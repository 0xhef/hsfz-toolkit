//! HSFZ man-in-the-middle proxy.
//!
//! Sits between a flashing app and a real MEVD17 DME, transparently
//! forwarding HSFZ frames in both directions while logging everything
//! and optionally rewriting selected fields.
//!
//! ## Architecture
//!
//! ```text
//!                         ┌──────────────────────────────┐
//!  ┌──────────┐ udp/tcp   │ proxy listener (this module) │ tcp   ┌─────┐
//!  │ flasher  │──────────▶│  :6811 udp / :6801 tcp       │──────▶│ DME │
//!  │ (flasher)│◀──────────│ discovery + framer + rewrite │◀──────│     │
//!  └──────────┘           └──────────────────────────────┘       └─────┘
//! ```
//!
//! Two background services run inside one `proxy_start` call:
//!
//! 1. **UDP discovery responder** (port 6811). Replies to any HSFZ
//!    vehicle-identification probe with `DIAGADR<n>BMWMAC<mac>BMWVIN<vin>`,
//!    using the spoofed VIN if configured. The flasher then connects
//!    TCP to the proxy's IP because that's where the UDP response came
//!    from. Critical: real HSFZ flash tools do not let you type a manual
//!    DME IP — they broadcast on every NIC and use the first reply.
//!
//! 2. **TCP forwarder** (port 6801). For every accepted client we open
//!    a fresh upstream socket to the real DME and run two pump threads
//!    that bidirectionally forward HSFZ frames, parsed via the existing
//!    `simulator::hsfz` framer.
//!
//! Each accepted session writes its capture into its own directory
//! under `proxy_captures/<timestamp>_<peer>/`:
//!
//! ```text
//!   proxy_captures/20260408_153012_10.5.0.2_58237/
//!     meta.json       — start_unix_ms, peers, spoof_vin
//!     timeline.bin    — append-only [t_ms u64 BE][dir u8][len u32 BE][bytes]
//! ```
//!
//! Past sessions are listed via `proxy_list_sessions` and exported to
//! Wireshark-readable `.pcap` via `proxy_export_pcap`, which
//! synthesises an Ethernet/IPv4/TCP frame around each timeline record
//! using the peers stored in `meta.json`.
//!
//! ## VIN spoofing
//!
//! The original use case: a flashing app is licensed to VIN `XYZ` but
//! the user's car has VIN `ABC`. The proxy intercepts the upstream
//! response to `22 F190` and rewrites the 17-byte ASCII VIN payload to
//! `XYZ` before forwarding it to the flasher. The flasher sees its
//! expected VIN, accepts the licence check, and continues to flash the
//! underlying real car. Discovery responses get the same treatment
//! before the TCP session even starts.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};

use crate::pcap::writer::write_pcap_timed;
use crate::simulator::hsfz::{frame_to_wire, read_frame, ReadOutcome};
use crate::types::TcpPacket;

const SPOOF_VIN_DID: u16 = 0xF190;
const VIN_LEN: usize = 17;
const DISCOVERY_PORT: u16 = 6811;
const DISCOVERY_RECV_TIMEOUT: Duration = Duration::from_millis(250);
/// HSFZ control word the simulator's discovery responder uses. Real
/// HSFZ gateways emit `0x0004` (vehicle-identification-data response);
/// every HSFZ tool we've tested accepts it. Mirroring it here keeps
/// frame-format symmetry with the simulator side.
const CONTROL_VEHICLE_IDENT_RESPONSE: u16 = 0x0004;

// Timeline record direction tags. Kept as u8 constants instead of an
// enum so the on-disk format stays trivially parseable from any
// language.
const DIR_C2U: u8 = 0;
const DIR_U2C: u8 = 1;

/// Global proxy state managed by Tauri so commands can stop/inspect it.
pub struct ProxyState {
    inner: Mutex<Option<RunningProxy>>,
}

impl Default for ProxyState {
    fn default() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
}

impl ProxyState {
    pub fn new() -> Self {
        Self::default()
    }
}

struct RunningProxy {
    stop_flag: Arc<AtomicBool>,
    listener_thread: Option<thread::JoinHandle<()>>,
    discovery_thread: Option<thread::JoinHandle<()>>,
    config: ProxyConfig,
    stats: Arc<ProxyStats>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub upstream_addr: String,
    /// Real VIN read from the upstream DME via discovery, if known.
    /// Always advertised when `spoof_enabled` is `false`. When
    /// spoofing is on, used as a fallback if `spoof_vin` is blank.
    pub real_vin: Option<String>,
    /// Real MAC read from the upstream DME via discovery, if known.
    /// Same fallback semantics as `real_vin`.
    pub real_mac: Option<String>,
    /// Diagnostic address advertised in the discovery reply. The
    /// flasher uses this as the destination byte on every UDS
    /// request, so it needs to match whatever the real DME expects.
    /// Auto-populated from `discover_vehicles` and rarely needs
    /// manual override (defaults to `0x10` for MEVD17).
    pub diag_addr: u8,
    /// Master spoof toggle. When `false`, the proxy is a transparent
    /// passthrough — the discovery responder advertises the real
    /// VIN/MAC and `22 F190` responses are forwarded unchanged.
    /// When `true`, the spoof values below take effect (with
    /// real values as fallback for any blank spoof field).
    pub spoof_enabled: bool,
    /// Spoofed VIN. Used in the discovery reply AND substituted into
    /// every `62 F190` response from the real DME when
    /// `spoof_enabled` is `true`.
    pub spoof_vin: Option<String>,
    /// Spoofed 12-hex-char MAC. Used only in the discovery reply
    /// when `spoof_enabled` is `true`. Some licence checks key off
    /// the MAC as a secondary identifier — set this to the licensed
    /// car's MAC if known.
    pub spoof_mac: Option<String>,
    /// Whether to bind the UDP discovery responder at all. Defaults
    /// to `true` — without it, real HSFZ flash tools can't find us,
    /// since they all broadcast-discover and don't accept manual IPs.
    pub enable_discovery: bool,
}

impl ProxyConfig {
    /// Resolve the VIN that the discovery responder + F190 rewriter
    /// should advertise, given the current spoof toggle state.
    fn effective_vin(&self) -> Option<&str> {
        if self.spoof_enabled {
            self.spoof_vin
                .as_deref()
                .filter(|s| !s.is_empty())
                .or(self.real_vin.as_deref())
        } else {
            self.real_vin.as_deref()
        }
    }

    /// Resolve the MAC the discovery responder should advertise.
    fn effective_mac(&self) -> Option<&str> {
        if self.spoof_enabled {
            self.spoof_mac
                .as_deref()
                .filter(|s| !s.is_empty())
                .or(self.real_mac.as_deref())
        } else {
            self.real_mac.as_deref()
        }
    }
}

#[derive(Default)]
struct ProxyStats {
    bytes_c2u: AtomicU64,
    bytes_u2c: AtomicU64,
    rewrites: AtomicU64,
    frames: AtomicU64,
    sessions: AtomicU64,
}

#[derive(Serialize)]
pub struct ProxyStatus {
    pub running: bool,
    pub config: Option<ProxyConfig>,
    pub bytes_c2u: u64,
    pub bytes_u2c: u64,
    pub frames: u64,
    pub rewrites: u64,
    pub sessions: u64,
}

#[derive(Serialize, Clone)]
struct ProxyFrameEvent {
    direction: &'static str, // "C2U" or "U2C"
    control: u16,
    bytes_hex: String,
    note: Option<String>,
}

#[derive(Serialize, Clone)]
struct ProxyStatusEvent {
    state: &'static str, // "listening" / "connected" / "disconnected" / "stopped" / "error"
    detail: String,
}

#[derive(Serialize, Deserialize)]
struct SessionMeta {
    start_unix_ms: u64,
    listen_addr: String,
    upstream_addr: String,
    flasher_peer: String,
    spoof_vin: Option<String>,
}

#[derive(Serialize)]
pub struct ProxySession {
    pub dir_name: String,
    pub dir_path: String,
    pub started_at: String,
    pub flasher_peer: String,
    pub upstream_addr: String,
    pub spoof_vin: Option<String>,
    pub frames: u64,
    pub bytes: u64,
}

// ── Tauri commands ──────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub fn proxy_start(
    app: AppHandle,
    state: State<'_, ProxyState>,
    listen_addr: String,
    upstream_addr: String,
    real_vin: Option<String>,
    real_mac: Option<String>,
    diag_addr: Option<u8>,
    spoof_enabled: Option<bool>,
    spoof_vin: Option<String>,
    spoof_mac: Option<String>,
    enable_discovery: Option<bool>,
) -> Result<ProxyStatus, String> {
    let mut guard = state.inner.lock().map_err(|_| "proxy state poisoned")?;
    if guard.is_some() {
        return Err("proxy already running".to_string());
    }

    // Validate the upstream addr eagerly so we don't crash inside the
    // listener thread on a typo.
    upstream_addr
        .parse::<SocketAddr>()
        .map_err(|e| format!("invalid upstream addr {:?}: {}", upstream_addr, e))?;

    let cfg = ProxyConfig {
        listen_addr: listen_addr.clone(),
        upstream_addr: upstream_addr.clone(),
        real_vin: real_vin.and_then(normalize_vin),
        real_mac: real_mac
            .map(|m| sanitize_mac(&m))
            .filter(|m| m != "000000000000"),
        diag_addr: diag_addr.unwrap_or(0x10),
        spoof_enabled: spoof_enabled.unwrap_or(false),
        spoof_vin: spoof_vin.and_then(normalize_vin),
        spoof_mac: spoof_mac
            .map(|m| sanitize_mac(&m))
            .filter(|m| !m.is_empty() && m != "000000000000"),
        enable_discovery: enable_discovery.unwrap_or(true),
    };

    let listener =
        TcpListener::bind(&listen_addr).map_err(|e| format!("bind {}: {}", listen_addr, e))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking: {}", e))?;

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(ProxyStats::default());

    log::info!(
        "proxy: TCP listening on {}, upstream {}, spoof_vin={:?}, discovery={}",
        listen_addr,
        upstream_addr,
        cfg.spoof_vin,
        cfg.enable_discovery
    );
    emit_status(&app, "listening", format!("Listening on {}", listen_addr));

    // ── Discovery responder ────────────────────────────────────────
    let discovery_thread = if cfg.enable_discovery {
        spawn_discovery_responder(cfg.clone(), stop_flag.clone(), app.clone())
    } else {
        None
    };

    // ── TCP listener loop ──────────────────────────────────────────
    let cfg_for_thread = cfg.clone();
    let stop_for_thread = stop_flag.clone();
    let stats_for_thread = stats.clone();
    let app_for_thread = app.clone();
    let handle = thread::Builder::new()
        .name(format!("proxy-listener-{}", listen_addr))
        .spawn(move || {
            listener_loop(
                listener,
                stop_for_thread,
                cfg_for_thread,
                stats_for_thread,
                app_for_thread,
            );
        })
        .map_err(|e| format!("spawn listener: {}", e))?;

    *guard = Some(RunningProxy {
        stop_flag,
        listener_thread: Some(handle),
        discovery_thread,
        config: cfg.clone(),
        stats: stats.clone(),
    });

    Ok(snapshot_status(&cfg, &stats, true))
}

#[tauri::command]
pub fn proxy_stop(state: State<'_, ProxyState>) -> Result<ProxyStatus, String> {
    let mut guard = state.inner.lock().map_err(|_| "proxy state poisoned")?;
    if let Some(mut running) = guard.take() {
        running.stop_flag.store(true, Ordering::SeqCst);
        if let Some(h) = running.listener_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = running.discovery_thread.take() {
            let _ = h.join();
        }
    }
    Ok(ProxyStatus {
        running: false,
        config: None,
        bytes_c2u: 0,
        bytes_u2c: 0,
        frames: 0,
        rewrites: 0,
        sessions: 0,
    })
}

#[tauri::command]
pub fn proxy_status(state: State<'_, ProxyState>) -> Result<ProxyStatus, String> {
    let guard = state.inner.lock().map_err(|_| "proxy state poisoned")?;
    match guard.as_ref() {
        Some(r) => Ok(snapshot_status(&r.config, &r.stats, true)),
        None => Ok(ProxyStatus {
            running: false,
            config: None,
            bytes_c2u: 0,
            bytes_u2c: 0,
            frames: 0,
            rewrites: 0,
            sessions: 0,
        }),
    }
}

#[tauri::command]
pub fn proxy_captures_dir() -> String {
    proxy_captures_root().to_string_lossy().to_string()
}

#[tauri::command]
pub fn proxy_list_sessions() -> Result<Vec<ProxySession>, String> {
    let root = proxy_captures_root();
    let mut out: Vec<ProxySession> = Vec::new();
    let entries = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(format!("read proxy captures dir: {}", e)),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let dir_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let meta_path = path.join("meta.json");
        let timeline_path = path.join("timeline.bin");
        if !meta_path.exists() || !timeline_path.exists() {
            continue;
        }
        let meta: SessionMeta = match std::fs::read_to_string(&meta_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
        {
            Some(m) => m,
            None => continue,
        };
        let (frames, bytes) = scan_timeline_summary(&timeline_path).unwrap_or((0, 0));
        let started_at = format_unix_ms(meta.start_unix_ms);
        out.push(ProxySession {
            dir_name,
            dir_path: path.to_string_lossy().to_string(),
            started_at,
            flasher_peer: meta.flasher_peer,
            upstream_addr: meta.upstream_addr,
            spoof_vin: meta.spoof_vin,
            frames,
            bytes,
        });
    }
    out.sort_by(|a, b| b.dir_name.cmp(&a.dir_name));
    Ok(out)
}

/// Build a Wireshark-readable `.pcap` file body from a stored proxy
/// session and stash it in `AppState.last_bytes`. Returns the byte
/// count; frontend calls `pull_last_bytes` to retrieve the actual
/// bytes as a raw `ArrayBuffer`. Same two-command split as the other
/// large-binary commands — see `pull_last_bytes` in `commands.rs`.
#[tauri::command]
pub fn proxy_export_pcap(
    dir_name: String,
    state: tauri::State<'_, crate::commands::AppState>,
) -> Result<usize, String> {
    use crate::op_log::OpLog;
    let mut op = OpLog::new();

    let build_log = |op: &OpLog, dir_name: &str, status: &str, result_footer: String| {
        let header = crate::op_log::header(
            "Proxy PCAP Export",
            &[("Session", dir_name.to_string()), ("Status", status.to_string())],
        );
        op.format(&header, &result_footer)
    };

    op.push(format!("Resolving proxy session dir: {}", dir_name));
    let session_dir = match resolve_session_dir(&dir_name) {
        Ok(d) => d,
        Err(e) => {
            op.push(format!("resolve_session_dir failed: {}", e));
            crate::op_log::stash(
                &state,
                build_log(
                    &op,
                    &dir_name,
                    "FAILED",
                    format!("RESULT: FAILED\nError: {}\n", e),
                ),
            );
            return Err(e);
        }
    };
    let meta_path = session_dir.join("meta.json");
    let timeline_path = session_dir.join("timeline.bin");
    op.push(format!("meta.json: {}", meta_path.display()));
    op.push(format!("timeline.bin: {}", timeline_path.display()));
    let meta: SessionMeta = serde_json::from_str(
        &std::fs::read_to_string(&meta_path).map_err(|e| format!("read meta: {}", e))?,
    )
    .map_err(|e| format!("parse meta: {}", e))?;
    op.push(format!(
        "Session meta loaded: flasher={} upstream={} start_unix_ms={}",
        meta.flasher_peer, meta.upstream_addr, meta.start_unix_ms
    ));

    let (flasher_ip, flasher_port) = parse_addr(&meta.flasher_peer)?;
    let (dme_ip, dme_port) = parse_addr(&meta.upstream_addr)?;

    let timeline = std::fs::read(&timeline_path).map_err(|e| format!("read timeline: {}", e))?;

    let mut packets: Vec<(TcpPacket, u64)> = Vec::new();
    let mut seq_c2u: u32 = 1;
    let mut seq_u2c: u32 = 1;
    let mut cursor = 0usize;
    while cursor + 13 <= timeline.len() {
        let t_ms = u64::from_be_bytes(
            timeline[cursor..cursor + 8]
                .try_into()
                .map_err(|_| "timeline header truncated")?,
        );
        let dir = timeline[cursor + 8];
        let len = u32::from_be_bytes(
            timeline[cursor + 9..cursor + 13]
                .try_into()
                .map_err(|_| "timeline length truncated")?,
        ) as usize;
        cursor += 13;
        if cursor + len > timeline.len() {
            return Err("timeline body truncated".to_string());
        }
        let payload = timeline[cursor..cursor + len].to_vec();
        cursor += len;

        let abs_ms = meta.start_unix_ms.saturating_add(t_ms);
        let pkt = match dir {
            DIR_C2U => {
                let p = TcpPacket {
                    src_ip: flasher_ip,
                    dst_ip: dme_ip,
                    src_port: flasher_port,
                    dst_port: dme_port,
                    seq: seq_c2u,
                    payload,
                };
                seq_c2u = seq_c2u.wrapping_add(p.payload.len() as u32);
                p
            }
            DIR_U2C => {
                let p = TcpPacket {
                    src_ip: dme_ip,
                    dst_ip: flasher_ip,
                    src_port: dme_port,
                    dst_port: flasher_port,
                    seq: seq_u2c,
                    payload,
                };
                seq_u2c = seq_u2c.wrapping_add(p.payload.len() as u32);
                p
            }
            _ => continue,
        };
        packets.push((pkt, abs_ms));
    }

    op.push(format!(
        "Reassembled {} TCP packet(s) from timeline",
        packets.len()
    ));

    let bytes = write_pcap_timed(&packets);
    let len = bytes.len();
    op.push(format!("Wrote PCAP body: {} bytes", len));
    log::info!(
        "Built proxy session {} as PCAP ({} bytes), stashing for pull_last_bytes",
        dir_name,
        len
    );
    let mut stash = state
        .last_bytes
        .lock()
        .map_err(|_| "internal state lock error".to_string())?;
    *stash = Some(bytes);
    drop(stash);

    crate::op_log::stash(
        &state,
        build_log(
            &op,
            &dir_name,
            "SUCCESS",
            format!(
                "RESULT: SUCCESS\nPackets:      {}\nPCAP size:    {} bytes\n",
                packets.len(),
                len
            ),
        ),
    );
    Ok(len)
}

// ── Discovery responder ────────────────────────────────────────────────

fn spawn_discovery_responder(
    cfg: ProxyConfig,
    stop_flag: Arc<AtomicBool>,
    app: AppHandle,
) -> Option<thread::JoinHandle<()>> {
    let bind = format!("0.0.0.0:{}", DISCOVERY_PORT);
    let socket = match UdpSocket::bind(&bind) {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "proxy: cannot bind UDP {} ({}). Flashers won't see the proxy via discovery.",
                bind,
                e
            );
            emit_status(
                &app,
                "error",
                format!("UDP discovery bind {} failed: {}", bind, e),
            );
            return None;
        }
    };
    let _ = socket.set_broadcast(true);
    if let Err(e) = socket.set_read_timeout(Some(DISCOVERY_RECV_TIMEOUT)) {
        log::warn!("proxy: discovery set_read_timeout: {}", e);
    }

    let response = build_discovery_response(&cfg);
    log::info!(
        "proxy: discovery responder up on UDP {} (spoof={}, vin={}, mac={}, diag=0x{:02X}, {} bytes)",
        bind,
        cfg.spoof_enabled,
        cfg.effective_vin().unwrap_or("(none)"),
        cfg.effective_mac().unwrap_or("(none)"),
        cfg.diag_addr,
        response.len()
    );

    thread::Builder::new()
        .name("proxy-discovery".to_string())
        .spawn(move || {
            let mut buf = [0u8; 1024];
            while !stop_flag.load(Ordering::SeqCst) {
                match socket.recv_from(&mut buf) {
                    Ok((n, peer)) => {
                        log::debug!(
                            "proxy: discovery probe from {} ({} bytes), replying",
                            peer,
                            n
                        );
                        // Reply IMMEDIATELY — beating the real DME's
                        // own UDP response is the only thing that
                        // matters when both are reachable on the
                        // same broadcast domain.
                        if let Err(e) = socket.send_to(&response, peer) {
                            log::warn!("proxy: discovery reply to {} failed: {}", peer, e);
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(e) => {
                        log::warn!("proxy: discovery recv error: {}", e);
                        thread::sleep(Duration::from_millis(500));
                    }
                }
            }
            log::info!("proxy: discovery responder stopped");
        })
        .ok()
}

fn build_discovery_response(cfg: &ProxyConfig) -> Vec<u8> {
    // Body: `DIAGADR<decimal>BMWMAC<12hex>BMWVIN<17chars>` — exactly
    // what the real vehicle-ident UDP reply contains. The
    // VIN/MAC values are picked by `effective_vin` / `effective_mac`,
    // which honour the `spoof_enabled` master toggle and fall back
    // to the real DME's discovered values when spoofing is off.
    let vin = pad_or_truncate(
        cfg.effective_vin().unwrap_or("WBA00000000000000"),
        VIN_LEN,
        '0',
    );
    let mac = match cfg.effective_mac() {
        Some(m) if m.len() == 12 => m.to_string(),
        _ => "001A3744FFEE".to_string(),
    };
    let text = format!("DIAGADR{}BMWMAC{}BMWVIN{}", cfg.diag_addr, mac, vin);
    let payload = text.into_bytes();
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&CONTROL_VEHICLE_IDENT_RESPONSE.to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

// ── Listener / forwarder loop ──────────────────────────────────────────

fn listener_loop(
    listener: TcpListener,
    stop_flag: Arc<AtomicBool>,
    cfg: ProxyConfig,
    stats: Arc<ProxyStats>,
    app: AppHandle,
) {
    while !stop_flag.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((client, peer)) => {
                log::info!("proxy: client connected from {}", peer);
                emit_status(&app, "connected", format!("Client {} connected", peer));
                stats.sessions.fetch_add(1, Ordering::Relaxed);

                let upstream_sa: SocketAddr = match cfg.upstream_addr.parse() {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("proxy: bad upstream addr: {}", e);
                        emit_status(&app, "error", format!("Bad upstream addr: {}", e));
                        continue;
                    }
                };
                let upstream =
                    match TcpStream::connect_timeout(&upstream_sa, Duration::from_secs(5)) {
                        Ok(s) => s,
                        Err(e) => {
                            log::warn!("proxy: upstream connect failed: {}", e);
                            emit_status(&app, "error", format!("Upstream connect failed: {}", e));
                            continue;
                        }
                    };

                let cfg_clone = cfg.clone();
                let stats_clone = stats.clone();
                let app_clone = app.clone();
                let stop_clone = stop_flag.clone();
                thread::spawn(move || {
                    if let Err(e) = run_session(
                        client,
                        upstream,
                        peer,
                        cfg_clone,
                        stats_clone,
                        app_clone.clone(),
                        stop_clone,
                    ) {
                        log::warn!("proxy: session ended: {}", e);
                        emit_status(&app_clone, "disconnected", format!("Session: {}", e));
                    } else {
                        emit_status(&app_clone, "disconnected", "Session ended".to_string());
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                log::warn!("proxy: accept error: {}", e);
                emit_status(&app, "error", format!("Accept: {}", e));
                thread::sleep(Duration::from_millis(500));
            }
        }
    }
    log::info!("proxy: listener stopped");
    emit_status(&app, "stopped", "Listener stopped".to_string());
}

fn run_session(
    client: TcpStream,
    upstream: TcpStream,
    flasher_peer: SocketAddr,
    cfg: ProxyConfig,
    stats: Arc<ProxyStats>,
    app: AppHandle,
    stop_flag: Arc<AtomicBool>,
) -> std::io::Result<()> {
    client.set_nodelay(true)?;
    upstream.set_nodelay(true)?;
    // Long read timeout — we get back into the read loop quickly via
    // `ReadOutcome::Idle` if a TimedOut fires anyway. Real flash
    // sessions can sit idle for 10s+ between user prompts.
    client.set_read_timeout(Some(Duration::from_secs(2)))?;
    upstream.set_read_timeout(Some(Duration::from_secs(2)))?;

    // Per-session capture dir + meta + timeline.
    let session_dir = make_session_dir(&flasher_peer)?;
    let start_unix_ms = unix_ms_now();
    let meta = SessionMeta {
        start_unix_ms,
        listen_addr: cfg.listen_addr.clone(),
        upstream_addr: cfg.upstream_addr.clone(),
        flasher_peer: flasher_peer.to_string(),
        spoof_vin: cfg.spoof_vin.clone(),
    };
    std::fs::write(
        session_dir.join("meta.json"),
        serde_json::to_vec_pretty(&meta).unwrap_or_default(),
    )?;
    let timeline = Arc::new(Mutex::new(std::fs::File::create(
        session_dir.join("timeline.bin"),
    )?));

    // Per-session shutdown flag — distinct from the global stop flag
    // so one session ending doesn't tear the whole listener down.
    let session_stop = Arc::new(AtomicBool::new(false));
    let started = Instant::now();

    // Two stream handles per direction so each pump owns its own
    // half. We deliberately do NOT use `try_clone` because the
    // session_stop flag handles termination — instead we hand the
    // raw streams to the pumps and let them shutdown the *other*
    // peer's handle on exit.
    let mut client_rd = client.try_clone()?;
    let mut client_wr = client.try_clone()?;
    let mut upstream_rd = upstream.try_clone()?;
    let mut upstream_wr = upstream.try_clone()?;

    // Cloned handles to call `shutdown()` on from the cleanup hook.
    let client_for_shutdown = client.try_clone()?;
    let upstream_for_shutdown = upstream.try_clone()?;

    // ── client → upstream pump (sub-thread) ────────────────────────
    let cfg_a = cfg.clone();
    let stats_a = stats.clone();
    let timeline_a = timeline.clone();
    let app_a = app.clone();
    let stop_a = session_stop.clone();
    let global_stop_a = stop_flag.clone();
    let started_a = started;
    let pump_c2u = thread::spawn(move || {
        let res = forward(
            &mut client_rd,
            &mut upstream_wr,
            DIR_C2U,
            &cfg_a,
            &stats_a,
            &timeline_a,
            &app_a,
            stop_a.clone(),
            global_stop_a,
            started_a,
        );
        // No matter how the pump exits, signal the other side to
        // unblock and force-shutdown both stream halves so the
        // upstream→client read returns immediately.
        stop_a.store(true, Ordering::SeqCst);
        let _ = client_for_shutdown.shutdown(Shutdown::Both);
        let _ = upstream_for_shutdown.shutdown(Shutdown::Both);
        res
    });

    // ── upstream → client pump (this thread) ───────────────────────
    let res_u2c = forward(
        &mut upstream_rd,
        &mut client_wr,
        DIR_U2C,
        &cfg,
        &stats,
        &timeline,
        &app,
        session_stop.clone(),
        stop_flag.clone(),
        started,
    );
    session_stop.store(true, Ordering::SeqCst);
    let _ = client.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);

    // Join the sub-thread so we don't leak it.
    let _ = pump_c2u.join();
    res_u2c
}

#[allow(clippy::too_many_arguments)]
fn forward(
    src: &mut TcpStream,
    dst: &mut TcpStream,
    direction: u8,
    cfg: &ProxyConfig,
    stats: &Arc<ProxyStats>,
    timeline: &Arc<Mutex<std::fs::File>>,
    app: &AppHandle,
    session_stop: Arc<AtomicBool>,
    global_stop: Arc<AtomicBool>,
    started: Instant,
) -> std::io::Result<()> {
    while !session_stop.load(Ordering::SeqCst) && !global_stop.load(Ordering::SeqCst) {
        let frame = match read_frame(src) {
            Ok(ReadOutcome::Frame(f)) => f,
            Ok(ReadOutcome::Eof) => break,
            Ok(ReadOutcome::Idle) => continue,
            Err(e)
                if e.kind() == std::io::ErrorKind::ConnectionReset
                    || e.kind() == std::io::ErrorKind::ConnectionAborted
                    || e.kind() == std::io::ErrorKind::BrokenPipe
                    || e.kind() == std::io::ErrorKind::NotConnected =>
            {
                break;
            }
            Err(e) => return Err(e),
        };

        // Optionally rewrite the payload before re-emitting.
        let (payload, rewritten) = match direction {
            DIR_U2C => maybe_rewrite_vin(&frame.payload, cfg),
            _ => (frame.payload.clone(), false),
        };
        if rewritten {
            stats.rewrites.fetch_add(1, Ordering::Relaxed);
        }

        let wire = frame_to_wire(frame.control, &payload);

        // Append a timestamped record to the timeline.
        let t_ms = started.elapsed().as_millis() as u64;
        if let Ok(mut f) = timeline.lock() {
            let _ = f.write_all(&t_ms.to_be_bytes());
            let _ = f.write_all(&[direction]);
            let _ = f.write_all(&(wire.len() as u32).to_be_bytes());
            let _ = f.write_all(&wire);
        }

        let counter = match direction {
            DIR_C2U => &stats.bytes_c2u,
            _ => &stats.bytes_u2c,
        };
        counter.fetch_add(wire.len() as u64, Ordering::Relaxed);
        stats.frames.fetch_add(1, Ordering::Relaxed);

        // Live frontend transcript event. Cap displayed hex at 48
        // bytes so a 4 KiB TransferData block doesn't flood the UI;
        // the timeline.bin on disk has the full bytes.
        let display = if wire.len() > 48 {
            format!("{} (+{} bytes)", encode_hex(&wire[..48]), wire.len() - 48)
        } else {
            encode_hex(&wire)
        };
        let _ = app.emit(
            "proxy-frame",
            ProxyFrameEvent {
                direction: dir_label(direction),
                control: frame.control,
                bytes_hex: display,
                note: rewritten.then(|| "VIN rewritten".to_string()),
            },
        );

        if let Err(e) = dst.write_all(&wire) {
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
            ) {
                break;
            }
            return Err(e);
        }
        let _ = dst.flush();
    }
    Ok(())
}

fn dir_label(d: u8) -> &'static str {
    match d {
        DIR_C2U => "C2U",
        _ => "U2C",
    }
}

// ── VIN rewriter ────────────────────────────────────────────────────────

/// Walk an HSFZ payload looking for a `62 F1 90 …` RDBI positive
/// response and replace its 17-byte VIN field with the spoofed VIN.
/// Returns the (possibly rewritten) payload and whether a swap happened.
///
/// HSFZ payload layout for a UDS response: `[src][dst][SID][body…]`.
/// We accept SID `0x62` (positive RDBI) at offset 2 and then scan the
/// rest of the body for the F190 DID marker so compound RDBI responses
/// (multi-DID requests) also get rewritten in-place.
fn maybe_rewrite_vin(payload: &[u8], cfg: &ProxyConfig) -> (Vec<u8>, bool) {
    // Only rewrite when the master spoof toggle is on AND a non-empty
    // spoof VIN is configured. With spoofing off, the proxy is a
    // transparent passthrough — the flasher sees the real DME's VIN.
    if !cfg.spoof_enabled {
        return (payload.to_vec(), false);
    }
    let Some(spoof) = cfg.spoof_vin.as_deref() else {
        return (payload.to_vec(), false);
    };
    if spoof.len() != VIN_LEN {
        return (payload.to_vec(), false);
    }
    if payload.len() < 5 || payload[2] != 0x62 {
        return (payload.to_vec(), false);
    }
    let body = &payload[3..];
    let Some(idx) = find_f190(body) else {
        return (payload.to_vec(), false);
    };
    let vin_start = 3 + idx + 2; // body offset + DID(2)
    if payload.len() < vin_start + VIN_LEN {
        return (payload.to_vec(), false);
    }
    let mut out = payload.to_vec();
    out[vin_start..vin_start + VIN_LEN].copy_from_slice(spoof.as_bytes());
    (out, true)
}

fn find_f190(body: &[u8]) -> Option<usize> {
    body.windows(2)
        .position(|w| w[0] == ((SPOOF_VIN_DID >> 8) as u8) && w[1] == (SPOOF_VIN_DID as u8))
}

fn normalize_vin(s: String) -> Option<String> {
    let trimmed: String = s
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_uppercase();
    if trimmed.len() == VIN_LEN {
        Some(trimmed)
    } else {
        None
    }
}

fn sanitize_mac(mac: &str) -> String {
    let mut out: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    while out.len() < 12 {
        out.push('0');
    }
    out.truncate(12);
    out
}

fn pad_or_truncate(s: &str, len: usize, pad: char) -> String {
    let mut out = s.to_string();
    while out.len() < len {
        out.push(pad);
    }
    out.truncate(len);
    out
}

// ── Capture directory + helpers ────────────────────────────────────────

fn proxy_captures_root() -> PathBuf {
    crate::app_paths::proxy_captures_dir()
}

fn make_session_dir(peer: &SocketAddr) -> std::io::Result<PathBuf> {
    let root = proxy_captures_root();
    std::fs::create_dir_all(&root)?;
    let stamp = format_unix_ms_compact(unix_ms_now());
    let peer_safe = peer
        .to_string()
        .replace([':', '.'], "_")
        .chars()
        .take(40)
        .collect::<String>();
    let dir = root.join(format!("{}_{}", stamp, peer_safe));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn format_unix_ms(ms: u64) -> String {
    // Plain UTC ISO-8601 without pulling chrono in. Calendar maths
    // copied from the simulator capture module's helper.
    let secs = ms / 1000;
    let (y, m, d, hh, mm, ss) = epoch_secs_to_ymdhms(secs);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z", y, m, d, hh, mm, ss)
}

fn format_unix_ms_compact(ms: u64) -> String {
    let secs = ms / 1000;
    let (y, m, d, hh, mm, ss) = epoch_secs_to_ymdhms(secs);
    format!("{:04}{:02}{:02}_{:02}{:02}{:02}", y, m, d, hh, mm, ss)
}

/// Convert seconds-since-unix-epoch into Y-M-D h:m:s in UTC. Avoids
/// pulling `chrono`/`time` for two timestamp formatters. Algorithm
/// from <https://howardhinnant.github.io/date_algorithms.html>.
fn epoch_secs_to_ymdhms(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as u32;
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d, hh, mm, ss)
}

fn scan_timeline_summary(path: &Path) -> std::io::Result<(u64, u64)> {
    let mut f = std::fs::File::open(path)?;
    let mut frames: u64 = 0;
    let mut bytes: u64 = 0;
    let mut header = [0u8; 13];
    loop {
        match f.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let len = u32::from_be_bytes([header[9], header[10], header[11], header[12]]) as u64;
        bytes = bytes.saturating_add(len);
        frames = frames.saturating_add(1);
        // Skip the body — we only care about the count + total bytes.
        let mut sink = vec![0u8; len as usize];
        f.read_exact(&mut sink)?;
    }
    Ok((frames, bytes))
}

fn resolve_session_dir(dir_name: &str) -> Result<PathBuf, String> {
    if dir_name.is_empty() || dir_name.len() > 128 {
        return Err("session name length out of range".to_string());
    }
    if dir_name.contains('/') || dir_name.contains('\\') || dir_name.contains("..") {
        return Err("session name contains path separators".to_string());
    }
    let root = proxy_captures_root();
    let path = root.join(dir_name);
    let canonical_root = std::fs::canonicalize(&root).unwrap_or(root);
    let canonical_path =
        std::fs::canonicalize(&path).map_err(|e| format!("session not found: {}", e))?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err("session path escaped captures directory".to_string());
    }
    Ok(canonical_path)
}

fn parse_addr(s: &str) -> Result<([u8; 4], u16), String> {
    let sa: SocketAddr = s.parse().map_err(|e| format!("parse {}: {}", s, e))?;
    match sa {
        SocketAddr::V4(v) => Ok((v.ip().octets(), v.port())),
        SocketAddr::V6(_) => Err("ipv6 not supported in pcap export".to_string()),
    }
}

fn snapshot_status(cfg: &ProxyConfig, stats: &ProxyStats, running: bool) -> ProxyStatus {
    ProxyStatus {
        running,
        config: Some(cfg.clone()),
        bytes_c2u: stats.bytes_c2u.load(Ordering::Relaxed),
        bytes_u2c: stats.bytes_u2c.load(Ordering::Relaxed),
        frames: stats.frames.load(Ordering::Relaxed),
        rewrites: stats.rewrites.load(Ordering::Relaxed),
        sessions: stats.sessions.load(Ordering::Relaxed),
    }
}

fn emit_status(app: &AppHandle, state: &'static str, detail: String) {
    let _ = app.emit("proxy-status", ProxyStatusEvent { state, detail });
}

fn encode_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02X}", byte));
    }
    s
}
