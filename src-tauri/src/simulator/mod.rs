//! DME Simulator — accept HSFZ UDS flashing traffic from a real tuning tool
//! and capture the flash payload as it's written.
//!
//! This is a *stateful* simulator (not a replay). It implements just enough
//! of the HSFZ/UDS state machine — DiagSession, SecurityAccess (bypass),
//! RoutineControl, RequestDownload + TransferData + RequestTransferExit,
//! ReadDataByIdentifier — to satisfy a flasher end-to-end. The actual
//! protocol behaviour and DID values come from `EcuProfile`, which can be
//! the bundled default (cloned from a real MEVD17) or a user-supplied JSON
//! file or a freshly cloned profile read from a live car.
//!
//! Layout:
//!
//! | File                  | Responsibility                                |
//! | --------------------- | --------------------------------------------- |
//! | `profile.rs`          | EcuProfile struct + JSON load/save + builtin  |
//! | `hsfz.rs`             | Server-side HSFZ frame read/write             |
//! | `state.rs`            | Per-session UDS state (download segments)     |
//! | `services.rs`         | UDS service handlers (10/22/27/31/34/36/37…)  |
//! | `capture.rs`          | Per-session .bin writer + transcript log      |
//! | `server.rs`           | TCP listener + accept loop + session loop     |
//! | `mod.rs` (this file)  | Tauri commands + global running-server state  |

pub mod capture;
pub mod clone;
pub mod discovery_responder;
pub mod encoder;
pub mod hsfz;
pub mod profile;
pub mod server;
pub mod services;
pub mod state;
pub mod synthesize;

use std::sync::Mutex;

use serde::Serialize;
use tauri::{AppHandle, State};

use profile::EcuProfile;
use server::{spawn, RunningServer, ServerConfig};

/// Global handle to the currently running simulator (if any). Wrapped in a
/// `Mutex` because Tauri commands can be invoked concurrently.
pub struct SimulatorState {
    pub running: Mutex<Option<RunningServer>>,
}

impl SimulatorState {
    pub fn new() -> Self {
        Self {
            running: Mutex::new(None),
        }
    }
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub running: bool,
    pub bind_addr: Option<String>,
}

// ── Tauri commands ──────────────────────────────────────────────────────

/// Start the simulator. `bind_addr` is e.g. `"0.0.0.0:6801"`. `profile_name`
/// selects which profile to serve — `None` or `"default"` means the
/// built-in MEVD17 profile cloned from the included PCAP.
#[tauri::command]
pub fn simulator_start(
    app: AppHandle,
    state: State<'_, SimulatorState>,
    bind_addr: Option<String>,
    profile_name: Option<String>,
) -> Result<StatusResponse, String> {
    let mut guard = state
        .running
        .lock()
        .map_err(|_| "simulator state poisoned".to_string())?;
    if guard.is_some() {
        return Err("Simulator already running".to_string());
    }

    let bind_addr = bind_addr.unwrap_or_else(|| format!("0.0.0.0:{}", hsfz::HSFZ_PORT));
    if !is_valid_bind(&bind_addr) {
        return Err(format!("Invalid bind address: {}", bind_addr));
    }

    let profile = load_profile(profile_name.as_deref())?;
    log::info!(
        "simulator: starting with profile '{}' (VIN={:?}, {} DIDs)",
        profile.name,
        profile.vin,
        profile.dids.len()
    );

    let cfg = ServerConfig {
        bind_addr: bind_addr.clone(),
        profile,
    };
    let server = spawn(app, cfg)?;
    *guard = Some(server);

    Ok(StatusResponse {
        running: true,
        bind_addr: Some(bind_addr),
    })
}

#[tauri::command]
pub fn simulator_stop(state: State<'_, SimulatorState>) -> Result<StatusResponse, String> {
    let mut guard = state
        .running
        .lock()
        .map_err(|_| "simulator state poisoned".to_string())?;
    if let Some(mut server) = guard.take() {
        server.stop();
    }
    Ok(StatusResponse {
        running: false,
        bind_addr: None,
    })
}

#[tauri::command]
pub fn simulator_status(state: State<'_, SimulatorState>) -> Result<StatusResponse, String> {
    let guard = state
        .running
        .lock()
        .map_err(|_| "simulator state poisoned".to_string())?;
    Ok(match guard.as_ref() {
        Some(s) => StatusResponse {
            running: true,
            bind_addr: Some(s.bind_addr.clone()),
        },
        None => StatusResponse {
            running: false,
            bind_addr: None,
        },
    })
}

#[tauri::command]
pub fn simulator_list_profiles() -> Vec<String> {
    profile::list_profiles()
}

#[tauri::command]
pub fn simulator_get_profile(name: Option<String>) -> Result<EcuProfile, String> {
    load_profile(name.as_deref())
}

/// Persist a profile to the user profiles directory under a sanitized name.
/// The frontend uses this for the "Clone From Car" / "Save Profile" flows.
#[tauri::command]
pub fn simulator_save_profile(name: String, profile: EcuProfile) -> Result<String, String> {
    let safe = sanitize_profile_name(&name)?;
    let path = profile::profiles_dir().join(format!("{}.json", safe));
    profile.save_to_file(&path)?;
    Ok(path.to_string_lossy().to_string())
}

/// Delete a profile from the user profiles directory. Refuses to run
/// while the simulator is started so a delete can't pull the rug out
/// from under an active session. Sanitises the name and verifies the
/// resolved path stays inside the profiles directory before unlinking.
#[tauri::command]
pub fn simulator_delete_profile(
    state: State<'_, SimulatorState>,
    name: String,
) -> Result<(), String> {
    {
        let guard = state
            .running
            .lock()
            .map_err(|_| "simulator state poisoned".to_string())?;
        if guard.is_some() {
            return Err("Stop the simulator before deleting a profile".to_string());
        }
    }
    let safe = sanitize_profile_name(&name)?;
    let dir = profile::profiles_dir();
    let path = dir.join(format!("{}.json", safe));

    // Defence-in-depth path traversal check (mirrors load_profile).
    let canonical_dir = std::fs::canonicalize(&dir).unwrap_or(dir);
    if let Ok(canonical_path) = std::fs::canonicalize(&path) {
        if !canonical_path.starts_with(&canonical_dir) {
            return Err("profile path escaped profiles directory".to_string());
        }
    }
    if !path.exists() {
        return Err(format!("Profile '{}' does not exist", safe));
    }
    std::fs::remove_file(&path).map_err(|e| format!("delete {}: {}", path.display(), e))?;
    log::info!("simulator: deleted profile '{}'", safe);
    Ok(())
}

/// Create a fresh, mostly-empty profile and persist it. The user supplies
/// the name, ECU address, and an optional VIN that gets stamped into the
/// `F190` DID. Everything else stays empty until they either edit the
/// profile or run the clone flow against a real car.
#[tauri::command]
pub fn simulator_create_empty_profile(
    name: String,
    ecu_address: u8,
    vin: Option<String>,
) -> Result<String, String> {
    if !matches!(ecu_address, 0x12 | 0x13) {
        return Err(format!(
            "Only DME addresses 0x12 / 0x13 are supported (got 0x{:02X})",
            ecu_address
        ));
    }
    let safe = sanitize_profile_name(&name)?;
    let vin_clean = match vin {
        Some(v) => {
            let upper = v.trim().to_uppercase();
            if upper.is_empty() {
                None
            } else {
                if !is_valid_vin(&upper) {
                    return Err("VIN must be 17 ASCII alphanumeric chars (no I, O, Q)".to_string());
                }
                Some(upper)
            }
        }
        None => None,
    };
    let profile = EcuProfile::empty(&safe, ecu_address, vin_clean);
    let path = profile::profiles_dir().join(format!("{}.json", safe));
    profile.save_to_file(&path)?;
    Ok(safe)
}

/// VIN validator (ISO 3779): 17 ASCII alphanumeric characters, no `I`, `O`, or `Q`.
fn is_valid_vin(vin: &str) -> bool {
    if vin.len() != 17 {
        return false;
    }
    vin.chars()
        .all(|c| c.is_ascii_alphanumeric() && !matches!(c, 'I' | 'O' | 'Q'))
}

/// Read the typed identifiers (BTLD/SWFL/SWFK/CAFD/HWEL + flash counters)
/// out of a saved profile so the editor form can pre-fill them.
#[tauri::command]
pub fn simulator_get_dme_identifiers(name: String) -> Result<encoder::DmeIdentifiers, String> {
    let profile = load_profile(Some(&name))?;
    Ok(encoder::extract(&profile))
}

/// Apply edited identifiers to a profile and persist. The simulator must
/// be stopped to avoid mid-session profile churn — the frontend disables
/// the editor while the server is running but we double-check on the
/// backend side too.
#[tauri::command]
pub fn simulator_set_dme_identifiers(
    state: State<'_, SimulatorState>,
    name: String,
    ids: encoder::DmeIdentifiers,
) -> Result<(), String> {
    {
        let guard = state
            .running
            .lock()
            .map_err(|_| "simulator state poisoned".to_string())?;
        if guard.is_some() {
            return Err("Stop the simulator before editing the profile".to_string());
        }
    }
    let safe = sanitize_profile_name(&name)?;
    let mut profile = load_profile(Some(&safe))?;
    encoder::apply(&mut profile, &ids)?;
    let path = profile::profiles_dir().join(format!("{}.json", safe));
    profile.save_to_file(&path)?;
    Ok(())
}

/// Merge an NCD coding backup (NCD tuning-tool JSON format) into the
/// named profile. The JSON contents are passed in directly so the
/// frontend owns the file picker; passing the path through the IPC
/// boundary would mean teaching the backend about per-OS file dialogs.
#[tauri::command]
pub fn simulator_import_ncd_backup(
    state: State<'_, SimulatorState>,
    name: String,
    json: String,
) -> Result<usize, String> {
    {
        let guard = state
            .running
            .lock()
            .map_err(|_| "simulator state poisoned".to_string())?;
        if guard.is_some() {
            return Err("Stop the simulator before editing the profile".to_string());
        }
    }
    let safe = sanitize_profile_name(&name)?;
    let mut profile = load_profile(Some(&safe))?;
    let count = encoder::import_ncd_backup(&mut profile, &json)?;
    let path = profile::profiles_dir().join(format!("{}.json", safe));
    profile.save_to_file(&path)?;
    Ok(count)
}

/// Return the bundled sample NCD coding backup so the UI can offer a
/// "Load Sample Coding" button — useful for trying the simulator
/// against a flasher without needing to source a real NCD file.
#[tauri::command]
pub fn simulator_sample_ncd_backup() -> &'static str {
    encoder::SAMPLE_NCD_BACKUP
}

/// Discover a real MEVD17 DME on the network and clone every fingerprint DID
/// into a fresh `EcuProfile`. The returned profile is **not** persisted —
/// the caller can preview it and call `simulator_save_profile` to write it
/// to disk under a chosen name.
///
/// Validates IP and ECU address up front so a malformed IPC payload is
/// rejected before any network I/O.
#[cfg(not(feature = "live-ecu"))]
#[tauri::command]
pub fn simulator_clone_from_car(
    _app: AppHandle,
    ip: String,
    ecu_address: u8,
    name: String,
) -> Result<EcuProfile, String> {
    if !is_valid_bind(&format!("{}:1", ip)) {
        return Err(format!("Invalid IP: {}", ip));
    }
    if !matches!(ecu_address, 0x12 | 0x13) {
        return Err(format!(
            "Only DME addresses 0x12 / 0x13 are supported (got 0x{:02X})",
            ecu_address
        ));
    }
    let _safe = sanitize_profile_name(&name)?;
    Err("This build does not include live-ECU access. Rebuild with \
         `--features live-ecu` to enable clone-from-car. See SCOPE.md."
        .to_string())
}

#[cfg(feature = "live-ecu")]
#[tauri::command]
pub fn simulator_clone_from_car(
    app: AppHandle,
    ip: String,
    ecu_address: u8,
    name: String,
) -> Result<EcuProfile, String> {
    if !is_valid_bind(&format!("{}:1", ip)) {
        return Err(format!("Invalid IP: {}", ip));
    }
    if !matches!(ecu_address, 0x12 | 0x13) {
        return Err(format!(
            "Only DME addresses 0x12 / 0x13 are supported (got 0x{:02X})",
            ecu_address
        ));
    }
    let safe = sanitize_profile_name(&name)?;
    clone::clone_from_car(Some(&app), &ip, ecu_address, &safe)
}

/// Returns the absolute path to the captures directory so the frontend can
/// surface a "Open captures folder" link.
#[tauri::command]
pub fn simulator_captures_dir() -> String {
    capture::captures_dir().to_string_lossy().to_string()
}

#[derive(serde::Serialize)]
pub struct FlashSession {
    pub dir_name: String,
    pub dir_path: String,
    pub vin: Option<String>,
    pub started_at: String,
    pub segment_count: usize,
    pub total_bytes: u64,
    pub min_address: u32,
    pub max_address: u32,
}

#[derive(serde::Serialize)]
pub struct FlashSegmentFile {
    pub address: u32,
    pub size: u64,
    pub file_path: String,
}

/// List all capture session directories that contain at least one
/// `seg_*.bin` file (i.e. real flash captures, not just probe sweeps).
/// Most-recent first, so the editor's "Captured Flashes" panel can show
/// past sessions even after the flasher has disconnected.
#[tauri::command]
pub fn simulator_list_flash_sessions() -> Result<Vec<FlashSession>, String> {
    let root = capture::captures_dir();
    let mut out: Vec<FlashSession> = Vec::new();
    // Tolerate the captures dir not existing yet — that just means no
    // flash sessions have been captured on this device. Return an empty
    // list instead of an OS error 2 "No such file or directory".
    let entries = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(format!("read captures dir: {}", e)),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let segments = list_segments_in(&path);
        if segments.is_empty() {
            continue;
        }
        let dir_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        // Directory name format: `YYYYMMDD_HHMMSS_VIN`
        let mut parts = dir_name.splitn(3, '_');
        let date = parts.next().unwrap_or("");
        let time = parts.next().unwrap_or("");
        let vin = parts
            .next()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let started_at = if date.len() == 8 && time.len() == 6 {
            format!(
                "{}-{}-{} {}:{}:{}",
                &date[0..4],
                &date[4..6],
                &date[6..8],
                &time[0..2],
                &time[2..4],
                &time[4..6],
            )
        } else {
            dir_name.clone()
        };
        let total_bytes: u64 = segments.iter().map(|s| s.size).sum();
        let min_address = segments.iter().map(|s| s.address).min().unwrap_or(0);
        let max_address = segments
            .iter()
            .map(|s| s.address.saturating_add(s.size as u32))
            .max()
            .unwrap_or(0);
        out.push(FlashSession {
            dir_name,
            dir_path: path.to_string_lossy().to_string(),
            vin,
            started_at,
            segment_count: segments.len(),
            total_bytes,
            min_address,
            max_address,
        });
    }
    // Newest first.
    out.sort_by(|a, b| b.dir_name.cmp(&a.dir_name));
    Ok(out)
}

/// List the captured segment files inside a single session directory.
/// `dir_name` must be a bare folder name (no path separators); we resolve
/// it under the captures root and refuse anything that escapes.
#[tauri::command]
pub fn simulator_list_segments(dir_name: String) -> Result<Vec<FlashSegmentFile>, String> {
    let path = resolve_session_dir(&dir_name)?;
    Ok(list_segments_in(&path))
}

/// Concatenate every `seg_*.bin` in `dir_name` into one contiguous
/// flash dump (gaps padded with `0xFF`) and stash it in
/// `AppState.last_bytes`. Returns the byte count; frontend calls
/// `pull_last_bytes` to retrieve the actual bytes as a raw
/// `ArrayBuffer`. Same two-command split as the other large-binary
/// commands — see `pull_last_bytes` in `commands.rs`.
#[tauri::command]
pub fn simulator_export_flash_bin(
    dir_name: String,
    base_address: Option<u32>,
    state: tauri::State<'_, crate::commands::AppState>,
) -> Result<usize, String> {
    use crate::op_log::OpLog;
    let mut op = OpLog::new();

    let build_log = |op: &OpLog, status: &str, footer_body: String| {
        let header = crate::op_log::header(
            "Simulator Flash Export",
            &[
                ("Session", dir_name.clone()),
                (
                    "Base address",
                    match base_address {
                        Some(a) => format!("0x{:08X} (user-specified)", a),
                        None => "(auto from segments)".to_string(),
                    },
                ),
                ("Status", status.to_string()),
            ],
        );
        op.format(&header, &footer_body)
    };

    op.push(format!("Resolving session dir: {}", dir_name));
    let session_dir = match resolve_session_dir(&dir_name) {
        Ok(d) => d,
        Err(e) => {
            op.push(format!("resolve_session_dir failed: {}", e));
            crate::op_log::stash(
                &state,
                build_log(&op, "FAILED", format!("RESULT: FAILED\nError: {}\n", e)),
            );
            return Err(e);
        }
    };
    let segments = list_segments_in(&session_dir);
    op.push(format!("Found {} segment(s)", segments.len()));
    if segments.is_empty() {
        let e = "session has no captured segments".to_string();
        crate::op_log::stash(
            &state,
            build_log(&op, "FAILED", format!("RESULT: FAILED\nError: {}\n", e)),
        );
        return Err(e);
    }
    let base = base_address.unwrap_or_else(|| segments.iter().map(|s| s.address).min().unwrap());
    let end = segments
        .iter()
        .map(|s| s.address.saturating_add(s.size as u32))
        .max()
        .unwrap_or(base);
    op.push(format!(
        "Computed flash range: 0x{:08X}..0x{:08X}",
        base, end
    ));
    if end <= base {
        let e = "computed flash range is empty".to_string();
        crate::op_log::stash(
            &state,
            build_log(&op, "FAILED", format!("RESULT: FAILED\nError: {}\n", e)),
        );
        return Err(e);
    }
    let span = (end - base) as usize;
    const MAX_SPAN: usize = 64 * 1024 * 1024;
    if span > MAX_SPAN {
        let e = format!(
            "flash span {} bytes exceeds {} MiB cap",
            span,
            MAX_SPAN / (1024 * 1024)
        );
        op.push(e.clone());
        crate::op_log::stash(
            &state,
            build_log(&op, "FAILED", format!("RESULT: FAILED\nError: {}\n", e)),
        );
        return Err(e);
    }
    let mut buf = vec![0xFFu8; span];
    for seg in &segments {
        if seg.address < base {
            op.push(format!(
                "Skipping segment 0x{:08X}: below base 0x{:08X}",
                seg.address, base
            ));
            continue;
        }
        let offset = (seg.address - base) as usize;
        let bytes = match std::fs::read(&seg.file_path) {
            Ok(b) => b,
            Err(e) => {
                let msg = format!("read {}: {}", seg.file_path, e);
                op.push(msg.clone());
                crate::op_log::stash(
                    &state,
                    build_log(&op, "FAILED", format!("RESULT: FAILED\nError: {}\n", msg)),
                );
                return Err(msg);
            }
        };
        let end_off = offset.saturating_add(bytes.len());
        if end_off > buf.len() {
            let e = format!(
                "segment 0x{:08X} ({} bytes) extends past computed flash end",
                seg.address,
                bytes.len()
            );
            op.push(e.clone());
            crate::op_log::stash(
                &state,
                build_log(&op, "FAILED", format!("RESULT: FAILED\nError: {}\n", e)),
            );
            return Err(e);
        }
        op.push(format!(
            "Placed segment 0x{:08X} ({} bytes) at offset 0x{:06X}",
            seg.address,
            bytes.len(),
            offset
        ));
        buf[offset..end_off].copy_from_slice(&bytes);
    }
    let len = buf.len();
    op.push(format!("Assembled flash dump: {} bytes", len));
    log::info!(
        "Built flash dump from session {} ({} bytes), stashing for pull_last_bytes",
        dir_name,
        len
    );
    let mut stash = state
        .last_bytes
        .lock()
        .map_err(|_| "internal state lock error".to_string())?;
    *stash = Some(buf);
    drop(stash);

    crate::op_log::stash(
        &state,
        build_log(
            &op,
            "SUCCESS",
            format!(
                "RESULT: SUCCESS\nSegments:     {}\nSpan:         {} bytes\nBase address: 0x{:08X}\n",
                segments.len(),
                len,
                base
            ),
        ),
    );
    Ok(len)
}

/// Resolve a session folder name under the captures root, refusing any
/// input containing path separators or `..` components. Mirrors the
/// `sanitize_profile_name` defence-in-depth pattern.
fn resolve_session_dir(dir_name: &str) -> Result<std::path::PathBuf, String> {
    if dir_name.is_empty() || dir_name.len() > 128 {
        return Err("session name length out of range".to_string());
    }
    if dir_name.contains('/') || dir_name.contains('\\') || dir_name.contains("..") {
        return Err("session name contains path separators".to_string());
    }
    let root = capture::captures_dir();
    let path = root.join(dir_name);
    let canonical_root = std::fs::canonicalize(&root).unwrap_or(root);
    let canonical_path =
        std::fs::canonicalize(&path).map_err(|e| format!("session not found: {}", e))?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err("session path escaped captures directory".to_string());
    }
    if !canonical_path.is_dir() {
        return Err("session path is not a directory".to_string());
    }
    Ok(canonical_path)
}

/// Walk a session directory for `seg_<HEX>_<N>_bytes.bin` files and
/// return them sorted by start address. The address is parsed from the
/// filename (the simulator's `capture::write_segment` is the only thing
/// that ever writes these, so the filename is authoritative).
fn list_segments_in(path: &std::path::Path) -> Vec<FlashSegmentFile> {
    let mut out: Vec<FlashSegmentFile> = Vec::new();
    let entries = match std::fs::read_dir(path) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let name = match p.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if !name.starts_with("seg_") || !name.ends_with(".bin") {
            continue;
        }
        // `seg_<ADDR_HEX>_<SIZE>_bytes.bin`
        let stem = &name[4..name.len() - 4];
        let mut parts = stem.split('_');
        let addr_hex = match parts.next() {
            Some(h) => h,
            None => continue,
        };
        let address = match u32::from_str_radix(addr_hex, 16) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        out.push(FlashSegmentFile {
            address,
            size,
            file_path: p.to_string_lossy().to_string(),
        });
    }
    out.sort_by_key(|s| s.address);
    out
}

// ── Internals ───────────────────────────────────────────────────────────

fn load_profile(name: Option<&str>) -> Result<EcuProfile, String> {
    let n = name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            "No profile selected. Create a new profile or clone one from a live car first."
                .to_string()
        })?;
    let safe = sanitize_profile_name(n)?;
    let path = profile::profiles_dir().join(format!("{}.json", safe));

    // Defence-in-depth: even after name sanitisation, canonicalize and
    // verify the resolved path stays inside the profiles directory. Catches
    // weird filesystem edge cases (symlinks, junctions, parent escapes via
    // OS-level rewriting) before any I/O.
    let dir = profile::profiles_dir();
    let canonical_dir = std::fs::canonicalize(&dir).unwrap_or(dir);
    if let Ok(canonical_path) = std::fs::canonicalize(&path) {
        if !canonical_path.starts_with(&canonical_dir) {
            return Err("profile path escaped profiles directory".to_string());
        }
    }
    EcuProfile::load_from_file(&path)
}

/// Allow only `[A-Za-z0-9_-]{1,64}` as a profile name. Anything outside that
/// alphabet is rejected — no slashes, no dots, no spaces, no nulls — so
/// `name` cannot be used to traverse out of the profiles directory or
/// clobber files like `~/.bashrc` via a crafted IPC payload.
fn sanitize_profile_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err("profile name must be 1..=64 characters".to_string());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        return Err("profile name may only contain [A-Za-z0-9_-]".to_string());
    }
    Ok(trimmed.to_string())
}

fn is_valid_bind(addr: &str) -> bool {
    // Strict: must parse as a literal `SocketAddr` (IPv4 or IPv6 + port).
    // We deliberately do NOT call `to_socket_addrs` because that performs
    // DNS resolution on hostnames, which would let an IPC caller force the
    // simulator into a synchronous DNS lookup against an attacker-controlled
    // name. Localhost / 0.0.0.0 / explicit IPs only.
    use std::net::SocketAddr;
    addr.parse::<SocketAddr>().is_ok()
}
