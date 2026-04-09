//! TCP listener and per-connection session loop.
//!
//! v1 architecture:
//!
//!   * One background thread runs `accept()` in a loop.
//!   * Each accepted connection is handled **inline** on the listener
//!     thread (single concurrent flasher) — when the session ends, the
//!     listener resumes accepting. This keeps the model simple and matches
//!     reality (a real car only talks to one tester at a time).
//!   * A `stop_flag` AtomicBool unblocks the loop on a short accept timeout
//!     so `simulator_stop` is responsive.
//!
//! Every UDS exchange is emitted as a Tauri event so the frontend can
//! stream the transcript live.

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter};

use super::capture::CaptureSession;
use super::discovery_responder;
use super::hsfz::{
    self, configure_socket, frame_to_wire, read_frame, write_ack, write_alive_check_response,
    write_negative_response, write_uds_response, ReadOutcome, CONTROL_ALIVE_CHECK_REQUEST,
    CONTROL_ALIVE_CHECK_RESPONSE, CONTROL_UDS, HSFZ_PORT, TESTER_ADDRESS,
};
use super::profile::EcuProfile;
use super::services::{handle_request, HandlerOutcome};
use super::state::SessionState;

/// Configuration handed to the listener thread on startup.
pub struct ServerConfig {
    pub bind_addr: String, // e.g. "0.0.0.0:6801"
    pub profile: EcuProfile,
}

/// Outcome reported via `log_session_end` so the on-disk transcript shows
/// why a session terminated.
fn outcome_string(result: &std::io::Result<()>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(e) => format!("error: {}", e),
    }
}

/// Handle returned to the Tauri command layer. Drop or call `stop()` to
/// terminate the listener and the discovery responder together.
pub struct RunningServer {
    pub stop_flag: Arc<AtomicBool>,
    pub thread: Option<thread::JoinHandle<()>>,
    pub discovery_thread: Option<thread::JoinHandle<()>>,
    pub bind_addr: String,
}

impl RunningServer {
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            // Best-effort: don't block forever if the listener wedged.
            let _ = handle.join();
        }
        if let Some(handle) = self.discovery_thread.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Serialize, Clone)]
struct TranscriptEvent {
    direction: &'static str, // "REQ" or "RSP"
    service: u8,
    body_hex: String,
    note: Option<String>,
}

#[derive(Serialize, Clone)]
struct StatusEvent {
    state: &'static str, // "listening" / "connected" / "disconnected" / "stopped" / "error"
    detail: String,
}

#[derive(Serialize, Clone)]
struct SegmentEvent {
    address: u32,
    size: usize,
    file_path: String,
}

/// Spawn the listener thread. Returns immediately.
pub fn spawn(app: AppHandle, cfg: ServerConfig) -> Result<RunningServer, String> {
    let listener =
        TcpListener::bind(&cfg.bind_addr).map_err(|e| format!("bind {}: {}", cfg.bind_addr, e))?;
    listener
        .set_nonblocking(false)
        .map_err(|e| format!("set_nonblocking: {}", e))?;
    // Short accept timeout so the stop flag is checked frequently.
    // (Linux: TCP listeners don't honour SO_RCVTIMEO directly, so we use
    //  set_nonblocking + sleep below as a fallback if needed. On most
    //  platforms set_read_timeout on the accepted stream is enough; the
    //  listener itself uses non-blocking polling.)
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking: {}", e))?;

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_thread = stop_flag.clone();
    let bind_addr = cfg.bind_addr.clone();
    let bind_addr_log = bind_addr.clone();

    log::info!("simulator: listening on {}", bind_addr_log);
    emit_status(&app, "listening", format!("Listening on {}", bind_addr_log));

    // Start the UDP discovery responder so diagnostic tools
    // can find the simulator via the standard ENET broadcast probe.
    // Best-effort: a port-already-in-use error logs a warning and the
    // TCP listener still comes up.
    let discovery_thread = discovery_responder::spawn(cfg.profile.clone(), stop_flag.clone());

    let app_for_thread = app.clone();
    let bind_for_thread = bind_addr.clone();
    let handle = thread::Builder::new()
        .name(format!("dme-sim-listener-{}", bind_addr))
        .spawn(move || {
            listener_loop(
                listener,
                stop_flag_thread,
                app_for_thread,
                cfg.profile,
                bind_for_thread,
            );
        })
        .map_err(|e| format!("spawn listener: {}", e))?;

    Ok(RunningServer {
        stop_flag,
        thread: Some(handle),
        discovery_thread,
        bind_addr,
    })
}

fn listener_loop(
    listener: TcpListener,
    stop_flag: Arc<AtomicBool>,
    app: AppHandle,
    profile_template: EcuProfile,
    bind_addr: String,
) {
    while !stop_flag.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                log::info!("simulator: client connected from {}", peer);
                if let Err(e) = configure_socket(&stream) {
                    log::warn!("simulator: configure_socket: {}", e);
                }
                // Each session gets its own copy of the profile so writes
                // (WDBI) don't bleed across sessions.
                let mut state = SessionState::new(profile_template.clone());
                let mut capture = CaptureSession::new(&state.profile);
                let peer_str = peer.to_string();
                capture.log_session_start(&peer_str, &bind_addr, &state.profile);
                capture.log_event("info", format!("Tester connected from {}", peer_str));
                emit_status(
                    &app,
                    "connected",
                    format!(
                        "Tester connected: {} — capture dir: {}",
                        peer,
                        capture.dir().display()
                    ),
                );
                let result = session_loop(&mut stream, &mut state, &mut capture, &app);
                let outcome = outcome_string(&result);
                capture.log_event(
                    if result.is_ok() { "info" } else { "warn" },
                    format!("Session ended: {}", outcome),
                );
                capture.log_session_end(&outcome);
                if let Err(e) = result {
                    log::warn!("simulator: session ended with error: {}", e);
                    emit_status(&app, "disconnected", format!("Session error: {}", e));
                } else {
                    emit_status(&app, "disconnected", "Tester disconnected".to_string());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                log::warn!("simulator: accept error: {}", e);
                emit_status(&app, "error", format!("Accept error: {}", e));
                thread::sleep(Duration::from_millis(500));
            }
        }
    }
    log::info!("simulator: listener stopped");
    emit_status(&app, "stopped", "Listener stopped".to_string());
}

fn session_loop(
    stream: &mut TcpStream,
    state: &mut SessionState,
    capture: &mut CaptureSession,
    app: &AppHandle,
) -> std::io::Result<()> {
    loop {
        let frame = match read_frame(stream)? {
            ReadOutcome::Frame(f) => f,
            ReadOutcome::Eof => {
                capture.log_event("info", "Peer closed connection (clean EOF)");
                return Ok(());
            }
            ReadOutcome::Idle => {
                // Read timeout fired without bytes — just loop. We
                // don't proactively ping the tester; real DMEs don't
                // either. The flasher's keepalive is its own VIN-poll loop
                // at 22 F190 dst=0x10, which we answer below.
                continue;
            }
        };

        // Persist the raw inbound frame to `raw.hsfz` first — even bytes
        // we end up ignoring (unknown control codes, malformed UDS) get
        // recorded for offline analysis.
        let raw_in = frame_to_wire(frame.control, &frame.payload);
        capture.log_raw_in(&raw_in);

        // Alive-check handling.
        //
        // HSFZ defines two distinct control codes:
        //   0x0011 — Alive Check **Request**  (tester → ECU "are you there?")
        //   0x0012 — Alive Check **Response** (ECU → tester "yes, here's my addr")
        //
        // The ENET hardware tester sends 0x0011 every ~1–5s and tears the
        // TCP session down if it doesn't get a 0x0012 reply containing
        // the ECU's logical address. We also tolerate a peer that sends
        // 0x0012 unsolicited (some loopback test rigs do that) by
        // logging it without replying — replying to a response would
        // create an infinite ping-pong.
        if frame.control == CONTROL_ALIVE_CHECK_REQUEST {
            log::debug!(
                "simulator: ALIVE_CHECK request ({} bytes), replying",
                frame.payload.len()
            );
            capture.log_alive_check(&frame.payload);
            // Reply as the profile's primary ECU address. Body
            // payload of the alive-check is just src/dst, so an
            // arbitrary ECU id is fine.
            let sent = write_alive_check_response(stream, state.profile.ecu_address)?;
            capture.log_raw_out(&sent);
            continue;
        }
        if frame.control == CONTROL_ALIVE_CHECK_RESPONSE {
            capture.log_alive_check(&frame.payload);
            continue;
        }

        if frame.control != CONTROL_UDS {
            log::debug!(
                "simulator: ignoring HSFZ control 0x{:04X} ({} bytes)",
                frame.control,
                frame.payload.len()
            );
            capture.log_event(
                "warn",
                format!(
                    "Ignored HSFZ control 0x{:04X} ({} bytes)",
                    frame.control,
                    frame.payload.len()
                ),
            );
            continue;
        }

        let req = match frame.as_uds_request() {
            Some(r) => r,
            None => {
                capture.log_event("warn", "Truncated UDS frame, skipping");
                continue;
            }
        };

        // Build the full request bytes for the transcript / ACK echo:
        // [service][body…]
        let mut full_req = Vec::with_capacity(1 + req.body.len());
        full_req.push(req.service);
        full_req.extend_from_slice(&req.body);

        // ACK every UDS request, mirroring real DME wire behaviour:
        //   src/dst echo the request direction (tester→ECU)
        //   body echoes the first 5 bytes of the request UDS payload
        if let Ok(ack_bytes) = write_ack(stream, req.src, req.dst, &full_req) {
            capture.log_raw_out(&ack_bytes);
        }

        capture.log_request(&full_req, None);
        emit_transcript(app, "REQ", req.service, &full_req, None);

        // Dispatch. The simulator answers as whichever ECU the tester
        // addressed (`req.dst`), not the profile's primary ECU — so a
        // single profile can answer 0x10 / 0x12 / 0x40 etc. on one
        // TCP session, the way a real HSFZ gateway does.
        let resp_src = req.dst;
        let resp_dst = req.src;
        let _ = TESTER_ADDRESS; // suppress unused-import noise; kept for clarity
        let outcome = handle_request(state, req.service, &req.body);

        match outcome {
            HandlerOutcome::Positive(resp) => {
                capture.log_response(&resp, None);
                emit_transcript(app, "RSP", resp.first().copied().unwrap_or(0), &resp, None);
                let sent = write_uds_response(stream, resp_src, resp_dst, &resp)?;
                capture.log_raw_out(&sent);
            }
            HandlerOutcome::Negative(nrc) => {
                let resp = vec![0x7F, req.service, nrc];
                capture.log_response(&resp, Some("NRC"));
                emit_transcript(app, "RSP", 0x7F, &resp, Some(format!("NRC 0x{:02X}", nrc)));
                let sent = write_negative_response(stream, resp_src, resp_dst, req.service, nrc)?;
                capture.log_raw_out(&sent);
            }
            HandlerOutcome::SegmentFinished {
                address,
                data,
                response,
            } => {
                let saved = capture.write_segment(address, &data);
                capture.log_response(&response, Some("segment finished"));
                emit_transcript(
                    app,
                    "RSP",
                    response.first().copied().unwrap_or(0),
                    &response,
                    Some(format!("segment 0x{:08X} finished", address)),
                );
                if let Some(path) = saved {
                    let _ = app.emit(
                        "simulator-segment",
                        SegmentEvent {
                            address,
                            size: data.len(),
                            file_path: path.to_string_lossy().to_string(),
                        },
                    );
                }
                let sent = write_uds_response(stream, resp_src, resp_dst, &response)?;
                capture.log_raw_out(&sent);
            }
        }
    }
}

fn emit_transcript(
    app: &AppHandle,
    direction: &'static str,
    service: u8,
    body: &[u8],
    note: Option<String>,
) {
    let _ = app.emit(
        "simulator-transcript",
        TranscriptEvent {
            direction,
            service,
            body_hex: encode_hex(body),
            note,
        },
    );
}

fn emit_status(app: &AppHandle, state: &'static str, detail: String) {
    let _ = app.emit("simulator-status", StatusEvent { state, detail });
}

fn encode_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02X}", byte));
    }
    s
}

#[allow(dead_code)]
pub fn default_bind_addr() -> String {
    format!("0.0.0.0:{}", HSFZ_PORT)
}

// Make sure unused HSFZ helpers don't trigger warnings.
#[allow(dead_code)]
fn _link_hsfz() {
    let _ = hsfz::TESTER_ADDRESS;
}
