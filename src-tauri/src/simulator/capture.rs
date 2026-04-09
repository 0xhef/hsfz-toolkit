//! Per-session capture: written segments + UDS transcript log.
//!
//! Each accepted connection gets a new directory under
//! `<data_dir>/captures/<timestamp>_<vin>/` containing:
//!
//!   * one `.bin` per `RequestDownload` → `RequestTransferExit` pair, named
//!     by start address and size — this is the actual flash payload the
//!     tester wrote
//!   * `transcript.jsonl` — newline-delimited JSON, one entry per UDS
//!     exchange (request + response), with timestamps and hex-encoded bodies
//!
//! Everything is best-effort: any I/O failure is logged and the simulator
//! continues — we never want a disk-full or permission error to break a
//! live flash session.

use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::profile::EcuProfile;

/// Schema version stamped into the session header so future tooling can
/// reject (or upgrade) older transcripts cleanly.
const TRANSCRIPT_SCHEMA: &str = "bmsec.simulator.transcript/1";

/// Returns the root captures directory, creating it if missing.
/// Resolves via the cross-platform `app_paths` helper which on Android
/// lands in app-scoped external storage (visible to file managers).
pub fn captures_dir() -> PathBuf {
    crate::app_paths::captures_dir()
}

fn timestamp_token() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // YYYYMMDD_HHMMSS in UTC, computed without chrono.
    let days = secs / 86400;
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = days_to_ymd(days as i64);
    format!("{:04}{:02}{:02}_{:02}{:02}{:02}", y, mo, d, h, m, s)
}

/// Civil-from-days algorithm (Howard Hinnant) — converts days-since-epoch
/// into a (year, month, day) tuple. We avoid pulling in `chrono` for one
/// timestamp.
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    (y as i32, m as u32, d as u32)
}

/// Per-session writer. Owned by the connection thread.
///
/// Produces three artifacts per session in `<captures>/<ts>_<vin>/`:
///
///   * `transcript.jsonl` — newline-delimited JSON, one entry per *event*
///     (UDS request/response, ALIVE_CHECK echo, errors, lifecycle markers).
///     Schema-versioned via the first `kind: "session_start"` line so
///     future tooling can detect and migrate older transcripts.
///   * `raw.hsfz` — every HSFZ frame the simulator saw or sent, in the
///     same `[len:u32][ctrl:u16][payload]` wire format the live socket
///     uses. Each frame is preceded by a 16-byte tag
///     `[t_ms_le:u64][dir:u8 0=in 1=out][reserved:7]` so the file can be
///     diffed against a real PCAP byte-for-byte and reassembled into a
///     synthetic pcap if needed.
///   * `seg_*.bin` — one file per finished `RequestDownload`/`Exit`
///     segment, named by start address and size.
///
/// Everything is best-effort. Any I/O failure is logged via `log::warn!`
/// and the simulator continues — we never want a disk-full or permission
/// error to break a live flash session.
pub struct CaptureSession {
    dir: PathBuf,
    transcript: Option<File>,
    raw: Option<File>,
    started_ms: u128,
    request_count: u64,
    response_count: u64,
    alive_count: u64,
    error_count: u64,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TranscriptEntry<'a> {
    SessionStart {
        schema: &'static str,
        t_ms: u128,
        wall_iso8601: String,
        peer: &'a str,
        bind_addr: &'a str,
        profile_name: &'a str,
        profile_vin: Option<&'a str>,
        ecu_address: u8,
        did_count: usize,
    },
    SessionEnd {
        t_ms: u128,
        request_count: u64,
        response_count: u64,
        alive_count: u64,
        error_count: u64,
        outcome: &'a str,
    },
    UdsRequest {
        t_ms: u128,
        service: u8,
        body_hex: String,
        note: Option<&'a str>,
    },
    UdsResponse {
        t_ms: u128,
        service: u8,
        body_hex: String,
        note: Option<&'a str>,
    },
    AliveCheck {
        t_ms: u128,
        payload_len: usize,
        payload_hex: String,
    },
    Event {
        t_ms: u128,
        category: &'a str, // "info" | "warn" | "error"
        message: String,
    },
}

/// Direction marker for the binary `raw.hsfz` stream.
const RAW_DIR_IN: u8 = 0;
const RAW_DIR_OUT: u8 = 1;

impl CaptureSession {
    pub fn new(profile: &EcuProfile) -> Self {
        let vin = profile.vin.clone().unwrap_or_else(|| "UNKNOWN".to_string());
        let dirname = format!("{}_{}", timestamp_token(), vin);
        let dir = captures_dir().join(dirname);
        if let Err(e) = std::fs::create_dir_all(&dir) {
            log::warn!("capture: cannot create {}: {}", dir.display(), e);
        }
        let transcript = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("transcript.jsonl"))
            .ok();
        let raw = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("raw.hsfz"))
            .ok();
        let started_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        log::info!("capture: session dir = {}", dir.display());
        Self {
            dir,
            transcript,
            raw,
            started_ms,
            request_count: 0,
            response_count: 0,
            alive_count: 0,
            error_count: 0,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn now_rel_ms(&self) -> u128 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis().saturating_sub(self.started_ms))
            .unwrap_or(0)
    }

    /// First entry on every transcript: who connected, which profile is
    /// being served, when in wall-clock time, and the schema version.
    pub fn log_session_start(&mut self, peer: &str, bind_addr: &str, profile: &EcuProfile) {
        let entry = TranscriptEntry::SessionStart {
            schema: TRANSCRIPT_SCHEMA,
            t_ms: 0,
            wall_iso8601: current_iso8601(),
            peer,
            bind_addr,
            profile_name: &profile.name,
            profile_vin: profile.vin.as_deref(),
            ecu_address: profile.ecu_address,
            did_count: profile.dids.len(),
        };
        self.append(&entry);
    }

    /// Final entry on every transcript: counts and outcome (`"ok"` /
    /// `"error: <msg>"`). Always called from `server.rs`, even on failure
    /// paths, via the connection-thread `Drop` of the session loop.
    pub fn log_session_end(&mut self, outcome: &str) {
        let entry = TranscriptEntry::SessionEnd {
            t_ms: self.now_rel_ms(),
            request_count: self.request_count,
            response_count: self.response_count,
            alive_count: self.alive_count,
            error_count: self.error_count,
            outcome,
        };
        self.append(&entry);
        // Best-effort flush so the last lines are durable even if the
        // process is killed shortly after.
        if let Some(t) = self.transcript.as_mut() {
            let _ = t.flush();
        }
        if let Some(r) = self.raw.as_mut() {
            let _ = r.flush();
        }
    }

    /// Append a request entry. `body` is the *full* UDS message starting
    /// with the service byte.
    pub fn log_request(&mut self, body: &[u8], note: Option<&str>) {
        self.request_count += 1;
        let entry = TranscriptEntry::UdsRequest {
            t_ms: self.now_rel_ms(),
            service: body.first().copied().unwrap_or(0),
            body_hex: encode_hex(body),
            note,
        };
        self.append(&entry);
    }

    /// Append a response entry.
    pub fn log_response(&mut self, body: &[u8], note: Option<&str>) {
        self.response_count += 1;
        let entry = TranscriptEntry::UdsResponse {
            t_ms: self.now_rel_ms(),
            service: body.first().copied().unwrap_or(0),
            body_hex: encode_hex(body),
            note,
        };
        self.append(&entry);
    }

    /// Append an HSFZ ALIVE_CHECK echo entry. We don't normally surface
    /// these to the live UI (too noisy) but they're invaluable when
    /// diagnosing why a tester tore down the session prematurely.
    pub fn log_alive_check(&mut self, payload: &[u8]) {
        self.alive_count += 1;
        let entry = TranscriptEntry::AliveCheck {
            t_ms: self.now_rel_ms(),
            payload_len: payload.len(),
            payload_hex: encode_hex(payload),
        };
        self.append(&entry);
    }

    /// Generic event row — connection lifecycle, warnings, parse errors,
    /// transient I/O failures the session loop chose to recover from.
    pub fn log_event(&mut self, category: &str, message: impl Into<String>) {
        if category == "error" {
            self.error_count += 1;
        }
        let entry = TranscriptEntry::Event {
            t_ms: self.now_rel_ms(),
            category,
            message: message.into(),
        };
        self.append(&entry);
    }

    /// Append a raw HSFZ frame to `raw.hsfz`. The frame must already be
    /// in wire format (`[len:u32 BE][ctrl:u16 BE][payload]`) — this matches
    /// what `read_frame` sees on the wire and what the various
    /// `write_*_frame` helpers send out, so the file is a faithful
    /// byte-for-byte record of the entire session.
    pub fn log_raw_in(&mut self, frame: &[u8]) {
        self.write_raw(RAW_DIR_IN, frame);
    }

    pub fn log_raw_out(&mut self, frame: &[u8]) {
        self.write_raw(RAW_DIR_OUT, frame);
    }

    fn write_raw(&mut self, dir: u8, frame: &[u8]) {
        // Snapshot the timestamp *before* taking the mutable borrow on
        // `self.raw`, otherwise we hit a self-borrow conflict.
        let t = self.now_rel_ms() as u64;
        let Some(file) = self.raw.as_mut() else {
            return;
        };
        let mut tag = [0u8; 16];
        tag[0..8].copy_from_slice(&t.to_le_bytes());
        tag[8] = dir;
        // bytes 9..16 reserved / future use (peer port, frame seq, …)
        let _ = file.write_all(&tag);
        let _ = file.write_all(frame);
    }

    fn append(&mut self, entry: &TranscriptEntry<'_>) {
        let Some(file) = self.transcript.as_mut() else {
            return;
        };
        if let Ok(line) = serde_json::to_string(entry) {
            let _ = writeln!(file, "{}", line);
        }
    }

    /// Write a completed download segment to disk.
    /// Returns the path so the simulator can emit it to the frontend.
    pub fn write_segment(&self, address: u32, data: &[u8]) -> Option<PathBuf> {
        let name = format!("seg_{:08X}_{}_bytes.bin", address, data.len());
        let path = self.dir.join(name);
        match std::fs::write(&path, data) {
            Ok(()) => {
                log::info!(
                    "capture: wrote segment 0x{:08X} ({} bytes) → {}",
                    address,
                    data.len(),
                    path.display()
                );
                Some(path)
            }
            Err(e) => {
                log::warn!("capture: failed to write segment: {}", e);
                None
            }
        }
    }
}

/// ISO-8601 wall-clock for the session header. Hand-rolled to avoid the
/// chrono dep — same algorithm as `clone::current_iso8601`.
fn current_iso8601() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = days_to_ymd(days as i64);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s)
}

fn encode_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02X}", byte));
    }
    s
}
