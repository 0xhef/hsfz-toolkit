//! MEVD17 calibration-region read over HSFZ/UDS.
//!
//! Implements the "fast" MEVD17 calibration read path in a self-contained,
//! synchronous HSFZ/TCP client. Reads the MEVD17 calibration region
//! (~511 KB) using `ReadMemoryByAddress` (UDS 0x23) in 4092-byte blocks.
//!
//! # Scope and safety rails (see also: SCOPE.md in the repo root)
//!
//! This module is **read-only** by design. It does not implement, and
//! intentionally cannot be made to perform:
//!
//!   * `0x27` SecurityAccess key computation for real ECUs
//!   * `0x34` RequestDownload / `0x36` TransferData / `0x37` TransferExit
//!     against a real ECU (those services exist only in the simulator,
//!     which *receives* flashes for research — it never sends them)
//!   * Reads of any memory region outside the MEVD17 calibration bounds
//!     `[CALIBRATION_START, CALIBRATION_END]`, enforced at runtime by
//!     `assert_unprotected_region` on every `ReadMemoryByAddress` call
//!
//! The calibration region this reader targets is exposed by the MEVD17
//! DME in the default diagnostic session without SecurityAccess — no
//! seed/key exchange, no session upgrade, no authentication. It is not
//! protected by any technological measure within the meaning of
//! 17 USC §1201(a)(3)(B).
//!
//! Network-level scope: `validate_host` refuses public/internet-routable
//! targets. Only RFC1918, link-local, loopback, and plain DNS-style
//! hostnames are accepted, reinforcing the "bench research on a
//! directly-connected vehicle you own" use case.
//!
//! Two save formats are supported:
//!   * `raw` — write the calibration bytes verbatim
//!   * `padded_4mb` — embed the calibration at offset `0x180000` inside a
//!     4 MB image padded with `0x00`, mirroring the on-flash layout
//!
//! # Build feature
//!
//! The live-ECU networking code is gated behind the `live-ecu` Cargo
//! feature. The feature is part of the default feature set so developer
//! builds work unchanged. A "research-only" binary that has no live-ECU
//! reader compiled in can be produced with:
//!
//! ```sh
//! cargo build --release --no-default-features --features research
//! ```
//!
//! When `live-ecu` is disabled, `read_calibration_region` and
//! `discover_vehicles` return a clear error at runtime without attempting
//! any socket activity.

#![cfg_attr(not(feature = "live-ecu"), allow(dead_code))]

pub mod client;
pub mod discovery;

use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};
#[cfg(feature = "live-ecu")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "live-ecu")]
use std::sync::Arc;
#[cfg(feature = "live-ecu")]
use tauri::ipc::Channel;
use tauri::AppHandle;

#[cfg(feature = "live-ecu")]
use client::{HsfzClient, HSFZ_PORT};

// ── MEVD17 calibration memory map ────────────────────────────────────────
// Derived from captured diagnostic traffic and public reverse-engineering
// references. See docs/mevd17.md for the full memory layout.
pub const CALIBRATION_START: u32 = 0x80180000;
pub const CALIBRATION_END: u32 = 0x801FFC00;
pub const CALIBRATION_SIZE: u32 = CALIBRATION_END - CALIBRATION_START;
pub const READ_BLOCK_SIZE: u16 = 4092;

// ── 4 MB pad layout ──────────────────────────────────────────────────────
const PFLASH_SIZE: usize = 0x400000;
const CALIBRATION_OFFSET: usize = 0x180000;

// ── UDS services ─────────────────────────────────────────────────────────
#[cfg(feature = "live-ecu")]
const SVC_READ_MEMORY_BY_ADDRESS: u8 = 0x23;
#[cfg(feature = "live-ecu")]
const SVC_ROUTINE_CONTROL: u8 = 0x31;

#[cfg(feature = "live-ecu")]
const FEM_BDC_ADDRESS: u8 = 0x40;

#[derive(Debug, Serialize)]
pub struct CalibrationReadResult {
    pub success: bool,
    pub bytes_read: usize,
    pub file_size: usize,
    pub format: String,
    pub message: String,
}

/// One progress update sent over the `tauri::ipc::Channel` from the
/// Rust read loop to the frontend. The frontend renders these directly
/// into the inline progress card. Channels deliver in-order with low
/// latency on every platform (desktop AND mobile) — they're scoped to
/// the active command rather than going through the global event bus,
/// so they don't suffer the buffering/delivery quirks the global event
/// system has on Android WebView.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent {
    pub bytes_read: usize,
    pub total: usize,
    pub percentage: u32,
    pub elapsed_ms: u64,
    /// Optional status note surfaced to the UI. `None` on normal
    /// progress ticks; populated when we hit a transient failure and
    /// are retrying ("Retrying block 0x…"), reconnecting, etc. — so
    /// the user can see the reader recovering instead of staring at a
    /// frozen progress bar.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Human-readable name for common UDS Negative Response Codes.
/// Used to decorate NRC errors so the user gets a real diagnosis
/// instead of "NRC 0x33".
#[cfg(feature = "live-ecu")]
fn nrc_name(nrc: u8) -> &'static str {
    match nrc {
        0x10 => "generalReject",
        0x11 => "serviceNotSupported",
        0x12 => "subFunctionNotSupported",
        0x13 => "incorrectMessageLengthOrInvalidFormat",
        0x14 => "responseTooLong",
        0x21 => "busyRepeatRequest",
        0x22 => "conditionsNotCorrect",
        0x24 => "requestSequenceError",
        0x25 => "noResponseFromSubnetComponent",
        0x26 => "failurePreventsExecutionOfRequestedAction",
        0x31 => "requestOutOfRange",
        0x33 => "securityAccessDenied",
        0x35 => "invalidKey",
        0x36 => "exceedNumberOfAttempts",
        0x37 => "requiredTimeDelayNotExpired",
        0x70 => "uploadDownloadNotAccepted",
        0x71 => "transferDataSuspended",
        0x72 => "generalProgrammingFailure",
        0x73 => "wrongBlockSequenceCounter",
        0x78 => "responsePending",
        0x7E => "subFunctionNotSupportedInActiveSession",
        0x7F => "serviceNotSupportedInActiveSession",
        _ => "unknown",
    }
}

/// Classify a low-level read error string to decide whether retrying
/// the same block is worth it, whether we should drop and reconnect,
/// or whether the error is fatal and we should bail immediately.
#[cfg(feature = "live-ecu")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorClass {
    /// Transient — retry the same request on the same connection.
    /// E.g. read timeout mid-frame, short framing hiccup.
    Transient,
    /// Connection is dead — drop the stream and reconnect before
    /// retrying. E.g. broken pipe, connection reset, EOF.
    ConnectionLost,
    /// Protocol-level refusal from the ECU (NRC) or gateway. Retrying
    /// will not help.
    Fatal,
}

#[cfg(feature = "live-ecu")]
use crate::op_log::OpLog;

/// Build the calibration-read operation log header via the shared
/// header builder.
#[cfg(feature = "live-ecu")]
fn cal_read_header(ip: &str, ecu: u8, save_format: &str) -> String {
    crate::op_log::header(
        "Calibration Read",
        &[
            ("Target IP", ip.to_string()),
            ("ECU address", format!("0x{:02X}", ecu)),
            ("Save format", save_format.to_string()),
            (
                "Calibration bounds",
                format!(
                    "0x{:08X}..0x{:08X} ({} bytes)",
                    CALIBRATION_START, CALIBRATION_END, CALIBRATION_SIZE
                ),
            ),
            ("Read block size", format!("{} bytes", READ_BLOCK_SIZE)),
        ],
    )
}

#[cfg(feature = "live-ecu")]
fn classify_read_error(err: &str) -> ErrorClass {
    let e = err.to_ascii_lowercase();
    if e.contains("broken pipe")
        || e.contains("connection reset")
        || e.contains("connection aborted")
        || e.contains("unexpected eof")
        || e.contains("not connected")
        || e.contains("os error 32")
        || e.contains("os error 104")
        || e.contains("os error 107")
    {
        ErrorClass::ConnectionLost
    } else if e.contains("nrc")
        || e.contains("hsfz gateway error")
        || e.contains("refusing read")
        || e.contains("exceeded pending-response")
    {
        ErrorClass::Fatal
    } else if e.contains("timed out")
        || e.contains("timeout")
        || e.contains("would block")
        || e.contains("interrupted")
    {
        ErrorClass::Transient
    } else {
        // Default to Transient — one retry is cheaper than failing a
        // 30-second read over an unknown intermittent glitch.
        ErrorClass::Transient
    }
}

/// Enforced invariant: this reader will refuse any address range outside
/// the MEVD17 unprotected calibration region. Every call to
/// `read_memory_by_address` flows through this gate. This is deliberate
/// and load-bearing — do not loosen without reading SCOPE.md.
///
/// The bounds `[CALIBRATION_START, CALIBRATION_END]` correspond to the
/// MEVD17 SWFL_1 partition, which the DME exposes via 0x23
/// ReadMemoryByAddress in the default diagnostic session. Any region
/// outside these bounds either (a) doesn't exist, (b) is gated behind
/// SecurityAccess 0x27, or (c) is not part of this project's scope.
fn assert_unprotected_region(addr: u32, size: u32) -> Result<(), String> {
    let end = addr
        .checked_add(size)
        .ok_or_else(|| "address + size overflow".to_string())?;
    if addr < CALIBRATION_START || end > CALIBRATION_END {
        return Err(format!(
            "refusing read outside MEVD17 unprotected calibration region \
             [0x{:08X}..0x{:08X}]: requested 0x{:08X}..0x{:08X}",
            CALIBRATION_START, CALIBRATION_END, addr, end
        ));
    }
    Ok(())
}

/// Validate the IPv4-or-hostname string passed from the frontend.
///
/// Accepts:
///   * Loopback (127.0.0.0/8, ::1)
///   * RFC1918 private ranges (10/8, 172.16/12, 192.168/16)
///   * Link-local (169.254/16) — the common range for direct ENET
///     connections to a vehicle gateway
///   * DNS-style hostnames (no dots-to-numeric-only IPs, so `bmw.local`
///     and similar mDNS names work)
///
/// Refuses anything that parses as a public/internet-routable IPv4. This
/// is deliberate: the tool is designed for bench research on a
/// directly-connected vehicle, not over the internet.
fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() || host.len() > 253 {
        return Err("Invalid host".to_string());
    }
    let ok = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
    if !ok {
        return Err("Invalid host".to_string());
    }

    // If it parses as an IPv4 literal, enforce the private-range policy.
    // If it doesn't parse as an IP, treat it as a hostname and let DNS
    // resolution handle it (a hostname that resolves to a public IP will
    // still connect — users who go out of their way to do that have
    // opted out of the guardrail, and the warning here is documentation
    // rather than a hard block against DNS shenanigans).
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                if !is_bench_ipv4(&v4) {
                    return Err(format!(
                        "refusing to connect to public IP {}: this tool \
                         is scoped to directly-connected vehicles on \
                         loopback, RFC1918, or link-local networks",
                        v4
                    ));
                }
            }
            IpAddr::V6(v6) => {
                if !(v6.is_loopback() || v6.is_unspecified()) {
                    // IPv6 on automotive ENET is rare; reject anything
                    // that isn't loopback to keep the scope tight.
                    return Err("IPv6 targets other than loopback are out of scope".to_string());
                }
            }
        }
    }
    Ok(())
}

/// True if the IPv4 address is in a range suitable for direct bench
/// research: loopback, RFC1918, or link-local.
fn is_bench_ipv4(v4: &Ipv4Addr) -> bool {
    v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
}

// Note: The output path validation that used to live here was removed
// as part of the cross-platform file-I/O refactor. The Rust layer no
// longer touches the filesystem directly for user-picked output paths
// — it returns the file bytes via IPC and the frontend writes them
// via `plugin-fs writeFile`, which handles both POSIX paths and
// Android Storage Access Framework content URIs (`content://...`)
// transparently. See the architecture comment on `read_calibration_region`.

/// Send the FEM/BDC preparation routine 0x0110 to ECU 0x40.
///
/// On vehicles with a gateway FEM/BDC the DME goes silent for read commands
/// until this routine has been issued. Treated as best-effort: a missing or
/// non-FEM gateway must not abort the read, so we log and continue.
#[cfg(feature = "live-ecu")]
fn prepare_fem_for_dme_read(client: &mut HsfzClient, op: &mut OpLog) {
    let req = [0x31, 0x01, 0x10, 0x01, 0x0a, 0x0a, 0x43];
    match client.send_uds(FEM_BDC_ADDRESS, &req) {
        Ok(resp) => op.push(format!("FEM 0x0110 prep ok ({} bytes)", resp.len())),
        Err(e) => op.push(format!("FEM 0x0110 prep failed (continuing): {}", e)),
    }
}

/// Send the DME calibration-read preparation routine 0x0205.
///
/// Best-effort for the same reason: some MEVD17 variants accept the read
/// without it. Errors are logged, never propagated.
#[cfg(feature = "live-ecu")]
fn prepare_dme_calibration_read(client: &mut HsfzClient, ecu: u8, op: &mut OpLog) {
    let req = [
        SVC_ROUTINE_CONTROL,
        0x01,
        0x02,
        0x05,
        0x06,
        0x00,
        0x00,
        0x19,
        0x01,
        0x01,
        0x31,
        0x02,
    ];
    match client.send_uds(ecu, &req) {
        Ok(resp) => op.push(format!("DME 0x0205 prep ok ({} bytes)", resp.len())),
        Err(e) => op.push(format!("DME 0x0205 prep failed (continuing): {}", e)),
    }
}

/// Issue a single ReadMemoryByAddress (0x23) for `size` bytes at `address`.
///
/// **Enforces `assert_unprotected_region` before every read.** This is the
/// single choke-point through which all live-ECU memory reads flow, so
/// the scope guarantee is expressible as: "this tool cannot read any
/// region that is not within `[CALIBRATION_START, CALIBRATION_END]`,
/// because every call site goes through this function and this function
/// refuses anything outside those bounds."
///
/// Uses ALFID 0x24 (2-byte size + 4-byte address), which is what MEVD17
/// expects. Returns the raw data bytes (the leading 0x63 service-response
/// byte is already stripped by the HSFZ client).
#[cfg(feature = "live-ecu")]
fn read_memory_by_address(
    client: &mut HsfzClient,
    ecu: u8,
    address: u32,
    size: u16,
) -> Result<Vec<u8>, String> {
    // Load-bearing: enforce the region invariant on every read. See the
    // doc comment on `assert_unprotected_region` and SCOPE.md.
    assert_unprotected_region(address, size as u32)?;

    let mut req = Vec::with_capacity(8);
    req.push(SVC_READ_MEMORY_BY_ADDRESS);
    req.push(0x24);
    req.extend_from_slice(&address.to_be_bytes());
    req.extend_from_slice(&size.to_be_bytes());

    let resp = client.send_uds(ecu, &req)?;

    // Negative response: [0x23, NRC]
    if resp.len() == 2 && resp[0] == SVC_READ_MEMORY_BY_ADDRESS {
        return Err(format!(
            "ReadMemoryByAddress NRC 0x{:02X} ({}) at 0x{:08X}",
            resp[1],
            nrc_name(resp[1]),
            address
        ));
    }
    if resp.is_empty() {
        return Err(format!("Empty response at 0x{:08X}", address));
    }
    Ok(resp)
}

/// Read MEVD17 calibration via the fast path: send the two prep
/// routines, then loop ReadMemoryByAddress in 4092-byte blocks until
/// the region is covered. Sends progress updates over the supplied
/// `Channel` after every block. Checks `cancel_flag` on every
/// iteration and bails cleanly if the user requested cancellation.
/// Maximum number of same-connection retries per block before we
/// attempt a reconnect. Each retry waits `RETRY_BACKOFF_MS * attempt`
/// to give the gateway time to recover.
///
/// Android is more generous with both budgets because mobile Wi-Fi
/// is noisy compared to a direct ENET link: the radio can PSP-idle
/// between packets, carrier-grade NAT paths can drop idle flows,
/// and a phone moving around the bench can see transient link
/// quality changes that wouldn't affect a cabled desktop.
#[cfg(all(feature = "live-ecu", not(target_os = "android")))]
const BLOCK_RETRY_BUDGET: u32 = 3;
#[cfg(all(feature = "live-ecu", target_os = "android"))]
const BLOCK_RETRY_BUDGET: u32 = 5;

#[cfg(feature = "live-ecu")]
const RETRY_BACKOFF_MS: u64 = 250;

/// How many times we'll reconnect across the whole read. One
/// reconnect is usually enough to survive a cable blip on desktop;
/// mobile gets a larger budget for the reasons above.
#[cfg(all(feature = "live-ecu", not(target_os = "android")))]
const MAX_RECONNECTS: u32 = 2;
#[cfg(all(feature = "live-ecu", target_os = "android"))]
const MAX_RECONNECTS: u32 = 4;

#[cfg(feature = "live-ecu")]
fn send_progress(
    on_progress: &Channel<ProgressEvent>,
    bytes_read: usize,
    total: usize,
    started: std::time::Instant,
    note: Option<String>,
) {
    let percent = if total > 0 {
        ((bytes_read as f64 / total as f64) * 100.0) as u32
    } else {
        0
    };
    let _ = on_progress.send(ProgressEvent {
        bytes_read,
        total,
        percentage: percent,
        elapsed_ms: started.elapsed().as_millis() as u64,
        note,
    });
}

/// Format a low-level read error into an actionable user-facing
/// message with the most likely remediation. Called from the final
/// `Err(...)` path after retries + reconnects are exhausted.
#[cfg(feature = "live-ecu")]
fn format_final_error(addr: u32, bytes_read: usize, total: usize, err: &str) -> String {
    let progress_pct = if total > 0 {
        (bytes_read as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let where_ = format!(
        "at 0x{:08X} ({} / {} bytes, {:.1}%)",
        addr, bytes_read, total, progress_pct
    );
    match classify_read_error(err) {
        ErrorClass::ConnectionLost => format!(
            "Connection to the gateway was lost {where_}. \
             Check the ENET cable, make sure the ignition is in Position 1, \
             and verify nothing else is holding a diagnostic session on the car. \
             Underlying error: {err}"
        ),
        ErrorClass::Transient => format!(
            "The gateway stopped responding {where_}. \
             The link is up but the ECU is not answering within the timeout — \
             try again, and if it keeps happening, power-cycle the ignition. \
             Underlying error: {err}"
        ),
        ErrorClass::Fatal => format!(
            "Read refused by the ECU {where_}. {err}. \
             This is a protocol-level rejection; retrying will not help. \
             Make sure you are on the correct ECU address and that no other \
             tool is currently talking to the DME."
        ),
    }
}

#[cfg(feature = "live-ecu")]
fn read_calibration_fast(
    client: &mut HsfzClient,
    ecu: u8,
    ip: &str,
    on_progress: &Channel<ProgressEvent>,
    cancel_flag: &Arc<AtomicBool>,
    op: &mut OpLog,
) -> Result<Vec<u8>, String> {
    op.push(format!(
        "Starting read: 0x{:08X}..0x{:08X} ({} bytes)",
        CALIBRATION_START, CALIBRATION_END, CALIBRATION_SIZE
    ));

    prepare_fem_for_dme_read(client, op);
    std::thread::sleep(std::time::Duration::from_millis(5));
    prepare_dme_calibration_read(client, ecu, op);
    std::thread::sleep(std::time::Duration::from_millis(1));

    let total = CALIBRATION_SIZE as usize;
    let mut data = Vec::with_capacity(total);
    let mut addr = CALIBRATION_START;
    let started = std::time::Instant::now();
    let mut reconnects_used: u32 = 0;

    // Initial 0% tick so the UI switches from "starting…" to the live
    // progress card with the correct totals before the first block.
    send_progress(on_progress, 0, total, started, None);

    while addr < CALIBRATION_END {
        if cancel_flag.load(Ordering::Acquire) {
            return Err("Cancelled by user".to_string());
        }

        let remaining = CALIBRATION_END - addr;
        let chunk = std::cmp::min(READ_BLOCK_SIZE as u32, remaining) as u16;

        // Attempt the block with retries. On ConnectionLost we drop
        // the stream and reconnect (up to MAX_RECONNECTS times
        // across the whole read). On Transient we back off and
        // retry the same connection. On Fatal we bail immediately.
        let mut attempt: u32 = 0;
        let block = loop {
            if cancel_flag.load(Ordering::Acquire) {
                return Err("Cancelled by user".to_string());
            }

            match read_memory_by_address(client, ecu, addr, chunk) {
                Ok(b) => break b,
                Err(e) => {
                    let class = classify_read_error(&e);
                    op.push(format!(
                        "Block read failed at 0x{:08X} (attempt {}/{}): [{:?}] {}",
                        addr,
                        attempt + 1,
                        BLOCK_RETRY_BUDGET,
                        class,
                        e
                    ));

                    if class == ErrorClass::Fatal {
                        return Err(format_final_error(addr, data.len(), total, &e));
                    }

                    if class == ErrorClass::ConnectionLost {
                        if reconnects_used >= MAX_RECONNECTS {
                            return Err(format_final_error(addr, data.len(), total, &e));
                        }
                        reconnects_used += 1;
                        op.push(format!(
                            "Connection lost — reconnect {}/{} at 0x{:08X}",
                            reconnects_used, MAX_RECONNECTS, addr
                        ));
                        send_progress(
                            on_progress,
                            data.len(),
                            total,
                            started,
                            Some(format!(
                                "Connection lost — reconnecting ({}/{})…",
                                reconnects_used, MAX_RECONNECTS
                            )),
                        );
                        std::thread::sleep(std::time::Duration::from_millis(500));
                        match HsfzClient::connect(ip, HSFZ_PORT) {
                            Ok(new_client) => {
                                *client = new_client;
                                op.push("Reconnect ok, re-running prep routines");
                                prepare_fem_for_dme_read(client, op);
                                std::thread::sleep(std::time::Duration::from_millis(5));
                                prepare_dme_calibration_read(client, ecu, op);
                                std::thread::sleep(std::time::Duration::from_millis(1));
                                send_progress(
                                    on_progress,
                                    data.len(),
                                    total,
                                    started,
                                    Some(format!("Reconnected — resuming at 0x{:08X}", addr)),
                                );
                                attempt = 0;
                                continue;
                            }
                            Err(reconnect_err) => {
                                return Err(format_final_error(
                                    addr,
                                    data.len(),
                                    total,
                                    &format!("reconnect failed: {}", reconnect_err),
                                ));
                            }
                        }
                    }

                    // Transient — back off and try again on the same
                    // connection, unless we've used our budget.
                    attempt += 1;
                    if attempt >= BLOCK_RETRY_BUDGET {
                        return Err(format_final_error(addr, data.len(), total, &e));
                    }
                    send_progress(
                        on_progress,
                        data.len(),
                        total,
                        started,
                        Some(format!(
                            "Retrying block 0x{:08X} ({}/{})…",
                            addr, attempt, BLOCK_RETRY_BUDGET
                        )),
                    );
                    std::thread::sleep(std::time::Duration::from_millis(
                        RETRY_BACKOFF_MS * attempt as u64,
                    ));
                }
            }
        };

        if block.len() != chunk as usize {
            log::warn!(
                "Short read at 0x{:08X}: expected {}, got {}",
                addr,
                chunk,
                block.len()
            );
        }

        addr += block.len() as u32;
        data.extend_from_slice(&block);

        send_progress(on_progress, data.len(), total, started, None);
    }

    op.push(format!(
        "Read loop complete: {} bytes in {} ms ({} reconnect(s) used)",
        data.len(),
        started.elapsed().as_millis(),
        reconnects_used
    ));
    Ok(data)
}

/// Build the on-disk file from the raw calibration bytes according to the
/// requested format. `padded_4mb` produces a 4 MB buffer of 0x00 with
/// the calibration copied to offset 0x180000 (the on-flash layout).
#[cfg(feature = "live-ecu")]
fn build_output(data: &[u8], format: &str) -> (Vec<u8>, String) {
    match format {
        "padded_4mb" => {
            let mut full = vec![0x00u8; PFLASH_SIZE];
            let copy_len = data.len().min(PFLASH_SIZE - CALIBRATION_OFFSET);
            full[CALIBRATION_OFFSET..CALIBRATION_OFFSET + copy_len]
                .copy_from_slice(&data[..copy_len]);
            (
                full,
                format!("4MB padded (cal at offset 0x{:06X})", CALIBRATION_OFFSET),
            )
        }
        _ => (data.to_vec(), format!("raw {} bytes", data.len())),
    }
}

/// Tauri command: connect to the gateway, read the MEVD17 calibration
/// region, return the file bytes (in either `raw` or `padded_4mb`
/// format) for the frontend to write to disk via `plugin-fs writeFile`.
///
/// # File I/O architecture
///
/// This command does **not** touch the filesystem. It returns the
/// constructed file body as `Vec<u8>` in the `bytes` field of
/// `CalibrationReadResult`, and the frontend writes that buffer to
/// the user-picked output path using `@tauri-apps/plugin-fs`'s
/// `writeFile`.
///
/// The reason: on Android, the system file picker returns Storage
/// Access Framework URIs like `content://com.android.externalstorage
/// .documents/document/primary%3ADownload%2Fdump.bin`. `std::fs::write`
/// has no idea what to do with a URI — it expects a POSIX path. Tauri's
/// `plugin-fs`, on the other hand, talks to Android's `ContentResolver`
/// natively and handles both POSIX paths and content URIs transparently.
/// Routing the write through the frontend lets the same code path work
/// on every platform, which is what we want for a sideload-friendly
/// Android variant. The same architecture is used by every other
/// user-facing file write in this app: `save_binary`, `save_capture_pcap`,
/// `proxy_export_pcap`, `simulator_export_flash_bin`.
///
/// Sync command — Tauri runs it on a worker thread, so the ~30 s read
/// does not block the UI. Progress is reported via the
/// `calibration-read-progress` event emitted from inside the read loop.
///
/// When the `live-ecu` Cargo feature is disabled, this command returns
/// a clear error without touching the network. See SCOPE.md.
#[cfg(not(feature = "live-ecu"))]
#[tauri::command]
pub fn read_calibration_region(
    _app: AppHandle,
    _state: tauri::State<'_, crate::commands::AppState>,
    _on_progress: tauri::ipc::Channel<ProgressEvent>,
    ip: String,
    _ecu_address: u8,
    save_format: String,
) -> Result<CalibrationReadResult, String> {
    validate_host(&ip)?;
    if !matches!(save_format.as_str(), "raw" | "padded_4mb") {
        return Err("save_format must be 'raw' or 'padded_4mb'".to_string());
    }
    Err("This build does not include live-ECU access. Rebuild with \
         `--features live-ecu` to enable the calibration reader. See \
         SCOPE.md for the rationale."
        .to_string())
}

#[cfg(feature = "live-ecu")]
#[tauri::command(async)]
pub fn read_calibration_region(
    _app: AppHandle,
    state: tauri::State<'_, crate::commands::AppState>,
    on_progress: Channel<ProgressEvent>,
    ip: String,
    ecu_address: u8,
    save_format: String,
) -> Result<CalibrationReadResult, String> {
    log::info!(
        "═══ Calibration read: ip={} ecu=0x{:02X} format={} ═══",
        ip,
        ecu_address,
        save_format
    );

    validate_host(&ip)?;
    if !matches!(save_format.as_str(), "raw" | "padded_4mb") {
        return Err("save_format must be 'raw' or 'padded_4mb'".to_string());
    }

    // Build the per-operation log buffer. Every significant event
    // from this point on is appended to `op`, and the final formatted
    // text is stashed in `AppState.last_op_log` so the frontend can
    // write it as a sibling `.log` next to the artifact.
    let header = cal_read_header(&ip, ecu_address, &save_format);
    let mut op = OpLog::new();

    // Reset the cooperative-cancel flag at the start of every operation.
    let cancel_flag = Arc::clone(&state.cancel_flag);
    cancel_flag.store(false, Ordering::Release);

    op.push(format!("Connecting to HSFZ gateway {}:{}", ip, HSFZ_PORT));
    let mut client = match HsfzClient::connect(&ip, HSFZ_PORT) {
        Ok(c) => {
            op.push("Gateway connected and registered");
            c
        }
        Err(e) => {
            let err_str = format!("Gateway {}: {}", ip, e);
            op.push(format!("Gateway connect FAILED: {}", err_str));
            let footer = format!("RESULT: FAILED\nError: {}\n", err_str);
            crate::op_log::stash(&state, op.format(&header, &footer));
            return Err(err_str);
        }
    };

    let data = match read_calibration_fast(
        &mut client,
        ecu_address,
        &ip,
        &on_progress,
        &cancel_flag,
        &mut op,
    ) {
        Ok(d) => d,
        Err(e) => {
            op.push(format!("Read FAILED: {}", e));
            let footer = format!("RESULT: FAILED\nError: {}\n", e);
            crate::op_log::stash(&state, op.format(&header, &footer));
            return Err(e);
        }
    };

    let (file_bytes, fmt_desc) = build_output(&data, &save_format);

    let msg = format!(
        "Calibration read complete: {} bytes read, file: {}",
        data.len(),
        fmt_desc
    );
    op.push(msg.clone());

    let footer = format!(
        "RESULT: SUCCESS\nBytes read:   {}\nFile size:    {}\nFormat:       {}\nDescription:  {}\n",
        data.len(),
        file_bytes.len(),
        save_format,
        fmt_desc
    );
    crate::op_log::stash(&state, op.format(&header, &footer));

    let result = CalibrationReadResult {
        success: true,
        bytes_read: data.len(),
        file_size: file_bytes.len(),
        format: save_format,
        message: msg,
    };
    let mut stash = state
        .last_bytes
        .lock()
        .map_err(|_| "internal state lock error".to_string())?;
    *stash = Some(file_bytes);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_unprotected_region_accepts_in_bounds() {
        assert!(assert_unprotected_region(CALIBRATION_START, 4092).is_ok());
        assert!(assert_unprotected_region(CALIBRATION_END - 4, 4).is_ok());
    }

    #[test]
    fn assert_unprotected_region_rejects_below() {
        assert!(assert_unprotected_region(CALIBRATION_START - 1, 1).is_err());
        assert!(assert_unprotected_region(0x80000000, 4).is_err()); // BTLD
        assert!(assert_unprotected_region(0x80020000, 4).is_err()); // CAFD
    }

    #[test]
    fn assert_unprotected_region_rejects_above() {
        assert!(assert_unprotected_region(CALIBRATION_END, 1).is_err());
        assert!(assert_unprotected_region(0x80220000, 4).is_err()); // SWFL_2
    }

    #[test]
    fn assert_unprotected_region_rejects_overflow() {
        assert!(assert_unprotected_region(u32::MAX - 10, 100).is_err());
    }

    #[test]
    fn assert_unprotected_region_rejects_straddle() {
        // Starts in-bounds, extends past the end.
        assert!(assert_unprotected_region(CALIBRATION_END - 4, 16).is_err());
    }

    #[test]
    fn validate_host_accepts_private_ranges() {
        assert!(validate_host("192.168.0.10").is_ok());
        assert!(validate_host("10.0.0.1").is_ok());
        assert!(validate_host("172.16.5.5").is_ok());
        assert!(validate_host("169.254.199.72").is_ok()); // link-local
        assert!(validate_host("127.0.0.1").is_ok());
        assert!(validate_host("bmw.local").is_ok()); // hostname
    }

    #[test]
    fn validate_host_rejects_public_ipv4() {
        assert!(validate_host("8.8.8.8").is_err());
        assert!(validate_host("1.1.1.1").is_err());
        assert!(validate_host("203.0.113.7").is_err());
    }

    #[test]
    fn validate_host_rejects_empty_and_overlong() {
        assert!(validate_host("").is_err());
        assert!(validate_host(&"a".repeat(254)).is_err());
    }
}
