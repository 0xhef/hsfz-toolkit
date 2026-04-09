//! UDS service handlers — the brain of the simulator.
//!
//! Each handler takes the parsed request body (everything *after* the
//! service id byte) plus mutable session state, and returns either
//! `Ok(response_body)` (a positive response, body must already include the
//! `service_id + 0x40` echo byte) or `Err(nrc)` for a negative response.
//!
//! The dispatcher (`handle_request`) is the only public entry point.
//!
//! Notable behaviours:
//!
//! * **`27` SecurityAccess** — we *are* the ECU, so we own the verification
//!   step. Return any 8-byte seed on RequestSeed, accept any signature on
//!   SendKey. The signature is logged but never validated. See the
//!   `SecAccess` notes in `simulator/state.rs`.
//! * **`34` RequestDownload** — parses the ALFID-prefixed
//!   `[ALFID][addr][size]` body, registers a fresh download segment, and
//!   responds with the canonical `74 20 0FFE` (max block = 4094 bytes,
//!   matches what real MEVD17 DMEs return — verified against captured wire data).
//! * **`36` TransferData** — appends every block verbatim. We do **not**
//!   enforce the block-sequence counter strictly because some HSFZ tools
//!   restart it mid-flash.
//! * **`37` RequestTransferExit** — finalizes the segment; the server
//!   layer then writes it to disk via the capture session.
//! * **`31` RoutineControl** — every routine is positive. For the erase
//!   routine `0xFF00` we additionally parse the embedded address/size to
//!   pre-emptively wipe that region from any in-memory shadow store (no-op
//!   in v1 since reads always return profile-or-FF).
//! * **Unknown services** — return NRC `0x11` (serviceNotSupported).

use rand::RngCore;

use super::state::SessionState;

// ── UDS NRCs we may emit ────────────────────────────────────────────────
pub const NRC_SERVICE_NOT_SUPPORTED: u8 = 0x11;
pub const NRC_SUBFUNCTION_NOT_SUPPORTED: u8 = 0x12;
pub const NRC_INCORRECT_LENGTH: u8 = 0x13;
pub const NRC_CONDITIONS_NOT_CORRECT: u8 = 0x22;
pub const NRC_REQUEST_OUT_OF_RANGE: u8 = 0x31;

/// Result of a single request → response handling cycle.
pub enum HandlerOutcome {
    /// Send this body as a positive UDS response.
    Positive(Vec<u8>),
    /// Send a negative response with this NRC.
    Negative(u8),
    /// Segment just finished — server should persist it via capture and
    /// then send the included positive response.
    SegmentFinished {
        address: u32,
        data: Vec<u8>,
        response: Vec<u8>,
    },
}

/// Top-level service dispatcher. `service` is the request service id byte;
/// `body` is everything after it.
pub fn handle_request(state: &mut SessionState, service: u8, body: &[u8]) -> HandlerOutcome {
    match service {
        0x10 => session_control(state, body),
        0x11 => ecu_reset(body),
        0x14 => clear_dtc(),
        0x19 => read_dtc(body),
        0x22 => read_data_by_id(state, body),
        0x23 => read_memory_by_address(state, body),
        0x27 => security_access(state, body),
        0x28 => communication_control(body),
        0x2E => write_data_by_id(state, body),
        0x31 => routine_control(state, body),
        0x34 => request_download(state, body),
        0x36 => transfer_data(state, body),
        0x37 => request_transfer_exit(state, body),
        0x3D => write_memory_by_address(body),
        0x3E => tester_present(body),
        0x85 => control_dtc_setting(body),
        _ => HandlerOutcome::Negative(NRC_SERVICE_NOT_SUPPORTED),
    }
}

// ── 0x10 DiagnosticSessionControl ───────────────────────────────────────

fn session_control(state: &mut SessionState, body: &[u8]) -> HandlerOutcome {
    if body.is_empty() {
        return HandlerOutcome::Negative(NRC_INCORRECT_LENGTH);
    }
    let sub = body[0];
    state.session = sub;
    // Standard P2/P2* timing: P2 = 50 ms, P2* = 5000 ms. The 4 bytes after
    // the subfunction echo are how the HSFZ layer reports timing back to the tester.
    let resp = vec![0x50, sub, 0x00, 0x32, 0x01, 0xF4];
    HandlerOutcome::Positive(resp)
}

// ── 0x11 ECUReset ───────────────────────────────────────────────────────

fn ecu_reset(body: &[u8]) -> HandlerOutcome {
    if body.is_empty() {
        return HandlerOutcome::Negative(NRC_INCORRECT_LENGTH);
    }
    HandlerOutcome::Positive(vec![0x51, body[0]])
}

// ── 0x14 / 0x19 DTC stubs ───────────────────────────────────────────────

fn clear_dtc() -> HandlerOutcome {
    HandlerOutcome::Positive(vec![0x54])
}

fn read_dtc(body: &[u8]) -> HandlerOutcome {
    // Echo subfunction with an empty DTC list and "no faults" status mask.
    let sub = body.first().copied().unwrap_or(0x02);
    HandlerOutcome::Positive(vec![0x59, sub, 0xFF, 0x00, 0x00])
}

// ── 0x22 ReadDataByIdentifier ───────────────────────────────────────────
//
// HSFZ testers often pack multiple DIDs into one request. We respond to all
// of them in one positive frame, in order, returning whatever the profile
// has — and 0xFF padding for unknown DIDs (so we never NRC during the
// fingerprint sweep, which would tell the tester something is wrong).

fn read_data_by_id(state: &SessionState, body: &[u8]) -> HandlerOutcome {
    if body.len() < 2 || !body.len().is_multiple_of(2) {
        return HandlerOutcome::Negative(NRC_INCORRECT_LENGTH);
    }
    let single = body.len() == 2;
    let mut resp = vec![0x62];
    let mut i = 0;
    while i + 2 <= body.len() {
        let did = ((body[i] as u16) << 8) | body[i + 1] as u16;

        // Four-tier resolution:
        //   1. Session-state DIDs (F186 ActiveDiagnosticSession, …) —
        //      these depend on live state, not the profile.
        //   2. `synthesize_did` builds wire bytes from `profile.metadata`
        //      (the source of truth for VIN, DME type, SVK, flash
        //      counters, etc.). This means encoder fixes apply to
        //      existing profiles automatically — no re-save required.
        //   3. Raw `dids` map fallback for arbitrary overrides (cloned
        //      coding DIDs, vendor blocks we don't model).
        //   4. Unknown — for a single-DID request we NRC
        //      `requestOutOfRange` (matching real DMEs); for a multi-DID
        //      sweep we pad with 0xFF so one missing DID doesn't kill
        //      the whole probe.
        let value = synth_session_did(state, did)
            .or_else(|| super::synthesize::synthesize_did(&state.profile, did))
            .or_else(|| state.profile.lookup_did(did));
        match value {
            Some(v) => {
                resp.push(body[i]);
                resp.push(body[i + 1]);
                resp.extend_from_slice(&v);
            }
            None if single => {
                log::debug!("simulator: RDBI unknown DID 0x{:04X}, NRC 31", did);
                return HandlerOutcome::Negative(NRC_REQUEST_OUT_OF_RANGE);
            }
            None => {
                log::debug!("simulator: RDBI unknown DID 0x{:04X}, padding", did);
                resp.push(body[i]);
                resp.push(body[i + 1]);
                resp.extend_from_slice(&[0xFFu8; 16]);
            }
        }
        i += 2;
    }
    HandlerOutcome::Positive(resp)
}

/// DIDs whose value depends on live session state rather than the
/// stored profile. Kept here (not in `synthesize.rs`) because
/// `synthesize_did` only takes the profile, and we don't want to
/// thread `SessionState` through the encoder layer just for one DID.
fn synth_session_did(state: &SessionState, did: u16) -> Option<Vec<u8>> {
    match did {
        // ActiveDiagnosticSession — two bytes on real MEVD17:
        //   byte 0 = current session id (0x01 default, 0x02 prog, 0x03 ext)
        //   byte 1 = session control flags. Captured value on a real
        //            MEVD17 DME was `01 81` (verified against a live
        //            wire trace). The high bit of byte 1 mirrors the
        //            SuppressPosResp bit; the rest is reserved.
        //            Returning a single byte makes some flashers
        //            reject the response.
        0xF186 => Some(vec![state.session, 0x81]),
        _ => None,
    }
}

// ── 0x23 ReadMemoryByAddress ────────────────────────────────────────────
//
// We don't model a memory map. Return whatever was just written if the
// region matches a completed segment; otherwise 0xFF padding. This is
// enough for the typical "read-back-to-verify" pattern most flashers use
// after a write.

fn read_memory_by_address(state: &SessionState, body: &[u8]) -> HandlerOutcome {
    let (addr, size) = match parse_alfid(body) {
        Some(t) => t,
        None => return HandlerOutcome::Negative(NRC_INCORRECT_LENGTH),
    };
    if size == 0 {
        return HandlerOutcome::Negative(NRC_REQUEST_OUT_OF_RANGE);
    }
    // Cap reads at one HSFZ frame's worth of payload — testers shouldn't
    // ever need more in a single ReadMemoryByAddress, and the cap stops
    // a malicious flasher from coercing us into a huge allocation.
    let size = size.min(0x1000) as usize;
    let mut out = vec![0x63];
    out.extend(serve_memory(state, addr, size));
    HandlerOutcome::Positive(out)
}

fn serve_memory(state: &SessionState, addr: u32, size: usize) -> Vec<u8> {
    // Look in completed segments first. If part of the requested range is
    // covered, fill from there; the rest stays 0xFF.
    let mut out = vec![0xFFu8; size];
    for seg in &state.completed {
        let seg_end = seg.address.saturating_add(seg.data.len() as u32);
        let req_end = addr.saturating_add(size as u32);
        let overlap_start = addr.max(seg.address);
        let overlap_end = req_end.min(seg_end);
        if overlap_start < overlap_end {
            let dst_off = (overlap_start - addr) as usize;
            let src_off = (overlap_start - seg.address) as usize;
            let len = (overlap_end - overlap_start) as usize;
            out[dst_off..dst_off + len].copy_from_slice(&seg.data[src_off..src_off + len]);
        }
    }
    out
}

// ── 0x27 SecurityAccess ─────────────────────────────────────────────────
//
// We're the ECU. We own the verification, so we accept any signature.
// Both the legacy 0x01/0x02 (coding) and the programming-level 0x11/0x12
// dance work the same way.

fn security_access(state: &mut SessionState, body: &[u8]) -> HandlerOutcome {
    if body.is_empty() {
        return HandlerOutcome::Negative(NRC_INCORRECT_LENGTH);
    }
    let sub = body[0];
    let is_request_seed = sub % 2 == 1; // odd = request seed, even = send key
    if is_request_seed {
        // Generate an 8-byte non-zero pseudo-random seed. Some flashers
        // detect all-zero seeds as "already unlocked" and skip SendKey,
        // which would leave us in an inconsistent state.
        let mut seed = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut seed);
        if seed.iter().all(|&b| b == 0) {
            seed[0] = 0x01;
        }
        state.last_seed = Some(seed);
        let mut resp = vec![0x67, sub];
        resp.extend_from_slice(&seed);
        HandlerOutcome::Positive(resp)
    } else {
        // SendKey: accept anything, mark unlocked, log the signature length.
        let sig_len = body.len().saturating_sub(1);
        log::info!(
            "simulator: SecurityAccess SendKey sub=0x{:02X} sig_len={} (accepting blindly)",
            sub,
            sig_len
        );
        state.security_unlocked = true;
        HandlerOutcome::Positive(vec![0x67, sub])
    }
}

// ── 0x28 CommunicationControl ───────────────────────────────────────────

fn communication_control(body: &[u8]) -> HandlerOutcome {
    let sub = body.first().copied().unwrap_or(0x00);
    HandlerOutcome::Positive(vec![0x68, sub])
}

// ── 0x2E WriteDataByIdentifier ──────────────────────────────────────────

fn write_data_by_id(state: &mut SessionState, body: &[u8]) -> HandlerOutcome {
    if body.len() < 2 {
        return HandlerOutcome::Negative(NRC_INCORRECT_LENGTH);
    }
    let did = ((body[0] as u16) << 8) | body[1] as u16;
    let value = &body[2..];
    state.profile.set_did(did, value);
    log::info!(
        "simulator: WDBI 0x{:04X} ({} bytes) stored",
        did,
        value.len()
    );
    HandlerOutcome::Positive(vec![0x6E, body[0], body[1]])
}

// ── 0x31 RoutineControl ─────────────────────────────────────────────────
//
// Always positive. For the well-known erase routine 0xFF00 we parse the
// embedded address/size so the transcript log records what region was
// erased. We don't actually wipe anything since reads default to 0xFF.

fn routine_control(state: &mut SessionState, body: &[u8]) -> HandlerOutcome {
    if body.len() < 3 {
        return HandlerOutcome::Negative(NRC_INCORRECT_LENGTH);
    }
    let sub = body[0];
    let rid = ((body[1] as u16) << 8) | body[2] as u16;

    if rid == 0xFF00 && body.len() >= 4 {
        // Format observed in captured wire data:
        //   [01][FF00][ALFID=02][addr 4 bytes][size 4 bytes]
        if let Some((addr, size)) = parse_alfid(&body[3..]) {
            log::info!(
                "simulator: erase routine 0xFF00 addr=0x{:08X} size=0x{:08X}",
                addr,
                size
            );
        }
    }

    // ── Routine 0x0205 — DME identification / development info ──
    //
    // Real DMEs (verified against captured wire traffic) return a body
    // that contains the BTLD SVK entry bytes followed by the DME type
    // as ASCII at the tail. HSFZ tuning tools parse this response
    // (not F150) to derive the displayed DME Type and Engine.
    //
    // Real response observed:
    //   71 01 02 05 25 01 06 00 00 19 01 01 31 02 23 4D 45 56 44 31 37 …
    //                ^^                           ^^ ^^ ^^ ^^ ^^ ^^
    //                status                       'M  E  V  D  1  7'
    //
    // We mirror that shape: [status:1][BTLD entry:8][len:1][DME ASCII…].
    // The exact framing bytes don't matter much — the parser just
    // substring-scans for `MEVD` / `DME` / `N20` / etc. in the bytes.
    if rid == 0x0205 {
        if let Some(resp) = build_routine_0205_response(state, sub) {
            return HandlerOutcome::Positive(resp);
        }
    }

    // Default: 71 [sub] [rid_hi] [rid_lo] 00 (status = success)
    HandlerOutcome::Positive(vec![0x71, sub, body[1], body[2], 0x00])
}

/// Build a routine-0x0205 response in the exact format real MEVD17 DMEs
/// emit. Verified against live wire captures (see `simulator/clone.rs`
/// for the inverse parser).
///
/// Wire format:
/// ```text
/// 71 01 02 05 [status:1] [class:1] [SGBM:4] [ver:3]
/// '#' DME_TYPE
/// '#' C1
/// '#' marker
/// '#' full_designation_with_engine
/// '#' cal_id
/// '#' project_code
/// (padding bytes)
/// ```
///
/// Where `#` is `0x23`. The DME type, calibration ID, project code,
/// and the long designation that contains the engine code (`MEVD17.2.P-N20-...`)
/// are all carried as ASCII separated by `#` bytes. HSFZ tuning tools
/// substring-match against this blob to extract the displayed DME Type,
/// Engine, and Calibration ID — none of which come from a DID. The
/// status byte and the embedded SVK entry vary depending on which SVK
/// the tester sent as the routine parameter; the ASCII payload is the
/// same regardless.
fn build_routine_0205_response(state: &SessionState, sub: u8) -> Option<Vec<u8>> {
    let m = &state.profile.metadata;
    let dme = m
        .dme_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    let engine = m.engine_code.as_deref().map(str::trim).unwrap_or("");
    let cal_id = m.calibration_id.as_deref().map(str::trim).unwrap_or("");

    let mut resp = vec![0x71, sub, 0x02, 0x05, 0x25];

    // SVK entry slot. Mirrors the real DME shape: a leading "class
    // slot" byte followed by an 8-byte SVK entry. We use the BTLD
    // entry from the profile when available, otherwise the SWFL
    // program entry. If the profile has neither we fall back to a
    // zero-filled 9-byte stub so the response stays parseable.
    let svk_entry = m
        .btld
        .as_ref()
        .or(m.swfl_program.as_ref())
        .and_then(|m| Some((parse_sgbm(&m.sgbm)?, parse_version(&m.version)?)));
    if let Some((sgbm, ver)) = svk_entry {
        let class_byte = if m.btld.is_some() { 0x06 } else { 0x08 };
        resp.push(0x01); // class-slot prefix observed in real responses
        resp.push(class_byte);
        resp.extend_from_slice(&sgbm);
        resp.extend_from_slice(&ver);
    } else {
        resp.extend_from_slice(&[0u8; 9]);
    }

    // ── ASCII payload, '#'-separated ──────────────────────────────
    // Field order matches the real-DME captures the user shared:
    //   #<dme_type>#C1#PST#<long_designation>#<cal_id>#<project>
    //
    // The long designation embeds the engine code so a tuning tool's
    // substring scan finds `N20` / `N55` / etc.
    // We synthesize a plausible long designation when the user has
    // provided both the DME type and the engine code; otherwise we
    // skip that field (the basic DME type field above is enough for
    // most parsers).
    resp.push(b'#');
    resp.extend_from_slice(dme.as_bytes());
    // Marker is `DST` on real MEVD17 wire (verified against a
    // real-DME capture). Older notes had this as `PST`; that was
    // a misread of the binary header preceding the marker.
    resp.extend_from_slice(b"#C1#DST#");
    // Long designation: prefer the cloned value verbatim. Falls back
    // to a synthesised "<DME>-<ENGINE>-Mo-B20-U0-F030-EU6-HGAG_-LL-RL"
    // shape so manual profiles still produce a parseable string.
    if let Some(long) = m
        .long_designation
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        resp.extend_from_slice(long.as_bytes());
    } else if !engine.is_empty() {
        let long = format!("{}-{}-Mo-B20-U0-F030-EU6-HGAG_-LL-RL", dme, engine);
        resp.extend_from_slice(long.as_bytes());
    }
    resp.push(b'#');
    if !cal_id.is_empty() {
        resp.extend_from_slice(cal_id.as_bytes());
    }
    resp.push(b'#');
    if let Some(proj) = m
        .project_code
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        resp.extend_from_slice(proj.as_bytes());
    }

    Some(resp)
}

fn parse_sgbm(s: &str) -> Option<[u8; 4]> {
    let s = s.trim();
    if s.len() != 8 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 4];
    for i in 0..4 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn parse_version(v: &str) -> Option<[u8; 3]> {
    let parts: Vec<&str> = v.trim().split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    Some([
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ])
}

// ── 0x34 RequestDownload ────────────────────────────────────────────────

fn request_download(state: &mut SessionState, body: &[u8]) -> HandlerOutcome {
    // Body: [dataFormatIdentifier][ALFID][address...][size...]
    if body.len() < 2 {
        return HandlerOutcome::Negative(NRC_INCORRECT_LENGTH);
    }
    let _data_fmt = body[0];
    let (addr, size) = match parse_alfid(&body[1..]) {
        Some(t) => t,
        None => return HandlerOutcome::Negative(NRC_INCORRECT_LENGTH),
    };
    log::info!(
        "simulator: RequestDownload addr=0x{:08X} size=0x{:08X} ({} bytes)",
        addr,
        size,
        size
    );
    if let Err(e) = state.begin_download(addr, size) {
        log::warn!("simulator: rejecting oversized RequestDownload: {}", e);
        return HandlerOutcome::Negative(NRC_REQUEST_OUT_OF_RANGE);
    }

    // Positive response: 74 [LFID=0x20] [maxBlockLength 2 bytes BE]
    // 0x20 = 2-byte length follows. 0x0FFE = 4094 bytes per TransferData
    // block, matching what real MEVD17 DMEs return (verified against wire captures).
    HandlerOutcome::Positive(vec![0x74, 0x20, 0x0F, 0xFE])
}

// ── 0x36 TransferData ───────────────────────────────────────────────────

fn transfer_data(state: &mut SessionState, body: &[u8]) -> HandlerOutcome {
    if body.is_empty() {
        return HandlerOutcome::Negative(NRC_INCORRECT_LENGTH);
    }
    if state.current_download.is_none() {
        return HandlerOutcome::Negative(NRC_CONDITIONS_NOT_CORRECT);
    }
    let seq = body[0];
    let data = &body[1..];
    state.push_block(seq, data);

    // Optional artificial throttle. Some flashing apps measure the
    // wall-clock duration of the TransferData burst and refuse to
    // upload telemetry if a 4 MiB DME image lands in <10s, since no
    // real car flashes that fast. When the profile sets a kB/s cap
    // we sleep `block_size / rate` seconds before answering, which
    // paces the whole transfer to that rate without needing any
    // bookkeeping across blocks.
    if let Some(kbps) = state.profile.transfer_rate_kbps {
        if kbps > 0 && !data.is_empty() {
            let bytes_per_sec = (kbps as u64).saturating_mul(1024);
            // Nanoseconds = bytes * 1e9 / bytes_per_sec
            let nanos = (data.len() as u64).saturating_mul(1_000_000_000) / bytes_per_sec;
            // Cap any single sleep at 5s defensively — a misconfigured
            // 1 kB/s rate against a 64 KiB block would otherwise sleep
            // for over a minute and trigger the tester's read timeout.
            let nanos = nanos.min(5_000_000_000);
            std::thread::sleep(std::time::Duration::from_nanos(nanos));
        }
    }

    HandlerOutcome::Positive(vec![0x76, seq])
}

// ── 0x37 RequestTransferExit ────────────────────────────────────────────

fn request_transfer_exit(state: &mut SessionState, _body: &[u8]) -> HandlerOutcome {
    let Some(completed) = state.finish_download() else {
        return HandlerOutcome::Negative(NRC_CONDITIONS_NOT_CORRECT);
    };
    log::info!(
        "simulator: RequestTransferExit — segment 0x{:08X} done ({} bytes)",
        completed.address,
        completed.data.len()
    );
    HandlerOutcome::SegmentFinished {
        address: completed.address,
        data: completed.data,
        response: vec![0x77],
    }
}

// ── 0x3D WriteMemoryByAddress ───────────────────────────────────────────

fn write_memory_by_address(body: &[u8]) -> HandlerOutcome {
    let _ = body; // we don't model memory
    HandlerOutcome::Positive(vec![0x7D])
}

// ── 0x3E TesterPresent ──────────────────────────────────────────────────

fn tester_present(body: &[u8]) -> HandlerOutcome {
    let sub = body.first().copied().unwrap_or(0x00);
    HandlerOutcome::Positive(vec![0x7E, sub])
}

// ── 0x85 ControlDTCSetting ──────────────────────────────────────────────

fn control_dtc_setting(body: &[u8]) -> HandlerOutcome {
    let sub = body.first().copied().unwrap_or(0x01);
    HandlerOutcome::Positive(vec![0xC5, sub])
}

// ── ALFID parser ────────────────────────────────────────────────────────
//
// The address-and-length-format identifier byte: high nibble = size of
// memorySize field, low nibble = size of memoryAddress field. Both values
// are big-endian. Used by RequestDownload, RequestUpload, ReadMemByAddr.

fn parse_alfid(body: &[u8]) -> Option<(u32, u32)> {
    if body.is_empty() {
        return None;
    }
    let alfid = body[0];
    let addr_bytes = (alfid & 0x0F) as usize;
    let size_bytes = ((alfid >> 4) & 0x0F) as usize;
    if addr_bytes == 0 || size_bytes == 0 || addr_bytes > 4 || size_bytes > 4 {
        return None;
    }
    let need = 1 + addr_bytes + size_bytes;
    if body.len() < need {
        return None;
    }
    let mut addr: u32 = 0;
    for i in 0..addr_bytes {
        addr = (addr << 8) | body[1 + i] as u32;
    }
    let mut size: u32 = 0;
    for i in 0..size_bytes {
        size = (size << 8) | body[1 + addr_bytes + i] as u32;
    }
    Some((addr, size))
}

// Surface a couple of constants for the integration tests / docs.
#[allow(dead_code)]
pub const SIMULATED_MAX_BLOCK_LENGTH: u16 = 0x0FFE;

#[allow(dead_code)]
pub fn nrc_name(nrc: u8) -> &'static str {
    match nrc {
        NRC_SERVICE_NOT_SUPPORTED => "serviceNotSupported",
        NRC_SUBFUNCTION_NOT_SUPPORTED => "subFunctionNotSupported",
        NRC_INCORRECT_LENGTH => "incorrectMessageLengthOrInvalidFormat",
        NRC_CONDITIONS_NOT_CORRECT => "conditionsNotCorrect",
        NRC_REQUEST_OUT_OF_RANGE => "requestOutOfRange",
        _ => "unknown",
    }
}
