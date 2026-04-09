//! Clone an EcuProfile from a real MEVD17 DME on the network.
//!
//! Uses the same `HsfzClient` the calibration-read tab uses (gateway registration,
//! HSFZ alive-check echo, NRC 0x78 retry, …) to read every fingerprint
//! DID a tuning tool checks during its license/discovery sweep, plus a
//! handful of extra DIDs observed in captured tool traffic.
//!
//! The result is an `EcuProfile` byte-perfect to the source car — when
//! served by the simulator a VIN-licensed tuning flasher cannot
//! distinguish it from the real DME.

#![cfg_attr(not(feature = "live-ecu"), allow(dead_code, unused_imports))]

use serde::Serialize;
use tauri::{AppHandle, Emitter};

#[cfg(feature = "live-ecu")]
use crate::calibration_read::client::{HsfzClient, HSFZ_PORT};

use super::encoder::{DmeIdentifiers, ModuleIdent};
use super::profile::EcuProfile;

/// DIDs cloned during a sweep, in the order observed on the wire when
/// a real HSFZ tuning tool performs its discovery pass. The list
/// intentionally mirrors the real-car probe order so the clone is
/// byte-for-byte indistinguishable from a genuine discovery sweep.
const DISCOVERY_DIDS: &[u16] = &[
    0xF190, // VIN
    0xF101, // SVK (Software Version Key)
    0xF18B, // ECU manufacturing date (3-byte BCD)
    0x2502, // Current flash counter
    0x2503, // Max flash counter
    0x5815, // Battery voltage
    0xDAD6, // Vendor block (purpose unknown — kept for parity)
    0xF187, // DME supplier number
    0xF18A, // System supplier identifier
    0xF18C, // ECU serial number
    0xF191, // Vehicle manufacturer ECU hardware number
    0xF197, // System name / ECU name
    0x401F, // KIS / I-Step status
    0x59C8, // ZBNR
    0x403C, // Calibration ID + CVN (20 bytes)
    0x4038, // Variant coding
    0xF150, // SGBD index
    0x3F06, // Vendor blob (~204 bytes on real DME)
    0x100B, // I-Step triple (read on gateway, kept for transcript parity)
];

/// Coding DIDs read after the discovery sweep so the simulator can
/// serve a flasher's coding download / restore workflow with realistic
/// bytes. Same DID set HSFZ tuning tools back up via their NCD
/// coding-backup command. Stored as raw hex in the profile's `dids`
/// map (no metadata model — coding is vendor-specific binary).
const CODING_DIDS: &[u16] = &[
    0x3300, // Coding sub-block 1
    0x3320, // Coding sub-block 2
    0x3350, // CAFD reference
    0x3351, // CAFD reference (extended)
    0x37FE, // Coding signature / verification
];

#[derive(Serialize, Clone)]
pub struct CloneProgress {
    pub current: usize,
    pub total: usize,
    pub did: u16,
    pub status: &'static str, // "ok" | "missing" | "nrc"
}

/// Read every DID in `FINGERPRINT_DIDS` from a live car and return a
/// populated profile. Emits `simulator-clone-progress` events so the UI
/// can show a modal during the read.
///
/// `app` is optional so this can be called from non-Tauri contexts (tests).
#[cfg(feature = "live-ecu")]
pub fn clone_from_car(
    app: Option<&AppHandle>,
    ip: &str,
    ecu_address: u8,
    profile_name: &str,
) -> Result<EcuProfile, String> {
    log::info!(
        "simulator: cloning DME profile from {} (ECU 0x{:02X})",
        ip,
        ecu_address
    );

    // `ConnectError` Display produces a message that identifies whether
    // the TCP connect or the HSFZ handshake is the failing stage.
    let mut client =
        HsfzClient::connect(ip, HSFZ_PORT).map_err(|e| format!("Gateway {}: {}", ip, e))?;

    // Total = discovery DIDs + coding DIDs + 1 routine call. The
    // routine is reported as its own progress step at the end so the
    // modal counter matches.
    let total = DISCOVERY_DIDS.len() + CODING_DIDS.len() + 1;
    let mut profile = EcuProfile {
        name: profile_name.to_string(),
        description: format!("Cloned from {} on {}", ip, current_iso8601()),
        ecu_address,
        vin: None,
        mac: "00:00:00:00:00:12".to_string(),
        metadata: DmeIdentifiers::default(),
        dids: Default::default(),
        transfer_rate_kbps: None,
    };

    // ── DID sweep ──────────────────────────────────────────────────
    for (i, &did) in DISCOVERY_DIDS.iter().enumerate() {
        let request = [0x22u8, (did >> 8) as u8, did as u8];
        let status = match client.send_uds(ecu_address, &request) {
            Ok(resp) => {
                if resp.len() == 2 && resp[0] == 0x22 {
                    log::debug!("clone: DID 0x{:04X} NRC 0x{:02X}", did, resp[1]);
                    "nrc"
                } else if resp.len() >= 2 && resp[0] == (did >> 8) as u8 && resp[1] == did as u8 {
                    let value = &resp[2..];
                    // Always keep the raw bytes in dids for clones we
                    // don't have a typed slot for (e.g. 0x3F06, 0xDAD6).
                    profile
                        .dids
                        .insert(format!("{:04X}", did), encode_hex(value));
                    // Decode known DIDs into the typed metadata so the
                    // synthesizer (and the editor's pre-fill) sees them.
                    decode_did_into_metadata(&mut profile, did, value);
                    "ok"
                } else {
                    log::warn!(
                        "clone: DID 0x{:04X} unexpected response shape ({} bytes)",
                        did,
                        resp.len()
                    );
                    "missing"
                }
            }
            Err(e) => {
                log::warn!("clone: DID 0x{:04X} read failed: {}", did, e);
                "missing"
            }
        };

        if let Some(app) = app {
            let _ = app.emit(
                "simulator-clone-progress",
                CloneProgress {
                    current: i + 1,
                    total,
                    did,
                    status,
                },
            );
        }
    }

    // ── Coding DID sweep ───────────────────────────────────────────
    //
    // After the discovery DIDs we read the coding DIDs (3300, 3320,
    // 3350, 3351, 37FE) so the simulator can serve a flasher's coding
    // download / restore workflow with realistic bytes. Stored as raw
    // hex in the dids map — no metadata typing because coding is
    // vendor-specific opaque binary.
    let mut coding_offset = DISCOVERY_DIDS.len();
    for &did in CODING_DIDS {
        coding_offset += 1;
        let request = [0x22u8, (did >> 8) as u8, did as u8];
        let status = match client.send_uds(ecu_address, &request) {
            Ok(resp) => {
                if resp.len() == 2 && resp[0] == 0x22 {
                    log::debug!("clone: coding DID 0x{:04X} NRC 0x{:02X}", did, resp[1]);
                    "nrc"
                } else if resp.len() >= 2 && resp[0] == (did >> 8) as u8 && resp[1] == did as u8 {
                    let value = &resp[2..];
                    profile
                        .dids
                        .insert(format!("{:04X}", did), encode_hex(value));
                    "ok"
                } else {
                    "missing"
                }
            }
            Err(e) => {
                log::warn!("clone: coding DID 0x{:04X} read failed: {}", did, e);
                "missing"
            }
        };
        if let Some(app) = app {
            let _ = app.emit(
                "simulator-clone-progress",
                CloneProgress {
                    current: coding_offset,
                    total,
                    did,
                    status,
                },
            );
        }
    }

    // ── Routine 0x0205 in extended session ─────────────────────────
    //
    // Mirrors what HSFZ tuning tools do at the end of their discovery
    // sweep — switch to extended session, call the routine with the
    // cloned BTLD entry as parameters, parse the ASCII tail of the
    // response for the DME type and engine code.
    let _ = call_routine_0205(&mut client, ecu_address, &mut profile);

    if let Some(app) = app {
        let _ = app.emit(
            "simulator-clone-progress",
            CloneProgress {
                current: total,
                total,
                did: 0x0205,
                status: "ok",
            },
        );
    }

    log::info!(
        "simulator: clone done — vin={:?}, dme_type={:?}, engine={:?}, {} raw DIDs cached",
        profile.vin,
        profile.metadata.dme_type,
        profile.metadata.engine_code,
        profile.dids.len()
    );
    Ok(profile)
}

/// Decode a known DID's raw bytes into the typed `profile.metadata`
/// fields so the editor pre-fills with friendly values and the
/// synthesizer rebuilds wire bytes from the typed source.
fn decode_did_into_metadata(profile: &mut EcuProfile, did: u16, value: &[u8]) {
    match did {
        0xF190 => {
            if let Ok(vin) = std::str::from_utf8(value) {
                let trimmed = vin.trim_end_matches('\0').trim().to_string();
                if !trimmed.is_empty() {
                    profile.vin = Some(trimmed);
                }
            }
        }
        0xF18C => {
            if let Some(s) = printable_ascii(value) {
                profile.metadata.serial_number = Some(s);
            }
        }
        0xF187 => {
            if let Some(s) = printable_ascii(value) {
                profile.metadata.dme_supplier = Some(s);
            }
        }
        0xF18A => {
            if let Some(s) = printable_ascii(value) {
                profile.metadata.system_supplier = Some(s);
            }
        }
        0xF191 => {
            if let Some(s) = printable_ascii(value) {
                profile.metadata.hardware_number = Some(s);
            }
        }
        0x59C8 => {
            if let Some(s) = printable_ascii(value) {
                profile.metadata.zbnr = Some(s);
            }
        }
        0xF18B => {
            // 3 BCD bytes (year, month, day) → "YYMMDD"
            if value.len() >= 3 {
                let mut s = String::with_capacity(6);
                let mut ok = true;
                for &byte in &value[..3] {
                    let hi = (byte >> 4) & 0x0F;
                    let lo = byte & 0x0F;
                    if hi > 9 || lo > 9 {
                        ok = false;
                        break;
                    }
                    s.push(char::from(b'0' + hi));
                    s.push(char::from(b'0' + lo));
                }
                if ok {
                    profile.metadata.manufacture_date = Some(s);
                }
            }
        }
        0x2502 => {
            // 4-byte BE current flash counter
            if value.len() >= 4 {
                profile.metadata.flash_counter =
                    Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
        }
        0x2503 => {
            // Real DME returns 2 bytes BE — handle either width.
            if value.len() >= 4 {
                profile.metadata.max_flash_counter =
                    Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            } else if value.len() >= 2 {
                profile.metadata.max_flash_counter =
                    Some(u16::from_be_bytes([value[0], value[1]]) as u32);
            }
        }
        0x5815 => {
            // 1 byte * 0.0942 = volts. 0xFF means "unknown" — skip.
            if let Some(&raw) = value.first() {
                if raw != 0xFF {
                    profile.metadata.voltage_v = Some(raw as f32 * 0.0942);
                }
            }
        }
        0x403C => {
            // 20-byte block: bytes 16..20 are a 32-bit CVN. The ASCII
            // *calibration ID* (e.g. "9VT9G40B") does NOT live here —
            // it comes from the routine 0x0205 ASCII tail. Don't try to
            // pull a cal_id out of bytes 0..8; that's a separate
            // checksum/hash that just happens to be ASCII-printable on
            // some cars and would clobber the real cal_id.
            if value.len() >= 20 {
                let cvn = u32::from_be_bytes([value[16], value[17], value[18], value[19]]);
                if cvn != 0 && cvn != 0xFFFFFFFF {
                    profile.metadata.cvn = Some(cvn);
                }
            }
        }
        0xF101 => {
            decode_f101_into_metadata(&mut profile.metadata, value);
        }
        _ => {}
    }
}

/// Walk an F101 SVK response and populate the BTLD/SWFL/CAFD/HWEL
/// metadata slots. Header layout was reverse-engineered from captured
/// wire traffic — entries start at offset 17 when byte 7's high nibble
/// is 0x80, otherwise at offset 8.
fn decode_f101_into_metadata(m: &mut DmeIdentifiers, value: &[u8]) {
    if value.len() < 18 {
        return;
    }
    let entries_start = if (value[7] & 0xF0) == 0x80 { 17 } else { 8 };
    let mut swfls: Vec<ModuleIdent> = Vec::new();
    let mut swfk: Option<ModuleIdent> = None;
    let mut pos = entries_start;
    while pos + 8 <= value.len() {
        let cls = value[pos];
        if cls == 0 {
            pos += 8;
            continue;
        }
        let sgbm = format!(
            "{:02X}{:02X}{:02X}{:02X}",
            value[pos + 1],
            value[pos + 2],
            value[pos + 3],
            value[pos + 4]
        );
        let ver = format!(
            "{:03}.{:03}.{:03}",
            value[pos + 5],
            value[pos + 6],
            value[pos + 7]
        );
        let entry = ModuleIdent { sgbm, version: ver };
        match cls {
            0x01 => m.hwel = Some(entry),
            0x06 => m.btld = Some(entry),
            0x05 => m.cafd = Some(entry),
            0x08 => swfls.push(entry),
            0x0D => swfk = Some(entry),
            _ => {}
        }
        pos += 8;
    }
    let mut iter = swfls.into_iter();
    m.swfl_program = iter.next();
    if let Some(s) = swfk {
        m.calibration = Some(s);
    } else if let Some(second_swfl) = iter.next() {
        m.calibration = Some(second_swfl);
    }
}

/// Switch the session to extended (`10 03`), call routine `31 01 02 05`
/// with the BTLD SVK entry as parameters, parse the ASCII tail of the
/// response for the DME type and engine code, then drop back to the
/// default session (`10 01`). Mirrors the discovery pcap exactly.
#[cfg(feature = "live-ecu")]
fn call_routine_0205(
    client: &mut HsfzClient,
    ecu_address: u8,
    profile: &mut EcuProfile,
) -> Result<(), String> {
    // Enter extended session.
    let _ = client.send_uds(ecu_address, &[0x10, 0x03]);

    // Build params from the BTLD SVK entry we just cloned. If we don't
    // have one yet (clone-from-car ran but F101 was empty) we send a
    // hard-coded SWFL param blob observed as a fallback in the wild.
    let mut params: Vec<u8> = Vec::with_capacity(11);
    params.extend_from_slice(&[0x31, 0x01, 0x02, 0x05]);
    if let Some(btld) = profile.metadata.btld.as_ref() {
        if let (Some(sgbm), Some(ver)) = (parse_sgbm(&btld.sgbm), parse_version(&btld.version)) {
            params.push(0x06); // BTLD class
            params.extend_from_slice(&sgbm);
            params.extend_from_slice(&ver);
        }
    }
    if params.len() == 4 {
        // No BTLD — use the hard-coded fallback observed on the wire.
        params.extend_from_slice(&[0x08, 0x00, 0x00, 0x1D, 0x01, 0x1D, 0x96, 0x07]);
    }

    let resp = client
        .send_uds(ecu_address, &params)
        .map_err(|e| format!("routine 0x0205 failed: {}", e))?;

    // Drop back to the default session.
    let _ = client.send_uds(ecu_address, &[0x10, 0x01]);

    // Parse the routine response.
    //
    // Real DMEs return a `#`-separated ASCII payload after the SVK
    // entry slot — verified against the user-supplied wire data:
    //   71 01 02 05 [status] [class_byte] [SVK 8 bytes]
    //   #<dme_type>#C1#<marker>#<long_designation>#<cal_id>#<project>
    //
    // Example real response (with SWFL second entry as parameter):
    //   71 01 02 05 ff 01 08 00 00 1c 9f 1d 96 01
    //   #MEVD17.2.9________
    //   #C1#DST
    //   #MEVD17.2.P-N20-Mo-B20-U0-F030-EU6-HGAG_-LL-RL
    //   #9VT9G40B    ← cal ID
    //   #9G4LBIX6    ← project code
    //   (zero / underscore / 0xC3 padding)
    //
    // Strategy: split on `0x23`, take field[1] as the DME type,
    // pick the longest later ASCII field as the long designation,
    // grab the next 4-12 char alphanumeric field after it as the
    // cal ID, and substring-scan the whole blob for the engine code.
    if !resp.is_empty() && resp[0] != 0x31 {
        let fields = split_routine_response(&resp);
        // DME type: scan the ASCII payload for the canonical
        // `MEVDxx.x.x` / `MEDxx.x.x` / `MGxx.x.x` token rather than
        // trusting `fields[1]` blindly. Different flasher sub-functions
        // and different DMEs put extra prefixes (`DME-`, …)
        // before the bare type, so a substring scan is the only
        // reliable way to recover just the type designator.
        if let Some(dme) = extract_dme_type(&resp) {
            profile.metadata.dme_type = Some(dme);
        }
        let mut long_idx = None;
        let mut max_len = 0;
        for (i, f) in fields.iter().enumerate().skip(2) {
            if f.len() > max_len && f.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                max_len = f.len();
                long_idx = Some(i);
            }
        }
        if let Some(idx) = long_idx {
            // Capture the long designation verbatim so the synthesizer
            // can replay it byte-for-byte on the routine response.
            if let Some(long) = clean_field(&fields[idx]) {
                profile.metadata.long_designation = Some(long);
            }
            // First short alphanumeric field after the long designation
            // is the cal ID; the next one is the project code.
            let mut cal_assigned = false;
            for f in fields.iter().skip(idx + 1) {
                if let Some(s) = clean_field(f) {
                    if (4..=12).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric()) {
                        if !cal_assigned {
                            profile.metadata.calibration_id = Some(s);
                            cal_assigned = true;
                        } else {
                            profile.metadata.project_code = Some(s);
                            break;
                        }
                    }
                }
            }
        }

        // Engine code: substring scan over the whole ASCII blob,
        // matching how HSFZ tuning tools extract the engine code.
        let ascii: String = resp
            .iter()
            .map(|&b| {
                if (0x20..=0x7E).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        const ENGINES: &[&str] = &[
            "N20", "N55", "N26", "B48", "B58", "S55", "S58", "N63", "S63", "N74",
        ];
        for engine in ENGINES {
            if ascii.contains(engine) {
                profile.metadata.engine_code = Some((*engine).to_string());
                break;
            }
        }
    }
    Ok(())
}

/// Split a routine 0x0205 response into `0x23`-separated fields. The
/// header (`71 01 02 05 [status] [class_byte] [8-byte SVK entry]`) is
/// returned as `fields[0]` so callers can find their offset.
fn split_routine_response(resp: &[u8]) -> Vec<Vec<u8>> {
    let header_end = resp.iter().position(|&b| b == 0x23).unwrap_or(resp.len());
    let mut fields: Vec<Vec<u8>> = Vec::new();
    fields.push(resp[..header_end].to_vec());
    if header_end >= resp.len() {
        return fields;
    }
    let tail = &resp[header_end + 1..];
    let mut start = 0;
    for (i, &b) in tail.iter().enumerate() {
        if b == 0x23 {
            fields.push(tail[start..i].to_vec());
            start = i + 1;
        }
    }
    fields.push(tail[start..].to_vec());
    fields
}

/// Clean an ASCII field from a routine response: strip trailing
/// underscores / nulls / `0xFF` / `0xC3` padding, validate it's
/// printable, return `None` if empty after cleaning.
/// Scan a routine 0x0205 response for a DME type designator like
/// `MEVD17.2.9`, `MED17.7`, `MG1CS003`, etc. Walks the ASCII bytes,
/// finds a run that starts with `M` followed by a DME family prefix,
/// and stops at the first non-type character (so leading prefixes such
/// as `DME-` are skipped and trailing padding/separators are dropped).
fn extract_dme_type(resp: &[u8]) -> Option<String> {
    const PREFIXES: &[&str] = &["MEVD", "MED", "MEV", "MSD", "MSV", "MG1", "MG2", "MGU"];
    let ascii: String = resp
        .iter()
        .map(|&b| {
            if (0x20..=0x7E).contains(&b) {
                b as char
            } else {
                ' '
            }
        })
        .collect();
    for prefix in PREFIXES {
        if let Some(start) = ascii.find(prefix) {
            let tail: String = ascii[start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.')
                .collect();
            if tail.len() > prefix.len() {
                return Some(tail);
            }
        }
    }
    None
}

fn clean_field(bytes: &[u8]) -> Option<String> {
    let trimmed: Vec<u8> = bytes
        .iter()
        .copied()
        .take_while(|&b| b != 0 && b != 0xFF && b != 0xC3)
        .collect();
    if trimmed.is_empty() || !trimmed.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        return None;
    }
    let s = String::from_utf8(trimmed).ok()?;
    let s = s.trim_end_matches('_').trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
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

/// Returns `Some(string)` if `bytes` is non-empty, all printable ASCII,
/// and not all 0xFF (the simulator's "unknown" sentinel). Otherwise
/// `None` so the metadata field stays unset.
fn printable_ascii(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.iter().all(|&b| b == 0xFF) {
        return None;
    }
    if !bytes.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
        return None;
    }
    String::from_utf8(bytes.to_vec())
        .ok()
        .map(|s| s.trim().to_string())
}

fn encode_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02X}", byte));
    }
    s
}

/// Current UTC time as ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`). Hand-rolled to
/// avoid pulling in the `chrono` dependency for one timestamp.
fn current_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
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
