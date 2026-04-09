//! Synthesize on-wire UDS DID response bytes from a profile's metadata.
//!
//! This is the *read* side of the encoder layer. The editor stores
//! everything as plain typed fields (text, numbers, dates) in
//! `EcuProfile.metadata`, and at RDBI response time the simulator calls
//! `synthesize_did(metadata, did)` to materialise the bytes a real DME
//! would return for that DID.
//!
//! Why? Two reasons:
//!
//! 1. **Profile JSON stays human-readable.** No hex blobs for VIN,
//!    serial, system name, etc. — they live as plain strings the user
//!    can edit by hand.
//! 2. **Encoder fixes apply to existing profiles for free.** When we
//!    fix the F101 header bug or change the F150 separator, the user
//!    doesn't need to "re-save" every profile — the next response
//!    rebuilds from the typed metadata using the corrected encoder.
//!
//! Returns `None` for DIDs we don't know how to synthesise — the RDBI
//! handler then falls back to the raw `dids` map (for arbitrary
//! overrides like cloned coding DIDs) and finally to 0xFF padding.

use super::encoder::DmeIdentifiers;
use super::profile::EcuProfile;

// SVK process-class bytes used in the F101 entries. We currently
// always encode the calibration slot as the legacy `SWFL` (`0x08`)
// because the editor doesn't surface a class toggle — see the comment
// in `synth_f101` for the trade-off. SWFK (0x0D) would be added here
// the moment the editor grows that option.
const PROCESS_CLASS_HWEL: u8 = 0x01;
const PROCESS_CLASS_CAFD: u8 = 0x05;
const PROCESS_CLASS_BTLD: u8 = 0x06;
const PROCESS_CLASS_SWFL: u8 = 0x08;

const F101_HEADER_LEN: usize = 17;

/// Top-level dispatcher. Tries to build a synthesised response for
/// `did` from the profile's typed metadata. Returns `None` if the DID
/// isn't one we model — caller should fall back to the raw `dids` map.
pub fn synthesize_did(profile: &EcuProfile, did: u16) -> Option<Vec<u8>> {
    let m = &profile.metadata;
    match did {
        // ── Plain ASCII identification DIDs ─────────────────────────
        0xF190 => synth_ascii(profile.vin.as_deref()),
        0xF18C => synth_ascii(m.serial_number.as_deref()),
        0xF187 => synth_ascii(m.dme_supplier.as_deref()),
        0xF18A => synth_ascii(m.system_supplier.as_deref()),
        0xF191 => synth_ascii(m.hardware_number.as_deref()),
        0x59C8 => synth_ascii(m.zbnr.as_deref()),

        // ── DME type / engine code ──────────────────────────────────
        //
        // **Important:** the real DME does NOT return ASCII for either
        // of these DIDs. F150 on the captured real MEVD17 is just three
        // binary bytes (`0F 18 10` — meaning unknown, possibly an
        // SGBD index ID), and F197 isn't queried at all by typical
        // flashers. The DME type string ("MEVD17.2.9") actually comes
        // from the **routine 0x0205 response body**, which carries
        // ASCII at the tail.
        //
        // We don't synthesise F150 or F197 here; they fall through to
        // the legacy `dids` map (so a clone-from-car gets the real
        // bytes byte-for-byte) and finally to 0xFF padding. The DME
        // type appears in the routine response built by `services.rs`.

        // ── F101 SVK ────────────────────────────────────────────────
        0xF101 => synth_f101(m),

        // ── F18B manufacture date (BCD) ─────────────────────────────
        0xF18B => synth_bcd_date(m.manufacture_date.as_deref()),

        // ── 0x5815 battery voltage (1 byte * 0.0942) ────────────────
        0x5815 => synth_voltage(m.voltage_v),

        // ── Flash counters ───────────────────────────────────────────
        // Real DME wire format (verified against
        // a real MEVD17 DME discovery capture):
        //   0x2502 — current flash count → 4 bytes BE u32 (`00 00 00 03`)
        //   0x2503 — max permitted count → **2 bytes BE u16** (`00 3C`)
        // Sending 4 bytes for 0x2503 makes some flashers split the
        // response into upper/lower words and display "0/0".
        0x2502 => m.flash_counter.map(|c| c.to_be_bytes().to_vec()),
        0x2503 => m
            .max_flash_counter
            .map(|c| (c as u16).to_be_bytes().to_vec()),

        // ── 0x403C Calibration ID + CVN (20 bytes) ──────────────────
        0x403C => synth_403c(m),

        _ => None,
    }
}

fn synth_ascii(s: Option<&str>) -> Option<Vec<u8>> {
    let s = s?.trim();
    if s.is_empty() {
        return None;
    }
    Some(s.as_bytes().to_vec())
}

fn synth_f101(m: &DmeIdentifiers) -> Option<Vec<u8>> {
    let mut entries: Vec<(u8, [u8; 4], [u8; 3])> = Vec::new();
    if let Some(e) = parse_module(PROCESS_CLASS_HWEL, m.hwel.as_ref()) {
        entries.push(e);
    }
    if let Some(e) = parse_module(PROCESS_CLASS_BTLD, m.btld.as_ref()) {
        entries.push(e);
    }
    if let Some(e) = parse_module(PROCESS_CLASS_SWFL, m.swfl_program.as_ref()) {
        entries.push(e);
    }
    if let Some(e) = parse_module(PROCESS_CLASS_SWFL, m.calibration.as_ref()) {
        // Heuristic: legacy SWFL slot. Newer DMEs use SWFK; the
        // editor doesn't surface a class toggle, so we'd need to look
        // at neighbouring entries to decide. For now legacy is the
        // common case (MEVD17 et al). Override by adding a raw F101
        // entry to the dids map if you need SWFK exactly.
        entries.push(e);
    }
    if let Some(e) = parse_module(PROCESS_CLASS_CAFD, m.cafd.as_ref()) {
        entries.push(e);
    }
    if entries.is_empty() {
        return None;
    }

    // Header layout reverse-engineered from captured wire traffic against
    // a real MEVD17 DME. The byte values mirror what the DME returns:
    //
    //   byte 0     : SVK version           = 0x01
    //   byte 1     : programming-deps flag = 0x01
    //   bytes 2..4 : XWE count BE          = number of entries
    //   bytes 4..7 : programming date BCD  (year, month, day)
    //   byte 7     : TEK / fingerprint flags
    //                — high nibble 0x80 mandatory: tells the parser
    //                  entries start at offset 17, not offset 8.
    //                — low nibble  0x0F is what real DMEs send.
    //   bytes 8..9 : dealer ID
    //   byte 10    : programming device type
    //   bytes 11..14 : programming system S/N
    //   bytes 15..16 : KM stand
    //
    // Some paranoid flasher parsers sanity-check the date and dealer
    // fields. We populate them with plausible non-zero values rather
    // than zeros so a strict parser sees a "real-looking" header.
    let mut f101 = vec![0u8; F101_HEADER_LEN];
    f101[0] = 0x01; // SVK version
    f101[1] = 0x01; // programming-deps checked
    let xwe = entries.len() as u16;
    f101[2..4].copy_from_slice(&xwe.to_be_bytes());
    // BCD programming date 2024-01-01 — generic, not user-supplied.
    // Real DMEs encode their flash date here; we don't model this in
    // the editor so a static plausible value beats zeros.
    f101[4] = 0x24;
    f101[5] = 0x01;
    f101[6] = 0x01;
    // Extended fingerprint flag (high nibble 0x80) plus standard
    // TEK low nibble 0x0F. Mirrors real DME byte 7 = 0x8F exactly.
    f101[7] = 0x8F;
    // Dealer ID 0x04D2 — same value the captured real DME emits.
    f101[8] = 0x04;
    f101[9] = 0xD2;
    // Programming device type
    f101[10] = 0x01;
    // bytes 11..16 stay zero — programming S/N + KM stand

    for (cls, sgbm, ver) in &entries {
        f101.push(*cls);
        f101.extend_from_slice(sgbm);
        f101.extend_from_slice(ver);
    }
    Some(f101)
}

fn parse_module(
    class_byte: u8,
    m: Option<&super::encoder::ModuleIdent>,
) -> Option<(u8, [u8; 4], [u8; 3])> {
    let m = m?;
    let sgbm = parse_sgbm(&m.sgbm)?;
    let ver = parse_version(&m.version)?;
    Some((class_byte, sgbm, ver))
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

fn synth_bcd_date(s: Option<&str>) -> Option<Vec<u8>> {
    let s = s?.trim();
    if s.len() != 6 || !s.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = vec![0u8; 3];
    for i in 0..3 {
        let hi = bytes[i * 2] - b'0';
        let lo = bytes[i * 2 + 1] - b'0';
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn synth_voltage(v: Option<f32>) -> Option<Vec<u8>> {
    let v = v?;
    if !(0.0..=24.0).contains(&v) {
        return None;
    }
    let raw = (v / 0.0942).round() as i32;
    let clamped = raw.clamp(0, 0xFF) as u8;
    Some(vec![clamped])
}

fn synth_403c(m: &DmeIdentifiers) -> Option<Vec<u8>> {
    // 0x403C is a 20-byte block whose only field we model is the
    // 32-bit CVN at bytes 16..20. The ASCII calibration ID is NOT
    // stored here — that comes from the routine 0x0205 ASCII tail.
    // Bytes 0..16 are an opaque checksum/hash that varies per car;
    // we leave them zero rather than fabricating values.
    let cvn = m.cvn?;
    let mut buf = vec![0u8; 20];
    buf[16..20].copy_from_slice(&cvn.to_be_bytes());
    Some(buf)
}
