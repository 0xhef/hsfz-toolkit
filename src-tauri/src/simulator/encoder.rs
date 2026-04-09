//! Editor-side typed model for everything the HSFZ DIDs surface to a
//! tuning tool — VIN, DME type, SVK, flash counters, voltage, etc.
//!
//! This is **just storage**. The simulator's RDBI handler calls
//! [`synthesize::synthesize_did`](super::synthesize::synthesize_did) at
//! response time to build the actual on-wire bytes from these typed
//! fields. That means:
//!
//! * Profile JSON stays human-readable (plain ASCII / numbers / dates).
//! * Encoder fixes apply to existing profiles automatically — no
//!   "re-save every profile after a code change" friction.
//!
//! Wire-format reference for everything in here lives next to the
//! synthesizer in `simulator/synthesize.rs`.

use serde::{Deserialize, Serialize};

use super::profile::EcuProfile;

/// One module identifier as the user types it: an 8-hex-char SGBM and
/// a dotted version string like `"001.019.003"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleIdent {
    pub sgbm: String,
    pub version: String,
}

/// Everything the editor lets the user populate with one Save click.
///
/// `swfl_program` and `calibration` are presented as separate rows even
/// though older DMEs encode both under the same SVK process class
/// (`SWFL` / `0x08`) — the synthesizer figures out the byte layout, the
/// editor just talks in friendly names.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DmeIdentifiers {
    // ── F101 SVK entries ────────────────────────────────────────────
    pub hwel: Option<ModuleIdent>,
    pub btld: Option<ModuleIdent>,
    pub swfl_program: Option<ModuleIdent>,
    pub calibration: Option<ModuleIdent>,
    pub cafd: Option<ModuleIdent>,

    // ── Flash counters ──────────────────────────────────────────────
    /// Current flash count (DID `0x2502`, 4 bytes BE on the wire).
    pub flash_counter: Option<u32>,
    /// Maximum permitted flash count (DID `0x2503`, 4 bytes BE).
    pub max_flash_counter: Option<u32>,

    // ── Plain ASCII identification DIDs ─────────────────────────────
    /// `0xF18C` — ECU serial number
    pub serial_number: Option<String>,
    /// `0xF187` — DME supplier number / part number
    #[serde(alias = "bmw_supplier")]
    pub dme_supplier: Option<String>,
    /// `0xF18A` — System supplier identifier
    pub system_supplier: Option<String>,
    /// `0xF191` — Vehicle manufacturer ECU hardware number
    pub hardware_number: Option<String>,
    /// `0x59C8` — ZBNR (basis number)
    pub zbnr: Option<String>,

    // ── Date / numeric ──────────────────────────────────────────────
    /// `0xF18B` — manufacture date as `YYMMDD` (e.g. `"240115"`),
    /// encoded as 3 BCD bytes by the synthesizer.
    pub manufacture_date: Option<String>,

    /// `0x5815` — battery voltage in volts. Encoded as a single byte
    /// using the vendor-documented scale `voltage / 0.0942`.
    pub voltage_v: Option<f32>,

    /// DME type designator (e.g. `"MEVD17.2.9"`). The synthesizer
    /// writes this verbatim into `0xF197` and into `0xF150` (combined
    /// with `engine_code` via a space separator).
    pub dme_type: Option<String>,
    /// Engine code (e.g. `"N20"`, `"N55"`, `"B58"`). Combined with
    /// `dme_type` into the F150 SGBD-index string so a tuning tool's
    /// substring scan for the engine code finds it.
    pub engine_code: Option<String>,

    /// 8-character ASCII calibration ID (e.g. `"9VT9G40B"`). Stored
    /// in the first 8 bytes of DID `0x403C` **and** carried verbatim
    /// in the routine `0x0205` response (after the long designation).
    pub calibration_id: Option<String>,
    /// 32-bit Calibration Verification Number. Stored in bytes 16-19
    /// of DID `0x403C` as big-endian.
    pub cvn: Option<u32>,

    /// Long DME designation as it appears in the routine `0x0205`
    /// response, e.g. `"MEVD17.2.P-N20-Mo-B20-U0-F030-EU6-HGAG_-LL-RL"`.
    /// Cloned from real cars; synthesised from `dme_type + engine_code`
    /// when not set.
    pub long_designation: Option<String>,
    /// Project code that follows the cal ID in the routine `0x0205`
    /// response (e.g. `"9G4LBIX6"`). Captured from real cars during
    /// clone — purpose unknown but preserved for parity.
    pub project_code: Option<String>,
}

/// Validate the editor inputs and write them to `profile.metadata`.
///
/// All validation is done up-front so the user gets a meaningful error
/// toast on Save instead of an opaque failure later. After a successful
/// `apply` the simulator's RDBI handler synthesizes wire bytes from
/// `profile.metadata` on every read — there's nothing pre-encoded into
/// `profile.dids` for the well-known DIDs, so any future encoder fix
/// rolls out without requiring profiles to be re-saved.
pub fn apply(profile: &mut EcuProfile, ids: &DmeIdentifiers) -> Result<(), String> {
    validate(ids)?;
    profile.metadata = ids.clone();

    // Purge stale pre-encoded bytes from the legacy `dids` map for any
    // DID we synthesise from metadata. Without this, an old profile
    // saved before the synthesizer existed would still serve its
    // out-of-date hex blobs because the RDBI handler falls back to
    // `dids` when synthesise returns `None`.
    for did in [
        0xF101u16, 0xF150, 0xF18B, 0xF18C, 0xF187, 0xF18A, 0xF190, 0xF191, 0xF197, 0x59C8, 0x5815,
        0x2502, 0x2503, 0x403C,
    ] {
        let key = format!("{:04X}", did);
        profile.dids.remove(&key);
    }
    Ok(())
}

/// Return the typed metadata so the editor can pre-fill its form. The
/// metadata field on the profile *is* the source of truth — there's no
/// hex-decode fallback any more.
pub fn extract(profile: &EcuProfile) -> DmeIdentifiers {
    profile.metadata.clone()
}

fn validate(ids: &DmeIdentifiers) -> Result<(), String> {
    for (label, m) in [
        ("HWEL", &ids.hwel),
        ("BTLD", &ids.btld),
        ("SWFL Program", &ids.swfl_program),
        ("Calibration", &ids.calibration),
        ("CAFD", &ids.cafd),
    ] {
        let Some(m) = m else { continue };
        // Allow blank rows — only validate when at least one field is
        // non-empty (so the user can add modules incrementally).
        if m.sgbm.trim().is_empty() && m.version.trim().is_empty() {
            continue;
        }
        if !is_valid_sgbm(&m.sgbm) {
            return Err(format!(
                "{} SGBM must be 8 hex chars (got {:?})",
                label, m.sgbm
            ));
        }
        if !is_valid_version(&m.version) {
            return Err(format!(
                "{} version must be M.m.p (got {:?})",
                label, m.version
            ));
        }
    }
    if let Some(date) = &ids.manufacture_date {
        let d = date.trim();
        if !d.is_empty() && (d.len() != 6 || !d.chars().all(|c| c.is_ascii_digit())) {
            return Err(format!(
                "Manufacture date must be 6 digits YYMMDD (got {:?})",
                date
            ));
        }
    }
    if let Some(v) = ids.voltage_v {
        if !(0.0..=24.0).contains(&v) {
            return Err(format!("Voltage {} out of range (0..=24V)", v));
        }
    }
    if let Some(cal) = &ids.calibration_id {
        if cal.trim().len() > 8 {
            return Err(format!(
                "Calibration ID must be ≤ 8 characters (got {})",
                cal.trim().len()
            ));
        }
    }
    Ok(())
}

fn is_valid_sgbm(s: &str) -> bool {
    let s = s.trim();
    s.len() == 8 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_valid_version(v: &str) -> bool {
    let parts: Vec<&str> = v.trim().split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

// ── NCD coding-backup import ────────────────────────────────────────
//
// HSFZ tuning tools produce "NCD backup" JSON files when the user hits
// Backup Coding in their flash tab. The format observed in the wild:
//
// ```json
// {
//   "dids": [
//     { "did": "3300", "data": "ffffffff…" },
//     { "did": "3320", "data": "…" },
//     …
//   ]
// }
// ```
//
// We import them so the simulator can serve coding DIDs (0x3300,
// 0x3320, 0x3350, 0x3351, 0x37FE) when a flasher reads them. Coding
// DIDs are vendor-specific binary blobs we don't model in metadata, so
// they go into the raw `dids` map.

#[derive(Debug, Deserialize)]
struct NcdBackupFile {
    dids: Vec<NcdDidEntry>,
}

#[derive(Debug, Deserialize)]
struct NcdDidEntry {
    did: String,
    data: String,
}

/// Parse an NCD backup JSON and merge its DIDs into the supplied
/// profile. Returns the number of DIDs that were merged.
pub fn import_ncd_backup(profile: &mut EcuProfile, json: &str) -> Result<usize, String> {
    let parsed: NcdBackupFile =
        serde_json::from_str(json).map_err(|e| format!("parse NCD JSON: {}", e))?;
    let mut count = 0;
    for entry in parsed.dids {
        let did = u16::from_str_radix(entry.did.trim_start_matches("0x"), 16)
            .map_err(|e| format!("invalid DID '{}': {}", entry.did, e))?;
        let bytes = decode_hex_lenient(&entry.data)
            .ok_or_else(|| format!("invalid hex data for DID 0x{:04X}", did))?;
        profile.set_did(did, &bytes);
        count += 1;
    }
    Ok(count)
}

/// Lower-case-tolerant hex decoder used by the NCD importer
/// (tuning tools typically write these hex blobs in lower case).
fn decode_hex_lenient(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).ok()?);
    }
    Some(out)
}

/// The bundled sample NCD coding backup, baked into the binary at
/// compile time so the "Load Sample Coding" button works without
/// needing the user to source a real NCD JSON file.
pub const SAMPLE_NCD_BACKUP: &str = include_str!("../../resources/sample_ncd_coding_backup.json");
