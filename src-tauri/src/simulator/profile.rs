//! ECU profile — the data the simulator hands to a flasher to make it
//! believe it's talking to a real DME.
//!
//! A profile carries:
//!   * VIN (string + the raw `F190` bytes)
//!   * Diagnostic address (typically `0x12`)
//!   * MAC (used by the discovery responder)
//!   * A `did` map: hex-string DID → hex-string response value
//!
//! Profiles are persisted as JSON. A built-in default profile cloned from
//! `PCAPdroid_08_Apr_03_13_44.pcap` ships with the binary so the simulator
//! works out of the box against any HSFZ tuning flasher without setup.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// On-disk JSON shape. Deliberately simple — every value is a hex string so
/// users can hand-edit profiles in any text editor.
///
/// Two storage layers:
///
/// * **`metadata`** is the source of truth for everything the editor
///   exposes — VIN, DME type, serial number, SVK entries, flash counters,
///   etc. These are stored as plain typed fields (text where possible,
///   numbers where appropriate) and the simulator's RDBI handler
///   *synthesises* the on-wire bytes from them at response time. Editing
///   the JSON by hand is straightforward; code fixes to the encoder take
///   effect immediately for existing profiles without requiring re-save.
///
/// * **`dids`** is the raw escape hatch — DID → hex bytes — used for
///   anything `metadata` doesn't model (cloned coding DIDs from an NCD
///   backup, raw bytes from a clone-from-car for DIDs we don't decode).
///   The RDBI handler consults `metadata` first, then falls back to
///   `dids`, then to 0xFF padding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcuProfile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub ecu_address: u8,
    pub vin: Option<String>,
    #[serde(default = "default_mac")]
    pub mac: String,
    /// Source-of-truth typed fields — see `synthesize::synthesize_did`
    /// for which DIDs are derived from this. `#[serde(default)]` so
    /// older profile JSONs (pre-refactor) load cleanly with empty
    /// metadata; the loader migrates them via `extract`.
    #[serde(default)]
    pub metadata: super::encoder::DmeIdentifiers,
    /// Raw DID overrides as hex strings. Anything not modelled by
    /// `metadata` lives here (coding DIDs, vendor blocks, etc.).
    #[serde(default)]
    pub dids: BTreeMap<String, String>,
    /// Optional artificial transfer-rate cap in **kilobytes per
    /// second**. When set, the `0x36 TransferData` handler sleeps
    /// after each block so the apparent flash rate matches the cap.
    /// `None` (or 0) means "as fast as possible". Real K-line/HSFZ
    /// flashes run at ~20–60 kB/s; tuning telemetry flags a 4 MiB
    /// write that finishes in <10s as obviously synthetic.
    #[serde(default)]
    pub transfer_rate_kbps: Option<u32>,
}

fn default_mac() -> String {
    "00:00:00:00:00:12".to_string()
}

impl EcuProfile {
    /// Look up a DID and return its raw response bytes (just the value
    /// portion — the caller is responsible for prepending the DID echo).
    pub fn lookup_did(&self, did: u16) -> Option<Vec<u8>> {
        let key = format!("{:04X}", did);
        let hex = self.dids.get(&key)?;
        decode_hex(hex).ok()
    }

    /// Set / overwrite a DID value (used by `WriteDataByIdentifier` so the
    /// simulator remembers what the flasher wrote and serves it back if
    /// re-read in the same session).
    pub fn set_did(&mut self, did: u16, value: &[u8]) {
        let key = format!("{:04X}", did);
        self.dids.insert(key, encode_hex(value));
    }

    /// Build an empty profile shell — no DIDs, just metadata. The user
    /// fills it in manually (VIN at minimum) or runs the clone-from-car
    /// flow to populate the DID map from a live ECU. We deliberately do
    /// **not** ship a "default" profile baked from somebody else's car —
    /// shipping a stranger's VIN as the apparent default is misleading and
    /// has no practical use.
    pub fn empty(name: &str, ecu_address: u8, vin: Option<String>) -> Self {
        // VIN lives on the top-level field — the synthesizer reads it
        // from there for DID 0xF190, no need to pre-encode bytes into
        // the dids map. Everything else stays blank until the user
        // fills it in or clones from a real car.
        Self {
            name: name.to_string(),
            description: format!("Empty profile created at {}", current_iso8601()),
            ecu_address,
            vin,
            mac: default_mac(),
            metadata: Default::default(),
            dids: BTreeMap::new(),
            transfer_rate_kbps: None,
        }
    }

    /// Load from an arbitrary JSON file path.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let body =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        serde_json::from_str(&body).map_err(|e| format!("parse {}: {}", path.display(), e))
    }

    /// Persist to JSON.
    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {}", parent.display(), e))?;
        }
        let body = serde_json::to_string_pretty(self).map_err(|e| format!("serialize: {}", e))?;
        std::fs::write(path, body).map_err(|e| format!("write {}: {}", path.display(), e))
    }
}

/// Directory where user-saved profiles live. Resolves to the
/// platform-correct app data root (set up at Tauri startup in
/// `lib::run`) plus the `profiles` subdir. On Android this lands
/// under `/storage/emulated/0/Android/data/org.bmsecresearch.app/files/profiles/`
/// which is visible to file managers without root.
pub fn profiles_dir() -> PathBuf {
    crate::app_paths::profiles_dir()
}

/// List every profile JSON in the profiles directory. Returns an empty
/// vector if the user hasn't created any yet — the frontend uses that as
/// the signal to show the empty state and prompt for a Clone or Create.
pub fn list_profiles() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let dir = profiles_dir();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            if let Some(name) = e.file_name().to_str() {
                if name.ends_with(".json") {
                    out.push(name.trim_end_matches(".json").to_string());
                }
            }
        }
    }
    out.sort();
    out
}

/// ISO-8601 timestamp for description fields. Hand-rolled to keep
/// `chrono` out of the dep tree.
fn current_iso8601() -> String {
    use std::time::SystemTime;
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

fn encode_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{:02X}", byte));
    }
    s
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("odd hex length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())?;
        out.push(byte);
    }
    Ok(out)
}
