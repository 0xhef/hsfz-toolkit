//! Security utilities: input sanitization helpers shared across modules.
//!
//! Note: this file used to host `validate_input_path` and
//! `validate_output_path` for user-picked file paths. Both were removed
//! when the file-I/O architecture switched to "frontend handles all
//! user-picked paths via `@tauri-apps/plugin-fs`" — see the
//! architecture comment on `read_calibration_region` in
//! `calibration_read/mod.rs`. The Rust layer no longer takes any
//! user-picked path through IPC, so the path validators became dead
//! code and were deleted.

#[cfg(feature = "libpcap")]
use crate::error::PcapError;

/// Maximum length of interface name strings. Only used by
/// `validate_interface_name`, which is itself gated behind the
/// `libpcap` Cargo feature (interface names are a libpcap concept).
#[cfg(feature = "libpcap")]
const MAX_INTERFACE_NAME_LEN: usize = 256;

/// Validate an interface name string from the frontend.
///
/// Gated behind `libpcap` because interface names are a libpcap-only
/// concept — the only caller is `start_capture`, which itself only
/// has a real implementation when libpcap is compiled in.
#[cfg(feature = "libpcap")]
pub fn validate_interface_name(name: &str) -> Result<&str, PcapError> {
    if name.is_empty() || name.len() > MAX_INTERFACE_NAME_LEN {
        return Err(PcapError::InvalidPath);
    }
    // Interface names from pcap::Device::list() contain ASCII letters, digits,
    // dashes, underscores, colons, braces and GUID-style curly braces on Windows.
    // Reject control characters and NULs which could indicate injection attempts.
    if name.chars().any(|c| c.is_control() || c == '\0') {
        return Err(PcapError::InvalidPath);
    }
    Ok(name)
}

/// Sanitize a VIN (Vehicle Identification Number) for use in filenames
/// and display. VINs are 17 ASCII alphanumeric characters; anything else
/// is filtered out.
pub fn sanitize_vin(raw: &str) -> Option<String> {
    let clean: String = raw
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(17)
        .collect();
    if clean.is_empty() {
        None
    } else {
        Some(clean)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_vin_filters_special_chars() {
        assert_eq!(
            sanitize_vin("TEST1234/../../etc/passwd").as_deref(),
            Some("TEST1234etcpasswd")
        );
    }

    #[test]
    fn sanitize_vin_truncates_to_17() {
        assert_eq!(
            sanitize_vin("ABCDEFGHIJKLMNOPQRSTUVWXYZ").as_deref(),
            Some("ABCDEFGHIJKLMNOPQ")
        );
    }

    #[test]
    fn sanitize_vin_empty_returns_none() {
        assert_eq!(sanitize_vin(""), None);
        assert_eq!(sanitize_vin("!@#$%"), None);
    }

    #[cfg(feature = "libpcap")]
    #[test]
    fn validate_interface_name_rejects_control_chars() {
        assert!(validate_interface_name("eth0\0injected").is_err());
        assert!(validate_interface_name("\x01bad").is_err());
        assert!(validate_interface_name("eth0").is_ok());
    }

    #[cfg(feature = "libpcap")]
    #[test]
    fn validate_interface_name_rejects_empty_and_overlong() {
        assert!(validate_interface_name("").is_err());
        let long = "a".repeat(MAX_INTERFACE_NAME_LEN + 1);
        assert!(validate_interface_name(&long).is_err());
    }
}
