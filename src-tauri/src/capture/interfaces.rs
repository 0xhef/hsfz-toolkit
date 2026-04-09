use serde::Serialize;

use crate::error::PcapError;

/// Network interface info returned to the frontend
#[derive(Debug, Clone, Serialize)]
pub struct NetworkInterface {
    pub name: String,
    pub description: String,
    pub is_loopback: bool,
    pub is_up: bool,
}

/// List all available capture interfaces.
///
/// On Windows, requires Npcap to be installed.
/// On Linux/macOS, requires libpcap and appropriate permissions.
/// On Android, libpcap is not part of the NDK and the default sideload
/// build omits the `libpcap` Cargo feature. Rooted-Android users with
/// a cross-compiled libpcap can rebuild with `--features libpcap` to
/// enable this. See ANDROID.md.
#[cfg(feature = "libpcap")]
pub fn list_interfaces() -> Result<Vec<NetworkInterface>, PcapError> {
    let devices = pcap::Device::list().map_err(|e| PcapError::PcapLibrary(format!("{}", e)))?;

    let interfaces: Vec<NetworkInterface> = devices
        .into_iter()
        .map(|d| NetworkInterface {
            description: d.desc.clone().unwrap_or_default(),
            is_loopback: d.flags.is_loopback(),
            is_up: d.flags.is_up(),
            name: d.name,
        })
        .collect();

    Ok(interfaces)
}

#[cfg(not(feature = "libpcap"))]
pub fn list_interfaces() -> Result<Vec<NetworkInterface>, PcapError> {
    Err(PcapError::PlatformUnsupported(
        "Live capture is not compiled into this build (the `libpcap` \
         feature is disabled). Use the Proxy tab to record HSFZ frames \
         as they're forwarded — the resulting capture can be analyzed \
         in the Extract from PCAP tab. See SCOPE.md and ANDROID.md."
            .to_string(),
    ))
}
