//! HSFZ gateway discovery via HSFZ vehicle-identification UDP broadcast.
//!
//! Runs on Tauri's command thread directly with plain
//! `std::net::UdpSocket` (no tokio).
//!
//! Wire format (as observed from real HSFZ tooling):
//!   * Bind UDP socket to `0.0.0.0:7811`
//!   * Send 6-byte HSFZ packet `[00 00 00 00 00 11]` (length=0, control=0x0011)
//!     to every interface broadcast address on UDP port 6811
//!   * Collect text responses containing `DIAGADR<n>BMWMAC<12hex>BMWVIN<17>`
//!
//! The active sender side (`discover()`) is gated behind the `live-ecu`
//! Cargo feature; when disabled, `discover_vehicles` returns an empty
//! list and no UDP packets are emitted.

#![cfg_attr(not(feature = "live-ecu"), allow(dead_code))]

use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

const DISCOVERY_DST_PORT: u16 = 6811;
const DISCOVERY_SRC_PORT: u16 = 7811;
const VEHICLE_IDENT_DATA: u16 = 0x0011;
const DISCOVERY_TIMEOUT_SECS: u64 = 3;

#[derive(Debug, Serialize, Clone)]
pub struct DiscoveredDevice {
    pub ip: String,
    pub mac_address: String,
    pub vin: String,
    pub diag_address: u8,
}

/// Build the 6-byte HSFZ vehicle-identification packet.
fn discovery_packet() -> [u8; 6] {
    let mut buf = [0u8; 6];
    // length = 0
    // control = 0x0011 (big-endian)
    buf[4] = 0x00;
    buf[5] = 0x11;
    let _ = VEHICLE_IDENT_DATA; // documentation reference
    buf
}

/// Parse a discovery response. Layout is text-based:
///   `...DIAGADR<digits>BMWMAC<12hex>BMWVIN<17 chars>...`
fn parse_response(data: &[u8], source: Ipv4Addr) -> Option<DiscoveredDevice> {
    let s = String::from_utf8_lossy(data);
    let start = s.find("DIAGADR")?;
    let cleaned = &s[start..];

    // DIAGADR<digits>
    let after_diag = &cleaned[7..];
    let digits: String = after_diag
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let diag_address: u8 = digits.parse().ok()?;

    // BMWMAC<12hex>
    let mac_pos = cleaned.find("BMWMAC")?;
    let mac_raw: String = cleaned[mac_pos + 6..].chars().take(12).collect();
    if mac_raw.len() != 12 || !mac_raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mac_address = format!(
        "{}:{}:{}:{}:{}:{}",
        &mac_raw[0..2],
        &mac_raw[2..4],
        &mac_raw[4..6],
        &mac_raw[6..8],
        &mac_raw[8..10],
        &mac_raw[10..12],
    );

    // BMWVIN<17 chars>
    let vin_pos = cleaned.find("BMWVIN")?;
    let vin: String = cleaned[vin_pos + 6..].chars().take(17).collect();
    if vin.len() != 17 {
        return None;
    }

    Some(DiscoveredDevice {
        ip: source.to_string(),
        mac_address,
        vin,
        diag_address,
    })
}

/// Enumerate per-interface broadcast addresses on Windows by parsing
/// `ipconfig` output. On other platforms (and as a fallback on Windows when
/// parsing yields nothing) we send to the global broadcast `255.255.255.255`,
/// which is enough for the typical "laptop ↔ ENET cable ↔ car" topology.
fn broadcast_addresses() -> Vec<Ipv4Addr> {
    let mut out = Vec::new();

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("ipconfig").output() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                let mut cur_ip: Option<Ipv4Addr> = None;
                let mut cur_mask: Option<Ipv4Addr> = None;
                for line in text.lines() {
                    let line = line.trim();
                    if line.contains("IPv4 Address") || line.contains("IP Address") {
                        if let Some(s) = line.split(':').nth(1) {
                            let s = s.trim().trim_end_matches("(Preferred)").trim();
                            if let Ok(ip) = s.parse::<Ipv4Addr>() {
                                cur_ip = Some(ip);
                            }
                        }
                    }
                    if line.contains("Subnet Mask") {
                        if let Some(s) = line.split(':').nth(1) {
                            if let Ok(mask) = s.trim().parse::<Ipv4Addr>() {
                                cur_mask = Some(mask);
                            }
                        }
                    }
                    if let (Some(ip), Some(mask)) = (cur_ip, cur_mask) {
                        let ipo = ip.octets();
                        let mo = mask.octets();
                        let bcast = Ipv4Addr::new(
                            ipo[0] | !mo[0],
                            ipo[1] | !mo[1],
                            ipo[2] | !mo[2],
                            ipo[3] | !mo[3],
                        );
                        if !ip.is_loopback() && !bcast.is_loopback() {
                            out.push(bcast);
                        }
                        cur_ip = None;
                        cur_mask = None;
                    }
                }
            }
        }
    }

    if out.is_empty() {
        out.push(Ipv4Addr::new(255, 255, 255, 255));
    }
    out
}

/// Run a discovery sweep and return all unique devices found within the
/// 3-second listen window. Deduplicated by VIN — some gateways respond on
/// multiple interfaces.
pub fn discover() -> Result<Vec<DiscoveredDevice>, String> {
    let bind_addr = format!("0.0.0.0:{}", DISCOVERY_SRC_PORT);
    let socket = UdpSocket::bind(&bind_addr)
        .map_err(|e| format!("Failed to bind UDP {}: {}", bind_addr, e))?;
    socket
        .set_broadcast(true)
        .map_err(|e| format!("set_broadcast failed: {}", e))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(DISCOVERY_TIMEOUT_SECS)))
        .map_err(|e| format!("set_read_timeout failed: {}", e))?;

    let packet = discovery_packet();
    for bcast in broadcast_addresses() {
        let dst = SocketAddr::new(IpAddr::V4(bcast), DISCOVERY_DST_PORT);
        if let Err(e) = socket.send_to(&packet, dst) {
            log::warn!("Discovery send to {} failed: {}", dst, e);
        } else {
            log::info!("Discovery probe sent to {}", dst);
        }
    }

    let mut devices: Vec<DiscoveredDevice> = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((size, src)) => {
                if let SocketAddr::V4(v4) = src {
                    if let Some(dev) = parse_response(&buf[..size], *v4.ip()) {
                        if !devices.iter().any(|d| d.vin == dev.vin) {
                            log::info!(
                                "Discovered: ip={} vin={} diag=0x{:02X}",
                                dev.ip,
                                dev.vin,
                                dev.diag_address
                            );
                            devices.push(dev);
                        }
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => {
                log::warn!("Discovery recv error: {}", e);
                break;
            }
        }
    }

    log::info!("Discovery complete: {} device(s)", devices.len());
    Ok(devices)
}

/// Tauri command wrapper.
///
/// Gated behind the `live-ecu` Cargo feature. When the feature is off,
/// the command returns an empty list instead of emitting a UDP broadcast
/// probe. See SCOPE.md for the rationale.
#[cfg(not(feature = "live-ecu"))]
#[tauri::command]
pub fn discover_vehicles() -> Result<Vec<DiscoveredDevice>, String> {
    Ok(Vec::new())
}

#[cfg(feature = "live-ecu")]
#[tauri::command]
pub fn discover_vehicles() -> Result<Vec<DiscoveredDevice>, String> {
    discover()
}
