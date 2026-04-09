//! UDP vehicle-identification responder.
//!
//! HSFZ diagnostic and tuning tools all start a session by
//! broadcasting an HSFZ vehicle-identification probe on UDP port `6811`
//! and waiting for any responder on the LAN to reply with a text payload
//! containing `DIAGADR/BMWMAC/BMWVIN`. Without this responder the
//! simulator's TCP listener on port `6801` is invisible to discovery —
//! tools see "no vehicle on the network" and never connect.
//!
//! This module spawns a background thread that:
//!
//!   * binds `0.0.0.0:6811` (UDP)
//!   * listens for any inbound packet (we don't bother validating the
//!     probe — every HSFZ tool sends something different and they all
//!     expect a reply)
//!   * sends back an HSFZ-framed identification response built from the
//!     active profile's VIN, MAC, and diagnostic address
//!
//! Best-effort throughout: if port 6811 is already in use the responder
//! logs a warning and exits, leaving the TCP listener up.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::profile::EcuProfile;

const DISCOVERY_PORT: u16 = 6811;
const RECV_TIMEOUT: Duration = Duration::from_millis(250);

/// HSFZ control word used in identification responses. Real HSFZ gateways
/// use `0x0004` (vehicle-identification-data response); the parser in
/// our own calibration-read discovery module accepts any frame containing the
/// `DIAGADR` text, so this is also compatible with our own clients.
const CONTROL_VEHICLE_IDENT_RESPONSE: u16 = 0x0004;

/// Spawn the responder thread. The returned handle is parked inside the
/// running-server state alongside the TCP listener so `simulator_stop`
/// can tear both down together.
pub fn spawn(profile: EcuProfile, stop_flag: Arc<AtomicBool>) -> Option<thread::JoinHandle<()>> {
    let bind = format!("0.0.0.0:{}", DISCOVERY_PORT);
    let socket = match UdpSocket::bind(&bind) {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "discovery responder: cannot bind {} ({}). \
                 Tools won't see the simulator via UDP discovery.",
                bind,
                e
            );
            return None;
        }
    };
    if let Err(e) = socket.set_read_timeout(Some(RECV_TIMEOUT)) {
        log::warn!("discovery responder: set_read_timeout failed: {}", e);
    }
    log::info!(
        "discovery responder: listening on UDP {} (replying for VIN={:?}, ECU=0x{:02X})",
        bind,
        profile.vin,
        profile.ecu_address
    );

    let response = build_response(&profile);
    let handle = thread::Builder::new()
        .name("dme-sim-discovery".to_string())
        .spawn(move || {
            run(socket, response, stop_flag);
        })
        .ok()?;
    Some(handle)
}

fn run(socket: UdpSocket, response: Vec<u8>, stop_flag: Arc<AtomicBool>) {
    let mut buf = [0u8; 1024];
    while !stop_flag.load(Ordering::SeqCst) {
        match socket.recv_from(&mut buf) {
            Ok((n, peer)) => {
                log::info!(
                    "discovery responder: probe from {} ({} bytes), replying",
                    peer,
                    n
                );
                if let Err(e) = socket.send_to(&response, peer) {
                    log::warn!("discovery responder: reply to {} failed: {}", peer, e);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Timeout — loop and re-check the stop flag.
            }
            Err(e) => {
                log::warn!("discovery responder: recv error: {}", e);
                // Avoid a tight loop on a hard error.
                thread::sleep(Duration::from_millis(500));
            }
        }
    }
    log::info!("discovery responder: stopped");
}

/// Build the on-wire reply for a vehicle-identification probe.
///
/// Layout (HSFZ frame + ASCII payload):
/// ```text
/// [len:u32 BE][control:u16 BE = 0x0004][ "DIAGADR<n>BMWMAC<12hex>BMWVIN<17>" ]
/// ```
///
/// `<n>` is the diagnostic address in **decimal** (per HSFZ convention —
/// the parser in `calibration_read/discovery.rs` does `digits.parse::<u8>()`).
fn build_response(profile: &EcuProfile) -> Vec<u8> {
    let diag_decimal = profile.ecu_address;
    let mac_hex = sanitize_mac(&profile.mac);
    let vin = profile
        .vin
        .clone()
        .unwrap_or_else(|| "WBA00000000000000".to_string());
    let vin = if vin.len() == 17 {
        vin
    } else {
        // Pad or truncate to exactly 17 chars so the HSFZ parser's
        // fixed-width VIN read doesn't pull garbage from after the field.
        let mut s = vin;
        while s.len() < 17 {
            s.push('0');
        }
        s.truncate(17);
        s
    };

    let text = format!("DIAGADR{}BMWMAC{}BMWVIN{}", diag_decimal, mac_hex, vin);
    let payload = text.into_bytes();

    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&CONTROL_VEHICLE_IDENT_RESPONSE.to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

/// Strip colons / dashes / whitespace from a MAC string and uppercase it.
/// Pads or truncates to exactly 12 hex chars so the HSFZ parser's
/// fixed-width MAC read always succeeds.
fn sanitize_mac(mac: &str) -> String {
    let mut out: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    while out.len() < 12 {
        out.push('0');
    }
    out.truncate(12);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_profile() -> EcuProfile {
        EcuProfile {
            name: "test".into(),
            description: String::new(),
            ecu_address: 0x12,
            vin: Some("TESTVIN1234567890".into()),
            mac: "00:11:22:33:44:55".into(),
            metadata: Default::default(),
            dids: BTreeMap::new(),
            transfer_rate_kbps: None,
        }
    }

    #[test]
    fn response_has_diagadr_in_decimal() {
        let frame = build_response(&make_profile());
        let text = std::str::from_utf8(&frame[6..]).unwrap();
        assert!(text.starts_with("DIAGADR18"), "got {}", text);
        assert!(text.contains("BMWMAC001122334455"));
        assert!(text.contains("BMWVINTESTVIN1234567890"));
    }

    #[test]
    fn mac_sanitiser_strips_separators() {
        assert_eq!(sanitize_mac("00:11:22:33:44:55"), "001122334455");
        assert_eq!(sanitize_mac("aa-bb-cc-dd-ee-ff"), "AABBCCDDEEFF");
    }
}
