//! Synchronous HSFZ/UDS TCP client.
//!
//! Self-contained, minimal HSFZ client: a calibration read is a strictly
//! serial request/response loop against a single ECU, so a plain blocking
//! `TcpStream` is enough — no background reader thread, channels, or
//! auto-reconnect logic needed.
//!
//! Wire format:
//!
//! ```text
//! [length: u32 BE]   // = 3 + payload.len() (size of UDS message portion)
//! [control: u16 BE]  // 0x0001 = UDS, 0x0002 = ACK, 0x0012 = Alive
//! [src: u8]          // 0xF4 (TESTER_ADDRESS)
//! [dst: u8]          // ECU address (e.g. 0x12 for DME, 0x40 for FEM)
//! [service_id: u8]
//! [payload bytes...]
//! ```
//!
//! This module is only used when the `live-ecu` Cargo feature is
//! enabled; under `--no-default-features --features research` the
//! whole struct is dead code (allowed below).

#![cfg_attr(not(feature = "live-ecu"), allow(dead_code))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

pub const HSFZ_PORT: u16 = 6801;

const TESTER_ADDRESS: u8 = 0xF4;
const GATEWAY_ADDRESS: u8 = 0x10;
const CONTROL_UDS: u16 = 0x0001;
const CONTROL_ACK: u16 = 0x0002;
/// Dual-purpose code: ALIVE CHECK request/response and VIN/diagnostic
/// address registration broadcast. Disambiguated by payload length in the
/// receive loop.
const CONTROL_ALIVE_CHECK_RESPONSE: u16 = 0x0012;

/// Number of VIN polls sent to the gateway after TCP connect to register
/// the tester (observed behavior of real HSFZ diagnostic sessions).
const GATEWAY_VIN_POLL_COUNT: usize = 4;
/// Spacing between VIN polls. Faster than 1 s/poll causes the gateway to
/// reject with HSFZ error 0x00FF (OUT_OF_MEMORY) — observed empirically.
const GATEWAY_VIN_POLL_INTERVAL_MS: u64 = 1000;

// Timeouts. Mobile (Android) runs with longer read timeouts because
// Wi-Fi power-save mode on phones aggressively idles the radio
// between packets, so single-frame round trips can stall for a
// second or two while the radio wakes back up. Desktop ENET has no
// such delay, so the tighter 10 s timeout is fine there.
#[cfg(not(target_os = "android"))]
const CONNECT_TIMEOUT_SECS: u64 = 5;
#[cfg(target_os = "android")]
const CONNECT_TIMEOUT_SECS: u64 = 10;

#[cfg(not(target_os = "android"))]
const READ_TIMEOUT_SECS: u64 = 10;
// 15 s on Android — enough slack for a Wi-Fi PSP wake + retransmit
// without making real stalls feel glacial. Combined with the retry
// budget and reconnect logic in `calibration_read::mod.rs`, this
// strikes a reasonable balance between fast recovery on a
// genuinely dead link and false-positive timeouts on a slow one.
#[cfg(target_os = "android")]
const READ_TIMEOUT_SECS: u64 = 15;

#[cfg(not(target_os = "android"))]
const WRITE_TIMEOUT_SECS: u64 = 5;
#[cfg(target_os = "android")]
const WRITE_TIMEOUT_SECS: u64 = 10;

/// Maximum HSFZ payload we'll accept on a single frame. The largest legitimate
/// frame in this app is a calibration block (~4096 bytes). Anything bigger is
/// almost certainly a desync or hostile peer.
const MAX_FRAME_PAYLOAD: u32 = 0x10000;

/// Pending-response retry budget. NRC 0x78 (responseStillPending) tells us to
/// keep waiting; this caps how many times we'll re-read before giving up.
const MAX_PENDING_RETRIES: usize = 60;

/// Structured error from the HSFZ client so the caller can surface a
/// user-friendly message that accurately identifies which stage of
/// the connection handshake failed. Desktop and mobile frontends both
/// render these via the `Display` impl on `ConnectError`.
#[derive(Debug)]
pub enum ConnectError {
    /// TCP connect itself failed — host unreachable, port refused,
    /// timed out, etc. Network-layer problem.
    Tcp(std::io::Error),
    /// TCP connected OK but configuring socket options failed. Rare.
    SocketConfig(std::io::Error),
    /// TCP connected OK but the HSFZ gateway closed the connection or
    /// rejected our HSFZ registration handshake. Almost always means
    /// "something is listening at that IP:port but it's not an HSFZ
    /// gateway, or the gateway is asleep/rejecting us".
    GatewayHandshake(std::io::Error),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(e) => write!(
                f,
                "TCP connect failed ({}). Check that the IP is reachable \
                 from this device and that nothing is blocking port 6801.",
                e
            ),
            Self::SocketConfig(e) => write!(f, "Socket setup failed: {}", e),
            Self::GatewayHandshake(e) => write!(
                f,
                "TCP connected but HSFZ handshake failed ({}). The IP is \
                 reachable but the peer is not responding as a HSFZ gateway — \
                 either the gateway is asleep (turn ignition to Position 1), \
                 the IP belongs to a different service, or the gateway is \
                 refusing new HSFZ sessions. Try Discover instead of a \
                 manual IP.",
                e
            ),
        }
    }
}

impl std::error::Error for ConnectError {}

pub struct HsfzClient {
    stream: TcpStream,
}

impl HsfzClient {
    /// Open a TCP connection to the HSFZ gateway and complete the HSFZ
    /// tester-registration handshake. Sets nodelay (request/response
    /// is latency-sensitive) and conservative timeouts before sending
    /// the first VIN poll.
    ///
    /// Returns a structured `ConnectError` that distinguishes TCP-layer
    /// failures (unreachable / refused / timed out) from gateway-layer
    /// failures (HSFZ handshake rejection) so the user can see at a
    /// glance which stage broke.
    pub fn connect(host: &str, port: u16) -> Result<Self, ConnectError> {
        let addr_str = format!("{}:{}", host, port);
        let addr: SocketAddr = addr_str
            .to_socket_addrs()
            .map_err(ConnectError::Tcp)?
            .next()
            .ok_or_else(|| {
                ConnectError::Tcp(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("no addresses resolved for {}", addr_str),
                ))
            })?;

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .map_err(ConnectError::Tcp)?;
        stream
            .set_nodelay(true)
            .map_err(ConnectError::SocketConfig)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)))
            .map_err(ConnectError::SocketConfig)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(WRITE_TIMEOUT_SECS)))
            .map_err(ConnectError::SocketConfig)?;

        log::info!("HSFZ TCP connected to {}", addr);
        let mut client = Self { stream };
        client
            .register_with_gateway()
            .map_err(ConnectError::GatewayHandshake)?;
        Ok(client)
    }

    /// Register this tester with the HSFZ gateway by issuing four VIN
    /// (`22 F1 90`) reads to gateway address `0x10` with 1 s spacing.
    ///
    /// Without this registration handshake, the gateway will *not* route
    /// subsequent UDS traffic to the DME — the read silently fails or
    /// times out. The 1-second spacing is mandatory: faster polling
    /// triggers HSFZ error 0x00FF (OUT_OF_MEMORY) on the gateway. Each
    /// poll's response (and any ACK frames) are read and discarded so
    /// the socket buffer stays clean for the actual read traffic.
    fn register_with_gateway(&mut self) -> std::io::Result<()> {
        log::info!(
            "Registering tester with gateway 0x{:02X}: {} VIN poll(s)",
            GATEWAY_ADDRESS,
            GATEWAY_VIN_POLL_COUNT
        );
        let vin_request = [0x22u8, 0xF1, 0x90];
        let frame = build_hsfz_frame(CONTROL_UDS, GATEWAY_ADDRESS, &vin_request);

        for i in 0..GATEWAY_VIN_POLL_COUNT {
            self.stream.write_all(&frame)?;
            self.stream.flush()?;
            log::info!(
                "VIN poll {}/{} sent to gateway",
                i + 1,
                GATEWAY_VIN_POLL_COUNT
            );

            // Drain whatever the gateway sends back (ACK, response, possibly
            // an extra Alive frame). Use a short read window so we don't
            // block forever if the gateway only emits one frame.
            let prev_timeout = self.stream.read_timeout()?;
            let _ = self
                .stream
                .set_read_timeout(Some(Duration::from_millis(800)));
            for _ in 0..4 {
                if self.recv_frame().is_err() {
                    break;
                }
            }
            let _ = self.stream.set_read_timeout(prev_timeout);

            if i + 1 < GATEWAY_VIN_POLL_COUNT {
                std::thread::sleep(Duration::from_millis(GATEWAY_VIN_POLL_INTERVAL_MS));
            }
        }

        // Final settle so the gateway considers registration complete before
        // we start the DME read storm.
        std::thread::sleep(Duration::from_millis(500));
        log::info!("Gateway registration complete");
        Ok(())
    }

    /// Send a UDS request and return the response data bytes.
    ///
    /// `request` is the full UDS message starting with the service id. The
    /// response on success has the leading `service_id + 0x40` byte
    /// stripped. On a negative response (`0x7F`), the returned vec is
    /// `[service_id, NRC]` so callers can pattern-match exactly the way
    /// `read_memory_by_address` expects.
    pub fn send_uds(&mut self, dst: u8, request: &[u8]) -> Result<Vec<u8>, String> {
        if request.is_empty() {
            return Err("Empty UDS request".to_string());
        }
        let service_id = request[0];

        let frame = build_hsfz_frame(CONTROL_UDS, dst, request);
        self.stream
            .write_all(&frame)
            .map_err(|e| format!("HSFZ write failed: {}", e))?;

        // The gateway echoes an ACK frame, may emit Alive frames, and may
        // emit one or more pending-response NRCs (0x78) before the final
        // answer. Loop until we get a UDS frame that matches our request.
        for _ in 0..MAX_PENDING_RETRIES {
            let (control, payload) = self.recv_frame()?;

            // HSFZ-level errors from the gateway. Anything in 0x0040-0x0045
            // or 0x00FF (OUT_OF_MEMORY) is an error, not a frame to keep
            // chasing.
            if matches!(control, 0x0040..=0x0045 | 0x00FF) {
                return Err(format!(
                    "HSFZ gateway error 0x{:04X}: {}",
                    control,
                    hsfz_error_name(control)
                ));
            }

            // ACK frames are routing acknowledgements — discard.
            if control == CONTROL_ACK {
                continue;
            }

            // Control 0x0012 has dual meaning (observed on the wire):
            //   * payload <= 2 bytes → ALIVE CHECK request from gateway —
            //     must be echoed back verbatim or the gateway disconnects us.
            //   * payload  > 2 bytes → VIN/diagnostic-address registration
            //     broadcast — silently ignored, sending any reply triggers
            //     HSFZ error 0x0042 (INCORRECT_FORMAT).
            if control == CONTROL_ALIVE_CHECK_RESPONSE {
                if payload.len() <= 2 {
                    let echo = build_raw_frame(control, &payload);
                    if let Err(e) = self.stream.write_all(&echo) {
                        log::warn!("ALIVE CHECK echo failed: {}", e);
                    } else {
                        log::debug!("Echoed HSFZ ALIVE CHECK ({} bytes)", payload.len());
                    }
                }
                continue;
            }

            if control != CONTROL_UDS {
                log::debug!(
                    "Skipping unknown HSFZ control 0x{:04X} ({} byte payload)",
                    control,
                    payload.len()
                );
                continue;
            }

            // UDS layer: [src][dst][service_response][payload...]
            if payload.len() < 3 {
                log::debug!("Truncated UDS frame ({} bytes), skipping", payload.len());
                continue;
            }
            let src = payload[0];
            let service_resp = payload[2];
            let body = &payload[3..];

            // Filter out leftover gateway VIN-poll responses from the
            // registration phase. Format:
            //   positive: [0x10][0xF4][0x62][0xF1][0x90][VIN…]
            //   negative: [0x10][0xF4][0x7F][0x22][NRC]
            // Anything from src=0x10 that isn't a response to *this* dst is
            // not ours and gets discarded.
            let is_gateway_vin_poll_echo = src == GATEWAY_ADDRESS
                && dst != GATEWAY_ADDRESS
                && ((service_resp == 0x62
                    && body.len() >= 2
                    && body[0] == 0xF1
                    && body[1] == 0x90)
                    || (service_resp == 0x7F && !body.is_empty() && body[0] == 0x22));
            if is_gateway_vin_poll_echo {
                log::debug!("Discarding stray gateway VIN-poll frame");
                continue;
            }

            // Negative response to *our* request.
            if service_resp == 0x7F {
                // body = [echoed_service, NRC, ...]
                if body.len() >= 2 && body[0] == service_id && body[1] == 0x78 {
                    log::debug!("NRC 0x78 (pending) — waiting for next frame");
                    continue;
                }
                if body.is_empty() || body[0] != service_id {
                    log::debug!(
                        "NRC for unrelated service 0x{:02X}, skipping",
                        body.first().copied().unwrap_or(0)
                    );
                    continue;
                }
                let mut out = vec![service_id];
                if body.len() >= 2 {
                    out.push(body[1]);
                }
                return Ok(out);
            }

            // Positive response — must echo our service_id + 0x40, otherwise
            // it's somebody else's response and we keep waiting.
            if service_resp != service_id + 0x40 {
                log::debug!(
                    "Unrelated positive response 0x{:02X} (expected 0x{:02X}), skipping",
                    service_resp,
                    service_id + 0x40
                );
                continue;
            }
            return Ok(body.to_vec());
        }

        Err("Exceeded pending-response retry budget".to_string())
    }

    /// Read a single HSFZ frame from the stream. Returns (control, payload).
    ///
    /// We use `read_exact` directly — there is no byte-level resync because
    /// a TCP stream can't be re-aligned mid-frame, and an active HSFZ
    /// session is supposed to be perfectly framed by the gateway anyway.
    /// If the framing ever desyncs the only sane response is to error out
    /// and let the caller drop the connection.
    fn recv_frame(&mut self) -> Result<(u16, Vec<u8>), String> {
        let mut header = [0u8; 6];
        self.stream
            .read_exact(&mut header)
            .map_err(|e| format!("HSFZ read header failed: {}", e))?;

        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let control = u16::from_be_bytes([header[4], header[5]]);

        // length == 0 is legitimate for HSFZ ALIVE CHECK and discovery
        // probes; only reject lengths beyond our sanity bound.
        if length > MAX_FRAME_PAYLOAD {
            return Err(format!("Invalid HSFZ length: {}", length));
        }

        let mut payload = vec![0u8; length as usize];
        if length > 0 {
            self.stream
                .read_exact(&mut payload)
                .map_err(|e| format!("HSFZ read payload failed: {}", e))?;
        }
        Ok((control, payload))
    }
}

/// Build a complete HSFZ frame: `[length:u32][control:u16][src][dst][svc][payload]`.
/// `request` must already start with the service-id byte.
fn build_hsfz_frame(control: u16, dst: u8, request: &[u8]) -> Vec<u8> {
    // UDS message body: [src][dst][service][payload]
    // length field counts the body, i.e. 3 (src+dst+svc) + (request.len() - 1).
    let body_len = (3 + (request.len() - 1)) as u32;
    let mut out = Vec::with_capacity(6 + body_len as usize);
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(&control.to_be_bytes());
    out.push(TESTER_ADDRESS);
    out.push(dst);
    out.extend_from_slice(request); // [service_id, payload...]
    out
}

/// Build a raw HSFZ frame with a custom control word and an arbitrary
/// payload (no UDS layering applied). Used to echo ALIVE CHECK frames
/// back to the gateway verbatim.
fn build_raw_frame(control: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&control.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Human-readable name for the HSFZ error control codes
/// (per `scapy/contrib/automotive/bmw/hsfz.py`).
fn hsfz_error_name(code: u16) -> &'static str {
    match code {
        0x0040 => "INCORRECT_TESTER_ADDRESS",
        0x0041 => "INCORRECT_CONTROL_WORD",
        0x0042 => "INCORRECT_FORMAT",
        0x0043 => "INCORRECT_DEST_ADDRESS",
        0x0044 => "MESSAGE_TOO_LARGE",
        0x0045 => "DIAG_APP_NOT_READY",
        0x00FF => "OUT_OF_MEMORY",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_layout_matches_wire_capture() {
        // ReadDataByIdentifier 0x22 0xF1 0x90 to ECU 0x12.
        let req = [0x22, 0xF1, 0x90];
        let frame = build_hsfz_frame(CONTROL_UDS, 0x12, &req);
        // length = bytes after the control field
        //        = src(1) + dst(1) + service(1) + payload(request.len()-1)
        //        = 2 + request.len() = 5
        assert_eq!(&frame[0..4], &[0x00, 0x00, 0x00, 0x05]);
        // control = 0x0001
        assert_eq!(&frame[4..6], &[0x00, 0x01]);
        // src, dst, service, payload
        assert_eq!(&frame[6..], &[0xF4, 0x12, 0x22, 0xF1, 0x90]);
    }
}
