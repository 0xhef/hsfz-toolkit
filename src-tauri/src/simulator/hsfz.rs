//! Server-side HSFZ framer.
//!
//! Symmetric to `calibration_read/client.rs` but from the *ECU* end. We listen for an
//! incoming TCP connection, frame UDS messages on top of it, and emit ACK +
//! response frames the way a real HSFZ gateway does.
//!
//! Wire format (identical to the client side):
//! ```text
//! [length: u32 BE]   = bytes after the control field
//! [control: u16 BE]  0x0001 UDS, 0x0002 ACK, 0x0012 ALIVE, 0x0040..=0x0045 errors
//! [src: u8]          ECU diagnostic address (we are the ECU)
//! [dst: u8]          tester address (typically 0xF4)
//! [service: u8]
//! [payload bytes...]
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub const HSFZ_PORT: u16 = 6801;
pub const TESTER_ADDRESS: u8 = 0xF4;

pub const CONTROL_UDS: u16 = 0x0001;
pub const CONTROL_ACK: u16 = 0x0002;
/// Tester → ECU "are you still there?" probe.
pub const CONTROL_ALIVE_CHECK_REQUEST: u16 = 0x0011;
/// ECU → tester reply to an alive-check request. Body is the ECU's
/// 2-byte logical address (some testers also accept it empty).
pub const CONTROL_ALIVE_CHECK_RESPONSE: u16 = 0x0012;

const MAX_FRAME_PAYLOAD: u32 = 0x100000; // 1 MiB — generous for TransferData

/// One HSFZ frame as received from the wire.
#[derive(Debug, Clone)]
pub struct InFrame {
    pub control: u16,
    pub payload: Vec<u8>,
}

/// One UDS request decoded from a `CONTROL_UDS` frame. We keep the
/// raw `src`/`dst` bytes from the wire so the response can be sent
/// back with the same logical addressing — real HSFZ gateways multiplex
/// several ECU addresses on one TCP session (0x10, 0x12, 0x40, …) and
/// answering everything as a single hard-coded ECU breaks some
/// flashers that VIN-poll 0x10 as their keepalive even after talking
/// to 0x12.
#[derive(Debug, Clone)]
pub struct UdsRequest {
    pub src: u8,
    pub dst: u8,
    pub service: u8,
    pub body: Vec<u8>,
}

impl InFrame {
    pub fn as_uds_request(&self) -> Option<UdsRequest> {
        if self.control != CONTROL_UDS || self.payload.len() < 3 {
            return None;
        }
        Some(UdsRequest {
            src: self.payload[0],
            dst: self.payload[1],
            service: self.payload[2],
            body: self.payload[3..].to_vec(),
        })
    }
}

/// Result of one `read_frame` poll. The `Idle` variant lets the
/// session loop wake up periodically and emit alive-check pings
/// without having to mix raw `io::ErrorKind` matches into its body.
pub enum ReadOutcome {
    Frame(InFrame),
    Idle,
    Eof,
}

/// Read one full HSFZ frame from the stream. Returns `Idle` if the
/// configured read timeout fired with no bytes available (so the
/// caller can send a periodic alive-check), or `Eof` on a clean
/// peer-close.
pub fn read_frame(stream: &mut TcpStream) -> std::io::Result<ReadOutcome> {
    let mut header = [0u8; 6];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(ReadOutcome::Eof),
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            return Ok(ReadOutcome::Idle);
        }
        Err(e) => return Err(e),
    }
    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let control = u16::from_be_bytes([header[4], header[5]]);
    if length > MAX_FRAME_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("HSFZ length {} exceeds {}", length, MAX_FRAME_PAYLOAD),
        ));
    }
    let mut payload = vec![0u8; length as usize];
    if length > 0 {
        // Once we've committed to a frame (header is in), block
        // until the body arrives or the socket genuinely fails —
        // a half-read frame is unrecoverable.
        let prev = stream.read_timeout()?;
        stream.set_read_timeout(None)?;
        let res = stream.read_exact(&mut payload);
        stream.set_read_timeout(prev)?;
        res?;
    }
    Ok(ReadOutcome::Frame(InFrame { control, payload }))
}

/// Send an ACK frame in response to a UDS message. Real MEVD17 DMEs
/// emit the ACK with the **same** src/dst as the request (i.e.
/// tester→ECU, not swapped) and echo the first few bytes of the
/// request body. Verified against a real MEVD17 DME wire capture:
///   request:  `00000009 0001 f4 40 31 01 10 01 0a 0a 43`
///   ack:      `00000007 0002 f4 40 31 01 10 01 0a`
/// We mirror exactly that.
pub fn write_ack(
    stream: &mut TcpStream,
    req_src: u8,
    req_dst: u8,
    req_body: &[u8],
) -> std::io::Result<Vec<u8>> {
    let echo_len = req_body.len().min(5);
    let mut payload = Vec::with_capacity(2 + echo_len);
    payload.push(req_src);
    payload.push(req_dst);
    payload.extend_from_slice(&req_body[..echo_len]);
    write_raw_frame(stream, CONTROL_ACK, &payload)
}

/// Send a positive UDS response frame. The response is addressed
/// **from** the ECU that the request was sent **to**, back to the
/// tester that originated it — so a request to dst=0x10 produces a
/// response from src=0x10, even if the simulator's profile ECU is
/// 0x12. This lets one simulator answer to every logical address
/// a flasher might talk to (DME at 0x10, DME-OBD at 0x12, gateway at 0x40).
pub fn write_uds_response(
    stream: &mut TcpStream,
    src: u8,
    dst: u8,
    body: &[u8],
) -> std::io::Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(2 + body.len());
    payload.push(src);
    payload.push(dst);
    payload.extend_from_slice(body);
    write_raw_frame(stream, CONTROL_UDS, &payload)
}

/// Send a negative response (`7F <service> <nrc>`).
pub fn write_negative_response(
    stream: &mut TcpStream,
    src: u8,
    dst: u8,
    service: u8,
    nrc: u8,
) -> std::io::Result<Vec<u8>> {
    write_uds_response(stream, src, dst, &[0x7F, service, nrc])
}

/// Reply to a tester's alive-check **request** (`0x0011`) with an
/// alive-check **response** (`0x0012`). Body is the ECU's 2-byte
/// logical address — testers reject empty replies on some stacks.
pub fn write_alive_check_response(stream: &mut TcpStream, ecu: u8) -> std::io::Result<Vec<u8>> {
    let body = [ecu, TESTER_ADDRESS];
    write_raw_frame(stream, CONTROL_ALIVE_CHECK_RESPONSE, &body)
}

/// Reconstruct the wire bytes of a frame we already received via
/// `read_frame`. The capture layer logs the result via `log_raw_in` so
/// the on-disk `raw.hsfz` is a faithful byte-for-byte record of every
/// inbound frame, not just the parsed/decoded view.
pub fn frame_to_wire(control: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&control.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn write_raw_frame(
    stream: &mut TcpStream,
    control: u16,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    let frame = frame_to_wire(control, payload);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(frame)
}

/// Configure a freshly accepted TCP socket the way a HSFZ gateway does.
///
/// Critical on Windows: accepted sockets inherit the **listener's**
/// non-blocking flag, and our listener is non-blocking so `simulator_stop`
/// can poll the stop flag between accepts. Without an explicit
/// `set_nonblocking(false)` here every `read_exact` returns
/// `WouldBlock` (WSA error 10035) immediately and the session aborts on
/// the very first frame. POSIX handles this correctly without the call,
/// but it's harmless and makes the behaviour consistent across platforms.
pub fn configure_socket(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    // 5-minute read timeout. Interactive tuning flashers commonly
    // pull their fingerprint DIDs in a burst then sit idle waiting
    // for the user to pick a tune, so a too-tight read timeout
    // killed otherwise-healthy sessions. Real DMEs do NOT proactively
    // ping the tester; flashers keep the link alive by polling
    // `22 F190` (VIN) at address 0x10 every ~1.2s, and we just answer
    // those polls. The long timeout is only there so a hung session
    // eventually frees.
    stream.set_read_timeout(Some(Duration::from_secs(5 * 60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    Ok(())
}
