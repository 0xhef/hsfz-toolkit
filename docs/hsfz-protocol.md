# HSFZ Protocol Reference

**HSFZ** — *High-Speed Fahrzeug-Zugang* ("high-speed vehicle access") — is
BMW's proprietary transport for tunnelling ISO 14229 (UDS) diagnostic
traffic over Ethernet/IP. It is the link layer that every modern BMW
diagnostic or reflash tool speaks to the car's central gateway once the
tool has moved past the OBD-II DoIP handshake or a direct ENET cable
connection. HSFZ is deceptively simple on the wire — six bytes of header
plus a payload — but understanding its framing, control codes, and the
logical-addressing conventions sitting on top of it is a prerequisite for
any PCAP-level analysis of BMW reflash sessions.

This document describes HSFZ as it is implemented in this repository's
simulator and pcap extractor. All constants, field layouts, and
behaviours cited here are taken directly from
`src-tauri/src/simulator/hsfz.rs`,
`src-tauri/src/simulator/discovery_responder.rs`, and the pcap reader
under `src-tauri/src/pcap/`. Where the protocol admits multiple valid
implementations, the choices described are the ones observed from real
BMW gateways and ECUs captured in wire traces, and encoded as constants
or comments in those modules.

The target audience is a security researcher or reverse-engineer already
comfortable with UDS, ISO-TP, and TCP/IP; this is not an introduction to
diagnostic protocols.

---

## 1. Transport and Ports

HSFZ runs over two well-known IP ports:

| Port | Transport | Direction | Purpose                               |
|------|-----------|-----------|---------------------------------------|
| 6801 | TCP       | Bidirectional | UDS request/response session      |
| 6811 | UDP       | Broadcast + unicast reply | Vehicle-identification discovery |

The TCP port is a long-lived session: a tester opens one TCP connection
to the gateway (or directly to a target ECU, when the ECU is addressed
via an ENET-capable header unit), and that single socket carries every
subsequent UDS exchange — diagnostic session control, security access,
ReadDataByIdentifier, RequestDownload, TransferData, and so on — for as
long as the flashing or diagnostic job runs. The simulator's constant
is declared directly:

```rust
pub const HSFZ_PORT: u16 = 6801;
```

(`src-tauri/src/simulator/hsfz.rs`.)

The UDP port is stateless and is used only for the initial "who is on
this network?" broadcast probe described in section 8.

Because every byte on port 6801 is HSFZ, identifying HSFZ in a pcap is
unambiguous: filter TCP streams where either endpoint uses port 6801
and carries non-empty payload. The repo's reader does exactly this:

```rust
const HSFZ_PORT: u16 = 6801;
// ...
if (tcp.src_port == HSFZ_PORT || tcp.dst_port == HSFZ_PORT)
    && !tcp.payload.is_empty() { ... }
```

(`src-tauri/src/pcap/reader.rs`.)

---

## 2. Frame Format

Every HSFZ frame, on either direction, has the same six-byte header
followed by a variable-length payload:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Payload length (u32 BE)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Control word (u16 BE)   |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+        Payload (length B)     +
|                            ...                                |
+---------------------------------------------------------------+
```

Field semantics:

| Offset | Size | Field           | Notes                                              |
|--------|------|-----------------|----------------------------------------------------|
| 0      | 4    | `length`        | Big-endian u32. **Counts only the payload**; the 6-byte header is not included. |
| 4      | 2    | `control`       | Big-endian u16. See section 3.                     |
| 6      | N    | `payload`       | `length` bytes. Interpretation depends on `control`. |

Two important properties follow directly from this layout:

1. **`length` does not include itself or the control word.** A UDS
   frame carrying `10 02` (DiagnosticSessionControl, programming
   session) has five total payload bytes (two address bytes + three
   UDS bytes, as shown in section 4), so `length = 0x00000005` and the
   complete frame is 11 bytes on the wire.

2. **TCP segmentation is irrelevant at this layer.** A single HSFZ
   frame can be split across multiple TCP segments (common during
   `TransferData` bursts), and conversely multiple small frames can
   share one segment. Any correct HSFZ reader must loop over `length`
   and reassemble across segment boundaries. The simulator's
   `read_frame` does this by first reading exactly six bytes, decoding
   `length`, then performing a single `read_exact` for the body:

   ```rust
   let mut header = [0u8; 6];
   stream.read_exact(&mut header)?;
   let length  = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
   let control = u16::from_be_bytes([header[4], header[5]]);
   // ...
   let mut payload = vec![0u8; length as usize];
   stream.read_exact(&mut payload)?;
   ```

A defensive upper bound of 1 MiB is enforced on the length field to
prevent a hostile peer from forcing a huge allocation on a malformed
header:

```rust
const MAX_FRAME_PAYLOAD: u32 = 0x100000; // 1 MiB
```

Real BMW `TransferData` blocks are typically well under 4 KiB per
frame, so 1 MiB is already vastly more generous than anything
legitimate traffic produces.

### 2.1 Reconstructing a frame

To emit an HSFZ frame programmatically, the simulator uses a trivial
builder:

```rust
pub fn frame_to_wire(control: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&control.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}
```

Note the absence of any checksum, magic number, or version field. HSFZ
trusts TCP for integrity and trusts the control word to disambiguate
frame types. There is no way to tell an HSFZ frame from an arbitrary
TCP byte stream without either prior knowledge of the port or a
heuristic on the control word value.

---

## 3. Control Codes

The control word identifies the *kind* of frame. This implementation
recognises the following values:

| Value    | Name                              | Direction            | Meaning                                                    |
|----------|-----------------------------------|----------------------|------------------------------------------------------------|
| `0x0001` | `CONTROL_UDS`                     | Both                 | A UDS request or response (see section 4).                 |
| `0x0002` | `CONTROL_ACK`                     | ECU → tester         | Acknowledgement of a received UDS request (section 6).     |
| `0x0004` | Vehicle identification data       | ECU/gateway → tester | Reply to a UDP vehicle-ident probe (section 8).            |
| `0x0011` | `CONTROL_ALIVE_CHECK_REQUEST`     | Tester → ECU         | "Are you still there?" keepalive probe (section 7).        |
| `0x0012` | `CONTROL_ALIVE_CHECK_RESPONSE`    | ECU → tester         | Reply to an alive-check request; body is the ECU address.  |

These are declared directly in the simulator:

```rust
pub const CONTROL_UDS:                   u16 = 0x0001;
pub const CONTROL_ACK:                   u16 = 0x0002;
pub const CONTROL_ALIVE_CHECK_REQUEST:   u16 = 0x0011;
pub const CONTROL_ALIVE_CHECK_RESPONSE:  u16 = 0x0012;
```

and the discovery responder additionally uses:

```rust
const CONTROL_VEHICLE_IDENT_RESPONSE: u16 = 0x0004;
```

Other values exist in the wider HSFZ specification (error classes in
the `0x0040..=0x0045` range for malformed headers, unsupported control
words, etc.) but this tool does not emit them — a real gateway does,
and a researcher reversing an unfamiliar capture should treat any
high-range control word as a potential error indication rather than
silently discarding the frame.

**Identifying a frame by control word in a pcap:** after locating the
six-byte header, read bytes `[4..6]` as a big-endian u16. If the value
is `0x0001`, the payload parses as UDS (section 4); `0x0002` is an
ACK; `0x0011`/`0x0012` are the keepalive pair; anything else should be
logged verbatim rather than interpreted.

---

## 4. UDS Encapsulation Inside `0x0001`

A `CONTROL_UDS` frame carries a single UDS PDU plus a two-byte logical
address header:

```text
+--------+--------+--------+--------+--------+--------+--------+---
|  src   |  dst   | svc    | body[0]| body[1]| body[2]|  ...   |
+--------+--------+--------+--------+--------+--------+--------+---
   1 B      1 B      1 B               N bytes
```

The simulator's parser decodes it directly:

```rust
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
            src:     self.payload[0],
            dst:     self.payload[1],
            service: self.payload[2],
            body:    self.payload[3..].to_vec(),
        })
    }
}
```

So the *minimum* valid UDS frame is three bytes of payload: src, dst,
and a one-byte service (e.g. `3E` TesterPresent with no sub-function
and no suppress-positive-response flag). In practice every service
used during a reflash carries at least a sub-function byte.

### 4.1 Worked hex example

A tester at address `0xF4` reading the VIN (DID `0xF190`) from the
gateway at `0x10` produces the following request frame:

```text
00 00 00 06   0001   f4 10 22 f1 90
^^^^^^^^^^^   ^^^^   ^^ ^^ ^^ ^^ ^^
 length=6     UDS    sr ds sv did....
```

Total 12 bytes on the wire. The gateway's positive response is:

```text
00 00 00 XX   0001   10 f4 62 f1 90 57 42 41 ... 37
             (UDS)   src=0x10 dst=0xF4 0x62 (pos resp to 0x22) DID body
```

Note that the response *swaps* the src and dst fields: the request was
`F4 → 10`, the response is `10 → F4`. The repo comments this
explicitly, because it is load-bearing for the simulator to answer on
the correct logical address:

> The response is addressed **from** the ECU that the request was sent
> **to**, back to the tester that originated it — so a request to
> `dst=0x10` produces a response from `src=0x10`, even if the
> simulator's profile ECU is `0x12`.

### 4.2 Negative responses

Negative responses use the standard UDS `7F <service> <NRC>` form
inside an otherwise normal `0x0001` frame. The simulator has a direct
helper:

```rust
pub fn write_negative_response(
    stream: &mut TcpStream,
    src: u8, dst: u8,
    service: u8, nrc: u8,
) -> std::io::Result<Vec<u8>> {
    write_uds_response(stream, src, dst, &[0x7F, service, nrc])
}
```

There is no HSFZ-level "error" framing for UDS-layer failures; HSFZ
only defines error control codes for HSFZ-layer violations such as a
malformed header or an unsupported control word. A UDS NRC is
indistinguishable from a positive response at the HSFZ layer.

---

## 5. Logical Addresses

HSFZ reuses UDS logical (diagnostic) addresses. A BMW tester
conventionally identifies as `0xF4`:

```rust
pub const TESTER_ADDRESS: u8 = 0xF4;
```

Common ECU addresses a researcher will see on port 6801 of a modern
BMW include:

| Addr | ECU                                                         |
|------|-------------------------------------------------------------|
| `0x10` | Central gateway (ZGW). Many flashers VIN-poll this address as a keepalive even while flashing a different ECU. |
| `0x12` | DME (engine control unit) on its primary OBD logical address. |
| `0x13` | DME secondary address (seen on some dual-bus configurations). |
| `0x40` | FEM / BDC (body-domain controller) — also commonly seen as a destination on modern F/G-chassis cars. |
| `0xF4` | Tester (fixed by convention; the simulator hard-codes it).  |

The critical operational point — and the reason the simulator
carefully preserves the request's src/dst instead of swapping them to
a fixed profile address — is that **a single TCP session on port 6801
multiplexes multiple logical ECU addresses**. A flasher targeting the
DME at `0x12` may simultaneously poll `22 F190` at `0x10` every ~1.2
seconds as its keepalive, and the gateway is expected to answer *both*
on the same TCP stream. The simulator's commentary calls this out
directly:

> real BMW gateways multiplex several ECU addresses on one TCP session
> (0x10, 0x12, 0x40, …) and answering everything as a single
> hard-coded ECU breaks some flashers that VIN-poll 0x10 as their
> keepalive even after talking to 0x12.

When analysing a capture, do not assume a single destination address
per session. Group frames by `(src, dst)` pair after decoding the UDS
header, not by TCP 5-tuple.

---

## 6. ACK Frames (`0x0002`)

Real BMW ECUs acknowledge every received UDS request with a dedicated
`0x0002` frame *before* the actual UDS response is emitted. This is
sometimes confused with a transport-layer ACK (it isn't — TCP has
already acknowledged the bytes); its purpose is to tell the tester
"HSFZ received your frame and understood it as a UDS request",
independently of how long the ECU will take to produce the functional
response.

The ACK echoes the request's *original* src/dst (it is **not** swapped
the way a UDS response is) and the first up-to-five bytes of the
request body. The simulator implements this exactly:

```rust
pub fn write_ack(
    stream: &mut TcpStream,
    req_src: u8, req_dst: u8,
    req_body: &[u8],
) -> std::io::Result<Vec<u8>> {
    let echo_len = req_body.len().min(5);
    let mut payload = Vec::with_capacity(2 + echo_len);
    payload.push(req_src);
    payload.push(req_dst);
    payload.extend_from_slice(&req_body[..echo_len]);
    write_raw_frame(stream, CONTROL_ACK, &payload)
}
```

The five-byte echo length is not arbitrary: it was verified against a
captured MEVD17 DME wire trace, shown in the simulator's comments
verbatim:

```text
request:  00000009 0001 f4 40 31 01 10 01 0a 0a 43
ack:      00000007 0002 f4 40 31 01 10 01 0a
```

Reading this trace:

* The request is `31 01 10 01 0a 0a 43` — a RoutineControl (service
  `0x31`) "start routine" (sub-function `0x01`) against routine
  identifier `0x1001`, with routine arguments `0a 0a 43`.
* The request body (after the UDS service byte) is therefore
  `01 10 01 0a 0a 43`, six bytes.
* The ACK echoes `src=f4`, `dst=40`, service `31`, and then the first
  **five** bytes of the body after the service byte:
  `01 10 01 0a 0a`. The final `43` is not echoed.

A researcher reconstructing a session from a pcap can use this
predictable echo to pair each ACK with its originating request even
when the response itself is delayed (e.g. during a multi-second
`31 01 FF 00` erase routine).

---

## 7. Alive-Check Request / Response (`0x0011` / `0x0012`)

HSFZ defines a dedicated keepalive control word pair that is *not* the
same as UDS `3E TesterPresent`. The alive-check request (`0x0011`) is
an HSFZ-layer ping sent by the tester; the ECU replies with
`0x0012`, carrying its own two-byte logical address as the body:

```rust
pub fn write_alive_check_response(
    stream: &mut TcpStream,
    ecu: u8,
) -> std::io::Result<Vec<u8>> {
    let body = [ecu, TESTER_ADDRESS];
    write_raw_frame(stream, CONTROL_ALIVE_CHECK_RESPONSE, &body)
}
```

So an alive-check response has exactly two payload bytes: `[ecu,
tester]`. Some tester stacks will accept an empty body, but others
will close the socket on receipt of an empty `0x0012`, which is why
the simulator always populates both bytes.

### 7.1 Observed keepalive behaviour

There are **two** distinct keepalive mechanisms that can appear on a
live HSFZ session, and a researcher should not conflate them:

1. **HSFZ alive-check** (`0x0011` / `0x0012`). Tester-initiated at a
   typical cadence of 1–5 seconds. Rare in practice from end-user
   reflash tooling; more common from OEM diagnostic stacks.

2. **UDS-level VIN poll.** The tester issues
   `22 F190` (`ReadDataByIdentifier` / VIN) at address `0x10` every
   ~1.2 seconds on the same TCP socket. The simulator explicitly
   documents that this is what most modern flashers actually do:

   > Real DMEs do NOT proactively ping the tester; flashers keep the
   > link alive by polling `22 F190` (VIN) at address `0x10` every
   > ~1.2s, and we just answer those polls.

When reverse-engineering an unfamiliar flasher, both patterns are
worth checking: a tool might use one, the other, or both. A 1-second
`22 F190` poll stream against `0x10` is a strong fingerprint of
mainstream third-party flashing tooling.

---

## 8. UDP Discovery on Port 6811

Before any tool can open a TCP session to port 6801, it needs the IP
address of the gateway. BMW's convention is a UDP broadcast on port
6811: the tool sends an HSFZ-framed vehicle-identification *probe* to
`255.255.255.255:6811` (or the subnet broadcast), and any responder
on the link replies with a unicast HSFZ frame containing vehicle
identification data.

The simulator binds `0.0.0.0:6811` and does not bother validating the
probe contents at all — the comment explains why:

> we don't bother validating the probe — every BMW tool sends
> something different and they all expect a reply

The response is an HSFZ frame with control word `0x0004`:

```rust
const CONTROL_VEHICLE_IDENT_RESPONSE: u16 = 0x0004;
```

and an **ASCII** payload in a very specific fixed layout:

```text
DIAGADR<n>BMWMAC<12 hex>BMWVIN<17 chars>
```

where:

* `<n>` is the gateway's diagnostic address **in decimal** (not hex —
  this is an easy trap for anyone writing a parser, since the rest of
  HSFZ is binary). For a gateway at `0x12` (decimal 18) the string
  begins `DIAGADR18BMWMAC...`.
* `<12 hex>` is the gateway's MAC address, separators stripped,
  uppercased, and padded or truncated to exactly 12 hex characters.
* `<17 chars>` is the 17-character VIN, padded with `'0'` or
  truncated if necessary so that the field is *always* exactly 17
  bytes — BMW's fixed-width parser will read whatever follows
  otherwise.

The full on-wire layout of a response:

```text
[len:u32 BE][0x0004:u16 BE]["DIAGADR18BMWMAC001122334455BMWVINWBATESTVIN1234567"]
```

This is why the repo's unit tests assert:

```rust
assert!(text.starts_with("DIAGADR18"));
assert!(text.contains("BMWMAC001122334455"));
assert!(text.contains("BMWVINWBATESTVIN1234567"));
```

A researcher looking for BMW diagnostic endpoints on a strange network
can send any plausible probe to UDP `255.255.255.255:6811` and watch
for `0x0004` frames in replies; the ASCII `DIAGADR`/`BMWMAC`/`BMWVIN`
tags make these trivially greppable in raw pcap data.

---

## 9. Session Lifetime and the Five-Minute Read Timeout

HSFZ sessions on port 6801 have no protocol-defined idle timeout: the
session lives as long as TCP lives. In practice, however, simulator
and tester implementations need *some* upper bound so that a half-open
connection (e.g. the tester crashed, or the user walked away mid-job)
eventually frees resources.

The simulator sets a deliberately generous five-minute read timeout:

```rust
stream.set_read_timeout(Some(Duration::from_secs(5 * 60)))?;
stream.set_write_timeout(Some(Duration::from_secs(10)))?;
```

The commentary is worth quoting in full because it describes real
observed flasher behaviour:

> Interactive tuning flashers commonly pull their fingerprint DIDs in
> a burst then sit idle waiting for the user to pick a tune, so a
> too-tight read timeout killed otherwise-healthy sessions. Real DMEs
> do NOT proactively ping the tester; flashers keep the link alive by
> polling `22 F190` (VIN) at address `0x10` every ~1.2s, and we just
> answer those polls. The long timeout is only there so a hung
> session eventually frees.

Two practical consequences:

1. **Gaps of up to several minutes in a pcap are not suspicious on
   their own.** A capture that appears to "pause" for 30–90 seconds
   in the middle of a fingerprinting sequence is almost certainly a
   user at the tool's UI, not a protocol stall.

2. **Absence of `22 F190` polls in a capture is a fingerprint of
   tooling that uses the HSFZ `0x0011` alive-check instead.** Use
   this to classify unknown flashers.

Additionally, once the six-byte header of a frame has been read, the
simulator clears the read timeout entirely for the body read:

```rust
let prev = stream.read_timeout()?;
stream.set_read_timeout(None)?;
let res = stream.read_exact(&mut payload);
stream.set_read_timeout(prev)?;
```

The rationale is that a half-received frame is unrecoverable — there
is no resync marker in HSFZ — so it is better to block indefinitely
than to fail with a mid-frame timeout and have to reset the entire
TCP session. A researcher reproducing HSFZ parsing code should adopt
the same posture: do not attempt byte-level recovery inside a frame.

---

## 10. Identifying HSFZ in a PCAP

To decide whether a given pcap contains HSFZ traffic:

1. **Filter by port.** `tcp.port == 6801` or `udp.port == 6811`. The
   repo's `pcap::reader` does exactly this for the TCP case.
2. **Reassemble the TCP stream.** Use a stream reassembler (the repo
   has one in `src-tauri/src/pcap/tcp_reassembly.rs`); do not operate
   on raw segment payloads, since HSFZ frames freely straddle segment
   boundaries during TransferData bursts.
3. **Parse the six-byte header of the first frame.** If bytes
   `[0..4]` as a big-endian u32 give a value ≤ ~`0x100000` *and*
   bytes `[4..6]` are one of `{0x0001, 0x0002, 0x0004, 0x0011,
   0x0012, 0x0040..=0x0045}`, the stream is HSFZ with high confidence.
4. **Step forward by `6 + length` bytes** to the next frame and
   repeat. The absence of any inter-frame delimiter means a parser
   that loses sync cannot recover; on error, abort the stream.

For UDP discovery traffic on 6811, a plaintext grep for `DIAGADR`,
`BMWMAC`, or `BMWVIN` in packet payloads is sufficient — those tags
appear nowhere else in normal network traffic.

---

## 11. Summary of Wire Constants

For quick reference, the full set of magic numbers used by this
implementation:

| Constant                          | Value       | Source file                                |
|-----------------------------------|-------------|--------------------------------------------|
| `HSFZ_PORT`                       | `6801`      | `simulator/hsfz.rs`, `pcap/reader.rs`      |
| `DISCOVERY_PORT`                  | `6811`      | `simulator/discovery_responder.rs`         |
| `TESTER_ADDRESS`                  | `0xF4`      | `simulator/hsfz.rs`                        |
| `CONTROL_UDS`                     | `0x0001`    | `simulator/hsfz.rs`                        |
| `CONTROL_ACK`                     | `0x0002`    | `simulator/hsfz.rs`                        |
| `CONTROL_VEHICLE_IDENT_RESPONSE`  | `0x0004`    | `simulator/discovery_responder.rs`         |
| `CONTROL_ALIVE_CHECK_REQUEST`     | `0x0011`    | `simulator/hsfz.rs`                        |
| `CONTROL_ALIVE_CHECK_RESPONSE`    | `0x0012`    | `simulator/hsfz.rs`                        |
| `MAX_FRAME_PAYLOAD`               | `0x100000`  | `simulator/hsfz.rs`                        |
| Read timeout (session)            | `300 s`     | `simulator/hsfz.rs::configure_socket`      |
| Write timeout                     | `10 s`      | `simulator/hsfz.rs::configure_socket`      |
| Discovery recv timeout            | `250 ms`    | `simulator/discovery_responder.rs`         |

Every one of these is either declared as a `const` or set via an API
call in the cited files, and they are the authoritative reference for
this tool's behaviour — not this document. When in doubt, read the
source.

---

## 12. Additional Wire Constants Observed in Production Flashers

The simulator in this repository is intentionally minimal. A survey of
production flasher implementations against real F- and G-chassis BMWs
shows several additional constants and control-word values that the
simulator does not emit but that a researcher *will* see when reading
captures from a live car, and must handle in a parser.

### 12.1 HSFZ-layer error control words

Real gateways use the `0x0040..=0x0045` block (and `0x00FF`) to report
HSFZ-layer errors. A frame with one of these control words means the
gateway rejected the previous frame **at the HSFZ layer** — i.e. before
the UDS payload was even parsed. Treat these as fatal for the current
request:

| Value    | Meaning                                                 |
|----------|---------------------------------------------------------|
| `0x0040` | Incorrect tester address                                |
| `0x0041` | Incorrect control word                                  |
| `0x0042` | Incorrect frame format (malformed header/length)        |
| `0x0043` | Incorrect destination address                           |
| `0x0044` | Message too large                                       |
| `0x0045` | Diagnostic application not ready                        |
| `0x00FF` | Out of memory                                           |

A common way to trip `0x0042` in practice is to *reply* to a gateway's
unsolicited `0x0012` broadcast that carries a body larger than two
bytes — see section 13.3 on the DIAGADR broadcast gotcha.

### 12.2 Additional logical addresses

Beyond the addresses already listed in section 5, production flasher
code routinely targets:

| Addr   | ECU / role                                                             |
|--------|------------------------------------------------------------------------|
| `0x40` | FEM / BDC body-domain controller (also used for battery registration). |
| `0xDF` | Functional/broadcast address — used as the destination for a "global" TesterPresent that every ECU on the bus will ingest without producing a response. |

The `0xDF` address in particular is load-bearing: production flashers
send `22 F4 DF 3E 80` (suppress-positive-response TesterPresent) on a
~1 s cadence as their keepalive. `0xDF` means "everyone", and `0x3E80`
means "don't reply", so the frame is silent on the wire except for the
tester's own transmission.

### 12.3 UDS session sub-functions seen in flash jobs

ISO-14229 defines `0x01` (default), `0x02` (programming), `0x03`
(extended), and `0x04` (safety) as standard sub-functions of
`DiagnosticSessionControl` (SID `0x10`). BMW flashers also use two
vendor-specific values that will confuse a textbook UDS parser:

| Sub-function | Name (BMW)             | Used for                                   |
|--------------|------------------------|--------------------------------------------|
| `0x41`       | BMW programming        | SecurityAccess unlock on FEM/BDC and some gateway-mediated flows. Distinct from `0x02`. |
| `0x85`       | BMW coding             | Writing coding (NCD) data on body-domain ECUs. |

### 12.4 Security-access level pairing

`SecurityAccess` (SID `0x27`) seed/key pairs seen in captures:

| Level | Seed sub-func | Key sub-func | Purpose                     |
|-------|---------------|--------------|-----------------------------|
| 1     | `0x01`        | `0x02`       | Coding / configuration      |
| 2     | `0x03`        | `0x04`       | Flashing / programming      |
| 3     | `0x05`        | `0x06`       | Advanced / development      |

### 12.5 BMW-specific DIDs worth knowing when reading captures

None of these are required to parse HSFZ itself, but they appear so
often in real reflash traffic that recognising them removes a lot of
noise from a capture:

| DID      | Meaning                                                        |
|----------|----------------------------------------------------------------|
| `0xF190` | VIN (the keepalive-poll target at address `0x10`).             |
| `0xF191` | Hardware number (contains ZBNR for CAFD lookup).               |
| `0xF187` | Spare-part number.                                             |
| `0xF18C` | ECU serial number.                                             |
| `0xF18B` | Manufacturing / diagnostic date.                               |
| `0xF197` | System name / engine type.                                     |
| `0xF101` | SVK — BMW software inventory, 8-byte entries from offset 17.   |
| `0xF1A0` | StandardVersionsKennzeichnung (alt SVK container).             |
| `0xF12F` | Current integration level (I-Stufe).                           |
| `0xF12E` | Factory-shipment I-Stufe.                                      |
| `0x2502` | Current flash counter.                                         |
| `0x2503` | Maximum permitted flash counter.                               |
| `0x3F06` | Vehicle Order (VO / Fahrzeug-Auftrag) from ZGW.                |
| `0x460A` | DME battery voltage (2 bytes, ×0.015).                         |
| `0xDAD6` | FEM/BDC main battery supply line 1 (2 bytes, /10).             |

F101 SVK entries encode a one-byte *process class* (`0x01` HWEL,
`0x05` CAFD, `0x06` BTLD, `0x08` SWFL, `0x0D` SWFK) followed by a
four-byte big-endian module ID and a three-byte version, for an
eight-byte record stride. Entries begin at offset 17 of the SVK
payload.

---

## 13. Socket Tuning and Session Lifecycle in Production Flashers

The simulator's five-minute read timeout (section 9) is a
*server-side* choice appropriate for the passive side of the link.
Production *client* flashers use noticeably tighter numbers, and a
researcher reproducing their behaviour will need to match them or risk
subtle timing bugs.

### 13.1 TCP socket options

Observed settings on the client TCP socket to port 6801 in production
code:

| Option               | Value              | Rationale                                                    |
|----------------------|--------------------|--------------------------------------------------------------|
| `TCP_NODELAY`        | enabled            | Nagle's algorithm adds ~40 ms latency to the second half of a small frame; disabling it is essential for a responsive request/response UDS loop. |
| Connect timeout      | 5 s                | Gateway is either there or it isn't — a long connect timeout just hides misconfiguration. |
| Read timeout (socket-level) | 10 s        | Acts as a last-resort backstop for the background reader thread; per-request logic uses a tighter 3 s response timeout on top. |
| Per-request UDS timeout | 3 s             | Matches widely-observed OEM-stack timing for a standard UDS exchange. Long operations (erase, flash) bypass this and pass an explicit larger timeout (e.g. 30 s). |

TCP keepalive at the kernel level is *not* relied on — the protocol
has its own application-layer keepalive (section 13.2). This is
deliberate: kernel keepalives are typically configured at tens of
minutes, far longer than a BMW gateway's own idle-disconnect.

### 13.2 Application-layer keepalive cadence

Production flashers keep the HSFZ session alive with a
**one-second** cadence of suppress-positive-response TesterPresent
frames addressed to `0xDF` (functional broadcast):

```text
00 00 00 04   0001   f4 df 3e 80
^^^^^^^^^^^   ^^^^   ^^ ^^ ^^ ^^
 length=4     UDS    sr ds sv sub
```

Ten bytes total on the wire. Properties:

* **Destination `0xDF`** is the global/functional address. Every ECU
  ingests the frame; none replies.
* **Sub-function `0x80`** is the standard UDS suppress-positive-
  response bit. The ECU processes the frame but does not emit
  `7E 00`.
* **Length `0x00000004`** — four payload bytes (`F4 DF 3E 80`). A
  legitimate HSFZ TesterPresent is always exactly ten bytes on the
  wire.

The cadence used in production is **1000 ms between frames**, well
inside the BMW gateway's observed ~5-second inactivity window. That
window is measured from the last frame sent *to* the gateway, not from
the last frame received; sending only UDS requests to a non-gateway
ECU (e.g. flashing `0x12`) will still time out the gateway session
unless the tester also emits the broadcast TesterPresent.

In parallel, the gateway itself may emit `0x0012` (alive-check)
frames at an interval that varies by vehicle generation. A correct
implementation must *always* echo a received two-byte `0x0012` back
verbatim to keep the gateway happy, regardless of what the tester's
own keepalive loop is doing. The echo format is simply the same
six-byte header plus the same two-byte body; do not rewrite
addresses.

### 13.3 Gotcha: `0x0012` with a >2-byte body is *not* an alive check

F-chassis FEM/ZGW gateways have been observed to emit a `0x0012`
frame whose body contains an ASCII string of the form:

```text
DIAGADR10BMWVIN<17-char VIN>
```

This is a *diagnostic address registration broadcast*, not an
alive-check request, and it must **not** be echoed. Replying to it
produces an HSFZ error `0x0042` (incorrect format) and typically
tears down the session. The reliable discriminator is body length: a
real alive-check has a body of two bytes or fewer; anything longer on
control `0x0012` is informational and must be silently dropped.

A related quirk: the same DIAGADR announcement has also been observed
emitted with **control word `0x0001`** instead of `0x0012` on some
gateways. A UDS-layer parser that blindly consumes the first three
bytes of payload as `src/dst/service` will decode the leading `D I A`
(`0x44 0x49 0x41`) and report a phantom negative response with
"service `0x41`" / "NRC `0x47`" — neither of which are real. The
defensive fix is to check for the ASCII prefix `DIAG` (`44 49 41 47`)
on any inbound `0x0001` frame and drop it before UDS parsing.

### 13.4 Gateway VIN-poll responses must be filtered from the UDS queue

If the tester's keepalive strategy is the `22 F190` VIN poll against
`0x10` (see section 7.1) rather than the `0xDF` broadcast TesterPresent,
the gateway's replies to those polls will arrive on the same TCP
socket as legitimate UDS responses to other ECUs. A background reader
that fans responses out to per-request consumers must explicitly
recognise and discard them, or they will be handed to the wrong
caller. The discriminator is:

* Positive: `[src=0x10][dst=0xF4][0x62][0xF1][0x90] …`
* Negative: `[src=0x10][dst=0xF4][0x7F][0x22] …`

Any frame matching either pattern while the caller is waiting for a
response from a non-gateway ECU is keepalive noise and should be
dropped.

### 13.5 Only one TCP session per gateway

BMW central gateways accept exactly **one** concurrent TCP connection
on port 6801. A second connect attempt either hangs, times out, or
succeeds but immediately drops the first session — behaviour varies by
generation. Practical consequences:

* A researcher running a live flasher and a pcap capture at the same
  time must capture *passively* (tap or mirror port), not by opening
  a parallel diagnostic session.
* Any architecture that multiplexes "multiple UDS operations" over
  one gateway must do so by sharing a single long-lived socket and
  serialising requests through a single reader/writer pair — not by
  opening a socket per operation.
* The simulator's single-connection model is therefore not a
  limitation; it matches real gateway semantics.

### 13.6 Concurrent requests on one session are unsafe

Because the HSFZ response channel is not request-keyed (there is no
transaction ID; correlation is purely positional, by address and
service), issuing two UDS requests on the same TCP socket before the
first has responded leads to interleaved responses that the reader
cannot unambiguously dispatch. Production flashers serialise all UDS
traffic on a given session through a single mutex, even when the
application layer appears to be launching "parallel" background tasks
(e.g. a coding backup and an SVT backup). If you observe what looks
like out-of-order responses in a capture, the more likely explanation
is that the tester fired two requests concurrently and the second
response is being delivered ahead of the first.

### 13.7 Long-running UDS operations need per-request timeouts

Flash-erase (`31 01 FF 00`) routines and some large `TransferData`
writes can take tens of seconds to complete. The standard 3-second
per-request UDS timeout used for reads is not appropriate for these.
Production flashers pass an explicit timeout of up to ~30 seconds for
such calls, and allow a correspondingly larger number of `NRC 0x78`
(`requestCorrectlyReceived-ResponsePending`) frames to be received
before giving up. A reasonable cap is 30 response-pending frames per
request; beyond that, the ECU is almost certainly wedged.

Note that `NRC 0x78` frames are *not* treated as failures — each one
resets the tester's local response timer, and the final positive or
negative response can legitimately arrive many seconds after the
initial request.

---

## 14. Connection Lifecycle State Machine

A complete reflash session against a BMW gateway walks through the
following phases. Captures almost always contain all of them in this
order; a missing phase is itself diagnostic.

```text
 ┌──────────────┐
 │ Disconnected │
 └──────┬───────┘
        │ UDP broadcast 6811, collect 0x0004 replies
        ▼
 ┌──────────────────────┐
 │ Vehicle discovered   │  ← VIN, MAC, diag addr, gateway IP
 └──────┬───────────────┘
        │ TCP connect to <ip>:6801 (5 s timeout)
        │ setsockopt TCP_NODELAY
        ▼
 ┌──────────────┐
 │  Connected   │
 └──────┬───────┘
        │ Start background reader thread
        │ Start 1 Hz TesterPresent keepalive to 0xDF
        │ Read identity DIDs (F190, F191, F187, F18C, F101, …)
        ▼
 ┌──────────────────────┐
 │  Identified / idle   │  ← ECU version info known; waiting for work
 └──────┬───────────────┘
        │ 10 02  DiagnosticSessionControl → programming session
        │ 27 03 / 27 04  SecurityAccess level 2 (seed/key)
        ▼
 ┌──────────────────────┐
 │  Programming session │
 └──────┬───────────────┘
        │ 31 01 FF 00  erase routine (long, many NRC 0x78)
        │ 34          RequestDownload
        │ 36 …        TransferData (blocks, monotonic sequence counter)
        │ 37          RequestTransferExit
        │ 31 01 <checksum routine>
        │ (repeat per segment)
        ▼
 ┌──────────────────────┐
 │  Post-flash coding   │  ← optional: 2E writes, session 0x85
 └──────┬───────────────┘
        │ 11 01  ECU reset
        │ 10 01  back to default session
        ▼
 ┌──────────────┐
 │ Disconnected │  ← TCP FIN
 └──────────────┘
```

Between every phase, the keepalive loop continues running in the
background. A correct parser tracks the current UDS session state and
security-access state per `(src, dst)` pair, not per TCP connection,
because the session multiplexes several logical ECUs (section 5).

The pre-flash "identified / idle" phase is where the bulk of the
visible DID traffic in a capture actually lives — a production flasher
may read 50+ DIDs from the DME and the gateway before touching a
single flash byte, to fingerprint the exact ECU variant and select
the correct calibration.

---

## 15. Production Flasher Gotchas (Summary)

A concise list of behaviours that will bite anyone implementing or
reverse-engineering an HSFZ stack, collated from comments in mature
production implementations:

1. **`0x0012` is overloaded.** Two-byte body = alive-check, echo it.
   Longer body = diagnostic address registration broadcast, drop it.
   Replying to the wrong one gets HSFZ error `0x0042`.
2. **`0x0001` can carry DIAG-ADR announcements too.** Any inbound
   `0x0001` frame whose payload begins with ASCII `DIAG`
   (`44 49 41 47`) is a gateway broadcast and must be dropped before
   UDS parsing, or it will be misread as a bogus negative response.
3. **Broadcast TesterPresent, not unicast.** Flashers keep the
   session alive with `22 F4 DF 3E 80` — destination `0xDF`,
   suppress-positive-response. A *unicast* TesterPresent to `0x10`
   is also valid but less common and produces visible response
   traffic.
4. **Gateway VIN-poll responses pollute the UDS queue.** If your
   keepalive is `22 F190` to `0x10`, you must explicitly filter
   `[0x10][0xF4][0x62][0xF1][0x90] …` and
   `[0x10][0xF4][0x7F][0x22] …` frames from the response dispatcher.
5. **One TCP session per gateway.** Do not try to open two. Share a
   single socket across all concurrent work, and serialise requests
   through a single writer.
6. **Do not issue concurrent UDS requests on one session.** There is
   no transaction ID. Responses correlate only by address/service and
   will interleave unpredictably.
7. **`NRC 0x78` resets the timer.** Long operations legitimately
   produce many `7F xx 78` response-pending frames before the real
   answer. Expect up to ~30 of them during an erase.
8. **TCP segmentation is orthogonal.** A single HSFZ frame may span
   many TCP segments (common during `36` TransferData), and several
   small frames may share one segment. Always loop on `length` and
   reassemble.
9. **Do not reset the read timeout mid-frame.** Once the six-byte
   header is in, block unconditionally for the body — mid-frame
   timeout recovery is impossible because HSFZ has no resync marker.
10. **`0xF4` is a convention, not a requirement.** Nothing in HSFZ
    enforces the tester address; some stacks use other values. Trust
    the frame's own `src/dst`, not an assumed constant.
11. **Gateway idle-disconnect is ~5 seconds from last *outbound*
    frame.** A flasher that goes quiet for longer without sending
    keepalive traffic will find its session dead even though TCP is
    still nominally open.
12. **Discovery payload is ASCII but diag address is decimal.** The
    `DIAGADR<n>` field in the `0x0004` reply is decimal, not hex —
    easy trap when parsing a binary-heavy protocol.
