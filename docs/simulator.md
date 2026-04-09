# DME Simulator

A stateful HSFZ server that impersonates a BMW DME. It speaks enough of
the wire protocol that production flashers will connect, enumerate,
authenticate, erase, and write a full flash image to it — while the
simulator records every byte to disk for offline analysis.

Primary use cases:

- **Honeypot / fingerprinting** — run flashers against the simulator and
  capture their entire behavioural envelope (DID reads, routines called,
  TesterPresent cadence, checksum verification steps, write payloads).
- **Development harness** — iterate on flasher logic without risking a
  real ECU.
- **Protocol fuzzing** — modify responses mid-session to study flasher
  error handling (truncated NRCs, session timeouts, malformed UDS).
- **Capturing the flash** — run a flasher's write sequence against the
  simulator and reassemble the written binary from recorded segments.

Source: `src-tauri/src/simulator/`

---

## 1. Architecture

```
                       +---------------------+
                       |  Tauri command layer|
                       |  (simulator/mod.rs) |
                       +----------+----------+
                                  |
              spawn(cfg)          |          stop()
                                  v
                       +---------------------+
                       |  Listener thread    |
                       |  (server.rs)        |
                       |  - accept loop      |
                       |  - stop_flag poll   |
                       +----------+----------+
                                  |
               one accepted TCP connection at a time
                                  v
                       +---------------------+
                       |  session_loop       |
                       |  - read_frame       |
                       |  - dispatch UDS     |
                       |  - write_ack/resp   |
                       +---+-------------+---+
                           |             |
                           v             v
                  +----------------+  +------------------+
                  |  SessionState  |  |  CaptureSession  |
                  |  (state.rs)    |  |  (capture.rs)    |
                  |  mutable clone |  |  per-conn dir    |
                  |  of profile    |  |  raw.hsfz + log  |
                  +----------------+  +------------------+
```

Key properties:

- **One session at a time.** A real car only talks to one tester. The
  listener accepts inline on its own thread and resumes accepting only
  after the session ends.
- **Per-session profile clone.** Each accepted connection gets a fresh
  `SessionState` built from the template profile — WDBI writes don't
  bleed across sessions.
- **Short accept timeout + stop flag.** The listener polls a shared
  `AtomicBool` so `simulator_stop` is responsive.
- **Everything is captured.** Raw HSFZ frames, decoded UDS exchanges,
  and completed flash segments all land in a timestamped capture
  directory under the app's data folder.

---

## 2. Profile model

A profile is a JSON file that tells the simulator what kind of DME to
impersonate.

Source of truth: `simulator/profile.rs::EcuProfile`.

```json
{
  "name": "example-mevd17",
  "description": "Example profile",
  "ecu_address": 18,
  "vin": "WBATESTVIN1234567",
  "mac": "02:00:00:00:00:12",
  "metadata": {
    "dme_type": "MEVD17.2.9",
    "hw_number": "8614408",
    "sw_number": "",
    "programming_date_bcd": "20200615",
    "serial": "0012345678",
    "svk_entries": [ ... ],
    "cvn": "DEADBEEF",
    "flash_counter": 3
  },
  "dids": {
    "A011": "0102030405",
    "2000": "00FF00FF"
  },
  "transfer_rate_kbps": 45
}
```

### Two storage layers

1. **`metadata`** — typed source-of-truth fields (VIN, DME type, serial,
   SVK, flash counters, etc.). The simulator's RDBI handler
   *synthesises* the on-wire bytes at response time via
   `simulator::synthesize::synthesize_did`. This means:
   - You can edit profile JSON by hand without caring about byte layouts
     per DID.
   - Fixes to the encoder (e.g. the F186 "2 bytes not 1" bug) take
     effect for all existing profiles without re-saving.

2. **`dids`** — raw escape hatch, `{"DID_HEX": "VALUE_HEX"}`. Used for
   anything `metadata` doesn't model: coding DIDs from an NCD backup,
   vendor-specific blocks, cloned bytes from a real car that don't
   decode cleanly.

### DID resolution order

When the flasher issues `22 XX XX` (ReadDataByIdentifier), the simulator
resolves the response in this order:

1. **Session-overridden DIDs** — values the flasher wrote in the current
   session via WDBI (`0x2E`). These win over everything so re-reads
   return what was just written.
2. **`synthesize_did`** — typed metadata → wire bytes (F190, F101,
   F18B, F186, 0x403C CVN, etc.).
3. **`profile.dids`** — raw hex fallback.
4. **NRC / padding** —
   - Single-DID request: return NRC `0x31` (requestOutOfRange).
   - Multi-DID read (some flashers batch): pad the unknown DID with
     `0xFF` and continue — some flashers abort the whole session on any
     NRC inside a batch read.

---

## 3. Multi-address answering

**Critical design choice.** The simulator answers as `req.dst`, not as
`profile.ecu_address`.

Why: production flashers often poll `22 F190` at dst=`0x10` (gateway)
as a keepalive, even while flashing the DME at `0x12`. A simulator
that only answers as its own configured address would silently drop
those probes, and the flasher would tear the TCP session down after
~5 seconds of no reply.

Implementation (`simulator/server.rs`):

```rust
let resp_src = req.dst;  // we answer as whichever address was targeted
let resp_dst = req.src;
```

One profile therefore responds on `0x10`, `0x12`, `0x40`, etc.
simultaneously over a single TCP session — the same way a real BMW
gateway multiplexes diagnostic addresses across one ENET socket.

---

## 4. UDS service handlers

All implemented in `simulator/services.rs::handle_request`. The dispatch
returns `HandlerOutcome::{Positive, Negative, SegmentFinished}`.

| Svc    | Name                          | Behavior                                                |
|--------|-------------------------------|---------------------------------------------------------|
| `0x10` | DiagnosticSessionControl      | Accepts any subfunction, updates `state.session`, responds with session echo + P2 timings |
| `0x14` | ClearDiagnosticInformation    | No-op positive ack                                      |
| `0x19` | ReadDTCInformation            | Returns empty DTC list                                  |
| `0x22` | ReadDataByIdentifier          | DID resolution order above                              |
| `0x23` | ReadMemoryByAddress           | Returns synthesized memory (zeros or calibration excerpt from profile.metadata) |
| `0x27` | SecurityAccess                | Accepts any key — **this is a simulator, not a security oracle**. Returns success on any seed request and any key submission |
| `0x2E` | WriteDataByIdentifier         | Mutates `state.session_dids` (not persisted to profile file) |
| `0x31` | RoutineControl                | Subroutine `0x0205` (checksum verify) returns synthesized `#DST#` marker response; `FF01` (erase) positive-acks; other routines positive-ack with routine ID echo |
| `0x34` | RequestDownload               | Opens a new download context: records address + size, prepares segment buffer, returns max block length |
| `0x36` | TransferData                  | Appends block bytes to the active segment buffer; applies `transfer_rate_kbps` throttle sleep; returns block counter echo |
| `0x37` | RequestTransferExit           | Seals the segment → emits `SegmentFinished` to the capture layer, which writes `seg_*.bin` |
| `0x3E` | TesterPresent                 | Positive ack (no side effects)                          |

Unsupported services respond with NRC `0x11` (serviceNotSupported).

### SecurityAccess philosophy

The simulator **does not implement real seed/key cryptography**. It
accepts any key the flasher submits. This is deliberate:

- Implementing real key algorithms would make the tool a key-cracking
  oracle, which is out of scope for defensive research.
- The whole point of running a flasher against the simulator is to
  observe what the flasher does *after* auth succeeds — the write
  payload, the calibration diff, the verification steps. Gating on a
  real key would block that observation.

If you need to study seed/key algorithms, do it offline against your
own captured `0x27` exchanges; don't embed crackers in this tool.

---

## 5. Flash segment capture

When the flasher executes a download:

```
34 <addr> <len>                            request download
36 <cnt> <block bytes...>    (many times)  transfer data
37                                         request transfer exit
```

The simulator:

1. On `34`, records the `(address, declared_length)` pair and opens an
   in-memory segment buffer.
2. On each `36`, appends the block bytes and *optionally sleeps* to
   enforce `transfer_rate_kbps`:
   ```
   nanos = (block_len * 1_000_000_000) / (kbps * 1024)
   ```
   capped at 5 seconds per block so a misconfiguration doesn't lock the
   session.
3. On `37`, emits `HandlerOutcome::SegmentFinished { address, data }`.
   The session loop writes this to disk as
   `seg_<addr_hex>_<size>_bytes.bin`.
4. Emits a `simulator-segment` Tauri event so the frontend can list it
   live without polling the filesystem.

Multiple segments per session are common — a typical MEVD17 flash is
CAFD + SWFL + possibly BTLD, each as a separate `34/36*/37` sequence.

### Transfer-rate throttle

Real HSFZ flashes clock in around 20-60 kB/s. A simulator that accepts
4 MiB in four seconds trips telemetry in some flashers that flags
"unrealistically fast flash completion". The `transfer_rate_kbps`
profile field (default `None` = uncapped) forces the simulator to pace
TransferData blocks to match a realistic rate.

Useful values for research:

| Setting | Effect |
|---------|--------|
| `None` / `0` | Uncapped (fastest — good for quick iteration) |
| `20`–`60`   | Realistic ENET flash range |
| `5`–`10`    | K-line/simulated-slow flash, useful for timing-attack research |

---

## 6. Capture directory layout

Every accepted session creates a new directory under the app's
`captures/` root:

```
<data_dir>/bmsecresearch/captures/
└── 20260408_143022_WBATESTVIN1234567/
    ├── meta.json                  # session header: profile name, VIN, peer, schema version
    ├── raw.hsfz                   # every HSFZ frame in/out, tagged with [t_ms u64][dir u8]
    ├── transcript.jsonl           # one NDJSON line per decoded UDS exchange / event
    ├── events.ndjson              # lifecycle events (info / warn / error)
    ├── seg_80180000_524288_bytes.bin
    ├── seg_80220000_524288_bytes.bin
    └── ...
```

- `<data_dir>` is `$XDG_DATA_HOME` on Linux, `%LOCALAPPDATA%` on
  Windows, or `$HOME/.local/share` fallback.
- `raw.hsfz` uses the on-wire HSFZ framing (`[len u32][ctrl u16][body]`)
  prefixed with a 16-byte tag `[t_ms u64 LE][dir u8 0=in,1=out][rsvd 7]`
  so the file can be diffed byte-for-byte against a real pcap and
  reassembled into a synthetic pcap if needed.
- `transcript.jsonl` is schema-versioned via the first
  `kind: "session_start"` line (`bmsec.simulator.transcript/1`) so
  downstream tooling can detect and migrate older captures.
- Segment files are named with address in hex and declared size in
  decimal for easy grep/sort.

All capture I/O is **best-effort**. A disk-full or permission error
is logged and the session continues — a live flash must never be
killed by a capture write failure.

---

## 7. Export pipeline

Three Tauri commands expose captures to the frontend:

| Command | Returns | Purpose |
|---------|---------|---------|
| `simulator_list_flash_sessions` | `Vec<FlashSession>` | Enumerate every capture dir, parse `meta.json`, return VIN + start time + segment count + total bytes + min/max address |
| `simulator_list_segments`       | `Vec<FlashSegmentFile>` | List `seg_*.bin` in a given session dir with parsed address + size |
| `simulator_export_flash_bin`    | path string | Concatenate all segments in address order, pad gaps with `0xFF`, write to a user-chosen path |

`export_flash_bin` hard-caps the output at **64 MiB** to avoid a
runaway concat if a session contains segments with absurd addresses.
Gaps between segments are padded with `0xFF` (erased-flash default) so
the output is a drop-in flash image for analysis tools.

The frontend (`src/lib/components/SimulatorPanel.svelte`) renders the
captured sessions as a list, with an **Export .bin** button that
triggers `simulator_export_flash_bin` and shows a top-center toast with
the output path.

---

## 8. Cloning from real captures

Two paths populate a profile from real data:

### 8.1 From a pcap

`simulator/clone.rs::clone_from_pcap` parses a tester↔DME pcap, walks
the HSFZ stream, and decodes every `62 XX XX …` RDBI response into
typed profile metadata. Key DIDs handled:

- `F190` VIN → `profile.vin`
- `F101` SVK → `metadata.svk_entries`
- `F18B` programming date → `metadata.programming_date_bcd`
- `F18C` serial → `metadata.serial`
- `403C` CVN → `metadata.cvn` (bytes 16..20; **not** the cal ID)
- Routine `0x0205` response → parses the `#DST#` ASCII tail for
  `dme_type`, long designation, `cal_id`, project code

Unknown DIDs are dumped verbatim into `profile.dids` as hex strings.

### 8.2 From an NCD backup

`simulator_import_ncd_backup` reads an NCD file (BMW's backup format
for coding/calibration dumps) and extracts coding DIDs into
`profile.dids`. Useful for cloning the coding state of a specific car
without capturing it live.

### 8.3 Empty-profile creation

`EcuProfile::empty` builds a shell with just VIN + ECU address. The
user then either runs clone-from-car against a live ECU or edits the
JSON by hand. The simulator deliberately does **not** ship a "default"
profile baked from a stranger's VIN — shipping someone else's VIN as
the apparent default has no practical use and raises privacy concerns.

---

## 9. Discovery responder

`simulator/discovery_responder.rs` spawns a UDP listener on port 6811.
When it sees a vehicle-identification broadcast probe, it replies with
a `DIAGADR<addr>BMWMAC<mac>BMWVIN<vin>` payload built from the profile.

Without this, a flasher doing broadcast-discovery wouldn't find the
simulator — you'd be limited to flashers that accept a manual host IP,
which most do not.

The responder:

- Binds `0.0.0.0:6811` UDP with `SO_REUSEADDR` so it coexists with a
  real gateway on the same subnet if the user is running both.
- Pre-computes the response bytes at profile-load time so the UDP
  handler can `sendto` directly without reformatting per probe.
- Best-effort: a port-already-in-use error logs a warning and the TCP
  listener still comes up — you just won't auto-discover.

---

## 10. Tauri event surface

The simulator streams three event types to the frontend:

| Event name | Payload | Meaning |
|------------|---------|---------|
| `simulator-status` | `{ state, detail }` | Lifecycle: `listening` / `connected` / `disconnected` / `stopped` / `error` |
| `simulator-transcript` | `{ direction, service, body_hex, note }` | Every decoded UDS request/response, direction `"REQ"` or `"RSP"` |
| `simulator-segment` | `{ address, size, file_path }` | Emitted when a `34/36*/37` sequence completes and `seg_*.bin` is written |

The UI uses these to render a live wire-log, a session-state pill, and
a "Captured Flashes" list that can be exported to disk.

---

## 11. Usage

Typical flow from a cold start:

1. **Create or import a profile.**
   - Fastest: run a pcap through the Extract tab, then
     `simulator_clone_from_pcap` — profile is populated from real DME
     responses.
   - Alternative: `simulator_create_empty_profile` + hand-edit JSON +
     `simulator_save_profile`.
2. **Start the listener.**
   - `simulator_start` with the profile name and bind address
     (default `0.0.0.0:6801`).
   - UI shows the "listening" status pill.
3. **Point the flasher at the simulator host.**
   - Most flashers will auto-discover via the UDP responder. Some
     accept a manual host IP in their settings.
4. **Watch the transcript.**
   - Live UDS exchanges stream into the wire-log panel.
5. **Export captured flashes.**
   - When the flasher finishes, use the "Captured Flashes" list to
     export any written segments as a single `.bin`.
6. **Stop the listener** when done. Subsequent sessions start fresh
   (profile mutations during the last session are discarded unless
   you explicitly saved them).

---

## 12. Research ideas

- **Cross-flasher diff**: run multiple flashers against the same
  profile, diff the `seg_*.bin` outputs. What does each flasher
  actually write? Does it touch fingerprint regions? Does it sanitize
  the cal ID?
- **Telemetry detection**: enable `transfer_rate_kbps` at realistic
  values and watch whether the flasher proceeds normally. Then
  disable it and repeat — does the flasher flag the unrealistic rate?
- **Malformed-response fuzzing**: patch `synthesize_did` to return
  malformed bytes for a specific DID and observe how the flasher
  handles it. Does it retry, abort, or misinterpret?
- **Routine 0x0205 spoofing**: change `metadata.dme_type` or `cal_id`
  mid-session and observe how the flasher validates its own write.
- **Session-binding research**: use multi-address answering to have
  the simulator respond as `0x10` with a different VIN than `0x12`.
  How do flashers handle gateway/DME VIN mismatch?
