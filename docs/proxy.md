# DME Proxy — MITM Between Flasher and Real DME

The DME Proxy is a transparent-or-modifying man-in-the-middle that sits on
the wire between a flashing tool ("flasher") and a real BMW DME. It speaks
HSFZ on both sides, captures every byte of a live session with real
wall-clock timing, and optionally rewrites selected identity fields
(VIN, MAC, diagnostic address) on the fly.

Relevant source:

- `src-tauri/src/proxy/mod.rs` — proxy state, discovery responder, TCP
  forwarder, VIN rewriter, session capture, pcap export.
- `src-tauri/src/pcap/writer.rs` — `write_pcap_timed`, which wraps the
  captured HSFZ TCP payloads in synthetic Ethernet/IPv4/TCP headers so
  Wireshark can dissect them.
- `src/lib/components/ProxyPanel.svelte` — frontend UX for configuration,
  discovery, spoofing, session list, and export.
- `src/lib/types.ts` — the `ProxyConfig`, `ProxyStatus`, `ProxySession`,
  and `ProxyFrameEvent` types the Tauri bridge exchanges with Svelte.

---

## 1. Purpose

The proxy exists for three overlapping reasons:

1. **Observe live traffic.** Flash sessions are normally opaque — a
   compiled flasher talks to the DME and prints terse status strings. The
   proxy makes the entire HSFZ/UDS transcript visible, frame by frame, in
   real time, and writes a precise timestamped record to disk.

2. **Capture sessions for offline analysis.** Each accepted TCP session
   produces a self-contained capture directory that can be replayed,
   diffed, or exported to a Wireshark `.pcap` with correct timing. This
   is invaluable for reverse-engineering undocumented routines, checking
   transfer-data block sizes, confirming seed/key exchanges, or lining up
   a failure against its exact preceding request.

3. **Research VIN-binding behavior.** Many flashers enforce a license
   that ties a tool to a specific VIN. The proxy can rewrite the upstream
   DME's `22 F190` (Read Data By Identifier → VIN) response and the UDP
   discovery reply so the flasher sees a different VIN than the real
   car on the wire. This lets a researcher systematically probe where,
   when, and how VIN checks happen — and what breaks when the identity
   advertised during discovery disagrees with the identity reported by
   the DME later in the session.

The proxy is not a flash tool in its own right; it is a lens and a
lever applied to a real flash tool's traffic.

---

## 2. Architectural Challenge: Broadcast Discovery

BMW flashers do not let the operator type in a DME IP address. They find
the DME by broadcasting an HSFZ vehicle-identification probe on UDP 6811
and trusting the first reply. The proxy therefore cannot simply "be
configured" as the target — it has to **win the discovery race** so the
flasher dials the proxy's TCP port instead of the real DME's.

Two practical topologies satisfy this constraint. Both are documented in
the Setup banner of `ProxyPanel.svelte`.

### Setup A — Bridged Dual-NIC (recommended)

The proxy host has two physical network interfaces. One is plugged into
the flasher network; the other, via a BMW ENET cable, into the DME. The
DME's ENET cable is explicitly unplugged from the flasher's switch
before the proxy starts. With no L2 path between the two networks
except through the proxy host, the flasher's broadcast can only ever
reach the proxy, and there is no discovery race.

```
    ┌──────────┐              ┌────────────────────────┐              ┌──────┐
    │ flasher  │  eth0 LAN    │ proxy host             │  eth1 ENET   │ DME  │
    │          │─────────────▶│  UDP 6811 responder    │─────────────▶│      │
    │          │◀─────────────│  TCP 6801 forwarder    │◀─────────────│      │
    └──────────┘   broadcast  │  VIN rewriter          │   point-to-  └──────┘
                              │  session capture       │   point
                              └────────────────────────┘
```

Key properties:

- No UDP broadcast ever reaches the real DME from the flasher side; the
  proxy is the *only* possible responder on `eth0`.
- The proxy opens a fresh TCP connection on `eth1` to the real DME when
  a flasher client connects.
- IP forwarding is **not** required at the kernel level. The proxy does
  application-layer forwarding of the HSFZ frames it understands, not L3
  routing.

### Setup B — Single-Subnet Race

When the proxy host has only one NIC and proxy, flasher, and real DME
all share one broadcast domain, both the proxy and the real DME will
see the same discovery probe and both will answer. The proxy's responder
replies as fast as user-space can manage (microseconds), but the real
DME also answers on its own hardware. Whichever packet arrives at the
flasher first wins.

```
                   broadcast
    ┌──────────┐      │         ┌──────────────┐
    │ flasher  │──────┼────────▶│ proxy host   │ ← usually wins the race
    │          │      │         └──────────────┘
    │          │      │         ┌──────────────┐
    │          │──────┴────────▶│ real DME     │ ← also answers
    └──────────┘                └──────────────┘
```

Empirically the proxy usually wins because it can pre-build its reply
in memory and send it the instant a probe arrives (see
`spawn_discovery_responder` — the reply bytes are built once at startup
and the recv-loop does nothing but `send_to`). Still, this topology is
**inherently racy** and should only be used when Setup A is impractical.
If the flasher ends up connecting directly to the real DME, the symptom
is obvious (no proxy session is logged) and the operator must retry.

The reliable version of Setup B is to physically unplug the DME from
the flasher's switch and re-cable it into its own dedicated segment
reachable only from the proxy host — at which point it is just Setup A
with the proxy doing L3 forwarding instead of L2 bridging.

---

## 3. `ProxyConfig` Fields

`ProxyConfig` is defined in `src-tauri/src/proxy/mod.rs` and mirrored in
`src/lib/types.ts`. It is the single source of truth for proxy
behavior during a run.

| Field              | Type              | Meaning                                                                                                                                                                                              |
| ------------------ | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `listen_addr`      | `String`          | TCP bind address for the forwarder, e.g. `0.0.0.0:6801`. Flashers connect here after discovery resolves the proxy's IP.                                                                              |
| `upstream_addr`    | `String`          | `ip:port` of the real DME. A fresh `TcpStream::connect_timeout` is opened per accepted flasher session.                                                                                              |
| `real_vin`         | `Option<String>`  | VIN reported by the real DME. **Populated by the Discover button**, normalized via `normalize_vin`. Displayed read-only in the Detected DME card. Used as the advertised VIN when spoofing is off.   |
| `real_mac`         | `Option<String>`  | 12-hex-char MAC of the real DME. Populated by Discover and sanitized via `sanitize_mac`. Used as the advertised MAC when spoofing is off.                                                            |
| `diag_addr`        | `u8`              | Diagnostic destination byte the flasher writes into each UDS request. Defaults to `0x10` (MEVD17). Populated by Discover, editable because some non-MEVD17 ECUs need a different value.              |
| `spoof_enabled`    | `bool`            | **Master spoof toggle.** When `false` the proxy is a transparent passthrough: discovery advertises the real VIN/MAC and `62 F190` responses are forwarded unmodified.                                |
| `spoof_vin`        | `Option<String>`  | The VIN to advertise in discovery and to substitute into every `62 F190` positive response when `spoof_enabled` is `true`. Blank → fall back to `real_vin`.                                          |
| `spoof_mac`        | `Option<String>`  | The MAC to advertise in discovery when `spoof_enabled` is `true`. Blank → fall back to `real_mac`. Some license checks key off MAC as a secondary identifier.                                        |
| `enable_discovery` | `bool`            | Whether to bind the UDP 6811 responder at all. Defaults to `true`; turning it off is only useful when something else on the host already responds to BMW discovery probes.                           |

The `ProxyConfig::effective_vin()` and `effective_mac()` helpers centralize
the toggle logic:

```
fn effective_vin(&self) -> Option<&str> {
    if self.spoof_enabled {
        self.spoof_vin.as_deref().filter(|s| !s.is_empty())
            .or(self.real_vin.as_deref())
    } else {
        self.real_vin.as_deref()
    }
}
```

Both the discovery responder and the VIN rewriter consult these rather
than reading `spoof_vin` directly, so a single `spoof_enabled = false`
flip reliably puts the whole proxy into passthrough mode.

---

## 4. Two-Way Rewrite and the Early Return

Traffic flows through `forward()`, one call per direction, running in
its own thread. For each HSFZ frame it reads via `read_frame`, the
direction determines whether rewriting is even considered:

```
let (payload, rewritten) = match direction {
    DIR_U2C => maybe_rewrite_vin(&frame.payload, cfg),
    _       => (frame.payload.clone(), false),
};
```

Only upstream-to-client (DME → flasher) frames are candidates. There is
nothing to rewrite in the flasher's request — the flasher is asking for
the VIN, not asserting one — so the C2U path is pure forwarding.

`maybe_rewrite_vin` is defensive. It early-returns the payload
unchanged in any of these conditions, in order:

1. `spoof_enabled == false`. This is the critical guard: regardless of
   whatever is typed in the Spoof VIN field, the proxy does not mutate a
   single byte unless the master toggle is on.
2. `spoof_vin` is `None` or empty.
3. `spoof_vin` is not exactly 17 bytes.
4. The HSFZ payload is shorter than 5 bytes or the SID byte at offset 2
   is not `0x62` (the positive RDBI response SID).
5. A `F1 90` DID marker cannot be located in the body (`find_f190`).
6. The remaining payload from the DID is shorter than 17 bytes.

Only if all six checks pass does the rewriter clone the payload and
overwrite `[vin_start .. vin_start + 17]` with the spoofed VIN bytes.
The rewritten payload is then re-framed via `frame_to_wire` with the
original HSFZ control word and forwarded downstream.

Because the scan walks the whole body looking for the DID marker (not
just the first two bytes after the SID), compound RDBI responses — the
kind flashers send when they query several DIDs in one request — also
get rewritten in place, without disturbing any of the other DID values.

On a successful swap, `stats.rewrites` increments and the emitted
`proxy-frame` event carries `note: Some("VIN rewritten")`, which the
frontend highlights in the live frame list.

---

## 5. Auto-Discovery of the Upstream DME

Before the proxy is started, the operator needs to know (a) the real
DME's IP, (b) its diagnostic address, and — if Transparent mode is being
used — (c) the VIN and MAC to advertise in the discovery reply. Typing
these by hand is tedious and error-prone.

The Discover button in the Detected DME card reuses the existing
`discover_vehicles` Tauri command (the same one the Calibration Read tab uses).
That command broadcasts an HSFZ vehicle-identification probe on UDP
6811, waits briefly, and returns a `DiscoveredDevice[]` array built from
every `DIAGADR<n>BMWMAC<mac>BMWVIN<vin>` reply it received.

The frontend handler `applyDiscovered` then:

1. Sets `upstreamAddr` to `${d.ip}:6801`.
2. Sets `diagAddr` to `d.diag_address`.
3. Populates `realVin` with `d.vin`.
4. Populates `realMac` with `d.mac_address` (stripped of separators
   and uppercased).

Critically, the Discover flow **does not touch `spoofVin` or
`spoofMac`**. This is deliberate and discussed below (§10).

Note that `discover_vehicles` binds UDP 6811 itself, which is the same
port the proxy's own discovery responder uses. The two cannot coexist,
so the Discover button is disabled (and a toast warns the operator)
while the proxy is running. In practice: discover first, then start.

---

## 6. Discovery Responder on UDP 6811

When `proxy_start` is called and `enable_discovery` is `true`,
`spawn_discovery_responder` binds UDP `0.0.0.0:6811` and pre-builds the
reply payload exactly once via `build_discovery_response(&cfg)`:

```
let vin = pad_or_truncate(cfg.effective_vin().unwrap_or("WBA00000000000000"), 17, '0');
let mac = match cfg.effective_mac() { Some(m) if m.len() == 12 => m.into(), _ => "001A3744FFEE".into() };
let text = format!("DIAGADR{}BMWMAC{}BMWVIN{}", cfg.diag_addr, mac, vin);
```

The body is wrapped in the 6-byte HSFZ header: a 4-byte big-endian
length, then the 2-byte control word `0x0004`
(`CONTROL_VEHICLE_IDENT_RESPONSE`), then the ASCII body. The resulting
`Vec<u8>` is captured by move into the responder thread.

The thread itself is pathologically simple:

```
while !stop_flag.load(Ordering::SeqCst) {
    match socket.recv_from(&mut buf) {
        Ok((_, peer)) => { let _ = socket.send_to(&response, peer); }
        Err(_ WouldBlock/TimedOut) => {}
        Err(e) => { log::warn!(...); thread::sleep(...); }
    }
}
```

There is no parsing of the probe. The proxy assumes that any UDP 6811
packet on its wire is a BMW discovery probe and answers immediately with
the prebuilt frame. The `250 ms` read timeout is there so the loop can
check `stop_flag` and return cleanly on shutdown, not because any
packets are ignored.

Because the body was built from `effective_vin()` / `effective_mac()`,
flipping `spoof_enabled` at config time (before start) automatically
changes what the responder advertises. Changing the toggle *while* the
proxy is running does not currently rebuild the prebuilt response — the
operator stops the proxy, flips the toggle, and restarts. This is a
deliberate simplification: the responder's hot loop contains no locks.

---

## 7. Per-Session Capture

Each accepted TCP session allocates its own capture directory:

```
proxy_captures/
  20260408_153012_10.5.0.2_58237/
    meta.json
    timeline.bin
```

`make_session_dir` composes the directory name from the current
timestamp and the flasher's peer (`ip_port` with dots kept, colon
replaced). The directory lives under `proxy_captures_root()`, which
the frontend reads via the `proxy_captures_dir` command and displays
beneath the status line.

### `meta.json`

Written once at session start:

```
SessionMeta {
    start_unix_ms: u64,
    listen_addr:   String,
    upstream_addr: String,
    flasher_peer:  String,
    spoof_vin:     Option<String>,
}
```

This is the only place the absolute wall-clock start time is stored;
everything in `timeline.bin` is a delta from it.

### `timeline.bin`

Append-only binary log, one record per HSFZ frame in either direction.
Record format:

```
[ t_ms          : u64 BE ]   8 bytes — millis since session start
[ direction     : u8     ]   1 byte  — 0 = C2U, 1 = U2C
[ len           : u32 BE ]   4 bytes — frame length
[ bytes         : len    ]           — full HSFZ frame (header + payload)
```

13-byte fixed header plus a variable-length body. Big-endian integers
and a direction tag kept as a plain `u8` constant mean the format is
trivially parseable from any language without pulling in `serde` or
similar.

Every frame that passes `forward()` is appended here, including any
payload that was mutated by the VIN rewriter. `timeline.bin` therefore
reflects what *actually went on the wire*, not the pristine upstream
frame. This is intentional — the primary consumer is the Wireshark
export, and the operator wants Wireshark to show what the flasher saw.

The `scan_timeline_summary` helper used by `proxy_list_sessions` walks
the file once to recompute the total frame and byte counts without
loading the whole thing into memory.

---

## 8. PCAP Export

`proxy_list_sessions` scans `proxy_captures/`, loads each `meta.json` +
`timeline.bin` pair, and returns a `Vec<ProxySession>` ordered by
directory name descending (newest first). The frontend renders these
in the Captured Sessions card; each row has an Export .pcap button.

`proxy_export_pcap(dir_name, dest_path)` does the heavy lifting. For
the requested session it:

1. Loads `meta.json` and parses `flasher_peer` and `upstream_addr`
   into `(ip, port)` via `parse_addr`.
2. Reads the whole `timeline.bin` into memory.
3. Walks the byte stream, decoding fixed 13-byte record headers and
   variable bodies.
4. For each record, builds a `TcpPacket`:
   - Direction `C2U` → `src = flasher`, `dst = dme`.
   - Direction `U2C` → `src = dme`, `dst = flasher`.
   - Two independent `u32` sequence counters (`seq_c2u`, `seq_u2c`)
     are advanced by the payload length. These are synthetic — there
     is no real TCP state — but they make Wireshark's "Follow TCP
     Stream" view coherent and stream reassembly work correctly.
5. Converts `t_ms` to absolute unix millis via
   `meta.start_unix_ms.saturating_add(t_ms)` and pushes
   `(pkt, abs_ms)` into a `Vec`.
6. Calls `write_pcap_timed(&packets)` and writes the resulting bytes
   to `dest_path`.

`write_pcap_timed` (see `src-tauri/src/pcap/writer.rs`) wraps each
`TcpPacket` in a synthetic Ethernet II + IPv4 + TCP header stack. The
Ethernet MACs are locally-administered junk (`02:00:00:00:00:01/02`),
the IPv4 checksum is computed correctly, and TCP flags are fixed at
`PSH | ACK` with the synthetic sequence numbers from the export loop.
Each pcap record header carries `ts_sec` and `ts_usec` derived from
the absolute unix millis, so Wireshark's Time column shows real
wall-clock time instead of monotonic fakes — exactly what you want
when correlating a capture against a physical bench test.

The return value is the number of bytes written, which the frontend
displays in its "Exported X → path" toast.

---

## 9. Shutdown Semantics

Cleanly tearing down a session that might be blocked in a `recv` on
either end requires more than a stop flag. `forward()` is a blocking
loop that calls `read_frame(src)`, which calls `src.read(...)` — and a
blocking socket read ignores `AtomicBool`s. The design in `run_session`
handles this with `TcpStream::shutdown(Shutdown::Both)`.

Each session spawns a sub-thread for the C2U pump (`client → upstream`)
and runs the U2C pump (`upstream → client`) on the current session
thread. Both pumps share a `session_stop: Arc<AtomicBool>` that is
independent from the global listener stop flag — one session ending
must not tear the whole listener down.

When either pump exits (EOF, error, or stop), it:

1. Sets `session_stop` to `true`, so the other pump will bail on its
   next iteration check.
2. Calls `shutdown(Shutdown::Both)` on **both** cloned `TcpStream`
   handles it holds for the peers. This forces any pending `read` on
   the other pump to return immediately with an error
   (`ConnectionReset`, `ConnectionAborted`, `BrokenPipe`, or
   `NotConnected`), which `forward()` treats as a clean exit rather
   than propagating as an error.
3. After the U2C pump returns, the outer `run_session` joins the
   spawned C2U pump so no thread is leaked.

`proxy_stop` drives global shutdown by setting the top-level
`stop_flag`, then joining the listener and discovery threads. The
listener's `accept` loop uses a non-blocking listener with a 100 ms
sleep, so it exits within one sleep cycle.

---

## 10. Frontend UI Structure

`ProxyPanel.svelte` is built around four cards plus a live frame list.
The layout is intentionally sequenced top-to-bottom in the order the
operator actually needs to fill things in:

### Setup banner

A small amber-on-dark panel at the top explains the discovery problem
and the two topology options. It is collapsed by default under a
`<details>` summary.

### Config form

Top row: `Listen Address (TCP)` and `Upstream DME` side by side. The
Upstream field has a Discover button attached to its right edge that
fires `discover_vehicles`. Beneath them is a single `enable_discovery`
checkbox.

### Detected DME card (read-only)

Shows three fields: VIN, MAC, Diag Address. VIN and MAC are rendered
as plain `<div>`s — they are not editable. Only the Diag Address is an
`<input type="number">`, since some non-MEVD17 ECUs need a manual
override. A subtitle indicates whether the card was `auto-filled by
Discover` or is still waiting for a click.

### Identity Spoofing card

A master checkbox (`spoof_enabled`) on top, followed by two inputs
(`spoof_vin`, `spoof_mac`). Both inputs use `disabled={!spoofEnabled}`
in addition to `disabled={status.running}` so that turning the master
toggle off visually greys out the values and prevents accidental edits.

### Active values preview

The key affordance that makes the spoof/passthrough distinction legible
at a glance. Shows the values the proxy will *actually* advertise,
computed via two `$derived` expressions:

```
let activeVin = $derived(
  spoofEnabled
    ? spoofVin.trim() || realVin.trim() || '(none)'
    : realVin.trim() || '(none)',
);
```

These mirror `ProxyConfig::effective_vin` / `effective_mac` on the
backend exactly. The preview card's border turns amber
(`border-color: var(--accent)`) when `spoofEnabled` is on, and a
`SPOOFING ACTIVE` / `TRANSPARENT` pill in the corner reinforces the
state. The displayed VIN/MAC text also turns amber when spoofing is
actively overriding a value. An operator cannot miss that the proxy is
modifying traffic.

### Why Discover populates `realVin`/`realMac` but not `spoofVin`/`spoofMac`

This is the single most important UX rule of the panel. `applyDiscovered`
fills in the real-value fields because those describe what is actually
on the wire — auto-filling them is pure convenience. But it deliberately
leaves the spoof fields alone.

The reason is the primary research use case: a researcher wants the
flasher to see a VIN *other than* the one the real DME reports. Auto-
filling `spoofVin` with `d.vin` would make the spoof identical to the
real value — which looks like spoofing is working, but actually changes
nothing observable. The researcher would then have to remember to edit
the spoof field every single time they discover, which is exactly the
kind of footgun that produces wrong experimental results.

Instead, the spoof fields are the *only* values the panel requires the
operator to type by hand. If they are blank and spoofing is off, the
proxy runs in transparent passthrough. If they are blank and spoofing
is on, `effective_vin()` falls back to the real values and the proxy
*still* runs as passthrough, but with the amber "SPOOFING ACTIVE" pill
on so the operator knows their spoof configuration is incomplete.

### Captured Sessions list

Below the config card, `proxy_list_sessions` results render as rows
showing `flasher_peer → upstream_addr`, the start time, frame count,
byte count, and a small `spoof` chip if the session was captured with
a spoof VIN set. The Export .pcap button on each row calls
`proxy_export_pcap` and pops a native save dialog.

### Live frames

When the proxy is running, `proxy-frame` events are appended to a
capped buffer (`FRAME_LIMIT = 200`) and rendered in a scrollable
monospace list. Direction tag is color-coded; frames rewritten by
the VIN rewriter display a `[VIN rewritten]` note.

---

## 11. Tauri Events

The proxy emits two events on the Tauri `AppHandle`:

- **`proxy-status`** (`ProxyStatusEvent`): a coarse lifecycle stream
  with a `state` of `"listening" | "connected" | "disconnected" |
  "stopped" | "error"` and a human-readable `detail`. Emitted when the
  listener binds, when a flasher accepts, when a session ends, and on
  any error. The frontend uses the `disconnected` transition as the
  cue to refresh the captured-sessions list from disk, since a session
  ending is the moment a new directory appears under `proxy_captures/`.

- **`proxy-frame`** (`ProxyFrameEvent`): one event per HSFZ frame
  forwarded in either direction. Fields: `direction` (`"C2U" | "U2C"`),
  `control` (the HSFZ control word), `bytes_hex` (the full frame hex,
  truncated to 48 bytes with a `(+N bytes)` suffix for long frames so
  a 4 KiB TransferData block does not flood the UI), and an optional
  `note` that is set to `"VIN rewritten"` when the rewriter altered
  the payload. The on-disk `timeline.bin` always has the complete
  bytes; truncation is a UI concern only.

In addition to events, the frontend polls `proxy_status` once per
second while the proxy is running to keep the running totals
(`bytes_c2u`, `bytes_u2c`, `frames`, `rewrites`, `sessions`) fresh
without needing a high-frequency event for every byte counter tick.

---

## 12. Research Use Cases

### VIN-binding analysis

Turn on spoofing with a deliberately wrong VIN and observe where the
flasher first objects. Some tools check at discovery, some at the
first `22 F190`, some only on specific sub-routines, and some only
at commit time. By moving the spoof point around (discovery-only,
F190-only, or both) the researcher can map each check to its exact
UDS transaction.

### Session hijacking / replay research

A captured session provides a ground-truth record of every byte in
the conversation. Because `timeline.bin` uses monotonic deltas from
a single `meta.start_unix_ms`, two sessions recorded against different
DMEs can be precisely aligned and diffed to identify which responses
depend on vehicle state and which are static.

### Protocol fuzzing

The proxy can be extended to mutate more than just the VIN — any
`forward()` rewrite targeting any UDS service can be dropped in right
next to `maybe_rewrite_vin`. Because the rewriter operates on fully
decoded HSFZ frames and re-frames with `frame_to_wire`, it does not
have to worry about length fields or control words; it simply edits
the payload. This makes it straightforward to flip bits in seed/key
exchanges, mangle transfer-data blocks, or inject NRCs to probe error
handling.

### Flasher behavior fingerprinting

A passthrough capture (`spoof_enabled = false`) taken under controlled
conditions produces a canonical transcript of what a given flasher
does against a given DME. Captures from different tool versions or
different DME hardware can then be compared to identify version-
specific behaviors, fallback paths, or feature detection sequences —
all without touching the flasher's own code.

---

## Summary

The DME Proxy is a small, focused MITM: it binds UDP 6811 for discovery
and TCP 6801 for HSFZ forwarding, optionally rewrites VIN fields in
both the discovery reply and `62 F190` responses based on a single
master toggle, and records every frame to disk with precise timing for
later analysis or Wireshark export. The UX is built around making the
spoof state impossible to misread and the capture-to-pcap pipeline
frictionless, because both properties matter more during live research
than any amount of configurability would.
