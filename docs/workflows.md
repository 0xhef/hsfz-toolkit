# BMSecResearch — Field Workflows

This document is a practical, operator-focused playbook for the five tabs
exposed by the application:

    01  EXTRACT FROM PCAP   — recover .bin from a flash trace
    02  CAPTURE FLASH       — sniff a live flash session
    03  CALIBRATION READ    — read calibration over ENET
    04  DME SIMULATOR       — spoof a DME for tools
    05  DME PROXY           — MITM real DME <-> flasher

Every workflow below is grounded in commands that actually exist in the
Tauri backend (`simulator_*`, `proxy_*`, the pcap reassembly pipeline
under `src-tauri/src/pcap/`, and the capture/calibration-read panels).
If a step references a button, it's a button that exists in the
current UI.

A hard rule throughout: only run these flows against vehicles and
hardware you own, or that you have written permission to test. The
header footer says the same thing for a reason.

Terminology used in this document:

- `flasher A`, `flasher B`, `flasher under test` — any third-party
  BMW tuning / diagnostic application that speaks HSFZ on TCP 6801.
- `DME` — the engine control module on the test bench or in the car.
- `captures dir` — the platform-appropriate app data directory; the
  exact absolute path is printed in the Simulator and Proxy panels
  ("Captures:" line). Files land in subdirectories named
  `YYYYMMDD_HHMMSS_VIN`.

---

## Workflow 1 — Offline pcap to flash extraction

### Goal

Given a pcap that someone captured during a flash (yours or another
researcher's), recover the raw flash binary(s) that the flasher wrote
to the DME. You want the `.bin` on disk so you can:

- run `strings` / `binwalk` / entropy plots,
- verify published checksums against real content,
- diff two calibrations (stock vs modified) byte-for-byte,
- feed it into downstream map-identification tooling.

### Prerequisites

- A `.pcap` or `.pcapng` file containing the full flash session.
  Partial captures lose the header and extraction will fail at the
  reassembly stage — make sure the capture started before the
  flasher's `10 02` DiagSession handshake and ended after
  `37` RequestTransferExit for the final segment.
- No hardware needed. This is a pure offline workflow.

### Steps

1. Open the app. Click tab `01 EXTRACT FROM PCAP`.
2. Drop the pcap onto the drop zone, or use the file picker.
3. Wait for the parser to finish. The backend pipeline is:
   - `pcap::reader` parses the link-layer records,
   - `pcap::tcp_reassembly` stitches TCP 6801 streams per flow,
   - the HSFZ layer peels off the transport header,
   - the UDS layer recognizes `34 / 36 / 37` and accumulates
     `TransferData` payloads under each `RequestDownload` address.
4. The Load panel lists each recovered download as a row: start
   address, size, block count, and a status chip (complete / gap /
   truncated).
5. For each row you care about, click `Save .bin`. Choose a
   destination. The backend writes the concatenated payload with
   `0xFF` padding across any gaps (same convention as
   `simulator_export_flash_bin`).
6. Optional: click `Save All` to dump every recovered segment as
   sibling `.bin` files under one folder.

### Expected output

- One `.bin` per `RequestDownload` the flasher issued. For a
  calibration-only flash on a MEVD17 that's typically one file at the
  cal base address; for a full flash it may be two or three (BTLD,
  program, cal).
- File size matches `max_address - min_address` rounded to the
  transfer block size.

### Analysis tips

- `strings -n 8 calibration.bin | grep -i -E 'bmw|mevd|cafd|swfl'`
  pulls version markers.
- The BMW checksum words live near fixed offsets at the end of each
  logical region. Open the file in a hex editor at
  `size - 0x40` and look for the ASCII tag blocks.
- To diff two cal images of the same part number:
  `cmp -l old.bin new.bin | wc -l` for a rough change count, then
  `vbindiff` or `radiff2 -x` for byte ranges.
- If the extracted size is suspiciously round (exactly 0x80000,
  0x100000), but the flasher was flashing a stock-sized image, you
  may be looking at a zero-padded buffer — check the gap report in
  the Load panel.

### Gotchas

- `.pcapng` with multiple interfaces: the reassembler handles it,
  but if two interfaces saw the same TCP flow you may see duplicate
  rows. Pick the one with the higher byte count.
- Truncated captures: if the pcap stops mid-`TransferData`, the row
  will show `gap` status and extraction will pad the missing
  tail with `0xFF`. Treat the tail as untrusted.
- VPN / tunnel captures: if the flasher was going through a VPN the
  outer frames won't reassemble. Capture on the inside of the
  tunnel.
- HSFZ uses control word `0x0001` for UDS frames and `0x0011` for
  ack; the extractor ignores acks, but a malformed capture with
  reordered segments before retransmit can produce duplicate bytes.
  The Load panel flags this as `overlap`.

---

## Workflow 2 — Live capture to flash extraction

### Goal

Sniff a live flash session from a flasher under test against a real
DME (or the built-in simulator) on a lab NIC, and produce a `.bin`
in real time — no separate Wireshark step, no round-trip through a
file.

### Prerequisites

- Lab NIC that can see both sides of the flash traffic. Two common
  topologies:
  - SPAN / mirror port on a managed switch between flasher and DME,
  - Cheap USB-Ethernet tap in line with the DME.
- Administrator / root privileges to open the NIC in promiscuous
  mode (the app prompts on first run).
- Know the interface name in advance (the Capture panel lists them,
  but picking the wrong one is the number one cause of "nothing is
  happening").

### Steps

1. Click tab `02 CAPTURE FLASH`.
2. Pick the NIC from the interface dropdown. If the list is empty,
   you don't have capture privileges — restart the app elevated.
3. (Optional) Narrow the BPF filter to `tcp port 6801` to drop
   background noise on a busy lab segment.
4. Click `Start Capture`. The status strip goes green.
5. On the flasher host, kick off the flash as normal.
6. Watch the live counters: bytes per second, recovered segments,
   UDS service histogram. A healthy session shows the counters
   climbing monotonically and the segment row appearing as soon as
   the flasher finishes the first `RequestDownload`.
7. When the flasher reports success, click `Stop Capture`.
8. The Load panel (tab 01) auto-populates with the captured rows.
   Export as in Workflow 1.
9. Optional: click `Save pcap` on the Capture panel to keep the raw
   trace alongside the `.bin` for later re-analysis.

### Expected output

- Live `.bin` file(s) as soon as the flasher's final
  `RequestTransferExit` comes in.
- Optional `.pcap` side-car if you saved the raw trace.
- On-screen histogram of UDS services seen (useful for Workflow 5).

### Analysis tips

- Keep both outputs. The pcap is your ground truth; the `.bin` is
  your analysis target.
- If you're looking at a flasher you don't trust, start capture
  first, flash second, stop third. Any network activity before
  `10 02` is out-of-band telemetry worth looking at — filter the
  pcap for non-6801 destinations.

### Gotchas

- WSL2 cannot see the Windows NIC. Run the app natively on whichever
  side of the bridge has the traffic.
- Many USB-Ethernet adapters do not honour promiscuous mode even
  when the driver claims to. If the segment counter stays at zero
  during a known-good flash, swap to a wired PCIe NIC before
  debugging anything else.
- Autonegotiation mismatches on half-duplex SPAN ports silently drop
  frames, which manifests as `gap` rows in extraction. Force the
  SPAN to the DME's link speed.

---

## Workflow 3 — Read-only calibration read

### Goal

Back up the calibration region of a real MEVD17 DME over ENET
without taking SecurityAccess, without writing anything to flash,
and without any flasher software involved. Useful before any
invasive test so you have a known-good reference.

### Prerequisites

- BMW ENET cable plugged into the OBD port.
- Vehicle in ignition-on / engine-off (KL15 on) so the DME stays
  awake.
- Laptop NIC on the same subnet as the DME (typically `169.254.x.x`
  if the cable's DHCP responder is working, otherwise static).
- Nothing else on the network talking to UDP 6811 — a second
  discovery responder will race you.

### Steps

1. Click tab `03 CALIBRATION READ`.
2. Click `Discover`. The backend broadcasts the ENET
   vehicle-identification probe on UDP 6811 (same machinery reused
   by the Proxy panel via `discover_vehicles`).
3. The device list populates with one row per ECU that answered:
   IP, diag address, MAC, VIN. For a single-DME backup you will
   usually see exactly one row with diag address `0x10` (the MEVD17
   default — the panel explicitly documents this).
4. Select the DME row. The detail view fills in.
5. Choose output format:
   - `Raw` — exactly the bytes the DME returned, with the gap map
     preserved. Use this when you want forensic fidelity.
   - `4 MB Padded` — normalised 4 MiB image with gaps filled
     `0xFF`. Use this when you want to diff against a flash dump
     or feed an image into downstream tools that expect a fixed
     size.
6. Click `Back Up`. Progress ticks via the same event channel the
   simulator clone flow uses.
7. When the counter hits 100%, click `Save .bin` and pick a
   destination. The file name defaults to
   `<VIN>_<YYYYMMDD_HHMMSS>_backup.bin`.

### Expected output

- A single `.bin` on disk — 4 MiB if you picked padded, somewhere
  between 2 and 4 MiB if you picked raw.
- A side-car JSON with the DID fingerprint: VIN, hardware number,
  SWFL/BTLD/CAFD, flash counter, CVN. This is the same shape the
  simulator's `simulator_get_dme_identifiers` command returns and
  is the raw material for Workflow 4.

### Analysis tips

- Before anything else, run `sha256sum` on the backup and paste the
  digest into your lab notebook. Re-backup later to confirm nothing
  on the DME moved.
- Compare the backup's CVN field against the value the cluster
  reports via instrument-cluster diagnostics. A mismatch means the
  flash counter got bumped since the last cluster sync.
- Grep the raw backup for the 17-byte VIN ASCII string; it should
  appear exactly where the `F190` DID says it is.

### Gotchas

- This is a read-only flow — no SecurityAccess, no `27 XX`, no
  `34 / 36 / 37`. If you see the DME go to bus-off during backup,
  the problem is almost certainly on your cable, not the protocol.
- Some aftermarket ECU swaps respond with diag address `0x12`
  instead of `0x10`. The panel lets you override manually.
- Running the Calibration Read tab while the Proxy is listening on the same
  host will fail: both want UDP 6811. Stop the proxy first (the
  Proxy panel is explicit about this — it refuses to start
  discovery while the proxy is running).
- If you forget to enable ignition, the DME drops off the network
  between discovery and the first UDS request. You'll see
  `Discover` succeed and the backup fail a few seconds in.

---

## Workflow 4 — Cloning a real DME into the simulator

### Goal

Capture a real car's responses well enough that a flasher cannot
distinguish the simulator from the genuine DME. Use this to build a
reproducible bench target for every subsequent workflow — no more
burning real flash cycles on the car.

### Prerequisites

- Workflow 3 completed so you have a fresh backup of the target
  car, OR a pcap containing the target car's discovery + UDS
  responses (Workflow 1 material).
- Bench / lab machine where you can run the simulator on TCP 6801.
  This often needs to be a separate host from the flasher, because
  most flashers hard-code destination port 6801 and broadcast on
  6811.

### Steps — cloning via live DME

1. Click tab `04 DME SIMULATOR`.
2. Click `Clone From Car`. The UI asks for IP and ECU address
   (0x12 or 0x13; the backend rejects anything else in
   `simulator_clone_from_car`).
3. Provide a name for the new profile — `A-Za-z0-9_-`, up to 64
   chars (the backend's `sanitize_profile_name` is strict).
4. The backend walks the DID fingerprint set, reads each one off
   the real DME, and builds an `EcuProfile` in memory. Progress
   events stream to the UI.
5. When the preview lands, review: VIN, HWEL, BTLD, SWFL, CAFD,
   flash counter, CVN. These are the values a flasher will read
   back during its pre-flash handshake.
6. Click `Save Profile`. The profile is persisted as
   `<name>.json` under the profiles directory.

### Steps — cloning via pcap / backup import

1. Run Workflow 1 or 3 first to produce a pcap and/or a backup.
2. On the Simulator panel, create an empty profile: `New Profile`,
   pick a name, pick an ECU address (0x12 or 0x13), enter the VIN
   you want the profile stamped with. The backend validates the
   VIN is 17 chars and free of `I`, `O`, `Q`.
3. Use `Edit Identifiers` to paste the HWEL / BTLD / SWFL / CAFD /
   serial / flash counter values from the backup's side-car JSON
   into the form.
4. If you have an NCD coding backup for the target car, click
   `Import NCD Backup` and point at the JSON. The backend merges
   the coded DIDs into the profile via
   `simulator_import_ncd_backup`.

### Bringing the profile online

1. Select the profile from the dropdown at the top of the
   Simulator panel.
2. Set `Bind Address` — usually `0.0.0.0:6801` so the flasher's
   discovery reply is routable.
3. Click `Start Simulator`. Status goes to `listening`.
4. On the flasher host, kick off a normal pre-flash
   identification. You should see:
   - the discovery responder answer with the profile's VIN/MAC,
   - the flasher open a TCP 6801 connection,
   - the transcript stream fill with `10 / 22 / 27 / 3E` frames,
   - no `segments` yet (no download has started).

### Verifying the clone

- Have the flasher read out identification. The values it shows
  must match what you put into the profile. Any mismatch is a
  copy-paste error in the identifier editor.
- Run a dry-run flash with a known-good file. The simulator will
  happily accept the whole `RequestDownload` / `TransferData`
  sequence and drop every `seg_*.bin` into a new
  `YYYYMMDD_HHMMSS_VIN` folder under the captures directory.
- Open the `Captured Flashes` section at the bottom of the
  Simulator panel. The new session appears at the top of the
  list. Click `Export .bin` and verify you can re-open the file
  in tab 01.

### Expected output

- `<name>.json` in the profiles directory.
- A capture session directory per flash attempt under the
  captures directory (path printed as `Captures:` on the panel).
- `seg_<ADDR_HEX>_<SIZE>_bytes.bin` files per segment, which the
  Simulator panel can concatenate into one `.bin` via
  `simulator_export_flash_bin`.

### Analysis tips

- After the first successful clone, freeze the profile JSON into
  your lab's version control. Every subsequent workflow becomes
  reproducible.
- Diff the flash the flasher wrote to the simulator against the
  backup from Workflow 3. For a read-only flasher handshake they
  should match; a discrepancy is either encryption, compression,
  or a telemetry marker injected mid-stream.

### Gotchas

- Profiles are per-ECU-address. A profile created for 0x12 won't
  load on a 0x13 listener and vice versa.
- Editing a profile while the simulator is running is blocked by
  the backend (`Stop the simulator before editing the profile`).
  The UI disables the editor, but the backend enforces it too.
- The simulator bypasses SecurityAccess — any seed/key sequence
  the flasher sends is accepted. That's the whole point for
  research, but it means you cannot use the simulator to study
  seed/key algorithms. Use Workflow 6 for that.
- The built-in profile is a last-resort convenience. Prefer a
  cloned profile for any serious work; the built-in DIDs have a
  synthetic VIN and will not match any real car.

---

## Workflow 5 — Flasher fingerprinting with the simulator

### Goal

Build a behavioural profile of each flasher under test: which DIDs
it reads, which routines it calls, how often it sends
TesterPresent, whether it checks SecurityAccess, whether it
verifies checksums, and — critically — what bytes it actually
writes to the flash region.

### Prerequisites

- A cloned profile from Workflow 4 that closely matches the car
  the flasher expects. A flasher that bails out at the
  identification stage produces no signal.
- Two or more flashers to compare, ideally on matched versions.

### Steps

1. Start the simulator with the cloned profile (Workflow 4).
2. Clear any stale captures: either delete old session folders
   under the captures directory, or just note the current
   timestamp so you can find today's runs.
3. Run `flasher A` against the simulator. Go through its full
   workflow: identification, pre-checks, flash, verification,
   post-checks.
4. Stop the simulator. The `disconnected` event triggers a
   refresh of the `Captured Flashes` list.
5. Repeat with `flasher B`, `flasher under test`, etc. Each
   session lands in its own `YYYYMMDD_HHMMSS_VIN` folder.
6. Export each session's concatenated `.bin` via the panel's
   `Export .bin` button (wraps `simulator_export_flash_bin`).
7. Grep the transcript files in each session folder for what
   matters to you (see analysis tips).

### Expected output

- One session folder per flasher.
- `seg_*.bin` files capturing every byte each flasher wrote.
- Transcript log per session — the raw UDS frames, timestamped.

### Analysis tips

- DID inventory: grep the transcript for `22 ` followed by the
  two-byte identifier. A flasher that only reads `F18C / F190`
  is lazy; one that pulls `F1A2 / F1A5 / F187 / F18B / F197`
  before touching flash is serious.
- Routine inventory: grep for `31 01` (StartRoutine). Common
  ones to classify: `FF00` (pre-programming condition check),
  `0203` (erase memory), `0202` (check memory / checksum),
  `FF01` (post-programming).
- TesterPresent cadence: grep for `3E 80` and histogram the
  inter-frame deltas from the transcript timestamps. Most
  flashers settle at 2s; anything much tighter or looser is a
  fingerprint.
- SecurityAccess behaviour: grep for `27 `. The simulator will
  happily answer every seed request with a fixed seed and
  accept any key. If a flasher retries with multiple seeds
  (implying it checks the seed value itself) that's a
  fingerprint.
- Checksum verification: after the flash, does the flasher
  issue a `22` on a checksum DID, or a `31 01 02 02` routine?
  If neither, it trusts whatever it wrote — a meaningful
  finding.
- Write-content diff: `cmp -l flasherA.bin flasherB.bin`. Two
  flashers nominally writing the same stock image should
  produce byte-identical output. Any difference is either a
  watermark, a per-flasher encryption layer, or a bug.

### Gotchas

- Do not change the profile between flasher runs — identifier
  changes will invalidate comparisons. The backend blocks
  editing while the simulator is running, but it's still easy
  to stop the simulator, edit, restart, and forget.
- Some flashers cache identification per VIN across runs. To
  force them to re-probe, either wipe their cache or use a
  different profile VIN per run.
- `seg_*.bin` filenames embed the segment base address. If you
  see wildly different base addresses between flashers, they
  are not flashing the same region — do not diff them as if
  they were.

---

## Workflow 6 — MITM proxy for VIN-binding research

### Goal

Sit between a real flasher and a real DME, spoof the VIN (and
optionally MAC) the flasher sees, and study how the flasher binds
its session to the VIN. Questions you can answer:

- Does the flasher check the VIN once at start, or repeatedly?
- If the VIN changes mid-session, does the flasher abort?
- Does the flasher sign flash data against the VIN?
- Does it phone home with the VIN before allowing the flash?

### Prerequisites

- Real DME on the bench, powered and on the network.
- Two NICs on the proxy host (recommended — see Setup A in the
  Proxy panel's help text). NIC one faces the flasher; NIC two
  faces the DME. With only one NIC you race the real DME for
  the discovery reply, which is unreliable.
- Nothing else on the flasher's segment should answer UDP 6811.

### Steps

1. Click tab `05 DME PROXY`.
2. Leave `Listen Address` as `0.0.0.0:6801`.
3. Click `Discover`. This reuses the Backup panel's
   `discover_vehicles` command. The first DME that answers
   pre-fills the upstream address, diag address, real VIN, and
   real MAC. The real VIN/MAC fields are read-only; the spoof
   fields stay empty on purpose so autofill cannot
   accidentally defeat the licence-bypass use case.
4. (If you have multiple DMEs.) Pick the correct one from the
   discovered list.
5. Tick `Enable identity spoofing`.
6. Enter a `Spoof VIN` — 17 chars, BMW VIN alphabet. Leave
   `Spoof MAC` blank unless you specifically want to test MAC
   binding.
7. Confirm the `What the flasher will see` preview shows
   `SPOOFING ACTIVE` in the accent colour and your spoof VIN in
   the VIN field.
8. Leave `Run UDP discovery responder on port 6811` ticked —
   required for BMW flashers, which all broadcast-discover.
9. Click `Start Proxy`. Status strip shows `listening`.
10. On the flasher host, kick off the flasher. Watch the live
    frame feed at the bottom of the panel. `C2U` frames are
    flasher-to-DME, `U2C` are DME-to-flasher. Rewritten frames
    are flagged in the `note` column (`vin-rewrite` for `62 F190`
    rewrites, `discovery-rewrite` for the UDP 6811 reply).
11. Let the session run to whatever stage you're studying —
    identification, pre-check, partial flash, full flash.
12. Click `Stop Proxy`. The session is persisted under the
    proxy captures directory (`Captures:` line on the panel).
13. Click `Export .pcap` to dump a Wireshark-loadable file.

### Expected output

- A timestamped proxy session directory with the full
  transcript, byte counts, frame count, and spoof metadata
  (`spoof_vin` shows in the session list if you enabled it).
- One exported `.pcap` per session you care about. These are
  real pcaps with wall-clock timestamps — suitable for
  feeding back into tab 01 or Workflow 1 after the fact.

### Research variations

- Mid-session VIN swap: stop the proxy, edit the spoof VIN,
  restart. Does the flasher abort, or does it only re-check on
  reconnect?
- VIN mismatch at telemetry time: run a full flash with VIN
  `A` spoofed, then start a second flasher session with VIN
  `B`. Does the flasher's vendor backend notice the mismatch?
- Selective rewrite: spoof the MAC but leave the VIN alone,
  and vice versa. Figure out which field the flasher licence
  binds to.

### Analysis tips

- Frame histogram by `control`: `0x0001` is UDS data,
  `0x0011` is HSFZ ack. The proxy counts both — a spike in
  `0x0011` without matching `0x0001` is a flasher that's
  keep-aliving but not talking.
- Rewrites counter on the status line is gold: it increments
  every time the proxy patched a `62 F190` response or the
  discovery reply. If you spoofed but the counter stays at 0,
  the flasher isn't asking for VIN — revisit your spoof
  strategy.
- For VIN-bound flashers that phone home, watch your host's
  egress firewall during the session. Anything leaving the
  proxy host that isn't TCP 6801 or UDP 6811 is worth
  investigating.

### Gotchas

- The Discover button refuses to run while the proxy is up,
  because both want UDP 6811. This is enforced in the UI and
  on the backend.
- Single-NIC topology is explicitly documented as a race in
  the Proxy panel's help text. Do not trust any VIN-binding
  result obtained from a single-NIC setup — the flasher may
  have been talking to the real DME on half the frames.
- Some flashers cache the DME's MAC across runs and get
  suspicious if it changes. If you're iterating on spoofs,
  clear the flasher's cache between runs or keep the MAC
  pinned.
- VIN length and alphabet are enforced client-side (17 chars,
  no I/O/Q). The backend's VIN validator is the same.

---

## Workflow 7 — Transfer-rate telemetry evasion research

### Goal

Real flashes are slow — a full MEVD17 calibration flash takes
minutes, not seconds, because each `TransferData` block is
rate-limited by the DME itself. The simulator, by default, is
as fast as TCP allows. If a flasher's backend looks at elapsed
wall time to flag implausibly fast flashes, the simulator is a
giveaway. The profile's `transfer_rate_kbps` field exists to
throttle the simulator to a realistic rate so you can study
this.

### Goal — specifically

- Measure what rate each flasher considers "normal".
- Measure what rate triggers a warning or refusal.
- Measure whether the flasher phones home with the elapsed
  time after a flash.

### Prerequisites

- A cloned profile from Workflow 4.
- Workflow 5 baseline runs at the default (unthrottled) rate
  for comparison.

### Steps

1. Click tab `04 DME SIMULATOR`.
2. Select the profile.
3. Locate the `Transfer rate (kB/s)` input. Set a realistic
   value — 30 to 100 kB/s is typical for MEVD17 over ENET.
4. Click `Save` next to the field. The backend rewrites the
   profile JSON with `transfer_rate_kbps` set (the UI calls
   `simulator_save_profile` with the updated profile). A toast
   confirms `Throttle set to N kB/s`.
5. Start the simulator.
6. Run the flasher under test through a full flash.
7. Stop the simulator.
8. Repeat at different rates — 10, 30, 60, 100, and
   unthrottled (`null`).
9. For each run, record: total wall-clock duration, whether
   the flasher completed, any warnings, whether it reported
   the rate in its log.

### Expected output

- One capture session per rate, all under the same profile.
- A table of `rate -> duration -> outcome` that is the main
  deliverable of this workflow.

### Analysis tips

- Most flashers show progress bars based on total bytes, not
  elapsed time. If the progress bar stops matching the byte
  counter, the flasher is doing its own rate sanity check.
- A flasher that finishes a full flash in under 10 seconds is
  almost certainly against the simulator at default rate.
  Anything that refuses to run below some threshold is also a
  fingerprint.
- Cross-reference with Workflow 5 transcripts: look for
  `22` reads of battery voltage or ignition status during the
  flash. Those are the DIDs a cautious flasher uses to verify
  the environment is real.
- To disable the throttle, set the field blank (or 0) and save
  again. The UI falls back to `null` in the profile JSON.

### Gotchas

- `transfer_rate_kbps` is in kilobytes per second, not
  kilobits. 100 kB/s is 800 kbit/s.
- Throttling is applied per `TransferData` block, not as a
  smooth rate. Very low rates (< 5 kB/s) interact badly with
  some flashers' `P2*` session timers — they'll time out
  before the block lands. That's itself a finding, but expect
  it and don't diagnose it as a bug.
- Saving the profile while the simulator is running is blocked
  by the backend. Stop, save, restart.

---

## Workflow 8 — Protocol fuzzing via the simulator

### Goal

Study flasher error handling by deliberately returning malformed,
truncated, delayed, or policy-violating UDS responses from the
simulator. Questions you can answer:

- Does the flasher crash, hang, retry, or gracefully abort on
  a malformed NRC?
- Does it handle a truncated positive response?
- Does it respect session timeouts correctly?
- Does it log anything unusual to its telemetry backend?

### Prerequisites

- A cloned profile from Workflow 4 — so the flasher gets far
  enough to start exercising the services you want to fuzz.
- Willingness to edit the profile JSON directly, and/or to run
  a patched build of the simulator. The UI does not (as of
  this writing) expose per-response byte mutation — that's
  intentional, because you don't want accidental malformed
  responses leaking into serious research. For fuzzing you
  drop down to the JSON.

### Steps — response-content fuzzing

1. Stop the simulator.
2. Open the profile JSON file under the profiles directory.
   It's human-readable; each DID maps a request to a canned
   response byte array.
3. Mutate a target response. Examples worth starting with:
   - truncate a `62 F190` VIN response to 16 bytes instead of
     17 + the 3-byte UDS header,
   - replace a positive response with a negative
     `7F <service> <nrc>` where the NRC is reserved
     (e.g. `0xAA`),
   - return a response for the wrong DID (`62 F19X` when the
     flasher asked for `F190`),
   - emit a 2-byte garbage payload for a RoutineControl
     positive response.
4. Save the JSON. Verify it still parses — a load failure is
   logged and will stop the simulator from starting. If so,
   restore from the backup you took before editing.
5. Start the simulator.
6. Run the flasher under test. Watch the live transcript and
   note exactly what the flasher does — retry count, error
   code shown to the user, whether it proceeds to the next
   service or aborts.
7. Save the capture session folder — it pairs the malformed
   response with the flasher's exact behaviour.

### Steps — timing fuzzing

1. Use `transfer_rate_kbps` (Workflow 7) at extreme values:
   1 kB/s to deliberately blow past the flasher's
   `P2*Ext` timer.
2. Alternatively, stop and restart the simulator mid-flash to
   force a socket reset. Some flashers reconnect silently;
   others abort with an unrecoverable error.

### Steps — service-policy fuzzing

1. Normally the simulator bypasses SecurityAccess. For this
   workflow, hand-edit the profile so the `27` service
   returns an NRC (e.g. `33 securityAccessDenied`)
   unconditionally.
2. Start the simulator and run the flasher.
3. Record whether the flasher retries with a different
   algorithm, falls back to a lower session level, or
   abandons the flash.

### Expected output

- One capture session per mutation.
- A notebook entry per test case:
  `mutation -> flasher behaviour -> severity`.
- The mutated profile JSON itself, preserved alongside the
  capture, so the test case is reproducible.

### Analysis tips

- Correlate mutations with the flasher's user-facing error
  strings. Good flashers translate NRCs; bad ones print raw
  bytes; ugly ones crash.
- Compare the transcript before and after a mutation to see
  where the flasher gave up. A flasher that retries the
  failed request three times then moves on is more robust
  than one that dies on the first failure.
- If a flasher crashes on a specific mutation, that mutation
  is interesting for more than just robustness — it's a
  potential input-validation bug. Escalate it via your
  normal vulnerability disclosure process. Do not publish
  until the vendor has had a chance to fix it.

### Gotchas

- Keep an untouched copy of every profile you fuzz. The JSON
  is the single source of truth for the simulator, and there
  is no "undo" button.
- Profile-name sanitisation is strict: do not rename a
  mutated profile with slashes, dots, or spaces. The backend
  will reject it at load time.
- Fuzzing interacts badly with real DMEs. Never run a fuzzed
  simulator on the same segment as a real DME that a flasher
  might accidentally reach — you risk the flasher sending
  half-fuzzed, half-real traffic and corrupting a real
  calibration. Airgap the lab segment.
- If you find yourself hand-editing more than a handful of
  profiles, you're past the point this workflow targets —
  consider writing a small script that drives the profile
  JSONs directly and runs the simulator headless.

---

## Cross-workflow reference

### Captures directory layout

Both the simulator and the proxy write captures under an
app-data directory that each panel prints as `Captures:`.
The naming convention is `YYYYMMDD_HHMMSS_VIN` for simulator
flash sessions and an analogous timestamped name for proxy
sessions. Inside a simulator flash session you will find one
`seg_<ADDR_HEX>_<SIZE>_bytes.bin` per `RequestDownload`, plus
a transcript log. The backend's `simulator_export_flash_bin`
is the canonical way to concatenate those segments into one
`.bin` with `0xFF` padding across gaps, capped at 64 MiB for
safety.

### Profile directory layout

Simulator profiles live in a sibling directory. File names
are `<sanitized-name>.json` where the sanitizer allows only
`[A-Za-z0-9_-]{1,64}`. The backend refuses to load or save
anything outside that alphabet and double-checks the
canonicalised path stays inside the profiles directory —
so attempts to use `../../etc/passwd` as a profile name are
defeated in two independent places.

### Command cheat sheet

Frontend (Svelte) commands you will see invoked in the panels:

- `simulator_start`, `simulator_stop`, `simulator_status`
- `simulator_list_profiles`, `simulator_get_profile`,
  `simulator_save_profile`, `simulator_delete_profile`,
  `simulator_create_empty_profile`
- `simulator_get_dme_identifiers`,
  `simulator_set_dme_identifiers`,
  `simulator_import_ncd_backup`,
  `simulator_sample_ncd_backup`
- `simulator_clone_from_car`
- `simulator_list_flash_sessions`,
  `simulator_list_segments`, `simulator_export_flash_bin`,
  `simulator_captures_dir`
- `proxy_start`, `proxy_stop`, `proxy_status`,
  `proxy_captures_dir`, `proxy_list_sessions`,
  `proxy_export_pcap`
- `discover_vehicles` (shared by the Backup and Proxy tabs)

### Event channels

Live UI updates come in over Tauri event channels:

- `simulator-status` — state transitions (`listening`,
  `connected`, `disconnected`, `stopped`)
- `simulator-transcript` — per-frame UDS log, rate-limited to
  the last N frames in the UI
- `simulator-segment` — one event per flash segment committed
  to disk
- `simulator-clone-progress` — clone-from-car progress
- `proxy-status` — proxy state transitions
- `proxy-frame` — per-frame live feed (last 200 frames)

Use these to drive any scripted instrumentation you layer on
top of the UI.

---

## Safety and scope reminder

Every workflow above assumes a lab environment, a vehicle you
own, or explicit written permission. The tools are intentionally
strict about a few things:

- profile names are sanitized and path-confined,
- session directories are sanitized and path-confined,
- bind addresses must be literal `SocketAddr` values (no DNS),
- `simulator_clone_from_car` only accepts ECU addresses
  `0x12` and `0x13`,
- editing or deleting a profile while the simulator is running
  is refused by the backend,
- running discovery while the proxy is bound to UDP 6811 is
  refused.

Those are safety rails, not speed bumps. They exist so a
malformed IPC payload can't traverse the filesystem, burn the
wrong ECU address, or pull a profile out from under an active
flash session. Do not work around them — if you hit one, step
back and check your plan.
