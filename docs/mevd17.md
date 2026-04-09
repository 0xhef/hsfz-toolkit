# Bosch MEVD17 DME — Technical Reference

A security-researcher's reference for the Bosch Motronic 17.x DME
family as deployed on BMW vehicles (approximately 2008–2018). Covers
memory map, flash process, DID taxonomy, identification routines, and
dump analysis.

> [!IMPORTANT]
> This document describes the **protocol and memory layout**, not the
> security-access cryptography. Seed/key algorithms are out of scope
> and the tool in this repository intentionally does not implement
> them (see §7).

---

## 1. MEVD17 at a glance

| Property              | Value                                             |
|-----------------------|---------------------------------------------------|
| Vendor                | Robert Bosch GmbH                                 |
| Family                | Motronic 17 (petrol) / EDC17 (diesel)             |
| Variants observed     | MEVD17.2.0 / .2.2 / .2.6 / .2.8 / .2.9 / .2.H     |
| Engines (examples)    | B38, N13, N20, N26, N55, S55, N63, S63            |
| Transport             | ENET (HSFZ over TCP) or K-line (older generations)|
| Diagnostic address    | `0x12` (DME), `0x13` (DME2 on dual-DME N63/S63)   |
| Protocol              | UDS (ISO 14229) over HSFZ (`docs/hsfz-protocol.md`)|
| Core architecture     | Infineon TriCore (TC1797 / TC1782 / similar)      |
| Flash region          | ~4 MiB total, calibration is ~512 KiB slice       |

Not all MEVD17 variants are equivalent — the memory map below is the
**common case**. Variants exist that reorder BTLD and CAFD or use a
different SWFL partition base. Always verify against the actual SVK
response before trusting hardcoded addresses.

---

## 2. Memory map (logical addresses)

All addresses are in the DME's logical UDS address space, which is
mapped by the ECU firmware onto physical flash sectors. The simulator
and PCAP extractor in this repo hard-code these for MEVD17:

```
0x80000000 ─┬──────────────────────────────┐
            │ BTLD  (bootloader)           │ ~64 KiB
0x80010000 ─┤                              │
            │                              │
0x80020000 ─┼──────────────────────────────┤
            │ CAFD  (coding / calibration  │ ~384 KiB
            │        data, non-safety)     │
0x80080000 ─┤                              │
            │                              │
0x80180000 ─┼──────────────────────────────┤
            │ SWFL_1  (software / cal      │ ~512 KiB
            │          primary partition)  │   ~511 KiB
            │                              │   readable via
            │                              │   RMBA without
            │                              │   SecAccess
0x80200000 ─┤                              │
            │                              │
0x80220000 ─┼──────────────────────────────┤
            │ SWFL_2  (software / cal      │ ~512 KiB
            │          secondary partition)│
0x802A0000 ─┤                              │
            │                              │
0x80??FD00 ─┼──────────────────────────────┤
            │ fingerprint region           │ per-partition
            │  (last 256 B of each         │
            │   partition — contains       │
            │   programming-date, tool-id, │
            │   tester serial, etc.)       │
            │                              │
0x80400000 ─┴──────────────────────────────┘
```

Partition semantics:

- **BTLD** — bootloader. Contains the primary boot code and the small
  resident routine that handles erase/program requests from the
  diagnostic session. Almost never rewritten in the field.
- **CAFD** — "Calibration File Data". Non-safety-relevant coding and
  calibration slot. Coding DIDs written via WDBI usually land here.
- **SWFL** (partitions 1 and 2) — the main software + calibration
  image. This is where production flashers write tuned calibrations.
  MEVD17 keeps two partitions so flashes can be A/B-swapped with a
  valid image always present.
- **Fingerprints** — a 256-byte block at the end of each partition
  (`*FD00` through `*FDFF`) that records the last programming event:
  date, tool identifier, tester serial, checksum. Flashers write this
  as the final step of every flash; some analyses look here to detect
  "the car has been tuned" without dumping the whole flash.

---

## 3. Read access — `ReadMemoryByAddress` (0x23)

The MEVD17 SWFL_1 calibration partition (`0x80180000..0x801FFC00`) is
readable over UDS without SecurityAccess via **ReadMemoryByAddress**
(service `0x23`). This is the only region this repo's Calibration Read
tab will touch — see [SCOPE.md](../SCOPE.md) and the
`assert_unprotected_region` invariant in
`src-tauri/src/calibration_read/mod.rs`.

### Request format

```
23 <alfid> <addr bytes> <len bytes>
```

- `alfid` — AddressAndLengthFormatIdentifier. High nibble = length
  size in bytes, low nibble = address size in bytes. MEVD17 uses
  `0x44` (4-byte address, 4-byte length).
- Address and length are big-endian.

Example — read 4092 bytes from `0x80180000`:

```
23 44  80 18 00 00  00 00 0F FC
```

### Response format

```
63 <raw bytes...>
```

Maximum block size is `0xFFC` = 4092 bytes. The Calibration Read
client loops this call across the bounded calibration region in
4092-byte chunks, assembling the full dump.

### Block size rationale

4092 rather than 4096 because the HSFZ + UDS framing overhead
(8-byte HSFZ header + 1-byte service echo + padding) has to fit
within the ECU's receive buffer. Going higher risks NRC `0x13`
(incorrectMessageLengthOrInvalidFormat).

### No security access required

RMBA is unauthenticated on MEVD17 by design — it's the same service
used by emissions-inspection equipment. That's why this repo's
Calibration Read flow is safe to run against any car you own: there is
no write operation, no unlock step, and the read is hard-bounded to
the calibration partition by `assert_unprotected_region`.

### Gateway preparation (F-chassis only)

On F-chassis vehicles (FEM/BDC gateway) the tool sends a best-effort
preparation routine to address `0x40` before reading. Failure is
logged and the read continues — the routine is only needed on a
subset of gateway firmwares, and running it on cars that don't need
it is a no-op.

---

## 4. Flash write sequence

A full MEVD17 flash by a production flasher looks like this. Every
step is UDS over HSFZ.

```
1.  10 02                                -- DiagnosticSessionControl: programmingSession
    50 02 <P2> <P2*>                         positive ack + P2 timings

2.  27 01                                -- SecurityAccess: requestSeed(level 1)
    67 01 <seed bytes>                       seed

3.  27 02 <key bytes>                    -- SecurityAccess: sendKey(level 1)
    67 02                                    unlock ok

4.  31 01 FF 00 <addr> <len>             -- RoutineControl: eraseMemory (vendor ID 0xFF00)
    71 01 FF 00 <status>                     erase complete

5.  34 <alfid> <addr> <len>              -- RequestDownload
    74 <lfid> <max_block_len>                accept

6.  36 <blk_ctr> <data...>               -- TransferData (repeated until buffer drained)
    76 <blk_ctr>                             block ack
    [... many times ...]

7.  37                                   -- RequestTransferExit
    77                                       exit ack

    [steps 4-7 repeat for each partition: BTLD, CAFD, SWFL_1, SWFL_2]

8.  31 01 02 05                          -- RoutineControl: checkFlashIntegrity
    71 01 02 05 <status> <class> <SVK 8> #<DME_TYPE>#C1#DST#<...>
                                             — success means checksums
                                               match across all partitions

9.  31 01 FF 01                          -- RoutineControl: finalizeProgramming
    71 01 FF 01 <status>                     fingerprint written, session cleanup

10. 11 01                                -- ECUReset: hardReset
    51 01                                    goodbye, reboot
```

### Notes on individual steps

- **Erase vendor ID `FF00`** — BMW's ID for the "erase this address
  range" routine. The address/length map onto partition boundaries
  from §2.
- **`0x34` max_block_len** — the ECU tells the flasher how many bytes
  it can send per `0x36`. Typical: 0xFFA or 0xFFE. The simulator in
  this repo reports `0xFFA` (4090 payload + 2 block counter + service
  byte = 4093).
- **`0x36` block counter** — rolls `01..FF` then wraps to `00`. The
  ECU rejects out-of-sequence blocks with NRC `0x73`
  (wrongBlockSequenceCounter).
- **Routine `0x0205`** — checkFlashIntegrity. The response contains
  not just a pass/fail but a full SVK echo and ASCII tail that
  identifies the DME — see §6.
- **Fingerprint write** — happens implicitly as part of
  `finalizeProgramming`. Some flashers write it explicitly via
  WriteMemoryByAddress to the `*FD00` regions instead.

---

## 5. Key DIDs (DataIdentifiers)

Read via `22 XX XX` (ReadDataByIdentifier).

| DID     | Name                          | Format / meaning                                |
|---------|-------------------------------|-------------------------------------------------|
| `F190`  | VIN                           | 17 ASCII bytes                                  |
| `F191`  | HW number                     | 7–10 ASCII bytes (Bosch part number)            |
| `F187`  | ZB (spare-part) number        | ASCII                                           |
| `F18B`  | ECU manufacturing date        | BCD `YYMMDD` or `YYYYMMDD`                      |
| `F18C`  | ECU serial number             | ASCII, typically 10 bytes                       |
| `F197`  | System name                   | ASCII                                           |
| `F101`  | SVK (System Variant Key)      | Structured block of SVK entries — see below    |
| `F186`  | ActiveDiagnosticSession       | **2 bytes**: `[session_id] 0x81`                |
| `F150`  | SGBD index                    | Varies                                          |
| `F1A0`  | Programming counter           | 2–4 bytes BE                                    |
| `0x403C`| Programmed hash block         | 32+ bytes; **CVN is at bytes 16..20** only      |
| `0x2502`| Flash counter (partition 1)   | 2–4 bytes BE                                    |
| `0x2503`| Flash counter (partition 2)   | 2–4 bytes BE                                    |
| `0x5815`| Battery voltage (live)        | 2 bytes, scaled                                 |
| `0x460A`| Operating hours               | 4 bytes BE seconds                              |

### F186 — the 2-byte trap

`F186` (ActiveDiagnosticSession) returns **2 bytes**, not 1:

```
62 F1 86 01 81
       ^  ^
       |  └─ always 0x81
       └─ current session (01 = default, 02 = programming, 03 = extended)
```

Early implementations of this tool returned only 1 byte and lost TCP
sessions because flashers enforce the 2-byte format. The `0x81` tail
is a BMW-specific extension.

### F101 — SVK layout

The SVK block is the canonical ECU identifier and is central to
checksum verification. Layout observed on MEVD17:

```
offset  length  meaning
────────────────────────────────────────────────────────────
0       1       entry count N
1       1       format version
2       N×8     SVK entries (each entry is 8 bytes)
2+N×8   1       process class
3+N×8   1       dealer ID high
4+N×8   2       dealer ID (big-endian)
6+N×8   ...     trailing fields (varies by variant)
```

Each 8-byte SVK entry encodes `(partition, version, checksum hint)`
in a format specific to the DME firmware. The simulator in this repo
synthesises SVK bytes from `profile.metadata.svk_entries` at response
time.

### 0x403C — CVN, NOT cal ID

The common misconception: `403C` looks like it contains the
calibration ID because it's a large structured block. It does not.
It contains the **CVN (Calibration Verification Number)** at bytes
`16..20`. The cal ID comes from routine `0x0205` (see §6), not from
any DID.

---

## 6. Routine `0x0205` — checkFlashIntegrity

This is the post-flash checksum verification call. Its response format
is undocumented by BMW but reverse-engineered extensively.

### Request

```
31 01 02 05
```

### Response

```
71 01 02 05 <status> <class> <SVK 8 bytes> #<DME_TYPE>#C1#DST#<long>#<cal_id>#<project>
```

- `status` — 1 byte, non-zero means checksum failure.
- `class` — 1 byte, vendor code.
- `SVK 8 bytes` — the primary SVK entry, same format as inside `F101`.
- **ASCII tail** — `#`-separated fields. Typical shape:
  ```
  #MEVD17.2.9#C1#DST#N55TUE0_R#9VT9G40B#V030_P061#
    ^^^^^^^^^ ^^ ^^^ ^^^^^^^^^ ^^^^^^^^ ^^^^^^^^^^
    dme type  __ mkr long name cal ID   project code
  ```

### Markers

- **`C1`** — constant class marker (some variants use `C0`).
- **`#DST#`** — delimiter marker. Old versions of this simulator used
  `#PST#` which was wrong; real DMEs send `#DST#`. (`PST` = Plant ST,
  `DST` = Dealer ST — don't ask why.)

### Parsing the cal ID

The cal ID is the **4th `#`-separated field after `#DST#`**, counting
from 0. In the example above: `9VT9G40B`. It is **not** in DID
`0x403C`. It is **not** the first ASCII string after the SVK block.
It is specifically the field in that position.

This repo's `simulator::clone::extract_dme_type` and cal-ID parsing
walks the tail with explicit field indexing for this reason.

### DME type extraction

The DME type (e.g. `MEVD17.2.9`) is not a fixed-offset field — it's
the first ASCII substring matching any canonical prefix:

- `MEVD` (MEVD17)
- `MED`  (older Motronic)
- `MEV`  (older Motronic variants)
- `MSD`  (Bosch diesel)
- `MSV`  (BMW-branded Motronic)
- `MG1`  (next-gen Infineon platform, B58)
- `MG2`
- `MGU`

Substring scan rather than field indexing because some DMEs prepend
`DME-` or append version qualifiers that break fixed-position
assumptions.

---

## 7. Security access — scope disclaimer

MEVD17 uses `SecurityAccess` (UDS service `0x27`) with a seed/key
challenge. The seed is typically 4 bytes; the key is computed by a
hashing function embedded in the flasher. The algorithm varies by
ECU firmware version and is **not** documented publicly.

**This repository does not implement key derivation.** The simulator
accepts any key and returns success. The Calibration Read flow doesn't
use `0x27` at all because RMBA is unauthenticated on MEVD17 within the
bounded calibration partition.

Why no crackers:

- Implementing them would turn this tool into a key-cracking oracle,
  which is useful for unauthorised flashing and therefore out of
  scope for defensive research.
- Defensive research rarely needs the real key — you can observe
  what flashers do *after* auth succeeds by running them against the
  simulator (which fakes success).
- If you're researching the key algorithm itself, do it offline
  against your own captured `27 01`/`67 01`/`27 02` exchanges with a
  real ECU. Don't embed the cracker in this tool.

---

## 8. Fingerprints

Every flash leaves a fingerprint at the end of each written partition
in a 256-byte block starting at `0x*FD00`. Layout (observed on
several MEVD17 firmwares — varies slightly by variant):

```
offset  length  meaning
────────────────────────────────────────────────────────
0x00    8       programming date (BCD: YYYYMMDDhhmmss)
0x08    8       tool identifier (ASCII, e.g. "ISTA-P  ")
0x10    10      tester serial number (ASCII)
0x1A    6       reserved
0x20    4       programming counter (BE)
0x24    4       session ID (BE)
0x28    ...     checksum + padding 0xFF
0xFC    4       fingerprint checksum (BE)
```

Fingerprints are how a dealer tool (or an investigator with a dump)
detects "this car has been flashed by X on Y date". Most production
tuning flashers either:

1. Write a fake fingerprint mimicking a dealer tool, or
2. Blank the fingerprint region with `0xFF`, or
3. Preserve whatever was there before (dangerous — it desyncs the
   programming counter from reality).

The simulator captures fingerprint writes as part of the normal
segment-capture flow — they show up as a small `seg_*.bin` at
`0x80??FD00`.

---

## 9. Dump identification

Given a flash binary (e.g. one produced by this repo's Calibration
Read or PCAP extract flow), how do you identify what it is?

### Quick checks

1. **BTLD header** at `0x80000000`:
   - First 4 bytes: typically `0xAA 0x55 0xAA 0x55` or similar magic.
   - Offset `0x10..0x20`: ASCII Bosch part number.
   - Offset `0x80`: reset vector.

2. **CAFD header** at `0x80020000`:
   - Starts with an SVK-format block.
   - ASCII coding field names at offsets `0x100+`.

3. **SWFL header** at `0x80180000`:
   - Bosch signature block.
   - Cal ID ASCII string findable via `strings | grep -E '^[0-9A-Z]{8}$'`.

### SVK match

A definitive identification: extract the SVK block from `F101` (or
from a dump's CAFD header) and cross-reference against a BMW parts
database. The 8-byte entries encode partition + version.

### Cal ID extraction from a dump

The cal ID (e.g. `9VT9G40B`) lives as an ASCII string inside SWFL
near the start of the partition, typically around offset
`0x80180100..0x80180200`. It's 8 uppercase alphanumerics. `strings`
will find it; matching it to an OEM calibration requires a BMW
database lookup.

---

## 10. MG1 divergence (coming, untested)

BMW's newer DMEs — **MG1CS003**, **MG1CS201**, **MG1CS024**,
**MG1CS221**, **MG1CS049**, plus the MEVD17-era **N63/S63 dual-DME**
configurations — are **not** fully supported by this repo yet, and
are listed as "untested" in the top-level README. Key differences
from MEVD17 that will need per-platform handling:

- **Write protocol**: MG1 uses `RequestUpload`/`TransferData` (0x35)
  instead of RMBA for non-privileged reads, and a different erase
  routine signature.
- **Memory map**: different partition bases and sizes. The hardcoded
  addresses in this repo's simulator profile are MEVD17-specific and
  will need per-platform constants.
- **SecurityAccess**: MG1 uses a more modern challenge-response
  protocol. The simulator's "accept any key" stub still works for
  observation but real-car interop requires the right algorithm.
- **Dual-DME coordination (N63/S63)**: two DMEs at `0x12` and `0x13`
  share a single VIN but have independent SVK entries and independent
  flash images. The simulator's multi-address answering mostly
  handles this, but flashers may require specific ordering (unlock
  both, then write in interleaved fashion).

If you're researching any of the above platforms, the right workflow
is still "capture a pcap of a real flash, import into the simulator,
iterate" — the data model is flexible enough that `profile.dids` and
`profile.metadata.svk_entries` can accommodate non-MEVD17 values, you
just lose the MEVD17-specific synthesis shortcuts.

---

## 11. Further reading

- [`hsfz-protocol.md`](hsfz-protocol.md) — transport layer
- [`simulator.md`](simulator.md) — how the simulator responds to all
  of the above
- [`workflows.md`](workflows.md) — operator playbooks using MEVD17
  DIDs and flash sequences
- ISO 14229-1 (UDS) — the base standard, available via ISO paywall or
  leaked preprints
- Bosch BMW ECU documentation — internal, rarely public
