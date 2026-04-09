# BMSecResearch

> An independent, open-source security research toolkit for BMW
> diagnostic protocols (HSFZ over TCP/UDP, UDS per ISO 14229).
> Built with **Tauri 2**, **Svelte 5**, and **Rust**.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS%20%7C%20Android-lightgrey)]()
[![Status](https://img.shields.io/badge/status-research-orange)]()

> [!IMPORTANT]
> **BMSecResearch is not affiliated with, endorsed by, sponsored by, or
> commercially connected to BMW AG, BMW Group, or any of their
> subsidiaries.** "BMW", "MEVD17", "Motronic", and related marks are the
> property of their respective owners and are used here in their
> nominative descriptive sense only — to identify the vehicles and
> diagnostic protocols this research toolkit targets. See
> [SCOPE.md](SCOPE.md) for the full scope and legal framing.

> [!WARNING]
> **Read [DISCLAIMER.md](DISCLAIMER.md) and [SCOPE.md](SCOPE.md) before
> using this software.** This is a security research tool. Use only on
> hardware you own or are authorized in writing to test. The tool is
> read-only and bounds-enforced against the MEVD17 unprotected
> calibration region — it does not write to ECUs and does not implement
> SecurityAccess key derivation.

---

## In plain English — what is this?

If you're not an automotive or security researcher, this section is for
you. The rest of this README gets technical fast.

### The very short version

Modern cars contain a network of small computers (**ECUs** — *Electronic
Control Units*) that communicate over standardised, publicly-documented
diagnostic protocols. Two of those protocols — **HSFZ** (a BMW
TCP/UDP transport) and **UDS** (*Unified Diagnostic Services*, ISO
14229, an international standard) — are what this project studies.

**BMSecResearch is a protocol study toolkit** for researchers,
students, and hobbyists working on vehicles they personally own. It
does **not** modify the car. It does not override anything. It does
not bypass security. It only *reads* and *records*, and only from
parts of the car's memory that the ECU itself is willing to return
in response to standard, unauthenticated diagnostic requests.

Think of it the same way a hobbyist might use an OBD-II scanner to
read engine fault codes on their own car — this project works one
layer deeper, on the raw protocol itself, for people writing academic
papers or studying how these standards work in practice.

### What you can actually do with it

| Feature | What it means in plain English |
|---|---|
| **Read the calibration** | Save a copy of the unprotected calibration region of your own ECU to a file, as a personal backup. Read-only, bounds-enforced, does not change anything on the car. |
| **Parse a PCAP capture** | Open a `.pcap` you recorded yourself (e.g. on a bench rig between two pieces of hardware you own) and reconstruct the higher-level protocol messages from it — a protocol-analyser for HSFZ/UDS traffic. |
| **Run an ECU simulator** | A software model of an ECU that speaks HSFZ/UDS on a loopback socket, so researchers can study the protocol without any physical hardware attached. Purely local, purely synthetic. |
| **Bench-rig proxy** | When you have two pieces of your own hardware on a bench and want to log the protocol exchange between them, the proxy sits on the wire and writes a PCAP. It's a local protocol recorder for your own lab setup. |

### What you *cannot* do with it

This is not a tuning tool. It does not flash custom maps. It does not
unlock engine power. It does not defeat any security system. It does
not bypass dealer lockouts. It does not crack keys. It does not remove
anti-theft. It is deliberately built so that it *can't* do those
things, even if you modified it — the scope is enforced at multiple
layers in the code. See [SCOPE.md](SCOPE.md) for the specifics.

If you're looking for a tool to modify your car, this isn't it. Look
at the commercial tuning-tool marketplace instead — that's a
different category of product with different legal rules.

### Who this is for

- **Security researchers** studying automotive network protocols for
  academic papers, conference talks, or responsible disclosure
- **Students** learning how the ISO 14229 (UDS) standard works in
  practice
- **CTF (capture-the-flag) competitors** practising on automotive
  security challenges
- **Hobbyists** who want a read-only personal backup of the
  unprotected calibration region of an ECU they own

### Who it is *not* for

- Anyone wanting to modify the engine calibration on a vehicle that
  drives on public roads
- Anyone wanting to defeat emissions controls, speed limiters,
  immobilisers, or anti-theft
- Anyone wanting to access a vehicle they don't own
- Commercial tuners looking for a shortcut

### Is this legal?

The tool itself is built to operate within the law. Whether *your use*
of it is legal depends on your country and what you do with it. The
short version:

- **Reading data from a car you own, on a bench, for research** — yes,
  in every jurisdiction we're aware of.
- **Modifying engine software on a car that drives on public roads** —
  the tool doesn't do this, but if you're thinking about doing it with
  other tools, be aware that emissions-tampering laws are strict in
  most countries.
- **Using it on a car you don't own** — not authorised. Don't.

The detailed legal analysis is in [SCOPE.md](SCOPE.md),
[TRADEMARKS.md](TRADEMARKS.md), [DISCLAIMER.md](DISCLAIMER.md), and
[NOTICE](NOTICE). If you're here to do serious research and need to
explain the legal framing to a legal department, those are the files
to read.

---

## What it does

Five integrated workflows, one app:

| # | Tab              | Purpose |
|---|------------------|---------|
| 1 | **Extract From PCAP** | Parse an offline `.pcap` / `.pcapng` HSFZ capture, reassemble segmented `TransferData` (0x36) flows, and export the flash binary. |
| 2 | **Capture Flash**     | Live-sniff HSFZ traffic on a NIC, extract segments in real time, save as `.bin`. |
| 3 | **Calibration Read**  | Connect directly to a BMW gateway over ENET, discover it via HSFZ broadcast, and read the MEVD17 unprotected calibration region (raw or 4 MB padded). Read-only, bounds-enforced. See [SCOPE.md](SCOPE.md). |
| 4 | **DME Simulator**     | Stateful HSFZ server that impersonates a DME. Answers UDS diagnostic sessions, SecAccess, RDBI/RMBA, Routines, Download/TransferData/TransferExit. Captures every flasher attempt to disk. |
| 5 | **DME Proxy**         | Transparent MITM between a flasher and a real DME. Per-session pcap captures, VIN/MAC spoofing, discovery responder, auto-discover upstream DME. |

See [docs/](docs/) for deep technical writeups on each subsystem.

---

## ECU support

| ECU family                | Calibration read | PCAP extract | Simulator | Proxy  | Notes |
|---------------------------|:-:|:-:|:-:|:-:|---|
| **MEVD17** (B38 / N13 / N20 / N26 / N55 / S55) | ✅ | ✅ | ✅ | ✅ | Primary target; most tested |
| MEVD17 N63 / S63 (dual DME) | 🟡 | 🟡 | 🟡 | 🟡 | Support coming — untested |
| MG1CS003 (B58)              | 🟡 | 🟡 | 🟡 | 🟡 | Support coming — untested |
| MG1CS201                    | 🟡 | 🟡 | 🟡 | 🟡 | Support coming — untested |
| MG1CS024                    | 🟡 | 🟡 | 🟡 | 🟡 | Support coming — untested |
| MG1CS221                    | 🟡 | 🟡 | 🟡 | 🟡 | Support coming — untested |
| MG1CS049                    | 🟡 | 🟡 | 🟡 | 🟡 | Support coming — untested |
| FEM / BDC (`0x40`)          | — | — | — | — | Gateway-prep routine only |
| Everything else             | ❌ | ❌ | ❌ | ❌ | Not planned |

Legend: ✅ working · 🟡 planned / untested · ❌ unsupported

MEVD17 uses `ReadMemoryByAddress` (0x23) in 4092-byte blocks and hard-codes
the calibration region at `0x80180000`/`0x80220000`. MG1 variants use
`RequestUpload` + `TransferData` with a different memory map and will be
added incrementally — **do not assume they work**.

---

## Quick start

```bash
# Prerequisites: bun, Rust stable, Tauri 2 system deps
#   Windows also needs: MSVC Build Tools + Edge WebView2
#   Linux also needs:   libwebkit2gtk-4.1-dev, libpcap-dev

git clone https://github.com/0xhef/hsfz-toolkit.git
cd hsfz-toolkit

bun install
bun run tauri dev      # development hot-reload
bun run tauri build    # production bundle
```

### Windows one-shot build

```powershell
powershell -ExecutionPolicy Bypass -File .\build-windows.ps1
```

Installs prereqs as needed and drops the portable exe + NSIS installer
into `release/` at the repo root.

### Android sideload build

The Android variant ships as a sideloaded APK — no Play Store. The
default Android build omits libpcap (which Android sandboxes away from
non-system apps) and uses proxy capture instead, which works in
userspace and needs no special permissions. See
[**ANDROID.md**](ANDROID.md) for full build, signing, and distribution
instructions.

```sh
# One-time setup: Android NDK + Rust Android targets + Tauri mobile init
# (see ANDROID.md for the full prerequisite list)

bun run tauri android build -- --no-default-features --features android-default
```

Rooted-Android users with a working libpcap cross-compile can re-enable
the live Capture tab via `--features libpcap` instead. See ANDROID.md
§ "Rooted-libpcap bundle" for the requirements.

### CLI mode

The binary also works headless for batch PCAP extraction:

```bash
bmsecresearch capture.pcap dump.bin
```

---

## Documentation

Deep-dive technical docs live under [`docs/`](docs/):

- [**docs/hsfz-protocol.md**](docs/hsfz-protocol.md) — HSFZ wire format, framing, control codes
- [**docs/mevd17.md**](docs/mevd17.md) — MEVD17 memory map + flash process
- [**docs/simulator.md**](docs/simulator.md) — stateful DME simulator internals
- [**docs/proxy.md**](docs/proxy.md) — MITM proxy architecture + VIN rewriting
- [**docs/workflows.md**](docs/workflows.md) — end-to-end security research workflows
- [**docs/build.md**](docs/build.md) — build + distribution instructions

---

## Legal / ethical

This project is published for **security research and education** under
**GPL-3.0**. BMSecResearch is an independent open-source project. It is
**not affiliated with, endorsed by, sponsored by, or commercially
connected to** BMW AG, BMW Group, Robert Bosch GmbH, or any of their
subsidiaries or affiliates. "BMW", "MEVD17", "Motronic", "ISTA", and
related marks are the property of their respective owners and are used
here in their nominative descriptive sense only, to identify the
vehicles and diagnostic protocols this research toolkit targets
(see *BMW v. Deenik*, ECJ C-63/97; *New Kids on the Block v. News
America Publishing*, 9th Cir. 1992).

- [LICENSE](LICENSE) — GPL-3.0
- [NOTICE](NOTICE) — copyright + attribution + no-copied-proprietary-code assertion
- [SCOPE.md](SCOPE.md) — what this tool does and does not do, with the legal framing
- [TRADEMARKS.md](TRADEMARKS.md) — nominative fair use framework for third-party marks
- [DISCLAIMER.md](DISCLAIMER.md) — no-warranty + intended-use statement
- [SECURITY.md](SECURITY.md) — responsible disclosure policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — PR guidelines + code of conduct

Do not use this tool on vehicles you do not own or lack written
authorization to test. Modifying engine calibrations on public-road
vehicles may violate emissions law in your jurisdiction.
