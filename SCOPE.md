# Scope of this tool

> This document describes what this project does, what it does not do,
> and the legal framing behind those choices. It is not legal advice.
> See [DISCLAIMER.md](DISCLAIMER.md) for the full liability disclaimer.

## What this tool does

This repository contains a security-research toolkit for the BMW
diagnostic protocol stack (HSFZ over TCP/UDP, UDS per ISO 14229). It
has five components:

1. **PCAP forensics (`Extract from PCAP` tab).** Parses pre-captured
   `.pcap` / `.pcapng` files containing HSFZ traffic, reassembles TCP
   streams, extracts UDS flash-download sessions, and reconstructs the
   transferred binary image. Pure offline analysis of traffic you
   already have.

2. **Live capture (`Capture Flash` tab).** Uses libpcap to observe HSFZ
   traffic on a network interface, then feeds the captured packets into
   the same forensic pipeline as `Extract from PCAP`. Passive
   observation only — the tool does not inject, modify, or forge
   traffic during capture.

3. **Calibration read (`Calibration Read` tab).** Connects to a BMW
   vehicle gateway over ENET and issues `ReadMemoryByAddress` (UDS
   `0x23`) against the **MEVD17 unprotected calibration region**
   `[0x80180000, 0x801FFC00]` — approximately 511 KB. This region is
   exposed by the DME in the default diagnostic session with no
   SecurityAccess, no seed/key exchange, and no authentication.
   See ["Read-only scope, enforced"](#read-only-scope-enforced) below.

4. **DME simulator (`DME Simulator` tab).** A behavioral simulator that
   impersonates a MEVD17-class DME over HSFZ. Implements a full UDS
   service table (`0x10`, `0x11`, `0x22`, `0x23`, `0x27`, `0x2E`, `0x31`,
   `0x34`, `0x36`, `0x37`, `0x3D`, `0x3E`, `0x85`). The simulator is the
   **receiver** of flash writes — it accepts `RequestDownload` /
   `TransferData` / `TransferExit` from a tester so that researchers
   can exercise and analyze diagnostic tooling against a benign,
   fully-logged target. It never initiates flash writes against a real
   ECU.

5. **MITM proxy (`DME Proxy` tab).** A transparent HSFZ proxy that sits
   between a tester and a real or simulated DME, logging every frame
   for analysis. Supports optional VIN/MAC rewriting for research
   against discovery and licensing workflows.

## What this tool does not do

This project does not implement, and is deliberately designed so that
it cannot be made to implement, the following:

- **Writes to a real ECU.** No code path in this repository sends UDS
  `0x34` RequestDownload, `0x36` TransferData, or `0x37`
  RequestTransferExit **to** a real ECU. The simulator handles those
  services because it is pretending to *be* an ECU, not attacking one.
- **SecurityAccess key computation.** No `0x27` client implementation
  exists. The simulator's `0x27` handler accepts any seed/key because
  the simulator owns the verification step (it is the ECU side), but
  there is no code that computes keys for real ECUs.
- **Reads of protected memory regions.** The calibration reader is
  bounded to `[CALIBRATION_START, CALIBRATION_END]` by the
  `assert_unprotected_region` invariant in
  `src-tauri/src/calibration_read/mod.rs`. Every call to
  `ReadMemoryByAddress` flows through that gate. The bounds cover the
  MEVD17 SWFL_1 partition and nothing else; regions behind
  SecurityAccess cannot be read even with a crafted IPC payload.
- **Bundled BMW firmware or proprietary data.** No BMW firmware,
  calibration maps, signing keys, certificates, cryptographic material,
  ISTA/WinKFP data, or other proprietary artifacts are included in
  this repository.
- **Defeat-device functionality.** This tool does not bypass, defeat,
  or render inoperative any device or element of design installed on
  or in a motor vehicle in compliance with emissions regulations
  (42 USC §7522(a)(3)).
- **Remote / over-the-internet operation.** The `validate_host`
  function in the calibration reader refuses public/internet-routable
  IPv4 targets. Only loopback, RFC1918 (10/8, 172.16/12, 192.168/16),
  and link-local (169.254/16) addresses are accepted, reinforcing the
  bench-research use case.

## Platform support and the libpcap → proxy-capture story

BMSecResearch runs on **Windows, Linux, macOS, and Android**. iOS support
is theoretically possible via Tauri 2's iOS target but is not currently
built or tested.

Live packet capture has historically required `libpcap` (or Npcap on
Windows), which depends on a kernel-mode driver and is unavailable to
non-system Android apps. Rather than fall back to the Android
`VpnService` API — which only sees traffic originating from the device
itself, not arbitrary frames on the wire — BMSecResearch uses **proxy
capture** as the cross-platform capture mechanism:

- The phone (or laptop) runs the proxy module on a chosen TCP port
- The operator points their tester at the proxy's address instead of
  the car's gateway address
- The proxy forwards every byte to the real gateway (or to the
  simulator) and writes the timestamped frame timeline to disk
- `proxy_export_pcap` converts the timeline into a Wireshark-compatible
  `.pcap` file that the PCAP Forensics tab can re-ingest

This is **strictly more portable and strictly safer** than libpcap
sniffing: no kernel driver, no `CAP_NET_RAW` capability, no Npcap
install, no `BPF` device permissions, no antivirus false positives, and
the same Rust code path runs identically on every platform. The only
thing it gives up is true passive sniffing of sessions the operator
didn't initiate — which for an intentional research tool is rarely
needed.

Capability is gated by **Cargo feature**, not by platform. The
`libpcap` feature controls whether libpcap-based passive sniffing is
compiled into a given binary:

- **Desktop default build** — `libpcap` is in the default feature set,
  so the Capture Flash tab is available
- **Android default sideload build** — built with
  `--no-default-features --features android-default`, omitting
  `libpcap`. The Capture tab is hidden in the UI; the capture commands
  return a clear `PlatformUnsupported` error if invoked anyway.
- **Android rooted opt-in build** — built with `--features libpcap`
  on a system that has libpcap cross-compiled for Android. Re-enables
  the live Capture tab. Requires a rooted target device with
  `CAP_NET_RAW`. See ANDROID.md for the build requirements.
- **Research-only build** — `--no-default-features --features research`
  omits both `libpcap` and `live-ecu`, producing a binary that cannot
  sniff network traffic and cannot communicate with real ECUs.

The frontend uses a runtime `has_live_capture()` Tauri command to
decide whether to render the Capture tab, so the same Svelte code
works correctly across all four build flavors without any
platform-specific branches in the UI logic.

## Read-only scope, enforced

The calibration reader's scope is enforced at three levels:

1. **Compile-time bounds.** `CALIBRATION_START` and `CALIBRATION_END`
   are `const` values. They cannot be changed at runtime.

2. **Runtime invariant.** Every call to `read_memory_by_address` calls
   `assert_unprotected_region(addr, size)` before issuing the UDS
   request. Any address range that falls outside the bounds — including
   the case of a range that starts inside and extends past the end —
   is rejected with a clear error, unit-tested at
   `src-tauri/src/calibration_read/mod.rs`.

3. **Build-time feature gate.** The entire live-ECU networking layer
   (calibration read, HSFZ vehicle discovery, clone-from-car) is gated
   behind the `live-ecu` Cargo feature. The feature is part of the
   default feature set so developer builds work unchanged, but a
   research-only binary with **no live-ECU code compiled in** can be
   produced with:

   ```sh
   cargo build --release --no-default-features --features research
   # or for the full Tauri app:
   bun run tauri build -- --no-default-features --features research
   ```

   When the `live-ecu` feature is disabled, `read_calibration_region`,
   `discover_vehicles`, and `simulator_clone_from_car` all return a
   clear error without touching the network. See the commented-out
   variant in `build-windows.ps1`.

## Legal framing (not legal advice)

The calibration region this tool reads is exposed by the MEVD17 DME
in the default diagnostic session without any authentication step.
17 USC §1201(a)(3)(B) defines "effectively controls access" as
requiring "the application of information, or a process or a treatment,
with the authority of the copyright owner, to gain access to the work."
A memory region that the ECU hands to any tester that asks, without a
key, handshake, or session upgrade, is not protected by a technological
measure within the meaning of the statute. See *Lexmark International
v. Static Control Components* (6th Cir. 2004) and *Chamberlain Group v.
Skylink Technologies* (Fed. Cir. 2004) for the governing framework on
"effective" access controls.

42 USC §7522(a)(3) (Clean Air Act) prohibits manufacture or sale of
parts whose principal effect is to bypass emissions controls. A
read-only calibration dumper has no effect on emissions controls — it
does not modify, write, install, or tamper with anything. No EPA
enforcement action in history has targeted a pure read/dump/forensics
tool; enforcement actions (Derive, EZ Lynk, Punch It Performance, H&S
Performance, Edge, Diablosport) have all targeted tools that *write*
modified calibrations.

Protocol reverse engineering of interface specifications is expressly
protected under 17 USC §1201(f) (reverse engineering for
interoperability) and under fair use (17 USC §107) as transformative,
non-commercial, educational research. Memory addresses, UDS service
IDs, routine numbers, and the structure of HSFZ frames are facts and
are not copyrightable (*Feist Publications v. Rural Telephone Service*,
499 U.S. 340, 1991).

Good-faith security research on motorized land vehicles is also
protected under the **Librarian of Congress triennial §1201
rulemaking exemption** for "computer programs that are contained in
and control the functioning of a lawfully acquired motorized land
vehicle such as a personal automobile ... when circumvention is a
necessary step to allow the diagnosis, repair, or lawful modification
of a vehicle function" — originally granted in the 2015 rulemaking
(80 Fed. Reg. 65944), renewed in 2018, 2021, and 2024, and expanded in
each cycle to include aftermarket customization and security
research. See 37 CFR §201.40(b)(9)(i–ii) for the current
regulatory text.

Additionally, 17 USC §1201(j) independently creates a permanent
exemption for "security testing" — defined as "accessing a computer,
computer system, or computer network, solely for the purpose of good
faith testing, investigating, or correcting, a security flaw or
vulnerability, with the authorization of the owner or operator of
such computer, computer system, or computer network." Combined with
the `validate_host` guard refusing public-internet targets and the
"vehicles you own or are authorized to test" language in
DISCLAIMER.md, this project is structurally aligned with the §1201(j)
authorization requirement.

17 USC §1201(g) provides a parallel encryption-research exemption for
circumvention done in the course of identifying and analyzing flaws
in encryption technologies — not directly applicable here because the
calibration region targeted by this tool is **not encrypted** (the
DME returns plaintext bytes to any tester that asks), but cited for
completeness of the anti-circumvention defense stack.

Nothing in this document constitutes legal advice. Laws vary by
jurisdiction. Users are solely responsible for ensuring that their use
of this tool complies with the laws of their country, state, and local
jurisdiction, and with any agreements (e.g. vehicle finance, lease,
warranty, insurance) that may apply to the vehicles they test.

## Authorized use

This tool is intended for:

- Security researchers analyzing vehicles they own.
- Security researchers operating under a written authorization to test
  (penetration test engagement, bug bounty, academic research program,
  manufacturer cooperation).
- Academic instruction and coursework on automotive security and
  diagnostic protocols.
- Forensic analysis of pre-captured diagnostic traffic.

Use on any vehicle you do not own or lack written authorization to
test is **not** an authorized use of this tool and may violate CFAA
§1030 (US), the Computer Misuse Act 1990 (UK), Directive 2013/40/EU
(European Union), or equivalent statutes in your jurisdiction.

Modifying engine calibration data on a vehicle that is operated on
public roads is a separate matter from the scope of this tool —
this tool does not modify anything — but researchers should be aware
that such modification may violate type-approval regulations
(EU 2018/858), tampering provisions of the Clean Air Act (42 USC
§7522(a)(3) in the US), and similar regulations elsewhere, regardless
of what tooling was used to perform the modification.

## Contact

If you are a security researcher, vendor security team, or regulator
with questions about this tool's scope or behavior, please open a
GitHub issue or refer to [SECURITY.md](SECURITY.md) for the coordinated
disclosure process.
