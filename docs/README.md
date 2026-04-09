# BMSecResearch — Documentation

Deep-dive technical documentation for security researchers working with
BMW diagnostic protocols. If you're looking for user-facing instructions,
see the top-level [README](../README.md). If you're here to attack your
own car's ECU on a bench, keep reading.

## Protocol reference

- [**hsfz-protocol.md**](hsfz-protocol.md) — HSFZ wire format, framing,
  control codes, UDS encapsulation, tester/ECU addressing, discovery
  over UDP 6811.

- [**mevd17.md**](mevd17.md) — Bosch MEVD17 DME memory map, flash
  process, DIDs, identification routines (0x0205 SVK + cal ID parsing),
  read/write access, security-access seed/key scope.

## Subsystem internals

- [**simulator.md**](simulator.md) — Stateful DME simulator. Profile
  model, UDS handler dispatch, multi-address answering, session capture
  format, transfer-rate throttle, flash segment reassembly.

- [**proxy.md**](proxy.md) — MITM proxy architecture. Topology options
  (dual-NIC bridged vs single-subnet race), VIN/MAC rewriting, upstream
  discovery, per-session pcap export, Detected/Spoofed/Active UI model.

## Operator playbooks

- [**workflows.md**](workflows.md) — End-to-end security research
  workflows: offline pcap extraction, live capture, calibration read, cloning
  a real DME into the simulator, flasher fingerprinting, VIN-binding
  research via the proxy, telemetry evasion research, protocol fuzzing.

## Build + distribution

- [**build.md**](build.md) — Build instructions (bun + Rust + Tauri),
  Windows one-shot script, `release/` output layout, cross-compilation
  notes, dependency pinning.

## See also

- [SECURITY.md](../SECURITY.md) — responsible-disclosure policy for
  vulnerabilities in *this tool*. For vulns in BMW products, contact
  BMW Group PSIRT.
- [DISCLAIMER.md](../DISCLAIMER.md) — intended use, scope, no-warranty.
- [CONTRIBUTING.md](../CONTRIBUTING.md) — PR guidelines.
