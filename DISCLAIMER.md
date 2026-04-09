# Disclaimer

BMSecResearch ("the Software") is published for **security research,
education, and defensive analysis** of BMW diagnostic protocols (HSFZ /
UDS / ENET). It is **not** affiliated with, endorsed by, sponsored by,
or commercially connected to BMW AG, BMW of North America, BMW Group,
Robert Bosch GmbH, or any of their subsidiaries or affiliates. "BMW",
"MEVD17", "Motronic", "ISTA", and related marks are the property of
their respective owners and are used here in their nominative
descriptive sense only, to identify the vehicles and diagnostic
protocols this research toolkit targets.

## Intended use

- Reverse-engineering BMW diagnostic protocols on vehicles you own or are
  authorized in writing to test.
- Offline analysis of packet captures (`.pcap` / `.pcapng`) you lawfully
  possess.
- Running the DME simulator and MITM proxy against your own hardware in
  an isolated lab network.
- Security research, conference talks, academic study, and CTF-style
  challenges.

## NOT intended for

- Tampering with vehicles you do not own.
- Bypassing immobilizers, anti-theft systems, or emissions controls on
  public roads.
- Any activity prohibited by your local laws (CFAA in the US, CMA in the
  UK, § 202 StGB in Germany, etc.).
- Production vehicle modification without the consent of the registered
  owner.

## No warranty

The Software is provided **"AS IS"**, WITHOUT WARRANTY OF ANY KIND,
express or implied, including merchantability, fitness for a particular
purpose, and non-infringement. The authors and contributors are **not
liable** for any direct, indirect, incidental, consequential, or other
damages — including but not limited to:

- Bricked ECUs, DMEs, gateways, or other vehicle modules.
- Vehicles that fail to start, fail inspection, or fail to meet emissions
  requirements.
- Loss of warranty, insurance coverage, or roadworthiness certification.
- Data loss from packet captures, exported flashes, or profiles.

**Flashing an ECU can permanently damage it.** Calibration writes,
key learns, and immobilizer writes are inherently risky and are often
irreversible without dealer-level tools. You are solely responsible for
any consequences of using this software on real hardware.

## Regulatory & legal

Modifying engine calibrations may:

- Violate the Clean Air Act (US) or equivalent emissions regulations in
  your jurisdiction.
- Void your manufacturer warranty.
- Make the vehicle illegal to operate on public roads.
- Trigger on-board diagnostic (OBD) readiness flags that fail inspection.

It is **your responsibility** to understand and comply with the laws
that apply where you live and operate the vehicle. The authors provide
no legal advice.

## Responsible disclosure

If you discover a security vulnerability in a BMW product using this
tool, please follow responsible disclosure practices. See
[SECURITY.md](SECURITY.md) for details.

By downloading, building, or running this software you acknowledge
that you have read and understood this disclaimer and that you accept
all associated risks.
