# Security Policy

## Scope

This repository is a **security research tool** targeting BMW diagnostic
protocols. This policy covers vulnerabilities in **the tool itself** —
not vulnerabilities you discover *using* the tool in BMW products.

- **Vulns in this tool** → report here (see below).
- **Vulns in BMW products** → report to BMW Group PSIRT via their
  official channels. Please follow coordinated-disclosure timelines.

## Reporting a vulnerability in this tool

If you find a security issue in the code (RCE in the proxy, path
traversal in capture export, auth bypass, injection in generated pcap
files, etc.):

1. **Do not** open a public GitHub issue.
2. Open a **private security advisory** via GitHub's *Security* tab on
   the repository. This lets maintainers triage privately.
3. Include:
   - Affected version / commit hash
   - Reproduction steps
   - Impact assessment
   - Any proof-of-concept (sanitized — no real VINs, MACs, or captured
     car data)

You should receive an acknowledgment within 7 days. We aim to have a
fix or mitigation within 30 days for high/critical issues.

## Disclosure timeline

- **Day 0** — You report privately.
- **Day 0–7** — Triage + acknowledgment.
- **Day 7–30** — Fix developed and tested.
- **Day 30+** — Coordinated public disclosure, credit in release notes.

## Out of scope

- Issues in third-party dependencies (report those upstream; we'll bump
  versions once patches land).
- Attacks requiring physical access to a machine already running the
  tool with elevated privileges — this is a research tool, not a
  hardened service.
- Denial-of-service against the local HSFZ listener or proxy (it's a
  local-use tool, not an internet service).

## Safe harbour

Good-faith security research on this codebase is welcome. We will not
pursue legal action against researchers who:

- Operate within this policy
- Do not exfiltrate user data beyond what is necessary for a PoC
- Give reasonable time for a fix before public disclosure

## Sensitive data

Please **never** include the following in a report, issue, or PR:

- Real VINs from production vehicles
- Real MAC addresses of BMW ECUs
- Captured flash binaries from vehicles you do not own
- Customer diagnostic sessions containing PII (dealer IDs, odometer
  readings tied to a VIN, etc.)

Use the placeholder VINs (`WBATESTVIN1234567`, `WBAXXXXXXXXXXXXXX`) and
scrubbed test captures under `tests/fixtures/` when demonstrating
issues.
