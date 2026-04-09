# Contributing

Thanks for your interest in BMSecResearch. This is a community-driven,
independent security research project (not affiliated with BMW AG).
All contributions go through GitHub pull requests.

## Ground rules

1. **No real vehicle data.** Never commit real VINs, real MAC addresses,
   or captured flashes from customer vehicles. Use the placeholder VINs
   (`WBATESTVIN1234567`, `WBAXXXXXXXXXXXXXX`) or synthetic fixtures.
2. **Responsible-use framing.** Don't add features whose sole purpose is
   to bypass immobilizers, emissions controls, or fraud detection on
   vehicles you don't own. Features that *could* be misused are fine as
   long as they have a legitimate research use case (the MITM proxy is
   the obvious example).
3. **GPL-3.0 only.** By submitting a PR you agree your contribution is
   licensed GPL-3.0 or later.

## Development setup

Prerequisites:

- [bun](https://bun.sh/) (package manager + script runner)
- Rust stable with `x86_64-pc-windows-msvc` target (Windows) or the
  native target for your OS
- Tauri 2.x system prerequisites (see https://tauri.app/start/prerequisites/)
- Windows: MSVC Build Tools + Edge WebView2 runtime

```bash
# install deps
bun install

# run dev build
bun run tauri dev

# production build (writes to release/ at repo root)
bun run tauri build
```

## Project layout

```
src/                  Svelte 5 frontend
  lib/components/     One file per UI tab
  lib/types.ts        TypeScript types mirroring Rust structs
src-tauri/src/
  pcap/               PCAP parser + writer
  flash/              Flash segment extraction / assembly
  simulator/          Stateful DME simulator (HSFZ server)
  proxy/              MITM proxy (flasher ↔ real DME)
  calibration_read/   Live MEVD17 calibration reader (scope-bounded)
docs/                 Security-researcher documentation
tests/fixtures/       Synthetic test vectors only
```

## Code style

- **Rust:** `cargo fmt` + `cargo clippy -- -D warnings` clean
- **Svelte/TS:** follow existing style; no Prettier config shipped
- **Commits:** conventional commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`)
- **Branch off `main`**, open PR against `main`

## Tests

```bash
cd src-tauri && cargo test
```

Fixtures live at `tests/fixtures/`. Anything in `captures/`,
`proxy_captures/`, or `profiles/` is gitignored and must never be
committed.

## Documentation

When adding protocol details, update the relevant file under `docs/`:

- `docs/hsfz-protocol.md` — HSFZ wire format
- `docs/mevd17.md` — MEVD17 memory map / flash process
- `docs/simulator.md` — simulator internals
- `docs/proxy.md` — MITM architecture
- `docs/workflows.md` — researcher workflows

## Reporting bugs / security issues

- **Functional bugs:** open a GitHub issue with reproduction steps.
- **Security issues:** see [SECURITY.md](SECURITY.md) — report privately.

## Feature requests

Open an issue with the `enhancement` label and describe the research
use case. Features that only make sense as fraud/emissions bypass will
be closed.
