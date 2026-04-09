# Build & Distribution

This project is a **Tauri 2** app: Rust backend + Svelte 5 frontend,
bundled as a native desktop binary. Package management is **bun**.

## Prerequisites

### All platforms

| Tool           | Minimum version | Notes                              |
|----------------|-----------------|------------------------------------|
| Rust           | stable (≥1.80)  | `rustup` managed                   |
| bun            | ≥1.1            | https://bun.sh/                    |
| Tauri CLI      | installed via `bun install` (devDep) |                 |

### Windows (additional)

| Tool                        | Notes                                  |
|-----------------------------|----------------------------------------|
| MSVC Build Tools            | "Desktop development with C++" workload |
| Edge WebView2 runtime       | Pre-installed on Win11; NSIS installer bootstraps otherwise |
| Target `x86_64-pc-windows-msvc` | Added by `build-windows.ps1` automatically |

### Linux (additional)

Debian/Ubuntu:
```bash
sudo apt install -y \
    libwebkit2gtk-4.1-dev \
    libgtk-3-dev \
    libayatana-appindicator3-dev \
    librsvg2-dev \
    libpcap-dev \
    build-essential curl wget file
```

The `libpcap-dev` package is required for the **Capture Flash** tab's
live-sniffing feature.

## Building from source

```bash
git clone https://github.com/0xhef/hsfz-toolkit.git
cd hsfz-toolkit

bun install
bun run tauri dev      # hot-reload development build
bun run tauri build    # production bundle
```

Production artifacts land under `src-tauri/target/release/` and
(on Windows) `src-tauri/target/release/bundle/nsis/`.

## Windows one-shot script

```powershell
powershell -ExecutionPolicy Bypass -File .\build-windows.ps1
```

The script:

1. Checks / installs Rust via `rustup-init`
2. Checks / installs bun via the official installer
3. Verifies MSVC Build Tools are present (prints install link if not)
4. Verifies WebView2 runtime
5. Runs `bun install`
6. Runs `bun run tauri build`
7. **Copies** the portable `.exe` and NSIS `*-setup.exe` into
   `<repo>/release/` at the repo root

Run the first invocation from an **elevated PowerShell** so prereq
installers can land. Subsequent builds don't need admin.

## Release output layout

After a successful build:

```
release/
├── bmsecresearch.exe              # portable (~15 MiB)
└── BMSecResearch_1.0.0_x64-setup.exe # NSIS installer (~6 MiB)
```

The `release/` directory is **gitignored** — these are build outputs,
not source. Attach them to a GitHub Release instead of committing them.

## Tauri plugin version pinning

`src-tauri/Cargo.toml` pins tauri plugin minor versions to match the JS
side:

```toml
tauri-plugin-process = "2.3"
tauri-plugin-dialog  = "2.7"
tauri-plugin-fs      = "2.5"
```

Mismatches between the Rust crate minor version and the
`@tauri-apps/plugin-*` package version will cause Tauri to refuse to
start with a "missing permission" error at runtime. Bump both sides
together.

## Cross-compilation

Not currently supported. The app uses platform-specific packet-capture
libraries (`libpcap` on Linux, Npcap on Windows). Build on the target
platform.

## Reproducible builds

`Cargo.lock` is committed (this is a binary crate). `bun.lockb` should
also be committed once you run `bun install` locally. `package-lock.json`
and `pnpm-lock.yaml` are gitignored as legacy artifacts from earlier
tooling — delete them if present.

## Code signing

The NSIS installer is **unsigned** by default. Windows SmartScreen will
warn on first run. For distribution:

- Sign with `signtool` using a code-signing certificate (EV preferred
  to skip SmartScreen reputation)
- Or publish via GitHub Releases so users can verify the SHA-256 hash

The `build-windows.ps1` script does **not** invoke signing. Add a
post-build step if you need it.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `cargo` not found after rustup install | Open a new shell, or `. $PROFILE` in PowerShell |
| `link.exe` not found during `cargo build` | MSVC Build Tools missing; install Desktop development with C++ workload |
| Tauri dev server hangs on first run | WebView2 runtime missing on Windows |
| `libpcap.h` not found on Linux | `sudo apt install libpcap-dev` |
| Plugin version mismatch error at runtime | Align Cargo.toml plugin versions with package.json |
| `bun install` fails on Windows with symlink errors | Run elevated PowerShell once |
