# build-windows.ps1
#
# One-shot Windows build script for BMSecResearch.
#
# Produces two artifacts under <repo>\release\:
#
#   1. bmsecresearch.exe
#      — portable single-file binary. Copy to another machine and
#        double-click; no install needed. Requires Microsoft Edge
#        WebView2 runtime (preinstalled on Windows 11 and most Win10).
#
#   2. BMSecResearch_1.0.0_x64-setup.exe
#      — NSIS installer. Distributable setup with Start Menu entry
#        and uninstaller.
#
# Run from an elevated PowerShell the first time so prereq installers
# can lay themselves down.
#
# Usage:
#   cd <path-to-repo>
#   powershell -ExecutionPolicy Bypass -File .\build-windows.ps1

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Step($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}

function Test-Command($name) {
    return $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

# ── Rust toolchain ──────────────────────────────────────────────────────
Write-Step "Checking Rust toolchain"
if (-not (Test-Command 'cargo')) {
    Write-Host "Rust not found. Installing via rustup-init..." -ForegroundColor Yellow
    $rustupInit = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile $rustupInit
    & $rustupInit -y --default-toolchain stable
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
} else {
    Write-Host "Found: $((cargo --version) 2>&1)" -ForegroundColor Green
}
rustup target add x86_64-pc-windows-msvc | Out-Null

# ── bun ─────────────────────────────────────────────────────────────────
Write-Step "Checking bun"
if (-not (Test-Command 'bun')) {
    Write-Host "bun not found. Installing via official installer..." -ForegroundColor Yellow
    powershell -c "irm bun.sh/install.ps1 | iex"
    $env:Path = "$env:USERPROFILE\.bun\bin;$env:Path"
}
Write-Host "Found: $((bun --version) 2>&1)" -ForegroundColor Green

# ── MSVC Build Tools ────────────────────────────────────────────────────
Write-Step "Checking MSVC Build Tools"
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $msvc = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($msvc) {
        Write-Host "Found: $msvc" -ForegroundColor Green
    } else {
        Write-Host "MSVC C++ Build Tools NOT installed." -ForegroundColor Red
        Write-Host "Install: https://visualstudio.microsoft.com/visual-cpp-build-tools/" -ForegroundColor Yellow
        Write-Host "Required workload: 'Desktop development with C++'" -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Host "Visual Studio installer not found." -ForegroundColor Red
    Write-Host "Install: https://visualstudio.microsoft.com/visual-cpp-build-tools/" -ForegroundColor Yellow
    exit 1
}

# ── WebView2 runtime ────────────────────────────────────────────────────
Write-Step "Checking Edge WebView2 runtime"
$wv2Key = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
if (Test-Path $wv2Key) {
    Write-Host "Found WebView2 runtime." -ForegroundColor Green
} else {
    Write-Host "WebView2 runtime not detected — installer will bootstrap it." -ForegroundColor Yellow
}

# ── Frontend deps ───────────────────────────────────────────────────────
Write-Step "Installing frontend dependencies (bun install)"
Push-Location $PSScriptRoot
try {
    bun install
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    Pop-Location
}

# ── Build ───────────────────────────────────────────────────────────────
#
# Default build includes the `live-ecu` feature (calibration reader,
# HSFZ discovery, clone-from-car). To produce a RESEARCH-ONLY binary
# that cannot talk to real vehicles — simulator + pcap forensics +
# proxy only — comment out the line below and uncomment the
# research-only line underneath it. See SCOPE.md for the rationale.
#
Write-Step "Building release bundle (first build takes a few minutes)"
Push-Location $PSScriptRoot
try {
    # Default: full build with live-ecu enabled
    bun run tauri build
    # Research-only: no live-ECU networking compiled in
    # bun run tauri build -- --no-default-features --features research
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "Build failed with exit code $LASTEXITCODE" -ForegroundColor Red
        exit $LASTEXITCODE
    }
} finally {
    Pop-Location
}

# ── Collect artifacts into release/ ─────────────────────────────────────
Write-Step "Collecting artifacts into release\"

$cargoRelease = Join-Path $PSScriptRoot 'src-tauri\target\release'
$releaseDir   = Join-Path $PSScriptRoot 'release'
New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null

$portable = Get-ChildItem -Path $cargoRelease -Filter '*.exe' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch '^build-script|deps' } |
    Select-Object -First 1
$installer = Get-ChildItem -Path (Join-Path $cargoRelease 'bundle\nsis') -Filter '*-setup.exe' -File -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($portable) {
    Copy-Item $portable.FullName (Join-Path $releaseDir $portable.Name) -Force
}
if ($installer) {
    Copy-Item $installer.FullName (Join-Path $releaseDir $installer.Name) -Force
}

# ── Output summary ──────────────────────────────────────────────────────
Write-Step "Build complete"

Get-ChildItem $releaseDir -File | ForEach-Object {
    $mb = [math]::Round($_.Length / 1MB, 1)
    Write-Host ("  {0,-70} {1} MiB" -f $_.Name, $mb) -ForegroundColor Green
}

Write-Host ""
Write-Host "Artifacts ready in: $releaseDir" -ForegroundColor Cyan
Write-Host ""
