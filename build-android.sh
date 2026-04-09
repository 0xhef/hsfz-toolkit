#!/usr/bin/env bash
#
# build-android.sh
#
# One-shot Android build script for BMSecResearch.
#
# Produces signed multi-ABI release APKs (and optionally a debug APK)
# under <repo>/release/, ready to sideload onto a phone or attach to
# a GitHub Release.
#
# Prerequisites (one-time setup, see ANDROID.md for the full guide):
#   * Java 17+ (OpenJDK 21 recommended)
#   * Android SDK + NDK installed under $ANDROID_HOME
#   * Rust toolchain with android targets:
#       rustup target add aarch64-linux-android armv7-linux-androideabi \
#                         i686-linux-android x86_64-linux-android
#   * Tauri CLI 2.x:
#       cargo install tauri-cli --version "^2.0" --locked
#   * bun (or npm/pnpm/yarn equivalent)
#   * A release keystore (one-time, see ANDROID.md § "Generating a
#     release keystore"). Set BMSEC_KEYSTORE_PATH to point at it.
#
# Usage:
#   # Default — signed multi-ABI release APK (sideload bundle)
#   ./build-android.sh
#
#   # Debug build for hot-reload testing
#   ./build-android.sh --debug
#
#   # Rooted-libpcap variant (advanced, requires libpcap cross-compile)
#   ./build-android.sh --features libpcap
#
# Environment variables consumed:
#   ANDROID_HOME            — Android SDK root (default: $HOME/Android/Sdk)
#   NDK_HOME                — NDK root (default: $ANDROID_HOME/ndk/<ver>)
#   JAVA_HOME               — JDK root (default: auto-detected)
#   BMSEC_KEYSTORE_PATH     — release signing keystore (default: $HOME/bmsecresearch-release.jks)
#   BMSEC_KEYSTORE_PASSWORD — keystore password
#   BMSEC_KEY_ALIAS         — key alias inside keystore (default: bmsecresearch)
#   BMSEC_KEY_PASSWORD      — key password
set -euo pipefail

# ── Repo root detection ────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Default env vars (override by exporting before invocation) ─────
: "${ANDROID_HOME:=$HOME/Android/Sdk}"
: "${JAVA_HOME:=$(readlink -f $(which java) 2>/dev/null | sed 's|/bin/java||' || echo /usr/lib/jvm/java-21-openjdk-amd64)}"

# Auto-detect NDK if not explicitly set
if [ -z "${NDK_HOME:-}" ]; then
    NDK_HOME="$(ls -d "$ANDROID_HOME"/ndk/*/ 2>/dev/null | sort -V | tail -1)"
    NDK_HOME="${NDK_HOME%/}"
fi

export ANDROID_HOME
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export NDK_HOME
export ANDROID_NDK_HOME="$NDK_HOME"
export ANDROID_NDK_ROOT="$NDK_HOME"
export JAVA_HOME
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$JAVA_HOME/bin:$PATH"

# ── Argument parsing ───────────────────────────────────────────────
BUILD_TYPE="release"
EXTRA_FEATURES=""
TARGETS="--target aarch64 --target armv7"

while [ $# -gt 0 ]; do
    case "$1" in
        --debug)        BUILD_TYPE="debug"; shift ;;
        --release)      BUILD_TYPE="release"; shift ;;
        --features)     EXTRA_FEATURES=",$2"; shift 2 ;;
        --arm64-only)   TARGETS="--target aarch64"; shift ;;
        -h|--help)
            sed -n '1,40p' "$0"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--debug|--release] [--features <name>] [--arm64-only]" >&2
            exit 1
            ;;
    esac
done

FEATURE_FLAGS="--no-default-features --features android-default${EXTRA_FEATURES}"

# ── Sanity checks ──────────────────────────────────────────────────
echo ""
echo "==> Sanity-checking build environment"
echo "    JAVA_HOME    = $JAVA_HOME"
echo "    ANDROID_HOME = $ANDROID_HOME"
echo "    NDK_HOME     = $NDK_HOME"
echo "    BUILD_TYPE   = $BUILD_TYPE"
echo "    TARGETS      = $TARGETS"
echo "    FEATURES     = $FEATURE_FLAGS"
echo ""

if [ ! -d "$ANDROID_HOME" ]; then
    echo "ERROR: ANDROID_HOME not found: $ANDROID_HOME" >&2
    echo "Install the Android SDK and set ANDROID_HOME, or run the install" >&2
    echo "steps in ANDROID.md." >&2
    exit 1
fi
if [ ! -d "$NDK_HOME" ]; then
    echo "ERROR: NDK_HOME not found: $NDK_HOME" >&2
    echo "Install the Android NDK via sdkmanager or Android Studio." >&2
    exit 1
fi
if ! command -v cargo-tauri >/dev/null 2>&1; then
    echo "ERROR: tauri-cli not installed" >&2
    echo "Run: cargo install tauri-cli --version \"^2.0\" --locked" >&2
    exit 1
fi
if ! command -v bun >/dev/null 2>&1; then
    echo "ERROR: bun not installed" >&2
    echo "Install from https://bun.sh" >&2
    exit 1
fi

# ── Release signing config (warn if missing on release builds) ────
if [ "$BUILD_TYPE" = "release" ]; then
    : "${BMSEC_KEYSTORE_PATH:=$HOME/bmsecresearch-release.jks}"
    if [ ! -f "$BMSEC_KEYSTORE_PATH" ]; then
        echo "WARN: No keystore at $BMSEC_KEYSTORE_PATH — release APK will be unsigned." >&2
        echo "      Set BMSEC_KEYSTORE_PATH to a real keystore for sideload-ready builds." >&2
        echo "      See ANDROID.md § 'Generating a release keystore'." >&2
    else
        export BMSEC_KEYSTORE_PATH
        : "${BMSEC_KEYSTORE_PASSWORD:=}"
        : "${BMSEC_KEY_ALIAS:=bmsecresearch}"
        : "${BMSEC_KEY_PASSWORD:=$BMSEC_KEYSTORE_PASSWORD}"
        export BMSEC_KEYSTORE_PASSWORD BMSEC_KEY_ALIAS BMSEC_KEY_PASSWORD
        echo "    Keystore     = $BMSEC_KEYSTORE_PATH"
    fi
fi

# ── Tauri Android scaffold (one-time per checkout) ─────────────────
if [ ! -d "src-tauri/gen/android" ]; then
    echo ""
    echo "==> Initialising Tauri Android scaffold (first run only)"
    cargo tauri android init
    echo ""
    echo "WARN: src-tauri/gen/android/app/src/main/AndroidManifest.xml" >&2
    echo "      was just generated — you may need to re-add the four" >&2
    echo "      BMSecResearch permissions. See ANDROID.md § 'Required" >&2
    echo "      Android permissions'." >&2
    echo ""
fi

# ── Frontend build ─────────────────────────────────────────────────
if [ ! -d "node_modules" ]; then
    echo ""
    echo "==> Installing frontend dependencies (first run only)"
    bun install
fi

echo ""
echo "==> Building frontend"
bun run build

# ── Android build ──────────────────────────────────────────────────
echo ""
echo "==> Building Android $BUILD_TYPE APK"
if [ "$BUILD_TYPE" = "debug" ]; then
    cargo tauri android build --debug --apk $TARGETS -- $FEATURE_FLAGS
    APK_SRC="src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk"
    APK_DST="release/BMSecResearch-1.0.0-debug.apk"
else
    cargo tauri android build --apk $TARGETS -- $FEATURE_FLAGS
    APK_SRC="src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk"
    APK_DST="release/BMSecResearch-1.0.0-release.apk"
fi

# ── Collect artifact ───────────────────────────────────────────────
mkdir -p release
if [ ! -f "$APK_SRC" ]; then
    echo "ERROR: Expected APK not found at $APK_SRC" >&2
    exit 1
fi
cp "$APK_SRC" "$APK_DST"

# ── Summary ────────────────────────────────────────────────────────
echo ""
echo "==> Build complete"
SIZE=$(ls -lh "$APK_DST" | awk '{print $5}')
echo "    APK    : $APK_DST ($SIZE)"

# Print signing info for release builds
if [ "$BUILD_TYPE" = "release" ] && [ -f "$ANDROID_HOME/build-tools/34.0.0/apksigner" ]; then
    echo ""
    echo "    Signing scheme:"
    "$ANDROID_HOME/build-tools/34.0.0/apksigner" verify --verbose "$APK_DST" 2>&1 \
        | grep -E "^Verified" | sed 's/^/      /'
    echo ""
    echo "    SHA-256 cert fingerprint (publish in release notes for verification):"
    "$ANDROID_HOME/build-tools/34.0.0/apksigner" verify --print-certs "$APK_DST" 2>&1 \
        | grep -i "SHA-256" | sed 's/^/      /'
fi

# Print embedded permissions and ABIs
if [ -f "$ANDROID_HOME/build-tools/34.0.0/aapt" ]; then
    echo ""
    echo "    Permissions:"
    "$ANDROID_HOME/build-tools/34.0.0/aapt" dump permissions "$APK_DST" 2>&1 \
        | grep "^uses-permission" | sed 's/^/      /'
    echo ""
    echo "    ABIs:"
    unzip -l "$APK_DST" 2>&1 | grep -E "\.so$" | awk '{print "      " $4}'
fi

echo ""
