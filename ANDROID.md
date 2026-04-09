# BMSecResearch on Android

A guide to building, signing, sideloading, and using the Android variant
of BMSecResearch.

> [!IMPORTANT]
> The Android variant is **sideload-only**. There is no Play Store
> listing. Distribution is via signed APK attached to GitHub Releases.
> See the [SCOPE.md](SCOPE.md) and [DISCLAIMER.md](DISCLAIMER.md) for
> the legal framing — both apply identically to the Android variant.

---

## What's different on Android

| Component | Desktop | Android (default sideload) | Android (rooted, opt-in) |
|---|---|---|---|
| **Extract from PCAP** | ✅ | ✅ | ✅ |
| **Capture Flash (libpcap)** | ✅ | ❌ Hidden | ✅ if `--features libpcap` |
| **Calibration Read** | ✅ | ✅ | ✅ |
| **DME Simulator** | ✅ | ✅ | ✅ |
| **DME Proxy** | ✅ | ✅ | ✅ |
| **HSFZ Discovery** | ✅ | ✅ | ✅ |

Capability is **gated by Cargo feature, not by platform**. The default
sideload Android build (`--features android-default`) omits the
`libpcap` feature, so the `Capture Flash` tab is hidden via the
runtime `has_live_capture` Tauri command. A rooted-Android build with
a working libpcap-for-Android cross-compile can re-enable the feature
via `--features libpcap` and gets the full Capture tab.

The frontend never inspects the platform string for capability
decisions — it only asks `has_live_capture()`, which reflects what's
actually compiled in. This means the same Svelte code works correctly
across desktop, sideload Android, and rooted Android builds without
any platform-specific branches in the UI logic.

The single behavioral difference operators need to know about: **on
Android, capture is always done via the Proxy tab**, not via passive
sniffing. The operator points their tester at the phone's IP instead of
the car's gateway IP, and the proxy logs every frame in transit. The
resulting session can be exported as `.pcap` and analyzed in the
Extract from PCAP tab — same end result, different mechanism. See
[SCOPE.md § Platform support](SCOPE.md#platform-support-and-the-libpcap--proxy-capture-story).

## Network topology

BMSecResearch works over **any IP-capable network interface** the
Android OS exposes — WiFi, USB-Ethernet, USB-OTG ENET dongles,
Bluetooth PAN. Internally the Rust networking code uses
`std::net::TcpStream` and `std::net::UdpSocket` which are
interface-agnostic; the OS's routing table picks the right netif
automatically. There is no platform-specific code path for "WiFi
mode" vs "Ethernet mode".

This section lists the topologies known to work and the operator
steps for each.

### Option A — WiFi-OBD adapter (most common)

A self-hosted WiFi access point inside the OBD/ENET adapter. The phone
joins the adapter's WiFi network, gets an IP via the adapter's DHCP,
and talks raw TCP to the BMW gateway through the adapter.

Adapters known to work in this topology with similar tools
(BMSecResearch has not been tested with all of them — verify yourself):

- **MHD WiFi Cable** — purpose-built for the MHD app, works generically
  with any tool that speaks HSFZ over TCP
- **OBDLink MX+** in WiFi mode — primarily OBD-II diagnostics, may or
  may not expose the full ENET stack depending on firmware
- Generic **ENET-to-WiFi bridges** sold by various tuning vendors

Operator steps:

1. Plug the WiFi-OBD adapter into the car's OBD-II port and wait for
   it to boot (LEDs solid)
2. On the phone, open Settings → WiFi and join the adapter's SSID
3. Wait until the phone reports "Connected (no internet)" — that's
   normal, the adapter doesn't route to WAN
4. Open BMSecResearch → Calibration Read tab
5. Tap *Discover* — the broadcast probe goes out the WiFi interface,
   the gateway responds, the IP appears in the device list
6. Tap *Start Read*

### Option B — USB-OTG → Ethernet adapter, phone joins car's ENET subnet

Some operators prefer a wired connection for reliability. Plug a
USB-C → Ethernet adapter into the phone (USB host mode), connect a
standard ENET cable from the adapter to the car's OBD port, and the
phone gets an IP from the car's gateway DHCP just like a laptop would.

Hardware notes:

- **Phone** must support USB-C host mode (USB-OTG). All Pixel models
  since Pixel 1, Samsung S/Note since S6, OnePlus since OnePlus 5,
  most other Android flagships from the last decade. Cheap budget
  phones often skip USB host mode — check your phone's spec sheet.
- **USB-Ethernet adapter** must use a chipset Android's kernel
  supports out of the box. Known-good chipsets:
    - **AX88179** / AX88179A (ASIX) — works on every modern Android
    - **RTL8153** (Realtek) — works on every modern Android
    - **AX88772** — older but widely supported
  Adapters built around these chips are sold under many brands
  (Anker, UGREEN, Plugable, generic) for $15-30. Avoid no-name
  adapters with unknown chipsets.
- **No special permissions** needed. Android manages USB-Ethernet
  natively at the kernel/system level — apps don't talk to USB
  directly for network adapters. The four permissions BMSecResearch
  already requests are sufficient.

Operator steps:

1. Plug USB-OTG ENET adapter into the phone (host mode)
2. Plug ENET cable from adapter into car's OBD port
3. Wait ~5 seconds for Android's network manager to bring up the
   interface and DHCP an IP from the car. You can verify this in
   Settings → About phone → Status → IP address (it should show the
   Ethernet IP, often `160.48.x.x` or `169.254.x.x` on BMW chassis).
4. Open BMSecResearch → Calibration Read tab
5. Tap *Discover*. The broadcast goes out the Ethernet interface,
   the gateway responds, the IP appears
6. Tap *Start Read*

### Option C — Phone provides DHCP via Ethernet tethering (BMW uses phone as upstream)

Some BMW chassis have an ENET gateway that expects to be a DHCP
**client** — it requests an IP from whatever's plugged into the
other end of the cable. In that topology, the *phone* needs to act
as a DHCP server.

Android 11+ supports **Ethernet tethering** as a system feature. The
phone becomes a DHCP/router for any device plugged into a USB-Ethernet
adapter, and the car gets a DHCP lease just like it would from a
home router.

This is a system-level setting — BMSecResearch doesn't control it,
but you only enable it once per phone:

1. Plug USB-OTG ENET adapter into the phone (do not connect the
   car yet)
2. On the phone, open **Settings → Network & internet → Hotspot &
   tethering → Ethernet tethering** (path varies slightly by OEM
   and Android version; on stock Android 11+ it's there directly,
   on Samsung One UI it's under Connections → Mobile Hotspot and
   Tethering)
3. Toggle Ethernet tethering ON. The phone starts a DHCP server on
   the USB-Ethernet interface, typically handing out leases in
   `192.168.42.x` or `192.168.49.x`
4. Plug the ENET cable from the adapter into the car's OBD port
5. The car requests a DHCP lease and the phone hands one out. You
   can verify by checking the Ethernet tethering status screen,
   which lists connected clients with their leased IPs
6. Open BMSecResearch → Calibration Read tab
7. Type the leased IP into the *Advanced → Gateway IP* field, or
   tap *Discover* if the gateway responds to broadcast probes
8. Tap *Start Read*

If your phone's Settings app doesn't show Ethernet tethering, your
OEM has disabled it. Some phones (older models, some heavily-skinned
ROMs) don't expose the option. Workarounds: install a stock-Android
ROM, use a different phone, or fall back to Option A (WiFi adapter).

### Option D — Bluetooth tethering

Same `std::net` abstraction; if Android routes traffic through a
Bluetooth PAN connection, BMSecResearch uses it. Latency is usually
too high for practical flash reads, but it works for diagnostic
discovery and small read operations. Not recommended for the full
~511 KB calibration read.

### Multi-interface routing — the one nuance to know about

If the phone has **both** an active WiFi connection (e.g., to your
home network) AND a USB-Ethernet adapter active simultaneously,
Android's `ConnectivityManager` defaults outbound traffic to the
"default network" — usually WiFi. A connection to a private IP that
happens to overlap your home subnet can race-route through the wrong
NIC.

Two ways to handle this:

1. **Operator workaround (zero code changes):** turn off WiFi when
   you're using USB-Ethernet for diagnostic work. Tuners do this
   anyway because it eliminates ambiguity.

2. **App-side fix (future):** bind the TCP socket to a specific local
   interface using `ConnectivityManager.bindProcessToNetwork()`.
   Requires a JNI shim. Will be added if multi-interface routing
   causes problems in real-world testing.

### Verifying the topology works on the bench

Before trusting any of the above, do this sanity check:

1. Connect the phone to the chosen network (WiFi adapter, USB-Eth,
   tether, etc.)
2. Open **any HTTP/TCP test app** — Termux's `nc`, an Android port
   scanner, an "IP info" app — and confirm the phone's IP is on the
   expected subnet
3. From a *separate* device on the same network (a laptop, another
   phone), try to `ping` the BMW gateway. If that works, the wire is
   good. If it doesn't, the problem is the cable / adapter / car,
   not BMSecResearch.
4. Only then launch BMSecResearch and try Discover. If Discover
   fails but `ping` works, the issue is broadcast routing (some
   adapters block UDP broadcast). Fall back to typing the IP
   manually in the Advanced section.

## Building from source

### Prerequisites

You need everything required for the desktop build, plus:

```sh
# Android SDK + NDK (one-time install)
# Easiest: install Android Studio and let it manage the SDK/NDK
# Or: download command-line tools from https://developer.android.com/studio
# After installing, set:
export ANDROID_HOME="$HOME/Android/Sdk"             # or wherever you installed
export NDK_HOME="$ANDROID_HOME/ndk/<version>"
export PATH="$ANDROID_HOME/platform-tools:$PATH"

# Rust targets for Android ABIs
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android

# Tauri CLI must be 2.x with mobile support
cargo install tauri-cli --version "^2.0" --locked
```

### Initial scaffold

Run once per repository to generate the `src-tauri/gen/android/` Gradle
project:

```sh
cd <repo>
bun run tauri android init
```

This produces:

- `src-tauri/gen/android/` — Gradle project
- `src-tauri/gen/android/app/src/main/AndroidManifest.xml` — manifest
  stub you'll need to customize for permissions
- `src-tauri/gen/android/app/build.gradle.kts` — build config

The `gen/` directory is in `.gitignore` (it should be — these are
generated build artifacts, not source). Each developer regenerates it
on first build.

### Required Android permissions

Edit `src-tauri/gen/android/app/src/main/AndroidManifest.xml` and add
these permissions inside the `<manifest>` element:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
<uses-permission android:name="android.permission.CHANGE_WIFI_MULTICAST_STATE" />
```

- `INTERNET` — required for any TCP/UDP socket operations. Mandatory.
- `ACCESS_NETWORK_STATE` — needed to detect WiFi connectivity changes
  (so the calibration reader can refuse to run when the phone is on
  cellular instead of the OBD adapter's WiFi).
- `ACCESS_WIFI_STATE` — needed to read the current WiFi SSID and IP
  configuration.
- `CHANGE_WIFI_MULTICAST_STATE` — needed for HSFZ vehicle discovery,
  which uses UDP broadcast. Without this permission *and* a runtime
  `WifiManager.MulticastLock` held during the discovery window,
  Android's WiFi driver silently drops broadcast packets in power-save
  mode.

These are all "normal" permissions — they don't require runtime user
consent and don't trigger the Play Protect runtime permission flow.

### Generating a release keystore

You sign every release APK with a keystore. Generate it once, store it
securely, and **never lose it** — losing the keystore means existing
installs cannot upgrade to a new version (Android refuses to install an
APK signed with a different key over one signed with the old key).

```sh
keytool -genkey -v \
  -keystore bmsecresearch-release.jks \
  -alias bmsecresearch \
  -keyalg RSA -keysize 4096 \
  -validity 10000

# Answer the prompts. For pseudonymous publishing:
#   First and last name: BMSecResearch
#   Organizational unit: (blank)
#   Organization: BMSecResearch
#   City: (blank or "Internet")
#   State: (blank)
#   Country code: (blank or "XX")
# Set a strong passphrase. Save it in a password manager.
# DO NOT commit the keystore to git. Add it to .gitignore.
```

Add the keystore reference to `src-tauri/gen/android/app/build.gradle.kts`:

```kotlin
android {
    signingConfigs {
        create("release") {
            storeFile = file("/absolute/path/to/bmsecresearch-release.jks")
            storePassword = System.getenv("BMSEC_KEYSTORE_PASSWORD")
            keyAlias = "bmsecresearch"
            keyPassword = System.getenv("BMSEC_KEY_PASSWORD")
        }
    }
    buildTypes {
        getByName("release") {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = false
        }
    }
}
```

Set the passwords in your shell environment before building, so they
never end up in source:

```sh
export BMSEC_KEYSTORE_PASSWORD="<your-passphrase>"
export BMSEC_KEY_PASSWORD="<your-passphrase>"
```

### Build commands

There are two Android build flavors: the default **sideload** bundle
(no libpcap, works on every phone) and the **rooted-libpcap** bundle
(requires a cross-compiled libpcap, only useful on rooted devices that
can grant `CAP_NET_RAW` to user processes).

#### Sideload bundle — recommended for everyone

This is the build you ship to GitHub Releases. It works on every
Android device, no root needed, no extra dependencies.

```sh
# Debug build to a connected device or emulator (hot reload)
bun run tauri android dev -- --no-default-features --features android-default

# Release build (signed APK)
bun run tauri android build -- --no-default-features --features android-default
```

The Capture Flash tab is hidden in the UI. Capture is done via the
Proxy tab — the operator points their tester at the phone's IP, the
proxy logs every frame, and `proxy_export_pcap` produces a Wireshark-
compatible `.pcap` that the Extract from PCAP tab can re-ingest.

#### Rooted-libpcap bundle — opt-in, advanced

If you have a **rooted Android device** with a cross-compiled libpcap
available to the build environment, you can enable the live Capture
Flash tab by adding the `libpcap` feature:

```sh
bun run tauri android build -- --features libpcap
```

This requires you to have:

1. A working **libpcap cross-compile for Android** in your build env.
   The simplest path is to build libpcap from the upstream source for
   the `aarch64-linux-android` target using the NDK toolchain. There
   is no prebuilt libpcap in the NDK, so you have to do this yourself.
   Termux's libpcap package is *not* usable here — that's for binaries
   running inside Termux on a rooted phone, not for an APK.
2. Cargo configured to find the cross-compiled libpcap headers and
   shared library at build time. Set `PKG_CONFIG_PATH`,
   `LIBPCAP_LIBDIR`, and `LIBPCAP_VER` as the `pcap` crate's build
   script expects.
3. A **rooted target device** with `CAP_NET_RAW` available to non-
   system apps. On most modern Android versions this requires an
   `su`-via-Magisk grant to the BMSecResearch process at runtime. The
   capture engine itself doesn't request root — it expects the
   capability to already be present when it tries to open the
   interface — so the user needs to launch the app with elevated
   privileges (`su -c am start -n org.bmsecresearch.app/.MainActivity`)
   or use a Magisk module that grants the capability persistently.

This build flavor is **not officially distributed**. If you want it,
you build it yourself. The reason: the cross-libpcap toolchain is
fragile, the rooted-target requirements vary across Magisk versions,
and the resulting APK only works for the specific operator who built
it. There's no general "rooted Android sideload APK with libpcap" we
can ship that would Just Work on arbitrary phones.

The signed APK from either flavor lands at:

```
src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk
```

Rename it to `BMSecResearch-1.0.0.apk` (or
`BMSecResearch-1.0.0-libpcap.apk` for the rooted variant) before
uploading to a release.

## Sideload distribution

### Hosting

Attach the signed APK as an asset on the relevant GitHub Release:

```sh
gh release create v1.0.0 \
    ./release/bmsecresearch.exe \
    "./release/BMSecResearch_1.0.0_x64-setup.exe" \
    ./BMSecResearch-1.0.0.apk \
    --title "v1.0.0 — initial public release" \
    --notes-file RELEASE-NOTES.md
```

Optionally also submit to **F-Droid** — their inclusion policy is
permissive for open-source security research projects, the build farm
reproduces from source (good for trust), and there is no review queue
for privacy/permissions in the way Play Store has.

### End-user install flow

Document this in the release notes so first-time users know what to
expect. The flow on a fresh modern Android phone:

1. Download the APK from the GitHub Release (browser, F-Droid client,
   or `adb install` from a desktop)
2. Tap the APK to open. Android shows: *"For your security, your phone
   is not allowed to install unknown apps from this source."*
3. The user taps *Settings* and toggles *Allow from this source* for
   whichever app they downloaded with (Chrome, Firefox, Files, etc.)
4. Return to the install prompt. Android shows: *"Do you want to
   install this app?"* — tap *Install*.
5. Play Protect may show a one-time *"App not commonly downloaded"*
   warning. The user taps *Install anyway*. After install, Play Protect
   does not warn again unless the APK is updated.
6. Launch BMSecResearch. The app requests no runtime permissions on
   first launch (the four permissions above are all "normal" install-
   time permissions, granted automatically).
7. Connect to the OBD adapter's WiFi network. Run a calibration read or
   open a proxy session.

### Verifying the APK signature

Before publishing the release, verify the signed APK:

```sh
# Check the APK is signed
apksigner verify --verbose ./BMSecResearch-1.0.0.apk

# Print the signing certificate fingerprint — publish this in the
# release notes so users can verify they got the real APK
apksigner verify --print-certs ./BMSecResearch-1.0.0.apk | grep SHA-256

# After install, verify the installed package matches:
adb shell pm dump org.bmsecresearch.app | grep -A1 'signing'
```

## Anonymity hygiene for the Android build

The same anonymity considerations from the desktop build apply, plus
some Android-specific ones:

- **Build from a clean WSL or Linux environment**, not your daily Mac
  with personal files in `$HOME`. The NDK toolchain doesn't usually
  bake `$HOME` paths into the binary, but the keystore subject does
  end up in the APK signature.
- **Keystore subject fields** (CN, OU, O, L, ST, C) are visible to
  anyone who runs `apksigner verify --print-certs`. Use neutral values
  like the example above (`CN=BMSecResearch, O=BMSecResearch, C=XX`).
  Do not put your real name, email, or location in there.
- **Don't reuse a keystore from another project**. Each project gets a
  fresh keystore with a unique alias. If you reuse, the cert
  fingerprint links the two projects publicly.
- **Strip debug symbols from the Rust shared library before packaging**
  (`[profile.release] strip = true` in `Cargo.toml` already covers
  this). The Android build uses the same release profile as desktop.
- **Disable `applicationIdSuffix`** in build.gradle.kts (it defaults to
  empty for release builds, but check) — otherwise you get
  `org.bmsecresearch.app.debug` in the package name on debug builds
  and that can leak into crash reports.

## What this build does *not* include

For clarity, in case anyone reviews the APK and wonders:

- No Play Services SDK
- No Firebase / analytics / telemetry of any kind
- No third-party SDKs other than what Tauri pulls in (mostly Android
  WebView and standard Kotlin/Java runtime)
- No background services that run when the app is closed
- No notification channels
- No location permission
- No camera, microphone, contacts, or storage permissions beyond the
  system file picker for opening `.pcap` files
- No analytics, crash reporting, or remote logging — all logs are
  written to local app storage and stay on the device

The minimal permission set is intentional: it makes the APK trivially
auditable (`apkanalyzer manifest permissions BMSecResearch-1.0.0.apk`)
and gives reviewers no surprises.
