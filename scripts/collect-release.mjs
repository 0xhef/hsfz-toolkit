#!/usr/bin/env node
// Collect every build artifact Tauri just produced into `./release/`
// with a consistent, versioned filename.
//
// Tauri scatters outputs across half a dozen build-tool-specific
// directories depending on target (Gradle for Android, MSI/NSIS for
// Windows, app/.dmg for macOS, .deb/.rpm/.AppImage for Linux). This
// script normalises all of that so the user has a single folder to
// look in after any `bun tauri *:build` invocation.
//
// Behavior:
//   - Reads the version from package.json so the filenames track it.
//   - Walks every known output directory, copies what it finds into
//     `release/` with a descriptive filename, and replaces any older
//     file at the same name so `release/` never accumulates stale
//     duplicates of the same target.
//   - Prints a short summary. Never fails the build on missing
//     artifacts — this script runs after both desktop and Android
//     builds and it's fine for a given run to produce only one
//     platform's outputs.

import { existsSync, mkdirSync, copyFileSync, statSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, '..');

const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));
const version = pkg.version || '0.0.0';

const releaseDir = join(repoRoot, 'release');
if (!existsSync(releaseDir)) {
  mkdirSync(releaseDir, { recursive: true });
}

// ── Android APK signing ───────────────────────────────────────────────
//
// Release-mode APKs produced by `tauri android build` are unsigned by
// default and Android refuses to install them ("app not installed").
// We keep a persistent keystore in `.android/bmsec.jks` (gitignored)
// and sign every release APK with it before copying into `release/`.
//
// The keystore is auto-generated on first run using non-interactive
// keytool flags with a generic DN ("CN=BMSecResearch, OU=Research, O=Local")
// and a well-known password baked into this script. Since this is a
// self-signed cert for sideloading only, the password doesn't protect
// anything — it just satisfies keytool's requirement that a key have
// one. If you ever Play-Store-publish, generate a proper keystore
// separately and don't reuse this one.

const androidDir = join(repoRoot, '.android');
const keystorePath = join(androidDir, 'bmsec.jks');
const KEYSTORE_ALIAS = process.env.ANDROID_KEY_ALIAS || 'bmsec';
// Keystore password. Prefer the ANDROID_KEYSTORE_PASSWORD env var (wired
// up from a repo secret in the release workflow). The fallback is only
// used for local dev builds where no env var has been set; it generates
// a throwaway sideload keystore whose password doesn't protect anything
// real. Publishing to a store would use a different, properly-secured
// keystore supplied exclusively via the env var.
const KEYSTORE_PASS = process.env.ANDROID_KEYSTORE_PASSWORD || 'bmsec-sideload';

/** Resolve the path to apksigner. Prefers the newest build-tools. */
function findApksigner() {
  const androidHome =
    process.env.ANDROID_HOME ||
    process.env.ANDROID_SDK_ROOT ||
    (process.platform === 'win32'
      ? join(process.env.LOCALAPPDATA || '', 'Android', 'Sdk')
      : join(process.env.HOME || '', 'Android', 'Sdk'));
  const btDir = join(androidHome, 'build-tools');
  if (!existsSync(btDir)) return null;
  const versions = readdirSync(btDir).sort().reverse();
  for (const v of versions) {
    const candidate = join(btDir, v, process.platform === 'win32' ? 'apksigner.bat' : 'apksigner');
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

function runOrFail(cmd, args, label) {
  const result = spawnSync(cmd, args, { stdio: 'pipe', encoding: 'utf8' });
  if (result.status !== 0) {
    console.error(`✗ ${label} failed:`);
    console.error(result.stdout);
    console.error(result.stderr);
    throw new Error(`${label} exited with code ${result.status}`);
  }
  return result;
}

/** Generate the signing keystore if it doesn't already exist. */
function ensureKeystore() {
  if (existsSync(keystorePath)) return;
  if (!existsSync(androidDir)) mkdirSync(androidDir, { recursive: true });
  console.log(`  → Generating signing keystore at ${keystorePath}`);
  runOrFail(
    'keytool',
    [
      '-genkey',
      '-v',
      '-keystore', keystorePath,
      '-alias', KEYSTORE_ALIAS,
      '-keyalg', 'RSA',
      '-keysize', '2048',
      '-validity', '10000',
      '-storepass', KEYSTORE_PASS,
      '-keypass', KEYSTORE_PASS,
      '-dname', 'CN=BMSecResearch, OU=Research, O=Local, L=Local, ST=Local, C=US',
    ],
    'keytool -genkey',
  );
}

/** Sign an unsigned APK in-place using apksigner. Returns true on success. */
function signApk(unsignedPath) {
  const apksigner = findApksigner();
  if (!apksigner) {
    console.warn(
      '  ⚠ apksigner not found (is ANDROID_HOME set?) — APK will be copied unsigned',
    );
    return false;
  }
  ensureKeystore();
  // apksigner can sign in-place, which is what we want so we don't
  // leave stale signed copies lying around under src-tauri/gen.
  runOrFail(
    apksigner,
    [
      'sign',
      '--ks', keystorePath,
      '--ks-key-alias', KEYSTORE_ALIAS,
      '--ks-pass', `pass:${KEYSTORE_PASS}`,
      '--key-pass', `pass:${KEYSTORE_PASS}`,
      unsignedPath,
    ],
    'apksigner sign',
  );
  return true;
}

// (glob pattern, output filename) pairs. First existing file for
// each pattern gets copied. We prefer release/signed over debug
// when both exist under the same tree.
const plans = [
  // ── Android ───────────────────────────────────────────────────
  {
    name: `BMSecResearch-${version}-android-universal.apk`,
    candidates: [
      'src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk',
      'src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk',
    ],
  },
  {
    name: `BMSecResearch-${version}-android-universal.aab`,
    candidates: [
      'src-tauri/gen/android/app/build/outputs/bundle/universalRelease/app-universal-release.aab',
    ],
  },
  // ── Windows (when built from the Windows side) ────────────────
  {
    name: `BMSecResearch-${version}-windows-x64.msi`,
    candidates: bundleGlob('msi', (f) => f.endsWith('.msi')),
  },
  {
    name: `BMSecResearch-${version}-windows-x64-setup.exe`,
    candidates: bundleGlob('nsis', (f) => f.endsWith('-setup.exe')),
  },
  // ── macOS ─────────────────────────────────────────────────────
  {
    name: `BMSecResearch-${version}-macos.dmg`,
    candidates: bundleGlob('dmg', (f) => f.endsWith('.dmg')),
  },
  // ── Linux ─────────────────────────────────────────────────────
  {
    name: `BMSecResearch-${version}-linux-x86_64.AppImage`,
    candidates: bundleGlob('appimage', (f) => f.endsWith('.AppImage')),
  },
  {
    name: `BMSecResearch-${version}-linux-amd64.deb`,
    candidates: bundleGlob('deb', (f) => f.endsWith('.deb')),
  },
];

/**
 * Tauri places bundles under either:
 *   src-tauri/target/release/bundle/<kind>/                      (no --target)
 *   src-tauri/target/<triple>/release/bundle/<kind>/             (with --target)
 * The CI release workflow always passes --target, so we have to probe
 * every target-triple subdirectory in addition to the bare path.
 */
function bundleGlob(kind, pred) {
  const roots = ['src-tauri/target/release/bundle'];
  const targetDir = join(repoRoot, 'src-tauri/target');
  if (existsSync(targetDir)) {
    for (const entry of readdirSync(targetDir)) {
      const candidate = join('src-tauri/target', entry, 'release/bundle');
      if (existsSync(join(repoRoot, candidate))) roots.push(candidate);
    }
  }
  const out = [];
  for (const root of roots) {
    out.push(...globLike(`${root}/${kind}`, pred));
  }
  return out;
}

/** List files in a directory under `repoRoot` matching a predicate. */
function globLike(relDir, pred) {
  const abs = join(repoRoot, relDir);
  if (!existsSync(abs)) return [];
  return readdirSync(abs)
    .filter(pred)
    .map((f) => join(relDir, f));
}

const collected = [];
const missing = [];

for (const plan of plans) {
  const found = plan.candidates.find((c) => existsSync(join(repoRoot, c)));
  if (!found) {
    missing.push(plan.name);
    continue;
  }
  const src = join(repoRoot, found);

  // If this is the Android APK, sign it in-place before copying so
  // the file that lands in release/ is immediately sideloadable.
  // Only APKs are signed; AABs don't get apksigner treatment (Play
  // Store does their signing on the server side after upload).
  if (plan.name.endsWith('.apk')) {
    try {
      const signed = signApk(src);
      if (signed) {
        console.log(`  → Signed ${plan.name}`);
      }
    } catch (e) {
      console.error(`  ✗ Signing ${plan.name} failed: ${e.message}`);
      console.error('    → APK will be copied unsigned and WILL NOT install on a device.');
    }
  }

  const dst = join(releaseDir, plan.name);
  copyFileSync(src, dst);
  const size = (statSync(dst).size / (1024 * 1024)).toFixed(1);
  collected.push(`${plan.name}  (${size} MB)`);
}

// Delete any sibling log/debug APK we're explicitly not carrying
// forward — keeps the folder tidy across version bumps. Only
// removes files matching our own naming scheme so user files are
// never touched.
const releaseFiles = readdirSync(releaseDir);
const debugArtifacts = releaseFiles.filter((f) => /-debug[-.]/.test(f));
for (const stale of debugArtifacts) {
  console.log(`  (would remove stale debug artifact: ${stale} — leaving in place, delete manually if unwanted)`);
}

console.log('\n=== release/ ===');
if (collected.length === 0) {
  console.log('  (nothing collected — no matching build outputs found)');
} else {
  for (const line of collected) console.log(`  ✓ ${line}`);
}
if (missing.length > 0) {
  console.log('  — not built this run:');
  for (const m of missing) console.log(`    · ${m}`);
}
console.log('');
