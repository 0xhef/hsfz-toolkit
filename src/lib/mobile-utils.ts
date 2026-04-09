// Mobile WebView UI utilities.
//
// These are small helpers that paper over the two biggest gotchas we
// hit while trying to keep the Svelte/Tauri app responsive on Android
// WebView during long-running Tauri commands:
//
//   1. Svelte reactive updates don't necessarily flush to paint before
//      an immediate `await invoke(...)` blocks the JS thread's
//      effective throughput. `tick()` flushes Svelte's reactivity
//      but not the browser paint phase — you need a real animation
//      frame for that.
//
//   2. Returning a large `Vec<u8>` directly from a Tauri command
//      encodes it as a JSON array of numbers, which for multi-MB
//      buffers (4 MB calibration dumps, multi-MB flash binaries)
//      causes multi-second JS-thread freezes when `JSON.parse` runs
//      on the response. The fix is to split into two commands: one
//      that stashes the bytes in Rust app state and returns metadata,
//      and a companion `pull_last_bytes` command that returns the
//      bytes as a `tauri::ipc::Response` which comes across the IPC
//      as a raw `ArrayBuffer` with zero JSON-parsing overhead.

import { invoke } from '@tauri-apps/api/core';
import { tick } from 'svelte';

/// Yield control to the browser so the UI paints before the next
/// synchronous or long-running operation. Runs Svelte's reactive
/// flush (tick) plus two `requestAnimationFrame` waits to guarantee
/// we've crossed a full render → paint cycle on mobile WebView.
///
/// Use this between setting a `$state` variable that controls a
/// visible loading indicator and awaiting a blocking IPC call, so
/// the user sees the loading state appear before the blocking work
/// begins.
///
///     status = 'reading';
///     await flushPaint();       // <-- real paint, not just tick
///     await invoke(...);        // blocks 30s on the ECU
export async function flushPaint(): Promise<void> {
  await tick();
  await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
}

/// Pull the bytes most recently stashed by a Rust command via the
/// `pull_last_bytes` Tauri command. Returns a `Uint8Array` suitable
/// for passing directly to `@tauri-apps/plugin-fs`'s `writeFile`.
///
/// The underlying command returns `tauri::ipc::Response::new(bytes)`
/// which Tauri 2 transfers as a raw binary payload across the IPC
/// bridge — no JSON encoding, no `JSON.parse` freeze on large buffers.
/// On the JS side we receive either an `ArrayBuffer` or a
/// `Uint8Array` depending on Tauri version; both are normalized to
/// `Uint8Array` here.
export async function pullLastBytes(): Promise<Uint8Array> {
  const raw = await invoke<ArrayBuffer | Uint8Array | number[]>(
    'pull_last_bytes',
  );
  if (raw instanceof Uint8Array) return raw;
  if (raw instanceof ArrayBuffer) return new Uint8Array(raw);
  if (Array.isArray(raw)) return new Uint8Array(raw);
  // Tauri 2's Response can arrive as an object with a numeric-keyed
  // buffer; fall back to the raw Array.from coercion.
  return Uint8Array.from(raw as unknown as ArrayLike<number>);
}

/// Pull the per-operation text log most recently stashed by a Rust
/// feature command (e.g. calibration read). Returns the full formatted
/// log as a string, or empty string if nothing is stashed. The caller
/// is expected to write it as a sibling `.log` file next to the
/// artifact using `plugin-fs writeFile`.
export async function pullLastOpLog(): Promise<string> {
  try {
    return await invoke<string>('pull_last_op_log');
  } catch {
    return '';
  }
}

/// Svelte action: when the bound input/textarea/select gains focus,
/// scroll it into the vertical center of the viewport on a rAF tick.
/// Fixes the common Android WebView problem where the virtual
/// keyboard pops up and hides the focused field — the visual viewport
/// shrinks, but the field itself stays where it was unless we force
/// a scroll. Center-alignment is chosen so there's headroom below
/// the field for any helper text / validation errors that appear.
///
/// Usage:
///   <input use:scrollIntoViewOnFocus type="text" ... />
export function scrollIntoViewOnFocus(node: HTMLElement): { destroy(): void } {
  const onFocus = () => {
    // rAF ensures the IME has had a paint cycle to come up so the
    // visual-viewport metrics we'd implicitly scroll against are
    // already updated.
    requestAnimationFrame(() => {
      try {
        node.scrollIntoView({ block: 'center', behavior: 'smooth' });
      } catch {
        // Old WebViews don't support the options object; fall back
        // to the boolean form which always at least aligns top.
        node.scrollIntoView(true);
      }
    });
  };
  node.addEventListener('focus', onFocus);
  return {
    destroy() {
      node.removeEventListener('focus', onFocus);
    },
  };
}

/// Derive a sibling log-file path from an artifact path, replacing
/// the file extension with `.log`. Works for both POSIX/Windows paths
/// and Android Storage Access Framework content URIs — for content
/// URIs, the last URI segment is edited.
export function siblingLogPath(artifactPath: string): string {
  // Find the last segment boundary and the final `.` within it. We
  // intentionally do NOT touch anything before the final segment so
  // SAF URIs like `content://.../document/primary%3ADownload%2Fdump.bin`
  // get their `.bin` → `.log` replaced in place without mangling
  // earlier URL-encoded dots.
  const sepIdx = Math.max(artifactPath.lastIndexOf('/'), artifactPath.lastIndexOf('\\'));
  const dotIdx = artifactPath.lastIndexOf('.');
  if (dotIdx > sepIdx) {
    return artifactPath.slice(0, dotIdx) + '.log';
  }
  return artifactPath + '.log';
}
