// Persistent form state across app launches.
//
// Android's WebView can be killed aggressively when the app is
// backgrounded (e.g. when the user goes to pick a file and returns).
// In-memory Svelte `$state` values are lost on that cycle, which
// means the user has to retype the gateway IP, ECU address, and
// save-format every time. `localStorage` survives the restart
// because it's backed by the WebView's on-disk storage, so stashing
// form values there gives us "remember where I was" behaviour
// without any Rust-side plumbing.
//
// All entry points are defensive: private-mode Safari, quota-exceeded
// errors, corrupt JSON — every failure silently falls back to the
// caller-provided default rather than crashing the panel.

const PREFIX = 'bmsec:';

/** Load a persisted value by key. Returns `fallback` on any error. */
export function loadPersisted<T>(key: string, fallback: T): T {
  try {
    if (typeof localStorage === 'undefined') return fallback;
    const raw = localStorage.getItem(PREFIX + key);
    if (raw === null) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

/** Store a value under the given key. Silently drops on any error. */
export function savePersisted<T>(key: string, value: T): void {
  try {
    if (typeof localStorage === 'undefined') return;
    localStorage.setItem(PREFIX + key, JSON.stringify(value));
  } catch {
    // Private mode, quota exceeded, disabled storage — we can't
    // meaningfully recover, and persistence is a nice-to-have.
  }
}

/** Remove a persisted value. */
export function clearPersisted(key: string): void {
  try {
    if (typeof localStorage === 'undefined') return;
    localStorage.removeItem(PREFIX + key);
  } catch {
    // ignore
  }
}
