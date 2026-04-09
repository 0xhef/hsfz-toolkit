// Haptic feedback wrapper.
//
// `navigator.vibrate` is a web platform API that maps to Android's
// system vibrator through WebView. iOS Safari ignores it. Desktop
// browsers ignore it (there's no hardware). So this is effectively a
// no-op everywhere except Android, which is exactly what we want — we
// get tactile confirmation of key actions on mobile without needing
// platform detection or any extra permissions.
//
// All entry points are wrapped in try/catch because some browsers
// gate the API behind a user-gesture requirement and throw if called
// too early; some embedded WebViews disable it entirely; and we never
// want a missed vibration to break a feature.

type HapticKind =
  | 'light'   // tap confirmation
  | 'medium'  // action kicked off (start read, save)
  | 'heavy'   // destructive / important (cancel, delete)
  | 'success' // success flourish (read complete)
  | 'warning' // non-fatal alert (retry, reconnect)
  | 'error';  // failure (read failed, connection lost)

// Vibration patterns. Single number = ms on; array = [on, off, on, ...].
// Kept short so they feel like tactile punctuation rather than alarms.
const patterns: Record<HapticKind, number | number[]> = {
  light: 8,
  medium: 18,
  heavy: 32,
  success: [12, 40, 24],
  warning: [20, 40, 20],
  error: [28, 50, 28, 50, 28],
};

/** Trigger a haptic pulse. No-op on platforms without vibrator support. */
export function haptic(kind: HapticKind = 'light'): void {
  try {
    if (typeof navigator === 'undefined') return;
    if (typeof navigator.vibrate !== 'function') return;
    navigator.vibrate(patterns[kind]);
  } catch {
    // Swallow — never let haptics break a user action.
  }
}
