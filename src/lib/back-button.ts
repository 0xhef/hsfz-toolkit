// Android hardware back-button handling via the History API.
//
// Tauri Android's WebView forwards the hardware back button to
// WebView.goBack(), which the History API surfaces as a `popstate`
// event. We use that to implement a stack of "closers" — functions
// that collapse the topmost overlay/inline-view back to its parent
// when the user hits the back button.
//
// Mental model:
//   - Every time a modal / inline card / wizard step opens, it
//     registers a closer via `pushCloser(fn)`. That registration
//     also pushes a dummy history entry.
//   - When the user taps the system back button, Android pops the
//     top history entry, `popstate` fires, we pop the top closer
//     off our stack and call it. The closer flips the component's
//     Svelte `$state` to dismiss the overlay.
//   - When the user closes the overlay some other way (tapping an
//     in-UI close button, finishing a wizard, etc.), the caller
//     invokes the returned unregister function. We remove the
//     closer from the stack and walk history back one step so the
//     dummy entry doesn't linger.
//
// Fallback behaviour: if no closers are registered, we let the
// back press pass through unchanged — Tauri's WryActivity will
// finish() and the app exits, which is the expected "I'm at the
// root, back takes me out" behaviour.

type Closer = () => void;

const stack: Closer[] = [];

// Set while we're programmatically walking history back so the
// popstate handler doesn't try to pop an already-removed closer.
let internalPop = false;

// Initialised once per page load. Guarded because HMR may re-import
// this module during dev without reloading the page.
let installed = false;

function install(): void {
  if (installed) return;
  if (typeof window === 'undefined') return;
  installed = true;

  window.addEventListener('popstate', () => {
    if (internalPop) return;
    if (stack.length === 0) return;
    const closer = stack.pop();
    try {
      closer?.();
    } catch (e) {
      console.warn('back-button closer threw:', e);
    }
  });
}

/**
 * Register a closer for the current overlay/inline-view. The returned
 * unregister function MUST be called when the view is closed through
 * non-back-button means (in-UI close button, success transition, etc.)
 * so the history stack stays in sync.
 *
 * Typical usage in a Svelte 5 component:
 *
 *   $effect(() => {
 *     if (status === 'reading') {
 *       const unreg = pushCloser(() => { handleCancel(); });
 *       return unreg;
 *     }
 *   });
 */
export function pushCloser(closer: Closer): () => void {
  install();
  if (typeof window === 'undefined') return () => {};

  stack.push(closer);
  try {
    window.history.pushState({ bmsec: Date.now() }, '');
  } catch {
    // Some embedded WebViews restrict pushState; degrade gracefully.
  }

  return () => {
    const idx = stack.lastIndexOf(closer);
    if (idx < 0) return;
    stack.splice(idx, 1);
    // Walk history back one step to consume the dummy entry we
    // pushed above. Guard with `internalPop` so the popstate
    // handler sees "this was programmatic, don't run a closer".
    try {
      internalPop = true;
      window.history.back();
      // popstate fires asynchronously; clear the flag on the next
      // microtask so it's false by the time the event lands.
      queueMicrotask(() => {
        internalPop = false;
      });
    } catch {
      internalPop = false;
    }
  };
}
