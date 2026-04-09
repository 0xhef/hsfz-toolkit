<script lang="ts">
  // Inline status strip — a mobile-native replacement for floating
  // `position: fixed` toast notifications. Renders in normal document
  // flow at the top of a panel (or wherever the parent places it) so
  // it never has the modal / fixed-positioning problems that affect
  // Android WebView.
  //
  // Usage:
  //
  //   <ToastStrip kind={toastKind} message={toastMessage} onDismiss={() => toastMessage = ''} />
  //
  // Parent holds the state (kind, message) and passes it down. The
  // component auto-dismisses after `ttlMs` ms via an internal timer.
  // Dismissal is communicated back via the `onDismiss` callback so
  // parent state stays the source of truth.

  interface Props {
    kind: 'success' | 'error' | 'info';
    message: string;
    /** Milliseconds before auto-dismiss. 0 = no auto-dismiss. */
    ttlMs?: number;
    onDismiss?: () => void;
  }

  let {
    kind = 'success',
    message = '',
    ttlMs = 5000,
    onDismiss,
  }: Props = $props();

  let timer: ReturnType<typeof setTimeout> | null = null;

  // Reset the auto-dismiss timer whenever a new message arrives.
  // Referencing `message` inside the effect body is how Svelte 5
  // registers the reactivity dependency — no need for a throwaway
  // local binding.
  $effect(() => {
    if (timer) clearTimeout(timer);
    if (message && ttlMs > 0) {
      timer = setTimeout(() => {
        timer = null;
        onDismiss?.();
      }, ttlMs);
    }
    return () => {
      if (timer) clearTimeout(timer);
      timer = null;
    };
  });

  function dismiss() {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    onDismiss?.();
  }

  const borderColor = $derived(
    kind === 'success'
      ? 'var(--accent)'
      : kind === 'error'
        ? 'var(--error)'
        : 'var(--info)',
  );
  const iconColor = $derived(borderColor);
  const iconChar = $derived(
    kind === 'success' ? '✓' : kind === 'error' ? '✕' : 'i',
  );
</script>

{#if message}
  <div
    class="p-4 rounded-lg bg-[var(--bg-secondary)] border-2"
    style="border-color: {borderColor};"
    role="status"
    aria-live="polite"
  >
    <div class="flex items-start gap-3">
      <span
        class="inline-flex items-center justify-center w-6 h-6 rounded-full text-white text-sm font-bold flex-shrink-0"
        style="background-color: {iconColor};"
        aria-hidden="true"
      >
        {iconChar}
      </span>
      <div class="flex-1 min-w-0">
        <div class="text-sm text-[var(--text-primary)] break-words">
          {message}
        </div>
      </div>
      <button
        type="button"
        onclick={dismiss}
        aria-label="Dismiss"
        class="text-[var(--text-secondary)] hover:text-[var(--text-primary)] text-xl leading-none px-2 -mr-2 min-h-[32px] flex-shrink-0"
      >
        ×
      </button>
    </div>
  </div>
{/if}
