<script lang="ts">
  import type { CaptureStatus } from '../../types';

  interface Props {
    canStart: boolean;
    canStop: boolean;
    status: CaptureStatus;
    onStart: () => void;
    onStop: () => void;
  }

  let { canStart, canStop, status, onStart, onStop }: Props = $props();

  const statusLabel = $derived(
    status === 'starting'
      ? 'Starting capture...'
      : status === 'stopping'
        ? 'Stopping and processing...'
        : ''
  );
</script>

<div class="flex items-center gap-3">
  {#if status === 'idle'}
    <button
      onclick={onStart}
      disabled={!canStart}
      class="px-6 py-2.5 bg-[var(--success)] text-white rounded font-medium
             hover:brightness-110 transition-all
             disabled:opacity-50 disabled:cursor-not-allowed"
    >
      Start Capture
    </button>
  {:else if status === 'capturing'}
    <button
      onclick={onStop}
      disabled={!canStop}
      class="px-6 py-2.5 bg-[var(--error)] text-white rounded font-medium
             hover:brightness-110 transition-all"
    >
      Stop Capture
    </button>
    <div class="flex items-center gap-2">
      <div class="w-2 h-2 rounded-full bg-[var(--error)] animate-pulse"></div>
      <span class="text-sm text-[var(--text-secondary)]">Capturing...</span>
    </div>
  {:else if status === 'starting' || status === 'stopping'}
    <div class="flex items-center gap-3">
      <div class="w-5 h-5 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin"></div>
      <span class="text-[var(--text-secondary)]">{statusLabel}</span>
    </div>
  {/if}
</div>
