<script lang="ts">
  import type { UdsEvent } from '../types';

  interface Props {
    events: UdsEvent[];
  }

  let { events }: Props = $props();
  let expanded = $state(false);

  function eventColor(type: string): string {
    switch (type) {
      case 'RequestDownload': return 'text-[var(--accent)]';
      case 'TransferExit': return 'text-[var(--success)]';
      case 'Erase': return 'text-[var(--warning)]';
      case 'NRC': return 'text-[var(--error)]';
      case 'VIN': return 'text-purple-400';
      case 'ECUReset': return 'text-orange-400';
      case 'SecurityAccess': return 'text-cyan-400';
      case 'DiagSession': return 'text-emerald-400';
      default: return 'text-[var(--text-secondary)]';
    }
  }

  const displayEvents = $derived(expanded ? events : events.slice(0, 20));
</script>

<div class="rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)] overflow-hidden">
  <div class="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between">
    <h2 class="text-sm font-semibold text-[var(--text-primary)]">
      UDS Event Log ({events.length} events)
    </h2>
    {#if events.length > 20}
      <button
        onclick={() => expanded = !expanded}
        class="text-xs text-[var(--accent)] hover:text-[var(--accent-hover)]"
      >
        {expanded ? 'Collapse' : 'Show All'}
      </button>
    {/if}
  </div>
  <div class="max-h-80 overflow-y-auto">
    <div class="p-3 space-y-0.5 font-mono text-xs">
      {#each displayEvents as evt}
        <div class="flex gap-2">
          <span class="{eventColor(evt.event_type)} min-w-[140px]">{evt.event_type}</span>
          <span class="text-[var(--text-secondary)]">{evt.detail}</span>
        </div>
      {/each}
    </div>
  </div>
</div>
