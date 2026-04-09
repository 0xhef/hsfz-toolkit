<script lang="ts">
  import type { CaptureStats, CaptureStatus } from '../../types';

  interface Props {
    stats: CaptureStats;
    status: CaptureStatus;
  }

  let { stats, status }: Props = $props();

  const formattedElapsed = $derived.by(() => {
    const mins = Math.floor(stats.duration_secs / 60);
    const secs = Math.floor(stats.duration_secs % 60);
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  });

  const formattedBytes = $derived.by(() => {
    if (stats.byte_count >= 1024 * 1024) {
      return `${(stats.byte_count / 1024 / 1024).toFixed(2)} MB`;
    }
    if (stats.byte_count >= 1024) {
      return `${(stats.byte_count / 1024).toFixed(1)} KB`;
    }
    return `${stats.byte_count} B`;
  });
</script>

<div class="rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)] overflow-hidden">
  <div class="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between">
    <h2 class="text-sm font-semibold text-[var(--text-primary)]">Capture Statistics</h2>
    {#if status === 'capturing'}
      <div class="flex items-center gap-2">
        <div class="w-2 h-2 rounded-full bg-[var(--success)] animate-pulse"></div>
        <span class="text-xs text-[var(--success)]">LIVE</span>
      </div>
    {:else if status === 'stopping'}
      <span class="text-xs text-[var(--warning)]">Processing...</span>
    {/if}
  </div>
  <div class="grid grid-cols-4 gap-4 p-4">
    <div class="text-center">
      <div class="text-2xl font-mono font-bold text-[var(--text-primary)]">
        {stats.packet_count.toLocaleString()}
      </div>
      <div class="text-xs text-[var(--text-secondary)] mt-1">Packets</div>
    </div>
    <div class="text-center">
      <div class="text-2xl font-mono font-bold text-[var(--text-primary)]">
        {formattedBytes}
      </div>
      <div class="text-xs text-[var(--text-secondary)] mt-1">Data</div>
    </div>
    <div class="text-center">
      <div class="text-2xl font-mono font-bold text-[var(--accent)]">
        {stats.packets_per_sec.toFixed(1)}
      </div>
      <div class="text-xs text-[var(--text-secondary)] mt-1">Pkts/sec</div>
    </div>
    <div class="text-center">
      <div class="text-2xl font-mono font-bold text-[var(--text-primary)]">
        {formattedElapsed}
      </div>
      <div class="text-xs text-[var(--text-secondary)] mt-1">Elapsed</div>
    </div>
  </div>
</div>
