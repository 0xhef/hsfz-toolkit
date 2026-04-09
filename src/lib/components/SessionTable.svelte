<script lang="ts">
  import type { FlashSegment } from '../types';

  interface Props {
    segments: FlashSegment[];
    baseAddress: number;
  }

  let { segments, baseAddress }: Props = $props();

  function formatAddr(addr: number): string {
    return '0x' + addr.toString(16).toUpperCase().padStart(8, '0');
  }

  function formatSize(bytes: number): string {
    if (bytes >= 1024 * 1024) {
      return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
    }
    if (bytes >= 1024) {
      return `${(bytes / 1024).toFixed(1)} KB`;
    }
    return `${bytes} B`;
  }

  function segmentName(addr: number): string {
    const offset = addr - baseAddress;
    if (offset === 0) return 'BTLD Header';
    if (offset >= 0x20000 && offset < 0x180000) return 'SWFK';
    if (offset >= 0x180000 && offset < 0x220000) return 'CAFD';
    if (offset >= 0x220000) return 'SWFL';
    return 'Data';
  }
</script>

<div class="rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)] overflow-hidden">
  <div class="px-4 py-3 border-b border-[var(--border)]">
    <h2 class="text-sm font-semibold text-[var(--text-primary)]">Flash Segments</h2>
  </div>
  <table class="w-full text-sm">
    <thead>
      <tr class="text-[var(--text-secondary)] text-xs uppercase">
        <th class="px-4 py-2 text-left">Address</th>
        <th class="px-4 py-2 text-left">Segment</th>
        <th class="px-4 py-2 text-right">Size</th>
        <th class="px-4 py-2 text-right">Blocks</th>
        <th class="px-4 py-2 text-center">Status</th>
      </tr>
    </thead>
    <tbody>
      {#each segments as seg}
        <tr class="border-t border-[var(--border)]/50 hover:bg-[var(--bg-tertiary)]/30">
          <td class="px-4 py-2 font-mono text-[var(--accent)]">{formatAddr(seg.address)}</td>
          <td class="px-4 py-2">{segmentName(seg.address)}</td>
          <td class="px-4 py-2 text-right font-mono">{formatSize(seg.actual_size)}</td>
          <td class="px-4 py-2 text-right font-mono">{seg.block_count}</td>
          <td class="px-4 py-2 text-center">
            {#if seg.size_match}
              <span class="text-[var(--success)]">OK</span>
            {:else}
              <span class="text-[var(--warning)]" title="Expected {seg.expected_size}, got {seg.actual_size}">
                MISMATCH
              </span>
            {/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>
