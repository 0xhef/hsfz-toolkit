<script lang="ts">
  import type { ActiveTab } from '../types';

  interface Props {
    activeTab: ActiveTab;
    hasLiveCapture?: boolean;
    onTabChange: (tab: ActiveTab) => void;
  }

  let { activeTab, hasLiveCapture = true, onTabChange }: Props = $props();

  // Tab definitions: short numeric prefix for the instrument-cluster
  // feel, monospace label, optional kicker for context. The
  // `requiresLiveCapture` flag marks tabs that need the libpcap Cargo
  // feature compiled in — currently just the live Capture tab. Proxy
  // capture covers the same ground in userspace and works on every
  // build, so the Proxy tab is always shown.
  const allTabs: {
    id: ActiveTab;
    index: string;
    label: string;
    kicker: string;
    requiresLiveCapture?: boolean;
  }[] = [
    {
      id: 'load',
      index: '01',
      label: 'EXTRACT FROM PCAP',
      kicker: 'Recover .bin from flash trace',
    },
    {
      id: 'capture',
      index: '02',
      label: 'CAPTURE FLASH',
      kicker: 'Sniff a live flash session',
      requiresLiveCapture: true,
    },
    {
      id: 'calibration_read',
      index: '03',
      label: 'CALIBRATION READ',
      kicker: 'Read calibration over ENET',
    },
    {
      id: 'simulator',
      index: '04',
      label: 'DME SIMULATOR',
      kicker: 'Spoof a DME for tools',
    },
    {
      id: 'proxy',
      index: '05',
      label: 'DME PROXY',
      kicker: 'MITM real DME ↔ flasher',
    },
  ];

  // Renumber tab indexes after filtering so the instrument-cluster
  // numbering stays contiguous (01, 02, 03, 04 instead of 01, 03, 04, 05).
  const tabs = $derived(
    allTabs
      .filter((t) => !(t.requiresLiveCapture && !hasLiveCapture))
      .map((t, i) => ({ ...t, index: String(i + 1).padStart(2, '0') })),
  );
</script>

<nav class="border border-[var(--border)] rounded-lg bg-[var(--bg-secondary)]/50">
  <div class="grid grid-cols-2 md:grid-cols-5">
    {#each tabs as tab, i}
      <button
        type="button"
        onclick={() => onTabChange(tab.id)}
        class="group relative text-left px-5 py-4 transition-colors
          {i > 0 ? 'border-l border-[var(--border)]' : ''}
          {i >= 2 ? 'md:border-l border-t border-[var(--border)] md:border-t-0' : ''}
          {activeTab === tab.id
          ? 'bg-[var(--bg-tertiary)]/40'
          : 'hover:bg-[var(--bg-tertiary)]/20'}"
      >
        <!-- Active accent bar — slim vertical stripe on the left edge -->
        <div
          class="absolute top-0 bottom-0 left-0 w-[2px] transition-colors
            {activeTab === tab.id ? 'bg-[var(--accent)]' : 'bg-transparent'}"
          style={activeTab === tab.id
            ? 'box-shadow: 0 0 8px var(--accent-glow);'
            : ''}
        ></div>

        <div class="flex items-center gap-3">
          <span
            class="font-mono text-[10px] font-semibold tracking-widest leading-none
              {activeTab === tab.id
              ? 'text-[var(--accent)]'
              : 'text-[var(--text-muted)] group-hover:text-[var(--text-secondary)]'}"
          >
            {tab.index}
          </span>
          <div class="flex flex-col gap-1">
            <span
              class="font-mono text-[12px] font-bold tracking-wider leading-none
                {activeTab === tab.id
                ? 'text-[var(--text-primary)]'
                : 'text-[var(--text-secondary)] group-hover:text-[var(--text-primary)]'}"
            >
              {tab.label}
            </span>
            <span
              class="font-sans text-[10px] tracking-wide leading-none
                {activeTab === tab.id
                ? 'text-[var(--text-secondary)]'
                : 'text-[var(--text-muted)]'}"
            >
              {tab.kicker}
            </span>
          </div>
        </div>
      </button>
    {/each}
  </div>
</nav>
