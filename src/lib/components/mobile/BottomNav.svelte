<script lang="ts">
  import type { ActiveTab } from '../../types';

  interface NavItem {
    id: ActiveTab;
    label: string;
    /** SVG path `d` strings, rendered as separate `<path>` elements
     *  inside a 24×24 viewBox with a 1.75 stroke. */
    paths: string[];
    requiresLiveCapture?: boolean;
  }

  interface Props {
    activeTab: ActiveTab;
    hasLiveCapture?: boolean;
    onTabChange: (tab: ActiveTab) => void;
  }

  let { activeTab, hasLiveCapture = true, onTabChange }: Props = $props();

  // Bottom-nav items. The Capture tab is included only when libpcap
  // is compiled in (default Android sideload omits it, so most mobile
  // users see four tabs). Icons are inline SVG path strings — line-art,
  // monochrome, designed to read at 22×22 against the dark theme.
  const allItems: NavItem[] = [
    {
      id: 'load',
      label: 'PCAP',
      paths: [
        'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z',
        'M14 2v6h6',
        'M16 13H8',
        'M16 17H8',
        'M10 9H9 H8',
      ],
    },
    {
      id: 'capture',
      label: 'Capture',
      paths: [
        'M22 12h-4',
        'M6 12H2',
        'M12 6V2',
        'M12 22v-4',
        'M19 5l-3 3',
        'M5 19l3-3',
        'M19 19l-3-3',
        'M5 5l3 3',
        'M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0z',
      ],
      requiresLiveCapture: true,
    },
    {
      id: 'calibration_read',
      label: 'Read',
      paths: [
        'M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z',
        'M8 9h8',
        'M8 13h6',
      ],
    },
    {
      id: 'simulator',
      label: 'Simulator',
      paths: [
        'M2 3h20v14H2z',
        'M8 21h8',
        'M12 17v4',
      ],
    },
    {
      id: 'proxy',
      label: 'Proxy',
      paths: [
        'M5 12h14',
        'M12 5l7 7-7 7',
        'M3 6v12',
      ],
    },
  ];

  const items = $derived(
    allItems.filter((item) => !(item.requiresLiveCapture && !hasLiveCapture)),
  );
</script>

<!--
  Fixed to viewport bottom. Industry-standard mobile app pattern: the
  bottom nav sits at `position: fixed; bottom: 0` so it's always
  thumb-reachable regardless of scroll position. The bottom safe-area
  inset is applied as padding so the icons clear the gesture-nav
  handle while the background extends edge-to-edge. The parent
  `<body>` has `overscroll-behavior: none` set in app.css to kill
  rubber-band scrolling, which would otherwise drag this nav with
  the content on pull-past-top (Android WebView rubber-band bug).

  z-40 is above the sticky header (z-30) and below modals (z-50) so
  the layer ordering is: content < header < nav < modals.
-->
<nav
  class="fixed bottom-0 inset-x-0 z-40 bg-[var(--bg-secondary)]/95 backdrop-blur-md border-t border-[var(--border)]"
  style="padding-bottom: max(12px, env(safe-area-inset-bottom, 12px));"
  aria-label="Primary navigation"
>
  <div class="flex items-stretch justify-around px-1 pt-1.5">
    {#each items as item (item.id)}
      {@const isActive = activeTab === item.id}
      <button
        type="button"
        onclick={() => onTabChange(item.id)}
        class="relative flex-1 flex flex-col items-center justify-center gap-1 px-1 py-1.5 rounded-md transition-colors min-h-[52px]
          {isActive
            ? 'text-[var(--accent)]'
            : 'text-[var(--text-secondary)] active:bg-[var(--bg-tertiary)]'}"
        aria-label={item.label}
        aria-current={isActive ? 'page' : undefined}
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="22"
          height="22"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.75"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          {#each item.paths as d}
            <path {d} />
          {/each}
        </svg>
        <span
          class="font-mono text-[10px] font-semibold tracking-wider uppercase leading-none"
        >
          {item.label}
        </span>
        {#if isActive}
          <span
            class="absolute bottom-0 left-1/2 -translate-x-1/2 w-8 h-[2px] bg-[var(--accent)] rounded-full"
            style="box-shadow: 0 0 6px var(--accent-glow);"
            aria-hidden="true"
          ></span>
        {/if}
      </button>
    {/each}
  </div>
</nav>
