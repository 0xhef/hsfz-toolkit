<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { ActiveTab } from '../../types';
  import BottomNav from './BottomNav.svelte';

  interface Props {
    activeTab: ActiveTab;
    hasLiveCapture: boolean;
    onTabChange: (tab: ActiveTab) => void;
    children: Snippet;
  }

  let { activeTab, hasLiveCapture, onTabChange, children }: Props = $props();

  // Tab title shown in the header. Mirrors what the desktop TabBar
  // displays as `kicker` text but as a single header line.
  const titles: Record<ActiveTab, { primary: string; secondary: string }> = {
    load: { primary: 'EXTRACT', secondary: 'PCAP forensics' },
    capture: { primary: 'CAPTURE', secondary: 'Live HSFZ sniff' },
    calibration_read: { primary: 'CAL READ', secondary: 'MEVD17 region' },
    simulator: { primary: 'SIMULATOR', secondary: 'DME impersonation' },
    proxy: { primary: 'PROXY', secondary: 'MITM forwarder' },
  };

  const title = $derived(titles[activeTab]);
</script>

<!--
  Mobile shell layout — body-scrolling architecture. Normal document
  flow for the header and main content; the bottom nav is absolutely
  fixed to the viewport. This arrangement makes body the CSS initial
  containing block for all descendant `position: fixed` elements, so
  modals and toasts rendered inside panels work correctly on Android
  WebView — they're positioned relative to the viewport with no
  clipping from scroll containers.

  Layout breakdown:
    <div class="mobile-root">       — plain block, normal flow
      <header sticky top-0>          — pinned to top, flows with body
      <main>                         — normal flow, padding-bottom
                                       clears the fixed bottom nav
        {@render children()}
    <BottomNav fixed bottom-0>       — pinned to viewport, z-40

  Safe-area insets are applied as padding to the header (top) and
  bottom nav (bottom) so the content clears notches and gesture-nav
  handles while the background extends edge-to-edge.
-->
<div class="mobile-root bg-[var(--bg-primary)]">
  <!-- ── Top app bar (sticky) ───────────────────────────────────── -->
  <header
    class="sticky top-0 z-30 bg-[var(--bg-secondary)]/95 backdrop-blur-md border-b border-[var(--border)]"
    style="padding-top: max(24px, env(safe-area-inset-top, 24px));"
  >
    <div class="flex items-center justify-between gap-3 px-4 pb-3 pt-2">
      <!-- Left: brand mark -->
      <div class="flex items-center gap-2.5 min-w-0">
        <div class="relative w-7 h-7 flex-shrink-0" aria-hidden="true">
          <div
            class="absolute inset-0 border border-[var(--accent)] rounded-sm"
          ></div>
          <div
            class="absolute -top-1 -right-1 w-1.5 h-1.5 bg-[var(--accent)] rounded-full"
            style="animation: pulse-glow 2.4s ease-in-out infinite;"
          ></div>
          <div
            class="absolute inset-0 flex items-center justify-center font-mono text-[9px] font-bold text-[var(--accent)] tracking-tighter"
          >
            BM
          </div>
        </div>
        <div class="flex flex-col gap-0.5 min-w-0">
          <span
            class="font-mono text-[11px] font-bold tracking-tight text-[var(--text-primary)] leading-none truncate"
          >
            {title.primary}
          </span>
          <span
            class="font-mono text-[9px] text-[var(--text-muted)] tracking-widest uppercase leading-none truncate"
          >
            {title.secondary}
          </span>
        </div>
      </div>

      <!-- Right: minimal status pill -->
      <div class="flex items-center gap-1.5 flex-shrink-0">
        <span
          class="w-1.5 h-1.5 rounded-full bg-[var(--success)]"
          style="box-shadow: 0 0 4px currentColor;"
          aria-hidden="true"
        ></span>
        <span
          class="font-mono text-[9px] tracking-widest uppercase text-[var(--text-secondary)]"
        >
          BMSec
        </span>
      </div>
    </div>
  </header>

  <!-- ── Content area (normal flow) ─────────────────────────────── -->
  <!--
    Normal-flow block. No overflow, no flex trap — body is the scroll
    container. `padding-bottom` leaves room for the fixed bottom nav
    (~64px) plus the gesture-nav safe area so the last bit of content
    is reachable when scrolled to the end.
  -->
  <!--
    `padding-bottom` stacks three values:
      1. 80px — bottom-nav height
      2. env(safe-area-inset-bottom) — gesture-nav handle
      3. env(keyboard-inset-height) — virtual keyboard height when
         the Android IME is visible. Supported on Chromium 108+,
         which covers the WebView in all Tauri mobile builds. Without
         this the IME covers the bottom part of any form (IP field,
         ECU field) when focused, because the visual viewport
         shrinks but our content padding doesn't react.
    `max(…)` picks whichever stack is tallest so we never add the
    keyboard AND the nav/safe-area together — they're mutually
    exclusive (the nav is obscured behind the IME when it's up).
  -->
  <main
    class="px-4 py-4"
    style="padding-bottom: max(
      calc(80px + env(safe-area-inset-bottom, 0px)),
      calc(env(keyboard-inset-height, 0px) + 24px)
    );"
  >
    {@render children()}
  </main>

  <!-- ── Bottom nav (fixed to viewport) ─────────────────────────── -->
  <BottomNav {activeTab} {hasLiveCapture} {onTabChange} />
</div>
