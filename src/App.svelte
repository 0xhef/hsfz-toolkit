<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import TabBar from './lib/components/TabBar.svelte';
  import LoadPanel from './lib/components/LoadPanel.svelte';
  import CapturePanel from './lib/components/capture/CapturePanel.svelte';
  import CalibrationReadPanel from './lib/components/CalibrationReadPanel.svelte';
  import SimulatorPanel from './lib/components/SimulatorPanel.svelte';
  import ProxyPanel from './lib/components/ProxyPanel.svelte';
  import MobileShell from './lib/components/mobile/MobileShell.svelte';
  import type { ActiveTab } from './lib/types';

  let activeTab: ActiveTab = $state('load');

  // Capability detection — used to hide the live Capture tab when the
  // libpcap feature isn't compiled into this build. This is the actual
  // determining factor (not the platform): a rooted Android build with
  // --features libpcap will report true here and get the full Capture
  // tab; a desktop research-only build will report false and have it
  // hidden. See SCOPE.md and ANDROID.md.
  let hasLiveCapture: boolean = $state(false);

  // Mobile-shell detection.
  //
  // We need a SYNCHRONOUS answer for the very first render so the
  // mobile shell renders immediately on Android without flashing the
  // desktop layout for one frame while the async `get_platform()` IPC
  // resolves. Solution: use viewport width as the primary signal
  // (initialised synchronously from `window.innerWidth`) and refine
  // it asynchronously with the platform string from Tauri once it
  // arrives. The viewport-width check also handles the desktop case
  // of a user resizing their window narrow — they get the mobile
  // shell automatically, which is the correct UX.
  //
  // Threshold: 768px is the standard tablet/mobile breakpoint. Below
  // this we assume the device is a phone and use the mobile shell.
  // Tauri's Android WebView starts at the device's actual CSS pixel
  // width (typically 360-420 on phones), so this catches Android on
  // first paint with zero IPC latency.
  const MOBILE_BREAKPOINT_PX = 768;
  let viewportIsMobile: boolean = $state(
    typeof window !== 'undefined' && window.innerWidth < MOBILE_BREAKPOINT_PX,
  );
  let platform: string = $state('');
  const platformIsMobile = $derived(platform === 'android' || platform === 'ios');
  const isMobile = $derived(viewportIsMobile || platformIsMobile);

  $effect(() => {
    invoke<boolean>('has_live_capture').then((v) => {
      hasLiveCapture = v;
      // If the user landed on a tab that's not compiled in, bounce
      // them back to the default load tab.
      if (!v && activeTab === 'capture') {
        activeTab = 'load';
      }
    });
    invoke<string>('get_platform').then((p) => {
      platform = p;
    });

    // Track viewport-width changes so a desktop user resizing their
    // window across the breakpoint gets the right shell. The Android
    // case fires this once on rotation (portrait <-> landscape) which
    // is harmless because both orientations on a phone are still
    // below the breakpoint.
    const onResize = () => {
      viewportIsMobile = window.innerWidth < MOBILE_BREAKPOINT_PX;
    };
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  });

  function handleTabChange(tab: ActiveTab) {
    activeTab = tab;
  }

  // Wall-clock displayed in the header status strip — updated every
  // second. Tiny detail but adds to the "live instrument" feel.
  let nowLabel: string = $state('');
  function updateClock() {
    const d = new Date();
    nowLabel =
      d.getUTCFullYear().toString().padStart(4, '0') +
      '-' +
      (d.getUTCMonth() + 1).toString().padStart(2, '0') +
      '-' +
      d.getUTCDate().toString().padStart(2, '0') +
      'T' +
      d.getUTCHours().toString().padStart(2, '0') +
      ':' +
      d.getUTCMinutes().toString().padStart(2, '0') +
      ':' +
      d.getUTCSeconds().toString().padStart(2, '0') +
      'Z';
  }
  updateClock();
  setInterval(updateClock, 1000);
</script>

{#if isMobile}
  <!-- ── Mobile shell: top app bar + bottom nav + content host ── -->
  <!--
    All panels stay mounted (CSS hidden) so live subscriptions (proxy
    transcript feed, simulator event log, calibration read progress)
    survive tab switches. Same pattern as the desktop branch below.
    Memory cost is acceptable on modern phones; the alternative is
    losing live state every time the user taps a different tab.
  -->
  <MobileShell {activeTab} {hasLiveCapture} onTabChange={handleTabChange}>
    <div class:hidden={activeTab !== 'load'}>
      <LoadPanel />
    </div>
    {#if hasLiveCapture}
      <div class:hidden={activeTab !== 'capture'}>
        <CapturePanel />
      </div>
    {/if}
    <div class:hidden={activeTab !== 'calibration_read'}>
      <CalibrationReadPanel />
    </div>
    <div class:hidden={activeTab !== 'simulator'}>
      <SimulatorPanel />
    </div>
    <div class:hidden={activeTab !== 'proxy'}>
      <ProxyPanel />
    </div>
  </MobileShell>
{:else}
<main class="min-h-screen">
  <!-- ── Header / wordmark ─────────────────────────────────────── -->
  <header class="border-b border-[var(--border)] bg-[var(--bg-secondary)]/70 backdrop-blur-sm">
    <div class="max-w-6xl mx-auto px-8 py-5 flex items-center justify-between gap-6">
      <div class="flex items-center gap-4">
        <!-- Logomark: a hollow accent square with an offset glyph.
             Cheap to render, distinctive, reads as "instrument". -->
        <div
          class="relative w-9 h-9 flex-shrink-0"
          aria-hidden="true"
        >
          <div
            class="absolute inset-0 border border-[var(--accent)] rounded-sm"
          ></div>
          <div
            class="absolute -top-1 -right-1 w-2 h-2 bg-[var(--accent)] rounded-full"
            style="animation: pulse-glow 2.4s ease-in-out infinite;"
          ></div>
          <div
            class="absolute inset-0 flex items-center justify-center font-mono text-[10px] font-bold text-[var(--accent)] tracking-tighter"
          >
            BM
          </div>
        </div>

        <div class="flex flex-col gap-0.5">
          <div class="flex items-baseline gap-3">
            <h1
              class="font-mono text-[15px] font-bold tracking-tight text-[var(--text-primary)] leading-none"
            >
              BMSECRESEARCH
            </h1>
            <span
              class="inline-flex items-center font-mono text-[9px] font-semibold tracking-[0.15em] uppercase text-[var(--accent)] border border-[var(--accent)] px-2 py-[3px] rounded-sm bg-[var(--accent-soft)] leading-none"
            >
              v1.0
            </span>
          </div>
          <p
            class="font-mono text-[10px] text-[var(--text-muted)] tracking-widest uppercase leading-none mt-1"
          >
            HSFZ / UDS · MEVD17 research · Independent · Not affiliated with BMW AG
          </p>
        </div>
      </div>

      <!-- ── Right rail: live status strip ──────────────────────── -->
      <div class="hidden md:flex items-center gap-6">
        <div class="flex flex-col items-end gap-0.5">
          <span class="label-sm leading-none">UTC</span>
          <span class="font-mono text-[11px] text-[var(--text-primary)] leading-none">
            {nowLabel}
          </span>
        </div>
        <div class="flex flex-col items-end gap-0.5">
          <span class="label-sm leading-none">STATUS</span>
          <div class="flex items-center gap-1.5 leading-none">
            <span
              class="w-1.5 h-1.5 rounded-full bg-[var(--success)]"
              style="box-shadow: 0 0 6px currentColor;"
            ></span>
            <span class="font-mono text-[11px] text-[var(--text-primary)]">READY</span>
          </div>
        </div>
      </div>
    </div>
  </header>

  <div class="max-w-6xl mx-auto px-8 py-8">
    <TabBar {activeTab} {hasLiveCapture} onTabChange={(tab) => (activeTab = tab)} />

    <!-- Both panels stay mounted (CSS hidden) to preserve state across tab switches -->
    <div class="mt-8">
      <div class:hidden={activeTab !== 'load'}>
        <LoadPanel />
      </div>
      {#if hasLiveCapture}
        <div class:hidden={activeTab !== 'capture'}>
          <CapturePanel />
        </div>
      {/if}
      <div class:hidden={activeTab !== 'calibration_read'}>
        <CalibrationReadPanel />
      </div>
      <div class:hidden={activeTab !== 'simulator'}>
        <SimulatorPanel />
      </div>
      <div class:hidden={activeTab !== 'proxy'}>
        <ProxyPanel />
      </div>
    </div>
  </div>

  <!-- ── Footer hairline ─────────────────────────────────────────── -->
  <footer class="border-t border-[var(--border)] mt-16">
    <div
      class="max-w-6xl mx-auto px-8 py-4 flex items-center justify-between font-mono text-[10px] tracking-wider text-[var(--text-muted)] uppercase"
    >
      <span>Research tool · Use only on vehicles you own or have permission to test · See SCOPE.md</span>
      <span>BMSecResearch · Not affiliated with BMW AG</span>
    </div>
  </footer>
</main>
{/if}
