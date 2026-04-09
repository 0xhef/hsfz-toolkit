<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { save as saveDialog } from '@tauri-apps/plugin-dialog';
  import { writeFile } from '@tauri-apps/plugin-fs';
  import { onDestroy, onMount } from 'svelte';
  import Spinner from './Spinner.svelte';
  import ToastStrip from './ToastStrip.svelte';
  import {
    flushPaint,
    pullLastBytes,
    pullLastOpLog,
    siblingLogPath,
    scrollIntoViewOnFocus,
  } from '../mobile-utils';
  import { haptic } from '../haptics';
  import { loadPersisted, savePersisted } from '../persistent-state';

  async function writeSiblingLog(artifactPath: string): Promise<void> {
    try {
      const text = await pullLastOpLog();
      if (!text) return;
      const encoder = new TextEncoder();
      await writeFile(siblingLogPath(artifactPath), encoder.encode(text));
    } catch (e) {
      console.warn('sibling log write failed:', e);
    }
  }
  import type {
    ProxyStatus,
    ProxyFrameEvent,
    ProxyStatusEvent,
    ProxySession,
    DiscoveredDevice,
  } from '../types';

  // ── Form state ──────────────────────────────────────────────────────
  // Persisted across app launches so the user doesn't have to retype
  // the upstream DME IP every time, which matters a lot on Android
  // where the WebView can be killed by the OS when backgrounded.
  let listenAddr: string = $state(
    loadPersisted<string>('proxy.listenAddr', '0.0.0.0:6801'),
  );
  let upstreamAddr: string = $state(
    loadPersisted<string>('proxy.upstreamAddr', '192.168.0.10:6801'),
  );
  $effect(() => {
    savePersisted('proxy.listenAddr', listenAddr);
  });
  $effect(() => {
    savePersisted('proxy.upstreamAddr', upstreamAddr);
  });
  // Detected from the upstream DME via Discover. Read-only in the UI.
  let realVin: string = $state('');
  let realMac: string = $state('');
  // The diag addr is technically auto-detected but the user can
  // override it (some non-MEVD17 ECUs use a different value), so it
  // stays editable.
  let diagAddr: number = $state(0x10);
  // Master spoof toggle.
  let spoofEnabled: boolean = $state(false);
  // What the proxy advertises to the flasher when spoofEnabled is true.
  let spoofVin: string = $state('');
  let spoofMac: string = $state('');
  let enableDiscovery: boolean = $state(true);

  // Live preview of the values the proxy will actually advertise,
  // computed from the spoof toggle + the spoof/real fields.
  let activeVin = $derived(
    spoofEnabled
      ? spoofVin.trim() || realVin.trim() || '(none)'
      : realVin.trim() || '(none)',
  );
  let activeMac = $derived(
    spoofEnabled
      ? spoofMac.trim() || realMac.trim() || '(none)'
      : realMac.trim() || '(none)',
  );

  // ── Upstream auto-discovery ─────────────────────────────────────────
  // Reuses the same ENET broadcast probe the Calibration Read tab uses
  // (`discover_vehicles`). The proxy can't run discovery while it's
  // already bound to UDP 6811, so the button is disabled while the
  // proxy is running.
  let discovering: boolean = $state(false);
  let discovered: DiscoveredDevice[] = $state([]);
  let discoveredError: string = $state('');

  async function discoverUpstream() {
    if (status.running) {
      showToast(
        'error',
        'Stop the proxy first — UDP 6811 is in use by the discovery responder.',
      );
      return;
    }
    discovering = true;
    discoveredError = '';
    discovered = [];
    await flushPaint();
    try {
      discovered = await invoke<DiscoveredDevice[]>('discover_vehicles');
      if (discovered.length === 0) {
        discoveredError = 'No DMEs answered the broadcast probe.';
        return;
      }
      // Pre-fill from the first hit. The user can override the
      // upstream addr or pick a different device from the list below.
      applyDiscovered(discovered[0]);
      showToast(
        'success',
        `Discovered ${discovered.length} device${discovered.length === 1 ? '' : 's'} — using ${discovered[0].ip}`,
      );
    } catch (e) {
      discoveredError = String(e);
      showToast('error', `Discovery failed: ${e}`);
    } finally {
      discovering = false;
    }
  }

  function applyDiscovered(d: DiscoveredDevice) {
    upstreamAddr = `${d.ip}:6801`;
    diagAddr = d.diag_address;
    // Populate the *real* (read-only) fields. The spoof fields stay
    // untouched — those represent what the user wants the flasher to
    // see, which is usually a *different* car than the one on the
    // wire. Auto-filling them with the real DME's values would
    // defeat the licence-bypass use case.
    realVin = d.vin;
    realMac = d.mac_address.replace(/[^0-9A-Fa-f]/g, '').toUpperCase();
  }

  // ── Live status ─────────────────────────────────────────────────────
  let status: ProxyStatus = $state({
    running: false,
    config: null,
    bytes_c2u: 0,
    bytes_u2c: 0,
    frames: 0,
    rewrites: 0,
    sessions: 0,
  });
  let statusLine: string = $state('idle');
  let errorMsg: string = $state('');
  let toastMessage: string = $state('');
  let toastKind: 'success' | 'error' = $state('success');
  let toastTimer: ReturnType<typeof setTimeout> | null = null;

  function showToast(kind: 'success' | 'error', message: string) {
    toastMessage = message;
    toastKind = kind;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(
      () => {
        toastMessage = '';
        toastTimer = null;
      },
      kind === 'success' ? 6000 : 12000,
    );
  }

  const FRAME_LIMIT = 200;
  let frames: ProxyFrameEvent[] = $state([]);

  // ── Persistent past-sessions list ───────────────────────────────────
  let sessions: ProxySession[] = $state([]);
  let sessionsError: string = $state('');
  let exportingDir: string | null = $state(null);
  let capturesDir: string = $state('');

  let unlisten: UnlistenFn[] = [];
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  async function refreshSessions() {
    try {
      sessions = await invoke<ProxySession[]>('proxy_list_sessions');
      sessionsError = '';
    } catch (e) {
      sessionsError = String(e);
    }
  }

  onMount(() => {
    (async () => {
      const u1 = await listen<ProxyStatusEvent>('proxy-status', (evt) => {
        statusLine = `${evt.payload.state}: ${evt.payload.detail}`;
        if (evt.payload.state === 'disconnected') {
          // A captured session just landed on disk; refresh the list.
          refreshSessions();
        }
      });
      const u2 = await listen<ProxyFrameEvent>('proxy-frame', (evt) => {
        frames = [...frames.slice(-(FRAME_LIMIT - 1)), evt.payload];
      });
      unlisten = [u1, u2];

      try {
        status = await invoke<ProxyStatus>('proxy_status');
      } catch (e) {
        console.warn('proxy_status:', e);
      }
      try {
        capturesDir = await invoke<string>('proxy_captures_dir');
      } catch (_) {
        /* best effort */
      }
      await refreshSessions();

      pollTimer = setInterval(async () => {
        if (!status.running) return;
        try {
          status = await invoke<ProxyStatus>('proxy_status');
        } catch (_) {
          /* swallow — handled by status events */
        }
        // Auto-refresh the captured sessions list while the proxy is
        // running so the user sees newly-disconnected sessions appear
        // without having to tap Refresh manually. The
        // `proxy_list_sessions` command is cheap (a directory walk
        // plus meta.json reads) — fine to call every poll cycle.
        try {
          sessions = await invoke<ProxySession[]>('proxy_list_sessions');
          sessionsError = '';
        } catch (_) {
          /* swallow — manual refresh button still works */
        }
      }, 1000);
    })();
  });

  onDestroy(() => {
    unlisten.forEach((u) => u());
    if (pollTimer) clearInterval(pollTimer);
  });

  async function startProxy() {
    haptic('medium');
    errorMsg = '';
    if (spoofVin.trim() && spoofVin.trim().length !== 17) {
      errorMsg = 'Spoof VIN must be exactly 17 characters (or empty).';
      haptic('error');
      return;
    }
    if (realVin.trim() && realVin.trim().length !== 17) {
      errorMsg = 'Real VIN must be 17 characters — re-run Discover or fix manually.';
      haptic('error');
      return;
    }
    try {
      status = await invoke<ProxyStatus>('proxy_start', {
        listenAddr,
        upstreamAddr,
        realVin: realVin.trim() || null,
        realMac: realMac.trim() || null,
        diagAddr,
        spoofEnabled,
        spoofVin: spoofVin.trim() || null,
        spoofMac: spoofMac.trim() || null,
        enableDiscovery,
      });
      frames = [];
      haptic('success');
      showToast('success', 'Proxy started');
    } catch (e) {
      errorMsg = String(e);
      haptic('error');
      showToast('error', `Start failed: ${e}`);
    }
  }

  async function stopProxy() {
    haptic('heavy');
    errorMsg = '';
    try {
      status = await invoke<ProxyStatus>('proxy_stop');
      showToast('success', 'Proxy stopped');
      await refreshSessions();
    } catch (e) {
      errorMsg = String(e);
      haptic('error');
      showToast('error', `Stop failed: ${e}`);
    }
  }

  async function exportSession(session: ProxySession) {
    if (exportingDir) return;
    const suggested = `${session.dir_name}.pcap`;
    const dest = await saveDialog({
      title: 'Export proxy capture as .pcap',
      defaultPath: suggested,
      filters: [{ name: 'PCAP', extensions: ['pcap'] }],
    });
    if (!dest) return;
    exportingDir = session.dir_name;
    try {
      await invoke<number>('proxy_export_pcap', { dirName: session.dir_name });
      const bytes = await pullLastBytes();
      await writeFile(dest, bytes);
      await writeSiblingLog(dest);
      showToast('success', `Exported ${formatBytes(bytes.length)} → ${dest}`);
    } catch (e) {
      showToast('error', `Export failed: ${e}`);
    } finally {
      exportingDir = null;
    }
  }

  function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / 1024 / 1024).toFixed(2)} MiB`;
  }
</script>

<div class="space-y-4">
  <!-- Inline toast strip — mobile-native, normal-flow, no fixed positioning -->
  <ToastStrip
    kind={toastKind}
    message={toastMessage}
    onDismiss={() => (toastMessage = '')}
  />
  <!-- ── Setup banner ─────────────────────────────────────────────── -->
  <div class="p-4 rounded-lg bg-[var(--bg-secondary)]/50 border border-[var(--border)]">
    <h2 class="text-lg font-semibold text-[var(--text-primary)] mb-2">DME Proxy</h2>
    <p class="text-xs text-[var(--accent)] leading-relaxed">
      Sits between a flashing app and a real MEVD17 DME. Forwards every HSFZ
      frame in both directions, captures the full transcript with real
      wall-clock timestamps, and rewrites <code>22 F190</code> VIN responses
      and the UDP discovery reply on the fly so a VIN-licensed flasher
      accepts a different vehicle than the one it's actually flashing.
    </p>
    <details class="mt-3 text-xs text-[var(--text-secondary)]">
      <summary class="cursor-pointer text-[var(--text-primary)] font-semibold">
        How to set up (read this first — flashers don't accept manual IPs)
      </summary>
      <div class="mt-2 space-y-2 leading-relaxed">
        <p>
          HSFZ flash tools find the DME via ENET broadcast on UDP 6811 — they
          don't let you type a manual IP. The proxy must be the first
          (ideally <em>only</em>) thing that responds to the broadcast on
          the flasher's network. Two practical topologies:
        </p>
        <p>
          <span class="text-[var(--accent)] font-semibold">Setup A — bridged laptop (recommended).</span>
          Run this app on a host with two NICs: one on the flasher's
          network, one with the ENET cable plugged into the DME.
          Disconnect the DME's ENET cable from the flasher's LAN before
          starting the proxy. The flasher's broadcast can only reach the
          proxy NIC; the DME is reachable only via the proxy host's
          second NIC. No race condition.
        </p>
        <p>
          <span class="text-[var(--accent)] font-semibold">Setup B — single-NIC (race).</span>
          If both the proxy and the real DME share a broadcast domain,
          both will answer the discovery probe. The proxy responds in
          microseconds and usually wins, but the result is undefined —
          if the flasher uses the DME's address, restart and retry.
          Reliable only after physically unplugging the DME from the
          flasher's switch.
        </p>
        <p>
          Either way: start this proxy <strong>before</strong> launching
          the flasher. Discovery responder is on by default and answers
          with the spoof VIN/MAC/diag-addr below.
        </p>
      </div>
    </details>
  </div>

  <!-- ── Config form ──────────────────────────────────────────────── -->
  <div class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)]">
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
      <label class="block">
        <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
          Listen Address (TCP)
        </span>
        <input
          type="text"
          bind:value={listenAddr}
          disabled={status.running}
          placeholder="0.0.0.0:6801"
          inputmode="decimal"
          autocomplete="off"
          autocorrect="off"
          autocapitalize="off"
          spellcheck="false"
          use:scrollIntoViewOnFocus
          class="mt-1 w-full px-3 py-2 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-sm focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
        />
      </label>
      <label class="block">
        <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
          Upstream DME
        </span>
        <div class="mt-1 flex gap-2">
          <input
            type="text"
            bind:value={upstreamAddr}
            disabled={status.running}
            placeholder="192.168.0.10:6801"
            inputmode="decimal"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            use:scrollIntoViewOnFocus
            class="flex-1 min-w-0 px-3 py-2 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-sm focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
          />
          <button
            type="button"
            onclick={discoverUpstream}
            disabled={status.running || discovering}
            class="shrink-0 inline-flex items-center gap-1.5 px-3 py-2 rounded border border-[var(--accent)] text-[var(--accent)] text-xs font-semibold hover:bg-[var(--accent)] hover:text-black disabled:opacity-50 disabled:hover:bg-transparent disabled:hover:text-[var(--accent)]"
            title="Broadcast an ENET vehicle-identification probe and pre-fill from the first DME that answers"
          >
            {#if discovering}
              <Spinner size={11} />
              <span>Scanning…</span>
            {:else}
              <span>Discover</span>
            {/if}
          </button>
        </div>
        {#if discovering}
          <!-- Mid-discovery loading card. Same visual treatment as the
               Calibration Read tab so users see consistent feedback
               across the app. The 3-second timeout in the Rust
               discovery function bounds how long this stays. -->
          <div
            class="mt-2 p-3 rounded bg-[var(--bg-tertiary)] border border-[var(--accent)]/40 flex items-center gap-3"
            style="box-shadow: 0 0 12px var(--accent-glow);"
          >
            <Spinner size={16} />
            <div class="flex flex-col gap-0.5 min-w-0">
              <span class="text-xs text-[var(--text-primary)] font-medium">
                Searching for upstream DMEs
              </span>
              <span class="text-[10px] text-[var(--text-secondary)]">
                Broadcasting HSFZ vehicle-identification probe on UDP 6811…
              </span>
            </div>
          </div>
        {/if}
        {#if discoveredError}
          <p class="mt-1 text-[10px] text-[var(--error)]">{discoveredError}</p>
        {/if}
        {#if discovered.length > 1}
          <p class="mt-1 text-[10px] text-[var(--text-secondary)]">
            Multiple DMEs answered — pick one:
          </p>
          <div class="mt-1 space-y-1">
            {#each discovered as d}
              <button
                type="button"
                onclick={() => applyDiscovered(d)}
                disabled={status.running}
                class="w-full text-left text-[11px] font-mono px-2 py-1 rounded border border-[var(--border)] hover:border-[var(--accent)] hover:bg-[var(--bg-tertiary)] disabled:opacity-50"
              >
                <span class="text-[var(--accent)]">{d.ip}</span>
                <span class="ml-2 text-[var(--text-secondary)]">
                  diag=0x{d.diag_address.toString(16).padStart(2, '0').toUpperCase()}
                  · MAC {d.mac_address}
                  · VIN {d.vin}
                </span>
              </button>
            {/each}
          </div>
        {/if}
      </label>
      <label class="flex items-center gap-2 sm:col-span-2 select-none">
        <input
          type="checkbox"
          bind:checked={enableDiscovery}
          disabled={status.running}
          class="accent-[var(--accent)]"
        />
        <span class="text-xs text-[var(--text-primary)]">
          Run UDP discovery responder on port 6811
        </span>
        <span class="text-[10px] text-[var(--text-secondary)]">
          (required for HSFZ flash tools — they all broadcast-discover)
        </span>
      </label>
    </div>

    <!-- ── Detected DME (read-only) ──────────────────────────────── -->
    <div class="mt-5 p-4 rounded border border-[var(--border)] bg-[var(--bg-tertiary)]/40">
      <div class="flex items-center justify-between mb-2">
        <span class="text-xs font-semibold uppercase tracking-wide text-[var(--text-secondary)]">
          Detected DME
        </span>
        <span class="text-[10px] text-[var(--text-secondary)]">
          {realVin || realMac ? 'auto-filled by Discover' : 'click Discover to populate'}
        </span>
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
        <div>
          <div class="text-[10px] text-[var(--text-secondary)] uppercase tracking-wide">VIN</div>
          <div class="text-[var(--text-primary)] break-all">{realVin || '—'}</div>
        </div>
        <div>
          <div class="text-[10px] text-[var(--text-secondary)] uppercase tracking-wide">MAC</div>
          <div class="text-[var(--text-primary)] break-all">{realMac || '—'}</div>
        </div>
        <div>
          <div class="text-[10px] text-[var(--text-secondary)] uppercase tracking-wide">
            Diag Address
          </div>
          <input
            type="number"
            min="0"
            max="255"
            bind:value={diagAddr}
            disabled={status.running}
            class="w-full px-2 py-1 mt-0.5 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
          />
        </div>
      </div>
      <p class="mt-2 text-[10px] text-[var(--text-secondary)] leading-tight">
        Diag address is the destination byte the flasher writes into every
        UDS request — it must match what the real DME expects.
        <code>16</code> (0x10) is the MEVD17 default and almost always
        correct; auto-populated by Discover.
      </p>
    </div>

    <!-- ── Identity Spoofing ─────────────────────────────────────── -->
    <div class="mt-4 p-4 rounded border border-[var(--border)] bg-[var(--bg-tertiary)]/40">
      <label class="flex items-center gap-2 select-none cursor-pointer">
        <input
          type="checkbox"
          bind:checked={spoofEnabled}
          disabled={status.running}
          class="accent-[var(--accent)]"
        />
        <span class="text-xs font-semibold uppercase tracking-wide text-[var(--text-primary)]">
          Enable identity spoofing
        </span>
        <span class="text-[10px] text-[var(--text-secondary)]">
          (off = transparent passthrough)
        </span>
      </label>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
        <label class="block">
          <span class="text-[10px] text-[var(--text-secondary)] uppercase tracking-wide">
            Spoof VIN (17 chars)
          </span>
          <input
            type="text"
            maxlength="17"
            bind:value={spoofVin}
            disabled={status.running || !spoofEnabled}
            placeholder="TEST1234567ABCDE89"
            class="mt-1 w-full px-3 py-2 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-sm focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
          />
        </label>
        <label class="block">
          <span class="text-[10px] text-[var(--text-secondary)] uppercase tracking-wide">
            Spoof MAC (12 hex)
          </span>
          <input
            type="text"
            maxlength="17"
            bind:value={spoofMac}
            disabled={status.running || !spoofEnabled}
            placeholder="001A3744FFEE"
            class="mt-1 w-full px-3 py-2 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-sm focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
          />
        </label>
      </div>
      <p class="mt-2 text-[10px] text-[var(--text-secondary)] leading-tight">
        When enabled, the discovery reply AND every <code>62 F190</code>
        response from the real DME are rewritten to advertise these
        values. Blank fields fall back to the detected real values, so
        you can spoof just the VIN and leave the MAC untouched.
      </p>
    </div>

    <!-- ── Active values preview ─────────────────────────────────── -->
    <div
      class="mt-4 p-4 rounded border-2 bg-[var(--bg-tertiary)]/20"
      style="border-color: {spoofEnabled
        ? 'var(--accent)'
        : 'var(--border)'};"
    >
      <div class="flex items-center justify-between mb-2">
        <span class="text-xs font-semibold uppercase tracking-wide text-[var(--text-primary)]">
          What the flasher will see
        </span>
        <span
          class="text-[10px] font-mono px-2 py-0.5 rounded"
          style="color: {spoofEnabled
            ? 'var(--accent)'
            : 'var(--text-secondary)'}; border: 1px solid {spoofEnabled
            ? 'var(--accent)'
            : 'var(--border)'};"
        >
          {spoofEnabled ? 'SPOOFING ACTIVE' : 'TRANSPARENT'}
        </span>
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
        <div>
          <div class="text-[10px] text-[var(--text-secondary)] uppercase tracking-wide">VIN</div>
          <div
            class="break-all"
            style="color: {spoofEnabled && spoofVin.trim()
              ? 'var(--accent)'
              : 'var(--text-primary)'};"
          >
            {activeVin}
          </div>
        </div>
        <div>
          <div class="text-[10px] text-[var(--text-secondary)] uppercase tracking-wide">MAC</div>
          <div
            class="break-all"
            style="color: {spoofEnabled && spoofMac.trim()
              ? 'var(--accent)'
              : 'var(--text-primary)'};"
          >
            {activeMac}
          </div>
        </div>
        <div>
          <div class="text-[10px] text-[var(--text-secondary)] uppercase tracking-wide">
            Diag Address
          </div>
          <div class="text-[var(--text-primary)]">
            {diagAddr} (0x{diagAddr.toString(16).padStart(2, '0').toUpperCase()})
          </div>
        </div>
      </div>
    </div>

    {#if errorMsg}
      <div class="mt-3 text-xs text-[var(--error)]">{errorMsg}</div>
    {/if}

    <div class="mt-4 flex gap-2">
      {#if status.running}
        <button
          type="button"
          onclick={stopProxy}
          class="px-4 py-2 rounded border border-[var(--error)] text-[var(--error)] text-sm font-semibold hover:bg-[var(--error)] hover:text-black"
        >
          Stop Proxy
        </button>
      {:else}
        <button
          type="button"
          onclick={startProxy}
          class="px-4 py-2 rounded border border-[var(--accent)] text-[var(--accent)] text-sm font-semibold hover:bg-[var(--accent)] hover:text-black"
        >
          Start Proxy
        </button>
      {/if}
    </div>

    <div class="mt-4 text-xs font-mono text-[var(--text-secondary)] space-y-1">
      <div>Status: <span class="text-[var(--text-primary)]">{statusLine}</span></div>
      {#if capturesDir}
        <div class="break-all">Captures: {capturesDir}</div>
      {/if}
      {#if status.running}
        <div>
          Sessions: <span class="text-[var(--accent)]">{status.sessions}</span>
          · Frames: <span class="text-[var(--accent)]">{status.frames}</span>
          · Rewrites: <span class="text-[var(--accent)]">{status.rewrites}</span>
        </div>
        <div>
          C→U: {formatBytes(status.bytes_c2u)} · U→C: {formatBytes(status.bytes_u2c)}
        </div>
      {/if}
    </div>
  </div>

  <!-- ── Captured sessions list ──────────────────────────────────── -->
  <div class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)]">
    <div class="flex items-center justify-between mb-3">
      <h3 class="text-sm font-semibold text-[var(--text-primary)]">
        Captured Sessions ({sessions.length})
      </h3>
      <button
        type="button"
        class="text-xs px-2 py-1 rounded border border-[var(--border)] hover:bg-[var(--bg-tertiary)]"
        onclick={refreshSessions}
      >
        Refresh
      </button>
    </div>
    {#if sessionsError}
      <div class="text-xs text-[var(--error)] mb-2">{sessionsError}</div>
    {/if}
    {#if sessions.length === 0}
      <div class="text-xs text-[var(--text-secondary)]">
        No proxy sessions captured yet. Start the proxy and let a
        flashing app go through it — every connection lands here as a
        timestamped capture you can export to Wireshark .pcap.
      </div>
    {:else}
      <div class="space-y-2">
        {#each sessions as s}
          <div class="p-3 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] font-mono text-xs">
            <div class="flex items-center justify-between gap-2">
              <div class="min-w-0">
                <div class="text-[var(--text-primary)]">
                  <span class="text-[var(--accent)]">{s.flasher_peer}</span>
                  <span class="ml-2 text-[var(--text-secondary)]">→ {s.upstream_addr}</span>
                </div>
                <div class="mt-1 text-[var(--text-secondary)]">
                  {s.started_at} · {s.frames} frames · {formatBytes(s.bytes)}
                  {#if s.spoof_vin}
                    · spoof <span class="text-[var(--accent)]">{s.spoof_vin}</span>
                  {/if}
                </div>
                <div class="mt-1 text-[var(--text-secondary)] break-all">{s.dir_path}</div>
              </div>
              <button
                type="button"
                class="shrink-0 text-xs px-3 py-1.5 rounded border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)] hover:text-black disabled:opacity-50"
                disabled={exportingDir !== null}
                onclick={() => exportSession(s)}
              >
                {exportingDir === s.dir_name ? 'Exporting…' : 'Export .pcap'}
              </button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  {#if frames.length > 0}
    <div class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)]">
      <h3 class="text-sm font-semibold text-[var(--text-primary)] mb-3">
        Live Frames (last {frames.length})
      </h3>
      <div class="space-y-1 max-h-96 overflow-y-auto font-mono text-xs">
        {#each frames as f}
          <div class="leading-tight">
            <span
              class:text-[var(--accent)]={f.direction === 'U2C'}
              class:text-[var(--text-secondary)]={f.direction === 'C2U'}
            >
              {f.direction}
            </span>
            <span class="ml-2 text-[var(--text-secondary)]">
              ctl=0x{f.control.toString(16).padStart(4, '0').toUpperCase()}
            </span>
            <span class="ml-2">{f.bytes_hex}</span>
            {#if f.note}
              <span class="ml-2 text-[var(--accent)]">[{f.note}]</span>
            {/if}
          </div>
        {/each}
      </div>
    </div>
  {/if}
</div>
