<script lang="ts">
  import { invoke, Channel } from '@tauri-apps/api/core';
  import { save } from '@tauri-apps/plugin-dialog';
  import { writeFile } from '@tauri-apps/plugin-fs';
  import { onDestroy } from 'svelte';
  import Spinner from './Spinner.svelte';
  import {
    flushPaint,
    pullLastBytes,
    pullLastOpLog,
    siblingLogPath,
    scrollIntoViewOnFocus,
  } from '../mobile-utils';
  import { haptic } from '../haptics';
  import { loadPersisted, savePersisted } from '../persistent-state';
  import { pushCloser } from '../back-button';
  import type {
    BackupResult,
    BackupSaveFormat,
    BackupStatus,
    BackupProgress,
    DiscoveredDevice,
  } from '../types';

  // ── Form state ────────────────────────────────────────────────────────
  // Default ECU is the primary DME (0x12). DME2 is 0x13 — exposed via the
  // ECU dropdown in advanced mode. FEM and other gateways are intentionally
  // excluded; this tool only targets MEVD17 DME/DME2.
  //
  // Initial values are loaded from localStorage so the form survives
  // app backgrounding (e.g. picking a save location on Android, which
  // can kill and restore the WebView). `$effect` below persists every
  // change back so we always have the last-known values on relaunch.
  let ip: string = $state(loadPersisted<string>('cal.ip', ''));
  let ecuAddressHex: string = $state(
    loadPersisted<string>('cal.ecu', '12'),
  );
  let saveFormat: BackupSaveFormat = $state(
    loadPersisted<BackupSaveFormat>('cal.saveFormat', 'raw'),
  );
  let advancedMode: boolean = $state(
    loadPersisted<boolean>('cal.advancedMode', false),
  );

  $effect(() => {
    savePersisted('cal.ip', ip);
  });
  $effect(() => {
    savePersisted('cal.ecu', ecuAddressHex);
  });
  $effect(() => {
    savePersisted('cal.saveFormat', saveFormat);
  });
  $effect(() => {
    savePersisted('cal.advancedMode', advancedMode);
  });

  // ── Run state ─────────────────────────────────────────────────────────
  let status: BackupStatus = $state('idle');
  let progressPercent: number = $state(0);
  let bytesRead: number = $state(0);
  let totalBytes: number = $state(0);
  let elapsedMs: number = $state(0);
  let readStartedAt: number = $state(0);
  let tickNow: number = $state(0);
  let tickTimer: ReturnType<typeof setInterval> | null = null;
  let statusNote: string = $state('');
  let result: BackupResult | null = $state(null);
  let errorMsg: string = $state('');

  // Cancellation flag — set when the user taps Cancel during a read.
  let cancelRequested: boolean = $state(false);

  // Client-side elapsed wall-clock, ticked every 500ms while a read
  // is active. Independent of whatever the Rust side sends in
  // ProgressEvent — so rate/ETA/Elapsed still update even if a
  // channel payload field goes missing or a rebuild is stale.
  const clientElapsedMs = $derived(
    readStartedAt > 0 ? Math.max(0, tickNow - readStartedAt) : 0,
  );
  // Prefer the Rust-reported elapsed if present (more precise),
  // otherwise fall back to the client tick.
  const effectiveElapsedMs = $derived(elapsedMs > 0 ? elapsedMs : clientElapsedMs);
  const bytesPerSec = $derived(
    effectiveElapsedMs > 0 ? (bytesRead / effectiveElapsedMs) * 1000 : 0,
  );
  const etaSeconds = $derived(
    bytesPerSec > 0 && totalBytes > bytesRead
      ? Math.round((totalBytes - bytesRead) / bytesPerSec)
      : 0,
  );

  // ── Discovery state ───────────────────────────────────────────────────
  let discovering: boolean = $state(false);
  let discoveredDevices: DiscoveredDevice[] = $state([]);
  let discoveryError: string = $state('');

  async function handleDiscover() {
    discovering = true;
    discoveryError = '';
    discoveredDevices = [];
    await flushPaint();
    try {
      discoveredDevices = await invoke<DiscoveredDevice[]>('discover_vehicles');
      if (discoveredDevices.length === 1) {
        ip = discoveredDevices[0].ip;
      } else if (discoveredDevices.length === 0) {
        discoveryError = 'No vehicles found. Check ENET cable and try again.';
      }
    } catch (e) {
      discoveryError = String(e);
    } finally {
      discovering = false;
    }
  }

  function selectDevice(d: DiscoveredDevice) {
    ip = d.ip;
  }

  // Auto-run discovery on first mount.
  let didAutoDiscover = false;
  $effect(() => {
    if (!didAutoDiscover) {
      didAutoDiscover = true;
      handleDiscover();
    }
  });

  onDestroy(() => {
    // Nothing to clean up — channels are scoped to the active invoke
    // and tear down automatically when the command resolves.
  });

  /// Cancel an in-progress operation. Sets the local cancel-requested
  /// state (the UI can react immediately) and asks the Rust side to
  /// raise the cooperative cancel flag. The active read loop will
  /// notice on its next iteration and bail with "Cancelled by user".
  async function handleCancel() {
    haptic('heavy');
    cancelRequested = true;
    try {
      await invoke('cancel_active_operation');
    } catch (e) {
      console.warn('cancel_active_operation failed:', e);
    }
  }

  // Register a back-button closer while the read is active so the
  // Android hardware back button triggers a cancel instead of just
  // exiting the app mid-operation. The effect auto-unregisters when
  // the reading state ends via the returned cleanup function.
  $effect(() => {
    if (status !== 'reading') return;
    const unreg = pushCloser(() => {
      void handleCancel();
    });
    return unreg;
  });

  function parseEcuAddress(): number | null {
    const cleaned = ecuAddressHex.trim().replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]{1,2}$/.test(cleaned)) return null;
    return parseInt(cleaned, 16);
  }

  async function handleStartRead() {
    haptic('medium');
    const ecuAddress = parseEcuAddress();
    if (ecuAddress === null) {
      errorMsg = 'ECU address must be a 1–2 digit hex value (e.g. 12)';
      status = 'error';
      haptic('error');
      return;
    }
    if (!ip.trim()) {
      errorMsg = 'Gateway IP is required';
      status = 'error';
      haptic('error');
      return;
    }

    const defaultName = `MEVD17_cal_${saveFormat === 'padded_4mb' ? '4MB' : 'raw'}.bin`;
    const outputPath = await save({
      defaultPath: defaultName,
      filters: [{ name: 'Binary', extensions: ['bin'] }],
    });
    if (!outputPath) return;

    status = 'reading';
    progressPercent = 0;
    bytesRead = 0;
    totalBytes = 0;
    elapsedMs = 0;
    readStartedAt = Date.now();
    tickNow = readStartedAt;
    if (tickTimer) clearInterval(tickTimer);
    tickTimer = setInterval(() => {
      tickNow = Date.now();
    }, 500);
    statusNote = '';
    result = null;
    errorMsg = '';
    cancelRequested = false;

    await flushPaint();

    // Set up a Tauri Channel to receive progress updates from the
    // Rust read loop. Channels are scoped to the active command (no
    // global event-bus buffering quirks) and work reliably on every
    // platform including Android WebView. The Rust side calls
    // `on_progress.send(ProgressEvent { ... })` after every block;
    // the closure here runs in the JS event loop and updates Svelte
    // reactive state which re-renders the inline progress card.
    const onProgress = new Channel<BackupProgress>();
    onProgress.onmessage = (msg) => {
      bytesRead = msg.bytesRead;
      totalBytes = msg.total;
      progressPercent = msg.percentage;
      elapsedMs = msg.elapsedMs;
      if (msg.note !== undefined) statusNote = msg.note;
    };

    try {
      const meta = await invoke<BackupResult>('read_calibration_region', {
        onProgress,
        ip: ip.trim(),
        ecuAddress,
        saveFormat,
      });
      const bytes = await pullLastBytes();
      await writeFile(outputPath, bytes);

      // Pull the per-operation text log that the Rust side built
      // alongside the artifact and write it as a sibling `.log` file
      // in the same directory/URI the user picked. Best-effort: if
      // the log write fails we still keep the artifact success path.
      try {
        const logText = await pullLastOpLog();
        if (logText) {
          const logPath = siblingLogPath(outputPath);
          const encoder = new TextEncoder();
          await writeFile(logPath, encoder.encode(logText));
        }
      } catch (logErr) {
        console.warn('sibling log write failed:', logErr);
      }

      result = {
        success: meta.success,
        file_path: outputPath,
        bytes_read: meta.bytes_read,
        file_size: meta.file_size,
        format: meta.format,
        message: `${meta.message} → ${outputPath}`,
      };
      status = 'done';
      haptic('success');
    } catch (e) {
      const msg = String(e);
      // Distinguish user-initiated cancellation from real errors.
      if (msg.includes('Cancelled by user')) {
        errorMsg = 'Read cancelled.';
        haptic('warning');
      } else {
        errorMsg = msg;
        haptic('error');
      }

      // Even on failure, try to pull and save the operation log —
      // it's the whole point of having per-feature logs, the failure
      // case is when you most want the trace. Write it next to the
      // user-picked artifact path so it's findable.
      try {
        const logText = await pullLastOpLog();
        if (logText) {
          const logPath = siblingLogPath(outputPath);
          const encoder = new TextEncoder();
          await writeFile(logPath, encoder.encode(logText));
        }
      } catch (logErr) {
        console.warn('sibling log write failed (error path):', logErr);
      }

      status = 'error';
    } finally {
      cancelRequested = false;
      if (tickTimer) {
        clearInterval(tickTimer);
        tickTimer = null;
      }
    }
  }

  function handleReset() {
    status = 'idle';
    result = null;
    errorMsg = '';
    progressPercent = 0;
    bytesRead = 0;
    totalBytes = 0;
    elapsedMs = 0;
  }

  function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(2)} MB`;
  }

  function formatRate(bps: number): string {
    if (bps <= 0) return '— KB/s';
    if (bps < 1024) return `${bps.toFixed(0)} B/s`;
    if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(1)} KB/s`;
    return `${(bps / 1024 / 1024).toFixed(2)} MB/s`;
  }

  function formatEta(seconds: number): string {
    if (seconds <= 0) return '—';
    return formatDuration(seconds);
  }

  /// Always renders a duration. Sub-60s as `Ns`, 60s+ as `Mm SSs`. Used
  /// for elapsed time so the modal never shows a placeholder mid-read.
  function formatDuration(seconds: number): string {
    const safe = Math.max(0, seconds);
    const m = Math.floor(safe / 60);
    const s = safe % 60;
    if (m === 0) return `${s}s`;
    return `${m}m ${s.toString().padStart(2, '0')}s`;
  }
</script>

<div class="space-y-6">
  <!--
    Inline progress card — takes the place of the form while the read is
    running. This is an industry-standard mobile UI pattern: long-running
    operations transition the panel content in-place rather than opening
    a modal overlay. Works correctly on every platform because it's just
    normal-flow content, no position: fixed, no stacking-context trickery.
    See src/lib/components/mobile/MobileShell.svelte for the layout
    rationale.
  -->
  {#if status === 'reading'}
    <div
      class="p-5 sm:p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--accent)]"
      style="box-shadow: 0 0 24px var(--accent-glow);"
    >
      <div class="flex items-center gap-3 mb-4">
        <Spinner size={22} />
        <h2 class="text-base sm:text-lg font-semibold text-[var(--text-primary)]">
          Reading MEVD17 Calibration
        </h2>
      </div>

      <div class="w-full h-3 bg-[var(--bg-tertiary)] rounded overflow-hidden mb-1">
        <div
          class="h-full bg-[var(--accent)] transition-[width] duration-150"
          style="width: {progressPercent}%"
        ></div>
      </div>
      <div class="flex justify-between text-xs text-[var(--text-secondary)] mb-4">
        <span>{progressPercent}%</span>
        <span class="font-mono">
          {formatBytes(bytesRead)} / {totalBytes ? formatBytes(totalBytes) : '—'}
        </span>
      </div>

      <dl class="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
        <dt class="text-[var(--text-secondary)]">Transfer rate</dt>
        <dd class="font-mono text-right text-[var(--text-primary)]">
          {formatRate(bytesPerSec)}
        </dd>
        <dt class="text-[var(--text-secondary)]">ETA</dt>
        <dd class="font-mono text-right text-[var(--text-primary)]">
          {formatEta(etaSeconds)}
        </dd>
        <dt class="text-[var(--text-secondary)]">Elapsed</dt>
        <dd class="font-mono text-right text-[var(--text-primary)]">
          {formatDuration(Math.floor(effectiveElapsedMs / 1000))}
        </dd>
      </dl>

      {#if statusNote}
        <div
          class="mt-4 px-3 py-2 rounded-md bg-[var(--bg-tertiary)] border border-[var(--warning,#d97706)]/40 text-xs text-[var(--warning,#d97706)] text-center font-medium"
        >
          {statusNote}
        </div>
      {/if}

      <p class="mt-5 mb-4 text-xs text-[var(--text-secondary)] text-center">
        Do not unplug the ENET cable or turn the ignition off.
      </p>

      <button
        type="button"
        onclick={handleCancel}
        disabled={cancelRequested}
        class="w-full min-h-[48px] py-3 bg-[var(--bg-tertiary)] border-2 border-[var(--error)] text-[var(--error)] rounded-lg font-semibold text-base hover:bg-[var(--error)] hover:text-white transition-colors disabled:opacity-50 disabled:hover:bg-[var(--bg-tertiary)] disabled:hover:text-[var(--error)]"
      >
        {cancelRequested ? 'Cancelling…' : 'Cancel Read'}
      </button>
    </div>
  {:else}
  <div class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)]">
    <h2 class="text-lg font-semibold text-[var(--text-primary)] mb-1">
      Read MEVD17 Calibration
    </h2>
    <p class="text-sm text-[var(--text-secondary)] mb-2">
      Connects to the vehicle's HSFZ gateway and reads the ~511&nbsp;KB
      calibration region using ReadMemoryByAddress (no security access
      required on a stock unprotected flash).
    </p>
    <p class="text-xs text-[var(--accent)] mb-2">
      ⚠ Currently only supports MEVD17 DME (0x12) / DME2 (0x13). Other ECUs
      are not implemented.
    </p>
    <!--
      Not every flash in the wild is readable. Aftermarket / custom
      flashes, some dealer-applied updates, and anti-tamper packages
      can disable ReadMemoryByAddress for the calibration region —
      the ECU will answer HSFZ, accept the session, and then reject
      the actual read with an NRC. Surface that up-front so a user
      whose read fails with "requestOutOfRange" or "conditionsNotCorrect"
      knows it isn't their setup — the ECU is locked.
    -->
    <div
      class="mb-6 p-3 rounded-md bg-[var(--bg-tertiary)] border border-[var(--warning)]/40"
    >
      <p class="text-xs text-[var(--warning)] font-semibold mb-1">
        Compatibility notice
      </p>
      <p class="text-xs text-[var(--text-secondary)] leading-relaxed">
        This reads the <em>unprotected</em> calibration region present on
        stock MEVD17 flashes. If the ECU currently has a custom or
        aftermarket flash, an anti-tamper package, or a map that
        disables ReadMemoryByAddress, the read will fail with an NRC
        like <code class="font-mono">0x31</code> (requestOutOfRange) or
        <code class="font-mono">0x22</code> (conditionsNotCorrect).
        That's the ECU refusing the request — retrying won't help, and
        it's not a bug in this tool.
      </p>
    </div>

    <!-- Discovery panel — default behaviour -->
    <div class="mb-4">
      <div class="flex items-center justify-between mb-2">
        <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
          Vehicle
        </span>
        <button
          type="button"
          onclick={handleDiscover}
          disabled={discovering}
          class="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] disabled:opacity-50"
        >
          {#if discovering}
            <Spinner size={11} />
            <span>Scanning…</span>
          {:else}
            <span>Rescan</span>
          {/if}
        </button>
      </div>

      {#if discovering}
        <!-- Discovery loading card — animated spinner + sequenced status
             text so the user has clear visual confirmation that work
             is happening. The 3-second timeout in the Rust discovery
             function (`DISCOVERY_TIMEOUT_SECS`) bounds how long this
             stays on screen. -->
        <div
          class="p-4 rounded bg-[var(--bg-tertiary)] border border-[var(--accent)]/40 flex items-center gap-3"
          style="box-shadow: 0 0 16px var(--accent-glow);"
        >
          <Spinner size={20} />
          <div class="flex flex-col gap-0.5 min-w-0">
            <span class="text-sm text-[var(--text-primary)] font-medium">
              Searching for vehicles
            </span>
            <span class="text-[11px] text-[var(--text-secondary)]">
              Broadcasting HSFZ vehicle-identification probe on UDP 6811…
            </span>
          </div>
        </div>
      {:else if discoveredDevices.length > 0}
        <div class="space-y-2">
          {#each discoveredDevices as d}
            <button
              type="button"
              onclick={() => selectDevice(d)}
              class="w-full text-left p-3 rounded border transition-colors font-mono text-sm
                {ip === d.ip
                  ? 'bg-[var(--bg-tertiary)] border-[var(--accent)]'
                  : 'bg-[var(--bg-tertiary)] border-[var(--border)] hover:border-[var(--accent)]'}"
            >
              <div class="flex items-center justify-between">
                <span class="text-[var(--text-primary)] font-bold">{d.ip}</span>
                {#if ip === d.ip}
                  <span class="text-xs text-[var(--accent)]">SELECTED</span>
                {/if}
              </div>
              <div class="text-xs text-[var(--text-secondary)] mt-1">
                VIN: {d.vin}
              </div>
              <div class="text-xs text-[var(--text-secondary)]">
                MAC: {d.mac_address} · diag: 0x{d.diag_address.toString(16).toUpperCase().padStart(2, '0')}
              </div>
            </button>
          {/each}
        </div>
      {:else}
        <div class="p-3 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] text-sm text-[var(--text-secondary)]">
          {discoveryError || 'No vehicles found yet. Click Rescan with the ENET cable connected.'}
        </div>
      {/if}
    </div>

    <!-- Advanced: manual IP / ECU override -->
    <div class="mb-4">
      <button
        type="button"
        onclick={() => (advancedMode = !advancedMode)}
        class="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] underline"
      >
        {advancedMode ? '▼ Hide' : '▶ Advanced'} (manual connection)
      </button>
      {#if advancedMode}
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-3">
          <label class="block">
            <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
              Gateway IP
            </span>
            <input
              type="text"
              bind:value={ip}
              placeholder="192.168.0.10"
              inputmode="decimal"
              pattern="[0-9.]*"
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck="false"
              use:scrollIntoViewOnFocus
              class="mt-1 w-full px-3 py-3 rounded-lg bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-base focus:outline-none focus:border-[var(--accent)]"
            />
          </label>
          <label class="block">
            <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
              ECU Address (12 = DME, 13 = DME2)
            </span>
            <select
              bind:value={ecuAddressHex}
              class="mt-1 w-full px-3 py-3 rounded-lg bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-base focus:outline-none focus:border-[var(--accent)]"
            >
              <option value="12">0x12 — DME</option>
              <option value="13">0x13 — DME2</option>
            </select>
          </label>
        </div>
      {/if}
    </div>

    <div class="mt-4">
      <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
        Save Format
      </span>
      <div class="flex gap-2 mt-1">
        <button
          type="button"
          onclick={() => (saveFormat = 'raw')}
          class="flex-1 min-h-[48px] py-3 px-4 rounded-lg text-base font-semibold transition-colors border-2
            {saveFormat === 'raw'
              ? 'bg-[var(--accent)] border-[var(--accent)] text-white'
              : 'bg-[var(--bg-tertiary)] border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'}"
        >
          Raw (~511 KB)
        </button>
        <button
          type="button"
          onclick={() => (saveFormat = 'padded_4mb')}
          class="flex-1 min-h-[48px] py-3 px-4 rounded-lg text-base font-semibold transition-colors border-2
            {saveFormat === 'padded_4mb'
              ? 'bg-[var(--accent)] border-[var(--accent)] text-white'
              : 'bg-[var(--bg-tertiary)] border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'}"
        >
          4 MB Padded
        </button>
      </div>
    </div>

    <button
      type="button"
      onclick={handleStartRead}
      class="mt-6 w-full min-h-[48px] py-3 bg-[var(--accent)] text-white rounded-lg font-semibold text-base hover:bg-[var(--accent-hover)] transition-colors"
    >
      Start Read
    </button>
  </div>
  {/if}

  {#if status === 'done' && result}
    <div class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)]">
      <p class="text-[var(--accent)] font-medium mb-3">Read complete</p>
      <div class="grid grid-cols-2 gap-3 text-sm">
        <div>
          <span class="text-[var(--text-secondary)]">Bytes read:</span>
          <span class="ml-2 font-mono">{formatBytes(result.bytes_read)}</span>
        </div>
        <div>
          <span class="text-[var(--text-secondary)]">File size:</span>
          <span class="ml-2 font-mono">{formatBytes(result.file_size)}</span>
        </div>
        <div class="col-span-2">
          <span class="text-[var(--text-secondary)]">Format:</span>
          <span class="ml-2 font-mono">{result.format}</span>
        </div>
        <div class="col-span-2 break-all">
          <span class="text-[var(--text-secondary)]">Path:</span>
          <span class="ml-2 font-mono text-xs">{result.file_path}</span>
        </div>
      </div>
      <button
        type="button"
        onclick={handleReset}
        class="mt-4 px-4 py-2 bg-[var(--bg-tertiary)] text-[var(--text-primary)] rounded hover:bg-[var(--border)] transition-colors text-sm"
      >
        Read Another
      </button>
    </div>
  {:else if status === 'error'}
    <div class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--error)]">
      <p class="text-[var(--error)] font-medium">Read failed</p>
      <p class="text-sm text-[var(--text-secondary)] mt-2 break-all">{errorMsg}</p>
      <button
        type="button"
        onclick={handleReset}
        class="mt-4 px-4 py-2 bg-[var(--bg-tertiary)] text-[var(--text-primary)] rounded hover:bg-[var(--border)] transition-colors text-sm"
      >
        Try Again
      </button>
    </div>
  {/if}
</div>
