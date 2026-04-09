<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import { save } from '@tauri-apps/plugin-dialog';
  import { writeFile } from '@tauri-apps/plugin-fs';
  import { onDestroy } from 'svelte';
  import InterfaceSelector from './InterfaceSelector.svelte';
  import CaptureControls from './CaptureControls.svelte';
  import LiveStats from './LiveStats.svelte';
  import SessionTable from '../SessionTable.svelte';
  import EventLog from '../EventLog.svelte';
  import ToastStrip from '../ToastStrip.svelte';
  import { pullLastBytes, pullLastOpLog, siblingLogPath } from '../../mobile-utils';

  // Pull the per-operation text log the Rust feature command built
  // and write it as a sibling `.log` next to the artifact the user
  // just picked. Best-effort — never throws back into the caller.
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

  // Toast state — replaces browser alert() calls.
  let toastMessage: string = $state('');
  let toastKind: 'success' | 'error' = $state('success');
  let toastTimer: ReturnType<typeof setTimeout> | null = null;
  function showToast(kind: 'success' | 'error', message: string) {
    toastMessage = message;
    toastKind = kind;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toastMessage = '';
      toastTimer = null;
    }, 5000);
  }
  import type {
    CaptureStatus,
    NetworkInterface,
    CaptureStats,
    CaptureSummary,
    ExtractionResult,
  } from '../../types';

  // ── Status state machine ─────────────────────────────────────────
  // idle → starting → capturing → stopping → summary
  //                                          ├→ extracting → done
  //                                          └→ (save / discard)
  type PanelStatus =
    | 'idle'
    | 'starting'
    | 'capturing'
    | 'stopping'
    | 'summary'
    | 'extracting'
    | 'done'
    | 'error';

  let status = $state<PanelStatus>('idle');
  let interfaces: NetworkInterface[] = $state([]);
  let selectedInterface: string = $state('');
  let stats: CaptureStats = $state({
    packet_count: 0,
    byte_count: 0,
    duration_secs: 0,
    packets_per_sec: 0,
  });
  let summary: CaptureSummary | null = $state(null);
  let result: ExtractionResult | null = $state(null);
  let errorMsg: string = $state('');
  let interfacesLoading: boolean = $state(true);

  let unlistenStats: (() => void) | null = null;
  let unlistenError: (() => void) | null = null;

  const captureStatus = $derived<CaptureStatus>(
    status === 'capturing' || status === 'starting'
      ? 'capturing'
      : status === 'stopping'
        ? 'stopping'
        : 'idle',
  );
  const canStart = $derived(
    status === 'idle' && selectedInterface !== '' && !interfacesLoading,
  );
  const canStop = $derived(status === 'capturing');
  const isCapturing = $derived(status === 'capturing' || status === 'starting');
  const showLiveStats = $derived(
    status === 'capturing' || status === 'stopping' || status === 'starting',
  );

  loadInterfaces();

  async function loadInterfaces() {
    interfacesLoading = true;
    try {
      interfaces = await invoke<NetworkInterface[]>('list_interfaces');
      const preferred = interfaces.find((i) => i.is_up && !i.is_loopback);
      selectedInterface = preferred?.name ?? interfaces[0]?.name ?? '';
      interfacesLoading = false;
    } catch (e) {
      interfacesLoading = false;
      errorMsg = String(e);
      status = 'error';
    }
  }

  async function startCapture() {
    status = 'starting';
    errorMsg = '';
    result = null;
    summary = null;
    stats = { packet_count: 0, byte_count: 0, duration_secs: 0, packets_per_sec: 0 };

    unlistenStats?.();
    unlistenStats = await listen<CaptureStats>('capture:stats', (event) => {
      stats = event.payload;
    });
    unlistenError?.();
    unlistenError = await listen<string>('capture:error', (event) => {
      errorMsg = String(event.payload);
      status = 'error';
      cleanupListeners();
    });

    try {
      await invoke('start_capture', { interfaceName: selectedInterface });
      status = 'capturing';
    } catch (e) {
      errorMsg = String(e);
      status = 'error';
      cleanupListeners();
    }
  }

  async function stopCapture() {
    status = 'stopping';
    try {
      summary = await invoke<CaptureSummary>('stop_capture');
      status = 'summary';
    } catch (e) {
      errorMsg = String(e);
      status = 'error';
    }
    cleanupListeners();
  }

  async function extractFromCapture() {
    status = 'extracting';
    try {
      result = await invoke<ExtractionResult>('extract_captured_flash');
      status = 'done';
    } catch (e) {
      errorMsg = String(e);
      status = 'error';
    }
  }

  async function savePcap() {
    if (!summary) return;
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const defaultName = `bmw_capture_${ts}.pcap`;
    const path = await save({
      defaultPath: defaultName,
      filters: [{ name: 'PCAP', extensions: ['pcap', 'pcapng'] }],
    });
    if (!path) return;
    try {
      await invoke<number>('save_capture_pcap');
      const bytes = await pullLastBytes();
      await writeFile(path, bytes);
      await writeSiblingLog(path);
      const name = path.split(/[\\/]/).pop() ?? path;
      showToast('success', `Saved ${(bytes.length / 1024).toFixed(1)} KB → ${name}`);
    } catch (e) {
      showToast('error', `Save failed: ${e}`);
    }
  }

  async function discardCapture() {
    try {
      await invoke('discard_capture');
    } catch {
      // best-effort — clearing UI state below either way
    }
    handleReset();
  }

  async function handleSaveBin() {
    if (!result) return;
    const vin = result.vin ?? 'unknown';
    const defaultName = `${vin}_captured_${result.binary_size}.bin`;
    const path = await save({
      defaultPath: defaultName,
      filters: [{ name: 'Binary', extensions: ['bin'] }],
    });
    if (!path) return;
    try {
      await invoke<number>('save_binary');
      const bytes = await pullLastBytes();
      await writeFile(path, bytes);
      await writeSiblingLog(path);
      result = { ...result, binary_path: path };
      const name = path.split(/[\\/]/).pop() ?? path;
      showToast('success', `Saved ${(bytes.length / 1024 / 1024).toFixed(2)} MB → ${name}`);
    } catch (e) {
      showToast('error', `Save failed: ${e}`);
    }
  }

  function handleReset() {
    status = 'idle';
    result = null;
    summary = null;
    errorMsg = '';
    stats = { packet_count: 0, byte_count: 0, duration_secs: 0, packets_per_sec: 0 };
    cleanupListeners();
  }

  function cleanupListeners() {
    unlistenStats?.();
    unlistenStats = null;
    unlistenError?.();
    unlistenError = null;
  }

  onDestroy(() => {
    cleanupListeners();
  });

  function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(2)} MB`;
  }

  function formatDuration(s: number): string {
    if (s < 60) return `${s.toFixed(1)} s`;
    const m = Math.floor(s / 60);
    const r = Math.floor(s % 60);
    return `${m}m ${r}s`;
  }
</script>

<div class="space-y-6">
  <!-- Inline toast strip — mobile-native, normal-flow, no fixed positioning -->
  <ToastStrip
    kind={toastKind}
    message={toastMessage}
    onDismiss={() => (toastMessage = '')}
  />
  <!-- ── Purpose blurb ────────────────────────────────────────── -->
  <div
    class="p-5 rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)]/50"
  >
    <p class="font-mono text-[10px] uppercase tracking-widest text-[var(--accent)] mb-1.5">
      Live HSFZ Capture · Flash Session Recorder
    </p>
    <p class="text-sm text-[var(--text-secondary)] leading-relaxed">
      Sniff HSFZ traffic on a network interface during an active flash
      operation. The captured packets can be saved as a PCAP for offline
      analysis, or piped through the flash-extraction pipeline to recover the
      DME binary that was just being written.
    </p>
  </div>

  {#if status === 'error'}
    <div
      class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--error)]"
    >
      <p class="font-mono text-xs uppercase tracking-wider text-[var(--error)]">
        {#if errorMsg.toLowerCase().includes('npcap') || errorMsg.toLowerCase().includes('wpcap')}
          Npcap not installed
        {:else if errorMsg.toLowerCase().includes('permission')}
          Permission denied
        {:else}
          Capture failed
        {/if}
      </p>
      <p class="text-sm text-[var(--text-secondary)] mt-2 break-all">{errorMsg}</p>
      {#if errorMsg.toLowerCase().includes('npcap') || errorMsg.toLowerCase().includes('wpcap')}
        <p class="text-xs text-[var(--text-secondary)] mt-3">
          Live capture requires Npcap. Download it from npcap.com and restart
          the app.
        </p>
      {/if}
      <button
        type="button"
        onclick={handleReset}
        class="mt-4 px-4 py-2 bg-[var(--bg-tertiary)] text-[var(--text-primary)] rounded hover:bg-[var(--border)] transition-colors text-sm"
      >
        Try Again
      </button>
    </div>
  {:else if status === 'summary' && summary}
    <!-- ── Capture summary + action chooser ────────────────────── -->
    <div
      class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)]"
    >
      <p
        class="font-mono text-[10px] uppercase tracking-widest text-[var(--accent)] mb-4"
      >
        Capture Complete · Pick Next Step
      </p>

      <div class="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
        <div>
          <p class="font-mono text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">
            Packets
          </p>
          <p class="font-mono text-base text-[var(--text-primary)]">
            {summary.packet_count.toLocaleString()}
          </p>
        </div>
        <div>
          <p class="font-mono text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">
            Bytes
          </p>
          <p class="font-mono text-base text-[var(--text-primary)]">
            {formatBytes(summary.byte_count)}
          </p>
        </div>
        <div>
          <p class="font-mono text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">
            Duration
          </p>
          <p class="font-mono text-base text-[var(--text-primary)]">
            {formatDuration(summary.duration_secs)}
          </p>
        </div>
        <div>
          <p class="font-mono text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">
            TCP streams
          </p>
          <p class="font-mono text-base text-[var(--text-primary)]">
            {summary.stream_count}
          </p>
        </div>
        <div>
          <p class="font-mono text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">
            HSFZ frames
          </p>
          <p class="font-mono text-base text-[var(--text-primary)]">
            {summary.hsfz_frame_count.toLocaleString()}
          </p>
        </div>
        <div>
          <p class="font-mono text-[10px] uppercase tracking-wider text-[var(--text-muted)] mb-1">
            Flash session
          </p>
          {#if summary.flash_session_likely}
            <p class="font-mono text-base text-[var(--success)]">DETECTED</p>
          {:else}
            <p class="font-mono text-base text-[var(--text-secondary)]">none seen</p>
          {/if}
        </div>
      </div>

      {#if !summary.flash_session_likely}
        <p class="mt-4 text-xs text-[var(--text-secondary)] leading-relaxed">
          No <code class="font-mono text-[var(--accent)]">RequestDownload</code>
          / <code class="font-mono text-[var(--accent)]">TransferData</code> frames
          were seen in this capture, so a flash extract probably won't find any
          binary data — but the raw packets are still useful for transcript
          analysis. Save them to a PCAP file and inspect with Wireshark, or
          discard and try again during the actual flash write.
        </p>
      {/if}

      <div class="mt-5 grid grid-cols-1 sm:grid-cols-3 gap-2">
        <button
          type="button"
          onclick={extractFromCapture}
          disabled={!summary.flash_session_likely && summary.hsfz_frame_count === 0}
          class="py-2.5 rounded font-mono text-xs uppercase tracking-wider transition-colors
            {summary.flash_session_likely
            ? 'bg-[var(--accent)] text-[var(--text-inverse)] hover:bg-[var(--accent-hover)]'
            : 'bg-[var(--bg-tertiary)] text-[var(--text-primary)] hover:bg-[var(--border)]'}
            disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Extract Flash .bin
        </button>
        <button
          type="button"
          onclick={savePcap}
          class="py-2.5 rounded font-mono text-xs uppercase tracking-wider bg-[var(--bg-tertiary)] text-[var(--text-primary)] hover:bg-[var(--border)] transition-colors"
        >
          Save as PCAP…
        </button>
        <button
          type="button"
          onclick={discardCapture}
          class="py-2.5 rounded font-mono text-xs uppercase tracking-wider bg-[var(--bg-tertiary)] text-[var(--error)] hover:bg-[var(--error)]/10 border border-transparent hover:border-[var(--error)] transition-colors"
        >
          Discard
        </button>
      </div>
    </div>
  {:else if status === 'extracting'}
    <div
      class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)] flex items-center gap-3"
    >
      <div
        class="w-4 h-4 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin"
      ></div>
      <span class="font-mono text-xs uppercase tracking-wider text-[var(--text-secondary)]">
        Running flash-extraction pipeline…
      </span>
    </div>
  {:else if status === 'done' && result}
    <!-- ── Extraction success ──────────────────────────────────── -->
    <div
      class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)]"
    >
      <p
        class="font-mono text-[10px] uppercase tracking-widest text-[var(--accent)] mb-4"
      >
        Flash Binary Recovered
      </p>
      <div class="grid grid-cols-2 gap-4 text-sm">
        <div>
          <span class="text-[var(--text-secondary)]">VIN:</span>
          <span class="ml-2 font-mono font-bold">{result.vin ?? 'N/A'}</span>
        </div>
        <div>
          <span class="text-[var(--text-secondary)]">ECU:</span>
          <span class="ml-2 font-mono">
            0x{result.ecu_address.toString(16).toUpperCase().padStart(2, '0')}
          </span>
        </div>
        <div>
          <span class="text-[var(--text-secondary)]">Size:</span>
          <span class="ml-2 font-mono">
            {(result.binary_size / 1024 / 1024).toFixed(2)} MB
          </span>
        </div>
        <div>
          <span class="text-[var(--text-secondary)]">Base:</span>
          <span class="ml-2 font-mono">
            0x{result.base_address.toString(16).toUpperCase().padStart(8, '0')}
          </span>
        </div>
        <div>
          <span class="text-[var(--text-secondary)]">Content:</span>
          <span class="ml-2 font-mono">{result.non_ff_percent.toFixed(1)}% non-0xFF</span>
        </div>
        <div>
          <span class="text-[var(--text-secondary)]">Segments:</span>
          <span class="ml-2 font-mono">{result.segments.length}</span>
        </div>
      </div>
      <div
        class="mt-4 pt-4 border-t border-[var(--border)] text-xs font-mono text-[var(--text-secondary)]"
      >
        <div>First 16: {result.first_16_hex}</div>
        <div>Last 16:  {result.last_16_hex}</div>
      </div>
    </div>

    <SessionTable segments={result.segments} baseAddress={result.base_address} />
    <EventLog events={result.events} />

    <div class="flex gap-3">
      <button
        type="button"
        onclick={handleSaveBin}
        class="px-6 py-2.5 bg-[var(--accent)] text-[var(--text-inverse)] rounded font-mono text-xs uppercase tracking-wider hover:bg-[var(--accent-hover)] transition-colors"
      >
        Save .bin
      </button>
      <button
        type="button"
        onclick={savePcap}
        class="px-6 py-2.5 bg-[var(--bg-tertiary)] text-[var(--text-primary)] rounded font-mono text-xs uppercase tracking-wider hover:bg-[var(--border)] transition-colors"
      >
        Also save PCAP…
      </button>
      <button
        type="button"
        onclick={handleReset}
        class="px-6 py-2.5 bg-[var(--bg-tertiary)] text-[var(--text-primary)] rounded font-mono text-xs uppercase tracking-wider hover:bg-[var(--border)] transition-colors"
      >
        Capture Another
      </button>
    </div>
  {:else}
    <!-- ── Setup & active capture ──────────────────────────────── -->
    <div
      class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)]"
    >
      {#if interfacesLoading}
        <div class="flex items-center gap-3">
          <div
            class="w-5 h-5 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin"
          ></div>
          <span class="text-[var(--text-secondary)]">
            Detecting network interfaces…
          </span>
        </div>
      {:else}
        <InterfaceSelector
          {interfaces}
          bind:selected={selectedInterface}
          disabled={isCapturing}
        />
        <CaptureControls
          {canStart}
          {canStop}
          status={captureStatus}
          onStart={startCapture}
          onStop={stopCapture}
        />
      {/if}
    </div>

    {#if showLiveStats}
      <LiveStats {stats} status={captureStatus} />
    {/if}
  {/if}
</div>

<!-- Toast is rendered inline at the top of the panel via <ToastStrip>. -->
