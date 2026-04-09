<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { save } from '@tauri-apps/plugin-dialog';
  import { readFile, writeFile } from '@tauri-apps/plugin-fs';
  import DropZone from './DropZone.svelte';
  import SessionTable from './SessionTable.svelte';
  import EventLog from './EventLog.svelte';
  import Spinner from './Spinner.svelte';
  import ToastStrip from './ToastStrip.svelte';
  import { flushPaint, pullLastBytes } from '../mobile-utils';
  import type { ExtractionResult, AppStatus } from '../types';

  // Toast state (replaces the browser `alert()` calls, which render as
  // native dialogs on Android and look off-brand / block the UI).
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

  let status: AppStatus = $state('idle');
  let result: ExtractionResult | null = $state(null);
  let errorMsg: string = $state('');
  let pcapPath: string = $state('');

  async function handleFileSelected(path: string) {
    pcapPath = path;
    status = 'loading';
    errorMsg = '';
    result = null;
    await flushPaint();

    try {
      const pcapBytes = await readFile(path);
      result = await invoke<ExtractionResult>('extract_pcap', {
        pcapBytes: Array.from(pcapBytes),
      });
      status = 'done';
    } catch (e) {
      errorMsg = String(e);
      status = 'error';
    }
  }

  async function handleSave() {
    if (!result) return;

    const vin = result.vin ?? 'unknown';
    const defaultName = `${vin}_extracted_${result.binary_size}.bin`;

    const path = await save({
      defaultPath: defaultName,
      filters: [{ name: 'Binary', extensions: ['bin'] }],
    });

    if (!path) return;

    try {
      // Two-phase: Rust builds the binary and stashes it, we pull
      // the raw bytes via ArrayBuffer IPC, then write via plugin-fs.
      // See src/lib/mobile-utils.ts for why.
      await invoke<number>('save_binary');
      const bytes = await pullLastBytes();
      await writeFile(path, bytes);
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
    errorMsg = '';
    pcapPath = '';
  }
</script>

<div class="space-y-6">
  <!-- Inline toast strip — mobile-native, normal-flow, no fixed positioning -->
  <ToastStrip
    kind={toastKind}
    message={toastMessage}
    onDismiss={() => (toastMessage = '')}
  />

  <!-- ── Purpose blurb ─────────────────────────────────────────── -->
  <div class="p-5 rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)]/50">
    <p class="font-mono text-[10px] uppercase tracking-widest text-[var(--accent)] mb-1.5">
      Offline Flash Extraction · PCAP Reader
    </p>
    <p class="text-sm text-[var(--text-secondary)] leading-relaxed">
      Drop a PCAP file recorded during a MEVD17 DME flash session and the
      tool will reassemble the HSFZ/UDS streams, locate every
      <code class="font-mono text-[var(--accent)]">RequestDownload</code> +
      <code class="font-mono text-[var(--accent)]">TransferData</code>
      block, and rebuild the flash binary that was being written to the ECU.
    </p>
  </div>

{#if status === 'idle'}
  <DropZone onFileSelected={handleFileSelected} />
{:else if status === 'loading'}
  <div class="flex items-center gap-3 p-4 sm:p-8 rounded-lg bg-[var(--bg-secondary)] border border-[var(--accent)]/40" style="box-shadow: 0 0 16px var(--accent-glow);">
    <Spinner size={20} />
    <div class="flex flex-col gap-0.5 min-w-0">
      <span class="text-sm font-medium text-[var(--text-primary)]">Extracting flash data</span>
      <span class="text-xs text-[var(--text-secondary)] truncate">{pcapPath.split(/[\\/]/).pop() ?? pcapPath}</span>
    </div>
  </div>
{:else if status === 'error'}
  <div class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--error)]">
    <p class="text-[var(--error)] font-medium">Extraction failed</p>
    <p class="text-sm text-[var(--text-secondary)] mt-2">{errorMsg}</p>
    <button
      onclick={handleReset}
      class="mt-4 px-4 py-2 bg-[var(--bg-tertiary)] text-[var(--text-primary)] rounded hover:bg-[var(--border)] transition-colors"
    >
      Try Another File
    </button>
  </div>
{:else if status === 'done' && result}
  <div class="space-y-6">
    <!-- Summary -->
    <div class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)]">
      <div class="grid grid-cols-2 gap-4 text-sm">
        <div>
          <span class="text-[var(--text-secondary)]">VIN:</span>
          <span class="ml-2 font-mono font-bold">{result.vin ?? 'N/A'}</span>
        </div>
        <div>
          <span class="text-[var(--text-secondary)]">ECU:</span>
          <span class="ml-2 font-mono">0x{result.ecu_address.toString(16).toUpperCase().padStart(2, '0')}</span>
        </div>
        <div>
          <span class="text-[var(--text-secondary)]">Size:</span>
          <span class="ml-2 font-mono">{(result.binary_size / 1024 / 1024).toFixed(2)} MB</span>
        </div>
        <div>
          <span class="text-[var(--text-secondary)]">Base:</span>
          <span class="ml-2 font-mono">0x{result.base_address.toString(16).toUpperCase().padStart(8, '0')}</span>
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

      <div class="mt-4 pt-4 border-t border-[var(--border)] text-xs font-mono text-[var(--text-secondary)]">
        <div>First 16: {result.first_16_hex}</div>
        <div>Last 16:  {result.last_16_hex}</div>
      </div>
    </div>

    <!-- Segments -->
    <SessionTable segments={result.segments} baseAddress={result.base_address} />

    <!-- Events -->
    <EventLog events={result.events} />

    <!-- Actions -->
    <div class="flex gap-3">
      <button
        onclick={handleSave}
        class="px-6 py-2.5 bg-[var(--accent)] text-white rounded font-medium hover:bg-[var(--accent-hover)] transition-colors"
      >
        Save .bin
      </button>
      <button
        onclick={handleReset}
        class="px-6 py-2.5 bg-[var(--bg-tertiary)] text-[var(--text-primary)] rounded hover:bg-[var(--border)] transition-colors"
      >
        Extract Another
      </button>
    </div>
  </div>
{/if}
</div>

<!-- Toast is rendered inline at the top of the panel via <ToastStrip>. -->

