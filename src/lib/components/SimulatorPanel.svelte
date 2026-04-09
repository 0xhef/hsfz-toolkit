<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { open as openDialog } from '@tauri-apps/plugin-dialog';
  import { readTextFile, writeFile } from '@tauri-apps/plugin-fs';
  import { onDestroy } from 'svelte';
  import { save as saveDialog } from '@tauri-apps/plugin-dialog';
  import Spinner from './Spinner.svelte';
  import ToastStrip from './ToastStrip.svelte';
  import {
    flushPaint,
    pullLastBytes,
    pullLastOpLog,
    siblingLogPath,
  } from '../mobile-utils';

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
    SimulatorStatus,
    SimulatorStatusEvent,
    SimulatorTranscriptEvent,
    SimulatorSegmentEvent,
    SimulatorEcuProfile,
    SimulatorCloneProgress,
    SimulatorDmeIdentifiers,
    SimulatorModuleIdent,
    DiscoveredDevice,
    FlashSession,
  } from '../types';

  // ── Form state ───────────────────────────────────────────────────────
  let bindAddr: string = $state('0.0.0.0:6801');
  // Optional artificial flash-rate cap (kB/s) — empty / 0 means
  // "unthrottled". Persisted on the loaded profile so different
  // profiles can have different speeds (e.g. clone-from-car defaults
  // to ~30 kB/s to match real-world telemetry, while a debug profile
  // can stay unthrottled for fast iteration).
  let transferRateKbps: number | null = $state(null);
  let savingThrottle: boolean = $state(false);
  // Empty by default — the user must pick or create a profile. No
  // built-in default; shipping a stranger's VIN as the apparent default
  // was misleading and caused confusion.
  let profileName: string = $state('');
  let profiles: string[] = $state([]);

  // ── Create empty profile flow ────────────────────────────────────────
  let createOpen: boolean = $state(false);
  let createName: string = $state('');
  let createVin: string = $state('');
  let createError: string = $state('');

  // ── Toast notification ───────────────────────────────────────────────
  // Floating top-right banner for save / clone / create outcomes — the
  // inline error/success text underneath each form is easy to miss when
  // the panel scrolls, so a toast surfaces success and failure both.
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
      // 7s for success, 12s for errors so users have time to read them.
      kind === 'success' ? 7000 : 12000,
    );
  }

  // ── DME identifier editor ────────────────────────────────────────────
  // The fields a tuning tool actually queries: F101 (BTLD/SWFL/SWFK/CAFD
  // SVK entries) plus the flash-counter DIDs 0x2502 / 0x2503. Built into
  // the simulator's profile when the user clicks Save.
  function emptyIdent(): SimulatorModuleIdent {
    return { sgbm: '', version: '' };
  }
  let editorOpen: boolean = $state(false);
  let identBtld: SimulatorModuleIdent = $state(emptyIdent());
  let identSwflProgram: SimulatorModuleIdent = $state(emptyIdent());
  // One calibration slot. The backend auto-picks the class byte (SWFL
  // for legacy MEVD17 / SWFK for newer DMEs) based on what's already in
  // the existing F101, so there's no UI choice here.
  let identCalibration: SimulatorModuleIdent = $state(emptyIdent());
  let identCafd: SimulatorModuleIdent = $state(emptyIdent());
  let identHwel: SimulatorModuleIdent = $state(emptyIdent());
  // Svelte 5 `bind:value` on `<input type="number">` coerces to
  // `number | null`, so the state types must match — using `string`
  // here would crash when the user clicks Save (`.trim is not a function`).
  let flashCounter: number | null = $state(null);
  let maxFlashCounter: number | null = $state(null);

  // ── Plain text identification DIDs ────────────────────────────────
  // What HSFZ flash tools read on connect to populate their UI. All
  // are optional — leave blank to fall through to the simulator's 0xFF
  // default (the flasher will display N/A / Unknown for those fields).
  let identSerial: string = $state('');
  let identDmeSupplier: string = $state('');
  let identSystemSupplier: string = $state('');
  let identHardwareNumber: string = $state('');

  let identZbnr: string = $state('');
  /// `YYMMDD`, e.g. `240115`.
  let identManufactureDate: string = $state('');
  /// Volts. Number-typed input so Svelte coerces to `number | null`.
  let identVoltageV: number | null = $state(null);
  let identDmeType: string = $state('');
  let identEngineCode: string = $state('');
  let identCalibrationId: string = $state('');
  let identCvnHex: string = $state(''); // hex string in the UI, converted to u32 on save
  let identLongDesignation: string = $state('');
  let identProjectCode: string = $state('');
  let editorError: string = $state('');
  let editorSavedNote: string = $state('');

  // Auto-uppercase all DME identifier inputs as the user types so SGBM
  // hex digits and version components stay visually consistent. Each
  // assignment is gated on a real diff to avoid an infinite re-run.
  function upper(s: string): string {
    return s.toUpperCase();
  }
  $effect(() => {
    const u = upper(identHwel.sgbm);
    if (u !== identHwel.sgbm) identHwel.sgbm = u;
    const v = upper(identHwel.version);
    if (v !== identHwel.version) identHwel.version = v;
  });
  $effect(() => {
    const u = upper(identBtld.sgbm);
    if (u !== identBtld.sgbm) identBtld.sgbm = u;
    const v = upper(identBtld.version);
    if (v !== identBtld.version) identBtld.version = v;
  });
  $effect(() => {
    const u = upper(identSwflProgram.sgbm);
    if (u !== identSwflProgram.sgbm) identSwflProgram.sgbm = u;
    const v = upper(identSwflProgram.version);
    if (v !== identSwflProgram.version) identSwflProgram.version = v;
  });
  $effect(() => {
    const u = upper(identCalibration.sgbm);
    if (u !== identCalibration.sgbm) identCalibration.sgbm = u;
    const v = upper(identCalibration.version);
    if (v !== identCalibration.version) identCalibration.version = v;
  });
  $effect(() => {
    const u = upper(identCafd.sgbm);
    if (u !== identCafd.sgbm) identCafd.sgbm = u;
    const v = upper(identCafd.version);
    if (v !== identCafd.version) identCafd.version = v;
  });

  // ── Run state ────────────────────────────────────────────────────────
  let running: boolean = $state(false);
  let statusLine: string = $state('Idle');
  let errorMsg: string = $state('');

  // Live transcript — capped to keep the DOM bounded during a 4 MB flash.
  let transcript: SimulatorTranscriptEvent[] = $state([]);
  const TRANSCRIPT_LIMIT = 500;

  let segments: SimulatorSegmentEvent[] = $state([]);

  // ── Persistent flash session list ───────────────────────────────────
  // Survives the flasher disconnecting; loaded from disk on mount and
  // refreshed whenever the simulator finishes a session or finishes
  // writing a new segment so the user can come back and export later.
  let flashSessions: FlashSession[] = $state([]);
  let flashSessionsError: string = $state('');
  let exportingDir: string | null = $state(null);

  async function refreshFlashSessions() {
    try {
      flashSessions = await invoke<FlashSession[]>(
        'simulator_list_flash_sessions',
      );
      flashSessionsError = '';
    } catch (e) {
      flashSessionsError = String(e);
    }
  }

  async function exportFlashSession(session: FlashSession) {
    if (exportingDir) return;
    const suggested = `${session.vin ?? 'flash'}_${session.dir_name}.bin`;
    const dest = await saveDialog({
      title: 'Export captured flash as .bin',
      defaultPath: suggested,
      filters: [{ name: 'Binary', extensions: ['bin'] }],
    });
    if (!dest) return;
    exportingDir = session.dir_name;
    try {
      await invoke<number>('simulator_export_flash_bin', {
        dirName: session.dir_name,
        baseAddress: null,
      });
      const bytes = await pullLastBytes();
      await writeFile(dest, bytes);
      await writeSiblingLog(dest);
      showToast(
        'success',
        `Exported ${formatBytes(bytes.length)} → ${dest}`,
      );
    } catch (e) {
      showToast('error', `Export failed: ${e}`);
    } finally {
      exportingDir = null;
    }
  }
  let capturesDir: string = $state('');

  // ── Profile preview ──────────────────────────────────────────────────
  // Loaded once at mount and re-fetched whenever the user picks a
  // different profile so the panel can show the VIN that will be served.
  let activeProfile: SimulatorEcuProfile | null = $state(null);
  let profileError: string = $state('');
  let editVin: string = $state('');

  // ── Clone-from-car flow ──────────────────────────────────────────────
  let cloneOpen: boolean = $state(false);
  let cloneDiscovering: boolean = $state(false);
  let cloneDevices: DiscoveredDevice[] = $state([]);
  let cloneSelectedIp: string = $state('');
  let cloneNewName: string = $state('');
  let cloneRunning: boolean = $state(false);
  let cloneProgress: SimulatorCloneProgress | null = $state(null);
  let cloneError: string = $state('');

  let unlisten: UnlistenFn[] = [];
  let didInit = false;

  $effect(() => {
    if (didInit) return;
    didInit = true;

    (async () => {
      try {
        capturesDir = await invoke<string>('simulator_captures_dir');
        const status = await invoke<SimulatorStatus>('simulator_status');
        running = status.running;
        if (status.bind_addr) bindAddr = status.bind_addr;
      } catch (e) {
        errorMsg = String(e);
      }

      const u1 = await listen<SimulatorTranscriptEvent>(
        'simulator-transcript',
        (evt) => {
          transcript = [...transcript.slice(-(TRANSCRIPT_LIMIT - 1)), evt.payload];
        },
      );
      const u2 = await listen<SimulatorStatusEvent>('simulator-status', (evt) => {
        statusLine = `${evt.payload.state}: ${evt.payload.detail}`;
        if (evt.payload.state === 'connected') {
          // Clear the live transcript on a new tester connection,
          // but DO NOT clear `segments` — those represent the most
          // recent flash and should stay visible (alongside the
          // persistent FlashSession list) until new segments come in.
          transcript = [];
          segments = [];
        }
        if (evt.payload.state === 'disconnected') {
          // The captured segments are now committed to disk; refresh
          // the persistent list so they show up in "Captured Flashes"
          // immediately, even if the user closes the flasher app.
          refreshFlashSessions();
        }
        if (evt.payload.state === 'stopped') {
          running = false;
        }
      });
      const u3 = await listen<SimulatorSegmentEvent>('simulator-segment', (evt) => {
        segments = [...segments, evt.payload];
        // Also refresh persistent list so the session row's
        // segment count / total bytes update live mid-flash.
        refreshFlashSessions();
      });
      const u4 = await listen<SimulatorCloneProgress>(
        'simulator-clone-progress',
        (evt) => {
          cloneProgress = evt.payload;
        },
      );
      unlisten = [u1, u2, u3, u4];

      await refreshProfiles();
      await refreshFlashSessions();
    })();
  });

  async function saveTransferRate() {
    if (!activeProfile) {
      showToast('error', 'Pick a profile first');
      return;
    }
    savingThrottle = true;
    try {
      const next: SimulatorEcuProfile = {
        ...activeProfile,
        transfer_rate_kbps:
          transferRateKbps && transferRateKbps > 0 ? transferRateKbps : null,
      };
      await invoke<string>('simulator_save_profile', {
        name: profileName,
        profile: next,
      });
      activeProfile = next;
      showToast(
        'success',
        next.transfer_rate_kbps
          ? `Throttle set to ${next.transfer_rate_kbps} kB/s`
          : 'Throttle disabled',
      );
    } catch (e) {
      showToast('error', `Save failed: ${e}`);
    } finally {
      savingThrottle = false;
    }
  }

  async function loadActiveProfile() {
    profileError = '';
    if (!profileName) {
      activeProfile = null;
      editVin = '';
      resetIdentifierForm();
      return;
    }
    try {
      activeProfile = await invoke<SimulatorEcuProfile>('simulator_get_profile', {
        name: profileName,
      });
      editVin = activeProfile?.vin ?? '';
      transferRateKbps = activeProfile?.transfer_rate_kbps ?? null;
      await loadIdentifiers();
    } catch (e) {
      profileError = String(e);
      activeProfile = null;
    }
  }

  function resetIdentifierForm() {
    identBtld = emptyIdent();
    identSwflProgram = emptyIdent();
    identCalibration = emptyIdent();
    identCafd = emptyIdent();
    identHwel = emptyIdent();
    flashCounter = null;
    maxFlashCounter = null;
    identSerial = '';
    identDmeSupplier = '';
    identSystemSupplier = '';
    identHardwareNumber = '';
    identZbnr = '';
    identManufactureDate = '';
    identVoltageV = null;
    identDmeType = '';
    identEngineCode = '';
    identCalibrationId = '';
    identCvnHex = '';
    identLongDesignation = '';
    identProjectCode = '';
    editorError = '';
    editorSavedNote = '';
  }

  async function loadIdentifiers() {
    if (!profileName) return;
    try {
      const ids = await invoke<SimulatorDmeIdentifiers>('simulator_get_dme_identifiers', {
        name: profileName,
      });
      identHwel = ids.hwel ?? emptyIdent();
      identBtld = ids.btld ?? emptyIdent();
      identSwflProgram = ids.swfl_program ?? emptyIdent();
      identCalibration = ids.calibration ?? emptyIdent();
      identCafd = ids.cafd ?? emptyIdent();
      flashCounter = ids.flash_counter;
      maxFlashCounter = ids.max_flash_counter;
      identSerial = ids.serial_number ?? '';
      identDmeSupplier = ids.dme_supplier ?? '';
      identSystemSupplier = ids.system_supplier ?? '';
      identHardwareNumber = ids.hardware_number ?? '';
      identZbnr = ids.zbnr ?? '';
      identManufactureDate = ids.manufacture_date ?? '';
      identVoltageV = ids.voltage_v;
      identDmeType = ids.dme_type ?? '';
      identEngineCode = ids.engine_code ?? '';
      identCalibrationId = ids.calibration_id ?? '';
      identCvnHex =
        ids.cvn != null
          ? '0x' + ids.cvn.toString(16).toUpperCase().padStart(8, '0')
          : '';
      identLongDesignation = ids.long_designation ?? '';
      identProjectCode = ids.project_code ?? '';
      editorError = '';
    } catch (e) {
      editorError = String(e);
    }
  }

  function nullIfBlank(s: string): string | null {
    const t = s.trim();
    return t === '' ? null : t;
  }

  /// Accept "0x06F10407", "06F10407", "06f10407", "115017223" — anything
  /// that parses as a 32-bit unsigned. Returns `null` if blank or invalid.
  function parseCvn(s: string): number | null {
    const t = s.trim();
    if (t === '') return null;
    const hex = t.toLowerCase().startsWith('0x') ? t.slice(2) : t;
    // Hex first (typical for HSFZ tooling), fall back to decimal.
    const asHex = Number.parseInt(hex, 16);
    if (Number.isFinite(asHex) && asHex >= 0 && asHex <= 0xffffffff) return asHex;
    const asDec = Number.parseInt(t, 10);
    if (Number.isFinite(asDec) && asDec >= 0 && asDec <= 0xffffffff) return asDec;
    return null;
  }

  // ── NCD coding-backup import ─────────────────────────────────────────
  async function handleImportSampleNcd() {
    if (!profileName) {
      showToast('error', 'Pick a profile first');
      return;
    }
    if (running) {
      showToast('error', 'Stop the simulator before importing coding');
      return;
    }
    try {
      const json = await invoke<string>('simulator_sample_ncd_backup');
      const count = await invoke<number>('simulator_import_ncd_backup', {
        name: profileName,
        json,
      });
      await loadActiveProfile();
      showToast('success', `Imported ${count} coding DIDs from sample backup`);
    } catch (e) {
      showToast('error', `Import failed: ${e}`);
    }
  }

  async function handleImportNcdFile() {
    if (!profileName) {
      showToast('error', 'Pick a profile first');
      return;
    }
    if (running) {
      showToast('error', 'Stop the simulator before importing coding');
      return;
    }
    try {
      const path = await openDialog({
        multiple: false,
        directory: false,
        filters: [{ name: 'NCD Backup JSON', extensions: ['json'] }],
      });
      if (!path || typeof path !== 'string') return;
      // Read the file via Tauri's fs plugin so we don't need a backend
      // command per OS-specific path quoting.
      const json = await readTextFile(path);
      const count = await invoke<number>('simulator_import_ncd_backup', {
        name: profileName,
        json,
      });
      await loadActiveProfile();
      showToast('success', `Imported ${count} coding DIDs from ${path.split(/[\\/]/).pop()}`);
    } catch (e) {
      showToast('error', `Import failed: ${e}`);
    }
  }

  function nonEmpty(m: SimulatorModuleIdent): SimulatorModuleIdent | null {
    return m.sgbm.trim() || m.version.trim() ? m : null;
  }

  async function saveIdentifiers() {
    log('info', `saveIdentifiers clicked (profile=${profileName || '<none>'})`);
    editorError = '';
    editorSavedNote = '';

    // Every early-exit path produces a toast — previously some returns
    // were silent and looked indistinguishable from "the click never
    // happened" to a user staring at the panel.
    if (!profileName) {
      showToast('error', 'Pick a profile first');
      return;
    }
    if (running) {
      showToast('error', 'Stop the simulator before editing the profile');
      return;
    }

    const ids: SimulatorDmeIdentifiers = {
      hwel: nonEmpty(identHwel),
      btld: nonEmpty(identBtld),
      swfl_program: nonEmpty(identSwflProgram),
      calibration: nonEmpty(identCalibration),
      cafd: nonEmpty(identCafd),
      // bind:value on type="number" gives us number | null directly.
      flash_counter: flashCounter,
      max_flash_counter: maxFlashCounter,
      serial_number: nullIfBlank(identSerial),
      dme_supplier: nullIfBlank(identDmeSupplier),
      system_supplier: nullIfBlank(identSystemSupplier),
      hardware_number: nullIfBlank(identHardwareNumber),
      zbnr: nullIfBlank(identZbnr),
      manufacture_date: nullIfBlank(identManufactureDate),
      voltage_v: identVoltageV,
      dme_type: nullIfBlank(identDmeType),
      engine_code: nullIfBlank(identEngineCode),
      calibration_id: nullIfBlank(identCalibrationId),
      cvn: parseCvn(identCvnHex),
      long_designation: nullIfBlank(identLongDesignation),
      project_code: nullIfBlank(identProjectCode),
    };
    if (identCvnHex.trim() !== '' && ids.cvn === null) {
      editorError = 'CVN must be a hex number (e.g. 0x06F10407)';
      showToast('error', 'CVN must be a hex number (e.g. 0x06F10407)');
      return;
    }
    if (
      (ids.flash_counter != null && !Number.isInteger(ids.flash_counter)) ||
      (ids.max_flash_counter != null && !Number.isInteger(ids.max_flash_counter))
    ) {
      editorError = 'Flash counter values must be integers';
      showToast('error', 'Flash counter values must be integers');
      return;
    }

    log('info', `saving identifiers: ${JSON.stringify(ids)}`);
    try {
      await invoke('simulator_set_dme_identifiers', { name: profileName, ids });
      editorSavedNote = `✓ Identifiers saved to "${profileName}"`;
      // Always toast the success first — re-loading the profile is a
      // best-effort UI refresh; if it fails we still want the user to
      // know the save itself worked.
      showToast('success', `Identifiers saved to "${profileName}"`);
      log('info', `save succeeded`);
      try {
        await loadActiveProfile();
      } catch (reloadErr) {
        log('warn', `post-save reload failed: ${reloadErr}`);
      }
    } catch (e) {
      editorError = String(e);
      editorSavedNote = '';
      showToast('error', `Save failed: ${e}`);
      log('error', `save failed: ${e}`);
    }
  }

  function log(level: 'info' | 'warn' | 'error', message: string) {
    if (level === 'error') console.error('[SimulatorPanel]', message);
    else if (level === 'warn') console.warn('[SimulatorPanel]', message);
    else console.info('[SimulatorPanel]', message);
  }

  async function refreshProfiles() {
    try {
      profiles = await invoke<string[]>('simulator_list_profiles');
      // Auto-pick the first profile if nothing's selected and at least one exists.
      if (!profileName && profiles.length > 0) {
        profileName = profiles[0];
      }
      // If the previously-selected profile no longer exists, drop it.
      if (profileName && !profiles.includes(profileName)) {
        profileName = profiles[0] ?? '';
      }
      await loadActiveProfile();
    } catch (e) {
      profileError = String(e);
    }
  }

  function isValidVinClient(v: string): boolean {
    return /^[A-HJ-NPR-Z0-9]{17}$/.test(v.trim().toUpperCase());
  }

  function openCreateModal() {
    createOpen = true;
    createName = '';
    createVin = '';
    createError = '';
  }

  function closeCreateModal() {
    createOpen = false;
  }

  async function handleDeleteProfile() {
    if (!profileName) {
      showToast('error', 'Pick a profile to delete');
      return;
    }
    if (running) {
      showToast('error', 'Stop the simulator before deleting a profile');
      return;
    }
    // Hard confirm — the JSON file is unlinked from disk and there's
    // no undo.
    const ok = window.confirm(
      `Permanently delete profile "${profileName}"? This cannot be undone.`,
    );
    if (!ok) return;
    try {
      await invoke('simulator_delete_profile', { name: profileName });
      const deleted = profileName;
      profileName = '';
      activeProfile = null;
      resetIdentifierForm();
      await refreshProfiles();
      showToast('success', `Profile "${deleted}" deleted`);
    } catch (e) {
      showToast('error', `Delete failed: ${e}`);
    }
  }

  async function handleCreateProfile() {
    createError = '';
    const safeName = createName.trim().replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64);
    if (!safeName) {
      createError = 'Profile name required';
      return;
    }
    const trimmedVin = createVin.trim().toUpperCase();
    if (trimmedVin && !isValidVinClient(trimmedVin)) {
      createError = 'VIN must be 17 chars, alphanumeric, no I/O/Q';
      return;
    }
    try {
      const created = await invoke<string>('simulator_create_empty_profile', {
        name: safeName,
        ecuAddress: 0x12,
        vin: trimmedVin || null,
      });
      profileName = created;
      createOpen = false;
      await refreshProfiles();
      showToast('success', `Profile "${created}" created`);
    } catch (e) {
      createError = String(e);
      showToast('error', `Create failed: ${e}`);
    }
  }

  function isValidVin(v: string): boolean {
    // VINs (ISO 3779) are 17 ASCII chars, alphanumeric, no I/O/Q.
    return /^[A-HJ-NPR-Z0-9]{17}$/.test(v.trim().toUpperCase());
  }

  async function handleSaveEditedVin() {
    if (!activeProfile) return;
    const trimmed = editVin.trim().toUpperCase();
    if (!isValidVin(trimmed)) {
      profileError = 'VIN must be 17 chars (no I, O, Q)';
      return;
    }
    // Build a new profile with the patched VIN bytes in F190 too, so
    // every place the simulator looks the override is consistent.
    const f190Hex = Array.from(trimmed)
      .map((c) => c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase())
      .join('');
    const next: SimulatorEcuProfile = {
      ...activeProfile,
      vin: trimmed,
      dids: { ...activeProfile.dids, F190: f190Hex },
    };
    const safeName = trimmed.toLowerCase().replace(/[^a-z0-9_-]/g, '_').slice(0, 40);
    const finalName = `manual_${safeName}`;
    try {
      await invoke<string>('simulator_save_profile', {
        name: finalName,
        profile: next,
      });
      profileName = finalName;
      await refreshProfiles();
      profileError = '';
      showToast('success', `Profile "${finalName}" saved with VIN ${trimmed}`);
    } catch (e) {
      profileError = String(e);
      showToast('error', `Save failed: ${e}`);
    }
  }

  async function handleOpenClone() {
    cloneOpen = true;
    cloneDiscovering = true;
    cloneError = '';
    cloneDevices = [];
    cloneSelectedIp = '';
    cloneNewName = '';
    cloneProgress = null;
    await flushPaint();
    try {
      cloneDevices = await invoke<DiscoveredDevice[]>('discover_vehicles');
      if (cloneDevices.length === 1) {
        cloneSelectedIp = cloneDevices[0].ip;
        cloneNewName = `cloned_${cloneDevices[0].vin.toLowerCase().slice(0, 8)}`;
      }
    } catch (e) {
      cloneError = String(e);
    } finally {
      cloneDiscovering = false;
    }
  }

  function handleCancelClone() {
    cloneOpen = false;
    cloneRunning = false;
    cloneProgress = null;
  }

  function selectCloneDevice(d: DiscoveredDevice) {
    cloneSelectedIp = d.ip;
    if (!cloneNewName) {
      cloneNewName = `cloned_${d.vin.toLowerCase().slice(0, 8)}`;
    }
  }

  async function runClone() {
    if (!cloneSelectedIp) {
      cloneError = 'Pick a vehicle first';
      return;
    }
    const safeName = cloneNewName.trim().replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64);
    if (!safeName) {
      cloneError = 'Profile name required';
      return;
    }
    cloneRunning = true;
    cloneError = '';
    cloneProgress = null;
    await flushPaint();
    try {
      const cloned = await invoke<SimulatorEcuProfile>('simulator_clone_from_car', {
        ip: cloneSelectedIp,
        ecuAddress: 0x12,
        name: safeName,
      });
      await invoke<string>('simulator_save_profile', {
        name: safeName,
        profile: cloned,
      });
      profileName = safeName;
      await refreshProfiles();
      editVin = cloned.vin ?? '';
      cloneOpen = false;
      showToast(
        'success',
        `Cloned ${Object.keys(cloned.dids).length} DIDs into "${safeName}"`,
      );
    } catch (e) {
      cloneError = String(e);
      showToast('error', `Clone failed: ${e}`);
    } finally {
      cloneRunning = false;
    }
  }

  onDestroy(() => {
    unlisten.forEach((u) => u());
  });

  async function handleProfileChange(event: Event) {
    profileName = (event.target as HTMLSelectElement).value;
    await loadActiveProfile();
  }

  async function handleStart() {
    errorMsg = '';
    try {
      const status = await invoke<SimulatorStatus>('simulator_start', {
        bindAddr,
        profileName,
      });
      running = status.running;
      transcript = [];
      segments = [];
    } catch (e) {
      errorMsg = String(e);
    }
  }

  async function handleStop() {
    errorMsg = '';
    try {
      await invoke('simulator_stop');
      running = false;
      statusLine = 'Stopped';
    } catch (e) {
      errorMsg = String(e);
    }
  }

  function svcName(svc: number): string {
    const names: Record<number, string> = {
      0x10: 'DiagSession',
      0x11: 'ECUReset',
      0x14: 'ClearDTC',
      0x19: 'ReadDTC',
      0x22: 'RDBI',
      0x23: 'RMBA',
      0x27: 'SecAccess',
      0x28: 'CommCtrl',
      0x2e: 'WDBI',
      0x31: 'Routine',
      0x34: 'ReqDownload',
      0x36: 'TransferData',
      0x37: 'TransferExit',
      0x3d: 'WriteMem',
      0x3e: 'TesterPresent',
      0x50: '+DiagSession',
      0x51: '+ECUReset',
      0x54: '+ClearDTC',
      0x59: '+ReadDTC',
      0x62: '+RDBI',
      0x63: '+RMBA',
      0x67: '+SecAccess',
      0x68: '+CommCtrl',
      0x6e: '+WDBI',
      0x71: '+Routine',
      0x74: '+ReqDownload',
      0x76: '+TransferData',
      0x77: '+TransferExit',
      0x7d: '+WriteMem',
      0x7e: '+TesterPresent',
      0x7f: 'NRC',
      0x85: 'CtlDTC',
    };
    return names[svc] ?? `0x${svc.toString(16).toUpperCase().padStart(2, '0')}`;
  }

  function formatBytes(n: number): string {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(2)} MB`;
  }
</script>

<div class="space-y-6">
  <!--
    Inline toast strip at the top of the panel. Normal-flow element,
    no position: fixed, works on every platform. Auto-dismisses after
    5 seconds via the ToastStrip component's internal timer.
  -->
  <ToastStrip
    kind={toastKind}
    message={toastMessage}
    onDismiss={() => (toastMessage = '')}
  />

  <!--
    Clone/create "view takeover" — when either flow is active, we
    render only that flow's inline card and hide the main profile
    editor behind it. The rendered sections live at the end of the
    template (see "Clone-from-car inline card" / "Create empty
    profile inline card"). Mobile-native pattern: one thing at a
    time, no modal overlay trickery.
  -->
  {#if !cloneOpen && !createOpen}
  <div class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)]">
    <h2 class="text-lg font-semibold text-[var(--text-primary)] mb-1">DME Simulator</h2>
    <p class="text-sm text-[var(--text-secondary)] mb-2">
      Pretend to be a real MEVD17 DME so a tuning tool flashes <em>us</em> instead
      of a car. Captures the flash payload as one .bin per segment.
    </p>
    <p class="text-xs text-[var(--accent)] mb-6">
      ⚠ MEVD17 only. Pick the built-in profile, clone a live vehicle off the
      network via the Clone button, or override the VIN below to spoof a
      specific vehicle against VIN-licensed HSFZ tuning flashers.
    </p>

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
      <label class="block">
        <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
          Bind Address
        </span>
        <input
          type="text"
          bind:value={bindAddr}
          disabled={running}
          placeholder="0.0.0.0:6801"
          class="mt-1 w-full px-3 py-2 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-sm focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
        />
      </label>
      <label class="block">
        <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
          Flash Throttle (kB/s)
        </span>
        <div class="mt-1 flex gap-2">
          <input
            type="number"
            min="0"
            step="1"
            placeholder="0 = unthrottled"
            bind:value={transferRateKbps}
            disabled={!activeProfile}
            class="flex-1 px-3 py-2 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-sm focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
          />
          <button
            type="button"
            onclick={saveTransferRate}
            disabled={!activeProfile || savingThrottle}
            class="px-3 py-2 rounded border border-[var(--accent)] text-[var(--accent)] text-xs font-semibold hover:bg-[var(--accent)] hover:text-black disabled:opacity-50"
          >
            {savingThrottle ? '…' : 'Save'}
          </button>
        </div>
        <p class="mt-1 text-[10px] text-[var(--text-secondary)] leading-tight">
          Real K-line/HSFZ flashes run ~20–60 kB/s. A 4 MiB write that
          finishes in &lt;10s will look fake to a flasher's telemetry.
        </p>
      </label>
      <label class="block">
        <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
          Profile
        </span>
        <select
          value={profileName}
          onchange={handleProfileChange}
          disabled={running || profiles.length === 0}
          class="mt-1 w-full px-3 py-2 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-sm focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
        >
          {#if profiles.length === 0}
            <option value="">— no profiles —</option>
          {:else}
            {#each profiles as p}
              <option value={p}>{p}</option>
            {/each}
          {/if}
        </select>
      </label>
    </div>

    {#if profiles.length === 0}
      <div class="mt-4 p-4 rounded bg-[var(--bg-tertiary)] border border-dashed border-[var(--border)]">
        <p class="text-sm text-[var(--text-primary)] font-medium mb-2">No profiles yet</p>
        <p class="text-xs text-[var(--text-secondary)] mb-4">
          Create one to start. Either clone a real DME off the network (most accurate
          — captures all SVK/coding info) or create an empty profile and edit it by
          hand.
        </p>
        <div class="flex gap-2">
          <button
            type="button"
            onclick={handleOpenClone}
            class="flex-1 py-2 text-sm rounded bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] transition-colors"
          >
            Clone From Live Car
          </button>
          <button
            type="button"
            onclick={openCreateModal}
            class="flex-1 py-2 text-sm rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] hover:border-[var(--accent)] transition-colors"
          >
            Create Empty Profile
          </button>
        </div>
      </div>
    {/if}

    <!-- ── Active profile preview / VIN editor ─────────────────────── -->
    <div class="mt-4 p-4 rounded bg-[var(--bg-tertiary)] border border-[var(--border)]">
      <div class="flex items-center justify-between mb-3">
        <div>
          <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
            Active Profile
          </span>
          {#if activeProfile}
            <div class="font-mono text-sm text-[var(--text-primary)] mt-1">
              {activeProfile.name}
              <span class="ml-2 text-xs text-[var(--text-secondary)]">
                · ECU 0x{activeProfile.ecu_address.toString(16).toUpperCase().padStart(2, '0')}
                · {Object.keys(activeProfile.dids).length} DIDs
              </span>
            </div>
          {/if}
        </div>
        <!-- Action buttons. Wraps to multiple rows on narrow screens
             so the button row doesn't overflow horizontally on phones. -->
        <div class="flex flex-wrap gap-2">
          <button
            type="button"
            onclick={openCreateModal}
            disabled={running}
            class="px-3 py-1.5 text-xs rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] hover:border-[var(--accent)] transition-colors disabled:opacity-50"
          >
            New
          </button>
          <button
            type="button"
            onclick={handleOpenClone}
            disabled={running}
            class="px-3 py-1.5 text-xs rounded bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] transition-colors disabled:opacity-50"
          >
            Clone From Live Car
          </button>
          <button
            type="button"
            onclick={handleDeleteProfile}
            disabled={running || !profileName}
            class="px-3 py-1.5 text-xs rounded bg-[var(--bg-secondary)] border border-[var(--error)] text-[var(--error)] hover:bg-[var(--error)] hover:text-white transition-colors disabled:opacity-50"
            title="Permanently delete the active profile"
          >
            Delete
          </button>
        </div>
      </div>

      <label class="block">
        <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
          VIN (override)
        </span>
        <!--
          On phones the input + Save button stack vertically (flex-col).
          On sm+ they sit side-by-side (sm:flex-row). The Save button
          gets `w-full sm:w-auto` so it spans the panel width on
          mobile, which is the standard Android touch-target pattern.
        -->
        <div class="mt-1 flex flex-col sm:flex-row gap-2">
          <input
            type="text"
            bind:value={editVin}
            disabled={running || !activeProfile}
            placeholder="WBAXXXXXXXXXXXXXX"
            maxlength="17"
            class="flex-1 min-w-0 px-3 py-2 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-sm uppercase focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
          />
          <button
            type="button"
            onclick={handleSaveEditedVin}
            disabled={running || !activeProfile || editVin.trim().length !== 17}
            class="w-full sm:w-auto px-4 py-2 text-sm rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] hover:border-[var(--accent)] transition-colors disabled:opacity-50"
          >
            Save as Manual Profile
          </button>
        </div>
      </label>

      {#if profileError}
        <p class="mt-2 text-xs text-[var(--error)] break-all">{profileError}</p>
      {/if}
    </div>

    <!-- ── DME Identifiers editor (F101 SVK + flash counters) ───────── -->
    {#if activeProfile}
      <div class="mt-4 p-4 rounded bg-[var(--bg-tertiary)] border border-[var(--border)]">
        <button
          type="button"
          onclick={() => (editorOpen = !editorOpen)}
          class="w-full flex items-center justify-between text-left"
        >
          <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
            DME Identifiers (BTLD / SWFL / CAFD / Flash counter)
          </span>
          <span class="text-xs text-[var(--text-secondary)]">
            {editorOpen ? '▾' : '▸'}
          </span>
        </button>

        {#if editorOpen}
          <p class="text-xs text-[var(--text-secondary)] mt-2 mb-3">
            These values are encoded into the F101 SVK response and the
            flash-counter DIDs (0x2502 / 0x2503) so VIN-licensed flashers
            see byte-perfect ECU info.
          </p>

          <div class="space-y-3">
            <!-- One row per identifier. Direct two-way `bind:value` to
                 each $state field — earlier version used an inline-array
                 each block with closure setters and was silently dropping
                 writes for some rows under Svelte 5 reactivity rules. -->

            <div class="grid grid-cols-12 gap-2 items-center">
              <span class="col-span-3 text-xs text-[var(--text-secondary)]">HWEL</span>
              <input
                type="text"
                bind:value={identHwel.sgbm}
                disabled={running}
                placeholder="000019A6"
                maxlength="8"
                class="col-span-5 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs uppercase focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
              />
              <input
                type="text"
                bind:value={identHwel.version}
                disabled={running}
                placeholder="001.019.003"
                maxlength="11"
                class="col-span-4 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs uppercase focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
              />
            </div>

            <div class="grid grid-cols-12 gap-2 items-center">
              <span class="col-span-3 text-xs text-[var(--text-secondary)]">BTLD (Bootloader)</span>
              <input
                type="text"
                bind:value={identBtld.sgbm}
                disabled={running}
                placeholder="00001901"
                maxlength="8"
                class="col-span-5 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs uppercase focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
              />
              <input
                type="text"
                bind:value={identBtld.version}
                disabled={running}
                placeholder="001.049.002"
                maxlength="11"
                class="col-span-4 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs uppercase focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
              />
            </div>

            <div class="grid grid-cols-12 gap-2 items-center">
              <span class="col-span-3 text-xs text-[var(--text-secondary)]">SWFL — Program</span>
              <input
                type="text"
                bind:value={identSwflProgram.sgbm}
                disabled={running}
                placeholder="00001572"
                maxlength="8"
                class="col-span-5 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs uppercase focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
              />
              <input
                type="text"
                bind:value={identSwflProgram.version}
                disabled={running}
                placeholder="001.005.007"
                maxlength="11"
                class="col-span-4 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs uppercase focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
              />
            </div>

            <!-- Calibration: one slot. Backend auto-picks SWFL (legacy
                 MEVD17) or SWFK (newer DMEs) from the existing F101. -->
            <div class="grid grid-cols-12 gap-2 items-center">
              <span class="col-span-3 text-xs text-[var(--text-secondary)]">
                SWFL / SWFK (Calibration)
              </span>
              <input
                type="text"
                bind:value={identCalibration.sgbm}
                disabled={running}
                placeholder="00001572"
                maxlength="8"
                class="col-span-5 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs uppercase focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
              />
              <input
                type="text"
                bind:value={identCalibration.version}
                disabled={running}
                placeholder="001.005.007"
                maxlength="11"
                class="col-span-4 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs uppercase focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
              />
            </div>

            <div class="grid grid-cols-12 gap-2 items-center">
              <span class="col-span-3 text-xs text-[var(--text-secondary)]">CAFD</span>
              <input
                type="text"
                bind:value={identCafd.sgbm}
                disabled={running}
                placeholder="000037FC"
                maxlength="8"
                class="col-span-5 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs uppercase focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
              />
              <input
                type="text"
                bind:value={identCafd.version}
                disabled={running}
                placeholder="000.001.000"
                maxlength="11"
                class="col-span-4 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs uppercase focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
              />
            </div>

            <div class="grid grid-cols-12 gap-2 items-center pt-2 border-t border-[var(--border)]">
              <span class="col-span-3 text-xs text-[var(--text-secondary)]">Flash counter</span>
              <input
                type="number"
                bind:value={flashCounter}
                disabled={running}
                placeholder="3"
                min="0"
                class="col-span-3 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs uppercase focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
              />
              <span class="col-span-3 text-xs text-[var(--text-secondary)]">Max counter</span>
              <input
                type="number"
                bind:value={maxFlashCounter}
                disabled={running}
                placeholder="255"
                min="0"
                class="col-span-3 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs uppercase focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
              />
            </div>

            <!-- ── Vehicle metadata DIDs ─────────────────────────────
                 The fields HSFZ tuning tools query on connect — leaving
                 any of them blank means the simulator returns 0xFF and
                 the flasher displays N/A / Unknown for that field. -->
            <div class="pt-3 border-t border-[var(--border)]">
              <p class="text-xs text-[var(--text-secondary)] mb-2 uppercase tracking-wide">
                Vehicle Metadata
              </p>

              <div class="grid grid-cols-12 gap-2 items-center mb-2">
                <span class="col-span-3 text-xs text-[var(--text-secondary)]">Serial number</span>
                <input
                  type="text"
                  bind:value={identSerial}
                  disabled={running}
                  placeholder="12345678"
                  maxlength="32"
                  class="col-span-9 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
                />
              </div>

              <div class="grid grid-cols-12 gap-2 items-center mb-2">
                <span class="col-span-3 text-xs text-[var(--text-secondary)]">Hardware #</span>
                <input
                  type="text"
                  bind:value={identHardwareNumber}
                  disabled={running}
                  placeholder="8612345"
                  maxlength="32"
                  class="col-span-9 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
                />
              </div>

              <div class="grid grid-cols-12 gap-2 items-center mb-2">
                <span class="col-span-3 text-xs text-[var(--text-secondary)]">DME supplier</span>
                <input
                  type="text"
                  bind:value={identDmeSupplier}
                  disabled={running}
                  placeholder="0261S08123"
                  maxlength="32"
                  class="col-span-9 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
                />
              </div>

              <div class="grid grid-cols-12 gap-2 items-center mb-2">
                <span class="col-span-3 text-xs text-[var(--text-secondary)]">System supplier</span>
                <input
                  type="text"
                  bind:value={identSystemSupplier}
                  disabled={running}
                  placeholder="Bosch"
                  maxlength="32"
                  class="col-span-9 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
                />
              </div>

              <div class="grid grid-cols-12 gap-2 items-center mb-2">
                <span class="col-span-3 text-xs text-[var(--text-secondary)]">ZBNR</span>
                <input
                  type="text"
                  bind:value={identZbnr}
                  disabled={running}
                  placeholder="8612345"
                  maxlength="32"
                  class="col-span-9 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
                />
              </div>

              <div class="grid grid-cols-12 gap-2 items-center mb-2">
                <span class="col-span-3 text-xs text-[var(--text-secondary)]">Mfg date (YYMMDD)</span>
                <input
                  type="text"
                  bind:value={identManufactureDate}
                  disabled={running}
                  placeholder="240115"
                  maxlength="6"
                  pattern="[0-9]{6}"
                  class="col-span-3 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
                />
                <span class="col-span-3 text-xs text-[var(--text-secondary)]">Voltage (V)</span>
                <input
                  type="number"
                  step="0.1"
                  min="0"
                  max="24"
                  bind:value={identVoltageV}
                  disabled={running}
                  placeholder="14.4"
                  class="col-span-3 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
                />
              </div>

              <div class="grid grid-cols-12 gap-2 items-center mb-2">
                <span class="col-span-3 text-xs text-[var(--text-secondary)]">DME Type</span>
                <input
                  type="text"
                  bind:value={identDmeType}
                  disabled={running}
                  placeholder="MEVD17.2.P"
                  maxlength="20"
                  class="col-span-4 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
                />
                <span class="col-span-2 text-xs text-[var(--text-secondary)]">Engine</span>
                <input
                  type="text"
                  bind:value={identEngineCode}
                  disabled={running}
                  placeholder="N20"
                  maxlength="8"
                  class="col-span-3 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
                />
              </div>

              <div class="grid grid-cols-12 gap-2 items-center mb-2">
                <span class="col-span-3 text-xs text-[var(--text-secondary)]">Calibration ID</span>
                <input
                  type="text"
                  bind:value={identCalibrationId}
                  disabled={running}
                  placeholder="9VT9G40B"
                  maxlength="8"
                  class="col-span-3 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
                />
                <span class="col-span-3 text-xs text-[var(--text-secondary)]">CVN (hex)</span>
                <input
                  type="text"
                  bind:value={identCvnHex}
                  disabled={running}
                  placeholder="0x06F10407"
                  maxlength="12"
                  class="col-span-3 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
                />
              </div>

              <!-- Long designation: full long DME identifier as it
                   appears in the routine 0x0205 response. Spans the
                   full row width because real values are ~50 chars. -->
              <div class="grid grid-cols-12 gap-2 items-center mb-2">
                <span class="col-span-3 text-xs text-[var(--text-secondary)]">Long designation</span>
                <input
                  type="text"
                  bind:value={identLongDesignation}
                  disabled={running}
                  placeholder="MEVD17.2.P-N20-Mo-B20-U0-F030-EU6-HGAG_-LL-RL"
                  maxlength="80"
                  class="col-span-9 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
                />
              </div>

              <div class="grid grid-cols-12 gap-2 items-center mb-2">
                <span class="col-span-3 text-xs text-[var(--text-secondary)]">Project code</span>
                <input
                  type="text"
                  bind:value={identProjectCode}
                  disabled={running}
                  placeholder="9G4LBIX6"
                  maxlength="16"
                  class="col-span-9 px-2 py-1.5 rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-xs focus:outline-none focus:border-[var(--accent)] disabled:opacity-50"
                />
              </div>
            </div>

            <!-- ── Coding DIDs (NCD backup import) ───────────────────
                 HSFZ tuning tools read DIDs 0x3300/0x3320/0x3350/0x3351/
                 0x37FE on connect to grab the ECU's coding state. The
                 simulator returns 0xFF for these by default — import an
                 NCD coding backup JSON to populate them with real
                 bytes a flasher will accept. -->
            <div class="pt-3 mt-3 border-t border-[var(--border)]">
              <p class="text-xs text-[var(--text-secondary)] mb-2 uppercase tracking-wide">
                Coding DIDs (NCD Backup)
              </p>
              <p class="text-xs text-[var(--text-secondary)] mb-3">
                Import an NCD coding backup JSON to populate the
                coding DIDs (3300, 3320, 3350, 3351, 37FE).
              </p>
              <div class="flex gap-2">
                <button
                  type="button"
                  onclick={handleImportNcdFile}
                  class="flex-1 py-2 text-xs rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] hover:border-[var(--accent)] transition-colors"
                >
                  Import NCD JSON…
                </button>
                <button
                  type="button"
                  onclick={handleImportSampleNcd}
                  class="flex-1 py-2 text-xs rounded bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-primary)] hover:border-[var(--accent)] transition-colors"
                >
                  Load Sample Coding
                </button>
              </div>
            </div>
          </div>

          {#if running}
            <p class="mt-3 text-xs text-[var(--error)]">
              Simulator is running — stop it before saving profile changes.
            </p>
          {/if}

          <button
            type="button"
            onclick={saveIdentifiers}
            class="mt-4 w-full py-2 bg-[var(--accent)] text-white rounded text-sm font-medium hover:bg-[var(--accent-hover)] transition-colors"
          >
            Save Identifiers to Profile
          </button>

          {#if editorError}
            <div class="mt-3 px-3 py-2 rounded border border-[var(--error)] bg-[var(--bg-secondary)] text-sm text-[var(--error)] break-all">
              {editorError}
            </div>
          {/if}
          {#if editorSavedNote}
            <div class="mt-3 px-3 py-2 rounded border border-[var(--accent)] bg-[var(--bg-secondary)] text-sm text-[var(--accent)] font-medium">
              {editorSavedNote}
            </div>
          {/if}
        {/if}
      </div>
    {/if}

    <div class="flex gap-3 mt-6">
      <button
        type="button"
        onclick={handleStart}
        disabled={running}
        class="flex-1 py-2.5 bg-[var(--accent)] text-white rounded font-medium hover:bg-[var(--accent-hover)] transition-colors disabled:opacity-50"
      >
        Start Simulator
      </button>
      <button
        type="button"
        onclick={handleStop}
        disabled={!running}
        class="flex-1 py-2.5 bg-[var(--bg-tertiary)] text-[var(--text-primary)] rounded font-medium hover:bg-[var(--border)] transition-colors disabled:opacity-50"
      >
        Stop
      </button>
    </div>

    <div class="mt-4 text-sm">
      <span class="text-[var(--text-secondary)]">Status:</span>
      <span class="ml-2 font-mono">{statusLine}</span>
    </div>
    {#if errorMsg}
      <div class="mt-2 text-xs text-[var(--error)] break-all">{errorMsg}</div>
    {/if}
    {#if capturesDir}
      <div class="mt-2 text-xs text-[var(--text-secondary)] break-all">
        Captures: <span class="font-mono">{capturesDir}</span>
      </div>
    {/if}
  </div>

  <!-- ── Persistent captured-flashes list ─────────────────────────── -->
  <div class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)]">
    <div class="flex items-center justify-between mb-3">
      <h3 class="text-sm font-semibold text-[var(--text-primary)]">
        Captured Flashes ({flashSessions.length})
      </h3>
      <button
        type="button"
        class="text-xs px-2 py-1 rounded border border-[var(--border)] hover:bg-[var(--bg-tertiary)]"
        onclick={refreshFlashSessions}
      >
        Refresh
      </button>
    </div>
    {#if flashSessionsError}
      <div class="text-xs text-[var(--error)] mb-2">{flashSessionsError}</div>
    {/if}
    {#if flashSessions.length === 0}
      <div class="text-xs text-[var(--text-secondary)]">
        No captured flashes yet. Start the simulator and let a tuning tool
        flash the simulated DME — the captured segments will appear here
        and persist across sessions.
      </div>
    {:else}
      <div class="space-y-2">
        {#each flashSessions as fs}
          <div
            class="p-3 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] font-mono text-xs"
          >
            <div class="flex items-center justify-between gap-2">
              <div class="min-w-0">
                <div class="text-[var(--text-primary)]">
                  <span class="text-[var(--accent)]">{fs.vin ?? '(no VIN)'}</span>
                  <span class="ml-2 text-[var(--text-secondary)]">{fs.started_at}</span>
                </div>
                <div class="mt-1 text-[var(--text-secondary)]">
                  {fs.segment_count} segments · {formatBytes(fs.total_bytes)} ·
                  0x{fs.min_address.toString(16).toUpperCase().padStart(8, '0')}
                  → 0x{fs.max_address.toString(16).toUpperCase().padStart(8, '0')}
                </div>
                <div class="mt-1 text-[var(--text-secondary)] break-all">
                  {fs.dir_path}
                </div>
              </div>
              <button
                type="button"
                class="shrink-0 text-xs px-3 py-1.5 rounded border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)] hover:text-black disabled:opacity-50"
                disabled={exportingDir !== null}
                onclick={() => exportFlashSession(fs)}
              >
                {exportingDir === fs.dir_name ? 'Exporting…' : 'Export .bin'}
              </button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  {#if segments.length > 0}
    <div class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)]">
      <h3 class="text-sm font-semibold text-[var(--text-primary)] mb-3">
        Live Segments ({segments.length})
      </h3>
      <div class="space-y-2">
        {#each segments as s}
          <div class="p-2 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] font-mono text-xs">
            <div>
              <span class="text-[var(--accent)]">0x{s.address.toString(16).toUpperCase().padStart(8, '0')}</span>
              <span class="ml-2 text-[var(--text-secondary)]">{formatBytes(s.size)}</span>
            </div>
            <div class="text-[var(--text-secondary)] break-all mt-1">{s.file_path}</div>
          </div>
        {/each}
      </div>
    </div>
  {/if}

  {#if transcript.length > 0}
    <div class="p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)]">
      <h3 class="text-sm font-semibold text-[var(--text-primary)] mb-3">
        Live Transcript (last {transcript.length})
      </h3>
      <div class="space-y-1 max-h-96 overflow-y-auto font-mono text-xs">
        {#each transcript as e}
          <div class:text-[var(--accent)]={e.direction === 'REQ'} class="leading-tight">
            <span class="text-[var(--text-secondary)]">{e.direction}</span>
            <span class="ml-2">{svcName(e.service)}</span>
            <span class="ml-2 text-[var(--text-secondary)]">
              {e.body_hex.length > 48 ? e.body_hex.slice(0, 48) + '…' : e.body_hex}
            </span>
            {#if e.note}<span class="ml-2 text-[var(--error)]">[{e.note}]</span>{/if}
          </div>
        {/each}
      </div>
    </div>
  {/if}
  {/if}

<!-- ── Clone-from-car inline card ─────────────────────────────────
     Rendered inline inside the panel content (NOT as a modal overlay).
     Mobile-native pattern: the panel content morphs into the clone
     workflow while cloneOpen is true. Works on every platform because
     it's just normal-flow content, no position: fixed, no stacking
     context trickery. -->
{#if cloneOpen}
  <div
    class="p-5 sm:p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--accent)]"
    style="box-shadow: 0 0 24px var(--accent-glow);"
    role="region"
    aria-labelledby="clone-section-title"
  >
    <div class="flex items-center justify-between mb-4">
      <h3 id="clone-section-title" class="text-base sm:text-lg font-semibold text-[var(--text-primary)]">
        Clone DME From Live Car
      </h3>
      {#if !cloneRunning}
        <button
          type="button"
          onclick={handleCancelClone}
          aria-label="Close"
          class="text-[var(--text-secondary)] hover:text-[var(--text-primary)] text-xl leading-none px-2 min-h-[40px]"
        >
          ×
        </button>
      {/if}
    </div>
    <div class="contents">

      {#if cloneRunning}
        <!-- Active clone — show progress if backend reports DIDs, or
             a generic spinner-only state if no progress events yet
             (the clone command runs ~10s through 19+ DIDs and blocks
             on each, so a visible loading indicator is essential). -->
        <div
          class="mb-4 p-4 rounded bg-[var(--bg-tertiary)] border border-[var(--accent)]/40"
          style="box-shadow: 0 0 16px var(--accent-glow);"
        >
          <div class="flex items-center gap-3 mb-3">
            <Spinner size={20} />
            <div class="flex-1 min-w-0">
              <div class="text-sm font-medium text-[var(--text-primary)]">
                Cloning DME profile
              </div>
              <div class="text-[11px] text-[var(--text-secondary)]">
                {cloneProgress
                  ? `Reading DID 0x${cloneProgress.did.toString(16).toUpperCase().padStart(4, '0')} (${cloneProgress.current}/${cloneProgress.total})`
                  : 'Connecting to gateway and reading discovery DIDs…'}
              </div>
            </div>
          </div>
          {#if cloneProgress}
            <div class="w-full h-2 bg-[var(--bg-secondary)] rounded overflow-hidden">
              <div
                class="h-full bg-[var(--accent)] transition-[width] duration-150"
                style="width: {(cloneProgress.current / cloneProgress.total) * 100}%"
              ></div>
            </div>
          {:else}
            <!-- Indeterminate progress bar pre-progress-events -->
            <div class="w-full h-2 bg-[var(--bg-secondary)] rounded overflow-hidden relative">
              <div
                class="absolute inset-y-0 w-1/3 bg-[var(--accent)] rounded"
                style="animation: indeterminate-slide 1.4s ease-in-out infinite;"
              ></div>
            </div>
          {/if}
        </div>
      {:else if cloneDiscovering}
        <div
          class="mb-4 p-4 rounded bg-[var(--bg-tertiary)] border border-[var(--accent)]/40 flex items-center gap-3"
          style="box-shadow: 0 0 12px var(--accent-glow);"
        >
          <Spinner size={18} />
          <div class="flex flex-col gap-0.5 min-w-0">
            <span class="text-sm font-medium text-[var(--text-primary)]">
              Searching for vehicles
            </span>
            <span class="text-[11px] text-[var(--text-secondary)]">
              Broadcasting HSFZ vehicle-identification probe on UDP 6811…
            </span>
          </div>
        </div>
      {:else if cloneDevices.length > 0}
        <div class="space-y-2 mb-4 max-h-48 overflow-y-auto">
          {#each cloneDevices as d}
            <button
              type="button"
              onclick={() => selectCloneDevice(d)}
              class="w-full text-left p-3 rounded border transition-colors font-mono text-sm
                {cloneSelectedIp === d.ip
                  ? 'bg-[var(--bg-tertiary)] border-[var(--accent)]'
                  : 'bg-[var(--bg-tertiary)] border-[var(--border)] hover:border-[var(--accent)]'}"
            >
              <div class="text-[var(--text-primary)] font-bold">{d.ip}</div>
              <div class="text-xs text-[var(--text-secondary)]">VIN: {d.vin}</div>
              <div class="text-xs text-[var(--text-secondary)]">
                MAC: {d.mac_address} · diag: 0x{d.diag_address.toString(16).toUpperCase().padStart(2, '0')}
              </div>
            </button>
          {/each}
        </div>

        <label class="block mb-4">
          <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
            Save profile as
          </span>
          <input
            type="text"
            bind:value={cloneNewName}
            placeholder="cloned_wba3b160"
            class="mt-1 w-full px-3 py-2 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-sm focus:outline-none focus:border-[var(--accent)]"
          />
          <span class="text-xs text-[var(--text-secondary)]">
            Letters, numbers, _ and - only.
          </span>
        </label>
      {:else}
        <div class="p-4 rounded bg-[var(--bg-tertiary)] border border-[var(--border)] text-sm text-[var(--text-secondary)] mb-4">
          No vehicles found on the network. Make sure the ENET cable is plugged
          in and the ignition is on.
        </div>
      {/if}

      {#if cloneError}
        <p class="mb-4 text-xs text-[var(--error)] break-all">{cloneError}</p>
      {/if}

      <div class="flex flex-col sm:flex-row gap-3">
        <button
          type="button"
          onclick={runClone}
          disabled={cloneRunning || cloneDiscovering || !cloneSelectedIp}
          class="flex-1 inline-flex items-center justify-center gap-2 min-h-[48px] py-3 bg-[var(--accent)] text-white rounded-lg font-semibold text-base hover:bg-[var(--accent-hover)] transition-colors disabled:opacity-50"
        >
          {#if cloneRunning}
            <Spinner size={16} thickness={2} />
            <span>Cloning…</span>
          {:else}
            <span>Clone &amp; Save</span>
          {/if}
        </button>
        <button
          type="button"
          onclick={handleCancelClone}
          disabled={cloneRunning}
          class="flex-1 min-h-[48px] py-3 bg-[var(--bg-tertiary)] text-[var(--text-primary)] rounded-lg font-semibold text-base hover:bg-[var(--border)] transition-colors disabled:opacity-50"
        >
          Cancel
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- ── Create empty profile inline card ───────────────────────────
     Rendered inline inside the panel. Mobile-native pattern: the
     profile list morphs into a "new profile" form when createOpen
     is true. No modal, no overlay, no fixed positioning. -->
{#if createOpen}
  <div
    class="p-5 sm:p-6 rounded-lg bg-[var(--bg-secondary)] border border-[var(--accent)]"
    style="box-shadow: 0 0 24px var(--accent-glow);"
    role="region"
    aria-labelledby="create-section-title"
  >
    <div class="flex items-center justify-between mb-1">
      <h3 id="create-section-title" class="text-base sm:text-lg font-semibold text-[var(--text-primary)]">
        Create Empty Profile
      </h3>
      <button
        type="button"
        onclick={closeCreateModal}
        aria-label="Close"
        class="text-[var(--text-secondary)] hover:text-[var(--text-primary)] text-xl leading-none px-2 min-h-[40px]"
      >
        ×
      </button>
    </div>
    <p class="text-xs text-[var(--text-secondary)] mb-4">
      Creates a blank profile with just metadata. You can paste real DID
      values into the JSON file afterwards, or use the Clone From Live
      Car option for an automatic capture.
    </p>

    <label class="block mb-3">
      <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
        Profile name
      </span>
      <input
        type="text"
        bind:value={createName}
        placeholder="my_test_dme"
        maxlength="64"
        class="mt-1 w-full px-3 py-3 rounded-lg bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-base focus:outline-none focus:border-[var(--accent)]"
      />
      <span class="text-xs text-[var(--text-secondary)]">
        Letters, numbers, _ and - only.
      </span>
    </label>

    <label class="block mb-4">
      <span class="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
        VIN (optional)
      </span>
      <input
        type="text"
        bind:value={createVin}
        placeholder="WBA…"
        maxlength="17"
        class="mt-1 w-full px-3 py-3 rounded-lg bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] font-mono text-base uppercase focus:outline-none focus:border-[var(--accent)]"
      />
      <span class="text-xs text-[var(--text-secondary)]">
        17 chars, no I/O/Q. Leave blank to fill in later.
      </span>
    </label>

    {#if createError}
      <p class="mb-4 text-xs text-[var(--error)] break-all">{createError}</p>
    {/if}

    <div class="flex flex-col sm:flex-row gap-3">
      <button
        type="button"
        onclick={handleCreateProfile}
        class="flex-1 min-h-[48px] py-3 bg-[var(--accent)] text-white rounded-lg font-semibold text-base hover:bg-[var(--accent-hover)] transition-colors"
      >
        Create
      </button>
      <button
        type="button"
        onclick={closeCreateModal}
        class="flex-1 min-h-[48px] py-3 bg-[var(--bg-tertiary)] text-[var(--text-primary)] rounded-lg font-semibold text-base hover:bg-[var(--border)] transition-colors"
      >
        Cancel
      </button>
    </div>
  </div>
{/if}
</div>

<!-- Toast is rendered inline at the top of the panel's space-y-6
     wrapper via <ToastStrip> — see the top of this file's template. -->
