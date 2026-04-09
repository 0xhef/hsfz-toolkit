export interface FlashSegment {
  address: number;
  expected_size: number;
  actual_size: number;
  block_count: number;
  size_match: boolean;
}

export interface UdsEvent {
  event_type: string;
  detail: string;
}

export interface ExtractionResult {
  vin: string | null;
  ecu_address: number;
  segments: FlashSegment[];
  events: UdsEvent[];
  binary_size: number;
  binary_path: string | null;
  base_address: number;
  non_ff_bytes: number;
  non_ff_percent: number;
  first_16_hex: string;
  last_16_hex: string;
}

export type AppStatus = 'idle' | 'loading' | 'done' | 'error';

export type ActiveTab =
  | 'load'
  | 'capture'
  | 'calibration_read'
  | 'simulator'
  | 'proxy';

export interface ProxyConfig {
  listen_addr: string;
  upstream_addr: string;
  /// Real DME values discovered from the upstream broadcast probe.
  /// Read-only display, used as a passthrough source when spoofing is off.
  real_vin: string | null;
  real_mac: string | null;
  diag_addr: number;
  /// Master spoof toggle. When false, the proxy is transparent.
  spoof_enabled: boolean;
  spoof_vin: string | null;
  spoof_mac: string | null;
  enable_discovery: boolean;
}

export interface ProxyStatus {
  running: boolean;
  config: ProxyConfig | null;
  bytes_c2u: number;
  bytes_u2c: number;
  frames: number;
  rewrites: number;
  sessions: number;
}

export interface ProxySession {
  dir_name: string;
  dir_path: string;
  started_at: string;
  flasher_peer: string;
  upstream_addr: string;
  spoof_vin: string | null;
  frames: number;
  bytes: number;
}

export interface ProxyFrameEvent {
  direction: 'C2U' | 'U2C';
  control: number;
  bytes_hex: string;
  note: string | null;
}

export interface ProxyStatusEvent {
  state: 'listening' | 'connected' | 'disconnected' | 'stopped' | 'error';
  detail: string;
}

export interface SimulatorStatus {
  running: boolean;
  bind_addr: string | null;
}

export interface SimulatorTranscriptEvent {
  direction: 'REQ' | 'RSP';
  service: number;
  body_hex: string;
  note: string | null;
}

export interface SimulatorStatusEvent {
  state: 'listening' | 'connected' | 'disconnected' | 'stopped' | 'error';
  detail: string;
}

export interface SimulatorSegmentEvent {
  address: number;
  size: number;
  file_path: string;
}

export interface FlashSession {
  dir_name: string;
  dir_path: string;
  vin: string | null;
  started_at: string;
  segment_count: number;
  total_bytes: number;
  min_address: number;
  max_address: number;
}

export interface FlashSegmentFile {
  address: number;
  size: number;
  file_path: string;
}

export interface SimulatorEcuProfile {
  name: string;
  description: string;
  ecu_address: number;
  vin: string | null;
  mac: string;
  dids: Record<string, string>;
  /// Optional artificial transfer-rate cap in kilobytes per second.
  /// Used to make the simulator's flash speed look realistic to a
  /// flasher's telemetry — null/0 means "as fast as possible".
  transfer_rate_kbps?: number | null;
}

export interface SimulatorCloneProgress {
  current: number;
  total: number;
  did: number;
  status: 'ok' | 'missing' | 'nrc';
}

/// One DME software-version-key entry as the Profile editor exposes it.
export interface SimulatorModuleIdent {
  sgbm: string; // 8 hex chars, e.g. "00001572"
  version: string; // dotted, e.g. "1.5.7"
}

/// All the typed DME identifiers a flasher actually queries during its
/// VIN/license check. Saved into the profile's F101 / 0x2502 / 0x2503 DIDs.
///
/// `calibration` is the second SWFL slot (legacy MEVD17) or the dedicated
/// SWFK entry (newer DMEs) — the backend auto-detects which class byte to
/// use based on what's already in the existing F101, so the editor just
/// shows one row.
export interface SimulatorDmeIdentifiers {
  hwel: SimulatorModuleIdent | null;
  btld: SimulatorModuleIdent | null;
  swfl_program: SimulatorModuleIdent | null;
  calibration: SimulatorModuleIdent | null;
  cafd: SimulatorModuleIdent | null;
  flash_counter: number | null;
  max_flash_counter: number | null;
  // Plain ASCII identification DIDs that diagnostic and tuning tools
  // read on every connect — return blank/N-A in their UI when unset,
  // so the editor exposes them as friendly text fields.
  serial_number: string | null;
  dme_supplier: string | null;
  system_supplier: string | null;
  hardware_number: string | null;
  zbnr: string | null;
  /// `YYMMDD`, encoded as 3 BCD bytes into DID 0xF18B by the backend.
  manufacture_date: string | null;
  /// Volts. Encoded as `voltage / 0.0942` rounded to a u8 in DID 0x5815.
  voltage_v: number | null;
  /// DME type designator (e.g. "MEVD17.2.P"). Stored in DID 0xF150.
  dme_type: string | null;
  /// Engine code (e.g. "N20"). Concatenated with dme_type into 0xF150.
  engine_code: string | null;
  /// 8-char ASCII calibration ID (e.g. "9VT9G40B"). Stored in DID 0x403C.
  calibration_id: string | null;
  /// 32-bit Calibration Verification Number. Stored in DID 0x403C.
  cvn: number | null;
  /// Long DME designation from the routine 0x0205 response,
  /// e.g. "MEVD17.2.P-N20-Mo-B20-U0-F030-EU6-HGAG_-LL-RL".
  long_designation: string | null;
  /// Project code that follows the cal ID in the routine 0x0205
  /// response (e.g. "9G4LBIX6").
  project_code: string | null;
}

export type BackupSaveFormat = 'raw' | 'padded_4mb';

export type BackupStatus = 'idle' | 'reading' | 'done' | 'error';

export interface BackupResult {
  success: boolean;
  file_path: string;
  bytes_read: number;
  file_size: number;
  format: string;
  message: string;
}

export interface BackupProgress {
  bytesRead: number;
  total: number;
  percentage: number;
  elapsedMs: number;
  /** Optional status note shown under the progress bar when the
   * reader is retrying a block, reconnecting, etc. */
  note?: string;
}

export interface DiscoveredDevice {
  ip: string;
  mac_address: string;
  vin: string;
  diag_address: number;
}

export type CaptureStatus =
  | 'idle'
  | 'starting'
  | 'capturing'
  | 'stopping'
  | 'done'
  | 'error';

export interface NetworkInterface {
  name: string;
  description: string;
  is_loopback: boolean;
  is_up: boolean;
}

export interface CaptureStats {
  packet_count: number;
  byte_count: number;
  duration_secs: number;
  packets_per_sec: number;
}

/// Returned by `stop_capture` — purely descriptive stats. The user
/// then chooses extract / save-pcap / discard via the dedicated
/// commands instead of having the stop step auto-run extraction.
export interface CaptureSummary {
  packet_count: number;
  byte_count: number;
  duration_secs: number;
  stream_count: number;
  hsfz_frame_count: number;
  flash_session_likely: boolean;
  interface: string;
}
