use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::State;

use crate::binary::assembler;
use crate::capture::interfaces::NetworkInterface;
use crate::capture::state::CaptureSession;
use crate::error::PcapError;
use crate::hsfz::parser::parse_hsfz_frames;
use crate::pcap::tcp_reassembly::reassemble_streams;
#[cfg(feature = "libpcap")]
use crate::security::validate_interface_name;
use crate::types::{ExtractionResult, TcpPacket};
use crate::uds::session::extract_sessions;

/// Minimum stream size to consider for flash extraction (skip small handshake streams)
const MIN_STREAM_SIZE: usize = 10_000;

/// Accumulated block data for a completed extraction.
/// First element is the base address, second is the list of (segment_address, blocks).
type BlockData = (u32, Vec<(u32, Vec<Vec<u8>>)>);

/// Capture-related state protected by a single Mutex to prevent race conditions
pub struct CaptureState {
    pub session: Option<Arc<CaptureSession>>,
    pub thread: Option<std::thread::JoinHandle<()>>,
}

/// A finished capture, retained on AppState until the user picks an
/// action (extract / save-pcap / discard). Just the packet buffer —
/// stats are returned separately via `CaptureSummary` and don't need
/// to be parked here.
pub struct CapturedData {
    pub packets: Vec<TcpPacket>,
}

/// Quick statistics computed when a capture stops — what gets returned
/// to the frontend so it can render action buttons with real numbers.
#[derive(Debug, Serialize)]
pub struct CaptureSummary {
    pub packet_count: u64,
    pub byte_count: u64,
    pub duration_secs: f64,
    pub stream_count: u64,
    pub hsfz_frame_count: u64,
    /// True if at least one reassembled stream contains UDS download
    /// session bytes — i.e. an extract attempt would actually find
    /// flash data, not just generic HSFZ traffic.
    pub flash_session_likely: bool,
    pub interface: String,
}

/// Application state shared across Tauri commands
pub struct AppState {
    pub last_block_data: Mutex<Option<BlockData>>,
    pub capture: Mutex<CaptureState>,
    pub last_capture: Mutex<Option<CapturedData>>,
    /// Cooperative cancellation flag for long-running operations
    /// (calibration read, clone-from-car). The frontend sets this via
    /// `cancel_active_operation` and the work loops check it on every
    /// iteration. `Arc<AtomicBool>` so the work-thread side can clone
    /// the handle into a worker without holding a lock.
    pub cancel_flag: Arc<AtomicBool>,
    /// Pull-back buffer for large binary command outputs. Commands
    /// that produce multi-megabyte `Vec<u8>` results (calibration
    /// read, assembled flash binary, proxy pcap export, simulator
    /// flash export) stash their bytes here and return metadata
    /// only. The frontend then calls the matching `pull_*_bytes`
    /// command which returns `tauri::ipc::Response::new(bytes)` —
    /// a raw binary transfer that bypasses JSON encoding.
    ///
    /// Without this split, returning `Vec<u8>` from a Tauri command
    /// serializes it as a JSON array of numbers (`[255, 127, 0,
    /// ...]`), which for a 4 MB calibration dump is ~12 MB of JSON
    /// text and causes multi-second JS-thread freezes on mobile
    /// WebView when `JSON.parse` runs.
    pub last_bytes: Mutex<Option<Vec<u8>>>,
    /// Pull-back buffer for the per-operation text log produced
    /// alongside the artifact. Feature commands (calibration read,
    /// etc.) build a timestamped human-readable log of everything
    /// they did during the run — gateway handshake, each block,
    /// retries, reconnects, final stats — and stash it here. The
    /// frontend pulls it via `pull_last_op_log` after the artifact
    /// has been written, and writes a sibling `.log` file next to
    /// the artifact using the same `writeFile` path as the artifact
    /// itself (so the log ends up in the same directory the user
    /// picked, with zero extra Android storage permissions needed).
    pub last_op_log: Mutex<Option<String>>,
}

/// Shared extraction pipeline: Vec<TcpPacket> -> ExtractionResult
///
/// Used by both `extract_pcap` (from file) and `stop_capture` (from live capture).
fn run_extraction_pipeline(
    packets: Vec<TcpPacket>,
    state: &State<'_, AppState>,
) -> Result<ExtractionResult, PcapError> {
    if packets.is_empty() {
        return Err(PcapError::NoHsfzStreams);
    }

    // Reassemble TCP streams
    let streams = reassemble_streams(packets);
    log::info!("Reassembled {} TCP streams", streams.len());

    // Parse HSFZ frames from all significant streams
    let mut all_frames = Vec::new();
    for stream in &streams {
        if stream.data.len() < MIN_STREAM_SIZE {
            continue;
        }

        let frames = parse_hsfz_frames(&stream.data);
        log::info!(
            "Stream {} -> {}: {} HSFZ frames from {} bytes",
            stream.src_port,
            stream.dst_port,
            frames.len(),
            stream.data.len()
        );
        all_frames.extend(frames);
    }

    if all_frames.is_empty() {
        return Err(PcapError::NoHsfzStreams);
    }

    // Extract UDS sessions
    let session_result = extract_sessions(&all_frames);

    if session_result.block_data.is_empty() {
        return Err(PcapError::NoFlashSessions);
    }

    // Assemble binary
    let result = assembler::assemble_binary(
        &session_result.segments,
        &session_result.block_data,
        session_result.events,
        session_result.vin,
        session_result.ecu_address,
    )?;

    // Store block data for later save
    {
        let mut lock = state
            .last_block_data
            .lock()
            .map_err(|_| PcapError::StateLock)?;
        *lock = Some((result.base_address, session_result.block_data));
    }

    log::info!(
        "Extraction complete: {} bytes, {} segments",
        result.binary_size,
        result.segments.len()
    );

    Ok(result)
}

/// Extract flash sessions from a PCAP file.
///
/// # File I/O architecture
///
/// The frontend reads the PCAP file via `@tauri-apps/plugin-fs`'s
/// `readFile` and passes the bytes here as a `Vec<u8>`. This works on
/// every platform — on Android, `plugin-fs` handles Storage Access
/// Framework content URIs (`content://...`) transparently, which
/// `std::fs::File::open` cannot. Same architecture as the user-facing
/// write commands; see the comment on `read_calibration_region`.
#[tauri::command]
pub fn extract_pcap(
    pcap_bytes: Vec<u8>,
    state: State<'_, AppState>,
) -> Result<ExtractionResult, PcapError> {
    log::info!(
        "Parsing PCAP from frontend buffer: {} bytes",
        pcap_bytes.len()
    );
    let packets = crate::pcap::reader::read_pcap_from_bytes(&pcap_bytes)?;
    log::info!("Found {} TCP packets on port 6801", packets.len());

    run_extraction_pipeline(packets, &state)
}

/// Build the extracted-flash binary from the most recent extraction
/// session, stash it in `AppState.last_bytes`, and return just the
/// byte count. The frontend calls `pull_last_bytes` next to retrieve
/// the actual bytes as a raw `ArrayBuffer` (no JSON encoding), then
/// writes them via `plugin-fs writeFile`. See the pull_last_bytes
/// comment for why this two-command split exists.
#[tauri::command]
pub fn save_binary(state: State<'_, AppState>) -> Result<usize, PcapError> {
    let block_lock = state
        .last_block_data
        .lock()
        .map_err(|_| PcapError::StateLock)?;

    let (base_address, block_data) = block_lock.as_ref().ok_or(PcapError::NoFlashSessions)?;
    let bytes = assembler::build_binary_bytes(block_data, *base_address)?;
    let len = bytes.len();
    drop(block_lock);

    let mut stash = state.last_bytes.lock().map_err(|_| PcapError::StateLock)?;
    *stash = Some(bytes);
    log::info!("Stashed {} flash bytes for pull_last_bytes", len);
    Ok(len)
}

// --- Live Capture Commands ---

#[tauri::command]
pub fn list_interfaces() -> Result<Vec<NetworkInterface>, PcapError> {
    crate::capture::interfaces::list_interfaces()
}

#[cfg(not(feature = "libpcap"))]
#[tauri::command]
pub fn start_capture(
    _interface_name: String,
    _app_handle: tauri::AppHandle,
    _state: State<'_, AppState>,
) -> Result<(), PcapError> {
    Err(PcapError::PlatformUnsupported(
        "Live capture is not compiled into this build (the `libpcap` \
         feature is disabled). Use the Proxy tab to record HSFZ \
         frames as they're forwarded; the resulting session can be \
         exported as a .pcap and analyzed in the Extract from PCAP \
         tab. See SCOPE.md and ANDROID.md."
            .to_string(),
    ))
}

#[cfg(feature = "libpcap")]
#[tauri::command]
pub fn start_capture(
    interface_name: String,
    app_handle: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), PcapError> {
    // Validate the interface name before any state changes
    let validated_name = validate_interface_name(&interface_name)?.to_string();

    let mut capture_lock = state.capture.lock().map_err(|_| PcapError::StateLock)?;

    if capture_lock.session.is_some() {
        return Err(PcapError::CaptureAlreadyRunning);
    }

    // Clear stale data from previous extraction while we hold the capture lock
    {
        let mut last = state
            .last_block_data
            .lock()
            .map_err(|_| PcapError::StateLock)?;
        *last = None;
    }

    let session = Arc::new(CaptureSession::new(validated_name));
    let thread_handle =
        crate::capture::engine::spawn_capture_thread(app_handle, Arc::clone(&session))?;

    capture_lock.session = Some(session);
    capture_lock.thread = Some(thread_handle);

    log::info!("Live capture started");
    Ok(())
}

/// Returns the platform this binary was compiled for.
///
/// Returns one of: `"linux"`, `"macos"`, `"windows"`, `"android"`,
/// `"ios"`, or one of the BSDs. The frontend uses this for purely
/// cosmetic platform-specific affordances; capability-driven decisions
/// (like whether to show the live Capture tab) should use
/// `has_live_capture()` instead, which reflects what's actually
/// compiled into this binary.
#[tauri::command]
pub fn get_platform() -> &'static str {
    std::env::consts::OS
}

/// Cooperative cancellation for in-flight long-running operations.
/// Sets the global `AppState.cancel_flag`; the calibration read loop
/// and clone-from-car loop check it on every iteration and bail
/// cleanly with a "Cancelled by user" error. No-op if no operation
/// is running.
#[tauri::command(async)]
pub fn cancel_active_operation(state: State<'_, AppState>) {
    state.cancel_flag.store(true, Ordering::Release);
    log::info!("cancel_active_operation: cancel flag raised");
}

/// Pull the most recent large-binary payload from app state as raw
/// bytes via `tauri::ipc::Response`. Returns an empty response if
/// nothing is stashed.
///
/// This is the raw-binary counterpart to the user-facing write
/// commands (`read_calibration_region`, `save_binary`,
/// `save_capture_pcap`, `proxy_export_pcap`,
/// `simulator_export_flash_bin`). Those commands now only return
/// metadata — the actual bytes are stashed in `AppState.last_bytes`
/// and pulled here via an `ArrayBuffer` transfer.
///
/// `tauri::ipc::Response::new(bytes)` bypasses JSON encoding and
/// sends the bytes as a binary payload on the IPC channel. The
/// frontend `invoke` call receives the bytes as a `Uint8Array`
/// directly (no `JSON.parse` of a huge number array), which is what
/// makes the mobile WebView stay responsive when moving multi-MB
/// buffers across the IPC boundary.
#[tauri::command]
pub fn pull_last_bytes(state: State<'_, AppState>) -> Result<tauri::ipc::Response, PcapError> {
    let mut lock = state.last_bytes.lock().map_err(|_| PcapError::StateLock)?;
    let bytes = lock.take().unwrap_or_default();
    Ok(tauri::ipc::Response::new(bytes))
}

/// Pull the most recent per-operation text log from app state. Feature
/// commands build a timestamped log of everything that happened during
/// the run and stash it in `AppState.last_op_log`; the frontend calls
/// this command after the artifact write has completed and writes the
/// returned text as a sibling `.log` file next to the artifact. Returns
/// empty string if nothing is stashed.
#[tauri::command]
pub fn pull_last_op_log(state: State<'_, AppState>) -> Result<String, PcapError> {
    let mut lock = state.last_op_log.lock().map_err(|_| PcapError::StateLock)?;
    Ok(lock.take().unwrap_or_default())
}

/// Returns `true` if the live `Capture Flash` feature (libpcap-based
/// passive sniffing) is compiled into this binary. The frontend uses
/// this to decide whether to render the Capture tab.
///
/// Capability-driven, not platform-driven: a rooted Android build with
/// `--features libpcap` will return `true` here and get the full
/// Capture tab; a desktop build with `--no-default-features --features
/// research` will return `false` and have the tab hidden, even though
/// it's running on Linux/Windows/macOS.
#[tauri::command]
pub fn has_live_capture() -> bool {
    cfg!(feature = "libpcap")
}

/// Stop the live capture and return summary statistics. Does **not**
/// auto-run the flash-extraction pipeline — the user picks what to do
/// with the captured data via `extract_captured_flash`,
/// `save_capture_pcap`, or `discard_capture`. The packets stay parked
/// on `AppState.last_capture` until one of those commands fires.
#[tauri::command]
pub fn stop_capture(state: State<'_, AppState>) -> Result<CaptureSummary, PcapError> {
    let (session, thread_handle) = {
        let mut capture_lock = state.capture.lock().map_err(|_| PcapError::StateLock)?;
        let session = capture_lock
            .session
            .take()
            .ok_or(PcapError::NoCaptureRunning)?;
        let thread = capture_lock.thread.take();
        (session, thread)
    };

    session.request_stop();
    if let Some(handle) = thread_handle {
        if let Err(e) = handle.join() {
            log::error!("Capture thread join panicked: {:?}", e);
        }
    }

    let packets = session.take_packets()?;
    let duration_secs = session.started_at.elapsed().as_secs_f64();
    let byte_count = session
        .byte_count
        .load(std::sync::atomic::Ordering::Relaxed);
    let interface = session.interface_name.clone();

    log::info!(
        "Capture stopped: {} packets, {} bytes, {:.1}s on {}",
        packets.len(),
        byte_count,
        duration_secs,
        interface
    );

    // Compute lightweight summary stats so the user can decide what to
    // do. Reassembling streams and parsing HSFZ frames here is cheap
    // (no UDS pipeline, no flash assembly) — it just lets us tell the
    // user "you got 4096 packets, 12 streams, 380 HSFZ frames, no flash
    // session detected" instead of a binary success/fail.
    let streams = if packets.is_empty() {
        Vec::new()
    } else {
        reassemble_streams(packets.clone())
    };
    let stream_count = streams.len() as u64;
    let mut hsfz_frame_count: u64 = 0;
    let mut flash_session_likely = false;
    for stream in &streams {
        let frames = parse_hsfz_frames(&stream.data);
        if !frames.is_empty() {
            hsfz_frame_count += frames.len() as u64;
            // A "flash session likely" stream contains at least one
            // UDS RequestDownload (`0x34`) — that's the strongest
            // single signal that an extract attempt would succeed.
            if frames
                .iter()
                .any(|f| f.payload.len() >= 3 && (f.payload[2] == 0x34 || f.payload[2] == 0x36))
            {
                flash_session_likely = true;
            }
        }
    }

    // Park the packets so extract / save-pcap / discard can find them.
    {
        let mut lock = state
            .last_capture
            .lock()
            .map_err(|_| PcapError::StateLock)?;
        *lock = Some(CapturedData { packets });
    }

    Ok(CaptureSummary {
        packet_count: session
            .packet_count
            .load(std::sync::atomic::Ordering::Relaxed),
        byte_count,
        duration_secs,
        stream_count,
        hsfz_frame_count,
        flash_session_likely,
        interface,
    })
}

/// Run the flash-extraction pipeline against the most recently
/// captured data. Returns the same `ExtractionResult` shape the
/// offline `extract_pcap` command does, so the existing UI rendering
/// works unchanged.
#[tauri::command]
pub fn extract_captured_flash(state: State<'_, AppState>) -> Result<ExtractionResult, PcapError> {
    let packets = {
        let lock = state
            .last_capture
            .lock()
            .map_err(|_| PcapError::StateLock)?;
        let captured = lock.as_ref().ok_or(PcapError::NoCaptureRunning)?;
        captured.packets.clone()
    };
    run_extraction_pipeline(packets, &state)
}

/// Build a `.pcap` file body from the most recently captured packets,
/// stash it in `AppState.last_bytes`, and return just the byte count.
/// Frontend pulls the bytes via `pull_last_bytes` and writes them via
/// plugin-fs. Same two-command split as `save_binary`.
#[tauri::command]
pub fn save_capture_pcap(state: State<'_, AppState>) -> Result<usize, PcapError> {
    use crate::op_log::OpLog;

    let mut op = OpLog::new();
    let cap_lock = state
        .last_capture
        .lock()
        .map_err(|_| PcapError::StateLock)?;
    let captured = cap_lock.as_ref().ok_or(PcapError::NoCaptureRunning)?;
    let packet_count = captured.packets.len();
    op.push(format!("Loaded capture buffer: {} packets", packet_count));

    let bytes = crate::pcap::writer::write_pcap(&captured.packets);
    let byte_count = bytes.len();
    op.push(format!(
        "Serialized PCAP: {} bytes ({} packets)",
        byte_count, packet_count
    ));
    drop(cap_lock);

    let mut stash = state.last_bytes.lock().map_err(|_| PcapError::StateLock)?;
    *stash = Some(bytes);
    drop(stash);

    let header = crate::op_log::header(
        "Capture Save",
        &[("Packets", packet_count.to_string())],
    );
    let footer = format!(
        "RESULT: SUCCESS\nPCAP size:    {} bytes\nPacket count: {}\n",
        byte_count, packet_count
    );
    crate::op_log::stash(&state, op.format(&header, &footer));

    log::info!(
        "Stashed {} packets ({} bytes) as PCAP for pull_last_bytes",
        packet_count, byte_count
    );
    Ok(byte_count)
}

/// Discard the most recently captured data and clear the buffer.
#[tauri::command]
pub fn discard_capture(state: State<'_, AppState>) -> Result<(), PcapError> {
    let mut lock = state
        .last_capture
        .lock()
        .map_err(|_| PcapError::StateLock)?;
    *lock = None;
    log::info!("Discarded captured data");
    Ok(())
}
