use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tauri::{AppHandle, Emitter};

use crate::capture::parser::parse_ethernet_frame;
use crate::capture::state::CaptureSession;
use crate::error::PcapError;

const BPF_FILTER: &str = "tcp port 6801";
const HSFZ_PORT: u16 = 6801;
const STATS_INTERVAL: Duration = Duration::from_millis(250);
const READ_TIMEOUT_MS: i32 = 100;
/// Safety limit: stop accepting packets after this count to prevent unbounded memory growth
const MAX_PACKETS: u64 = 5_000_000;

/// Spawn the background capture thread.
///
/// The pcap device is opened inside the spawned thread to avoid Send issues.
/// A sync_channel is used to report initialization success/failure back to the caller.
pub fn spawn_capture_thread(
    app_handle: AppHandle,
    session: Arc<CaptureSession>,
) -> Result<std::thread::JoinHandle<()>, PcapError> {
    let interface_name = session.interface_name.clone();
    let stop_flag = Arc::clone(&session.stop_flag);
    let packets = Arc::clone(&session.packets);
    let packet_count = Arc::clone(&session.packet_count);
    let byte_count = Arc::clone(&session.byte_count);
    let start_time = session.started_at;

    // Channel for the spawned thread to report init success/failure
    let (init_tx, init_rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);

    let handle = std::thread::Builder::new()
        .name("pcap-capture".into())
        .spawn(move || {
            // Open device inside the thread
            let cap = pcap::Capture::from_device(interface_name.as_str())
                .and_then(|c| c.promisc(true).timeout(READ_TIMEOUT_MS).open());

            let mut cap = match cap {
                Ok(c) => c,
                Err(e) => {
                    let _ = init_tx.send(Err(format!("Capture open failed: {}", e)));
                    return;
                }
            };

            if let Err(e) = cap.filter(BPF_FILTER, true) {
                let _ = init_tx.send(Err(format!("BPF filter failed: {}", e)));
                return;
            }

            // Signal successful init
            let _ = init_tx.send(Ok(()));

            let mut last_stats_emit = Instant::now();

            loop {
                if stop_flag.load(Ordering::Acquire) {
                    break;
                }

                match cap.next_packet() {
                    Ok(packet) => {
                        if let Some(tcp) = parse_ethernet_frame(packet.data) {
                            if (tcp.src_port == HSFZ_PORT || tcp.dst_port == HSFZ_PORT)
                                && !tcp.payload.is_empty()
                            {
                                let current = packet_count.load(Ordering::Relaxed);
                                if current >= MAX_PACKETS {
                                    log::warn!(
                                        "Max packet limit reached ({}), dropping packet",
                                        MAX_PACKETS
                                    );
                                    continue;
                                }

                                let payload_len = tcp.payload.len() as u64;
                                packet_count.fetch_add(1, Ordering::Relaxed);
                                byte_count.fetch_add(payload_len, Ordering::Relaxed);

                                match packets.lock() {
                                    Ok(mut lock) => lock.push(tcp),
                                    Err(_) => {
                                        log::error!(
                                            "Packet buffer mutex poisoned, stopping capture"
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Normal when no packets arrive within READ_TIMEOUT_MS
                    }
                    Err(e) => {
                        log::error!("Capture error: {}", e);
                        let _ = app_handle.emit("capture:error", format!("{}", e));
                        break;
                    }
                }

                // Throttled stats emission
                if last_stats_emit.elapsed() >= STATS_INTERVAL {
                    let pkt_count = packet_count.load(Ordering::Relaxed);
                    let bt_count = byte_count.load(Ordering::Relaxed);
                    let duration = start_time.elapsed().as_secs_f64();
                    let pps = if duration > 0.0 {
                        pkt_count as f64 / duration
                    } else {
                        0.0
                    };

                    let stats = crate::capture::state::CaptureStats {
                        packet_count: pkt_count,
                        byte_count: bt_count,
                        duration_secs: duration,
                        packets_per_sec: pps,
                    };

                    let _ = app_handle.emit("capture:stats", &stats);
                    last_stats_emit = Instant::now();
                }
            }

            log::info!(
                "Capture thread exiting: {} packets, {} bytes",
                packet_count.load(Ordering::Relaxed),
                byte_count.load(Ordering::Relaxed),
            );
        })
        .map_err(|e| PcapError::Io(std::io::Error::other(format!("Thread spawn failed: {}", e))))?;

    // Wait for init result from the spawned thread
    match init_rx.recv() {
        Ok(Ok(())) => Ok(handle),
        Ok(Err(msg)) => Err(PcapError::PcapLibrary(msg)),
        Err(_) => Err(PcapError::PcapLibrary(
            "Capture thread died during initialization".into(),
        )),
    }
}
