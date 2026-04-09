use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[cfg(feature = "libpcap")]
use serde::Serialize;

use crate::error::PcapError;
use crate::types::TcpPacket;

/// Live capture statistics emitted to the frontend via events.
///
/// Only constructed by the libpcap-backed capture engine, so the
/// struct definition is gated to match. The frontend's TypeScript
/// shape is independent and lives in `src/lib/types.ts`.
#[cfg(feature = "libpcap")]
#[derive(Debug, Clone, Serialize)]
pub struct CaptureStats {
    pub packet_count: u64,
    pub byte_count: u64,
    pub duration_secs: f64,
    pub packets_per_sec: f64,
}

/// Shared state for an active capture session
pub struct CaptureSession {
    pub stop_flag: Arc<AtomicBool>,
    pub packets: Arc<Mutex<Vec<TcpPacket>>>,
    pub packet_count: Arc<AtomicU64>,
    pub byte_count: Arc<AtomicU64>,
    pub started_at: Instant,
    pub interface_name: String,
}

impl CaptureSession {
    /// Construct a fresh capture session. Only callable when the
    /// `libpcap` feature is on, because that's the only path that
    /// ever populates the session field on `CaptureState`. The
    /// `CaptureSession` *type* still exists in no-libpcap builds
    /// (because `CaptureState` references it as
    /// `Option<Arc<CaptureSession>>`) — only the constructor is
    /// gated, since calling it without libpcap would create a
    /// session that nothing could ever feed packets into.
    #[cfg(feature = "libpcap")]
    pub fn new(interface_name: String) -> Self {
        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            packets: Arc::new(Mutex::new(Vec::new())),
            packet_count: Arc::new(AtomicU64::new(0)),
            byte_count: Arc::new(AtomicU64::new(0)),
            started_at: Instant::now(),
            interface_name,
        }
    }

    pub fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
    }

    /// Take ownership of the accumulated packets.
    /// Returns a `StateLock` error if the mutex was poisoned by a thread panic.
    pub fn take_packets(&self) -> Result<Vec<TcpPacket>, PcapError> {
        let mut lock = self.packets.lock().map_err(|_| {
            log::error!("Packet buffer mutex poisoned while taking packets");
            PcapError::StateLock
        })?;
        Ok(std::mem::take(&mut *lock))
    }
}
