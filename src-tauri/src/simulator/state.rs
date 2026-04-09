//! Per-connection UDS state machine.
//!
//! Tracks just enough to make a flasher happy:
//!
//! * current diagnostic session
//! * security-access seed/unlock state
//! * the active `RequestDownload` segment (if any) and its accumulated data
//! * a list of completed segments — these are the actual flash payload the
//!   tester wrote, ready to be persisted by the capture layer
//!
//! Nothing here touches the network — `services.rs` calls into this and
//! produces response bytes that `server.rs` then frames and writes.

use super::profile::EcuProfile;

/// Hard upper bound on a single download segment. The largest legitimate
/// MEVD17 region is the program flash at ~2 MB; we allow a generous 8 MB
/// to cover MG1 and future ECUs but reject anything beyond that to avoid
/// a malicious flasher pinning all our memory by claiming a 4 GB segment
/// in `RequestDownload`.
pub const MAX_SEGMENT_BYTES: usize = 8 * 1024 * 1024;

/// Hard upper bound on the number of completed segments we keep in RAM
/// for the duration of one session. Each segment is also written to disk,
/// so this only bounds the in-memory shadow used by `ReadMemoryByAddress`
/// fall-back. 64 segments is far more than any real flash workflow uses.
pub const MAX_COMPLETED_SEGMENTS: usize = 64;

/// One in-progress `RequestDownload` → `TransferData` → `RequestTransferExit`
/// pipeline. Block sequence is the standard ISO-14229 mod-256 counter that
/// the tester increments per `0x36` block; we follow it but don't enforce
/// it strictly because some HSFZ tools restart the counter mid-stream.
#[derive(Debug)]
pub struct DownloadSegment {
    pub address: u32,
    pub expected_size: u32,
    pub buffer: Vec<u8>,
    pub next_block_seq: u8,
}

/// One finished segment, ready to be written to disk.
#[derive(Debug, Clone)]
pub struct CompletedSegment {
    pub address: u32,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct SessionState {
    pub profile: EcuProfile,
    pub session: u8,
    pub security_unlocked: bool,
    /// 8-byte seed we returned on the most recent `27 11/13/…` request.
    /// Kept for the transcript log, not used for verification.
    pub last_seed: Option<[u8; 8]>,
    pub current_download: Option<DownloadSegment>,
    pub completed: Vec<CompletedSegment>,
}

impl SessionState {
    pub fn new(profile: EcuProfile) -> Self {
        Self {
            profile,
            session: 0x01, // default session
            security_unlocked: false,
            last_seed: None,
            current_download: None,
            completed: Vec::new(),
        }
    }

    /// Begin a new download segment. Any segment already in progress is
    /// abandoned (some flashers issue a fresh `RequestDownload` on retry
    /// without an explicit `RequestTransferExit`).
    ///
    /// Returns `Err` if `size` exceeds `MAX_SEGMENT_BYTES` — the caller
    /// should respond with NRC `requestOutOfRange` rather than allow a
    /// malicious tester to allocate gigabytes of buffer.
    pub fn begin_download(&mut self, address: u32, size: u32) -> Result<(), &'static str> {
        if size as usize > MAX_SEGMENT_BYTES {
            return Err("segment size exceeds MAX_SEGMENT_BYTES");
        }
        if let Some(prev) = self.current_download.take() {
            log::warn!(
                "simulator: discarding incomplete segment 0x{:08X} ({} of {} bytes)",
                prev.address,
                prev.buffer.len(),
                prev.expected_size
            );
        }
        self.current_download = Some(DownloadSegment {
            address,
            expected_size: size,
            buffer: Vec::with_capacity(size as usize),
            next_block_seq: 1,
        });
        Ok(())
    }

    /// Append a `TransferData` block to the current segment. Returns the
    /// block sequence number to echo in the positive response. Silently
    /// stops accepting bytes once the segment hits `MAX_SEGMENT_BYTES`
    /// (we still respond positively so the flasher's state machine
    /// doesn't deadlock — the bytes just don't get stored).
    pub fn push_block(&mut self, seq: u8, data: &[u8]) -> u8 {
        if let Some(seg) = self.current_download.as_mut() {
            let room = MAX_SEGMENT_BYTES.saturating_sub(seg.buffer.len());
            let take = data.len().min(room);
            seg.buffer.extend_from_slice(&data[..take]);
            seg.next_block_seq = seg.next_block_seq.wrapping_add(1);
        }
        seq
    }

    /// Finalize the current segment. Returns the completed segment so the
    /// caller can hand it to the capture layer. Older segments are evicted
    /// once `MAX_COMPLETED_SEGMENTS` is exceeded.
    pub fn finish_download(&mut self) -> Option<CompletedSegment> {
        let seg = self.current_download.take()?;
        let cs = CompletedSegment {
            address: seg.address,
            data: seg.buffer,
        };
        if self.completed.len() >= MAX_COMPLETED_SEGMENTS {
            self.completed.remove(0);
        }
        self.completed.push(cs.clone());
        Some(cs)
    }
}
