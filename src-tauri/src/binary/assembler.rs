use std::path::Path;

use crate::error::PcapError;
use crate::types::{ExtractionResult, FlashSegment, UdsEvent};

/// Maximum assembled binary size. Flash images for this ECU class are typically <16MB;
/// 64MB provides generous headroom while preventing crafted offsets from
/// causing unbounded allocations.
const MAX_BINARY_SIZE: usize = 64 * 1024 * 1024;

/// Compute the buffer size required to hold all block data, validating
/// that every segment address is >= base_address and that the resulting
/// size is within the allowed cap.
fn compute_buffer_size(
    block_data: &[(u32, Vec<Vec<u8>>)],
    base_address: u32,
) -> Result<usize, PcapError> {
    let mut max_end: usize = 0;
    for (addr, blocks) in block_data {
        let offset = addr
            .checked_sub(base_address)
            .ok_or(PcapError::NoFlashSessions)? as usize;
        let data_len: usize = blocks.iter().map(Vec::len).sum();
        let end = offset
            .checked_add(data_len)
            .ok_or(PcapError::NoFlashSessions)?;
        if end > MAX_BINARY_SIZE {
            return Err(PcapError::CaptureTooLarge);
        }
        if end > max_end {
            max_end = end;
        }
    }
    Ok(max_end)
}

/// Write each segment's blocks into `buf` at the correct offset.
/// Out-of-bounds writes are silently skipped (shouldn't happen because
/// compute_buffer_size() sizes the buffer to fit).
fn write_blocks(buf: &mut [u8], block_data: &[(u32, Vec<Vec<u8>>)], base_address: u32) {
    for (addr, blocks) in block_data {
        let Some(start_offset) = addr.checked_sub(base_address) else {
            continue;
        };
        let mut pos = start_offset as usize;
        for block in blocks {
            let Some(end) = pos.checked_add(block.len()) else {
                break;
            };
            if end <= buf.len() {
                buf[pos..end].copy_from_slice(block);
            }
            pos = end;
        }
    }
}

/// Assemble a flash binary from extracted download sessions.
///
/// Each session has a base address and a list of data blocks.
/// Blocks are placed sequentially starting at the session's address.
/// Gaps are filled with 0xFF (erased flash).
pub fn assemble_binary(
    segments: &[FlashSegment],
    block_data: &[(u32, Vec<Vec<u8>>)],
    events: Vec<UdsEvent>,
    vin: Option<String>,
    ecu_address: u8,
) -> Result<ExtractionResult, PcapError> {
    if block_data.is_empty() {
        return Ok(empty_result(events, vin, ecu_address));
    }

    // Find base address (minimum segment start).
    let base_address = block_data.iter().map(|(addr, _)| *addr).min().unwrap_or(0);

    let max_end = compute_buffer_size(block_data, base_address)?;

    // Allocate 0xFF-filled buffer (erased-flash default).
    let mut buf = vec![0xFFu8; max_end];
    write_blocks(&mut buf, block_data, base_address);

    let non_ff_bytes = buf.iter().filter(|&&b| b != 0xFF).count();
    let non_ff_percent = if buf.is_empty() {
        0.0
    } else {
        (non_ff_bytes as f64 / buf.len() as f64) * 100.0
    };

    let first_16 = hex_string(&buf[..buf.len().min(16)]);
    let last_16 = if buf.len() >= 16 {
        hex_string(&buf[buf.len() - 16..])
    } else {
        hex_string(&buf)
    };

    Ok(ExtractionResult {
        vin,
        ecu_address,
        segments: segments.to_vec(),
        events,
        binary_size: buf.len(),
        binary_path: None,
        base_address,
        non_ff_bytes,
        non_ff_percent,
        first_16_hex: first_16,
        last_16_hex: last_16,
    })
}

/// Build the assembled flash binary as an in-memory `Vec<u8>` for the
/// frontend to write via `plugin-fs writeFile`. Used by the
/// `save_binary` Tauri command — see the file-I/O architecture comment
/// on `read_calibration_region` in `calibration_read/mod.rs`.
pub fn build_binary_bytes(
    block_data: &[(u32, Vec<Vec<u8>>)],
    base_address: u32,
) -> Result<Vec<u8>, PcapError> {
    let max_end = compute_buffer_size(block_data, base_address)?;
    let mut buf = vec![0xFFu8; max_end];
    write_blocks(&mut buf, block_data, base_address);
    Ok(buf)
}

/// Write the assembled binary to disk at the given path. Desktop-only —
/// used by `main.rs` CLI mode (`bmsecresearch capture.pcap dump.bin`).
/// The Tauri command path uses `build_binary_bytes` instead so the
/// frontend can route the write through `plugin-fs`.
#[allow(dead_code)] // Used by main.rs CLI mode, which is desktop-only
pub fn save_binary(
    block_data: &[(u32, Vec<Vec<u8>>)],
    base_address: u32,
    output_path: &Path,
) -> Result<usize, PcapError> {
    let buf = build_binary_bytes(block_data, base_address)?;
    std::fs::write(output_path, &buf)?;
    Ok(buf.len())
}

fn hex_string(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn empty_result(events: Vec<UdsEvent>, vin: Option<String>, ecu_address: u8) -> ExtractionResult {
    ExtractionResult {
        vin,
        ecu_address,
        segments: Vec::new(),
        events,
        binary_size: 0,
        binary_path: None,
        base_address: 0,
        non_ff_bytes: 0,
        non_ff_percent: 0.0,
        first_16_hex: String::new(),
        last_16_hex: String::new(),
    }
}
