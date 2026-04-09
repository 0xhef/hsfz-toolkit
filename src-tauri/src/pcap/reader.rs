use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::capture::parser::parse_ethernet_frame;
use crate::error::PcapError;
use crate::types::TcpPacket;

const PCAP_MAGIC_LE: u32 = 0xA1B2_C3D4;
const HSFZ_PORT: u16 = 6801;

/// Maximum per-packet size accepted from the pcap header. Jumbo frames top out
/// near 65535 bytes; 256 KiB gives us headroom while blocking adversarial values.
const MAX_PACKET_SIZE: usize = 262_144;

/// Maximum number of matching packets accumulated from a single file.
/// Matches the live-capture limit in `capture/engine.rs` for consistency.
const MAX_FILE_PACKETS: usize = 5_000_000;

/// Read all HSFZ-port-6801 TCP packets from a PCAP file on disk. Used
/// by the desktop CLI mode (`bmsecresearch capture.pcap dump.bin`)
/// where we already have a real filesystem path. The Tauri command
/// path uses `read_pcap_from_bytes` instead so the frontend can hand
/// us a Vec<u8> from `plugin-fs readFile` (which works with Android
/// content URIs).
#[allow(dead_code)] // Used by main.rs CLI mode, which is desktop-only
pub fn read_pcap(path: &Path) -> Result<Vec<TcpPacket>, PcapError> {
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(1024 * 1024, file);
    read_pcap_inner(reader)
}

/// Parse an in-memory PCAP buffer. Used by the `extract_pcap` Tauri
/// command — the frontend reads the user-picked file via
/// `@tauri-apps/plugin-fs`'s `readFile` (which handles Android Storage
/// Access Framework URIs natively) and passes the bytes through IPC.
pub fn read_pcap_from_bytes(data: &[u8]) -> Result<Vec<TcpPacket>, PcapError> {
    let cursor = std::io::Cursor::new(data);
    read_pcap_inner(cursor)
}

fn read_pcap_inner<R: Read>(mut reader: R) -> Result<Vec<TcpPacket>, PcapError> {
    let global_header = read_bytes(&mut reader, 24)?;
    let magic = u32_le(&global_header, 0);
    if magic != PCAP_MAGIC_LE {
        return Err(PcapError::InvalidMagic(magic));
    }

    let link_type = u32_le(&global_header, 20);
    if link_type != 1 {
        return Err(PcapError::UnsupportedLinkType(link_type));
    }

    let mut packets = Vec::new();
    let mut offset: u64 = 24;

    while let Ok(pkt_header) = read_bytes(&mut reader, 16) {
        let incl_len = u32_le(&pkt_header, 8) as usize;

        // Guard against adversarial/oversized packet headers.
        if incl_len > MAX_PACKET_SIZE {
            log::warn!(
                "PCAP packet at offset {} declares {} bytes (exceeds limit)",
                offset,
                incl_len
            );
            return Err(PcapError::PacketTooLarge);
        }

        let pkt_data = match read_bytes(&mut reader, incl_len) {
            Ok(d) => d,
            Err(_) => return Err(PcapError::TruncatedPacket(offset)),
        };
        offset += 16 + incl_len as u64;

        if let Some(tcp) = parse_ethernet_frame(&pkt_data) {
            if (tcp.src_port == HSFZ_PORT || tcp.dst_port == HSFZ_PORT) && !tcp.payload.is_empty() {
                if packets.len() >= MAX_FILE_PACKETS {
                    log::warn!("Max file packet limit reached ({})", MAX_FILE_PACKETS);
                    return Err(PcapError::CaptureTooLarge);
                }
                packets.push(tcp);
            }
        }
    }

    Ok(packets)
}

fn read_bytes<R: Read>(reader: &mut R, n: usize) -> Result<Vec<u8>, PcapError> {
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}
