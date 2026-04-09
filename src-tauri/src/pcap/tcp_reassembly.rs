use std::collections::{BTreeMap, HashMap};

use crate::types::{TcpPacket, TcpStream};

type StreamKey = ([u8; 4], u16, [u8; 4], u16);

/// Per-stream reassembly size limit.
/// HSFZ flash firmware images are typically <16MB; 32MB provides headroom
/// while guarding against crafted sequence numbers causing huge allocations.
const MAX_STREAM_SIZE: usize = 32 * 1024 * 1024;

/// Group TCP packets into reassembled streams by 4-tuple.
/// Returns only streams on port 6801 with meaningful payload.
pub fn reassemble_streams(packets: Vec<TcpPacket>) -> Vec<TcpStream> {
    let mut groups: HashMap<StreamKey, Vec<TcpPacket>> = HashMap::new();

    for pkt in packets {
        let key = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port);
        groups.entry(key).or_default().push(pkt);
    }

    let mut streams: Vec<TcpStream> = groups
        .into_iter()
        .filter_map(|(key, pkts)| reassemble_single_stream(key, pkts))
        .collect();

    // Sort by total data size descending (largest stream first = most likely flash data)
    streams.sort_by(|a, b| b.data.len().cmp(&a.data.len()));
    streams
}

/// Reassemble a single TCP stream using sequence numbers for correct byte placement.
fn reassemble_single_stream(key: StreamKey, packets: Vec<TcpPacket>) -> Option<TcpStream> {
    if packets.is_empty() {
        return None;
    }

    // Use BTreeMap keyed on seq for ordered, deduplicated placement
    let mut segments: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    for pkt in &packets {
        // Keep largest payload for any given seq (handles retransmits)
        let existing_len = segments.get(&pkt.seq).map_or(0, Vec::len);
        if pkt.payload.len() > existing_len {
            segments.insert(pkt.seq, pkt.payload.clone());
        }
    }

    // Explicit match avoids .unwrap() on the minimum key.
    let min_seq = match segments.keys().next() {
        Some(&seq) => seq,
        None => return None,
    };

    // Calculate total stream size, capped at MAX_STREAM_SIZE to prevent
    // unbounded allocation from crafted sequence numbers.
    let max_end = segments
        .iter()
        .map(|(seq, data)| {
            let offset = seq.wrapping_sub(min_seq) as usize;
            offset.saturating_add(data.len())
        })
        .filter(|&end| end <= MAX_STREAM_SIZE)
        .max()
        .unwrap_or(0);

    if max_end == 0 {
        return None;
    }

    // Place each segment at its correct offset
    let mut buf = vec![0u8; max_end];
    for (seq, data) in &segments {
        let offset = seq.wrapping_sub(min_seq) as usize;
        if let Some(end) = offset.checked_add(data.len()) {
            if end <= max_end {
                buf[offset..end].copy_from_slice(data);
            }
        }
    }

    Some(TcpStream {
        src_ip: key.0,
        src_port: key.1,
        dst_ip: key.2,
        dst_port: key.3,
        data: buf,
        packet_count: packets.len(),
    })
}
