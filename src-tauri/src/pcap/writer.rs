//! Minimal PCAP writer.
//!
//! Used by `save_capture_pcap` to dump live-captured packets to disk
//! in the standard libpcap file format. The captured `TcpPacket`s
//! arrive without link-layer framing (we keep them lean during the
//! capture loop), so we synthesise a 14-byte Ethernet header and a
//! 20-byte IPv4 header per packet on the way out — enough for
//! Wireshark to identify and dissect them as TCP/HSFZ traffic.
//!
//! File format reference: <https://wiki.wireshark.org/Development/LibpcapFileFormat>
//!
//! ```text
//! [pcap global header: 24 bytes]
//!   magic         = 0xA1B2C3D4 (microsecond resolution, little-endian)
//!   version       = 2.4
//!   thiszone      = 0
//!   sigfigs       = 0
//!   snaplen       = 65535
//!   network       = 1 (Ethernet)
//!
//! [per-packet record header: 16 bytes]
//!   ts_sec        = 0 (we don't carry per-packet timestamps)
//!   ts_usec       = monotonic counter
//!   incl_len      = caplen
//!   orig_len      = caplen
//!
//! [packet bytes: ETH + IPv4 + TCP + payload]
//! ```

use crate::types::TcpPacket;

const PCAP_MAGIC_LE_US: u32 = 0xA1B2_C3D4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_SNAPLEN: u32 = 65_535;
const LINKTYPE_ETHERNET: u32 = 1;

const ETH_HDR_LEN: usize = 14;
const IPV4_HDR_LEN: usize = 20;
const TCP_HDR_LEN: usize = 20;

/// Encode a slice of `TcpPacket`s as a complete PCAP file body.
///
/// Returns the bytes the caller should `fs::write` to disk. We
/// generate one PCAP record per `TcpPacket`, with synthetic ethernet,
/// IPv4 and TCP headers wrapping the payload. TCP flags are set to
/// `PSH | ACK` on every record — any non-trivial value works for
/// dissection because Wireshark only needs the protocol numbers to
/// line up to dissect the HSFZ payload.
pub fn write_pcap(packets: &[TcpPacket]) -> Vec<u8> {
    // Backward-compatible wrapper: emit a pcap where each record's
    // timestamp is `index ms` past the unix epoch. Wireshark dissects
    // fine; the real timing is meaningless. The capture path that has
    // real wall-clock data should call `write_pcap_timed` instead.
    let timed: Vec<(TcpPacket, u64)> = packets
        .iter()
        .enumerate()
        .map(|(i, p)| (p.clone(), i as u64))
        .collect();
    write_pcap_timed(&timed)
}

/// Same as `write_pcap` but each packet carries its own absolute
/// timestamp in **milliseconds since the unix epoch**. Used by the
/// proxy export path so the resulting pcap has real wall-clock times
/// in Wireshark's "Time" column instead of fake monotonic ones.
pub fn write_pcap_timed(packets: &[(TcpPacket, u64)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + packets.len() * 96);

    // ── PCAP global header ──────────────────────────────────────
    out.extend_from_slice(&PCAP_MAGIC_LE_US.to_le_bytes());
    out.extend_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
    out.extend_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&PCAP_SNAPLEN.to_le_bytes());
    out.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());

    for (pkt, ts_unix_ms) in packets {
        let frame = build_ethernet_frame(pkt);
        let caplen = frame.len() as u32;
        let ts_sec = (ts_unix_ms / 1_000) as u32;
        let ts_usec = ((ts_unix_ms % 1_000) * 1_000) as u32;

        // ── PCAP record header ──────────────────────────────────
        out.extend_from_slice(&ts_sec.to_le_bytes());
        out.extend_from_slice(&ts_usec.to_le_bytes());
        out.extend_from_slice(&caplen.to_le_bytes());
        out.extend_from_slice(&caplen.to_le_bytes());
        out.extend_from_slice(&frame);
    }

    out
}

fn build_ethernet_frame(pkt: &TcpPacket) -> Vec<u8> {
    let payload = &pkt.payload;
    let total_len = ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN + payload.len();
    let mut frame = Vec::with_capacity(total_len);

    // ── Ethernet II header ──────────────────────────────────────
    // Synthetic locally-administered MAC pair so Wireshark doesn't
    // squawk. The first byte 0x02 marks them as locally administered.
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // dst MAC
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src MAC
    frame.extend_from_slice(&[0x08, 0x00]); // ethertype = IPv4

    // ── IPv4 header ─────────────────────────────────────────────
    let ip_total_len = (IPV4_HDR_LEN + TCP_HDR_LEN + payload.len()) as u16;
    frame.push(0x45); // version 4, IHL 5 (= 20 bytes)
    frame.push(0x00); // DSCP/ECN
    frame.extend_from_slice(&ip_total_len.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes()); // identification
    frame.extend_from_slice(&0x4000u16.to_be_bytes()); // flags=DF, offset=0
    frame.push(64); // TTL
    frame.push(6); // protocol = TCP
    let ip_csum_offset = frame.len();
    frame.extend_from_slice(&0u16.to_be_bytes()); // checksum (filled below)
    frame.extend_from_slice(&pkt.src_ip);
    frame.extend_from_slice(&pkt.dst_ip);

    // Compute IPv4 header checksum.
    let csum = ipv4_checksum(&frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);
    frame[ip_csum_offset..ip_csum_offset + 2].copy_from_slice(&csum.to_be_bytes());

    // ── TCP header ──────────────────────────────────────────────
    frame.extend_from_slice(&pkt.src_port.to_be_bytes());
    frame.extend_from_slice(&pkt.dst_port.to_be_bytes());
    frame.extend_from_slice(&pkt.seq.to_be_bytes());
    frame.extend_from_slice(&0u32.to_be_bytes()); // ack number
    frame.push(0x50); // data offset (5 << 4) | reserved
    frame.push(0x18); // flags = PSH | ACK
    frame.extend_from_slice(&8192u16.to_be_bytes()); // window
    frame.extend_from_slice(&0u16.to_be_bytes()); // checksum (left blank)
    frame.extend_from_slice(&0u16.to_be_bytes()); // urgent ptr

    // ── TCP payload ─────────────────────────────────────────────
    frame.extend_from_slice(payload);

    frame
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_capture_writes_just_the_global_header() {
        let bytes = write_pcap(&[]);
        assert_eq!(bytes.len(), 24);
        assert_eq!(&bytes[0..4], &PCAP_MAGIC_LE_US.to_le_bytes());
    }

    #[test]
    fn one_packet_round_trip_size() {
        let pkt = TcpPacket {
            src_ip: [10, 5, 0, 2],
            dst_ip: [10, 5, 0, 1],
            src_port: 12345,
            dst_port: 6801,
            seq: 0xDEADBEEF,
            payload: vec![0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0xF4, 0x12, 0x3E, 0x00],
        };
        let bytes = write_pcap(&[pkt]);
        // 24 (global) + 16 (record hdr) + 14 (eth) + 20 (ip) + 20 (tcp) + 10 (payload)
        assert_eq!(bytes.len(), 24 + 16 + 14 + 20 + 20 + 10);
    }
}
