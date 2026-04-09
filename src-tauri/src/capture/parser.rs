use crate::types::TcpPacket;

const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_PROTO_TCP: u8 = 6;

/// Parse a raw Ethernet frame into a TcpPacket.
/// Returns None if the frame is not an IPv4 TCP packet.
///
/// Shared between the PCAP file reader and the live capture engine.
pub fn parse_ethernet_frame(data: &[u8]) -> Option<TcpPacket> {
    // Minimum: Ethernet(14) + IP(20) + TCP(20) = 54
    if data.len() < 54 {
        return None;
    }

    let eth_type = u16::from_be_bytes([data[12], data[13]]);
    if eth_type != ETHERTYPE_IPV4 {
        return None;
    }

    let ip_start = 14;
    let ihl = ((data[ip_start] & 0x0F) as usize) * 4;
    // IHL must be at least 20 bytes (5 words) and fit within the packet
    if ihl < 20 || ip_start + ihl > data.len() {
        return None;
    }
    let proto = data[ip_start + 9];
    if proto != IP_PROTO_TCP {
        return None;
    }

    let src_ip = [
        data[ip_start + 12],
        data[ip_start + 13],
        data[ip_start + 14],
        data[ip_start + 15],
    ];
    let dst_ip = [
        data[ip_start + 16],
        data[ip_start + 17],
        data[ip_start + 18],
        data[ip_start + 19],
    ];

    let tcp_start = ip_start + ihl;
    if tcp_start + 20 > data.len() {
        return None;
    }

    let src_port = u16::from_be_bytes([data[tcp_start], data[tcp_start + 1]]);
    let dst_port = u16::from_be_bytes([data[tcp_start + 2], data[tcp_start + 3]]);
    let seq = u32::from_be_bytes([
        data[tcp_start + 4],
        data[tcp_start + 5],
        data[tcp_start + 6],
        data[tcp_start + 7],
    ]);
    let tcp_hdr_len = (((data[tcp_start + 12] >> 4) & 0x0F) as usize) * 4;
    if tcp_hdr_len < 20 {
        return None;
    }
    let payload_start = tcp_start + tcp_hdr_len;

    let payload = if payload_start < data.len() {
        data[payload_start..].to_vec()
    } else {
        Vec::new()
    };

    Some(TcpPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        payload,
    })
}
