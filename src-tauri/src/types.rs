use serde::Serialize;

/// Raw TCP packet extracted from PCAP
#[derive(Debug, Clone)]
pub struct TcpPacket {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub payload: Vec<u8>,
}

/// A reassembled TCP stream
#[derive(Debug, Clone)]
pub struct TcpStream {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub data: Vec<u8>,
    pub packet_count: usize,
}

impl TcpStream {
    pub fn direction_label(&self) -> String {
        format!(
            "{}.{}.{}.{}:{} -> {}.{}.{}.{}:{}",
            self.src_ip[0],
            self.src_ip[1],
            self.src_ip[2],
            self.src_ip[3],
            self.src_port,
            self.dst_ip[0],
            self.dst_ip[1],
            self.dst_ip[2],
            self.dst_ip[3],
            self.dst_port,
        )
    }
}

/// Parsed HSFZ frame
pub struct HsfzFrame {
    pub control: u16,
    pub payload: Vec<u8>,
}

/// A single flash download session (one RequestDownload..TransferExit cycle)
#[derive(Debug, Clone, Serialize)]
pub struct FlashSegment {
    pub address: u32,
    pub expected_size: u32,
    pub actual_size: u32,
    pub block_count: usize,
    pub size_match: bool,
}

/// A UDS event observed during extraction (for display)
#[derive(Debug, Clone, Serialize)]
pub struct UdsEvent {
    pub event_type: String,
    pub detail: String,
}

/// Complete extraction result returned to frontend
#[derive(Debug, Clone, Serialize)]
pub struct ExtractionResult {
    pub vin: Option<String>,
    pub ecu_address: u8,
    pub segments: Vec<FlashSegment>,
    pub events: Vec<UdsEvent>,
    pub binary_size: usize,
    pub binary_path: Option<String>,
    pub base_address: u32,
    pub non_ff_bytes: usize,
    pub non_ff_percent: f64,
    pub first_16_hex: String,
    pub last_16_hex: String,
}
