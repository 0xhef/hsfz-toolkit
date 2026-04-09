use crate::types::{FlashSegment, HsfzFrame, UdsEvent};
use crate::uds::parser::{parse_uds_frame, UdsMessage};

/// Tracks state across a sequence of UDS frames to extract flash sessions.
struct ActiveDownload {
    address: u32,
    expected_size: u32,
    blocks: Vec<Vec<u8>>,
}

/// Result of processing all UDS frames in a capture
pub struct SessionResult {
    pub segments: Vec<FlashSegment>,
    pub block_data: Vec<(u32, Vec<Vec<u8>>)>, // (address, blocks)
    pub events: Vec<UdsEvent>,
    pub vin: Option<String>,
    pub ecu_address: u8,
}

/// Process all HSFZ frames and extract flash download sessions.
pub fn extract_sessions(frames: &[HsfzFrame]) -> SessionResult {
    let mut segments = Vec::new();
    let mut block_data = Vec::new();
    let mut events = Vec::new();
    let mut vin: Option<String> = None;
    let mut ecu_address: u8 = 0x12;
    let mut current: Option<ActiveDownload> = None;

    for frame in frames {
        let msg = parse_uds_frame(frame);

        match msg {
            UdsMessage::RequestDownload { address, size, ecu } => {
                // Finalize any pending session
                if let Some(dl) = current.take() {
                    finalize_download(dl, &mut segments, &mut block_data);
                }
                ecu_address = ecu;
                events.push(UdsEvent {
                    event_type: "RequestDownload".into(),
                    detail: format!(
                        "addr=0x{:08X} size=0x{:X} ({} bytes) ECU=0x{:02X}",
                        address, size, size, ecu
                    ),
                });
                current = Some(ActiveDownload {
                    address,
                    expected_size: size,
                    blocks: Vec::new(),
                });
            }

            UdsMessage::RequestDownloadAccepted { max_block } => {
                events.push(UdsEvent {
                    event_type: "DownloadAccepted".into(),
                    detail: format!("max_block={}", max_block),
                });
            }

            UdsMessage::TransferData { data } => {
                if let Some(ref mut dl) = current {
                    dl.blocks.push(data);
                }
            }

            UdsMessage::TransferExit => {
                if let Some(dl) = current.take() {
                    let block_count = dl.blocks.len();
                    let actual: u32 = dl.blocks.iter().map(|b| b.len() as u32).sum();
                    events.push(UdsEvent {
                        event_type: "TransferExit".into(),
                        detail: format!("{} blocks, {} bytes", block_count, actual),
                    });
                    finalize_download(dl, &mut segments, &mut block_data);
                }
            }

            UdsMessage::Vin(v) => {
                events.push(UdsEvent {
                    event_type: "VIN".into(),
                    detail: v.clone(),
                });
                vin = Some(v);
            }

            UdsMessage::Event(evt) => {
                events.push(evt);
            }

            UdsMessage::Other => {}
        }
    }

    // Finalize any unclosed session
    if let Some(dl) = current.take() {
        finalize_download(dl, &mut segments, &mut block_data);
    }

    SessionResult {
        segments,
        block_data,
        events,
        vin,
        ecu_address,
    }
}

fn finalize_download(
    dl: ActiveDownload,
    segments: &mut Vec<FlashSegment>,
    block_data: &mut Vec<(u32, Vec<Vec<u8>>)>,
) {
    let actual_size: u32 = dl.blocks.iter().map(|b| b.len() as u32).sum();
    segments.push(FlashSegment {
        address: dl.address,
        expected_size: dl.expected_size,
        actual_size,
        block_count: dl.blocks.len(),
        size_match: actual_size == dl.expected_size,
    });
    block_data.push((dl.address, dl.blocks));
}
