use crate::types::{HsfzFrame, UdsEvent};

const HSFZ_UDS: u16 = 0x0001;

const SID_DIAG_SESSION: u8 = 0x10;
const SID_ECU_RESET: u8 = 0x11;
const SID_SECURITY_ACCESS: u8 = 0x27;
const SID_READ_DID_POS: u8 = 0x62;
const SID_ROUTINE_CONTROL: u8 = 0x31;
const SID_NEGATIVE_RESPONSE: u8 = 0x7F;

/// Parsed UDS message with semantic meaning
#[derive(Debug, Clone)]
pub enum UdsMessage {
    /// RequestDownload: address, size
    RequestDownload { address: u32, size: u32, ecu: u8 },
    /// RequestDownload positive response: max block size
    RequestDownloadAccepted { max_block: u32 },
    /// TransferData: block data (counter byte already stripped)
    TransferData { data: Vec<u8> },
    /// TransferExit
    TransferExit,
    /// Informational event (for display)
    Event(UdsEvent),
    /// VIN read from DID 0xF190
    Vin(String),
    /// Unrecognized or irrelevant
    Other,
}

/// Parse a single HSFZ UDS frame into a semantic UDS message.
pub fn parse_uds_frame(frame: &HsfzFrame) -> UdsMessage {
    if frame.control != HSFZ_UDS || frame.payload.len() < 3 {
        return UdsMessage::Other;
    }

    let src = frame.payload[0];
    let dst = frame.payload[1];
    let sid = frame.payload[2];
    let data = &frame.payload[3..];

    let is_tx = src == 0xF4 && (dst == 0x12 || dst == 0x13);
    let is_rx = dst == 0xF4 && (src == 0x12 || src == 0x13);

    // --- Tester -> ECU ---
    if is_tx {
        match sid {
            SID_DIAG_SESSION if !data.is_empty() => {
                let name = match data[0] {
                    0x01 => "Default",
                    0x02 => "Programming",
                    0x03 => "Extended",
                    0x41 => "Custom_0x41",
                    0x85 => "Custom_0x85",
                    _ => "Unknown",
                };
                UdsMessage::Event(UdsEvent {
                    event_type: "DiagSession".into(),
                    detail: name.into(),
                })
            }

            SID_ECU_RESET if !data.is_empty() => UdsMessage::Event(UdsEvent {
                event_type: "ECUReset".into(),
                detail: format!("type=0x{:02X}", data[0]),
            }),

            SID_SECURITY_ACCESS if !data.is_empty() => {
                let detail = if data[0] % 2 == 1 {
                    format!("RequestSeed L{}", data[0].div_ceil(2))
                } else {
                    format!("SendKey L{} ({} bytes)", data[0] / 2, data.len() - 1)
                };
                UdsMessage::Event(UdsEvent {
                    event_type: "SecurityAccess".into(),
                    detail,
                })
            }

            SID_ROUTINE_CONTROL if data.len() >= 3 => {
                let routine_id = u16_be(data, 1);
                match routine_id {
                    0xFF00 if data.len() >= 12 => {
                        let addr_len_fmt = data[4];
                        let ab = ((addr_len_fmt >> 4) & 0xF) as usize;
                        let lb = (addr_len_fmt & 0xF) as usize;
                        if data.len() >= 5 + ab + lb {
                            let addr = uint_be(&data[5..5 + ab]);
                            let size = uint_be(&data[5 + ab..5 + ab + lb]);
                            UdsMessage::Event(UdsEvent {
                                event_type: "Erase".into(),
                                detail: format!(
                                    "addr=0x{:08X} size=0x{:X} ({} bytes)",
                                    addr, size, size
                                ),
                            })
                        } else {
                            UdsMessage::Other
                        }
                    }
                    0xFF01 => UdsMessage::Event(UdsEvent {
                        event_type: "Routine".into(),
                        detail: "CheckProgrammingDependencies".into(),
                    }),
                    _ => UdsMessage::Event(UdsEvent {
                        event_type: "Routine".into(),
                        detail: format!("0x{:04X}", routine_id),
                    }),
                }
            }

            // RequestDownload (0x34)
            0x34 if data.len() >= 2 => {
                let addr_len = data[1];
                let ab = ((addr_len >> 4) & 0xF) as usize;
                let lb = (addr_len & 0xF) as usize;
                if data.len() >= 2 + ab + lb {
                    let address = uint_be(&data[2..2 + ab]) as u32;
                    let size = uint_be(&data[2 + ab..2 + ab + lb]) as u32;
                    UdsMessage::RequestDownload {
                        address,
                        size,
                        ecu: dst,
                    }
                } else {
                    UdsMessage::Other
                }
            }

            // TransferData (0x36)
            0x36 if !data.is_empty() => {
                // data[0] is block counter, rest is flash data
                UdsMessage::TransferData {
                    data: data[1..].to_vec(),
                }
            }

            // TransferExit (0x37)
            0x37 => UdsMessage::TransferExit,

            _ => UdsMessage::Other,
        }
    }
    // --- ECU -> Tester ---
    else if is_rx {
        match sid {
            // RequestDownload positive response (0x74)
            0x74 if !data.is_empty() => {
                let n = ((data[0] >> 4) & 0xF) as usize;
                if n > 0 && data.len() > n {
                    let max_block = uint_be(&data[1..1 + n]) as u32;
                    UdsMessage::RequestDownloadAccepted { max_block }
                } else {
                    UdsMessage::Other
                }
            }

            // ReadDataByIdentifier positive response (0x62)
            SID_READ_DID_POS if data.len() >= 2 => {
                let did = u16_be(data, 0);
                match did {
                    0xF190 if data.len() > 2 => {
                        // VINs from untrusted packets may contain arbitrary
                        // bytes; sanitize to ASCII alphanumeric before further
                        // use (filenames, display, etc.).
                        let raw = String::from_utf8_lossy(&data[2..]);
                        match crate::security::sanitize_vin(&raw) {
                            Some(vin) => UdsMessage::Vin(vin),
                            None => UdsMessage::Other,
                        }
                    }
                    _ => UdsMessage::Other,
                }
            }

            // Negative response
            SID_NEGATIVE_RESPONSE if data.len() >= 2 => {
                let nrc = data[1];
                if nrc == 0x78 {
                    // ResponsePending — ignore
                    UdsMessage::Other
                } else {
                    UdsMessage::Event(UdsEvent {
                        event_type: "NRC".into(),
                        detail: format!("SID=0x{:02X} code=0x{:02X}", data[0], nrc),
                    })
                }
            }

            _ => UdsMessage::Other,
        }
    } else {
        UdsMessage::Other
    }
}

fn u16_be(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn uint_be(bytes: &[u8]) -> usize {
    bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize)
}
