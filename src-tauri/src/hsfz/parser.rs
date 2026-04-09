use crate::types::HsfzFrame;

const HSFZ_UDS: u16 = 0x0001;
const HSFZ_ACK: u16 = 0x0002;
const HSFZ_ALIVE: u16 = 0x0012;

const MAX_PAYLOAD_LEN: u32 = 0x10000;

/// Parse HSFZ frames from a reassembled TCP stream byte buffer.
///
/// HSFZ frame format:
///   [0..4] Length (u32 BE) — size of UDS payload only
///   [4..6] Control (u16 BE) — 0x0001=UDS, 0x0002=ACK, 0x0012=Alive
///   [6..6+length] UDS payload
///
/// Non-HSFZ bytes (e.g. PCAPdroid MITM metadata) are skipped automatically.
pub fn parse_hsfz_frames(data: &[u8]) -> Vec<HsfzFrame> {
    let mut frames = Vec::new();
    let mut pos = 0;

    while pos + 6 <= data.len() {
        let length = u32_be(data, pos);
        let control = u16_be(data, pos + 4);

        if is_valid_control(control) && (1..=MAX_PAYLOAD_LEN).contains(&length) {
            let total = 6 + length as usize;
            if pos + total <= data.len() {
                let payload = data[pos + 6..pos + total].to_vec();
                frames.push(HsfzFrame { control, payload });
                pos += total;
                continue;
            }
        }

        // Not a valid HSFZ frame — skip one byte and retry
        pos += 1;
    }

    frames
}

fn is_valid_control(control: u16) -> bool {
    matches!(control, HSFZ_UDS | HSFZ_ACK | HSFZ_ALIVE)
}

fn u16_be(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn u32_be(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tester_present() {
        // TesterPresent: f4 12 3e 00
        let data = vec![0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0xf4, 0x12, 0x3e, 0x00];
        let frames = parse_hsfz_frames(&data);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].control, HSFZ_UDS);
        assert_eq!(frames[0].payload, vec![0xf4, 0x12, 0x3e, 0x00]);
    }

    #[test]
    fn test_skip_garbage_before_frame() {
        let mut data = vec![0xFF, 0xFF, 0xFF]; // garbage
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0xf4, 0x12, 0x3e, 0x00]);
        let frames = parse_hsfz_frames(&data);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, vec![0xf4, 0x12, 0x3e, 0x00]);
    }

    #[test]
    fn test_consecutive_frames() {
        let mut data = Vec::new();
        // Frame 1: TesterPresent
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0xf4, 0x12, 0x3e, 0x00]);
        // Frame 2: ACK
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0xf4, 0x12, 0x3e, 0x00]);
        let frames = parse_hsfz_frames(&data);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].control, HSFZ_UDS);
        assert_eq!(frames[1].control, HSFZ_ACK);
    }
}
