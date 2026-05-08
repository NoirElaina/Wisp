use crate::model::packet::{Http2Frame, Http2Message};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub fn parse(bytes: &[u8]) -> Option<Http2Message> {
    parse_message(bytes).map(|(message, _)| message)
}

pub fn parse_message(bytes: &[u8]) -> Option<(Http2Message, usize)> {
    let mut offset = 0usize;
    let mut has_preface = false;

    if bytes.starts_with(PREFACE) {
        has_preface = true;
        offset += PREFACE.len();
    }

    let mut frames = Vec::new();
    while bytes.len().saturating_sub(offset) >= 9 && frames.len() < 8 {
        let length =
            ((bytes[offset] as u32) << 16) | ((bytes[offset + 1] as u32) << 8) | bytes[offset + 2] as u32;
        let frame_type = bytes[offset + 3];
        let flags = bytes[offset + 4];
        let stream_id = u32::from_be_bytes([
            bytes[offset + 5] & 0x7f,
            bytes[offset + 6],
            bytes[offset + 7],
            bytes[offset + 8],
        ]);
        let total_len = 9usize.saturating_add(length as usize);
        if bytes.len().saturating_sub(offset) < total_len {
            break;
        }

        frames.push(Http2Frame {
            frame_type: frame_type_label(frame_type).to_string(),
            length,
            flags,
            stream_id,
        });
        offset += total_len;
    }

    if !has_preface && frames.is_empty() {
        return None;
    }

    Some((Http2Message { has_preface, frames }, offset))
}

fn frame_type_label(frame_type: u8) -> &'static str {
    match frame_type {
        0x0 => "DATA",
        0x1 => "HEADERS",
        0x2 => "PRIORITY",
        0x3 => "RST_STREAM",
        0x4 => "SETTINGS",
        0x5 => "PUSH_PROMISE",
        0x6 => "PING",
        0x7 => "GOAWAY",
        0x8 => "WINDOW_UPDATE",
        0x9 => "CONTINUATION",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::parse_message;

    #[test]
    fn parses_preface_and_settings_frame() {
        let mut bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);

        let (message, consumed) = parse_message(&bytes).expect("expected http2");
        assert!(message.has_preface);
        assert_eq!(message.frames.len(), 1);
        assert_eq!(message.frames[0].frame_type, "SETTINGS");
        assert_eq!(consumed, bytes.len());
    }
}
