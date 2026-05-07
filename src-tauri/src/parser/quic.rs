use crate::model::packet::QuicMessage;

pub fn parse(bytes: &[u8]) -> Option<QuicMessage> {
    if bytes.len() < 8 {
        return None;
    }

    let first = bytes[0];
    if first & 0x40 == 0 {
        return None;
    }

    if first & 0x80 == 0 {
        return Some(QuicMessage {
            packet_type: "Short".to_string(),
            version: "1-RTT".to_string(),
            dcid: String::new(),
            scid: String::new(),
        });
    }

    if bytes.len() < 7 {
        return None;
    }

    let version_raw = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    let packet_type_bits = (first >> 4) & 0x03;
    let mut offset = 5usize;
    let dcid_len = *bytes.get(offset)? as usize;
    if dcid_len > 20 {
        return None;
    }
    offset += 1;
    let dcid = bytes.get(offset..offset + dcid_len)?;
    offset += dcid_len;
    let scid_len = *bytes.get(offset)? as usize;
    if scid_len > 20 {
        return None;
    }
    offset += 1;
    let scid = bytes.get(offset..offset + scid_len)?;

    Some(QuicMessage {
        packet_type: packet_type_label(version_raw, packet_type_bits).to_string(),
        version: version_label(version_raw),
        dcid: hex(dcid),
        scid: hex(scid),
    })
}

fn packet_type_label(version: u32, bits: u8) -> &'static str {
    if version == 0 {
        return "VersionNegotiation";
    }

    match bits {
        0 => "Initial",
        1 => "0-RTT",
        2 => "Handshake",
        3 => "Retry",
        _ => "LongHeader",
    }
}

fn version_label(version: u32) -> String {
    match version {
        0 => "Version Negotiation".to_string(),
        0x0000_0001 => "QUIC v1".to_string(),
        0x6b33_43cf => "QUIC v2".to_string(),
        other => format!("0x{other:08x}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn detects_quic_initial() {
        let bytes = [
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x04, 0xaa, 0xbb, 0xcc,
            0xdd,
        ];

        let quic = parse(&bytes).expect("expected quic");
        assert_eq!(quic.packet_type, "Initial");
        assert_eq!(quic.version, "QUIC v1");
    }
}
