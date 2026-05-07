use crate::model::packet::IcmpPacket;

pub fn parse(bytes: &[u8]) -> Result<IcmpPacket, String> {
    if bytes.len() < 4 {
        return Err("icmp packet too short".to_string());
    }

    let icmp_type = bytes[0];
    let code = bytes[1];

    let (identifier, sequence) = if matches!(icmp_type, 0 | 8) && bytes.len() >= 8 {
        (
            Some(u16::from_be_bytes([bytes[4], bytes[5]])),
            Some(u16::from_be_bytes([bytes[6], bytes[7]])),
        )
    } else {
        (None, None)
    };

    Ok(IcmpPacket {
        icmp_type,
        code,
        identifier,
        sequence,
        description: description(icmp_type, code),
    })
}

fn description(icmp_type: u8, code: u8) -> String {
    match (icmp_type, code) {
        (0, _) => "Echo Reply".to_string(),
        (3, 0) => "Destination Unreachable: Network Unreachable".to_string(),
        (3, 1) => "Destination Unreachable: Host Unreachable".to_string(),
        (3, _) => "Destination Unreachable".to_string(),
        (8, _) => "Echo Request".to_string(),
        (11, 0) => "Time Exceeded: TTL Exceeded".to_string(),
        (11, _) => "Time Exceeded".to_string(),
        _ => format!("ICMP Type {icmp_type} Code {code}"),
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_echo_request() {
        let bytes = [8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        let packet = parse(&bytes).expect("expected icmp");
        assert_eq!(packet.description, "Echo Request");
        assert_eq!(packet.identifier, Some(0x1234));
    }
}
