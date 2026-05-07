use std::net::Ipv6Addr;

use crate::model::packet::Icmpv6Packet;

pub fn parse(bytes: &[u8]) -> Result<Icmpv6Packet, String> {
    if bytes.len() < 4 {
        return Err("icmpv6 packet too short".to_string());
    }

    let icmp_type = bytes[0];
    let code = bytes[1];

    let (identifier, sequence) = if matches!(icmp_type, 128 | 129) && bytes.len() >= 8 {
        (
            Some(u16::from_be_bytes([bytes[4], bytes[5]])),
            Some(u16::from_be_bytes([bytes[6], bytes[7]])),
        )
    } else {
        (None, None)
    };

    let target_address = if matches!(icmp_type, 135 | 136) && bytes.len() >= 24 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&bytes[8..24]);
        Some(Ipv6Addr::from(octets).to_string())
    } else {
        None
    };

    Ok(Icmpv6Packet {
        icmp_type,
        code,
        identifier,
        sequence,
        target_address,
        description: description(icmp_type, code),
    })
}

fn description(icmp_type: u8, code: u8) -> String {
    match (icmp_type, code) {
        (128, _) => "Echo Request".to_string(),
        (129, _) => "Echo Reply".to_string(),
        (135, _) => "Neighbor Solicitation".to_string(),
        (136, _) => "Neighbor Advertisement".to_string(),
        (1, _) => "Destination Unreachable".to_string(),
        (3, _) => "Time Exceeded".to_string(),
        _ => format!("ICMPv6 Type {icmp_type} Code {code}"),
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_neighbor_solicitation() {
        let mut bytes = [0u8; 24];
        bytes[0] = 135;
        bytes[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        let packet = parse(&bytes).expect("expected icmpv6");
        assert_eq!(packet.description, "Neighbor Solicitation");
        assert_eq!(packet.target_address.as_deref(), Some("2001:db8::1"));
    }
}
