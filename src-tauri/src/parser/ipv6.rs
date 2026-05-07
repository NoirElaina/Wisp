use std::net::Ipv6Addr;

use crate::model::packet::Ipv6Packet;

pub struct ParsedIpv6<'a> {
    pub packet: Ipv6Packet,
    pub payload: &'a [u8],
}

pub fn parse(bytes: &[u8]) -> Result<ParsedIpv6<'_>, String> {
    if bytes.len() < 40 {
        return Err("ipv6 packet too short".to_string());
    }

    let version = bytes[0] >> 4;
    if version != 6 {
        return Err("not an ipv6 packet".to_string());
    }

    let payload_length = u16::from_be_bytes([bytes[4], bytes[5]]);
    let next_header = bytes[6];
    let hop_limit = bytes[7];

    let mut src = [0u8; 16];
    src.copy_from_slice(&bytes[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&bytes[24..40]);

    let payload_start = 40usize;
    let payload_end = usize::min(payload_start + payload_length as usize, bytes.len());

    Ok(ParsedIpv6 {
        packet: Ipv6Packet {
            version,
            payload_length,
            next_header,
            hop_limit,
            src_ip: Ipv6Addr::from(src).to_string(),
            dst_ip: Ipv6Addr::from(dst).to_string(),
        },
        payload: &bytes[payload_start..payload_end],
    })
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_minimal_ipv6_header() {
        let mut bytes = [0u8; 40];
        bytes[0] = 0x60;
        bytes[6] = 17;
        bytes[7] = 64;
        bytes[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]);
        bytes[24..40].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]);

        let parsed = parse(&bytes).expect("expected ipv6 packet");
        assert_eq!(parsed.packet.version, 6);
        assert_eq!(parsed.packet.next_header, 17);
        assert_eq!(parsed.packet.hop_limit, 64);
        assert_eq!(parsed.packet.src_ip, "2001:db8::1");
        assert_eq!(parsed.packet.dst_ip, "2001:db8::2");
        assert!(parsed.payload.is_empty());
    }
}
