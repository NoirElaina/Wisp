use crate::{model::packet::Ipv4Packet, parser::cursor::ByteCursor};

pub struct ParsedIpv4<'a> {
    pub packet: Ipv4Packet,
    pub payload: &'a [u8],
}

pub fn parse(bytes: &[u8]) -> Result<ParsedIpv4<'_>, String> {
    if bytes.len() < 20 {
        return Err("ipv4 packet too short".to_string());
    }

    let mut cursor = ByteCursor::new(bytes);
    let version_ihl = cursor.read_u8()?;
    let version = version_ihl >> 4;
    let ihl = version_ihl & 0x0f;
    let header_length = ihl * 4;

    if version != 4 {
        return Err("not an ipv4 packet".to_string());
    }

    if header_length < 20 {
        return Err("invalid ipv4 header length".to_string());
    }

    let _dscp_ecn = cursor.read_u8()?;
    let total_length = cursor.read_be_u16()?;
    let _identification = cursor.read_be_u16()?;
    let _flags_fragment = cursor.read_be_u16()?;
    let ttl = cursor.read_u8()?;
    let protocol = cursor.read_u8()?;
    let checksum = cursor.read_be_u16()?;
    let src = cursor.read_slice(4)?;
    let dst = cursor.read_slice(4)?;

    if bytes.len() < header_length as usize {
        return Err("truncated ipv4 header".to_string());
    }

    let payload_start = header_length as usize;
    let payload_end = usize::min(total_length as usize, bytes.len());

    Ok(ParsedIpv4 {
        packet: Ipv4Packet {
            version,
            header_length,
            total_length,
            ttl,
            protocol,
            checksum,
            src_ip: format_ip(src),
            dst_ip: format_ip(dst),
        },
        payload: &bytes[payload_start..payload_end],
    })
}

fn format_ip(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(".")
}
