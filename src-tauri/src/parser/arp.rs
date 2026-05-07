use crate::{model::packet::ArpPacket, parser::cursor::ByteCursor};

pub fn parse(bytes: &[u8]) -> Result<ArpPacket, String> {
    if bytes.len() < 28 {
        return Err("arp packet too short".to_string());
    }

    let mut cursor = ByteCursor::new(bytes);
    let _hardware_type = cursor.read_be_u16()?;
    let _protocol_type = cursor.read_be_u16()?;
    let hardware_size = cursor.read_u8()?;
    let protocol_size = cursor.read_u8()?;
    let opcode = cursor.read_be_u16()?;

    if hardware_size != 6 || protocol_size != 4 {
        return Err("unsupported arp address length".to_string());
    }

    let src_mac = cursor.read_array_6()?;
    let src_ip = cursor.read_slice(4)?;
    let dst_mac = cursor.read_array_6()?;
    let dst_ip = cursor.read_slice(4)?;

    Ok(ArpPacket {
        opcode,
        src_mac: format_mac(&src_mac),
        src_ip: format_ip(src_ip),
        dst_mac: format_mac(&dst_mac),
        dst_ip: format_ip(dst_ip),
    })
}

fn format_mac(bytes: &[u8; 6]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_ip(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(".")
}
