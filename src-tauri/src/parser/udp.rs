use crate::{model::packet::UdpDatagram, parser::cursor::ByteCursor};

pub struct ParsedUdp<'a> {
    pub packet: UdpDatagram,
    pub payload: &'a [u8],
}

pub fn parse(bytes: &[u8]) -> Result<ParsedUdp<'_>, String> {
    if bytes.len() < 8 {
        return Err("udp packet too short".to_string());
    }

    let mut cursor = ByteCursor::new(bytes);
    let src_port = cursor.read_be_u16()?;
    let dst_port = cursor.read_be_u16()?;
    let length = cursor.read_be_u16()?;
    let checksum = cursor.read_be_u16()?;

    let payload_end = usize::min(length as usize, bytes.len());

    Ok(ParsedUdp {
        packet: UdpDatagram {
            src_port,
            dst_port,
            length,
            checksum,
        },
        payload: &bytes[8..payload_end],
    })
}
