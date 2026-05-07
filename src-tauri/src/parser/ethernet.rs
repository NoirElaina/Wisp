use crate::{model::packet::EthernetFrame, parser::cursor::ByteCursor};

pub struct ParsedEthernet<'a> {
    pub frame: EthernetFrame,
    pub payload: &'a [u8],
}

pub fn parse(bytes: &[u8]) -> Result<ParsedEthernet<'_>, String> {
    if bytes.len() < 14 {
        return Err("ethernet frame too short".to_string());
    }

    let mut cursor = ByteCursor::new(bytes);
    let dst_mac = cursor.read_array_6()?;
    let src_mac = cursor.read_array_6()?;
    let ether_type = cursor.read_be_u16()?;

    Ok(ParsedEthernet {
        frame: EthernetFrame {
            src_mac: format_mac(&src_mac),
            dst_mac: format_mac(&dst_mac),
            ether_type,
        },
        payload: &bytes[cursor.offset()..],
    })
}

fn format_mac(bytes: &[u8; 6]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
