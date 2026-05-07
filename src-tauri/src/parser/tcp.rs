use crate::{
    model::packet::{TcpFlags, TcpSegment},
    parser::cursor::ByteCursor,
};

pub struct ParsedTcp<'a> {
    pub segment: TcpSegment,
    pub payload: &'a [u8],
}

pub fn parse(bytes: &[u8]) -> Result<ParsedTcp<'_>, String> {
    if bytes.len() < 20 {
        return Err("tcp segment too short".to_string());
    }

    let mut cursor = ByteCursor::new(bytes);
    let src_port = cursor.read_be_u16()?;
    let dst_port = cursor.read_be_u16()?;
    let seq = cursor.read_be_u32()?;
    let ack = cursor.read_be_u32()?;
    let data_offset_reserved = cursor.read_u8()?;
    let flags = cursor.read_u8()?;
    let window_size = cursor.read_be_u16()?;
    let checksum = cursor.read_be_u16()?;
    let _urgent_pointer = cursor.read_be_u16()?;

    let header_length = (data_offset_reserved >> 4) * 4;
    if header_length < 20 {
        return Err("invalid tcp header length".to_string());
    }

    if bytes.len() < header_length as usize {
        return Err("truncated tcp header".to_string());
    }

    Ok(ParsedTcp {
        segment: TcpSegment {
            src_port,
            dst_port,
            seq,
            ack,
            header_length,
            checksum,
            window_size,
            flags: TcpFlags {
                fin: flags & 0x01 != 0,
                syn: flags & 0x02 != 0,
                rst: flags & 0x04 != 0,
                psh: flags & 0x08 != 0,
                ack: flags & 0x10 != 0,
                urg: flags & 0x20 != 0,
            },
        },
        payload: &bytes[header_length as usize..],
    })
}
