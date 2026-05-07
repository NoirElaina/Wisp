use std::net::{Ipv4Addr, Ipv6Addr};

use crate::model::packet::{DnsAnswer, DnsMessage, DnsQuestion};

pub fn parse(bytes: &[u8]) -> Result<DnsMessage, String> {
    if bytes.len() < 12 {
        return Err("dns message too short".to_string());
    }

    let transaction_id = be_u16(bytes, 0)?;
    let flags = be_u16(bytes, 2)?;
    let question_count = be_u16(bytes, 4)? as usize;
    let answer_count = be_u16(bytes, 6)? as usize;
    let authority_count = be_u16(bytes, 8)? as usize;
    let additional_count = be_u16(bytes, 10)? as usize;

    let mut offset = 12usize;
    let mut questions = Vec::new();
    for _ in 0..question_count {
        let (name, next_offset) = parse_name(bytes, offset, 0)?;
        offset = next_offset;
        let qtype = be_u16(bytes, offset)?;
        let _qclass = be_u16(bytes, offset + 2)?;
        offset += 4;
        questions.push(DnsQuestion {
            name,
            qtype: record_type_label(qtype),
        });
    }

    let mut answers = Vec::new();
    for _ in 0..answer_count {
        let (name, next_offset) = parse_name(bytes, offset, 0)?;
        offset = next_offset;
        let rtype = be_u16(bytes, offset)?;
        let _class = be_u16(bytes, offset + 2)?;
        let ttl = be_u32(bytes, offset + 4)?;
        let rdlength = be_u16(bytes, offset + 8)? as usize;
        offset += 10;

        let rdata = bytes
            .get(offset..offset + rdlength)
            .ok_or_else(|| "truncated dns answer".to_string())?;
        let data = format_rdata(bytes, rtype, offset, rdata)?;
        offset += rdlength;

        answers.push(DnsAnswer {
            name,
            rtype: record_type_label(rtype),
            data,
            ttl,
        });
    }

    let _ = authority_count;
    let _ = additional_count;

    Ok(DnsMessage {
        transaction_id,
        is_response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0x0f) as u8,
        rcode: (flags & 0x000f) as u8,
        questions,
        answers,
    })
}

fn parse_name(bytes: &[u8], offset: usize, depth: usize) -> Result<(String, usize), String> {
    if depth > 8 {
        return Err("dns compression pointer loop".to_string());
    }

    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut consumed = offset;
    let jumped = false;

    loop {
        let len = *bytes
            .get(cursor)
            .ok_or_else(|| "truncated dns name".to_string())?;

        if len == 0 {
            if !jumped {
                consumed = cursor + 1;
            }
            break;
        }

        if len & 0xc0 == 0xc0 {
            let next = *bytes
                .get(cursor + 1)
                .ok_or_else(|| "truncated dns compression pointer".to_string())?;
            let pointer = (((len & 0x3f) as usize) << 8) | next as usize;
            let (suffix, _) = parse_name(bytes, pointer, depth + 1)?;
            if !suffix.is_empty() {
                labels.push(suffix);
            }
            if !jumped {
                consumed = cursor + 2;
            }
            break;
        }

        cursor += 1;
        let label = bytes
            .get(cursor..cursor + len as usize)
            .ok_or_else(|| "truncated dns label".to_string())?;
        labels.push(String::from_utf8_lossy(label).to_string());
        cursor += len as usize;
        if !jumped {
            consumed = cursor;
        }
    }

    Ok((labels.join("."), consumed))
}

fn format_rdata(message: &[u8], rtype: u16, rdata_offset: usize, rdata: &[u8]) -> Result<String, String> {
    match rtype {
        1 if rdata.len() == 4 => Ok(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string()),
        28 if rdata.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            Ok(Ipv6Addr::from(octets).to_string())
        }
        5 | 2 | 12 => Ok(parse_name(message, rdata_offset, 0)?.0),
        15 => {
            if rdata.len() < 3 {
                return Err("truncated dns mx record".to_string());
            }
            let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
            let exchange = parse_name(message, rdata_offset + 2, 0)?.0;
            Ok(format!("{preference} {exchange}"))
        }
        16 => {
            if rdata.is_empty() {
                return Ok(String::new());
            }
            let len = rdata[0] as usize;
            let text = rdata
                .get(1..1 + len)
                .ok_or_else(|| "truncated dns txt record".to_string())?;
            Ok(String::from_utf8_lossy(text).to_string())
        }
        _ => Ok(rdata
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ")),
    }
}

pub fn record_type_label(value: u16) -> String {
    match value {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        65 => "HTTPS".to_string(),
        other => format!("TYPE{other}"),
    }
}

fn be_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "unexpected end of dns buffer".to_string())?;
    Ok(u16::from_be_bytes([slice[0], slice[1]]))
}

fn be_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| "unexpected end of dns buffer".to_string())?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_dns_query() {
        let bytes = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
            b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o',
            b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let dns = parse(&bytes).expect("expected dns query");
        assert!(!dns.is_response);
        assert_eq!(dns.questions[0].name, "www.example.com");
        assert_eq!(dns.questions[0].qtype, "A");
    }

    #[test]
    fn parses_dns_response() {
        let bytes = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03,
            b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o',
            b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x3c, 0x00, 0x04, 93, 184, 216, 34,
        ];

        let dns = parse(&bytes).expect("expected dns response");
        assert!(dns.is_response);
        assert_eq!(dns.answers[0].data, "93.184.216.34");
    }
}
