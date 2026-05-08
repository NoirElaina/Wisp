use std::str;

use crate::model::packet::TlsMessage;

pub fn parse(bytes: &[u8]) -> Option<TlsMessage> {
    if bytes.len() < 5 {
        return None;
    }

    let content_type = bytes[0];
    if !matches!(content_type, 20..=24) {
        return None;
    }

    let version_raw = be_u16(&bytes[1..3])?;
    if version_raw >> 8 != 0x03 {
        return None;
    }

    let record_length = be_u16(&bytes[3..5])?;
    let total_length = 5usize.saturating_add(record_length as usize);
    if bytes.len() < total_length {
        return None;
    }

    let record_payload = &bytes[5..total_length];
    let mut message = TlsMessage {
        content_type: content_type_label(content_type).to_string(),
        version: version_label(version_raw),
        record_length,
        handshake_type: None,
        server_name: None,
        alpn_protocols: Vec::new(),
        cipher_suite: None,
        client_random: None,
        server_random: None,
    };

    if content_type != 22 || record_payload.len() < 4 {
        return Some(message);
    }

    let handshake_type = record_payload[0];
    message.handshake_type = Some(handshake_type_label(handshake_type).to_string());

    let handshake_length = be_u24(&record_payload[1..4])?;
    if record_payload.len() < 4 + handshake_length as usize {
        return Some(message);
    }

    let body = &record_payload[4..4 + handshake_length as usize];
    match handshake_type {
        1 => {
            let (server_name, alpn_protocols, cipher_suite, client_random) =
                parse_client_hello(body)?;
            message.server_name = server_name;
            message.alpn_protocols = alpn_protocols;
            message.cipher_suite = cipher_suite;
            message.client_random = client_random;
        }
        2 => {
            let (alpn_protocols, cipher_suite, server_random) = parse_server_hello(body)?;
            message.alpn_protocols = alpn_protocols;
            message.cipher_suite = cipher_suite;
            message.server_random = server_random;
        }
        _ => {}
    }

    Some(message)
}

pub fn record_total_length(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 5 {
        return None;
    }

    let content_type = bytes[0];
    if !matches!(content_type, 20..=24) {
        return None;
    }

    let version_raw = be_u16(&bytes[1..3])?;
    if version_raw >> 8 != 0x03 {
        return None;
    }

    let record_length = be_u16(&bytes[3..5])? as usize;
    Some(5usize.saturating_add(record_length))
}

fn parse_client_hello(body: &[u8]) -> Option<(Option<String>, Vec<String>, Option<String>, Option<String>)> {
    if body.len() < 34 {
        return None;
    }

    let client_random = Some(hex(body.get(2..34)?));
    let mut offset = 34;
    let session_id_len = *body.get(offset)? as usize;
    offset += 1 + session_id_len;

    let cipher_suites_len = be_u16(body.get(offset..offset + 2)?)? as usize;
    let first_cipher_suite = if cipher_suites_len >= 2 {
        Some(cipher_suite_label(be_u16(body.get(offset + 2..offset + 4)?)?).to_string())
    } else {
        None
    };
    offset += 2 + cipher_suites_len;

    let compression_methods_len = *body.get(offset)? as usize;
    offset += 1 + compression_methods_len;

    let extensions_len = be_u16(body.get(offset..offset + 2)?)? as usize;
    offset += 2;
    let extensions_end = offset + extensions_len;
    let extensions = body.get(offset..extensions_end)?;

    let (server_name, alpn_protocols) = parse_extensions(extensions);
    Some((server_name, alpn_protocols, first_cipher_suite, client_random))
}

fn parse_server_hello(body: &[u8]) -> Option<(Vec<String>, Option<String>, Option<String>)> {
    if body.len() < 38 {
        return None;
    }

    let server_random = Some(hex(body.get(2..34)?));
    let mut offset = 34;
    let session_id_len = *body.get(offset)? as usize;
    offset += 1 + session_id_len;
    let cipher_suite = Some(cipher_suite_label(be_u16(body.get(offset..offset + 2)?)?).to_string());
    offset += 2;
    offset += 1; // compression method

    let extensions_len = be_u16(body.get(offset..offset + 2)?)? as usize;
    offset += 2;
    let extensions_end = offset + extensions_len;
    let extensions = body.get(offset..extensions_end)?;

    let (_, alpn_protocols) = parse_extensions(extensions);
    Some((alpn_protocols, cipher_suite, server_random))
}

fn parse_extensions(bytes: &[u8]) -> (Option<String>, Vec<String>) {
    let mut offset = 0usize;
    let mut server_name = None;
    let mut alpn_protocols = Vec::new();

    while offset + 4 <= bytes.len() {
        let ext_type = match be_u16(&bytes[offset..offset + 2]) {
            Some(value) => value,
            None => break,
        };
        let ext_len = match be_u16(&bytes[offset + 2..offset + 4]) {
            Some(value) => value as usize,
            None => break,
        };
        offset += 4;

        let ext_data = match bytes.get(offset..offset + ext_len) {
            Some(slice) => slice,
            None => break,
        };
        offset += ext_len;

        match ext_type {
            0x0000 => {
                if let Some(name) = parse_server_name(ext_data) {
                    server_name = Some(name);
                }
            }
            0x0010 => {
                alpn_protocols = parse_alpn(ext_data);
            }
            _ => {}
        }
    }

    (server_name, alpn_protocols)
}

fn parse_server_name(bytes: &[u8]) -> Option<String> {
    let list_len = be_u16(bytes.get(0..2)?)? as usize;
    let list = bytes.get(2..2 + list_len)?;
    if list.len() < 3 || list[0] != 0 {
        return None;
    }

    let name_len = be_u16(list.get(1..3)?)? as usize;
    let name_bytes = list.get(3..3 + name_len)?;
    str::from_utf8(name_bytes).ok().map(ToString::to_string)
}

fn parse_alpn(bytes: &[u8]) -> Vec<String> {
    let Some(list_len) = be_u16(bytes.get(0..2).unwrap_or_default()) else {
        return Vec::new();
    };
    let Some(list) = bytes.get(2..2 + list_len as usize) else {
        return Vec::new();
    };

    let mut protocols = Vec::new();
    let mut offset = 0usize;
    while offset < list.len() {
        let len = list[offset] as usize;
        offset += 1;

        let Some(protocol_bytes) = list.get(offset..offset + len) else {
            break;
        };
        offset += len;

        if let Ok(protocol) = str::from_utf8(protocol_bytes) {
            protocols.push(protocol.to_string());
        }
    }

    protocols
}

fn content_type_label(content_type: u8) -> &'static str {
    match content_type {
        20 => "ChangeCipherSpec",
        21 => "Alert",
        22 => "Handshake",
        23 => "ApplicationData",
        24 => "Heartbeat",
        _ => "Unknown",
    }
}

fn handshake_type_label(handshake_type: u8) -> &'static str {
    match handshake_type {
        1 => "ClientHello",
        2 => "ServerHello",
        11 => "Certificate",
        16 => "ClientKeyExchange",
        20 => "Finished",
        _ => "Handshake",
    }
}

fn version_label(version: u16) -> String {
    match version {
        0x0300 => "SSL 3.0".to_string(),
        0x0301 => "TLS 1.0".to_string(),
        0x0302 => "TLS 1.1".to_string(),
        0x0303 => "TLS 1.2".to_string(),
        0x0304 => "TLS 1.3".to_string(),
        _ => format!("0x{version:04x}"),
    }
}

fn cipher_suite_label(value: u16) -> &'static str {
    match value {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x1304 => "TLS_AES_128_CCM_SHA256",
        0x1305 => "TLS_AES_128_CCM_8_SHA256",
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        _ => "UNKNOWN_CIPHER_SUITE",
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn be_u16(bytes: &[u8]) -> Option<u16> {
    Some(((bytes.first().copied()? as u16) << 8) | bytes.get(1).copied()? as u16)
}

fn be_u24(bytes: &[u8]) -> Option<u32> {
    Some(
        ((bytes.first().copied()? as u32) << 16)
            | ((bytes.get(1).copied()? as u32) << 8)
            | bytes.get(2).copied()? as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_generic_tls_application_data() {
        let bytes = [0x17, 0x03, 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];

        let tls = parse(&bytes).expect("expected tls record");
        assert_eq!(tls.content_type, "ApplicationData");
        assert_eq!(tls.version, "TLS 1.2");
        assert_eq!(tls.record_length, 4);
        assert!(tls.handshake_type.is_none());
    }
}
