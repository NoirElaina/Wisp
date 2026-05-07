use crate::model::packet::{HeaderField, HttpMessage};

pub fn parse(bytes: &[u8]) -> Option<HttpMessage> {
    if bytes.is_empty() {
        return None;
    }

    let header_end = find_header_end(bytes)?;
    let raw_text = String::from_utf8_lossy(bytes).to_string();
    let starts_http = starts_http_message(&raw_text);

    if !starts_http {
        return None;
    }

    let header_text = String::from_utf8_lossy(&bytes[..header_end]).to_string();
    let mut lines = header_text.split("\r\n");
    let start_line = lines.next()?.to_string();
    let is_request = !start_line.starts_with("HTTP/");
    let mut headers = Vec::new();
    let body = String::from_utf8_lossy(&bytes[header_end..]).to_string();

    for line in lines {
        if line.is_empty() {
            continue;
        }

        if let Some((name, value)) = line.split_once(':') {
            headers.push(HeaderField {
                name: name.trim().to_string(),
                value: value.trim().to_string(),
            });
        }
    }

    Some(HttpMessage {
        is_request,
        start_line,
        headers,
        body_preview: body.chars().take(512).collect(),
        raw_text,
    })
}

pub fn extract_from_buffer(buffer: &mut Vec<u8>) -> Option<HttpMessage> {
    let start = find_http_start(buffer)?;
    if start > 0 {
        buffer.drain(..start);
    }

    let header_end = find_header_end(buffer)?;
    let message_bytes = buffer[..header_end].to_vec();
    buffer.drain(..header_end);
    parse(&message_bytes)
}

fn starts_http_message(raw_text: &str) -> bool {
    raw_text.starts_with("GET ")
        || raw_text.starts_with("POST ")
        || raw_text.starts_with("PUT ")
        || raw_text.starts_with("DELETE ")
        || raw_text.starts_with("HEAD ")
        || raw_text.starts_with("OPTIONS ")
        || raw_text.starts_with("PATCH ")
        || raw_text.starts_with("CONNECT ")
        || raw_text.starts_with("TRACE ")
        || raw_text.starts_with("HTTP/1.")
        || raw_text.starts_with("HTTP/2")
        || raw_text.starts_with("PRI * HTTP/2.0")
}

fn find_http_start(bytes: &[u8]) -> Option<usize> {
    const START_PATTERNS: [&[u8]; 11] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
        b"HTTP/1.",
        b"PRI * HTTP/2.0",
    ];

    for index in 0..bytes.len() {
        if START_PATTERNS
            .iter()
            .any(|pattern| bytes[index..].starts_with(pattern))
        {
            return Some(index);
        }
    }

    None
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .or_else(|| {
            bytes.windows(2)
                .position(|window| window == b"\n\n")
                .map(|index| index + 2)
        })
}
