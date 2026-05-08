use crate::model::packet::{HeaderField, HttpMessage};

pub fn parse(bytes: &[u8]) -> Option<HttpMessage> {
    parse_message(bytes).map(|message| message.0)
}

pub fn parse_message(bytes: &[u8]) -> Option<(HttpMessage, usize)> {
    if bytes.is_empty() {
        return None;
    }

    let start = find_http_start(bytes)?;
    let bytes = &bytes[start..];
    let header_end = find_header_end(bytes)?;
    let header_text = String::from_utf8_lossy(&bytes[..header_end]).to_string();
    if !starts_http_message(&header_text) {
        return None;
    }

    let mut lines = header_text.split("\r\n");
    let start_line = lines.next()?.to_string();
    let is_request = !start_line.starts_with("HTTP/");
    let mut headers = Vec::new();
    let mut content_length = None;
    let mut transfer_encoding_chunked = false;

    for line in lines {
        if line.is_empty() {
            continue;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();

            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse::<u64>().ok();
            }
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                transfer_encoding_chunked = true;
            }

            headers.push(HeaderField { name, value });
        }
    }

    let (body_bytes, consumed_bytes) = if transfer_encoding_chunked {
        let (body, consumed) = parse_chunked_body(&bytes[header_end..])?;
        (body, header_end + consumed)
    } else if let Some(content_length) = content_length {
        let content_length = content_length as usize;
        if bytes.len() < header_end + content_length {
            return None;
        }
        (
            bytes[header_end..header_end + content_length].to_vec(),
            header_end + content_length,
        )
    } else {
        (Vec::new(), header_end)
    };

    let raw_text = String::from_utf8_lossy(&bytes[..consumed_bytes]).to_string();

    Some((
        HttpMessage {
            is_request,
            start_line,
            headers,
            body_preview: String::from_utf8_lossy(&body_bytes).chars().take(512).collect(),
            content_length,
            transfer_encoding_chunked,
            consumed_bytes: consumed_bytes as u32,
            raw_text,
        },
        start + consumed_bytes,
    ))
}

#[allow(dead_code)]
pub fn extract_from_buffer(buffer: &mut Vec<u8>) -> Option<HttpMessage> {
    let (message, consumed) = parse_message(buffer)?;
    buffer.drain(..consumed);
    Some(message)
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
}

fn find_http_start(bytes: &[u8]) -> Option<usize> {
    const START_PATTERNS: [&[u8]; 10] = [
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

fn parse_chunked_body(bytes: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut offset = 0usize;
    let mut dechunked = Vec::new();

    loop {
        let line_end = bytes[offset..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|index| offset + index + 2)?;
        let line = std::str::from_utf8(&bytes[offset..line_end - 2]).ok()?;
        let chunk_size = usize::from_str_radix(line.split(';').next()?.trim(), 16).ok()?;
        offset = line_end;

        if bytes.len() < offset + chunk_size + 2 {
            return None;
        }

        if chunk_size == 0 {
            if bytes[offset..].starts_with(b"\r\n") {
                offset += 2;
            } else {
                let trailer_end = find_header_end(&bytes[offset..]).map(|end| offset + end)?;
                offset = trailer_end;
            }
            break;
        }

        dechunked.extend_from_slice(&bytes[offset..offset + chunk_size]);
        offset += chunk_size;
        if !bytes[offset..].starts_with(b"\r\n") {
            return None;
        }
        offset += 2;
    }

    Some((dechunked, offset))
}

#[cfg(test)]
mod tests {
    use super::parse_message;

    #[test]
    fn parses_content_length_body() {
        let bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        let (message, consumed) = parse_message(bytes).expect("expected http");
        assert_eq!(message.start_line, "GET / HTTP/1.1");
        assert_eq!(message.content_length, Some(5));
        assert_eq!(message.body_preview, "hello");
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn parses_chunked_body() {
        let bytes = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let (message, consumed) = parse_message(bytes).expect("expected chunked http");
        assert!(message.transfer_encoding_chunked);
        assert_eq!(message.body_preview, "hello");
        assert_eq!(consumed, bytes.len());
    }
}
