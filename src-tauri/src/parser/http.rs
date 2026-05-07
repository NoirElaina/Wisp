use crate::model::packet::{HeaderField, HttpMessage};

pub fn parse(bytes: &[u8]) -> Option<HttpMessage> {
    if bytes.is_empty() {
        return None;
    }

    let raw_text = String::from_utf8_lossy(bytes).to_string();
    let starts_http = raw_text.starts_with("GET ")
        || raw_text.starts_with("POST ")
        || raw_text.starts_with("PUT ")
        || raw_text.starts_with("DELETE ")
        || raw_text.starts_with("HEAD ")
        || raw_text.starts_with("OPTIONS ")
        || raw_text.starts_with("HTTP/1.");

    if !starts_http {
        return None;
    }

    let mut lines = raw_text.split("\r\n");
    let start_line = lines.next()?.to_string();
    let is_request = !start_line.starts_with("HTTP/1.");
    let mut headers = Vec::new();
    let mut body = String::new();
    let mut in_headers = true;

    for line in lines {
        if in_headers {
            if line.is_empty() {
                in_headers = false;
                continue;
            }

            if let Some((name, value)) = line.split_once(':') {
                headers.push(HeaderField {
                    name: name.trim().to_string(),
                    value: value.trim().to_string(),
                });
            }
        } else {
            if !body.is_empty() {
                body.push('\n');
            }
            body.push_str(line);
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
