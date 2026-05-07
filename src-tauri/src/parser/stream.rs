use std::collections::HashMap;

use crate::model::packet::{HttpMessage, TlsMessage};

use super::http;

const MAX_STREAM_BUFFER: usize = 64 * 1024;
const MAX_TRACKED_STREAMS: usize = 2048;

#[derive(Debug, Clone)]
pub struct TcpFlowObservation<'a> {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub fin: bool,
    pub rst: bool,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TlsFlowKey {
    endpoint_a_ip: String,
    endpoint_a_port: u16,
    endpoint_b_ip: String,
    endpoint_b_port: u16,
}

#[derive(Debug, Default)]
pub struct TcpFlowTracker {
    streams: HashMap<TcpFlowKey, TcpConversationState>,
    tls_flows: HashMap<TlsFlowKey, TlsFlowState>,
}

#[derive(Debug, Default)]
struct TcpConversationState {
    next_seq: Option<u32>,
    buffer: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct TlsFlowState {
    pub is_https: bool,
    pub server_name: Option<String>,
    pub alpn_protocols: Vec<String>,
    pub cipher_suite: Option<String>,
    pub client_random: Option<String>,
    pub server_random: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TlsFlowObservation<'a> {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub fin: bool,
    pub rst: bool,
    pub message: &'a TlsMessage,
}

impl TcpFlowTracker {
    pub fn observe_http(&mut self, observation: TcpFlowObservation<'_>) -> Option<HttpMessage> {
        if observation.payload.is_empty() {
            self.finish_stream_if_needed(&observation);
            return None;
        }

        if self.streams.len() >= MAX_TRACKED_STREAMS {
            self.streams.clear();
        }

        let key = TcpFlowKey {
            src_ip: observation.src_ip,
            dst_ip: observation.dst_ip,
            src_port: observation.src_port,
            dst_port: observation.dst_port,
        };

        let detected = {
            let state = self.streams.entry(key.clone()).or_default();
            append_payload(state, observation.seq, observation.payload);
            http::extract_from_buffer(&mut state.buffer)
        };

        if observation.fin || observation.rst {
            self.streams.remove(&key);
        }

        detected
    }

    fn finish_stream_if_needed(&mut self, observation: &TcpFlowObservation<'_>) {
        if !observation.fin && !observation.rst {
            return;
        }

        self.streams.remove(&TcpFlowKey {
            src_ip: observation.src_ip.clone(),
            dst_ip: observation.dst_ip.clone(),
            src_port: observation.src_port,
            dst_port: observation.dst_port,
        });
    }

    pub fn observe_tls(&mut self, observation: TlsFlowObservation<'_>) -> TlsFlowState {
        let key = TlsFlowKey::new(
            &observation.src_ip,
            observation.src_port,
            &observation.dst_ip,
            observation.dst_port,
        );

        let state = self.tls_flows.entry(key.clone()).or_default();

        if let Some(server_name) = &observation.message.server_name {
            state.server_name = Some(server_name.clone());
        }

        if !observation.message.alpn_protocols.is_empty() {
            state.alpn_protocols = observation.message.alpn_protocols.clone();
        }

        if let Some(cipher_suite) = &observation.message.cipher_suite {
            state.cipher_suite = Some(cipher_suite.clone());
        }

        if let Some(client_random) = &observation.message.client_random {
            state.client_random = Some(client_random.clone());
        }

        if let Some(server_random) = &observation.message.server_random {
            state.server_random = Some(server_random.clone());
        }

        if !state.is_https {
            state.is_https = likely_https(
                observation.src_port,
                observation.dst_port,
                observation.message,
                &state.alpn_protocols,
            );
        }

        let snapshot = state.clone();

        if observation.fin || observation.rst {
            self.tls_flows.remove(&key);
        }

        snapshot
    }
}

impl TlsFlowKey {
    fn new(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> Self {
        let left = (src_ip, src_port);
        let right = (dst_ip, dst_port);

        if left <= right {
            Self {
                endpoint_a_ip: src_ip.to_string(),
                endpoint_a_port: src_port,
                endpoint_b_ip: dst_ip.to_string(),
                endpoint_b_port: dst_port,
            }
        } else {
            Self {
                endpoint_a_ip: dst_ip.to_string(),
                endpoint_a_port: dst_port,
                endpoint_b_ip: src_ip.to_string(),
                endpoint_b_port: src_port,
            }
        }
    }
}

fn append_payload(state: &mut TcpConversationState, seq: u32, payload: &[u8]) {
    match state.next_seq {
        None => {
            state.buffer.extend_from_slice(payload);
            state.next_seq = Some(seq.wrapping_add(payload.len() as u32));
        }
        Some(next_seq) if seq == next_seq => {
            state.buffer.extend_from_slice(payload);
            state.next_seq = Some(next_seq.wrapping_add(payload.len() as u32));
        }
        Some(next_seq) if seq < next_seq => {
            let overlap = next_seq.saturating_sub(seq) as usize;
            if overlap < payload.len() {
                state.buffer.extend_from_slice(&payload[overlap..]);
                state.next_seq = Some(next_seq.wrapping_add((payload.len() - overlap) as u32));
            }
        }
        Some(_) => {
            state.buffer.clear();
            state.buffer.extend_from_slice(payload);
            state.next_seq = Some(seq.wrapping_add(payload.len() as u32));
        }
    }

    if state.buffer.len() > MAX_STREAM_BUFFER {
        let trim = state.buffer.len() - MAX_STREAM_BUFFER;
        state.buffer.drain(..trim);
    }
}

fn likely_https(src_port: u16, dst_port: u16, message: &TlsMessage, alpn_protocols: &[String]) -> bool {
    if alpn_protocols
        .iter()
        .any(|protocol| matches!(protocol.as_str(), "http/1.1" | "http/1.0" | "h2" | "h2c" | "h3"))
    {
        return true;
    }

    if message
        .server_name
        .as_deref()
        .is_some_and(|server_name| !server_name.is_empty())
        && matches!(message.handshake_type.as_deref(), Some("ClientHello") | Some("ServerHello"))
    {
        return true;
    }

    matches!(src_port, 443 | 8443) || matches!(dst_port, 443 | 8443)
}

#[cfg(test)]
mod tests {
    use crate::model::packet::TlsMessage;

    use super::{TcpFlowObservation, TcpFlowTracker, TlsFlowObservation};

    #[test]
    fn reassembles_http_request_across_segments() {
        let mut tracker = TcpFlowTracker::default();

        assert!(tracker
            .observe_http(TcpFlowObservation {
                src_ip: "10.0.0.2".to_string(),
                dst_ip: "93.184.216.34".to_string(),
                src_port: 51234,
                dst_port: 80,
                seq: 1000,
                fin: false,
                rst: false,
                payload: b"GE",
            })
            .is_none());

        let http = tracker.observe_http(TcpFlowObservation {
            src_ip: "10.0.0.2".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            src_port: 51234,
            dst_port: 80,
            seq: 1002,
            fin: false,
            rst: false,
            payload: b"T / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        });

        assert!(http.is_some());
        assert_eq!(http.expect("expected reassembled http").start_line, "GET / HTTP/1.1");
    }

    #[test]
    fn detects_follow_up_http_request_on_keep_alive_stream() {
        let mut tracker = TcpFlowTracker::default();

        let first = tracker.observe_http(TcpFlowObservation {
            src_ip: "10.0.0.2".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            src_port: 51234,
            dst_port: 80,
            seq: 1000,
            fin: false,
            rst: false,
            payload: b"GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n",
        });

        assert_eq!(
            first.expect("expected first http").start_line,
            "GET /one HTTP/1.1"
        );

        let second = tracker.observe_http(TcpFlowObservation {
            src_ip: "10.0.0.2".to_string(),
            dst_ip: "93.184.216.34".to_string(),
            src_port: 51234,
            dst_port: 80,
            seq: 1041,
            fin: false,
            rst: false,
            payload: b"GET /two HTTP/1.1\r\nHost: example.com\r\n\r\n",
        });

        assert_eq!(
            second.expect("expected second http").start_line,
            "GET /two HTTP/1.1"
        );
    }

    #[test]
    fn classifies_tls_web_flow_as_https() {
        let mut tracker = TcpFlowTracker::default();

        let state = tracker.observe_tls(TlsFlowObservation {
            src_ip: "10.0.0.2".to_string(),
            dst_ip: "39.156.66.10".to_string(),
            src_port: 53124,
            dst_port: 443,
            fin: false,
            rst: false,
            message: &TlsMessage {
                content_type: "Handshake".to_string(),
                version: "TLS 1.3".to_string(),
                record_length: 128,
                handshake_type: Some("ClientHello".to_string()),
                server_name: Some("www.baidu.com".to_string()),
                alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
                cipher_suite: Some("TLS_AES_128_GCM_SHA256".to_string()),
                client_random: Some("001122".to_string()),
                server_random: None,
            },
        });

        assert!(state.is_https);
        assert_eq!(state.server_name.as_deref(), Some("www.baidu.com"));
        assert_eq!(
            state.cipher_suite.as_deref(),
            Some("TLS_AES_128_GCM_SHA256")
        );
    }
}
