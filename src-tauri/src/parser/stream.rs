use std::collections::HashMap;

use crate::model::packet::HttpMessage;

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

#[derive(Debug, Default)]
pub struct TcpFlowTracker {
    streams: HashMap<TcpFlowKey, TcpStreamState>,
}

#[derive(Debug, Default)]
struct TcpStreamState {
    next_seq: Option<u32>,
    buffer: Vec<u8>,
    http_detected: bool,
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

        let mut detected = None;
        {
            let state = self.streams.entry(key.clone()).or_default();
            append_payload(state, observation.seq, observation.payload);

            if !state.http_detected {
                if let Some(http) = http::parse(&state.buffer) {
                    state.http_detected = true;
                    detected = Some(http);
                }
            }
        }

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
}

fn append_payload(state: &mut TcpStreamState, seq: u32, payload: &[u8]) {
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
            state.http_detected = false;
            state.buffer.extend_from_slice(payload);
            state.next_seq = Some(seq.wrapping_add(payload.len() as u32));
        }
    }

    if state.buffer.len() > MAX_STREAM_BUFFER {
        let trim = state.buffer.len() - MAX_STREAM_BUFFER;
        state.buffer.drain(..trim);
        state.http_detected = false;
    }
}

#[cfg(test)]
mod tests {
    use super::{TcpFlowObservation, TcpFlowTracker};

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
}
