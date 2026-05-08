use std::collections::{BTreeMap, HashMap};

use crate::model::packet::ReassemblyState;

use super::conversation::DirectionalFlowKey;

const MAX_STREAM_BUFFER: usize = 256 * 1024;
const MAX_TRACKED_STREAMS: usize = 4096;

#[derive(Debug, Clone)]
pub struct StreamObservation<'a> {
    pub key: DirectionalFlowKey,
    pub seq: u32,
    pub fin: bool,
    pub rst: bool,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Default)]
pub struct ReassemblySnapshot {
    pub buffered_bytes: usize,
    pub missing_ranges: u32,
    pub waiting_for_more: bool,
}

#[derive(Debug, Clone)]
pub struct ReassemblyMessages<T> {
    pub messages: Vec<T>,
    pub snapshot: ReassemblySnapshot,
}

#[derive(Debug, Default)]
pub struct ReassemblyService {
    streams: HashMap<DirectionalFlowKey, StreamState>,
}

#[derive(Debug, Default)]
struct StreamState {
    base_seq: Option<u32>,
    contiguous_end: Option<u32>,
    buffer: Vec<u8>,
    pending: BTreeMap<u32, Vec<u8>>,
}

impl ReassemblyService {
    pub fn reassemble_stream_with_boundary<T, F>(
        &mut self,
        observation: StreamObservation<'_>,
        mut extractor: F,
    ) -> ReassemblyMessages<T>
    where
        F: FnMut(&[u8]) -> Option<(T, usize)>,
    {
        self.prune_if_needed();

        let key = observation.key.clone();
        let (messages, snapshot) = {
            let state = self.streams.entry(key.clone()).or_default();
            state.observe(observation.seq, observation.payload);

            let mut messages = Vec::new();
            while let Some((message, consumed)) = extractor(&state.buffer) {
                if consumed == 0 || consumed > state.buffer.len() {
                    break;
                }
                messages.push(message);
                state.consume(consumed);
            }

            (messages, state.snapshot())
        };

        if observation.fin || observation.rst {
            self.streams.remove(&key);
        }

        ReassemblyMessages { messages, snapshot }
    }

    pub fn reassemble_by_known_len<F>(
        &mut self,
        observation: StreamObservation<'_>,
        min_header_len: usize,
        mut length_fn: F,
    ) -> ReassemblyMessages<Vec<u8>>
    where
        F: FnMut(&[u8]) -> Option<usize>,
    {
        self.prune_if_needed();

        let key = observation.key.clone();
        let (messages, snapshot) = {
            let state = self.streams.entry(key.clone()).or_default();
            state.observe(observation.seq, observation.payload);

            let mut messages = Vec::new();
            loop {
                if state.buffer.len() < min_header_len {
                    break;
                }

                let Some(total_len) = length_fn(&state.buffer) else {
                    break;
                };
                if total_len == 0 || total_len > state.buffer.len() {
                    break;
                }

                messages.push(state.buffer[..total_len].to_vec());
                state.consume(total_len);
            }

            (messages, state.snapshot())
        };

        if observation.fin || observation.rst {
            self.streams.remove(&key);
        }

        ReassemblyMessages { messages, snapshot }
    }

    pub fn make_state(&self, key: &DirectionalFlowKey, snapshot: &ReassemblySnapshot) -> ReassemblyState {
        ReassemblyState {
            status: if snapshot.waiting_for_more {
                "waiting".to_string()
            } else {
                "ready".to_string()
            },
            stream_key: key.display(),
            buffered_bytes: snapshot.buffered_bytes as u32,
            missing_ranges: snapshot.missing_ranges,
            note: if snapshot.waiting_for_more {
                Some("等待更多 TCP 字节完成重组".to_string())
            } else {
                None
            },
        }
    }

    fn prune_if_needed(&mut self) {
        if self.streams.len() <= MAX_TRACKED_STREAMS {
            return;
        }

        self.streams.clear();
    }
}

impl StreamState {
    fn observe(&mut self, seq: u32, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }

        self.pending.entry(seq).or_insert_with(|| payload.to_vec());
        self.base_seq = Some(self.base_seq.map_or(seq, |current| current.min(seq)));
        self.rebuild_buffer();
    }

    fn consume(&mut self, consumed: usize) {
        let Some(base_seq) = self.base_seq else {
            return;
        };
        self.base_seq = Some(base_seq.wrapping_add(consumed as u32));
        self.discard_consumed_segments();
        self.rebuild_buffer();
    }

    fn discard_consumed_segments(&mut self) {
        let Some(base_seq) = self.base_seq else {
            return;
        };

        let keys = self.pending.keys().copied().collect::<Vec<_>>();
        for key in keys {
            let Some(segment) = self.pending.remove(&key) else {
                continue;
            };
            let segment_end = key.wrapping_add(segment.len() as u32);
            if segment_end <= base_seq {
                continue;
            }

            if key < base_seq {
                let overlap = base_seq.saturating_sub(key) as usize;
                if overlap < segment.len() {
                    self.pending.insert(base_seq, segment[overlap..].to_vec());
                }
                continue;
            }

            self.pending.insert(key, segment);
        }
    }

    fn rebuild_buffer(&mut self) {
        self.buffer.clear();
        let Some(base_seq) = self.base_seq else {
            self.contiguous_end = None;
            return;
        };

        let mut cursor = base_seq;
        for (&segment_seq, segment) in &self.pending {
            if segment_seq > cursor {
                break;
            }

            let overlap = cursor.saturating_sub(segment_seq) as usize;
            if overlap >= segment.len() {
                continue;
            }

            self.buffer.extend_from_slice(&segment[overlap..]);
            cursor = segment_seq.wrapping_add(segment.len() as u32);
        }

        self.contiguous_end = Some(cursor);
        if self.buffer.len() > MAX_STREAM_BUFFER {
            let trim = self.buffer.len() - MAX_STREAM_BUFFER;
            self.buffer.drain(..trim);
            self.base_seq = Some(base_seq.wrapping_add(trim as u32));
        }
    }

    fn snapshot(&self) -> ReassemblySnapshot {
        let waiting_for_more = match (self.contiguous_end, self.pending.keys().next_back()) {
            (Some(contiguous_end), Some(last_pending)) => *last_pending > contiguous_end,
            _ => false,
        };

        ReassemblySnapshot {
            buffered_bytes: self.buffer.len(),
            missing_ranges: if waiting_for_more { 1 } else { 0 },
            waiting_for_more,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DirectionalFlowKey, ReassemblyService, StreamObservation};

    fn stream_key() -> DirectionalFlowKey {
        DirectionalFlowKey::new("10.0.0.2", 51234, "93.184.216.34", 80)
    }

    #[test]
    fn buffers_out_of_order_segments_until_gap_is_filled() {
        let mut service = ReassemblyService::default();

        let first = service.reassemble_by_known_len(
            StreamObservation {
                key: stream_key(),
                seq: 1004,
                fin: false,
                rst: false,
                payload: b"/ HTTP/1.1\r\n\r\n",
            },
            4,
            |_| None,
        );

        assert!(first.messages.is_empty());

        let second = service.reassemble_stream_with_boundary(
            StreamObservation {
                key: stream_key(),
                seq: 1000,
                fin: false,
                rst: false,
                payload: b"GET ",
            },
            |buffer| {
                std::str::from_utf8(buffer)
                    .ok()
                    .filter(|text| text.ends_with("\r\n\r\n"))
                    .map(|text| (text.to_string(), buffer.len()))
            },
        );

        assert_eq!(second.messages, vec!["GET / HTTP/1.1\r\n\r\n".to_string()]);
    }
}
