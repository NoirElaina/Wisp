use std::collections::{BTreeMap, VecDeque};

use crate::model::{
    packet::PacketSummary,
    stats::{BandwidthPoint, CaptureStats, ProtocolStat},
};

use super::protocol::ProtocolCounter;

pub struct StatsAccumulator {
    session_id: String,
    packets_total: u64,
    bytes_total: u64,
    buckets: BTreeMap<i64, (u64, u64)>,
    protocol_counter: ProtocolCounter,
}

impl StatsAccumulator {
    pub fn new(session_id: String) -> Self {
        Self {
            session_id,
            packets_total: 0,
            bytes_total: 0,
            buckets: BTreeMap::new(),
            protocol_counter: ProtocolCounter::default(),
        }
    }

    pub fn record(&mut self, summary: &PacketSummary) {
        self.packets_total += 1;
        self.bytes_total += summary.length as u64;

        let bucket = summary.ts_unix_ms / 1_000;
        let entry = self.buckets.entry(bucket).or_insert((0, 0));
        entry.0 += summary.length as u64;
        entry.1 += 1;

        while self.buckets.len() > 32 {
            if let Some(first) = self.buckets.keys().next().copied() {
                self.buckets.remove(&first);
            }
        }

        self.protocol_counter.record(summary.protocol.as_str(), summary.length as u64);
    }

    pub fn snapshot(&self) -> CaptureStats {
        let mut points = VecDeque::new();
        for (bucket, (bytes, packets)) in &self.buckets {
            points.push_back(BandwidthPoint {
                ts_unix_ms: bucket * 1_000,
                bytes_per_sec: *bytes,
                packets_per_sec: *packets,
            });
        }

        CaptureStats {
            session_id: self.session_id.clone(),
            packets_total: self.packets_total,
            bytes_total: self.bytes_total,
            bandwidth: points.into_iter().collect(),
            protocols: self
                .protocol_counter
                .snapshot()
                .into_iter()
                .map(|(protocol, packets, bytes)| ProtocolStat {
                    protocol,
                    packets,
                    bytes,
                })
                .collect(),
        }
    }
}
