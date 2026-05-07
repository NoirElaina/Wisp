use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthPoint {
    pub ts_unix_ms: i64,
    pub bytes_per_sec: u64,
    pub packets_per_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolStat {
    pub protocol: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStats {
    pub session_id: String,
    pub packets_total: u64,
    pub bytes_total: u64,
    pub bandwidth: Vec<BandwidthPoint>,
    pub protocols: Vec<ProtocolStat>,
}

impl CaptureStats {
    pub fn idle() -> Self {
        Self {
            session_id: String::new(),
            packets_total: 0,
            bytes_total: 0,
            bandwidth: Vec::new(),
            protocols: Vec::new(),
        }
    }
}
