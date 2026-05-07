use serde::{Deserialize, Serialize};

use crate::model::filter::FilterState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub description: String,
    pub addresses: Vec<String>,
    pub is_loopback: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSessionMeta {
    pub id: String,
    pub name: String,
    pub interface_name: String,
    pub started_at_ms: i64,
    pub ended_at_ms: Option<i64>,
    pub packet_count: u64,
    pub bytes_captured: u64,
    pub running: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureRuntimeState {
    pub active_session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsDecryptionConfig {
    pub enabled: bool,
    pub keylog_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartCaptureRequest {
    pub interface_name: String,
    pub filter: Option<FilterState>,
}
