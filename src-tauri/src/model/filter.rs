use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilterState {
    pub protocols: Vec<String>,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub query: Option<String>,
    pub only_malformed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketQuery {
    pub session_id: String,
    pub filter: Option<FilterState>,
    pub offset: usize,
    pub limit: usize,
}
