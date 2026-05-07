#![allow(dead_code)]

pub const CAPTURE_SESSIONS_SQL: &str = r#"
CREATE TABLE capture_sessions (
  id TEXT PRIMARY KEY,
  name TEXT,
  interface_name TEXT NOT NULL,
  started_at_ms INTEGER NOT NULL,
  ended_at_ms INTEGER,
  packet_count INTEGER NOT NULL DEFAULT 0,
  bytes_captured INTEGER NOT NULL DEFAULT 0
);
"#;

pub const PACKETS_SQL: &str = r#"
CREATE TABLE packets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  frame_no INTEGER NOT NULL,
  ts_unix_ms INTEGER NOT NULL,
  src_ip TEXT,
  dst_ip TEXT,
  src_port INTEGER,
  dst_port INTEGER,
  summary_protocol TEXT NOT NULL,
  summary_info TEXT NOT NULL,
  raw_bytes BLOB NOT NULL
);
"#;
