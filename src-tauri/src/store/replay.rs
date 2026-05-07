use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    filter::matcher,
    model::{
        filter::PacketQuery,
        packet::{PacketDetail, PacketPage, PacketSummary},
        session::CaptureSessionMeta,
    },
};

#[derive(Default)]
pub struct ReplayStore {
    sessions: Vec<CaptureSessionMeta>,
    packets: HashMap<String, Vec<PacketDetail>>,
    next_session_seq: u64,
    next_packet_id: i64,
}

impl ReplayStore {
    pub fn create_session(&mut self, interface_name: String) -> CaptureSessionMeta {
        self.next_session_seq += 1;
        let started_at_ms = now_ms();
        let session = CaptureSessionMeta {
            id: format!("session-{}", self.next_session_seq),
            name: format!("{} capture {}", interface_name, self.next_session_seq),
            interface_name,
            started_at_ms,
            ended_at_ms: None,
            packet_count: 0,
            bytes_captured: 0,
            running: true,
        };

        self.sessions.insert(0, session.clone());
        self.packets.insert(session.id.clone(), Vec::new());
        session
    }

    pub fn finish_session(&mut self, session_id: &str) -> Result<CaptureSessionMeta, String> {
        let session = self
            .sessions
            .iter_mut()
            .find(|session| session.id == session_id)
            .ok_or_else(|| "session not found".to_string())?;

        session.ended_at_ms = Some(now_ms());
        session.running = false;
        Ok(session.clone())
    }

    pub fn discard_session(&mut self, session_id: &str) {
        self.sessions.retain(|session| session.id != session_id);
        self.packets.remove(session_id);
    }

    pub fn append_packet(&mut self, session_id: &str, mut detail: PacketDetail) -> PacketSummary {
        self.next_packet_id += 1;
        detail.id = self.next_packet_id;
        detail.summary.id = self.next_packet_id;

        let summary = detail.summary.clone();
        self.packets
            .entry(session_id.to_string())
            .or_default()
            .push(detail);

        if let Some(session) = self.sessions.iter_mut().find(|session| session.id == session_id) {
            session.packet_count += 1;
            session.bytes_captured += summary.length as u64;
        }

        summary
    }

    pub fn list_sessions(&self) -> Vec<CaptureSessionMeta> {
        self.sessions.clone()
    }

    pub fn query_packets(&self, req: &PacketQuery) -> PacketPage {
        let filtered = self
            .packets
            .get(&req.session_id)
            .map(|items| {
                items
                    .iter()
                    .filter(|detail| match req.filter.as_ref() {
                        Some(filter) => matcher::matches_summary(&detail.summary, detail, filter),
                        None => true,
                    })
                    .map(|detail| detail.summary.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let total = filtered.len();
        let items = filtered
            .into_iter()
            .skip(req.offset)
            .take(req.limit)
            .collect::<Vec<_>>();

        PacketPage { items, total }
    }

    pub fn get_packet_detail(&self, session_id: &str, packet_id: i64) -> Option<PacketDetail> {
        self.packets
            .get(session_id)
            .and_then(|items| items.iter().find(|packet| packet.id == packet_id))
            .cloned()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}
