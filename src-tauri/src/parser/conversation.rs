use std::collections::{HashMap, HashSet};

use crate::model::packet::TlsMessage;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BidirectionalFlowKey {
    pub endpoint_a_ip: String,
    pub endpoint_a_port: u16,
    pub endpoint_b_ip: String,
    pub endpoint_b_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DirectionalFlowKey {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEndpoint {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsPeerRole {
    Client,
    Server,
}

#[derive(Debug, Clone, Default)]
pub struct TlsConversationData {
    pub is_https: bool,
    pub server_name: Option<String>,
    pub alpn_protocols: Vec<String>,
    pub cipher_suite: Option<String>,
    pub client_random: Option<String>,
    pub server_random: Option<String>,
    pub decrypted_protocol_hint: Option<String>,
    pub client_endpoint: Option<FlowEndpoint>,
    pub server_endpoint: Option<FlowEndpoint>,
    pub client_handshake_seq: u64,
    pub server_handshake_seq: u64,
    pub client_application_seq: u64,
    pub server_application_seq: u64,
    pub client_decrypted_buffer: Vec<u8>,
    pub server_decrypted_buffer: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct QuicConversationData {
    pub version: Option<String>,
    pub client_dcid: Option<String>,
    pub server_scid: Option<String>,
    pub packet_types_seen: HashSet<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TcpConversationData {
    pub setup_frame: u64,
    pub tls: TlsConversationData,
}

#[derive(Debug, Clone, Default)]
pub struct UdpConversationData {
    pub setup_frame: u64,
    pub quic: QuicConversationData,
}

#[derive(Debug, Default)]
pub struct ConversationStore {
    tcp: HashMap<BidirectionalFlowKey, TcpConversationData>,
    udp: HashMap<BidirectionalFlowKey, UdpConversationData>,
    known_quic_short_flows: HashSet<BidirectionalFlowKey>,
}

impl BidirectionalFlowKey {
    pub fn new(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> Self {
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

impl DirectionalFlowKey {
    pub fn new(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> Self {
        Self {
            src_ip: src_ip.to_string(),
            src_port,
            dst_ip: dst_ip.to_string(),
            dst_port,
        }
    }

    pub fn display(&self) -> String {
        format!(
            "{}:{} -> {}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }
}

impl FlowEndpoint {
    pub fn new(ip: &str, port: u16) -> Self {
        Self {
            ip: ip.to_string(),
            port,
        }
    }

    pub fn matches(&self, ip: &str, port: u16) -> bool {
        self.ip == ip && self.port == port
    }
}

impl ConversationStore {
    pub fn tcp_data_mut(
        &mut self,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        frame_no: u64,
    ) -> (BidirectionalFlowKey, &mut TcpConversationData) {
        let key = BidirectionalFlowKey::new(src_ip, src_port, dst_ip, dst_port);
        let entry = self.tcp.entry(key.clone()).or_insert_with(|| TcpConversationData {
            setup_frame: frame_no,
            ..TcpConversationData::default()
        });
        entry.setup_frame = entry.setup_frame.min(frame_no);
        (key, entry)
    }

    pub fn udp_data_mut(
        &mut self,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        frame_no: u64,
    ) -> (BidirectionalFlowKey, &mut UdpConversationData) {
        let key = BidirectionalFlowKey::new(src_ip, src_port, dst_ip, dst_port);
        let entry = self.udp.entry(key.clone()).or_insert_with(|| UdpConversationData {
            setup_frame: frame_no,
            ..UdpConversationData::default()
        });
        entry.setup_frame = entry.setup_frame.min(frame_no);
        (key, entry)
    }

    pub fn remember_quic_flow(&mut self, src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) {
        self.known_quic_short_flows
            .insert(BidirectionalFlowKey::new(src_ip, src_port, dst_ip, dst_port));
    }

    pub fn is_known_quic_flow(
        &self,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
    ) -> bool {
        self.known_quic_short_flows
            .contains(&BidirectionalFlowKey::new(src_ip, src_port, dst_ip, dst_port))
    }
}

pub fn update_tls_conversation(
    conversation: &mut TcpConversationData,
    message: &TlsMessage,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
) -> TlsConversationData {
    if matches!(message.handshake_type.as_deref(), Some("ClientHello")) {
        conversation.tls.client_endpoint = Some(FlowEndpoint::new(src_ip, src_port));
        if conversation.tls.server_endpoint.is_none() {
            conversation.tls.server_endpoint = Some(FlowEndpoint::new(dst_ip, dst_port));
        }
    }

    if matches!(message.handshake_type.as_deref(), Some("ServerHello")) {
        conversation.tls.server_endpoint = Some(FlowEndpoint::new(src_ip, src_port));
        if conversation.tls.client_endpoint.is_none() {
            conversation.tls.client_endpoint = Some(FlowEndpoint::new(dst_ip, dst_port));
        }
    }

    if let Some(server_name) = &message.server_name {
        conversation.tls.server_name = Some(server_name.clone());
    }

    if !message.alpn_protocols.is_empty() {
        conversation.tls.alpn_protocols = message.alpn_protocols.clone();
    }

    if let Some(cipher_suite) = &message.cipher_suite {
        conversation.tls.cipher_suite = Some(cipher_suite.clone());
    }

    if let Some(client_random) = &message.client_random {
        conversation.tls.client_random = Some(client_random.clone());
    }

    if let Some(server_random) = &message.server_random {
        conversation.tls.server_random = Some(server_random.clone());
    }

    if conversation.tls.decrypted_protocol_hint.is_none() {
        conversation.tls.decrypted_protocol_hint = message
            .alpn_protocols
            .iter()
            .find(|protocol| matches!(protocol.as_str(), "http/1.1" | "h2" | "h3"))
            .cloned();
    }

    if !conversation.tls.is_https {
        conversation.tls.is_https = message
            .alpn_protocols
            .iter()
            .any(|protocol| matches!(protocol.as_str(), "http/1.0" | "http/1.1" | "h2" | "h3"))
            || message
                .server_name
                .as_deref()
                .is_some_and(|server_name| !server_name.is_empty());
    }

    conversation.tls.clone()
}

pub fn tls_role_for_packet(
    conversation: &TlsConversationData,
    src_ip: &str,
    src_port: u16,
) -> Option<TlsPeerRole> {
    if conversation
        .client_endpoint
        .as_ref()
        .is_some_and(|endpoint| endpoint.matches(src_ip, src_port))
    {
        return Some(TlsPeerRole::Client);
    }

    if conversation
        .server_endpoint
        .as_ref()
        .is_some_and(|endpoint| endpoint.matches(src_ip, src_port))
    {
        return Some(TlsPeerRole::Server);
    }

    None
}
