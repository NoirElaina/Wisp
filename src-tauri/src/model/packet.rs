use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketProtocol {
    Ethernet,
    Arp,
    Ipv4,
    Ipv6,
    Dns,
    Http2,
    Icmp,
    Icmpv6,
    Https,
    Quic,
    Tcp,
    Udp,
    Http,
    Tls,
    Unknown,
}

impl PacketProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ethernet => "ethernet",
            Self::Arp => "arp",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Dns => "dns",
            Self::Http2 => "http2",
            Self::Icmp => "icmp",
            Self::Icmpv6 => "icmpv6",
            Self::Https => "https",
            Self::Quic => "quic",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Http => "http",
            Self::Tls => "tls",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSummary {
    pub id: i64,
    pub session_id: String,
    pub ts_unix_ms: i64,
    pub frame_no: u64,
    pub src: String,
    pub dst: String,
    pub protocol: PacketProtocol,
    pub length: u32,
    pub info: String,
    pub matched: bool,
    pub is_malformed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketPage {
    pub items: Vec<PacketSummary>,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketDetail {
    pub id: i64,
    pub summary: PacketSummary,
    pub ethernet: Option<EthernetFrame>,
    pub ipv4: Option<Ipv4Packet>,
    pub ipv6: Option<Ipv6Packet>,
    pub arp: Option<ArpPacket>,
    pub icmp: Option<IcmpPacket>,
    pub icmpv6: Option<Icmpv6Packet>,
    pub transport: Option<TransportPacket>,
    pub application: Option<ApplicationPacket>,
    pub layers: Vec<ProtocolLayerNode>,
    pub fields: Vec<FieldNode>,
    pub artifacts: Vec<PacketArtifact>,
    pub reassembly_state: Option<ReassemblyState>,
    pub decryption_state: Option<DecryptionState>,
    pub raw: RawPacketData,
    pub parse_notes: Vec<String>,
    pub is_malformed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolLayerNode {
    pub name: String,
    pub filter_key: String,
    pub summary: String,
    pub fields: Vec<FieldNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldNode {
    pub name: String,
    pub filter_key: String,
    pub value: String,
    pub children: Vec<FieldNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketArtifact {
    pub name: String,
    pub content_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReassemblyState {
    pub status: String,
    pub stream_key: String,
    pub buffered_bytes: u32,
    pub missing_ranges: u32,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionState {
    pub attempted: bool,
    pub secrets_loaded: bool,
    pub status: String,
    pub protocol_hint: Option<String>,
    pub note: Option<String>,
    pub keylog_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetFrame {
    pub src_mac: String,
    pub dst_mac: String,
    pub ether_type: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Packet {
    pub version: u8,
    pub header_length: u8,
    pub total_length: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: String,
    pub dst_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Packet {
    pub version: u8,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_ip: String,
    pub dst_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpPacket {
    pub opcode: u16,
    pub src_mac: String,
    pub src_ip: String,
    pub dst_mac: String,
    pub dst_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpPacket {
    pub icmp_type: u8,
    pub code: u8,
    pub identifier: Option<u16>,
    pub sequence: Option<u16>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Icmpv6Packet {
    pub icmp_type: u8,
    pub code: u8,
    pub identifier: Option<u16>,
    pub sequence: Option<u16>,
    pub target_address: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportPacket {
    Tcp(TcpSegment),
    Udp(UdpDatagram),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub header_length: u8,
    pub checksum: u16,
    pub window_size: u16,
    pub flags: TcpFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpDatagram {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationPacket {
    Http(HttpMessage),
    Http2(Http2Message),
    Tls(TlsMessage),
    Dns(DnsMessage),
    Quic(QuicMessage),
    Unknown(UnknownPayload),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpMessage {
    pub is_request: bool,
    pub start_line: String,
    pub headers: Vec<HeaderField>,
    pub body_preview: String,
    pub content_length: Option<u64>,
    pub transfer_encoding_chunked: bool,
    pub consumed_bytes: u32,
    pub raw_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Frame {
    pub frame_type: String,
    pub length: u32,
    pub flags: u8,
    pub stream_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Message {
    pub has_preface: bool,
    pub frames: Vec<Http2Frame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsMessage {
    pub content_type: String,
    pub version: String,
    pub record_length: u16,
    pub handshake_type: Option<String>,
    pub server_name: Option<String>,
    pub alpn_protocols: Vec<String>,
    pub cipher_suite: Option<String>,
    pub client_random: Option<String>,
    pub server_random: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: String,
    pub data: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsMessage {
    pub transaction_id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicMessage {
    pub packet_type: String,
    pub version: String,
    pub dcid: String,
    pub scid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownPayload {
    pub preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPacketData {
    pub captured_len: u32,
    pub original_len: u32,
    pub bytes_hex: String,
    pub ascii_preview: String,
}
