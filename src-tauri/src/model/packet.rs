use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketProtocol {
    Ethernet,
    Arp,
    Ipv4,
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
    pub arp: Option<ArpPacket>,
    pub transport: Option<TransportPacket>,
    pub application: Option<ApplicationPacket>,
    pub raw: RawPacketData,
    pub parse_notes: Vec<String>,
    pub is_malformed: bool,
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
pub struct ArpPacket {
    pub opcode: u16,
    pub src_mac: String,
    pub src_ip: String,
    pub dst_mac: String,
    pub dst_ip: String,
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
    Tls(TlsMessage),
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
    pub raw_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsMessage {
    pub content_type: String,
    pub version: String,
    pub record_length: u16,
    pub handshake_type: Option<String>,
    pub server_name: Option<String>,
    pub alpn_protocols: Vec<String>,
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
