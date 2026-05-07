pub mod arp;
pub mod cursor;
pub mod ethernet;
pub mod http;
pub mod ipv4;
pub mod stream;
pub mod tcp;
pub mod tls;
pub mod udp;

use crate::model::packet::{
    ApplicationPacket, HttpMessage, PacketDetail, PacketProtocol, PacketSummary, RawPacketData,
    TlsMessage, TransportPacket, UnknownPayload,
};

use self::stream::{TcpFlowObservation, TcpFlowTracker};

pub struct RawFrame {
    pub timestamp_ms: i64,
    pub original_len: u32,
    pub bytes: Vec<u8>,
}

pub fn parse_frame(
    id: i64,
    session_id: String,
    frame_no: u64,
    raw: RawFrame,
    flow_tracker: &mut TcpFlowTracker,
) -> PacketDetail {
    let raw_bytes = raw.bytes;
    let mut summary = PacketSummary {
        id,
        session_id,
        ts_unix_ms: raw.timestamp_ms,
        frame_no,
        src: "unknown".to_string(),
        dst: "unknown".to_string(),
        protocol: PacketProtocol::Unknown,
        length: raw.original_len,
        info: "Unrecognized frame".to_string(),
        matched: true,
        is_malformed: false,
    };

    let mut detail = PacketDetail {
        id,
        summary: summary.clone(),
        ethernet: None,
        ipv4: None,
        arp: None,
        transport: None,
        application: None,
        raw: RawPacketData {
            captured_len: raw_bytes.len() as u32,
            original_len: raw.original_len,
            bytes_hex: bytes_to_hex(&raw_bytes),
            ascii_preview: bytes_to_ascii(&raw_bytes),
        },
        parse_notes: Vec::new(),
        is_malformed: false,
    };

    match ethernet::parse(&raw_bytes) {
        Ok(frame) => {
            summary.src = frame.frame.src_mac.clone();
            summary.dst = frame.frame.dst_mac.clone();
            detail.ethernet = Some(frame.frame.clone());

            match frame.frame.ether_type {
                0x0800 => parse_ipv4(frame.payload, &mut summary, &mut detail, flow_tracker),
                0x0806 => match arp::parse(frame.payload) {
                    Ok(arp) => {
                        summary.protocol = PacketProtocol::Arp;
                        summary.src = arp.src_ip.clone();
                        summary.dst = arp.dst_ip.clone();
                        summary.info = format!("ARP {} asks for {}", arp.src_ip, arp.dst_ip);
                        detail.arp = Some(arp);
                    }
                    Err(err) => {
                        detail.is_malformed = true;
                        detail.parse_notes.push(err);
                    }
                },
                other => {
                    detail
                        .parse_notes
                        .push(format!("unsupported ether type 0x{other:04x}"));
                }
            }
        }
        Err(err) => {
            detail.is_malformed = true;
            detail.parse_notes.push(err);
            detail.application = Some(ApplicationPacket::Unknown(UnknownPayload {
                preview: detail.raw.ascii_preview.clone(),
            }));
        }
    }

    summary.is_malformed = detail.is_malformed;
    detail.summary = summary.clone();
    detail.id = summary.id;
    detail.summary.id = summary.id;
    detail
}

fn parse_ipv4(
    payload: &[u8],
    summary: &mut PacketSummary,
    detail: &mut PacketDetail,
    flow_tracker: &mut TcpFlowTracker,
) {
    match ipv4::parse(payload) {
        Ok(packet) => {
            summary.src = packet.packet.src_ip.clone();
            summary.dst = packet.packet.dst_ip.clone();
            detail.ipv4 = Some(packet.packet.clone());
            let src_ip = packet.packet.src_ip.clone();
            let dst_ip = packet.packet.dst_ip.clone();

            match packet.packet.protocol {
                6 => parse_tcp(packet.payload, &src_ip, &dst_ip, summary, detail, flow_tracker),
                17 => parse_udp(packet.payload, summary, detail),
                protocol => {
                    summary.protocol = PacketProtocol::Ipv4;
                    summary.info = format!("IPv4 protocol {}", protocol);
                    detail
                        .parse_notes
                        .push(format!("unsupported IPv4 protocol {protocol}"));
                }
            }
        }
        Err(err) => {
            detail.is_malformed = true;
            detail.parse_notes.push(err);
        }
    }
}

fn parse_tcp(
    payload: &[u8],
    src_ip: &str,
    dst_ip: &str,
    summary: &mut PacketSummary,
    detail: &mut PacketDetail,
    flow_tracker: &mut TcpFlowTracker,
) {
    match tcp::parse(payload) {
        Ok(segment) => {
            summary.protocol = PacketProtocol::Tcp;
            summary.info = format!(
                "TCP {} -> {} Seq={} Ack={}",
                segment.segment.src_port, segment.segment.dst_port, segment.segment.seq, segment.segment.ack
            );

            let transport = segment.segment.clone();

            if let Some(http) = http::parse(segment.payload) {
                apply_http(http, summary, detail);
            } else if let Some(tls) = tls::parse(segment.payload) {
                apply_tls(tls, summary, detail);
            } else if let Some(http) = flow_tracker.observe_http(TcpFlowObservation {
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                src_port: transport.src_port,
                dst_port: transport.dst_port,
                seq: transport.seq,
                fin: transport.flags.fin,
                rst: transport.flags.rst,
                payload: segment.payload,
            }) {
                apply_http(http, summary, detail);
                detail
                    .parse_notes
                    .push("HTTP 通过 TCP 流重组识别".to_string());
            } else if !segment.payload.is_empty() {
                detail.application = Some(ApplicationPacket::Unknown(UnknownPayload {
                    preview: bytes_to_ascii(segment.payload),
                }));
            }

            detail.transport = Some(TransportPacket::Tcp(transport));
        }
        Err(err) => {
            detail.is_malformed = true;
            detail.parse_notes.push(err);
        }
    }
}

fn parse_udp(payload: &[u8], summary: &mut PacketSummary, detail: &mut PacketDetail) {
    match udp::parse(payload) {
        Ok(datagram) => {
            summary.protocol = PacketProtocol::Udp;
            summary.info = format!(
                "UDP {} -> {} Len={}",
                datagram.packet.src_port, datagram.packet.dst_port, datagram.packet.length
            );
            detail.transport = Some(TransportPacket::Udp(datagram.packet));
            detail.application = Some(ApplicationPacket::Unknown(UnknownPayload {
                preview: bytes_to_ascii(datagram.payload),
            }));
        }
        Err(err) => {
            detail.is_malformed = true;
            detail.parse_notes.push(err);
        }
    }
}

fn apply_http(http: HttpMessage, summary: &mut PacketSummary, detail: &mut PacketDetail) {
    summary.protocol = PacketProtocol::Http;
    summary.info = http.start_line.clone();
    detail.application = Some(ApplicationPacket::Http(http));
}

fn apply_tls(tls: TlsMessage, summary: &mut PacketSummary, detail: &mut PacketDetail) {
    summary.protocol = PacketProtocol::Tls;
    summary.info = match tls.handshake_type.as_deref() {
        Some(kind) => match &tls.server_name {
            Some(server_name) => format!("TLS {kind} {server_name}"),
            None => format!("TLS {kind}"),
        },
        None => format!("TLS {}", tls.content_type),
    };

    detail.application = Some(ApplicationPacket::Tls(tls));
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut lines = Vec::new();

    for (index, chunk) in bytes.chunks(16).enumerate() {
        let offset = index * 16;
        let hex = chunk
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        lines.push(format!("{offset:04x}  {hex}"));
    }

    lines.join("\n")
}

fn bytes_to_ascii(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| match byte {
            32..=126 => char::from(*byte),
            b'\r' => '\r',
            b'\n' => '\n',
            _ => '.',
        })
        .collect()
}
