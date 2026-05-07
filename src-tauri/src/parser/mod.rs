pub mod arp;
pub mod cursor;
pub mod dns;
pub mod ethernet;
pub mod http;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod quic;
pub mod stream;
pub mod tcp;
pub mod tls;
pub mod udp;

use crate::model::packet::{
    ApplicationPacket, DnsMessage, HttpMessage, IcmpPacket, Icmpv6Packet, PacketDetail,
    PacketProtocol, PacketSummary, QuicMessage, RawPacketData, TlsMessage, TransportPacket,
    UnknownPayload,
};

use self::stream::{TcpFlowObservation, TcpFlowTracker, TlsFlowObservation};

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
        ipv6: None,
        arp: None,
        icmp: None,
        icmpv6: None,
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
                0x86dd => parse_ipv6(frame.payload, &mut summary, &mut detail, flow_tracker),
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
                1 => parse_icmp(packet.payload, summary, detail),
                6 => parse_tcp(packet.payload, &src_ip, &dst_ip, summary, detail, flow_tracker),
                17 => parse_udp(packet.payload, &src_ip, &dst_ip, summary, detail, flow_tracker),
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

fn parse_ipv6(
    payload: &[u8],
    summary: &mut PacketSummary,
    detail: &mut PacketDetail,
    flow_tracker: &mut TcpFlowTracker,
) {
    match ipv6::parse(payload) {
        Ok(packet) => {
            summary.src = packet.packet.src_ip.clone();
            summary.dst = packet.packet.dst_ip.clone();
            detail.ipv6 = Some(packet.packet.clone());
            let src_ip = packet.packet.src_ip.clone();
            let dst_ip = packet.packet.dst_ip.clone();

            match packet.packet.next_header {
                58 => parse_icmpv6(packet.payload, summary, detail),
                6 => parse_tcp(packet.payload, &src_ip, &dst_ip, summary, detail, flow_tracker),
                17 => parse_udp(packet.payload, &src_ip, &dst_ip, summary, detail, flow_tracker),
                next_header => {
                    summary.protocol = PacketProtocol::Ipv6;
                    summary.info = format!("IPv6 next header {}", next_header);
                    detail
                        .parse_notes
                        .push(format!("unsupported IPv6 next header {next_header}"));
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
                let flow = flow_tracker.observe_tls(TlsFlowObservation {
                    src_ip: src_ip.to_string(),
                    dst_ip: dst_ip.to_string(),
                    src_port: transport.src_port,
                    dst_port: transport.dst_port,
                    fin: transport.flags.fin,
                    rst: transport.flags.rst,
                    message: &tls,
                });
                apply_tls(tls, flow, summary, detail);
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

fn parse_udp(
    payload: &[u8],
    src_ip: &str,
    dst_ip: &str,
    summary: &mut PacketSummary,
    detail: &mut PacketDetail,
    flow_tracker: &mut TcpFlowTracker,
) {
    match udp::parse(payload) {
        Ok(datagram) => {
            let packet = datagram.packet.clone();
            detail.transport = Some(TransportPacket::Udp(packet.clone()));

            if let Some(quic_message) =
                try_parse_quic(datagram.payload, &packet, src_ip, dst_ip, flow_tracker)
            {
                apply_quic(quic_message, summary, detail);
            } else if let Some(dns_message) = try_parse_dns(datagram.payload, &packet) {
                apply_dns(dns_message, summary, detail);
            } else {
                summary.protocol = PacketProtocol::Udp;
                summary.info = format!(
                    "UDP {} -> {} Len={}",
                    packet.src_port, packet.dst_port, packet.length
                );
                detail.application = Some(ApplicationPacket::Unknown(UnknownPayload {
                    preview: bytes_to_ascii(datagram.payload),
                }));
            }
        }
        Err(err) => {
            detail.is_malformed = true;
            detail.parse_notes.push(err);
        }
    }
}

fn parse_icmp(payload: &[u8], summary: &mut PacketSummary, detail: &mut PacketDetail) {
    match icmp::parse(payload) {
        Ok(packet) => {
            summary.protocol = PacketProtocol::Icmp;
            summary.info = icmp_info(&packet);
            detail.icmp = Some(packet);
        }
        Err(err) => {
            detail.is_malformed = true;
            detail.parse_notes.push(err);
        }
    }
}

fn parse_icmpv6(payload: &[u8], summary: &mut PacketSummary, detail: &mut PacketDetail) {
    match icmpv6::parse(payload) {
        Ok(packet) => {
            summary.protocol = PacketProtocol::Icmpv6;
            summary.info = icmpv6_info(&packet);
            detail.icmpv6 = Some(packet);
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

fn apply_tls(
    tls: TlsMessage,
    flow: stream::TlsFlowState,
    summary: &mut PacketSummary,
    detail: &mut PacketDetail,
) {
    summary.protocol = if flow.is_https {
        PacketProtocol::Https
    } else {
        PacketProtocol::Tls
    };

    let label = if flow.is_https { "HTTPS" } else { "TLS" };
    let host = flow.server_name.or_else(|| tls.server_name.clone());
    let alpn = if !flow.alpn_protocols.is_empty() {
        flow.alpn_protocols.join(",")
    } else if !tls.alpn_protocols.is_empty() {
        tls.alpn_protocols.join(",")
    } else {
        String::new()
    };

    summary.info = match tls.handshake_type.as_deref() {
        Some(kind) => match (&host, alpn.is_empty()) {
            (Some(server_name), false) => format!("{label} {kind} {server_name} [{alpn}]"),
            (Some(server_name), true) => format!("{label} {kind} {server_name}"),
            (None, false) => format!("{label} {kind} [{alpn}]"),
            (None, true) => format!("{label} {kind}"),
        },
        None => match (&host, alpn.is_empty()) {
            (Some(server_name), false) => format!("{label} {} {server_name} [{alpn}]", tls.content_type),
            (Some(server_name), true) => format!("{label} {} {server_name}", tls.content_type),
            (None, false) => format!("{label} {} [{alpn}]", tls.content_type),
            (None, true) => format!("{label} {}", tls.content_type),
        },
    };

    detail.application = Some(ApplicationPacket::Tls(tls));
}

fn apply_dns(dns_message: DnsMessage, summary: &mut PacketSummary, detail: &mut PacketDetail) {
    summary.protocol = PacketProtocol::Dns;
    summary.info = dns_info(&dns_message);
    detail.application = Some(ApplicationPacket::Dns(dns_message));
}

fn apply_quic(quic_message: QuicMessage, summary: &mut PacketSummary, detail: &mut PacketDetail) {
    summary.protocol = PacketProtocol::Quic;
    summary.info = format!("QUIC {} {}", quic_message.packet_type, quic_message.version);
    detail.application = Some(ApplicationPacket::Quic(quic_message));
}

fn try_parse_dns(payload: &[u8], packet: &crate::model::packet::UdpDatagram) -> Option<DnsMessage> {
    let looks_like_dns = matches!(packet.src_port, 53 | 5353)
        || matches!(packet.dst_port, 53 | 5353);
    if !looks_like_dns {
        return None;
    }

    dns::parse(payload).ok()
}

fn try_parse_quic(
    payload: &[u8],
    packet: &crate::model::packet::UdpDatagram,
    src_ip: &str,
    dst_ip: &str,
    flow_tracker: &mut TcpFlowTracker,
) -> Option<QuicMessage> {
    let looks_like_quic = matches!(packet.src_port, 443 | 784 | 853 | 8443)
        || matches!(packet.dst_port, 443 | 784 | 853 | 8443);
    if !looks_like_quic {
        return None;
    }

    let quic = quic::parse(payload)?;
    if quic.packet_type == "Short"
        && !flow_tracker.is_known_quic_flow(src_ip, packet.src_port, dst_ip, packet.dst_port)
    {
        return None;
    }

    if quic.packet_type != "Short" {
        flow_tracker.remember_quic_flow(src_ip, packet.src_port, dst_ip, packet.dst_port);
    }

    Some(quic)
}

fn dns_info(message: &DnsMessage) -> String {
    let subject = message
        .questions
        .first()
        .map(|question| format!("{} {}", question.qtype, question.name))
        .unwrap_or_else(|| "Message".to_string());

    if message.is_response {
        if let Some(answer) = message.answers.first() {
            return format!("DNS Response {subject} -> {}", answer.data);
        }

        return format!("DNS Response {subject} RCODE={}", message.rcode);
    }

    format!("DNS Query {subject}")
}

fn icmp_info(packet: &IcmpPacket) -> String {
    match (packet.identifier, packet.sequence) {
        (Some(identifier), Some(sequence)) => format!(
            "ICMP {} id={} seq={}",
            packet.description, identifier, sequence
        ),
        _ => format!("ICMP {}", packet.description),
    }
}

fn icmpv6_info(packet: &Icmpv6Packet) -> String {
    if let Some(target_address) = &packet.target_address {
        return format!("ICMPv6 {} {}", packet.description, target_address);
    }

    match (packet.identifier, packet.sequence) {
        (Some(identifier), Some(sequence)) => format!(
            "ICMPv6 {} id={} seq={}",
            packet.description, identifier, sequence
        ),
        _ => format!("ICMPv6 {}", packet.description),
    }
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
