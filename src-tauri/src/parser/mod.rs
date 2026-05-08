pub mod arp;
pub mod conversation;
pub mod cursor;
pub mod decryption;
pub mod dns;
pub mod ethernet;
pub mod http;
pub mod http2;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod quic;
pub mod reassembly;
pub mod runtime;
#[allow(dead_code)]
pub mod stream;
pub mod tcp;
pub mod tls;
pub mod udp;

use crate::model::packet::{
    ApplicationPacket, DecryptionState, DnsMessage, FieldNode, Http2Message, HttpMessage,
    IcmpPacket, Icmpv6Packet, PacketArtifact, PacketDetail, PacketProtocol, PacketSummary,
    ProtocolLayerNode, QuicMessage, RawPacketData, TlsMessage, TransportPacket, UnknownPayload,
};
use crate::model::session::TlsDecryptionConfig;

use self::{
    conversation::{update_tls_conversation, DirectionalFlowKey},
    reassembly::StreamObservation,
    runtime::ParserRuntime,
};

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
    runtime: &mut ParserRuntime,
    tls_config: &TlsDecryptionConfig,
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
        layers: Vec::new(),
        fields: Vec::new(),
        artifacts: Vec::new(),
        reassembly_state: None,
        decryption_state: None,
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
                0x0800 => parse_ipv4(
                    frame.payload,
                    frame_no,
                    &mut summary,
                    &mut detail,
                    runtime,
                    tls_config,
                ),
                0x86dd => parse_ipv6(
                    frame.payload,
                    frame_no,
                    &mut summary,
                    &mut detail,
                    runtime,
                    tls_config,
                ),
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
    hydrate_protocol_tree(&mut detail);
    detail
}

fn parse_ipv4(
    payload: &[u8],
    frame_no: u64,
    summary: &mut PacketSummary,
    detail: &mut PacketDetail,
    runtime: &mut ParserRuntime,
    tls_config: &TlsDecryptionConfig,
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
                6 => parse_tcp(
                    packet.payload,
                    frame_no,
                    &src_ip,
                    &dst_ip,
                    summary,
                    detail,
                    runtime,
                    tls_config,
                ),
                17 => parse_udp(
                    packet.payload,
                    frame_no,
                    &src_ip,
                    &dst_ip,
                    summary,
                    detail,
                    runtime,
                ),
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
    frame_no: u64,
    summary: &mut PacketSummary,
    detail: &mut PacketDetail,
    runtime: &mut ParserRuntime,
    tls_config: &TlsDecryptionConfig,
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
                6 => parse_tcp(
                    packet.payload,
                    frame_no,
                    &src_ip,
                    &dst_ip,
                    summary,
                    detail,
                    runtime,
                    tls_config,
                ),
                17 => parse_udp(
                    packet.payload,
                    frame_no,
                    &src_ip,
                    &dst_ip,
                    summary,
                    detail,
                    runtime,
                ),
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
    frame_no: u64,
    src_ip: &str,
    dst_ip: &str,
    summary: &mut PacketSummary,
    detail: &mut PacketDetail,
    runtime: &mut ParserRuntime,
    tls_config: &TlsDecryptionConfig,
) {
    match tcp::parse(payload) {
        Ok(segment) => {
            summary.protocol = PacketProtocol::Tcp;
            summary.info = format!(
                "TCP {} -> {} Seq={} Ack={}",
                segment.segment.src_port, segment.segment.dst_port, segment.segment.seq, segment.segment.ack
            );

            let transport = segment.segment.clone();

            let directional_key = DirectionalFlowKey::new(
                src_ip,
                transport.src_port,
                dst_ip,
                transport.dst_port,
            );

            if let Some(http2) = http2::parse(segment.payload) {
                apply_http2(http2, summary, detail);
            } else if let Some(http) = http::parse(segment.payload) {
                apply_http(http, summary, detail);
            } else {
                let http_reassembly = runtime.reassembly.reassemble_stream_with_boundary(
                    StreamObservation {
                        key: directional_key.clone(),
                        seq: transport.seq,
                        fin: transport.flags.fin,
                        rst: transport.flags.rst,
                        payload: segment.payload,
                    },
                    http::parse_message,
                );

                if let Some(http) = http_reassembly.messages.first().cloned() {
                    apply_http(http, summary, detail);
                    detail
                        .parse_notes
                        .push("HTTP 通过 TCP 重组识别".to_string());
                    detail.reassembly_state = Some(
                        runtime
                            .reassembly
                            .make_state(&directional_key, &http_reassembly.snapshot),
                    );
                } else {
                    let tls_reassembly = runtime.reassembly.reassemble_by_known_len(
                        StreamObservation {
                            key: directional_key.clone(),
                            seq: transport.seq,
                            fin: transport.flags.fin,
                            rst: transport.flags.rst,
                            payload: segment.payload,
                        },
                        5,
                        tls::record_total_length,
                    );

                    if let Some(record_bytes) = tls_reassembly.messages.first().cloned() {
                        if let Some(tls_message) = tls::parse(&record_bytes) {
                            let (_conversation_key, conversation) = runtime.conversations.tcp_data_mut(
                                src_ip,
                                transport.src_port,
                                dst_ip,
                                transport.dst_port,
                                frame_no,
                            );
                            let flow = update_tls_conversation(conversation, &tls_message);
                            apply_tls(tls_message, flow, summary, detail);
                            detail.reassembly_state = Some(
                                runtime
                                    .reassembly
                                    .make_state(&directional_key, &tls_reassembly.snapshot),
                            );
                            detail.decryption_state = runtime
                                .decryption
                                .inspect_tls(tls_config, &conversation.tls, "record");
                        }
                    } else if let Some(tls_message) = tls::parse(segment.payload) {
                        let (_conversation_key, conversation) = runtime.conversations.tcp_data_mut(
                            src_ip,
                            transport.src_port,
                            dst_ip,
                            transport.dst_port,
                            frame_no,
                        );
                        let flow = update_tls_conversation(conversation, &tls_message);
                        apply_tls(tls_message, flow, summary, detail);
                        detail.decryption_state = runtime
                            .decryption
                            .inspect_tls(tls_config, &conversation.tls, "record");
                    } else if !segment.payload.is_empty() {
                        if let Some(http2) = http2::parse(segment.payload) {
                            apply_http2(http2, summary, detail);
                        } else {
                            detail.application = Some(ApplicationPacket::Unknown(UnknownPayload {
                                preview: bytes_to_ascii(segment.payload),
                            }));
                            detail.reassembly_state = Some(
                                runtime
                                    .reassembly
                                    .make_state(&directional_key, &http_reassembly.snapshot),
                            );
                        }
                    }
                }
            }

            if matches!(detail.application, Some(ApplicationPacket::Tls(_)))
                && detail.decryption_state.is_none()
            {
                detail.decryption_state = Some(DecryptionState {
                    attempted: false,
                    secrets_loaded: false,
                    status: "not_applicable".to_string(),
                    protocol_hint: None,
                    note: Some("当前 TLS 记录尚未建立可用的会话级解密状态".to_string()),
                    keylog_path: tls_config.keylog_path.clone(),
                });
            }

            if detail.application.is_none() && !segment.payload.is_empty() {
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
    frame_no: u64,
    src_ip: &str,
    dst_ip: &str,
    summary: &mut PacketSummary,
    detail: &mut PacketDetail,
    runtime: &mut ParserRuntime,
) {
    match udp::parse(payload) {
        Ok(datagram) => {
            let packet = datagram.packet.clone();
            detail.transport = Some(TransportPacket::Udp(packet.clone()));

            if let Some(quic_message) =
                try_parse_quic(datagram.payload, &packet, src_ip, dst_ip, frame_no, runtime)
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
    flow: conversation::TlsConversationData,
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

fn apply_http2(http2: Http2Message, summary: &mut PacketSummary, detail: &mut PacketDetail) {
    summary.protocol = PacketProtocol::Http2;
    summary.info = if let Some(first_frame) = http2.frames.first() {
        format!("HTTP/2 {} stream={}", first_frame.frame_type, first_frame.stream_id)
    } else if http2.has_preface {
        "HTTP/2 Preface".to_string()
    } else {
        "HTTP/2".to_string()
    };
    detail.application = Some(ApplicationPacket::Http2(http2));
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
    frame_no: u64,
    runtime: &mut ParserRuntime,
) -> Option<QuicMessage> {
    let looks_like_quic = matches!(packet.src_port, 443 | 784 | 853 | 8443)
        || matches!(packet.dst_port, 443 | 784 | 853 | 8443);
    if !looks_like_quic {
        return None;
    }

    let quic = quic::parse(payload)?;
    if quic.packet_type == "Short"
        && !runtime
            .conversations
            .is_known_quic_flow(src_ip, packet.src_port, dst_ip, packet.dst_port)
    {
        return None;
    }

    if quic.packet_type != "Short" {
        runtime
            .conversations
            .remember_quic_flow(src_ip, packet.src_port, dst_ip, packet.dst_port);
    }

    let (_conversation_key, conversation) = runtime
        .conversations
        .udp_data_mut(src_ip, packet.src_port, dst_ip, packet.dst_port, frame_no);
    if conversation.quic.version.is_none() {
        conversation.quic.version = Some(quic.version.clone());
    }
    if conversation.quic.client_dcid.is_none() && !quic.dcid.is_empty() {
        conversation.quic.client_dcid = Some(quic.dcid.clone());
    }
    if conversation.quic.server_scid.is_none() && !quic.scid.is_empty() {
        conversation.quic.server_scid = Some(quic.scid.clone());
    }
    conversation
        .quic
        .packet_types_seen
        .insert(quic.packet_type.clone());

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

fn hydrate_protocol_tree(detail: &mut PacketDetail) {
    let mut layers = Vec::new();

    if let Some(ethernet) = &detail.ethernet {
        layers.push(ProtocolLayerNode {
            name: "Ethernet II".to_string(),
            filter_key: "eth".to_string(),
            summary: format!("{} -> {}", ethernet.src_mac, ethernet.dst_mac),
            fields: vec![
                field("Source", "eth.src", &ethernet.src_mac),
                field("Destination", "eth.dst", &ethernet.dst_mac),
                field("Type", "eth.type", &format!("0x{:04x}", ethernet.ether_type)),
            ],
        });
    }

    if let Some(ipv4) = &detail.ipv4 {
        layers.push(ProtocolLayerNode {
            name: "IPv4".to_string(),
            filter_key: "ip".to_string(),
            summary: format!("{} -> {}", ipv4.src_ip, ipv4.dst_ip),
            fields: vec![
                field("Source", "ip.src", &ipv4.src_ip),
                field("Destination", "ip.dst", &ipv4.dst_ip),
                field("TTL", "ip.ttl", &ipv4.ttl.to_string()),
                field("Protocol", "ip.proto", &ipv4.protocol.to_string()),
                field("Total Length", "ip.len", &ipv4.total_length.to_string()),
            ],
        });
    }

    if let Some(ipv6) = &detail.ipv6 {
        layers.push(ProtocolLayerNode {
            name: "IPv6".to_string(),
            filter_key: "ipv6".to_string(),
            summary: format!("{} -> {}", ipv6.src_ip, ipv6.dst_ip),
            fields: vec![
                field("Source", "ipv6.src", &ipv6.src_ip),
                field("Destination", "ipv6.dst", &ipv6.dst_ip),
                field("Next Header", "ipv6.nxt", &ipv6.next_header.to_string()),
                field("Hop Limit", "ipv6.hlim", &ipv6.hop_limit.to_string()),
            ],
        });
    }

    if let Some(arp) = &detail.arp {
        layers.push(ProtocolLayerNode {
            name: "ARP".to_string(),
            filter_key: "arp".to_string(),
            summary: format!("{} asks for {}", arp.src_ip, arp.dst_ip),
            fields: vec![
                field("Source IP", "arp.src.proto_ipv4", &arp.src_ip),
                field("Target IP", "arp.dst.proto_ipv4", &arp.dst_ip),
                field("Opcode", "arp.opcode", &arp.opcode.to_string()),
            ],
        });
    }

    if let Some(icmp) = &detail.icmp {
        layers.push(ProtocolLayerNode {
            name: "ICMP".to_string(),
            filter_key: "icmp".to_string(),
            summary: icmp.description.clone(),
            fields: vec![
                field("Type", "icmp.type", &icmp.icmp_type.to_string()),
                field("Code", "icmp.code", &icmp.code.to_string()),
            ],
        });
    }

    if let Some(icmpv6) = &detail.icmpv6 {
        layers.push(ProtocolLayerNode {
            name: "ICMPv6".to_string(),
            filter_key: "icmpv6".to_string(),
            summary: icmpv6.description.clone(),
            fields: {
                let mut fields = vec![
                    field("Type", "icmpv6.type", &icmpv6.icmp_type.to_string()),
                    field("Code", "icmpv6.code", &icmpv6.code.to_string()),
                ];
                if let Some(target) = field_opt(
                    "Target",
                    "icmpv6.target_address",
                    icmpv6.target_address.as_deref(),
                ) {
                    fields.push(target);
                }
                fields
            },
        });
    }

    if let Some(transport) = &detail.transport {
        match transport {
            TransportPacket::Tcp(tcp) => layers.push(ProtocolLayerNode {
                name: "TCP".to_string(),
                filter_key: "tcp".to_string(),
                summary: format!("{} -> {}", tcp.src_port, tcp.dst_port),
                fields: vec![
                    field("Source Port", "tcp.srcport", &tcp.src_port.to_string()),
                    field("Destination Port", "tcp.dstport", &tcp.dst_port.to_string()),
                    field("Sequence Number", "tcp.seq", &tcp.seq.to_string()),
                    field("Acknowledgement", "tcp.ack", &tcp.ack.to_string()),
                    field(
                        "Flags",
                        "tcp.flags",
                        &[
                            (tcp.flags.fin, "FIN"),
                            (tcp.flags.syn, "SYN"),
                            (tcp.flags.rst, "RST"),
                            (tcp.flags.psh, "PSH"),
                            (tcp.flags.ack, "ACK"),
                            (tcp.flags.urg, "URG"),
                        ]
                        .into_iter()
                        .filter_map(|(enabled, name)| enabled.then_some(name))
                        .collect::<Vec<_>>()
                        .join(", "),
                    ),
                ],
            }),
            TransportPacket::Udp(udp) => layers.push(ProtocolLayerNode {
                name: "UDP".to_string(),
                filter_key: "udp".to_string(),
                summary: format!("{} -> {}", udp.src_port, udp.dst_port),
                fields: vec![
                    field("Source Port", "udp.srcport", &udp.src_port.to_string()),
                    field("Destination Port", "udp.dstport", &udp.dst_port.to_string()),
                    field("Length", "udp.length", &udp.length.to_string()),
                ],
            }),
        }
    }

    if let Some(application) = &detail.application {
        match application {
            ApplicationPacket::Http(http) => {
                layers.push(ProtocolLayerNode {
                    name: "HTTP/1.x".to_string(),
                    filter_key: "http".to_string(),
                    summary: http.start_line.clone(),
                    fields: vec![
                        field("Start Line", "http.start_line", &http.start_line),
                        field(
                            "Content Length",
                            "http.content_length",
                            &http
                                .content_length
                                .map(|value| value.to_string())
                                .unwrap_or_else(|| "—".to_string()),
                        ),
                        field(
                            "Chunked",
                            "http.transfer_encoding.chunked",
                            if http.transfer_encoding_chunked { "true" } else { "false" },
                        ),
                    ],
                });

                if !http.body_preview.is_empty() {
                    detail.artifacts.push(PacketArtifact {
                        name: "HTTP Body Preview".to_string(),
                        content_type: "text/plain".to_string(),
                        value: http.body_preview.clone(),
                    });
                }
            }
            ApplicationPacket::Http2(http2) => {
                layers.push(ProtocolLayerNode {
                    name: "HTTP/2".to_string(),
                    filter_key: "http2".to_string(),
                    summary: if let Some(first_frame) = http2.frames.first() {
                        format!("{} stream={}", first_frame.frame_type, first_frame.stream_id)
                    } else {
                        "Preface".to_string()
                    },
                    fields: http2
                        .frames
                        .iter()
                        .enumerate()
                        .map(|(index, frame)| FieldNode {
                            name: format!("Frame {}", index + 1),
                            filter_key: format!("http2.frame[{index}]"),
                            value: frame.frame_type.clone(),
                            children: vec![
                                field("Type", "http2.type", &frame.frame_type),
                                field("Length", "http2.length", &frame.length.to_string()),
                                field("Flags", "http2.flags", &format!("0x{:02x}", frame.flags)),
                                field("Stream", "http2.streamid", &frame.stream_id.to_string()),
                            ],
                        })
                        .collect(),
                });
            }
            ApplicationPacket::Tls(tls) => {
                layers.push(ProtocolLayerNode {
                    name: if detail.summary.protocol == PacketProtocol::Https {
                        "TLS / HTTPS"
                    } else {
                        "TLS"
                    }
                    .to_string(),
                    filter_key: "tls".to_string(),
                    summary: detail.summary.info.clone(),
                    fields: vec![
                        field("Record Type", "tls.record.content_type", &tls.content_type),
                        field("Version", "tls.record.version", &tls.version),
                        field(
                            "Handshake Type",
                            "tls.handshake.type",
                            tls.handshake_type.as_deref().unwrap_or("—"),
                        ),
                        field("SNI", "tls.handshake.extensions_server_name", tls.server_name.as_deref().unwrap_or("—")),
                        field("ALPN", "tls.handshake.extensions_alpn", &tls.alpn_protocols.join(",")),
                    ],
                });
            }
            ApplicationPacket::Dns(dns) => {
                layers.push(ProtocolLayerNode {
                    name: "DNS".to_string(),
                    filter_key: "dns".to_string(),
                    summary: dns_info(dns),
                    fields: vec![
                        field("Transaction ID", "dns.id", &format!("0x{:04x}", dns.transaction_id)),
                        field("Direction", "dns.flags.response", if dns.is_response { "response" } else { "query" }),
                        field("Response Code", "dns.flags.rcode", &dns.rcode.to_string()),
                    ],
                });
            }
            ApplicationPacket::Quic(quic) => {
                layers.push(ProtocolLayerNode {
                    name: "QUIC".to_string(),
                    filter_key: "quic".to_string(),
                    summary: format!("{} {}", quic.packet_type, quic.version),
                    fields: vec![
                        field("Packet Type", "quic.packet_type", &quic.packet_type),
                        field("Version", "quic.version", &quic.version),
                        field("DCID", "quic.dcid", &quic.dcid),
                        field("SCID", "quic.scid", &quic.scid),
                    ],
                });
            }
            ApplicationPacket::Unknown(unknown) => {
                if !unknown.preview.is_empty() {
                    detail.artifacts.push(PacketArtifact {
                        name: "Payload Preview".to_string(),
                        content_type: "text/plain".to_string(),
                        value: unknown.preview.clone(),
                    });
                }
            }
        }
    }

    if let Some(reassembly_state) = &detail.reassembly_state {
        detail.artifacts.push(PacketArtifact {
            name: "Reassembly".to_string(),
            content_type: "text/plain".to_string(),
            value: format!(
                "status={} buffered={} missing={} {}",
                reassembly_state.status,
                reassembly_state.buffered_bytes,
                reassembly_state.missing_ranges,
                reassembly_state.note.clone().unwrap_or_default()
            ),
        });
    }

    if let Some(decryption_state) = &detail.decryption_state {
        detail.artifacts.push(PacketArtifact {
            name: "Decryption".to_string(),
            content_type: "text/plain".to_string(),
            value: format!(
                "status={} secrets_loaded={} {}",
                decryption_state.status,
                decryption_state.secrets_loaded,
                decryption_state.note.clone().unwrap_or_default()
            ),
        });
    }

    detail.fields = layers
        .iter()
        .flat_map(|layer| {
            std::iter::once(FieldNode {
                name: layer.name.clone(),
                filter_key: layer.filter_key.clone(),
                value: layer.summary.clone(),
                children: layer.fields.clone(),
            })
        })
        .collect();
    detail.layers = layers;
}

fn field(name: &str, filter_key: &str, value: &str) -> FieldNode {
    FieldNode {
        name: name.to_string(),
        filter_key: filter_key.to_string(),
        value: value.to_string(),
        children: Vec::new(),
    }
}

fn field_opt(name: &str, filter_key: &str, value: Option<&str>) -> Option<FieldNode> {
    value.map(|value| field(name, filter_key, value))
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
