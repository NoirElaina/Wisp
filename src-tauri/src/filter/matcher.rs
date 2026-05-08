use crate::model::{
    filter::FilterState,
    packet::{ApplicationPacket, PacketDetail, PacketSummary, TransportPacket},
};

pub fn matches_filter(detail: &PacketDetail, filter: Option<&FilterState>) -> bool {
    match filter {
        Some(filter) => matches_all(detail, filter),
        None => true,
    }
}

pub fn matches_summary(summary: &PacketSummary, detail: &PacketDetail, filter: &FilterState) -> bool {
    let _ = summary;
    matches_all(detail, filter)
}

fn matches_all(detail: &PacketDetail, filter: &FilterState) -> bool {
    if !filter.protocols.is_empty() {
        let protocol = detail.summary.protocol.as_str();
        if !filter.protocols.iter().any(|item| item.eq_ignore_ascii_case(protocol)) {
            return false;
        }
    }

    if let Some(ip) = filter.ip.as_ref() {
        let ip = ip.trim().to_ascii_lowercase();
        if !ip.is_empty()
            && !detail.summary.src.to_ascii_lowercase().contains(&ip)
            && !detail.summary.dst.to_ascii_lowercase().contains(&ip)
        {
            return false;
        }
    }

    if let Some(port) = filter.port {
        let matched = match detail.transport.as_ref() {
            Some(TransportPacket::Tcp(tcp)) => tcp.src_port == port || tcp.dst_port == port,
            Some(TransportPacket::Udp(udp)) => udp.src_port == port || udp.dst_port == port,
            None => false,
        };

        if !matched {
            return false;
        }
    }

    if filter.only_malformed && !detail.is_malformed {
        return false;
    }

    if let Some(query) = filter.query.as_ref() {
        let needle = query.trim().to_ascii_lowercase();
        if !needle.is_empty() {
            let mut corpus = vec![
                detail.summary.info.to_ascii_lowercase(),
                detail.raw.ascii_preview.to_ascii_lowercase(),
            ];

            append_application_corpus(&mut corpus, detail.application.as_ref());
            append_application_corpus(&mut corpus, detail.decrypted_application.as_ref());

            for artifact in &detail.artifacts {
                corpus.push(artifact.name.to_ascii_lowercase());
                corpus.push(artifact.value.to_ascii_lowercase());
            }

            if let Some(reassembly_state) = detail.reassembly_state.as_ref() {
                corpus.push(reassembly_state.status.to_ascii_lowercase());
                if let Some(note) = &reassembly_state.note {
                    corpus.push(note.to_ascii_lowercase());
                }
            }

            if let Some(decryption_state) = detail.decryption_state.as_ref() {
                corpus.push(decryption_state.status.to_ascii_lowercase());
                if let Some(protocol_hint) = &decryption_state.protocol_hint {
                    corpus.push(protocol_hint.to_ascii_lowercase());
                }
                if let Some(note) = &decryption_state.note {
                    corpus.push(note.to_ascii_lowercase());
                }
                if let Some(keylog_path) = &decryption_state.keylog_path {
                    corpus.push(keylog_path.to_ascii_lowercase());
                }
            }

            if let Some(icmp) = detail.icmp.as_ref() {
                corpus.push(icmp.description.to_ascii_lowercase());
            }

            if let Some(icmpv6) = detail.icmpv6.as_ref() {
                corpus.push(icmpv6.description.to_ascii_lowercase());
                if let Some(target_address) = &icmpv6.target_address {
                    corpus.push(target_address.to_ascii_lowercase());
                }
            }

            if !corpus.into_iter().any(|value| value.contains(&needle)) {
                return false;
            }
        }
    }

    true
}

fn append_application_corpus(corpus: &mut Vec<String>, application: Option<&ApplicationPacket>) {
    match application {
                Some(ApplicationPacket::Http(http)) => {
                    corpus.push(http.start_line.to_ascii_lowercase());
                    corpus.push(http.raw_text.to_ascii_lowercase());
                }
                Some(ApplicationPacket::Http2(http2)) => {
                    corpus.push(if http2.has_preface {
                        "preface".to_string()
                    } else {
                        "frames".to_string()
                    });
                    corpus.extend(http2.frames.iter().flat_map(|frame| {
                        [
                            frame.frame_type.to_ascii_lowercase(),
                            frame.stream_id.to_string(),
                            frame.length.to_string(),
                        ]
                    }));
                }
                Some(ApplicationPacket::Tls(tls)) => {
                    corpus.push(tls.content_type.to_ascii_lowercase());
                    corpus.push(tls.version.to_ascii_lowercase());
                    if let Some(handshake_type) = &tls.handshake_type {
                        corpus.push(handshake_type.to_ascii_lowercase());
                    }
                    if let Some(server_name) = &tls.server_name {
                        corpus.push(server_name.to_ascii_lowercase());
                    }
                    if let Some(cipher_suite) = &tls.cipher_suite {
                        corpus.push(cipher_suite.to_ascii_lowercase());
                    }
                    corpus.extend(
                        tls.alpn_protocols
                            .iter()
                            .map(|protocol| protocol.to_ascii_lowercase()),
                    );
                }
                Some(ApplicationPacket::Dns(dns)) => {
                    corpus.extend(
                        dns.questions
                            .iter()
                            .flat_map(|question| {
                                [question.name.to_ascii_lowercase(), question.qtype.to_ascii_lowercase()]
                            }),
                    );
                    corpus.extend(
                        dns.answers.iter().flat_map(|answer| {
                            [
                                answer.name.to_ascii_lowercase(),
                                answer.rtype.to_ascii_lowercase(),
                                answer.data.to_ascii_lowercase(),
                            ]
                        }),
                    );
                }
                Some(ApplicationPacket::Quic(quic)) => {
                    corpus.push(quic.packet_type.to_ascii_lowercase());
                    corpus.push(quic.version.to_ascii_lowercase());
                    corpus.push(quic.dcid.to_ascii_lowercase());
                    corpus.push(quic.scid.to_ascii_lowercase());
                }
                Some(ApplicationPacket::Unknown(unknown)) => {
                    corpus.push(unknown.preview.to_ascii_lowercase());
                }
                None => {}
            }
}
