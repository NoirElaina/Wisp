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
        let ip = ip.trim();
        if !ip.is_empty()
            && !detail.summary.src.contains(ip)
            && !detail.summary.dst.contains(ip)
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

            if let Some(ApplicationPacket::Http(http)) = detail.application.as_ref() {
                corpus.push(http.start_line.to_ascii_lowercase());
                corpus.push(http.raw_text.to_ascii_lowercase());
            }

            if !corpus.into_iter().any(|value| value.contains(&needle)) {
                return false;
            }
        }
    }

    true
}
