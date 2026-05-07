use std::collections::BTreeMap;

#[derive(Default)]
pub struct ProtocolCounter {
    counts: BTreeMap<String, (u64, u64)>,
}

impl ProtocolCounter {
    pub fn record(&mut self, protocol: &str, bytes: u64) {
        let entry = self.counts.entry(protocol.to_string()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += bytes;
    }

    pub fn snapshot(&self) -> Vec<(String, u64, u64)> {
        self.counts
            .iter()
            .map(|(protocol, (packets, bytes))| (protocol.clone(), *packets, *bytes))
            .collect()
    }
}
