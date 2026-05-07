use crate::model::session::NetworkInterface;

pub fn list_interfaces() -> Vec<NetworkInterface> {
    match pcap::Device::list() {
        Ok(devices) => devices
            .into_iter()
            .map(|device| NetworkInterface {
                name: device.name,
                description: device
                    .desc
                    .unwrap_or_else(|| "No interface description".to_string()),
                addresses: device
                    .addresses
                    .into_iter()
                    .map(|address| address.addr.to_string())
                    .collect(),
                is_loopback: device.flags.is_loopback(),
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}
