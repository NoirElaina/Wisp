use pcap::{Capture, Device, Error};

use crate::parser::RawFrame;

pub struct LiveCaptureSource {
    capture: Capture<pcap::Active>,
}

impl LiveCaptureSource {
    pub fn open(interface_name: &str) -> Result<Self, String> {
        let device = Device::list()
            .map_err(format_pcap_error)?
            .into_iter()
            .find(|device| device.name == interface_name)
            .ok_or_else(|| format!("network interface not found: {interface_name}"))?;

        let capture = Capture::from_device(device)
            .map_err(format_pcap_error)?
            .promisc(true)
            .immediate_mode(true)
            .snaplen(65_535)
            .timeout(250)
            .open()
            .map_err(format_pcap_error)?;

        Ok(Self { capture })
    }

    pub fn breakloop_handle(&mut self) -> pcap::BreakLoop {
        self.capture.breakloop_handle()
    }

    pub fn next(&mut self) -> Result<Option<RawFrame>, String> {
        match self.capture.next_packet() {
            Ok(packet) => {
                let timestamp_ms =
                    packet.header.ts.tv_sec as i64 * 1_000 + (packet.header.ts.tv_usec as i64 / 1_000);

                Ok(Some(RawFrame {
                    timestamp_ms,
                    original_len: packet.header.len,
                    bytes: packet.data.to_vec(),
                }))
            }
            Err(Error::TimeoutExpired) => Ok(None),
            Err(err) => Err(format_pcap_error(err)),
        }
    }
}

fn format_pcap_error(err: Error) -> String {
    err.to_string()
}
