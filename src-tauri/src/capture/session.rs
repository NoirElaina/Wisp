use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
};

#[derive(Default)]
pub struct CaptureController {
    current: Option<RunningCapture>,
}

pub struct RunningCapture {
    pub session_id: String,
    pub stop_flag: Arc<AtomicBool>,
    pub breakloop: pcap::BreakLoop,
    pub handle: Option<JoinHandle<()>>,
}

impl CaptureController {
    pub fn ensure_idle(&self) -> Result<(), String> {
        if self.current.is_some() {
            return Err("capture is already running".to_string());
        }

        Ok(())
    }

    pub fn set_running(&mut self, running: RunningCapture) {
        self.current = Some(running);
    }

    pub fn stop(&mut self) -> Result<String, String> {
        let mut running = self
            .current
            .take()
            .ok_or_else(|| "capture is not running".to_string())?;

        running.stop_flag.store(true, Ordering::Relaxed);
        running.breakloop.breakloop();

        if let Some(handle) = running.handle.take() {
            let _ = handle.join();
        }

        Ok(running.session_id)
    }
}
