use std::sync::{Arc, Mutex};

use crate::{capture::session::CaptureController, store::replay::ReplayStore};

pub struct AppState {
    pub capture: Arc<Mutex<CaptureController>>,
    pub store: Arc<Mutex<ReplayStore>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            capture: Arc::new(Mutex::new(CaptureController::default())),
            store: Arc::new(Mutex::new(ReplayStore::default())),
        }
    }
}
