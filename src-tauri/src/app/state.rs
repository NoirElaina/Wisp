use std::sync::{Arc, Mutex};

use crate::{capture::session::CaptureController, model::session::TlsDecryptionConfig, store::replay::ReplayStore};

pub struct AppState {
    pub capture: Arc<Mutex<CaptureController>>,
    pub store: Arc<Mutex<ReplayStore>>,
    pub tls_decryption: Arc<Mutex<TlsDecryptionConfig>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            capture: Arc::new(Mutex::new(CaptureController::default())),
            store: Arc::new(Mutex::new(ReplayStore::default())),
            tls_decryption: Arc::new(Mutex::new(TlsDecryptionConfig {
                enabled: false,
                keylog_path: None,
                reload_on_change: false,
                strict_secret_match: true,
            })),
        }
    }
}
