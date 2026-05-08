use tauri::{AppHandle, Emitter, State};

use crate::{
    app::{events, state::AppState},
    capture::{device, session::CaptureController, worker},
    model::{
        filter::PacketQuery,
        packet::{PacketDetail, PacketPage},
        session::{
            CaptureRuntimeState, CaptureSessionMeta, NetworkInterface, StartCaptureRequest,
            TlsDecryptionConfig,
        },
        stats::CaptureStats,
    },
};

#[tauri::command]
pub fn list_interfaces() -> Vec<NetworkInterface> {
    device::list_interfaces()
}

#[tauri::command]
pub fn list_sessions(state: State<'_, AppState>) -> Result<Vec<CaptureSessionMeta>, String> {
    let active_session_id = {
        let capture = state
            .capture
            .lock()
            .map_err(|_| "capture lock poisoned".to_string())?;
        capture.current_session_id().map(str::to_string)
    };

    let store = state.store.lock().map_err(|_| "store lock poisoned".to_string())?;
    let mut sessions = store.list_sessions();
    for session in &mut sessions {
        session.running = active_session_id
            .as_ref()
            .is_some_and(|session_id| session.id == *session_id);
    }

    Ok(sessions)
}

#[tauri::command]
pub fn get_runtime_state(state: State<'_, AppState>) -> Result<CaptureRuntimeState, String> {
    let capture = state
        .capture
        .lock()
        .map_err(|_| "capture lock poisoned".to_string())?;

    Ok(CaptureRuntimeState {
        active_session_id: capture.current_session_id().map(str::to_string),
    })
}

#[tauri::command]
pub fn get_tls_decryption_config(
    state: State<'_, AppState>,
) -> Result<TlsDecryptionConfig, String> {
    let config = state
        .tls_decryption
        .lock()
        .map_err(|_| "tls decryption lock poisoned".to_string())?;
    Ok(config.clone())
}

#[tauri::command]
pub fn set_tls_decryption_config(
    state: State<'_, AppState>,
    config: TlsDecryptionConfig,
) -> Result<TlsDecryptionConfig, String> {
    let mut current = state
        .tls_decryption
        .lock()
        .map_err(|_| "tls decryption lock poisoned".to_string())?;
    *current = config.clone();
    Ok(config)
}

#[tauri::command]
pub fn query_packets(
    state: State<'_, AppState>,
    req: PacketQuery,
) -> Result<PacketPage, String> {
    let store = state.store.lock().map_err(|_| "store lock poisoned".to_string())?;
    Ok(store.query_packets(&req))
}

#[tauri::command]
pub fn get_packet_detail(
    state: State<'_, AppState>,
    session_id: String,
    packet_id: i64,
) -> Result<PacketDetail, String> {
    let store = state.store.lock().map_err(|_| "store lock poisoned".to_string())?;
    store
        .get_packet_detail(&session_id, packet_id)
        .ok_or_else(|| "packet not found".to_string())
}

#[tauri::command]
pub fn start_capture(
    app: AppHandle,
    state: State<'_, AppState>,
    req: StartCaptureRequest,
) -> Result<CaptureSessionMeta, String> {
    let session = {
        let mut capture = state
            .capture
            .lock()
            .map_err(|_| "capture lock poisoned".to_string())?;
        capture.ensure_idle()?;

        let session = {
            let mut store = state.store.lock().map_err(|_| "store lock poisoned".to_string())?;
            store.create_session(req.interface_name.clone())
        };

        if let Err(err) = worker::spawn(
            app.clone(),
            state.store.clone(),
            state.tls_decryption.clone(),
            &mut capture,
            session.clone(),
            req.interface_name.clone(),
            req.filter.clone(),
        ) {
            drop(capture);
            let mut store = state.store.lock().map_err(|_| "store lock poisoned".to_string())?;
            store.discard_session(&session.id);
            return Err(err);
        }

        session
    };

    app.emit(events::CAPTURE_STATE, session.clone())
        .map_err(|err| err.to_string())?;

    Ok(session)
}

#[tauri::command]
pub fn stop_capture(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CaptureSessionMeta, String> {
    let session_id = {
        let mut capture = state
            .capture
            .lock()
            .map_err(|_| "capture lock poisoned".to_string())?;
        capture.stop()?
    };

    let session = {
        let mut store = state.store.lock().map_err(|_| "store lock poisoned".to_string())?;
        store.finish_session(&session_id)?
    };

    app.emit(events::CAPTURE_STATE, session.clone())
        .map_err(|err| err.to_string())?;

    let empty_stats = CaptureStats::idle();
    app.emit(events::CAPTURE_STATS, empty_stats)
        .map_err(|err| err.to_string())?;

    Ok(session)
}

#[allow(dead_code)]
fn _assert_controller_send_sync(_: &CaptureController) {}
