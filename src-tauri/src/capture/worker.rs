use std::{
    sync::{atomic::AtomicBool, Arc, Mutex},
    thread,
};

use tauri::{AppHandle, Emitter};

use crate::{
    app::events,
    capture::{
        session::{CaptureController, RunningCapture},
        source::LiveCaptureSource,
    },
    filter::matcher,
    model::{filter::FilterState, session::CaptureSessionMeta},
    parser,
    stats::bandwidth::StatsAccumulator,
    store::replay::ReplayStore,
};

pub fn spawn(
    app: AppHandle,
    store: Arc<Mutex<ReplayStore>>,
    capture: &mut CaptureController,
    session: CaptureSessionMeta,
    interface_name: String,
    filter: Option<FilterState>,
) -> Result<(), String> {
    let mut source = LiveCaptureSource::open(&interface_name)?;
    let breakloop = source.breakloop_handle();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let thread_stop = stop_flag.clone();
    let thread_store = store.clone();
    let session_id = session.id.clone();

    let handle = thread::Builder::new()
        .name("wisp-live-capture".to_string())
        .spawn(move || {
            let mut frame_no = 1u64;
            let mut stats = StatsAccumulator::new(session_id.clone());

            while !thread_stop.load(std::sync::atomic::Ordering::Relaxed) {
                let raw = match source.next() {
                    Ok(Some(raw)) => raw,
                    Ok(None) => continue,
                    Err(err) => {
                        if !thread_stop.load(std::sync::atomic::Ordering::Relaxed) {
                            let _ = app.emit(events::CAPTURE_ERROR, err);
                        }
                        break;
                    }
                };

                let mut detail = parser::parse_frame(0, session_id.clone(), frame_no, raw);
                detail.summary.matched = matcher::matches_filter(&detail, filter.as_ref());
                stats.record(&detail.summary);

                let summary = {
                    let mut store = match thread_store.lock() {
                        Ok(store) => store,
                        Err(_) => {
                            let _ = app.emit(events::CAPTURE_ERROR, "store lock poisoned");
                            break;
                        }
                    };

                    store.append_packet(&session_id, detail)
                };

                let _ = app.emit(events::CAPTURE_PACKET, summary);
                let _ = app.emit(events::CAPTURE_STATS, stats.snapshot());

                frame_no += 1;
            }
        })
        .map_err(|err| err.to_string())?;

    capture.set_running(RunningCapture {
        session_id: session.id,
        stop_flag,
        breakloop,
        handle: Some(handle),
    });

    Ok(())
}
