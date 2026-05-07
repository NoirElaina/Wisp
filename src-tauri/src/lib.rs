mod app;
mod capture;
mod filter;
mod model;
mod parser;
mod stats;
mod store;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(app::state::AppState::new())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            app::commands::list_interfaces,
            app::commands::list_sessions,
            app::commands::get_runtime_state,
            app::commands::start_capture,
            app::commands::stop_capture,
            app::commands::query_packets,
            app::commands::get_packet_detail,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
