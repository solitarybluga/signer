#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::start_unseal,
            commands::submit_share,
            commands::get_status,
            commands::seal
        ])
        .run(tauri::generate_context!())
        .expect("error while running the signer desktop client");
}
