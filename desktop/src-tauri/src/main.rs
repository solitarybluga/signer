#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::start_unseal,
            commands::submit_share,
            commands::get_status,
            commands::seal,
            commands::holder_create_identity,
            commands::holder_export_public,
            commands::holder_import_share,
            commands::holder_vault_info,
            commands::holder_submit_from_vault
        ])
        .run(tauri::generate_context!())
        .expect("error while running the signer desktop client");
}
