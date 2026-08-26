mod backup;
mod commands;
mod crypto;
mod error;
mod keychain;
mod migration;
mod otp;
mod qr;
mod state;
mod uri;
mod vault;

use state::AppState;
use std::time::Duration;
use tauri::{Manager, WindowEvent};

/// Watchdog that locks the vault after the configured idle period. Runs at 1 Hz
/// and holds the state mutex only long enough to read two fields.
fn spawn_auto_lock(app: tauri::AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(1));

        let state = app.state::<AppState>();
        let should_lock = {
            let inner = state.lock_inner();
            match inner.unlocked.as_ref() {
                Some(unlocked) => {
                    let limit = unlocked.data.settings.auto_lock_seconds;
                    limit > 0 && inner.idle_seconds() >= limit
                }
                None => false,
            }
        };

        if should_lock {
            commands::lock_and_notify(&app, &state);
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            app.manage(AppState::new(dir.join("vault.json")));
            spawn_auto_lock(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window (or quitting) must not leave a decrypted vault
            // sitting in memory if the process lingers.
            if matches!(event, WindowEvent::CloseRequested { .. } | WindowEvent::Destroyed) {
                let app = window.app_handle();
                if let Some(state) = app.try_state::<AppState>() {
                    state.lock_inner().lock();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::create_vault,
            commands::unlock_vault,
            commands::unlock_with_saved_key,
            commands::lock_vault,
            commands::forget_saved_key,
            commands::change_master_password,
            commands::password_strength,
            commands::touch_activity,
            commands::list_accounts,
            commands::generate_codes,
            commands::add_account,
            commands::update_account,
            commands::delete_account,
            commands::reorder_accounts,
            commands::set_favorite,
            commands::advance_counter,
            commands::account_uri,
            commands::preview_uri,
            commands::import_uris,
            commands::preview_migration,
            commands::import_migration,
            commands::scan_qr_file,
            commands::scan_qr_bytes,
            commands::scan_qr_rgba,
            commands::scan_qr_screen,
            commands::export_backup,
            commands::import_backup,
            commands::export_plaintext,
            commands::import_plaintext,
            commands::get_settings,
            commands::update_settings,
            commands::clock_info,
        ])
        .run(tauri::generate_context!())
        .expect("Authom을 시작하지 못했습니다.");
}
