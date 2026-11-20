//! Re-Key tab UI (O(1) password and optional keyfile rotation).

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use eframe::egui;
use zeroize::Zeroizing;

use crate::state::{AppState, WorkerUpdate};
use crate::worker;

pub fn ui(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    state: &mut AppState,
    tx: &mpsc::Sender<WorkerUpdate>,
    cancel: &Arc<AtomicBool>,
) {
    ui.heading("Re-Key (O(1) Key Envelope Rotation)");
    ui.weak("Re-wraps the DEK under a new password/keyfile without decrypting payload chunks.");
    ui.add_space(6.0);

    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label("Vault:");
            ui.text_edit_singleline(&mut state.rekey.vault_path);
            if ui.button("Browse...").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("RPM Vault", &["vault"])
                    .pick_file()
                {
                    state.rekey.vault_path = p.display().to_string();
                }
            }
        });

        ui.horizontal(|ui| {
            ui.label("Current Password:");
            ui.add(
                egui::TextEdit::singleline(&mut state.rekey.current_password)
                    .password(true)
                    .desired_width(250.0),
            );
        });
        ui.horizontal(|ui| {
            ui.label("Current Keyfile: ");
            if let Some(ref kf) = state.rekey.current_keyfile {
                ui.label(kf.display().to_string());
                if ui.small_button("Clear").clicked() {
                    state.rekey.current_keyfile = None;
                }
            } else if ui.button("Select Keyfile...").clicked() {
                if let Some(kf) = rfd::FileDialog::new().pick_file() {
                    state.rekey.current_keyfile = Some(kf);
                }
            }
        });

        ui.separator();
        ui.horizontal(|ui| {
            ui.label("New Password:    ");
            ui.add(
                egui::TextEdit::singleline(&mut state.rekey.new_password)
                    .password(true)
                    .desired_width(250.0),
            );
        });
        ui.horizontal(|ui| {
            ui.label("Confirm New:     ");
            ui.add(
                egui::TextEdit::singleline(&mut state.rekey.confirm_password)
                    .password(true)
                    .desired_width(250.0),
            );
        });

        ui.checkbox(
            &mut state.rekey.keep_same_keyfile,
            "Keep same keyfile binding",
        );
        if !state.rekey.keep_same_keyfile {
            ui.horizontal(|ui| {
                ui.label("New Keyfile (none = remove keyfile requirement):");
                if let Some(ref kf) = state.rekey.new_keyfile {
                    ui.label(kf.display().to_string());
                    if ui.small_button("Clear").clicked() {
                        state.rekey.new_keyfile = None;
                    }
                } else if ui.button("Select New Keyfile...").clicked() {
                    if let Some(kf) = rfd::FileDialog::new().pick_file() {
                        state.rekey.new_keyfile = Some(kf);
                    }
                }
            });
        }
    });

    ui.add_space(10.0);
    ui.add_enabled_ui(!state.busy, |ui| {
        if ui.button("Re-Key Vault").clicked() {
            let p = PathBuf::from(state.rekey.vault_path.trim());
            if !p.is_file() {
                state.set_status("Select an existing .vault file", true);
                return;
            }
            if state.rekey.current_password.is_empty() || state.rekey.new_password.is_empty() {
                state.set_status("Enter both current and new passwords", true);
                return;
            }
            if state.rekey.new_password != state.rekey.confirm_password {
                state.set_status("New passwords do not match", true);
                return;
            }
            let old_pw = Zeroizing::new(std::mem::take(&mut state.rekey.current_password));
            let new_pw = Zeroizing::new(std::mem::take(&mut state.rekey.new_password));
            let new_kf = if state.rekey.keep_same_keyfile {
                state.rekey.current_keyfile.clone()
            } else {
                state.rekey.new_keyfile.clone()
            };
            state.clear_rekey_secrets();
            cancel.store(false, std::sync::atomic::Ordering::Relaxed);
            state.busy = true;
            state.set_status("Re-keying envelope...", false);
            worker::spawn_rekey(
                ctx.clone(),
                tx.clone(),
                Arc::clone(cancel),
                p,
                old_pw,
                new_pw,
                state.rekey.current_keyfile.clone(),
                new_kf,
                state.config.kdf_params(),
            );
        }
    });
}
