//! Decrypt tab UI (password or 24-word recovery phrase + optional keyfile).

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use eframe::egui;
use zeroize::Zeroizing;

use crate::state::{AppState, Tab, WorkerUpdate};
use crate::worker;

pub fn ui(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    state: &mut AppState,
    tx: &mpsc::Sender<WorkerUpdate>,
    cancel: &Arc<AtomicBool>,
) {
    ui.heading("Decrypt (.vault v5)");
    ui.add_space(6.0);

    ui.group(|ui| {
        ui.horizontal(|ui| {
            if ui.button("Add .vault Files...").clicked() {
                if let Some(files) = rfd::FileDialog::new()
                    .add_filter("RPM Vault", &["vault"])
                    .pick_files()
                {
                    state.add_dropped_paths(files, Some(Tab::Decrypt));
                }
            }
            if !state.decrypt.vaults.is_empty() && ui.button("Clear").clicked() {
                state.decrypt.vaults.clear();
            }
        });

        let mut remove_idx = None;
        egui::ScrollArea::vertical()
            .id_salt("dec_sources")
            .max_height(130.0)
            .show(ui, |ui| {
                if state.decrypt.vaults.is_empty() {
                    ui.weak("No .vault files selected (or drop .vault files onto window).");
                } else {
                    for (i, path) in state.decrypt.vaults.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(path.display().to_string());
                            if ui.small_button("Remove").clicked() {
                                remove_idx = Some(i);
                            }
                        });
                    }
                }
            });
        if let Some(idx) = remove_idx {
            state.decrypt.vaults.remove(idx);
        }
    });

    ui.add_space(8.0);
    ui.group(|ui| {
        ui.checkbox(
            &mut state.decrypt.use_recovery,
            "Use 24-word recovery phrase instead of password",
        );
        if state.decrypt.use_recovery {
            ui.label("Recovery phrase (24 words):");
            ui.add(
                egui::TextEdit::multiline(&mut state.decrypt.recovery_phrase)
                    .desired_width(480.0)
                    .desired_rows(3),
            );
        } else {
            ui.horizontal(|ui| {
                ui.label("Password:");
                ui.add(
                    egui::TextEdit::singleline(&mut state.decrypt.password)
                        .password(true)
                        .desired_width(280.0),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Keyfile (if bound):");
                if let Some(ref kf) = state.decrypt.keyfile {
                    ui.label(kf.display().to_string());
                    if ui.small_button("Clear").clicked() {
                        state.decrypt.keyfile = None;
                    }
                } else if ui.button("Select Keyfile...").clicked() {
                    if let Some(kf) = rfd::FileDialog::new().pick_file() {
                        state.decrypt.keyfile = Some(kf);
                    }
                }
            });
        }

        ui.horizontal(|ui| {
            ui.label("Output folder:");
            ui.text_edit_singleline(&mut state.decrypt.output_dir);
            if ui.button("Browse...").clicked() {
                if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                    state.decrypt.output_dir = dir.display().to_string();
                }
            }
        });
    });

    ui.add_space(10.0);
    ui.add_enabled_ui(!state.busy, |ui| {
        if ui.button("Decrypt Now").clicked() {
            if state.decrypt.vaults.is_empty() {
                state.set_status("Select one or more .vault files", true);
                return;
            }
            let secret_raw = if state.decrypt.use_recovery {
                std::mem::take(&mut state.decrypt.recovery_phrase)
            } else {
                std::mem::take(&mut state.decrypt.password)
            };
            if secret_raw.trim().is_empty() {
                state.set_status("Enter password or recovery phrase", true);
                return;
            }
            let out_opt = {
                let trimmed = state.decrypt.output_dir.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    let p = PathBuf::from(trimmed);
                    if !p.is_dir() {
                        state.set_status("Output folder does not exist", true);
                        return;
                    }
                    Some(p)
                }
            };

            state.clear_decrypt_secrets();
            cancel.store(false, std::sync::atomic::Ordering::Relaxed);
            state.busy = true;
            state.progress = 0.0;
            state.set_status("Authenticating chunks & streaming output...", false);
            worker::spawn_decrypt(
                ctx.clone(),
                tx.clone(),
                Arc::clone(cancel),
                state.decrypt.vaults.clone(),
                state.decrypt.use_recovery,
                Zeroizing::new(secret_raw),
                state.decrypt.keyfile.clone(),
                out_opt,
            );
        }
    });
}
