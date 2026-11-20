//! Encrypt tab UI + recovery phrase modal confirmation.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use eframe::egui;
use rpm_core::{entropy_to_mnemonic, generate_recovery_entropy};
use zeroize::Zeroizing;

use crate::state::{strength_label_and_color, AppState, RecoveryPrompt, WorkerUpdate};
use crate::worker;

pub fn ui(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    state: &mut AppState,
    tx: &mpsc::Sender<WorkerUpdate>,
    cancel: &Arc<AtomicBool>,
) {
    ui.heading("Encrypt (Vault Format v5 — Chunked AEAD)");
    ui.add_space(6.0);

    ui.group(|ui| {
        ui.label("Sources (or drag and drop files/folders anywhere onto the window):");
        ui.horizontal(|ui| {
            if ui.button("Add Files...").clicked() {
                if let Some(files) = rfd::FileDialog::new().pick_files() {
                    state.add_dropped_paths(files, Some(crate::state::Tab::Encrypt));
                }
            }
            if ui.button("Add Folder...").clicked() {
                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                    state.add_dropped_paths(vec![folder], Some(crate::state::Tab::Encrypt));
                }
            }
            if !state.encrypt.sources.is_empty() && ui.button("Clear List").clicked() {
                state.encrypt.sources.clear();
            }
        });

        let mut remove_idx = None;
        egui::ScrollArea::vertical()
            .id_salt("enc_sources")
            .max_height(140.0)
            .show(ui, |ui| {
                if state.encrypt.sources.is_empty() {
                    ui.weak("No sources selected.");
                } else {
                    for (i, path) in state.encrypt.sources.iter().enumerate() {
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
            state.encrypt.sources.remove(idx);
        }
    });

    ui.add_space(8.0);
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(
                egui::TextEdit::singleline(&mut state.encrypt.password)
                    .password(true)
                    .desired_width(280.0),
            );
            let (label, color) = strength_label_and_color(&state.encrypt.password);
            ui.colored_label(color, format!("Strength: {label}"));
        });
        ui.horizontal(|ui| {
            ui.label("Confirm:  ");
            ui.add(
                egui::TextEdit::singleline(&mut state.encrypt.confirm_password)
                    .password(true)
                    .desired_width(280.0),
            );
        });

        ui.horizontal(|ui| {
            ui.label("Optional Keyfile (2nd factor):");
            if let Some(ref kf) = state.encrypt.keyfile {
                ui.label(kf.display().to_string());
                if ui.small_button("Clear").clicked() {
                    state.encrypt.keyfile = None;
                }
            } else if ui.button("Select Keyfile...").clicked() {
                if let Some(kf) = rfd::FileDialog::new().pick_file() {
                    state.encrypt.keyfile = Some(kf);
                }
            }
        });

        ui.horizontal(|ui| {
            ui.checkbox(&mut state.encrypt.compress, "Compress (gzip)");
            ui.checkbox(
                &mut state.encrypt.secure_wipe,
                "Securely wipe originals after encrypt",
            );
        });

        ui.checkbox(
            &mut state.encrypt.save_next_to_source,
            "Save .vault next to first source",
        );
        if !state.encrypt.save_next_to_source {
            ui.horizontal(|ui| {
                ui.label("Output dir:");
                ui.text_edit_singleline(&mut state.encrypt.output_dir);
                if ui.button("Browse...").clicked() {
                    if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                        state.encrypt.output_dir = dir.display().to_string();
                    }
                }
            });
        }
    });

    ui.add_space(10.0);
    ui.add_enabled_ui(!state.busy, |ui| {
        if ui.button("Encrypt Now").clicked() {
            if state.encrypt.sources.is_empty() {
                state.set_status("Add at least one file or folder", true);
                return;
            }
            if state.encrypt.password.is_empty() {
                state.set_status("Enter a password", true);
                return;
            }
            if state.encrypt.password != state.encrypt.confirm_password {
                state.set_status("Passwords do not match", true);
                return;
            }
            if !state.encrypt.save_next_to_source {
                let p = PathBuf::from(state.encrypt.output_dir.trim());
                if !p.is_dir() {
                    state.set_status("Select a valid output directory", true);
                    return;
                }
            }
            let entropy = generate_recovery_entropy();
            match entropy_to_mnemonic(&entropy) {
                Ok(phrase) => {
                    state.encrypt.recovery_prompt = Some(RecoveryPrompt {
                        phrase: phrase.to_string(),
                        entropy,
                        confirmed: false,
                    });
                }
                Err(e) => state.set_status(e.to_string(), true),
            }
        }
    });

    // Modal recovery phrase confirmation before launching worker thread
    let mut launch = false;
    let mut close_modal = false;
    if let Some(prompt) = state.encrypt.recovery_prompt.as_mut() {
        egui::Window::new("Save 24-Word Recovery Phrase")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("Write down this 24-word emergency recovery phrase. It will NOT be shown again.");
                ui.add_space(6.0);
                ui.add(
                    egui::TextEdit::multiline(&mut prompt.phrase.as_str())
                        .desired_width(480.0)
                        .desired_rows(3)
                        .font(egui::TextStyle::Monospace),
                );
                ui.add_space(6.0);
                ui.checkbox(&mut prompt.confirmed, "I saved my 24-word recovery phrase securely");
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        close_modal = true;
                    }
                    if ui.button("Copy Phrase").clicked() {
                        ctx.copy_text(prompt.phrase.clone());
                    }
                    ui.add_enabled_ui(prompt.confirmed, |ui| {
                        if ui.button("Continue Encrypting").clicked() {
                            launch = true;
                        }
                    });
                });
            });
    }

    if close_modal {
        state.encrypt.recovery_prompt = None;
        state.set_status("Encryption cancelled", false);
    } else if launch {
        if let Some(prompt) = state.encrypt.recovery_prompt.take() {
            let out_dir = if state.encrypt.save_next_to_source {
                None
            } else {
                Some(PathBuf::from(state.encrypt.output_dir.trim()))
            };
            cancel.store(false, std::sync::atomic::Ordering::Relaxed);
            state.busy = true;
            state.progress = 0.0;
            state.set_status("Deriving key (Argon2id) & streaming chunks...", false);
            let pw = Zeroizing::new(std::mem::take(&mut state.encrypt.password));
            state.clear_encrypt_secrets();
            worker::spawn_encrypt(
                ctx.clone(),
                tx.clone(),
                Arc::clone(cancel),
                state.encrypt.sources.clone(),
                pw,
                prompt.entropy.clone(),
                state.encrypt.keyfile.clone(),
                out_dir,
                state.encrypt.compress,
                state.encrypt.secure_wipe,
                state.config.wipe_passes,
                state.config.kdf_params(),
            );
        }
    }
}
