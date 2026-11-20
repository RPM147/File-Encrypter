//! Encrypt tab UI + recovery phrase modal confirmation.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use eframe::egui;
use rpm_core::{entropy_to_mnemonic, generate_recovery_entropy};
use zeroize::Zeroizing;

use crate::state::{strength_label_and_color_for, AppState, RecoveryPrompt, Tab, WorkerUpdate};
use crate::{theme, worker};

pub fn ui(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    state: &mut AppState,
    tx: &mpsc::Sender<WorkerUpdate>,
    cancel: &Arc<AtomicBool>,
) {
    let s = state.strings();
    ui.heading(s.enc_heading);
    ui.add_space(8.0);

    theme::card_frame(ui.visuals()).show(ui, |ui| {
        ui.label(s.enc_sources_hint);
        ui.horizontal(|ui| {
            if ui.button(s.btn_add_files).clicked() {
                if let Some(files) = rfd::FileDialog::new().pick_files() {
                    state.add_dropped_paths(files, Some(Tab::Encrypt));
                }
            }
            if ui.button(s.btn_add_folder).clicked() {
                if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                    state.add_dropped_paths(vec![folder], Some(Tab::Encrypt));
                }
            }
            if !state.encrypt.sources.is_empty() && ui.button(s.btn_clear_list).clicked() {
                state.encrypt.sources.clear();
            }
        });

        let mut remove_idx = None;
        egui::ScrollArea::vertical()
            .id_salt("enc_sources")
            .max_height(140.0)
            .show(ui, |ui| {
                if state.encrypt.sources.is_empty() {
                    ui.weak(s.enc_no_sources);
                } else {
                    for (i, path) in state.encrypt.sources.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(path.display().to_string());
                            if ui.small_button(s.btn_remove).clicked() {
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

    ui.add_space(10.0);
    theme::card_frame(ui.visuals()).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(s.lbl_password);
            ui.add(
                egui::TextEdit::singleline(&mut state.encrypt.password)
                    .password(!state.encrypt.show_password)
                    .desired_width(280.0),
            );
            let toggle_lbl = if state.encrypt.show_password {
                s.btn_hide
            } else {
                s.btn_show
            };
            if ui.small_button(toggle_lbl).clicked() {
                state.encrypt.show_password = !state.encrypt.show_password;
            }
        });

        let (label, frac, color) =
            strength_label_and_color_for(&state.encrypt.password, state.config.language);
        ui.horizontal(|ui| {
            ui.label(s.lbl_strength);
            ui.add(
                egui::ProgressBar::new(frac)
                    .desired_width(180.0)
                    .fill(color),
            );
            ui.colored_label(color, label);
        });

        ui.horizontal(|ui| {
            ui.label(s.lbl_confirm);
            ui.add(
                egui::TextEdit::singleline(&mut state.encrypt.confirm_password)
                    .password(!state.encrypt.show_password)
                    .desired_width(280.0),
            );
        });

        ui.horizontal(|ui| {
            ui.label(s.lbl_keyfile_opt);
            if let Some(ref kf) = state.encrypt.keyfile {
                ui.label(kf.display().to_string());
                if ui.small_button(s.btn_clear).clicked() {
                    state.encrypt.keyfile = None;
                }
            } else if ui.button(s.btn_select_keyfile).clicked() {
                if let Some(kf) = rfd::FileDialog::new().pick_file() {
                    state.encrypt.keyfile = Some(kf);
                }
            }
        });

        ui.horizontal(|ui| {
            ui.checkbox(&mut state.encrypt.compress, s.chk_compress);
            ui.checkbox(&mut state.encrypt.secure_wipe, s.chk_secure_wipe);
        });

        ui.checkbox(
            &mut state.encrypt.save_next_to_source,
            s.chk_save_next_to_source,
        );
        if !state.encrypt.save_next_to_source {
            ui.horizontal(|ui| {
                ui.label(s.lbl_output_dir);
                ui.text_edit_singleline(&mut state.encrypt.output_dir);
                if ui.button(s.btn_browse).clicked() {
                    if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                        state.encrypt.output_dir = dir.display().to_string();
                    }
                }
            });
        }
    });

    ui.add_space(12.0);
    ui.add_enabled_ui(!state.busy, |ui| {
        if ui
            .add(theme::primary_button(s.btn_encrypt_now, ui.visuals()))
            .clicked()
        {
            if state.encrypt.sources.is_empty() {
                state.set_status(s.err_add_source, true);
                return;
            }
            if state.encrypt.password.is_empty() {
                state.set_status(s.err_enter_pw, true);
                return;
            }
            if state.encrypt.password != state.encrypt.confirm_password {
                state.set_status(s.err_pw_mismatch, true);
                return;
            }
            if !state.encrypt.save_next_to_source {
                let p = PathBuf::from(state.encrypt.output_dir.trim());
                if !p.is_dir() {
                    state.set_status(s.err_invalid_out_dir, true);
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
    let mut copy_phrase_now: Option<String> = None;
    if let Some(prompt) = state.encrypt.recovery_prompt.as_mut() {
        egui::Window::new(s.modal_rec_title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(s.modal_rec_body);
                ui.add_space(6.0);
                let mut view = prompt.phrase.as_str();
                ui.add(
                    egui::TextEdit::multiline(&mut view)
                        .desired_width(500.0)
                        .desired_rows(3)
                        .font(egui::TextStyle::Monospace),
                );
                ui.add_space(6.0);
                ui.checkbox(&mut prompt.confirmed, s.modal_rec_confirm);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button(s.btn_cancel).clicked() {
                        close_modal = true;
                    }
                    if ui.button(s.btn_copy_phrase).clicked() {
                        copy_phrase_now = Some(prompt.phrase.clone());
                    }
                    ui.add_enabled_ui(prompt.confirmed, |ui| {
                        if ui
                            .add(theme::primary_button(s.btn_continue_encrypt, ui.visuals()))
                            .clicked()
                        {
                            launch = true;
                        }
                    });
                });
            });
    }

    if let Some(phrase) = copy_phrase_now {
        state.copy_secret_with_autoclear(ctx, phrase, s.status_rec_copied);
    }

    if close_modal {
        state.encrypt.recovery_prompt = None;
        state.set_status(s.status_enc_cancelled, false);
    } else if launch {
        if let Some(prompt) = state.encrypt.recovery_prompt.take() {
            let out_dir = if state.encrypt.save_next_to_source {
                None
            } else {
                Some(PathBuf::from(state.encrypt.output_dir.trim()))
            };
            cancel.store(false, std::sync::atomic::Ordering::Relaxed);
            state.begin_transfer(s.status_enc_running);
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
                state.config.language,
            );
        }
    }
}
