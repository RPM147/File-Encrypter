//! Decrypt tab UI (password or 24-word recovery phrase + optional keyfile).

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use eframe::egui;
use zeroize::Zeroizing;

use crate::i18n::Strings;
use crate::queue::QueuedJobKind;
use crate::state::{AppState, Tab, WorkerUpdate};
use crate::{theme, worker};

struct ValidatedDecryptRequest {
    vaults: Vec<PathBuf>,
    use_recovery: bool,
    secret: Zeroizing<String>,
    keyfile: Option<PathBuf>,
    output_dir: Option<PathBuf>,
}

fn take_validated_decrypt_request(
    state: &mut AppState,
    s: &'static Strings,
) -> Option<ValidatedDecryptRequest> {
    if state.decrypt.vaults.is_empty() {
        state.set_status(s.err_select_vaults, true);
        return None;
    }
    let empty_secret = if state.decrypt.use_recovery {
        state.decrypt.recovery_phrase.trim().is_empty()
    } else {
        state.decrypt.password.trim().is_empty()
    };
    if empty_secret {
        state.set_status(s.err_enter_pw_or_rec, true);
        return None;
    }
    let out_opt = {
        let trimmed = state.decrypt.output_dir.trim();
        if trimmed.is_empty() {
            None
        } else {
            let p = PathBuf::from(trimmed);
            if !p.is_dir() {
                state.set_status(s.err_invalid_out_dir, true);
                return None;
            }
            Some(p)
        }
    };
    let secret_raw = if state.decrypt.use_recovery {
        std::mem::take(&mut state.decrypt.recovery_phrase)
    } else {
        std::mem::take(&mut state.decrypt.password)
    };
    let use_recovery = state.decrypt.use_recovery;
    let keyfile = state.decrypt.keyfile.clone();
    let vaults = state.decrypt.vaults.clone();
    state.clear_decrypt_secrets();
    Some(ValidatedDecryptRequest {
        vaults,
        use_recovery,
        secret: Zeroizing::new(secret_raw),
        keyfile,
        output_dir: out_opt,
    })
}

pub fn ui(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    state: &mut AppState,
    tx: &mpsc::Sender<WorkerUpdate>,
    cancel: &Arc<AtomicBool>,
) {
    let s = state.strings();
    ui.heading(s.dec_heading);
    ui.add_space(8.0);

    theme::card_frame(ui.visuals()).show(ui, |ui| {
        ui.horizontal(|ui| {
            if ui.button(s.btn_add_vaults).clicked() {
                if let Some(files) = rfd::FileDialog::new()
                    .add_filter("RPM Vault", &["vault", "001"])
                    .add_filter("All Files", &["*"])
                    .pick_files()
                {
                    state.add_dropped_paths(files, Some(Tab::Decrypt));
                }
            }
            if !state.decrypt.vaults.is_empty() && ui.button(s.btn_clear).clicked() {
                state.decrypt.vaults.clear();
            }
        });

        let mut remove_idx = None;
        egui::ScrollArea::vertical()
            .id_salt("dec_sources")
            .max_height(130.0)
            .show(ui, |ui| {
                if state.decrypt.vaults.is_empty() {
                    ui.weak(s.dec_no_vaults);
                } else {
                    for (i, path) in state.decrypt.vaults.iter().enumerate() {
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
            state.decrypt.vaults.remove(idx);
        }
        ui.add_space(4.0);
        ui.weak(s.dec_stealth_drop_hint);
    });

    ui.add_space(10.0);
    theme::card_frame(ui.visuals()).show(ui, |ui| {
        ui.checkbox(&mut state.decrypt.use_recovery, s.chk_use_recovery);
        if state.decrypt.use_recovery {
            ui.label(s.lbl_rec_phrase);
            ui.add(
                egui::TextEdit::multiline(&mut state.decrypt.recovery_phrase)
                    .desired_width(500.0)
                    .desired_rows(3)
                    .font(egui::TextStyle::Monospace),
            );
            ui.weak(s.dec_recovery_hidden_note);
        } else {
            ui.horizontal(|ui| {
                ui.label(s.lbl_password);
                ui.add(
                    egui::TextEdit::singleline(&mut state.decrypt.password)
                        .password(!state.decrypt.show_password)
                        .desired_width(280.0),
                );
                let toggle_lbl = if state.decrypt.show_password {
                    s.btn_hide
                } else {
                    s.btn_show
                };
                if ui.small_button(toggle_lbl).clicked() {
                    state.decrypt.show_password = !state.decrypt.show_password;
                }
            });
            ui.horizontal(|ui| {
                ui.label(s.lbl_keyfile_if_bound);
                if let Some(ref kf) = state.decrypt.keyfile {
                    ui.label(kf.display().to_string());
                    if ui.small_button(s.btn_clear).clicked() {
                        state.decrypt.keyfile = None;
                    }
                } else if ui.button(s.btn_select_keyfile).clicked() {
                    if let Some(kf) = rfd::FileDialog::new().pick_file() {
                        state.decrypt.keyfile = Some(kf);
                    }
                }
            });
        }

        ui.horizontal(|ui| {
            ui.label(s.lbl_output_folder);
            ui.text_edit_singleline(&mut state.decrypt.output_dir);
            if ui.button(s.btn_browse).clicked() {
                if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                    state.decrypt.output_dir = dir.display().to_string();
                }
            }
        });
    });

    ui.add_space(12.0);
    ui.horizontal(|ui| {
        ui.add_enabled_ui(!state.busy, |ui| {
            if ui
                .add(theme::primary_button(s.btn_decrypt_now, ui.visuals()))
                .clicked()
            {
                if let Some(req) = take_validated_decrypt_request(state, s) {
                    cancel.store(false, std::sync::atomic::Ordering::Relaxed);
                    state.begin_transfer(s.status_dec_running);
                    worker::spawn_decrypt_with_threads(
                        ctx.clone(),
                        tx.clone(),
                        Arc::clone(cancel),
                        req.vaults,
                        req.use_recovery,
                        req.secret,
                        req.keyfile,
                        req.output_dir,
                        usize::from(state.config.pipeline_threads),
                        state.config.language,
                    );
                }
            }
        });
        if ui.button(s.btn_add_to_queue).clicked() {
            if let Some(req) = take_validated_decrypt_request(state, s) {
                state.decrypt.vaults.clear();
                state.enqueue_job(QueuedJobKind::Decrypt {
                    vaults: req.vaults,
                    use_recovery: req.use_recovery,
                    secret: req.secret,
                    keyfile: req.keyfile,
                    output_dir: req.output_dir,
                });
            }
        }
    });
}
