//! Re-Key tab UI (O(1) password and optional keyfile rotation).

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use eframe::egui;
use zeroize::Zeroizing;

use crate::state::{strength_label_and_color_for, AppState, WorkerUpdate};
use crate::{theme, worker};

pub fn ui(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    state: &mut AppState,
    tx: &mpsc::Sender<WorkerUpdate>,
    cancel: &Arc<AtomicBool>,
) {
    let s = state.strings();
    ui.heading(s.rek_heading);
    ui.weak(s.rek_subtitle);
    ui.add_space(8.0);

    theme::card_frame(ui.visuals()).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(s.lbl_vault);
            ui.text_edit_singleline(&mut state.rekey.vault_path);
            if ui.button(s.btn_browse).clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("RPM Vault", &["vault"])
                    .add_filter("All Files", &["*"])
                    .pick_file()
                {
                    state.rekey.vault_path = p.display().to_string();
                }
            }
        });

        ui.horizontal(|ui| {
            ui.label(s.lbl_current_pw);
            ui.add(
                egui::TextEdit::singleline(&mut state.rekey.current_password)
                    .password(!state.rekey.show_password)
                    .desired_width(250.0),
            );
            let toggle_lbl = if state.rekey.show_password {
                s.btn_hide
            } else {
                s.btn_show
            };
            if ui.small_button(toggle_lbl).clicked() {
                state.rekey.show_password = !state.rekey.show_password;
            }
        });

        ui.horizontal(|ui| {
            ui.label(s.lbl_current_kf);
            if let Some(ref kf) = state.rekey.current_keyfile {
                ui.label(kf.display().to_string());
                if ui.small_button(s.btn_clear).clicked() {
                    state.rekey.current_keyfile = None;
                }
            } else if ui.button(s.btn_select_keyfile).clicked() {
                if let Some(kf) = rfd::FileDialog::new().pick_file() {
                    state.rekey.current_keyfile = Some(kf);
                }
            }
        });

        ui.separator();
        ui.horizontal(|ui| {
            ui.label(s.lbl_new_pw);
            ui.add(
                egui::TextEdit::singleline(&mut state.rekey.new_password)
                    .password(!state.rekey.show_password)
                    .desired_width(250.0),
            );
        });
        let (lbl, frac, color) =
            strength_label_and_color_for(&state.rekey.new_password, state.config.language);
        ui.horizontal(|ui| {
            ui.label(s.lbl_strength);
            ui.add(
                egui::ProgressBar::new(frac)
                    .desired_width(180.0)
                    .fill(color),
            );
            ui.colored_label(color, lbl);
        });

        ui.horizontal(|ui| {
            ui.label(s.lbl_confirm_new);
            ui.add(
                egui::TextEdit::singleline(&mut state.rekey.confirm_password)
                    .password(!state.rekey.show_password)
                    .desired_width(250.0),
            );
        });

        ui.checkbox(&mut state.rekey.keep_same_keyfile, s.chk_keep_same_kf);
        if !state.rekey.keep_same_keyfile {
            ui.horizontal(|ui| {
                ui.label(s.lbl_new_kf_opt);
                if let Some(ref kf) = state.rekey.new_keyfile {
                    ui.label(kf.display().to_string());
                    if ui.small_button(s.btn_clear).clicked() {
                        state.rekey.new_keyfile = None;
                    }
                } else if ui.button(s.btn_select_new_kf).clicked() {
                    if let Some(kf) = rfd::FileDialog::new().pick_file() {
                        state.rekey.new_keyfile = Some(kf);
                    }
                }
            });
        }
    });

    ui.add_space(12.0);
    ui.add_enabled_ui(!state.busy, |ui| {
        if ui
            .add(theme::primary_button(s.btn_rekey_now, ui.visuals()))
            .clicked()
        {
            let p = PathBuf::from(state.rekey.vault_path.trim());
            if !p.is_file() {
                state.set_status(s.err_select_vault, true);
                return;
            }
            if state.rekey.current_password.is_empty() || state.rekey.new_password.is_empty() {
                state.set_status(s.err_enter_both_pw, true);
                return;
            }
            if state.rekey.new_password != state.rekey.confirm_password {
                state.set_status(s.err_new_pw_mismatch, true);
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
            state.transfer = None;
            state.set_status(s.status_rekeying, false);
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
                state.config.language,
            );
        }
    });
}
