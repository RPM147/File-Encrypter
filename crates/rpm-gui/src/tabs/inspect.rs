//! Vault Inspect & Integrity Check tab UI.

use std::path::PathBuf;
use std::sync::mpsc;

use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

use crate::state::{AppState, WorkerUpdate};
use crate::{theme, worker};

pub fn ui(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    state: &mut AppState,
    tx: &mpsc::Sender<WorkerUpdate>,
) {
    let s = state.strings();
    ui.heading(s.ins_heading);
    ui.add_space(8.0);

    theme::card_frame(ui.visuals()).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(s.lbl_vault);
            ui.text_edit_singleline(&mut state.inspect.vault_path);
            if ui.button(s.btn_browse).clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("RPM Vault", &["vault"])
                    .pick_file()
                {
                    state.inspect.vault_path = p.display().to_string();
                }
            }
        });

        ui.checkbox(&mut state.inspect.use_recovery, s.chk_unlock_rec);
        if state.inspect.use_recovery {
            ui.add(
                egui::TextEdit::multiline(&mut state.inspect.recovery_phrase)
                    .desired_width(500.0)
                    .desired_rows(3)
                    .font(egui::TextStyle::Monospace),
            );
        } else {
            ui.horizontal(|ui| {
                ui.label(s.lbl_password);
                ui.add(
                    egui::TextEdit::singleline(&mut state.inspect.password)
                        .password(!state.inspect.show_password)
                        .desired_width(260.0),
                );
                let toggle_lbl = if state.inspect.show_password {
                    s.btn_hide
                } else {
                    s.btn_show
                };
                if ui.small_button(toggle_lbl).clicked() {
                    state.inspect.show_password = !state.inspect.show_password;
                }
            });
            ui.horizontal(|ui| {
                ui.label(s.lbl_keyfile_opt);
                if let Some(ref kf) = state.inspect.keyfile {
                    ui.label(kf.display().to_string());
                    if ui.small_button(s.btn_clear).clicked() {
                        state.inspect.keyfile = None;
                    }
                } else if ui.button(s.btn_select_keyfile).clicked() {
                    if let Some(kf) = rfd::FileDialog::new().pick_file() {
                        state.inspect.keyfile = Some(kf);
                    }
                }
            });
        }

        ui.add_enabled_ui(!state.busy, |ui| {
            ui.horizontal(|ui| {
                if ui.button(s.btn_integrity_check).clicked() {
                    let p = PathBuf::from(state.inspect.vault_path.trim());
                    if !p.is_file() {
                        state.set_status(s.err_select_vault, true);
                    } else {
                        state.busy = true;
                        state.set_status(s.status_checking_integrity, false);
                        worker::spawn_integrity_check(ctx.clone(), tx.clone(), p);
                    }
                }
                if ui
                    .add(theme::primary_button(s.btn_inspect_meta, ui.visuals()))
                    .clicked()
                {
                    let p = PathBuf::from(state.inspect.vault_path.trim());
                    if !p.is_file() {
                        state.set_status(s.err_select_vault, true);
                        return;
                    }
                    let sec = if state.inspect.use_recovery {
                        std::mem::take(&mut state.inspect.recovery_phrase)
                    } else {
                        std::mem::take(&mut state.inspect.password)
                    };
                    state.inspect.password.zeroize();
                    state.inspect.recovery_phrase.zeroize();
                    if sec.trim().is_empty() {
                        state.set_status(s.err_enter_pw_or_rec, true);
                        return;
                    }
                    state.busy = true;
                    state.set_status(s.status_inspecting, false);
                    worker::spawn_inspect(
                        ctx.clone(),
                        tx.clone(),
                        p,
                        state.inspect.use_recovery,
                        Zeroizing::new(sec),
                        state.inspect.keyfile.clone(),
                    );
                }
            });
        });
    });

    ui.add_space(10.0);
    theme::card_frame(ui.visuals()).show(ui, |ui| {
        egui::ScrollArea::vertical()
            .id_salt("inspect_results")
            .max_height(260.0)
            .show(ui, |ui| {
                let mut view = state.inspect.results.as_str();
                ui.add(
                    egui::TextEdit::multiline(&mut view)
                        .desired_width(f32::INFINITY)
                        .desired_rows(14)
                        .font(egui::TextStyle::Monospace),
                );
            });
    });
}
