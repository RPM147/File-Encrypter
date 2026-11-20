//! Vault Inspect, Integrity Check, and Selective File Extraction tab UI.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

use crate::state::{AppState, WorkerUpdate};
use crate::{theme, worker};

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", (bytes as f64) / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", (bytes as f64) / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

pub fn ui(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    state: &mut AppState,
    tx: &mpsc::Sender<WorkerUpdate>,
    cancel: &Arc<AtomicBool>,
) {
    let s = state.strings();
    ui.heading(s.ins_heading);
    ui.add_space(8.0);

    theme::card_frame(ui.visuals()).show(ui, |ui| {
        let mut vault_changed = false;
        ui.horizontal(|ui| {
            ui.label(s.lbl_vault);
            if ui
                .text_edit_singleline(&mut state.inspect.vault_path)
                .changed()
            {
                vault_changed = true;
            }
            if ui.button(s.btn_browse).clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("RPM Vault", &["vault"])
                    .pick_file()
                {
                    state.inspect.vault_path = p.display().to_string();
                    vault_changed = true;
                }
            }
        });
        if vault_changed {
            let current = PathBuf::from(state.inspect.vault_path.trim());
            if state.inspect.manifest_vault.as_ref() != Some(&current) {
                state.inspect.reset_manifest();
            }
        }

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
            .max_height(210.0)
            .show(ui, |ui| {
                let mut view = state.inspect.results.as_str();
                ui.add(
                    egui::TextEdit::multiline(&mut view)
                        .desired_width(f32::INFINITY)
                        .desired_rows(11)
                        .font(egui::TextStyle::Monospace),
                );
            });
    });

    if !state.inspect.manifest.is_empty() {
        ui.add_space(10.0);
        theme::card_frame(ui.visuals()).show(ui, |ui| {
            ui.strong(s.ins_selective_heading);
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut state.inspect.filter_query)
                        .hint_text(s.ins_filter_hint)
                        .desired_width(240.0),
                );
                if ui.button(s.btn_select_all).clicked() {
                    state.inspect.select_all_filtered();
                }
                if ui.button(s.btn_clear_selection).clicked() {
                    state.inspect.clear_selection();
                }
                ui.weak(format!(
                    "{}/{}",
                    state.inspect.selected_paths.len(),
                    state.inspect.manifest.len()
                ));
            });

            let indices = state.inspect.filtered_indices();
            egui::ScrollArea::vertical()
                .id_salt("inspect_manifest_list")
                .max_height(200.0)
                .show(ui, |ui| {
                    for idx in indices {
                        if let Some(entry) = state.inspect.manifest.get(idx) {
                            let mut checked = state.inspect.selected_paths.contains(&entry.path);
                            ui.horizontal(|ui| {
                                if ui.checkbox(&mut checked, "").changed() {
                                    if checked {
                                        state.inspect.selected_paths.insert(entry.path.clone());
                                    } else {
                                        state.inspect.selected_paths.remove(&entry.path);
                                    }
                                }
                                ui.label(&entry.path);
                                ui.weak(format!("({})", format_size(entry.size)));
                            });
                        }
                    }
                });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(s.lbl_output_folder);
                ui.text_edit_singleline(&mut state.inspect.extract_output_dir);
                if ui.button(s.btn_browse).clicked() {
                    if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                        state.inspect.extract_output_dir = dir.display().to_string();
                    }
                }
            });

            ui.weak(s.ins_reenter_creds_hint);
            ui.add_space(4.0);

            let can_extract = !state.busy && !state.inspect.selected_paths.is_empty();
            ui.add_enabled_ui(can_extract, |ui| {
                if ui
                    .add(theme::primary_button(s.btn_extract_selected, ui.visuals()))
                    .clicked()
                {
                    let vault = state
                        .inspect
                        .manifest_vault
                        .clone()
                        .unwrap_or_else(|| PathBuf::from(state.inspect.vault_path.trim()));
                    if !vault.is_file() {
                        state.set_status(s.err_select_vault, true);
                        return;
                    }
                    if state.inspect.selected_paths.is_empty() {
                        state.set_status(s.err_select_manifest_files, true);
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
                    let out_opt = {
                        let trimmed = state.inspect.extract_output_dir.trim();
                        if trimmed.is_empty() {
                            None
                        } else {
                            let p = PathBuf::from(trimmed);
                            if !p.is_dir() {
                                state.set_status(s.err_invalid_out_dir, true);
                                return;
                            }
                            Some(p)
                        }
                    };
                    let mut chosen: Vec<String> =
                        state.inspect.selected_paths.iter().cloned().collect();
                    chosen.sort();
                    cancel.store(false, std::sync::atomic::Ordering::Relaxed);
                    state.busy = true;
                    state.progress = 0.0;
                    state.set_status(s.status_extracting_selected, false);
                    worker::spawn_selective_extract(
                        ctx.clone(),
                        tx.clone(),
                        Arc::clone(cancel),
                        vault,
                        state.inspect.use_recovery,
                        Zeroizing::new(sec),
                        state.inspect.keyfile.clone(),
                        chosen,
                        out_opt,
                    );
                }
            });
        });
    }
}
