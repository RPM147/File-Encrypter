//! Vault Inspect, Integrity Check, and Selective File Extraction tab UI.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use eframe::egui;
use rpm_storage::DEFAULT_PREVIEW_MAX_BYTES;
use zeroize::{Zeroize, Zeroizing};

use crate::i18n::Strings;
use crate::queue::QueuedJobKind;
use crate::state::{AppState, WorkerUpdate};
use crate::worker::VaultDiffTarget;
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

#[allow(clippy::too_many_arguments)]
fn diff_vault_side_ui(
    ui: &mut egui::Ui,
    id_salt: &str,
    vault_label: &str,
    vault_path: &mut String,
    keyfile: &mut Option<PathBuf>,
    use_recovery: &mut bool,
    password: &mut String,
    show_password: &mut bool,
    recovery_phrase: &mut String,
    s: &'static Strings,
) {
    ui.push_id(id_salt, |ui| {
        ui.horizontal(|ui| {
            ui.label(vault_label);
            ui.text_edit_singleline(vault_path);
            if ui.button(s.btn_browse).clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("RPM Vault", &["vault"])
                    .add_filter("All Files", &["*"])
                    .pick_file()
                {
                    *vault_path = p.display().to_string();
                }
            }
        });

        ui.checkbox(use_recovery, s.chk_unlock_rec);
        if *use_recovery {
            ui.add(
                egui::TextEdit::multiline(recovery_phrase)
                    .desired_width(500.0)
                    .desired_rows(2)
                    .font(egui::TextStyle::Monospace),
            );
        } else {
            ui.horizontal(|ui| {
                ui.label(s.lbl_password);
                ui.add(
                    egui::TextEdit::singleline(password)
                        .password(!*show_password)
                        .desired_width(240.0),
                );
                let toggle_lbl = if *show_password {
                    s.btn_hide
                } else {
                    s.btn_show
                };
                if ui.small_button(toggle_lbl).clicked() {
                    *show_password = !*show_password;
                }
            });
            ui.horizontal(|ui| {
                ui.label(s.lbl_keyfile_opt);
                if let Some(ref kf) = *keyfile {
                    ui.label(kf.display().to_string());
                    if ui.small_button(s.btn_clear).clicked() {
                        *keyfile = None;
                    }
                } else if ui.button(s.btn_select_keyfile).clicked() {
                    if let Some(kf) = rfd::FileDialog::new().pick_file() {
                        *keyfile = Some(kf);
                    }
                }
            });
        }
    });
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
                    .add_filter("All Files", &["*"])
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
                state.clear_preview_and_busy();
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

        ui.horizontal_wrapped(|ui| {
            ui.add_enabled_ui(!state.busy, |ui| {
                if ui.button(s.btn_repair).clicked() {
                    let path = PathBuf::from(state.inspect.vault_path.trim());
                    if path.is_file() {
                        cancel.store(false, std::sync::atomic::Ordering::Relaxed);
                        state.busy = true;
                        state.transfer = None;
                        state.set_status(s.repair_running, false);
                        worker::spawn_repair(
                            ctx.clone(),
                            tx.clone(),
                            path,
                            cancel.clone(),
                            state.config.language,
                        );
                    } else {
                        state.set_status(s.err_select_vault, true);
                    }
                }
            });
            if ui.small_button(s.btn_queue_short).clicked() {
                let path = PathBuf::from(state.inspect.vault_path.trim());
                if path.is_file() {
                    state.enqueue_job(QueuedJobKind::Repair { path });
                } else {
                    state.set_status(s.err_select_vault, true);
                }
            }
            ui.add_enabled_ui(!state.busy, |ui| {
                if ui.button(s.btn_integrity_check).clicked() {
                    let p = PathBuf::from(state.inspect.vault_path.trim());
                    if !p.is_file() {
                        state.set_status(s.err_select_vault, true);
                    } else {
                        state.busy = true;
                        state.transfer = None;
                        state.set_status(s.status_checking_integrity, false);
                        worker::spawn_integrity_check(
                            ctx.clone(),
                            tx.clone(),
                            p,
                            state.config.language,
                        );
                    }
                }
            });
            if ui.small_button(s.btn_queue_short).clicked() {
                let path = PathBuf::from(state.inspect.vault_path.trim());
                if path.is_file() {
                    state.enqueue_job(QueuedJobKind::IntegrityCheck { path });
                } else {
                    state.set_status(s.err_select_vault, true);
                }
            }
            ui.add_enabled_ui(!state.busy, |ui| {
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
                    state.transfer = None;
                    state.set_status(s.status_inspecting, false);
                    worker::spawn_inspect(
                        ctx.clone(),
                        tx.clone(),
                        p,
                        state.inspect.use_recovery,
                        Zeroizing::new(sec),
                        state.inspect.keyfile.clone(),
                        state.config.language,
                    );
                }
            });
        });
        ui.add_space(4.0);
        ui.weak(s.ins_actions_note);
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
            ui.weak(s.ins_preview_limits_note);
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

            let mut requested = None;
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
                                let too_large = entry.size > DEFAULT_PREVIEW_MAX_BYTES as u64;
                                let preview_btn = ui.add_enabled(
                                    !state.busy && !too_large,
                                    egui::Button::new(s.btn_preview).small(),
                                );
                                let preview_btn = if too_large {
                                    preview_btn.on_disabled_hover_text(s.preview_too_large_tip)
                                } else {
                                    preview_btn
                                };
                                if preview_btn.clicked() {
                                    requested = Some(entry.path.clone());
                                }
                                ui.label(&entry.path);
                                ui.weak(format!("({})", format_size(entry.size)));
                            });
                        }
                    }
                });

            ui.add_space(6.0);
            if let Some(path) = requested {
                state.inspect.clear_preview();
                let secret = Zeroizing::new(std::mem::take(if state.inspect.use_recovery {
                    &mut state.inspect.recovery_phrase
                } else {
                    &mut state.inspect.password
                }));
                state.inspect.password.zeroize();
                state.inspect.recovery_phrase.zeroize();
                if secret.trim().is_empty() {
                    state.set_status(s.err_enter_pw_or_rec, true);
                } else {
                    let vault_path = state
                        .inspect
                        .manifest_vault
                        .clone()
                        .unwrap_or_else(|| PathBuf::from(state.inspect.vault_path.trim()));
                    let target = VaultDiffTarget {
                        path: vault_path,
                        use_recovery: state.inspect.use_recovery,
                        secret,
                        keyfile: state.inspect.keyfile.clone(),
                    };
                    let (gen, preview_cancel) = state.inspect.begin_preview();
                    state.begin_transfer(s.preview_loading);
                    worker::spawn_preview(
                        ctx.clone(),
                        tx.clone(),
                        preview_cancel,
                        gen,
                        target,
                        path,
                        state.config.language,
                    );
                }
            }
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
                    state.begin_transfer(s.status_extracting_selected);
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
                        state.config.language,
                    );
                }
            });
        });
    }

    ui.add_space(12.0);
    theme::card_frame(ui.visuals()).show(ui, |ui| {
        ui.strong(s.diff_heading);
        ui.weak(s.diff_subtitle);
        ui.add_space(6.0);

        diff_vault_side_ui(
            ui,
            "diff_vault_a",
            s.lbl_vault_a,
            &mut state.diff.vault_a_path,
            &mut state.diff.keyfile_a,
            &mut state.diff.use_recovery_a,
            &mut state.diff.password_a,
            &mut state.diff.show_password_a,
            &mut state.diff.recovery_phrase_a,
            s,
        );

        ui.add_space(6.0);
        ui.separator();
        ui.add_space(6.0);

        diff_vault_side_ui(
            ui,
            "diff_vault_b",
            s.lbl_vault_b,
            &mut state.diff.vault_b_path,
            &mut state.diff.keyfile_b,
            &mut state.diff.use_recovery_b,
            &mut state.diff.password_b,
            &mut state.diff.show_password_b,
            &mut state.diff.recovery_phrase_b,
            s,
        );

        ui.add_space(6.0);
        ui.add_enabled_ui(!state.busy, |ui| {
            if ui
                .add(theme::primary_button(s.btn_compare_vaults, ui.visuals()))
                .clicked()
            {
                let path_a = PathBuf::from(state.diff.vault_a_path.trim());
                let path_b = PathBuf::from(state.diff.vault_b_path.trim());
                if !path_a.is_file() || !path_b.is_file() {
                    state.set_status(s.err_diff_select_vaults, true);
                    return;
                }

                let use_recovery_a = state.diff.use_recovery_a;
                let use_recovery_b = state.diff.use_recovery_b;
                let sec_a = Zeroizing::new(if use_recovery_a {
                    std::mem::take(&mut state.diff.recovery_phrase_a)
                } else {
                    std::mem::take(&mut state.diff.password_a)
                });
                let sec_b = Zeroizing::new(if use_recovery_b {
                    std::mem::take(&mut state.diff.recovery_phrase_b)
                } else {
                    std::mem::take(&mut state.diff.password_b)
                });
                state.clear_diff_secrets();

                if sec_a.trim().is_empty() || sec_b.trim().is_empty() {
                    state.set_status(s.err_diff_enter_creds, true);
                    return;
                }

                let target_a = VaultDiffTarget {
                    path: path_a,
                    use_recovery: use_recovery_a,
                    secret: sec_a,
                    keyfile: (!use_recovery_a)
                        .then(|| state.diff.keyfile_a.clone())
                        .flatten(),
                };
                let target_b = VaultDiffTarget {
                    path: path_b,
                    use_recovery: use_recovery_b,
                    secret: sec_b,
                    keyfile: (!use_recovery_b)
                        .then(|| state.diff.keyfile_b.clone())
                        .flatten(),
                };

                state.busy = true;
                state.transfer = None;
                state.set_status(s.status_comparing_vaults, false);
                worker::spawn_vault_diff(
                    ctx.clone(),
                    tx.clone(),
                    target_a,
                    target_b,
                    state.config.language,
                );
            }
        });

        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .id_salt("inspect_diff_results")
            .max_height(210.0)
            .show(ui, |ui| {
                let mut view = state.diff.results.as_str();
                ui.add(
                    egui::TextEdit::multiline(&mut view)
                        .desired_width(f32::INFINITY)
                        .desired_rows(10)
                        .font(egui::TextStyle::Monospace),
                );
            });
    });
    if let Some(preview) = &mut state.inspect.preview {
        if preview.show(ctx, s) {
            state.inspect.clear_preview();
        }
    }
}
