//! Vault Inspect, Integrity Check, and Selective File Extraction tab UI.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use eframe::egui;
use rpm_core::FileManifestEntry;
use rpm_storage::config::AppLanguage;
use rpm_storage::DEFAULT_PREVIEW_MAX_BYTES;
use zeroize::{Zeroize, Zeroizing};

use crate::explorer::{
    build_manifest_tree, category_badge, classify_file_category, file_basename,
    folder_selection_state, set_folder_selection, FileCategory, FileCategoryFilter,
    FolderSelectionState, ManifestTreeNode, ManifestViewMode, SizeFilter,
};
use crate::i18n::Strings;
use crate::progress::format_bytes;
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

fn badge_color(cat: FileCategory, visuals: &egui::Visuals) -> egui::Color32 {
    let dark = visuals.dark_mode;
    match cat {
        FileCategory::Text => {
            if dark {
                egui::Color32::from_rgb(94, 234, 212)
            } else {
                egui::Color32::from_rgb(13, 148, 136)
            }
        }
        FileCategory::Image => {
            if dark {
                egui::Color32::from_rgb(125, 211, 252)
            } else {
                egui::Color32::from_rgb(2, 132, 199)
            }
        }
        FileCategory::Archive => {
            if dark {
                egui::Color32::from_rgb(252, 211, 77)
            } else {
                egui::Color32::from_rgb(180, 83, 9)
            }
        }
        FileCategory::Media => {
            if dark {
                egui::Color32::from_rgb(216, 180, 254)
            } else {
                egui::Color32::from_rgb(126, 34, 206)
            }
        }
        FileCategory::Other => visuals.weak_text_color(),
    }
}

#[allow(clippy::too_many_arguments)]
fn render_manifest_file_row(
    ui: &mut egui::Ui,
    entry: &FileManifestEntry,
    display_name: &str,
    full_path_tooltip: Option<&str>,
    selected_paths: &mut std::collections::HashSet<String>,
    busy: bool,
    requested: &mut Option<String>,
    s: &'static Strings,
) {
    let mut checked = selected_paths.contains(&entry.path);
    ui.horizontal(|ui| {
        if ui.checkbox(&mut checked, "").changed() {
            if checked {
                selected_paths.insert(entry.path.clone());
            } else {
                selected_paths.remove(&entry.path);
            }
        }
        let too_large = entry.size > DEFAULT_PREVIEW_MAX_BYTES as u64;
        let preview_btn = ui.add_enabled(
            !busy && !too_large,
            egui::Button::new(s.btn_preview).small(),
        );
        let preview_btn = if too_large {
            preview_btn.on_disabled_hover_text(s.preview_too_large_tip)
        } else {
            preview_btn
        };
        if preview_btn.clicked() {
            *requested = Some(entry.path.clone());
        }
        let cat = classify_file_category(&entry.path);
        ui.colored_label(
            badge_color(cat, ui.visuals()),
            egui::RichText::new(category_badge(cat)).monospace().small(),
        );
        let lbl_resp = ui.label(display_name);
        if let Some(tip) = full_path_tooltip {
            lbl_resp.on_hover_text(tip);
        }
        ui.weak(format!("({})", format_size(entry.size)));
    });
}

#[allow(clippy::too_many_arguments)]
fn render_manifest_tree_dirs(
    ui: &mut egui::Ui,
    node: &ManifestTreeNode,
    manifest: &[FileManifestEntry],
    selected_paths: &mut std::collections::HashSet<String>,
    busy: bool,
    tree_default_open: bool,
    tree_epoch: u64,
    active_filters: bool,
    requested: &mut Option<String>,
    s: &'static Strings,
) {
    for dir_node in node.dirs.values() {
        let sel_state = folder_selection_state(dir_node, manifest, selected_paths);
        let mut all_checked = sel_state == FolderSelectionState::All;
        let is_partial = sel_state == FolderSelectionState::Partial;

        let id = if active_filters {
            ui.make_persistent_id(("inspect_tree_filtered", &dir_node.full_path))
        } else {
            ui.make_persistent_id(("inspect_tree", tree_epoch, &dir_node.full_path))
        };
        let state = egui::collapsing_header::CollapsingState::load_with_default_open(
            ui.ctx(),
            id,
            active_filters || tree_default_open,
        );
        let header_res = state.show_header(ui, |ui| {
            let chk = ui.add(egui::Checkbox::new(&mut all_checked, "").indeterminate(is_partial));
            if chk.changed() {
                set_folder_selection(dir_node, manifest, selected_paths, all_checked);
            }
            ui.strong(&dir_node.name);
            ui.weak(format!(
                "({}, {})",
                dir_node.total_files,
                format_bytes(dir_node.total_bytes)
            ));
        });
        header_res.body(|ui| {
            render_manifest_tree_dirs(
                ui,
                dir_node,
                manifest,
                selected_paths,
                busy,
                tree_default_open,
                tree_epoch,
                active_filters,
                requested,
                s,
            );
            for &idx in &dir_node.files {
                if let Some(entry) = manifest.get(idx) {
                    render_manifest_file_row(
                        ui,
                        entry,
                        file_basename(&entry.path),
                        Some(entry.path.as_str()),
                        selected_paths,
                        busy,
                        requested,
                        s,
                    );
                }
            }
        });
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
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut state.inspect.filter_query)
                        .hint_text(s.ins_filter_hint)
                        .desired_width(210.0),
                );
                ui.label(s.lbl_filter_type);
                egui::ComboBox::from_id_salt("ins_category_filter")
                    .selected_text(state.inspect.category_filter.localized_label(s))
                    .show_ui(ui, |ui| {
                        for cat in FileCategoryFilter::ALL {
                            ui.selectable_value(
                                &mut state.inspect.category_filter,
                                cat,
                                cat.localized_label(s),
                            );
                        }
                    });
                ui.label(s.lbl_filter_size);
                egui::ComboBox::from_id_salt("ins_size_filter")
                    .selected_text(state.inspect.size_filter.localized_label(s))
                    .show_ui(ui, |ui| {
                        for sz in SizeFilter::ALL {
                            ui.selectable_value(
                                &mut state.inspect.size_filter,
                                sz,
                                sz.localized_label(s),
                            );
                        }
                    });
                ui.selectable_value(
                    &mut state.inspect.view_mode,
                    ManifestViewMode::Tree,
                    s.view_tree,
                );
                ui.selectable_value(
                    &mut state.inspect.view_mode,
                    ManifestViewMode::Flat,
                    s.view_flat,
                );
            });

            let indices = state.inspect.filtered_indices();
            let shown_count = indices.len();
            let total_count = state.inspect.manifest.len();
            let selected_count = state.inspect.selected_paths.len();
            let selected_bytes = state.inspect.selected_total_bytes();
            let has_filters = state.inspect.has_active_filters();

            ui.horizontal_wrapped(|ui| {
                if ui.button(s.btn_select_all).clicked() {
                    state.inspect.select_all_filtered();
                }
                if ui.button(s.btn_clear_selection).clicked() {
                    state.inspect.clear_selection();
                }
                if state.inspect.view_mode == ManifestViewMode::Tree && !has_filters {
                    if ui.small_button(s.btn_expand_all).clicked() {
                        state.inspect.expand_all_tree();
                    }
                    if ui.small_button(s.btn_collapse_all).clicked() {
                        state.inspect.collapse_all_tree();
                    }
                }
                if has_filters && ui.small_button(s.btn_reset_filters).clicked() {
                    state.inspect.reset_filters();
                }
                let summary = match state.config.language {
                    AppLanguage::Tr => format!(
                        "Seçili: {selected_count}/{total_count} ({}) · Gösterilen: {shown_count}/{total_count}",
                        format_bytes(selected_bytes)
                    ),
                    AppLanguage::En => format!(
                        "Selected: {selected_count}/{total_count} ({}) · Showing: {shown_count}/{total_count}",
                        format_bytes(selected_bytes)
                    ),
                };
                ui.weak(summary);
            });

            let mut requested = None;
            egui::ScrollArea::vertical()
                .id_salt("inspect_manifest_list")
                .max_height(260.0)
                .show(ui, |ui| {
                    if indices.is_empty() {
                        ui.weak(s.ins_no_matching_files);
                        return;
                    }
                    match state.inspect.view_mode {
                        ManifestViewMode::Flat => {
                            for idx in indices {
                                if let Some(entry) = state.inspect.manifest.get(idx) {
                                    render_manifest_file_row(
                                        ui,
                                        entry,
                                        &entry.path,
                                        None,
                                        &mut state.inspect.selected_paths,
                                        state.busy,
                                        &mut requested,
                                        s,
                                    );
                                }
                            }
                        }
                        ManifestViewMode::Tree => {
                            let tree = build_manifest_tree(&state.inspect.manifest, &indices);
                            let busy = state.busy;
                            let tree_default_open = state.inspect.tree_default_open;
                            let tree_epoch = state.inspect.tree_id_epoch;
                            render_manifest_tree_dirs(
                                ui,
                                &tree,
                                &state.inspect.manifest,
                                &mut state.inspect.selected_paths,
                                busy,
                                tree_default_open,
                                tree_epoch,
                                has_filters,
                                &mut requested,
                                s,
                            );
                            for &idx in &tree.files {
                                if let Some(entry) = state.inspect.manifest.get(idx) {
                                    render_manifest_file_row(
                                        ui,
                                        entry,
                                        file_basename(&entry.path),
                                        Some(entry.path.as_str()),
                                        &mut state.inspect.selected_paths,
                                        busy,
                                        &mut requested,
                                        s,
                                    );
                                }
                            }
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
