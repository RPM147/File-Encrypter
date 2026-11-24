//! Encrypt tab UI + recovery phrase modal confirmation.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use eframe::egui;
use rpm_core::{entropy_to_mnemonic, generate_recovery_entropy};
use rpm_storage::config::AppLanguage;
use zeroize::Zeroizing;

use crate::estimator::{ContainerFitStatus, SplitEstimateStatus};
use crate::i18n::Strings;
use crate::progress::format_bytes;
use crate::queue::QueuedJobKind;
use crate::state::{
    strength_label_and_color_for, AppState, BuiltinEncryptPreset, ContainerSizeError,
    ContainerSizePreset, RecoveryPrompt, SplitSizeError, SplitSizePreset, Tab, WorkerUpdate,
};
use crate::{theme, worker};

fn container_size_error_msg(err: ContainerSizeError, s: &'static Strings) -> &'static str {
    match err {
        ContainerSizeError::InvalidCustomValue => s.err_container_invalid_mb,
        ContainerSizeError::OutOfRange => s.err_container_out_of_range,
        ContainerSizeError::RequiredForHidden => s.err_hidden_requires_container,
    }
}

fn split_size_error_msg(err: SplitSizeError, s: &'static Strings) -> &'static str {
    match err {
        SplitSizeError::InvalidCustomValue => s.err_split_invalid_mb,
        SplitSizeError::OutOfRange => s.err_split_out_of_range,
    }
}

fn validate_encrypt_inputs(
    state: &AppState,
    s: &'static Strings,
) -> Result<(Option<u64>, Option<u64>), &'static str> {
    if state.encrypt.sources.is_empty() {
        return Err(s.err_add_source);
    }
    if state.encrypt.password.is_empty() {
        return Err(s.err_enter_pw);
    }
    if state.encrypt.password != state.encrypt.confirm_password {
        return Err(s.err_pw_mismatch);
    }
    if !state.encrypt.save_next_to_source {
        let p = PathBuf::from(state.encrypt.output_dir.trim());
        if !p.is_dir() {
            return Err(s.err_invalid_out_dir);
        }
    }
    let container_size = state
        .encrypt
        .resolve_container_size()
        .map_err(|e| container_size_error_msg(e, s))?;
    let split_part_size = state
        .encrypt
        .resolve_split_size()
        .map_err(|e| split_size_error_msg(e, s))?;
    if state.encrypt.enable_hidden {
        if state.encrypt.hidden_sources.is_empty() {
            return Err(s.err_hidden_add_source);
        }
        if state.encrypt.hidden_password.is_empty() {
            return Err(s.err_hidden_enter_pw);
        }
        if state.encrypt.hidden_password != state.encrypt.hidden_confirm_password {
            return Err(s.err_hidden_pw_mismatch);
        }
        if state.encrypt.hidden_password == state.encrypt.password {
            return Err(s.err_hidden_same_pw);
        }
    }
    Ok((container_size, split_part_size))
}

fn render_source_list(
    ui: &mut egui::Ui,
    id_salt: &str,
    max_height: f32,
    paths: &mut Vec<PathBuf>,
    empty_label: &str,
    remove_label: &str,
) {
    let mut remove_idx = None;
    egui::ScrollArea::vertical()
        .id_salt(id_salt)
        .max_height(max_height)
        .show(ui, |ui| {
            if paths.is_empty() {
                ui.weak(empty_label);
            } else {
                for (i, path) in paths.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(path.display().to_string());
                        if ui.small_button(remove_label).clicked() {
                            remove_idx = Some(i);
                        }
                    });
                }
            }
        });
    if let Some(idx) = remove_idx {
        paths.remove(idx);
    }
}

fn open_recovery_prompt(state: &mut AppState, s: &'static Strings, queue_after_confirm: bool) {
    if let Err(err_msg) = validate_encrypt_inputs(state, s) {
        state.set_status(err_msg, true);
        return;
    }
    let entropy = generate_recovery_entropy();
    match entropy_to_mnemonic(&entropy) {
        Ok(phrase) => {
            state.encrypt.recovery_prompt = Some(RecoveryPrompt {
                phrase: phrase.to_string(),
                entropy,
                confirmed: false,
                queue_after_confirm,
            });
        }
        Err(e) => state.set_status(e.to_string(), true),
    }
}

fn format_scan_summary(
    count: u64,
    bytes: u64,
    lang: AppLanguage,
    label_tr: &str,
    label_en: &str,
) -> String {
    match lang {
        AppLanguage::Tr => format!("{label_tr}: {count} dosya ({})", format_bytes(bytes)),
        AppLanguage::En => format!("{label_en}: {count} file(s) ({})", format_bytes(bytes)),
    }
}

fn render_profile_card(ui: &mut egui::Ui, state: &mut AppState, s: &'static Strings) {
    theme::card_frame(ui.visuals()).show(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(s.lbl_profile);
            let selected_text = state
                .encrypt
                .selected_profile_name
                .as_deref()
                .unwrap_or(s.profile_custom_none);
            let mut apply_profile = None;
            egui::ComboBox::from_id_salt("enc_profile_combo")
                .selected_text(selected_text)
                .show_ui(ui, |ui| {
                    for preset in BuiltinEncryptPreset::ALL {
                        let label = preset.localized_label(s);
                        let is_selected =
                            state.encrypt.selected_profile_name.as_deref() == Some(label);
                        if ui.selectable_label(is_selected, label).clicked() {
                            apply_profile = Some(preset.to_profile(s));
                        }
                    }
                    if !state.config.encrypt_profiles.is_empty() {
                        ui.separator();
                        for prof in &state.config.encrypt_profiles {
                            let is_selected = state
                                .encrypt
                                .selected_profile_name
                                .as_deref()
                                .is_some_and(|n| n.eq_ignore_ascii_case(&prof.name));
                            if ui.selectable_label(is_selected, &prof.name).clicked() {
                                apply_profile = Some(prof.clone());
                            }
                        }
                    }
                });
            if let Some(prof) = apply_profile {
                state.apply_encrypt_profile(&prof);
            }

            ui.add(
                egui::TextEdit::singleline(&mut state.encrypt.profile_name_input)
                    .hint_text(s.profile_name_hint)
                    .desired_width(150.0),
            );
            if ui.button(s.btn_save_profile).clicked() {
                let name = state.encrypt.profile_name_input.clone();
                let _ = state.save_current_encrypt_profile(&name);
            }
            let selected_is_user =
                state
                    .encrypt
                    .selected_profile_name
                    .as_deref()
                    .is_some_and(|sel| {
                        state
                            .config
                            .encrypt_profiles
                            .iter()
                            .any(|p| p.name.eq_ignore_ascii_case(sel))
                    });
            if selected_is_user && ui.button(s.btn_delete_profile).clicked() {
                if let Some(name) = state.encrypt.selected_profile_name.clone() {
                    state.delete_encrypt_profile(&name);
                }
            }
        });
        ui.weak(s.profile_note);
    });
}

fn render_preflight_card(ui: &mut egui::Ui, state: &AppState, s: &'static Strings) {
    if state.encrypt.sources.is_empty()
        && !(state.encrypt.enable_hidden && !state.encrypt.hidden_sources.is_empty())
    {
        return;
    }
    ui.add_space(10.0);
    theme::card_frame(ui.visuals()).show(ui, |ui| {
        ui.strong(s.preflight_heading);
        if state.encrypt.preflight_scanning {
            ui.weak(s.preflight_scanning);
            return;
        }
        let est = state.encrypt.preflight_estimate();
        let lang = state.config.language;
        let outer_summary = format_scan_summary(
            est.outer.file_count,
            est.outer.raw_bytes,
            lang,
            "Dış kaynak",
            "Outer sources",
        );
        if state.encrypt.enable_hidden {
            let hidden_summary = format_scan_summary(
                est.hidden.file_count,
                est.hidden.raw_bytes,
                lang,
                "Gizli kaynak",
                "Hidden sources",
            );
            ui.label(format!("{outer_summary}  •  {hidden_summary}"));
        } else {
            ui.label(outer_summary);
        }

        if est.outer.truncated
            || est.hidden.truncated
            || est.outer.skipped_symlinks > 0
            || est.hidden.skipped_symlinks > 0
            || est.outer.unreadable_entries > 0
            || est.hidden.unreadable_entries > 0
        {
            let skipped = est.outer.skipped_symlinks + est.hidden.skipped_symlinks;
            let unreadable = est.outer.unreadable_entries + est.hidden.unreadable_entries;
            let truncated = est.outer.truncated || est.hidden.truncated;
            let note = match lang {
                AppLanguage::Tr => format!(
                    "Tarama notu: atlanan sembolik bağ={skipped}, okunamayan={unreadable}{}",
                    if truncated { ", sınırda kesildi" } else { "" }
                ),
                AppLanguage::En => format!(
                    "Scan note: skipped symlinks={skipped}, unreadable={unreadable}{}",
                    if truncated {
                        ", truncated at limit"
                    } else {
                        ""
                    }
                ),
            };
            ui.weak(note);
        }

        let output_line = if state.encrypt.reed_solomon {
            format!(
                "{} ~{}  ({} +{})",
                s.preflight_est_output,
                format_bytes(est.estimated_disk_bytes),
                s.preflight_rs_overhead,
                format_bytes(est.rs_overhead_bytes)
            )
        } else {
            format!(
                "{} ~{}",
                s.preflight_est_output,
                format_bytes(est.estimated_disk_bytes)
            )
        };
        ui.label(output_line);

        match est.split {
            SplitEstimateStatus::Off => {}
            SplitEstimateStatus::Invalid(err) => {
                ui.colored_label(
                    egui::Color32::from_rgb(230, 80, 80),
                    split_size_error_msg(err, s),
                );
            }
            SplitEstimateStatus::Parts {
                part_bytes,
                estimated_parts,
            } => {
                let split_line = match lang {
                    AppLanguage::Tr => format!(
                        "{} ~{estimated_parts} parça (parça başına en fazla {})",
                        s.preflight_split_parts,
                        format_bytes(part_bytes)
                    ),
                    AppLanguage::En => format!(
                        "{} ~{estimated_parts} part(s) (max {} each)",
                        s.preflight_split_parts,
                        format_bytes(part_bytes)
                    ),
                };
                ui.label(split_line);
            }
        }

        match est.fit {
            ContainerFitStatus::NoContainer => {}
            ContainerFitStatus::InvalidContainer(err) => {
                ui.colored_label(
                    egui::Color32::from_rgb(230, 80, 80),
                    container_size_error_msg(err, s),
                );
            }
            ContainerFitStatus::Fits {
                used_bytes,
                container_bytes,
                free_bytes,
            } => {
                let frac = (used_bytes as f32 / container_bytes.max(1) as f32).clamp(0.0, 1.0);
                let fill = egui::Color32::from_rgb(20, 184, 166);
                ui.horizontal(|ui| {
                    ui.add(egui::ProgressBar::new(frac).desired_width(180.0).fill(fill));
                    let msg = match lang {
                        AppLanguage::Tr => {
                            format!("{} (~{} boş)", s.preflight_fit_ok, format_bytes(free_bytes))
                        }
                        AppLanguage::En => {
                            format!(
                                "{} (~{} free)",
                                s.preflight_fit_ok,
                                format_bytes(free_bytes)
                            )
                        }
                    };
                    ui.colored_label(fill, msg);
                });
            }
            ContainerFitStatus::CompressionDependent {
                required_uncompressed,
                container_bytes,
                suggested_mib,
            } => {
                let amber = egui::Color32::from_rgb(225, 175, 50);
                ui.horizontal(|ui| {
                    ui.add(egui::ProgressBar::new(1.0).desired_width(180.0).fill(amber));
                    let msg = match lang {
                        AppLanguage::Tr => format!(
                            "{}: ~{} > {} — güvenli öneri: >= {suggested_mib} MiB",
                            s.preflight_fit_comp,
                            format_bytes(required_uncompressed),
                            format_bytes(container_bytes)
                        ),
                        AppLanguage::En => format!(
                            "{}: ~{} > {} — safe minimum: >= {suggested_mib} MiB",
                            s.preflight_fit_comp,
                            format_bytes(required_uncompressed),
                            format_bytes(container_bytes)
                        ),
                    };
                    ui.colored_label(amber, msg);
                });
            }
            ContainerFitStatus::ExceedsContainer {
                required_bytes,
                container_bytes,
                suggested_mib,
            } => {
                let red = egui::Color32::from_rgb(230, 80, 80);
                ui.horizontal(|ui| {
                    ui.add(egui::ProgressBar::new(1.0).desired_width(180.0).fill(red));
                    let msg = match lang {
                        AppLanguage::Tr => format!(
                            "{}: ~{} > {} — en az {suggested_mib} MiB seçin",
                            s.preflight_fit_exceeds,
                            format_bytes(required_bytes),
                            format_bytes(container_bytes)
                        ),
                        AppLanguage::En => format!(
                            "{}: ~{} > {} — choose at least {suggested_mib} MiB",
                            s.preflight_fit_exceeds,
                            format_bytes(required_bytes),
                            format_bytes(container_bytes)
                        ),
                    };
                    ui.colored_label(red, msg);
                });
            }
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
    state.trigger_preflight_scan_if_needed(ctx, tx);
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

        render_source_list(
            ui,
            "enc_sources",
            140.0,
            &mut state.encrypt.sources,
            s.enc_no_sources,
            s.btn_remove,
        );
    });

    ui.add_space(10.0);
    render_profile_card(ui, state, s);

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
        if state.encrypt.secure_wipe {
            ui.weak(s.wipe_warning_note);
        }

        let mut stealth = state.encrypt.stealth;
        let stealth_resp = ui
            .add_enabled(
                !state.encrypt.reed_solomon,
                egui::Checkbox::new(&mut stealth, s.stealth_mode),
            )
            .on_disabled_hover_text(s.stealth_disabled_tip);
        if stealth_resp.changed() {
            state.encrypt.set_stealth(stealth);
        }
        if state.encrypt.stealth {
            ui.weak(s.stealth_help);
        }
        let mut rs = state.encrypt.reed_solomon;
        let rs_resp = ui
            .add_enabled(
                !state.encrypt.stealth,
                egui::Checkbox::new(&mut rs, s.rs_mode),
            )
            .on_disabled_hover_text(s.rs_disabled_tip);
        if rs_resp.changed() {
            state.encrypt.set_reed_solomon(rs);
        }
        ui.weak(s.rs_help);

        ui.horizontal(|ui| {
            ui.label(s.lbl_container_size);
            egui::ComboBox::from_id_salt("enc_container_preset")
                .selected_text(state.encrypt.container_preset.localized_label(s))
                .show_ui(ui, |ui| {
                    for preset in ContainerSizePreset::ALL {
                        if state.encrypt.enable_hidden && preset == ContainerSizePreset::Auto {
                            continue;
                        }
                        ui.selectable_value(
                            &mut state.encrypt.container_preset,
                            preset,
                            preset.localized_label(s),
                        );
                    }
                });
            if state.encrypt.container_preset == ContainerSizePreset::Custom {
                ui.add(
                    egui::TextEdit::singleline(&mut state.encrypt.container_custom_mb)
                        .desired_width(80.0),
                );
                ui.label("MiB");
            }
        });
        if state.encrypt.container_preset != ContainerSizePreset::Auto {
            ui.weak(s.hint_container_padding);
        }

        ui.horizontal(|ui| {
            ui.label(s.lbl_split_volume);
            egui::ComboBox::from_id_salt("enc_split_preset")
                .selected_text(state.encrypt.split_preset.localized_label(s))
                .show_ui(ui, |ui| {
                    for preset in SplitSizePreset::ALL {
                        ui.selectable_value(
                            &mut state.encrypt.split_preset,
                            preset,
                            preset.localized_label(s),
                        );
                    }
                });
            if state.encrypt.split_preset == SplitSizePreset::Custom {
                ui.add(
                    egui::TextEdit::singleline(&mut state.encrypt.split_custom_mb)
                        .desired_width(80.0),
                );
                ui.label("MiB");
            }
        });
        if state.encrypt.split_preset != SplitSizePreset::None {
            ui.weak(s.hint_split_volume);
        }

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

    ui.add_space(10.0);
    theme::card_frame(ui.visuals()).show(ui, |ui| {
        egui::CollapsingHeader::new(s.hidden_section_title)
            .id_salt("enc_hidden_vault")
            .default_open(state.encrypt.enable_hidden)
            .show(ui, |ui| {
                let mut enable_hidden = state.encrypt.enable_hidden;
                if ui
                    .checkbox(&mut enable_hidden, s.chk_enable_hidden)
                    .changed()
                {
                    state.encrypt.set_hidden_enabled(enable_hidden);
                }
                ui.weak(s.hidden_section_hint);

                if state.encrypt.enable_hidden {
                    ui.add_space(6.0);
                    ui.label(s.hidden_sources_hint);
                    ui.horizontal(|ui| {
                        if ui.button(s.btn_add_files).clicked() {
                            if let Some(files) = rfd::FileDialog::new().pick_files() {
                                state.encrypt.add_hidden_sources(files);
                            }
                        }
                        if ui.button(s.btn_add_folder).clicked() {
                            if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                state.encrypt.add_hidden_sources(vec![folder]);
                            }
                        }
                        if !state.encrypt.hidden_sources.is_empty()
                            && ui.button(s.btn_clear_list).clicked()
                        {
                            state.encrypt.hidden_sources.clear();
                        }
                    });
                    render_source_list(
                        ui,
                        "enc_hidden_sources",
                        110.0,
                        &mut state.encrypt.hidden_sources,
                        s.hidden_no_sources,
                        s.btn_remove,
                    );

                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(s.lbl_hidden_password);
                        ui.add(
                            egui::TextEdit::singleline(&mut state.encrypt.hidden_password)
                                .password(!state.encrypt.show_hidden_password)
                                .desired_width(280.0),
                        );
                        let toggle_lbl = if state.encrypt.show_hidden_password {
                            s.btn_hide
                        } else {
                            s.btn_show
                        };
                        if ui.small_button(toggle_lbl).clicked() {
                            state.encrypt.show_hidden_password =
                                !state.encrypt.show_hidden_password;
                        }
                    });

                    let (h_label, h_frac, h_color) = strength_label_and_color_for(
                        &state.encrypt.hidden_password,
                        state.config.language,
                    );
                    ui.horizontal(|ui| {
                        ui.label(s.lbl_strength);
                        ui.add(
                            egui::ProgressBar::new(h_frac)
                                .desired_width(180.0)
                                .fill(h_color),
                        );
                        ui.colored_label(h_color, h_label);
                    });

                    ui.horizontal(|ui| {
                        ui.label(s.lbl_hidden_confirm);
                        ui.add(
                            egui::TextEdit::singleline(&mut state.encrypt.hidden_confirm_password)
                                .password(!state.encrypt.show_hidden_password)
                                .desired_width(280.0),
                        );
                    });

                    ui.horizontal(|ui| {
                        ui.label(s.lbl_hidden_keyfile_opt);
                        if let Some(ref kf) = state.encrypt.hidden_keyfile {
                            ui.label(kf.display().to_string());
                            if ui.small_button(s.btn_clear).clicked() {
                                state.encrypt.hidden_keyfile = None;
                            }
                        } else if ui.button(s.btn_select_keyfile).clicked() {
                            if let Some(kf) = rfd::FileDialog::new().pick_file() {
                                state.encrypt.hidden_keyfile = Some(kf);
                            }
                        }
                    });

                    ui.checkbox(&mut state.encrypt.hidden_compress, s.chk_hidden_compress);
                    ui.weak(s.hidden_recovery_note);
                    ui.weak(s.hidden_limits_note);
                }
            });
    });

    render_preflight_card(ui, state, s);

    ui.add_space(12.0);
    ui.horizontal(|ui| {
        ui.add_enabled_ui(!state.busy, |ui| {
            if ui
                .add(theme::primary_button(s.btn_encrypt_now, ui.visuals()))
                .clicked()
            {
                open_recovery_prompt(state, s, false);
            }
        });
        if ui.button(s.btn_add_to_queue).clicked() {
            open_recovery_prompt(state, s, true);
        }
    });

    // Modal recovery phrase confirmation before launching worker thread
    let mut launch = false;
    let mut close_modal = false;
    let mut copy_phrase_now: Option<String> = None;
    let enable_hidden_now = state.encrypt.enable_hidden;
    if let Some(prompt) = state.encrypt.recovery_prompt.as_mut() {
        egui::Window::new(s.modal_rec_title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(s.modal_rec_body);
                if enable_hidden_now {
                    ui.add_space(4.0);
                    ui.weak(s.hidden_recovery_note);
                }
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
        let (container_size, split_part_bytes) = match validate_encrypt_inputs(state, s) {
            Ok(pair) => pair,
            Err(err_msg) => {
                state.encrypt.recovery_prompt = None;
                state.set_status(err_msg, true);
                return;
            }
        };
        if let Some(prompt) = state.encrypt.recovery_prompt.take() {
            let out_dir = if state.encrypt.save_next_to_source {
                None
            } else {
                Some(PathBuf::from(state.encrypt.output_dir.trim()))
            };
            if prompt.queue_after_confirm {
                if state.encrypt.enable_hidden {
                    let Some(container_size_bytes) = container_size else {
                        state.set_status(s.err_hidden_requires_container, true);
                        return;
                    };
                    let decoy_pw = Zeroizing::new(std::mem::take(&mut state.encrypt.password));
                    let hidden_pw =
                        Zeroizing::new(std::mem::take(&mut state.encrypt.hidden_password));
                    let decoy_sources = std::mem::take(&mut state.encrypt.sources);
                    let hidden_sources = std::mem::take(&mut state.encrypt.hidden_sources);
                    state.clear_encrypt_secrets();
                    state.enqueue_job(QueuedJobKind::EncryptHidden {
                        decoy_sources,
                        hidden_sources,
                        decoy_password: decoy_pw,
                        hidden_password: hidden_pw,
                        decoy_recovery_entropy: prompt.entropy.clone(),
                        decoy_keyfile: state.encrypt.keyfile.clone(),
                        hidden_keyfile: state.encrypt.hidden_keyfile.clone(),
                        output_dir: out_dir,
                        decoy_compressed: state.encrypt.compress,
                        hidden_compressed: state.encrypt.hidden_compress,
                        container_size_bytes,
                        split_part_bytes,
                        stealth: state.encrypt.stealth,
                        reed_solomon: state.encrypt.reed_solomon,
                        secure_wipe: state.encrypt.secure_wipe,
                        wipe_passes: state.config.wipe_passes,
                        kdf: state.config.kdf_params(),
                    });
                } else {
                    let pw = Zeroizing::new(std::mem::take(&mut state.encrypt.password));
                    let sources = std::mem::take(&mut state.encrypt.sources);
                    state.clear_encrypt_secrets();
                    state.enqueue_job(QueuedJobKind::Encrypt {
                        sources,
                        password: pw,
                        recovery_entropy: prompt.entropy.clone(),
                        keyfile: state.encrypt.keyfile.clone(),
                        output_dir: out_dir,
                        compress: state.encrypt.compress,
                        container_size_bytes: container_size,
                        split_part_bytes,
                        stealth: state.encrypt.stealth,
                        reed_solomon: state.encrypt.reed_solomon,
                        secure_wipe: state.encrypt.secure_wipe,
                        wipe_passes: state.config.wipe_passes,
                        kdf: state.config.kdf_params(),
                    });
                }
            } else {
                cancel.store(false, std::sync::atomic::Ordering::Relaxed);
                if state.encrypt.enable_hidden {
                    let Some(container_size_bytes) = container_size else {
                        state.set_status(s.err_hidden_requires_container, true);
                        return;
                    };
                    state.begin_transfer(s.status_enc_hidden_running);
                    let decoy_pw = Zeroizing::new(std::mem::take(&mut state.encrypt.password));
                    let hidden_pw =
                        Zeroizing::new(std::mem::take(&mut state.encrypt.hidden_password));
                    state.clear_encrypt_secrets();
                    worker::spawn_encrypt_hidden_with_split(
                        ctx.clone(),
                        tx.clone(),
                        Arc::clone(cancel),
                        state.encrypt.sources.clone(),
                        state.encrypt.hidden_sources.clone(),
                        decoy_pw,
                        hidden_pw,
                        prompt.entropy.clone(),
                        state.encrypt.keyfile.clone(),
                        state.encrypt.hidden_keyfile.clone(),
                        out_dir,
                        state.encrypt.compress,
                        state.encrypt.hidden_compress,
                        container_size_bytes,
                        split_part_bytes,
                        state.encrypt.stealth,
                        state.encrypt.reed_solomon,
                        state.encrypt.secure_wipe,
                        state.config.wipe_passes,
                        state.config.kdf_params(),
                        state.config.language,
                    );
                } else {
                    state.begin_transfer(s.status_enc_running);
                    let pw = Zeroizing::new(std::mem::take(&mut state.encrypt.password));
                    state.clear_encrypt_secrets();
                    worker::spawn_encrypt_with_split(
                        ctx.clone(),
                        tx.clone(),
                        Arc::clone(cancel),
                        state.encrypt.sources.clone(),
                        pw,
                        prompt.entropy.clone(),
                        state.encrypt.keyfile.clone(),
                        out_dir,
                        state.encrypt.compress,
                        container_size,
                        split_part_bytes,
                        state.encrypt.stealth,
                        state.encrypt.reed_solomon,
                        state.encrypt.secure_wipe,
                        state.config.wipe_passes,
                        state.config.kdf_params(),
                        state.config.language,
                    );
                }
            }
        }
    }
}
