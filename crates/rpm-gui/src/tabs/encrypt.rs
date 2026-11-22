//! Encrypt tab UI + recovery phrase modal confirmation.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};

use eframe::egui;
use rpm_core::{entropy_to_mnemonic, generate_recovery_entropy};
use zeroize::Zeroizing;

use crate::i18n::Strings;
use crate::state::{
    strength_label_and_color_for, AppState, ContainerSizeError, ContainerSizePreset,
    RecoveryPrompt, Tab, WorkerUpdate,
};
use crate::{theme, worker};

fn container_size_error_msg(err: ContainerSizeError, s: &'static Strings) -> &'static str {
    match err {
        ContainerSizeError::InvalidCustomValue => s.err_container_invalid_mb,
        ContainerSizeError::OutOfRange => s.err_container_out_of_range,
        ContainerSizeError::RequiredForHidden => s.err_hidden_requires_container,
    }
}

fn validate_encrypt_inputs(
    state: &AppState,
    s: &'static Strings,
) -> Result<Option<u64>, &'static str> {
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
    Ok(container_size)
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

    ui.add_space(12.0);
    ui.add_enabled_ui(!state.busy, |ui| {
        if ui
            .add(theme::primary_button(s.btn_encrypt_now, ui.visuals()))
            .clicked()
        {
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
        let container_size = match validate_encrypt_inputs(state, s) {
            Ok(sz) => sz,
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
            cancel.store(false, std::sync::atomic::Ordering::Relaxed);
            if state.encrypt.enable_hidden {
                let Some(container_size_bytes) = container_size else {
                    state.set_status(s.err_hidden_requires_container, true);
                    return;
                };
                state.begin_transfer(s.status_enc_hidden_running);
                let decoy_pw = Zeroizing::new(std::mem::take(&mut state.encrypt.password));
                let hidden_pw = Zeroizing::new(std::mem::take(&mut state.encrypt.hidden_password));
                state.clear_encrypt_secrets();
                worker::spawn_encrypt_hidden(
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
                    container_size,
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
