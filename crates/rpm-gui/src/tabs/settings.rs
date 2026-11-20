//! Settings & Windows Shell Integration tab UI.

use eframe::egui;
use rpm_storage::config::{save_config_to, AppLanguage, ThemeMode};
use rpm_storage::shell_integration;

use crate::state::AppState;
use crate::theme;

pub fn ui(ui: &mut egui::Ui, ctx: &egui::Context, state: &mut AppState) {
    let s = state.strings();
    ui.heading(s.set_heading);
    ui.add_space(8.0);

    theme::card_frame(ui.visuals()).show(ui, |ui| {
        ui.strong(s.set_section_appearance);
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.label(s.lbl_theme);
            if ui
                .radio_value(&mut state.config.theme, ThemeMode::Dark, s.theme_dark)
                .clicked()
                || ui
                    .radio_value(&mut state.config.theme, ThemeMode::Light, s.theme_light)
                    .clicked()
            {
                state.apply_theme_visuals(ctx);
            }
        });

        ui.horizontal(|ui| {
            ui.label(s.lbl_language);
            let mut lang_changed = false;
            lang_changed |= ui
                .radio_value(&mut state.config.language, AppLanguage::Tr, "Türkçe")
                .clicked();
            lang_changed |= ui
                .radio_value(&mut state.config.language, AppLanguage::En, "English")
                .clicked();
            if lang_changed {
                state.set_status(state.strings().status_ready, false);
            }
        });

        let s = state.strings();
        ui.horizontal(|ui| {
            ui.label(s.lbl_argon_mem);
            egui::ComboBox::from_id_salt("argon_mem")
                .selected_text(format!("{} MiB", state.config.argon_memory_kib / 1024))
                .show_ui(ui, |ui| {
                    for (kib, label) in [
                        (16_384, s.argon_16),
                        (65_536, s.argon_64),
                        (131_072, s.argon_128),
                        (262_144, s.argon_256),
                    ] {
                        ui.selectable_value(&mut state.config.argon_memory_kib, kib, label);
                    }
                });
        });

        ui.checkbox(
            &mut state.config.compress_by_default,
            s.chk_default_compress,
        );

        ui.horizontal(|ui| {
            ui.label(s.lbl_wipe_passes);
            ui.add(egui::Slider::new(&mut state.config.wipe_passes, 1..=5));
        });

        ui.add_space(4.0);
        if ui
            .add(theme::primary_button(s.btn_save_prefs, ui.visuals()))
            .clicked()
        {
            if let Some(ref p) = state.config_path {
                match save_config_to(p, &state.config) {
                    Ok(()) => state.set_status(s.status_prefs_saved, false),
                    Err(e) => state.set_status(format!("Error: {e}"), true),
                }
            }
        }
    });

    ui.add_space(10.0);
    theme::card_frame(ui.visuals()).show(ui, |ui| {
        ui.strong(s.set_section_shell);
        ui.add_space(4.0);
        if !state.shell_status.supported {
            ui.weak(s.shell_windows_only);
        } else {
            let status_str = if state.shell_status.installed {
                s.shell_installed
            } else {
                s.shell_not_installed
            };
            ui.label(status_str);
            ui.horizontal(|ui| {
                if ui.button(s.btn_install_shell).clicked() {
                    state.show_shell_install_modal = true;
                }
                if ui.button(s.btn_remove_shell).clicked() {
                    match shell_integration::uninstall_shell_integration() {
                        Ok(st) => {
                            state.shell_status = st;
                            state.set_status(s.status_shell_removed, false);
                        }
                        Err(e) => state.set_status(format!("Error: {e}"), true),
                    }
                }
            });
        }
    });

    if state.show_shell_install_modal {
        let mut close = false;
        egui::Window::new(s.modal_shell_title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(s.modal_shell_body);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button(s.btn_cancel).clicked() {
                        close = true;
                    }
                    if ui
                        .add(theme::primary_button(s.btn_install, ui.visuals()))
                        .clicked()
                    {
                        match shell_integration::install_shell_integration() {
                            Ok(st) => {
                                state.shell_status = st;
                                state.set_status(s.status_shell_installed, false);
                            }
                            Err(e) => state.set_status(format!("Error: {e}"), true),
                        }
                        close = true;
                    }
                });
            });
        if close {
            state.show_shell_install_modal = false;
        }
    }
}
