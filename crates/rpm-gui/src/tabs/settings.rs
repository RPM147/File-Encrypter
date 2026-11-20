//! Settings & Windows Shell Integration tab UI.

use eframe::egui;
use rpm_storage::config::{save_config_to, ThemeMode};
use rpm_storage::shell_integration;

use crate::state::AppState;

pub fn ui(ui: &mut egui::Ui, ctx: &egui::Context, state: &mut AppState) {
    ui.heading("Settings");
    ui.add_space(6.0);

    ui.group(|ui| {
        ui.label("Appearance & Crypto Defaults");
        ui.horizontal(|ui| {
            ui.label("Theme:");
            if ui
                .radio_value(&mut state.config.theme, ThemeMode::Dark, "Dark")
                .clicked()
                || ui
                    .radio_value(&mut state.config.theme, ThemeMode::Light, "Light")
                    .clicked()
            {
                state.apply_theme_visuals(ctx);
            }
        });

        ui.horizontal(|ui| {
            ui.label("Argon2id Memory:");
            egui::ComboBox::from_id_salt("argon_mem")
                .selected_text(format!("{} MiB", state.config.argon_memory_kib / 1024))
                .show_ui(ui, |ui| {
                    for (kib, label) in [
                        (16_384, "16 MiB (Fast)"),
                        (65_536, "64 MiB (OWASP Default)"),
                        (131_072, "128 MiB"),
                        (262_144, "256 MiB (High)"),
                    ] {
                        ui.selectable_value(&mut state.config.argon_memory_kib, kib, label);
                    }
                });
        });

        ui.horizontal(|ui| {
            ui.label("Secure Wipe Passes:");
            ui.add(egui::Slider::new(&mut state.config.wipe_passes, 1..=5));
        });

        if ui.button("Save Preferences").clicked() {
            if let Some(ref p) = state.config_path {
                match save_config_to(p, &state.config) {
                    Ok(()) => state.set_status("Settings saved", false),
                    Err(e) => state.set_status(format!("Save failed: {e}"), true),
                }
            }
        }
    });

    ui.add_space(10.0);
    ui.group(|ui| {
        ui.label("Windows Shell Integration (HKCU Only — No Admin Rights)");
        if !state.shell_status.supported {
            ui.weak("Status: Available on Windows only");
        } else {
            let status_str = if state.shell_status.installed {
                "Installed (Right-click 'Encrypt with RPM Encrypter' & .vault double-click)"
            } else {
                "Not installed"
            };
            ui.label(format!("Status: {status_str}"));
            ui.horizontal(|ui| {
                if ui
                    .button("Install Context Menu & .vault Association")
                    .clicked()
                {
                    state.show_shell_install_modal = true;
                }
                if ui.button("Remove Shell Integration").clicked() {
                    match shell_integration::uninstall_shell_integration() {
                        Ok(st) => {
                            state.shell_status = st;
                            state.set_status("Windows shell integration removed", false);
                        }
                        Err(e) => state.set_status(format!("Removal failed: {e}"), true),
                    }
                }
            });
        }
    });

    if state.show_shell_install_modal {
        let mut close = false;
        egui::Window::new("Install Windows Shell Integration?")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(
                    "Register user-scoped HKCU\\Software\\Classes keys for Explorer \
                     right-click encryption and .vault double-click decryption?",
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                    if ui.button("Install").clicked() {
                        match shell_integration::install_shell_integration() {
                            Ok(st) => {
                                state.shell_status = st;
                                state.set_status("Windows shell integration installed", false);
                            }
                            Err(e) => state.set_status(format!("Install failed: {e}"), true),
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
