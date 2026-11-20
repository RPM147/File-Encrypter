//! Vault Inspect & Integrity Check tab UI.

use std::path::PathBuf;
use std::sync::mpsc;

use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

use crate::state::{AppState, WorkerUpdate};
use crate::worker;

pub fn ui(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    state: &mut AppState,
    tx: &mpsc::Sender<WorkerUpdate>,
) {
    ui.heading("Inspect & Integrity Check");
    ui.add_space(6.0);

    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label("Vault:");
            ui.text_edit_singleline(&mut state.inspect.vault_path);
            if ui.button("Browse...").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("RPM Vault", &["vault"])
                    .pick_file()
                {
                    state.inspect.vault_path = p.display().to_string();
                }
            }
        });

        ui.checkbox(
            &mut state.inspect.use_recovery,
            "Unlock with 24-word recovery phrase",
        );
        if state.inspect.use_recovery {
            ui.add(
                egui::TextEdit::multiline(&mut state.inspect.recovery_phrase)
                    .desired_width(480.0)
                    .desired_rows(3),
            );
        } else {
            ui.horizontal(|ui| {
                ui.label("Password:");
                ui.add(
                    egui::TextEdit::singleline(&mut state.inspect.password)
                        .password(true)
                        .desired_width(260.0),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Keyfile (optional):");
                if let Some(ref kf) = state.inspect.keyfile {
                    ui.label(kf.display().to_string());
                    if ui.small_button("Clear").clicked() {
                        state.inspect.keyfile = None;
                    }
                } else if ui.button("Select Keyfile...").clicked() {
                    if let Some(kf) = rfd::FileDialog::new().pick_file() {
                        state.inspect.keyfile = Some(kf);
                    }
                }
            });
        }

        ui.add_enabled_ui(!state.busy, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Integrity Check (No Password)").clicked() {
                    let p = PathBuf::from(state.inspect.vault_path.trim());
                    if !p.is_file() {
                        state.set_status("Select an existing .vault file", true);
                    } else {
                        state.busy = true;
                        state.set_status("Computing SHA-256 & header check...", false);
                        worker::spawn_integrity_check(ctx.clone(), tx.clone(), p);
                    }
                }
                if ui.button("Inspect Metadata").clicked() {
                    let p = PathBuf::from(state.inspect.vault_path.trim());
                    if !p.is_file() {
                        state.set_status("Select an existing .vault file", true);
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
                        state.set_status("Enter password or recovery phrase", true);
                        return;
                    }
                    state.busy = true;
                    state.set_status("Inspecting encrypted header...", false);
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

    ui.add_space(8.0);
    egui::ScrollArea::vertical()
        .id_salt("inspect_results")
        .max_height(260.0)
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut state.inspect.results.as_str())
                    .desired_width(f32::INFINITY)
                    .desired_rows(14)
                    .font(egui::TextStyle::Monospace),
            );
        });
}
