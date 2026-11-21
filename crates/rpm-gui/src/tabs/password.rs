//! Password Generator tab UI with 30-second auto-clearing clipboard timer.

use std::time::Instant;

use eframe::egui;
use rpm_storage::config::AppLanguage;

use crate::state::{strength_label_and_color_for, AppState, Tab};
use crate::theme;

pub fn ui(ui: &mut egui::Ui, ctx: &egui::Context, state: &mut AppState) {
    let s = state.strings();
    ui.heading(s.pwg_heading);
    ui.add_space(8.0);

    theme::card_frame(ui.visuals()).show(ui, |ui| {
        ui.add(egui::Slider::new(&mut state.pwgen.length, 12..=64).text(s.pwg_length));
        ui.add_space(4.0);

        let only_one = state.pwgen.enabled_class_count() <= 1;
        ui.horizontal_wrapped(|ui| {
            ui.add_enabled(
                !(only_one && state.pwgen.include_uppercase),
                egui::Checkbox::new(&mut state.pwgen.include_uppercase, s.chk_uppercase),
            )
            .on_disabled_hover_text(s.err_pw_no_class);
            ui.add_enabled(
                !(only_one && state.pwgen.include_lowercase),
                egui::Checkbox::new(&mut state.pwgen.include_lowercase, s.chk_lowercase),
            )
            .on_disabled_hover_text(s.err_pw_no_class);
            ui.add_enabled(
                !(only_one && state.pwgen.include_digits),
                egui::Checkbox::new(&mut state.pwgen.include_digits, s.chk_digits),
            )
            .on_disabled_hover_text(s.err_pw_no_class);
            ui.add_enabled(
                !(only_one && state.pwgen.include_symbols),
                egui::Checkbox::new(&mut state.pwgen.include_symbols, s.chk_symbols),
            )
            .on_disabled_hover_text(s.err_pw_no_class);
        });
        ui.checkbox(&mut state.pwgen.exclude_ambiguous, s.chk_exclude_ambiguous);

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui
                .add(theme::primary_button(s.btn_generate, ui.visuals()))
                .clicked()
            {
                state.generate_password();
            }
            if !state.pwgen.generated.is_empty() && ui.button(s.btn_copy_30s).clicked() {
                let text = state.pwgen.generated.clone();
                state.copy_secret_with_autoclear(ctx, text, s.status_pw_copied);
            }
            if !state.pwgen.generated.is_empty() && ui.button(s.btn_use_in_encrypt).clicked() {
                state.encrypt.password = state.pwgen.generated.clone();
                state.encrypt.confirm_password = state.pwgen.generated.clone();
                state.select_tab(Tab::Encrypt);
                state.set_status(s.status_pw_transferred, false);
            }
        });

        ui.add_space(8.0);
        ui.add(
            egui::TextEdit::singleline(&mut state.pwgen.generated)
                .desired_width(460.0)
                .font(egui::TextStyle::Monospace),
        );
        let (label, frac, color) =
            strength_label_and_color_for(&state.pwgen.generated, state.config.language);
        ui.horizontal(|ui| {
            ui.label(s.lbl_strength);
            ui.add(
                egui::ProgressBar::new(frac)
                    .desired_width(180.0)
                    .fill(color),
            );
            ui.colored_label(color, label);
        });

        if let Some(deadline) = state.clipboard_deadline {
            let now = Instant::now();
            if now < deadline {
                let secs = (deadline - now).as_secs() + 1;
                let msg = match state.config.language {
                    AppLanguage::Tr => format!("Pano {secs} saniye içinde otomatik temizlenecek"),
                    AppLanguage::En => format!("Clipboard auto-clear in {secs}s"),
                };
                ui.weak(msg);
            }
        }
    });
}
