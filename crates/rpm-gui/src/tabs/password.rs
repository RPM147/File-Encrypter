//! Password Generator tab UI with 30-second auto-clearing clipboard timer.

use std::time::{Duration, Instant};

use eframe::egui;

use crate::state::{strength_label_and_color, AppState, Tab};

pub fn ui(ui: &mut egui::Ui, ctx: &egui::Context, state: &mut AppState) {
    ui.heading("Password Generator");
    ui.add_space(6.0);

    ui.group(|ui| {
        ui.add(egui::Slider::new(&mut state.pwgen.length, 12..=64).text("Length"));
        ui.checkbox(
            &mut state.pwgen.include_symbols,
            "Include symbols (!@#$...)",
        );

        ui.horizontal(|ui| {
            if ui.button("Generate").clicked() {
                state.generate_password();
            }
            if !state.pwgen.generated.is_empty() && ui.button("Copy (auto-clears in 30s)").clicked()
            {
                ctx.copy_text(state.pwgen.generated.clone());
                state.pwgen.clipboard_deadline = Some(Instant::now() + Duration::from_secs(30));
                state.set_status("Password copied (will clear in 30s)", false);
            }
            if !state.pwgen.generated.is_empty() && ui.button("Use in Encrypt Tab").clicked() {
                state.encrypt.password = state.pwgen.generated.clone();
                state.encrypt.confirm_password = state.pwgen.generated.clone();
                state.active_tab = Tab::Encrypt;
                state.set_status("Password transferred to Encrypt tab", false);
            }
        });

        ui.add_space(6.0);
        ui.add(
            egui::TextEdit::singleline(&mut state.pwgen.generated)
                .desired_width(420.0)
                .font(egui::TextStyle::Monospace),
        );
        let (label, color) = strength_label_and_color(&state.pwgen.generated);
        ui.colored_label(color, format!("Strength: {label}"));

        if let Some(deadline) = state.pwgen.clipboard_deadline {
            let now = Instant::now();
            if now < deadline {
                let secs = (deadline - now).as_secs() + 1;
                ui.weak(format!("Clipboard auto-clear in {secs}s"));
            }
        }
    });
}
