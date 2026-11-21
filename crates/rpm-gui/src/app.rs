//! Main `eframe::App` shell: branded sidebar, shortcuts, OS drag-and-drop, progress bar, logs.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use eframe::egui;
use rpm_storage::config::{AppLanguage, ThemeMode};
use rpm_storage::GuiLaunchIntent;

use crate::progress::{format_transfer_summary, format_transfer_tooltip};
use crate::state::{AppState, Tab, WorkerUpdate};
use crate::{tabs, theme};

pub struct RpmApp {
    pub state: AppState,
    tx: mpsc::Sender<WorkerUpdate>,
    rx: mpsc::Receiver<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
    theme_initialized: bool,
}

impl RpmApp {
    pub fn new(intent: GuiLaunchIntent) -> Self {
        let (tx, rx) = mpsc::channel();
        let mut state = AppState::default();
        state.apply_launch_intent(intent);
        Self {
            state,
            tx,
            rx,
            cancel: Arc::new(AtomicBool::new(false)),
            theme_initialized: false,
        }
    }

    fn drain_updates(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                WorkerUpdate::Progress(snap) => {
                    self.state.progress = snap.fraction;
                    self.state.transfer = Some(snap);
                }
                WorkerUpdate::Log(line) => self.state.push_log(line),
                WorkerUpdate::EncryptDone { status } => {
                    self.state.busy = false;
                    self.state.progress = 1.0;
                    self.state.transfer = None;
                    self.state.encrypt.sources.clear();
                    self.state.set_status(status, false);
                }
                WorkerUpdate::DecryptDone { status } => {
                    self.state.busy = false;
                    self.state.progress = 1.0;
                    self.state.transfer = None;
                    self.state.set_status(status, false);
                }
                WorkerUpdate::InspectDone {
                    text,
                    status,
                    manifest,
                    vault_path,
                } => {
                    self.state.busy = false;
                    self.state.transfer = None;
                    self.state.inspect.results = text;
                    self.state.inspect.set_manifest(vault_path, manifest);
                    self.state.set_status(status, false);
                }
                WorkerUpdate::IntegrityDone { text, ok } => {
                    self.state.busy = false;
                    self.state.transfer = None;
                    self.state.inspect.results = text;
                    self.state.inspect.reset_manifest();
                    let s = self.state.strings();
                    let label = match self.state.config.language {
                        AppLanguage::Tr => {
                            if ok {
                                "Bütünlük doğrulaması başarılı"
                            } else {
                                "Bütünlük doğrulaması başarısız"
                            }
                        }
                        AppLanguage::En => {
                            if ok {
                                "Integrity check passed"
                            } else {
                                "Integrity check failed"
                            }
                        }
                    };
                    let _ = s;
                    self.state.set_status(label, !ok);
                }
                WorkerUpdate::RekeyDone { status } => {
                    self.state.busy = false;
                    self.state.transfer = None;
                    self.state.set_status(status, false);
                }
                WorkerUpdate::Error(err) => {
                    self.state.busy = false;
                    self.state.progress = 0.0;
                    self.state.transfer = None;
                    self.state.set_status(err.clone(), true);
                    self.state.push_log(format!("ERROR: {err}"));
                }
            }
        }
    }

    fn handle_keyboard_shortcuts(&mut self, ctx: &egui::Context) {
        let mut digit_pressed: Option<u8> = None;
        let mut esc_pressed = false;
        ctx.input(|i| {
            if i.modifiers.ctrl || i.modifiers.command {
                for (key, digit) in [
                    (egui::Key::Num1, 1),
                    (egui::Key::Num2, 2),
                    (egui::Key::Num3, 3),
                    (egui::Key::Num4, 4),
                    (egui::Key::Num5, 5),
                    (egui::Key::Num6, 6),
                ] {
                    if i.key_pressed(key) {
                        digit_pressed = Some(digit);
                        break;
                    }
                }
            }
            if i.key_pressed(egui::Key::Escape) {
                esc_pressed = true;
            }
        });

        if let Some(d) = digit_pressed {
            self.state.handle_shortcut_tab(d);
        }
        if esc_pressed && !self.state.dismiss_modals() && self.state.busy {
            self.cancel.store(true, Ordering::Relaxed);
            let msg = self.state.strings().status_cancelling;
            self.state.set_status(msg, false);
        }
    }
}

impl eframe::App for RpmApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &ui.ctx().clone();
        if !self.theme_initialized {
            self.state.apply_theme_visuals(ctx);
            self.theme_initialized = true;
        }

        self.drain_updates();
        self.handle_keyboard_shortcuts(ctx);

        // Unified clipboard auto-clear timer check (Password Gen + Recovery Modal)
        if let Some(deadline) = self.state.clipboard_deadline {
            if Instant::now() >= deadline {
                ctx.copy_text(String::new());
                self.state.clipboard_deadline = None;
                let msg = self.state.strings().status_clipboard_cleared;
                self.state.set_status(msg, false);
            } else {
                ctx.request_repaint_after(Duration::from_millis(500));
            }
        }

        // Native OS file drag-and-drop
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|df| df.path().to_path_buf())
                .filter(|p| !p.as_os_str().is_empty())
                .collect()
        });
        if !dropped.is_empty() {
            let forced = match self.state.active_tab {
                Tab::Inspect | Tab::Rekey => Some(self.state.active_tab),
                _ => None,
            };
            self.state.add_dropped_paths(dropped, forced);
        }
        let is_hovering_files = ctx.input(|i| !i.raw.hovered_files.is_empty());

        ui.reset_style();
        let s = self.state.strings();
        let style = ctx.global_style();
        let accent = theme::accent_color(&style.visuals);

        egui::Panel::bottom("status_bar")
            .frame(egui::Frame::side_top_panel(&style).inner_margin(egui::Margin::symmetric(14, 8)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if self.state.is_error {
                        ui.colored_label(egui::Color32::from_rgb(230, 80, 80), &self.state.status);
                    } else {
                        ui.label(&self.state.status);
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.state.busy && ui.button(s.btn_cancel).clicked() {
                            self.cancel.store(true, Ordering::Relaxed);
                            self.state.set_status(s.status_cancelling, false);
                        }
                        let bar_resp = ui.add(
                            egui::ProgressBar::new(self.state.progress)
                                .desired_width(190.0)
                                .show_percentage(),
                        );
                        if let Some(snap) = self.state.transfer {
                            let tip = format_transfer_tooltip(&snap, self.state.config.language);
                            bar_resp.on_hover_text(tip);
                            if self.state.busy {
                                if let Some(summary) =
                                    format_transfer_summary(&snap, self.state.config.language)
                                {
                                    ui.add_space(6.0);
                                    ui.small(summary);
                                }
                            }
                        }
                    });
                });
            });

        egui::Panel::left("sidebar")
            .resizable(false)
            .default_size(200.0)
            .show(ui, |ui| {
                ui.add_space(10.0);
                ui.heading(s.app_title);
                ui.colored_label(accent, egui::RichText::new(s.app_badge).small().strong());
                ui.add_space(6.0);
                ui.separator();
                ui.add_space(4.0);

                for (idx, tab) in Tab::ALL.into_iter().enumerate() {
                    let selected = self.state.active_tab == tab;
                    let text = format!("{}  ({})", tab.localized_label(s), idx + 1);
                    let resp = ui.add_sized(
                        [ui.available_width(), 30.0],
                        egui::Button::new(text)
                            .selected(selected)
                            .corner_radius(egui::CornerRadius::same(6)),
                    );
                    if resp.clicked() {
                        self.state.active_tab = tab;
                    }
                }

                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.small_button(s.lbl_lang_short).clicked() {
                            self.state.toggle_language();
                            self.state.persist_config_best_effort();
                        }
                        let theme_lbl = match self.state.config.theme {
                            ThemeMode::Dark => s.lbl_theme_toggle_light,
                            ThemeMode::Light => s.lbl_theme_toggle_dark,
                        };
                        if ui.small_button(theme_lbl).clicked() {
                            self.state.toggle_theme(ctx);
                            self.state.persist_config_best_effort();
                        }
                    });
                    ui.separator();
                });
            });

        egui::CentralPanel::default().show(ui, |ui| {
            if is_hovering_files {
                egui::Frame::NONE
                    .fill(egui::Color32::from_rgba_unmultiplied(20, 184, 166, 36))
                    .stroke(egui::Stroke::new(2.0_f32, accent))
                    .corner_radius(8.0)
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.centered_and_justified(|ui| {
                            ui.strong(s.drop_banner);
                        });
                    });
                ui.add_space(8.0);
            }

            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.state.active_tab {
                    Tab::Encrypt => {
                        tabs::encrypt::ui(ui, ctx, &mut self.state, &self.tx, &self.cancel);
                    }
                    Tab::Decrypt => {
                        tabs::decrypt::ui(ui, ctx, &mut self.state, &self.tx, &self.cancel);
                    }
                    Tab::Inspect => {
                        tabs::inspect::ui(ui, ctx, &mut self.state, &self.tx, &self.cancel);
                    }
                    Tab::Rekey => {
                        tabs::rekey::ui(ui, ctx, &mut self.state, &self.tx, &self.cancel);
                    }
                    Tab::Password => {
                        tabs::password::ui(ui, ctx, &mut self.state);
                    }
                    Tab::Settings => {
                        tabs::settings::ui(ui, ctx, &mut self.state);
                    }
                }

                if !self.state.logs.is_empty() {
                    let s = self.state.strings();
                    ui.add_space(12.0);
                    ui.collapsing(s.activity_log, |ui| {
                        if ui.small_button(s.btn_clear).clicked() {
                            self.state.logs.clear();
                        }
                        for line in self.state.logs.iter().rev().take(30) {
                            ui.small(line);
                        }
                    });
                }
            });
        });
    }
}
