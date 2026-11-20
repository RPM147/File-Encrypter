//! Main `eframe::App` shell: sidebar navigation, OS file drag-and-drop, progress bar, logs.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Instant;

use eframe::egui;
use rpm_storage::GuiLaunchIntent;

use crate::state::{AppState, Tab, WorkerUpdate};
use crate::tabs;

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
                WorkerUpdate::Progress(p) => self.state.progress = p,
                WorkerUpdate::Log(line) => self.state.push_log(line),
                WorkerUpdate::EncryptDone { status } => {
                    self.state.busy = false;
                    self.state.progress = 1.0;
                    self.state.encrypt.sources.clear();
                    self.state.set_status(status, false);
                }
                WorkerUpdate::DecryptDone { status } => {
                    self.state.busy = false;
                    self.state.progress = 1.0;
                    self.state.set_status(status, false);
                }
                WorkerUpdate::InspectDone { text, status } => {
                    self.state.busy = false;
                    self.state.inspect.results = text;
                    self.state.set_status(status, false);
                }
                WorkerUpdate::IntegrityDone { text, ok } => {
                    self.state.busy = false;
                    self.state.inspect.results = text;
                    self.state.set_status(
                        if ok {
                            "Integrity check passed"
                        } else {
                            "Integrity check failed"
                        },
                        !ok,
                    );
                }
                WorkerUpdate::RekeyDone { status } => {
                    self.state.busy = false;
                    self.state.set_status(status, false);
                }
                WorkerUpdate::Error(err) => {
                    self.state.busy = false;
                    self.state.progress = 0.0;
                    self.state.set_status(err.clone(), true);
                    self.state.push_log(format!("ERROR: {err}"));
                }
            }
        }
    }
}

impl eframe::App for RpmApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_initialized {
            self.state.apply_theme_visuals(ctx);
            self.theme_initialized = true;
        }

        self.drain_updates();

        // Clipboard auto-clear timer check
        if let Some(deadline) = self.state.pwgen.clipboard_deadline {
            if Instant::now() >= deadline {
                ctx.copy_text(String::new());
                self.state.pwgen.clipboard_deadline = None;
                self.state.set_status("Clipboard cleared", false);
            } else {
                ctx.request_repaint_after(std::time::Duration::from_millis(500));
            }
        }

        // Native OS file drag-and-drop
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|df| df.path.clone())
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

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if self.state.is_error {
                    ui.colored_label(egui::Color32::from_rgb(230, 80, 80), &self.state.status);
                } else {
                    ui.label(&self.state.status);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.state.busy && ui.button("Cancel").clicked() {
                        self.cancel.store(true, Ordering::Relaxed);
                        self.state.set_status("Cancelling...", false);
                    }
                    ui.add(
                        egui::ProgressBar::new(self.state.progress)
                            .desired_width(180.0)
                            .show_percentage(),
                    );
                });
            });
        });

        egui::SidePanel::left("sidebar")
            .resizable(false)
            .default_width(160.0)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.heading("RPM Encrypter");
                ui.weak("v5 Chunked AEAD");
                ui.separator();
                for tab in Tab::ALL {
                    if ui
                        .selectable_label(self.state.active_tab == tab, tab.label())
                        .clicked()
                    {
                        self.state.active_tab = tab;
                    }
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            if is_hovering_files {
                egui::Frame::NONE
                    .fill(egui::Color32::from_rgba_unmultiplied(40, 120, 220, 45))
                    .stroke(egui::Stroke::new(
                        2.0_f32,
                        egui::Color32::from_rgb(80, 160, 255),
                    ))
                    .corner_radius(6.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.centered_and_justified(|ui| {
                            ui.strong("Drop files/folders to Encrypt or .vault files to Decrypt");
                        });
                    });
                ui.add_space(6.0);
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
                        tabs::inspect::ui(ui, ctx, &mut self.state, &self.tx);
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
                    ui.add_space(10.0);
                    ui.collapsing("Activity / Worker Log", |ui| {
                        for line in self.state.logs.iter().rev().take(30) {
                            ui.small(line);
                        }
                    });
                }
            });
        });
    }
}
