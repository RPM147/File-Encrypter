//! Main `eframe::App` shell: branded sidebar, shortcuts, OS drag-and-drop, progress bar, logs.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use eframe::egui;
use rpm_storage::config::{AppLanguage, ThemeMode};
use rpm_storage::GuiLaunchIntent;

use crate::progress::{format_transfer_summary, format_transfer_tooltip};
use crate::state::{AppState, LastCompletedAction, SessionClearReason, Tab, WorkerUpdate};
use crate::{reveal, tabs, theme, worker};

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

    pub fn drain_updates(&mut self, ctx: &egui::Context) {
        let mut completed_transfer = false;
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                WorkerUpdate::SourceScanDone { gen, outer, hidden } => {
                    if gen == self.state.encrypt.preflight_scan_gen {
                        self.state.encrypt.preflight_outer = outer;
                        self.state.encrypt.preflight_hidden = hidden;
                        self.state.encrypt.preflight_scanning = false;
                        self.state.encrypt.preflight_scan_cancel = None;
                    }
                }
                WorkerUpdate::PreviewDone {
                    gen,
                    path,
                    bytes,
                    status,
                } => {
                    if let Some((g, c)) = self.state.inspect.preview_pending.as_ref() {
                        if *g == gen {
                            let cancelled = c.load(Ordering::Relaxed);
                            self.state.inspect.preview_pending = None;
                            self.state.busy = false;
                            self.state.transfer = None;
                            if cancelled {
                                let msg = self.state.strings().preview_cancelled;
                                self.state.set_status(msg, false);
                            } else {
                                self.state.inspect.preview =
                                    Some(crate::preview::PreviewState::new(ctx, path, bytes));
                                self.state.set_status(status, false);
                            }
                        }
                    }
                }
                WorkerUpdate::PreviewError {
                    gen,
                    message,
                    cancelled,
                } => {
                    if self
                        .state
                        .inspect
                        .preview_pending
                        .as_ref()
                        .is_some_and(|(g, _)| *g == gen)
                    {
                        self.state.inspect.preview_pending = None;
                        self.state.busy = false;
                        self.state.transfer = None;
                        self.state.set_status(message.clone(), !cancelled);
                        if !cancelled {
                            self.state.push_log(format!("ERROR: {message}"));
                        }
                    }
                }
                WorkerUpdate::Progress(snap) => {
                    if self.state.busy {
                        self.state.progress = snap.fraction;
                        self.state.transfer = Some(snap);
                    }
                }
                WorkerUpdate::Log(line) => self.state.push_log(line),
                WorkerUpdate::EncryptDone {
                    status,
                    output_path,
                } => {
                    let was_queued = self.state.active_queue_job.take().is_some();
                    self.state.busy = false;
                    self.state.progress = 1.0;
                    self.state.transfer = None;
                    if !was_queued {
                        self.state.encrypt.sources.clear();
                        self.state.encrypt.hidden_sources.clear();
                    }
                    self.state.last_action = Some(LastCompletedAction {
                        summary: status.clone(),
                        reveal_path: output_path.clone(),
                        verify_vault: Some(output_path),
                    });
                    if was_queued {
                        self.state.queue_completed += 1;
                    }
                    self.state.set_status(status, false);
                    completed_transfer = true;
                }
                WorkerUpdate::DecryptDone {
                    status,
                    output_path,
                } => {
                    let was_queued = self.state.active_queue_job.take().is_some();
                    self.state.busy = false;
                    self.state.progress = 1.0;
                    self.state.transfer = None;
                    if let Some(reveal_path) = output_path {
                        self.state.last_action = Some(LastCompletedAction {
                            summary: status.clone(),
                            reveal_path,
                            verify_vault: None,
                        });
                    }
                    if was_queued {
                        self.state.queue_completed += 1;
                    }
                    self.state.set_status(status, false);
                    completed_transfer = true;
                }
                WorkerUpdate::InspectDone {
                    text,
                    status,
                    manifest,
                    vault_path,
                } => {
                    let was_queued = self.state.active_queue_job.take().is_some();
                    self.state.busy = false;
                    self.state.transfer = None;
                    if was_queued {
                        self.state.queue_completed += 1;
                    }
                    if vault_path != std::path::Path::new(self.state.inspect.vault_path.trim()) {
                        continue;
                    }
                    self.state.inspect.results = text;
                    self.state.inspect.set_manifest(vault_path, manifest);
                    self.state.set_status(status, false);
                    completed_transfer = true;
                }
                WorkerUpdate::RepairDone { text, vault_path } => {
                    let was_queued = self.state.active_queue_job.take().is_some();
                    self.state.busy = false;
                    self.state.transfer = None;
                    self.state.inspect.reset_manifest();
                    self.state.inspect.results = text.clone();
                    self.state.last_action = Some(LastCompletedAction {
                        summary: text.clone(),
                        reveal_path: vault_path.clone(),
                        verify_vault: Some(vault_path),
                    });
                    if was_queued {
                        self.state.queue_completed += 1;
                    }
                    self.state.set_status(text, false);
                    completed_transfer = true;
                }
                WorkerUpdate::IntegrityDone {
                    text,
                    ok,
                    sha256_only,
                } => {
                    let was_queued = self.state.active_queue_job.take().is_some();
                    self.state.busy = false;
                    self.state.transfer = None;
                    self.state.inspect.results = text;
                    self.state.inspect.reset_manifest();
                    if was_queued {
                        if !sha256_only && !ok {
                            self.state.queue_failed += 1;
                        } else {
                            self.state.queue_completed += 1;
                        }
                    }
                    let label = match (sha256_only, self.state.config.language, ok) {
                        (true, ..) => self.state.strings().digest_computed,
                        (false, AppLanguage::Tr, true) => "Bütünlük doğrulaması başarılı",
                        (false, AppLanguage::Tr, false) => "Bütünlük doğrulaması başarısız",
                        (false, AppLanguage::En, true) => "Integrity check passed",
                        (false, AppLanguage::En, false) => "Integrity check failed",
                    };
                    self.state.set_status(label, !sha256_only && !ok);
                    completed_transfer = true;
                }
                WorkerUpdate::DiffDone { text, status } => {
                    let was_queued = self.state.active_queue_job.take().is_some();
                    self.state.busy = false;
                    self.state.transfer = None;
                    self.state.diff.results = text;
                    if was_queued {
                        self.state.queue_completed += 1;
                    }
                    self.state.set_status(status, false);
                    completed_transfer = true;
                }
                WorkerUpdate::RekeyDone { status, vault_path } => {
                    let was_queued = self.state.active_queue_job.take().is_some();
                    self.state.busy = false;
                    self.state.transfer = None;
                    self.state.last_action = Some(LastCompletedAction {
                        summary: status.clone(),
                        reveal_path: vault_path.clone(),
                        verify_vault: Some(vault_path),
                    });
                    if was_queued {
                        self.state.queue_completed += 1;
                    }
                    self.state.set_status(status, false);
                    completed_transfer = true;
                }
                WorkerUpdate::Error(err) => {
                    let was_queued = self.state.active_queue_job.take().is_some();
                    self.state.busy = false;
                    self.state.progress = 0.0;
                    self.state.transfer = None;
                    if was_queued {
                        self.state.queue_failed += 1;
                        if self.cancel.load(Ordering::Relaxed) {
                            self.state.queue_paused = true;
                        }
                    }
                    self.state.set_status(err.clone(), true);
                    self.state.push_log(format!("ERROR: {err}"));
                    completed_transfer = true;
                }
            }
        }

        if completed_transfer
            && self.state.config.notify_on_complete
            && (self.state.job_queue.is_empty() || self.state.queue_paused)
            && !ctx.input(|i| i.viewport().focused.unwrap_or(true))
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                egui::UserAttentionType::Informational,
            ));
        }
    }

    pub fn maybe_start_next_queued_job(&mut self, ctx: &egui::Context) -> bool {
        if self.state.busy || self.state.queue_paused {
            return false;
        }
        let Some(job) = self.state.pop_next_queued_job() else {
            return false;
        };
        self.cancel.store(false, Ordering::Relaxed);
        let label = job.label.clone();
        let status = worker::spawn_queued_job(
            ctx.clone(),
            self.tx.clone(),
            Arc::clone(&self.cancel),
            job,
            self.state.config.language,
        );
        self.state.active_queue_job = Some(label);
        self.state.begin_transfer(status);
        true
    }

    fn handle_keyboard_shortcuts(&mut self, ctx: &egui::Context) {
        let mut digit_pressed: Option<u8> = None;
        let mut lock_pressed = false;
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
                if i.key_pressed(egui::Key::L) {
                    lock_pressed = true;
                }
            }
            if i.key_pressed(egui::Key::Escape) {
                esc_pressed = true;
            }
        });

        if lock_pressed {
            self.state
                .clear_sensitive_session(SessionClearReason::ManualPanic);
            return;
        }
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
            self.state.apply_ui_scale(ctx);
            self.theme_initialized = true;
        }

        let now = Instant::now();
        let had_user_input = ctx.input(|i| {
            i.raw.events.iter().any(|ev| {
                matches!(
                    ev,
                    egui::Event::Key { .. }
                        | egui::Event::Text(_)
                        | egui::Event::PointerButton { .. }
                        | egui::Event::PointerMoved(_)
                        | egui::Event::MouseWheel { .. }
                        | egui::Event::Touch { .. }
                        | egui::Event::Paste(_)
                        | egui::Event::MiddleClickPaste { .. }
                        | egui::Event::Zoom(_)
                        | egui::Event::Rotate(_)
                )
            })
        });
        if had_user_input {
            self.state.note_activity(now);
        }

        self.drain_updates(ctx);
        self.handle_keyboard_shortcuts(ctx);

        // Unified clipboard auto-clear timer check (Password Gen + Recovery Modal)
        if let Some(deadline) = self.state.clipboard_deadline {
            if now >= deadline {
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
            self.state.note_activity(now);
            let forced = match self.state.active_tab {
                Tab::Decrypt if dropped.iter().all(|p| !p.is_dir()) => Some(Tab::Decrypt),
                Tab::Inspect | Tab::Rekey => Some(self.state.active_tab),
                _ => None,
            };
            self.state.add_dropped_paths(dropped, forced);
        }

        self.state.check_idle_timeout(now);
        if self.state.config.idle_clear_minutes > 0
            && self.state.has_sensitive_session_data()
            && !(self.state.busy && self.state.inspect.preview_pending.is_none())
        {
            ctx.request_repaint_after(Duration::from_secs(1));
        }

        let is_hovering_files = ctx.input(|i| !i.raw.hovered_files.is_empty());

        ui.reset_style();
        let s = self.state.strings();
        let style = ctx.global_style();
        let accent = theme::accent_color(&style.visuals);

        egui::Panel::bottom("status_bar")
            .frame(egui::Frame::side_top_panel(&style).inner_margin(egui::Margin::symmetric(14, 8)))
            .show(ui, |ui| {
                if let Some(last) = self.state.last_action.clone() {
                    let mut dismiss = false;
                    ui.horizontal(|ui| {
                        ui.small(&last.summary).on_hover_text(&last.summary);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("×").clicked() {
                                dismiss = true;
                            }
                            if let Some(vault_path) = last.verify_vault {
                                let verify_btn = ui.add_enabled(
                                    !self.state.busy,
                                    egui::Button::new(s.btn_verify_now).small(),
                                );
                                if verify_btn.clicked() {
                                    self.state.select_tab(Tab::Inspect);
                                    self.state.inspect.vault_path =
                                        vault_path.display().to_string();
                                    self.state.clear_preview_and_busy();
                                    self.state.inspect.reset_manifest();
                                    self.state.busy = true;
                                    self.state.transfer = None;
                                    self.state.set_status(s.status_checking_integrity, false);
                                    worker::spawn_integrity_check(
                                        ctx.clone(),
                                        self.tx.clone(),
                                        vault_path,
                                        self.state.config.language,
                                    );
                                }
                            }
                            if ui.small_button(s.btn_reveal_folder).clicked() {
                                if let Err(err) = reveal::reveal_in_file_manager(&last.reveal_path)
                                {
                                    self.state.set_status(format!("Error: {err}"), true);
                                }
                            }
                        });
                    });
                    if dismiss {
                        self.state.last_action = None;
                    }
                    ui.separator();
                }

                ui.horizontal(|ui| {
                    if self.state.is_error {
                        ui.colored_label(egui::Color32::from_rgb(230, 80, 80), &self.state.status);
                    } else {
                        ui.label(&self.state.status);
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.state.busy && ui.button(s.btn_cancel).clicked() {
                            self.cancel.store(true, Ordering::Relaxed);
                            if let Some((_, ref preview_cancel)) =
                                self.state.inspect.preview_pending
                            {
                                preview_cancel.store(true, Ordering::Relaxed);
                            }
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
                        self.state.select_tab(tab);
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
                    let has_session_data = self.state.has_sensitive_session_data();
                    let clear_btn = ui
                        .add_enabled(
                            has_session_data,
                            egui::Button::new(s.btn_clear_session)
                                .min_size(egui::vec2(ui.available_width(), 28.0))
                                .corner_radius(egui::CornerRadius::same(6)),
                        )
                        .on_hover_text(s.clear_session_tip)
                        .on_disabled_hover_text(s.clear_session_tip);
                    if clear_btn.clicked() {
                        self.state
                            .clear_sensitive_session(SessionClearReason::ManualPanic);
                    }
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

                if !self.state.job_queue.is_empty() || self.state.active_queue_job.is_some() {
                    let s = self.state.strings();
                    ui.add_space(12.0);
                    theme::card_frame(ui.visuals()).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.strong(format!(
                                "{} ({})",
                                s.queue_heading,
                                self.state.job_queue.len()
                            ));
                            if self.state.queue_completed > 0 || self.state.queue_failed > 0 {
                                ui.weak(format!(
                                    "[ok: {}, err: {}]",
                                    self.state.queue_completed, self.state.queue_failed
                                ));
                            }
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if !self.state.job_queue.is_empty()
                                        && ui.small_button(s.btn_queue_clear).clicked()
                                    {
                                        self.state.clear_pending_queue();
                                    }
                                    let toggle_lbl = if self.state.queue_paused {
                                        s.btn_queue_resume
                                    } else {
                                        s.btn_queue_pause
                                    };
                                    if ui.small_button(toggle_lbl).clicked() {
                                        self.state.queue_paused = !self.state.queue_paused;
                                    }
                                },
                            );
                        });
                        if let Some(ref active_label) = self.state.active_queue_job {
                            ui.small(format!("▶ {active_label}"));
                        }
                        if self.state.queue_paused {
                            ui.colored_label(
                                egui::Color32::from_rgb(225, 175, 50),
                                s.queue_paused_label,
                            );
                        }

                        let mut remove_id: Option<u64> = None;
                        let mut move_up: Option<usize> = None;
                        let mut move_down: Option<usize> = None;
                        let pending_len = self.state.job_queue.len();
                        for (idx, job) in self.state.job_queue.iter().enumerate() {
                            ui.horizontal(|ui| {
                                ui.label(format!("{}. {}", idx + 1, job.label));
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.small_button("×").clicked() {
                                            remove_id = Some(job.id);
                                        }
                                        if ui
                                            .add_enabled(
                                                idx + 1 < pending_len,
                                                egui::Button::new("↓").small(),
                                            )
                                            .clicked()
                                        {
                                            move_down = Some(idx);
                                        }
                                        if ui
                                            .add_enabled(idx > 0, egui::Button::new("↑").small())
                                            .clicked()
                                        {
                                            move_up = Some(idx);
                                        }
                                    },
                                );
                            });
                        }
                        if let Some(id) = remove_id {
                            self.state.remove_queued_job(id);
                        }
                        if let Some(idx) = move_up {
                            self.state.move_queued_job_up(idx);
                        }
                        if let Some(idx) = move_down {
                            self.state.move_queued_job_down(idx);
                        }
                    });
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

        self.maybe_start_next_queued_job(ctx);
    }
}

#[cfg(test)]
mod preview_tests {
    use super::*;
    use rpm_storage::config::AppConfig;
    use zeroize::Zeroizing;

    fn isolated_app() -> RpmApp {
        let (tx, rx) = mpsc::channel();
        RpmApp {
            state: AppState::from_config(AppConfig::default(), None),
            tx,
            rx,
            cancel: Arc::new(AtomicBool::new(false)),
            theme_initialized: false,
        }
    }

    #[test]
    fn late_preview_after_escape_is_discarded() {
        let mut app = isolated_app();
        app.state.select_tab(Tab::Inspect);
        app.state.busy = true;
        let (gen, cancel) = app.state.inspect.begin_preview();
        assert!(app.state.dismiss_modals());
        assert!(cancel.load(Ordering::Relaxed));
        assert!(!app.state.busy, "Esc during preview must release busy lock");
        app.tx
            .send(WorkerUpdate::PreviewDone {
                gen,
                path: "note".into(),
                bytes: Zeroizing::new(b"private".to_vec()),
                status: "ready".into(),
            })
            .unwrap();
        app.drain_updates(&egui::Context::default());
        assert!(app.state.inspect.preview.is_none());
        assert!(!app.state.busy);
        assert!(app.state.transfer.is_none());
    }

    #[test]
    fn cancel_button_and_tab_switch_during_pending_preview_release_busy_lock() {
        // 1. Cancel button sets preview_cancel while worker finishes with PreviewDone.
        let mut app = isolated_app();
        app.state.select_tab(Tab::Inspect);
        app.state.begin_transfer("loading");
        let (gen, cancel) = app.state.inspect.begin_preview();
        cancel.store(true, Ordering::Relaxed);
        app.tx
            .send(WorkerUpdate::PreviewDone {
                gen,
                path: "note".into(),
                bytes: Zeroizing::new(b"private".to_vec()),
                status: "ready".into(),
            })
            .unwrap();
        app.drain_updates(&egui::Context::default());
        assert!(app.state.inspect.preview.is_none());
        assert!(app.state.inspect.preview_pending.is_none());
        assert!(!app.state.busy);

        // 2. Switching away from Inspect during pending preview cancels & releases busy lock,
        //    and stale late Progress/PreviewDone updates do not re-pollute transfer/preview.
        app.state.select_tab(Tab::Inspect);
        app.state.begin_transfer("loading");
        let (gen2, cancel2) = app.state.inspect.begin_preview();
        app.state.select_tab(Tab::Encrypt);
        assert!(cancel2.load(Ordering::Relaxed));
        assert!(!app.state.busy);
        app.tx
            .send(WorkerUpdate::Progress(crate::progress::TransferSnapshot {
                fraction: 0.5,
                bytes_done: 50,
                bytes_total: 100,
                bytes_per_sec: None,
                eta: None,
                item_index: None,
            }))
            .unwrap();
        app.tx
            .send(WorkerUpdate::PreviewDone {
                gen: gen2,
                path: "note".into(),
                bytes: Zeroizing::new(b"private".to_vec()),
                status: "ready".into(),
            })
            .unwrap();
        app.drain_updates(&egui::Context::default());
        assert!(app.state.inspect.preview.is_none());
        assert!(app.state.transfer.is_none());
        assert!(!app.state.busy);
    }

    #[test]
    fn stale_preview_generation_does_not_overwrite_newer_request() {
        let mut app = isolated_app();
        app.state.select_tab(Tab::Inspect);
        let (gen1, cancel1) = app.state.inspect.begin_preview();
        let (gen2, cancel2) = app.state.inspect.begin_preview();
        assert!(cancel1.load(Ordering::Relaxed));
        assert!(!cancel2.load(Ordering::Relaxed));
        app.state.busy = true;

        app.tx
            .send(WorkerUpdate::PreviewDone {
                gen: gen1,
                path: "old".into(),
                bytes: Zeroizing::new(b"stale".to_vec()),
                status: "stale".into(),
            })
            .unwrap();
        app.drain_updates(&egui::Context::default());
        assert!(app.state.busy);
        assert!(app.state.inspect.preview.is_none());

        app.tx
            .send(WorkerUpdate::PreviewDone {
                gen: gen2,
                path: "new".into(),
                bytes: Zeroizing::new(b"fresh".to_vec()),
                status: "fresh".into(),
            })
            .unwrap();
        app.drain_updates(&egui::Context::default());
        assert!(!app.state.busy);
        assert!(app.state.inspect.preview.is_some());
    }

    #[test]
    fn drain_updates_discards_stale_source_scan_generation() {
        let mut app = isolated_app();
        app.state.encrypt.preflight_scan_gen = 5;
        app.state.encrypt.preflight_scanning = true;

        let stale = crate::estimator::SourceSizeSummary {
            file_count: 99,
            raw_bytes: 9999,
            ..Default::default()
        };
        app.tx
            .send(WorkerUpdate::SourceScanDone {
                gen: 4,
                outer: stale,
                hidden: crate::estimator::SourceSizeSummary::default(),
            })
            .unwrap();
        app.drain_updates(&egui::Context::default());
        assert!(app.state.encrypt.preflight_scanning);
        assert_eq!(app.state.encrypt.preflight_outer.file_count, 0);

        let fresh = crate::estimator::SourceSizeSummary {
            file_count: 3,
            raw_bytes: 2048,
            ..Default::default()
        };
        app.tx
            .send(WorkerUpdate::SourceScanDone {
                gen: 5,
                outer: fresh.clone(),
                hidden: crate::estimator::SourceSizeSummary::default(),
            })
            .unwrap();
        app.drain_updates(&egui::Context::default());
        assert!(!app.state.encrypt.preflight_scanning);
        assert_eq!(app.state.encrypt.preflight_outer, fresh);
    }

    #[test]
    fn drain_updates_populates_last_action_and_preserves_queued_sources() {
        let mut app = isolated_app();
        let ctx = egui::Context::default();

        // Direct encrypt clears sources and enables Verify + Reveal
        app.state.encrypt.sources = vec![PathBuf::from("draft.txt")];
        app.state.busy = true;
        app.tx
            .send(WorkerUpdate::EncryptDone {
                status: "ok".into(),
                output_path: PathBuf::from("out.vault"),
            })
            .unwrap();
        app.drain_updates(&ctx);
        assert!(app.state.encrypt.sources.is_empty());
        let last = app.state.last_action.as_ref().unwrap();
        assert_eq!(last.reveal_path, PathBuf::from("out.vault"));
        assert_eq!(last.verify_vault, Some(PathBuf::from("out.vault")));

        // Queued encrypt preserves newly drafted sources, increments queue_completed
        app.state.encrypt.sources = vec![PathBuf::from("next_draft.txt")];
        app.state.active_queue_job = Some("Queued".into());
        app.state.busy = true;
        app.tx
            .send(WorkerUpdate::EncryptDone {
                status: "queued ok".into(),
                output_path: PathBuf::from("queued.vault"),
            })
            .unwrap();
        app.drain_updates(&ctx);
        assert_eq!(
            app.state.encrypt.sources,
            vec![PathBuf::from("next_draft.txt")]
        );
        assert_eq!(app.state.queue_completed, 1);

        // Decrypt sets reveal_path with verify_vault == None
        app.state.busy = true;
        app.tx
            .send(WorkerUpdate::DecryptDone {
                status: "dec ok".into(),
                output_path: Some(PathBuf::from("extracted_dir")),
            })
            .unwrap();
        app.drain_updates(&ctx);
        let last_dec = app.state.last_action.as_ref().unwrap();
        assert_eq!(last_dec.reveal_path, PathBuf::from("extracted_dir"));
        assert_eq!(last_dec.verify_vault, None);
    }

    #[test]
    fn queue_auto_advances_end_to_end_and_pauses_on_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("doc.txt");
        let out_dir = dir.path().join("out");
        std::fs::create_dir(&out_dir).unwrap();
        std::fs::write(&src, b"queued payload bytes").unwrap();
        let expected_vault = out_dir.join("doc.txt.vault");

        let ctx = egui::Context::default();
        let mut app = isolated_app();
        app.enqueue_test_encrypt_then_verify(
            &ctx,
            src.clone(),
            out_dir.clone(),
            expected_vault.clone(),
        );
        assert!(!expected_vault.exists());

        // Start job 1 (Encrypt)
        assert!(app.maybe_start_next_queued_job(&ctx));
        assert!(app.state.busy);
        assert_eq!(app.state.job_queue.len(), 1);

        let deadline = Instant::now() + Duration::from_secs(30);
        while app.state.busy && Instant::now() < deadline {
            app.drain_updates(&ctx);
            std::thread::sleep(Duration::from_millis(15));
        }
        app.drain_updates(&ctx);
        assert!(!app.state.busy);
        assert!(expected_vault.is_file());
        assert_eq!(app.state.queue_completed, 1);

        // Start job 2 (IntegrityCheck)
        assert!(app.maybe_start_next_queued_job(&ctx));
        let deadline = Instant::now() + Duration::from_secs(30);
        while app.state.busy && Instant::now() < deadline {
            app.drain_updates(&ctx);
            std::thread::sleep(Duration::from_millis(15));
        }
        app.drain_updates(&ctx);
        assert!(!app.state.busy);
        assert_eq!(app.state.queue_completed, 2);
        assert_eq!(app.state.queue_failed, 0);
        assert!(!app.state.is_error);

        // Cancel during a queued job pauses remaining queue
        app.state
            .enqueue_job(crate::queue::QueuedJobKind::IntegrityCheck {
                path: expected_vault,
            });
        app.state.active_queue_job = Some("active".into());
        app.state.busy = true;
        app.cancel.store(true, Ordering::Relaxed);
        app.tx
            .send(WorkerUpdate::Error("cancelled".into()))
            .unwrap();
        app.drain_updates(&ctx);
        assert!(app.state.queue_paused);
        assert_eq!(app.state.queue_failed, 1);
        assert!(!app.maybe_start_next_queued_job(&ctx));
    }

    impl RpmApp {
        fn enqueue_test_encrypt_then_verify(
            &mut self,
            _ctx: &egui::Context,
            src: PathBuf,
            out_dir: PathBuf,
            expected_vault: PathBuf,
        ) {
            self.state
                .enqueue_job(crate::queue::QueuedJobKind::Encrypt {
                    sources: vec![src],
                    password: Zeroizing::new("QueuePass!1".into()),
                    recovery_entropy: rpm_core::generate_recovery_entropy(),
                    keyfile: None,
                    output_dir: Some(out_dir),
                    compress: true,
                    container_size_bytes: None,
                    stealth: false,
                    reed_solomon: false,
                    secure_wipe: false,
                    wipe_passes: 1,
                    kdf: rpm_core::KdfParams::fast_test(),
                });
            self.state
                .enqueue_job(crate::queue::QueuedJobKind::IntegrityCheck {
                    path: expected_vault,
                });
        }
    }
}
