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

    pub fn clear_sensitive_session(&mut self, reason: SessionClearReason) {
        self.cancel.store(true, Ordering::Relaxed);
        self.state.clear_sensitive_session(reason);
    }

    pub fn request_cancel(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.state.cancel_active_job();
        if self.state.active_queue_job.is_some() || !self.state.job_queue.is_empty() {
            self.state.queue_paused = true;
        }
        let msg = self.state.strings().status_cancelling;
        self.state.set_status(msg, false);
    }

    fn select_tab_synced(&mut self, tab: Tab) {
        let had_pending = tab != Tab::Inspect && self.state.inspect.preview_pending.is_some();
        self.state.select_tab(tab);
        if had_pending {
            self.cancel.store(false, Ordering::Relaxed);
        }
    }

    fn is_active_job_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed) || self.state.is_active_job_cancelled()
    }

    fn finish_cancelled_done(&mut self, was_queued: bool) {
        self.state.finish_active_job();
        self.state.progress = 0.0;
        self.cancel.store(false, Ordering::Relaxed);
        if was_queued {
            self.state.queue_paused = true;
            self.state.queue_failed += 1;
        }
        let msg = self.state.strings().status_cancelled;
        self.state.set_status(msg, false);
    }

    pub fn drain_updates(&mut self, ctx: &egui::Context) {
        let mut completed_transfer = false;
        while let Ok(raw_msg) = self.rx.try_recv() {
            let msg = match raw_msg {
                WorkerUpdate::Scoped {
                    epoch,
                    job_id,
                    update,
                } => {
                    if epoch != self.state.session_epoch() {
                        continue;
                    }
                    let inner = *update;
                    if !matches!(inner, WorkerUpdate::SourceScanDone { .. })
                        && (job_id == 0 || job_id != self.state.active_job_id())
                    {
                        continue;
                    }
                    inner
                }
                other => other,
            };
            match msg {
                WorkerUpdate::Scoped { .. } => unreachable!("unwrapped above"),
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
                            let cancelled =
                                c.load(Ordering::Relaxed) || self.is_active_job_cancelled();
                            self.state.inspect.preview_pending = None;
                            self.state.finish_active_job();
                            self.cancel.store(false, Ordering::Relaxed);
                            if cancelled {
                                self.state.progress = 0.0;
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
                        self.state.finish_active_job();
                        self.state.progress = 0.0;
                        self.cancel.store(false, Ordering::Relaxed);
                        self.state.set_status(message.clone(), !cancelled);
                        if !cancelled {
                            self.state.push_log(format!("ERROR: {message}"));
                        }
                    }
                }
                WorkerUpdate::Progress(snap) => {
                    if self.state.busy && !self.is_active_job_cancelled() {
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
                    if self.is_active_job_cancelled() {
                        self.finish_cancelled_done(was_queued);
                        continue;
                    }
                    self.state.finish_active_job();
                    self.state.progress = 1.0;
                    self.cancel.store(false, Ordering::Relaxed);
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
                    if self.is_active_job_cancelled() {
                        self.finish_cancelled_done(was_queued);
                        continue;
                    }
                    self.state.finish_active_job();
                    self.state.progress = 1.0;
                    self.cancel.store(false, Ordering::Relaxed);
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
                    if self.is_active_job_cancelled() {
                        self.finish_cancelled_done(was_queued);
                        continue;
                    }
                    self.state.finish_active_job();
                    self.cancel.store(false, Ordering::Relaxed);
                    if was_queued {
                        self.state.queue_completed += 1;
                    }
                    if vault_path != std::path::Path::new(self.state.inspect.vault_path.trim()) {
                        let msg = self.state.strings().status_ready;
                        self.state.set_status(msg, false);
                        continue;
                    }
                    self.state.inspect.results = text;
                    self.state.inspect.set_manifest(vault_path, manifest);
                    self.state.set_status(status, false);
                    completed_transfer = true;
                }
                WorkerUpdate::RepairDone { text, vault_path } => {
                    let was_queued = self.state.active_queue_job.take().is_some();
                    if self.is_active_job_cancelled() {
                        self.finish_cancelled_done(was_queued);
                        continue;
                    }
                    self.state.finish_active_job();
                    self.cancel.store(false, Ordering::Relaxed);
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
                    if self.is_active_job_cancelled() {
                        self.finish_cancelled_done(was_queued);
                        continue;
                    }
                    self.state.finish_active_job();
                    self.cancel.store(false, Ordering::Relaxed);
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
                    if self.is_active_job_cancelled() {
                        self.finish_cancelled_done(was_queued);
                        continue;
                    }
                    self.state.finish_active_job();
                    self.cancel.store(false, Ordering::Relaxed);
                    self.state.diff.results = text;
                    if was_queued {
                        self.state.queue_completed += 1;
                    }
                    self.state.set_status(status, false);
                    completed_transfer = true;
                }
                WorkerUpdate::RekeyDone { status, vault_path } => {
                    let was_queued = self.state.active_queue_job.take().is_some();
                    if self.is_active_job_cancelled() {
                        self.finish_cancelled_done(was_queued);
                        continue;
                    }
                    self.state.finish_active_job();
                    self.cancel.store(false, Ordering::Relaxed);
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
                WorkerUpdate::SplitDone { status, first_part } => {
                    let was_queued = self.state.active_queue_job.take().is_some();
                    if self.is_active_job_cancelled() {
                        self.finish_cancelled_done(was_queued);
                        continue;
                    }
                    self.state.finish_active_job();
                    self.state.progress = 1.0;
                    self.cancel.store(false, Ordering::Relaxed);
                    self.state.last_action = Some(LastCompletedAction {
                        summary: status.clone(),
                        reveal_path: first_part.clone(),
                        verify_vault: Some(first_part),
                    });
                    if was_queued {
                        self.state.queue_completed += 1;
                    }
                    self.state.set_status(status, false);
                    completed_transfer = true;
                }
                WorkerUpdate::JoinDone {
                    status,
                    output_path,
                } => {
                    let was_queued = self.state.active_queue_job.take().is_some();
                    if self.is_active_job_cancelled() {
                        self.finish_cancelled_done(was_queued);
                        continue;
                    }
                    self.state.finish_active_job();
                    self.state.progress = 1.0;
                    self.cancel.store(false, Ordering::Relaxed);
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
                WorkerUpdate::Error(err) => {
                    let was_queued = self.state.active_queue_job.take().is_some();
                    let was_cancelled = self.is_active_job_cancelled();
                    self.state.finish_active_job();
                    self.state.progress = 0.0;
                    self.cancel.store(false, Ordering::Relaxed);
                    if was_queued {
                        self.state.queue_failed += 1;
                        if was_cancelled {
                            self.state.queue_paused = true;
                        }
                    }
                    if was_cancelled {
                        let s = self.state.strings();
                        let msg = if err == s.repair_cancelled {
                            err
                        } else {
                            s.status_cancelled.to_string()
                        };
                        self.state.set_status(msg, false);
                    } else {
                        self.state.set_status(err.clone(), true);
                        self.state.push_log(format!("ERROR: {err}"));
                        completed_transfer = true;
                    }
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
        let label = job.label.clone();
        let (scope, job_cancel) = self.state.begin_job(&self.cancel);
        let status = worker::spawn_queued_job_scoped(
            ctx.clone(),
            self.tx.clone(),
            job_cancel,
            Some(scope),
            job,
            usize::from(self.state.config.pipeline_threads),
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
            let frame_ctrl = i.modifiers.ctrl || i.modifiers.command;
            for ev in &i.events {
                if let egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } = ev
                {
                    let ctrl = frame_ctrl || modifiers.ctrl || modifiers.command;
                    if ctrl {
                        if digit_pressed.is_none() {
                            digit_pressed = match key {
                                egui::Key::Num1 => Some(1),
                                egui::Key::Num2 => Some(2),
                                egui::Key::Num3 => Some(3),
                                egui::Key::Num4 => Some(4),
                                egui::Key::Num5 => Some(5),
                                egui::Key::Num6 => Some(6),
                                _ => None,
                            };
                        }
                        if *key == egui::Key::L {
                            lock_pressed = true;
                        }
                    }
                    if *key == egui::Key::Escape {
                        esc_pressed = true;
                    }
                }
            }
        });

        if lock_pressed {
            self.clear_sensitive_session(SessionClearReason::ManualPanic);
            return;
        }
        if let Some(d) = digit_pressed {
            let had_pending = self.state.inspect.preview_pending.is_some();
            if self.state.handle_shortcut_tab(d) && had_pending && !self.state.busy {
                self.cancel.store(false, Ordering::Relaxed);
            }
        }
        if esc_pressed {
            let had_pending = self.state.inspect.preview_pending.is_some();
            if self.state.dismiss_modals() {
                if had_pending {
                    self.cancel.store(false, Ordering::Relaxed);
                }
            } else if self.state.busy {
                self.request_cancel();
            }
        }
    }

    pub(crate) fn render_ui(&mut self, ui: &mut egui::Ui) {
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

        if self.state.check_idle_timeout(now) {
            self.cancel.store(true, Ordering::Relaxed);
        }
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
                                    let (scope, job_cancel) = self
                                        .state
                                        .begin_busy_job(s.status_checking_integrity, &self.cancel);
                                    worker::spawn_integrity_check_scoped(
                                        ctx.clone(),
                                        self.tx.clone(),
                                        job_cancel,
                                        Some(scope),
                                        vault_path,
                                        usize::from(self.state.config.pipeline_threads),
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
                            self.request_cancel();
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
                        self.select_tab_synced(tab);
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
                        self.clear_sensitive_session(SessionClearReason::ManualPanic);
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

impl eframe::App for RpmApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.render_ui(ui);
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
                    split_part_bytes: None,
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

    #[test]
    fn all_nine_done_arms_honor_cancel_and_cancel_pauses_active_queued_job_immediately() {
        let ctx = egui::Context::default();
        let dir = tempfile::tempdir().unwrap();
        let precious = dir.path().join("precious.txt");
        std::fs::write(&precious, b"do not wipe").unwrap();

        let make_done_cases = || -> Vec<WorkerUpdate> {
            vec![
                WorkerUpdate::EncryptDone {
                    status: "enc".into(),
                    output_path: dir.path().join("a.vault"),
                },
                WorkerUpdate::DecryptDone {
                    status: "dec".into(),
                    output_path: Some(dir.path().join("out")),
                },
                WorkerUpdate::InspectDone {
                    text: "SECRET MANIFEST".into(),
                    status: "ins".into(),
                    manifest: vec![rpm_core::FileManifestEntry {
                        path: "secret.txt".into(),
                        size: 42,
                        modified_unix: 1,
                    }],
                    vault_path: dir.path().join("a.vault"),
                },
                WorkerUpdate::RepairDone {
                    text: "repaired".into(),
                    vault_path: dir.path().join("a.vault"),
                },
                WorkerUpdate::IntegrityDone {
                    text: "INTEGRITY OK".into(),
                    ok: true,
                    sha256_only: false,
                },
                WorkerUpdate::DiffDone {
                    text: "DIFF SECRET".into(),
                    status: "diff".into(),
                },
                WorkerUpdate::RekeyDone {
                    status: "rekey".into(),
                    vault_path: dir.path().join("a.vault"),
                },
                WorkerUpdate::SplitDone {
                    status: "split".into(),
                    first_part: dir.path().join("a.vault.001"),
                },
                WorkerUpdate::JoinDone {
                    status: "join".into(),
                    output_path: dir.path().join("a.vault"),
                },
            ]
        };

        for done in make_done_cases() {
            let mut app = isolated_app();
            app.state.encrypt.sources = vec![precious.clone()];
            app.state.inspect.vault_path = dir.path().join("a.vault").display().to_string();
            let default_ins = app.state.inspect.results.clone();
            let default_diff = app.state.diff.results.clone();

            let (scope, _job_cancel) = app.state.begin_transfer_job("working", &app.cancel);
            app.state.progress = 0.7;
            app.request_cancel();

            app.tx
                .send(WorkerUpdate::Scoped {
                    epoch: scope.epoch,
                    job_id: scope.job_id,
                    update: Box::new(done),
                })
                .unwrap();
            app.drain_updates(&ctx);

            assert!(!app.state.busy);
            assert_eq!(app.state.progress, 0.0);
            assert!(!app.state.is_error);
            assert_eq!(app.state.status, app.state.strings().status_cancelled);
            assert_eq!(app.state.encrypt.sources, vec![precious.clone()]);
            assert!(app.state.last_action.is_none());
            assert_eq!(app.state.inspect.results, default_ins);
            assert!(app.state.inspect.manifest.is_empty());
            assert_eq!(app.state.diff.results, default_diff);
        }

        // Active queued job + waiting secure_wipe job: request_cancel immediately pauses queue
        // so even a racing EncryptDone cannot auto-start the next queued job.
        let mut app = isolated_app();
        app.state.enqueue_job(crate::queue::QueuedJobKind::Encrypt {
            sources: vec![precious.clone()],
            password: Zeroizing::new("WipePass!1".into()),
            recovery_entropy: rpm_core::generate_recovery_entropy(),
            keyfile: None,
            output_dir: Some(dir.path().to_path_buf()),
            compress: false,
            container_size_bytes: None,
            split_part_bytes: None,
            stealth: false,
            reed_solomon: false,
            secure_wipe: true,
            wipe_passes: 1,
            kdf: rpm_core::KdfParams::fast_test(),
        });
        let (scope, _job_cancel) = app.state.begin_transfer_job("active queued", &app.cancel);
        app.state.active_queue_job = Some("active job".into());
        assert!(!app.state.queue_paused);

        app.request_cancel();
        assert!(
            app.state.queue_paused,
            "Cancel/Esc during an active queued job must immediately pause the queue"
        );

        app.tx
            .send(WorkerUpdate::Scoped {
                epoch: scope.epoch,
                job_id: scope.job_id,
                update: Box::new(WorkerUpdate::EncryptDone {
                    status: "raced done".into(),
                    output_path: dir.path().join("raced.vault"),
                }),
            })
            .unwrap();
        app.drain_updates(&ctx);

        assert!(!app.state.busy);
        assert!(app.state.queue_paused);
        assert_eq!(app.state.queue_failed, 1);
        assert_eq!(app.state.queue_completed, 0);
        assert!(app.state.last_action.is_none());
        assert!(!app.maybe_start_next_queued_job(&ctx));
        assert_eq!(std::fs::read(&precious).unwrap(), b"do not wipe");
    }

    #[test]
    fn scoped_workers_honor_cancel_for_integrity_inspect_diff_and_wipe_sources() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("keep_unwiped.txt");
        std::fs::write(&src, b"keep this payload").unwrap();
        let vault_a = dir.path().join("a.vault");
        let vault_b = dir.path().join("b.vault");

        let no_cancel = Arc::new(AtomicBool::new(false));
        let opts = rpm_core::EncryptOptions {
            kdf: rpm_core::KdfParams::fast_test(),
            compressed: false,
            ..Default::default()
        };
        rpm_storage::encrypt_sources_v5(
            std::slice::from_ref(&src),
            &vault_a,
            b"TestPass!1",
            &opts,
            Arc::new(|_, _| {}),
            Arc::clone(&no_cancel),
            |_| {},
        )
        .unwrap();
        rpm_storage::encrypt_sources_v5(
            std::slice::from_ref(&src),
            &vault_b,
            b"TestPass!1",
            &opts,
            Arc::new(|_, _| {}),
            Arc::clone(&no_cancel),
            |_| {},
        )
        .unwrap();

        let ctx = egui::Context::default();
        let scope = worker::WorkerScope {
            epoch: 7,
            job_id: 99,
        };
        let pre_cancel = Arc::new(AtomicBool::new(true));
        let expect_cancelled = |rx: &mpsc::Receiver<WorkerUpdate>| {
            let msg = rx.recv_timeout(Duration::from_secs(10)).unwrap();
            match msg {
                WorkerUpdate::Scoped {
                    epoch,
                    job_id,
                    update,
                } => {
                    assert_eq!(epoch, scope.epoch);
                    assert_eq!(job_id, scope.job_id);
                    match *update {
                        WorkerUpdate::Error(err) => {
                            assert_eq!(err, crate::i18n::EN.status_cancelled);
                        }
                        other => panic!("expected cancelled Error, got {other:?}"),
                    }
                }
                other => panic!("expected Scoped update, got {other:?}"),
            }
        };

        // 1. QueuedJobKind::IntegrityCheck propagates cancel
        let (tx, rx) = mpsc::channel();
        worker::spawn_queued_job_scoped(
            ctx.clone(),
            tx,
            Arc::clone(&pre_cancel),
            Some(scope),
            crate::queue::QueuedJob {
                id: 1,
                label: "verify".into(),
                kind: crate::queue::QueuedJobKind::IntegrityCheck {
                    path: vault_a.clone(),
                },
            },
            2,
            AppLanguage::En,
        );
        expect_cancelled(&rx);

        // 2. Inspect propagates cancel
        let (tx, rx) = mpsc::channel();
        worker::spawn_inspect_scoped(
            ctx.clone(),
            tx,
            Arc::clone(&pre_cancel),
            Some(scope),
            vault_a.clone(),
            false,
            Zeroizing::new("TestPass!1".into()),
            None,
            2,
            AppLanguage::En,
        );
        expect_cancelled(&rx);

        // 3. Vault Diff propagates cancel
        let (tx, rx) = mpsc::channel();
        worker::spawn_vault_diff_scoped(
            ctx.clone(),
            tx,
            Arc::clone(&pre_cancel),
            Some(scope),
            worker::VaultDiffTarget {
                path: vault_a,
                use_recovery: false,
                secret: Zeroizing::new("TestPass!1".into()),
                keyfile: None,
            },
            worker::VaultDiffTarget {
                path: vault_b,
                use_recovery: false,
                secret: Zeroizing::new("TestPass!1".into()),
                keyfile: None,
            },
            2,
            AppLanguage::En,
        );
        expect_cancelled(&rx);

        // 4. Encrypt with secure_wipe=true honors cancel without wiping source
        let (tx, rx) = mpsc::channel();
        worker::spawn_encrypt_scoped(
            ctx,
            tx,
            Arc::clone(&pre_cancel),
            Some(scope),
            vec![src.clone()],
            Zeroizing::new("TestPass!1".into()),
            rpm_core::generate_recovery_entropy(),
            None,
            Some(dir.path().to_path_buf()),
            false,
            None,
            None,
            false,
            false,
            true,
            1,
            rpm_core::KdfParams::fast_test(),
            2,
            AppLanguage::En,
        );
        expect_cancelled(&rx);
        assert_eq!(std::fs::read(&src).unwrap(), b"keep this payload");
    }

    #[test]
    fn clear_sensitive_session_fences_stale_updates_cancels_workers_and_preserves_clipboard() {
        let ctx = egui::Context::default();
        let mut app = isolated_app();
        let clip_deadline = Instant::now() + Duration::from_secs(20);
        app.state.clipboard_deadline = Some(clip_deadline);
        app.state.inspect.vault_path = "secret.vault".into();
        app.state.encrypt.preflight_scanning = true;
        let preflight_cancel = Arc::new(AtomicBool::new(false));
        app.state.encrypt.preflight_scan_cancel = Some(Arc::clone(&preflight_cancel));

        let (old_scope, old_job_cancel) = app.state.begin_busy_job("inspecting", &app.cancel);
        app.state.active_queue_job = Some("queued secret".into());
        app.state
            .enqueue_job(crate::queue::QueuedJobKind::IntegrityCheck {
                path: PathBuf::from("secret.vault"),
            });

        let old_epoch = app.state.session_epoch();
        app.clear_sensitive_session(SessionClearReason::ManualPanic);

        assert!(app.cancel.load(Ordering::Relaxed));
        assert!(old_job_cancel.load(Ordering::Relaxed));
        assert!(preflight_cancel.load(Ordering::Relaxed));
        assert!(!app.state.encrypt.preflight_scanning);
        assert_eq!(app.state.session_epoch(), old_epoch + 1);
        assert_eq!(app.state.active_job_id(), 0);
        assert!(app.state.active_queue_job.is_none());
        assert!(app.state.job_queue.is_empty());
        assert!(!app.state.busy);
        assert!(!app.state.has_sensitive_session_data());
        assert_eq!(
            app.state.clipboard_deadline,
            Some(clip_deadline),
            "clipboard-safe clear must never alter clipboard_deadline"
        );

        let default_ins = app.state.inspect.results.clone();
        let default_diff = app.state.diff.results.clone();
        let panic_status = app.state.status.clone();

        let stale_updates = vec![
            WorkerUpdate::Log("LEAKED PATH /secret/file".into()),
            WorkerUpdate::Progress(crate::progress::TransferSnapshot {
                fraction: 0.88,
                bytes_done: 88,
                bytes_total: 100,
                bytes_per_sec: None,
                eta: None,
                item_index: None,
            }),
            WorkerUpdate::InspectDone {
                text: "LEAKED MANIFEST".into(),
                status: "unlocked".into(),
                manifest: vec![rpm_core::FileManifestEntry {
                    path: "top_secret.pdf".into(),
                    size: 123,
                    modified_unix: 0,
                }],
                vault_path: PathBuf::from("secret.vault"),
            },
            WorkerUpdate::DiffDone {
                text: "LEAKED DIFF".into(),
                status: "diffed".into(),
            },
            WorkerUpdate::IntegrityDone {
                text: "LEAKED INTEGRITY".into(),
                ok: true,
                sha256_only: false,
            },
            WorkerUpdate::EncryptDone {
                status: "LEAKED ENC".into(),
                output_path: PathBuf::from("leaked.vault"),
            },
            WorkerUpdate::DecryptDone {
                status: "LEAKED DEC".into(),
                output_path: Some(PathBuf::from("leaked_dir")),
            },
            WorkerUpdate::RepairDone {
                text: "LEAKED REPAIR".into(),
                vault_path: PathBuf::from("leaked.vault"),
            },
            WorkerUpdate::RekeyDone {
                status: "LEAKED REKEY".into(),
                vault_path: PathBuf::from("leaked.vault"),
            },
            WorkerUpdate::SplitDone {
                status: "LEAKED SPLIT".into(),
                first_part: PathBuf::from("leaked.vault.001"),
            },
            WorkerUpdate::JoinDone {
                status: "LEAKED JOIN".into(),
                output_path: PathBuf::from("leaked.vault"),
            },
            WorkerUpdate::PreviewDone {
                gen: 1,
                path: "leaked.txt".into(),
                bytes: Zeroizing::new(b"leaked".to_vec()),
                status: "ready".into(),
            },
            WorkerUpdate::PreviewError {
                gen: 1,
                message: "leaked err".into(),
                cancelled: false,
            },
            WorkerUpdate::Error("LEAKED ERROR".into()),
            WorkerUpdate::SourceScanDone {
                gen: app.state.encrypt.preflight_scan_gen,
                outer: crate::estimator::SourceSizeSummary {
                    file_count: 7,
                    raw_bytes: 777,
                    ..Default::default()
                },
                hidden: crate::estimator::SourceSizeSummary::default(),
            },
        ];
        for stale in stale_updates {
            app.tx
                .send(WorkerUpdate::Scoped {
                    epoch: old_scope.epoch,
                    job_id: old_scope.job_id,
                    update: Box::new(stale),
                })
                .unwrap();
        }
        app.drain_updates(&ctx);

        assert!(app.state.logs.is_empty());
        assert_eq!(app.state.inspect.results, default_ins);
        assert!(app.state.inspect.manifest.is_empty());
        assert_eq!(app.state.diff.results, default_diff);
        assert!(app.state.last_action.is_none());
        assert!(app.state.inspect.preview.is_none());
        assert!(app.state.transfer.is_none());
        assert_eq!(app.state.progress, 0.0);
        assert_eq!(app.state.status, panic_status);
        assert_eq!(app.state.encrypt.preflight_outer.file_count, 0);

        // Starting a fresh job in the new epoch must NEVER un-cancel the old worker's token.
        let (new_scope, new_job_cancel) = app.state.begin_transfer_job("fresh job", &app.cancel);
        assert!(old_job_cancel.load(Ordering::Relaxed));
        assert!(!new_job_cancel.load(Ordering::Relaxed));
        assert_ne!(new_scope.epoch, old_scope.epoch);
    }

    #[test]
    fn abandoned_preview_progress_does_not_overwrite_new_job_progress() {
        let ctx = egui::Context::default();
        let mut app = isolated_app();
        app.state.select_tab(Tab::Inspect);

        let (gen1, scope1, cancel1) = app.state.begin_preview_job("loading preview", &app.cancel);
        assert!(app.state.busy);

        // User abandons preview via Esc / tab switch
        assert!(app.state.clear_preview_and_busy());
        assert!(cancel1.load(Ordering::Relaxed));
        assert!(!app.state.busy);

        // User starts a new Encrypt transfer job
        let (scope2, _cancel2) = app.state.begin_transfer_job("encrypting", &app.cancel);
        assert_ne!(scope1.job_id, scope2.job_id);

        // Job 2 reports 25% progress
        app.tx
            .send(WorkerUpdate::Scoped {
                epoch: scope2.epoch,
                job_id: scope2.job_id,
                update: Box::new(WorkerUpdate::Progress(crate::progress::TransferSnapshot {
                    fraction: 0.25,
                    bytes_done: 25,
                    bytes_total: 100,
                    bytes_per_sec: None,
                    eta: None,
                    item_index: None,
                })),
            })
            .unwrap();
        app.drain_updates(&ctx);
        assert!((app.state.progress - 0.25).abs() < 1e-6);

        // Abandoned preview thread emits late 99% Progress + PreviewError
        app.tx
            .send(WorkerUpdate::Scoped {
                epoch: scope1.epoch,
                job_id: scope1.job_id,
                update: Box::new(WorkerUpdate::Progress(crate::progress::TransferSnapshot {
                    fraction: 0.99,
                    bytes_done: 99,
                    bytes_total: 100,
                    bytes_per_sec: None,
                    eta: None,
                    item_index: None,
                })),
            })
            .unwrap();
        app.tx
            .send(WorkerUpdate::Scoped {
                epoch: scope1.epoch,
                job_id: scope1.job_id,
                update: Box::new(WorkerUpdate::PreviewError {
                    gen: gen1,
                    message: "cancelled".into(),
                    cancelled: true,
                }),
            })
            .unwrap();
        app.drain_updates(&ctx);

        assert!(
            app.state.busy,
            "abandoned preview must not clear new job's busy flag"
        );
        assert!(
            (app.state.progress - 0.25).abs() < 1e-6,
            "abandoned preview overwrote new job's progress: {}",
            app.state.progress
        );
        assert_eq!(app.state.transfer.unwrap().bytes_done, 25);
    }

    #[test]
    fn guarded_worker_panic_emits_error_and_releases_busy_state() {
        let ctx = egui::Context::default();
        let mut app = isolated_app();
        app.state.config.language = AppLanguage::En;
        let (scope, _job_cancel) = app.state.begin_busy_job("running", &app.cancel);
        assert!(app.state.busy);

        worker::spawn_guarded_worker(
            app.tx.clone(),
            ctx.clone(),
            Some(scope),
            AppLanguage::En,
            || {
                panic!("simulated worker panic");
            },
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        while app.state.busy && Instant::now() < deadline {
            app.drain_updates(&ctx);
            std::thread::sleep(Duration::from_millis(10));
        }
        app.drain_updates(&ctx);

        assert!(!app.state.busy, "worker panic left state.busy stuck true");
        assert!(app.state.is_error);
        assert!(
            app.state.status.contains("simulated worker panic"),
            "unexpected status: {}",
            app.state.status
        );
        assert!(app
            .state
            .logs
            .iter()
            .any(|l| l.contains("simulated worker panic")));
    }

    fn run_frame(ctx: &egui::Context, app: &mut RpmApp, events: Vec<egui::Event>) {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::pos2(0.0, 0.0),
                egui::vec2(1280.0, 800.0),
            )),
            events,
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, |ui| app.render_ui(ui));
        out.textures_delta.clear();
    }

    #[test]
    fn raw_input_ctrl_l_esc_and_idle_timeout_during_pending_preview_end_to_end() {
        let ctx = egui::Context::default();
        let dir = tempfile::tempdir().unwrap();
        let precious = dir.path().join("precious_raw.txt");
        std::fs::write(&precious, b"never auto-wipe").unwrap();

        // 1. Real Ctrl+L RawInput clears sensitive session, cancels active job, preserves clipboard,
        //    and fences stale updates on the next full frame.
        let mut app = isolated_app();
        let clip_deadline = Instant::now() + Duration::from_secs(25);
        app.state.clipboard_deadline = Some(clip_deadline);
        app.state.encrypt.password = "TopSecret!99".into();
        let (old_scope, old_cancel) = app.state.begin_busy_job("inspecting", &app.cancel);
        app.state.active_queue_job = Some("active secret job".into());

        run_frame(
            &ctx,
            &mut app,
            vec![egui::Event::Key {
                key: egui::Key::L,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::CTRL,
            }],
        );
        assert!(app.cancel.load(Ordering::Relaxed));
        assert!(old_cancel.load(Ordering::Relaxed));
        assert!(app.state.encrypt.password.is_empty());
        assert!(app.state.active_queue_job.is_none());
        assert!(!app.state.busy);
        assert_eq!(app.state.clipboard_deadline, Some(clip_deadline));

        app.tx
            .send(WorkerUpdate::Scoped {
                epoch: old_scope.epoch,
                job_id: old_scope.job_id,
                update: Box::new(WorkerUpdate::InspectDone {
                    text: "LEAKED".into(),
                    status: "unlocked".into(),
                    manifest: vec![],
                    vault_path: PathBuf::from("secret.vault"),
                }),
            })
            .unwrap();
        run_frame(&ctx, &mut app, vec![]);
        assert!(!app.state.inspect.results.contains("LEAKED"));

        // 2. Real Esc RawInput during an active queued job immediately pauses queue so
        //    maybe_start_next_queued_job at frame end never starts waiting secure_wipe job.
        let mut app2 = isolated_app();
        app2.state
            .enqueue_job(crate::queue::QueuedJobKind::Encrypt {
                sources: vec![precious.clone()],
                password: Zeroizing::new("WipePass!1".into()),
                recovery_entropy: rpm_core::generate_recovery_entropy(),
                keyfile: None,
                output_dir: Some(dir.path().to_path_buf()),
                compress: false,
                container_size_bytes: None,
                split_part_bytes: None,
                stealth: false,
                reed_solomon: false,
                secure_wipe: true,
                wipe_passes: 1,
                kdf: rpm_core::KdfParams::fast_test(),
            });
        let (q_scope, q_cancel) = app2
            .state
            .begin_transfer_job("queued running", &app2.cancel);
        app2.state.active_queue_job = Some("job 1".into());
        run_frame(
            &ctx,
            &mut app2,
            vec![egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert!(q_cancel.load(Ordering::Relaxed));
        assert!(app2.state.queue_paused);

        // Even when the cancelled queued job races with EncryptDone on the next frame,
        // `render_ui` (including `maybe_start_next_queued_job`) must NOT start the waiting wipe job.
        app2.tx
            .send(WorkerUpdate::Scoped {
                epoch: q_scope.epoch,
                job_id: q_scope.job_id,
                update: Box::new(WorkerUpdate::EncryptDone {
                    status: "raced".into(),
                    output_path: dir.path().join("raced.vault"),
                }),
            })
            .unwrap();
        run_frame(&ctx, &mut app2, vec![]);
        assert!(!app2.state.busy);
        assert!(app2.state.queue_paused);
        assert_eq!(app2.state.job_queue.len(), 1);
        assert_eq!(std::fs::read(&precious).unwrap(), b"never auto-wipe");

        // 3. Idle timeout firing during a pending preview inside `render_ui` cancels and
        //    epoch-fences the abandoned preview without touching `clipboard_deadline`.
        let mut app3 = isolated_app();
        app3.state.config.idle_clear_minutes = 1;
        let clip3 = Instant::now() + Duration::from_secs(20);
        app3.state.clipboard_deadline = Some(clip3);
        app3.state.select_tab(Tab::Inspect);
        let (prev_gen, prev_scope, prev_cancel) = app3
            .state
            .begin_preview_job("loading preview", &app3.cancel);
        app3.state.last_activity = Instant::now() - Duration::from_secs(120);

        run_frame(&ctx, &mut app3, vec![]);
        assert!(prev_cancel.load(Ordering::Relaxed));
        assert!(app3.cancel.load(Ordering::Relaxed));
        assert!(!app3.state.busy);
        assert!(app3.state.inspect.preview_pending.is_none());
        assert_eq!(app3.state.clipboard_deadline, Some(clip3));

        app3.tx
            .send(WorkerUpdate::Scoped {
                epoch: prev_scope.epoch,
                job_id: prev_scope.job_id,
                update: Box::new(WorkerUpdate::PreviewDone {
                    gen: prev_gen,
                    path: "secret.txt".into(),
                    bytes: Zeroizing::new(b"secret preview".to_vec()),
                    status: "ready".into(),
                }),
            })
            .unwrap();
        run_frame(&ctx, &mut app3, vec![]);
        assert!(app3.state.inspect.preview.is_none());
        assert_eq!(app3.state.clipboard_deadline, Some(clip3));
    }

    #[test]
    fn cancel_error_and_progress_fencing_and_waiting_queue_pause_and_modal_click_guard() {
        let ctx = egui::Context::default();
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("queued_wipe.txt");
        std::fs::write(&src, b"keep safe").unwrap();

        // 1. Direct job running while a `secure_wipe: true` job waits in `job_queue`:
        //    `request_cancel` pauses queue, ignores subsequent `Progress`, and treats
        //    the worker's `Error(cancelled)` as clean non-error cancellation without
        //    auto-starting the waiting `secure_wipe` job.
        let mut app = isolated_app();
        app.state.config.language = AppLanguage::En;
        app.state.enqueue_job(crate::queue::QueuedJobKind::Encrypt {
            sources: vec![src.clone()],
            password: Zeroizing::new("WaitWipe!1".into()),
            recovery_entropy: rpm_core::generate_recovery_entropy(),
            keyfile: None,
            output_dir: Some(dir.path().to_path_buf()),
            compress: false,
            container_size_bytes: None,
            split_part_bytes: None,
            stealth: false,
            reed_solomon: false,
            secure_wipe: true,
            wipe_passes: 1,
            kdf: rpm_core::KdfParams::fast_test(),
        });
        let (scope, job_cancel) = app.state.begin_transfer_job("direct running", &app.cancel);
        app.state.progress = 0.30;
        app.request_cancel();
        assert!(job_cancel.load(Ordering::Relaxed));
        assert!(app.state.queue_paused);

        app.tx
            .send(WorkerUpdate::Scoped {
                epoch: scope.epoch,
                job_id: scope.job_id,
                update: Box::new(WorkerUpdate::Progress(crate::progress::TransferSnapshot {
                    fraction: 0.99,
                    bytes_done: 99,
                    bytes_total: 100,
                    bytes_per_sec: None,
                    eta: None,
                    item_index: None,
                })),
            })
            .unwrap();
        app.drain_updates(&ctx);
        assert!(
            (app.state.progress - 0.30).abs() < 1e-6,
            "progress advanced after request_cancel: {}",
            app.state.progress
        );

        app.tx
            .send(WorkerUpdate::Scoped {
                epoch: scope.epoch,
                job_id: scope.job_id,
                update: Box::new(WorkerUpdate::Error(crate::i18n::EN.status_cancelled.into())),
            })
            .unwrap();
        let logs_before = app.state.logs.len();
        run_frame(&ctx, &mut app, vec![]);
        assert!(!app.state.busy);
        assert!(
            !app.state.is_error,
            "user cancel must not show error banner"
        );
        assert_eq!(app.state.status, crate::i18n::EN.status_cancelled);
        assert_eq!(
            app.state.logs.len(),
            logs_before,
            "user cancel must not log ERROR line"
        );
        assert!(app.state.queue_paused);
        assert_eq!(app.state.job_queue.len(), 1);
        assert_eq!(std::fs::read(&src).unwrap(), b"keep safe");

        // 2. Clicking btn_cancel during a pending preview then pressing Esc clears legacy `cancel`.
        let mut app2 = isolated_app();
        app2.state.select_tab(Tab::Inspect);
        let (_g, _s, _c) = app2.state.begin_preview_job("loading", &app2.cancel);
        app2.request_cancel();
        assert!(app2.cancel.load(Ordering::Relaxed));
        run_frame(
            &ctx,
            &mut app2,
            vec![egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert!(!app2.state.busy);
        assert!(!app2.cancel.load(Ordering::Relaxed));

        // 3. Recovery confirmation modal rendered in full `render_ui` while `busy == true`:
        //    synthetic pointer click across the modal cannot launch a second worker or clear `cancel`.
        let mut app3 = isolated_app();
        app3.state.encrypt.sources = vec![src.clone()];
        app3.state.encrypt.password = "ModalPass!1".into();
        app3.state.encrypt.confirm_password = "ModalPass!1".into();
        let (busy_scope, busy_cancel) = app3.state.begin_transfer_job("active work", &app3.cancel);
        app3.cancel.store(true, Ordering::Relaxed);
        app3.state.encrypt.recovery_prompt = Some(crate::state::RecoveryPrompt {
            phrase: "abandon ".repeat(24),
            entropy: rpm_core::SecretKey::new([0x33; 32]),
            confirmed: true,
            queue_after_confirm: false,
        });
        // Prime layout then send click across the modal's button row.
        run_frame(&ctx, &mut app3, vec![]);
        for x in [720.0_f32, 780.0, 840.0] {
            run_frame(
                &ctx,
                &mut app3,
                vec![
                    egui::Event::PointerMoved(egui::pos2(x, 470.0)),
                    egui::Event::PointerButton {
                        pos: egui::pos2(x, 470.0),
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers: egui::Modifiers::NONE,
                    },
                    egui::Event::PointerButton {
                        pos: egui::pos2(x, 470.0),
                        button: egui::PointerButton::Primary,
                        pressed: false,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
        }
        assert_eq!(app3.state.active_job_id(), busy_scope.job_id);
        assert!(app3.state.busy);
        assert!(app3.state.encrypt.recovery_prompt.is_some());
        assert!(app3.cancel.load(Ordering::Relaxed));
        assert!(!busy_cancel.load(Ordering::Relaxed));
    }

    #[test]
    fn preview_and_source_scan_worker_panics_recover_cleanly_without_stalling_ui() {
        let ctx = egui::Context::default();
        let mut app = isolated_app();
        app.state.config.language = AppLanguage::En;
        app.state.select_tab(Tab::Inspect);

        // 1. Panicking preview worker emits PreviewError and clears busy + preview_pending.
        let (gen, scope, _cancel) = app.state.begin_preview_job("loading", &app.cancel);
        assert!(app.state.busy);
        assert!(app.state.inspect.preview_pending.is_some());
        worker::spawn_guarded_preview_worker(
            app.tx.clone(),
            ctx.clone(),
            Some(scope),
            gen,
            AppLanguage::En,
            || panic!("injected preview panic"),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while app.state.busy && Instant::now() < deadline {
            app.drain_updates(&ctx);
            std::thread::sleep(Duration::from_millis(10));
        }
        app.drain_updates(&ctx);
        assert!(!app.state.busy);
        assert!(app.state.inspect.preview_pending.is_none());
        assert!(app.state.is_error);
        assert!(app.state.status.contains("injected preview panic"));

        // 2. Panicking preflight source-scan worker emits SourceScanDone and clears preflight_scanning.
        app.state.encrypt.preflight_scan_gen = 11;
        app.state.encrypt.preflight_scanning = true;
        let scan_cancel = Arc::new(AtomicBool::new(false));
        app.state.encrypt.preflight_scan_cancel = Some(Arc::clone(&scan_cancel));
        worker::spawn_guarded_source_scan_worker(
            app.tx.clone(),
            ctx.clone(),
            scan_cancel,
            11,
            Some(worker::WorkerScope {
                epoch: app.state.session_epoch(),
                job_id: 0,
            }),
            || panic!("injected source scan panic"),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while app.state.encrypt.preflight_scanning && Instant::now() < deadline {
            app.drain_updates(&ctx);
            std::thread::sleep(Duration::from_millis(10));
        }
        app.drain_updates(&ctx);
        assert!(
            !app.state.encrypt.preflight_scanning,
            "panicking source scan left preflight_scanning stuck true"
        );
    }

    #[test]
    fn live_encrypt_with_secure_wipe_honors_mid_flight_cancel_without_encrypt_done() {
        let ctx = egui::Context::default();
        let dir = tempfile::tempdir().unwrap();
        let out_dir = dir.path().join("vault_out");
        std::fs::create_dir(&out_dir).unwrap();
        let sub = dir.path().join("nested_folder");
        std::fs::create_dir(&sub).unwrap();

        // Create multi-file + subfolder sources (~12 MiB total) so encryption runs long enough
        // to trigger live mid-flight cancellation after initial progress ticks.
        let mut sources = Vec::new();
        let chunk_data = vec![0xA5u8; 2 * 1024 * 1024];
        for i in 0..4usize {
            let p = dir.path().join(format!("file_{i}.bin"));
            std::fs::write(&p, &chunk_data).unwrap();
            sources.push(p);
        }
        let nested_file = sub.join("deep.bin");
        std::fs::write(&nested_file, &chunk_data).unwrap();
        sources.push(sub.clone());

        let mut app = isolated_app();
        app.state.config.language = AppLanguage::En;
        let (scope, job_cancel) = app.state.begin_transfer_job("encrypting", &app.cancel);
        worker::spawn_encrypt_scoped(
            ctx.clone(),
            app.tx.clone(),
            job_cancel,
            Some(scope),
            sources.clone(),
            Zeroizing::new("LiveWipe!1".into()),
            rpm_core::generate_recovery_entropy(),
            None,
            Some(out_dir.clone()),
            true,
            None,
            None,
            false,
            false,
            true,
            3,
            rpm_core::KdfParams::fast_test(),
            2,
            AppLanguage::En,
        );

        let mut cancelled_sent = false;
        let deadline = Instant::now() + Duration::from_secs(30);
        while app.state.busy && Instant::now() < deadline {
            app.drain_updates(&ctx);
            if !cancelled_sent && app.state.progress > 0.0 {
                app.request_cancel();
                cancelled_sent = true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if !cancelled_sent {
            app.request_cancel();
            app.drain_updates(&ctx);
        }
        assert!(!app.state.busy);
        assert!(
            cancelled_sent,
            "expected live encrypt progress tick before completion"
        );
        assert!(!app.state.is_error);
        assert_eq!(app.state.status, crate::i18n::EN.status_cancelled);
        assert!(
            app.state.last_action.is_none(),
            "cancelled encrypt must never publish EncryptDone / last_action"
        );
        // Because encryption was cancelled mid-stream before commit, every source file must remain intact.
        for p in &sources {
            assert!(
                p.exists(),
                "source {} was unexpectedly deleted on cancelled encrypt",
                p.display()
            );
        }
    }
}
