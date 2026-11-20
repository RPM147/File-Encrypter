//! CLI stderr progress reporting with throughput (MiB/s) and ETA.

use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::ValueEnum;

const CLI_PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Controls when CLI operations emit live transfer progress on `stderr`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum ProgressMode {
    /// Emit `\r` live updates only when `stderr` is an interactive terminal (TTY).
    #[default]
    Auto,
    /// Always emit progress updates to `stderr` (newline-delimited when piped).
    Always,
    /// Suppress all progress updates.
    Never,
}

/// Point-in-time transfer measurement for CLI progress formatting.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CliProgressSnapshot {
    pub percent: u8,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub bytes_per_sec: Option<f64>,
    pub eta: Option<Duration>,
}

/// Exponentially smoothed throughput and ETA tracker for CLI transfers.
#[derive(Clone, Debug)]
pub struct CliProgressMeter {
    started_at: Instant,
    last_time: Option<Instant>,
    last_done: u64,
    smoothed_bps: Option<f64>,
}

impl CliProgressMeter {
    /// Create a new progress meter anchored at `started_at`.
    pub fn new(started_at: Instant) -> Self {
        Self {
            started_at,
            last_time: None,
            last_done: 0,
            smoothed_bps: None,
        }
    }

    /// Record progress at an explicit `Instant` (deterministic for tests).
    pub fn update_at(&mut self, now: Instant, done: u64, total: u64) -> CliProgressSnapshot {
        let effective_done = if total > 0 { done.min(total) } else { done };
        let percent = if total > 0 {
            ((effective_done as f64 / total as f64) * 100.0)
                .clamp(0.0, 100.0)
                .round() as u8
        } else {
            100
        };

        if let Some(prev_t) = self.last_time {
            if effective_done > self.last_done {
                let dt = now.saturating_duration_since(prev_t).as_secs_f64();
                if dt >= 0.001 {
                    let inst = (effective_done - self.last_done) as f64 / dt;
                    self.smoothed_bps = Some(match self.smoothed_bps {
                        Some(prev) => prev * 0.65 + inst * 0.35,
                        None => inst,
                    });
                    self.last_time = Some(now);
                    self.last_done = effective_done;
                }
            }
        } else if effective_done > 0 {
            self.last_time = Some(now);
            self.last_done = effective_done;
            let elapsed = now.saturating_duration_since(self.started_at).as_secs_f64();
            if elapsed >= 0.05 {
                self.smoothed_bps = Some(effective_done as f64 / elapsed);
            }
        }

        let eta = if total > 0 && effective_done >= total {
            Some(Duration::ZERO)
        } else if total > 0 {
            self.smoothed_bps.and_then(|bps| {
                if bps >= 1.0 {
                    let rem = (total - effective_done) as f64;
                    let secs = (rem / bps).ceil().min(359_999.0);
                    Some(Duration::from_secs(secs as u64))
                } else {
                    None
                }
            })
        } else {
            None
        };

        CliProgressSnapshot {
            percent,
            bytes_done: effective_done,
            bytes_total: total,
            bytes_per_sec: self.smoothed_bps,
            eta,
        }
    }
}

/// Format a byte count using binary IEC units (`B`, `KiB`, `MiB`, `GiB`).
pub fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    let b = bytes as f64;
    if b < KIB {
        format!("{bytes} B")
    } else if b < MIB {
        format!("{:.1} KiB", b / KIB)
    } else if b < GIB {
        format!("{:.1} MiB", b / MIB)
    } else {
        format!("{:.2} GiB", b / GIB)
    }
}

/// Format throughput in bytes/second using binary IEC units.
pub fn format_rate(bps: f64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    let val = if bps.is_finite() && bps > 0.0 {
        bps
    } else {
        0.0
    };
    if val < KIB {
        format!("{val:.0} B/s")
    } else if val < MIB {
        format!("{:.1} KiB/s", val / KIB)
    } else if val < GIB {
        format!("{:.1} MiB/s", val / MIB)
    } else {
        format!("{:.2} GiB/s", val / GIB)
    }
}

/// Format remaining duration concisely (`12s`, `2m 05s`, `1h 01m`).
pub fn format_eta(d: Duration) -> String {
    let total_secs = d.as_secs();
    if total_secs < 60 {
        format!("{total_secs}s")
    } else if total_secs < 3600 {
        format!("{}m {:02}s", total_secs / 60, total_secs % 60)
    } else {
        format!("{}h {:02}m", total_secs / 3600, (total_secs % 3600) / 60)
    }
}

/// Format one single-line progress status string.
pub fn format_progress_line(label: &str, snap: &CliProgressSnapshot) -> String {
    let counts = if snap.bytes_total > 0 {
        format!(
            "{} / {}",
            format_bytes(snap.bytes_done),
            format_bytes(snap.bytes_total)
        )
    } else {
        format_bytes(snap.bytes_done)
    };

    let mut line = format!("{label}: {:>3}% ({counts})", snap.percent);
    if let Some(bps) = snap.bytes_per_sec {
        line.push(' ');
        line.push_str(&format_rate(bps));
        if let Some(eta) = snap.eta {
            line.push_str(" ETA ");
            line.push_str(&format_eta(eta));
        }
    }
    line
}

#[derive(Clone, Debug)]
enum Target {
    Silent,
    LiveStderr,
    Buffered(Arc<Mutex<Vec<u8>>>),
}

#[derive(Debug)]
struct InnerState {
    label: String,
    meter: CliProgressMeter,
    last_flush: Option<Instant>,
    final_written: bool,
    max_len: usize,
    printed_any: bool,
}

fn emit_line(target: &Target, pad: usize, line: &str) {
    match target {
        Target::Silent => {}
        Target::LiveStderr => {
            let mut err = io::stderr();
            let _ = write!(err, "\r{line}{}", " ".repeat(pad));
            let _ = err.flush();
        }
        Target::Buffered(buf) => {
            if let Ok(mut out) = buf.lock() {
                let _ = writeln!(out, "{line}");
            }
        }
    }
}

/// Thread-safe reporter producing progress callbacks and clean line termination.
pub struct CliProgressReporter {
    target: Target,
    state: Arc<Mutex<InnerState>>,
}

impl CliProgressReporter {
    /// Construct a reporter honoring `--progress` and whether `stderr` is a TTY.
    pub fn new(mode: ProgressMode, stderr_is_tty: bool, label: impl Into<String>) -> Self {
        let target = match (mode, stderr_is_tty) {
            (ProgressMode::Never, _) | (ProgressMode::Auto, false) => Target::Silent,
            (ProgressMode::Auto | ProgressMode::Always, true) => Target::LiveStderr,
            (ProgressMode::Always, false) => Target::Buffered(Arc::new(Mutex::new(Vec::new()))),
        };
        Self {
            target,
            state: Arc::new(Mutex::new(InnerState {
                label: label.into(),
                meter: CliProgressMeter::new(Instant::now()),
                last_flush: None,
                final_written: false,
                max_len: 0,
                printed_any: false,
            })),
        }
    }

    /// Build the `(done, total)` progress callback passed to `rpm-storage`.
    pub fn callback(&self) -> Arc<dyn Fn(u64, u64) + Send + Sync> {
        if matches!(self.target, Target::Silent) {
            return Arc::new(|_, _| {});
        }
        let target = self.target.clone();
        let state = Arc::clone(&self.state);
        Arc::new(move |done, total| {
            let now = Instant::now();
            let Ok(mut st) = state.lock() else {
                return;
            };
            let snap = st.meter.update_at(now, done, total);
            let is_final = total > 0 && done >= total;
            if st.final_written && is_final {
                return;
            }
            let due = is_final
                || match st.last_flush {
                    None => true,
                    Some(prev) => now.saturating_duration_since(prev) >= CLI_PROGRESS_INTERVAL,
                };
            if !due {
                return;
            }
            let line = format_progress_line(&st.label, &snap);
            let pad = st.max_len.saturating_sub(line.len());
            st.max_len = st.max_len.max(line.len());
            st.last_flush = Some(now);
            st.printed_any = true;
            if is_final {
                st.final_written = true;
            }
            drop(st);
            emit_line(&target, pad, &line);
        })
    }

    /// Finish progress reporting cleanly (newline on TTY, flush buffered lines to `stderr`).
    pub fn finish<W: Write>(&self, stderr_out: &mut W) {
        match &self.target {
            Target::Silent => {}
            Target::LiveStderr => {
                let printed = self.state.lock().map(|st| st.printed_any).unwrap_or(false);
                if printed {
                    let mut err = io::stderr();
                    let _ = writeln!(err);
                    let _ = err.flush();
                }
            }
            Target::Buffered(buf) => {
                if let Ok(mut guard) = buf.lock() {
                    if !guard.is_empty() {
                        let _ = stderr_out.write_all(&guard);
                        let _ = stderr_out.flush();
                        guard.clear();
                    }
                }
            }
        }
    }
}
