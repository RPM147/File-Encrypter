//! Live transfer throughput (MiB/s) and ETA estimator for GUI progress reporting.

use std::time::{Duration, Instant};

use rpm_storage::config::AppLanguage;

/// Point-in-time transfer progress snapshot sent from worker threads to the GUI.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TransferSnapshot {
    pub fraction: f32,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub bytes_per_sec: Option<f64>,
    pub eta: Option<Duration>,
    pub item_index: Option<(usize, usize)>,
}

/// Exponentially smoothed throughput and remaining-time tracker.
#[derive(Clone, Debug)]
pub struct TransferMeter {
    started_at: Instant,
    last_time: Option<Instant>,
    last_done: u64,
    smoothed_bps: Option<f64>,
    item_index: Option<(usize, usize)>,
}

impl TransferMeter {
    /// Start a single-item transfer meter at `started_at`.
    pub fn new(started_at: Instant) -> Self {
        Self {
            started_at,
            last_time: None,
            last_done: 0,
            smoothed_bps: None,
            item_index: None,
        }
    }

    /// Start a multi-item transfer meter tagged with `(current, total_items)`.
    pub fn with_item(started_at: Instant, current: usize, total_items: usize) -> Self {
        Self {
            started_at,
            last_time: None,
            last_done: 0,
            smoothed_bps: None,
            item_index: Some((current, total_items)),
        }
    }

    /// Record progress using the current wall-clock `Instant`.
    pub fn update(&mut self, done: u64, total: u64) -> TransferSnapshot {
        self.update_at(Instant::now(), done, total)
    }

    /// Record progress at an explicit `Instant` (deterministic for unit tests).
    pub fn update_at(&mut self, now: Instant, done: u64, total: u64) -> TransferSnapshot {
        let effective_done = if total > 0 { done.min(total) } else { done };
        let fraction = if total > 0 {
            (effective_done as f32 / total as f32).clamp(0.0, 1.0)
        } else {
            1.0
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
            // Skip initial sub-50ms spike on small first buffers until another sample arrives.
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

        TransferSnapshot {
            fraction,
            bytes_done: effective_done,
            bytes_total: total,
            bytes_per_sec: self.smoothed_bps,
            eta,
            item_index: self.item_index,
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

/// Format throughput in bytes/second using binary IEC rate units.
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

/// Format remaining duration in Turkish or English.
pub fn format_eta(d: Duration, lang: AppLanguage) -> String {
    let total_secs = d.as_secs();
    if total_secs < 60 {
        match lang {
            AppLanguage::Tr => format!("{total_secs} sn"),
            AppLanguage::En => format!("{total_secs}s"),
        }
    } else if total_secs < 3600 {
        let m = total_secs / 60;
        let s = total_secs % 60;
        match lang {
            AppLanguage::Tr => format!("{m} dk {s:02} sn"),
            AppLanguage::En => format!("{m}m {s:02}s"),
        }
    } else {
        let h = total_secs / 3600;
        let m = (total_secs % 3600) / 60;
        match lang {
            AppLanguage::Tr => format!("{h} sa {m:02} dk"),
            AppLanguage::En => format!("{h}h {m:02}m"),
        }
    }
}

/// Format a compact status-bar summary (`[cur/tot] MiB/s • ETA`).
pub fn format_transfer_summary(snap: &TransferSnapshot, lang: AppLanguage) -> Option<String> {
    let prefix = snap
        .item_index
        .filter(|&(_, tot)| tot > 1)
        .map(|(cur, tot)| format!("[{cur}/{tot}]"));

    let mut details = Vec::with_capacity(2);
    if let Some(bps) = snap.bytes_per_sec {
        details.push(format_rate(bps));
        if let Some(eta) = snap.eta {
            let formatted = format_eta(eta, lang);
            match lang {
                AppLanguage::Tr => details.push(format!("Kalan: {formatted}")),
                AppLanguage::En => details.push(format!("ETA {formatted}")),
            }
        }
    }

    match (prefix, details.is_empty()) {
        (None, true) => None,
        (Some(p), true) => Some(p),
        (None, false) => Some(details.join(" • ")),
        (Some(p), false) => Some(format!("{p} {}", details.join(" • "))),
    }
}

/// Format hover tooltip text showing transferred/total bytes and optional speed/ETA.
pub fn format_transfer_tooltip(snap: &TransferSnapshot, lang: AppLanguage) -> String {
    let bytes_line = if snap.bytes_total > 0 {
        format!(
            "{} / {}",
            format_bytes(snap.bytes_done),
            format_bytes(snap.bytes_total)
        )
    } else {
        format_bytes(snap.bytes_done)
    };
    match format_transfer_summary(snap, lang) {
        Some(summary) => format!("{bytes_line}\n{summary}"),
        None => bytes_line,
    }
}
