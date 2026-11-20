//! System TTF font loader so Turkish & Unicode glyphs render cleanly across OSes.

use std::fs;
use std::sync::Arc;

use eframe::egui::{self, FontData, FontDefinitions, FontFamily};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FontLoadReport {
    pub proportional_loaded: bool,
    pub monospace_loaded: bool,
}

#[cfg(target_os = "windows")]
const PROPORTIONAL_CANDIDATES: &[&str] = &[
    r"C:\Windows\Fonts\segoeui.ttf",
    r"C:\Windows\Fonts\arial.ttf",
    r"C:\Windows\Fonts\tahoma.ttf",
];

#[cfg(target_os = "windows")]
const MONOSPACE_CANDIDATES: &[&str] = &[
    r"C:\Windows\Fonts\consola.ttf",
    r"C:\Windows\Fonts\lucon.ttf",
];

#[cfg(target_os = "linux")]
const PROPORTIONAL_CANDIDATES: &[&str] = &[
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
];

#[cfg(target_os = "linux")]
const MONOSPACE_CANDIDATES: &[&str] = &[
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
];

#[cfg(target_os = "macos")]
const PROPORTIONAL_CANDIDATES: &[&str] = &[
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
];

#[cfg(target_os = "macos")]
const MONOSPACE_CANDIDATES: &[&str] = &["/System/Library/Fonts/Supplemental/Courier New.ttf"];

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
const PROPORTIONAL_CANDIDATES: &[&str] = &[];

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
const MONOSPACE_CANDIDATES: &[&str] = &[];

fn read_first_font(candidates: &[&str]) -> Option<Vec<u8>> {
    for path in candidates {
        if let Ok(bytes) = fs::read(path) {
            if !bytes.is_empty() {
                return Some(bytes);
            }
        }
    }
    None
}

/// Prepend an OS-provided UTF-8/Turkish-complete font to `Proportional` and `Monospace`,
/// preserving `egui`'s built-in fonts as glyph fallbacks.
pub fn configure_fonts(ctx: &egui::Context) -> FontLoadReport {
    let mut fonts = FontDefinitions::default();
    let mut report = FontLoadReport::default();

    if let Some(bytes) = read_first_font(PROPORTIONAL_CANDIDATES) {
        fonts
            .font_data
            .insert("rpm_sys_sans".into(), Arc::new(FontData::from_owned(bytes)));
        if let Some(family) = fonts.families.get_mut(&FontFamily::Proportional) {
            family.insert(0, "rpm_sys_sans".into());
        }
        report.proportional_loaded = true;
    }

    if let Some(bytes) = read_first_font(MONOSPACE_CANDIDATES) {
        fonts
            .font_data
            .insert("rpm_sys_mono".into(), Arc::new(FontData::from_owned(bytes)));
        if let Some(family) = fonts.families.get_mut(&FontFamily::Monospace) {
            family.insert(0, "rpm_sys_mono".into());
        }
        report.monospace_loaded = true;
    }

    ctx.set_fonts(fonts);
    report
}
