//! System TTF font loader so Turkish & Unicode glyphs render cleanly across OSes.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui::{self, FontData, FontDefinitions, FontFamily};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FontLoadReport {
    pub proportional_loaded: bool,
    pub monospace_loaded: bool,
}

#[cfg(target_os = "windows")]
fn windows_font_paths_from(
    windir: Option<std::ffi::OsString>,
    system_root: Option<std::ffi::OsString>,
    files: &[&str],
) -> Vec<PathBuf> {
    let mut roots = Vec::with_capacity(3);
    for candidate in [
        windir.filter(|v| !v.is_empty()).map(PathBuf::from),
        system_root.filter(|v| !v.is_empty()).map(PathBuf::from),
        Some(PathBuf::from(r"C:\Windows")),
    ]
    .into_iter()
    .flatten()
    {
        if !roots.iter().any(|existing: &PathBuf| {
            existing
                .to_string_lossy()
                .eq_ignore_ascii_case(&candidate.to_string_lossy())
        }) {
            roots.push(candidate);
        }
    }

    let mut out = Vec::with_capacity(roots.len() * files.len());
    for root in roots {
        let fonts_dir = root.join("Fonts");
        for name in files {
            out.push(fonts_dir.join(name));
        }
    }
    out
}

#[cfg(target_os = "windows")]
fn windows_font_paths(files: &[&str]) -> Vec<PathBuf> {
    windows_font_paths_from(
        std::env::var_os("WINDIR"),
        std::env::var_os("SystemRoot"),
        files,
    )
}

#[cfg(target_os = "windows")]
fn proportional_candidates() -> Vec<PathBuf> {
    windows_font_paths(&["segoeui.ttf", "arial.ttf", "tahoma.ttf"])
}

#[cfg(target_os = "windows")]
fn monospace_candidates() -> Vec<PathBuf> {
    windows_font_paths(&["consola.ttf", "lucon.ttf"])
}

#[cfg(target_os = "linux")]
fn proportional_candidates() -> Vec<PathBuf> {
    [
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

#[cfg(target_os = "linux")]
fn monospace_candidates() -> Vec<PathBuf> {
    [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

#[cfg(target_os = "macos")]
fn proportional_candidates() -> Vec<PathBuf> {
    [
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

#[cfg(target_os = "macos")]
fn monospace_candidates() -> Vec<PathBuf> {
    vec![PathBuf::from(
        "/System/Library/Fonts/Supplemental/Courier New.ttf",
    )]
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn proportional_candidates() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn monospace_candidates() -> Vec<PathBuf> {
    Vec::new()
}

fn read_first_font(candidates: &[PathBuf]) -> Option<Vec<u8>> {
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

    let proportional = proportional_candidates();
    if let Some(bytes) = read_first_font(&proportional) {
        fonts
            .font_data
            .insert("rpm_sys_sans".into(), Arc::new(FontData::from_owned(bytes)));
        if let Some(family) = fonts.families.get_mut(&FontFamily::Proportional) {
            family.insert(0, "rpm_sys_sans".into());
        }
        report.proportional_loaded = true;
    }

    let monospace = monospace_candidates();
    if let Some(bytes) = read_first_font(&monospace) {
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

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn windows_font_paths_fall_back_across_windir_system_root_and_default() {
        let paths = windows_font_paths_from(
            Some(OsString::from(r"Z:\NonExistent")),
            Some(OsString::from(r"D:\Windows")),
            &["segoeui.ttf"],
        );
        assert_eq!(
            paths,
            vec![
                PathBuf::from(r"Z:\NonExistent\Fonts\segoeui.ttf"),
                PathBuf::from(r"D:\Windows\Fonts\segoeui.ttf"),
                PathBuf::from(r"C:\Windows\Fonts\segoeui.ttf"),
            ]
        );

        let deduped = windows_font_paths_from(
            Some(OsString::from(r"c:\windows")),
            Some(OsString::from(r"C:\Windows")),
            &["arial.ttf"],
        );
        assert_eq!(deduped, vec![PathBuf::from(r"c:\windows\Fonts\arial.ttf")]);

        let empty = windows_font_paths_from(Some(OsString::from("")), None, &["tahoma.ttf"]);
        assert_eq!(empty, vec![PathBuf::from(r"C:\Windows\Fonts\tahoma.ttf")]);
    }
}
