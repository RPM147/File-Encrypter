pub mod app;
pub mod estimator;
pub mod fonts;
pub mod i18n;
pub mod progress;
pub mod queue;
pub mod reveal;
pub mod state;
pub mod tabs;
pub mod theme;
pub mod worker;

use eframe::egui;

/// Decode the embedded PNG application icon for desktop window chrome/taskbar.
pub fn load_app_icon() -> Option<egui::IconData> {
    eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png")).ok()
}

pub mod preview;
