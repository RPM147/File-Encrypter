#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use rpm_gui::app::RpmApp;
use rpm_storage::parse_gui_launch_args;

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let intent = parse_gui_launch_args(&args);

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1080.0, 760.0])
        .with_min_inner_size([860.0, 560.0])
        .with_drag_and_drop(true);
    if let Some(icon) = rpm_gui::load_app_icon() {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "RPM Encrypter — Vault v5",
        options,
        Box::new(|cc| {
            rpm_gui::fonts::configure_fonts(&cc.egui_ctx);
            Ok(Box::new(RpmApp::new(intent)))
        }),
    )
}
