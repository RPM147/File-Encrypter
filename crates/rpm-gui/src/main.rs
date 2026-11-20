#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use rpm_gui::app::RpmApp;
use rpm_storage::parse_gui_launch_args;

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let intent = parse_gui_launch_args(&args);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1060.0, 740.0])
            .with_min_inner_size([860.0, 560.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };

    eframe::run_native(
        "RPM Encrypter (Pure Rust)",
        options,
        Box::new(|_cc| Ok(Box::new(RpmApp::new(intent)))),
    )
}
