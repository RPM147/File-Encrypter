//! Refined Dark/Light palette and reusable card / primary-action helpers.

use eframe::egui::{self, Color32, CornerRadius, Stroke, Visuals};
use rpm_storage::config::ThemeMode;

pub const ACCENT_DARK: Color32 = Color32::from_rgb(20, 184, 166);
pub const ACCENT_LIGHT: Color32 = Color32::from_rgb(15, 118, 110);

pub fn apply_theme(ctx: &egui::Context, mode: ThemeMode) {
    let mut visuals = match mode {
        ThemeMode::Dark => {
            let mut v = Visuals::dark();
            v.panel_fill = Color32::from_rgb(16, 21, 28);
            v.window_fill = Color32::from_rgb(22, 29, 39);
            v.extreme_bg_color = Color32::from_rgb(11, 15, 20);
            v.faint_bg_color = Color32::from_rgb(24, 32, 43);
            v.widgets.noninteractive.bg_fill = Color32::from_rgb(24, 32, 43);
            v.widgets.noninteractive.bg_stroke =
                Stroke::new(1.0_f32, Color32::from_rgb(44, 56, 74));
            v.widgets.inactive.bg_fill = Color32::from_rgb(33, 43, 58);
            v.widgets.hovered.bg_fill = Color32::from_rgb(44, 58, 78);
            v.widgets.active.bg_fill = Color32::from_rgb(52, 70, 94);
            v.selection.bg_fill = Color32::from_rgb(17, 130, 118);
            v.selection.stroke = Stroke::new(1.0_f32, ACCENT_DARK);
            v.widgets.noninteractive.corner_radius = CornerRadius::same(6);
            v.widgets.inactive.corner_radius = CornerRadius::same(6);
            v.widgets.hovered.corner_radius = CornerRadius::same(6);
            v.widgets.active.corner_radius = CornerRadius::same(6);
            v
        }
        ThemeMode::Light => {
            let mut v = Visuals::light();
            v.panel_fill = Color32::from_rgb(243, 246, 250);
            v.window_fill = Color32::from_rgb(255, 255, 255);
            v.extreme_bg_color = Color32::from_rgb(255, 255, 255);
            v.faint_bg_color = Color32::from_rgb(233, 238, 245);
            v.widgets.noninteractive.bg_fill = Color32::from_rgb(255, 255, 255);
            v.widgets.noninteractive.bg_stroke =
                Stroke::new(1.0_f32, Color32::from_rgb(212, 220, 232));
            v.selection.bg_fill = Color32::from_rgb(19, 132, 122);
            v.selection.stroke = Stroke::new(1.0_f32, ACCENT_LIGHT);
            v.widgets.noninteractive.corner_radius = CornerRadius::same(6);
            v.widgets.inactive.corner_radius = CornerRadius::same(6);
            v.widgets.hovered.corner_radius = CornerRadius::same(6);
            v.widgets.active.corner_radius = CornerRadius::same(6);
            v
        }
    };
    visuals.window_corner_radius = CornerRadius::same(8);
    let egui_theme = match mode {
        ThemeMode::Dark => egui::Theme::Dark,
        ThemeMode::Light => egui::Theme::Light,
    };
    ctx.set_theme(egui_theme);
    ctx.set_visuals_of(egui_theme, visuals);

    ctx.style_mut_of(egui_theme, |style| {
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 6.0);
        style.spacing.window_margin = egui::Margin::same(14);
    });
}

pub fn card_frame(visuals: &Visuals) -> egui::Frame {
    let (fill, stroke) = if visuals.dark_mode {
        (
            Color32::from_rgb(22, 29, 39),
            Stroke::new(1.0_f32, Color32::from_rgb(42, 54, 72)),
        )
    } else {
        (
            Color32::from_rgb(255, 255, 255),
            Stroke::new(1.0_f32, Color32::from_rgb(214, 222, 234)),
        )
    };

    egui::Frame::NONE
        .fill(fill)
        .stroke(stroke)
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::same(14))
}

pub fn accent_color(visuals: &Visuals) -> Color32 {
    if visuals.dark_mode {
        ACCENT_DARK
    } else {
        ACCENT_LIGHT
    }
}

pub fn primary_button<'a>(text: &'a str, visuals: &Visuals) -> egui::Button<'a> {
    let fill = if visuals.dark_mode {
        Color32::from_rgb(13, 148, 136)
    } else {
        ACCENT_LIGHT
    };
    egui::Button::new(egui::RichText::new(text).strong().color(Color32::WHITE))
        .fill(fill)
        .corner_radius(CornerRadius::same(6))
        .min_size(egui::vec2(140.0, 32.0))
}
