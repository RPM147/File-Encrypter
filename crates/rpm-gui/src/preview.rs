use crate::i18n::Strings;
use eframe::egui;
use image::{ImageFormat, ImageReader, Limits};
use std::{io::Cursor, path::Path};
use zeroize::Zeroizing;

pub enum ClassifiedPreview {
    Text(Zeroizing<String>),
    Image(egui::ColorImage),
    InvalidImage,
    Binary,
}

fn decode(bytes: &[u8], format: ImageFormat) -> Option<egui::ColorImage> {
    let reader = || ImageReader::with_format(Cursor::new(bytes), format);
    let (w, h) = reader().into_dimensions().ok()?;
    // Bound decoded memory independently of compressed file size.
    if w == 0 || h == 0 || w > 8192 || h > 8192 || u64::from(w) * u64::from(h) > 8 * 1024 * 1024 {
        return None;
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(64 * 1024 * 1024);
    let mut decoder = reader();
    decoder.limits(limits);
    let rgba = Zeroizing::new(decoder.decode().ok()?.into_rgba8().into_raw());
    Some(egui::ColorImage::from_rgba_unmultiplied(
        [w as usize, h as usize],
        &rgba,
    ))
}

pub fn classify_preview(path: &str, bytes: &[u8]) -> ClassifiedPreview {
    let format = Path::new(path)
        .extension()
        .and_then(ImageFormat::from_extension);
    if let Some(
        format @ (ImageFormat::Png
        | ImageFormat::Jpeg
        | ImageFormat::WebP
        | ImageFormat::Gif
        | ImageFormat::Bmp),
    ) = format
    {
        return decode(bytes, format)
            .map_or(ClassifiedPreview::InvalidImage, ClassifiedPreview::Image);
    }
    if !bytes.contains(&0) {
        if let Ok(text) = std::str::from_utf8(bytes) {
            return ClassifiedPreview::Text(Zeroizing::new(text.to_owned()));
        }
    }
    ClassifiedPreview::Binary
}

enum Content {
    Text(Zeroizing<String>),
    Image(egui::TextureHandle),
    InvalidImage,
    Binary,
}

pub struct PreviewState {
    path: String,
    size: usize,
    content: Content,
    page: usize,
}

impl PreviewState {
    pub fn new(ctx: &egui::Context, path: String, bytes: Zeroizing<Vec<u8>>) -> Self {
        let size = bytes.len();
        let classified = classify_preview(&path, &bytes);
        drop(bytes);
        let content = match classified {
            ClassifiedPreview::Text(text) => Content::Text(text),
            ClassifiedPreview::Image(image)
                if image.width().max(image.height()) > ctx.input(|i| i.max_texture_side) =>
            {
                Content::InvalidImage
            }
            ClassifiedPreview::Image(image) => {
                Content::Image(ctx.load_texture("vault-preview", image, Default::default()))
            }
            ClassifiedPreview::Binary => Content::Binary,
            ClassifiedPreview::InvalidImage => Content::InvalidImage,
        };
        Self {
            path,
            size,
            content,
            page: 0,
        }
    }

    pub(crate) fn show(&mut self, ctx: &egui::Context, s: &Strings) -> bool {
        let mut open = true;
        let mut close = false;
        egui::Window::new(s.preview_title)
            .id(egui::Id::unique("vault-preview"))
            .open(&mut open)
            .default_width(520.)
            .show(ctx, |ui| {
                ui.heading(&self.path);
                ui.label(format!("{} B · {}", self.size, s.preview_ram));
                match &self.content {
                    Content::Text(text) => {
                        // Keep egui's per-frame text layout bounded even for a single huge line.
                        const PAGE: usize = 8192;
                        let start = text.floor_char_boundary(self.page * PAGE);
                        let end =
                            text.floor_char_boundary(((self.page + 1) * PAGE).min(text.len()));
                        egui::ScrollArea::both().max_height(400.).show(ui, |ui| {
                            ui.monospace(&text[start..end]);
                        });
                        if text.len() > PAGE {
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(self.page > 0, egui::Button::new(s.preview_prev))
                                    .clicked()
                                {
                                    self.page -= 1;
                                }
                                if ui
                                    .add_enabled(
                                        end < text.len(),
                                        egui::Button::new(s.preview_next),
                                    )
                                    .clicked()
                                {
                                    self.page += 1;
                                }
                            });
                        }
                    }
                    Content::Image(texture) => {
                        let size = texture.size_vec2();
                        let scale = (ui.available_width() / size.x)
                            .min((ctx.content_rect().height() * 0.6) / size.y)
                            .clamp(0.01, 1.);
                        ui.image((texture.id(), size * scale));
                    }
                    Content::InvalidImage => {
                        ui.label(s.preview_image_error);
                    }
                    Content::Binary => {
                        ui.label(s.preview_binary);
                    }
                }
                close = ui.button(s.preview_close).clicked();
            });
        close || !open
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_window_renders_image_and_respects_renderer_limit() {
        let ctx = egui::Context::default();
        let png = include_bytes!("../assets/icon.png");
        let mut output = ctx.run_ui(Default::default(), |ui| {
            let mut state =
                PreviewState::new(ui.ctx(), "icon.png".into(), Zeroizing::new(png.to_vec()));
            assert!(matches!(state.content, Content::Image(_)));
            assert!(!state.show(ui.ctx(), &crate::i18n::EN));
            ui.ctx().input_mut(|i| i.max_texture_side = 1);
            let limited =
                PreviewState::new(ui.ctx(), "icon.png".into(), Zeroizing::new(png.to_vec()));
            assert!(matches!(limited.content, Content::InvalidImage));
        });
        // No renderer consumes texture uploads in this headless frame.
        output.textures_delta.clear();
    }
}
