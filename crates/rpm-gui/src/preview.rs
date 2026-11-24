//! Enhanced RAM-only zero-disk preview viewer:
//! - UTF-8 text with line-snapped pagination, line numbers, and Unicode-safe Ctrl+F search.
//! - Decoded PNG/JPEG/WebP/GIF/BMP image with zoom, Fit/100%, and lossless 90-degree rotation.
//! - Binary files rendered as a paginated, read-only hex + ASCII view in zeroized RAM.

use std::io::Cursor;
use std::path::Path;
use std::sync::atomic::{compiler_fence, Ordering};

use eframe::egui;
use image::{ImageFormat, ImageReader, Limits};
use zeroize::Zeroizing;

use crate::i18n::Strings;

pub const TEXT_PAGE_BYTES: usize = 8192;
pub const MAX_TEXT_MATCHES: usize = 10_000;
pub const HEX_PAGE_BYTES: usize = 4096;
pub const IMAGE_ZOOM_MIN: f32 = 0.25;
pub const IMAGE_ZOOM_MAX: f32 = 4.0;

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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TextMatch {
    pub byte_start: usize,
    pub byte_end: usize,
    pub line: usize,
    pub page: usize,
}

/// Partition `text` into valid UTF-8 `(start, end)` pages, preferring newline boundaries.
pub fn compute_text_pages(text: &str, page_bytes: usize) -> Vec<(usize, usize)> {
    let page_bytes = page_bytes.max(1);
    if text.is_empty() {
        return vec![(0, 0)];
    }
    let mut pages = Vec::new();
    let mut pos = 0usize;
    while pos < text.len() {
        let mut max_end = text.floor_char_boundary(pos.saturating_add(page_bytes).min(text.len()));
        if max_end <= pos {
            let next_ch_len = text[pos..].chars().next().map_or(1, char::len_utf8);
            max_end = (pos + next_ch_len).min(text.len());
        }
        let end = if max_end < text.len() {
            if let Some(nl_rel) = text[pos..max_end].rfind('\n') {
                pos + nl_rel + 1
            } else {
                max_end
            }
        } else {
            max_end
        };
        pages.push((pos, end));
        pos = end;
    }
    pages
}

fn compute_page_first_lines(text: &str, pages: &[(usize, usize)]) -> Vec<usize> {
    let mut out = Vec::with_capacity(pages.len());
    let mut line = 1usize;
    let mut prev_end = 0usize;
    for &(start, _end) in pages {
        if start > prev_end {
            line += text[prev_end..start]
                .bytes()
                .filter(|&b| b == b'\n')
                .count();
            prev_end = start;
        }
        out.push(line);
    }
    out
}

fn push_folded_char(ch: char, out: &mut String, push_byte: &mut impl FnMut()) {
    if ch == 'İ' {
        out.push('i');
        push_byte();
    } else {
        for lc in ch.to_lowercase() {
            let mut buf = [0u8; 4];
            let encoded = lc.encode_utf8(&mut buf);
            out.push_str(encoded);
            for _ in 0..encoded.len() {
                push_byte();
            }
        }
    }
}

fn fold_query_for_search(query: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(query.len()));
    for ch in query.chars() {
        push_folded_char(ch, &mut out, &mut || {});
    }
    out
}

/// Find case-insensitive UTF-8-safe occurrences of `query` in `text`, up to `limit` matches.
pub fn find_text_matches(
    text: &str,
    query: &str,
    pages: &[(usize, usize)],
    limit: usize,
) -> (Vec<TextMatch>, bool) {
    if query.is_empty() || text.is_empty() || pages.is_empty() || limit == 0 {
        return (Vec::new(), false);
    }

    let mut matches = Vec::new();
    let mut truncated = false;
    let mut page_idx = 0usize;

    if text.is_ascii() && query.is_ascii() {
        let hay = text.as_bytes();
        let needle = query.as_bytes();
        if needle.len() > hay.len() {
            return (Vec::new(), false);
        }
        let mut line = 1usize;
        let mut last_counted = 0usize;
        let mut pos = 0usize;
        let max_start = hay.len() - needle.len();
        while pos <= max_start {
            if hay[pos..pos + needle.len()].eq_ignore_ascii_case(needle) {
                line += hay[last_counted..pos]
                    .iter()
                    .filter(|&&b| b == b'\n')
                    .count();
                last_counted = pos;
                while page_idx + 1 < pages.len() && pages[page_idx].1 <= pos {
                    page_idx += 1;
                }
                if matches.len() >= limit {
                    truncated = true;
                    break;
                }
                matches.push(TextMatch {
                    byte_start: pos,
                    byte_end: pos + needle.len(),
                    line,
                    page: page_idx,
                });
                pos += needle.len();
            } else {
                pos += 1;
            }
        }
        return (matches, truncated);
    }

    let folded_query = fold_query_for_search(query);
    if folded_query.is_empty() {
        return (Vec::new(), false);
    }

    let mut folded_line = Zeroizing::new(String::new());
    let mut byte_starts: Vec<u32> = Vec::new();
    let mut byte_ends: Vec<u32> = Vec::new();
    let mut line_offset = 0usize;

    for (line_idx, raw_line) in text.split_inclusive('\n').enumerate() {
        let line_no = line_idx + 1;
        folded_line.clear();
        byte_starts.clear();
        byte_ends.clear();

        for (rel_idx, ch) in raw_line.char_indices() {
            let orig_s = (line_offset + rel_idx) as u32;
            let orig_e = (line_offset + rel_idx + ch.len_utf8()) as u32;
            push_folded_char(ch, &mut folded_line, &mut || {
                byte_starts.push(orig_s);
                byte_ends.push(orig_e);
            });
        }

        for (m_idx, _) in folded_line.match_indices(folded_query.as_str()) {
            let m_end_idx = m_idx + folded_query.len() - 1;
            let orig_start = byte_starts[m_idx] as usize;
            let orig_end = byte_ends[m_end_idx] as usize;
            if let Some(prev) = matches.last() {
                if prev.byte_start == orig_start && prev.byte_end == orig_end {
                    continue;
                }
            }
            while page_idx + 1 < pages.len() && pages[page_idx].1 <= orig_start {
                page_idx += 1;
            }
            if matches.len() >= limit {
                truncated = true;
                return (matches, truncated);
            }
            matches.push(TextMatch {
                byte_start: orig_start,
                byte_end: orig_end,
                line: line_no,
                page: page_idx,
            });
        }

        line_offset += raw_line.len();
    }

    (matches, truncated)
}

/// Losslessly rotate a RGBA `ColorImage` 90 degrees clockwise.
pub fn rotate_color_image_cw(src: &egui::ColorImage) -> egui::ColorImage {
    let [w, h] = src.size;
    if w == 0 || h == 0 {
        return src.clone();
    }
    let mut out = egui::ColorImage::filled([h, w], egui::Color32::TRANSPARENT);
    for y in 0..h {
        for x in 0..w {
            let nx = h - 1 - y;
            let ny = x;
            out.pixels[ny * h + nx] = src.pixels[y * w + x];
        }
    }
    out
}

/// Losslessly rotate a RGBA `ColorImage` 90 degrees counter-clockwise.
pub fn rotate_color_image_ccw(src: &egui::ColorImage) -> egui::ColorImage {
    let [w, h] = src.size;
    if w == 0 || h == 0 {
        return src.clone();
    }
    let mut out = egui::ColorImage::filled([h, w], egui::Color32::TRANSPARENT);
    for y in 0..h {
        for x in 0..w {
            let nx = y;
            let ny = w - 1 - x;
            out.pixels[ny * h + nx] = src.pixels[y * w + x];
        }
    }
    out
}

/// Format a 16-bytes-per-row read-only hexadecimal and ASCII dump for one page.
pub fn format_hex_page(bytes: &[u8], page: usize, page_size: usize) -> String {
    if bytes.is_empty() || page_size == 0 {
        return String::new();
    }
    let start = page.saturating_mul(page_size).min(bytes.len());
    let end = start.saturating_add(page_size).min(bytes.len());
    let slice = &bytes[start..end];
    let rows = slice.len().div_ceil(16);
    let mut out = String::with_capacity(rows * 80);

    for (row_idx, chunk) in slice.chunks(16).enumerate() {
        use std::fmt::Write;
        let offset = start + row_idx * 16;
        let _ = write!(out, "{offset:08x}  ");
        for i in 0..16 {
            if i == 8 {
                out.push(' ');
            }
            if let Some(&b) = chunk.get(i) {
                let _ = write!(out, "{b:02x} ");
            } else {
                out.push_str("   ");
            }
        }
        out.push_str(" |");
        for &b in chunk {
            let ch = if (0x20..=0x7E).contains(&b) {
                b as char
            } else {
                '.'
            };
            out.push(ch);
        }
        out.push('|');
        if row_idx + 1 < rows {
            out.push('\n');
        }
    }
    out
}

struct TextPreview {
    text: Zeroizing<String>,
    pages: Vec<(usize, usize)>,
    page_first_line: Vec<usize>,
    page: usize,
    show_line_numbers: bool,
    search_query: String,
    last_searched_query: String,
    matches: Vec<TextMatch>,
    matches_truncated: bool,
    active_match: usize,
}

impl TextPreview {
    fn new(text: Zeroizing<String>) -> Self {
        let pages = compute_text_pages(&text, TEXT_PAGE_BYTES);
        let page_first_line = compute_page_first_lines(&text, &pages);
        Self {
            text,
            pages,
            page_first_line,
            page: 0,
            show_line_numbers: true,
            search_query: String::new(),
            last_searched_query: String::new(),
            matches: Vec::new(),
            matches_truncated: false,
            active_match: 0,
        }
    }

    fn sync_search(&mut self) {
        if self.search_query == self.last_searched_query {
            return;
        }
        self.last_searched_query = self.search_query.clone();
        let (matches, truncated) = find_text_matches(
            &self.text,
            &self.search_query,
            &self.pages,
            MAX_TEXT_MATCHES,
        );
        self.matches = matches;
        self.matches_truncated = truncated;
        self.active_match = 0;
        if let Some(first) = self.matches.first() {
            self.page = first.page;
        }
    }

    fn set_search_query(&mut self, query: &str) {
        self.search_query = query.to_owned();
        self.sync_search();
    }

    fn next_match(&mut self) {
        if self.matches.is_empty() {
            return;
        }
        self.active_match = (self.active_match + 1) % self.matches.len();
        self.page = self.matches[self.active_match].page;
    }

    fn prev_match(&mut self) {
        if self.matches.is_empty() {
            return;
        }
        self.active_match = if self.active_match == 0 {
            self.matches.len() - 1
        } else {
            self.active_match - 1
        };
        self.page = self.matches[self.active_match].page;
    }

    fn build_page_layout(&self, style: &egui::Style) -> egui::text::LayoutJob {
        let mut job = egui::text::LayoutJob::default();
        let mono = egui::TextStyle::Monospace.resolve(style);
        let normal_fg = style.visuals.text_color();
        let gutter_fg = style.visuals.weak_text_color();
        let normal_fmt = egui::TextFormat::simple(mono.clone(), normal_fg);
        let gutter_fmt = egui::TextFormat::simple(mono.clone(), gutter_fg);
        let mut other_match_fmt = egui::TextFormat::simple(mono.clone(), normal_fg);
        other_match_fmt.background = egui::Color32::from_rgba_unmultiplied(20, 184, 166, 95);
        let mut active_match_fmt = egui::TextFormat::simple(mono, egui::Color32::BLACK);
        active_match_fmt.background = egui::Color32::from_rgb(245, 190, 60);

        let (page_start, page_end) = self.pages[self.page];
        let slice = &self.text[page_start..page_end];
        if slice.is_empty() {
            if self.show_line_numbers {
                job.append("    1 | ", 0.0, gutter_fmt);
            }
            return job;
        }

        let first_line = self.page_first_line.get(self.page).copied().unwrap_or(1);
        let mut pos = 0usize;
        let mut match_cursor = self.matches.partition_point(|m| m.byte_end <= page_start);

        for (line_no, raw_line) in (first_line..).zip(slice.split_inclusive('\n')) {
            let line_abs_start = page_start + pos;
            let line_abs_end = line_abs_start + raw_line.len();
            pos += raw_line.len();

            if self.show_line_numbers {
                job.append(&format!("{line_no:>5} | "), 0.0, gutter_fmt.clone());
            }

            let mut cursor = line_abs_start;
            while match_cursor > 0 && self.matches[match_cursor - 1].byte_end > line_abs_start {
                match_cursor -= 1;
            }
            while match_cursor < self.matches.len()
                && self.matches[match_cursor].byte_start < line_abs_end
            {
                let m = &self.matches[match_cursor];
                let ms = m.byte_start.max(cursor).min(line_abs_end);
                let me = m.byte_end.min(line_abs_end).max(ms);
                if ms > cursor {
                    job.append(&self.text[cursor..ms], 0.0, normal_fmt.clone());
                }
                if me > ms {
                    let fmt = if match_cursor == self.active_match {
                        active_match_fmt.clone()
                    } else {
                        other_match_fmt.clone()
                    };
                    job.append(&self.text[ms..me], 0.0, fmt);
                }
                cursor = me;
                if m.byte_end > line_abs_end {
                    break;
                }
                match_cursor += 1;
            }
            if cursor < line_abs_end {
                job.append(&self.text[cursor..line_abs_end], 0.0, normal_fmt.clone());
            }
        }

        job
    }
}

struct ImagePreview {
    image: egui::ColorImage,
    texture: egui::TextureHandle,
    zoom: f32,
    fit_to_window: bool,
    rotation_deg: u16,
}

impl ImagePreview {
    fn new(ctx: &egui::Context, image: egui::ColorImage) -> Self {
        let texture = ctx.load_texture("vault-preview", image.clone(), Default::default());
        Self {
            image,
            texture,
            zoom: 1.0,
            fit_to_window: true,
            rotation_deg: 0,
        }
    }

    fn zoom_in(&mut self) {
        self.fit_to_window = false;
        self.zoom = (self.zoom * 1.25).clamp(IMAGE_ZOOM_MIN, IMAGE_ZOOM_MAX);
    }

    fn zoom_out(&mut self) {
        self.fit_to_window = false;
        self.zoom = (self.zoom / 1.25).clamp(IMAGE_ZOOM_MIN, IMAGE_ZOOM_MAX);
    }

    fn reset_100(&mut self) {
        self.fit_to_window = false;
        self.zoom = 1.0;
    }

    fn rotate_cw(&mut self) {
        let rotated = rotate_color_image_cw(&self.image);
        let mut old = std::mem::replace(&mut self.image, rotated);
        old.pixels.fill(egui::Color32::TRANSPARENT);
        compiler_fence(Ordering::SeqCst);
        self.rotation_deg = (self.rotation_deg + 90) % 360;
        self.texture.set(self.image.clone(), Default::default());
    }

    fn rotate_ccw(&mut self) {
        let rotated = rotate_color_image_ccw(&self.image);
        let mut old = std::mem::replace(&mut self.image, rotated);
        old.pixels.fill(egui::Color32::TRANSPARENT);
        compiler_fence(Ordering::SeqCst);
        self.rotation_deg = (self.rotation_deg + 270) % 360;
        self.texture.set(self.image.clone(), Default::default());
    }
}

impl Drop for ImagePreview {
    fn drop(&mut self) {
        self.image.pixels.fill(egui::Color32::TRANSPARENT);
        compiler_fence(Ordering::SeqCst);
    }
}

struct HexPreview {
    bytes: Zeroizing<Vec<u8>>,
    page: usize,
}

impl HexPreview {
    fn page_count(&self) -> usize {
        self.bytes.len().max(1).div_ceil(HEX_PAGE_BYTES)
    }
}

enum Content {
    Text(TextPreview),
    Image(ImagePreview),
    InvalidImage,
    Binary(HexPreview),
}

pub struct PreviewState {
    path: String,
    size: usize,
    content: Content,
}

impl PreviewState {
    pub fn new(ctx: &egui::Context, path: String, bytes: Zeroizing<Vec<u8>>) -> Self {
        let size = bytes.len();
        let classified = classify_preview(&path, &bytes);
        let content = match classified {
            ClassifiedPreview::Text(text) => {
                drop(bytes);
                Content::Text(TextPreview::new(text))
            }
            ClassifiedPreview::Image(mut image)
                if image.width().max(image.height()) > ctx.input(|i| i.max_texture_side) =>
            {
                drop(bytes);
                image.pixels.fill(egui::Color32::TRANSPARENT);
                compiler_fence(Ordering::SeqCst);
                Content::InvalidImage
            }
            ClassifiedPreview::Image(image) => {
                drop(bytes);
                Content::Image(ImagePreview::new(ctx, image))
            }
            ClassifiedPreview::Binary => Content::Binary(HexPreview { bytes, page: 0 }),
            ClassifiedPreview::InvalidImage => {
                drop(bytes);
                Content::InvalidImage
            }
        };
        Self {
            path,
            size,
            content,
        }
    }

    pub fn set_search_query(&mut self, query: &str) {
        if let Content::Text(tp) = &mut self.content {
            tp.set_search_query(query);
        }
    }

    pub fn search_match_count(&self) -> usize {
        match &self.content {
            Content::Text(tp) => tp.matches.len(),
            _ => 0,
        }
    }

    pub fn active_search_match(&self) -> Option<TextMatch> {
        match &self.content {
            Content::Text(tp) => tp.matches.get(tp.active_match).copied(),
            _ => None,
        }
    }

    pub fn next_search_match(&mut self) {
        if let Content::Text(tp) = &mut self.content {
            tp.next_match();
        }
    }

    pub fn prev_search_match(&mut self) {
        if let Content::Text(tp) = &mut self.content {
            tp.prev_match();
        }
    }

    pub fn current_page(&self) -> usize {
        match &self.content {
            Content::Text(tp) => tp.page,
            Content::Binary(hp) => hp.page,
            _ => 0,
        }
    }

    pub fn zoom_in(&mut self) {
        if let Content::Image(img) = &mut self.content {
            img.zoom_in();
        }
    }

    pub fn zoom_out(&mut self) {
        if let Content::Image(img) = &mut self.content {
            img.zoom_out();
        }
    }

    pub fn set_fit_to_window(&mut self, fit: bool) {
        if let Content::Image(img) = &mut self.content {
            img.fit_to_window = fit;
        }
    }

    pub fn rotate_cw(&mut self) {
        if let Content::Image(img) = &mut self.content {
            img.rotate_cw();
        }
    }

    pub fn rotate_ccw(&mut self) {
        if let Content::Image(img) = &mut self.content {
            img.rotate_ccw();
        }
    }

    pub fn image_dimensions(&self) -> Option<[usize; 2]> {
        match &self.content {
            Content::Image(img) => Some(img.image.size),
            _ => None,
        }
    }

    pub fn image_rotation_deg(&self) -> Option<u16> {
        match &self.content {
            Content::Image(img) => Some(img.rotation_deg),
            _ => None,
        }
    }

    pub fn image_zoom(&self) -> Option<f32> {
        match &self.content {
            Content::Image(img) => Some(img.zoom),
            _ => None,
        }
    }

    pub(crate) fn show(&mut self, ctx: &egui::Context, s: &Strings) -> bool {
        let mut open = true;
        let mut close = false;
        let focus_search =
            ctx.input(|i| (i.modifiers.ctrl || i.modifiers.command) && i.key_pressed(egui::Key::F));
        let shift_down = ctx.input(|i| i.modifiers.shift);

        egui::Window::new(s.preview_title)
            .id(egui::Id::unique("vault-preview"))
            .open(&mut open)
            .default_width(600.)
            .show(ctx, |ui| {
                ui.heading(&self.path);
                ui.label(format!("{} B · {}", self.size, s.preview_ram));
                ui.add_space(4.0);
                match &mut self.content {
                    Content::Text(tp) => {
                        ui.horizontal_wrapped(|ui| {
                            let search_resp = ui.add(
                                egui::TextEdit::singleline(&mut tp.search_query)
                                    .hint_text(s.preview_search_hint)
                                    .desired_width(210.0),
                            );
                            if focus_search {
                                search_resp.request_focus();
                            }
                            tp.sync_search();
                            if search_resp.lost_focus()
                                && ui.input(|i| i.key_pressed(egui::Key::Enter))
                            {
                                if shift_down {
                                    tp.prev_match();
                                } else {
                                    tp.next_match();
                                }
                                search_resp.request_focus();
                            }

                            let count_text = if tp.search_query.is_empty() {
                                String::new()
                            } else if tp.matches.is_empty() {
                                "0 / 0".to_owned()
                            } else if tp.matches_truncated {
                                format!("{} / {}+", tp.active_match + 1, tp.matches.len())
                            } else {
                                format!("{} / {}", tp.active_match + 1, tp.matches.len())
                            };
                            if !count_text.is_empty() {
                                ui.weak(count_text);
                            }

                            let has_matches = !tp.matches.is_empty();
                            if ui
                                .add_enabled(has_matches, egui::Button::new("↑").small())
                                .on_hover_text(s.preview_match_prev)
                                .clicked()
                            {
                                tp.prev_match();
                            }
                            if ui
                                .add_enabled(has_matches, egui::Button::new("↓").small())
                                .on_hover_text(s.preview_match_next)
                                .clicked()
                            {
                                tp.next_match();
                            }
                            if !tp.search_query.is_empty() && ui.small_button("×").clicked() {
                                tp.set_search_query("");
                            }
                            ui.checkbox(&mut tp.show_line_numbers, s.preview_line_numbers);
                        });

                        ui.add_space(4.0);
                        let job = tp.build_page_layout(ui.style());
                        egui::ScrollArea::both().max_height(380.).show(ui, |ui| {
                            ui.add(egui::Label::new(job).selectable(true));
                        });

                        let page_count = tp.pages.len();
                        if page_count > 1 {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(tp.page > 0, egui::Button::new(s.preview_prev))
                                    .clicked()
                                {
                                    tp.page -= 1;
                                }
                                ui.weak(format!("{} / {page_count}", tp.page + 1));
                                if ui
                                    .add_enabled(
                                        tp.page + 1 < page_count,
                                        egui::Button::new(s.preview_next),
                                    )
                                    .clicked()
                                {
                                    tp.page += 1;
                                }
                            });
                        }
                    }
                    Content::Image(img) => {
                        let [w, h] = img.image.size;
                        let fit_scale = (ui.available_width() / (w.max(1) as f32))
                            .min((ctx.content_rect().height() * 0.6) / (h.max(1) as f32))
                            .clamp(0.01, 1.0);
                        let active_scale = if img.fit_to_window {
                            fit_scale
                        } else {
                            img.zoom
                        };

                        ui.horizontal_wrapped(|ui| {
                            if ui.small_button("-").clicked() {
                                img.zoom_out();
                            }
                            if ui.small_button("+").clicked() {
                                img.zoom_in();
                            }
                            if ui
                                .selectable_label(
                                    !img.fit_to_window && (img.zoom - 1.0).abs() < 0.01,
                                    "100%",
                                )
                                .clicked()
                            {
                                img.reset_100();
                            }
                            if ui
                                .selectable_label(img.fit_to_window, s.preview_zoom_fit)
                                .clicked()
                            {
                                img.fit_to_window = true;
                            }
                            if ui
                                .small_button("↶ 90°")
                                .on_hover_text(s.preview_rotate_left)
                                .clicked()
                            {
                                img.rotate_ccw();
                            }
                            if ui
                                .small_button("↷ 90°")
                                .on_hover_text(s.preview_rotate_right)
                                .clicked()
                            {
                                img.rotate_cw();
                            }
                            let zoom_pct = (active_scale * 100.0).round() as u32;
                            ui.weak(format!("{w}×{h} · {zoom_pct}% · {}°", img.rotation_deg));
                        });

                        ui.add_space(4.0);
                        let tex_size = img.texture.size_vec2();
                        let tex_id = img.texture.id();
                        egui::ScrollArea::both().max_height(420.).show(ui, |ui| {
                            ui.image((tex_id, tex_size * active_scale));
                        });
                    }
                    Content::InvalidImage => {
                        ui.label(s.preview_image_error);
                    }
                    Content::Binary(hp) => {
                        ui.label(s.preview_binary);
                        ui.add_space(4.0);
                        if hp.bytes.is_empty() {
                            ui.weak(s.preview_empty_binary);
                        } else {
                            let hex_text = format_hex_page(&hp.bytes, hp.page, HEX_PAGE_BYTES);
                            egui::ScrollArea::both().max_height(380.).show(ui, |ui| {
                                ui.add(
                                    egui::Label::new(egui::RichText::new(hex_text).monospace())
                                        .selectable(true),
                                );
                            });
                            let page_count = hp.page_count();
                            if page_count > 1 {
                                let start = hp.page * HEX_PAGE_BYTES;
                                let end = (start + HEX_PAGE_BYTES).min(hp.bytes.len());
                                ui.add_space(4.0);
                                ui.horizontal(|ui| {
                                    if ui
                                        .add_enabled(hp.page > 0, egui::Button::new(s.preview_prev))
                                        .clicked()
                                    {
                                        hp.page -= 1;
                                    }
                                    ui.weak(format!(
                                        "{} / {page_count} (0x{start:08x}..0x{end:08x})",
                                        hp.page + 1
                                    ));
                                    if ui
                                        .add_enabled(
                                            hp.page + 1 < page_count,
                                            egui::Button::new(s.preview_next),
                                        )
                                        .clicked()
                                    {
                                        hp.page += 1;
                                    }
                                });
                            }
                        }
                    }
                }
                ui.add_space(6.0);
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

    #[test]
    fn text_pagination_unicode_search_and_navigation_work() {
        // Multi-page text (>16 KiB) with Turkish uppercase dotted-I cases plus an >10 KiB unbroken line
        let mut raw = String::new();
        raw.push_str("Birinci satır İstanbul\n");
        for i in 2..=320 {
            raw.push_str(&format!(
                "Satır {i:03} dolgu metni abcdefghijklmnopqrstuvwxyz 0123456789\n"
            ));
        }
        raw.push_str(&"x".repeat(10_500));
        raw.push('\n');
        raw.push_str("Son satır İSTANBUL ve istanbul\n");

        let pages = compute_text_pages(&raw, TEXT_PAGE_BYTES);
        assert!(pages.len() >= 3);
        for &(s, e) in &pages {
            assert!(raw.is_char_boundary(s));
            assert!(raw.is_char_boundary(e));
        }

        let ctx = egui::Context::default();
        let mut st = PreviewState::new(
            &ctx,
            "notes.txt".into(),
            Zeroizing::new(raw.as_bytes().to_vec()),
        );
        st.set_search_query("istanbul");
        assert_eq!(st.search_match_count(), 3);
        let m0 = st.active_search_match().unwrap();
        assert_eq!(m0.line, 1);
        assert_eq!(m0.page, 0);

        st.next_search_match();
        let m1 = st.active_search_match().unwrap();
        assert!(m1.page > 0);
        assert_eq!(st.current_page(), m1.page);

        st.next_search_match();
        st.next_search_match(); // wraps back to m0
        assert_eq!(st.active_search_match().unwrap().line, 1);
        st.prev_search_match(); // wraps back to last match
        let last = st.active_search_match().unwrap();
        assert!(last.byte_start > m0.byte_start);
        assert!(st.current_page() > 0);

        let mut out = ctx.run_ui(Default::default(), |ui| {
            assert!(!st.show(ui.ctx(), &crate::i18n::TR));
        });
        out.textures_delta.clear();
    }

    #[test]
    fn image_rotation_and_zoom_round_trip() {
        let mut pixels = Vec::new();
        for i in 0u8..8 {
            pixels.push(egui::Color32::from_rgb(i * 30, i * 10 + 5, 200 - i * 20));
        }
        let img = egui::ColorImage {
            size: [4, 2],
            source_size: egui::Vec2::new(4.0, 2.0),
            pixels: pixels.clone(),
        };

        let cw1 = rotate_color_image_cw(&img);
        assert_eq!(cw1.size, [2, 4]);
        let ccw_back = rotate_color_image_ccw(&cw1);
        assert_eq!(ccw_back.size, [4, 2]);
        assert_eq!(ccw_back.pixels, pixels);

        let mut rot = img.clone();
        for _ in 0..4 {
            rot = rotate_color_image_cw(&rot);
        }
        assert_eq!(rot.size, [4, 2]);
        assert_eq!(rot.pixels, pixels);

        // Exercise PreviewState zoom & rotate controls + headless render
        let dyn_img = image::DynamicImage::ImageRgba8(image::RgbaImage::from_fn(4, 2, |x, y| {
            image::Rgba([(x * 50) as u8, (y * 100) as u8, 128, 255])
        }));
        let mut buf = Vec::new();
        dyn_img
            .write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
            .unwrap();
        let ctx = egui::Context::default();
        let mut st = PreviewState::new(&ctx, "rect.png".into(), Zeroizing::new(buf));
        assert_eq!(st.image_dimensions(), Some([4, 2]));
        assert_eq!(st.image_rotation_deg(), Some(0));

        st.rotate_cw();
        assert_eq!(st.image_dimensions(), Some([2, 4]));
        assert_eq!(st.image_rotation_deg(), Some(90));
        st.rotate_ccw();
        assert_eq!(st.image_dimensions(), Some([4, 2]));
        assert_eq!(st.image_rotation_deg(), Some(0));

        st.zoom_out();
        for _ in 0..10 {
            st.zoom_out();
        }
        assert_eq!(st.image_zoom(), Some(IMAGE_ZOOM_MIN));
        for _ in 0..20 {
            st.zoom_in();
        }
        assert_eq!(st.image_zoom(), Some(IMAGE_ZOOM_MAX));
        st.set_fit_to_window(true);

        let mut out = ctx.run_ui(Default::default(), |ui| {
            assert!(!st.show(ui.ctx(), &crate::i18n::EN));
        });
        out.textures_delta.clear();
    }

    #[test]
    fn binary_hex_formatter_and_pagination_work() {
        assert_eq!(format_hex_page(&[], 0, HEX_PAGE_BYTES), "");
        let sample = b"\x00Hello  world!\x7f\xff\x10Z";
        let dump = format_hex_page(sample, 0, HEX_PAGE_BYTES);
        assert!(dump.contains(
            "00000000  00 48 65 6c 6c 6f 20 20  77 6f 72 6c 64 21 7f ff  |.Hello  world!..|"
        ));
        assert!(dump.contains("00000010  10 5a"));
        assert!(dump.contains("|.Z|"));

        // Multi-page binary (>4096 bytes) renders cleanly
        let large = vec![0x41u8; HEX_PAGE_BYTES + 32];
        let p1 = format_hex_page(&large, 1, HEX_PAGE_BYTES);
        assert!(p1.starts_with("00001000  "));

        let ctx = egui::Context::default();
        let mut st = PreviewState::new(&ctx, "blob.bin".into(), Zeroizing::new(large));
        let mut out = ctx.run_ui(Default::default(), |ui| {
            assert!(!st.show(ui.ctx(), &crate::i18n::EN));
        });
        out.textures_delta.clear();
    }
}
