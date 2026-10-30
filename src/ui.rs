// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Look & feel: colors, line icons, status badges and reusable widgets.

use crate::checks::Level;
use egui::{Color32, CornerRadius, FontId, Pos2, Rect, Sense, Stroke, Vec2};

/// "OK" green, the same as Windows Security's.
pub const GREEN: Color32 = Color32::from_rgb(16, 124, 16);
/// "Needs attention" yellow.
pub const AMBER: Color32 = Color32::from_rgb(252, 185, 0);
/// Errors and "Not installed"-style values.
pub const RED: Color32 = Color32::from_rgb(209, 52, 56);
/// Buttons and links in the light theme.
pub const ACCENT: Color32 = Color32::from_rgb(0, 103, 192);
/// Buttons and links in the dark theme (lighter, for contrast).
pub const ACCENT_DARK_THEME: Color32 = Color32::from_rgb(76, 194, 255);

/// Accent color for the current theme.
pub fn accent(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        ACCENT_DARK_THEME
    } else {
        ACCENT
    }
}

/// Background of a card (white in light theme).
pub fn card_fill(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(43, 43, 43)
    } else {
        Color32::WHITE
    }
}

/// Background of the page behind the cards.
pub fn page_fill(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(32, 32, 32)
    } else {
        Color32::from_rgb(243, 243, 243)
    }
}

/// Background of the side menu.
pub fn nav_fill(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(39, 39, 39)
    } else {
        Color32::from_rgb(235, 235, 235)
    }
}

/// Color for secondary text.
pub fn weak(ui: &egui::Ui) -> Color32 {
    ui.visuals().weak_text_color()
}

// ------------------------------------------------------------------ icons

/// Line icons (original artwork), drawn white so they can be tinted.
macro_rules! svg {
    ($body:literal) => {
        concat!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="96" height="96" fill="none" stroke="#ffffff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">"##,
            $body,
            "</svg>"
        )
    };
}

/// The line icons used in the side menu, tiles and buttons.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Icon {
    Menu,
    Home,
    Virus,
    Firewall,
    SecurityUpdates,
    Packages,
    Restore,
    Chip,
    Refresh,
    Search,
    External,
    Account,
    Lock,
    Pulse,
    Apps,
    Backup,
    Report,
}

impl Icon {
    /// SVG source of the icon.
    fn svg(self) -> &'static str {
        match self {
            Icon::Menu => svg!(r#"<path d="M4 6.5h16M4 12h16M4 17.5h16"/>"#),
            Icon::Home => svg!(
                r#"<path d="M3 11.2 12 3.5l9 7.7"/><path d="M5.5 9.3V20.5h4.8v-6h3.4v6h4.8V9.3"/>"#
            ),
            Icon::Virus => svg!(
                r#"<path d="M12 2.5 4.2 5.4v6.1c0 4.9 3.3 8.5 7.8 10 4.5-1.5 7.8-5.1 7.8-10V5.4z"/><path d="M7.3 12.2h2.4l1.4-2.9 1.9 5.6 1.4-2.7h2.3"/>"#
            ),
            Icon::Firewall => svg!(
                r#"<rect x="3" y="5" width="18" height="14" rx="1.2"/><path d="M3 9.7h18M3 14.3h18M9 5v4.7M15 5v4.7M6 9.7v4.6M12 9.7v4.6M18 9.7v4.6M9 14.3V19M15 14.3V19"/>"#
            ),
            Icon::SecurityUpdates => svg!(
                r#"<path d="M19.6 13.5a7.8 7.8 0 0 1-14 3.4"/><path d="M4.4 10.5a7.8 7.8 0 0 1 14-3.4"/><path d="M18.9 3.3v4.4h-4.4"/><path d="M5.1 20.7v-4.4h4.4"/><path d="M12 8.6 9.3 9.7v1.9c0 1.6 1.1 2.8 2.7 3.3 1.6-.5 2.7-1.7 2.7-3.3V9.7z"/>"#
            ),
            Icon::Packages => svg!(
                r#"<path d="M12 2.8 20.3 7.4v9.2L12 21.2l-8.3-4.6V7.4z"/><path d="M3.7 7.4 12 12l8.3-4.6M12 12v9.2M7.8 5.1l8.3 4.6"/>"#
            ),
            Icon::Restore => svg!(
                r#"<path d="M3.8 12.5A8.3 8.3 0 1 0 6.2 6"/><path d="M3.2 3.6V8h4.4"/><path d="M12 7.6V12l3.1 2"/>"#
            ),
            Icon::Chip => svg!(
                r#"<rect x="6" y="6" width="12" height="12" rx="1.5"/><rect x="9.4" y="9.4" width="5.2" height="5.2" rx=".6"/><path d="M9 2.8V6M12 2.8V6M15 2.8V6M9 18v3.2M12 18v3.2M15 18v3.2M2.8 9H6M2.8 12H6M2.8 15H6M18 9h3.2M18 12h3.2M18 15h3.2"/>"#
            ),
            Icon::Refresh => svg!(
                r#"<path d="M19.6 13.5a7.8 7.8 0 0 1-14 3.4"/><path d="M4.4 10.5a7.8 7.8 0 0 1 14-3.4"/><path d="M18.9 3.3v4.4h-4.4"/><path d="M5.1 20.7v-4.4h4.4"/>"#
            ),
            Icon::Search => {
                svg!(r#"<circle cx="10.5" cy="10.5" r="6.3"/><path d="m15.3 15.3 5.2 5.2"/>"#)
            }
            Icon::External => svg!(
                r#"<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>"#
            ),
            Icon::Account => svg!(
                r#"<circle cx="12" cy="8" r="4.2"/><path d="M4 20.5c.8-4 4-6.3 8-6.3s7.2 2.3 8 6.3"/>"#
            ),
            Icon::Lock => svg!(
                r#"<rect x="5" y="10.5" width="14" height="10" rx="1.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/><path d="M12 14.5v2.5"/>"#
            ),
            Icon::Pulse => svg!(
                r#"<path d="M12 20.3S3.5 15 3.5 9.2A4.5 4.5 0 0 1 12 7a4.5 4.5 0 0 1 8.5 2.2C20.5 15 12 20.3 12 20.3z"/><path d="M6 12h3l1.5-2.5 2 5 1.5-2.5h4"/>"#
            ),
            Icon::Apps => svg!(
                r#"<rect x="4" y="4" width="6.5" height="6.5" rx="1.2"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.2"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.2"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.2"/>"#
            ),
            Icon::Backup => svg!(
                r#"<path d="M7 18.5h10.5a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.6 9.1 4.7 4.7 0 0 0 7 18.5z"/><path d="M12 16.5v-6M9.5 13l2.5-2.5 2.5 2.5"/>"#
            ),
            Icon::Report => svg!(
                r#"<path d="M6 3.5h8l4 4v13H6z"/><path d="M14 3.5v4h4M9 12h6M9 15h6M9 18h4"/>"#
            ),
        }
    }

    /// egui image cache key; one per icon.
    fn uri(self) -> String {
        format!("bytes://proton-icon-{self:?}.svg")
    }

    /// The icon as an egui image of `size` points, tinted with `tint`.
    pub fn image(self, size: f32, tint: Color32) -> egui::Image<'static> {
        egui::Image::from_bytes(self.uri(), self.svg().as_bytes())
            .fit_to_exact_size(Vec2::splat(size))
            .tint(tint)
    }

    /// Draw the icon into `rect`.
    pub fn paint(self, ui: &egui::Ui, rect: Rect, tint: Color32) {
        self.image(rect.width(), tint).paint_at(ui, rect);
    }
}

// ------------------------------------------------------------------ badges

/// Green check / yellow exclamation badge, like Windows Security.
pub fn paint_badge(
    painter: &egui::Painter,
    center: Pos2,
    r: f32,
    level: Option<Level>,
    outline: Color32,
) {
    painter.circle_filled(center, r + 2.0, outline);
    match level {
        Some(Level::Ok) => {
            painter.circle_filled(center, r, GREEN);
            let s = r * 0.5;
            let pts = vec![
                center + Vec2::new(-s * 0.95, 0.05 * s),
                center + Vec2::new(-s * 0.25, s * 0.72),
                center + Vec2::new(s, -s * 0.62),
            ];
            painter.line(pts, Stroke::new((r * 0.24).max(1.6), Color32::WHITE));
        }
        Some(Level::Warn) => {
            painter.circle_filled(center, r, AMBER);
            let w = (r * 0.22).max(1.8);
            painter.line_segment(
                [
                    center + Vec2::new(0.0, -r * 0.55),
                    center + Vec2::new(0.0, r * 0.15),
                ],
                Stroke::new(w, Color32::BLACK),
            );
            painter.circle_filled(center + Vec2::new(0.0, r * 0.5), w * 0.65, Color32::BLACK);
        }
        None => {
            painter.circle_filled(center, r, Color32::from_gray(140));
            for dx in [-0.45, 0.0, 0.45] {
                painter.circle_filled(center + Vec2::new(r * dx, 0.0), r * 0.12, Color32::WHITE);
            }
        }
    }
}

/// White "!" badge: worth knowing, but not a problem (doesn't turn
/// anything yellow).
pub fn paint_notice_badge(painter: &egui::Painter, center: Pos2, r: f32, outline: Color32) {
    painter.circle_filled(center, r + 2.0, outline);
    painter.circle_filled(center, r, Color32::WHITE);
    painter.circle_stroke(center, r, Stroke::new(1.2, Color32::from_gray(150)));
    let w = (r * 0.22).max(1.8);
    let ink = Color32::from_gray(60);
    painter.line_segment(
        [
            center + Vec2::new(0.0, -r * 0.55),
            center + Vec2::new(0.0, r * 0.15),
        ],
        Stroke::new(w, ink),
    );
    painter.circle_filled(center + Vec2::new(0.0, r * 0.5), w * 0.65, ink);
}

/// Large icon with a status badge in its lower-right corner.
pub fn badged_icon(
    ui: &mut egui::Ui,
    icon: Icon,
    size: f32,
    level: Option<Level>,
) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let tint = ui.visuals().strong_text_color();
    let inner = rect.shrink(size * 0.06);
    icon.paint(ui, inner, tint);
    let r = size * 0.17;
    let c = rect.right_bottom() - Vec2::new(r + 1.0, r + 1.0);
    let outline = card_fill(ui);
    paint_badge(ui.painter(), c, r, level, outline);
    resp
}

/// Small inline status dot + text.
pub fn status_line(ui: &mut egui::Ui, level: Option<Level>, text: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
        let outline = ui.visuals().panel_fill;
        paint_badge(ui.painter(), rect.center(), 8.0, level, outline);
        ui.label(text);
    });
}

// ------------------------------------------------------------------ widgets

/// A white rounded card (the boxes on every page). Returns whatever `add` returns.
pub fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(card_fill(ui))
        .stroke(Stroke::new(
            1.0,
            ui.visuals()
                .widgets
                .noninteractive
                .bg_stroke
                .color
                .linear_multiply(0.6),
        ))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::same(18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// Page title with a line icon, like the Windows Security section headers.
pub fn page_header(ui: &mut egui::Ui, icon: Icon, title: &str, subtitle: &str) {
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.add(icon.image(40.0, ui.visuals().strong_text_color()));
        ui.add_space(6.0);
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(title).size(28.0).strong());
            ui.label(egui::RichText::new(subtitle).color(weak(ui)));
        });
    });
    ui.add_space(14.0);
}

/// Heading above a card.
pub fn section_title(ui: &mut egui::Ui, text: &str) {
    ui.add_space(14.0);
    ui.label(egui::RichText::new(text).size(19.0).strong());
    ui.add_space(6.0);
}

/// Filled accent-colored button for the main action.
pub fn primary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let fill = accent(ui);
    let fg = if ui.visuals().dark_mode {
        Color32::BLACK
    } else {
        Color32::WHITE
    };
    ui.add(
        egui::Button::new(egui::RichText::new(text).color(fg))
            .fill(fill)
            .corner_radius(CornerRadius::same(4))
            .min_size(Vec2::new(0.0, 30.0)),
    )
}

/// Normal grey button.
pub fn button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(text)
            .corner_radius(CornerRadius::same(4))
            .min_size(Vec2::new(0.0, 30.0)),
    )
}

/// A one-line text box with a visible border (unfocused boxes are white on white in the light
/// theme otherwise).
pub fn text_field(ui: &mut egui::Ui, value: &mut String, width: f32, hint: &str) -> egui::Response {
    let stroke = Stroke::new(
        1.0,
        if ui.visuals().dark_mode {
            Color32::from_gray(110)
        } else {
            Color32::from_gray(165)
        },
    );
    ui.add(
        egui::TextEdit::singleline(value)
            .hint_text(hint)
            .desired_width(width)
            .frame(
                egui::Frame::new()
                    .stroke(stroke)
                    .corner_radius(4)
                    .inner_margin(egui::Margin::symmetric(6, 4))
                    .fill(ui.visuals().extreme_bg_color),
            ),
    )
}

/// Normal grey button that can be greyed out (`enabled = false`).
pub fn add_enabled_button(ui: &mut egui::Ui, enabled: bool, text: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(text)
            .corner_radius(CornerRadius::same(4))
            .min_size(Vec2::new(0.0, 30.0)),
    )
}

/// Button with a small icon before the text.
pub fn icon_button(ui: &mut egui::Ui, icon: Icon, text: &str) -> egui::Response {
    let tint = ui.visuals().text_color();
    ui.add(
        egui::Button::image_and_text(icon.image(16.0, tint), text)
            .corner_radius(CornerRadius::same(4))
            .min_size(Vec2::new(0.0, 30.0)),
    )
}

/// Underlined text that behaves like a link (opens settings, other apps…).
pub fn link(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let c = accent(ui);
    ui.add(egui::Label::new(egui::RichText::new(text).color(c).underline()).sense(Sense::click()))
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Small grey text for explanations and notes.
pub fn small(ui: &mut egui::Ui, text: impl Into<String>) {
    ui.label(egui::RichText::new(text.into()).size(13.0).color(weak(ui)));
}

/// Fonts sizes, spacing and colors for the whole app (light and dark themes).
pub fn setup_style(ctx: &egui::Context) {
    use egui::TextStyle::*;
    ctx.all_styles_mut(|s| {
        s.text_styles.insert(Body, FontId::proportional(14.5));
        s.text_styles.insert(Button, FontId::proportional(14.5));
        s.text_styles.insert(Heading, FontId::proportional(22.0));
        s.text_styles.insert(Small, FontId::proportional(12.5));
        s.text_styles.insert(Monospace, FontId::monospace(13.0));
        s.spacing.item_spacing = Vec2::new(8.0, 7.0);
        s.spacing.button_padding = Vec2::new(12.0, 5.0);
        s.spacing.interact_size.y = 26.0;
        let dark = s.visuals.dark_mode;
        s.visuals.panel_fill = page_fill(dark);
        s.visuals.window_fill = card_fill_for(dark);
        s.visuals.selection.bg_fill = if dark {
            Color32::from_rgb(0, 84, 140)
        } else {
            Color32::from_rgb(204, 228, 247)
        };
        s.visuals.selection.stroke.color = if dark {
            Color32::WHITE
        } else {
            Color32::from_rgb(0, 40, 80)
        };
        s.visuals.hyperlink_color = if dark { ACCENT_DARK_THEME } else { ACCENT };
    });
}

/// [`card_fill`] for a given theme, before a `Ui` exists.
fn card_fill_for(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(43, 43, 43)
    } else {
        Color32::WHITE
    }
}

// ------------------------------------------------------------------ status shield

/// Shield outline (64×64 view box) shared by the status icons.
const SHIELD_PATH: &str = "M32 4 9 12.5v17.2C9 44.6 18.8 55.3 32 60c13.2-4.7 23-15.4 23-30.3V12.5z";

/// The status shield shared by the tray icon and "Security at a glance":
/// green with a check, yellow with an exclamation mark, gray while checking.
pub fn status_shield_svg(level: Option<Level>) -> String {
    let (fill, mark) = match level {
        Some(Level::Ok) => (
            "#1f9d3a",
            r##"<path d="M21 32.5l7.5 7.5L44 24.5" fill="none" stroke="#fff" stroke-width="6.5" stroke-linecap="round" stroke-linejoin="round"/>"##,
        ),
        Some(Level::Warn) => (
            "#f5b400",
            r##"<path d="M32 18v17" stroke="#1b1b1b" stroke-width="7" stroke-linecap="round"/><circle cx="32" cy="45" r="4.2" fill="#1b1b1b"/>"##,
        ),
        None => ("#8a8f98", ""),
    };
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="256" height="256"><path d="{SHIELD_PATH}" fill="{fill}" stroke="#00000033" stroke-width="1.5"/>{mark}</svg>"##
    )
}

/// The status shield as an egui image (the big shield on "Security at a glance").
pub fn status_shield(level: Option<Level>, size: f32) -> egui::Image<'static> {
    let key = match level {
        Some(Level::Ok) => "ok",
        Some(Level::Warn) => "warn",
        None => "checking",
    };
    egui::Image::from_bytes(
        format!("bytes://proton-status-shield-{key}.svg"),
        status_shield_svg(level).into_bytes(),
    )
    .fit_to_exact_size(Vec2::splat(size))
}
