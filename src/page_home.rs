// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Drawing code for "Security at a glance": the big status shield and the grid of
//! nine equal tiles. The grid is sized to the window so it never needs scrolling,
//! even on a 1366×768 screen; tiles show fewer lines when space is short.

use crate::App;
use crate::checks::{Action, CheckId, CheckResult, Level};
use crate::ui::{self, Icon};
use egui::{Align, Layout, Rect, RichText, Sense, StrokeKind, UiBuilder, Vec2};

/// Tile icon for each check.
fn icon_for(id: CheckId) -> Icon {
    match id {
        CheckId::SecurityUpdates => Icon::SecurityUpdates,
        CheckId::Firewall => Icon::Firewall,
        CheckId::Updates => Icon::Packages,
        CheckId::Snapper => Icon::Restore,
        CheckId::Antivirus => Icon::Virus,
        CheckId::Account => Icon::Account,
        CheckId::DeviceSecurity => Icon::Lock,
        CheckId::Health => Icon::Pulse,
        CheckId::Backup => Icon::Backup,
    }
}

/// Tile order (same as `checks::run_all`), shown while checking.
const ALL_TILES: [(CheckId, &str); 9] = [
    (CheckId::Antivirus, "Virus & threat protection"),
    (CheckId::SecurityUpdates, "Automatic security updates"),
    (CheckId::Updates, "Package & Flatpak updates"),
    (CheckId::Firewall, "Firewall & network protection"),
    (CheckId::Account, "Account protection"),
    (CheckId::DeviceSecurity, "Device security"),
    (CheckId::Health, "Device performance & health"),
    (CheckId::Snapper, "System restore"),
    (CheckId::Backup, "File backup"),
];

/// Tiles to show before the first check finishes (pages hidden by policy are left out).
fn placeholders() -> Vec<(CheckId, &'static str)> {
    let p = crate::policy::get();
    ALL_TILES
        .into_iter()
        .filter(|(id, _)| id.policy_page().map(|k| !p.hidden(k)).unwrap_or(true))
        .collect()
}

/// Space between tiles.
const GAP: f32 = 14.0;

/// How much fits in a tile of a given height.
#[derive(Clone, Copy)]
struct TileStyle {
    /// Icon size in points.
    icon: f32,
    /// Detail lines that fit.
    details: usize,
    /// Smaller fonts and spacing.
    compact: bool,
}

/// Choose icon size and number of detail lines for the tile height.
fn tile_style(h: f32) -> TileStyle {
    if h >= 300.0 {
        TileStyle {
            icon: 78.0,
            details: 3,
            compact: false,
        }
    } else if h >= 250.0 {
        TileStyle {
            icon: 64.0,
            details: 2,
            compact: false,
        }
    } else if h >= 205.0 {
        TileStyle {
            icon: 54.0,
            details: 1,
            compact: true,
        }
    } else if h >= 160.0 {
        TileStyle {
            icon: 44.0,
            details: 0,
            compact: true,
        }
    } else {
        TileStyle {
            icon: 34.0,
            details: 0,
            compact: true,
        }
    }
}

impl App {
    /// Drawn without a scroll area: the five tiles always fit the window and
    /// all have exactly the same size.
    pub fn page_home(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        // Re-check every 2 minutes while the page is visible.
        if self.checks.stale(std::time::Duration::from_secs(120)) {
            self.refresh_checks(&ctx);
        }
        ctx.request_repaint_after(std::time::Duration::from_secs(30));
        let results = self.checks.get();
        let busy = self.checks.busy();

        // ---- hero banner
        let warn = results
            .as_ref()
            .map(|r| r.iter().filter(|c| c.level == Level::Warn).count());
        let short = ui.available_height() < 680.0;
        ui.horizontal(|ui| {
            let size = if short { 64.0 } else { 84.0 };
            // Same artwork as the tray icon.
            let level = warn.map(|w| if w == 0 { Level::Ok } else { Level::Warn });
            ui.add(ui::status_shield(level, size));
            ui.add_space(10.0);
            ui.vertical(|ui| {
                ui.label(RichText::new("Security at a glance").size(if short { 24.0 } else { 28.0 }).strong());
                if !short {
                    ui.label(
                        RichText::new("See what's happening with the security and health of your device and take any actions needed.")
                            .color(ui::weak(ui)),
                    );
                }
                let text = match warn {
                    None => "Checking your device…".to_string(),
                    Some(0) => "Your device is protected. No action needed.".to_string(),
                    Some(1) => "1 item needs your attention.".to_string(),
                    Some(n) => format!("{n} items need your attention."),
                };
                ui.horizontal(|ui| {
                    ui.label(RichText::new(text).size(15.5).strong());
                    ui.add_space(10.0);
                    if busy {
                        ui.add(egui::Spinner::new());
                    } else if ui::icon_button(ui, Icon::Refresh, "Check again").clicked() {
                        self.refresh_checks(&ctx);
                        self.refresh_clam(&ctx);
                    }
                    if self.report_busy {
                        ui.add(egui::Spinner::new());
                    } else if ui::icon_button(ui, Icon::Report, "Export report")
                        .on_hover_text("Save a security report of this computer (HTML; print it to PDF from the browser).")
                        .clicked()
                    {
                        self.export_report(&ctx);
                    }
                });
            });
        });
        ui.add_space(14.0);

        // ---- equal-size grid filling the rest of the page
        let area = ui.available_rect_before_wrap();
        let tiles = placeholders();
        let n = tiles.len();
        let cols: usize = if area.width() >= 3.0 * 215.0 + 2.0 * GAP {
            3
        } else if area.width() >= 2.0 * 220.0 + GAP {
            2
        } else {
            1
        };
        let rows = n.div_ceil(cols);
        let tile_w = ((area.width() - GAP * (cols as f32 - 1.0)) / cols as f32).floor();
        let tile_h = ((area.height() - GAP * (rows as f32 - 1.0)) / rows as f32)
            .floor()
            .clamp(125.0, 340.0);
        let style = tile_style(tile_h);

        let mut clicked: Option<Action> = None;
        for (i, placeholder) in tiles.iter().enumerate() {
            let (r, c) = (i / cols, i % cols);
            let min = area.min + Vec2::new(c as f32 * (tile_w + GAP), r as f32 * (tile_h + GAP));
            let rect = Rect::from_min_size(min, Vec2::new(tile_w, tile_h));
            let result = results.as_ref().and_then(|v| v.get(i));
            if let Some(a) = tile(ui, rect, result, *placeholder, style) {
                clicked = Some(a);
            }
        }
        // Claim the space so nothing else draws over the grid.
        ui.allocate_rect(
            Rect::from_min_size(
                area.min,
                Vec2::new(area.width(), rows as f32 * (tile_h + GAP) - GAP),
            ),
            Sense::hover(),
        );
        if let Some(a) = clicked {
            self.do_action(&ctx, &a);
        }
    }
}

/// Draw one tile into `rect`. Returns the action of a clicked button.
fn tile(
    ui: &mut egui::Ui,
    rect: Rect,
    r: Option<&CheckResult>,
    (id, fallback_title): (CheckId, &str),
    st: TileStyle,
) -> Option<Action> {
    let painter = ui.painter();
    painter.rect(
        rect,
        8,
        ui::card_fill(ui),
        egui::Stroke::new(
            1.0,
            ui.visuals()
                .widgets
                .noninteractive
                .bg_stroke
                .color
                .linear_multiply(0.6),
        ),
        StrokeKind::Inside,
    );
    let inner = rect.shrink2(Vec2::new(16.0, if st.compact { 12.0 } else { 18.0 }));
    let mut clicked = None;

    // Actions are anchored to the bottom so buttons line up across tiles.
    let actions: Vec<Action> = r.map(|r| r.actions.clone()).unwrap_or_default();
    let shown_actions = if st.compact {
        actions.len().min(1)
    } else {
        actions.len().min(2)
    };
    let action_h = shown_actions as f32 * 34.0;
    let top = Rect::from_min_max(
        inner.min,
        egui::pos2(inner.max.x, inner.max.y - action_h - 4.0),
    );
    let bottom = Rect::from_min_max(egui::pos2(inner.min.x, inner.max.y - action_h), inner.max);

    ui.scope_builder(
        UiBuilder::new()
            .max_rect(top)
            .layout(Layout::top_down(Align::Center)),
        |ui| {
            ui.set_clip_rect(top.intersect(ui.clip_rect()));
            ui::badged_icon(ui, icon_for(id), st.icon, r.map(|r| r.level));
            ui.add_space(if st.compact { 2.0 } else { 6.0 });
            ui.label(
                RichText::new(r.map(|r| r.title).unwrap_or(fallback_title))
                    .size(16.5)
                    .strong(),
            );
            match r {
                None => {
                    ui.add(egui::Spinner::new());
                    ui::small(ui, "Checking…");
                }
                Some(r) => {
                    let color = if r.level == Level::Ok {
                        ui.visuals().text_color()
                    } else {
                        ui.visuals().strong_text_color()
                    };
                    let headline = egui::Label::new(RichText::new(&r.headline).color(color));
                    if st.compact {
                        ui.add(headline.truncate()).on_hover_text(&r.headline);
                    } else {
                        ui.add(headline.wrap());
                    }
                    if let Some((label, value, good)) = &r.status_item {
                        // One wrapping text: a long value moves to a second line.
                        let color = if *good { ui::GREEN } else { ui::RED };
                        let font = egui::FontId::proportional(13.0);
                        let mut job = egui::text::LayoutJob::default();
                        job.append(
                            &format!("{label}: "),
                            0.0,
                            egui::TextFormat {
                                font_id: font.clone(),
                                color: ui::weak(ui),
                                ..Default::default()
                            },
                        );
                        job.append(
                            value,
                            0.0,
                            egui::TextFormat {
                                font_id: font,
                                color,
                                // keep "Not installed" together when it wraps
                                ..Default::default()
                            },
                        );
                        job.halign = egui::Align::Center;
                        job.wrap.max_width = ui.available_width();
                        let h = ui.fonts_mut(|f| f.layout_job(job.clone())).size().y;
                        if h <= ui.available_height() {
                            ui.add(egui::Label::new(job).wrap());
                        }
                    }
                    for d in r.details.iter().take(st.details) {
                        // Only draw a line (wrapped to 1-2 rows) when it fully fits above the buttons.
                        let color = ui::weak(ui);
                        let h = ui
                            .fonts_mut(|f| {
                                f.layout(
                                    d.clone(),
                                    egui::FontId::proportional(12.5),
                                    color,
                                    ui.available_width(),
                                )
                            })
                            .size()
                            .y;
                        if h + 2.0 > ui.available_height() {
                            break;
                        }
                        ui.add(egui::Label::new(RichText::new(d).size(12.5).color(color)).wrap());
                    }
                }
            }
        },
    );

    if let Some(r) = r {
        ui.scope_builder(
            UiBuilder::new()
                .max_rect(bottom)
                .layout(Layout::top_down(Align::Center)),
            |ui| {
                for (i, a) in actions.iter().take(shown_actions).enumerate() {
                    let resp = if i == 0 && r.level == Level::Warn {
                        ui::primary_button(ui, &a.label())
                    } else {
                        ui::link(ui, &a.label())
                    };
                    if resp.clicked() {
                        clicked = Some(a.clone());
                    }
                }
            },
        );
    }
    clicked
}
