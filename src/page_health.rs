// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Drawing code for the "Device performance & health" page: restart, storage,
//! disk health (including bad sectors), battery and memory. Data comes from
//! `health.rs`.

use crate::page_account::status_row;
use crate::sys;
use crate::ui::{self, Icon};
use crate::{AfterAdmin, App};
use egui::RichText;

impl App {
    /// Draw the Device performance & health page.
    pub fn page_health(&mut self, ui: &mut egui::Ui) {
        // Sections: "Restart" (why one is recommended), "Storage" (free space, clean-up), "Disk
        // health" (SMART data per drive), "Battery" (wear), "Memory".
        let ctx = ui.ctx().clone();
        if self.health.stale(std::time::Duration::from_secs(60)) {
            self.health.refresh(&ctx, crate::health::load);
        }
        ui::page_header(
            ui,
            Icon::Pulse,
            "Device performance & health",
            "Restarts, storage, disk health and battery.",
        );
        let Some(h) = self.health.get() else {
            ui.add(egui::Spinner::new());
            return;
        };

        // ---- restart
        ui::section_title(ui, "Restart");
        ui::card(ui, |ui| {
            if h.restart.required {
                status_row(
                    ui,
                    Some(false),
                    "Restart recommended",
                    &h.restart.headline(),
                );
                for r in h
                    .restart
                    .reasons
                    .iter()
                    .filter(|_| !(h.restart.long_uptime && h.restart.reasons.len() == 1))
                {
                    ui::small(ui, r);
                }
                ui.add_space(6.0);
                if ui::primary_button(ui, "Restart now").clicked() {
                    self.confirm_restart = true;
                }
            } else {
                status_row(
                    ui,
                    Some(true),
                    "No restart needed",
                    &format!("Running for {}.", uptime_text(h.uptime_secs)),
                );
            }
        });

        // ---- storage
        ui::section_title(ui, "Storage");
        ui::card(ui, |ui| {
            for d in &h.disks {
                let name = if d.mount == "/" {
                    "System drive"
                } else {
                    &d.mount
                };
                status_row(
                    ui,
                    Some(!d.low()),
                    &format!(
                        "{name}: {} free of {}",
                        sys::fmt_bytes(d.free),
                        sys::fmt_bytes(d.size)
                    ),
                    if d.low() {
                        "Low on space. Programs and updates may stop working."
                    } else {
                        "Enough free space."
                    },
                );
                let frac = d.used_fraction();
                let fill = if d.low() { ui::RED } else { ui::accent(ui) };
                ui.scope(|ui| {
                    ui.visuals_mut().extreme_bg_color = if ui.visuals().dark_mode {
                        egui::Color32::from_gray(60)
                    } else {
                        egui::Color32::from_gray(225)
                    };
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .fill(fill)
                            .desired_height(8.0)
                            .desired_width(ui.available_width().min(520.0)),
                    );
                });
                ui.add_space(8.0);
            }
            ui.separator();
            ui.add_space(4.0);
            ui.label(RichText::new("Free up space").strong());
            ui::small(
                ui,
                format!(
                    "Your trash: {}   ·   Picture previews cache: {}",
                    sys::fmt_bytes(h.trash_bytes),
                    sys::fmt_bytes(h.thumbnails_bytes)
                ),
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui::button(ui, "Empty trash and cache").on_hover_text("Deletes the files in your trash and the picture preview cache. No password needed.").clicked() {
                    let freed = crate::health::clean_user_files();
                    self.toast(format!("Freed {}.", sys::fmt_bytes(freed)));
                    self.health.refresh(&ctx, crate::health::load);
                    self.refresh_checks(&ctx);
                }
                if ui::button(ui, "Clean up system files")
                    .on_hover_text("Removes downloaded update files, packages that are no longer needed, old logs and unused Flatpak runtimes.")
                    .clicked()
                {
                    self.run_admin(&ctx, "Cleaning up system files", &["cleanup"], AfterAdmin::RefreshAll, true);
                }
                if ui::link(ui, "See what uses space").clicked() && !sys::spawn_detached("filelight", &[&sys::home().to_string_lossy()]) {
                    self.toast("Install Filelight to see what uses space.");
                }
            });
        });

        // ---- disk health
        ui::section_title(ui, "Disk health");
        ui::card(ui, |ui| {
            if h.smart_unavailable {
                status_row(
                    ui,
                    None,
                    "Disk health is unknown",
                    "The UDisks2 service is not available on this computer.",
                );
            } else if h.drives.is_empty() {
                status_row(
                    ui,
                    None,
                    "No disks report their health",
                    "Virtual machines and some USB disks don't provide health data.",
                );
            }
            for d in &h.drives {
                let mut info = vec![sys::fmt_bytes(d.size)];
                if let Some(t) = d.temperature_c {
                    info.push(format!("{t:.0} °C"));
                }
                if let Some(hrs) = d.power_on_hours {
                    info.push(format!("used for {hrs} hours"));
                }
                if let Some(w) = d.wear_percent {
                    info.push(format!("{w}% of rated life used"));
                }
                if let Some(b) = d.bad_sectors_text() {
                    info.push(b);
                }
                let text = if d.warnings.is_empty() {
                    format!("Healthy · {}", info.join(" · "))
                } else {
                    format!(
                        "{} Back up your files and replace this disk. ({})",
                        d.warnings.join(" "),
                        info.join(" · ")
                    )
                };
                let bad = d.bad_sectors.unwrap_or(0) > 0;
                status_row(ui, Some(!d.failing && !bad), &d.model, &text);
                ui.add_space(4.0);
            }
        });

        // ---- battery
        if !h.batteries.is_empty() {
            ui::section_title(ui, "Battery");
            ui::card(ui, |ui| {
                for b in &h.batteries {
                    let mut parts = vec![];
                    if let Some(c) = b.charge {
                        parts.push(format!("charged {c}%"));
                    }
                    if let Some(cy) = b.cycles {
                        parts.push(format!("{cy} charge cycles"));
                    }
                    match b.health_percent {
                        Some(p) => status_row(
                            ui,
                            Some(p >= 40.0),
                            &format!("Battery health: {p:.0}%"),
                            &format!(
                                "{}{}",
                                if p < 40.0 {
                                    "The battery holds much less charge than when new. Consider replacing it. "
                                } else {
                                    ""
                                },
                                parts.join(" · ")
                            ),
                        ),
                        None => status_row(ui, None, &b.name, &parts.join(" · ")),
                    }
                }
            });
        }

        // ---- memory
        ui::section_title(ui, "Memory");
        ui::card(ui, |ui| {
            ui.label(format!(
                "{} available of {}",
                sys::fmt_bytes(h.memory_available),
                sys::fmt_bytes(h.memory_total)
            ));
        });
    }
}

/// "3 day(s) 4 hour(s)" style uptime.
fn uptime_text(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 {
        format!("{d} day(s) {h} hour(s)")
    } else if h > 0 {
        format!("{h} hour(s) {m} min")
    } else {
        format!("{m} min")
    }
}
