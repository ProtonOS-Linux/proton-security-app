// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Drawing code for the "Restore & backup" page: restore point status and schedule,
//! the restore point list, and the "Create restore point" dialog. Data comes from
//! `restore.rs`.

use crate::checks::Level;
use crate::restore::{self, Snapshot};
use crate::sys;
use crate::ui::{self, Icon};
use crate::{AfterAdmin, App};
use egui::RichText;

/// Snapshot type in words (pre/post pairs are made around software changes).
fn kind_text(s: &Snapshot) -> String {
    match s.kind.as_str() {
        "pre" => "Before change".into(),
        "post" => match s.pre_number {
            Some(n) => format!("After change (pairs with #{n})"),
            None => "After change".into(),
        },
        _ => "Single".into(),
    }
}

/// Snapshot description in words, translating Snapper's own names.
fn description_text(s: &Snapshot) -> String {
    let d = s.description.trim();

    match d {
        "timeline" => "Scheduled restore point".to_string(),
        "boot" => "Created at startup".to_string(),
        "apt" => "Software change (apt)".to_string(),
        "" => match s.cleanup.as_str() {
            "timeline" => "Scheduled restore point".into(),
            _ => "(no description)".into(),
        },
        other => other.to_string(),
    }
}

/// Snapper date in a friendlier format.
fn pretty_date(d: &str) -> String {
    chrono::NaiveDateTime::parse_from_str(d, "%Y-%m-%d %H:%M:%S")
        .map(|t| t.format("%b %-d, %Y  %-I:%M %p").to_string())
        .unwrap_or_else(|_| d.to_string())
}

/// Description text allowed by the helper (kept in sync with it).
pub fn valid_description(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 80
        && s.chars()
            .all(|c| c.is_alphanumeric() || " .,-_()/:".contains(c))
}

impl App {
    /// Draw the Restore & backup page.
    pub fn page_restore(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if self.restore.last.is_none() {
            self.refresh_restore(&ctx);
        }
        ui::page_header(
            ui,
            Icon::Restore,
            "Restore & backup",
            "Back up your personal files, and roll the system back to an earlier state with Snapper restore points.",
        );

        self.backup_card(ui);
        ui::section_title(ui, "System restore points");

        let Some(st) = self.restore.get() else {
            ui.add(egui::Spinner::new());
            return;
        };

        // ---- overview
        let schedules = st.effective_schedules();
        let scheduled = !schedules.is_empty();
        let recent = st.has_recent(8.0);
        ui::card(ui, |ui| {
            let (level, text) = if !st.btrfs() {
                (
                    Level::Warn,
                    "Your system drive is not Btrfs, so restore points are not available.",
                )
            } else if !st.installed {
                (Level::Warn, "Snapper is not installed.")
            } else if !st.configured() {
                (Level::Warn, "System restore is not set up yet.")
            } else if scheduled || recent {
                (Level::Ok, "System restore is on.")
            } else {
                (
                    Level::Warn,
                    "No automatic restore point schedule was found.",
                )
            };
            ui::status_line(ui, Some(level), text);
            ui.add_space(4.0);
            egui::Grid::new("restore_info")
                .num_columns(2)
                .spacing([24.0, 4.0])
                .show(ui, |ui| {
                    let row = |ui: &mut egui::Ui, k: &str, v: String| {
                        ui.label(RichText::new(k).color(ui::weak(ui)));
                        ui.label(v);
                        ui.end_row();
                    };
                    row(
                        ui,
                        "System drive",
                        if st.root_fs.is_empty() {
                            "unknown".into()
                        } else {
                            st.root_fs.clone()
                        },
                    );
                    row(
                        ui,
                        "Snapper",
                        if st.installed {
                            "Installed".into()
                        } else {
                            "Not installed".into()
                        },
                    );
                    if st.installed {
                        row(
                            ui,
                            "Configurations",
                            if st.configs.is_empty() {
                                "none".into()
                            } else {
                                st.configs.join(", ")
                            },
                        );
                    }
                    if schedules.is_empty() {
                        if st.installed {
                            row(ui, "Automatic schedule", "None found".into());
                        }
                    } else {
                        for (i, s) in schedules.iter().enumerate() {
                            let mut v = s.when.clone();
                            if let Some(n) = &s.next {
                                v.push_str(&format!("   (next: {n})"));
                            }
                            row(ui, if i == 0 { "Automatic schedule" } else { "" }, v);
                        }
                    }
                    if let Some(t) = st.latest().and_then(|s| s.time()) {
                        row(
                            ui,
                            "Last restore point",
                            format!("{} ({})", sys::fmt_time(t), sys::fmt_ago(t)),
                        );
                    }
                });
            if st.btrfs() && (!st.installed || !st.configured() || !(scheduled || recent)) {
                ui.add_space(6.0);
                if ui::primary_button(ui, "Turn on system restore").clicked() {
                    self.run_admin(
                        &ctx,
                        "Turning on system restore points",
                        &["enable-snapper"],
                        AfterAdmin::RefreshAll,
                        true,
                    );
                }
            }
        });
        ui.add_space(10.0);

        // ---- toolbar
        ui.horizontal(|ui| {
            ui.add_enabled_ui(st.installed && st.configured(), |ui| {
                if ui::primary_button(ui, "Create restore point").clicked() {
                    self.create_dialog = Some(String::new());
                }
            });
            if ui::icon_button(ui, Icon::Refresh, "Refresh").clicked() {
                self.refresh_restore(&ctx);
                if self.snapshot_override.is_some() {
                    self.run_admin(
                        &ctx,
                        "Reading restore points",
                        &["snapper-list"],
                        AfterAdmin::SnapperList,
                        false,
                    );
                }
            }
            if st.assistant_installed {
                if ui::icon_button(ui, Icon::External, "Open Btrfs Assistant")
                    .on_hover_text(
                        "Roll back, compare, delete restore points and change Snapper settings",
                    )
                    .clicked()
                {
                    let cmd = restore::assistant_command().unwrap_or("btrfs-assistant-launcher");
                    if !sys::spawn_detached(cmd, &[]) {
                        self.toast("Could not start Btrfs Assistant.");
                    }
                }
            } else if ui::icon_button(ui, Icon::External, "Install Btrfs Assistant").clicked() {
                self.run_admin(
                    &ctx,
                    "Installing Btrfs Assistant",
                    &["install-btrfs-assistant"],
                    AfterAdmin::RefreshAll,
                    true,
                );
            }
        });
        ui.add_space(8.0);

        if !st.installed || !st.configured() {
            return;
        }
        if let Some(e) = &st.error {
            ui::card(ui, |ui| ui::status_line(ui, Some(Level::Warn), e));
            ui.add_space(8.0);
        }

        let snaps = self
            .snapshot_override
            .clone()
            .unwrap_or(st.snapshots.clone());
        if st.needs_admin && self.snapshot_override.is_none() {
            // Snapper only lets administrators read the list. Nothing runs as
            // admin until the user asks for it here.
            ui::card(ui, |ui| {
                ui.label("Snapper only shows restore points to administrators. Enter your password to see the list.");
                ui.add_space(6.0);
                if ui::primary_button(ui, "Show restore points").clicked() {
                    self.run_admin(
                        &ctx,
                        "Reading restore points",
                        &["snapper-list"],
                        AfterAdmin::SnapperList,
                        false,
                    );
                }
            });
            return;
        }

        // ---- list
        ui::section_title(ui, &format!("{} restore point(s)", snaps.len()));
        ui::card(ui, |ui| {
            if snaps.is_empty() {
                ui::small(
                    ui,
                    "No restore points yet. Create one now, or wait for the next scheduled one.",
                );
                return;
            }
            egui::ScrollArea::horizontal().show(ui, |ui| {
                egui::Grid::new("snaps")
                    .striped(true)
                    .num_columns(5)
                    .spacing([22.0, 7.0])
                    .show(ui, |ui| {
                        for h in ["#", "Date", "Description", "Type", "Kept by"] {
                            ui.label(RichText::new(h).strong());
                        }
                        ui.end_row();
                        for s in &snaps {
                            let num = if st.configs.len() > 1 {
                                format!("{}:{}", s.config, s.number)
                            } else {
                                s.number.to_string()
                            };
                            ui.label(num);
                            ui.label(pretty_date(&s.date));
                            let mut d = description_text(s);
                            if s.default || s.active {
                                d.push_str("  (current system)");
                            }
                            let resp = ui.label(d);
                            if !s.userdata.is_empty() || !s.user.is_empty() {
                                resp.on_hover_text(format!(
                                    "Created by {}\n{}",
                                    s.user, s.userdata
                                ));
                            }
                            ui.label(kind_text(s));
                            ui.label(match s.cleanup.as_str() {
                                "timeline" => "Schedule",
                                "number" => "Count limit",
                                "" => "Until deleted",
                                other => other,
                            });
                            ui.end_row();
                        }
                    });
            });
        });
        ui.add_space(6.0);
        ui::small(
            ui,
            "To roll back, compare files or delete restore points, use Btrfs Assistant.",
        );
    }

    /// The "Create restore point" dialog (description, then the helper makes the snapshot).
    pub fn create_restore_dialog(&mut self, ctx: &egui::Context) {
        let Some(mut desc) = self.create_dialog.take() else {
            return;
        };
        let mut keep = true;
        let mut create = false;
        egui::Modal::new(egui::Id::unique("create_restore"))
            .frame(
                egui::Frame::popup(&ctx.global_style())
                    .inner_margin(20)
                    .corner_radius(10),
            )
            .show(ctx, |ui| {
                ui.set_width(440.0);
                ui.label(RichText::new("Create a restore point").size(18.0).strong());
                ui.add_space(4.0);
                ui.label("Type a description to help you identify the restore point:");
                let r = ui.add(
                    egui::TextEdit::singleline(&mut desc)
                        .desired_width(f32::INFINITY)
                        .hint_text("Before installing new software"),
                );
                r.request_focus();
                let valid = valid_description(&desc);
                if !desc.is_empty() && !valid {
                    ui::small(
                        ui,
                        "Use letters, numbers, spaces and . , - _ ( ) / : (max 80 characters).",
                    );
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(valid, |ui| {
                        if ui::primary_button(ui, "Create").clicked()
                            || (valid && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                        {
                            create = true;
                        }
                    });
                    if ui::button(ui, "Cancel").clicked()
                        || ui.input(|i| i.key_pressed(egui::Key::Escape))
                    {
                        keep = false;
                    }
                });
            });
        if create {
            let d = desc.trim().to_string();
            self.run_admin(
                ctx,
                "Creating a restore point",
                &["snapper-create", &d],
                AfterAdmin::RefreshAll,
                true,
            );
            self.snapshot_override = None;
        } else if keep {
            self.create_dialog = Some(desc);
        }
    }
}
