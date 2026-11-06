// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Drawing code for the "App permissions" page (Flatpak permissions table, data from
//! `appperms.rs`) and the File backup section of "Restore & backup" (data from
//! `backup.rs`).

use crate::appperms::{self, Perm};
use crate::page_account::status_row;
use crate::ui::{self, Icon};
use crate::{AfterAdmin, App};
use egui::{Color32, RichText};

impl App {
    /// Draw the App permissions page.
    pub fn page_apps(&mut self, ui: &mut egui::Ui) {
        // Layout: title, a line explaining permissions, then one card per Flatpak app with broad
        // access (all files, home folder, devices, network…), each permission a switch. A switch
        // writes a per-user override (`flatpak override --user`), never the system, and "Reset"
        // removes this app's overrides.
        let ctx = ui.ctx().clone();
        if self.apps.last.is_none() {
            self.apps.refresh(&ctx, appperms::load);
        }
        ui::page_header(
            ui,
            Icon::Apps,
            "App permissions",
            "See what your Flatpak apps can access, and take permissions away. Changes apply only to your account.",
        );
        if crate::sys::which("flatpak").is_none() {
            ui::card(ui, |ui| {
                status_row(
                    ui,
                    None,
                    "Flatpak is not installed",
                    "App permissions apply to apps installed from Flathub.",
                )
            });
            return;
        }
        let Some(apps) = self.apps.get() else {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new());
                ui.label("Reading app permissions…");
            });
            return;
        };
        let pol = crate::policy::get();
        let can_change = pol.allow_app_permission_changes;

        let risky = apps.iter().filter(|a| a.risky()).count();
        ui::card(ui, |ui| {
            if apps.is_empty() {
                status_row(ui, Some(true), "No Flatpak apps installed", "");
            } else if risky == 0 {
                status_row(
                    ui,
                    Some(true),
                    "No app has broad access",
                    &format!("{} app(s) checked.", apps.len()),
                );
            } else {
                status_row(
                    ui,
                    None,
                    &format!("{risky} app(s) can read your files or use your camera and devices"),
                    "That is often needed (a photo editor opens your pictures), but you can take access away from apps that don't need it.",
                );
            }
            if !can_change {
                ui::small(
                    ui,
                    format!("{}: changes are turned off.", pol.managed_text()),
                );
            }
            ui.horizontal(|ui| {
                if ui::icon_button(ui, Icon::Refresh, "Refresh").clicked() {
                    self.apps.refresh(&ctx, appperms::load);
                }
            });
        });
        ui.add_space(10.0);

        let green = if ui.visuals().dark_mode {
            Color32::from_rgb(108, 203, 95)
        } else {
            ui::GREEN
        };
        let amber = if ui.visuals().dark_mode {
            ui::AMBER
        } else {
            Color32::from_rgb(157, 93, 0)
        };
        let mut change: Option<(String, Option<(Perm, bool)>)> = None;
        for app in &apps {
            ui::card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new(&app.name).strong().size(15.5));
                        ui::small(ui, &app.id);
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if app.overridden
                            && ui
                                .add_enabled(can_change, egui::Button::new("Reset"))
                                .on_hover_text("Undo your changes for this app")
                                .clicked()
                        {
                            change = Some((app.id.clone(), None));
                        }
                        if app.overridden {
                            ui::small(ui, "Changed by you");
                        }
                    });
                });
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    for p in Perm::ALL {
                        let on = app.has(p);
                        let color = if !on {
                            ui::weak(ui)
                        } else if p.risky() {
                            amber
                        } else {
                            green
                        };
                        let mut checked = on;
                        let resp = ui.add_enabled(
                            can_change,
                            egui::Checkbox::new(
                                &mut checked,
                                RichText::new(p.label()).color(color),
                            ),
                        );
                        if resp.changed() {
                            change = Some((app.id.clone(), Some((p, checked))));
                        }
                        ui.add_space(10.0);
                    }
                });
            });
            ui.add_space(6.0);
        }
        if let Some((id, what)) = change {
            let r = match what {
                Some((p, on)) => appperms::set(&id, p, on),
                None => appperms::reset(&id),
            };
            match r {
                Ok(()) => self.toast("Saved. Restart the app for the change to take effect."),
                Err(e) => self.toast(format!("Could not change the permission: {e}")),
            }
            self.apps.refresh(&ctx, appperms::load);
        }
        let _ = AfterAdmin::RefreshAll;
    }

    /// "File backup" card at the top of the Restore & backup page.
    pub fn backup_card(&mut self, ui: &mut egui::Ui) {
        // The "File backup" card: backup tools found and their last backup, and buttons to set up Kup
        // or say "I back up another way".
        let ctx = ui.ctx().clone();
        if self.backup.stale(std::time::Duration::from_secs(30)) {
            self.backup.refresh(&ctx, crate::backup::load);
        }
        ui::section_title(ui, "File backup");
        let Some(b) = self.backup.get() else {
            ui.add(egui::Spinner::new());
            return;
        };
        ui::card(ui, |ui| {
            if !b.configured() {
                status_row(
                    ui,
                    Some(!crate::policy::get().require_backup),
                    "Your personal files are not backed up",
                    "Restore points protect the system, not your documents and photos. Back them up to a USB drive or network folder with Kup.",
                );
            } else if b.stale() {
                status_row(
                    ui,
                    Some(false),
                    "Your backup is out of date",
                    &format!(
                        "Last backup: {}.",
                        b.last().map(crate::sys::fmt_time).unwrap_or_default()
                    ),
                );
            } else {
                status_row(ui, Some(true), "Your personal files are backed up", "");
            }
            for t in &b.tools {
                ui::small(
                    ui,
                    match t.last {
                        Some(l) => format!(
                            "{} · {} · last backup {}",
                            t.name,
                            t.detail,
                            crate::sys::fmt_ago(l)
                        ),
                        None => format!("{} · {}", t.name, t.detail),
                    },
                );
            }
            if b.other_way && !b.has_backup_tool() {
                ui::small(ui, "You said you back up your files another way.");
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if b.kup_installed {
                    if ui::primary_button(ui, "Backup settings").clicked()
                        && !crate::backup::open_settings()
                    {
                        self.toast("Could not open the Kup settings.");
                    }
                } else if ui::primary_button(ui, "Set up backup")
                    .on_hover_text("Installs Kup, KDE's backup tool")
                    .clicked()
                {
                    self.run_admin(
                        &ctx,
                        "Installing Kup backup",
                        &["install-kup"],
                        AfterAdmin::RefreshAll,
                        true,
                    );
                }
                let mut other = b.other_way;
                if ui
                    .checkbox(&mut other, "I back up my files another way")
                    .changed()
                {
                    crate::settings::update(|s| s.backup_other_way = other);
                    self.backup.refresh(&ctx, crate::backup::load);
                    self.refresh_checks(&ctx);
                    crate::tray::poke_tray();
                }
            });
        });
    }
}
