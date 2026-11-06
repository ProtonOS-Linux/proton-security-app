// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Drawing code for the "Device manager" page: the device tree, the properties
//! panel and the driver actions (update, reinstall, uninstall, enable). Hardware
//! data comes from `devices.rs`; driver changes go through the helper.

use crate::checks::Level;
use crate::devices::{self, Category, Device, Status};
use crate::sys;
use crate::ui::{self, Icon};
use crate::{AfterAdmin, App};
use egui::RichText;
use std::collections::BTreeMap;
use std::time::Duration;

/// Small symbol shown before each device group.
fn cat_glyph(c: Category) -> &'static str {
    match c {
        Category::Other => "❓",
        Category::Audio => "🔊",
        Category::Batteries => "🔋",
        Category::Bluetooth => "📶",
        Category::Cameras => "📷",
        Category::Disks => "🖴",
        Category::Optical => "💿",
        Category::Display => "🖵",
        Category::Hid => "🎮",
        Category::Imaging => "🖼",
        Category::Keyboards => "⌨",
        Category::Mice => "🖱",
        Category::Monitors => "🖥",
        Category::Network => "🖧",
        Category::Ports => "🔌",
        Category::Printers => "🖶",
        Category::Processors => "⚙",
        Category::Storage => "🗄",
        Category::System => "💻",
        Category::UsbControllers => "🔌",
        Category::UsbDevices => "🔌",
    }
}

impl App {
    /// Draw the Device manager page.
    pub fn page_devices(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if self.devices.last.is_none() {
            self.refresh_devices(&ctx);
        }
        // "Watch for new devices": every 3 s compare a cheap fingerprint of the hardware and run
        // the full scan (which starts helper commands) only when something was plugged in or
        // out, or a driver changed. Re-scanning every few seconds made the page flicker.
        if self.watch_devices {
            let interval = Duration::from_secs(3);
            let due = self
                .dev_fp
                .as_ref()
                .map(|(t, _)| t.elapsed() >= interval)
                .unwrap_or(true);
            if due {
                let fp = devices::hw_fingerprint();
                let changed = self
                    .dev_fp
                    .as_ref()
                    .map(|(_, old)| *old != fp)
                    .unwrap_or(false);
                self.dev_fp = Some((std::time::Instant::now(), fp));
                if changed {
                    self.refresh_devices(&ctx);
                }
            }
            ctx.request_repaint_after(interval);
        }

        ui::page_header(
            ui,
            Icon::Chip,
            "Device manager",
            "See the hardware in this computer and whether each device has a working driver.",
        );

        let Some(snap) = self.devices.value.lock().unwrap().clone() else {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new());
                ui.label("Looking for devices…");
            });
            return;
        };

        // ---- status banner + toolbar
        let problems = snap.problems();
        ui::card(ui, |ui| {
            if problems == 0 {
                ui::status_line(
                    ui,
                    Some(Level::Ok),
                    &format!("All {} devices have working drivers.", snap.devices.len()),
                );
            } else {
                ui::status_line(
                    ui,
                    Some(Level::Warn),
                    &format!(
                        "{problems} device(s) need attention. They are listed under \"Other devices\"."
                    ),
                );
                ui.add_space(4.0);
                if ui::primary_button(ui, "Find missing drivers and firmware")
                    .on_hover_text("Uses Debian's isenkram to install firmware packages that match your hardware.")
                    .clicked()
                {
                    self.run_admin(&ctx, "Looking for missing drivers and firmware", &["install-firmware"], AfterAdmin::RefreshAll, true);
                }
            }
            if !snap.firmware_messages.is_empty() {
                ui.add_space(4.0);
                egui::CollapsingHeader::new(format!(
                    "{} firmware message(s) from the kernel",
                    snap.firmware_messages.len()
                ))
                .id_salt("fw")
                .show(ui, |ui| {
                    for m in &snap.firmware_messages {
                        ui.label(RichText::new(m).monospace().size(12.0));
                    }
                });
            }
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui::icon_button(ui, Icon::Search, "Scan for hardware changes").clicked() {
                self.dev_manual_scan = true;
                self.refresh_devices(&ctx);
            }
            ui.checkbox(&mut self.watch_devices, "Watch for new devices");
            {
                let pol = crate::policy::get();
                let st = crate::settings::load();
                let mut alerts = crate::policy::effective(st.usb_alerts, pol.usb_alerts);
                if ui
                    .add_enabled(
                        pol.usb_alerts == crate::policy::Forced::No,
                        egui::Checkbox::new(&mut alerts, "Alert me about new USB devices"),
                    )
                    .on_hover_text("The tray icon notifies you when a new USB keyboard, network adapter or drive is plugged in. A USB stick that pretends to be a keyboard can type commands on your computer.")
                    .changed()
                {
                    crate::settings::update(|s| s.usb_alerts = alerts);
                }
            }
            ui.checkbox(
                &mut self.only_problems,
                "Show only devices that need attention",
            );
            // Keep the spinner's space reserved so the toolbar never shifts; only show it for a
            // scan the user asked for.
            if !self.devices.busy() {
                self.dev_manual_scan = false;
            }
            let (r, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
            if self.dev_manual_scan {
                egui::Spinner::new().size(14.0).paint_at(ui, r);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui::small(ui, format!("Kernel {}", devices::kernel()));
            });
        });
        ui.add_space(8.0);

        // Keep a valid selection
        if self
            .selected_device
            .as_ref()
            .map(|k| !snap.devices.iter().any(|d| &d.key == k))
            .unwrap_or(true)
        {
            self.selected_device = snap
                .devices
                .iter()
                .find(|d| d.status.is_problem())
                .map(|d| d.key.clone());
        }

        // ---- properties panel (right)
        let selected = self
            .selected_device
            .as_ref()
            .and_then(|k| snap.devices.iter().find(|d| &d.key == k))
            .cloned();
        let dark = ui.visuals().dark_mode;
        egui::Panel::right("device_props")
            .resizable(true)
            .default_size(360.0)
            .min_size(280.0)
            .show_separator_line(false)
            .frame(
                egui::Frame::new()
                    .fill(ui::page_fill(dark))
                    .inner_margin(egui::Margin {
                        left: 12,
                        right: 0,
                        top: 0,
                        bottom: 0,
                    }),
            )
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("props_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui::card(ui, |ui| match &selected {
                            None => ui::small(ui, "Select a device to see its properties."),
                            Some(d) => self.device_props(ui, d),
                        });
                    });
            });

        // ---- device tree (left)
        let mut groups: BTreeMap<Category, Vec<&Device>> = BTreeMap::new();
        for d in &snap.devices {
            if self.only_problems && !d.status.is_problem() {
                continue;
            }
            groups.entry(d.category).or_default().push(d);
        }
        egui::Frame::new()
            .fill(ui::card_fill(ui))
            .corner_radius(8)
            .inner_margin(10)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("tree_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        if groups.is_empty() {
                            ui::small(
                                ui,
                                if self.only_problems {
                                    "No devices need attention."
                                } else {
                                    "No devices found."
                                },
                            );
                        }
                        for (cat, devs) in &groups {
                            let has_problem = devs.iter().any(|d| d.status.is_problem());
                            let header = RichText::new(format!(
                                "{}  {}  ({})",
                                cat_glyph(*cat),
                                cat.name(),
                                devs.len()
                            ));
                            egui::CollapsingHeader::new(header)
                                .id_salt(cat.name())
                                .default_open(has_problem || self.only_problems)
                                .show(ui, |ui| {
                                    for d in devs {
                                        let sel = self.selected_device.as_deref() == Some(&d.key);
                                        let resp = ui
                                            .horizontal(|ui| {
                                                let (r, _) = ui.allocate_exact_size(
                                                    egui::vec2(16.0, 16.0),
                                                    egui::Sense::hover(),
                                                );
                                                if d.status.is_problem() {
                                                    ui::paint_badge(
                                                        ui.painter(),
                                                        r.center(),
                                                        7.0,
                                                        Some(Level::Warn),
                                                        ui::card_fill(ui),
                                                    );
                                                }
                                                ui.selectable_label(sel, &d.name)
                                            })
                                            .inner;
                                        if resp.clicked() {
                                            self.selected_device = Some(d.key.clone());
                                        }
                                    }
                                });
                        }
                    });
            });
    }

    /// Turn a finished dry run into the confirmation dialog.
    fn purge_plan_ready(&mut self) {
        let Some(slot) = &self.purge_plan else { return };
        let Some(plan) = slot.lock().unwrap().take() else {
            return;
        };
        self.purge_plan = None;
        let m = plan.module.clone();
        if let Some(why) = plan.blocked {
            self.toast(format!("Can't uninstall {m}: {why}"));
            return;
        }
        if plan.kernel {
            self.ask_confirm(
                "Uninstall driver?",
                &format!(
                    "\"{m}\" is part of the Linux kernel, so its files can't be removed without removing the kernel. \
                     Proton Security will remove it from use instead: the driver is unloaded and blocked from loading again, \
                     even after a restart. Devices that use it will stop working. \
                     You can undo this with Enable driver (the device will be listed under \"Other devices\")."
                ),
                "Uninstall",
                &format!("Uninstalling driver {m}"),
                &["driver-purge", &m],
            );
        } else {
            let pkg = plan.package.clone().unwrap_or_default();
            let list = if plan.remove.is_empty() {
                pkg.clone()
            } else {
                plan.remove.join(", ")
            };
            self.ask_confirm(
                "Uninstall driver?",
                &format!(
                    "The driver \"{m}\" will be removed from the system together with its settings.\n\n\
                     Packages that will be removed: {list}\n\n\
                     Devices that use this driver will stop working. Restart the computer afterwards. \
                     To get the driver back later, install {pkg} again."
                ),
                "Uninstall",
                &format!("Uninstalling driver {m}"),
                &["driver-purge", &m],
            );
        }
    }

    /// Properties panel of the selected device, with its driver details and actions.
    fn device_props(&mut self, ui: &mut egui::Ui, d: &Device) {
        // The Properties window of a device, like Windows: "General" (name, manufacturer, location,
        // state), "Driver" (driver in use or available, its file, version and package) with the
        // driver buttons (update, reinstall, uninstall/enable, load), then all other properties.
        self.purge_plan_ready();
        let ctx = ui.ctx().clone();
        ui.label(RichText::new(&d.name).size(17.0).strong());
        ui::small(ui, d.category.name());
        ui.add_space(6.0);
        ui::status_line(
            ui,
            Some(if d.status.is_problem() {
                Level::Warn
            } else {
                Level::Ok
            }),
            d.status.text(),
        );
        ui.add_space(6.0);

        ui.label(RichText::new("General").strong());
        egui::Grid::new("gen")
            .num_columns(2)
            .spacing([14.0, 4.0])
            .show(ui, |ui| {
                let mut row = |k: &str, v: &str| {
                    if !v.is_empty() {
                        ui.label(RichText::new(k).color(ui::weak(ui)));
                        ui.add(egui::Label::new(v).wrap());
                        ui.end_row();
                    }
                };
                row("Manufacturer", &d.vendor);
                row("Bus", d.bus);
                row("Hardware ID", &d.ids);
                for (k, v) in &d.props {
                    row(k, v);
                }
            });
        ui.add_space(8.0);
        // Details about the kernel module(s) behind this device (cached).
        let disabled = devices::disabled_modules();
        let infos: Vec<devices::DriverInfo> = d
            .modules
            .iter()
            .chain(d.candidate_modules.iter())
            .map(|m| {
                self.driver_info
                    .entry(m.clone())
                    .or_insert_with(|| devices::driver_info(m))
                    .clone()
            })
            .collect();
        let main = infos.first().cloned();

        ui.label(RichText::new("Driver").strong());
        egui::Grid::new("drv")
            .num_columns(2)
            .spacing([14.0, 4.0])
            .show(ui, |ui| {
                let mut row = |k: &str, v: String| {
                    ui.label(RichText::new(k).color(ui::weak(ui)));
                    ui.add(egui::Label::new(v).wrap());
                    ui.end_row();
                };
                row(
                    "Driver in use",
                    d.driver.clone().unwrap_or_else(|| "None".into()),
                );
                if !d.candidate_modules.is_empty() {
                    row("Available driver", d.candidate_modules.join(", "));
                }
                if let Some(i) = &main {
                    if i.builtin {
                        row("Driver file", "Built into the Linux kernel".into());
                    } else if let Some(f) = &i.file {
                        row("Driver file", f.clone());
                    }
                    if let Some(v) = &i.version {
                        row("Driver version", v.clone());
                    }
                    if let Some(p) = &i.package {
                        let v = i.package_version.clone().unwrap_or_default();
                        row("Provided by", format!("{p} {v}"));
                    }
                }
                if d.driver.is_none() && d.candidate_modules.iter().any(|m| disabled.contains(m)) {
                    row(
                        "State",
                        "Disabled (uninstalled with Proton Security)".into(),
                    );
                }
            });
        if let Some(m) = &d.modalias {
            ui.add_space(2.0);
            egui::CollapsingHeader::new("Device alias")
                .id_salt("alias")
                .show(ui, |ui| {
                    ui.add(egui::Label::new(RichText::new(m).monospace().size(11.5)).wrap());
                });
        }

        // ---- problem devices
        if d.status.is_problem() {
            ui.add_space(8.0);
            let disabled_mod = d
                .candidate_modules
                .iter()
                .find(|m| disabled.contains(m))
                .cloned();
            if let Some(m) = disabled_mod {
                if ui::primary_button(ui, &format!("Enable driver ({m})")).clicked() {
                    self.run_admin(
                        &ctx,
                        &format!("Enabling driver {m}"),
                        &["driver-enable", &m],
                        AfterAdmin::RefreshAll,
                        true,
                    );
                }
            } else if d.status == Status::DriverNotLoaded {
                if let Some(m) = d.candidate_modules.first()
                    && ui::primary_button(ui, &format!("Load driver ({m})")).clicked()
                {
                    let m = m.clone();
                    self.run_admin(
                        &ctx,
                        &format!("Loading driver {m}"),
                        &["load-module", &m],
                        AfterAdmin::RefreshAll,
                        true,
                    );
                }
            } else if ui::primary_button(ui, "Find missing drivers and firmware").clicked() {
                self.run_admin(
                    &ctx,
                    "Looking for missing drivers and firmware",
                    &["install-firmware"],
                    AfterAdmin::RefreshAll,
                    true,
                );
            }
            if let Some(q) = &d.hw_query {
                ui.add_space(4.0);
                if ui::link(ui, "Search online for a Linux driver").clicked() {
                    sys::open_url(&format!("https://linux-hardware.org/?id={q}"));
                }
            }
        }

        // ---- update / reinstall / uninstall (like Windows' driver tab)
        let driver_changes = crate::policy::get().allow_driver_changes;
        if !driver_changes && d.driver.is_some() && !d.modules.is_empty() {
            ui.add_space(8.0);
            ui::small(
                ui,
                format!(
                    "{}: driver changes are turned off.",
                    crate::policy::get().managed_text()
                ),
            );
        }
        if let Some(i) = main
            .clone()
            .filter(|i| driver_changes && d.driver.is_some() && !d.modules.is_empty() && !i.builtin)
        {
            let m = i.module.clone();
            ui.add_space(10.0);
            ui.label(RichText::new("Driver actions").strong());
            ui.horizontal_wrapped(|ui| {
                if ui::button(ui, "Update driver")
                    .on_hover_text("Checks for a newer version of the package that provides this driver (the kernel for built-in drivers) and its firmware, and installs it.")
                    .clicked()
                {
                    self.run_admin(&ctx, &format!("Updating driver {m}"), &["driver-update", &m], AfterAdmin::RefreshAll, true);
                }
                let allowed = devices::uninstall_allowed(d.category);
                let core_tip = "This is a core system device. Unloading its driver while the computer is running could make it unusable.";
                if allowed {
                    if ui::button(ui, "Reinstall driver")
                        .on_hover_text("Unloads the driver and loads it again. This resets the device.")
                        .clicked()
                    {
                        self.ask_confirm(
                            "Reinstall driver?",
                            &format!(
                                "The driver \"{m}\" will be unloaded and loaded again. \
                                 The device will stop working for a few seconds (for example, Wi-Fi or sound will reconnect)."
                            ),
                            "Reinstall",
                            &format!("Reinstalling driver {m}"),
                            &["driver-reinstall", &m],
                        );
                    }
                    let planning = self.purge_plan.is_some();
                    if ui
                        .add_enabled(!planning, egui::Button::new("Uninstall driver").corner_radius(4).min_size(egui::vec2(0.0, 30.0)))
                        .on_hover_text("Removes the driver from the system. You will see exactly what will be removed before anything happens.")
                        .clicked()
                    {
                        let slot = crate::sys::shared(None);
                        let (slot2, ctx2, m2, pkg) = (slot.clone(), ctx.clone(), m.clone(), i.package.clone());
                        std::thread::spawn(move || {
                            *slot2.lock().unwrap() = Some(devices::purge_plan(&m2, pkg.as_deref()));
                            ctx2.request_repaint();
                        });
                        self.purge_plan = Some(slot);
                    }
                    if planning {
                        ui.add(egui::Spinner::new().size(14.0));
                        ui::small(ui, "Checking what will be removed…");
                    }
                } else {
                    ui.add_enabled(false, egui::Button::new("Reinstall driver")).on_disabled_hover_text(core_tip);
                    ui.add_enabled(false, egui::Button::new("Uninstall driver")).on_disabled_hover_text(core_tip);
                }
            });
            if i.in_use_by > 0 {
                ui::small(
                    ui,
                    format!(
                        "This driver is in use by {} other module(s); a reload may need a restart.",
                        i.in_use_by
                    ),
                );
            }
        } else if let Some(i) = &main
            && i.builtin
        {
            ui.add_space(6.0);
            ui::small(
                ui,
                "This driver is part of the Linux kernel. It is updated together with the kernel through system updates.",
            );
        }
        ui.add_space(8.0);
        if ui::link(ui, "Copy details").clicked() {
            let mut s = format!(
                "{}\n{}\nStatus: {}\n",
                d.name,
                d.category.name(),
                d.status.text()
            );
            s += &format!(
                "Manufacturer: {}\nBus: {}\nHardware ID: {}\n",
                d.vendor, d.bus, d.ids
            );
            for (k, v) in &d.props {
                s += &format!("{k}: {v}\n");
            }
            s += &format!(
                "Driver: {}\n",
                d.driver.clone().unwrap_or_else(|| "None".into())
            );
            if let Some(m) = &d.modalias {
                s += &format!("Alias: {m}\n");
            }
            ui.ctx().copy_text(s);
            self.toast("Device details copied to the clipboard.");
        }
    }
}
