// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Drawing code for the "Firewall & network" page: firewall status, the
//! connections table with allow / block buttons, rules added from the app, and the
//! firewall log. Data comes from `firewall.rs`.

use crate::checks::Level;
use crate::firewall::{self, Conn, ConnState, Rule, RuleKind};
use crate::ui::{self, Icon};
use crate::{AfterAdmin, App, PendingFw};
use egui::{Color32, RichText};
use egui_extras::{Column, TableBuilder};
use std::time::Duration;

/// Which rows the connections table shows.
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum ConnFilter {
    /// Connections to other computers (the default).
    #[default]
    Active,
    /// Ports this computer accepts connections on.
    Listening,
    /// Both.
    All,
}

/// Height of a table row.
const ROW_H: f32 = 26.0;

/// UFW default policy in words (DROP -> "Blocked").
fn policy_text(p: &str) -> &'static str {
    match p {
        "DROP" | "REJECT" => "Blocked",
        "ACCEPT" => "Allowed",
        _ => "Unknown",
    }
}

/// Current Unix time in seconds.
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

impl App {
    /// Draw the Firewall & network page.
    pub fn page_firewall(&mut self, ui: &mut egui::Ui) {
        // Layout: title and firewall status (with "Turn on"), the rule buttons ("Add a rule…",
        // "Rules you added", "Show all firewall rules"), the "Connections" table (programs using
        // the network, with Allow/Block), then the "Firewall log". This page fills the window
        // height itself: the table scrolls, the rest stays in place.
        let ctx = ui.ctx().clone();
        if self.fw_status.stale(Duration::from_secs(10)) {
            self.fw_status.refresh(&ctx, firewall::status);
        }
        if self.fw_conns.last.is_none()
            || (self.fw_live && self.fw_conns.stale(Duration::from_secs(3)))
        {
            self.fw_conns.refresh(&ctx, firewall::connections);
        }
        if self.fw_log.stale(Duration::from_secs(15)) && self.fw_log_override.is_none() {
            self.fw_log.refresh(&ctx, firewall::read_log);
        }
        ctx.request_repaint_after(Duration::from_secs(3));

        ui::page_header(
            ui,
            Icon::Firewall,
            "Firewall & network protection",
            "See which programs use the network, and allow or block connections.",
        );

        let status = self.fw_status.get().unwrap_or_default();
        let rules = crate::settings::load().fw_rules;

        // ---- status
        ui::card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                if status.on() {
                    ui::status_line(
                        ui,
                        Some(Level::Ok),
                        if status.blocks_incoming_by_default() {
                            "Firewall is on. Other computers can't connect to yours unless you allow it."
                        } else {
                            "Firewall is on."
                        },
                    );
                } else {
                    ui::status_line(ui, Some(Level::Warn), "Firewall is off. Your device may be exposed.");
                }
            });
            if status.enabled {
                ui::small(
                    ui,
                    format!(
                        "Incoming: {}   ·   Outgoing: {}   ·   Logging: {}",
                        policy_text(&status.incoming),
                        policy_text(&status.outgoing),
                        status.logging
                    ),
                );
            } else if status.firewalld {
                ui::small(
                    ui,
                    "This computer uses firewalld. Allow and Block below need UFW.",
                );
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if !status.on() && ui::primary_button(ui, "Turn on").clicked() {
                    self.run_admin(&ctx, "Turning on the firewall", &["enable-firewall"], AfterAdmin::RefreshAll, true);
                }
                let can_add = status.ufw_installed
                    && !status.firewalld
                    && crate::policy::get().allow_firewall_changes;
                if ui::add_enabled_button(ui, can_add, "Add a rule…")
                    .on_hover_text("Allow or block a port, or block an address")
                    .on_disabled_hover_text(if !crate::policy::get().allow_firewall_changes {
                        format!("{}: firewall changes are turned off.", crate::policy::get().managed_text())
                    } else {
                        "Adding rules needs the UFW firewall.".to_string()
                    })
                    .clicked()
                {
                    self.fw_add = Some(AddRuleForm::default());
                }
                if ui::button(ui, &format!("Rules you added ({})", rules.len())).clicked() {
                    self.fw_rules_dialog = true;
                }
                if status.ufw_installed
                    && ui::link(ui, "Show all firewall rules")
                        .on_hover_text("Shows every UFW rule. Needs your password because the rule list is only readable by administrators.")
                        .clicked()
                {
                    self.run_admin(&ctx, "Firewall rules", &["fw-rules"], AfterAdmin::RefreshAll, true);
                }
            });
        });
        ui.add_space(10.0);

        let can_change = status.ufw_installed
            && !status.firewalld
            && crate::policy::get().allow_firewall_changes;
        let total_h = ui.available_height();
        let conn_h = (total_h * 0.56).max(160.0);

        // ---- connections
        let conns = self.fw_conns.get().unwrap_or_default();
        let shown: Vec<&Conn> = conns
            .iter()
            .filter(|c| self.fw_show_local || !c.is_local_only())
            .filter(|c| match self.fw_filter {
                ConnFilter::Active => {
                    matches!(c.state, ConnState::Connected | ConnState::Connecting)
                }
                ConnFilter::Listening => c.state == ConnState::Listening,
                ConnFilter::All => true,
            })
            .collect();
        ui.horizontal(|ui| {
            ui.label(RichText::new("Connections").size(19.0).strong());
            ui.add_space(12.0);
            ui.selectable_value(&mut self.fw_filter, ConnFilter::Active, "Active");
            ui.selectable_value(&mut self.fw_filter, ConnFilter::Listening, "Open ports");
            ui.selectable_value(&mut self.fw_filter, ConnFilter::All, "All");
            ui.add_space(12.0);
            ui.checkbox(
                &mut self.fw_show_local,
                "Show connections inside this computer",
            );
            ui.checkbox(&mut self.fw_live, "Live");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui::small(ui, format!("{} shown", shown.len()));
            });
        });
        ui.add_space(4.0);

        let mut act: Option<(String, String, String, Vec<String>, PendingFw)> = None;
        let weak = ui::weak(ui);
        let red = ui::RED;
        let green = if ui.visuals().dark_mode {
            Color32::from_rgb(108, 203, 95)
        } else {
            ui::GREEN
        };
        let amber_text = if ui.visuals().dark_mode {
            ui::AMBER
        } else {
            Color32::from_rgb(157, 93, 0)
        };
        let blocks_default = status.blocks_incoming_by_default();
        table_frame(ui, conn_h, |ui| {
            TableBuilder::new(ui)
                .id_salt("fw_conns")
                .striped(true)
                                .vscroll(true)
                .auto_shrink([false, false])
                .min_scrolled_height(0.0)
                .max_scroll_height(conn_h - 56.0)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .columns_fit(&[0.19, 0.10, 0.15, 0.18, 0.20, 0.18])
                .header(24.0, |mut h| {
                    for t in ["Name / program", "Status", "IP address", "MAC address", "Protocol", "Firewall"] {
                        h.col(|ui| {
                            ui.label(RichText::new(t).strong());
                        });
                    }
                })
                .body(|body| {
                    body.rows(ROW_H, shown.len(), |mut row| {
                        let c = shown[row.index()];
                        let rule = firewall::rule_for(&rules, c);
                        row.col(|ui| {
                            let name = if c.count > 1 { format!("{}  ×{}", c.program, c.count) } else { c.program.clone() };
                            ui.label(name).on_hover_text(&c.detail);
                        });
                        row.col(|ui| {
                            let color = match c.state {
                                ConnState::Connected => green,
                                ConnState::Listening => ui.visuals().text_color(),
                                _ => weak,
                            };
                            ui.label(RichText::new(c.state.text()).color(color));
                        });
                        row.col(|ui| {
                            ui.label(c.address_text()).on_hover_text(match c.state {
                                ConnState::Listening => format!("Waiting for connections on {}:{}", c.local_ip, c.local_port),
                                _ => format!("{}:{}  →  {}:{}", c.local_ip, c.local_port, c.remote_ip, c.remote_port),
                            });
                        });
                        row.col(|ui| match &c.mac {
                            Some(m) if c.mac_is_router => {
                                ui.label(RichText::new(format!("{m} (router)")).color(weak))
                                    .on_hover_text("This address is on the internet. Traffic to it goes through your router, whose MAC address is shown.");
                            }
                            Some(m) => {
                                ui.label(m);
                            }
                            None => {
                                ui.label(RichText::new("—").color(weak));
                            }
                        });
                        row.col(|ui| {
                            ui.label(format!("{} · {}", c.proto.name(), firewall::port_text(c.service_port())));
                        });
                        row.col(|ui| {
                            if c.is_local_only() || c.state == ConnState::Closing {
                                ui.label(RichText::new("—").color(weak));
                                return;
                            }
                            match (c.state, rule.map(|r| &r.kind)) {
                                (_, Some(RuleKind::BlockAddress { .. })) | (_, Some(RuleKind::BlockPort { .. })) => {
                                    ui.label(RichText::new("Blocked").color(red));
                                }
                                (_, Some(RuleKind::AllowPort { .. })) => {
                                    ui.label(RichText::new("Allowed").color(green));
                                }
                                (ConnState::Listening, None) => {
                                    if blocks_default {
                                        ui.label(RichText::new("Blocked").color(weak))
                                            .on_hover_text("Other computers can't reach this port (the firewall blocks incoming connections by default), unless a rule outside this app allows it.");
                                    } else {
                                        ui.label(RichText::new("Open").color(amber_text))
                                            .on_hover_text("Other computers on your network may be able to connect to this port.");
                                    }
                                }
                                _ => {}
                            }
                            if !can_change {
                                return;
                            }
                            let note = c.program.clone();
                            match (c.state, rule) {
                                (_, Some(r)) => {
                                    if ui.small_button("Undo").on_hover_text(format!("Remove your rule: {}", r.describe())).clicked() {
                                        act = Some((
                                            "Remove firewall rule?".into(),
                                            format!("\"{}\" will be removed. The firewall's normal setting applies again.", r.describe()),
                                            "Remove".into(),
                                            r.remove_args(),
                                            PendingFw::Remove(r.clone()),
                                        ));
                                    }
                                }
                                (ConnState::Listening, None) => {
                                    let port = c.local_port;
                                    let proto = c.proto;
                                    let kind = if blocks_default {
                                        RuleKind::AllowPort { port, proto }
                                    } else {
                                        RuleKind::BlockPort { port, proto }
                                    };
                                    let label = if blocks_default { "Allow" } else { "Block" };
                                    let r = Rule { kind, note, added: now() };
                                    if ui.small_button(label).clicked() {
                                        let text = if blocks_default {
                                            format!(
                                                "Other computers will be able to connect to {} on port {} ({}). Only allow this if you trust the program.",
                                                c.program, port, proto.name()
                                            )
                                        } else {
                                            format!("Other computers will no longer be able to connect to {} on port {} ({}).", c.program, port, proto.name())
                                        };
                                        act = Some((format!("{label} incoming connections?"), text, label.into(), r.add_args(), PendingFw::Add(r)));
                                    }
                                }
                                (_, None) => {
                                    let ip = c.remote_ip.to_string();
                                    let r = Rule { kind: RuleKind::BlockAddress { ip: ip.clone() }, note, added: now() };
                                    if ui.small_button("Block").clicked() {
                                        act = Some((
                                            "Block this address?".into(),
                                            format!(
                                                "All traffic to and from {ip} will be blocked for every program on this computer (it is used by {} right now). You can undo this from \"Rules you added\".",
                                                c.program
                                            ),
                                            "Block".into(),
                                            r.add_args(),
                                            PendingFw::Add(r),
                                        ));
                                    }
                                }
                            }
                        });
                    });
                });
        });
        if let Some((title, text, button, args, pending)) = act {
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            self.ask_confirm_fw(&title, &text, &button, &title.replace('?', ""), &a, pending);
        }

        // ---- firewall log
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Firewall log").size(19.0).strong());
            ui.add_space(8.0);
            if ui::icon_button(ui, Icon::Refresh, "Refresh").clicked() {
                if self.fw_log_override.is_some() {
                    self.run_admin(
                        &ctx,
                        "Reading the firewall log",
                        &["fw-log"],
                        AfterAdmin::FirewallLog,
                        false,
                    );
                } else {
                    self.fw_log.refresh(&ctx, firewall::read_log);
                }
            }
            if status.enabled && status.logging == "off" {
                ui::small(ui, "Logging is off, so nothing new is recorded.");
            }
        });
        ui.add_space(4.0);
        let log = self.fw_log.get().unwrap_or_default();
        let entries = self.fw_log_override.clone().unwrap_or(log.entries);
        let log_h = (ui.available_height() - 4.0).max(120.0);
        if log.needs_admin && self.fw_log_override.is_none() {
            ui::card(ui, |ui| {
                ui.label("Your account can't read the system log, so the firewall log needs your password.");
                ui::small(
                    ui,
                    "Tip: accounts in the \"adm\" group can see this log without a password.",
                );
                ui.add_space(6.0);
                if ui::primary_button(ui, "Show firewall log").clicked() {
                    self.run_admin(
                        &ctx,
                        "Reading the firewall log",
                        &["fw-log"],
                        AfterAdmin::FirewallLog,
                        false,
                    );
                }
            });
            return;
        }
        table_frame(ui, log_h, |ui| {
            TableBuilder::new(ui)
                .id_salt("fw_log")
                .striped(true)
                .vscroll(true)
                .auto_shrink([false, false])
                .min_scrolled_height(0.0)
                .max_scroll_height(log_h - 56.0)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .columns_fit(&[0.18, 0.10, 0.09, 0.14, 0.15, 0.17, 0.08, 0.09])
                .header(24.0, |mut h| {
                    for t in [
                        "Time",
                        "Action",
                        "Direction",
                        "Address",
                        "MAC address",
                        "Port",
                        "Protocol",
                        "Network",
                    ] {
                        h.col(|ui| {
                            ui.label(RichText::new(t).strong());
                        });
                    }
                })
                .body(|body| {
                    if entries.is_empty() {
                        body.rows(ROW_H, 1, |mut row| {
                            row.col(|ui| {
                                ui.label(RichText::new("No events yet").color(weak));
                            });
                        });
                        return;
                    }
                    body.rows(ROW_H, entries.len(), |mut row| {
                        let e = &entries[row.index()];
                        row.col(|ui| {
                            ui.label(&e.time);
                        });
                        row.col(|ui| {
                            let c = if e.action.starts_with("Allowed") {
                                green
                            } else {
                                red
                            };
                            ui.label(RichText::new(&e.action).color(c));
                        });
                        row.col(|ui| {
                            ui.label(e.direction);
                        });
                        row.col(|ui| {
                            ui.label(&e.address);
                        });
                        row.col(|ui| {
                            ui.label(if e.mac.is_empty() { "—" } else { &e.mac });
                        });
                        row.col(|ui| {
                            ui.label(
                                e.port
                                    .map(firewall::port_text)
                                    .unwrap_or_else(|| "—".into()),
                            );
                        });
                        row.col(|ui| {
                            ui.label(&e.proto);
                        });
                        row.col(|ui| {
                            ui.label(&e.interface);
                        });
                    });
                });
        });
    }

    /// Window listing the rules added from this app, each with a Remove button.
    pub fn fw_rules_window(&mut self, ctx: &egui::Context) {
        // Lists the rules Proton Security added (kept in settings), each with "Remove".
        if !self.fw_rules_dialog {
            return;
        }
        let rules = crate::settings::load().fw_rules;
        let mut close = false;
        let mut remove: Option<Rule> = None;
        egui::Modal::new(egui::Id::unique("fw_rules"))
            .frame(egui::Frame::popup(&ctx.global_style()).inner_margin(20).corner_radius(10))
            .show(ctx, |ui| {
                ui.set_width(560.0);
                ui.label(RichText::new("Rules you added").size(18.0).strong());
                ui::small(ui, "Firewall rules created from this page. Removing one asks for your password.");
                ui.add_space(8.0);
                if rules.is_empty() {
                    ui.label("You haven't added any rules yet. Use \"Add a rule…\", or Allow / Block in the Connections list.");
                }
                egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                    for r in &rules {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(r.describe());
                                let when = chrono::DateTime::from_timestamp(r.added, 0)
                                    .map(|d| d.with_timezone(&chrono::Local).format("%b %-d, %Y").to_string())
                                    .unwrap_or_default();
                                ui::small(ui, format!("Added {when} for {}", r.note));
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui::button(ui, "Remove").clicked() {
                                    remove = Some(r.clone());
                                }
                            });
                        });
                        ui.separator();
                    }
                });
                ui.add_space(8.0);
                if ui::primary_button(ui, "Close").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    close = true;
                }
            });
        if let Some(r) = remove {
            let args = r.remove_args();
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            self.pending_fw = Some(PendingFw::Remove(r));
            self.run_admin(
                ctx,
                "Removing firewall rule",
                &a,
                AfterAdmin::RefreshAll,
                true,
            );
            close = true;
        }
        if close {
            self.fw_rules_dialog = false;
        }
    }
}

/// What the "Add a rule" form creates.
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum AddRuleKind {
    /// Block incoming connections to a port of this computer (the default: safest choice).
    #[default]
    BlockPort,
    /// Allow incoming connections to a port of this computer.
    AllowPort,
    /// Block all traffic to and from one address.
    BlockAddress,
}

/// State of the "Add a rule" form.
#[derive(Clone, Debug)]
pub struct AddRuleForm {
    /// Rule type chosen.
    pub kind: AddRuleKind,
    /// Port number, as typed.
    pub port: String,
    /// Protocol for port rules.
    pub proto: firewall::Proto,
    /// Address, as typed (for "Block an address").
    pub ip: String,
    /// Optional name, shown in "Rules you added" ("Game server", "Printer"…).
    pub name: String,
}

impl Default for AddRuleForm {
    fn default() -> Self {
        Self {
            kind: AddRuleKind::default(),
            port: String::new(),
            proto: firewall::Proto::Tcp,
            ip: String::new(),
            name: String::new(),
        }
    }
}

impl AddRuleForm {
    /// The rule described by the form, or a sentence saying what to correct. Checks the same
    /// limits as the helper script (it checks them again as root).
    pub fn rule(&self) -> Result<Rule, String> {
        let note = if self.name.trim().is_empty() {
            "a rule you added".to_string()
        } else {
            self.name.trim().chars().take(60).collect()
        };
        let kind = match self.kind {
            AddRuleKind::BlockPort | AddRuleKind::AllowPort => {
                let port: u16 = self
                    .port
                    .trim()
                    .parse()
                    .ok()
                    .filter(|p| *p >= 1)
                    .ok_or("Type a port number from 1 to 65535.")?;
                if self.kind == AddRuleKind::AllowPort {
                    RuleKind::AllowPort {
                        port,
                        proto: self.proto,
                    }
                } else {
                    RuleKind::BlockPort {
                        port,
                        proto: self.proto,
                    }
                }
            }
            AddRuleKind::BlockAddress => {
                let t = self.ip.trim();
                let ip: std::net::IpAddr = t
                    .parse()
                    .map_err(|_| "Type an address like 203.0.113.5 or 2001:db8::1.".to_string())?;
                // The helper accepts IPv6 only as hex digits and colons (no ::ffff:1.2.3.4 form).
                if ip.is_ipv6() && t.contains('.') {
                    return Err(
                        "Type this IPv6 address without the IPv4 part, or use the IPv4 address."
                            .into(),
                    );
                }
                if ip.is_loopback() || ip.is_unspecified() {
                    return Err("This address is this computer itself; it can't be blocked.".into());
                }
                RuleKind::BlockAddress { ip: ip.to_string() }
            }
        };
        Ok(Rule {
            kind,
            note,
            added: now(),
        })
    }
}

impl App {
    /// The "Add a rule" window: choose allow / block port or block address, then confirm (the
    /// change goes through the helper and asks for the password).
    pub fn fw_add_rule_window(&mut self, ctx: &egui::Context) {
        // The "Add a firewall rule" form. `AddRuleForm::rule` checks what was typed (port 1–65535,
        // a real IP address) before the helper is asked to do anything.
        let Some(form) = &mut self.fw_add else { return };
        let (mut submit, mut cancel) = (false, false);
        egui::Modal::new(egui::Id::unique("fw_add_rule"))
            .frame(egui::Frame::popup(&ctx.global_style()).inner_margin(20).corner_radius(10))
            .show(ctx, |ui| {
                ui.set_width(480.0);
                ui.label(RichText::new("Add a firewall rule").size(18.0).strong());
                ui.add_space(8.0);
                ui.radio_value(&mut form.kind, AddRuleKind::BlockPort, "Block incoming connections to a port");
                ui.radio_value(&mut form.kind, AddRuleKind::AllowPort, "Allow incoming connections to a port");
                ui.radio_value(&mut form.kind, AddRuleKind::BlockAddress, "Block an address (all traffic, both directions)");
                ui.add_space(8.0);
                match form.kind {
                    AddRuleKind::BlockPort | AddRuleKind::AllowPort => {
                        ui.horizontal(|ui| {
                            ui.label("Port:");
                            ui::text_field(ui, &mut form.port, 80.0, "8080");
                            ui.add_space(12.0);
                            ui.radio_value(&mut form.proto, firewall::Proto::Tcp, "TCP");
                            ui.radio_value(&mut form.proto, firewall::Proto::Udp, "UDP");
                        });
                        if let Ok(p) = form.port.trim().parse::<u16>()
                            && let Some(s) = firewall::service_name(p)
                        {
                            ui::small(ui, format!("Port {p} is usually {s}."));
                        }
                        ui.add_space(4.0);
                        ui::small(ui, if form.kind == AddRuleKind::AllowPort {
                            "Other computers will be able to connect to this port. Only allow ports for programs you trust."
                        } else {
                            "Other computers will not be able to connect to this port, even if a program listens on it."
                        });
                    }
                    AddRuleKind::BlockAddress => {
                        ui.horizontal(|ui| {
                            ui.label("Address:");
                            ui::text_field(ui, &mut form.ip, 260.0, "203.0.113.5");
                        });
                        ui.add_space(4.0);
                        ui::small(ui, "Nothing on this computer will be able to talk to this address, and it can't reach this computer.");
                    }
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label("Name (optional):");
                    ui::text_field(ui, &mut form.name, 240.0, "Game server");
                });
                let check = form.rule();
                if let Err(e) = &check
                    && !(form.port.is_empty() && form.ip.is_empty())
                {
                    ui.add_space(4.0);
                    ui.label(RichText::new(e).color(ui::RED).size(13.0));
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui::add_enabled_button(ui, check.is_ok(), "Add rule").clicked() {
                        submit = true;
                    }
                    if ui::button(ui, "Cancel").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                        cancel = true;
                    }
                });
                ui::small(ui, "You will be asked for your administrator password.");
            });
        if cancel {
            self.fw_add = None;
        } else if submit && let Some(Ok(r)) = self.fw_add.as_ref().map(|f| f.rule()) {
            self.fw_add = None;
            let args = r.add_args();
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            let title = match r.kind {
                RuleKind::AllowPort { .. } => "Adding an allow rule",
                _ => "Adding a block rule",
            };
            self.pending_fw = Some(PendingFw::Add(r.clone()));
            self.run_admin(ctx, title, &a, AfterAdmin::RefreshAll, true);
        }
    }
}

/// Give each column a share of the table width so the table always fits.
trait FitColumns {
    /// Add one column per share (fractions of the width); the last one takes the rest.
    fn columns_fit(self, shares: &[f32]) -> Self;
}

impl FitColumns for TableBuilder<'_> {
    /// See [`FitColumns::columns_fit`].
    fn columns_fit(mut self, shares: &[f32]) -> Self {
        let spacing = self_spacing();
        let avail = TABLE_WIDTH.with(|w| w.get()) - spacing * (shares.len() as f32 - 1.0);
        for (i, f) in shares.iter().enumerate() {
            self = if i + 1 == shares.len() {
                self.column(Column::remainder().clip(true))
            } else {
                self.column(Column::exact((avail * f).floor().max(40.0)).clip(true))
            };
        }
        self
    }
}

/// Space between table columns.
fn self_spacing() -> f32 {
    8.0
}

thread_local! {
    /// Width of the table being drawn, set by [`table_frame`].
    static TABLE_WIDTH: std::cell::Cell<f32> = const { std::cell::Cell::new(800.0) };
}

/// Card around a table, `height` points high; records the width for [`FitColumns`].
fn table_frame(ui: &mut egui::Ui, height: f32, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(ui::card_fill(ui))
        .stroke(egui::Stroke::new(
            1.0,
            ui.visuals()
                .widgets
                .noninteractive
                .bg_stroke
                .color
                .linear_multiply(0.6),
        ))
        .corner_radius(8)
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_height(height - 14.0);
            ui.set_width(ui.available_width());
            TABLE_WIDTH.with(|w| w.set(ui.available_width()));
            add(ui)
        });
}

#[cfg(test)]
mod add_rule_tests {
    use super::*;

    fn form(kind: AddRuleKind, port: &str, ip: &str) -> AddRuleForm {
        AddRuleForm {
            kind,
            port: port.into(),
            ip: ip.into(),
            ..Default::default()
        }
    }

    #[test]
    fn port_rules() {
        let r = form(AddRuleKind::AllowPort, " 8080 ", "").rule().unwrap();
        assert_eq!(r.add_args(), vec!["fw-allow-port", "8080", "tcp"]);
        assert_eq!(
            form(AddRuleKind::BlockPort, "22", "")
                .rule()
                .unwrap()
                .add_args()[0],
            "fw-block-port"
        );
        for bad in ["", "0", "65536", "-1", "22/tcp", "abc"] {
            assert!(
                form(AddRuleKind::BlockPort, bad, "").rule().is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn address_rules() {
        assert_eq!(
            form(AddRuleKind::BlockAddress, "", "203.0.113.5")
                .rule()
                .unwrap()
                .add_args(),
            vec!["fw-block-ip", "203.0.113.5"]
        );
        assert!(
            form(AddRuleKind::BlockAddress, "", "2001:db8::1")
                .rule()
                .is_ok()
        );
        for bad in [
            "",
            "example.com",
            "10.0.0.0/8",
            "127.0.0.1",
            "::ffff:1.2.3.4",
            "-x",
        ] {
            assert!(
                form(AddRuleKind::BlockAddress, "", bad).rule().is_err(),
                "{bad}"
            );
        }
    }
}
