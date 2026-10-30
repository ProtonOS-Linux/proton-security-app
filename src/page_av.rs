// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Drawing code for the "Virus & threat protection" page: current threats, scan
//! options and progress, automatic protection switches, definitions, protection
//! history and quarantine. Scanning itself is in `antivirus.rs`.

use crate::antivirus::{self, Phase, ScanKind};
use crate::checks::{DEFS_STALE_DAYS, Level};
use crate::sys;
use crate::ui::{self, Icon};
use crate::{AfterAdmin, App};
use egui::RichText;
use std::path::PathBuf;

impl App {
    /// Draw the Virus & threat protection page.
    pub fn page_antivirus(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if self.clam.stale(std::time::Duration::from_secs(60)) {
            self.refresh_clam(&ctx);
        }
        ui::page_header(
            ui,
            Icon::Virus,
            "Virus & threat protection",
            "Protection for your device against viruses and malware, powered by ClamAV.",
        );

        let info = self.clam.get();
        let Some(info) = info else {
            ui.add(egui::Spinner::new());
            return;
        };
        if !info.installed {
            ui::card(ui, |ui| {
                ui::status_line(ui, Some(Level::Warn), "ClamAV antivirus is not installed.");
                ui::small(
                    ui,
                    "Install it to scan files for viruses and receive daily virus definition updates.",
                );
                ui.add_space(6.0);
                if ui::primary_button(ui, "Install ClamAV").clicked() {
                    self.run_admin(
                        &ctx,
                        "Installing ClamAV antivirus",
                        &["install-clamav"],
                        AfterAdmin::RefreshAll,
                        true,
                    );
                }
            });
            return;
        }

        // Folder picker result (from a background kdialog)
        if let Some(p) = self.folder_pick.lock().unwrap().take() {
            self.custom_path = p.to_string_lossy().into_owned();
            self.scan_kind = ScanKind::Custom;
        }

        // Quick scan requested from the dashboard
        if self.start_quick_scan {
            self.start_quick_scan = false;
            if self.scan.is_none() {
                self.begin_scan(&ctx);
            }
        }

        // ------------------------------------------------ current threats / scan progress
        ui::section_title(ui, "Current threats");
        self.scan_status(ui);

        // ------------------------------------------------ scan options
        ui::section_title(ui, "Scan options");
        let scanning = self.scan.is_some();
        ui::card(ui, |ui| {
            ui.add_enabled_ui(!scanning, |ui| {
                let quick_desc = format!(
                    "Checks the places where threats are most often found: {}.",
                    antivirus::quick_targets()
                        .iter()
                        .map(|p| short_path(p))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                scan_option(ui, &mut self.scan_kind, ScanKind::Quick, &quick_desc);
                scan_option(
                    ui,
                    &mut self.scan_kind,
                    ScanKind::Full,
                    "Checks all files on your computer. This can take over an hour. Files you don't have permission to read are skipped.",
                );
                scan_option(ui, &mut self.scan_kind, ScanKind::Custom, "Choose which folder to check.");
                if self.scan_kind == ScanKind::Custom {
                    ui.horizontal(|ui| {
                        ui.add_space(28.0);
                        ui.add(egui::TextEdit::singleline(&mut self.custom_path).hint_text("/home/you/Downloads").desired_width(380.0));
                        if ui::button(ui, "Browse…").clicked() {
                            let slot = self.folder_pick.clone();
                            let ctx2 = ctx.clone();
                            std::thread::spawn(move || {
                                if let Some(p) = sys::pick_folder() {
                                    *slot.lock().unwrap() = Some(p);
                                    ctx2.request_repaint();
                                }
                            });
                        }
                    });
                }
                ui.add_space(8.0);
                if ui::primary_button(ui, "Scan now").clicked() {
                    self.begin_scan(&ctx);
                }
            });
        });

        // ------------------------------------------------ scheduled scan
        ui::section_title(ui, "Automatic scan");
        ui::card(ui, |ui| {
            let pol = crate::policy::get();
            let forced_daily = pol.daily_scan != crate::policy::Forced::No;
            let mut daily = crate::policy::effective(self.daily_scan, pol.daily_scan);
            if ui
                .add_enabled(!forced_daily, egui::Checkbox::new(&mut daily, "Run a quick scan automatically every day"))
                .on_hover_text("The Proton Security tray icon starts a low-priority quick scan once a day, at least 10 minutes after you sign in. You are notified only if a threat is found.")
                .changed()
            {
                self.daily_scan = daily;
                crate::settings::update(|s| s.daily_scan = daily);
            }
            let st = crate::settings::load();
            let forced_dl = pol.scan_downloads != crate::policy::Forced::No;
            let mut dl = crate::policy::effective(st.scan_downloads, pol.scan_downloads);
            if ui
                .add_enabled(!forced_dl, egui::Checkbox::new(&mut dl, "Scan new files in my Downloads folder"))
                .on_hover_text("The tray icon checks each new download with ClamAV as soon as it has finished downloading, and warns you if it is dangerous.")
                .changed()
            {
                crate::settings::update(|s| s.scan_downloads = dl);
            }
            let forced_usb = pol.scan_usb != crate::policy::Forced::No;
            let mut usb = crate::policy::effective(st.scan_usb, pol.scan_usb);
            if ui
                .add_enabled(!forced_usb, egui::Checkbox::new(&mut usb, "Scan USB drives and memory cards when I open them"))
                .on_hover_text("When you open a USB drive, the tray icon quickly checks its programs, documents and archives (photos and videos are skipped) and tells you the result.")
                .changed()
            {
                crate::settings::update(|s| s.scan_usb = usb);
            }
            // The tray icon does all of the above; say if it isn't running.
            let running = tray_running_cached();
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
                ui::paint_badge(
                    ui.painter(),
                    r.center(),
                    7.0,
                    Some(if running { crate::checks::Level::Ok } else { crate::checks::Level::Warn }),
                    ui.visuals().window_fill,
                );
                ui.label(if running {
                    "Background protection is running."
                } else {
                    "Background protection is not running, so downloads and USB drives are not checked."
                });
                if !running && ui::primary_button(ui, "Start it").clicked() {
                    if crate::tray::start_tray() {
                        self.toast("Background protection started.");
                    } else {
                        self.toast("Could not start background protection.");
                    }
                    TRAY_CACHE.with(|c| c.set(None));
                }
            });
            if forced_daily || forced_dl || forced_usb {
                ui::small(
                    ui,
                    format!(
                        "{}: some of these settings can't be changed.",
                        pol.managed_text()
                    ),
                );
            }
            let last = antivirus::last_scan_time();
            let next = if !daily {
                "Automatic scans are off.".to_string()
            } else {
                match last {
                    Some(t) if sys::age_days(t) < 1.0 => {
                        let due = t + std::time::Duration::from_secs(24 * 3600);
                        format!("Next automatic scan: after {}", sys::fmt_time(due))
                    }
                    _ => "Next automatic scan: soon (within the next few minutes while you are signed in).".into(),
                }
            };
            ui::small(ui, next);
        });

        // ------------------------------------------------ updates
        ui::section_title(ui, "Virus & threat protection updates");
        ui::card(ui, |ui| {
            let stale = info
                .db_date
                .map(|t| sys::age_days(t) > DEFS_STALE_DAYS)
                .unwrap_or(true);
            ui::status_line(
                ui,
                Some(if stale { Level::Warn } else { Level::Ok }),
                if stale {
                    "Virus definitions are out of date."
                } else {
                    "Virus definitions are up to date."
                },
            );
            ui.add_space(2.0);
            egui::Grid::new("defs")
                .num_columns(2)
                .spacing([24.0, 4.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Definitions version").color(ui::weak(ui)));
                    ui.label(info.db_version.clone().unwrap_or_else(|| "unknown".into()));
                    ui.end_row();
                    ui.label(RichText::new("Last update").color(ui::weak(ui)));
                    ui.label(match info.db_date {
                        Some(t) => format!("{} ({})", sys::fmt_time(t), sys::fmt_ago(t)),
                        None => "unknown".into(),
                    });
                    ui.end_row();
                    ui.label(RichText::new("ClamAV engine").color(ui::weak(ui)));
                    ui.label(
                        info.engine_version
                            .clone()
                            .unwrap_or_else(|| "unknown".into()),
                    );
                    ui.end_row();
                });
            ui.add_space(8.0);
            let mut auto = info.auto_update();
            if ui
                .checkbox(&mut auto, "Check for virus definition updates automatically every day")
                .on_hover_text("Runs the clamav-freshclam service, which checks for new definitions throughout the day.")
                .changed()
            {
                let state = if auto { "on" } else { "off" };
                let title = if auto { "Turning on automatic definition updates" } else { "Turning off automatic definition updates" };
                self.run_admin(&ctx, title, &["av-auto", state], AfterAdmin::RefreshAll, false);
            }
            ui.add_space(6.0);
            if ui::icon_button(ui, Icon::Refresh, "Check for updates").clicked() {
                self.run_admin(
                    &ctx,
                    "Updating virus definitions",
                    &["av-update"],
                    AfterAdmin::RefreshAll,
                    true,
                );
            }
        });

        // ------------------------------------------------ history
        ui::section_title(ui, "Protection history (last 30 days)");
        self.history_card(ui);

        // ------------------------------------------------ quarantine
        if !self.quarantine.is_empty() {
            ui::section_title(ui, "Quarantined items");
            self.quarantine_card(ui);
        }
    }

    /// Start the scan chosen under Scan options.
    fn begin_scan(&mut self, ctx: &egui::Context) {
        let targets = match self.scan_kind {
            ScanKind::Quick | ScanKind::Scheduled => antivirus::quick_targets(),
            ScanKind::Full => vec![PathBuf::from("/")],
            ScanKind::Custom => {
                let p = PathBuf::from(self.custom_path.trim());
                if self.custom_path.trim().is_empty() || !p.exists() {
                    self.av_message = Some((
                        false,
                        "Choose a folder that exists for a custom scan.".into(),
                    ));
                    return;
                }
                vec![p]
            }
        };
        self.av_message = None;
        self.scan = Some(antivirus::start_scan(self.scan_kind, targets, Some(ctx)));
    }

    /// Current threats, or the progress of a running scan, with the Quick scan button.
    fn scan_status(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if let Some(job) = &self.scan {
            let p = job.snapshot();
            let kind = job.kind;
            if p.phase == Phase::Done {
                if let Some(r) = &p.result {
                    let msg = if r.cancelled {
                        (
                            false,
                            format!("{} was cancelled after {} files.", r.kind, r.files),
                        )
                    } else if r.threats.is_empty() {
                        (
                            true,
                            format!(
                                "{} finished. No threats found in {} files.",
                                r.kind, r.files
                            ),
                        )
                    } else {
                        // The threat list below says it all.
                        (false, String::new())
                    };
                    self.av_message = (!msg.1.is_empty()).then_some(msg);
                }
                self.scan = None;
                self.reload_av_files();
                crate::tray::poke_tray();
                self.refresh_checks(&ctx);
            } else {
                let mut cancel = false;
                ui::card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().size(20.0));
                        ui.label(
                            RichText::new(format!("{} in progress…", kind.label()))
                                .size(16.0)
                                .strong(),
                        );
                    });
                    ui.add_space(4.0);
                    let phase = match p.phase {
                        Phase::Counting => format!("Preparing… {} files found", p.estimate),
                        Phase::Loading => "Loading virus definitions…".into(),
                        _ => format!(
                            "{} of about {} files scanned",
                            p.scanned,
                            p.estimate.max(p.scanned)
                        ),
                    };
                    ui.label(phase);
                    let frac = if p.estimate > 0 {
                        (p.scanned as f32 / p.estimate as f32).min(0.99)
                    } else {
                        0.0
                    };
                    ui.scope(|ui| {
                        // Make the bar's track visible on white cards.
                        ui.visuals_mut().extreme_bg_color = if ui.visuals().dark_mode {
                            egui::Color32::from_gray(60)
                        } else {
                            egui::Color32::from_gray(225)
                        };
                        let fill = ui::accent(ui);
                        ui.add(
                            egui::ProgressBar::new(frac)
                                .show_percentage()
                                .fill(fill)
                                .desired_height(10.0)
                                .animate(p.phase != Phase::Scanning),
                        );
                    });
                    let elapsed = (chrono::Utc::now().timestamp() - p.started).max(0);
                    ui::small(
                        ui,
                        format!("Elapsed time: {}m {:02}s", elapsed / 60, elapsed % 60),
                    );
                    if !p.current.is_empty() {
                        ui::small(ui, ellipsize(&p.current, 110));
                    }
                    if !p.threats.is_empty() {
                        ui.add_space(4.0);
                        ui::status_line(
                            ui,
                            Some(Level::Warn),
                            &format!("{} threat(s) found so far", p.threats.len()),
                        );
                    }
                    ui.add_space(6.0);
                    if ui::button(ui, "Cancel scan").clicked() {
                        cancel = true;
                    }
                });
                if cancel && let Some(j) = &self.scan {
                    j.cancel();
                }
                ctx.request_repaint_after(std::time::Duration::from_millis(250));
                return;
            }
        }

        // Not scanning: show the result of the last scan + any open threats.
        let last = antivirus::last_completed_scan(&self.history).cloned();
        let open: Vec<(i64, antivirus::Threat)> = self
            .history
            .iter()
            .flat_map(|r| {
                r.threats
                    .iter()
                    .filter(|t| t.action.is_none())
                    .map(move |t| (r.started, t.clone()))
            })
            .collect();

        let mut act: Option<(i64, antivirus::Threat, &'static str)> = None;
        ui::card(ui, |ui| {
            if let Some((ok, msg)) = &self.av_message {
                ui::status_line(ui, Some(if *ok { Level::Ok } else { Level::Warn }), msg);
                ui.add_space(4.0);
            }
            if open.is_empty() {
                ui::status_line(ui, Some(Level::Ok), "No current threats.");
            } else {
                ui::status_line(
                    ui,
                    Some(Level::Warn),
                    &format!(
                        "{} threat(s) found. Choose what to do with each one.",
                        open.len()
                    ),
                );
            }
            match &last {
                Some(r) => ui::small(
                    ui,
                    format!(
                        "Last scan: {} ({}, {} files scanned in {})",
                        sys::fmt_time(r.finished_time()),
                        r.kind.to_lowercase(),
                        r.files,
                        r.duration_text()
                    ),
                ),
                None => ui::small(
                    ui,
                    "No scan has been run yet. Run a quick scan to check your files.",
                ),
            }
            for (started, t) in &open {
                ui.add_space(8.0);
                ui.separator();
                ui.label(RichText::new(&t.signature).strong().color(ui::RED));
                ui.label(RichText::new(&t.path).monospace().size(12.5));
                ui.horizontal(|ui| {
                    if ui::primary_button(ui, "Quarantine")
                        .on_hover_text(
                            "Move the file to a locked folder. You can restore it later.",
                        )
                        .clicked()
                    {
                        act = Some((*started, (*t).clone(), "Quarantined"));
                    }
                    if ui::button(ui, "Delete").clicked() {
                        act = Some((*started, (*t).clone(), "Deleted"));
                    }
                    if ui::button(ui, "Allow")
                        .on_hover_text("Keep the file. Only do this if you trust it.")
                        .clicked()
                    {
                        act = Some((*started, (*t).clone(), "Allowed"));
                    }
                });
            }
        });
        if let Some((started, threat, action)) = act {
            let path = threat.path.clone();
            let res = match action {
                "Quarantined" => antivirus::quarantine(&threat),
                "Deleted" => antivirus::delete_file(&threat),
                _ => Ok(()),
            };
            match res {
                Ok(()) => {
                    antivirus::set_threat_action(started, &path, action);
                    self.av_message = Some((
                        true,
                        format!("{action}: {}", short_path(std::path::Path::new(&path))),
                    ));
                }
                Err(e) if threat.fs_path().is_absolute() && !threat.fs_path().exists() => {
                    // File is already gone; nothing left to act on.
                    antivirus::set_threat_action(started, &path, "Removed");
                    self.av_message = Some((true, format!("The file is no longer present ({e}).")));
                }
                Err(e) => self.av_message = Some((false, e)),
            }
            self.reload_av_files();
            crate::tray::poke_tray();
            self.refresh_checks(&ctx);
        }
    }

    /// Protection history table (last 30 days).
    fn history_card(&mut self, ui: &mut egui::Ui) {
        ui::card(ui, |ui| {
            if self.history.is_empty() {
                ui::small(ui, "No scans yet.");
                return;
            }
            egui::Grid::new("history")
                .striped(true)
                .num_columns(5)
                .spacing([22.0, 6.0])
                .show(ui, |ui| {
                    for h in ["Date", "Scan", "Files", "Threats", "Result"] {
                        ui.label(RichText::new(h).strong());
                    }
                    ui.end_row();
                    for r in self.history.iter().rev() {
                        ui.label(sys::fmt_time(r.finished_time()));
                        ui.label(&r.kind);
                        ui.label(r.files.to_string());
                        ui.label(r.threats.len().to_string());
                        let res = if r.cancelled {
                            "Cancelled".to_string()
                        } else if r.threats.is_empty() {
                            "No threats".to_string()
                        } else {
                            let handled: Vec<String> =
                                r.threats.iter().filter_map(|t| t.action.clone()).collect();
                            if handled.len() == r.threats.len() {
                                format!("Resolved ({})", handled.join(", "))
                            } else {
                                "Action needed".to_string()
                            }
                        };
                        ui.label(res);
                        ui.end_row();
                    }
                });
        });
    }

    /// Quarantined files with Restore and Delete buttons.
    fn quarantine_card(&mut self, ui: &mut egui::Ui) {
        let mut act: Option<(String, bool)> = None;
        ui::card(ui, |ui| {
            ui::small(
                ui,
                "Quarantined files are locked and cannot run. Restore a file only if you are sure it is safe.",
            );
            for q in &self.quarantine {
                ui.add_space(6.0);
                ui.separator();
                ui.label(RichText::new(&q.signature).strong());
                ui.label(RichText::new(&q.original_path).monospace().size(12.5));
                ui.horizontal(|ui| {
                    if ui::button(ui, "Restore").clicked() {
                        act = Some((q.id.clone(), true));
                    }
                    if ui::button(ui, "Delete permanently").clicked() {
                        act = Some((q.id.clone(), false));
                    }
                });
            }
        });
        if let Some((id, restore)) = act {
            let r = if restore {
                antivirus::restore_quarantined(&id)
            } else {
                antivirus::delete_quarantined(&id)
            };
            self.av_message = Some(match r {
                Ok(()) => (
                    true,
                    if restore {
                        "File restored.".into()
                    } else {
                        "File deleted.".into()
                    },
                ),
                Err(e) => (false, e),
            });
            self.reload_av_files();
            crate::tray::poke_tray();
        }
    }
}

/// One radio button of Scan options, with its explanation below.
fn scan_option(ui: &mut egui::Ui, current: &mut ScanKind, kind: ScanKind, desc: &str) {
    ui.radio_value(current, kind, RichText::new(kind.label()).strong());
    ui.horizontal(|ui| {
        ui.add_space(28.0);
        ui.add(egui::Label::new(RichText::new(desc).size(13.0).color(ui::weak(ui))).wrap());
    });
    ui.add_space(4.0);
}

/// Show paths in the home folder as `~/…`.
fn short_path(p: &std::path::Path) -> String {
    let home = sys::home();
    match p.strip_prefix(&home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => p.display().to_string(),
    }
}

/// Keep the end of a long path (the file name), cutting the start.
fn ellipsize(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        s.to_string()
    } else {
        let tail: String = s.chars().skip(n - (max - 1)).collect();
        format!("…{tail}")
    }
}

thread_local! {
    /// Last answer of [`tray_running_cached`] and when it was checked.
    static TRAY_CACHE: std::cell::Cell<Option<(std::time::Instant, bool)>> = const { std::cell::Cell::new(None) };
}

/// Whether the tray runs, checked at most every 3 seconds.
fn tray_running_cached() -> bool {
    TRAY_CACHE.with(|c| match c.get() {
        Some((t, v)) if t.elapsed() < std::time::Duration::from_secs(3) => v,
        _ => {
            let v = crate::tray::tray_running();
            c.set(Some((std::time::Instant::now(), v)));
            v
        }
    })
}
