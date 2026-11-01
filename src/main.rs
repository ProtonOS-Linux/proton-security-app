// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Proton Security — a Windows Security style center for Proton OS (Debian + KDE Plasma).

mod account;
mod admin;
mod antivirus;
mod appperms;
mod backup;
mod checks;
mod devices;
mod devsec;
mod firewall;
mod health;
mod page_account;
mod page_apps;
mod page_av;
mod page_devices;
mod page_firewall;
mod page_health;
mod page_home;
mod page_restore;
mod policy;
mod report;
mod restore;
mod risk;
mod settings;
mod startup;
mod sys;
mod tray;
mod ui;
mod watchers;

use admin::{AdminTask, TaskState};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use sys::{Shared, shared};
use ui::Icon;

/// Name shown in the window title, notifications and the tray.
pub const APP_NAME: &str = "Proton Security";

/// The pages in the side menu.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Home,
    Antivirus,
    Firewall,
    Account,
    DeviceSecurity,
    Health,
    Apps,
    Restore,
    Devices,
}

impl Page {
    /// Side menu order.
    const ALL: [Page; 9] = [
        Page::Home,
        Page::Antivirus,
        Page::Firewall,
        Page::Account,
        Page::DeviceSecurity,
        Page::Health,
        Page::Apps,
        Page::Restore,
        Page::Devices,
    ];
    /// Side menu text.
    fn label(self) -> &'static str {
        match self {
            Page::Home => "Security at a glance",
            Page::Antivirus => "Virus & threat protection",
            Page::Firewall => "Firewall & network",
            Page::Account => "Account protection",
            Page::DeviceSecurity => "Device security",
            Page::Health => "Performance & health",
            Page::Apps => "App permissions",
            Page::Restore => "Restore & backup",
            Page::Devices => "Device manager",
        }
    }
    /// Side menu icon.
    fn icon(self) -> Icon {
        match self {
            Page::Home => Icon::Home,
            Page::Antivirus => Icon::Virus,
            Page::Firewall => Icon::Firewall,
            Page::Account => Icon::Account,
            Page::DeviceSecurity => Icon::Lock,
            Page::Health => Icon::Pulse,
            Page::Apps => Icon::Apps,
            Page::Restore => Icon::Restore,
            Page::Devices => Icon::Chip,
        }
    }
    /// Key used by the company policy's `hide_pages`.
    fn policy_key(self) -> Option<&'static str> {
        Some(match self {
            Page::Home => return None,
            Page::Antivirus => "antivirus",
            Page::Firewall => "firewall",
            Page::Account => "account",
            Page::DeviceSecurity => "device-security",
            Page::Health => "health",
            Page::Apps => "apps",
            Page::Restore => "restore",
            Page::Devices => "devices",
        })
    }
    /// False when the company policy hides this page.
    fn visible(self) -> bool {
        self.policy_key()
            .map(|k| !policy::get().hidden(k))
            .unwrap_or(true)
    }
}

/// What to do when a privileged task finishes.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum AfterAdmin {
    /// Re-read everything (most actions).
    RefreshAll,
    /// stdout is `snapper --jsonout list` output to show.
    SnapperList,
    /// stdout is firewall log text to show.
    FirewallLog,
    /// stdout has a new disk recovery key to show.
    RecoveryKey,
    /// stdout has the path of an encryption header backup to save.
    HeaderBackup,
    /// Follow-up already done; the log window is still open.
    Handled,
}

/// A value computed on a background thread.
pub struct Bg<T> {
    /// The latest finished value (`None` until the first one finishes).
    pub value: Shared<Option<T>>,
    /// A computation is running.
    busy: Arc<AtomicBool>,
    /// When the last computation started.
    pub last: Option<Instant>,
}

impl<T: Send + 'static> Bg<T> {
    /// Nothing computed yet.
    fn new() -> Self {
        Self {
            value: shared(None),
            busy: Arc::new(AtomicBool::new(false)),
            last: None,
        }
    }
    /// True while a computation runs.
    pub fn busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }
    /// Compute a new value with `f` on a background thread and redraw the window when it's
    /// done. Does nothing if a computation is already running.
    pub fn refresh(&mut self, ctx: &egui::Context, f: impl FnOnce() -> T + Send + 'static) {
        if self.busy.swap(true, Ordering::SeqCst) {
            return;
        }
        self.last = Some(Instant::now());
        let (slot, busy, ctx) = (self.value.clone(), self.busy.clone(), ctx.clone());
        std::thread::spawn(move || {
            let v = f();
            *slot.lock().unwrap() = Some(v);
            busy.store(false, Ordering::SeqCst);
            ctx.request_repaint();
        });
    }
    /// A copy of the latest value.
    pub fn get(&self) -> Option<T>
    where
        T: Clone,
    {
        self.value.lock().unwrap().clone()
    }
    /// True when nothing was computed yet or the last computation started more than `every`
    /// ago.
    pub fn stale(&self, every: Duration) -> bool {
        self.last.map(|t| t.elapsed() > every).unwrap_or(true)
    }
}

/// The whole state of the main window. Each page's data lives in a [`Bg`] so it loads in the
/// background; the page modules (`page_*.rs`) add the drawing code to this type.
pub struct App {
    /// The page shown now.
    pub page: Page,
    /// None = automatic (collapsed on narrow windows), Some = user's choice.
    nav_choice: Option<bool>,
    /// The window was sized to the screen (done once at start).
    window_fitted: bool,
    /// Frames waited for the monitor size to be known.
    fit_frames: u32,
    /// The window is too narrow for the full side menu.
    narrow: bool,
    /// First-frame work (loading data, starting a requested scan) is done.
    started: bool,

    /// Results for "Security at a glance" and the side menu badges.
    pub checks: Bg<Vec<checks::CheckResult>>,

    /// The administrator task running or just finished, and what to do afterwards.
    pub admin: Option<(AdminTask, AfterAdmin)>,
    /// Short message at the bottom of the window, and when it appeared.
    pub toast: Option<(String, Instant)>,

    // Antivirus
    /// ClamAV version and definitions.
    pub clam: Bg<antivirus::ClamInfo>,
    /// The scan running now (started from the window).
    pub scan: Option<antivirus::ScanJob>,
    /// Scan type chosen under "Scan options".
    pub scan_kind: antivirus::ScanKind,
    /// Folder for a custom scan.
    pub custom_path: String,
    /// Answer from the folder picker (it runs on its own thread).
    pub folder_pick: Shared<Option<PathBuf>>,
    /// Protection history (reloaded when the tray adds to it).
    pub history: Vec<antivirus::ScanRecord>,
    /// Quarantined files.
    pub quarantine: Vec<antivirus::QuarantineItem>,
    /// Result message on the antivirus page: (success, text).
    pub av_message: Option<(bool, String)>,
    /// Start a quick scan when the antivirus page opens ("Quick scan" button on a tile).
    pub start_quick_scan: bool,

    // Restore points
    /// Snapper state and schedules.
    pub restore: Bg<restore::RestoreState>,
    /// Restore points read with the administrator password ("Show restore points").
    pub snapshot_override: Option<Vec<restore::Snapshot>>,
    /// Description typed in the "Create restore point" dialog, while it is open.
    pub create_dialog: Option<String>,

    // Devices
    /// Last hardware scan.
    pub devices: Bg<devices::DeviceSnapshot>,
    /// Key of the device selected in the device manager.
    pub selected_device: Option<String>,
    /// "Show only devices that need attention".
    pub only_problems: bool,
    /// Re-scan hardware every few seconds while the device manager is open.
    pub watch_devices: bool,
    /// Last hardware fingerprint seen by "Watch for new devices", and when it was taken.
    pub dev_fp: Option<(Instant, String)>,
    /// The user asked for a scan ("Scan for hardware changes"): show the spinner.
    pub dev_manual_scan: bool,
    /// module name -> (file, package) details for the device panel
    pub driver_info: std::collections::HashMap<String, devices::DriverInfo>,

    /// Daily quick scan setting (mirrors the settings file).
    pub daily_scan: bool,
    /// Account protection data.
    pub account: Bg<account::AccountState>,
    /// Device security data.
    pub devsec: Bg<devsec::DeviceSecurity>,
    /// Performance & health data.
    pub health: Bg<health::Health>,
    /// Flatpak apps and their permissions.
    pub apps: Bg<Vec<appperms::AppPerms>>,
    /// File backup status.
    pub backup: Bg<backup::BackupState>,
    /// The security report is being generated.
    pub report_busy: bool,
    /// Disk password dialog (recovery key / change password), while open.
    pub luks_dialog: Option<page_account::LuksDialog>,
    /// A new recovery key to show once; cleared when its window closes.
    pub recovery_key: Option<String>,
    /// Result of saving a recovery key or header backup to a file (done on another thread).
    pub file_saved: Shared<Option<Result<PathBuf, String>>>,
    /// The "Restart your computer?" dialog is open.
    pub confirm_restart: bool,
    /// Latest [`checks::fingerprint`], polled every 5 seconds.
    quick: Bg<String>,
    /// The fingerprint the window last reacted to.
    quick_seen: Option<String>,
    /// Modification times of the history and quarantine files the window last loaded.
    av_stamp: (Option<std::time::SystemTime>, Option<std::time::SystemTime>),
    /// Levels of the last check results, to tell the tray when they change.
    levels_seen: Option<Vec<checks::Level>>,
    /// Where the report was saved, or why it failed (set by the report thread).
    pub report_done: Shared<Option<Result<PathBuf, String>>>,
    /// Dry run of "Uninstall driver" being worked out in the background.
    pub purge_plan: Option<Shared<Option<devices::PurgePlan>>>,

    // Firewall
    /// Firewall on/off and defaults.
    pub fw_status: Bg<firewall::FirewallStatus>,
    /// Network connections.
    pub fw_conns: Bg<Vec<firewall::Conn>>,
    /// Firewall log readable without a password.
    pub fw_log: Bg<firewall::LogState>,
    /// Log read with the administrator password.
    pub fw_log_override: Option<Vec<firewall::LogEntry>>,
    /// Which connections the table shows.
    pub fw_filter: page_firewall::ConnFilter,
    /// Also show connections inside this computer.
    pub fw_show_local: bool,
    /// Refresh the connections every few seconds.
    pub fw_live: bool,
    /// The "Rules added here" window is open.
    pub fw_rules_dialog: bool,
    /// The "Add a rule" form, while open.
    pub fw_add: Option<page_firewall::AddRuleForm>,
    /// Firewall rule change to save once its administrator task succeeds.
    pub pending_fw: Option<PendingFw>,

    /// Confirmation dialog for a risky admin action.
    pub confirm: Option<Confirm>,
}

/// A firewall rule change to record once the admin task succeeds.
#[derive(Clone, Debug)]
pub enum PendingFw {
    /// A rule is being added.
    Add(firewall::Rule),
    /// A rule is being removed.
    Remove(firewall::Rule),
}

/// A confirmation dialog shown before a risky administrator action.
pub struct Confirm {
    /// Dialog title.
    pub title: String,
    /// Explanation of what will happen.
    pub text: String,
    /// Text of the button that goes ahead.
    pub button: String,
    /// Title of the task window if confirmed.
    pub task_title: String,
    /// Helper command to run if confirmed.
    pub args: Vec<String>,
    /// Firewall rule to record if confirmed.
    pub fw: Option<PendingFw>,
}

impl App {
    /// Create the window state: theme, fonts, settings, and the listener that brings this
    /// window forward when the app is opened again.
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        egui_extras::install_image_loaders(&cc.egui_ctx);
        match std::env::var("PROTON_SECURITY_THEME").as_deref() {
            Ok("light") => cc.egui_ctx.set_theme(egui::Theme::Light),
            Ok("dark") => cc.egui_ctx.set_theme(egui::Theme::Dark),
            _ => {}
        }
        ui::setup_style(&cc.egui_ctx);
        let page = page_from_arg(std::env::args().nth(1).as_deref());
        if let Some(listener) = INSTANCE_LISTENER.lock().unwrap().take() {
            let (slot, ctx) = (REQUESTED_PAGE.clone(), cc.egui_ctx.clone());
            std::thread::spawn(move || instance_server(listener, slot, ctx));
        }
        Self {
            page,
            nav_choice: None,
            window_fitted: false,
            fit_frames: 0,
            narrow: false,
            started: false,
            checks: Bg::new(),
            admin: None,
            toast: None,
            clam: Bg::new(),
            scan: None,
            scan_kind: antivirus::ScanKind::Quick,
            custom_path: String::new(),
            folder_pick: shared(None),
            history: antivirus::load_history(),
            quarantine: antivirus::load_quarantine(),
            av_message: None,
            start_quick_scan: false,
            restore: Bg::new(),
            snapshot_override: None,
            create_dialog: None,
            devices: Bg::new(),
            selected_device: None,
            only_problems: false,
            watch_devices: true,
            dev_fp: None,
            dev_manual_scan: false,
            daily_scan: settings::load().daily_scan,
            purge_plan: None,
            account: Bg::new(),
            devsec: Bg::new(),
            health: Bg::new(),
            apps: Bg::new(),
            backup: Bg::new(),
            report_busy: false,
            luks_dialog: None,
            // Debug builds only: show the recovery key window for testing.
            recovery_key: if cfg!(debug_assertions) {
                std::env::var("PROTON_SECURITY_DEMO_RECOVERY_KEY").ok()
            } else {
                None
            },
            file_saved: shared(None),
            confirm_restart: false,
            quick: Bg::new(),
            quick_seen: None,
            av_stamp: antivirus::files_stamp(),
            levels_seen: None,
            report_done: shared(None),
            fw_status: Bg::new(),
            fw_conns: Bg::new(),
            fw_log: Bg::new(),
            fw_log_override: None,
            fw_filter: Default::default(),
            fw_show_local: false,
            fw_live: true,
            fw_rules_dialog: false,
            fw_add: None,
            pending_fw: None,
            confirm: None,
            driver_info: std::collections::HashMap::new(),
        }
    }

    /// Notice changes made outside the app (every 5 s) and keep the tray in
    /// step with what the window shows.
    fn watch_changes(&mut self, ctx: &egui::Context) {
        if self.quick.stale(Duration::from_secs(5)) {
            self.quick.refresh(ctx, checks::fingerprint);
        }
        if let Some(q) = self.quick.get()
            && self.quick_seen.as_ref() != Some(&q)
        {
            if self.quick_seen.is_some() {
                self.refresh_checks(ctx);
                self.account.refresh(ctx, account::load);
                self.refresh_clam(ctx);
            }
            self.quick_seen = Some(q);
        }
        if let Some(c) = self.checks.get() {
            let levels: Vec<checks::Level> = c.iter().map(|r| r.level).collect();
            if self.levels_seen.as_ref() != Some(&levels) {
                if self.levels_seen.is_some() {
                    tray::poke_tray();
                }
                self.levels_seen = Some(levels);
            }
        }
        // Scans recorded by the tray (downloads, USB drives, daily scan).
        let stamp = antivirus::files_stamp();
        if stamp != self.av_stamp {
            self.av_stamp = stamp;
            self.reload_av_files();
            self.refresh_checks(ctx);
        }
        // Keep polling while the window is idle.
        ctx.request_repaint_after(Duration::from_secs(2));
    }

    /// Re-run all checks in the background.
    pub fn refresh_checks(&mut self, ctx: &egui::Context) {
        self.checks.refresh(ctx, checks::run_all);
    }
    /// Re-read ClamAV's state in the background.
    pub fn refresh_clam(&mut self, ctx: &egui::Context) {
        self.clam.refresh(ctx, antivirus::clam_info);
    }
    /// Re-read Snapper's state in the background.
    pub fn refresh_restore(&mut self, ctx: &egui::Context) {
        self.restore.refresh(ctx, restore::load);
    }
    /// Re-scan hardware in the background.
    pub fn refresh_devices(&mut self, ctx: &egui::Context) {
        self.devices.refresh(ctx, devices::scan);
    }
    /// Re-read the protection history and quarantine list.
    pub fn reload_av_files(&mut self) {
        self.history = antivirus::load_history();
        self.quarantine = antivirus::load_quarantine();
    }

    /// Show a short message at the bottom of the window for a few seconds.
    pub fn toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    /// Run a whitelisted helper command as root (polkit asks for the password).
    pub fn run_admin(
        &mut self,
        ctx: &egui::Context,
        title: &str,
        args: &[&str],
        after: AfterAdmin,
        visible: bool,
    ) {
        if self
            .admin
            .as_ref()
            .map(|(t, _)| !t.finished())
            .unwrap_or(false)
        {
            self.toast("Please wait for the current task to finish.");
            return;
        }
        self.admin = Some((admin::spawn(title, args, visible, ctx), after));
    }

    /// Like `run_admin`, sending `input` (passwords) on the helper's stdin.
    pub fn run_admin_input(
        &mut self,
        ctx: &egui::Context,
        title: &str,
        args: &[&str],
        input: String,
        after: AfterAdmin,
        visible: bool,
    ) {
        if self
            .admin
            .as_ref()
            .map(|(t, _)| !t.finished())
            .unwrap_or(false)
        {
            self.toast("Please wait for the current task to finish.");
            return;
        }
        self.admin = Some((
            admin::spawn_with_input(title, args, Some(input), visible, ctx),
            after,
        ));
    }

    /// Carry out a tile button ([`checks::Action`]).
    pub fn do_action(&mut self, ctx: &egui::Context, a: &checks::Action) {
        match a {
            checks::Action::Admin { title, args, .. } => {
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                self.run_admin(ctx, title, &args, AfterAdmin::RefreshAll, true);
            }
            checks::Action::Open { page, .. } => self.page = *page,
            checks::Action::QuickScan => {
                self.page = Page::Antivirus;
                self.scan_kind = antivirus::ScanKind::Quick;
                self.start_quick_scan = true;
            }
            checks::Action::Launch { cmd, args, .. } => {
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                if !sys::spawn_detached(cmd, &args) {
                    self.toast(format!("Could not start {cmd}."));
                }
            }
            checks::Action::Fix { fix, .. } => {
                match fix {
                    checks::Fix::ScreenLock => {
                        match account::fix_screen_lock(policy::get().max_screen_lock_minutes) {
                            Ok(()) => self.toast("Screen lock is on."),
                            Err(e) => self.toast(e),
                        }
                    }
                    checks::Fix::Restart => self.confirm_restart = true,
                    checks::Fix::BackupSettings => {
                        if !backup::open_settings() {
                            self.page = Page::Restore;
                        }
                    }
                    checks::Fix::BackupOtherWay => settings::update(|s| s.backup_other_way = true),
                }
                self.refresh_checks(ctx);
                self.account.last = None;
                self.backup.last = None;
                tray::poke_tray();
            }
        }
    }

    /// "Save your work" confirmation before restarting.
    fn restart_dialog(&mut self, ctx: &egui::Context) {
        if !self.confirm_restart {
            return;
        }
        let (mut go, mut cancel) = (false, false);
        egui::Modal::new(egui::Id::unique("restart_confirm"))
            .frame(
                egui::Frame::popup(&ctx.global_style())
                    .inner_margin(20)
                    .corner_radius(10),
            )
            .show(ctx, |ui| {
                ui.set_width(440.0);
                ui.horizontal(|ui| {
                    let (r, _) =
                        ui.allocate_exact_size(egui::vec2(24.0, 24.0), egui::Sense::hover());
                    ui::paint_badge(
                        ui.painter(),
                        r.center(),
                        10.0,
                        Some(checks::Level::Warn),
                        ui.visuals().window_fill,
                    );
                    ui.label(
                        egui::RichText::new("Restart your computer?")
                            .size(18.0)
                            .strong(),
                    );
                });
                ui.add_space(6.0);
                ui.add(
                    egui::Label::new(
                        "Before you restart, save your work and close all open apps. \
                         Anything that is not saved will be lost.",
                    )
                    .wrap(),
                );
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui::primary_button(ui, "Restart now").clicked() {
                        go = true;
                    }
                    if ui::button(ui, "Cancel").clicked()
                        || ui.input(|i| i.key_pressed(egui::Key::Escape))
                    {
                        cancel = true;
                    }
                });
            });
        if go {
            self.confirm_restart = false;
            if !health::request_restart() {
                self.toast("Could not start the restart.");
            }
        } else if cancel {
            self.confirm_restart = false;
        }
    }

    /// Write the security report in the background and open it in the browser.
    pub fn export_report(&mut self, ctx: &egui::Context) {
        if self.report_busy {
            return;
        }
        self.report_busy = true;
        let (slot, ctx) = (self.report_done.clone(), ctx.clone());
        std::thread::spawn(move || {
            let default = report::default_path();
            // Let the user choose where to save (KDE file dialog), default in Documents.
            let path = if sys::which("kdialog").is_some() {
                match sys::run_full(
                    "kdialog",
                    &[
                        "--title",
                        "Save security report",
                        "--getsavefilename",
                        &default.to_string_lossy(),
                        "*.html",
                    ],
                ) {
                    Some((true, out, _)) if !out.trim().is_empty() => {
                        Some(PathBuf::from(out.trim()))
                    }
                    Some(_) => None, // cancelled
                    None => Some(default),
                }
            } else {
                Some(default)
            };
            let r = match path {
                None => Err(String::new()),
                Some(p) => report::save(&p).map(|_| p),
            };
            *slot.lock().unwrap() = Some(r);
            ctx.request_repaint();
        });
    }

    /// Per-frame bookkeeping: finish background work (report, admin tasks and their
    /// follow-ups), switch page when another launch asked for one, and keep the window sized to
    /// the screen.
    fn poll(&mut self, ctx: &egui::Context) {
        self.fit_to_screen(ctx);
        let report = self.report_done.lock().unwrap().take();
        if let Some(r) = report {
            self.report_busy = false;
            match r {
                Ok(p) => {
                    sys::open_url(&p.to_string_lossy());
                    self.toast(format!("Report saved to {}", p.display()));
                }
                Err(e) if !e.is_empty() => self.toast(e),
                Err(_) => {}
            }
        }
        if !self.page.visible() {
            self.page = Page::Home;
        }
        if let Some(p) = REQUESTED_PAGE.lock().unwrap().take() {
            if let Some(p) = p {
                self.page = p;
            }
            self.refresh_checks(ctx);
        }
        if !self.started {
            self.started = true;
            self.refresh_checks(ctx);
            self.refresh_clam(ctx);
        }
        // Admin task finished?
        let finished = self
            .admin
            .as_ref()
            .filter(|(t, after)| t.finished() && *after != AfterAdmin::Handled)
            .map(|(t, after)| {
                (
                    t.state(),
                    *after,
                    t.stdout.lock().unwrap().clone(),
                    t.visible,
                )
            });
        if let Some((state, after, stdout, visible)) = finished {
            tray::poke_tray();
            // Record firewall rule changes only when the command really worked.
            if let Some(p) = self.pending_fw.take()
                && state == TaskState::Succeeded
            {
                settings::update(|s| match p {
                    PendingFw::Add(r) => {
                        s.fw_rules.retain(|x| x.kind != r.kind);
                        s.fw_rules.push(r);
                    }
                    PendingFw::Remove(r) => s.fw_rules.retain(|x| x.kind != r.kind),
                });
            }
            match after {
                AfterAdmin::RefreshAll => {
                    self.refresh_checks(ctx);
                    self.refresh_clam(ctx);
                    if self.restore.last.is_some() {
                        self.refresh_restore(ctx);
                    }
                    self.driver_info.clear();
                    if self.devices.last.is_some() {
                        self.refresh_devices(ctx);
                    }
                    self.account.last = None;
                    self.devsec.last = None;
                    self.health.last = None;
                    self.backup.last = None;
                    self.fw_status.refresh(ctx, firewall::status);
                    self.fw_conns.refresh(ctx, firewall::connections);
                }
                AfterAdmin::RecoveryKey => {
                    if state == TaskState::Succeeded {
                        self.recovery_key = stdout
                            .lines()
                            .find_map(|l| l.strip_prefix(admin::SECRET_PREFIX))
                            .map(|k| k.trim().to_string());
                    }
                    // Don't keep the key in the task's buffer.
                    if let Some((t, _)) = &self.admin {
                        t.stdout.lock().unwrap().clear();
                    }
                }
                AfterAdmin::HeaderBackup => {
                    if state == TaskState::Succeeded
                        && let Some(src) =
                            stdout.lines().find_map(|l| l.strip_prefix("HEADER-FILE: "))
                    {
                        let src = PathBuf::from(src.trim());
                        let slot = self.file_saved.clone();
                        std::thread::spawn(move || {
                            let name = src
                                .file_name()
                                .map(|n| {
                                    n.to_string_lossy()
                                        .replace("proton-security-header-", "Encryption-header-")
                                })
                                .unwrap_or_default();
                            let default = report::default_path().with_file_name(name);
                            let r =
                                page_account::choose_save_path(&default, "*.img").and_then(|dst| {
                                    std::fs::copy(&src, &dst)
                                        .map_err(|e| format!("Could not save: {e}"))?;
                                    Ok(dst)
                                });
                            let _ = std::fs::remove_file(&src);
                            *slot.lock().unwrap() = Some(r);
                        });
                    }
                }
                AfterAdmin::FirewallLog => {
                    if state == TaskState::Succeeded {
                        self.fw_log_override = Some(firewall::parse_log(&stdout));
                    }
                }
                AfterAdmin::Handled => {}
                AfterAdmin::SnapperList => {
                    if state == TaskState::Succeeded {
                        match restore::parse_list(&stdout) {
                            Ok(s) => self.snapshot_override = Some(s),
                            Err(e) => self.toast(e),
                        }
                    }
                }
            }
            // Hidden tasks are discarded right away; visible ones wait for "Close".
            if !visible {
                if state == TaskState::Failed {
                    self.toast("The task failed.");
                }
                self.admin = None;
            } else if let Some(a) = &mut self.admin {
                a.1 = AfterAdmin::Handled;
            }
        }
        if let Some((_, t)) = &self.toast
            && t.elapsed() > Duration::from_secs(5)
        {
            self.toast = None;
        }
    }

    /// Draw the side menu: page buttons with attention badges and the footer (Proton OS link,
    /// version).
    fn nav(&mut self, ui: &mut egui::Ui) {
        let dark = ui.visuals().dark_mode;
        ui.add_space(8.0);
        let w = ui.available_width();
        // Hamburger: collapse/expand the menu, like Windows Security.
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(44.0, 40.0), egui::Sense::click());
        if resp.hovered() {
            ui.painter()
                .rect_filled(rect, 4.0, ui.visuals().widgets.hovered.weak_bg_fill);
        }
        Icon::Menu.paint(
            ui,
            egui::Rect::from_center_size(rect.center(), egui::vec2(20.0, 20.0)),
            ui.visuals().text_color(),
        );
        if resp
            .on_hover_text(if self.nav_expanded() {
                "Collapse menu"
            } else {
                "Expand menu"
            })
            .clicked()
        {
            self.nav_choice = Some(!self.nav_expanded());
        }
        ui.add_space(6.0);

        let counts = self.attention_counts();
        for page in Page::ALL.into_iter().filter(|p| p.visible()) {
            let selected = self.page == page;
            let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, 42.0), egui::Sense::click());
            let bg = if selected {
                if dark {
                    egui::Color32::from_rgb(55, 55, 55)
                } else {
                    egui::Color32::from_rgb(222, 222, 222)
                }
            } else if resp.hovered() {
                ui.visuals().widgets.hovered.weak_bg_fill
            } else {
                egui::Color32::TRANSPARENT
            };
            ui.painter()
                .rect_filled(rect.shrink2(egui::vec2(4.0, 1.0)), 5.0, bg);
            if selected {
                let bar = egui::Rect::from_min_size(
                    rect.left_top() + egui::vec2(4.0, 11.0),
                    egui::vec2(3.0, 20.0),
                );
                ui.painter().rect_filled(bar, 2.0, ui::accent(ui));
            }
            let icon_rect = egui::Rect::from_center_size(
                rect.left_center() + egui::vec2(22.0, 0.0),
                egui::vec2(20.0, 20.0),
            );
            page.icon().paint(ui, icon_rect, ui.visuals().text_color());
            // Small warning dot on the nav icon when that area needs attention.
            if counts.for_page(page) > 0 {
                let outline = ui::nav_fill(dark);
                ui::paint_badge(
                    ui.painter(),
                    icon_rect.right_bottom() + egui::vec2(-1.0, -1.0),
                    5.0,
                    Some(checks::Level::Warn),
                    outline,
                );
            }
            if self.nav_expanded() {
                ui.painter().text(
                    rect.left_center() + egui::vec2(46.0, 0.0),
                    egui::Align2::LEFT_CENTER,
                    page.label(),
                    egui::FontId::proportional(14.5),
                    ui.visuals().text_color(),
                );
            }
            let resp = if self.nav_expanded() {
                resp
            } else {
                resp.on_hover_text(page.label())
            };
            if resp.clicked() {
                self.page = page;
            }
        }

        // Footer
        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
            ui.add_space(10.0);
            if self.nav_expanded() {
                // Bottom-up layout: added from the bottom line to the top.
                let line = |ui: &mut egui::Ui, add: &mut dyn FnMut(&mut egui::Ui)| {
                    ui.horizontal(|ui| {
                        ui.add_space(14.0);
                        add(ui);
                    });
                };
                line(ui, &mut |ui| {
                    ui::small(ui, format!("{APP_NAME} {}", env!("CARGO_PKG_VERSION")))
                });
                line(ui, &mut |ui| {
                    if ui::link(ui, "www.protonos.org").clicked() {
                        sys::open_url("https://www.protonos.org");
                    }
                });
                line(ui, &mut |ui| ui::small(ui, "App created by Proton OS"));
            } else {
                let (r, resp) =
                    ui.allocate_exact_size(egui::vec2(44.0, 20.0), egui::Sense::hover());
                let _ = r;
                resp.on_hover_text(format!(
                    "{APP_NAME} {}\nApp created by Proton OS\nwww.protonos.org",
                    env!("CARGO_PKG_VERSION")
                ));
            }
        });
    }

    /// Progress window of an administrator task, with its live log.
    fn admin_window(&mut self, ctx: &egui::Context) {
        let Some((task, _)) = &self.admin else { return };
        if !task.visible {
            return;
        }
        let state = task.state();
        let title = task.title.clone();
        let log = task.log.lock().unwrap().clone();
        let mut close = false;
        egui::Modal::new(egui::Id::unique("admin_task"))
            .frame(
                egui::Frame::popup(&ctx.global_style())
                    .inner_margin(20)
                    .corner_radius(10),
            )
            .show(ctx, |ui| {
                ui.set_width(620.0);
                ui.horizontal(|ui| {
                    match state {
                        TaskState::Running => {
                            ui.add(egui::Spinner::new().size(22.0));
                        }
                        TaskState::Succeeded => {
                            let (r, _) = ui
                                .allocate_exact_size(egui::vec2(24.0, 24.0), egui::Sense::hover());
                            ui::paint_badge(
                                ui.painter(),
                                r.center(),
                                10.0,
                                Some(checks::Level::Ok),
                                ui.visuals().window_fill,
                            );
                        }
                        _ => {
                            let (r, _) = ui
                                .allocate_exact_size(egui::vec2(24.0, 24.0), egui::Sense::hover());
                            ui::paint_badge(
                                ui.painter(),
                                r.center(),
                                10.0,
                                Some(checks::Level::Warn),
                                ui.visuals().window_fill,
                            );
                        }
                    }
                    ui.label(egui::RichText::new(&title).size(18.0).strong());
                });
                ui.add_space(4.0);
                ui::small(
                    ui,
                    match state {
                        TaskState::Running => "Working… You may be asked for your password.",
                        TaskState::Succeeded => "Done.",
                        TaskState::Failed => "Something went wrong. See the details below.",
                        TaskState::Cancelled => "The task was cancelled.",
                    },
                );
                ui.add_space(6.0);
                egui::Frame::new()
                    .fill(if ui.visuals().dark_mode {
                        egui::Color32::from_gray(24)
                    } else {
                        egui::Color32::from_gray(248)
                    })
                    .corner_radius(6)
                    .inner_margin(8)
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .max_height(280.0)
                            .stick_to_bottom(true)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                for l in &log {
                                    ui.label(egui::RichText::new(l).monospace().size(12.0));
                                }
                            });
                    });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if state != TaskState::Running && ui::primary_button(ui, "Close").clicked() {
                        close = true;
                    }
                });
            });
        if close {
            self.admin = None;
        }
    }

    /// Ask before running a risky administrator action.
    pub fn ask_confirm(
        &mut self,
        title: &str,
        text: &str,
        button: &str,
        task_title: &str,
        args: &[&str],
    ) {
        self.confirm = Some(Confirm {
            title: title.into(),
            text: text.into(),
            button: button.into(),
            task_title: task_title.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            fw: None,
        });
    }

    /// Like [`App::ask_confirm`], also recording a firewall rule change if it succeeds.
    pub fn ask_confirm_fw(
        &mut self,
        title: &str,
        text: &str,
        button: &str,
        task_title: &str,
        args: &[&str],
        fw: PendingFw,
    ) {
        self.ask_confirm(title, text, button, task_title, args);
        if let Some(c) = &mut self.confirm {
            c.fw = Some(fw);
        }
    }

    /// Draw the confirmation dialog, and start the task when confirmed.
    fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(c) = &self.confirm else { return };
        let (mut go, mut cancel) = (false, false);
        egui::Modal::new(egui::Id::unique("confirm"))
            .frame(
                egui::Frame::popup(&ctx.global_style())
                    .inner_margin(20)
                    .corner_radius(10),
            )
            .show(ctx, |ui| {
                ui.set_width(460.0);
                ui.horizontal(|ui| {
                    let (r, _) =
                        ui.allocate_exact_size(egui::vec2(24.0, 24.0), egui::Sense::hover());
                    ui::paint_badge(
                        ui.painter(),
                        r.center(),
                        10.0,
                        Some(checks::Level::Warn),
                        ui.visuals().window_fill,
                    );
                    ui.label(egui::RichText::new(&c.title).size(18.0).strong());
                });
                ui.add_space(6.0);
                ui.add(egui::Label::new(&c.text).wrap());
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui::primary_button(ui, &c.button).clicked() {
                        go = true;
                    }
                    if ui::button(ui, "Cancel").clicked()
                        || ui.input(|i| i.key_pressed(egui::Key::Escape))
                    {
                        cancel = true;
                    }
                });
            });
        if go {
            let c = self.confirm.take().unwrap();
            let args: Vec<&str> = c.args.iter().map(String::as_str).collect();
            self.pending_fw = c.fw.clone();
            self.run_admin(ctx, &c.task_title, &args, AfterAdmin::RefreshAll, true);
        } else if cancel {
            self.confirm = None;
        }
    }

    /// On small screens (e.g. 1366x768 laptops) open maximized so the window
    /// never hides behind the taskbar; on large screens open at a comfortable size.
    fn fit_to_screen(&mut self, ctx: &egui::Context) {
        if self.window_fitted {
            return;
        }
        self.fit_frames += 1;
        let monitor = ctx.input(|i| i.viewport().monitor_size);
        match monitor {
            Some(m) if m.x > 0.0 && m.y > 0.0 => {
                self.window_fitted = true;
                if m.x < 1280.0 || m.y < 900.0 {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(true));
                } else {
                    let size = egui::vec2((m.x * 0.8).min(1180.0), (m.y * 0.8).min(800.0));
                    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
                }
            }
            // The monitor size may not be known on the very first frames.
            _ if self.fit_frames > 30 => self.window_fitted = true,
            _ => ctx.request_repaint(),
        }
    }

    /// Show the full side menu (with text) or only icons.
    fn nav_expanded(&self) -> bool {
        self.nav_choice.unwrap_or(!self.narrow)
    }

    /// How many items need attention on each page, for the side menu badges.
    pub fn attention_counts(&self) -> Attention {
        let mut a = Attention::default();
        if let Some(c) = self.checks.get() {
            for r in c.iter().filter(|r| r.level == checks::Level::Warn) {
                a.home += 1;
                match r.id {
                    checks::CheckId::Antivirus => a.av += 1,
                    checks::CheckId::Snapper => a.restore += 1,
                    checks::CheckId::Firewall => a.firewall += 1,
                    checks::CheckId::Account => a.account += 1,
                    checks::CheckId::DeviceSecurity => a.devsec += 1,
                    checks::CheckId::Health => a.health += 1,
                    checks::CheckId::Backup => a.restore += 1,
                    _ => {}
                }
            }
        }
        if let Some(d) = self.devices.value.lock().unwrap().as_ref() {
            a.devices = d.problems();
        }
        a
    }
}

/// Attention counts per page.
#[derive(Default)]
pub struct Attention {
    /// Tiles that need attention (all pages together).
    pub home: usize,
    /// Virus & threat protection.
    pub av: usize,
    /// System restore and File backup.
    pub restore: usize,
    /// Devices without a working driver.
    pub devices: usize,
    /// Firewall.
    pub firewall: usize,
    /// Account protection.
    pub account: usize,
    /// Device security.
    pub devsec: usize,
    /// Performance & health.
    pub health: usize,
}

impl Attention {
    /// Count for one page.
    fn for_page(&self, p: Page) -> usize {
        match p {
            Page::Home => self.home,
            Page::Antivirus => self.av,
            Page::Firewall => self.firewall,
            Page::Account => self.account,
            Page::DeviceSecurity => self.devsec,
            Page::Health => self.health,
            Page::Apps => 0,
            Page::Restore => self.restore,
            Page::Devices => self.devices,
        }
    }
}

impl eframe::App for App {
    /// Draw one frame: side menu, current page, then any dialogs on top.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll(&ctx);
        self.watch_changes(&ctx);
        let dark = ui.visuals().dark_mode;
        self.narrow = ui.available_width() < 1060.0;

        egui::Panel::left("nav")
            .resizable(false)
            .exact_size(if self.nav_expanded() { 260.0 } else { 52.0 })
            .show_separator_line(false)
            .frame(
                egui::Frame::new()
                    .fill(ui::nav_fill(dark))
                    .inner_margin(egui::Margin::symmetric(4, 0)),
            )
            .show(ui, |ui| self.nav(ui));

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(ui::page_fill(dark))
                    .inner_margin(egui::Margin {
                        left: 32,
                        right: 24,
                        top: 18,
                        bottom: 12,
                    }),
            )
            .show(ui, |ui| {
                if let Some((msg, _)) = self.toast.clone() {
                    ui::card(ui, |ui| {
                        ui::status_line(ui, Some(checks::Level::Warn), &msg)
                    });
                    ui.add_space(8.0);
                }
                match self.page {
                    Page::Devices => self.page_devices(ui),
                    Page::Home => self.page_home(ui),
                    Page::Firewall => self.page_firewall(ui),
                    page => {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                let w = ui.available_width().min(1100.0);
                                ui.set_max_width(w);
                                match page {
                                    Page::Antivirus => self.page_antivirus(ui),
                                    Page::Restore => self.page_restore(ui),
                                    Page::Account => self.page_account(ui),
                                    Page::DeviceSecurity => self.page_devsec(ui),
                                    Page::Health => self.page_health(ui),
                                    Page::Apps => self.page_apps(ui),
                                    Page::Devices | Page::Home | Page::Firewall => unreachable!(),
                                }
                                ui.add_space(24.0);
                            });
                    }
                }
            });

        self.admin_window(&ctx);
        self.create_restore_dialog(&ctx);
        self.confirm_dialog(&ctx);
        self.fw_rules_window(&ctx);
        self.fw_add_rule_window(&ctx);
        self.luks_dialogs(&ctx);
        self.restart_dialog(&ctx);
    }
}

/// Page for a command-line flag such as `--firewall`.
fn page_from_arg(a: Option<&str>) -> Page {
    match a {
        Some("--antivirus") => Page::Antivirus,
        Some("--restore") => Page::Restore,
        Some("--devices") => Page::Devices,
        Some("--firewall") => Page::Firewall,
        Some("--account") => Page::Account,
        Some("--device-security") => Page::DeviceSecurity,
        Some("--health") => Page::Health,
        Some("--apps") => Page::Apps,
        _ => Page::Home,
    }
}

// ------------------------------------------------------------------ single instance

/// Page asked for by another launch of the app: `Some(None)` = just come to the front,
/// `Some(Some(p))` = also show page `p`.
type PageRequest = Shared<Option<Option<Page>>>;

/// Socket of the first running window, opened in `main` and served once the window exists.
static INSTANCE_LISTENER: std::sync::Mutex<Option<std::os::unix::net::UnixListener>> =
    std::sync::Mutex::new(None);
/// Filled by the socket server, read by [`App::poll`].
static REQUESTED_PAGE: std::sync::LazyLock<PageRequest> = std::sync::LazyLock::new(|| shared(None));

/// `$XDG_RUNTIME_DIR/proton-security.sock` (private to the user).
fn socket_path() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("proton-security.sock")
}

/// If a window is already open, ask it to come to the front and return true.
fn forward_to_running_instance(arg: Option<&str>) -> bool {
    use std::io::Write;
    let path = socket_path();
    if let Ok(mut s) = std::os::unix::net::UnixStream::connect(&path) {
        let _ = s.write_all(arg.unwrap_or("--home").as_bytes());
        return true;
    }
    // Stale socket from a crashed instance.
    let _ = std::fs::remove_file(&path);
    if let Ok(l) = std::os::unix::net::UnixListener::bind(&path) {
        *INSTANCE_LISTENER.lock().unwrap() = Some(l);
    }
    false
}

/// Accept messages from later launches (one page flag each) and bring the window forward.
fn instance_server(l: std::os::unix::net::UnixListener, slot: PageRequest, ctx: egui::Context) {
    use std::io::Read;
    for mut stream in l.incoming().flatten() {
        let mut buf = String::new();
        let _ = stream.read_to_string(&mut buf);
        let page = match buf.trim() {
            "--home" | "" => None,
            a => Some(page_from_arg(Some(a))),
        };
        *slot.lock().unwrap() = Some(page);
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        ctx.request_repaint();
    }
}

// ------------------------------------------------------------------ diagnostics

/// `proton-security --diagnose`: print what every check sees, for bug reports.
fn diagnose() {
    println!("{APP_NAME} {} diagnostics\n", env!("CARGO_PKG_VERSION"));
    let st = restore::load();
    println!("== System restore");
    println!("root filesystem : {}", st.root_fs);
    println!(
        "snapper         : {}",
        if st.installed {
            "installed"
        } else {
            "NOT installed"
        }
    );
    println!("configs         : {:?}", st.configs);
    println!(
        "list source     : {:?}{}",
        st.source,
        if st.needs_admin {
            " (reading the list needs the administrator password)"
        } else {
            ""
        }
    );
    println!("snapshots       : {}", st.snapshots.len());
    if let Some(s) = st.latest() {
        println!(
            "latest          : #{} {} {}",
            s.number, s.date, s.description
        );
    }
    if st.timeline_disabled_in_config() {
        println!("note            : TIMELINE_CREATE=no in the root config");
    }
    if st.schedules.is_empty() {
        println!("schedules       : none detected");
    }
    for s in &st.schedules {
        println!(
            "schedule        : {} -> {}{}",
            s.source,
            s.when,
            s.next
                .as_ref()
                .map(|n| format!(" (next {n})"))
                .unwrap_or_default()
        );
    }
    println!("\n== Timers mentioning snap");
    if let Some(o) = sys::run_out("systemctl", &["list-timers", "--all", "--no-pager"]) {
        for l in o
            .lines()
            .filter(|l| l.to_lowercase().contains("snap") || l.starts_with("NEXT"))
        {
            println!("{l}");
        }
    }
    println!("\n== Checks");
    for r in checks::run_all() {
        println!(
            "[{}] {} - {}",
            if r.level == checks::Level::Ok {
                " OK "
            } else {
                "WARN"
            },
            r.title,
            r.headline
        );
        if let Some((l, v, _)) = &r.status_item {
            println!("         {l}: {v}");
        }
        for d in &r.details {
            println!("         {d}");
        }
    }
    let s = settings::load();
    println!("\n== Antivirus schedule");
    println!(
        "daily quick scan: {}",
        if s.daily_scan { "on" } else { "off" }
    );
    println!("scan due now    : {}", tray::scheduled_scan_due());
}

/// Entry point. Command-line modes:
/// - no flag or a page flag (`--firewall`, `--restore`…): open the window, or bring an already
///   open window forward;
/// - `--tray`: the background part (see [`tray::run`]);
/// - `--scheduled-scan`: one quick scan without a window;
/// - `--report [file]`: write the security report and print its path;
/// - `--diagnose`: print diagnostics;
/// - `--version`: print the version.
fn main() -> eframe::Result {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        Some("--tray") => std::process::exit(tray::run()),
        Some("--scheduled-scan") => std::process::exit(tray::scheduled_scan_main()),
        Some("--report") => {
            let path = std::env::args()
                .nth(2)
                .map(PathBuf::from)
                .unwrap_or_else(report::default_path);
            match report::save(&path) {
                Ok(()) => {
                    println!("{}", path.display());
                    std::process::exit(0)
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
            }
        }
        Some("--diagnose") => {
            diagnose();
            std::process::exit(0)
        }
        Some("--version") | Some("-V") => {
            println!("{APP_NAME} {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0)
        }
        Some("--help") | Some("-h") => {
            println!(
                "Usage: proton-security [--antivirus|--firewall|--account|--device-security|--health|--apps|--restore|--devices]\n       proton-security --tray | --scheduled-scan | --diagnose | --report [file.html] | --version"
            );
            std::process::exit(0)
        }
        _ => {}
    }
    if forward_to_running_instance(arg.as_deref()) {
        return Ok(());
    }
    let icon =
        eframe::icon_data::from_png_bytes(include_bytes!("../assets/proton-security.png")).ok();
    let mut viewport = egui::ViewportBuilder::default()
        .with_title(APP_NAME)
        .with_app_id("proton-security")
        .with_inner_size([1120.0, 700.0])
        .with_min_inner_size([800.0, 560.0]);
    if let Some(i) = icon {
        viewport = viewport.with_icon(i);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(APP_NAME, options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
