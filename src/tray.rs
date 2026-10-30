// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! System tray icon (StatusNotifierItem, shown in Plasma's system tray).
//!
//! Green shield with a check when everything is fine, yellow shield with an
//! exclamation mark when something needs attention. Also runs the daily
//! automatic quick scan.

use crate::checks::{self, Level};
use crate::policy::{self, Forced};
use crate::{antivirus, settings, sys, watchers};
use ksni::blocking::TrayMethods;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Run all checks at least this often, even when nothing seems to change.
const RECHECK_EVERY: Duration = Duration::from_secs(10 * 60);
/// Don't start the daily scan right at login.
const SCAN_DELAY_AFTER_LOGIN: Duration = Duration::from_secs(10 * 60);
/// The daily quick scan runs when the last scan is at least this old.
const SCAN_INTERVAL_SECS: i64 = 24 * 3600;

// ------------------------------------------------------------------ icons

/// Render an SVG to ARGB32 (network byte order) pixmaps for the tray.
pub fn render_icons(svg: &str) -> Vec<ksni::Icon> {
    let Ok(tree) = resvg::usvg::Tree::from_str(svg, &resvg::usvg::Options::default()) else {
        return vec![];
    };
    [16u32, 22, 24, 32, 48, 64]
        .iter()
        .filter_map(|&size| {
            let mut pm = resvg::tiny_skia::Pixmap::new(size, size)?;
            let s = size as f32 / tree.size().width();
            resvg::render(
                &tree,
                resvg::tiny_skia::Transform::from_scale(s, s),
                &mut pm.as_mut(),
            );
            let mut data = Vec::with_capacity((size * size * 4) as usize);
            for px in pm.pixels() {
                let c = px.demultiply();
                data.extend_from_slice(&[c.alpha(), c.red(), c.green(), c.blue()]);
            }
            Some(ksni::Icon {
                width: size as i32,
                height: size as i32,
                data,
            })
        })
        .collect()
}

// ------------------------------------------------------------------ tray

/// State of the tray icon. ksni reads it to draw the icon, tooltip and menu.
struct Tray {
    /// Result of the last full check; `None` until the first check finishes (grey icon).
    level: Option<Level>,
    /// Titles of the tiles that need attention, for the tooltip.
    problems: Vec<String>,
    /// The daily quick scan is running.
    scanning: bool,
    /// "Checking a download…" etc. while a background check runs.
    activity: Option<String>,
    /// Mirror of the daily-scan setting, for the menu checkmark.
    daily_scan: bool,
    /// Pre-rendered icons: green (OK), yellow (attention), grey (checking).
    icons: [Vec<ksni::Icon>; 3],
}

impl Tray {
    /// Which of `icons` to show.
    fn icon_index(&self) -> usize {
        match self.level {
            Some(Level::Ok) => 0,
            Some(Level::Warn) => 1,
            None => 2,
        }
    }
}

/// Open the main window (or bring it forward, see the single-instance code in `main.rs`).
fn open_app(args: &[&str]) {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("proton-security"));
    let _ = Command::new(exe).args(args).spawn();
}

impl ksni::Tray for Tray {
    /// StatusNotifierItem id; stays the same across versions so Plasma remembers the user's
    /// tray settings.
    fn id(&self) -> String {
        "proton-security".into()
    }
    /// Name Plasma shows in the system tray settings.
    fn title(&self) -> String {
        crate::APP_NAME.into()
    }
    /// Plasma groups the icon with system services.
    fn category(&self) -> ksni::Category {
        ksni::Category::SystemServices
    }
    /// `NeedsAttention` makes Plasma always show the icon (never hide it in the overflow) while
    /// something needs attention.
    fn status(&self) -> ksni::Status {
        match self.level {
            Some(Level::Warn) => ksni::Status::NeedsAttention,
            _ => ksni::Status::Active,
        }
    }
    /// Current icon.
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        self.icons[self.icon_index()].clone()
    }
    /// Icon Plasma uses for the `NeedsAttention` state.
    fn attention_icon_pixmap(&self) -> Vec<ksni::Icon> {
        self.icons[1].clone()
    }
    /// Tooltip: what the tray is doing right now, or a summary of the status.
    fn tool_tip(&self) -> ksni::ToolTip {
        let description = if let Some(a) = &self.activity {
            a.clone()
        } else if self.scanning {
            "Running the daily quick scan…".to_string()
        } else {
            match self.level {
                None => "Checking your device…".into(),
                Some(Level::Ok) => "Your device is protected.".into(),
                Some(Level::Warn) => format!("Needs attention: {}", self.problems.join(", ")),
            }
        };
        ksni::ToolTip {
            title: crate::APP_NAME.into(),
            description,
            icon_pixmap: self.icons[self.icon_index()].clone(),
            ..Default::default()
        }
    }
    /// Left click opens the main window.
    fn activate(&mut self, _x: i32, _y: i32) {
        open_app(&[]);
    }
    /// Right-click menu: status, shortcuts to pages, and the background protection switches
    /// (greyed out when the company policy forces them).
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;
        let pol = policy::get();
        let st = settings::load();
        let status = match self.level {
            None => "Checking…".to_string(),
            Some(Level::Ok) => "No action needed".to_string(),
            Some(Level::Warn) => format!("{} item(s) need attention", self.problems.len()),
        };
        vec![
            StandardItem {
                label: status,
                enabled: false,
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Open Proton Security".into(),
                icon_name: "security-high".into(),
                activate: Box::new(|_| open_app(&[])),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Virus & threat protection".into(),
                activate: Box::new(|_| open_app(&["--antivirus"])),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Restore points".into(),
                activate: Box::new(|_| open_app(&["--restore"])),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            CheckmarkItem {
                label: "Daily automatic quick scan".into(),
                checked: self.daily_scan,
                enabled: pol.daily_scan == Forced::No,
                activate: Box::new(|t: &mut Self| {
                    t.daily_scan = !t.daily_scan;
                    let on = t.daily_scan;
                    settings::update(|s| s.daily_scan = on);
                }),
                ..Default::default()
            }
            .into(),
            CheckmarkItem {
                label: "Scan new downloads".into(),
                checked: policy::effective(st.scan_downloads, pol.scan_downloads),
                enabled: pol.scan_downloads == Forced::No,
                activate: Box::new(|_| settings::update(|s| s.scan_downloads = !s.scan_downloads)),
                ..Default::default()
            }
            .into(),
            CheckmarkItem {
                label: "Scan USB drives when opened".into(),
                checked: policy::effective(st.scan_usb, pol.scan_usb),
                enabled: pol.scan_usb == Forced::No,
                activate: Box::new(|_| settings::update(|s| s.scan_usb = !s.scan_usb)),
                ..Default::default()
            }
            .into(),
            CheckmarkItem {
                label: "Alert me about new USB devices".into(),
                checked: policy::effective(st.usb_alerts, pol.usb_alerts),
                enabled: pol.usb_alerts == Forced::No,
                activate: Box::new(|_| settings::update(|s| s.usb_alerts = !s.usb_alerts)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

// ------------------------------------------------------------------ helpers

/// `$XDG_RUNTIME_DIR` (`/run/user/<uid>`, private to the user), where the lock and marker files
/// live.
fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

/// File the main window touches after it changes something, so the tray
/// re-checks right away.
pub fn status_marker() -> PathBuf {
    runtime_dir().join("proton-security.changed")
}

/// Tell the tray to re-check now (the window calls this after it changes something).
pub fn poke_tray() {
    let _ = std::fs::write(status_marker(), b"1");
}

/// Hold an exclusive lock for the life of the process. Returns None when
/// another instance holds it.
pub fn instance_lock(name: &str) -> Option<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(runtime_dir().join(name))
        .ok()?;
    f.try_lock().ok()?;
    Some(f)
}

/// Show a desktop notification. Tries `notify-send`, then the freedesktop D-Bus interface
/// directly, then `kdialog`. Debug builds can write notifications to a file instead
/// (`PROTON_SECURITY_NOTIFY_LOG`) for tests.
pub fn notify(summary: &str, body: &str) {
    #[cfg(debug_assertions)]
    if let Ok(f) = std::env::var("PROTON_SECURITY_NOTIFY_LOG") {
        use std::io::Write;
        if let Ok(mut fh) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(f)
        {
            let _ = writeln!(fh, "{summary} | {body}");
        }
        return;
    }
    let ok = sys::which("notify-send").is_some()
        && Command::new("notify-send")
            .args([
                "--app-name",
                crate::APP_NAME,
                "--icon",
                "proton-security",
                summary,
                body,
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    if ok {
        return;
    }
    // Plain D-Bus notification (works on Plasma without extra packages).
    let sent = sys::which("gdbus").is_some()
        && Command::new("gdbus")
            .args([
                "call",
                "--session",
                "--dest",
                "org.freedesktop.Notifications",
                "--object-path",
                "/org/freedesktop/Notifications",
                "--method",
                "org.freedesktop.Notifications.Notify",
                crate::APP_NAME,
                "0",
                "proton-security",
                summary,
                body,
                "[]",
                "{}",
                "15000",
            ])
            .stdout(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    if !sent && sys::which("kdialog").is_some() {
        let _ = Command::new("kdialog")
            .args(["--title", summary, "--passivepopup", body, "15"])
            .spawn();
    }
}

/// Current Unix time in seconds.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// True on battery power with less than 30% charge: the daily scan waits so it doesn't drain
/// the battery.
fn on_low_battery() -> bool {
    let Ok(rd) = std::fs::read_dir("/sys/class/power_supply") else {
        return false;
    };
    let mut on_ac = false;
    let mut low = false;
    for e in rd.flatten() {
        let p = e.path();
        match sys::read_trim(p.join("type")).as_deref() {
            Some("Mains") => on_ac |= sys::read_trim(p.join("online")).as_deref() == Some("1"),
            Some("Battery") if sys::read_trim(p.join("scope")).as_deref() != Some("Device") => {
                let cap: u32 = sys::read_trim(p.join("capacity"))
                    .and_then(|c| c.parse().ok())
                    .unwrap_or(100);
                low |= cap < 30;
            }
            _ => {}
        }
    }
    low && !on_ac
}

/// Is the daily automatic scan due?
pub fn scheduled_scan_due() -> bool {
    let s = settings::load();
    if !policy::effective(s.daily_scan, policy::get().daily_scan)
        || sys::which("clamscan").is_none()
    {
        return false;
    }
    let last_scan = antivirus::last_scan_time()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let last = last_scan.max(s.last_scheduled_scan);
    now() - last >= SCAN_INTERVAL_SECS
}

/// Overall level and the titles that need attention.
fn summarize(results: &[checks::CheckResult]) -> (Level, Vec<String>) {
    let problems: Vec<String> = results
        .iter()
        .filter(|r| r.level == Level::Warn)
        .map(|r| r.title.to_string())
        .collect();
    (
        if problems.is_empty() {
            Level::Ok
        } else {
            Level::Warn
        },
        problems,
    )
}

// ------------------------------------------------------------------ main loop

/// `proton-security --tray`: the background part of the app, started at login
/// (`/etc/xdg/autostart`). Runs as the user, never as root.
///
/// Every 5 seconds it:
/// - notifies about new USB devices;
/// - checks finished downloads and newly opened USB drives with ClamAV (on background threads);
/// - runs all checks again when something changed: the window asked (`poke_tray`), a scan was
///   recorded, or [`checks::fingerprint`] changed and has settled;
/// - starts the daily quick scan when it is due.
///
/// Returns the process exit code.
pub fn run() -> i32 {
    let Some(_lock) = instance_lock("proton-security-tray.lock") else {
        eprintln!("Proton Security tray is already running.");
        return 0;
    };
    let tray = Tray {
        level: None,
        problems: vec![],
        scanning: false,
        activity: None,
        daily_scan: settings::load().daily_scan,
        icons: [
            render_icons(&crate::ui::status_shield_svg(Some(Level::Ok))),
            render_icons(&crate::ui::status_shield_svg(Some(Level::Warn))),
            render_icons(&crate::ui::status_shield_svg(None)),
        ],
    };
    // The panel may start after us at login (or not at all). Protection
    // (download and USB checks, daily scan) runs either way; the icon is
    // registered whenever the panel becomes available.
    let handle = TrayIcon::new(tray);
    handle.try_register();

    let started = Instant::now();
    let mut last_check: Option<Instant> = None;
    let mark_mtime = |p: &PathBuf| sys::mtime(p);
    let history = sys::data_dir().join("scan-history.json");
    let mut seen_marker = mark_mtime(&status_marker());
    let mut seen_history = mark_mtime(&history);
    let scanning = Arc::new(AtomicBool::new(false));
    let mut last_due_check = Instant::now() - Duration::from_secs(3600);
    // What the last full check saw, and what the previous poll saw.
    let mut checked_fp = checks::fingerprint();
    let mut polled_fp = checked_fp.clone();

    let mut downloads = watchers::DownloadWatcher::new();
    let mut usb = watchers::UsbWatcher::new();
    let mut mounts = watchers::MountWatcher::new();
    let download_scan_busy = Arc::new(AtomicBool::new(false));

    loop {
        handle.retry_register();
        let st = settings::load();
        let pol = policy::get();

        // New USB keyboards / network adapters / drives.
        let alerts = usb.poll();
        if policy::effective(st.usb_alerts, pol.usb_alerts) {
            for a in alerts {
                let (title, body) = a.message();
                notify(&title, &body);
            }
        }

        // New files in Downloads.
        let ready = downloads.poll();
        if !ready.is_empty()
            && policy::effective(st.scan_downloads, pol.scan_downloads)
            && !download_scan_busy.swap(true, Ordering::SeqCst)
        {
            let (busy, h2) = (download_scan_busy.clone(), handle.clone());
            let what = if ready.len() == 1 {
                format!(
                    "Checking {} for viruses…",
                    watchers::file_name(&ready[0].to_string_lossy())
                )
            } else {
                format!("Checking {} downloads for viruses…", ready.len())
            };
            h2.update(|t: &mut Tray| t.activity = Some(what.clone()));
            std::thread::spawn(move || {
                check_downloads(&ready);
                h2.update(|t: &mut Tray| t.activity = None);
                busy.store(false, Ordering::SeqCst);
            });
        }

        // USB drives and memory cards opened in the file manager.
        let opened = mounts.poll();
        if !opened.is_empty() && policy::effective(st.scan_usb, pol.scan_usb) {
            for m in opened {
                let h2 = handle.clone();
                let label = watchers::drive_label(&m);
                h2.update(|t: &mut Tray| {
                    t.activity = Some(format!("Checking \"{label}\" for viruses…"))
                });
                std::thread::spawn(move || {
                    check_usb(&m);
                    h2.update(|t: &mut Tray| t.activity = None);
                });
            }
        }

        // Re-check when asked by the main window, after a scan, or every 10 min.
        let marker = mark_mtime(&status_marker());
        let hist = mark_mtime(&history);
        // Changes made outside the app (packages removed, firewall turned off,
        // screen locking blocked…). Wait until it stops changing for one poll,
        // so an apt run in progress is checked once, when it's done.
        let fp = checks::fingerprint();
        let settled_change = fp == polled_fp && fp != checked_fp;
        polled_fp = fp.clone();
        let changed = marker != seen_marker || hist != seen_history || settled_change;
        if changed
            || last_check
                .map(|t| t.elapsed() > RECHECK_EVERY)
                .unwrap_or(true)
        {
            seen_marker = marker;
            seen_history = hist;
            checked_fp = fp;
            let results = checks::run_all();
            let (level, problems) = summarize(&results);
            eprintln!("Status: {:?} {:?}", level, problems);
            let daily = settings::load().daily_scan;
            handle.update(|t: &mut Tray| {
                t.level = Some(level);
                t.problems = problems.clone();
                t.daily_scan = daily;
            });
            last_check = Some(Instant::now());
        }

        // Daily automatic quick scan.
        if started.elapsed() > SCAN_DELAY_AFTER_LOGIN
            && last_due_check.elapsed() > Duration::from_secs(300)
            && !scanning.load(Ordering::SeqCst)
        {
            last_due_check = Instant::now();
            if scheduled_scan_due() && !on_low_battery() {
                settings::update(|s| s.last_scheduled_scan = now());
                scanning.store(true, Ordering::SeqCst);
                handle.update(|t: &mut Tray| t.scanning = true);
                let (scanning, h2) = (scanning.clone(), handle.clone());
                std::thread::spawn(move || {
                    let exe = std::env::current_exe()
                        .unwrap_or_else(|_| PathBuf::from("proton-security"));
                    // Lowest CPU and disk priority so the scan doesn't slow the desktop.
                    let mut cmd = if sys::which("ionice").is_some() {
                        let mut c = Command::new("ionice");
                        c.args(["-c", "3", "nice", "-n", "19"]).arg(&exe);
                        c
                    } else {
                        let mut c = Command::new("nice");
                        c.args(["-n", "19"]).arg(&exe);
                        c
                    };
                    let _ = cmd.arg("--scheduled-scan").status();
                    scanning.store(false, Ordering::SeqCst);
                    h2.update(|t: &mut Tray| t.scanning = false);
                });
            }
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// The tray icon, if registered, plus its state (kept so it can be
/// registered later when the panel appears).
#[derive(Clone)]
struct TrayIcon {
    /// Current state, kept even while no icon is shown.
    state: Arc<Mutex<Tray>>,
    /// The registered icon, once Plasma's system tray accepted it.
    handle: Arc<Mutex<Option<ksni::blocking::Handle<Tray>>>>,
    /// When registration was last tried.
    last_try: Arc<Mutex<Instant>>,
}

impl TrayIcon {
    /// Wrap the tray state; the icon is registered separately.
    fn new(t: Tray) -> Self {
        Self {
            state: Arc::new(Mutex::new(t)),
            handle: Arc::new(Mutex::new(None)),
            last_try: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Try to show the icon (fails when Plasma's system tray isn't running yet).
    fn try_register(&self) {
        *self.last_try.lock().unwrap() = Instant::now();
        let t = self.state.lock().unwrap().clone_for_retry();
        match t.spawn() {
            Ok(h) => *self.handle.lock().unwrap() = Some(h),
            Err(e) => eprintln!("Tray icon not available yet: {e}"),
        }
    }

    /// Retry every 15 seconds until the icon is shown.
    fn retry_register(&self) {
        let missing = self.handle.lock().unwrap().is_none();
        if missing && self.last_try.lock().unwrap().elapsed() > Duration::from_secs(15) {
            self.try_register();
        }
    }

    /// Change the tray state; the icon, tooltip and menu update immediately if shown.
    fn update(&self, f: impl Fn(&mut Tray) + Send + Sync) {
        f(&mut self.state.lock().unwrap());
        if let Some(h) = self.handle.lock().unwrap().as_ref() {
            h.update(|t: &mut Tray| f(t));
        }
    }
}

/// Scan finished downloads and tell the user the result.
fn check_downloads(files: &[PathBuf]) {
    let out = watchers::scan_files(files);
    if let Some(why) = &out.failed {
        notify("Could not check your download", why);
        return;
    }
    let targets: Vec<String> = files
        .iter()
        .map(|f| f.to_string_lossy().into_owned())
        .collect();
    watchers::record_scan("Download check", targets, files.len() as u64, &out);
    if out.threats.is_empty() {
        let body = if files.len() == 1 {
            format!(
                "{} is safe. No threats found.",
                watchers::file_name(&files[0].to_string_lossy())
            )
        } else {
            format!("{} new files are safe. No threats found.", files.len())
        };
        notify("Download checked", &body);
    } else {
        let names: Vec<String> = out
            .threats
            .iter()
            .map(|t| watchers::file_name(&t.path))
            .collect();
        notify(
            "Threat found in a download",
            &format!(
                "{} is dangerous. Open Proton Security to quarantine or delete it.",
                names.join(", ")
            ),
        );
    }
    poke_tray();
}

/// Quick-scan a USB drive that was just opened.
fn check_usb(mount: &std::path::Path) {
    let label = watchers::drive_label(mount);
    // Let the file manager finish opening the drive first.
    std::thread::sleep(Duration::from_secs(2));
    let (files, truncated) = watchers::usb_files(mount);
    if files.is_empty() {
        notify(
            "USB drive checked",
            &format!("\"{label}\" has no files that need checking."),
        );
        return;
    }
    notify(
        "Checking USB drive",
        &format!("Checking \"{label}\" for viruses ({} files)…", files.len()),
    );
    let out = watchers::scan_files(&files);
    if let Some(why) = &out.failed {
        notify("Could not check the USB drive", why);
        return;
    }
    watchers::record_scan(
        "USB drive scan",
        vec![mount.to_string_lossy().into_owned()],
        files.len() as u64,
        &out,
    );
    if out.threats.is_empty() {
        notify(
            "USB drive checked",
            &format!(
                "\"{label}\" is safe. No threats found in {} files.{}",
                files.len(),
                if truncated {
                    " To check every file, run a full scan of the drive in Proton Security → Custom scan."
                } else {
                    ""
                }
            ),
        );
    } else {
        let names: Vec<String> = out
            .threats
            .iter()
            .take(3)
            .map(|t| watchers::file_name(&t.path))
            .collect();
        notify(
            "Threat found on USB drive",
            &format!(
                "{} dangerous file(s) on \"{label}\": {}. Don't open them. Open Proton Security to quarantine or delete them.",
                out.threats.len(),
                names.join(", ")
            ),
        );
    }
    poke_tray();
}

/// True when the tray (background protection) is running for this user.
pub fn tray_running() -> bool {
    instance_lock("proton-security-tray.lock").is_none()
}

/// Start the tray in the background, detached from the window (used by the "Start it" button).
pub fn start_tray() -> bool {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("proton-security"));
    let mut c = Command::new(exe);
    c.arg("--tray")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    {
        use std::os::unix::process::CommandExt;
        c.process_group(0);
    }
    c.spawn().is_ok()
}

impl Tray {
    /// Copy of the state for a new registration attempt (ksni takes ownership of it).
    fn clone_for_retry(&self) -> Tray {
        Tray {
            level: self.level,
            problems: self.problems.clone(),
            scanning: self.scanning,
            activity: self.activity.clone(),
            daily_scan: self.daily_scan,
            icons: self.icons.clone(),
        }
    }
}

/// `proton-security --scheduled-scan`: headless quick scan + notification.
pub fn scheduled_scan_main() -> i32 {
    let Some(_lock) = instance_lock("proton-security-scan.lock") else {
        return 0;
    };
    match antivirus::run_scheduled_scan_blocking() {
        Some(r) if !r.threats.is_empty() => {
            notify(
                "Threats found",
                &format!(
                    "The daily quick scan found {} threat(s). Open Proton Security to choose what to do.",
                    r.threats.len()
                ),
            );
            poke_tray();
            2
        }
        Some(_) => {
            poke_tray();
            0
        }
        None => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes the tray icons as PNG when PROTON_ICON_OUT is set (for review).
    #[test]
    fn icons_render() {
        for (name, lvl) in [
            ("ok", Some(Level::Ok)),
            ("warn", Some(Level::Warn)),
            ("checking", None),
        ] {
            let icons = render_icons(&crate::ui::status_shield_svg(lvl));
            assert_eq!(icons.len(), 6);
            let big = icons.last().unwrap();
            assert_eq!(big.data.len(), 64 * 64 * 4);
            if let Some(dir) = std::env::var_os("PROTON_ICON_OUT") {
                let mut pm = resvg::tiny_skia::Pixmap::new(64, 64).unwrap();
                for (i, px) in big.data.chunks_exact(4).enumerate() {
                    let (a, r, g, b) = (px[0], px[1], px[2], px[3]);
                    pm.pixels_mut()[i] =
                        resvg::tiny_skia::ColorU8::from_rgba(r, g, b, a).premultiply();
                }
                pm.save_png(std::path::Path::new(&dir).join(format!("tray-{name}.png")))
                    .unwrap();
            }
        }
    }
}
