// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! The checks shown on "Security at a glance". All run without root.

use crate::antivirus;
use crate::sys;
use chrono::{Local, NaiveDateTime, TimeZone};
use std::io::Read;
use std::path::PathBuf;
use std::time::SystemTime;

/// Days without updates before we raise a warning.
pub const STALE_DAYS: f64 = 30.0;

/// Result of a check: the tile shows a green check or a yellow "!".
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Level {
    /// Nothing to do.
    Ok,
    /// Needs the user's attention; also turns the tray icon yellow.
    Warn,
}

/// Identifies each tile on "Security at a glance".
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum CheckId {
    /// Automatic security updates (unattended-upgrades).
    SecurityUpdates,
    /// Firewall & network protection.
    Firewall,
    /// Package & Flatpak updates.
    Updates,
    /// System restore (Snapper restore points).
    Snapper,
    /// Virus & threat protection (ClamAV).
    Antivirus,
    /// Account protection.
    Account,
    /// Device security.
    DeviceSecurity,
    /// Device performance & health.
    Health,
    /// File backup.
    Backup,
}

impl CheckId {
    /// Page key used by the company policy's `hide_pages`.
    pub fn policy_page(self) -> Option<&'static str> {
        match self {
            CheckId::Antivirus => Some("antivirus"),
            CheckId::Firewall => Some("firewall"),
            CheckId::Snapper | CheckId::Backup => Some("restore"),
            CheckId::Account => Some("account"),
            CheckId::DeviceSecurity => Some("device-security"),
            CheckId::Health => Some("health"),
            CheckId::SecurityUpdates | CheckId::Updates => None,
        }
    }
}

/// Fixes that run as the user (no password).
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Fix {
    /// Turn on the screen lock in the user's KDE settings.
    ScreenLock,
    /// Restart the computer (after the "save your work" confirmation).
    Restart,
    /// Open the backup tool's settings.
    BackupSettings,
    /// Remember that the user backs up their files another way.
    BackupOtherWay,
}

/// A button on a tile.
#[derive(Clone, Debug)]
pub enum Action {
    /// Run `proton-security-helper <args>` as root.
    Admin {
        /// Button text ("Turn on").
        label: String,
        /// Title of the progress window while it runs ("Turning on the firewall").
        title: String,
        /// Helper command and its arguments (`["enable-firewall"]`).
        args: Vec<String>,
    },
    /// Open one of the app's own pages.
    Open {
        /// Button text.
        label: String,
        /// The page to open.
        page: crate::Page,
    },
    /// Start a quick scan on the antivirus page.
    QuickScan,
    /// A fix that needs no administrator rights.
    Fix {
        /// Button text.
        label: String,
        /// What to do.
        fix: Fix,
    },
    /// Launch an external program.
    Launch {
        /// Button text.
        label: String,
        /// The program (a name found in `PATH`, such as `systemsettings`).
        cmd: String,
        /// Its arguments.
        args: Vec<String>,
    },
}

impl Action {
    /// Shortcut for an [`Action::Admin`] button.
    pub fn admin(label: &str, title: &str, args: &[&str]) -> Self {
        Action::Admin {
            label: label.into(),
            title: title.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }
    /// Button text.
    pub fn label(&self) -> String {
        match self {
            Action::Admin { label, .. }
            | Action::Open { label, .. }
            | Action::Launch { label, .. }
            | Action::Fix { label, .. } => label.clone(),
            Action::QuickScan => "Quick scan".into(),
        }
    }
}

/// The outcome of one check: everything a tile and the report show.
#[derive(Clone, Debug)]
pub struct CheckResult {
    /// Which check this is.
    pub id: CheckId,
    /// Tile title, for example "Firewall & network protection".
    pub title: &'static str,
    /// Green or yellow.
    pub level: Level,
    /// One sentence under the title: what is wrong, or that all is well.
    pub headline: String,
    /// Extra lines for the report and tooltips.
    pub details: Vec<String>,
    /// Buttons, most important first.
    pub actions: Vec<Action>,
    /// A highlighted "label: value" line shown first on the tile, value in
    /// green (true) or red (false).
    pub status_item: Option<(String, String, bool)>,
}

/// Services the tiles depend on.
const WATCHED_UNITS: [&str; 10] = [
    "unattended-upgrades.service",
    "apt-daily.timer",
    "apt-daily-upgrade.timer",
    "ufw.service",
    "firewalld.service",
    "nftables.service",
    "clamav-freshclam.service",
    "clamav-daemon.service",
    "snapper-timeline.timer",
    "snapper-cleanup.timer",
];

/// Cheap summary of everything the tiles depend on (a few file dates, two
/// systemctl calls and the account state). Polled every few seconds by the
/// tray and the window; when it changes, the full checks run again. This
/// catches changes made outside the app: removing ClamAV, `ufw disable`,
/// stopping unattended-upgrades, the battery menu's screen locking switch…
pub fn fingerprint() -> String {
    let home = sys::home();
    let files = [
        // Any package installed or removed.
        std::path::PathBuf::from("/var/lib/dpkg/status"),
        "/etc/ufw/ufw.conf".into(),
        "/etc/default/ufw".into(),
        "/etc/apt/apt.conf.d".into(),
        "/var/lib/clamav".into(),
        "/etc/default/snapper".into(),
        "/etc/snapper/configs".into(),
        "/run/reboot-required".into(),
        "/var/run/reboot-required".into(),
        "/boot".into(),
        "/etc/sddm.conf.d".into(),
        "/etc/timeshift/timeshift.json".into(),
        home.join(".config/kuprc"),
        home.join(".local/share/flatpak/overrides"),
        "/var/lib/flatpak/app".into(),
        crate::settings::path(),
    ];
    let mut fp = String::new();
    for f in &files {
        let t = sys::mtime(f)
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis())
            .unwrap_or(0);
        fp.push_str(&format!("{t};"));
    }
    for cmd in ["is-active", "is-enabled"] {
        let mut args = vec![cmd];
        args.extend(WATCHED_UNITS);
        // Exit code is non-zero when any unit is inactive: only the text matters.
        if let Some((_, out, _)) = sys::run_full("systemctl", &args) {
            fp.push_str(&out.split_whitespace().collect::<Vec<_>>().join(","));
        }
        fp.push(';');
    }
    fp.push_str(&crate::account::quick_fingerprint());
    fp
}

/// Run every check, in tile order. Pages hidden by the company policy are left out. Takes about
/// a second, so callers run it on a background thread.
pub fn run_all() -> Vec<CheckResult> {
    // Same order as the tiles on "Security at a glance".
    let all = vec![
        antivirus_check(),
        security_updates(),
        updates(),
        firewall(),
        account(),
        device_security(),
        health(),
        snapper(),
        backup(),
    ];
    let p = crate::policy::get();
    all.into_iter()
        .filter(|c| c.id.policy_page().map(|k| !p.hidden(k)).unwrap_or(true))
        .collect()
}

// ------------------------------------------------------------------ apt helpers

/// Values from `apt-config dump <key>` as (key, value) pairs.
fn apt_config(key: &str) -> Vec<(String, String)> {
    sys::run_out("apt-config", &["dump", key])
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(' ')?;
            Some((
                k.to_string(),
                v.trim().trim_end_matches(';').trim_matches('"').to_string(),
            ))
        })
        .collect()
}

/// True when an `APT::Periodic::…` setting is on (any value except empty or 0).
fn periodic_on(cfg: &[(String, String)], key: &str) -> bool {
    cfg.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| !v.is_empty() && v != "0")
        .unwrap_or(false)
}

/// The package sources unattended-upgrades is allowed to install from.
fn origin_patterns() -> Vec<String> {
    let mut v: Vec<String> = apt_config("Unattended-Upgrade::Origins-Pattern")
        .into_iter()
        .map(|(_, v)| v)
        .filter(|v| !v.is_empty())
        .collect();
    v.extend(
        apt_config("Unattended-Upgrade::Allowed-Origins")
            .into_iter()
            .map(|(_, v)| v)
            .filter(|v| !v.is_empty()),
    );
    v
}

/// How unattended-upgrades is set up.
struct UnattendedState {
    /// The unattended-upgrades package is installed.
    installed: bool,
    /// `APT::Periodic::Update-Package-Lists` is on.
    lists_daily: bool,
    /// `APT::Periodic::Unattended-Upgrade` is on.
    upgrade_daily: bool,
    /// apt's daily timers are active.
    timers: bool,
    /// Security updates are among the allowed sources.
    security_origin: bool,
    /// Regular (non-security) updates are allowed too, so all packages update automatically.
    regular_origin: bool,
}

impl UnattendedState {
    /// True when unattended-upgrades is installed, scheduled and its timers run.
    fn working(&self) -> bool {
        self.installed && self.lists_daily && self.upgrade_daily && self.timers
    }
}

/// Read unattended-upgrades' configuration (`apt-config dump`, timers).
fn unattended_state() -> UnattendedState {
    let periodic = apt_config("APT::Periodic");
    let origins = origin_patterns();
    UnattendedState {
        installed: sys::dpkg_installed("unattended-upgrades"),
        lists_daily: periodic_on(&periodic, "APT::Periodic::Update-Package-Lists"),
        upgrade_daily: periodic_on(&periodic, "APT::Periodic::Unattended-Upgrade"),
        timers: sys::systemctl_active("apt-daily.timer")
            && sys::systemctl_active("apt-daily-upgrade.timer"),
        security_origin: origins
            .iter()
            .any(|o| o.to_lowercase().contains("security")),
        regular_origin: origins
            .iter()
            .any(|o| !o.to_lowercase().contains("security")),
    }
}

// ------------------------------------------------------------------ 1. security updates

/// Tile "Automatic security updates". Green when the unattended-upgrades package is installed
/// and its service is active (the switch people use: `systemctl enable --now
/// unattended-upgrades`).
fn security_updates() -> CheckResult {
    let u = unattended_state();
    // The unattended-upgrades service is what users turn on and off
    // (systemctl enable/disable --now unattended-upgrades).
    let service_active = sys::systemctl_active("unattended-upgrades.service");
    let ok = u.installed && service_active;

    let mut details = vec![match last_package_change() {
        Some(t) => format!("Package last update: {}", sys::fmt_time(t)),
        None => "Package last update: no record".into(),
    }];
    if ok && !u.security_origin {
        details.push("Note: security sources are not in the allowed list.".into());
    }

    let headline = if ok {
        "Security updates install automatically."
    } else if !u.installed {
        "Automatic security updates are not installed."
    } else {
        "Automatic security updates are turned off."
    };
    let mut actions = vec![];
    if !ok {
        actions.push(Action::admin(
            "Turn on",
            "Turning on automatic security updates",
            &["enable-security-updates"],
        ));
    }
    let value = if !u.installed {
        "Not installed"
    } else if service_active {
        "Active"
    } else {
        "Not active"
    };
    CheckResult {
        id: CheckId::SecurityUpdates,
        title: "Automatic security updates",
        level: if ok { Level::Ok } else { Level::Warn },
        headline: headline.into(),
        details,
        actions,
        status_item: Some(("Unattended security updates".into(), value.into(), ok)),
    }
}

// ------------------------------------------------------------------ 2. firewall

/// Tile "Firewall & network protection". Green when UFW is enabled and its service runs, or
/// firewalld runs.
fn firewall() -> CheckResult {
    // What is installed and running. UFW counts as on only when all three agree: installed,
    // switched on in its config file (readable by everyone), and its service running.
    let ufw_installed = sys::which("ufw").is_some();
    let ufw_conf_on = sys::read("/etc/ufw/ufw.conf")
        .map(|s| {
            s.lines()
                .map(|l| l.trim().replace(' ', ""))
                .any(|l| l.eq_ignore_ascii_case("ENABLED=yes"))
        })
        .unwrap_or(false);
    let ufw_service = sys::systemctl_active("ufw.service");
    let firewalld = sys::systemctl_active("firewalld.service");
    let nft = sys::systemctl_active("nftables.service");

    // Either supported firewall being on is enough.
    let (ok, name) = if ufw_installed && ufw_conf_on && ufw_service {
        (true, "UFW")
    } else if firewalld {
        (true, "firewalld")
    } else {
        (false, "")
    };

    // Detail lines under the headline: which firewall is on, or why UFW isn't.
    let mut details = vec![];
    if ok {
        details.push(format!("Active firewall: {name}"));
        details.push("Incoming connections are filtered.".into());
    } else {
        details.push(format!(
            "UFW: {}",
            if !ufw_installed {
                "not installed"
            } else if ufw_conf_on {
                "enabled but service not running"
            } else {
                "disabled"
            }
        ));
        if nft {
            details.push("nftables service is running with custom rules.".into());
        }
    }

    // Buttons: "Turn on" only when needed (asks for the password), then a link to the page.
    let mut actions = vec![];
    if !ok {
        actions.push(Action::admin(
            "Turn on",
            "Turning on the firewall",
            &["enable-firewall"],
        ));
    }
    actions.push(Action::Open {
        label: "View connections".into(),
        page: crate::Page::Firewall,
    });
    CheckResult {
        id: CheckId::Firewall,
        title: "Firewall & network protection",
        level: if ok { Level::Ok } else { Level::Warn },
        headline: if ok {
            "Firewall is on.".into()
        } else {
            "Firewall is off. Your device may be exposed.".into()
        },
        details,
        actions,
        status_item: None,
    }
}

// ------------------------------------------------------------------ 3. apt + flatpak updates

/// Time of the most recent `apt` transaction that upgraded packages.
/// Most recent time any package was installed or upgraded (apt history and dpkg log).
pub fn last_package_change() -> Option<SystemTime> {
    let from_apt = last_apt_entry(&["Install:", "Upgrade:"]);
    let from_dpkg = sys::read("/var/log/dpkg.log").and_then(|t| {
        t.lines()
            .rev()
            .find(|l| {
                let mut f = l.split_whitespace().skip(2);
                matches!(f.next(), Some("install" | "upgrade"))
            })
            .and_then(|l| {
                let d: Vec<&str> = l.split_whitespace().take(2).collect();
                let nd = NaiveDateTime::parse_from_str(&d.join(" "), "%Y-%m-%d %H:%M:%S").ok()?;
                Local
                    .from_local_datetime(&nd)
                    .single()
                    .map(SystemTime::from)
            })
    });
    match (from_apt, from_dpkg) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

/// When packages were last upgraded with apt.
fn last_apt_upgrade() -> Option<SystemTime> {
    last_apt_entry(&["Upgrade:"])
}

/// Latest Start-Date of an apt history entry containing one of `kinds`.
fn last_apt_entry(kinds: &[&str]) -> Option<SystemTime> {
    let mut texts = vec![];
    if let Some(s) = sys::read("/var/log/apt/history.log") {
        texts.push(s);
    }
    if let Ok(f) = std::fs::File::open("/var/log/apt/history.log.1.gz") {
        let mut s = String::new();
        if flate2::read::GzDecoder::new(f)
            .read_to_string(&mut s)
            .is_ok()
        {
            texts.push(s);
        }
    }
    let mut best: Option<SystemTime> = None;
    for text in texts {
        for block in text.split("\n\n") {
            if !block
                .lines()
                .any(|l| kinds.iter().any(|k| l.starts_with(k)))
            {
                continue;
            }
            let Some(line) = block.lines().find(|l| l.starts_with("Start-Date:")) else {
                continue;
            };
            let d = line["Start-Date:".len()..]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if let Ok(nd) = NaiveDateTime::parse_from_str(&d, "%Y-%m-%d %H:%M:%S")
                && let Some(t) = Local.from_local_datetime(&nd).single()
            {
                let t: SystemTime = t.into();
                best = Some(best.map_or(t, |b| b.max(t)));
            }
        }
    }
    best
}

/// Number of package updates waiting (`apt list --upgradable`, uses the cached lists, no
/// download).
fn apt_pending() -> Option<usize> {
    let out = sys::run_out("apt", &["list", "--upgradable"])?;
    Some(
        out.lines()
            .filter(|l| l.contains("[upgradable from"))
            .count(),
    )
}

/// System-wide and per-user Flatpak installations.
fn flatpak_roots() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/var/lib/flatpak"),
        sys::home().join(".local/share/flatpak"),
    ]
}

/// (number of installed apps, time of the newest deployed app/runtime)
fn flatpak_state() -> (usize, Option<SystemTime>) {
    let mut apps = 0;
    let mut newest: Option<SystemTime> = None;
    for root in flatpak_roots() {
        for kind in ["app", "runtime"] {
            let Ok(ids) = std::fs::read_dir(root.join(kind)) else {
                continue;
            };
            for id in ids.flatten() {
                if kind == "app" {
                    apps += 1;
                }
                // <id>/<arch>/<branch>/active -> deploy dir
                let Ok(arches) = std::fs::read_dir(id.path()) else {
                    continue;
                };
                for arch in arches.flatten() {
                    let Ok(branches) = std::fs::read_dir(arch.path()) else {
                        continue;
                    };
                    for br in branches.flatten() {
                        if let Some(t) = sys::lmtime(br.path().join("active")) {
                            newest = Some(newest.map_or(t, |n| n.max(t)));
                        }
                    }
                }
            }
        }
    }
    (apps, newest)
}

/// True when Flatpak apps update automatically: an enabled flatpak update timer (system or
/// user), or Discover's "Apply updates automatically".
fn flatpak_auto() -> bool {
    let enabled_timer = |user: bool| {
        let mut args = vec![];
        if user {
            args.push("--user");
        }
        args.extend([
            "list-unit-files",
            "--type=timer",
            "--state=enabled",
            "--no-legend",
            "*flatpak*",
        ]);
        sys::run_out("systemctl", &args)
            .map(|s| s.lines().any(|l| !l.trim().is_empty()))
            .unwrap_or(false)
    };
    // KDE Discover's "Apply updates automatically"
    let discover = [
        sys::home().join(".config/PlasmaDiscoverUpdates"),
        PathBuf::from("/etc/xdg/PlasmaDiscoverUpdates"),
    ]
    .iter()
    .filter_map(sys::read)
    .any(|s| {
        s.lines().any(|l| {
            l.replace(' ', "")
                .eq_ignore_ascii_case("UseUnattendedUpdates=true")
        })
    });
    enabled_timer(false) || enabled_timer(true) || discover
}

/// Tile "Package & Flatpak updates". Yellow when package lists or Flatpak apps haven't been
/// refreshed in over [`STALE_DAYS`] days, or automatic updates are
/// off.
fn updates() -> CheckResult {
    // Gather what we know: automatic updates (unattended-upgrades must be working AND include
    // regular updates, not only security ones), when packages were last updated, when the
    // package lists were last refreshed, how many updates are waiting, and the same for Flatpak.
    let u = unattended_state();
    let apt_auto = u.working() && u.regular_origin;
    let last_upgrade = last_apt_upgrade();
    let lists = sys::mtime("/var/lib/apt/periodic/update-success-stamp")
        .or_else(|| sys::mtime("/var/lib/apt/lists"));
    let pending = apt_pending();

    let has_flatpak = sys::which("flatpak").is_some();
    let (fp_apps, fp_newest) = if has_flatpak {
        flatpak_state()
    } else {
        (0, None)
    };
    let fp_auto = has_flatpak && flatpak_auto();

    let mut problems = vec![];
    let mut details = vec![];

    // Packages (apt)
    let lists_stale = lists.map(|t| sys::age_days(t) > STALE_DAYS).unwrap_or(true);
    let upgrade_stale = last_upgrade
        .map(|t| sys::age_days(t) > STALE_DAYS)
        .unwrap_or(true);
    let pend = pending.unwrap_or(0);
    details.push(match last_upgrade {
        Some(t) => format!("Packages last updated: {}", sys::fmt_ago(t)),
        None => "Packages last updated: no record".into(),
    });
    if pend > 0 {
        details.push(format!("{pend} package update(s) available"));
    }
    if lists_stale {
        problems.push("Package lists have not been refreshed in over a month.");
    } else if upgrade_stale && pend > 0 {
        problems.push("Packages have not been updated in over a month.");
    }
    if !apt_auto {
        problems.push("Automatic package updates are off.");
    }

    // Flatpak
    if has_flatpak && fp_apps > 0 {
        details.push(match fp_newest {
            Some(t) => format!("Flatpak apps last updated: {}", sys::fmt_ago(t)),
            None => "Flatpak apps last updated: unknown".into(),
        });
        if fp_newest
            .map(|t| sys::age_days(t) > STALE_DAYS)
            .unwrap_or(true)
        {
            problems.push("Flatpak apps have not been updated in over a month.");
        }
        if !fp_auto {
            problems.push("Automatic Flatpak updates are off.");
        }
    }
    details.push(format!(
        "Automatic: packages {}{}",
        if apt_auto { "on" } else { "off" },
        if has_flatpak && fp_apps > 0 {
            format!(", Flatpak {}", if fp_auto { "on" } else { "off" })
        } else {
            String::new()
        }
    ));

    // The first problem found becomes the headline; buttons offer to turn on automatic
    // updates (only when off) and to update now.
    let ok = problems.is_empty();
    let mut actions = vec![];
    if !apt_auto || (has_flatpak && fp_apps > 0 && !fp_auto) {
        actions.push(Action::admin(
            "Turn on automatic updates",
            "Turning on automatic package and Flatpak updates",
            &["enable-auto-updates"],
        ));
    }
    actions.push(Action::admin(
        "Update now",
        "Updating packages and Flatpak apps",
        &["update-now"],
    ));

    CheckResult {
        id: CheckId::Updates,
        title: "Package & Flatpak updates",
        level: if ok { Level::Ok } else { Level::Warn },
        headline: if ok {
            "Your apps and packages are up to date.".into()
        } else {
            problems[0].to_string()
        },
        details,
        actions,
        status_item: None,
    }
}

// ------------------------------------------------------------------ 4. snapper

/// A restore point this recent counts as "working", even if we could not
/// identify the schedule (covers weekly schedules with a day of slack).
const RESTORE_RECENT_DAYS: f64 = 8.0;

/// Tile "System restore". Green when `/` is Btrfs, Snapper is installed and configured, and
/// restore points are made automatically (a schedule exists, or one was made in the last
/// [`RESTORE_RECENT_DAYS`] days).
fn snapper() -> CheckResult {
    // Green needs every link of the chain: a Btrfs system drive, Snapper installed and set up,
    // and restore points made automatically (a schedule, or a recent restore point as proof).
    let st = crate::restore::load();
    let schedules = st.effective_schedules();
    let scheduled = !schedules.is_empty();
    let recent = st.has_recent(RESTORE_RECENT_DAYS);
    let ok = st.btrfs() && st.installed && st.configured() && (scheduled || recent);

    // Detail lines: the drive's filesystem, the schedule(s), and the newest restore point.
    // Without administrator rights the list of restore points may be unreadable; then the
    // "last restore point" line is left out instead of claiming there is none.
    let mut details = vec![format!(
        "System drive: {}",
        if st.btrfs() {
            "Btrfs (supported)".to_string()
        } else if st.root_fs.is_empty() {
            "unknown".into()
        } else {
            format!("{} (not supported)", st.root_fs)
        }
    )];
    if st.installed && st.btrfs() {
        if scheduled {
            for s in schedules.iter().take(2) {
                details.push(format!("Schedule: {}", s.when));
            }
        } else {
            details.push("Schedule: none found".into());
        }
        match st.latest().and_then(|s| s.time()) {
            Some(t) => details.push(format!("Last restore point: {}", sys::fmt_ago(t))),
            None if st.needs_admin => {}
            None => details.push("Last restore point: none".into()),
        }
    } else if !st.installed {
        details.push("Snapper: not installed".into());
    }

    // The headline names the first missing link of the chain.
    let headline = if ok {
        "Restore points are being created automatically."
    } else if !st.btrfs() {
        "System drive does not support restore points."
    } else if !st.installed {
        "Snapper is not installed."
    } else if !st.configured() {
        "System restore is not set up."
    } else {
        "Automatic restore points are turned off."
    };

    // "Turn on" only makes sense on Btrfs; other filesystems can't have restore points.
    let mut actions = vec![];
    if !ok && st.btrfs() {
        actions.push(Action::admin(
            "Turn on",
            "Turning on system restore points",
            &["enable-snapper"],
        ));
    }
    actions.push(Action::Open {
        label: "View restore points".into(),
        page: crate::Page::Restore,
    });

    CheckResult {
        id: CheckId::Snapper,
        title: "System restore",
        level: if ok { Level::Ok } else { Level::Warn },
        headline: headline.into(),
        details,
        actions,
        status_item: None,
    }
}

// ------------------------------------------------------------------ 5. antivirus

/// No completed virus scan for this many days turns the antivirus tile yellow.
pub const SCAN_STALE_DAYS: f64 = 14.0;
/// Virus definitions older than this turn the antivirus tile yellow.
pub const DEFS_STALE_DAYS: f64 = 7.0;

/// Tile "Virus & threat protection". Green when ClamAV is installed, its definitions update
/// automatically and are recent, a scan finished in the last [`SCAN_STALE_DAYS`] days, and no
/// threat is waiting for a decision.
fn antivirus_check() -> CheckResult {
    // ClamAV's state, the scan history, the newest scan that really ran, and threats that are
    // still waiting for the user to choose quarantine, delete or allow.
    let info = antivirus::clam_info();
    let history = antivirus::load_history();
    let last = antivirus::last_completed_scan(&history).cloned();
    let open_threats: usize = history.iter().map(|r| r.open_threats()).sum();

    let mut details = vec![];
    let mut actions = vec![];
    let headline: String;
    let ok;

    if !info.installed {
        ok = false;
        headline = "No antivirus is installed.".into();
        details.push("ClamAV is not installed.".into());
        actions.push(Action::admin(
            "Install ClamAV",
            "Installing ClamAV antivirus",
            &["install-clamav"],
        ));
    } else {
        // Missing dates count as stale: better a yellow tile than a false green.
        let defs_stale = info
            .db_date
            .map(|t| sys::age_days(t) > DEFS_STALE_DAYS)
            .unwrap_or(true);
        let scan_stale = last
            .as_ref()
            .map(|r| sys::age_days(r.finished_time()) > SCAN_STALE_DAYS)
            .unwrap_or(true);

        details.push(format!(
            "Automatic definition updates: {}",
            if info.auto_update() { "on" } else { "off" }
        ));
        details.push(match info.db_date {
            Some(t) => format!("Definitions updated {}", sys::fmt_ago(t)),
            None => "Definitions: unknown".into(),
        });
        details.push(match &last {
            Some(r) => format!(
                "Last scan: {} ({}, {} threats)",
                sys::fmt_ago(r.finished_time()),
                r.kind.to_lowercase(),
                r.threats.len()
            ),
            None => "Last scan: never".into(),
        });

        // Green only when all four hold. The headline names the most urgent problem: open threats
        // first, then updates switched off, old definitions, no scan ever, an old scan.
        ok = info.auto_update() && !defs_stale && !scan_stale && open_threats == 0;
        // One fix button matching the headline, plus "Quick scan" which always helps.
        headline = if open_threats > 0 {
            format!("{open_threats} threat(s) need your attention.")
        } else if !info.auto_update() {
            "Virus definition updates are turned off.".into()
        } else if defs_stale {
            "Virus definitions are out of date.".into()
        } else if last.is_none() {
            "No scan has been run yet.".into()
        } else if scan_stale {
            "It has been a while since the last scan.".into()
        } else {
            "No current threats.".into()
        };

        if open_threats > 0 {
            actions.push(Action::Open {
                label: "See threats".into(),
                page: crate::Page::Antivirus,
            });
        } else if !info.auto_update() {
            actions.push(Action::admin(
                "Turn on",
                "Turning on automatic definition updates",
                &["av-auto", "on"],
            ));
        } else if defs_stale {
            actions.push(Action::admin(
                "Update definitions",
                "Updating virus definitions",
                &["av-update"],
            ));
        }
        actions.push(Action::QuickScan);
    }

    CheckResult {
        id: CheckId::Antivirus,
        title: "Virus & threat protection",
        level: if ok { Level::Ok } else { Level::Warn },
        headline,
        details,
        actions,
        status_item: None,
    }
}

// ------------------------------------------------------------------ 6. account protection

/// Tile "Account protection": the problems from [`crate::account::problems`] (password,
/// automatic sign-in, screen lock, the battery menu's screen locking switch). Being an
/// administrator is information only and never turns it yellow.
fn account() -> CheckResult {
    // The company policy may set a shorter screen lock limit than the default 15 minutes.
    let pol = crate::policy::get();
    let a = crate::account::load();
    let problems = crate::account::problems(&a, pol.max_screen_lock_minutes);
    let ok = problems.is_empty();
    let lock_text = if !a.lock.autolock {
        "Off".to_string()
    } else {
        format!("After {} min", a.lock.timeout_min)
    };
    let mut details = vec![format!("Screen lock: {lock_text}")];
    details.push(format!(
        "Automatic sign-in: {}",
        if a.autologin.is_some() { "On" } else { "Off" }
    ));
    // Buttons in the same order as the problems, so the first matches the headline.
    let mut actions = vec![];
    if a.no_password() {
        actions.push(Action::Launch {
            label: "Set a password".into(),
            cmd: "kcmshell6".into(),
            args: vec!["kcm_users".into()],
        });
    }
    if a.autologin.is_some() {
        actions.push(Action::admin(
            "Turn off automatic sign-in",
            "Turning off automatic sign-in",
            &["disable-autologin"],
        ));
    }
    if !a.lock.autolock
        || a.lock.timeout_min > pol.max_screen_lock_minutes
        || !a.lock.lock_on_resume
    {
        actions.push(Action::Fix {
            label: "Turn on screen lock".into(),
            fix: Fix::ScreenLock,
        });
    }
    actions.push(Action::Open {
        label: "Account settings".into(),
        page: crate::Page::Account,
    });
    CheckResult {
        id: CheckId::Account,
        title: "Account protection",
        level: if ok { Level::Ok } else { Level::Warn },
        headline: if ok {
            "Your account is protected.".into()
        } else {
            problems[0].clone()
        },
        details,
        actions,
        status_item: None,
    }
}

// ------------------------------------------------------------------ 7. device security

/// Tile "Device security". Information only (Secure Boot, encryption, TPM), unless the company
/// policy requires disk encryption or Secure Boot.
fn device_security() -> CheckResult {
    let pol = crate::policy::get();
    let d = crate::devsec::load();
    let enc = d.root_encrypted().unwrap_or(false);
    let mut problems = vec![];
    if pol.require_disk_encryption && !d.all_encrypted() {
        problems.push("Your organization requires disk encryption.");
    }
    if pol.require_secure_boot && d.secure_boot != Some(true) {
        problems.push("Your organization requires Secure Boot.");
    }
    let ok = problems.is_empty();
    let sb = match (d.uefi, d.secure_boot) {
        (false, _) => "Not supported (legacy BIOS)",
        (true, Some(true)) => "On",
        (true, Some(false)) => "Off",
        (true, None) => "Unknown",
    };
    let details = vec![
        format!("Secure Boot: {sb}"),
        format!("Disk encryption: {}", if enc { "On" } else { "Off" }),
        format!(
            "Security chip (TPM): {}",
            d.tpm.clone().unwrap_or_else(|| "Not found".into())
        ),
    ];
    CheckResult {
        id: CheckId::DeviceSecurity,
        title: "Device security",
        level: if ok { Level::Ok } else { Level::Warn },
        headline: if !ok {
            problems[0].to_string()
        } else if d.secure_boot == Some(true) && enc {
            "Your device meets the requirements for enhanced security.".into()
        } else {
            "Standard security is in place.".into()
        },
        details,
        actions: vec![Action::Open {
            label: "Details".into(),
            page: crate::Page::DeviceSecurity,
        }],
        status_item: None,
    }
}

// ------------------------------------------------------------------ 8. performance & health

/// Tile "Device performance & health": failing disk, low disk space, restart recommended, worn
/// battery (most serious first).
fn health() -> CheckResult {
    // Problems in order of seriousness; the most serious one becomes the headline.
    let h = crate::health::load();
    let low = h.low_disks();
    let failing = h.failing_drives();
    let mut actions = vec![];
    let headline = if !failing.is_empty() {
        format!(
            "Disk \"{}\" may fail soon. Back up your files now.",
            failing[0].model
        )
    } else if !low.is_empty() {
        format!(
            "Low disk space: {} free on {}.",
            sys::fmt_bytes(low[0].free),
            low[0].mount
        )
    // Buttons for the problems found, then always "Details".
    } else if h.restart.required {
        h.restart.headline()
    } else if let Some(b) = h.worn_battery() {
        format!(
            "Battery health is low ({:.0}%).",
            b.health_percent.unwrap_or(0.0)
        )
    } else {
        "No issues.".into()
    };
    // Green only with none of the four problems.
    let ok =
        failing.is_empty() && low.is_empty() && !h.restart.required && h.worn_battery().is_none();
    if h.restart.required {
        actions.push(Action::Fix {
            label: "Restart now".into(),
            fix: Fix::Restart,
        });
    }
    if !low.is_empty() {
        actions.push(Action::Open {
            label: "Free up space".into(),
            page: crate::Page::Health,
        });
    }
    actions.push(Action::Open {
        label: "Details".into(),
        page: crate::Page::Health,
    });
    // Detail lines: free space on the system drive, disk health, restart needed.
    let mut details = vec![];
    if let Some(root) = h.disks.iter().find(|d| d.mount == "/") {
        details.push(format!(
            "Storage: {} free of {}",
            sys::fmt_bytes(root.free),
            sys::fmt_bytes(root.size)
        ));
    }
    details.push(format!(
        "Disk health: {}",
        if h.smart_unavailable {
            "unknown".into()
        } else if failing.is_empty() {
            "OK".to_string()
        } else {
            "problem found".into()
        }
    ));
    details.push(format!(
        "Restart needed: {}",
        if h.restart.required { "Yes" } else { "No" }
    ));
    CheckResult {
        id: CheckId::Health,
        title: "Device performance & health",
        level: if ok { Level::Ok } else { Level::Warn },
        headline,
        details,
        actions,
        status_item: None,
    }
}

// ------------------------------------------------------------------ 9. backup

/// Tile "File backup". Green when a real backup tool is set up (or the user says they back up
/// another way) and the last known backup isn't older than [`crate::backup::STALE_DAYS`].
fn backup() -> CheckResult {
    // Without a backup the tile is yellow by default; a company policy can switch the
    // requirement off (`require_backup = no`), then it stays green either way.
    let pol = crate::policy::get();
    let b = crate::backup::load();
    let ok = (b.configured() && !b.stale()) || !pol.require_backup;
    let headline = if b.stale() {
        format!(
            "Your last backup was {}.",
            b.last().map(sys::fmt_ago).unwrap_or_default()
        )
    } else if b.configured() {
        "Your personal files are backed up.".into()
    } else {
        "Your personal files are not backed up.".into()
    };
    // Detail lines: "another way" if the user said so, and up to two backup tools with their
    // last backup.
    let mut details = vec![];
    if b.other_way && !b.has_backup_tool() {
        details.push("You back up another way.".into());
    }
    for t in b.backups().take(2) {
        details.push(match t.last {
            Some(l) => format!("{}: last backup {}", t.name, sys::fmt_ago(l)),
            None => format!("{}: {}", t.name, t.detail),
        });
    }
    // Without a (recent) backup: set up Kup (installing it first if needed), and let the user
    // say they back up another way (which turns the tile green, see `settings.rs`).
    let mut actions = vec![];
    if !b.configured() || b.stale() {
        if b.kup_installed {
            actions.push(Action::Fix {
                label: "Set up backup".into(),
                fix: Fix::BackupSettings,
            });
        } else {
            actions.push(Action::admin(
                "Set up backup",
                "Installing Kup backup",
                &["install-kup"],
            ));
        }
        if !b.configured() {
            actions.push(Action::Fix {
                label: "I back up another way".into(),
                fix: Fix::BackupOtherWay,
            });
        }
    }
    CheckResult {
        id: CheckId::Backup,
        title: "File backup",
        level: if ok { Level::Ok } else { Level::Warn },
        headline,
        details,
        actions,
        status_item: None,
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    #[test]
    fn fingerprint_is_cheap_and_stable() {
        let t = std::time::Instant::now();
        let a = fingerprint();
        let b = fingerprint();
        eprintln!("fingerprint x2: {:?}", t.elapsed());
        assert_eq!(a, b);
    }
}
