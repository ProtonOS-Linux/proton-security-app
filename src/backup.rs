// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Backup status of the user's personal files (read as the user).

use crate::sys;
use std::time::SystemTime;

/// A backup program or schedule found on this computer.
#[derive(Clone, Debug)]
pub struct BackupTool {
    /// Shown to the user: "Kup", "Déjà Dup", or a timer name.
    pub name: String,
    /// One line about it: "2 backup plan(s)", "Automatic backups on"…
    pub detail: String,
    /// When the last backup finished, if the tool records it.
    pub last: Option<SystemTime>,
    /// A real copy of your files. Snapshots on the same disk (Snapper,
    /// Timeshift) are listed but are not a backup: they are lost with the disk.
    pub counts: bool,
}

/// What the File backup tile and section show.
#[derive(Clone, Debug, Default)]
pub struct BackupState {
    /// Everything found, including same-disk snapshots that don't count (see
    /// [`BackupTool::counts`]).
    pub tools: Vec<BackupTool>,
    /// The user said they back up another way.
    pub other_way: bool,
    /// Kup is installed, so "Set up backup" opens it instead of installing it.
    pub kup_installed: bool,
}

/// A backup older than this turns the tile yellow.
pub const STALE_DAYS: f64 = 14.0;

impl BackupState {
    /// Backup tools that make a real copy of your files.
    pub fn backups(&self) -> impl Iterator<Item = &BackupTool> {
        self.tools.iter().filter(|t| t.counts)
    }
    /// True when at least one real backup tool was found.
    pub fn has_backup_tool(&self) -> bool {
        self.backups().next().is_some()
    }
    /// True when files are backed up: a real backup tool was found, or the user said they back
    /// up another way.
    pub fn configured(&self) -> bool {
        self.has_backup_tool() || self.other_way
    }
    /// Finish time of the newest backup any real tool recorded.
    pub fn last(&self) -> Option<SystemTime> {
        self.backups().filter_map(|t| t.last).max()
    }
    /// True when the newest known backup is older than [`STALE_DAYS`]. Tools that don't record
    /// a date never count as stale.
    pub fn stale(&self) -> bool {
        // Only judge when a date is known.
        self.last()
            .map(|t| sys::age_days(t) > STALE_DAYS)
            .unwrap_or(false)
    }
}

/// Parse the date formats backup tools write (RFC 3339, or ISO dates without a time zone, read
/// as local time).
fn parse_date(s: &str) -> Option<SystemTime> {
    use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
    let s = s.trim().trim_matches('\'').trim_matches('"');
    if let Ok(d) = DateTime::parse_from_rfc3339(s) {
        return Some(d.into());
    }
    for f in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(n) = NaiveDateTime::parse_from_str(s, f)
            && let Some(t) = Local.from_local_datetime(&n).earliest()
        {
            return Some(t.into());
        }
    }
    None
}

/// Kup (KDE's backup tool): reads `~/.config/kuprc`. Counts when at least one backup plan
/// exists and backups aren't switched off.
fn kup() -> Option<BackupTool> {
    let t = sys::read(sys::home().join(".config/kuprc"))?;
    let ini = crate::account::read_ini(&t);
    let plans: Vec<_> = ini.iter().filter(|(g, _)| g.starts_with("Plan/")).collect();
    if plans.is_empty() {
        return None;
    }
    if ini
        .get("Kup settings")
        .and_then(|s| s.get("Backups enabled"))
        .map(|v| v == "false")
        .unwrap_or(false)
    {
        return None;
    }
    let last = plans
        .iter()
        .filter_map(|(_, p)| p.get("Last complete backup").and_then(|v| parse_date(v)))
        .max();
    Some(BackupTool {
        name: "Kup".into(),
        detail: format!("{} backup plan(s)", plans.len()),
        last,
        counts: true,
    })
}

/// Déjà Dup (GNOME's backup tool): reads its settings with `gsettings`. Counts when it has
/// backed up at least once or has automatic backups on.
fn deja_dup() -> Option<BackupTool> {
    sys::which("deja-dup")?;
    let last = sys::run_out("gsettings", &["get", "org.gnome.DejaDup", "last-backup"])
        .and_then(|v| parse_date(&v));
    let periodic = sys::run_out("gsettings", &["get", "org.gnome.DejaDup", "periodic"])
        .map(|v| v.trim() == "true")
        .unwrap_or(false);
    (last.is_some() || periodic).then(|| BackupTool {
        name: "Déjà Dup".into(),
        detail: if periodic {
            "Automatic backups on".into()
        } else {
            "Manual backups".into()
        },
        last,
        counts: true,
    })
}

/// Pika Backup (Flatpak): counts when its configuration file exists.
fn pika() -> Option<BackupTool> {
    let cfg =
        sys::home().join(".var/app/org.gnome.World.PikaBackup/config/pika-backup/config.json");
    cfg.exists().then(|| BackupTool {
        name: "Pika Backup".into(),
        detail: "Configured".into(),
        last: None,
        counts: true,
    })
}

/// A Snapper configuration for /home. Listed, but snapshots on the same disk are not a backup.
fn snapper_home() -> Option<BackupTool> {
    let t = sys::read("/etc/default/snapper")?;
    t.lines()
        .find(|l| l.trim_start().starts_with("SNAPPER_CONFIGS="))
        .filter(|l| l.split(['=', '"', ' ']).any(|w| w == "home"))
        .map(|_| BackupTool {
            name: "Snapper (home folder)".into(),
            detail: "Restore points of your home folder on this disk. Not a backup: they are lost if the disk fails."
                .into(),
            last: None,
            counts: false,
        })
}

/// Timeshift set to include the home folder. Listed, but not counted as a backup.
fn timeshift_home() -> Option<BackupTool> {
    let t = sys::read("/etc/timeshift/timeshift.json")?;
    let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    compact
        .contains("\"include_btrfs_home_for_backup\":\"true\"")
        .then(|| BackupTool {
            name: "Timeshift".into(),
            detail: "Snapshots include your home folder. Not a backup if they are on this disk."
                .into(),
            last: None,
            counts: false,
        })
}

/// User systemd timers whose name suggests a backup (borg, restic, kopia…), for people who
/// script their own backups.
fn user_timers() -> Vec<BackupTool> {
    let out = sys::run_out(
        "systemctl",
        &["--user", "list-timers", "--all", "--no-legend", "--plain"],
    )
    .unwrap_or_default();
    out.lines()
        .filter_map(|l| l.split_whitespace().find(|t| t.ends_with(".timer")))
        .filter(|t| {
            let t = t.to_lowercase();
            [
                "backup",
                "borg",
                "restic",
                "kopia",
                "rsnapshot",
                "duplicity",
            ]
            .iter()
            .any(|k| t.contains(k))
        })
        .map(|t| BackupTool {
            name: t.trim_end_matches(".timer").into(),
            detail: "Scheduled backup".into(),
            last: None,
            counts: true,
        })
        .collect()
}

/// Look for every supported backup tool.
pub fn load() -> BackupState {
    let mut tools: Vec<BackupTool> = [kup(), deja_dup(), pika(), snapper_home(), timeshift_home()]
        .into_iter()
        .flatten()
        .collect();
    tools.extend(user_timers());
    BackupState {
        tools,
        other_way: crate::settings::load().backup_other_way,
        kup_installed: sys::which("kup-daemon").is_some() || sys::dpkg_installed("kup-backup"),
    }
}

/// Open the backup settings (Kup's page in System Settings).
pub fn open_settings() -> bool {
    for (cmd, args) in [
        ("kcmshell6", vec!["kcm_kup"]),
        ("systemsettings", vec!["kcm_kup"]),
        ("kcmshell5", vec!["kcm_kup"]),
    ] {
        if sys::spawn_detached(cmd, &args) {
            return true;
        }
    }
    false
}
