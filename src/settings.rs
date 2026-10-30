// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Per-user settings in ~/.config/proton-security/settings.json.

use crate::sys;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The user's own choices, saved as JSON. Every field has a default (see the `Default` impl),
/// so a missing or older settings file still loads. A company policy (see [`crate::policy`])
/// can override some of these.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Settings {
    /// Run a quick scan automatically once a day (done by the tray).
    pub daily_scan: bool,
    /// Unix time of the last scheduled scan attempt (finished or not).
    pub last_scheduled_scan: i64,
    /// Firewall rules added from the Firewall page (ufw's own rule file is
    /// only readable by root, so the app remembers what it added).
    pub fw_rules: Vec<crate::firewall::Rule>,
    /// Scan new files in Downloads (done by the tray).
    pub scan_downloads: bool,
    /// Notify when a new USB keyboard / network / storage device appears.
    pub usb_alerts: bool,
    /// Quick-scan USB drives and memory cards when they are opened (mounted).
    pub scan_usb: bool,
    /// The user said they back up their files another way.
    pub backup_other_way: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            daily_scan: true,
            last_scheduled_scan: 0,
            fw_rules: vec![],
            scan_downloads: true,
            usb_alerts: true,
            scan_usb: true,
            backup_other_way: false,
        }
    }
}

/// Where the settings file lives: `$XDG_CONFIG_HOME/proton-security/settings.json`, normally
/// `~/.config/proton-security/settings.json`.
pub fn path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| sys::home().join(".config"));
    base.join("proton-security/settings.json")
}

/// Read the settings. A missing or damaged file gives the defaults, never an error.
pub fn load() -> Settings {
    sys::read(path())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Write the settings. The file is written to a temporary name and then renamed, so the app and
/// the tray (two processes) never see a half-written file.
pub fn save(s: &Settings) {
    let p = path();
    if let Some(d) = p.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    if let Ok(t) = serde_json::to_string_pretty(s) {
        let tmp = p.with_extension("json.tmp");
        if std::fs::write(&tmp, t).is_ok() {
            let _ = std::fs::rename(tmp, p);
        }
    }
}

/// Load, change and save in one step, for example `settings::update(|s| s.daily_scan = false)`.
pub fn update(f: impl FnOnce(&mut Settings)) {
    let mut s = load();
    f(&mut s);
    save(&s);
}
