// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Company policy: /etc/proton-security/policy.conf, written by an
//! administrator (root-owned, readable by everyone). It can force settings
//! on or off for every user and hide or lock features.
//!
//! Format: `key = value` lines, `#` comments. See packaging/policy.conf.example.

use crate::sys;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Where administrators put the policy. Only root can write it; everyone can read it.
pub const POLICY_PATH: &str = "/etc/proton-security/policy.conf";

/// A user setting that the policy can force.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Forced {
    /// User decides.
    No,
    /// Always on; the user can't turn it off.
    On,
    /// Always off; the user can't turn it on.
    Off,
}

/// Everything the policy file can set. Without a policy file every field has its default (see
/// the `Default` impl): users decide everything and nothing is required beyond the normal
/// checks.
#[derive(Clone, Debug)]
pub struct Policy {
    /// `daily_scan`: the daily automatic quick scan.
    pub daily_scan: Forced,
    /// `scan_downloads`: checking new files in Downloads.
    pub scan_downloads: Forced,
    /// `usb_alerts`: notifications for new USB keyboards, network adapters and drives.
    pub usb_alerts: Forced,
    /// `scan_usb`: scanning USB drives when they are opened.
    pub scan_usb: Forced,
    /// `allow_driver_changes = no` hides driver update / reinstall / uninstall in the device
    /// manager.
    pub allow_driver_changes: bool,
    /// `allow_firewall_changes = no` hides firewall on/off and allow/block buttons.
    pub allow_firewall_changes: bool,
    /// `allow_app_permission_changes = no` makes Flatpak permissions read-only.
    pub allow_app_permission_changes: bool,
    /// `require_disk_encryption = yes`: an unencrypted system drive turns Device security
    /// yellow.
    pub require_disk_encryption: bool,
    /// `require_secure_boot = yes`: Secure Boot off turns Device security yellow.
    pub require_secure_boot: bool,
    /// `require_backup = no`: a missing file backup no longer turns the File backup tile
    /// yellow.
    pub require_backup: bool,
    /// Longest allowed screen-lock delay, in minutes.
    pub max_screen_lock_minutes: u32,
    /// Pages to hide: antivirus, firewall, account, device-security,
    /// health, apps, restore, devices.
    pub hide_pages: Vec<String>,
    /// Shown in the app ("Managed by ...").
    pub organization: Option<String>,
    /// True when a policy file was found (the app then shows "Managed by …").
    pub loaded: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            daily_scan: Forced::No,
            scan_downloads: Forced::No,
            usb_alerts: Forced::No,
            scan_usb: Forced::No,
            allow_driver_changes: true,
            allow_firewall_changes: true,
            allow_app_permission_changes: true,
            require_disk_encryption: false,
            require_secure_boot: false,
            require_backup: true,
            max_screen_lock_minutes: 15,
            hide_pages: vec![],
            organization: None,
            loaded: false,
        }
    }
}

/// Accepts yes/no, true/false, on/off and 1/0, in any letter case.
fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// `force-on` / `force-off` (or simply on/off); anything else lets the user decide.
fn parse_forced(v: &str) -> Forced {
    match v.to_ascii_lowercase().as_str() {
        "force-on" | "on" | "true" | "yes" => Forced::On,
        "force-off" | "off" | "false" | "no" => Forced::Off,
        _ => Forced::No,
    }
}

/// Parse the policy text. Unknown keys and bad values are ignored, so a typo never breaks the
/// app; the setting simply keeps its default.
pub fn parse(text: &str) -> Policy {
    let mut kv: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        let l = line.split('#').next().unwrap_or("").trim();
        if let Some((k, v)) = l.split_once('=') {
            kv.insert(
                k.trim().to_ascii_lowercase(),
                v.trim().trim_matches('"').to_string(),
            );
        }
    }
    let mut p = Policy {
        loaded: true,
        ..Default::default()
    };
    let b = |k: &str, default: bool| kv.get(k).and_then(|v| parse_bool(v)).unwrap_or(default);
    if let Some(v) = kv.get("daily_scan") {
        p.daily_scan = parse_forced(v);
    }
    if let Some(v) = kv.get("scan_downloads") {
        p.scan_downloads = parse_forced(v);
    }
    if let Some(v) = kv.get("usb_alerts") {
        p.usb_alerts = parse_forced(v);
    }
    if let Some(v) = kv.get("scan_usb") {
        p.scan_usb = parse_forced(v);
    }
    p.allow_driver_changes = b("allow_driver_changes", true);
    p.allow_firewall_changes = b("allow_firewall_changes", true);
    p.allow_app_permission_changes = b("allow_app_permission_changes", true);
    p.require_disk_encryption = b("require_disk_encryption", false);
    p.require_secure_boot = b("require_secure_boot", false);
    p.require_backup = b("require_backup", true);
    if let Some(m) = kv
        .get("max_screen_lock_minutes")
        .and_then(|v| v.parse().ok())
    {
        p.max_screen_lock_minutes = m;
    }
    if let Some(h) = kv.get("hide_pages") {
        p.hide_pages = h
            .split([',', ' '])
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
    }
    p.organization = kv.get("organization").filter(|s| !s.is_empty()).cloned();
    p
}

/// The policy, read once per process.
pub fn get() -> &'static Policy {
    /// Parsed on first use; the file is not watched (restart the app or tray after changing
    /// it).
    static P: OnceLock<Policy> = OnceLock::new();
    P.get_or_init(|| {
        #[cfg(debug_assertions)]
        if let Ok(f) = std::env::var("PROTON_SECURITY_POLICY") {
            return parse(&sys::read(f).unwrap_or_default());
        }
        match sys::read(POLICY_PATH) {
            Some(t) => parse(&t),
            None => Policy::default(),
        }
    })
}

impl Policy {
    /// "Managed by Acme Corp", shown next to settings the policy locks.
    pub fn managed_text(&self) -> String {
        match &self.organization {
            Some(o) => format!("Managed by {o}"),
            None => "Managed by your organization".into(),
        }
    }
    /// True when the policy hides this page (`hide_pages = firewall, devices`).
    pub fn hidden(&self, page_key: &str) -> bool {
        self.hide_pages.iter().any(|p| p == page_key)
    }
}

/// Apply a forced value to a user setting.
pub fn effective(user_value: bool, forced: Forced) -> bool {
    match forced {
        Forced::No => user_value,
        Forced::On => true,
        Forced::Off => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_policy() {
        let p = parse(
            "# comment\norganization = Acme Corp\ndaily_scan = force-on\nusb_alerts=force-off\n\
             allow_driver_changes = no\nrequire_disk_encryption = yes\nmax_screen_lock_minutes = 10\n\
             hide_pages = devices, firewall\n",
        );
        assert_eq!(p.daily_scan, Forced::On);
        assert_eq!(p.usb_alerts, Forced::Off);
        assert_eq!(p.scan_downloads, Forced::No);
        assert!(!p.allow_driver_changes);
        assert!(p.require_disk_encryption);
        assert_eq!(p.max_screen_lock_minutes, 10);
        assert!(p.hidden("devices") && p.hidden("firewall") && !p.hidden("apps"));
        assert_eq!(p.managed_text(), "Managed by Acme Corp");
    }
}
