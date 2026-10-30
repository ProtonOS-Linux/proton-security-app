// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! App permissions for Flatpak apps. Changes use per-user overrides
//! (`flatpak override --user`), so no administrator rights are needed.

use crate::sys;

/// The Flatpak permissions shown on the App permissions page. Each one groups the Flatpak
/// settings that give the same kind of access.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Perm {
    /// All files (host / host-os / host-etc)
    AllFiles,
    /// Your home folder
    Home,
    /// Camera, USB and other devices (devices=all)
    Devices,
    /// Sound and microphone (pulseaudio socket)
    Audio,
    /// Internet and network
    Network,
}

impl Perm {
    /// All permissions, in the order of the table columns.
    pub const ALL: [Perm; 5] = [
        Perm::AllFiles,
        Perm::Home,
        Perm::Devices,
        Perm::Audio,
        Perm::Network,
    ];
    /// Column heading shown to the user.
    pub fn label(self) -> &'static str {
        match self {
            Perm::AllFiles => "All files",
            Perm::Home => "Home folder",
            Perm::Devices => "Camera & devices",
            Perm::Audio => "Microphone & sound",
            Perm::Network => "Network",
        }
    }
    /// Permissions that let an app read your files or use your camera. Apps with one of these
    /// are listed first and mentioned in the report.
    pub fn risky(self) -> bool {
        matches!(self, Perm::AllFiles | Perm::Home | Perm::Devices)
    }
    /// `flatpak override` arguments to give (on=true) or take away the permission.
    pub fn override_args(self, on: bool) -> Vec<&'static str> {
        match (self, on) {
            (Perm::AllFiles, true) => vec!["--filesystem=host"],
            (Perm::AllFiles, false) => vec![
                "--nofilesystem=host",
                "--nofilesystem=host-os",
                "--nofilesystem=host-etc",
            ],
            (Perm::Home, true) => vec!["--filesystem=home"],
            (Perm::Home, false) => vec!["--nofilesystem=home", "--nofilesystem=~"],
            (Perm::Devices, true) => vec!["--device=all"],
            (Perm::Devices, false) => vec!["--nodevice=all"],
            (Perm::Audio, true) => vec!["--socket=pulseaudio"],
            (Perm::Audio, false) => vec!["--nosocket=pulseaudio"],
            (Perm::Network, true) => vec!["--share=network"],
            (Perm::Network, false) => vec!["--unshare=network"],
        }
    }
}

/// One installed Flatpak app and the permissions it has right now.
#[derive(Clone, Debug)]
pub struct AppPerms {
    /// Flatpak application ID, for example `org.mozilla.firefox`.
    pub id: String,
    /// The app's display name.
    pub name: String,
    /// Permissions it has after the user's overrides.
    pub perms: Vec<Perm>,
    /// The user changed this app's permissions.
    pub overridden: bool,
}

impl AppPerms {
    /// True when the app has this permission.
    pub fn has(&self, p: Perm) -> bool {
        self.perms.contains(&p)
    }
    /// True when the app has at least one [`Perm::risky`] permission.
    pub fn risky(&self) -> bool {
        self.perms.iter().any(|p| p.risky())
    }
}

/// Parse `flatpak info --show-permissions` output, then apply this user's
/// overrides (`flatpak override --user --show`), where "!name" removes.
#[cfg(test)]
pub fn parse_permissions(text: &str) -> Vec<Perm> {
    parse_with_overrides(text, "")
}

pub fn parse_with_overrides(text: &str, overrides: &str) -> Vec<Perm> {
    let mut v = base_permissions(text);
    let ini = crate::account::read_ini(overrides);
    let ctx = ini.get("Context").cloned().unwrap_or_default();
    for (key, val) in &ctx {
        for item in val.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            let (remove, name) = match item.strip_prefix('!') {
                Some(n) => (true, n),
                None => (false, item),
            };
            let name = name.split(':').next().unwrap_or(name);
            let perm = match (key.as_str(), name) {
                ("filesystems", "host" | "host-os" | "host-etc") => Some(Perm::AllFiles),
                ("filesystems", "home" | "~") => Some(Perm::Home),
                ("devices", "all") => Some(Perm::Devices),
                ("sockets", "pulseaudio") => Some(Perm::Audio),
                ("shared", "network") => Some(Perm::Network),
                _ => None,
            };
            if let Some(p) = perm {
                v.retain(|x| *x != p);
                if !remove {
                    v.push(p);
                }
            }
        }
    }
    // Keep a stable order.
    Perm::ALL.into_iter().filter(|p| v.contains(p)).collect()
}

fn base_permissions(text: &str) -> Vec<Perm> {
    let ini = crate::account::read_ini(text);
    let ctx = ini.get("Context").cloned().unwrap_or_default();
    let list = |k: &str| -> Vec<String> {
        ctx.get(k)
            .map(|v| {
                v.split(';')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };
    let fs = list("filesystems");
    let mut v = vec![];
    let granted = |name: &str| {
        fs.iter()
            .any(|f| f == name || f.starts_with(&format!("{name}:")))
    };
    if granted("host") || granted("host-os") || granted("host-etc") {
        v.push(Perm::AllFiles);
    }
    if granted("home") || granted("~") {
        v.push(Perm::Home);
    }
    if list("devices").iter().any(|d| d == "all") {
        v.push(Perm::Devices);
    }
    if list("sockets").iter().any(|s| s == "pulseaudio") {
        v.push(Perm::Audio);
    }
    if list("shared").iter().any(|s| s == "network") {
        v.push(Perm::Network);
    }
    v
}

pub fn load() -> Vec<AppPerms> {
    if sys::which("flatpak").is_none() {
        return vec![];
    }
    let list = sys::run_out("flatpak", &["list", "--app", "--columns=application,name"])
        .unwrap_or_default();
    let mut apps: Vec<AppPerms> = list
        .lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            let id = f.next()?.trim().to_string();
            if id.is_empty() || id == "Application ID" {
                return None;
            }
            let name = f
                .next()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| id.clone());
            let base =
                sys::run_out("flatpak", &["info", "--show-permissions", &id]).unwrap_or_default();
            let over =
                sys::run_out("flatpak", &["override", "--user", "--show", &id]).unwrap_or_default();
            let perms = parse_with_overrides(&base, &over);
            let overridden = over.lines().any(|l| l.contains('='));
            Some(AppPerms {
                id,
                name,
                perms,
                overridden,
            })
        })
        .collect();
    apps.sort_by(|a, b| {
        b.risky()
            .cmp(&a.risky())
            .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    apps.dedup_by(|a, b| a.id == b.id);
    apps
}

/// Give or take away one permission for this user.
pub fn set(app: &str, perm: Perm, on: bool) -> Result<(), String> {
    let mut args = vec!["override", "--user"];
    args.extend(perm.override_args(on));
    args.push(app);
    match sys::run_full("flatpak", &args) {
        Some((true, _, _)) => Ok(()),
        Some((false, o, e)) => Err(format!("{o}{e}").trim().to_string()),
        None => Err("Could not run flatpak.".into()),
    }
}

/// Undo all of this user's changes for an app.
pub fn reset(app: &str) -> Result<(), String> {
    match sys::run_full("flatpak", &["override", "--user", "--reset", app]) {
        Some((true, _, _)) => Ok(()),
        Some((false, o, e)) => Err(format!("{o}{e}").trim().to_string()),
        None => Err("Could not run flatpak.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_permissions() {
        let t = "[Context]\nshared=network;ipc;\nsockets=x11;wayland;pulseaudio;\ndevices=dri;all;\nfilesystems=xdg-download;home;\n\n[Session Bus Policy]\norg.freedesktop.Notifications=talk\n";
        let p = parse_permissions(t);
        assert_eq!(
            p,
            vec![Perm::Home, Perm::Devices, Perm::Audio, Perm::Network]
        );
        let h = parse_permissions("[Context]\nfilesystems=host:ro;\n");
        assert_eq!(h, vec![Perm::AllFiles]);
        assert!(parse_permissions("[Context]\nfilesystems=xdg-documents;\n").is_empty());
        let o = parse_with_overrides(t, "[Context]\nfilesystems=!home;\ndevices=!all;\n");
        assert_eq!(o, vec![Perm::Audio, Perm::Network]);
        let add = parse_with_overrides("[Context]\n", "[Context]\nfilesystems=host;\n");
        assert_eq!(add, vec![Perm::AllFiles]);
    }
}
