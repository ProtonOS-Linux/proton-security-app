// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Account protection: screen lock, automatic login, password and
//! administrator accounts. Everything is read as the normal user.

use crate::sys;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// KDE screen locker settings (`kscreenlockerrc`, group `[Daemon]`).
#[derive(Clone, Debug, Default)]
pub struct ScreenLock {
    /// Lock the screen automatically after `timeout_min` minutes without activity.
    pub autolock: bool,
    /// Minutes of inactivity before the screen locks.
    pub timeout_min: u32,
    /// Ask for the password when the computer wakes from sleep.
    pub lock_on_resume: bool,
}

/// Whether the account has a password, from `passwd -S`.
#[derive(Clone, Debug, PartialEq)]
pub enum PasswordStatus {
    /// A password is set.
    Set,
    /// No password: anyone can sign in or unlock the screen.
    NoPassword,
    /// Password login is disabled for this account.
    Locked,
    /// `passwd -S` printed something we don't recognize.
    Unknown,
}

/// Everything shown on the Account protection page.
#[derive(Clone, Debug, Default)]
pub struct AccountState {
    /// The signed-in user name.
    pub user: String,
    /// `None` when `passwd` couldn't be run.
    pub password: Option<PasswordStatus>,
    /// Screen lock settings.
    pub lock: ScreenLock,
    /// User that logs in automatically, and the file that says so.
    pub autologin: Option<(String, String)>,
    /// Members of the sudo / wheel / admin groups.
    pub admins: Vec<String>,
    /// True when the signed-in user is one of `admins`.
    pub is_admin: bool,
    /// Apps currently blocking sleep and screen locking: (app, reason).
    pub inhibitions: Vec<(String, String)>,
}

impl AccountState {
    /// True when the account has no password at all.
    pub fn no_password(&self) -> bool {
        self.password == Some(PasswordStatus::NoPassword)
    }
    /// The manual "Sleep and screen locking after inactivity" switch in the
    /// battery/power applet is off. (Video players and calls also pause
    /// screen locking while they play; those are normal and temporary.)
    pub fn manual_inhibition(&self) -> Option<&(String, String)> {
        self.inhibitions
            .iter()
            .find(|(app, reason)| is_manual(app, reason))
    }
}

/// True for the inhibition created by the switch in the battery/power applet. Plasma registers
/// it under its own name (plasmashell / PowerDevil) with a reason mentioning the applet; apps
/// such as video players use their own names.
fn is_manual(app: &str, reason: &str) -> bool {
    let a = app.to_lowercase();
    let r = reason.to_lowercase();
    a.contains("plasmashell")
        || a.contains("plasma workspace")
        || a.contains("powerdevil")
        || r.contains("battery applet")
        || r.contains("manually")
        || r.contains("power management applet")
}

/// Inhibitions held in KDE's power management (Plasma 5 and 6).
pub fn inhibitions() -> Vec<(String, String)> {
    #[cfg(debug_assertions)]
    if let Ok(mut v) = std::env::var("PROTON_SECURITY_FAKE_INHIBIT") {
        // A path: read the list from that file (so tests can change it live).
        if v.starts_with('/') {
            v = sys::read(&v).unwrap_or_default().trim().to_string();
        }
        return v
            .split(';')
            .filter_map(|p| p.split_once('|'))
            .map(|(a, r)| (a.to_string(), r.to_string()))
            .collect();
    }
    let out = sys::run_out(
        "busctl",
        &[
            "--user",
            "--json=short",
            "call",
            "org.kde.Solid.PowerManagement",
            "/org/kde/Solid/PowerManagement/PolicyAgent",
            "org.kde.Solid.PowerManagement.PolicyAgent",
            "ListInhibitions",
        ],
    );
    if let Some(o) = out {
        return parse_inhibitions_json(&o);
    }
    // Fallback: gdbus prints ([('app', 'reason'), ...],)
    sys::run_out(
        "gdbus",
        &[
            "call",
            "--session",
            "--dest",
            "org.kde.Solid.PowerManagement",
            "--object-path",
            "/org/kde/Solid/PowerManagement/PolicyAgent",
            "--method",
            "org.kde.Solid.PowerManagement.PolicyAgent.ListInhibitions",
        ],
    )
    .map(|o| parse_inhibitions_gdbus(&o))
    .unwrap_or_default()
}

/// Parse `busctl --json=short` output of `ListInhibitions` (D-Bus type `a(ss)`).
fn parse_inhibitions_json(text: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text.trim()) else {
        return vec![];
    };
    // {"type":"a(ss)","data":[[["app","reason"],...]]}
    let list = v["data"]
        .get(0)
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default();
    list.iter()
        .filter_map(|p| {
            Some((
                p.get(0)?.as_str()?.to_string(),
                p.get(1)?.as_str()?.to_string(),
            ))
        })
        .collect()
}

/// Parse `gdbus call` output of `ListInhibitions`: `([('app', 'reason'), ...],)`.
fn parse_inhibitions_gdbus(text: &str) -> Vec<(String, String)> {
    // Pull out the quoted strings and pair them up.
    let mut strs = vec![];
    let mut cur: Option<String> = None;
    let mut esc = false;
    for c in text.chars() {
        match (&mut cur, c) {
            (Some(s), _) if esc => {
                s.push(c);
                esc = false;
            }
            (Some(_), '\\') => esc = true,
            (Some(_), '\'') => strs.push(cur.take().unwrap()),
            (Some(s), _) => s.push(c),
            (None, '\'') => cur = Some(String::new()),
            _ => {}
        }
    }
    strs.chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| (c[0].clone(), c[1].clone()))
        .collect()
}

// ------------------------------------------------------------------ ini helpers

/// Read `[group] key=value` files (KDE config / SDDM style).
pub fn read_ini(text: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut group = String::new();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('#') || l.starts_with(';') || l.is_empty() {
            continue;
        }
        if l.starts_with('[') && l.ends_with(']') {
            group = l[1..l.len() - 1].to_string();
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            out.entry(group.clone())
                .or_default()
                .insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

/// Set keys in one group of an ini file, keeping everything else.
///
/// The group, keys and values may not contain line breaks (they would add lines of their own).
/// The file is written to a temporary name next to it and renamed, so a crash never leaves it
/// half-written; when `path` is a symbolic link (dotfiles kept elsewhere), the file it points
/// to is updated and the link stays.
pub fn write_ini_keys(path: &Path, group: &str, keys: &[(&str, &str)]) -> std::io::Result<()> {
    let has_break = |s: &str| s.contains(['\n', '\r']);
    if has_break(group) || keys.iter().any(|(k, v)| has_break(k) || has_break(v)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "settings can't contain line breaks",
        ));
    }
    let resolved;
    let path = if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        resolved = std::fs::canonicalize(path)?;
        resolved.as_path()
    } else {
        path
    };
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let header = format!("[{group}]");
    let start = lines.iter().position(|l| l.trim() == header);
    let start = match start {
        Some(i) => i,
        None => {
            if !lines.is_empty() && !lines.last().unwrap().is_empty() {
                lines.push(String::new());
            }
            lines.push(header.clone());
            lines.len() - 1
        }
    };
    let end = lines[start + 1..]
        .iter()
        .position(|l| l.trim_start().starts_with('['))
        .map(|p| start + 1 + p)
        .unwrap_or(lines.len());
    let mut insert_at = end;
    // Don't insert after trailing blank lines of the group.
    while insert_at > start + 1 && lines[insert_at - 1].trim().is_empty() {
        insert_at -= 1;
    }
    for (k, v) in keys {
        let found = (start + 1..end).find(|&i| {
            lines[i]
                .split_once('=')
                .map(|(a, _)| a.trim() == *k)
                .unwrap_or(false)
        });
        match found {
            Some(i) => lines[i] = format!("{k}={v}"),
            None => {
                lines.insert(insert_at, format!("{k}={v}"));
                insert_at += 1;
            }
        }
    }
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let mut out = lines.join("\n");
    out.push('\n');
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.proton-security-tmp"));
    let _ = std::fs::remove_file(&tmp);
    // Keep the file's permissions (a private config stays private).
    let mode = std::fs::metadata(path)
        .map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o777)
        .unwrap_or(0o644);
    let res = (|| {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(out.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// `$XDG_CONFIG_HOME`, normally `~/.config`.
fn config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| sys::home().join(".config"))
}

// ------------------------------------------------------------------ screen lock

/// The effective screen lock settings: KDE's defaults, then the system-wide file, then the
/// user's own file (later files win, as in KDE).
pub fn screen_lock() -> ScreenLock {
    // Defaults of KDE's screen locker.
    let mut s = ScreenLock {
        autolock: true,
        timeout_min: 5,
        lock_on_resume: true,
    };
    for f in [
        PathBuf::from("/etc/xdg/kscreenlockerrc"),
        config_home().join("kscreenlockerrc"),
    ] {
        let Some(t) = sys::read(&f) else { continue };
        let ini = read_ini(&t);
        if let Some(d) = ini.get("Daemon") {
            if let Some(v) = d.get("Autolock") {
                s.autolock = v != "false";
            }
            if let Some(v) = d.get("Timeout").and_then(|v| v.parse().ok()) {
                s.timeout_min = v;
            }
            if let Some(v) = d.get("LockOnResume") {
                s.lock_on_resume = v != "false";
            }
        }
    }
    s
}

/// Turn on the screen lock for this user (no administrator rights needed).
pub fn fix_screen_lock(max_minutes: u32) -> Result<(), String> {
    let current = screen_lock();
    let timeout = current.timeout_min.clamp(1, max_minutes.max(1)).to_string();
    write_ini_keys(
        &config_home().join("kscreenlockerrc"),
        "Daemon",
        &[
            ("Autolock", "true"),
            ("Timeout", &timeout),
            ("LockOnResume", "true"),
        ],
    )
    .map_err(|e| format!("Could not save the screen lock settings: {e}"))?;
    // Ask the running screen locker to reload its settings.
    let _ = sys::run_full(
        "dbus-send",
        &[
            "--session",
            "--type=method_call",
            "--dest=org.freedesktop.ScreenSaver",
            "/ScreenSaver",
            "org.kde.screensaver.configure",
        ],
    );
    Ok(())
}

// ------------------------------------------------------------------ autologin

/// SDDM's configuration files in the order SDDM reads them (later ones win).
fn sddm_files() -> Vec<PathBuf> {
    let mut v = vec![];
    for dir in ["/usr/lib/sddm/sddm.conf.d", "/etc/sddm.conf.d"] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
            files.sort();
            v.extend(files);
        }
    }
    v.push(PathBuf::from("/etc/sddm.conf"));
    v
}

/// The account that logs in without a password at startup, if any.
pub fn autologin() -> Option<(String, String)> {
    let mut found: Option<(String, String)> = None;
    // Later files override earlier ones, like SDDM does.
    for f in sddm_files() {
        let Some(t) = sys::read(&f) else { continue };
        if let Some(a) = read_ini(&t).get("Autologin")
            && let Some(u) = a.get("User")
        {
            found = (!u.is_empty()).then(|| (u.clone(), f.display().to_string()));
        }
    }
    if found.is_none()
        && let Some(t) = sys::read("/etc/lightdm/lightdm.conf")
    {
        for g in read_ini(&t).values() {
            if let Some(u) = g.get("autologin-user").filter(|u| !u.is_empty()) {
                found = Some((u.clone(), "/etc/lightdm/lightdm.conf".into()));
            }
        }
    }
    found
}

// ------------------------------------------------------------------ password & admins

/// The signed-in user name, from the real user ID this program runs as (the owner of
/// `/proc/self`), looked up in `/etc/passwd`, or with `id -un` for accounts that live elsewhere
/// (LDAP, a company directory). `$USER` is not used: any program can set it to another name.
pub fn current_user() -> String {
    let uid = crate::watchers::my_uid();
    if let Some(name) = sys::read("/etc/passwd").and_then(|t| user_name_for(&t, uid)) {
        return name;
    }
    sys::run_out("id", &["-un"])
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// The name of user `uid` in `/etc/passwd`-format text (`name:x:uid:gid:…`).
fn user_name_for(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        let id: u32 = f.nth(1)?.parse().ok()?;
        (id == uid && !name.is_empty()).then(|| name.to_string())
    })
}

/// Password status of `user` from `passwd -S` (allowed for your own account without
/// administrator rights).
pub fn password_status(user: &str) -> Option<PasswordStatus> {
    // `passwd -S` works for your own account without administrator rights.
    let out = sys::run_out("passwd", &["-S", user])?;
    let code = out.split_whitespace().nth(1)?;
    Some(match code {
        "P" | "PS" => PasswordStatus::Set,
        "NP" => PasswordStatus::NoPassword,
        "L" | "LK" => PasswordStatus::Locked,
        _ => PasswordStatus::Unknown,
    })
}

/// The last `passwd -S` answer: (user, modification time of /etc/shadow, status).
type PasswordCache = Option<(
    String,
    Option<std::time::SystemTime>,
    Option<PasswordStatus>,
)>;
/// See [`password_status_cached`].
static PASSWORD_CACHE: std::sync::Mutex<PasswordCache> = std::sync::Mutex::new(None);

/// [`password_status`], run again only when `/etc/shadow` changed (its date can be read without
/// administrator rights). The tray checks the account every 5 seconds; this saves starting
/// `passwd` each time.
fn password_status_cached(user: &str) -> Option<PasswordStatus> {
    let stamp = sys::mtime("/etc/shadow");
    let mut c = PASSWORD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((u, t, st)) = c.as_ref()
        && u == user
        && *t == stamp
        && stamp.is_some()
    {
        return st.clone();
    }
    let st = password_status(user);
    *c = Some((user.to_string(), stamp, st.clone()));
    st
}

/// Accounts that can become administrator: members of the `sudo`, `wheel` or `admin` groups in
/// /etc/group.
pub fn admins() -> Vec<String> {
    let groups = sys::read("/etc/group").unwrap_or_default();
    let mut v: Vec<String> = vec![];
    for l in groups.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() >= 4 && (f[0] == "sudo" || f[0] == "wheel" || f[0] == "admin") {
            for m in f[3].split(',').filter(|m| !m.is_empty()) {
                if !v.iter().any(|x| x == m) {
                    v.push(m.to_string());
                }
            }
        }
    }
    v
}

/// Read everything for the Account protection page (takes a few milliseconds; runs on a
/// background thread in the app).
pub fn load() -> AccountState {
    let user = current_user();
    let admins = admins();
    AccountState {
        password: password_status_cached(&user),
        lock: screen_lock(),
        autologin: autologin(),
        is_admin: admins.contains(&user),
        inhibitions: inhibitions(),
        admins,
        user,
    }
}

/// Account problems right now, joined: cheap enough to poll every few
/// seconds. Used to notice changes made outside the app, such as the
/// battery menu's "Sleep and screen locking" switch.
pub fn quick_fingerprint() -> String {
    problems(&load(), crate::policy::get().max_screen_lock_minutes).join("|")
}

/// Problems found, as short sentences (empty = all good).
pub fn problems(a: &AccountState, max_lock_minutes: u32) -> Vec<String> {
    let mut v = vec![];
    if a.no_password() {
        v.push("Your account has no password.".into());
    }
    if let Some((u, _)) = &a.autologin {
        v.push(format!(
            "The computer signs in to \"{u}\" automatically, without a password."
        ));
    }
    if !a.lock.autolock {
        v.push("The screen does not lock automatically.".into());
    } else if a.lock.timeout_min > max_lock_minutes {
        v.push(format!(
            "The screen locks after {} minutes (recommended: {max_lock_minutes} or less).",
            a.lock.timeout_min
        ));
    }
    if !a.lock.lock_on_resume {
        v.push("The screen does not lock when the computer wakes from sleep.".into());
    }
    if a.manual_inhibition().is_some() {
        v.push("Sleep and screen locking are turned off in the battery menu.".into());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_inhibitions() {
        let j = r#"{"type":"a(ss)","data":[[["plasmashell","The battery applet has enabled suppressing sleep and screen locking"],["Firefox","Playing video"]]]}"#;
        let v = parse_inhibitions_json(j);
        assert_eq!(v.len(), 2);
        assert!(is_manual(&v[0].0, &v[0].1));
        assert!(!is_manual(&v[1].0, &v[1].1));
        let g = "([('plasmashell', 'The battery applet has enabled suppressing sleep and screen locking'), ('VLC', 'Playing')],)";
        assert_eq!(
            parse_inhibitions_gdbus(g),
            v.iter()
                .take(1)
                .cloned()
                .chain([("VLC".into(), "Playing".into())])
                .collect::<Vec<_>>()
        );
        assert!(parse_inhibitions_json(r#"{"type":"a(ss)","data":[[]]}"#).is_empty());
    }

    #[test]
    fn user_from_passwd() {
        let t =
            "root:x:0:0:root:/root:/bin/bash\nana:x:1000:1000:Ana,,,:/home/ana:/bin/bash\nbroken\n";
        assert_eq!(user_name_for(t, 1000).as_deref(), Some("ana"));
        assert_eq!(user_name_for(t, 0).as_deref(), Some("root"));
        assert_eq!(user_name_for(t, 1001), None);
    }

    #[test]
    fn gdbus_escaped_quotes() {
        let g = r"([('Firefox', 'Playing \'Song\' video')],)";
        assert_eq!(
            parse_inhibitions_gdbus(g),
            vec![("Firefox".to_string(), "Playing 'Song' video".to_string())]
        );
    }

    #[test]
    fn ini_write_is_safe() {
        let dir = std::env::temp_dir().join(format!("ps-ini-safe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("dotfiles")).unwrap();
        // Line breaks would add settings of their own: refused, file untouched.
        let f = dir.join("rc");
        std::fs::write(&f, "[Daemon]\nTimeout=5\n").unwrap();
        assert!(write_ini_keys(&f, "Daemon", &[("Timeout", "5\nAutolock=false")]).is_err());
        assert_eq!(
            std::fs::read_to_string(&f).unwrap(),
            "[Daemon]\nTimeout=5\n"
        );
        // A symlinked config: the target is updated, the link stays a link.
        let target = dir.join("dotfiles/kscreenlockerrc");
        std::fs::write(&target, "[Daemon]\nTimeout=30\n").unwrap();
        let link = dir.join("kscreenlockerrc");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        write_ini_keys(&link, "Daemon", &[("Timeout", "10")]).unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            read_ini(&std::fs::read_to_string(&target).unwrap())["Daemon"]["Timeout"],
            "10"
        );
        // No temporary file is left behind.
        assert_eq!(std::fs::read_dir(dir.join("dotfiles")).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ini_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ps-ini-{}", std::process::id()));
        let f = dir.join("kscreenlockerrc");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &f,
            "[Greeter]\nTheme=x\n\n[Daemon]\nTimeout=30\n\n[Other]\nA=1\n",
        )
        .unwrap();
        write_ini_keys(&f, "Daemon", &[("Autolock", "true"), ("Timeout", "10")]).unwrap();
        let t = std::fs::read_to_string(&f).unwrap();
        let ini = read_ini(&t);
        assert_eq!(ini["Daemon"]["Timeout"], "10");
        assert_eq!(ini["Daemon"]["Autolock"], "true");
        assert_eq!(ini["Greeter"]["Theme"], "x");
        assert_eq!(ini["Other"]["A"], "1");
        write_ini_keys(&dir.join("new"), "Daemon", &[("Autolock", "true")]).unwrap();
        assert_eq!(
            read_ini(&std::fs::read_to_string(dir.join("new")).unwrap())["Daemon"]["Autolock"],
            "true"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
