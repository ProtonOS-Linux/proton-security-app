// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Small helpers for talking to the operating system without root.

use chrono::{DateTime, Local};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// A value shared between the UI thread and background threads.
pub type Shared<T> = Arc<Mutex<T>>;

/// Wrap a value in [`Shared`].
pub fn shared<T>(v: T) -> Shared<T> {
    Arc::new(Mutex::new(v))
}

/// Directories searched for executables. Normal users on Debian do not have
/// the sbin directories in PATH, but tools like ufw and modprobe live there.
fn search_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    for d in [
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ] {
        let p = PathBuf::from(d);
        if !dirs.contains(&p) {
            dirs.push(p);
        }
    }
    dirs
}

/// Find an executable by name in [`search_dirs`]. Returns its full path, or `None` if it isn't
/// installed.
pub fn which(name: &str) -> Option<PathBuf> {
    search_dirs()
        .into_iter()
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// Run a command with a C locale. Returns (success, stdout, stderr).
pub fn run_full(cmd: &str, args: &[&str]) -> Option<(bool, String, String)> {
    let path = which(cmd).unwrap_or_else(|| PathBuf::from(cmd));
    let out = Command::new(path)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .output()
        .ok()?;
    Some((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// stdout of a command, regardless of exit status.
pub fn run_out(cmd: &str, args: &[&str]) -> Option<String> {
    run_full(cmd, args).map(|(_, o, _)| o)
}

/// True when a systemd unit is running right now (`systemctl is-active`).
pub fn systemctl_active(unit: &str) -> bool {
    run_out("systemctl", &["is-active", unit])
        .map(|s| s.trim() == "active")
        .unwrap_or(false)
}

/// True when a systemd unit starts automatically (`systemctl is-enabled`). `static` and `alias`
/// units count as enabled because they are started by another unit.
pub fn systemctl_enabled(unit: &str) -> bool {
    run_out("systemctl", &["is-enabled", unit])
        .map(|s| matches!(s.trim(), "enabled" | "enabled-runtime" | "static" | "alias"))
        .unwrap_or(false)
}

/// True when a Debian package is installed (not just known, or removed with its config files
/// left behind).
pub fn dpkg_installed(pkg: &str) -> bool {
    run_out("dpkg-query", &["-W", "-f=${db:Status-Status}", pkg])
        .map(|s| s.trim() == "installed")
        .unwrap_or(false)
}

/// Read a whole text file. `None` if it is missing or unreadable.
pub fn read(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Read a small text file (for example a sysfs value) without surrounding whitespace. `None` if
/// missing or empty.
pub fn read_trim(path: impl AsRef<Path>) -> Option<String> {
    read(path)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Last modification time of a file or folder.
pub fn mtime(path: impl AsRef<Path>) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// mtime of the link itself, not its target.
pub fn lmtime(path: impl AsRef<Path>) -> Option<SystemTime> {
    std::fs::symlink_metadata(path)
        .and_then(|m| m.modified())
        .ok()
}

/// How many days ago `t` was (fractional). Times in the future count as 0.
pub fn age_days(t: SystemTime) -> f64 {
    SystemTime::now()
        .duration_since(t)
        .map(|d| d.as_secs_f64() / 86400.0)
        .unwrap_or(0.0)
}

/// Format a time for people, in local time: "Oct 29, 2026 1:36 PM".
pub fn fmt_time(t: SystemTime) -> String {
    let dt: DateTime<Local> = t.into();
    dt.format("%b %-d, %Y %-I:%M %p").to_string()
}

/// Format a time as "just now", "5 minutes ago", "3 days ago"…
pub fn fmt_ago(t: SystemTime) -> String {
    let secs = SystemTime::now()
        .duration_since(t)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match secs {
        0..=59 => "just now".into(),
        60..=3599 => plural(secs / 60, "minute"),
        3600..=86399 => plural(secs / 3600, "hour"),
        _ => plural(secs / 86400, "day"),
    }
}

/// "1 day ago" / "2 days ago".
fn plural(n: u64, unit: &str) -> String {
    if n == 1 {
        format!("1 {unit} ago")
    } else {
        format!("{n} {unit}s ago")
    }
}

/// The user's home folder ($HOME).
pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

/// ~/.local/share/proton-security (created on demand).
pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home().join(".local/share"));
    let d = base.join("proton-security");
    let _ = std::fs::create_dir_all(&d);
    d
}

/// Filesystem type mounted at `/`.
pub fn root_fs_type() -> Option<String> {
    // Debug builds only: pretend the root filesystem is something else (testing).
    #[cfg(debug_assertions)]
    if let Ok(fs) = std::env::var("PROTON_SECURITY_FAKE_ROOTFS") {
        return Some(fs);
    }
    let mounts = read("/proc/self/mounts")?;
    mounts
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let _dev = f.next()?;
            let mp = f.next()?;
            let fs = f.next()?;
            (mp == "/").then(|| fs.to_string())
        })
        .next_back()
}

/// Launch a GUI program detached from us.
pub fn spawn_detached(cmd: &str, args: &[&str]) -> bool {
    let Some(path) = which(cmd) else { return false };
    Command::new(path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_ok()
}

/// Open a web page or file with the desktop's default app.
pub fn open_url(url: &str) {
    if !spawn_detached("xdg-open", &[url]) {
        spawn_detached("kde-open", &[url]);
    }
}

/// Human readable byte size.
pub fn fmt_bytes(b: u64) -> String {
    /// Unit names, each 1000 times the previous.
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// Ask the desktop for a folder (kdialog on Plasma, zenity as a fallback).
pub fn pick_folder() -> Option<PathBuf> {
    let home = home().to_string_lossy().into_owned();
    let out = if which("kdialog").is_some() {
        run_full(
            "kdialog",
            &[
                "--title",
                "Choose a folder to scan",
                "--getexistingdirectory",
                &home,
            ],
        )
    } else if which("zenity").is_some() {
        run_full(
            "zenity",
            &[
                "--file-selection",
                "--directory",
                "--title=Choose a folder to scan",
            ],
        )
    } else {
        None
    }?;
    let p = out.1.trim();
    (out.0 && !p.is_empty()).then(|| PathBuf::from(p))
}
