// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! ClamAV integration: definitions info, scans, scan history and quarantine.

use crate::sys::{self, Shared, shared};
use chrono::{Local, NaiveDateTime, TimeZone};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------- info

/// ClamAV's state: installed version, virus definitions and services.
#[derive(Clone, Default, Debug)]
pub struct ClamInfo {
    /// `clamscan` is installed.
    pub installed: bool,
    /// ClamAV engine version ("1.4.3").
    pub engine_version: Option<String>,
    /// Version number of the virus definitions (daily database).
    pub db_version: Option<String>,
    /// When the virus definitions were published (or the files last changed).
    pub db_date: Option<SystemTime>,
    /// The definition updater service (`clamav-freshclam`) is running.
    pub freshclam_active: bool,
    /// The definition updater starts at boot.
    pub freshclam_enabled: bool,
    /// The ClamAV daemon (`clamd`) is running; background checks use it because it is much
    /// faster than starting `clamscan`.
    pub daemon_active: bool,
}

impl ClamInfo {
    /// True when virus definitions update automatically (freshclam is running and enabled).
    pub fn auto_update(&self) -> bool {
        self.freshclam_active && self.freshclam_enabled
    }
}

/// Read ClamAV's state. `clamscan --version` prints the engine, definition version and date in
/// one line; the definition files' dates are used when that fails.
pub fn clam_info() -> ClamInfo {
    let mut i = ClamInfo {
        installed: sys::which("clamscan").is_some(),
        ..Default::default()
    };
    if !i.installed {
        return i;
    }
    // "ClamAV 1.4.3/27801/Mon Oct 26 08:34:02 2026"
    if let Some(v) = sys::run_out("clamscan", &["--version"]) {
        let v = v.trim();
        let mut parts = v.splitn(3, '/');
        i.engine_version = parts
            .next()
            .map(|s| s.trim_start_matches("ClamAV").trim().to_string());
        i.db_version = parts.next().map(|s| s.trim().to_string());
        if let Some(d) = parts.next() {
            let d = d.split_whitespace().collect::<Vec<_>>().join(" ");
            if let Ok(nd) = NaiveDateTime::parse_from_str(&d, "%a %b %d %H:%M:%S %Y")
                && let Some(t) = Local.from_local_datetime(&nd).single()
            {
                i.db_date = Some(t.into());
            }
        }
    }
    if i.db_date.is_none() {
        i.db_date = ["daily.cld", "daily.cvd"]
            .iter()
            .filter_map(|f| sys::mtime(Path::new("/var/lib/clamav").join(f)))
            .max();
    }
    i.freshclam_active = sys::systemctl_active("clamav-freshclam.service");
    i.freshclam_enabled = sys::systemctl_enabled("clamav-freshclam.service");
    i.daemon_active = sys::systemctl_active("clamav-daemon.service");
    i
}

// ---------------------------------------------------------------- history

/// A file ClamAV found dangerous.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Threat {
    /// Full path of the file, as text. For a file with an unusual name (see [`unusual_name`])
    /// this is only for display, and [`Threat::raw_path`] holds the exact name.
    pub path: String,
    /// ClamAV's name for what it found, for example "Win.Trojan.Agent-12345".
    pub signature: String,
    /// None = action needed; otherwise "Quarantined", "Deleted", "Allowed", "Restored".
    #[serde(default)]
    pub action: Option<String>,
    /// Exact bytes of the path when it isn't plain text (control characters such as a line
    /// break, or not valid UTF-8). Quarantine and Delete use this, never the display text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_path: Option<Vec<u8>>,
}

impl Threat {
    /// A threat in the file at `p`. Unusual names keep their exact bytes in `raw_path`.
    pub fn new(p: &Path, signature: impl Into<String>) -> Self {
        use std::os::unix::ffi::OsStrExt;
        Threat {
            path: display_path(p),
            signature: signature.into(),
            action: None,
            raw_path: unusual_name(p).then(|| p.as_os_str().as_bytes().to_vec()),
        }
    }
    /// The real location of the file on disk.
    pub fn fs_path(&self) -> PathBuf {
        use std::os::unix::ffi::OsStrExt;
        match &self.raw_path {
            Some(b) => PathBuf::from(std::ffi::OsStr::from_bytes(b)),
            None => PathBuf::from(&self.path),
        }
    }
}

/// One entry of the protection history (any scan: manual, daily, download check, USB drive).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanRecord {
    /// "Quick scan", "Full scan", "Download check", "USB drive scan"…
    pub kind: String,
    /// Start time (Unix seconds). Also identifies the record when a threat's action is saved.
    pub started: i64,
    /// End time (Unix seconds).
    pub finished: i64,
    /// Files checked.
    pub files: u64,
    /// Files that couldn't be read.
    pub errors: u64,
    /// The user stopped the scan.
    pub cancelled: bool,
    /// Folders or files that were scanned.
    pub targets: Vec<String>,
    /// Threats found.
    pub threats: Vec<Threat>,
    /// Why ClamAV could not run (missing virus definitions, …). A scan with a problem doesn't
    /// count as a recent scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

impl ScanRecord {
    /// End time as a `SystemTime`.
    pub fn finished_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.finished.max(0) as u64)
    }
    /// "1m 20s" style duration.
    pub fn duration_text(&self) -> String {
        let s = (self.finished - self.started).max(0);
        if s >= 3600 {
            format!("{}h {}m", s / 3600, (s % 3600) / 60)
        } else if s >= 60 {
            format!("{}m {}s", s / 60, s % 60)
        } else {
            format!("{s}s")
        }
    }
    /// Threats nobody has decided about yet.
    pub fn open_threats(&self) -> usize {
        self.threats.iter().filter(|t| t.action.is_none()).count()
    }
}

/// `~/.local/share/proton-security/scan-history.json`. Written by the window and by the tray.
fn history_path() -> PathBuf {
    sys::data_dir().join("scan-history.json")
}

/// Protection history keeps 30 days. Scans with threats you haven't handled
/// yet are kept until you choose what to do with them.
pub const HISTORY_DAYS: i64 = 30;
/// Never keep more records than this, even within 30 days.
const HISTORY_MAX: usize = 200;

/// Drop records older than [`HISTORY_DAYS`] (unless they still have open threats) and keep at
/// most [`HISTORY_MAX`]. Returns true when something was removed.
fn prune(h: &mut Vec<ScanRecord>) -> bool {
    let cutoff = now_unix() - HISTORY_DAYS * 86400;
    let before = h.len();
    h.retain(|r| r.finished >= cutoff || r.open_threats() > 0);
    if h.len() > HISTORY_MAX {
        let extra = h.len() - HISTORY_MAX;
        h.drain(..extra);
    }
    h.len() != before
}

/// Read the protection history (oldest first), pruning old records.
pub fn load_history() -> Vec<ScanRecord> {
    let mut h: Vec<ScanRecord> = sys::read(history_path())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if prune(&mut h) {
        write_history(&h);
    }
    h
}

/// Save the protection history.
pub fn save_history(h: &[ScanRecord]) {
    let mut h = h.to_vec();
    prune(&mut h);
    write_history(&h);
}

/// Write through a temporary file and rename it, so the window and the tray never read a
/// half-written file.
fn write_history(h: &[ScanRecord]) {
    if let Ok(s) = serde_json::to_string_pretty(h) {
        let tmp = history_path().with_extension("json.tmp");
        if std::fs::write(&tmp, s).is_ok() {
            let _ = std::fs::rename(tmp, history_path());
        }
    }
}

/// Most recent scan that was not cancelled and did run.
pub fn last_completed_scan(h: &[ScanRecord]) -> Option<&ScanRecord> {
    h.iter().rev().find(|r| !r.cancelled && r.problem.is_none())
}

/// Current Unix time in seconds.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------- quarantine

/// A file moved to quarantine.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QuarantineItem {
    /// File name inside the quarantine folder.
    pub id: String,
    /// Where the file was, for "Restore".
    pub original_path: String,
    /// What ClamAV found in it.
    pub signature: String,
    /// When it was quarantined (Unix seconds).
    pub quarantined_at: i64,
    /// Exact bytes of `original_path` for unusual names (see [`Threat::raw_path`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_raw: Option<Vec<u8>>,
}

impl QuarantineItem {
    /// Where the file was, exactly.
    pub fn original_fs_path(&self) -> PathBuf {
        use std::os::unix::ffi::OsStrExt;
        match &self.original_raw {
            Some(b) => PathBuf::from(std::ffi::OsStr::from_bytes(b)),
            None => PathBuf::from(&self.original_path),
        }
    }
}

/// `~/.local/share/proton-security/quarantine`, readable only by the user (mode 700).
fn quarantine_dir() -> PathBuf {
    let d = sys::data_dir().join("quarantine");
    let _ = std::fs::create_dir_all(&d);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
    }
    d
}

/// List of quarantined files (JSON) inside the quarantine folder.
fn quarantine_index() -> PathBuf {
    quarantine_dir().join("index.json")
}

/// When the scan history and the quarantine list last changed. The tray
/// writes them too (download and USB checks, the daily scan), so the window
/// watches these to stay up to date.
pub fn files_stamp() -> (Option<std::time::SystemTime>, Option<std::time::SystemTime>) {
    (
        sys::mtime(history_path()),
        sys::mtime(sys::data_dir().join("quarantine/index.json")),
    )
}

/// Quarantined files.
pub fn load_quarantine() -> Vec<QuarantineItem> {
    sys::read(quarantine_index())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Save the list of quarantined files.
fn save_quarantine(items: &[QuarantineItem]) {
    if let Ok(s) = serde_json::to_string_pretty(items) {
        let _ = std::fs::write(quarantine_index(), s);
    }
}

/// Move a file, also across filesystems (copy, then delete the original). If the original can't
/// be deleted (for example it belongs to another account), the copy is removed again, so a failed
/// move never leaves a second copy of a dangerous file behind.
fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        // Another account's file in a shared folder (/tmp): copying wouldn't help.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(e),
        Err(_) => {
            // Different filesystem: copy + remove.
            std::fs::copy(from, to)?;
            if let Err(e) = std::fs::remove_file(from) {
                let _ = std::fs::remove_file(to);
                return Err(e);
            }
            Ok(())
        }
    }
}

/// Explain a failed quarantine / delete in words.
fn explain_io(what: &str, e: std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        format!(
            "This file belongs to another account, so you can't {what} it. Ask an administrator to remove it."
        )
    } else {
        format!("Could not {what} the file: {e}")
    }
}

/// Refuse to touch anything that isn't a complete path to an existing regular file.
/// Scan results only ever contain absolute paths; anything else would be resolved against the
/// app's working folder (the home folder), which is exactly what a crafted file name tries to
/// make happen.
fn check_target(p: &Path) -> Result<(), String> {
    if !p.is_absolute() {
        return Err(
            "This file location is incomplete, so Proton Security won't touch it. Run a new scan."
                .into(),
        );
    }
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_file() => Ok(()),
        Ok(_) => Err("This is not a regular file anymore, so it was left alone.".into()),
        Err(_) => Err("The file no longer exists.".into()),
    }
}

/// Move a dangerous file into quarantine and remove all its permissions (mode 000), so it can't
/// be run or opened by accident.
pub fn quarantine(t: &Threat) -> Result<(), String> {
    let src = t.fs_path();
    check_target(&src)?;
    let id = format!("{}-{}", now_unix(), std::process::id() ^ rand_suffix());
    let dst = quarantine_dir().join(&id);
    move_file(&src, &dst).map_err(|e| explain_io("quarantine", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o000));
    }
    let mut items = load_quarantine();
    items.push(QuarantineItem {
        id,
        original_path: t.path.clone(),
        signature: t.signature.clone(),
        quarantined_at: now_unix(),
        original_raw: t.raw_path.clone(),
    });
    save_quarantine(&items);
    Ok(())
}

/// A few changing bits to make quarantine file names unique.
fn rand_suffix() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0)
}

/// Put a quarantined file back where it was. Refuses to overwrite a file that is there now.
pub fn restore_quarantined(id: &str) -> Result<(), String> {
    let mut items = load_quarantine();
    let Some(pos) = items.iter().position(|i| i.id == id) else {
        return Err("Item not found.".into());
    };
    let item = items[pos].clone();
    let src = quarantine_dir().join(&item.id);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o600));
    }
    let dst_buf = item.original_fs_path();
    let dst = dst_buf.as_path();
    if !dst.is_absolute() {
        return Err("The original location is incomplete; delete this file instead.".into());
    }
    if dst.exists() {
        return Err("A file already exists at the original location.".into());
    }
    if let Some(parent) = dst.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    move_file(&src, dst).map_err(|e| format!("Could not restore the file: {e}"))?;
    items.remove(pos);
    save_quarantine(&items);
    Ok(())
}

/// Delete a quarantined file for good.
pub fn delete_quarantined(id: &str) -> Result<(), String> {
    let mut items = load_quarantine();
    let Some(pos) = items.iter().position(|i| i.id == id) else {
        return Err("Item not found.".into());
    };
    let p = quarantine_dir().join(&items[pos].id);
    if p.exists() {
        std::fs::remove_file(&p).map_err(|e| format!("Could not delete: {e}"))?;
    }
    items.remove(pos);
    save_quarantine(&items);
    Ok(())
}

/// Delete a dangerous file in place (only a complete path to a regular file, see
/// [`check_target`]).
pub fn delete_file(t: &Threat) -> Result<(), String> {
    let p = t.fs_path();
    check_target(&p)?;
    std::fs::remove_file(&p).map_err(|e| explain_io("delete", e))
}

// ---------------------------------------------------------------- scanning

/// The scans the user can start.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ScanKind {
    /// Places where malware usually lands (see [`quick_targets`]).
    Quick,
    /// Daily automatic quick scan started by the tray.
    Scheduled,
    /// The whole computer, except virtual filesystems and snapshots.
    Full,
    /// A folder the user picks.
    Custom,
}

impl ScanKind {
    /// Name shown in the history.
    pub fn label(self) -> &'static str {
        match self {
            ScanKind::Quick => "Quick scan",
            ScanKind::Full => "Full scan",
            ScanKind::Custom => "Custom scan",
            ScanKind::Scheduled => "Scheduled quick scan",
        }
    }
}

/// Directories never descended into by a full scan.
const FULL_EXCLUDES: [&str; 7] = [
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/.snapshots",
    "/var/lib/docker",
    "/var/lib/containers",
];

/// Folders a quick scan checks: Downloads, Desktop, Documents, `~/.local/bin`, autostart
/// entries and the temporary folders.
pub fn quick_targets() -> Vec<PathBuf> {
    let h = sys::home();
    let mut v: Vec<PathBuf> = [
        h.join("Downloads"),
        h.join("Desktop"),
        h.join("Documents"),
        h.join(".local/bin"),
        h.join(".config/autostart"),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
    ]
    .into_iter()
    .filter(|p| p.exists())
    .collect();
    if v.is_empty() {
        v.push(h);
    }
    v
}

/// Stages of a scan, for the progress display.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Phase {
    /// Counting files, to estimate progress.
    Counting,
    /// ClamAV is loading its virus definitions (takes 10–30 seconds).
    Loading,
    /// Checking files.
    Scanning,
    /// Finished (or cancelled); `result` is set.
    Done,
}

/// Live progress of a running scan, shared with the window.
#[derive(Clone, Debug)]
pub struct ScanProgress {
    /// Current stage.
    pub phase: Phase,
    /// Number of files expected.
    pub estimate: u64,
    /// Files checked so far.
    pub scanned: u64,
    /// Files that couldn't be read so far.
    pub errors: u64,
    /// File being checked now.
    pub current: String,
    /// Threats found so far.
    pub threats: Vec<Threat>,
    /// Start time (Unix seconds).
    pub started: i64,
    /// The history record, once finished.
    pub result: Option<ScanRecord>,
    /// Why ClamAV could not run, if it couldn't (see [`explain_failure`]).
    pub problem: Option<String>,
}

/// A running scan.
pub struct ScanJob {
    /// Type of scan.
    pub kind: ScanKind,
    /// Progress, updated by the scanning thread.
    pub progress: Shared<ScanProgress>,
    /// Set to stop the scan.
    cancel: Arc<AtomicBool>,
}

impl ScanJob {
    /// Stop the scan (ClamAV is killed within 200 ms).
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }
    /// A copy of the current progress.
    pub fn snapshot(&self) -> ScanProgress {
        self.progress.lock().unwrap().clone()
    }
}

/// True when `p` is one of the excluded folders.
fn excluded(p: &Path, excludes: &[&str]) -> bool {
    excludes.iter().any(|e| p == Path::new(e))
}

// ---------------------------------------------------------------- safe scanning
//
// ClamAV reports one line per file: "<path>: <result>". Linux allows almost any byte in a file
// name, including a line break, and ClamAV prints names as they are. A crafted name such as
// "holiday⏎important.odt" would then produce a line "important.odt: <virus> FOUND" and make the
// app blame a different file. To rule that out:
//   1. We never let ClamAV search folders itself. We walk them, and give ClamAV an exact list
//      of files (`--file-list`) containing only "plain" names: valid UTF-8, no control
//      characters. Their result lines can't be ambiguous.
//   2. Files with unusual names are scanned one at a time through ClamAV's standard input, so
//      their name never appears in the output; we keep the exact path ourselves.
//   3. A result line is only accepted for an absolute, plain path (and, where we have it, one
//      of the files we sent). Everything else is ignored.

/// True for file names ClamAV can't report unambiguously: names with control characters (such as
/// a line break) or that aren't valid UTF-8. Such files are scanned through standard input.
pub fn unusual_name(p: &Path) -> bool {
    match p.to_str() {
        Some(s) => s.chars().any(char::is_control),
        None => true,
    }
}

/// A path for showing to people: a line break shows as "⏎", other control characters and
/// invalid bytes as "�".
pub fn display_path(p: &Path) -> String {
    p.to_string_lossy()
        .chars()
        .map(|c| match c {
            '\n' => '⏎',
            c if c.is_control() => '\u{FFFD}',
            c => c,
        })
        .collect()
}

/// Most files with unusual names checked one by one in a single scan. More than this is itself
/// suspicious (and each one takes a moment), so the rest are counted as "couldn't be checked".
pub const MAX_UNUSUAL: usize = 50;

/// Private folder for temporary scan lists: `~/.cache/proton-security` (mode 700). Lists can be
/// large for a full scan, so they go to disk, never to the shared `/tmp`.
pub fn private_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| sys::home().join(".cache"));
    let d = base.join("proton-security");
    let _ = std::fs::create_dir_all(&d);
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700));
    }
    d
}

/// A list of files for `clamscan --file-list`, written to a new private file (mode 600) that is
/// deleted when the list is dropped.
pub struct FileList {
    /// Where the list is written.
    pub path: PathBuf,
    /// The open list file, written one path per line.
    out: std::io::BufWriter<std::fs::File>,
    /// Number of files in the list.
    pub len: u64,
}

impl FileList {
    /// Create an empty list in [`private_dir`].
    pub fn create() -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let path = private_dir().join(format!(
            "scan-list-{}-{}.txt",
            std::process::id(),
            rand_suffix()
        ));
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        Ok(FileList {
            path,
            out: std::io::BufWriter::new(f),
            len: 0,
        })
    }
    /// Add a file. Only plain names belong here (see [`unusual_name`]).
    pub fn push(&mut self, p: &Path) -> std::io::Result<()> {
        use std::io::Write;
        debug_assert!(!unusual_name(p));
        self.out.write_all(p.as_os_str().as_encoded_bytes())?;
        self.out.write_all(b"\n")?;
        self.len += 1;
        Ok(())
    }
    /// Write everything to disk so ClamAV can read it.
    pub fn flush(&mut self) -> std::io::Result<()> {
        use std::io::Write;
        self.out.flush()
    }
}

impl Drop for FileList {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// One result line of `clamscan --stdout` / `clamdscan --stdout`.
#[derive(Debug, PartialEq)]
pub enum ClamLine {
    /// The file is clean.
    Clean(PathBuf),
    /// ClamAV found something: (file, signature).
    Found(PathBuf, String),
    /// The file couldn't be read.
    Failed,
}

/// Parse one result line. Only lines about an absolute path with a plain name are accepted: we
/// only ever send ClamAV such paths, so any other line was made up by a crafted file name (or is
/// a warning) and is ignored.
pub fn parse_clam_line(line: &str) -> Option<ClamLine> {
    let plain = |p: &str| -> Option<PathBuf> {
        let p = Path::new(p);
        (p.is_absolute() && !unusual_name(p)).then(|| p.to_path_buf())
    };
    if let Some(rest) = line.strip_suffix(" FOUND") {
        // Signature names never contain ": ", so the last ": " separates path and signature.
        let (path, sig) = rest.rsplit_once(": ")?;
        return Some(ClamLine::Found(plain(path)?, sig.to_string()));
    }
    if let Some(path) = line
        .strip_suffix(": OK")
        .or_else(|| line.strip_suffix(": Empty file"))
    {
        return Some(ClamLine::Clean(plain(path)?));
    }
    if line.ends_with(" ERROR") || line.contains("Access denied") {
        return Some(ClamLine::Failed);
    }
    None
}

/// Scan one file through ClamAV's standard input, so its name never appears in ClamAV's output.
/// Returns the signature when something was found. Used for files with unusual names.
pub fn scan_via_stdin(p: &Path, use_daemon: bool) -> Result<Option<String>, String> {
    let file = open_regular_file(p)?;
    let (cmd, args): (&str, &[&str]) = if use_daemon {
        ("clamdscan", &["--no-summary", "--stdout", "-"])
    } else {
        ("clamscan", &["--no-summary", "--stdout", "-"])
    };
    let exe = sys::which(cmd).ok_or_else(|| format!("{cmd} is not installed"))?;
    let out = Command::new(exe)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::from(file))
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out.stdout);
    for l in text.lines() {
        if let Some(sig) = l
            .strip_prefix("stdin: ")
            .and_then(|r| r.strip_suffix(" FOUND"))
        {
            return Ok(Some(sig.to_string()));
        }
    }
    match out.status.code() {
        Some(0) => Ok(None),
        _ => Err(explain_failure(&String::from_utf8_lossy(&out.stderr))),
    }
}

/// Open `p` for reading only if it is a regular file, without following a symbolic link at the
/// last step (`O_NOFOLLOW`), and check the file that was actually opened (not the name again):
/// a file swapped for a link, a pipe or a device after the folder walk is refused. Opening a
/// pipe never blocks (`O_NONBLOCK`; it is refused right after).
pub fn open_regular_file(p: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    // The flag values differ between processor types, so they come from `libc`.
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                "not a regular file (a link)".to_string() // the name is a symbolic link
            } else {
                e.to_string()
            }
        })?;
    match f.metadata() {
        Ok(m) if m.file_type().is_file() => Ok(f),
        _ => Err("not a regular file".into()),
    }
}

/// Turn ClamAV's error output into a sentence for the user (a notification or the scan
/// result).
pub fn explain_failure(stderr: &str) -> String {
    let s = stderr.to_lowercase();
    if s.contains("no supported database") || s.contains("cli_loaddb") || s.contains("database") {
        "The virus definitions are missing. Open Proton Security → Virus & threat protection and click \"Check for updates\".".into()
    } else if let Some(l) = stderr.lines().find(|l| !l.trim().is_empty()) {
        let l: String = l.trim().chars().take(200).collect();
        format!("ClamAV reported: {l}")
    } else {
        "ClamAV could not run.".into()
    }
}

/// Start a scan on a background thread. `ctx` is repainted on progress when a
/// window is showing it (None for the headless scheduled scan).
///
/// 1. Walk the targets (skipping [`FULL_EXCLUDES`] for a full scan, never following symlinks),
///    writing plain names to a private [`FileList`] and keeping unusual names aside.
/// 2. Run `clamscan --file-list` and read one result line per file (see [`parse_clam_line`]).
/// 3. Scan the unusual names one by one through standard input ([`scan_via_stdin`]).
/// 4. Save the result to the protection history.
pub fn start_scan(kind: ScanKind, targets: Vec<PathBuf>, ctx: Option<&egui::Context>) -> ScanJob {
    let started = now_unix();
    let progress = shared(ScanProgress {
        phase: Phase::Counting,
        estimate: 0,
        scanned: 0,
        errors: 0,
        current: String::new(),
        threats: vec![],
        started,
        result: None,
        problem: None,
    });
    let cancel = Arc::new(AtomicBool::new(false));
    let (p, c) = (progress.clone(), cancel.clone());
    let ctx_opt = ctx.cloned();
    let ctx = Repaint(ctx_opt);

    std::thread::spawn(move || {
        let excludes: Vec<&str> = if kind == ScanKind::Full {
            FULL_EXCLUDES.to_vec()
        } else {
            vec![]
        };

        // 1. Walk the folders: build the list of files and count them for the progress bar.
        let mut list = FileList::create();
        let mut unusual: Vec<PathBuf> = vec![];
        let mut skipped_unusual = 0u64;
        let mut count = 0u64;
        'outer: for t in &targets {
            let walker = walkdir::WalkDir::new(t)
                .follow_links(false)
                .same_file_system(false)
                .into_iter()
                .filter_entry(|e| !excluded(e.path(), &excludes));
            for e in walker.flatten() {
                if !e.file_type().is_file() {
                    continue;
                }
                count += 1;
                if unusual_name(e.path()) {
                    if unusual.len() < MAX_UNUSUAL {
                        unusual.push(e.into_path());
                    } else {
                        skipped_unusual += 1;
                    }
                } else if let Ok(l) = list.as_mut() {
                    let _ = l.push(e.path());
                }
                if count.is_multiple_of(2000) {
                    p.lock().unwrap().estimate = count;
                    ctx.request_repaint();
                    if c.load(Ordering::SeqCst) {
                        break 'outer;
                    }
                }
            }
        }
        {
            let mut g = p.lock().unwrap();
            g.estimate = count;
            g.errors += skipped_unusual;
            g.phase = Phase::Loading;
        }
        ctx.request_repaint();

        // 2. Run clamscan on the list, reading one result line per file.
        let mut cancelled = c.load(Ordering::SeqCst);
        match list.as_mut() {
            Err(e) => {
                let mut g = p.lock().unwrap();
                g.errors += 1;
                g.current = format!("Could not prepare the scan: {e}");
            }
            Ok(l) if !cancelled && l.len > 0 => {
                if let Err(e) = l.flush() {
                    p.lock().unwrap().current = format!("Could not prepare the scan: {e}");
                }
                let args: Vec<String> = vec![
                    "--stdout".into(),
                    "--no-summary".into(),
                    "--follow-file-symlinks=0".into(),
                    format!("--file-list={}", l.path.to_string_lossy()),
                ];
                run_clamscan_listing(&args, &p, &c, &ctx);
            }
            Ok(_) => {}
        }
        cancelled = c.load(Ordering::SeqCst);

        // 3. Files with unusual names, one by one through standard input.
        if !cancelled && !unusual.is_empty() {
            let daemon =
                sys::systemctl_active("clamav-daemon.service") && sys::which("clamdscan").is_some();
            for f in &unusual {
                if c.load(Ordering::SeqCst) {
                    cancelled = true;
                    break;
                }
                p.lock().unwrap().current = display_path(f);
                ctx.request_repaint();
                let r = scan_via_stdin(f, daemon);
                let mut g = p.lock().unwrap();
                g.phase = Phase::Scanning;
                match r {
                    Ok(Some(sig)) => {
                        g.threats.push(Threat::new(f, sig));
                        g.scanned += 1;
                    }
                    Ok(None) => g.scanned += 1,
                    Err(_) => g.errors += 1,
                }
            }
        }
        drop(list); // deletes the list file

        // 4. Record the result.
        let rec = {
            let g = p.lock().unwrap();
            ScanRecord {
                kind: kind.label().to_string(),
                started,
                finished: now_unix(),
                files: g.scanned,
                errors: g.errors,
                cancelled,
                problem: g.problem.clone(),
                targets: targets
                    .iter()
                    .map(|t| t.to_string_lossy().into_owned())
                    .collect(),
                threats: g.threats.clone(),
            }
        };
        let mut h = load_history();
        h.push(rec.clone());
        save_history(&h);
        {
            let mut g = p.lock().unwrap();
            g.phase = Phase::Done;
            g.result = Some(rec);
        }
        ctx.request_repaint();
    });

    ScanJob {
        kind,
        progress,
        cancel,
    }
}

/// Run clamscan with `args` and turn its output into progress: files checked, threats found,
/// errors. Stops ClamAV within 200 ms when the scan is cancelled.
fn run_clamscan_listing(
    args: &[String],
    p: &Shared<ScanProgress>,
    c: &Arc<AtomicBool>,
    ctx: &Repaint,
) {
    let child = Command::new(sys::which("clamscan").unwrap_or_else(|| "clamscan".into()))
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Err(e) => {
            let mut g = p.lock().unwrap();
            g.errors += 1;
            g.current = format!("Could not start clamscan: {e}");
            return;
        }
        Ok(c) => c,
    };
    let out = child.stdout.take().unwrap();
    // ClamAV's error messages (kept up to 8 KB) explain a scan that could not run.
    let err_reader = child.stderr.take().map(|e| {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = Vec::new();
            let _ = e.take(8192).read_to_end(&mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        })
    });
    // Watch for cancel in a side thread so a slow file does not block it.
    let pid = child.id();
    let done = Arc::new(AtomicBool::new(false));
    let watcher = {
        let (c, d2) = (c.clone(), done.clone());
        std::thread::spawn(move || {
            while !d2.load(Ordering::SeqCst) {
                if c.load(Ordering::SeqCst) {
                    let _ = Command::new("kill").arg(pid.to_string()).status();
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        })
    };
    let mut last_paint = std::time::Instant::now();
    for line in BufReader::new(out).lines().map_while(Result::ok) {
        let mut g = p.lock().unwrap();
        g.phase = Phase::Scanning;
        match parse_clam_line(&line) {
            Some(ClamLine::Found(path, sig)) => {
                // Only regular files can be in the list; anything else was made up.
                if std::fs::symlink_metadata(&path)
                    .map(|m| m.file_type().is_file())
                    .unwrap_or(false)
                {
                    g.threats.push(Threat::new(&path, sig));
                }
                g.scanned += 1;
            }
            Some(ClamLine::Clean(path)) => {
                g.scanned += 1;
                g.current = path.to_string_lossy().into_owned();
            }
            Some(ClamLine::Failed) => g.errors += 1,
            None => {}
        }
        drop(g);
        if last_paint.elapsed() > Duration::from_millis(100) {
            ctx.request_repaint();
            last_paint = std::time::Instant::now();
        }
    }
    let status = child.wait();
    done.store(true, Ordering::SeqCst);
    let _ = watcher.join();
    let stderr = err_reader.and_then(|t| t.join().ok()).unwrap_or_default();
    // Exit code 2 with no file answered: ClamAV itself could not run (no definitions…).
    let mut g = p.lock().unwrap();
    if status.ok().and_then(|s| s.code()) == Some(2) && g.scanned == 0 && !c.load(Ordering::SeqCst)
    {
        g.problem = Some(explain_failure(&stderr));
    }
}

/// Update the stored action of a threat in the scan history.
pub fn set_threat_action(started: i64, path: &str, action: &str) {
    let mut h = load_history();
    for r in h.iter_mut().filter(|r| r.started == started) {
        for t in r.threats.iter_mut().filter(|t| t.path == path) {
            t.action = Some(action.to_string());
        }
    }
    save_history(&h);
}

/// Asks the window to redraw when progress changes; does nothing for headless scans.
struct Repaint(Option<egui::Context>);

impl Repaint {
    /// Redraw the window, if there is one.
    fn request_repaint(&self) {
        if let Some(c) = &self.0 {
            c.request_repaint();
        }
    }
}

/// Run a scheduled quick scan to completion (used by `--scheduled-scan`).
/// Returns the finished record.
pub fn run_scheduled_scan_blocking() -> Option<ScanRecord> {
    let job = start_scan(ScanKind::Scheduled, quick_targets(), None);
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let p = job.snapshot();
        if p.phase == Phase::Done {
            return p.result;
        }
    }
}

/// Most recent scan of any kind that ran to the end.
pub fn last_scan_time() -> Option<SystemTime> {
    last_completed_scan(&load_history()).map(|r| r.finished_time())
}

#[cfg(test)]
mod history_tests {
    use super::*;

    fn rec(days_ago: i64, open_threat: bool) -> ScanRecord {
        let t = now_unix() - days_ago * 86400;
        ScanRecord {
            kind: "Quick scan".into(),
            started: t - 10,
            finished: t,
            files: 1,
            errors: 0,
            cancelled: false,
            targets: vec![],
            threats: if open_threat {
                vec![Threat::new(Path::new("/x"), "S")]
            } else {
                vec![]
            },
            problem: None,
        }
    }

    #[test]
    fn keeps_30_days_and_open_threats() {
        let mut h = vec![
            rec(90, false),
            rec(45, true),
            rec(31, false),
            rec(29, false),
            rec(1, false),
        ];
        assert!(prune(&mut h));
        let ages: Vec<i64> = h
            .iter()
            .map(|r| (now_unix() - r.finished) / 86400)
            .collect();
        assert_eq!(ages, vec![45, 29, 1]);
    }
}

/// Regression tests for the crafted-file-name attack (audit 2026-10-29, findings 1 and 2).
#[cfg(test)]
mod safe_scan_tests {
    use super::*;

    #[test]
    fn opens_only_regular_files() {
        let d = std::env::temp_dir().join(format!("ps-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let file = d.join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        assert!(open_regular_file(&file).is_ok());
        // A link (even to a regular file) is refused: it may have replaced the file.
        let link = d.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(open_regular_file(&link).is_err());
        // A folder, and a pipe (opening it must not hang).
        assert!(open_regular_file(&d).is_err());
        let fifo = d.join("fifo");
        if std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|s| s.success())
        {
            assert!(open_regular_file(&fifo).is_err());
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn clamav_errors_become_sentences() {
        assert!(
            explain_failure("LibClamAV Error: cli_loaddb(): No supported database files found")
                .contains("definitions are missing")
        );
        assert_eq!(
            explain_failure("\nERROR: Can't allocate memory\n"),
            "ClamAV reported: ERROR: Can't allocate memory"
        );
        assert_eq!(explain_failure(""), "ClamAV could not run.");
    }

    #[test]
    fn only_absolute_plain_paths_are_accepted() {
        assert_eq!(
            parse_clam_line("/home/ana/x.exe: Win.Trojan.Agent FOUND"),
            Some(ClamLine::Found(
                "/home/ana/x.exe".into(),
                "Win.Trojan.Agent".into()
            ))
        );
        // A path containing ": " is still split at the last ": ".
        assert_eq!(
            parse_clam_line("/tmp/a: b.exe: Eicar FOUND"),
            Some(ClamLine::Found("/tmp/a: b.exe".into(), "Eicar".into()))
        );
        assert_eq!(
            parse_clam_line("/tmp/ok.txt: OK"),
            Some(ClamLine::Clean("/tmp/ok.txt".into()))
        );
        // The second half of a name split by a line break: relative, ignored.
        assert_eq!(parse_clam_line("important.odt: Eicar FOUND"), None);
        assert_eq!(parse_clam_line(".bashrc: OK"), None);
        // Control characters in what claims to be a path: ignored.
        assert_eq!(parse_clam_line("/tmp/a\rb: Eicar FOUND"), None);
        assert_eq!(parse_clam_line("WARNING: something"), None);
    }

    #[test]
    fn unusual_names_and_display() {
        assert!(unusual_name(Path::new("/tmp/holiday\nimportant.odt")));
        assert!(!unusual_name(Path::new("/tmp/Résumé 2026.pdf")));
        {
            use std::os::unix::ffi::OsStrExt;
            let bad = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/caf\xe9.txt"));
            assert!(unusual_name(bad));
            let t = Threat::new(bad, "S");
            assert_eq!(
                t.fs_path(),
                bad,
                "exact bytes are kept for quarantine / delete"
            );
        }
        assert_eq!(display_path(Path::new("/tmp/a\nb")), "/tmp/a⏎b");
    }

    #[test]
    fn quarantine_and_delete_refuse_relative_paths() {
        let t = Threat {
            path: "important.odt".into(),
            signature: "Eicar".into(),
            action: None,
            raw_path: None,
        };
        assert!(quarantine(&t).is_err());
        assert!(delete_file(&t).is_err());
    }

    /// The proof of concept from the audit, run against the real scan code and ClamAV. Skipped
    /// when ClamAV (or a signature that detects the EICAR test file) isn't available, as in CI.
    #[test]
    fn crafted_file_name_cannot_redirect_a_threat() {
        const EICAR: &[u8] =
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let Some(clamscan) = sys::which("clamscan") else {
            eprintln!("skipped: clamscan not installed");
            return;
        };
        let root = std::env::temp_dir().join(format!("ps-poc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (home, scan) = (root.join("home"), root.join("scan"));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&scan).unwrap();
        // Probe: does this ClamAV detect EICAR at all?
        std::fs::write(scan.join("probe.com"), EICAR).unwrap();
        let probe = Command::new(&clamscan)
            .args(["--no-summary", "--stdout"])
            .arg(scan.join("probe.com"))
            .output()
            .unwrap();
        std::fs::remove_file(scan.join("probe.com")).unwrap();
        if !String::from_utf8_lossy(&probe.stdout).contains("FOUND") {
            eprintln!("skipped: no signature for the EICAR test file");
            return;
        }
        // The victim's document, and the attacker's crafted file.
        std::fs::write(home.join("important.odt"), b"my thesis").unwrap();
        let crafted = scan.join("holiday\nimportant.odt");
        std::fs::write(&crafted, EICAR).unwrap();
        // SAFETY: the only test that changes the environment and working folder.
        unsafe {
            std::env::set_var("XDG_DATA_HOME", root.join("data"));
            std::env::set_var("XDG_CACHE_HOME", root.join("cache"));
        }
        std::env::set_current_dir(&home).unwrap();

        // Manual scan (finding 1).
        let job = start_scan(ScanKind::Custom, vec![scan.clone()], None);
        let rec = loop {
            std::thread::sleep(Duration::from_millis(200));
            let p = job.snapshot();
            if p.phase == Phase::Done {
                break p.result.unwrap();
            }
        };
        assert_eq!(rec.threats.len(), 1, "exactly the crafted file is reported");
        assert_eq!(rec.threats[0].fs_path(), crafted);
        quarantine(&rec.threats[0]).unwrap();
        assert!(
            home.join("important.odt").exists(),
            "the innocent file is untouched"
        );
        assert!(!crafted.exists(), "the real threat was quarantined");

        // Background scan (finding 2): the crafted file is checked, not skipped.
        std::fs::write(&crafted, EICAR).unwrap();
        let out = crate::watchers::scan_files(std::slice::from_ref(&crafted));
        assert_eq!(
            out.threats.len(),
            1,
            "background scan found the crafted file"
        );
        assert_eq!(out.threats[0].fs_path(), crafted);
        // No scan list may be left behind.
        let leftovers = std::fs::read_dir(root.join("cache/proton-security"))
            .map(|d| d.count())
            .unwrap_or(0);
        assert_eq!(leftovers, 0);
        let _ = std::fs::remove_dir_all(&root);
    }
}
