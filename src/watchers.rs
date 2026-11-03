// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Background watchers run by the tray (as the user, no administrator rights):
//! - scan new files where files arrive (Downloads, the desktop, apps' download folders, files
//!   opened straight from the browser or email, your own risky files in `/tmp`) with ClamAV,
//!   and re-check the last week's new files when the virus definitions are updated
//! - quick-scan USB drives and memory cards when they are opened
//! - alert when a new USB keyboard, network adapter or drive is plugged in

use crate::antivirus::{self, ScanRecord, Threat};
use crate::{risk, sys};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

// ------------------------------------------------------------------ new files

/// Browser "still downloading" files.
const PARTIAL: [&str; 7] = [
    "part",
    "crdownload",
    "download",
    "tmp",
    "opdownload",
    "partial",
    "!ut",
];
/// Files bigger than this are skipped, unless they are risky (see [`risk::risky`]).
const MAX_SIZE: u64 = 1_000_000_000;
/// Most entries looked at in one folder per check, so a folder with a huge number of files
/// can't make the tray slow.
const MAX_ENTRIES_PER_ROOT: usize = 5000;
/// Most new files checked at once (risky ones first). More than this at once means an archive
/// was unpacked; the archive itself was already checked when it arrived.
const MAX_BATCH: usize = 500;

/// The user's Downloads folder (`xdg-user-dir DOWNLOAD`, so it follows translated folder
/// names), or `~/Downloads`.
pub fn downloads_dir() -> PathBuf {
    xdg_dir("DOWNLOAD").unwrap_or_else(|| sys::home().join("Downloads"))
}

/// A folder from `xdg-user-dir` (`DOWNLOAD`, `DESKTOP`…), if it exists and isn't the home
/// folder itself (which is what xdg-user-dir answers for folders that aren't set up).
fn xdg_dir(name: &str) -> Option<PathBuf> {
    let d = PathBuf::from(sys::run_out("xdg-user-dir", &[name])?.trim());
    (d.is_absolute() && d.is_dir() && d != sys::home()).then_some(d)
}

/// The user id this program runs as (the owner of `/proc/self`). `u32::MAX` if unknown, which
/// matches no file, so "own files only" places are then skipped.
pub fn my_uid() -> u32 {
    std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(u32::MAX)
}

/// Where a new file was found. Decides what the user is told.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Place {
    /// The Downloads folder.
    Downloads,
    /// The desktop folder.
    Desktop,
    /// A Flatpak app's own Downloads folder (`~/.var/app/<app>/Downloads`).
    AppDownloads,
    /// Where Firefox and Thunderbird put files you open without saving them
    /// (`/tmp/mozilla_<user>0`).
    OpenedFromBrowser,
    /// Your own risky files in `/tmp` or `/dev/shm`.
    Temporary,
}

impl Place {
    /// Words for notifications ("in Downloads").
    pub fn label(self) -> &'static str {
        match self {
            Place::Downloads => "in Downloads",
            Place::Desktop => "on the desktop",
            Place::AppDownloads => "in an app's Downloads folder",
            Place::OpenedFromBrowser => "opened from the browser or email",
            Place::Temporary => "in temporary files",
        }
    }

    /// Whether a "file is safe" notification is shown. Downloads are something the user just
    /// did and waits for; the other places get many files the user never thinks about, so
    /// they are checked quietly and only threats are reported.
    pub fn tells_safe(self) -> bool {
        matches!(self, Place::Downloads | Place::AppDownloads)
    }
}

/// A folder where new files arrive and how to look at it.
#[derive(Clone, Debug)]
struct Root {
    /// The folder.
    path: PathBuf,
    /// How deep to look (1 = only files directly in it).
    depth: usize,
    /// Only check risky files (programs, scripts, documents, archives).
    risky_only: bool,
    /// Only files owned by this user (shared folders like `/tmp`).
    own_only: bool,
    /// What this place is called in notifications.
    place: Place,
}

/// The Downloads and desktop folders (asking `xdg-user-dir`, a separate program, so this is
/// done once a minute, not on every check).
#[derive(Clone)]
struct UserDirs {
    /// See [`downloads_dir`].
    downloads: PathBuf,
    /// The desktop folder, if it exists and differs from Downloads.
    desktop: Option<PathBuf>,
    /// When they were looked up.
    at: std::time::Instant,
}

impl UserDirs {
    /// Look the folders up now.
    fn lookup() -> Self {
        let downloads = downloads_dir();
        let desktop = xdg_dir("DESKTOP").filter(|d| *d != downloads);
        Self {
            downloads,
            desktop,
            at: std::time::Instant::now(),
        }
    }
}

/// Every place watched for new files, found again on each check (an app's Downloads folder or
/// Firefox's temporary folder can appear at any time).
fn arrival_roots(uid: u32, dirs: &UserDirs) -> Vec<Root> {
    let home = sys::home();
    let mut roots = vec![Root {
        path: dirs.downloads.clone(),
        depth: 2,
        risky_only: false,
        own_only: false,
        place: Place::Downloads,
    }];
    if let Some(desk) = &dirs.desktop {
        roots.push(Root {
            path: desk.clone(),
            depth: 1,
            risky_only: false,
            own_only: false,
            place: Place::Desktop,
        });
    }
    // Flatpak apps without access to the real Downloads folder save into their own.
    if let Ok(rd) = std::fs::read_dir(home.join(".var/app")) {
        for e in rd.flatten().take(500) {
            let d = e.path().join("Downloads");
            // symlink_metadata: a link pointing somewhere else is not followed.
            if std::fs::symlink_metadata(&d).is_ok_and(|m| m.is_dir()) {
                roots.push(Root {
                    path: d,
                    depth: 2,
                    risky_only: false,
                    own_only: false,
                    place: Place::AppDownloads,
                });
            }
        }
    }
    for tmp in ["/tmp", "/dev/shm"] {
        roots.push(Root {
            path: PathBuf::from(tmp),
            depth: 1,
            risky_only: true,
            own_only: true,
            place: Place::Temporary,
        });
    }
    // Firefox/Thunderbird: /tmp/mozilla_<user>0. Only a real folder owned by us counts:
    // anyone can create names in /tmp.
    if let Ok(rd) = std::fs::read_dir("/tmp") {
        for e in rd.flatten().take(MAX_ENTRIES_PER_ROOT) {
            if !e.file_name().to_string_lossy().starts_with("mozilla_") {
                continue;
            }
            if let Ok(md) = std::fs::symlink_metadata(e.path())
                && md.is_dir()
                && md.uid() == uid
            {
                roots.push(Root {
                    path: e.path(),
                    depth: 1,
                    risky_only: false,
                    own_only: true,
                    place: Place::OpenedFromBrowser,
                });
            }
        }
    }
    roots
}

/// Temporary files Chrome/Chromium writes into Downloads while downloading.
fn chromium_temp(name: &str) -> bool {
    name.starts_with(".com.google.Chrome.") || name.starts_with(".org.chromium.Chromium.")
}

/// Size and modification time of every finished, non-empty file in a watched place. Hidden
/// folders, browser partial downloads and (for shared folders) other people's files are left
/// out. Hidden files are kept here and filtered later (only risky ones are checked).
fn snapshot(root: &Root, uid: u32) -> Vec<(PathBuf, (u64, SystemTime))> {
    let mut v = vec![];
    for e in walkdir::WalkDir::new(&root.path)
        .max_depth(root.depth)
        .follow_links(false)
        .same_file_system(true)
        .into_iter()
        .filter_entry(|e| {
            e.depth() == 0
                || !(e.file_type().is_dir() && e.file_name().to_string_lossy().starts_with('.'))
        })
        .take(MAX_ENTRIES_PER_ROOT)
        .flatten()
    {
        if !e.file_type().is_file() {
            continue;
        }
        let p = e.path();
        let name = e.file_name().to_string_lossy();
        if chromium_temp(&name) {
            continue;
        }
        let ext = p
            .extension()
            .map(|x| x.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if PARTIAL.contains(&ext.as_str()) {
            continue;
        }
        if let Ok(md) = e.metadata()
            && md.len() > 0
            && (!root.own_only || md.uid() == uid)
        {
            v.push((
                p.to_path_buf(),
                (md.len(), md.modified().unwrap_or(UNIX_EPOCH)),
            ));
        }
    }
    v
}

/// A new file that is ready to be checked.
#[derive(Clone, Debug)]
pub struct Arrival {
    /// The file.
    pub path: PathBuf,
    /// Where it was found.
    pub place: Place,
    /// It is a program, script, document or archive (checked first).
    pub risky: bool,
}

/// Finds files that are new or changed since the tray started in every place where files
/// arrive (see [`Place`]), once they have stopped growing.
pub struct ArrivalWatcher {
    /// This user's id (for "own files only" places).
    uid: u32,
    /// The Downloads and desktop folders, refreshed once a minute.
    dirs: UserDirs,
    /// Files already handled, with the size and date they had then.
    known: HashMap<PathBuf, (u64, SystemTime)>,
    /// New/changed file -> (state when first seen, polls it stayed unchanged)
    pending: HashMap<PathBuf, ((u64, SystemTime), u32)>,
}

impl ArrivalWatcher {
    /// Start watching. Files already there are remembered, not checked (the daily scan covers
    /// the important folders). Places that appear later (a new app's Downloads folder,
    /// Firefox's temporary folder) start empty, so their first files are checked.
    pub fn new() -> Self {
        let uid = my_uid();
        let dirs = UserDirs::lookup();
        let known = arrival_roots(uid, &dirs)
            .iter()
            .flat_map(|r| snapshot(r, uid))
            .collect();
        Self {
            uid,
            dirs,
            known,
            pending: HashMap::new(),
        }
    }

    /// Call every few seconds. Returns files ready to check, risky ones first.
    pub fn poll(&mut self) -> Vec<Arrival> {
        if self.dirs.at.elapsed().as_secs() >= 60 {
            self.dirs = UserDirs::lookup();
        }
        let roots = arrival_roots(self.uid, &self.dirs);
        // File -> (size and date, which place). The first place listing a file wins.
        let mut now: HashMap<PathBuf, ((u64, SystemTime), usize)> = HashMap::new();
        for (i, r) in roots.iter().enumerate() {
            for (p, st) in snapshot(r, self.uid) {
                now.entry(p).or_insert((st, i));
            }
        }
        for (p, (st, _)) in &now {
            if self.known.get(p) != Some(st) {
                match self.pending.get_mut(p) {
                    Some((prev, n)) if prev == st => *n += 1,
                    Some((prev, n)) => {
                        *prev = *st;
                        *n = 0;
                    }
                    None => {
                        self.pending.insert(p.clone(), (*st, 0));
                    }
                }
            }
        }
        self.pending.retain(|p, _| now.contains_key(p));
        let ready: Vec<PathBuf> = self
            .pending
            .iter()
            .filter(|(_, (_, n))| *n >= 1)
            .map(|(p, _)| p.clone())
            .collect();
        let mut out = vec![];
        for p in ready {
            let Some((st, _)) = self.pending.remove(&p) else {
                continue;
            };
            self.known.insert(p.clone(), st);
            let root = &roots[now[&p].1];
            let Ok(md) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            // Only now, once per new file, is the content looked at.
            let risky = risk::risky(&p, &md);
            let hidden = p
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with('.'));
            if !risky && (root.risky_only || hidden || md.len() > MAX_SIZE) {
                continue;
            }
            out.push(Arrival {
                path: p,
                place: root.place,
                risky,
            });
        }
        // Forget deleted files.
        self.known.retain(|p, _| now.contains_key(p));
        out.sort_by_key(|a| !a.risky);
        out.truncate(MAX_BATCH);
        out
    }
}

// ------------------------------------------------------------------ recent arrivals

/// How long new files are remembered for a re-check with newer virus definitions.
const RECENT_DAYS: i64 = 7;
/// Most files remembered (the oldest are dropped first).
const RECENT_MAX: usize = 2000;
/// Shortest time between two re-checks (definitions can update several times a day).
pub const RECHECK_MIN_SECS: i64 = 4 * 3600;

/// Files that arrived in the last week, so they can be checked again when ClamAV gets new
/// virus definitions: a brand-new threat is often only recognized a day or two later. Saved in
/// `~/.local/share/proton-security/recent-arrivals.json`.
#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub struct RecentArrivals {
    /// Date of the virus definitions the files were last checked with (see [`defs_stamp`]).
    pub defs_stamp: i64,
    /// Unix time of the last re-check.
    pub last_recheck: i64,
    /// (path, see [`enc_path`]; Unix time it arrived), oldest first.
    pub files: Vec<(String, i64)>,
}

/// Where [`RecentArrivals`] is saved.
fn recent_path() -> PathBuf {
    sys::data_dir().join("recent-arrivals.json")
}

impl RecentArrivals {
    /// Read the list; missing or damaged gives an empty one.
    pub fn load() -> Self {
        sys::read(recent_path())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Write the list (atomically, via a temporary file).
    pub fn save(&self) {
        write_json(&recent_path(), self);
    }

    /// Add files, drop ones older than a week, keep at most [`RECENT_MAX`].
    pub fn add(&mut self, files: &[PathBuf], now: i64) {
        for f in files {
            let e = enc_path(f);
            self.files.retain(|(p, _)| *p != e);
            self.files.push((e, now));
        }
        self.prune(now);
    }

    /// Drop entries older than [`RECENT_DAYS`] and the oldest beyond [`RECENT_MAX`].
    pub fn prune(&mut self, now: i64) {
        self.files.retain(|(_, t)| now - *t <= RECENT_DAYS * 86400);
        if self.files.len() > RECENT_MAX {
            let extra = self.files.len() - RECENT_MAX;
            self.files.drain(..extra);
        }
    }

    /// Stop remembering these files.
    pub fn forget(&mut self, files: &[PathBuf]) {
        let gone: HashSet<String> = files.iter().map(|f| enc_path(f)).collect();
        self.files.retain(|(p, _)| !gone.contains(p));
    }

    /// The remembered files that still exist as regular files.
    pub fn existing(&self) -> Vec<PathBuf> {
        self.files
            .iter()
            .filter_map(|(p, _)| dec_path(p))
            .filter(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file()))
            .collect()
    }
}

/// Serializes changes to the recent-arrivals file (the download checks and the re-check run in
/// different threads of the tray).
static RECENT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Remember files that were just checked, for the re-check after the next definition update.
pub fn remember_arrivals(files: &[PathBuf], now: i64) {
    let _g = RECENT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = RecentArrivals::load();
    r.add(files, now);
    r.save();
}

/// Change the recent-arrivals record under the lock (`f` gets the loaded list).
pub fn update_recent(f: impl FnOnce(&mut RecentArrivals)) {
    let _g = RECENT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut r = RecentArrivals::load();
    f(&mut r);
    r.save();
}

/// When ClamAV's virus definitions last changed: the newest modification time (Unix seconds)
/// of the files in `/var/lib/clamav` (official `.cvd`/`.cld` databases and any extra signature
/// files), not counting freshclam's own bookkeeping. 0 when there are none.
pub fn defs_stamp() -> i64 {
    let Ok(rd) = std::fs::read_dir("/var/lib/clamav") else {
        return 0;
    };
    rd.flatten()
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            e.file_type().is_ok_and(|t| t.is_file())
                && !n.starts_with('.')
                && !matches!(n.as_ref(), "freshclam.dat" | "mirrors.dat")
                && !n.ends_with(".tmp")
        })
        .filter_map(|e| e.metadata().ok()?.modified().ok())
        .filter_map(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .max()
        .unwrap_or(0)
}

/// A path as text for saving in JSON, without losing anything: `u:` plus the name when it is
/// valid UTF-8, otherwise `x:` plus the bytes in hex.
pub fn enc_path(p: &Path) -> String {
    let b = p.as_os_str().as_bytes();
    match std::str::from_utf8(b) {
        Ok(s) => format!("u:{s}"),
        Err(_) => {
            let mut s = String::from("x:");
            for byte in b {
                s.push_str(&format!("{byte:02x}"));
            }
            s
        }
    }
}

/// Undo [`enc_path`]. `None` for anything that isn't an absolute path in that format.
pub fn dec_path(s: &str) -> Option<PathBuf> {
    let p = if let Some(u) = s.strip_prefix("u:") {
        PathBuf::from(u)
    } else {
        let h = s.strip_prefix("x:")?;
        if h.len() % 2 != 0 || !h.is_ascii() {
            return None;
        }
        let bytes = (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        PathBuf::from(std::ffi::OsString::from_vec(bytes))
    };
    p.is_absolute().then_some(p)
}

/// Save a value as JSON, readable only by the user, written to a temporary name and renamed so
/// a crash never leaves a half-written file.
pub fn write_json<T: Serialize>(path: &Path, v: &T) {
    use std::io::Write;
    let Ok(text) = serde_json::to_string(v) else {
        return;
    };
    let tmp = path.with_extension("json.tmp");
    let _ = std::fs::remove_file(&tmp);
    let ok = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .is_ok();
    if ok {
        let _ = std::fs::rename(&tmp, path);
    } else {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Result of a background scan.
#[derive(Debug, Default)]
pub struct ScanOutcome {
    /// Threats found.
    pub threats: Vec<Threat>,
    /// Files that could not be read or scanned.
    pub errors: u64,
    /// The scan could not run at all (not installed, no definitions, …).
    pub failed: Option<String>,
}

/// Scan files with clamd if it runs (fast), otherwise clamscan (slow start).
///
/// Plain names go to ClamAV in a private list (`--file-list`); a result counts only when it names
/// one of exactly those files. Files with unusual names (a line break, other control characters,
/// invalid UTF-8) can't be listed safely, so each is scanned through standard input instead.
/// See the "safe scanning" notes in `antivirus.rs`.
pub fn scan_files(files: &[PathBuf]) -> ScanOutcome {
    scan_files_with(files, Priority::Background)
}

/// How much the computer is allowed to notice a background scan.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Priority {
    /// New files and USB drives: the user waits for the answer, but the desktop comes first
    /// (low CPU priority, lowest normal disk priority).
    Background,
    /// Re-checks nobody waits for: only uses the CPU and disk when nothing else does.
    Idle,
}

/// [`scan_files`] with a chosen [`Priority`].
pub fn scan_files_with(files: &[PathBuf], priority: Priority) -> ScanOutcome {
    if files.is_empty() {
        return ScanOutcome::default();
    }
    let use_daemon =
        sys::systemctl_active("clamav-daemon.service") && sys::which("clamdscan").is_some();
    let cmd = if use_daemon { "clamdscan" } else { "clamscan" };
    let Some(exe) = sys::which(cmd) else {
        return ScanOutcome {
            failed: Some("ClamAV is not installed. Open Proton Security → Virus & threat protection to install it.".into()),
            ..Default::default()
        };
    };
    let (unusual, plain): (Vec<&PathBuf>, Vec<&PathBuf>) =
        files.iter().partition(|f| antivirus::unusual_name(f));
    let mut outcome = ScanOutcome::default();

    if !plain.is_empty() {
        let sent: HashSet<&Path> = plain.iter().map(|p| p.as_path()).collect();
        let mut list = match antivirus::FileList::create() {
            Ok(l) => l,
            Err(e) => {
                outcome.failed = Some(format!("Could not start the scan: {e}"));
                return outcome;
            }
        };
        for f in &plain {
            let _ = list.push(f);
        }
        if let Err(e) = list.flush() {
            outcome.failed = Some(format!("Could not start the scan: {e}"));
            return outcome;
        }
        let mut args: Vec<String> = vec![
            "--no-summary".into(),
            "--stdout".into(),
            format!("--file-list={}", list.path.to_string_lossy()),
        ];
        if use_daemon {
            args.insert(0, "--fdpass".into());
        } else {
            // clamscan skips files over 100 MB by default, which would leave big installers
            // (.AppImage, .iso) unchecked. Check files up to 2 GB, reading at most 512 MB of
            // each. (clamd uses its own limits from /etc/clamav/clamd.conf.)
            args.push("--max-filesize=2000M".into());
            args.push("--max-scansize=512M".into());
        }
        let mut c = low_priority(&exe, priority);
        let out = c
            .args(&args)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .output();
        drop(list); // deletes the list file
        let Ok(out) = out else {
            outcome.failed = Some("ClamAV could not run.".into());
            return outcome;
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let mut answered = 0;
        for line in stdout.lines() {
            match antivirus::parse_clam_line(line) {
                // Only results about a file we actually sent count.
                Some(antivirus::ClamLine::Found(p, sig)) if sent.contains(p.as_path()) => {
                    outcome.threats.push(Threat::new(&p, sig));
                    answered += 1;
                }
                Some(antivirus::ClamLine::Clean(p)) if sent.contains(p.as_path()) => answered += 1,
                Some(antivirus::ClamLine::Failed) => outcome.errors += 1,
                _ => {}
            }
        }
        // Exit code: 0 clean, 1 virus found, 2 error. With 2 and nothing answered, the scan
        // itself failed (no definitions, daemon down…).
        if out.status.code() == Some(2) && answered == 0 && outcome.errors == 0 {
            outcome.failed = Some(antivirus::explain_failure(&stderr));
            return outcome;
        }
    }

    for (i, f) in unusual.iter().enumerate() {
        if i >= antivirus::MAX_UNUSUAL {
            outcome.errors += (unusual.len() - i) as u64;
            break;
        }
        match antivirus::scan_via_stdin(f, use_daemon) {
            Ok(Some(sig)) => outcome.threats.push(Threat::new(f, sig)),
            Ok(None) => {}
            Err(_) => outcome.errors += 1,
        }
    }
    outcome
}

/// A command that runs `exe` with lower CPU (`nice`) and disk (`ionice`) priority, using
/// whichever of the two tools is installed.
fn low_priority(exe: &Path, priority: Priority) -> Command {
    let (nice, io): (&str, &[&str]) = match priority {
        Priority::Background => ("15", &["-c", "2", "-n", "7"]),
        Priority::Idle => ("19", &["-c", "3"]),
    };
    let mut c = if sys::which("ionice").is_some() {
        let mut c = Command::new("ionice");
        c.args(io);
        if sys::which("nice").is_some() {
            c.args(["nice", "-n", nice]);
        }
        c
    } else if sys::which("nice").is_some() {
        let mut c = Command::new("nice");
        c.args(["-n", nice]);
        c
    } else {
        return Command::new(exe);
    };
    c.arg(exe);
    c
}

/// Just the file name of a path, for notifications ("invoice.pdf"). Control characters are
/// shown as symbols (see [`antivirus::display_path`]).
pub fn file_name(p: &str) -> String {
    let name = Path::new(p)
        .file_name()
        .map(|n| Path::new(n).to_path_buf())
        .unwrap_or_else(|| PathBuf::from(p));
    antivirus::display_path(&name)
}

/// Save a background scan to the protection history.
pub fn record_scan(kind: &str, targets: Vec<String>, files: u64, outcome: &ScanOutcome) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut h = antivirus::load_history();
    h.push(ScanRecord {
        kind: kind.into(),
        started: now,
        finished: now,
        files,
        errors: outcome.errors,
        cancelled: false,
        targets,
        threats: outcome.threats.clone(),
        problem: outcome.failed.clone(),
    });
    antivirus::save_history(&h);
}

// ------------------------------------------------------------------ USB drives

/// Folders where the desktop opens removable drives.
fn removable_mount(path: &str) -> bool {
    path.starts_with("/media/") || path.starts_with("/run/media/")
}

/// Undo the octal escapes in /proc/mounts (`\040` is a space).
fn unescape_mount(s: &str) -> String {
    // /proc/mounts writes spaces etc. as \040.
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Mount points under /media or /run/media, where the desktop opens USB drives and memory
/// cards.
pub fn parse_mounts(text: &str) -> HashSet<PathBuf> {
    text.lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .map(unescape_mount)
        .filter(|m| removable_mount(m))
        .map(PathBuf::from)
        .collect()
}

/// Removable drives mounted right now.
fn mounts() -> HashSet<PathBuf> {
    #[cfg(debug_assertions)]
    if let Ok(f) = std::env::var("PROTON_SECURITY_FAKE_MOUNTS") {
        return parse_mounts(&sys::read(f).unwrap_or_default());
    }
    parse_mounts(&sys::read("/proc/self/mounts").unwrap_or_default())
}

/// Finds removable drives opened since the last poll.
pub struct MountWatcher {
    /// Drives mounted at the last poll.
    known: HashSet<PathBuf>,
}

impl MountWatcher {
    /// Start watching. Drives already open are not scanned.
    pub fn new() -> Self {
        // Drives already open when the tray starts are not scanned.
        Self { known: mounts() }
    }

    /// Call every few seconds. Returns drives opened since the last call.
    pub fn poll(&mut self) -> Vec<PathBuf> {
        let now = mounts();
        let new: Vec<PathBuf> = now.difference(&self.known).cloned().collect();
        self.known = now;
        new
    }
}

/// Most files a quick USB scan looks at.
pub const USB_MAX_FILES: usize = 3000;
/// Files bigger than this are skipped by the quick USB scan.
const USB_MAX_FILE: u64 = 100_000_000;
/// Photos, music and videos: big, and rarely carry viruses.
const MEDIA: [&str; 20] = [
    "jpg", "jpeg", "png", "gif", "heic", "webp", "raw", "cr2", "nef", "mp3", "flac", "wav", "ogg",
    "m4a", "mp4", "mkv", "mov", "avi", "wmv", "m4v",
];

/// Most entries looked at on a drive by the quick scan (folders and files).
const USB_MAX_ENTRIES: usize = 30_000;

/// Files to check on a USB drive, risky ones first.
///
/// Risky files (programs, scripts, Office files, PDFs, archives, by name or by content: a
/// program renamed `photo.jpg` counts) are always included, whatever their size. Other files
/// are included up to 100 MB, except photos, music and videos. At most [`USB_MAX_FILES`]
/// files; the second value is true when some were left out.
///
/// The executable bit isn't used here: FAT, exFAT and NTFS drives often mark every file as
/// runnable.
pub fn usb_files(root: &Path) -> (Vec<PathBuf>, bool) {
    let mut risky = vec![];
    let mut other = vec![];
    let mut truncated = false;
    for (n, e) in walkdir::WalkDir::new(root)
        .max_depth(6)
        .follow_links(false)
        .same_file_system(true)
        .into_iter()
        .filter_entry(|e| {
            // Skip system folders on Windows-formatted drives.
            let n = e.file_name().to_string_lossy().to_lowercase();
            !(e.depth() == 1 && (n == "system volume information" || n == "$recycle.bin"))
        })
        .flatten()
        .enumerate()
    {
        if n >= USB_MAX_ENTRIES || risky.len() >= USB_MAX_FILES {
            truncated = true;
            break;
        }
        if !e.file_type().is_file() {
            continue;
        }
        let Ok(md) = e.metadata() else { continue };
        if md.len() == 0 {
            continue;
        }
        let p = e.path();
        if risk::risky_name(p) || risk::risky_content(p) {
            risky.push(e.into_path());
            continue;
        }
        let ext = p
            .extension()
            .map(|x| x.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if !MEDIA.contains(&ext.as_str()) && md.len() <= USB_MAX_FILE {
            other.push(e.into_path());
        }
    }
    let room = USB_MAX_FILES.saturating_sub(risky.len());
    if other.len() > room {
        truncated = true;
        other.truncate(room);
    }
    risky.extend(other);
    (risky, truncated)
}

/// Name shown for a drive: its folder name ("KINGSTON").
pub fn drive_label(mount: &Path) -> String {
    mount
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "USB drive".into())
}

// ------------------------------------------------------------------ USB

/// The kinds of USB device worth telling the user about.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum UsbKind {
    /// Can type on the computer. A USB stick pretending to be a keyboard ("BadUSB") can type
    /// commands.
    Keyboard,
    /// Can change how the computer connects to networks.
    Network,
    /// A USB drive or card reader.
    Storage,
}

/// A newly plugged-in USB device to notify about.
#[derive(Clone, Debug)]
pub struct UsbAlert {
    /// What it is.
    pub kind: UsbKind,
    /// Its name from the device ("Kingston DataTraveler 3.0").
    pub name: String,
}

impl UsbAlert {
    /// Notification (title, text) for this device.
    pub fn message(&self) -> (String, String) {
        match self.kind {
            UsbKind::Keyboard => (
                "New keyboard connected".into(),
                format!(
                    "\"{}\" was plugged in and can type on this computer. If you did not connect a keyboard, unplug it now: it could be a malicious USB stick.",
                    self.name
                ),
            ),
            UsbKind::Network => (
                "New network adapter connected".into(),
                format!(
                    "\"{}\" can change how this computer connects to networks. Unplug it if you don't recognize it.",
                    self.name
                ),
            ),
            UsbKind::Storage => (
                "USB drive connected".into(),
                format!(
                    "\"{}\" will be checked for viruses automatically when you open it.",
                    self.name
                ),
            ),
        }
    }
}

/// Read a hexadecimal sysfs value such as `bInterfaceClass`.
fn hex(p: &Path) -> Option<u32> {
    sys::read_trim(p).and_then(|s| u32::from_str_radix(&s, 16).ok())
}

/// Where USB devices appear in sysfs.
fn usb_root() -> PathBuf {
    // Debug builds only: point at a fake sysfs tree for testing.
    #[cfg(debug_assertions)]
    if let Ok(d) = std::env::var("PROTON_SECURITY_FAKE_USB") {
        return PathBuf::from(d);
    }
    PathBuf::from("/sys/bus/usb/devices")
}

/// USB devices plugged in now: id -> (name, kinds). The id combines port, vendor, product and
/// serial number, so the same device in the same port keeps its id. The kind comes from the USB
/// interface classes: 0x03 protocol 1 = keyboard, 0x08 = storage, 0x02 / 0x0a / 0xe0 = network
/// (or any interface with a `net/` folder).
fn usb_devices() -> HashMap<String, (String, Vec<UsbKind>)> {
    let mut m = HashMap::new();
    let Ok(rd) = std::fs::read_dir(usb_root()) else {
        return m;
    };
    let entries: Vec<_> = rd
        .flatten()
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
        .collect();
    for (name, p) in &entries {
        if name.contains(':') || name.starts_with("usb") {
            continue;
        }
        let id = format!(
            "{name}:{}:{}:{}",
            sys::read_trim(p.join("idVendor")).unwrap_or_default(),
            sys::read_trim(p.join("idProduct")).unwrap_or_default(),
            sys::read_trim(p.join("serial")).unwrap_or_default()
        );
        let product = sys::read_trim(p.join("product")).unwrap_or_else(|| "USB device".into());
        let maker = sys::read_trim(p.join("manufacturer")).unwrap_or_default();
        let label = if maker.is_empty() || product.contains(&maker) {
            product
        } else {
            format!("{maker} {product}")
        };
        let mut kinds = vec![];
        for (iname, ip) in entries
            .iter()
            .filter(|(n, _)| n.starts_with(&format!("{name}:")))
        {
            let _ = iname;
            let class = hex(&ip.join("bInterfaceClass")).unwrap_or(0);
            let proto = hex(&ip.join("bInterfaceProtocol")).unwrap_or(0);
            let kind = match class {
                0x03 if proto == 1 => Some(UsbKind::Keyboard),
                0x08 => Some(UsbKind::Storage),
                0x02 | 0x0a | 0xe0 => Some(UsbKind::Network),
                _ => {
                    // Vendor-specific Wi-Fi/Ethernet adapters: they have a net/ directory.
                    std::fs::read_dir(ip).ok().and_then(|d| {
                        d.flatten()
                            .any(|e| e.file_name() == "net")
                            .then_some(UsbKind::Network)
                    })
                }
            };
            if let Some(k) = kind
                && !kinds.contains(&k)
            {
                kinds.push(k);
            }
        }
        m.insert(id, (label, kinds));
    }
    m
}

/// Notices newly plugged-in USB devices by comparing the sysfs list every few seconds.
pub struct UsbWatcher {
    /// Device ids seen at the last poll.
    known: HashSet<String>,
}

impl UsbWatcher {
    /// Start watching. Devices already plugged in don't alert.
    pub fn new() -> Self {
        // Devices plugged in before the tray started don't alert.
        Self {
            known: usb_devices().into_keys().collect(),
        }
    }

    /// Call every few seconds. Returns devices plugged in since the last call.
    pub fn poll(&mut self) -> Vec<UsbAlert> {
        let now = usb_devices();
        let mut alerts = vec![];
        for (id, (name, kinds)) in &now {
            if self.known.contains(id) {
                continue;
            }
            // Keyboard first: it is the most dangerous kind.
            for k in [UsbKind::Keyboard, UsbKind::Network, UsbKind::Storage] {
                if kinds.contains(&k) {
                    alerts.push(UsbAlert {
                        kind: k,
                        name: name.clone(),
                    });
                    break;
                }
            }
        }
        self.known = now.into_keys().collect();
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mounts_parse() {
        let m = parse_mounts(
            "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /media/ana/MY\\040USB vfat rw 0 0\n/dev/sdc1 /run/media/bob/CARD exfat rw 0 0\ntmpfs /run/user/1000 tmpfs rw 0 0\n",
        );
        assert!(m.contains(Path::new("/media/ana/MY USB")));
        assert!(m.contains(Path::new("/run/media/bob/CARD")));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn paths_round_trip() {
        use std::os::unix::ffi::OsStrExt;
        let odd = PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/a\nb\xff.sh"));
        for p in [PathBuf::from("/home/ana/Downloads/x y.pdf"), odd] {
            assert_eq!(dec_path(&enc_path(&p)).as_deref(), Some(p.as_path()));
        }
        assert!(dec_path("u:relative/path").is_none());
        assert!(dec_path("x:2f7").is_none());
        assert!(dec_path("/no/prefix").is_none());
    }

    #[test]
    fn recent_arrivals_expire() {
        let mut r = RecentArrivals::default();
        let day = 86400;
        r.add(&[PathBuf::from("/a")], 0);
        r.add(&[PathBuf::from("/b")], 5 * day);
        r.add(&[PathBuf::from("/a")], 6 * day); // seen again: moves to the end
        assert_eq!(r.files.len(), 2);
        r.prune(12 * day + 1);
        assert_eq!(r.files, vec![("u:/a".to_string(), 6 * day)]);
        r.forget(&[PathBuf::from("/a")]);
        assert!(r.files.is_empty());
    }

    #[test]
    fn usb_files_skip_media() {
        let d = std::env::temp_dir().join(format!("ps-usb-{}", std::process::id()));
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("setup.exe"), b"MZ").unwrap();
        std::fs::write(d.join("sub/report.docx"), b"PK").unwrap();
        std::fs::write(d.join("photo.JPG"), b"x").unwrap();
        std::fs::write(d.join("notes.txt"), b"hello").unwrap();
        // A program pretending to be a photo is found by its content.
        std::fs::write(d.join("sub/cat.jpg"), b"\x7fELF\x02\x01").unwrap();
        let (f, t) = usb_files(&d);
        assert_eq!(f.len(), 4);
        assert!(!t);
        // Risky files come first, the plain text file last.
        assert_eq!(f.last().unwrap().file_name().unwrap(), "notes.txt");
        assert!(f.iter().any(|p| p.ends_with("sub/cat.jpg")));
        let _ = std::fs::remove_dir_all(&d);
    }
}
