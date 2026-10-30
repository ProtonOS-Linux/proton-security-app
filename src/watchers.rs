// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Background watchers run by the tray (as the user, no administrator rights):
//! - scan new files in the Downloads folder with ClamAV
//! - quick-scan USB drives and memory cards when they are opened
//! - alert when a new USB keyboard, network adapter or drive is plugged in

use crate::antivirus::{self, ScanRecord, Threat};
use crate::sys;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

// ------------------------------------------------------------------ downloads

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
/// Files bigger than this are skipped (ClamAV's default limit is lower anyway).
const MAX_SIZE: u64 = 1_000_000_000;

/// The user's Downloads folder (`xdg-user-dir DOWNLOAD`, so it follows translated folder
/// names), or `~/Downloads`.
pub fn downloads_dir() -> PathBuf {
    if let Some(d) = sys::run_out("xdg-user-dir", &["DOWNLOAD"]) {
        let d = PathBuf::from(d.trim());
        if d.is_dir() && d != sys::home() {
            return d;
        }
    }
    sys::home().join("Downloads")
}

/// Size and modification time of every finished file in `dir` and its direct subfolders. Hidden
/// files, browser partial downloads and files over [`MAX_SIZE`] are left out.
fn snapshot(dir: &Path) -> HashMap<PathBuf, (u64, SystemTime)> {
    let mut m = HashMap::new();
    for e in walkdir::WalkDir::new(dir)
        .max_depth(2)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| e.depth() == 0 || !e.file_name().to_string_lossy().starts_with('.'))
        .flatten()
    {
        if !e.file_type().is_file() {
            continue;
        }
        let p = e.path();
        let ext = p
            .extension()
            .map(|x| x.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if PARTIAL.contains(&ext.as_str()) {
            continue;
        }
        if let Ok(md) = e.metadata()
            && md.len() > 0
            && md.len() <= MAX_SIZE
        {
            m.insert(
                p.to_path_buf(),
                (md.len(), md.modified().unwrap_or(UNIX_EPOCH)),
            );
        }
    }
    m
}

/// Finds files that are new or changed since the tray started, once they have
/// stopped growing.
pub struct DownloadWatcher {
    /// The Downloads folder.
    dir: PathBuf,
    /// Files already handled, with the size and date they had then.
    known: HashMap<PathBuf, (u64, SystemTime)>,
    /// New/changed file -> (state when first seen, polls it stayed unchanged)
    pending: HashMap<PathBuf, ((u64, SystemTime), u32)>,
}

impl DownloadWatcher {
    /// Start watching. Files already in Downloads are remembered, not scanned.
    pub fn new() -> Self {
        let dir = downloads_dir();
        // Files already there are not scanned again (the daily scan covers them).
        let known = snapshot(&dir);
        Self {
            dir,
            known,
            pending: HashMap::new(),
        }
    }

    /// Call every few seconds. Returns files ready to scan.
    pub fn poll(&mut self) -> Vec<PathBuf> {
        let now = snapshot(&self.dir);
        for (p, st) in &now {
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
        for p in &ready {
            if let Some((st, _)) = self.pending.remove(p) {
                self.known.insert(p.clone(), st);
            }
        }
        // Forget deleted files.
        self.known.retain(|p, _| now.contains_key(p));
        ready
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

/// Turn clamscan's error output into a sentence for a notification.
fn explain_failure(stderr: &str) -> String {
    let s = stderr.to_lowercase();
    if s.contains("no supported database") || s.contains("cli_loaddb") || s.contains("database") {
        "The virus definitions are missing. Open Proton Security → Virus & threat protection and click \"Check for updates\".".into()
    } else if let Some(l) = stderr.lines().find(|l| !l.trim().is_empty()) {
        format!("ClamAV reported: {}", l.trim())
    } else {
        "ClamAV could not run.".into()
    }
}

/// Scan files with clamd if it runs (fast), otherwise clamscan (slow start).
///
/// Plain names go to ClamAV in a private list (`--file-list`); a result counts only when it names
/// one of exactly those files. Files with unusual names (a line break, other control characters,
/// invalid UTF-8) can't be listed safely, so each is scanned through standard input instead.
/// See the "safe scanning" notes in `antivirus.rs`.
pub fn scan_files(files: &[PathBuf]) -> ScanOutcome {
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
        }
        let mut c = if sys::which("nice").is_some() {
            let mut c = Command::new("nice");
            c.args(["-n", "15"]).arg(&exe);
            c
        } else {
            Command::new(&exe)
        };
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
            outcome.failed = Some(explain_failure(&stderr));
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

/// Files to check on a USB drive: everything that can run or open as a
/// document first (programs, scripts, Office files, archives), photos and
/// videos are skipped.
pub fn usb_files(root: &Path) -> (Vec<PathBuf>, bool) {
    let mut files = vec![];
    let mut truncated = false;
    for e in walkdir::WalkDir::new(root)
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
    {
        if !e.file_type().is_file() {
            continue;
        }
        let ext = e
            .path()
            .extension()
            .map(|x| x.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if MEDIA.contains(&ext.as_str()) {
            continue;
        }
        if let Ok(md) = e.metadata()
            && md.len() > 0
            && md.len() <= USB_MAX_FILE
        {
            if files.len() >= USB_MAX_FILES {
                truncated = true;
                break;
            }
            files.push(e.into_path());
        }
    }
    (files, truncated)
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
    fn usb_files_skip_media() {
        let d = std::env::temp_dir().join(format!("ps-usb-{}", std::process::id()));
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("setup.exe"), b"MZ").unwrap();
        std::fs::write(d.join("sub/report.docx"), b"PK").unwrap();
        std::fs::write(d.join("photo.JPG"), b"x").unwrap();
        let (f, t) = usb_files(&d);
        assert_eq!(f.len(), 2);
        assert!(!t);
        let _ = std::fs::remove_dir_all(&d);
    }
}
