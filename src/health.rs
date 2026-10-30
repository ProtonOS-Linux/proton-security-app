// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Device performance & health: pending restart, disk space, disk health
//! (SMART via UDisks2) and battery. Read as the normal user.

use crate::sys;
use std::cmp::Ordering;
use std::path::Path;

/// Warn when a disk has less free space than this...
pub const LOW_SPACE_BYTES: u64 = 5_000_000_000;
/// ...or less than this fraction free.
pub const LOW_SPACE_FRACTION: f64 = 0.10;

/// Whether the computer should be restarted, and why.
#[derive(Clone, Debug, Default)]
pub struct Restart {
    /// True when a restart is recommended (the tile turns yellow).
    pub required: bool,
    /// One sentence per reason, shown on the Health page.
    pub reasons: Vec<String>,
    /// Only because of a long uptime (no updates waiting).
    pub long_uptime: bool,
}

/// Free space on one mounted filesystem (`/`, and `/home` if separate).
#[derive(Clone, Debug)]
pub struct DiskSpace {
    /// Mount point.
    pub mount: String,
    /// Total size in bytes.
    pub size: u64,
    /// Bytes available to normal users (what `df` calls "Available").
    pub free: u64,
}

impl DiskSpace {
    /// Low when under 5 GB free, or under 10% free on a disk where that is
    /// also less than 15 GB (big disks with 20+ GB free are fine).
    pub fn low(&self) -> bool {
        self.size > 0
            && (self.free < LOW_SPACE_BYTES
                || ((self.free as f64) < self.size as f64 * LOW_SPACE_FRACTION
                    && self.free < 15_000_000_000))
    }
    /// Used space from 0.0 to 1.0, for the progress bar.
    pub fn used_fraction(&self) -> f32 {
        if self.size == 0 {
            0.0
        } else {
            1.0 - self.free as f32 / self.size as f32
        }
    }
}

/// Health of one physical disk as reported by the disk itself (SMART), read through UDisks2.
#[derive(Clone, Debug, Default)]
pub struct DriveHealth {
    /// Model name, for example "Samsung SSD 980 1TB".
    pub model: String,
    /// Capacity in bytes.
    pub size: u64,
    /// The disk itself says it is failing (SMART "failing" or an NVMe critical warning).
    pub failing: bool,
    /// The disk reports SMART data.
    pub smart: bool,
    /// Current temperature in °C.
    pub temperature_c: Option<f64>,
    /// Total hours the disk has been powered on.
    pub power_on_hours: Option<u64>,
    /// NVMe: percentage of rated life used.
    pub wear_percent: Option<u64>,
    /// ATA: reallocated + pending sectors. NVMe: media and data integrity errors.
    pub bad_sectors: Option<u64>,
    /// NVMe drives report errors instead of sectors.
    pub nvme: bool,
    /// UDisks2 object path.
    pub object: String,
    /// Sentences explaining each problem found.
    pub warnings: Vec<String>,
}

impl DriveHealth {
    /// "Bad sectors: 0" style line, if the drive reports it.
    pub fn bad_sectors_text(&self) -> Option<String> {
        let n = self.bad_sectors?;
        Some(if self.nvme {
            format!("Media errors: {n}")
        } else {
            format!("Bad sectors: {n}")
        })
    }
}

/// Laptop battery wear, from /sys/class/power_supply.
#[derive(Clone, Debug, Default)]
pub struct Battery {
    /// Battery model name.
    pub name: String,
    /// Capacity when full, compared with when new (design capacity).
    pub health_percent: Option<f64>,
    /// Charge cycles, if the battery reports them.
    pub cycles: Option<u64>,
    /// Current charge in percent.
    pub charge: Option<u64>,
}

/// Everything shown on the Device performance & health page.
#[derive(Clone, Debug, Default)]
pub struct Health {
    /// Restart recommendation.
    pub restart: Restart,
    /// Free space per filesystem.
    pub disks: Vec<DiskSpace>,
    /// Health of each physical disk.
    pub drives: Vec<DriveHealth>,
    /// UDisks2 is not available, so disk health is unknown.
    pub smart_unavailable: bool,
    /// Laptop batteries (empty on desktops).
    pub batteries: Vec<Battery>,
    /// RAM in bytes.
    pub memory_total: u64,
    /// RAM available for new programs, in bytes.
    pub memory_available: u64,
    /// Seconds since the computer started.
    pub uptime_secs: u64,
    /// Size of the user's trash.
    pub trash_bytes: u64,
    /// Size of the picture preview cache.
    pub thumbnails_bytes: u64,
}

impl Health {
    /// Filesystems that are low on space.
    pub fn low_disks(&self) -> Vec<&DiskSpace> {
        self.disks.iter().filter(|d| d.low()).collect()
    }
    /// Disks that report they are failing.
    pub fn failing_drives(&self) -> Vec<&DriveHealth> {
        self.drives.iter().filter(|d| d.failing).collect()
    }
    /// A battery that holds less than 40% of its original charge, if any.
    pub fn worn_battery(&self) -> Option<&Battery> {
        self.batteries
            .iter()
            .find(|b| b.health_percent.map(|h| h < 40.0).unwrap_or(false))
    }
}

// ------------------------------------------------------------------ restart

/// Compare kernel versions like "6.12.48+deb13-amd64" numerically.
pub fn cmp_version(a: &str, b: &str) -> Ordering {
    let parts = |s: &str| -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    };
    parts(a).cmp(&parts(b))
}

/// Is a restart recommended? Three reasons are checked:
/// - Debian's `/run/reboot-required` flag (written by updates such as a new kernel or libc);
/// - a newer kernel in /boot than the one running;
/// - more than [`RESTART_AFTER_DAYS`] days since the last restart.
pub fn restart() -> Restart {
    let mut r = Restart::default();
    if Path::new("/var/run/reboot-required").exists() || Path::new("/run/reboot-required").exists()
    {
        r.required = true;
        let pkgs = sys::read("/run/reboot-required.pkgs")
            .or_else(|| sys::read("/var/run/reboot-required.pkgs"))
            .unwrap_or_default();
        let list: Vec<&str> = pkgs.lines().filter(|l| !l.is_empty()).collect();
        r.reasons.push(if list.is_empty() {
            "Updates were installed that need a restart.".into()
        } else {
            format!("Updated: {}", list.join(", "))
        });
    }
    // A newer kernel installed than the one running.
    let running = sys::read_trim("/proc/sys/kernel/osrelease").unwrap_or_default();
    let newest = std::fs::read_dir("/boot")
        .map(|d| {
            d.flatten()
                .filter_map(|e| {
                    e.file_name()
                        .to_str()?
                        .strip_prefix("vmlinuz-")
                        .map(String::from)
                })
                .max_by(|a, b| cmp_version(a, b))
        })
        .ok()
        .flatten();
    if let Some(n) = newest
        && !running.is_empty()
        && cmp_version(&n, &running) == Ordering::Greater
    {
        r.required = true;
        r.reasons.push(format!(
            "A new Linux kernel ({n}) is installed. You are running {running}."
        ));
    }
    let days = uptime_secs() / 86400;
    if days >= RESTART_AFTER_DAYS {
        r.required = true;
        r.long_uptime = true;
        r.reasons.push(format!(
            "Your computer hasn't been restarted in {days} days. Restarting regularly keeps it fast and applies updates."
        ));
    }
    r
}

impl Restart {
    /// One sentence for the tile and the Health page.
    pub fn headline(&self) -> String {
        if self.long_uptime && self.reasons.len() == 1 {
            format!(
                "Your computer hasn't been restarted in {} days.",
                uptime_secs() / 86400
            )
        } else {
            "Restart your computer to finish installing updates.".into()
        }
    }
}

/// Suggest a restart after this many days without one.
pub const RESTART_AFTER_DAYS: u64 = 15;

/// Seconds since boot, from /proc/uptime.
pub fn uptime_secs() -> u64 {
    #[cfg(debug_assertions)]
    if let Some(d) = std::env::var("PROTON_SECURITY_FAKE_UPTIME_DAYS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return d * 86400;
    }
    sys::read("/proc/uptime")
        .and_then(|t| t.split('.').next().and_then(|v| v.parse().ok()))
        .unwrap_or(0)
}

// ------------------------------------------------------------------ disk space

/// Free space on `/` and `/home` (`df`), listed once when they are the same filesystem.
pub fn disk_space() -> Vec<DiskSpace> {
    let mut v: Vec<DiskSpace> = vec![];
    let out = sys::run_out("df", &["-P", "-B1", "/", "/home"]).unwrap_or_default();
    for l in out.lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 6 {
            continue;
        }
        let mount = f[5..].join(" ");
        // /home on the same filesystem as / shows up as "/".
        if v.iter().any(|d| d.mount == mount) {
            continue;
        }
        v.push(DiskSpace {
            mount,
            size: f[1].parse().unwrap_or(0),
            free: f[3].parse().unwrap_or(0),
        });
    }
    v
}

/// Total size of all files under a folder (symlinks are not followed).
fn dir_size(p: &Path) -> u64 {
    walkdir::WalkDir::new(p)
        .follow_links(false)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

/// The user's trash folder (freedesktop.org Trash specification).
pub fn trash_dir() -> std::path::PathBuf {
    sys::home().join(".local/share/Trash")
}

/// The user's thumbnail cache (re-created automatically when needed).
pub fn thumbnails_dir() -> std::path::PathBuf {
    sys::home().join(".cache/thumbnails")
}

/// Empty this user's trash and thumbnail cache (no administrator rights).
pub fn clean_user_files() -> u64 {
    let before = dir_size(&trash_dir()) + dir_size(&thumbnails_dir());
    for sub in ["files", "info", "expunged"] {
        let d = trash_dir().join(sub);
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                let _ = if p.is_dir() {
                    std::fs::remove_dir_all(&p)
                } else {
                    std::fs::remove_file(&p)
                };
            }
        }
    }
    let _ = std::fs::remove_file(trash_dir().join("metadata"));
    let _ = std::fs::remove_dir_all(thumbnails_dir());
    let after = dir_size(&trash_dir()) + dir_size(&thumbnails_dir());
    before.saturating_sub(after)
}

// ------------------------------------------------------------------ SMART (UDisks2)

/// Parse `udisksctl dump` into drives.
pub fn parse_udisks_dump(text: &str) -> Vec<DriveHealth> {
    let mut drives: Vec<DriveHealth> = vec![];
    let mut in_drive_obj = false;
    let mut iface = String::new();
    for line in text.lines() {
        if !line.starts_with(' ') && line.ends_with(':') {
            in_drive_obj = line.starts_with("/org/freedesktop/UDisks2/drives/");
            if in_drive_obj {
                drives.push(DriveHealth {
                    object: line.trim_end_matches(':').to_string(),
                    ..Default::default()
                });
            }
            iface.clear();
            continue;
        }
        if !in_drive_obj {
            continue;
        }
        let t = line.trim();
        if line.starts_with("  ") && !line.starts_with("    ") && t.ends_with(':') {
            iface = t.trim_end_matches(':').to_string();
            continue;
        }
        let Some((k, v)) = t.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        let d = drives.last_mut().unwrap();
        match (iface.as_str(), k) {
            ("org.freedesktop.UDisks2.Drive", "Model") => d.model = v.to_string(),
            ("org.freedesktop.UDisks2.Drive", "Size") => d.size = v.parse().unwrap_or(0),
            ("org.freedesktop.UDisks2.Drive.Ata", "SmartEnabled") => d.smart = v == "true",
            ("org.freedesktop.UDisks2.Drive.Ata", "SmartFailing") => {
                if v == "true" {
                    d.failing = true;
                    d.warnings
                        .push("The drive reports it is likely to fail soon.".into());
                }
            }
            ("org.freedesktop.UDisks2.Drive.Ata", "SmartTemperature") => {
                // Kelvin
                d.temperature_c = v
                    .parse::<f64>()
                    .ok()
                    .filter(|k| *k > 0.0)
                    .map(|k| k - 273.15);
            }
            ("org.freedesktop.UDisks2.Drive.Ata", "SmartPowerOnSeconds") => {
                d.power_on_hours = v.parse::<u64>().ok().filter(|s| *s > 0).map(|s| s / 3600);
            }
            ("org.freedesktop.UDisks2.Drive.Ata", "SmartNumBadSectors") => {
                if let Ok(n) = v.parse::<u64>() {
                    d.bad_sectors = Some(n);
                    if n > 0 {
                        d.warnings.push(format!(
                            "{n} bad sector(s) found: parts of the disk can no longer store data reliably."
                        ));
                    }
                }
            }
            ("org.freedesktop.UDisks2.NVMe.Controller", "SmartCriticalWarning") => {
                d.smart = true;
                d.nvme = true;
                let w = v.trim_matches(|c| c == '[' || c == ']').trim();
                if !w.is_empty() {
                    d.failing = true;
                    d.warnings.push(format!("Critical warning: {w}"));
                }
            }
            ("org.freedesktop.UDisks2.NVMe.Controller", "SmartTemperature") => {
                d.temperature_c = v
                    .parse::<f64>()
                    .ok()
                    .filter(|k| *k > 0.0)
                    .map(|k| k - 273.15);
            }
            ("org.freedesktop.UDisks2.NVMe.Controller", "SmartPowerOnHours") => {
                d.power_on_hours = v.parse().ok();
            }
            ("org.freedesktop.UDisks2.NVMe.Controller", "SmartPercentUsed") => {
                d.wear_percent = v.parse().ok();
                if d.wear_percent.map(|p| p >= 100).unwrap_or(false) {
                    d.warnings
                        .push("The drive has reached its rated lifetime.".into());
                }
            }
            _ => {}
        }
    }
    // Skip card readers / optical drives that report nothing useful.
    drives.retain(|d| d.size > 0);
    drives
}

// ------------------------------------------------------------------ battery & system

/// Laptop batteries. Batteries of devices (mice, keyboards) are skipped.
fn batteries() -> Vec<Battery> {
    let Ok(rd) = std::fs::read_dir("/sys/class/power_supply") else {
        return vec![];
    };
    rd.flatten()
        .filter_map(|e| {
            let p = e.path();
            if sys::read_trim(p.join("type")).as_deref() != Some("Battery")
                || sys::read_trim(p.join("scope")).as_deref() == Some("Device")
            {
                return None;
            }
            let num = |f: &str| sys::read_trim(p.join(f)).and_then(|s| s.parse::<f64>().ok());
            let full = num("energy_full").or_else(|| num("charge_full"));
            let design = num("energy_full_design").or_else(|| num("charge_full_design"));
            Some(Battery {
                name: sys::read_trim(p.join("model_name"))
                    .unwrap_or_else(|| e.file_name().to_string_lossy().into_owned()),
                health_percent: match (full, design) {
                    (Some(f), Some(d)) if d > 0.0 => Some((f / d * 100.0).min(100.0)),
                    _ => None,
                },
                cycles: num("cycle_count").map(|c| c as u64).filter(|c| *c > 0),
                charge: num("capacity").map(|c| c as u64),
            })
        })
        .collect()
}

/// (total, available) memory in bytes from /proc/meminfo.
fn meminfo() -> (u64, u64) {
    let t = sys::read("/proc/meminfo").unwrap_or_default();
    let get = |k: &str| {
        t.lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
            * 1024
    };
    (get("MemTotal:"), get("MemAvailable:"))
}

/// NVMe media errors are only available through SmartGetAttributes.
fn nvme_media_errors(object: &str) -> Option<u64> {
    let out = sys::run_out(
        "busctl",
        &[
            "--system",
            "--json=short",
            "call",
            "org.freedesktop.UDisks2",
            object,
            "org.freedesktop.UDisks2.NVMe.Controller",
            "SmartGetAttributes",
            "a{sv}",
            "0",
        ],
    )?;
    parse_nvme_media_errors(&out)
}

/// Read `media_errors` from busctl's JSON answer to `SmartGetAttributes`.
fn parse_nvme_media_errors(json: &str) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_str(json.trim()).ok()?;
    // {"type":"a{sv}","data":[{"media_errors":{"type":"t","data":0},...}]}
    v["data"].get(0)?.get("media_errors")?.get("data")?.as_u64()
}

/// Read everything for the Health page. Takes up to a second (disk health asks every disk), so
/// it runs on a background thread.
pub fn load() -> Health {
    let dump = sys::run_full("udisksctl", &["dump"]);
    let (drives, smart_unavailable) = match dump {
        Some((true, out, _)) => {
            let mut drives = parse_udisks_dump(&out);
            for d in drives.iter_mut().filter(|d| d.nvme) {
                d.bad_sectors = nvme_media_errors(&d.object);
                if let Some(n) = d.bad_sectors.filter(|n| *n > 0) {
                    d.warnings.push(format!(
                        "{n} media error(s): the drive could not read or write some data."
                    ));
                }
            }
            (drives, false)
        }
        _ => (vec![], true),
    };
    let (memory_total, memory_available) = meminfo();
    Health {
        restart: restart(),
        disks: disk_space(),
        drives,
        smart_unavailable,
        batteries: batteries(),
        memory_total,
        memory_available,
        uptime_secs: uptime_secs(),
        trash_bytes: dir_size(&trash_dir()),
        thumbnails_bytes: dir_size(&thumbnails_dir()),
    }
}

/// Ask Plasma to show its restart dialog; fall back to logind.
pub fn request_restart() -> bool {
    for q in ["qdbus6", "qdbus", "qdbus-qt6"] {
        if sys::which(q).is_some()
            && sys::run_full(
                q,
                &[
                    "org.kde.LogoutPrompt",
                    "/LogoutPrompt",
                    "org.kde.LogoutPrompt.promptReboot",
                ],
            )
            .map(|r| r.0)
            .unwrap_or(false)
        {
            return true;
        }
    }
    sys::spawn_detached("systemctl", &["reboot"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvme_media_errors_json() {
        let j = r#"{"type":"a{sv}","data":[{"percent_used":{"type":"y","data":3},"media_errors":{"type":"t","data":7}}]}"#;
        assert_eq!(parse_nvme_media_errors(j), Some(7));
        assert_eq!(
            parse_nvme_media_errors(r#"{"type":"a{sv}","data":[{}]}"#),
            None
        );
    }

    #[test]
    fn kernel_versions() {
        assert_eq!(
            cmp_version("6.12.48+deb13-amd64", "6.12.41+deb13-amd64"),
            Ordering::Greater
        );
        assert_eq!(cmp_version("6.10.1", "6.9.12"), Ordering::Greater);
        assert_eq!(
            cmp_version("6.12.48+deb13-amd64", "6.12.48+deb13-amd64"),
            Ordering::Equal
        );
    }

    #[test]
    fn udisks_dump() {
        let d = "/org/freedesktop/UDisks2/drives/Samsung_SSD_870:
  org.freedesktop.UDisks2.Drive:
    Model:                      Samsung SSD 870 EVO 500GB
    Size:                       500107862016
  org.freedesktop.UDisks2.Drive.Ata:
    SmartEnabled:               true
    SmartFailing:               false
    SmartNumBadSectors:         0
    SmartPowerOnSeconds:        36000000
    SmartTemperature:           308.15000000000003

/org/freedesktop/UDisks2/drives/WD_Blue:
  org.freedesktop.UDisks2.Drive:
    Model:                      WDC WD10EZEX
    Size:                       1000204886016
  org.freedesktop.UDisks2.Drive.Ata:
    SmartEnabled:               true
    SmartFailing:               true
    SmartNumBadSectors:         12

/org/freedesktop/UDisks2/drives/KINGSTON_NVMe:
  org.freedesktop.UDisks2.Drive:
    Model:                      KINGSTON SNV2S1000G
    Size:                       1000204886016
  org.freedesktop.UDisks2.NVMe.Controller:
    SmartCriticalWarning:       []
    SmartPercentUsed:           3
    SmartPowerOnHours:          1520

/org/freedesktop/UDisks2/block_devices/sda:
  org.freedesktop.UDisks2.Block:
    Size:                       500107862016
";
        let v = parse_udisks_dump(d);
        assert_eq!(v.len(), 3);
        assert!(!v[0].failing);
        assert_eq!(v[0].power_on_hours, Some(10000));
        assert_eq!(v[0].temperature_c.map(|t| t.round() as i64), Some(35));
        assert!(v[1].failing);
        assert_eq!(v[1].warnings.len(), 2);
        assert!(!v[2].failing);
        assert_eq!(v[2].wear_percent, Some(3));
    }
}
