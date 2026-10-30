// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Snapper restore points (snapshots) and their schedule.
//!
//! Everything here runs as the normal user. The schedule is detected from
//! systemd timers and cron (readable by everyone). The snapshot list itself
//! is only readable by root unless Snapper allows the user, so the app asks
//! for the password only when the user clicks "Show restore points".

use crate::sys;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::SystemTime;

/// One Snapper restore point, as listed by `snapper --jsonout list`.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// Snapper configuration it belongs to (`root`, `home`).
    pub config: String,
    /// Snapshot number within its configuration.
    pub number: u64,
    /// `single`, `pre` or `post` (pre/post pairs are made around package installs).
    pub kind: String,
    /// For a `post` snapshot: the matching `pre` snapshot.
    pub pre_number: Option<u64>,
    /// Creation time as Snapper prints it (`2026-10-23 00:00:03`, local time).
    pub date: String,
    /// Who created it (usually root).
    pub user: String,
    /// Cleanup algorithm (`number`, `timeline`…), i.e. when Snapper deletes it again.
    pub cleanup: String,
    /// Free text, for example "weekly restore point" or the apt command.
    pub description: String,
    /// Extra key=value data attached to the snapshot.
    pub userdata: String,
    /// The system boots into this snapshot by default.
    pub default: bool,
    /// The system is running from this snapshot now.
    pub active: bool,
}

impl Snapshot {
    /// Creation time, parsed from [`Snapshot::date`].
    pub fn time(&self) -> Option<SystemTime> {
        parse_snapper_date(&self.date)
    }
}

/// An automatic restore point schedule found on the system.
#[derive(Clone, Debug)]
pub struct Schedule {
    /// Where it comes from: a systemd timer or a cron file.
    pub source: String,
    /// Human readable, e.g. "Every Friday at 3:00 AM".
    pub when: String,
    /// Next run, if known.
    pub next: Option<String>,
}

/// How the snapshot list was obtained.
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub enum ListSource {
    /// Not read yet.
    #[default]
    None,
    /// Read with administrator permission after the user asked for it.
    Admin,
    /// `snapper list` worked as the current user (ALLOW_USERS / ALLOW_GROUPS).
    Direct,
}

/// Everything shown on the Restore & backup page and the System restore tile.
#[derive(Clone, Debug, Default)]
pub struct RestoreState {
    /// Snapper is installed.
    pub installed: bool,
    /// Filesystem of `/`; restore points need Btrfs.
    pub root_fs: String,
    /// Snapper configurations (`root`, `home`…).
    pub configs: Vec<String>,
    /// Settings of each config (only when the config files are readable).
    pub config_values: BTreeMap<String, BTreeMap<String, String>>,
    /// Restore points, once they were read.
    pub snapshots: Vec<Snapshot>,
    /// How `snapshots` were read.
    pub source: ListSource,
    /// Snapshots could not be read without a password.
    pub needs_admin: bool,
    /// Why reading the list failed, in words.
    pub error: Option<String>,
    /// Btrfs Assistant (a GUI for restoring) is installed.
    pub assistant_installed: bool,
    /// Automatic schedules that create restore points.
    pub schedules: Vec<Schedule>,
}

impl RestoreState {
    /// True when `/` is Btrfs (required for Snapper restore points).
    pub fn btrfs(&self) -> bool {
        self.root_fs == "btrfs"
    }
    /// True when at least one Snapper configuration exists.
    pub fn configured(&self) -> bool {
        !self.configs.is_empty()
    }
    /// The newest restore point.
    pub fn latest(&self) -> Option<&Snapshot> {
        self.snapshots.iter().max_by_key(|s| s.time())
    }
    /// Timeline is explicitly switched off in the root config.
    pub fn timeline_disabled_in_config(&self) -> bool {
        self.config_values
            .get("root")
            .and_then(|c| c.get("TIMELINE_CREATE"))
            .map(|v| v == "no")
            .unwrap_or(false)
    }
    /// Schedules that actually create restore points.
    pub fn effective_schedules(&self) -> Vec<&Schedule> {
        let timeline_off = self.timeline_disabled_in_config();
        self.schedules
            .iter()
            .filter(|s| !(timeline_off && s.source == "snapper-timeline.timer"))
            .collect()
    }
    /// True when a restore point is at most `days` old.
    pub fn has_recent(&self, days: f64) -> bool {
        self.latest()
            .and_then(|s| s.time())
            .map(|t| sys::age_days(t) <= days)
            .unwrap_or(false)
    }
}

/// Command that starts Btrfs Assistant (the launcher asks for the password itself).
pub fn assistant_command() -> Option<&'static str> {
    ["btrfs-assistant-launcher", "btrfs-assistant"]
        .into_iter()
        .find(|c| sys::which(c).is_some())
}

/// Parse Snapper's local date format.
pub fn parse_snapper_date(d: &str) -> Option<SystemTime> {
    use chrono::{Local, NaiveDateTime, TimeZone};
    let nd = NaiveDateTime::parse_from_str(d.trim(), "%Y-%m-%d %H:%M:%S").ok()?;
    Local.from_local_datetime(&nd).earliest().map(Into::into)
}

// ------------------------------------------------------------------ list parsing

/// Parse `snapper --jsonout list` output: `{ "<config>": [ {..}, .. ], .. }`
pub fn parse_list(json: &str) -> Result<Vec<Snapshot>, String> {
    // pkexec output may contain stray lines before the JSON object.
    let start = json.find('{').ok_or("No data returned by snapper.")?;
    let v: Value = serde_json::from_str(&json[start..])
        .map_err(|e| format!("Could not read snapper output: {e}"))?;
    parse_list_value(&v)
}

/// Collect the snapshots of every configuration in Snapper's JSON. Snapshot 0 ("current", the
/// live system) is skipped.
fn parse_list_value(v: &Value) -> Result<Vec<Snapshot>, String> {
    let obj = v.as_object().ok_or("Unexpected snapper output.")?;
    let mut out = vec![];
    for (config, list) in obj {
        let Some(arr) = list.as_array() else { continue };
        for s in arr {
            let number = s.get("number").and_then(Value::as_u64).unwrap_or(0);
            if number == 0 {
                continue; // "current" pseudo snapshot
            }
            let st = |k: &str| s.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            let userdata = match s.get("userdata") {
                Some(Value::Object(m)) => m
                    .iter()
                    .map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or("")))
                    .collect::<Vec<_>>()
                    .join(", "),
                _ => String::new(),
            };
            out.push(Snapshot {
                config: config.clone(),
                number,
                kind: s
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("single")
                    .to_string(),
                pre_number: s.get("pre-number").and_then(Value::as_u64),
                date: st("date"),
                user: st("user"),
                cleanup: st("cleanup"),
                description: st("description"),
                userdata,
                default: s.get("default").and_then(Value::as_bool).unwrap_or(false),
                active: s.get("active").and_then(Value::as_bool).unwrap_or(false),
            });
        }
    }
    out.sort_by(|a, b| b.date.cmp(&a.date).then(b.number.cmp(&a.number)));
    Ok(out)
}

/// Run `snapper --jsonout list` as the current user, trying newer options first and older ones
/// when Snapper doesn't know them. Returns (success, stdout, stderr).
fn snapper_list_json() -> Option<(bool, String, String)> {
    // Newer snapper: list every config at once, skip the slow used-space query.
    let tries: [&[&str]; 3] = [
        &["--jsonout", "list", "--all-configs", "--disable-used-space"],
        &["--jsonout", "list", "--all-configs"],
        &["--jsonout", "list"],
    ];
    let mut last = None;
    for args in tries {
        let r = sys::run_full("snapper", args)?;
        let unknown_opt = !r.0
            && (r.2.contains("Unknown option")
                || r.2.contains("unrecognized")
                || r.2.contains("invalid option"));
        if !unknown_opt {
            return Some(r);
        }
        last = Some(r);
    }
    last
}

// ------------------------------------------------------------------ configs

/// Parse `KEY="value"` shell-style config files (Snapper configs, /etc/default/snapper).
fn parse_kv(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            Some((k.trim().to_string(), v.trim().trim_matches('"').to_string()))
        })
        .collect()
}

/// Config names visible to a normal user.
fn config_names() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir("/etc/snapper/configs")
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| !n.starts_with('.'))
                .collect()
        })
        .unwrap_or_default();
    // Debian lists active configs here (world readable).
    for f in ["/etc/default/snapper", "/etc/sysconfig/snapper"] {
        if let Some(t) = sys::read(f)
            && let Some(list) = parse_kv(&t).get("SNAPPER_CONFIGS")
        {
            for c in list.split_whitespace() {
                if !v.iter().any(|x| x == c) {
                    v.push(c.to_string());
                }
            }
        }
    }
    v.sort();
    v
}

// ------------------------------------------------------------------ schedules

/// systemd / cron day abbreviations and their names.
const WEEKDAYS: [(&str, &str); 7] = [
    ("mon", "Monday"),
    ("tue", "Tuesday"),
    ("wed", "Wednesday"),
    ("thu", "Thursday"),
    ("fri", "Friday"),
    ("sat", "Saturday"),
    ("sun", "Sunday"),
];

/// "Fri" -> "Friday".
fn day_name(tok: &str) -> Option<&'static str> {
    let t = tok.to_lowercase();
    WEEKDAYS
        .iter()
        .find(|(short, _)| t.starts_with(short))
        .map(|(_, long)| *long)
}

/// "03:00:00" -> "3:00 AM".
fn pretty_clock(t: &str) -> Option<String> {
    let mut it = t.split(':');
    let h: u32 = it.next()?.parse().ok()?;
    let m: u32 = it.next().unwrap_or("0").parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    let (h12, ap) = match h {
        0 => (12, "AM"),
        1..=11 => (h, "AM"),
        12 => (12, "PM"),
        _ => (h - 12, "PM"),
    };
    Some(format!("{h12}:{m:02} {ap}"))
}

/// Turn a systemd OnCalendar expression into words.
pub fn describe_calendar(expr: &str) -> String {
    let e = expr.trim();
    match e.to_lowercase().as_str() {
        "minutely" => return "Every minute".into(),
        "hourly" => return "Every hour".into(),
        "daily" => return "Every day".into(),
        "weekly" => return "Every Monday".into(),
        "monthly" => return "Every month".into(),
        "yearly" | "annually" => return "Every year".into(),
        _ => {}
    }
    let parts: Vec<&str> = e.split_whitespace().collect();
    let mut days: Vec<&str> = vec![];
    let mut rest = parts.as_slice();
    if let Some(first) = parts.first()
        && first.chars().next().is_some_and(|c| c.is_alphabetic())
    {
        // "Fri", "Mon,Fri", "Mon..Fri"
        if let Some((a, b)) = first.split_once("..") {
            if let (Some(a), Some(b)) = (day_name(a), day_name(b)) {
                days.push(a);
                days.push("to");
                days.push(b);
            }
        } else {
            days.extend(first.split(',').filter_map(day_name));
        }
        rest = &parts[1..];
    }
    let time = rest
        .iter()
        .find(|p| p.contains(':') && !p.contains('-'))
        .and_then(|t| pretty_clock(t));
    let hourly = rest.iter().any(|p| p.starts_with("*:"));
    let mut s = if !days.is_empty() {
        format!(
            "Every {}",
            days.join(if days.contains(&"to") { " " } else { ", " })
        )
    } else if hourly {
        "Every hour".into()
    } else if rest.iter().any(|p| *p == "*-*-*" || p.starts_with("*-*-*")) || time.is_some() {
        "Every day".into()
    } else {
        format!("On schedule ({e})")
    };
    if let Some(t) = time
        && !hourly
    {
        s.push_str(&format!(" at {t}"));
    }
    s
}

/// `systemctl show` properties of a unit as a map.
fn show_props(unit: &str, props: &[&str]) -> BTreeMap<String, String> {
    let mut args = vec!["show", unit, "--no-pager"];
    for p in props {
        args.push("-p");
        args.push(p);
    }
    sys::run_out("systemctl", &args)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            l.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect()
}

/// Does this service create Snapper snapshots? Looks at the unit file and any
/// script it runs.
fn service_creates_snapshots(service: &str) -> bool {
    let text = sys::run_out("systemctl", &["cat", service, "--no-pager"]).unwrap_or_default();
    let mentions = creates_snapshot_text;
    if mentions(&text) {
        return true;
    }
    // ExecStart=/usr/local/bin/weekly-restore-point.sh  -> peek into the script
    for line in text
        .lines()
        .filter(|l| l.trim_start().starts_with("ExecStart"))
    {
        let Some((_, cmd)) = line.split_once('=') else {
            continue;
        };
        let exe = cmd.trim().trim_start_matches(['-', '@', '+', '!', ':']);
        let exe = exe.split_whitespace().next().unwrap_or("");
        if exe.starts_with('/')
            && let Ok(meta) = std::fs::metadata(exe)
            && meta.len() < 256 * 1024
            && let Some(script) = sys::read(exe)
            && mentions(&script)
        {
            return true;
        }
    }
    false
}

/// True when some line runs `snapper ... create` (or a raw btrfs snapshot).
/// `snapper cleanup` lines alone don't count, but `--cleanup-algorithm` does.
fn creates_snapshot_text(text: &str) -> bool {
    text.lines().any(|l| {
        let l = l.to_lowercase();
        let l = l.split('#').next().unwrap_or("");
        (l.contains("snapper") && l.split_whitespace().any(|w| w == "create"))
            || l.contains("btrfs subvolume snapshot")
    })
}

/// Describe a systemd timer in words ("Every Friday at 12:00 AM") with its next run.
fn timer_schedule(timer: &str) -> Schedule {
    let p = show_props(
        timer,
        &[
            "TimersCalendar",
            "TimersMonotonic",
            "NextElapseUSecRealtime",
        ],
    );
    let cal = p.get("TimersCalendar").cloned().unwrap_or_default();
    // "{ OnCalendar=Fri *-*-* 03:00:00 ; next_elapse=... }"
    let exprs: Vec<String> = cal
        .split("OnCalendar=")
        .skip(1)
        .filter_map(|s| s.split(';').next())
        .map(|s| s.trim().to_string())
        .collect();
    let when = if !exprs.is_empty() {
        exprs
            .iter()
            .map(|e| describe_calendar(e))
            .collect::<Vec<_>>()
            .join("; ")
    } else if p
        .get("TimersMonotonic")
        .is_some_and(|m| m.contains("OnBootUSec"))
    {
        "At every startup".into()
    } else {
        "On a schedule".into()
    };
    let next = p
        .get("NextElapseUSecRealtime")
        .filter(|v| !v.is_empty() && *v != "n/a" && *v != "0")
        .cloned();
    Schedule {
        source: timer.to_string(),
        when,
        next,
    }
}

/// Active systemd timers as (timer, service).
fn active_timers() -> Vec<(String, String)> {
    let out = sys::run_out(
        "systemctl",
        &["list-timers", "--no-legend", "--no-pager", "--plain"],
    )
    .unwrap_or_default();
    let mut v = vec![];
    for line in out.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if let Some(i) = toks.iter().position(|t| t.ends_with(".timer")) {
            let svc = toks
                .get(i + 1)
                .map(|s| s.to_string())
                .unwrap_or_else(|| toks[i].replace(".timer", ".service"));
            v.push((toks[i].to_string(), svc));
        }
    }
    v
}

/// Cron day-of-week field ("5" or "1,5" or "fri") in words; `None` for every day.
fn cron_dow(field: &str) -> Option<String> {
    if field == "*" {
        return None;
    }
    let names = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
    ];
    let days: Vec<String> = field
        .split(',')
        .map(|d| match d.parse::<usize>() {
            Ok(n) if n < names.len() => names[n].to_string(),
            _ => day_name(d)
                .map(String::from)
                .unwrap_or_else(|| d.to_string()),
        })
        .collect();
    Some(days.join(", "))
}

/// Cron jobs that create snapshots (/etc/crontab, /etc/cron.d, and the hourly / daily / weekly
/// / monthly folders).
fn cron_schedules() -> Vec<Schedule> {
    let mut v = vec![];
    let mut files: Vec<std::path::PathBuf> = vec!["/etc/crontab".into(), "/etc/anacrontab".into()];
    for d in [
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ] {
        if let Ok(rd) = std::fs::read_dir(d) {
            files.extend(rd.flatten().map(|e| e.path()));
        }
    }
    for f in files {
        let Some(text) = sys::read(&f) else { continue };
        let fname = f.to_string_lossy().into_owned();
        let dir_when = if fname.starts_with("/etc/cron.hourly") {
            Some("Every hour")
        } else if fname.starts_with("/etc/cron.daily") {
            Some("Every day")
        } else if fname.starts_with("/etc/cron.weekly") {
            Some("Every week")
        } else if fname.starts_with("/etc/cron.monthly") {
            Some("Every month")
        } else {
            None
        };
        if let Some(w) = dir_when {
            if creates_snapshot_text(&text) {
                v.push(Schedule {
                    source: fname.clone(),
                    when: w.into(),
                    next: None,
                });
            }
            continue;
        }
        for line in text.lines() {
            let l = line.trim();
            if l.starts_with('#') || !creates_snapshot_text(l) {
                continue;
            }
            let f: Vec<&str> = l.split_whitespace().collect();
            let when = if l.starts_with('@') {
                f[0].trim_start_matches('@').to_string()
            } else if f.len() >= 5 {
                let time = format!("{}:{}", f[1], f[0]);
                let at = pretty_clock(&time)
                    .map(|t| format!(" at {t}"))
                    .unwrap_or_default();
                match cron_dow(f[4]) {
                    Some(d) => format!("Every {d}{at}"),
                    None => format!("Every day{at}"),
                }
            } else {
                "On a schedule".into()
            };
            v.push(Schedule {
                source: fname.clone(),
                when,
                next: None,
            });
        }
    }
    v
}

/// Every automatic restore point schedule: Snapper's own timeline and boot timers, any other
/// systemd timer whose service creates snapshots (for example Proton OS's weekly restore
/// point), and cron jobs.
pub fn detect_schedules() -> Vec<Schedule> {
    let mut v = vec![];
    for (timer, svc) in active_timers() {
        if timer.starts_with("snapper-cleanup")
            || timer.starts_with("snapd")
            || timer.starts_with("proton-security")
        {
            continue;
        }
        let known = timer.starts_with("snapper-timeline") || timer.starts_with("snapper-boot");
        if known || service_creates_snapshots(&svc) {
            v.push(timer_schedule(&timer));
        }
    }
    v.extend(cron_schedules());
    v
}

// ------------------------------------------------------------------ load (user side)

/// Read everything that doesn't need a password. The snapshot list itself is tried too, and
/// works when Snapper allows this user (ALLOW_USERS / ALLOW_GROUPS); otherwise `needs_admin` is
/// set and the page offers "Show restore points".
pub fn load() -> RestoreState {
    let mut st = RestoreState {
        installed: sys::which("snapper").is_some(),
        root_fs: sys::root_fs_type().unwrap_or_default(),
        assistant_installed: assistant_command().is_some(),
        ..Default::default()
    };
    if !st.installed {
        return st;
    }
    st.schedules = detect_schedules();
    st.configs = config_names();
    // Config files are root-only on Debian; use them when an admin made them readable.
    for c in &st.configs {
        if let Some(t) = sys::read(format!("/etc/snapper/configs/{c}")) {
            st.config_values.insert(c.clone(), parse_kv(&t));
        }
    }
    if st.configs.is_empty() {
        return st;
    }

    // `snapper list` works without a password only when Snapper allows this
    // user (ALLOW_USERS / ALLOW_GROUPS). Otherwise the page offers a button.
    match snapper_list_json() {
        Some((true, o, _)) => match parse_list(&o) {
            Ok(s) => {
                st.snapshots = s;
                st.source = ListSource::Direct;
            }
            Err(e) => st.error = Some(e),
        },
        Some((false, o, e)) => {
            let msg = format!("{o}{e}");
            let l = msg.to_lowercase();
            if l.contains("permission") || l.contains("denied") || l.contains("not allowed") {
                st.needs_admin = true;
            } else {
                st.error = Some(msg.trim().to_string());
            }
        }
        None => st.error = Some("Could not run snapper.".into()),
    }
    st
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_words() {
        assert_eq!(
            describe_calendar("Fri *-*-* 03:00:00"),
            "Every Friday at 3:00 AM"
        );
        assert_eq!(describe_calendar("Fri"), "Every Friday");
        assert_eq!(describe_calendar("weekly"), "Every Monday");
        assert_eq!(describe_calendar("hourly"), "Every hour");
        assert_eq!(describe_calendar("*-*-* 12:30:00"), "Every day at 12:30 PM");
        assert_eq!(
            describe_calendar("Mon..Fri *-*-* 18:00"),
            "Every Monday to Friday at 6:00 PM"
        );
        assert_eq!(describe_calendar("*-*-* *:00:00"), "Every hour");
    }

    #[test]
    fn detects_create_lines() {
        assert!(creates_snapshot_text(
            "snapper -c root create --description weekly --cleanup-algorithm number"
        ));
        assert!(creates_snapshot_text(
            "ExecStart=/usr/bin/snapper --config root create -d x"
        ));
        assert!(!creates_snapshot_text(
            "ExecStart=/usr/bin/snapper --config root cleanup timeline"
        ));
        assert!(!creates_snapshot_text("# snapper create (disabled)"));
    }

    #[test]
    fn cron_days() {
        assert_eq!(cron_dow("5").as_deref(), Some("Friday"));
        assert_eq!(cron_dow("fri").as_deref(), Some("Friday"));
        assert_eq!(cron_dow("*"), None);
    }
}
