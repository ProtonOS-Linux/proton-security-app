// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Security report: one self-contained HTML file (print it to PDF from the
//! browser). Used by the "Export report" button and `proton-security --report`.

use crate::checks::{self, Level};
use crate::sys;
use std::fmt::Write;
use std::path::PathBuf;

/// Escape text for HTML.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// "Proton OS 1.0" style name from /etc/os-release.
fn os_name() -> String {
    sys::read("/etc/os-release")
        .and_then(|t| {
            t.lines().find_map(|l| {
                l.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim_matches('"').to_string())
            })
        })
        .unwrap_or_else(|| "Linux".into())
}

/// This computer's name.
pub fn hostname() -> String {
    sys::read_trim("/proc/sys/kernel/hostname").unwrap_or_else(|| "computer".into())
}

/// Where "Export report" saves by default:
/// `~/Documents/Proton-Security-Report-<computer>-<date>.html`.
pub fn default_path() -> PathBuf {
    let docs = sys::run_out("xdg-user-dir", &["DOCUMENTS"])
        .map(|d| PathBuf::from(d.trim()))
        .filter(|d| d.is_dir() && *d != sys::home())
        .unwrap_or_else(|| sys::home().join("Documents"));
    let _ = std::fs::create_dir_all(&docs);
    docs.join(format!(
        "Proton-Security-Report-{}-{}.html",
        hostname(),
        chrono::Local::now().format("%Y-%m-%d")
    ))
}

/// Append one `<tr>` with a heading and a value.
fn row(out: &mut String, k: &str, v: &str) {
    let _ = write!(out, "<tr><th>{}</th><td>{}</td></tr>", esc(k), esc(v));
}

/// Coloured "OK" / "Attention" / "Info" label.
fn badge(ok: Option<bool>) -> &'static str {
    match ok {
        Some(true) => "<span class=\"b ok\">✓ OK</span>",
        Some(false) => "<span class=\"b warn\">! Attention</span>",
        None => "<span class=\"b info\">Info</span>",
    }
}

/// Build the whole report as one self-contained HTML page (styles inline, no external files),
/// so it can be emailed or printed to PDF from the browser. It runs every check again, so it
/// takes a few seconds.
pub fn generate() -> String {
    let pol = crate::policy::get();
    let results = checks::run_all();
    let warn = results.iter().filter(|r| r.level == Level::Warn).count();
    let now = chrono::Local::now()
        .format("%B %-d, %Y %-I:%M %p")
        .to_string();

    let mut o = String::new();
    let _ = write!(
        o,
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security report – {host}</title>
<style>
:root{{--fg:#1b1b1b;--muted:#5f6368;--line:#e3e3e3;--ok:#107c10;--warn:#9d5d00;--bg:#fff;--card:#f7f7f7}}
body{{font:15px/1.5 system-ui,"Noto Sans",sans-serif;color:var(--fg);background:var(--bg);max-width:960px;margin:24px auto;padding:0 16px}}
h1{{font-size:26px;margin:0}} h2{{font-size:19px;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}}
.muted{{color:var(--muted)}} table{{border-collapse:collapse;width:100%}} th,td{{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line)}}
th{{width:34%;font-weight:600}} .b{{display:inline-block;padding:1px 8px;border-radius:10px;font-size:13px;font-weight:600;white-space:nowrap}}
.ok{{background:#dff6dd;color:var(--ok)}} .warn{{background:#fff4ce;color:var(--warn)}} .info{{background:#eef2f7;color:#33475b}}
.summary{{background:var(--card);border-radius:8px;padding:14px 16px;margin-top:14px}}
ul{{margin:4px 0;padding-left:20px}} footer{{margin-top:32px;font-size:13px}}
@media print{{body{{margin:0}} h2{{break-after:avoid}} tr{{break-inside:avoid}}}}
</style></head><body>
<h1>Security report</h1>
<div class="muted">{host} · {os} · {now}</div>
<div class="summary"><strong>{summary}</strong></div>
"#,
        host = esc(&hostname()),
        os = esc(&os_name()),
        now = esc(&now),
        summary = if warn == 0 {
            "This device is protected. No action needed.".to_string()
        } else {
            format!("{warn} item(s) need attention.")
        }
    );

    // ---- overview
    o.push_str("<h2>Security at a glance</h2><table>");
    for r in &results {
        let mut cell = format!("{} {}", badge(Some(r.level == Level::Ok)), esc(&r.headline));
        let mut lines: Vec<String> = vec![];
        if let Some((l, v, _)) = &r.status_item {
            lines.push(format!("{l}: {v}"));
        }
        lines.extend(r.details.iter().cloned());
        if !lines.is_empty() {
            cell.push_str("<ul>");
            for d in lines {
                let _ = write!(cell, "<li class=\"muted\">{}</li>", esc(&d));
            }
            cell.push_str("</ul>");
        }
        let _ = write!(o, "<tr><th>{}</th><td>{}</td></tr>", esc(r.title), cell);
    }
    o.push_str("</table>");

    // ---- system
    let h = crate::health::load();
    let d = crate::devsec::load();
    let a = crate::account::load();
    o.push_str("<h2>Device</h2><table>");
    row(&mut o, "Computer name", &hostname());
    row(&mut o, "Operating system", &os_name());
    row(
        &mut o,
        "Linux kernel",
        &sys::read_trim("/proc/sys/kernel/osrelease").unwrap_or_default(),
    );
    row(
        &mut o,
        "Memory",
        &format!("{} total", sys::fmt_bytes(h.memory_total)),
    );
    for disk in &h.disks {
        row(
            &mut o,
            &format!("Storage {}", disk.mount),
            &format!(
                "{} free of {}",
                sys::fmt_bytes(disk.free),
                sys::fmt_bytes(disk.size)
            ),
        );
    }
    for dr in &h.drives {
        row(
            &mut o,
            &format!("Disk {}", dr.model),
            &format!(
                "{}{}",
                if dr.failing {
                    "Problem reported by the disk"
                } else if dr.bad_sectors.unwrap_or(0) > 0 {
                    "Needs attention"
                } else {
                    "Healthy"
                },
                dr.bad_sectors_text()
                    .map(|b| format!(" · {b}"))
                    .unwrap_or_default()
            ),
        );
    }
    for b in &h.batteries {
        if let Some(p) = b.health_percent {
            row(&mut o, "Battery health", &format!("{p:.0}%"));
        }
    }
    row(
        &mut o,
        "Restart required",
        if h.restart.required { "Yes" } else { "No" },
    );
    o.push_str("</table>");

    o.push_str("<h2>Device security</h2><table>");
    row(
        &mut o,
        "Secure Boot",
        match (d.uefi, d.secure_boot) {
            (false, _) => "Not supported (legacy BIOS)",
            (true, Some(true)) => "On",
            (true, Some(false)) => "Off",
            _ => "Unknown",
        },
    );
    row(
        &mut o,
        "TPM",
        &d.tpm.clone().unwrap_or_else(|| "Not found".into()),
    );
    for disk in &d.disks {
        row(
            &mut o,
            &format!("Encryption {} ({})", disk.mount, disk.device),
            if disk.encrypted {
                "Encrypted"
            } else {
                "Not encrypted"
            },
        );
    }
    o.push_str("</table>");

    o.push_str("<h2>Account protection</h2><table>");
    row(&mut o, "Account", &a.user);
    row(
        &mut o,
        "Screen lock",
        &if a.lock.autolock {
            format!("After {} min", a.lock.timeout_min)
        } else {
            "Off".into()
        },
    );
    row(
        &mut o,
        "Lock after sleep",
        if a.lock.lock_on_resume { "Yes" } else { "No" },
    );
    row(
        &mut o,
        "Automatic sign-in",
        &a.autologin
            .as_ref()
            .map(|(u, _)| format!("On ({u})"))
            .unwrap_or_else(|| "Off".into()),
    );
    row(&mut o, "Administrator accounts", &a.admins.join(", "));
    o.push_str("</table>");

    // ---- antivirus
    let clam = crate::antivirus::clam_info();
    let hist = crate::antivirus::load_history();
    o.push_str("<h2>Virus &amp; threat protection</h2><table>");
    row(
        &mut o,
        "ClamAV",
        &clam
            .engine_version
            .clone()
            .unwrap_or_else(|| "Not installed".into()),
    );
    row(
        &mut o,
        "Definitions",
        &clam
            .db_date
            .map(sys::fmt_time)
            .unwrap_or_else(|| "Unknown".into()),
    );
    row(
        &mut o,
        "Automatic definition updates",
        if clam.auto_update() { "On" } else { "Off" },
    );
    let st = crate::settings::load();
    row(
        &mut o,
        "Daily quick scan",
        if crate::policy::effective(st.daily_scan, pol.daily_scan) {
            "On"
        } else {
            "Off"
        },
    );
    row(
        &mut o,
        "Scan new downloads",
        if crate::policy::effective(st.scan_downloads, pol.scan_downloads) {
            "On"
        } else {
            "Off"
        },
    );
    row(
        &mut o,
        "Scan USB drives when opened",
        if crate::policy::effective(st.scan_usb, pol.scan_usb) {
            "On"
        } else {
            "Off"
        },
    );
    row(
        &mut o,
        "Quarantined files",
        &crate::antivirus::load_quarantine().len().to_string(),
    );
    o.push_str("</table>");
    if !hist.is_empty() {
        o.push_str("<table><tr><th>Scan (last 30 days)</th><th>Files</th><th>Threats</th></tr>");
        for r in hist.iter().rev().take(30) {
            let _ = write!(
                o,
                "<tr><td>{} – {}</td><td>{}</td><td>{}</td></tr>",
                esc(&sys::fmt_time(r.finished_time())),
                esc(&r.kind),
                r.files,
                r.threats.len()
            );
        }
        o.push_str("</table>");
    }

    // ---- firewall
    let fw = crate::firewall::status();
    o.push_str("<h2>Firewall</h2><table>");
    row(&mut o, "Firewall", if fw.on() { "On" } else { "Off" });
    row(&mut o, "Incoming by default", &fw.incoming);
    row(&mut o, "Outgoing by default", &fw.outgoing);
    for r in &st.fw_rules {
        row(&mut o, "Rule added by the user", &r.describe());
    }
    o.push_str("</table>");

    // ---- restore & backup
    let rs = crate::restore::load();
    let bk = crate::backup::load();
    o.push_str("<h2>Restore points &amp; backup</h2><table>");
    for s in rs.effective_schedules() {
        row(
            &mut o,
            "Restore point schedule",
            &format!("{} ({})", s.when, s.source),
        );
    }
    if rs.effective_schedules().is_empty() {
        row(&mut o, "Restore point schedule", "None found");
    }
    if !bk.has_backup_tool() {
        row(
            &mut o,
            "File backup",
            if bk.other_way {
                "Another method (stated by the user)"
            } else {
                "Not set up"
            },
        );
    }
    for t in &bk.tools {
        row(
            &mut o,
            "File backup",
            &format!(
                "{} – {}{}",
                t.name,
                t.detail,
                t.last
                    .map(|l| format!(", last {}", sys::fmt_time(l)))
                    .unwrap_or_default()
            ),
        );
    }
    o.push_str("</table>");

    // ---- apps
    let apps = crate::appperms::load();
    let risky: Vec<_> = apps.iter().filter(|a| a.risky()).collect();
    if !apps.is_empty() {
        o.push_str("<h2>App permissions</h2><table>");
        row(&mut o, "Flatpak apps", &apps.len().to_string());
        for a in risky {
            let perms: Vec<&str> = a
                .perms
                .iter()
                .filter(|p| p.risky())
                .map(|p| p.label())
                .collect();
            row(&mut o, &a.name, &perms.join(", "));
        }
        o.push_str("</table>");
    }

    let _ = write!(
        o,
        "<footer class=\"muted\">Created by Proton Security {} · App created by Proton OS · www.protonos.org{}</footer></body></html>",
        env!("CARGO_PKG_VERSION"),
        if pol.loaded {
            format!(" · {}", esc(&pol.managed_text()))
        } else {
            String::new()
        }
    );
    o
}

/// Generate the report and write it to `path`.
pub fn save(path: &std::path::Path) -> Result<(), String> {
    std::fs::write(path, generate()).map_err(|e| format!("Could not save the report: {e}"))
}
