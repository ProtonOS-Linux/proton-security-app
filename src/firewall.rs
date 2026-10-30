// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Firewall page data: network connections, firewall status and the UFW log.
//! Everything here is read as the normal user.

use crate::sys;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ------------------------------------------------------------------ status

/// Firewall settings, read from UFW's configuration files (readable by everyone) and systemd.
#[derive(Clone, Debug, Default)]
pub struct FirewallStatus {
    /// UFW (Uncomplicated Firewall) is installed.
    pub ufw_installed: bool,
    /// UFW is switched on (`ENABLED=yes`) and its service is running.
    pub enabled: bool,
    /// firewalld is running instead of UFW.
    pub firewalld: bool,
    /// "DROP", "REJECT" or "ACCEPT" (from /etc/default/ufw)
    pub incoming: String,
    /// Default for outgoing connections (usually ACCEPT).
    pub outgoing: String,
    /// UFW log level (`off`, `low`, `medium`…).
    pub logging: String,
}

impl FirewallStatus {
    /// True when any supported firewall is on.
    pub fn on(&self) -> bool {
        self.enabled || self.firewalld
    }
    /// True when UFW refuses incoming connections unless a rule allows them (the safe default).
    pub fn blocks_incoming_by_default(&self) -> bool {
        self.enabled && matches!(self.incoming.as_str(), "DROP" | "REJECT")
    }
}

/// Parse `KEY=value` files such as /etc/ufw/ufw.conf.
fn kv_file(path: &str) -> HashMap<String, String> {
    sys::read(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            Some((k.trim().to_string(), v.trim().trim_matches('"').to_string()))
        })
        .collect()
}

/// Read the firewall status.
pub fn status() -> FirewallStatus {
    let conf = kv_file("/etc/ufw/ufw.conf");
    let def = kv_file("/etc/default/ufw");
    let ufw_installed = sys::which("ufw").is_some();
    FirewallStatus {
        ufw_installed,
        enabled: ufw_installed
            && conf
                .get("ENABLED")
                .map(|v| v.eq_ignore_ascii_case("yes"))
                .unwrap_or(false)
            && sys::systemctl_active("ufw.service"),
        firewalld: sys::systemctl_active("firewalld.service"),
        incoming: def.get("DEFAULT_INPUT_POLICY").cloned().unwrap_or_default(),
        outgoing: def
            .get("DEFAULT_OUTPUT_POLICY")
            .cloned()
            .unwrap_or_default(),
        logging: conf
            .get("LOGLEVEL")
            .cloned()
            .unwrap_or_else(|| "off".into()),
    }
}

// ------------------------------------------------------------------ services

/// Friendly name for well-known ports.
pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        20 | 21 => "FTP",
        22 => "SSH",
        25 | 587 => "Email (SMTP)",
        53 => "DNS",
        67 | 68 => "DHCP",
        80 => "Web (HTTP)",
        110 => "Email (POP3)",
        123 => "Time (NTP)",
        137..=139 => "Windows sharing",
        143 => "Email (IMAP)",
        443 => "Web (HTTPS)",
        445 => "Windows sharing (SMB)",
        465 => "Email (SMTPS)",
        631 => "Printing",
        853 => "Secure DNS",
        993 => "Email (IMAPS)",
        995 => "Email (POP3S)",
        1714..=1764 => "KDE Connect",
        1900 => "Device discovery (SSDP)",
        3389 => "Remote desktop",
        3478 | 19302..=19309 => "Calls / video (STUN)",
        5222 | 5223 => "Messaging",
        5353 => "Local discovery (mDNS)",
        5355 => "Name lookup (LLMNR)",
        8080 => "Web (alt)",
        _ => return None,
    })
}

/// "Web (HTTPS) · 443", or just the number for unknown ports.
pub fn port_text(port: u16) -> String {
    match service_name(port) {
        Some(s) => format!("{s} · {port}"),
        None => port.to_string(),
    }
}

// ------------------------------------------------------------------ connections

/// Network protocol of a connection or rule.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    /// "TCP" / "UDP" for display.
    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        }
    }
    /// "tcp" / "udp" for ufw.
    pub fn arg(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// Connection states shown in the table (the kernel has more; they are grouped).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ConnState {
    /// Waiting for incoming connections (a server port).
    Listening,
    /// An open connection.
    Connected,
    /// Being set up.
    Connecting,
    /// Being closed.
    Closing,
}

impl ConnState {
    /// State in words.
    pub fn text(self) -> &'static str {
        match self {
            ConnState::Listening => "Listening",
            ConnState::Connected => "Connected",
            ConnState::Connecting => "Connecting",
            ConnState::Closing => "Closing",
        }
    }
}

/// One row of the connections table.
#[derive(Clone, Debug)]
pub struct Conn {
    /// Program that owns the connection ("Firefox"), or the user name when it belongs to
    /// another user.
    pub program: String,
    /// Full command line, for the tooltip.
    pub detail: String,
    /// TCP or UDP.
    pub proto: Proto,
    /// Listening, connected…
    pub state: ConnState,
    /// This computer's address used by the connection.
    pub local_ip: IpAddr,
    /// This computer's port.
    pub local_port: u16,
    /// The other side's address.
    pub remote_ip: IpAddr,
    /// The other side's port.
    pub remote_port: u16,
    /// Hardware (MAC) address of the other side, when it is on the local network.
    pub mac: Option<String>,
    /// MAC shown is the router's (remote is on the internet).
    pub mac_is_router: bool,
    /// Number of identical connections merged into this row.
    pub count: usize,
}

impl Conn {
    /// True for connections that never leave this computer (loopback). Hidden by default.
    pub fn is_local_only(&self) -> bool {
        match self.state {
            ConnState::Listening => self.local_ip.is_loopback(),
            _ => self.remote_ip.is_loopback() || self.remote_ip == self.local_ip,
        }
    }
    /// The port that identifies the service: ours when listening, theirs otherwise.
    pub fn service_port(&self) -> u16 {
        if self.state == ConnState::Listening {
            self.local_port
        } else {
            self.remote_port
        }
    }
    /// Address column text: who can reach a listening port, or the other side's IP.
    pub fn address_text(&self) -> String {
        if self.state == ConnState::Listening {
            if self.local_ip.is_unspecified() {
                "All networks".into()
            } else if self.local_ip.is_loopback() {
                "This computer only".into()
            } else {
                self.local_ip.to_string()
            }
        } else {
            self.remote_ip.to_string()
        }
    }
}

/// Parse an address from /proc/net/tcp (`0100007F:0277` is 127.0.0.1:631). IPv4 is one
/// little-endian 32-bit word; IPv6 is four of them.
fn parse_hex_addr(s: &str) -> Option<(IpAddr, u16)> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let ip = match a.len() {
        8 => {
            let v = u32::from_str_radix(a, 16).ok()?;
            IpAddr::V4(Ipv4Addr::from(v.swap_bytes()))
        }
        32 => {
            // Four 32-bit words, each in host (little-endian) byte order.
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&a[i * 8..i * 8 + 8], 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&w.swap_bytes().to_be_bytes());
            }
            let v6 = Ipv6Addr::from(bytes);
            // Show IPv4-mapped addresses (::ffff:1.2.3.4) as plain IPv4.
            match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            }
        }
        _ => return None,
    };
    Some((ip, port))
}

/// A socket as read from /proc/net, before it is matched to a program.
struct RawSock {
    /// TCP or UDP.
    proto: Proto,
    /// Connection state.
    state: ConnState,
    /// This computer's address and port.
    local: (IpAddr, u16),
    /// The other side's address and port.
    remote: (IpAddr, u16),
    /// Account that owns the socket.
    uid: u32,
    /// Socket inode, used to find the process that has it open.
    inode: u64,
}

/// Read the kernel's socket table for one protocol (/proc/net/tcp, tcp6, udp, udp6). Readable
/// by every user.
fn read_proc_net(file: &str, proto: Proto) -> Vec<RawSock> {
    let Some(text) = sys::read(format!("/proc/net/{file}")) else {
        return vec![];
    };
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let local = parse_hex_addr(f[1])?;
            let remote = parse_hex_addr(f[2])?;
            let st = u8::from_str_radix(f[3], 16).ok()?;
            let state = match proto {
                Proto::Tcp => match st {
                    0x01 => ConnState::Connected,
                    0x02 | 0x03 => ConnState::Connecting,
                    0x0A => ConnState::Listening,
                    _ => ConnState::Closing,
                },
                // UDP has no real states: unconnected sockets are "listening".
                Proto::Udp => {
                    if remote.1 == 0 {
                        ConnState::Listening
                    } else {
                        ConnState::Connected
                    }
                }
            };
            Some(RawSock {
                proto,
                state,
                local,
                remote,
                uid: f[7].parse().ok()?,
                inode: f[9].parse().ok()?,
            })
        })
        .collect()
}

/// socket inode -> (program, command line). Only this user's processes are
/// visible without root; others are named after their user account.
fn socket_owners() -> HashMap<u64, (String, String)> {
    let mut m = HashMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return m;
    };
    for p in procs.flatten() {
        let name = p.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|s| s.chars().all(|c| c.is_ascii_digit()))
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else {
            continue;
        };
        let mut program: Option<(String, String)> = None;
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let t = target.to_string_lossy();
            let Some(inode) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) else {
                continue;
            };
            let Ok(inode) = inode.parse::<u64>() else {
                continue;
            };
            let prog = program.get_or_insert_with(|| process_name(pid));
            m.insert(inode, prog.clone());
        }
    }
    m
}

/// (friendly program name, full command line) of a process. The name comes from the command
/// line, made readable (for example interpreter scripts show the script's name).
fn process_name(pid: &str) -> (String, String) {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| {
            b.split(|c| *c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let comm = sys::read_trim(format!("/proc/{pid}/comm")).unwrap_or_else(|| "?".into());
    // Prefer the executable name from the command line (comm is cut at 15 chars).
    let exe = cmdline
        .first()
        .and_then(|c| std::path::Path::new(c).file_name())
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty() && s.len() >= comm.len())
        .unwrap_or(comm);
    (
        pretty_program(&exe),
        format!("PID {pid}: {}", cmdline.join(" ")),
    )
}

/// Friendlier names for common programs.
fn pretty_program(exe: &str) -> String {
    let known = [
        ("firefox", "Firefox"),
        ("firefox-esr", "Firefox"),
        ("chrome", "Google Chrome"),
        ("chromium", "Chromium"),
        ("thunderbird", "Thunderbird"),
        ("kdeconnectd", "KDE Connect"),
        ("plasmashell", "Plasma desktop"),
        ("discover", "Discover"),
        ("plasma-discover", "Discover"),
        ("kdeinit5", "KDE"),
        ("NetworkManager", "Network Manager"),
        ("systemd-resolved", "DNS resolver"),
        ("avahi-daemon", "Local discovery (Avahi)"),
        ("cupsd", "Printing (CUPS)"),
        ("cups-browsed", "Printer discovery"),
        ("sshd", "SSH server"),
        ("chronyd", "Time sync"),
        ("systemd-timesyncd", "Time sync"),
        ("freshclam", "ClamAV updates"),
        ("flatpak", "Flatpak"),
        ("packagekitd", "Software updates"),
        ("steam", "Steam"),
        ("teams-for-linux", "Teams"),
        ("slack", "Slack"),
        ("discord", "Discord"),
        ("spotify", "Spotify"),
    ];
    known
        .iter()
        .find(|(k, _)| *k == exe)
        .map(|(_, v)| v.to_string())
        .unwrap_or_else(|| exe.to_string())
}

/// User id -> user name, from /etc/passwd.
fn user_names() -> HashMap<u32, String> {
    sys::read("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            Some((f.get(2)?.parse().ok()?, f.first()?.to_string()))
        })
        .collect()
}

/// IP -> MAC from the neighbor table, plus the default router's IP.
fn neighbors() -> (HashMap<IpAddr, String>, Option<IpAddr>) {
    let mut m = HashMap::new();
    if let Some(out) = sys::run_out("ip", &["neigh", "show"]) {
        for l in out.lines() {
            let f: Vec<&str> = l.split_whitespace().collect();
            if let (Some(ip), Some(i)) = (f.first(), f.iter().position(|x| *x == "lladdr"))
                && let (Ok(ip), Some(mac)) = (ip.parse::<IpAddr>(), f.get(i + 1))
            {
                m.insert(ip, mac.to_string());
            }
        }
    } else if let Some(arp) = sys::read("/proc/net/arp") {
        for l in arp.lines().skip(1) {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() >= 4
                && f[3] != "00:00:00:00:00:00"
                && let Ok(ip) = f[0].parse::<IpAddr>()
            {
                m.insert(ip, f[3].to_string());
            }
        }
    }
    let gw = sys::run_out("ip", &["route", "show", "default"])
        .and_then(|o| {
            o.lines().find_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                let i = f.iter().position(|x| *x == "via")?;
                f.get(i + 1)?.parse().ok()
            })
        })
        .or_else(|| {
            sys::read("/proc/net/route")?.lines().skip(1).find_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                if f.get(1) == Some(&"00000000") {
                    let v = u32::from_str_radix(f.get(2)?, 16).ok()?;
                    Some(IpAddr::V4(Ipv4Addr::from(v.swap_bytes())))
                } else {
                    None
                }
            })
        });
    (m, gw)
}

/// True for private / link-local addresses (the local network).
fn is_lan(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_link_local(),
        IpAddr::V6(v) => {
            (v.segments()[0] & 0xffc0) == 0xfe80 || (v.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Identical rows (same program, state and endpoints) are merged.
type MergeKey = (String, Proto, ConnState, IpAddr, u16, IpAddr, u16);

/// All network connections and listening ports, with the program behind each.
/// Sockets are matched to programs through `/proc/<pid>/fd`. A normal user can't
/// look into other accounts' processes, so those rows say "System service" (for
/// root and system accounts) or "Program of `<user>`" instead of a name.
pub fn connections() -> Vec<Conn> {
    let mut raw = vec![];
    for (f, p) in [
        ("tcp", Proto::Tcp),
        ("tcp6", Proto::Tcp),
        ("udp", Proto::Udp),
        ("udp6", Proto::Udp),
    ] {
        raw.extend(read_proc_net(f, p));
    }
    let owners = socket_owners();
    let users = user_names();
    let (neigh, gw) = neighbors();
    let gw_mac = gw.and_then(|g| neigh.get(&g).cloned());

    // Merge identical rows (e.g. a browser with 6 connections to one server).
    let mut merged: Vec<Conn> = vec![];
    let mut index: HashMap<MergeKey, usize> = HashMap::new();
    for s in raw {
        let (program, detail) = match owners.get(&s.inode) {
            Some(o) => o.clone(),
            None if s.inode == 0 => (
                "(closed)".into(),
                "Connection is closing; no program owns it anymore.".into(),
            ),
            None => {
                let user = users
                    .get(&s.uid)
                    .cloned()
                    .unwrap_or_else(|| s.uid.to_string());
                let who = if s.uid == 0 {
                    "System service".to_string()
                } else if s.uid < 1000 {
                    format!("System service ({user})")
                } else {
                    format!("Program of {user}")
                };
                (
                    who,
                    "Run by another account; its name is only visible to administrators.".into(),
                )
            }
        };
        let (mac, mac_is_router) = if s.state == ConnState::Listening {
            (None, false)
        } else if let Some(m) = neigh.get(&s.remote.0) {
            (Some(m.clone()), false)
        } else if !s.remote.0.is_loopback() && !is_lan(&s.remote.0) {
            (gw_mac.clone(), gw_mac.is_some())
        } else {
            (None, false)
        };
        // For listening sockets the remote side is meaningless; for connections
        // the local port is random, so leave it out of the merge key.
        let key_local_port = if s.state == ConnState::Listening {
            s.local.1
        } else {
            0
        };
        let key = (
            program.clone(),
            s.proto,
            s.state,
            s.local.0,
            key_local_port,
            s.remote.0,
            s.remote.1,
        );
        if let Some(&i) = index.get(&key) {
            merged[i].count += 1;
            continue;
        }
        index.insert(key, merged.len());
        merged.push(Conn {
            program,
            detail,
            proto: s.proto,
            state: s.state,
            local_ip: s.local.0,
            local_port: s.local.1,
            remote_ip: s.remote.0,
            remote_port: s.remote.1,
            mac,
            mac_is_router,
            count: 1,
        });
    }
    merged.sort_by(|a, b| {
        a.program
            .to_lowercase()
            .cmp(&b.program.to_lowercase())
            .then(a.state.text().cmp(b.state.text()))
            .then(a.service_port().cmp(&b.service_port()))
    });
    merged
}

// ------------------------------------------------------------------ rules added from the app

/// The kinds of firewall rule the app can add.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum RuleKind {
    /// Block all traffic to and from an address.
    BlockAddress { ip: String },
    /// Allow incoming connections to one of this computer's ports.
    AllowPort { port: u16, proto: Proto },
    /// Block incoming connections to one of this computer's ports.
    BlockPort { port: u16, proto: Proto },
}

/// A firewall rule added from the Firewall page. Saved in the user's settings, because UFW's
/// own rule list can only be read as root.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    /// What the rule does.
    pub kind: RuleKind,
    /// What the user saw when adding it (program name).
    pub note: String,
    /// When it was added (Unix seconds).
    pub added: i64,
}

impl Rule {
    /// The rule in words.
    pub fn describe(&self) -> String {
        match &self.kind {
            RuleKind::BlockAddress { ip } => format!("Block all traffic with {ip}"),
            RuleKind::AllowPort { port, proto } => {
                format!("Allow incoming {} {}", proto.name(), port_text(*port))
            }
            RuleKind::BlockPort { port, proto } => {
                format!("Block incoming {} {}", proto.name(), port_text(*port))
            }
        }
    }
    /// Helper arguments to add this rule.
    pub fn add_args(&self) -> Vec<String> {
        match &self.kind {
            RuleKind::BlockAddress { ip } => vec!["fw-block-ip".into(), ip.clone()],
            RuleKind::AllowPort { port, proto } => {
                vec!["fw-allow-port".into(), port.to_string(), proto.arg().into()]
            }
            RuleKind::BlockPort { port, proto } => {
                vec!["fw-block-port".into(), port.to_string(), proto.arg().into()]
            }
        }
    }
    /// Helper arguments to remove this rule.
    pub fn remove_args(&self) -> Vec<String> {
        match &self.kind {
            RuleKind::BlockAddress { ip } => vec!["fw-unblock-ip".into(), ip.clone()],
            RuleKind::AllowPort { port, proto } | RuleKind::BlockPort { port, proto } => {
                vec![
                    "fw-remove-port".into(),
                    port.to_string(),
                    proto.arg().into(),
                ]
            }
        }
    }
}

/// Rule (if any) the user added that applies to this connection row.
pub fn rule_for<'a>(rules: &'a [Rule], c: &Conn) -> Option<&'a Rule> {
    rules.iter().find(|r| match &r.kind {
        RuleKind::BlockAddress { ip } => {
            c.state != ConnState::Listening && *ip == c.remote_ip.to_string()
        }
        RuleKind::AllowPort { port, proto } | RuleKind::BlockPort { port, proto } => {
            c.state == ConnState::Listening && *port == c.local_port && *proto == c.proto
        }
    })
}

// ------------------------------------------------------------------ log

/// One line of the firewall log, in words.
#[derive(Clone, Debug)]
pub struct LogEntry {
    /// Local time, formatted.
    pub time: String,
    /// "Blocked", "Allowed"…
    pub action: String,
    /// "Incoming", "Outgoing" or "Forwarded".
    pub direction: &'static str,
    /// The other side's IP address.
    pub address: String,
    /// The other side's hardware address (source MAC), if logged.
    pub mac: String,
    /// Destination port.
    pub port: Option<u16>,
    /// Protocol (TCP, UDP, ICMP…).
    pub proto: String,
    /// Network interface (`wlan0`, `enp3s0`).
    pub interface: String,
}

/// Value of `KEY=` in a kernel log line.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!(" {key}=");
    let i = line.find(&pat)? + pat.len();
    let rest = &line[i..];
    Some(rest.split_whitespace().next().unwrap_or("")).filter(|v| !v.is_empty() && !v.contains('='))
}

/// Parse one kernel log line written by UFW.
pub fn parse_log_line(line: &str) -> Option<LogEntry> {
    let start = line.find("[UFW ")?;
    let tag_end = line[start..].find(']')? + start;
    let action = match &line[start + 5..tag_end] {
        "BLOCK" => "Blocked",
        "ALLOW" => "Allowed",
        "AUDIT" => "Checked",
        "LIMIT BLOCK" => "Rate-limited",
        other => other,
    }
    .to_string();
    let inn = field(line, "IN").unwrap_or("");
    let out = field(line, "OUT").unwrap_or("");
    let direction = match (inn.is_empty(), out.is_empty()) {
        (false, true) => "Incoming",
        (true, false) => "Outgoing",
        _ => "Forwarded",
    };
    let src = field(line, "SRC").unwrap_or("");
    let dst = field(line, "DST").unwrap_or("");
    let address = if direction == "Outgoing" { dst } else { src }.to_string();
    // MAC= is destination(6):source(6):type(2) bytes.
    let mac = field(line, "MAC")
        .map(|m| {
            let parts: Vec<&str> = m.split(':').collect();
            if parts.len() >= 12 {
                parts[6..12].join(":")
            } else {
                String::new()
            }
        })
        .unwrap_or_default();
    let time = line[..start]
        .split_whitespace()
        .next()
        .map(|t| {
            chrono::DateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S%z")
                .or_else(|_| chrono::DateTime::parse_from_rfc3339(t))
                .map(|d| {
                    d.with_timezone(&chrono::Local)
                        .format("%b %-d, %-I:%M:%S %p")
                        .to_string()
                })
                .unwrap_or_else(|_| t.to_string())
        })
        .unwrap_or_default();
    Some(LogEntry {
        time,
        action,
        direction,
        address,
        mac,
        port: field(line, "DPT").and_then(|p| p.parse().ok()),
        proto: field(line, "PROTO").unwrap_or("").to_string(),
        interface: if inn.is_empty() { out } else { inn }.to_string(),
    })
}

/// Parse many log lines, newest first.
pub fn parse_log(text: &str) -> Vec<LogEntry> {
    let mut v: Vec<LogEntry> = text.lines().filter_map(parse_log_line).collect();
    v.reverse(); // newest first
    v
}

/// The firewall log as shown on the page.
#[derive(Clone, Debug, Default)]
pub struct LogState {
    /// Entries, newest first.
    pub entries: Vec<LogEntry>,
    /// The log could not be read without administrator permission.
    pub needs_admin: bool,
}

/// Read recent UFW entries as the current user (works for members of the
/// adm / systemd-journal groups).
pub fn read_log() -> LogState {
    #[cfg(debug_assertions)]
    if let Ok(f) = std::env::var("PROTON_SECURITY_FAKE_UFW_LOG") {
        return LogState {
            entries: parse_log(&sys::read(f).unwrap_or_default()),
            needs_admin: false,
        };
    }
    if let Some((_, out, err)) = sys::run_full(
        "journalctl",
        &[
            "-q",
            "--no-pager",
            "-o",
            "short-iso",
            "_TRANSPORT=kernel",
            "-g",
            "\\[UFW ",
            "-n",
            "300",
        ],
    ) {
        let entries = parse_log(&out);
        let denied = err.to_lowercase().contains("insufficient permissions")
            || err.to_lowercase().contains("not seeing messages");
        if !entries.is_empty() || !denied {
            return LogState {
                entries,
                needs_admin: false,
            };
        }
    }
    // Systems that log to a file (rsyslog).
    if let Some(t) = sys::read("/var/log/ufw.log") {
        let lines: Vec<&str> = t.lines().collect();
        let tail = lines[lines.len().saturating_sub(300)..].join("\n");
        return LogState {
            entries: parse_log(&tail),
            needs_admin: false,
        };
    }
    LogState {
        entries: vec![],
        needs_admin: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_addresses() {
        assert_eq!(
            parse_hex_addr("0100007F:0035"),
            Some(("127.0.0.1".parse().unwrap(), 53))
        );
        assert_eq!(
            parse_hex_addr("0000000000000000FFFF00000100A8C0:01BB"),
            Some(("192.168.0.1".parse().unwrap(), 443))
        );
        assert_eq!(
            parse_hex_addr("00000000000000000000000001000000:0016"),
            Some(("::1".parse().unwrap(), 22))
        );
    }

    #[test]
    fn ufw_log_line() {
        let l = "2026-10-27T14:03:11-04:00 proton kernel: [UFW BLOCK] IN=wlp0s20f3 OUT= MAC=01:00:5e:00:00:fb:a4:83:e7:12:34:56:08:00 SRC=192.168.1.20 DST=224.0.0.251 LEN=73 TOS=0x00 PROTO=UDP SPT=5353 DPT=5353 LEN=53";
        let e = parse_log_line(l).unwrap();
        assert_eq!(e.action, "Blocked");
        assert_eq!(e.direction, "Incoming");
        assert_eq!(e.address, "192.168.1.20");
        assert_eq!(e.mac, "a4:83:e7:12:34:56");
        assert_eq!(e.port, Some(5353));
        assert_eq!(e.proto, "UDP");
        let o = "2026-10-27T14:05:00-04:00 proton kernel: [UFW BLOCK] IN= OUT=wlp0s20f3 SRC=192.168.1.5 DST=203.0.113.9 LEN=60 PROTO=TCP SPT=40000 DPT=443 WINDOW=64240 SYN URGP=0";
        let e = parse_log_line(o).unwrap();
        assert_eq!(e.direction, "Outgoing");
        assert_eq!(e.address, "203.0.113.9");
        assert_eq!(e.port, Some(443));
    }
}
