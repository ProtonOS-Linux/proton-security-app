# Architecture

This page explains how Proton Security is put together, so you can find your way around the code. Every source
file also starts with a comment saying what it is for, and every function has a doc comment; run
`cargo doc --document-private-items --open` to browse them.

## Three programs in one binary

The package installs one executable, `/usr/bin/proton-security`, plus one shell script. Which part runs depends
on how it is started:

| Started as | Runs as | What it does | Entry point |
|---|---|---|---|
| `proton-security [--page]` | the user | The window | `main()` → `App` in [`main.rs`](../src/main.rs) |
| `proton-security --tray` | the user | Tray icon and background protection; started at login by `/etc/xdg/autostart/proton-security-tray.desktop` | [`tray::run`](../src/tray.rs) |
| `pkexec …/proton-security-helper <cmd>` (or `…-protected`) | root | The only privileged code: a whitelisted shell script, installed under two names (see [SECURITY-MODEL.md](SECURITY-MODEL.md#polkit)) | [`packaging/proton-security-helper`](../packaging/proton-security-helper) |

There are also two one-shot modes: `--scheduled-scan` (a quick scan without a window) and `--report` /
`--diagnose` (print and exit).

The window and the tray never need administrator rights to *look* at the system. They read files that every user
can read (`/proc`, `/sys`, `/etc/…`), run read-only commands (`systemctl is-active`, `apt list`, `lsblk`,
`busctl`…), and change only the user's own settings (KDE screen lock, Flatpak overrides). See
[SECURITY-MODEL.md](SECURITY-MODEL.md).

## Source layout

```text
src/
├── main.rs            Window shell: Page enum, App state, side menu, admin task window, dialogs,
│                      single-instance socket, command-line modes, --diagnose
├── ui.rs              Colors, line icons (inline SVG), status badges, cards, buttons, status shield
├── sys.rs             Small OS helpers: run a command, read a file, systemctl, dpkg, time formatting
├── settings.rs        Per-user settings (~/.config/proton-security/settings.json)
├── policy.rs          Company policy (/etc/proton-security/policy.conf)
├── admin.rs           Runs the pkexec helper on a thread and streams its output to the window
│
├── checks.rs          The nine "Security at a glance" checks + fingerprint() change detection
├── antivirus.rs       ClamAV: version/definitions, scans (clamscan), history, quarantine
├── watchers.rs        Background watchers used by the tray: Downloads, opened USB drives, new USB devices
├── firewall.rs        Firewall status, network connections (/proc/net), UFW log, rules added from the app
├── account.rs         Screen lock, automatic sign-in, password, administrators, PowerDevil inhibitions
├── devsec.rs          Secure Boot, TPM, disk encryption
├── health.rs          Restart needed, disk space, disk health (UDisks2), battery, memory
├── restore.rs         Snapper: configs, restore point list, schedule detection (timers and cron)
├── backup.rs          Finds backup tools (Kup, Déjà Dup, Pika, timers)
├── appperms.rs        Flatpak permissions and per-user overrides
├── devices.rs         Hardware enumeration from sysfs (device manager), driver details
├── report.rs          The HTML security report
├── tray.rs            Tray icon (StatusNotifierItem via ksni), background loop, notifications
│
└── page_*.rs          Drawing code, one file per page (they add methods to `App`):
    page_home.rs       Security at a glance (tile grid)
    page_av.rs         Virus & threat protection
    page_firewall.rs   Firewall & network
    page_account.rs    Account protection + Device security (+ disk encryption dialogs)
    page_health.rs     Device performance & health
    page_apps.rs       App permissions + File backup section
    page_restore.rs    Restore & backup
    page_devices.rs    Device manager
packaging/             Helper script, polkit policy, .desktop files, AppStream metadata, policy example
debian/                Package maintainer scripts (preinst, postinst, prerm, postrm)
assets/                App icon (SVG and PNG)
docs/                  These documents and the screenshots
```

**Rule of thumb:** a *data* module (`account.rs`, `health.rs`…) only reads the system and returns plain structs;
a *page* module (`page_account.rs`…) only draws those structs and reacts to clicks. Data modules don't depend on
egui (except `antivirus.rs`, which can ask the window to repaint during a scan).

## The window

The UI uses [egui](https://github.com/emilk/egui) through eframe in *immediate mode*: `App::ui` draws the whole
window every frame from the current state, so there is no widget tree to keep in sync.

### Never block the UI thread

Most checks take tens to hundreds of milliseconds (they run commands), so each page's data sits in a
[`Bg<T>`](../src/main.rs):

```rust
// In a page: refresh every 60 s, draw a spinner until the first result arrives.
if self.health.stale(Duration::from_secs(60)) {
    self.health.refresh(&ctx, crate::health::load);   // runs on a background thread
}
let Some(h) = self.health.get() else { ui.add(egui::Spinner::new()); return; };
```

`refresh` starts the function on a thread (unless one is already running) and asks egui to repaint when it
finishes. Long jobs (scans, admin tasks, saving files) follow the same idea with shared state
(`Arc<Mutex<…>>`, see `sys::Shared`).

### Administrator actions

`App::run_admin` starts [`admin::spawn`](../src/admin.rs), which runs
`pkexec /usr/libexec/proton-security/proton-security-helper <args>` on a thread (or `…-protected` for commands
that lower protection, see `admin::PROTECTED_COMMANDS`) and collects its output line by
line. The window shows a progress window with the live log. When the task ends, `App::poll` looks at the
`AfterAdmin` value stored with it to decide what to do next (refresh everything, show the restore point list,
show a recovery key…).

Passwords (disk encryption) go to the helper's **standard input**, never its command line.

### One window only

The first window listens on a Unix socket, `$XDG_RUNTIME_DIR/proton-security.sock`. Starting the app again
(menu, tray click, `--firewall`…) connects to that socket, sends the page flag, and exits; the running window
comes to the front and switches page.

### Fitting small screens

On screens smaller than 1280×900 the window opens maximized. "Security at a glance" computes the tile size from
the space available and chooses how many detail lines fit (`page_home::tile_style`), so it never scrolls.

## The tray (background protection)

[`tray::run`](../src/tray.rs) registers a StatusNotifierItem (the system tray icon) and then loops every
5 seconds:

1. **New USB devices**: compare `/sys/bus/usb/devices` with the last loop; notify about keyboards, network
   adapters and drives.
2. **Downloads**: files in `~/Downloads` that are new and have stopped growing are scanned on a thread.
3. **Opened USB drives**: new mount points under `/media` or `/run/media` are scanned on a thread.
4. **Re-check** when something changed (see below), and update the icon, tooltip and menu.
5. **Daily quick scan** when due (runs `proton-security --scheduled-scan` at idle priority).

If Plasma's system tray isn't there yet (early at login), the loop still runs and the icon is registered as soon
as possible, so protection never waits for the panel. A lock file (`proton-security-tray.lock`) makes sure only
one tray runs per user; the window uses it to show "Background protection is running".

### Noticing changes

The tray and the window both call [`checks::fingerprint`](../src/checks.rs) every 5 seconds. It is a cheap
summary (about 60 ms) of everything the tiles depend on: modification times of a few files and folders
(`/var/lib/dpkg/status`, `/etc/ufw/ufw.conf`, `/var/lib/clamav`, Snapper's config…), the state of the relevant
systemd units, and the account problems (screen lock, automatic sign-in, battery menu switch).

- **Tray:** when the fingerprint changes *and then stays the same for one more poll* (so a running `apt` is
  checked once it ends), all checks run again.
- **Window:** when it changes, the checks are refreshed; when the window's results change, it touches
  `$XDG_RUNTIME_DIR/proton-security.changed` so the tray re-checks too.

The window also watches the scan history and quarantine files, because the tray writes to them.

## Files on disk

Written by the app and the tray (as the user):

| Path | What |
|---|---|
| `~/.config/proton-security/settings.json` | Settings: daily scan, download/USB scanning, USB alerts, firewall rules added, backup choice |
| `~/.local/share/proton-security/scan-history.json` | Protection history (30 days) |
| `~/.local/share/proton-security/quarantine/` | Quarantined files (folder mode 700, files mode 000) and `index.json` |
| `~/.cache/proton-security/scan-list-*.txt` | The list of files given to ClamAV during a scan (folder mode 700, file mode 600), deleted afterwards |
| `~/Documents/Proton-Security-Report-*.html` | Exported reports (where you choose) |
| `~/.config/kscreenlockerrc` | Changed by *Turn on screen lock* |
| `~/.local/share/flatpak/overrides/` | Changed by the App permissions page (`flatpak override --user`) |
| `$XDG_RUNTIME_DIR/proton-security.sock`, `*.lock`, `proton-security.changed` | Single instance, tray lock, "re-check now" marker |

Files are written to a temporary name and renamed, because the window and the tray may write at the same time.

Written by the helper (as root, only when you confirm an action): see the
[helper commands](SECURITY-MODEL.md#helper-commands); for example `/etc/apt/apt.conf.d/20auto-upgrades`,
`/etc/modprobe.d/proton-security-disabled.conf` or UFW rules.

Read only: `/etc/proton-security/policy.conf` (the [company policy](POLICY.md)).

## Dependencies

| Crate | Used for |
|---|---|
| `eframe`, `egui`, `egui_extras` | Window, widgets, tables, SVG icons |
| `ksni` | System tray icon (StatusNotifierItem over D-Bus) |
| `resvg` | Rendering the tray icon's SVG to pixels |
| `serde`, `serde_json` | Settings, history, Snapper and busctl JSON |
| `chrono` | Dates in logs, history and the report |
| `walkdir` | Walking folders (scans, Downloads, USB drives) |
| `flate2` | Reading rotated (gzip) apt history logs |

Everything else is done with the Rust standard library and the system's own tools.
