# Changelog

All notable changes to Proton Security are listed here, newest first.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [0.4.9] - 2026-11-01

### Added
- **More places are checked for new files.** Besides Downloads, the tray now checks new files on the desktop, in
  Flatpak apps' own Downloads folders, files opened straight from Firefox or Thunderbird (`/tmp/mozilla_*`), and
  your own programs and scripts saved in `/tmp` and `/dev/shm`. Downloads still tell you "… is safe"; the other
  places are checked quietly and only threats are reported.
- **Risky files first.** Programs, scripts, installers, macro documents and archives are recognized by name, by
  content (a program renamed `photo.jpg` is still caught) and by the executable bit. They are checked first and
  even when they are big or hidden; on USB drives they are never skipped as "photos" or "too big".
- **Startup watch.** New setting *Tell me when a program is set to start automatically* (on by default, policy
  key `watch_startup`, also in the tray menu). The tray watches sign-in programs, background tasks for your
  account, KDE sign-in scripts, `.bashrc`/`.profile`, `~/.local/bin` and app shortcuts, scans every new or changed
  item, and tells you about new sign-in programs and anything suspicious, for example a `.bashrc` line that
  downloads and runs a script. Changes made while the tray wasn't running are noticed at the next login.
- **Re-check after definition updates.** The last week's new files are scanned again, at idle priority and at
  most every 4 hours, when ClamAV's virus definitions change, because new threats are often recognized only a day
  or two later. You hear about it only if something is found.

### Changed
- Background scans with `clamscan` now check files up to 2 GB (reading at most 512 MB of each) instead of
  silently skipping files over 100 MB, and run at the lowest normal disk priority.

### Fixed
- New downloads that finished while another download was being checked were never checked. They now wait in a
  queue.

### Security
- Notification text is escaped, so a file name, drive label or USB device name can no longer add links or
  formatting to a Proton Security notification (audit finding 5).

## [0.4.8] - 2026-10-30

### Added
- **Firewall & network: *Add a rule…*** opens a form to block or allow incoming connections to a port (TCP or UDP),
  or block an address, with an optional name. Input is checked before anything runs (port 1–65535, a real IP
  address, not this computer), and the rule appears in *Rules you added*. Allowing a port asks for the
  administrator password every time, like other changes that lower protection. Hidden by the policy key
  `allow_firewall_changes = no`.

### Fixed
- **Device manager no longer flickers.** "Watch for new devices" re-scanned all hardware every 4 seconds (running
  driver lookups each time) and a spinner appeared in the toolbar, shifting it. It now checks a cheap summary of
  the hardware every 3 seconds and re-scans only when something is plugged in or out or a driver changes; the
  spinner only shows for a scan you start, in a space that is always reserved.
- Text boxes in the new firewall form have visible borders in the light theme.

### Removed
- *Power management settings* link on Account protection.

## [0.4.7] - 2026-10-29

Security fixes from the audit of 0.4.6. Please upgrade.

### Security
- **A crafted file name could make a scan blame another file.** A file whose name contains a line break (for
  example `holiday⏎important.odt`) made ClamAV print a line naming a different file, and *Quarantine* or *Delete*
  then acted on that file in the home folder while the real threat stayed hidden. Anyone who can put a file in
  `/tmp` (scanned by the daily quick scan) or on a USB drive could use it. Scans now give ClamAV an exact list of
  files with plain names; files with unusual names are scanned one at a time through ClamAV's standard input; a
  result counts only for an absolute path the app actually sent; Quarantine and Delete refuse incomplete paths.
- **Background scans skipped files with unusual names.** Download and USB checks split such names in two, so the
  file was never scanned. They are now scanned through standard input like above.
- **A remembered administrator password could be reused for commands that lower protection.** The helper is now
  installed under a second name, `proton-security-helper-protected`, with its own polkit action that asks for the
  password every time. It runs only the commands that lower protection or touch disk-encryption secrets (open
  firewall ports, stop definition updates, uninstall / reload / load drivers, disk recovery keys and passwords,
  restore point access), and the everyday helper refuses them.
- `load-module` and `driver-enable` only accept drivers that match a device in the computer (or that Proton
  Security disabled), instead of any installed kernel module.
- The list of files to scan is no longer written to `/tmp`, where other accounts could read it; it goes to
  `~/.cache/proton-security` (mode 600) and is deleted after the scan.
- A quarantine that failed halfway (a file that can't be removed, such as another account's file in `/tmp`) no
  longer leaves a readable copy of the dangerous file in the quarantine folder; the app explains that an
  administrator needs to remove it.

### Changed
- File names with control characters are shown with visible symbols (a line break as ⏎).
- New regression tests replay the attack against the real scan code and ClamAV.

## [0.4.6] - 2026-10-29

First public (open-source) release.

### Security
- **Encryption header backup**: the helper no longer changes the owner or permissions of a file inside the
  user's own runtime folder as root. The backup is now copied there with the user's own rights (`setpriv`), so a
  file swapped in at the last moment can't trick root into handing over a system file.
- The helper no longer writes `modprobe`'s error output to a fixed file name in `/tmp`.
- The `PROTON_SECURITY_HELPER` override (use a different helper script) now works in debug builds only.

### Changed
- Every source file is documented: a header explaining the file, a comment on every function, type and
  non-obvious field, and a description of every helper command.
- New repository documents: README, architecture, security model, checks reference, policy reference,
  development and packaging guides, contributing guide, security policy, code of conduct.
- Licensed under GPL-3.0-or-later (`LICENSE`, SPDX headers in every file).
- GitHub Actions: formatting, lints, tests, documentation and `.deb` build on every push; releases attach the `.deb`.

## [0.4.5] - 2026-10-29

- **Protection history updates live**: USB drive scans, download checks and the daily scan are run by the
  tray, which writes them to the history file; the open window now watches that file (and the quarantine list)
  and shows new entries and threats within about 2 seconds, without reopening the app.
- **New app icon colour**: the same shield, now magenta (menu, taskbar, window icon). The green/yellow tray
  status icons are unchanged.

## [0.4.4] - 2026-10-29

- **The tray watches for changes in the background**: every 5 seconds it looks at the things behind the tiles
  (installed packages, the firewall configuration, the unattended-upgrades / firewall / ClamAV / Snapper
  services and timers, virus definitions, restore and backup settings, pending restarts, screen lock and
  sign-in). When something changes, for example ClamAV is removed, `ufw disable` is run or
  unattended-upgrades is stopped, it runs all checks again as soon as the change is finished (an `apt` run in
  progress is checked once, when it ends), and the icon turns yellow or green within a few seconds. Cost:
  about 60 ms of work every 5 seconds.
- The open window uses the same watcher, so its tiles and side menu badges follow the same changes.
- **Account protection**: new *Power management settings* link next to *Screen locking settings*.

## [0.4.3] - 2026-10-29

- **Tray icon follows screen lock changes**: the tray and the open window now check the screen lock and
  sign-in settings every 5 seconds, so switching "Sleep and screen locking after inactivity" off or on in the
  battery menu turns the tray icon yellow or green again within a few seconds (it used to wait up to 10
  minutes, or for another change). The window's side menu badges update the same way, and the window tells
  the tray whenever its results change.

## [0.4.2] - 2026-10-29

- **Account protection → Administrators**: "Your account is an administrator" now has a white "!" notice icon.
  It is information only and never turns the tile or the tray icon yellow.
- **File backup**: Snapper and Timeshift snapshots of your home folder no longer count as a backup (they are
  on the same disk and are lost with it). They are still listed, but the File backup tile stays yellow until a
  real backup (Kup, Déjà Dup, Pika, a backup timer) is set up or you tick *I back up my files another way*.

## [0.4.1] - 2026-10-28

- **Account protection**: the screen lock tile turns yellow when "Sleep and screen locking after inactivity"
  is switched off in the battery (power) menu, and the page explains how to switch it back on. Video players
  and calls that pause locking while they play are listed but don't count as a problem.
- **Device security → Disk encryption** (for encrypted drives, admin password needed):
  *Create recovery key* (a 48-digit key added as a second way to unlock the drive, shown once, *Save to file…*
  or *Copy*), *Change disk password*, *Back up encryption header* (saved where you choose).
  The system drive can't be encrypted or decrypted while running from it, so the page explains how
  (choose encryption when installing; USB and data drives with KDE Partition Manager).
- Firmware section removed from Device security.
- **Performance & health**: a restart is recommended after **15 days** without one. *Restart now* (page and
  tile) first asks you to save your work and close your apps.
- **Disk health** shows **Bad sectors** (SATA/HDD: reallocated + pending sectors) or **Media errors** (NVMe),
  also in the report.
- **App permissions**: removed the "Advanced: Flatpak permissions in System Settings" link.
- **USB drives are scanned automatically** when you open them (mounted under `/media` or `/run/media`):
  programs, documents and archives (up to 3000 files, photos/videos/files over 100 MB skipped). You get a
  "Checking…" notification and the result; it's saved in the protection history as "USB drive scan".
  Setting: *Scan USB drives and memory cards when I open them* (Virus & threat protection, tray menu,
  policy key `scan_usb`).
- **Download checks are visible**: every new download gives a "Download checked: … is safe" (or threat)
  notification and appears in the protection history; if ClamAV can't run (missing definitions, not
  installed) you're told why instead of silence. The tray tooltip shows what's being checked.
- Background protection (download/USB checks, daily scan) now works even when the tray icon can't be shown,
  and the Virus & threat protection page says whether it is running, with a *Start it* button.

## [0.4.0] - 2026-10-28

New pages and tiles (Security at a glance now has 9 tiles, still no scrolling):

| Page / tile | What it checks | Fixes |
|---|---|---|
| **Account protection** | Screen lock on and delay (≤ 15 min), lock after sleep, automatic sign-in (SDDM/LightDM), account password, administrator accounts | *Turn on screen lock* (no password), *Turn off automatic sign-in* (admin), System Settings links |
| **Device security** | Secure Boot, TPM, disk encryption of `/` and `/home`, swap | Info only, unless the policy requires encryption / Secure Boot; firmware updates via Discover |
| **Performance & health** | Restart required (pending updates or newer kernel), disk space, disk health (SMART via UDisks2), battery health, memory | *Restart now*, *Empty trash and cache* (no password), *Clean up system files* (admin) |
| **File backup** (on *Restore & backup*) | Kup, Déjà Dup, Pika, Snapper home config, Timeshift with home, backup timers; warns after 14 days | *Set up backup* (installs/opens Kup), *I back up my files another way* |
| **App permissions** | Flatpak apps' access to all files, home folder, camera & devices, microphone & sound, network (including your own overrides) | Tick/untick per app (`flatpak override --user`, no password), *Reset* |

Also:

- **Scan new downloads**: the tray checks each new file in Downloads with ClamAV once it finishes
  downloading (uses `clamd` if running). Threats are notified and added to the protection history.
- **USB alerts**: notification when a new USB keyboard (BadUSB), network adapter or drive is plugged in.
- **Company policy** `/etc/proton-security/policy.conf` (example in
  `/usr/share/doc/proton-security/policy.conf.example`): organization name, force daily scan / download
  scanning / USB alerts on or off, block driver / firewall / app permission changes, require disk encryption /
  Secure Boot / backup, maximum screen-lock delay, hide pages.
- **Security report**: *Export report* on Security at a glance, or `proton-security --report [file.html]` for
  scripts. One HTML file; print it to PDF from the browser.
- New command-line pages: `--account`, `--device-security`, `--health`, `--apps`.

## [0.3.2] - 2026-10-28

- Fits small screens: on screens smaller than 1280×900 (for example 1366×768 laptops) the window opens
  maximized, so it never goes under the taskbar. Minimum window size lowered to 800×560.
- Tile text wraps onto a second line instead of being cut off (e.g. "Unattended security updates: Not installed"),
  and a line is only shown when it fully fits above the buttons.
- Side menu footer: "App created by Proton OS", a link to www.protonos.org, and the version number.
- AppStream metadata now includes the homepage (validates cleanly).

## [0.3.1] - 2026-10-27

- **Automatic security updates** follows `unattended-upgrades.service`: the tile shows
  "Unattended security updates: **Active**" (green) or "**Not active**" (red), and "Package last update: <date>".
  Disabling the service (`systemctl disable --now unattended-upgrades`) turns the tile yellow.
- **Uninstall driver** removes the driver from the system:
  - a driver shipped in its own package (DKMS, NVIDIA, Broadcom, Realtek…) is **purged** with `apt purge`;
    the dialog lists every package that will be removed (dry run first, no password needed for that);
  - a driver that is part of the Linux kernel can't be deleted without removing the kernel, so it is
    **blocked permanently** instead (survives restarts; *Enable driver* undoes it).
  - Refused for core drivers and whenever the removal would take an essential package or a kernel with it.

## [0.3.0] - 2026-10-27

- **Firewall tab** (5th tab): live list of network connections (program, status, IP address, MAC address,
  protocol/service) with **Allow / Block** buttons, a "Rules you added" list with Remove, and a **firewall log**
  table (time, blocked/allowed, direction, address, MAC, port, protocol, network).
- **No background service runs as administrator.** The 0.2.0 restore-point service was removed (and is cleaned
  up on upgrade). Restore points are listed after you click *Show restore points* and enter your password.
  Admin rights are only used for the action you just clicked.
- **Driver actions fixed**: *Uninstall* only unloads the driver (it comes back after a restart or with *Load
  driver*); *Reinstall* unloads and loads it again; *Update* no longer fails with "error code 1".
- **Protection history keeps 30 days** (scans with threats you haven't handled stay until you handle them).
- **Automatic security updates tile** shows "Unattended security updates: installed and enabled" and
  "Packages last updated and installed: <date>".
- The big shield on *Security at a glance* is the same green ✓ / yellow ! artwork as the tray icon.
- **Shows in KDE Discover** (AppStream metadata) and installs from Discover / PackageKit.

## [0.2.0] - 2026-10-27

- **Tray icon** next to the volume/network icons: green shield ✓ when everything is OK, yellow shield ! when
  something needs attention (hover for the list). Click to open the app; right-click for shortcuts and the
  daily scan toggle. Starts at login (`/etc/xdg/autostart`) and **right after installing** the package.
- **Opens automatically after installation** (fresh install only; upgrades just restart the tray).
- **Daily automatic quick scan**, on by default, run by the tray at low CPU/disk priority (10 min after login,
  skipped on low battery). Turn it off with the checkbox on *Virus & threat protection* or in the tray menu.
  You get a desktop notification only if a threat is found.
- **Security at a glance** never scrolls: five tiles of identical size that resize with the window, in this
  order: Virus & threat protection, Automatic security updates, Package & Flatpak updates, Firewall, System restore.
  On narrow windows the side menu collapses to icons automatically.
- **System restore detection rewritten**: recognizes any schedule that creates Snapper snapshots: the
  `snapper-timeline` timer (including drop-ins such as `OnCalendar=Fri`), custom systemd timers whose
  service or script runs `snapper … create`, and cron jobs. A restore point from the last 8 days also counts.
- ~~Restore points list without a password~~ (background root service, removed in 0.3.0).
- **Driver actions** in Device manager: *Update driver*, *Reinstall driver*, *Uninstall driver* (and
  *Enable driver* to undo). Core devices (disks, USB controllers, keyboard/mouse, processors) can't be uninstalled.
- `proton-security --diagnose` prints what the app detects (schedules, export file, every check).

## [0.1.0] - 2026-10-26

First version: Security at a glance with five checks (antivirus, security updates, package updates, firewall,
system restore), a ClamAV front end with quick / full / custom scans, a Snapper restore point list and a device
manager.

[0.4.9]: https://github.com/ProtonOS-Linux/proton-security-app/releases/tag/v0.4.9
[0.4.8]: https://github.com/ProtonOS-Linux/proton-security-app/releases/tag/v0.4.8
[0.4.7]: https://github.com/ProtonOS-Linux/proton-security-app/releases/tag/v0.4.7
[0.4.6]: https://github.com/ProtonOS-Linux/proton-security-app/releases/tag/v0.4.6
