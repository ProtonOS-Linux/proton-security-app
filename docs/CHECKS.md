# The checks on "Security at a glance"

Each tile is one check. It is **green** when everything in the "Green when" column is true, and **yellow** as
soon as one item is not. Any yellow tile also turns the **tray icon** yellow. All checks run as the normal
user; nothing here needs a password. The code lives in [`src/checks.rs`](../src/checks.rs) (one function per
tile), with the details read by the module named in each section.

Buttons marked **(admin)** run a helper command through `pkexec`, so they ask for the administrator password;
the commands are described in [SECURITY-MODEL.md](SECURITY-MODEL.md#helper-commands).

When things change outside the app (a package is removed, `ufw disable`, the battery menu's switch), the tray
and the window notice within about 5 seconds and run the checks again. See
[ARCHITECTURE.md](ARCHITECTURE.md#noticing-changes).

---

## Virus & threat protection

Data: [`src/antivirus.rs`](../src/antivirus.rs)

| Green when | Value |
|---|---|
| ClamAV (`clamscan`) is installed | |
| Virus definitions update automatically | `clamav-freshclam.service` running **and** enabled |
| Virus definitions are recent | at most **7 days** old (`DEFS_STALE_DAYS`) |
| A scan finished recently | within **14 days** (`SCAN_STALE_DAYS`); any scan counts, including the daily one |
| No threat is waiting for a decision | every threat was quarantined, deleted or allowed |

Buttons: **Install ClamAV** (admin, `install-clamav`) · **See threats** · **Turn on** automatic definition
updates (admin, `av-auto on`) · **Update definitions** (admin, `av-update`) · **Quick scan**.

Background protection, run by the tray (each can be switched off on the page or in the tray menu, unless the
company policy forces it):

- **Daily quick scan**: once every 24 hours, at least 10 minutes after login, at the lowest CPU and disk
  priority, and not on battery below 30%. Notifies only when a threat is found.
- **New file check** (setting *Scan new files…*, policy key `scan_downloads`): new files are scanned once they
  stop growing, in every place files arrive:

  | Place | Looks at | You are told |
  |---|---|---|
  | Downloads (`xdg-user-dir DOWNLOAD`) and its direct subfolders | every file | either way ("… is safe" / "Threat found") |
  | Flatpak apps' own `~/.var/app/<app>/Downloads` | every file | either way |
  | The desktop (`xdg-user-dir DESKTOP`) | every file | only threats |
  | `/tmp/mozilla_<user>0` (files opened from Firefox or Thunderbird without saving) | every file | only threats |
  | `/tmp` and `/dev/shm`, files directly in them | only your own risky files | only threats |

  Partial downloads (`.part`, `.crdownload`, Chrome's hidden temporary files…) are skipped. Hidden files and
  files over 1 GB are checked only when they are risky. Risky files are checked first.
- **Risky files** ([`src/risk.rs`](../src/risk.rs)) are programs, scripts, installers, documents that can carry
  macros or exploits, and archives, recognized three ways: by name (`.sh .bash .run .bin .AppImage .deb .rpm
  .snap .flatpak .flatpakref .desktop .py .pl .rb .php .js .jar`, `.exe .msi .com .scr .dll .bat .cmd .ps1 .vbs
  .hta .lnk`, `.pdf .rtf .doc .xls .ppt .docm .xlsm .pptm .odt .ods`, `.zip .7z .rar .tar .gz .tgz .xz .bz2 .zst
  .iso .img .cab`), by content (the first bytes of a Linux or Windows program, a script, PDF, Office document or
  archive, so a program renamed `photo.jpg` still counts), or by the executable bit (not on USB drives, where
  FAT/exFAT/NTFS often mark every file as runnable).
- **Re-check after a definition update**: clean files from the new file, startup and download checks are
  remembered for 7 days (at most 2000). When the files in `/var/lib/clamav` change, at most once every 4 hours,
  at least 10 minutes after login and not on battery below 30%, they are scanned again at idle CPU and disk
  priority. You hear about it only if a threat is found (then it is also in the history).
- **Startup watch** (setting *Tell me when a program is set to start automatically*, policy key
  `watch_startup`), see [`src/startup.rs`](../src/startup.rs). Every 30 seconds the tray compares the sizes and
  dates of the places programs use to start automatically with what it saw before (kept in
  `startup-baseline.json`, so changes made while it wasn't running are noticed at the next login). Each new or
  changed item is scanned with ClamAV:

  | Place | You are told when |
  |---|---|
  | `~/.config/autostart` (sign-in programs) | an item is added or now runs a different program, unless it is switched off (`Hidden=true`) |
  | `~/.config/systemd/user` (background tasks, `systemctl --user enable`) | a unit or enable link is added, or a unit runs a different program |
  | `~/.config/plasma-workspace/env`, `…/shutdown` (KDE sign-in/out scripts) | a script is added or gets new lines |
  | `.bashrc .profile .bash_profile .bash_login .bash_logout .zshrc .zprofile` | an added line looks suspicious |
  | `~/.local/bin` (personal programs) | a new script looks suspicious |
  | `~/.local/share/applications` (app shortcuts) | a shortcut runs something suspicious |

  and always when ClamAV finds a threat. "Suspicious" means downloading (`curl`, `wget`), decoding hidden text
  (`base64 -d`), opening network connections (`/dev/tcp/`, `nc -e`, `socat`), running inline Python/Perl, piping
  text into a shell (`| sh`), running from `/tmp`, `/dev/shm`, Downloads, `~/.cache` or `~/.config`, `LD_PRELOAD`,
  or replacing `sudo`/`su` with an alias. Ordinary installer lines (`. "$HOME/.cargo/env"`, `export PATH=…`) stay
  quiet.
- **USB drive check**: a drive opened under `/media` or `/run/media` is scanned, up to 3000 files: risky files
  first and whatever their size, then other files up to 100 MB, skipping photos, music and videos. Notifications
  at the start and with the result.

Background scans run ClamAV at low CPU priority (`nice 15`) and the lowest normal disk priority (`ionice -c2 -n7`);
re-checks at idle priority (`nice 19`, `ionice -c3`). With `clamscan`, files up to 2 GB are scanned (at most 512 MB
of each); with the ClamAV daemon, its own limits in `/etc/clamav/clamd.conf` apply.

All scans are recorded in the protection history (kept 30 days; scans with unhandled threats are kept until
handled).

## Automatic security updates

Data: [`src/checks.rs`](../src/checks.rs) (`security_updates`)

| Green when |
|---|
| The `unattended-upgrades` package is installed |
| `unattended-upgrades.service` is active |

The tile also shows the last time packages changed (from `/var/log/apt/history.log`) and notes when the
security archive is missing from the allowed sources.

Button: **Turn on** (admin, `enable-security-updates`).

## Package & Flatpak updates

Data: [`src/checks.rs`](../src/checks.rs) (`updates`)

| Green when | Value |
|---|---|
| Package lists were refreshed recently | within **30 days** (`STALE_DAYS`) |
| Packages were upgraded recently, or nothing is waiting | last `apt` upgrade within 30 days, or `apt list --upgradable` is empty |
| Packages update automatically | unattended-upgrades fully set up **and** allowed to install regular (not only security) updates |
| Flatpak apps were updated recently (if any are installed) | within 30 days |
| Flatpak apps update automatically (if any are installed) | an enabled Flatpak update timer (system or user), or Discover's "Apply updates automatically" |

Buttons: **Turn on automatic updates** (admin, `enable-auto-updates`) · **Update now** (admin, `update-now`).

## Firewall & network protection

Data: [`src/firewall.rs`](../src/firewall.rs)

| Green when |
|---|
| UFW is installed, `ENABLED=yes` in `/etc/ufw/ufw.conf`, and `ufw.service` is active — **or** `firewalld.service` is active |

Buttons: **Turn on** (admin, `enable-firewall`: deny incoming, allow outgoing, keep local discovery working) ·
**View connections**.

## Account protection

Data: [`src/account.rs`](../src/account.rs)

| Green when | Value |
|---|---|
| The account has a password | `passwd -S` |
| No automatic sign-in | SDDM `[Autologin] User=` or LightDM `autologin-user=` |
| The screen locks automatically | KDE `kscreenlockerrc`: `Autolock` on |
| …soon enough | `Timeout` at most **15 minutes** (policy `max_screen_lock_minutes`) |
| …and after sleep | `LockOnResume` on |
| Screen locking isn't blocked from the battery menu | KDE PowerDevil has no manual "block sleep and screen locking" inhibition |

Being an administrator is shown as information (white "!") and never turns the tile yellow. Video players and
calls that pause screen locking while they play are listed but don't count either.

Buttons: **Set a password** (opens System Settings) · **Turn off automatic sign-in** (admin,
`disable-autologin`) · **Turn on screen lock** (no password: edits your own KDE settings) · **Account settings**.

## Device security

Data: [`src/devsec.rs`](../src/devsec.rs)

Information only: Secure Boot, TPM chip and disk encryption are shown but don't turn the tile yellow, because
most people can't change them after installation. A [company policy](POLICY.md) can make them required:

| Yellow when | Policy key |
|---|---|
| `/` or `/home` is not encrypted | `require_disk_encryption = yes` |
| Secure Boot is not on | `require_secure_boot = yes` |

For encrypted drives the page offers (admin): **Create recovery key** (`luks-add-recovery`), **Change disk
password** (`luks-change-password`), **Back up encryption header** (`luks-header-backup`).

## Device performance & health

Data: [`src/health.rs`](../src/health.rs)

| Green when | Value |
|---|---|
| No disk reports it is failing | SMART "failing", or an NVMe critical warning (UDisks2) |
| Enough free space on `/` and `/home` | low means under **5 GB**, or under **10%** while also under 15 GB |
| No restart is recommended | no `/run/reboot-required`, no newer kernel in `/boot`, and up less than **15 days** |
| The battery isn't worn out | holds at least **40%** of its original charge |

Bad sectors (SATA) and media errors (NVMe) are shown on the page and in the report.

Buttons: **Restart now** (asks you to save your work first) · **Free up space** · **Details**.

## System restore

Data: [`src/restore.rs`](../src/restore.rs)

| Green when | Value |
|---|---|
| `/` is Btrfs | Snapper restore points need Btrfs |
| Snapper is installed and has a configuration | |
| Restore points are made automatically | a schedule is found (Snapper's timeline / boot timers, any other timer or cron job that runs `snapper … create`), **or** a restore point is at most **8 days** old |

Buttons: **Turn on** (admin, `enable-snapper`) · **View restore points**.

## File backup

Data: [`src/backup.rs`](../src/backup.rs)

| Green when | Value |
|---|---|
| Your files are backed up | Kup with a backup plan, Déjà Dup used or scheduled, Pika Backup configured, a user timer named like a backup tool — **or** you ticked *I back up my files another way* |
| The last backup is recent | at most **14 days** old, when the tool records a date |

Snapper or Timeshift snapshots of `/home` are listed but **don't count**: they are on the same disk and are lost
with it. `require_backup = no` in the [policy](POLICY.md) keeps this tile green.

Buttons: **Set up backup** (opens Kup; installs it first if needed, admin `install-kup`) · **I back up another way**.
