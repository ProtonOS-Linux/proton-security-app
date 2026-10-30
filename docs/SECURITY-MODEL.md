# Security model

Proton Security is a security tool, so it has to be safe itself. This page says exactly what runs with which
rights, and lists every privileged command. If you find something that doesn't match this page, please report it
(see [SECURITY.md](../SECURITY.md)).

## Summary

- The window and the tray icon **always run as the signed-in user**. There is no background service running as
  root, and no setuid binary.
- Administrator rights are used **only** for the action the user just clicked, through
  `pkexec` + polkit, which asks for an administrator password.
- The only code that runs as root is [`packaging/proton-security-helper`](../packaging/proton-security-helper), a
  short Bash script that accepts a fixed list of commands and validates every argument. It is installed under two
  names: everyday fixes may reuse a recently typed password; commands that **lower protection** always ask again.
- Passwords never appear on a command line. Secrets are kept out of logs and are wiped from memory and disk
  after use.

## Who runs what

| Component | Runs as | Can change |
|---|---|---|
| Window (`proton-security`) | user | the user's own settings, quarantine, KDE screen-lock settings, Flatpak user overrides |
| Tray (`proton-security --tray`) | user | the user's history and settings; sends notifications |
| Helper (`proton-security-helper`, `proton-security-helper-protected`) | root, via pkexec | only what its commands below do |

Running the scans as the user means they can't read other users' files or protected system files. That is
deliberate: a scan can be stopped any time, and a bug in file handling can't become a root problem.

## polkit

The same script is installed twice, and each copy has its own polkit action
([policy file](../packaging/org.protonos.security.policy)). pkexec picks the action by the program's exact path:

| Installed as | polkit action | Password | Runs |
|---|---|---|---|
| `/usr/libexec/proton-security/proton-security-helper` | `org.protonos.security.helper` | `auth_admin_keep`: remembered for a few minutes | everyday fixes: turn things **on**, update, install tools, read logs and rules |
| `/usr/libexec/proton-security/proton-security-helper-protected` | `org.protonos.security.helper.protected` | `auth_admin`: asked **every time** | the **protected commands** below |

**Protected commands** lower the computer's protection or touch disk-encryption secrets: `fw-allow-port`,
`fw-remove-port`, `fw-unblock-ip`, `av-auto`, `driver-purge`, `driver-reinstall`, `driver-enable`,
`load-module`, `luks-add-recovery`, `luks-change-password`, `luks-header-backup`, `snapper-allow-sudo`.

The script checks the name it was started under: the everyday name refuses protected commands, and the protected
name refuses everything else. So a remembered password can never be reused for a protected command, not by Proton
Security and not by another program running as the user. (polkit ties a remembered password to whoever asked
for it; depending on the system that can cover more than one program, so this separation matters.)
The two lists are kept in sync by a unit test (`admin::tests`).

- polkit asks for an **administrator's** password (a member of `sudo`). On a standard account, an administrator
  has to type theirs; the user's own password isn't enough.
- Release builds always run the installed helpers. A debug build can point at another script with
  `PROTON_SECURITY_HELPER` (for development; protected commands then use the same path plus `-protected`); that
  code is not compiled into release builds.

## Rules the helper follows

1. **Whitelist.** The first argument must be one of the commands below; anything else exits with code 2.
2. **Validation before use.** Arguments are matched against strict patterns before they reach any command:

   | Argument | Allowed |
   |---|---|
   | Kernel module name | `^[a-z0-9_-]{1,64}$` |
   | Port | 1–65535, digits only |
   | Protocol | `tcp` or `udp` |
   | IP address | an IPv4 dotted address, or IPv6 hex digits and colons (no ranges, nothing that starts with `-`) |
   | Encrypted partition | `^/dev/[A-Za-z0-9/_.-]+$`, must be a block device and a LUKS partition |
   | Restore point description | at most 80 letters, digits, spaces and `.,_()/:-` |

3. **Arguments stay arguments.** Values are always passed quoted (`"$arg"`), modules after `--`, so they can't be
   interpreted as options or code.
4. **Core drivers are protected.** Drivers for disks, USB controllers, keyboards, filesystems and encryption (the
   `CRITICAL_RE` list) can't be reloaded or uninstalled. Package removals are simulated first and refused if they
   would remove a kernel or an essential/required package.
5. **No writes as root into user-controlled places.** Temporary secrets go to a private `mktemp` folder in
   `/run` (mode 700) that is shredded on exit. The encryption header backup is copied into the user's runtime
   folder *with the user's own rights* (`setpriv`), never chmod/chown'd there by root.
6. **Drivers only for real hardware.** `load-module` only loads a driver that matches a device in the computer
   (one of the modules the kernel itself would pick for a device's `modalias`). `driver-enable` also accepts a
   driver that Proton Security disabled before. Loading arbitrary kernel modules would widen the kernel's attack
   surface.
7. **Fail safely.** `set -euo pipefail`; a failing step stops the command.

## Helper commands

The window builds these command lines; each is shown here with what it changes.

### Updates

| Command | Does | Changes |
|---|---|---|
| `enable-security-updates` | Install unattended-upgrades if missing, turn on daily package lists and security upgrades | `/etc/apt/apt.conf.d/20auto-upgrades`; enables `apt-daily*.timer`, `unattended-upgrades.service` |
| `enable-auto-updates` | The above, plus regular stable updates and a daily Flatpak update | `/etc/apt/apt.conf.d/52proton-auto-updates`, `/etc/systemd/system/proton-flatpak-update.{service,timer}` |
| `update-now` | Install all updates now (apt, Flatpak, Snap) | packages |

### Firewall

| Command | Does |
|---|---|
| `enable-firewall` | Start firewalld if installed; otherwise install/enable UFW with deny-incoming / allow-outgoing (and allow mDNS 5353/udp for printers and sharing) |
| `fw-allow-port <port> <tcp\|udp>` | `ufw allow` (removes a matching deny first) |
| `fw-block-port <port> <tcp\|udp>` | `ufw deny` (removes a matching allow first) |
| `fw-remove-port <port> <tcp\|udp>` | Delete both rules for that port |
| `fw-block-ip <address>` | Deny in and out for one address (rule placed first), end its open connections (`ss -K`) |
| `fw-unblock-ip <address>` | Undo `fw-block-ip` |
| `fw-rules` | Print `ufw status verbose` (read only) |
| `fw-log` | Print the last 300 firewall log lines (read only) |

### System restore

| Command | Does |
|---|---|
| `enable-snapper` | Btrfs only: install Snapper, create the `root` config with cleanup limits, enable its timers, create a first restore point |
| `snapper-list` | Print the restore points as JSON (read only) |
| `snapper-create <description>` | Create a restore point |
| `snapper-allow-sudo` | Set `ALLOW_GROUPS=sudo` so administrators can list restore points without a password |
| `install-btrfs-assistant` | Install the package |

### Antivirus

| Command | Does |
|---|---|
| `install-clamav` | Install `clamav clamav-freshclam`, enable definition updates |
| `av-update` | Download definitions now (pauses `clamav-freshclam` meanwhile) |
| `av-auto on\|off` | Enable or disable `clamav-freshclam.service` |

### Devices and drivers

| Command | Does | Changes |
|---|---|---|
| `install-firmware` | Install firmware for this hardware with `isenkram-autoinstall-firmware` | packages |
| `load-module <module>` | Load a driver now and at boot (protected; only drivers that match a device present) | `/etc/modules-load.d/proton-security.conf` |
| `driver-update <module>` | `apt-get install --only-upgrade` the driver's package (the kernel meta-package for built-in drivers) and installed firmware packages | packages |
| `driver-reinstall <module>` | Unload and load the driver again (refused for core drivers) | — |
| `driver-purge <module>` | Driver in its own package: purge that package (after a dry run). Driver inside the kernel: block it | packages or `/etc/modprobe.d/proton-security-disabled.conf`, initramfs |
| `driver-enable <module>` | Remove the block and load the driver (protected; only drivers we disabled or that match a device present) | `/etc/modprobe.d/proton-security-disabled.conf` |

### Account and disk encryption

| Command | Does |
|---|---|
| `disable-autologin` | Comment out the auto-login user in SDDM / LightDM configuration |
| `luks-add-recovery <partition>` | Reads the current disk password from stdin, adds a random 48-digit recovery key (`luksAddKey`), prints it once on a `RECOVERY-KEY:` line |
| `luks-change-password <partition>` | Reads the current and new password (8+ characters) from stdin, `luksChangeKey` |
| `luks-header-backup <partition>` | `luksHeaderBackup` into the private temp folder, then copied as the user to `/run/user/<uid>/`; prints `HEADER-FILE: <path>` |

### Maintenance

| Command | Does |
|---|---|
| `install-kup` | Install the Kup backup tool |
| `cleanup` | `apt-get clean`, `autoremove --purge`, shrink the journal to 200 MB, remove unused Flatpak runtimes |

## Scanning untrusted files

Scans run as the user, but the files they look at (downloads, USB drives, `/tmp`) may come from an attacker, and
so may their **names**. Linux allows almost any byte in a file name, including a line break, and ClamAV prints
names as they are. Before 0.4.7 a file named `holiday⏎important.odt` made ClamAV print a line that blamed
`important.odt`, and Quarantine or Delete then acted on that file in the home folder (audit finding 1); the same
names were split in two and never scanned by the background checks (finding 2). Now:

1. ClamAV never searches folders itself. The app walks them and gives ClamAV an exact list of files
   (`--file-list`, in a private file under `~/.cache/proton-security`, mode 600) that contains only plain names:
   valid UTF-8 and no control characters. Their result lines can't be ambiguous.
2. Files with unusual names are scanned one at a time through ClamAV's **standard input**, so their name never
   appears in the output. The app keeps the exact path (as bytes) itself. At most 50 per scan; more are reported as
   "couldn't be checked".
3. A result line is only accepted for an absolute, plain path. Background scans also require it to be one of the
   files they sent; manual scans require it to be an existing regular file.
4. Quarantine and Delete refuse anything that isn't an absolute path to a regular file, and never follow a
   symlink. Unusual names are shown with visible symbols (a line break as `⏎`).
5. A file the user can't move (another account's file in `/tmp`) is reported as such ("ask an administrator"); a
   failed move never leaves a copy of the dangerous file in the quarantine folder.

`antivirus::safe_scan_tests` replays the original proof of concept against the real scan code and ClamAV.

## Secrets

- **Disk passwords** are typed in the window, sent to the helper on standard input, written to files only inside
  the private temp folder, and passed to `cryptsetup` as key files. The temp folder is shredded when the helper
  exits, even on errors. The window clears its password fields when the dialog closes.
- **Recovery keys** come back on a line starting with `RECOVERY-KEY:`. The app shows that line in its own window
  only; the task log shows "(The recovery key is shown in its own window.)" instead, and the output buffer is
  cleared afterwards. Saving the key writes a file with mode 600.
- Random digits for recovery keys come from Bash's `$SRANDOM` (the kernel's random generator).

## Data the app keeps

All user data stays on the computer, in the user's home folder (see
[ARCHITECTURE.md](ARCHITECTURE.md#files-on-disk)). Proton Security sends nothing over the network itself; network
access only happens through the system tools it starts on request (apt, freshclam, flatpak). The device manager's
"search online" opens a hardware database page in the browser only when clicked.

## Test hooks

Debug builds read a few environment variables (`PROTON_SECURITY_FAKE_*`, `…_DEMO_*`, `…_NOTIFY_LOG`,
`…_POLICY`, `…_HELPER`) that fake system state for testing. All of them are behind `cfg(debug_assertions)` and are
not present in release builds; you can check with
`strings /usr/bin/proton-security | grep PROTON_SECURITY_` (only `PROTON_SECURITY_THEME` appears).

## Limits

- ClamAV scans on demand (daily, downloads, USB drives, manual). It is not real-time (on-access) protection.
- The company policy file is trusted: whoever can write `/etc/proton-security/policy.conf` is already root.
- An administrator who authenticates can run any helper command, which is no more than `sudo` already allows.
