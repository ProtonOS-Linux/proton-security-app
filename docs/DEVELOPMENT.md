# Development guide

## Set up

You need Rust **1.95 or newer** (the code uses the 2024 edition and recent egui), a C toolchain, and the
usual desktop libraries, which a KDE Plasma system already has.

```bash
sudo apt install build-essential curl pkg-config git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup component add rustfmt clippy

git clone https://github.com/ProtonOS-Linux/proton-security-app.git
cd proton-security-app
cargo run                        # debug build, opens the window
cargo run -- --tray              # run the tray part in the foreground
cargo run -- --diagnose          # print what every check sees
```

For realistic results install the tools the app talks to (they are the package's `Recommends`):

```bash
sudo apt install clamav clamav-freshclam snapper unattended-upgrades ufw kdialog libnotify-bin udisks2 \
                 mokutil kup-backup xdg-user-dirs pci.ids usb.ids
```

A debug build finds the privileged helper next to the sources (`packaging/proton-security-helper`, and the
`proton-security-helper-protected` symlink to it for protected commands) when the
package isn't installed, so administrator buttons work from `cargo run` too (polkit then asks with the generic
"run a program as administrator" prompt).

## Before you send a change

```bash
cargo fmt                                    # formatting
cargo clippy --all-targets -- -D warnings    # lints, no warnings allowed
cargo test                                   # unit tests
cargo doc --no-deps --document-private-items # docs must build without warnings
bash -n packaging/proton-security-helper     # helper syntax
shellcheck packaging/proton-security-helper debian/*   # if you have shellcheck
```

The same commands run in CI on every push and pull request
([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)).

## Unit tests

`cargo test` runs tests for the parts that turn system output into data. They need no root, no desktop and no
installed tools:

| Module | Tests |
|---|---|
| `restore.rs` | Snapper JSON, systemd calendar expressions in words, cron days, which scripts create snapshots |
| `firewall.rs` | `/proc/net` hex addresses (IPv4/IPv6), UFW kernel log lines |
| `health.rs` | Kernel version comparison, `udisksctl dump` parsing, NVMe media errors |
| `account.rs` | KDE ini read/write round trip, PowerDevil inhibitions (busctl and gdbus formats) |
| `antivirus.rs` | History keeps 30 days and scans with open threats; scan result parsing only accepts absolute plain paths; unusual file names; Quarantine/Delete refuse incomplete paths; **end-to-end replay of the crafted-file-name attack** against ClamAV (skipped when ClamAV isn't installed) |
| `admin.rs` | The protected command list matches the helper script; commands go to the right entry point |
| `watchers.rs` | `/proc/mounts` parsing (escaped spaces), USB quick-scan file selection |
| `appperms.rs` | Flatpak permissions plus user overrides |
| `policy.rs` | Policy file parsing |
| `tray.rs` | Tray icons render |
| `checks.rs` | The change fingerprint is stable and cheap |

New parsing code should come with a test that feeds it real sample output.

## Test switches (debug builds only)

Many screens depend on hardware or system states you may not have (an encrypted disk, a USB stick, a blocked
screen lock…). Debug builds read these environment variables to fake them. They are compiled out of release
builds (`#[cfg(debug_assertions)]`).

| Variable | Value | Fakes |
|---|---|---|
| `PROTON_SECURITY_THEME` | `light` / `dark` | Forces a theme (also works in release builds) |
| `PROTON_SECURITY_POLICY` | path | Reads the company policy from this file instead of `/etc/proton-security/policy.conf` |
| `PROTON_SECURITY_HELPER` | path | Runs this helper script with pkexec instead of the installed one (protected commands use the path plus `-protected`; make that a symlink to the script) |
| `PROTON_SECURITY_FAKE_ROOTFS` | `btrfs` | Pretends `/` is Btrfs (System restore) |
| `PROTON_SECURITY_FAKE_LUKS` | e.g. `/dev/nvme0n1p3` | Pretends the system drive is encrypted on that partition (shows the encryption buttons) |
| `PROTON_SECURITY_DEMO_RECOVERY_KEY` | any text | Opens the recovery key window with this key at start |
| `PROTON_SECURITY_FAKE_INHIBIT` | `app\|reason;app\|reason` or a path to a file with that text | PowerDevil inhibitions. `plasmashell\|The battery applet has enabled suppressing sleep and screen locking` = the battery menu switch. A file can be changed while the app runs |
| `PROTON_SECURITY_FAKE_UPTIME_DAYS` | number | Uptime (restart reminder after 15 days) |
| `PROTON_SECURITY_DEMO_DEVICE` | `1` | Adds a device without a driver and a Wi-Fi card to the device manager |
| `PROTON_SECURITY_FAKE_UFW_LOG` | path | Reads firewall log lines (kernel log format) from a file |
| `PROTON_SECURITY_FAKE_USB` | folder | Reads USB devices from this folder instead of `/sys/bus/usb/devices` |
| `PROTON_SECURITY_FAKE_MOUNTS` | path | Reads mounts (`/proc/mounts` format) from this file, to simulate opening a USB drive |
| `PROTON_SECURITY_NOTIFY_LOG` | path | Appends notifications to this file (`title \| text`) instead of showing them |

### Examples

See the disk encryption tools and the recovery key window:

```bash
PROTON_SECURITY_FAKE_LUKS=/dev/nvme0n1p3 cargo run -- --device-security
PROTON_SECURITY_DEMO_RECOVERY_KEY=123456-234567-345678-456789-567890-678901-789012-890123 cargo run
```

Watch the tray react to the battery menu switch (it re-checks within about 5 seconds):

```bash
echo "" > /tmp/inhibit
PROTON_SECURITY_FAKE_INHIBIT=/tmp/inhibit cargo run -- --tray &
echo "plasmashell|The battery applet has enabled suppressing sleep and screen locking" > /tmp/inhibit
```

Simulate opening a USB drive with a test virus (the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/)
is harmless; every antivirus detects it):

```bash
grep -E ' / ' /proc/mounts > /tmp/mounts
PROTON_SECURITY_FAKE_MOUNTS=/tmp/mounts PROTON_SECURITY_NOTIFY_LOG=/tmp/notify.log cargo run -- --tray &
sudo mkdir -p "/media/$USER/TESTUSB" && sudo chown "$USER" "/media/$USER/TESTUSB"
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "/media/$USER/TESTUSB/eicar.com"
echo "/dev/sdz1 /media/$USER/TESTUSB vfat rw 0 0" >> /tmp/mounts
sleep 20; cat /tmp/notify.log
```

## Testing the helper

The helper only runs as root, so test it in a virtual machine or with care. Every command can be run directly:

```bash
sudo packaging/proton-security-helper fw-rules
```

Protected commands (see [SECURITY-MODEL.md](SECURITY-MODEL.md#polkit)) only run under the second name, which in the
source tree is a symlink to the same script:

```bash
sudo packaging/proton-security-helper-protected fw-allow-port 8080 tcp
sudo packaging/proton-security-helper fw-allow-port 8080 tcp     # refused: wrong entry point
```

Disk encryption commands can be tried on a disk image instead of a real drive:

```bash
truncate -s 64M /tmp/disk.img
printf 'oldpass123' | sudo cryptsetup luksFormat -q --type luks2 /tmp/disk.img -
LOOP=$(sudo losetup -f --show /tmp/disk.img)
printf 'oldpass123\n' | sudo packaging/proton-security-helper-protected luks-add-recovery "$LOOP"
printf 'oldpass123\nnewpass456\n' | sudo packaging/proton-security-helper-protected luks-change-password "$LOOP"
sudo PKEXEC_UID=$(id -u) packaging/proton-security-helper-protected luks-header-backup "$LOOP"
sudo losetup -d "$LOOP"
```

## Taking screenshots

The screenshots in `docs/screenshots/` are 1366×768 (a common laptop size, minus a 44-pixel taskbar). To make
new ones without touching your desktop, run the app on a virtual screen:

```bash
sudo apt install xvfb openbox imagemagick
Xvfb :98 -screen 0 1366x768x24 & DISPLAY=:98 openbox &
DISPLAY=:98 PROTON_SECURITY_THEME=light target/release/proton-security --health &
sleep 5; DISPLAY=:98 import -window root health.png
```

## Code style

- **Write for the user.** Every text in the UI is plain English for someone who has never used Linux: say what
  happened and what to do, avoid jargon ("module", "daemon"), no exclamation marks in errors.
- **Document as you go.** Every file starts with a `//!` comment; every function, type and non-obvious field gets
  a `///` comment saying what it is *for* (and why, when it isn't obvious). Comments inside functions explain
  decisions, not the obvious.
- **Read as the user.** Checks must work without root. If something can only be read as root, ask for the
  password only when the user clicks a button for it.
- **Never block the UI thread.** Anything that runs a command or walks folders goes through `Bg::refresh` or its
  own thread.
- **Keep the helper small.** New privileged actions go into `packaging/proton-security-helper` as a new command,
  with validated arguments, and are listed in [SECURITY-MODEL.md](SECURITY-MODEL.md). See
  [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-privileged-action).
- **Fit 1366×768.** Check new screens at that size, in light and dark themes.
