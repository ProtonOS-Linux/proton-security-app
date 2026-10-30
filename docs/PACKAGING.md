# Packaging

Proton Security is shipped as a Debian package built with [cargo-deb](https://github.com/kornelski/cargo-deb).
The package description, dependencies and file list are in the `[package.metadata.deb]` section of
[`Cargo.toml`](../Cargo.toml).

## Build the package

```bash
cargo install cargo-deb
cargo deb            # builds the release binary, then target/debian/proton-security_<version>-1_amd64.deb
```

Check it:

```bash
dpkg-deb --info     target/debian/proton-security_*_amd64.deb
dpkg-deb --contents target/debian/proton-security_*_amd64.deb
appstreamcli validate --no-net packaging/org.protonos.ProtonSecurity.metainfo.xml
```

## What gets installed

| Path | From | Purpose |
|---|---|---|
| `/usr/bin/proton-security` | `target/release/proton-security` | The app, the tray and the one-shot modes |
| `/usr/libexec/proton-security/proton-security-helper` | `packaging/proton-security-helper` | The privileged helper (root via pkexec), everyday fixes |
| `/usr/libexec/proton-security/proton-security-helper-protected` | `packaging/proton-security-helper` (same script) | The same helper for commands that lower protection; its polkit action always asks for the password |
| `/usr/share/polkit-1/actions/org.protonos.security.policy` | `packaging/` | The two polkit actions for the helper |
| `/usr/share/applications/proton-security.desktop` | `packaging/` | Menu entry, with jump actions to each page |
| `/etc/xdg/autostart/proton-security-tray.desktop` | `packaging/` | Starts the tray at login (a conffile: admins may edit or disable it) |
| `/usr/share/metainfo/org.protonos.ProtonSecurity.metainfo.xml` | `packaging/` | AppStream data, so KDE Discover lists the app |
| `/usr/share/icons/hicolor/{scalable,256x256}/apps/proton-security.{svg,png}` | `assets/` | App icon |
| `/usr/share/doc/proton-security/` | `README.md`, `packaging/policy.conf.example` | Documentation and the policy example |

### Dependencies

- **Depends:** pkexec (polkit), kmod, util-linux, procps, apt, and the OpenGL / Wayland / X11 client libraries
  the window needs.
- **Recommends** (installed by default, but the app works without them and offers to install what's missing):
  `clamav clamav-freshclam snapper unattended-upgrades ufw kdialog libnotify-bin udisks2 mokutil kup-backup
  xdg-user-dirs pci.ids usb.ids btrfs-assistant isenkram-cli`.

## Maintainer scripts

[`debian/`](../debian) holds the scripts `dpkg` runs:

| Script | When | What |
|---|---|---|
| `preinst` | before unpacking an upgrade | Stops the background service that version 0.2.0 had (later versions have none) |
| `postinst` | after installing | Removes 0.2.0 leftovers, refreshes the AppStream cache, then starts the tray in every active desktop session; on a **first install** it also opens the window, on an **upgrade** it restarts the tray so the new version runs |
| `prerm` | before removing | Closes the app and the tray |
| `postrm` | after removing | Refreshes the AppStream cache; `purge` also deletes `/var/lib/proton-security` (0.2.0 leftovers) |

`postinst` starts the tray as each signed-in user (`runuser` with that session's display variables), never as
root. It does nothing when there are no desktop sessions, for example inside a chroot.

| Variable | Effect |
|---|---|
| `PROTON_SECURITY_NO_LAUNCH=1` | Don't start the tray or the window after installing |
| `PROTON_SECURITY_DEBUG=1` | Trace `postinst` (`set -x`) |

## Adding it to a Proton OS ISO

The Proton OS ISO is made with [penguins-eggs](https://penguins-eggs.net) from a prepared system:

1. Install the package and its recommended tools on the source system:
   ```bash
   sudo PROTON_SECURITY_NO_LAUNCH=1 apt install ./proton-security_*_amd64.deb
   ```
2. Optional, for a smoother first run:
   - Format `/` as **Btrfs** in the installer, so restore points work, and run *Turn on* for System restore once
     (or `sudo /usr/libexec/proton-security/proton-security-helper enable-snapper`).
   - Add the default user to the `adm` group, so the firewall log shows without a password.
   - Run `sudo /usr/libexec/proton-security/proton-security-helper-protected snapper-allow-sudo`, so administrators see
     restore points without a password.
3. Build the ISO (`sudo eggs produce …`).

User data lives in each user's home folder, so nothing personal ends up in the ISO.

## Releasing a new version

1. Update the version in `Cargo.toml`.
2. Add a `<release>` entry at the top of `packaging/org.protonos.ProtonSecurity.metainfo.xml`.
3. Describe the changes in `CHANGELOG.md`.
4. Run the checks from [DEVELOPMENT.md](DEVELOPMENT.md#before-you-send-a-change) and `cargo deb`; test an
   upgrade from the previous `.deb`.
5. Commit and push to `main`, then publish the release, either way:
   - **On GitHub's website:** *Releases → Draft a new release*, type the tag (`v0.4.8`) and choose
     *Create new tag on publish*, target `main`, then *Publish release*;
   - **or from a terminal:** `git tag v0.4.8 && git push origin v0.4.8`.

The [release workflow](../.github/workflows/release.yml) then builds the `.deb` from that tag (it checks the tag
matches the version in `Cargo.toml`) and attaches it to the release with its SHA-256 checksum and the notes from
`CHANGELOG.md`.
