# Company policy

Organizations can set Proton Security up the same way on every computer with one file:
**`/etc/proton-security/policy.conf`**. Only root can write it; the app and the tray read it as the user.
Without the file, users decide everything.

An annotated example is installed at `/usr/share/doc/proton-security/policy.conf.example` (source:
[`packaging/policy.conf.example`](../packaging/policy.conf.example)).

```bash
sudo mkdir -p /etc/proton-security
sudo cp /usr/share/doc/proton-security/policy.conf.example /etc/proton-security/policy.conf
sudo nano /etc/proton-security/policy.conf      # remove the # in front of the lines you want
```

Changes apply the next time Proton Security and its tray icon start: sign out and back in.

## Format

One `key = value` per line. `#` starts a comment, also after a value. Keys and the values `yes/no`,
`true/false`, `on/off`, `1/0` are not case-sensitive. Unknown keys and invalid values are ignored, so a typo
never breaks the app: that setting simply keeps its default.

When a policy file exists, the app shows "Managed by *organization*" next to the settings it locks, and the
report mentions it.

## Keys

### Organization

| Key | Value | Default |
|---|---|---|
| `organization` | Name shown as "Managed by …" | "your organization" |

### Force background protection on or off

`force-on` / `force-off` lock the setting (the checkbox and the tray menu item are greyed out). Leave the key
out to let users choose.

| Key | Controls | Users' default |
|---|---|---|
| `daily_scan` | Daily automatic quick scan | on |
| `scan_downloads` | Checking new files in Downloads | on |
| `scan_usb` | Scanning USB drives when they are opened | on |
| `usb_alerts` | Notifications for new USB keyboards, network adapters and drives | on |

### Lock features

| Key | `no` hides or disables | Default |
|---|---|---|
| `allow_driver_changes` | The Update / Reinstall / Uninstall driver buttons in the device manager | `yes` |
| `allow_firewall_changes` | *Add a rule…* and the Allow / Block buttons on the Firewall page | `yes` |
| `allow_app_permission_changes` | Changing Flatpak permissions (the page becomes read-only) | `yes` |

These only change what the app offers. They are not a security boundary: an administrator can still use the
terminal.

### Requirements

| Key | Effect | Default |
|---|---|---|
| `require_disk_encryption` | `yes`: Device security turns yellow when `/` or `/home` is not encrypted | `no` |
| `require_secure_boot` | `yes`: Device security turns yellow when Secure Boot is off | `no` |
| `require_backup` | `no`: File backup stays green without a backup | `yes` |
| `max_screen_lock_minutes` | Longest screen-lock delay before Account protection warns; also used by *Turn on screen lock* | `15` |

### Hide pages

```ini
hide_pages = devices, firewall
```

Comma- or space-separated. Page keys: `antivirus`, `firewall`, `account`, `device-security`, `health`, `apps`,
`restore`, `devices`. Hiding a page also removes its tile from Security at a glance (`restore` hides both
System restore and File backup).

## Example

```ini
organization = Acme Corp
daily_scan = force-on
scan_downloads = force-on
scan_usb = force-on
allow_driver_changes = no
require_disk_encryption = yes
max_screen_lock_minutes = 10
hide_pages = devices
```

## Testing a policy

Debug builds can read a policy from another path, so you can try one without root:

```bash
PROTON_SECURITY_POLICY=./my-policy.conf cargo run
```
