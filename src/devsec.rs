// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Device security: Secure Boot, TPM and disk encryption (read as the user).

use crate::sys;
use std::path::Path;

/// Encryption status of one mounted drive (`/` and `/home`).
#[derive(Clone, Debug, Default)]
pub struct DiskEncryption {
    /// Mount point, `/` or `/home`.
    pub mount: String,
    /// The device mounted there, for example `/dev/mapper/luks-…` or `/dev/nvme0n1p2`.
    pub device: String,
    /// True when the device is (or sits on) a dm-crypt/LUKS mapping.
    pub encrypted: bool,
    /// The LUKS partition behind it (for password / recovery key actions).
    pub luks: Option<String>,
}

/// Everything shown on the Device security page.
#[derive(Clone, Debug, Default)]
pub struct DeviceSecurity {
    /// The computer started in UEFI mode (needed for Secure Boot).
    pub uefi: bool,
    /// None = could not tell.
    pub secure_boot: Option<bool>,
    /// "2.0", "1.2" or None when no TPM.
    pub tpm: Option<String>,
    /// Encryption of `/` and `/home` (one entry if they are the same drive).
    pub disks: Vec<DiskEncryption>,
    /// `None` when there is no disk swap (zram doesn't count: it is in memory).
    pub swap_encrypted: Option<bool>,
    /// `cryptsetup` is installed (needed for the recovery key / password actions).
    pub cryptsetup: bool,
    /// KDE Partition Manager is installed (offered for encrypting USB and data drives).
    pub partition_manager: bool,
}

impl DeviceSecurity {
    /// Encryption of the system drive; `None` if it wasn't found.
    pub fn root_encrypted(&self) -> Option<bool> {
        self.disks
            .iter()
            .find(|d| d.mount == "/")
            .map(|d| d.encrypted)
    }
    /// True when every checked drive is encrypted.
    pub fn all_encrypted(&self) -> bool {
        !self.disks.is_empty() && self.disks.iter().all(|d| d.encrypted)
    }
}

/// The UEFI variable that says whether Secure Boot is on (readable by every user).
const SECURE_BOOT_VAR: &str =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// Secure Boot state: from the UEFI variable, or `mokutil --sb-state` as a fallback. `None`
/// when it can't be told (for example legacy BIOS).
fn secure_boot() -> Option<bool> {
    // efivar file: 4 bytes of attributes, then the value byte.
    if let Ok(b) = std::fs::read(SECURE_BOOT_VAR)
        && b.len() >= 5
    {
        return Some(b[4] == 1);
    }
    let out = sys::run_full("mokutil", &["--sb-state"])?;
    let t = format!("{}{}", out.1, out.2).to_lowercase();
    if t.contains("secureboot enabled") {
        Some(true)
    } else if t.contains("secureboot disabled") {
        Some(false)
    } else {
        None
    }
}

/// TPM chip version from sysfs, or `None` when the computer has no (enabled) TPM.
fn tpm() -> Option<String> {
    let base = Path::new("/sys/class/tpm/tpm0");
    if !base.exists() {
        return None;
    }
    Some(
        match sys::read_trim(base.join("tpm_version_major")).as_deref() {
            Some("2") => "2.0".into(),
            Some("1") => "1.2".into(),
            _ => "present".into(),
        },
    )
}

/// Is the block device (or anything under it) a dm-crypt/LUKS mapping?
fn device_encrypted(dev: &str) -> bool {
    // `lsblk -s` lists the device and everything it sits on.
    sys::run_out("lsblk", &["-s", "-n", "-o", "TYPE", dev])
        .map(|o| o.lines().any(|l| l.trim() == "crypt"))
        .unwrap_or(false)
}

/// The LUKS (crypto_LUKS) partition the device sits on.
fn luks_partition(dev: &str) -> Option<String> {
    let out = sys::run_out("lsblk", &["-s", "-l", "-n", "-o", "PATH,FSTYPE", dev])?;
    out.lines().find_map(|l| {
        let mut f = l.split_whitespace();
        let path = f.next()?;
        (f.next() == Some("crypto_LUKS")).then(|| path.to_string())
    })
}

/// The device mounted at `mount` (`findmnt`). Btrfs subvolume suffixes like `[/@home]` are
/// removed.
fn mount_source(mount: &str) -> Option<String> {
    let out = sys::run_out("findmnt", &["-n", "-o", "SOURCE", "--target", mount])?;
    let src = out.lines().next()?.trim();
    // Btrfs shows "/dev/sda2[/@home]".
    Some(src.split('[').next().unwrap_or(src).to_string())
}

/// Read everything for the Device security page.
pub fn load() -> DeviceSecurity {
    let mut disks = vec![];
    let mut seen = vec![];
    // Encryption of the system drive and, if separate, /home: find the device each is mounted
    // from and check whether it sits on an encrypted (LUKS) layer. The same device is only
    // listed once (a /home folder on the system drive).
    for m in ["/", "/home"] {
        if let Some(dev) = mount_source(m) {
            if !dev.starts_with("/dev/") || seen.contains(&dev) {
                continue;
            }
            seen.push(dev.clone());
            let encrypted = device_encrypted(&dev);
            disks.push(DiskEncryption {
                mount: m.into(),
                encrypted,
                luks: if encrypted {
                    luks_partition(&dev)
                } else {
                    None
                },
                device: dev,
            });
        }
    }
    // Debug builds only: pretend the system drive is encrypted.
    #[cfg(debug_assertions)]
    if let Ok(l) = std::env::var("PROTON_SECURITY_FAKE_LUKS") {
        disks = vec![DiskEncryption {
            mount: "/".into(),
            encrypted: true,
            luks: Some(l),
            device: "/dev/mapper/luks-root".into(),
        }];
    }
    // Swap space on a disk can hold copies of memory (passwords, open files), so it should be
    // encrypted too. Swap in compressed RAM (zram) never reaches the disk and is ignored.
    let swaps: Vec<String> = sys::read("/proc/swaps")
        .unwrap_or_default()
        .lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next().map(String::from))
        .filter(|d| d.starts_with("/dev/") && !d.contains("zram"))
        .collect();
    let swap_encrypted = (!swaps.is_empty()).then(|| swaps.iter().all(|d| device_encrypted(d)));
    DeviceSecurity {
        uefi: Path::new("/sys/firmware/efi").exists(),
        secure_boot: secure_boot(),
        tpm: tpm(),
        disks,
        swap_encrypted,
        cryptsetup: sys::which("cryptsetup").is_some(),
        partition_manager: sys::which("partitionmanager").is_some(),
    }
}
