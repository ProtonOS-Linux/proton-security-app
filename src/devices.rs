// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Hardware enumeration from sysfs, similar to Windows Device Manager.
//! Works without root and without lspci/lsusb (their ID databases are used
//! for names when present).

use crate::sys;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Device groups, named and ordered like Windows Device Manager.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Category {
    Other, // shown first, like Windows' "Other devices"
    Audio,
    Batteries,
    Bluetooth,
    Cameras,
    Disks,
    Optical,
    Display,
    Hid,
    Imaging,
    Keyboards,
    Mice,
    Monitors,
    Network,
    Ports,
    Printers,
    Processors,
    Storage,
    System,
    UsbControllers,
    UsbDevices,
}

impl Category {
    /// Group heading.
    pub fn name(self) -> &'static str {
        match self {
            Category::Other => "Other devices",
            Category::Audio => "Sound, video and game controllers",
            Category::Batteries => "Batteries",
            Category::Bluetooth => "Bluetooth",
            Category::Cameras => "Cameras",
            Category::Disks => "Disk drives",
            Category::Optical => "DVD/CD-ROM drives",
            Category::Display => "Display adapters",
            Category::Hid => "Human Interface Devices",
            Category::Imaging => "Imaging devices",
            Category::Keyboards => "Keyboards",
            Category::Mice => "Mice and other pointing devices",
            Category::Monitors => "Monitors",
            Category::Network => "Network adapters",
            Category::Ports => "Ports (COM & serial)",
            Category::Printers => "Print queues & printers",
            Category::Processors => "Processors",
            Category::Storage => "Storage controllers",
            Category::System => "System devices",
            Category::UsbControllers => "Universal Serial Bus controllers",
            Category::UsbDevices => "Universal Serial Bus devices",
        }
    }
}

/// Driver status of a device.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Status {
    /// A driver is bound to the device.
    Ok,
    /// No driver bound, but this kind of device normally doesn't need one.
    NotRequired,
    /// A kernel module exists for it but isn't loaded.
    DriverNotLoaded,
    /// No driver is available.
    NoDriver,
}

impl Status {
    /// True when the device needs a driver it doesn't have (shown with a warning).
    pub fn is_problem(self) -> bool {
        matches!(self, Status::DriverNotLoaded | Status::NoDriver)
    }
    /// Status sentence for the properties panel, worded like Windows.
    pub fn text(self) -> &'static str {
        match self {
            Status::Ok => "This device is working properly.",
            Status::NotRequired => "This device does not need a driver.",
            Status::DriverNotLoaded => {
                "A driver is available for this device but it is not loaded."
            }
            Status::NoDriver => "The drivers for this device are not installed.",
        }
    }
}

/// One device in the device manager.
#[derive(Clone, Debug)]
pub struct Device {
    /// Stable key (sysfs path or similar) used to keep the selection.
    pub key: String,
    /// Group it is listed under.
    pub category: Category,
    /// Device name (from the device, or the pci.ids / usb.ids databases).
    pub name: String,
    /// Manufacturer.
    pub vendor: String,
    /// "PCI", "USB", "Input"…
    pub bus: &'static str,
    /// vendor:product IDs ("8086:a0f0").
    pub ids: String,
    /// Kernel driver bound to it now.
    pub driver: Option<String>,
    /// The device's modalias: the string kernel modules match to find a driver.
    pub modalias: Option<String>,
    /// Modules that could drive it (`modprobe -R`), when none is bound.
    pub candidate_modules: Vec<String>,
    /// Kernel modules behind `driver` (empty when built into the kernel).
    pub modules: Vec<String>,
    /// Driver status.
    pub status: Status,
    /// Lines for the properties panel.
    pub props: Vec<(String, String)>,
    /// Query string for linux-hardware.org, e.g. "usb:0bda-8179".
    pub hw_query: Option<String>,
}

/// Result of one hardware scan.
#[derive(Clone, Debug, Default)]
pub struct DeviceSnapshot {
    /// All devices, sorted by group and name.
    pub devices: Vec<Device>,
    /// Kernel messages about missing firmware files.
    pub firmware_messages: Vec<String>,
}

impl DeviceSnapshot {
    /// Number of devices without a working driver.
    pub fn problems(&self) -> usize {
        self.devices
            .iter()
            .filter(|d| d.status.is_problem())
            .count()
    }
}

// ------------------------------------------------------------------ ID databases

/// A PCI or USB ID database (pci.ids / usb.ids from the pciutils / usbutils packages).
#[derive(Default)]
struct IdDb {
    /// Vendor ID -> vendor name.
    vendors: HashMap<u16, String>,
    /// (vendor ID, device ID) -> device name.
    devices: HashMap<(u16, u16), String>,
}

/// Parse the first ID database found among `paths`. Format: vendor lines start at column 0,
/// device lines with one tab.
fn parse_ids(paths: &[&str]) -> IdDb {
    let mut db = IdDb::default();
    let Some(text) = paths.iter().find_map(|p| {
        std::fs::read(p)
            .ok()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    }) else {
        return db;
    };
    let mut cur: Option<u16> = None;
    for line in text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        // Class sections ("C 03 ...") end the vendor list.
        if line.starts_with("C ") {
            break;
        }
        if let Some(rest) = line.strip_prefix('\t') {
            if rest.starts_with('\t') {
                continue; // subsystem lines
            }
            if let (Some(v), Some((id, name))) = (cur, rest.split_once("  "))
                && let Ok(d) = u16::from_str_radix(id.trim(), 16)
            {
                db.devices.insert((v, d), name.trim().to_string());
            }
        } else if let Some((id, name)) = line.split_once("  ") {
            cur = u16::from_str_radix(id.trim(), 16).ok();
            if let Some(v) = cur {
                db.vendors.insert(v, name.trim().to_string());
            }
        }
    }
    db
}

/// The PCI ID database, loaded once.
fn pci_db() -> &'static IdDb {
    /// Loaded on first use.
    static DB: OnceLock<IdDb> = OnceLock::new();
    DB.get_or_init(|| {
        parse_ids(&[
            "/usr/share/misc/pci.ids",
            "/usr/share/hwdata/pci.ids",
            "/usr/share/pci.ids",
        ])
    })
}

/// The USB ID database, loaded once.
fn usb_db() -> &'static IdDb {
    /// Loaded on first use.
    static DB: OnceLock<IdDb> = OnceLock::new();
    DB.get_or_init(|| {
        parse_ids(&[
            "/var/lib/usbutils/usb.ids",
            "/usr/share/misc/usb.ids",
            "/usr/share/hwdata/usb.ids",
            "/usr/share/usb.ids",
        ])
    })
}

// ------------------------------------------------------------------ helpers

/// Read a sysfs value.
fn rd(p: impl AsRef<Path>) -> Option<String> {
    sys::read_trim(p)
}

/// Read a hexadecimal sysfs value (`0x8086` or `8086`).
fn hex(p: impl AsRef<Path>) -> Option<u32> {
    rd(p).and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok())
}

/// Name of what a sysfs symlink points to (the `driver` link gives the driver name).
fn link_name(p: impl AsRef<Path>) -> Option<String> {
    std::fs::read_link(p)
        .ok()
        .and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()))
}

/// Kernel modules that claim a modalias (`modprobe -R`), without loading anything.
fn modules_for(modalias: &str) -> Vec<String> {
    sys::run_full("modprobe", &["-R", modalias])
        .filter(|(ok, _, _)| *ok)
        .map(|(_, o, _)| {
            o.lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Version of a loaded kernel module, from /sys/module.
fn module_version(module: &str) -> Option<String> {
    rd(format!("/sys/module/{module}/version"))
        .or_else(|| rd(format!("/sys/module/{module}/srcversion")).map(|s| format!("src {s}")))
}

/// Status of a device: Ok with a driver; otherwise DriverNotLoaded when a module matches its
/// modalias, NotRequired for device kinds that work without one, else NoDriver. Also returns
/// the matching modules.
fn status_for(
    driver: &Option<String>,
    modalias: &Option<String>,
    optional: bool,
) -> (Status, Vec<String>) {
    if driver.is_some() {
        return (Status::Ok, vec![]);
    }
    let mods = modalias.as_deref().map(modules_for).unwrap_or_default();
    if !mods.is_empty() {
        (Status::DriverNotLoaded, mods)
    } else if optional {
        (Status::NotRequired, mods)
    } else {
        (Status::NoDriver, mods)
    }
}

/// Running kernel version.
fn kernel_release() -> String {
    rd("/proc/sys/kernel/osrelease").unwrap_or_default()
}

/// Map `/sys/class/net/<if>/device` to the device's real sysfs path.
fn net_interfaces() -> HashMap<PathBuf, Vec<String>> {
    let mut m: HashMap<PathBuf, Vec<String>> = HashMap::new();
    if let Ok(d) = std::fs::read_dir("/sys/class/net") {
        for e in d.flatten() {
            if let Ok(real) = std::fs::canonicalize(e.path().join("device")) {
                m.entry(real)
                    .or_default()
                    .push(e.file_name().to_string_lossy().into_owned());
            }
        }
    }
    m
}

// ------------------------------------------------------------------ PCI

/// Name of a PCI device class, used when the ID database doesn't know the device.
fn pci_class_name(class: u32) -> &'static str {
    let (base, sub) = ((class >> 16) & 0xff, (class >> 8) & 0xff);
    match (base, sub) {
        (0x01, 0x06) => "SATA controller",
        (0x01, 0x08) => "NVMe controller",
        (0x01, _) => "Storage controller",
        (0x02, _) => "Network controller",
        (0x03, _) => "Display controller",
        (0x04, 0x03) => "Audio device",
        (0x04, _) => "Multimedia controller",
        (0x05, _) => "Memory controller",
        (0x06, 0x00) => "Host bridge",
        (0x06, 0x01) => "ISA bridge",
        (0x06, 0x04) => "PCI bridge",
        (0x06, _) => "Bridge",
        (0x07, _) => "Communication controller",
        (0x08, _) => "System peripheral",
        (0x0c, 0x03) => "USB controller",
        (0x0c, 0x05) => "SMBus controller",
        (0x0c, _) => "Serial bus controller",
        (0x0d, _) => "Wireless controller",
        (0x10, _) => "Encryption controller",
        (0x11, _) => "Signal processing controller",
        (0x12, _) => "Processing accelerator",
        _ => "PCI device",
    }
}

/// Device manager group for a PCI class code.
fn pci_category(class: u32) -> Category {
    let (base, sub) = ((class >> 16) & 0xff, (class >> 8) & 0xff);
    match (base, sub) {
        (0x01, _) => Category::Storage,
        (0x02, _) => Category::Network,
        (0x03, _) => Category::Display,
        (0x04, _) => Category::Audio,
        (0x07, _) => Category::Ports,
        (0x0c, 0x03) => Category::UsbControllers,
        (0x0d, 0x11) => Category::Bluetooth,
        (0x0d, _) => Category::Network,
        _ => Category::System,
    }
}

/// Device classes users care about; everything else (bridges, memory
/// controllers, system peripherals...) is fine without a driver.
fn pci_needs_driver(class: u32) -> bool {
    matches!((class >> 16) & 0xff, 0x01 | 0x02 | 0x03 | 0x04 | 0x0d) || (class >> 8) == 0x0c03
}

/// PCI devices (graphics, network, sound, storage controllers…) from /sys/bus/pci/devices.
fn scan_pci(out: &mut Vec<Device>, nets: &HashMap<PathBuf, Vec<String>>) {
    let Ok(dir) = std::fs::read_dir("/sys/bus/pci/devices") else {
        return;
    };
    for e in dir.flatten() {
        let p = e.path();
        let slot = e.file_name().to_string_lossy().into_owned();
        let (Some(class), Some(ven), Some(dev)) = (
            hex(p.join("class")),
            hex(p.join("vendor")),
            hex(p.join("device")),
        ) else {
            continue;
        };
        let (ven, dev) = (ven as u16, dev as u16);
        let db = pci_db();
        let vendor = db
            .vendors
            .get(&ven)
            .cloned()
            .unwrap_or_else(|| format!("Vendor {ven:04x}"));
        let name = db
            .devices
            .get(&(ven, dev))
            .cloned()
            .unwrap_or_else(|| format!("{} ({ven:04x}:{dev:04x})", pci_class_name(class)));
        let driver = link_name(p.join("driver"));
        let modalias = rd(p.join("modalias"));
        let (status, mods) = status_for(&driver, &modalias, !pci_needs_driver(class));

        let mut props = vec![
            ("Device type".into(), pci_class_name(class).into()),
            ("Location".into(), format!("PCI slot {slot}")),
        ];
        if let Ok(real) = std::fs::canonicalize(&p)
            && let Some(ifs) = nets.get(&real)
        {
            props.push(("Network interface".into(), ifs.join(", ")));
        }
        if let Some(r) = rd(p.join("revision")) {
            props.push(("Revision".into(), r));
        }
        if let (Some(sv), Some(sd)) = (
            hex(p.join("subsystem_vendor")),
            hex(p.join("subsystem_device")),
        ) {
            props.push(("Subsystem".into(), format!("{sv:04x}:{sd:04x}")));
        }

        let category = if status.is_problem() {
            Category::Other
        } else {
            pci_category(class)
        };
        out.push(Device {
            key: format!("pci:{slot}"),
            category,
            name,
            vendor,
            bus: "PCI",
            ids: format!("{ven:04x}:{dev:04x}"),
            driver,
            modalias,
            candidate_modules: mods,
            modules: vec![],
            status,
            props,
            hw_query: Some(format!("pci:{ven:04x}-{dev:04x}")),
        });
    }
}

// ------------------------------------------------------------------ USB

/// Device manager group for a USB interface class.
fn usb_iface_category(class: u32, sub: u32, driver: Option<&str>) -> Category {
    match class {
        0x01 => Category::Audio,
        0x02 if sub == 0x02 => Category::Ports,
        0x02 | 0x0a => Category::Network,
        0x03 => Category::Hid,
        0x06 => Category::Imaging,
        0x07 => Category::Printers,
        0x08 => Category::UsbControllers,
        0x09 => Category::UsbControllers,
        0x0e => Category::Cameras,
        0xe0 => Category::Bluetooth,
        _ => {
            let d = driver.unwrap_or("");
            if [
                "rtl8",
                "rtw",
                "mt76",
                "mt7",
                "ath9k",
                "ath10k",
                "ath11k",
                "carl9170",
                "r8152",
                "ax88179",
                "cdc_ether",
                "rndis",
                "brcmfmac",
                "iwlwifi",
            ]
            .iter()
            .any(|p| d.starts_with(p))
            {
                Category::Network
            } else if d == "btusb" {
                Category::Bluetooth
            } else if d.starts_with("uvc") {
                Category::Cameras
            } else if d.contains("serial")
                || d.starts_with("ftdi")
                || d.starts_with("ch34")
                || d.starts_with("cp210")
                || d.starts_with("pl2303")
            {
                Category::Ports
            } else {
                Category::UsbDevices
            }
        }
    }
}

/// USB devices from /sys/bus/usb/devices, grouped by their interfaces. Root hubs are listed as
/// USB controllers.
fn scan_usb(out: &mut Vec<Device>, nets: &HashMap<PathBuf, Vec<String>>) {
    let Ok(dir) = std::fs::read_dir("/sys/bus/usb/devices") else {
        return;
    };
    let mut entries: Vec<_> = dir.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in &entries {
        let name_s = e.file_name().to_string_lossy().into_owned();
        if name_s.contains(':') {
            continue; // interface, handled with its device
        }
        let p = e.path();
        let (Some(ven), Some(prod)) = (hex(p.join("idVendor")), hex(p.join("idProduct"))) else {
            continue;
        };
        let (ven, prod) = (ven as u16, prod as u16);
        let dev_class = hex(p.join("bDeviceClass")).unwrap_or(0);
        let speed = rd(p.join("speed"));

        // Root hubs
        if name_s.starts_with("usb") {
            let ver = rd(p.join("version")).unwrap_or_default();
            out.push(Device {
                key: format!("usb:{name_s}"),
                category: Category::UsbControllers,
                name: format!("USB Root Hub (USB {})", ver.trim()),
                vendor: "Linux Foundation".into(),
                bus: "USB",
                ids: format!("{ven:04x}:{prod:04x}"),
                driver: link_name(p.join("driver")),
                modalias: None,
                candidate_modules: vec![],
                modules: vec![],
                status: Status::Ok,
                props: vec![(
                    "Location".into(),
                    format!("Bus {}", name_s.trim_start_matches("usb")),
                )],
                hw_query: None,
            });
            continue;
        }

        // Interfaces of this device
        let prefix = format!("{name_s}:");
        let mut ifaces = vec![];
        for i in entries
            .iter()
            .filter(|i| i.file_name().to_string_lossy().starts_with(&prefix))
        {
            let ip = i.path();
            ifaces.push((
                hex(ip.join("bInterfaceClass")).unwrap_or(0),
                hex(ip.join("bInterfaceSubClass")).unwrap_or(0),
                link_name(ip.join("driver")),
                rd(ip.join("modalias")),
                std::fs::canonicalize(&ip).ok(),
            ));
        }

        let is_hub = dev_class == 0x09 || ifaces.iter().any(|f| f.0 == 0x09);
        let bound: Vec<String> = ifaces
            .iter()
            .filter_map(|f| f.2.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let driver = (!bound.is_empty()).then(|| bound.join(", "));
        // Category comes from the first meaningful interface.
        let main = ifaces
            .iter()
            .find(|f| f.0 != 0xfe && f.0 != 0x09)
            .or(ifaces.first());
        let category = if is_hub {
            Category::UsbControllers
        } else {
            main.map(|f| usb_iface_category(f.0, f.1, f.2.as_deref()))
                .unwrap_or(Category::UsbDevices)
        };
        let modalias = main.and_then(|f| f.3.clone());
        let (status, mods) = if is_hub {
            (Status::Ok, vec![])
        } else {
            let mut all_mods = vec![];
            if driver.is_none() {
                for f in &ifaces {
                    if let Some(m) = &f.3 {
                        for x in modules_for(m) {
                            if !all_mods.contains(&x) {
                                all_mods.push(x);
                            }
                        }
                    }
                }
            }
            if driver.is_some() {
                (Status::Ok, vec![])
            } else if !all_mods.is_empty() {
                (Status::DriverNotLoaded, all_mods)
            } else {
                (Status::NoDriver, vec![])
            }
        };

        let db = usb_db();
        let vendor = rd(p.join("manufacturer"))
            .or_else(|| db.vendors.get(&ven).cloned())
            .unwrap_or_else(|| format!("Vendor {ven:04x}"));
        let name = rd(p.join("product"))
            .or_else(|| db.devices.get(&(ven, prod)).cloned())
            .unwrap_or_else(|| {
                if is_hub {
                    "Generic USB Hub".into()
                } else {
                    format!("Unknown USB device ({ven:04x}:{prod:04x})")
                }
            });

        let mut props = vec![("Location".into(), format!("USB port {name_s}"))];
        if let Some(s) = speed {
            props.push(("Speed".into(), format!("{s} Mbit/s")));
        }
        let ifs: Vec<String> = ifaces
            .iter()
            .filter_map(|f| f.4.as_ref().and_then(|r| nets.get(r)))
            .flatten()
            .cloned()
            .collect();
        if !ifs.is_empty() {
            props.push(("Network interface".into(), ifs.join(", ")));
        }
        props.push(("Interfaces".into(), ifaces.len().to_string()));

        out.push(Device {
            key: format!("usb:{name_s}"),
            category: if status.is_problem() {
                Category::Other
            } else {
                category
            },
            name,
            vendor,
            bus: "USB",
            ids: format!("{ven:04x}:{prod:04x}"),
            driver,
            modalias,
            candidate_modules: mods,
            modules: vec![],
            status,
            props,
            hw_query: Some(format!("usb:{ven:04x}-{prod:04x}")),
        });
    }
}

// ------------------------------------------------------------------ other classes

/// Build a [`Device`] for classes that are listed for information (processors, disks,
/// monitors…).
fn simple(
    key: String,
    category: Category,
    name: String,
    vendor: String,
    bus: &'static str,
    driver: Option<String>,
    props: Vec<(String, String)>,
) -> Device {
    Device {
        key,
        category,
        name,
        vendor,
        bus,
        ids: String::new(),
        driver,
        modalias: None,
        candidate_modules: vec![],
        modules: vec![],
        status: Status::Ok,
        props,
        hw_query: None,
    }
}

/// Processors from /proc/cpuinfo.
fn scan_cpus(out: &mut Vec<Device>) {
    let info = sys::read("/proc/cpuinfo").unwrap_or_default();
    let cpufreq = rd("/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver");
    let mut idx = 0;
    for block in info.split("\n\n") {
        let get = |k: &str| {
            block.lines().find_map(|l| {
                let (a, b) = l.split_once(':')?;
                (a.trim() == k).then(|| b.trim().to_string())
            })
        };
        let Some(model) = get("model name")
            .or_else(|| get("Model"))
            .or_else(|| get("cpu model"))
        else {
            continue;
        };
        let vendor = get("vendor_id").unwrap_or_default();
        let mut props = vec![("Logical processor".into(), idx.to_string())];
        if let Some(c) = get("cpu cores") {
            props.push(("Cores per package".into(), c));
        }
        if let Some(g) = &cpufreq {
            props.push(("Frequency scaling".into(), g.clone()));
        }
        out.push(simple(
            format!("cpu:{idx}"),
            Category::Processors,
            model,
            vendor,
            "CPU",
            Some("processor".into()),
            props,
        ));
        idx += 1;
    }
}

/// Disk drives and DVD drives from /sys/block (virtual devices such as loop and zram are
/// skipped).
fn scan_block(out: &mut Vec<Device>) {
    let Ok(dir) = std::fs::read_dir("/sys/block") else {
        return;
    };
    for e in dir.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if ["loop", "ram", "zram", "dm-", "md", "nbd"]
            .iter()
            .any(|p| n.starts_with(p))
        {
            continue;
        }
        let p = e.path();
        let model = rd(p.join("device/model")).or_else(|| rd(p.join("device/name")));
        // Some buses (virtio, NVMe) put a numeric ID here instead of a name.
        let vendor = rd(p.join("device/vendor"))
            .filter(|v| !v.starts_with("0x"))
            .unwrap_or_default();
        let sectors: u64 = rd(p.join("size")).and_then(|s| s.parse().ok()).unwrap_or(0);
        if sectors == 0 && !n.starts_with("sr") {
            continue;
        }
        let removable = rd(p.join("removable")).as_deref() == Some("1");
        let rotational = rd(p.join("queue/rotational")).as_deref() == Some("1");
        let category = if n.starts_with("sr") {
            Category::Optical
        } else {
            Category::Disks
        };
        let kind = if n.starts_with("nvme") {
            "NVMe SSD"
        } else if n.starts_with("mmcblk") {
            "SD / eMMC"
        } else if n.starts_with("sr") {
            "Optical drive"
        } else if rotational {
            "Hard disk"
        } else {
            "Solid-state / flash"
        };
        let mut props = vec![
            ("Device".into(), format!("/dev/{n}")),
            ("Type".into(), kind.into()),
            ("Capacity".into(), sys::fmt_bytes(sectors * 512)),
            (
                "Removable".into(),
                if removable { "Yes" } else { "No" }.into(),
            ),
        ];
        if let Some(s) = rd(p.join("device/serial")) {
            props.push(("Serial".into(), s));
        }
        let driver = link_name(p.join("device/driver"))
            .or_else(|| link_name(p.join("device/device/driver")));
        out.push(simple(
            format!("blk:{n}"),
            category,
            model.unwrap_or_else(|| format!("Disk {n}")),
            vendor,
            "Block",
            driver,
            props,
        ));
    }
}

/// Keyboards, mice, touchpads and other input devices from /proc/bus/input/devices.
fn scan_input(out: &mut Vec<Device>) {
    let text = sys::read("/proc/bus/input/devices").unwrap_or_default();
    for block in text.split("\n\n") {
        let mut name = String::new();
        let mut handlers = String::new();
        let mut sysfs = String::new();
        let mut phys = String::new();
        for l in block.lines() {
            if let Some(v) = l.strip_prefix("N: Name=") {
                name = v.trim_matches('"').to_string();
            } else if let Some(v) = l.strip_prefix("H: Handlers=") {
                handlers = v.to_string();
            } else if let Some(v) = l.strip_prefix("S: Sysfs=") {
                sysfs = v.to_string();
            } else if let Some(v) = l.strip_prefix("P: Phys=") {
                phys = v.to_string();
            }
        }
        if name.is_empty() {
            continue;
        }
        let lname = name.to_lowercase();
        let category = if handlers.split_whitespace().any(|h| h.starts_with("mouse")) {
            Category::Mice
        } else if handlers.contains("kbd") && lname.contains("keyboard") {
            Category::Keyboards
        } else if ["touchpad", "touchscreen", "pen", "stylus", "wacom"]
            .iter()
            .any(|k| lname.contains(k))
        {
            Category::Mice
        } else {
            continue;
        };
        let driver = link_name(format!("/sys{sysfs}/device/driver"));
        let mut props = vec![("Handlers".into(), handlers.trim().to_string())];
        if !phys.is_empty() {
            props.push(("Physical path".into(), phys));
        }
        out.push(simple(
            format!("input:{sysfs}"),
            category,
            name,
            String::new(),
            "Input",
            driver,
            props,
        ));
    }
}

/// Monitor name and manufacturer from an EDID blob.
fn parse_edid(edid: &[u8]) -> Option<(String, String)> {
    if edid.len() < 128 || edid[0..8] != [0, 255, 255, 255, 255, 255, 255, 0] {
        return None;
    }
    let m = u16::from_be_bytes([edid[8], edid[9]]);
    let pnp: String = [(m >> 10) & 31, (m >> 5) & 31, m & 31]
        .iter()
        .map(|c| (b'A' + *c as u8 - 1) as char)
        .collect();
    let mut name = None;
    for i in 0..4 {
        let d = &edid[54 + i * 18..54 + (i + 1) * 18];
        if d[0] == 0 && d[1] == 0 && d[3] == 0xFC {
            let s: String = d[5..]
                .iter()
                .take_while(|&&b| b != 0x0a)
                .map(|&b| b as char)
                .collect();
            name = Some(s.trim().to_string());
        }
    }
    Some((name.unwrap_or_else(|| "Generic monitor".into()), pnp))
}

/// Connected monitors from /sys/class/drm (name and maker from the monitor's EDID data).
fn scan_monitors(out: &mut Vec<Device>) {
    let Ok(dir) = std::fs::read_dir("/sys/class/drm") else {
        return;
    };
    for e in dir.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if !n.contains('-') {
            continue;
        }
        let p = e.path();
        if rd(p.join("status")).as_deref() != Some("connected") {
            continue;
        }
        let connector = n
            .split_once('-')
            .map(|x| x.1.to_string())
            .unwrap_or(n.clone());
        let (name, vendor) = std::fs::read(p.join("edid"))
            .ok()
            .and_then(|b| parse_edid(&b))
            .unwrap_or_else(|| ("Generic monitor".into(), String::new()));
        let card = n.split('-').next().unwrap_or("card0");
        let driver = link_name(format!("/sys/class/drm/{card}/device/driver"));
        let mut props = vec![("Connector".into(), connector)];
        if let Some(m) = sys::read(p.join("modes")).and_then(|s| s.lines().next().map(String::from))
        {
            props.push(("Preferred mode".into(), m));
        }
        out.push(simple(
            format!("drm:{n}"),
            Category::Monitors,
            name,
            vendor,
            "Display",
            driver,
            props,
        ));
    }
}

/// Batteries and power adapters from /sys/class/power_supply.
fn scan_power(out: &mut Vec<Device>) {
    let Ok(dir) = std::fs::read_dir("/sys/class/power_supply") else {
        return;
    };
    for e in dir.flatten() {
        let p = e.path();
        let n = e.file_name().to_string_lossy().into_owned();
        let kind = rd(p.join("type")).unwrap_or_default();
        let scope = rd(p.join("scope")).unwrap_or_default();
        if scope == "Device" {
            continue; // e.g. wireless mouse batteries
        }
        let (name, props) = match kind.as_str() {
            "Battery" => {
                let mut props = vec![];
                if let Some(c) = rd(p.join("capacity")) {
                    props.push(("Charge".into(), format!("{c}%")));
                }
                if let Some(s) = rd(p.join("status")) {
                    props.push(("State".into(), s));
                }
                if let (Some(full), Some(design)) = (
                    rd(p.join("energy_full"))
                        .or_else(|| rd(p.join("charge_full")))
                        .and_then(|s| s.parse::<f64>().ok()),
                    rd(p.join("energy_full_design"))
                        .or_else(|| rd(p.join("charge_full_design")))
                        .and_then(|s| s.parse::<f64>().ok()),
                ) && design > 0.0
                {
                    props.push((
                        "Health".into(),
                        format!("{:.0}% of design capacity", full / design * 100.0),
                    ));
                }
                (
                    rd(p.join("model_name"))
                        .map(|m| format!("Battery ({m})"))
                        .unwrap_or_else(|| format!("Battery {n}")),
                    props,
                )
            }
            "Mains" => (
                "AC Adapter".to_string(),
                vec![(
                    "Plugged in".into(),
                    if rd(p.join("online")).as_deref() == Some("1") {
                        "Yes"
                    } else {
                        "No"
                    }
                    .into(),
                )],
            ),
            _ => continue,
        };
        let vendor = rd(p.join("manufacturer")).unwrap_or_default();
        out.push(simple(
            format!("power:{n}"),
            Category::Batteries,
            name,
            vendor,
            "Power",
            None,
            props,
        ));
    }
}

/// Firmware load failures from the kernel log (only visible to users in the
/// adm / systemd-journal groups; silently empty otherwise).
fn firmware_messages() -> Vec<String> {
    let out = sys::run_out(
        "journalctl",
        &[
            "-k",
            "-b",
            "-q",
            "--no-pager",
            "-o",
            "cat",
            "--grep",
            "firmware",
        ],
    )
    .unwrap_or_default();
    let mut v: Vec<String> = out
        .lines()
        .filter(|l| {
            let l = l.to_lowercase();
            l.contains("failed")
                || l.contains("missing")
                || l.contains("error")
                || l.contains("not found")
        })
        .map(|l| l.trim().to_string())
        .collect();
    v.dedup();
    v.truncate(20);
    v
}

/// Cheap summary of the hardware present: the device folders on the PCI and USB buses, block
/// devices, input devices, monitors and power supplies, with each device's bound driver. Takes
/// well under a millisecond (no commands run), so "Watch for new devices" calls it every few
/// seconds and runs the full [`scan`] only when it changes.
pub fn hw_fingerprint() -> String {
    let mut parts: Vec<String> = vec![];
    for dir in [
        "/sys/bus/pci/devices",
        "/sys/bus/usb/devices",
        "/sys/class/block",
        "/sys/class/input",
        "/sys/class/drm",
        "/sys/class/power_supply",
    ] {
        let Ok(rd) = std::fs::read_dir(dir) else {
            continue;
        };
        for e in rd.flatten() {
            let driver = link_name(e.path().join("driver"))
                .or_else(|| link_name(e.path().join("device/driver")))
                .unwrap_or_default();
            let status = sys::read_trim(e.path().join("status")).unwrap_or_default();
            parts.push(format!(
                "{dir}/{}={driver}:{status}",
                e.file_name().to_string_lossy()
            ));
        }
    }
    parts.sort();
    parts.join("\n")
}

/// Scan all hardware. Takes a fraction of a second; runs on a background thread.
pub fn scan() -> DeviceSnapshot {
    let nets = net_interfaces();
    let mut devices = vec![];
    scan_pci(&mut devices, &nets);
    scan_usb(&mut devices, &nets);
    scan_cpus(&mut devices);
    scan_block(&mut devices);
    scan_input(&mut devices);
    scan_monitors(&mut devices);
    scan_power(&mut devices);

    // Resolve driver name -> kernel module, and driver version.
    for d in devices.iter_mut() {
        if let Some(drv) = &d.driver {
            for name in drv.split(", ") {
                if let Some(m) = module_of_driver(name)
                    && !d.modules.contains(&m)
                {
                    d.modules.push(m);
                }
            }
        }
    }
    for d in devices.iter_mut() {
        if let Some(drv) = &d.driver {
            let first = drv.split(", ").next().unwrap_or("").replace('-', "_");
            if let Some(v) = module_version(&first) {
                d.props.push(("Driver version".into(), v));
            }
        }
    }
    // Debug builds only: PROTON_SECURITY_DEMO_DEVICE=1 adds a fake device
    // without a driver, to preview how problem devices look.
    #[cfg(debug_assertions)]
    if std::env::var_os("PROTON_SECURITY_DEMO_DEVICE").is_some() {
        devices.push(Device {
            key: "demo:usb".into(),
            category: Category::Other,
            name: "Unknown USB device (0bda:c820)".into(),
            vendor: "Vendor 0bda".into(),
            bus: "USB",
            ids: "0bda:c820".into(),
            driver: None,
            modalias: Some("usb:v0BDApC820d0200dcEFdsc02dp01icE0isc01ip01in00".into()),
            candidate_modules: vec![],
            modules: vec![],
            status: Status::NoDriver,
            props: vec![
                ("Location".into(), "USB port 1-4".into()),
                ("Speed".into(), "480 Mbit/s".into()),
            ],
            hw_query: Some("usb:0bda-c820".into()),
        });
        devices.push(Device {
            key: "demo:wifi".into(),
            category: Category::Network,
            name: "Wi-Fi 6 AX201 160MHz".into(),
            vendor: "Intel Corporation".into(),
            bus: "PCI",
            ids: "8086:a0f0".into(),
            driver: Some("iwlwifi".into()),
            modalias: None,
            candidate_modules: vec![],
            modules: vec!["iwlwifi".into()],
            status: Status::Ok,
            props: vec![
                ("Location".into(), "PCI slot 0000:00:14.3".into()),
                ("Network interface".into(), "wlp0s20f3".into()),
            ],
            hw_query: Some("pci:8086-a0f0".into()),
        });
    }
    devices.sort_by(|a, b| {
        a.category
            .cmp(&b.category)
            .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    DeviceSnapshot {
        devices,
        firmware_messages: firmware_messages(),
    }
}

/// Running kernel version, for the page footer.
pub fn kernel() -> String {
    kernel_release()
}

/// Kernel module that provides a driver, from `/sys/bus/*/drivers/<name>/module`.
/// None when the driver is built into the kernel.
pub fn module_of_driver(driver: &str) -> Option<String> {
    let rd = std::fs::read_dir("/sys/bus").ok()?;
    for bus in rd.flatten() {
        let link = bus.path().join("drivers").join(driver).join("module");
        if let Some(m) = link_name(&link) {
            return Some(m);
        }
    }
    // Some drivers are named exactly like their module.
    let m = driver.replace('-', "_");
    Path::new("/sys/module")
        .join(&m)
        .join("refcnt")
        .exists()
        .then_some(m)
}

// ------------------------------------------------------------------ driver details

/// modprobe configuration where "Uninstall driver" blocks kernel drivers. The helper writes it;
/// deleting a line ("Enable driver") undoes it.
pub const BLACKLIST_FILE: &str = "/etc/modprobe.d/proton-security-disabled.conf";

/// Modules the user disabled ("uninstalled") through Proton Security.
pub fn disabled_modules() -> Vec<String> {
    sys::read(BLACKLIST_FILE)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().strip_prefix("blacklist "))
        .map(|m| m.trim().to_string())
        .collect()
}

/// Details about a kernel driver, shown before driver actions.
#[derive(Clone, Debug, Default)]
pub struct DriverInfo {
    /// Module name ("iwlwifi").
    pub module: String,
    /// Module file on disk.
    pub file: Option<String>,
    /// Debian package that installed the module file.
    pub package: Option<String>,
    /// Version of that package.
    pub package_version: Option<String>,
    /// Module version, if it declares one.
    pub version: Option<String>,
    /// Built into the kernel (can't be removed or reloaded).
    pub builtin: bool,
    /// Loaded right now.
    pub loaded: bool,
    /// Other modules that depend on it (it can't be unloaded while this is above 0).
    pub in_use_by: usize,
}

/// Look up a driver with `modinfo`, `dpkg -S` and /sys/module (all as the normal user).
pub fn driver_info(module: &str) -> DriverInfo {
    let file = sys::run_full("modinfo", &["-n", module])
        .filter(|r| r.0)
        .map(|r| r.1.trim().to_string())
        .filter(|f| !f.is_empty());
    let builtin = file
        .as_deref()
        .map(|f| f.contains("(builtin)"))
        .unwrap_or(false);
    let real_file = file.clone().filter(|_| !builtin);
    let package = real_file.as_ref().and_then(|f| {
        // dpkg -S knows the /lib path; on merged-/usr systems try both spellings.
        let alt = f
            .strip_prefix("/usr")
            .map(String::from)
            .unwrap_or_else(|| format!("/usr{f}"));
        [f.clone(), alt].iter().find_map(|path| {
            sys::run_full("dpkg", &["-S", path])
                .filter(|r| r.0)
                .and_then(|r| {
                    r.1.lines()
                        .next()
                        .and_then(|l| l.split(':').next())
                        .map(|p| p.trim().to_string())
                })
        })
    });
    let package_version = package
        .as_ref()
        .and_then(|p| sys::run_out("dpkg-query", &["-W", "-f=${Version}", p]))
        .filter(|v| !v.is_empty());
    let loaded = Path::new("/sys/module").join(module).exists();
    let in_use_by = sys::read_trim(format!("/sys/module/{module}/refcnt"))
        .and_then(|r| r.parse().ok())
        .unwrap_or(0);
    DriverInfo {
        module: module.to_string(),
        version: sys::run_full("modinfo", &["-F", "version", module])
            .filter(|r| r.0)
            .map(|r| r.1.trim().to_string())
            .filter(|v| !v.is_empty()),
        file: real_file,
        package,
        package_version,
        builtin,
        loaded,
        in_use_by,
    }
}

/// Devices that should never be uninstalled from here (disks, USB ports,
/// core system devices): losing them can make the computer unusable.
pub fn uninstall_allowed(c: Category) -> bool {
    !matches!(
        c,
        Category::Storage
            | Category::Disks
            | Category::Processors
            | Category::System
            | Category::UsbControllers
            | Category::Keyboards
            | Category::Mice
    )
}

// ------------------------------------------------------------------ uninstall (purge) plan

/// What "Uninstall driver" will do, worked out before asking the user.
#[derive(Clone, Debug, Default)]
pub struct PurgePlan {
    /// Kernel module of the driver.
    pub module: String,
    /// Package that ships the driver (None for drivers inside the kernel).
    pub package: Option<String>,
    /// Packages apt would purge (dry run).
    pub remove: Vec<String>,
    /// The driver is part of the Linux kernel package: it can only be disabled.
    pub kernel: bool,
    /// The dry run refused or would remove something we must not remove.
    pub blocked: Option<String>,
}

/// True for the kernel's own packages, which must never be removed by "Uninstall driver".
fn is_kernel_package(p: &str) -> bool {
    p.starts_with("linux-image") || p.starts_with("linux-modules") || p.starts_with("linux-signed")
}

/// Dry run as the normal user (`apt-get -s` needs no password).
pub fn purge_plan(module: &str, package: Option<&str>) -> PurgePlan {
    let mut plan = PurgePlan {
        module: module.to_string(),
        package: package.map(String::from),
        ..Default::default()
    };
    let Some(pkg) = package.filter(|p| !is_kernel_package(p)) else {
        plan.kernel = true;
        return plan;
    };
    match sys::run_full("apt-get", &["-s", "-q", "purge", pkg]) {
        Some((true, out, _)) => {
            plan.remove = out
                .lines()
                .filter_map(|l| l.strip_prefix("Purg ").or_else(|| l.strip_prefix("Remv ")))
                .filter_map(|l| l.split_whitespace().next())
                .map(String::from)
                .collect();
            if let Some(bad) = plan.remove.iter().find(|p| {
                is_kernel_package(p)
                    || sys::run_out("dpkg-query", &["-W", "-f=${Essential} ${Priority}", p])
                        .map(|v| {
                            v.starts_with("yes")
                                || v.contains("required")
                                || v.contains("important")
                        })
                        .unwrap_or(false)
            }) {
                plan.blocked = Some(format!(
                    "Removing this driver would also remove {bad}, which the system needs."
                ));
            }
        }
        Some((false, o, e)) => plan.blocked = Some(format!("{o}{e}").trim().to_string()),
        None => plan.blocked = Some("Could not run apt-get.".into()),
    }
    plan
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    #[test]
    fn hardware_fingerprint_is_stable_and_fast() {
        let t = std::time::Instant::now();
        let a = hw_fingerprint();
        let b = hw_fingerprint();
        assert!(t.elapsed() < std::time::Duration::from_millis(200));
        assert_eq!(a, b, "nothing changed, so the fingerprint must not change");
    }
}
