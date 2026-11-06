// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Drawing code for two pages: "Account protection" (screen lock, sign-in, password,
//! administrators) and "Device security" (Secure Boot, TPM, disk encryption with its
//! recovery key / password / header backup dialogs). The data comes from
//! `account.rs` and `devsec.rs`.

use crate::checks::Level;
use crate::ui::{self, Icon};
use crate::{AfterAdmin, App};
use egui::RichText;

/// One "status row": badge + title + explanation + optional button.
pub fn status_row(ui: &mut egui::Ui, ok: Option<bool>, title: &str, text: &str) {
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(egui::vec2(22.0, 22.0), egui::Sense::hover());
        let lvl = ok.map(|o| if o { Level::Ok } else { Level::Warn });
        ui::paint_badge(ui.painter(), r.center(), 9.0, lvl, ui::card_fill(ui));
        ui.vertical(|ui| {
            ui.label(RichText::new(title).strong());
            ui.add(egui::Label::new(RichText::new(text).color(ui::weak(ui))).wrap());
        });
    });
}

/// Open a page of KDE System Settings (`kcmshell6 <module>`), with fallbacks for older Plasma.
/// False when none could be started.
pub fn open_kcm(module: &str) -> bool {
    crate::sys::spawn_detached("kcmshell6", &[module])
        || crate::sys::spawn_detached("systemsettings", &[module])
        || crate::sys::spawn_detached("kcmshell5", &[module])
}

impl App {
    /// Draw the Account protection page.
    pub fn page_account(&mut self, ui: &mut egui::Ui) {
        // Layout, top to bottom: page title and status line; "Screen lock" (settings and the fix
        // button, the battery menu's screen locking switch); "Sign-in" (password, automatic
        // sign-in); "Administrators" (information only). Data loads in the background (`Bg`).
        let ctx = ui.ctx().clone();
        if self.account.stale(std::time::Duration::from_secs(20)) {
            self.account.refresh(&ctx, crate::account::load);
        }
        ui::page_header(
            ui,
            Icon::Account,
            "Account protection",
            "Keep your account and this computer locked when you are away.",
        );
        let Some(a) = self.account.get() else {
            ui.add(egui::Spinner::new());
            return;
        };
        let max = crate::policy::get().max_screen_lock_minutes;

        // ---- screen lock
        ui::section_title(ui, "Screen lock");
        ui::card(ui, |ui| {
            let paused = a.manual_inhibition().cloned();
            let settings_ok = a.lock.autolock && a.lock.timeout_min <= max && a.lock.lock_on_resume;
            let ok = settings_ok && paused.is_none();
            let text = if settings_ok && paused.is_some() {
                "Screen locking is paused: \"Sleep and screen locking after inactivity\" is turned off in the battery menu. Your screen will not lock while you are away.".to_string()
            } else if !a.lock.autolock {
                "The screen does not lock by itself. Anyone can use your computer while you are away.".to_string()
            } else {
                format!(
                    "The screen locks after {} minute(s) without activity{}.",
                    a.lock.timeout_min,
                    if a.lock.lock_on_resume {
                        " and when the computer wakes from sleep"
                    } else {
                        ", but not after sleep"
                    }
                )
            };
            status_row(
                ui,
                Some(ok),
                if ok {
                    "Screen lock is on"
                } else {
                    "Screen lock needs attention"
                },
                &text,
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if !settings_ok && ui::primary_button(ui, "Turn on screen lock").clicked() {
                    match crate::account::fix_screen_lock(max) {
                        Ok(()) => self.toast("Screen lock is on."),
                        Err(e) => self.toast(e),
                    }
                    self.account.refresh(&ctx, crate::account::load);
                    self.refresh_checks(&ctx);
                }
                if ui::link(ui, "Screen locking settings").clicked()
                    && !open_kcm("kcm_screenlocker")
                {
                    self.toast("Could not open System Settings.");
                }
            });
            if paused.is_some() {
                ui.add_space(4.0);
                ui::small(
                    ui,
                    "To turn it back on: click the battery (or power) icon in the taskbar and switch on \"Sleep and screen locking after inactivity\".",
                );
            }
            // Video players and calls pause locking while they play: show, don't warn.
            let others: Vec<String> = a
                .inhibitions
                .iter()
                .filter(|i| Some(*i) != paused.as_ref())
                .map(|(app, why)| format!("{app} ({why})"))
                .collect();
            if !others.is_empty() {
                ui.add_space(4.0);
                ui::small(
                    ui,
                    format!(
                        "Paused for now by: {}. Locking resumes when they finish.",
                        others.join(", ")
                    ),
                );
            }
        });

        // ---- sign-in
        ui::section_title(ui, "Sign-in");
        ui::card(ui, |ui| {
            match &a.autologin {
                Some((user, file)) => {
                    status_row(
                        ui,
                        Some(false),
                        "Automatic sign-in is on",
                        &format!(
                            "The computer opens \"{user}\"'s desktop at startup without asking for a password (set in {file})."
                        ),
                    );
                    ui.add_space(6.0);
                    if ui::primary_button(ui, "Turn off automatic sign-in").clicked() {
                        self.run_admin(
                            &ctx,
                            "Turning off automatic sign-in",
                            &["disable-autologin"],
                            AfterAdmin::RefreshAll,
                            true,
                        );
                    }
                }
                None => status_row(
                    ui,
                    Some(true),
                    "Automatic sign-in is off",
                    "A password is needed to sign in at startup.",
                ),
            }
            ui.add_space(8.0);
            ui.separator();
            ui.add_space(4.0);
            match &a.password {
                Some(crate::account::PasswordStatus::NoPassword) => {
                    status_row(
                        ui,
                        Some(false),
                        "Your account has no password",
                        "Anyone can sign in as you. Set a password in System Settings.",
                    );
                }
                Some(crate::account::PasswordStatus::Set) => {
                    status_row(
                        ui,
                        Some(true),
                        "Your account has a password",
                        &format!("Signed in as {}.", a.user),
                    );
                }
                _ => status_row(ui, None, "Password", &format!("Signed in as {}.", a.user)),
            }
            ui.add_space(6.0);
            if ui::link(ui, "Change password or manage accounts").clicked()
                && !open_kcm("kcm_users")
            {
                self.toast("Could not open System Settings.");
            }
        });

        // ---- administrators
        ui::section_title(ui, "Administrators");
        ui::card(ui, |ui| {
            if a.is_admin {
                // Information only: never turns the tile or the tray icon yellow.
                ui.horizontal(|ui| {
                    let (r, _) =
                        ui.allocate_exact_size(egui::vec2(22.0, 22.0), egui::Sense::hover());
                    ui::paint_notice_badge(ui.painter(), r.center(), 9.0, ui::card_fill(ui));
                    ui.add(
                        egui::Label::new(
                            "Your account is an administrator: it can install software and change system settings after entering its password.",
                        )
                        .wrap(),
                    );
                });
            } else {
                ui.label("Your account is a standard account. Administrators can install software and change system settings.");
            }
            ui.add_space(4.0);
            if a.admins.is_empty() {
                ui::small(ui, "No administrator accounts found in the sudo group.");
            } else {
                ui::small(
                    ui,
                    format!("Administrator accounts: {}", a.admins.join(", ")),
                );
            }
            ui::small(ui, "Tip: for everyday work, a standard account is safer.");
        });
    }

    /// Draw the Device security page.
    pub fn page_devsec(&mut self, ui: &mut egui::Ui) {
        // Layout: "Secure Boot", "Security chip (TPM)", then "Disk encryption" with the tools for an
        // encrypted drive (recovery key, change password, header backup). Information only, except
        // those tools; each asks for the administrator password (protected helper commands).
        let ctx = ui.ctx().clone();
        if self.devsec.last.is_none() {
            self.devsec.refresh(&ctx, crate::devsec::load);
        }
        ui::page_header(
            ui,
            Icon::Lock,
            "Device security",
            "Security built into your computer's hardware and storage.",
        );
        let Some(d) = self.devsec.get() else {
            ui.add(egui::Spinner::new());
            return;
        };
        let pol = crate::policy::get();

        ui::section_title(ui, "Secure Boot");
        ui::card(ui, |ui| {
            let (ok, title, text) = match (d.uefi, d.secure_boot) {
                (false, _) => (
                    None,
                    "Not supported",
                    "This computer starts in legacy BIOS mode, which has no Secure Boot.",
                ),
                (true, Some(true)) => (
                    Some(true),
                    "Secure Boot is on",
                    "Only trusted, signed software can run while the computer starts. This blocks boot-level malware (rootkits).",
                ),
                (true, Some(false)) => (
                    if pol.require_secure_boot {
                        Some(false)
                    } else {
                        None
                    },
                    "Secure Boot is off",
                    "Turn it on in the computer's firmware settings (UEFI/BIOS setup) to block boot-level malware.",
                ),
                (true, None) => (
                    None,
                    "Secure Boot status unknown",
                    "Install the mokutil package to check it.",
                ),
            };
            status_row(ui, ok, title, text);
        });

        ui::section_title(ui, "Security chip (TPM)");
        ui::card(ui, |ui| match &d.tpm {
            Some(v) => status_row(
                ui,
                Some(true),
                &format!("TPM {v} is available"),
                "The Trusted Platform Module stores encryption keys in hardware.",
            ),
            None => status_row(
                ui,
                None,
                "No TPM found",
                "This computer has no TPM, or it is turned off in the firmware settings.",
            ),
        });

        ui::section_title(ui, "Disk encryption");
        let mut open_dialog: Option<LuksDialog> = None;
        ui::card(ui, |ui| {
            if d.disks.is_empty() {
                status_row(ui, None, "Unknown", "Could not find the system drive.");
            }
            for disk in &d.disks {
                let what = if disk.mount == "/" {
                    "System drive"
                } else {
                    "Home folder drive"
                };
                if disk.encrypted {
                    status_row(
                        ui,
                        Some(true),
                        &format!("{what} is encrypted"),
                        "If the computer is lost or stolen, your files can't be read without the disk password.",
                    );
                    if let (Some(luks), true) = (&disk.luks, d.cryptsetup) {
                        ui.add_space(4.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.add_space(30.0);
                            if ui::button(ui, "Create recovery key")
                                .on_hover_text("Adds a second key (48 digits) that also unlocks the drive. Save it somewhere safe in case you forget the disk password.")
                                .clicked()
                            {
                                open_dialog = Some(LuksDialog::new(LuksKind::Recovery, luks));
                            }
                            if ui::button(ui, "Change disk password").clicked() {
                                open_dialog = Some(LuksDialog::new(LuksKind::ChangePassword, luks));
                            }
                            if ui::button(ui, "Back up encryption header")
                                .on_hover_text("Saves a copy of the drive's encryption header. If the header is ever damaged, it is the only way to get your files back.")
                                .clicked()
                            {
                                let l = luks.clone();
                                self.run_admin(&ctx, "Backing up the encryption header", &["luks-header-backup", &l], AfterAdmin::HeaderBackup, true);
                            }
                        });
                    }
                } else {
                    status_row(
                        ui,
                        if pol.require_disk_encryption {
                            Some(false)
                        } else {
                            None
                        },
                        &format!("{what} is not encrypted"),
                        "Anyone with physical access to the disk could read your files.",
                    );
                }
                ui.add_space(6.0);
            }
            if let Some(false) = d.swap_encrypted {
                ui::small(ui, "Note: the swap partition is not encrypted.");
            }
            if pol.require_disk_encryption && !d.all_encrypted() {
                ui::small(
                    ui,
                    format!("{}: disk encryption is required.", pol.managed_text()),
                );
            }
            ui.add_space(4.0);
            ui.separator();
            ui.add_space(4.0);
            ui.label(RichText::new("Turning encryption on or off").strong());
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "The system drive can't be encrypted or decrypted while the computer is running from it. \
                         Encryption is chosen when Proton OS is installed (\"Encrypt system\" in the installer). \
                         To add or remove it later, back up your files and reinstall. \
                         USB and data drives can be encrypted with KDE Partition Manager; this erases the drive.",
                    )
                    .color(ui::weak(ui)),
                )
                .wrap(),
            );
            if d.partition_manager {
                ui.add_space(4.0);
                if ui::link(ui, "Open KDE Partition Manager").clicked()
                    && !crate::sys::spawn_detached("partitionmanager", &[])
                {
                    self.toast("Could not open KDE Partition Manager.");
                }
            }
        });
        if let Some(dlg) = open_dialog {
            self.luks_dialog = Some(dlg);
        }
    }
}

// ------------------------------------------------------------------ disk encryption dialogs

/// Which disk password dialog is open.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum LuksKind {
    /// Create a recovery key (asks for the current disk password).
    Recovery,
    /// Change the disk password (asks for the current and the new one).
    ChangePassword,
}

/// State of the disk password dialog. The typed passwords are wiped when it closes (see the
/// `Drop` impl).
pub struct LuksDialog {
    /// Which dialog.
    pub kind: LuksKind,
    /// The LUKS partition, for example `/dev/nvme0n1p3`.
    pub device: String,
    /// Current disk password, as typed.
    pub current: String,
    /// New password (change password only).
    pub new1: String,
    /// New password again, to catch typos.
    pub new2: String,
}

impl LuksDialog {
    /// An empty dialog for `device`.
    pub fn new(kind: LuksKind, device: &str) -> Self {
        Self {
            kind,
            device: device.to_string(),
            current: String::new(),
            new1: String::new(),
            new2: String::new(),
        }
    }
}

impl Drop for LuksDialog {
    fn drop(&mut self) {
        // Don't leave passwords lying around in memory longer than needed.
        for s in [&mut self.current, &mut self.new1, &mut self.new2] {
            s.clear();
            s.shrink_to_fit();
        }
    }
}

/// A label and a password box with a visible border (white-on-white otherwise in the light
/// theme).
fn password_field(ui: &mut egui::Ui, label: &str, value: &mut String) -> egui::Response {
    ui.label(label);
    // Unfocused text boxes are white on white in the light theme: draw a border.
    let stroke = egui::Stroke::new(
        1.0,
        if ui.visuals().dark_mode {
            egui::Color32::from_gray(110)
        } else {
            egui::Color32::from_gray(165)
        },
    );
    ui.add(
        egui::TextEdit::singleline(value)
            .password(true)
            .frame(
                egui::Frame::new()
                    .stroke(stroke)
                    .corner_radius(4)
                    .inner_margin(egui::Margin::symmetric(6, 4))
                    .fill(ui.visuals().extreme_bg_color),
            )
            .desired_width(f32::INFINITY),
    )
}

impl App {
    /// Draw the disk password dialog and the recovery key window when open. Passwords are sent
    /// to the helper on its standard input, never on the command line, so other users can't see
    /// them in the process list.
    pub fn luks_dialogs(&mut self, ctx: &egui::Context) {
        // The disk-encryption windows: entering passwords (they go to the helper on standard input,
        // never on a command line), then showing a new recovery key once in its own window.
        // ---- enter passwords
        if let Some(dlg) = &mut self.luks_dialog {
            let (mut submit, mut cancel) = (false, false);
            egui::Modal::new(egui::Id::unique("luks_dialog"))
                .frame(egui::Frame::popup(&ctx.global_style()).inner_margin(20).corner_radius(10))
                .show(ctx, |ui| {
                    ui.set_width(460.0);
                    let title = match dlg.kind {
                        LuksKind::Recovery => "Create a recovery key",
                        LuksKind::ChangePassword => "Change disk password",
                    };
                    ui.label(RichText::new(title).size(18.0).strong());
                    ui::small(ui, format!("Drive: {}", dlg.device));
                    ui.add_space(6.0);
                    let r = password_field(ui, "Current disk password (the one you type when the computer starts):", &mut dlg.current);
                    if dlg.kind == LuksKind::ChangePassword {
                        password_field(ui, "New disk password (at least 8 characters):", &mut dlg.new1);
                        password_field(ui, "Type the new password again:", &mut dlg.new2);
                    } else {
                        ui::small(ui, "A 48-digit recovery key will be created. It unlocks the drive if you forget your password.");
                    }
                    r.request_focus();
                    let ok = !dlg.current.is_empty()
                        && (dlg.kind == LuksKind::Recovery || (dlg.new1.chars().count() >= 8 && dlg.new1 == dlg.new2));
                    if dlg.kind == LuksKind::ChangePassword && !dlg.new2.is_empty() && dlg.new1 != dlg.new2 {
                        ui.colored_label(ui::RED, "The new passwords don't match.");
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.add_enabled_ui(ok, |ui| {
                            if ui::primary_button(ui, "Continue").clicked() {
                                submit = true;
                            }
                        });
                        if ui::button(ui, "Cancel").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                            cancel = true;
                        }
                    });
                    ui.add_space(4.0);
                    ui::small(ui, "You will also be asked for your administrator password.");
                });
            if submit {
                let dlg = self.luks_dialog.take().unwrap();
                let (cmd, input, after, title) = match dlg.kind {
                    LuksKind::Recovery => (
                        "luks-add-recovery",
                        format!("{}\n", dlg.current),
                        AfterAdmin::RecoveryKey,
                        "Creating a recovery key",
                    ),
                    LuksKind::ChangePassword => (
                        "luks-change-password",
                        format!("{}\n{}\n", dlg.current, dlg.new1),
                        AfterAdmin::RefreshAll,
                        "Changing the disk password",
                    ),
                };
                let dev = dlg.device.clone();
                self.run_admin_input(ctx, title, &[cmd, &dev], input, after, true);
            } else if cancel {
                self.luks_dialog = None;
            }
        }

        // ---- show a new recovery key
        if let Some(key) = self.recovery_key.clone() {
            let mut done = false;
            egui::Modal::new(egui::Id::unique("recovery_key"))
                .frame(egui::Frame::popup(&ctx.global_style()).inner_margin(20).corner_radius(10))
                .show(ctx, |ui| {
                    ui.set_width(560.0);
                    ui.label(RichText::new("Your recovery key").size(18.0).strong());
                    ui.add_space(4.0);
                    ui.label("Save or print this key and keep it somewhere safe, not only on this computer. You can type it instead of your disk password when the computer starts.");
                    ui.add_space(8.0);
                    egui::Frame::new()
                        .fill(if ui.visuals().dark_mode { egui::Color32::from_gray(24) } else { egui::Color32::from_gray(245) })
                        .corner_radius(6)
                        .inner_margin(12)
                        .show(ui, |ui| {
                            ui.vertical_centered(|ui| {
                                ui.label(RichText::new(two_lines(&key)).monospace().size(17.0).strong());
                            });
                        });
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui::primary_button(ui, "Save to file…").clicked() {
                            let k = key.clone();
                            let slot = self.file_saved.clone();
                            std::thread::spawn(move || {
                                let default = crate::report::default_path()
                                    .with_file_name(format!("Recovery-key-{}.txt", crate::report::hostname()));
                                let r = save_secret_file(&default, &format!(
                                    "Proton OS disk recovery key\nComputer: {}\nCreated: {}\n\n{}\n\nType this key instead of your disk password when the computer starts.\n",
                                    crate::report::hostname(),
                                    chrono::Local::now().format("%B %-d, %Y"),
                                    k
                                ));
                                *slot.lock().unwrap() = Some(r);
                            });
                        }
                        if ui::button(ui, "Copy").clicked() {
                            ui.ctx().copy_text(key.clone());
                        }
                        if ui::button(ui, "I saved it").clicked() {
                            done = true;
                        }
                    });
                });
            if done {
                self.recovery_key = None;
            }
        }
        let saved = self.file_saved.lock().unwrap().take();
        if let Some(r) = saved {
            match r {
                Ok(p) => self.toast(format!("Saved to {}", p.display())),
                Err(e) if !e.is_empty() => self.toast(e),
                Err(_) => {}
            }
        }
    }
}

/// Ask where to save (KDE file dialog) and write the file readable only by the user.
pub fn save_secret_file(
    default: &std::path::Path,
    content: &str,
) -> Result<std::path::PathBuf, String> {
    let path = choose_save_path(default, "*.txt")?;
    write_private(&path, content.as_bytes())?;
    Ok(path)
}

/// Ask where to save a file (kdialog). `Err("")` means the user cancelled; without kdialog the
/// default path is used.
pub fn choose_save_path(
    default: &std::path::Path,
    filter: &str,
) -> Result<std::path::PathBuf, String> {
    if crate::sys::which("kdialog").is_some() {
        match crate::sys::run_full(
            "kdialog",
            &[
                "--title",
                "Save as",
                "--getsavefilename",
                &default.to_string_lossy(),
                filter,
            ],
        ) {
            Some((true, out, _)) if !out.trim().is_empty() => {
                Ok(std::path::PathBuf::from(out.trim()))
            }
            Some(_) => Err(String::new()), // cancelled
            None => Ok(default.to_path_buf()),
        }
    } else {
        Ok(default.to_path_buf())
    }
}

/// Write a file only the user can read (mode 600), for recovery keys and header backups.
pub fn write_private(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("Could not save: {e}"))?;
    f.write_all(data)
        .map_err(|e| format!("Could not save: {e}"))
}

/// "a-b-c-d-e-f-g-h" -> "a-b-c-d-\ne-f-g-h" so the key never wraps mid-group.
fn two_lines(key: &str) -> String {
    let g: Vec<&str> = key.split('-').collect();
    if g.len() < 6 {
        return key.to_string();
    }
    let h = g.len().div_ceil(2);
    format!("{}-\n{}", g[..h].join("-"), g[h..].join("-"))
}
