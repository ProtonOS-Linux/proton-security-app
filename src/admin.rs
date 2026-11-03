// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors

//! Runs privileged actions through `pkexec proton-security-helper <command>`.
//! The helper is a small whitelisted shell script installed with a polkit policy, under two
//! names: one for everyday fixes and one for commands that lower protection (see
//! [`PROTECTED_COMMANDS`]).

use crate::sys::{Shared, shared};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Where the Debian package installs the helper script for everyday fixes. The polkit policy
/// (`packaging/org.protonos.security.policy`) names this exact path and remembers the password
/// for a few minutes.
pub const HELPER_INSTALLED: &str = "/usr/libexec/proton-security/proton-security-helper";

/// The same script installed under a second name, for [`PROTECTED_COMMANDS`]. Its polkit action
/// asks for the password every time, so a remembered password can't be reused for them.
pub const HELPER_PROTECTED_INSTALLED: &str =
    "/usr/libexec/proton-security/proton-security-helper-protected";

/// Helper commands that lower protection or touch disk-encryption secrets. They only run
/// through [`HELPER_PROTECTED_INSTALLED`]. Must match `PROTECTED_COMMANDS` in the helper script
/// (checked by a unit test).
pub const PROTECTED_COMMANDS: [&str; 12] = [
    "fw-allow-port",
    "fw-remove-port",
    "fw-unblock-ip",
    "av-auto",
    "driver-purge",
    "driver-reinstall",
    "driver-enable",
    "load-module",
    "luks-add-recovery",
    "luks-change-password",
    "luks-header-backup",
    "snapper-allow-sudo",
];

/// True when `command` must go through the protected entry point.
pub fn is_protected(command: &str) -> bool {
    PROTECTED_COMMANDS.contains(&command)
}

/// The helper script to run with pkexec for `command`: the protected entry point for
/// [`PROTECTED_COMMANDS`], the everyday one for everything else.
pub fn helper_path(command: &str) -> PathBuf {
    let name = if is_protected(command) {
        "proton-security-helper-protected"
    } else {
        "proton-security-helper"
    };
    // Debug builds only: an explicit override for testing a changed script. Protected commands
    // use the override's path with "-protected" added (make it a symlink to the script).
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("PROTON_SECURITY_HELPER") {
        let mut p = p;
        if is_protected(command) {
            p.push("-protected");
        }
        return PathBuf::from(p);
    }
    let installed = PathBuf::from(if is_protected(command) {
        HELPER_PROTECTED_INSTALLED
    } else {
        HELPER_INSTALLED
    });
    // Release builds always use the installed helpers: they are the only paths the
    // polkit policy allows without the generic "run any program" prompt.
    if !cfg!(debug_assertions) || installed.exists() {
        return installed;
    }
    // Debug builds without the package installed: the script in the source tree.
    if let Ok(exe) = std::env::current_exe() {
        for anc in exe.ancestors().skip(1).take(4) {
            let p = anc.join("packaging").join(name);
            if p.exists() {
                return p;
            }
        }
    }
    installed
}

/// Progress of an administrator task.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TaskState {
    /// pkexec or the helper is still running.
    Running,
    /// The helper exited with code 0.
    Succeeded,
    /// The helper failed (any other exit code); the log says why.
    Failed,
    /// The password dialog was closed, or the user isn't allowed (pkexec exit 126/127).
    Cancelled,
}

/// One running or finished administrator action. Its fields are shared with the background
/// thread that reads the helper's output, so the window can show the log live.
pub struct AdminTask {
    /// Shown as the title of the progress window ("Updating driver").
    pub title: String,
    /// Combined stdout + stderr, for the log view.
    pub log: Shared<Vec<String>>,
    /// stdout only, for commands that return data (e.g. JSON).
    pub stdout: Shared<String>,
    /// Current [`TaskState`], updated by the background thread.
    pub state: Shared<TaskState>,
    /// Show the log window to the user.
    pub visible: bool,
}

impl AdminTask {
    /// Current state.
    pub fn state(&self) -> TaskState {
        *self.state.lock().unwrap()
    }
    /// True once the task is no longer running (whatever the result).
    pub fn finished(&self) -> bool {
        self.state() != TaskState::Running
    }
}

/// Start `pkexec proton-security-helper <args>` in the background. polkit shows the password
/// dialog; the window polls the returned task to show progress.
pub fn spawn(title: &str, args: &[&str], visible: bool, ctx: &egui::Context) -> AdminTask {
    spawn_with_input(title, args, None, visible, ctx)
}

/// Lines starting with this are secrets meant for the app, never the log window.
pub const SECRET_PREFIX: &str = "RECOVERY-KEY:";

/// What the log window shows for a line of the helper's output: secret lines (see
/// [`SECRET_PREFIX`]) are replaced, wherever in the line the prefix appears.
fn log_line(line: String) -> String {
    if line.contains(SECRET_PREFIX) {
        "(The recovery key is shown in its own window.)".into()
    } else {
        line
    }
}

/// Like `spawn`, but writes `input` (e.g. a disk password) to the helper's
/// standard input. Secrets never appear on the command line.
pub fn spawn_with_input(
    title: &str,
    args: &[&str],
    input: Option<String>,
    visible: bool,
    ctx: &egui::Context,
) -> AdminTask {
    let log = shared(Vec::<String>::new());
    let stdout_buf = shared(String::new());
    let state = shared(TaskState::Running);
    let helper = helper_path(args.first().copied().unwrap_or(""));
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

    {
        let (log, stdout_buf, state, ctx) =
            (log.clone(), stdout_buf.clone(), state.clone(), ctx.clone());
        std::thread::spawn(move || {
            let child = Command::new("pkexec")
                .arg(&helper)
                .args(&args)
                .stdin(if input.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();
            let mut child = match child {
                Ok(c) => c,
                Err(e) => {
                    log.lock()
                        .unwrap()
                        .push(format!("Could not start pkexec: {e}"));
                    *state.lock().unwrap() = TaskState::Failed;
                    ctx.request_repaint();
                    return;
                }
            };
            if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
                use std::io::Write;
                let _ = stdin.write_all(data.as_bytes());
                // dropping stdin closes it
            }
            let err = child.stderr.take().unwrap();
            let err_thread = {
                let (log, ctx) = (log.clone(), ctx.clone());
                std::thread::spawn(move || {
                    for line in BufReader::new(err).lines().map_while(Result::ok) {
                        // The helper prints secrets on standard output only; hide them here too,
                        // in case a tool ever echoes one on its error output.
                        log.lock().unwrap().push(log_line(line));
                        ctx.request_repaint();
                    }
                })
            };
            let out = child.stdout.take().unwrap();
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                {
                    let mut s = stdout_buf.lock().unwrap();
                    s.push_str(&line);
                    s.push('\n');
                }
                log.lock().unwrap().push(log_line(line));
                ctx.request_repaint();
            }
            let _ = err_thread.join();
            let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
            let st = match code {
                0 => TaskState::Succeeded,
                // pkexec: 126 = dialog dismissed, 127 = not authorized
                126 | 127 => {
                    log.lock()
                        .unwrap()
                        .push("Authentication was cancelled or not authorized.".into());
                    TaskState::Cancelled
                }
                c => {
                    log.lock()
                        .unwrap()
                        .push(format!("Finished with error code {c}."));
                    TaskState::Failed
                }
            };
            *state.lock().unwrap() = st;
            ctx.request_repaint();
        });
    }

    AdminTask {
        title: title.to_string(),
        log,
        stdout: stdout_buf,
        state,
        visible,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The protected list here and in the helper script must be the same, or a command would be
    /// sent to the wrong entry point and refused.
    #[test]
    fn protected_list_matches_the_helper() {
        let script = include_str!("../packaging/proton-security-helper");
        let line = script
            .lines()
            .find_map(|l| l.strip_prefix("PROTECTED_COMMANDS=\""))
            .and_then(|l| l.strip_suffix('"'))
            .expect("PROTECTED_COMMANDS line in the helper");
        let mut theirs: Vec<&str> = line.split_whitespace().collect();
        let mut ours = PROTECTED_COMMANDS.to_vec();
        theirs.sort();
        ours.sort();
        assert_eq!(ours, theirs);
        // Every protected command exists in the helper.
        for c in PROTECTED_COMMANDS {
            // A `case` branch label such as "fw-allow-port)" or "a|b|c)".
            let is_branch = |l: &str| {
                let l = l.trim();
                l.ends_with(')') && l.trim_end_matches(')').split('|').any(|x| x == c)
            };
            assert!(
                script.lines().any(is_branch),
                "{c} is not a command of the helper"
            );
        }
    }

    #[test]
    fn secrets_never_reach_the_log() {
        assert!(!log_line("RECOVERY-KEY: 123456-654321".into()).contains("123456"));
        assert!(!log_line("cryptsetup: RECOVERY-KEY: 123456".into()).contains("123456"));
        assert_eq!(log_line("==> Done".into()), "==> Done");
    }

    #[test]
    fn commands_go_to_the_right_entry_point() {
        assert!(helper_path("fw-allow-port").ends_with("proton-security-helper-protected"));
        assert!(helper_path("luks-add-recovery").ends_with("proton-security-helper-protected"));
        assert!(helper_path("enable-firewall").ends_with("proton-security-helper"));
    }
}
