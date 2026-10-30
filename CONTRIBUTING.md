# Contributing to Proton Security

Thank you for helping! Proton Security is used by people who are new to Linux, so every change is judged by one
question: **does this make their computer safer without making it harder to use?**

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) in all project spaces.

## Ways to help

- **Report a bug.** [Open an issue](https://github.com/ProtonOS-Linux/proton-security-app/issues/new/choose) and attach the
  output of `proton-security --diagnose`. Remove anything private (user names, network addresses) first.
- **Suggest an improvement.** Open a feature request and describe the problem you want solved, not only the
  solution.
- **Improve the wording.** If a message confused you, it will confuse others. Small text fixes are very welcome.
- **Test on your hardware.** Laptops, NVMe disks, fingerprint readers, unusual Wi-Fi cards: reports from real
  machines find bugs nobody else can.
- **Write code.** Look for issues labelled `good first issue`.

Security problems are the exception: please report them privately, as described in [SECURITY.md](SECURITY.md).

## Making a change

1. Fork the repository and create a branch from `main`.
2. Set up the project as described in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).
3. Make your change. Keep pull requests focused: one fix or feature each.
4. Run the checks:
   ```bash
   cargo fmt
   cargo clippy --all-targets -- -D warnings
   cargo test
   cargo doc --no-deps --document-private-items
   bash -n packaging/proton-security-helper
   ```
5. If users will notice the change, add a line under a new version heading at the top of
   [CHANGELOG.md](CHANGELOG.md).
6. Open a pull request and fill in the template. Add a screenshot for anything visible, at 1366×768 if you can.

## What we look for in review

- **Plain language.** UI text is written for someone who has never used Linux. Say what happened and what to do.
- **Comments.** Every file starts with a `//!` comment, every function and type has a `///` comment saying what it
  is for, and non-obvious decisions are explained where they're made. Reviewers will ask for them.
- **No root in the app.** The window and the tray run as the user. Reading something that needs root is only done
  after the user clicks a button for it.
- **Responsive UI.** Commands and folder walks never run on the UI thread (use `Bg::refresh` or a thread).
- **Small screens.** New pages must work at 1366×768 and in both light and dark themes.
- **Tests.** New parsing of command output or files comes with a unit test using real sample output.

## Adding a privileged action

Anything that needs root goes through the helper script, and changes to it get extra review.

1. Add a new command to the `case` in
   [`packaging/proton-security-helper`](packaging/proton-security-helper), with a comment above it saying what it
   does and what its arguments are.
2. **Validate every argument** with a strict pattern before using it (see the `valid_*` functions), and quote it
   when you use it (`"$arg"`, and `--` before it for commands that take options).
3. Never write as root into a folder the user controls (their home, `/run/user/<uid>`, `/tmp`). Use a
   `mktemp -d` folder in `/run`, and hand files to the user with `setpriv` as in `luks-header-backup`.
4. Passwords and other secrets come on standard input, never as arguments.
5. If the command **lowers protection** (opens something, turns something off, removes or loads drivers) or
   handles secrets, add it to `PROTECTED_COMMANDS` in both the helper script and `src/admin.rs`: it then runs
   through `proton-security-helper-protected`, which always asks for the password. A unit test checks the two
   lists match.
6. Call it from the app with `App::run_admin` (or `run_admin_input` for secrets); the right entry point is chosen
   automatically.
7. Document it in the command tables of [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md#helper-commands).

## Commit messages

Write a short summary line in the imperative ("Show bad sectors on the Health page"), then, if needed, a blank
line and a few sentences about *why*. Reference issues with `Fixes #123`.

## License

By contributing, you agree that your contribution is licensed under the
[GNU General Public License v3.0 or later](LICENSE), like the rest of the project. New source files start with:

```rust
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Proton OS contributors
```
