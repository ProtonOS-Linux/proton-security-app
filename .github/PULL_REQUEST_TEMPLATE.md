## What does this change?

<!-- One or two sentences. Link the issue it fixes: "Fixes #123". -->

## How did you test it?

<!-- For example: "cargo test, and opened the Health page with PROTON_SECURITY_FAKE_UPTIME_DAYS=20". -->

## Checklist

- [ ] `cargo fmt`, `cargo clippy --all-targets -- -D warnings` and `cargo test` pass
- [ ] New and changed functions have `///` comments; new files start with a `//!` comment and the SPDX header
- [ ] UI text is plain language for someone new to Linux
- [ ] Visible changes: screenshot attached, checked at 1366×768 in light and dark theme
- [ ] Changes to `packaging/proton-security-helper`: arguments validated, and
      [docs/SECURITY-MODEL.md](https://github.com/ProtonOS-Linux/proton-security-app/blob/main/docs/SECURITY-MODEL.md) updated
- [ ] User-visible change: line added to `CHANGELOG.md`
