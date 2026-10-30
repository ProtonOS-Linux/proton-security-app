# Security policy

Proton Security helps people protect their computers, so we treat problems in it with priority.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report them privately through GitHub:
[**Report a vulnerability**](https://github.com/ProtonOS-Linux/proton-security-app/security/advisories/new)
(the *Security* tab of this repository, then *Report a vulnerability*).
If you can't use GitHub, email [support@protonos.org](mailto:support@protonos.org) with "Security" in the subject.

Please include:

- what an attacker can do, and what they need first (a local account? physical access? a crafted file?);
- the steps to reproduce it, and the Proton Security version (`proton-security --version`);
- your distribution and desktop.

What happens next:

- We confirm we received the report within **3 working days**.
- We tell you whether we can reproduce it, and our plan, within **10 working days**.
- We fix confirmed issues as fast as we can and publish a release with a security advisory. We credit you in the
  advisory unless you prefer not to be named.
- Please give us a reasonable time to release a fix before you publish details (normally up to 90 days).

## Supported versions

Security fixes go into the **latest release**. Proton OS updates the package automatically, so please upgrade
before reporting.

## What counts

The most important part to review is the code that runs as root:
[`packaging/proton-security-helper`](packaging/proton-security-helper) and its polkit policy. For example:

- running a command as root that the helper doesn't list, or with arguments it should have refused;
- making root write, delete or change ownership of a file the user shouldn't control;
- leaking a disk password or recovery key (into a log, a world-readable file, the process list);
- the app or the tray doing something as root without an administrator authenticating.

Also in scope: a file or device (a download, a USB drive, a malicious file name) that makes the app crash, hang,
or run something; and wrong security advice (a tile showing green when the computer is not protected).

Out of scope: things an administrator can already do with `sudo`; missing real-time antivirus protection (ClamAV
here scans on demand); problems in ClamAV, UFW, Snapper or other tools themselves (please report those to their
projects).

The design is described in [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).
