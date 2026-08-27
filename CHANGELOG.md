# Changelog

This file tells the operator what changed. Write one line for each change.

The program `debian/make-changelog` reads this file. It finds the section for
the version of the build. Then it writes that section to `debian/changelog`.
These rules apply:

- Write a version heading as `## <version>`. Use the git tag, but do not write
  the `v`.
- Start each line of a section with `-`. Do not write a `###` heading, because
  the program copies it to `debian/changelog` without a change.
- Write new lines in the `## Unreleased` section. When you make the tag, change
  that heading to the version.
- Keep each line shorter than 79 characters. The program adds two characters to
  each line, and lintian refuses a line longer than 80 characters.

Some changes need work from the operator. Write those changes in
`debian/kerbridge-config.NEWS.in__disabled` also, and rename the file to
remove `__disabled`. The package manager shows it during the upgrade. Disable
it again once a release needs no work from the operator: the file takes the
version of the build, so a note left in it is shown a second time.

A push of a `v*` tag starts the release. The release reads the section that
names the tag, and it stops if that section is absent or empty.

## Unreleased

- Config `sync.toml`: `cycle_deadline_seconds` and `read_deadline_seconds`
  are removed. A read from the cloud IdP runs until the directory has been
  read out, so there is no allowance to set. A read that stops making
  progress is abandoned on its own. Run `kbconfig upgrade` to remove the
  option, or edit the file.

## 0.9.2

- Intune config and installation automation for Windows agent (Group Policy
  template, `KerBridge.admx`, installer packaging).
- New `kbmanage problems` lists what is wrong now. It reads the problem
  files, so it needs no webhook and no network.
- `kbmanage doctor` fixes.
- Notification, `kbmanage cloud list` and `kbmanage group list` read more
  easily.

## 0.9.1

- Hardening: static-PIE binaries on arm64, a `.dep-v0` dependency
  list the scanners can read, and `ring` in place of the hand-written ASN.1.
  Each build runs the binary it linked, so one that cannot start fails.
- New `kbsetup status` says what is done and what is left.
- New `kbsetup secrets` asks for the credentials nothing can generate and
  writes each at the mode its reader needs.
- `kbsetup realm` now needs `samba-ad-provision`, checks for the templates
  before it writes, restores your own `smb.conf` if the provision fails, and
  disables `winbind`, `smbd` and `nmbd` on the domain controller.
- `kbsetup` no longer stops at a password prompt when it has a terminal.
- The release page attaches fewer files: one zip for each architecture's
  `.deb` packages, one zip for the standalone `kbmanage` and `kbconfig`
  binaries, and a client download named for its platform and architecture.
- CI and release improvements.
- Documentation improvements.

## 0.9.0

- Debian packages install from a signed apt repository.
- Installs from six Debian packages, as an alternative to Docker Compose.
- Domain controller: Debian 13 or Ubuntu 24.04 onwards. Older ones refused.
- The realm needs a privileged container or a virtual machine: Samba
  provisions with gid 3000000, which an unprivileged container cannot use.
- Audit logs moved to `/var/log/kerbridge/`, state to `/var/lib/kerbridge/`.
- Secrets moved to `/etc/kerbridge.secrets/`.
- New `kbsetup` provisions the realm and bootstraps the directory.
- `kbconfig template` is now `kbconfig init`, with your answers in it.
- A lowercase realm is refused, by `kbconfig check` and at startup.
- Default Entra groups renamed: `KerBridge Allowed On-prem Users` and
  `KerBridge Device Grants`.
- The daemons reopen their logs on `SIGUSR1`, so logrotate can rotate them.
- `/usr/local` left the root subprocess PATH: the packaged `samba-tool` wins.
- Compose `.env` holds only interpolated values; bench keys in `bench.env`.
- Compose images install the shipped .deb files. Build them with `make`.
- A provision that stopped partway is refused, not read as a realm.
- New `SECURITY.md`: the risks, the limits, and the worst case.
