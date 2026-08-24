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
`debian/kerbridge-config.NEWS.in` also. The package manager shows that file
during an upgrade.

A push of a `v*` tag starts the release. The release reads the section that
names the tag, and it stops if that section is absent or empty.

## 0.9.1

- `kbsetup` no longer stops at a password prompt when it has a terminal.
- The release page ships the MSI only. It holds both Windows programs.
- The release page ships the macOS agent: arm64, ad-hoc signed.
- CI builds and tests the macOS agent on each change.
- The device-grant group example is now `KerBridge Device Grant Users`.
- `kbsetup realm` disables `winbind`, `smbd` and `nmbd`. A domain controller
  runs both daemons itself, and the standalone units stopped it from starting.
- The deployment guide says to point the DC's resolver at the DC itself.

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
