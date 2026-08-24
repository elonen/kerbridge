# The Debian deployment

One of the two ways to bring up the KerBridge server in
[step 4 (*Stand up the broker host*) in SETUP.md](../../SETUP.md#4-stand-up-the-broker-host).
The other is [`compose-deployment.md`](compose-deployment.md).

The server runs from `.deb` packages under systemd, on the distro's own
`samba-ad-dc`. Everything on this page is those packages. What is true whichever
method you chose — enabling synchronization, operator notification, backup — is
in [`broker-host.md`](broker-host.md).

On this page, **`<secrets-dir>` is `/etc/kerbridge.secrets/`**.

## Where it installs

The binaries are static musl with no shared-library dependency, so one build
installs on every release that has the same architecture. The architecture is
not free. `make debian-docker` builds for the architecture of the build host:
an `arm64` workstation makes `*_arm64.deb` packages, and an `amd64` server
refuses them. Build on the architecture the server runs, or emulate it. What
differs between releases is only how much has been exercised:

| Release | Samba | Promise |
|---|---|---|
| Debian 13 *trixie* | 4.22 | The reference. Built, installed, run, and the stack test passes. |
| Ubuntu 24.04 *noble* | 4.19 | [Installable and untested](../../GLOSSARY.md#installable-and-untested). |

**Debian 12 *bookworm* and Ubuntu 22.04 *jammy* are not supported**, and the
floor is the Samba they ship rather than a policy about age. KerBridge stores
every external identity in `msDS-ExternalDirectoryObjectId`, an attribute that is
stock only from the Windows Server 2016 schema. Samba offers that schema to
`samba-tool domain provision` from 4.19; bookworm's 4.17 and jammy's 4.15 ship
the definitions under `/usr/share/samba/setup/ad-schema/` and will not lay them
down — `--base-schema` there stops at `2012_R2`, and `samba-tool domain
schemaupgrade` stops at the same place, so there is no second route. `kbsetup
realm` refuses on such a host before it writes anything.

`kerbridge-issuerd` says so in its dependencies as well: `samba-ad-dc (>=
2:4.19)`, so on an older release apt refuses the package rather than installing
a domain controller that cannot become one. That refusal is the only thing
either release is tested for, and it is the only thing offered — including for
`kbmanage` on an administrator's own machine, which belongs on a supported
release like everything else.

## The packages

Install them from the apt repository, or from the `.deb` files themselves.

### From the apt repository

The packages are served as assets on a release tagged `apt`, and the index over
them is signed. Add the key and the source once:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL -o /etc/apt/keyrings/kerbridge.asc \
  https://github.com/elonen/kerbridge/releases/download/apt/kerbridge-archive-keyring.asc
sudo tee /etc/apt/sources.list.d/kerbridge.sources > /dev/null <<'EOF'
Types: deb
URIs: https://github.com/elonen/kerbridge/releases/download/apt/
Suites: ./
Signed-By: /etc/apt/keyrings/kerbridge.asc
EOF
sudo apt update
sudo apt install --no-install-recommends kerbridge
```

`--no-install-recommends` matters here: `krb5-user` Recommends `krb5-config`, and
krb5-config asks its own "Default Kerberos version 5 realm" debconf question --
worded independently of, and asked right after, kerbridge-config's own realm
question above. Nothing reads its answer: KDC location lives in
`/etc/krb5.conf.d/kerbridge.conf`, which `kbsetup realm` writes, and
`kerbridge-issuerd` creates a bare `/etc/krb5.conf` itself when krb5-config never
ran (`crates/kerbridge-setup/src/krb5.rs`, `debian/kerbridge-issuerd.postinst`).

`Suites: ./` is not a placeholder to fill in. This is a flat repository — the
indices sit at the base URI with no `dists/` tree, because a release's assets
are one flat namespace — and `./` is how a flat repository is named.

Check the key before you trust it. Its fingerprint is in
[`SECURITY.md`](../../SECURITY.md#13-dependencies-and-artifacts), and an
operator who reaches this page over the same compromised network that served
the key gains nothing by comparing the two — read it from somewhere else:

```sh
gpg --show-keys --with-fingerprint /etc/apt/keyrings/kerbridge.asc
```

Updates are `apt upgrade` from then on.

### From the files

`make debian-docker` builds them all into `dist/debian/`. The package version
comes from `git describe` inside the image, so a tree with no tag reachable from
HEAD needs `make debian-docker KB_VERSION=0.10.0` instead. The build stops and
says so rather than guess a version. Install them with `apt` rather than
`dpkg -i`, so the distro dependencies — Samba above all — are resolved for you:

```sh
sudo apt install --no-install-recommends ./kerbridge*.deb
```

Nothing verifies these. They carry no signature of their own — only the
repository index is signed — so a file you did not build yourself is worth the
`SHA256SUMS` check the release page ships.

| Package | What it is | Where it goes |
|---|---|---|
| `kerbridge-config` | `kbconfig`, and the deployment's shared state: it owns `/etc/kerbridge` and `/etc/kerbridge.secrets`, creates the `_kerbridge` group, and asks the install-time questions. | every host |
| `kerbridge-issuerd` | `issuerd` and `kbsetup`. Pulls in Samba. | the domain controller |
| `kerbridge-broker` | `kerbridge-broker`, the only component a workstation talks to. | the domain controller |
| `kerbridge-sync` | `kerbridge-sync`, the directory mirror. | the domain controller |
| `kerbridge-manage` | `kbmanage`. Creates no account and needs no daemon. | the DC, or an administrator's own machine |
| `kerbridge` | Metapackage: the packages above. Ships no files. | the domain controller |

The broker cannot be moved to a host of its own. It reaches the issuer over a
unix socket, and `SO_PEERCRED` is the whole of the authentication between them —
there is no network transport to configure. `kerbridge-manage` is the one part
that installs alone, on an administrator's machine, with only `kerbridge-config`
beside it; [`rsat-and-kerbridge-management.md`](../rsat-and-kerbridge-management.md)
has that case.

These unix identities are created and are **never removed**, not even by purge:
the `_kerbridge` group, and the `_kerbridge-broker` and `_kerbridge-sync` system
users. A uid that a later `adduser` reallocated would inherit whatever files
elsewhere still carry it.

Purge keeps more than the identities, and it does so on purpose. Purge removes
the configuration set. It does not remove `<secrets-dir>`, an audit log under
`/var/log/kerbridge/`, or any file under `/etc/samba` or `/var/lib/samba`. If
you purge every package, the domain controller still runs, and the Entra
client secret and the realm Administrator password stay on the disk. **A purge
is not a decommission.** To decommission a host, erase `<secrets-dir>` as well.

## The install questions

`kerbridge-config` asks them, before anything is unpacked, and no other package
asks anything. The answers are used **on first install only**, to write a config
set that is not there yet: no package ever edits a configuration file you
already have.

| Question | Answer |
|---|---|
| Kerberos realm for this deployment | Upper case, e.g. `EXAMPLE.SITE`. Further values are derived from it. |
| LDAPS URL of the domain controller | `ldaps://` only. Proposed as `ldaps://kerbridge.<realm lowercased>:636`; the DC's short name is this URL's first label. |
| Cloud IdP tenant id | The Entra tenant, as a UUID. **Leave empty** for a host that runs no sync and serves no sign-ins — the questions below are then not asked. |
| Application id of the broker API registration | From [step 2](../../SETUP.md#2-register-three-applications-in-entra). |
| Application id of the workstation client registration | From step 2. |
| Application id of the synchronisation registration | From step 2. |
| Name of the cloud group whose members are admitted | Defaults to `KerBridge Allowed On-prem Users`. Nothing works until a group by that name exists in the tenant. |

Nothing secret passes through debconf, and that is structural rather than
careful: every secret in the config set is a *path*, never a value, and these
answers are a realm, a URL, public OIDC identifiers and a group name.

These outcomes are all legal:

- **Realm left empty** — nothing is written at all, and the postinst says so.
  This is the right outcome for an unattended install with no answers to give:
  under `DEBIAN_FRONTEND=noninteractive` the questions are skipped and those
  without a default stay empty, so no set naming a realm nobody chose is
  created.
- **Realm set, tenant left empty** — a realm-only set, `sources = []`. This is
  the administrator's machine that runs `kbmanage` and no daemon.
- **Both set** — the complete set, in `/etc/kerbridge`.

`dpkg-reconfigure kerbridge-config` asks them all again, showing what the files
say rather than what you answered last time, and then writes nothing. To change
a live deployment, edit the files — see
[config-management.md](config-management.md).

With **no config set written**, the units are skipped rather than started:
each carries `ConditionPathExists=/etc/kerbridge/main.toml`, so `systemctl
status` shows them inactive with the unmet condition named, and nothing appears
in `systemctl --failed`. Write the set with `kbconfig init /etc/kerbridge` or
`dpkg-reconfigure kerbridge-config`, then start them:

```sh
sudo systemctl start kerbridge-issuerd kerbridge-broker kerbridge-sync
```

They start on their own at the next boot, and after an install that *did* get a
realm — dpkg starts them, and the condition holds.

## Provision the realm

Everything so far installed files. This is the step that creates a domain, and
it is an operator's to run, with a terminal, as root on the DC:

```sh
sudo kbsetup realm        # provisions the domain, the LDAPS CA and certificate
sudo kbsetup directory    # the OUs, the service accounts and their delegation
```

Both are idempotent, and `kbsetup realm` refuses to run twice over a realm that
exists. It also refuses, before writing anything, on a Samba too old to lay down
the Server 2016 schema — see *Where it installs* above.

What `kbsetup realm` decides is baked into the Samba database with the domain
SID: correcting it later means provisioning again, and every filesystem ACL that
carries the old SID stops resolving.

Know these things before you run it:

- **`/etc/samba/smb.conf`.** Any existing file is moved aside to
  `/etc/samba/smb.conf.kerbridge-orig` and a new one written. The file stays
  registered with `samba-common`'s `ucf`, so a later Samba upgrade may prompt
  about it — the answer is *keep the currently-installed version*.
- **systemd-resolved is refused, never reconfigured.** Its stub listener holds
  `127.0.0.53:53` and collides with Samba's internal DNS. `kbsetup realm` stops
  with a message rather than changing your resolver for you.
- **An unprivileged container cannot hold the realm.** Samba's own idmap gives
  gid 3000000 to `BUILTIN\Administrators`, and no `smb.conf` setting changes
  that number. Provisioning sets the group of the sysvol tree to that gid. An
  unprivileged container has only part of the host's id space — usually 65536
  ids — so it cannot use gid 3000000. The change of group fails, and Samba 4.22
  reports the failure as a panic rather than as an error. `kbsetup realm` reads
  `/proc/self/gid_map` and gives the cause. Use a privileged container or a
  virtual machine. The configuration set has no effect on this.
- **A run that stops partway leaves no realm, and says so next time.**
  `samba-tool domain provision` leaves a database behind when it exits, so a
  finished run stamps `/var/lib/samba/private/kerbridge-provisioned`. Without
  that file beside `sam.ldb`, `kbsetup` refuses the realm rather than verifying
  it, and the way out is to destroy the Samba state and provision again.
  **A domain controller you built yourself has no stamp either**, and there
  nothing is wrong: once you are sure it serves the realm your config set names,
  `touch` that path to adopt it. `kbsetup` cannot tell the two apart, so it
  states both and lets you choose.
- **The generated Administrator password** lands at
  `<secrets-dir>/generated/realm_admin_password`, `0600 root:root`. It is
  break-glass — provisioning, `net ads join -U administrator` on a member
  server, and RSAT as Administrator. It is not `kbmanage`'s credential.

`kbsetup realm` finishes by printing the ports the DC now listens on. No package
touches your firewall; `ufw` and `nftables` starting points are at
`/usr/share/doc/kerbridge-issuerd/examples/`, and
[dns-and-firewall.md](dns-and-firewall.md) is the table they came from.

> **CAUTION: a package-installed Samba binds every service on every interface.**
> `bind interfaces only` is per-*interface*, not per-port, so the per-port bind
> addresses a Docker Compose deployment publishes do not survive here. LDAPS on
> `636` is loopback-only there and network-reachable here. That is safe — the
> SAN certificate covers the FQDN — but it is your firewall's job, not Samba's.

### The Kerberos drop-in

The KDC has to be named explicitly. Samba's own generated `krb5.conf` carries no
`kdc =` line and leaves KDC location to DNS SRV, which works in a container only
because the container's resolver is Samba's own DNS; a DC installed from
packages generally does not point its resolver at itself.

So `kerbridge-issuerd`'s postinst makes sure `/etc/krb5.conf` has the line
`includedir /etc/krb5.conf.d/` — creating the file and the directory if the host
has neither, appending the line under a marker comment if it has a `krb5.conf`
already — and `kbsetup realm` writes `/etc/krb5.conf.d/kerbridge.conf` from the
config set. `kbsetup verify` checks the pair at every issuer start. Purge takes
the drop-in and the marked line back out, in that order.

> **CAUTION:** never leave an `includedir` pointing at a directory that does not
> exist. It is fatal for **every** krb5 program on the host, not only
> KerBridge's — an empty directory is fine, a missing one breaks `kinit` for
> everybody.

## Terminate TLS in front of the broker

The broker serves plain HTTP on `127.0.0.1:8080` and **refuses any listen
address that is not on the loopback interface**. That is enforced in the
program, so TLS terminates on this same host: a terminator on another machine is
not a configuration you can write.

The certificate is yours to obtain and renew — see
[TLS strategy (`names-and-decisions.md`)](names-and-decisions.md#tls-strategy)
for the validity limit it has to respect. Tested starting points for both common
terminators ship with the package:

```
/usr/share/doc/kerbridge-broker/examples/kerbridge.caddyfile
/usr/share/doc/kerbridge-broker/examples/kerbridge-nginx.conf
```

Each proxies only the documented routes to `127.0.0.1:8080` and 404s everything
else at the edge, caps the request body at 16 KB, and logs no bodies — a ticket
response carries a credential cache and a request carries a bearer token.

## The units

```
kerbridge-issuerd.service    root, on the DC: holds KDC authority, reads sam.ldb
kerbridge-broker.service     _kerbridge-broker, the client-facing API
kerbridge-sync.service       _kerbridge-sync, the directory mirror
```

dpkg enables and starts them. Each runs `kbconfig check` at `ExecStartPre`, and
the issuer runs `kbsetup verify` as well, so a config set that does not check out
stops the bridge — and never the domain controller.

A stopped bridge is a **failed** unit, not a restart loop. Each unit pairs
`StartLimitIntervalSec=60` with `StartLimitBurst=5`, so five attempts at
`RestartSec=5s` take about 25 seconds and then systemd gives up and says
`Start request repeated too quickly`. Read the reason with `journalctl -u
kerbridge-issuerd -n 30`, fix it, then:

```sh
sudo systemctl reset-failed kerbridge-issuerd
sudo systemctl start kerbridge-issuerd
```

> **`reset-failed` is not optional here.** Within the 60-second window a plain
> `systemctl start` is refused without even running `ExecStartPre=`, and each
> refusal pushes the window out another minute — so retrying in a loop looks
> exactly like a unit that is permanently stuck. Either clear the counter as
> above, or leave the unit alone for a full minute and then start it. Measured
> on systemd 252 and 257 alike.

Installing before you provision is expected, and the issuer costs you nothing
for it: `kbsetup verify` answers *nothing is provisioned yet* as a warning
rather than a mismatch, so `kerbridge-issuerd` runs idle from install onwards
and simply starts working when `kbsetup realm` gives it a realm. Measured on
trixie across the whole sequence — install, configure, `kbsetup realm`,
`kbsetup directory` — it never restarted once. A provisioning run that *stopped
partway* is the other side of that line: `kbsetup verify` exits 2 and names the
state, so the issuer is `failed` rather than idle.

**`kerbridge-broker` is the one that will be `failed` while you work**, and it
is not a fault: its LDAP bind password does not exist until `kbsetup directory`
writes it, so until then it exits with `reading secret …/svc_kerbridge_broker_password`
and latches. Bring it up when the directory is bootstrapped:

```sh
sudo systemctl reset-failed kerbridge-broker
sudo systemctl start kerbridge-broker
```

```sh
systemctl status kerbridge-issuerd kerbridge-broker kerbridge-sync
journalctl -u kerbridge-sync -f
```

Each daemon keeps its own audit record under `/var/log/kerbridge/<daemon>/`,
one directory per daemon so that no daemon can rewrite another's. Logrotate
rotates them weekly, twelve deep. The daemons connect lazily — the broker
opens the issuer socket per request, sync per cycle — so a DC restart or a cold
boot needs nothing from you.

## Check it

```sh
kbmanage doctor
kbmanage doctor --endpoint https://kerbridge.example.site
```

`doctor` walks the chain and names the first broken link: which config set it
read, whether the DC name from `ldap_url` resolves on this host, whether the port
answers, whether the realm CA at `/etc/kerbridge/certs/realm-ca.pem` matches what
the DC now presents, and whether the bind succeeds. `--endpoint` adds the public
URL a client would enroll against. It exits non-zero on any failed link.

`kbmanage endpoint <url>` is the endpoint check on its own: it reads no config
set and binds nothing, prints one line, and exits `0` served, `2` still
settling, `3` the port is open and no TLS session came of it, `1` answering
wrongly.

Then continue with
[Enable synchronization (`broker-host.md`)](broker-host.md#enable-synchronization).
