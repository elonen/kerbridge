# The Debian deployment

One of the two ways to bring up the KerBridge server in
[step 4 (*Stand up the broker host*) in SETUP.md](../../SETUP.md#4-stand-up-the-broker-host).
The other is [`compose-deployment.md`](compose-deployment.md).

The server runs from `.deb` packages under systemd, on the distribution's own
`samba-ad-dc`. What is true whichever method you chose — synchronization,
operator notification and backup — is in
[`broker-host.md`](broker-host.md).

On this page, **`<secrets-dir>` is `/etc/kerbridge.secrets/`**.

## Where it installs

| Release | Samba | Promise |
|---|---|---|
| Debian 13 *trixie* | 4.22 | The reference. Built, installed, run, and the stack test passes. |
| Ubuntu 24.04 *noble* | 4.19 | Installable and untested<sup>[?](../../GLOSSARY.md#installable-and-untested)</sup>. |

>  **Debian 12 *bookworm* and Ubuntu 22.04 *jammy* are not supported.** 
> Their Samba is too old to lay down the schema that KerBridge needs.

<details>
<summary>Why Samba 4.19 is the minimum</summary>

The floor is the Samba that a release ships, not a policy about age. KerBridge
stores every external identity in `msDS-ExternalDirectoryObjectId`, an
attribute that is stock only from the Windows Server 2016 schema. Samba offers
that schema to `samba-tool domain provision` from 4.19.

Bookworm's 4.17 and jammy's 4.15 ship the definitions under
`/usr/share/samba/setup/ad-schema/` and will not lay them down: `--base-schema`
there stops at `2012_R2`, and `samba-tool domain schemaupgrade` stops at the
same place. There is no second route.

That refusal is the only thing that either release is tested for, and it is the
only thing offered — `kbmanage` on an administrator's own machine included.

</details>

## The packages

Install them from the apt repository, or from the `.deb` files.

### Option 1: From the apt repository

The packages are served as assets on a release tagged `apt`, and the index over
them is signed. Add the key and the source one time:

```sh
sudo curl -fsSL -o /etc/apt/keyrings/kerbridge.asc \
  https://github.com/elonen/kerbridge/releases/download/apt/kerbridge-archive-keyring.asc

# Add apt source file
sudo tee /etc/apt/sources.list.d/kerbridge.sources > /dev/null <<'EOF'
Types: deb
URIs: https://github.com/elonen/kerbridge/releases/download/apt/
Suites: ./
Signed-By: /etc/apt/keyrings/kerbridge.asc
EOF

sudo apt update
sudo apt install --no-install-recommends kerbridge
```

The current apt repository signing key fingerprint is `F434 FD6F 31F2 D93C 0ABB  6FDA 49A7 BBC9 D472 9807`.
You can view your installed one by:

```sh
gpg --show-keys --with-fingerprint /etc/apt/keyrings/kerbridge.asc
```

<details>
<summary>Two things in those commands that might look wrong</summary>

**`--no-install-recommends` matters here.** `krb5-user` recommends
`krb5-config`, and `krb5-config` asks its own "Default Kerberos version 5
realm" debconf question. That question is worded independently of
`kerbridge-config`'s own realm question, and it is asked directly after it.
Nothing reads its answer: the KDC location lives in
`/etc/krb5.conf.d/kerbridge.conf`, which `kbsetup realm` writes, and
`kerbridge-issuerd` creates a bare `/etc/krb5.conf` itself when `krb5-config`
never ran.

**`Suites: ./` is not a placeholder to fill in.** This is a flat repository:
the indices sit at the base URI with no `dists/` tree, because a release's
assets are one flat namespace. `./` is how a flat repository is named.

</details>

### Option 2: From the files

Skip this if you installed via apt repository.

Each release attaches `kerbridge-server-deb-packages_<version>_amd64.zip` and
the `arm64` one. A zip holds every package for that architecture, so one
download is a complete set. `make debian-docker` builds the same files into
`dist/debian/`.

Install them with `apt` rather than `dpkg -i`, so that the distribution
dependencies — Samba above all — are resolved for you:

```sh
unzip kerbridge-server-deb-packages_*.zip
sudo apt install --no-install-recommends ./kerbridge*.deb
```

The package version comes from `git describe` inside the image, so a tree with
no tag reachable from HEAD needs `make debian-docker KB_VERSION=0.10.0`
instead. The build stops and says so rather than guess a version.

Nothing verifies these files. They carry no signature of their own — the
repository index is the only signed part — so check a zip that you did not
build yourself against the `SHA256SUMS` on the release page, before you
unpack it.

| Package | What it is | Where it goes |
|---|---|---|
| `kerbridge-config` | `kbconfig`, and the deployment's shared state: it owns `/etc/kerbridge` and `/etc/kerbridge.secrets`, it creates the `_kerbridge` group, and it asks the install-time questions. | every host |
| `kerbridge-issuerd` | `issuerd` and `kbsetup`. Pulls in Samba. | the domain controller |
| `kerbridge-broker` | `kerbridge-broker`, the only component that a workstation talks to. | the domain controller |
| `kerbridge-sync` | `kerbridge-sync`, the directory mirror. | the domain controller |
| `kerbridge-manage` | `kbmanage`. Creates no account and needs no daemon. | the DC, or an administrator's own machine |
| `kerbridge` | Metapackage: the packages above. Ships no files. | the domain controller |

You cannot move the broker to a host of its own. It reaches the issuer over a
unix socket, and `SO_PEERCRED` is the whole of the authentication between them.
There is no network transport to configure. `kerbridge-manage` is the one part
that installs alone, on an administrator's machine, with `kerbridge-config`
beside it —
[`rsat-and-kerbridge-management.md`](../rsat-and-kerbridge-management.md).

> **CAUTION: A purge is not a decommission.** Purge removes the config set. It
> does not remove `<secrets-dir>`, an audit log under `/var/log/kerbridge/`, or
> any file under `/etc/samba` or `/var/lib/samba`. So a purged host still runs
> the domain controller, and it still holds the Entra client secret and the
> realm Administrator password on disk. To decommission a host, erase
> `<secrets-dir>` as well.

Three unix identities are created and are **never removed**, not even by purge:
the `_kerbridge` group, and the `_kerbridge-broker` and `_kerbridge-sync`
system users. A uid that a later `adduser` reallocated would inherit whatever
files elsewhere still carry it.

## The install questions

`kerbridge-config` asks them, before anything is unpacked, and no other package
asks anything. The answers are used **on first install only**, to write a
config set that is not there yet. No package edits a configuration file that
you already have.

| Question | Answer |
|---|---|
| Kerberos realm for this deployment | Upper case, for example `EXAMPLE.SITE`. Further values are derived from it. |
| LDAPS URL of the domain controller | `ldaps://` only. Proposed as `ldaps://kerbridge.<realm lowercased>:636`. The DC's short name is this URL's first label. |
| Cloud IdP tenant id | The Entra tenant, as a UUID. **Leave it empty** for a host that runs no sync and serves no sign-ins. The questions below are then not asked. |
| UUID of the broker's Entra app, usually named "KerBridge broker API" | From [step 2](../../SETUP.md#2-register-three-applications-in-entra). |
| UUID of the client's Entra app, usually named "KerBridge public client" | From step 2. |
| UUID of the sync Entra app, usually named "KerBridge sync" | From step 2. |
| Name of the cloud group whose members are admitted | Defaults to `KerBridge Allowed On-prem Users`. Nothing works until a group with that name exists in the tenant. |

Nothing secret passes through debconf. That is structural rather than careful:
every secret in the config set is a *path*, never a value, and these answers
are a realm, a URL, public OIDC identifiers and a group name.

<details>
<summary>If you want to skip the questions</summary>

Three outcomes of debhelper questions are all valid:

- **Realm left empty** — nothing is written, and the postinst says so. Unattended installs
  could need this.
- **Realm set, tenant left empty** — a realm-only set, `sources = []`. This could be
  an administrator machine that has `kbmanage` but and no daemons.
- **Both are set** — the complete set, in `/etc/kerbridge`. Usual case.

With **no config set written**, the units are skipped rather than started. Each
carries `ConditionPathExists=/etc/kerbridge/main.toml`, so `systemctl status`
shows them inactive with the unmet condition named, and nothing appears in
`systemctl --failed`. Write the set with `kbconfig init /etc/kerbridge` or
`dpkg-reconfigure kerbridge-config`, then start them:

```sh
sudo systemctl start kerbridge-issuerd kerbridge-broker kerbridge-sync
```

They start on their own at the next boot, and after an install that *did* get a
realm.

</details>

> **CAUTION: Running `dpkg-reconfigure` later won't help**.
> If you try `dpkg-reconfigure kerbridge-config` after the first install, it shows what
> the files say rather than what you answered last time, and then it writes
> nothing. To change a live deployment, edit the files directly  —
> [config-management.md](config-management.md).

## Ask the host what is left

Everything so far installed files. Three steps remain, and none of them is
something a package may do for you. You do not have to keep them in your head:

```sh
sudo kbsetup status
```

It reads the state on this host, marks each step done or outstanding, and prints
the command for the next one. It writes nothing, asks nothing and opens no
connection, so it is safe at any point — run it again after each step. It exits
`0` when every step it can answer is done, `2` while any remains.

The `kerbridge-issuerd` postinst runs it as the last thing an installation says,
so the list is already on your screen. `/usr/share/doc/kerbridge-config/README.Debian`
is the same ground in prose.

Some steps are never answered from this host, and it says so rather than
guessing: the TLS terminator is a program KerBridge does not ship, and a unit's
state is a sentence in its own journal.

## Provision the realm

This step creates a domain in Samba. You run it, in a terminal, as root on the
realm server:

```sh
sudo kbsetup realm        # provisions the domain to Samba, the LDAPS CA and certificate
sudo kbsetup directory    # the OUs, the service accounts and their delegation
```

Running these again won't ruin your setup, and `kbsetup realm` refuses to run twice over a realm that exists.

What `kbsetup realm` decides is baked into the Samba database with the domain
SID. To correct it later means to provision Samba again, and every filesystem ACL
that carries the old SID stops resolving.

Know these things before you run it:

- **`/etc/samba/smb.conf`.** An existing file is moved aside to
  `/etc/samba/smb.conf.kerbridge-orig`, and a new one is written. The file
  stays registered with `samba-common`'s `ucf`, so a later Samba upgrade may
  prompt about it. Answer *keep the currently-installed version*. A provision
  that fails puts your file back, so the command can be run again; one that is
  killed leaves both files, and then `kbsetup realm` asks you which to keep.
- **systemd-resolved is refused, never reconfigured.** Its stub listener holds
  `127.0.0.53:53` and collides with Samba's internal DNS. `kbsetup realm` stops
  with a message rather than change your resolver for you.
- **`winbind`, `smbd` and `nmbd` are disabled, and say so.** A domain controller
  runs both daemons itself, as children of `samba`. The standalone units come
  from the KerBridge packages' own dependencies and start at install time, while
  this host is not a DC yet. Left running, they hold the socket and the port the
  DC's own children need, and `samba-ad-dc` dies at every start.
- **Point this host's resolver at itself.** The DC serves its own zone, and
  `samba_dnsupdate` verifies each record through `/etc/resolv.conf` before it
  writes. A resolver that names the forwarder instead confirms nothing —
  [dns-and-firewall.md](dns-and-firewall.md#the-dcs-own-resolver).
- **The generated Administrator password** lands in
  `<secrets-dir>/generated/realm_admin_password`, `0600 root:root`. It is
  break-glass: provisioning, `net ads join -U administrator` on a member
  server, and RSAT as Administrator. It is not `kbmanage`'s credential.

> **CAUTION: An unprivileged LXC container cannot hold the realm.** Samba's own
> idmap gives gid 3000000 to `BUILTIN\Administrators`, and no `smb.conf`
> setting changes that number. Provisioning sets the group of the sysvol tree
> to that gid. An unprivileged container has part of the host's id space only,
> usually 65536 ids, so it cannot use gid 3000000. The change of group fails,
> and Samba 4.22 reports the failure as a panic rather than as an error.
> `kbsetup realm` reads `/proc/self/gid_map` and gives the cause. Use a
> privileged container or a virtual machine. The config set has no effect on
> this.

> **CAUTION: A package-installed Samba binds every service on every
> interface. Mind your firewall.** `bind interfaces only` is per-*interface*, not per-port, so the
> per-port bind addresses that a Docker Compose deployment publishes do not
> survive here. LDAPS on `636` is loopback-only there and network-reachable
> here. That is safe, because the SAN certificate covers the FQDN. But it is
> your firewall's job, not Samba's —
> [dns-and-firewall.md](dns-and-firewall.md#firewall).

`kbsetup realm` finishes by printing the ports that the DC now listens on. No
package touches your firewall. `ufw` and `nftables` starting points are at
`/usr/share/doc/kerbridge-issuerd/examples/`.

<details>
<summary>A run that stops partway leaves no realm, and says so next time</summary>
`samba-tool domain provision` leaves a database behind when it exits, so a
finished run stamps `/var/lib/samba/private/kerbridge-provisioned`. Without
that file beside `sam.ldb`, `kbsetup` refuses the realm rather than verify it,
and the way out is to destroy the Samba state and provision again.

**A domain controller that you built yourself has no stamp either**, and there
nothing is wrong. When you are sure that it serves the realm your config set
names, `touch` that path to adopt it. `kbsetup` cannot tell the two apart, so
it states both and lets you choose.

</details>

<details>
<summary>The krb5.conf configuration drop-in</summary>

The KDC must be named explicitly. Samba's own generated `krb5.conf` carries no
`kdc =` line and leaves KDC location to DNS SRV. That works in a container only
because the container's resolver is Samba's own DNS, and a DC installed from
packages generally does not point its resolver at itself.

So `kerbridge-issuerd`'s postinst makes sure that `/etc/krb5.conf` starts with
the line `includedir /etc/krb5.conf.d/`. It creates the file and the directory
if the host has neither, and it puts the line under a marker comment at the top
if the host has a `krb5.conf` already. The top is not cosmetic: MIT reads the
first value it finds, so a line further down would let `krb5-config`'s
`default_realm` — `ATHENA.MIT.EDU` on an install that answered no questions —
beat the realm you configured. `kbsetup realm` then writes
`/etc/krb5.conf.d/kerbridge.conf` from the config set, and `kbsetup verify`
checks the pair at every issuer start. Purge takes the drop-in and the marked
line back out, in that order.

> **CAUTION: Never leave an `includedir` that points at a directory which does
> not exist.** It is fatal for **every** krb5 program on the host, not only
> KerBridge's. An empty directory is fine. A missing one breaks `kinit` for
> everybody.

</details>

## Supply the credentials only you have

Every secret in the config set is named as a *path*, never written as a value.
`kbsetup realm` and `kbsetup directory` filled the generated half under
`<secrets-dir>/generated/`. The other half comes from your cloud IdP's portal,
and nothing in the deployment can produce it:

```sh
sudo kbsetup secrets
```

One prompt per credential the config set names and this host does not have yet.
The value is typed with the terminal echo off, checked, and written straight to
its file at `0640 root:_kerbridge` — the mode the daemon that reads it needs.
`0640` and not `0600`: sync runs unprivileged and reaches its own credential
through the group, so the stricter mode is a daemon that cannot start.

A credential already in place is left alone and reported, so a re-run only fills
what is still missing. `--replace` asks about the ones that are there as well,
and confirms before it overwrites each.

**Nothing secret goes through the installation questions, and that is
structural.** A value that passes through debconf is written to
`/var/cache/debconf/config.dat` and again to `config.dat-old`, which is
world-readable — so the questions ask for a realm, a URL, public application
identifiers and a group name, and this command collects the rest.
It reaches no argument list, no environment variable and no shell history
either.

For Entra the one credential is the sync app registration's client secret.
`kbsetup secrets` refuses a value that is GUID-shaped and says why: that is the
*Secret ID*, which stays readable in the portal after the *Value* beside it has
been masked, and it is the one usually copied by mistake.

<details>
<summary>Writing the files yourself, from a configuration-management run</summary>

With no terminal to ask at, `kbsetup secrets` refuses rather than reading a
credential from anywhere a passer-by could see it, and prints the file, the
owner and the mode for each one instead:

```sh
sudo install -o root -g _kerbridge -m 0640 /dev/null \
  /etc/kerbridge.secrets/idp/entra/credential
```

Then write the bare value into it, with no trailing newline. Sync finds it on
its next cycle and needs no restart.

</details>

## Terminate TLS in front of the broker

The broker serves plain HTTP on `127.0.0.1:8080`, and it **refuses any listen
address that is not on the loopback interface**. That is enforced in the
program, so TLS terminates on this same host. A terminator
on another machine is currently not a supported configuration, even though
you could do it indirectly with stunnel or similar programs.

The certificate is yours to obtain and renew — see
[TLS strategy](names-and-decisions.md#tls-strategy)
for the validity limit that it must respect. Tested starting points for both
common terminators ship with the package:

```
/usr/share/doc/kerbridge-broker/examples/kerbridge.caddyfile
/usr/share/doc/kerbridge-broker/examples/kerbridge-nginx.conf
```

Each proxies the documented routes only to `127.0.0.1:8080`, and 404s
everything else at the edge. Each caps the request body at 16 KB, and each logs
no bodies: a ticket response carries a Kerberos credential cache, and a request carries
a bearer token. They are secrets.

## The systemd units

```
kerbridge-issuerd.service    root, on the DC: holds KDC authority, reads sam.ldb
kerbridge-broker.service     _kerbridge-broker, the client-facing API
kerbridge-sync.service       _kerbridge-sync, the directory mirror
```

dpkg enables and starts them. Each runs `kbconfig check` at `ExecStartPre`, and
the issuer runs `kbsetup verify` as well. So a config set that does not check
out stops the bridge — but not the domain controller.

Two states are normal while you work. Neither is a fault:

- **`kerbridge-issuerd` runs idle before you provision.** `kbsetup verify`
  answers *nothing is provisioned yet* as a warning rather than a mismatch. The
  issuer simply starts working when `kbsetup realm` gives it a realm.
- **`kerbridge-broker` and `kerbridge-sync` are `failed` until `kbsetup
  directory` runs.** Their LDAP bind passwords do not exist until then, so each
  exits with `reading secret …/svc_kerbridge_*_password` and latches. `kbsetup
  directory` starts them itself once it has written the passwords, and `kbsetup
  secrets` does the same for whatever was waiting on a credential you pasted —
  so neither state outlives the step that ends it.

A unit that failed for a reason no setup verb writes away stays failed. Read the
reason, then clear the counter and start the unit:

```sh
journalctl _SYSTEMD_UNIT=kerbridge-broker.service -n 30
sudo systemctl reset-failed kerbridge-broker
sudo systemctl start kerbridge-broker
```

> **Do not read the reason out of `systemctl status`.** It prints ten lines, and
> a unit that spent its restart budget has ten lines of systemd's own —
> `Scheduled restart job`, `Start request repeated too quickly` — with the
> sentence that says why pushed off the top. `-u kerbridge-broker` adds those
> same messages to the journal query; `_SYSTEMD_UNIT=` as above matches only
> what the daemon itself wrote. `kbsetup status` quotes that line for every
> failed unit, so it answers this without the incantation.

> **CAUTION: `reset-failed` is not optional here.** Within the 60-second window
> a plain `systemctl start` is refused, and it does not even run
> `ExecStartPre=`. Each refusal pushes the window out another minute, so to
> retry in a loop looks exactly like a unit that is permanently stuck. Either
> clear the counter as above, or leave the unit alone for a full minute and
> then start it.

<details>
<summary>The rate limit, and what was measured</summary>
Each unit pairs `StartLimitIntervalSec=60` with `StartLimitBurst=5`, so five
attempts at `RestartSec=5s` take about 25 seconds. systemd then gives up and
says `Start request repeated too quickly`. Measured on systemd 252 and 257
alike.

The idle-issuer behavior was measured on trixie across the whole sequence —
install, configure, `kbsetup realm`, `kbsetup directory` — and the issuer never
restarted once. A provisioning run that *stopped partway* is the other side of
that line: `kbsetup verify` exits 2 and names the state, so the issuer is
`failed` rather than idle.

</details>

Each daemon keeps its own audit record under `/var/log/kerbridge/<daemon>/`,
one directory per daemon, so that no daemon can rewrite another's. Logrotate
rotates them weekly, twelve deep. The daemons connect lazily — the broker opens
the issuer socket per request, and sync per cycle — so a DC restart or a cold
boot needs nothing from you.

## Check it

```sh
kbmanage doctor
kbmanage doctor --endpoint https://kerbridge.example.site
```

`doctor` walks the chain and names the first broken link. `--endpoint` adds the
public URL that a client would enroll against. It exits non-zero on any failed
link. For what each link is, see
[troubleshooting.md](troubleshooting.md#the-diagnostic-that-walks-the-whole-chain).

`kbmanage endpoint <url>` is the endpoint check on its own. It reads no config
set and binds nothing. It prints one line, and it exits `0` served, `2` still
settling, `3` the port is open and no TLS session came of it, `1` answering
wrongly.

Then continue with
[Enable synchronization (`broker-host.md`)](broker-host.md#enable-synchronization).
