# The broker host

This page holds the part of
[step 4 (*Stand up the broker host*) in SETUP.md](../../SETUP.md#4-stand-up-the-broker-host)
that is true whichever way you brought the server up. To bring it up is the one
part that differs, and it has a page each:

- [`compose-deployment.md`](compose-deployment.md) — containers, `make up`.
- [`debian-deployment.md`](debian-deployment.md) — `.deb` packages, systemd.

Everything below assumes that the server runs. `<secrets-dir>` is
`deploy/secrets/` in a Docker Compose deployment, and `/etc/kerbridge.secrets/`
in a Debian one. The config set names `/etc/kerbridge.secrets/…` in both,
because Compose mounts its tree there.

`kbmanage` is `dist/kbmanage` in a Docker Compose deployment, built one time
with `make kbmanage` from the repository root. In a Debian deployment it is on
the `PATH`, from the `kerbridge-manage` package.

## Enable synchronization

Sync runs from the start, and it stays idle until its credential exists. `sync
idle` is the normal state until you do this.

### 1. Write each source's credential

The credential is provider-specific:

| Provider | Sync credential |
|---|---|
| Entra | The sync app client-secret **Value**. |
| authentik | The dedicated service account's API token, with Intent `API`. |

Repeat this for every source. Use the source name from step 1 and the credential
from that provider's step-2 page.

**Docker Compose**, from `deploy/`:

```sh
SOURCE=authentik                   # or entra; the source name from step 1
printf '%s' '<the sync credential>' > "secrets/idp/$SOURCE/credential"
chown root:${BROKER_GID:-10002} "secrets/idp/$SOURCE/credential"   # Linux only
chmod 0640 "secrets/idp/$SOURCE/credential"
make ready                         # judges the mode, and says so if it is wrong
```

**Debian:**

```sh
sudo kbsetup secrets
```

`kbsetup secrets` discovers each configured source, asks the provider-specific
question, and writes the correct path and mode.

This enables sync. It needs no restart. Sync finds the file on its next cycle,
so it takes effect within one `interval_seconds`, which is 300 by default.

> **CAUTION: Do not write the file `0600 root:root`.** That denies sync its own
> secret. Sync runs unprivileged, and it reaches the file through its group.

> **CAUTION: Store each sync credential as a secret.** It is read-only in the
> cloud IdP, but it can read that provider's whole directory (IdP), including
> users that KerBridge does not synchronize. Sync's separate directory (realm)
> account can create admitted identities, but its rights are confined to that
> source's IdP-specific OU. It cannot change `OU=Resources`.

<details>
<summary>Check the gid first, in a Docker Compose deployment</summary>

A compose secret is a bind mount: the container gets the host's owner and mode,
and the group is the numeric `BROKER_GID`.

**Before you trust that gid, make sure that it is unused.**
`getent group ${BROKER_GID:-10002}` must return nothing. If a host group
already holds the gid, the members of that group can read a source's sync
credential. Select an unused gid in `.env`.

Docker Desktop remaps ownership instead, so on macOS the `chown` fails and
`chmod 600` is enough. That bench also cannot reproduce the Linux failure.

In a Debian deployment the group is `_kerbridge`, created by `kerbridge-config`
with a number that `adduser` chose, so there is no gid to check.

</details>

### 2. Watch one cycle before it writes

Set `dry_run = true` in `sync.toml` **before sync first runs**. The template
comments this line out, and the default is `false`, so a deployment that leaves
the line alone writes to the directory (realm) on its first cycle. Remove the `#` from
`#dry_run = false`, then change the value to `true`.

Watch one or two cycles:

```sh
docker compose logs -f sync          # Docker Compose
journalctl -u kerbridge-sync -f      # Debian
```

Check that sync reads the directory (IdP), that it resolves the admission group, and
that it logs the plan that it *would* apply.

### 3. Let it write

When the plan is correct, comment the `dry_run` line out again and restart
sync. A commented-out line sets nothing, so sync uses the default. Do not write
`dry_run = false` instead: an option that you set keeps your value even where a
later version has a better default.

```sh
docker compose up -d sync              # Docker Compose
sudo systemctl restart kerbridge-sync  # Debian
```

Check that your users appear:

```sh
kbmanage cloud list users
```

## Operator notification

No other system reports these events:

- the sync credential comes near its expiry;
- the admission group is deleted or duplicated;
- a sync cycle fails repeatedly.

They always appear as `NOTIFY <severity> <event>:` lines in sync's log. A
webhook also puts them in a channel. Set the webhook up now.

### 1. Name the file in the config set

The URL alone delivers nothing. `url_file` names the file it goes in, and it
ships commented out, because no deployment can be assumed to have a webhook.
Remove the `#` in the `[notify]` table of `main.toml`. The path is the same
string either way, because the config set names the container's view of it:

```toml
url_file = "/etc/kerbridge.secrets/notify_url"
```

### 2. Write the URL

```sh
# Debian
sudo kbsetup secrets
```

`kbsetup secrets` asks for every credential the set names and cannot generate,
this one included, and writes each at the owner and mode its reader needs.

> **CAUTION: to write this file by hand is to own its group.** The broker and
> sync read it as `_kerbridge` and open it at *every* start — a URL written
> `root:root`, which is what `sudo tee` leaves, stops both daemons dead rather
> than switching notification off. Should you place it yourself:
> `sudo chown root:_kerbridge` and `sudo chmod 0640`, in that order, and
> `kbsetup status` says whether the daemons can read what is there.

```sh
# Docker Compose, from deploy/
printf '%s' '<the webhook URL>' > secrets/notify_url
chown root:${BROKER_GID:-10002} secrets/notify_url   # Linux only, as above
chmod 0640 secrets/notify_url
```

### 3. Restart and test

The URL is read at start, so restart the two daemons that send. Then look in
the channel:

```sh
docker compose up -d broker sync                     # Docker Compose
make test-notification

sudo systemctl restart kerbridge-broker kerbridge-sync         # Debian
sudo -u _kerbridge-sync /usr/sbin/kerbridge-sync --test-notification
```

**The test is not optional.** A notification channel fails with no error
message, the same as the conditions that it reports. The command sends one
synthetic event, so you find a broken channel now and not during an incident.

### Two settings to decide

Both are in the `[notify]` table of `main.toml`, and most deployments change
neither line:

- **`template`** — while the line stays commented out, the message renders on
  Slack, Teams, Mattermost and Rocket.Chat. Any other receiver needs a template
  that you write. The services refuse to start on a template that names an
  unknown `%PLACEHOLDER%`, or that does not produce JSON.
- **`min_severity`** — the default is `info`. If the channel gets too many
  messages, uncomment the line and set the value to `warning`. No `info` event
  is urgent.

An expiry is reported at 30, 14, 7, 3 and 1 days remaining, not daily. Each
other condition repeats one time each day while it is still true.

If you leave `url_file` commented out, these events stay log lines. That is a
supported deployment. But decide which deployment you operate.

<details>
<summary>Feed your own monitoring instead of a chat channel</summary>

The receiver can also sit behind a private CA. For both cases, see
[Operator notification (`deploy/README.md`)](../../deploy/README.md#operator-notification).

Every condition is also a file in the broker's and sync's own state directory —
`deploy/state/<daemon>/`, or `/var/lib/kerbridge/<daemon>/` — with or without a
configured URL. So a count of those files is a complete integration.

</details>

## Operational notes

- **Do not delete a password file to get a fresh one.** After the domain is
  provisioned, the accounts have the passwords in `<secrets-dir>/generated/`.
  Rotation is not implemented.
- **A re-provisioned realm issues a new CA.** Copy the new
  `/etc/kerbridge/certs/realm-ca.pem` to every host that holds a copy — an
  administrator's machine that runs `kbmanage`, most of all. Nothing refreshes
  it.

## Backup, before you change anything

Two things need a backup, and they are complements rather than overlaps: the
**domain**, and **KerBridge's own state**.

### The domain

**Docker Compose:** `deploy/scripts/compose/backup.sh out.tgz` writes one
tarball, and it takes both halves at once. The tarball holds everything that
this deployment cannot generate again:

- `.env`
- all of `secrets/`
- Terraform's state
- the Docker volumes `samba`, `etc-samba` and `caddy-data`, and also `m1-*` if
  you run `nas1`.

`restore.sh out.tgz` puts the contents back.

Stop the stack with `make down` before a full backup. The script refuses to tar
a live Samba database, which prevents a torn copy. `--config-only` skips the
volumes, and it is safe while the stack is up.

The tarball is the authority of the deployment in one file: the account
passwords, the KDC keys, the TLS private key and the sync credential. The
script writes it with mode `0600`. `backup.sh -` writes the tarball to stdout,
so you can pipe it directly into `age` or `gpg` and land no plaintext copy on
disk. Scheduling, retention and off-site copies are yours.

**Debian:** the domain is Samba's, and Samba's own procedure is the one to
follow — [Back up and Restoring a Samba AD
DC](https://wiki.samba.org/index.php/Back_up_and_Restoring_a_Samba_AD_DC).
`samba-tool domain backup online` is the command. Read that page rather than a
paraphrase of it here.

### KerBridge's own state

`samba-tool` deliberately backs up the domain and nothing per-server: its
`private/tls` folder comes out empty, and the wiki says that per-server
information must be generated again. So KerBridge's paths are exactly what it
does not take. In a Debian deployment, tar these:

- `/etc/kerbridge/` — the config set, and `certs/realm-ca.pem` with it
- `/etc/kerbridge.secrets/`
- `/etc/samba/smb.conf`
- `/var/lib/samba/`
- `/var/log/kerbridge/<daemon>/` — the audit records, which nothing else keeps
- your own TLS certificate and key, wherever your terminator holds them.

### Two things to know before you restore

**A restore preserves the domain SID.** That is the property that matters. The
SID is what every filesystem ACL on every member server resolves against, and a
fresh provision of the same realm produces a *different* one, against which
those ACLs mean nothing.

**A restore needs a DC name that never existed.** `samba-tool domain restore`
insists on `--newservername`, so a restored deployment necessarily runs under a
*different* DC host name than the one that it was backed up from. And
`dc_hostname` is one of the identity values that `kbsetup verify` treats as
fatal. After a restore, edit `realm.toml` to the new name and issue the LDAPS
certificate again. This is a property of Samba, and the check is correct as
designed.
