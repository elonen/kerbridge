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

### 1. Write the credential

Write the client secret from
[step 2](../../SETUP.md#2-register-three-applications-in-entra) into
`<secrets-dir>/idp/entra/credential`. The file must be mode `0640`, and it must
be group-readable by the account that sync runs as:

```sh
# Docker Compose, from deploy/
printf '%s' '<the secret Value>' > secrets/idp/entra/credential
chown root:${BROKER_GID:-10002} secrets/idp/entra/credential   # Linux only
chmod 0640 secrets/idp/entra/credential
make ready                       # judges the mode, and says so if it is wrong
```

```sh
# Debian
printf '%s' '<the secret Value>' | sudo tee /etc/kerbridge.secrets/idp/entra/credential >/dev/null
sudo chown root:_kerbridge /etc/kerbridge.secrets/idp/entra/credential
sudo chmod 0640 /etc/kerbridge.secrets/idp/entra/credential
```

This enables sync. It needs no restart. Sync finds the file on its next cycle,
so it takes effect within one `interval_seconds`, which is 300 by default.

> **CAUTION: Do not write the file `0600 root:root`.** That denies sync its own
> secret. Sync runs unprivileged, and it reaches the file through its group.

> **CAUTION: Store this credential as a secret, not as a read-only key.** It is
> equivalent to realm access. Sync creates identities and manages the admission
> group, so the holder can admit themselves to the realm and receive tickets.
> The directory rights are confined to `OU=Entra,OU=CloudIdP`: the credential
> cannot change `OU=Resources`, so it cannot authorize itself against a share
> without your resource groups.

<details>
<summary>Check the gid first, in a Docker Compose deployment</summary>

A compose secret is a bind mount: the container gets the host's owner and mode,
and the group is the numeric `BROKER_GID`.

**Before you trust that gid, make sure that it is unused.**
`getent group ${BROKER_GID:-10002}` must return nothing. If a host group
already holds the gid, the members of that group can read your Entra client
secret. Select an unused gid in `.env`.

Docker Desktop remaps ownership instead, so on macOS the `chown` fails and
`chmod 600` is enough. That bench also cannot reproduce the Linux failure.

In a Debian deployment the group is `_kerbridge`, created by `kerbridge-config`
with a number that `adduser` chose, so there is no gid to check.

</details>

### 2. Watch one cycle before it writes

Set `dry_run = true` in `sync.toml` **before sync first runs**. The template
comments this line out, and the default is `false`, so a deployment that leaves
the line alone writes to the directory on its first cycle. Remove the `#` from
`#dry_run = false`, then change the value to `true`.

Watch one or two cycles:

```sh
docker compose logs -f sync          # Docker Compose
journalctl -u kerbridge-sync -f      # Debian
```

Check that sync reads the tenant, that it resolves the admission group, and
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

- the Graph credential comes near its expiry;
- the admission group is deleted or duplicated;
- a sync cycle fails repeatedly.

They always appear as `NOTIFY <severity> <event>:` lines in sync's log. A
webhook also puts them in a channel. Set the webhook up now.

### 1. Write the URL

```sh
# Docker Compose, from deploy/
printf '%s' '<the webhook URL>' > secrets/notify_url
chown root:${BROKER_GID:-10002} secrets/notify_url   # Linux only, as above
chmod 0640 secrets/notify_url
```

```sh
# Debian
printf '%s' '<the webhook URL>' | sudo tee /etc/kerbridge.secrets/notify_url >/dev/null
sudo chown root:_kerbridge /etc/kerbridge.secrets/notify_url
sudo chmod 0640 /etc/kerbridge.secrets/notify_url
```

### 2. Name the file in the config set

The file alone delivers nothing. `url_file` names it, and it ships commented
out, because no deployment can be assumed to have a webhook. Remove the `#` in
the `[notify]` table of `main.toml`. The path is the same string either way,
because the config set names the container's view of it:

```toml
url_file = "/etc/kerbridge.secrets/notify_url"
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
passwords, the KDC keys, the TLS private key and the Graph credential. The
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
