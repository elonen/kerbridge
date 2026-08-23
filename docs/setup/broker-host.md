# The broker host

This page gives the detail for
[step 4 (*Stand up the broker host*) in SETUP.md](../../SETUP.md#4-stand-up-the-broker-host)
that is true whichever way you brought the server up. Bringing it up is the one
part that differs, and it has a page each:

- [`compose-deployment.md`](compose-deployment.md) — containers, `make up`.
- [`debian-deployment.md`](debian-deployment.md) — `.deb` packages, systemd.

Everything below assumes the server is running. `<secrets-dir>` is
`deploy/secrets/` in a Docker Compose deployment and `/etc/kerbridge.secrets/`
in a Debian one; the config set names `/etc/kerbridge.secrets/…` in both,
because Compose mounts its tree there.

## Enable synchronization

1. Write the client secret from step 2 into its file. It is
   `<secrets-dir>/idp/entra/credential`, mode `0640`, group-readable by the
   account sync runs as:

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

   This is the full procedure that enables sync. It needs no restart. Sync
   finds the file on its next cycle, so it takes effect within one
   `interval_seconds`, which is 300 by default.

   > **CAUTION:** `0600 root:root` denies sync its own secret. Sync runs
   > unprivileged and reaches the file through its group.
   >
   > **In a Docker Compose deployment**, a compose secret is a bind mount: the
   > container gets the host's owner and mode, and the group is the numeric
   > `BROKER_GID`. Docker Desktop remaps ownership instead, so on macOS the
   > `chown` fails and `chmod 600` is enough — that bench also cannot reproduce
   > the Linux failure. **Before you trust the gid, make sure that it is
   > unused:** `getent group ${BROKER_GID:-10002}` must return nothing. If a
   > host group already holds the gid, the members of that group can read your
   > Entra client secret; select an unused gid in `.env`.
   >
   > **In a Debian deployment** the group is `_kerbridge`, created by
   > `kerbridge-config` with a number `adduser` chose, so there is no gid to
   > check.

   > **CAUTION:** This secret is equivalent to realm access. Sync creates
   > identities and manages the admission group. Thus the holder of this
   > credential can admit themselves to the realm and receive tickets. The
   > directory rights are confined to `OU=Entra,OU=CloudIdP`: the credential cannot change
   > `OU=Resources`, so it cannot authorize itself against a share without
   > your resource groups. But it is not a read-only credential. Do not store
   > it like one.

2. Set `dry_run = true` in your config set's `sync.toml` **before sync first
   runs**. The template comments this line out, and the default is `false`, so a
   deployment that leaves the line alone writes to the directory on its first
   cycle. Remove the `#` from `#dry_run = false`, then change the value to
   `true`. Watch one or two cycles:

   ```sh
   docker compose logs -f sync          # Docker Compose
   journalctl -u kerbridge-sync -f      # Debian
   ```

   Make sure that sync reads the tenant, resolves the admission group, and
   logs the plan that it *would* apply.

3. When the plan is correct, comment the `dry_run` line out again and restart
   sync. A commented-out line sets nothing, so sync uses the default. Do not
   write `dry_run = false` instead: an option you set keeps your value even
   where a later version has a better default.

   ```sh
   docker compose up -d sync              # Docker Compose
   sudo systemctl restart kerbridge-sync  # Debian
   ```

   Make sure that your users appear:

   ```sh
   kbmanage cloud list users
   ```

   In a Docker Compose deployment the binary is `dist/kbmanage`, built with
   `make kbmanage` from the repo root; in a Debian deployment `kbmanage` is on
   the `PATH` from the `kerbridge-manage` package.

## Operator notification

No other system reports these events:

- the Graph credential comes near its expiry
- the admission group is deleted or duplicated
- a sync cycle fails repeatedly.

These events always appear as `NOTIFY <severity> <event>:` lines in sync's log —
`docker compose logs sync`, or `journalctl -u kerbridge-sync`. A webhook also
puts them in a channel.

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

The file alone delivers nothing. `url_file` names it, and ships commented out
because no deployment can be assumed to have a webhook. Remove the `#` in the
`[notify]` table of `main.toml` — the path is the same string either way, since
the config set names the container's view of it:

```toml
url_file = "/etc/kerbridge.secrets/notify_url"
```

The URL is read at start, so restart the two daemons that send, then look in the
channel:

```sh
docker compose up -d broker sync                     # Docker Compose
make test-notification

sudo systemctl restart kerbridge-broker kerbridge-sync         # Debian
sudo -u _kerbridge-sync /usr/sbin/kerbridge-sync --test-notification
```

The test is not optional. A notification channel fails with no error message,
the same as the conditions that it reports. The command sends one synthetic
event. Thus you find a broken channel now, not during an incident.

Decide these two settings. Both are in the `[notify]` table of `main.toml`, and
most deployments change neither line:

- **`template`** — while the line stays commented out, the message renders on
  Slack, Teams, Mattermost, and Rocket.Chat. Any other receiver needs a
  template that you write. The services refuse to start on a template that
  names an unknown `%PLACEHOLDER%` or that does not produce JSON.
- **`min_severity`** — the default is `info`. If the channel gets too
  many messages, uncomment the line and set the value to `warning`. No `info`
  event is urgent.

An expiry is reported at 30, 14, 7, 3, and 1 days remaining, not daily. Each
other condition repeats once each day while it is still true.

You can feed your own monitoring system instead of a chat channel. The
receiver can also sit behind a private CA. For these cases, see
[Operator notification (`deploy/README.md`)](../../deploy/README.md#operator-notification).
Every condition is a file in the broker's and sync's own state directory —
`deploy/state/` per daemon, or `/var/lib/kerbridge/<daemon>/` — with or without
a configured URL. Thus a count of these files is a complete integration.

## Operational notes

- **Do not delete a password file to get a fresh one.** After the domain is
  provisioned, the accounts have the passwords in `<secrets-dir>/generated/`.
  Rotation is not implemented.
- **A re-provisioned realm issues a new CA.** Any host that holds a copy of
  `/etc/kerbridge/certs/realm-ca.pem` — an administrator's machine running
  `kbmanage`, most of all — needs the new one copied to it. Nothing refreshes it.

## Backup, before you change anything

Two things need backing up, and they are complements rather than overlaps: the
**domain**, and **KerBridge's own state**.

### The domain

**Docker Compose:** `deploy/scripts/compose/backup.sh out.tgz` writes one
tarball, and it takes both halves at once. The tarball holds everything that
this deployment cannot regenerate:

- `.env`
- all of `secrets/`
- Terraform's state
- the Docker volumes: `samba`, `etc-samba`, `caddy-data`, and also `m1-*` if
  you run `nas1`.

`restore.sh out.tgz` puts the contents back.

Before a full backup, stop the stack with `make down`. The script refuses to
tar a live Samba database; this prevents a torn copy. `--config-only` skips
the volumes and is safe while the stack is up.

The tarball is the authority of the deployment in one file: the account
passwords, the KDC keys, the TLS private key, and the Graph credential. The
script writes it with mode `0600`. `backup.sh -` writes the tarball to stdout.
Thus you can pipe it directly into `age` or `gpg`, and no plaintext copy lands
on disk. Scheduling, retention, and off-site copies are your responsibility.

**Debian:** the domain is Samba's, and Samba's own procedure is the one to
follow — [Back up and Restoring a Samba AD
DC](https://wiki.samba.org/index.php/Back_up_and_Restoring_a_Samba_AD_DC).
`samba-tool domain backup online` is the command; read that page rather than a
paraphrase of it here.

### KerBridge's own state

`samba-tool` deliberately backs up the domain and nothing per-server — its
`private/tls` folder comes out empty, and the wiki says per-server information
must be regenerated. So KerBridge's paths are exactly what it does not take. In
a Debian deployment, tar these:

- `/etc/kerbridge/` — the config set, and `certs/realm-ca.pem` with it
- `/etc/kerbridge.secrets/`
- `/etc/samba/smb.conf`
- `/var/lib/samba/`
- `/var/log/kerbridge/<daemon>/` — the audit records, which nothing else keeps
- your own TLS certificate and key, wherever your terminator holds them.

### Two things to know before you restore

**A restore preserves the domain SID.** That is the property that matters: the
SID is what every filesystem ACL on every member server resolves against, and a
fresh provision of the same realm produces a *different* one, against which
those ACLs mean nothing. It is what
[SETUP.md's `clean-docker-volumes` CAUTION](../../SETUP.md#9-uninstall) is
really about.

**A restore requires a DC name that never existed.** `samba-tool domain
restore` insists on `--newservername`, so a restored deployment necessarily runs
under a *different* DC hostname than the one it was backed up from — and
`dc_hostname` is one of the three identity values `kbsetup verify` treats as
fatal. After a restore, edit `realm.toml` to the new name and reissue the LDAPS
certificate. This is a property of Samba, and the check is correct as designed.
