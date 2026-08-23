# The Docker Compose deployment

One of the two ways to bring up the KerBridge server in
[step 4 (*Stand up the broker host*) in SETUP.md](../../SETUP.md#4-stand-up-the-broker-host).
The other is [`debian-deployment.md`](debian-deployment.md).

The server runs as the `kerbridge` Compose project: five images built from this
repository, with Caddy and the Samba AD DC among them. Everything on this page
is that project. What is true whichever method you chose —
enabling synchronization, operator notification, backup — is in
[`broker-host.md`](broker-host.md).

On this page, **`<secrets-dir>` is `deploy/secrets/`**, on the host.

```sh
git clone <this repo> kerbridge
cd kerbridge/deploy
cp .env.example .env
```

## Edit `.env` and the config set

[config-management.md](config-management.md) is the rules: what a config set is,
why almost every line ships commented out, and what an upgrade does with the
lines you change. Read it once, then this page for the settings themselves.

`.env.example` has many comments. **Read them as you do each step.** In summary:

- Replace each `example.site` with your domain and realm in `.env` — `AD_REALM`,
  `AD_DNS_DOMAIN`, `AD_NETBIOS_DOMAIN` and `BROKER_FQDN`.
  - Also replace it in `configs/realm.toml`, in `realm` and in `ldap_url`.
    Leave `base_dn` commented out. KerBridge derives it from `realm`.
- Copy the config templates (`for f in configs/*.toml.example; do cp "$f"
  "${f%.example}"; done`) and make sure that each `[provider_config]` value in
  `configs/idp_entra.toml` is correct. Terraform's `print-provider-config.sh` prints them.
  If you did the manual setup, copy them yourself from the Entra portal. For
  the six values and the purpose of each, see
  [`entra.md`](entra.md#the-six-providerconfig-values).
- Set `TLS_STRATEGY` and make sure that certificate issuance works. The next
  section tells you how.

## Supply the certificate

You made this decision in
[TLS strategy (`names-and-decisions.md`)](names-and-decisions.md#tls-strategy),
which also states the validity limit that every certificate here has to respect.

**`TLS_STRATEGY=external`** — copy your certificate and key to:

```
deploy/secrets/tls/broker.crt
deploy/secrets/tls/broker.key
```

Without these files, `make up` refuses to provision the Samba AD domain. This
is intentional: the TLS decision is easier to make before a domain exists than
after.

> **Note:** Copy both files. A symlink to the host's key location is refused.
> The reason: that directory is bind-mounted as a directory, so Caddy would
> resolve the link inside its own filesystem, where the target does not exist.

**`TLS_STRATEGY=acme-dns`:**

- Set `CADDY_DNS_MODULE` to your provider's Caddy module.
- Set `ACME_DNS_PROVIDER` to the `dns` directive arguments.
- Put the provider credentials in `deploy/secrets/acme-dns.env`.

**`TLS_STRATEGY=acme`** — supply nothing, but the DNS records from
[step 3 (*Publish the DNS records*)](../../SETUP.md#3-publish-the-dns-records)
must already resolve publicly.

The first `make up` builds Caddy for the strategy that you chose. Read
[Certificates (`deploy/README.md`)](../../deploy/README.md#certificates) if:

- you change the strategy later
- a challenge fails
- your provider does not match the options above.

The strategy is a build argument. A change has no effect until you run
`docker compose build caddy`.

## Bring it up

> **CAUTION:** On Linux, the TLS material you place by hand must be owned by
> `root` — `secrets/tls/broker.key` for the `external` strategy. Secrets are
> bind-mounted into the containers with their host owner and mode intact, and
> every container that reads one runs with `cap_drop: ALL`, so a `0600` file an
> unprivileged operator owns is unreadable to the container it is for. The files
> KerBridge generates need nothing from you: they are written by root in
> containers. [Secrets (`deploy/README.md`)](../../deploy/README.md#secrets)
> gives the rules in full.

```sh
make up
```

<details>
<summary>Why root, and why rootless Docker is not supported</summary>

**Rootless Docker is not tested and not supported.** No spike was run, and the
bench is Docker Desktop. This section tells you why root is the supported path.
It is not a recipe that makes rootless Docker work.

There are two independent reasons. Only one of them is about file ownership.

**Privileged ports.** The stack publishes Kerberos on port `88`, SMB on port
`445`, and LDAP on port `389`. A rootless runtime cannot bind below 1024 unless
the host lowers `net.ipv4.ip_unprivileged_port_start` or grants
`CAP_NET_BIND_SERVICE` to rootlesskit. Port `445` cannot move to a different
number, because you cannot configure an SMB client to use a different port.
Thus a rootless stack would still need privileged port forwarding in front of
it. The privilege moves outward; it does not go away.

**Extended attributes.** Samba stores NT ACLs in the `security.NTACL` extended
attribute. A write to the `security.*` namespace needs `CAP_SYS_ADMIN` in the
user namespace that owns the filesystem. That namespace is the host's, not the
container's. Rootless Docker grants the capability only inside its own
namespace. Thus a rootless realm is expected to fail during *provisioning*,
not at start. Provisioning without xattrs (`posix:eadb`) would avoid this, but
that is a durable format decision, not a switch. Nothing here was built or
tested that way.

**The secret permissions become easier, not harder.** Under rootless Docker,
the container's root *is* your own account. Thus the container can already
read the `0600` files that you generated. The exception is the group-readable
secrets that the broker and sync need. Their gid would land outside your
`subgid` range and mean nothing inside the container. `make check-secrets`
would then compare a host number against a number that the container never
sees.

</details>

A successful run shows this output:

```
Waiting for the stack to settle (up to 300s; READY_TIMEOUT overrides).
  realm     ok
  broker    ok
  endpoint  ok      serving /config over a publicly trusted certificate
  sync      idle
Stack is up.
```

- Run the report again at any time with `make ready`. For example, if
  `endpoint` fails on the TLS certificate, wait and run the report again. This
  shows whether issuance was only slow.
- Every target is idempotent. If you run a target again after a failure, it
  continues where it stopped.
- `sync idle` is expected. Sync always runs, and it idles until its credential
  exists. [Enable synchronization (`broker-host.md`)](broker-host.md#enable-synchronization)
  is the step that ends it.

<details>
<summary>What <code>make up</code> does, in order</summary>

1. It does three preflight checks: the `.env` values, the TLS material, and
   the secret permissions.
2. It generates the host-side secrets into `deploy/secrets/generated/`.
3. It provisions the domain in Samba AD.
4. It creates `OU=CloudIdP` with `OU=Entra` inside it, `OU=Resources`, and
   three service accounts:
   `svc-kerbridge-broker`, which is the read-only LDAP identity of the broker
   and needs no delegation, and `svc-kerbridge-sync-entra` and
   `svc-kerbridge-manage` with theirs.
5. It starts the rest of the stack.
6. It waits for the stack to settle.

For each step in detail, with the failures that are permitted at each one, see
[`make up`, step by step (`deploy/README.md`)](../../deploy/README.md#make-up-step-by-step).

</details>

> **CAUTION:** A refused directory delegation stops the bootstrap.
> `kbsetup directory` prints `FAILED to delegate <what>` with the
> `samba-tool` command it tried, and exits 1 — so you never reach "Stack is up"
> with sync unable to write. The script is idempotent: fix the cause and run it
> again.

**Do not run `make seed`.** It is the dev bench fixture: a fake demo user,
groups, and a share ACL. In production, these objects arrive from Entra
through sync. `make seed` puts objects in `OU=Entra,OU=CloudIdP` that sync does not own.

`kbmanage` is built with `make kbmanage` from the repo root, and `make up`
writes its configuration to `deploy/configs/kbmanage.toml` and links
`~/.config/kerbridge/configs` to `deploy/configs/`, so `dist/kbmanage` finds it
from any directory.

## Operational notes

- **Restart Caddy each time that you restart the broker.** Caddy runs inside
  the broker's network namespace. A broker restart orphans Caddy, and every
  request is reset until you run `docker compose restart caddy`.
- **A rebuilt realm container creates a new CA.** After a rebuild:
  1. Restart `broker` and `sync`.
  2. Restart `caddy`.
  3. Run `make kbmanage-config` again.
