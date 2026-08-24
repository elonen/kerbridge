# The Docker Compose deployment

One of the two ways to bring up the KerBridge server in
[step 4 (*Stand up the broker host*) in SETUP.md](../../SETUP.md#4-stand-up-the-broker-host).
The other is [`debian-deployment.md`](debian-deployment.md).

The server runs as the `kerbridge` Compose project: images built from this
repository, with Caddy and the Samba AD DC among them. What is true whichever
method you chose — synchronization, operator notification and backup — is in
[`broker-host.md`](broker-host.md).

On this page, **`<secrets-dir>` is `deploy/secrets/`**, on the host.

```sh
git clone <this repo> kerbridge
cd kerbridge/deploy
cp .env.example .env
```

## Edit `.env` and the config set

[config-management.md](config-management.md) holds the rules: what a config set
is, why almost every line ships commented out, and what an upgrade does with
the lines that you changed. Read it one time, then this page for the settings.

`.env.example` has many comments. **Read them as you do each step.** In
summary:

1. In `.env`, replace each `example.site` with your domain and realm:
   `AD_REALM`, `AD_DNS_DOMAIN`, `AD_NETBIOS_DOMAIN`, `AD_DC_HOSTNAME` and
   `BROKER_FQDN`.
2. Copy the config templates:

   ```sh
   for f in configs/*.toml.example; do cp "$f" "${f%.example}"; done
   ```

3. In `configs/realm.toml`, set `realm` to the same value as `AD_REALM`, and
   `ldap_url` to `ldaps://<AD_DC_HOSTNAME>.<AD_DNS_DOMAIN>:636`. Leave
   `base_dn` commented out — KerBridge derives it from `realm`.
4. In `configs/idp_entra.toml`, paste the `[provider_config]` block from step 2.
   Terraform's `print-provider-config.sh` prints it. On the manual path, copy
   the values yourself. For each value and what it does, see
   [`entra.md`](entra.md#the-providerconfig-values).
5. Set `TLS_STRATEGY` in `.env`, and supply its material. The next section
   tells you how.

`make up` refuses to start until `.env` and the config set agree where they
overlap.

## Supply the certificate

You made this decision in
[TLS strategy (`names-and-decisions.md`)](names-and-decisions.md#tls-strategy),
which also states the validity limit that every certificate here must respect.

**`TLS_STRATEGY=external`** — copy your certificate and key to:

```
deploy/secrets/tls/broker.crt
deploy/secrets/tls/broker.key
```

Without these files, `make up` refuses to provision the domain. This is
intentional: the TLS decision is easier to make before a domain exists than
after.

> **Note:** Copy both files. A symlink to the host's key location is refused,
> because that directory is bind-mounted as a directory. Caddy would resolve
> the link inside its own filesystem, where the target does not exist.

**`TLS_STRATEGY=acme-dns`:**

- Set `CADDY_DNS_MODULE` to your provider's Caddy module.
- Set `ACME_DNS_PROVIDER` to the `dns` directive arguments.
- Put the provider credentials in `deploy/secrets/acme-dns.env`.

**`TLS_STRATEGY=acme`** — supply nothing. But the DNS records of
[step 3](../../SETUP.md#3-publish-the-dns-records) must already resolve
publicly.

The first `make up` builds Caddy for the strategy that you chose. The strategy
is a build argument, so a change has no effect until you run
`docker compose build caddy`. Read
[Certificates (`deploy/README.md`)](../../deploy/README.md#certificates) if you
change the strategy later, if a challenge fails, or if your provider does not
match the options above.

## Bring it up

> **CAUTION: Give root the TLS material that you place by hand.** On Linux,
> `secrets/tls/broker.key` for the `external` strategy must be owned by `root`.
> Secrets are bind-mounted into the containers with their host owner and mode
> intact, and every container that reads one runs with `cap_drop: ALL`. So a
> `0600` file that an unprivileged operator owns is unreadable to the container
> that it is for. The files that KerBridge generates need nothing from you:
> root writes them inside containers.
> [Secrets (`deploy/README.md`)](../../deploy/README.md#secrets) gives the
> rules in full.

```sh
make up
```

`make up` prints a readiness report at the end —
[step 4](../../SETUP.md#4-stand-up-the-broker-host) shows what a good one looks
like. Run the report again at any time with `make ready`. If `endpoint` failed
on the TLS certificate, wait and run the report again: this shows whether
issuance was only slow. Every target is idempotent, so a target that you run
again after a failure continues where it stopped.

> **CAUTION: A refused directory delegation stops the bootstrap.**
> `kbsetup directory` prints `FAILED to delegate <what>` with the `samba-tool`
> command that it tried, and it exits 1. So you never reach "Stack is up" with
> sync unable to write. The script is idempotent: repair the cause and run it
> again.

> **CAUTION: Do not run `make seed`.** It is the development bench fixture: a
> false user, groups and a share ACL. It puts objects in
> `OU=Entra,OU=CloudIdP` that sync does not own. In production these objects
> arrive from Entra through sync.

`kbmanage` is built with `make kbmanage` from the repository root. `make up`
writes its configuration to `deploy/configs/kbmanage.toml`, and it links
`~/.config/kerbridge/configs` to `deploy/configs/`. So `dist/kbmanage` finds
the deployment from any directory, **for the user that ran `make up`**. Another
account has no such link, and it reports that the domain is missing.

<details>
<summary>Why root, and why rootless Docker is not supported</summary>

**Rootless Docker is not tested and not supported.** No spike was run, and the
bench is Docker Desktop. This section tells you why root is the supported path.
It is not a recipe that makes rootless Docker work.

There are two independent reasons, and only one is about file ownership.

**Privileged ports.** The stack publishes Kerberos on port `88`, SMB on port
`445` and LDAP on port `389`. A rootless runtime cannot bind below 1024 unless
the host lowers `net.ipv4.ip_unprivileged_port_start` or grants
`CAP_NET_BIND_SERVICE` to rootlesskit. Port `445` cannot move to a different
number, because you cannot configure an SMB client to use a different port. So
a rootless stack would still need privileged port forwarding in front of it.
The privilege moves outward; it does not go away.

**Extended attributes.** Samba stores NT ACLs in the `security.NTACL` extended
attribute. A write to the `security.*` namespace needs `CAP_SYS_ADMIN` in the
user namespace that owns the filesystem, and that namespace is the host's, not
the container's. Rootless Docker grants the capability inside its own namespace
only. So a rootless realm is expected to fail during *provisioning*, not at
start. To provision without xattrs (`posix:eadb`) would avoid this, but that is
a durable format decision, not a switch. Nothing here was built or tested that
way.

**The secret permissions become easier, not harder.** Under rootless Docker the
container's root *is* your own account, so the container can already read the
`0600` files that you generated. The exception is the group-readable secrets
that the broker and sync need: their gid would land outside your `subgid` range
and mean nothing inside the container. `make check-secrets` would then compare
a host number against a number that the container never sees.

</details>

<details>
<summary>What <code>make up</code> does, in order</summary>

1. It does the preflight checks: the `.env` values, the TLS material and the
   secret permissions.
2. It generates the host-side secrets into `deploy/secrets/generated/`.
3. It provisions the domain in Samba AD.
4. It creates `OU=CloudIdP` with `OU=Entra` inside it, `OU=Resources`, and the
   service accounts: `svc-kerbridge-broker`, which is the read-only LDAP
   identity of the broker and needs no delegation, and
   `svc-kerbridge-sync-entra` and `svc-kerbridge-manage` with theirs.
5. It starts the rest of the stack.
6. It waits for the stack to settle.

For each step in detail, with the failures that are permitted at each one, see
[`make up`, step by step (`deploy/README.md`)](../../deploy/README.md#make-up-step-by-step).

</details>

## Operational notes

- **Restart Caddy each time that you restart the broker.** Caddy runs inside
  the broker's network namespace. A broker restart orphans Caddy, and every
  request is reset until you run `docker compose restart caddy`.
- **A rebuilt realm container creates a new CA.** After a rebuild, restart
  `broker` and `sync`, restart `caddy`, then run `make kbmanage-config` again.

Then continue with
[Enable synchronization (`broker-host.md`)](broker-host.md#enable-synchronization).
