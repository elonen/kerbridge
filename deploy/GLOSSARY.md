# deploy glossary

The Compose project that runs the server: `.env`, the config set, the overlays,
and the bench/production shapes they select.

Everything here is the [Docker Compose
deployment](../GLOSSARY.md#docker-compose-deployment); a
[Debian deployment](../GLOSSARY.md#debian-deployment) has none of these files.

Part of the repo-wide vocabulary in [`GLOSSARY.md`](../GLOSSARY.md) — a term
means the same thing there and here. It lives in this file, closest to where
it's used, rather than in the root file, because the root file would be
unreadably long if it carried every term at once.

### `bench.env`

The tracked fixture file the [development bench](#development-bench) is built
from, and the one env file no operator edits: the seeded accounts and their
object ids, the [mockidp](../GLOSSARY.md#mockidp) tenant id, and
[nas1](#nas1)'s name and address. Compose and the deploy scripts both read it
*before* [`.env`](#env), and the last file read wins, so a line in `.env` —
or a variable in the environment — overrides a fixture without editing this
one. It holds no secret, and nothing in it is inert if wrong: a value that
disagrees with the [config set](#config-set) breaks the bench loudly.
<!-- refs: `deploy/bench.env`, `COMPOSE_ENV_FILES=bench.env,.env` -->
<!-- avoid: the fixture env, dev.env, the bench dotenv, bench env file -->

### broker host

The one Linux host that runs the Compose stack. It is also the
DC, because the broker and the DC share a name and a machine.
<!-- avoid: the linux host, the kerbridge host, the kerbridge vm, the dc -->

### `BROKER_LISTEN`

The address the broker serves plain HTTP on behind Caddy.
Stated twice and never published: `listen` in `configs/broker.toml` is what the
broker binds, and this optional `.env` key is what Caddy proxies to. The two
must name one address -- Caddy cannot read TOML, and each end defaults to
`127.0.0.1:8080` so a deployment that sets neither agrees by construction. It is
deliberately not a settable key in the example env file, and both the env check
and the broker itself refuse a non-loopback value, because the broker speaks in
the clear and a non-loopback bind puts the API on the network.
<!-- refs: `broker.toml` `listen`, `BROKER_UPSTREAM`, `deploy/scripts/config/check-env.sh` -->
<!-- avoid: the broker address, the api port -->

### CI stack

A disposable stack that a stack tier runs from a gitignored copy of the tracked
tree. It uses a separate Compose project, container names, subnet, and published
port. It tests provisioning, bootstrap scripts, the LDAPS bind, the issuer
socket, the KDC, and a member's PAC. It is not a deployment method.
`scripts/bench/provision.sh` creates the stack and waits for `/config`; each
[stack tier](#stack-tier) sources it.
<!-- refs: `deploy/scripts/bench/ci-stack.sh`, `deploy/scripts/bench/provision.sh`, project `${CI_PROJECT}` -->
<!-- avoid: the test stack -->

### config set

The TOML files the binaries read: `main.toml`, `realm.toml`, `issuerd.toml`,
`broker.toml`, `sync.toml`, the optional `kbmanage.toml`, and one
`idp_<source>.toml` per [source](../GLOSSARY.md#source). `main.toml` is the
entry point; the rest are found beside it under those fixed names, so
`--config path/to/configs` relocates a whole deployment. A binary is pointed at
the directory, never at one file inside it -- it reads the others regardless.

`kbmanage.toml` is optional because it is the one file no container needs: the
operator CLI runs on a host, and holds an identity and two paths that differ on
that side of the container boundary.

The cut between `realm.toml` and `main.toml` is one question: *would this still
be true if a different tool fronted the same realm?* Yes goes in `realm.toml` —
so the ticket ceilings do, being Kerberos facts. No goes in `main.toml`, which
is where [device grants](../GLOSSARY.md#device-grant) live, the concept not
existing without KerBridge.

Distinct from [`.env`](#env), which no binary reads. A deployment keeps its
own copies in `deploy/configs/`, which the containers mount at the compiled-in
`/etc/kerbridge`; a host-run tool given no `--config` reads
`~/.config/kerbridge/configs` — a link `make kbmanage-config` writes — and then
`/etc/kerbridge`, and names both when neither answers. The committed
`*.toml.example` set is rendered from a
[template source](../crates/kerbridge-config/GLOSSARY.md#template-source) and the
[config schema](../crates/kerbridge-config/GLOSSARY.md#config-schema), so it
cannot disagree with the parser. A copy of it does not load until its
[lines to complete](../crates/kerbridge-config/GLOSSARY.md#line-to-complete) are
completed; `kbconfig check` names every one of them.
<!-- refs: `kerbridge_core::config`, `deploy/configs/`, `DEFAULT_CONFIG_DIR` -->
<!-- avoid: the toml config, configs/, `kbmanage.env` -->
<!-- user-facing: the config files, the config directory -->
<!-- different than: `.env` (compose-level, and what this replaced) -->

### delegation (directory rights)

An SDDL ACE `kbsetup directory` applies
with `samba-tool dsacl set`, which is what makes a service account more than a
name. A refused one aborts the bootstrap rather than warning.
<!-- refs: `kbsetup directory`, `crates/kerbridge-setup/src/directory.rs` -->
<!-- avoid: acl, permission grant, rights assignment -->

### development bench

The shape the base compose file ships: bridge network
with published ports, named volumes for Samba state, the example realm.
Production differs in exactly those two infrastructure choices — host
networking and bind mounts under the production state directory.
<!-- refs: `deploy/compose.yaml`, realm `EXAMPLE.SITE`, `KERBRIDGE_STATE_DIR` -->
<!-- avoid: dev environment, local -->

### Entra identifiers

The GUID-shaped `[provider_config]` values in
`configs/idp_<source>.toml` that name a tenant's registered applications: the
tenant ID, the broker API client ID and the public client ID. A forgotten
edit — the example file's synthetic placeholders left in place — looks
exactly like a configured deployment and surfaces only as a crash-looping
broker.
<!-- refs: `tenant_id`, `broker_api_client_id`, `public_client_id` in `configs/idp_<source>.toml`'s `[provider_config]`, `idp_entra.toml.example` -->
<!-- avoid: the client ids, tenant config, placeholders -->

### `.env`

The deployment-shape file, holding what compose itself interpolates and what the
deploy scripts source as shell. Its keys are classified by **where the operator
gets the value** — the realm being created, the portal,
the directory, or nowhere but the operator's own decision, which is unprefixed.
It carries no secrets; those are one-value files under `secrets/`.

Read last, after [`bench.env`](#benchenv), by compose and by the scripts alike:
this file is the operator's, so nothing tracked may quietly outrank it.

Not a deployment's configuration: what the binaries read is the
[config set](#config-set), and no component reads an environment variable at
all. This is what compose itself needs — image names, ports, mounts, the realm
the entrypoint provisions — plus the values the deploy scripts source as shell,
because shell cannot read TOML.
<!-- refs: prefixes `AD_*`, `ENTRA_*`, `LDAP_*`, unprefixed, `deploy/scripts/` -->
<!-- avoid: the config file, environment file, dotenv, the operator's single configuration file -->

### fixture (deployment)

An opt-in Compose piece — or a value one is built from — that exists to make the
whole path demonstrable on one machine and that production never creates: the
bench file server, the mock IdP, and the accounts and identifiers
[`bench.env`](#benchenv) states for them.
<!-- refs: `nas1` (`NAS=1`, `compose.nas.yaml`), `mockidp` (`MOCKIDP=1`, `compose.mockidp.yaml`), `deploy/bench.env` -->
<!-- avoid: demo container, example service, the nas overlay -->

### `generated/`

The subdirectory of `secrets/` holding machine-generated
values, never to be opened or edited: the same value also lives in the
directory, so editing one desynchronizes a password rather than changing it.
It is the whole of what [`kbsetup`](../GLOSSARY.md#kbsetup) writes and the only
part of `secrets/` the [setup service](#setup-service) is given, which is why a
per-source `bind_password` lives at `generated/idp/<name>/` rather than beside
the credential the operator supplies.
<!-- refs: `deploy/secrets/generated/` -->
<!-- avoid: minted secrets, auto secrets -->

### `idp/`

The subdirectory of `secrets/` holding what the *operator* supplies per
[source](../GLOSSARY.md#source): `idp/<name>/credential`, that IdP's application
credential, pasted from its portal. Named for the file set it mirrors,
`configs/idp_<name>.toml`.

Deliberately not the same directory as `generated/idp/<name>/`: the two have
different writers, and a credential that is an authority in the operator's cloud
tenant is not something the container holding this realm's KDC authority is
handed.
<!-- refs: `deploy/secrets/idp/<name>/credential` -->
<!-- avoid: the sources directory, secrets/sources -->

### `kerbridge` (Compose project)

The Compose project name, a literal `name:`
in the base compose file rather than an interpolated value, so teardown and
`clean` can identify the deployment without reading `.env`. It is also the
volume-name and label prefix.
<!-- refs: `deploy/compose.yaml`, volume `kerbridge_samba` -->
<!-- avoid: the compose stack -->

### `KERBRIDGE_STATE_DIR`

The production bind-mount root that replaces the
named volumes for Samba state, named in the base compose file,
the deploy README and the backup script. No script or service reads it today and it
is not in the example env file; it is distinct from `state/`.
<!-- refs: `deploy/compose.yaml`, `deploy/README.md`, `backup.sh`, `.env.example` -->
<!-- avoid: state dir -->

### nas1

The bench file server: a joined Samba member in a container, declared
only in its own overlay and opted into with an environment flag. A fixture and a
demonstration, not a product and not a name any deployment publishes; it takes
the DC's published `:445` for itself, so a deployment running it is one no
external file server can join.
<!-- refs: `deploy/compose.nas.yaml`, `NAS=1` -->
<!-- avoid: the member, the example member, the nas, the demo nas, the example file server, kerbridge-nas1, `kerbridge-member` -->

### overlay

A `compose.*.yaml` file applied to the base Compose file through the compose-file
environment variable. The repository has file-server, mock-IdP, CI isolation,
and stack-tier overlays. Order is significant because a later overlay narrows an
earlier one. Each [stack tier](#stack-tier) states its complete list -- the Entra
tier layers `compose.ci-entra.yaml` over the mock IdP, the authentik tier layers
`compose.authentik.yaml` in its place. Scripts do not use `-f`; they call plain
`docker compose`, so only the environment variable selects overlays.
<!-- refs: `COMPOSE_FILE`, `compose.nas.yaml`, `compose.mockidp.yaml`, `compose.ci.yaml`, `compose.ci-entra.yaml`, `compose.authentik.yaml` -->
<!-- avoid: compose file, extension file, fragment, profile -->

### provisioning

`samba-tool domain provision` in the realm entrypoint, on
first start only. It bakes the realm identity, the domain SID and the KDC keys
into the durable database, which is why nothing about the realm identity can be
corrected by editing configuration afterwards.
<!-- avoid: domain creation, realm creation, initialization -->

### public endpoint

The `:443` HTTPS path as a whole: TLS terminating, the
routes matching, and the broker answering behind them. The readiness script
calls its check `endpoint`, and it is one `GET /config` — asked by `kbmanage
endpoint`, which is the part of that report a deployment without Compose runs
too.
<!-- refs: `deploy/scripts/compose/wait-ready.sh`, `crates/kerbridge-manage/src/endpoint.rs` -->
<!-- avoid: the api, the ingress, the front door -->

### realm CA

The CA the realm container creates at provisioning and publishes
on its shared volume, which the broker and sync verify LDAPS
against. The kbmanage config script copies it into the generated secrets
for host-run tooling; it regenerates with the realm.
<!-- refs: `/run/kerbridge/realm-ca.pem`, `kbmanage-config.sh`, `secrets/generated/realm-ca.pem` -->
<!-- avoid: the internal ca, the ldaps ca, ca.pem -->

### realm identity

The values baked into the Samba database at
provisioning: realm, DNS domain, NetBIOS domain and
DC hostname. The one group a later edit cannot correct: fixing a forgotten one means
deleting the realm volume, and with it the domain SID and every filesystem ACL
carrying it.
<!-- refs: `AD_REALM`, `AD_DNS_DOMAIN`, `AD_NETBIOS_DOMAIN`, `AD_DC_HOSTNAME` -->
<!-- avoid: realm config, domain settings -->

### seed

The bench-only hand-provisioning of the source-OU content sync would
own in production, plus the resource groups and the share ACL.
Production never runs it, and it
refuses to run where the sync credential secret has content, because hand-
writing a second set of objects into a sync-owned OU is how an ambiguous
identity is created.
<!-- refs: `deploy/scripts/bench/seed-demo.sh`, `make seed`, `secrets/idp/<name>/credential` -->
<!-- avoid: demo seed, dev seed, fixture data -->

### setup service

The `setup` service in `compose.yaml`: `kbsetup` in a container that exists for
the length of one command, behind a `profiles:` key so `up` never starts it.
`docker compose run --rm setup directory` is what `make directory` runs, and it
is the same binary a [Debian deployment](../GLOSSARY.md#debian-deployment) runs
from `/usr/sbin/kbsetup`.

It has **default capabilities**, unlike every other container here, because
writing a credential at `0640 root:<daemon group>` needs `CHOWN` — and a
container that can act on files it does not own is by definition not hardened.
That is what it buys by being throwaway rather than a mount added to `realm`.
<!-- refs: `deploy/compose.yaml` @ `setup`, `make directory` -->
<!-- avoid: the bootstrap container, the provisioning container -->

### source list

`sources` in `main.toml`: the [sources](../GLOSSARY.md#source) this deployment
serves, named one by one and never matched by a wildcard. A source that vanished
from a glob would orphan every object it owns — [SIDs](../GLOSSARY.md#sid),
memberships, file ownership — with nothing reporting it.

It is also the enable switch. Drop a name and keep the file and that source stops
being mirrored and stops being served, with nothing in the
[directory (realm)](../GLOSSARY.md#directory-realm) touched; there is no `enabled` field. A
listed name with no file refuses to start, and a file no name lists is ignored
with a line saying so.
<!-- refs: `main.sources`, `kbconfig sources` -->
<!-- avoid: the sources array, enabled sources, the idp list -->

### stack

Every service the current compose-file list declares, taken
together. One make target brings it all up once the realm is bootstrapped, and
the readiness script reports "Stack is up."
<!-- refs: `COMPOSE_FILE`, `make stack`, `deploy/scripts/compose/wait-ready.sh` -->
<!-- avoid: the cluster -->

### stack tier

A script that sources `scripts/bench/provision.sh` for one identity source and
then runs source-specific assertions. A stack tier provides the prerequisites,
the `.env` fragment, the `idp_<source>.toml` body, and the final Compose overlay.
`ci-stack.sh`, which implements `make test-stack`, is the Entra stack tier;
`ci-authentik.sh`, which implements `make test-authentik`, is the authentik one.
Stack tiers use vendor names because the supported source types form a closed
set.
<!-- refs: `deploy/scripts/bench/ci-stack.sh`, `deploy/scripts/bench/ci-authentik.sh`, `deploy/scripts/bench/provision.sh`, `idp_prepare`, `idp_env_lines`, `idp_source_toml` -->
<!-- avoid: the CI profile, the idp profile, the test driver -->

### `state/`

The bind-mounted host directories the services write into:
per-component directories for the open-problem record and for the audit trail.
Bind mounts and not named
volumes because a fresh named volume is root-owned.
<!-- refs: `state/broker/`, `state/sync/`, `state/broker-audit/`, `state/issuer-audit/`, `state/sync-audit/` -->
<!-- avoid: runtime state, the data dir -->

### ticket policy

The lifetime and renewable lifetime a ticket is asked for,
and the ceiling that request is clamped to. The keys in `configs/realm.toml`:
`ticket_lifetime_seconds` and `ticket_renewable_seconds` are what the broker
asks for, `max_lifetime_seconds` and `max_renewable_seconds` are what `issuerd`
allows. Samba's own domain policy caps the result again below both.
<!-- refs: `configs/realm.toml`, `kerbridge_core::config::Realm` -->
<!-- avoid: ttl settings, ticket config, lifetime knobs, lifetime policy -->

### `TLS_STRATEGY`

The `.env` value naming where the public broker certificate
comes from: ACME over DNS (recommended), ACME with an inbound
challenge, or an operator-supplied pair. It selects a
Caddyfile *and* a Dockerfile build stage, so changing it needs a rebuild of
the Caddy image.
<!-- refs: values `acme-dns`, `acme`, `external`, `docker compose build caddy` -->
<!-- avoid: cert mode, acme mode, the tls setting, certificate strategy, tls mode -->
