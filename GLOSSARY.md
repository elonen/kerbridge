# Glossary

This file defines terms that apply to the full repository. A term has the same
meaning in the code, the documentation, and the user interface.
Terms that apply to only one component are in these files:

| Scope | Glossary |
|---|---|
| Shared formats and rules. | [`crates/kerbridge-core/GLOSSARY.md`](crates/kerbridge-core/GLOSSARY.md) |
| Configuration options, defaults and templates. | [`crates/kerbridge-config/GLOSSARY.md`](crates/kerbridge-config/GLOSSARY.md) |
| Broker HTTP API. | [`crates/kerbridge-broker/GLOSSARY.md`](crates/kerbridge-broker/GLOSSARY.md) |
| Cloud IdP adapters: tokens and IdP directory reads. | [`crates/kerbridge-idp/GLOSSARY.md`](crates/kerbridge-idp/GLOSSARY.md) |
| IdP-directory-to-realm-directory synchronization. | [`crates/kerbridge-sync/GLOSSARY.md`](crates/kerbridge-sync/GLOSSARY.md) |
| Operator commands and diagnostics. | [`crates/kerbridge-manage/GLOSSARY.md`](crates/kerbridge-manage/GLOSSARY.md) |
| Ticket issuance and device grants. | [`crates/kerbridge-issuerd/GLOSSARY.md`](crates/kerbridge-issuerd/GLOSSARY.md) |
| Operator notifications. | [`crates/kerbridge-notify/GLOSSARY.md`](crates/kerbridge-notify/GLOSSARY.md) |
| Workstation behavior and user interface. | [`client/GLOSSARY.md`](client/GLOSSARY.md) |
| Test fixtures and tools. | [`testbench/GLOSSARY.md`](testbench/GLOSSARY.md) |
| Deployment configuration. | [`deploy/GLOSSARY.md`](deploy/GLOSSARY.md) |

If you add, change, or remove a term, update its glossary in the same commit.

### admission

Permission to have an on-premises account and to get Kerberos tickets. Membership
in the [`admission group`](#admission-group) gives admission. Admission does not automatically give access to a [file server](#file-server).
<!-- refs: marker `kbrole1|realm-admission` -->

### admission group

The group whose members have [admission](#admission) to the [realm](#realm).
[Sync](#sync) uses its cloud membership to select accounts. The [realm directory](#realm-directory)
must contain exactly one admission group.
<!-- refs: `admission_group_id` in `configs/idp_<source>.toml`'s `[provider_config]`, marker `kbrole1|realm-admission` -->
<!-- avoid: realm group, the first gate, the users group -->

### agent

The [workstation](#workstation) program that *runs in background*, gets and installs [tickets](#ticket)
for one user. The name in code and on disk is the agent. The name shown to users
is the *[NAS Access](#nas-access)* app.
<!-- refs: binary `kerbridge-agent` -->
<!-- avoid: helper, systray helper, winhelper.exe, tray, client app -->

### authentik

The cloud IdP product supported by KerBridge's authentik adapter. The product
styles its name `authentik`: lowercase, including at the start of a sentence
and in headings.
<!-- refs: `PRODUCT_NAME` in `crates/kerbridge-idp/src/authentik/mod.rs` -->
<!-- avoid: Authentik -->

### base_url

The field in the [broker's](#broker) `/config` reply that names which
[source](#source) an address reached, as a reference to resolve against the
address the reply came from — `/entra`, not a whole URL. The [client](#client)
sends that run's ticket, nonce and device requests to the result.

It answers the one question an address without a source segment leaves open. A
`_kerbridge._tcp` SRV record carries a host and a port and has nowhere to put a
path, so a client that found its broker in DNS asks a bare `/config`; the broker
answers it only where one source makes the answer unambiguous, and this is how
the reply says which one. Held for the run and never written to settings: a
stored copy pins a machine that is following DNS to whichever source answers
today.
<!-- refs: `Discovery` in `crates/kerbridge-broker/src/config.rs`, `BrokerConfig::base_url` in `client/kerbridge-client/src/discovery.rs` -->
<!-- avoid: source URL, prefix, broker base -->
<!-- different than: broker URL (what the operator hands out or DNS answers) -->

### bench

A disposable environment that represents a deployment. A bench can include the
Compose stack, test tools, and test [workstations](#workstation). Do not put data
that a person depends on in a bench.

### blueprint

An authentik YAML declaration of model objects, attributes, and relationships.
A blueprint instance imports it, and authentik reapplies it on its schedule.
Reapplication restores a `state: present` entry to the declared state. A
`state: created` entry is created once; later operator changes remain.
<!-- refs: `docs/setup/authentik-blueprint.yaml`; `testbench/authentik/blueprints/` -->

### broker

The KerBridge HTTP service that exchanges an [`identity proof`](#identity-proof) for a [ticket](#ticket).
It verifies the proof, finds one admitted account, and asks [issuerd](#issuerd)
to issue the ticket. The broker does not hold Kerberos keys or change the
[realm directory](#realm-directory).
<!-- avoid: the ticket api, the api service -->
<!-- different than: kerbridge server -->

### browser sign-in

A [sign-in](#sign-in) that opens the system browser. The browser gets an
[identity proof](#identity-proof) from the [cloud IdP](#cloud-idp) and returns it
to the [client](#client). A [device grant](#device-grant) can replace browser
sign-in for a limited time.
<!-- refs: OIDC authorization code with PKCE, loopback redirect, `kerbridge_client::oidc` -->
<!-- avoid: browser flow, web flow, interactive sign-in, interactive login, loopback flow, the entra login, `login` -->

### Caddy

The public HTTP service. It terminates TLS and sends [broker](#broker) requests
to the broker. It does not verify [identity proofs](#identity-proof).
<!-- avoid: the edge -->

### ccache

The byte format that carries Kerberos [tickets](#ticket) and their session keys.
The [broker](#broker) returns a ccache, and the [client](#client) reads it. A
ccache is not the operating system's `ticket cache`.
<!-- refs: MIT ccache v4, response field `ccache_b64` -->
<!-- avoid: credential cache, cred cache, cache blob, cache file -->

### client

A program that sends an [identity proof](#identity-proof) to the [broker](#broker)
and consumes the returned [ccache](#ccache). The [agent](#agent), the
[`kerbridge` CLI](#kerbridge-cli), and test scripts can be clients.
<!-- avoid: helper, tray -->
<!-- different than: agent (a backgrounded client) -->

### cloud identity

A [cloud IdP](#cloud-idp) user as seen by the on-premises system. [Sync](#sync)
creates a corresponding object in a [IdP-specific OU](#idp-specific-ou).
<!-- avoid: entra identity, the external user -->

### cloud IdP

The identity provider that is the authority for users and
groups. KerBridge has Entra and authentik adapters.

### Organizational Unit

The place in the LDAP [realm directory](#realm-directory) that contains an object.
KerBridge compares the parts of a distinguished name to test containment. It does
not compare text suffixes. Acronym: OU.
<!-- refs: `kerbridge_core::dn::parent_of` -->
<!-- avoid: container (confuses with Docker) -->

### IdP parent OU

The [OU](#organizational-unit) that holds one [IdP-specific OU](#idp-specific-ou) per
configured [cloud IdP](#cloud-idp), and nothing else. It is the boundary
[`kbmanage`](#kbmanage) and [`issuerd`](#issuerd) test against: everything inside
it is [sync's](#sync) to own, whichever cloud IdP that object came from.
<!-- refs: DN `OU=CloudIdP,<base DN>`; `configs/realm.toml` `idp_parent_ou` -->
<!-- avoid: cloud idp ou, the parent ou, the idp container, OU=Entra (that is one IdP-specific OU) -->

### IdP-specific OU

The [OU](#organizational-unit) one [sync](#sync) controls, directly under the
[IdP parent OU](#idp-parent-ou). Usually: `OU=Entra,OU=CloudIdP`. It contains
the users and groups that sync mirrors from one [cloud IdP](#cloud-idp). One per cloud IdP, each with its own
[`svc-kerbridge-sync-<source>`](#svc-kerbridge-sync-ltsourcegt) and written by
that account alone; the [operator's](#operator) resource objects are outside all
of them.

The split is not organizational tidiness: a [role marker](#marker) is
resolved by a subtree search that requires exactly one match, so two cloud IdPs
sharing an IdP-specific OU would give a broker two [admission groups](#admission-group)
and freeze every login.
<!-- refs: DN `OU=<source>,OU=CloudIdP,<base DN>`; `configs/idp_<source>.toml` `ou`; `issuerd` can write device grants; `kbmanage` can perform limited operations -->
<!-- avoid: source ou, entra base, the entra ou, the sync ou, the sync-owned container, OU=Entra (that is one IdP-specific OU's name, not the term) -->

### Debian deployment

KerBridge installed from `.deb` packages, with systemd running the daemons and
the distro's own `samba-ad-dc` providing the [realm](#realm). Debian 13 or
Ubuntu 24.04 and newer -- below that the distro's Samba cannot provision the
schema; the packages are the same bytes on both. The other way to run the
[server](#server) is a [Docker Compose deployment](#docker-compose-deployment).
<!-- refs: `debian/`, `/etc/kerbridge`, `kerbridge-issuerd.service` -->
<!-- avoid: native deployment, native install, bare metal, apt deployment, non-Docker -->

### delegate

A user who has [admission](#admission) and can authorize a device to work as another
account. The agent then stores a [device grant](#device-grant) to a TPM. The device then gets
[tickets](#ticket) for the target account, not for the delegate.
<!-- avoid: owner, proxy, second party, on-behalf-of caller, authoriser, impersonation -->
<!-- not to confuse: Entra ID delegated token -->

### delegate group

A group whose members can authorize devices for one target account. The group
must identify the target in `managedBy` and have the [delegate](#delegate) role
[marker](#marker). Each target has its own delegate group.
<!-- refs: marker `kbrole1|delegates` -->
<!-- avoid: delegates group, delegation group, managed group, owner group, device delegates, the managedby group -->
<!-- different than: device-grant group -->

### deriving name

The process that calculates a new account's login name, UPN, and CN from [cloud
identity](#cloud-identity) data. [Sync](#sync) uses one common rule to derive
and compare login names.
<!-- refs: `kerbridge_sync::planner::names::alloc_names`, `SamSource` -->
<!-- avoid: allocate name, generate name, compute name, mint name -->

### device grant

A time-limited TPM-stored record that lets one [workstation](#workstation) get [tickets](#ticket) without a new [browser sign-in](#browser-sign-in).
It belongs to one synchronized user and one key held by the workstation.
The grant-authorizing user must be a member of [delegate group](#delegate-group). The grant can identify another user.
This is why it's shown to end-users as *Authorize this device to work as user X*.
<!-- refs: encoding `kbkey1|`, `kerbridge_core::grant`, `configs/main.toml` `device_grant_days` -->
<!-- avoid: grant (bare), machine grant, TPM grant, device authorization -->

### device-grant group

The optional group that controls which target accounts can be target users of a [device grant](#device-grant).
Its members must also have [admission](#admission). KerBridge checks membership
at each [ticket exchange](#ticket-exchange).
<!-- refs: marker `kbrole1|device-grant` -->
<!-- avoid: grant group, device group, device grants group, the second gate -->
<!-- different than: delegate group -->

### Docker Compose deployment

KerBridge run as the `kerbridge` Compose project, which builds the [server](#server)
as containers and brings its own [Caddy](#caddy) and [realm](#realm) images. The
other way to run the server is a [Debian deployment](#debian-deployment).
<!-- refs: `deploy/compose.yaml`, `make up` -->
<!-- avoid: compose deployment, the Compose stack, the Docker deployment, dockerized -->
<!-- different than: stack (deploy/GLOSSARY.md), the services one compose-file list declares -->

### doctor

The [kbmanage](#kbmanage) command that checks access for one user or checks the
full [realm directory](#realm-directory). A failed check gives a nonzero exit status. A
warning does not.
<!-- refs: whole-directory mode `sweep` -->
<!-- avoid: diagnose, `diagnose_user` -->

### eligible

An existing synchronized account that [issuerd](#issuerd) can
use for a [ticket](#ticket) or a [device grant](#device-grant). The account must be a live user account. It must not
be disabled or be a machine account.
<!-- refs: `issuerd::issue::lookup`, `issuerd::grant::target` -->
<!-- different than: syncable (sync's account-creation gate) -->

### Entra app

An Entra application registration for one KerBridge component. KerBridge uses
separate apps for the [broker](#broker), [client](#client), and [sync](#sync), each with its own client ID and
only the permissions it needs.
<!-- refs: `kerbridge-broker`, `kerbridge-client`, `kerbridge-sync` -->
<!-- avoid: app registration, Entra application, Azure app -->

### enrollment

[Workstation](#workstation) configuration that tells the operating system about
the [realm](#realm). Windows needs machine-wide configuration. MacOS uses DNS.
Enrollment does not join the workstation to the realm and does not [sign in](#sign-in)
a user. Shown to end-users as *Windows setup* in agent UI.
<!-- refs: `kerbridge_client::enroll`, Windows `ksetup` -->
<!-- avoid: enrolment, realm registration, ksetup enrolment, realm setup, join, registration -->

### exchange

The [client](#client) term for one [ticket exchange](#ticket-exchange). An
exchange runs; the client does not "exchange" a [ticket](#ticket). It exchanges
an [identity proof](#identity-proof) for a ticket.
<!-- refs: `kerbridge_client::broker::fetch_ticket` -->
<!-- avoid: mint, fetch -->

### fail closed

Refuse an operation when required information is absent,
incomplete, or ambiguous. Do not guess a safe result.

### file server

A server that is joined to the KerBridge [realm](#realm) and provides
SMB shares. KerBridge does not install or manage file servers.
<!-- avoid: the nas, member server, the member, joined member -->

### give up grant

The action by which a [workstation](#workstation) removes its own [device grant](#device-grant).
The [client](#client) first deletes the local key. It then asks the [broker](#broker)
to remove the grant. Shown to users as *Remove authorization*.
<!-- refs: `kerbridge_client::session::revoke_this_device` -->
<!-- avoid: release, hand back, drop, unauthorize -->

### group suffix

What every [synced group's](#synced-group) [`sAMAccountName`](#samaccountname) from
one [source](#source) ends with — `payroll` becomes `payroll-entra` — so that two
[cloud IdPs](#cloud-idp) which each hold a group of the same name do not need the
same name in the realm directory.

It exists because a `sAMAccountName` is unique across the whole [realm](#realm),
not within an [IdP-specific OU](#idp-specific-ou). Without distinct suffixes, the
second [sync](#sync) to reach a shared name refuses its every cycle — mirroring no
users either — until an operator renames the group in one of the cloud IdPs.
The name a resource ACL carries is this one, so it is chosen before a source is
provisioned rather than after.

`none` is the literal spelling of *no suffix*, and is correct for a deployment
with one cloud IdP that accepts renaming its groups if it gains a second. An
empty string is not that spelling: this is a setting where "not decided yet" and
"deliberately empty" must not look alike, so the key has no default and the
empty value is refused.
Only the sAMAccountName carries it — the [CN](#organizational-unit) does not, since
that only has to be unique inside its own OU.
<!-- refs: `group_suffix` in `configs/idp_<source>.toml`; `kerbridge_sync::planner::names::group_names` -->
<!-- avoid: group prefix, name suffix, source suffix, the group tag -->
<!-- different than: source name (that is the storage key, not a display name) -->

### guest

A user whom another [tenant](#tenant) authenticates. KerBridge can synchronize
a guest in the same way as a tenant member. [Admission](#admission) of a guest
is an explicit [operator](#operator) choice.
<!-- avoid: external user, invited user, b2b user -->

### identity proof

Data that proves a caller's [cloud identity](#cloud-identity) to the [broker](#broker).
An Entra ID delegated token and a device assertion are identity proofs. Each proof
resolves to one external identity.
<!-- refs: `Authorization` schemes `Bearer` and `DeviceGrant`, `kerbridge_broker::http::Proof` -->
<!-- avoid: oidc proof, the token -->

### IdP directory

The users and groups that a [cloud IdP](#cloud-idp) exposes to [sync](#sync).
Each [directory source](crates/kerbridge-sync/GLOSSARY.md#directory-source)
reads one IdP directory. The adapter defines the protocol and the rules for
the read.
<!-- avoid: directory (bare), cloud directory, provider directory -->
<!-- different than: realm directory, which is the Samba AD data store -->

### IdP display name

What the [agent](#agent) calls a [cloud IdP](#cloud-idp) on screen — *Sign out of
Entra*. The [broker](#broker) publishes it in `GET /config` and the agent
substitutes it into `{idp}`; the [client](#client) carries no provider names of
its own, so this is the only way one reaches a screen.

The [adapter's](#cloud-idp) product name is the default, and an operator
overrides it. The name a workforce recognises is the one on the sign-in page they
were just redirected to, which is often neither the vendor's nor the
[source name](#source-name). Purely cosmetic: it reaches no realm directory
object and
is safe to change whenever.
<!-- refs: `configs/idp_<source>.toml` `provider_config.display_name`; `kerbridge_idp::OidcDiscovery::display_name` -->
<!-- avoid: idp name, provider name, tenant name, the brand -->
<!-- different than: source name (that is the storage key, and frozen) -->

### installable and untested

The third state a target release can be in, distinct both from supported and
from refused. The Debian packages install and their dependencies resolve there,
and nothing in CI ever starts what they installed. Ubuntu 24.04 is the live
case. Debian 12 and Ubuntu 22.04 are the *refused* one, for contrast: their
Samba cannot provision the schema `msDS-ExternalDirectoryObjectId` belongs to,
so `kbsetup realm` stops rather than building a realm that can hold no identity.

Say it of a release, never of a feature: a feature nobody tested is untested,
and the point of this term is that installability was measured while behaviour
was not.
<!-- refs: `docs/setup/debian-deployment.md`, the release table -->
<!-- avoid: best-effort, partially supported, unsupported -->

### injection

The action that puts a [broker](#broker)-returned [TGT](#tgt) in the current
user's operating-system Kerberos ticket cache. This lets standard SMB and Kerberos
[clients](#client) like Windows Explorer to use the [ticket](#ticket).
<!-- refs: `kerbridge_client::tickets::inject` -->
<!-- avoid: submit, submission, store, write, install, pass-the-ticket, ptt, import -->

### issuance

The step in which [issuerd](#issuerd) creates a [ticket](#ticket) for an account
that the [broker](#broker) selected. An issuance failure means that the broker
and issuerd disagree about that account.
<!-- refs: broker error `ticket issuance failed`, `kerbridge_broker::problems::issuer_failure` -->
<!-- avoid: mint, minting -->
<!-- not to confuse: certificate issuer, OIDC issuer field -->

### issuer (identity)

The [tenant](#tenant)-specific OIDC value that identifies who issued an
[identity proof](#identity-proof). The [broker](#broker) accepts only the
configured issuer. This term does not refer to [issuerd](#issuerd).

An authentication input, and deliberately not what objects are stored under —
that is the [source name](#source-name). For every cloud IdP except Entra an
operator can change the issuer, and a storage key that moved would orphan every
synchronized object.
<!-- refs: token claim `iss`, Entra form `https://login.microsoftonline.com/<tid>/v2.0` -->
<!-- avoid: token issuer, authority -->

### issuerd

The privileged KerBridge daemon that issues [tickets](#ticket), and records [device grants](#device-grant) to [realm directory](#realm-directory).
It runs on the same host as the [KDC](#kdc) and holds KDC authority. On Docker
Compose that is the `issuer` service, beside `realm`; on Debian it is
`kerbridge-issuerd.service`, beside `samba-ad-dc.service`.
<!-- avoid: the issuer, ticket issuer, the minter, the privileged half -->

### JWKS

The document that contains the [cloud IdP](#cloud-idp) public signing keys. The
[broker](#broker) uses these keys to verify [identity proofs](#identity-proof).
Configuration selects the document; a token cannot select it.
<!-- refs: `kerbridge_idp::jwks` -->
<!-- avoid: signing keys, the keys document, key set -->

### kbconfig

The server-side command-line tool that reads the [config
set](deploy/GLOSSARY.md#config-set). It validates the whole set offline, prints
one value by path, lists the active [source names](#source-name), and writes the
templates. On request it also probes a [cloud IdP](#cloud-idp).

A different tool from [kbmanage](#kbmanage) rather than a subcommand of it: it
runs before a realm exists, and it has no [realm directory](#realm-directory) rights and no
way to acquire any. The middle of [setup → config →
manage](#setup--config--manage).
<!-- refs: `crates/kerbridge-config`, `dist/kbconfig` -->
<!-- avoid: the config tool, config checker, kerbridge-config (the crate) -->
<!-- different than: kbmanage, kbsetup -->

### kbmanage

The server-side command-line tool for [operators](#operator). It manages
resource groups, [delegate groups](#delegate-group), login-name pins, and
[device grants](#device-grant). It also diagnoses the access path from a [cloud
identity](#cloud-identity) to a [file server](#file-server). The last of [setup →
config → manage](#setup--config--manage).
<!-- avoid: groupmgt, operator tool, operator tooling, the cli, group management cli, kerbridge-manage (the crate) -->
<!-- different than: client, kbsetup -->

### kbsetup

The server-side command-line tool that brings a deployment into existence, run as
root on the domain controller: the `setup` service on Docker Compose, or the
host itself on Debian. The verbs: `status` reports how far through the procedure
this host is and names the command for the next step, `realm` provisions the
[realm](#realm) if there is none and refuses if the one that exists disagrees
with the config set, `directory` creates the [OUs](#organizational-unit), the
[service accounts](#service-account-directory) and their
[delegation](deploy/GLOSSARY.md#delegation-directory-rights), `secrets` asks for
each [pasted credential](#pasted-credential) and writes it at the mode its reader
needs, and `verify` answers whether durable state still matches the config set.

The first of [setup → config → manage](#setup--config--manage). Its boundary
against the other two checkers is one question each: `kbsetup verify` asks
whether durable state matches the config set, [doctor](#doctor) asks whether an
identity can reach a [file server](#file-server), and `kbconfig check` asks
whether the config set is internally coherent.
<!-- refs: `crates/kerbridge-setup`, `/usr/sbin/kbsetup` -->
<!-- avoid: kbrealm, kbdirectory, `kbsetup provision`, the provisioning script, bootstrap tool -->
<!-- different than: kbconfig, kbmanage -->

### KDC

Kerberos Key Distribution Center. The KDC issues [TGTs](#tgt) and [service
tickets](#service-ticket). In KerBridge, the Samba AD domain controller provides
the KDC.

### KerBridge

The complete system and the name used in code, file names, and [operator](#operator)
documentation. The [workstation](#workstation) UI product has the user-facing name
*[NAS Access](#nas-access)* by KerBridge.
<!-- avoid: `Kerbridge` -->

### `kerbridge` CLI

The console interface to the same [client](#client) functions that the [agent](#agent)
uses. It performs one action at a time and shows its output. [Operators](#operator)
can use it to diagnose the agent. Not a background process, unlike [agents](#agent).
<!-- refs: `kerbridge.exe` on Windows, `kerbridge` on other platforms -->
<!-- avoid: the console tool, the cli, the command-line tool -->

### label

An untrusted display name that a [workstation](#workstation) gives to its
[device grant](#device-grant). KerBridge displays the label but does not use it
as an identifier. The stable identifier is an opaque hash.
<!-- refs: `kerbridge_core::grant::sanitize_label`, `MAX_LABEL` -->
<!-- avoid: name, device name, friendly name, machine label -->

### managed object

A user or group in a [IdP-specific OU](#idp-specific-ou) that has a valid external identity for
the configured [tenant](#tenant). [Sync](#sync) manages these objects.
<!-- refs: attribute `msDS-ExternalDirectoryObjectId`, `kerbridge_sync::directory` -->
<!-- avoid: entraobject, entra object, synced object, synchronized object, owned object, kb1 object -->

### marker

One value in the [realm directory](#realm-directory) `extensionName` attribute. Markers store
KerBridge roles, states, and [device grants](#device-grant) in LDAP. Components
must preserve the exact stored value. They start with string `kbrole1|`,
`kbstate1|` or `kbkey1|`.

Almost always on an object in a [IdP-specific OU](#idp-specific-ou). One
exception: the `kbrole1|delegates` marker lives on a
[delegate group](#delegate-group) in the [resource OU](#resource-ou) or elsewhere
outside the [IdP parent OU](#idp-parent-ou) — `kbmanage` reads and writes it there
directly, since nothing under an IdP-specific OU names that group.

Markers are a deep KerBrdige implementation detail. Usually not even [operator](#operator)
has to think about them, but could encounter them when browsing LDAP.
<!-- refs:  `kerbridge_core::state` -->
<!-- avoid: tag, flag, annotation, extensionname value, attribute value -->

### mockidp

An optional test service that replaces the [cloud IdP](#cloud-idp) for integration testing.
It is not part of a production deployment.
<!-- refs: `compose.mockidp.yaml`, `MOCKIDP=1` -->

### name pin

A [marker](#marker) that says an [operator](#operator) selected an account's
login name. [Sync](#sync) does not derive a new name for the user object while the pin exists.
Removing the pin returns control of the name to sync.
<!-- refs: marker `kbstate1|namepinned|<timestamp>`, `kerbridge_core::state::ST_NAME_PINNED`, `kbmanage cloud unpin` -->
<!-- avoid: name lock, locked name, frozen name, manual name, manual rename -->

### NAS Access

The user-facing name of the [agent](#agent) on Windows and macOS. Code,
binaries, directories, and operator documentation use the name "agent".
<!-- refs: `kerbridge_client::strings::app_name`, macOS display name `NAS Access by KerBridge` -->
<!-- avoid: NasAccess, nas-access, nasaccess, NAS access -->

### nesting

Placement of a [synced group](#synced-group) in a resource group. This connects
cloud group membership to [file-server](#file-server) access. Access-control
lists use the resource group's [SID](#sid). You can use the [kbmanage](#kbmanage) tool to do so.

### NTLM fallback

A Windows failure in which an SMB connection changes from Kerberos to NTLM after
a [TGT](#tgt) expires. The KerBridge [realm](#realm) cannot authenticate cloud
users with NTLM. A [repair](#repair) clears the failed connection state.
<!-- avoid: NTLM latch, stuck redirector -->

### operator

The person(s) who deploys and runs KerBridge. The operator controls the server,
[tenant](#tenant) configuration, DNS, [file servers](#file-server), and the
resource side of the [realm directory](#realm-directory). [Sync](#sync) controls the [IdP-specific OUs](#idp-specific-ou).
<!-- avoid: admin, administrator, sysadmin, user (in the person-running-the-tool sense) -->

### operator notification

A durable message about a [server](#server) condition that an [operator](#operator)
must correct. A delivery failure cannot fail a ticket request or a [sync](#sync)
cycle.
<!-- refs: `kerbridge-notify`, `NOTIFY <severity> <event>: <message>`, problem directory -->
<!-- avoid: alerting, the notifier, alarms -->

### pasted credential

A [secret file](#secret-file) whose value comes from outside KerBridge and that
nothing in the deployment can generate: a cloud IdP's application credential,
copied from that IdP's portal, and the webhook URL of an
[operator notification](#operator-notification) receiver. It is the half of
[`<secrets-dir>`](#secrets-dir) the [operator](#operator) writes, as against the
half [kbsetup](#kbsetup) generates under `generated/`.

`kbsetup secrets` asks for each one the [config set](deploy/GLOSSARY.md#config-set)
names and writes it at the mode its reader needs. It is asked for at a terminal
rather than at install time because a value that passes through debconf is
written to `/var/cache/debconf/config.dat` and again to the world-readable
`config.dat-old` — so every install question is a realm, a URL, a public
identifier or a group's object id, and none is a secret.
<!-- refs: `crates/kerbridge-setup/src/pasted.rs`; `<secrets-dir>/idp/<source name>/credential` -->
<!-- user-facing: the credentials you supply -->
<!-- avoid: operator secret, manual secret, the pasted secret -->
<!-- different than: generated credential -->

### prepare-state

The helper that creates every directory and empty credential file a deployment
needs before a daemon starts, shipped by `kerbridge-config` at
`/usr/libexec/kerbridge/prepare-state`. Both deployments run the same bytes: the
Debian package's `postinst` calls it directly, and the Docker Compose deployment
calls it in a throwaway root container, because a bind mount masks whatever an
install created underneath it and the hardened service containers cannot set the
ownership their own mounts need.

Internal, and the install path says so: `/usr/libexec/kerbridge/` promises
nothing outside this repository, while `/usr/sbin/` -- [kbsetup](#kbsetup) and
the daemons -- is operator-facing and documented.
<!-- refs: `crates/kerbridge-config/libexec/prepare-state`, `deploy/scripts/compose/bootstrap-secrets.sh` -->
<!-- avoid: the bootstrap script, bootstrap-secrets, the state helper -->
<!-- different than: kbsetup -->

### principal

The Kerberos name in a [ticket](#ticket). It has the form `name@REALM`.
KerBridge derives it from the account login name and the configured [realm](#realm).
<!-- avoid: upn, user principal name, client principal -->

### provision stamp

The file [kbsetup](#kbsetup) writes beside `sam.ldb` when `kbsetup realm`
finishes. `samba-tool domain provision` leaves a database behind when it exits
partway, so the database alone does not say that a [realm](#realm) exists: with
no stamp beside it, every verb refuses the realm instead of verifying it.
Samba starts on a half-provisioned domain and then reports a machine account it
cannot reach, which names nothing about provisioning.

A domain controller built by hand has no stamp either, and nothing is wrong
with it. The refusal states both readings: the stopped provision first, and
then the DC to adopt with `touch` once its operator is sure it serves the realm
the config set names.
<!-- refs: `/var/lib/samba/private/kerbridge-provisioned`, `kerbridge-setup/src/dc.rs` -->
<!-- avoid: completion marker, provision marker, provisioned flag -->
<!-- different than: marker -->

### quarantined group

The state of a synchronized group that no longer exists in the
[cloud IdP](#cloud-idp). [Sync](#sync) removes the cloud-managed members and
retires the name. It keeps the group and its [SID](#sid).
<!-- refs: marker `kbstate1|quarantined|<timestamp>` -->
<!-- avoid: quar, group retirement, group tombstone, soft-deleted group, emptied, dangling, archived -->

### realm

The Kerberos and AD authority that one deployment serves. The realm name is
uppercase in Kerberos [principals](#principal). Examples use realm name
`EXAMPLE.SITE`.
<!-- refs: `AD_REALM` -->
<!-- avoid: kerberos domain, kdc realm -->

### `realm` container

The Compose service that runs the Samba AD domain controller, [KDC](#kdc), DNS,
and [issuerd](#issuerd). Use [`realm`](#realm) without `<code>` formatting only
for the Kerberos authority.
<!-- refs: service `realm`, image and container `kerbridge-realm` -->
<!-- avoid (when talking about the Docker Container): dc, domain controller, the dc container, the domain container -->

### realm directory

The Samba AD data store. It contains identities, groups, [markers](#marker), and
[device grants](#device-grant). [Server](#server) components use this store to
share state.
<!-- refs: remote access by LDAPS; local issuer access to `sam.ldb` -->
<!-- avoid: directory (bare), ad, ldap, the dc, the sam -->
<!-- different than: IdP directory, which a directory source reads -->

### realm volume

The persistent Docker volume that contains the [realm directory](#realm-directory), KDC keys,
domain [SID](#sid), SYSVOL, and LDAPS certificate. Deletion of this volume
deletes the [realm](#realm).
<!-- refs: Compose volume `samba`, host volume `kerbridge_samba` -->
<!-- avoid: the samba volume, the database, the domain data -->

### repair

The user-approved action that restarts the Windows Workstation service to clear
[NTLM fallback](#ntlm-fallback). It disconnects all SMB sessions on the
[workstation](#workstation).
<!-- refs: service `LanmanWorkstation`, `kerbridge_client::repair::restart_workstation` -->
<!-- avoid: restartworkstation, restart workstation, restart the redirector, service restart, fix drives -->

### resource OU

The LDAP [realm directory](#realm-directory) [Organizational Unit](#organizational-unit) that the [operator](#operator)
controls. It contains resource groups and [delegate groups](#delegate-group). It
is outside the [IdP parent OU](#idp-parent-ou).
<!-- refs: default DN `OU=Resources,<base DN>`, `configs/realm.toml` `resource_ou` -->
<!-- avoid: ou=resources, the operator ou, the local ou, the delegated ou -->

### retired prefix

The `_retired-` prefix that [sync](#sync) adds to the login name of a retired
user or [quarantined group](#quarantined-group). This releases the old name for
a live object and keeps the old [SID](#sid).
<!-- refs: `kerbridge_core::state::RETIRED_PREFIX`, `kerbridge_sync::planner::names::retired_names` -->

### renew

The action that immediately runs a [ticket exchange](#ticket-exchange) with an
available silent credential and [injects](#injection) the returned [ticket](#ticket).
Shown to users as *Renew now*. It does not renew an installed TGT in place with [KDC](#kdc);
it gets a new one from [broker](#broker).
<!-- refs: `agent::commands::renew_now`, `Action::ReinjectTicket` -->
<!-- avoid: renew ticket, TGT renewal, re-inject -->

### revoke

Remove a [device grant](#device-grant). Revocation takes effect at the
[workstation's](#workstation) next [ticket exchange](#ticket-exchange). It does
not delete the local key, and a later [browser sign-in](#browser-sign-in) can
authorize the workstation again.
<!-- refs: `kbmanage device revoke`, `DELETE /devices/{handle}`, self-revocation in `crates/kerbridge-broker/src/devices.rs` -->
<!-- avoid: delete, unregister, deauthorize, withdraw, cancel -->
<!-- different than: give up grant -->

### `sAMAccountName`

The [realm directory](#realm-directory) attribute that contains the login name. KerBridge
uses one rule to create, validate, and compare this value. Informal code and
prose can use "a sam," but not "the SAM."
<!-- refs: `kerbridge_core::sam`; letters, digits, `.`, `-`, `_`; no leading `-`; maximum 64 bytes; NFC -->
<!-- avoid: sam, the sam, account name -->

### secret file

A file that contains one credential. KerBridge reads credentials only from
protected files under [`<secrets-dir>`](#secrets-dir), each named by path from the
[config set](deploy/GLOSSARY.md#config-set); no configuration file holds a
credential itself.
<!-- refs: `kerbridge_core::secret::read` -->
<!-- avoid: credential file, password file -->

### `<secrets-dir>`

The directory that contains one [secret file](#secret-file) per file, split by who
writes it. The [operator](#operator) puts theirs directly in this directory and in
`<secrets-dir>/idp/<source name>/`; KerBridge puts every value it generates under
`<secrets-dir>/generated/`, including a [source's](#source) `bind_password`, at
`<secrets-dir>/generated/idp/<source name>/`. Nothing writes into both halves. All
of it is outside the [config set](deploy/GLOSSARY.md#config-set).

The heading is the notation: documentation writes the placeholder and expands it
once per page, because only the path the operator types differs by method. The
config set names `/etc/kerbridge.secrets/…` in both, since a
[Docker Compose deployment](#docker-compose-deployment) mounts its tree there.

| Deployment | `<secrets-dir>` is |
|---|---|
| [Docker Compose deployment](#docker-compose-deployment) | `deploy/secrets/`, on the host, and git-ignored |
| [Debian deployment](#debian-deployment) | `/etc/kerbridge.secrets/` |

<!-- refs: `<secrets-dir>/idp/<name>/credential`, `<secrets-dir>/generated/idp/<name>/bind_password` -->
<!-- avoid: credential store, vault, the secrets volume -->

### server

The part of [KerBridge](#kerbridge) that runs on the Linux host. It includes the
[broker](#broker), [issuerd](#issuerd), [sync](#sync), [kbmanage](#kbmanage), the
[realm](#realm), and [Caddy](#caddy). Documentation calls it the *KerBridge
server*.
<!-- avoid: the stack, the broker stack, the compose project, the backend -->

### service account (authentik)

An authentik [IdP directory](#idp-directory) user object with type
`service_account`, used by software instead of a person. KerBridge's
`svc-kerbridge-sync` owns the sync API token and receives the global read-only
Role. It is not a [service account (directory)](#service-account-directory) or a
[service account (device grant)](#service-account-device-grant).
<!-- refs: `docs/setup/authentik.md`; authentik type `service_account` -->

### service account (device grant)

An ordinary cloud user account that an unattended machine uses to get [tickets](#ticket).
A [delegate](#delegate) authorizes the machine for this account. The account has
no [realm directory](#realm-directory) privileges.

### service account (directory)

An account that a [server](#server) component uses to access the [realm directory](#realm-directory).
These accounts have only the permissions that their components need. They are
outside the [IdP parent OU](#idp-parent-ou).
<!-- refs: `svc-kerbridge-broker`, `svc-kerbridge-sync-<source>` (one per cloud IdP), `svc-kerbridge-manage` -->
<!-- avoid: svc account, bind account, the delegated account -->

### service ticket

A [ticket](#ticket) for one Kerberos service, such as `cifs/<host>`. The
operating system gets it from the [KDC](#kdc) by use of a [TGT](#tgt). KerBridge
does not issue or process service tickets.
<!-- avoid: tgs ticket, cifs/ ticket -->

### setup → config → manage

The phases of a deployment's life, and the tools that own them:
[kbsetup](#kbsetup) brings it into existence, [kbconfig](#kbconfig) owns its
[config set](deploy/GLOSSARY.md#config-set), [kbmanage](#kbmanage) runs it day to
day. Say which phase a job belongs to before asking which tool should grow a verb
for it.

The phases are the reason these are separate programs rather than one with
a noun group each. `kbsetup` runs as root on the domain controller and creates
things that cannot be uncreated; `kbmanage` runs on an [operator's](#operator)
own workstation as themselves; `kbconfig` runs before either has anything to talk
to.
<!-- avoid: the CLIs, the tool chain, bootstrap/config/admin -->

### SID

The Windows security identifier of a [realm directory](#realm-directory) object. It stays
stable when the object name changes. File-system access-control lists use SIDs.
<!-- refs: form `S-1-5-21-...`; issuer protocol account key; `idmap_rid` input -->
<!-- avoid: objectsid, security identifier -->

### sign-in

Get an [identity proof](#identity-proof) for the caller's [cloud identity](#cloud-identity).
A sign-in can use the browser or the operating system. It gets a cloud access
token; it does not get a Kerberos [ticket](#ticket). Shown to
users as *Sign in* when they don't have access, or as *Extend access* when
 they already have a ticket.
<!-- avoid: signin, log in, logon, login, auth -->
<!-- different than: authorization -->

### sign off

Remove this [realm's](#realm) [tickets](#ticket) from the [workstation](#workstation).
It does not [sign out](#sign-out) or remove the [device grant](#device-grant).
<!-- refs: `agent::commands::drop_ticket` -->
<!-- avoid: `DropKrbTicket`, log out, disconnect, drop tickets -->
<!-- different than: sign out, give up -->

### sign out

The action that ends the [agent's](#agent) session with the [cloud IdP](#cloud-idp).
It does not remove Kerberos tickets, a [device grant](#device-grant), or an
operating-system account. Use [sign off](#sign-off) to remove tickets. Shown to
users as *Sign out of Entra*.
<!-- refs: `agent::commands::sign_out_entra` -->
<!-- avoid: cloud logout, logout, entra sign-out -->
<!-- different than: sign off, give up -->

### source

One configured [cloud IdP](#cloud-idp) within a [realm](#realm), as everything
on the on-premises side sees it: its own [IdP-specific OU](#idp-specific-ou), its
own [`svc-kerbridge-sync-<source>`](#svc-kerbridge-sync-ltsourcegt) account, and
its own [source name](#source-name). One [sync](#sync) and one
[broker](#broker) serve every source; each reconciles and answers for one source
at a time, and leaves every other source's objects untouched.

Its settings are one `configs/idp_<source>.toml` in the
[config set](deploy/GLOSSARY.md#config-set), and `main.toml`'s
[source list](deploy/GLOSSARY.md#source-list) is what makes it exist: a file no
name lists is neither loaded nor served. So a deployment adds a source with a
config file (`configs/idp_<source>.toml`) and a secrets directory
(`secrets/idp/<source>/`), and edits nothing tracked.
<!-- refs: `kerbridge_core::Source`, `configs/idp_<source>.toml` -->
<!-- avoid: tenant (that is an Entra thing), idp instance, provider instance -->

### source name

The name a [source](#source) is stored under: the same string as its [IdP-specific OU](#idp-specific-ou)
(`entra`, `google`), and field 2 of a `kb1|` identity. Unique by construction,
because a name is assigned per configured source within one realm.

Deliberately **not** the issuer URL. An issuer is an authentication input — the
adapter compares a token's `iss` against it, and every IdP except Entra lets an
operator change it — while a source name is a storage key. Conflating them
forces a mutable external string into permanent storage.

**Frozen at first provisioning.** Changing it rewrites every stored identity,
orphaning every synchronized object and detaching every file whose owner
`idmap_rid` derived from that object's SID. Silent and unrecoverable.

The name→[source](#source) binding is a configuration invariant the stored value
does not enforce. Pointing an existing name at a *different* Entra tenant is not
silent — the new tenant's object ids share none of the old ones, so
sync retires every account and creates a replacement, which is loud — but it
costs every SID and therefore every file's owner, exactly as renaming the source
name does. Give a new tenant its own name and its own OU. What records the
binding is `idp_<name>.toml`, and nothing in the realm directory restates it.
<!-- refs: `kerbridge_core::Source` -->
<!-- avoid: source alias, alias, idp alias, provider name -->

### svc-kerbridge-sync-&lt;source&gt;

The [realm directory](#realm-directory) account that [sync](#sync) uses for writes — **one per
cloud IdP**, named for the IdP it reads, so the Entra deployment's is
`svc-kerbridge-sync-entra`. Each has delegated write access to that IdP's OU and to no
other, which is what keeps one IdP's sync from rewriting another's objects. Other
components do not have this set of permissions.
<!-- avoid: svc-sync, svc-sync-<source>, the bind account -->
<!-- more generally: service account for sync -->

### sync

The KerBridge daemon that reads selected users and groups from a
[IdP directory](#idp-directory). It makes the source's
[IdP-specific OU](#idp-specific-ou) match the read. An adapter reads the
IdP directory. Sync writes to the [realm directory](#realm-directory) with
LDAPS.
<!-- refs: crate and service `kerbridge-sync`; realm directory accounts `svc-kerbridge-sync-<source>` -->
<!-- avoid: reconciler -->

### syncable

The cloud-side rule that decides if [sync](#sync) can create an
on-premises account for an object. KerBridge accepts Entra users of type
`Member` or `Guest`. It rejects unknown types, devices, and service principals.
<!-- refs: `kerbridge_idp::entra::wire::user_syncable` -->
<!-- avoid: eligibility, eligibility policy, qualification -->
<!-- different than: eligible -->

### synced group

A group in a [IdP-specific OU](#idp-specific-ou) that represents a [cloud IdP](#cloud-idp) group.
An [operator](#operator) nests it in a resource group to give access to a resource.
<!-- avoid: synced entra group -->

### tenant

The Entra [IdP directory](#idp-directory) that a deployment reads and trusts. Its GUID
identifies it. The [broker](#broker) and [sync](#sync) must use the same tenant.

An Entra concept, and not the same thing as a [source](#source): a tenant is what
one source's adapter is pointed at, and it is named in that source's
configuration rather than in every stored identity. An `oid` is unique per
tenant, so once the adapter has pinned `tid` to the configured tenant the `oid`
alone is a sufficient key — which is why the identity does not carry the tenant.
<!-- refs: token claim `tid`, `tenant_id` in `configs/idp_<source>.toml` -->
<!-- avoid: the org, organization -->
<!-- different than: an authentik instance; authentik no longer uses tenant as its product name -->

### test tier

One `make test-*` target, with its own cost, its own prerequisites and its own
CI job. They range from `test-fast`, which needs no Docker and no network, to
`test-deb`, which installs the packages on every Debian release the docs make a
claim about. `make test-all` runs every tier except `test-mac`, which needs a
Mac. A tier that cannot run on this host says so rather than passing quietly.

A tier is not a set of cases: the verifier conformance suite is a set of cases
*inside* `test-fast`.
<!-- refs: `Makefile`, `.github/workflows/ci.yml` -->
<!-- user-facing: which tests you can run -->
<!-- avoid: test suite, test level, test stage -->
<!-- different than: conformance suite -->

### TGT

Ticket-Granting Ticket, a Kerberos term. The [client](#client) uses a TGT to ask the [KDC](#kdc)
for [service tickets](#service-ticket). The [broker](#broker) returns one TGT in
each successful [ccache](#ccache), and the client [injects](#injection) it into
the operating system.
<!-- avoid: kerberos ticket, cloud tgt, ticket-granting ticket -->

### ticket

Data from a [KDC](#kdc) that proves identity or permits access to a service. A
[TGT](#tgt) lets a [client](#client) request [service tickets](#service-ticket).
A service ticket permits access to one service. Shown to users on help page only
as **pass** (an analogy).
<!-- avoid: pass (anywhere other than the help page analogy) -->


### ticket exchange

One request in which a [client](#client) sends an [identity proof](#identity-proof)
to the [broker](#broker) and receives a [ccache](#ccache) with a [ticket](#ticket).
KerBridge checks [admission](#admission) and other current authorization at each
[exchange](#exchange).
<!-- refs: `POST /ticket` -->
<!-- avoid: ticket request, the ticket call, exchange path -->

### unmanaged object

An object in a [IdP-specific OU](#idp-specific-ou) that is not a [managed object](#managed-object).
[Sync](#sync) reports it as a conflict and does not change it.
<!-- avoid: unowned object, stray object, stray, orphan, untouched object -->

### Windows sign-in

A [sign-in](#sign-in) that gets a cloud [identity proof](#identity-proof) from
the Windows token store without opening a browser. If it cannot get a proof, the
[client](#client) uses [browser sign-in](#browser-sign-in). The [agent](#agent)
cannot sign out the Windows account. In technical details: WAM.
<!-- refs: `Host::native_token` -->
<!-- avoid: native token, `NativeToken`, native sign-in, silent sign-in -->

### workstation

The user's computer that runs the [agent](#agent). It must be unjoined or
Entra-only-joined. It must not join the KerBridge [realm](#realm).
<!-- avoid: the pc, the endpoint -->
<!-- different than: client -->
