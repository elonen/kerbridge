# What is configured in Entra

This page gives detail for
[step 2 (*Register three applications in Entra*) in SETUP.md](../../SETUP.md#2-register-three-applications-in-entra).
It holds what is common to both paths: what you create, the values it
produces, and the Entra defaults that are wrong for KerBridge. The procedure
itself is one of:

- **[entra-terraform.md](entra-terraform.md)** — recommended.
- **[entra-manual.md](entra-manual.md)** — the portal walk-through, or `az`.

## The `[provider_config]` values

The Entra app registrations and the group produce the values that
`configs/idp_entra.toml`'s `[provider_config]` table must contain. Each value
must match what Entra issued. A client id with a typing error, or a stale
group id, denies every login. Usually no value in the config set looks
incorrect.

| What | Why it exists | `[provider_config]` keys |
|---|---|---|
| **Broker API** (`KerBridge broker API`) | The audience of every `/ticket` token. It exposes the `access_as_user` scope and issues v2 tokens. It holds no credential — it only validates tokens. | `broker_api_client_id`, `scope` |
| **Public client** (`KerBridge public client`) | The native app that does the browser sign-in with auth-code + PKCE. It is public, thus it has no secret. | `public_client_id` |
| **Sync app** (`KerBridge sync`) | It reads users and groups from Graph, app-only and read-only. It needs a credential. | `sync_client_id` |
| **Admission group** (`KerBridge Allowed On-prem Users`) | Membership admits a user to the realm. Nothing works without this group: with no admission group, sync mirrors no users, and every sign-in fails with a 403. | `admission_group` *or* `admission_group_id` — one, never both |
| the tenant itself | | `tenant_id` |

Each display name is the key it fills, without the `_id` — thus
`KerBridge broker API` supplies `broker_api_client_id`. A display name is yours
to select and no config value holds one, but if you select your own, keep that
relation: the name in the portal is what tells an operator which of three
almost identical GUIDs goes in which key.

The admission group is bound by name **or** by id. If you set both values,
sync refuses to start. The name is only for the initial binding. After the
realm is bound, sync does not bind it again because of a name. The reason: if
a group is renamed or recreated, its name can resolve to a group that the
operator did not select. To point the realm at a different group, or to
correct an incorrect binding, put the Object ID of the correct group in
`admission_group_id` and remove the name. The id is an explicit
statement, that allows sync to ignore the changed name. Sync then retires
every user that the new group does not admit. This retirement is what a
repoint means.

## Entra defaults that are wrong for KerBridge

These defaults break a deployment with no error message. Terraform sets them
all correctly. The manual guide identifies each one at the step where it
occurs.

- **The broker API must issue v2 tokens.** The default for
  `requestedAccessTokenVersion` is `null`, which means v1. A v1 token has a
  different `aud` and `iss`. The broker accepts only v2 tokens, thus with the
  default it rejects *every* token. This is the most common setup failure.
- **The broker API needs its Application ID URI** (`api://{BROKER_APP_ID}`).
  That URI is the resource that the client requests. If the URI is not set,
  every token request fails with `AADSTS500011`. The portal does not let you
  add a scope without it, but a tool that drives Graph directly can leave it
  not set.
- **The public client needs the WAM redirect URI**
  (`ms-appx-web://microsoft.aad.brokerplugin/{CLIENT_APP_ID}`). Without it,
  the Windows sign-in path of the tray fails with a redirect-URI mismatch.
  The loopback URI must also be `http://127.0.0.1`, not `localhost`.
- **The sync app's Graph permissions need admin consent.** To add
  `User.Read.All` and `Group.Read.All` is not sufficient. Without the grant,
  the app-only token carries no roles, and every read fails with a 403.

> **CAUTION:** The `idtyp` optional claim is a security control — set it.
> Entra issues an app-only token with `aud = {BROKER_APP_ID}` to **any**
> confidential client in your tenant, with no grant, no consent, and no app
> role. This is the design of Entra, and you cannot turn it off. The presence
> of `scp` together with `idtyp != "app"` is the *only* mark that separates a
> real user from any service principal in your directory. Both paths request
> this claim. Do not remove it.

## Token signing is asymmetric, and not negotiable

The broker verifies a token's signature against the IdP's **published public
key**, and its list of accepted algorithms is compiled in: the RSA families
`RS*` and `PS*` today, and never any `HS*` or `none`. A key the provider
publishes with an `alg` of its own is held to that one algorithm.

Some providers offer *symmetric* signing as an ordinary option, keyed by a
shared secret. Configure a provider that way and every login is refused with an
opaque 401; the broker's log says `disallowed alg "HS256"` and nothing else does.
The fix is to give the provider an asymmetric signing key.

Two reasons it is not a setting. A verifier that trusted the token's own `alg`
would let anyone take the published public key, use those bytes as an HMAC
secret, and forge a token asserting any identity. And with an asymmetric
algorithm the broker holds only public key material, so it cannot mint an
identity even if it is completely compromised — which is the same reason KDC
authority lives in `issuerd` and not in the broker.

## What this does not touch

This setup does not change sign-in policy, conditional access, MFA, or
password state. Entra stays the only authority over *whether* a user can sign
in. KerBridge only learns *who* signed in and which groups they are members
of.

The flow of authority is one-way: Entra → KerBridge. If an attacker gets full
control of the broker host, the attacker gets no more *in Entra* than read
access to the names, groups, and memberships that the on-prem realm already
holds.

The one exception is on-prem, not in Entra. The sync credential is read-only in
Entra, but it writes to the realm directory: it creates the identities in
`OU=Entra,OU=CloudIdP` there and manages the admission group. See [Enable synchronization
(`broker-host.md`)](broker-host.md#enable-synchronization).
