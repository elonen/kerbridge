# What is configured in Entra

This page is the Entra path for [step 2 (*Set up your cloud identity
provider(s)*) in
SETUP.md](../../SETUP.md#2-set-up-your-cloud-identity-providers). It holds what
is true on both paths: what you create, the values that it produces, and the
Entra defaults that are wrong for KerBridge.

Entra spells KerBridge's two faces — sign a person in, read the IdP directory
one way — as **three application registrations and one security group**, in
your one tenant. All three applications are read-only in Entra, and no
application is an administrator:

1. **Broker API app** — it validates the tokens that are addressed to it. It
   holds no credential.
2. **Public client app** — the app that signs users in over OIDC. It is native,
   and it has no secret.
3. **Sync app** — the only app with a credential. It can list users, groups and
   memberships. It can change nothing.

Select one path. The two paths give the same result:

| | |
| --- | --- |
| **[Terraform](entra-terraform.md)** — recommended | `terraform apply && ./print-provider-config.sh` creates all of it. It then prints a `[provider_config]` block for `configs/idp_entra.toml`. It needs `az login` to your tenant. |
| **[By hand](entra-manual.md)** | The steps in the portal, and an `az` script that gives the same values. Use this path if the Azure CLI cannot connect to your tenant. |

On both paths, you must also put the sync app's secret in place yourself. No
path does this for you —
[The sync credential (`entra-manual.md`)](entra-manual.md#the-sync-credential).

## The `[provider_config]` values

The app registrations and the group produce the values that the
`[provider_config]` table of `configs/idp_entra.toml` must contain. Each value
must match what Entra issued. A client id with a typing error, or a stale group
id, denies every login — and usually no value in the config set looks wrong.

| What | Why it exists | `[provider_config]` keys |
|---|---|---|
| **Broker API** (`KerBridge broker API`) | The audience of every `/ticket` token. It exposes the `access_as_user` scope and issues v2 tokens. It holds no credential, and it only validates tokens. | `broker_api_client_id`, `scope` |
| **Public client** (`KerBridge public client`) | The native app that does the browser sign-in with auth-code and PKCE. It is public, so it has no secret. | `public_client_id` |
| **Sync app** (`KerBridge sync`) | It reads users and groups from Graph, app-only and read-only. It needs a credential. | `sync_client_id` |
| **Admission group** (`KerBridge Allowed On-prem Users`) | Membership admits a user to the realm. Nothing works without this group: sync then mirrors no users, and every sign-in fails with a 403. | `admission_group_id` — the group's Object Id |
| The tenant | | `tenant_id` |

Each display name is the key that it fills, without the `_id`. So
`KerBridge broker API` supplies `broker_api_client_id`. A display name is yours
to select, and no config value holds one. But if you select your own, keep that
relation: the name in the portal is what tells an operator which of three
almost identical GUIDs goes in which key.

**Bind the admission group by its Object ID.** A display name is not a binding:
a group that is renamed or recreated keeps its Object ID, but its name can come
to belong to a group you did not select.

<details>
<summary>How to repoint the realm at a different group</summary>

Put the Object ID of the new group in `admission_group_id`. Sync then moves the
realm-admission marker onto it, and retires every user that the new group does
not admit. That retirement is what a repoint means.

</details>

## Entra defaults that are wrong for KerBridge

These defaults break a deployment and show no error message. Terraform sets
them all correctly. The manual guide names each one at the step where it
occurs:

- **The broker API must issue v2 tokens.** The default for
  `requestedAccessTokenVersion` is `null`, which means v1. A v1 token has a
  different `aud` and `iss`, and the broker accepts v2 tokens only. So with the
  default, the broker rejects *every* token. **This is the most common setup
  failure.**
- **The broker API needs its Application ID URI** (`api://{BROKER_APP_ID}`).
  That URI is the resource that the client requests. Without it, every token
  request fails with `AADSTS500011`. The portal does not let you add a scope
  before you set it, but a tool that drives Graph directly can leave it unset.
- **The public client needs the WAM redirect URI**
  (`ms-appx-web://microsoft.aad.brokerplugin/{CLIENT_APP_ID}`). Without it, the
  Windows sign-in path fails with a redirect-URI mismatch. The loopback URI
  must also be `http://127.0.0.1`, not `localhost`.
- **The sync app's Graph permissions need admin consent.** To add
  `User.Read.All` and `Group.Read.All` is not sufficient. Without the grant the
  app-only token carries no roles, and every read fails with a 403.

> **CAUTION: Set the `idtyp` optional claim, and never remove it.** It is a
> security control. Entra issues an app-only token with
> `aud = {BROKER_APP_ID}` to **any** confidential client in your tenant, with
> no grant, no consent and no app role. This is the design of Entra, and you
> cannot turn it off. The presence of `scp` together with `idtyp != "app"` is
> the *only* mark that separates a real user from any service principal in your
> IdP directory. Both paths request this claim.

## What this does not touch

This setup does not change sign-in policy, conditional access, MFA or password
state. Entra stays the only authority over *whether* a user can sign in.
KerBridge learns *who* signed in, and which groups that user is a member of.

Authority flows one way: Entra → KerBridge. If an attacker gets full control of
the broker host, that attacker gets no more *in Entra* than read access to the
names, groups and memberships that the on-prem realm already holds.

The one exception is on-prem, not in Entra. The sync credential is read-only in
Entra, but it writes to the realm directory: it creates the identities in
`OU=Entra,OU=CloudIdP` and it manages the admission group. See
[Enable synchronization (`broker-host.md`)](broker-host.md#enable-synchronization).

Entra always signs asymmetrically, so there is no signing-key choice to make on
this provider.

## Removing it

This is [step 9 (*Uninstall*) in
SETUP.md](../../SETUP.md#9-uninstall), for the Entra side.

On the Terraform path, `terraform destroy` removes all of it —
[Teardown (`entra-terraform.md`)](entra-terraform.md#teardown), which also says
what deleting the group costs you. By hand, delete the three application
registrations and the admission group, and revoke the sync app's secret if it
outlives the app.
