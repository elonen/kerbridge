# What is configured in authentik

This page is the authentik path for [step 2 (*Set up your cloud identity
provider(s)*) in
SETUP.md](../../SETUP.md#2-set-up-your-cloud-identity-providers). It is a
sibling of [entra.md](entra.md): same two faces, spelled the authentik way.

authentik splits the OIDC protocol from access control, so KerBridge's two
faces are:

1. **Sign a person in** — one **OAuth2 provider** and the **application** that
   fronts it. The agent signs in against the application as a public client on
   authorization code plus PKCE, with no secret.
2. **Read the directory one way** — a read-only **service account** with an API
   token, granted `view_user` and `view_group` globally through a Role.

You do not build these by hand. Everything above is one blueprint, and this
page is how to apply it and read back the two values only you can produce.

## Apply the blueprint

The whole fixture is [`authentik-blueprint.yaml`](authentik-blueprint.yaml) —
measured against a live instance, so paste it as written.

1. In the admin interface, go to **Customization → Blueprints → Create**.
2. Set the source to **Internal** and paste the file's contents. Leave
   *Context* empty and *Enabled* on. Internal storage is the only delivery that
   works without shell access to the authentik host — a file-based blueprint
   has to sit on a path the server can read, which a hosted or shared instance
   does not give you.
3. Save. **Creating the instance does not apply it.** The new row sits at
   `Unknown`, and left alone it waits for the hourly scheduler. Press **▶
   Apply** on the row to run it now, and confirm the status goes to
   `Successful`.

The blueprint re-applies on every scheduler run. That is deliberate, and the
`state:` on each entry decides what that costs you — see [Why the entries heal,
and what stays yours](#why-the-entries-heal-and-what-stays-yours).

### You edit nothing — with one exception

There are **zero required edits**. The one thing you may need to touch is the
signing key. authentik ships a self-signed certificate named `authentik
Self-signed Certificate`, and the blueprint names it. If your instance has more
than one signing certificate and you want a specific one, put its name on the
`signing_key` line. Otherwise leave the file alone.

The `client_id` and the application **slug** are fixed constants in the file,
both `kerbridge`. Unlike Entra, where these are GUIDs the platform generates,
authentik's are strings you write — so KerBridge pins them rather than reading
them back, and the matching `[provider_config]` values are already correct in
`configs/idp_authentik.toml`.

> **Why a Signing Key is mandatory, not advisory.** Without one, an authentik
> provider signs `HS256` with its client secret and publishes an empty JWKS.
> The broker accepts asymmetric algorithms only and refuses every such token
> with an opaque 401 — see the note on why token signing must be asymmetric in
> [entra.md](entra.md).
> The blueprint attaches the key so this cannot happen; do not remove it.

## The two read-backs

Two values are yours to fetch after the blueprint runs. Put both into this
source's `[provider_config]` in `configs/idp_authentik.toml`; that file's
comments carry the full rule for each.

### 1. The admission group's pk

The blueprint creates the group **KerBridge Allowed On-prem Users**. Open it in
**Directory → Groups** and copy its **pk** — a uuid — into `admission_group_id`.
Bind by the pk, not the name: a renamed group keeps its pk, while a name can
come to answer for a group you did not choose. Nothing works without this value:
with no admission group, sync mirrors no users and every sign-in is a 403.

### 2. An API token for sync

The blueprint creates the service account `svc-kerbridge-sync`, the Role
**KerBridge sync (read-only)** and its **global** grant — but it does **not**
create the token, because once created a token cannot be read back through the
API, so a blueprint could set it but never hand it to you.

Create it yourself, on `svc-kerbridge-sync`:

- **Intent must be `API`.** An *App password* token authenticates nothing here
  and fails byte-for-byte the way a wrong token does — a silent dead end.
- The **Identifier is a slug**, not a display name; give it something like
  `kerbridge-sync-api-token`.
- **Leave *Expiring* on.** With it off, `expires` is junk: KerBridge reads an
  API token's own expiry to warn you before it lapses, and an off `Expiring`
  makes that countdown read nothing.

Paste the token into the file named by `sync_credential_file`, never the config
itself.

> **The grant is global on purpose.** A per-object grant answers `200` with a
> silently shortened list, and against authentik's directory — where a deletion
> is only ever an absence from a full read — sync would reconcile everyone
> missing from that short list as having left. The blueprint's Role grants
> `view_user` and `view_group` across all objects so a partial read cannot
> masquerade as a complete one.

## The permissions trap: two keys, one name

> **WARNING — global vs object-level permissions.** In an
> `authentik_rbac.role` entry, the `permissions` **attribute** grants
> **global** permissions — permissions over every object of that type. A
> blueprint entry's own top-level `permissions:` **block**
> (`blueprints/v1/importer.py:366-375`) grants **object-level** permissions on
> that one entry only. They are two different keys with one name, and the
> obvious one is the wrong one. The landed blueprint uses the Role attribute,
> which is what makes sync's read complete. If you rebuild or edit the grant,
> put the permissions on the Role's `attrs.permissions`, not in an entry-level
> block.

## Why the entries heal, and what stays yours

A blueprint re-applies hourly, and each entry's `state:` decides what that
re-application does:

- **`state: present`** — on the **provider** and the **Role**. These carry the
  settings that fail *silently* when wrong, so they are re-applied every run and
  cannot drift: `sub_mode: user_uuid` (the default cannot be looked up through
  the REST API, so sync could never match a signed-in user to a directory
  entry), the Signing Key, the `offline_access` scope mapping (unattached, the
  scope is dropped without a word and the agent can never renew in the
  background), the regex loopback redirect, and the Role's global grant. None of
  these shows up in a token; the only signal that one is wrong is a login or a
  sync that quietly does not work. Re-applying them is the repair.
- **`state: created`** — on the **application**, the **group** and the
  **service account**. These are yours to rename, re-icon and bind policies to.
  The blueprint writes them once and never touches them again, so your changes
  stand.

## Where the values go

The rest of this source's setup is the config file, not authentik. See
`configs/idp_authentik.toml` (from `idp_authentik.toml.example`): it lists every
`[provider_config]` value, marks the ones you must supply, and explains the
derived URLs. The blueprint fills the authentik side; that file is the KerBridge
side.
