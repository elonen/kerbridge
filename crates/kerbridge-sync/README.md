# kerbridge-sync — every cloud IdP into its own local IdP-specific OU

Reads the configured users and groups from Microsoft
Graph, works out what Samba AD should look like as a result, and applies the
difference over delegated LDAPS — stamping each object with the
`ExternalIdentity` the broker will later look it up by. Nothing else writes
an IdP-specific OU.

One process serves every source `main.toml` lists, taking them one at a time
and binding as each source's own account. Sequential rather than concurrent,
because a `sAMAccountName` is unique across the whole realm: two sources
allocating one at the same moment would each see the other's name as free.

## Why it is a separate service

- **Credentials.** A Graph read token and directory *write* privileges have no
  business in the interactive authentication path. The broker reads the
  directory; only this service changes it.
- **No second database.** Samba AD is the single source of truth for the
  external-to-realm mapping. This service persists only delta cursors and
  reconciliation state — rebuildable by a full resync, and nothing a login
  depends on.
- **It cannot delete.** The plan type has no delete op, so no plan — however
  wrong — can destroy an object. Deletion is the operator's, through `kbmanage`,
  which says what a lost SID costs: SIDs sit in durable filesystem ACLs and every
  member derives `uid = RID + range base` from them.

## How a cycle runs

- App-only token, then per-stream delta reads for users and groups. Delta entries
  are sparse patches merged into a local shadow, never whole objects; only an
  `@odata.deltaLink` ends a stream, and a `410` resync is handled apart from a
  `400` on a corrupt cursor.
- The shadow becomes a desired state: the syncable rule, the group closure
  reachable from the admission group, and any configured allowlist. **An account
  is created for a user a selected group holds and for nobody else** — everyone
  else in the tenant is read and dropped. Members and guests both qualify; an
  unrecognized `userType` fails closed. Leaving the closure therefore retires
  the account, which is what makes the OU readable as the admitted set. A
  pure planner diffs that against the current directory and emits an ordered op
  list — every op asserted to target a DN inside that OU, and a
  `sAMAccountName` collision refusing the whole cycle rather than half-applying
  it.
- **Any read that was not complete produces no plan at all** — including a 200
  with an empty page, which would otherwise look exactly like an emptied tenant
  and retire everyone. Freeze and alert instead.
- Users no longer in the admitted set go ACTIVE → DISABLED → RETIRED, renamed into a `_retired-`
  namespace that frees the live name and UPN. Retention holds the SID, not the
  name. Retirement also clears every device grant on the object, because a
  revocation that undid itself on re-adoption would not be one; disable
  deliberately does not, since a disabled account's grants are already inert and
  restoring access is usually the intent.
- The device-grant group, where a deployment names one, joins the closure roots
  and is marked with its own role marker, exactly as the admission group is. One
  deliberate difference: nothing about it freezes a cycle. Admission decides
  whether anyone gets a ticket at all; device grants are optional and already
  fail closed on their own, so an ambiguous marker there is an event and not an
  outage.
- Login names for **new** accounts are derived from one of three Entra
  attributes, chosen by `sam_source` in `configs/sync.toml`: `displayname` (default, every
  whitespace token joined by dots), `email_username` (the local part of Email, or of the first Other email — an
  account invited from another tenant has no Email in this tenant) or
  `upn` (the UPN local part, most unique). Each falls back to the others when
  its attribute yields no usable name -- absent, or nothing a
  `sAMAccountName` may keep. `displayname` is the default because an invited
  account's UPN embeds the source domain (`alice.anderson_gmail.com#EXT#@…`)
  and `.`/`_` are legal in a sam, so the domain cannot be told from a surname —
  it becomes `alice.anderson_gmail`, cut mid-domain. Not only guests, who sync
  rejects: a member invited from another tenant keeps that UPN. The display name takes every
  token rather than first-and-last, because first-and-last drops middle tokens
  and, on a Spanish double surname, keeps the *maternal* one and drops the
  paternal one that identifies the person. It imposes no ordering of its own:
  `山田 太郎` stays family-first. `deploy/configs/sync.toml.example` carries the
  full reasoning and `planner/tests/names.rs` pins each case with a test.
- **A live account's login name follows its Entra display name**
  (`automatic_sam_renames` in `configs/sync.toml`, default on). It is what
  Windows shows as the file owner and in the *Security* tab, so a person who
  changes their name and keeps the old login name has been failed by the
  directory. The cost is borne by that user alone and once: the sam is their
  Kerberos principal, so tickets issued under the old name stop working and
  they sign out and back in. Set the flag to `false` to freeze every live name
  instead, and rename by hand.
  `kbmanage cloud rename` pins a name against this — a `kbstate1|namepinned|`
  marker sync checks before recomputing — and `kbmanage cloud unpin` hands it
  back. It is the account's Kerberos principal, so
  re-deriving it would invalidate every ticket already issued to that user, and
  AD treats a sam as a stable logon name for the same reason. The only
  re-derivation of a *live* name is into the `_retired-` namespace — and back
  out of it. Reinstatement after retention re-derives rather than restoring what
  was stored, because the retirement rename is lossy (it keeps 11 characters, so
  `erno.jalonen` is held as `_retired-erno.jalone`) and because the freed name
  may since have been taken, which the `-<oid4>` fallback answers. The effect is
  that a retire/return cycle catches the login name up to the current display
  name: an account created as `민준.박` whose display name later became
  `민준 Park` returns as `민준.park`. Measured on the bench 2026-07-29. Names are derived through
  `kerbridge_core::sam`, which `issuerd` validates against — one rule, because
  two copies of it disagreed and non-ASCII users could sync but never sign in
  (research spike `unicode-name`).
- **Group login names carry a per-source suffix** (`group_suffix` in
  `configs/idp_<source>.toml`, no default, `none` for none). A group's
  `sAMAccountName` is unique realm-wide rather than per OU, so two cloud IdPs that each hold a `payroll` want one name
  — and the second sync to reach it refuses every cycle, mirroring no users
  either, until one is renamed upstream. Unlike a user's, a group name is never
  auto-disambiguated: it is what a share ACL may name, so sync refuses instead of
  renaming. The suffix is on the `sAMAccountName` only; the CN needs no help,
  being unique within its own OU already.
- Every cycle reports days remaining on the Graph credential; Entra credentials
  never auto-renew, and an expired one stops every read at once.

`DESIGN.md`
§ [Directory ownership and synchronization](../../docs/design/identity-and-directory.md#directory-ownership-and-synchronization)
and § [Graph credential lifetime](../../docs/design/identity-and-directory.md#graph-credential-lifetime).
Operator configuration is the `[provider_config]` block in
`configs/idp_<source>.toml`, the `secrets/idp/<name>/credential` file (empty
means "not configured yet" — that source idles), and [`SETUP.md`](../../SETUP.md)
steps 2 and 4.
