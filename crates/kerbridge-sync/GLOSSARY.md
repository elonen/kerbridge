# kerbridge-sync glossary

The Entra-to-source-OU reconciliation loop: reading Graph, planning and
applying — the read/plan/apply cycle and the directory state it reasons about.

Part of the repo-wide vocabulary in [`GLOSSARY.md`](../../GLOSSARY.md) — a term
means the same thing there and here. It lives in this file, closest to where
it's used, rather than in the root file, because the root file would be
unreadably long if it carried every term at once.

### admitted

Effectively inside the `admission group`, transitively: the state
that earns a cloud user an on-prem object and lets the broker issue for them. A
user can be syncable in Entra — a `Member` or `Guest` sync would mirror —
without being admitted.
<!-- avoid: enrolled, entitled, allowed in -->

### admitted set

The users an on-prem account exists for: those a selected
group holds and the syncable rule admits, which is exactly what the IdP-specific OU contains.
Leaving the admission-group closure therefore retires the account rather than
only dropping its memberships.
<!-- refs: `kerbridge_sync::graph::build_desired` -->
<!-- avoid: synchronized set, the admitted, managed set -->

### alert

A planner finding routed to a named operator channel by its kind —
`AdmissionGroup`, `DeviceGrantGroup` or `Note` — rather than by re-deriving the
class from the message text at the notification boundary. An `AdmissionGroup`
alert reports a whole-run freeze: the plan comes back with no ops at all and the
broker fails closed on the role marker.
<!-- refs: `kerbridge_sync::planner::AlertKind` -->
<!-- avoid: warning, escalation -->

### allowlist

Extra Entra group object ids synchronized beyond the admission-
group `closure`, named directly by the operator.
They are closure roots like the admission group itself, so their nested groups
come with them.
<!-- refs: `extra_group_ids` in `configs/idp_<source>.toml`'s `[provider_config]` -->
<!-- avoid: extra group ids -->

### apply

Writing a `plan (sync)`'s ops to the directory in order, as `svc-
sync` over LDAPS. A failed op is recorded in the apply report's failures and the
rest proceed, so one bad write cannot strand the others.
<!-- refs: `ApplyReport::failures`, `kerbridge_sync::directory::Directory::apply` -->
<!-- avoid: apply_plan, commit, execute, push -->

### automatic sam rename

Whether a live account's `login name` follows its
Entra display name after creation — default on.
It costs that one user a sign-out, because the name is their Kerberos
`principal`; `kbmanage cloud rename` stamps `kbstate1|namepinned|` in the same
modify to hold an operator's own choice against it, and `kbmanage cloud unpin`
hands the name back.
<!-- refs: `automatic_sam_renames` in `configs/sync.toml` -->
<!-- avoid: auto rename, name drift -->

### bind by id

Naming the admission or device-grant group by its immutable
Entra object id instead of a display name; setting a name beside an id is
refused at startup. An
id is an identity, so sync moves a role marker found on the wrong group to obey
it, where a resolved display name only freezes the cycle. A different operation
from a `name pin`, which freezes a value against recomputation rather than
selecting by a key.
<!-- refs: `admission_group_id`, `device_grant_group_id` in `configs/idp_<source>.toml`'s `[provider_config]` -->
<!-- avoid: pin, pinned, pinning the group, pinned id, id pin, id override, admission_pinned -->

### closure

The set of Entra groups reachable from the `admission group` and
the `allowlist` through nested group membership; it is the whole answer to who
has a directory object here, not merely who may get a ticket. Direct edges are
mirrored as-is and nesting is resolved by Samba, not flattened here; leaving the
closure therefore retires the account rather than only dropping its memberships.
<!-- refs: `kerbridge_sync::graph::build_desired` -->
<!-- avoid: selected, group closure, selected set, expansion -->

### CN

The first RDN value of a directory object's DN, and what ADUC shows.
Sync derives it from the display name, not from the login name, and unlike a
`sAMAccountName` it carries no length limit worth enforcing.
<!-- avoid: common name, new_cn -->

### complete read

The caller's assertion that the Graph read behind a `desired
state` actually finished; false refuses the whole plan. A `200` with an empty
page still asserts complete, which is why the empty-expansion freeze — no users
desired while accounts are synchronized — is a separate guard in the planner.
<!-- refs: `Desired::complete`, `PlanError::PartialRead`, `kerbridge_sync::planner::plan_sync` -->
<!-- avoid: complete flag -->

### conflict

A per-object finding sync reports but will not act on: an
`ambiguous identity`, an unmanaged object inside the IdP-specific OU, a `foreign member`,
or a conflicted object's membership left frozen. Conflicts ride beside a plan
that still applies — freeze at per-object radius, unlike the whole-run freeze an
`alert` carries. Plain strings on the plan.
<!-- refs: `Plan::conflicts` -->
<!-- avoid: warning, issue -->

### corrupt cursor

A stored `delta cursor` Graph rejects with `400` on a
request that carried one; sync discards it and reads fresh. Distinct from a
`resync` (`410`) and from a `400` on a URL built here from constants, which is a
fault to surface rather than a cursor to throw away.
<!-- refs: `StreamResult::CursorCorrupt` -->
<!-- avoid: cursorcorrupt, corrupt, rejected cursor, bad token -->

### current state

What the directory actually holds: everything under
the IdP-specific OU plus a domain-wide `sAMAccountName` scan for collision-safe naming.
Only objects carrying a `kb1` identity for the configured `tenant` reach the
user and group maps; the rest land in the unmanaged set, reported and never
touched.
<!-- refs: `kerbridge_sync::planner::Current`, field `unmanaged_dns` -->
<!-- avoid: current, actual state, live state, on-prem state, dump_current -->

### cycle

One read / plan / apply pass, repeated after a pause. A cycle plans
whole or is discarded — an `incomplete read`, an ambiguous admission marker or a
`sAMAccountName` collision refuses the entire plan — but once applying has
started a failed op is recorded and the remaining ops still run.
<!-- refs: `run_cycle` in `crates/kerbridge-sync/src/main.rs` -->
<!-- avoid: run, pass, iteration, tick -->

### delta cursor

The `@odata.deltaLink` stored at the end of a completed
stream read and replayed at the start of the next `cycle`. Cursors are per
stream — a groups cursor is not a users cursor — and nothing a login depends on.
<!-- avoid: cursor, delta token, deltalink, resumption cursor, sync state -->

### delta entry

One object as it arrives on a delta stream: a *sparse* patch
carrying only the properties and membership edges that changed, never a whole
object. Absent is not empty.
<!-- avoid: delta slice, sparse patch, change -->

### desired state

The on-prem target: what the IdP-specific OU should contain once
the syncable rule and the admission-group closure have been applied to the shadow —
never the raw Graph read. Carries its own `complete read` assertion.
<!-- refs: `kerbridge_sync::graph::build_desired`, `planner::Desired` -->
<!-- avoid: desired, target state, wanted state, cloud state, source state -->

### disambiguation suffix

The short object-id fragment appended when a name is
already taken: `John Doe (8b21)` in the CN, `jdoe-8b21` in the `sAMAccountName`.
Allocated by sync when it needs one, unlike the operator's `group suffix`, which
is on every group name in the source whether anything collides or not.
<!-- avoid: oid prefix, mangling -->
<!-- different than: group suffix (root GLOSSARY) -->

### display-name collision

Two distinct cloud users sharing one `displayName`,
which forces distinct on-prem CNs and login names. The committed corpora hold a
permanent pair to keep the case alive; not the same thing as a `collision`,
which is about the derived name already being taken.
<!-- avoid: duplicate name, duplicate-name pair -->

### dry run

The cycle reads, plans and logs every op it
would apply, and applies nothing.
<!-- refs: `dry_run` in `configs/sync.toml` -->
<!-- avoid: dry-run, would apply, no-op mode, simulate -->

### foreign member

A group member whose DN sits outside the IdP-specific OU and was
therefore put there by an operator. Reported as a `conflict` and left in place,
never removed — including when the group is quarantined, where it survives as
the `clear_members` keep-set.
<!-- avoid: external member, outside member, non-entra member -->

### foreign sam

A `sAMAccountName` present in the domain but outside
the IdP-specific OU and unmanaged by sync: built-ins, the DC machine account, `krbtgt`,
service accounts — and every object another cloud IdP's sync owns, since the
scan is domain-wide. It constrains name allocation and nothing else — it is the
namespace a derived name must not collide with.
<!-- avoid: unmanaged sam, domain sam, reserved names, builtins -->

### freeze

Refusing to act at all rather than risk the wrong action when the
role-group state is ambiguous; operator text says `FROZEN`. It has two blast
radii: whole-run, where the planner returns an empty plan
and an admission alert, and per-object, where one conflicted member's membership
is withheld while the rest of the plan applies.
<!-- refs: `kerbridge_sync::planner::plan` -->
<!-- avoid: blocked, block, halt, guard, conservative freeze -->

### graph credential

The app-only client secret sync authenticates to
Microsoft Graph with, read from a secret file: an empty file
is the whole of "sync not configured", and writing content into it starts
synchronization on the next poll, with no switch and no restart. It never auto-
renews, an expired one stops every read at once, and its expiry is an operator's
configured assertion rather than a measurement.
<!-- refs: `secrets/idp/<name>/credential`, `SourceConfig::credential` in `crates/kerbridge-sync/src/config.rs`, `sync_credential_expires` in `configs/idp_<source>.toml`'s `[provider_config]` -->
<!-- avoid: sync credential, the sync credential, entra credential, graph secret, secret value, secret id -->

### hard delete

Graph's permanent, non-restorable removal, reported as
`@removed.reason: "deleted"`. The same reason string also marks a membership
removal inside `members@delta` where the member object still exists, so the
reason alone does not say an object is gone.
<!-- avoid: harddeleted, purge, permanent delete -->

### held (group membership)

Said of an Entra user a selected group actually
contains; everyone else in the tenant is read and dropped, so an account exists
for a held user and for nobody else. Held is independent of `syncable` — a
held but unsyncable user is reported as a refusal, not created.
<!-- avoid: member, in the closure, admitted -->

### held (retention)

Kept in the directory after Entra stopped listing the
object, so the SID survives and a returning identity comes back to its own
files. Only the SID is held: the name is released in the same cycle, and
`kbmanage doctor` warns (`name still held`) when a retired object still carries
a live-form `sAMAccountName`.
<!-- avoid: retained, in retention, held-age -->

### incomplete read

A Graph stream read cut short by the read deadline,
having been throttled or paged past it, and therefore no evidence that anything
is absent. Nothing may be planned from one: the
`cycle` is discarded and counted toward the consecutive-failure alert.
<!-- refs: `StreamResult::Incomplete` -->
<!-- avoid: partial read, partial-read refusal, incomplete -->

### op

One reconciliation action targeting exactly one DN inside the IdP-specific OU:
`create_user`, `create_group`, `add_member`, `remove_member`, `enable_user`,
`disable_user`, `rename`, `set_attr`, `set_marker`, `set_role_marker`,
`clear_marker`, `clear_members`. There is
deliberately no delete op, so no plan — however wrong — can destroy an object;
deletion is the operator's, through `kbmanage`.
<!-- refs: `kerbridge_sync::planner::Op` -->
<!-- avoid: action, operation, change, mutation, step -->

### plan (sync)

The ordered `op` list a `cycle` will apply, together with its
conflicts and alerts; a pure function of `desired state` and `current state`.
Present with empty `ops` means there is
nothing to do; no plan at all means planning was refused.
<!-- refs: `kerbridge_sync::planner::plan_sync` -->
<!-- avoid: diff, changeset, op list -->

### reappearance

A retired or quarantined object returning to desired state
while its state marker is still on it: the marker is cleared and a user re-
enabled rather than a fresh object created, so the SID and the files under it
survive. The name is re-derived through the ordinary allocator, not restored,
because the retirement rename is lossy and the freed name may have been taken
since.
<!-- avoid: reinstatement, restore, return, revival, undelete -->

### retired

The state of a user sync no longer sees in Entra: disabled, marked
`kbstate1|retired|<timestamp>`, every device grant cleared, and renamed —
`sAMAccountName` and UPN both — into the `_retired-` namespace, so the live name
is freed and only the SID is held. Retirement is a revocation that must not undo
itself on re-adoption, so `issuerd` refuses every grant verb on a retired
account; the group equivalent is `quarantined`. Sync itself never deletes.
<!-- avoid: deleted, deprovisioned, deactivated, archived, tombstoned, soft-deleted, offboard -->

### recycle bin

Graph's `/directory/deletedItems`, where a soft-deleted object
waits out its 30 days. Soft-deleted security groups report `securityEnabled:
false` there, so they are told apart by `groupTypes` being empty.
<!-- avoid: deleteditems, deleted items -->

### repoint

Moving the admission role marker to a group the operator has newly
bound by id. Only a group bound by id repoints; one resolved from a display name
freezes the cycle instead, because a name is not an identity. The move is clear-
then-stamp, so a partial apply leaves too few markers rather than too many.
<!-- avoid: remark, re-stamp, marker move, redirect -->

### resync

A full read from scratch with no cursor, forced when Graph answers
`410` because the stored cursor aged out (>7 days). Both streams resync
together, from an emptied shadow, and the cycle retries at most once.
<!-- avoid: full read, full resync, fresh delta -->

### retention

The holding of a retired or quarantined object for its SID,
which durable filesystem ACLs and every `uid = RID + range base` derivation
depend on. Deliberately not a window: age is reported, never gated on, because a
lost SID does not become cheap with age. The *name* is not held — the object is
renamed into the `_retired-` namespace.
<!-- avoid: grace period, retention window, retention period, ttl, expiry window, tombstone -->

### safe name

A display name reduced to something a DN parser and AD both
accept: control characters and the union of RFC 4514's RDN-reserved set with
AD's own become **spaces**, never escapes. That is the invariant the whole
naming layer rests on — no name sync writes carries a reserved character — which
is what lets DN handling split on a plain comma instead of becoming escape-aware.
<!-- refs: `kerbridge_sync::planner::names::safe_name` -->
<!-- avoid: sanitized name, escaped name, cleaned name -->

### sam source

Which Entra attribute a **new** account's `login name` is
derived from: display name, mail local part, or UPN local part. The chosen one
leads a fixed fallback order through the
other two, and a source counts as spent only when it *sanitizes* to a name — not
merely when it is non-blank, or a display name of `...` would consume the turn
and leave a good mail address unread.
<!-- refs: `sam_source` in `configs/sync.toml` -->
<!-- avoid: name source, sam strategy -->

### secret ID

The Entra portal's identifier for an app credential, which is
GUID-shaped where the secret *Value* is not, and is routinely pasted in its
place. Sync refuses a GUID-shaped credential file for exactly that reason.

### shadow

The locally accumulated copy of the Entra directory that delta
pages patch. Besides the delta cursors it is
the only state sync persists: a full read starts from an empty one and a full
resync rebuilds it.
<!-- refs: `kerbridge_sync::graph::Shadow` -->
<!-- avoid: mirror, local copy, read model, directory copy -->

### soft delete

Graph's restorable removal, reported as `@removed.reason:
"changed"`; the object waits in the `recycle bin`. For a group, sync treats both
removal reasons the same way — quarantine now.
<!-- avoid: softdeleted, reason changed -->

### throttle

A Graph 429 with `Retry-After`. It makes a read incomplete — no
plan may be produced from one — and says nothing about the directory.
<!-- refs: `Outcome::Throttled` in `crates/kerbridge-sync/src/graphclient.rs` -->
<!-- avoid: 429, throttling, rate limit -->
