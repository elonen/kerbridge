# kerbridge-sync glossary

The cloud-IdP-to-IdP-specific-OU reconciliation loop: planning and applying —
the read/plan/apply cycle and the directory state it reasons about. How an IdP
is read is the adapter's, below the seam — see
[`crates/kerbridge-idp/GLOSSARY.md`](../kerbridge-idp/GLOSSARY.md).

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
<!-- refs: `kerbridge_idp::sync::build_desired` -->
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
cloud object id, which is the only way either is stated. An id is an identity,
so sync moves a role marker found on the wrong group to obey it, and a rename
at the IdP cannot point the binding at a different group. A different
operation from a `name pin`, which freezes a value against recomputation rather
than selecting by a key.
<!-- refs: `admission_group_id`, `device_grant_group_id` in `configs/idp_<source>.toml`'s `[provider_config]` -->
<!-- avoid: pin, pinned, pinning the group, pinned id, id pin, id override, admission_pinned -->

### closure

The set of Entra groups reachable from the `admission group` and
the `allowlist` through nested group membership; it is the whole answer to who
has a directory object here, not merely who may get a ticket. Direct edges are
mirrored as-is and nesting is resolved by Samba, not flattened here; leaving the
closure therefore retires the account rather than only dropping its memberships.
<!-- refs: `kerbridge_idp::sync::build_desired` -->
<!-- avoid: selected, group closure, selected set, expansion -->

### CN

The first RDN value of a directory object's DN, and what ADUC shows.
Sync derives it from the display name, not from the login name, and unlike a
`sAMAccountName` it carries no length limit worth enforcing.
<!-- avoid: common name, new_cn -->

### conflict

A per-object finding sync reports but will not act on: an
`ambiguous identity`, an unmanaged object inside the IdP-specific OU, a `foreign member`,
or a conflicted object's membership left frozen. Conflicts ride beside a plan
that still applies — freeze at per-object radius, unlike the whole-run freeze an
`alert` carries. Plain strings on the plan.
<!-- refs: `Plan::conflicts` -->
<!-- avoid: warning, issue -->

### current state

What the directory actually holds: everything under
the IdP-specific OU plus a domain-wide `sAMAccountName` scan for collision-safe naming.
Only objects carrying a `kb1` identity for the configured `source` reach the
user and group maps; the rest land in the unmanaged set, reported and never
touched.
<!-- refs: `kerbridge_sync::planner::Current`, field `unmanaged_dns` -->
<!-- avoid: current, actual state, live state, on-prem state, dump_current -->

### cycle

One read / plan / apply pass, repeated after a pause. A cycle plans
whole or is discarded — a [stalled read](../kerbridge-idp/GLOSSARY.md#stalled-read)
or a `sAMAccountName` collision refuses
the entire plan — but once applying has started a failed op is recorded and the
remaining ops still run.
<!-- refs: `SourceSync::tick` in `crates/kerbridge-sync/src/main.rs` -->
<!-- avoid: run, pass, iteration, tick -->

### desired state

The on-prem target: what the IdP-specific OU should contain once the
admission-group closure and the held-narrowing have been applied to the
`enumeration` — never the raw read.
<!-- refs: `kerbridge_idp::sync::build_desired`, `kerbridge_idp::sync::Desired` -->
<!-- avoid: desired, target state, wanted state, cloud state, source state -->

### directory source

One cloud IdP behind the seam, reduced to what the mirror needs of it: it
advances, and yields a `source snapshot` or says why it could not. How it reads
— the protocol, the credential, the
[cursors](../kerbridge-idp/GLOSSARY.md#delta-cursor) — is its own, and
reconciliation never enters one.
<!-- refs: `kerbridge_idp::sync::DirectorySource` -->
<!-- avoid: connector, provider interface, source trait, reader -->

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

### enumeration

One `directory source`'s whole reading of its IdP, before the realm's rules
narrow it: every account the adapter's own rules accept, every group it read,
and the accounts it turned away. `build_desired` turns one into a `desired
state`. Filling one in is how an adapter opts into the `closure` walk and the
held-narrowing; an adapter whose IdP expands nesting itself builds a desired
state directly and produces none.
<!-- refs: `kerbridge_idp::sync::Enumeration`, `kerbridge_idp::sync::build_desired` -->
<!-- avoid: raw read, tenant dump, directory read -->

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

### held (group membership)

Said of a cloud user a selected group actually
contains; everyone else the adapter read is dropped, so an account exists
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

### name candidate

One string a **new** account's `login name` may be minted from, already reduced
to what AD accepts. The `directory source` offers an ordered list of them, best
first, and the realm takes the first one nobody holds; it is constructible only
through the one rule, so no adapter carries a charset of its own. An empty list
is legal and means the account offered nothing usable — the `fallback name`
then stands in as its one candidate. A list of one is what the Entra adapter
offers: a second entry lets a taken name fall to another string instead of to
the `disambiguation suffix`, which renames a live account and signs that user
out.
<!-- refs: `kerbridge_idp::sync::NameCandidate`, `kerbridge_idp::sync::name_candidate` -->
<!-- avoid: name suggestion, sam candidate, candidate name -->

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

### repoint

Moving the admission role marker to the group the operator has newly
bound by id. The move is clear-then-stamp, so a partial apply leaves too few
markers rather than too many.
<!-- avoid: remark, re-stamp, marker move, redirect -->

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

### source snapshot

One `cycle`'s whole reading of an IdP: the `desired state`, and the refusals
the `directory source`'s own rules produced. Its existence is the assertion — an
adapter that cannot enumerate yields none — so a read that did not finish can
never delete or disable anything. A `200` with an empty page still yields one,
which is why the empty-expansion freeze — no users desired while accounts are
synchronized — is a separate guard in the planner.
<!-- refs: `kerbridge_idp::sync::SourceSnapshot` -->
<!-- avoid: poll result, directory image, desired set, complete read, complete flag -->

### sync credential

What a `directory source` authenticates to its own IdP with, read from a secret
file: an empty file is the whole of "sync not configured", and writing content
into it starts synchronization on the next poll, with no switch and no restart.
Read-only, and never a user's token. Entra's is an app-only client secret, which
never auto-renews, stops every read at once when it expires, and states its
expiry as an operator assertion rather than a measurement.
<!-- refs: `secrets/idp/<name>/credential`, `EntraSource::credential` in `crates/kerbridge-idp/src/entra/sync.rs`, `sync_credential_expires` in `configs/idp_<source>.toml`'s `[provider_config]` -->
<!-- avoid: graph credential, idp credential, entra credential, graph secret, secret value, secret id -->
