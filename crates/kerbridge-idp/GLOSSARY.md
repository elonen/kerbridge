# kerbridge-idp glossary

The two faces of a cloud IdP: what a bearer credential is reduced to, and what a
directory read returns. Every term here is one adapter's, below the seam — the
mirror above it reads none of them. What the mirror does with a
[source snapshot](../kerbridge-sync/GLOSSARY.md#source-snapshot) is in
[`crates/kerbridge-sync/GLOSSARY.md`](../kerbridge-sync/GLOSSARY.md).

Part of the repo-wide vocabulary in [`GLOSSARY.md`](../../GLOSSARY.md) — a term
means the same thing there and here. It lives in this file, closest to where
it's used, rather than in the root file, because the root file would be
unreadably long if it carried every term at once.

### corrupt cursor

A stored `delta cursor` Graph rejects with `400` on a
request that carried one; the adapter discards it and reads fresh. Distinct from
a `resync` (`410`) and from a `400` on a URL built here from constants, which is
a fault to surface rather than a cursor to throw away.
<!-- refs: `StreamResult::CursorCorrupt` -->
<!-- avoid: cursorcorrupt, corrupt, rejected cursor, bad token -->

### delta cursor

The `@odata.deltaLink` stored at the end of a completed
stream read and replayed at the start of the next
[cycle](../kerbridge-sync/GLOSSARY.md#cycle). Cursors are per
stream — a groups cursor is not a users cursor — and nothing a login depends on.
<!-- avoid: cursor, delta token, deltalink, resumption cursor, sync state -->

### delta entry

One object as it arrives on a delta stream: a *sparse* patch
carrying only the properties and membership edges that changed, never a whole
object. Absent is not empty.
<!-- avoid: delta slice, sparse patch, change -->

### hard delete

Graph's permanent, non-restorable removal, reported as
`@removed.reason: "deleted"`. The same reason string also marks a membership
removal inside `members@delta` where the member object still exists, so the
reason alone does not say an object is gone.
<!-- avoid: harddeleted, purge, permanent delete -->

### recycle bin

Graph's `/directory/deletedItems`, where a soft-deleted object
waits out its 30 days. Soft-deleted security groups report `securityEnabled:
false` there, so they are told apart by `groupTypes` being empty.
<!-- avoid: deleteditems, deleted items -->

### resync

A full read from scratch with no cursor, forced when Graph answers
`410` because the stored cursor aged out (>7 days). Both streams resync
together, from an emptied shadow, and the cycle retries at most once.
<!-- avoid: full read, full resync, fresh delta -->

### secret ID

The Entra portal's identifier for an app credential, which is
GUID-shaped where the secret *Value* is not, and is routinely pasted in its
place. A GUID-shaped credential file is refused for exactly that reason.

### shadow

The locally accumulated copy of the Entra directory that delta
pages patch. It lives in memory alone: a full read starts from an empty one, a
full resync rebuilds it, and a restart loses it.
<!-- refs: `kerbridge_idp::entra::wire::Shadow` -->
<!-- avoid: mirror, local copy, read model, directory copy -->

### soft delete

Graph's restorable removal, reported as `@removed.reason:
"changed"`; the object waits in the `recycle bin`. For a group, sync treats both
removal reasons the same way — quarantine now.
<!-- avoid: softdeleted, reason changed -->

### stalled read

A Graph stream read abandoned because no page arrived for long enough to call
it dead, and therefore no evidence that anything is absent. Nothing may be
planned from one: the [cycle](../kerbridge-sync/GLOSSARY.md#cycle) is discarded
and counted toward the consecutive-
failure alert. It says Graph is unreachable or refusing, never that the
directory is large — how long a whole read takes is not bounded.
<!-- refs: `StreamResult::Stalled` -->
<!-- avoid: incomplete read, partial read, partial-read refusal, incomplete, timeout, read deadline -->

### throttle

A Graph 429 with `Retry-After`. It stops a read from finishing — no
[source snapshot](../kerbridge-sync/GLOSSARY.md#source-snapshot) comes out of
one — and says nothing about the directory.
<!-- refs: `Outcome::Throttled` in `crates/kerbridge-idp/src/entra/client.rs` -->
<!-- avoid: 429, throttling, rate limit -->
