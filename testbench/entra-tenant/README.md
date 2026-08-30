# The Graph conformance run

**Where it is:** [`conformance.py`](conformance.py), in this directory. Run it
by hand from the repository root:

```sh
python3 testbench/entra-tenant/conformance.py
```

**What it is for.** The `graph-sync` corpus
([`../fixtures/graph-sync/`](../fixtures/graph-sync/)) is what every Rust test of
the Entra sync path reads. Its shapes are written from Microsoft's
documentation, and nothing in it came from a tenant. So the sync is tested
against what Graph is *documented* to send.

This run closes that gap. It reads a live tenant and names each place where
Graph and the corpus disagree. A disagreement means the corpus was wrong, or
Graph changed. Both matter, and `make test` can see neither: it reads the same
corpus, so it agrees with itself whatever Graph does.

It also states the tenant it expects. That makes the shapes reproducible by
anyone, which is the second half of the same problem — a corpus whose meaning
lives only in filenames cannot be checked by a reader.

The run is read-only. It changes nothing in the tenant.

## What it does not do

- It does not sign a user in. `make test-stack` does that against the stand-in
  authority.
- It does not get a ticket and it does not read a file over SMB.
- It is not a test tier, and it must not gate a merge. It becomes red when
  Microsoft changes something, not when a commit changes something.

## What you need

- One Entra tenant that holds nothing else. The run reads every user and every
  group in the tenant. Do not point it at a tenant you use for other work.
- One application registration in that tenant.
- Entra ID Free is sufficient. Two objects need Entra ID P1, and the run reports
  those as absent instead of failing.

## Step 1 — make the application

1. Open **App registrations**. Select **New registration**.
2. Give it a name. Select **Accounts in this organizational directory only**.
3. Add no redirect URI. Select **Register**.
4. Open **API permissions**. Select **Add a permission**, then **Microsoft
   Graph**, then **Application permissions**.
5. Add `User.Read.All` and `Group.Read.All`. Add nothing else.
6. Select **Grant admin consent**. Both rows must show *Granted*.
7. Open **Certificates & secrets**. Make a client secret. Copy the value now.
   Entra shows it one time only.

The run needs no other application. The broker application and the public client
application are for a deployment, not for this.

## Step 2 — make the users

Make four users. Each username is the part before the `@` in the **User
principal name**:

| Username | Account enabled |
|---|---|
| `kb-alice` | yes |
| `kb-bob` | yes |
| `kb-carol` | yes |
| `kb-dave-disabled` | no |

The display name is free text. The run does not read it. Write one display name
in a non-Latin script if you want that case covered. `Carol 高橋` is a good
value for `kb-carol`.

Then invite one external user:

1. Open **Users**. Select **New user**, then **Invite external user**.
2. Give any email address you control.

The invitation makes the username and the display name from that address. The
run does not expect a value for either. It finds the guest by the `#EXT#` in the
user principal name.

## Step 3 — make the groups

Make five groups. **Membership type** is **Assigned** for every one.

| Group name | Group type |
|---|---|
| `KerBridge Allowed On-prem Users` | Security |
| `eng-team` | Security |
| `eng-backend` | Security |
| `proj-x` | Security |
| `kb-collab` | Microsoft 365 |

`KerBridge Allowed On-prem Users` is the admission group. Terraform makes this
one under the same name. See [`../../deploy/terraform/entra/`](../../deploy/terraform/entra/).

Microsoft 365 is the only group type that asks for a group email address. Give
it any value. Nothing reads it.

## Step 4 — add the members

| Group | Members |
|---|---|
| `KerBridge Allowed On-prem Users` | `kb-alice`, the group `eng-team`, the guest |
| `eng-team` | `kb-bob`, the group `eng-backend` |
| `eng-backend` | `kb-carol` |
| `proj-x` | `kb-alice`, `kb-dave-disabled`, the application's service principal |

`kb-collab` needs no members.

Three things follow from this shape, and each one is a check:

- `kb-dave-disabled` is in `proj-x` only. It must not be reachable from the
  admission group. This is what shows that admission is by membership and not by
  existing.
- The guest is in the admission group. The sync must refuse it there.
- The service principal is in `proj-x`. Graph v1.0 omits it from `/members` and
  shows it only under the type cast. The run measures both halves.

To add the service principal with Graph, if your portal does not offer it:

```
POST https://graph.microsoft.com/v1.0/groups/<proj-x id>/members/$ref
{"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/<service principal id>"}
```

The service principal id is the **Object ID** on the application's **Enterprise
application** page. It is not the application (client) ID.

## Step 5 — run it

Set three variables. The run reads no file and asks no question:

```sh
export ENTRA_TENANT_ID=<directory (tenant) ID>
export ENTRA_SYNC_APP_ID=<application (client) ID>
export ENTRA_SYNC_APP_SECRET=<the client secret>

python3 testbench/entra-tenant/conformance.py
```

`python3 testbench/entra-tenant/conformance.py --list` prints the directory the
run expects. It needs no tenant and no variables. The list above and that output
are the same expectations, so use it to check your work.

Exit status:

| Status | Meaning |
|---|---|
| 0 | every check passed |
| 1 | one or more checks failed |
| 2 | a variable is missing or malformed |

## How to read the output

Each line is `PASS` or `FAIL`. A line under it that starts with `note:` is
information, and it does not make the run fail.

A note tells you the tenant holds no object of some kind, so the run compared
nothing. A smaller tenant is not a fault.

`FAIL` has two causes. Read the message to tell them apart:

- The message names an object, a group type or a member. Your tenant does not
  match this page. Correct the tenant.
- The message says a field is no longer returned. Graph changed, or the corpus
  was wrong. This is a finding. Record it, then correct
  `testbench/fixtures/graph-sync/make_fixtures.py` and regenerate the corpus.
  `cargo test -p kerbridge-idp` then says whether the wire structs still cope.

The output carries no identifier. There is no object id, no user principal name
and no tenant ID in any message. A run pastes into a public issue with no edit.

## What stays unmeasured

These are reported and never failed:

| Object | Why |
|---|---|
| `kb-duplicate-name`, twice | Two groups under one name settle whether a name resolves to one object. The portal refuses a second group under a name it holds, so only Graph can make the pair. Without it, name ambiguity stays unmeasured. |
| `kb-distlist` | A distribution list. A tenant may refuse to make one. |
| `kb-dynamic` | Dynamic membership needs Entra ID P1. |

Three items from the sync research also stay open, and this run cannot reach
them: the `410 Gone` `Location` shape needs a cursor more than seven days old,
real throttling values need load or a large tenant, and dynamic-group delta needs
Entra ID P1.

## Measured behaviour

What the first live runs found, on 2026-08-30. The corpus now records all of it:

- **A group omits a selected property that has no value.** A `/groups/delta`
  that selects `membershipRule`, `membershipRuleProcessingState` and
  `onPremisesSyncEnabled` gets back none of the three for a cloud-only static
  group. The corpus recorded all three as null.
- **`/users` does not do this.** It returns `onPremisesSyncEnabled` as null. The
  rule is a groups rule, not a Graph-wide one.
- **A `/members` read with no `$select` answers with the default property set,
  and that set has no `userType`.** The corpus asked for no `$select` and
  recorded `userType`, so it described a response Graph does not send. A
  `$select` that names a property no returned type holds is ignored, not
  refused, so one list serves the mixed collection.
- **An initial `/groups/delta` can carry `@removed` entries.** A tenant that
  held deleted groups returned them on a read with no cursor. No fixture records
  this.

## The other files here

They are for acquiring evidence, and the conformance run uses none of them.
`graph.py`, `devicecode.py`, `setup_directory.py` and the `exp_*` instruments
write `config.json`, `directory.json` and a `secrets/` directory. Those hold a
delegated admin token, generated passwords and live object ids. The
`.gitignore` here excludes all three.
