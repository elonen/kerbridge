# Map to pre-existing user IDs

Scenario covered in this document: Your file server holds files that local accounts own. Those uids are on disk already. This page shows two methods to solve this:

1. **Manually set `uidNumber` in Samba**: simpler, but you have to manually edit *all* users.
2. **Map users by Samba `idmap_script` **: more work, but allows precise control + mixing new and old users

Read [file-server.md](file-server.md) first. This page replaces its
[§2 idmap lines](file-server.md#2-etcsambasmbconf), and nothing else.

## Do you need this

Only if all three are true:

- **Owner** permissions control the access, not group permissions.
- A `chown` of the full tree costs too much.
- Files on the share carry owner uids below 65534.

If group permissions control the access, stop here. Keep `idmap_rid`, and add
one group ACE to the old files:

```sh
setfacl -R -m g:'EXAMPLE\nas-share-rw':rwX -m d:g:'EXAMPLE\nas-share-rw':rwX /srv/share
```

## Why `idmap_rid` cannot do it

`idmap_rid` computes `unix_id = RID + range_low`. RIDs start near 1000, and a
range must not overlap the local accounts (0–65533). No range gives a uid below 65534. See [The idmap range is a one-way door](file-server.md#the-idmap-range-is-a-one-way-door).

Two methods stay. Method A holds the numbers in the directory. Method B computes
them on the file server.

## What KerBridge does not do

KerBridge does not assign `uidNumber` or `gidNumber`. Sync does not write them,
and `kbmanage` does not write them or show them. All work on this page is yours.

## Step 1 — Find the pairs

The old uids, from the disk. This list is the authoritative one:

```sh
find /srv/share -xdev -printf '%U\n' | sort -n | uniq -c | sort -rn   # owners, by file count
find /srv/share -xdev -printf '%G\n' | sort -un                       # owning groups
getfacl -Rsn /srv/share | grep -E '^(user|group):[0-9]'               # named ACL entries
```

Named ACL entries hold uids too. Both methods correct them, because both map the
same numbers.

The new SIDs, from the directory. The RID is the last component:

```sh
kbmanage cloud list users --json | jq -r '.[] | [.sam, .sid] | @tsv'
kbmanage cloud show alice                     # one account, with its objectSid
```

Sync must create the accounts first. Before that, no SID exists.

Then match the two lists **by person**. No tool can do this: a cloud identity
and a line in `/etc/passwd` agree only on data that changes. Each pair is a
privilege grant, and a wrong pair gives one person the files of another. Review
the full table before you apply it.

Something like:

```
alice.alison	S-1-5-21-xxx-yyy-zzz-1123
```

The `1123` part is the RID for `alice.alison`.

## Step 2 — Plan the ID bands

Give each kind of ID its own band. No two bands touch. This example maps old
uids 1000–1005:

| Band | Holds | Set by |
|---|---|---|
| 0–999 | local system accounts | the distribution |
| 1000–1005 | the mapped old owners | this page |
| 1001000–1999999 | every other realm object | `RID + 1000000` |
| 2000000–2099999 | BUILTIN and non-realm SIDs | `idmap config *` |
| 2100000–2199999 | future local accounts | `/etc/login.defs` |

Three rules:

- **Keep each mapped uid below the arithmetic band.** This is what keeps the two
  apart. The invariant is `max(mapped uid) < 1000000`.
- **Move `idmap config * : range`.** The realm range now covers the old one, and
  ranges must not overlap. This move is safe, unlike a change to the realm
  range: the `*` backend allocates, it is member-local, it holds BUILTIN only,
  and BUILTIN must never appear in an ACL.
- **Move the local allocation.** Debian gives `UID_MIN 1000`, which is inside
  the realm range. A later `useradd` then takes a number the realm owns.

  ```ini
  # /etc/login.defs
  UID_MIN   2100000
  UID_MAX   2199999
  GID_MIN   2100000
  GID_MAX   2199999
  ```

  Set `FIRST_UID`, `LAST_UID`, `FIRST_GID` and `LAST_GID` in
  `/etc/adduser.conf` to the same band if `adduser` is installed. System
  accounts use 101–999 and stay correct.

Delete the old local accounts. A locked account keeps its name in front of
winbind, and `ls -l` then shows the local name for a realm identity.

## Method A — the numbers live in the directory (`idmap_ad`)

### A1. Write the numbers

The base schema KerBridge provisions holds `uidNumber` and `gidNumber`
(`--base-schema=2019`). `--use-rfc2307` is not necessary, and no `objectClass`
change is necessary. Measured on Samba 4.22.

On the DC:

```sh
ldbmodify -H /var/lib/samba/private/sam.ldb <<'EOF'
dn: CN=alice,OU=Entra,OU=CloudIdP,DC=example,DC=site
changetype: modify
add: uidNumber
uidNumber: 1002
EOF
```

Write a `uidNumber` for **every admitted user**, not only the mapped ones. Use
`RID + 1000000` for the others. Write a `gidNumber` for every group in a share
ACL, and for `CN=Domain Users,CN=Users,DC=example,DC=site`.

### A2. Configure the file server

Replace the four idmap lines of [file-server.md
§2](file-server.md#2-etcsambasmbconf):

```ini
    # Allocating, member-local. BUILTIN and any non-realm SID.
    idmap config * : backend = tdb
    idmap config * : range = 2000000-2099999
    # Read-only. Every number comes from the directory.
    idmap config EXAMPLE : backend = ad
    idmap config EXAMPLE : range = 1000-1999999
    idmap config EXAMPLE : schema_mode = rfc2307
```

Then `net cache flush` and restart `winbindd`.

### A3. Verify

```sh
wbinfo --name-to-sid 'EXAMPLE\alice'    # the SID, and its RID
wbinfo --sid-to-uid <sid>               # must print the mapped uid
id 'EXAMPLE\alice'                      # must list the domain-local group
```

### What Method A costs

- The backend is **read-only**. Winbind maps only a user that has a `uidNumber`
  **and** whose primary group has a `gidNumber`. Write both before the person
  signs in the first time.
- A value outside the range is discarded. No message says so.
- `all_groupmem` is `no` by default. A member without a `uidNumber` is absent
  from a group list, with no message.
- A DC outage with a cold winbind cache stops all mapping. `idmap_rid` has no
  such failure, because it needs no lookup.

## Method B — the numbers are computed on the file server (`idmap_script`)

`idmap_script` starts an external program for each unknown ID. The program does
the `idmap_rid` arithmetic, and holds a small table for the exceptions. The
directory does not change, and KerBridge does not change.

```ini
    idmap config EXAMPLE : backend = script
    idmap config EXAMPLE : range = 1000-1999999
    idmap config EXAMPLE : script = /opt/my-idmap
```

The protocol is `idmap_script(8)`. One argument in, exactly one line out:

| In | Out |
|---|---|
| `SIDTOID <sid>` | `UID:n`, `GID:n`, `XID:n` or `ERR:text` |
| `IDTOSID UID\|GID\|XID <n>` | `SID:s` or `ERR:text` |

`_NO_WINBINDD=1` is set in the environment. Never call `wbinfo` from the
program. The shape:

```
DOMAIN_SID, BASE = 1000000
PINS = [(rid, uid), ...]                    # one row per mapped person

SIDTOID sid:
    ERR unless sid is under DOMAIN_SID
    rid = last component of sid
    XID: pinned uid of rid,  if rid is pinned
    XID: rid + BASE,         otherwise

IDTOSID kind n:
    SID: DOMAIN_SID-<pinned rid of n>,  if n is a pinned uid
    SID: DOMAIN_SID-<n - BASE>,         if n > BASE and (n - BASE) is not pinned
    ERR,                                otherwise
```

Three rules make it correct:

- **`XID` is the correct reply.** `idmap_rid` gives `ID_TYPE_BOTH`: the spike
  `joined-nas-authorization` measured `wbinfo --sid-to-uid` and `--sid-to-gid`
  both answering for one user SID. A mapped uid therefore claims the same gid.
  Make sure no unrelated group holds that number.
- **`IDTOSID` must refuse the arithmetic ID of a pinned RID.** Without that
  refusal, one SID gets two IDs, and the split ownership comes back.
- **The table must be a bijection.** A repeated rid, or a repeated uid, gives
  two people one identity and shows no error. Check the table before `winbindd`
  starts, and stop `winbindd` if the check fails.

One process starts for each uncached lookup. Keep the program small.

### What Method B costs

- The table is member-local. Copy it to every member, byte-identical. This is
  the risk the single range carried, multiplied by the number of rows.
- The directory does not know the table exists. There is no audit, and no
  check can find a row that points at a deleted account.

## Which method

| | A — `idmap_ad` | B — `idmap_script` |
|---|---|---|
| Numbers live in | the directory | a file on each member |
| A new user needs | a directory write before the first sign-in | nothing |
| A new ACL group needs | a `gidNumber` | nothing |
| Several file servers | one source | one copied file per member |
| DC down, cold cache | no mapping at all | mapping still works |
| Audit | any LDAP read shows the value | none |

Use A with more than one file server, or when a hand-copied file is not
something you can trust. Use B with one file server, when the outage behaviour
matters, or to keep the directory unchanged.

Both give the same numbers if both use `RID + 1000000` as the default. A move
from B to A therefore needs no `chown`.

## Hazards of both methods

- **A deleted account destroys the map.** `kbmanage cloud delete` removes the
  SID, and a replacement account gets a new SID and a new RID. Method A loses
  the `uidNumber` with the object. Method B keeps a row that points at nothing.
  The files stay, with an owner that no name resolves.
- **Keep the pairs outside the file server, and back them up.** Without the
  list you cannot rebuild the map.
- **The bands are permanent.** They are part of every uid on disk, exactly like
  the range.
- **Do not mix the methods.** Configure one of them on every member.
