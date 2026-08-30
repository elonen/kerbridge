# The up-front decisions

This page is [step 1 (*Decide the names*) in
SETUP.md](../../SETUP.md#1-decide-the-names). Make these decisions before you
install anything. The first provisioning freezes some of them, and the others
are expensive to change later.

| Decision | Frozen by | Cost of changing it later |
|---|---|---|
| Domain and realm names | The first provisioning | **High**: you must destroy and rebuild the domain. Every SID, and thus every filesystem ACL, becomes invalid. You must also update DNS. |
| Idmap ranges | The first `net ads join` | **High**: you must `chown` every file on every member |
| The source name | The first sync cycle | **High**: it orphans every synchronized object, and it detaches every file whose owner came from one |
| The group suffix | The first sync cycle | **Medium**: every synchronized group is renamed, so a share ACL that names one by hand stops matching |
| TLS strategy | Not frozen, but easier to select now | **Low**: rebuild the Caddy image, then restart |
| The admission group | Not frozen | **None** — it is a group in that cloud IdP |
| Resource groups | Not frozen | **None** |

## Make the realm the uppercased DNS domain

If your services are in `example.site`, use `EXAMPLE.SITE` as the realm.

This is the opposite of the usual AD advice, because KerBridge clients are
**not domain-joined**. An unjoined or Entra-joined Windows client has no AD
domain to fall back to. It selects the Kerberos realm of a service from the
server's DNS suffix only:

- If the realm is the same as the suffix, the selection is correct with no
  configuration.
- If the realm is different, each Kerberized service needs a
  `ksetup /addhosttorealmmap` entry. You must push that entry to every client,
  where it stays in the boot cache permanently. Each new file server then makes
  you enroll the full fleet again.

**The cost that you accept** is some SRV and A records in your DNS —
[dns-and-firewall.md](dns-and-firewall.md).

**Do not use `.local`.** It is reserved for mDNS. Use a domain that you own, or
a subdomain of one. Do this also when the domain resolves on your LAN only. You
must be able to get valid certificates for the domain.

Keep the default **DC hostname**, `kerbridge`. Do not select a name such as
`dc1`. The default name keeps this host different from the real domain
controllers that you may install later.

<details>
<summary>Why the domain-joined fallback does not exist here</summary>

A joined workstation can find a DNS suffix that it cannot map to a known
Kerberos realm. It then asks its own KDC, which finds the SPN at its location
in the forest. This fallback lets a conventional AD accept a service in one DNS
domain and the realm in a different one.

An unjoined or Entra-only-joined Windows has no domain of its own to ask. It
must select a realm from the host name only, through the Windows DNS-suffix
heuristic. There is no other source.

</details>

## The source name

The source name is `name` in `configs/idp_<source>.toml`, and it is listed in
`main.toml`'s `sources`. It names one cloud IdP as this realm stores it.

- For the first source, use the adapter's lowercase name: `entra` or `authentik`.
- The IdP-specific OU is normally derived from it (`OU=Entra` or
  `OU=Authentik`).
- A plain lowercase word is the whole of it.

> **CAUTION: Do not change the source name after the first sync cycle. Do not
> point an existing name at a different IdP directory.** Both operations replace
> every synchronized account with one that has a *different SID*, and every file
> whose owner came from the old SID loses its owner. To recover, you must restore
> the realm directory.

A replacement IdP directory gets a new source name, its own `ou`, and its own
`configs/idp_<source>.toml`. That is what a second source is.

<details>
<summary>What the rename does, in detail</summary>

The source name ends up inside every synchronized object's
`msDS-ExternalDirectoryObjectId`, which is the value that the broker searches
for at every login. Change the name and every one of those values is rewritten.
Sync then sees the old objects as gone and the new ones as new: it retires each
account and creates a replacement. Nothing warns you. The accounts stop
working, and the files show unresolved SIDs.

Repointing an Entra source at another tenant is at least loud, because the new
tenant's object ids share none of the old ones. But the bill is the same.

Nothing in the realm directory records which cloud IdP a name means. The OU holds the
objects, and the config set says what filled it. So a name that you repoint in
`configs/idp_<source>.toml` is a name that changed meaning silently. The
realm directory has no older answer to contradict it with.

</details>

## The group suffix

`group_suffix` in `configs/idp_<source>.toml` is what this source's group login
names end with. With suffix `-entra`, `payroll` becomes `payroll-entra` in the
realm directory.

- Use up to 20 characters. Use no whitespace, and no character that AD refuses.
- Use the literal `none` for no suffix.
- There is no default. Both answers cost something, and only you know which
  cost applies.

**Choose a suffix if you may ever add a second cloud IdP.** Choose `none` only
if this is your one cloud IdP, and you accept a rename of its groups later.

<details>
<summary>Why a second IdP without suffixes stops all synchronization</summary>

A group's `sAMAccountName` must be unique across the **whole realm**, not
within one IdP's OU. Two cloud IdPs that each hold a group called `payroll` are
therefore asking for one name. The second sync to reach it refuses that cycle
and every cycle after it — it mirrors **no users either**, not only the one
group — until a person renames the group in one of the two IdPs.

Distinct suffixes remove the whole class of problem, and there is no other way
to remove it. Sync will not rename a group for you, because the name is what a
share ACL may refer to.

The later rename is not free: every synchronized group changes login name at
once, and any share ACL that names a group by hand rather than by SID stops
matching. To add the suffix now costs you a slightly longer name. To add it
later costs a rename of groups that are already in use.

</details>

## TLS strategy

The broker endpoint (`https://kerbridge.example.site`) relays Kerberos tickets
to workstations, so it needs a TLS certificate.

A Docker Compose deployment<sup>[?](../../GLOSSARY.md#docker-compose-deployment)</sup>
brings its own Caddy. Select one of three strategies:

| Strategy | Select it when |
|---|---|
| `external` | You have your own CA or PKI. You supply `broker.crt` and `broker.key`, and you renew them. |
| `acme-dns` | `DNS-01` method. The broker is on your LAN, but its zone has public delegation. It shows control through a DNS TXT record, and it needs no inbound connection. It puts a credential that can change DNS on the host. |
| `acme` | `HTTP-01` method. `BROKER_FQDN` resolves publicly to this host, and the internet can reach `:443`.<br />**Not recommended** — keep a KDC in a private LAN. |

To supply the material for your strategy, see
[Supply the certificate (`compose-deployment.md`)](compose-deployment.md#supply-the-certificate).

A Debian deployment<sup>[?](../../GLOSSARY.md#debian-deployment)</sup> has no
Caddy and no strategy setting. The broker binds to loopback only, and you run a
terminator of your own in front of it on that same host —
[`debian-deployment.md`](debian-deployment.md#terminate-tls-in-front-of-the-broker).

> **CAUTION: Issue the certificate for 398 days or fewer.** This applies to
> every method. macOS refuses a TLS server certificate with a longer validity.
> To trust the root does not remove the limit. macOS reports
> `CSSMERR_TP_CERT_SUSPENDED`, which is a revocation code, on a certificate
> that names no CRL. Windows and Linux clients accept the same certificate. So
> a longer certificate does not look like a certificate problem. It looks like
> a broken Mac client.

## Which group admits users to the realm

Each source needs one admission group. The documented default is **KerBridge
Allowed On-prem Users**.

- Create it in that cloud IdP.
- Add the users who must reach your Kerberos services. Nested groups are
  expanded recursively, so you can add an existing group instead of each user.
- This group is Kerberos admission only. It gives no file access.
- Record its immutable identifier, not its name:
  - **Entra:** the group **Object ID**.
  - **authentik:** the group **pk**.

The provider page in step 2 tells you how to create or read the group and how to
put its identifier in `admission_group_id`.

## Which cloud IdP groups carry your authorization

- Use groups that you already have, for example `proj-x` or `finance`.
- Sync mirrors each group that is reachable from the admission group.
- Some groups are not reachable, for example a share-access group with no
  members from the admission group. You can name those groups explicitly later.

For the two chains that this creates, and why they are separate, see
[Authorize a cloud identity (`file-server.md`)](file-server.md#6-authorize-a-cloud-identity).

## Idmap ranges for the file server

Keep the defaults: `100000-199999` for the allocating backend, and
`1000000-1999999` for the realm.

> **CAUTION: You cannot change the idmap range later.** The range is part of
> every uid that is stored on disk. It must be byte-identical on every member,
> and it must not overlap 0–65533. For the failure that a change causes, see
> [The idmap range is a one-way door
> (`file-server.md`)](file-server.md#the-idmap-range-is-a-one-way-door).
