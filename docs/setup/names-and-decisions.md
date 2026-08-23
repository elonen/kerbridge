# The up-front decisions

Detail for [step 1 (*Decide the names*) in SETUP.md](../../SETUP.md#1-decide-the-names).
Make these seven decisions before you install anything. Each decision is frozen at the
first provisioning, or is expensive to change later.

| Decision | Frozen by | Cost of changing it later |
|---|---|---|
| Domain / realm names | First `make up` | **High**: you must destroy and rebuild the domain; every SID, and thus every filesystem ACL, becomes invalid; DNS updates are also necessary |
| Idmap ranges | First `net ads join` | **High**: you must `chown` every file on every member |
| The source name | First sync cycle | **High**: changing it orphans every synchronized object and detaches every file whose owner came from one |
| The group suffix | First sync cycle | **Medium**: every synchronized group is renamed, so any share ACL naming one by hand stops matching |
| TLS strategy | Not frozen, but easier to select now | **Low**: rebuild the Caddy image, then restart |
| The admission group | Not frozen | **None** — it is a standard Entra group |
| Resource groups | Not frozen | **None** |

## Make the realm the uppercased DNS domain

If your services are in `example.site`, use `EXAMPLE.SITE` as the realm.

This is opposite to the usual AD advice (Microsoft prefers a dedicated
`ad.example.site`). The reason is that KerBridge clients are **not
domain-joined**:

- An unjoined or Entra-joined Windows client has no AD domain as a fallback.
  It selects the Kerberos realm of a service from the server's DNS suffix
  only.
  - If the realm is the same as the suffix, this selection is correct with no
    configuration.
  - If the realm is not the same as the domain name, each Kerberized service
    needs a `ksetup /addhosttorealmmap` entry. You must push this entry to
    every client, where it stays in the boot cache, permanently. Each new
    file server then causes a re-enrollment of the full fleet with the Windows
    systray helper.
- **The cost that you accept:** some SRV and A records in your DNS
  ([step 3, *Publish the DNS records*](../../SETUP.md#3-publish-the-dns-records)).

<details>
<summary>Why the domain-joined fallback does not exist here</summary>

A joined workstation can find a DNS suffix that it cannot map to a known
Kerberos realm. Then it asks its own KDC (Domain Controller), which finds the
SPN at its location in the forest. This fallback lets a conventional AD accept
a service in one DNS domain and the realm in a different one.

An unjoined or Entra-only-joined Windows has no domain of its own as a
fallback. It must select a realm from the hostname only, through the Windows
DNS-suffix heuristic. There is no other source that it can ask.

</details>

**Do not use `.local`**. It is reserved for mDNS. Use a domain that you own,
or a subdomain of one. Do this also when the domain resolves only on your LAN.
You must be able to get valid certificates for the domain.

Recommendation: keep the default **DC hostname**: `kerbridge`. Do not select a
name such as `dc1`. The default name keeps it different from any "real" Domain
Controllers that you may choose to install in the future.

## The source name

The source name — `name` in `configs/idp_<source>.toml`, and listed in
`main.toml`'s `sources` — names one cloud IdP as this realm stores it. It
defaults to `entra`, it should match the OU name (`OU=Entra,OU=CloudIdP,…`),
and a plain lowercase word is the whole of it: `entra`, `google`, `authentik`.

It ends up inside every synchronized object's
`msDS-ExternalDirectoryObjectId` — the value the broker searches for on every
login. **Change it later and every one of those values is rewritten.** Sync then
sees the old objects as gone and the new ones as new: it retires each account and
creates a replacement with a *different SID*, and every file whose owner was
resolved from the old SID loses its owner. Nothing warns you; the accounts simply
stop working and the files show unresolved SIDs. Recovering means restoring the
directory.

**Never point an existing name at a different Entra tenant** either. That one is
at least loud — the new tenant's object ids share none of the old ones, so sync
retires every account and creates a replacement — but the bill is the same: every
SID is new and every file loses its owner. A new tenant gets a new name and its
own `ou`, in its own `configs/idp_<source>.toml`; that is what a second source is.

Nothing in the directory records which cloud IdP a name means. The OU holds the
objects and the config set says what filled it, so a name repointed in
`configs/idp_<source>.toml` is a name that changed meaning silently — the
directory has no older answer to contradict it with.

## The group suffix

`configs/idp_<source>.toml`'s `group_suffix` is what this source's group login names end with, so
`payroll` in Entra becomes `payroll-entra` in the directory. Up to 20 characters,
none of them whitespace or anything AD rejects — or the literal `none` for no
suffix at all. It has no default: both answers cost something, and only you know
which applies.

A group's `sAMAccountName` has to be unique across the **whole realm**, not
within one IdP's OU. Two cloud IdPs that each hold a group called `payroll` are
therefore asking for one name, and the second sync to reach it refuses that cycle
and every cycle after it — mirroring **no users either**, not just the one group —
until somebody renames the group in one of the two IdPs. Distinct suffixes remove
the whole class of problem, and there is no other way to remove it: sync will not
rename a group for you, because the name is what a share ACL may refer to.

Choose `none` only if this is your one cloud IdP and you accept renaming its
groups if you ever add a second. That rename is not free: every synchronized
group changes login name at once, and any share ACL that names a group by hand
rather than by SID stops matching. Adding the suffix now costs you a slightly
longer name; adding it later costs a rename of groups already in use.

## TLS strategy

The broker endpoint (`https://kerbridge.example.site`) relays Kerberos tickets
to workstations. Thus it needs a TLS certificate.

A [Docker Compose deployment](../../GLOSSARY.md#docker-compose-deployment)
brings its own Caddy and terminates TLS with it, in one of three strategies:

| Strategy | Choose when |
|---|---|
| `external` | You have your own CA or PKI. You supply `broker.crt` + `broker.key` and renew them yourself. |
| `acme-dns` | `DNS-01` method. The broker is on your LAN, but its zone has public delegation. It shows control through a DNS TXT record; no inbound connection is necessary. It puts a credential that can change DNS on the host. |
| `acme` | `HTTP-01` method. `BROKER_FQDN` resolves publicly to this host, and the internet can reach `:443`.<br />(**Not recommended** — usually, keep a KDC in a private LAN.) |

To supply the material for your strategy, see
[Supply the certificate (`compose-deployment.md`)](compose-deployment.md#supply-the-certificate).

A [Debian deployment](../../GLOSSARY.md#debian-deployment) has no Caddy and no
strategy setting: the broker binds loopback only, and you run a terminator of
your own in front of it on that same host, with a certificate you obtain and
renew yourself. Caddy and nginx examples ship with the package —
[`debian-deployment.md`](debian-deployment.md#terminate-tls-in-front-of-the-broker).

> **CAUTION:** Issue the certificate for 398 days or fewer, whichever method you
> use. macOS refuses a TLS server certificate with a longer validity. The trust
> store does not change this, and machine-wide installation of the root does not
> remove the limit. macOS reports `CSSMERR_TP_CERT_SUSPENDED`, a revocation
> code, on a certificate that names no CRL. Windows and Linux clients accept the
> same certificate. Thus a longer certificate does not look like a certificate
> problem. It looks like only the Mac client is broken.

## Which Entra group admits users to the realm

Default: `KerBridge Allowed On-prem Users`

Only the members of this group are mirrored from Entra to the local directory.
Only they can get Kerberos tickets.

- Create a security group in Entra; `KerBridge Allowed On-prem Users` is the
  default name.
- Add as members all users who must have access to your Kerberos services —
  **or add groups**. Nested groups are expanded recursively. Thus, if you put
  your existing `engineering` group in, all of its members are admitted,
  including persons added to it later. All types of group operate correctly:
  security, Microsoft 365, dynamic. It is not necessary to list users one by
  one.
- This is *Kerberos admission only*. It gives no file access by itself.
- `kerbridge-sync` mirrors the member user objects into `OU=Entra,OU=CloudIdP`, and
  `kerbridge-broker` issues Kerberos tickets for them.
- The two levels are deliberate and you do not have to configure either. Each
  cloud IdP gets its own OU (`OU=Entra`) under one shared parent
  (`OU=CloudIdP`), so a second IdP later becomes a sibling OU with its own
  config file rather than a change to this one. Override with `idp_parent_ou`
  in `configs/realm.toml` and `ou` in `configs/idp_<source>.toml` if the names
  collide with an existing directory layout.

## Which Entra groups carry your authorization

- The groups that you already use — for example `proj-x` or `finance`.
- Each group that is reachable from the admission group is synchronized
  automatically.
- Some groups are not reachable, for example a share-access group with no
  members from the admission group. You can name these groups explicitly
  later.

For the two chains that this creates, and the reason that they are separate,
see [step 6 (*Authorize cloud identities on SMB share*)](../../SETUP.md#6-authorize-cloud-identities-on-smb-share).

## Idmap ranges for the file server

You cannot change this decision later. `idmap_rid` calculates each uid and gid
arithmetically from the RID. Thus the range is a permanent part of each uid
stored on disk. The range must be byte-identical on every member. It must not
overlap 0–65533. Do not change it after deployment. For the full reasons and
the failure that a change causes, see [The idmap range is a one-way door
(`file-server.md`)](file-server.md#the-idmap-range-is-a-one-way-door).
