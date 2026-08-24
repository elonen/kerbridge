# kerbridge-issuerd glossary

The privileged local daemon holding KDC authority: issuing tickets and writing
device grants over the local `sam.ldb`.

Part of the repo-wide vocabulary in [`GLOSSARY.md`](../../GLOSSARY.md) — a term
means the same thing there and here. It lives in this file, closest to where
it's used, rather than in the root file, because the root file would be
unreadably long if it carried every term at once.

### base DN

The LDAP search root, derived from the realm rather than configured separately:
`EXAMPLE.SITE` → `DC=example,DC=site`.
<!-- refs: `kerbridge_core::dn::base_dn_for` -->
<!-- avoid: base -->

### client category

The short refusal string `issuerd` lets cross the socket, a closed set:
`issuer failed`, `bad request`, `unknown account`, `account not eligible`,
`device grant cap reached`. The detail behind it — account names, command
output — stays on `issuerd`'s own log.
<!-- avoid: error, reason -->

### credential

One entry in a ccache: a client principal, a server principal, four timestamps
and the ticket flags. The cloud-side sense of the word is `graph credential`
and the on-disk sense is `secret file`; these senses do not overlap.
<!-- refs: `ccache::Credential` -->

### DENY

The `issuerd` log line for a request that decoded and was then turned down,
carrying the request id, the client category and the operator-only detail.
Distinct from `REFUSE`, which is a connection turned away before any request
was read.
<!-- avoid: reject -->

### grant cap

The per-account ceiling on stored device grants. `issuerd`'s own bound rather
than a number the broker sends, and it refuses rather than evicting, so one
device cannot push the others out; a `re-grant` takes no extra room and does
not count against it.
<!-- refs: `configs/main.toml` `device_grant_max_per_user` -->
<!-- avoid: ceiling, per-user cap, per-object cap -->

### issue

The production of one ticket for one resolved account. The wire verb, every
identifier in `issuerd`, and the `ISSUE` line in the audit log all spell it
this way.
<!-- refs: `kerbridge_core::issuer::Request::Issue` -->
<!-- avoid: mint, minting -->

### issuer (ticket)

`issuerd`'s side of the Unix socket, correct only inside the fixed compounds
that name it: issuer socket, issuer protocol, and their code counterparts. The
daemon itself is `issuerd`; "the issuer" as an actor means `issuer (identity)`,
the OIDC sense.
<!-- refs: `kerbridge_core::issuer`, `IssuerError` -->

### keytab

The request-scoped file holding the account's **existing** exported key,
written to tmpfs and destroyed with the work directory. The export command
changes neither the key nor the kvno, which is what makes issuing a ticket a
read of the KDC database rather than a write.
<!-- refs: `issuerd::issue`, `samba-tool domain exportkeytab` -->
<!-- avoid: kt, key file -->

### peer

Whoever is connected to `issuerd`'s Unix socket, identified by the uid the
kernel reports rather than by anything claimed, and permitted only for root or
the broker. The socket's group permission is not an identity, which is why this
check sits behind it; `peer` is never a name for the broker as an actor.
<!-- refs: `issuerd::peer::authorized` -->

### ping

The liveness verb `issuerd` answers and the ping subcommand the container
healthcheck runs. Shipped in the same binary as the server so the probe cannot
drift from the protocol it probes, and it must not touch Samba or the
directory.
<!-- refs: `kerbridge_core::issuer::Request::Ping`, `issuerd ping` -->

### pseudo-credential

An `X-CACHECONF:` entry in a fresh ccache whose "ticket" is a configuration
string rather than an encoded ticket. It names `krbtgt` in a *component*, so a
TGT test matching on the service name alone would accept one.
<!-- refs: `Credential::is_tgt` -->

### re-grant

Recording a grant for a thumbprint the account already holds. Replaces the
stored value in one LDIF modify rather than duplicating it, restarts both the
window and the `last seen` stamp, and does not count against the `grant cap`.
<!-- avoid: replacing -->

### REFUSE

The `issuerd` log line for a connection turned away before any request was
read: an unauthorized peer, or the in-flight cap. `DENY` is the one for a
request that decoded first.

### renewable

The Kerberos property of a ticket whose `renew_till` runs past its `end time`;
`issuerd` refuses to return a ticket that lacks it. Carried and reported and
nothing more — no client schedule is built on it, because Windows never
installs a renewed injected TGT.
<!-- avoid: renewal, extendable -->

### request id

The caller's own correlation string, echoed back in the issuer response and
into the audit line. Filtered to alphanumerics and hyphens and capped at 64
characters, because a newline in it would let a caller write a convincing
`ISSUE` line for someone else.
<!-- refs: `safe_id` -->

### sam.ldb

The Samba AD database as a file on the DC. `issuerd` is the only component that
touches it as a file, through `ldbsearch` and `ldbmodify`; every other
component sees the same store as the `directory`, over LDAPS.
<!-- refs: `/var/lib/samba/private/sam.ldb`, `issuerd.toml` `sam_db` -->
<!-- avoid: the sam, samba database, the samba store -->

### ticket flags

The RFC 4120 `TicketFlags` `issuerd` asserts on before returning a ticket
— `INITIAL` and `RENEWABLE` set, `INVALID` clear — read from the packed form
MIT stores them in. A non-renewable ticket handed back as renewable is the
failure this catches, and the client would otherwise only find out when renewal
silently stopped working.
<!-- refs: `TKT_FLG_*` in `issuerd::ccache` -->
<!-- avoid: flags -->
