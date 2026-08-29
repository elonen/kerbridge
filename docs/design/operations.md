# Design » Operations

What configures a deployment, what must survive it, what it tells an operator,
and what the tests cover. [`DESIGN.md`](../../DESIGN.md) is the index.

## Compose configuration

`.env` controls the deployment shape: the realm identity, the TLS strategy, and
what Compose publishes and mounts. The config set under `deploy/configs/`
controls the service policy, one TOML file per service. It is also where a
source's cloud IdP settings are named. Secret values are supplied as files,
through Compose secrets or through explicit read-only bind mounts.

`deploy/bench.env` is a third file. It is tracked, and it is read before `.env`,
and thus `.env` overrides it. It holds the development bench's fixtures, which
are inert on a production deployment. It is never an operator's to edit.

**[`deploy/.env.example`](../../deploy/.env.example),
[`deploy/bench.env`](../../deploy/bench.env) and `deploy/configs/*.toml.example`
are the reference for the key set.** Each key is documented there, next to its
default and its failure mode. This document deliberately does not restate them.
`KERBRIDGE_STATE_DIR` belongs to a design that is not built yet and appears in
none of them. The section that specifies it names it, below.

<details>
<summary>Why the key list is not restated here</summary>

The list drifted one time already. It still named `TICKET_LIFETIME` and
`CADDY_ACME_CHALLENGE` after the shipped file had moved to
`TICKET_LIFETIME_SECONDS` and `TLS_STRATEGY`. A second home for the same facts is
what let that happen unnoticed.

</details>

Secret files:

- The initial Samba domain administrator password.
- Per source: the sync `credential`, in
  `secrets/idp/<name>/`, and the `bind_password` of the delegated Samba sync
  account `svc-kerbridge-sync-<name>`, in `secrets/generated/idp/<name>/`. There
  are two directories, because the two files have different writers. Each
  directory is mounted whole, and neither is a Compose secret, and thus to add a
  source edits no tracked file.
- The broker LDAP read credential: the LDAP bind password of
  `svc-kerbridge-broker`.
- Under `TLS_STRATEGY=external`, the certificate and key that the operator
  supplies.
- Under `TLS_STRATEGY=acme-dns`, the DNS provider API token. It reaches Caddy as
  an environment value, and not as a Compose secret, because Caddy's provider
  modules read credentials through the `{env.*}` placeholder and cannot read a
  file.
- The notification webhook URL. Its presence is what enables notification. It
  ships empty, and empty means that notification is off.

No secret value is ever put in a checked-in file: not in the Compose files, not
in `.env.example`, and not in `bench.env`.

## Durable state

The shipped Compose file keeps Samba's state in **named volumes** (`samba`,
`etc-samba`, `caddy-data`). `/var/lib/samba` needs a filesystem that carries
extended attributes, and `security.NTACL` writes fail on a macOS bind mount.

The intended production shape is bind mounts under `KERBRIDGE_STATE_DIR` on ext4,
so that an operator can see what cannot be regenerated. **That shape is designed
and not built.** `backup.sh` accordingly discovers volumes, and would find no
such bind mount.

Indicative layout for it:

```text
/srv/kerbridge/
    realm/
        etc-samba/
        var-lib-samba/
    broker/
        config/
    sync/
        state/
    caddy/
        config/
        data/
    secrets/
```

The directory (realm) is the critical state. It contains:

- The domain SID and the KDC keys.
- The synchronized users and groups.
- The external identity mappings.
- The locally managed resource groups and memberships.
- SYSVOL and other AD DC state.

Also durable:

- Caddy's ACME state: the issued certificate and the ACME account. On tmpfs,
  Caddy would issue again at each restart and trip Let's Encrypt's rate limits.
- The secret files.
- The notifier's open problems and their last-notified stamps. These are one
  directory per service under `deploy/state/`. They are bind-mounted, and not a
  named volume, for two reasons: a fresh named volume is created root-owned and
  neither service runs as root, and the point of the directory is that something
  outside the container reads it. If the directory is lost at a restart, a crash
  loop re-sends each outstanding event, and each condition looks new. It is the
  one durable thing here whose loss costs noise and not authority, and the only
  one that a service starts without.

Not durable:

- Logs can go to the container runtime or to the host logging system, and need
  no bind mount by default.
- Request keytabs, ccaches and issuer temporary directories live on tmpfs.
- The issuer socket volume is runtime state, and can be recreated.
- Provider read state lives in the sync process only. Entra keeps delta cursors
  and a shadow. A restart causes a full reconciliation, which is also the
  recovery for a Graph `410`. Authentik performs a full read in each cycle and
  has no cursor. Persistent provider state would add a second value that can be
  stale. Broker configuration is environment plus one secret file, with nothing
  to persist.

`deploy/scripts/compose/backup.sh` collects exactly the durable set above — the
host-side files and the Docker volumes — into one tarball. `restore.sh` puts it
back. Both refuse to run against a stack that is up: Samba writes its databases
continuously, and a tar that is taken across them is torn in a way that nothing
notices until the restore. Scheduling and retention stay with the operator.

## Observability

Each ticket request gets a random correlation ID. It is random and not
sequential, and thus it carries no information about the traffic volume. Audit
records include:

- The timestamp and the result.
- The source name and stable subject, in canonical form. Both are identity
  coordinates, not credentials. The identity proof that supplied them is never
  logged. Entra also records its tenant ID.
- The Samba SID and the returned principal.
- The admission decision, and the reason for a refusal.
- The ticket expiry and renewal timestamps.
- The request latency and the categorized failure.

Logs never include:

- bearer tokens
- ccaches
- session keys
- temporary keytab contents
- sync credentials
- LDAP passwords
- the notification webhook URL

### Operator notification

Some conditions are actionable by a human only, and are invisible in a log that
nobody reads: an expiring sync credential, a deleted admission group, a sync
cycle that fails again and again.

Built, in the `kerbridge-notify` crate. Each event is a structured, greppable
`NOTIFY <severity> <event>: <message>` line in the log of the service that emits
it, whether or not a webhook is configured. The log is no longer the seam: it is
the fallback. The webhook is what also puts the event where an operator looks.

**The only delivery method is an HTTP webhook.** The presence of the webhook URL
secret file enables it, and its absence disables it. There is no method selector,
because with one method a selector is a second way to say the same thing, and a
second way to be misconfigured. Startup gives a warning when no URL is
configured, and thus a deployment that can reach nobody says so.

<details>
<summary>Why email is omitted</summary>

Each common receiver accepts a webhook. SMTP brings a relay, credentials, and
header construction from untrusted directory (realm)-derived text, for no capability that
the webhook lacks. To add it later is a second implementation of one trait.

</details>

The payload is a template. It is rendered from a substitution set that is common
to each event:

| Placeholder | Value |
|---|---|
| `%EVENT%` | Stable slug, e.g. `sync-credential-expiring`. |
| `%SEVERITY%` | `info`, `warning` or `error`. |
| `%COMPONENT%` | Emitting service, e.g. `sync`. |
| `%REALM%` | Configured Kerberos realm. |
| `%TIMESTAMP%` | RFC 3339 UTC. |
| `%MESSAGE%` | One-line human summary. |
| `%DETAIL%` | Event specifics; may be empty. |
| `%ICON%` | An emoji for the state: 🔴 error, 🟠 warning, 🔵 info, ✅ recovery. |

Rules that keep the channel trustworthy:

- An unknown `%PLACEHOLDER%` in a template is a startup configuration error. It
  is not a field that is silently empty.
- The body is JSON, and substituted values are always JSON-string-escaped.
  Directory (realm)-derived text can contain quotes, backslashes and newlines, and must
  not break or extend the payload. The content type is fixed and not
  configurable: a configurable one would let a template select an encoding that
  the escaper does not implement, which is an injection bug with a plausible
  excuse.
- Delivery is best-effort and bounded: one attempt, `notify.timeout_seconds`
  (5 s by default), and no retry storm. A send failure is logged at error level,
  and never fails the sync cycle or a ticket request. The log line that names it
  carries no URL, because `reqwest` puts the request URL in its error text, and
  that URL is a credential.
- **The repeat policy depends on whether the condition has a deadline.** A
  condition that only persists — `sync-cycle-failing` — repeats on
  `notify.repeat_interval_hours` (24 h by default). A countdown does not: an
  expiry notifies on an escalating schedule, at 30, 14, 7, 3 and 1 days
  remaining, and is otherwise silent. A 24 h interval on a 30-day countdown would
  send thirty events, which is the flood that the rate limit exists to prevent.
- The last-notified record is durable state. It is keyed on the event **and the
  subject**, and thus a restart loop cannot flood the channel, and two instances
  of one event class — two groups that carry the admission marker, for example —
  do not suppress each other. It is the one thing here that degrades rather than
  refuses: a record that cannot be read or written costs rate limiting across
  restarts, and is reported. A service that will not start until its *rate
  limiter* is repaired would be the wrong way round.
- **The webhook is not the only exit.** That record is a directory of JSON files,
  one per condition, and it is the deployment's answer to "what is wrong right
  now". A file is `problem-<event>.json` while a condition holds, and
  `recent-<event>.json` after the condition has cleared. A deployment that wants
  a monitoring system instead of a chat channel points one at the directory and
  configures its own alerting. To count `problem-*.json` is the entire
  integration, and that is why the class is in the file name and not only in the
  body. The files are written whether or not a webhook is configured.

  Files are `0640`, and the service never sets the group. Thus an operator can
  `chgrp` the directory to their agent's group and set the setgid bit. The mode
  is set explicitly and not left to `umask`, which would otherwise produce `0600`
  under `umask 077` and lock the agent out. The files are not world-readable,
  because subjects carry account names and error text. The directory is created
  if it is absent, and is never re-permissioned if it is present, and thus that
  arrangement survives a restart.
- **A condition that clears says so.** Each event is one of two things. A
  *condition* stays true until something disproves it. An *incident* had already
  healed when it was reported; `sync-cursor-corrupt` is the only one, because to
  list it as open would leave an entry that nothing could ever clear. A resolved
  condition leaves the open set. If its event was delivered, it also sends a
  recovery that names how long the condition lasted.

  Only a component that re-evaluates a condition can honestly report it clear.
  Thus sync, which is a polling loop, clears its conditions on a completed cycle.
  The broker is request-driven, clears its one condition on a successful lookup,
  and is therefore latent: it learns that the admission group is back when
  somebody next logs in.

  A recovery is judged against the severity floor that its **event** passed, and
  that is why the raised severity is stored. To judge it as `info` would leave an
  operator who raised `notify.min_severity` with each alarm and no all-clear. It
  is *displayed* as `info` in any case, because it is good news.

  Resolution is by event, across each subject at one time. Several subjects
  describe the symptom rather than a stable thing — the reason that an
  admission-group lookup failed, or the set of colliding names. Thus a caller
  that has just proven the condition false cannot name the subject that it was
  raised under, and a reworded reason would strand the old record forever.
- **Flapping needs no separate mechanism.** The last-notified stamp outlives the
  condition that it belongs to. Thus a condition that clears and returns inside
  the repeat interval is not announced a second time. This is deliberately *not*
  an in-memory dwell counter: a crash loop is exactly when conditions are raised
  and cleared again and again, and that is the case that in-memory state forgets.
  The files still track each transition exactly. Only the chat channel is calmed
  down.
- Both halves of an announcement carry the current open set. Thus one message
  says what changed *and* what the deployment's whole problem list now is. It
  rides on `%DETAIL%`, and not on a placeholder of its own, and thus an operator
  who has already written a custom template gets it and edits nothing.
- A notification channel can fail as silently as the condition that it reports.
  Thus each service supports a `--test-notification` run, which sends a synthetic
  `info` event and bypasses both the severity floor and the rate limit. `make
  test-notification` is that run. Installation is not complete until somebody has
  seen the event arrive.
- **The webhook connection validates TLS, by default and by preference.** Two
  configured escapes cover the legitimate cases, and neither is a blanket
  downgrade:
  - An operator CA file, for a self-hosted receiver behind a private CA. It is
    *added* to the public roots, and does not replace them. The LDAPS trust
    decision in `kerbridge-core::tls` is different: it refuses the public roots
    outright, because an LDAPS bind has exactly one legitimate peer and a webhook
    does not.
  - An explicit per-URL insecure opt-in, for a lab. It logs a standing warning
    for as long as it is set. It is keyed on the receiver's *host*, and thus to
    point the deployment at a different receiver turns validation back on, and
    does not carry the exemption silently across. The same opt-in is what permits
    an `http://` URL, which is otherwise refused: plaintext hands the URL to
    anyone on the path, which is strictly worse than an unvalidated certificate.

  Neither escape is the default.

<details>
<summary>Why webhook TLS is not skippable, despite circular trust-store failure</summary>

The URL is the channel's only authentication for common receivers. Thus a
connection that does not authenticate its peer lets a network attacker capture
the URL. The attacker can then post forged `info` events into the operator's
channel, which mutes the alarm, and can read the directory (realm)-derived text in each
event body.

Notification is itself subject to the trust store that it reports on. If the
roots are old enough to break an IdP path, a webhook to a public receiver
chains to the same roots and fails too. The answer is refreshable native roots,
and not to skip validation. To skip validation would not reach that receiver
either, and would only surrender the channel's authentication.
`--test-notification` proves that the channel reaches its receiver, before an
incident depends on it.

</details>

Events and their repeat policy follow. This table is the union of all adapter
events. An adapter raises only the events that its IdP can produce.

| Event | Raised by | Repeat |
|---|---|---|
| `sync-not-configured` — no credential for the source's IdP yet, so sync is idle | sync | persisting |
| `sync-credential-expiring` | sync | countdown |
| `sync-credential-expired` | sync | persisting |
| `admission-group-missing` — no group carries the realm-admission marker, so nobody can be admitted | sync **and the broker** | persisting |
| `admission-group-ambiguous` — two or more groups carry the realm-admission marker, so which group admits is undefined | the broker | persisting |
| `grant-group-missing` — no group carries the device-grant marker, so every device grant is refused. Not a freeze: ordinary sign-in is unaffected | broker | persisting |
| `grant-group-ambiguous` — two or more groups carry the device-grant marker. Refuses the same grants for the opposite reason | broker | persisting |
| `grant-group-misconfigured` — the configured device-grant group and the marker disagree, in either direction: grants still working after the operator turned the feature off, or no machine able to authorize at all. Invisible to the broker, which sees one marked group and nothing wrong | sync | persisting |
| `device-grants-expiring` — one aggregate, not one problem per device: a laptop fleet would make the per-device form unusable, and the per-user channel already exists in the tray. Off unless `sync.toml`'s `device_grant_notify` names a threshold | sync | persisting |
| `sync-cursor-corrupt` — a stored delta cursor was rejected and the cycle fell back to a full read. The one **incident**: never an open problem | sync | persisting |
| `sync-cycle-failing`, after three consecutive discarded cycles — a stalled read or a transport failure against a directory (IdP) or the directory (realm) discards a cycle | sync | persisting |
| `sync-name-collision` — a `sAMAccountName` collision blocked the whole cycle | sync | persisting |
| `sync-apply-failing` — the directory (realm) rejected writes the plan expected to succeed, usually a delegation ACE that was never granted. The cycle returns `Ok`, so nothing else counts it | sync | persisting |
| `idp-trust-failure` — outbound TLS to the IdP could not be validated, distinct from the IdP being merely unreachable. Keyed per source | broker | persisting |
| `idp-keys-unavailable` — the IdP signing keys could not be fetched and it is not a trust problem. `error` at startup and once the cached document has expired, `warning` while cached keys still serve. Keyed per source | broker | persisting |
| `directory-unavailable` — the directory (realm) is not answering, so no login can succeed. A rejected bind — a rotated `svc-kerbridge-broker` password — is indistinguishable from here and equally fatal | broker | persisting |
| `issuer-refused` — `issuerd` refused an account the broker admitted, so the two disagree. Keyed per account | broker | persisting |
| `identity-ambiguous` — two directory (realm) objects carry one external identity. Keyed per identity | broker | persisting |

The `<role>-group-<fault>` events above are one family. Each one names a
single condition with a single way out: create and mark a group, unmark the
extras, or make the configuration and the marker agree. They are separate
problems, and not one problem that is keyed by the reason, because the
faults change into each other without passing through health. A realm with no
marked group acquires a second one and is now ambiguous, and it was never right.
Thus a service that concludes one of them clears the rest of the family in the
same breath. If it did not, an operator would read a stale instruction beside a
live one.

`admission-group-missing` is the freeze-and-alert case. It also covers a
directory (IdP) read that came back complete but empty, which is indistinguishable
from an IdP that genuinely emptied. To freeze is the side to be wrong on.

`test-notification` is emitted too, and is deliberately not in these tables. It
is the `--test-notification` self-test: an `info` event that reports nothing, is
raised by an operator and not by a condition, has no repeat policy, and has
nothing to clear.

Only a cycle that reached the end of its *write* breaks the run of failures
behind `sync-cycle-failing`. A cycle that merely read its directory (IdP)
successfully does not break it. Otherwise a directory (realm) that answers reads and refuses writes would clear
the count as fast as it raised it, and would never alert, however long it stayed
broken.

The first event and the second-to-last event in the table were emitted by sync
before this list was written, and were missing from it. They are recorded here
and not dropped from the code, because both are conditions that only an operator
can clear.

Each event is keyed on the subject that it is about: the adapter's stable
credential identifier, for the two credential events; the reason for a
`<role>-group-*` problem; the colliding names for `sync-name-collision`; and the
source name, for the two `idp-*` conditions, which are about one configured IdP
and not about the deployment. Two groups that carry a marker and three that
carry it are one condition, but a reworded reason must not sit behind the first
one's repeat interval. `sync-cycle-failing` and `sync-cursor-corrupt` are about
the deployment, and have no subject.

Where each condition is disproved, because only whatever would have raised a
condition can clear it:

| Event | Cleared by |
|---|---|
| `sync-not-configured` | the credential file having content |
| `sync-credential-expiring` | a deadline back beyond 30 days |
| `sync-credential-expired` | a token acquisition that succeeds |
| `admission-group-missing` | a plan that built with no admission-group alert (sync); a directory (realm) lookup that completed (broker) |
| `admission-group-ambiguous` | a directory (realm) lookup that completed |
| `grant-group-missing`, `grant-group-ambiguous` | a directory (realm) lookup that completed |
| `grant-group-misconfigured` | a plan that built with no device-grant alert |
| `device-grants-expiring` | a cycle in which no grant is inside the window |
| `sync-cycle-failing` | a cycle that reached the end of its write |
| `sync-name-collision` | a plan that built at all |
| `sync-apply-failing` | a cycle whose writes all applied |
| `idp-trust-failure`, `idp-keys-unavailable` | a signing-key fetch **for that source** that succeeds |
| `directory-unavailable` | a directory (realm) lookup that completed |
| `issuer-refused` | **that account** getting a ticket |
| `identity-ambiguous` | **that identity** resolving to one object |

The last two and the two `idp-*` conditions clear one subject, and not the whole
event: a second broken account is not fixed when the first one works, and a
second IdP answering does not make the first one reachable. Each other event
clears across each of its subjects, because its subject describes the symptom
and not a stable thing.

The broker's conditions are all latent. The broker is request-driven, and
thus both the raise and the clear wait for somebody to log in. On a quiet
deployment, an operator can learn at 09:00 about a directory (realm) that stopped
answering overnight. The `idp-*` conditions are raised only if a token arrives
that carries an unknown `kid`, because nothing else prompts a refresh. Sync's
conditions are prompt, because a polling loop re-evaluates on its own.

`notify.min_severity` suppresses anything below the configured level.
`--test-notification` ignores it, because a floor above `info` would otherwise
make the test prove nothing.

The webhook URL is a credential, and for common chat receivers it is the *only*
authentication. Thus it is a secret file, and not an `.env` value.

Notification has two consumers, and not one:

- **Sync** raises the credential, cycle, plan and apply events,
  `admission-group-missing`, and `grant-group-misconfigured`. That is the one
  fault in the family that only sync can see, because only sync reads the
  operator's configuration beside the marker. Sync has no admission
  `-misconfigured` reading: the file names the group by object id, so a marker
  found anywhere else is repointed rather than reported.
- **The broker** raises the admission problems that it can see too. It counts the
  groups that carry the `kbrole1|realm-admission` marker at each request — none
  is `-missing`, and two or more is `-ambiguous` — and it used to only fail the
  request. Either service can be the only one that runs when this happens. It
  reads the device-grant marker the same way, for the same two faults. It also
  raises what only it can see: the two `idp-*` conditions from its signing-key
  path, `directory-unavailable`, `issuer-refused` and `identity-ambiguous`. In
  each case the refusal that the client sees is unchanged, because none of these
  tell a caller anything new and there is nothing that a caller can do. What is
  new is that a human hears about it.
- Both services already link an HTTP client.
- `issuerd` must be kept out of it. It holds KDC authority, and a notifier would
  add an HTTP and TLS dependency tree inside the privileged process. Thus
  notification lives in its own `kerbridge-notify` crate, and not in
  `kerbridge-core`, which `issuerd` links.

Sync keeps an audit file of its own, on its own mount, for the same reason as the
other services and with one more behind it: it is the daemon that *creates*
the objects. A ticket expires in hours and a device grant in days, but an account
that sync mints owns files and is a Kerberos principal until somebody retires it.
Nothing else in the deployment says who was given one.

What lands in the file is the cycles that changed something: the tally, then one
line per applied write that names the operation and the object that it touched,
and one line per write that the directory (realm) refused. A cycle that changed nothing is
a console heartbeat and nothing more. The file answers *who was given what, and
when*, and a line at each interval that says that nobody was is what would bury
the answer. Conflicts and skipped destructive actions stay on the console for the
same reason: they changed nothing. A source that has discarded three cycles in a
row records that crossing and its recovery, and thus a stretch during which the
directory (realm) was not updated can be dated afterwards. The days that remain on the
sync credential are a notification and not a record, at warning severity after
the configured threshold is crossed.

## Test architecture

The tiers are in order, cheapest first, because each one needs more of the
world than the last: nothing, a cross-compiler, Docker, and a provisioned
realm. The `Makefile` is authoritative, and `make test-all` runs them all.

| Target | Needs | What it covers |
|---|---|---|
| `make test` (= `test-fast`) | stable Rust | `cargo test --workspace`, `cargo clippy -D warnings`, `shellcheck` over the deployment's scripts, a doc-link checker that resolves every relative markdown link and `#anchor` in the tree, and the Windows client's *pure-logic* unit tests — `krbcred.rs`'s DER encoding and `discovery.rs`'s URL rules — built for the host triple. Those need no Windows and no MinGW: nothing in a test references the Win32 FFI, so the linker never pulls those modules out of the rlib |
| `make test-win` | MinGW-w64 | the Windows client as a Windows artifact: a clean cross-build to `x86_64-pc-windows-gnu` plus clippy. What this covers and `test-fast` cannot is the **link** — that the shipping binary really builds against the Win32 FFI. LSA, ccache injection and the message loop are not testable on any host, and are checked on a real client by hand |
| `make test-build` | Docker | every shipping artifact still builds: the service images, both `.exe`s, the operator CLI and the MSI. It does not resolve the image-only authentik and PostgreSQL pins; a cached build also does not prove that a registry still serves a pin |
| `make test-authentik` | Docker and the pinned external images | the authentik adapter from OIDC sign-in and a full directory (IdP) read through TGT issuance and an SMB file read. The preflight checks for both images in the local image store; Compose pulls an absent image |
| `make test-stack` | Docker | the whole server path against a realm provisioned from an empty volume: sign-in proof to a file read over SMB, no tenant and no secret. Runs in a disposable copy of the tree with its own project, names, subnet and port, so it is safe beside a running bench |
| `make test-deb` | Docker | the Debian packages themselves: `lintian` at build time, then an install, a purge and `piuparts` on trixie and noble, and a check that bookworm and jammy refuse `kerbridge-issuerd` |

`test-fast` opens with `cargo fmt --all --check` over both workspaces. The style
is rustfmt's default with `use_small_heuristics = "Max"`. `rustfmt.toml` is at the
repo root, and the nested client workspace inherits it.

The boundaries that those tiers exercise, and where each one lands:

- The Entra and authentik token verifiers, with local JWKS and claim fixtures —
  unit. Both adapters pass the common verifier conformance suite.
- Provider-neutral external identity normalization — unit, in `kerbridge-core`.
- The shared reconciliation planner, as a pure desired/current-state comparison
  — unit. Its tests replay recorded Graph fixtures. The authentik adapter also
  has a recorded full-read corpus with torn-read and dangling-member cases.
- Notification templating, escaping, repeat policy and the durable record —
  unit, in `kerbridge-notify`. Delivery runs against a loopback
  receiver, and covers what a receiver actually gets, that a 404 is not delivery,
  and that a transport failure does not put the webhook URL in a log line.
- `issuerd` protocol framing and ccache parsing — unit.
- The LDAP mapper, the Samba reconciliation adapter and `issuerd` issuance,
  against a real provisioned domain — `test-stack`. It also exercises the realm
  entrypoint's first-run provisioning, and the administrator-password replacement
  on each run.
- Joined file-server authorization, with `idmap_rid` and nested groups —
  `test-stack`.
- Authentik token verification, directory (IdP) reading, sync, ticket issuance,
  and joined file-server authorization — `test-authentik`.
- Windows end-to-end ticket injection and the re-injection lifecycle —
  **manual**. The live Entra tenant and the ACME TLS strategies are manual too.

Each IdP verifier must pass the common verifier conformance suite. A future
federation deployment changes the configured authority and the verifier policy.
It does not change the Samba mapping, the issuer protocol or the helper ticket
format.
