# kerbridge-notify — telling an operator what only they can fix

Some conditions are invisible in a log nobody reads and actionable by nobody
else: an expiring Graph credential, a deleted admission group, a sync cycle that
keeps failing. This is the one channel they leave by.

`DESIGN.md` § [Operator notification](../../docs/design/operations.md#operator-notification) is
authoritative, including the event list and what each `[notify]` key does.
`deploy/configs/main.toml.example` is the reference for the keys themselves.

## Why it is a crate of its own

`issuerd` links `kerbridge-core` and holds KDC authority. A notifier inside that
dependency tree would put an HTTP client and a TLS stack inside the most
privileged process in the system, to serve a feature it has no part in. So the
notifier lives here, and only `kerbridge-broker` and `kerbridge-sync` link it —
both of which already have an HTTP client for their own reasons.

## What it guarantees

**Nothing a tenant can name may reshape the payload.** The body is one JSON
template with `%PLACEHOLDER%` substitution, and every substituted value goes
through `serde_json`'s own string escaper. Directory-derived text — a display
name, a group name, an error quoting either — can carry quotes, backslashes and
newlines, and none of it can close the string it lands in. The content type is
fixed for the same reason: a configurable one would let a template select an
encoding the escaper does not implement. An unknown placeholder, or a template
that does not render as JSON, is a startup error rather than a broken event at
three in the morning.

**Nothing may flood it.** The last-notified record is durable and keyed on event
*and* subject, so a crash loop cannot re-send everything outstanding on every
restart, and two groups carrying the admission marker are two events rather than
one. Two repeat policies, because two kinds of condition need them:

- a condition that simply persists repeats on `notify.repeat_interval_hours`;
- a countdown does not. An expiry is reported as it crosses 30, 14, 7, 3 and 1
  days remaining and is silent between those — on a 24 h interval a 30-day
  countdown would send thirty events, which is the flood the limit exists
  to prevent.

The stamp outlives the condition it belongs to, which is also the whole of the
flap control: one that clears and comes straight back is not announced twice
inside the interval. An in-memory dwell counter would have missed the case that
matters, since a crash loop is exactly when a condition is raised and cleared
repeatedly and exactly what in-memory state forgets.

**The webhook is not the only way out.** That record is a directory —
`problem-<event>.json` per condition currently true, `recent-<event>.json` once it
has cleared — written whether or not a webhook is configured. Point a Zabbix
agent or a cron script at it and counting `problem-*.json` is the whole
integration, which is why the class is in the file name rather than only in the
body. `kbmanage problems` reads the same set for a human, on the host that wrote
it. Files are `0640` with the group left alone, so `chgrp` plus the setgid bit
on the directory is all an operator needs to let their agent read them; the mode
is set explicitly rather than left to `umask`, which under `umask 077` would
otherwise lock that agent out.

**A condition that clears says so.** `Notifier::resolve` closes every open subject
of an event and sends a recovery for each that had been delivered. Resolution is
by event and not by subject because several subjects describe the *symptom* — the
reason an admission-group lookup failed, the set of colliding names — so a caller that has
just proven the condition false cannot name the subject it was raised under. The
recovery is judged against the floor its event passed, using the severity stored
on the record: judging it as `info` would leave an operator who raised
`notify.min_severity` with every alarm and no all-clear.

An `Event` is a condition unless `.incident()` says otherwise. An incident is
something already over when it is reported, and listing it as open would leave an
entry nothing could ever clear.

**Nothing may fail because of it.** One attempt, bounded by
`notify.timeout_seconds`, no retry. `Notifier::send` returns nothing at all, so
there is no failure a caller could accidentally propagate into a sync cycle or a
ticket request. Every event is written to the service's own log as a
`NOTIFY <severity> <event>: <message>` line first, whether or not a webhook is
configured — the log is the fallback, not the seam.

**The URL never reaches a log.** For common chat receivers it is the channel's
only authentication. `reqwest` puts the request URL in its error text, so every
transport error out of here is stripped of it before it is logged — there is a
test for exactly that.

## Using it

```rust
let notifier = Notifier::from_config("sync", &config.notify, &config.realm)?; // "sync" is %COMPONENT%
notifier.send(
    Event::new("graph-credential-expiring", Severity::Warning, "expires in 14 days")
        .subject(&client_id)                        // keyed with the slug
        .countdown(14),                             // not the repeat interval
).await;

// Wherever the condition is disproved -- the point that would have raised it
// and did not. Costs nothing when nothing is open, so a per-request caller may
// call it unconditionally.
notifier.resolve("graph-credential-expiring").await;
```

`Notifier::from_config` warns and returns a working notifier when no URL is
configured; that deployment gets the log lines and nothing else, which is a
supported state and the default. `test_notification_requested()` reads the
`--test-notification` flag both services accept, and
`Notifier::test_notification` sends one synthetic `info` event past both the
severity floor and the rate limit — a channel can fail as silently as the
conditions it reports.
