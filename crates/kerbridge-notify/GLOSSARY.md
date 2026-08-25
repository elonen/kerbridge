# kerbridge-notify glossary

The operator-notification channel: the durable problem directory, the webhook
template, and the repeat/severity rules that decide when to speak again.

Part of the repo-wide vocabulary in [`GLOSSARY.md`](../../GLOSSARY.md) — a term
means the same thing there and here. It lives in this file, closest to where
it's used, rather than in the root file, because the root file would be
unreadably long if it carried every term at once.

### band

One rung of the fixed countdown schedule an operator notification announces on
— 30, 14, 7, 3 and 1 days remaining — with silence between rungs however long
that is. A deadline further out than the widest rung is not yet news, and a
deadline that moves back out disarms the schedule.
<!-- refs: `BANDS` in `crates/kerbridge-notify/src/problems/mod.rs` -->
<!-- avoid: step, schedule -->

### channel

The configured way out to a human: one webhook URL with one
`template`. Its absence is a supported deployment state, not an error — the
`NOTIFY` log lines and the `problem directory` still happen.
<!-- avoid: webhook (when meaning the channel), delivery method -->

### condition (notification)

A state of the world the server raises that stays true until something clears
it, and is listed as an open problem until then. Almost every event is one.
<!-- refs: `kerbridge_notify::Kind::Condition`, as against `Kind::Incident` -->
<!-- avoid: kind -->

### event

The stable kebab-case slug naming which operator-actionable condition this is:
`graph-credential-expiring`, `identity-ambiguous`, `admission-group-missing`.
The word means the slug, not the payload — its durable record is a `problem`,
and the slug is half that record's key and half its file name. Not the
user-facing `notification` an agent raises on a workstation.
<!-- refs: struct `kerbridge_notify::Event` -->
<!-- avoid: operator event, event class -->

### incident

An `event` that was already over by the time it was reported. Announced once
but never listed as `open`, because nothing could ever clear it.
<!-- refs: `kerbridge_notify::Kind::Incident` -->

### last-notified stamp

The time delivery was last *attempted* for a `problem`
— not last succeeded — kept on the record and kept after the condition resolves.
It is the whole of the flap control: a condition that clears and comes straight
back is still inside its own repeat interval, and the stamp survives a restart.
<!-- avoid: last-notified record, the stamp, rate-limit record -->

### open

The property of a `problem` whose condition is still true. The set of open
problems is the deployment's answer to "what is wrong right now", and it is
exactly what the `problem-*.json` files count.
<!-- refs: `problem-*.json` -->
<!-- avoid: still true, outstanding, currently wrong -->

### open summary

The one-line census of every `open` problem — `2 open: <slug>, <slug>`, or
`no problems open` — appended to the detail of every announcement, so one
message says both what changed and what is still wrong.
<!-- refs: `Problems::open_summary` -->
<!-- avoid: aggregate, census, the problem list, summary -->

### placeholder

A `%NAME%` in the notification `template` naming one of the substitutable
values: `%EVENT%`, `%SEVERITY%`, `%COMPONENT%`, `%REALM%`, `%TIMESTAMP%`,
`%MESSAGE%`, `%DETAIL%`, `%ICON%`. Every substituted value is escaped as a JSON string,
so nothing a tenant can name can reshape the body.
<!-- refs: `crates/kerbridge-notify/src/template.rs` -->
<!-- avoid: field, substituted value, substitution set -->

### problem

The durable record of a raised `event`: one JSON object per (slug,
`subject`), carrying its severity, message, when it was first raised and when
delivery was last attempted. It outlives the condition it describes and is
stateful on purpose — raised once and later resolved, so a restart loop does not
become an event flood.
<!-- avoid: record, state file, entry -->

### problem directory

The directory of `problem` records on disk, and the integration surface for a
deployment that wants a monitoring agent rather than a chat channel. Two file
classes, told apart by name so one can be counted without parsing the other:
`problem-*.json` is `open`, `recent-*.json` is resolved-or-`incident` and is
kept only while its `last-notified stamp` still matters.
<!-- refs: `notify.state_dir`, `problem-*.json`, `recent-*.json` -->
<!-- avoid: state dir, notification state directory -->

### problem file

One `problem-<event>.json` under `state/<service>/` on the host, written
whether or not a webhook is configured; counting them is the whole integration
for an operator's own monitoring. An event with a `subject` gets
`problem-<event>__<hash>.json`, because a subject is arbitrary text and a file
name has to be one bounded path component.
<!-- refs: `problem-<event>.json` and `problem-<event>__<hash>.json` under `state/<service>/` -->
<!-- avoid: alert file, condition file, event file -->

### recovery

The `info` announcement that a resolved condition has gone,
naming how long it lasted and what it had been. Judged against the `severity
floor` its own event passed rather than against `info`, so raising the floor
cannot leave an operator with alarms and no all-clears.
<!-- avoid: all-clear, recovered (as a noun) -->

### repeat policy

Which rule decides that an already-recorded condition is worth announcing
again. There are exactly two: *persisting* (again once the configured repeat
interval has passed) and *countdown* (again only on entering a nearer `band`).
<!-- refs: `kerbridge_notify::Repeat`, `notify.repeat_interval_hours` -->
<!-- avoid: repeat, rate limit, rate limiter -->

### resolve

To declare a condition no longer true, from the place that would have raised
it and did not. One call clears every open `subject` of a slug at once; another
clears one named subject, for a condition that only that subject succeeding can
disprove.
<!-- refs: `Notifier::resolve`, `Notifier::resolve_subject` -->
<!-- avoid: clear, close, disprove -->

### severity floor

The configured minimum severity for delivery. Anything below it is still
recorded in the `problem directory` but never sent — and never consumes a
`last-notified stamp`, so an event that was never going to go out cannot mute
one that would.
<!-- refs: `notify.min_severity` -->
<!-- avoid: min severity, the configured level -->

### subject (notification)

What *this occurrence* of a reported problem is about — the credential, the
group, the account — and the other half of the record key alongside the event
slug, so two occurrences of one slug do not suppress each other behind one
repeat interval. Arbitrary text, empty when the condition is about the
deployment as a whole.
<!-- refs: `kerbridge_notify::Event::subject` -->
<!-- avoid: instance, scope, key -->

### template

The single JSON body an operator may replace, written with `%PLACEHOLDER%`
substitution. It is validated at startup by rendering it with hostile values
and parsing the result, so a template that cannot produce JSON stops the
service instead of emptying a field at three in the morning.
<!-- refs: `notify.template` -->
<!-- avoid: body, payload -->
