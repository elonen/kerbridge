use super::*;
use std::sync::Arc;

#[test]
fn a_deployment_with_no_url_still_logs() {
    let n = Notifier::from_config("test", &Notify::default(), "EXAMPLE.SITE").unwrap();
    assert!(n.channel.is_none());
}

/// The rule the whole TLS section exists for. `http://` publishes the
/// channel's only credential to anyone on the path.
#[test]
fn a_plaintext_url_is_refused_unless_its_host_is_named() {
    let err = insecure_opt_in("http://hooks.example.site/T000/B000", "test", None).unwrap_err();
    assert!(err.to_string().contains("notify.insecure_host"), "{err}");

    let ok =
        insecure_opt_in("http://hooks.example.site/T000/B000", "test", Some("hooks.example.site"));
    assert!(ok.unwrap());
}

/// Per-URL, not global: an exemption written for a lab receiver must not
/// follow the deployment to a real one.
#[test]
fn the_insecure_opt_in_does_not_carry_over_to_another_host() {
    let lab = Some("lab.example.site");
    let carried = insecure_opt_in("https://hooks.example.site/T000/B000", "test", lab);
    assert!(!carried.unwrap());

    // And it does not turn a plaintext URL to a *different* host into an
    // accepted one either.
    let still_refused = insecure_opt_in("http://hooks.example.site/T000/B000", "test", lab);
    assert!(still_refused.is_err());
}

#[test]
fn https_needs_no_opt_in_and_a_non_web_scheme_is_not_a_webhook() {
    assert!(!insecure_opt_in("https://hooks.example.site/T000/B000", "test", None).unwrap());
    for bad in ["ftp://host/x", "file:///etc/passwd"] {
        assert!(insecure_opt_in(bad, "test", None).is_err(), "{bad}");
    }
    assert!(insecure_opt_in("not a url", "test", None).is_err());
}

/// The default has to satisfy the template rules it is the example of.
#[test]
fn the_default_template_parses_and_renders_json() {
    let body = Template::parse(DEFAULT_TEMPLATE).unwrap().render(&Values {
        event: "sync-cycle-failing",
        severity: "error",
        component: "sync",
        realm: "EXAMPLE.SITE",
        timestamp: "2026-07-30T12:00:00Z",
        message: "3 cycles discarded in a row",
        detail: "",
        icon: severity_icon(Severity::Error),
    });
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let text = parsed["text"].as_str().unwrap();
    assert!(text.contains("sync-cycle-failing"), "{text}");
    assert!(text.contains("EXAMPLE.SITE"), "{text}");
    assert!(text.contains("3 cycles discarded in a row"), "{text}");
}

/// `reqwest` puts the request URL in its error Display, and the URL is the
/// channel's only authentication. A receiver that is simply not there must
/// not be the thing that writes the webhook secret into the log.
#[tokio::test]
async fn a_transport_failure_does_not_log_the_url() {
    // Bound and dropped, so the port is closed and the connection is
    // refused immediately -- no timeout to wait out, and no server to run.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);

    let notifier = notifier_with(
        Some(format!("http://127.0.0.1:{port}/T00000/B00000/s3cr3t-webhook-token")),
        Severity::Info,
        Duration::from_secs(2),
    );
    let channel = notifier.channel.as_ref().unwrap();
    let event = Event::new("test-notification", Severity::Info, "hello");
    let err = format!(
        "{:#}",
        notifier.post(channel, &event, severity_icon(event.severity), 0).await.unwrap_err()
    );
    assert!(!err.contains("s3cr3t-webhook-token"), "{err}");
    assert!(!err.contains(&port.to_string()), "{err}");
}

/// What a receiver actually gets: the method, the fixed content type, and a
/// JSON body carrying the rendered event. The other half is that answering
/// at all is not success -- a webhook that has been revoked answers 404, and
/// would otherwise read as delivered.
#[tokio::test]
async fn a_receiver_sees_one_json_post_and_only_a_2xx_counts_as_delivered() {
    for (status, expect_ok) in
        [(axum::http::StatusCode::OK, true), (axum::http::StatusCode::NOT_FOUND, false)]
    {
        let (url, seen, _served) = receiver(status).await;
        let notifier = notifier_posting_to(url);
        let channel = notifier.channel.as_ref().unwrap();
        let event = Event::new("sync-cycle-failing", Severity::Error, "3 cycles discarded")
            .detail("since 2026-07-30");
        let result =
            notifier.post(channel, &event, severity_icon(event.severity), 1_785_412_800).await;
        assert_eq!(result.is_ok(), expect_ok, "{status}: {result:?}");

        let (content_type, body) = seen.lock().unwrap().clone().expect("nothing was posted");
        assert_eq!(content_type, "application/json");
        let text = serde_json::from_str::<serde_json::Value>(&body).unwrap()["text"]
            .as_str()
            .unwrap()
            .to_owned();
        for expected in [
            "sync-cycle-failing",
            "error",
            "sync",
            "EXAMPLE.SITE",
            "2026-07-30T12:00:00Z",
            "3 cycles discarded",
            "since 2026-07-30",
        ] {
            assert!(text.contains(expected), "{expected} missing from {text}");
        }
    }
}

/// A one-request HTTP receiver: its URL, what it saw, and the task serving
/// it (dropped by the caller to shut it down).
type Seen = Arc<Mutex<Option<(String, String)>>>;

async fn receiver(status: axum::http::StatusCode) -> (String, Seen, tokio::task::JoinHandle<()>) {
    let seen: Seen = Arc::new(Mutex::new(None));
    let captured = seen.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
            let captured = captured.clone();
            async move {
                let content_type = headers
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                *captured.lock().unwrap() = Some((content_type, body));
                status
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    let served = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, seen, served)
}

fn notifier_posting_to(url: String) -> Notifier {
    notifier_with(Some(url), Severity::Info, Duration::from_secs(5))
}

/// A notifier holding its problem state in memory, so nothing in these tests
/// touches a directory. `insecure` is set throughout because every receiver
/// here is plain HTTP on loopback; nothing about TLS is under test.
fn notifier_with(url: Option<String>, min_severity: Severity, timeout: Duration) -> Notifier {
    Notifier {
        component: "sync",
        realm: "EXAMPLE.SITE".into(),
        min_severity,
        repeat_interval: Duration::from_secs(3600),
        problems: Mutex::new(Problems::load(None, "sync", 3600, 0)),
        channel: url.map(|url| Channel {
            http: http_client(timeout, None, true).unwrap(),
            url,
            template: Template::parse(DEFAULT_TEMPLATE).unwrap(),
        }),
    }
}

/// The rate limit as the caller meets it: `send` delivers the first and
/// swallows the second, and neither one can fail the caller.
#[tokio::test]
async fn send_delivers_once_per_interval_and_returns_nothing_on_failure() {
    let (url, seen, _served) = receiver(axum::http::StatusCode::OK).await;
    let notifier = notifier_posting_to(url);
    let event = || Event::new("admission-group-missing", Severity::Error, "no group carries it");

    notifier.send(event()).await;
    assert!(seen.lock().unwrap().is_some());
    *seen.lock().unwrap() = None;
    notifier.send(event()).await;
    assert!(seen.lock().unwrap().is_none(), "the repeat interval did not hold");

    // A receiver that is not there is logged, not returned: `send` has no
    // failure a caller could accidentally propagate into a sync cycle.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = dead.local_addr().unwrap().port();
    drop(dead);
    notifier_posting_to(format!("http://127.0.0.1:{port}/hook")).send(event()).await;
}

/// Below the floor is not delivered, and there is no receiver here to
/// deliver to -- the assertion is that `send` returns rather than hanging on
/// a connection to a port nothing is listening on.
#[tokio::test]
async fn an_event_below_the_floor_is_never_sent() {
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    // The timeout is long enough that an attempted send would be visible as
    // a hang rather than as a fast failure.
    let notifier = notifier_with(
        Some(format!("http://127.0.0.1:{port}/hook")),
        Severity::Error,
        Duration::from_secs(30),
    );
    let started = std::time::Instant::now();
    notifier.send(Event::new("sync-cursor-corrupt", Severity::Warning, "m")).await;
    assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
}

/// The other half of the channel: a condition that clears says so, names how
/// long it lasted, and carries the aggregate so one message answers both
/// "what changed" and "what is still wrong".
#[tokio::test]
async fn a_resolved_condition_is_announced_with_the_remaining_problem_list() {
    let (url, seen, _served) = receiver(axum::http::StatusCode::OK).await;
    let notifier = notifier_posting_to(url);

    notifier.send(Event::new("admission-group-missing", Severity::Error, "no group")).await;
    notifier.send(Event::new("sync-cycle-failing", Severity::Error, "3 in a row")).await;
    let raised = text_seen(&seen);
    assert!(raised.contains("2 open: admission-group-missing, sync-cycle-failing"), "{raised}");

    notifier.resolve("admission-group-missing").await;
    let recovered = text_seen(&seen);
    assert!(recovered.contains("admission-group-missing"), "{recovered}");
    assert!(recovered.contains("recovered after"), "{recovered}");
    assert!(recovered.contains("info"), "{recovered}");
    assert!(recovered.contains("was: no group"), "{recovered}");
    assert!(recovered.contains("1 open: sync-cycle-failing"), "{recovered}");

    // Nothing is open once the last one goes, and saying so is the point.
    notifier.resolve("sync-cycle-failing").await;
    assert!(text_seen(&seen).contains("no problems open"));
}

/// A chat client puts a raise and its all-clear in the same colour, so the glyph
/// is what tells them apart in a channel somebody is scrolling past.
#[tokio::test]
async fn a_raise_and_its_recovery_do_not_carry_the_same_icon() {
    let (url, seen, _served) = receiver(axum::http::StatusCode::OK).await;
    let notifier = notifier_posting_to(url);

    notifier.send(Event::new("grant-group-missing", Severity::Error, "no group carries it")).await;
    assert!(text_seen(&seen).starts_with('\u{1f534}'), "{}", text_seen(&seen));

    notifier.resolve("grant-group-missing").await;
    assert!(text_seen(&seen).starts_with('\u{2705}'), "{}", text_seen(&seen));

    notifier
        .send(Event::new("sync-cursor-corrupt", Severity::Warning, "resynced").incident())
        .await;
    assert!(text_seen(&seen).starts_with('\u{1f7e0}'), "{}", text_seen(&seen));
}

/// Resolving something that was never open says nothing at all, so the
/// broker may clear its condition on every successful request.
#[tokio::test]
async fn resolving_an_unraised_condition_announces_nothing() {
    let (url, seen, _served) = receiver(axum::http::StatusCode::OK).await;
    let notifier = notifier_posting_to(url);
    notifier.resolve("admission-group-missing").await;
    assert!(seen.lock().unwrap().is_none(), "a recovery was sent for nothing");
}

/// The role-group family changes arity: a realm with no marked group can
/// acquire two without ever being healthy in between. The caller that concludes
/// the second reading clears the first, so an operator sees one open problem
/// naming the condition that is actually true -- not a stale `missing` beside a
/// live `ambiguous`, with the wrong instruction attached to the wrong one.
///
/// This is the sequence sync and the broker both perform: raise the reading that
/// holds, clear its siblings.
#[tokio::test]
async fn a_condition_that_changes_arity_does_not_leave_the_earlier_reading_open() {
    let (url, seen, _served) = receiver(axum::http::StatusCode::OK).await;
    let notifier = notifier_posting_to(url);

    notifier
        .send(Event::new(
            "admission-group-missing",
            Severity::Error,
            "no group carries the kbrole1|realm-admission marker",
        ))
        .await;
    assert!(text_seen(&seen).contains("1 open: admission-group-missing"));

    // The operator creates a second group and marks it, without unmarking the
    // first: the arity goes from zero to two in one step.
    notifier
        .send(Event::new(
            "admission-group-ambiguous",
            Severity::Error,
            "2 groups carry the kbrole1|realm-admission marker",
        ))
        .await;
    notifier.resolve("admission-group-missing").await;
    notifier.resolve("admission-group-misconfigured").await;

    let after = text_seen(&seen);
    assert!(after.contains("admission-group-missing"), "no all-clear for the old reading: {after}");
    assert!(after.contains("recovered after"), "{after}");
    assert!(after.contains("1 open: admission-group-ambiguous"), "{after}");
}

/// The two families are separate problems, not one keyed by role: a realm can
/// have no admission group *and* two device-grant groups, and clearing either
/// must not silence the other.
#[tokio::test]
async fn the_role_group_problems_are_four_independent_conditions() {
    let (url, seen, _served) = receiver(axum::http::StatusCode::OK).await;
    let notifier = notifier_posting_to(url);

    for problem in [
        "admission-group-missing",
        "admission-group-ambiguous",
        "grant-group-missing",
        "grant-group-ambiguous",
    ] {
        notifier.send(Event::new(problem, Severity::Error, "why")).await;
    }
    assert!(text_seen(&seen).contains("4 open: "));

    notifier.resolve("admission-group-missing").await;
    let after = text_seen(&seen);
    assert!(
        after.contains(
            "3 open: admission-group-ambiguous, grant-group-ambiguous, grant-group-missing"
        ),
        "{after}"
    );
}

/// A recovery is judged against the floor its *event* passed, not against
/// `info`. An operator who raises the floor to quiet the channel down would
/// otherwise get every alarm and never a single all-clear.
#[tokio::test]
async fn a_recovery_clears_the_floor_its_alert_cleared() {
    let (url, seen, _served) = receiver(axum::http::StatusCode::OK).await;
    let mut notifier = notifier_posting_to(url);
    notifier.min_severity = Severity::Error;

    notifier.send(Event::new("sync-cycle-failing", Severity::Error, "3 in a row")).await;
    assert!(seen.lock().unwrap().is_some(), "an error was suppressed");
    *seen.lock().unwrap() = None;
    notifier.resolve("sync-cycle-failing").await;
    assert!(seen.lock().unwrap().is_some(), "the all-clear was lost to the floor");

    // Below the floor, both halves stay silent -- not the event but not the
    // recovery either, which is the pairing that matters.
    notifier.send(Event::new("sync-cursor-corrupt", Severity::Warning, "resynced")).await;
    *seen.lock().unwrap() = None;
    notifier.resolve("sync-cursor-corrupt").await;
    assert!(seen.lock().unwrap().is_none(), "a muted event produced an all-clear");
}

/// The directory is the integration surface, so it is written whether or not
/// a webhook exists -- that is the whole point of it being a directory.
#[tokio::test]
async fn problems_are_written_with_no_webhook_configured() {
    let dir = std::env::temp_dir().join(format!("kb-notify-nohook-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let notifier = Notifier {
        component: "sync",
        realm: "EXAMPLE.SITE".into(),
        min_severity: Severity::Info,
        repeat_interval: Duration::from_secs(3600),
        problems: Mutex::new(Problems::load(Some(dir.clone()), "sync", 3600, 0)),
        channel: None,
    };
    notifier.send(Event::new("sync-cycle-failing", Severity::Error, "3 in a row")).await;
    assert!(dir.join("problem-sync-cycle-failing.json").exists());
    notifier.resolve("sync-cycle-failing").await;
    assert!(dir.join("recent-sync-cycle-failing.json").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// One `notify.state_dir` in `main.toml`, three daemons reading it: each takes
/// the directory named after itself, and writes nothing beside it.
#[tokio::test]
async fn each_component_takes_its_own_directory_under_the_configured_one() {
    let dir = std::env::temp_dir().join(format!("kb-notify-percomp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = Notify { state_dir: Some(dir.clone()), ..Notify::default() };

    for component in ["broker", "sync"] {
        let notifier = Notifier::from_config(component, &cfg, "EXAMPLE.SITE").unwrap();
        notifier.send(Event::new("sync-cycle-failing", Severity::Error, "3 in a row")).await;
        assert!(
            dir.join(component).join("problem-sync-cycle-failing.json").exists(),
            "{component} did not write under its own name"
        );
    }
    assert!(!dir.join("problem-sync-cycle-failing.json").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The `text` of the last thing the receiver saw.
fn text_seen(seen: &Seen) -> String {
    let (_, body) = seen.lock().unwrap().clone().expect("nothing was posted");
    serde_json::from_str::<serde_json::Value>(&body).unwrap()["text"].as_str().unwrap().to_owned()
}
