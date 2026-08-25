//! Pure diagnosis: a [`Snapshot`] in, a report out.
//!
//! The question this answers is "my account reaches the server but a folder
//! says access denied", which today takes a manual trace through two
//! OUs. It walks the authorization chain link by link and says which
//! link is broken -- and, at the end, names the one link it cannot see, rather
//! than pretending to have checked it.
//!
//! [`diagnose_reach`] is the same walk one phase earlier, over a [`Reach`]
//! instead of a [`Snapshot`]. A snapshot exists only after a bind has already
//! succeeded, so everything below it diagnoses *authorization* and can say
//! nothing at all about *reach* -- and on a host that is not the DC, reach is
//! what breaks.

use std::collections::BTreeMap;

use kerbridge_core::dn::dn_components;
use kerbridge_core::state::RETIRED_PREFIX;
use serde::Serialize;

use crate::model::{
    Answer, CertFault, CloudObject, Endpoint, Kind, Reach, ResourceGroup, Snapshot, State,
    TrustAnchor,
};
use crate::validate::dn_is_at_or_within;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    /// Works, but is not what the design intends.
    Warn,
    /// This link is broken.
    Fail,
    /// Neither good nor bad -- context the operator needs.
    Info,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub label: &'static str,
    pub status: Status,
    pub detail: String,
}

fn check(label: &'static str, status: Status, detail: impl Into<String>) -> Check {
    Check { label, status, detail: detail.into() }
}

#[derive(Debug, Clone, Serialize)]
pub struct UserReport {
    pub subject: String,
    pub dn: Option<String>,
    pub sam: Option<String>,
    pub checks: Vec<Check>,
    /// The one step this tool cannot take: winbind's view, on the file server.
    pub next_step: Option<String>,
}

impl UserReport {
    pub fn worst(&self) -> Status {
        worst(&self.checks)
    }
}

/// The verdict a chain of checks adds up to. `Info` never carries one: it is
/// context, and context is not a state to exit non-zero on.
fn worst(checks: &[Check]) -> Status {
    if checks.iter().any(|c| c.status == Status::Fail) {
        Status::Fail
    } else if checks.iter().any(|c| c.status == Status::Warn) {
        Status::Warn
    } else {
        Status::Ok
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReachReport {
    /// The directory the walk was aimed at, as the config set spelled it.
    pub target: String,
    pub checks: Vec<Check>,
}

impl ReachReport {
    pub fn worst(&self) -> Status {
        worst(&self.checks)
    }
}

/// What the endpoint walk added up to, in the four shapes a caller has to act
/// on differently.
///
/// A readiness poll is why this is not just [`Status`]: "not yet" and "broken"
/// are the same colour on a screen and opposite instructions to a loop, and the
/// third is opposite again per deployment -- a TLS session that never formed is
/// issuance in flight under an ACME strategy and a certificate file that did not
/// load under a supplied one, and only the caller knows which it configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Reachable {
    /// The broker answered for this path.
    Serving,
    /// Nothing is wrong that waiting cannot fix: nothing listening yet, or the
    /// proxy answering for a broker that has not come up behind it.
    Settling,
    /// The endpoint accepted a connection and no TLS session came of it.
    NoSession,
    /// Answering, and not with this.
    Broken,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointReport {
    /// The URL that was asked for, which is the base the caller gave plus
    /// `/config`.
    pub target: String,
    pub checks: Vec<Check>,
    pub verdict: Reachable,
}

impl EndpointReport {
    pub fn worst(&self) -> Status {
        worst(&self.checks)
    }

    /// One line: the link the walk stopped at, which is the diagnosis.
    ///
    /// What a poll loop prints, and the whole of what the verb outputs. Every
    /// earlier link is either clean or, under `--any-cert`, a fact the caller
    /// said it was not asking about -- and a line that repeated it would put a
    /// warning in a readiness report about the one thing that deployment had
    /// already decided. `--json` and `doctor --endpoint` carry all of them.
    pub fn summary(&self) -> &str {
        self.checks.last().map_or("nothing was asked", |c| c.detail.as_str())
    }
}

/// Walk the public path: does the name resolve, does the port accept, what does
/// the certificate say, and does the broker answer `GET /config` behind it.
///
/// The link `wait-ready.sh` alone used to know: a broker serving several sources
/// legitimately refuses an unprefixed `/config` and lists them, while a path
/// nothing routed refuses it with an empty body. Both are 404, and a success
/// criterion that does not separate them either reports a healthy multi-source
/// deployment as broken or passes a deployment whose route was never wired.
pub fn diagnose_endpoint(endpoint: &Endpoint) -> EndpointReport {
    let mut checks = Vec::new();
    let done = |checks: Vec<Check>, verdict: Reachable| EndpointReport {
        target: endpoint.asked.clone(),
        checks,
        verdict,
    };

    match &endpoint.resolve {
        // `--resolve` was given: the address is the caller's, and saying which
        // one is what tells a probe of the published port from a probe of
        // whatever the site resolver happens to answer.
        None if endpoint.via.is_some() => checks.push(check(
            "address",
            Status::Info,
            format!(
                "not looked up: --resolve named {}. The certificate is still judged \
                 against {}",
                endpoint.via.expect("the arm tested it"),
                endpoint.host
            ),
        )),
        None => return done(checks, Reachable::Broken),
        Some(Ok(addrs)) => checks.push(check(
            "address",
            Status::Ok,
            format!(
                "{} -> {}",
                endpoint.host,
                addrs.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            ),
        )),
        Some(Err(e)) => {
            checks.push(check(
                "address",
                Status::Fail,
                format!(
                    "{} does not resolve from this host: {e}. Either the record is \
                     missing, or this host does not see the published name -- --resolve \
                     names an address instead",
                    endpoint.host
                ),
            ));
            return done(checks, Reachable::Broken);
        }
    }

    match &endpoint.tcp {
        None => return done(checks, Reachable::Broken),
        Some(Ok(addr)) => {
            checks.push(check("connect", Status::Ok, format!("{addr} accepted a connection")));
        }
        Some(Err(e)) => {
            checks.push(check(
                "connect",
                Status::Fail,
                format!(
                    "nothing accepted a connection on port {}: {e}. It is not up yet, \
                     or nothing publishes that port",
                    endpoint.port
                ),
            ));
            // Not a fault to send anyone anywhere over: a stack still coming up
            // spends its first seconds exactly here.
            return done(checks, Reachable::Settling);
        }
    }

    if endpoint.tls {
        let against = match &endpoint.anchor {
            TrustAnchor::Public => "the public roots".to_owned(),
            TrustAnchor::Ca(path) => path.display().to_string(),
        };
        match &endpoint.cert {
            None if endpoint.session.is_none() => return done(checks, Reachable::Broken),
            None => {}
            Some(Ok(())) => checks.push(check(
                "certificate",
                Status::Ok,
                format!("{} presented one that validates against {against}", endpoint.host),
            )),
            Some(Err(fault)) => {
                let (status, verdict) = if endpoint.any_cert {
                    // Context, not a complaint: the caller said this certificate
                    // is not what it is probing for -- an operator's own, or a
                    // staging directory's -- so the walk records what it found
                    // and carries on to the route behind it.
                    (Status::Info, Reachable::Serving)
                } else {
                    (Status::Fail, Reachable::Broken)
                };
                checks.push(check("certificate", status, cert_detail(endpoint, fault, &against)));
                if verdict == Reachable::Broken {
                    return done(checks, verdict);
                }
            }
        }
        match &endpoint.session {
            None => return done(checks, Reachable::Broken),
            Some(Ok(())) => {}
            // One field, two failures. Collapsed into one arm, a handshake that
            // failed past an accepted certificate is reported as no certificate
            // at all, and the operator goes looking at a file that is fine.
            Some(Err(e)) if endpoint.cert.is_none() => {
                checks.push(check(
                    "certificate",
                    Status::Fail,
                    format!(
                        "the TLS handshake ended before a certificate was seen: {e}. An \
                         issuance still in flight looks like this, and so does a \
                         certificate file that did not load"
                    ),
                ));
                return done(checks, Reachable::NoSession);
            }
            Some(Err(e)) => {
                checks.push(check(
                    "TLS session",
                    Status::Fail,
                    format!("the certificate was accepted and the handshake still failed: {e}"),
                ));
                return done(checks, Reachable::Broken);
            }
        }
    }

    match &endpoint.answer {
        None => done(checks, Reachable::Broken),
        Some(Err(e)) => {
            checks.push(check(
                "GET /config",
                Status::Fail,
                format!("{} did not answer: {e}", endpoint.asked),
            ));
            done(checks, Reachable::Settling)
        }
        Some(Ok(answer)) => {
            let (status, verdict, detail) = answer_detail(endpoint, answer);
            checks.push(check("GET /config", status, detail));
            done(checks, verdict)
        }
    }
}

fn cert_detail(endpoint: &Endpoint, fault: &CertFault, against: &str) -> String {
    let head = match fault {
        CertFault::NoCa(e) => {
            return format!("{against} cannot be used to judge a certificate: {e}");
        }
        CertFault::Untrusted => {
            format!("nothing in {against} vouches for the certificate {} presented", endpoint.host)
        }
        CertFault::WrongName { presented } if presented.is_empty() => {
            format!("the certificate validates against {against}, but not for {}", endpoint.host)
        }
        CertFault::WrongName { presented } => format!(
            "the certificate validates against {against}, but not for {}: it carries {}",
            endpoint.host,
            presented.join(", ")
        ),
        CertFault::Expired => {
            format!("the certificate {} presented has expired", endpoint.host)
        }
        CertFault::Other(e) => format!("the handshake with {} failed: {e}", endpoint.host),
    };
    // The same fact means opposite things per strategy, so it is said as a fact
    // and the consequence is left to whoever configured the strategy: a
    // certificate the operator supplied is theirs to vouch for, and one an ACME
    // strategy went and got is worthless if a client's own store says this.
    match endpoint.any_cert {
        true => format!(
            "{head} -- said, not judged: whether that matters is the deployment's TLS \
             decision, and this does not read it"
        ),
        false => {
            format!("{head}. A client validates against its own store, and would say the same")
        }
    }
}

fn answer_detail(endpoint: &Endpoint, answer: &Answer) -> (Status, Reachable, String) {
    let path = endpoint.asked.as_str();
    match (answer.status, &answer.sources) {
        (200, _) => (Status::Ok, Reachable::Serving, format!("{path} answered 200")),
        // A broker with several sources refuses an unprefixed /config and lists
        // them, because the operator has to put one in a URL. A served endpoint,
        // not a routing fault -- and told apart by the list in the body, because
        // a path nothing routed answers with nothing in it.
        (404, Some(names)) if !names.is_empty() => (
            Status::Ok,
            Reachable::Serving,
            format!(
                "{path} answered 404 listing {}: the broker is up and wants the source \
                 in the path, because {}. A client enrolls against {}/<source>",
                names.join(", "),
                match names.len() {
                    1 =>
                        "an unprefixed /config is answered only where one source makes it \
                          unambiguous",
                    _ => "several sources make an unprefixed /config ambiguous",
                },
                endpoint.asked.trim_end_matches("/config")
            ),
        ),
        // The same refusal from a deployment that has no source at all, which is
        // a realm mid-bootstrap rather than a broken route.
        (404, Some(_)) => (
            Status::Warn,
            Reachable::Serving,
            format!(
                "{path} answered 404 listing no source: the broker is up and serves \
                 nothing yet -- main.toml's `sources` is empty"
            ),
        ),
        (404, None) => (
            Status::Fail,
            Reachable::Broken,
            format!(
                "{path} answered 404 with no source list: either nothing routes that \
                 path to the broker -- look at the reverse proxy -- or the path names a \
                 source this deployment does not serve"
            ),
        ),
        // Broken now, and waiting may still fix it: the two verdicts are not the
        // same question. `doctor` exits on the status, a poll loop branches on
        // the verdict, and a proxy answering for a broker that has not started
        // is a failure to a one-shot diagnosis and the normal first seconds of a
        // stack coming up.
        (502 | 503, _) => (
            Status::Fail,
            Reachable::Settling,
            format!(
                "{path} answered {}: what terminates TLS is up and the broker is not \
                 answering behind it",
                answer.status
            ),
        ),
        (status, _) => (
            Status::Fail,
            Reachable::Broken,
            format!("{path} answered {status}, which is not an answer this path has"),
        ),
    }
}

/// Walk the connectivity chain: which config set answered, does the host
/// resolve, does the port accept, does the realm CA validate what the server
/// presents, and does the bind succeed.
///
/// Every link names the value it used. That is what makes a wrong `--config`,
/// a stale CA and a firewall distinguishable from each other without a packet
/// capture -- the three read alike in `ldap3`'s own errors.
///
/// The walk ends at the first break. There is nothing to learn from a bind
/// attempted through a port that refused a connection, and a row saying so
/// would sit under the one line that matters.
pub fn diagnose_reach(reach: &Reach) -> ReachReport {
    let mut checks = Vec::new();
    let done = |checks: Vec<Check>| ReachReport { target: reach.url.clone(), checks };

    // Link 1. That the set parsed is already established -- `Config::load`
    // would have ended the run otherwise -- so what is left to say is *which*
    // one, because every value the four links below use came out of it and a
    // `--config` naming another deployment moves all four at once. `kbmanage
    // config` prints what it resolved to; this names the file it read.
    checks.push(check(
        "config set",
        Status::Ok,
        format!("{} -- `kbmanage config` prints everything it resolved to", reach.source.display()),
    ));

    // Link 2. This machine's resolver, not the DC's: the name is the DC's own
    // and it is this host that has to know it.
    match &reach.resolve {
        None => return done(checks),
        Some(Ok(addrs)) => checks.push(check(
            "host resolves",
            Status::Ok,
            format!(
                "{} -> {}",
                reach.host,
                addrs.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            ),
        )),
        Some(Err(e)) => {
            checks.push(check(
                "host resolves",
                Status::Fail,
                format!(
                    "{} does not resolve from this host: {e}. The name comes from \
                     ldap_url above, and must resolve here -- not only on the DC",
                    reach.url
                ),
            ));
            return done(checks);
        }
    }

    // Link 3. Nothing about the directory is wrong yet if this fails: the name
    // resolved, so what is between the two hosts is what did not carry.
    match &reach.tcp {
        None => return done(checks),
        Some(Ok(addr)) => {
            checks.push(check("tcp connect", Status::Ok, format!("{addr} accepted a connection")));
        }
        Some(Err(e)) => {
            checks.push(check(
                "tcp connect",
                Status::Fail,
                format!(
                    "no address for {}:{} accepted a connection: {e}. The name resolves, \
                     so this is a firewall, a DC that does not listen, or a port \
                     published to loopback only",
                    reach.host, reach.port
                ),
            ));
            return done(checks);
        }
    }

    // Link 4. The one that fails in the field. Trust is CA-exclusive by design
    // -- `kerbridge_core::tls::client_config` refuses `None` and never falls
    // back to the OS store -- so the realm CA going stale under a re-provisioned
    // realm has no second chance to succeed, and must not read as "TLS error".
    let ca = reach.ca_file.display();
    match &reach.tls {
        None => return done(checks),
        Some(Ok(())) => checks.push(check(
            "realm CA",
            Status::Ok,
            format!("the certificate {} presented validates against {ca}", reach.host),
        )),
        Some(Err(fault)) => {
            checks.push(check(
                "realm CA",
                Status::Fail,
                match fault {
                    CertFault::Untrusted => format!(
                        "the CA at {ca} does not validate this server's certificate: a \
                         re-provisioned realm issues a new one. Copy the current CA out \
                         of the DC again -- nothing else is trusted here"
                    ),
                    CertFault::NoCa(e) => format!(
                        "{ca} cannot be used as a CA: {e}. There is no fallback -- this \
                         bind trusts that file or nothing"
                    ),
                    CertFault::WrongName { presented } if presented.is_empty() => format!(
                        "the certificate validates against {ca}, but not for {}. Its \
                         SAN carries the DC's FQDN, its short name and the loopback \
                         names -- ldap_url has to use one of them",
                        reach.host
                    ),
                    CertFault::WrongName { presented } => format!(
                        "the certificate validates against {ca}, but not for {}: it \
                         carries {}. ldap_url has to name one of those",
                        reach.host,
                        presented.join(", ")
                    ),
                    CertFault::Expired => format!(
                        "the certificate {} presented has expired. {ca} still vouches \
                         for it -- renew the realm's certificate, do not re-copy the CA",
                        reach.host
                    ),
                    CertFault::Other(e) => {
                        format!("the TLS handshake with {}:{} failed: {e}", reach.host, reach.port)
                    }
                },
            ));
            return done(checks);
        }
    }

    // Link 5. By here the host is right, the port is open and the realm is the
    // one this host is configured for, which leaves the credential.
    match &reach.bind {
        None => return done(checks),
        Some(Ok(())) => checks.push(check("simple bind", Status::Ok, reach.bind_dn.clone())),
        Some(Err(e)) => checks.push(check(
            "simple bind",
            Status::Fail,
            format!(
                "{} could not bind: {e}. The connection and the certificate are good, \
                 so the fault is bind_dn or the password file above",
                reach.bind_dn
            ),
        )),
    }

    done(checks)
}

/// Resolve a user by `sAMAccountName`, UPN, or external identity -- whichever
/// the operator happened to have.
pub fn resolve_user<'a>(snap: &'a Snapshot, subject: &str) -> Option<&'a CloudObject> {
    snap.cloud.iter().find(|o| {
        o.kind == Kind::User
            && (o.sam.eq_ignore_ascii_case(subject)
                || o.upn.as_deref().is_some_and(|u| u.eq_ignore_ascii_case(subject))
                || o.identity.as_deref() == Some(subject)
                || o.dn.eq_ignore_ascii_case(subject))
    })
}

/// A DN as an operator knows it, falling back to the DN itself: a delegate
/// group may nest a group from a part of the tree no read here covers.
fn name_of(snap: &Snapshot, dn: &str) -> String {
    snap.find_cloud(dn)
        .map(|o| o.sam.clone())
        .or_else(|| snap.find_resource(dn).map(|g| g.sam.clone()))
        .unwrap_or_else(|| dn.to_owned())
}

/// Walk one user's chain: does the identity resolve, is the account usable, is
/// it admitted to the realm, and does anything it is in reach a resource group.
pub fn diagnose_user(snap: &Snapshot, subject: &str) -> UserReport {
    let Some(user) = resolve_user(snap, subject) else {
        return UserReport {
            subject: subject.to_owned(),
            dn: None,
            sam: None,
            checks: vec![check(
                "object",
                Status::Fail,
                format!(
                    "no user under {} matches {subject:?} by sAMAccountName, \
                     userPrincipalName, DN or external identity",
                    snap.cloud_idp_ou
                ),
            )],
            next_step: None,
        };
    };

    let mut checks = vec![check("object", Status::Ok, user.dn.clone())];

    checks.push(match user.identity() {
        Some(Ok(id)) => check("external identity", Status::Ok, id.label().to_string()),
        Some(Err(e)) => check(
            "external identity",
            Status::Fail,
            format!(
                "msDS-ExternalDirectoryObjectId is present but unreadable: {e}. The \
                 broker matches tokens against it, so it admits nobody"
            ),
        ),
        None => check(
            "external identity",
            Status::Fail,
            "no msDS-ExternalDirectoryObjectId: nothing ties this object to a cloud \
             identity, so no token can resolve to it"
                .to_owned(),
        ),
    });

    checks.push(match user.state() {
        State::Live => check("state", Status::Ok, "live"),
        s => check(
            "state",
            Status::Fail,
            format!(
                "{s:?} for {} days -- gone from the cloud IdP, held for its SID. Sync \
                 re-enables it if the cloud IdP object comes back",
                user.held_days(snap.now).map_or("?".to_owned(), |d| d.to_string())
            ),
        ),
    });

    checks.push(match user.enabled() {
        Some(true) => {
            check("account enabled", Status::Ok, "userAccountControl has no ACCOUNTDISABLE")
        }
        Some(false) => check(
            "account enabled",
            Status::Fail,
            "disabled: the KDC refuses this account at AS and TGS alike",
        ),
        None => check("account enabled", Status::Warn, "no userAccountControl on the object"),
    });

    let closure = snap.closure_of(&user.dn);
    let inside = |dn: &String| dn_is_at_or_within(dn, &snap.cloud_idp_ou);

    // Role groups are resolved in this user's own IdP-specific OU. Another cloud IdP's
    // admission group is a different group with a different SID, and says nothing
    // about whether this user is admitted.
    let source_ou = snap.idp_ou_of(&user.dn);

    checks.push(match source_ou.as_deref().map(|ou| (ou, snap.admission_group_in(ou))) {
        None => check(
            "realm admission",
            Status::Fail,
            format!(
                "not in any IdP-specific OU under {}: no broker's search base holds it, \
                 so nothing can issue for it",
                snap.cloud_idp_ou
            ),
        ),
        Some((ou, None)) => check(
            "realm admission",
            Status::Fail,
            format!(
                "no group in {ou} carries the realm-admission marker, so that source's \
                 broker admits nobody"
            ),
        ),
        Some((_, Some(admission)))
            if closure.iter().any(|dn| dn.eq_ignore_ascii_case(&admission.dn)) =>
        {
            check("realm admission", Status::Ok, format!("in {}", admission.sam))
        }
        Some((_, Some(admission))) => check(
            "realm admission",
            Status::Fail,
            format!(
                "not in {}: the broker issues no ticket at all. Membership comes from \
                 the cloud IdP -- add them there and let sync run",
                admission.sam
            ),
        ),
    });

    // Reported only for a user who actually holds one. A deployment with device
    // grants off has none, and a line saying so on every user would be noise in
    // the one report an operator reads when something is broken.
    let devices = user.grants();
    if !devices.is_empty() {
        let named = devices
            .iter()
            .map(|(_, g)| format!("{} ({})", g.short_id(), g.label))
            .collect::<Vec<_>>()
            .join(", ");
        // A grant past its stamped deadline is dead whatever the broker's
        // `device_grant_days` is, because that setting can only bring the
        // deadline in. The live end is therefore not knowable here -- this tool
        // reads the directory and the setting lives on the broker -- but "past
        // the stamped date" is, and it is the half worth reporting.
        let lapsed: Vec<String> =
            devices.iter().filter(|(_, g)| g.end <= snap.now).map(|(_, g)| g.short_id()).collect();
        checks.push(match source_ou.as_deref().and_then(|ou| snap.grant_group_in(ou)) {
            Some(_) if !lapsed.is_empty() => check(
                "device grants",
                Status::Warn,
                format!(
                    "{named}, but {lapsed:?} passed its stamped deadline -- refused until \
                     someone signs in at that machine again"
                ),
            ),
            Some(group) if closure.iter().any(|dn| dn.eq_ignore_ascii_case(&group.dn)) => check(
                "device grants",
                Status::Ok,
                format!(
                    "{named}; in {} and inside its stamped deadline. The broker's \
                     DEVICE_GRANT_DAYS can bring that deadline in, and is not readable here",
                    group.sam
                ),
            ),
            Some(group) => check(
                "device grants",
                Status::Warn,
                format!(
                    "{named}, but not in {} -- each is refused at its next ticket \
                     exchange. Membership comes from the cloud IdP",
                    group.sam
                ),
            ),
            None => check(
                "device grants",
                Status::Warn,
                format!(
                    "{named}, but no group carries the device-grant marker, so all are \
                     refused"
                ),
            ),
        });
    }

    // Reported only for an account a delegate group names, like the device-grant
    // row above: a deployment that lends no grants out has none of these, and a
    // line saying so on every user is noise in the one report an operator reads
    // when something is broken.
    let delegates = snap.delegates_of(&user.dn);
    if !delegates.is_empty() {
        let chain = |g: &&ResourceGroup| {
            let who = if g.members.is_empty() {
                "nobody".to_owned()
            } else {
                g.members.iter().map(|dn| name_of(snap, dn)).collect::<Vec<_>>().join(", ")
            };
            format!("{} <- {who}", g.sam)
        };
        let chains = delegates.iter().map(chain).collect::<Vec<_>>().join("; ");
        let grant_group = source_ou.as_deref().and_then(|ou| snap.grant_group_in(ou));
        let covered =
            grant_group.is_some_and(|g| closure.iter().any(|dn| dn.eq_ignore_ascii_case(&g.dn)));
        checks.push(if delegates.len() > 1 {
            check(
                "device delegates",
                Status::Warn,
                format!(
                    "{chains} -- {} groups authorize devices as this account. `device \
                     delegate set` keeps one, so at least one was written by hand",
                    delegates.len()
                ),
            )
        } else if delegates[0].members.is_empty() {
            check(
                "device delegates",
                Status::Warn,
                format!(
                    "{chains} -- nobody is in it, so only this account can authorize a \
                     machine for itself"
                ),
            )
        } else if !covered {
            check(
                "device delegates",
                Status::Warn,
                format!(
                    "{chains}, but this account is not in {} -- no machine can be \
                     authorized for it, by a delegate or by itself",
                    grant_group.map_or("any device-grant group".to_owned(), |g| g.sam.clone())
                ),
            )
        } else {
            check(
                "device delegates",
                Status::Ok,
                format!(
                    "{chains} -- they may authorize a machine to obtain tickets as this \
                     account. Each must also be admitted to the realm in their own right"
                ),
            )
        });
    }

    let synced: Vec<&CloudObject> = closure
        .iter()
        .filter(|dn| inside(dn))
        .filter_map(|dn| snap.find_cloud(dn))
        .filter(|o| !o.is_admission_group())
        .collect();
    checks.push(if synced.is_empty() {
        check(
            "synced groups",
            Status::Warn,
            "in no synchronized group but the admission group: admitted to the realm, \
             but carrying nothing a resource group can authorize",
        )
    } else {
        check(
            "synced groups",
            Status::Ok,
            synced.iter().map(|o| o.sam.as_str()).collect::<Vec<_>>().join(", "),
        )
    });

    let nested: Vec<_> = closure.iter().filter(|dn| !inside(dn)).collect();
    if nested.is_empty() {
        checks.push(check(
            "resource groups",
            Status::Fail,
            format!(
                "none of this user's groups is nested outside {}, so nothing on a file \
                 server authorizes them. Run `kbmanage group member add <resource-group> \
                 <synced-group>`",
                snap.cloud_idp_ou
            ),
        ));
    } else {
        for dn in nested {
            let Some(rg) = snap.find_resource(dn) else {
                checks.push(check(
                    "resource group",
                    Status::Warn,
                    format!("{dn} -- outside {}, and not read back", snap.cloud_idp_ou),
                ));
                continue;
            };
            checks.push(if rg.is_domain_local() {
                check("resource group", Status::Ok, format!("{} (domain-local)", rg.sam))
            } else {
                check(
                    "resource group",
                    Status::Warn,
                    format!(
                        "{} has groupType {} -- not domain-local. A global group is \
                         evaluated only in its own domain, so it is missing from the PAC \
                         for a resource in another",
                        rg.sam,
                        rg.group_type.as_deref().unwrap_or("(unset)")
                    ),
                )
            });
        }
    }

    let domain = snap.netbios.as_deref().unwrap_or("DOMAIN");
    UserReport {
        subject: subject.to_owned(),
        dn: Some(user.dn.clone()),
        sam: Some(user.sam.clone()),
        checks,
        next_step: Some(format!(
            "On the file server, not here: `id '{domain}\\{}'` must print the uid and \
             every group above. If it does not, the break is winbind or the join, not the \
             directory. This tool cannot see share or filesystem ACLs.",
            user.sam
        )),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub status: Status,
    pub kind: &'static str,
    pub subject: String,
    pub detail: String,
}

fn finding(
    status: Status,
    kind: &'static str,
    subject: impl Into<String>,
    detail: impl Into<String>,
) -> Finding {
    Finding { status, kind, subject: subject.into(), detail: detail.into() }
}

/// Whole-directory sweep. Ordered worst-first by the caller; this returns them
/// grouped by check so a fixture comparison stays readable.
pub fn sweep(snap: &Snapshot) -> Vec<Finding> {
    let mut out = Vec::new();

    // A source that has never synced, said before the admission-group failure it
    // causes: an empty IdP-specific OU is the directory-visible half of "sync is
    // idle", and the readiness report's own version of this check is the one
    // thing it can say about sync that running is not.
    //
    // The cause is named rather than read. Which file holds a source's cloud
    // credential is inside `[provider_config]`, which only the adapter may
    // parse -- `kerbridge-idp` exists to keep that out of everything else, and
    // this tool links no adapter -- and in a Docker Compose deployment the path is one
    // inside the containers anyway, so a host-run binary could not stat it. Both
    // causes are therefore stated, because the symptom does not separate them
    // and either sends the operator to a file they can look at.
    for ou in &snap.idp_ous {
        if snap.cloud.iter().any(|o| dn_is_at_or_within(&o.dn, &ou.dn)) {
            continue;
        }
        out.push(finding(
            Status::Warn,
            "source",
            &ou.dn,
            "holds no object: nothing has ever synced into it. Either that source's \
             cloud credential is not written yet -- sync skips such a source and \
             mirrors the others -- or sync is not running. Its log says which",
        ));
    }

    // The admission group. Nothing else matters if this is wrong: with no admission
    // group nobody is admitted, and with two the admission policy is undefined.
    //
    // Counted per IdP-specific OU, not realm-wide. Each cloud IdP mirrors its own
    // admission group into its own OU and its own broker resolves the marker with
    // that OU as the search base, so N sources means N marked groups and that is
    // the healthy state. Realm-wide counting would report every correctly
    // configured second source as a duplicate -- and, worse, stay quiet about two
    // in one OU if a third source made the total look wrong for another reason.
    let mut by_source: BTreeMap<String, (String, Vec<&CloudObject>)> = BTreeMap::new();
    let mut orphaned: Vec<&CloudObject> = Vec::new();
    for obj in snap.cloud.iter().filter(|o| o.is_admission_group()) {
        match snap.idp_ou_of(&obj.dn) {
            Some(ou) => {
                let key = dn_components(&ou).map_or_else(|| ou.to_lowercase(), |c| c.join(","));
                by_source.entry(key).or_insert_with(|| (ou, Vec::new())).1.push(obj);
            }
            None => orphaned.push(obj),
        }
    }
    if by_source.is_empty() && orphaned.is_empty() {
        out.push(finding(
            Status::Fail,
            "admission group",
            "(none)",
            format!(
                "no group under {} carries the realm-admission marker: every broker \
                 refuses every request. Never recreate it by hand -- a new group has a \
                 new SID. Find why sync stopped",
                snap.cloud_idp_ou
            ),
        ));
    }
    for (ou, groups) in by_source.into_values() {
        match groups.len() {
            1 => out.push(finding(
                Status::Ok,
                "admission group",
                &groups[0].sam,
                format!("carries the realm-admission marker in {ou}"),
            )),
            n => out.push(finding(
                Status::Fail,
                "admission group",
                groups.iter().map(|g| g.sam.as_str()).collect::<Vec<_>>().join(", "),
                format!(
                    "{n} groups in {ou} carry the realm-admission marker: that source's \
                     broker refuses every login until one is unmarked"
                ),
            )),
        }
    }
    for obj in orphaned {
        out.push(finding(
            Status::Fail,
            "admission group",
            &obj.sam,
            format!(
                "carries the realm-admission marker but sits directly in {}, not in an \
                 IdP-specific OU under it, so no broker's search base holds it",
                snap.cloud_idp_ou
            ),
        ));
    }

    // Duplicate and malformed identities. The broker fails closed on both, so
    // they are silent until someone cannot log in.
    for (i, obj) in snap.cloud.iter().enumerate() {
        match obj.identity() {
            Some(Ok(_)) => {
                let dupes: Vec<&str> = snap
                    .cloud
                    .iter()
                    .enumerate()
                    .filter(|(j, o)| *j != i && o.identity == obj.identity)
                    .map(|(_, o)| o.sam.as_str())
                    .collect();
                if !dupes.is_empty() {
                    out.push(finding(
                        Status::Fail,
                        "ambiguous identity",
                        &obj.sam,
                        format!(
                            "shares its external identity with {}. The broker refuses \
                             an ambiguous match",
                            dupes.join(", ")
                        ),
                    ));
                }
            }
            Some(Err(e)) => out.push(finding(
                Status::Fail,
                "malformed identity",
                &obj.sam,
                format!("msDS-ExternalDirectoryObjectId does not decode: {e}"),
            )),
            None => out.push(finding(
                Status::Warn,
                "unmanaged object",
                &obj.sam,
                format!("{} carries no external identity. Sync leaves it alone", obj.dn),
            )),
        }
    }

    for obj in &snap.cloud {
        let state = obj.state();
        if state == State::Live {
            // A live group nested into nothing grants nothing, which reads as
            // working right up until someone opens a folder. A role group is the
            // exception: the marker is what makes it authorize, and both of them
            // gate a decision the broker makes rather than a resource.
            if obj.kind == Kind::Group && !obj.is_admission_group() && !obj.is_grant_group() {
                let nested = snap
                    .closure_of(&obj.dn)
                    .into_iter()
                    .any(|dn| !dn_is_at_or_within(&dn, &snap.cloud_idp_ou));
                if !nested {
                    out.push(finding(
                        Status::Info,
                        "authorizes nothing",
                        &obj.sam,
                        "synchronized, but nested into no group outside the IdP parent \
                         OU, so it gates no resource",
                    ));
                }
            }
            continue;
        }

        // Held objects are reported with their age and nothing else. There is
        // deliberately no window to be "past": the SID is what retention
        // protects, and it does not become cheap with age -- a returning
        // identity is no cheaper to break on day 400 than on day 4. Accumulating
        // tombstones is the intended steady state, not a backlog.
        if let Some(days) = obj.held_days(snap.now) {
            out.push(finding(
                Status::Info,
                "held",
                &obj.sam,
                format!(
                    "{state:?} for {days} days, keeping its SID. Nothing to do: if the \
                     cloud IdP object returns, sync revives this one and its files still \
                     resolve"
                ),
            ));
        }

        // Sync renames held objects out of the live namespace. One that is still
        // holding a live-form name means that migration has not reached it, and
        // the name it holds is a name a returning object cannot have.
        if !obj.sam.starts_with(RETIRED_PREFIX) {
            out.push(finding(
                Status::Warn,
                "name still held",
                &obj.sam,
                format!(
                    "{state:?} but still holding the live-form sAMAccountName {:?}. \
                     Sync frees the name at retirement; if this lasts a cycle, sync is \
                     not running or is refusing it",
                    obj.sam
                ),
            ));
        }

        if state == State::Quarantined {
            let nested: Vec<String> = snap
                .closure_of(&obj.dn)
                .into_iter()
                .filter(|dn| !dn_is_at_or_within(dn, &snap.cloud_idp_ou))
                .collect();
            if !nested.is_empty() {
                out.push(finding(
                    Status::Warn,
                    "dangling nesting",
                    &obj.sam,
                    format!(
                        "quarantined, but still nested into {}. Its members were \
                         cleared, so it grants nothing, yet it reads as live in \
                         `group list`",
                        nested.join(", ")
                    ),
                ));
            }
        }
    }

    for rg in &snap.resources {
        if !rg.is_domain_local() {
            out.push(finding(
                Status::Warn,
                "resource group scope",
                &rg.sam,
                format!(
                    "groupType {} -- a resource group has to be domain-local, so it is \
                     evaluated where the resource is",
                    rg.group_type.as_deref().unwrap_or("(unset)")
                ),
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests;
