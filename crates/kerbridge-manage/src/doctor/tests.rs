use kerbridge_core::ExternalIdentity;
use kerbridge_core::state::{
    GROUP_TYPE_DOMAIN_LOCAL_SECURITY, GROUP_TYPE_GLOBAL_SECURITY, ROLE_ADMISSION, ROLE_DELEGATES,
    ROLE_DEVICE_GRANT, ST_QUAR, ST_RETIRED, UAC_DISABLED, UAC_ENABLED,
};

use super::*;
use crate::model::{Answer, CertFault, IdpOu, Reach, ResourceGroup, TrustAnchor};

const CLOUD_IDP: &str = "OU=CloudIdP,DC=example,DC=site";
/// One cloud IdP's own OU, nested under the parent as a deployment nests it.
const IDP_OU: &str = "OU=Entra,OU=CloudIdP,DC=example,DC=site";
const RES: &str = "OU=Resources,DC=example,DC=site";
/// 2026-07-25T12:00:00Z, the stamp the markers below carry.
const STAMPED: u64 = 1_784_980_800;

/// Encoded through `kerbridge-core`, never written out by hand: this crate
/// must not be able to drift from the encoding it reads.
fn identity(subject: &str) -> String {
    ExternalIdentity::new(&kerbridge_core::Source::new("entra").unwrap(), subject).unwrap().encode()
}

fn user(sam: &str) -> CloudObject {
    CloudObject {
        dn: format!("CN={sam},{IDP_OU}"),
        sam: sam.to_owned(),
        kind: Kind::User,
        display_name: Some(sam.to_owned()),
        upn: Some(format!("{sam}@example.site")),
        identity: Some(identity(sam)),
        markers: vec![],
        uac: Some(UAC_ENABLED.parse().unwrap()),
        sid: Some(format!("S-1-5-21-1-2-3-{}", sam.len())),
        members: vec![],
        member_of: vec![],
    }
}

fn group(sam: &str, members: &[&str]) -> CloudObject {
    CloudObject {
        kind: Kind::Group,
        members: members.iter().map(|m| m.to_string()).collect(),
        ..user(sam)
    }
}

fn resource(sam: &str, members: &[&str]) -> ResourceGroup {
    ResourceGroup {
        dn: format!("CN={sam},{RES}"),
        sam: sam.to_owned(),
        group_type: Some(GROUP_TYPE_DOMAIN_LOCAL_SECURITY.to_owned()),
        sid: Some("S-1-5-21-1-2-3-99".to_owned()),
        members: members.iter().map(|m| m.to_string()).collect(),
        managed_by: None,
        markers: vec![],
    }
}

fn snapshot(cloud: Vec<CloudObject>, resources: Vec<ResourceGroup>) -> Snapshot {
    Snapshot {
        base_dn: "DC=example,DC=site".to_owned(),
        cloud_idp_ou: CLOUD_IDP.to_owned(),
        resource_ou: RES.to_owned(),
        netbios: Some("EXAMPLE".to_owned()),
        now: STAMPED,
        cloud,
        resources,
        idp_ous: vec![IdpOu { dn: IDP_OU.to_owned() }],
    }
}

/// alice -> admission group, alice -> proj-x -> share-rw (authorization).
/// Two independent chains, as the design intends.
fn healthy() -> Snapshot {
    let alice = format!("CN=alice,{IDP_OU}");
    let mut admission = group("onprem-realm-users", &[&alice]);
    admission.markers = vec![ROLE_ADMISSION.to_owned()];
    snapshot(
        vec![user("alice"), admission, group("proj-x", &[&alice])],
        vec![resource("share-rw", &[&format!("CN=proj-x,{IDP_OU}")])],
    )
}

/// A host that reaches its realm: every link answered, in the shipped shapes.
/// The tests below break exactly one of them.
fn reachable() -> Reach {
    Reach {
        source: std::path::PathBuf::from("/etc/kerbridge"),
        url: "ldaps://kerbridge.example.site:636".to_owned(),
        host: "kerbridge.example.site".to_owned(),
        port: 636,
        ca_file: std::path::PathBuf::from("/run/kerbridge/realm-ca.pem"),
        bind_dn: "CN=svc-kerbridge-manage,CN=Users,DC=example,DC=site".to_owned(),
        resolve: Some(Ok(vec!["10.0.0.5".parse().unwrap()])),
        tcp: Some(Ok("10.0.0.5:636".parse().unwrap())),
        tls: Some(Ok(())),
        bind: Some(Ok(())),
    }
}

fn labels(report: &ReachReport) -> Vec<&str> {
    report.checks.iter().map(|c| c.label).collect()
}

/// The last link the walk reached: the one an operator acts on.
fn broken(report: &ReachReport) -> &Check {
    let last = report.checks.last().expect("a walk always says which set answered");
    assert_eq!(last.status, Status::Fail, "{:#?}", report.checks);
    last
}

/// Every link names the value it used, which is what makes a wrong `--config`,
/// a stale CA and a firewall separable without a packet capture.
#[test]
fn a_reachable_directory_walks_all_five_links_naming_what_each_used() {
    let reach = reachable();
    let report = diagnose_reach(&reach);
    assert_eq!(report.worst(), Status::Ok, "{:#?}", report.checks);
    assert_eq!(
        labels(&report),
        ["config set", "host resolves", "tcp connect", "realm CA", "simple bind"]
    );
    assert_eq!(report.target, reach.url);
    let said = |needle: &str| {
        assert!(
            report.checks.iter().any(|c| c.detail.contains(needle)),
            "no link named {needle:?}: {:#?}",
            report.checks
        );
    };
    said("/etc/kerbridge");
    said("kerbridge.example.site");
    said("10.0.0.5:636");
    said("/run/kerbridge/realm-ca.pem");
    said("CN=svc-kerbridge-manage,CN=Users,DC=example,DC=site");
}

/// The non-obvious failure on a host that is not the DC. Trust is CA-exclusive
/// by design, so this must name the CA and the reason it went stale -- not read
/// as a TLS error with a certificate in it somewhere.
#[test]
fn a_stale_ca_is_reported_as_a_stale_ca_and_not_as_a_tls_error() {
    let reach = Reach { tls: Some(Err(CertFault::Untrusted)), bind: None, ..reachable() };
    let report = diagnose_reach(&reach);
    let f = broken(&report);
    assert_eq!(f.label, "realm CA");
    assert!(
        f.detail.contains(
            "the CA at /run/kerbridge/realm-ca.pem does not validate this server's certificate"
        ),
        "{}",
        f.detail
    );
    assert!(f.detail.contains("re-provisioned realm issues a new one"), "{}", f.detail);
    assert!(!f.detail.contains("TLS"), "{}", f.detail);
    // The walk stops here: a bind row under this would sit on top of the one
    // line the operator has to read.
    assert!(!labels(&report).contains(&"simple bind"), "{:#?}", report.checks);
}

/// The other half of the same link, and the one that must *not* borrow the
/// stale-CA wording: the CA is fine and the URL names something the SAN does
/// not, which sends the operator to a different file entirely.
#[test]
fn a_name_outside_the_certificate_is_not_reported_as_a_stale_ca() {
    let presented = vec!["dc1.example.site".to_owned(), "localhost".to_owned()];
    let reach =
        Reach { tls: Some(Err(CertFault::WrongName { presented })), bind: None, ..reachable() };
    let f = broken(&diagnose_reach(&reach)).detail.clone();
    assert!(f.contains("dc1.example.site, localhost"), "{f}");
    assert!(f.contains("ldap_url"), "{f}");
    assert!(!f.contains("re-provisioned"), "{f}");
}

/// A CA file that cannot be loaded at all is a third distinct answer, and the
/// absence of a fallback is the part an operator does not expect: no system
/// trust store stands behind it.
#[test]
fn an_unusable_ca_file_says_there_is_no_fallback() {
    let reach = Reach {
        tls: Some(Err(CertFault::NoCa("no such file or directory".to_owned()))),
        bind: None,
        ..reachable()
    };
    let f = broken(&diagnose_reach(&reach)).detail.clone();
    assert!(f.contains("/run/kerbridge/realm-ca.pem cannot be used as a CA"), "{f}");
    assert!(f.contains("no such file or directory"), "{f}");
    assert!(f.contains("no fallback"), "{f}");
}

/// The link that separates a wrong `ldap_url` from a firewall: nothing was
/// looked up, so nothing below it ran.
#[test]
fn an_unresolvable_host_ends_the_walk_at_the_resolver() {
    let reach = Reach {
        resolve: Some(Err("Name or service not known".to_owned())),
        tcp: None,
        tls: None,
        bind: None,
        ..reachable()
    };
    let report = diagnose_reach(&reach);
    assert_eq!(labels(&report), ["config set", "host resolves"]);
    let f = broken(&report);
    assert!(f.detail.contains("ldaps://kerbridge.example.site:636"), "{}", f.detail);
    assert!(f.detail.contains("Name or service not known"), "{}", f.detail);
}

/// A refused port is not a directory fault, and saying so is what stops an
/// operator editing the realm to fix a firewall.
#[test]
fn a_refused_port_is_reported_as_reach_and_not_as_configuration() {
    let reach = Reach {
        tcp: Some(Err("10.0.0.5:636: Connection refused".to_owned())),
        tls: None,
        bind: None,
        ..reachable()
    };
    let report = diagnose_reach(&reach);
    assert_eq!(labels(&report), ["config set", "host resolves", "tcp connect"]);
    let f = broken(&report);
    assert!(f.detail.contains("kerbridge.example.site:636"), "{}", f.detail);
    assert!(f.detail.contains("firewall"), "{}", f.detail);
}

/// The last link: everything under it is known good, so the credential is all
/// that is left -- and the config set that named it is what to open.
#[test]
fn a_refused_bind_names_the_account_and_sends_the_operator_to_the_password_file() {
    let reach = Reach { bind: Some(Err("rc=49: invalid credentials".to_owned())), ..reachable() };
    let report = diagnose_reach(&reach);
    assert_eq!(labels(&report).len(), 5);
    let f = broken(&report);
    assert!(f.detail.contains("CN=svc-kerbridge-manage"), "{}", f.detail);
    assert!(f.detail.contains("password file"), "{}", f.detail);
}

/// A probe that never ran ends the walk after link 1 rather than reporting the
/// four it did not attempt.
#[test]
fn a_walk_that_probed_nothing_still_says_which_config_set_answered() {
    let reach = Reach { resolve: None, tcp: None, tls: None, bind: None, ..reachable() };
    let report = diagnose_reach(&reach);
    assert_eq!(labels(&report), ["config set"]);
    assert_eq!(report.worst(), Status::Ok);
    assert!(report.checks[0].detail.contains("/etc/kerbridge"), "{:#?}", report.checks);
}

fn status_of(report: &UserReport, label: &str) -> Status {
    report.checks.iter().find(|c| c.label == label).unwrap_or_else(|| panic!("{label}")).status
}

fn kinds(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.kind).collect()
}

#[test]
fn a_healthy_chain_reports_every_link_intact() {
    let report = diagnose_user(&healthy(), "alice");
    assert_eq!(report.worst(), Status::Ok, "{:#?}", report.checks);
    assert!(report.next_step.as_ref().unwrap().contains("id 'EXAMPLE\\alice'"));
    // No device grants in the deployment, so no line about them: a report
    // read during an outage should not carry rows that are always the same.
    assert!(report.checks.iter().all(|c| c.label != "device grants"));
}

/// The device-grant group is checked separately from admission because it
/// answers a different question. A user can be perfectly admitted and still
/// have every one of their machines refused, and that combination is exactly
/// the one that looks like a broker fault from the outside.
#[test]
fn a_grant_holder_is_told_whether_the_grant_group_still_covers_them() {
    let alice = format!("CN=alice,{IDP_OU}");
    let grant = kerbridge_core::grant::DeviceGrant {
        label: "BUILD01\\svc".into(),
        alg: kerbridge_core::grant::ALG_ES256,
        thumbprint: "GsNH2NUyRXY46_dTvTB1SIf7hkZ8LYlOKPT-ODdVUgo".into(),
        start: STAMPED,
        end: STAMPED + 30 * 86_400,
        seen: None,
    };
    let held = [alice.as_str()];
    let with_grants = |member: bool| {
        let mut snap = healthy();
        snap.cloud[0].markers = vec![grant.encode()];
        let mut grants = group("onprem-device-grants", if member { &held[..] } else { &[][..] });
        grants.markers = vec![ROLE_DEVICE_GRANT.to_owned()];
        snap.cloud.push(grants);
        snap
    };

    let report = diagnose_user(&with_grants(true), "alice");
    assert_eq!(status_of(&report, "device grants"), Status::Ok, "{:#?}", report.checks);
    assert_eq!(report.worst(), Status::Ok);

    let report = diagnose_user(&with_grants(false), "alice");
    assert_eq!(status_of(&report, "device grants"), Status::Warn);
    // A warning and not a failure: they can still sign in through the
    // browser, so nothing about their access to the realm is broken.
    assert_eq!(report.worst(), Status::Warn, "{:#?}", report.checks);

    // Grants held in a deployment where no group carries the marker at all.
    let mut orphaned = healthy();
    orphaned.cloud[0].markers = vec![grant.encode()];
    let report = diagnose_user(&orphaned, "alice");
    assert_eq!(status_of(&report, "device grants"), Status::Warn);

    // Past the stamped deadline, group membership stops being the answer:
    // the grant is refused whatever `device_grant_days` says, because
    // that setting can only bring the deadline in. It is the one thing
    // about the live deadline this tool can decide without reading the
    // broker's configuration, which it deliberately does not have.
    let mut lapsed = with_grants(true);
    lapsed.cloud[0].markers =
        vec![kerbridge_core::grant::DeviceGrant { end: STAMPED, ..grant.clone() }.encode()];
    let report = diagnose_user(&lapsed, "alice");
    assert_eq!(status_of(&report, "device grants"), Status::Warn, "{:#?}", report.checks);
}

/// The chain a delegation makes is three links long and lives in two
/// OUs, so it is exactly the thing nobody reconstructs by hand: the
/// account, the group that may authorize a machine as it, and who is in that
/// group.
#[test]
fn a_delegated_account_shows_who_may_authorize_a_machine_for_it() {
    let alice = format!("CN=alice,{IDP_OU}");
    let held = [alice.as_str()];
    let with_delegates = |members: &[&str], in_grant_group: bool| {
        let mut snap = healthy();
        let mut grants =
            group("onprem-device-grants", if in_grant_group { &held[..] } else { &[][..] });
        grants.markers = vec![ROLE_DEVICE_GRANT.to_owned()];
        snap.cloud.push(grants);
        let mut delegates = resource("nas-build-delegates", members);
        delegates.managed_by = Some(alice.clone());
        delegates.markers = vec![ROLE_DELEGATES.to_owned()];
        snap.resources.push(delegates);
        snap
    };

    let proj_x = format!("CN=proj-x,{IDP_OU}");
    let snap = with_delegates(&[&proj_x], true);
    let report = diagnose_user(&snap, "alice");
    let chain = report.checks.iter().find(|c| c.label == "device delegates").unwrap();
    assert_eq!(chain.status, Status::Ok, "{}", chain.detail);
    // Named as an operator knows them, not as DNs.
    assert!(chain.detail.contains("nas-build-delegates <- proj-x"), "{}", chain.detail);

    // A delegate group nobody is in delegates nothing, and reads as set up.
    let report = diagnose_user(&with_delegates(&[], true), "alice");
    assert_eq!(status_of(&report, "device delegates"), Status::Warn);

    // The delegation is inert while the target is outside the device-grant
    // group: the broker resolves the *target* with that check, so no machine
    // can be authorized for them by anyone, delegate or not.
    let report = diagnose_user(&with_delegates(&[&proj_x], false), "alice");
    assert_eq!(status_of(&report, "device delegates"), Status::Warn);

    // `managedBy` without the marker is an admin's ownership record. It is not
    // a delegation, and a report that called it one would be inventing a right.
    let mut owned = with_delegates(&[&proj_x], true);
    owned.resources.last_mut().unwrap().markers.clear();
    let report = diagnose_user(&owned, "alice");
    assert!(report.checks.iter().all(|c| c.label != "device delegates"), "{:#?}", report.checks);
    assert_eq!(report.worst(), Status::Ok);
}

/// The handle is a function of the key, so it selects one device even when
/// two machines claim the same label -- which is exactly what a hostile one
/// would do.
#[test]
fn a_device_is_found_by_handle_and_never_by_label() {
    use kerbridge_core::grant::{ALG_ES256, DeviceGrant};
    let grant = |thumbprint: &str| DeviceGrant {
        label: "BUILD01\\svc".into(),
        alg: ALG_ES256,
        thumbprint: thumbprint.into(),
        start: STAMPED,
        end: STAMPED + 30 * 86_400,
        seen: None,
    };
    let a = grant("GsNH2NUyRXY46_dTvTB1SIf7hkZ8LYlOKPT-ODdVUgo");
    let b = grant("ZZNH2NUyRXY46_dTvTB1SIf7hkZ8LYlOKPT-ODdVUgo");
    assert_ne!(a.short_id(), b.short_id(), "same label, different key");

    let mut snap = healthy();
    snap.cloud[0].markers = vec![a.encode(), b.encode(), ROLE_ADMISSION.to_owned()];
    let (obj, raw, found) = snap.find_device(&b.short_id()).expect("found by handle");
    assert_eq!(obj.sam, "alice");
    assert_eq!(found.thumbprint, b.thumbprint);
    // The exact stored bytes, because that is what a revocation deletes.
    assert_eq!(raw, b.encode());
    assert!(snap.find_device("00000000").is_none());
    // The unrelated role marker is not a grant.
    assert_eq!(snap.cloud[0].grants().len(), 2);
}

#[test]
fn a_user_is_found_by_sam_upn_dn_or_identity() {
    let snap = healthy();
    for subject in [
        "alice",
        "ALICE",
        "alice@example.site",
        "CN=alice,OU=Entra,OU=CloudIdP,DC=example,DC=site",
        &identity("alice"),
    ] {
        assert!(resolve_user(&snap, subject).is_some(), "{subject:?}");
    }
    assert!(resolve_user(&snap, "nobody").is_none());
    // A group is not a user, however it is spelled.
    assert!(resolve_user(&snap, "proj-x").is_none());
}

#[test]
fn an_unknown_subject_fails_on_the_first_link_and_offers_no_next_step() {
    let report = diagnose_user(&healthy(), "mallory");
    assert_eq!(report.checks.len(), 1);
    assert_eq!(report.worst(), Status::Fail);
    assert!(report.next_step.is_none());
}

#[test]
fn a_user_outside_the_admission_group_gets_no_ticket_at_all() {
    let mut snap = healthy();
    snap.cloud.iter_mut().find(|o| o.is_admission_group()).unwrap().members.clear();
    let report = diagnose_user(&snap, "alice");
    assert_eq!(status_of(&report, "realm admission"), Status::Fail);
    // The authorization chain is still intact -- they are separate failures.
    assert_eq!(status_of(&report, "resource group"), Status::Ok);
}

#[test]
fn an_admission_group_with_no_marker_is_a_frozen_realm_not_a_missing_user() {
    let mut snap = healthy();
    snap.cloud.iter_mut().find(|o| o.is_admission_group()).unwrap().markers.clear();
    assert_eq!(status_of(&diagnose_user(&snap, "alice"), "realm admission"), Status::Fail);
    assert!(kinds(&sweep(&snap)).contains(&"admission group"));
    assert_eq!(
        sweep(&snap).iter().find(|f| f.kind == "admission group").unwrap().status,
        Status::Fail
    );
}

#[test]
fn a_synced_group_nested_into_nothing_authorizes_nobody() {
    let mut snap = healthy();
    snap.resources.clear();
    let report = diagnose_user(&snap, "alice");
    assert_eq!(status_of(&report, "resource groups"), Status::Fail);
    // Admission is unaffected: they reach the server and are refused the folder.
    assert_eq!(status_of(&report, "realm admission"), Status::Ok);
    assert!(kinds(&sweep(&snap)).contains(&"authorizes nothing"));
}

/// A device-grant group gates the exchange and not a share, so it is nested into
/// nothing by design. Flagging it sends an operator to look for a fault that the
/// marker says is not there.
#[test]
fn a_device_grant_group_is_not_told_it_authorizes_nothing() {
    let mut snap = healthy();
    let mut grant = group("onprem-device-grants", &[&format!("CN=alice,{IDP_OU}")]);
    grant.markers = vec![ROLE_DEVICE_GRANT.to_owned()];
    snap.cloud.push(grant);
    let flagged: Vec<_> = sweep(&snap)
        .into_iter()
        .filter(|f| f.kind == "authorizes nothing")
        .map(|f| f.subject)
        .collect();
    assert!(!flagged.contains(&"onprem-device-grants".to_owned()), "{flagged:?}");
}

#[test]
fn a_global_resource_group_is_flagged_without_being_called_broken() {
    let mut snap = healthy();
    snap.resources[0].group_type = Some(GROUP_TYPE_GLOBAL_SECURITY.to_owned());
    let report = diagnose_user(&snap, "alice");
    assert_eq!(status_of(&report, "resource group"), Status::Warn);
    assert_eq!(report.worst(), Status::Warn);
    let sweep = sweep(&snap);
    assert!(kinds(&sweep).contains(&"resource group scope"));
}

#[test]
fn a_malformed_identity_is_reported_as_malformed_not_as_missing() {
    let mut snap = healthy();
    snap.cloud[0].identity = Some("kb1|entra".to_owned());
    assert_eq!(status_of(&diagnose_user(&snap, "alice"), "external identity"), Status::Fail);
    assert!(kinds(&sweep(&snap)).contains(&"malformed identity"));

    snap.cloud[0].identity = None;
    assert_eq!(status_of(&diagnose_user(&snap, "alice"), "external identity"), Status::Fail);
    assert!(kinds(&sweep(&snap)).contains(&"unmanaged object"));
}

#[test]
fn two_objects_carrying_one_identity_are_both_named() {
    let mut snap = healthy();
    let mut twin = user("alice2");
    twin.identity = Some(identity("alice"));
    snap.cloud.push(twin);
    let findings = sweep(&snap);
    let dupes = findings.iter().filter(|f| f.kind == "ambiguous identity").count();
    assert_eq!(dupes, 2, "both sides of the collision are reported");
}

#[test]
fn a_disabled_account_fails_separately_from_its_memberships() {
    let mut snap = healthy();
    snap.cloud[0].uac = Some(UAC_DISABLED.parse().unwrap());
    let report = diagnose_user(&snap, "alice");
    assert_eq!(status_of(&report, "account enabled"), Status::Fail);
    assert_eq!(status_of(&report, "realm admission"), Status::Ok);
}

#[test]
fn a_retired_user_reads_as_retired_with_the_days_held() {
    let mut snap = healthy();
    snap.cloud[0].markers = vec![format!("{ST_RETIRED}2026-07-25T12:00:00Z")];
    snap.cloud[0].sam = "_retired-alice".to_owned();
    snap.now = STAMPED + 40 * 86_400;
    let report = diagnose_user(&snap, "_retired-alice");
    let state = report.checks.iter().find(|c| c.label == "state").unwrap();
    assert_eq!(state.status, Status::Fail);
    assert!(state.detail.contains("40 days"), "{}", state.detail);
}

/// A held object is reported at any age, at `Info`, with no threshold
/// anywhere. There deliberately is no window: one would imply that crossing
/// it makes deletion safe, and it never does.
#[test]
fn a_held_object_is_reported_by_age_and_never_as_a_backlog() {
    let mut snap = healthy();
    snap.cloud[0].markers = vec![format!("{ST_RETIRED}2026-07-25T12:00:00Z")];
    snap.cloud[0].sam = "_retired-alice".to_owned();

    for days in [0u64, 1, 29, 30, 400] {
        snap.now = STAMPED + days * 86_400;
        let findings = sweep(&snap);
        let held = findings
            .iter()
            .find(|f| f.kind == "held")
            .unwrap_or_else(|| panic!("no held finding at {days} days"));
        assert_eq!(held.status, Status::Info, "age is never a Warn at {days} days");
        assert!(held.detail.contains(&format!("{days} days")), "{}", held.detail);
        assert!(
            !held.detail.contains("window") && !held.detail.contains("past"),
            "no window may be implied: {}",
            held.detail
        );
    }
}

#[test]
fn a_held_object_still_holding_a_live_form_name_means_sync_has_not_reached_it() {
    let mut snap = healthy();
    snap.cloud[0].markers = vec![format!("{ST_RETIRED}2026-07-25T12:00:00Z")];
    // sam left as "alice" -- the pre-rename state.
    assert!(kinds(&sweep(&snap)).contains(&"name still held"));

    snap.cloud[0].sam = "_retired-alice".to_owned();
    assert!(!kinds(&sweep(&snap)).contains(&"name still held"));
}

#[test]
fn a_quarantined_group_still_nested_grants_nothing_but_reads_as_live() {
    let mut snap = healthy();
    let projx = snap.cloud.iter_mut().find(|o| o.sam == "proj-x").unwrap();
    projx.markers = vec![format!("{ST_QUAR}2026-07-25T12:00:00Z")];
    projx.sam = "_retired-proj-x".to_owned();
    projx.members.clear();
    let findings = sweep(&snap);
    let dangling = findings.iter().find(|f| f.kind == "dangling nesting").unwrap();
    assert!(dangling.detail.contains("share-rw"), "{}", dangling.detail);
    // And the user it used to authorize now reaches no resource group.
    assert_eq!(status_of(&diagnose_user(&snap, "alice"), "resource groups"), Status::Fail);
}

#[test]
fn a_healthy_directory_sweeps_to_nothing_but_the_admission_group() {
    let findings = sweep(&healthy());
    assert_eq!(kinds(&findings), vec!["admission group"]);
    assert!(findings.iter().all(|f| f.status == Status::Ok));
}

#[test]
fn nesting_is_followed_through_depth_and_survives_a_cycle() {
    let alice = format!("CN=alice,{IDP_OU}");
    let inner = format!("CN=inner,{IDP_OU}");
    let outer = format!("CN=outer,{IDP_OU}");
    let mut admission = group("onprem-realm-users", &[&alice]);
    admission.markers = vec![ROLE_ADMISSION.to_owned()];
    // inner contains alice and outer; outer contains inner -- a cycle the
    // directory permits and the sync fixtures actually contain.
    let snap = snapshot(
        vec![
            user("alice"),
            admission,
            group("inner", &[&alice, &outer]),
            group("outer", &[&inner]),
        ],
        vec![resource("share-rw", &[&outer])],
    );
    let report = diagnose_user(&snap, "alice");
    assert_eq!(report.worst(), Status::Ok, "{:#?}", report.checks);
}

/// A second cloud IdP in the same realm: two marked groups, one per OU, is the
/// healthy state -- the reading a realm-wide count got wrong.
#[test]
fn two_sources_each_with_their_own_admission_group_are_both_healthy() {
    const GOOGLE: &str = "OU=Google,OU=CloudIdP,DC=example,DC=site";
    let mut snap = healthy();
    let bob = format!("CN=bob,{GOOGLE}");
    let mut other = group("workspace-realm-users", &[&bob]);
    other.dn = format!("CN=workspace-realm-users,{GOOGLE}");
    other.markers = vec![ROLE_ADMISSION.to_owned()];
    let mut bob_obj = user("bob");
    bob_obj.dn = bob;
    snap.cloud.push(bob_obj);
    snap.cloud.push(other);

    let found = sweep(&snap);
    let admission: Vec<&Finding> = found.iter().filter(|f| f.kind == "admission group").collect();
    assert_eq!(admission.len(), 2, "one per IdP-specific OU: {admission:#?}");
    assert!(admission.iter().all(|f| f.status == Status::Ok), "{admission:#?}");
}

/// Two in *one* OU is still undefined, and now says whose logins it freezes.
#[test]
fn two_admission_groups_in_one_source_ou_freeze_that_source() {
    let mut snap = healthy();
    let mut second = group("second-admission", &[]);
    second.markers = vec![ROLE_ADMISSION.to_owned()];
    snap.cloud.push(second);
    let found = sweep(&snap);
    let f = found.iter().find(|f| f.kind == "admission group").unwrap();
    assert_eq!(f.status, Status::Fail, "{f:#?}");
    assert!(f.detail.contains(IDP_OU), "names the OU it froze: {}", f.detail);
}

/// A marked group directly in the parent OU is in no broker's search base, which
/// looks fine to any check that only counts markers.
#[test]
fn an_admission_group_outside_every_source_ou_is_reachable_by_nobody() {
    let mut snap = healthy();
    let marked = snap.cloud.iter_mut().find(|o| o.is_admission_group()).unwrap();
    marked.dn = format!("CN={},{CLOUD_IDP}", marked.sam);
    let found = sweep(&snap);
    let f = found.iter().find(|f| f.kind == "admission group").unwrap();
    assert_eq!(f.status, Status::Fail, "{f:#?}");
    assert!(f.detail.contains("IdP-specific OU"), "{}", f.detail);
}
/// The readiness report's "sync is idle" as the directory shows it. A second
/// source whose OU holds nothing has never synced, and the sweep says so per
/// source -- the realm-wide admission-group failure it also causes names
/// neither which source nor what to look at.
#[test]
fn a_source_that_has_never_synced_is_named_with_both_of_its_causes() {
    let mut snap = healthy();
    let empty = "OU=Google,OU=CloudIdP,DC=example,DC=site";
    snap.idp_ous.push(IdpOu { dn: empty.to_owned() });
    let findings = sweep(&snap);
    let idle: Vec<&Finding> = findings.iter().filter(|f| f.kind == "source").collect();
    assert_eq!(idle.len(), 1, "only the empty one: {findings:#?}");
    assert_eq!(idle[0].subject, empty);
    assert_eq!(idle[0].status, Status::Warn);
    assert!(idle[0].detail.contains("credential"), "{}", idle[0].detail);
    assert!(idle[0].detail.contains("sync is not running"), "{}", idle[0].detail);
}

// ---------------------------------------------------------------------------
// The endpoint link. Nothing here listens: the walk is data, so every verdict a
// readiness loop branches on is pinned without a stack to bring up.
// ---------------------------------------------------------------------------

/// A public path that answers, for one source.
fn serving() -> Endpoint {
    Endpoint {
        asked: "https://kerbridge.example.site:443/config".to_owned(),
        host: "kerbridge.example.site".to_owned(),
        port: 443,
        tls: true,
        via: Some("127.0.0.1:443".parse().unwrap()),
        anchor: TrustAnchor::Public,
        any_cert: false,
        resolve: None,
        tcp: Some(Ok("127.0.0.1:443".parse().unwrap())),
        cert: Some(Ok(())),
        session: Some(Ok(())),
        answer: Some(Ok(Answer { status: 200, sources: None })),
    }
}

fn endpoint_labels(report: &EndpointReport) -> Vec<&str> {
    report.checks.iter().map(|c| c.label).collect()
}

#[test]
fn a_served_path_is_the_whole_of_a_pass() {
    let report = diagnose_endpoint(&serving());
    assert_eq!(report.verdict, Reachable::Serving);
    assert_eq!(endpoint_labels(&report), ["address", "connect", "certificate", "GET /config"]);
    assert!(report.summary().contains("answered 200"), "{}", report.summary());
}

/// The distinction this link exists for. Both are 404, and a criterion that
/// does not read the body calls one of them wrong -- which is how the readiness
/// copy in ci-stack.sh could have passed a broker nothing routed to.
#[test]
fn the_two_404s_are_opposite_verdicts() {
    let listed = Endpoint {
        answer: Some(Ok(Answer {
            status: 404,
            sources: Some(vec!["entra".to_owned(), "google".to_owned()]),
        })),
        ..serving()
    };
    let report = diagnose_endpoint(&listed);
    assert_eq!(report.verdict, Reachable::Serving);
    assert!(report.summary().contains("entra, google"), "{}", report.summary());

    let unrouted =
        Endpoint { answer: Some(Ok(Answer { status: 404, sources: None })), ..serving() };
    let report = diagnose_endpoint(&unrouted);
    assert_eq!(report.verdict, Reachable::Broken);
    assert!(report.summary().contains("no source list"), "{}", report.summary());
}

/// A deployment mid-bootstrap: the broker is up and `main.toml` lists no
/// source, which the same refusal reports with an empty list. Working, and not
/// what anyone wants left alone -- so it passes, loudly.
#[test]
fn a_broker_serving_no_source_yet_passes_with_a_warning() {
    let none =
        Endpoint { answer: Some(Ok(Answer { status: 404, sources: Some(vec![]) })), ..serving() };
    let report = diagnose_endpoint(&none);
    assert_eq!(report.verdict, Reachable::Serving);
    assert_eq!(report.checks.last().unwrap().status, Status::Warn);
}

/// The three a poll loop must not give up on, against the two it must.
#[test]
fn what_waiting_can_and_cannot_fix() {
    let refused = Endpoint {
        tcp: Some(Err("127.0.0.1:443: Connection refused".to_owned())),
        cert: None,
        session: None,
        answer: None,
        ..serving()
    };
    assert_eq!(diagnose_endpoint(&refused).verdict, Reachable::Settling);

    let proxy_alone =
        Endpoint { answer: Some(Ok(Answer { status: 502, sources: None })), ..serving() };
    assert_eq!(diagnose_endpoint(&proxy_alone).verdict, Reachable::Settling);

    // No certificate presented at all. Under an ACME strategy this is an
    // issuance still in flight and under a supplied one a file that did not
    // load, so the verdict is its own rather than either answer.
    let no_tls = Endpoint {
        cert: None,
        session: Some(Err("received fatal alert: UnrecognisedName".to_owned())),
        answer: None,
        ..serving()
    };
    assert_eq!(diagnose_endpoint(&no_tls).verdict, Reachable::NoSession);

    let teapot = Endpoint { answer: Some(Ok(Answer { status: 418, sources: None })), ..serving() };
    assert_eq!(diagnose_endpoint(&teapot).verdict, Reachable::Broken);

    // The same field, and not the same failure: a handshake that failed with an
    // accepted certificate beside it failed over something else, and reporting
    // it as "no certificate" would send the operator to the wrong file.
    let after_cert = Endpoint {
        session: Some(Err("peer closed the connection".to_owned())),
        answer: None,
        ..serving()
    };
    let report = diagnose_endpoint(&after_cert);
    assert_eq!(report.verdict, Reachable::Broken);
    assert!(report.summary().contains("still failed"), "{}", report.summary());
}

/// Judged, the certificate ends the walk. Reported, it is context the walk
/// carries past -- recorded in the chain, and out of the one line a readiness
/// report prints, which must not warn about the thing that deployment decided.
#[test]
fn a_certificate_is_judged_or_reported_and_the_line_says_which() {
    let untrusted = Endpoint { cert: Some(Err(CertFault::Untrusted)), ..serving() };
    let judged = diagnose_endpoint(&untrusted);
    assert_eq!(judged.verdict, Reachable::Broken);
    assert_eq!(endpoint_labels(&judged), ["address", "connect", "certificate"]);
    assert!(judged.summary().contains("vouches"), "{}", judged.summary());

    let reported = diagnose_endpoint(&Endpoint { any_cert: true, ..untrusted });
    assert_eq!(reported.verdict, Reachable::Serving);
    assert_eq!(reported.checks[2].status, Status::Info);
    assert!(reported.checks[2].detail.contains("vouches"), "{:#?}", reported.checks);
    assert_eq!(reported.summary(), reported.checks[3].detail);
}

/// A name that carries no certificate question at all: the broker's own listen
/// address, which is what a Debian deployment has before anything fronts it.
#[test]
fn a_plain_http_base_has_no_certificate_link() {
    let plain = Endpoint {
        asked: "http://127.0.0.1:8080/config".to_owned(),
        host: "127.0.0.1".to_owned(),
        port: 8080,
        tls: false,
        cert: None,
        session: None,
        ..serving()
    };
    let report = diagnose_endpoint(&plain);
    assert_eq!(report.verdict, Reachable::Serving);
    assert_eq!(endpoint_labels(&report), ["address", "connect", "GET /config"]);
}
