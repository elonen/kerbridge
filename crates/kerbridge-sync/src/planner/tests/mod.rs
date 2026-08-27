//! Planner unit tests. The builders below are the shared fixture vocabulary --
//! every submodule reaches them through `use super::*`.
//!
//! Every *user* object id below is a canonical GUID, because the encoder these
//! tests plan with is the adapter's own. Group ids never reach it.

mod collisions;
mod corpus;
mod grants;
mod guards;
mod names;

use super::*;
use kerbridge_core::ExternalIdentity;

const ADMISSION: &str = "8689e2c1-3268-4744-a647-30d05e5c7b90";
const BASE: &str = "OU=Entra,DC=example,DC=site";

/// The encoder every test plans with: the Entra adapter's, reached the way the
/// service reaches it, so a fixture's expected `identity` is the same string the
/// broker would search for.
const ENCODE: &dyn Fn(&str) -> Result<String, kerbridge_core::IdentityError> = &|subject| {
    kerbridge_idp::encode_identity(
        kerbridge_idp::Provider::Entra,
        &kerbridge_core::Source::new("entra").unwrap(),
        subject,
    )
    .map(|id| id.encode())
};

fn ctx() -> PlanCtx<'static> {
    PlanCtx {
        idp_ou: BASE,
        upn_suffix: "example.site",
        group_suffix: "",
        now: "2026-07-21T12:00:00Z",
        sam_source: SamSource::DisplayName,
        automatic_sam_renames: true,
        identity: ENCODE,
    }
}

/// Desired state carrying the admission group plus whatever the test adds, so
/// no test pays for admission-group invariants it is not about.
fn desired(users: Vec<(&str, DesiredUser)>, groups: Vec<(&str, DesiredGroup)>) -> Desired {
    let mut groups: BTreeMap<String, DesiredGroup> =
        groups.into_iter().map(|(oid, g)| (oid.to_owned(), g)).collect();
    groups.insert(
        ADMISSION.to_owned(),
        DesiredGroup { display_name: "onprem-realm-users".to_owned() },
    );
    Desired {
        complete: true,
        admission_subject: Some(ADMISSION.to_owned()),
        grant_subject: None,
        users: users.into_iter().map(|(oid, u)| (oid.to_owned(), u)).collect(),
        groups,
        membership: BTreeMap::new(),
    }
}

/// Current state with the admission group present and marked, each object's
/// identity derived from its own oid so nothing reads as a duplicate.
fn current(users: Vec<(&str, CurrentUser)>, groups: Vec<(&str, CurrentGroup)>) -> Current {
    let admission = CurrentGroup {
        markers: vec![ROLE_ADMISSION.to_owned()],
        ..cur_group("onprem-realm-users", "onprem-realm-users")
    };
    let ident = |oid: &str| format!("kb1|entra|{oid}");
    Current {
        users: OrderedMap(
            users
                .into_iter()
                .map(|(oid, u)| (oid.to_owned(), CurrentUser { identity: ident(oid), ..u }))
                .collect(),
        ),
        groups: OrderedMap(
            std::iter::once((ADMISSION, admission))
                .chain(groups)
                .map(|(oid, g)| (oid.to_owned(), CurrentGroup { identity: ident(oid), ..g }))
                .collect(),
        ),
        foreign_sams: vec![],
        unmanaged_dns: vec![],
    }
}

/// A live managed user at `CN=<display>` directly under `OU=Entra`.
fn cur_user(sam: &str, display: &str) -> CurrentUser {
    CurrentUser {
        dn: format!("CN={display},{BASE}"),
        sam: sam.to_owned(),
        display_name: Some(display.to_owned()),
        enabled: true,
        markers: vec![],
        identity: String::new(),
    }
}

fn cur_group(sam: &str, display: &str) -> CurrentGroup {
    CurrentGroup {
        dn: format!("CN={display},{BASE}"),
        sam: sam.to_owned(),
        display_name: display.to_owned(),
        members: vec![],
        markers: vec![],
        identity: String::new(),
    }
}

fn des_user(display: &str) -> DesiredUser {
    DesiredUser {
        display_name: display.to_owned(),
        mail: String::new(),
        other_mails: Vec::new(),
        upn: "someone@contoso.example".to_owned(),
        enabled: true,
    }
}

/// Retired one window ago, i.e. before the cycle under test.
fn retired_marker() -> String {
    format!("{ST_RETIRED}2026-07-01T00:00:00Z")
}

const STEADY: &str = "5c0ffee0-0000-0000-0000-000000000001";

/// Carol, retired and brought back in `names`, cleared of a grant in `grants`.
const CAROL: &str = "ca201005-0000-0000-0000-000000000005";

/// A user unchanged on both sides: she plans no ops of her own, and her
/// presence is what keeps the empty-desired-state freeze out of the way in
/// tests that are about somebody *else* being retired. Without her, "the
/// only user vanished" and "the read came back empty" are the same input,
/// and the planner is right to refuse to tell them apart.
fn steady_desired() -> Vec<(&'static str, DesiredUser)> {
    vec![(STEADY, des_user("Steady State"))]
}

fn steady_current() -> Vec<(&'static str, CurrentUser)> {
    vec![(STEADY, cur_user("steady.state", "Steady State"))]
}
