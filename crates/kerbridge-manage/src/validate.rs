//! Pure checks that stand between an operator's argument and a directory write.
//!
//! The one that matters is DN confinement. Everything under the IdP parent OU is
//! sync-owned and this tool has no update path into it; the guard that enforces
//! that is a string comparison, so it is written to survive the ways a string
//! comparison is normally got around -- case, whitespace, and a DN that merely
//! *contains* the OU's text without being under it.

use std::fmt;

// The confinement guard's DN parsing moved to `kerbridge-core` when sync turned out
// to be asking the same containment question with `ends_with`. Re-exported, because
// the guard is still this module's job and its callers name it here.
pub use kerbridge_core::dn::{dn_components, dn_equals, dn_is_at_or_within};
use kerbridge_core::state::RETIRED_PREFIX;

use crate::model::ManagedGroup;

/// Why a DN was refused. A caller renders these; the library never prints.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The target is inside the OU sync owns.
    InsideCloudIdp { dn: String, cloud_idp_ou: String },
    /// The target is the IdP parent OU object itself.
    IsCloudIdpOuItself { dn: String },
    /// The target is outside the OU this deployment delegates on.
    OutsideResourceOu { dn: String, resource_ou: String },
    /// Not a DN at all, or one with an empty component.
    Malformed { dn: String },
    /// A name that cannot become an RDN without escaping games.
    BadName { name: String, why: &'static str },
    /// A group verb resolved to something that is not a group.
    NotAGroup { dn: String, classes: String },
    /// A delegation resolved to something that is not a person.
    NotAUser { dn: String, classes: String },
    /// A proposed login name the realm cannot carry.
    BadLoginName { name: String, why: String },
    /// A two-name verb whose arguments were given the other way round.
    ReversedArguments { verb: &'static str, wanted: &'static str, first: String, second: String },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsideCloudIdp { dn, cloud_idp_ou } => write!(
                f,
                "{dn} is inside {cloud_idp_ou}, which kerbridge-sync owns. \
                 This tool reads there, deletes, and renames a login name; it updates \
                 nothing else -- a second writer racing the reconciliation loop is the \
                 failure it exists to avoid"
            ),
            Self::IsCloudIdpOuItself { dn } => {
                write!(f, "{dn} is the sync-owned OU itself, not an object in it")
            }
            Self::BadLoginName { name, why } => write!(
                f,
                "{name:?} cannot be a login name here: {why}. It has to satisfy the same rule \
                 kerbridge-sync derives under and issuerd validates against, or the account \
                 synchronizes but can never be issued a ticket"
            ),
            Self::OutsideResourceOu { dn, resource_ou } => write!(
                f,
                "{dn} is outside {resource_ou}. svc-kerbridge-manage is delegated on that OU only, \
                 so the directory would refuse this with insufficientAccessRights. \
                 Set resource_ou in realm.toml (and move the delegation) if the OU has moved"
            ),
            Self::Malformed { dn } => write!(f, "{dn:?} is not a well-formed DN"),
            Self::BadName { name, why } => write!(f, "{name:?} is not a usable group name: {why}"),
            Self::NotAGroup { dn, classes } => write!(
                f,
                "{dn} is not a group -- it is {classes}. The group verbs act only on groups; \
                 name resolution matches people too, and a person is not something to \
                 delete or rename by accident"
            ),
            Self::NotAUser { dn, classes } => write!(
                f,
                "{dn} is not a person -- it is {classes}. A delegation names the account whose \
                 device grants are lent out, and the broker resolves that as an account: a \
                 group here is a link nothing would ever follow"
            ),
            Self::ReversedArguments { verb, wanted, first, second } => write!(
                f,
                "{first:?} cannot be the {wanted} `kbmanage {verb}` acts on, and {second:?} can \
                 -- the two arguments are the other way round.\n\
                 Try: kbmanage {verb} {second} {first}"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// The guard on every write verb: refuse anything sync owns.
pub fn assert_outside_cloud_idp(dn: &str, cloud_idp_ou: &str) -> Result<(), Refusal> {
    if dn_components(dn).is_none() {
        return Err(Refusal::Malformed { dn: dn.to_owned() });
    }
    if dn_is_at_or_within(dn, cloud_idp_ou) {
        return Err(Refusal::InsideCloudIdp {
            dn: dn.to_owned(),
            cloud_idp_ou: cloud_idp_ou.to_owned(),
        });
    }
    Ok(())
}

/// The guard on `cloud delete`: the target must be *in* the IdP parent OU, and must
/// not be the OU itself.
pub fn assert_inside_cloud_idp(dn: &str, cloud_idp_ou: &str) -> Result<(), Refusal> {
    if dn_components(dn).is_none() {
        return Err(Refusal::Malformed { dn: dn.to_owned() });
    }
    if dn_equals(dn, cloud_idp_ou) {
        return Err(Refusal::IsCloudIdpOuItself { dn: dn.to_owned() });
    }
    if !dn_is_at_or_within(dn, cloud_idp_ou) {
        return Err(Refusal::Malformed { dn: dn.to_owned() });
    }
    Ok(())
}

/// The guard on resource-group writes. Not a security boundary -- the directory
/// enforces that with the delegation -- but a better error than LDAP 50, given
/// the delegation and this check are configured from the same value.
pub fn assert_within_resource_ou(dn: &str, resource_ou: &str) -> Result<(), Refusal> {
    if dn_components(dn).is_none() {
        return Err(Refusal::Malformed { dn: dn.to_owned() });
    }
    if !dn_is_at_or_within(dn, resource_ou) || dn_equals(dn, resource_ou) {
        return Err(Refusal::OutsideResourceOu {
            dn: dn.to_owned(),
            resource_ou: resource_ou.to_owned(),
        });
    }
    Ok(())
}

/// The guard on the destructive group verbs: the target must actually be a group.
///
/// `Directory::resolve` matches users as well as groups -- `cloud` needs that --
/// and it matches on `cn` and `sAMAccountName` among others, so a resource group
/// and a person can answer to the same string. Without this, `group delete
/// <name>` landing on a user account is a delete of that account, and the only
/// thing standing in the way is whether the directory happens to have delegated
/// it. Matched case-insensitively because `objectClass` values are, and read
/// from the entry the verb is about to act on rather than from a second lookup.
pub fn assert_is_group(dn: &str, object_classes: &[String]) -> Result<(), Refusal> {
    if object_classes.iter().any(|c| c.eq_ignore_ascii_case("group")) {
        return Ok(());
    }
    Err(Refusal::NotAGroup {
        dn: dn.to_owned(),
        // Empty when the directory returned no objectClass at all, which is not
        // a group either -- fail closed and say what was seen.
        classes: if object_classes.is_empty() {
            "an object with no objectClass".to_owned()
        } else {
            object_classes.join(", ")
        },
    })
}

/// The guard on a delegation's target: `managedBy` must name a person.
///
/// The broker resolves that account the way it resolves anyone -- login name,
/// admission, device-grant group, `userAccountControl` -- so a link naming a
/// group is one nothing will ever follow. Refusing here says so; the
/// alternative is a delegation that reads as set and authorizes nobody.
pub fn assert_is_user(dn: &str, object_classes: &[String]) -> Result<(), Refusal> {
    if object_classes.iter().any(|c| c.eq_ignore_ascii_case("user")) {
        return Ok(());
    }
    Err(Refusal::NotAUser {
        dn: dn.to_owned(),
        classes: if object_classes.is_empty() {
            "an object with no objectClass".to_owned()
        } else {
            object_classes.join(", ")
        },
    })
}

/// One argument of a two-name verb: what the operator typed, and which of the
/// verb's two positions the object it resolved to could fill.
#[derive(Debug, Clone, Copy)]
pub struct Arg<'a> {
    pub given: &'a str,
    pub fits_first: bool,
    pub fits_second: bool,
}

/// Refuse a two-name verb whose arguments were given the other way round, and
/// say which command would have worked.
///
/// This is not "are these the right kinds of object" -- the per-verb guards
/// answer that, and say more about it. It is the narrower question they cannot
/// answer: whether the *other* order would have been accepted. That is the one
/// mistake a script converted from `group nest` makes, and the one a generic
/// "outside the IdP parent OU" refusal never explains. A pair that is wrong in some
/// other way falls through to those guards untouched.
pub fn assert_argument_order(
    verb: &'static str,
    wanted: &'static str,
    first: Arg<'_>,
    second: Arg<'_>,
) -> Result<(), Refusal> {
    if first.fits_first && second.fits_second {
        return Ok(());
    }
    if second.fits_first && first.fits_second {
        return Err(Refusal::ReversedArguments {
            verb,
            wanted,
            first: first.given.to_owned(),
            second: second.given.to_owned(),
        });
    }
    Ok(())
}

/// The delegate links a write has to clear first: every delegate group naming
/// the account, except the one `set` is about to keep.
///
/// One delegate group per account, enforced here and not by the directory,
/// which allows several. A `set` that left the previous one standing would
/// leave the team it was for a right nobody remembers granting -- an operator
/// moving a service account between teams reads "set" as replace.
///
/// A group naming the account *without* the marker is left out deliberately:
/// that is an admin's ownership record, it authorizes nobody, and destroying it
/// would be this tool editing something it was not asked about.
pub fn delegate_links_to_clear<'a>(
    managed: &'a [ManagedGroup],
    keeping: Option<&str>,
) -> Vec<&'a str> {
    managed
        .iter()
        .filter(|g| g.is_delegate && !keeping.is_some_and(|dn| dn_equals(&g.dn, dn)))
        .map(|g| g.dn.as_str())
        .collect()
}

/// A group name that will survive becoming both an RDN and a `sAMAccountName`.
///
/// `sAMAccountName` is capped at 20 characters for accounts; groups are capped
/// at 64 in practice, and it is the name a file server matches in
/// `valid users`, so it may not carry the characters AD reserves in an RDN.
pub fn check_group_name(name: &str) -> Result<(), Refusal> {
    let bad = |why| Err(Refusal::BadName { name: name.to_owned(), why });
    if name.trim() != name || name.is_empty() {
        return bad("leading or trailing whitespace, or empty");
    }
    if name.len() > 64 {
        return bad("longer than the 64 characters AD allows a group's sAMAccountName");
    }
    if name.chars().any(|c| matches!(c, ',' | '=' | '+' | '<' | '>' | '#' | ';' | '\\' | '"')) {
        return bad("contains a character AD reserves in a DN (,=+<>#;\\\")");
    }
    if name.chars().any(|c| c.is_control()) {
        return bad("contains a control character");
    }
    Ok(())
}

/// A login name an operator proposes, against the one rule the realm has.
///
/// Defers to `kerbridge_core::sam`, deliberately: that is the rule
/// `kerbridge-sync` derives under and `issuerd` validates against, and a third
/// opinion here is how a name that synchronizes but cannot sign in gets made.
/// The `_retired-` namespace is refused on top, because sync reads that prefix
/// as "this account is in retention" and an operator moving a live account into
/// it would be lying to the reconciler.
pub fn check_login_name(name: &str) -> Result<(), Refusal> {
    kerbridge_core::sam::validate(name)
        .map_err(|why| Refusal::BadLoginName { name: name.to_owned(), why: why.to_string() })?;
    if name.starts_with(RETIRED_PREFIX) {
        return Err(Refusal::BadLoginName {
            name: name.to_owned(),
            why: format!("{RETIRED_PREFIX}* is the namespace sync retires accounts into"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLOUD_IDP_OU: &str = "OU=Entra,DC=example,DC=site";

    /// A rename must not be able to derive a name sync itself could not have
    /// derived -- that is the whole reason this delegates rather than deciding.
    #[test]
    fn a_proposed_login_name_answers_to_the_realm_rule() {
        assert!(check_login_name("jane.doe").is_ok());
        assert!(check_login_name("민준.박").is_ok(), "non-ASCII is a name, not an error");
        assert!(check_login_name("o-brien_2").is_ok());

        // Whatever kerbridge_core::sam refuses, this refuses.
        for bad in ["", "jane doe", "jane@doe", "-jane", "jane/doe"] {
            assert!(check_login_name(bad).is_err(), "{bad:?} must be refused");
        }
        // Decomposed input: the combining mark is not alphanumeric, and issuerd
        // would reject the account at first sign-in. Refuse it at the keyboard.
        assert!(check_login_name("a\u{30a}sa").is_err(), "NFD must not get in by hand");

        // The retirement namespace is sync's to write, not an operator's.
        let e = check_login_name("_retired-jane.doe").unwrap_err();
        assert!(matches!(&e, Refusal::BadLoginName { why, .. } if why.contains("retire")), "{e:?}");
        assert!(check_login_name(&"a".repeat(65)).is_err(), "past the 64-byte budget");
    }

    const RES: &str = "OU=Resources,DC=example,DC=site";

    #[test]
    fn confinement_survives_case_and_whitespace() {
        for dn in [
            "CN=alice,OU=Entra,DC=example,DC=site",
            "cn=alice,ou=entra,dc=example,dc=site",
            "CN=alice,  OU=Entra , DC=example,DC=site",
            "CN=x,OU=Retired,OU=Entra,DC=example,DC=site",
            "OU=Entra,DC=example,DC=site",
        ] {
            assert!(assert_outside_cloud_idp(dn, CLOUD_IDP_OU).is_err(), "{dn} must be refused");
        }
    }

    #[test]
    fn confinement_is_not_a_substring_match() {
        // Each of these contains the OU's text without being under it.
        for dn in [
            "CN=alice,OU=Entra-archive,DC=example,DC=site",
            "CN=OU=Entra\\,DC=example\\,DC=site,OU=Resources,DC=example,DC=site",
            "CN=alice,OU=NotEntra,DC=example,DC=site",
            "CN=alice,OU=Entra,DC=example,DC=other",
        ] {
            assert!(assert_outside_cloud_idp(dn, CLOUD_IDP_OU).is_ok(), "{dn} must be allowed");
        }
    }

    #[test]
    /// What the *guards* do with a DN they cannot parse, which is this module's
    /// half. That `dn_components` rejects these at all is `kerbridge-core`'s test.
    fn malformed_dns_are_refused_rather_than_parsed_generously() {
        for dn in ["", "not a dn", "CN=", "=value,DC=x", "CN=a,,DC=x", "CN=a,DC="] {
            assert!(assert_outside_cloud_idp(dn, CLOUD_IDP_OU).is_err(), "{dn:?}");
            assert!(assert_within_resource_ou(dn, RES).is_err(), "{dn:?}");
        }
    }

    #[test]
    fn resource_writes_stay_in_the_delegated_ou() {
        assert!(
            assert_within_resource_ou("CN=share-rw,OU=Resources,DC=example,DC=site", RES).is_ok()
        );
        assert!(
            assert_within_resource_ou("CN=g,OU=Sub,OU=Resources,DC=example,DC=site", RES).is_ok()
        );
        // The OU itself is not a group.
        assert!(assert_within_resource_ou(RES, RES).is_err());
        // Elsewhere entirely, including the sync-owned OU.
        assert!(assert_within_resource_ou("CN=g,OU=Entra,DC=example,DC=site", RES).is_err());
        assert!(assert_within_resource_ou("CN=g,CN=Users,DC=example,DC=site", RES).is_err());
    }

    #[test]
    fn cloud_delete_targets_objects_inside_and_not_the_ou_itself() {
        assert!(
            assert_inside_cloud_idp("CN=alice,OU=Entra,DC=example,DC=site", CLOUD_IDP_OU).is_ok()
        );
        assert!(
            assert_inside_cloud_idp("CN=x,OU=Retired,OU=Entra,DC=example,DC=site", CLOUD_IDP_OU)
                .is_ok()
        );
        assert_eq!(
            assert_inside_cloud_idp(CLOUD_IDP_OU, CLOUD_IDP_OU),
            Err(Refusal::IsCloudIdpOuItself { dn: CLOUD_IDP_OU.to_owned() })
        );
        assert!(
            assert_inside_cloud_idp("CN=g,OU=Resources,DC=example,DC=site", CLOUD_IDP_OU).is_err()
        );
    }

    #[test]
    fn the_group_verbs_refuse_anything_that_is_not_a_group() {
        let dn = "CN=alice,CN=Users,DC=example,DC=site";
        let group = ["top".to_owned(), "group".to_owned()];
        assert!(assert_is_group(dn, &group).is_ok());
        // AD returns objectClass in schema order and in mixed case.
        assert!(assert_is_group(dn, &["Top".to_owned(), "Group".to_owned()]).is_ok());

        let user = ["top", "person", "organizationalPerson", "user"].map(str::to_owned);
        assert!(matches!(assert_is_group(dn, &user), Err(Refusal::NotAGroup { .. })));
        assert!(matches!(assert_is_group(dn, &[]), Err(Refusal::NotAGroup { .. })));
        // `group` must be a whole value, not a substring of one.
        let computer = ["top".to_owned(), "groupPolicyContainer".to_owned()];
        assert!(matches!(assert_is_group(dn, &computer), Err(Refusal::NotAGroup { .. })));
    }

    /// The whole point of the check: `group nest <synced> <resource>` became
    /// `group member add <resource> <synced>`, so a script someone converted by
    /// changing the verb keeps the old order, and the verb name no longer
    /// catches it. This is the only place left that can.
    #[test]
    fn reversed_arguments_are_refused_with_the_command_that_would_have_worked() {
        // A synced group fits only the member position; a resource group fits
        // either, since nesting one resource group into another is ordinary.
        let synced = Arg { given: "proj-x", fits_first: false, fits_second: true };
        let resource = Arg { given: "nas-share-rw", fits_first: true, fits_second: true };

        let e = assert_argument_order("group member add", "resource group", synced, resource)
            .unwrap_err();
        let msg = e.to_string();
        assert!(msg.contains("kbmanage group member add nas-share-rw proj-x"), "{msg}");
        assert!(msg.contains("resource group"), "the wrong argument is named: {msg}");

        assert!(
            assert_argument_order("group member add", "resource group", resource, synced).is_ok()
        );

        // Wrong in some other way -- neither order would have worked -- is the
        // per-verb guards' refusal to give, and they say more about it.
        let person = Arg { given: "alice", fits_first: false, fits_second: true };
        assert!(
            assert_argument_order("group member add", "resource group", person, synced).is_ok()
        );

        // The exception D16 states: `device delegate set` puts the user first,
        // so the reversal it catches is the group-first one.
        let user = Arg { given: "svc-builder", fits_first: true, fits_second: false };
        let delegates = Arg { given: "nas-build-delegates", fits_first: false, fits_second: true };
        let e = assert_argument_order("device delegate set", "user", delegates, user).unwrap_err();
        assert!(
            e.to_string().contains("kbmanage device delegate set svc-builder nas-build-delegates"),
            "{e}"
        );
        assert!(assert_argument_order("device delegate set", "user", user, delegates).is_ok());
    }

    /// D8: one delegate group per account, enforced by the tool because the
    /// directory would allow several.
    #[test]
    fn delegate_set_clears_the_link_the_account_already_had() {
        let managed = |dn: &str, is_delegate| ManagedGroup { dn: dn.to_owned(), is_delegate };
        let team_a = format!("CN=team-a-delegates,{RES}");
        let team_b = format!("CN=team-b-delegates,{RES}");
        let owned = format!("CN=nas-share-rw,{RES}");
        let links = [
            managed(&team_a, true),
            managed(&team_b, true),
            // An admin's `managedBy`, set for ADUC reasons. It delegates
            // nothing and is not this tool's to destroy.
            managed(&owned, false),
        ];

        assert_eq!(delegate_links_to_clear(&links, Some(&team_b)), vec![team_a.as_str()]);
        // The DN comes back from a second search, so it is compared as a DN and
        // not as the operator's spelling of one.
        assert_eq!(
            delegate_links_to_clear(
                &links,
                Some("cn=team-b-delegates, ou=Resources,dc=example,DC=site")
            ),
            vec![team_a.as_str()]
        );
        // Setting the group that is already in place clears nothing else.
        assert_eq!(
            delegate_links_to_clear(&[managed(&team_b, true)], Some(&team_b)),
            Vec::<&str>::new()
        );
        // `clear` keeps nothing, and still leaves the ownership record alone.
        assert_eq!(delegate_links_to_clear(&links, None), vec![team_a.as_str(), team_b.as_str()]);
    }

    #[test]
    fn a_delegation_names_a_person_and_never_a_group() {
        let dn = "CN=svc-builder,OU=Entra,DC=example,DC=site";
        let user = ["top", "person", "organizationalPerson", "user"].map(str::to_owned);
        assert!(assert_is_user(dn, &user).is_ok());
        assert!(matches!(
            assert_is_user(dn, &["top".to_owned(), "group".to_owned()]),
            Err(Refusal::NotAUser { .. })
        ));
        assert!(matches!(assert_is_user(dn, &[]), Err(Refusal::NotAUser { .. })));
    }

    #[test]
    fn group_names_that_would_break_an_rdn_or_a_valid_users_line() {
        assert!(check_group_name("nas-share-rw").is_ok());
        assert!(check_group_name("Backup Operators (site)").is_ok());
        for bad in ["", " leading", "trailing ", "with,comma", "with=equals", "back\\slash"] {
            assert!(check_group_name(bad).is_err(), "{bad:?}");
        }
        assert!(check_group_name(&"x".repeat(65)).is_err());
        assert!(check_group_name(&"x".repeat(64)).is_ok());
    }
}
