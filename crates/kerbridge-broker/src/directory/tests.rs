use super::*;

/// The admission-group DN reaches a filter, thus it is escaped like any other
/// value.
#[test]
fn escapes_a_hostile_admission_group_dn() {
    let escaped = escape_ldap_filter_value("CN=admission)(objectClass=*");
    assert!(!escaped.contains(')'), "got {escaped}");
    assert!(!escaped.contains('('), "got {escaped}");
}

/// `kerbridge_core::tls` owns the trust decision and tests it. This test pins
/// only that the broker calls it in the form that refuses a missing CA, and
/// does not fall back to the OS trust store.
#[test]
fn refuses_ldaps_without_a_configured_ca() {
    assert!(kerbridge_core::tls::client_config(None).is_err());
}

/// The two spellings that a delegated request may name a target by.
#[test]
fn a_target_is_a_login_name_or_a_literal_identity() {
    assert_eq!(Target::parse("svc-builder"), Ok(Target::Sam("svc-builder".to_owned())));
    assert_eq!(Target::parse("  svc-builder  "), Ok(Target::Sam("svc-builder".to_owned())));
    let id =
        ExternalIdentity::new(&kerbridge_core::Source::new("entra").unwrap(), "object").unwrap();
    assert_eq!(Target::parse(&id.encode()), Ok(Target::Identity(Box::new(id))));
}

/// A UPN is refused on the wire even though it would resolve. A second mutable
/// spelling that arrives as end-user input is attack surface and support load,
/// and the error must name which spelling to use instead.
#[test]
fn a_target_may_not_be_a_upn_or_a_broken_identity() {
    let refusal = Target::parse("riku@example.site").expect_err("a UPN was accepted");
    assert!(refusal.contains("login name"), "{refusal}");
    assert!(Target::parse("").is_err());
    assert!(Target::parse("   ").is_err());
    // Recognized by its tag and then refused. It does not fall through and
    // read as a login name that happens to contain pipes.
    assert!(Target::parse("kb1|entra|sub|extra").is_err());
    assert!(Target::parse("kb1||sub").is_err());
}

/// The login-name filter constrains `objectClass`. Without that, a group
/// resolves here and then dies on its missing `userAccountControl`: a 500 where
/// a refusal belongs. The value itself reaches a filter, thus it is escaped like
/// any other.
#[test]
fn the_login_name_filter_is_constrained_and_escaped() {
    let filter = Target::Sam("svc)(objectClass=*".to_owned()).ldap_filter();
    assert!(filter.starts_with("(&(objectClass=user)"), "{filter}");
    assert!(!filter.contains("=*)"), "{filter}");
}

fn account(sam: &str, dn: &str) -> Account {
    Account {
        sid: format!("S-1-5-21-0-0-0-{sam}"),
        sam_account_name: sam.to_owned(),
        identity: format!("kb1|entra|{sam}"),
        dn: dn.to_owned(),
        managed_objects: Vec::new(),
        grants: Vec::new(),
    }
}

/// The caller/target matrix, as `verdict` states it. The reads on both sides
/// belong to the directory; this test covers the rule alone.
#[test]
fn the_caller_target_matrix() {
    let riku = || account("riku", "CN=riku,OU=Entra,DC=example,DC=site");
    let svc = || account("svc-builder", "CN=svc-builder,OU=Entra,DC=example,DC=site");

    // Caller is the target: the self-service path, whatever the delegate
    // answer would have been. It is not consulted.
    for delegated in [true, false] {
        let ok = verdict(riku(), riku(), delegated).expect("naming yourself is refused");
        assert_eq!(ok.target.sam_account_name, "riku");
        assert!(ok.delegate.is_none(), "the self path named a delegate");
    }

    // Caller differs and is in the target's delegate group. The grant is the
    // target's, and the audit line names the caller.
    let ok = verdict(riku(), svc(), true).expect("a delegate is refused");
    assert_eq!(ok.target.sam_account_name, "svc-builder");
    assert_eq!(ok.delegate.as_deref(), Some("riku"));

    // Caller differs and is not a delegate: the one refusal in the table, and
    // the one that fails silently if it ever stops happening.
    assert!(matches!(verdict(riku(), svc(), false), Err(Denied::NotDelegate)));
}

/// AD returns a DN in whatever case the object was created with, and different
/// filters reach the two sides of this comparison. A case-sensitive test here
/// would demand a delegate group of someone who named nobody but themselves.
#[test]
fn naming_yourself_is_the_self_path_whatever_the_dn_case() {
    let ok = verdict(
        account("riku", "CN=riku,OU=Entra,DC=example,DC=site"),
        account("riku", "cn=Riku,ou=entra,dc=Example,dc=Site"),
        false,
    )
    .expect("a differently-cased DN was treated as somebody else");
    assert!(ok.delegate.is_none());
}
