//! Taking a distinguished name apart, the same way everywhere.
//!
//! Only what more than one component needs -- which now includes the component-wise
//! containment test. It used to live in `kbmanage` alone, on the reasoning that a
//! security boundary belongs next to the thing it guards; that turned out to be the
//! wrong cut. Sync was answering the same question with `ends_with`, so the two
//! disagreed about whether `OU=Entra-archive,DC=…` is inside `OU=Entra,DC=…` --
//! `kbmanage` refused to write there and sync treated its contents as its own.
//! One implementation, one answer, one test suite.

/// `EXAMPLE.SITE` -> `DC=example,DC=site`, the same derivation AD itself makes,
/// so the realm is the only place the domain is configured.
pub fn base_dn_for(realm: &str) -> String {
    realm.to_lowercase().split('.').map(|label| format!("DC={label}")).collect::<Vec<_>>().join(",")
}

/// The OU holding one IdP-specific OU per source, and nothing else.
pub fn idp_parent_ou_for(base_dn: &str) -> String {
    format!("OU=CloudIdP,{base_dn}")
}

/// Everything after a DN's first RDN: the OU an object is in.
///
/// `""` when there is no comma, which is a DN with no parent. Neither caller can
/// reach that -- sync's DNs are all under `OU=Entra` and `kbmanage`'s under the
/// resource OU -- and the alternative, returning the whole DN, would quietly make
/// `format!("CN=new,{}", parent_of(dn))` name a sibling of a root that has none.
///
/// A backslash escapes the character after it, so `CN=Doe\, Jane,OU=…` splits at
/// the second comma rather than the first. Sync's own writes never contain one --
/// `safe_name` replaces reserved characters before a name is ever written -- but
/// `kbmanage` renames objects an operator created, and there the escape is real.
/// The two implementations that preceded this one differed exactly here, which
/// is the kind of divergence that shows up as one malformed DN a year later.
pub fn parent_of(dn: &str) -> &str {
    let mut chars = dn.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            ',' => return &dn[i + 1..],
            _ => {}
        }
    }
    ""
}

/// Split a DN into normalized components: `attr=value`, attribute lowercased,
/// value case-folded and trimmed, `\,` and `\\` escapes honored.
///
/// Normalization is what closes the bypasses. `ou=entra , dc=example,dc=site`
/// and `OU=Entra,DC=example,DC=site` produce the same components, so neither
/// case nor spacing changes the answer.
pub fn dn_components(dn: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = dn.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                // An escape keeps its backslash: `CN=a\,b` and `CN=a,b` are
                // different DNs and must not normalize to the same components.
                current.push('\\');
                current.push(chars.next()?);
            }
            ',' => {
                out.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    out.push(current);

    out.iter()
        .map(|component| {
            let (attr, value) = component.split_once('=')?;
            let (attr, value) = (attr.trim(), value.trim());
            if attr.is_empty() || value.is_empty() {
                return None;
            }
            Some(format!("{}={}", attr.to_lowercase(), value.to_lowercase()))
        })
        .collect()
}

/// Is `dn` the OU itself, or anything beneath it?
///
/// Component-wise, so `OU=Entra-archive,DC=…` is not "inside" `OU=Entra,DC=…`
/// merely because one string contains the other.
pub fn dn_is_at_or_within(dn: &str, ou: &str) -> bool {
    let (Some(d), Some(c)) = (dn_components(dn), dn_components(ou)) else {
        return false;
    };
    d.len() >= c.len() && d[d.len() - c.len()..] == c[..]
}

pub fn dn_equals(a: &str, b: &str) -> bool {
    match (dn_components(a), dn_components(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_the_base_dn_from_the_realm() {
        assert_eq!(base_dn_for("EXAMPLE.SITE"), "DC=example,DC=site");
        assert_eq!(base_dn_for("a.b.c.example.site"), "DC=a,DC=b,DC=c,DC=example,DC=site");
    }

    #[test]
    fn drops_exactly_the_first_rdn() {
        assert_eq!(parent_of("CN=a,OU=Entra,DC=x"), "OU=Entra,DC=x");
        assert_eq!(
            parent_of("CN=alice,OU=Retired,OU=Entra,DC=example,DC=site"),
            "OU=Retired,OU=Entra,DC=example,DC=site"
        );
    }

    /// The case the two previous implementations disagreed on: an escaped comma
    /// is part of the CN, not a component boundary.
    #[test]
    fn an_escaped_comma_does_not_end_the_rdn() {
        assert_eq!(parent_of("CN=Doe\\, Jane,OU=Entra,DC=x"), "OU=Entra,DC=x");
        assert_eq!(parent_of("CN=a\\,b\\,c,DC=x"), "DC=x");
        // An escaped backslash is not an escape for the comma behind it.
        assert_eq!(parent_of("CN=a\\\\,DC=x"), "DC=x");
    }

    #[test]
    fn a_dn_with_no_parent_is_empty_rather_than_itself() {
        assert_eq!(parent_of("DC=x"), "");
        assert_eq!(parent_of(""), "");
        // A trailing comma leaves an empty parent, which is what it says.
        assert_eq!(parent_of("CN=a,"), "");
    }

    #[test]
    fn an_escaped_comma_is_one_component_not_two() {
        let parts = dn_components("CN=Doe\\, Jane,OU=Resources,DC=example,DC=site").unwrap();
        assert_eq!(parts.len(), 4, "{parts:?}");
        assert_eq!(parts[0], "cn=doe\\, jane");
    }

    #[test]
    fn malformed_dns_are_refused_rather_than_parsed_generously() {
        for dn in ["", "not a dn", "CN=", "=value,DC=x", "CN=a,,DC=x", "CN=a,DC="] {
            assert_eq!(dn_components(dn), None, "{dn:?}");
        }
    }

    /// Both callers ask this about a *security* boundary, in opposite directions:
    /// `kbmanage` refuses to write inside the OU, sync claims ownership of
    /// what is inside it. So the interesting assertions are the negative ones.
    #[test]
    fn containment_is_by_component_not_by_substring() {
        const BASE: &str = "OU=Entra,DC=example,DC=site";
        assert!(dn_is_at_or_within("CN=a,OU=Entra,DC=example,DC=site", BASE));
        assert!(dn_is_at_or_within("CN=a,OU=Sub,OU=Entra,DC=example,DC=site", BASE));
        // The OU itself is "at or within" it.
        assert!(dn_is_at_or_within(BASE, BASE));
        // Case and spacing do not change the answer.
        assert!(dn_is_at_or_within("cn=a , ou=entra,dc=example,dc=site", BASE));

        // A sibling OU that merely shares a prefix or a fragment of the name.
        assert!(!dn_is_at_or_within("CN=a,OU=Entra-archive,DC=example,DC=site", BASE));
        assert!(!dn_is_at_or_within("CN=a,OU=NotEntra,DC=example,DC=site", BASE));
        assert!(!dn_is_at_or_within("CN=a,OU=Entra,DC=example,DC=other", BASE));

        // The two a plain `ends_with` gets wrong, and the reason this function
        // exists: the base string ends the DN without starting a component. An
        // escaped comma is the reachable one -- that is a single RDN named
        // `Bob,OU=Entra`, in `DC=example,DC=site`, nowhere near the OU.
        for outside in ["CN=Bob\\,OU=Entra,DC=example,DC=site", "CN=fooOU=Entra,DC=example,DC=site"]
        {
            assert!(outside.ends_with(BASE), "{outside} must be a suffix match to be the case");
            assert!(!dn_is_at_or_within(outside, BASE), "{outside}");
        }

        // A malformed DN is outside everything rather than inside anything.
        assert!(!dn_is_at_or_within("not a dn", BASE));
        assert!(!dn_is_at_or_within("CN=a,OU=Entra,DC=example,DC=site", "not a dn"));
    }

    #[test]
    fn equality_is_component_wise_too() {
        assert!(dn_equals("OU=Entra,DC=x", "ou=entra , dc=x"));
        assert!(!dn_equals("OU=Entra,DC=x", "OU=Entra-archive,DC=x"));
        assert!(!dn_equals("not a dn", "not a dn"));
    }
}
