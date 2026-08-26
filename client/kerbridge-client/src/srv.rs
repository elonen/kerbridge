//! Finding the broker in DNS, so a fresh machine needs neither a typed address
//! nor a value pushed from a management system.
//!
//! ```text
//! _kerbridge._tcp.example.site.  SRV  0 100 443 kerbridge.example.site.
//! ```
//!
//! The realm's zone already carries `_kerberos._udp`/`_tcp` for the KDC, so this
//! is one more line in a file the operator is editing anyway -- and, unlike a
//! policy value, it reaches machines that no management system owns.
//!
//! **What DNS is trusted for here, and what it is not.** Only the *name* of a
//! broker inside this machine's own DNS domain: the SRV target must live in the
//! domain that answered, the URL is `https://`, and the certificate is validated
//! against the OS trust store exactly as it would be for a typed address. So a
//! hostile answer can point the client at a host in its own domain -- which a
//! hostile resolver could do to a typed address too -- but it cannot redirect it
//! to a domain the attacker owns, where their certificate would be valid. The
//! broker is still trusted to name the realm's KDCs.
//!
//! "This machine's own domain" includes the parents of its suffixes, down to two
//! labels -- see [`parents`]. A client in `usr.example.site` will therefore take a
//! broker named by `example.site`, which is the point: one record for an
//! organization whose clients sit in per-site subdomains. It will still not take
//! one named by a zone it is not under.
//!
//! Precedence is unchanged by all this: policy, then `config.toml`, and DNS only
//! when neither has an answer.
//!
//! Only two things are per-platform -- how to ask for an SRV record, and how to
//! find out which domains this machine is in. Both are in the arms; the policy
//! above is here, once, and so are its tests.

#[cfg_attr(windows, path = "windows/srv.rs")]
#[cfg_attr(target_os = "macos", path = "macos/srv.rs")]
#[cfg_attr(target_os = "linux", path = "linux/srv.rs")]
mod imp;

/// The record we look for, under each of this machine's DNS domains.
const SERVICE: &str = "_kerbridge._tcp";

pub struct Srv {
    pub target: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

/// The broker URL DNS knows about, if any. `None` is the ordinary answer on a
/// network that publishes no such record, and never an error worth showing.
pub fn discover_broker() -> Option<String> {
    for domain in dns_domains() {
        let name = format!("{SERVICE}.{domain}");
        let Some(srv) = pick(imp::lookup_srv(&name)) else {
            continue;
        };
        // A target outside the domain that answered is the one shape of answer
        // that would let a hostile resolver hand this client to a host whose
        // certificate genuinely validates. Refuse it and say so.
        if !within(&srv.target, &domain) {
            crate::log::warn(&format!(
                "ignoring {name}: target {} is outside {domain}",
                srv.target
            ));
            continue;
        }
        let url = match srv.port {
            443 => format!("https://{}", srv.target),
            port => format!("https://{}:{port}", srv.target),
        };
        crate::log::info(&format!("{name} points at {url}"));
        return Some(url);
    }
    None
}

/// Lowest priority wins, then highest weight. RFC 2782 asks for a weighted
/// random choice among equals; a deterministic pick is chosen instead, because
/// one broker is the documented deployment and a reproducible answer is worth
/// more here than load spreading between two.
fn pick(mut records: Vec<Srv>) -> Option<Srv> {
    records.sort_by_key(|r| (r.priority, u16::MAX - r.weight));
    records.into_iter().next()
}

/// True when `host` is the domain itself or a name inside it.
fn within(host: &str, domain: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// The zones to ask, best guess first: this machine's own DNS domains, and then
/// their parents. Duplicates are dropped so a lookup is never repeated.
///
/// Every one of the machine's own suffixes is tried before any parent, so a
/// subdomain that publishes its own record always beats the one its parent
/// publishes for everybody.
fn dns_domains() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in imp::own_domains() {
        add(&mut out, &value);
    }
    for parent in out.clone().iter().flat_map(|d| parents(d)) {
        if !out.contains(&parent) {
            out.push(parent);
        }
    }
    out
}

/// Normalize and append. A Windows `SearchList` is one comma-separated value, so
/// every source is treated as one.
fn add(out: &mut Vec<String>, value: &str) {
    for candidate in value.split(',') {
        let candidate = candidate.trim().trim_end_matches('.').to_ascii_lowercase();
        // A single-label suffix is a workgroup name, not a zone we can query.
        if candidate.contains('.') && !out.contains(&candidate) {
            out.push(candidate);
        }
    }
}

/// A domain's parent zones, most specific first and stopping at two labels:
/// `usr.example.site` yields `example.site` and nothing more.
///
/// This is the suffix devolution a resolver applies to unqualified names, and
/// which therefore never helps us -- every name asked for here is already fully
/// qualified. One broker for a whole organization, with clients on per-site
/// subdomains, is the ordinary shape; without this the record has to be
/// republished in every subdomain, and each of those copies then names a target
/// in the parent, which [`within`] refuses. Walking up is the fix that keeps that
/// refusal intact rather than weakening it.
///
/// Two labels is where Windows stops by default (`DomainNameDevolutionLevel`),
/// and it is what keeps this from ever asking a bare TLD.
fn parents(domain: &str) -> Vec<String> {
    let labels: Vec<&str> = domain.split('.').collect();
    (1..labels.len().saturating_sub(1)).map(|i| labels[i..].join(".")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug this exists for: a client in `usr.example.site` reaching a broker
    /// the parent zone names. Without the walk up, the only record it ever sees
    /// is its own subdomain's, whose target is in the parent and so refused.
    #[test]
    fn a_subdomain_reaches_the_parent_zone() {
        assert_eq!(parents("usr.example.site"), ["example.site"]);
        assert_eq!(parents("a.b.example.site"), ["b.example.site", "example.site"]);
    }

    /// Two labels is the floor, so no lookup is ever aimed at a bare TLD.
    #[test]
    fn devolution_stops_before_the_tld() {
        assert!(parents("example.site").is_empty());
        assert!(parents("site").is_empty());
        assert!(parents("").is_empty());
    }

    #[test]
    fn a_target_must_be_in_the_zone_that_answered() {
        assert!(within("kerbridge.example.site", "example.site"));
        assert!(within("example.site", "example.site"));
        assert!(within("KerBridge.Example.Site.", "example.site"));
        // The refusal that makes the walk up necessary rather than optional.
        assert!(!within("kerbridge.example.site", "usr.example.site"));
        // And the one it exists for: a look-alike registered next door.
        assert!(!within("kerbridge.example.site.evil.test", "example.site"));
        assert!(!within("notexample.site", "example.site"));
    }

    /// Ordering is the policy: everything the machine is actually in, then
    /// parents. A subdomain that publishes its own record beats its parent's.
    #[test]
    fn parents_come_after_every_own_domain() {
        let own = ["usr.example.site".to_string(), "vpn.example.test".to_string()];
        let mut out = own.to_vec();
        for parent in own.iter().flat_map(|d| parents(d)) {
            if !out.contains(&parent) {
                out.push(parent);
            }
        }
        assert_eq!(out, ["usr.example.site", "vpn.example.test", "example.site", "example.test"]);
    }

    /// Single-label suffixes are workgroup names and a comma-separated list is
    /// one value -- both of which arrive from a real Windows `SearchList`.
    #[test]
    fn only_multi_label_domains_survive_normalization() {
        let mut out = Vec::new();
        add(&mut out, "WORKGROUP");
        add(&mut out, "Example.Site., usr.example.site");
        add(&mut out, "example.site");
        assert_eq!(out, ["example.site", "usr.example.site"]);
    }
}
