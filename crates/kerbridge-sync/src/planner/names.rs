//! Every name the planner writes: login names, CNs, and the DNs built from them.
//!
//! The invariant that holds the layer together is [`safe_name`]'s -- no name
//! derived here carries a DN-reserved character -- which is what lets `parent_of`
//! and the post-rename CN extraction split on a plain comma instead of becoming
//! escape-aware.

use std::collections::HashSet;

use kerbridge_core::dn::parent_of;
use kerbridge_core::sam;
use kerbridge_core::state::RETIRED_PREFIX;
use kerbridge_idp::sync::NameCandidate;
use unicode_normalization::UnicodeNormalization;

use super::{DesiredUser, PlanError};

/// First four characters of an object id -- the collision-disambiguation suffix.
///
/// By character, not by byte. An object id is remote input: Entra's is an ASCII
/// GUID, but nothing on the path *enforces* that, and a byte slice through the
/// middle of a codepoint is a panic rather than a bad name. This runs while
/// planning a retirement, so the panic would take down the cycle that was trying
/// to tidy up.
pub(super) fn oid4(oid: &str) -> String {
    oid.chars().take(4).collect()
}

/// `(sAMAccountName, CN)` for an object being retired: the live name is released
/// for a returning cloud object, this one keeps a recognizable, obviously-retired
/// form of it. `RETIRED_PREFIX` is 9 of `sanitize_sam`'s 20-char budget, so the
/// kept part is 11 -- or 6 plus `-<oid4>` when an earlier retirement already took
/// the short form, mirroring `alloc_names`. The CN has no length limit and is what
/// ADUC shows, so it stays readable.
pub(super) fn retired_names(
    dn: &str,
    sam: &str,
    label: &str,
    oid: &str,
    sam_keys: &mut HashSet<String>,
    taken_dns: &mut HashSet<String>,
) -> (String, String) {
    let mut new_sam = format!("{RETIRED_PREFIX}{}", sanitize_sam(sam, 11));
    if sam_keys.contains(&sam::fold(&new_sam)) {
        new_sam = format!("{RETIRED_PREFIX}{}-{}", sanitize_sam(sam, 6), oid4(oid));
    }
    sam_keys.insert(sam::fold(&new_sam));
    let label = safe_name(label).unwrap_or_else(|| new_sam.clone());
    let parent = parent_of(dn);
    let mut cn = format!("{label} (retired)");
    if taken_dns.contains(&format!("CN={cn},{parent}")) {
        cn = format!("{} (retired {})", label.trim(), oid4(oid));
    }
    taken_dns.insert(format!("CN={cn},{parent}"));
    (new_sam, cn)
}

/// Characters that cannot appear in a name this planner writes: the union of
/// what RFC 4514 reserves in an RDN value and what AD refuses in a
/// `sAMAccountName`. One set rather than two, because a group's CN and its
/// `sAMAccountName` are the same string and the union is what both survive.
const NAME_RESERVED: &[char] =
    &[',', '+', '"', '\\', '<', '>', ';', '=', '/', '[', ']', ':', '|', '*', '?'];

/// A display name reduced to something usable as an RDN value.
///
/// These strings come from the cloud IdP, where a **group owner** -- an ordinary
/// user, not an administrator -- sets them. Unescaped, a comma in one splits the DN
/// into components the planner did not intend, and the rest of the set is
/// simply rejected by AD, which turns one hostile or careless name into a
/// permanent apply failure every cycle.
///
/// Reserved characters become spaces rather than being escaped, and that choice
/// is essential: [`parent_of`] and the post-rename CN extraction both split
/// DNs on a plain comma, and would need to become escape-aware if a `\,` could
/// ever reach them. Keeping the invariant "no name written here contains a
/// reserved character" makes those correct by construction instead.
///
/// `None` when nothing survives -- the caller has a better fallback than this
/// does, and an empty CN would build the malformed DN `CN=,OU=Entra,…`.
pub(super) fn safe_name(value: &str) -> Option<String> {
    let replaced: String = value
        .chars()
        .map(|c| if c.is_control() || NAME_RESERVED.contains(&c) { ' ' } else { c })
        .collect();
    // A leading `#` means "hex-encoded BER value" to a DN parser, so it is not a
    // name character even though nothing rejects it outright.
    let trimmed = replaced.trim().trim_start_matches('#').trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// `(CN, sAMAccountName)` for a synchronized group, the sam carrying `suffix`.
///
/// Both come from the display name, sanitized to a value both AD and the DN
/// parser accept. Computed here rather than at each of the three sites that need
/// it, because the collision pre-check compares against the name that will
/// actually be written: if those two disagreed, two groups could sanitize to one
/// name and the check that exists to catch it would not.
///
/// The suffix lands on the sam alone. A `sAMAccountName` must be unique across
/// the whole domain and is the name that reaches a resource ACL, so it is what
/// two cloud IdPs holding a same-named group collide on; a CN only has to be
/// unique inside one source's OU, which it already is, and suffixing it would
/// repeat in every RDN what the OU says once.
pub(super) fn group_names(display_name: &str, oid: &str, suffix: &str) -> (String, String) {
    // Caller guarantees the bound: `config::group_suffix` refuses a longer one at
    // startup. Past 64 the subtraction below underflows, which in release wraps
    // to a take() that truncates nothing and emits a sam AD will reject.
    debug_assert!(suffix.chars().count() <= MAX_GROUP_SUFFIX, "unvalidated suffix: {suffix:?}");
    let cn = safe_name(display_name).unwrap_or_else(|| format!("group-{}", oid4(oid)));
    // The CN is what ADUC shows and carries no length limit worth enforcing; a
    // group's sAMAccountName does, and 64 is what AD accepts in practice --
    // `kbmanage` refuses an operator's name past the same bound. The
    // suffix is spent from that budget, not added past it.
    let base: String = cn.chars().take(64 - suffix.chars().count()).collect();
    (cn, format!("{}{suffix}", base.trim_end()))
}

/// The longest `group_suffix` accepted, out of `group_names`' 64: a share
/// small enough that a group's own name keeps the larger part of the budget.
pub(crate) const MAX_GROUP_SUFFIX: usize = 20;

/// Why `suffix` cannot be a group-name suffix, or `None` if it can.
///
/// Refused rather than sanitized, unlike every other name here: an operator
/// typed this one, and it is baked into every group the source will ever create,
/// so a silently mangled suffix is discovered only by reading a name in
/// Explorer. Whitespace is out for the same reason a trailing space in a group
/// name is -- two names that render identically.
pub(crate) fn group_suffix_rejection(suffix: &str) -> Option<String> {
    if suffix.chars().count() > MAX_GROUP_SUFFIX {
        return Some(format!("longer than {MAX_GROUP_SUFFIX} characters"));
    }
    suffix
        .chars()
        .find(|c| c.is_control() || c.is_whitespace() || NAME_RESERVED.contains(c))
        .map(|c| format!("contains {c:?}, which AD or the DN parser rejects"))
}

/// `sAMAccountName`-safe, by the one rule `issuerd` also validates against.
///
/// The retirement path only. A name minted from the cloud goes through
/// `kerbridge_idp::sync::name_candidate`; this reshapes a name the directory
/// already holds.
///
/// NFC first, as that function does: Unicode spells `å` as either `U+00E5` or
/// `a` + `U+030A`, the two render identically, and a directory holding both
/// holds two accounts no human can tell apart. A name this tool wrote is
/// composed already; a hand-edited one need not be.
///
/// `maxlen` is a *character* budget; the byte ceiling is `sam::MAX_BYTES` and
/// binds independently, since 20 characters of 4-byte UTF-8 is 80 bytes. The
/// `_retired-` caller stays inside it: 11 characters cannot exceed 44 bytes,
/// leaving room for the 9-byte prefix.
pub(super) fn sanitize_sam(local: &str, maxlen: usize) -> String {
    let nfc: String = local.nfc().collect();
    sam::sanitize(&nfc, maxlen, sam::MAX_BYTES)
}

/// Deterministic `(sam, upn, cn)` with an oid-suffix fallback on collision.
///
/// The adapter says which strings are worth trying and in what order; this
/// decides which of them a name may actually be. Only the realm can: the
/// namespace is domain-wide, so `current_sam_keys` covers other sources and
/// operator-managed objects an adapter cannot see.
pub(super) fn alloc_names(
    du: &DesiredUser,
    oid: &str,
    current_sam_keys: &HashSet<String>,
    upn_suffix: &str,
) -> Result<(String, String, String), PlanError> {
    let held = |name: &str| current_sam_keys.contains(&sam::fold(name));
    // An empty candidate list is legal and means the account offered nothing
    // usable. The fallback name then stands in as its one candidate, so it is
    // tried and, where it is taken, disambiguated like any other.
    let offered: Vec<&str> = match du.name_candidates.is_empty() {
        true => vec![sam::FALLBACK],
        false => du.name_candidates.iter().map(NameCandidate::as_str).collect(),
    };
    let sam = match offered.iter().copied().find(|name| !held(name)) {
        Some(name) => name.to_owned(),
        None => {
            // Every candidate is taken, so the preferred one is disambiguated
            // rather than a later one preferred: the suffix keeps the name the
            // person would recognize.
            let short: String = offered[0].chars().take(15).collect();
            let suffixed = format!("{short}-{}", oid4(oid));
            if held(&suffixed) {
                return Err(PlanError::NameCollision(vec![format!("{suffixed:?} (user {oid})")]));
            }
            suffixed
        }
    };
    let cn = safe_name(&du.display_name).unwrap_or_else(|| sam.clone());
    Ok((sam.clone(), format!("{sam}@{upn_suffix}"), cn))
}

/// A DN inside the IdP-specific OU for `cn`, suffixed with the oid if the plain
/// form is already taken.
pub(super) fn fresh_dn(cn: &str, oid: &str, idp_ou: &str, taken: &mut HashSet<String>) -> String {
    let mut dn = format!("CN={cn},{idp_ou}");
    if taken.contains(&dn) {
        dn = format!("CN={cn} ({}),{idp_ou}", oid4(oid));
    }
    taken.insert(dn.clone());
    dn
}
