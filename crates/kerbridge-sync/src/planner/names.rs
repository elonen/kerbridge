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
use unicode_normalization::UnicodeNormalization;

use super::{DesiredUser, PlanError, SamSource};

/// First four characters of an object id -- the collision-disambiguation suffix.
///
/// By character, not by byte. An object id is remote input: Graph returns GUIDs
/// here and a GUID is ASCII, but nothing on the path *enforces* that, and a byte
/// slice through the middle of a codepoint is a panic rather than a bad name. This
/// runs while planning a retirement, so the panic would take down the cycle that
/// was trying to tidy up.
pub(super) fn oid4(oid: &str) -> String {
    oid.chars().take(4).collect()
}

/// `(sAMAccountName, CN)` for an object being retired: the live name is released
/// for a returning Entra object, this one keeps a recognizable, obviously-retired
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
/// These strings come from Entra, where a **group owner** -- an ordinary user,
/// not an administrator -- sets them. Unescaped, a comma in one splits the DN
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
/// NFC first, and this is the only place it happens: Unicode spells `å` as
/// either `U+00E5` or `a` + `U+030A`, the two render identically, and deriving
/// both would put two accounts in the directory that no human can tell apart.
/// Normalizing here means the directory only ever holds the composed form --
/// `issuerd` refuses the decomposed one rather than treating it as a second
/// principal. sync owns this because `kerbridge-core` may not carry the Unicode
/// tables it needs: `issuerd` links that crate and holds KDC authority.
///
/// `maxlen` is a *character* budget; the byte ceiling is `sam::MAX_BYTES` and
/// binds independently, since 20 characters of 4-byte UTF-8 is 80 bytes. The
/// `_retired-` caller stays inside it: 11 characters cannot exceed 44 bytes,
/// leaving room for the 9-byte prefix.
pub(super) fn sanitize_sam(local: &str, maxlen: usize) -> String {
    let nfc: String = local.nfc().collect();
    sam::sanitize(&nfc, maxlen, sam::MAX_BYTES)
}

/// `"Jane Doe" -> "jane.doe"`: every whitespace-separated token of the
/// display name, joined by `.`. Empty when there is no usable token, so the
/// caller can fall back. Casing and illegal characters are `sanitize_sam`'s.
///
/// Every token rather than first-and-last. First-and-last assumes a name is
/// *given* then *family*, and that assumption
/// is wrong in both directions: it drops middle tokens everywhere, and on a
/// Spanish double surname it keeps the last token -- the maternal surname --
/// while dropping the paternal one that actually identifies the person
/// (`Gabriel García Márquez` -> `gabriel.márquez`, not `gabriel.garcía`).
/// Joining every token imposes no ordering of its own, which is the only
/// defensible reading of a display name: `山田 太郎` is family-first in the
/// source and stays family-first here.
fn dotted(display_name: &str) -> String {
    display_name.split_whitespace().collect::<Vec<_>>().join(".")
}

/// The account's mail address: `mail`, or the first of `otherMails` when it has
/// none.
///
/// An account with no mailbox in this tenant has no `mail` at all, while
/// `otherMails` still holds an address the person actually uses. A member
/// invited from another tenant is the case that reaches sync today -- the
/// mailbox is in the tenant they came from -- and a guest has the same shape.
///
/// Without the second half, `email_username` would silently fall through to the
/// UPN for precisely those accounts, and theirs is the UPN that carries a
/// domain in its local part.
fn email_address(du: &DesiredUser) -> &str {
    if du.mail.trim().is_empty() {
        du.other_mails.first().map_or("", String::as_str)
    } else {
        &du.mail
    }
}

/// The part of an address before the `@`, with Entra's `#EXT#` guest marker
/// stripped. Empty when there is nothing usable.
fn local_part(address: &str) -> &str {
    address.split('@').next().unwrap_or("").split('#').next().unwrap_or("")
}

/// Deterministic `(sam, upn, cn)` with an oid-suffix fallback on collision.
pub(super) fn alloc_names(
    du: &DesiredUser,
    oid: &str,
    current_sam_keys: &HashSet<String>,
    upn_suffix: &str,
    sam_source: SamSource,
) -> Result<(String, String, String), PlanError> {
    // Every source falls back to the others, in a fixed order, because any of
    // them can be absent on a real account: a user with no mailbox has no mail,
    // a display name is not enforced, and only the UPN is guaranteed to exist.
    let display = dotted(&du.display_name);
    let email = local_part(email_address(du));
    let upn = local_part(&du.upn);
    let order: [&str; 3] = match sam_source {
        SamSource::DisplayName => [&display, email, upn],
        // The UPN before the display name here, not after it: someone who asked
        // for an address-shaped name is better served by another address.
        SamSource::EmailUsername => [email, upn, &display],
        SamSource::Upn => [upn, &display, email],
    };
    // A source is spent only when it *sanitizes* to a name, not when it is
    // merely non-blank: a display name of `...` is three allowed characters and
    // no name, and testing the raw string would derive `sam::FALLBACK` for it
    // while a perfectly good mail address went unread. Lazy, so no source past
    // the first usable one is sanitized at all.
    let base = order
        .into_iter()
        .map(|s| sanitize_sam(s, 20))
        .find(|s| s != sam::FALLBACK)
        .unwrap_or_else(|| sam::FALLBACK.to_owned());
    let mut sam = base.clone();
    if current_sam_keys.contains(&sam::fold(&sam)) {
        let short: String = base.chars().take(15).collect();
        sam = format!("{short}-{}", oid4(oid));
        if current_sam_keys.contains(&sam::fold(&sam)) {
            return Err(PlanError::NameCollision(vec![format!("{sam:?} (user {oid})")]));
        }
    }
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
