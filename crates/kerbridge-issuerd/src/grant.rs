//! Recording, removing and stamping device grants on a synchronized account.
//!
//! `issuerd` does the directory write because it already has local Samba
//! database access without LDAP credentials. The broker decides *who*; this
//! decides *what*, exactly as on the ticket path, and the broker's own LDAP
//! identity stays read-only.
//!
//! What has to be defended here is not `issuerd`'s privilege -- it is already a
//! KDC administrator -- but the **width of the verbs**. Each one names one
//! account by SID and one attribute value, and every constraint below exists to
//! keep it that narrow:
//!
//! - the object is resolved from the SID, never from a caller-supplied DN, and
//!   must sit inside the IdP parent OU;
//! - a disabled or retired account is refused;
//! - `alg` is checked against the allow-list and the thumbprint against its
//!   exact length and charset, and the stored value is *constructed* here rather
//!   than taken verbatim;
//! - the label is sanitized, because it is whatever the client said it was;
//! - grants per object are capped, and the cap refuses rather than evicting --
//!   evicting the oldest would let an attacker holding one grant push out the
//!   others;
//! - re-granting an existing thumbprint updates that value; it never duplicates.
//!
//! Every write goes out as one LDIF modify with base64 values. Base64 is not
//! decoration: the label is client data, and a value that could carry a newline
//! into an LDIF would be a second modification of the caller's choosing.

use kerbridge_core::dn::dn_is_at_or_within;
use kerbridge_core::grant::{
    DeviceGrant, GRANT_PREFIX, algorithm, is_thumbprint, needs_touch, sanitize_label,
};
use kerbridge_core::issuer::{GrantDeviceRequest, RevokeGrantRequest, TouchGrantRequest};
use kerbridge_core::state::ST_RETIRED;
use kerbridge_core::time::now_unix;

use crate::issue::{
    Account, Config, IssueError, Result, Workdir, base64, lookup, run, validated_sid,
};

/// One account and the grants it already carries.
struct Target {
    account: Account,
    /// Stored `kbkey1|` values that parse, paired with the exact bytes they were
    /// stored as -- a delete has to name the value byte for byte.
    grants: Vec<(String, DeviceGrant)>,
    /// Every `kbkey1|` value, parsable or not. The cap counts these: a value
    /// this build cannot read still occupies the object, and a hand-edited one
    /// must not become a way past the ceiling.
    stored: usize,
}

/// Resolve the account a grant verb names, and refuse everything that is not an
/// ordinary live synchronized person.
fn target(cfg: &Config, sid: &str) -> Result<Target> {
    // `lookup` already refuses a non-user, a machine account, a disabled account
    // and anything with no readable external identity. What it does not know
    // about is where the object lives or whether it is retired.
    let account = lookup(cfg, validated_sid(sid)?)?;
    // Component-wise, never `ends_with`. `CN=Bob\,OU=CloudIdP,DC=example,DC=site`
    // is one RDN sitting at the domain root, and a suffix match calls it inside
    // the OU -- see `kerbridge_core::dn`, which exists because two other copies
    // of this question disagreed the same way.
    if !dn_is_at_or_within(&account.dn, &cfg.cloud_idp_ou) {
        return Err(IssueError::new(
            "account not eligible",
            format!("{} is outside {}", account.dn, cfg.cloud_idp_ou),
        ));
    }
    // Retirement is a revocation, and one that undid itself on re-adoption would
    // not be one. Sync clears the grants when it stamps this; refusing here is
    // what stops a race from writing one back afterwards.
    if account.markers.iter().any(|m| m.starts_with(ST_RETIRED)) {
        return Err(IssueError::new("account not eligible", "account is retired"));
    }

    let stored = account.markers.iter().filter(|m| m.starts_with(GRANT_PREFIX)).count();
    let grants = account
        .markers
        .iter()
        .filter(|m| m.starts_with(GRANT_PREFIX))
        .filter_map(|m| DeviceGrant::decode(m).ok().map(|g| (m.clone(), g)))
        .collect();
    Ok(Target { account, grants, stored })
}

/// Record a grant, replacing any the same key already holds.
pub fn grant(cfg: &Config, req: &GrantDeviceRequest) -> Result<()> {
    let alg = algorithm(&req.alg).ok_or_else(|| {
        IssueError::new("bad request", format!("unknown algorithm {:?}", req.alg))
    })?;
    if !is_thumbprint(&req.thumbprint) {
        return Err(IssueError::new(
            "bad request",
            format!("thumbprint is {} bytes of the wrong shape", req.thumbprint.len()),
        ));
    }
    let start = now_unix();
    if req.expires_at <= start {
        return Err(IssueError::new(
            "bad request",
            format!("grant would expire at {}, which has passed", req.expires_at),
        ));
    }

    let t = target(cfg, &req.account_sid)?;
    let replacing: Vec<String> = t
        .grants
        .iter()
        .filter(|(_, g)| g.thumbprint == req.thumbprint)
        .map(|(raw, _)| raw.clone())
        .collect();
    // The cap bounds *new* devices. Re-granting a key the account already holds
    // takes no extra room, and refusing it at the ceiling would strand a device
    // that is already there.
    if replacing.is_empty() && t.stored >= cfg.max_grants {
        return Err(IssueError::new(
            "device grant cap reached",
            format!("{} already holds {} grants", t.account.sam_account_name, t.stored),
        ));
    }

    let value = DeviceGrant {
        label: sanitize_label(&req.label),
        alg,
        thumbprint: req.thumbprint.clone(),
        start,
        end: req.expires_at,
        // A re-grant is a fresh authorization, so the window and the last-use
        // stamp both start over rather than being carried across.
        seen: None,
    }
    .encode();
    modify(cfg, &t.account.dn, &replacing, &[value])
}

/// Remove a grant. Removing one that is not there succeeds: the caller asked for
/// it to be gone, and it is.
pub fn revoke(cfg: &Config, req: &RevokeGrantRequest) -> Result<()> {
    let t = target(cfg, &req.account_sid)?;
    let victims: Vec<String> = t
        .grants
        .iter()
        .filter(|(_, g)| g.thumbprint == req.thumbprint)
        .map(|(raw, _)| raw.clone())
        .collect();
    if victims.is_empty() {
        return Ok(());
    }
    modify(cfg, &t.account.dn, &victims, &[])
}

/// Stamp a grant's last-use day, if the schedule says to.
///
/// The schedule is re-evaluated here rather than trusted from the caller because
/// this is the side holding the stored value: the broker's copy of it is one
/// exchange old, and two devices on one account racing would otherwise write
/// twice for one day.
pub fn touch(cfg: &Config, req: &TouchGrantRequest) -> Result<()> {
    let t = target(cfg, &req.account_sid)?;
    let Some((raw, g)) = t.grants.iter().find(|(_, g)| g.thumbprint == req.thumbprint) else {
        return Ok(());
    };
    if !needs_touch(g.seen, req.seen) {
        return Ok(());
    }
    let updated = DeviceGrant { seen: Some(req.seen), ..g.clone() }.encode();
    modify(cfg, &t.account.dn, std::slice::from_ref(raw), &[updated])
}

/// Apply one `extensionName` delete-then-add against `dn`.
///
/// Both halves in a single LDIF so a replacement is one directory operation:
/// a delete that succeeded and an add that did not would leave the device
/// silently revoked.
fn modify(cfg: &Config, dn: &str, delete: &[String], add: &[String]) -> Result<()> {
    if delete.is_empty() && add.is_empty() {
        return Ok(());
    }
    let work = Workdir::create(&cfg.tmp_dir)?;
    let path = work.path.join("mod.ldif");
    std::fs::write(&path, ldif(dn, delete, add))
        .map_err(|e| IssueError::new("issuer failed", format!("writing ldif: {e}")))?;
    run(cfg, &["ldbmodify", "-H", &cfg.sam_db, path.to_str().unwrap()], &[])
        .map_err(|e| IssueError::new("issuer failed", format!("ldbmodify: {}", e.detail)))?;
    Ok(())
}

/// The change record itself, as text.
///
/// Every value goes out base64 (`attr::`), including the DN. Not decoration: the
/// label inside a grant value is client data, and a value able to carry a
/// newline into an LDIF would be a second modification of the caller's choosing.
/// Base64 removes the question rather than answering it per character.
fn ldif(dn: &str, delete: &[String], add: &[String]) -> String {
    let mut out = format!("dn:: {}\nchangetype: modify\n", base64(dn.as_bytes()));
    for (verb, values) in [("delete", delete), ("add", add)] {
        if values.is_empty() {
            continue;
        }
        out.push_str(&format!("{verb}: extensionName\n"));
        for v in values {
            out.push_str(&format!("extensionName:: {}\n", base64(v.as_bytes())));
        }
        out.push_str("-\n");
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerbridge_core::grant::ALG_ES256;

    const TP: &str = "GsNH2NUyRXY46_dTvTB1SIf7hkZ8LYlOKPT-ODdVUgo";

    fn value(label: &str) -> String {
        DeviceGrant {
            label: label.into(),
            alg: ALG_ES256,
            thumbprint: TP.into(),
            start: 1,
            end: 2,
            seen: None,
        }
        .encode()
    }

    const DN: &str = "CN=Alice,OU=Entra,DC=example,DC=site";

    /// A replacement is one change record. Two would leave a window in which the
    /// device is revoked and not yet re-granted, and a failure between them
    /// would make that window permanent.
    #[test]
    fn a_replacement_deletes_and_adds_in_one_record() {
        let text = ldif(DN, &[value("old")], &[value("new")]);
        assert_eq!(text.matches("changetype: modify").count(), 1);
        assert_eq!(text.matches("dn:: ").count(), 1);
        let verbs: Vec<&str> = text.lines().filter(|l| l.ends_with(": extensionName")).collect();
        assert_eq!(verbs, ["delete: extensionName", "add: extensionName"]);
        assert_eq!(text.matches("extensionName:: ").count(), 2);
        // A removal is the delete half alone, not a replace with nothing.
        let removal = ldif(DN, &[value("old")], &[]);
        assert!(removal.contains("delete: extensionName"));
        assert!(!removal.contains("add: extensionName"));
    }

    /// The label inside a grant is whatever the client said it was, and it
    /// reaches an LDIF. Base64 is what stops a newline in it from becoming a
    /// second modification: nothing client-chosen appears in the record as text.
    #[test]
    fn a_hostile_label_cannot_write_its_own_ldif() {
        let hostile = value("x\nreplace: userAccountControl\nuserAccountControl: 66048\n-");
        let text = ldif(DN, &[], &[hostile]);
        assert!(!text.contains("userAccountControl"), "{text}");
        assert_eq!(text.matches("changetype").count(), 1);
        assert_eq!(text.lines().filter(|l| l.starts_with("extensionName")).count(), 1);
        // And the DN itself, which is directory-derived but still interpolated.
        assert!(!ldif("CN=a\nchangetype: delete", &[], &[value("x")]).contains("delete"));
    }
}
