//! `kbsetup verify` -- does durable state still match the config set.
//!
//! One of three questions, and it must stay one of three. `kbmanage doctor`
//! answers *can this identity reach that file server*; `kbconfig check` answers
//! *is the config set internally coherent*; this answers *does the realm that
//! exists match the one the config set describes*. Three questions, three tools,
//! and a fourth checker does not grow.
//!
//! This sits on `kerbridge-issuerd.service`'s start path as an `ExecStartPre=`,
//! after `kbconfig check` -- coherence of the set before comparing it against
//! durable state, because a broken set makes this comparison meaningless. It is
//! deliberately **not** a drop-in on `samba-ad-dc.service`: that would be one
//! package modifying another's unit, and it would let a TOML typo take down a
//! domain controller. A mismatched config stops the bridge, not the DC. A DC
//! nobody bridges is a far better failure than no DC.
//!
//! **Fatal versus warning is unfixable versus fixable**, which is a rule that
//! stays true as the list grows rather than a list to memorize. `realm`,
//! `workgroup` and `netbios name` are baked into the database at provisioning:
//! a mismatch means the configuration describes a realm that does not exist, and
//! correcting it means destroying the domain SID and every filesystem ACL
//! carrying it. The TLS keys and the audit log class are one edit away, and the
//! service that needs each of them fails with its own better error.
//!
//! Exit codes mirror `kbconfig upgrade --dry-run`: **0** match, **2** mismatch,
//! **1** error. Warnings ride with 0 -- including *nothing is provisioned yet*,
//! which is one command from fixed and is a documented step of every install. A
//! provision that stopped partway is not one of those: it is exit 2, because
//! the realm it left cannot be corrected by editing anything.

use std::path::Path;

use anyhow::Result;
use kerbridge_core::config::Config;

use crate::{dc, krb5, realm};

pub const MATCHES: u8 = 0;
pub const ERROR: u8 = 1;
pub const MISMATCH: u8 = 2;

#[derive(Default)]
pub struct Report {
    /// Unfixable disagreements. Each one is exit 2.
    pub fatal: Vec<String>,
    /// Fixable ones, and anything an operator should know that is not a
    /// disagreement at all.
    pub warn: Vec<String>,
    /// What was compared and held, for the line this prints when all is well.
    pub matched: Vec<String>,
}

impl Report {
    pub fn code(&self) -> u8 {
        if self.fatal.is_empty() { MATCHES } else { MISMATCH }
    }

    pub fn say(&self, what: &str) {
        for line in &self.fatal {
            eprintln!("[kbsetup] MISMATCH: {line}");
        }
        for line in &self.warn {
            eprintln!("[kbsetup] warning: {line}");
        }
        if self.fatal.is_empty() {
            println!("[kbsetup] {what} matches the config set ({})", self.matched.join(", "));
        }
    }
}

/// The comparison itself, over a reader that answers for one `smb.conf`
/// parameter.
///
/// Taking the reader as an argument is what lets the classification be tested on
/// a host with no Samba at all: the values `testparm` would return are the only
/// input, and which side of the line each key falls on is the thing worth
/// holding to account.
pub fn compare(config: &Config, mut value: impl FnMut(&str) -> Result<String>) -> Result<Report> {
    let mut report = Report::default();
    let realm = &config.realm;
    let tls = realm::tls_dir(&config.issuerd.sam_db);

    // Compared case-insensitively, and with the whitespace `testparm` pads a
    // value with removed. None of the three is case-sensitive in AD: the NetBIOS
    // name is provisioned as the uppercase of the configured host name, and the
    // realm is uppercase by convention.
    for (key, want) in [
        ("realm", realm.realm.clone()),
        ("workgroup", realm.netbios_domain()),
        ("netbios name", realm.dc_hostname()),
    ] {
        let found = value(key)?;
        if squash(&found) == squash(&want) {
            report.matched.push(format!("{key} {found}"));
        } else {
            report.fatal.push(format!(
                "the config set says {key} = {want:?} and the provisioned database says \
                 {found:?}. Every value in this group is baked in by provisioning; none can be \
                 changed by editing configuration. Correct realm.toml, or reprovision -- which \
                 destroys the domain SID and every filesystem ACL carrying it."
            ));
        }
    }

    // Fixable from here down.
    let enabled = value("tls enabled")?;
    // `squash` upper-cases, because that is what the identity comparison needs;
    // `testparm` renders this one as "Yes".
    if !matches!(squash(&enabled).as_str(), "YES" | "TRUE") {
        report.warn.push(format!(
            "smb.conf says tls enabled = {enabled:?}. LDAPS is how the broker and kbmanage reach \
             the directory, and neither can bind without it."
        ));
    }
    for (key, want) in [
        ("tls keyfile", tls.join("key.pem")),
        ("tls certfile", tls.join("cert.pem")),
        ("tls cafile", tls.join("ca.pem")),
    ] {
        let found = value(key)?;
        if Path::new(found.trim()) != want {
            report.warn.push(format!(
                "smb.conf says {key} = {found:?}, and this deployment's own certificate is at \
                 {}. The realm CA published to {} validates the certificate at that path and no \
                 other, so an LDAPS bind will fail to verify the name it connects to.",
                want.display(),
                realm.ldap_ca_file.display()
            ));
        }
    }
    let level = value("log level")?;
    if !level.contains("auth_audit:3") {
        report.warn.push(format!(
            "smb.conf says log level = {level:?}, with no auth_audit:3 class. That class is the \
             KDC's record of every AS exchange -- without it a failed authentication leaves no \
             Auth: line anywhere, which is measured rather than assumed."
        ));
    }
    Ok(report)
}

/// The whole verb: compare, self-heal the one thing that is disposable, and
/// report.
pub fn run(dir: &Path) -> Result<u8> {
    let config = Config::load(dir)?;
    for warning in &config.warnings {
        eprintln!("[kbsetup] warning: {warning}");
    }
    let db = dc::Dc::at(&config.issuerd.sam_db);
    match db.state() {
        dc::State::Provisioned => {}
        dc::State::Absent => {
            // Fixable, so it warns and rides on 0, by this module's own rule. A
            // host between `apt install` and `kbsetup realm` has no realm yet:
            // that is a documented step, not a disagreement, and a non-zero
            // answer here holds `kerbridge-issuerd.service` down for the whole
            // of it. Starting without a realm is harmless -- issuerd opens
            // nothing but its socket, and every directory access is a
            // per-request ldbsearch.
            eprintln!(
                "[kbsetup] warning: there is no Samba database at {}. Nothing is provisioned, \
                 so there is no durable state to compare the config set against. Run `kbsetup \
                 realm`.",
                config.issuerd.sam_db.display()
            );
            return Ok(MATCHES);
        }
        dc::State::Unfinished => {
            // The other side of that rule: no edit reaches this one, and the
            // comparison below would pass -- provisioning writes smb.conf
            // before it writes the domain, so every value it reads agrees with
            // the config set while the realm is half made.
            eprintln!("[kbsetup] MISMATCH: {}", db.unfinished());
            return Ok(MISMATCH);
        }
    }

    let mut report = compare(&config, dc::parameter)?;

    // The published CA is disposable by design, and republishing it iff missing
    // is what preserves the self-heal the container entrypoint had from copying
    // it on every start: an empty certs directory on a fresh host repairs itself
    // instead of failing an LDAPS bind with a confusing error. The master stays
    // where it was created.
    match realm::publish_ca(&config) {
        Ok(Some(where_to)) => report.warn.push(format!(
            "the realm CA was missing from {where_to} and has been republished from the master \
             in {}.",
            realm::tls_dir(&config.issuerd.sam_db).display()
        )),
        Ok(None) => {}
        // Reported, never fatal, and that matters most where the self-heal
        // cannot run at all: this verb is `kerbridge-issuerd.service`'s second
        // ExecStartPre, inside a unit whose ProtectSystem=strict makes the
        // whole of /etc read-only except what ReadWritePaths names. The
        // issuer does not read this file itself, so a copy that is refused
        // there is a line for the operator. Stopping the issuer over it would
        // cost more than the missing file does.
        Err(e) => report.warn.push(format!(
            "the realm CA is missing from {}, and it could not be republished from the master \
             in {}: {e:#}. Nothing that binds over LDAPS starts until that file is there. Run \
             `kbsetup realm` to write it again, or copy it there yourself.",
            config.realm.ldap_ca_file.display(),
            realm::tls_dir(&config.issuerd.sam_db).display()
        )),
    }

    if !krb5::current_matches(&config.realm, &krb5::path()) {
        report.warn.push(format!(
            "{} is missing or does not match the config set. issuerd runs kinit with a cleared \
             environment, so /etc/krb5.conf is the only file it can read and this drop-in is the \
             only place the KDC is named explicitly. `kbsetup realm` rewrites it.",
            krb5::DROPIN
        ));
    }

    report.say("durable state");
    Ok(report.code())
}

fn squash(value: &str) -> String {
    value.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase()
}

/// Refuse to go further when durable state disagrees -- what `kbsetup realm`
/// does on a DC that is already provisioned.
pub fn refuse_on_mismatch(report: &Report) -> Result<()> {
    if report.fatal.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "the provisioned realm does not match the config set:\n  {}\nRefusing to touch it.",
        report.fatal.join("\n  ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    /// Every value as provisioned: the comparison holds and nothing is said.
    #[test]
    fn a_realm_that_matches_reports_nothing() {
        let config = testing::config();
        let report = compare(&config, |key| Ok(testing::provisioned(key))).unwrap();
        assert!(report.fatal.is_empty(), "{:?}", report.fatal);
        assert!(report.warn.is_empty(), "{:?}", report.warn);
        assert_eq!(report.code(), MATCHES);
    }

    /// The three baked-in keys are fatal, one at a time and by name.
    #[test]
    fn each_identity_key_is_fatal_on_its_own() {
        for (key, wrong) in
            [("realm", "OTHER.SITE"), ("workgroup", "OTHER"), ("netbios name", "dc9")]
        {
            let config = testing::config();
            let report = compare(&config, |asked| {
                Ok(if asked == key { wrong.to_owned() } else { testing::provisioned(asked) })
            })
            .unwrap();
            assert_eq!(report.fatal.len(), 1, "{key}: {:?}", report.fatal);
            assert_eq!(report.code(), MISMATCH, "{key}");
            assert!(report.fatal[0].contains(key), "{}", report.fatal[0]);
        }
    }

    /// Case and padding are not disagreements. `testparm` pads `netbios name`,
    /// and the NetBIOS name is provisioned as the uppercase of the configured
    /// host name.
    #[test]
    fn case_and_padding_are_not_a_mismatch() {
        let config = testing::config();
        let report = compare(&config, |key| {
            Ok(match key {
                "netbios name" => "  KERBRIDGE  ".to_owned(),
                "realm" => "example.site".to_owned(),
                other => testing::provisioned(other),
            })
        })
        .unwrap();
        assert!(report.fatal.is_empty(), "{:?}", report.fatal);
    }

    /// The fixable half warns and still exits 0 -- this runs on a daemon's start
    /// path, and a warning that stopped the unit would be a fatal check wearing
    /// a different word.
    #[test]
    fn the_fixable_keys_warn_and_ride_on_zero() {
        let config = testing::config();
        let report = compare(&config, |key| {
            Ok(match key {
                "tls enabled" => "no".to_owned(),
                "log level" => "1".to_owned(),
                "tls certfile" => "/etc/ssl/certs/other.pem".to_owned(),
                other => testing::provisioned(other),
            })
        })
        .unwrap();
        assert!(report.fatal.is_empty(), "{:?}", report.fatal);
        assert_eq!(report.warn.len(), 3, "{:?}", report.warn);
        assert_eq!(report.code(), MATCHES);
    }

    /// A host that has been configured but not yet provisioned exits 0. It is
    /// the state between `apt install` and `kbsetup realm`, and it sits on
    /// `kerbridge-issuerd.service`'s ExecStartPre=, where a non-zero answer is a
    /// restart loop for the whole of a documented step.
    #[test]
    fn nothing_provisioned_yet_is_a_warning_not_a_mismatch() {
        let set = testing::set_with(&[(
            "issuerd.toml",
            "sam_db = \"/nonexistent/kbsetup-verify-test/sam.ldb\"\n",
        )]);
        assert_eq!(run(set.dir()).unwrap(), MATCHES);
    }

    /// A provision that stopped partway is exit 2, and it never reaches the
    /// comparison -- which would pass, `smb.conf` being written before the
    /// domain is.
    #[test]
    fn a_half_provisioned_realm_is_a_mismatch() {
        let set = testing::set();
        let db = set.dir().join("sam.ldb");
        std::fs::write(&db, "half a domain").unwrap();
        std::fs::write(set.dir().join("issuerd.toml"), format!("sam_db = {db:?}\n")).unwrap();
        assert_eq!(run(set.dir()).unwrap(), MISMATCH);
    }

    /// `tls enabled` is what `testparm` prints it as, and Samba accepts both
    /// spellings of true.
    #[test]
    fn either_spelling_of_tls_enabled_is_accepted() {
        for spelling in ["Yes", "true"] {
            let config = testing::config();
            let report = compare(&config, |key| {
                Ok(if key == "tls enabled" {
                    spelling.to_owned()
                } else {
                    testing::provisioned(key)
                })
            })
            .unwrap();
            assert!(report.warn.is_empty(), "{spelling}: {:?}", report.warn);
        }
    }
}
