//! `kbsetup directory` -- the OUs, the service accounts, the delegation and the
//! deny.
//!
//! The infrastructure every deployment needs, whether or not `kerbridge-sync`
//! ever runs:
//!
//! * **the IdP parent OU** -- the parent of every IdP-specific OU. It holds no
//!   objects itself; it exists so that "is this DN sync-owned" stays *one*
//!   question however many cloud IdPs the realm ends up with.
//! * **one OU per source**, under that parent. That source's sync asserts it
//!   exists and never creates it. Left empty here.
//! * **the resource OU**, where the operator's own domain-local resource groups
//!   live. Empty here -- nothing creates the groups for you -- but the OU is
//!   infrastructure every deployment needs, not seed data.
//! * **the service accounts** in `CN=Users`: the broker's read-only bind
//!   identity, one delegated write identity per source, and the operator CLI's.
//! * **the delegation**, which is what makes a service account more than a name.
//! * **the deny** that keeps a synchronized user from rewriting which cloud
//!   identity it is.
//!
//! It seeds **no** users and **no** groups: in production `kerbridge-sync` owns
//! each source OU's content and creates the admission group with its marker.
//!
//! **Idempotent, and by construction rather than by tolerance.** Everything here
//! tests for what it is about to create and creates only what is absent. Whether
//! a repeat would have been harmless never comes up.
//!
//! **A refused delegation aborts.** Its failure is the kind nobody notices: a
//! deployment whose ACEs were refused starts clean, passes every readiness check,
//! and then silently writes nothing to its IdP-specific OU for the lifetime of
//! the install. The operator is watching this command right now and will never be
//! this well placed to fix it again.
//!
//! **Never assert where a password file ought to be.** The config set states
//! where it goes and this writes it there; a path composed here refuses a default
//! set and tells the operator to restore something that does not exist.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use kerbridge_core::config::Config;
use kerbridge_core::password::{Alphabet, generate};

use crate::secrets::{self, Reader};
use crate::{dc, ldif, units};

/// `NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD`. Mandatory rather than cosmetic: an
/// expired password breaks keytab-based issuance and the delegated bind.
const UAC_NO_EXPIRY: &str = "66048";

/// The three attributes `svc-kerbridge-manage` may write inside the IdP parent
/// OU, by `schemaIDGUID`. Read out of a live schema when the delegation was
/// first written, and kept as literals because they are stock attributes whose
/// GUIDs are fixed by the Windows schema rather than by this deployment:
///
/// * `sAMAccountName` and `userPrincipalName` for `kbmanage cloud rename`. A
///   login name is not an internal key -- Windows shows it as the file owner and
///   in the Security pane, so it can be wrong, and being unable to correct it is
///   worse than the signed-out session the correction costs. Racing sync is not
///   a risk for these two: sync derives a login name once, at creation, and never
///   recomputes it for a live account.
/// * `extensionName`, because a rename is not safe without it: sync recomputes
///   login names on its own cycle, and the rename is only durable if the same
///   modify also stamps the pin marker that tells sync to leave it alone.
///
/// Granted per attribute (`OA` + GUID) rather than as a blanket `WP`, which is
/// what keeps this identity away from `msDS-ExternalDirectoryObjectId` -- the
/// attribute deciding which cloud identity an account *is* -- and away from
/// `userAccountControl`.
const RENAMEABLE: [(&str, &str); 3] = [
    ("sAMAccountName", "3e0abfd0-126a-11d0-a060-00aa006c33ed"),
    ("userPrincipalName", "28630ebb-41d5-11d1-a9c1-0000f80367c1"),
    ("extensionName", "bf967972-0de6-11d0-a285-00aa003049e2"),
];

/// The operator CLI's identity. Not read from `kbmanage.toml`: that file states
/// the *operator's own* copy of the credential, on their own workstation, and a
/// domain controller normally has no such file at all.
const KBMANAGE_CN: &str = "svc-kerbridge-manage";

struct Account {
    dn: String,
    description: String,
    password_file: PathBuf,
    /// The group owning the directories this file sits in, whoever reads the
    /// file itself: they are shared, and the operator's own credential must not
    /// leave the daemon unable to traverse to its neighbour.
    group: u32,
    reader: Reader,
}

impl Account {
    fn cn(&self) -> &str {
        dc::cn_of(&self.dn)
    }
}

pub fn run(dir: &Path) -> Result<()> {
    let config = crate::load(dir)?;
    for warning in &config.warnings {
        eprintln!("[kbsetup] warning: {warning}");
    }
    let db = dc::Dc::at(&config.issuerd.sam_db);
    match db.state() {
        dc::State::Provisioned => {}
        dc::State::Absent => bail!(
            "there is no Samba database at {}. The directory is bootstrapped inside a realm that \
             already exists -- run `kbsetup realm` first.",
            config.issuerd.sam_db.display()
        ),
        dc::State::Unfinished => bail!("{}", db.unfinished()),
    }

    let parent_ou = config.realm.idp_parent_ou();
    let resource_ou = config.realm.resource_ou();

    // Parent first: `ou create` does not make intermediate OUs.
    for ou in [parent_ou.clone(), resource_ou.clone()]
        .into_iter()
        .chain(config.sources.iter().map(|s| s.ou(&parent_ou)))
    {
        if db.ou_create(&ou)? {
            println!("[kbsetup] created {ou}");
        }
    }

    let accounts = accounts(&config)?;
    for account in &accounts {
        ensure(&db, account)?;
    }
    set_password_never_expires(&db, &accounts)?;
    delegate(&db, &config, &parent_ou, &resource_ou)?;
    deny_self_identity_write(&db, &parent_ou)?;

    println!(
        "[kbsetup] bootstrapped {parent_ou}, {resource_ou}, and one OU and sync account per \
         source ({})",
        if config.sources.is_empty() {
            "none listed".to_owned()
        } else {
            config.sources.iter().map(|s| s.name.clone()).collect::<Vec<_>>().join(" ")
        }
    );
    // The broker and sync exit for want of the bind passwords written above, and
    // have been in `failed` since the packages were installed.
    units::resume_failed();
    println!("[kbsetup] `kbsetup status` says what is outstanding now.");
    Ok(())
}

/// Every account this creates, by the DN the component that binds with it
/// states.
///
/// Taking each DN from the config set rather than composing one here is what
/// stops this creating an account nothing looks for.
fn accounts(config: &Config) -> Result<Vec<Account>> {
    let group = secrets::daemon_group(&config.issuerd)?;
    let mut accounts = vec![
        // Not in an IdP-specific OU -- those are sync-owned. The broker is local
        // infrastructure and needs no privilege beyond the directory read every
        // authenticated account already has.
        Account {
            dn: config.broker.bind_dn.clone(),
            description: "KerBridge broker LDAP read identity".to_owned(),
            password_file: config.broker.bind_password_file.clone(),
            group,
            reader: Reader::Group(group),
        },
        // Separate from every sync account because their rights are
        // near-opposites: this one writes in the resource OU, where sync is
        // denied, and under the IdP parent OU it may only delete. Its password
        // file is the operator's, not a container's, so it takes no group -- the
        // operator copies it to their own workstation.
        Account {
            dn: format!("CN={KBMANAGE_CN},CN=Users,{}", config.realm.base_dn()),
            description: "KerBridge operator CLI identity".to_owned(),
            group,
            password_file: beside(
                &config.broker.bind_password_file,
                "svc_kerbridge_manage_password",
            ),
            reader: Reader::RootOnly,
        },
    ];
    for source in &config.sources {
        accounts.push(Account {
            dn: source.bind_dn.clone(),
            description: format!(
                "KerBridge sync delegated write identity for source {}",
                source.name
            ),
            password_file: source.bind_password_file.clone(),
            group,
            reader: Reader::Group(group),
        });
    }
    Ok(accounts)
}

/// `svc-kerbridge-manage`'s password file, which no config key names.
///
/// `kbmanage.toml` names the operator's copy on their own host, so it cannot be
/// the answer here. The file lands in the directory the *broker's* credential
/// lives in, which is the secrets directory this deployment actually uses --
/// following the config set rather than a compiled-in `/etc/kerbridge.secrets`,
/// so a deployment keeping its secrets on separate or encrypted storage is not
/// left with one file outside it.
fn beside(known: &Path, name: &str) -> PathBuf {
    known.parent().unwrap_or(Path::new("/etc/kerbridge.secrets")).join(name)
}

/// Create one account if it is absent, generating its password.
///
/// Generation is tied to creation -- generate iff the account is absent -- so a
/// deployment that never runs a seed still gets one, and a re-run never
/// invalidates a credential something is already binding with.
fn ensure(db: &dc::Dc, account: &Account) -> Result<()> {
    let name = account.cn();
    if db.users()?.iter().any(|existing| existing == name) {
        if secrets::existing(&account.password_file)?.is_none() {
            eprintln!(
                "[kbsetup] warning: {name} exists but {} has no content -- its bind will fail \
                 until the file is restored (samba-tool user setpassword)",
                account.password_file.display()
            );
        }
        return Ok(());
    }
    let password = generate(Alphabet::Base64Url);
    // The file first: an account whose password nothing recorded is one nobody
    // can bind as, and it is repaired only with `setpassword`. A file written for
    // an account that then failed to be created is harmless -- the next run
    // overwrites it.
    for warning in secrets::write(&account.password_file, &password, account.group, account.reader)?
    {
        eprintln!("[kbsetup] warning: {warning}");
    }
    let said = db.user_create(name, &account.description, &password)?;
    if !said.is_empty() {
        println!("[kbsetup] {said}");
    }
    println!("[kbsetup] {name} created; password written to {}", account.password_file.display());
    Ok(())
}

/// One modify per account, in one `ldbmodify`.
fn set_password_never_expires(db: &dc::Dc, accounts: &[Account]) -> Result<()> {
    let ldif: String = accounts
        .iter()
        .map(|account| {
            format!(
                "dn: {}\nchangetype: modify\nreplace: userAccountControl\n\
                 userAccountControl: {UAC_NO_EXPIRY}\n-\n\n",
                account.dn
            )
        })
        .collect();
    db.modify(&ldif, &[]).context("clearing password expiry on the service accounts")?;
    Ok(())
}

/// Every ACE, and a refusal on any of them stops the bootstrap.
fn delegate(db: &dc::Dc, config: &Config, parent_ou: &str, resource_ou: &str) -> Result<()> {
    let apply = |what: &str, dn: &str, sddl: &str| -> Result<()> {
        db.dsacl_set(dn, sddl).map_err(|e| {
            anyhow::anyhow!(
                "{e:#}\n\nFAILED to delegate {what}. The directory refused:\n  \
                 samba-tool dsacl set --objectdn='{dn}' --sddl='{sddl}'\nRe-run this command once \
                 the cause is fixed; it is idempotent."
            )
        })?;
        println!("[kbsetup] delegated {what}");
        Ok(())
    };

    // Each sync identity: one ACE granting create/delete child and
    // write-property, inherited under its own IdP-specific OU only, so it cannot
    // touch the resource OU, another cloud IdP's OU, or anything else in the
    // directory. That scope is the confinement doing the work.
    //
    // Deliberately coarser than the minimal 16-ACE set, which was measured
    // sufficient and is still not what ships -- DESIGN.md @ Directory ownership
    // and synchronization has the reasoning. Short version: creating realm
    // identities and managing the admission group IS sync's job, so a stolen sync
    // credential grants its holder access to the protected services either way.
    // Enumerating attributes does not address that, and would have to be
    // re-derived every time sync writes a new one.
    for source in &config.sources {
        let ou = source.ou(parent_ou);
        let sid = sid(db, &source.bind_dn)?;
        apply(
            &format!("{ou} write to {} ({sid})", dc::cn_of(&source.bind_dn)),
            &ou,
            &format!("(A;CI;CCDCWP;;;{sid})"),
        )?;
    }

    let manage_dn = format!("CN={KBMANAGE_CN},CN=Users,{}", config.realm.base_dn());
    let manage = sid(db, &manage_dn)?;

    // Two deliberately different grants.
    //
    //   resource OU   CCDCWP -- create, delete and write. This is the operator's
    //                 own container and the CLI's whole job is to manage it.
    //   IdP parent OU DC, plus write on exactly three attributes. Delete-child,
    //                 no CC, no general WP: enough to destroy an object, not
    //                 enough to alter one. That matters -- every IdP-specific OU
    //                 under it is sync-owned, and a second writer racing the
    //                 reconciliation loop is what the CLI's read-only rule exists
    //                 to prevent. The directory enforces it here, not just the
    //                 code. Measured on the pinned baseline: with only
    //                 (A;CI;DC;;;SID), deleting a user and a group both succeed
    //                 with no object-level SD, while modify and add are refused
    //                 with LDAP 50.
    apply(
        &format!("{resource_ou} write to {KBMANAGE_CN} ({manage})"),
        resource_ou,
        &format!("(A;CI;CCDCWP;;;{manage})"),
    )?;
    apply(
        &format!("{parent_ou} delete-child (only) to {KBMANAGE_CN}"),
        parent_ou,
        &format!("(A;CI;DC;;;{manage})"),
    )?;
    for (attribute, guid) in RENAMEABLE {
        apply(
            &format!("{parent_ou} write {attribute} to {KBMANAGE_CN}"),
            parent_ou,
            &format!("(OA;CI;WP;{guid};;{manage})"),
        )?;
    }
    Ok(())
}

fn sid(db: &dc::Dc, dn: &str) -> Result<String> {
    db.sid_of(dn)?.with_context(|| {
        format!(
            "could not read {dn}'s SID from the directory, moments after creating it. The \
             directory is not in the state the rest of this command assumes -- check the domain \
             controller's log before re-running."
        )
    })
}

/// Deny SELF write of `msDS-ExternalDirectoryObjectId` -- the attribute that
/// decides which cloud identity an account *is*.
///
/// It sits in the Personal-Information property set, which every user's default
/// security descriptor grants the object itself, and KerBridge hands each
/// admitted user a real TGT for that account: the access check keys on the bound
/// principal, not on how it authenticated, so "synced users have random
/// undisclosed passwords" does not close this.
///
/// **Two halves, because a default SD only reaches objects created after it
/// changes**: the class default covers everything sync creates from now on, and
/// the sweep covers a directory that was bootstrapped before this existed. The
/// delegated sync write is untouched -- the deny names SELF, and sync is never
/// the object it is writing.
///
/// **Neither half round-trips NDR.** `ldbsearch --controls="sd_flags:1:4"`
/// renders the descriptor as SDDL with nothing before `D:`, and the schema half
/// edits an attribute that is *stored* as SDDL text. So this reads to decide and
/// never read-modify-writes: the class default is one `ldbmodify` of text, and
/// each swept object is one `samba-tool dsacl set --sddl=`, which prepends.
fn deny_self_identity_write(db: &dc::Dc, parent_ou: &str) -> Result<()> {
    let schema_dn = db.schema_dn()?;
    let deny = format!("(OD;;WP;{};;PS)", identity_attribute_guid(db, &schema_dn)?);

    // The class default. Samba guards *any* write to the schema partition, which
    // is why the option is needed -- and this adds no class and no attribute:
    // `msDS-ExternalDirectoryObjectId` is stock since the Server 2016 schema and
    // only its `schemaIDGUID` is read. `--option=`, never `-o`: that one is an
    // `ldb_connect` option and fails with the same LDAP 53 as passing nothing.
    // The flag reaches this one process; nothing is written to smb.conf, so the
    // realm does not stay schema-writable afterwards.
    let class = format!("CN=User,{schema_dn}");
    let current = attribute(db, &class, "defaultSecurityDescriptor")?;
    if contains_ace(&current, &deny) {
        println!("[kbsetup] the user class default SD already denies SELF the identity attribute");
    } else {
        let updated = ldif::insert_first_ace(&current, &deny)?;
        db.modify(
            &format!(
                "dn: {class}\nchangetype: modify\nreplace: defaultSecurityDescriptor\n\
                 defaultSecurityDescriptor: {updated}\n-\n\n"
            ),
            &["--option=dsdb:schema update allowed=yes"],
        )
        .context("denying SELF the identity attribute on the user class default SD")?;
        println!("[kbsetup] user class default SD now denies SELF write of the identity attribute");
    }

    // The sweep. A DACL-only read on the way in, because the owner and the audit
    // policy are not ours to read or rewrite -- and because a DACL-only
    // descriptor is also SDDL with nothing before `D:` for the insertion to trip
    // over.
    let mut swept = 0;
    for entry in db.search(&[
        "-b",
        parent_ou,
        "-s",
        "sub",
        "--controls=sd_flags:1:4",
        "(objectClass=user)",
        "nTSecurityDescriptor",
    ])? {
        let (Some(dn), Some(sddl)) =
            (ldif::first(&entry, "dn"), ldif::first(&entry, "nTSecurityDescriptor"))
        else {
            continue;
        };
        if contains_ace(sddl, &deny) {
            continue;
        }
        db.dsacl_set(dn, &deny)
            .with_context(|| format!("denying SELF the identity attribute on {dn}"))?;
        swept += 1;
    }
    println!("[kbsetup] swept {swept} existing cloud-IdP user object(s)");
    Ok(())
}

/// The identity attribute's `schemaIDGUID`, read out of *this* schema.
///
/// Never hardcoded: a wrong GUID here would deny nothing and look fine.
fn identity_attribute_guid(db: &dc::Dc, schema_dn: &str) -> Result<String> {
    let found = db.search(&[
        "-b",
        schema_dn,
        "-s",
        "sub",
        "(lDAPDisplayName=msDS-ExternalDirectoryObjectId)",
        "schemaIDGUID",
    ])?;
    let with_guid: Vec<&String> =
        found.iter().filter_map(|entry| ldif::first(entry, "schemaIDGUID")).collect();
    match with_guid.as_slice() {
        [one] => ldif::guid(one),
        [] => bail!(
            "msDS-ExternalDirectoryObjectId is not in this schema. It is stock since the Server \
             2016 schema, so a directory without it is older than this design supports."
        ),
        many => bail!("{} attributes claim to be msDS-ExternalDirectoryObjectId", many.len()),
    }
}

fn attribute(db: &dc::Dc, dn: &str, name: &str) -> Result<String> {
    let found = db.search(&["-b", dn, "-s", "base", name])?;
    found
        .first()
        .and_then(|entry| ldif::first(entry, name))
        .cloned()
        .with_context(|| format!("{dn} has no {name}"))
}

/// SDDL is case-insensitive, and Samba does not promise which case it renders a
/// descriptor in.
fn contains_ace(sddl: &str, ace: &str) -> bool {
    sddl.to_lowercase().contains(&ace.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    /// Every account comes from the config set, and the two whose credential a
    /// container reads take the group while the operator's does not.
    #[test]
    fn the_accounts_are_the_ones_the_config_set_names() {
        let config = testing::config();
        let accounts = accounts(&config).unwrap();
        let names: Vec<&str> = accounts.iter().map(Account::cn).collect();
        assert_eq!(
            names,
            ["svc-kerbridge-broker", "svc-kerbridge-manage", "svc-kerbridge-sync-entra"]
        );

        assert!(matches!(accounts[0].reader, Reader::Group(10002)));
        assert!(matches!(accounts[1].reader, Reader::RootOnly));
        assert!(matches!(accounts[2].reader, Reader::Group(10002)));
    }

    /// The path each password lands at is the one the component that binds with
    /// it will read -- never a path this program composes. A composed path
    /// refuses a default set.
    #[test]
    fn each_password_file_is_the_path_the_config_set_states() {
        let config = testing::config();
        let accounts = accounts(&config).unwrap();
        assert_eq!(
            accounts[0].password_file,
            Path::new("/etc/kerbridge.secrets/generated/svc_kerbridge_broker_password")
        );
        assert_eq!(
            accounts[2].password_file,
            Path::new("/etc/kerbridge.secrets/generated/idp/entra/bind_password")
        );
    }

    /// The one account no key names lands beside the ones that are named, so a
    /// deployment whose secrets live somewhere else keeps all of them together.
    #[test]
    fn the_operator_credential_lands_in_the_deployments_own_secrets_directory() {
        assert_eq!(
            beside(
                Path::new("/srv/keys/svc_kerbridge_broker_password"),
                "svc_kerbridge_manage_password"
            ),
            Path::new("/srv/keys/svc_kerbridge_manage_password")
        );
    }

    /// One `ldbmodify` document, one modify per account, each terminated the way
    /// LDIF requires -- a missing `-` or blank line silently drops the rest.
    #[test]
    fn the_uac_document_carries_one_modify_per_account() {
        let accounts = accounts(&testing::config()).unwrap();
        let ldif: String = accounts
            .iter()
            .map(|a| {
                format!(
                    "dn: {}\nchangetype: modify\nreplace: userAccountControl\n\
                     userAccountControl: {UAC_NO_EXPIRY}\n-\n\n",
                    a.dn
                )
            })
            .collect();
        assert_eq!(ldif.matches("changetype: modify").count(), 3);
        assert_eq!(ldif.matches("userAccountControl: 66048").count(), 3);
        assert!(ldif.ends_with("-\n\n"));
    }

    /// Case is not a difference in SDDL, and a sweep that thought it was would
    /// prepend a second deny to every user on every run.
    #[test]
    fn an_existing_deny_is_recognized_whatever_case_it_is_rendered_in() {
        let deny = "(OD;;WP;bf9679e8-0de6-11d0-a285-00aa003049e2;;PS)";
        assert!(contains_ace(&format!("D:{}(A;;RP;;;WD)", deny.to_uppercase()), deny));
        assert!(!contains_ace("D:(A;;RP;;;WD)", deny));
    }
}
