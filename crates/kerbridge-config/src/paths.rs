//! The loaded configuration as one flat table of dotted paths, which is the
//! whole of what `get` can answer.
//!
//! Built once and looked up, rather than a reader per key: the set a shell can
//! read is then visible in one place, and a path that is not here does not
//! resolve rather than resolving to something nobody enumerated.
//!
//! Three joins, and only the middle one is written down here. `kerbridge-core`
//! generates a path per plain field. The nine below are what is *not* a field:
//! a value read back through an accessor, where the field is the override and
//! the path is the derivation. Each source's adapter then answers for its own
//! block, in the resolved form -- `sources.<name>.issuer` is the endpoint that
//! source verifies against, whether the file states it or the adapter derived
//! it from `tenant_id`, which is the contract `realm.base_dn` already has.
//!
//! `paths.txt` beside this crate's source is the committed list of what the
//! three come to, and the ratchet on it.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use kerbridge_core::config::{Config, SourceFile};
use kerbridge_idp::{IdpSettings, Provider};

/// One path's value out of [`flatten`]'s table.
///
/// An unknown path names itself and says what the table is, because the operator
/// who reaches this is running a script someone else wrote against a config set
/// they did not lay out.
pub fn resolve<'a>(table: &'a BTreeMap<String, String>, path: &str) -> Result<&'a String> {
    match table.get(path) {
        Some(value) => Ok(value),
        // The `sources.` note only where it could be the explanation. Offered
        // for a `main.` or `realm.` typo it sends the reader looking for an
        // adapter that has nothing to do with it.
        None if path.starts_with("sources.") => bail!(
            "{path:?} is not a configuration path. A source answers for the settings its own \
             adapter reads, and only once that `[provider_config]` parses -- `kbconfig check` \
             says whether it does."
        ),
        None => bail!(
            "{path:?} is not a configuration path. `kbconfig check` prints what a set holds; \
             a value that is absent from a set this reads is absent from the table too, which \
             is what `kbmanage.*` looks like without a kbmanage.toml."
        ),
    }
}

/// Dotted path to value, an array's elements one per line.
pub fn flatten(config: &Config) -> Result<BTreeMap<String, String>> {
    let mut table =
        kerbridge_core::config::field_paths(config).map_err(|e| anyhow::anyhow!("{e}"))?;

    let realm = &config.realm;
    let mut put = |path: &str, value: String| {
        table.insert(path.to_owned(), value);
    };
    put("realm.base_dn", realm.base_dn());
    put("realm.ad_dns_domain", realm.ad_dns_domain());
    put("realm.netbios_domain", realm.netbios_domain());
    put("realm.dc_hostname", realm.dc_hostname());
    put("realm.idp_parent_ou", realm.idp_parent_ou());
    put("realm.resource_ou", realm.resource_ou());

    if let Some(kbmanage) = &config.kbmanage {
        put("kbmanage.ldap_url", kbmanage.ldap_url(realm).to_owned());
        put("kbmanage.ldap_ca_file", kbmanage.ldap_ca_file(realm).display().to_string());
    }

    let parent_ou = realm.idp_parent_ou();
    for source in &config.sources {
        let at = |field: &str| format!("sources.{}.{field}", source.name);
        put(&at("ou"), source.ou(&parent_ou));
        for (key, value) in settings(source).map(|s| s.paths()).unwrap_or_default() {
            put(&at(&key), value);
        }
    }

    Ok(table)
}

/// One source's adapter settings, or nothing where its block does not parse yet.
///
/// Tolerated rather than fatal, because `get` runs on the bootstrap path: a
/// realm is created before its cloud IdP app registration is finished, and a
/// set whose `[provider_config]` is half filled in still has to answer
/// `realm.base_dn` for the script creating the OUs. The block's own paths are
/// then absent rather than wrong, which is what [`resolve`] says, and
/// `kbconfig check` is where an unparseable block is reported properly.
fn settings(source: &SourceFile) -> Option<IdpSettings> {
    let provider = Provider::from_name(&source.provider).ok()?;
    IdpSettings::parse(provider, &source.name, &source.provider_config).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::fixture;

    /// The committed list of every path `get` answers, beside this crate's
    /// source. `get` is a promised interface -- `deploy/scripts/` reads it in
    /// fifteen places -- so extending it is a decision somebody types rather
    /// than a side effect of adding a struct field.
    const SNAPSHOT: &str = "paths.txt";

    /// What `KB_WRITE_PATH_SNAPSHOT=1` writes above the list.
    const SNAPSHOT_HEADER: &str = "\
# Every path `kbconfig get` answers, on a set copied straight from the
# templates. Generated from the config structs and each adapter's settings, and
# committed as a ratchet: `get` is a promised interface, and a field added to a
# struct must not silently extend it.
#
# Regenerate: KB_WRITE_PATH_SNAPSHOT=1 cargo test -p kerbridge-config
";

    /// What the table promises: everything it offers answers, the values core
    /// derives rather than reads are the derivations and not the empty
    /// overrides behind them, and a source's own settings are there in the form
    /// its adapter resolved them to.
    #[test]
    fn every_path_resolves_and_a_derived_one_answers_with_the_derivation() {
        let dir = fixture("flatten");
        let table = flatten(&dir.load()).unwrap();
        for path in table.keys() {
            resolve(&table, path).unwrap();
        }
        // The envelope, including what core derives rather than reads.
        assert_eq!(table["realm.base_dn"], "DC=example,DC=site");
        assert_eq!(table["realm.ad_dns_domain"], "example.site");
        assert_eq!(table["realm.netbios_domain"], "EXAMPLE");
        assert_eq!(table["realm.dc_hostname"], "kerbridge");
        assert_eq!(table["realm.idp_parent_ou"], "OU=CloudIdP,DC=example,DC=site");
        assert_eq!(table["realm.resource_ou"], "OU=Resources,DC=example,DC=site");
        assert_eq!(table["sources.entra.ou"], "OU=Entra,OU=CloudIdP,DC=example,DC=site");
        // And a nested table's keys, dotted the way the file nests them.
        assert_eq!(table["realm.provision.dns_forwarder"], "");
        assert_eq!(table["realm.provision.rpc_port_range"], "49152-49251");
        assert_eq!(table["broker.listen"], "127.0.0.1:8080");
        assert_eq!(table["main.device_grant_days"], "0");
        assert_eq!(table["main.sources"], "entra");
        // The raw `[provider_config]` reaches nothing: the adapter's resolved
        // settings are the answer, under the keys the file spells them by.
        let tenant_id = &table["sources.entra.tenant_id"];
        assert!(!tenant_id.is_empty());
        assert_eq!(
            table["sources.entra.issuer"],
            format!("https://login.microsoftonline.com/{tenant_id}/v2.0")
        );
        assert_eq!(
            table["sources.entra.admission_group_id"],
            "77778888-bbbb-9999-cccc-0000dddd1111"
        );
        assert_eq!(table["sources.entra.device_grant_group_id"], "");
        assert!(!table.keys().any(|path| path.contains("provider_config")));
    }

    /// A source states `issuer` -- a sovereign cloud, or a bench -- and the path
    /// answers with what that source verifies against rather than with the
    /// endpoint the tenant id would have derived.
    #[test]
    fn a_stated_provider_value_wins_over_the_one_the_adapter_would_derive() {
        let dir = fixture("stated-issuer");
        let path = dir.dir().join("idp_entra.toml");
        let stated = "https://login.microsoftonline.us/aaaabbbb-0000-cccc-1111-dddd2222eeee/v2.0";
        let body = std::fs::read_to_string(&path).unwrap() + &format!("issuer = \"{stated}\"\n");
        std::fs::write(&path, body).unwrap();

        let table = flatten(&dir.load()).unwrap();
        assert_eq!(table["sources.entra.issuer"], stated);
        // The authority is not stated, so it still derives: the pair is what a
        // script rebuilding either one in shell would get wrong.
        assert!(table["sources.entra.authority"].starts_with("https://login.microsoftonline.com/"));
    }

    /// The optional file, both ways: its own values, its fallback to the realm,
    /// and its absence leaving paths absent rather than empty -- which is what
    /// every container's set looks like.
    #[test]
    fn the_kbmanage_paths_appear_only_when_the_set_holds_that_file() {
        let dir = fixture("kbmanage-paths");
        let table = flatten(&dir.load()).unwrap();
        assert_eq!(
            table["kbmanage.bind_dn"],
            "CN=svc-kerbridge-manage,CN=Users,DC=example,DC=site"
        );
        assert_eq!(table["kbmanage.ldap_url"], table["realm.ldap_url"]);

        std::fs::remove_file(dir.dir().join("kbmanage.toml")).unwrap();
        let table = flatten(&dir.load()).unwrap();
        assert!(!table.contains_key("kbmanage.bind_dn"));
        let err = format!("{:#}", resolve(&table, "kbmanage.bind_dn").unwrap_err());
        assert!(err.contains("kbmanage.toml"), "{err}");
    }

    /// A block that does not parse costs its own paths and nothing else:
    /// bootstrap reads `realm.base_dn` off a set whose source file is still
    /// being filled in.
    #[test]
    fn an_unparseable_provider_block_leaves_the_envelope_answering() {
        let dir = fixture("unparseable-block");
        let path = dir.dir().join("idp_entra.toml");
        let body = std::fs::read_to_string(&path).unwrap().replace("admission_group_id = ", "#");
        std::fs::write(&path, body).unwrap();

        let table = flatten(&dir.load()).unwrap();
        assert_eq!(table["realm.base_dn"], "DC=example,DC=site");
        assert_eq!(table["sources.entra.ou"], "OU=Entra,OU=CloudIdP,DC=example,DC=site");
        let err = format!("{:#}", resolve(&table, "sources.entra.tenant_id").unwrap_err());
        assert!(err.contains("kbconfig check"), "{err}");
    }

    /// Same guarantee as the committed templates, same regeneration step.
    #[test]
    fn the_committed_path_snapshot_is_current() {
        let file = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(SNAPSHOT);
        let table = flatten(&fixture("snapshot").load()).unwrap();
        let listed: Vec<&str> = table.keys().map(String::as_str).collect();

        if std::env::var_os("KB_WRITE_PATH_SNAPSHOT").is_some() {
            let body = format!("{SNAPSHOT_HEADER}{}\n", listed.join("\n"));
            std::fs::write(&file, body).expect("writing the snapshot");
            return;
        }

        let committed = std::fs::read_to_string(&file).expect("reading the snapshot");
        let snapshot: Vec<&str> =
            committed.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
        // The one path that moved rather than two lists: the list is eighty
        // lines long, and a dump of it buries the line that changed.
        if let Some(path) = listed.iter().find(|path| !snapshot.contains(path)) {
            panic!("{path} is new to a promised interface. {REGENERATE}");
        }
        if let Some(path) = snapshot.iter().find(|path| !listed.contains(path)) {
            panic!(
                "{path} is gone from a promised interface, which a deploy script may be \
                 reading. {REGENERATE}"
            );
        }
    }

    const REGENERATE: &str = "Regenerate the snapshot to accept it: \
                              `KB_WRITE_PATH_SNAPSHOT=1 cargo test -p kerbridge-config`.";
}
