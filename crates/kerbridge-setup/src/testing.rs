//! A config set on disk, for the tests of everything that reads one.
//!
//! Written out and loaded through `Config::load` rather than assembled from
//! structs: half the values these verbs act on are *derived* -- `base_dn` from
//! the realm, an OU from the source name, the NetBIOS name from the realm's first
//! label -- and a hand-built struct would let a test assert against a derivation
//! that the parser does not actually make.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use kerbridge_core::config::Config;

/// The realm the examples ship, which is also what the example-realm gate exists
/// to catch.
pub const REALM: &str = "realm = \"EXAMPLE.SITE\"\n\
                         ldap_url = \"ldaps://kerbridge.example.site:636\"\n\
                         ldap_ca_file = \"/run/kerbridge/realm-ca.pem\"\n";

/// A deployment that named itself, for the tests that need the gate to stay
/// quiet.
pub const REALM_OF_ITS_OWN: &str = "realm = \"AD.CONTOSO.COM\"\n\
                                    ldap_url = \"ldaps://dc1.ad.contoso.com:636\"\n\
                                    ldap_ca_file = \"/etc/kerbridge/certs/realm-ca.pem\"\n";

const MAIN: &str = "sources = [\"entra\"]\n";
const BROKER: &str = "bind_dn = \"CN=svc-kerbridge-broker,CN=Users,DC=example,DC=site\"\n\
                      bind_password_file = \"/etc/kerbridge.secrets/generated/svc_kerbridge_broker_password\"\n";
const SOURCE: &str = "name = \"entra\"\n\
                      provider = \"entra\"\n\
                      group_suffix = \"-entra\"\n\
                      bind_dn = \"CN=svc-kerbridge-sync-entra,CN=Users,DC=example,DC=site\"\n\
                      bind_password_file = \"/etc/kerbridge.secrets/generated/idp/entra/bind_password\"\n";

/// A directory holding one config set, removed when it goes out of scope.
pub struct Set {
    dir: PathBuf,
}

impl Set {
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Set {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The set every test starts from: one realm, one source, defaults everywhere
/// else.
pub fn set() -> Set {
    set_with(&[])
}

/// The same, with named files replaced.
pub fn set_with(overrides: &[(&str, &str)]) -> Set {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "kbsetup-set-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    for (name, body) in [
        ("main.toml", MAIN),
        ("realm.toml", REALM),
        ("issuerd.toml", ""),
        ("broker.toml", BROKER),
        ("sync.toml", ""),
        ("idp_entra.toml", SOURCE),
    ] {
        let body = overrides
            .iter()
            .find_map(|(over, with)| (*over == name).then_some(*with))
            .unwrap_or(body);
        std::fs::write(dir.join(name), body).expect("writing the fixture");
    }
    Set { dir }
}

pub fn config() -> Config {
    let set = set();
    Config::load(set.dir()).expect("the fixture set loads")
}

/// What `testparm` answers on a realm provisioned from the set above. The values
/// are shaped the way Samba renders them, padding and case included, because
/// that is what the comparison has to survive.
pub fn provisioned(key: &str) -> String {
    match key {
        "realm" => "EXAMPLE.SITE",
        "workgroup" => "EXAMPLE",
        "netbios name" => "KERBRIDGE",
        "tls enabled" => "Yes",
        "tls keyfile" => "/var/lib/samba/private/tls/key.pem",
        "tls certfile" => "/var/lib/samba/private/tls/cert.pem",
        "tls cafile" => "/var/lib/samba/private/tls/ca.pem",
        "log level" => "1 auth_audit:3",
        other => panic!("no fixture value for the smb.conf parameter {other:?}"),
    }
    .to_owned()
}
