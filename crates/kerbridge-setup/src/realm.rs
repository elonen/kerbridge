//! `kbsetup realm` -- provision if absent, verify and refuse if present.
//!
//! This is `deploy/realm/entrypoint.sh`'s first half, the example-realm gate out
//! of `check-env.sh`, and the generation of `realm_admin_password`, in the one
//! program both deployments run. `prepare-state` leaves an empty file where the
//! value goes and this fills it. Nothing provisions at install time:
//! a broker-only host would otherwise acquire a domain it never asked for.
//!
//! **Provisioning happens only when no database exists.** When one does, the
//! configuration is checked against it and a conflict is fatal -- silently
//! reprovisioning a populated volume would destroy the domain SID, and with it
//! every SID sitting in a filesystem ACL somewhere.
//!
//! **A database is not a realm.** `samba-tool domain provision` leaves one
//! behind when it exits partway, so a finished run stamps the private directory
//! and a database without that stamp is refused rather than verified. Left
//! alone it starts: Samba reports a machine account it cannot reach, and names
//! nothing about provisioning.
//!
//! **What this owns, and what it does not.** Being a domain controller forces
//! three things on a host, and the provisioning act owns them rather than any
//! package: `/etc/samba/smb.conf`, the Samba state under `/var/lib/samba`, and
//! -- through the drop-in in [`crate::krb5`] -- the Kerberos client
//! configuration. `/etc/krb5.conf` itself is not one of them. `systemd-resolved`
//! is emphatically not one of them: its stub listener collides with Samba's
//! internal DNS, and this refuses with an actionable message rather than
//! reconfiguring it behind the operator's back.
//!
//! **No documented `samba-tool` recipe could replace this.** The provision call
//! hands `--adminpass` a throwaway and replaces it over stdin immediately,
//! because container argv is in the host's process table. An operator following
//! a guide types `--adminpass="$(cat …)"` and reintroduces exactly that leak, on
//! the one credential worth more than all the others together. The same holds
//! for the four `tls` options and `log level = 1 auth_audit:3`: every one is
//! necessary, and a guide that lists them is a guide people edit.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use kerbridge_core::config::Config;
use kerbridge_core::password::{Alphabet, generate};

use crate::secrets::{self, Reader};
use crate::{dc, krb5, run, verify};

/// Where Samba's own `smb.conf` lives. Not a dpkg conffile: `samba-common`'s
/// postinst builds it with `ucf` and registers it with `ucfr`. That registration
/// **stays with `samba-common`** -- stealing it would ambush the next person
/// debugging Samba, and refreshing ucf's hash to fake pristineness disarms a
/// warning that is telling the truth. So a pre-existing file is moved aside and
/// the provisioner writes its own, and the operator meets one interactive
/// upgrade prompt whose answer is "keep the currently-installed version".
const SMB_CONF: &str = "/etc/samba/smb.conf";
const SMB_CONF_ORIG: &str = "/etc/samba/smb.conf.kerbridge-orig";

/// The base schema `samba-tool domain provision` is told to lay down.
///
/// Not a preference: `kerbridge-sync` stamps every external identity into
/// `msDS-ExternalDirectoryObjectId`, and that attribute is stock only since the
/// Server 2016 schema. Named rather than inherited so that two hosts provisioned
/// from one config set cannot disagree about a thing baked in at provision time.
///
/// 2019 rather than 2016 because it is what the releases that can provision at
/// all already default to, so naming it changes nothing they do.
const BASE_SCHEMA: &str = "2019";

/// The marker that says the annotation below is already in the file.
const ANNOTATION_MARKER: &str = "# --- KerBridge: what may be tuned, and what may not ---";

/// The LDAPS material, beside the database it belongs to.
///
/// Derived from `issuerd.sam_db` rather than hardcoded at
/// `/var/lib/samba/private/tls`, so a deployment that moved its private
/// directory does not end up with a certificate in one place and a database in
/// another.
pub fn tls_dir(sam_db: &Path) -> PathBuf {
    sam_db.parent().unwrap_or(Path::new("/var/lib/samba/private")).join("tls")
}

pub fn run(dir: &Path, allow_example_realm: bool) -> Result<()> {
    let config = crate::load(dir)?;
    for warning in &config.warnings {
        eprintln!("[kbsetup] warning: {warning}");
    }
    let db = dc::Dc::at(&config.issuerd.sam_db);
    let provisioning = match db.state() {
        dc::State::Absent => true,
        dc::State::Provisioned => false,
        dc::State::Unfinished => bail!("{}", db.unfinished()),
    };

    // Every refusal ahead of the certificate, so a run that stops leaves the
    // host as it found it. `make_tls` has to precede `provision` -- the options
    // it passes name the key and certificate paths -- but nothing here needs it.
    if provisioning {
        refuse_old_schema()?;
        gate(&config, allow_example_realm)?;
        refuse_resolved_collision()?;
    }

    make_tls(&config)?;
    if let Some(where_to) = publish_ca(&config)? {
        println!("[kbsetup] published the realm CA to {where_to}");
    }

    if provisioning {
        provision(&config, &db)?;
    } else {
        println!(
            "[kbsetup] {} exists; checking it against the config set rather than provisioning",
            config.issuerd.sam_db.display()
        );
        let report = verify::compare(&config, dc::parameter)?;
        verify::refuse_on_mismatch(&report)?;
        report.say("durable state");
    }

    match krb5::write(&config.realm, &krb5::path())? {
        krb5::Wrote::Dropin => println!("[kbsetup] wrote {}", krb5::DROPIN),
        krb5::Wrote::Nothing => {}
        krb5::Wrote::ReadOnly => println!(
            "[kbsetup] {} is on a read-only filesystem and was left alone. Expected in the \
             realm container, whose rootfs is read-only and whose resolver is this DC's own \
             DNS, so the KDC is located through SRV records. On a host that writes its own \
             Kerberos configuration, this line means kinit will not find the KDC.",
            krb5::DROPIN
        ),
    }
    epilogue(&config);
    Ok(())
}

/// Samba's autogenerated certificate carries no `subjectAltName`, and
/// rustls-based LDAPS clients reject it outright -- so the broker could never
/// connect. Create a CA and a SAN certificate instead. Both live in the durable
/// private directory and regenerate with the realm, so nothing outside has to
/// reissue anything when the domain is rebuilt.
///
/// The SAN carries the loopback names as well as the FQDN. LDAPS is published on
/// 127.0.0.1 for host-run tooling, and rustls validates the name in the URL:
/// with the FQDN alone, every such caller needed an `/etc/hosts` line pointing
/// the DC's name at loopback, and got a bare `NotValidForName` when it was
/// missing. Naming loopback grants nothing extra -- reaching it already means
/// being on this host.
fn make_tls(config: &Config) -> Result<()> {
    let tls = tls_dir(&config.issuerd.sam_db);
    if tls.join("cert.pem").exists() {
        return Ok(());
    }
    let realm = &config.realm;
    let host = realm.dc_hostname();
    let fqdn = format!("{host}.{}", realm.ad_dns_domain());
    println!("[kbsetup] creating the LDAPS CA and SAN certificate for {fqdn} (+ loopback)");

    std::fs::create_dir_all(&tls).with_context(|| format!("creating {}", tls.display()))?;
    std::fs::set_permissions(&tls, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .with_context(|| format!("setting the mode of {}", tls.display()))?;

    let at = |name: &str| tls.join(name).display().to_string();
    run::plain(&[
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:4096",
        "-sha256",
        "-days",
        "3650",
        "-nodes",
        "-keyout",
        &at("ca-key.pem"),
        "-out",
        &at("ca.pem"),
        "-subj",
        &format!("/CN=KerBridge realm CA {}", realm.realm),
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ])?;
    run::plain(&[
        "openssl",
        "req",
        "-newkey",
        "rsa:4096",
        "-sha256",
        "-nodes",
        "-keyout",
        &at("key.pem"),
        "-out",
        &at("csr.pem"),
        "-subj",
        &format!("/CN={fqdn}"),
    ])?;

    // `openssl x509` reads extensions from a path, so the SAN goes in a file.
    let ext = tls.join("san.ext");
    std::fs::write(
        &ext,
        format!(
            "subjectAltName=DNS:{fqdn},DNS:{host},DNS:localhost,IP:127.0.0.1,IP:::1\n\
             extendedKeyUsage=serverAuth\n"
        ),
    )
    .with_context(|| format!("writing {}", ext.display()))?;
    run::plain(&[
        "openssl",
        "x509",
        "-req",
        "-in",
        &at("csr.pem"),
        "-sha256",
        "-days",
        "825",
        "-CA",
        &at("ca.pem"),
        "-CAkey",
        &at("ca-key.pem"),
        "-CAcreateserial",
        "-out",
        &at("cert.pem"),
        "-extfile",
        &ext.display().to_string(),
    ])?;

    let _ = std::fs::remove_file(tls.join("csr.pem"));
    let _ = std::fs::remove_file(&ext);
    for name in ["ca-key.pem", "ca.pem", "key.pem", "cert.pem"] {
        let file = tls.join(name);
        if file.exists() {
            std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .with_context(|| format!("setting the mode of {}", file.display()))?;
        }
    }
    Ok(())
}

/// Put the realm CA where the components that validate against it can read it,
/// if it is not there already.
///
/// The broker validates the DC's LDAPS certificate against this CA and cannot
/// read it where it is created: `0600`, root-owned, inside a `0700` directory. A
/// CA certificate is public by construction, so a copy goes to the path the
/// config set names. **The config set names it**, rather than this program:
/// `realm.ldap_ca_file` is what every consumer reads, so publishing anywhere
/// else would be a second answer.
///
/// The published copy is disposable -- this republishes it from the master --
/// which is why the master is what backups cover.
pub fn publish_ca(config: &Config) -> Result<Option<String>> {
    let to = &config.realm.ldap_ca_file;
    if to.exists() {
        return Ok(None);
    }
    let from = tls_dir(&config.issuerd.sam_db).join("ca.pem");
    if !from.exists() {
        return Ok(None);
    }
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::copy(&from, to)
        .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    std::fs::set_permissions(to, std::os::unix::fs::PermissionsExt::from_mode(0o644))
        .with_context(|| format!("setting the mode of {}", to.display()))?;
    Ok(Some(to.display().to_string()))
}

/// The values that are still the documented example, if any are.
///
/// Three keys, and only three: the gate's reason is values *a later edit cannot
/// correct*, and these are exactly the three the durable-state guard compares.
/// One list, two enforcement points. The broker's public name used to be in here
/// and is not, because it is correctable with an edit and a certificate reissue.
fn example_values(config: &Config) -> Vec<String> {
    let realm = &config.realm;
    [
        ("realm", realm.realm.clone()),
        ("netbios_domain", realm.netbios_domain()),
        ("dc_hostname", realm.dc_hostname()),
    ]
    .into_iter()
    .filter(|(_, value)| {
        let lowered = value.to_lowercase();
        lowered.contains("example.site") || lowered == "example"
    })
    .map(|(key, value)| format!("{key} = {value}"))
    .collect()
}

/// Refuse to bake the documented example realm into a database, unless told to
/// on purpose.
///
/// The realm identity the examples ship is the one group of values a later edit
/// cannot correct: this call bakes them in, and every start afterwards refuses
/// any configuration that disagrees with what was provisioned. Fixing a
/// forgotten edit means destroying the realm, its domain SID and every
/// filesystem ACL carrying it.
///
/// It fires only while there is nothing to lose -- this is reached only when no
/// database exists -- and it announces itself when it lets something through,
/// because a silent skip would leave that reasoning nowhere the next time this
/// realm is provisioned.
fn gate(config: &Config, allowed: bool) -> Result<()> {
    let found = example_values(config);
    if found.is_empty() {
        return Ok(());
    }
    if allowed {
        println!(
            "[kbsetup] --allow-example-realm: provisioning the documented example realm on \
             purpose:"
        );
        for line in &found {
            println!("[kbsetup]   {line}");
        }
        println!(
            "[kbsetup]   It is baked in by this run and unchangeable: a different realm later \
             means destroying this one, its domain SID and every filesystem ACL carrying it."
        );
        return Ok(());
    }
    bail!(
        "the config set still names the documented example realm, and nothing is provisioned \
         yet:\n  {}\nThese are baked into the Samba database by this command and cannot be \
         changed afterwards -- correcting one later destroys the domain SID and every filesystem \
         ACL holding it. SETUP.md section 1 is the decision. A development bench that means \
         example.site: pass --allow-example-realm.",
        found.join("\n  ")
    )
}

/// Refuse a `samba-tool` that cannot lay down [`BASE_SCHEMA`], while there is
/// still nothing to undo.
///
/// Samba ships the 2016 attribute definitions in
/// `/usr/share/samba/setup/ad-schema/` long before it offers them to
/// `provision`. Measured: bookworm's 4.17.12 and jammy's 4.15.13 answer
/// `invalid choice: '2019' (choose from '2008_R2', '2008_R2_old', '2012',
/// '2012_R2')`, and their `domain schemaupgrade` stops at 2012_R2 as well, so
/// there is no second route. Trixie's 4.22.10 and noble's 4.19.5 default to 2019
/// already.
///
/// The probe is the real command with `--help`: optparse validates the choice
/// before `--help` short-circuits, so it answers without writing anything.
/// Without it the refusal arrives from `kbsetup directory`, after a domain SID,
/// two OUs and two service accounts exist, as a missing attribute.
fn refuse_old_schema() -> Result<()> {
    let flag = format!("--base-schema={BASE_SCHEMA}");
    let probe = run::attempt(&["samba-tool", "domain", "provision", &flag, "--help"], None)?;
    if probe.ok() {
        return Ok(());
    }
    bail!(
        "this samba-tool cannot provision the Windows Server {BASE_SCHEMA} schema: {}\n\n\
         KerBridge stores every external identity in msDS-ExternalDirectoryObjectId, which is \
         stock since the Server 2016 schema, so a domain provisioned below it can never carry \
         one. Provision the domain controller on a release whose Samba offers the schema -- \
         Debian trixie or Ubuntu noble -- or install a newer Samba here. Nothing has been \
         written yet.",
        probe.reason()
    )
}

/// `systemd-resolved`'s stub listener holds `127.0.0.53:53` and collides with
/// Samba's internal DNS.
///
/// Detected and refused, never reconfigured: resolved is the host's, and a
/// provisioning command that rewrites another subsystem's configuration behind
/// an operator's back is worse than one that stops and says what is wrong.
fn refuse_resolved_collision() -> Result<()> {
    // 127.0.0.53:53 as /proc/net renders it: the address little-endian, the port
    // big-endian, both uppercase hex.
    const STUB: &str = "3500007F:0035";
    let listening = ["/proc/net/udp", "/proc/net/tcp"].into_iter().any(|table| {
        std::fs::read_to_string(table).is_ok_and(|text| {
            text.lines().skip(1).any(|line| line.split_whitespace().nth(1) == Some(STUB))
        })
    });
    if !listening {
        return Ok(());
    }
    bail!(
        "systemd-resolved is listening on 127.0.0.53:53, and a Samba AD domain controller runs \
         its own DNS server on :53. Provisioning would create a realm whose DNS nothing can \
         answer for. KerBridge does not reconfigure resolved for you -- that file is the host's. \
         Disable the stub listener (DNSStubListener=no in /etc/systemd/resolved.conf, then \
         restart systemd-resolved and repoint /etc/resolv.conf), or provision this DC on a host \
         that is not running it."
    )
}

/// Create the realm, and give the Administrator the password the config set
/// names.
fn provision(config: &Config, db: &dc::Dc) -> Result<()> {
    let realm = &config.realm;
    let provision = &realm.provision;
    let tls = tls_dir(&config.issuerd.sam_db);

    // Generated iff absent, and never overwritten: this is the one key in the
    // whole config set naming a file KerBridge *writes*. Empty counts as absent
    // -- see `secrets` for the measurement that makes that a rule rather than a
    // habit.
    let password = match secrets::existing(&provision.admin_password_file)? {
        Some(existing) => {
            println!(
                "[kbsetup] using the Administrator password already at {}",
                provision.admin_password_file.display()
            );
            existing
        }
        None => {
            let drawn = generate(Alphabet::Alphanumeric);
            // The daemon group, even though this file is root-only: it is the
            // first credential written, so it is what creates the secrets
            // directory the broker's is written into moments later.
            let group = secrets::daemon_group(&config.issuerd)?;
            for warning in
                secrets::write(&provision.admin_password_file, &drawn, group, Reader::RootOnly)?
            {
                eprintln!("[kbsetup] warning: {warning}");
            }
            println!(
                "[kbsetup] generated the realm Administrator password into {}",
                provision.admin_password_file.display()
            );
            drawn
        }
    };

    move_smb_conf_aside()?;

    let mut options = vec![
        "disable netbios = yes".to_owned(),
        "smb ports = 445".to_owned(),
        format!("rpc server dynamic port range = {}", provision.rpc_port_range),
        "tls enabled = yes".to_owned(),
        format!("tls keyfile = {}", tls.join("key.pem").display()),
        format!("tls certfile = {}", tls.join("cert.pem").display()),
        format!("tls cafile = {}", tls.join("ca.pem").display()),
        "log level = 1 auth_audit:3".to_owned(),
    ];
    if !provision.dns_forwarder.is_empty() {
        options.push(format!("dns forwarder = {}", provision.dns_forwarder));
    }

    // A throwaway on argv, and the real password over stdin straight afterwards.
    //
    // `provision` takes the password on argv or not at all: omitting it makes
    // samba generate one and *print* it, which trades a process-table exposure
    // for a durable one in the service's log. So it is given a value nobody will
    // ever hold, replaced before anything is listening.
    let throwaway = generate(Alphabet::Base64Url);
    let mut argv: Vec<String> = vec![
        "samba-tool".into(),
        "domain".into(),
        "provision".into(),
        format!("--realm={}", realm.realm),
        format!("--domain={}", realm.netbios_domain()),
        "--server-role=dc".into(),
        "--dns-backend=SAMBA_INTERNAL".into(),
        "--function-level=2008_R2".into(),
        format!("--base-schema={BASE_SCHEMA}"),
        format!("--host-name={}", realm.dc_hostname()),
        format!("--adminpass={throwaway}"),
    ];
    argv.extend(options.iter().map(|o| format!("--option={o}")));

    println!("[kbsetup] provisioning {} -- this takes a while", realm.realm);
    run::plain(&argv.iter().map(String::as_str).collect::<Vec<_>>())
        .map_err(unmapped_gid_hint)
        .context("samba-tool domain provision")?;

    db.set_password("Administrator", &password).map_err(|e| {
        anyhow::anyhow!(
            "{e:#}\n\nThe realm {} is provisioned and holds a throwaway password nobody has a \
             copy of. It cannot be repaired from outside: destroy the Samba state and provision \
             again.",
            realm.realm
        )
    })?;
    annotate_smb_conf()?;
    db.stamp_provisioned(&realm.realm)?;
    println!("[kbsetup] provisioned {}", realm.realm);
    Ok(())
}

/// The gid Samba's provisioner has to chown the sysvol tree to. It is what
/// Samba's own idmap allocates for `BUILTIN\Administrators`, and no `smb.conf`
/// setting moves it: `idmap config * : range` governs winbind's mappings, not
/// the ones the AD DC's `idmap.ldb` hands out.
const SYSVOL_OWNER_GID: u64 = 3_000_000;

/// Whether this process's user namespace can name `gid` at all.
///
/// An identity map, or no `gid_map` to read, answers yes -- the question only
/// has a different answer inside a container that was given a slice of the
/// host's id space. Unreadable counts as yes: this decides what a message says,
/// never what runs.
fn gid_is_mappable(gid: u64) -> bool {
    match std::fs::read_to_string("/proc/self/gid_map") {
        Ok(text) => gid_in_map(&text, gid),
        Err(_) => true,
    }
}

/// The `gid_map` half of the question, as text: one `inside outside count` row
/// per line, and a gid is nameable if some row covers it. A file with no row
/// this understands answers yes, for the same reason an unreadable one does.
fn gid_in_map(text: &str, gid: u64) -> bool {
    let mut saw_a_range = false;
    for line in text.lines() {
        let f: Vec<u64> = line.split_whitespace().filter_map(|w| w.parse().ok()).collect();
        if f.len() != 3 {
            continue;
        }
        saw_a_range = true;
        if gid >= f[0] && gid - f[0] < f[2] {
            return true;
        }
    }
    !saw_a_range
}

/// What a provisioning failure means when the host cannot own the sysvol tree.
///
/// The provisioner chowns `/var/lib/samba/sysvol` to [`SYSVOL_OWNER_GID`]. An
/// unprivileged container is typically given 65536 ids, so that chown cannot
/// succeed there -- and Samba 4.22.10 panics on the failed chown rather than
/// reporting it, which leaves an operator with a backtrace and no cause.
///
/// Measured on Debian 13 in an unprivileged Proxmox LXC: plain `samba-tool
/// domain provision`, with none of the options above, fails identically. So
/// there is nothing here to configure around, and the sentence says what has to
/// change instead of implying that something might.
fn unmapped_gid_hint(e: anyhow::Error) -> anyhow::Error {
    if gid_is_mappable(SYSVOL_OWNER_GID) {
        return e;
    }
    anyhow::anyhow!(
        "{e:#}\n\nThis host's user namespace does not include gid {SYSVOL_OWNER_GID}. Samba sets \
         the group of the sysvol tree to that gid while it provisions the realm, so the change \
         of group cannot succeed here. Samba reports that failure as a panic rather than as an \
         error. An unprivileged container cannot hold a Samba AD DC for this reason. Provision \
         the realm in a privileged container or a virtual machine instead. The KerBridge \
         configuration set has no effect on this."
    )
}

/// `samba-tool domain provision` refuses to run with an `smb.conf` present; it
/// writes its own. The existing file is moved, never removed -- it is the
/// operator's, and it is the only record of what this host was configured to do
/// before it became a domain controller.
///
/// Which is why the refusal below names `smb.conf` and not the moved-aside copy
/// as the file to clear. Only this function ever writes `.kerbridge-orig`, and
/// only from what was at `smb.conf` before any provision ran, so that file is
/// always the older and always the one to keep. A provision that panicked
/// midway leaves an `smb.conf` of Samba's own beside it. Naming the archive as
/// the file to delete would destroy exactly what the move exists to preserve.
fn move_smb_conf_aside() -> Result<()> {
    let current = Path::new(SMB_CONF);
    if !current.exists() {
        return Ok(());
    }
    if Path::new(SMB_CONF_ORIG).exists() {
        bail!(
            "both {SMB_CONF} and {SMB_CONF_ORIG} exist, so an earlier provision moved one file \
             aside and did not finish. {SMB_CONF_ORIG} is the copy this host used before kbsetup \
             ran, so keep it. {SMB_CONF} is the file that unfinished provision left. Read both, \
             then move or remove {SMB_CONF} yourself. kbsetup does not choose between them, \
             because the wrong choice destroys a file you cannot get back."
        );
    }
    std::fs::rename(current, SMB_CONF_ORIG)
        .with_context(|| format!("moving {SMB_CONF} to {SMB_CONF_ORIG}"))?;
    println!("[kbsetup] moved the existing {SMB_CONF} to {SMB_CONF_ORIG}");
    Ok(())
}

/// Say in the file itself which of its settings are not a matter of taste.
///
/// The provisioner writes a plain `smb.conf` with no indication that some of its
/// lines are required, and it is a file operators tune. Two groups, one line
/// per marked setting: permanent because the database says so, and permanent
/// because KerBridge depends on it.
fn annotate_smb_conf() -> Result<()> {
    let current = std::fs::read_to_string(SMB_CONF)
        .with_context(|| format!("reading {SMB_CONF} back after provisioning"))?;
    if current.contains(ANNOTATION_MARKER) {
        return Ok(());
    }
    let note = format!(
        "{ANNOTATION_MARKER}\n\
         # This file is a starting point to tune, except where it is marked below.\n\
         #\n\
         # Permanent because the database says so. Each was baked in by provisioning,\n\
         # and changing one means destroying the realm -- its domain SID, and every\n\
         # filesystem ACL carrying it:\n\
         #   realm         the Kerberos realm this DC serves\n\
         #   workgroup     the flat NT4 name of the domain\n\
         #   netbios name  this DC's own name\n\
         #\n\
         # Permanent because KerBridge depends on it. Each is one edit away from\n\
         # breaking a component, which then fails with its own error:\n\
         #   tls enabled, tls keyfile, tls certfile, tls cafile\n\
         #                 the LDAPS certificate the broker validates. Samba's own\n\
         #                 autogenerated certificate carries no subjectAltName, which\n\
         #                 every rustls client refuses outright.\n\
         #   log level     the auth_audit:3 class is the KDC's record of every AS\n\
         #                 exchange. `-d 1` on the command line overrides this line\n\
         #                 wholesale and produces no Auth: line at all -- measured.\n\
         #\n\
         # `kbsetup verify` compares all of these against the config set.\n\
         # ------------------------------------------------------------------\n\n\
         {current}"
    );
    std::fs::write(SMB_CONF, note).with_context(|| format!("annotating {SMB_CONF}"))?;
    Ok(())
}

/// What a package-installed DC exposes.
///
/// The Docker Compose deployment publishes a deliberate list with per-port bind
/// addresses; a distro-packaged Samba binds everything on every interface, and
/// `bind interfaces only` is per-*interface*, not per-port. So the per-port
/// addresses do not survive: LDAPS is loopback-only in Compose and
/// network-reachable here. That is safe -- the SAN certificate already covers
/// the FQDN -- but it is a difference in exposure.
///
/// No package touches the firewall, and this prints one line naming the examples
/// rather than a wall of recipe.
fn epilogue(config: &Config) {
    println!(
        "[kbsetup] this host now serves: 53 (DNS), 88 (Kerberos, tcp+udp), 135 and {} (RPC), \n\
         [kbsetup]   389 (LDAP, tcp+udp), 445 (SMB), 464 (kpasswd) and 636 (LDAPS).",
        config.realm.provision.rpc_port_range
    );
    println!(
        "[kbsetup] Nothing here configures a firewall. ufw and nftables examples are in \
         /usr/share/doc/kerbridge-issuerd/examples/."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    /// The two maps this has to tell apart, both copied from a running host: an
    /// unprivileged Proxmox LXC, which cannot name the sysvol gid, and the
    /// whole-space map a privileged container and a bare host both show.
    #[test]
    fn the_sysvol_gid_is_nameable_outside_a_sliced_id_space() {
        assert!(!gid_in_map("         0     100000      65536\n", SYSVOL_OWNER_GID));
        assert!(gid_in_map("         0          0 4294967295\n", SYSVOL_OWNER_GID));
        // A second row covering the range is enough, wherever it sits.
        assert!(gid_in_map("0 100000 65536\n3000000 200000 1000\n", SYSVOL_OWNER_GID));
        // Nothing to read is not evidence of a namespace, so it must not accuse.
        assert!(gid_in_map("", SYSVOL_OWNER_GID));
    }

    /// Derived from the database's own directory, so the certificate cannot end
    /// up beside a different `sam.ldb` than the one everything else writes to.
    #[test]
    fn the_certificate_lives_beside_the_database() {
        assert_eq!(
            tls_dir(Path::new("/var/lib/samba/private/sam.ldb")),
            Path::new("/var/lib/samba/private/tls")
        );
        assert_eq!(tls_dir(Path::new("/srv/dc/private/sam.ldb")), Path::new("/srv/dc/private/tls"));
    }

    /// The two spellings that count as the documented example: a realm carrying
    /// `example.site`, and a flat name that is the bare word. `kerbridge` is
    /// neither, so a deployment that changed only its realm is still caught by
    /// the other two rather than passing on one edit.
    #[test]
    fn the_gate_sees_the_documented_example_and_refuses_it() {
        let config = testing::config();
        assert_eq!(
            example_values(&config),
            ["realm = EXAMPLE.SITE".to_owned(), "netbios_domain = EXAMPLE".to_owned()]
        );
        assert!(gate(&config, false).is_err(), "the gate must refuse it");
        assert!(gate(&config, true).is_ok(), "and let it through when told to");
    }

    /// A real deployment passes the gate without an escape hatch.
    #[test]
    fn a_realm_of_its_own_is_not_gated() {
        let set = testing::set_with(&[("realm.toml", testing::REALM_OF_ITS_OWN)]);
        let config = Config::load(set.dir()).unwrap();
        assert!(example_values(&config).is_empty());
        assert!(gate(&config, false).is_ok());
    }

    /// The broker's public name is deliberately not one of the gated values: it
    /// is correctable with an edit and a certificate reissue, and the gate is for
    /// what a later edit cannot correct.
    #[test]
    fn the_gate_names_only_the_three_baked_in_keys() {
        let config = testing::config();
        for line in example_values(&config) {
            let key = line.split(' ').next().unwrap();
            assert!(
                ["realm", "netbios_domain", "dc_hostname"].contains(&key),
                "unexpected gated key {key}"
            );
        }
    }
}
