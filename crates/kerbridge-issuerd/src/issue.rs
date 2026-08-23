//! Resolving an account and issuing its ticket.
//!
//! The sequence is the one the `samba-tgt-issuance` spike gave a GO: export the
//! account's *existing* key to a request-scoped keytab on tmpfs, `kinit -k -r`
//! with it, read the cache, and destroy the temporary material. Export does not
//! change the key or bump the kvno, so this is a read of the KDC database
//! rather than a write -- nothing about the account changes when a ticket is
//! issued.
//!
//! Every check here is deliberately independent of the broker's. The broker
//! decides who may ask; `issuerd` decides what it is willing to issue, and holds
//! the authority to issue anything at all.

use std::collections::HashMap;
use std::fs::{self, DirBuilder};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use kerbridge_core::ExternalIdentity;

use crate::ccache;
use kerbridge_core::issuer::{IssueRequest, TICKET_FORMAT, Ticket};
use kerbridge_core::time::rfc3339;

/// Output accepted from a subprocess before it is treated as runaway.
const MAX_OUTPUT: u64 = 256 * 1024;

/// A ccache larger than this is not one `kinit` wrote. Bounded because the read
/// happens as root and the result is base64'd into a response.
const MAX_CCACHE: u64 = 1024 * 1024;

/// `ACCOUNTDISABLE` in `userAccountControl`.
const UAC_ACCOUNTDISABLE: u32 = 0x0002;

/// The machine-account bits. None of these belongs to a person, and a ticket
/// for one is a machine identity on the network -- refused whatever the
/// directory says about its external identity.
const UAC_MACHINE: u32 = 0x0800 | 0x1000 | 0x2000; // interdomain/workstation/server trust

/// The environment root subprocesses get. Nothing is inherited: every program
/// run from here runs as root, and each reads environment variables that change
/// where it looks for things.
///
/// `/usr/local` is deliberately absent, and that is consequential on a host
/// rather than in a container: every program run from here -- `timeout`,
/// `samba-tool`, `ldbsearch`, `ldbmodify`, `kinit` -- comes from a distro
/// package, and `/usr/local/bin` is where an operator's hand-built copy of one
/// of them lands. Searching it first would run that copy as root against the
/// live directory, the ambient influence the `env_clear()` in `run` removes.
const SUBPROCESS_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// MIT's `kinit` under the name it carries where Heimdal is packaged beside it.
const KINIT_MIT: &str = "kinit.mit";

/// The bare name, which is MIT's on the releases that do not disambiguate.
const KINIT_ANY: &str = "kinit";

static KINIT: OnceLock<String> = OnceLock::new();

/// Which `kinit` to run, probed once against [`SUBPROCESS_PATH`].
///
/// It has to be MIT's: `ccache` parses an MIT ccache v4, and Heimdal writes a
/// different format. No single spelling says "MIT" on every release we target.
///
/// * On both targets `/usr/bin/kinit` is an `update-alternatives` link both
///   implementations register. MIT wins on priority today (30 against Heimdal's
///   23), but `update-alternatives --set kinit /usr/bin/kinit.heimdal` is a
///   thing an operator may legitimately do to their own host, and it would swap
///   the binary under us. `kinit.mit` is the unambiguous name there.
/// * The bare name is the fallback, for a host whose `krb5-user` ships a plain
///   `/usr/bin/kinit` and registers no alternative at all. No supported release
///   does that; the fallback stays in preference to a startup failure on a host
///   nobody has measured.
///
/// Measured with `krb5-user` installed, as `update-alternatives --query kinit`
/// beside `ls /usr/bin/kinit*`: `Best: /usr/bin/kinit.mit` at priority 30.
/// Heimdal's priority 23 was measured with both implementations installed.
///
/// Probed once per process, so which binary issues tickets cannot change
/// between two requests; a `kinit.mit` installed underneath a running `issuerd`
/// is picked up at its next restart.
pub fn kinit_program() -> &'static str {
    KINIT.get_or_init(|| {
        program_in_path(KINIT_MIT, SUBPROCESS_PATH).unwrap_or_else(|| KINIT_ANY.to_owned())
    })
}

/// The first executable named `program` along `path`, as an absolute path.
///
/// The same search the exec would do, done here so the answer can be logged at
/// startup and so it is made against the PATH the child actually gets rather
/// than the one `issuerd` was started with.
fn program_in_path(program: &str, path: &str) -> Option<String> {
    path.split(':').filter(|dir| !dir.is_empty()).find_map(|dir| {
        let candidate = Path::new(dir).join(program);
        let meta = fs::metadata(&candidate).ok()?;
        if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
            return None;
        }
        Some(candidate.to_str()?.to_owned())
    })
}

static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);

pub struct Config {
    pub realm: String,
    pub base_dn: String,
    /// The OU an account must be inside for anything here to issue for it or
    /// write to it.
    ///
    /// The *parent* of the IdP-specific OUs, not one of them: a ticket is a ticket
    /// whichever cloud IdP the account came from, so this boundary has no reason
    /// to care which. Keeping it source-agnostic is also what means adding a
    /// second IdP never touches the process holding KDC authority.
    pub cloud_idp_ou: String,
    pub sam_db: String,
    pub tmp_dir: PathBuf,
    pub max_lifetime: u32,
    pub max_renewable: u32,
    pub cmd_timeout: u32,
    /// Device grants one account may hold. `issuerd`'s own bound rather than a
    /// number the broker sends: what it defends against is a compromised broker
    /// looping `GrantDevice` until the object will not load.
    pub max_grants: usize,
}

/// A failure with two audiences: `client` crosses the socket, `detail` goes to
/// the log. Command output and directory contents stay on the `detail` side.
#[derive(Debug)]
pub struct IssueError {
    pub client: &'static str,
    pub detail: String,
}

impl IssueError {
    pub fn new(client: &'static str, detail: impl Into<String>) -> Self {
        Self { client, detail: detail.into() }
    }
}

pub type Result<T> = std::result::Result<T, IssueError>;

pub fn issue(cfg: &Config, req: &IssueRequest) -> Result<Ticket> {
    let sid = validated_sid(&req.account_sid)?;
    let account = lookup(cfg, sid)?;
    let principal = format!("{}@{}", account.sam_account_name, cfg.realm);

    let lifetime = req.lifetime_seconds.unwrap_or(cfg.max_lifetime).min(cfg.max_lifetime);
    let renewable =
        req.renewable_lifetime_seconds.unwrap_or(cfg.max_renewable).min(cfg.max_renewable);

    let work = Workdir::create(&cfg.tmp_dir)?;
    let keytab = work.path.join("kt");
    let cache = work.path.join("cc");

    run(
        cfg,
        &[
            "samba-tool",
            "domain",
            "exportkeytab",
            keytab.to_str().unwrap(),
            &format!("--principal={principal}"),
        ],
        &[],
    )
    .map_err(|e| IssueError::new("issuer failed", format!("exportkeytab: {}", e.detail)))?;

    // `--` ends option parsing, so the principal is a positional argument even
    // if a directory write ever gets a leading `-` past `validated_sam`. Both
    // guards are wanted: this one is structural, that one is readable.
    run(
        cfg,
        &[
            kinit_program(),
            "-k",
            "-t",
            keytab.to_str().unwrap(),
            "-l",
            &format!("{lifetime}s"),
            "-r",
            &format!("{renewable}s"),
            "--",
            &principal,
        ],
        &[("KRB5CCNAME", &format!("FILE:{}", cache.display()))],
    )
    .map_err(|e| IssueError::new("issuer failed", format!("kinit: {}", e.detail)))?;

    let bytes = read_bounded(&cache)?;
    let tgt = validate(cfg, &bytes, &principal)?;

    Ok(Ticket {
        request_id: req.request_id.clone(),
        principal,
        ticket_format: TICKET_FORMAT.into(),
        ccache_b64: base64(&bytes),
        starts_at: rfc3339(tgt.starts_at),
        expires_at: rfc3339(tgt.expires_at),
        renew_until: rfc3339(tgt.renew_until),
    })
}

/// The file `kinit` just wrote, with a ceiling. Root reading an unbounded file
/// into memory is a bad primitive to have lying around even when the writer is
/// trusted.
fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let fail = |e: std::io::Error| IssueError::new("issuer failed", format!("reading ccache: {e}"));
    let mut buf = Vec::new();
    fs::File::open(path).map_err(fail)?.take(MAX_CCACHE + 1).read_to_end(&mut buf).map_err(fail)?;
    if buf.len() as u64 > MAX_CCACHE {
        return Err(IssueError::new("issuer failed", format!("ccache exceeds {MAX_CCACHE} bytes")));
    }
    Ok(buf)
}

/// The cache must hold a TGT for exactly the account we resolved, issued by the
/// configured realm, and carrying the flags that were asked for. A cache that
/// satisfies `kinit` but names someone else is one failure this catches; a
/// non-renewable ticket handed back as renewable is the other, and the client
/// only finds out about that one when renewal silently stops working.
fn validate(cfg: &Config, bytes: &[u8], principal: &str) -> Result<ccache::Credential> {
    let creds = ccache::credentials(bytes)
        .map_err(|e| IssueError::new("issuer failed", format!("parsing ccache: {e}")))?;
    let mut tgts = creds.into_iter().filter(|c| c.is_tgt(&cfg.realm));
    let tgt = tgts
        .next()
        .ok_or_else(|| IssueError::new("issuer failed", "ccache holds no TGT for the realm"))?;
    if tgts.next().is_some() {
        return Err(IssueError::new("issuer failed", "ccache holds more than one TGT"));
    }
    if tgt.client.display() != principal {
        return Err(IssueError::new(
            "issuer failed",
            format!("ccache client is {}, expected {principal}", tgt.client.display()),
        ));
    }
    check_flags(&tgt)?;
    Ok(tgt)
}

/// `INITIAL` because this must be an AS-REP and not something derived from one;
/// `RENEWABLE` with a `renew_until` beyond expiry because the response promises
/// renewal and the helper plans around it; `INVALID` clear because a postdated
/// ticket is not usable until validated.
fn check_flags(tgt: &ccache::Credential) -> Result<()> {
    let refuse = |why: String| Err(IssueError::new("issuer failed", why));
    if tgt.flags & ccache::TKT_FLG_INITIAL == 0 {
        return refuse(format!("TGT is not initial (flags {:#010x})", tgt.flags));
    }
    if tgt.flags & ccache::TKT_FLG_INVALID != 0 {
        return refuse(format!("TGT is marked invalid (flags {:#010x})", tgt.flags));
    }
    if tgt.flags & ccache::TKT_FLG_RENEWABLE == 0 {
        return refuse(format!("TGT is not renewable (flags {:#010x})", tgt.flags));
    }
    if tgt.renew_until < tgt.expires_at {
        return refuse(format!(
            "renew_until {} is before expiry {}",
            tgt.renew_until, tgt.expires_at
        ));
    }
    Ok(())
}

/// Anchored: `S-1-` then dash-separated decimal fields, nothing else. The value
/// is interpolated into an LDAP filter, so a permissive check here is a filter
/// injection.
pub fn validated_sid(sid: &str) -> Result<&str> {
    let bad = || IssueError::new("bad request", format!("malformed SID ({} bytes)", sid.len()));
    let rest = sid.strip_prefix("S-1-").ok_or_else(bad)?;
    if sid.len() > 189 || rest.is_empty() {
        return Err(bad());
    }
    if !rest.split('-').all(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit())) {
        return Err(bad());
    }
    Ok(sid)
}

pub struct Account {
    /// Resolved from the SID here, never taken from a caller. Every directory
    /// write in this process addresses this DN and no other.
    pub dn: String,
    pub sam_account_name: String,
    /// Every `extensionName` value on the object: the state markers and the
    /// device grants, in the order the directory returned them.
    pub markers: Vec<String>,
}

pub fn lookup(cfg: &Config, sid: &str) -> Result<Account> {
    let out = run(
        cfg,
        &[
            "ldbsearch",
            "-H",
            &cfg.sam_db,
            "--scope=sub",
            "-b",
            &cfg.base_dn,
            &format!("(objectSid={sid})"),
            "sAMAccountName",
            "userAccountControl",
            "objectClass",
            "msDS-ExternalDirectoryObjectId",
            "extensionName",
        ],
        &[],
    )
    .map_err(|e| IssueError::new("issuer failed", format!("ldbsearch: {}", e.detail)))?;

    let entries = ldif_entries(&out);
    if entries.len() != 1 {
        return Err(IssueError::new(
            "unknown account",
            format!("{} directory entries matched {sid}", entries.len()),
        ));
    }
    let entry = &entries[0];

    let sam = first(entry, "sAMAccountName")
        .ok_or_else(|| IssueError::new("unknown account", "entry has no sAMAccountName"))?;
    validated_sam(sam)?;

    // A user object and nothing else. `computer` derives from `user`, so the
    // presence of `user` alone would admit machine accounts, and a machine
    // account's TGT is an identity on the network that no person owns.
    let classes = entry.get("objectClass").map(Vec::as_slice).unwrap_or_default();
    if !classes.iter().any(|c| c.eq_ignore_ascii_case("user")) {
        return Err(IssueError::new(
            "account not eligible",
            format!("object is not a user (objectClass {classes:?})"),
        ));
    }
    let extra =
        classes.iter().find(|c| !ELIGIBLE_CLASSES.contains(&c.to_ascii_lowercase().as_str()));
    if let Some(c) = extra {
        return Err(IssueError::new(
            "account not eligible",
            format!("object carries the {c} class"),
        ));
    }

    let uac: u32 =
        first(entry, "userAccountControl").and_then(|v| v.parse().ok()).ok_or_else(|| {
            IssueError::new("account not eligible", "entry has no userAccountControl")
        })?;
    if uac & UAC_ACCOUNTDISABLE != 0 {
        return Err(IssueError::new(
            "account not eligible",
            format!("account disabled (uac {uac})"),
        ));
    }
    if uac & UAC_MACHINE != 0 {
        return Err(IssueError::new(
            "account not eligible",
            format!("machine account (uac {uac})"),
        ));
    }

    // Independent of the broker's own check: refuse to issue for anything that
    // is not a synchronized object, and refuse an identity value that does not
    // decode -- a corrupt mapping is exactly the state where a ticket could go
    // to the wrong person.
    let identity = first(entry, "msDS-ExternalDirectoryObjectId").ok_or_else(|| {
        IssueError::new("account not eligible", "account carries no external identity")
    })?;
    ExternalIdentity::decode(identity).map_err(|e| {
        IssueError::new("account not eligible", format!("undecodable external identity: {e}"))
    })?;

    let dn =
        first(entry, "dn").ok_or_else(|| IssueError::new("unknown account", "entry has no dn"))?;
    Ok(Account {
        dn: dn.clone(),
        sam_account_name: sam.clone(),
        markers: entry.get("extensionName").cloned().unwrap_or_default(),
    })
}

/// The complete `objectClass` chain a synchronized person may carry. An
/// allowlist rather than a computer/MSA denylist, because the next AD class
/// that derives from `user` is one nobody here will remember to add.
const ELIGIBLE_CLASSES: [&str; 4] = ["top", "person", "organizationalperson", "user"];

/// `sAMAccountName` as it is allowed to reach a command line.
///
/// The value is directory-controlled -- whoever can write a synchronized account
/// chooses it -- and it becomes `kinit`'s principal argument. The rule itself
/// lives in `kerbridge_core::sam` because sync derives against it and this
/// validates against it: the copies here and there were once separate, and
/// disagreed, so a non-ASCII account synchronized cleanly and could never
/// obtain a ticket.
fn validated_sam(sam: &str) -> Result<&str> {
    kerbridge_core::sam::validate(sam).map_err(|why| {
        IssueError::new(
            "account not eligible",
            format!("unusable sAMAccountName ({} bytes): {why}", sam.len()),
        )
    })?;
    Ok(sam)
}

/// One entry's attributes. Multi-valued, because `objectClass` is and the
/// eligibility check reads all of it -- a map that kept only the last value
/// would decide what an object is from whichever class `ldbsearch` printed
/// last.
type Entry = HashMap<String, Vec<String>>;

/// LDIF, with continuation lines folded back in -- a long attribute such as the
/// external identity is wrapped across lines and would otherwise be truncated --
/// and `attr:: <base64>` values decoded. `ldbsearch` base64-encodes any value
/// that is not safe ASCII, so a display name with an accent in it used to make
/// the identity attribute unreadable and the login fail.
///
/// Only blocks carrying a `dn` count. A subtree search also returns referral
/// blocks (`ref:`) for the Configuration and Schema partitions, and counting
/// those made a single unambiguous match look like four.
fn ldif_entries(text: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut current = Entry::new();
    // (attribute, accumulated text, base64?)
    let mut pending: Option<(String, String, bool)> = None;

    fn flush(current: &mut Entry, p: Option<(String, String, bool)>) {
        let Some((k, v, b64)) = p else { return };
        let value = if b64 {
            // An undecodable value is dropped rather than guessed at: the
            // checks downstream all fail closed on a missing attribute.
            let Ok(raw) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &v)
            else {
                return;
            };
            String::from_utf8_lossy(&raw).into_owned()
        } else {
            v
        };
        current.entry(k).or_default().push(value);
    }

    for line in text.lines().chain(std::iter::once("")) {
        if let Some(rest) = line.strip_prefix(' ') {
            if let Some((_, v, _)) = pending.as_mut() {
                v.push_str(rest);
            }
            continue;
        }
        flush(&mut current, pending.take());

        if line.is_empty() || line.starts_with('#') {
            if line.is_empty() && current.contains_key("dn") {
                entries.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(":: ") {
            pending = Some((k.to_owned(), v.to_owned(), true));
        } else if let Some((k, v)) = line.split_once(": ") {
            pending = Some((k.to_owned(), v.to_owned(), false));
        }
    }
    entries
}

fn first<'a>(entry: &'a Entry, attr: &str) -> Option<&'a String> {
    entry.get(attr).and_then(|v| v.first())
}

/// Runs a command with a bounded wall clock and bounded output. `timeout(1)`
/// does the killing so no supervision thread is needed; exit 124 is its way of
/// saying it fired.
pub fn run(cfg: &Config, argv: &[&str], env: &[(&str, &str)]) -> Result<String> {
    let fail = |detail: String| IssueError::new("issuer failed", detail);

    let mut cmd = Command::new("timeout");
    cmd.arg(cfg.cmd_timeout.to_string())
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Nothing is inherited. These run as root, and KRB5_CONFIG, KRB5CCNAME,
        // LD_PRELOAD and PYTHONPATH all change where they look for things --
        // so the environment is built here rather than filtered.
        .env_clear()
        .env("PATH", SUBPROCESS_PATH);
    for (k, v) in env {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().map_err(|e| fail(format!("spawning {}: {e}", argv[0])))?;
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .take(MAX_OUTPUT)
        .read_to_string(&mut stdout)
        .map_err(|e| fail(format!("reading stdout: {e}")))?;
    child
        .stderr
        .take()
        .unwrap()
        .take(MAX_OUTPUT)
        .read_to_string(&mut stderr)
        .map_err(|e| fail(format!("reading stderr: {e}")))?;
    let status = child.wait().map_err(|e| fail(format!("waiting for {}: {e}", argv[0])))?;

    match status.code() {
        Some(0) => Ok(stdout),
        Some(124) => Err(fail(format!("{} timed out after {}s", argv[0], cfg.cmd_timeout))),
        code => {
            let last = stderr.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("no stderr");
            Err(fail(format!("{} exited {code:?}: {last}", argv[0])))
        }
    }
}

/// A request-scoped directory on tmpfs, removed when it goes out of scope --
/// including on the error paths, which is the point.
pub struct Workdir {
    pub path: PathBuf,
}

impl Workdir {
    pub fn create(root: &Path) -> Result<Self> {
        let unique =
            format!("req.{}.{}", std::process::id(), REQUEST_SEQ.fetch_add(1, Ordering::SeqCst));
        let path = root.join(unique);
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| IssueError::new("issuer failed", format!("creating work dir: {e}")))?;
        Ok(Self { path })
    }
}

impl Drop for Workdir {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.path) {
            eprintln!("[issuerd] WARNING: could not remove {}: {e}", self.path.display());
        }
    }
}

pub fn base64(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory holding fake programs, named per test so two can run at once.
    fn bin_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("issuerd-path-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn put(dir: &Path, name: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn subprocess_path_never_searches_usr_local() {
        // A hand-built samba-tool or kinit there would run as root against the
        // live directory.
        assert!(
            !SUBPROCESS_PATH.split(':').any(|dir| dir.starts_with("/usr/local")),
            "{SUBPROCESS_PATH} searches /usr/local"
        );
    }

    #[test]
    fn prefers_the_explicit_mit_name_where_the_host_has_it() {
        // Both targets: kinit.mit exists, so the alternatives link is not
        // consulted at all and Heimdal cannot be set in front of us.
        let dir = bin_dir("mit");
        let mit = put(&dir, KINIT_MIT, 0o755);
        put(&dir, KINIT_ANY, 0o755);
        assert_eq!(
            program_in_path(KINIT_MIT, dir.to_str().unwrap()),
            Some(mit.to_str().unwrap().to_owned())
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn falls_back_to_the_bare_name_where_it_does_not_exist() {
        // A host whose krb5-user ships /usr/bin/kinit and no alternative: the
        // bare name is the only spelling there, and it is already MIT's.
        let dir = bin_dir("bare");
        put(&dir, KINIT_ANY, 0o755);
        assert_eq!(program_in_path(KINIT_MIT, dir.to_str().unwrap()), None);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn skips_what_cannot_be_executed_and_directories_that_are_not_there() {
        let dir = bin_dir("skip");
        put(&dir, KINIT_MIT, 0o644);
        fs::create_dir(dir.join("later")).unwrap();
        let found = put(&dir.join("later"), KINIT_MIT, 0o755);
        let path = format!("{}:/no/such/dir::{}/later", dir.display(), dir.display());
        assert_eq!(program_in_path(KINIT_MIT, &path), Some(found.to_str().unwrap().to_owned()));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_probe_answers_with_one_of_the_two_spellings() {
        let resolved = kinit_program();
        assert!(
            resolved == KINIT_ANY || resolved.ends_with(&format!("/{KINIT_MIT}")),
            "resolved to {resolved}"
        );
        assert_eq!(kinit_program(), resolved, "the probe is not stable across calls");
    }

    #[test]
    fn accepts_a_real_sid() {
        assert!(validated_sid("S-1-5-21-1202390749-206116854-323321699-1103").is_ok());
    }

    #[test]
    fn rejects_filter_injection_and_junk() {
        for bad in [
            "S-1-5-21-1)(cn=*",
            "S-1-5-21-*",
            "S-1-",
            "",
            "alice",
            "s-1-5-21-1",
            "S-1-5-21--1",
            "S-1-5-21-1 ",
        ] {
            assert!(validated_sid(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn folds_wrapped_ldif_values() {
        // ldbsearch wraps long values and continues them with a leading space.
        let text = "\
# record 1
dn: CN=alice,OU=Entra,DC=example,DC=site
sAMAccountName: alice
userAccountControl: 66048
msDS-ExternalDirectoryObjectId: kb1|entra|690222be-ff1a-4d56-abd1-7e4f7
 d38e474

# returned 1 records
";
        let entries = ldif_entries(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(first(&entries[0], "sAMAccountName").unwrap(), "alice");
        let identity = first(&entries[0], "msDS-ExternalDirectoryObjectId").unwrap();
        assert!(ExternalIdentity::decode(identity).is_ok(), "unfolded to {identity}");
    }

    #[test]
    fn decodes_base64_values_and_keeps_every_class() {
        // ldbsearch switches to `attr::` for anything that is not safe ASCII.
        // Before this was handled, one accented display name made the identity
        // attribute unreadable and denied that user every login.
        let text = "\
dn: CN=alice,OU=Entra,DC=example,DC=site
sAMAccountName: alice
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
displayName:: QWxpY2Ugw4VuZ3N0csO2bQ==

";
        let e = &ldif_entries(text)[0];
        assert_eq!(e["objectClass"], ["top", "person", "organizationalPerson", "user"]);
        assert_eq!(first(e, "displayName").unwrap(), "Alice Ångström");
    }

    #[test]
    fn accepts_the_names_sync_derives() {
        for good in ["alice", "alice.anderson", "svc-kerbridge-broker", "_retired-alice", "a1"] {
            assert!(validated_sam(good).is_ok(), "rejected {good:?}");
        }
    }

    #[test]
    fn rejects_a_sam_that_kinit_would_read_as_options() {
        // The directory chooses this value; kinit parses it. Anything getopt
        // could take for a flag, or a shell for a second word, is refused
        // before it becomes an argument.
        let long = "a".repeat(65);
        for bad in ["-l", "--client", "", "alice bob", "alice;id", "alice$", "alice\nbob", &long] {
            assert!(validated_sam(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn refuses_a_ticket_that_is_not_what_was_asked_for() {
        use ccache::{Principal, TKT_FLG_INITIAL, TKT_FLG_INVALID, TKT_FLG_RENEWABLE};
        let cred = |flags, renew_until| ccache::Credential {
            client: Principal { realm: "EXAMPLE.SITE".into(), components: vec!["alice".into()] },
            server: Principal {
                realm: "EXAMPLE.SITE".into(),
                components: vec!["krbtgt".into(), "EXAMPLE.SITE".into()],
            },
            starts_at: 1000,
            expires_at: 37000,
            renew_until,
            flags,
        };
        assert!(check_flags(&cred(TKT_FLG_INITIAL | TKT_FLG_RENEWABLE, 605800)).is_ok());
        // Non-renewable: kinit succeeds, renew_till is zero, and the response
        // would have promised a renewal that never works.
        assert!(check_flags(&cred(TKT_FLG_INITIAL, 0)).is_err());
        assert!(check_flags(&cred(TKT_FLG_RENEWABLE, 605800)).is_err());
        assert!(
            check_flags(&cred(TKT_FLG_INITIAL | TKT_FLG_RENEWABLE | TKT_FLG_INVALID, 605800))
                .is_err()
        );
        assert!(check_flags(&cred(TKT_FLG_INITIAL | TKT_FLG_RENEWABLE, 36999)).is_err());
    }

    #[test]
    fn counts_multiple_entries_so_ambiguity_is_visible() {
        let text = "dn: CN=a,DC=x\nsAMAccountName: a\n\ndn: CN=b,DC=x\nsAMAccountName: b\n\n";
        assert_eq!(ldif_entries(text).len(), 2);
    }

    #[test]
    fn ignores_referral_blocks() {
        // A subtree search returns these alongside the match. Counting them
        // made one unambiguous account look like four and denied the request.
        let text = "\
# record 1
dn: CN=alice,OU=Entra,DC=example,DC=site
sAMAccountName: alice

# Referral
ref: ldap://example.site/CN=Configuration,DC=example,DC=site

# Referral
ref: ldap://example.site/CN=Schema,CN=Configuration,DC=example,DC=site

# returned 1 records
";
        let entries = ldif_entries(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(first(&entries[0], "sAMAccountName").unwrap(), "alice");
    }
}
