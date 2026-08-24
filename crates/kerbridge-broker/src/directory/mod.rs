//! Resolves an external identity to exactly one Samba AD account.
//!
//! Samba AD is the single source of truth for the external-to-realm mapping.
//! There is no parallel broker database. Everything here is read-only: the bind
//! identity is a plain account with no delegation, because a broker that could
//! write the directory could grant itself admission.
//!
//! An ordinary ticket asks three questions, and all three must be yes. Does this
//! identity resolve to exactly one object? Is that object enabled? Is it in the
//! realm-admission group? Ambiguity is a refusal, never a choice.
//!
//! A device grant asks a fourth -- is the object also in the device-grant group
//! -- and reads the grants off the same entry. That is still one request's worth
//! of reads, and still read-only: every write in the device-grant design goes
//! through `issuerd`.
//!
//! A *delegated* device grant asks the same four of the account that the grant
//! is for. It then asks separately whether whoever presented the token is in
//! that account's delegate group. Both halves are ordinary reads. Nothing here
//! gains a write.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use kerbridge_core::grant::DeviceGrant;
use kerbridge_core::state::{ROLE_ADMISSION, ROLE_DELEGATES, ROLE_DEVICE_GRANT};
use kerbridge_core::{ExternalIdentity, decode_sid_attr, escape_ldap_filter_value};
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

/// `ADS_UF_ACCOUNTDISABLE`. Measured as the immediate revocation lever: a
/// disabled account is refused at AS and TGS at once, ahead of any group
/// change.
const UF_ACCOUNTDISABLE: u32 = 0x0002;

/// `LDAP_MATCHING_RULE_IN_CHAIN`. The directory evaluates nested membership,
/// cycles included, so this process does not walk the tree itself.
const MATCHING_RULE_IN_CHAIN: &str = "1.2.840.113556.1.4.1941";

/// One source's view of the directory. Every source uses the same bind and the
/// same account search, and differs only in where it looks for its role groups.
pub struct Directory {
    url: String,
    base_dn: String,
    /// Where [`Directory::role_dn`] searches: this source's IdP-specific OU.
    /// Narrower than [`Self::base_dn`], because exactly-one-or-freeze is a claim
    /// about one source. Realm-wide, a second source's admission group would
    /// make the first one ambiguous and freeze both.
    role_base_dn: String,
    bind_dn: String,
    bind_password: String,
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
}

/// One resolved account. Not the whole directory entry, on purpose: the issuer
/// gets a SID, and nothing else needs to travel.
#[derive(Debug, PartialEq, Eq)]
pub struct Account {
    pub sid: String,
    pub sam_account_name: String,
    /// The object's own `msDS-ExternalDirectoryObjectId`, verbatim. A device
    /// must claim this value to resolve, thus the broker hands it back and does
    /// not re-encode it. A delegated grant is created against an account that
    /// the caller never presented an identity for, and a different spelling
    /// would be refused on every exchange with nothing to point at.
    pub identity: String,
    pub dn: String,
    /// The `managedObjects` back-link: every group that names this object in
    /// `managedBy`. Raw. A group is a *delegate* group only if it also carries
    /// [`ROLE_DELEGATES`], which [`Directory::is_delegate`] checks.
    pub managed_objects: Vec<String>,
    /// Every device grant on the object that this build can read. A stored value
    /// that does not parse is dropped here and never half-trusted: it can
    /// authenticate nothing, thus it is not a grant.
    pub grants: Vec<DeviceGrant>,
}

/// How a `/devices` request names the account it acts on.
///
/// A UPN is not one of these, on purpose: it is a second mutable spelling that
/// arrives as end-user input, where a login name is domain-unique and a `kb1|`
/// value needs no lookup at all. `kbmanage` keeps the wider resolution: its
/// audience is an operator, and the string never travels in an assertion.
#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    Sam(String),
    Identity(Box<ExternalIdentity>),
}

impl Target {
    /// Parse a target. `kb1|…` is a literal identity; anything else is a login
    /// name.
    ///
    /// The client reads the error, thus it names which spelling was wrong and
    /// never what the filter would have been.
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("empty target".to_owned());
        }
        if value.starts_with("kb1|") {
            return ExternalIdentity::decode(value)
                .map(|id| Self::Identity(Box::new(id)))
                .map_err(|e| format!("{value:?} is not a kb1| identity: {e}"));
        }
        if value.contains('@') {
            return Err(format!(
                "{value:?} looks like a UPN; name the account by its login name or its kb1| \
                 identity"
            ));
        }
        Ok(Self::Sam(value.to_owned()))
    }

    fn ldap_filter(&self) -> String {
        match self {
            Self::Identity(id) => id.ldap_filter(),
            // `objectClass` is constrained because everything downstream reads
            // a user. A group that resolved here would die on its missing
            // `userAccountControl`: a 500 where a refusal belongs.
            Self::Sam(sam) => {
                format!("(&(objectClass=user)(sAMAccountName={}))", escape_ldap_filter_value(sam))
            }
        }
    }
}

/// A `/devices` request that passed the authorization rule.
pub struct Authorized {
    /// The account the grant is for: admitted, and in the device-grant group.
    pub target: Account,
    /// Who asked, when that is not the target. `None` on the ordinary
    /// self-service path, where the same name twice would say nothing.
    pub delegate: Option<String>,
}

/// A refusal the caller can map to a status code without a string comparison.
#[derive(Debug)]
pub enum Denied {
    /// No object carries this identity. Not synchronized, or synchronized to a
    /// different tenant.
    NotFound,
    /// More than one object carries it. Fails closed: to pick one is to pick
    /// whose tickets an attacker gets.
    Ambiguous(usize),
    Disabled,
    NotAdmitted,
    /// Admitted to the realm, but not permitted to authorize a device. A policy
    /// answer that a new sign-in cannot change, which makes it a 403 where an
    /// expired grant is a 401.
    NotGranted,
    /// Admitted to the realm, but not in the delegate group of the account this
    /// request named. A 403 for the same reason [`Self::NotGranted`] is one.
    NotDelegate,
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "no directory object carries this identity"),
            Self::Ambiguous(n) => write!(f, "{n} directory objects carry this identity"),
            Self::Disabled => write!(f, "account is disabled"),
            Self::NotAdmitted => write!(f, "account is not in the realm-admission group"),
            Self::NotGranted => write!(f, "account is not in the device-grant group"),
            Self::NotDelegate => {
                write!(f, "caller is not in that account's delegate group")
            }
        }
    }
}

/// Either a policy refusal or an infrastructure failure. The client sees 403 and
/// 502 respectively, thus the two must not be one type.
pub enum LookupError {
    Denied(Denied),
    /// No group carries a role marker, thus no request that depends on it can be
    /// decided. Answers the client as [`Self::Unavailable`] does. It is its own
    /// variant because it is an operator's mistake and not a directory that is
    /// down: the caller notifies on it.
    ///
    /// It carries the marker so that the caller can key the notification by
    /// which group it was. A missing admission group freezes every login; a
    /// missing grant group freezes only the granted ones. One must not sit
    /// behind the other's repeat interval.
    RoleMissing {
        marker: &'static str,
        why: String,
    },
    /// Two or more groups carry one role marker. Separate from
    /// [`Self::RoleMissing`] because the way out is the opposite one -- unmark
    /// the extras, instead of create and mark a group -- and because a realm can
    /// go from one fault to the other and never pass through health.
    RoleAmbiguous {
        marker: &'static str,
        why: String,
    },
    Unavailable(anyhow::Error),
}

impl From<anyhow::Error> for LookupError {
    fn from(e: anyhow::Error) -> Self {
        Self::Unavailable(e)
    }
}

impl Directory {
    pub fn new(
        url: String,
        base_dn: String,
        role_base_dn: String,
        bind_dn: String,
        bind_password: String,
        ca_pem: Option<&std::path::Path>,
        timeout: Duration,
    ) -> Result<Self> {
        Ok(Self {
            url,
            base_dn,
            role_base_dn,
            bind_dn,
            bind_password,
            tls: kerbridge_core::tls::client_config(ca_pem)?,
            timeout,
        })
    }

    /// Arm the timeout for the next operation on `ldap`.
    ///
    /// `ldap3` consumes the deadline and does not keep it, thus it covers
    /// exactly one operation and every call site must ask. A directory can stop
    /// answering after the connect: a TCP connection that completes and then
    /// goes quiet leaves a bind or a search waiting forever, and a request that
    /// waits forever holds one of the broker's in-flight slots for just as long.
    /// Every call goes through here, and not through an inline `with_timeout`,
    /// so that a later operation cannot silently become the unbounded one.
    fn op<'a>(&self, ldap: &'a mut ldap3::Ldap) -> &'a mut ldap3::Ldap {
        ldap.with_timeout(self.timeout)
    }

    /// Open and bind one connection. One per request: the directory read takes a
    /// few milliseconds beside a ticket issuance that runs Samba, thus a pool
    /// would buy nothing and cost a class of stale-connection bug.
    async fn connect(&self) -> Result<ldap3::Ldap> {
        let settings =
            LdapConnSettings::new().set_config(self.tls.clone()).set_conn_timeout(self.timeout);
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.url)
            .await
            .with_context(|| format!("connecting to {}", self.url))?;
        ldap3::drive!(conn);
        self.op(&mut ldap)
            .simple_bind(&self.bind_dn, &self.bind_password)
            .await
            .context("binding to the directory")?
            .success()
            .with_context(|| format!("binding as {}", self.bind_dn))?;
        Ok(ldap)
    }

    /// Resolve an identity for an ordinary ticket: admission only.
    pub async fn resolve(&self, identity: &ExternalIdentity) -> Result<Account, LookupError> {
        self.lookup(identity, false).await
    }

    /// Resolve an identity for anything that a device grant touches: a ticket
    /// from one, and the routes that create, list or revoke one. Everything
    /// `resolve` checks, plus membership of the device-grant group.
    ///
    /// Every exchange re-reads that membership. That is what makes the group a
    /// revocation lever and not only an enrollment gate.
    pub async fn resolve_for_grant(
        &self,
        identity: &ExternalIdentity,
    ) -> Result<Account, LookupError> {
        self.lookup(identity, true).await
    }

    /// Resolve a `/devices` request: which account the grant is for, and whether
    /// this caller may authorize a device on it.
    ///
    /// The authorization rule, as one invariant:
    ///
    /// > The **target** resolves with the device-grant checks. The **caller**
    /// > resolves with admission alone and, when caller and target differ, must
    /// > also be in the target's delegate group.
    ///
    /// With no target the two are the same object, and this is exactly
    /// [`Self::resolve_for_grant`]. The self-service path is the general rule
    /// with both identities equal, not a second case beside it. A delegate needs
    /// no device grant of their own, but is still checked for admission: the
    /// delegate group is additional to admission, never instead of it.
    pub async fn authorize_device_request(
        &self,
        caller: &ExternalIdentity,
        target: Option<&Target>,
    ) -> Result<Authorized, LookupError> {
        let mut ldap = self.connect().await?;
        let result = self.authorize(&mut ldap, caller, target).await;
        let _ = self.op(&mut ldap).unbind().await;
        result
    }

    async fn authorize(
        &self,
        ldap: &mut ldap3::Ldap,
        caller: &ExternalIdentity,
        target: Option<&Target>,
    ) -> Result<Authorized, LookupError> {
        let Some(target) = target else {
            let target = self.find_account(ldap, &caller.ldap_filter(), true).await?;
            return Ok(Authorized { target, delegate: None });
        };
        // The caller first, on purpose: someone who is not admitted to the
        // realm learns nothing here about which accounts exist.
        let caller = self.find_account(ldap, &caller.ldap_filter(), false).await?;
        let target = self.find_account(ldap, &target.ldap_filter(), true).await?;
        // Asked before the rule is applied, and only when it can matter. The
        // self case reaches no delegate group at all.
        let delegated = !same_object(&caller, &target)
            && self.is_delegate(ldap, &caller.dn, &target.managed_objects).await?;
        verdict(caller, target, delegated).map_err(LookupError::Denied)
    }

    async fn lookup(
        &self,
        identity: &ExternalIdentity,
        need_grant_group: bool,
    ) -> Result<Account, LookupError> {
        let mut ldap = self.connect().await?;
        let account = self.find_account(&mut ldap, &identity.ldap_filter(), need_grant_group).await;
        // Best-effort: the answer is already in hand, and a failed unbind is
        // not a reason to deny a ticket. Still bounded -- this is the one place
        // that discards the result, so a hang here would be invisible.
        let _ = self.op(&mut ldap).unbind().await;
        account
    }

    async fn find_account(
        &self,
        ldap: &mut ldap3::Ldap,
        filter: &str,
        need_grant_group: bool,
    ) -> Result<Account, LookupError> {
        let (entries, _) = self
            .op(ldap)
            .search(
                &self.base_dn,
                Scope::Subtree,
                filter,
                vec![
                    "objectSid",
                    "sAMAccountName",
                    "userAccountControl",
                    "distinguishedName",
                    "extensionName",
                    "msDS-ExternalDirectoryObjectId",
                    // The `managedBy` back-link. Measured readable by the
                    // broker's own bind, which holds no privilege above the
                    // authenticated read that every account has.
                    "managedObjects",
                ],
            )
            .await
            .context("searching for the account")?
            .success()
            .context("account search was refused")?;

        if entries.is_empty() {
            return Err(LookupError::Denied(Denied::NotFound));
        }
        if entries.len() > 1 {
            return Err(LookupError::Denied(Denied::Ambiguous(entries.len())));
        }

        let entry = SearchEntry::construct(entries.into_iter().next().expect("length checked"));
        let uac: u32 = one(&entry, "userAccountControl")
            .context("account has no userAccountControl")?
            .parse()
            .context("userAccountControl is not a number")?;
        if uac & UF_ACCOUNTDISABLE != 0 {
            return Err(LookupError::Denied(Denied::Disabled));
        }

        let sid = decode_sid_attr(
            entry.bin_attrs.get("objectSid").map(|v| &v[..]),
            entry.attrs.get("objectSid").map(|v| &v[..]),
        )
        .ok_or_else(|| anyhow!("account has no readable objectSid"))?;
        let sam_account_name =
            one(&entry, "sAMAccountName").context("account has no sAMAccountName")?;
        // Reached only by a target named by login name: the identity filter
        // cannot match an object that lacks the attribute. This broker can issue
        // for no such object, whatever else it is, thus it is refused as the
        // account it is not and does not surface as a missing attribute.
        let Some(identity) =
            entry.attrs.get("msDS-ExternalDirectoryObjectId").and_then(|v| v.first())
        else {
            return Err(LookupError::Denied(Denied::NotFound));
        };

        if !self.in_role_group(ldap, &entry.dn, ROLE_ADMISSION).await? {
            return Err(LookupError::Denied(Denied::NotAdmitted));
        }
        if need_grant_group && !self.in_role_group(ldap, &entry.dn, ROLE_DEVICE_GRANT).await? {
            return Err(LookupError::Denied(Denied::NotGranted));
        }
        let grants = entry
            .attrs
            .get("extensionName")
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(|v| DeviceGrant::decode(v).ok())
            .collect();
        Ok(Account {
            sid,
            sam_account_name,
            identity: identity.clone(),
            managed_objects: entry.attrs.get("managedObjects").cloned().unwrap_or_default(),
            dn: entry.dn,
            grants,
        })
    }

    /// Is `caller_dn` inside one of the groups that the target named as its
    /// delegates?
    ///
    /// Two essential conditions: `managedBy` alone is not a
    /// delegation: it has a live conventional meaning -- who owns this group --
    /// and an admin who set it for ADUC reasons must not thereby hand every
    /// member of that group the right to authorize devices as the account it
    /// names. The group must thus also carry [`ROLE_DELEGATES`].
    ///
    /// That marker does not go through [`Self::role_dn`], on purpose. It is
    /// non-singleton -- one group per delegated account -- and that method's
    /// exactly-one-or-freeze is right for a realm-wide policy group and wrong
    /// here, where two of these is the ordinary state.
    async fn is_delegate(
        &self,
        ldap: &mut ldap3::Ldap,
        caller_dn: &str,
        managed: &[String],
    ) -> Result<bool, LookupError> {
        let marker = format!("(extensionName={})", escape_ldap_filter_value(ROLE_DELEGATES));
        let mut delegate_groups = Vec::new();
        for dn in managed {
            let (entries, _) = self
                .op(ldap)
                .search(dn, Scope::Base, &marker, vec!["1.1"])
                .await
                .context("reading a managed group")?
                .success()
                .context("managed-group read was refused")?;
            if !entries.is_empty() {
                delegate_groups.push(dn.clone());
            }
        }
        if delegate_groups.is_empty() {
            return Ok(false);
        }
        // One search, scoped to the caller, whatever the group count. A delegate
        // group that holds the whole engineering department thus never becomes a
        // large result set out here.
        let filter = format!(
            "(|{})",
            delegate_groups
                .iter()
                .map(|dn| format!(
                    "(memberOf:{MATCHING_RULE_IN_CHAIN}:={})",
                    escape_ldap_filter_value(dn)
                ))
                .collect::<String>()
        );
        let (entries, _) = self
            .op(ldap)
            .search(caller_dn, Scope::Base, &filter, vec!["1.1"])
            .await
            .context("evaluating delegate-group membership")?
            .success()
            .context("delegate-group membership search was refused")?;
        Ok(!entries.is_empty())
    }

    /// Is `user_dn` in the group that carries this role marker? The directory
    /// evaluates the membership, scoped to the one user, thus a large group
    /// never becomes a large result set here.
    async fn in_role_group(
        &self,
        ldap: &mut ldap3::Ldap,
        user_dn: &str,
        marker: &'static str,
    ) -> Result<bool, LookupError> {
        let group_dn = self.role_dn(ldap, marker).await?;
        let filter =
            format!("(memberOf:{MATCHING_RULE_IN_CHAIN}:={})", escape_ldap_filter_value(&group_dn));
        let (entries, _) = self
            .op(ldap)
            .search(user_dn, Scope::Base, &filter, vec!["1.1"])
            .await
            .context("evaluating role-group membership")?
            .success()
            .context("role-group membership search was refused")?;
        Ok(!entries.is_empty())
    }

    /// The DN of the group that carries this role marker.
    ///
    /// Found by marker and not by name: a renamed group must keep working, and a
    /// name is not an identity. Searched under [`Self::role_base_dn`], thus
    /// "exactly one" counts this source's groups.
    async fn role_dn(
        &self,
        ldap: &mut ldap3::Ldap,
        marker: &'static str,
    ) -> Result<String, LookupError> {
        let filter = format!("(extensionName={})", escape_ldap_filter_value(marker));
        let (entries, _) = self
            .op(ldap)
            .search(&self.role_base_dn, Scope::Subtree, &filter, vec!["distinguishedName"])
            .await
            .context("searching for a role group")?
            .success()
            .context("role-group search was refused")?;
        match entries.len() {
            1 => Ok(SearchEntry::construct(entries.into_iter().next().expect("length checked")).dn),
            // Both are operator errors, and both must freeze the decision
            // instead of resolving themselves: with no group nobody is in it,
            // and with two the policy is undefined. Neither clears without a
            // human, which is what makes them worth a notification.
            //
            // The message names the OU: with one broker serving several
            // sources, "no group carries it" is a different fault from "not in
            // the one you looked in", and only the message tells them apart.
            0 => Err(LookupError::RoleMissing {
                marker,
                why: format!("no group under {} carries the {marker} marker", self.role_base_dn),
            }),
            n => Err(LookupError::RoleAmbiguous {
                marker,
                why: format!("{n} groups under {} carry the {marker} marker", self.role_base_dn),
            }),
        }
    }
}

/// Are these two resolved accounts the same object? Compared by DN, because
/// different filters reached the two, and case-insensitively, because AD returns
/// a DN in whatever case the object was created with.
fn same_object(caller: &Account, target: &Account) -> bool {
    caller.dn.eq_ignore_ascii_case(&target.dn)
}

/// Apply the authorization rule, once both objects and the delegate answer are
/// in hand. Kept apart from the reads so that the caller/target matrix is a pure
/// function, and a test of it needs no directory.
///
/// A caller who names themselves is on the self path and is not a delegate, thus
/// they need no delegate group. That is what makes `--for $(whoami)` behave like
/// a plain `--grant`, instead of a demand for a group nobody would have created.
fn verdict(caller: Account, target: Account, delegated: bool) -> Result<Authorized, Denied> {
    if same_object(&caller, &target) {
        return Ok(Authorized { target, delegate: None });
    }
    if !delegated {
        return Err(Denied::NotDelegate);
    }
    Ok(Authorized { target, delegate: Some(caller.sam_account_name) })
}

fn one(entry: &SearchEntry, attr: &str) -> Result<String> {
    entry
        .attrs
        .get(attr)
        .and_then(|v| v.first())
        .cloned()
        .ok_or_else(|| anyhow!("attribute {attr} is missing"))
}

#[cfg(test)]
mod tests;
