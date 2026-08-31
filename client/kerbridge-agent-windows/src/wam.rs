//! WAM (Windows Web Account Manager) as a token source -- the silent half of
//! sign-in, and what the "skip the browser" toggle in Settings allows.
//!
//! Windows already holds a Primary Refresh Token for the signed-in Entra account
//! (Windows Hello for Business, on an Entra-joined box). WAM will issue an access
//! token for our broker API from it, so sign-in and -- the part that matters --
//! every re-injection thereafter need no browser and no prompt.
//!
//! Measured before it was built, on a physical Entra-joined workstation
//! (research spike `windows-wam-whfb-silent-token`):
//!
//! - The token is an ordinary v2.0 user access token that the broker's locked
//!   validator accepts, and the broker issued a real TGT from it (@Q5, @Q6). No
//!   `xms_cc`, no device or CA claims -- nothing the server side must learn.
//! - Silent acquisition is promptless in steady state, survives a reboot, and a
//!   forced refresh still issues a fresh token without interaction (@Q4).
//! - The first-ever acquisition may still need one interactive WAM dialog -- in
//!   the bench tenant Conditional Access demanded MFA the PRT could not satisfy
//!   (@Q1), because the device and the app live in different tenants. That need
//!   is deliberately no longer served here: a silent failure goes to the browser
//!   instead, for the reason on [`acquire`].
//! - `ms-appx-web://microsoft.aad.brokerplugin/<client id>` must be registered as
//!   a redirect URI on the public client, or the interactive call fails with a
//!   redirect-URI mismatch (@Q2). That is a one-time portal edit, not something
//!   this code can do. Nothing here reaches it any more: the silent call is the
//!   only call, so the registration matters to the bootstrap and to nothing else.
//!
//! **Nothing here is allowed to break sign-in.** Every failure -- no provider, no
//! broker plugin, a WAM error, a machine that is not Entra-joined at all --
//! returns [`Outcome::Unavailable`], and the caller falls back to the browser
//! flow that has always been there.
//!
//! WAM hands back an access token only; the refresh token stays inside Windows.
//! That is the point -- there is no credential for this process to keep.

use std::sync::OnceLock;

use windows::Security::Authentication::Web::Core::{
    WebAuthenticationCoreManager, WebTokenRequest, WebTokenRequestPromptType,
    WebTokenRequestResult, WebTokenRequestStatus,
};
use windows::Win32::System::Com::CoIncrementMTAUsage;
use windows::core::HSTRING;

use kerbridge_client::discovery::OidcConfig;
use kerbridge_client::log;
use kerbridge_client::secret::Secret;

/// The account-provider id for Microsoft accounts and Entra ID. Constant, and
/// not the same string as the authority -- this names the *provider*, the
/// authority below names the tenant it should authenticate against.
const PROVIDER_ID: &str = "https://login.microsoft.com";

/// Ask the AAD plugin for v2.0 protocol behavior, so `scope` means what it means
/// everywhere else in this codebase and the token comes back v2.0 -- the shape the
/// broker validates. MSAL sets the same property for the same reason.
const WAM_COMPAT: (&str, &str) = ("wam_compat", "2.0");

/// Scopes that mean nothing to WAM: it is not running an OIDC flow for us and it
/// keeps the refresh token itself. Sending them risks the plugin resolving the
/// wrong resource, and dropping them leaves exactly the broker API scope.
const OIDC_SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];

pub enum Outcome {
    /// A bearer access token for the broker API, issued by Windows.
    Token(Secret),
    /// WAM cannot serve this request. The caller falls back to the browser.
    Unavailable,
}

/// Try Windows for a broker token.
///
/// Silent is the whole of the ordinary path, on sign-in as much as on
/// re-injection: a silent success is the working test for "Windows holds a
/// usable PRT", and a silent failure means its dialog would be a Workplace Join
/// prompt rather than a sign-in -- so the caller takes the browser instead. There
/// is no exception: an app cannot sign an OS account out, so there is nothing a
/// forced re-authentication here would retire.
pub fn acquire(cfg: &OidcConfig) -> Outcome {
    match try_acquire(cfg) {
        Ok(outcome) => outcome,
        // An HRESULT here is a machine that cannot do WAM at all (no broker
        // plugin, not Entra-joined, WinRT unavailable): worth one log line, then
        // the browser.
        Err(e) => {
            log::warn(&format!("WAM unavailable, falling back to the browser: {e}"));
            Outcome::Unavailable
        }
    }
}

fn try_acquire(cfg: &OidcConfig) -> windows::core::Result<Outcome> {
    let Some(scope) = broker_scope(&cfg.scopes) else {
        log::warn("WAM: the broker advertised no resource scope");
        return Ok(Outcome::Unavailable);
    };
    ensure_mta();

    let authority = wam_authority(&cfg.authority);
    log::info(&format!("WAM: asking {authority} for a token"));
    let provider = WebAuthenticationCoreManager::FindAccountProviderWithAuthorityAsync(
        &HSTRING::from(PROVIDER_ID),
        &HSTRING::from(authority),
    )?
    .get()?;

    let request = WebTokenRequest::CreateWithPromptType(
        &provider,
        &HSTRING::from(scope),
        &HSTRING::from(cfg.client_id.as_str()),
        WebTokenRequestPromptType::Default,
    )?;
    request.Properties()?.Insert(&HSTRING::from(WAM_COMPAT.0), &HSTRING::from(WAM_COMPAT.1))?;

    // Silent only: in steady state this is the whole flow, and it is what makes
    // an unattended re-injection possible. There is no interactive branch -- the
    // only caller that ever wanted one was a forced re-authentication, and an app
    // cannot sign an OS account out, so there was nothing for it to retire.
    let result = WebAuthenticationCoreManager::GetTokenSilentlyAsync(&request)?.get()?;
    match result.ResponseStatus()? {
        WebTokenRequestStatus::Success => {
            log::info("WAM: silent token acquired");
            return Ok(Outcome::Token(Secret::new(token_of(&result)?)));
        }
        // Windows has no account here it can serve unattended. Escalating to its
        // dialog would summon the Workplace Join prompt, and answering that "No,
        // this app only" leaves an account that renews silently exactly never --
        // so this is the browser's case, not one to push further into Windows.
        WebTokenRequestStatus::UserInteractionRequired | WebTokenRequestStatus::AccountSwitch => {
            log::info(&format!("WAM: no account to use silently{}", describe(&result)));
        }
        s => {
            log::warn(&format!("WAM: silent request failed ({}){}", s.0, describe(&result)));
        }
    }
    Ok(Outcome::Unavailable)
}

/// The first response carries the token; the rest, if any, are for other
/// accounts we did not ask about.
fn token_of(result: &WebTokenRequestResult) -> windows::core::Result<String> {
    Ok(result.ResponseData()?.GetAt(0)?.Token()?.to_string())
}

/// The provider's error, for the log. Best effort -- a result that failed early
/// may carry none -- and never the token or anything from it.
fn describe(result: &WebTokenRequestResult) -> String {
    let Ok(error) = result.ResponseError() else {
        return String::new();
    };
    let code = error.ErrorCode().unwrap_or_default();
    let message = error.ErrorMessage().map(|m| m.to_string()).unwrap_or_default();
    format!(": 0x{code:08x} {message}")
}

/// The broker API scope, i.e. the one that names the resource. See [`OIDC_SCOPES`].
fn broker_scope(scopes: &[String]) -> Option<String> {
    let scope: Vec<&str> =
        scopes.iter().map(String::as_str).filter(|s| !OIDC_SCOPES.contains(s)).collect();
    (!scope.is_empty()).then(|| scope.join(" "))
}

/// WAM wants the tenant authority, not the OIDC issuer: the `/v2.0` suffix the
/// discovery document is published under is not part of it.
fn wam_authority(authority: &str) -> &str {
    authority.trim_end_matches('/').trim_end_matches("/v2.0").trim_end_matches('/')
}

/// WinRT needs the calling thread initialized for COM, and `IAsyncOperation::get`
/// blocks, which an apartment-threaded caller must never do. Rather than
/// initialize (and balance) every short-lived worker thread, give the process an
/// implicit MTA that any uninitialized thread joins. The cookie is deliberately
/// never released: it is wanted for the life of the process.
///
/// Reached before the provider lookup, so a sign-in attempt establishes it as
/// soon as the broker advertises a resource scope -- including on a machine
/// joined to nothing, where WAM was never going to work. `windows_sign_in` is
/// the only thing that stops it. Any thread that has not initialized COM itself
/// is then in this MTA, whether it already existed or is spawned later --
/// `kerbridge_client::windows::elevate`'s included.
fn ensure_mta() {
    static MTA: OnceLock<()> = OnceLock::new();
    MTA.get_or_init(|| unsafe {
        let _ = CoIncrementMTAUsage();
    });
}
