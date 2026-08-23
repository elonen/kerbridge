//! Only realm registration (`--enroll`, `--reenroll`, `--unenroll`) and
//! `--repair` elevate. Sign-in, injection and sign-out must *not*: an elevated
//! process runs under a different LUID with a different ticket cache, and a
//! ticket landed there is invisible to the SMB redirector (measured:
//! research spike `windows-tgt-followup-entra-joined` @5). So the agent never elevates
//! itself wholesale -- it relaunches a second copy for exactly the one privileged
//! step, waits for it, and carries on unprivileged.

use std::ffi::c_void;

use anyhow::{Result, bail};

use super::Elevated;

/// The user declined the elevation prompt, as `ShellExecuteExW` reports it --
/// and the only signal there is. `consent.exe` owns the retry loop on the secure
/// desktop, imposes no attempt limit of its own, and reports back exactly once:
/// when the user gives up. Measured on Windows 11 26200, 2026-08-05 -- eight
/// wrong passwords followed by a dismissal produced this code and nothing else.
/// So a mistyped password cannot be told from a refusal here, and must not be
/// given copy of its own.
const ERROR_CANCELLED: u32 = 1223;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, TerminateProcess,
    WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{SHELLEXECUTEINFOW, ShellExecuteExW};

const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;
const SW_SHOWNORMAL: i32 = 1;

/// Does this process handle's token carry elevation? `None` when it cannot be
/// determined at all.
///
/// The distinction is crucial, so this deliberately does not collapse to
/// a plain `bool`. Reading the token of a *more privileged* process can be
/// refused, so "access denied" is evidence of the opposite of what a `false`
/// would say here. [`run_elevated`] acts only on a definite `Some(false)`.
fn handle_elevation(process: HANDLE) -> Option<bool> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        CloseHandle(token);
        (ok != 0).then_some(elevation.TokenIsElevated != 0)
    }
}

pub fn is_elevated() -> bool {
    // Our own token is always readable; `unwrap_or(false)` is for the
    // unreachable case, and "assume unprivileged" is the safe way to be wrong.
    handle_elevation(unsafe { GetCurrentProcess() }).unwrap_or(false)
}

pub fn run_elevated(args: &[&str], started: &dyn Fn()) -> Result<Elevated> {
    let exe = std::env::current_exe()?;
    let exe_w = wide(&exe.to_string_lossy());
    // Quote every argument: paths and URLs can contain spaces.
    let params = args.iter().map(|a| format!("\"{a}\"")).collect::<Vec<_>>().join(" ");
    let params_w = wide(&params);
    let verb_w = wide("runas");

    // No apartment, or the implicit MTA `wam::ensure_mta` gives the process once
    // a sign-in has been attempted -- never an STA, which is what Microsoft's
    // guidance prefers for ShellExecuteEx. Both states measured working through
    // real `runas` on Windows 11 26200: implicit MTA 2026-08-05, no apartment
    // 2026-08-06.
    //
    // Don't reach for CoInitializeEx(COINIT_APARTMENTTHREADED): it succeeds even
    // against the implicit MTA, but the INFINITE wait below pumps no messages,
    // which is what an STA must never do -- an extension needing its apartment
    // serviced would not be. It also makes the calling thread the process main
    // STA (APTTYPE_MAINSTA; nothing else here enters an STA), hosting
    // ThreadingModel=Main objects until it exits.
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb_w.as_ptr();
        info.lpFile = exe_w.as_ptr();
        info.lpParameters = params_w.as_ptr();
        info.nShow = SW_SHOWNORMAL;

        if ShellExecuteExW(&mut info) == 0 {
            let e = GetLastError();
            if e == ERROR_CANCELLED {
                return Ok(Elevated::Declined);
            }
            bail!("could not start the elevated helper (error {e})");
        }
        if info.hProcess.is_null() {
            bail!("the elevated helper did not start");
        }

        // A successful ShellExecuteExW is NOT evidence that elevation
        // happened. The "runas" verb is serviced by the UAC elevation broker,
        // and with UAC disabled (`EnableLUA=0`) that broker is inert: the call
        // succeeds and returns a copy running on the caller's own unprivileged
        // token. The copy then finds itself unelevated, relaunches for the
        // same reason, and the chain grows without bound -- measured at ~1 new
        // process/second until the machine was unusable.
        //
        // So audit the token we actually got rather than trusting the verb.
        // Checked before the wait, while the copy is still starting up, so it
        // is stopped before it can relaunch anything of its own.
        //
        // Only a *definite* "not elevated" counts. When elevation really did
        // happen the copy outranks us and reading its token can be refused --
        // exactly the case that must not be mistaken for a failure to elevate,
        // or the fix for the runaway would kill every legitimate helper on a
        // normally configured machine instead.
        if handle_elevation(info.hProcess) == Some(false) {
            TerminateProcess(info.hProcess, 1);
            CloseHandle(info.hProcess);
            // The invocation goes to the log rather than into the sentence: the
            // surface says what is wrong in one line, and the command that works
            // around it is for whoever reads the log.
            crate::log::error(
                "the helper was relaunched to gain administrator rights but came back \
                 unprivileged, so it was stopped rather than allowed to try again. Run it from \
                 an already-elevated shell instead, e.g. \
                 `runas /user:<admin account> \"<command>\"`",
            );
            return Ok(Elevated::Unavailable);
        }

        // The child exists, so the prompt is answered and the work is under way.
        started();
        WaitForSingleObject(info.hProcess, INFINITE);
        let mut code: u32 = 1;
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
        Ok(Elevated::Ran(code))
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
