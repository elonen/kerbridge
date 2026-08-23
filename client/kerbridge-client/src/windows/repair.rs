//! Restarting the redirector is destructive in a way the user must consent to
//! first: **every SMB session on the machine drops**, not just the realm's. The
//! caller owns that warning; this module owns doing it correctly.
//!
//! "Correctly" means handling dependents. `LanmanWorkstation` normally has
//! running dependents (on a domain-joined machine, `Netlogon`), and SCM refuses
//! to stop a service whose dependents are running. So: stop the dependents that
//! are running, stop the service, start it, then start those dependents again --
//! leaving a machine with `Netlogon` stopped would be a worse outcome than the
//! NTLM fallback.

use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, ENUM_SERVICE_STATUSW, EnumDependentServicesW,
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE, SC_MANAGER_CONNECT,
    SERVICE_ACTIVE, SERVICE_CONTROL_STOP, SERVICE_ENUMERATE_DEPENDENTS, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED, StartServiceW,
};

const SERVICE: &str = "LanmanWorkstation";
/// How long to wait for one service to reach the requested state.
const TRANSITION_TIMEOUT: Duration = Duration::from_secs(45);

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// An owned SC_HANDLE. Service handles leak silently otherwise, and this
/// function has half a dozen early returns.
struct Handle(SC_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

pub fn restart_workstation() -> Result<Vec<String>> {
    let scm =
        Handle(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) });
    if scm.0.is_null() {
        bail!("cannot open the service control manager (error {}) -- run elevated", last_error());
    }

    let access = SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS;
    let svc = open(&scm, SERVICE, access)?;

    let mut steps = Vec::new();
    let dependents = dependents_of(&svc)?;
    if !dependents.is_empty() {
        steps.push(format!("dependent services running: {}", dependents.join(", ")));
    }

    // Reverse order on the way back up: SCM lists dependents outermost-first.
    for name in &dependents {
        let dep = open(&scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS)?;
        stop(&dep, name)?;
        steps.push(format!("stopped {name}"));
    }
    stop(&svc, SERVICE)?;
    steps.push(format!("stopped {SERVICE}"));

    start(&svc, SERVICE)?;
    steps.push(format!("started {SERVICE}"));

    for name in dependents.iter().rev() {
        let dep = open(&scm, name, SERVICE_START | SERVICE_QUERY_STATUS)?;
        match start(&dep, name) {
            Ok(()) => steps.push(format!("started {name}")),
            // The redirector is back either way; a dependent that will not start
            // is worth reporting, not worth failing the repair over.
            Err(e) => steps.push(format!("could not restart {name}: {e:#}")),
        }
    }

    for s in &steps {
        crate::log::info(&format!("repair: {s}"));
    }
    Ok(steps)
}

fn open(scm: &Handle, name: &str, access: u32) -> Result<Handle> {
    let h = Handle(unsafe { OpenServiceW(scm.0, w(name).as_ptr(), access) });
    if h.0.is_null() {
        bail!("cannot open the {name} service (error {})", last_error());
    }
    Ok(h)
}

/// Names of the service's dependents that are currently active.
///
/// The zero-size first call is the standard sizing idiom, but its failure has to
/// be discriminated: `ERROR_MORE_DATA` means "here is the size", anything else
/// means the enumeration genuinely failed. Treating the latter as "no dependents"
/// would send us on to stop a service whose dependents are still running, which
/// SCM refuses with a far less obvious error.
/// The same list the parent shows before it asks, opened with the one right that
/// an unprivileged process is granted. Empty on any failure: this is a sentence
/// in a dialog, not a precondition of the repair.
pub fn running_dependents() -> Vec<String> {
    let scm =
        Handle(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) });
    if scm.0.is_null() {
        return Vec::new();
    }
    open(&scm, SERVICE, SERVICE_ENUMERATE_DEPENDENTS)
        .and_then(|svc| dependents_of(&svc))
        .unwrap_or_default()
}

fn dependents_of(svc: &Handle) -> Result<Vec<String>> {
    const ERROR_MORE_DATA: u32 = 234;
    let mut needed: u32 = 0;
    let mut count: u32 = 0;
    unsafe {
        if EnumDependentServicesW(
            svc.0,
            SERVICE_ACTIVE,
            std::ptr::null_mut(),
            0,
            &mut needed,
            &mut count,
        ) != 0
        {
            return Ok(Vec::new()); // succeeded with no buffer => no dependents
        }
        match last_error() {
            ERROR_MORE_DATA => {}
            e => bail!("enumerating dependents of {SERVICE} failed (error {e})"),
        }
        if needed == 0 {
            return Ok(Vec::new());
        }

        // Allocated as ENUM_SERVICE_STATUSW rather than bytes so the head of the
        // buffer is correctly aligned for the records SCM writes there; the name
        // strings land in the tail, which needs no alignment.
        let slots = needed.div_ceil(size_of::<ENUM_SERVICE_STATUSW>() as u32) as usize;
        let mut buf: Vec<ENUM_SERVICE_STATUSW> = vec![std::mem::zeroed(); slots];
        if EnumDependentServicesW(
            svc.0,
            SERVICE_ACTIVE,
            buf.as_mut_ptr(),
            (slots * size_of::<ENUM_SERVICE_STATUSW>()) as u32,
            &mut needed,
            &mut count,
        ) == 0
        {
            bail!("enumerating dependents of {SERVICE} failed (error {})", last_error());
        }
        // SAFETY: SCM filled `count` records at the head of `buf`, whose name
        // pointers point into the tail of the same buffer.
        Ok((0..count as usize)
            .map(|i| pwstr_to_string(buf[i].lpServiceName))
            .filter(|n| !n.is_empty())
            .collect())
    }
}

fn stop(svc: &Handle, name: &str) -> Result<()> {
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    if unsafe { QueryServiceStatus(svc.0, &mut status) } != 0
        && status.dwCurrentState == SERVICE_STOPPED
    {
        return Ok(());
    }
    if unsafe { ControlService(svc.0, SERVICE_CONTROL_STOP, &mut status) } == 0 {
        bail!("stopping {name} failed (error {})", last_error());
    }
    await_state(svc, SERVICE_STOPPED, name)
}

fn start(svc: &Handle, name: &str) -> Result<()> {
    if unsafe { StartServiceW(svc.0, 0, std::ptr::null()) } == 0 {
        const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;
        let e = last_error();
        if e != ERROR_SERVICE_ALREADY_RUNNING {
            bail!("starting {name} failed (error {e})");
        }
    }
    await_state(svc, SERVICE_RUNNING, name)
}

fn await_state(svc: &Handle, want: u32, name: &str) -> Result<()> {
    let deadline = Instant::now() + TRANSITION_TIMEOUT;
    loop {
        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        if unsafe { QueryServiceStatus(svc.0, &mut status) } == 0 {
            return Err(anyhow!("querying {name} failed (error {})", last_error()));
        }
        if status.dwCurrentState == want {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("{name} did not reach the requested state within {TRANSITION_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn pwstr_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}
