//! The agent as a Windows Service: what systemd and the agent's unit do
//! on Linux. Two halves:
//! - **in the service**, [`dispatch`] hands the process to the Service
//!   Control Manager, which calls back into it to run the daemon; a stop
//!   or a system shutdown wakes [`stop_requested`], which the daemon waits
//!   on beside Ctrl-C, and goes down the same path a SIGTERM does on Linux;
//! - **for `install` and `leave`**, creating, starting, stopping and
//!   deleting the service.
//!
//! One service per instance: `wireserve-agent`, or `wireserve-agent-<name>`
//! for a named one, each running `wireserve.exe daemon --service` as
//! LocalSystem, started at boot and restarted after a failure.

use std::io;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE,
    ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, RegisterServiceCtrlHandlerExW, SetServiceStatus,
    StartServiceCtrlDispatcherW, StartServiceW, SC_ACTION, SC_ACTION_RESTART, SC_HANDLE, SC_MANAGER_ALL_ACCESS,
    SC_MANAGER_CONNECT, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_DESCRIPTIONW,
    SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW, SERVICE_FAILURE_ACTIONS_FLAG,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_HANDLE, SERVICE_STOP, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS,
};

use crate::paths::Instance;
use crate::winnet::wide;

/// The service's name for `instance`.
#[must_use]
pub fn service_name(instance: &Instance) -> String {
    if instance.is_default() {
        "wireserve-agent".to_string()
    } else {
        format!("wireserve-agent-{}", instance.name())
    }
}

// ---- in the service ----

/// What the service runs, set once by [`dispatch`]: the daemon, returning
/// its exit code.
static RUN: OnceLock<Box<dyn Fn() -> u32 + Send + Sync>> = OnceLock::new();
static NAME: OnceLock<Vec<u16>> = OnceLock::new();
/// The status handle, as a `usize`: set by `service_main` before anything
/// can read it.
static STATUS: OnceLock<usize> = OnceLock::new();
static STOP: OnceLock<tokio::sync::Notify> = OnceLock::new();

fn stop() -> &'static tokio::sync::Notify {
    STOP.get_or_init(tokio::sync::Notify::new)
}

/// Resolves once the Service Control Manager asks the service to stop, or
/// the system is shutting down. Never, outside a service.
pub async fn stop_requested() {
    stop().notified().await;
}

/// Hands this process to the Service Control Manager to run as `name`,
/// calling `run` for the service's life. Returns when the service has
/// stopped. Fails at once when the process was not started by the SCM —
/// someone ran `daemon --service` by hand.
pub fn dispatch(name: &str, run: impl Fn() -> u32 + Send + Sync + 'static) -> io::Result<()> {
    let _ = RUN.set(Box::new(run));
    let name = NAME.get_or_init(|| wide(name));
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_ptr().cast_mut(), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: std::ptr::null_mut(), lpServiceProc: None },
    ];
    // SAFETY: a NULL-terminated table whose name outlives the call (static).
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let Some(name) = NAME.get() else { return };
    // SAFETY: a NUL-terminated name and a handler that lives for the process.
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), std::ptr::null()) };
    if handle.is_null() {
        return;
    }
    let _ = STATUS.set(handle as usize);
    set_status(SERVICE_START_PENDING, NO_ERROR, 0);
    set_status(SERVICE_RUNNING, NO_ERROR, 0);
    let code = RUN.get().map_or(1, |run| run());
    // A nonzero exit is a failure, which the restart actions act on.
    if code == 0 {
        set_status(SERVICE_STOPPED, NO_ERROR, 0);
    } else {
        set_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, code);
    }
}

unsafe extern "system" fn handler(control: u32, _event: u32, _data: *mut core::ffi::c_void, _ctx: *mut core::ffi::c_void) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            set_status(SERVICE_STOP_PENDING, NO_ERROR, 0);
            // A permit is kept if the daemon is not waiting yet.
            stop().notify_one();
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        // ERROR_CALL_NOT_IMPLEMENTED
        _ => 120,
    }
}

fn set_status(state: u32, win32_exit: u32, specific_exit: u32) {
    let Some(handle) = STATUS.get() else { return };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING { SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN } else { 0 },
        dwWin32ExitCode: win32_exit,
        dwServiceSpecificExitCode: specific_exit,
        dwCheckPoint: 0,
        // Teardown waits up to `wg::nt`'s removal wait for the adapter.
        dwWaitHint: if state == SERVICE_STOP_PENDING { 15_000 } else { 0 },
    };
    // SAFETY: the handle RegisterServiceCtrlHandlerExW returned.
    unsafe { SetServiceStatus(*handle as SERVICE_STATUS_HANDLE, &status) };
}

// ---- for install and leave ----

struct Handle(SC_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: a handle we opened, closed once.
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn manager(access: u32) -> io::Result<Handle> {
    // SAFETY: the local machine's active database.
    let h = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), access) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(Handle(h))
}

/// The service `name`, if it exists.
fn open(name: &str, access: u32) -> io::Result<Option<Handle>> {
    let scm = manager(SC_MANAGER_CONNECT)?;
    let wname = wide(name);
    // SAFETY: a NUL-terminated name.
    let h = unsafe { OpenServiceW(scm.0, wname.as_ptr(), access) };
    if h.is_null() {
        let err = io::Error::last_os_error();
        return if err.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) { Ok(None) } else { Err(err) };
    }
    Ok(Some(Handle(h)))
}

fn state(h: &Handle) -> io::Result<u32> {
    // SAFETY: all-zero is a valid SERVICE_STATUS to be written.
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    // SAFETY: a handle opened with SERVICE_QUERY_STATUS.
    if unsafe { QueryServiceStatus(h.0, &mut status) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(status.dwCurrentState)
}

/// Whether the service `name` exists and is running (or starting).
pub fn is_running(name: &str) -> io::Result<bool> {
    Ok(match open(name, SERVICE_QUERY_STATUS)? {
        Some(h) => matches!(state(&h)?, SERVICE_RUNNING | SERVICE_START_PENDING),
        None => false,
    })
}

/// Creates the service `name` to run `exe daemon --service` for
/// `instance`, or brings an existing one's configuration up to date.
pub fn install(name: &str, instance: &Instance, exe: &Path) -> io::Result<()> {
    let mut command = format!("\"{}\" daemon --service", exe.display());
    if !instance.is_default() {
        command.push_str(&format!(" --instance {}", instance.name()));
    }
    let wcommand = wide(&command);
    let wname = wide(name);
    let display = wide(&if instance.is_default() {
        "wireserve agent".to_string()
    } else {
        format!("wireserve agent ({})", instance.name())
    });
    let service = match open(name, SERVICE_ALL_ACCESS)? {
        Some(h) => {
            // SAFETY: a handle with SERVICE_CHANGE_CONFIG; NULL leaves a field as it is.
            let ok = unsafe {
                ChangeServiceConfigW(
                    h.0,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    wcommand.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    display.as_ptr(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            h
        }
        None => {
            let scm = manager(SC_MANAGER_ALL_ACCESS)?;
            // SAFETY: NUL-terminated strings; a NULL account is LocalSystem.
            let h = unsafe {
                CreateServiceW(
                    scm.0,
                    wname.as_ptr(),
                    display.as_ptr(),
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    wcommand.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };
            if h.is_null() {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(ERROR_SERVICE_MARKED_FOR_DELETE as i32) {
                    return Err(io::Error::other(format!(
                        "the {name} service is still being removed; close the Services console if it is open, and try again"
                    )));
                }
                return Err(err);
            }
            Handle(h)
        }
    };

    let mut description = wide("Keeps this computer in its wireserve mesh: WireGuard peers, firewall and names.");
    let info = SERVICE_DESCRIPTIONW { lpDescription: description.as_mut_ptr() };
    // SAFETY: a description that outlives the call.
    unsafe { ChangeServiceConfig2W(service.0, SERVICE_CONFIG_DESCRIPTION, std::ptr::from_ref(&info).cast()) };

    // Restarted 5 s after a failure, then 30 s, then every minute; the count
    // resets after a day without one. Failures include a nonzero exit, not
    // only a crash (the flag below), as `Restart=on-failure` does.
    let mut actions = [
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 5_000 },
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 30_000 },
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 60_000 },
    ];
    let failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 24 * 60 * 60,
        lpRebootMsg: std::ptr::null_mut(),
        lpCommand: std::ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    // SAFETY: structures that outlive the calls.
    if unsafe { ChangeServiceConfig2W(service.0, SERVICE_CONFIG_FAILURE_ACTIONS, std::ptr::from_ref(&failure).cast()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let flag = SERVICE_FAILURE_ACTIONS_FLAG { fFailureActionsOnNonCrashFailures: 1 };
    if unsafe { ChangeServiceConfig2W(service.0, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, std::ptr::from_ref(&flag).cast()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Starts the service and waits until it runs. One that stops instead
/// failed at startup, and says so.
pub fn start(name: &str, log: &Path) -> io::Result<()> {
    let h = open(name, SERVICE_START | SERVICE_QUERY_STATUS)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("there is no {name} service")))?;
    // SAFETY: a handle with SERVICE_START; no arguments.
    if unsafe { StartServiceW(h.0, 0, std::ptr::null()) } == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(ERROR_SERVICE_ALREADY_RUNNING as i32) {
            return Err(err);
        }
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match state(&h)? {
            SERVICE_RUNNING => return Ok(()),
            SERVICE_STOPPED => {
                return Err(io::Error::other(format!("the {name} service stopped right after starting; see {}", log.display())))
            }
            _ if Instant::now() >= deadline => {
                return Err(io::Error::other(format!("the {name} service did not start within 30 s; see {}", log.display())))
            }
            _ => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// Stops the service if it runs, and waits until it has. Whether it was
/// running, so the caller can start it again.
pub fn stop_and_wait(name: &str) -> io::Result<bool> {
    let Some(h) = open(name, SERVICE_STOP | SERVICE_QUERY_STATUS)? else {
        return Ok(false);
    };
    if state(&h)? == SERVICE_STOPPED {
        return Ok(false);
    }
    // SAFETY: all-zero is a valid SERVICE_STATUS to be written.
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    // SAFETY: a handle with SERVICE_STOP.
    if unsafe { ControlService(h.0, SERVICE_CONTROL_STOP, &mut status) } == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(ERROR_SERVICE_NOT_ACTIVE as i32) {
            return Err(err);
        }
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while state(&h)? != SERVICE_STOPPED {
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!("the {name} service did not stop within 30 s")));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(true)
}

/// Removes the service, stopped first. One that does not exist is done.
pub fn delete(name: &str) -> io::Result<()> {
    stop_and_wait(name)?;
    // DELETE access right.
    let Some(h) = open(name, 0x0001_0000)? else {
        return Ok(());
    };
    // SAFETY: a handle with DELETE access.
    if unsafe { DeleteService(h.0) } == 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(ERROR_SERVICE_MARKED_FOR_DELETE as i32) {
            return Err(err);
        }
    }
    Ok(())
}

/// The instances among `instances` whose service is running now: all of
/// them run the same installed binary, which an upgrade replaces.
pub fn running_instances(instances: Vec<Instance>) -> io::Result<Vec<Instance>> {
    let mut out = Vec::new();
    for instance in instances {
        if is_running(&service_name(&instance))? {
            out.push(instance);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_instance_has_a_service_of_its_own() {
        assert_eq!(service_name(&Instance::default()), "wireserve-agent");
        assert_eq!(service_name(&Instance::new("work").unwrap()), "wireserve-agent-work");
    }

    #[test]
    fn a_service_that_does_not_exist_is_neither_running_nor_an_error() {
        assert!(!is_running("wireserve-agent-no-such-instance").unwrap());
    }

    #[test]
    fn dispatching_outside_the_service_manager_fails_rather_than_hangs() {
        // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT
        let err = dispatch("wireserve-test", || 0).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(1063));
    }
}
