//! Interface claims on Windows: a named file mapping,
//! `Global\wireserve-if-<ifname>`. What makes the abstract socket right on
//! Linux holds here too: creating one is atomic, the kernel destroys it
//! when the last handle closes — the holder dying included — and the
//! `Global\` namespace is host-wide.
//!
//! A file mapping, not an event or a mutex, because it is the one kind of
//! object whose creation in `Global\` takes `SeCreateGlobalPrivilege`
//! (outside session 0), which only administrators and services hold. So
//! a user can't take a name first, and whoever holds one is another
//! agent. Its contents are never used: one page, never mapped.

use std::io;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Memory::{CreateFileMappingW, OpenFileMappingW, FILE_MAP_READ, PAGE_READONLY};

use crate::lock::Holder;
use crate::platform::windows::net::wide;
use crate::platform::windows::security::{SecurityDescriptor, ADMINS_ONLY};

fn claim_name(ifname: &str) -> String {
    format!(r"Global\wireserve-if-{ifname}")
}

/// This process's claim on an interface name.
#[derive(Debug)]
pub struct IfnameClaim {
    ifname: String,
    handle: HANDLE,
}

// SAFETY: kernel object handles may be used and closed from any thread.
unsafe impl Send for IfnameClaim {}

impl Drop for IfnameClaim {
    fn drop(&mut self) {
        // SAFETY: a handle we own, closed once.
        unsafe { CloseHandle(self.handle) };
    }
}

impl IfnameClaim {
    /// Takes the claim, or reports who has it.
    pub fn take(ifname: &str) -> io::Result<Result<Self, Holder>> {
        let sd = SecurityDescriptor::from_sddl(ADMINS_ONLY)?;
        let sa = sd.attributes();
        let name = wide(&claim_name(ifname));
        // SAFETY: valid attributes and a NUL-terminated name for the call;
        // a page-file-backed mapping of one page.
        let handle = unsafe { CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READONLY, 0, 1, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: read straight after the call that set it.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // SAFETY: the handle the call just returned.
            unsafe { CloseHandle(handle) };
            return Ok(Err(Holder::AnotherAgent));
        }
        Ok(Ok(Self {
            ifname: ifname.to_string(),
            handle,
        }))
    }

    #[must_use]
    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    /// Keeps the claim for the rest of this process's life.
    pub fn hold(self) {
        std::mem::forget(self);
    }
}

/// Who holds `ifname`'s claim: whoever has the mapping open. Opening it
/// keeps it alive for a moment, so a claim taken at that very instant
/// sees it taken — the safe way round.
#[must_use]
pub fn holder(ifname: &str) -> Holder {
    let name = wide(&claim_name(ifname));
    // SAFETY: a NUL-terminated name.
    let handle = unsafe { OpenFileMappingW(FILE_MAP_READ, 0, name.as_ptr()) };
    if !handle.is_null() {
        // SAFETY: the handle the call just returned.
        unsafe { CloseHandle(handle) };
        return Holder::AnotherAgent;
    }
    // SAFETY: read straight after the call that set it.
    match unsafe { GetLastError() } {
        ERROR_FILE_NOT_FOUND => Holder::Nobody,
        code => Holder::Unknown(io::Error::from_raw_os_error(code as i32).to_string()),
    }
}
