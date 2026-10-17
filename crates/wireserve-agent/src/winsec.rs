//! Windows access control: what Unix modes (`0700`, `0600`) and socket
//! permissions do on Linux.
//!
//! A file or directory created under `%ProgramData%` inherits an ACL that
//! lets every local user read it, and the state directory holds this
//! node's private key and bearer token. So it is given a *protected* ACL
//! of its own (nothing inherited from above) granting only SYSTEM, the
//! Administrators group and the directory's owner, inherited in turn by
//! everything created inside.
//!
//! Any local user may create a directory in `%ProgramData%`, though, and
//! the owner of a directory can always rewrite its ACL. So the ACL is only
//! applied to a directory whose owner is SYSTEM, Administrators, or the
//! account the agent runs as; one some other user created first is
//! refused rather than adopted.

use std::io;
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SetNamedSecurityInfoW,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetSecurityDescriptorDacl, GetTokenInformation, TokenElevation, TokenUser,
    WinBuiltinAdministratorsSid,
    WinLocalSystemSid, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
    WELL_KNOWN_SID_TYPE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::winnet::wide;

/// Full control for SYSTEM and Administrators, inherited by files and
/// subdirectories (`OICI`), nothing inherited from the parent (`P`).
pub const ADMINS_ONLY: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// [`ADMINS_ONLY`] plus the owner (`OW`, Owner Rights) — for a directory
/// whose owner [`restrict_to_admins`] has checked is one of those two or
/// the agent's own account, which an unelevated test run is.
const ADMINS_AND_OWNER: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)";

/// A self-relative security descriptor built from SDDL, freed on drop.
pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: an owned allocation, never written after it is built.
unsafe impl Send for SecurityDescriptor {}
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let sddl = wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated string; `sd` is allocated by the call and
        // freed in `drop`.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut())
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sd))
    }

    /// For `CreateNamedPipeW` and friends. Valid while `self` is.
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }

    fn dacl(&self) -> io::Result<*mut ACL> {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: a valid descriptor; the DACL pointer points into it.
        if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(dacl)
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated with LocalAlloc by the SDDL conversion; freed once.
        unsafe { LocalFree(self.0) };
    }
}

/// Replaces `path`'s ACL with SYSTEM, Administrators and its owner only,
/// applied to what is already inside it as well — after checking the
/// owner is one of the first two or the account this process runs as.
pub fn restrict_to_admins(path: &Path) -> io::Result<()> {
    let name = wide(&path.to_string_lossy());
    check_owner(path, &name)?;
    let sd = SecurityDescriptor::from_sddl(ADMINS_AND_OWNER)?;
    let dacl = sd.dacl()?;
    // SAFETY: a NUL-terminated path and a DACL inside `sd`, both live for the call.
    let code = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    Ok(())
}

/// Creates `dir` if need be and makes it private (see
/// [`restrict_to_admins`]) — every time, not only when it is new: one that
/// was already there may have been put there by another user.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    restrict_to_admins(dir)
}

/// Refuses a `path` owned by anyone but SYSTEM, Administrators or this
/// process's own user.
fn check_owner(path: &Path, name: &[u16]) -> io::Result<()> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated path; `owner` points into `sd`, which the call
    // allocates and the guard below frees.
    let code = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let _sd = SecurityDescriptor(sd);
    let system = well_known_sid(WinLocalSystemSid)?;
    let admins = well_known_sid(WinBuiltinAdministratorsSid)?;
    let me = process_user()?;
    // SAFETY: `me` starts with a TOKEN_USER (8-aligned, as a `Vec<u64>`)
    // whose SID points further into `me`.
    let my_sid = unsafe { (*me.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: valid SIDs, all alive for the comparison.
    let trusted = unsafe {
        EqualSid(owner, system.as_ptr().cast_mut().cast()) != 0
            || EqualSid(owner, admins.as_ptr().cast_mut().cast()) != 0
            || EqualSid(owner, my_sid) != 0
    };
    if trusted {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is owned by another user, who could read the keys kept in it; \
                 remove it and start again",
                path.display()
            ),
        ))
    }
}

fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Vec<u8>> {
    let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut len = SECURITY_MAX_SID_SIZE;
    // SAFETY: `sid` is `len` bytes, written by the call.
    if unsafe { CreateWellKnownSid(kind, std::ptr::null_mut(), sid.as_mut_ptr().cast(), &mut len) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sid)
}

/// Whether this process runs elevated — as SYSTEM, or an administrator
/// past the UAC prompt: the Windows counterpart of `euid == 0`.
pub fn is_elevated() -> io::Result<bool> {
    let token = process_token()?;
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
    // SAFETY: a fixed-size query into `elevation`.
    let ok = unsafe { GetTokenInformation(token, TokenElevation, std::ptr::from_mut(&mut elevation).cast(), len, &mut len) };
    let err = io::Error::last_os_error();
    // SAFETY: a token handle we opened.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(err);
    }
    Ok(elevation.TokenIsElevated != 0)
}

fn process_token() -> io::Result<HANDLE> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo-handle of this process; `token` is written by the call.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(token)
}

/// This process's `TOKEN_USER`, as raw bytes (it points into itself).
fn process_user() -> io::Result<Vec<u64>> {
    let token = process_token()?;
    let mut len = 0u32;
    // SAFETY: a size query, then a read into a buffer of that size.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    let ok = unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) };
    let err = io::Error::last_os_error();
    // SAFETY: a token handle we opened.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(err);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_admins_only_descriptor_parses() {
        let sd = SecurityDescriptor::from_sddl(ADMINS_ONLY).unwrap();
        assert!(!sd.dacl().unwrap().is_null());
    }

    /// The test run owns its temp directory, so it keeps access to it —
    /// which is also what the agent's own account has to its state.
    #[test]
    fn a_restricted_directory_stays_usable_by_its_owner() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("nested");
        std::fs::create_dir_all(&sub).unwrap();
        restrict_to_admins(&sub).unwrap();
        std::fs::write(sub.join("f"), b"x").unwrap();
        assert_eq!(std::fs::read(sub.join("f")).unwrap(), b"x");
    }

    #[test]
    fn malformed_sddl_is_an_error() {
        assert!(SecurityDescriptor::from_sddl("D:(nonsense)").is_err());
    }
}
