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
//!
//! The daemon's pipe may also be shared with a local group, as its socket
//! is with the `wireserve` group on Linux; [`local_group_sid`] is the
//! lookup and [`ensure_local_group`] the `groupadd`.

use std::io;
use std::path::Path;

use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_ALIAS_EXISTS, ERROR_NONE_MAPPED, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::NetManagement::{NetLocalGroupAdd, LOCALGROUP_INFO_1};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetSecurityDescriptorDacl, GetTokenInformation, LookupAccountNameW, SidTypeAlias,
    TokenElevation, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SECURITY_MAX_SID_SIZE, SID_NAME_USE, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, WELL_KNOWN_SID_TYPE,
};
use windows_sys::Win32::System::SystemInformation::{ComputerNameNetBIOS, GetComputerNameExW};
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

/// The SID, as SDDL writes it, of `name` if that is a group of this
/// computer's own (an alias in its local account database), and `None`
/// otherwise. Not a domain's group of the same name, nor a built-in one:
/// the plain name would resolve to a domain group when there is no local
/// one, and anyone the domain lets create groups could make that.
pub fn local_group_sid(name: &str) -> io::Result<Option<String>> {
    if name.is_empty() || name.contains(['\\', '@']) {
        return Ok(None);
    }
    let computer = computer_name()?;
    let account = wide(&format!("{computer}\\{name}"));
    let mut sid = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut sid_len = SECURITY_MAX_SID_SIZE;
    let mut domain = vec![0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: a NUL-terminated name; `sid` and `domain` are the sizes given.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        let err = io::Error::last_os_error();
        return if err.raw_os_error() == Some(ERROR_NONE_MAPPED as i32) { Ok(None) } else { Err(err) };
    }
    let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
    if kind != SidTypeAlias || !domain.eq_ignore_ascii_case(&computer) {
        return Ok(None);
    }
    let mut text: PWSTR = std::ptr::null_mut();
    // SAFETY: a valid SID; `text` is allocated by the call and freed below.
    if unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a NUL-terminated string from the call above, freed once.
    let out = unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        out
    };
    Ok(Some(out))
}

/// Creates the local group `name` unless one exists already: the Windows
/// `groupadd --system`. A user or a domain group of that name is an error,
/// as it would be the account [`local_group_sid`] refuses.
pub fn ensure_local_group(name: &str, comment: &str) -> io::Result<()> {
    // Network Management's own codes, which the system's messages don't
    // cover (`io::Error` would print "unknown error").
    const NERR_GROUP_EXISTS: u32 = 2223;
    const NERR_USER_EXISTS: u32 = 2224;
    let mut wname = wide(name);
    let mut wcomment = wide(comment);
    let info = LOCALGROUP_INFO_1 { lgrpi1_name: wname.as_mut_ptr(), lgrpi1_comment: wcomment.as_mut_ptr() };
    let mut bad_field = 0u32;
    // SAFETY: level 1 takes a LOCALGROUP_INFO_1, whose strings outlive the call.
    let code = unsafe { NetLocalGroupAdd(std::ptr::null(), 1, std::ptr::from_ref(&info).cast(), &mut bad_field) };
    match code {
        ERROR_SUCCESS | ERROR_ALIAS_EXISTS => Ok(()),
        NERR_GROUP_EXISTS | NERR_USER_EXISTS => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("could not create the local group `{name}`: a user or a domain group already has that name"),
        )),
        code => Err(io::Error::other(format!("could not create the local group `{name}` (error {code})"))),
    }
}

/// This computer's NetBIOS name: the name of its local account database.
fn computer_name() -> io::Result<String> {
    let mut buf = vec![0u16; 64];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` is `len` characters, written by the call.
    if unsafe { GetComputerNameExW(ComputerNameNetBIOS, buf.as_mut_ptr(), &mut len) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
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

    #[test]
    fn only_a_group_of_this_computer_has_a_local_group_sid() {
        assert_eq!(local_group_sid("wireserve-test-no-such-group").unwrap(), None);
        // Built in, so in BUILTIN and not in this computer's own database.
        assert_eq!(local_group_sid("Administrators").unwrap(), None);
        // A name with a domain in it is refused before any lookup.
        assert_eq!(local_group_sid(r"OTHER\wireserve").unwrap(), None);
        assert_eq!(local_group_sid("").unwrap(), None);
    }

    /// Creating a local group takes an administrator.
    #[test]
    fn a_created_group_is_found_and_creating_it_again_is_fine() {
        use windows_sys::Win32::NetworkManagement::NetManagement::NetLocalGroupDel;

        if !is_elevated().unwrap_or(false) {
            assert!(std::env::var_os("WIRESERVE_TEST_STRICT").is_none(), "would skip under WIRESERVE_TEST_STRICT: not elevated");
            eprintln!("SKIPPED: not elevated: creating a local group takes an administrator");
            return;
        }
        let name = format!("wireserve-test-{}", std::process::id());
        ensure_local_group(&name, "wireserve test").unwrap();
        let found = local_group_sid(&name);
        let again = ensure_local_group(&name, "wireserve test");
        // SAFETY: a NUL-terminated name.
        unsafe { NetLocalGroupDel(std::ptr::null(), wide(&name).as_ptr()) };
        let sid = found.unwrap().expect("the group just created");
        assert!(sid.starts_with("S-1-5-21-"), "a local account database's SID, not {sid}");
        again.unwrap();
        assert_eq!(local_group_sid(&name).unwrap(), None);
    }
}
