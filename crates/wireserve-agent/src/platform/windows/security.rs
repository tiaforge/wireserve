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
//! the owner of a directory can always rewrite its ACL, and rename or
//! replace what is in it. So the ACL is only applied to a directory whose
//! owner is SYSTEM, Administrators, or the account the agent runs as, and
//! every directory from the state root down to it must be owned so too
//! and be no junction or symbolic link (PLAN.md #362): one some other user
//! created first is refused rather than adopted.
//!
//! The daemon's pipe may also be shared with a local group, as its socket
//! is with the `wireserve` group on Linux; [`local_group_sid`] is the
//! lookup and [`ensure_local_group`] the `groupadd`.
//!
//! The TLS terminator (PLAN.md M51) runs as a virtual account of its own,
//! `NT SERVICE\<its service>` ([`service_sid`]): its state directory
//! ([`ensure_private_dir_for`]), its pipe and its firewall permits name it.

use std::io;
use std::path::{Component, Path, PathBuf};

use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_ALIAS_EXISTS, ERROR_NONE_MAPPED, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{NetLocalGroupAdd, LOCALGROUP_INFO_1};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SE_OBJECT_TYPE,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetSecurityDescriptorDacl, GetSecurityDescriptorLength, GetTokenInformation,
    LookupAccountNameW, SidTypeAlias, TokenElevation, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SECURITY_MAX_SID_SIZE, SID_NAME_USE, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, WELL_KNOWN_SID_TYPE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::SystemInformation::{ComputerNameNetBIOS, GetComputerNameExW};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::platform::windows::net::wide;

/// Full control for SYSTEM and Administrators, inherited by files and
/// subdirectories (`OICI`), nothing inherited from the parent (`P`).
pub const ADMINS_ONLY: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// [`ADMINS_ONLY`] plus the owner (`OW`, Owner Rights) — for a directory
/// whose owner [`ensure_private_dir`] has checked is one of those two or
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

    /// The descriptor as bytes, self-relative: what WFP takes as a
    /// `FWP_SECURITY_DESCRIPTOR_TYPE` value.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: a valid self-relative descriptor of that many bytes,
        // alive as long as `self`.
        unsafe { std::slice::from_raw_parts(self.0.cast::<u8>(), GetSecurityDescriptorLength(self.0) as usize) }
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

/// The directories from `root` down to `dir`, `root` first and `dir`
/// last: every one of them is checked, since whoever owns a directory can
/// rename or replace what is in it. `dir` alone when it is not under
/// `root` (a test's own directory), or reached from it by anything but
/// plain names.
fn chain(root: &Path, dir: &Path) -> Vec<PathBuf> {
    let Ok(rest) = dir.strip_prefix(root) else {
        return vec![dir.to_path_buf()];
    };
    if !rest.components().all(|c| matches!(c, Component::Normal(_))) {
        return vec![dir.to_path_buf()];
    }
    let mut out = vec![root.to_path_buf()];
    let mut at = root.to_path_buf();
    for c in rest.components() {
        at.push(c);
        out.push(at.clone());
    }
    out
}

/// One directory, open as itself, never through a junction or symbolic
/// link, and kept open without delete sharing, so it is neither renamed
/// nor replaced while it is checked and given its ACL. Closed on drop.
struct Dir(HANDLE);

impl Drop for Dir {
    fn drop(&mut self) {
        // SAFETY: a handle we opened, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

impl Dir {
    /// Opens `path`, refusing anything but a plain directory: a reparse
    /// point (a junction, a symbolic link) would send every later use of
    /// the path wherever its owner pointed it. `write_dac` to give it an
    /// ACL after.
    fn open(path: &Path, write_dac: bool) -> io::Result<Self> {
        let name = wide(&path.to_string_lossy());
        let access = READ_CONTROL | FILE_READ_ATTRIBUTES | if write_dac { WRITE_DAC } else { 0 };
        // SAFETY: a NUL-terminated path; the handle is owned by `Dir` from here.
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                // A directory takes backup semantics to be opened at all.
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let dir = Self(h);
        // SAFETY: all-zero is a valid BY_HANDLE_FILE_INFORMATION to be written.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: an open handle with FILE_READ_ATTRIBUTES.
        if unsafe { GetFileInformationByHandle(dir.0, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} is a link (a junction or symbolic link), not a folder; remove it and start again", path.display()),
            ));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(io::Error::other(format!("{} is not a folder", path.display())));
        }
        Ok(dir)
    }

    /// Refuses a directory owned by anyone but SYSTEM, Administrators or
    /// this process's own user.
    fn check_owner(&self, path: &Path) -> io::Result<()> {
        if owner_trusted(self.0, SE_FILE_OBJECT)? {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is owned by another user, who could read the keys kept under it; \
                     remove it and start again",
                    path.display()
                ),
            ))
        }
    }

    /// Replaces the directory's ACL with `sddl`'s, protected (nothing
    /// inherited from above) and passed on to what is already inside it.
    fn set_acl(&self, sddl: &str) -> io::Result<()> {
        let sd = SecurityDescriptor::from_sddl(sddl)?;
        let dacl = sd.dacl()?;
        // SAFETY: a handle opened with WRITE_DAC and a DACL inside `sd`, both
        // live for the call.
        let code = unsafe {
            SetSecurityInfo(
                self.0,
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
}

/// Creates what is missing from `root` down to `dir`, and makes sure no
/// one but SYSTEM, Administrators or this process's own user owns any of
/// it, and none of it is a link: an unprivileged user may create folders
/// in `%ProgramData%`, so with no default instance installed one could
/// otherwise own `wireserve\instances` and swap a named instance's folder
/// under the agent. `root` gets `root_sddl` and `dir` `leaf_sddl` (only
/// that, when they are one), each protected; what lies between inherits
/// the root's. Every directory stays open until the end, so none is
/// replaced in between.
fn ensure_private_tree(root: &Path, dir: &Path, root_sddl: &str, leaf_sddl: &str) -> io::Result<()> {
    let chain = chain(root, dir);
    // Above the root: `%ProgramData%`, or a test's own directory.
    if let Some(parent) = chain[0].parent() {
        std::fs::create_dir_all(parent)?;
    }
    let last = chain.len() - 1;
    let mut held = Vec::with_capacity(chain.len());
    for (i, path) in chain.iter().enumerate() {
        match std::fs::create_dir(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let sddl = if i == last {
            Some(leaf_sddl)
        } else if i == 0 {
            Some(root_sddl)
        } else {
            None
        };
        let d = Dir::open(path, sddl.is_some())?;
        d.check_owner(path)?;
        if let Some(sddl) = sddl {
            d.set_acl(sddl)?;
        }
        held.push(d);
    }
    Ok(())
}

/// Creates `dir` if need be and makes it private: SYSTEM, Administrators
/// and its owner only, after checking every folder from the state root
/// down to it (see [`ensure_private_tree`]) — every time, not only when it
/// is new: one that was already there may have been put there by another
/// user. The state root, `%ProgramData%\wireserve`, gets the same ACL.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    ensure_private_tree(&super::paths::state_root(), dir, ADMINS_AND_OWNER, ADMINS_AND_OWNER)
}

/// [`ensure_private_dir`] for a directory another account works in — the
/// TLS terminator's: SYSTEM, Administrators and that account (`sid`), and
/// nobody else, after the same checks from the terminators' root,
/// `%ProgramData%\wireserve-tls`, down. The root is the default
/// instance's own directory: when `dir` is a named instance's below it,
/// the root gets SYSTEM, Administrators and `root_sid`, the default
/// instance's terminator when it has one. A named instance's terminator
/// needs no right on the root to reach its own folder: its token's
/// `SeChangeNotifyPrivilege` (bypassing traverse checks) takes it there.
pub fn ensure_private_dir_for(dir: &Path, sid: &str, root_sid: Option<&str>) -> io::Result<()> {
    let leaf = format!("{ADMINS_ONLY}(A;OICI;FA;;;{sid})");
    let root = match root_sid {
        Some(root_sid) => format!("{ADMINS_ONLY}(A;OICI;FA;;;{root_sid})"),
        None => ADMINS_ONLY.to_string(),
    };
    ensure_private_tree(&super::paths::tls_state_root(), dir, &root, &leaf)
}

/// Whether the owner of the object `h` (of the kind `kind`) is SYSTEM,
/// Administrators or this process's own user. Read from the open handle,
/// not by name, so it is the owner of exactly what was opened.
fn owner_trusted(h: HANDLE, kind: SE_OBJECT_TYPE) -> io::Result<bool> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: an open handle with READ_CONTROL; `owner` points into `sd`,
    // which the call allocates and the guard below frees.
    let code = unsafe {
        GetSecurityInfo(
            h,
            kind,
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
    Ok(unsafe {
        EqualSid(owner, system.as_ptr().cast_mut().cast()) != 0
            || EqualSid(owner, admins.as_ptr().cast_mut().cast()) != 0
            || EqualSid(owner, my_sid) != 0
    })
}

/// Refuses the named pipe `h` (at `path`) unless SYSTEM, Administrators or
/// this process's own user created it, and so owns it: anyone may create a
/// pipe of a free name, and a client that took another user's for the
/// daemon's would tell it what it asks and believe what it answers. The
/// daemon runs as LocalSystem, whose objects are owned by SYSTEM or, as its
/// token's default owner, Administrators — which no other user can make
/// the owner of anything. This process's own user is trusted too, as for
/// directories: an unelevated test's daemon is that, and it could only
/// deceive itself. `h` needs READ_CONTROL.
pub fn check_pipe_owner(h: HANDLE, path: &Path) -> io::Result<()> {
    if owner_trusted(h, SE_KERNEL_OBJECT)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} was not created by the wireserve daemon; refusing to talk to it", path.display()),
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
    Ok(lookup(&format!("{computer}\\{name}"))?
        .filter(|(_, kind, domain)| *kind == SidTypeAlias && domain.eq_ignore_ascii_case(&computer))
        .map(|(sid, ..)| sid))
}

/// The SID of the service `name`'s own account, `NT SERVICE\<name>`, as
/// SDDL writes it — what its process runs as under a virtual account.
/// `None` until the service exists.
pub fn service_sid(name: &str) -> io::Result<Option<String>> {
    Ok(lookup(&format!(r"NT SERVICE\{name}"))?
        .filter(|(sid, _, domain)| sid.starts_with("S-1-5-80-") && domain.eq_ignore_ascii_case("NT SERVICE"))
        .map(|(sid, ..)| sid))
}

/// `account`'s SID (as SDDL writes it), what kind of account it is, and
/// the domain it was found in; `None` for no such account.
fn lookup(account: &str) -> io::Result<Option<(String, SID_NAME_USE, String)>> {
    let account = wide(account);
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
    Ok(Some((sid_string(sid.as_mut_ptr().cast())?, kind, domain)))
}

/// `sid` as SDDL writes it (`S-1-5-...`).
fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text: PWSTR = std::ptr::null_mut();
    // SAFETY: a valid SID; `text` is allocated by the call and freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a NUL-terminated string from the call above, freed once.
    Ok(unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        out
    })
}

/// The SID of the user this process runs as, as SDDL writes it.
pub fn process_user_sid() -> io::Result<String> {
    let me = process_user()?;
    // SAFETY: `me` starts with a TOKEN_USER (8-aligned, as a `Vec<u64>`)
    // whose SID points further into `me`, which outlives the conversion.
    sid_string(unsafe { (*me.as_ptr().cast::<TOKEN_USER>()).User.Sid })
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
        ensure_private_dir(&sub).unwrap();
        std::fs::write(sub.join("f"), b"x").unwrap();
        assert_eq!(std::fs::read(sub.join("f")).unwrap(), b"x");
    }

    #[test]
    fn every_directory_from_the_root_down_is_checked() {
        let root = Path::new(r"C:\ProgramData\wireserve");
        let dir = root.join("instances").join("work");
        assert_eq!(chain(root, &dir), vec![root.to_path_buf(), root.join("instances"), dir.clone()]);
        // The default instance's directory is the root itself.
        assert_eq!(chain(root, root), vec![root.to_path_buf()]);
        // Anything not under the root is itself alone.
        let elsewhere = Path::new(r"C:\Users\me\AppData\Local\Temp\x");
        assert_eq!(chain(root, elsewhere), vec![elsewhere.to_path_buf()]);
        assert_eq!(chain(root, &root.join("..").join("other")), vec![root.join("..").join("other")]);
    }

    /// A named instance's directories, from a root of the test's own, are
    /// created, checked and kept usable; a junction anywhere on the way is
    /// refused, the leaf's or a parent's.
    #[test]
    fn a_tree_is_created_and_a_junction_in_it_refused() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("wireserve");
        let leaf = root.join("instances").join("work");
        ensure_private_tree(&root, &leaf, ADMINS_AND_OWNER, ADMINS_AND_OWNER).unwrap();
        std::fs::write(leaf.join("f"), b"x").unwrap();
        assert_eq!(std::fs::read(leaf.join("f")).unwrap(), b"x");
        // Again: nothing changes, nothing fails.
        ensure_private_tree(&root, &leaf, ADMINS_AND_OWNER, ADMINS_AND_OWNER).unwrap();

        // A junction for a parent, pointing at a directory of the user's.
        let target = base.path().join("target");
        std::fs::create_dir_all(target.join("work")).unwrap();
        let planted = base.path().join("planted");
        std::fs::create_dir_all(&planted).unwrap();
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(planted.join("instances"))
            .arg(&target)
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J needs no privilege");
        let err = ensure_private_tree(&planted, &planted.join("instances").join("work"), ADMINS_AND_OWNER, ADMINS_AND_OWNER)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        // And for the leaf itself.
        let err = ensure_private_tree(&planted, &planted.join("instances"), ADMINS_AND_OWNER, ADMINS_AND_OWNER).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
    }

    #[test]
    fn this_process_has_a_user_sid() {
        let sid = process_user_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
    }

    #[test]
    fn malformed_sddl_is_an_error() {
        assert!(SecurityDescriptor::from_sddl("D:(nonsense)").is_err());
    }

    /// Every service has a service SID, running or not: the Service
    /// Control Manager's own `NT SERVICE\EventLog`, say.
    #[test]
    fn a_service_has_a_sid_of_its_own_and_a_missing_one_none() {
        let sid = service_sid("EventLog").unwrap().expect("the event log service");
        assert!(sid.starts_with("S-1-5-80-"), "{sid}");
        assert_eq!(service_sid("wireserve-tls-no-such-instance").unwrap(), None);
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
