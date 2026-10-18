//! Files on Windows: no modes, as what protects a file is the ACL its
//! directory passes on (the state directory's own is set by
//! [`super::security`]), and the updates of shared files (see
//! `crate::fsutil`, `crate::hosts`).

use std::fs::OpenOptions;
use std::path::Path;

/// The Windows counterparts of Unix's (these are Win32 error codes, not
/// errnos): a file another process has open without delete sharing — the
/// DNS Client reading the hosts file, say — can't be renamed over.
pub const RENAME_FALLBACK_ERRORS: [i32; 4] = [
    5,  // ERROR_ACCESS_DENIED
    17, // ERROR_NOT_SAME_DEVICE
    19, // ERROR_WRITE_PROTECT
    32, // ERROR_SHARING_VIOLATION
];

/// Nothing: the new file takes its directory's ACL.
pub fn create_with_mode(_options: &mut OpenOptions, _mode: u32) {}

/// The Windows counterpart of `0700`: SYSTEM and Administrators only.
pub fn make_private_dir(path: &Path) -> std::io::Result<()> {
    super::security::restrict_to_admins(path)
}

/// Runs a read-modify-write of `path` under an exclusive lock (see the
/// Unix version). On Windows the lock is on a file of its own next to the
/// hosts file, `.<name>.wireserve-lock`, which is never renamed over, so
/// there is no retry dance. It lives in `drivers\etc`, where only
/// administrators can create files, so no one else can hold it. Released
/// by the kernel when the handle closes, the holder dying included. The
/// file stays behind, empty: removing it would race the next writer
/// opening it.
pub fn lock_for_update<T>(path: &Path, f: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut lock_name = std::ffi::OsString::from(".");
    lock_name.push(name);
    lock_name.push(".wireserve-lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path.with_file_name(lock_name))?;
    lock.lock()?;
    f()
}

/// Replaces `path` with `contents` atomically.
pub fn replace_keeping_mode(path: &Path, contents: &str) -> std::io::Result<()> {
    // No mode to preserve: the new file takes the `etc` directory's ACL,
    // which is what the hosts file it replaces had.
    crate::fsutil::atomic_write(path, contents.as_bytes(), 0o644)
}
