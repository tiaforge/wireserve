//! Files on Unix: modes set as files are created, the directories the
//! state lives in, and the rename-based updates of shared files (see
//! `crate::fsutil`, `crate::hosts`).

use std::fs::OpenOptions;
use std::path::Path;

/// `EBUSY`/`EXDEV` come from a bind-mounted target (every container
/// runtime's `/etc/hosts`). `EROFS`/`EACCES`/`EPERM` come from the
/// opposite direction: a read-only or non-writable *directory* with a
/// writable file bind-mounted into it, which is exactly what
/// `ProtectSystem=strict` plus `ReadWritePaths=/etc/hosts` produces.
pub const RENAME_FALLBACK_ERRORS: [i32; 5] = [
    1,  // EPERM
    13, // EACCES
    16, // EBUSY
    18, // EXDEV
    30, // EROFS
];

/// The file `options` creates gets exactly `mode` from the moment it
/// exists.
pub fn create_with_mode(options: &mut OpenOptions, mode: u32) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(mode);
}

/// `0700`: the directory the state (keys, token) lives in.
pub fn make_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Runs a read-modify-write of `path` under an exclusive `flock`, so two
/// agent instances rewriting their own blocks at the same moment can't
/// each write back a copy missing the other's change.
///
/// The lock is on the file itself, and `atomic_write` replaces the file by
/// renaming a new one over it, so a lock taken while waiting may end up on
/// the replaced file rather than the current one. Checked after locking,
/// by comparing the locked descriptor's inode with the path's, and retried
/// until the two agree — the usual protocol for locking a file that is
/// updated by rename. A missing file has nothing to lock; the write that
/// creates it goes ahead unlocked.
pub fn lock_for_update<T>(path: &Path, f: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    loop {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return f(),
            Err(e) => return Err(e),
        };
        // SAFETY: a plain syscall on a descriptor that outlives the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let locked = file.metadata()?;
        match std::fs::metadata(path) {
            Ok(now) if now.dev() == locked.dev() && now.ino() == locked.ino() => return f(),
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return f(),
            Err(e) => return Err(e),
        }
    }
}

/// Replaces `path` with `contents` atomically, keeping the mode it had.
pub fn replace_keeping_mode(path: &Path, contents: &str) -> std::io::Result<()> {
    let mode = std::fs::metadata(path)
        .map(|m| {
            use std::os::unix::fs::PermissionsExt;
            m.permissions().mode() & 0o777
        })
        .unwrap_or(0o644);

    crate::fsutil::atomic_write(path, contents.as_bytes(), mode)
}
