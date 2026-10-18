//! The instance lock on Unix: an `flock` (see `crate::lock`).

use std::io;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use crate::lock::{InstanceLock, LockError};

pub fn lock_file(instance: &str, path: PathBuf) -> Result<InstanceLock, LockError> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    let io_err = |source| LockError::Io {
        path: path.clone(),
        source,
    };
    if let Some(parent) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(io_err)?;
    }
    // O_NOFOLLOW: this runs as root, and a symlink planted at the lock
    // path would otherwise have root create (at mode 600) whatever file
    // it points to (security review finding #6). The directory is
    // root-only in every shipped deployment; this is the second layer.
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(io_err)?;
    // SAFETY: a plain syscall on a descriptor we own for the call's duration.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        return Err(if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            LockError::Busy {
                instance: instance.to_string(),
                path,
            }
        } else {
            io_err(err)
        });
    }
    Ok(InstanceLock::held_by(file))
}
