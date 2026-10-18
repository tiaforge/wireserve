//! The instance lock on Windows (see `crate::lock`).

use std::path::PathBuf;

use crate::lock::{InstanceLock, LockError};

/// The Windows instance lock: a byte-range lock on the same file
/// (`LockFileEx`), released by the kernel when the handle closes or the
/// process dies, like `flock`. The directory is made private
/// (`crate::platform::windows::security`) first — it is the state directory.
pub fn lock_file(instance: &str, path: PathBuf) -> Result<InstanceLock, LockError> {
    let io_err = |source| LockError::Io {
        path: path.clone(),
        source,
    };
    if let Some(parent) = path.parent() {
        crate::platform::windows::security::ensure_private_dir(parent).map_err(io_err)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(io_err)?;
    match file.try_lock() {
        Ok(()) => Ok(InstanceLock::held_by(file)),
        Err(std::fs::TryLockError::WouldBlock) => Err(LockError::Busy {
            instance: instance.to_string(),
            path,
        }),
        Err(std::fs::TryLockError::Error(e)) => Err(io_err(e)),
    }
}
