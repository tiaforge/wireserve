//! Shared atomic-write helpers. Both the managed `/etc/hosts` block (§6)
//! and the local state file (bearer token, WireGuard private key — §7,
//! mode 600) need "write a temp file, then rename over the target" so a
//! crash mid-write can never leave a half-written file in place — a
//! `rename()` within the same filesystem is atomic.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Writes `contents` to `path` atomically, creating the file at exactly
/// `mode` from the moment it's created (not a post-hoc `chmod`, which would
/// leave a window where the file exists with default permissions).
///
/// The temp file is created in the same directory as `path` so the final
/// `rename` is guaranteed to be on the same filesystem (required for
/// atomicity — a cross-filesystem "rename" silently falls back to
/// copy+delete on some platforms, which is not atomic).
pub fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp_name = {
        let mut n = std::ffi::OsString::from(".");
        n.push(file_name);
        n.push(".tmp");
        n
    };
    let tmp_path = dir.join(tmp_name);

    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp_path)?;
    f.write_all(contents)?;
    f.sync_all()?;
    drop(f);

    std::fs::rename(&tmp_path, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn writes_contents_and_exact_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        atomic_write(&path, b"hello", 0o600).unwrap();

        let contents = std::fs::read(&path).unwrap();
        assert_eq!(contents, b"hello");

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "file must be created at exactly the requested mode");
    }

    #[test]
    fn overwrites_existing_file_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        atomic_write(&path, b"version-1", 0o600).unwrap();
        atomic_write(&path, b"version-2", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"version-2");

        // No leftover temp file.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp file must not survive a successful write");
    }

    #[test]
    fn does_not_touch_original_when_write_target_directory_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        atomic_write(&path, b"original", 0o600).unwrap();

        let bad_path = dir.path().join("missing-subdir").join("state.json");
        let err = atomic_write(&bad_path, b"should-not-apply", 0o600);
        assert!(err.is_err());

        // Original file, unrelated to bad_path, is untouched.
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
    }
}
