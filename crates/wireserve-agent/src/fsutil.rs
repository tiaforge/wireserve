//! Shared atomic-write helpers. Both the managed `/etc/hosts` block (§6)
//! and the local state file (bearer token, WireGuard private key — §7,
//! mode 600) need "write a temp file, then rename over the target" so a
//! crash mid-write can never leave a half-written file in place — a
//! `rename()` within the same filesystem is atomic.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// `EBUSY` — see the fallback note on `atomic_write` below.
const EBUSY: i32 = 16;
/// `EXDEV` — likewise.
const EXDEV: i32 = 18;

/// Writes `contents` to `path` atomically, creating the file at exactly
/// `mode` from the moment it's created (not a post-hoc `chmod`, which would
/// leave a window where the file exists with default permissions).
///
/// The temp file is created in the same directory as `path` so the final
/// `rename` is guaranteed to be on the same filesystem (required for
/// atomicity — a cross-filesystem "rename" silently falls back to
/// copy+delete on some platforms, which is not atomic).
///
/// **Falls back to a non-atomic in-place write if `rename()` fails with
/// `EBUSY`/`EXDEV`.** Found by an actual containerized end-to-end test:
/// `/etc/hosts` inside *every* container runtime (Podman, Docker,
/// Kubernetes) is a bind-mounted file — including a container's own
/// hosts file with no explicit `-v` flag at all, not just the
/// `-v /etc/hosts:/etc/hosts` pattern this project's own Dockerfile
/// documents — and `rename()` onto a bind-mounted path fails with EBUSY,
/// since the mount point's inode can't be replaced. On a normal
/// filesystem (the primary systemd/bare-metal/VM deployment this project
/// targets) this fallback path is never exercised. Inside a container, it
/// trades the crash-atomicity guarantee for the hosts-file sync actually
/// working at all — an accepted, documented tradeoff, not a silent
/// downgrade: see PLAN.md decisions log.
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

    // `create_new` (O_CREAT|O_EXCL), not `create`: O_EXCL refuses to
    // follow a symlink and refuses an existing file, so a leftover temp
    // path — whether from a crashed earlier run or planted deliberately —
    // can neither redirect this write somewhere else nor leave the file
    // at permissions from before, since `mode` is only honoured when the
    // file is actually created. Any stale temp file is removed first, so
    // the stricter open does not turn a crash into a permanent failure.
    // The directories these files live in are root-only in every shipped
    // deployment, so this is a second layer rather than the only one.
    let _ = std::fs::remove_file(&tmp_path);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp_path)?;
    f.write_all(contents)?;
    f.sync_all()?;
    drop(f);

    match std::fs::rename(&tmp_path, path) {
        Ok(()) => Ok(()),
        Err(e) if matches!(e.raw_os_error(), Some(EBUSY) | Some(EXDEV)) => {
            let result = write_in_place(path, contents);
            let _ = std::fs::remove_file(&tmp_path);
            result
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Non-atomic fallback: truncate-and-write the target file directly,
/// preserving whatever permissions it already has (no `O_CREAT` needed
/// for a path that already exists, so `OpenOptions::mode` — only applied
/// on creation — never comes into play here).
fn write_in_place(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new().write(true).truncate(true).open(path)?;
    f.write_all(contents)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // The EBUSY/EXDEV-triggering condition itself (a real bind mount) needs
    // privileges this test suite can't assume — it's exercised for real by
    // an actual containerized deployment test instead (see PLAN.md decisions
    // log). This test covers `write_in_place`'s own contract directly: it
    // writes contents in place and leaves the target's existing permission
    // bits untouched, since a container's already-bind-mounted /etc/hosts
    // typically isn't mode 600 the way atomic_write's happy path creates
    // new files.
    #[test]
    fn write_in_place_writes_contents_and_preserves_existing_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, "old content").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_in_place(&path, b"new content").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new content");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "write_in_place must not alter existing permissions");
    }

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
    fn does_not_follow_a_symlink_planted_at_the_temp_path() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("attacker-controlled");
        std::fs::write(&target, "untouched").unwrap();
        let path = dir.path().join("state.json");
        std::os::unix::fs::symlink(&target, dir.path().join(".state.json.tmp")).unwrap();

        atomic_write(&path, b"secret", 0o600).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
    }

    #[test]
    fn recovers_from_a_leftover_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(dir.path().join(".state.json.tmp"), "stale junk").unwrap();

        atomic_write(&path, b"fresh", 0o600).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"fresh");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
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
