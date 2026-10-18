//! The agent's IPC endpoints on Unix: sockets, each in a directory of its
//! own, root-only or shared with one group by their modes (see
//! `crate::ipc::server`, `crate::ipc::tls`).

use std::path::Path;

use tokio::net::{UnixListener, UnixStream};

/// Who an endpoint may be shared with: a group, by its id.
pub type Principal = u32;

/// What the endpoint is called in the log.
pub const ENDPOINT: &str = "socket";
/// Who may use an endpoint shared with nobody.
pub const PRIVATE: &str = "root-only";
/// What to do about being refused (`ipc::client`).
pub const DENIED_HINT: &str = "run this with sudo, or add yourself to the `wireserve` group \
     (`sudo usermod -aG wireserve $USER`, then log in again). The daemon shares its socket with \
     that group only if the group existed when it started";

/// The group named `name`, if this host has one.
#[must_use]
pub fn group(name: &str) -> Option<Principal> {
    lookup_group(name)
}

/// Who the TLS terminator's socket is shared with: its own group
/// (`ipc::tls::tls_group_name`), the one its unit runs it as.
#[must_use]
pub fn terminator(_instance: &crate::paths::Instance) -> Option<Principal> {
    crate::ipc::tls::tls_group_name().and_then(|g| lookup_group(&g))
}

/// A listening socket.
pub struct Listener(UnixListener);

impl Listener {
    /// Binds the socket (removing any stale one from a previous run).
    ///
    /// With no `group` the socket and its parent directory are root-only
    /// (0600/0700). With one, the same two are handed to that group (0660/0750),
    /// so its members can use `wireserve <service>`/`status`/... without sudo. Modes are
    /// set explicitly rather than left to umask, and the directory is only
    /// opened to the group after the socket is final, so there is no moment
    /// when the group can reach a socket with default permissions.
    pub fn bind(path: &Path, shared_with: Option<&Principal>) -> std::io::Result<Self> {
        Ok(Self(bind_socket(path, shared_with.copied())?))
    }

    pub async fn accept(&mut self) -> std::io::Result<UnixStream> {
        Ok(self.0.accept().await?.0)
    }
}

/// Connects to the endpoint at `path`.
pub async fn connect(path: &Path) -> std::io::Result<UnixStream> {
    UnixStream::connect(path).await
}

fn lookup_group(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0u8; 4096];
    loop {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut out: *mut libc::group = std::ptr::null_mut();
        let rc = unsafe {
            libc::getgrnam_r(cname.as_ptr(), &mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut out)
        };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            let doubled = buf.len() * 2;
            buf.resize(doubled, 0);
            continue;
        }
        return if rc == 0 && !out.is_null() { Some(grp.gr_gid) } else { None };
    }
}

fn bind_socket(socket_path: &Path, gid: Option<u32>) -> std::io::Result<UnixListener> {
    let parent = socket_path.parent();
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)?;
        set_mode(parent, 0o700)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    let shared = match gid {
        None => false,
        // Sharing is a convenience; failing at it (a hand-written unit
        // without CAP_CHOWN, say) must leave a working root-only socket,
        // not a daemon nobody can talk to.
        Some(gid) => match share_with_group(socket_path, parent, gid) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "could not share the IPC socket with the group; it stays root-only");
                false
            }
        },
    };
    if !shared {
        set_mode(socket_path, 0o600)?;
        if let Some(parent) = parent {
            set_mode(parent, 0o700)?;
        }
    }
    Ok(listener)
}

/// The socket first, the directory last: until the directory opens, the
/// group cannot reach the socket whatever its permissions are.
fn share_with_group(socket_path: &Path, parent: Option<&Path>, gid: u32) -> std::io::Result<()> {
    set_group(socket_path, gid)?;
    set_mode(socket_path, 0o660)?;
    if let Some(parent) = parent {
        set_group(parent, gid)?;
        set_mode(parent, 0o750)?;
    }
    Ok(())
}

fn set_group(path: &Path, gid: u32) -> std::io::Result<()> {
    std::os::unix::fs::chown(path, None, Some(gid))
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn socket_without_a_group_is_root_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run/agent.sock");
        let _l = bind_socket(&path, None).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[tokio::test]
    async fn socket_with_a_group_is_shared_with_exactly_that_group() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run/agent.sock");
        // A group the test process may chown to without privilege.
        let gid = unsafe { libc::getegid() };
        let _l = bind_socket(&path, Some(gid)).unwrap();
        let sock = std::fs::metadata(&path).unwrap();
        let parent = std::fs::metadata(path.parent().unwrap()).unwrap();
        assert_eq!(sock.permissions().mode() & 0o777, 0o660);
        assert_eq!(parent.permissions().mode() & 0o777, 0o750);
        assert_eq!((sock.gid(), parent.gid()), (gid, gid));
    }

    #[tokio::test]
    async fn failing_to_share_leaves_a_root_only_socket_not_an_error() {
        use std::os::unix::fs::PermissionsExt;
        // Root may chown to any group, so there is nothing to fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run/agent.sock");
        // Group 0 is one an unprivileged test process is not in.
        let _l = bind_socket(&path, Some(0)).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[test]
    fn a_missing_group_means_no_sharing() {
        assert_eq!(lookup_group("wireserve-no-such-group-xyz"), None);
        assert_eq!(lookup_group("root"), Some(0));
    }
}
