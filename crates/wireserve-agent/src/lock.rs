//! The two kinds of exclusivity several agents on one host depend on.
//!
//! **Instance lock** — one process per instance. An `flock` on a file
//! next to the instance's state, because the state *is* the instance: two
//! daemons on the same state file would register the same identity twice
//! and overwrite each other's saves, and a `join` under a running daemon
//! would swap its keys out from under it. Scoped to the filesystem, like
//! the thing it protects.
//!
//! **Interface claims** — one agent per interface name. Every piece of
//! firewall state an agent owns is keyed on its interface name, so the
//! name is what other agents need to see as taken, both while choosing a
//! name and when deciding whether a tagged rule somewhere belongs to a
//! running agent or is a leftover. The claim is a listening Unix socket
//! in the *abstract* namespace, `@wireserve/if/<ifname>`:
//! - abstract sockets are scoped to the network namespace, exactly like
//!   interface names and nftables tables — two containers sharing the
//!   host's network see each other's claims even with separate
//!   filesystems, and two network namespaces never collide;
//! - binding is atomic, so two agents starting at once can't both take a
//!   name;
//! - the kernel releases it the moment the process dies, so a crash never
//!   leaves a stale claim behind.
//!
//! Abstract sockets have no permissions, so any local user could bind one
//! of these names first. A claim only counts when the holder has the same
//! effective uid as us (checked with `SO_PEERCRED`); a squatter can make
//! an agent skip a name, but can't make a dead agent's firewall rules look
//! alive or be taken for a running agent.

use std::fs::File;
use std::io;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use crate::paths::Instance;

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error(
        "another wireserve process is already using instance '{instance}' (it holds \
         {}); stop it first, or use a different --instance",
        path.display()
    )]
    Busy { instance: String, path: PathBuf },
    #[error("could not take the instance lock {}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },
}

/// Held for as long as this process uses the instance. Released by the
/// kernel when the file is closed, including on a crash.
#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
}

pub fn lock_instance(instance: &Instance) -> Result<InstanceLock, LockError> {
    lock_file(instance.name(), instance.lock_path())
}

#[cfg(unix)]
fn lock_file(instance: &str, path: PathBuf) -> Result<InstanceLock, LockError> {
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
    Ok(InstanceLock { _file: file })
}

/// The Windows instance lock: a byte-range lock on the same file
/// (`LockFileEx`), released by the kernel when the handle closes or the
/// process dies, like `flock`. The directory is made private
/// (`crate::winsec`) first — it is the state directory.
#[cfg(windows)]
fn lock_file(instance: &str, path: PathBuf) -> Result<InstanceLock, LockError> {
    let io_err = |source| LockError::Io {
        path: path.clone(),
        source,
    };
    if let Some(parent) = path.parent() {
        crate::winsec::ensure_private_dir(parent).map_err(io_err)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(io_err)?;
    match file.try_lock() {
        Ok(()) => Ok(InstanceLock { _file: file }),
        Err(std::fs::TryLockError::WouldBlock) => Err(LockError::Busy {
            instance: instance.to_string(),
            path,
        }),
        Err(std::fs::TryLockError::Error(e)) => Err(io_err(e)),
    }
}

/// Who holds an interface name's claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holder {
    Nobody,
    /// A process running as our own effective uid — for all practical
    /// purposes another wireserve agent.
    Agent { pid: i32 },
    /// Another wireserve agent, where the claim doesn't say which process
    /// (Windows: only an administrator can create one, see `windows`).
    #[cfg(windows)]
    AnotherAgent,
    /// Bound by a process of another user. Never counts as an agent.
    Other { pid: i32, uid: u32 },
    /// Couldn't tell (the probe failed in some unexpected way). Treated
    /// as taken wherever that is the safe reading.
    Unknown(String),
}

impl Holder {
    /// Whether a running agent owns the name. `Unknown` counts: the only
    /// thing this decides is whether another agent's firewall rules may be
    /// deleted as leftovers, and when in doubt they stay.
    #[must_use]
    pub fn is_agent(&self) -> bool {
        #[cfg(windows)]
        if *self == Holder::AnotherAgent {
            return true;
        }
        matches!(self, Holder::Agent { .. } | Holder::Unknown(_))
    }
}

impl std::fmt::Display for Holder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Holder::Nobody => write!(f, "not claimed"),
            Holder::Agent { pid } => write!(f, "claimed by another wireserve agent (pid {pid})"),
            #[cfg(windows)]
            Holder::AnotherAgent => write!(f, "claimed by another wireserve agent"),
            Holder::Other { pid, uid } => {
                write!(f, "its claim socket is held by pid {pid}, which runs as uid {uid} and is not a wireserve agent")
            }
            Holder::Unknown(why) => write!(f, "its claim could not be checked ({why})"),
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{holder, IfnameClaim};

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener};

    use super::Holder;

    fn claim_name(ifname: &str) -> String {
        format!("wireserve/if/{ifname}")
    }

    /// This process's claim on an interface name.
    #[derive(Debug)]
    pub struct IfnameClaim {
        ifname: String,
        listener: UnixListener,
    }

    impl IfnameClaim {
        /// Takes the claim, or reports who has it.
        pub fn take(ifname: &str) -> io::Result<Result<Self, Holder>> {
            let addr = SocketAddr::from_abstract_name(claim_name(ifname).as_bytes())?;
            match UnixListener::bind_addr(&addr) {
                Ok(listener) => Ok(Ok(Self {
                    ifname: ifname.to_string(),
                    listener,
                })),
                Err(e) if e.kind() == io::ErrorKind::AddrInUse => Ok(Err(holder(ifname))),
                Err(e) => Err(e),
            }
        }

        #[must_use]
        pub fn ifname(&self) -> &str {
            &self.ifname
        }

        /// Keeps the claim for the rest of this process's life. Other
        /// agents check it by connecting; a thread accepts and drops those
        /// connections so they never pile up in the backlog.
        pub fn hold(self) {
            let listener = self.listener;
            let spawned = std::thread::Builder::new()
                .name("ifname-claim".into())
                .spawn(move || {
                    for conn in listener.incoming() {
                        drop(conn);
                    }
                });
            if let Err(e) = spawned {
                tracing::warn!(error = %e, "could not start the interface-claim thread; other agents' checks may stall");
            }
        }
    }

    /// Who holds `ifname`'s claim. Connects without blocking: a squatter
    /// that listens but never accepts fills its backlog, and a blocking
    /// connect would then hang whoever is asking.
    #[must_use]
    pub fn holder(ifname: &str) -> Holder {
        match probe(ifname) {
            Ok(h) => h,
            Err(e) => Holder::Unknown(e.to_string()),
        }
    }

    fn probe(ifname: &str) -> io::Result<Holder> {
        let name = claim_name(ifname);
        // SAFETY: zeroed sockaddr_un is valid; the name fits (checked).
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        if name.len() + 1 > addr.sun_path.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "claim name too long"));
        }
        // sun_path[0] stays NUL: that is what makes the address abstract.
        for (dst, src) in addr.sun_path[1..].iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }
        let len = std::mem::size_of::<libc::sa_family_t>() + 1 + name.len();

        // SAFETY: plain syscalls; the descriptor is owned by `fd` from here on.
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let rc = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                len as libc::socklen_t,
            )
        };
        if rc != 0 {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::ECONNREFUSED) => Ok(Holder::Nobody),
                Some(libc::EAGAIN) => Ok(Holder::Unknown("its backlog is full".into())),
                _ => Err(err),
            };
        }

        // SAFETY: `cred` is a plain struct sized by `len`.
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::addr_of_mut!(cred).cast::<libc::c_void>(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: no preconditions.
        let euid = unsafe { libc::geteuid() };
        Ok(if cred.uid == euid {
            Holder::Agent { pid: cred.pid }
        } else {
            Holder::Other {
                pid: cred.pid,
                uid: cred.uid,
            }
        })
    }
}

#[cfg(windows)]
pub use windows::{holder, IfnameClaim};

/// Interface claims on Windows: a named file mapping,
/// `Global\wireserve-if-<ifname>`. What makes the abstract socket right on
/// Linux holds here too: creating one is atomic, the kernel destroys it
/// when the last handle closes — the holder dying included — and the
/// `Global\` namespace is host-wide.
///
/// A file mapping, not an event or a mutex, because it is the one kind of
/// object whose creation in `Global\` takes `SeCreateGlobalPrivilege`
/// (outside session 0), which only administrators and services hold. So
/// a user can't take a name first, and whoever holds one is another
/// agent. Its contents are never used: one page, never mapped.
#[cfg(windows)]
mod windows {
    use std::io;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Memory::{CreateFileMappingW, OpenFileMappingW, FILE_MAP_READ, PAGE_READONLY};

    use super::Holder;
    use crate::winnet::wide;
    use crate::winsec::{SecurityDescriptor, ADMINS_ONLY};

    fn claim_name(ifname: &str) -> String {
        format!(r"Global\wireserve-if-{ifname}")
    }

    /// This process's claim on an interface name.
    #[derive(Debug)]
    pub struct IfnameClaim {
        ifname: String,
        handle: HANDLE,
    }

    // SAFETY: kernel object handles may be used and closed from any thread.
    unsafe impl Send for IfnameClaim {}

    impl Drop for IfnameClaim {
        fn drop(&mut self) {
            // SAFETY: a handle we own, closed once.
            unsafe { CloseHandle(self.handle) };
        }
    }

    impl IfnameClaim {
        /// Takes the claim, or reports who has it.
        pub fn take(ifname: &str) -> io::Result<Result<Self, Holder>> {
            let sd = SecurityDescriptor::from_sddl(ADMINS_ONLY)?;
            let sa = sd.attributes();
            let name = wide(&claim_name(ifname));
            // SAFETY: valid attributes and a NUL-terminated name for the call;
            // a page-file-backed mapping of one page.
            let handle = unsafe { CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READONLY, 0, 1, name.as_ptr()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: read straight after the call that set it.
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                // SAFETY: the handle the call just returned.
                unsafe { CloseHandle(handle) };
                return Ok(Err(Holder::AnotherAgent));
            }
            Ok(Ok(Self {
                ifname: ifname.to_string(),
                handle,
            }))
        }

        #[must_use]
        pub fn ifname(&self) -> &str {
            &self.ifname
        }

        /// Keeps the claim for the rest of this process's life.
        pub fn hold(self) {
            std::mem::forget(self);
        }
    }

    /// Who holds `ifname`'s claim: whoever has the mapping open. Opening it
    /// keeps it alive for a moment, so a claim taken at that very instant
    /// sees it taken — the safe way round.
    #[must_use]
    pub fn holder(ifname: &str) -> Holder {
        let name = wide(&claim_name(ifname));
        // SAFETY: a NUL-terminated name.
        let handle = unsafe { OpenFileMappingW(FILE_MAP_READ, 0, name.as_ptr()) };
        if !handle.is_null() {
            // SAFETY: the handle the call just returned.
            unsafe { CloseHandle(handle) };
            return Holder::AnotherAgent;
        }
        // SAFETY: read straight after the call that set it.
        match unsafe { GetLastError() } {
            ERROR_FILE_NOT_FOUND => Holder::Nobody,
            code => Holder::Unknown(io::Error::from_raw_os_error(code as i32).to_string()),
        }
    }
}

/// Stand-ins where there are no abstract sockets: every claim succeeds
/// and nobody else ever holds one, which is what a single agent per host
/// amounts to.
#[cfg(not(any(target_os = "linux", windows)))]
pub use fallback::{holder, IfnameClaim};

#[cfg(not(any(target_os = "linux", windows)))]
mod fallback {
    use super::Holder;

    #[derive(Debug)]
    pub struct IfnameClaim {
        ifname: String,
    }

    impl IfnameClaim {
        pub fn take(ifname: &str) -> std::io::Result<Result<Self, Holder>> {
            Ok(Ok(Self {
                ifname: ifname.to_string(),
            }))
        }
        #[must_use]
        pub fn ifname(&self) -> &str {
            &self.ifname
        }
        pub fn hold(self) {}
    }

    #[must_use]
    pub fn holder(_ifname: &str) -> Holder {
        Holder::Nobody
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Abstract names are shared with everything else in this network
    /// namespace — a real agent included — so tests use names nothing
    /// else will.
    #[cfg(target_os = "linux")]
    fn unique(tag: &str) -> String {
        format!("t{}{tag}", std::process::id())
    }

    #[test]
    fn instance_lock_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("agent.lock");
        let first = lock_file("t", path.clone()).unwrap();
        let second = lock_file("t", path.clone());
        assert!(matches!(second, Err(LockError::Busy { .. })), "{second:?}");
        drop(first);
        lock_file("t", path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_lock_path_is_refused_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        let path = dir.path().join("agent.lock");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(lock_file("t", path).is_err());
        assert!(!target.exists(), "the symlink's target must not have been created");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_claim_is_exclusive_visible_and_released_on_drop() {
        let name = unique("a");
        assert_eq!(holder(&name), Holder::Nobody);

        let claim = IfnameClaim::take(&name).unwrap().unwrap();
        assert_eq!(claim.ifname(), name);
        let pid = i32::try_from(std::process::id()).unwrap();
        assert_eq!(holder(&name), Holder::Agent { pid });
        assert_eq!(IfnameClaim::take(&name).unwrap().unwrap_err(), Holder::Agent { pid });

        drop(claim);
        assert_eq!(holder(&name), Holder::Nobody);
        assert!(IfnameClaim::take(&name).unwrap().is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_held_claim_survives_many_probes() {
        let name = unique("b");
        IfnameClaim::take(&name).unwrap().unwrap().hold();
        // Far more than any listen backlog: the accept thread keeps up.
        for _ in 0..1000 {
            assert!(holder(&name).is_agent());
        }
    }

    #[test]
    fn only_agents_and_unknowns_count_as_live() {
        assert!(!Holder::Nobody.is_agent());
        assert!(!Holder::Other { pid: 1, uid: 1000 }.is_agent());
        assert!(Holder::Agent { pid: 1 }.is_agent());
        assert!(Holder::Unknown("x".into()).is_agent());
    }
}
