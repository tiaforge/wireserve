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

impl InstanceLock {
    /// The lock `file` holds, which lasts as long as it stays open.
    pub(crate) fn held_by(file: File) -> Self {
        Self { _file: file }
    }
}

pub fn lock_instance(instance: &Instance) -> Result<InstanceLock, LockError> {
    crate::platform::lock::lock_file(instance.name(), instance.lock_path())
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
        matches!(self, Holder::Agent { .. } | Holder::AnotherAgent | Holder::Unknown(_))
    }
}

impl std::fmt::Display for Holder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Holder::Nobody => write!(f, "not claimed"),
            Holder::Agent { pid } => write!(f, "claimed by another wireserve agent (pid {pid})"),
            Holder::AnotherAgent => write!(f, "claimed by another wireserve agent"),
            Holder::Other { pid, uid } => {
                write!(f, "its claim socket is held by pid {pid}, which runs as uid {uid} and is not a wireserve agent")
            }
            Holder::Unknown(why) => write!(f, "its claim could not be checked ({why})"),
        }
    }
}

pub use crate::platform::lock::{holder, IfnameClaim};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::lock::lock_file;

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
