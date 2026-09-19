//! Well-known filesystem locations, per agent instance.
//!
//! One host can run several agents side by side — one per mesh, or one
//! per identity in the same mesh — each as a named *instance* with its
//! own state, IPC socket, WireGuard interface, firewall tables and
//! hosts-file block. The unnamed default instance keeps the paths every
//! existing deployment already uses, so an upgrade moves nothing on disk:
//!
//! | instance  | state                                     | socket                        |
//! |-----------|-------------------------------------------|-------------------------------|
//! | `default` | `/var/lib/wireserve/agent-state.json`     | `/run/wireserve/agent.sock`   |
//! | `<n>`     | `/var/lib/wireserve-<n>/agent-state.json` | `/run/wireserve-<n>/agent.sock` |
//!
//! Sibling directories rather than nesting named instances under the
//! default's: systemd removes a unit's `RuntimeDirectory` when the unit
//! stops, so nesting would have stopping the default instance delete the
//! sockets of every other one while they are still running.
//!
//! The roots are overridable via env so tests (and anyone running the
//! agent rootless for development) don't need to write to `/run` or
//! `/var/lib`; `WIRESERVE_STATE_PATH`/`WIRESERVE_SOCKET_PATH` still
//! override the full path for whichever instance is running.

use std::path::PathBuf;

use crate::state::AgentState;

pub const DEFAULT_INSTANCE: &str = "default";
const DIR_PREFIX: &str = "wireserve";
const STATE_FILE: &str = "agent-state.json";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "invalid instance name {0:?}: use 1-32 characters from A-Z, a-z, 0-9, '_', '-', \
     starting with a letter or digit"
)]
pub struct InvalidInstance(pub String);

/// A validated instance name. It ends up in directory names, the
/// hosts-file markers and lock names, so it is restricted to a set of
/// characters that is plain in all of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    name: String,
}

impl Default for Instance {
    fn default() -> Self {
        Self {
            name: DEFAULT_INSTANCE.to_string(),
        }
    }
}

impl Instance {
    pub fn new(name: &str) -> Result<Self, InvalidInstance> {
        let ok = (1..=32).contains(&name.len())
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
        if ok {
            Ok(Self { name: name.to_string() })
        } else {
            Err(InvalidInstance(name.to_string()))
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn is_default(&self) -> bool {
        self.name == DEFAULT_INSTANCE
    }

    fn dir_name(&self) -> String {
        if self.is_default() {
            DIR_PREFIX.to_string()
        } else {
            format!("{DIR_PREFIX}-{}", self.name)
        }
    }

    #[must_use]
    pub fn state_path(&self) -> PathBuf {
        std::env::var("WIRESERVE_STATE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| state_root().join(self.dir_name()).join(STATE_FILE))
    }

    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        std::env::var("WIRESERVE_SOCKET_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| run_root().join(self.dir_name()).join("agent.sock"))
    }

    /// Next to the state file: the lock guards that file, so it has to
    /// live wherever the state does — including under a
    /// `WIRESERVE_STATE_PATH` override.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.state_path().with_file_name("agent.lock")
    }

    /// The label on this instance's hosts-file block. `None` for the
    /// default instance, whose block keeps the unlabelled markers written
    /// by every earlier version.
    #[must_use]
    pub fn hosts_label(&self) -> Option<&str> {
        (!self.is_default()).then_some(self.name.as_str())
    }
}

fn state_root() -> PathBuf {
    std::env::var("WIRESERVE_STATE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib"))
}

fn run_root() -> PathBuf {
    std::env::var("WIRESERVE_RUN_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run"))
}

/// Which instance a directory under the state root belongs to, if any.
fn instance_of_dir(dir_name: &str) -> Option<Instance> {
    if dir_name == DIR_PREFIX {
        return Some(Instance::default());
    }
    Instance::new(dir_name.strip_prefix(DIR_PREFIX)?.strip_prefix('-')?).ok()
}

/// The saved state of every *other* instance on this host, running or
/// not. Used to keep one instance from picking an interface name or
/// listen port another one has already made its own — including one that
/// is merely stopped right now and will want them back. A state file that
/// can't be read is skipped with a warning: it can't claim anything, and
/// refusing to start over someone else's broken file would be worse.
#[must_use]
pub fn other_instances(own: &Instance) -> Vec<(Instance, AgentState)> {
    let Ok(entries) = std::fs::read_dir(state_root()) else {
        return Vec::new();
    };
    let own_state = own.state_path();
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Some(instance) = entry.file_name().to_str().and_then(instance_of_dir) else {
            continue;
        };
        let path = entry.path().join(STATE_FILE);
        if instance == *own || path == own_state || !path.exists() {
            continue;
        }
        match AgentState::load(&path) {
            Ok(state) => out.push((instance, state)),
            Err(e) => tracing::warn!(path = %path.display(), error = %e, "ignoring unreadable state of another instance"),
        }
    }
    out.sort_by(|a, b| a.0.name().cmp(b.0.name()));
    out
}

/// Linux/macOS/BSD hosts file. Spec §6 names the Windows path too
/// (`C:\Windows\System32\drivers\etc\hosts`), but Windows support is
/// explicitly deferred (spec "open items"), and this crate's atomic file
/// writer is Unix-only, so no Windows branch is kept here — it would be
/// dead code that cannot compile on the platform it claims to support.
/// Shared by every instance; each one owns only its own marked block.
pub fn hosts_path() -> PathBuf {
    std::env::var("WIRESERVE_HOSTS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/hosts"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_names_are_plain() {
        for ok in ["default", "work", "mesh-2", "a", "A_b-9", &"x".repeat(32)] {
            assert!(Instance::new(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-x", "_x", "a.b", "a/b", "a b", "../x", &"x".repeat(33)] {
            assert!(Instance::new(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn default_instance_keeps_the_historic_directory_names() {
        let d = Instance::default();
        assert!(d.is_default());
        assert_eq!(d.dir_name(), "wireserve");
        assert_eq!(d.hosts_label(), None);
        let w = Instance::new("work").unwrap();
        assert_eq!(w.dir_name(), "wireserve-work");
        assert_eq!(w.hosts_label(), Some("work"));
    }

    #[test]
    fn directories_map_back_to_their_instance() {
        assert_eq!(instance_of_dir("wireserve"), Some(Instance::default()));
        assert_eq!(instance_of_dir("wireserve-work"), Instance::new("work").ok());
        assert_eq!(instance_of_dir("wireserve-"), None);
        assert_eq!(instance_of_dir("wireservex"), None);
        assert_eq!(instance_of_dir("wireserve-a.b"), None);
        assert_eq!(instance_of_dir("other"), None);
    }
}
