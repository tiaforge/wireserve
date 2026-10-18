//! Well-known filesystem locations, per agent instance.
//!
//! One host can run several agents side by side — one per mesh, or one
//! per identity in the same mesh — each as a named *instance* with its
//! own state, IPC socket, WireGuard interface, firewall tables and
//! hosts-file block. The default instance keeps the paths every existing
//! deployment already uses, so an upgrade moves nothing on disk:
//!
//! | instance  | state                                               | socket                          |
//! |-----------|-----------------------------------------------------|---------------------------------|
//! | `default` | `/var/lib/wireserve/agent-state.json`               | `/run/wireserve/agent.sock`     |
//! | `<n>`     | `/var/lib/wireserve/instances/<n>/agent-state.json` | `/run/wireserve-<n>/agent.sock` |
//!
//! Each socket is root-only, or shared with the `wireserve` group when the
//! host has one (see `ipc::server::serve`).
//!
//! State nests under the default's directory, so one directory (and the
//! container image's one volume) holds every instance's keys. Sockets
//! don't: systemd removes a unit's `RuntimeDirectory` when the unit stops,
//! so nesting would have stopping the default instance delete the sockets
//! of every other one while they are still running.
//!
//! `WIRESERVE_STATE_ROOT` (default `/var/lib/wireserve`) and
//! `WIRESERVE_RUN_ROOT` (default `/run`) move all of it, so tests — and
//! anyone running the agent rootless for development — don't need to
//! write to `/run` or `/var/lib`.

use std::path::PathBuf;

use crate::state::AgentState;

pub const DEFAULT_INSTANCE: &str = "default";
const STATE_FILE: &str = "agent-state.json";
const INSTANCES_DIR: &str = "instances";

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

    fn state_dir(&self) -> PathBuf {
        if self.is_default() {
            crate::platform::paths::state_root()
        } else {
            crate::platform::paths::state_root().join(INSTANCES_DIR).join(&self.name)
        }
    }

    fn run_dir(&self) -> PathBuf {
        if self.is_default() {
            crate::platform::paths::run_root().join("wireserve")
        } else {
            crate::platform::paths::run_root().join(format!("wireserve-{}", self.name))
        }
    }

    #[must_use]
    pub fn state_path(&self) -> PathBuf {
        self.state_dir().join(STATE_FILE)
    }

    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.run_dir().join("agent.sock")
    }

    /// The TLS terminator's socket (PLAN.md M33): in a directory of its
    /// own, beside this instance's run directory rather than inside it —
    /// that one is root-only, and the terminator runs as its own user.
    #[must_use]
    pub fn tls_socket_path(&self) -> PathBuf {
        let dir = if self.is_default() {
            crate::platform::paths::run_root().join("wireserve-tls")
        } else {
            crate::platform::paths::run_root().join(format!("wireserve-tls-{}", self.name))
        };
        dir.join("tls.sock")
    }

    /// Where the TLS terminator keeps its certificates when not run by its
    /// unit, which gives it a state directory of its own.
    #[must_use]
    pub fn tls_state_dir(&self) -> PathBuf {
        let root = crate::platform::paths::tls_state_root();
        if self.is_default() {
            root
        } else {
            root.join(&self.name)
        }
    }

    /// The terminator's log on Windows (PLAN.md M50), in its own state
    /// directory: the agent's is not its to write.
    #[must_use]
    pub fn tls_log_path(&self) -> PathBuf {
        self.tls_state_dir().join("tls.log")
    }

    /// The service's log on Windows, beside the state: a service has no
    /// console, and the state directory is already private.
    #[must_use]
    pub fn log_path(&self) -> PathBuf {
        self.state_path().with_file_name("agent.log")
    }

    /// Next to the state file: the lock guards that file, so it has to
    /// live wherever the state does.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.state_path().with_file_name("agent.lock")
    }

    /// The label on this instance's hosts-file block. `None` for the
    /// default instance, whose block has unlabelled markers.
    #[must_use]
    pub fn hosts_label(&self) -> Option<&str> {
        (!self.is_default()).then_some(self.name.as_str())
    }
}

/// Every instance that has a state directory, the default one included.
pub fn all_instances() -> Vec<Instance> {
    let mut out = vec![Instance::default()];
    if let Ok(entries) = std::fs::read_dir(crate::platform::paths::state_root().join(INSTANCES_DIR)) {
        out.extend(
            entries
                .flatten()
                .filter_map(|e| e.file_name().to_str().and_then(|n| Instance::new(n).ok()))
                .filter(|i| !i.is_default()),
        );
    }
    out
}

/// The saved state of every *other* instance on this host, running or
/// not. Used to keep one instance from picking an interface name or
/// listen port another one has already made its own — including one that
/// is merely stopped right now and will want them back. A state file that
/// can't be read is skipped with a warning: it can't claim anything, and
/// refusing to start over someone else's broken file would be worse.
#[must_use]
pub fn other_instances(own: &Instance) -> Vec<(Instance, AgentState)> {
    let own_state = own.state_path();
    let mut out = Vec::new();
    for instance in all_instances() {
        let path = instance.state_path();
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

/// The hosts file (spec §6). Shared by every instance; each one owns only
/// its own marked block.
pub fn hosts_path() -> PathBuf {
    crate::platform::paths::hosts_path()
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

    /// One test for everything that reads the environment, so parallel
    /// tests never see each other's variables.
    #[test]
    fn layout_overrides_and_discovery() {
        let root = tempfile::tempdir().unwrap();
        // SAFETY: the only test in this crate that sets these variables.
        unsafe {
            std::env::set_var("WIRESERVE_STATE_ROOT", root.path().join("lib"));
            std::env::set_var("WIRESERVE_RUN_ROOT", root.path().join("run"));
        }
        let lib = root.path().join("lib");
        let run = root.path().join("run");
        let d = Instance::default();
        let w = Instance::new("work").unwrap();

        assert_eq!(d.state_path(), lib.join("agent-state.json"));
        assert_eq!(d.socket_path(), run.join("wireserve/agent.sock"));
        assert_eq!(d.lock_path(), lib.join("agent.lock"));
        assert_eq!(w.state_path(), lib.join("instances/work/agent-state.json"));
        assert_eq!(w.socket_path(), run.join("wireserve-work/agent.sock"));
        assert_eq!(w.lock_path(), lib.join("instances/work/agent.lock"));
        assert_eq!((d.hosts_label(), w.hosts_label()), (None, Some("work")));

        // Discovery: every other instance with a state file.
        let save = |i: &Instance, port| {
            AgentState {
                listen_port: Some(port),
                ..Default::default()
            }
            .save(&i.state_path())
            .unwrap();
        };
        save(&d, 51820);
        save(&w, 51821);
        std::fs::create_dir_all(lib.join("instances/not.valid")).unwrap();
        std::fs::create_dir_all(lib.join("instances/empty")).unwrap();
        let ports = |own: &Instance| -> Vec<(String, Option<u16>)> {
            other_instances(own)
                .into_iter()
                .map(|(i, s)| (i.name().to_string(), s.listen_port))
                .collect()
        };
        assert_eq!(ports(&d), [("work".to_string(), Some(51821))]);
        assert_eq!(ports(&w), [("default".to_string(), Some(51820))]);

        unsafe {
            for v in ["WIRESERVE_STATE_ROOT", "WIRESERVE_RUN_ROOT"] {
                std::env::remove_var(v);
            }
        }
    }
}
