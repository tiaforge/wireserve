//! Well-known filesystem locations, overridable via env so tests (and
//! anyone running the agent rootless for development) don't need to write
//! to `/run` or `/var/lib`.

use std::path::PathBuf;

pub fn socket_path() -> PathBuf {
    std::env::var("WIRESERVE_SOCKET_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/wireserve/agent.sock"))
}

pub fn state_path() -> PathBuf {
    std::env::var("WIRESERVE_STATE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/wireserve/agent-state.json"))
}

/// Linux/macOS/BSD hosts file. Spec §6 names the Windows path too
/// (`C:\Windows\System32\drivers\etc\hosts`), but Windows support is
/// explicitly deferred (spec "open items"), and this crate's atomic file
/// writer is Unix-only, so no Windows branch is kept here — it would be
/// dead code that cannot compile on the platform it claims to support.
pub fn hosts_path() -> PathBuf {
    std::env::var("WIRESERVE_HOSTS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/hosts"))
}
