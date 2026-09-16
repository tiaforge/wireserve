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

#[cfg(target_os = "windows")]
pub fn hosts_path() -> PathBuf {
    std::env::var("WIRESERVE_HOSTS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts"))
}

#[cfg(not(target_os = "windows"))]
pub fn hosts_path() -> PathBuf {
    std::env::var("WIRESERVE_HOSTS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/hosts"))
}
