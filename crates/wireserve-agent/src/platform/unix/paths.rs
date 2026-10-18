//! Where things live on Unix (see `crate::paths`).

use std::path::PathBuf;

/// `WIRESERVE_STATE_ROOT`, or `/var/lib/wireserve`.
pub fn state_root() -> PathBuf {
    std::env::var("WIRESERVE_STATE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/wireserve"))
}

/// Where the TLS terminator keeps its certificates when not run by its
/// unit, which gives it a state directory of its own.
pub fn tls_state_root() -> PathBuf {
    PathBuf::from("/var/lib/wireserve-tls")
}

/// The state directory systemd named (`STATE_DIRECTORY`), which may list
/// several, colon-separated: the unit names exactly one.
#[must_use]
pub fn named_state_dir(dir: Option<PathBuf>) -> Option<PathBuf> {
    dir.and_then(|d| d.to_str().and_then(|s| s.split(':').next()).map(PathBuf::from))
}

/// Where the IPC sockets live: `WIRESERVE_RUN_ROOT`, or `/run`.
pub fn run_root() -> PathBuf {
    std::env::var("WIRESERVE_RUN_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run"))
}

/// `WIRESERVE_HOSTS_PATH`, or `/etc/hosts`.
pub fn hosts_path() -> PathBuf {
    std::env::var("WIRESERVE_HOSTS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/hosts"))
}
