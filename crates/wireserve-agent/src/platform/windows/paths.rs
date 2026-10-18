//! Where things live on Windows (see `crate::paths`).

use std::path::PathBuf;

/// `%ProgramData%\wireserve`. The directory gets an ACL of its own when
/// created ([`super::security`]): what ProgramData's children inherit lets
/// every local user read them.
pub fn state_root() -> PathBuf {
    std::env::var("WIRESERVE_STATE_ROOT").map(PathBuf::from).unwrap_or_else(|_| {
        let data = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
        PathBuf::from(data).join("wireserve")
    })
}

/// `%ProgramData%\wireserve-tls`, beside the agent's own directory rather
/// than in it: `install` gives it an ACL of its own, which lets the
/// terminator's account in ([`super::security::ensure_private_dir_for`]).
pub fn tls_state_root() -> PathBuf {
    let data = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    PathBuf::from(data).join("wireserve-tls")
}

/// The state directory given, as it is: a Windows path has a colon of its
/// own, and there is no systemd to list several.
#[must_use]
pub fn named_state_dir(dir: Option<PathBuf>) -> Option<PathBuf> {
    dir
}

/// Where the IPC endpoints live: the named-pipe namespace, so a socket
/// path is a pipe name such as `\\.\pipe\wireserve\agent.sock`.
pub fn run_root() -> PathBuf {
    std::env::var("WIRESERVE_RUN_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"\\.\pipe"))
}

/// `WIRESERVE_HOSTS_PATH`, or `%SystemRoot%\System32\drivers\etc\hosts`.
pub fn hosts_path() -> PathBuf {
    std::env::var("WIRESERVE_HOSTS_PATH").map(PathBuf::from).unwrap_or_else(|_| {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        PathBuf::from(root).join(r"System32\drivers\etc\hosts")
    })
}
