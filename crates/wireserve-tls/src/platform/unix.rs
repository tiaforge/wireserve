//! The terminator on Unix (see [`super`]): the agent's socket, systemd's
//! listening sockets on one port of every address, and file modes.

use std::path::Path;

use crate::serve::{Incoming, Listening};

// ---- the link to the agent ----

pub(crate) async fn connect(socket: &Path) -> std::io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(socket).await
}

// ---- listening ----

/// The TLS connections, the listening that goes with them, and the port
/// they arrive on: [`crate::serve::listener`] on Linux; each service address's 443 on
/// Windows, where nothing rewrites it (PLAN.md M50).
pub(crate) fn open_tls(port: u16) -> std::io::Result<(Incoming, Listening, u16)> {
    let listener = crate::serve::listener(port)?;
    let port = listener.local_addr()?.port();
    Ok((listener.into(), Listening::Every, port))
}

/// [`open_tls`] for plain HTTP (PLAN.md #328): [`crate::serve::http_listener`] on Linux,
/// each service address's 80 on Windows.
pub(crate) fn open_http(port: u16) -> std::io::Result<Option<(Incoming, Listening, u16)>> {
    let Some(listener) = crate::serve::http_listener(port)? else {
        return Ok(None);
    };
    let port = listener.local_addr()?.port();
    Ok(Some((listener.into(), Listening::Every, port)))
}

/// Nothing to set: a socket bound to its own address is no other user's
/// to share, as nobody else may bind below port 1024.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn prepare_address_socket(_socket: &socket2::Socket) -> std::io::Result<()> {
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn passed_listener(fd: i32) -> Option<std::net::TcpListener> {
    use std::os::fd::FromRawFd;
    // SAFETY: systemd passed this descriptor to this very process
    // (LISTEN_PID), and nothing else in it has taken ownership of it.
    Some(unsafe { std::net::TcpListener::from_raw_fd(fd) })
}

// ---- files ----

/// `0600`: readable and writable by the terminator's user alone.
pub(crate) fn owner_only(options: &mut std::fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

pub(crate) fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}
