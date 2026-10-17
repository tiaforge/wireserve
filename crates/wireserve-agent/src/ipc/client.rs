//! Thin client used by the `wireserve <service>`/`status`/`leave` CLI
//! subcommands to talk to a running daemon over the Unix socket (a named
//! pipe on Windows). The socket is root-only, or shared with the `wireserve`
//! group when the host has one (see `server::serve`), so a refused
//! connection is reported as that, not as a daemon that isn't running.

use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;

use super::protocol::{IpcRequest, IpcResponse};

#[derive(Debug, thiserror::Error)]
pub enum IpcClientError {
    #[error("could not connect to wireserve daemon at {0}: {1} (is it running?)")]
    Connect(std::path::PathBuf, std::io::Error),
    #[cfg(unix)]
    #[error(
        "not permitted to use the wireserve daemon at {0}: run this with sudo, or add yourself to \
         the `wireserve` group (`sudo usermod -aG wireserve $USER`, then log in again). The daemon \
         shares its socket with that group only if the group existed when it started"
    )]
    Denied(std::path::PathBuf),
    #[cfg(windows)]
    #[error("not permitted to use the wireserve daemon at {0}: run this from an elevated (Administrator) terminal")]
    Denied(std::path::PathBuf),
    #[error("I/O error talking to daemon: {0}")]
    Io(#[from] std::io::Error),
    #[error("daemon returned an unparseable response: {0}")]
    BadResponse(#[from] serde_json::Error),
}

pub async fn call(socket_path: &Path, req: &IpcRequest) -> Result<IpcResponse, IpcClientError> {
    let stream = connect(socket_path).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::PermissionDenied => IpcClientError::Denied(socket_path.to_path_buf()),
        _ => IpcClientError::Connect(socket_path.to_path_buf(), e),
    })?;
    let (read_half, mut write_half) = tokio::io::split(stream);

    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    write_half.write_all(line.as_bytes()).await?;
    write_half.shutdown().await?;

    let mut reader = BufReader::new(read_half);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await?;

    Ok(serde_json::from_str(&response_line)?)
}

#[cfg(unix)]
async fn connect(socket_path: &Path) -> std::io::Result<UnixStream> {
    UnixStream::connect(socket_path).await
}

/// Opens the daemon's named pipe. Busy means every instance is taken by
/// other clients for the moment; the server makes a new one per client,
/// so a short wait is enough.
#[cfg(windows)]
async fn connect(socket_path: &Path) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    let mut tries = 0;
    loop {
        match ClientOptions::new().open(socket_path.as_os_str()) {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && tries < 50 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            result => return result,
        }
    }
}
