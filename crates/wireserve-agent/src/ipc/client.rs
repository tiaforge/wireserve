//! Thin client used by the `wireserve <service>`/`status`/`leave` CLI
//! subcommands to talk to a running daemon over the Unix socket. The socket
//! is root-only, or shared with the `wireserve` group when the host has one
//! (see `server::serve`), so a refused connection is reported as that, not
//! as a daemon that isn't running.

use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::protocol::{IpcRequest, IpcResponse};

#[derive(Debug, thiserror::Error)]
pub enum IpcClientError {
    #[error("could not connect to wireserve daemon at {0}: {1} (is it running?)")]
    Connect(std::path::PathBuf, std::io::Error),
    #[error(
        "not permitted to use the wireserve daemon at {0}: run this with sudo, or add yourself to \
         the `wireserve` group (`sudo usermod -aG wireserve $USER`, then log in again). The daemon \
         shares its socket with that group only if the group existed when it started"
    )]
    Denied(std::path::PathBuf),
    #[error("I/O error talking to daemon: {0}")]
    Io(#[from] std::io::Error),
    #[error("daemon returned an unparseable response: {0}")]
    BadResponse(#[from] serde_json::Error),
}

pub async fn call(socket_path: &Path, req: &IpcRequest) -> Result<IpcResponse, IpcClientError> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => IpcClientError::Denied(socket_path.to_path_buf()),
            _ => IpcClientError::Connect(socket_path.to_path_buf(), e),
        })?;
    let (read_half, mut write_half) = stream.into_split();

    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    write_half.write_all(line.as_bytes()).await?;
    write_half.shutdown().await?;

    let mut reader = BufReader::new(read_half);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await?;

    Ok(serde_json::from_str(&response_line)?)
}
