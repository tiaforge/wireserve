//! Talking to the agent over its TLS socket (PLAN.md M33): one request and
//! one response per connection, newline-delimited JSON.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use wireserve_types::tls::{TlsConfig, TlsRequest, TlsResponse};

/// How long one exchange with the agent may take. A challenge includes the
/// coordinator's call to the DNS provider, which is the slow part.
const TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("the agent's TLS socket {0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("the agent did not answer in time")]
    Timeout,
    #[error("the agent's answer was not understood: {0}")]
    Decode(serde_json::Error),
    #[error("{0}")]
    Refused(String),
    /// The sign-in session is over (PLAN.md M48).
    #[error("signed out")]
    SignedOut,
}

#[derive(Debug, Clone)]
pub struct Link {
    socket: PathBuf,
}

impl Link {
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self { socket: socket.into() }
    }

    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Tells the agent what is served now, on which port, and which known
    /// devices connected since the last time; returns what should be served.
    pub async fn check_in(&self, serving: Vec<String>, port: u16, seen: Vec<std::net::Ipv4Addr>) -> Result<TlsConfig, LinkError> {
        match self.exchange(&TlsRequest::CheckIn { serving, port, seen }).await? {
            TlsResponse::Config(config) => Ok(*config),
            other => Err(unexpected(other)),
        }
    }

    /// Publishes (`present`) or withdraws one challenge value.
    pub async fn challenge(&self, fqdn: &str, value: &str, present: bool) -> Result<(), LinkError> {
        let req = TlsRequest::Challenge { fqdn: fqdn.into(), value: value.into(), present };
        match self.exchange(&req).await? {
            TlsResponse::Ok => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    /// Redeems a sign-in ticket for the service `fqdn` (PLAN.md M48): its
    /// session token, and the path the browser goes on to.
    pub async fn redeem(&self, fqdn: &str, ticket: &str) -> Result<(String, Option<String>), LinkError> {
        match self.exchange(&TlsRequest::Redeem { fqdn: fqdn.into(), ticket: ticket.into() }).await? {
            TlsResponse::Session { token, to } => Ok((token, to)),
            other => Err(unexpected(other)),
        }
    }

    /// A fresh session token for an expired one.
    pub async fn renew(&self, fqdn: &str, token: &str) -> Result<String, LinkError> {
        match self.exchange(&TlsRequest::Renew { fqdn: fqdn.into(), token: token.into() }).await? {
            TlsResponse::Session { token, .. } => Ok(token),
            other => Err(unexpected(other)),
        }
    }

    /// Ends the session `token` is for.
    pub async fn end(&self, fqdn: &str, token: &str) -> Result<(), LinkError> {
        match self.exchange(&TlsRequest::End { fqdn: fqdn.into(), token: token.into() }).await? {
            TlsResponse::Ok | TlsResponse::SignedOut => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    async fn exchange(&self, req: &TlsRequest) -> Result<TlsResponse, LinkError> {
        let io = |e| LinkError::Io(self.socket.clone(), e);
        let run = async {
            let stream = UnixStream::connect(&self.socket).await.map_err(io)?;
            let (read, mut write) = stream.into_split();
            let mut line = serde_json::to_string(req).map_err(LinkError::Decode)?;
            line.push('\n');
            write.write_all(line.as_bytes()).await.map_err(io)?;
            let mut answer = String::new();
            BufReader::new(read).read_line(&mut answer).await.map_err(io)?;
            serde_json::from_str::<TlsResponse>(answer.trim_end()).map_err(LinkError::Decode)
        };
        tokio::time::timeout(TIMEOUT, run).await.map_err(|_| LinkError::Timeout)?
    }
}

fn unexpected(resp: TlsResponse) -> LinkError {
    match resp {
        TlsResponse::Error { message } => LinkError::Refused(message),
        TlsResponse::SignedOut => LinkError::SignedOut,
        other => LinkError::Refused(format!("unexpected answer: {other:?}")),
    }
}
