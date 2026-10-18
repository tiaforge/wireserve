//! Talking to the agent over its TLS socket (PLAN.md M33), a named pipe on
//! Windows: one request and one response per connection, newline-delimited
//! JSON.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

    /// Tells the agent what is served now, and on which ports: TLS on
    /// `port`, the services in `http` in plain HTTP on `http_port` (0: none);
    /// returns what should be served.
    pub async fn check_in(&self, serving: Vec<String>, port: u16, http: Vec<String>, http_port: u16) -> Result<TlsConfig, LinkError> {
        match self.exchange(&TlsRequest::CheckIn { serving, port, http, http_port }).await? {
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

    /// Redeems a sign-in ticket for the service `fqdn` (PLAN.md M48), for the
    /// browser whose bind cookie hashes to `bind`: its session token, and the
    /// path the browser goes on to.
    pub async fn redeem(&self, fqdn: &str, ticket: &str, bind: &str) -> Result<(String, Option<String>), LinkError> {
        match self.exchange(&TlsRequest::Redeem { fqdn: fqdn.into(), ticket: ticket.into(), bind: bind.into() }).await? {
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
            let stream = connect(&self.socket).await.map_err(io)?;
            let (read, mut write) = tokio::io::split(stream);
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

#[cfg(unix)]
async fn connect(socket: &Path) -> std::io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(socket).await
}

/// The agent's pipe for the terminator. Busy means every instance is taken
/// for the moment; the agent makes a new one per connection.
#[cfg(windows)]
async fn connect(socket: &Path) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
    let mut tries = 0;
    loop {
        match pipe::open(socket) {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && tries < 50 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            result => return result,
        }
    }
}

#[cfg(windows)]
mod pipe {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use tokio::net::windows::named_pipe::NamedPipeClient;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_WRITE_DATA, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    };

    /// Opens the pipe for reading and writing it, and no more — all the
    /// agent grants the terminator's account — and only if the agent made
    /// it (see [`check_owner`]). Identification only: the agent may learn
    /// who connects, never act as them.
    pub(super) fn open(socket: &Path) -> std::io::Result<NamedPipeClient> {
        let name: Vec<u16> = socket.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: a NUL-terminated name. The handle is closed here on a
        // refusal, and owned and closed by tokio otherwise.
        unsafe {
            let h = CreateFileW(
                name.as_ptr(),
                FILE_GENERIC_READ | FILE_WRITE_DATA,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            );
            if h == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error());
            }
            if let Err(e) = check_owner(h, socket) {
                CloseHandle(h);
                return Err(e);
            }
            NamedPipeClient::from_raw_handle(h)
        }
    }

    /// Refuses a pipe its creator, who owns it, could not have been the
    /// agent: anyone may create a pipe of any free name, and one made
    /// before the agent's (at boot, say) would be handed every sign-in
    /// ticket and session the terminator passes on. The agent runs as
    /// LocalSystem; an object it creates is owned by SYSTEM or, as its
    /// token's default owner, Administrators — which no other user can
    /// make the owner of anything.
    fn check_owner(h: HANDLE, socket: &Path) -> std::io::Result<()> {
        let mut owner: PSID = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: an open handle with READ_CONTROL (in FILE_GENERIC_READ);
        // `owner` points into `sd`, which the call allocates and we free.
        let code = unsafe {
            GetSecurityInfo(
                h,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(code as i32));
        }
        // SAFETY: `owner` is a valid SID inside `sd`, freed once after.
        let trusted = unsafe {
            let trusted = IsWellKnownSid(owner, WinLocalSystemSid) != 0 || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0;
            LocalFree(sd);
            trusted
        };
        if trusted {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{} was not created by the agent; refusing to talk to it", socket.display()),
            ))
        }
    }
}

fn unexpected(resp: TlsResponse) -> LinkError {
    match resp {
        TlsResponse::Error { message } => LinkError::Refused(message),
        TlsResponse::SignedOut => LinkError::SignedOut,
        other => LinkError::Refused(format!("unexpected answer: {other:?}")),
    }
}
