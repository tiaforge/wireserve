//! The agent's IPC endpoints on Windows: named pipes, for SYSTEM and
//! Administrators, and shared with one account or local group when there
//! is one (see `crate::ipc::server`, `crate::ipc::tls`).

use std::path::{Path, PathBuf};

use tokio::net::windows::named_pipe::NamedPipeServer;

use super::security::SecurityDescriptor;

/// Who an endpoint may be shared with: an account or local group, by its
/// SID.
pub type Principal = String;

/// What the endpoint is called in the log.
pub const ENDPOINT: &str = "pipe";
/// Who may use an endpoint shared with nobody.
pub const PRIVATE: &str = "administrators-only";
/// What to do about being refused (`ipc::client`).
pub const DENIED_HINT: &str = "run this from an elevated (Administrator) terminal, or join the \
     `wireserve` group (`net localgroup wireserve <user> /add` from an elevated terminal, then sign \
     out and in again). The daemon shares its pipe with that group only if the group existed when \
     it started";

/// The local group named `name`, if this computer has one of its own (see
/// [`super::security::local_group_sid`]). A lookup that fails leaves the
/// pipe administrators-only.
#[must_use]
pub fn group(name: &str) -> Option<Principal> {
    match super::security::local_group_sid(name) {
        Ok(sid) => sid,
        Err(e) => {
            tracing::warn!(group = %name, error = %e, "could not look up the group; the pipe stays administrators-only");
            None
        }
    }
}

/// Who the TLS terminator's pipe is shared with: its service's own
/// account (PLAN.md M50), once `install` made the service.
#[must_use]
pub fn terminator(instance: &crate::paths::Instance) -> Option<Principal> {
    let name = super::service::tls_service_name(instance);
    match super::security::service_sid(&name) {
        Ok(sid) => sid,
        Err(e) => {
            tracing::warn!(service = %name, error = %e, "could not look up the TLS terminator's account");
            None
        }
    }
}

/// A named pipe, open to SYSTEM and Administrators — the counterpart of
/// the root-only socket — and to `shared_with`. An administrator's shell
/// has to be elevated to use it; unelevated, its token carries
/// Administrators as a deny-only group.
///
/// The first instance is created with `first_pipe_instance`, so a pipe of
/// that name someone else created first is an error rather than a server
/// we'd be talking through. Each accepted client gets the instance it
/// connected to, and a fresh one takes over listening.
pub struct Listener {
    path: PathBuf,
    sd: SecurityDescriptor,
    next: NamedPipeServer,
}

impl Listener {
    pub fn bind(path: &Path, shared_with: Option<&Principal>) -> std::io::Result<Self> {
        let sd = SecurityDescriptor::from_sddl(&pipe_sddl(shared_with.map(String::as_str)))?;
        let next = pipe_instance(path, &sd, true)?;
        Ok(Self { path: path.to_path_buf(), sd, next })
    }

    pub async fn accept(&mut self) -> std::io::Result<NamedPipeServer> {
        self.next.connect().await?;
        let fresh = pipe_instance(&self.path, &self.sd, false)?;
        Ok(std::mem::replace(&mut self.next, fresh))
    }
}

/// One instance of the pipe `name`, local clients only. The first is
/// created as the first instance of that name, so a pipe someone else made
/// before the agent started is an error, never one the agent shares.
fn pipe_instance(
    name: &Path,
    sd: &SecurityDescriptor,
    first: bool,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    let mut sa = sd.attributes();
    // SAFETY: `sa` and the descriptor it points to outlive the call.
    unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(name.as_os_str(), std::ptr::from_mut(&mut sa).cast())
    }
}

/// SYSTEM and Administrators, full access; nothing inherited.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

/// What the group (or the TLS terminator's account) may do
/// with the pipe: read it and write to it, and no more. `GENERIC_WRITE` would include `FILE_CREATE_PIPE_INSTANCE` (the
/// same bit as `FILE_APPEND_DATA`), with which a member could create
/// instances of the pipe itself and answer clients, administrators
/// included, in the daemon's place. The client asks for no more than
/// this ([`connect`]).
pub const GROUP_PIPE_ACCESS: u32 = windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ
    | windows_sys::Win32::Storage::FileSystem::FILE_WRITE_DATA;

/// [`PIPE_SDDL`], and the group's access when there is one.
fn pipe_sddl(group_sid: Option<&str>) -> String {
    match group_sid {
        Some(sid) => format!("{PIPE_SDDL}(A;;0x{GROUP_PIPE_ACCESS:x};;;{sid})"),
        None => PIPE_SDDL.to_string(),
    }
}

/// Opens the daemon's named pipe. Busy means every instance is taken by
/// other clients for the moment; the server makes a new one per client,
/// so a short wait is enough.
pub async fn connect(socket_path: &Path) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    let mut tries = 0;
    loop {
        match open_pipe(socket_path) {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && tries < 50 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            result => return result,
        }
    }
}

/// `ClientOptions::open`, but asking for reading and writing the pipe only
/// ([`GROUP_PIPE_ACCESS`]): its `GENERIC_WRITE` asks for more than a
/// member of the `wireserve` group is given, and would be refused. Still
/// identification only, as tokio's is: the server may learn who connects,
/// never act as them.
fn open_pipe(socket_path: &Path) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use std::os::windows::ffi::OsStrExt;
    use tokio::net::windows::named_pipe::NamedPipeClient;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };

    let name: Vec<u16> = socket_path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: a NUL-terminated name; the handle is handed to tokio, which
    // owns and closes it from then on.
    unsafe {
        let h = CreateFileW(
            name.as_ptr(),
            GROUP_PIPE_ACCESS,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            std::ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        NamedPipeClient::from_raw_handle(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pipe_grants_the_group_reading_and_writing_only() {
        use windows_sys::Win32::Storage::FileSystem::FILE_CREATE_PIPE_INSTANCE;
        assert_eq!(pipe_sddl(None), PIPE_SDDL);
        // Users, standing in for a local group's SID.
        let shared = pipe_sddl(Some("S-1-5-32-545"));
        assert_eq!(shared, "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;S-1-5-32-545)");
        assert_eq!(GROUP_PIPE_ACCESS & FILE_CREATE_PIPE_INSTANCE, 0);
        SecurityDescriptor::from_sddl(&shared).unwrap();
    }
}
