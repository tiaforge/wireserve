//! The terminator on Windows (see [`super`]; PLAN.md M50): the agent's
//! named pipe, each service address's own socket on 443 and 80, and files
//! protected by their directory's ACL.

use std::path::Path;

use crate::serve::{Incoming, Listening};

// ---- the link to the agent ----

/// The agent's pipe for the terminator. Busy means every instance is taken
/// for the moment; the agent makes a new one per connection.
pub(crate) async fn connect(socket: &Path) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
    let mut tries = 0;
    loop {
        match pipe::open(socket) {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && tries < 50 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            result => return result,
        }
    }
}

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

// ---- listening ----

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn open_tls(_port: u16) -> std::io::Result<(Incoming, Listening, u16)> {
    let (addresses, incoming) = crate::serve::Addresses::new(wireserve_types::TLS_PUBLIC_PORT);
    Ok((incoming, crate::serve::Listening::PerAddress(addresses), wireserve_types::TLS_PUBLIC_PORT))
}

#[allow(clippy::unnecessary_wraps)]
pub(crate) fn open_http(_port: u16) -> std::io::Result<Option<(Incoming, Listening, u16)>> {
    let (addresses, incoming) = crate::serve::Addresses::new(wireserve_types::HTTP_PUBLIC_PORT);
    Ok(Some((incoming, crate::serve::Listening::PerAddress(addresses), wireserve_types::HTTP_PUBLIC_PORT)))
}

/// `SO_EXCLUSIVEADDRUSE`: without it, Windows lets another process bind the
/// same address and port with `SO_REUSEADDR` and take connections from us.
pub(crate) fn prepare_address_socket(socket: &socket2::Socket) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, SOCKET_ERROR, SOL_SOCKET, SO_EXCLUSIVEADDRUSE};
    let on: i32 = 1;
    // SAFETY: an open socket, and a value of the size given.
    let rc = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            std::ptr::from_ref(&on).cast(),
            std::mem::size_of::<i32>() as i32,
        )
    };
    if rc == SOCKET_ERROR {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// No systemd: nothing is ever passed.
pub(crate) fn passed_listener(_fd: i32) -> Option<std::net::TcpListener> {
    None
}

// ---- files ----

/// Nothing: the file takes the state directory's ACL, which `install`
/// gives the terminator's account and administrators only.
pub(crate) fn owner_only(_options: &mut std::fs::OpenOptions) {}

/// See [`owner_only`]: the directory's ACL is `install`'s.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}
