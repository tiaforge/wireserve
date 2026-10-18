//! Interface claims on Linux: abstract Unix sockets (see `crate::lock`).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener};

use crate::lock::Holder;

fn claim_name(ifname: &str) -> String {
    format!("wireserve/if/{ifname}")
}

/// This process's claim on an interface name.
#[derive(Debug)]
pub struct IfnameClaim {
    ifname: String,
    listener: UnixListener,
}

impl IfnameClaim {
    /// Takes the claim, or reports who has it.
    pub fn take(ifname: &str) -> io::Result<Result<Self, Holder>> {
        let addr = SocketAddr::from_abstract_name(claim_name(ifname).as_bytes())?;
        match UnixListener::bind_addr(&addr) {
            Ok(listener) => Ok(Ok(Self {
                ifname: ifname.to_string(),
                listener,
            })),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => Ok(Err(holder(ifname))),
            Err(e) => Err(e),
        }
    }

    #[must_use]
    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    /// Keeps the claim for the rest of this process's life. Other
    /// agents check it by connecting; a thread accepts and drops those
    /// connections so they never pile up in the backlog.
    pub fn hold(self) {
        let listener = self.listener;
        let spawned = std::thread::Builder::new()
            .name("ifname-claim".into())
            .spawn(move || {
                for conn in listener.incoming() {
                    drop(conn);
                }
            });
        if let Err(e) = spawned {
            tracing::warn!(error = %e, "could not start the interface-claim thread; other agents' checks may stall");
        }
    }
}

/// Who holds `ifname`'s claim. Connects without blocking: a squatter
/// that listens but never accepts fills its backlog, and a blocking
/// connect would then hang whoever is asking.
#[must_use]
pub fn holder(ifname: &str) -> Holder {
    match probe(ifname) {
        Ok(h) => h,
        Err(e) => Holder::Unknown(e.to_string()),
    }
}

fn probe(ifname: &str) -> io::Result<Holder> {
    let name = claim_name(ifname);
    // SAFETY: zeroed sockaddr_un is valid; the name fits (checked).
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if name.len() + 1 > addr.sun_path.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "claim name too long"));
    }
    // sun_path[0] stays NUL: that is what makes the address abstract.
    for (dst, src) in addr.sun_path[1..].iter_mut().zip(name.bytes()) {
        *dst = src as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + 1 + name.len();

    // SAFETY: plain syscalls; the descriptor is owned by `fd` from here on.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            len as libc::socklen_t,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ECONNREFUSED) => Ok(Holder::Nobody),
            Some(libc::EAGAIN) => Ok(Holder::Unknown("its backlog is full".into())),
            _ => Err(err),
        };
    }

    // SAFETY: `cred` is a plain struct sized by `len`.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: no preconditions.
    let euid = unsafe { libc::geteuid() };
    Ok(if cred.uid == euid {
        Holder::Agent { pid: cred.pid }
    } else {
        Holder::Other {
            pid: cred.pid,
            uid: cred.uid,
        }
    })
}
