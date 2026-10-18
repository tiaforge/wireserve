//! Everything that differs between operating systems, behind one surface.
//!
//! The rest of the agent is the same code on every platform and calls
//! what it needs from here. Each platform's modules live beside each
//! other:
//! - [`unix`]: what every Unix shares — Unix sockets, file modes, `flock`,
//!   signals, the systemd `install`;
//! - [`linux`]: what only Linux has — nftables and the host-firewall
//!   interop, netlink routes, per-interface forwarding;
//! - [`windows`]: the Windows Filtering Platform, wireguard-nt, the Service
//!   Control Manager, named pipes and ACLs (PLAN.md M49, M50);
//! - `fallback`: stand-ins where a platform has nothing to do.
//!
//! This is the one module that chooses between them; below, each name is
//! listed with what it is on every platform.

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

#[cfg(not(target_os = "linux"))]
mod fallback;

// ---- what the platform can do ----

/// What a platform can do that not every one can: rewrite ports, carry
/// traffic.
#[cfg(target_os = "linux")]
pub use linux::capabilities;
#[cfg(windows)]
pub use windows::capabilities;

// ---- files, paths, the instance lock ----

#[cfg(unix)]
pub use unix::fs;
#[cfg(windows)]
pub use windows::fs;

#[cfg(unix)]
pub use unix::paths;
#[cfg(windows)]
pub use windows::paths;

/// The instance lock and the interface claims (see `crate::lock`).
pub mod lock {
    #[cfg(unix)]
    pub use super::unix::lock::lock_file;
    #[cfg(windows)]
    pub use super::windows::lock::lock_file;

    #[cfg(target_os = "linux")]
    pub use super::linux::claim::{holder, IfnameClaim};
    #[cfg(all(unix, not(target_os = "linux")))]
    pub use super::unix::claim::{holder, IfnameClaim};
    #[cfg(windows)]
    pub use super::windows::claim::{holder, IfnameClaim};
}

// ---- IPC, the service, install ----

#[cfg(unix)]
pub use unix::ipc;
#[cfg(windows)]
pub use windows::ipc;

#[cfg(unix)]
pub use unix::service;
#[cfg(windows)]
pub use windows::service;

/// `install`: systemd units, or Windows services.
pub mod install {
    #[cfg(unix)]
    pub use super::unix::install::run;
    #[cfg(windows)]
    pub use super::windows::install::run;

    /// What `install` was given, as the CLI parsed it.
    pub struct Request {
        pub coordinator_url: Option<String>,
        pub allow_plaintext_http: bool,
        /// A URL or a token: a join. Without either, on a node that has an
        /// identity, an upgrade.
        pub join_args_given: bool,
        pub tls_port: Option<u16>,
    }
}

// ---- interfaces, WireGuard, routes ----

#[cfg(unix)]
pub use unix::net;
#[cfg(windows)]
pub use windows::net;

#[cfg(target_os = "linux")]
pub use linux::wg;
#[cfg(windows)]
pub use windows::wg;

#[cfg(target_os = "linux")]
pub use linux::routes;
#[cfg(windows)]
pub use windows::routes;

/// The service addresses the host receives on itself.
#[cfg(not(any(target_os = "linux", windows)))]
pub use fallback::host_addresses;
#[cfg(target_os = "linux")]
pub use linux::host_addresses;
#[cfg(windows)]
pub use windows::host_addresses;

// ---- the firewall, forwarding ----

#[cfg(not(any(target_os = "linux", windows)))]
pub use fallback::firewall;
#[cfg(target_os = "linux")]
pub use linux::firewall;
#[cfg(windows)]
pub use windows::firewall;

#[cfg(not(target_os = "linux"))]
pub use fallback::forwarding;
#[cfg(target_os = "linux")]
pub use linux::forwarding;
