pub mod backoff;
pub mod endpoint_dns;
pub mod firewall;
pub mod fsutil;
pub mod held;
pub mod hosts;
pub mod ifname;
#[cfg(unix)]
pub mod install;
pub mod ipc;
pub mod lock;
pub mod mesh;
pub mod paths;
pub mod poll_loop;
pub mod port_check;
pub mod probe;
pub mod reflexive;
pub mod register;
#[cfg(target_os = "linux")]
pub mod routes;
#[cfg(windows)]
#[path = "routes_windows.rs"]
pub mod routes;
pub mod state;
pub mod tls_link;
// Only the Linux host-firewall interop's tests measure allocations.
#[cfg(all(test, target_os = "linux"))]
mod test_alloc;
pub mod vip;
pub mod wg;
#[cfg(windows)]
pub mod winnet;
#[cfg(windows)]
pub mod winpath;
#[cfg(windows)]
pub mod winsec;
#[cfg(windows)]
pub mod winservice;

/// Words that can't name a service declared here: `wireserve <word>` runs
/// that command instead (PLAN.md M44). `off` is what withdraws one.
pub const RESERVED_SERVICE_NAMES: &[&str] =
    &["join", "install", "daemon", "tls-daemon", "tls-serve", "transit", "exit", "status", "leave", "help", "off"];
