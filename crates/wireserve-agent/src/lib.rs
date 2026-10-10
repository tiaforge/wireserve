pub mod backoff;
pub mod endpoint_dns;
pub mod firewall;
pub mod fsutil;
pub mod held;
pub mod hosts;
pub mod ifname;
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
pub mod state;
pub mod tls_link;
#[cfg(test)]
mod test_alloc;
pub mod vip;
pub mod wg;

/// Words that can't name a service declared here: `wireserve <word>` runs
/// that command instead (PLAN.md M44). `off` is what withdraws one.
pub const RESERVED_SERVICE_NAMES: &[&str] =
    &["join", "install", "daemon", "tls-daemon", "tls-serve", "transit", "exit", "status", "leave", "help", "off"];
