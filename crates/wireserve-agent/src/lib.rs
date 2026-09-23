pub mod endpoint_dns;
pub mod firewall;
pub mod fsutil;
pub mod hosts;
pub mod ifname;
pub mod install;
pub mod ipc;
pub mod lock;
pub mod mesh;
pub mod paths;
pub mod poll_loop;
pub mod probe;
pub mod proxy;
pub mod reflexive;
pub mod register;
#[cfg(target_os = "linux")]
pub mod routes;
pub mod state;
#[cfg(test)]
mod test_alloc;
pub mod vip;
pub mod wg;
