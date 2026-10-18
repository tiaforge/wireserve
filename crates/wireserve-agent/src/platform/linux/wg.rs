//! WireGuard on Linux: the kernel's, through defguard (see `crate::wg`).

use defguard_wireguard_rs::error::WireguardInterfaceError;
pub use defguard_wireguard_rs::WireguardInterfaceApi as InterfaceApi;
use defguard_wireguard_rs::{Kernel, WGApi};

/// The kernel WireGuard API.
pub type Api = WGApi<Kernel>;

/// Deletes the interface, and with it its addresses and routes. Not
/// defguard's `remove_interface`; see `routes::delete_link` for why.
pub fn remove_interface(_api: &mut Api, ifname: &str) -> Result<(), WireguardInterfaceError> {
    super::routes::delete_link(ifname)?;
    Ok(())
}

/// The carry interface (PLAN.md M39) goes the same way.
pub fn release_carry(mut api: Api, ifname: &str) -> Result<(), WireguardInterfaceError> {
    remove_interface(&mut api, ifname)
}
