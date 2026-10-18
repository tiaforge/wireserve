//! WireGuard on Windows: our own wireguard-nt binding ([`super::nt`]; see
//! `crate::wg`).

use defguard_wireguard_rs::error::WireguardInterfaceError;

/// The kernel WireGuard API: wireguard-nt, whose methods are its own.
pub type Api = super::nt::NtApi;

/// Nothing to bring into scope: `NtApi`'s methods are inherent.
pub trait InterfaceApi {}

/// Closes the adapter, which removes it with its addresses and routes,
/// and waits until it is gone (see [`super::nt`]).
#[allow(clippy::unnecessary_wraps)]
pub fn remove_interface(api: &mut Api, _ifname: &str) -> Result<(), WireguardInterfaceError> {
    api.remove_interface();
    Ok(())
}

/// The carry interface (PLAN.md M39): its handle closed, which removes
/// the adapter as the process ending would, without waiting for it, so a
/// service stop takes no longer than the mesh adapter's own removal.
#[allow(clippy::unnecessary_wraps)]
pub fn release_carry(api: Api, _ifname: &str) -> Result<(), WireguardInterfaceError> {
    drop(api);
    Ok(())
}
