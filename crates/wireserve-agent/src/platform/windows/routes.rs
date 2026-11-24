//! Host routes towards mesh peers, on Windows: see `routes.rs` for why
//! they are needed. Only the part a mesh member uses — a `/32` and `/128`
//! per peer address on the WireGuard adapter, through IP Helper rather
//! than netlink. The terminator's local routes and the exit's egress
//! lookup serve roles Windows nodes don't take.
//!
//! Every route here goes with the adapter: wireguard-nt removes the
//! adapter, routes included, when the agent closes it or dies.

use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2, InitializeIpForwardEntry,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::MIB_IPPROTO_NETMGMT;

use crate::platform::windows::net as winnet;

/// What `sync` has to do to go from routes to `old` to routes to `new`:
/// add every wanted address (existing ones are a no-op, so a restart that
/// starts from nothing recorded still converges), remove the rest.
#[must_use]
pub fn plan(old: &BTreeSet<IpAddr>, new: &BTreeSet<IpAddr>) -> (Vec<IpAddr>, Vec<IpAddr>) {
    (new.iter().copied().collect(), old.difference(new).copied().collect())
}

/// Makes the host routes on `ifname` go from `old` to `new` (see `plan`).
/// Every address is tried; the first error is returned after the rest ran.
pub fn sync(ifname: &str, old: &BTreeSet<IpAddr>, new: &BTreeSet<IpAddr>) -> io::Result<()> {
    sync_all(&[RouteSet { ifname, old, new, prefsrc: None }])
}

/// One interface's routes for [`sync_all`]. `prefsrc` only matters for
/// the carry interface, which Windows nodes never have; it is ignored.
pub struct RouteSet<'a> {
    pub ifname: &'a str,
    pub old: &'a BTreeSet<IpAddr>,
    pub new: &'a BTreeSet<IpAddr>,
    pub prefsrc: Option<(Ipv4Addr, std::net::Ipv6Addr)>,
}

/// Moves several interfaces' routes at once: every removal first, then
/// every addition, as on Linux.
pub fn sync_all(sets: &[RouteSet<'_>]) -> io::Result<()> {
    let mut first_err = None;
    let mut adds = Vec::new();
    for set in sets {
        let luid = match winnet::luid_by_alias(set.ifname) {
            Ok(Some(luid)) => luid,
            Ok(None) => {
                first_err.get_or_insert(io::Error::new(io::ErrorKind::NotFound, format!("no interface {}", set.ifname)));
                continue;
            }
            Err(e) => {
                first_err.get_or_insert(e);
                continue;
            }
        };
        let (add, remove) = plan(set.old, set.new);
        for addr in remove {
            if let Err(e) = request(luid, addr, false) {
                tracing::warn!(%addr, ifname = set.ifname, error = %e, "could not remove the route to a departed peer");
                first_err.get_or_insert(e);
            }
        }
        adds.push((set.ifname, luid, add));
    }
    for (ifname, luid, add) in adds {
        for addr in add {
            if let Err(e) = request(luid, addr, true) {
                tracing::warn!(%addr, ifname, error = %e, "could not add the route to a peer");
                first_err.get_or_insert(e);
            }
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// Adds (`add`) or deletes the on-link host route to `addr` on the
/// interface. Adding one that exists and deleting one that doesn't both
/// count as done. The route names the interface, so only ours is ever
/// removed.
fn request(luid: NET_LUID_LH, addr: IpAddr, add: bool) -> io::Result<()> {
    // SAFETY: an all-zero row is valid input to InitializeIpForwardEntry.
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.DestinationPrefix.Prefix = winnet::to_sockaddr_inet(SocketAddr::new(addr, 0));
    row.DestinationPrefix.PrefixLength = if addr.is_ipv4() { 32 } else { 128 };
    // On-link: an unspecified next hop of the destination's own family.
    let unspecified = if addr.is_ipv4() { IpAddr::from(Ipv4Addr::UNSPECIFIED) } else { IpAddr::from(std::net::Ipv6Addr::UNSPECIFIED) };
    row.NextHop = winnet::to_sockaddr_inet(SocketAddr::new(unspecified, 0));
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    // SAFETY: a complete row.
    let code = unsafe { if add { CreateIpForwardEntry2(&row) } else { DeleteIpForwardEntry2(&row) } };
    match code {
        NO_ERROR => Ok(()),
        ERROR_OBJECT_ALREADY_EXISTS if add => Ok(()),
        ERROR_NOT_FOUND if !add => Ok(()),
        code => Err(io::Error::from_raw_os_error(code as i32)),
    }
}

/// The adapter's interface index, which stays its own for as long as the
/// adapter lives; `ENODEV`, as on Linux, when no adapter has the name —
/// what `WgInterface::check` takes for "gone".
pub fn interface_index(ifname: &str) -> io::Result<u32> {
    match winnet::luid_by_alias(ifname)? {
        Some(luid) => winnet::index_of(luid),
        None => Err(io::Error::from_raw_os_error(libc::ENODEV)),
    }
}

/// Every address the host has a host route to, through any interface (see
/// the Linux version): what [`sync`] would find already there. Windows
/// removes an adapter's routes when it is disabled.
pub fn host_routes() -> io::Result<BTreeSet<IpAddr>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: the table is allocated by the call and freed below.
    winnet::check(unsafe { GetIpForwardTable2(windows_sys::Win32::Networking::WinSock::AF_UNSPEC, &mut table) })?;
    // SAFETY: `NumEntries` rows follow the count, alive until the table is freed.
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize) };
    let out = rows
        .iter()
        .filter_map(|row| {
            let addr = winnet::from_sockaddr_inet(&row.DestinationPrefix.Prefix)?.ip();
            let full = if addr.is_ipv4() { 32 } else { 128 };
            (row.DestinationPrefix.PrefixLength == full).then_some(addr)
        })
        .collect();
    // SAFETY: the table the call above allocated, freed once.
    unsafe { FreeMibTable(table.cast()) };
    Ok(out)
}

/// Always: an adapter is up from `configure_interface` on for as long as
/// its handle is held, and nothing like `ip link set down` takes it down
/// without removing it. One disabled by hand loses its routes, which
/// `WgInterface::check` puts back when it is enabled again.
#[allow(clippy::unnecessary_wraps)]
pub fn link_is_up(_index: u32) -> io::Result<bool> {
    Ok(true)
}

/// Nothing: see [`link_is_up`].
#[allow(clippy::unnecessary_wraps)]
pub fn set_link_up(_index: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_adds_everything_wanted_and_removes_the_rest() {
        let a: IpAddr = "100.90.0.2".parse().unwrap();
        let b: IpAddr = "100.90.0.3".parse().unwrap();
        let (add, remove) = plan(&[a, b].into(), &[b].into());
        assert_eq!(add, vec![b]);
        assert_eq!(remove, vec![a]);
    }

    #[test]
    fn an_adapter_that_does_not_exist_has_no_index_and_loopback_is_routed() {
        let err = interface_index("wireserve-no-such-adapter").unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENODEV));
        // Windows keeps a host route to 127.0.0.1.
        assert!(host_routes().unwrap().contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }
}
