//! Kernel routes towards mesh peers.
//!
//! WireGuard's `AllowedIPs` decides which peer a packet belongs to once it
//! has reached the interface; getting it to the interface takes an entry
//! in the host's routing table. Every peer here has exactly its own `/32`
//! and `/128`, so what's needed is one link-scoped host route per peer
//! address on our interface, as `wg-quick` would add from `AllowedIPs`.
//!
//! This used to be defguard's `configure_peer_routing`, which does that
//! and then also runs `configure_endpoints`: a host route to every peer's
//! *endpoint* through the default gateway, and on a host without one a
//! *blackhole* route to it — cutting off the very address the tunnel
//! talks to (and a coordinator sharing it). That step exists for peers
//! routing `0.0.0.0/0`, whose endpoint must be kept out of the tunnel; our
//! peers never route anything but their own addresses, so an endpoint is
//! reached over the host's normal routes like any other address and no
//! extra route is needed. It also only ever added, so a removed peer's
//! route stayed behind; `sync` removes those.

use std::collections::BTreeSet;
use std::io;
use std::net::IpAddr;

use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::{constants::NETLINK_ROUTE, Socket, SocketAddr};

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
    let index = interface_index(ifname)?;
    let (add, remove) = plan(old, new);
    let mut first_err = None;
    for addr in remove {
        if let Err(e) = request(route_message(index, addr), false) {
            tracing::warn!(%addr, ifname, error = %e, "could not remove the route to a departed peer");
            first_err.get_or_insert(e);
        }
    }
    for addr in add {
        if let Err(e) = request(route_message(index, addr), true) {
            tracing::warn!(%addr, ifname, error = %e, "could not add the route to a peer");
            first_err.get_or_insert(e);
        }
    }
    first_err.map_or(Ok(()), Err)
}

fn interface_index(ifname: &str) -> io::Result<u32> {
    let name = std::ffi::CString::new(ifname).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `name` is a valid NUL-terminated string for the call.
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        index => Ok(index),
    }
}

/// `<addr>/32` (or `/128`) `dev <index> scope link`, in the main table —
/// the same route defguard's `add_route` built.
fn route_message(index: u32, addr: IpAddr) -> RouteMessage {
    let (family, len, dest) = match addr {
        IpAddr::V4(a) => (AddressFamily::Inet, 32, RouteAddress::Inet(a)),
        IpAddr::V6(a) => (AddressFamily::Inet6, 128, RouteAddress::Inet6(a)),
    };
    let mut message = RouteMessage::default();
    message.header = RouteHeader {
        address_family: family,
        destination_prefix_length: len,
        table: RouteHeader::RT_TABLE_MAIN,
        scope: RouteScope::Link,
        kind: RouteType::Unicast,
        protocol: RouteProtocol::Boot,
        ..Default::default()
    };
    message.attributes.push(RouteAttribute::Oif(index));
    message.attributes.push(RouteAttribute::Destination(dest));
    message
}

/// Adds (`add`) or deletes one route and waits for the kernel's answer.
/// Adding a route that exists and deleting one that doesn't both count as
/// done. A delete carries the output interface, so only our interface's
/// route to that address is ever removed — never another mesh's.
fn request(message: RouteMessage, add: bool) -> io::Result<()> {
    let (payload, flags) = if add {
        (RouteNetlinkMessage::NewRoute(message), NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL)
    } else {
        (RouteNetlinkMessage::DelRoute(message), NLM_F_REQUEST | NLM_F_ACK)
    };
    let mut req = NetlinkMessage::from(payload);
    req.header.flags = flags;
    req.finalize();
    let mut buf = vec![0u8; req.buffer_len()];
    req.serialize(&mut buf);

    let socket = Socket::new(NETLINK_ROUTE)?;
    socket.connect(&SocketAddr::new(0, 0))?;
    if socket.send(&buf, 0)? != buf.len() {
        return Err(io::Error::other("short netlink send"));
    }
    let mut recv_buf = vec![0u8; 8192];
    loop {
        let n = socket.recv(&mut &mut recv_buf[..], 0)?;
        let mut offset = 0;
        while offset < n {
            let response = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&recv_buf[offset..n])
                .map_err(|e| io::Error::other(e.to_string()))?;
            match response.payload {
                NetlinkPayload::Error(e) if e.code.is_none() => return Ok(()),
                NetlinkPayload::Error(e) => {
                    let err = e.to_io();
                    let done = match err.raw_os_error() {
                        Some(libc::EEXIST) => add,
                        Some(libc::ESRCH | libc::ENOENT) => !add,
                        _ => false,
                    };
                    return if done { Ok(()) } else { Err(err) };
                }
                NetlinkPayload::Done(_) => return Ok(()),
                _ => {}
            }
            let len = response.header.length as usize;
            if len == 0 {
                break;
            }
            offset += len;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(addrs: &[&str]) -> BTreeSet<IpAddr> {
        addrs.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn plan_adds_everything_wanted_and_removes_only_the_departed() {
        let (add, remove) = plan(&set(&["10.0.0.2", "10.0.0.3", "fd::3"]), &set(&["10.0.0.3", "10.0.0.4"]));
        assert_eq!(add, Vec::from_iter(set(&["10.0.0.3", "10.0.0.4"])));
        assert_eq!(remove, Vec::from_iter(set(&["10.0.0.2", "fd::3"])));
    }

    /// Against a real kernel: routes appear scoped to the interface, adding
    /// twice is fine, a departed peer's route goes, and a route to the
    /// same address on another interface is never touched.
    #[test]
    fn kernel_sync_adds_and_removes_only_our_routes() {
        if !crate::firewall::netns::reexec("routes::tests::kernel_sync_adds_and_removes_only_our_routes") {
            return;
        }
        let sh = |script: &str| {
            let out = std::process::Command::new("sh").args(["-euc", script]).output().unwrap();
            assert!(out.status.success(), "{script}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8(out.stdout).unwrap()
        };
        sh("ip link add wgt type wireguard && ip link set wgt up && \
            ip link add other type dummy && ip link set other up && \
            ip route add 10.0.0.9/32 dev other");

        let a = set(&["10.0.0.2", "10.0.0.3", "fd00::2"]);
        sync("wgt", &BTreeSet::new(), &a).unwrap();
        sync("wgt", &BTreeSet::new(), &a).unwrap();
        let v4 = sh("ip -4 route show dev wgt");
        assert!(v4.contains("10.0.0.2 scope link") && v4.contains("10.0.0.3 scope link"), "{v4}");
        assert!(sh("ip -6 route show dev wgt").contains("fd00::2"));

        sync("wgt", &a, &set(&["10.0.0.2"])).unwrap();
        let v4 = sh("ip -4 route show dev wgt");
        assert!(v4.contains("10.0.0.2") && !v4.contains("10.0.0.3"), "{v4}");
        assert!(!sh("ip -6 route show dev wgt").contains("fd00::2"));

        // An address another interface already routes: the add is a no-op
        // (the kernel keeps one route per prefix), and removing it from us
        // never takes the other interface's route.
        let with_9 = set(&["10.0.0.2", "10.0.0.9"]);
        sync("wgt", &set(&["10.0.0.2"]), &with_9).unwrap();
        sync("wgt", &with_9, &set(&["10.0.0.2"])).unwrap();
        assert!(sh("ip -4 route show dev other").contains("10.0.0.9"), "the other interface's route survived");

        // Removing what is already gone is not an error.
        sync("wgt", &a, &set(&["10.0.0.2"])).unwrap();
        sync("wgt", &a, &set(&["10.0.0.2"])).unwrap();
    }
}
