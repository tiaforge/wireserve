//! The host's interfaces on Unix, by `getifaddrs` (see `crate::wg`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Every interface other than `except` that has `addr` assigned.
pub fn interfaces_with_address(addr: IpAddr, except: &str) -> std::io::Result<Vec<String>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list we free below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: every node of the list is valid until freeifaddrs; the
        // sockaddr is read as the type its family says it is.
        let ifa = unsafe { &*cursor };
        cursor = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        let found = match i32::from(unsafe { (*ifa.ifa_addr).sa_family }) {
            libc::AF_INET => {
                let sin = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
                IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
            }
            libc::AF_INET6 => {
                let sin6 = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in6>() };
                IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr))
            }
            _ => continue,
        };
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
        if found == addr && name != except && !out.contains(&name) {
            out.push(name);
        }
    }
    // SAFETY: `head` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// Interface-name prefixes treated as virtual rather than a real LAN
/// uplink — a private address on one of these is a container bridge or
/// VPN overlay, not the home network this feature means to reach.
/// Judgment call, not exhaustive; worth revisiting if a real deployment's
/// LAN NIC gets misclassified.
const VIRTUAL_IFACE_PREFIXES: &[&str] = &[
    "lo", "docker", "veth", "br-", "virbr", "tun", "tap", "wg", "tailscale", "zt", "cni", "flannel", "podman",
];

fn looks_virtual(name: &str) -> bool {
    VIRTUAL_IFACE_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// This node's own private-range (RFC1918) IPv4 interfaces, in
/// `getifaddrs` enumeration order, excluding `except` (this node's own
/// mesh interface — same hygiene `interfaces_with_address` applies) and
/// anything that `looks_virtual`. IPv4 only: v1 of the NAT-hairpin fix has
/// no IPv6 LAN candidate — real hairpin is an IPv4 NAT problem. Impure —
/// the actual syscall; kept separate from the pure functions below so
/// those stay unit-testable without a live interface, same probe/choice
/// split as `interfaces_with_address` itself.
pub fn local_lan_ifaces(except: &str) -> std::io::Result<Vec<crate::wg::LocalLan>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list we free below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: every node of the list is valid until freeifaddrs; the
        // sockaddr is read as the type its family says it is.
        let ifa = unsafe { &*cursor };
        cursor = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() {
            continue;
        }
        if i32::from(unsafe { (*ifa.ifa_addr).sa_family }) != libc::AF_INET {
            continue;
        }
        // SAFETY: family checked above.
        let sin = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
        let addr = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        // SAFETY: ifa_netmask is non-null and shares ifa_addr's family for
        // an AF_INET entry.
        let mask_sin = unsafe { &*ifa.ifa_netmask.cast::<libc::sockaddr_in>() };
        let prefix_len = u32::from_be(mask_sin.sin_addr.s_addr).count_ones() as u8;
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
        if addr.is_private() && name != except && !looks_virtual(&name) {
            out.push(crate::wg::LocalLan { addr, prefix_len });
        }
    }
    // SAFETY: `head` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// Whether a network interface with this name already exists on the
/// host, WireGuard or otherwise. Asked directly rather than inferred
/// from a netlink error, because the distinction that matters here
/// ("something already owns this name") is not one the WireGuard API
/// reports cleanly: `create_interface` deliberately treats `EEXIST` as
/// success so that restarts are idempotent.
///
/// `if_nametoindex`, not `/sys/class/net`: sysfs shows the network
/// namespace of whoever mounted it, which is not ours when the agent is
/// started in a namespace without its own sysfs mount (`nsenter`,
/// `unshare -n`) — there it would call a name that is taken here free.
/// Anything but "no such device" counts as taken: when in doubt, the
/// name is not ours to configure.
pub fn interface_exists(ifname: &str) -> bool {
    let Ok(name) = std::ffi::CString::new(ifname) else {
        return true;
    };
    // SAFETY: `name` is a valid NUL-terminated string for the call.
    if unsafe { libc::if_nametoindex(name.as_ptr()) } != 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ENODEV)
}
