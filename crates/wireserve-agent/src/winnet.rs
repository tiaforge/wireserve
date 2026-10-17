//! The Windows IP Helper calls the agent's Windows code shares: finding an
//! interface by name, listing the host's addresses, and assigning an
//! adapter its addresses and MTU. What `getifaddrs`, `if_nametoindex` and
//! netlink do on Linux.
//!
//! Interfaces are named by their *alias* — what `Get-NetAdapter` shows
//! as `Name`, and what wireguard-nt calls the adapter's name.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, ERROR_NO_DATA,
    ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry, FreeMibTable,
    GetAdaptersAddresses, GetIpInterfaceEntry, GetUnicastIpAddressTable, InitializeIpInterfaceEntry,
    InitializeUnicastIpAddressEntry, SetIpInterfaceEntry, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
    MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    IpDadStatePreferred, ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_INET,
};

/// An IP Helper return code as an `io::Error`. These functions return
/// their error rather than setting the thread's last error.
pub fn check(code: u32) -> io::Result<()> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

/// `s` as a NUL-terminated UTF-16 string.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A NUL-terminated UTF-16 string, read up to its terminator.
///
/// # Safety
/// `p` is null or points to a NUL-terminated UTF-16 string.
unsafe fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

/// `SOCKADDR_INET` is 28 bytes: family, port (network order), then for
/// IPv4 the address at offset 4, for IPv6 the flow info at 4, the
/// address at 8 and the scope id at 24. Written byte by byte so the
/// unions windows-sys models it with don't leak out of here.
pub fn to_sockaddr_inet(addr: SocketAddr) -> SOCKADDR_INET {
    let mut raw = [0u8; 28];
    match addr {
        SocketAddr::V4(a) => {
            raw[..2].copy_from_slice(&AF_INET.to_ne_bytes());
            raw[2..4].copy_from_slice(&a.port().to_be_bytes());
            raw[4..8].copy_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            raw[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            raw[2..4].copy_from_slice(&a.port().to_be_bytes());
            raw[4..8].copy_from_slice(&a.flowinfo().to_be_bytes());
            raw[8..24].copy_from_slice(&a.ip().octets());
            raw[24..28].copy_from_slice(&a.scope_id().to_ne_bytes());
        }
    }
    // SAFETY: SOCKADDR_INET is plain data of exactly 28 bytes.
    unsafe { std::mem::transmute::<[u8; 28], SOCKADDR_INET>(raw) }
}

/// The inverse of [`to_sockaddr_inet`]; `None` for any other family
/// (`AF_UNSPEC` is how wireguard-nt reports a peer with no endpoint).
pub fn from_sockaddr_inet(sa: &SOCKADDR_INET) -> Option<SocketAddr> {
    // SAFETY: as above, read as the bytes it is.
    let raw = unsafe { std::mem::transmute::<SOCKADDR_INET, [u8; 28]>(*sa) };
    let family = ADDRESS_FAMILY::from_ne_bytes([raw[0], raw[1]]);
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    if family == AF_INET {
        let ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
        Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    } else if family == AF_INET6 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&raw[8..24]);
        let flowinfo = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let scope = u32::from_ne_bytes([raw[24], raw[25], raw[26], raw[27]]);
        Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, flowinfo, scope)))
    } else {
        None
    }
}

/// A `SOCKADDR` of either family, as `GetAdaptersAddresses` hands them out.
///
/// # Safety
/// `sa` is null or points to a socket address of the length its family implies.
unsafe fn from_sockaddr(sa: *const SOCKADDR) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    let family = unsafe { (*sa).sa_family };
    if family != AF_INET && family != AF_INET6 {
        return None;
    }
    let inet = unsafe { sa.cast::<SOCKADDR_INET>().read_unaligned() };
    from_sockaddr_inet(&inet).map(|a| a.ip())
}

/// The LUID of the interface with alias `name`; `None` when there is none.
pub fn luid_by_alias(name: &str) -> io::Result<Option<NET_LUID_LH>> {
    let name = wide(name);
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: `name` is NUL-terminated and `luid` is written by the call.
    match unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) } {
        NO_ERROR => Ok(Some(luid)),
        // Documented as ERROR_INVALID_PARAMETER for an unknown alias; seen
        // as both of the others too.
        ERROR_INVALID_PARAMETER | ERROR_NOT_FOUND | ERROR_FILE_NOT_FOUND => Ok(None),
        code => Err(io::Error::from_raw_os_error(code as i32)),
    }
}

/// One address of one interface on this host.
#[derive(Debug, Clone)]
pub struct HostAddress {
    /// The interface's alias.
    pub ifname: String,
    /// Its description: the driver's own name for it ("Hyper-V Virtual
    /// Ethernet Adapter"), which says more than an alias like "Ethernet 2".
    pub description: String,
    /// `IF_TYPE_*` (IANA ifType).
    pub if_type: u32,
    pub addr: IpAddr,
    pub prefix_len: u8,
}

/// Every unicast address on every interface, in the order Windows lists
/// them. The counterpart of walking `getifaddrs`.
pub fn host_addresses() -> io::Result<Vec<HostAddress>> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    // 15 KB is what Microsoft suggests to start with; the call says how
    // much it needs when that is not enough.
    let mut len: u32 = 15 * 1024;
    let mut buf: Vec<u64>;
    loop {
        buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buf` is `len` bytes, 8-aligned, and only written by the call.
        let code = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                std::ptr::null(),
                buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut len,
            )
        };
        match code {
            NO_ERROR => break,
            ERROR_BUFFER_OVERFLOW => continue,
            // No adapters at all.
            ERROR_NO_DATA => return Ok(Vec::new()),
            code => return Err(io::Error::from_raw_os_error(code as i32)),
        }
    }
    let mut out = Vec::new();
    let mut adapter = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !adapter.is_null() {
        // SAFETY: the list lives in `buf`, which outlives this loop, and every
        // pointer in it was filled in by the call above.
        let a = unsafe { &*adapter };
        let ifname = unsafe { from_wide(a.FriendlyName) };
        let description = unsafe { from_wide(a.Description) };
        let mut unicast = a.FirstUnicastAddress;
        while !unicast.is_null() {
            let u = unsafe { &*unicast };
            if let Some(addr) = unsafe { from_sockaddr(u.Address.lpSockaddr) } {
                out.push(HostAddress {
                    ifname: ifname.clone(),
                    description: description.clone(),
                    if_type: a.IfType,
                    addr,
                    prefix_len: u.OnLinkPrefixLength,
                });
            }
            unicast = u.Next;
        }
        adapter = a.Next;
    }
    Ok(out)
}

/// The interface's settings for one address family; `None` when that
/// family is not enabled on it (IPv6 turned off, say).
fn ip_interface(luid: NET_LUID_LH, family: ADDRESS_FAMILY) -> Option<MIB_IPINTERFACE_ROW> {
    // SAFETY: an all-zero row is valid input to InitializeIpInterfaceEntry.
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = family;
    row.InterfaceLuid = luid;
    (unsafe { GetIpInterfaceEntry(&mut row) } == NO_ERROR).then_some(row)
}

/// Sets the interface's MTU for every family enabled on it.
pub fn set_mtu(luid: NET_LUID_LH, mtu: u32) -> io::Result<()> {
    for family in [AF_INET, AF_INET6] {
        let Some(mut row) = ip_interface(luid, family) else {
            continue;
        };
        row.NlMtu = mtu;
        // SetIpInterfaceEntry refuses an IPv4 row with the site prefix
        // length GetIpInterfaceEntry itself returned.
        if family == AF_INET {
            row.SitePrefixLength = 0;
        }
        // SAFETY: `row` is a complete row read from the same interface.
        check(unsafe { SetIpInterfaceEntry(&mut row) })?;
    }
    Ok(())
}

/// Makes `addrs` (each with its prefix length) exactly the interface's
/// unicast addresses: every other one is removed. An address whose family
/// is turned off on the interface is skipped with a warning, as Linux has
/// no such state to mirror.
pub fn set_addresses(luid: NET_LUID_LH, addrs: &[(IpAddr, u8)]) -> io::Result<()> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: the table is allocated by the call and freed below.
    check(unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) })?;
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize) };
    let mut first_err = None;
    for row in rows {
        // SAFETY: both are plain integers inside the LUID union.
        if unsafe { row.InterfaceLuid.Value != luid.Value } {
            continue;
        }
        let keep = from_sockaddr_inet(&row.Address)
            .is_some_and(|a| addrs.iter().any(|(want, len)| *want == a.ip() && *len == row.OnLinkPrefixLength));
        if !keep {
            if let Err(e) = check(unsafe { DeleteUnicastIpAddressEntry(row) }) {
                first_err.get_or_insert(e);
            }
        }
    }
    unsafe { FreeMibTable(table.cast()) };
    for (addr, prefix_len) in addrs {
        let family = if addr.is_ipv4() { AF_INET } else { AF_INET6 };
        if ip_interface(luid, family).is_none() {
            tracing::warn!(%addr, "not assigning this address: its IP version is turned off on the interface");
            continue;
        }
        // SAFETY: an all-zero row is valid input to InitializeUnicastIpAddressEntry.
        let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.InterfaceLuid = luid;
        row.Address = to_sockaddr_inet(SocketAddr::new(*addr, 0));
        row.OnLinkPrefixLength = *prefix_len;
        // No duplicate-address detection: the address is ours by assignment,
        // and DAD on a point-to-point tunnel only delays it becoming usable.
        row.DadState = IpDadStatePreferred;
        match unsafe { CreateUnicastIpAddressEntry(&row) } {
            NO_ERROR | ERROR_OBJECT_ALREADY_EXISTS => {}
            code => {
                first_err.get_or_insert(io::Error::from_raw_os_error(code as i32));
            }
        }
    }
    first_err.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_addresses_round_trip_through_sockaddr_inet() {
        for addr in ["100.90.0.3:51820", "[fd00::3]:51820", "[fe80::1%7]:9"] {
            let addr: SocketAddr = addr.parse().unwrap();
            assert_eq!(from_sockaddr_inet(&to_sockaddr_inet(addr)), Some(addr));
        }
    }

    #[test]
    fn an_unspecified_family_is_no_address() {
        // SAFETY: all-zero is AF_UNSPEC.
        let zero: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        assert_eq!(from_sockaddr_inet(&zero), None);
    }

    #[test]
    fn an_unknown_alias_is_none_rather_than_an_error() {
        assert!(luid_by_alias("wireserve-no-such-adapter").unwrap().is_none());
    }

    #[test]
    fn this_host_has_a_loopback_address() {
        let all = host_addresses().unwrap();
        assert!(all.iter().any(|a| a.addr == IpAddr::V4(Ipv4Addr::LOCALHOST)), "{all:?}");
    }
}
