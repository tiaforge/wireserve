//! IP allocation. Not specified by the spec (PLAN.md decisions log #2):
//! first-free-address scan over a configured v4 CIDR / v6 ULA prefix,
//! skipping the network address.

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IpamError {
    #[error("invalid CIDR/prefix: {0}")]
    InvalidRange(String),
    #[error("address range exhausted")]
    Exhausted,
}

/// Smallest unused IPv4 host address in `cidr`, skipping the network
/// address (`.0`). `used` need not be sorted.
pub fn allocate_v4(cidr: &str, used: &[Ipv4Addr]) -> Result<Ipv4Addr, IpamError> {
    let (network, prefix_len) = parse_v4_cidr(cidr)?;
    let host_bits = 32 - prefix_len;
    if host_bits == 0 {
        return Err(IpamError::Exhausted);
    }
    let network_u32 = u32::from(network);
    let max_hosts = 1u32 << host_bits;

    for host in 1..max_hosts {
        let candidate = Ipv4Addr::from(network_u32 | host);
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(IpamError::Exhausted)
}

/// Smallest unused IPv6 host address in `prefix`, skipping the network
/// address (`::`).
pub fn allocate_v6(prefix: &str, used: &[Ipv6Addr]) -> Result<Ipv6Addr, IpamError> {
    let (network, prefix_len) = parse_v6_prefix(prefix)?;
    let host_bits = 128 - prefix_len;
    if host_bits == 0 {
        return Err(IpamError::Exhausted);
    }
    let network_u128 = u128::from(network);
    // Cap the search space for very large prefixes (e.g. /64) — scanning
    // 2^64 addresses is not viable. In practice the used-address table is
    // tiny, so linearly trying low host numbers is sufficient; if that
    // narrow band is ever fully occupied we report exhaustion rather than
    // spin forever.
    let max_hosts: u128 = 1u128 << host_bits.min(32);

    for host in 1..max_hosts {
        let candidate = Ipv6Addr::from(network_u128 | host);
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(IpamError::Exhausted)
}

fn parse_v4_cidr(cidr: &str) -> Result<(Ipv4Addr, u32), IpamError> {
    let (addr_str, len_str) = cidr
        .split_once('/')
        .ok_or_else(|| IpamError::InvalidRange(cidr.to_string()))?;
    let addr: Ipv4Addr = addr_str
        .parse()
        .map_err(|_| IpamError::InvalidRange(cidr.to_string()))?;
    let len: u32 = len_str
        .parse()
        .map_err(|_| IpamError::InvalidRange(cidr.to_string()))?;
    if len > 32 {
        return Err(IpamError::InvalidRange(cidr.to_string()));
    }
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    Ok((Ipv4Addr::from(u32::from(addr) & mask), len))
}

fn parse_v6_prefix(prefix: &str) -> Result<(Ipv6Addr, u32), IpamError> {
    let (addr_str, len_str) = prefix
        .split_once('/')
        .ok_or_else(|| IpamError::InvalidRange(prefix.to_string()))?;
    let addr: Ipv6Addr = addr_str
        .parse()
        .map_err(|_| IpamError::InvalidRange(prefix.to_string()))?;
    let len: u32 = len_str
        .parse()
        .map_err(|_| IpamError::InvalidRange(prefix.to_string()))?;
    if len > 128 {
        return Err(IpamError::InvalidRange(prefix.to_string()));
    }
    let mask = if len == 0 { 0 } else { u128::MAX << (128 - len) };
    Ok((Ipv6Addr::from(u128::from(addr) & mask), len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_allocates_sequentially_from_1() {
        let a = allocate_v4("100.90.0.0/24", &[]).unwrap();
        assert_eq!(a, Ipv4Addr::new(100, 90, 0, 1));
    }

    #[test]
    fn v4_skips_used_addresses() {
        let used = vec![Ipv4Addr::new(100, 90, 0, 1), Ipv4Addr::new(100, 90, 0, 2)];
        let a = allocate_v4("100.90.0.0/24", &used).unwrap();
        assert_eq!(a, Ipv4Addr::new(100, 90, 0, 3));
    }

    #[test]
    fn v4_exhausted_returns_error() {
        // /30 has 2 usable host addresses (.1, .2); network .0 and
        // broadcast-ish .3 both fall in our scanned range's edges, but our
        // algorithm scans host numbers 1..max_hosts (max_hosts = 4 for a
        // /30), i.e. host values 1..3 -> .1, .2, .3. Fill them all.
        let used = vec![
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 3),
        ];
        let result = allocate_v4("10.0.0.0/30", &used);
        assert_eq!(result, Err(IpamError::Exhausted));
    }

    #[test]
    fn v4_rejects_invalid_cidr() {
        assert!(allocate_v4("not-a-cidr", &[]).is_err());
        assert!(allocate_v4("10.0.0.0/33", &[]).is_err());
    }

    #[test]
    fn v6_allocates_sequentially_from_1() {
        let a = allocate_v6("fd00:90::/64", &[]).unwrap();
        assert_eq!(a, "fd00:90::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn v6_skips_used_addresses() {
        let used = vec!["fd00:90::1".parse().unwrap()];
        let a = allocate_v6("fd00:90::/64", &used).unwrap();
        assert_eq!(a, "fd00:90::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn v6_rejects_invalid_prefix() {
        assert!(allocate_v6("not-a-prefix", &[]).is_err());
        assert!(allocate_v6("fd00::/129", &[]).is_err());
    }
}
