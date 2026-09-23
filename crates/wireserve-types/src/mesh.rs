//! The mesh's own address ranges, as the coordinator allocates from them
//! and as an agent checks directory entries against them (security review
//! finding #4).

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// The coordinator's configured mesh ranges, in the same notation as
/// `WIRESERVE_NET_V4_CIDR` / `WIRESERVE_NET_V6_PREFIX`. Sent at
/// registration and on every poll; an agent pins the first one it can
/// verify and never takes a different one afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshInfo {
    pub net_v4_cidr: String,
    pub net_v6_prefix: String,
}

/// [`MeshInfo`], parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshRanges {
    v4: (u32, u32),
    v6: (u128, u32),
}

impl MeshRanges {
    /// `None` if either range doesn't parse.
    #[must_use]
    pub fn parse(info: &MeshInfo) -> Option<Self> {
        let (a4, l4) = info.net_v4_cidr.split_once('/')?;
        let (a6, l6) = info.net_v6_prefix.split_once('/')?;
        let (a4, l4): (Ipv4Addr, u32) = (a4.parse().ok()?, l4.parse().ok()?);
        let (a6, l6): (Ipv6Addr, u32) = (a6.parse().ok()?, l6.parse().ok()?);
        if l4 > 32 || l6 > 128 {
            return None;
        }
        Some(Self {
            v4: (u32::from(a4) & mask32(l4), l4),
            v6: (u128::from(a6) & mask128(l6), l6),
        })
    }

    /// The v4 range in canonical `network/len` form, rebuilt from the
    /// parsed value rather than echoed from the input.
    ///
    /// Anything rendered into a WireGuard `.conf` has to come back out of a
    /// parser, never straight from a configured string — the same rule
    /// `export-config`'s service addresses already follow. A mesh CIDR
    /// reaches the coordinator from `WIRESERVE_NET_V4_CIDR` or the bootstrap
    /// file, neither of which is structurally validated at load (the startup
    /// checks only warn), so it is exactly the kind of value that could
    /// otherwise carry an extra `.conf` directive into the file.
    #[must_use]
    pub fn v4_cidr(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.v4.0), self.v4.1)
    }

    /// The v6 range in canonical `network/len` form. See [`Self::v4_cidr`].
    #[must_use]
    pub fn v6_prefix(&self) -> String {
        format!("{}/{}", Ipv6Addr::from(self.v6.0), self.v6.1)
    }

    #[must_use]
    pub fn contains4(&self, addr: Ipv4Addr) -> bool {
        u32::from(addr) & mask32(self.v4.1) == self.v4.0
    }

    #[must_use]
    pub fn contains6(&self, addr: Ipv6Addr) -> bool {
        u128::from(addr) & mask128(self.v6.1) == self.v6.0
    }
}

fn mask32(len: u32) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - len) }
}

fn mask128(len: u32) -> u128 {
    if len == 0 { 0 } else { u128::MAX << (128 - len) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(v4: &str, v6: &str) -> Option<MeshRanges> {
        MeshRanges::parse(&MeshInfo { net_v4_cidr: v4.into(), net_v6_prefix: v6.into() })
    }

    #[test]
    fn membership_follows_the_prefix_length() {
        let r = ranges("10.90.0.0/24", "fdb4:d481:7c21::/64").unwrap();
        assert!(r.contains4("10.90.0.1".parse().unwrap()));
        assert!(!r.contains4("10.90.1.1".parse().unwrap()));
        assert!(!r.contains4("192.168.1.1".parse().unwrap()));
        assert!(r.contains6("fdb4:d481:7c21::5".parse().unwrap()));
        assert!(!r.contains6("fdb4:d481:7c22::5".parse().unwrap()));
    }

    #[test]
    fn host_bits_in_the_configured_network_are_ignored() {
        let r = ranges("10.90.0.77/24", "fdb4:d481:7c21::9/64").unwrap();
        assert!(r.contains4("10.90.0.1".parse().unwrap()));
        assert!(r.contains6("fdb4:d481:7c21::1".parse().unwrap()));
    }

    #[test]
    fn canonical_forms_are_rebuilt_from_the_parsed_value_not_echoed() {
        // Host bits are dropped, and nothing of the input string survives —
        // which is the point: this is what gets written into a .conf.
        let r = ranges("10.90.0.77/24", "fdb4:d481:7c21::9/64").unwrap();
        assert_eq!(r.v4_cidr(), "10.90.0.0/24");
        assert_eq!(r.v6_prefix(), "fdb4:d481:7c21::/64");
    }

    #[test]
    fn a_range_carrying_conf_syntax_never_parses_so_never_renders() {
        assert!(ranges("10.90.0.0/24\nAllowedIPs = 0.0.0.0/0", "fd00::/64").is_none());
        assert!(ranges("10.90.0.0/24", "fd00::/64\nEndpoint = evil.example:1").is_none());
    }

    #[test]
    fn garbage_does_not_parse() {
        assert!(ranges("10.90.0.0", "fd00::/64").is_none());
        assert!(ranges("10.90.0.0/33", "fd00::/64").is_none());
        assert!(ranges("10.90.0.0/24", "fd00::/129").is_none());
        assert!(ranges("nonsense/24", "fd00::/64").is_none());
    }
}
