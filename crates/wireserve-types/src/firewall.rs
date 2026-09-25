//! Swappable firewall backend trait (spec §5). Lives in the shared types
//! crate rather than the agent binary because it's explicitly meant to be
//! implemented again by a future Windows backend (§9's deferred items),
//! and keeping it here avoids a cross-crate trait-orphan problem if
//! anything else ever needs to reference `ServiceRule`.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::node::Proto;
use crate::ports::PortMap;

/// One hole in the default-deny on the mesh interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceRule {
    /// `vip:map.public` → `node:map.target`, and nothing else of the
    /// target port: a peer connecting straight to `node:map.target` (or
    /// `vip:map.target`) is still refused. The client's own address is
    /// kept end to end — the service sees who is really connecting.
    ///
    /// With `map.addr` set (PLAN.md M26) the target is that address
    /// instead of `node`, and the node forwards to it: the request leaves
    /// with the node's own address as its source, since whatever answers
    /// there has no route back into the mesh.
    Mapped {
        vip: Ipv4Addr,
        node: Ipv4Addr,
        map: PortMap,
    },
    /// `port` opened on the node's own mesh address(es), as before service
    /// addresses existed. Only used while the coordinator hands out no
    /// address for a service, i.e. one that predates them.
    ///
    /// The addresses are part of the rule, not decoration (security
    /// review finding #3): matched on the port alone, the hole also
    /// admitted a peer's packets *addressed to somewhere else* on that
    /// port — another local address of the node, a container or VM
    /// bridge behind it, its LAN — whenever the node forwards, turning a
    /// declared service into a relay. Only a connection the peer
    /// addressed to one of these is let through.
    Open {
        proto: Proto,
        port: u16,
        node: Ipv4Addr,
        node6: Option<Ipv6Addr>,
    },
}

/// One side of an active [`TransitForward`] pairing (PLAN.md M23): every
/// address that side's peer entry — plus its owned service VIPs — routes
/// to, gathered agent-side from the same poll response's `PeerInfo`/
/// `ServiceInfo` entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransitEndpoint {
    pub ip4: Option<Ipv4Addr>,
    pub ip6: Option<Ipv6Addr>,
    pub vips: Vec<Ipv4Addr>,
}

/// One active transit pairing this node must forward IP traffic between,
/// as this node's own kernel forwarding/firewall rules — never a rewrite,
/// unlike [`ServiceRule::Mapped`] (PLAN.md M23: this node is B, decrypting
/// and re-encrypting an ordinary connection between two other peers, not
/// terminating or rewriting it). Crosses the [`FirewallBackend`] trait
/// boundary the same way [`ServiceRule`] does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransitForward {
    pub near: TransitEndpoint,
    pub far: TransitEndpoint,
}

impl ServiceRule {
    /// For a mapping onto another address (PLAN.md M26): that address.
    #[must_use]
    pub fn remote_target(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Mapped { map, .. } => map.addr,
            Self::Open { .. } => None,
        }
    }
}

/// What this node forwards, beyond delivering to itself: applied in the
/// same transaction as the service rules, so the two never disagree about
/// which cycle they reflect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Forwarding {
    /// Active transit pairs (PLAN.md M23) — empty whenever this node
    /// currently carries none, whether or not it has opted in.
    pub transit: Vec<TransitForward>,
    /// Interfaces whose IPv4 forwarding this agent turned on so replies
    /// from a service's target address can reach the mesh (PLAN.md M26).
    /// Nothing else may be forwarded from them: before the agent turned
    /// the switch on, nothing was.
    pub guarded: Vec<String>,
    /// Devices this node is the exit for (PLAN.md M27), by mesh IPv4
    /// address: their new flows to the internet are forwarded out of the
    /// host and masqueraded. Empty unless this node opted in with
    /// `exit on`.
    pub exit: Vec<std::net::Ipv4Addr>,
    /// The mesh's own IPv4 range, which an exit never forwards to — that
    /// is transit's job, with its own rules. Only read when `exit` is
    /// non-empty; `None` there means no exit rules at all, since without
    /// it the mesh itself would count as "the internet".
    pub mesh_v4: Option<(std::net::Ipv4Addr, u8)>,
}

/// Replaces the current WireGuard-interface ruleset with exactly the given
/// rules, default-denying everything else on that interface.
pub trait FirewallBackend {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Replace the current ruleset with exactly these rules and exactly
    /// this forwarding.
    fn apply(&mut self, rules: &[ServiceRule], forwarding: &Forwarding) -> Result<(), Self::Error>;

    /// Tear down whatever this backend has applied, returning the interface
    /// to having no firewall state of ours on it.
    fn teardown(&mut self) -> Result<(), Self::Error>;
}

/// Where an exit never forwards to (PLAN.md M27): every IPv4 range that is
/// not the public internet. The gateway's own table refuses these as
/// destinations, and `export-config` refuses them as the full-tunnel
/// profile's resolver, so the two can never disagree about what an exit
/// reaches. Private ranges are here on purpose: an exit client reaching the
/// gateway's LAN would bypass the per-service approval a LAN target needs
/// (M26). Documentation ranges are not: they say nothing about
/// reachability, and they are what this project's tests use to mean "a
/// public address".
pub const NOT_THE_INTERNET_V4: [(std::net::Ipv4Addr, u8); 11] = {
    use std::net::Ipv4Addr as A;
    [
        (A::new(0, 0, 0, 0), 8),
        (A::new(10, 0, 0, 0), 8),
        (A::new(100, 64, 0, 0), 10),
        (A::new(127, 0, 0, 0), 8),
        (A::new(169, 254, 0, 0), 16),
        (A::new(172, 16, 0, 0), 12),
        (A::new(192, 0, 0, 0), 24),
        (A::new(192, 168, 0, 0), 16),
        (A::new(198, 18, 0, 0), 15),
        (A::new(224, 0, 0, 0), 4),
        (A::new(240, 0, 0, 0), 4),
    ]
};

/// Whether an exit forwards to `ip`: outside every range in
/// [`NOT_THE_INTERNET_V4`].
#[must_use]
pub fn is_internet_v4(ip: std::net::Ipv4Addr) -> bool {
    NOT_THE_INTERNET_V4.iter().all(|&(net, len)| {
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len)) };
        u32::from(ip) & mask != u32::from(net)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_internet_is_what_is_left_over() {
        for public in ["1.1.1.1", "9.9.9.9", "203.0.113.1", "8.8.4.4", "100.128.0.1", "198.20.0.1"] {
            assert!(is_internet_v4(public.parse().unwrap()), "{public}");
        }
        for not in [
            "0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.1", "127.0.0.1", "169.254.1.1", "172.16.0.1",
            "172.31.255.255", "192.0.0.8", "192.168.0.1", "198.18.0.1", "198.19.255.1", "224.0.0.1",
            "240.0.0.1", "255.255.255.255",
        ] {
            assert!(!is_internet_v4(not.parse().unwrap()), "{not}");
        }
    }
}
