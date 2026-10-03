//! Swappable firewall backend trait (spec §5). Lives in the shared types
//! crate rather than the agent binary because it's explicitly meant to be
//! implemented again by a future Windows backend (§9's deferred items),
//! and keeping it here avoids a cross-crate trait-orphan problem if
//! anything else ever needs to reference `ServiceRule`.

use std::net::Ipv4Addr;

use crate::ports::PortMap;

/// Which mesh addresses a rule admits (PLAN.md M36): `None` is every one,
/// as before grants; `Some` only these — and an empty list none at all,
/// though the service address still answers them with a refusal.
pub type Sources = Option<std::sync::Arc<[Ipv4Addr]>>;

/// One hole in the default-deny on the mesh interface.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    Mapped { vip: Ipv4Addr, node: Ipv4Addr, map: PortMap, sources: Sources },
    /// `vip:map.public` answered by this node's own TLS terminator
    /// (PLAN.md M33): rewritten to `vip:port`, where the terminator listens
    /// on every address (PLAN.md M35), and nothing of `map.target` is
    /// opened — the terminator reaches the backend locally. `map` is kept
    /// so the target stays reserved against every other mapping on the node.
    Terminated { vip: Ipv4Addr, map: PortMap, port: u16, sources: Sources },
}

/// One side of a relayed pair (PLAN.md M39), as its carrier sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayEnd {
    /// Its mesh address.
    pub ip4: Ipv4Addr,
    /// Its relay port: what the carrier receives its packets on, and what
    /// the carrier sends from towards the other side.
    pub relay_port: u16,
    /// The listen port of its carry interface, where the session ends.
    pub carry_port: u16,
}

/// A node this node relays phones to (PLAN.md M40): UDP arriving from the
/// internet at `port` goes on to `to:to_port`, the node's own WireGuard
/// port, leaving this node from its mesh address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicRelay {
    pub port: u16,
    pub to: Ipv4Addr,
    pub to_port: u16,
}

/// A pair whose end-to-end session this node relays (PLAN.md M39): UDP
/// arriving on this node's mesh address at one side's relay port goes on
/// to that side's carry interface, appearing to come from the other
/// side's relay port. Nothing is decrypted: this node never holds the
/// session's keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayForward {
    pub a: RelayEnd,
    pub c: RelayEnd,
}

impl ServiceRule {
    /// The mesh addresses this rule admits; see [`Sources`].
    #[must_use]
    pub fn sources(&self) -> &Sources {
        match self {
            Self::Mapped { sources, .. } | Self::Terminated { sources, .. } => sources,
        }
    }

    /// For a mapping onto another address (PLAN.md M26): that address.
    #[must_use]
    pub fn remote_target(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Mapped { map, .. } => map.addr,
            // The terminator connects to a remote target itself, as an
            // ordinary local process: nothing is forwarded for it.
            Self::Terminated { .. } => None,
        }
    }
}

/// What this node forwards, beyond delivering to itself: applied in the
/// same transaction as the service rules, so the two never disagree about
/// which cycle they reflect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Forwarding {
    /// Pairs this node relays end to end (PLAN.md M39). Needs `relay_self`.
    pub relay: Vec<RelayForward>,
    /// This node's own mesh address, which relayed packets arrive at and
    /// leave from. Without it no relay rule is written.
    pub relay_self: Option<Ipv4Addr>,
    /// UDP ports of this node's own WireGuard interfaces that relayed
    /// sessions arrive at through the mesh interface (PLAN.md M39, M40):
    /// the carry interface's listen port, and the mesh interface's own for
    /// a phone relayed through a carrier's public port. WireGuard
    /// authenticates every packet on them, so letting the mesh send there
    /// opens nothing else.
    pub relay_ends: Vec<u16>,
    /// Nodes this node relays phones to (PLAN.md M40): what arrives on
    /// `relay_public_iface` at one of their relay ports goes on to them.
    pub relay_public: Vec<PublicRelay>,
    /// The interface phones reach this node's public address on — the one
    /// its default route leaves by. `None` writes no public relay rules.
    pub relay_public_iface: Option<String>,
    /// Every relay port, and the ports relayed phone sessions leave this
    /// node from, as two inclusive ranges. The first is closed to anything
    /// not relayed on every interface but the mesh's, so a packet that
    /// arrives before its relay rule is dropped rather than tracked — and
    /// then kept alive untranslated by its sender's keepalives. Checked
    /// ports (`relay_checks`) are left open for their check.
    pub relay_ranges: Option<((u16, u16), (u16, u16))>,
    /// Relay ports under a port check right now, which a listener of the
    /// agent's own answers.
    pub relay_checks: Vec<u16>,
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
/// destinations, and `device create` refuses them as the full-tunnel
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
