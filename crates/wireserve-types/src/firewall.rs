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
    Mapped {
        vip: Ipv4Addr,
        node: Ipv4Addr,
        map: PortMap,
    },
    /// `port` opened on the node's own address, as before service
    /// addresses existed. Only used while the coordinator hands out no
    /// address for a service, i.e. one that predates them.
    Open { proto: Proto, port: u16 },
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

/// Replaces the current WireGuard-interface ruleset with exactly the given
/// rules, default-denying everything else on that interface.
pub trait FirewallBackend {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Replace the current ruleset with exactly these rules, plus exactly
    /// these active transit forwarding pairs (PLAN.md M23) — empty
    /// whenever this node currently carries none, whether or not it has
    /// opted in.
    fn apply(&mut self, rules: &[ServiceRule], transit: &[TransitForward]) -> Result<(), Self::Error>;

    /// Tear down whatever this backend has applied, returning the interface
    /// to having no firewall state of ours on it.
    fn teardown(&mut self) -> Result<(), Self::Error>;
}
