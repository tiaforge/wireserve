//! Swappable firewall backend trait (spec §5). Lives in the shared types
//! crate rather than the agent binary because it's explicitly meant to be
//! implemented again by a future Windows backend (§9's deferred items),
//! and keeping it here avoids a cross-crate trait-orphan problem if
//! anything else ever needs to reference `ServiceRule`.

use std::net::Ipv4Addr;

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

/// Replaces the current WireGuard-interface ruleset with exactly the given
/// rules, default-denying everything else on that interface.
pub trait FirewallBackend {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Replace the current ruleset with exactly these rules.
    fn apply(&mut self, rules: &[ServiceRule]) -> Result<(), Self::Error>;

    /// Tear down whatever this backend has applied, returning the interface
    /// to having no firewall state of ours on it.
    fn teardown(&mut self) -> Result<(), Self::Error>;
}
