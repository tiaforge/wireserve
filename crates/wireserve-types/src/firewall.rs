//! Swappable firewall backend trait (spec §5). Lives in the shared types
//! crate rather than the agent binary because it's explicitly meant to be
//! implemented again by a future Windows backend (§9's deferred items),
//! and keeping it here avoids a cross-crate trait-orphan problem if
//! anything else ever needs to reference `ServiceRule`.

use crate::node::Proto;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceRule {
    pub proto: Proto,
    pub port: u16,
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
