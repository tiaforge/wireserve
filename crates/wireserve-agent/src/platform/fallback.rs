//! Stand-ins where a platform has nothing to do: no forwarding (Windows
//! carries nobody's traffic), and no firewall or host-firewall interop
//! where there is no backend.

use std::collections::BTreeSet;

/// Forwarding, where nothing is ever forwarded.
pub mod forwarding {
    use super::BTreeSet;
    use wireserve_types::ServiceRule;
    use crate::firewall::ip_forward::EgressPlan;

    #[must_use]
    pub fn ipv6_per_interface_supported() -> bool {
        false
    }

    pub fn set_enabled(_ifname: &str, _enabled: bool) {}

    #[must_use]
    pub fn begin_egress(_wanted: &BTreeSet<String>, _owned: &BTreeSet<String>) -> EgressPlan {
        EgressPlan::default()
    }

    pub fn take_egress(_take: &BTreeSet<String>) {}

    pub fn release_egress(_owned: &BTreeSet<String>) {}

    /// Nowhere to forward to.
    pub fn egress_interfaces(_rules: &[ServiceRule], _mesh_ifname: &str) -> BTreeSet<String> {
        BTreeSet::new()
    }

    /// Never an exit.
    pub fn internet_egress(_mesh_ifname: &str) -> Option<String> {
        None
    }
}

/// The service addresses, where the host has none of its own to keep
/// (neither Linux nor Windows).
#[cfg(not(windows))]
pub mod host_addresses {
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;

    /// Only the terminated ones, as on Linux.
    pub const EVERY_SERVICE: bool = false;

    pub fn sync(old: &BTreeSet<Ipv4Addr>, _new: &BTreeSet<Ipv4Addr>, _node: Option<Ipv4Addr>, _ifname: &str) -> BTreeSet<Ipv4Addr> {
        old.clone()
    }

    #[must_use]
    pub fn left_behind(_recorded: &[Ipv4Addr], _range: Option<&wireserve_types::MeshRanges>) -> Vec<Ipv4Addr> {
        Vec::new()
    }

    pub fn remove(_addrs: &[Ipv4Addr]) {}
}

/// No firewall backend (neither Linux nor Windows) — never a supported
/// production configuration, just keeps `daemon` linkable there.
#[cfg(not(windows))]
pub mod firewall {
    use std::net::IpAddr;

    use wireserve_types::FirewallBackend;

    use crate::firewall::{ForwardWanted, NoopInterop};
    use crate::paths::Instance;

    pub struct Backend;

    impl FirewallBackend for Backend {
        type Error = std::convert::Infallible;
        fn apply(
            &mut self,
            _rules: &[wireserve_types::ServiceRule],
            _forwarding: &wireserve_types::Forwarding,
        ) -> Result<(), Self::Error> {
            tracing::warn!("no firewall backend compiled in — firewall rules are NOT being applied");
            Ok(())
        }
        fn teardown(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Clone)]
    pub struct OwnTable;
    pub type Interop = NoopInterop;

    #[allow(clippy::unnecessary_wraps)]
    pub fn backend(_ifname: &str, _carry: Option<String>, _own: &[IpAddr], _instance: &Instance) -> Result<Backend, Box<dyn std::error::Error>> {
        Ok(Backend)
    }

    pub fn own_table(_fw: &Backend) -> OwnTable {
    OwnTable
}

    pub fn start_interop(_ifname: &str, _forward_wanted: ForwardWanted, _own_table: OwnTable) -> Interop {
        NoopInterop
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn after_bring_up(_fw: &mut Backend) -> std::io::Result<()> {
        Ok(())
    }

    pub fn remove_leftover(_name: &str) {}

    pub fn remove_leftover_carry(_main: &str, _private_key: &str) {}
}
