//! Firewall backend wiring (spec §5). The trait itself and `ServiceRule`
//! live in `wireserve_types` (shared with any future Windows backend); this
//! module holds the concrete Linux implementation plus the startup
//! sequencing that's a hard spec requirement regardless of which backend is
//! in use.

#[cfg(all(feature = "nftables", target_os = "linux"))]
pub mod nftables;

use wireserve_types::FirewallBackend;

/// Spec §5: "Startup ordering — `teardown()`-then-deny-all must run
/// *before* the first successful `apply()`; the interface should never
/// come up permissive-by-default while waiting on the first poll
/// response." Calling this before the poll loop's first real `apply(...)`
/// satisfies that regardless of backend.
pub fn startup_sequence<B: FirewallBackend>(backend: &mut B) -> Result<(), B::Error> {
    backend.teardown()?;
    backend.apply(&[])
}

#[cfg(test)]
pub mod fake {
    //! A `FirewallBackend` test double that records call order, so the
    //! startup-sequencing requirement can be verified without a real
    //! nftables/netlink backend (which this sandbox can't build — see
    //! Cargo.toml's `nftables` feature).

    use wireserve_types::{FirewallBackend, ServiceRule};

    #[derive(Debug, Clone, PartialEq)]
    pub enum Call {
        Teardown,
        Apply(Vec<ServiceRule>),
    }

    #[derive(Debug, thiserror::Error)]
    #[error("fake firewall backend error")]
    pub struct FakeError;

    #[derive(Debug, Default)]
    pub struct FakeFirewallBackend {
        pub calls: Vec<Call>,
    }

    impl FirewallBackend for FakeFirewallBackend {
        type Error = FakeError;

        fn apply(&mut self, rules: &[ServiceRule]) -> Result<(), Self::Error> {
            self.calls.push(Call::Apply(rules.to_vec()));
            Ok(())
        }

        fn teardown(&mut self) -> Result<(), Self::Error> {
            self.calls.push(Call::Teardown);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{Call, FakeFirewallBackend};
    use super::startup_sequence;
    use wireserve_types::{FirewallBackend, Proto, ServiceRule};

    #[test]
    fn startup_sequence_tears_down_then_applies_empty_ruleset() {
        let mut backend = FakeFirewallBackend::default();
        startup_sequence(&mut backend).unwrap();
        assert_eq!(backend.calls, vec![Call::Teardown, Call::Apply(vec![])]);
    }

    #[test]
    fn startup_sequence_runs_strictly_before_first_real_apply() {
        let mut backend = FakeFirewallBackend::default();
        startup_sequence(&mut backend).unwrap();
        backend
            .apply(&[ServiceRule {
                proto: Proto::Tcp,
                port: 32400,
            }])
            .unwrap();

        assert_eq!(
            backend.calls,
            vec![
                Call::Teardown,
                Call::Apply(vec![]),
                Call::Apply(vec![ServiceRule {
                    proto: Proto::Tcp,
                    port: 32400
                }]),
            ]
        );
    }
}
