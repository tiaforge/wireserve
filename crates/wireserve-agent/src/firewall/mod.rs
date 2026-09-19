//! Firewall backend wiring (spec §5). The trait itself and `ServiceRule`
//! live in `wireserve_types` (shared with any future Windows backend); this
//! module holds the concrete Linux implementation plus the startup
//! sequencing that's a hard spec requirement regardless of which backend is
//! in use.

#[cfg(target_os = "linux")]
pub mod nft;
#[cfg(target_os = "linux")]
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
    //! nftables backend (which needs root and a kernel netfilter hook).

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

/// Real-kernel test support: runs a shell script inside a throwaway
/// unprivileged user+network namespace (`unshare -rn`), where `nft` and
/// `iptables` get `CAP_NET_ADMIN` over a private, empty netfilter state.
/// Nothing touches the host's firewall and no root is needed — but not
/// every environment allows unprivileged user namespaces (some CI
/// containers don't), so callers get `None` there and skip, loudly.
#[cfg(all(test, target_os = "linux"))]
pub mod netns {
    use std::process::Command;

    pub fn available() -> bool {
        Command::new("unshare")
            .args(["-rn", "true"])
            .status()
            .is_ok_and(|s| s.success())
            && super::nft::NFT_CANDIDATES
                .iter()
                .any(|p| std::path::Path::new(p).is_file())
    }

    /// Runs `script` with `sh -c` in a fresh namespace. Returns stdout, or
    /// `None` (after printing why) when namespaces or `nft` are
    /// unavailable. Panics with stderr if the script itself fails.
    pub fn run(script: &str) -> Option<String> {
        if !available() {
            eprintln!("SKIPPED: unprivileged network namespaces or nft unavailable");
            return None;
        }
        let out = Command::new("unshare")
            .args(["-rn", "sh", "-euc", script])
            .output()
            .expect("spawn unshare");
        assert!(
            out.status.success(),
            "netns script failed ({}):\n{}\n--- script ---\n{script}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        Some(String::from_utf8(out.stdout).unwrap())
    }
}
