//! Firewall backend wiring (spec §5). The trait itself and `ServiceRule`
//! live in `wireserve_types` (shared with any future Windows backend); this
//! module holds the concrete Linux implementation plus the startup
//! sequencing that's a hard spec requirement regardless of which backend is
//! in use.

#[cfg(target_os = "linux")]
pub mod nft;
#[cfg(target_os = "linux")]
pub mod nftables;
#[cfg(target_os = "linux")]
pub mod host_interop;
pub mod ip_forward;

use wireserve_types::FirewallBackend;

/// Spec §5: "Startup ordering — `teardown()`-then-deny-all must run
/// *before* the first successful `apply()`; the interface should never
/// come up permissive-by-default while waiting on the first poll
/// response." Calling this before the poll loop's first real `apply(...)`
/// satisfies that regardless of backend.
pub fn startup_sequence<B: FirewallBackend>(backend: &mut B) -> Result<(), B::Error> {
    backend.teardown()?;
    backend.apply(&[], &wireserve_types::Forwarding::default())
}

/// Which forwarded traffic from and to the mesh interface the host's other
/// firewalls must leave to our own table. Neither: `FORWARD` is left
/// exactly as untouched as it was before either existed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ForwardWanted {
    /// This node is transit-capable (PLAN.md M23): mesh → mesh.
    pub transit: bool,
    /// This node declares a service mapped onto another address (PLAN.md
    /// M26): mesh → elsewhere and back, for flows our table marked only.
    pub services: bool,
    /// This node is an exit (PLAN.md M27): mesh → internet and back, for
    /// flows our table marked with the exit bit only.
    pub exit: bool,
}

impl ForwardWanted {
    #[must_use]
    pub fn any(self) -> bool {
        self.transit || self.services || self.exit
    }

    /// What the daemon's state calls for right now.
    #[must_use]
    pub fn of(state: &crate::state::AgentState) -> Self {
        Self {
            transit: state.transit_capable,
            services: state
                .declared_services
                .iter()
                .any(|d| d.ports.clone().iter().any(|m| m.addr.is_some())),
            exit: state.exit_capable,
        }
    }
}

/// The running host-firewall interop, as the daemon sees it.
pub trait InteropHandle {
    /// Poll-tick safety net: reconcile now.
    ///
    /// `forward_wanted` is passed every tick rather than captured at start,
    /// because `wireserve transit on` and `serve` change it on a
    /// running daemon.
    fn tick(&self, forward_wanted: ForwardWanted);
    /// Remove everything the interop added. Idempotent.
    fn stop(&mut self);
}

/// Stand-in where there is no host-firewall interop (non-Linux).
pub struct NoopInterop;

impl InteropHandle for NoopInterop {
    fn tick(&self, _forward_wanted: ForwardWanted) {}
    fn stop(&mut self) {}
}

/// The daemon's bring-up, in the only order that is safe:
///
/// 1. `preflight` — the interface name is ours to use (free, or this
///    agent's own interface from a previous run). Runs **before any
///    firewall change**: every rule below is keyed on the interface name,
///    so running them for a name someone else owns (a wg-quick `wg0`, a
///    typo such as `eth0`) would default-deny that interface — cutting off
///    the other tunnel, or SSH — and open it through ufw/firewalld.
/// 2. our own table: teardown, then deny-all (spec §5);
/// 3. the host-firewall interop, now that our default-deny is in place;
/// 4. `bring_up` — the interface itself, last.
///
/// If `bring_up` fails, steps 3 and 2 are undone (in that order) before
/// the error is returned, so a daemon that never came up leaves nothing
/// behind for an interface nobody manages.
pub fn guarded_bring_up<B, W, I, E>(
    backend: &mut B,
    wg: &mut W,
    preflight: impl FnOnce(&W) -> Result<(), E>,
    start_interop: impl FnOnce() -> I,
    bring_up: impl FnOnce(&mut W) -> Result<(), E>,
) -> Result<I, E>
where
    B: FirewallBackend,
    B::Error: std::fmt::Display,
    I: InteropHandle,
    E: From<B::Error>,
{
    preflight(wg)?;
    startup_sequence(backend)?;
    let mut interop = start_interop();
    if let Err(e) = bring_up(wg) {
        interop.stop();
        if let Err(te) = backend.teardown() {
            tracing::warn!(error = %te, "failed to remove firewall rules after a failed bring-up");
        }
        return Err(e);
    }
    Ok(interop)
}

#[cfg(test)]
pub mod fake {
    //! A `FirewallBackend` test double that records call order, so the
    //! startup-sequencing requirement can be verified without a real
    //! nftables backend (which needs root and a kernel netfilter hook).

    use wireserve_types::{FirewallBackend, Forwarding, ServiceRule};

    #[derive(Debug, Clone, PartialEq)]
    pub enum Call {
        Teardown,
        Apply(Vec<ServiceRule>, Forwarding),
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

        fn apply(&mut self, rules: &[ServiceRule], forwarding: &Forwarding) -> Result<(), Self::Error> {
            self.calls.push(Call::Apply(rules.to_vec(), forwarding.clone()));
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
    use wireserve_types::{FirewallBackend, Forwarding, Proto, ServiceRule};

    #[test]
    fn startup_sequence_tears_down_then_applies_empty_ruleset() {
        let mut backend = FakeFirewallBackend::default();
        startup_sequence(&mut backend).unwrap();
        assert_eq!(backend.calls, vec![Call::Teardown, Call::Apply(vec![], Forwarding::default())]);
    }

    const NODE: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 90, 0, 2);
    const VIP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(100, 90, 0, 50);

    #[test]
    fn startup_sequence_runs_strictly_before_first_real_apply() {
        let mut backend = FakeFirewallBackend::default();
        startup_sequence(&mut backend).unwrap();
        backend
            .apply(
                &[ServiceRule::Mapped { vip: VIP, node: NODE, map: wireserve_types::PortMap::identity(32400, Proto::Tcp), sources: None }],
                &Forwarding::default(),
            )
            .unwrap();

        assert_eq!(
            backend.calls,
            vec![
                Call::Teardown,
                Call::Apply(vec![], Forwarding::default()),
                Call::Apply(
                    vec![ServiceRule::Mapped { vip: VIP, node: NODE, map: wireserve_types::PortMap::identity(32400, Proto::Tcp), sources: None }],
                    Forwarding::default()
                ),
            ]
        );
    }

    // ---- guarded_bring_up ----

    use super::{guarded_bring_up, InteropHandle};
    use std::cell::RefCell;
    use std::rc::Rc;

    type Log = Rc<RefCell<Vec<&'static str>>>;

    struct LoggingBackend(Log);
    impl FirewallBackend for LoggingBackend {
        type Error = super::fake::FakeError;
        fn apply(&mut self, _rules: &[ServiceRule], _forwarding: &Forwarding) -> Result<(), Self::Error> {
            self.0.borrow_mut().push("fw.apply");
            Ok(())
        }
        fn teardown(&mut self) -> Result<(), Self::Error> {
            self.0.borrow_mut().push("fw.teardown");
            Ok(())
        }
    }

    struct LoggingInterop(Log);
    impl InteropHandle for LoggingInterop {
        fn tick(&self, _forward_wanted: super::ForwardWanted) {}
        fn stop(&mut self) {
            self.0.borrow_mut().push("interop.stop");
        }
    }

    #[derive(Debug)]
    struct Failed;
    impl From<super::fake::FakeError> for Failed {
        fn from(_: super::fake::FakeError) -> Self {
            Failed
        }
    }

    fn run(preflight_ok: bool, bring_up_ok: bool) -> (Result<(), ()>, Vec<&'static str>) {
        let log: Log = Rc::default();
        let mut fw = LoggingBackend(log.clone());
        let result = guarded_bring_up(
            &mut fw,
            &mut (),
            |()| {
                log.borrow_mut().push("preflight");
                if preflight_ok { Ok(()) } else { Err(Failed) }
            },
            || {
                log.borrow_mut().push("interop.start");
                LoggingInterop(log.clone())
            },
            |()| {
                log.borrow_mut().push("bring_up");
                if bring_up_ok { Ok(()) } else { Err(Failed) }
            },
        );
        let result = result.map(|_| ()).map_err(|_| ());
        let entries = log.borrow().clone();
        (result, entries)
    }

    #[test]
    fn bring_up_runs_in_the_safe_order() {
        assert_eq!(
            run(true, true),
            (Ok(()), vec!["preflight", "fw.teardown", "fw.apply", "interop.start", "bring_up"])
        );
    }

    #[test]
    fn failed_preflight_touches_no_firewall_at_all() {
        assert_eq!(run(false, true), (Err(()), vec!["preflight"]));
    }

    #[test]
    fn failed_bring_up_undoes_interop_then_our_table() {
        assert_eq!(
            run(true, false),
            (
                Err(()),
                vec![
                    "preflight",
                    "fw.teardown",
                    "fw.apply",
                    "interop.start",
                    "bring_up",
                    "interop.stop",
                    "fw.teardown"
                ]
            )
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

    const IN_NETNS: &str = "WIRESERVE_TEST_IN_NETNS";

    /// Re-runs the test at `path` (as `--exact` knows it) inside a fresh
    /// network namespace. Returns whether the caller is already inside it
    /// and should do the work; outside, it waits for the inner run and
    /// fails if that did.
    pub fn reexec(path: &str) -> bool {
        if std::env::var_os(IN_NETNS).is_some() {
            return true;
        }
        if !available() {
            eprintln!("SKIPPED: unprivileged network namespaces or nft unavailable");
            return false;
        }
        let status = Command::new("unshare")
            .arg("-rn")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", path, "--nocapture"])
            .env(IN_NETNS, "1")
            .status()
            .unwrap();
        assert!(status.success(), "in-namespace run failed");
        false
    }

    /// Like [`run`], but a failing script is returned rather than a
    /// panic: stdout and stderr, for a test that inspects what failed.
    pub fn run_capturing(script: &str) -> Option<(String, String)> {
        if !available() {
            eprintln!("SKIPPED: unprivileged network namespaces or nft unavailable");
            return None;
        }
        let out = Command::new("unshare").args(["-rn", "sh", "-euc", script]).output().expect("spawn unshare");
        Some((String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap()))
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
