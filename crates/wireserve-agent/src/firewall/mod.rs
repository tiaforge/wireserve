//! Firewall backend wiring (spec §5). The trait itself and `ServiceRule`
//! live in `wireserve_types`; the concrete backends are the platform's —
//! nftables on Linux, the Windows Filtering Platform on Windows (see
//! `crate::platform::firewall`). This module holds what every backend
//! shares: the startup sequencing that's a hard spec requirement whichever
//! is in use, and what the host-firewall interop is asked for.

pub mod ip_forward;

use wireserve_types::FirewallBackend;

/// Spec §5: "Startup ordering — `teardown()`-then-deny-all must run
/// *before* the first successful `apply()`; the interface should never
/// come up permissive-by-default while waiting on the first poll
/// response." Calling this before the poll loop's first real `apply(...)`
/// satisfies that regardless of backend.
///
/// One `apply` and no `teardown` before it: `apply` replaces whatever the
/// backend's tables hold, a previous run's included, in one atomic
/// transaction (the nftables backend deletes and re-adds its mesh and
/// carry tables in a single `nft` run), so it is both of spec §5's steps at
/// once. A separate teardown first would delete the previous run's table a
/// process spawn before the deny-all arrived — and after a crash the
/// previous run's interface is still up with all its peers (preflight
/// reuses it), with nothing of ours default-denying it in between.
pub fn startup_sequence<B: FirewallBackend>(backend: &mut B) -> Result<(), B::Error> {
    backend.apply(&[], &wireserve_types::Forwarding::default())
}

/// The daemon's stop, the mirror of [`guarded_bring_up`], in the only
/// order that is closed at every step:
///
/// 1. the host-firewall interop: the host's other firewalls close back
///    over the interfaces, while our own table still default-denies them;
/// 2. `tear_down_interfaces` — the mesh and carry interfaces themselves.
///    Once they are gone nothing arrives on them for a table to filter;
/// 3. our own tables, last.
///
/// The other way round, the interfaces stay up with all their peers and
/// no rules of ours for at least one process spawn. On a host whose own
/// firewall does not default-deny (a plain Debian box, a Docker host)
/// nothing else filters them then, and a SYN a peer sends to an
/// unpublished port in that gap can open a connection that conntrack keeps.
///
/// If `tear_down_interfaces` fails, an interface may still be up, so our
/// tables stay where they are — closed, and replaced atomically by the
/// next start — and the error is returned.
pub fn guarded_tear_down<B, I, E>(
    backend: &mut B,
    interop: &mut I,
    tear_down_interfaces: impl FnOnce() -> Result<(), E>,
) -> Result<(), E>
where
    B: FirewallBackend,
    B::Error: std::fmt::Display,
    I: InteropHandle,
{
    interop.stop();
    tear_down_interfaces()?;
    if let Err(e) = backend.teardown() {
        tracing::warn!(error = %e, "failed to tear down firewall rules during teardown");
    }
    Ok(())
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

/// The mesh interface's interop and, when there is one, the carry
/// interface's (PLAN.md M39). The carry interface forwards nothing but a
/// service's own flows to its target (PLAN.md #278–#280), so its interop
/// opens the services' openings when the mesh interface's does, and never
/// transit, exit or relay ones: nothing of those arrives on it.
pub struct Interops<I> {
    pub main: I,
    pub carry: Option<I>,
}

impl<I: InteropHandle> InteropHandle for Interops<I> {
    fn tick(&self, forward_wanted: ForwardWanted) {
        self.main.tick(forward_wanted);
        if let Some(carry) = &self.carry {
            carry.tick(ForwardWanted { services: forward_wanted.services, ..ForwardWanted::default() });
        }
    }

    fn stop(&mut self) {
        if let Some(carry) = &mut self.carry {
            carry.stop();
        }
        self.main.stop();
    }
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
/// 2. our own table: deny-all, replacing a previous run's in the same
///    transaction (spec §5, see [`startup_sequence`]);
/// 3. the host-firewall interop, now that our default-deny is in place;
/// 4. `bring_up` — the interface itself, last.
///
/// If `bring_up` fails, steps 3 and 2 are undone (in that order) before
/// the error is returned, so a daemon that never came up leaves nothing
/// behind for an interface nobody manages. Our table stays, though, while
/// `still_ours` says the interface is still there and this agent's: after
/// a crash it is the previous run's, still up with its peers, and a
/// bring-up that failed on it must not leave it without a default-deny.
/// The next start replaces the table atomically.
pub fn guarded_bring_up<B, W, I, E>(
    backend: &mut B,
    wg: &mut W,
    preflight: impl FnOnce(&W) -> Result<(), E>,
    start_interop: impl FnOnce() -> I,
    bring_up: impl FnOnce(&mut W) -> Result<(), E>,
    still_ours: impl FnOnce(&W) -> bool,
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
        if still_ours(wg) {
            tracing::warn!("bring-up failed on this agent's own interface: keeping its firewall table");
        } else if let Err(te) = backend.teardown() {
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
    #[allow(clippy::large_enum_variant)]
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
    fn the_carry_interfaces_interop_opens_only_what_a_service_forwards() {
        use super::{ForwardWanted, InteropHandle, Interops};
        use std::sync::{Arc, Mutex};
        #[derive(Clone, Default)]
        struct Recorder(Arc<Mutex<Vec<ForwardWanted>>>);
        impl InteropHandle for Recorder {
            fn tick(&self, forward_wanted: ForwardWanted) {
                self.0.lock().unwrap().push(forward_wanted);
            }
            fn stop(&mut self) {}
        }
        let (main, carry) = (Recorder::default(), Recorder::default());
        let both = Interops { main: main.clone(), carry: Some(carry.clone()) };
        let everything = ForwardWanted { transit: true, services: true, exit: true };
        both.tick(everything);
        both.tick(ForwardWanted { transit: true, services: false, exit: true });
        assert_eq!(*main.0.lock().unwrap(), [everything, ForwardWanted { transit: true, services: false, exit: true }]);
        assert_eq!(
            *carry.0.lock().unwrap(),
            [ForwardWanted { services: true, ..ForwardWanted::default() }, ForwardWanted::default()],
            "a relayed peer's request for a service's target is forwarded from the carry interface (PLAN.md #280)"
        );
    }

    #[test]
    fn startup_sequence_replaces_the_ruleset_with_an_empty_one_and_deletes_nothing_first() {
        let mut backend = FakeFirewallBackend::default();
        startup_sequence(&mut backend).unwrap();
        assert_eq!(
            backend.calls,
            vec![Call::Apply(vec![], Forwarding::default())],
            "a bare teardown first would leave a crashed run's interface without a table until the apply"
        );
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
        run_with(preflight_ok, bring_up_ok, false)
    }

    fn run_with(preflight_ok: bool, bring_up_ok: bool, still_ours: bool) -> (Result<(), ()>, Vec<&'static str>) {
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
            |()| still_ours,
        );
        let result = result.map(|_| ()).map_err(|_| ());
        let entries = log.borrow().clone();
        (result, entries)
    }

    #[test]
    fn bring_up_runs_in_the_safe_order() {
        assert_eq!(
            run(true, true),
            (Ok(()), vec!["preflight", "fw.apply", "interop.start", "bring_up"])
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
                vec!["preflight", "fw.apply", "interop.start", "bring_up", "interop.stop", "fw.teardown"]
            )
        );
    }

    #[test]
    fn a_failed_bring_up_on_our_own_surviving_interface_keeps_its_table() {
        assert_eq!(
            run_with(true, false, true),
            (Err(()), vec!["preflight", "fw.apply", "interop.start", "bring_up", "interop.stop"])
        );
    }

    // ---- guarded_tear_down ----

    use super::guarded_tear_down;

    fn tear_down(interfaces_ok: bool) -> (Result<(), ()>, Vec<&'static str>) {
        let log: Log = Rc::default();
        let mut fw = LoggingBackend(log.clone());
        let mut interop = LoggingInterop(log.clone());
        let result = guarded_tear_down(&mut fw, &mut interop, || {
            log.borrow_mut().push("wg.teardown");
            if interfaces_ok { Ok(()) } else { Err(Failed) }
        });
        let entries = log.borrow().clone();
        (result.map_err(|_| ()), entries)
    }

    #[test]
    fn a_stop_removes_the_interfaces_before_their_table() {
        assert_eq!(tear_down(true), (Ok(()), vec!["interop.stop", "wg.teardown", "fw.teardown"]));
    }

    #[test]
    fn a_stop_that_cannot_remove_the_interfaces_keeps_their_table() {
        assert_eq!(tear_down(false), (Err(()), vec!["interop.stop", "wg.teardown"]));
    }
}
