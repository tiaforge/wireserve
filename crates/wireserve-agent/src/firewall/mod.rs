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
    /// This node relays phones from its public address (PLAN.md M40):
    /// internet → mesh and back, for flows our table marked with the relay
    /// bit only.
    pub relay: bool,
    /// This node may be asked to check one of its public relay ports
    /// (PLAN.md M40): the coordinator's probe, which this node's own table
    /// marks with `nftables::CHECK_MARK`, reaches the agent's listener on the
    /// INPUT hook. Not forwarding, and so not part of [`Self::any`]: it opens
    /// no `FORWARD` chain.
    pub relay_check: bool,
}

impl ForwardWanted {
    #[must_use]
    pub fn any(self) -> bool {
        self.transit || self.services || self.exit || self.relay
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
            relay: state.transit_capable
                && state.last_directory.as_ref().is_some_and(|d| !d.relay_public.is_empty()),
            // Only a carrier is ever asked to check a port. The opening lets
            // in nothing until a check is under way, since only then does
            // our table mark anything with the bit it matches.
            relay_check: state.transit_capable,
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
        let everything = ForwardWanted { transit: true, services: true, exit: true, relay: true, relay_check: false };
        both.tick(everything);
        both.tick(ForwardWanted { transit: true, services: false, exit: true, relay: true, relay_check: false });
        assert_eq!(*main.0.lock().unwrap(), [everything, ForwardWanted { transit: true, services: false, exit: true, relay: true, relay_check: false }]);
        assert_eq!(
            *carry.0.lock().unwrap(),
            [ForwardWanted { services: true, ..ForwardWanted::default() }, ForwardWanted::default()],
            "a relayed peer's request for a service's target is forwarded from the carry interface (PLAN.md #280)"
        );
    }

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
