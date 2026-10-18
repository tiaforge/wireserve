//! Interface-scoped IPv4/IPv6 forwarding for opt-in transit (PLAN.md M23).
//!
//! Deliberately writes the wg interface's own per-interface switches —
//! `/proc/sys/net/ipv4/conf/<ifname>/forwarding` and
//! `/proc/sys/net/ipv6/conf/<ifname>/force_forwarding` — **never** the
//! host's global/`all` switches (`net.ipv4.ip_forward`,
//! `net.ipv6.conf.all.forwarding`).
//!
//! **The two families differ, and the IPv6 half was wrong until M27.**
//! IPv4 forwards a packet when the interface it arrived on has
//! `forwarding` set. IPv6's per-interface `forwarding` only picks host or
//! router behaviour (router advertisements, the IsRouter flag); whether a
//! packet is forwarded at all is decided by `all.forwarding`, or, since
//! Linux 6.17, by `force_forwarding` on the interface it arrived on. This
//! module used to write IPv6's `forwarding`, so IPv6 transit only ever
//! worked on hosts that forwarded globally anyway (Docker, Podman) —
//! verified on a real kernel, see the test at the bottom. On an older
//! kernel there is no per-interface IPv6 switch at all, and turning on
//! `all.forwarding` would make every interface a router and stop the host
//! accepting router advertisements, which can cost it its own IPv6
//! route. So there IPv6 transit is left off, with a warning, and IPv4
//! transit is unaffected. For transit the packet arrives on and leaves by
//! the mesh interface, so that one interface's flag is all it needs. The `wireserve-fwd` FORWARD chain's
//! own base policy is deliberately `accept` for every interface but this
//! one's own `iifname`-matched rules (see `nftables.rs`'s `apply_batch`
//! doc comment for why — a past live-deployment bug taught this project
//! that a stricter base policy silently firewalls off traffic on every
//! interface, not just the ones its rules match, since a base chain's
//! policy is global). A global forwarding switch would leave a
//! multi-homed host (a second NIC, a LAN, a container bridge) forwarding
//! traffic freely between its *other* interfaces too, the moment transit
//! turned it on, with nothing in this project's firewall code scoping
//! that back down. Scoping the kernel-level switch itself to just this
//! interface mirrors the same discipline the firewall rules already
//! apply, instead of relying on the chain to narrow a global switch back
//! down.
//!
//! Best-effort (warn, don't fail the poll cycle) — same posture as
//! `crate::platform::routes::sync`.
//!
//! **Egress interfaces (PLAN.md M26).** A service mapped onto another
//! address (`serve myrouter 443:192.168.178.1:80`) has its replies arrive
//! on the interface facing that address, and IPv4 forwards a packet only if
//! the interface it *arrived on* forwards. So that interface's flag has to
//! be on too — the one thing the discipline above cannot avoid. It is
//! turned on only where it was off and the host does not forward globally
//! (a host that does is a router, or runs Docker or Podman, and the switch
//! is not ours to own), and while it is ours, our table drops everything
//! forwarded from that interface that is not one of our own flows (see
//! `Forwarding::guarded`), so the host does not become a router for its
//! LAN. Ownership is kept in the state file, not in memory, so a crashed
//! agent's successor still knows what it has to guard and turn back off.

use std::collections::BTreeSet;

/// Writing the switches is the platform's: Linux's `/proc/sys` (see
/// `platform::linux::forwarding`); nothing where nothing is forwarded.
pub use crate::platform::forwarding::{begin_egress, ipv6_per_interface_supported, release_egress, set_enabled, take_egress};

/// What one cycle does about egress forwarding; see [`plan_egress`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EgressPlan {
    /// Owned after this cycle, once `take` is done: the ruleset guards
    /// exactly these.
    pub guard: BTreeSet<String>,
    /// Off now, and ours to turn on — only after the guard is in place.
    pub take: BTreeSet<String>,
    /// Ours, and no longer wanted: turned off before the guard goes.
    pub release: BTreeSet<String>,
}

/// Decides, from the interfaces this cycle's targets are reached through
/// (`wanted`) and those this agent owns (`owned`), what to turn on, off
/// and guard. `flag` reads an interface's IPv4 forwarding switch (`None`:
/// no such interface); `all_on` is the host-wide one.
///
/// A host that forwards globally owns nothing of ours: everything is
/// forgotten without a write — turning a flag off there would break
/// whatever turned forwarding on, and guarding it would break its traffic.
/// An interface that already forwards and isn't ours stays someone else's.
#[must_use]
pub fn plan_egress(
    wanted: &BTreeSet<String>,
    owned: &BTreeSet<String>,
    all_on: bool,
    flag: impl Fn(&str) -> Option<bool>,
) -> EgressPlan {
    let mut plan = EgressPlan::default();
    if all_on {
        return plan;
    }
    for name in owned.difference(wanted) {
        if flag(name) == Some(true) {
            plan.release.insert(name.clone());
        }
    }
    for name in wanted {
        match (owned.contains(name), flag(name)) {
            // Ours; switched off behind our back — back on, it's needed.
            (true, Some(false)) | (false, Some(false)) => {
                plan.guard.insert(name.clone());
                plan.take.insert(name.clone());
            }
            (true, Some(true)) => {
                plan.guard.insert(name.clone());
            }
            // Someone else's forwarding, or the interface is gone.
            (false, Some(true)) | (_, None) => {}
        }
    }
    plan
}

#[cfg(test)]
mod egress_tests {
    use super::*;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    fn flags<'a>(on: &'a [&'a str], off: &'a [&'a str]) -> impl Fn(&str) -> Option<bool> + 'a {
        move |n| {
            if on.contains(&n) {
                Some(true)
            } else if off.contains(&n) {
                Some(false)
            } else {
                None
            }
        }
    }

    #[test]
    fn an_interface_that_does_not_forward_is_taken_and_guarded() {
        let plan = plan_egress(&set(&["eth0"]), &set(&[]), false, flags(&[], &["eth0"]));
        assert_eq!(plan, EgressPlan { guard: set(&["eth0"]), take: set(&["eth0"]), release: set(&[]) });
    }

    #[test]
    fn an_interface_someone_else_turned_on_is_left_alone() {
        let plan = plan_egress(&set(&["eth0"]), &set(&[]), false, flags(&["eth0"], &[]));
        assert_eq!(plan, EgressPlan::default(), "not ours: neither guarded nor ever turned off");
    }

    #[test]
    fn an_owned_interface_stays_guarded_and_is_released_when_no_longer_wanted() {
        let plan = plan_egress(&set(&["eth0"]), &set(&["eth0"]), false, flags(&["eth0"], &[]));
        assert_eq!(plan, EgressPlan { guard: set(&["eth0"]), take: set(&[]), release: set(&[]) });

        let plan = plan_egress(&set(&[]), &set(&["eth0"]), false, flags(&["eth0"], &[]));
        assert_eq!(plan, EgressPlan { guard: set(&[]), take: set(&[]), release: set(&["eth0"]) });

        // Already off (by someone else): forgotten, nothing written.
        let plan = plan_egress(&set(&[]), &set(&["eth0"]), false, flags(&[], &["eth0"]));
        assert_eq!(plan, EgressPlan::default());
    }

    #[test]
    fn a_host_that_forwards_globally_owns_nothing_of_ours() {
        // Docker started since: `all` rewrote every interface's flag. A
        // guard would now break the runtime's forwarding, and turning the
        // flag off would break it outright.
        let plan = plan_egress(&set(&["eth0"]), &set(&["eth0"]), true, flags(&["eth0"], &[]));
        assert_eq!(plan, EgressPlan::default());
    }

    #[test]
    fn a_vanished_interface_is_neither_guarded_nor_written() {
        let plan = plan_egress(&set(&["usb0"]), &set(&["usb0"]), false, flags(&[], &[]));
        assert_eq!(plan, EgressPlan::default());
    }

}
