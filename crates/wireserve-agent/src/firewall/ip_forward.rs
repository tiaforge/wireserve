//! Interface-scoped IPv4/IPv6 forwarding for opt-in transit (PLAN.md M23).
//!
//! Deliberately writes the wg interface's own per-interface forwarding
//! flag (`/proc/sys/net/{ipv4,ipv6}/conf/<ifname>/forwarding`), **never**
//! the host's global/`all` switches (`net.ipv4.ip_forward`,
//! `net.ipv6.conf.all.forwarding`). The `wireserve-fwd` FORWARD chain's
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
//! `crate::routes::sync`.
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
use std::sync::atomic::{AtomicBool, Ordering};

/// Whether *this process* was the one that last turned forwarding on for
/// this interface — so a later call to disable it only ever writes `0`
/// if this daemon itself is the one that wrote the `1`, never clobbering
/// a forwarding posture some other process or a previous run left
/// behind. Same "don't own state we didn't set" discipline as the
/// host-firewall-interop code.
static ENABLED_BY_US: AtomicBool = AtomicBool::new(false);

/// Enables or disables forwarding on `ifname` alone. Called once per poll
/// cycle with `enabled = !transit_forwards.is_empty()` — idempotent, so
/// writing "on" every cycle while this node keeps carrying at least one
/// pair is harmless. Touched only when this node currently carries at
/// least one active transit pair; a node that opted in but was never
/// selected never has this called with `true`, so its host's forwarding
/// posture is never touched at all.
#[cfg(target_os = "linux")]
pub fn set_enabled(ifname: &str, enabled: bool) {
    if enabled {
        write_flag("ipv4", ifname, true);
        write_flag("ipv6", ifname, true);
        ENABLED_BY_US.store(true, Ordering::Relaxed);
    } else if ENABLED_BY_US.swap(false, Ordering::Relaxed) {
        write_flag("ipv4", ifname, false);
        write_flag("ipv6", ifname, false);
    }
}

#[cfg(target_os = "linux")]
fn write_flag(family: &str, ifname: &str, on: bool) {
    let path = format!("/proc/sys/net/{family}/conf/{ifname}/forwarding");
    if let Err(e) = std::fs::write(&path, if on { b"1".as_slice() } else { b"0".as_slice() }) {
        tracing::warn!(path = %path, error = %e, "could not set interface-scoped forwarding");
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_enabled(_ifname: &str, _enabled: bool) {}

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

/// Whether `name` could be a kernel interface name, so it is safe to put
/// in a `/proc` path — the owned set comes back from the state file.
fn plausible_ifname(name: &str) -> bool {
    !name.is_empty() && name.len() < 16 && name != "." && name != ".." && !name.contains(['/', '\0'])
}

#[cfg(target_os = "linux")]
fn read_flag(path: &str) -> Option<bool> {
    std::fs::read_to_string(path).ok().map(|v| v.trim() != "0")
}

/// [`plan_egress`] against this host, with the releases already written.
#[cfg(target_os = "linux")]
#[must_use]
pub fn begin_egress(wanted: &BTreeSet<String>, owned: &BTreeSet<String>) -> EgressPlan {
    let all_on = read_flag("/proc/sys/net/ipv4/conf/all/forwarding") == Some(true);
    let plan = plan_egress(wanted, owned, all_on, |name| {
        if plausible_ifname(name) {
            read_flag(&format!("/proc/sys/net/ipv4/conf/{name}/forwarding"))
        } else {
            None
        }
    });
    if all_on && !owned.is_empty() {
        tracing::info!(
            interfaces = ?owned,
            "the host now forwards IPv4 on every interface; no longer managing forwarding for service targets"
        );
    }
    release_egress(&plan.release);
    plan
}

/// Turns forwarding on for `take` — call once the guard is in place.
#[cfg(target_os = "linux")]
pub fn take_egress(take: &BTreeSet<String>) {
    for name in take.iter().filter(|n| plausible_ifname(n)) {
        tracing::info!(ifname = %name, "turning on IPv4 forwarding for replies from service targets");
        write_flag("ipv4", name, true);
    }
}

/// Turns forwarding back off where this agent turned it on — on release
/// and on stop. Only while the host still doesn't forward globally, for
/// the reason [`plan_egress`] gives.
#[cfg(target_os = "linux")]
pub fn release_egress(owned: &BTreeSet<String>) {
    if read_flag("/proc/sys/net/ipv4/conf/all/forwarding") == Some(true) {
        return;
    }
    for name in owned.iter().filter(|n| plausible_ifname(n)) {
        tracing::info!(ifname = %name, "turning IPv4 forwarding back off");
        write_flag("ipv4", name, false);
    }
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn begin_egress(_wanted: &BTreeSet<String>, _owned: &BTreeSet<String>) -> EgressPlan {
    EgressPlan::default()
}

#[cfg(not(target_os = "linux"))]
pub fn take_egress(_take: &BTreeSet<String>) {}

#[cfg(not(target_os = "linux"))]
pub fn release_egress(_owned: &BTreeSet<String>) {}

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

    #[test]
    fn implausible_names_never_reach_a_proc_path() {
        for bad in ["", ".", "..", "../all", "a/b", "sixteen-chars-xx"] {
            assert!(!plausible_ifname(bad), "{bad:?}");
        }
        assert!(plausible_ifname("eth0") && plausible_ifname("enp3s0f1"));
    }

    /// Against a real kernel: take and release write the named interface's
    /// flag, and nothing else.
    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_take_and_release_touch_only_the_named_interface() {
        if !crate::firewall::netns::reexec(
            "firewall::ip_forward::egress_tests::kernel_take_and_release_touch_only_the_named_interface",
        ) {
            return;
        }
        let out = std::process::Command::new("sh")
            .args(["-euc", "ip link add lan0 type dummy && ip link add other type dummy"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        // See the test above for why the baseline is set, not assumed.
        for path in [
            "/proc/sys/net/ipv4/conf/all/forwarding",
            "/proc/sys/net/ipv4/conf/lan0/forwarding",
            "/proc/sys/net/ipv4/conf/other/forwarding",
        ] {
            std::fs::write(path, b"0").unwrap();
        }
        let read = |n: &str| read_flag(&format!("/proc/sys/net/ipv4/conf/{n}/forwarding"));

        let plan = begin_egress(&set(&["lan0"]), &set(&[]));
        assert_eq!(plan.take, set(&["lan0"]));
        take_egress(&plan.take);
        assert_eq!((read("lan0"), read("other"), read("all")), (Some(true), Some(false), Some(false)));

        let plan = begin_egress(&set(&[]), &plan.guard);
        assert_eq!(plan, EgressPlan { guard: set(&[]), take: set(&[]), release: set(&["lan0"]) });
        assert_eq!(read("lan0"), Some(false), "released by begin_egress itself");

        // On a host that has since started forwarding globally, stop
        // never turns anything off.
        take_egress(&set(&["lan0"]));
        std::fs::write("/proc/sys/net/ipv4/conf/all/forwarding", b"1").unwrap();
        release_egress(&set(&["lan0"]));
        assert_eq!(read("lan0"), Some(true));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn read(path: &str) -> String {
        std::fs::read_to_string(path).unwrap().trim().to_string()
    }

    /// Regression test for the exact gap this module exists to close: a
    /// real kernel network namespace with two interfaces, asserting
    /// `set_enabled` turns forwarding on for the named one alone.
    ///
    /// **Not asserted against a hardcoded `"0"` baseline.** A fresh
    /// `unshare -rn` namespace inherits `conf.default.forwarding` (and so
    /// every new interface's own starting value, `conf.all.forwarding`
    /// included) from whatever the *host's* namespace already has at the
    /// moment of the clone — confirmed empirically, not assumed: on a
    /// host where Podman/netavark has already turned on `ip_forward=1`
    /// for its own bridge networking (completely normal — and, on a dev
    /// machine that has ever run this project's own container-based e2e
    /// suites, likely already true), a brand-new namespace's `all`,
    /// `default`, and every freshly-created interface all start at `1`,
    /// not `0`. The `other` interface is explicitly zeroed as a control
    /// *before* `set_enabled` runs, specifically so this test still
    /// proves the real property (our write never touches anything but
    /// the named interface) regardless of that ambient inherited value —
    /// asserting a literal `"0"` here previously made this test fail on
    /// exactly the environment it most needs to run correctly in: a
    /// container test host.
    #[test]
    fn set_enabled_scopes_forwarding_to_the_named_interface_only() {
        if !crate::firewall::netns::reexec(
            "firewall::ip_forward::tests::set_enabled_scopes_forwarding_to_the_named_interface_only",
        ) {
            return;
        }
        let out = std::process::Command::new("sh")
            .args(["-euc", "ip link add wgtest type dummy && ip link set wgtest up && ip link add other type dummy && ip link set other up"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

        let wgtest_v4 = "/proc/sys/net/ipv4/conf/wgtest/forwarding";
        let wgtest_v6 = "/proc/sys/net/ipv6/conf/wgtest/forwarding";
        let other_v4 = "/proc/sys/net/ipv4/conf/other/forwarding";
        let all_v4 = "/proc/sys/net/ipv4/conf/all/forwarding";
        std::fs::write(other_v4, b"0").unwrap();
        let all_baseline = read(all_v4);

        set_enabled("wgtest", true);
        assert_eq!(read(wgtest_v4), "1");
        assert_eq!(read(wgtest_v6), "1");
        assert_eq!(read(other_v4), "0", "an unrelated interface must never be turned into a router as a side effect");
        assert_eq!(read(all_v4), all_baseline, "the global switch must never be written, whatever it started at");

        // Only disables what this process itself enabled.
        ENABLED_BY_US.store(false, std::sync::atomic::Ordering::Relaxed);
        set_enabled("wgtest", false);
        assert_eq!(read(wgtest_v4), "1", "must not clobber a posture this process didn't set");

        ENABLED_BY_US.store(true, std::sync::atomic::Ordering::Relaxed);
        set_enabled("wgtest", false);
        assert_eq!(read(wgtest_v4), "0");
        assert_eq!(read(all_v4), all_baseline, "still never written, even on the disable path");
    }
}
