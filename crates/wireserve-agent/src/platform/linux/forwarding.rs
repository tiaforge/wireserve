//! Interface-scoped forwarding on Linux: the `/proc/sys` switches (see
//! `crate::firewall::ip_forward` for what is turned on when, and why only
//! ever one interface's).

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use std::net::Ipv4Addr;

use wireserve_types::ServiceRule;

use crate::firewall::ip_forward::{plan_egress, EgressPlan};

/// The interfaces *this process* last turned forwarding on for — so a
/// later call to disable one only ever writes `0` if this daemon itself
/// is the one that wrote the `1`, never clobbering a forwarding posture
/// some other process or a previous run left behind. Same "don't own
/// state we didn't set" discipline as the host-firewall-interop code. Per
/// interface: the carry interface (PLAN.md #279) has its own.
static ENABLED_BY_US: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// Enables or disables forwarding on `ifname` alone. Called once per poll
/// cycle with `enabled = !transit_forwards.is_empty()` — idempotent, so
/// writing "on" every cycle while this node keeps carrying at least one
/// pair is harmless. Touched only when this node currently carries at
/// least one active transit pair; a node that opted in but was never
/// selected never has this called with `true`, so its host's forwarding
/// posture is never touched at all.
///
/// Written every cycle while enabled, not once: writing `all.forwarding`
/// (as anything toggling Docker's or a VPN's forwarding does) resets every
/// interface's `force_forwarding`, so a one-time write would silently stop
/// IPv6 transit the next time that happened.
pub fn set_enabled(ifname: &str, enabled: bool) {
    let mut ours = ENABLED_BY_US.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if enabled {
        write_flag("ipv4", ifname, true);
        write_v6_flag(ifname, true);
        ours.insert(ifname.to_string());
    } else if ours.remove(ifname) {
        write_flag("ipv4", ifname, false);
        write_v6_flag(ifname, false);
    }
}

/// Whether this kernel can forward IPv6 on one interface alone
/// (`force_forwarding`, Linux 6.17). Read from `conf/all`, which has it
/// whenever any interface does.
#[must_use]
pub fn ipv6_per_interface_supported() -> bool {
    std::path::Path::new("/proc/sys/net/ipv6/conf/all/force_forwarding").exists()
}

/// Said once per daemon run, not every cycle.
static WARNED_NO_V6: AtomicBool = AtomicBool::new(false);

fn write_v6_flag(ifname: &str, on: bool) {
    if ipv6_per_interface_supported() {
        write_sysctl(&format!("/proc/sys/net/ipv6/conf/{ifname}/force_forwarding"), on);
    } else if on
        && read_flag("/proc/sys/net/ipv6/conf/all/forwarding") != Some(true)
        && !WARNED_NO_V6.swap(true, Ordering::Relaxed)
    {
        tracing::warn!(
            "this kernel cannot forward IPv6 on one interface alone (force_forwarding needs \
             Linux 6.17), so this node carries IPv4 transit only; IPv6 between the peers it \
             carries will not get through"
        );
    }
}

fn write_flag(family: &str, ifname: &str, on: bool) {
    write_sysctl(&format!("/proc/sys/net/{family}/conf/{ifname}/forwarding"), on);
}

fn write_sysctl(path: &str, on: bool) {
    if let Err(e) = std::fs::write(path, if on { b"1".as_slice() } else { b"0".as_slice() }) {
        tracing::warn!(path = %path, error = %e, "could not set interface-scoped forwarding");
    }
}

/// Whether `name` could be a kernel interface name, so it is safe to put
/// in a `/proc` path — the owned set comes back from the state file.
fn plausible_ifname(name: &str) -> bool {
    !name.is_empty() && name.len() < 16 && name != "." && name != ".." && !name.contains(['/', '\0'])
}

fn read_flag(path: &str) -> Option<bool> {
    std::fs::read_to_string(path).ok().map(|v| v.trim() != "0")
}

/// [`plan_egress`] against this host, with the releases already written.
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
pub fn take_egress(take: &BTreeSet<String>) {
    for name in take.iter().filter(|n| plausible_ifname(n)) {
        tracing::info!(ifname = %name, "turning on IPv4 forwarding for replies from service targets");
        write_flag("ipv4", name, true);
    }
}

/// Turns forwarding back off where this agent turned it on — on release
/// and on stop. Only while the host still doesn't forward globally, for
/// the reason [`plan_egress`] gives.
pub fn release_egress(owned: &BTreeSet<String>) {
    if read_flag("/proc/sys/net/ipv4/conf/all/forwarding") == Some(true) {
        return;
    }
    for name in owned.iter().filter(|n| plausible_ifname(n)) {
        tracing::info!(ifname = %name, "turning IPv4 forwarding back off");
        write_flag("ipv4", name, false);
    }
}

// The interfaces replies from this cycle's target addresses (PLAN.md M26)
/// arrive on, as the kernel routes to them now. A target the host delivers
/// locally needs none; one routed into the mesh interface is refused
/// earlier (`service_rules`) and never needs forwarding turned on here.
pub fn egress_interfaces(rules: &[ServiceRule], mesh_ifname: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let targets: BTreeSet<Ipv4Addr> = rules.iter().filter_map(ServiceRule::remote_target).collect();
    for addr in targets {
        match crate::platform::routes::egress_ifname(addr) {
            Ok(Some(name)) if name == mesh_ifname => {
                tracing::warn!(%addr, "a service's target address is routed into the mesh; not forwarding to it");
            }
            Ok(Some(name)) => {
                out.insert(name);
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(%addr, error = %e, "no route to a service's target address"),
        }
    }
    out
}

/// The interface this host reaches the internet through, for an exit
/// (PLAN.md M27): where the replies to its clients' traffic arrive. A route
/// lookup only — nothing is sent to the address. A real global one rather
/// than a documentation range, which a host may route to a blackhole.
pub fn internet_egress(mesh_ifname: &str) -> Option<String> {
    const ANY_GLOBAL: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    match crate::platform::routes::egress_ifname(ANY_GLOBAL) {
        Ok(Some(name)) if name != mesh_ifname => Some(name),
        Ok(_) => {
            tracing::warn!("this node's default route leads into the mesh; not acting as an exit");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "this node has no route to the internet; not acting as an exit");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_string()).collect()
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
    #[test]
    fn kernel_take_and_release_touch_only_the_named_interface() {
        if !crate::platform::linux::netns::reexec(
            "platform::linux::forwarding::tests::kernel_take_and_release_touch_only_the_named_interface",
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
        if !crate::platform::linux::netns::reexec(
            "platform::linux::forwarding::tests::set_enabled_scopes_forwarding_to_the_named_interface_only",
        ) {
            return;
        }
        let out = std::process::Command::new("sh")
            .args(["-euc", "ip link add wgtest type dummy && ip link set wgtest up && ip link add other type dummy && ip link set other up"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

        let wgtest_v4 = "/proc/sys/net/ipv4/conf/wgtest/forwarding";
        let wgtest_v6 = "/proc/sys/net/ipv6/conf/wgtest/force_forwarding";
        let other_v4 = "/proc/sys/net/ipv4/conf/other/forwarding";
        let all_v4 = "/proc/sys/net/ipv4/conf/all/forwarding";
        std::fs::write(other_v4, b"0").unwrap();
        let all_baseline = read(all_v4);

        set_enabled("wgtest", true);
        assert_eq!(read(wgtest_v4), "1");
        if ipv6_per_interface_supported() {
            assert_eq!(read(wgtest_v6), "1");
        }
        assert_eq!(read(other_v4), "0", "an unrelated interface must never be turned into a router as a side effect");
        assert_eq!(read(all_v4), all_baseline, "the global switch must never be written, whatever it started at");

        // Only disables what this process itself enabled.
        ENABLED_BY_US.lock().unwrap().remove("wgtest");
        set_enabled("wgtest", false);
        assert_eq!(read(wgtest_v4), "1", "must not clobber a posture this process didn't set");

        ENABLED_BY_US.lock().unwrap().insert("wgtest".into());
        set_enabled("wgtest", false);
        assert_eq!(read(wgtest_v4), "0");
        assert_eq!(read(all_v4), all_baseline, "still never written, even on the disable path");
    }

    /// What the flags are *for*: an IPv6 packet actually crossing a router
    /// namespace, between two peer namespaces on either side of it.
    ///
    /// Pins the bug this module had until M27 — IPv6's per-interface
    /// `forwarding` set on both sides forwards nothing while
    /// `all.forwarding` is off — and that `force_forwarding`, which is read
    /// on the interface a packet *arrives* on, is what does. Transit
    /// arrives on and leaves by the mesh interface, so one interface's flag
    /// covers both directions there; two veths need one each.
    #[test]
    fn kernel_ipv6_forwards_only_with_force_forwarding() {
        if !ipv6_per_interface_supported() {
            eprintln!("SKIPPED: this kernel has no force_forwarding (Linux 6.17+)");
            return;
        }
        if !crate::platform::linux::netns::reexec(
            "platform::linux::forwarding::tests::kernel_ipv6_forwards_only_with_force_forwarding",
        ) {
            return;
        }
        // Two peer namespaces, held open by a sleeping child each, with
        // this namespace routing between them.
        let mut peers = Vec::new();
        for _ in 0..2 {
            peers.push(
                std::process::Command::new("unshare")
                    .args(["-n", "sleep", "60"])
                    .spawn()
                    .unwrap(),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (a, c) = (peers[0].id(), peers[1].id());
        let script = format!(
            "ip link set lo up
             ip link add r-a type veth peer name a-r && ip link set a-r netns {a}
             ip link add r-c type veth peer name c-r && ip link set c-r netns {c}
             ip link set r-a up && ip link set r-c up
             ip -6 addr add fd00:a::1/64 dev r-a nodad && ip -6 addr add fd00:c::1/64 dev r-c nodad
             nsenter -t {a} -n sh -euc 'ip link set lo up; ip link set a-r up; ip -6 addr add fd00:a::2/64 dev a-r nodad; ip -6 route add default via fd00:a::1'
             nsenter -t {c} -n sh -euc 'ip link set lo up; ip link set c-r up; ip -6 addr add fd00:c::2/64 dev c-r nodad; ip -6 route add default via fd00:c::1'
             echo 0 > /proc/sys/net/ipv6/conf/all/forwarding"
        );
        let out = std::process::Command::new("sh").args(["-euc", &script]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        // Any reply of three: the first packet after a flag changes can be
        // lost to neighbour discovery.
        let crosses = || {
            std::process::Command::new("nsenter")
                .args(["-t", &a.to_string(), "-n", "ping", "-6", "-c3", "-i0.2", "-W1", "fd00:c::2"])
                .output()
                .unwrap()
                .status
                .success()
        };
        let write = |path: &str, v: &[u8]| std::fs::write(path, v).unwrap();

        write("/proc/sys/net/ipv6/conf/r-a/forwarding", b"1");
        write("/proc/sys/net/ipv6/conf/r-c/forwarding", b"1");
        let with_forwarding = crosses();
        write("/proc/sys/net/ipv6/conf/r-a/forwarding", b"0");
        write("/proc/sys/net/ipv6/conf/r-c/forwarding", b"0");

        set_enabled("r-a", true);
        set_enabled("r-c", true);
        let with_ours = crosses();
        let all_after = read("/proc/sys/net/ipv6/conf/all/forwarding");

        for mut p in peers {
            let _ = p.kill();
            let _ = p.wait();
        }
        assert!(!with_forwarding, "per-interface `forwarding` alone must not forward IPv6 — if it now does, the module doc is out of date");
        assert!(with_ours, "set_enabled must make IPv6 cross the router");
        assert_eq!(all_after, "0", "the global switch must never be written");
    }
}
