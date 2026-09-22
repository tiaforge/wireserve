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
