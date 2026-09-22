//! Host-firewall interop, NetBird-style: makes the *other* firewalls on the
//! host let traffic on our interface through, so that our own
//! `wireserve.<ifname>` table is the only thing deciding for it.
//!
//! Why this is needed at all: every base chain on a netfilter hook sees
//! the packet independently, and while a `drop` anywhere is final, an
//! `accept` only ends evaluation of the chain it is in. So our table
//! accepting a declared service does not stop ufw's `INPUT` policy DROP,
//! a native `inet filter input { policy drop }`, or firewalld's zone
//! rules from dropping it anyway. Neither table priority nor anything
//! else within our own table can change that; the only fixes are a rule
//! inside the other tool's chain, or asking the tool itself.
//!
//! What gets added (all runtime-only, all recognisable by the
//! `wireserve:<ifname>` comment, all removed again on stop):
//! - `iifname "<if>" counter accept` at the head of every foreign
//!   INPUT-hook filter chain (crowdsec, geoip-shell, native configs, …);
//! - `-I INPUT 1 -i <if> … -j ACCEPT` in each iptables ruleset in use
//!   (ufw, docker hosts, hand-written scripts; nft-backed and legacy);
//! - firewalld: the interface in the `trusted` zone (runtime), with a
//!   forward guard (`inet wireserve-interop.<if>`) that drops forwarded
//!   traffic from the interface, because a zone's target also covers
//!   forwarding.
//!
//! A transit-capable node (PLAN.md M23) additionally, for exactly as long
//! as it stays transit-capable, gets the same treatment on the FORWARD
//! hook too — `iifname "<if>" oifname "<if>" counter accept` (nft) /
//! `-I FORWARD 1 -i <if> -o <if> … -j ACCEPT` (iptables) — pinned to
//! *both* interfaces being this one, so this only ever opens hairpin
//! traffic back onto the mesh, never routing from the mesh to any other
//! interface on the host. A node that never opts into transit gets
//! exactly the footprint this module had before transit existed. This
//! does not yet extend to firewalld's own forwarding permission (its
//! `trusted` zone opens forwarding host-wide, not scoped to one
//! interface pair, so narrowing it safely is deliberately left as a
//! follow-up rather than guessed at here) — a transit-capable node under
//! firewalld still needs an operator to open FORWARD for it by hand.
//!
//! Several agents can run on one host, each on its own interface. Each
//! one only ever adds, keeps and removes what is tagged with its own
//! interface name; a tagged rule for another name is left alone while a
//! running agent claims that name (`crate::lock`), and cleaned up as a
//! leftover once none does.
//!
//! What is never done: anything on another interface, anything on the
//! forward or output path beyond the above and the guard's drop, anything
//! to an operator's own firewalld zone choice, writing into an owned
//! table. The pure rules for all of that are in `planner`; `planner_tests`
//! pins them.
//!
//! Runs on one dedicated thread (so no locking), woken by `nft -j monitor`
//! events (debounced), by every poll tick (the safety net), and by stop.
//! Every failure is logged, never propagated: our own table keeps
//! default-denying the interface regardless, so the worst case is the
//! behavior from before this existed — declared services blocked by the
//! host firewall.

pub mod firewalld;
pub mod iptables;
pub mod model;
pub mod monitor;
pub mod nft_ops;
pub mod ops;
pub mod planner;
pub mod ruleset;

#[cfg(test)]
mod planner_tests;

use std::collections::HashSet;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use self::monitor::{Debouncer, Monitor};
use self::ops::RealOps;
use super::nft::Nft;
use super::InteropHandle;

const DEBOUNCE: Duration = Duration::from_millis(500);
/// Upper bound on waiting for the worker to remove everything at stop.
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

enum Msg {
    Changed,
    MonitorExited,
    Tick,
    Stop(Sender<()>),
}

/// Handle to the running interop worker.
pub struct HostInterop {
    tx: Option<Sender<Msg>>,
    worker: Option<JoinHandle<()>>,
}

impl HostInterop {
    /// Opens the host firewall for `ifname` right away (synchronously, so
    /// it is in place before the interface comes up), then keeps it that
    /// way from a background thread. Never fails: if `nft` can't be found
    /// the handle is inert (the nftables backend would already have refused
    /// to start in that case).
    ///
    /// `transit_capable` (PLAN.md M23) — set once at join time and never
    /// changed for the life of a running agent, so it is safe to capture
    /// once here rather than re-read every reconcile — is whether this
    /// node's FORWARD hook is opened at all, alongside the INPUT hook this
    /// module has always opened. A node that never opts into transit gets
    /// exactly the footprint this module had before transit existed.
    #[must_use]
    pub fn start(ifname: &str, transit_capable: bool) -> Self {
        let nft = match Nft::locate() {
            Ok(nft) => nft,
            Err(e) => {
                tracing::warn!(error = %e, "host firewall interop disabled");
                return Self {
                    tx: None,
                    worker: None,
                };
            }
        };
        Self::start_with(ifname, nft.clone(), RealOps::new(nft), transit_capable)
    }

    fn start_with(ifname: &str, nft: Nft, mut ops: RealOps, forward_wanted: bool) -> Self {
        let mut told = HashSet::new();
        ops::reconcile(&mut ops, ifname, forward_wanted, &mut told);

        let (tx, rx) = mpsc::channel();
        let ifname = ifname.to_string();
        let monitor_tx = tx.clone();
        let worker = std::thread::Builder::new()
            .name("host-interop".into())
            .spawn(move || run(ops, &ifname, forward_wanted, &nft, &rx, &monitor_tx, told));
        match worker {
            Ok(worker) => Self {
                tx: Some(tx),
                worker: Some(worker),
            },
            Err(e) => {
                tracing::error!(error = %e, "could not start the host firewall interop thread");
                Self {
                    tx: None,
                    worker: None,
                }
            }
        }
    }
}

/// Removes everything the interop ever added for `ifname`: for an
/// interface this instance used before and has now left behind.
pub fn remove_for(ifname: &str) {
    match Nft::locate() {
        Ok(nft) => ops::remove(&mut RealOps::new(nft), ifname),
        Err(e) => tracing::warn!(error = %e, ifname, "could not remove host firewall interop"),
    }
}

/// Removes what an agent from before multi-instance support left behind:
/// its fixed-name guard (with the firewalld trust it guarded) and its
/// fixed-name `inet wireserve` table. Its tagged rules go with any
/// agent's next reconcile, like every other leftover.
pub fn remove_legacy() {
    let nft = match Nft::locate() {
        Ok(nft) => nft,
        Err(e) => {
            tracing::warn!(error = %e, "could not look for a legacy agent's leftovers");
            return;
        }
    };
    let wg0_live = crate::lock::holder(planner::LEGACY_IFNAME).is_agent();
    ops::remove_legacy(&mut RealOps::new(nft.clone()), wg0_live);
    if let Err(e) = super::nftables::remove_legacy_table(&nft) {
        tracing::warn!(error = %e, "could not remove a legacy agent's `inet wireserve` table");
    }
}

impl InteropHandle for HostInterop {
    fn tick(&self) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Msg::Tick);
        }
    }

    /// Removes everything the interop added. Idempotent.
    fn stop(&mut self) {
        let (Some(tx), Some(worker)) = (self.tx.take(), self.worker.take()) else {
            return;
        };
        let (done_tx, done_rx) = mpsc::channel();
        if tx.send(Msg::Stop(done_tx)).is_ok() && done_rx.recv_timeout(STOP_TIMEOUT).is_ok() {
            let _ = worker.join();
        } else {
            tracing::warn!("host firewall interop did not confirm removal of its rules");
        }
    }
}

impl Drop for HostInterop {
    /// An early return out of the daemon must not leave the host firewall
    /// opened for an interface nobody is managing.
    fn drop(&mut self) {
        self.stop();
    }
}

fn run(
    mut ops: RealOps,
    ifname: &str,
    forward_wanted: bool,
    nft: &Nft,
    rx: &Receiver<Msg>,
    tx: &Sender<Msg>,
    mut told: HashSet<String>,
) {
    let spawn_monitor = || match Monitor::spawn(nft, tx.clone(), || Msg::Changed, || Msg::MonitorExited) {
        Ok(m) => Some(m),
        Err(e) => {
            tracing::warn!(error = %e, "could not start `nft monitor`; relying on the poll tick");
            None
        }
    };
    let mut monitor = spawn_monitor();
    let mut debounce = Debouncer::new(DEBOUNCE);
    loop {
        let wait = debounce
            .wait(Instant::now())
            .unwrap_or(Duration::from_secs(3600));
        match rx.recv_timeout(wait) {
            Ok(Msg::Changed) => debounce.event(Instant::now()),
            Ok(Msg::MonitorExited) => {
                tracing::warn!("`nft monitor` exited; will restart it on the next poll tick");
                monitor = None;
            }
            Ok(Msg::Tick) => {
                if monitor.is_none() {
                    monitor = spawn_monitor();
                }
                ops::reconcile(&mut ops, ifname, forward_wanted, &mut told);
            }
            Ok(Msg::Stop(done)) => {
                drop(monitor.take());
                ops::remove(&mut ops, ifname);
                let _ = done.send(());
                return;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        if debounce.take_due(Instant::now()) {
            let planned = ops::reconcile(&mut ops, ifname, forward_wanted, &mut told);
            if planned > 0 {
                tracing::info!(changes = planned, "restored host firewall interop after an external change");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn sh(script: &str) -> String {
        let out = Command::new("sh").args(["-euc", script]).output().unwrap();
        assert!(
            out.status.success(),
            "{script}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn wait_for(what: &str, timeout: Duration, mut check: impl FnMut() -> bool) {
        let start = Instant::now();
        while !check() {
            assert!(start.elapsed() < timeout, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn tags(listing: &str) -> usize {
        listing.matches("wireserve:wg0").count()
    }

    /// The whole runtime — worker thread, `nft monitor`, debounce, tick,
    /// stop — against a real kernel. Re-runs this test binary inside a
    /// fresh unprivileged network namespace (so nothing touches the host),
    /// with firewalld disabled (its D-Bus is not namespace-scoped).
    #[test]
    fn kernel_runtime_opens_restores_and_removes() {
        if !crate::firewall::netns::reexec("firewall::host_interop::tests::kernel_runtime_opens_restores_and_removes") {
            return;
        }

        // A ufw-like iptables-nft INPUT and a native nftables config.
        let native = "table inet filter {\n chain input {\n  type filter hook input priority 0; policy drop;\n  iif lo accept\n }\n}\n";
        sh(&format!("iptables-nft -P INPUT DROP; iptables-nft -A INPUT -i lo -j ACCEPT; printf '{native}' | nft -f -"));
        let list = || sh("nft list ruleset; iptables-nft -S INPUT");

        let nft = Nft::locate().unwrap();
        let mut interop = HostInterop::start_with("wg0", nft.clone(), RealOps::without_firewalld(nft), false);

        // Synchronously in place when start() returns: native chain + iptables.
        let after_start = list();
        assert_eq!(tags(&after_start), 2, "{after_start}");
        assert!(sh("iptables-nft -S INPUT").lines().nth(1).unwrap().contains("wireserve:wg0"));

        // A native config reload drops our rule → the monitor restores it.
        sh(&format!("nft delete table inet filter; printf '{native}' | nft -f -"));
        wait_for("rule restored after reload", Duration::from_secs(5), || {
            tags(&sh("nft list table inet filter")) == 1
        });

        // iptables-nft rules are nftables too, so the monitor sees this.
        sh("iptables-nft -D INPUT -i wg0 -m comment --comment wireserve:wg0 -j ACCEPT");
        wait_for("iptables rule restored", Duration::from_secs(5), || {
            tags(&sh("iptables-nft -S INPUT")) == 1
        });

        // The tick path works on its own too, and a settled state is left alone.
        interop.tick();
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(tags(&list()), 2, "no duplicates after tick + events");

        // Stop removes exactly what we added.
        interop.stop();
        let after_stop = list();
        assert_eq!(tags(&after_stop), 0, "{after_stop}");
        assert!(after_stop.contains("policy drop"), "foreign config intact: {after_stop}");
        assert!(after_stop.contains("-A INPUT -i lo -j ACCEPT"), "{after_stop}");
    }

    /// Two agents' runtimes on one host, each holding its interface
    /// claim: both get their rules in, neither keeps rewriting the other's
    /// (rule handles stay put), and stopping one leaves the other intact.
    #[test]
    fn kernel_two_agents_coexist() {
        if !crate::firewall::netns::reexec("firewall::host_interop::tests::kernel_two_agents_coexist") {
            return;
        }
        let native = "table inet filter {\n chain input {\n  type filter hook input priority 0; policy drop;\n  iif lo accept\n }\n}\n";
        sh(&format!("iptables-nft -P INPUT DROP; iptables-nft -A INPUT -i lo -j ACCEPT; printf '{native}' | nft -f -"));
        let count = |ifname: &str| {
            sh("nft list ruleset; iptables-nft -S INPUT").matches(&format!("wireserve:{ifname}\"")).count()
        };

        let nft = Nft::locate().unwrap();
        crate::lock::IfnameClaim::take("wireserve0").unwrap().unwrap().hold();
        crate::lock::IfnameClaim::take("wireserve1").unwrap().unwrap().hold();
        let mut a = HostInterop::start_with("wireserve0", nft.clone(), RealOps::without_firewalld(nft.clone()), false);
        let mut b = HostInterop::start_with("wireserve1", nft.clone(), RealOps::without_firewalld(nft), false);
        assert_eq!((count("wireserve0"), count("wireserve1")), (2, 2));

        // Each one's monitor sees the other's inserts; let that settle, then
        // check nothing is being rewritten any more.
        std::thread::sleep(Duration::from_millis(1500));
        let settled = sh("nft -a list ruleset");
        a.tick();
        b.tick();
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(sh("nft -a list ruleset"), settled, "rules were rewritten: the agents are fighting");
        assert_eq!((count("wireserve0"), count("wireserve1")), (2, 2));

        b.stop();
        assert_eq!((count("wireserve0"), count("wireserve1")), (2, 0));
        a.stop();
        assert_eq!((count("wireserve0"), count("wireserve1")), (0, 0));
    }
}
