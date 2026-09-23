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
//! interface on the host. firewalld gets the equivalent instead: since its
//! `trusted` zone opens forwarding host-wide (not scoped to one interface
//! pair) once the interface is a member, the existing forward guard —
//! which already exists purely to keep that from happening — gains the
//! same hairpin exception *ahead* of its unconditional drop, so only
//! traffic routed back onto this same interface ever escapes it. A node
//! that never opts into transit gets exactly the footprint this module
//! had before transit existed.
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
//! Every failure is logged, never propagated.
//!
//! **Everything here depends on our own table being in place**, because
//! what this module adds tells every other firewall to leave the
//! interface to that table. So each reconcile first checks it (see
//! `planner::own_table_intact`): if something else removed it — a
//! `flush ruleset` from an nftables.service reload, a `flush chain` — the
//! reconcile puts back the last ruleset the backend applied
//! (`nftables::SharedRuleset`), and if that isn't possible it removes
//! everything this module added instead of adding it, so the host
//! firewalls go back to blocking the interface. The monitor reacts to
//! deletions in our table for the same reason. Before this, a reload
//! left the interface open to every mesh peer on every port until the
//! next successful poll, and indefinitely while the coordinator was
//! unreachable.

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
    /// Carries the *current* opt-in, because it can change while the daemon
    /// runs — see `run`.
    Tick { forward_wanted: bool },
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
    /// `transit_capable` (PLAN.md M23) is whether this node's FORWARD hook
    /// is opened at all, alongside the INPUT hook this module has always
    /// opened. A node that never opts into transit gets exactly the
    /// footprint this module had before transit existed.
    ///
    /// It is the value at startup only. `wireserve-agent transit on` mutates
    /// the running daemon (M23 #102), so it is re-sent on every tick and the
    /// worker acts on the change — see `run`. This comment used to claim the
    /// flag was "set once at join time and never changed for the life of a
    /// running agent"; it never was, and believing it meant a node that
    /// opted in without restarting carried transit in its own table while
    /// ufw silently dropped every forwarded packet.
    ///
    /// `own_table` is the backend's last applied ruleset, which a
    /// reconcile restores when our table has gone missing.
    #[must_use]
    pub fn start(ifname: &str, transit_capable: bool, own_table: super::nftables::SharedRuleset) -> Self {
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
        Self::start_with(ifname, nft.clone(), RealOps::new(nft).with_own_table(own_table), transit_capable)
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
        // `run` reconciles on monitor events, which it filters by this
        // interface (see `monitor::is_relevant`).
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
    fn tick(&self, forward_wanted: bool) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Msg::Tick { forward_wanted });
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

/// The worker loop.
///
/// `forward_wanted` is mutable and re-read from every tick, not captured:
/// transit is a live toggle, so a node can start carrying traffic long after
/// its daemon started. Opening the host firewall's FORWARD hook only at
/// startup meant `transit on` took effect everywhere *except* ufw and
/// firewalld — the node's own table accepted the forward, the host's dropped
/// it, and the only symptom was a peer that could not be reached through it.
fn run(
    mut ops: RealOps,
    ifname: &str,
    mut forward_wanted: bool,
    nft: &Nft,
    rx: &Receiver<Msg>,
    tx: &Sender<Msg>,
    mut told: HashSet<String>,
) {
    let spawn_monitor = || match Monitor::spawn(nft, ifname, tx.clone(), || Msg::Changed, || Msg::MonitorExited) {
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
            Ok(Msg::Tick { forward_wanted: now }) => {
                if now != forward_wanted {
                    tracing::info!(
                        forward_wanted = now,
                        "transit opt-in changed; reopening the host firewall's forward hook"
                    );
                    forward_wanted = now;
                }
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

    /// Our own deny table for `ifname`, applied the way the daemon applies
    /// it before starting the interop, plus the handle the interop
    /// restores it from.
    fn own_table(ifname: &str) -> (crate::firewall::nftables::NftablesBackend, super::super::nftables::SharedRuleset) {
        use wireserve_types::FirewallBackend;
        let mut backend = crate::firewall::nftables::NftablesBackend::new(ifname).unwrap();
        backend.apply(&[], &[]).unwrap();
        let shared = backend.last_applied();
        (backend, shared)
    }

    const NATIVE_DROP_ALL: &str = "table inet filter {\n chain input {\n  type filter hook input priority 0; policy drop;\n  iif lo accept\n }\n}\n";

    /// Security review: an nftables.service reload (`flush ruleset`, then
    /// the host's own config) used to leave the interface open to every
    /// mesh peer — our table gone, our accept back in the host's chain
    /// within a second. Now the same reconcile puts our table back first.
    #[test]
    fn kernel_a_flushed_ruleset_gets_our_table_back_before_anything_is_reopened() {
        if !crate::firewall::netns::reexec(
            "firewall::host_interop::tests::kernel_a_flushed_ruleset_gets_our_table_back_before_anything_is_reopened",
        ) {
            return;
        }
        sh(&format!("printf '{NATIVE_DROP_ALL}' | nft -f -"));
        let nft = Nft::locate().unwrap();
        let (_backend, shared) = own_table("wg0");
        let _interop = HostInterop::start_with("wg0", nft.clone(), RealOps::without_firewalld(nft).with_own_table(shared), false);
        assert_eq!(tags(&sh("nft list table inet filter")), 1);

        sh(&format!("printf 'flush ruleset\n{NATIVE_DROP_ALL}' | nft -f -"));
        wait_for("our table restored and the host firewall reopened", Duration::from_secs(5), || {
            let all = sh("nft list ruleset");
            all.contains("table inet wireserve.wg0") && tags(&all) == 1
        });
        let ours = sh("nft list table inet wireserve.wg0");
        assert!(ours.contains("iifname \"wg0\" drop"), "{ours}");
    }

    /// With nothing to restore from, losing our table must close the host
    /// firewalls again rather than leave them opened for it.
    #[test]
    fn kernel_losing_our_table_with_nothing_to_restore_closes_the_host_firewall() {
        if !crate::firewall::netns::reexec(
            "firewall::host_interop::tests::kernel_losing_our_table_with_nothing_to_restore_closes_the_host_firewall",
        ) {
            return;
        }
        sh(&format!("iptables-nft -P INPUT DROP; printf '{NATIVE_DROP_ALL}' | nft -f -"));
        let nft = Nft::locate().unwrap();
        let (_backend, _shared) = own_table("wg0");
        let _interop = HostInterop::start_with("wg0", nft.clone(), RealOps::without_firewalld(nft), false);
        assert_eq!(tags(&sh("nft list ruleset; iptables-nft -S INPUT")), 2);

        sh("nft flush chain inet wireserve.wg0 wireserve-in");
        wait_for("host firewalls closed again", Duration::from_secs(5), || {
            tags(&sh("nft list ruleset; iptables-nft -S INPUT")) == 0
        });
    }

    /// Opting into transit on a *running* daemon must open the host
    /// firewall's FORWARD hook, against a real kernel.
    ///
    /// The regression this pins: `transit_capable` was captured once at
    /// startup on the belief that it "never changed for the life of a
    /// running agent", while `transit on` had always mutated the running
    /// daemon. A node that opted in without restarting therefore carried
    /// transit in its own table while ufw's FORWARD DROP ate every packet,
    /// and the only visible symptom was a peer unreachable through it.
    #[test]
    fn kernel_opting_into_transit_opens_the_forward_hook_without_a_restart() {
        if !crate::firewall::netns::reexec(
            "firewall::host_interop::tests::kernel_opting_into_transit_opens_the_forward_hook_without_a_restart",
        ) {
            return;
        }

        // A ufw-shaped host: FORWARD defaults to DROP, which is what silently
        // ate transited packets on a node that ran `transit on` without
        // restarting its daemon.
        sh("iptables-nft -P INPUT DROP; iptables-nft -P FORWARD DROP; iptables-nft -A INPUT -i lo -j ACCEPT");
        let forward_rules = || tags(&sh("iptables-nft -S FORWARD"));

        let nft = Nft::locate().unwrap();
        let (_backend, shared) = own_table("wg0");
        // Started opted OUT, exactly as a daemon that came up before the
        // operator decided to carry transit.
        let mut interop = HostInterop::start_with(
            "wg0",
            nft.clone(),
            RealOps::without_firewalld(nft).with_own_table(shared),
            false,
        );
        assert_eq!(forward_rules(), 0, "a node that never opted in opens nothing in FORWARD");

        // `wireserve-agent transit on` — no restart.
        interop.tick(true);
        wait_for("forward hook opened after opting in", Duration::from_secs(5), || {
            forward_rules() == 1
        });
        let rule = sh("iptables-nft -S FORWARD");
        assert!(rule.contains("-i wg0"), "{rule}");
        assert!(rule.contains("-o wg0"), "pinned to both interfaces, never a general router: {rule}");

        // And back off again, without a restart either.
        interop.tick(false);
        wait_for("forward hook closed after opting out", Duration::from_secs(5), || {
            forward_rules() == 0
        });

        interop.stop();
        let after = sh("iptables-nft -S INPUT; iptables-nft -S FORWARD");
        assert_eq!(tags(&after), 0, "{after}");
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
        let (_backend, shared) = own_table("wg0");
        let mut interop = HostInterop::start_with("wg0", nft.clone(), RealOps::without_firewalld(nft).with_own_table(shared), false);

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
        // `false` matches the `start_with` above: this test is about restoring
        // the INPUT footprint, not about changing the opt-in.
        interop.tick(false);
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
        let (_backend_a, shared_a) = own_table("wireserve0");
        let (_backend_b, shared_b) = own_table("wireserve1");
        let mut a = HostInterop::start_with("wireserve0", nft.clone(), RealOps::without_firewalld(nft.clone()).with_own_table(shared_a), false);
        let mut b = HostInterop::start_with("wireserve1", nft.clone(), RealOps::without_firewalld(nft).with_own_table(shared_b), false);
        assert_eq!((count("wireserve0"), count("wireserve1")), (2, 2));

        // Each one's monitor sees the other's inserts; let that settle, then
        // check nothing is being rewritten any more.
        std::thread::sleep(Duration::from_millis(1500));
        let settled = sh("nft -a list ruleset");
        a.tick(true);
        b.tick(true);
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(sh("nft -a list ruleset"), settled, "rules were rewritten: the agents are fighting");
        assert_eq!((count("wireserve0"), count("wireserve1")), (2, 2));

        b.stop();
        assert_eq!((count("wireserve0"), count("wireserve1")), (2, 0));
        a.stop();
        assert_eq!((count("wireserve0"), count("wireserve1")), (0, 0));
    }
}
