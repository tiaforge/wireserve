//! Observe → plan → execute, behind a small trait so the orchestration
//! (ordering, failure handling) is tested against a recording fake, the
//! same way `firewall::fake::FakeFirewallBackend` stands in for nftables.

use std::collections::{BTreeSet, HashSet};

use super::model::{tag_owner, Action, FirewalldState, IptablesObservation, NftView, Observed, ForwardWanted};
use super::{firewalld, iptables, nft_ops, planner, ruleset};
use crate::firewall::nft::Nft;
use crate::firewall::nftables::SharedRuleset;

pub trait HostOps {
    /// Never fails as a whole: a part that can't be observed is reported as
    /// unknown/unavailable, and the planner plans nothing for it.
    fn observe(&mut self, ifname: &str) -> Observed;
    fn execute(&mut self, action: &Action) -> Result<(), String>;
    /// Puts our own deny table back from the backend's last applied
    /// ruleset. `Ok(false)` when there is nothing to restore from.
    fn restore_own_table(&mut self) -> Result<bool, String>;
}

pub struct RealOps {
    nft: Nft,
    firewalld: bool,
    own_table: Option<SharedRuleset>,
    /// Whether this `nft` understands `-t` — see [`RealOps::list_ruleset`].
    terse: bool,
}

impl RealOps {
    #[must_use]
    pub fn new(nft: Nft) -> Self {
        Self { nft, firewalld: true, own_table: None, terse: true }
    }

    /// The ruleset, without the contents of anyone's sets.
    ///
    /// `-t` is the difference between a reconcile costing `nft` 11 MB and
    /// costing it 124 MB on a host running crowdsec and geoip-shell,
    /// measured on a 100k-element set — and a reconcile runs on every poll
    /// tick. Terse leaves out set *elements* and nothing else: tables keep
    /// their flags, chains their hooks, rules their full expressions, which
    /// is everything `planner` reads (the elements never were: see
    /// `ruleset`'s module doc for what parsing them used to cost this
    /// process, which is a separate bill from what it costs `nft`).
    ///
    /// nft has had `-t` since 0.9.1, but a host's nft is the host's to
    /// choose, so one that rejects it is not an error: the plain listing is
    /// tried straight away and used from then on. Only a plain listing that
    /// fails too is a failure to observe.
    pub(super) fn list_ruleset(&mut self) -> Result<Vec<u8>, crate::firewall::nft::NftError> {
        if !self.terse {
            return self.nft.run(&["-j", "list", "ruleset"], None);
        }
        match self.nft.run(&["-t", "-j", "list", "ruleset"], None) {
            Ok(out) => Ok(out),
            Err(terse_failed) => {
                let out = self.nft.run(&["-j", "list", "ruleset"], None)?;
                // The retry worked, so `-t` was the problem — an nft too
                // old for it, most likely. Stop asking.
                self.terse = false;
                tracing::warn!(
                    error = %terse_failed,
                    "this `nft` will not list the ruleset tersely; listing it with every set element instead"
                );
                Ok(out)
            }
        }
    }

    /// Lets a reconcile restore our own table from `own_table` (see
    /// [`reconcile`]). Without it, a missing table can only ever make a
    /// reconcile close the host firewalls again.
    #[must_use]
    pub fn with_own_table(mut self, own_table: SharedRuleset) -> Self {
        self.own_table = Some(own_table);
        self
    }

    /// For tests that run inside a private network namespace: `firewall-cmd`
    /// talks to the host's firewalld over D-Bus, which is not
    /// namespace-scoped, so it must not be touched from there.
    #[cfg(test)]
    #[must_use]
    pub fn without_firewalld(nft: Nft) -> Self {
        Self { nft, firewalld: false, own_table: None, terse: true }
    }
}

impl HostOps for RealOps {
    fn observe(&mut self, ifname: &str) -> Observed {
        let nft = match self.list_ruleset() {
            Ok(out) => match ruleset::parse(&out) {
                Ok(view) => Some(view),
                Err(e) => {
                    tracing::warn!(error = %e, "could not read the nftables ruleset");
                    None
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "could not list the nftables ruleset");
                None
            }
        };
        // Both INPUT and FORWARD are always observed — see `iptables::observe`
        // for why (PLAN.md M23: cleanup must find a FORWARD-hook leftover
        // even on a run that no longer wants it inserted).
        let iptables = iptables::observe();
        let live = live_owners(nft.as_ref(), &iptables, ifname, |o| {
            crate::lock::holder(o).is_agent()
        });
        Observed {
            nft,
            iptables,
            firewalld: if self.firewalld {
                firewalld::observe(ifname)
            } else {
                FirewalldState::Unavailable
            },
            live,
        }
    }

    fn execute(&mut self, action: &Action) -> Result<(), String> {
        let nft = |batch| self.nft.apply(&batch).map_err(|e| e.to_string());
        match action {
            Action::NftInsert { chain, ifname, opening } => nft(nft_ops::insert_accept(chain, ifname, *opening)),
            Action::NftDelete { chain, handle } => nft(nft_ops::delete_rule(chain, *handle)),
            Action::GuardCreate { ifname, forward } => nft(nft_ops::guard_create(ifname, *forward)),
            Action::GuardDelete { table } => nft(nft_ops::guard_delete(table)),
            Action::IptablesInsert { target, ifname, opening } => {
                iptables::run(target, &iptables::insert_args(ifname, *opening)).map(|_| ())
            }
            Action::IptablesDelete { target, line } => {
                iptables::run(target, &iptables::delete_args(line)?).map(|_| ())
            }
            Action::FirewalldTrust { .. } | Action::FirewalldUntrust { .. } if !self.firewalld => {
                Err("firewalld disabled".into())
            }
            Action::FirewalldTrust { ifname } => firewalld::execute(&firewalld::trust_args(ifname)),
            Action::FirewalldUntrust { ifname } => firewalld::execute(&firewalld::untrust_args(ifname)),
        }
    }

    fn restore_own_table(&mut self) -> Result<bool, String> {
        match &self.own_table {
            Some(shared) => crate::firewall::nftables::restore(&self.nft, shared).map_err(|e| e.to_string()),
            None => Ok(false),
        }
    }
}

/// Every interface name, other than `ifname`, that a tagged rule was seen
/// for and that `is_live` says a running agent holds. Asked once per name,
/// not per rule.
pub fn live_owners(
    nft: Option<&NftView>,
    iptables: &[IptablesObservation],
    ifname: &str,
    is_live: impl Fn(&str) -> bool,
) -> BTreeSet<String> {
    let from_nft = nft
        .into_iter()
        .flat_map(|v| &v.chains)
        .flat_map(|c| &c.rules)
        .filter_map(|r| r.comment.as_deref().and_then(tag_owner).map(str::to_string));
    let from_iptables = iptables
        .iter()
        .flat_map(|o| o.tagged_lines.iter().flatten())
        .filter_map(|l| iptables::line_tag(l))
        .filter_map(|t| tag_owner(&t).map(str::to_string));
    let owners: BTreeSet<String> = from_nft.chain(from_iptables).filter(|o| o != ifname).collect();
    owners.into_iter().filter(|o| is_live(o)).collect()
}

/// Runs `actions` in order, logging each. Every failure is logged and the
/// rest still runs — except where running on would leave the host more
/// open than intended:
/// - no firewalld trust if the forward guard could not be created;
/// - no guard removal if the firewalld trust could not be removed.
///
/// Returns how many actions failed or were skipped.
pub fn execute_all(ops: &mut impl HostOps, actions: &[Action]) -> usize {
    let mut problems = 0;
    let mut guard_failed = false;
    let mut untrust_failed = false;
    for action in actions {
        let skip = match action {
            Action::FirewalldTrust { .. } => guard_failed,
            Action::GuardDelete { .. } => untrust_failed,
            _ => false,
        };
        if skip {
            problems += 1;
            tracing::warn!(?action, "skipped: an earlier step it depends on failed");
            continue;
        }
        match ops.execute(action) {
            Ok(()) => tracing::info!(?action, "host firewall interop"),
            Err(e) => {
                problems += 1;
                match action {
                    Action::GuardCreate { .. } => guard_failed = true,
                    Action::FirewalldUntrust { .. } => untrust_failed = true,
                    _ => {}
                }
                tracing::warn!(?action, error = %e, "host firewall interop step failed");
            }
        }
    }
    problems
}

/// One reconcile pass. Returns the number of actions it planned (0 once
/// settled). `told` remembers which operator notices were already logged,
/// so each is logged once rather than every poll. `forward_wanted` must
/// match what `ops` itself was constructed with (`RealOps::new`'s own
/// flag) — kept as an explicit parameter here too since this function is
/// generic over `HostOps` and so can't reach into `ops`'s own state.
///
/// Opens nothing unless our own deny table is in place (see
/// `planner::own_table_intact`, and the module doc of `host_interop` for
/// the failure this prevents). A missing table is restored from the
/// backend's last ruleset first; if that isn't possible, this plans the
/// same removal as [`remove`], so every other firewall goes back to
/// blocking the interface until the table is back.
pub fn reconcile(ops: &mut impl HostOps, ifname: &str, forward_wanted: ForwardWanted, told: &mut HashSet<String>) -> usize {
    let mut observed = ops.observe(ifname);
    for notice in planner::notices(&observed, ifname) {
        if told.insert(notice.clone()) {
            tracing::warn!("{notice}");
        }
    }
    if observed.nft.is_some() && !planner::own_table_intact(&observed, ifname) {
        match ops.restore_own_table() {
            Ok(true) => {
                tracing::warn!(
                    ifname,
                    "this interface's firewall table was removed by something else on the host \
                     (a `flush ruleset`?); restored it"
                );
                observed = ops.observe(ifname);
            }
            Ok(false) => {}
            Err(e) => tracing::warn!(ifname, error = %e, "could not restore this interface's firewall table"),
        }
    }
    let closed_notice = format!("closed:{ifname}");
    let actions = if planner::own_table_intact(&observed, ifname) {
        told.remove(&closed_notice);
        planner::plan_reconcile(&observed, ifname, forward_wanted)
    } else {
        if told.insert(closed_notice) {
            tracing::warn!(
                ifname,
                "this interface's own firewall table is missing or unreadable; keeping the host \
                 firewalls closed to it until it is back"
            );
        }
        planner::plan_removal(&observed, ifname)
    };
    execute_all(ops, &actions);
    actions.len()
}

/// Removes everything this module added for `ifname`, plus any leftovers
/// no running agent claims.
pub fn remove(ops: &mut impl HostOps, ifname: &str) {
    let observed = ops.observe(ifname);
    execute_all(ops, &planner::plan_removal(&observed, ifname));
}

#[cfg(test)]
pub mod fake {
    use super::*;

    /// Serves a fixed observation, records every executed action and fails
    /// the ones listed in `fail`.
    pub struct FakeOps {
        pub observed: Observed,
        pub executed: Vec<Action>,
        pub fail: Vec<Action>,
        /// What `restore_own_table` returns, and the observation it swaps
        /// in when it "restores".
        pub restore: Result<bool, String>,
        pub after_restore: Option<Observed>,
        pub restores: usize,
    }

    impl HostOps for FakeOps {
        fn observe(&mut self, _ifname: &str) -> Observed {
            self.observed.clone()
        }
        fn execute(&mut self, action: &Action) -> Result<(), String> {
            self.executed.push(action.clone());
            if self.fail.contains(action) {
                Err("injected failure".into())
            } else {
                Ok(())
            }
        }
        fn restore_own_table(&mut self) -> Result<bool, String> {
            self.restores += 1;
            if let (Ok(true), Some(after)) = (&self.restore, self.after_restore.take()) {
                self.observed = after;
            }
            self.restore.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeOps;
    use super::*;
    use crate::firewall::host_interop::model::{ChainRef, Family};

    fn chain(name: &str) -> ChainRef {
        ChainRef {
            family: Family::Inet,
            table: "filter".into(),
            chain: name.into(),
        }
    }

    fn fake(fail: Vec<Action>) -> FakeOps {
        FakeOps {
            observed: Observed {
                nft: None,
                iptables: vec![],
                firewalld: FirewalldState::Unavailable,
                live: BTreeSet::new(),
            },
            executed: vec![],
            fail,
            restore: Ok(false),
            after_restore: None,
            restores: 0,
        }
    }

    /// An nft view holding exactly our own table for `wg0`, as the backend
    /// applies it with no services: both chains ending in the drop.
    fn own_table_view() -> NftView {
        use crate::firewall::host_interop::model::{ChainInfo, RuleInfo};
        use serde_json::json;
        let drop = RuleInfo {
            handle: 9,
            comment: None,
            expr: vec![
                json!({"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wg0"}}),
                json!({"drop": null}),
            ],
        };
        let chain = |name: &str| ChainInfo {
            chain: ChainRef { family: Family::Inet, table: "wireserve.wg0".into(), chain: name.into() },
            hook: Some("input".into()),
            chain_type: Some("filter".into()),
            rules: vec![drop.clone()],
        };
        NftView { tables: vec![], chains: vec![chain("wireserve-in"), chain("wireserve-fwd")] }
    }

    fn firewalld_running() -> FirewalldState {
        FirewalldState::Running { runtime_zone: None, permanent_zone: None }
    }

    #[test]
    fn with_our_table_in_place_the_host_firewalls_are_opened() {
        let mut ops = fake(vec![]);
        ops.observed.firewalld = firewalld_running();
        ops.observed.nft = Some(own_table_view());
        reconcile(&mut ops, "wg0", ForwardWanted::default(), &mut HashSet::new());
        assert_eq!(ops.restores, 0, "nothing to restore");
        assert!(ops.executed.contains(&Action::FirewalldTrust { ifname: "wg0".into() }), "{:?}", ops.executed);
    }

    #[test]
    fn a_missing_table_that_cannot_be_restored_keeps_everything_closed() {
        // After `flush ruleset`, with firewalld still trusting the
        // interface from before: nothing may be opened, and the trust must
        // be withdrawn, or the interface is open to every mesh peer.
        let mut ops = fake(vec![]);
        ops.observed.firewalld = FirewalldState::Running { runtime_zone: Some("trusted".into()), permanent_zone: None };
        ops.observed.nft = Some(NftView::default());
        reconcile(&mut ops, "wg0", ForwardWanted::default(), &mut HashSet::new());
        assert_eq!(ops.restores, 1);
        assert!(
            !ops.executed.iter().any(|a| matches!(a, Action::FirewalldTrust { .. } | Action::NftInsert { .. } | Action::IptablesInsert { .. })),
            "{:?}",
            ops.executed
        );
        assert!(ops.executed.contains(&Action::FirewalldUntrust { ifname: "wg0".into() }), "{:?}", ops.executed);
    }

    #[test]
    fn a_missing_table_is_restored_before_anything_is_opened() {
        let mut ops = fake(vec![]);
        ops.observed.firewalld = firewalld_running();
        ops.observed.nft = Some(NftView::default());
        ops.restore = Ok(true);
        let mut restored = ops.observed.clone();
        restored.nft = Some(own_table_view());
        ops.after_restore = Some(restored);
        reconcile(&mut ops, "wg0", ForwardWanted::default(), &mut HashSet::new());
        assert_eq!(ops.restores, 1);
        assert!(ops.executed.contains(&Action::FirewalldTrust { ifname: "wg0".into() }), "{:?}", ops.executed);
    }

    #[test]
    fn a_table_whose_chain_was_flushed_counts_as_missing() {
        let mut view = own_table_view();
        view.chains[0].rules.clear();
        let mut ops = fake(vec![]);
        ops.observed.firewalld = firewalld_running();
        ops.observed.nft = Some(view);
        reconcile(&mut ops, "wg0", ForwardWanted::default(), &mut HashSet::new());
        assert_eq!(ops.restores, 1);
        assert!(!ops.executed.contains(&Action::FirewalldTrust { ifname: "wg0".into() }));
    }

    #[test]
    fn a_failed_step_does_not_stop_the_others() {
        let a = Action::NftInsert {
            chain: chain("a"),
            ifname: "wg0".into(),
            opening: crate::firewall::host_interop::model::Opening::Input,
        };
        let b = Action::NftInsert {
            chain: chain("b"),
            ifname: "wg0".into(),
            opening: crate::firewall::host_interop::model::Opening::Input,
        };
        let mut ops = fake(vec![a.clone()]);
        assert_eq!(execute_all(&mut ops, &[a.clone(), b.clone()]), 1);
        assert_eq!(ops.executed, [a, b]);
    }

    #[test]
    fn no_firewalld_trust_without_the_forward_guard() {
        let guard = Action::GuardCreate { ifname: "wg0".into(), forward: ForwardWanted::default() };
        let trust = Action::FirewalldTrust { ifname: "wg0".into() };
        let mut ops = fake(vec![guard.clone()]);
        assert_eq!(execute_all(&mut ops, &[guard.clone(), trust]), 2);
        assert_eq!(ops.executed, [guard], "trust must not run after the guard failed");
    }

    #[test]
    fn the_guard_stays_while_firewalld_trust_could_not_be_removed() {
        let untrust = Action::FirewalldUntrust { ifname: "wg0".into() };
        let delete = Action::GuardDelete {
            table: "wireserve-interop.wg0".into(),
        };
        let mut ops = fake(vec![untrust.clone()]);
        assert_eq!(execute_all(&mut ops, &[untrust.clone(), delete]), 2);
        assert_eq!(ops.executed, [untrust], "guard must stay while the interface is still trusted");
    }

    #[test]
    fn removal_and_reconcile_use_the_planner() {
        let mut ops = fake(vec![]);
        ops.observed.firewalld = FirewalldState::Running {
            runtime_zone: None,
            permanent_zone: None,
        };
        // No nft view: the forward guard can't be verified, so firewalld
        // is not touched either.
        assert_eq!(reconcile(&mut ops, "wg0", ForwardWanted::default(), &mut HashSet::new()), 0);
        assert!(ops.executed.is_empty());

        ops.observed.nft = Some(own_table_view());
        assert_eq!(reconcile(&mut ops, "wg0", ForwardWanted::default(), &mut HashSet::new()), 2);
        assert_eq!(
            ops.executed,
            [
                Action::GuardCreate { ifname: "wg0".into(), forward: ForwardWanted::default() },
                Action::FirewalldTrust { ifname: "wg0".into() }
            ]
        );
    }

    #[test]
    fn only_other_interfaces_a_running_agent_holds_are_live() {
        use crate::firewall::host_interop::model::{ChainInfo, Hook, IptablesTarget, IptablesVariant, IpVersion, RuleInfo};
        let rule = |comment: &str| RuleInfo {
            handle: 1,
            comment: Some(comment.into()),
            expr: vec![],
        };
        let nft = NftView {
            tables: vec![],
            chains: vec![ChainInfo {
                chain: chain("input"),
                hook: Some("input".into()),
                chain_type: Some("filter".into()),
                rules: vec![rule("wireserve:wg0"), rule("wireserve:alive"), rule("wireserve:dead"), rule("ssh")],
            }],
        };
        let iptables = vec![IptablesObservation {
            target: IptablesTarget {
                version: IpVersion::V4,
                variant: IptablesVariant::Nft,
                binary: "/usr/sbin/iptables".into(),
            },
            hook: Hook::Input,
            tagged_lines: Some(vec![
                "-A INPUT -i alive2 -m comment --comment \"wireserve:alive2\" -j ACCEPT".into(),
            ]),
        }];
        let asked = std::cell::RefCell::new(Vec::new());
        let live = live_owners(Some(&nft), &iptables, "wg0", |o| {
            asked.borrow_mut().push(o.to_string());
            o.starts_with("alive")
        });
        assert_eq!(live, BTreeSet::from(["alive".to_string(), "alive2".to_string()]));
        assert_eq!(*asked.borrow(), ["alive", "alive2", "dead"], "never asks about our own name");
    }

    /// A host whose `nft` predates `-t` must still be observable — and
    /// must not pay for a rejected `-t` on every reconcile afterwards.
    #[test]
    fn an_nft_without_terse_falls_back_once_and_stays_fallen_back() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("args");
        let fake = dir.path().join("nft");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\n\
                 echo \"$@\" >> {log}\n\
                 case \"$1\" in -t) echo \"nft: invalid option -- 't'\" >&2; exit 1;; esac\n\
                 echo '{{\"nftables\":[]}}'\n",
                log = log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        // Another test thread forking while the script was open for writing
        // holds a copy of that descriptor until its child execs, and until
        // then exec'ing the script fails with ETXTBSY — which the code under
        // test rightly reads as "this nft cannot do -t". Wait that out here
        // so the first real call is the one the test is about.
        while let Err(e) = std::process::Command::new(&fake).arg("warmup").output() {
            assert_eq!(e.raw_os_error(), Some(libc::ETXTBSY), "{e}");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::fs::remove_file(&log).unwrap();

        let mut ops = RealOps::without_firewalld(Nft::at(fake));
        for _ in 0..3 {
            let out = ops.list_ruleset().expect("the plain listing works");
            assert_eq!(ruleset::parse(&out).unwrap(), NftView::default());
        }
        let asked: Vec<String> = std::fs::read_to_string(&log).unwrap().lines().map(str::to_string).collect();
        assert_eq!(
            asked,
            [
                "-t -j list ruleset", // tried once,
                "-j list ruleset",    // fell back,
                "-j list ruleset",    // and never asked again.
                "-j list ruleset",
            ]
        );
    }

    /// Against a real kernel, on a host shaped like the one this was
    /// found on: a table full of set elements must cost us nothing to
    /// observe, and everything the planner reads must still be there.
    ///
    /// The bill this pins is `nft`'s own, not ours — a full
    /// `list ruleset` on a 100k-element set peaked at 124 MB in the `nft`
    /// child against 11 MB for the terse one, once per poll tick, and the
    /// agent's cgroup is what the operator sees.
    #[test]
    fn kernel_a_hosts_set_elements_are_never_listed() {
        if !crate::firewall::netns::reexec("firewall::host_interop::ops::tests::kernel_a_hosts_set_elements_are_never_listed") {
            return;
        }
        let elements: Vec<String> = (0..20_000u32)
            .map(|i| format!("{}.{}.{}.0/24", (i >> 16) & 255, (i >> 8) & 255, i & 255))
            .collect();
        // Through a file: a set this size is past the kernel's limit on
        // the length of one argument.
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("host.nft");
        std::fs::write(
            &config,
            format!(
                "table inet geoip-shell {{\n\
                   set allow {{ type ipv4_addr; flags interval; elements = {{ {} }} }}\n\
                   chain input {{ type filter hook input priority -141; policy accept; ip saddr @allow accept; }}\n\
                 }}\n\
                 table inet filter {{\n  chain input {{ type filter hook input priority 0; policy drop; }}\n}}\n",
                elements.join(", ")
            ),
        )
        .unwrap();

        let nft = Nft::locate().unwrap();
        // Loading a set this size takes a bigger socket buffer than
        // net.core.wmem_max allows by default (Ubuntu's is about 200 KB),
        // and only real root may go past that limit.
        if let Err(e) = nft.run(&["-f", config.to_str().unwrap()], None) {
            if e.to_string().contains("Message too long") {
                crate::firewall::netns::skip("loading the set needs `sysctl -w net.core.wmem_max=2097152` on the host");
                return;
            }
            panic!("the host's ruleset loads: {e:?}");
        }
        let mut ops = RealOps::without_firewalld(nft.clone());
        let terse = ops.list_ruleset().unwrap();
        let full = nft.run(&["-j", "list", "ruleset"], None).unwrap();
        assert!(
            terse.len() * 20 < full.len(),
            "terse listing is {} KB against a full one of {} KB — is `-t` being dropped?",
            terse.len() / 1024,
            full.len() / 1024
        );
        assert!(!String::from_utf8_lossy(&terse).contains("\"elem\""), "set contents came back anyway");

        // Everything `planner` reads survives it: both tables, both base
        // chains with their hooks and types, and the rules with their
        // expressions.
        let view = ruleset::parse(&terse).unwrap();
        assert!(view.tables.iter().any(|t| t.name == "geoip-shell"));
        let foreign = view
            .chains
            .iter()
            .find(|c| c.chain.table == "filter" && c.chain.chain == "input")
            .expect("the host's own input chain");
        assert_eq!(foreign.hook.as_deref(), Some("input"));
        assert_eq!(foreign.chain_type.as_deref(), Some("filter"));
        let geoip = view.chains.iter().find(|c| c.chain.table == "geoip-shell").unwrap();
        assert_eq!(geoip.rules.len(), 1, "a rule that matches on a set is still a rule we can see");
        assert!(!geoip.rules[0].expr.is_empty());
    }
}
