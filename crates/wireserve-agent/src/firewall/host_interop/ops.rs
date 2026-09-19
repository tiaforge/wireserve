//! Observe → plan → execute, behind a small trait so the orchestration
//! (ordering, failure handling) is tested against a recording fake, the
//! same way `firewall::fake::FakeFirewallBackend` stands in for nftables.

use std::collections::{BTreeSet, HashSet};

use super::model::{tag_owner, Action, FirewalldState, IptablesObservation, NftView, Observed};
use super::{firewalld, iptables, nft_ops, planner, ruleset};
use crate::firewall::nft::Nft;

pub trait HostOps {
    /// Never fails as a whole: a part that can't be observed is reported as
    /// unknown/unavailable, and the planner plans nothing for it.
    fn observe(&mut self, ifname: &str) -> Observed;
    fn execute(&mut self, action: &Action) -> Result<(), String>;
}

pub struct RealOps {
    nft: Nft,
    firewalld: bool,
}

impl RealOps {
    #[must_use]
    pub fn new(nft: Nft) -> Self {
        Self { nft, firewalld: true }
    }

    /// For tests that run inside a private network namespace: `firewall-cmd`
    /// talks to the host's firewalld over D-Bus, which is not
    /// namespace-scoped, so it must not be touched from there.
    #[cfg(test)]
    #[must_use]
    pub fn without_firewalld(nft: Nft) -> Self {
        Self { nft, firewalld: false }
    }
}

impl HostOps for RealOps {
    fn observe(&mut self, ifname: &str) -> Observed {
        let nft = match self.nft.run(&["-j", "list", "ruleset"], None) {
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
            Action::NftInsert { chain, ifname } => nft(nft_ops::insert_accept(chain, ifname)),
            Action::NftDelete { chain, handle } => nft(nft_ops::delete_rule(chain, *handle)),
            Action::GuardCreate { ifname } => nft(nft_ops::guard_create(ifname)),
            Action::GuardDelete { table } => nft(nft_ops::guard_delete(table)),
            Action::IptablesInsert { target, ifname } => {
                iptables::run(target, &iptables::insert_args(ifname)).map(|_| ())
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
/// so each is logged once rather than every poll.
pub fn reconcile(ops: &mut impl HostOps, ifname: &str, told: &mut HashSet<String>) -> usize {
    let observed = ops.observe(ifname);
    for notice in planner::notices(&observed, ifname) {
        if told.insert(notice.clone()) {
            tracing::warn!("{notice}");
        }
    }
    let actions = planner::plan_reconcile(&observed, ifname);
    execute_all(ops, &actions);
    actions.len()
}

/// Removes everything this module added for `ifname`, plus any leftovers
/// no running agent claims.
pub fn remove(ops: &mut impl HostOps, ifname: &str) {
    let observed = ops.observe(ifname);
    execute_all(ops, &planner::plan_removal(&observed, ifname));
}

/// Removes what an agent from before multi-instance support left behind:
/// its fixed-name forward guard, and the firewalld trust it guarded. Its
/// tagged rules need nothing special — nobody claims `wg0` for them, so
/// every reconcile treats them as leftovers already.
pub fn remove_legacy(ops: &mut impl HostOps, wg0_live: bool) {
    let observed = ops.observe(planner::LEGACY_IFNAME);
    execute_all(ops, &planner::plan_legacy_removal(&observed, wg0_live));
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
        }
    }

    #[test]
    fn a_failed_step_does_not_stop_the_others() {
        let a = Action::NftInsert {
            chain: chain("a"),
            ifname: "wg0".into(),
        };
        let b = Action::NftInsert {
            chain: chain("b"),
            ifname: "wg0".into(),
        };
        let mut ops = fake(vec![a.clone()]);
        assert_eq!(execute_all(&mut ops, &[a.clone(), b.clone()]), 1);
        assert_eq!(ops.executed, [a, b]);
    }

    #[test]
    fn no_firewalld_trust_without_the_forward_guard() {
        let guard = Action::GuardCreate { ifname: "wg0".into() };
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
        assert_eq!(reconcile(&mut ops, "wg0", &mut HashSet::new()), 0);
        assert!(ops.executed.is_empty());

        ops.observed.nft = Some(Default::default());
        assert_eq!(reconcile(&mut ops, "wg0", &mut HashSet::new()), 2);
        assert_eq!(
            ops.executed,
            [
                Action::GuardCreate { ifname: "wg0".into() },
                Action::FirewalldTrust { ifname: "wg0".into() }
            ]
        );
    }

    #[test]
    fn only_other_interfaces_a_running_agent_holds_are_live() {
        use crate::firewall::host_interop::model::{ChainInfo, IptablesTarget, IptablesVariant, IpVersion, RuleInfo};
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
}
