//! The nft transactions the interop sends: head-insert our tagged accept
//! into a foreign chain, delete one rule by handle, and create/remove the
//! forward guard. Pure builders (pinned by golden tests) plus one real-
//! kernel round trip.

use std::borrow::Cow;

use nftables::expr::{BinaryOperation, Expression, Meta, MetaKey, NamedExpression, CT};
use nftables::schema::{Chain, NfCmd, NfListObject, NfObject, Nftables, Rule, Table};
use nftables::stmt::{Accept, Counter, Drop, Match, Operator, Statement};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};

use super::model::{guard_table, tag, ChainRef, Family, ForwardWanted, Opening, GUARD_CHAIN};

fn nf_family(family: Family) -> NfFamily {
    match family {
        Family::Ip => NfFamily::IP,
        Family::Ip6 => NfFamily::IP6,
        Family::Inet => NfFamily::INet,
    }
}

fn iifname_is(ifname: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta {
            key: MetaKey::Iifname,
        })),
        right: Expression::String(Cow::Owned(ifname.to_string())),
        op: Operator::EQ,
    })
}

fn oifname_is(ifname: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta {
            key: MetaKey::Oifname,
        })),
        right: Expression::String(Cow::Owned(ifname.to_string())),
        op: Operator::EQ,
    })
}

/// `ct mark & M == M`: a flow our own table marked as a service's.
fn service_mark_is() -> Statement<'static> {
    let mark = crate::firewall::nftables::SERVICE_MARK;
    let ct_mark = Expression::Named(NamedExpression::CT(CT { key: "mark".into(), family: None, dir: None }));
    Statement::Match(Match {
        left: Expression::BinaryOperation(Box::new(BinaryOperation::AND(ct_mark, Expression::Number(mark)))),
        right: Expression::Number(mark),
        op: Operator::EQ,
    })
}

/// The matches of `opening` — see [`Opening`] for why every `FORWARD`
/// one is pinned to a second condition.
fn opening_matches(ifname: &str, opening: Opening) -> Vec<Statement<'static>> {
    match opening {
        Opening::Input => vec![iifname_is(ifname)],
        Opening::Hairpin => vec![iifname_is(ifname), oifname_is(ifname)],
        Opening::ServiceRequest => vec![iifname_is(ifname), service_mark_is()],
        Opening::ServiceReply => vec![oifname_is(ifname), service_mark_is()],
    }
}

/// `insert rule <chain> <opening's matches> counter accept comment
/// "wireserve:<ifname>"` — `insert` without a position puts it at the head
/// of the chain, ahead of that chain's own drops.
#[must_use]
pub fn insert_accept(chain: &ChainRef, ifname: &str, opening: Opening) -> Nftables<'static> {
    let mut expr = opening_matches(ifname, opening);
    expr.push(Statement::Counter(Counter::Anonymous(None)));
    expr.push(Statement::Accept(None::<Accept>));
    Nftables {
        objects: vec![NfObject::CmdObject(NfCmd::Insert(NfListObject::Rule(Rule {
            family: nf_family(chain.family),
            table: Cow::Owned(chain.table.clone()),
            chain: Cow::Owned(chain.chain.clone()),
            expr: expr.into(),
            handle: None,
            index: None,
            comment: Some(Cow::Owned(tag(ifname))),
        })))]
        .into(),
    }
}

#[must_use]
pub fn delete_rule(chain: &ChainRef, handle: u64) -> Nftables<'static> {
    Nftables {
        objects: vec![NfObject::CmdObject(NfCmd::Delete(NfListObject::Rule(Rule {
            family: nf_family(chain.family),
            table: Cow::Owned(chain.table.clone()),
            chain: Cow::Owned(chain.chain.clone()),
            expr: vec![].into(),
            // nft handles are u64 in the kernel but the schema uses u32;
            // real handles are small counters, so a larger one means the
            // observation was corrupt — refuse rather than delete another.
            handle: Some(u32::try_from(handle).unwrap_or(u32::MAX)),
            index: None,
            comment: None,
        })))]
        .into(),
    }
}

fn inet_table(name: &str) -> Table<'static> {
    Table {
        family: NfFamily::INet,
        name: Cow::Owned(name.to_string()),
        handle: None,
    }
}

fn delete_table_cmds(name: &str) -> Vec<NfObject<'static>> {
    vec![
        NfObject::CmdObject(NfCmd::Add(NfListObject::Table(inet_table(name)))),
        NfObject::CmdObject(NfCmd::Delete(NfListObject::Table(inet_table(name)))),
    ]
}

/// Atomically (re)creates `inet wireserve-interop.<ifname>` holding a
/// forward-hook `iifname "<ifname>" drop`, plus exceptions added *ahead*
/// of it: `iifname "<ifname>" oifname "<ifname>" accept` for transit
/// (PLAN.md M23), and `iifname "<ifname>" ct mark & M == M accept` for a
/// service's target address (PLAN.md M26). A drop is final across every
/// chain on the hook, so without an exception nothing — firewalld's
/// `trusted` zone included — can let traffic from the mesh be forwarded to
/// another interface; with them, only traffic routed back onto this same
/// interface, or a flow our own table rewrote to a declared target, ever
/// escapes that drop.
#[must_use]
pub fn guard_create(ifname: &str, forward: ForwardWanted) -> Nftables<'static> {
    let table = guard_table(ifname);
    let mut objects = delete_table_cmds(&table);
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Table(inet_table(&table)))));
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: Cow::Owned(table.clone()),
        name: GUARD_CHAIN.into(),
        _type: Some(NfChainType::Filter),
        hook: Some(NfHook::Forward),
        prio: Some(0),
        policy: Some(NfChainPolicy::Accept),
        ..Chain::default()
    }))));
    let exceptions = [(forward.transit, Opening::Hairpin), (forward.services, Opening::ServiceRequest)];
    for (_, opening) in exceptions.into_iter().filter(|(wanted, _)| *wanted) {
        let mut expr = opening_matches(ifname, opening);
        expr.push(Statement::Accept(None::<Accept>));
        objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(Rule {
            family: NfFamily::INet,
            table: Cow::Owned(table.clone()),
            chain: GUARD_CHAIN.into(),
            expr: expr.into(),
            handle: None,
            index: None,
            comment: None,
        }))));
    }
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(Rule {
        family: NfFamily::INet,
        table: Cow::Owned(table),
        chain: GUARD_CHAIN.into(),
        expr: vec![iifname_is(ifname), Statement::Drop(None::<Drop>)].into(),
        handle: None,
        index: None,
        comment: None,
    }))));
    Nftables {
        objects: objects.into(),
    }
}

/// Deletes the guard table `table` (by full name) if it exists.
#[must_use]
pub fn guard_delete(table: &str) -> Nftables<'static> {
    Nftables {
        objects: delete_table_cmds(table).into(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::{Action, FirewalldState, Observed};
    use super::super::{planner, ruleset};
    use super::*;
    use serde_json::json;

    const TRANSIT: ForwardWanted = ForwardWanted { transit: true, services: false };

    fn chain() -> ChainRef {
        ChainRef {
            family: Family::Inet,
            table: "filter".into(),
            chain: "input".into(),
        }
    }

    #[test]
    fn insert_accept_json_is_exact() {
        assert_eq!(
            serde_json::to_value(insert_accept(&chain(), "wg0", Opening::Input)).unwrap(),
            json!({"nftables": [{"insert": {"rule": {
                "family": "inet", "table": "filter", "chain": "input",
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wg0"}},
                    {"counter": null},
                    {"accept": null}
                ],
                "comment": "wireserve:wg0"
            }}}]})
        );
        assert_eq!(
            serde_json::to_value(insert_accept(&chain(), "wg0", Opening::Hairpin)).unwrap(),
            json!({"nftables": [{"insert": {"rule": {
                "family": "inet", "table": "filter", "chain": "input",
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wg0"}},
                    {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wg0"}},
                    {"counter": null},
                    {"accept": null}
                ],
                "comment": "wireserve:wg0"
            }}}]})
        );
    }

    #[test]
    fn delete_rule_json_is_exact() {
        assert_eq!(
            serde_json::to_value(delete_rule(&chain(), 42)).unwrap(),
            json!({"nftables": [{"delete": {"rule": {
                "family": "inet", "table": "filter", "chain": "input", "expr": [], "handle": 42
            }}}]})
        );
    }

    #[test]
    fn guard_json_is_exact_and_only_drops() {
        let t = json!({"family": "inet", "name": "wireserve-interop.wg0"});
        assert_eq!(
            serde_json::to_value(guard_create("wg0", ForwardWanted::default())).unwrap(),
            json!({"nftables": [
                {"add": {"table": t}},
                {"delete": {"table": t}},
                {"add": {"table": t}},
                {"add": {"chain": {"family": "inet", "table": "wireserve-interop.wg0",
                    "name": "forward-guard", "type": "filter", "hook": "forward",
                    "prio": 0, "policy": "accept"}}},
                {"add": {"rule": {"family": "inet", "table": "wireserve-interop.wg0",
                    "chain": "forward-guard", "expr": [
                        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wg0"}},
                        {"drop": null}
                    ]}}}
            ]})
        );
        assert_eq!(
            serde_json::to_value(guard_delete("wireserve-interop.wg0")).unwrap(),
            json!({"nftables": [{"add": {"table": t}}, {"delete": {"table": t}}]})
        );
    }

    #[test]
    fn guard_json_with_transit_adds_a_hairpin_exception_ahead_of_the_drop() {
        assert_eq!(
            serde_json::to_value(guard_create("wg0", TRANSIT)).unwrap(),
            json!({"nftables": [
                {"add": {"table": {"family": "inet", "name": "wireserve-interop.wg0"}}},
                {"delete": {"table": {"family": "inet", "name": "wireserve-interop.wg0"}}},
                {"add": {"table": {"family": "inet", "name": "wireserve-interop.wg0"}}},
                {"add": {"chain": {"family": "inet", "table": "wireserve-interop.wg0",
                    "name": "forward-guard", "type": "filter", "hook": "forward",
                    "prio": 0, "policy": "accept"}}},
                {"add": {"rule": {"family": "inet", "table": "wireserve-interop.wg0",
                    "chain": "forward-guard", "expr": [
                        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wg0"}},
                        {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wg0"}},
                        {"accept": null}
                    ]}}},
                {"add": {"rule": {"family": "inet", "table": "wireserve-interop.wg0",
                    "chain": "forward-guard", "expr": [
                        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wg0"}},
                        {"drop": null}
                    ]}}}
            ]})
        );
    }

    fn apply_script(batch: &Nftables<'_>) -> String {
        format!("nft -j -f - <<'JSON'\n{}\nJSON\n", serde_json::to_string(batch).unwrap())
    }

    /// The whole loop against a real kernel: what we insert reads back
    /// (through our own reader) as exactly what the planner keeps, lands
    /// at the head of the chain, and deleting it by the observed handle
    /// leaves the foreign chain as it was. Also that the guard reads back
    /// as the planner's "correct guard".
    #[test]
    fn kernel_round_trip_matches_the_planner() {
        let setup = "nft -f - <<'EOF'\n\
            table inet filter {\n  chain input {\n    type filter hook input priority 0; policy drop;\n    iif lo accept\n  }\n}\nEOF\n";
        let script = format!(
            "{setup}{}{}nft -j list ruleset",
            apply_script(&insert_accept(&chain(), "wg0", Opening::Input)),
            apply_script(&guard_create("wg0", ForwardWanted::default())),
        );
        let Some(out) = crate::firewall::netns::run(&script) else {
            return;
        };
        let view = ruleset::parse(out.as_bytes()).unwrap();
        let input = view.chains.iter().find(|c| c.chain == chain()).unwrap();
        assert_eq!(input.rules.len(), 2);
        assert!(planner::is_accept_shape(&input.rules[0], "wg0", Opening::Input), "{:?}", input.rules[0]);
        assert_eq!(input.rules[0].comment.as_deref(), Some("wireserve:wg0"));

        let observed = Observed {
            nft: Some(view.clone()),
            iptables: vec![],
            firewalld: FirewalldState::Running {
                runtime_zone: Some("trusted".into()),
                permanent_zone: None,
            },
            live: Default::default(),
        };
        assert_eq!(planner::plan_reconcile(&observed, "wg0", ForwardWanted::default()), vec![], "settled on real kernel output");

        // Removal, using the handles the kernel reported.
        let removal = planner::plan_removal(&observed, "wg0");
        let mut script = format!("{setup}{}{}", apply_script(&insert_accept(&chain(), "wg0", Opening::Input)), apply_script(&guard_create("wg0", ForwardWanted::default())));
        for action in &removal {
            match action {
                Action::NftDelete { chain, handle } => script += &apply_script(&delete_rule(chain, *handle)),
                Action::GuardDelete { table } => script += &apply_script(&guard_delete(table)),
                Action::FirewalldUntrust { .. } => {}
                other => panic!("unexpected removal action {other:?}"),
            }
        }
        script += "nft list ruleset";
        let Some(out) = crate::firewall::netns::run(&script) else {
            return;
        };
        let lines: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines,
            [
                "table inet filter {",
                "chain input {",
                "type filter hook input priority filter; policy drop;",
                "iif \"lo\" accept",
                "}",
                "}"
            ]
        );
    }

    /// The transit-shaped guard (PLAN.md M23) against a real kernel: the
    /// hairpin exception plus the still-present drop both read back and
    /// are recognised as the planner's "correct guard", and settle (no
    /// further actions) exactly like the plain drop-only guard already
    /// does above.
    #[test]
    fn kernel_transit_guard_round_trips_and_settles() {
        let script = format!("{}nft -j list ruleset", apply_script(&guard_create("wg0", TRANSIT)));
        let Some(out) = crate::firewall::netns::run(&script) else {
            return;
        };
        let view = ruleset::parse(out.as_bytes()).unwrap();
        let guard = view
            .chains
            .iter()
            .find(|c| c.chain.chain == "forward-guard")
            .expect("guard chain present");
        assert_eq!(guard.rules.len(), 2, "{:?}", guard.rules);
        assert!(planner::is_guard_shape(&guard.rules, "wg0", TRANSIT), "{:?}", guard.rules);
        assert!(!planner::is_guard_shape(&guard.rules, "wg0", ForwardWanted::default()), "the false shape must not also match");

        let observed = Observed {
            nft: Some(view),
            iptables: vec![],
            firewalld: FirewalldState::Running {
                runtime_zone: Some("trusted".into()),
                permanent_zone: None,
            },
            live: Default::default(),
        };
        assert_eq!(planner::plan_reconcile(&observed, "wg0", TRANSIT), vec![], "settled on real kernel output");
    }

    /// The service openings and guard (PLAN.md M26) against a real kernel:
    /// what nft lists back for `ct mark & M == M` is what the planner
    /// expects, so they settle instead of being replaced every reconcile.
    #[test]
    fn kernel_service_openings_round_trip_and_settle() {
        let both = ForwardWanted { transit: true, services: true };
        let forward = ChainRef { family: Family::Inet, table: "filter".into(), chain: "forward".into() };
        let setup = "nft -f - <<'EOF'\n\
            table inet filter {\n  chain input {\n    type filter hook input priority 0; policy drop;\n  }\n  \
            chain forward {\n    type filter hook forward priority 0; policy drop;\n  }\n}\nEOF\n";
        let mut script = setup.to_string();
        script += &apply_script(&insert_accept(&chain(), "wg0", Opening::Input));
        for opening in [Opening::Hairpin, Opening::ServiceRequest, Opening::ServiceReply] {
            script += &apply_script(&insert_accept(&forward, "wg0", opening));
        }
        script += &apply_script(&guard_create("wg0", both));
        script += "nft -j list ruleset";
        let Some(out) = crate::firewall::netns::run(&script) else {
            return;
        };
        let view = ruleset::parse(out.as_bytes()).unwrap();
        let fwd = view.chains.iter().find(|c| c.chain == forward).unwrap();
        assert_eq!(fwd.rules.len(), 3);
        assert!(planner::is_accept_shape(&fwd.rules[0], "wg0", Opening::ServiceReply), "{:?}", fwd.rules[0]);
        assert!(planner::is_accept_shape(&fwd.rules[1], "wg0", Opening::ServiceRequest), "{:?}", fwd.rules[1]);
        let guard = view.chains.iter().find(|c| c.chain.chain == "forward-guard").unwrap();
        assert!(planner::is_guard_shape(&guard.rules, "wg0", both), "{:?}", guard.rules);

        let observed = Observed {
            nft: Some(view),
            iptables: vec![],
            firewalld: FirewalldState::Running {
                runtime_zone: Some("trusted".into()),
                permanent_zone: None,
            },
            live: Default::default(),
        };
        assert_eq!(planner::plan_reconcile(&observed, "wg0", both), vec![], "settled on real kernel output");
    }
}
