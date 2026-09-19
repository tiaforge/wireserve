//! The nft transactions the interop sends: head-insert our tagged accept
//! into a foreign chain, delete one rule by handle, and create/remove the
//! forward guard. Pure builders (pinned by golden tests) plus one real-
//! kernel round trip.

use std::borrow::Cow;

use nftables::expr::{Expression, Meta, MetaKey, NamedExpression};
use nftables::schema::{Chain, NfCmd, NfListObject, NfObject, Nftables, Rule, Table};
use nftables::stmt::{Accept, Counter, Drop, Match, Operator, Statement};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};

use super::model::{tag, ChainRef, Family, GUARD_CHAIN, GUARD_TABLE};

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

/// `insert rule <chain> iifname "<ifname>" counter accept comment "wireserve:<ifname>"`
/// — `insert` without a position puts it at the head of the chain, ahead
/// of that chain's own drops.
#[must_use]
pub fn insert_accept(chain: &ChainRef, ifname: &str) -> Nftables<'static> {
    Nftables {
        objects: vec![NfObject::CmdObject(NfCmd::Insert(NfListObject::Rule(Rule {
            family: nf_family(chain.family),
            table: Cow::Owned(chain.table.clone()),
            chain: Cow::Owned(chain.chain.clone()),
            expr: vec![
                iifname_is(ifname),
                Statement::Counter(Counter::Anonymous(None)),
                Statement::Accept(None::<Accept>),
            ]
            .into(),
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

fn guard_table() -> Table<'static> {
    Table {
        family: NfFamily::INet,
        name: GUARD_TABLE.into(),
        handle: None,
    }
}

fn delete_guard_cmds() -> Vec<NfObject<'static>> {
    vec![
        NfObject::CmdObject(NfCmd::Add(NfListObject::Table(guard_table()))),
        NfObject::CmdObject(NfCmd::Delete(NfListObject::Table(guard_table()))),
    ]
}

/// Atomically (re)creates `inet wireserve-interop` holding exactly one
/// forward-hook rule: `iifname "<ifname>" drop`. A drop is final across
/// every chain on the hook, so while this exists nothing — firewalld's
/// `trusted` zone included — can let traffic from the mesh be forwarded
/// to another interface.
#[must_use]
pub fn guard_create(ifname: &str) -> Nftables<'static> {
    let mut objects = delete_guard_cmds();
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Table(guard_table()))));
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: GUARD_TABLE.into(),
        name: GUARD_CHAIN.into(),
        _type: Some(NfChainType::Filter),
        hook: Some(NfHook::Forward),
        prio: Some(0),
        policy: Some(NfChainPolicy::Accept),
        ..Chain::default()
    }))));
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(Rule {
        family: NfFamily::INet,
        table: GUARD_TABLE.into(),
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

#[must_use]
pub fn guard_delete() -> Nftables<'static> {
    Nftables {
        objects: delete_guard_cmds().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::{Action, FirewalldState, Observed};
    use super::super::{planner, ruleset};
    use super::*;
    use serde_json::json;

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
            serde_json::to_value(insert_accept(&chain(), "wg0")).unwrap(),
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
        let t = json!({"family": "inet", "name": "wireserve-interop"});
        assert_eq!(
            serde_json::to_value(guard_create("wg0")).unwrap(),
            json!({"nftables": [
                {"add": {"table": t}},
                {"delete": {"table": t}},
                {"add": {"table": t}},
                {"add": {"chain": {"family": "inet", "table": "wireserve-interop",
                    "name": "forward-guard", "type": "filter", "hook": "forward",
                    "prio": 0, "policy": "accept"}}},
                {"add": {"rule": {"family": "inet", "table": "wireserve-interop",
                    "chain": "forward-guard", "expr": [
                        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wg0"}},
                        {"drop": null}
                    ]}}}
            ]})
        );
        assert_eq!(
            serde_json::to_value(guard_delete()).unwrap(),
            json!({"nftables": [{"add": {"table": t}}, {"delete": {"table": t}}]})
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
            apply_script(&insert_accept(&chain(), "wg0")),
            apply_script(&guard_create("wg0")),
        );
        let Some(out) = crate::firewall::netns::run(&script) else {
            return;
        };
        let view = ruleset::parse(out.as_bytes()).unwrap();
        let input = view.chains.iter().find(|c| c.chain == chain()).unwrap();
        assert_eq!(input.rules.len(), 2);
        assert!(planner::is_accept_shape(&input.rules[0], "wg0"), "{:?}", input.rules[0]);
        assert_eq!(input.rules[0].comment.as_deref(), Some("wireserve:wg0"));

        let observed = Observed {
            nft: Some(view.clone()),
            iptables: vec![],
            firewalld: FirewalldState::Running {
                runtime_zone: Some("trusted".into()),
                permanent_zone: None,
            },
        };
        assert_eq!(planner::plan_reconcile(&observed, "wg0"), vec![], "settled on real kernel output");

        // Removal, using the handles the kernel reported.
        let removal = planner::plan_removal(&observed, "wg0");
        let mut script = format!("{setup}{}{}", apply_script(&insert_accept(&chain(), "wg0")), apply_script(&guard_create("wg0")));
        for action in &removal {
            match action {
                Action::NftDelete { chain, handle } => script += &apply_script(&delete_rule(chain, *handle)),
                Action::GuardDelete => script += &apply_script(&guard_delete()),
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
}
