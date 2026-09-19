//! Linux v1 `FirewallBackend` — nftables via the `nft` binary's JSON API
//! (spec §5; see `firewall/nft.rs` for why this is no longer netlink via
//! `rustables`).

use std::borrow::Cow;

use nftables::expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, CT};
use nftables::schema::{Chain, NfCmd, NfListObject, NfObject, Nftables, Rule, Table};
use nftables::stmt::{Accept, Drop, Match, Operator, Statement};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};
use wireserve_types::{FirewallBackend, Proto, ServiceRule};

use super::nft::{Nft, NftError};

/// Our table is `inet wireserve.<ifname>`: one per interface, so several
/// agents on one host each replace and remove only their own.
pub const TABLE_PREFIX: &str = "wireserve.";
/// The single fixed-name table every version before multi-instance
/// support used. Nothing creates it any more; see `remove_legacy_table`.
pub const LEGACY_TABLE_NAME: &str = "wireserve";
const CHAIN_NAME: &str = "wireserve-in";

#[derive(Debug, thiserror::Error)]
pub enum NftablesError {
    #[error("nftables error: {0}")]
    Nft(#[from] NftError),
}

#[must_use]
pub fn table_name(ifname: &str) -> String {
    format!("{TABLE_PREFIX}{ifname}")
}

pub struct NftablesBackend {
    /// The WireGuard interface every rule is scoped to — this backend must
    /// never install a rule that isn't `iifname`-restricted to it, or it
    /// would be firewalling the whole host rather than just the mesh.
    ifname: String,
    nft: Nft,
}

impl NftablesBackend {
    /// Fails if `nft` can't be found: the firewall is not optional, so a
    /// daemon without one must refuse to start rather than run open.
    pub fn new(ifname: impl Into<String>) -> Result<Self, NftablesError> {
        Ok(Self {
            ifname: ifname.into(),
            nft: Nft::locate()?,
        })
    }
}

fn table(name: &str) -> Table<'static> {
    Table {
        family: NfFamily::INet,
        name: Cow::Owned(name.to_string()),
        handle: None,
    }
}

/// "Delete the table `name` if it exists", as two commands inside one
/// transaction: adding a table that already exists is a no-op, so the
/// delete that follows always has something to remove. This is the
/// standard nft idiom for an unconditional atomic replace — no separate
/// existence check, and no window in which the old and new rulesets are
/// both partially applied.
fn delete_table_cmds(name: &str) -> [NfObject<'static>; 2] {
    [
        NfObject::CmdObject(NfCmd::Add(NfListObject::Table(table(name)))),
        NfObject::CmdObject(NfCmd::Delete(NfListObject::Table(table(name)))),
    ]
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

/// `ct state { established, related }`. RELATED alongside ESTABLISHED:
/// ICMP errors tied to a tracked flow — packet-too-big for path MTU
/// discovery in particular, which WireGuard's 1420 MTU makes routine — are
/// RELATED and would otherwise be dropped.
fn established_or_related() -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::CT(CT {
            key: "state".into(),
            family: None,
            dir: None,
        })),
        right: Expression::List(vec![
            Expression::String("established".into()),
            Expression::String("related".into()),
        ]),
        op: Operator::IN,
    })
}

fn dport_is(rule: &ServiceRule) -> Statement<'static> {
    let protocol = match rule.proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    };
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
            protocol: protocol.into(),
            field: "dport".into(),
        }))),
        right: Expression::Number(u32::from(rule.port)),
        op: Operator::EQ,
    })
}

fn rule(table: &str, expr: Vec<Statement<'static>>) -> NfObject<'static> {
    NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(Rule {
        family: NfFamily::INet,
        table: Cow::Owned(table.to_string()),
        chain: CHAIN_NAME.into(),
        expr: expr.into(),
        handle: None,
        index: None,
        comment: None,
    })))
}

/// The whole transaction `apply` sends. Pure, so its exact shape is pinned
/// by tests without a kernel.
///
/// **Real bug found and fixed by an actual end-to-end deployment test**
/// (two agent containers + a coordinator, see PLAN.md decisions log):
/// this chain is a *base* chain hooked into netfilter's global INPUT path
/// — a base chain's own default policy applies to packets on *every*
/// interface, not just the ones its individual rules happen to
/// `iifname`-match. The original version set a `drop` policy, which
/// silently firewalled off **all** inbound traffic on every interface
/// (including the node's own outbound HTTP poll requests' return traffic
/// on its regular network interface) the moment the agent started — every
/// poll request hung in `SYN_SENT` forever, caught only by watching real
/// TCP state during a live test. Fixed by keeping the chain's own policy
/// at `accept` (safe for every non-WireGuard interface) and instead
/// scoping the actual deny behavior to an explicit final `iifname`
/// catch-all rule, so *only* traffic arriving on the WireGuard interface
/// is default-denied, per spec §5's actual intent.
pub(crate) fn apply_batch(ifname: &str, rules: &[ServiceRule]) -> Nftables<'static> {
    let name = table_name(ifname);
    let mut objects: Vec<NfObject<'static>> = delete_table_cmds(&name).into();
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Table(table(&name)))));
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: Cow::Owned(name.clone()),
        name: CHAIN_NAME.into(),
        _type: Some(NfChainType::Filter),
        hook: Some(NfHook::Input),
        prio: Some(0),
        policy: Some(NfChainPolicy::Accept),
        ..Chain::default()
    }))));

    // Allow return traffic for connections this node itself initiated over
    // the WireGuard interface (e.g. this node acting as a client of another
    // peer's declared service) — without this, a WG-interface-scoped
    // default-deny would break outbound connectivity through the tunnel
    // just as badly as the bug above broke it on every other interface.
    objects.push(rule(&name, vec![
        iifname_is(ifname),
        established_or_related(),
        Statement::Accept(None::<Accept>),
    ]));

    for service in rules {
        objects.push(rule(&name, vec![
            iifname_is(ifname),
            dport_is(service),
            Statement::Accept(None::<Accept>),
        ]));
    }

    // Default-deny, but ONLY for the WireGuard interface — everything else
    // stays governed by the chain's own accept policy above.
    objects.push(rule(&name, vec![iifname_is(ifname), Statement::Drop(None::<Drop>)]));

    Nftables {
        objects: objects.into(),
    }
}

/// The transaction `teardown` sends: remove the table if present, nothing
/// else. Unlike the netlink version this replaces, removing a table that
/// was never created is not a special case — the add-then-delete pair
/// handles it, so there is no empty batch that could hang (see PLAN.md
/// decisions log for that bug).
pub(crate) fn teardown_batch(table: &str) -> Nftables<'static> {
    Nftables {
        objects: Vec::from(delete_table_cmds(table)).into(),
    }
}

/// Removes the fixed-name table of an agent from before multi-instance
/// support — left behind if that version crashed, or was upgraded while
/// its interface was up. Default-denying `wg0`, it would otherwise keep
/// blocking any other tunnel that later uses that name.
pub fn remove_legacy_table(nft: &Nft) -> Result<(), NftablesError> {
    nft.apply(&teardown_batch(LEGACY_TABLE_NAME))?;
    Ok(())
}

impl FirewallBackend for NftablesBackend {
    type Error = NftablesError;

    /// Full-replace in one atomic transaction: the previous table (if any)
    /// is deleted and the table/chain/rules recreated from scratch.
    fn apply(&mut self, rules: &[ServiceRule]) -> Result<(), Self::Error> {
        self.nft.apply(&apply_batch(&self.ifname, rules))?;
        Ok(())
    }

    /// Removes this interface's table entirely, if present.
    fn teardown(&mut self) -> Result<(), Self::Error> {
        self.nft.apply(&teardown_batch(&table_name(&self.ifname)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn as_json(batch: &Nftables<'_>) -> Value {
        serde_json::to_value(batch).unwrap()
    }

    fn iif(ifname: &str) -> Value {
        json!({"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": ifname}})
    }

    fn table_json() -> Value {
        json!({"family": "inet", "name": "wireserve.wg0"})
    }

    fn rule_json(expr: Value) -> Value {
        json!({"add": {"rule": {
            "family": "inet", "table": "wireserve.wg0", "chain": "wireserve-in", "expr": expr
        }}})
    }

    fn prelude() -> Vec<Value> {
        vec![
            json!({"add": {"table": table_json()}}),
            json!({"delete": {"table": table_json()}}),
            json!({"add": {"table": table_json()}}),
            json!({"add": {"chain": {
                "family": "inet", "table": "wireserve.wg0", "name": "wireserve-in",
                "type": "filter", "hook": "input", "prio": 0, "policy": "accept"
            }}}),
            rule_json(json!([
                iif("wg0"),
                {"match": {"op": "in", "left": {"ct": {"key": "state"}},
                           "right": ["established", "related"]}},
                {"accept": null}
            ])),
        ]
    }

    #[test]
    fn apply_with_no_services_is_default_deny_on_the_interface_only() {
        let mut expected = prelude();
        expected.push(rule_json(json!([iif("wg0"), {"drop": null}])));
        assert_eq!(as_json(&apply_batch("wg0", &[])), json!({ "nftables": expected }));
    }

    #[test]
    fn apply_opens_exactly_the_declared_services() {
        let rules = [
            ServiceRule {
                proto: Proto::Tcp,
                port: 32400,
            },
            ServiceRule {
                proto: Proto::Udp,
                port: 5353,
            },
        ];
        let mut expected = prelude();
        expected.push(rule_json(json!([
            iif("wg0"),
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 32400}},
            {"accept": null}
        ])));
        expected.push(rule_json(json!([
            iif("wg0"),
            {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 5353}},
            {"accept": null}
        ])));
        expected.push(rule_json(json!([iif("wg0"), {"drop": null}])));
        assert_eq!(as_json(&apply_batch("wg0", &rules)), json!({ "nftables": expected }));
    }

    #[test]
    fn every_rule_is_scoped_to_the_configured_interface() {
        let rules = [ServiceRule {
            proto: Proto::Tcp,
            port: 22,
        }];
        for ifname in ["wg0", "wireserve0", "wg-mesh.1"] {
            let batch = as_json(&apply_batch(ifname, &rules));
            let rules: Vec<&Value> = batch["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|o| o.get("add").and_then(|a| a.get("rule")))
                .collect();
            assert_eq!(rules.len(), 3);
            for r in rules {
                assert_eq!(r["expr"][0], iif(ifname), "rule not scoped to {ifname}: {r}");
            }
        }
    }

    #[test]
    fn teardown_only_removes_our_table() {
        assert_eq!(
            as_json(&teardown_batch("wireserve.wg0")),
            json!({"nftables": [
                {"add": {"table": table_json()}},
                {"delete": {"table": table_json()}}
            ]})
        );
    }

    // ---- real kernel (unprivileged netns, skipped where unavailable) ----

    fn nft_script(batches: &[Nftables<'_>]) -> String {
        batches
            .iter()
            .map(|b| format!("nft -j -f - <<'JSON'\n{}\nJSON\n", serde_json::to_string(b).unwrap()))
            .collect()
    }

    #[test]
    fn kernel_accepts_apply_and_renders_the_expected_ruleset() {
        let rules = [ServiceRule {
            proto: Proto::Tcp,
            port: 32400,
        }];
        let script = nft_script(&[apply_batch("wg0", &rules)]) + "nft list table inet wireserve.wg0";
        let Some(listing) = crate::firewall::netns::run(&script) else {
            return;
        };
        // nft renders a ct-state bitmask as `established,related` (1.1.x)
        // or `{ established, related }` (some older releases) — the same
        // kernel rule either way, so normalise before comparing.
        let listing = listing.replace("{ established, related }", "established,related");
        let lines: Vec<&str> = listing.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines,
            [
                "table inet wireserve.wg0 {",
                "chain wireserve-in {",
                "type filter hook input priority filter; policy accept;",
                "iifname \"wg0\" ct state established,related accept",
                "iifname \"wg0\" tcp dport 32400 accept",
                "iifname \"wg0\" drop",
                "}",
                "}",
            ]
        );
    }

    #[test]
    fn kernel_apply_twice_replaces_rather_than_accumulates() {
        let tcp = |port| ServiceRule {
            proto: Proto::Tcp,
            port,
        };
        let script = nft_script(&[apply_batch("wg0", &[tcp(1)]), apply_batch("wg0", &[tcp(2)])])
            + "nft list table inet wireserve.wg0";
        let Some(listing) = crate::firewall::netns::run(&script) else {
            return;
        };
        assert!(!listing.contains("dport 1 "), "{listing}");
        assert!(listing.contains("tcp dport 2 accept"), "{listing}");
        assert_eq!(listing.matches("chain wireserve-in").count(), 1, "{listing}");
    }

    #[test]
    fn kernel_teardown_works_with_and_without_an_existing_table() {
        // Teardown on a fresh namespace (no table yet) must succeed — the
        // case that hung the old netlink implementation — and teardown
        // after apply must leave nothing behind.
        let script = nft_script(&[
            teardown_batch("wireserve.wg0"),
            apply_batch("wg0", &[]),
            teardown_batch("wireserve.wg0"),
        ])
            + "nft list ruleset";
        let Some(listing) = crate::firewall::netns::run(&script) else {
            return;
        };
        assert_eq!(listing.trim(), "");
    }

    #[test]
    fn every_interface_gets_its_own_table() {
        for ifname in ["wg0", "wireserve1"] {
            let batch = as_json(&apply_batch(ifname, &[]));
            for object in batch["nftables"].as_array().unwrap() {
                let body = object.get("add").or_else(|| object.get("delete")).unwrap();
                let table = match body.get("table") {
                    Some(t) => &t["name"],
                    None => &body.as_object().unwrap().values().next().unwrap()["table"],
                };
                assert_eq!(*table, json!(format!("wireserve.{ifname}")), "{object}");
            }
        }
    }

    #[test]
    fn kernel_two_interfaces_keep_separate_tables() {
        let tcp = |port| ServiceRule {
            proto: Proto::Tcp,
            port,
        };
        let script = nft_script(&[
            apply_batch("wireserve0", &[tcp(1)]),
            apply_batch("wireserve1", &[tcp(2)]),
            apply_batch("wireserve0", &[tcp(3)]),
            teardown_batch("wireserve.wireserve0"),
        ]) + "nft list ruleset";
        let Some(listing) = crate::firewall::netns::run(&script) else {
            return;
        };
        assert!(!listing.contains("wireserve.wireserve0"), "{listing}");
        assert!(listing.contains("table inet wireserve.wireserve1"), "{listing}");
        assert!(listing.contains("iifname \"wireserve1\" tcp dport 2 accept"), "{listing}");
    }
}
