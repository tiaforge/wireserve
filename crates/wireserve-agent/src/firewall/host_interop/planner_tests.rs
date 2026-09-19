//! Contract tests for the planner — each one pins a behavior the design
//! depends on, so a change that drifts from it fails here. Fixtures under
//! `tests/fixtures/nft/` are real `nft -j list ruleset` output, generated
//! by real nft/iptables-nft inside a throwaway network namespace.

use std::path::PathBuf;

use serde_json::json;

use super::model::*;
use super::planner::*;
use super::ruleset;

const STRATO_LIKE: &[u8] = include_bytes!("../../../tests/fixtures/nft/strato_like.json");
const NATIVE: &[u8] = include_bytes!("../../../tests/fixtures/nft/native.json");
const FIREWALLD_LIKE: &[u8] = include_bytes!("../../../tests/fixtures/nft/firewalld_like.json");

fn view(fixture: &[u8]) -> NftView {
    ruleset::parse(fixture).expect("fixture parses")
}

fn target(version: IpVersion, variant: IptablesVariant) -> IptablesTarget {
    let binary = match (version, variant) {
        (IpVersion::V4, IptablesVariant::Nft) => "/usr/sbin/iptables-nft",
        (IpVersion::V6, IptablesVariant::Nft) => "/usr/sbin/ip6tables-nft",
        (IpVersion::V4, IptablesVariant::Legacy) => "/usr/sbin/iptables-legacy",
        (IpVersion::V6, IptablesVariant::Legacy) => "/usr/sbin/ip6tables-legacy",
    };
    IptablesTarget {
        version,
        variant,
        binary: PathBuf::from(binary),
    }
}

fn ipt(version: IpVersion, variant: IptablesVariant, lines: &[&str]) -> IptablesObservation {
    IptablesObservation {
        target: target(version, variant),
        tagged_lines: Some(lines.iter().map(|l| (*l).to_string()).collect()),
    }
}

fn observed(nft: NftView) -> Observed {
    Observed {
        nft: Some(nft),
        iptables: vec![],
        firewalld: FirewalldState::Unavailable,
    }
}

fn chain_ref(family: Family, table: &str, chain: &str) -> ChainRef {
    ChainRef {
        family,
        table: table.into(),
        chain: chain.into(),
    }
}

fn nft_inserts(actions: &[Action]) -> Vec<ChainRef> {
    let mut out: Vec<ChainRef> = actions
        .iter()
        .filter_map(|a| match a {
            Action::NftInsert { chain, .. } => Some(chain.clone()),
            _ => None,
        })
        .collect();
    out.sort();
    out
}

/// A strato-shaped observation: nft view plus working iptables-nft for
/// both families, nothing of ours installed yet.
fn strato() -> Observed {
    Observed {
        nft: Some(view(STRATO_LIKE)),
        iptables: vec![
            ipt(IpVersion::V4, IptablesVariant::Nft, &[]),
            ipt(IpVersion::V6, IptablesVariant::Nft, &[]),
        ],
        firewalld: FirewalldState::Unavailable,
    }
}

/// Plans, applies the plan as the kernel would, and returns the result.
fn converge(obs: &Observed, ifname: &str) -> Observed {
    simulate(obs, &plan_reconcile(obs, ifname))
}

// ---------------------------------------------------------------------
// Safety invariants: never open anything on another interface
// ---------------------------------------------------------------------

#[test]
fn every_insert_is_for_exactly_the_configured_interface() {
    for fixture in [STRATO_LIKE, NATIVE, FIREWALLD_LIKE] {
        for ifname in ["wg0", "wireserve0", "mesh-1.a"] {
            let mut obs = observed(view(fixture));
            obs.iptables = vec![
                ipt(IpVersion::V4, IptablesVariant::Nft, &[]),
                ipt(IpVersion::V4, IptablesVariant::Legacy, &[]),
            ];
            obs.firewalld = FirewalldState::Running {
                runtime_zone: None,
                permanent_zone: None,
            };
            for action in plan_reconcile(&obs, ifname) {
                match action {
                    Action::NftInsert { ifname: i, .. }
                    | Action::IptablesInsert { ifname: i, .. }
                    | Action::FirewalldTrust { ifname: i }
                    | Action::GuardCreate { ifname: i } => assert_eq!(i, ifname),
                    Action::NftDelete { .. }
                    | Action::IptablesDelete { .. }
                    | Action::FirewalldUntrust { .. }
                    | Action::GuardDelete => {}
                }
            }
        }
    }
}

#[test]
fn inserts_only_ever_target_input_hook_filter_chains() {
    for fixture in [STRATO_LIKE, NATIVE, FIREWALLD_LIKE] {
        let v = view(fixture);
        for chain in nft_inserts(&plan_reconcile(&observed(v.clone()), "wg0")) {
            let info = v.chains.iter().find(|c| c.chain == chain).unwrap();
            assert_eq!(info.hook.as_deref(), Some("input"), "{chain:?}");
            assert_eq!(info.chain_type.as_deref(), Some("filter"), "{chain:?}");
        }
    }
}

#[test]
fn accept_shape_requires_the_exact_interface() {
    let rule = |ifname: &str| RuleInfo {
        handle: 1,
        comment: Some(tag("wg0")),
        expr: vec![
            json!({"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": ifname}}),
            json!({"counter": {"packets": 5, "bytes": 99}}),
            json!({"accept": null}),
        ],
    };
    assert!(is_accept_shape(&rule("wg0"), "wg0"));
    assert!(!is_accept_shape(&rule("wg1"), "wg0"));
    assert!(!is_accept_shape(&rule("wg*"), "wg0"));

    // Anything broader than `iifname == <if> counter accept` is not ours
    // to keep, even with our tag on it.
    let mut unscoped = rule("wg0");
    unscoped.expr.remove(0);
    assert!(!is_accept_shape(&unscoped, "wg0"));
    let mut not_equal = rule("wg0");
    not_equal.expr[0] = json!({"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "wg0"}});
    assert!(!is_accept_shape(&not_equal, "wg0"));
}

#[test]
fn iptables_line_is_exact_and_interface_scoped() {
    assert_eq!(
        iptables_line("wg0"),
        "-A INPUT -i wg0 -m comment --comment \"wireserve:wg0\" -j ACCEPT"
    );
}

#[test]
fn forward_guard_only_drops_and_only_exists_with_firewalld_trust() {
    let mut obs = observed(view(NATIVE));
    obs.firewalld = FirewalldState::Running {
        runtime_zone: None,
        permanent_zone: None,
    };
    let actions = plan_reconcile(&obs, "wg0");
    assert!(actions.contains(&Action::FirewalldTrust { ifname: "wg0".into() }));
    assert!(actions.contains(&Action::GuardCreate { ifname: "wg0".into() }));

    let after = simulate(&obs, &actions);
    let guard = after
        .nft
        .as_ref()
        .unwrap()
        .chains
        .iter()
        .find(|c| c.chain.table == GUARD_TABLE)
        .unwrap();
    assert!(guard.rules.iter().all(|r| is_guard_shape(r, "wg0")));

    // Without firewalld there is no guard, and a leftover one is removed.
    let mut gone = after.clone();
    gone.firewalld = FirewalldState::Unavailable;
    assert!(plan_reconcile(&gone, "wg0").contains(&Action::GuardDelete));
    assert!(!plan_reconcile(&observed(view(NATIVE)), "wg0")
        .iter()
        .any(|a| matches!(a, Action::GuardCreate { .. })));
}

// ---------------------------------------------------------------------
// Chain selection
// ---------------------------------------------------------------------

#[test]
fn native_inet_filter_input_gets_an_nft_insert() {
    let actions = plan_reconcile(&observed(view(NATIVE)), "wg0");
    assert!(nft_inserts(&actions).contains(&chain_ref(Family::Inet, "filter", "input")));
}

#[test]
fn native_table_named_filter_with_lowercase_input_goes_through_nft() {
    // `table ip filter { chain input … }` is a native config, not
    // iptables-nft (which always says INPUT) — even when iptables works.
    let mut obs = observed(view(NATIVE));
    obs.iptables = vec![ipt(IpVersion::V4, IptablesVariant::Nft, &[])];
    let actions = plan_reconcile(&obs, "wg0");
    assert!(nft_inserts(&actions).contains(&chain_ref(Family::Ip, "filter", "input")));
    // …and iptables-nft gets nothing: there is no iptables `INPUT` chain.
    assert!(!actions.iter().any(|a| matches!(a, Action::IptablesInsert { .. })));
}

#[test]
fn skipped_chains_are_never_touched() {
    let actions = plan_reconcile(&observed(view(NATIVE)), "wg0");
    let inserted = nft_inserts(&actions);
    for skipped in [
        chain_ref(Family::Inet, "filter", "forward"),
        chain_ref(Family::Inet, "filter", "output"),
        chain_ref(Family::Inet, "filter", "helper"), // regular chain
        chain_ref(Family::Ip, "nat", "input"),       // nat type, iptables name
        chain_ref(Family::Ip, "nat", "prerouting"),
    ] {
        assert!(!inserted.contains(&skipped), "{skipped:?}");
    }
    // bridge and netdev families are not even read.
    assert!(view(NATIVE).chains.iter().all(|c| c.chain.table != "br" && c.chain.table != "ingressfilter"));
}

#[test]
fn our_own_tables_and_firewalld_are_never_inserted_into() {
    let actions = plan_reconcile(&observed(view(FIREWALLD_LIKE)), "wg0");
    assert!(nft_inserts(&actions).is_empty(), "{actions:?}");
    let actions = plan_reconcile(&strato(), "wg0");
    assert!(!nft_inserts(&actions).iter().any(|c| OWN_TABLES.contains(&c.table.as_str())));
}

#[test]
fn owner_flagged_tables_are_skipped() {
    let mut v = view(NATIVE);
    for t in &mut v.tables {
        if t.family == Family::Inet && t.name == "filter" {
            t.flags = vec!["owner".into(), "persist".into()];
        }
    }
    let inserted = nft_inserts(&plan_reconcile(&observed(v), "wg0"));
    assert!(!inserted.contains(&chain_ref(Family::Inet, "filter", "input")));
}

#[test]
fn strato_like_host_gets_exactly_the_expected_plan() {
    let actions = plan_reconcile(&strato(), "wg0");
    assert_eq!(
        nft_inserts(&actions),
        vec![
            chain_ref(Family::Ip, "crowdsec", "crowdsec-chain"),
            chain_ref(Family::Ip6, "crowdsec6", "crowdsec6-chain"),
            chain_ref(Family::Inet, "geoip-shell", "gs_in"),
        ],
        "iptables-nft's filter/INPUT goes through iptables; tailscale's ts-input and \
         ufw's chains are regular chains; geoip-shell's prerouting chain is not INPUT"
    );
    let ipt_inserts: Vec<_> = actions
        .iter()
        .filter_map(|a| match a {
            Action::IptablesInsert { target, ifname } => Some((target.version, ifname.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(ipt_inserts, [(IpVersion::V4, "wg0"), (IpVersion::V6, "wg0")]);
    assert_eq!(actions.len(), 5, "{actions:#?}");
}

#[test]
fn iptables_nft_filter_without_a_working_binary_falls_back_to_nft() {
    let mut obs = strato();
    obs.iptables = vec![]; // no iptables binary at all
    let inserted = nft_inserts(&plan_reconcile(&obs, "wg0"));
    assert!(inserted.contains(&chain_ref(Family::Ip, "filter", "INPUT")));
    assert!(inserted.contains(&chain_ref(Family::Ip6, "filter", "INPUT")));

    // A binary that can't read the table (`-S` failed) is the same case.
    obs.iptables = vec![IptablesObservation {
        target: target(IpVersion::V4, IptablesVariant::Nft),
        tagged_lines: None,
    }];
    let inserted = nft_inserts(&plan_reconcile(&obs, "wg0"));
    assert!(inserted.contains(&chain_ref(Family::Ip, "filter", "INPUT")));
}

#[test]
fn iptables_nft_is_not_used_when_there_is_no_filter_table() {
    // Never create iptables' filter table just to open it.
    let mut obs = observed(view(FIREWALLD_LIKE));
    obs.iptables = vec![ipt(IpVersion::V4, IptablesVariant::Nft, &[])];
    assert!(plan_reconcile(&obs, "wg0").is_empty());
}

#[test]
fn legacy_and_nft_iptables_are_handled_independently() {
    let mut obs = strato();
    obs.iptables.push(ipt(IpVersion::V4, IptablesVariant::Legacy, &[]));
    let variants: Vec<_> = plan_reconcile(&obs, "wg0")
        .into_iter()
        .filter_map(|a| match a {
            Action::IptablesInsert { target, .. } => Some((target.version, target.variant)),
            _ => None,
        })
        .collect();
    assert_eq!(
        variants,
        [
            (IpVersion::V4, IptablesVariant::Nft),
            (IpVersion::V6, IptablesVariant::Nft),
            (IpVersion::V4, IptablesVariant::Legacy),
        ]
    );
}

// ---------------------------------------------------------------------
// Idempotency and recovering from drift
// ---------------------------------------------------------------------

#[test]
fn reconcile_settles_after_one_pass() {
    let mut obs = strato();
    obs.iptables.push(ipt(IpVersion::V4, IptablesVariant::Legacy, &[]));
    obs.firewalld = FirewalldState::Running {
        runtime_zone: None,
        permanent_zone: None,
    };
    let once = converge(&obs, "wg0");
    assert_eq!(plan_reconcile(&once, "wg0"), vec![], "second pass must be a no-op");
}

#[test]
fn stale_duplicate_and_misshapen_tags_are_replaced() {
    let mut obs = converge(&observed(view(NATIVE)), "wg1"); // old interface name
    let input = chain_ref(Family::Inet, "filter", "input");
    {
        let chain = obs
            .nft
            .as_mut()
            .unwrap()
            .chains
            .iter_mut()
            .find(|c| c.chain == input)
            .unwrap();
        let mut dup = chain.rules[0].clone();
        dup.handle = 777;
        chain.rules.push(dup);
        chain.rules.push(RuleInfo {
            handle: 778,
            comment: Some(tag("wg0")),
            expr: vec![json!({"accept": null})], // right tag, unscoped shape
        });
    }
    let actions = plan_reconcile(&obs, "wg0");
    let deleted: Vec<u64> = actions
        .iter()
        .filter_map(|a| match a {
            Action::NftDelete { chain, handle } if *chain == input => Some(*handle),
            _ => None,
        })
        .collect();
    assert_eq!(deleted.len(), 3, "old tag, its duplicate and the misshapen one: {actions:?}");
    assert!(deleted.contains(&777) && deleted.contains(&778));
    assert!(nft_inserts(&actions).contains(&input));
    let settled = simulate(&obs, &actions);
    assert_eq!(plan_reconcile(&settled, "wg0"), vec![]);
}

#[test]
fn duplicate_correct_rules_collapse_to_one() {
    // e.g. two agent processes raced, or a crash between insert and the
    // next reconcile's observation.
    let mut obs = converge(&observed(view(NATIVE)), "wg0");
    let input = chain_ref(Family::Inet, "filter", "input");
    let chain = obs
        .nft
        .as_mut()
        .unwrap()
        .chains
        .iter_mut()
        .find(|c| c.chain == input)
        .unwrap();
    let mut dup = chain.rules[0].clone();
    dup.handle = 4242;
    chain.rules.push(dup);
    assert_eq!(
        plan_reconcile(&obs, "wg0"),
        [Action::NftDelete {
            chain: input,
            handle: 4242
        }]
    );
}

#[test]
fn a_correct_rule_further_down_the_chain_is_left_alone() {
    // Presence, not position, is what's reconciled (as in NetBird): a tool
    // that later inserts its own rule above ours is not fought over.
    let mut obs = converge(&observed(view(NATIVE)), "wg0");
    let input = chain_ref(Family::Inet, "filter", "input");
    let chain = obs
        .nft
        .as_mut()
        .unwrap()
        .chains
        .iter_mut()
        .find(|c| c.chain == input)
        .unwrap();
    chain.rules.rotate_left(1);
    assert!(chain.rules.last().unwrap().comment.is_some());
    assert_eq!(plan_reconcile(&obs, "wg0"), vec![]);
}

#[test]
fn a_reloaded_chain_gets_its_rule_back() {
    // `nft -f /etc/nftables.conf`, `firewall-cmd --reload`, a bouncer
    // restart: the chain comes back without our rule.
    let obs = converge(&strato(), "wg0");
    let reloaded = strato(); // fresh, as if every foreign table was rebuilt
    let actions = plan_reconcile(&reloaded, "wg0");
    assert_eq!(nft_inserts(&actions).len(), 3);
    assert_eq!(plan_reconcile(&obs, "wg0"), vec![]);
}

#[test]
fn iptables_stale_and_duplicate_lines_are_replaced() {
    let mut obs = strato();
    obs.iptables = vec![ipt(
        IpVersion::V4,
        IptablesVariant::Nft,
        &[
            "-A INPUT -i wg1 -m comment --comment \"wireserve:wg1\" -j ACCEPT",
            &iptables_line("wg0"),
            &iptables_line("wg0"),
        ],
    )];
    let actions = plan_reconcile(&obs, "wg0");
    let deletes: Vec<&str> = actions
        .iter()
        .filter_map(|a| match a {
            Action::IptablesDelete { line, .. } => Some(line.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        deletes,
        [
            "-A INPUT -i wg1 -m comment --comment \"wireserve:wg1\" -j ACCEPT",
            iptables_line("wg0").as_str()
        ]
    );
    assert!(!actions.iter().any(|a| matches!(a, Action::IptablesInsert { .. })));
}

#[test]
fn firewalld_operator_choices_are_respected() {
    let running = |runtime: Option<&str>, permanent: Option<&str>| {
        let mut obs = observed(view(FIREWALLD_LIKE));
        obs.firewalld = FirewalldState::Running {
            runtime_zone: runtime.map(Into::into),
            permanent_zone: permanent.map(Into::into),
        };
        plan_reconcile(&obs, "wg0")
    };
    // Unassigned → guard, then trust (runtime) — in that order, so
    // forwarding from the mesh is never open between the two.
    assert_eq!(
        running(None, None),
        [
            Action::GuardCreate { ifname: "wg0".into() },
            Action::FirewalldTrust { ifname: "wg0".into() }
        ]
    );
    // Already trusted at runtime by us (e.g. after a restart) → guard only.
    assert_eq!(running(Some("trusted"), None), [Action::GuardCreate { ifname: "wg0".into() }]);
    // Anything an operator chose is left exactly as it is, with no guard.
    assert_eq!(running(Some("public"), None), []);
    assert_eq!(running(Some("public"), Some("public")), []);
    assert_eq!(running(Some("trusted"), Some("trusted")), []);
}

#[test]
fn no_firewalld_trust_when_the_ruleset_is_unreadable() {
    // Without an nft view the forward guard can't be verified, so trusting
    // the interface could open forwarding: nothing happens instead.
    let obs = Observed {
        nft: None,
        iptables: vec![],
        firewalld: FirewalldState::Running {
            runtime_zone: None,
            permanent_zone: None,
        },
    };
    assert_eq!(plan_reconcile(&obs, "wg0"), []);
}

// ---------------------------------------------------------------------
// Removal
// ---------------------------------------------------------------------

#[test]
fn removal_takes_away_everything_we_added_and_nothing_else() {
    let mut obs = strato();
    obs.iptables.push(ipt(IpVersion::V4, IptablesVariant::Legacy, &[]));
    obs.firewalld = FirewalldState::Running {
        runtime_zone: None,
        permanent_zone: None,
    };
    let installed = converge(&obs, "wg0");
    let removal = plan_removal(&installed, "wg0");

    // Untrust comes before the guard goes: forwarding is never open.
    let untrust = removal.iter().position(|a| matches!(a, Action::FirewalldUntrust { .. }));
    let guard = removal.iter().position(|a| *a == Action::GuardDelete);
    assert!(untrust.unwrap() < guard.unwrap(), "{removal:?}");

    let after = simulate(&installed, &removal);
    assert_eq!(after, obs, "removal must restore the exact prior state");
}

#[test]
fn removal_finds_tags_for_any_interface_name() {
    // After an --ifname change or a crash, cleanup still finds everything.
    let installed = converge(&strato(), "old0");
    let after = simulate(&installed, &plan_removal(&installed, "new0"));
    assert_eq!(after, strato());
}

#[test]
fn removal_leaves_an_operators_firewalld_zone_alone() {
    let mut obs = observed(view(FIREWALLD_LIKE));
    obs.firewalld = FirewalldState::Running {
        runtime_zone: Some("trusted".into()),
        permanent_zone: Some("trusted".into()),
    };
    assert_eq!(plan_removal(&obs, "wg0"), []);
}

// ---------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------

#[test]
fn reader_tolerates_unknown_objects_and_expressions() {
    let doc = json!({"nftables": [
        {"metainfo": {"version": "9.9.9", "json_schema_version": 7}},
        {"table": {"family": "inet", "name": "t", "handle": 1, "flags": "owner"}},
        {"chain": {"family": "inet", "table": "t", "name": "in", "handle": 1,
                   "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
        {"flowtable": {"family": "inet", "name": "f", "table": "t", "hook": "ingress"}},
        {"rule": {"family": "inet", "table": "t", "chain": "in", "handle": 2,
                  "comment": "wireserve:wg0",
                  "expr": [{"future-expression": {"x": [1, 2, 3]}}, {"accept": null}]}},
        {"rule": {"family": "arp", "table": "a", "chain": "in", "handle": 3, "expr": []}},
        {"totally-new-object": {}},
        "not even an object"
    ]});
    let v = ruleset::parse(doc.to_string().as_bytes()).unwrap();
    assert_eq!(v.tables[0].flags, ["owner"]);
    assert_eq!(v.chains.len(), 1);
    assert_eq!(v.chains[0].rules.len(), 1);
    assert_eq!(v.chains[0].rules[0].comment.as_deref(), Some("wireserve:wg0"));
}

#[test]
fn reader_parses_every_fixture() {
    for fixture in [STRATO_LIKE, NATIVE, FIREWALLD_LIKE] {
        let v = view(fixture);
        assert!(!v.tables.is_empty() && !v.chains.is_empty());
    }
    // xt compat rules (ufw's conntrack match) survive as opaque statements.
    let v = view(STRATO_LIKE);
    let ufw = v
        .chains
        .iter()
        .find(|c| c.chain.chain == "ufw-before-input" && c.chain.family == Family::Ip)
        .unwrap();
    assert!(ufw.rules.iter().any(|r| r.expr.iter().any(|e| e.get("xt").is_some())));
}

// ---------------------------------------------------------------------
// Operator notices
// ---------------------------------------------------------------------

#[test]
fn notices_explain_what_is_deliberately_left_alone() {
    // firewalld active but unreachable (containerised agent).
    let obs = observed(view(FIREWALLD_LIKE));
    let n = notices(&obs, "wg0");
    assert_eq!(n.len(), 1);
    assert!(n[0].contains("firewall-cmd --zone=trusted --change-interface=wg0"), "{n:?}");

    let zone = |runtime: Option<&str>, permanent: Option<&str>| {
        let mut obs = observed(view(FIREWALLD_LIKE));
        obs.firewalld = FirewalldState::Running {
            runtime_zone: runtime.map(Into::into),
            permanent_zone: permanent.map(Into::into),
        };
        notices(&obs, "wg0")
    };
    assert_eq!(zone(Some("public"), None).len(), 1);
    assert_eq!(zone(None, Some("public")).len(), 1);
    // Nothing to say when we manage it, or when an operator trusted it.
    assert!(zone(None, None).is_empty());
    assert!(zone(Some("trusted"), None).is_empty());
    assert!(zone(Some("trusted"), Some("trusted")).is_empty());
    // No firewalld at all: nothing.
    assert!(notices(&observed(view(NATIVE)), "wg0").is_empty());
}
