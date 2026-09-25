//! Contract tests for the planner — each one pins a behavior the design
//! depends on, so a change that drifts from it fails here. Fixtures under
//! `tests/fixtures/nft/` are real `nft -j list ruleset` output, generated
//! by real nft/iptables-nft inside a throwaway network namespace.

use std::path::PathBuf;

use serde_json::json;

use super::model::*;
use super::planner::*;
use super::ruleset;

const NONE: ForwardWanted = ForwardWanted { transit: false, services: false };
const TRANSIT: ForwardWanted = ForwardWanted { transit: true, services: false };
const SERVICES: ForwardWanted = ForwardWanted { transit: false, services: true };
const BOTH: ForwardWanted = ForwardWanted { transit: true, services: true };

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
    ipt_hook(version, variant, Hook::Input, lines)
}

fn ipt_hook(version: IpVersion, variant: IptablesVariant, hook: Hook, lines: &[&str]) -> IptablesObservation {
    IptablesObservation {
        target: target(version, variant),
        hook,
        tagged_lines: Some(lines.iter().map(|l| (*l).to_string()).collect()),
    }
}

fn observed(nft: NftView) -> Observed {
    Observed {
        nft: Some(nft),
        iptables: vec![],
        firewalld: FirewalldState::Unavailable,
        live: Default::default(),
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
        live: Default::default(),
    }
}

/// Plans, applies the plan as the kernel would, and returns the result.
fn converge(obs: &Observed, ifname: &str) -> Observed {
    simulate(obs, &plan_reconcile(obs, ifname, NONE))
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
            for action in plan_reconcile(&obs, ifname, NONE) {
                match action {
                    Action::NftInsert { ifname: i, .. }
                    | Action::IptablesInsert { ifname: i, .. }
                    | Action::FirewalldTrust { ifname: i }
                    | Action::GuardCreate { ifname: i, .. } => assert_eq!(i, ifname),
                    Action::NftDelete { .. }
                    | Action::IptablesDelete { .. }
                    | Action::FirewalldUntrust { .. }
                    | Action::GuardDelete { .. } => {}
                }
            }
        }
    }
}

#[test]
fn inserts_only_ever_target_input_hook_filter_chains() {
    for fixture in [STRATO_LIKE, NATIVE, FIREWALLD_LIKE] {
        let v = view(fixture);
        for chain in nft_inserts(&plan_reconcile(&observed(v.clone()), "wg0", NONE)) {
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
    assert!(is_accept_shape(&rule("wg0"), "wg0", Opening::Input));
    assert!(!is_accept_shape(&rule("wg1"), "wg0", Opening::Input));
    assert!(!is_accept_shape(&rule("wg*"), "wg0", Opening::Input));

    // Anything broader than `iifname == <if> counter accept` is not ours
    // to keep, even with our tag on it.
    let mut unscoped = rule("wg0");
    unscoped.expr.remove(0);
    assert!(!is_accept_shape(&unscoped, "wg0", Opening::Input));
    let mut not_equal = rule("wg0");
    not_equal.expr[0] = json!({"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "wg0"}});
    assert!(!is_accept_shape(&not_equal, "wg0", Opening::Input));

    // Forward requires the oifname match too — iifname alone is an INPUT
    // shape, not a valid Forward one (it would open routing to any other
    // interface, not just hairpin back onto this one).
    assert!(!is_accept_shape(&rule("wg0"), "wg0", Opening::Hairpin));
    let fwd_rule = RuleInfo {
        handle: 1,
        comment: Some(tag("wg0")),
        expr: vec![
            json!({"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wg0"}}),
            json!({"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wg0"}}),
            json!({"counter": {"packets": 0, "bytes": 0}}),
            json!({"accept": null}),
        ],
    };
    assert!(is_accept_shape(&fwd_rule, "wg0", Opening::Hairpin));
}

#[test]
fn iptables_line_is_exact_and_interface_scoped() {
    assert_eq!(
        iptables_line("wg0", Opening::Input),
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
    let actions = plan_reconcile(&obs, "wg0", NONE);
    assert!(actions.contains(&Action::FirewalldTrust { ifname: "wg0".into() }));
    assert!(actions.contains(&Action::GuardCreate {
        ifname: "wg0".into(),
        forward: NONE
    }));

    let after = simulate(&obs, &actions);
    let guard = after
        .nft
        .as_ref()
        .unwrap()
        .chains
        .iter()
        .find(|c| c.chain.table == guard_table("wg0"))
        .unwrap();
    assert!(is_guard_shape(&guard.rules, "wg0", NONE));

    // Without firewalld there is no guard, and a leftover one is removed.
    let mut gone = after.clone();
    gone.firewalld = FirewalldState::Unavailable;
    assert!(plan_reconcile(&gone, "wg0", NONE).contains(&Action::GuardDelete {
        table: "wireserve-interop.wg0".into()
    }));
    assert!(!plan_reconcile(&observed(view(NATIVE)), "wg0", NONE)
        .iter()
        .any(|a| matches!(a, Action::GuardCreate { .. })));
}

#[test]
fn firewalld_guard_gets_a_hairpin_exception_when_transit_capable() {
    // firewalld's `trusted` zone opens forwarding host-wide once the
    // interface is a member — this is the one place that's true, unlike
    // ufw/iptables/native nft, where each foreign chain only ever sees an
    // explicit accept for this exact interface. The guard's hairpin
    // exception is what keeps the same narrow "only wireserve0 back onto
    // wireserve0" promise true here too (PLAN.md M23).
    let mut obs = observed(view(NATIVE));
    obs.firewalld = FirewalldState::Running {
        runtime_zone: None,
        permanent_zone: None,
    };
    let actions = plan_reconcile(&obs, "wg0", TRANSIT);
    assert!(actions.contains(&Action::GuardCreate {
        ifname: "wg0".into(),
        forward: TRANSIT
    }));

    let after = simulate(&obs, &actions);
    let guard = after
        .nft
        .as_ref()
        .unwrap()
        .chains
        .iter()
        .find(|c| c.chain.table == guard_table("wg0"))
        .unwrap();
    assert!(is_guard_shape(&guard.rules, "wg0", TRANSIT));
    assert_eq!(guard.rules.len(), 2, "the hairpin exception sits ahead of the still-present drop");
    assert_eq!(plan_reconcile(&after, "wg0", TRANSIT), vec![], "settled");
}

#[test]
fn firewalld_guard_shape_is_corrected_when_transit_capable_changes() {
    // transit_capable only ever changes across a restart (join time), but
    // the guard left by a previous run must still converge to whichever
    // shape this run actually wants, not get stuck as "close enough".
    let mut obs = observed(view(NATIVE));
    obs.firewalld = FirewalldState::Running {
        runtime_zone: None,
        permanent_zone: None,
    };
    let with_transit = simulate(&obs, &plan_reconcile(&obs, "wg0", TRANSIT));
    let actions = plan_reconcile(&with_transit, "wg0", NONE);
    assert!(
        actions.contains(&Action::GuardCreate {
            ifname: "wg0".into(),
            forward: NONE
        }),
        "{actions:#?}"
    );

    let without_transit = simulate(&obs, &plan_reconcile(&obs, "wg0", NONE));
    let actions = plan_reconcile(&without_transit, "wg0", TRANSIT);
    assert!(
        actions.contains(&Action::GuardCreate {
            ifname: "wg0".into(),
            forward: TRANSIT
        }),
        "{actions:#?}"
    );
}

// ---------------------------------------------------------------------
// Chain selection
// ---------------------------------------------------------------------

#[test]
fn native_inet_filter_input_gets_an_nft_insert() {
    let actions = plan_reconcile(&observed(view(NATIVE)), "wg0", NONE);
    assert!(nft_inserts(&actions).contains(&chain_ref(Family::Inet, "filter", "input")));
}

#[test]
fn native_table_named_filter_with_lowercase_input_goes_through_nft() {
    // `table ip filter { chain input … }` is a native config, not
    // iptables-nft (which always says INPUT) — even when iptables works.
    let mut obs = observed(view(NATIVE));
    obs.iptables = vec![ipt(IpVersion::V4, IptablesVariant::Nft, &[])];
    let actions = plan_reconcile(&obs, "wg0", NONE);
    assert!(nft_inserts(&actions).contains(&chain_ref(Family::Ip, "filter", "input")));
    // …and iptables-nft gets nothing: there is no iptables `INPUT` chain.
    assert!(!actions.iter().any(|a| matches!(a, Action::IptablesInsert { .. })));
}

#[test]
fn skipped_chains_are_never_touched() {
    let actions = plan_reconcile(&observed(view(NATIVE)), "wg0", NONE);
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
    let actions = plan_reconcile(&observed(view(FIREWALLD_LIKE)), "wg0", NONE);
    assert!(nft_inserts(&actions).is_empty(), "{actions:?}");
    let actions = plan_reconcile(&strato(), "wg0", NONE);
    assert!(!nft_inserts(&actions).iter().any(|c| is_own_table(&c.table)));
}

#[test]
fn owner_flagged_tables_are_skipped() {
    let mut v = view(NATIVE);
    for t in &mut v.tables {
        if t.family == Family::Inet && t.name == "filter" {
            t.flags = vec!["owner".into(), "persist".into()];
        }
    }
    let inserted = nft_inserts(&plan_reconcile(&observed(v), "wg0", NONE));
    assert!(!inserted.contains(&chain_ref(Family::Inet, "filter", "input")));
}

#[test]
fn strato_like_host_gets_exactly_the_expected_plan() {
    let actions = plan_reconcile(&strato(), "wg0", NONE);
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
            Action::IptablesInsert { target, ifname, .. } => Some((target.version, ifname.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(ipt_inserts, [(IpVersion::V4, "wg0"), (IpVersion::V6, "wg0")]);
    assert_eq!(actions.len(), 5, "{actions:#?}");
}

// ---------------------------------------------------------------------
// FORWARD hook (PLAN.md M23, transit) — opened only when transit-capable
// ---------------------------------------------------------------------

/// A ufw-like host's `ip filter` table, shaped like the real one this was
/// diagnosed against: `INPUT` and `FORWARD` base chains, both readable
/// through iptables-nft, `FORWARD` holding no rule of ours yet.
fn ufw_forward() -> Observed {
    let mut nft = view(STRATO_LIKE);
    // Both families' INPUT chains get a matching FORWARD sibling — STRATO_LIKE
    // carries one iptables-nft `filter`/`INPUT` per family (`ip` and `ip6`),
    // and a fixture with only one would silently under-test the other.
    let inputs: Vec<_> = nft.chains.iter().filter(|c| c.chain.chain == "INPUT").cloned().collect();
    assert_eq!(inputs.len(), 2, "expected one INPUT chain per family in the fixture");
    for input in inputs {
        nft.chains.push(ChainInfo {
            chain: ChainRef {
                family: input.chain.family,
                table: input.chain.table.clone(),
                chain: "FORWARD".into(),
            },
            hook: Some("forward".into()),
            chain_type: Some("filter".into()),
            rules: vec![],
        });
    }
    Observed {
        nft: Some(nft),
        iptables: vec![
            ipt_hook(IpVersion::V4, IptablesVariant::Nft, Hook::Input, &[]),
            ipt_hook(IpVersion::V4, IptablesVariant::Nft, Hook::Forward, &[]),
            ipt_hook(IpVersion::V6, IptablesVariant::Nft, Hook::Input, &[]),
            ipt_hook(IpVersion::V6, IptablesVariant::Nft, Hook::Forward, &[]),
        ],
        firewalld: FirewalldState::Unavailable,
        live: Default::default(),
    }
}

#[test]
fn forward_hook_is_left_completely_alone_without_transit_capable() {
    // The exact bug this fixes: before the fix, an iptables-nft `FORWARD`
    // chain with a default-deny policy silently ate every transited
    // packet, because nothing ever asked it to let this interface's
    // hairpin traffic through. Without `forward_wanted`, that must stay
    // true — same footprint as before transit existed.
    let actions = plan_reconcile(&ufw_forward(), "wg0", NONE);
    assert!(!actions.iter().any(|a| matches!(a,
        Action::NftInsert { opening: Opening::Hairpin, .. } | Action::IptablesInsert { opening: Opening::Hairpin, .. }
    )));
}

#[test]
fn forward_hook_gets_a_narrow_hairpin_only_insert_when_transit_capable() {
    let actions = plan_reconcile(&ufw_forward(), "wg0", TRANSIT);
    let fwd_inserts: Vec<_> = actions
        .iter()
        .filter_map(|a| match a {
            Action::IptablesInsert {
                target,
                ifname,
                opening: Opening::Hairpin,
            } => Some((target.version, ifname.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(
        fwd_inserts,
        [(IpVersion::V4, "wg0"), (IpVersion::V6, "wg0")],
        "iptables-nft's filter/FORWARD is readable, so it goes through iptables, same as INPUT: {actions:#?}"
    );
    // INPUT is still opened exactly as before — this is additive, not a
    // replacement.
    let input_inserts = actions
        .iter()
        .filter(|a| matches!(a, Action::IptablesInsert { opening: Opening::Input, .. }))
        .count();
    assert_eq!(input_inserts, 2);
}

#[test]
fn forward_reconcile_settles_and_removal_takes_it_back_out() {
    let obs = ufw_forward();
    let installed = simulate(&obs, &plan_reconcile(&obs, "wg0", TRANSIT));
    assert_eq!(plan_reconcile(&installed, "wg0", TRANSIT), vec![], "second pass is a no-op");

    let removal = plan_removal(&installed, "wg0");
    assert!(removal.iter().any(|a| matches!(a, Action::IptablesDelete { line, .. } if line.contains("FORWARD"))));
    let after = simulate(&installed, &removal);
    assert_eq!(after, obs, "removal restores the exact prior state");
}

#[test]
fn a_stray_forward_rule_is_removed_even_when_no_longer_transit_capable() {
    // If transit_capable is turned off (a rejoin), the next start's
    // `forward_wanted=false` reconcile must still find and remove any
    // FORWARD-hook rule a previous, transit-capable run left behind —
    // `plan_reconcile`'s nft-side removal loop runs over every foreign
    // chain regardless of hook, independent of `forward_wanted`.
    let obs = ufw_forward();
    let installed = simulate(&obs, &plan_reconcile(&obs, "wg0", TRANSIT));
    let actions = plan_reconcile(&installed, "wg0", NONE);
    assert_eq!(
        actions.iter().filter(|a| matches!(a, Action::IptablesDelete { line, .. } if line.contains("FORWARD"))).count(),
        2,
        "one per family: {actions:#?}"
    );
    assert!(!actions.iter().any(|a| matches!(a, Action::IptablesInsert { opening: Opening::Hairpin, .. })));
}

#[test]
fn iptables_nft_filter_without_a_working_binary_falls_back_to_nft() {
    let mut obs = strato();
    obs.iptables = vec![]; // no iptables binary at all
    let inserted = nft_inserts(&plan_reconcile(&obs, "wg0", NONE));
    assert!(inserted.contains(&chain_ref(Family::Ip, "filter", "INPUT")));
    assert!(inserted.contains(&chain_ref(Family::Ip6, "filter", "INPUT")));

    // A binary that can't read the table (`-S` failed) is the same case.
    obs.iptables = vec![IptablesObservation {
        target: target(IpVersion::V4, IptablesVariant::Nft),
        hook: Hook::Input,
        tagged_lines: None,
    }];
    let inserted = nft_inserts(&plan_reconcile(&obs, "wg0", NONE));
    assert!(inserted.contains(&chain_ref(Family::Ip, "filter", "INPUT")));
}

#[test]
fn iptables_nft_is_not_used_when_there_is_no_filter_table() {
    // Never create iptables' filter table just to open it.
    let mut obs = observed(view(FIREWALLD_LIKE));
    obs.iptables = vec![ipt(IpVersion::V4, IptablesVariant::Nft, &[])];
    assert!(plan_reconcile(&obs, "wg0", NONE).is_empty());
}

#[test]
fn legacy_and_nft_iptables_are_handled_independently() {
    let mut obs = strato();
    obs.iptables.push(ipt(IpVersion::V4, IptablesVariant::Legacy, &[]));
    let variants: Vec<_> = plan_reconcile(&obs, "wg0", NONE)
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
    assert_eq!(plan_reconcile(&once, "wg0", NONE), vec![], "second pass must be a no-op");
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
    let actions = plan_reconcile(&obs, "wg0", NONE);
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
    assert_eq!(plan_reconcile(&settled, "wg0", NONE), vec![]);
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
        plan_reconcile(&obs, "wg0", NONE),
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
    assert_eq!(plan_reconcile(&obs, "wg0", NONE), vec![]);
}

#[test]
fn a_reloaded_chain_gets_its_rule_back() {
    // `nft -f /etc/nftables.conf`, `firewall-cmd --reload`, a bouncer
    // restart: the chain comes back without our rule.
    let obs = converge(&strato(), "wg0");
    let reloaded = strato(); // fresh, as if every foreign table was rebuilt
    let actions = plan_reconcile(&reloaded, "wg0", NONE);
    assert_eq!(nft_inserts(&actions).len(), 3);
    assert_eq!(plan_reconcile(&obs, "wg0", NONE), vec![]);
}

#[test]
fn iptables_stale_and_duplicate_lines_are_replaced() {
    let mut obs = strato();
    obs.iptables = vec![ipt(
        IpVersion::V4,
        IptablesVariant::Nft,
        &[
            "-A INPUT -i wg1 -m comment --comment \"wireserve:wg1\" -j ACCEPT",
            &iptables_line("wg0", Opening::Input),
            &iptables_line("wg0", Opening::Input),
        ],
    )];
    let actions = plan_reconcile(&obs, "wg0", NONE);
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
            iptables_line("wg0", Opening::Input).as_str()
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
        plan_reconcile(&obs, "wg0", NONE)
    };
    // Unassigned → guard, then trust (runtime) — in that order, so
    // forwarding from the mesh is never open between the two.
    assert_eq!(
        running(None, None),
        [
            Action::GuardCreate {
                ifname: "wg0".into(),
                forward: NONE
            },
            Action::FirewalldTrust { ifname: "wg0".into() }
        ]
    );
    // Already trusted at runtime by us (e.g. after a restart) → guard only.
    assert_eq!(
        running(Some("trusted"), None),
        [Action::GuardCreate {
            ifname: "wg0".into(),
            forward: NONE
        }]
    );
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
        live: Default::default(),
    };
    assert_eq!(plan_reconcile(&obs, "wg0", NONE), []);
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
    let guard = removal.iter().position(|a| matches!(a, Action::GuardDelete { .. }));
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

// ---------------------------------------------------------------------
// Several agents on one host
// ---------------------------------------------------------------------

/// `obs` as the agent on `ifname` sees it, with `others` running.
fn seen_by(obs: &Observed, others: &[&str]) -> Observed {
    let mut o = obs.clone();
    o.live = others.iter().map(|s| (*s).to_string()).collect();
    o
}

fn tag_count(obs: &Observed, ifname: &str) -> usize {
    let wanted = tag(ifname);
    let nft = obs
        .nft
        .iter()
        .flat_map(|v| &v.chains)
        .flat_map(|c| &c.rules)
        .filter(|r| r.comment.as_deref() == Some(wanted.as_str()))
        .count();
    let ipt = obs
        .iptables
        .iter()
        .flat_map(|o| o.tagged_lines.iter().flatten())
        .filter(|l| l.contains(&format!("\"{wanted}\"")))
        .count();
    nft + ipt
}

/// ufw via iptables-nft (v4 + v6), crowdsec natively, legacy iptables too.
fn busy_host() -> Observed {
    let mut obs = strato();
    obs.iptables.push(ipt(IpVersion::V4, IptablesVariant::Legacy, &[]));
    obs
}

#[test]
fn two_running_agents_settle_side_by_side() {
    let a = converge(&seen_by(&busy_host(), &["wireserve1"]), "wireserve0");
    let both = converge(&seen_by(&a, &["wireserve0"]), "wireserve1");

    let per_agent = tag_count(&a, "wireserve0");
    assert!(per_agent >= 4, "one accept per chain and ruleset: {per_agent}");
    assert_eq!(tag_count(&both, "wireserve0"), per_agent, "B left A's rules alone");
    assert_eq!(tag_count(&both, "wireserve1"), per_agent);

    // Neither has anything left to do: no ping-pong between the two.
    assert_eq!(plan_reconcile(&seen_by(&both, &["wireserve1"]), "wireserve0", NONE), vec![]);
    assert_eq!(plan_reconcile(&seen_by(&both, &["wireserve0"]), "wireserve1", NONE), vec![]);
}

#[test]
fn a_stopping_agent_removes_only_its_own_rules() {
    let a = converge(&seen_by(&busy_host(), &["wireserve1"]), "wireserve0");
    let both = converge(&seen_by(&a, &["wireserve0"]), "wireserve1");

    let after = simulate(&both, &plan_removal(&seen_by(&both, &["wireserve1"]), "wireserve0"));
    assert_eq!(tag_count(&after, "wireserve0"), 0);
    assert_eq!(tag_count(&after, "wireserve1"), tag_count(&both, "wireserve1"));
}

#[test]
fn a_dead_agents_rules_are_cleaned_up_by_a_running_one() {
    // B crashed: its claim is gone, so A no longer sees it as live.
    let a = converge(&seen_by(&busy_host(), &["wireserve1"]), "wireserve0");
    let both = converge(&seen_by(&a, &["wireserve0"]), "wireserve1");

    let actions = plan_reconcile(&seen_by(&both, &[]), "wireserve0", NONE);
    assert!(nft_inserts(&actions).is_empty(), "{actions:?}");
    let after = simulate(&both, &actions);
    assert_eq!(tag_count(&after, "wireserve1"), 0);
    assert_eq!(tag_count(&after, "wireserve0"), tag_count(&a, "wireserve0"));
}

#[test]
fn each_agent_keeps_its_own_forward_guard() {
    let firewalld = |obs: &Observed| {
        let mut o = obs.clone();
        o.firewalld = FirewalldState::Running {
            runtime_zone: None,
            permanent_zone: None,
        };
        o
    };
    let a = converge(&firewalld(&seen_by(&observed(view(FIREWALLD_LIKE)), &["wireserve1"])), "wireserve0");
    let has_guard = |obs: &Observed, ifname: &str| {
        obs.nft.as_ref().unwrap().tables.iter().any(|t| t.name == guard_table(ifname))
    };
    assert!(has_guard(&a, "wireserve0"));

    // B, with firewalld reporting its own interface as unassigned, creates
    // its own guard and never deletes A's.
    let b_actions = plan_reconcile(&firewalld(&seen_by(&a, &["wireserve0"])), "wireserve1", NONE);
    assert!(b_actions.contains(&Action::GuardCreate {
        ifname: "wireserve1".into(),
        forward: NONE
    }));
    assert!(!b_actions.iter().any(|x| matches!(x, Action::GuardDelete { .. })), "{b_actions:?}");
    let both = simulate(&a, &b_actions);
    assert!(has_guard(&both, "wireserve0") && has_guard(&both, "wireserve1"));

    // B's removal takes only B's guard.
    let mut b_trusted = seen_by(&both, &["wireserve0"]);
    b_trusted.firewalld = FirewalldState::Running {
        runtime_zone: Some("trusted".into()),
        permanent_zone: None,
    };
    let removal = plan_removal(&b_trusted, "wireserve1");
    assert_eq!(
        removal,
        [
            Action::FirewalldUntrust {
                ifname: "wireserve1".into()
            },
            Action::GuardDelete {
                table: "wireserve-interop.wireserve1".into()
            }
        ]
    );
}

#[test]
fn legacy_guard_and_its_trust_are_removed_once() {
    let mut v = view(FIREWALLD_LIKE);
    v.tables.push(TableInfo {
        family: Family::Inet,
        name: LEGACY_GUARD_TABLE.into(),
        flags: vec![],
    });
    let mut obs = observed(v);
    obs.firewalld = FirewalldState::Running {
        runtime_zone: Some("trusted".into()),
        permanent_zone: None,
    };
    let delete = Action::GuardDelete {
        table: "wireserve-interop".into(),
    };
    assert_eq!(
        plan_legacy_removal(&obs, false),
        [Action::FirewalldUntrust { ifname: "wg0".into() }, delete.clone()]
    );
    // A running agent that claims `wg0` now owns that trust.
    assert_eq!(plan_legacy_removal(&obs, true), std::slice::from_ref(&delete));
    // An operator's permanent binding is theirs.
    obs.firewalld = FirewalldState::Running {
        runtime_zone: Some("trusted".into()),
        permanent_zone: Some("trusted".into()),
    };
    assert_eq!(plan_legacy_removal(&obs, false), [delete]);
    // Nothing legacy, nothing to do.
    assert_eq!(plan_legacy_removal(&observed(view(FIREWALLD_LIKE)), false), []);
}

// ---------------------------------------------------------------------
// Services mapped onto other addresses (PLAN.md M26)
// ---------------------------------------------------------------------

fn fwd_openings(actions: &[Action]) -> Vec<(IpVersion, Opening)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::IptablesInsert { target, opening, .. } if opening.hook() == Hook::Forward => {
                Some((target.version, *opening))
            }
            _ => None,
        })
        .collect()
}

#[test]
fn a_service_target_opens_the_forward_hook_for_marked_flows_only() {
    let actions = plan_reconcile(&ufw_forward(), "wg0", SERVICES);
    assert_eq!(
        fwd_openings(&actions),
        [
            (IpVersion::V4, Opening::ServiceRequest),
            (IpVersion::V4, Opening::ServiceReply),
            (IpVersion::V6, Opening::ServiceRequest),
            (IpVersion::V6, Opening::ServiceReply),
        ],
        "no hairpin without transit: {actions:#?}"
    );
    let line = iptables_line("wg0", Opening::ServiceRequest);
    assert_eq!(
        line,
        "-A FORWARD -i wg0 -m connmark --mark 0x1000000/0x1000000 -m comment --comment \"wireserve:wg0\" -j ACCEPT"
    );
}

#[test]
fn transit_and_services_together_get_all_three_forward_openings_and_settle() {
    let obs = ufw_forward();
    let actions = plan_reconcile(&obs, "wg0", BOTH);
    assert_eq!(fwd_openings(&actions).len(), 6, "{actions:#?}");
    let installed = simulate(&obs, &actions);
    assert_eq!(plan_reconcile(&installed, "wg0", BOTH), vec![], "settled");

    // Dropping services keeps the hairpin, and only removes theirs.
    let actions = plan_reconcile(&installed, "wg0", TRANSIT);
    let deleted: Vec<&str> = actions
        .iter()
        .filter_map(|a| match a {
            Action::IptablesDelete { line, .. } => Some(line.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(deleted.len(), 4, "{actions:#?}");
    assert!(deleted.iter().all(|l| l.contains("connmark")), "{deleted:?}");
    assert!(!actions.iter().any(|a| matches!(a, Action::IptablesInsert { .. })));

    let removal = simulate(&installed, &plan_removal(&installed, "wg0"));
    assert_eq!(removal, obs, "removal restores the exact prior state");
}

#[test]
fn native_forward_chains_get_the_service_openings_too() {
    let mut obs = ufw_forward();
    obs.iptables.clear(); // no iptables binary: NetBird's native fallback
    let actions = plan_reconcile(&obs, "wg0", SERVICES);
    let fwd: Vec<Opening> = actions
        .iter()
        .filter_map(|a| match a {
            Action::NftInsert { chain, opening, .. } if chain.chain == "FORWARD" => Some(*opening),
            _ => None,
        })
        .collect();
    assert_eq!(fwd, [Opening::ServiceRequest, Opening::ServiceReply, Opening::ServiceRequest, Opening::ServiceReply]);
    let installed = simulate(&obs, &actions);
    assert_eq!(plan_reconcile(&installed, "wg0", SERVICES), vec![], "settled");
}

#[test]
fn a_rule_of_one_opening_is_not_taken_for_another() {
    let rule = |expr: Vec<serde_json::Value>| RuleInfo { handle: 1, comment: Some(tag("wg0")), expr };
    let counted = |opening| {
        let mut e = opening_matches("wg0", opening);
        e.push(json!({"counter": {"packets": 0, "bytes": 0}}));
        e.push(json!({"accept": null}));
        rule(e)
    };
    let all = [Opening::Input, Opening::Hairpin, Opening::ServiceRequest, Opening::ServiceReply];
    for a in all {
        for b in all {
            assert_eq!(is_accept_shape(&counted(a), "wg0", b), a == b, "{a:?} as {b:?}");
        }
    }
}

#[test]
fn firewalld_guard_gets_a_service_exception_ahead_of_the_drop() {
    let mut obs = observed(view(NATIVE));
    obs.firewalld = FirewalldState::Running {
        runtime_zone: None,
        permanent_zone: None,
    };
    for forward in [SERVICES, BOTH] {
        let actions = plan_reconcile(&obs, "wg0", forward);
        assert!(actions.contains(&Action::GuardCreate { ifname: "wg0".into(), forward }), "{actions:#?}");
        let after = simulate(&obs, &actions);
        let guard = after.nft.as_ref().unwrap().chains.iter().find(|c| c.chain.table == guard_table("wg0")).unwrap();
        assert!(is_guard_shape(&guard.rules, "wg0", forward));
        assert_eq!(guard.rules.len(), if forward.transit { 3 } else { 2 });
        for other in [NONE, TRANSIT, SERVICES, BOTH].into_iter().filter(|o| *o != forward) {
            assert!(!is_guard_shape(&guard.rules, "wg0", other), "{forward:?} guard taken for {other:?}");
        }
        assert_eq!(plan_reconcile(&after, "wg0", forward), vec![], "settled");
    }
}
