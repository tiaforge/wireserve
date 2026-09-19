//! Pure planning: observed host-firewall state + our interface name →
//! the exact list of changes to make. This is where every rule about
//! *what* gets opened, and where, lives — the rest of the module only
//! observes and executes — so it is also where the tests pinning that
//! behavior live.
//!
//! Safety properties, each pinned by a test below:
//! - every accept we add matches exactly `iifname == <ifname>` and sits in
//!   an INPUT-hook chain: nothing is ever opened on another interface, and
//!   nothing is ever opened for forwarded or outgoing traffic;
//! - the only forward-hook object we create is the guard, which only
//!   drops, and only exists while firewalld trust is in place;
//! - repeated planning on the resulting state yields no actions (it
//!   settles instead of churning on its own writes);
//! - another running agent's rules (tagged for an interface in
//!   `Observed::live`) and tables are never touched, so several agents
//!   on one host settle side by side instead of undoing each other.

use serde_json::{json, Value};

use std::collections::BTreeSet;

use super::iptables::line_tag;
use super::model::{
    guard_table, is_own_table, tag, tag_owner, Action, ChainInfo, Family, FirewalldState,
    IpVersion, IptablesObservation, IptablesVariant, NftView, Observed, RuleInfo,
    FIREWALLD_TABLE, GUARD_CHAIN, IPTABLES_TABLES, LEGACY_GUARD_TABLE, TAG_PREFIX,
};

const TRUSTED: &str = "trusted";

/// `iifname "<ifname>"` as nft's JSON renders it.
fn iifname_match(ifname: &str) -> Value {
    json!({"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": ifname}})
}

/// Is `rule` exactly `iifname "<ifname>" counter accept` (counter values
/// ignored)? A tagged rule of any other shape — edited by hand, or written
/// by a future version of this code — is replaced rather than trusted.
#[must_use]
pub fn is_accept_shape(rule: &RuleInfo, ifname: &str) -> bool {
    matches!(rule.expr.as_slice(),
        [iif, counter, verdict]
            if *iif == iifname_match(ifname)
                && counter.get("counter").is_some()
                && *verdict == json!({"accept": null}))
}

/// Is `rule` exactly the guard's `iifname "<ifname>" drop`?
#[must_use]
pub fn is_guard_shape(rule: &RuleInfo, ifname: &str) -> bool {
    matches!(rule.expr.as_slice(),
        [iif, verdict] if *iif == iifname_match(ifname) && *verdict == json!({"drop": null}))
}

fn is_ours(rule: &RuleInfo) -> bool {
    rule.comment.as_deref().is_some_and(|c| c.starts_with(TAG_PREFIX))
}

/// Whether a tagged rule, owned by the interface in its tag, is ours to
/// clean up: our own, or one no running agent claims.
fn removable(owner: Option<&str>, ifname: &str, live: &BTreeSet<String>) -> bool {
    match owner {
        Some(o) if o == ifname => true,
        Some(o) => !live.contains(o),
        None => true,
    }
}

fn rule_removable(rule: &RuleInfo, ifname: &str, live: &BTreeSet<String>) -> bool {
    removable(rule.comment.as_deref().and_then(tag_owner), ifname, live)
}

fn version_of(family: Family) -> Option<IpVersion> {
    match family {
        Family::Ip => Some(IpVersion::V4),
        Family::Ip6 => Some(IpVersion::V6),
        Family::Inet => None,
    }
}

/// Where a foreign chain's accept goes, if anywhere.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    Nft,
    /// An iptables-nft `filter`/`INPUT` chain that the `iptables` binary
    /// can read: handled by an iptables observation instead.
    Iptables,
    Skip,
}

fn route(view: &NftView, chain: &ChainInfo, iptables: &[IptablesObservation]) -> Route {
    let c = &chain.chain;
    if is_own_table(&c.table) || c.table == FIREWALLD_TABLE {
        return Route::Skip;
    }
    let owner_flagged = view
        .tables
        .iter()
        .any(|t| t.family == c.family && t.name == c.table && t.flags.iter().any(|f| f == "owner"));
    if owner_flagged {
        return Route::Skip;
    }
    if chain.chain_type.as_deref() != Some("filter") || chain.hook.as_deref() != Some("input") {
        return Route::Skip;
    }
    if let Some(version) = version_of(c.family) {
        if IPTABLES_TABLES.contains(&c.table.as_str()) {
            if c.table != "filter" {
                // mangle/raw/security/nat: iptables territory, not where
                // host firewalls default-deny. Left alone.
                return Route::Skip;
            }
            // iptables-nft always names its base chain `INPUT`; a native
            // nftables config that happens to call its table `filter`
            // almost always uses lowercase `input`. The name is the only
            // marker there is — iptables-nft tables carry no flag.
            let iptables_readable = iptables.iter().any(|o| {
                o.target.version == version
                    && o.target.variant == IptablesVariant::Nft
                    && o.tagged_lines.is_some()
            });
            if c.chain == "INPUT" && iptables_readable {
                return Route::Iptables;
            }
            // Either a native table named `filter`, or iptables-nft's
            // table with no working `iptables` binary to go through —
            // NetBird's fallback: insert natively.
        }
    }
    Route::Nft
}

/// The reconcile plan: make every foreign INPUT-hook filter chain (and each
/// iptables ruleset in use) hold exactly one correct accept for `ifname`,
/// remove every other rule carrying our tag except a running agent's, and
/// keep firewalld trust and the forward guard in step.
#[must_use]
pub fn plan_reconcile(observed: &Observed, ifname: &str) -> Vec<Action> {
    let mut actions = Vec::new();

    if let Some(view) = &observed.nft {
        for chain in &view.chains {
            let foreign = !is_own_table(&chain.chain.table);
            match route(view, chain, &observed.iptables) {
                Route::Nft => plan_nft_chain(chain, ifname, &observed.live, &mut actions),
                // Not ours to fill, but a tagged rule that ended up there
                // (an older version, a changed chain type) still goes.
                Route::Iptables | Route::Skip if foreign => {
                    delete_removable(chain, ifname, &observed.live, &mut actions);
                }
                Route::Iptables | Route::Skip => {}
            }
        }
    }

    for obs in &observed.iptables {
        plan_iptables(obs, ifname, observed.nft.as_ref(), &observed.live, &mut actions);
    }

    plan_firewalld(observed, ifname, &mut actions);
    actions
}

fn plan_nft_chain(chain: &ChainInfo, ifname: &str, live: &BTreeSet<String>, actions: &mut Vec<Action>) {
    let wanted = tag(ifname);
    let mut kept = false;
    for rule in chain.rules.iter().filter(|r| is_ours(r) && rule_removable(r, ifname, live)) {
        let correct = rule.comment.as_deref() == Some(wanted.as_str()) && is_accept_shape(rule, ifname);
        if correct && !kept {
            kept = true;
        } else {
            actions.push(Action::NftDelete {
                chain: chain.chain.clone(),
                handle: rule.handle,
            });
        }
    }
    if !kept {
        actions.push(Action::NftInsert {
            chain: chain.chain.clone(),
            ifname: ifname.to_string(),
        });
    }
}

fn delete_removable(chain: &ChainInfo, ifname: &str, live: &BTreeSet<String>, actions: &mut Vec<Action>) {
    for rule in chain.rules.iter().filter(|r| is_ours(r) && rule_removable(r, ifname, live)) {
        actions.push(Action::NftDelete {
            chain: chain.chain.clone(),
            handle: rule.handle,
        });
    }
}

/// The exact line `iptables -S INPUT` prints for our rule.
#[must_use]
pub fn iptables_line(ifname: &str) -> String {
    format!("-A INPUT -i {ifname} -m comment --comment \"{}\" -j ACCEPT", tag(ifname))
}

/// Whether this iptables ruleset needs our rule at all. For iptables-nft
/// the table must already exist (visible in nft as `ip`/`ip6 filter` with
/// an `INPUT` chain) — we never create a filter table just to open it.
/// A legacy observation only exists when the legacy `filter` table is
/// loaded, so it always applies.
fn iptables_applies(obs: &IptablesObservation, nft: Option<&NftView>) -> bool {
    match obs.target.variant {
        IptablesVariant::Legacy => true,
        IptablesVariant::Nft => {
            let family = match obs.target.version {
                IpVersion::V4 => Family::Ip,
                IpVersion::V6 => Family::Ip6,
            };
            nft.is_some_and(|v| {
                v.chains.iter().any(|c| {
                    c.chain.family == family && c.chain.table == "filter" && c.chain.chain == "INPUT"
                })
            })
        }
    }
}

fn plan_iptables(
    obs: &IptablesObservation,
    ifname: &str,
    nft: Option<&NftView>,
    live: &BTreeSet<String>,
    actions: &mut Vec<Action>,
) {
    let Some(lines) = &obs.tagged_lines else {
        return;
    };
    let applies = iptables_applies(obs, nft);
    let wanted = iptables_line(ifname);
    let mut kept = false;
    for line in lines.iter().filter(|l| iptables_line_removable(l, ifname, live)) {
        if applies && *line == wanted && !kept {
            kept = true;
        } else {
            actions.push(Action::IptablesDelete {
                target: obs.target.clone(),
                line: line.clone(),
            });
        }
    }
    if applies && !kept {
        actions.push(Action::IptablesInsert {
            target: obs.target.clone(),
            ifname: ifname.to_string(),
        });
    }
}

fn iptables_line_removable(line: &str, ifname: &str, live: &BTreeSet<String>) -> bool {
    let tag = line_tag(line);
    removable(tag.as_deref().and_then(tag_owner), ifname, live)
}

fn guard_state(nft: Option<&NftView>, ifname: &str) -> GuardState {
    let Some(view) = nft else {
        return GuardState::Unknown;
    };
    let table = guard_table(ifname);
    let chain = view.chains.iter().find(|c| {
        c.chain.family == Family::Inet && c.chain.table == table && c.chain.chain == GUARD_CHAIN
    });
    let table_exists = view
        .tables
        .iter()
        .any(|t| t.family == Family::Inet && t.name == table);
    match chain {
        Some(c)
            if c.hook.as_deref() == Some("forward")
                && c.rules.len() == 1
                && is_guard_shape(&c.rules[0], ifname) =>
        {
            GuardState::Correct
        }
        _ if table_exists => GuardState::Wrong,
        _ => GuardState::Absent,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum GuardState {
    Correct,
    Wrong,
    Absent,
    Unknown,
}

fn plan_firewalld(observed: &Observed, ifname: &str, actions: &mut Vec<Action>) {
    let guard = guard_state(observed.nft.as_ref(), ifname);
    if guard == GuardState::Unknown {
        // The ruleset couldn't be read, so whether the forward guard is in
        // place can't be verified — and trust without the guard would open
        // forwarding. Change nothing on this side until it can.
        return;
    }
    let mut trust = false;
    // The guard exists exactly while the interface is in `trusted` on our
    // account (runtime binding, no permanent one from an operator).
    let want_guard = match &observed.firewalld {
        FirewalldState::Unavailable => false,
        FirewalldState::Running {
            runtime_zone,
            permanent_zone,
        } => match (runtime_zone.as_deref(), permanent_zone) {
            // An operator bound the interface to a zone permanently: a
            // deliberate choice, left exactly as it is.
            (_, Some(_)) => false,
            (None, None) => {
                trust = true;
                true
            }
            (Some(TRUSTED), None) => true,
            // Runtime-bound to some other zone by someone else: leave it.
            (Some(_), None) => false,
        },
    };
    match (want_guard, guard) {
        (true, GuardState::Absent | GuardState::Wrong) => actions.push(Action::GuardCreate {
            ifname: ifname.to_string(),
        }),
        (false, GuardState::Correct | GuardState::Wrong) => actions.push(Action::GuardDelete {
            table: guard_table(ifname),
        }),
        _ => {}
    }
    // Trust only after the guard: forwarding from the mesh must never be
    // open, not even between two commands. (The executor also skips the
    // trust if creating the guard failed.)
    if trust {
        actions.push(Action::FirewalldTrust {
            ifname: ifname.to_string(),
        });
    }
}

/// Situations the planner deliberately leaves alone but an operator should
/// hear about, since the mesh interface may stay blocked by them. Stable
/// strings, so the caller can log each one once.
#[must_use]
pub fn notices(observed: &Observed, ifname: &str) -> Vec<String> {
    let mut out = Vec::new();
    let firewalld_table = observed.nft.as_ref().is_some_and(|v| {
        v.tables
            .iter()
            .any(|t| t.family == Family::Inet && t.name == FIREWALLD_TABLE)
    });
    match &observed.firewalld {
        FirewalldState::Unavailable if firewalld_table => out.push(format!(
            "firewalld is filtering this host but can't be reached from here (e.g. inside a \
             container); traffic on {ifname} may be blocked by it. On the host, run: \
             firewall-cmd --zone=trusted --change-interface={ifname}"
        )),
        FirewalldState::Running {
            runtime_zone,
            permanent_zone,
        } => {
            let chosen = permanent_zone.as_deref().or(match runtime_zone.as_deref() {
                Some(TRUSTED) | None => None,
                other => other,
            });
            if let Some(zone) = chosen.filter(|z| *z != TRUSTED) {
                out.push(format!(
                    "{ifname} is in firewalld zone '{zone}', which was set outside wireserve and \
                     is left as it is; if that zone blocks it, the mesh can't reach this node's \
                     services"
                ));
            }
        }
        FirewalldState::Unavailable => {}
    }
    out
}

/// The removal plan for shutdown/`leave`: every tagged rule anywhere that
/// isn't a running agent's (so leftovers go too), our firewalld trust (runtime `trusted` with no operator binding — the only
/// state we ever create), then the guard. Ordered so the host closes back
/// before the guard goes: the guard must never be missing while trust is
/// still in place.
#[must_use]
pub fn plan_removal(observed: &Observed, ifname: &str) -> Vec<Action> {
    let mut actions = Vec::new();
    if let Some(view) = &observed.nft {
        for chain in &view.chains {
            if !is_own_table(&chain.chain.table) {
                delete_removable(chain, ifname, &observed.live, &mut actions);
            }
        }
    }
    for obs in &observed.iptables {
        for line in obs
            .tagged_lines
            .iter()
            .flatten()
            .filter(|l| iptables_line_removable(l, ifname, &observed.live))
        {
            actions.push(Action::IptablesDelete {
                target: obs.target.clone(),
                line: line.clone(),
            });
        }
    }
    if let FirewalldState::Running {
        runtime_zone: Some(zone),
        permanent_zone: None,
    } = &observed.firewalld
    {
        if zone == TRUSTED {
            actions.push(Action::FirewalldUntrust {
                ifname: ifname.to_string(),
            });
        }
    }
    let table = guard_table(ifname);
    let guard_table_exists = observed
        .nft
        .as_ref()
        .is_some_and(|v| v.tables.iter().any(|t| t.family == Family::Inet && t.name == table));
    if guard_table_exists {
        actions.push(Action::GuardDelete { table });
    }
    actions
}

/// The interface name every agent used before `--ifname` had another
/// default.
pub const LEGACY_IFNAME: &str = "wg0";

/// What an agent from before multi-instance support leaves behind if it
/// crashed or was upgraded mid-run, beyond tagged rules: its fixed-name
/// guard table and, while that exists, the firewalld trust for `wg0` it
/// guarded. Only planned when the legacy guard is there — the evidence
/// that trust was ours — and the trust is left alone while a running
/// agent claims `wg0` now (its trust, guarded by its own table). Same
/// order as `plan_removal`: trust goes before its guard.
#[must_use]
pub fn plan_legacy_removal(observed: &Observed, wg0_live: bool) -> Vec<Action> {
    let legacy_guard = observed.nft.as_ref().is_some_and(|v| {
        v.tables
            .iter()
            .any(|t| t.family == Family::Inet && t.name == LEGACY_GUARD_TABLE)
    });
    if !legacy_guard {
        return Vec::new();
    }
    let mut actions = Vec::new();
    if let FirewalldState::Running {
        runtime_zone: Some(zone),
        permanent_zone: None,
    } = &observed.firewalld
    {
        if zone == TRUSTED && !wg0_live {
            actions.push(Action::FirewalldUntrust {
                ifname: LEGACY_IFNAME.to_string(),
            });
        }
    }
    actions.push(Action::GuardDelete {
        table: LEGACY_GUARD_TABLE.to_string(),
    });
    actions
}

/// Applies `actions` to `observed` as the kernel would, for tests that
/// check the plan settles. Handles are invented; inserted rules go first.
#[cfg(test)]
pub(crate) fn simulate(observed: &Observed, actions: &[Action]) -> Observed {
    use super::model::{ChainRef, TableInfo};

    let mut out = observed.clone();
    // Past every handle already there, as the kernel's would be — so rules
    // from separate simulated passes never share one.
    let mut next_handle = observed
        .nft
        .iter()
        .flat_map(|v| &v.chains)
        .flat_map(|c| &c.rules)
        .map(|r| r.handle)
        .max()
        .unwrap_or(0)
        .max(10_000);
    for action in actions {
        match action {
            Action::NftInsert { chain, ifname } => {
                let view = out.nft.as_mut().unwrap();
                let c = view.chains.iter_mut().find(|c| &c.chain == chain).unwrap();
                next_handle += 1;
                c.rules.insert(
                    0,
                    RuleInfo {
                        handle: next_handle,
                        comment: Some(tag(ifname)),
                        expr: vec![
                            iifname_match(ifname),
                            json!({"counter": {"packets": 0, "bytes": 0}}),
                            json!({"accept": null}),
                        ],
                    },
                );
            }
            Action::NftDelete { chain, handle } => {
                let view = out.nft.as_mut().unwrap();
                let c = view.chains.iter_mut().find(|c| &c.chain == chain).unwrap();
                c.rules.retain(|r| r.handle != *handle);
            }
            Action::IptablesInsert { target, ifname } => {
                let o = out.iptables.iter_mut().find(|o| &o.target == target).unwrap();
                o.tagged_lines.as_mut().unwrap().insert(0, iptables_line(ifname));
            }
            Action::IptablesDelete { target, line } => {
                let o = out.iptables.iter_mut().find(|o| &o.target == target).unwrap();
                let lines = o.tagged_lines.as_mut().unwrap();
                let pos = lines.iter().position(|l| l == line).unwrap();
                lines.remove(pos);
            }
            Action::FirewalldTrust { .. } => {
                if let FirewalldState::Running { runtime_zone, .. } = &mut out.firewalld {
                    *runtime_zone = Some(TRUSTED.into());
                }
            }
            Action::FirewalldUntrust { .. } => {
                if let FirewalldState::Running { runtime_zone, .. } = &mut out.firewalld {
                    *runtime_zone = None;
                }
            }
            Action::GuardCreate { ifname } => {
                let table = guard_table(ifname);
                let view = out.nft.as_mut().unwrap();
                view.tables.retain(|t| t.name != table);
                view.chains.retain(|c| c.chain.table != table);
                view.tables.push(TableInfo {
                    family: Family::Inet,
                    name: table.clone(),
                    flags: vec![],
                });
                next_handle += 1;
                view.chains.push(ChainInfo {
                    chain: ChainRef {
                        family: Family::Inet,
                        table,
                        chain: GUARD_CHAIN.into(),
                    },
                    hook: Some("forward".into()),
                    chain_type: Some("filter".into()),
                    rules: vec![RuleInfo {
                        handle: next_handle,
                        comment: None,
                        expr: vec![iifname_match(ifname), json!({"drop": null})],
                    }],
                });
            }
            Action::GuardDelete { table } => {
                let view = out.nft.as_mut().unwrap();
                view.tables.retain(|t| t.name != *table);
                view.chains.retain(|c| c.chain.table != *table);
            }
        }
    }
    out
}
