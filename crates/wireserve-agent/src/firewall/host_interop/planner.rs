//! Pure planning: observed host-firewall state + our interface name →
//! the exact list of changes to make. This is where every rule about
//! *what* gets opened, and where, lives — the rest of the module only
//! observes and executes — so it is also where the tests pinning that
//! behavior live.
//!
//! Safety properties, each pinned by a test below:
//! - every INPUT-hook accept we add matches exactly `iifname == <ifname>`;
//!   nothing is ever opened for outgoing traffic;
//! - every FORWARD-hook object — an accept, or one of the guard's
//!   exceptions — additionally requires `oifname == <ifname>` (hairpin
//!   traffic back onto this same interface, for a transit-capable node,
//!   PLAN.md M23) or a flow our own table marked as a service's (for a
//!   node forwarding to a service's target address, PLAN.md M26), so it
//!   never opens routing from the mesh to another interface as such, and
//!   only exists at all when `ForwardWanted` asks for it;
//! - the guard's unconditional drop (no exception) is the only
//!   forward-hook object ever created without `ForwardWanted`, and only
//!   exists while firewalld trust is in place;
//! - repeated planning on the resulting state yields no actions (it
//!   settles instead of churning on its own writes);
//! - another running agent's rules (tagged for an interface in
//!   `Observed::live`) and tables are never touched, so several agents
//!   on one host settle side by side instead of undoing each other.

use serde_json::{json, Value};

use std::collections::BTreeSet;

use super::iptables::line_tag;
use super::model::{
    guard_table, is_own_table, tag, tag_owner, Action, ChainInfo, Family, FirewalldState, ForwardWanted,
    Hook, IpVersion, IptablesObservation, IptablesVariant, NftView, Observed, Opening, RuleInfo,
    FIREWALLD_TABLE, GUARD_CHAIN, IPTABLES_TABLES, LEGACY_GUARD_TABLE, TAG_PREFIX,
};
use crate::firewall::nftables::SERVICE_MARK;

const TRUSTED: &str = "trusted";

/// `iifname "<ifname>"` as nft's JSON renders it.
fn iifname_match(ifname: &str) -> Value {
    json!({"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": ifname}})
}

/// `oifname "<ifname>"` as nft's JSON renders it.
fn oifname_match(ifname: &str) -> Value {
    json!({"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": ifname}})
}

/// `ct mark & M == M` as nft's JSON renders it: a flow our own table
/// marked as a service's.
fn service_mark_match() -> Value {
    json!({"match": {"op": "==", "left": {"&": [{"ct": {"key": "mark"}}, SERVICE_MARK]}, "right": SERVICE_MARK}})
}

/// The matches of `opening`'s accept, as nft's JSON renders them.
#[must_use]
pub fn opening_matches(ifname: &str, opening: Opening) -> Vec<Value> {
    match opening {
        Opening::Input => vec![iifname_match(ifname)],
        Opening::Hairpin => vec![iifname_match(ifname), oifname_match(ifname)],
        Opening::ServiceRequest => vec![iifname_match(ifname), service_mark_match()],
        Opening::ServiceReply => vec![oifname_match(ifname), service_mark_match()],
    }
}

/// Is `rule` exactly `<opening's matches> counter accept` (counter values
/// ignored)? A tagged rule of any other shape — edited by hand, or written
/// by a future version of this code — is replaced rather than trusted.
#[must_use]
pub fn is_accept_shape(rule: &RuleInfo, ifname: &str, opening: Opening) -> bool {
    let matches = opening_matches(ifname, opening);
    let n = matches.len();
    rule.expr.len() == n + 2
        && rule.expr[..n] == matches[..]
        && rule.expr[n].get("counter").is_some()
        && rule.expr[n + 1] == json!({"accept": null})
}

/// Whether `ifname`'s own deny table (`inet wireserve.<ifname>`) is in
/// place: both its input and its forward chain present and ending in
/// `iifname "<ifname>" drop`, as every ruleset the backend applies does.
///
/// Everything [`plan_reconcile`] opens hands the interface over to that
/// table, so without it the reconcile must open nothing (see
/// `ops::reconcile`). An unreadable ruleset counts as not in place: fail
/// closed.
#[must_use]
pub fn own_table_intact(observed: &Observed, ifname: &str) -> bool {
    use crate::firewall::nftables::{table_name, CHAIN_NAME, FORWARD_CHAIN};
    let Some(view) = &observed.nft else {
        return false;
    };
    let table = table_name(ifname);
    let ends_in_drop = |name: &str| {
        view.chains.iter().any(|c| {
            c.chain.family == Family::Inet
                && c.chain.table == table
                && c.chain.chain == name
                && c.rules.last().is_some_and(|r| is_guard_drop_shape(r, ifname))
        })
    };
    ends_in_drop(CHAIN_NAME) && ends_in_drop(FORWARD_CHAIN)
}

/// Is `rule` exactly the guard's plain `iifname "<ifname>" drop`?
#[must_use]
pub fn is_guard_drop_shape(rule: &RuleInfo, ifname: &str) -> bool {
    matches!(rule.expr.as_slice(),
        [iif, verdict] if *iif == iifname_match(ifname) && *verdict == json!({"drop": null}))
}

/// The guard's exceptions for `forward`, in order: the matches of each
/// `<matches> accept` ahead of the drop.
#[must_use]
pub fn guard_exceptions(ifname: &str, forward: ForwardWanted) -> Vec<Vec<Value>> {
    let mut out = Vec::new();
    if forward.transit {
        out.push(opening_matches(ifname, Opening::Hairpin));
    }
    if forward.services {
        out.push(opening_matches(ifname, Opening::ServiceRequest));
    }
    out
}

/// Are `rules` exactly the guard's rules for `forward`? With neither,
/// unchanged from before either existed: one rule, `iifname "<ifname>"
/// drop`, final across every chain on the hook. Exceptions go *ahead* of
/// that same drop — the hairpin one for transit (PLAN.md M23), so traffic
/// routed back onto this same interface escapes it, and the service one
/// (PLAN.md M26), so a flow our own table rewrote to a declared target
/// does; any other forwarding to another interface on the host stays
/// exactly as blocked as it always was, even though firewalld's `trusted`
/// zone would otherwise allow it host-wide.
#[must_use]
pub fn is_guard_shape(rules: &[RuleInfo], ifname: &str, forward: ForwardWanted) -> bool {
    let exceptions = guard_exceptions(ifname, forward);
    let Some((drop, accepts)) = rules.split_last() else {
        return false;
    };
    accepts.len() == exceptions.len()
        && is_guard_drop_shape(drop, ifname)
        && accepts.iter().zip(&exceptions).all(|(rule, matches)| {
            let n = matches.len();
            rule.expr.len() == n + 1 && rule.expr[..n] == matches[..] && rule.expr[n] == json!({"accept": null})
        })
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
    Nft(Hook),
    /// An iptables-nft `filter`/`INPUT`or`FORWARD` chain that the
    /// `iptables` binary can read: handled by an iptables observation
    /// instead.
    Iptables,
    Skip,
}

/// `forward` — this node is transit-capable (PLAN.md M23), or forwards to
/// a service's target address (PLAN.md M26) — is what makes a
/// `forward`-hook chain routable at all; without it, `FORWARD` is left
/// exactly as untouched as it was before either existed.
fn route(view: &NftView, chain: &ChainInfo, iptables: &[IptablesObservation], forward: ForwardWanted) -> Route {
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
    if chain.chain_type.as_deref() != Some("filter") {
        return Route::Skip;
    }
    let hook = match chain.hook.as_deref() {
        Some("input") => Hook::Input,
        Some("forward") if forward.any() => Hook::Forward,
        _ => return Route::Skip,
    };
    if let Some(version) = version_of(c.family) {
        if IPTABLES_TABLES.contains(&c.table.as_str()) {
            if c.table != "filter" {
                // mangle/raw/security/nat: iptables territory, not where
                // host firewalls default-deny. Left alone.
                return Route::Skip;
            }
            // iptables-nft always names its base chains upper-case; a
            // native nftables config that happens to call its table
            // `filter` almost always uses lower-case names. The name is
            // the only marker there is — iptables-nft tables carry no flag.
            let iptables_readable = iptables.iter().any(|o| {
                o.hook == hook
                    && o.target.version == version
                    && o.target.variant == IptablesVariant::Nft
                    && o.tagged_lines.is_some()
            });
            if c.chain == hook.iptables_chain() && iptables_readable {
                return Route::Iptables;
            }
            // Either a native table named `filter`, or iptables-nft's
            // table with no working `iptables` binary to go through —
            // NetBird's fallback: insert natively.
        }
    }
    Route::Nft(hook)
}

/// The reconcile plan: make every foreign INPUT-hook filter chain (and each
/// iptables ruleset in use) hold exactly one correct accept for `ifname`,
/// remove every other rule carrying our tag except a running agent's, keep
/// firewalld trust and the forward guard in step, and — only when
/// `forward` asks for it — do the same for every foreign FORWARD-hook
/// filter chain too, with the narrower shapes of [`Opening`] so nothing
/// but hairpin traffic back onto this same interface, or a service flow
/// our own table marked, is ever opened.
#[must_use]
pub fn plan_reconcile(observed: &Observed, ifname: &str, forward: ForwardWanted) -> Vec<Action> {
    let mut actions = Vec::new();

    if let Some(view) = &observed.nft {
        for chain in &view.chains {
            let foreign = !is_own_table(&chain.chain.table);
            match route(view, chain, &observed.iptables, forward) {
                Route::Nft(hook) => plan_nft_chain(chain, ifname, hook, forward, &observed.live, &mut actions),
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
        plan_iptables(obs, ifname, observed.nft.as_ref(), forward, &observed.live, &mut actions);
    }

    plan_firewalld(observed, ifname, forward, &mut actions);
    actions
}

/// Keeps exactly one correct rule per wanted opening, deletes every other
/// removable one of ours, inserts what is missing.
fn plan_nft_chain(
    chain: &ChainInfo,
    ifname: &str,
    hook: Hook,
    forward: ForwardWanted,
    live: &BTreeSet<String>,
    actions: &mut Vec<Action>,
) {
    let tagged = tag(ifname);
    let wanted = Opening::wanted(hook, forward);
    let mut kept: Vec<Opening> = Vec::new();
    for rule in chain.rules.iter().filter(|r| is_ours(r) && rule_removable(r, ifname, live)) {
        let correct = (rule.comment.as_deref() == Some(tagged.as_str()))
            .then(|| wanted.iter().copied().find(|o| !kept.contains(o) && is_accept_shape(rule, ifname, *o)))
            .flatten();
        match correct {
            Some(opening) => kept.push(opening),
            None => actions.push(Action::NftDelete {
                chain: chain.chain.clone(),
                handle: rule.handle,
            }),
        }
    }
    for opening in wanted.into_iter().filter(|o| !kept.contains(o)) {
        actions.push(Action::NftInsert {
            chain: chain.chain.clone(),
            ifname: ifname.to_string(),
            opening,
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

/// The exact line `iptables -S INPUT`/`-S FORWARD` prints for our rule.
#[must_use]
pub fn iptables_line(ifname: &str, opening: Opening) -> String {
    let matches = super::iptables::opening_spec(ifname, opening).join(" ");
    format!("-A {} {matches} -m comment --comment \"{}\" -j ACCEPT", opening.hook().iptables_chain(), tag(ifname))
}

/// Whether this iptables ruleset needs our rules at all. `Hook::Forward`
/// additionally needs `forward` to ask for something (PLAN.md M23, M26) —
/// but this only gates *inserting*: `plan_iptables` still scans (and
/// removes from) a `Hook::Forward` observation's tagged lines even when it
/// doesn't apply, so a rule left behind by an earlier run that wanted it is
/// still found and removed once nothing does, the same as the nft side
/// already does. For iptables-nft the
/// table must already exist (visible in nft as `ip`/`ip6 filter` with the
/// matching `INPUT`/`FORWARD` chain) — we never create a filter table just
/// to open it. A legacy observation only exists when the legacy `filter`
/// table is loaded, so it always applies.
fn iptables_applies(obs: &IptablesObservation, nft: Option<&NftView>, forward: ForwardWanted) -> bool {
    if obs.hook == Hook::Forward && !forward.any() {
        return false;
    }
    match obs.target.variant {
        IptablesVariant::Legacy => true,
        IptablesVariant::Nft => {
            let family = match obs.target.version {
                IpVersion::V4 => Family::Ip,
                IpVersion::V6 => Family::Ip6,
            };
            nft.is_some_and(|v| {
                v.chains.iter().any(|c| {
                    c.chain.family == family && c.chain.table == "filter" && c.chain.chain == obs.hook.iptables_chain()
                })
            })
        }
    }
}

fn plan_iptables(
    obs: &IptablesObservation,
    ifname: &str,
    nft: Option<&NftView>,
    forward: ForwardWanted,
    live: &BTreeSet<String>,
    actions: &mut Vec<Action>,
) {
    let Some(lines) = &obs.tagged_lines else {
        return;
    };
    let wanted = if iptables_applies(obs, nft, forward) { Opening::wanted(obs.hook, forward) } else { Vec::new() };
    let mut kept: Vec<Opening> = Vec::new();
    for line in lines.iter().filter(|l| iptables_line_removable(l, ifname, live)) {
        match wanted.iter().copied().find(|o| !kept.contains(o) && *line == iptables_line(ifname, *o)) {
            Some(opening) => kept.push(opening),
            None => actions.push(Action::IptablesDelete {
                target: obs.target.clone(),
                line: line.clone(),
            }),
        }
    }
    for opening in wanted.into_iter().filter(|o| !kept.contains(o)) {
        actions.push(Action::IptablesInsert {
            target: obs.target.clone(),
            ifname: ifname.to_string(),
            opening,
        });
    }
}

fn iptables_line_removable(line: &str, ifname: &str, live: &BTreeSet<String>) -> bool {
    let tag = line_tag(line);
    removable(tag.as_deref().and_then(tag_owner), ifname, live)
}

fn guard_state(nft: Option<&NftView>, ifname: &str, forward: ForwardWanted) -> GuardState {
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
        Some(c) if c.hook.as_deref() == Some("forward") && is_guard_shape(&c.rules, ifname, forward) => {
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

/// `forward` (PLAN.md M23, M26) only ever changes the guard's own *shape*
/// (see `is_guard_shape`) — whether the guard exists at all is still
/// purely about firewalld's own state, same as before either existed.
fn plan_firewalld(observed: &Observed, ifname: &str, forward: ForwardWanted, actions: &mut Vec<Action>) {
    let guard = guard_state(observed.nft.as_ref(), ifname, forward);
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
            forward,
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
            Action::NftInsert { chain, ifname, opening } => {
                let view = out.nft.as_mut().unwrap();
                let c = view.chains.iter_mut().find(|c| &c.chain == chain).unwrap();
                next_handle += 1;
                let mut expr = opening_matches(ifname, *opening);
                expr.push(json!({"counter": {"packets": 0, "bytes": 0}}));
                expr.push(json!({"accept": null}));
                c.rules.insert(
                    0,
                    RuleInfo {
                        handle: next_handle,
                        comment: Some(tag(ifname)),
                        expr,
                    },
                );
            }
            Action::NftDelete { chain, handle } => {
                let view = out.nft.as_mut().unwrap();
                let c = view.chains.iter_mut().find(|c| &c.chain == chain).unwrap();
                c.rules.retain(|r| r.handle != *handle);
            }
            Action::IptablesInsert { target, ifname, opening } => {
                let o = out.iptables.iter_mut().find(|o| &o.target == target && o.hook == opening.hook()).unwrap();
                o.tagged_lines.as_mut().unwrap().insert(0, iptables_line(ifname, *opening));
            }
            Action::IptablesDelete { target, line } => {
                // Matched by which observation actually holds `line`, not
                // `target` alone: `target` no longer uniquely identifies an
                // observation now that INPUT and FORWARD each get their own.
                let o = out
                    .iptables
                    .iter_mut()
                    .find(|o| &o.target == target && o.tagged_lines.as_ref().is_some_and(|l| l.contains(line)))
                    .unwrap();
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
            Action::GuardCreate { ifname, forward } => {
                let table = guard_table(ifname);
                let view = out.nft.as_mut().unwrap();
                view.tables.retain(|t| t.name != table);
                view.chains.retain(|c| c.chain.table != table);
                view.tables.push(TableInfo {
                    family: Family::Inet,
                    name: table.clone(),
                    flags: vec![],
                });
                let mut rules = Vec::new();
                for mut expr in guard_exceptions(ifname, *forward) {
                    next_handle += 1;
                    expr.push(json!({"accept": null}));
                    rules.push(RuleInfo {
                        handle: next_handle,
                        comment: None,
                        expr,
                    });
                }
                next_handle += 1;
                rules.push(RuleInfo {
                    handle: next_handle,
                    comment: None,
                    expr: vec![iifname_match(ifname), json!({"drop": null})],
                });
                view.chains.push(ChainInfo {
                    chain: ChainRef {
                        family: Family::Inet,
                        table,
                        chain: GUARD_CHAIN.into(),
                    },
                    hook: Some("forward".into()),
                    chain_type: Some("filter".into()),
                    rules,
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
