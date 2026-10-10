//! Ephemeral, in-process transit selection state (PLAN.md M23) — opt-in
//! single-hop routing through a third mesh member for a pair that can't
//! reach each other directly (symmetric NAT). See `routes::poll` for how
//! this gets read from and written to on every poll.
//!
//! **Deliberately not the database**, unlike `lan_addr`/`reflexive_addr`
//! (which each got a migration because they're durable identity facts
//! worth surviving a coordinator restart): every report here is refreshed
//! on a ≤20s cycle and meaningless once stale, the same shape as
//! `rate_limit::RateLimiter`'s own in-memory state, not a fact about a
//! node worth persisting.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use chrono::{DateTime, Utc};

struct NodeTransitReport {
    transit_capable: bool,
    /// Only meaningful when `transit_capable` is true.
    reachable: HashSet<String>,
    wanted: HashSet<String>,
    reported_at: DateTime<Utc>,
}

#[derive(Default)]
pub struct TransitState {
    by_pubkey: Mutex<HashMap<String, NodeTransitReport>>,
    /// When each node last offered to be an exit (PLAN.md M27, `exit on`),
    /// by pubkey. Kept apart from the transit report because nothing about
    /// selection reads it: only the export's eligibility check does.
    exit_offered_at: Mutex<HashMap<String, DateTime<Utc>>>,
    /// What each node last said it can do (`PollRequest::capabilities`),
    /// and when. Same lifetime and staleness rule as the rest of this.
    capabilities: Mutex<HashMap<String, CapabilityReport>>,
    /// Each node's carry interface port (PLAN.md M39), from its last poll.
    carry_ports: Mutex<HashMap<String, (u16, DateTime<Utc>)>>,
    /// Whether each node is dialable from outside (PLAN.md M40), as its
    /// agent last reported.
    dialable: Mutex<HashMap<String, (bool, DateTime<Utc>)>>,
    /// Port checks under way, by carrier pubkey (PLAN.md M40).
    port_checks: Mutex<HashMap<String, Vec<PendingCheck>>>,
}

/// One port check under way: the carrier listens on `port`, and the
/// coordinator sends `nonce` to it from outside.
#[derive(Debug, Clone)]
struct PendingCheck {
    port: u16,
    nonce: [u8; 8],
    /// The carrier has been told, in a poll response.
    picked_up: bool,
    seen: bool,
}

/// How a port check stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    /// The carrier hasn't polled since the check began.
    Waiting,
    /// It has, and is listening; nothing has arrived yet.
    Listening,
    /// The nonce arrived: the port is open.
    Seen,
}

/// One node's last capability report, and when it came.
type CapabilityReport = (HashSet<String>, DateTime<Utc>);

impl TransitState {
    /// Replaces this node's report wholesale — never merged, so a node
    /// that stops reporting a peer (it reconnected directly, or gave up
    /// on it) doesn't leave a stale fact behind that outlives its own
    /// truth.
    pub fn report(&self, pubkey: &str, transit_capable: bool, reachable: &[String], wanted: &[String]) {
        let mut by_pubkey = self.by_pubkey.lock().expect("transit state mutex poisoned");
        by_pubkey.insert(
            pubkey.to_string(),
            NodeTransitReport {
                transit_capable,
                reachable: reachable.iter().cloned().collect(),
                wanted: wanted.iter().cloned().collect(),
                reported_at: Utc::now(),
            },
        );
    }

    /// The pubkey of the node `a` and `c` should route through, or `None`
    /// if no such node currently qualifies. Pure function of the current
    /// snapshot: every entry that is `transit_capable`, reported within
    /// `fresh_secs`, is neither `a` nor `c`, and whose `reachable` set
    /// contains BOTH — sorted by pubkey ascending, first wins.
    /// Deterministic so that `a`'s poll and `c`'s poll, landing on
    /// whatever cycle each happens to, independently converge on the same
    /// answer with no coordination between them.
    #[must_use]
    pub fn select(&self, a: &str, c: &str, fresh_secs: i64) -> Option<String> {
        self.select_where(a, c, fresh_secs, &|_| true)
    }

    /// [`Self::select`] among the carriers `eligible` accepts — for a relay
    /// (PLAN.md M39), only those that can relay end to end.
    #[must_use]
    pub fn select_where(&self, a: &str, c: &str, fresh_secs: i64, eligible: &dyn Fn(&str) -> bool) -> Option<String> {
        let by_pubkey = self.by_pubkey.lock().expect("transit state mutex poisoned");
        let now = Utc::now();
        let mut candidates: Vec<&String> = by_pubkey
            .iter()
            .filter(|(pubkey, report)| {
                pubkey.as_str() != a
                    && pubkey.as_str() != c
                    && report.transit_capable
                    && (now - report.reported_at).num_seconds() < fresh_secs
                    && report.reachable.contains(a)
                    && report.reachable.contains(c)
                    && eligible(pubkey)
            })
            .map(|(pubkey, _)| pubkey)
            .collect();
        candidates.sort_unstable();
        candidates.into_iter().next().cloned()
    }

    /// True if either `a`'s or `c`'s own last report names the other in
    /// `wanted` — checked from each side's independently-stored report,
    /// not just one side, so the first side to give up drives both
    /// directions to a `transit_via` on their own very next poll, rather
    /// than requiring both sides to time out in the same window.
    #[must_use]
    pub fn either_wants(&self, a: &str, c: &str) -> bool {
        let by_pubkey = self.by_pubkey.lock().expect("transit state mutex poisoned");
        let wants = |x: &str, y: &str| by_pubkey.get(x).is_some_and(|r| r.wanted.contains(y));
        wants(a, c) || wants(c, a)
    }

    /// Every `(x, y)` some node's last report names in its `wanted` set, in
    /// one pass under one hold. [`Self::either_wants`] is false for any other
    /// pair, so these are the only pairs a relay can ever be chosen for —
    /// what `/poll` walks instead of every pair of nodes in the mesh.
    /// Unordered, may name the same two nodes both ways, and may name nodes
    /// no longer in the directory.
    #[must_use]
    pub fn wanted_pairs(&self) -> Vec<(String, String)> {
        let by_pubkey = self.by_pubkey.lock().expect("transit state mutex poisoned");
        by_pubkey
            .iter()
            .flat_map(|(x, report)| report.wanted.iter().map(move |y| (x.clone(), y.clone())))
            .collect()
    }

    /// Stops a node being selected as a carrier from this moment, keeping
    /// the rest of its report (what it wants) — for an admin withdrawing
    /// its transit approval, which should not wait for the node's next
    /// poll to take effect.
    pub fn withdraw_carrier(&self, pubkey: &str) {
        let mut by_pubkey = self.by_pubkey.lock().expect("transit state mutex poisoned");
        if let Some(report) = by_pubkey.get_mut(pubkey) {
            report.transit_capable = false;
            report.reachable.clear();
        }
    }

    /// Whether this node is *currently* offering to carry traffic, from its
    /// own most recent poll (PLAN.md M24).
    ///
    /// Distinct from the admin approval stored on the node row, and both are
    /// needed: approval is the mesh admin's trust, this is whether the daemon
    /// is actually set up to forward. The agent captures its own
    /// `transit_capable` once at start and opens the *host* firewall's
    /// FORWARD hook from it, so a node that was approved but never ran
    /// `wireserve transit on` accepts the forward in its own table
    /// while ufw or firewalld still drops it — silently, and painfully hard
    /// to debug from the other end.
    #[must_use]
    pub fn is_offering(&self, pubkey: &str, fresh_secs: i64) -> bool {
        let now = chrono::Utc::now();
        self.by_pubkey.lock().is_ok_and(|m| {
            m.get(pubkey).is_some_and(|r| {
                r.transit_capable && (now - r.reported_at).num_seconds() <= fresh_secs
            })
        })
    }

    /// Records this poll's exit opt-in (PLAN.md M27). Replaced every poll,
    /// like [`Self::report`], so switching it off takes effect at once.
    pub fn report_exit(&self, pubkey: &str, exit_capable: bool) {
        let mut offered = self.exit_offered_at.lock().expect("transit state mutex poisoned");
        if exit_capable {
            offered.insert(pubkey.to_string(), Utc::now());
        } else {
            offered.remove(pubkey);
        }
    }

    /// Whether this node's own most recent poll offered to be an exit —
    /// the node's half of the consent, checked before an export bakes it
    /// into a device's full-tunnel profile.
    #[must_use]
    pub fn is_offering_exit(&self, pubkey: &str, fresh_secs: i64) -> bool {
        let now = Utc::now();
        self.exit_offered_at
            .lock()
            .is_ok_and(|m| m.get(pubkey).is_some_and(|at| (now - *at).num_seconds() <= fresh_secs))
    }

    /// Records this poll's capabilities, replacing the last ones.
    pub fn report_capabilities(&self, pubkey: &str, capabilities: &[String]) {
        self.capabilities.lock().expect("transit state mutex poisoned").insert(
            pubkey.to_string(),
            (capabilities.iter().cloned().collect(), Utc::now()),
        );
    }

    /// Whether this node's own most recent poll, no older than
    /// `fresh_secs`, said it can do `capability`. A node that has not
    /// polled since the coordinator started does not count: an admin action
    /// gated on this waits one poll rather than trusting nothing.
    #[must_use]
    pub fn has_capability(&self, pubkey: &str, capability: &str, fresh_secs: i64) -> bool {
        let now = Utc::now();
        self.capabilities.lock().is_ok_and(|m| {
            m.get(pubkey)
                .is_some_and(|(caps, at)| caps.contains(capability) && (now - *at).num_seconds() <= fresh_secs)
        })
    }

    /// Records this poll's carry port, or its absence.
    pub fn report_carry_port(&self, pubkey: &str, port: Option<u16>) {
        let mut ports = self.carry_ports.lock().expect("transit state mutex poisoned");
        match port.filter(|p| *p != 0) {
            Some(p) => ports.insert(pubkey.to_string(), (p, Utc::now())),
            None => ports.remove(pubkey),
        };
    }

    /// The carry port this node last reported, if it can be relayed to: it
    /// said so in a poll no older than `fresh_secs`.
    #[must_use]
    pub fn carry_port(&self, pubkey: &str, fresh_secs: i64) -> Option<u16> {
        if !self.has_capability(pubkey, wireserve_types::CAP_RELAY, fresh_secs) {
            return None;
        }
        let now = Utc::now();
        self.carry_ports
            .lock()
            .ok()?
            .get(pubkey)
            .filter(|(_, at)| (now - *at).num_seconds() <= fresh_secs)
            .map(|(p, _)| *p)
    }

    /// The nodes whose own most recent poll, no older than `fresh_secs`, said
    /// they can do `capability` — [`Self::has_capability`] for every node
    /// at once, one hold of the mutex.
    #[must_use]
    pub fn with_capability(&self, capability: &str, fresh_secs: i64) -> HashSet<String> {
        let now = Utc::now();
        let caps = self.capabilities.lock().expect("transit state mutex poisoned");
        caps.iter()
            .filter(|(_, (c, at))| c.contains(capability) && (now - *at).num_seconds() <= fresh_secs)
            .map(|(pk, _)| pk.clone())
            .collect()
    }

    /// [`Self::carry_port`] for every node at once: one hold of each mutex
    /// instead of two per node, for the directory snapshot.
    #[must_use]
    pub fn carry_ports(&self, fresh_secs: i64) -> HashMap<String, u16> {
        let now = Utc::now();
        let caps = self.capabilities.lock().expect("transit state mutex poisoned");
        let ports = self.carry_ports.lock().expect("transit state mutex poisoned");
        ports
            .iter()
            .filter(|(pk, (_, at))| {
                (now - *at).num_seconds() <= fresh_secs
                    && caps.get(pk.as_str()).is_some_and(|(c, cat)| {
                        c.contains(wireserve_types::CAP_RELAY) && (now - *cat).num_seconds() <= fresh_secs
                    })
            })
            .map(|(pk, (port, _))| (pk.clone(), *port))
            .collect()
    }

    /// Records whether this node found itself dialable, if it could tell.
    pub fn report_dialable(&self, pubkey: &str, dialable: Option<bool>) {
        let mut map = self.dialable.lock().expect("transit state mutex poisoned");
        match dialable {
            Some(d) => map.insert(pubkey.to_string(), (d, Utc::now())),
            None => map.remove(pubkey),
        };
    }

    /// Whether this node is dialable from outside, as it said in a poll no
    /// older than `fresh_secs`; `None` when it hasn't said.
    #[must_use]
    pub fn dialable(&self, pubkey: &str, fresh_secs: i64) -> Option<bool> {
        let now = Utc::now();
        self.dialable
            .lock()
            .ok()?
            .get(pubkey)
            .filter(|(_, at)| (now - *at).num_seconds() <= fresh_secs)
            .map(|(d, _)| *d)
    }

    /// Whether `carrier`'s last report, no older than `fresh_secs`, says it
    /// reaches `peer` right now — the ground truth a relay needs.
    #[must_use]
    pub fn reaches(&self, carrier: &str, peer: &str, fresh_secs: i64) -> bool {
        let now = Utc::now();
        self.by_pubkey.lock().is_ok_and(|m| {
            m.get(carrier).is_some_and(|r| {
                r.transit_capable && r.reachable.contains(peer) && (now - r.reported_at).num_seconds() < fresh_secs
            })
        })
    }

    /// Starts a check of `carrier`'s `port`, unless one is under way; the
    /// nonce to send it.
    pub fn start_check(&self, carrier: &str, port: u16) -> [u8; 8] {
        let mut checks = self.port_checks.lock().expect("transit state mutex poisoned");
        let list = checks.entry(carrier.to_string()).or_default();
        if let Some(c) = list.iter().find(|c| c.port == port) {
            return c.nonce;
        }
        let nonce: [u8; 8] = rand::random();
        list.push(PendingCheck { port, nonce, picked_up: false, seen: false });
        nonce
    }

    /// The checks `carrier` should run, for its poll response. Marks them
    /// picked up.
    pub fn checks_for(&self, carrier: &str) -> Vec<wireserve_types::PortCheck> {
        let mut checks = self.port_checks.lock().expect("transit state mutex poisoned");
        let Some(list) = checks.get_mut(carrier) else {
            return Vec::new();
        };
        list.iter_mut()
            .filter(|c| !c.seen)
            .map(|c| {
                c.picked_up = true;
                wireserve_types::PortCheck { port: c.port, nonce: hex(&c.nonce) }
            })
            .collect()
    }

    /// Records the nonces `carrier` says it received. Only a nonce this
    /// coordinator sent to that port counts.
    pub fn record_seen(&self, carrier: &str, seen: &[wireserve_types::PortCheck]) {
        let mut checks = self.port_checks.lock().expect("transit state mutex poisoned");
        let Some(list) = checks.get_mut(carrier) else {
            return;
        };
        for c in list.iter_mut() {
            if seen.iter().any(|s| s.port == c.port && s.nonce == hex(&c.nonce)) {
                c.seen = true;
            }
        }
    }

    /// How the check of `carrier`'s `port` stands; `None` when there is none.
    #[must_use]
    pub fn check_state(&self, carrier: &str, port: u16) -> Option<CheckState> {
        let checks = self.port_checks.lock().ok()?;
        let c = checks.get(carrier)?.iter().find(|c| c.port == port)?;
        Some(if c.seen {
            CheckState::Seen
        } else if c.picked_up {
            CheckState::Listening
        } else {
            CheckState::Waiting
        })
    }

    /// Ends the check of `carrier`'s `port`.
    pub fn finish_check(&self, carrier: &str, port: u16) {
        let mut checks = self.port_checks.lock().expect("transit state mutex poisoned");
        if let Some(list) = checks.get_mut(carrier) {
            list.retain(|c| c.port != port);
            if list.is_empty() {
                checks.remove(carrier);
            }
        }
    }

    /// Drops a node's report — on revoke and rejoin, so it can never be
    /// selected as transit and never shows up as wanting anything
    /// afterward.
    pub fn forget(&self, pubkey: &str) {
        let mut by_pubkey = self.by_pubkey.lock().expect("transit state mutex poisoned");
        by_pubkey.remove(pubkey);
        drop(by_pubkey);
        self.exit_offered_at.lock().expect("transit state mutex poisoned").remove(pubkey);
        self.capabilities.lock().expect("transit state mutex poisoned").remove(pubkey);
        self.carry_ports.lock().expect("transit state mutex poisoned").remove(pubkey);
        self.dialable.lock().expect("transit state mutex poisoned").remove(pubkey);
        self.port_checks.lock().expect("transit state mutex poisoned").remove(pubkey);
    }
}

/// A nonce as the wire carries it: 16 lowercase hex digits.
#[must_use]
pub fn hex(nonce: &[u8; 8]) -> String {
    nonce.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_exit_offer_holds_until_withdrawn_or_forgotten() {
        let s = TransitState::default();
        assert!(!s.is_offering_exit("b", 30));
        s.report_exit("b", true);
        assert!(s.is_offering_exit("b", 30));
        assert!(!s.is_offering_exit("b", -1), "a stale offer counts for nothing");
        s.report_exit("b", false);
        assert!(!s.is_offering_exit("b", 30));
        s.report_exit("b", true);
        s.forget("b");
        assert!(!s.is_offering_exit("b", 30));
    }

    #[test]
    fn select_picks_a_capable_fresh_node_reaching_both() {
        let s = TransitState::default();
        s.report("b", true, &["a".into(), "c".into()], &[]);
        assert_eq!(s.select("a", "c", 30).as_deref(), Some("b"));
    }

    #[test]
    fn select_ignores_a_stale_report() {
        let s = TransitState::default();
        let mut by_pubkey = s.by_pubkey.lock().unwrap();
        by_pubkey.insert(
            "b".into(),
            NodeTransitReport {
                transit_capable: true,
                reachable: ["a".into(), "c".into()].into_iter().collect(),
                wanted: HashSet::new(),
                reported_at: Utc::now() - chrono::Duration::seconds(60),
            },
        );
        drop(by_pubkey);
        assert_eq!(s.select("a", "c", 30), None);
    }

    #[test]
    fn select_ignores_a_non_capable_node_even_if_it_reports_reaching_both() {
        let s = TransitState::default();
        s.report("b", false, &["a".into(), "c".into()], &[]);
        assert_eq!(s.select("a", "c", 30), None);
    }

    #[test]
    fn select_never_returns_either_endpoint_itself() {
        let s = TransitState::default();
        // A stale/adversarial report naming itself as reaching both.
        s.report("a", true, &["a".into(), "c".into()], &[]);
        assert_eq!(s.select("a", "c", 30), None);
    }

    #[test]
    fn select_tie_breaks_deterministically_by_pubkey() {
        let s = TransitState::default();
        s.report("bbb", true, &["a".into(), "c".into()], &[]);
        s.report("aaa", true, &["a".into(), "c".into()], &[]);
        assert_eq!(s.select("a", "c", 30).as_deref(), Some("aaa"));
    }

    #[test]
    fn select_requires_reaching_both_not_just_one() {
        let s = TransitState::default();
        s.report("b", true, &["a".into()], &[]);
        assert_eq!(s.select("a", "c", 30), None);
    }

    #[test]
    fn either_wants_true_when_only_one_side_reported() {
        let s = TransitState::default();
        s.report("a", false, &[], &["c".into()]);
        assert!(TransitState::either_wants(&s, "a", "c"));
        assert!(TransitState::either_wants(&s, "c", "a"));
    }

    #[test]
    fn either_wants_false_when_neither_side_reported_wanting() {
        let s = TransitState::default();
        s.report("a", false, &[], &[]);
        s.report("c", false, &[], &[]);
        assert!(!s.either_wants("a", "c"));
    }

    #[test]
    fn report_replaces_wholesale_never_merges_stale_data() {
        let s = TransitState::default();
        s.report("b", true, &["a".into(), "c".into()], &[]);
        s.report("b", true, &["a".into()], &[]);
        assert_eq!(s.select("a", "c", 30), None);
    }

    #[test]
    fn withdraw_carrier_stops_selection_but_keeps_what_the_node_wants() {
        let s = TransitState::default();
        s.report("b", true, &["a".into(), "c".into()], &["x".into()]);
        s.withdraw_carrier("b");
        assert_eq!(s.select("a", "c", 30), None);
        assert!(s.either_wants("b", "x"));
    }

    #[test]
    fn forget_removes_a_revoked_node_from_consideration() {
        let s = TransitState::default();
        s.report("b", true, &["a".into(), "c".into()], &["x".into()]);
        s.forget("b");
        assert_eq!(s.select("a", "c", 30), None);
        assert!(!s.either_wants("b", "x"));
    }

    #[test]
    fn wanted_pairs_cover_exactly_the_pairs_either_wants_accepts() {
        let s = TransitState::default();
        let names = ["a", "b", "c", "d", "e", "f"];
        // A small mesh where each node wants a few others, some both ways.
        let wants: [(&str, &[&str]); 4] = [("a", &["b", "c"]), ("b", &["a"]), ("d", &["e"]), ("f", &[])];
        for (who, list) in wants {
            let list: Vec<String> = list.iter().map(|n| (*n).to_string()).collect();
            s.report(who, false, &[], &list);
        }
        let pairs = s.wanted_pairs();
        for x in names {
            for y in names {
                let listed = pairs.iter().any(|(p, q)| (p == x && q == y) || (p == y && q == x));
                assert_eq!(listed, s.either_wants(x, y), "{x} {y}");
            }
        }
    }
}
