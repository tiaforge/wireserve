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
}

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
    /// `wireserve-agent transit on` accepts the forward in its own table
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

    /// Drops a node's report — on revoke and rejoin, so it can never be
    /// selected as transit and never shows up as wanting anything
    /// afterward.
    pub fn forget(&self, pubkey: &str) {
        let mut by_pubkey = self.by_pubkey.lock().expect("transit state mutex poisoned");
        by_pubkey.remove(pubkey);
        drop(by_pubkey);
        self.exit_offered_at.lock().expect("transit state mutex poisoned").remove(pubkey);
    }
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
}
