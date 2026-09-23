//! Noticing that another tool changed the ruleset — `ufw reload`,
//! `firewall-cmd --reload`, `nft -f /etc/nftables.conf`, a crowdsec
//! bouncer or geoip-shell rebuilding its table — so our rules come back
//! within about a second instead of at the next poll.
//!
//! `nft -j monitor` streams one JSON object per change. Only table, chain
//! and rule changes outside our own tables matter; set and element churn
//! (crowdsec updates its blocklist sets constantly) is ignored. Events
//! arriving in a burst are debounced into one reconcile. The poll tick
//! remains the safety net for everything this can't see: legacy iptables
//! (not nftables at all), a monitor process that died, lost events.
//!
//! Ignored *without being read*, which is why [`is_relevant`] streams the
//! line rather than taking a `serde_json::Value` of it. One event is one
//! netlink message, and a bulk element add is one message: geoip-shell
//! loading a country set, or crowdsec reloading a blocklist, arrives as a
//! single line megabytes long. Turning one such line into a `Value` cost a
//! 143 MB peak here — to decide, from its second key, that the line is an
//! element event and none of our business. `host_interop::ruleset` has the
//! same shape for the same reason, and its module doc has the detail on why
//! that peak then stays resident.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::model::{is_own_table, Family};
use crate::firewall::nft::Nft;

/// Should this `nft -j monitor` line trigger a reconcile for `ifname`?
///
/// Changes outside our own tables, and deletions inside `ifname`'s own
/// deny table: a `flush ruleset` or `flush chain` shows up as exactly
/// those, and the reconcile is what restores the table (see the module
/// doc of `host_interop`). Our own per-poll replace deletes too, which
/// costs one reconcile that finds everything in place. Other agents'
/// tables stay ignored: reacting to each other's polls would have them
/// reconciling in response to one another.
#[must_use]
pub fn is_relevant(line: &str, ifname: &str) -> bool {
    let Ok(event) = serde_json::from_str::<Event>(line) else {
        return false;
    };
    let Some(object) = event.object else {
        return false; // sets, elements, flowtables, counters, …
    };
    if !object.family_ok {
        return false;
    }
    let our_deny_table_lost_something =
        event.deleted && object.table == crate::firewall::nftables::table_name(ifname);
    !is_own_table(&object.table) || our_deny_table_lost_something
}

/// One monitor line, in the three things the filter above looks at.
struct Event {
    deleted: bool,
    /// `None` for a change to an object kind we don't filter on.
    object: Option<ObjectRef>,
}

/// Which table a change was in, and whether its family is one we handle.
struct ObjectRef {
    family_ok: bool,
    table: String,
}

/// A table's own change names it in `name`; a chain's or a rule's names
/// its table in `table`. Every other field — a rule's `expr`, an element
/// event's `elem` — is skipped by serde as an unknown field, so none of it
/// is ever built.
#[derive(Deserialize)]
struct TableBody {
    family: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct ChainOrRuleBody {
    family: Option<String>,
    table: Option<String>,
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(EventVisitor)
    }
}

struct EventVisitor;

impl<'de> Visitor<'de> for EventVisitor {
    type Value = Event;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("an nft monitor event")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Event, A::Error> {
        let mut event = Event { deleted: false, object: None };
        let mut found = false;
        while let Some(key) = map.next_key::<String>()? {
            // `add` before `delete`, as reading the two keys in that order
            // always did; nft sends one or the other, never both.
            match key.as_str() {
                "add" | "delete" if !found => {
                    found = true;
                    event.deleted = key == "delete";
                    event.object = map.next_value_seed(Body)?;
                }
                _ => drop(map.next_value::<IgnoredAny>()?),
            }
        }
        Ok(event)
    }
}

/// The `{"<kind>": {…}}` an `add` or a `delete` carries.
struct Body;

impl<'de> DeserializeSeed<'de> for Body {
    type Value = Option<ObjectRef>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Body {
    type Value = Option<ObjectRef>;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("the object an nft monitor event changed")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut object = None;
        while let Some(kind) = map.next_key::<String>()? {
            match kind.as_str() {
                "table" if object.is_none() => {
                    let t: TableBody = map.next_value()?;
                    object = Some(ObjectRef {
                        family_ok: t.family.as_deref().and_then(Family::parse).is_some(),
                        table: t.name.unwrap_or_default(),
                    });
                }
                "chain" | "rule" if object.is_none() => {
                    let c: ChainOrRuleBody = map.next_value()?;
                    object = Some(ObjectRef {
                        family_ok: c.family.as_deref().and_then(Family::parse).is_some(),
                        table: c.table.unwrap_or_default(),
                    });
                }
                _ => drop(map.next_value::<IgnoredAny>()?),
            }
        }
        Ok(object)
    }
}

/// Collapses a burst of events into one action `delay` after the last.
#[derive(Debug)]
pub struct Debouncer {
    delay: Duration,
    deadline: Option<Instant>,
}

impl Debouncer {
    #[must_use]
    pub fn new(delay: Duration) -> Self {
        Self { delay, deadline: None }
    }

    pub fn event(&mut self, now: Instant) {
        self.deadline = Some(now + self.delay);
    }

    /// How long until something is due, if anything is pending.
    #[must_use]
    pub fn wait(&self, now: Instant) -> Option<Duration> {
        self.deadline.map(|d| d.saturating_duration_since(now))
    }

    /// True (once) when the pending action is due.
    pub fn take_due(&mut self, now: Instant) -> bool {
        match self.deadline {
            Some(d) if d <= now => {
                self.deadline = None;
                true
            }
            _ => false,
        }
    }
}

/// A running `nft -j monitor` child. Its reader thread forwards relevant
/// events as `on_event()` messages and sends `on_exit()` when the stream
/// ends; dropping this kills the child.
pub struct Monitor {
    child: Child,
}

impl Monitor {
    pub fn spawn<M: Send + 'static>(
        nft: &Nft,
        ifname: &str,
        tx: Sender<M>,
        on_event: fn() -> M,
        on_exit: fn() -> M,
    ) -> std::io::Result<Self> {
        let mut child = Command::new(nft.path())
            .args(["-j", "monitor"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdout = child.stdout.take().expect("stdout was piped");
        let ifname = ifname.to_string();
        std::thread::Builder::new()
            .name("nft-monitor".into())
            .spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    if is_relevant(&line, &ifname) && tx.send(on_event()).is_err() {
                        return;
                    }
                }
                let _ = tx.send(on_exit());
            })?;
        Ok(Self { child })
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Lines as printed by `nft -j monitor` (nftables 1.1.6).
    const FOREIGN_RULE_ADD: &str = r#"{"add": {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 2, "expr": [{"accept": null}]}}}"#;
    const FOREIGN_RULE_DEL: &str = r#"{"delete": {"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 2, "expr": []}}}"#;
    const FOREIGN_CHAIN_DEL: &str = r#"{"delete": {"chain": {"family": "inet", "table": "t", "name": "c", "handle": 1}}}"#;
    const FOREIGN_TABLE_ADD: &str = r#"{"add": {"table": {"family": "ip", "name": "filter", "handle": 2}}}"#;
    const SET_ADD: &str = r#"{"add": {"set": {"family": "ip", "name": "crowdsec-blacklists", "table": "crowdsec", "type": "ipv4_addr", "handle": 3}}}"#;
    const ELEMENT_ADD: &str = r#"{"add": {"element": {"family": "ip", "table": "crowdsec", "name": "crowdsec-blacklists", "elem": {"set": ["1.2.3.4"]}}}}"#;
    const OWN_TABLE_ADD: &str = r#"{"add": {"table": {"family": "inet", "name": "wireserve", "handle": 9}}}"#;
    const OWN_RULE_ADD: &str = r#"{"add": {"rule": {"family": "inet", "table": "wireserve", "chain": "wireserve-in", "handle": 3, "expr": []}}}"#;
    const GUARD_CHAIN_ADD: &str = r#"{"add": {"chain": {"family": "inet", "table": "wireserve-interop", "name": "forward-guard", "handle": 1}}}"#;
    const OTHER_AGENT_RULE_ADD: &str = r#"{"add": {"rule": {"family": "inet", "table": "wireserve.wireserve1", "chain": "wireserve-in", "handle": 3, "expr": []}}}"#;
    const OTHER_AGENT_GUARD_ADD: &str = r#"{"add": {"table": {"family": "inet", "name": "wireserve-interop.wireserve1", "handle": 4}}}"#;
    const LOOKALIKE_TABLE_ADD: &str = r#"{"add": {"table": {"family": "inet", "name": "wireservex", "handle": 5}}}"#;
    const BRIDGE_RULE: &str = r#"{"add": {"rule": {"family": "bridge", "table": "br", "chain": "input", "handle": 2, "expr": []}}}"#;

    /// One `nft -j monitor` line for a bulk element add — geoip-shell
    /// loading a country set, crowdsec reloading a blocklist. nft sends
    /// one netlink message for the batch, so this arrives as one line.
    fn bulk_element_event(elements: usize) -> String {
        use std::fmt::Write as _;
        let mut s = String::from(
            r#"{"add": {"element": {"family": "inet", "table": "geoip-shell", "name": "allow", "elem": ["#,
        );
        for i in 0..elements {
            if i > 0 {
                s.push(',');
            }
            let (a, b, c) = ((i >> 16) as u8, (i >> 8) as u8, i as u8);
            write!(s, r#"{{"prefix":{{"addr":"{a}.{b}.{c}.0","len":24}}}}"#).unwrap();
        }
        s.push_str("]}}}");
        s
    }

    /// The line this filter exists to throw away is the biggest one it
    /// will ever see, and deciding to throw it away must not depend on
    /// its size: the element array is skipped as the line is read, not
    /// built and dropped (module doc).
    #[test]
    fn a_bulk_element_event_costs_nothing_to_ignore() {
        let line = bulk_element_event(50_000);
        let mut relevant = true;
        let used = crate::test_alloc::allocated(|| relevant = is_relevant(&line, "wg0"));
        assert!(!relevant, "an element event is none of our business");
        assert!(
            used < line.len() / 100,
            "ignoring a {} KB element event allocated {} KB — the line is being materialised again",
            line.len() / 1024,
            used / 1024
        );
    }

    #[test]
    fn foreign_table_chain_and_rule_changes_are_relevant() {
        for line in [FOREIGN_RULE_ADD, FOREIGN_RULE_DEL, FOREIGN_CHAIN_DEL, FOREIGN_TABLE_ADD, LOOKALIKE_TABLE_ADD] {
            assert!(is_relevant(line, "wg0"), "{line}");
        }
    }

    #[test]
    fn set_churn_our_own_tables_and_other_families_are_ignored() {
        // Another agent's tables included: reacting to its every poll would
        // have two agents reconciling in response to each other forever.
        for line in [
            SET_ADD,
            ELEMENT_ADD,
            OWN_TABLE_ADD,
            OWN_RULE_ADD,
            GUARD_CHAIN_ADD,
            OTHER_AGENT_RULE_ADD,
            OTHER_AGENT_GUARD_ADD,
            BRIDGE_RULE,
        ] {
            assert!(!is_relevant(line, "wg0"), "{line}");
        }
    }

    #[test]
    fn a_deletion_in_our_own_deny_table_is_relevant_to_us_alone() {
        // What `flush ruleset` and `flush chain` look like to the monitor
        // (captured from nftables 1.1.6): our table losing its drop rule,
        // its chain, the table itself.
        let lost = [
            r#"{"delete": {"rule": {"family": "inet", "table": "wireserve.wg0", "chain": "wireserve-in", "handle": 2, "expr": [{"drop": null}]}}}"#,
            r#"{"delete": {"chain": {"family": "inet", "table": "wireserve.wg0", "name": "wireserve-in", "handle": 1}}}"#,
            r#"{"delete": {"table": {"family": "inet", "name": "wireserve.wg0", "handle": 1}}}"#,
        ];
        for line in lost {
            assert!(is_relevant(line, "wg0"), "{line}");
            assert!(!is_relevant(line, "wireserve1"), "another agent's table is not ours to restore: {line}");
        }
        let added = r#"{"add": {"table": {"family": "inet", "name": "wireserve.wg0", "handle": 1}}}"#;
        assert!(!is_relevant(added, "wg0"), "our own table being written is no news");
    }

    #[test]
    fn garbage_is_ignored() {
        for line in ["", "not json", "[]", r#"{"metainfo": {}}"#, r#"{"add": 5}"#] {
            assert!(!is_relevant(line, "wg0"), "{line:?}");
        }
    }

    #[test]
    fn debouncer_collapses_a_burst_into_one_action_after_the_last_event() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut d = Debouncer::new(ms(500));
        assert_eq!(d.wait(t0), None);
        assert!(!d.take_due(t0));

        for i in 0..10 {
            d.event(t0 + ms(i * 100)); // last event at +900ms
        }
        assert!(!d.take_due(t0 + ms(1300)), "not due until 500ms after the LAST event");
        assert_eq!(d.wait(t0 + ms(1300)), Some(ms(100)));
        assert!(d.take_due(t0 + ms(1400)));
        assert!(!d.take_due(t0 + ms(5000)), "fires once");
        assert_eq!(d.wait(t0 + ms(5000)), None);
    }

    #[test]
    fn kernel_monitor_reports_foreign_changes() {
        // Real `nft -j monitor` in a namespace: a foreign change produces a
        // relevant line, set churn and our own table do not.
        let script = "(timeout 2 nft -j monitor > mon.out &)\nsleep 0.3\n\
            nft add table inet wireserve\n\
            nft add table ip crowdsec\n\
            nft add set ip crowdsec s '{ type ipv4_addr; }'\n\
            nft add element ip crowdsec s '{ 1.2.3.4 }'\n\
            nft add table inet filter\n\
            nft add chain inet filter input '{ type filter hook input priority 0; }'\n\
            sleep 1\ncat mon.out";
        let dir = tempfile::tempdir().unwrap();
        let script = format!("cd {}\n{script}", dir.path().display());
        let Some(out) = crate::firewall::netns::run(&script) else {
            return;
        };
        let relevant: Vec<&str> = out.lines().filter(|l| is_relevant(l, "wg0")).collect();
        assert_eq!(relevant.len(), 3, "crowdsec table, filter table, filter chain:\n{out}");
        assert!(out.lines().any(|l| l.contains("\"element\"")), "monitor saw the set churn:\n{out}");
    }
}
