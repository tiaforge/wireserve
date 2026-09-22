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

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use serde_json::Value;

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
    let Ok(Value::Object(event)) = serde_json::from_str::<Value>(line) else {
        return false;
    };
    let Some(Value::Object(body)) = event.get("add").or_else(|| event.get("delete")) else {
        return false;
    };
    let (object, table_key) = if let Some(o) = body.get("table") {
        (o, "name")
    } else if let Some(o) = body.get("chain") {
        (o, "table")
    } else if let Some(o) = body.get("rule") {
        (o, "table")
    } else {
        return false; // sets, elements, flowtables, counters, …
    };
    let family_ok = object
        .get("family")
        .and_then(Value::as_str)
        .and_then(Family::parse)
        .is_some();
    let table = object.get(table_key).and_then(Value::as_str).unwrap_or_default();
    let our_deny_table_lost_something =
        event.get("delete").is_some() && table == crate::firewall::nftables::table_name(ifname);
    family_ok && (!is_own_table(table) || our_deny_table_lost_something)
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
