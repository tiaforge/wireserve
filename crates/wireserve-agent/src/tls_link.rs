//! What the agent knows about this node's TLS terminator (PLAN.md M33):
//! when it last checked in, which services it said it serves, and on which
//! port it listens (PLAN.md M35).
//!
//! Two readings of the same check-ins, for two different jobs:
//! * [`TlsLink::serving`] is what the firewall acts on: only while the
//!   terminator checked in recently, and exactly what it said then. A
//!   terminator that stopped is not trusted to answer on a service address.
//! * [`TlsLink::reported`] is what the coordinator is told, and is latched:
//!   a name stays reported for [`LATCH`] after the terminator last named it.
//!   The coordinator moves public DNS on this report, and a terminator
//!   restarting — every agent upgrade restarts it — must not swing every
//!   name to the proxy and back through resolver caches.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a name stays reported after the terminator last named it.
pub const LATCH: Duration = Duration::from_secs(180);
/// How recent the last check-in must be for the firewall to rely on it.
pub const ALIVE: Duration = Duration::from_secs(30);
/// How long a device stays reported after it last connected: the coordinator
/// names its owner to this node for that long.
pub const CALLER_TTL: Duration = Duration::from_secs(24 * 3600);
/// Devices remembered at once; a mesh has far fewer.
const MAX_CALLERS: usize = 1024;

#[derive(Default)]
pub struct TlsLink {
    inner: Mutex<Inner>,
    /// Woken when a device connects that was not reported before, so the
    /// poll loop asks the coordinator for its owner now rather than at the
    /// next cycle.
    pub wake: tokio::sync::Notify,
}

#[derive(Default)]
struct Inner {
    last_checkin: Option<Instant>,
    serving: BTreeSet<String>,
    port: u16,
    /// Name → when the terminator last said it serves it.
    seen: BTreeMap<String, Instant>,
    /// Device → when it last connected to the terminator.
    callers: BTreeMap<Ipv4Addr, Instant>,
}

impl TlsLink {
    /// Records a check-in: the terminator serves exactly `serving` now, on
    /// `port`.
    /// `callers` are the known devices that connected since its last one.
    pub fn check_in(&self, serving: BTreeSet<String>, port: u16, callers: &[Ipv4Addr], now: Instant) {
        let mut inner = self.lock();
        let mut fresh = false;
        for addr in callers.iter().take(wireserve_types::MAX_CALLERS_SEEN_PER_POLL) {
            if !inner.callers.get(addr).is_some_and(|at| now.saturating_duration_since(*at) < CALLER_TTL) {
                fresh = true;
            }
            inner.callers.insert(*addr, now);
        }
        inner.callers.retain(|_, at| now.saturating_duration_since(*at) < CALLER_TTL);
        while inner.callers.len() > MAX_CALLERS {
            let Some(oldest) = inner.callers.iter().min_by_key(|(_, at)| **at).map(|(a, _)| *a) else { break };
            inner.callers.remove(&oldest);
        }
        if fresh {
            self.wake.notify_one();
        }
        for name in &serving {
            inner.seen.insert(name.clone(), now);
        }
        inner.seen.retain(|_, at| now.saturating_duration_since(*at) < LATCH);
        inner.serving = serving;
        inner.port = port;
        inner.last_checkin = Some(now);
    }

    /// Whether a terminator has checked in within [`LATCH`] — the agent
    /// then reports the capability.
    #[must_use]
    pub fn present(&self, now: Instant) -> bool {
        self.lock().last_checkin.is_some_and(|t| now.saturating_duration_since(t) < LATCH)
    }

    /// What the firewall may hand to the terminator this cycle.
    #[must_use]
    pub fn serving(&self, now: Instant) -> BTreeSet<String> {
        let inner = self.lock();
        match inner.last_checkin {
            Some(t) if now.saturating_duration_since(t) < ALIVE => inner.serving.clone(),
            _ => BTreeSet::new(),
        }
    }

    /// The port [`Self::serving`] is served on, under the same condition:
    /// where the firewall rewrites those services' 443 to.
    #[must_use]
    pub fn port(&self, now: Instant) -> Option<u16> {
        let inner = self.lock();
        match inner.last_checkin {
            Some(t) if now.saturating_duration_since(t) < ALIVE => Some(inner.port),
            _ => None,
        }
    }

    /// The devices that connected within [`CALLER_TTL`], most recent first:
    /// what the coordinator is told, and so whose owners it names here.
    #[must_use]
    pub fn callers_seen(&self, now: Instant) -> Vec<Ipv4Addr> {
        let inner = self.lock();
        let mut all: Vec<(Ipv4Addr, Instant)> = inner
            .callers
            .iter()
            .filter(|(_, at)| now.saturating_duration_since(**at) < CALLER_TTL)
            .map(|(a, at)| (*a, *at))
            .collect();
        all.sort_by(|a, b| b.1.cmp(&a.1));
        all.into_iter().map(|(a, _)| a).take(wireserve_types::MAX_CALLERS_SEEN_PER_POLL).collect()
    }

    /// What the coordinator is told, latched (see the module doc).
    #[must_use]
    pub fn reported(&self, now: Instant) -> Vec<String> {
        self.lock()
            .seen
            .iter()
            .filter(|(_, at)| now.saturating_duration_since(**at) < LATCH)
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn devices_are_reported_most_recent_first_and_for_a_day() {
        let link = TlsLink::default();
        let t0 = Instant::now();
        assert!(link.callers_seen(t0).is_empty());
        link.check_in(set(&[]), 11443, &[ip("10.9.0.3")], t0);
        let t1 = t0 + Duration::from_secs(60);
        link.check_in(set(&[]), 11443, &[ip("10.9.0.4")], t1);
        assert_eq!(link.callers_seen(t1), vec![ip("10.9.0.4"), ip("10.9.0.3")]);

        // Seen again, it moves to the front and lives another day.
        let t2 = t1 + Duration::from_secs(60);
        link.check_in(set(&[]), 11443, &[ip("10.9.0.3")], t2);
        assert_eq!(link.callers_seen(t2), vec![ip("10.9.0.3"), ip("10.9.0.4")]);

        let later = t2 + CALLER_TTL - Duration::from_secs(1);
        assert_eq!(link.callers_seen(later), vec![ip("10.9.0.3")], ".4 has been quiet a day");
        assert!(link.callers_seen(t2 + CALLER_TTL).is_empty());
    }

    async fn woken(link: &TlsLink) -> bool {
        tokio::time::timeout(Duration::from_millis(50), link.wake.notified()).await.is_ok()
    }

    #[tokio::test]
    async fn only_a_device_not_reported_before_wakes_the_poll_loop() {
        let link = TlsLink::default();
        let t0 = Instant::now();
        link.check_in(set(&[]), 11443, &[], t0);
        assert!(!woken(&link).await, "nobody came");
        link.check_in(set(&[]), 11443, &[ip("10.9.0.3")], t0);
        assert!(woken(&link).await, "a new device");
        link.check_in(set(&[]), 11443, &[ip("10.9.0.3")], t0 + Duration::from_secs(5));
        assert!(!woken(&link).await, "the same one again");
        link.check_in(set(&[]), 11443, &[ip("10.9.0.3")], t0 + Duration::from_secs(5) + CALLER_TTL + Duration::from_secs(1));
        assert!(woken(&link).await, "after a day it is new again");
    }

    #[test]
    fn nothing_before_the_first_check_in() {
        let link = TlsLink::default();
        let now = Instant::now();
        assert!(!link.present(now));
        assert!(link.serving(now).is_empty());
        assert_eq!(link.port(now), None);
        assert!(link.reported(now).is_empty());
    }

    #[test]
    fn the_firewall_follows_the_terminator_and_the_report_is_latched() {
        let link = TlsLink::default();
        let t0 = Instant::now();
        link.check_in(set(&["plex", "git"]), 11443, &[], t0);
        assert_eq!(link.serving(t0), set(&["plex", "git"]));

        // The terminator drops git: the firewall stops at once, the report
        // keeps it until the latch runs out.
        let t1 = t0 + Duration::from_secs(5);
        link.check_in(set(&["plex"]), 12443, &[], t1);
        assert_eq!(link.serving(t1), set(&["plex"]));
        assert_eq!(link.port(t1), Some(12443), "the latest port, as it is now");
        assert_eq!(link.reported(t1), vec!["git".to_string(), "plex".to_string()]);

        // The terminator goes quiet: the firewall stops relying on it, the
        // report still holds — a restart must not move public DNS.
        let quiet = t1 + ALIVE;
        assert!(link.serving(quiet).is_empty());
        assert_eq!(link.port(quiet), None);
        assert_eq!(link.reported(quiet).len(), 2);
        assert!(link.present(quiet));

        let gone = t1 + LATCH;
        assert!(link.reported(gone).is_empty());
        assert!(!link.present(gone));
    }
}
