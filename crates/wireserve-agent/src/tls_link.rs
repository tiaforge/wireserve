//! What the agent knows about this node's TLS terminator (PLAN.md M33):
//! when it last checked in, and which services it said it serves.
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
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a name stays reported after the terminator last named it.
pub const LATCH: Duration = Duration::from_secs(180);
/// How recent the last check-in must be for the firewall to rely on it.
pub const ALIVE: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct TlsLink {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    last_checkin: Option<Instant>,
    serving: BTreeSet<String>,
    /// Name → when the terminator last said it serves it.
    seen: BTreeMap<String, Instant>,
}

impl TlsLink {
    /// Records a check-in: the terminator serves exactly `serving` now.
    pub fn check_in(&self, serving: BTreeSet<String>, now: Instant) {
        let mut inner = self.lock();
        for name in &serving {
            inner.seen.insert(name.clone(), now);
        }
        inner.seen.retain(|_, at| now.saturating_duration_since(*at) < LATCH);
        inner.serving = serving;
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

    #[test]
    fn nothing_before_the_first_check_in() {
        let link = TlsLink::default();
        let now = Instant::now();
        assert!(!link.present(now));
        assert!(link.serving(now).is_empty());
        assert!(link.reported(now).is_empty());
    }

    #[test]
    fn the_firewall_follows_the_terminator_and_the_report_is_latched() {
        let link = TlsLink::default();
        let t0 = Instant::now();
        link.check_in(set(&["plex", "git"]), t0);
        assert_eq!(link.serving(t0), set(&["plex", "git"]));

        // The terminator drops git: the firewall stops at once, the report
        // keeps it until the latch runs out.
        let t1 = t0 + Duration::from_secs(5);
        link.check_in(set(&["plex"]), t1);
        assert_eq!(link.serving(t1), set(&["plex"]));
        assert_eq!(link.reported(t1), vec!["git".to_string(), "plex".to_string()]);

        // The terminator goes quiet: the firewall stops relying on it, the
        // report still holds — a restart must not move public DNS.
        let quiet = t1 + ALIVE;
        assert!(link.serving(quiet).is_empty());
        assert_eq!(link.reported(quiet).len(), 2);
        assert!(link.present(quiet));

        let gone = t1 + LATCH;
        assert!(link.reported(gone).is_empty());
        assert!(!link.present(gone));
    }
}
