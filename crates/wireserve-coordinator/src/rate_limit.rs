//! Hand-rolled in-process sliding-window rate limiter keyed by source IP
//! (PLAN.md decisions log #7 — no external dependency). Applied to
//! `/register` unconditionally and, from every route handler that can
//! reject a request for bad auth, recorded as a "hit" so repeated failed
//! auth attempts also trip it (spec §7: "basic rate limiting on /register
//! and on failed-auth responses from any endpoint").

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    max: u32,
    window: Duration,
    hits: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl RateLimiter {
    pub fn new(max: u32, window_secs: u64) -> Self {
        Self {
            max,
            window: Duration::from_secs(window_secs),
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `ip` has already exhausted its failed-attempt budget for the
    /// current window — a pure check, records nothing. Callers check this
    /// *before* doing any auth-comparison work, so a blocked IP is turned
    /// away without spending a hash/DB-lookup on a request that was never
    /// going to be allowed anyway (a real, if minor, resource-exhaustion
    /// consideration security review flagged: checking only after the
    /// comparison already happened meant the limiter changed the response
    /// code but not the per-request cost).
    ///
    /// Read-only in the strict sense (security review G5): this runs on
    /// *every* request, successful ones included, so it must never insert
    /// a map entry — otherwise every distinct source address ever seen
    /// would occupy memory forever.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        hits.get(&ip).is_some_and(|entry| {
            let live = entry
                .iter()
                .filter(|t| now.duration_since(**t) < self.window)
                .count();
            live as u32 >= self.max
        })
    }

    /// Records one failed attempt from `ip` — call only on an actual auth
    /// failure (never on success), so legitimate traffic never eats into
    /// the budget. This is also where the table is pruned: every expired
    /// timestamp and every address left with none is dropped, so the map
    /// is bounded by (sources with a live failure in the window × `max`).
    /// Failures are rare relative to requests, so the sweep is cheap.
    pub fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        hits.retain(|_, entry| {
            entry.retain(|t| now.duration_since(*t) < self.window);
            !entry.is_empty()
        });
        hits.entry(ip).or_default().push(now);
    }

    /// Number of source addresses currently tracked — exposed for tests
    /// that pin down the no-growth guarantee above.
    pub fn tracked_sources(&self) -> usize {
        self.hits.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn allows_up_to_max_failures_then_blocks() {
        let rl = RateLimiter::new(3, 60);
        let a = ip("10.0.0.1");
        for _ in 0..3 {
            assert!(!rl.is_blocked(a));
            rl.record_failure(a);
        }
        assert!(rl.is_blocked(a), "4th attempt within window must be blocked");
    }

    #[test]
    fn is_keyed_per_ip() {
        let rl = RateLimiter::new(1, 60);
        let (a, b) = (ip("10.0.0.1"), ip("10.0.0.2"));
        rl.record_failure(a);
        assert!(rl.is_blocked(a));
        assert!(!rl.is_blocked(b), "a different source IP must not be affected");
    }

    #[test]
    fn resets_after_window_elapses() {
        // window of 0s: every recorded failure is immediately stale.
        let rl = RateLimiter::new(1, 0);
        let a = ip("10.0.0.1");
        rl.record_failure(a);
        assert!(!rl.is_blocked(a));
    }

    #[test]
    fn is_blocked_never_inserts_an_entry() {
        let rl = RateLimiter::new(1, 60);
        for n in 0..100u8 {
            assert!(!rl.is_blocked(ip(&format!("203.0.113.{n}"))));
        }
        assert_eq!(rl.tracked_sources(), 0, "checking must not allocate per source");
    }

    #[test]
    fn record_failure_prunes_expired_sources() {
        let rl = RateLimiter::new(5, 0);
        rl.record_failure(ip("10.0.0.1"));
        rl.record_failure(ip("10.0.0.2"));
        // With a 0s window both earlier entries are expired by the time
        // the next failure sweeps the table; only the newest survives.
        rl.record_failure(ip("10.0.0.3"));
        assert_eq!(rl.tracked_sources(), 1);
    }
}
