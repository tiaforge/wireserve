//! Hand-rolled in-process rate limiting for failed authentication
//! (PLAN.md decisions log #7 — no external dependency).
//!
//! **Read this before assuming what it protects.** There are two
//! mechanisms here and they do different jobs:
//!
//! 1. A **per-source sliding window** (`is_blocked` / `record_failure`).
//!    This drives the response code — an over-budget source that fails
//!    again gets `429` instead of `401` — and nothing else. It
//!    deliberately does **not** reject a request carrying a valid
//!    credential, for the reason spelled out on `auth::over_budget`:
//!    spec §7 mandates a reverse proxy in front of this coordinator, so
//!    in the topology the spec actually describes *every node shares one
//!    key*, the proxy's address. Rejecting on the budget alone let ten
//!    bad guesses from any stranger take the whole mesh offline. So this
//!    is not, and cannot be, a bound on how fast an attacker may guess.
//!
//! 2. A **global failed-auth budget** (`record_failure` /
//!    `failure_delay`), which is the actual bound. Once failures across
//!    all sources exceed the budget for the window, each further
//!    *failure response* is delayed. Successful authentication is never
//!    delayed, which is what makes this free of collateral damage where
//!    (1) is not: the only population slowed is the one failing, and a
//!    legitimate node behind the same shared address is unaffected
//!    because its credential is good.
//!
//! Neither mechanism is a volumetric defence, and neither pretends to
//! be. Against 256-bit CSPRNG tokens the real protection is the token
//! itself; these exist so that a flood of guesses costs the attacker
//! something and shows up in the audit log
//! (`event = "auth_failure"`) where the operator's proxy — which, unlike
//! this process, can see the real client address and holds the privilege
//! to act on it — can block the source. See `deploy/fail2ban/`.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Delay added to the first failure response past the global budget.
const DELAY_BASE: Duration = Duration::from_millis(250);
/// Ceiling on that delay however far over budget the process is. A
/// failure response is still a response; holding a connection open for
/// seconds would be its own denial of service.
const DELAY_MAX: Duration = Duration::from_millis(1000);
/// How many responses may be sitting in a delay at once. Past this,
/// failures answer immediately and undelayed — an attacker must not be
/// able to convert this mitigation into unbounded held connections,
/// which is the exact shape of the problem it exists to reduce.
const MAX_CONCURRENT_DELAYS: usize = 64;

/// A per-source sliding-window hit counter, with no notion of
/// "failure," no global budget, and no response delay — just "has this
/// source exceeded `max` recorded hits in the last `window`."
/// `RateLimiter` wraps one of these for its own per-source half (see the
/// module doc's mechanism (1)); the coordinator's reflexive UDP
/// responder (PLAN.md M22) uses one directly, with its own, much smaller
/// budget, since a stateless UDP echo has no "authentication failure" to
/// count and — critically — must never sleep inside its single receive
/// loop the way `RateLimiter`'s delay mechanism does, which would be a
/// self-inflicted backlog for every other datagram waiting behind it.
pub struct SlidingWindowLimiter {
    max: u32,
    window: Duration,
    hits: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl SlidingWindowLimiter {
    pub fn new(max: u32, window_secs: u64) -> Self {
        Self {
            max,
            window: Duration::from_secs(window_secs),
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `ip` has already exhausted its budget for the current
    /// window — a pure check, records nothing (security review G5: this
    /// must never insert a map entry, or every distinct source address
    /// ever seen would occupy memory forever).
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

    /// Records one hit from `ip`. Also where the table is pruned: every
    /// expired timestamp and every address left with none is dropped, so
    /// the map is bounded by (sources with a live hit in the window ×
    /// `max`).
    pub fn record(&self, ip: IpAddr) {
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

pub struct RateLimiter {
    per_source: SlidingWindowLimiter,
    /// Failures across *all* sources, for the global budget. Kept
    /// separate from `per_source` rather than derived by summing it,
    /// because `per_source` is pruned per source and a sum over it would
    /// silently change meaning the moment that pruning changed.
    global_max: u32,
    global_window: Duration,
    global: Mutex<Vec<Instant>>,
    delaying: AtomicUsize,
}

impl RateLimiter {
    pub fn new(max: u32, window_secs: u64) -> Self {
        Self::with_global_budget(max, window_secs, u32::MAX, window_secs)
    }

    pub fn with_global_budget(
        max: u32,
        window_secs: u64,
        global_max: u32,
        global_window_secs: u64,
    ) -> Self {
        Self {
            per_source: SlidingWindowLimiter::new(max, window_secs),
            global_max,
            global_window: Duration::from_secs(global_window_secs),
            global: Mutex::new(Vec::new()),
            delaying: AtomicUsize::new(0),
        }
    }

    /// How long this failure response should be held before it is sent,
    /// or `None` while the global budget is intact.
    ///
    /// Call **only** on a path already known to be a failure, and — this
    /// is the part that matters — only once every database lock is
    /// released. `state.db.conn` is a single global `Mutex<Connection>`;
    /// awaiting this while holding it would serialise every other request
    /// in the process behind the attacker and turn a brute-force
    /// mitigation into a total denial of service.
    #[must_use]
    pub fn failure_delay(&self) -> Option<Duration> {
        let now = Instant::now();
        let live = {
            let mut g = self.global.lock().unwrap_or_else(|e| e.into_inner());
            g.retain(|t| now.duration_since(*t) < self.global_window);
            g.len() as u64
        };
        let over = live.saturating_sub(u64::from(self.global_max));
        if over == 0 {
            return None;
        }
        // Linear in the overage, capped. Enough to make a sustained
        // guessing run expensive without ever pinning a worker for long.
        let scaled = DELAY_BASE.saturating_mul(u32::try_from(over).unwrap_or(u32::MAX));
        Some(scaled.min(DELAY_MAX))
    }

    /// Applies [`failure_delay`](Self::failure_delay), holding one of a
    /// bounded number of delay slots. A no-op when the budget is intact
    /// or every slot is taken.
    ///
    /// Must not be called while holding the database lock — see
    /// `failure_delay`.
    pub async fn apply_failure_delay(&self) {
        let Some(delay) = self.failure_delay() else {
            return;
        };
        if self.delaying.fetch_add(1, Ordering::Relaxed) >= MAX_CONCURRENT_DELAYS {
            self.delaying.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        tokio::time::sleep(delay).await;
        self.delaying.fetch_sub(1, Ordering::Relaxed);
    }

    /// Delay slots currently held — exposed for tests that pin the
    /// concurrency cap.
    pub fn delays_in_flight(&self) -> usize {
        self.delaying.load(Ordering::Relaxed)
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
        self.per_source.is_blocked(ip)
    }

    /// Records one failed attempt from `ip` — call only on an actual auth
    /// failure (never on success), so legitimate traffic never eats into
    /// the budget. Failures are rare relative to requests, so the sweep
    /// `SlidingWindowLimiter::record` does is cheap.
    pub fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        {
            let mut g = self.global.lock().unwrap_or_else(|e| e.into_inner());
            g.retain(|t| now.duration_since(*t) < self.global_window);
            g.push(now);
        }
        self.per_source.record(ip);
    }

    /// Number of source addresses currently tracked — exposed for tests
    /// that pin down the no-growth guarantee above.
    pub fn tracked_sources(&self) -> usize {
        self.per_source.tracked_sources()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ---- SlidingWindowLimiter, standalone ----

    #[test]
    fn sliding_window_allows_up_to_max_then_blocks() {
        let l = SlidingWindowLimiter::new(3, 60);
        let a = ip("10.0.0.1");
        for _ in 0..3 {
            assert!(!l.is_blocked(a));
            l.record(a);
        }
        assert!(l.is_blocked(a), "4th hit within window must be blocked");
    }

    #[test]
    fn sliding_window_is_keyed_per_ip() {
        let l = SlidingWindowLimiter::new(1, 60);
        let (a, b) = (ip("10.0.0.1"), ip("10.0.0.2"));
        l.record(a);
        assert!(l.is_blocked(a));
        assert!(!l.is_blocked(b), "a different source IP must not be affected");
    }

    #[test]
    fn sliding_window_resets_after_window_elapses() {
        let l = SlidingWindowLimiter::new(1, 0);
        let a = ip("10.0.0.1");
        l.record(a);
        assert!(!l.is_blocked(a));
    }

    #[test]
    fn sliding_window_is_blocked_never_inserts_an_entry() {
        let l = SlidingWindowLimiter::new(1, 60);
        for n in 0..100u8 {
            assert!(!l.is_blocked(ip(&format!("203.0.113.{n}"))));
        }
        assert_eq!(l.tracked_sources(), 0, "checking must not allocate per source");
    }

    #[test]
    fn sliding_window_record_prunes_expired_sources() {
        let l = SlidingWindowLimiter::new(5, 0);
        l.record(ip("10.0.0.1"));
        l.record(ip("10.0.0.2"));
        l.record(ip("10.0.0.3"));
        assert_eq!(l.tracked_sources(), 1);
    }

    // ---- RateLimiter, now delegating to SlidingWindowLimiter ----

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
    fn global_budget_is_intact_until_it_is_exceeded() {
        let rl = RateLimiter::with_global_budget(u32::MAX, 60, 3, 60);
        for _ in 0..3 {
            rl.record_failure(ip("10.0.0.1"));
            assert!(
                rl.failure_delay().is_none(),
                "failures inside the budget must not be delayed"
            );
        }
        rl.record_failure(ip("10.0.0.1"));
        assert!(rl.failure_delay().is_some(), "past the budget, delay applies");
    }

    #[test]
    fn global_budget_counts_every_source_together() {
        // The point of a *global* budget: an attacker spreading guesses
        // across addresses (or arriving through one proxy, which is the
        // normal topology) must not get a fresh allowance per address.
        let rl = RateLimiter::with_global_budget(u32::MAX, 60, 2, 60);
        rl.record_failure(ip("10.0.0.1"));
        rl.record_failure(ip("10.0.0.2"));
        assert!(rl.failure_delay().is_none());
        rl.record_failure(ip("10.0.0.3"));
        assert!(rl.failure_delay().is_some());
    }

    #[test]
    fn the_delay_is_capped_however_far_over_budget() {
        let rl = RateLimiter::with_global_budget(u32::MAX, 60, 0, 60);
        for _ in 0..10_000 {
            rl.record_failure(ip("10.0.0.1"));
        }
        assert_eq!(
            rl.failure_delay(),
            Some(DELAY_MAX),
            "a failure response held open indefinitely would be its own DoS"
        );
    }

    #[test]
    fn an_expired_global_window_restores_the_budget() {
        let rl = RateLimiter::with_global_budget(u32::MAX, 60, 0, 0);
        rl.record_failure(ip("10.0.0.1"));
        assert!(
            rl.failure_delay().is_none(),
            "a 0s window means every recorded failure is already stale"
        );
    }

    #[tokio::test]
    async fn concurrent_delays_are_capped() {
        use std::sync::Arc;
        let rl = Arc::new(RateLimiter::with_global_budget(u32::MAX, 60, 0, 60));
        rl.record_failure(ip("10.0.0.1"));
        assert!(rl.failure_delay().is_some());

        // Saturate the slots, then confirm the next caller returns at once
        // instead of queueing. Without the cap an attacker could convert
        // this mitigation into unbounded held connections.
        let mut handles = Vec::new();
        for _ in 0..MAX_CONCURRENT_DELAYS {
            let rl = Arc::clone(&rl);
            handles.push(tokio::spawn(async move { rl.apply_failure_delay().await }));
        }
        while rl.delays_in_flight() < MAX_CONCURRENT_DELAYS {
            tokio::task::yield_now().await;
        }

        let start = std::time::Instant::now();
        rl.apply_failure_delay().await;
        assert!(
            start.elapsed() < DELAY_BASE,
            "past the cap a failure must answer immediately, not queue"
        );

        for h in handles {
            let _ = h.await;
        }
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
