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

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
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

/// How many distinct sources one limiter tracks at once (security review
/// finding #7). Without a ceiling the table grew with every source seen
/// in a window — and the reflexive responder's sources are spoofable UDP,
/// so "every source" is whatever an attacker chooses to send. A full
/// table stops tracking new sources; what that means differs per caller
/// (see [`SlidingWindowLimiter::record`]).
pub const MAX_TRACKED_SOURCES: usize = 65_536;

/// The key a source is counted under: an IPv4 address as is, an IPv6
/// address by its /64. A single IPv6 host is routinely handed a whole /64
/// and can send from any address in it, so per-address keys gave it
/// 2^64 fresh budgets. An IPv4-mapped IPv6 address counts as the IPv4
/// address it maps.
fn source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let bits = u128::from(v6) & !((1u128 << 64) - 1);
            IpAddr::V6(Ipv6Addr::from(bits))
        }
        v4 => v4,
    }
}

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
///
/// **Bounded in memory and in per-call work** (security review finding
/// #7). Each source keeps at most `max` timestamps; at most
/// [`MAX_TRACKED_SOURCES`] sources are tracked; and expired sources are
/// swept once per window rather than on every hit. The previous version
/// swept the entire table on every `record` while holding this mutex,
/// which a flood of distinct (spoofed) sources turned into quadratic
/// work, blocking an async worker thread for as long as it lasted.
pub struct SlidingWindowLimiter {
    max: u32,
    window: Duration,
    max_sources: usize,
    inner: Mutex<Inner>,
}

struct Inner {
    hits: HashMap<IpAddr, VecDeque<Instant>>,
    last_sweep: Instant,
}

impl SlidingWindowLimiter {
    pub fn new(max: u32, window_secs: u64) -> Self {
        Self::with_max_sources(max, window_secs, MAX_TRACKED_SOURCES)
    }

    pub fn with_max_sources(max: u32, window_secs: u64, max_sources: usize) -> Self {
        Self {
            max,
            window: Duration::from_secs(window_secs),
            max_sources,
            inner: Mutex::new(Inner {
                hits: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    fn live(&self, entry: &VecDeque<Instant>, now: Instant) -> usize {
        entry.iter().filter(|t| now.duration_since(**t) < self.window).count()
    }

    /// Whether `ip` has already exhausted its budget for the current
    /// window — a pure check, records nothing (security review G5: this
    /// must never insert a map entry, or every distinct source address
    /// ever seen would occupy memory forever). At most `max` timestamps
    /// are looked at.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner
            .hits
            .get(&source_key(ip))
            .is_some_and(|entry| self.live(entry, now) as u64 >= u64::from(self.max))
    }

    /// Records one hit from `ip`, returning whether it was recorded.
    ///
    /// `false` means the table is full and `ip` is not already in it — the
    /// hit could not be counted. The reflexive responder treats that as
    /// "blocked" and stays silent: answering untracked sources is exactly
    /// the unlimited reflection the limiter exists to prevent, and a
    /// legitimate node's probe is best-effort anyway. The auth limiter
    /// ignores it: per-source state there only picks 429 over 401, and
    /// the global budget still counts the failure.
    pub fn record(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let key = source_key(ip);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if now.duration_since(inner.last_sweep) >= self.window {
            let window = self.window;
            inner.hits.retain(|_, entry| {
                entry.retain(|t| now.duration_since(*t) < window);
                !entry.is_empty()
            });
            inner.last_sweep = now;
        }
        let full = inner.hits.len() >= self.max_sources;
        let entry = match inner.hits.get_mut(&key) {
            Some(entry) => entry,
            None if full => return false,
            None => inner.hits.entry(key).or_default(),
        };
        while entry.front().is_some_and(|t| now.duration_since(*t) >= self.window) {
            entry.pop_front();
        }
        entry.push_back(now);
        // Only the newest `max` can matter: `max` live hits already mean
        // blocked, and older ones expire first.
        let cap = usize::try_from(self.max).unwrap_or(usize::MAX).max(1);
        while entry.len() > cap {
            entry.pop_front();
        }
        true
    }

    /// Number of sources currently tracked — exposed for tests that pin
    /// down the no-growth guarantees above.
    pub fn tracked_sources(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).hits.len()
    }

    #[cfg(test)]
    fn timestamps_for(&self, ip: IpAddr) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.hits.get(&source_key(ip)).map_or(0, VecDeque::len)
    }
}

/// Failures across every source, counted in one-second buckets: a fixed
/// `window_secs` of memory and O(window) work however many failures
/// arrive (security review finding #7 — this used to be a list with one
/// timestamp per failure, swept in full on every failure).
struct GlobalCounter {
    window_secs: u64,
    epoch: Instant,
    /// `(second since epoch, failures in it)`, indexed by second modulo
    /// the window.
    buckets: Vec<(u64, u64)>,
}

impl GlobalCounter {
    fn new(window_secs: u64) -> Self {
        let len = usize::try_from(window_secs.max(1)).unwrap_or(usize::MAX).min(3600);
        Self {
            window_secs,
            epoch: Instant::now(),
            buckets: vec![(0, 0); len],
        }
    }

    fn now_sec(&self) -> u64 {
        self.epoch.elapsed().as_secs()
    }

    fn record(&mut self) {
        let sec = self.now_sec();
        let len = self.buckets.len() as u64;
        let slot = &mut self.buckets[usize::try_from(sec % len).unwrap_or(0)];
        if slot.0 != sec {
            *slot = (sec, 0);
        }
        slot.1 = slot.1.saturating_add(1);
    }

    fn live(&self) -> u64 {
        let now = self.now_sec();
        self.buckets
            .iter()
            .filter(|(sec, _)| now - sec < self.window_secs)
            .map(|(_, n)| n)
            .sum()
    }
}

pub struct RateLimiter {
    per_source: SlidingWindowLimiter,
    /// Failures across *all* sources, for the global budget. Kept
    /// separate from `per_source` rather than derived by summing it,
    /// because `per_source` is pruned per source and a sum over it would
    /// silently change meaning the moment that pruning changed.
    global_max: u32,
    global: Mutex<GlobalCounter>,
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
            global: Mutex::new(GlobalCounter::new(global_window_secs)),
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
        let live = self.global.lock().unwrap_or_else(|e| e.into_inner()).live();
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
    /// the budget.
    pub fn record_failure(&self, ip: IpAddr) {
        self.global.lock().unwrap_or_else(|e| e.into_inner()).record();
        // A full table leaves this source untracked, which only costs it
        // the 429 in place of a 401; see `SlidingWindowLimiter::record`.
        let _ = self.per_source.record(ip);
    }

    /// Number of source addresses currently tracked — exposed for tests
    /// that pin down the no-growth guarantee above.
    pub fn tracked_sources(&self) -> usize {
        self.per_source.tracked_sources()
    }
}

/// What a keyed bucket says about one request.
#[derive(Debug, PartialEq, Eq)]
pub enum Take {
    Allowed,
    /// Over budget. `log` is true for the first refusal in a minute, so a
    /// flood is one log line a minute and not one per request.
    Refused { log: bool },
}

/// A token bucket per key: `capacity` requests at once, refilled at a steady
/// `per_minute`. For what an *authenticated* caller may do to the
/// coordinator — the failed-auth limiter above never sees a valid token, so
/// a node with a good one could otherwise ask as often as it liked, each
/// `/poll` reading every node and service and writing under the one database
/// lock. `per_minute` of 0 turns it off.
pub struct TokenBuckets {
    capacity: f64,
    per_sec: f64,
    max_keys: usize,
    inner: Mutex<HashMap<i64, Bucket>>,
}

struct Bucket {
    tokens: f64,
    at: Instant,
    last_logged: Option<Instant>,
}

impl TokenBuckets {
    #[must_use]
    pub fn new(capacity: u32, per_minute: u32) -> Self {
        Self {
            capacity: f64::from(capacity.max(1)),
            per_sec: f64::from(per_minute) / 60.0,
            max_keys: MAX_TRACKED_SOURCES,
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn take(&self, key: i64) -> Take {
        self.take_at(key, Instant::now())
    }

    fn take_at(&self, key: i64, now: Instant) -> Take {
        if self.per_sec <= 0.0 {
            return Take::Allowed;
        }
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= self.max_keys {
            // Nodes that have been quiet long enough to be full again cost
            // nothing to forget.
            let (cap, rate) = (self.capacity, self.per_sec);
            map.retain(|_, b| b.tokens + now.duration_since(b.at).as_secs_f64() * rate < cap);
        }
        let b = map.entry(key).or_insert(Bucket { tokens: self.capacity, at: now, last_logged: None });
        b.tokens = (b.tokens + now.duration_since(b.at).as_secs_f64() * self.per_sec).min(self.capacity);
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            return Take::Allowed;
        }
        let log = b.last_logged.is_none_or(|t| now.duration_since(t) >= Duration::from_secs(60));
        if log {
            b.last_logged = Some(now);
        }
        Take::Refused { log }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_allows_its_burst_then_refills_steadily_per_key() {
        let l = TokenBuckets::new(3, 60); // one a second
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(l.take_at(1, t0), Take::Allowed);
        }
        assert_eq!(l.take_at(1, t0), Take::Refused { log: true });
        assert_eq!(l.take_at(1, t0), Take::Refused { log: false }, "one log line a minute");
        assert_eq!(l.take_at(2, t0), Take::Allowed, "another node is unaffected");
        assert_eq!(l.take_at(1, t0 + Duration::from_millis(1100)), Take::Allowed, "a second buys one");
        assert!(matches!(l.take_at(1, t0 + Duration::from_millis(1200)), Take::Refused { .. }));
        // Idle for a long time: full again, and never fuller than the burst.
        let later = t0 + Duration::from_secs(3600);
        for _ in 0..3 {
            assert_eq!(l.take_at(1, later), Take::Allowed);
        }
        assert!(matches!(l.take_at(1, later), Take::Refused { .. }));
    }

    #[test]
    fn a_rate_of_zero_is_no_limit() {
        let l = TokenBuckets::new(1, 0);
        for _ in 0..1000 {
            assert_eq!(l.take(1), Take::Allowed);
        }
    }

    #[test]
    fn the_table_forgets_nodes_that_are_full_again() {
        let mut l = TokenBuckets::new(2, 60);
        l.max_keys = 3;
        let t0 = Instant::now();
        for k in 0..3 {
            l.take_at(k, t0);
        }
        // Long after, a new key arrives at a full table: the old ones, refilled, go.
        l.take_at(99, t0 + Duration::from_secs(600));
        assert!(l.inner.lock().unwrap().len() <= 3);
    }

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

    #[test]
    fn the_source_table_stops_growing_at_its_cap() {
        let l = SlidingWindowLimiter::with_max_sources(5, 60, 3);
        for n in 0..3u8 {
            assert!(l.record(ip(&format!("203.0.113.{n}"))));
        }
        assert!(!l.record(ip("203.0.113.99")), "a new source past the cap is not tracked");
        assert!(l.record(ip("203.0.113.0")), "a source already tracked still is");
        assert_eq!(l.tracked_sources(), 3);
    }

    #[test]
    fn a_full_table_frees_up_once_its_entries_expire() {
        let l = SlidingWindowLimiter::with_max_sources(5, 0, 1);
        assert!(l.record(ip("10.0.0.1")));
        assert!(l.record(ip("10.0.0.2")), "the expired entry is swept, not held forever");
    }

    #[test]
    fn a_source_keeps_at_most_max_timestamps() {
        let l = SlidingWindowLimiter::new(3, 60);
        let a = ip("10.0.0.1");
        for _ in 0..10_000 {
            l.record(a);
        }
        assert_eq!(l.timestamps_for(a), 3);
        assert!(l.is_blocked(a));
    }

    #[test]
    fn an_ipv6_source_is_counted_by_its_64() {
        let l = SlidingWindowLimiter::new(1, 60);
        l.record(ip("2001:db8:1:2::1"));
        assert!(l.is_blocked(ip("2001:db8:1:2:ffff::9")), "same /64, same budget");
        assert!(!l.is_blocked(ip("2001:db8:1:3::1")), "another /64 is another source");
    }

    #[test]
    fn an_ipv4_mapped_source_counts_as_its_ipv4_address() {
        let l = SlidingWindowLimiter::new(1, 60);
        l.record(ip("::ffff:192.0.2.7"));
        assert!(l.is_blocked(ip("192.0.2.7")));
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

    #[test]
    fn the_global_budget_uses_fixed_memory_however_many_failures_arrive() {
        let rl = RateLimiter::with_global_budget(u32::MAX, 60, 0, 60);
        for n in 0..100_000u32 {
            rl.record_failure(IpAddr::from(n.to_be_bytes()));
        }
        let g = rl.global.lock().unwrap();
        assert_eq!(g.buckets.len(), 60);
        assert_eq!(g.live(), 100_000);
        drop(g);
        assert!(rl.tracked_sources() <= MAX_TRACKED_SOURCES);
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
