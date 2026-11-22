//! A per-source sliding-window hit counter, shared by the coordinator (its
//! failed-auth limiter and its reflexive UDP responder, PLAN.md M22) and the
//! agent (its own reflexive answer on the WireGuard port, PLAN.md M50).
//! Moved here from `wireserve-coordinator::rate_limit` so both count a
//! source the same way.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How many distinct sources one limiter tracks at once (security review
/// finding #7). Without a ceiling the table grew with every source seen
/// in a window — and the reflexive responder's sources are spoofable UDP,
/// so "every source" is whatever an attacker chooses to send. A full
/// table stops tracking new sources; what that means differs per caller
/// (see [`SlidingWindowLimiter::record`]).
pub const MAX_TRACKED_SOURCES: usize = 65_536;

/// The prefix an IPv6 source is counted by unless a limiter says otherwise
/// ([`SlidingWindowLimiter::with_v6_prefix`]).
pub const DEFAULT_V6_PREFIX: u8 = 64;

/// The key a source is counted under: an IPv4 address as is, an IPv6
/// address by its first `v6_prefix` bits (a /64 by default). A single IPv6
/// host is routinely handed a whole /64 and can send from any address in
/// it, so per-address keys gave it 2^64 fresh budgets. An IPv4-mapped IPv6
/// address counts as the IPv4 address it maps.
fn source_key(ip: IpAddr, v6_prefix: u8) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let keep = u32::from(v6_prefix.min(128));
            let mask = if keep == 0 { 0 } else { u128::MAX << (128 - keep) };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
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
    v6_prefix: u8,
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
            v6_prefix: DEFAULT_V6_PREFIX,
            inner: Mutex::new(Inner {
                hits: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Counts IPv6 sources by their first `bits` instead: a limiter whose
    /// table filling up turns new sources away needs a prefix an attacker
    /// does not hold 65,536 of (a routed /48 is free from a tunnel broker,
    /// and holds that many /64s).
    #[must_use]
    pub fn with_v6_prefix(mut self, bits: u8) -> Self {
        self.v6_prefix = bits;
        self
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
            .get(&source_key(ip, self.v6_prefix))
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
        let key = source_key(ip, self.v6_prefix);
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

    /// How many timestamps `ip` holds — for tests that pin down the
    /// per-source cap.
    #[doc(hidden)]
    #[must_use]
    pub fn timestamps_for(&self, ip: IpAddr) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.hits.get(&source_key(ip, self.v6_prefix)).map_or(0, VecDeque::len)
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
    fn a_limiter_may_count_ipv6_by_a_wider_prefix() {
        let l = SlidingWindowLimiter::new(1, 60).with_v6_prefix(48);
        l.record(ip("2001:db8:1:2::1"));
        assert!(l.is_blocked(ip("2001:db8:1:ffff::9")), "same /48, same budget");
        assert!(!l.is_blocked(ip("2001:db8:2::1")), "another /48 is another source");
        l.record(ip("10.0.0.1"));
        assert!(l.is_blocked(ip("10.0.0.1")) && !l.is_blocked(ip("10.0.0.2")), "IPv4 is by address still");
    }

    #[test]
    fn an_ipv4_mapped_source_counts_as_its_ipv4_address() {
        let l = SlidingWindowLimiter::new(1, 60);
        l.record(ip("::ffff:192.0.2.7"));
        assert!(l.is_blocked(ip("192.0.2.7")));
    }
}
