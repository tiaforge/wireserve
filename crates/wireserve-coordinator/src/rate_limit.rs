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

    /// Records a hit for `ip` and returns whether the caller should be
    /// allowed to proceed (`true`) or is over the limit (`false`).
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock().unwrap();
        let entry = hits.entry(ip).or_default();
        entry.retain(|t| now.duration_since(*t) < self.window);
        if entry.len() as u32 >= self.max {
            false
        } else {
            entry.push(now);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_max_then_blocks() {
        let rl = RateLimiter::new(3, 60);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(rl.check(ip));
        assert!(!rl.check(ip), "4th request within window must be blocked");
    }

    #[test]
    fn is_keyed_per_ip() {
        let rl = RateLimiter::new(1, 60);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(rl.check(a));
        assert!(!rl.check(a));
        assert!(rl.check(b), "a different source IP must not be affected");
    }

    #[test]
    fn resets_after_window_elapses() {
        let rl = RateLimiter::new(1, 0); // window of 0s: every check is "expired" immediately
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(rl.check(ip));
        // With a 0-length window the previous hit is immediately stale.
        assert!(rl.check(ip));
    }
}
