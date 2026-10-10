//! How long the poll loop waits after the coordinator could not be reached or
//! could not keep up, so that a coordinator already struggling is not asked
//! again at once by every node that timed out (a missed tick used to fire
//! the moment a 30 s timeout returned).

use std::time::Duration;

/// The longest wait, however many polls in a row have failed.
pub const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// The wait after `failures` polls in a row failed (at least one): twice the
/// poll interval, doubling each time, to [`MAX_BACKOFF`], spread by ±25% so
/// nodes that failed together do not come back together. `unit` is a random
/// number in `0.0..1.0`.
#[must_use]
pub fn delay(interval: Duration, failures: u32, unit: f64) -> Duration {
    let doublings = failures.min(16);
    let base = interval.saturating_mul(1u32 << doublings).min(MAX_BACKOFF);
    base.mul_f64(0.75 + 0.5 * unit.clamp(0.0, 1.0)).max(interval)
}

#[cfg(test)]
mod tests {
    use super::*;

    const I: Duration = Duration::from_secs(20);

    #[test]
    fn doubles_from_twice_the_interval_up_to_the_cap() {
        let at = |n| delay(I, n, 0.5).as_secs();
        assert_eq!([at(1), at(2), at(3), at(4)], [40, 80, 160, 300]);
        assert_eq!(at(5), 300);
        assert_eq!(at(1000), 300, "a long outage neither overflows nor passes the cap");
    }

    #[test]
    fn is_spread_by_a_quarter_either_way_and_never_below_the_interval() {
        assert_eq!(delay(I, 1, 0.0).as_secs(), 30);
        assert_eq!(delay(I, 1, 1.0).as_secs(), 50);
        assert_eq!(delay(I, 4, 0.0).as_secs(), 225);
        assert!(delay(Duration::from_secs(1), 1, 0.0) >= Duration::from_secs(1));
    }
}
