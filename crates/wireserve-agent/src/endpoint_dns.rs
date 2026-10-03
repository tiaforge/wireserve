//! Resolving peer endpoints that are hostnames, without letting a slow
//! resolver hold up the poll cycle (security review).
//!
//! A peer's endpoint can be a DNS name — an operator's `--endpoint`
//! for a dynamic-DNS host is the legitimate case — and it used to be
//! resolved synchronously for every peer on every cycle (defguard's
//! `Peer::set_endpoint`), ahead of the firewall and hosts-file steps. Any
//! one node could name a host whose DNS server never answers and make
//! every other node wait out the resolver's timeout (seconds, per attempt)
//! on every cycle: denied services' firewall holes, revoked peers and new
//! ones all waited behind it.
//!
//! Here a literal `ip:port` needs no lookup at all. A name is looked up on
//! a background thread, one lookup per name at a time; the result is kept
//! for [`TTL`], and the last good address stays in use while a refresh
//! runs or after one fails. [`EndpointResolver::prepare`] waits at most
//! [`WAIT`] in total per cycle for lookups still running, so the normal
//! case (a name that resolves in milliseconds) still takes effect on the
//! cycle that first sees it, and the worst case costs [`WAIT`], not the
//! resolver's timeout times the number of hostile names.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a lookup's result is used before it is looked up again.
pub const TTL: Duration = Duration::from_secs(60);
/// The most one cycle waits, in total, for lookups still running.
pub const WAIT: Duration = Duration::from_secs(1);
/// Names remembered at once. A node sends one endpoint name at most, so
/// this is far above any real mesh; it only bounds what a directory full
/// of junk could make this process hold.
const MAX_NAMES: usize = 1024;

type Lookup = dyn Fn(&str) -> Option<SocketAddr> + Send + Sync;

#[derive(Default)]
struct Entry {
    /// The last address this name resolved to, kept across failed and
    /// in-progress refreshes.
    addr: Option<SocketAddr>,
    /// When the last lookup finished; `None` before the first one has.
    checked: Option<Instant>,
    in_flight: bool,
}

pub struct EndpointResolver {
    lookup: Arc<Lookup>,
    names: Arc<Mutex<HashMap<String, Entry>>>,
}

impl Default for EndpointResolver {
    fn default() -> Self {
        Self::with_lookup(system_lookup)
    }
}

/// The system resolver, first address — what defguard's own resolution
/// did, so which address a name maps to is unchanged.
fn system_lookup(endpoint: &str) -> Option<SocketAddr> {
    endpoint.to_socket_addrs().ok()?.next()
}

impl EndpointResolver {
    pub fn with_lookup(lookup: impl Fn(&str) -> Option<SocketAddr> + Send + Sync + 'static) -> Self {
        Self {
            lookup: Arc::new(lookup),
            names: Arc::default(),
        }
    }

    /// Starts a lookup for every name among `endpoints` that is due one,
    /// then waits — at most [`WAIT`] in total — for the lookups this call
    /// started. Lookups still running afterwards finish in the background
    /// and are used from a later cycle on.
    pub fn prepare<'a>(&self, endpoints: impl IntoIterator<Item = &'a str>) {
        let now = Instant::now();
        let (done_tx, done_rx) = mpsc::channel();
        let mut started = 0;
        {
            let mut names = self.names.lock().unwrap_or_else(|e| e.into_inner());
            for endpoint in endpoints {
                if endpoint.parse::<SocketAddr>().is_ok() {
                    continue;
                }
                if !names.contains_key(endpoint) && names.len() >= MAX_NAMES {
                    tracing::warn!(endpoint = %endpoint.escape_debug(), "too many peer endpoint names to track; not resolving this one");
                    continue;
                }
                let entry = names.entry(endpoint.to_string()).or_default();
                let due = entry.checked.is_none_or(|t| now.duration_since(t) >= TTL);
                if !due || entry.in_flight {
                    continue;
                }
                entry.in_flight = true;
                started += 1;
                let (name, lookup, names, done) =
                    (endpoint.to_string(), Arc::clone(&self.lookup), Arc::clone(&self.names), done_tx.clone());
                let spawned = std::thread::Builder::new().name("endpoint-dns".into()).spawn(move || {
                    let addr = lookup(&name);
                    if addr.is_none() {
                        tracing::warn!(endpoint = %name.escape_debug(), "could not resolve a peer endpoint");
                    }
                    let mut names = names.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(entry) = names.get_mut(&name) {
                        entry.in_flight = false;
                        entry.checked = Some(Instant::now());
                        if addr.is_some() {
                            entry.addr = addr;
                        }
                    }
                    let _ = done.send(());
                });
                if let Err(e) = spawned {
                    tracing::warn!(error = %e, "could not start a peer endpoint lookup");
                    entry.in_flight = false;
                    started -= 1;
                }
            }
        }
        let deadline = now + WAIT;
        for _ in 0..started {
            let left = deadline.saturating_duration_since(Instant::now());
            if done_rx.recv_timeout(left).is_err() {
                break;
            }
        }
    }

    /// The address to use for `endpoint` right now: a literal as is, a
    /// name as last resolved. `None` for a name not (yet) resolved.
    #[must_use]
    pub fn get(&self, endpoint: &str) -> Option<SocketAddr> {
        if let Ok(addr) = endpoint.parse() {
            return Some(addr);
        }
        let names = self.names.lock().unwrap_or_else(|e| e.into_inner());
        names.get(endpoint).and_then(|e| e.addr)
    }

    /// Forgets names no longer wanted, so the table follows the directory.
    pub fn retain<'a>(&self, wanted: impl IntoIterator<Item = &'a str>) {
        let wanted: std::collections::HashSet<&str> = wanted.into_iter().collect();
        let mut names = self.names.lock().unwrap_or_else(|e| e.into_inner());
        names.retain(|name, entry| entry.in_flight || wanted.contains(name.as_str()));
    }
}

/// Literal addresses only, for callers (tests) that must never touch DNS.
#[must_use]
pub fn literal_only(endpoint: &str) -> Option<SocketAddr> {
    endpoint.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_literal_needs_no_lookup() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let r = EndpointResolver::with_lookup(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            None
        });
        r.prepare(["203.0.113.5:51820", "[2001:db8::1]:51820"]);
        assert_eq!(r.get("203.0.113.5:51820"), Some(addr("203.0.113.5:51820")));
        assert_eq!(r.get("[2001:db8::1]:51820"), Some(addr("[2001:db8::1]:51820")));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_fast_name_is_usable_on_the_same_cycle_and_cached() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let r = EndpointResolver::with_lookup(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            Some(addr("198.51.100.7:51820"))
        });
        r.prepare(["home.example.com:51820"]);
        assert_eq!(r.get("home.example.com:51820"), Some(addr("198.51.100.7:51820")));
        r.prepare(["home.example.com:51820"]);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "within the TTL the cached answer is used");
    }

    #[test]
    fn a_name_that_never_answers_costs_one_bounded_wait_not_a_timeout_per_cycle() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let r = EndpointResolver::with_lookup(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_secs(5));
            None
        });
        let start = Instant::now();
        r.prepare(["tarpit.example:51820", "tarpit2.example:51820", "tarpit3.example:51820"]);
        let first = start.elapsed();
        assert!(first < WAIT + Duration::from_millis(500), "waited {first:?}");
        assert_eq!(r.get("tarpit.example:51820"), None);

        // The next cycle does not start a second lookup for a name whose
        // first is still running, and so does not wait at all.
        let start = Instant::now();
        r.prepare(["tarpit.example:51820", "tarpit2.example:51820", "tarpit3.example:51820"]);
        assert!(start.elapsed() < Duration::from_millis(100), "waited {:?}", start.elapsed());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn a_failed_refresh_keeps_the_last_good_address() {
        let answers = Arc::new(Mutex::new(vec![None, Some(addr("198.51.100.7:51820"))]));
        let a = Arc::clone(&answers);
        let r = EndpointResolver::with_lookup(move |_| a.lock().unwrap().pop().flatten());
        r.prepare(["home.example.com:51820"]);
        assert_eq!(r.get("home.example.com:51820"), Some(addr("198.51.100.7:51820")));
        // Force the entry due again, then have the refresh fail.
        r.names.lock().unwrap().get_mut("home.example.com:51820").unwrap().checked = None;
        r.prepare(["home.example.com:51820"]);
        assert_eq!(r.get("home.example.com:51820"), Some(addr("198.51.100.7:51820")));
    }

    #[test]
    fn names_no_longer_wanted_are_forgotten() {
        let r = EndpointResolver::with_lookup(|_| Some(addr("198.51.100.7:51820")));
        r.prepare(["a.example:1", "b.example:1"]);
        r.retain(["a.example:1"]);
        assert!(r.get("a.example:1").is_some());
        assert!(r.get("b.example:1").is_none());
    }
}
