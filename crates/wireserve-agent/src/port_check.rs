//! Port checks (PLAN.md M40): the coordinator asks a carrier to listen on
//! one of its public relay ports for a while, and sends a nonce to it from
//! outside. What arrives says the port is open to the internet — the one
//! thing an operator has to arrange by hand, in a firewall this node can't
//! see. The nonce goes back in the next poll, which a received one brings
//! forward.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wireserve_types::PortCheck;

/// How long a listener waits for its nonce. Longer than the coordinator
/// keeps sending it, so the check never ends on this side first.
const LISTEN_FOR: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct PortChecker {
    inner: Mutex<Inner>,
    /// Notified when a nonce arrives, so it is reported at once.
    pub wake: tokio::sync::Notify,
}

#[derive(Default)]
struct Inner {
    /// Ports being listened on, each with the check it now waits for.
    active: HashMap<u16, Listening>,
    /// Checks answered since the last poll.
    seen: Vec<PortCheck>,
}

struct Listening {
    check: PortCheck,
    nonce: [u8; 8],
    until: tokio::time::Instant,
}

impl PortChecker {
    /// Starts listening for each check not already under way. A port
    /// something else holds can't be listened on, and that check simply
    /// never answers — which is what a closed port looks like too.
    ///
    /// A new check for a port already being listened on takes that
    /// listener over, nonce and deadline: the one before it may still hold
    /// the port for a while after the coordinator gave up on it, and a
    /// second socket couldn't bind it. That is the usual way to get here —
    /// an export refused for a closed port, the port opened, the export
    /// run again at once.
    pub fn start(self: &Arc<Self>, checks: &[PortCheck]) {
        for check in checks.iter().take(wireserve_types::MAX_PORT_CHECKS_PER_POLL) {
            let Some(nonce) = parse_nonce(&check.nonce) else {
                continue;
            };
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if inner.active.get(&check.port).is_some_and(|l| l.check == *check) {
                continue;
            }
            let until = tokio::time::Instant::now() + LISTEN_FOR;
            let already = inner.active.insert(check.port, Listening { check: check.clone(), nonce, until }).is_some();
            drop(inner);
            if !already {
                tokio::spawn(listen(Arc::clone(self), check.port));
            }
        }
    }

    /// The ports being listened on right now, which the firewall leaves
    /// open for the check.
    #[must_use]
    pub fn active_ports(&self) -> Vec<u16> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut ports: Vec<u16> = inner.active.keys().copied().collect();
        ports.sort_unstable();
        ports
    }

    /// The checks answered since the last call, for the next poll.
    pub fn take_seen(&self) -> Vec<PortCheck> {
        std::mem::take(&mut self.inner.lock().unwrap_or_else(|e| e.into_inner()).seen)
    }
}

fn parse_nonce(hex: &str) -> Option<[u8; 8]> {
    if hex.len() != 16 {
        return None;
    }
    let mut out = [0u8; 8];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Listens on `port` until the nonce of the check it currently waits for
/// arrives, or that check's deadline passes.
async fn listen(me: Arc<PortChecker>, port: u16) {
    let socket = match tokio::net::UdpSocket::bind(("0.0.0.0", port)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(port, error = %e, "cannot listen for a relay port check; it will read as closed");
            me.inner.lock().unwrap_or_else(|e| e.into_inner()).active.remove(&port);
            return;
        }
    };
    let mut buf = [0u8; 64];
    loop {
        let until = {
            let mut inner = me.inner.lock().unwrap_or_else(|e| e.into_inner());
            match inner.active.get(&port) {
                Some(l) if l.until > tokio::time::Instant::now() => l.until,
                _ => {
                    inner.active.remove(&port);
                    return;
                }
            }
        };
        // A timeout only ends the wait if no newer check moved the deadline.
        let Ok(received) = tokio::time::timeout_at(until, socket.recv_from(&mut buf)).await else {
            continue;
        };
        let Ok((n, _)) = received else {
            me.inner.lock().unwrap_or_else(|e| e.into_inner()).active.remove(&port);
            return;
        };
        let Some((got, _)) = wireserve_types::reflexive::parse_response(&buf[..n]) else {
            continue;
        };
        let mut inner = me.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.active.get(&port).is_some_and(|l| l.nonce == got) {
            let heard = inner.active.remove(&port).expect("checked just above").check;
            inner.seen.push(heard);
            drop(inner);
            me.wake.notify_one();
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_parse_only_as_sixteen_hex_digits() {
        assert_eq!(parse_nonce("0001020304050607"), Some([0, 1, 2, 3, 4, 5, 6, 7]));
        assert_eq!(parse_nonce("00010203"), None);
        assert_eq!(parse_nonce("zz01020304050607"), None);
    }

    #[tokio::test]
    async fn a_nonce_sent_to_the_port_is_reported_once_and_wakes_the_poll() {
        let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let checker = Arc::new(PortChecker::default());
        let check = PortCheck { port, nonce: "0102030405060708".into() };
        checker.start(std::slice::from_ref(&check));
        assert_eq!(checker.active_ports(), [port]);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let wrong = wireserve_types::reflexive::build_response([9; 8], "127.0.0.1:1".parse().unwrap());
        sender.send_to(&wrong, ("127.0.0.1", port)).unwrap();
        let right = wireserve_types::reflexive::build_response([1, 2, 3, 4, 5, 6, 7, 8], "127.0.0.1:1".parse().unwrap());
        sender.send_to(&right, ("127.0.0.1", port)).unwrap();
        tokio::time::timeout(Duration::from_secs(2), checker.wake.notified()).await.unwrap();
        assert_eq!(checker.take_seen(), [check]);
        assert!(checker.take_seen().is_empty());
        assert!(checker.active_ports().is_empty());
    }

    /// An export refused for a closed port, the port opened, the export run
    /// again before the first listener's time is up: the second check must
    /// be heard, though the first one's socket still holds the port.
    #[tokio::test]
    async fn a_new_check_takes_over_a_port_still_listened_on_for_an_older_one() {
        let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let checker = Arc::new(PortChecker::default());
        let first = PortCheck { port, nonce: "0101010101010101".into() };
        checker.start(std::slice::from_ref(&first));
        tokio::time::sleep(Duration::from_millis(100)).await;
        let second = PortCheck { port, nonce: "0202020202020202".into() };
        checker.start(std::slice::from_ref(&second));
        assert_eq!(checker.active_ports(), [port]);
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let old = wireserve_types::reflexive::build_response([1; 8], "127.0.0.1:1".parse().unwrap());
        sender.send_to(&old, ("127.0.0.1", port)).unwrap();
        let new = wireserve_types::reflexive::build_response([2; 8], "127.0.0.1:1".parse().unwrap());
        sender.send_to(&new, ("127.0.0.1", port)).unwrap();
        tokio::time::timeout(Duration::from_secs(2), checker.wake.notified()).await.unwrap();
        assert_eq!(checker.take_seen(), [second]);
        assert!(checker.active_ports().is_empty());
    }
}
