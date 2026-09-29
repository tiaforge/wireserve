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
    /// Ports being listened on, with the nonce expected there.
    active: HashMap<u16, String>,
    /// Checks answered since the last poll.
    seen: Vec<PortCheck>,
}

impl PortChecker {
    /// Starts listening for each check not already under way. A port
    /// something else holds can't be listened on, and that check simply
    /// never answers — which is what a closed port looks like too.
    pub fn start(self: &Arc<Self>, checks: &[PortCheck]) {
        for check in checks.iter().take(wireserve_types::MAX_PORT_CHECKS_PER_POLL) {
            let Some(nonce) = parse_nonce(&check.nonce) else {
                continue;
            };
            {
                let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if inner.active.get(&check.port) == Some(&check.nonce) {
                    continue;
                }
                inner.active.insert(check.port, check.nonce.clone());
            }
            let me = Arc::clone(self);
            let check = check.clone();
            tokio::spawn(async move {
                let heard = listen(check.port, nonce).await;
                let mut inner = me.inner.lock().unwrap_or_else(|e| e.into_inner());
                if inner.active.get(&check.port) == Some(&check.nonce) {
                    inner.active.remove(&check.port);
                }
                if heard {
                    inner.seen.push(check);
                    drop(inner);
                    me.wake.notify_one();
                }
            });
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

/// Listens on `port` until `nonce` arrives, or [`LISTEN_FOR`] passes.
async fn listen(port: u16, nonce: [u8; 8]) -> bool {
    let socket = match tokio::net::UdpSocket::bind(("0.0.0.0", port)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(port, error = %e, "cannot listen for a relay port check; it will read as closed");
            return false;
        }
    };
    let deadline = tokio::time::Instant::now() + LISTEN_FOR;
    let mut buf = [0u8; 64];
    while let Ok(Ok((n, _))) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
        if wireserve_types::reflexive::parse_response(&buf[..n]).is_some_and(|(got, _)| got == nonce) {
            return true;
        }
    }
    false
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
}
