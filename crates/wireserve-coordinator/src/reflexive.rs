//! The coordinator's self-hosted, STUN-like UDP reflexive-address
//! responder (PLAN.md M22, NAT-traversal step 2): tells a node the
//! `ip:port` its packets are actually arriving from, so it can learn its
//! real NAT-mapped address instead of guessing at one.
//!
//! **Same trust model as `GET /probe`**: public, unauthenticated, no DB
//! access. Unlike `/probe`, this speaks raw UDP rather than HTTP,
//! because the whole point is to observe a *UDP* NAT mapping — an
//! HTTP/TCP connection tells a node nothing about how its UDP traffic is
//! translated.
//!
//! **This is a public UDP reflector, which is a classic
//! reflection/amplification abuse vector** (an attacker spoofs a
//! victim's source address so the reply goes to them instead). The
//! mitigation is structural: `wireserve_types::reflexive::RESPONSE_LEN`
//! is smaller than `REQUEST_LEN`, so the reflection factor is under 1x
//! by construction — see that module's doc comment. On top of that,
//! anything malformed or over its per-source rate budget is dropped
//! **silently** — never with an error reply, since an error reply is
//! still a reflected packet.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::rate_limit::SlidingWindowLimiter;

/// Serves the reflexive responder on `socket` until the process exits —
/// spawned as a detached task from `main`, same as the two HTTP servers
/// are `axum::serve`d, but never itself part of their `try_join!` exit
/// condition (a UDP recv loop has no natural "done").
///
/// `second` answers every request again, from a port the node never sent
/// anything to (PLAN.md M40): that answer only arrives where the node's NAT
/// or firewall lets unsolicited traffic in. Both answers together are
/// still smaller than the request (`reflexive`'s own compile-time check).
pub async fn serve(socket: UdpSocket, second: Option<Arc<std::net::UdpSocket>>, limiter: Arc<SlidingWindowLimiter>) {
    let mut buf = [0u8; wireserve_types::reflexive::REQUEST_LEN];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "reflexive UDP responder: recv error");
                continue;
            }
        };
        handle_datagram(&socket, second.as_deref(), &buf[..n], src, &limiter).await;
    }
}

async fn handle_datagram(
    socket: &UdpSocket,
    second: Option<&std::net::UdpSocket>,
    datagram: &[u8],
    src: SocketAddr,
    limiter: &SlidingWindowLimiter,
) {
    // IPv4 only (decisions log #90+) — the request format itself is
    // IPv4-only (`wireserve_types::reflexive`), so a v6 source could
    // never be answered meaningfully anyway.
    let SocketAddr::V4(src4) = src else {
        return;
    };
    // Wrong size/magic/version: drop with no reply at all, not an error
    // response — an error reply is still a reflected packet.
    let Some(nonce) = wireserve_types::reflexive::parse_request(datagram) else {
        return;
    };
    // Silent when over budget, and also when the limiter is full and
    // cannot track this source at all: answering an untracked source is
    // the unlimited reflection the limiter is there to prevent.
    if limiter.is_blocked(src.ip()) || !limiter.record(src.ip()) {
        return;
    }

    let response = wireserve_types::reflexive::build_response(nonce, src4);
    if let Err(e) = socket.send_to(&response, src).await {
        tracing::debug!(error = %e, %src, "reflexive UDP responder: send error");
    }
    if let Some(second) = second {
        // A UDP send on an unconnected socket doesn't block for long enough
        // to matter; the socket is shared with port checks, so std's.
        if let Err(e) = second.send_to(&response, src) {
            tracing::debug!(error = %e, %src, "reflexive UDP responder: second send error");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wireserve_types::reflexive::{build_request, parse_response, REQUEST_LEN};

    async fn spawn_responder(rate_limit_max: u32) -> SocketAddr {
        spawn_responder_with(SlidingWindowLimiter::new(rate_limit_max, 60)).await
    }

    async fn spawn_responder_with(limiter: SlidingWindowLimiter) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(serve(socket, None, Arc::new(limiter)));
        addr
    }

    #[tokio::test]
    async fn a_second_answer_comes_from_another_port() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let second = Arc::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
        let second_addr = second.local_addr().unwrap();
        tokio::spawn(serve(socket, Some(second), Arc::new(SlidingWindowLimiter::new(10, 60))));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let nonce = [7u8; 8];
        client.send_to(&build_request(nonce), addr).await.unwrap();
        let mut from = Vec::new();
        let mut buf = [0u8; 64];
        for _ in 0..2 {
            let (n, src) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await.unwrap().unwrap();
            assert_eq!(parse_response(&buf[..n]).unwrap().0, nonce);
            from.push(src);
        }
        from.sort();
        let mut want = vec![addr, second_addr];
        want.sort();
        assert_eq!(from, want);
    }

    #[tokio::test]
    async fn a_source_the_full_limiter_cannot_track_gets_no_reply() {
        // Room for no sources at all: nothing is ever tracked, so nothing
        // may be answered.
        let responder_addr = spawn_responder_with(SlidingWindowLimiter::with_max_sources(100, 60, 0)).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&build_request([7; 8]), responder_addr).await.unwrap();
        assert!(recv_with_timeout(&client).await.is_none());
    }

    async fn recv_with_timeout(socket: &UdpSocket) -> Option<(usize, SocketAddr, [u8; 64])> {
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => Some((n, src, buf)),
            _ => None,
        }
    }

    #[tokio::test]
    async fn responds_with_the_observed_source_address() {
        let responder_addr = spawn_responder(100).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        client.send_to(&build_request(nonce), responder_addr).await.unwrap();

        let (n, _, buf) = recv_with_timeout(&client).await.expect("a response");
        let (echoed_nonce, observed) = parse_response(&buf[..n]).expect("a valid response");
        assert_eq!(echoed_nonce, nonce);
        assert_eq!(SocketAddr::V4(observed), client_addr);
    }

    #[tokio::test]
    async fn drops_an_undersized_request_with_no_reply() {
        let responder_addr = spawn_responder(100).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&[0u8; REQUEST_LEN - 1], responder_addr).await.unwrap();
        assert!(recv_with_timeout(&client).await.is_none());
    }

    #[tokio::test]
    async fn drops_an_oversized_request_with_no_reply() {
        let responder_addr = spawn_responder(100).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&[0u8; REQUEST_LEN + 1], responder_addr).await.unwrap();
        assert!(recv_with_timeout(&client).await.is_none());
    }

    #[tokio::test]
    async fn drops_a_malformed_magic_with_no_reply() {
        let responder_addr = spawn_responder(100).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut req = build_request([0; 8]);
        req[0] = b'X';
        client.send_to(&req, responder_addr).await.unwrap();
        assert!(recv_with_timeout(&client).await.is_none());
    }

    #[tokio::test]
    async fn a_burst_past_the_rate_budget_is_actually_dropped() {
        let responder_addr = spawn_responder(3).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        for i in 0..10u8 {
            client.send_to(&build_request([i; 8]), responder_addr).await.unwrap();
        }

        let mut replies = 0;
        while recv_with_timeout(&client).await.is_some() {
            replies += 1;
        }
        assert_eq!(replies, 3, "exactly the budget's worth of requests must be answered");
    }
}
