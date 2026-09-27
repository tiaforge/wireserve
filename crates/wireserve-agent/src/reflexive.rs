//! Learns this node's own reflexive (NAT-mapped) `ip:port` from the
//! coordinator's self-hosted UDP responder (PLAN.md M22, NAT-traversal
//! step 2).
//!
//! **Must run once, before `wg::WgInterface::bring_up` claims
//! `listen_port`.** This agent uses the *kernel* WireGuard
//! implementation (`defguard_wireguard_rs::Kernel`): the real WireGuard
//! UDP socket is created by the kernel via netlink when `bring_up` runs,
//! and there is no userspace handle to multiplex a probe through it the
//! way a userspace WireGuard implementation could. The only clean
//! option: bind a short-lived userspace socket to the exact port
//! `bring_up` is about to claim, probe from it, and let it drop (closing
//! the socket) before `bring_up` runs moments later — relying on the NAT
//! reusing the same external mapping for a socket that rebinds the
//! identical local port immediately after. True for the great majority
//! of consumer NAT (full/restricted/port-restricted cone), not
//! guaranteed, and never attempted for symmetric NAT (out of scope —
//! that needs a relay, NAT-traversal step 3, not yet designed). Runs
//! once per agent process lifetime (`register::join` and each
//! `cmd_daemon` startup), not every poll cycle: a NAT remapping later
//! (e.g. a router reboot) is only recovered by a restart, same class of
//! limitation `listen_port` itself already has.

use std::time::Duration;

use wireserve_types::reflexive::{build_request, parse_response, Nonce, RESPONSE_LEN};

/// How long the whole probe (all attempts) is allowed to take.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// UDP is unreliable — one lost packet in either direction must not
/// disable the feature for the whole process lifetime.
const PROBE_ATTEMPTS: u32 = 3;

#[derive(Debug, thiserror::Error)]
enum ReflexiveProbeError {
    #[error("could not reach the coordinator to learn its reflexive UDP port: {0}")]
    FetchProbeResponse(#[from] crate::probe::ProbeError),
    #[error("could not bind local UDP port {0}: {1}")]
    Bind(u16, std::io::Error),
    #[error("network error during the reflexive probe: {0}")]
    Io(std::io::Error),
    #[error("no valid response from the coordinator's reflexive UDP responder")]
    NoResponse,
}

/// Learns this node's own reflexive `ip:port` for `listen_port`,
/// best-effort. Every internal failure (DNS, a bind conflict, a UDP
/// timeout, a corrupt or
/// mismatched-nonce reply) is logged and folded to `None` — a failed
/// probe must never fail `join` or the daemon's startup, exactly like
/// the existing dual-family HTTP probe it runs alongside.
pub async fn learn_reflexive_addr(coordinator_url: &str, listen_port: u16, timeout: Duration) -> Option<String> {
    match try_learn(coordinator_url, listen_port, timeout).await {
        Ok(addr) => Some(addr),
        Err(e) => {
            tracing::info!(error = %e, "reflexive-address probe did not succeed — continuing without it");
            None
        }
    }
}

async fn try_learn(coordinator_url: &str, listen_port: u16, timeout: Duration) -> Result<String, ReflexiveProbeError> {
    // IPv4 only (PLAN.md decisions log #90+) — the wire protocol itself
    // is IPv4-only, and a node with real working IPv6 skips this whole
    // mechanism before ever calling in (see `register::join`,
    // `main::cmd_daemon`).
    let probe_resp = crate::probe::fetch_probe_response(coordinator_url, crate::probe::Family::V4, timeout).await?;
    let reflexive_port = probe_resp.reflexive_port;
    let (_, coordinator_addr) = crate::probe::resolve_family(coordinator_url, crate::probe::Family::V4).await?;
    let target = std::net::SocketAddr::new(coordinator_addr.ip(), reflexive_port);

    // The exact port `bring_up` is about to claim — see module doc.
    let socket = tokio::net::UdpSocket::bind(("0.0.0.0", listen_port))
        .await
        .map_err(|e| ReflexiveProbeError::Bind(listen_port, e))?;

    let nonce: Nonce = rand::random();
    let request = build_request(nonce);
    let mut buf = [0u8; RESPONSE_LEN];
    let per_attempt_timeout = timeout / PROBE_ATTEMPTS;

    for _ in 0..PROBE_ATTEMPTS {
        socket.send_to(&request, target).await.map_err(ReflexiveProbeError::Io)?;
        let Ok(recv) = tokio::time::timeout(per_attempt_timeout, socket.recv_from(&mut buf)).await else {
            continue; // this attempt timed out — retry
        };
        let (n, _src) = recv.map_err(ReflexiveProbeError::Io)?;
        // Anything malformed, or a stray reply answering a different
        // request than the one just sent, is ignored rather than
        // trusted — retry instead.
        if let Some((echoed_nonce, observed)) = parse_response(&buf[..n]) {
            if echoed_nonce == nonce {
                return Ok(observed.to_string());
            }
        }
    }
    Err(ReflexiveProbeError::NoResponse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;
    use wireserve_types::reflexive::{parse_request, REQUEST_LEN};

    /// A minimal, hand-rolled `GET /probe` responder — no framework
    /// dependency needed for one fixed JSON reply per connection.
    async fn serve_probe_forever(listener: tokio::net::TcpListener, reflexive_port: u16) {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let body = format!(r#"{{"addr":"127.0.0.1","reflexive_port":{reflexive_port}}}"#);
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await; // request content is irrelevant
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }

    /// A fake coordinator: serves `GET /probe` (reporting `reflexive_port`
    /// as wherever the fake UDP responder is bound) and, if `respond`,
    /// a UDP responder that actually answers.
    async fn fake_coordinator(respond: bool) -> String {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = udp.local_addr().unwrap().port();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = listener.local_addr().unwrap();
        tokio::spawn(serve_probe_forever(listener, udp_port));

        tokio::spawn(async move {
            let mut buf = [0u8; REQUEST_LEN];
            loop {
                let Ok((n, src)) = udp.recv_from(&mut buf).await else { return };
                if !respond {
                    continue;
                }
                let Some(nonce) = parse_request(&buf[..n]) else { continue };
                let std::net::SocketAddr::V4(src_v4) = src else { continue };
                let resp = wireserve_types::reflexive::build_response(nonce, src_v4);
                let _ = udp.send_to(&resp, src).await;
            }
        });

        format!("http://{http_addr}")
    }

    #[tokio::test]
    async fn learns_the_reflexive_address_on_the_happy_path() {
        let coordinator_url = fake_coordinator(true).await;
        let addr = learn_reflexive_addr(&coordinator_url, 0, Duration::from_secs(2)).await;
        let addr = addr.expect("a real fake responder must produce an address");
        assert!(addr.starts_with("127.0.0.1:"), "{addr}");
    }

    #[tokio::test]
    async fn times_out_cleanly_when_the_responder_never_replies() {
        let coordinator_url = fake_coordinator(false).await;
        let addr = learn_reflexive_addr(&coordinator_url, 0, Duration::from_millis(300)).await;
        assert!(addr.is_none());
    }

    #[tokio::test]
    async fn a_mismatched_nonce_is_rejected_and_the_probe_times_out() {
        // A responder that always answers with someone else's nonce --
        // must never be trusted, even though a reply did arrive.
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = listener.local_addr().unwrap();
        tokio::spawn(serve_probe_forever(listener, udp_port));
        tokio::spawn(async move {
            let mut buf = [0u8; REQUEST_LEN];
            loop {
                let Ok((_, src)) = udp.recv_from(&mut buf).await else { return };
                let std::net::SocketAddr::V4(src_v4) = src else { continue };
                let wrong_nonce = [255u8; 8];
                let resp = wireserve_types::reflexive::build_response(wrong_nonce, src_v4);
                let _ = udp.send_to(&resp, src).await;
            }
        });

        let coordinator_url = format!("http://{http_addr}");
        let addr = learn_reflexive_addr(&coordinator_url, 0, Duration::from_millis(300)).await;
        assert!(addr.is_none());
    }
}
