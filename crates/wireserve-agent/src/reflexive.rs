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
//! `cmd_daemon` startup), not every poll cycle. A NAT remapping later (a
//! router reboot, a VPN switched on and off) is followed instead by an
//! approved carrier, which reports where it sees this node's packets come
//! from (`PollRequest::transit_observed`, PLAN.md decisions log #336); the
//! coordinator publishes that in place of this probe's answer.

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
    learn(coordinator_url, listen_port, timeout).await.addr
}

/// What the one-shot probe learned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Learned {
    /// The reflexive `ip:port`.
    pub addr: Option<String>,
    /// Whether unsolicited traffic reaches `listen_port` (PLAN.md M40): the
    /// coordinator's second answer, from a port this node never sent to,
    /// arrived. Only a NAT or firewall that lets inbound traffic in lets it
    /// through — a phone could dial this node directly. `None` when it could
    /// not be told: no answer at all, or a coordinator that answers once.
    pub dialable: Option<bool>,
}

/// [`learn_reflexive_addr`], and whether this node is dialable from outside.
pub async fn learn(coordinator_url: &str, listen_port: u16, timeout: Duration) -> Learned {
    match try_learn(coordinator_url, listen_port, timeout).await {
        Ok(learned) => learned,
        Err(e) => {
            tracing::info!(error = %e, "reflexive-address probe did not succeed — continuing without it");
            Learned::default()
        }
    }
}

/// How long the daemon's startup waits for a coordinator it can't reach
/// before it gives up on the check (see [`learn_waiting`]).
pub const UNREACHABLE_WAIT_MAX: Duration = Duration::from_secs(60);
/// How long between tries while the coordinator can't be reached.
const UNREACHABLE_RETRY: Duration = Duration::from_secs(5);

/// [`learn`], tried again for up to `max_wait` while the coordinator can't
/// be reached at all, for the daemon's startup. The check can only run
/// before the interface takes `listen_port`, so a coordinator that was down
/// just then (restarting, or killed for memory, as on the real mesh on
/// 2026-10-03) used to leave the node without its NAT-mapped port until its
/// next restart — and its NATed peers then hole-punched towards the wrong
/// port, and were relayed for good. Waiting costs nothing: the node can't
/// poll for its peers without the coordinator either.
///
/// Only an unreachable coordinator is waited for: one that answers over
/// IPv6 while this check, which is IPv4-only, fails means this node has no
/// IPv4 to learn, and waiting would only delay every start.
pub async fn learn_waiting(coordinator_url: &str, listen_port: u16, timeout: Duration, max_wait: Duration) -> Learned {
    let deadline = tokio::time::Instant::now() + max_wait;
    let mut said = false;
    loop {
        match try_learn(coordinator_url, listen_port, timeout).await {
            Ok(learned) => return learned,
            Err(ReflexiveProbeError::FetchProbeResponse(e))
                if tokio::time::Instant::now() + UNREACHABLE_RETRY < deadline
                    && crate::probe::fetch_probe_response(coordinator_url, crate::probe::Family::V6, timeout).await.is_err() =>
            {
                if !said {
                    tracing::info!(error = %e, "the coordinator can't be reached; waiting up to {}s for it before learning this node's NAT-mapped address", max_wait.as_secs());
                    said = true;
                }
                tokio::time::sleep(UNREACHABLE_RETRY).await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "reflexive-address probe did not succeed — continuing without it; peers behind a NAT can't dial this node first until the agent restarts");
                return Learned::default();
            }
        }
    }
}

/// How long to wait for the coordinator's second answer, and for the other
/// ports' answers, once the first came: all are sent together, so anything
/// later is lost, not late.
const SECOND_ANSWER_WAIT: Duration = Duration::from_millis(800);

/// One valid answer, matched to the request by its nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// From the port probed at this index of the list (most preferred
    /// first), with the address it saw.
    Probed(usize, std::net::SocketAddrV4),
    /// From the coordinator's address on a port this node never probed: its
    /// second answer (PLAN.md M40), which only arrives where unsolicited
    /// traffic is let in.
    Second(std::net::SocketAddrV4),
}

/// What an answer from `src` is, given the `targets` probed (PLAN.md M50,
/// #353). Only the coordinator's own address on an unprobed port counts as
/// its second answer: the node that answers on its WireGuard port is at the
/// same address, but on a port this node sent to.
fn classify(src: std::net::SocketAddr, targets: &[std::net::SocketAddr], observed: std::net::SocketAddrV4) -> Option<Answer> {
    if let Some(i) = targets.iter().position(|t| *t == src) {
        return Some(Answer::Probed(i, observed));
    }
    targets.iter().any(|t| t.ip() == src.ip()).then_some(Answer::Second(observed))
}

/// What a set of answers says (PLAN.md M50). The address: the most preferred
/// port's answer, else the second answer's. `dialable`: unknown from a
/// coordinator that answers once, or when its own port (`own`, the index of
/// `reflexive_port` in the list) never answered — then it never got the
/// request and so sent no second answer; otherwise whether the second came.
fn conclude(answers: &[Answer], answers_twice: bool, own: Option<usize>) -> Learned {
    let probed = answers.iter().filter_map(|a| match a {
        Answer::Probed(i, o) => Some((*i, *o)),
        Answer::Second(_) => None,
    });
    let best = probed.clone().min_by_key(|(i, _)| *i).map(|(_, o)| o);
    if let Some(best) = best {
        if let Some(other) = probed.clone().map(|(_, o)| o).find(|o| *o != best) {
            tracing::debug!(%best, %other, "the reflexive probe's answers disagree: a NAT that maps each destination port apart");
        }
    }
    let second = answers.iter().find_map(|a| match a {
        Answer::Second(o) => Some(*o),
        Answer::Probed(..) => None,
    });
    let own_answered = own.is_some_and(|own| probed.clone().any(|(i, _)| i == own));
    let dialable = if !answers_twice {
        None
    } else if second.is_some() {
        Some(true)
    } else if own_answered {
        Some(false)
    } else {
        None
    };
    Learned { addr: best.or(second).map(|o| o.to_string()), dialable }
}

async fn try_learn(coordinator_url: &str, listen_port: u16, timeout: Duration) -> Result<Learned, ReflexiveProbeError> {
    // IPv4 only (PLAN.md decisions log #90+) — the wire protocol itself
    // is IPv4-only. A node with working IPv6 calls in too (#207).
    let probe_resp = crate::probe::fetch_probe_response(coordinator_url, crate::probe::Family::V4, timeout).await?;
    let answers_twice = probe_resp.answers_twice;
    // Every port the coordinator lists, most preferred first (PLAN.md M50):
    // the WireGuard port of the node on its host, while that node answers
    // there, then its own.
    let ports = probe_resp.probe_ports();
    let own = ports.iter().position(|p| *p == probe_resp.reflexive_port);
    let (_, coordinator_addr) = crate::probe::resolve_family(coordinator_url, crate::probe::Family::V4).await?;
    let targets: Vec<std::net::SocketAddr> =
        ports.iter().map(|p| std::net::SocketAddr::new(coordinator_addr.ip(), *p)).collect();
    if targets.is_empty() {
        return Err(ReflexiveProbeError::NoResponse);
    }

    // The exact port `bring_up` is about to claim — see module doc.
    let socket = tokio::net::UdpSocket::bind(("0.0.0.0", listen_port))
        .await
        .map_err(|e| ReflexiveProbeError::Bind(listen_port, e))?;

    let nonce: Nonce = rand::random();
    let request = build_request(nonce);
    let mut buf = [0u8; RESPONSE_LEN];
    let per_attempt_timeout = timeout / PROBE_ATTEMPTS;
    let mut answers: Vec<Answer> = Vec::new();

    for _ in 0..PROBE_ATTEMPTS {
        // The same request, one nonce, to every port at once.
        for target in &targets {
            socket.send_to(&request, target).await.map_err(ReflexiveProbeError::Io)?;
        }
        let Ok(recv) = tokio::time::timeout(per_attempt_timeout, recv_answer(&socket, &mut buf)).await else {
            continue; // this attempt timed out — retry
        };
        let (n, src) = recv.map_err(ReflexiveProbeError::Io)?;
        // Anything malformed, or a stray reply answering a different
        // request than the one just sent, is ignored rather than
        // trusted — retry instead.
        let Some(answer) = parse_response(&buf[..n])
            .filter(|(echoed, _)| *echoed == nonce)
            .and_then(|(_, observed)| classify(src, &targets, observed))
        else {
            continue;
        };
        answers.push(answer);
        // The first came: whatever else is coming comes within moments.
        let deadline = tokio::time::Instant::now() + SECOND_ANSWER_WAIT;
        let done = |answers: &[Answer]| {
            let all_probed = (0..targets.len()).all(|i| answers.iter().any(|a| matches!(a, Answer::Probed(j, _) if *j == i)));
            let second = !answers_twice || answers.iter().any(|a| matches!(a, Answer::Second(_)));
            all_probed && second
        };
        while !done(&answers) {
            let Ok(Ok((n, src))) = tokio::time::timeout_at(deadline, recv_answer(&socket, &mut buf)).await else {
                break;
            };
            if let Some(answer) = parse_response(&buf[..n])
                .filter(|(echoed, _)| *echoed == nonce)
                .and_then(|(_, observed)| classify(src, &targets, observed))
            {
                if !answers.contains(&answer) {
                    answers.push(answer);
                }
            }
        }
        return Ok(conclude(&answers, answers_twice, own));
    }
    Err(ReflexiveProbeError::NoResponse)
}

/// The next datagram on `socket`. Windows reports a port that refused an
/// earlier send (an ICMP port-unreachable) as an error of the next receive,
/// "connection reset": one of the coordinator's listed ports being closed
/// is no reason to stop listening for the other's answer. Bounded by the
/// caller's timeout.
async fn recv_answer(socket: &tokio::net::UdpSocket, buf: &mut [u8]) -> std::io::Result<(usize, std::net::SocketAddr)> {
    loop {
        match socket.recv_from(buf).await {
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => return other,
        }
    }
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

    fn v4(s: &str) -> std::net::SocketAddrV4 {
        s.parse().unwrap()
    }

    #[test]
    fn only_the_coordinators_unprobed_port_is_its_second_answer() {
        let targets: Vec<std::net::SocketAddr> = vec!["192.0.2.1:51820".parse().unwrap(), "192.0.2.1:47820".parse().unwrap()];
        let o = v4("198.51.100.7:40000");
        assert_eq!(classify("192.0.2.1:51820".parse().unwrap(), &targets, o), Some(Answer::Probed(0, o)));
        assert_eq!(classify("192.0.2.1:47820".parse().unwrap(), &targets, o), Some(Answer::Probed(1, o)));
        assert_eq!(classify("192.0.2.1:33333".parse().unwrap(), &targets, o), Some(Answer::Second(o)));
        assert_eq!(classify("203.0.113.9:51820".parse().unwrap(), &targets, o), None, "someone else's answer");
    }

    #[test]
    fn the_wireguard_ports_answer_alone_never_makes_a_node_dialable() {
        let wg = Answer::Probed(0, v4("198.51.100.7:40000"));
        let own = Answer::Probed(1, v4("198.51.100.7:40000"));
        // The coordinator's own port blocked: it never got the request, so
        // its silence says nothing.
        assert_eq!(conclude(&[wg], true, Some(1)), Learned { addr: Some("198.51.100.7:40000".into()), dialable: None });
        // Its own port answered and the second never came: not dialable.
        assert_eq!(conclude(&[wg, own], true, Some(1)).dialable, Some(false));
        let second = Answer::Second(v4("198.51.100.7:40000"));
        assert_eq!(conclude(&[own, second], true, Some(1)).dialable, Some(true));
        assert_eq!(conclude(&[own], false, Some(1)).dialable, None, "a coordinator that answers once");
    }

    #[test]
    fn the_most_preferred_ports_answer_is_the_address() {
        let wg = Answer::Probed(0, v4("198.51.100.7:40000"));
        let own = Answer::Probed(1, v4("198.51.100.7:40001"));
        assert_eq!(conclude(&[own, wg], true, Some(1)).addr.as_deref(), Some("198.51.100.7:40000"));
        let second = Answer::Second(v4("198.51.100.7:40002"));
        assert_eq!(conclude(&[second], true, Some(1)).addr.as_deref(), Some("198.51.100.7:40002"), "the second alone still says where");
        assert_eq!(conclude(&[], true, Some(1)), Learned::default());
    }

    /// A fake coordinator listing two ports, of which only `answering` answers.
    async fn fake_two_port_coordinator(answering: usize) -> String {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ports = [a.local_addr().unwrap().port(), b.local_addr().unwrap().port()];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = listener.local_addr().unwrap();
        let body = format!(r#"{{"addr":"127.0.0.1","reflexive_port":{},"reflexive_ports":[{},{}]}}"#, ports[1], ports[0], ports[1]);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        let udp = if answering == 0 { a } else { b };
        tokio::spawn(async move {
            let mut buf = [0u8; REQUEST_LEN];
            loop {
                let Ok((n, src)) = udp.recv_from(&mut buf).await else { return };
                let Some(nonce) = parse_request(&buf[..n]) else { continue };
                let std::net::SocketAddr::V4(src_v4) = src else { continue };
                let _ = udp.send_to(&wireserve_types::reflexive::build_response(nonce, src_v4), src).await;
            }
        });
        format!("http://{http_addr}")
    }

    #[tokio::test]
    async fn learns_the_address_from_whichever_listed_port_answers() {
        for answering in [0, 1] {
            let url = fake_two_port_coordinator(answering).await;
            let learned = learn(&url, 0, Duration::from_secs(2)).await;
            assert!(learned.addr.is_some_and(|a| a.starts_with("127.0.0.1:")), "port {answering}");
        }
    }
}
