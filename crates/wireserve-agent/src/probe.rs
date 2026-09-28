//! Active dual-family endpoint self-discovery: forces a single HTTP
//! request to the coordinator's `GET /probe` over a connection pinned to
//! a specific IP address family, to learn which families this node can
//! actually reach the coordinator over (and, since the coordinator
//! echoes back the source address it observed, what this node's own
//! reachable address is for that family).
//!
//! This is deliberately *active*, not passive: relying on whichever
//! family the agent's normal HTTP client happens to pick for a given
//! request cannot reliably learn both families over time, because a
//! host's outbound connection family to a fixed hostname is normally
//! consistent across repeated attempts (ordinary OS/DNS behavior, not
//! something that alternates on its own).
//!
//! The same result is reused for two different jobs by its two callers:
//! self-reporting `endpoint_addr_v4`/`endpoint_addr_v6` on `/register` and
//! `/poll`, and (via [`DualProbeResult::v6`] being present) deciding whether *this* node
//! should prefer a peer's v6 candidate over its v4 one when reconciling
//! WireGuard peers — see `wg::choose_peer_endpoint`.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// How long a single probe attempt is allowed to take. Mandatory
/// regardless of family: a route-less destination typically fails fast
/// (confirmed on real hardware — `ping -6` to an address with no local
/// IPv6 route at all fails immediately at the connect/EINVAL stage), but
/// a *present but blackholed* route could otherwise hang for the OS's
/// full retransmit window.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("invalid coordinator URL: {0}")]
    BadUrl(String),
    #[error("no {0:?} address available for the coordinator host")]
    NoAddressForFamily(Family),
    #[error("HTTP error probing the coordinator: {0}")]
    Http(#[from] reqwest::Error),
    #[error("coordinator returned an unparseable probe response: {0}")]
    BadResponse(String),
}

/// Picks the first candidate matching `family` — pure and unit-testable
/// separately from the actual DNS resolution/networking below.
fn pick_for_family(candidates: &[SocketAddr], family: Family) -> Option<SocketAddr> {
    candidates
        .iter()
        .copied()
        .find(|addr| matches!((addr, family), (SocketAddr::V4(_), Family::V4) | (SocketAddr::V6(_), Family::V6)))
}

/// Formats an observed address as the `host:port` (or bracketed
/// `[host]:port` for IPv6) syntax `wireserve_types::is_valid_endpoint_addr`
/// requires — unlike `client_ip::endpoint_fallback`'s coordinator-internal
/// equivalent, this string round-trips back through that same validation
/// on the very next `/register` or `/poll` call this node makes, so an
/// unbracketed IPv6 literal here would make the agent reject its own
/// output.
fn format_endpoint(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// Resolves the coordinator's host to a `(host, addr)` pair pinned to
/// `family` — either literally (the URL is already a matching-family IP
/// literal) or via DNS. Shared by `fetch_probe_response`'s family-pinned
/// HTTP connection and `reflexive::learn_reflexive_addr`'s UDP send
/// target, so the two never drift on what "the coordinator's address for
/// family X" means.
pub async fn resolve_family(coordinator_url: &str, family: Family) -> Result<(String, SocketAddr), ProbeError> {
    let url = reqwest::Url::parse(coordinator_url)
        .map_err(|e| ProbeError::BadUrl(e.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| ProbeError::BadUrl("missing host".into()))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);

    // A coordinator_url that's already a literal IP has no "other family"
    // to fall back to — attempt only the one it actually is, with no DNS
    // lookup at all.
    let pinned = if let Ok(literal) = host.parse::<IpAddr>() {
        let matches = matches!((&literal, family), (IpAddr::V4(_), Family::V4) | (IpAddr::V6(_), Family::V6));
        if !matches {
            return Err(ProbeError::NoAddressForFamily(family));
        }
        SocketAddr::new(literal, port)
    } else {
        let candidates = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map(Iterator::collect::<Vec<_>>)
            .unwrap_or_default();
        pick_for_family(&candidates, family).ok_or(ProbeError::NoAddressForFamily(family))?
    };
    Ok((host, pinned))
}

/// Forces one `GET {coordinator_url}/probe` over a connection pinned to
/// `family`, returning the coordinator's raw response — the observed
/// address (`probe_observed_addr`'s own concern) and, since PLAN.md M22,
/// `reflexive_port` (`reflexive::learn_reflexive_addr`'s concern). Shared
/// by both so there is exactly one place that makes this HTTP call.
pub async fn fetch_probe_response(
    coordinator_url: &str,
    family: Family,
    timeout: Duration,
) -> Result<wireserve_types::ProbeResponse, ProbeError> {
    let (host, pinned) = resolve_family(coordinator_url, family).await?;
    let client = reqwest::Client::builder()
        .resolve(&host, pinned)
        .timeout(timeout)
        .build()?;

    let probe_url = format!("{}/probe", coordinator_url.trim_end_matches('/'));
    let resp = client
        .get(&probe_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(resp)
}

/// Forces one `GET {coordinator_url}/probe` over a connection pinned to
/// `family`, returning the address the coordinator reports having
/// observed.
pub async fn probe_observed_addr(
    coordinator_url: &str,
    family: Family,
    timeout: Duration,
) -> Result<IpAddr, ProbeError> {
    let resp = fetch_probe_response(coordinator_url, family, timeout).await?;
    resp.addr
        .parse()
        .map_err(|_| ProbeError::BadResponse(resp.addr))
}

#[derive(Debug, Clone, Default)]
pub struct DualProbeResult {
    pub v4: Option<String>,
    pub v6: Option<String>,
}

/// Purpose 1 — self-report: runs both families concurrently, formats
/// whichever succeed as `endpoint_addr_v4`/`endpoint_addr_v6` candidates
/// using this node's own `listen_port`. A family that can't reach the
/// coordinator at all (no route, timeout, no matching DNS record) is
/// `None`, not an error — that's the ordinary case for most of the mesh.
pub async fn probe_both(coordinator_url: &str, listen_port: u16, timeout: Duration) -> DualProbeResult {
    let (v4, v6) = tokio::join!(
        probe_observed_addr(coordinator_url, Family::V4, timeout),
        probe_observed_addr(coordinator_url, Family::V6, timeout),
    );
    DualProbeResult {
        v4: v4.ok().map(|ip| format_endpoint(ip, listen_port)),
        v6: v6.ok().map(|ip| format_endpoint(ip, listen_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn pick_for_family_returns_the_first_matching_candidate() {
        let candidates = vec![addr("[::1]:80"), addr("203.0.113.5:80")];
        assert_eq!(pick_for_family(&candidates, Family::V4), Some(addr("203.0.113.5:80")));
        assert_eq!(pick_for_family(&candidates, Family::V6), Some(addr("[::1]:80")));
    }

    #[test]
    fn pick_for_family_returns_none_when_absent() {
        let candidates = vec![addr("203.0.113.5:80")];
        assert_eq!(pick_for_family(&candidates, Family::V6), None);
    }

    #[test]
    fn format_endpoint_brackets_ipv6_but_not_ipv4() {
        assert_eq!(
            format_endpoint("203.0.113.5".parse().unwrap(), 51820),
            "203.0.113.5:51820"
        );
        assert_eq!(
            format_endpoint("2001:db8::1".parse().unwrap(), 51820),
            "[2001:db8::1]:51820"
        );
    }

    #[test]
    fn format_endpoint_output_passes_the_coordinators_own_validator() {
        // The whole reason this differs from client_ip::endpoint_fallback:
        // this string round-trips back through is_valid_endpoint_addr on
        // this node's own next /register or /poll call.
        assert!(wireserve_types::is_valid_endpoint_addr(&format_endpoint(
            "2001:db8::1".parse().unwrap(),
            51820
        )));
        assert!(wireserve_types::is_valid_endpoint_addr(&format_endpoint(
            "203.0.113.5".parse().unwrap(),
            51820
        )));
    }
}
