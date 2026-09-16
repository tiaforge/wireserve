//! Resolves the "real" client IP for rate limiting and `/register`'s
//! endpoint-address fallback.
//!
//! Security review finding (S4): spec §7 mandates a TLS-terminating
//! reverse proxy in front of the coordinator, which means `ConnectInfo`
//! is *always* the proxy's own address, never the actual client's — every
//! node ends up sharing one rate-limit bucket keyed on the proxy, and
//! `/register`'s endpoint-address fallback (spec §4.2) would hand out the
//! proxy's own loopback/private address to every agent as its "observed"
//! endpoint, which is useless (or actively wrong) for peer-to-peer
//! WireGuard connectivity.

use std::net::IpAddr;

use axum::http::HeaderMap;

/// Resolves the client IP to use for rate limiting and the `/register`
/// endpoint fallback. If `trust_proxy_headers` is set, prefers the
/// right-most `X-Forwarded-For` entry — the address the *nearest* hop
/// (the operator's own trusted reverse proxy) appended — over the raw
/// TCP peer address. This is a deliberately single-trusted-hop model: it
/// does not attempt to validate or walk a chain of untrusted proxies, on
/// the assumption (spec §7) that there is exactly one proxy in front of
/// the coordinator and it is trusted by the operator who set
/// `trust_proxy_headers`. Never enable this without actually running
/// behind a proxy that sets this header, or a client could simply forge
/// its own `X-Forwarded-For` to evade rate limiting entirely.
#[must_use]
pub fn resolve(headers: &HeaderMap, connect_ip: IpAddr, trust_proxy_headers: bool) -> IpAddr {
    if !trust_proxy_headers {
        return connect_ip;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or(connect_ip)
}

/// Whether `ip` is loopback or in a private/ULA range — used to decide
/// whether `/register`'s observed-source-IP fallback (spec §4.2) is worth
/// using at all. A loopback or private address is almost certainly the
/// reverse proxy's own address rather than anything reachable by other
/// mesh peers, so distributing it as this node's `endpoint_addr` would
/// actively mislead every other node's WireGuard config rather than just
/// being unhelpful.
#[must_use]
pub fn is_loopback_or_private(ip: IpAddr) -> bool {
    crate::config::is_loopback_or_private(ip)
}

/// Whether `ip` is specifically loopback — unlike
/// [`is_loopback_or_private`], this does NOT flag ordinary private-range
/// (RFC1918/ULA) addresses.
///
/// **Why register.rs uses this narrower check for the endpoint fallback,
/// not `is_loopback_or_private`**: a loopback address is unconditionally
/// useless to any other peer regardless of deployment topology (spec
/// §7's reverse-proxy requirement only bites when the network in between
/// is genuinely untrusted; an "internal Docker network" or private LAN
/// with no separate proxy hop is itself a spec-compliant topology, and
/// there the observed private-range address IS the real, reachable peer
/// address — confirmed by an actual two-agent-plus-coordinator
/// end-to-end test in this project's own development history, all
/// communicating over private container addresses). Blanket-rejecting
/// every private address here would break that legitimate case to guard
/// against a narrower one (a proxy on the same private network as the
/// coordinator) that `trust_proxy_headers` + `X-Forwarded-For` already
/// solves correctly when it actually applies.
#[must_use]
pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn ignores_xff_when_not_trusted() {
        let h = headers_with_xff("203.0.113.5");
        let connect: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(resolve(&h, connect, false), connect);
    }

    #[test]
    fn uses_rightmost_xff_entry_when_trusted() {
        let h = headers_with_xff("203.0.113.5, 198.51.100.9");
        let connect: IpAddr = "10.0.0.1".parse().unwrap();
        // The rightmost entry is what the nearest (trusted) proxy hop
        // appended; anything to its left is client-supplied and untrusted.
        assert_eq!(resolve(&h, connect, true), "198.51.100.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn falls_back_to_connect_ip_when_xff_missing_or_unparseable() {
        let connect: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(resolve(&HeaderMap::new(), connect, true), connect);

        let h = headers_with_xff("not-an-ip");
        assert_eq!(resolve(&h, connect, true), connect);
    }

    #[test]
    fn loopback_and_private_detection_matches_admin_listener_rule() {
        assert!(is_loopback_or_private("127.0.0.1".parse().unwrap()));
        assert!(is_loopback_or_private("10.1.2.3".parse().unwrap()));
        assert!(!is_loopback_or_private("203.0.113.5".parse().unwrap()));
    }
}
