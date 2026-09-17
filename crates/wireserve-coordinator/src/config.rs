use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub admin_listen_addr: SocketAddr,
    pub admin_token: String,
    pub db_path: String,
    pub net_v4_cidr: String,
    pub net_v6_prefix: String,
    pub online_threshold_secs: i64,
    pub rate_limit_max: u32,
    pub rate_limit_window_secs: u64,
    /// Security review finding S4: trust the right-most `X-Forwarded-For`
    /// entry as the client IP instead of the raw TCP peer address (which,
    /// per spec §7, is always the reverse proxy itself). Off by default —
    /// only safe to enable when the coordinator is actually reachable
    /// exclusively through a proxy that sets this header, since otherwise
    /// a client could forge it to evade rate limiting entirely.
    pub trust_proxy_headers: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} must be set")]
    Missing(&'static str),
    #[error("invalid value for {0}: {1}")]
    Invalid(&'static str, String),
    #[error(
        "WIRESERVE_ADMIN_LISTEN_ADDR ({0}) is not loopback or a private-range address — the \
         admin surface must never be reachable from an untrusted network (spec §4.0). Note \
         that 100.64.0.0/10 addresses (the carrier-grade-NAT range Tailscale and similar \
         overlays hand out) are deliberately not accepted as private here: that range is \
         also used by ISPs on real WAN links, so it cannot be treated as inherently \
         internal. Bind this listener to loopback and reach it from inside the host \
         instead."
    )]
    AdminListenerNotPrivate(SocketAddr),
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let listen_addr = env_or("WIRESERVE_LISTEN_ADDR", "0.0.0.0:8080")?;
        let admin_listen_addr = env_or("WIRESERVE_ADMIN_LISTEN_ADDR", "127.0.0.1:8081")?;
        validate_admin_listener(admin_listen_addr)?;

        let admin_token = std::env::var("WIRESERVE_ADMIN_TOKEN")
            .map_err(|_| ConfigError::Missing("WIRESERVE_ADMIN_TOKEN"))?;
        if admin_token.is_empty() {
            return Err(ConfigError::Invalid(
                "WIRESERVE_ADMIN_TOKEN",
                "must not be empty".into(),
            ));
        }

        let db_path =
            std::env::var("WIRESERVE_DB_PATH").unwrap_or_else(|_| "wireserve.db".to_string());
        let net_v4_cidr = std::env::var("WIRESERVE_NET_V4_CIDR")
            .unwrap_or_else(|_| "100.90.0.0/24".to_string());
        let net_v6_prefix = std::env::var("WIRESERVE_NET_V6_PREFIX")
            .unwrap_or_else(|_| "fd00:90::/64".to_string());

        let online_threshold_secs = env_parse_or("WIRESERVE_ONLINE_THRESHOLD_SECS", 180)?;
        let rate_limit_max = env_parse_or("WIRESERVE_RATE_LIMIT_MAX", 10)?;
        let rate_limit_window_secs = env_parse_or("WIRESERVE_RATE_LIMIT_WINDOW_SECS", 60)?;
        let trust_proxy_headers = env_parse_or("WIRESERVE_TRUST_PROXY_HEADERS", false)?;

        Ok(Self {
            listen_addr,
            admin_listen_addr,
            admin_token,
            db_path,
            net_v4_cidr,
            net_v6_prefix,
            online_threshold_secs,
            rate_limit_max,
            rate_limit_window_secs,
            trust_proxy_headers,
        })
    }
}

fn env_or(key: &'static str, default: &str) -> Result<SocketAddr, ConfigError> {
    let raw = std::env::var(key).unwrap_or_else(|_| default.to_string());
    raw.parse()
        .map_err(|_| ConfigError::Invalid(key, raw))
}

fn env_parse_or<T: std::str::FromStr>(key: &'static str, default: T) -> Result<T, ConfigError> {
    match std::env::var(key) {
        Ok(raw) => raw
            .parse()
            .map_err(|_| ConfigError::Invalid(key, raw)),
        Err(_) => Ok(default),
    }
}

/// The admin listener must never be reachable from an untrusted network,
/// independent of the token check (spec §4.0) — enforced here as a hard
/// startup failure, not merely documented operator guidance.
pub fn validate_admin_listener(addr: SocketAddr) -> Result<(), ConfigError> {
    if is_loopback_or_private(addr.ip()) {
        Ok(())
    } else {
        Err(ConfigError::AdminListenerNotPrivate(addr))
    }
}

/// The IPv4 carrier-grade-NAT range, RFC 6598. Tailscale allocates every
/// node address it hands out from inside this block, and so do some ISPs
/// on WAN links.
const CGNAT_V4: (u32, u32) = (0x6440_0000, 10); // 100.64.0.0/10

/// Whether a configured mesh CIDR overlaps `100.64.0.0/10`.
///
/// This is not a correctness problem for WireServe by itself — the mesh
/// works fine on any range the operator picks — but it collides with
/// whatever else on the host already claims that space. Tailscale is the
/// common case: it routes all of `100.64.0.0/10` to its own interface, so
/// a mesh address inside that block can end up resolving to a route
/// pointing at `tailscale0` rather than `wg0`, and traffic meant for a
/// WireServe peer leaves over the tailnet instead (or goes nowhere).
///
/// The project's default (`100.90.0.0/24`, which is what the spec's own
/// examples use throughout) sits squarely inside it, so this warns rather
/// than refuses: an operator who does not run any CGNAT-range overlay is
/// perfectly fine on the default, and silently moving the default would
/// break any deployment already addressed from it.
#[must_use]
pub fn v4_cidr_overlaps_cgnat(cidr: &str) -> bool {
    let Some((addr_str, len_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(addr) = addr_str.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Ok(len) = len_str.parse::<u32>() else {
        return false;
    };
    if len > 32 {
        return false;
    }
    let (cgnat_net, cgnat_len) = CGNAT_V4;
    // Two prefixes overlap when either contains the other's network
    // address, i.e. when they agree on the shorter of the two masks.
    let shorter = len.min(cgnat_len);
    let mask = if shorter == 0 {
        0
    } else {
        u32::MAX << (32 - shorter)
    };
    (u32::from(addr) & mask) == (cgnat_net & mask)
}

pub fn is_loopback_or_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                // Unique Local Address range fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wildcard_bind() {
        let addr: SocketAddr = "0.0.0.0:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_err());
    }

    #[test]
    fn rejects_public_address() {
        let addr: SocketAddr = "1.2.3.4:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_err());
    }

    #[test]
    fn accepts_loopback() {
        let addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_ok());
    }

    #[test]
    fn accepts_private_range() {
        let addr: SocketAddr = "10.0.0.5:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_ok());
        let addr: SocketAddr = "192.168.1.5:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_ok());
    }

    #[test]
    fn accepts_ipv6_loopback_and_ula() {
        let addr: SocketAddr = "[::1]:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_ok());
        let addr: SocketAddr = "[fd00::1]:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_ok());
    }

    #[test]
    fn detects_overlap_with_the_tailscale_cgnat_range() {
        // The project default is inside 100.64.0.0/10 — this is exactly
        // the case the startup warning exists for.
        assert!(v4_cidr_overlaps_cgnat("100.90.0.0/24"));
        assert!(v4_cidr_overlaps_cgnat("100.64.0.0/10"));
        assert!(v4_cidr_overlaps_cgnat("100.127.255.0/24"));
        // A prefix shorter than /10 that contains it still overlaps.
        assert!(v4_cidr_overlaps_cgnat("100.0.0.0/8"));
    }

    #[test]
    fn does_not_flag_ranges_outside_cgnat() {
        assert!(!v4_cidr_overlaps_cgnat("10.90.0.0/24"));
        assert!(!v4_cidr_overlaps_cgnat("192.168.90.0/24"));
        assert!(!v4_cidr_overlaps_cgnat("172.20.0.0/16"));
        // 100.128.0.0 is the first address past the top of the range.
        assert!(!v4_cidr_overlaps_cgnat("100.128.0.0/24"));
        // 100.63.255.0 is the last address below it.
        assert!(!v4_cidr_overlaps_cgnat("100.63.255.0/24"));
        assert!(!v4_cidr_overlaps_cgnat("garbage"));
    }

    #[test]
    fn rejects_public_ipv6() {
        let addr: SocketAddr = "[2001:db8::1]:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_err());
    }
}
