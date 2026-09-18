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
    /// How long a freshly-issued join token stays redeemable, in seconds.
    /// `0` disables expiry entirely.
    ///
    /// Default 1800 (30 minutes). A join token exists to cover the gap
    /// between an operator creating a node record and walking over to the
    /// machine to run `wireserve-agent join`; that is a minutes-long
    /// errand, not an open-ended one. The token travels out of band
    /// through chat, a password manager, terminal scrollback — places a
    /// credential outlives its usefulness by months. `rejoin` mints a
    /// fresh one whenever the window is missed, so the cost of a short
    /// default is one extra command, and the cost of no expiry at all is
    /// a live credential nobody remembers issuing.
    pub join_token_ttl_secs: u64,
    /// Failed authentications across *all* sources, per
    /// `global_auth_failure_window_secs`, before failure responses start
    /// being delayed. See `rate_limit`'s module doc for why this, and not
    /// the per-source window, is the actual bound on guess rate.
    pub global_auth_failure_max: u32,
    pub global_auth_failure_window_secs: u64,
    /// Require an admin to approve a service declaration before it is
    /// propagated to any other node.
    ///
    /// **On by default.** Service names are globally unique and
    /// first-come-first-served, so without this any node holding a valid
    /// bearer token can claim an unclaimed name — or re-claim one freed a
    /// moment earlier when its owner was revoked — and every other node's
    /// `/etc/hosts` will point `<name>.wg` at it. That is a credible way
    /// to intercept traffic a user believes is going somewhere else, and
    /// it needs only one compromised node.
    ///
    /// Turn it off (`false`) for a single-operator mesh where every node
    /// is already trusted and the round trip to approve is pure
    /// ceremony. With it off, a declaration is written approved on
    /// arrival and nothing downstream can tell the feature exists: the
    /// two extra `PollResponse` fields are provably empty and omitted
    /// from the JSON entirely.
    pub require_service_approval: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
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
    /// Loads configuration from the environment, generating and persisting
    /// a handful of first-run values (the admin token, both mesh ranges)
    /// when the operator hasn't set them explicitly. See
    /// [`crate::bootstrap`] for the resolution order and where those values
    /// are written.
    pub fn load() -> Result<Loaded, ConfigError> {
        let listen_addr = env_or("WIRESERVE_LISTEN_ADDR", "0.0.0.0:47820")?;
        let admin_listen_addr = env_or("WIRESERVE_ADMIN_LISTEN_ADDR", "127.0.0.1:47821")?;
        validate_admin_listener(admin_listen_addr)?;

        let db_path = resolve_db_path();
        let state_dir = std::path::Path::new(&db_path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        std::fs::create_dir_all(&state_dir).map_err(|e| {
            ConfigError::Invalid(
                "WIRESERVE_DB_PATH",
                format!("could not create parent directory {}: {e}", state_dir.display()),
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700));
        }

        let bootstrapped = crate::bootstrap::resolve(&state_dir).map_err(|e| {
            ConfigError::Invalid("WIRESERVE_ADMIN_TOKEN", format!("bootstrap failed: {e}"))
        })?;
        let admin_token = bootstrapped.admin_token;
        let net_v4_cidr = bootstrapped.net_v4_cidr;
        let net_v6_prefix = bootstrapped.net_v6_prefix;
        let generated = bootstrapped.generated;
        let secrets_path = bootstrapped.path;

        let online_threshold_secs = env_parse_or("WIRESERVE_ONLINE_THRESHOLD_SECS", 180)?;
        let rate_limit_max = env_parse_or("WIRESERVE_RATE_LIMIT_MAX", 10)?;
        let rate_limit_window_secs = env_parse_or("WIRESERVE_RATE_LIMIT_WINDOW_SECS", 60)?;
        let trust_proxy_headers = env_parse_or("WIRESERVE_TRUST_PROXY_HEADERS", false)?;
        let join_token_ttl_secs = env_parse_or("WIRESERVE_JOIN_TOKEN_TTL_SECS", 1800u64)?;
        let global_auth_failure_max = env_parse_or("WIRESERVE_GLOBAL_AUTH_FAILURE_MAX", 20u32)?;
        let global_auth_failure_window_secs =
            env_parse_or("WIRESERVE_GLOBAL_AUTH_FAILURE_WINDOW_SECS", 60u64)?;
        let require_service_approval =
            env_parse_or("WIRESERVE_REQUIRE_SERVICE_APPROVAL", true)?;

        Ok(Loaded {
            config: Self {
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
                join_token_ttl_secs,
                global_auth_failure_max,
                global_auth_failure_window_secs,
                require_service_approval,
            },
            generated,
            secrets_path,
        })
    }
}

/// The result of [`Config::load`]: the config itself, plus which first-run
/// values (if any) were freshly generated this call and where they were
/// persisted — `main` uses these two to print a one-time banner.
pub struct Loaded {
    pub config: Config,
    pub generated: Vec<&'static str>,
    pub secrets_path: std::path::PathBuf,
}

/// Resolves the database path: an explicit `WIRESERVE_DB_PATH` first, then
/// systemd's own `$STATE_DIRECTORY` (set automatically for any unit using
/// `StateDirectory=`, which the shipped coordinator unit does) joined with
/// `coordinator.db`, then the historical relative default. The middle case
/// is what lets the shipped systemd unit resolve a correct absolute path
/// with zero configuration instead of relying on an operator setting
/// `WIRESERVE_DB_PATH` in `coordinator.env` by convention.
fn resolve_db_path() -> String {
    if let Ok(path) = std::env::var("WIRESERVE_DB_PATH") {
        return path;
    }
    if let Ok(state_dir) = std::env::var("STATE_DIRECTORY") {
        // systemd may list multiple colon-separated directories; the first
        // is the one this unit's own StateDirectory= entry created.
        if let Some(first) = state_dir.split(':').next() {
            if !first.is_empty() {
                return format!("{first}/coordinator.db");
            }
        }
    }
    "wireserve.db".to_string()
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

/// Whether a configured IPv6 mesh prefix uses a Unique Local Address
/// block whose Global ID was obviously not generated the way RFC 4193
/// requires.
///
/// A ULA is `fd` followed by a **40-bit pseudo-randomly generated** Global
/// ID. The randomness is not decoration: it is the entire mechanism by
/// which two networks built independently, by people who never spoke to
/// each other, can later be bridged or merged without renumbering. A
/// prefix inside `fd00::/16` has a Global ID whose top 16 bits are zero,
/// which in practice means somebody picked a round number by hand —
/// `fd00::`, `fd00:1::`, and this project's own default `fd00:90::` are
/// among the most commonly hand-picked prefixes in existence, so they
/// collide with precisely the neighbours ULAs were designed to coexist
/// with: a Docker bridge given an `fd00::` pool, another VPN, a home
/// router handing out something memorable.
///
/// Warned about rather than refused, for the same reason as
/// [`v4_cidr_overlaps_cgnat`]: the default is what the spec's own
/// examples use throughout, and a deployment already addressed out of it
/// is working fine until the day something else turns up on the same
/// host.
///
/// Note this has nothing to do with Tailscale, whose IPv6 range is
/// `fd7a:115c:a1e0::/48` and collides with neither the default nor a
/// randomly generated prefix.
#[must_use]
pub fn v6_prefix_has_nonrandom_global_id(prefix: &str) -> bool {
    let Some((addr_str, _)) = prefix.split_once('/') else {
        return false;
    };
    let Ok(addr) = addr_str.parse::<std::net::Ipv6Addr>() else {
        return false;
    };
    // fd00::/16 — a ULA whose Global ID starts with 16 zero bits.
    addr.segments()[0] == 0xfd00
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
    fn flags_a_hand_picked_ula_global_id() {
        // The compiled-in default, and its equally round neighbours.
        assert!(v6_prefix_has_nonrandom_global_id("fd00:90::/64"));
        assert!(v6_prefix_has_nonrandom_global_id("fd00::/64"));
        assert!(v6_prefix_has_nonrandom_global_id("fd00:1::/48"));
    }

    #[test]
    fn accepts_a_properly_generated_ula_global_id() {
        assert!(!v6_prefix_has_nonrandom_global_id("fdb4:d481:7c21::/64"));
        // Tailscale's own range is a correctly generated ULA and must not
        // be flagged either.
        assert!(!v6_prefix_has_nonrandom_global_id("fd7a:115c:a1e0::/48"));
        assert!(!v6_prefix_has_nonrandom_global_id("garbage"));
    }

    #[test]
    fn rejects_public_ipv6() {
        let addr: SocketAddr = "[2001:db8::1]:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_err());
    }
}
