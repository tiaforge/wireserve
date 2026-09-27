use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub admin_listen_addr: SocketAddr,
    pub admin_token: String,
    pub db_path: String,
    pub net_v4_cidr: String,
    pub net_v6_prefix: String,
    /// The domain services are named under (PLAN.md M25), e.g.
    /// `int.example.com`. Unset leaves `<name>.wg` exactly as it was.
    pub service_domain: Option<String>,
    /// The sign-in every terminator puts in front of marked services
    /// (PLAN.md M34). Only with DNS records, which terminated services need.
    pub sign_in: Option<wireserve_types::SignIn>,
    /// Where the service names are published as public DNS records
    /// (PLAN.md M32). `None` leaves DNS to the operator, as before.
    pub dns: Option<crate::dns::DnsConfig>,
    /// The CA every node's terminator gets certificates from (PLAN.md M33).
    /// Only handed to nodes while `dns` is set: without the coordinator
    /// writing the challenge records, no certificate can be issued.
    pub acme: wireserve_types::AcmeSettings,
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
    /// The one address `X-Forwarded-For` is believed from (PLAN.md M31).
    /// Set, it replaces `trust_proxy_headers` with a narrower rule: the
    /// header counts when the TCP peer is this proxy and is ignored from
    /// anyone else. That is what a proxy on another machine needs — the
    /// listener is then on a LAN address, where any device could otherwise
    /// connect directly and name its own source address.
    pub trusted_proxy: Option<IpAddr>,
    /// How long a freshly-issued join token stays redeemable, in seconds.
    /// `0` disables expiry entirely.
    ///
    /// Default 1800 (30 minutes). A join token exists to cover the gap
    /// between an operator creating a node record and walking over to the
    /// machine to run `wireserve join`; that is a minutes-long
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
    /// Per-source budget for the self-hosted reflexive UDP responder
    /// (PLAN.md M22, `crate::reflexive`) — deliberately separate from
    /// `rate_limit_max`/`_window_secs`, which govern the HTTP failed-auth
    /// path and have no "failure" concept to reuse here. Small on
    /// purpose: a legitimate node probes this at most a few times per
    /// process lifetime (see `wireserve-agent`'s one-shot pre-`bring_up`
    /// probe), so there is no ordinary traffic pattern this could ever
    /// throttle by mistake.
    pub reflexive_rate_limit_max: u32,
    pub reflexive_rate_limit_window_secs: u64,
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
        // Loopback by default (security review finding #4): the node API
        // speaks plain HTTP and spec §7 puts a TLS-terminating proxy in
        // front of it, which on the usual single-host setup reaches it
        // over loopback. A wildcard default exposed it unencrypted to
        // every network the host is on unless the operator remembered to
        // firewall it. A proxy on another host, or a container publishing
        // the port, sets this explicitly (the image does).
        let listen_addr = env_or("WIRESERVE_LISTEN_ADDR", DEFAULT_LISTEN_ADDR)?;
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
        let trusted_proxy = match std::env::var("WIRESERVE_TRUSTED_PROXY") {
            Ok(p) if p.trim().is_empty() => None,
            Ok(p) => Some(p.trim().parse::<IpAddr>().map_err(|_| {
                ConfigError::Invalid("WIRESERVE_TRUSTED_PROXY", format!("{p:?} is not an IP address"))
            })?),
            Err(_) => None,
        };
        let join_token_ttl_secs = env_parse_or("WIRESERVE_JOIN_TOKEN_TTL_SECS", 1800u64)?;
        let global_auth_failure_max = env_parse_or("WIRESERVE_GLOBAL_AUTH_FAILURE_MAX", 20u32)?;
        let global_auth_failure_window_secs =
            env_parse_or("WIRESERVE_GLOBAL_AUTH_FAILURE_WINDOW_SECS", 60u64)?;
        let require_service_approval =
            env_parse_or("WIRESERVE_REQUIRE_SERVICE_APPROVAL", true)?;
        let reflexive_rate_limit_max = env_parse_or("WIRESERVE_REFLEXIVE_RATE_LIMIT_MAX", 20u32)?;
        let reflexive_rate_limit_window_secs =
            env_parse_or("WIRESERVE_REFLEXIVE_RATE_LIMIT_WINDOW_SECS", 10u64)?;

        // Rejected loudly rather than ignored: a typo here would silently
        // rename nothing and leave the operator hunting for why their
        // services still answer to `.wg`.
        let service_domain = match std::env::var("WIRESERVE_SERVICE_DOMAIN") {
            Ok(d) if d.trim().is_empty() => None,
            Ok(d) => {
                let d = d.trim().to_string();
                if !wireserve_types::is_valid_hostname(&d) {
                    return Err(ConfigError::Invalid(
                        "WIRESERVE_SERVICE_DOMAIN",
                        format!("{d:?} is not a valid domain (needs at least two labels)"),
                    ));
                }
                Some(d)
            }
            Err(_) => None,
        };
        let dns = crate::dns::config::from_lookup(|k| std::env::var(k).ok(), service_domain.as_deref())?;
        let acme = acme_from_lookup(|k| std::env::var(k).ok())?;
        let sign_in = sign_in_from_lookup(|k| std::env::var(k).ok(), dns.is_some())?;

        Ok(Loaded {
            config: Self {
                listen_addr,
                admin_listen_addr,
                admin_token,
                db_path,
                net_v4_cidr,
                net_v6_prefix,
                service_domain,
                sign_in,
                dns,
                acme,
                online_threshold_secs,
                rate_limit_max,
                rate_limit_window_secs,
                trust_proxy_headers,
                trusted_proxy,
                join_token_ttl_secs,
                global_auth_failure_max,
                global_auth_failure_window_secs,
                require_service_approval,
                reflexive_rate_limit_max,
                reflexive_rate_limit_window_secs,
            },
            generated,
            secrets_path,
        })
    }
}

impl Config {
    /// The mesh ranges as nodes are told them (security review finding
    /// #4): at registration, for the agent to pin, and on every poll.
    #[must_use]
    pub fn mesh_info(&self) -> wireserve_types::MeshInfo {
        wireserve_types::MeshInfo {
            net_v4_cidr: self.net_v4_cidr.clone(),
            net_v6_prefix: self.net_v6_prefix.clone(),
        }
    }
}

impl Config {
    /// Whether a request that arrived from `peer` may name its client in
    /// `X-Forwarded-For`. With `trusted_proxy` set, only that address may;
    /// otherwise `trust_proxy_headers` decides for every peer alike.
    #[must_use]
    pub fn trusts_forwarded_from(&self, peer: IpAddr) -> bool {
        match self.trusted_proxy {
            // A dual-stack listener reports an IPv4 peer as ::ffff:a.b.c.d.
            Some(proxy) => proxy.to_canonical() == peer.to_canonical(),
            None => self.trust_proxy_headers,
        }
    }
}

impl Config {
    /// How services are named, as nodes are told it (PLAN.md M25) — at
    /// registration and on every poll, the same shape and for the same reason
    /// as [`Config::mesh_info`]. `None` when no domain is set: services are
    /// then `<name>.wg`, known only to the nodes' hosts files.
    #[must_use]
    pub fn service_naming(&self) -> Option<wireserve_types::ServiceNaming> {
        self.service_domain.as_ref().map(|domain| wireserve_types::ServiceNaming {
            domain: domain.clone(),
            acme: self.dns.is_some().then(|| self.acme.clone()),
            sign_in: self.sign_in.clone(),
        })
    }
}

/// The ACME settings (PLAN.md M33), defaulting to Let's Encrypt production.
///
/// Every node's terminator uses the one CA the coordinator names, so a
/// staging or private CA is chosen in one place, and a typo in the URL is a
/// startup failure rather than every node failing to get certificates.
pub fn acme_from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<wireserve_types::AcmeSettings, ConfigError> {
    let get = |key: &str| lookup(key).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let directory = get("WIRESERVE_ACME_DIRECTORY").unwrap_or_else(|| wireserve_types::LETS_ENCRYPT_DIRECTORY.to_string());
    if !directory.starts_with("https://") || directory.contains(char::is_whitespace) {
        return Err(ConfigError::Invalid("WIRESERVE_ACME_DIRECTORY", format!("{directory:?} is not an https:// URL")));
    }
    let email = get("WIRESERVE_ACME_EMAIL");
    if let Some(e) = &email {
        let valid = e.split_once('@').is_some_and(|(user, host)| {
            !user.is_empty() && wireserve_types::is_valid_hostname(host) && !e.contains(char::is_whitespace)
        });
        if !valid {
            return Err(ConfigError::Invalid("WIRESERVE_ACME_EMAIL", format!("{e:?} is not an email address")));
        }
    }
    let propagation_secs = match get("WIRESERVE_ACME_PROPAGATION_SECS") {
        None => 60,
        Some(raw) => match raw.parse::<u32>() {
            Ok(s) if s <= 600 => s,
            _ => return Err(ConfigError::Invalid("WIRESERVE_ACME_PROPAGATION_SECS", format!("{raw:?} is not 0..=600"))),
        },
    };
    Ok(wireserve_types::AcmeSettings { directory, email, propagation_secs })
}

/// The sign-in settings (PLAN.md M34). `None` unless `WIRESERVE_AUTH_SERVICE`
/// names the service running the provider; the rest default to authward's.
pub fn sign_in_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
    dns: bool,
) -> Result<Option<wireserve_types::SignIn>, ConfigError> {
    let get = |key: &str| lookup(key).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let Some(service) = get("WIRESERVE_AUTH_SERVICE") else {
        return Ok(None);
    };
    let service = service.to_ascii_lowercase();
    if !wireserve_types::is_valid_dns_label(&service) {
        return Err(ConfigError::Invalid("WIRESERVE_AUTH_SERVICE", format!("{service:?} must be a service name")));
    }
    if !dns {
        return Err(ConfigError::Invalid(
            "WIRESERVE_AUTH_SERVICE",
            "is set but WIRESERVE_DNS_PROVIDER is not; the sign-in is built into each node's TLS \
             terminator, which needs the DNS records"
                .into(),
        ));
    }
    let verify_path = get("WIRESERVE_AUTH_VERIFY_PATH").unwrap_or_else(|| "/verify".into());
    if !verify_path.starts_with('/') || verify_path.contains(char::is_whitespace) || verify_path.contains('#') {
        return Err(ConfigError::Invalid("WIRESERVE_AUTH_VERIFY_PATH", format!("{verify_path:?} is not a path")));
    }
    let copy_headers: Vec<String> = get("WIRESERVE_AUTH_COPY_HEADERS")
        .unwrap_or_else(|| "X-Auth-User X-Auth-Email X-Auth-Groups".into())
        .split([' ', ','])
        .filter(|h| !h.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    let reserved = ["host", "cookie", "authorization", "x-wireserve-node", "content-length", "transfer-encoding", "connection"];
    for h in &copy_headers {
        let token = !h.is_empty() && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !token || reserved.contains(&h.as_str()) || h.starts_with("x-forwarded-") || h == "forwarded" {
            return Err(ConfigError::Invalid("WIRESERVE_AUTH_COPY_HEADERS", format!("{h:?} cannot be copied from the sign-in")));
        }
    }
    let session_cookie = get("WIRESERVE_AUTH_SESSION_COOKIE").unwrap_or_else(|| "authward_session".into());
    if !session_cookie.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(ConfigError::Invalid("WIRESERVE_AUTH_SESSION_COOKIE", format!("{session_cookie:?} is not a cookie name")));
    }
    Ok(Some(wireserve_types::SignIn { service, verify_path, copy_headers, session_cookie }))
}

/// The result of [`Config::load`]: the config itself, plus which first-run
/// values (if any) were freshly generated this call and where they were
/// persisted — `main` uses these two to print a one-time banner.
/// See the comment where it is used in [`Config::load`].
pub const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:47820";

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
    fn the_node_api_listens_on_loopback_unless_told_otherwise() {
        let addr: SocketAddr = DEFAULT_LISTEN_ADDR.parse().unwrap();
        assert!(addr.ip().is_loopback());
    }

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
    fn acme_defaults_to_lets_encrypt_and_checks_what_it_is_given() {
        let none = acme_from_lookup(|_| None).unwrap();
        assert_eq!(none.directory, wireserve_types::LETS_ENCRYPT_DIRECTORY);
        assert_eq!((none.email, none.propagation_secs), (None, 60));
        let bad = |k: &'static str, v: &'static str| {
            matches!(acme_from_lookup(move |key| (key == k).then(|| v.to_string())), Err(ConfigError::Invalid(key, _)) if key == k)
        };
        assert!(bad("WIRESERVE_ACME_DIRECTORY", "http://acme.test/dir"));
        assert!(bad("WIRESERVE_ACME_EMAIL", "not-an-address"));
        assert!(bad("WIRESERVE_ACME_PROPAGATION_SECS", "3600"));
    }

    #[test]
    fn sign_in_defaults_to_authward_and_needs_dns() {
        let only = |k: &str| (k == "WIRESERVE_AUTH_SERVICE").then(|| "Auth".to_string());
        assert_eq!(sign_in_from_lookup(|_| None, true).unwrap(), None);
        let s = sign_in_from_lookup(only, true).unwrap().unwrap();
        assert_eq!((s.service.as_str(), s.verify_path.as_str(), s.session_cookie.as_str()), ("auth", "/verify", "authward_session"));
        assert_eq!(s.copy_headers, vec!["x-auth-user", "x-auth-email", "x-auth-groups"]);
        assert!(sign_in_from_lookup(only, false).is_err(), "without DNS there is nothing to terminate");
        for (k, v) in [
            ("WIRESERVE_AUTH_COPY_HEADERS", "X-Auth-User Cookie"),
            ("WIRESERVE_AUTH_COPY_HEADERS", "X-Forwarded-For"),
            ("WIRESERVE_AUTH_VERIFY_PATH", "verify"),
            ("WIRESERVE_AUTH_SESSION_COOKIE", "a;b"),
        ] {
            let l = move |key: &str| match key {
                "WIRESERVE_AUTH_SERVICE" => Some("auth".to_string()),
                x if x == k => Some(v.to_string()),
                _ => None,
            };
            assert!(matches!(sign_in_from_lookup(l, true), Err(ConfigError::Invalid(key, _)) if key == k), "{k}={v}");
        }
    }

    #[test]
    fn rejects_public_ipv6() {
        let addr: SocketAddr = "[2001:db8::1]:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_err());
    }
}
