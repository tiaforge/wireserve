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
    /// The sign-in restricted services fall back to (PLAN.md M34, M36).
    /// Only with DNS records, which terminated services need.
    pub sign_in: Option<wireserve_types::SignIn>,
    /// The headers backends learn who is calling from (PLAN.md M36).
    pub identity_headers: wireserve_types::IdentityHeaders,
    /// Further request headers the terminators remove (`WIRESERVE_STRIP_HEADERS`).
    pub strip_headers: Vec<String>,
    /// Nodes whose forwarding headers the terminators keep
    /// (`WIRESERVE_FORWARDING_NODES`, PLAN.md M43).
    pub forwarding_nodes: Vec<String>,
    /// Services that take requests other sites start
    /// (`WIRESERVE_CROSS_SITE_SERVICES`, PLAN.md #276).
    pub cross_site_services: Vec<String>,
    /// Where browsers and nodes reach the coordinator, e.g.
    /// `https://mesh.example.com` (`WIRESERVE_PUBLIC_URL`), without a
    /// trailing slash. Needed for the claim links of device owners.
    pub public_url: Option<String>,
    /// Device owners through an identity provider (PLAN.md M38).
    pub oidc: Option<OidcConfig>,
    /// Where the service names are published as public DNS records
    /// (PLAN.md M32). `None` leaves DNS to the operator, as before.
    pub dns: Option<crate::dns::DnsConfig>,
    /// The CA every node's terminator gets certificates from (PLAN.md M33).
    /// Only handed to nodes while `dns` is set: without the coordinator
    /// writing the challenge records, no certificate can be issued.
    pub acme: wireserve_types::AcmeSettings,
    pub online_threshold_secs: i64,
    /// The first relay port (PLAN.md M39, `WIRESERVE_RELAY_PORT_BASE`): a
    /// node's relay port is this plus its slot.
    pub relay_port_base: u16,
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
    /// How many `/poll`s one node may make at once, and how many a minute
    /// it may keep making — per node, after it has authenticated. 0 a minute
    /// turns the limit off.
    pub poll_rate_burst: u32,
    pub poll_rate_per_min: u32,
    /// Service names nobody may newly declare (`WIRESERVE_RESERVED_SERVICE_NAMES`,
    /// comma-separated), on top of the coordinator's own host name when it
    /// lies under the service domain.
    pub reserved_service_names: Vec<String>,
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
        let bootstrapped_token_key = bootstrapped.oidc_token_key;

        let online_threshold_secs = env_parse_or("WIRESERVE_ONLINE_THRESHOLD_SECS", 180)?;
        let relay_port_base = relay_port_base_from(env_parse_or("WIRESERVE_RELAY_PORT_BASE", wireserve_types::DEFAULT_RELAY_PORT_BASE)?)?;
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
        let reserved_service_names = reserved_names_from(std::env::var("WIRESERVE_RESERVED_SERVICE_NAMES").ok().as_deref())?;
        let poll_rate_burst = env_parse_or("WIRESERVE_POLL_RATE_BURST", 20u32)?;
        let poll_rate_per_min = env_parse_or("WIRESERVE_POLL_RATE_PER_MIN", 30u32)?;
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
        let identity_headers = identity_headers_from_lookup(|k| std::env::var(k).ok())?;
        let strip_headers = strip_headers_from(std::env::var("WIRESERVE_STRIP_HEADERS").ok().as_deref())?;
        let forwarding_nodes = forwarding_nodes_from(std::env::var("WIRESERVE_FORWARDING_NODES").ok().as_deref())?;
        let cross_site_services = cross_site_services_from(std::env::var("WIRESERVE_CROSS_SITE_SERVICES").ok().as_deref())?;
        let public_url = public_url_from_lookup(|k| std::env::var(k).ok())?;
        let oidc = oidc_from_lookup(|k| std::env::var(k).ok(), public_url.as_deref(), &bootstrapped_token_key)?;

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
                identity_headers,
                strip_headers,
                forwarding_nodes,
                cross_site_services,
                public_url,
                oidc,
                dns,
                acme,
                online_threshold_secs,
                relay_port_base,
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
                poll_rate_burst,
                poll_rate_per_min,
                reserved_service_names,
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

/// `WIRESERVE_RELAY_PORT_BASE`: room above it for every relay port and,
/// after them, the range a carrier's relayed phone sessions leave from
/// (PLAN.md M40), and not a privileged port.
fn relay_port_base_from(base: u16) -> Result<u16, ConfigError> {
    let top = u32::from(base) + 2 * u32::from(wireserve_types::RELAY_SLOTS);
    if base < 1024 || top > 65536 {
        return Err(ConfigError::Invalid(
            "WIRESERVE_RELAY_PORT_BASE",
            format!(
                "{base} leaves no room: relay ports run from it to {} above it, and must stay between 1024 and 65535",
                2 * wireserve_types::RELAY_SLOTS - 1
            ),
        ));
    }
    Ok(base)
}

/// `WIRESERVE_STRIP_HEADERS`: header names, comma-separated, lowercased.
/// Never one a request cannot do without.
pub fn strip_headers_from(raw: Option<&str>) -> Result<Vec<String>, ConfigError> {
    let vital = ["host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer"];
    let mut out: Vec<String> = Vec::new();
    for h in raw.unwrap_or("").split(',').map(|h| h.trim().to_ascii_lowercase()).filter(|h| !h.is_empty()) {
        let token = h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !token || vital.contains(&h.as_str()) {
            return Err(ConfigError::Invalid("WIRESERVE_STRIP_HEADERS", format!("{h:?} cannot be stripped")));
        }
        if !out.contains(&h) {
            out.push(h);
        }
    }
    Ok(out)
}

/// `WIRESERVE_FORWARDING_NODES`: node names, comma-separated, lowercased.
pub fn forwarding_nodes_from(raw: Option<&str>) -> Result<Vec<String>, ConfigError> {
    let mut out: Vec<String> = Vec::new();
    for name in raw.unwrap_or("").split(',').map(|n| n.trim().to_ascii_lowercase()).filter(|n| !n.is_empty()) {
        if !wireserve_types::is_valid_dns_label(&name) {
            return Err(ConfigError::Invalid("WIRESERVE_FORWARDING_NODES", format!("{name:?} is not a node name")));
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    Ok(out)
}

/// `WIRESERVE_CROSS_SITE_SERVICES` (PLAN.md #276): service names,
/// comma-separated, validated as labels.
pub fn cross_site_services_from(raw: Option<&str>) -> Result<Vec<String>, ConfigError> {
    let mut out: Vec<String> = Vec::new();
    for name in raw.unwrap_or("").split(',').map(|n| n.trim().to_ascii_lowercase()).filter(|n| !n.is_empty()) {
        if !wireserve_types::is_valid_dns_label(&name) {
            return Err(ConfigError::Invalid("WIRESERVE_CROSS_SITE_SERVICES", format!("{name:?} is not a service name")));
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    Ok(out)
}

/// `WIRESERVE_RESERVED_SERVICE_NAMES`: service names, comma-separated.
pub fn reserved_names_from(raw: Option<&str>) -> Result<Vec<String>, ConfigError> {
    let mut out = Vec::new();
    for name in raw.unwrap_or("").split(',').map(|n| n.trim().to_ascii_lowercase()).filter(|n| !n.is_empty()) {
        if !wireserve_types::is_valid_dns_label(&name) {
            return Err(ConfigError::Invalid("WIRESERVE_RESERVED_SERVICE_NAMES", format!("{name:?} is not a service name")));
        }
        out.push(name);
    }
    Ok(out)
}

impl Config {
    /// Why nobody may newly declare a service called `name`, if so: it is
    /// listed as reserved, or it is this coordinator's own host name under
    /// the service domain (a service by that name would point it somewhere
    /// else in public DNS).
    #[must_use]
    pub fn reserved_reason(&self, name: &str) -> Option<&'static str> {
        if self.reserved_service_names.iter().any(|r| r == name) {
            return Some("reserved by the operator");
        }
        let host = self.public_url.as_deref()?.split_once("://")?.1.split(['/', ':']).next()?.to_ascii_lowercase();
        let domain = self.service_domain.as_deref()?.trim_end_matches('.').to_ascii_lowercase();
        let label = host.strip_suffix(&format!(".{domain}"))?;
        (label == name).then_some("the coordinator's own name")
    }

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
            identity_headers: self.identity_headers.clone(),
            strip_headers: self.strip_headers.clone(),
            forwarding_nodes: self.forwarding_nodes.clone(),
            cross_site_services: self.cross_site_services.clone(),
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
/// names the service running the provider and `WIRESERVE_AUTH_NODE` the node
/// it must run on; the rest default to authward's.
///
/// The node pins the provider: every request to a service behind the
/// sign-in goes to it, cookies included, and its answer decides who gets
/// in. Were it known by service name alone, whichever node declared that
/// name next — after the real provider withdrew it — would take its place.
/// Without the node the sign-in stays off, with a warning, so a coordinator
/// configured before the setting existed still starts.
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
    let Some(node) = get("WIRESERVE_AUTH_NODE") else {
        tracing::warn!(
            "WIRESERVE_AUTH_SERVICE is set but WIRESERVE_AUTH_NODE is not; the sign-in stays off until it names \
             the node that runs `{service}`"
        );
        return Ok(None);
    };
    let node = node.to_ascii_lowercase();
    if !wireserve_types::is_valid_dns_label(&node) {
        return Err(ConfigError::Invalid("WIRESERVE_AUTH_NODE", format!("{node:?} must be a node name")));
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
    let session_cookie = get("WIRESERVE_AUTH_SESSION_COOKIE").unwrap_or_else(|| "authward_session".into());
    if !session_cookie.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(ConfigError::Invalid("WIRESERVE_AUTH_SESSION_COOKIE", format!("{session_cookie:?} is not a cookie name")));
    }
    Ok(Some(wireserve_types::SignIn { service, node, verify_path, session_cookie }))
}

/// Signing in the owner of a device (PLAN.md M38): an OpenID Connect
/// client of the operator's identity provider — the same one the sign-in
/// provider uses, so group names mean the same thing on both paths.
#[derive(Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    /// The claim the provider lists a person's groups in.
    pub groups_claim: String,
    /// How often each owner's groups are fetched again.
    pub refresh_interval: std::time::Duration,
    /// Seals refresh tokens at rest; see `bootstrap::OIDC_TOKEN_KEY`.
    pub token_key: [u8; 32],
    /// `<public url>/claim/callback`.
    pub redirect_url: String,
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .field("groups_claim", &self.groups_claim)
            .field("refresh_interval", &self.refresh_interval)
            .finish_non_exhaustive()
    }
}

/// `WIRESERVE_PUBLIC_URL`: an `http(s)://` URL, kept without a trailing
/// slash.
pub fn public_url_from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Option<String>, ConfigError> {
    let Some(url) = lookup("WIRESERVE_PUBLIC_URL").map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"));
    let host = rest.map(|r| r.split('/').next().unwrap_or_default()).unwrap_or_default();
    if host.is_empty() || url.contains(char::is_whitespace) || url.contains(['?', '#']) {
        return Err(ConfigError::Invalid("WIRESERVE_PUBLIC_URL", format!("{url:?} is not an http(s):// URL")));
    }
    Ok(Some(url.trim_end_matches('/').to_string()))
}

/// The device owners' identity provider (PLAN.md M38): off unless
/// `WIRESERVE_OIDC_ISSUER` is set, and then `_CLIENT_ID`, `_CLIENT_SECRET`
/// and `WIRESERVE_PUBLIC_URL` are required.
pub fn oidc_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
    public_url: Option<&str>,
    token_key_hex: &str,
) -> Result<Option<OidcConfig>, ConfigError> {
    let get = |key: &str| lookup(key).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let Some(issuer) = get("WIRESERVE_OIDC_ISSUER") else {
        return Ok(None);
    };
    if !(issuer.starts_with("https://") || issuer.starts_with("http://")) || issuer.contains(char::is_whitespace) {
        return Err(ConfigError::Invalid("WIRESERVE_OIDC_ISSUER", format!("{issuer:?} is not an http(s):// URL")));
    }
    let client_id = get("WIRESERVE_OIDC_CLIENT_ID")
        .ok_or_else(|| ConfigError::Invalid("WIRESERVE_OIDC_CLIENT_ID", "is required with WIRESERVE_OIDC_ISSUER".into()))?;
    let client_secret = get("WIRESERVE_OIDC_CLIENT_SECRET").ok_or_else(|| {
        ConfigError::Invalid("WIRESERVE_OIDC_CLIENT_SECRET", "is required with WIRESERVE_OIDC_ISSUER".into())
    })?;
    let public_url = public_url.ok_or_else(|| {
        ConfigError::Invalid(
            "WIRESERVE_PUBLIC_URL",
            "is required with WIRESERVE_OIDC_ISSUER: the identity provider sends browsers back to it".into(),
        )
    })?;
    let scopes: Vec<String> = get("WIRESERVE_OIDC_SCOPES")
        .unwrap_or_else(|| "openid email profile groups offline_access".into())
        .split([' ', ','])
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if !scopes.iter().any(|s| s == "openid") {
        return Err(ConfigError::Invalid("WIRESERVE_OIDC_SCOPES", "must include openid".into()));
    }
    let groups_claim = get("WIRESERVE_OIDC_GROUPS_CLAIM").unwrap_or_else(|| "groups".into());
    let refresh_secs: u64 = match get("WIRESERVE_OIDC_REFRESH_SECS") {
        None => 900,
        Some(raw) => match raw.parse::<u64>() {
            Ok(s) if (60..=86_400).contains(&s) => s,
            _ => return Err(ConfigError::Invalid("WIRESERVE_OIDC_REFRESH_SECS", format!("{raw:?} is not 60..=86400"))),
        },
    };
    let token_key = parse_key(token_key_hex).ok_or_else(|| {
        ConfigError::Invalid("WIRESERVE_OIDC_TOKEN_KEY", "must be 64 hexadecimal characters (32 bytes)".into())
    })?;
    Ok(Some(OidcConfig {
        issuer: issuer.trim_end_matches('/').to_string(),
        client_id,
        client_secret,
        scopes,
        groups_claim,
        refresh_interval: std::time::Duration::from_secs(refresh_secs),
        token_key,
        redirect_url: format!("{public_url}/claim/callback"),
    }))
}

fn parse_key(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The headers backends learn who is calling from (PLAN.md M36):
/// `WIRESERVE_AUTH_USER_HEADER`, `_EMAIL_HEADER` and `_GROUPS_HEADER`,
/// authward's names unless set. Every terminator removes them from every
/// request a client sends, so none may be a header anything else relies
/// on.
pub fn identity_headers_from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<wireserve_types::IdentityHeaders, ConfigError> {
    let get = |key: &str| lookup(key).map(|v| v.trim().to_ascii_lowercase()).filter(|v| !v.is_empty());
    if get("WIRESERVE_AUTH_COPY_HEADERS").is_some() {
        tracing::warn!(
            "WIRESERVE_AUTH_COPY_HEADERS is no longer read; the identity headers are WIRESERVE_AUTH_USER_HEADER, \
             WIRESERVE_AUTH_EMAIL_HEADER and WIRESERVE_AUTH_GROUPS_HEADER"
        );
    }
    let defaults = wireserve_types::IdentityHeaders::default();
    let reserved = ["host", "cookie", "authorization", "x-wireserve-node", "content-length", "transfer-encoding", "connection"];
    let pick = |key: &'static str, default: String| -> Result<String, ConfigError> {
        let h = get(key).unwrap_or(default);
        let token = !h.is_empty() && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !token || reserved.contains(&h.as_str()) || h.starts_with("x-forwarded-") || h == "forwarded" {
            return Err(ConfigError::Invalid(key, format!("{h:?} cannot be an identity header")));
        }
        Ok(h)
    };
    let headers = wireserve_types::IdentityHeaders {
        user: pick("WIRESERVE_AUTH_USER_HEADER", defaults.user)?,
        email: pick("WIRESERVE_AUTH_EMAIL_HEADER", defaults.email)?,
        groups: pick("WIRESERVE_AUTH_GROUPS_HEADER", defaults.groups)?,
    };
    let [a, b, c] = headers.names();
    if a == b || b == c || a == c {
        return Err(ConfigError::Invalid("WIRESERVE_AUTH_USER_HEADER", "the three identity headers must differ".into()));
    }
    Ok(headers)
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
/// This is not a correctness problem for wireserve by itself — the mesh
/// works fine on any range the operator picks — but it collides with
/// whatever else on the host already claims that space. Tailscale is the
/// common case: it routes all of `100.64.0.0/10` to its own interface, so
/// a mesh address inside that block can end up resolving to a route
/// pointing at `tailscale0` rather than `wg0`, and traffic meant for a
/// wireserve peer leaves over the tailnet instead (or goes nowhere).
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

    fn sample() -> Config {
        Config {
            listen_addr: "127.0.0.1:47820".parse().unwrap(),
            admin_listen_addr: "127.0.0.1:47821".parse().unwrap(),
            admin_token: "t".into(),
            db_path: "x.db".into(),
            net_v4_cidr: "10.1.2.0/24".into(),
            net_v6_prefix: "fdab:cdef:1234::/64".into(),
            service_domain: None,
            dns: None,
            acme: acme_from_lookup(|_| None).unwrap(),
            sign_in: None,
            identity_headers: Default::default(),
            public_url: None,
            oidc: None,
            online_threshold_secs: 180,
            relay_port_base: wireserve_types::DEFAULT_RELAY_PORT_BASE,
            rate_limit_max: 10,
            rate_limit_window_secs: 60,
            trust_proxy_headers: false,
            trusted_proxy: None,
            join_token_ttl_secs: 1800,
            global_auth_failure_max: 20,
            global_auth_failure_window_secs: 60,
            require_service_approval: true,
            reflexive_rate_limit_max: 20,
            reflexive_rate_limit_window_secs: 10,
            poll_rate_burst: 20,
            poll_rate_per_min: 0,
            reserved_service_names: Vec::new(),
            strip_headers: Vec::new(),
            forwarding_nodes: Vec::new(),
            cross_site_services: Vec::new(),
        }
    }

    fn reserving(names: &[&str], public_url: Option<&str>, domain: Option<&str>) -> Config {
        let mut c = sample();
        c.reserved_service_names = names.iter().map(|n| (*n).to_string()).collect();
        c.public_url = public_url.map(String::from);
        c.service_domain = domain.map(String::from);
        c
    }

    #[test]
    fn a_name_is_reserved_when_listed_or_when_it_is_the_coordinators_own_under_the_domain() {
        let c = reserving(&["www"], Some("https://Coord.Int.Example.com:8443/x"), Some("int.example.com."));
        assert_eq!(c.reserved_reason("www"), Some("reserved by the operator"));
        assert_eq!(c.reserved_reason("coord"), Some("the coordinator's own name"));
        assert_eq!(c.reserved_reason("plex"), None);
        // Elsewhere, or several labels deep, it is not a service name at all.
        assert_eq!(reserving(&[], Some("https://coord.example.org"), Some("int.example.com")).reserved_reason("coord"), None);
        assert_eq!(reserving(&[], Some("https://a.b.int.example.com"), Some("int.example.com")).reserved_reason("a"), None);
        assert_eq!(reserving(&[], None, None).reserved_reason("coord"), None);
    }

    #[test]
    fn extra_stripped_headers_are_header_names_and_never_ones_a_request_needs() {
        assert_eq!(strip_headers_from(Some(" X-Corp-User, x-corp-user ,Remote-Roles,")).unwrap(), ["x-corp-user", "remote-roles"]);
        assert!(strip_headers_from(None).unwrap().is_empty());
        assert_eq!(forwarding_nodes_from(Some(" Strato, strato ,edge,")).unwrap(), ["strato", "edge"]);
        assert!(forwarding_nodes_from(None).unwrap().is_empty());
        assert!(forwarding_nodes_from(Some("not a node")).is_err());
        assert_eq!(cross_site_services_from(Some(" Wiki,wiki ,erp,")).unwrap(), ["wiki", "erp"]);
        assert!(cross_site_services_from(None).unwrap().is_empty());
        assert!(cross_site_services_from(Some("not a name")).is_err());
        for bad in ["host", "Content-Length", "a b", "x:y"] {
            assert!(strip_headers_from(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_reserved_list_is_service_names_and_nothing_else() {
        assert_eq!(reserved_names_from(Some(" WWW, mail ,,")).unwrap(), ["www", "mail"]);
        assert!(reserved_names_from(None).unwrap().is_empty());
        assert!(reserved_names_from(Some("ok,not a name")).is_err());
    }

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
        let only = |k: &str| match k {
            "WIRESERVE_AUTH_SERVICE" => Some("Auth".to_string()),
            "WIRESERVE_AUTH_NODE" => Some("Homeserver".to_string()),
            _ => None,
        };
        assert_eq!(sign_in_from_lookup(|_| None, true).unwrap(), None);
        let s = sign_in_from_lookup(only, true).unwrap().unwrap();
        assert_eq!((s.service.as_str(), s.verify_path.as_str(), s.session_cookie.as_str()), ("auth", "/verify", "authward_session"));
        assert_eq!(s.node, "homeserver");
        let no_node = |k: &str| (k == "WIRESERVE_AUTH_SERVICE").then(|| "auth".to_string());
        assert_eq!(sign_in_from_lookup(no_node, true).unwrap(), None, "no node: off, not a startup failure");
        assert!(sign_in_from_lookup(only, false).is_err(), "without DNS there is nothing to terminate");
        for (k, v) in [
            ("WIRESERVE_AUTH_VERIFY_PATH", "verify"),
            ("WIRESERVE_AUTH_SESSION_COOKIE", "a;b"),
            ("WIRESERVE_AUTH_NODE", "not a node"),
        ] {
            let l = move |key: &str| match key {
                x if x == k => Some(v.to_string()),
                "WIRESERVE_AUTH_SERVICE" => Some("auth".to_string()),
                "WIRESERVE_AUTH_NODE" => Some("homeserver".to_string()),
                _ => None,
            };
            assert!(matches!(sign_in_from_lookup(l, true), Err(ConfigError::Invalid(key, _)) if key == k), "{k}={v}");
        }
    }

    #[test]
    fn identity_headers_default_to_authward_and_refuse_what_others_rely_on() {
        let h = identity_headers_from_lookup(|_| None).unwrap();
        assert_eq!(h, wireserve_types::IdentityHeaders::default());
        let one = |k: &'static str, v: &'static str| move |key: &str| (key == k).then(|| v.to_string());
        let h = identity_headers_from_lookup(one("WIRESERVE_AUTH_GROUPS_HEADER", "Remote-Groups")).unwrap();
        assert_eq!(h.groups, "remote-groups");
        for (k, v) in [
            ("WIRESERVE_AUTH_USER_HEADER", "Cookie"),
            ("WIRESERVE_AUTH_EMAIL_HEADER", "X-Forwarded-For"),
            ("WIRESERVE_AUTH_GROUPS_HEADER", "not a header"),
            ("WIRESERVE_AUTH_EMAIL_HEADER", "x-auth-user"),
        ] {
            assert!(identity_headers_from_lookup(one(k, v)).is_err(), "{k}={v}");
        }
    }

    #[test]
    fn oidc_needs_its_client_and_a_public_url() {
        let key = "ab".repeat(32);
        let all = |k: &str| match k {
            "WIRESERVE_OIDC_ISSUER" => Some("https://id.example.com/".to_string()),
            "WIRESERVE_OIDC_CLIENT_ID" => Some("wireserve".to_string()),
            "WIRESERVE_OIDC_CLIENT_SECRET" => Some("s3cret".to_string()),
            _ => None,
        };
        assert!(oidc_from_lookup(|_| None, None, &key).unwrap().is_none(), "off unless an issuer is set");
        let o = oidc_from_lookup(all, Some("https://mesh.example.com"), &key).unwrap().unwrap();
        assert_eq!(o.issuer, "https://id.example.com");
        assert_eq!(o.redirect_url, "https://mesh.example.com/claim/callback");
        assert!(o.scopes.contains(&"offline_access".to_string()));
        assert_eq!(o.groups_claim, "groups");
        assert_eq!(o.token_key, [0xab; 32]);
        assert!(!format!("{o:?}").contains("s3cret"), "the secret stays out of logs");
        assert!(oidc_from_lookup(all, None, &key).is_err(), "no public URL");
        assert!(oidc_from_lookup(all, Some("https://m"), "short").is_err(), "a broken key");
        let no_secret = |k: &str| if k == "WIRESERVE_OIDC_CLIENT_SECRET" { None } else { all(k) };
        assert!(oidc_from_lookup(no_secret, Some("https://m"), &key).is_err());
        let no_openid = |k: &str| if k == "WIRESERVE_OIDC_SCOPES" { Some("email groups".into()) } else { all(k) };
        assert!(oidc_from_lookup(no_openid, Some("https://m"), &key).is_err());
    }

    #[test]
    fn a_public_url_is_an_http_url() {
        let one = |v: &'static str| move |k: &str| (k == "WIRESERVE_PUBLIC_URL").then(|| v.to_string());
        assert_eq!(public_url_from_lookup(one("https://mesh.example.com/")).unwrap().as_deref(), Some("https://mesh.example.com"));
        assert_eq!(public_url_from_lookup(one("http://10.0.0.5:47820")).unwrap().as_deref(), Some("http://10.0.0.5:47820"));
        for bad in ["mesh.example.com", "https://", "https://a b", "https://m/?x"] {
            assert!(public_url_from_lookup(one(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_public_ipv6() {
        let addr: SocketAddr = "[2001:db8::1]:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_err());
    }
}
