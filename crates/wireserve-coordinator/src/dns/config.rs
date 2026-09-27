//! Which DNS provider holds the service domain, and how to write to it
//! (PLAN.md M32).
//!
//! A curated set rather than everything `dns-update` knows: each provider
//! takes different credentials, so each is a hand-written mapping, and only
//! the ones people are likely to use are worth that. Adding one is an enum
//! variant, its fields and an arm in `provider::connect`.

use std::fmt;

use crate::config::ConfigError;

/// The TTL written when none is configured. Short enough that a service
/// moving to another address is seen within minutes, long enough that
/// resolvers are not asking on every connection.
pub const DEFAULT_TTL: u32 = 300;

#[derive(Clone, PartialEq, Eq)]
pub struct DnsConfig {
    pub provider: DnsProvider,
    /// The zone the records are written into — the service domain itself,
    /// or a parent of it.
    pub zone: String,
    pub ttl: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub enum DnsProvider {
    /// RFC 2136 dynamic update, signed with TSIG: BIND, Knot, PowerDNS and
    /// anything else speaking the standard.
    Rfc2136 {
        /// `udp://host:port`, `tcp://host:port` or `host:port` (UDP).
        server: String,
        key_name: String,
        /// The key as BIND prints it: base64.
        secret: Vec<u8>,
        /// One of [`TSIG_ALGORITHMS`]. Kept as the name: `dns-update`'s own
        /// enum is neither `Clone` nor `PartialEq`, which `Config` needs.
        algorithm: &'static str,
    },
    Cloudflare { token: String },
    Desec { token: String },
    Hetzner { token: String },
    Porkbun { api_key: String, secret: String },
}

impl DnsProvider {
    /// The name the operator writes in `WIRESERVE_DNS_PROVIDER`.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Rfc2136 { .. } => "rfc2136",
            Self::Cloudflare { .. } => "cloudflare",
            Self::Desec { .. } => "desec",
            Self::Hetzner { .. } => "hetzner",
            Self::Porkbun { .. } => "porkbun",
        }
    }
}

/// Every name `WIRESERVE_DNS_PROVIDER` accepts, for messages and the
/// install wizard.
pub const PROVIDERS: [&str; 5] = ["rfc2136", "cloudflare", "desec", "hetzner", "porkbun"];

/// One setting a provider needs, as the install wizard asks for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    pub key: &'static str,
    pub label: &'static str,
    /// Read without echo, and never shown as a default.
    pub secret: bool,
    pub default: Option<&'static str>,
}

const RFC2136_FIELDS: &[Field] = &[
    Field { key: "WIRESERVE_DNS_SERVER", label: "DNS server that accepts updates (host:port)", secret: false, default: None },
    Field { key: "WIRESERVE_DNS_TSIG_KEY_NAME", label: "TSIG key name", secret: false, default: None },
    Field { key: "WIRESERVE_DNS_TSIG_SECRET", label: "TSIG secret (base64)", secret: true, default: None },
    Field {
        key: "WIRESERVE_DNS_TSIG_ALGORITHM",
        label: "TSIG algorithm",
        secret: false,
        default: Some("hmac-sha256"),
    },
];
const CLOUDFLARE_FIELDS: &[Field] =
    &[Field { key: "WIRESERVE_DNS_API_TOKEN", label: "Cloudflare API token", secret: true, default: None }];
const DESEC_FIELDS: &[Field] =
    &[Field { key: "WIRESERVE_DNS_API_TOKEN", label: "deSEC token", secret: true, default: None }];
const HETZNER_FIELDS: &[Field] =
    &[Field { key: "WIRESERVE_DNS_API_TOKEN", label: "Hetzner API token", secret: true, default: None }];
const PORKBUN_FIELDS: &[Field] = &[
    Field { key: "WIRESERVE_DNS_API_TOKEN", label: "Porkbun API key (pk1_…)", secret: true, default: None },
    Field { key: "WIRESERVE_DNS_API_SECRET", label: "Porkbun secret API key (sk1_…)", secret: true, default: None },
];

/// Where to get what [`fields`] asks for, in a few plain lines.
#[must_use]
pub fn help(provider: &str) -> &'static [&'static str] {
    match provider {
        "cloudflare" => &[
            "In the Cloudflare dashboard: My Profile → API Tokens → Create Token,",
            "then the \"Edit zone DNS\" template, limited to your domain.",
        ],
        "desec" => &["At desec.io: Token Management → add a token."],
        "hetzner" => &[
            "In the Hetzner Console, in the project that holds your domain's DNS:",
            "Security → API tokens → Generate API token, with Read & Write.",
            "(A token from the old DNS Console at dns.hetzner.com will not work.)",
        ],
        "porkbun" => &[
            "At porkbun.com: Account → API Access → create a key. Then, under",
            "Domain Management, switch on \"API Access\" for your domain too.",
        ],
        "rfc2136" => &[
            "Your own DNS server (BIND, Knot, PowerDNS) must accept dynamic",
            "updates (RFC 2136) for the domain, signed with a TSIG key.",
        ],
        _ => &[],
    }
}

/// The settings `provider` needs, in the order the wizard asks for them.
#[must_use]
pub fn fields(provider: &str) -> &'static [Field] {
    match provider {
        "rfc2136" => RFC2136_FIELDS,
        "porkbun" => PORKBUN_FIELDS,
        "cloudflare" => CLOUDFLARE_FIELDS,
        "desec" => DESEC_FIELDS,
        "hetzner" => HETZNER_FIELDS,
        _ => &[],
    }
}

/// Every credential key any provider reads: what switching provider, or
/// turning DNS off, clears so no stale secret is left behind.
pub const CREDENTIAL_KEYS: [&str; 6] = [
    "WIRESERVE_DNS_SERVER",
    "WIRESERVE_DNS_TSIG_KEY_NAME",
    "WIRESERVE_DNS_TSIG_SECRET",
    "WIRESERVE_DNS_TSIG_ALGORITHM",
    "WIRESERVE_DNS_API_TOKEN",
    "WIRESERVE_DNS_API_SECRET",
];

// Never print a credential: `Config` is `Debug`, and a config dump in a log
// or a bug report must not carry a live DNS token.
impl fmt::Debug for DnsProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rfc2136 { server, key_name, algorithm, .. } => f
                .debug_struct("Rfc2136")
                .field("server", server)
                .field("key_name", key_name)
                .field("algorithm", algorithm)
                .finish_non_exhaustive(),
            other => write!(f, "{}(..)", other.name()),
        }
    }
}

impl fmt::Debug for DnsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsConfig")
            .field("provider", &self.provider)
            .field("zone", &self.zone)
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// Reads the DNS settings through `lookup` (the environment, in
/// production). `None` when no provider is set.
///
/// Every mistake is a startup failure, never a silent "DNS off": an
/// operator who set a provider expects names to appear, and a typo that
/// quietly disabled them would look like a provider outage.
pub fn from_lookup(
    lookup: impl Fn(&str) -> Option<String>,
    service_domain: Option<&str>,
) -> Result<Option<DnsConfig>, ConfigError> {
    let get = |key: &str| lookup(key).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let Some(kind) = get("WIRESERVE_DNS_PROVIDER") else {
        return Ok(None);
    };
    let Some(domain) = service_domain else {
        return Err(ConfigError::Invalid(
            "WIRESERVE_DNS_PROVIDER",
            "is set but WIRESERVE_SERVICE_DOMAIN is not; the records are named under that domain".into(),
        ));
    };
    let need = |key: &'static str| {
        get(key).ok_or_else(|| ConfigError::Invalid(key, format!("is required for the {kind} DNS provider")))
    };

    let provider = match kind.to_ascii_lowercase().as_str() {
        "rfc2136" => {
            let server = need("WIRESERVE_DNS_SERVER")?;
            if dns_update::providers::rfc2136::DnsAddress::try_from(server.as_str()).is_err() {
                return Err(ConfigError::Invalid(
                    "WIRESERVE_DNS_SERVER",
                    format!("{server:?} is not udp://host:port, tcp://host:port or host:port"),
                ));
            }
            let key_name = need("WIRESERVE_DNS_TSIG_KEY_NAME")?;
            let secret = {
                use base64::Engine as _;
                let raw = need("WIRESERVE_DNS_TSIG_SECRET")?;
                base64::engine::general_purpose::STANDARD.decode(&raw).map_err(|_| {
                    ConfigError::Invalid("WIRESERVE_DNS_TSIG_SECRET", "is not base64 (paste the key's secret as BIND prints it)".into())
                })?
            };
            let algorithm = match get("WIRESERVE_DNS_TSIG_ALGORITHM") {
                None => "hmac-sha256",
                Some(a) => {
                    let wanted = a.trim_end_matches('.').to_ascii_lowercase();
                    TSIG_ALGORITHMS.into_iter().find(|known| *known == wanted).ok_or_else(|| {
                        ConfigError::Invalid(
                            "WIRESERVE_DNS_TSIG_ALGORITHM",
                            format!("{a:?} is not one of {}", TSIG_ALGORITHMS.join(", ")),
                        )
                    })?
                }
            };
            DnsProvider::Rfc2136 { server, key_name, secret, algorithm }
        }
        "cloudflare" => DnsProvider::Cloudflare { token: need("WIRESERVE_DNS_API_TOKEN")? },
        "desec" => DnsProvider::Desec { token: need("WIRESERVE_DNS_API_TOKEN")? },
        "hetzner" => DnsProvider::Hetzner { token: need("WIRESERVE_DNS_API_TOKEN")? },
        "porkbun" => DnsProvider::Porkbun {
            api_key: need("WIRESERVE_DNS_API_TOKEN")?,
            secret: need("WIRESERVE_DNS_API_SECRET")?,
        },
        _ => {
            return Err(ConfigError::Invalid(
                "WIRESERVE_DNS_PROVIDER",
                format!("{kind:?} is not one of {}", PROVIDERS.join(", ")),
            ))
        }
    };

    let zone = get("WIRESERVE_DNS_ZONE")
        .map(|z| z.trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_else(|| domain.to_ascii_lowercase());
    if !wireserve_types::is_valid_hostname(&zone) {
        return Err(ConfigError::Invalid("WIRESERVE_DNS_ZONE", format!("{zone:?} is not a valid domain")));
    }
    if !is_within(&domain.to_ascii_lowercase(), &zone) {
        return Err(ConfigError::Invalid(
            "WIRESERVE_DNS_ZONE",
            format!("{zone:?} does not contain the service domain {domain:?}"),
        ));
    }

    let ttl = match get("WIRESERVE_DNS_TTL") {
        None => DEFAULT_TTL,
        Some(raw) => match raw.parse::<u32>() {
            Ok(t) if (30..=86_400).contains(&t) => t,
            _ => return Err(ConfigError::Invalid("WIRESERVE_DNS_TTL", format!("{raw:?} is not 30..=86400 seconds"))),
        },
    };

    Ok(Some(DnsConfig { provider, zone, ttl }))
}

/// Whether `name` is `zone` or a name under it.
fn is_within(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{zone}"))
}

/// The TSIG algorithms accepted, as BIND names them. HMAC-MD5 is left out
/// on purpose.
pub const TSIG_ALGORITHMS: [&str; 5] = ["hmac-sha256", "hmac-sha384", "hmac-sha512", "hmac-sha224", "hmac-sha1"];

/// `dns-update`'s value for one of [`TSIG_ALGORITHMS`].
#[must_use]
pub fn tsig_algorithm(name: &str) -> dns_update::TsigAlgorithm {
    use dns_update::TsigAlgorithm as A;
    match name {
        "hmac-sha1" => A::HmacSha1,
        "hmac-sha224" => A::HmacSha224,
        "hmac-sha384" => A::HmacSha384,
        "hmac-sha512" => A::HmacSha512,
        _ => A::HmacSha256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(pairs: &[(&str, &str)], domain: Option<&str>) -> Result<Option<DnsConfig>, ConfigError> {
        let map: std::collections::HashMap<String, String> =
            pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect();
        from_lookup(|k| map.get(k).cloned(), domain)
    }

    fn err_key(r: Result<Option<DnsConfig>, ConfigError>) -> &'static str {
        match r {
            Err(ConfigError::Invalid(key, _)) => key,
            other => panic!("expected a config error, got {other:?}"),
        }
    }

    const RFC2136: [(&str, &str); 4] = [
        ("WIRESERVE_DNS_PROVIDER", "rfc2136"),
        ("WIRESERVE_DNS_SERVER", "10.0.0.53:53"),
        ("WIRESERVE_DNS_TSIG_KEY_NAME", "wireserve"),
        ("WIRESERVE_DNS_TSIG_SECRET", "c2VjcmV0LWtleS1ieXRlcw=="),
    ];

    #[test]
    fn no_provider_means_dns_off() {
        assert_eq!(load(&[], Some("int.example.com")).unwrap(), None);
        assert_eq!(load(&[("WIRESERVE_DNS_PROVIDER", " ")], Some("int.example.com")).unwrap(), None);
    }

    #[test]
    fn rfc2136_reads_its_fields_and_defaults_the_rest() {
        let cfg = load(&RFC2136, Some("int.example.com")).unwrap().unwrap();
        assert_eq!(cfg.zone, "int.example.com");
        assert_eq!(cfg.ttl, DEFAULT_TTL);
        match cfg.provider {
            DnsProvider::Rfc2136 { secret, algorithm, .. } => {
                assert_eq!(secret, b"secret-key-bytes");
                assert_eq!(algorithm, "hmac-sha256");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_provider_without_a_domain_is_refused() {
        assert_eq!(err_key(load(&RFC2136, None)), "WIRESERVE_DNS_PROVIDER");
    }

    #[test]
    fn unknown_provider_and_missing_fields_fail_loudly() {
        assert_eq!(err_key(load(&[("WIRESERVE_DNS_PROVIDER", "route53")], Some("a.b"))), "WIRESERVE_DNS_PROVIDER");
        assert_eq!(err_key(load(&[("WIRESERVE_DNS_PROVIDER", "cloudflare")], Some("a.b"))), "WIRESERVE_DNS_API_TOKEN");
        assert_eq!(
            err_key(load(&[("WIRESERVE_DNS_PROVIDER", "porkbun"), ("WIRESERVE_DNS_API_TOKEN", "k")], Some("a.b"))),
            "WIRESERVE_DNS_API_SECRET"
        );
        let mut bad_secret = RFC2136.to_vec();
        bad_secret[3] = ("WIRESERVE_DNS_TSIG_SECRET", "not base64!");
        assert_eq!(err_key(load(&bad_secret, Some("a.b"))), "WIRESERVE_DNS_TSIG_SECRET");
        let mut bad_alg = RFC2136.to_vec();
        bad_alg.push(("WIRESERVE_DNS_TSIG_ALGORITHM", "hmac-md5"));
        assert_eq!(err_key(load(&bad_alg, Some("a.b"))), "WIRESERVE_DNS_TSIG_ALGORITHM");
        let mut bad_server = RFC2136.to_vec();
        bad_server[1] = ("WIRESERVE_DNS_SERVER", "dns.example.com");
        assert_eq!(err_key(load(&bad_server, Some("a.b"))), "WIRESERVE_DNS_SERVER");
    }

    #[test]
    fn the_zone_must_contain_the_service_domain() {
        let mut parent = RFC2136.to_vec();
        parent.push(("WIRESERVE_DNS_ZONE", "Example.com."));
        assert_eq!(load(&parent, Some("int.example.com")).unwrap().unwrap().zone, "example.com");
        let mut unrelated = RFC2136.to_vec();
        unrelated.push(("WIRESERVE_DNS_ZONE", "other.com"));
        assert_eq!(err_key(load(&unrelated, Some("int.example.com"))), "WIRESERVE_DNS_ZONE");
        // A suffix match on the text alone is not containment.
        let mut lookalike = RFC2136.to_vec();
        lookalike.push(("WIRESERVE_DNS_ZONE", "ample.com"));
        assert_eq!(err_key(load(&lookalike, Some("int.example.com"))), "WIRESERVE_DNS_ZONE");
    }

    #[test]
    fn ttl_is_bounded() {
        let mut t = RFC2136.to_vec();
        t.push(("WIRESERVE_DNS_TTL", "5"));
        assert_eq!(err_key(load(&t, Some("a.b"))), "WIRESERVE_DNS_TTL");
        t[4] = ("WIRESERVE_DNS_TTL", "60");
        assert_eq!(load(&t, Some("a.b")).unwrap().unwrap().ttl, 60);
    }

    #[test]
    fn every_field_is_a_credential_key_and_every_provider_has_fields() {
        for p in PROVIDERS {
            assert!(!fields(p).is_empty(), "{p}");
            for f in fields(p) {
                assert!(CREDENTIAL_KEYS.contains(&f.key), "{}", f.key);
            }
        }
    }

    #[test]
    fn debug_never_prints_a_credential() {
        let cfg = load(
            &[("WIRESERVE_DNS_PROVIDER", "cloudflare"), ("WIRESERVE_DNS_API_TOKEN", "cf-live-token")],
            Some("int.example.com"),
        )
        .unwrap()
        .unwrap();
        assert!(!format!("{cfg:?}").contains("cf-live-token"));
        let rfc = load(&RFC2136, Some("int.example.com")).unwrap().unwrap();
        assert!(!format!("{rfc:?}").contains("c2VjcmV0"));
    }
}
