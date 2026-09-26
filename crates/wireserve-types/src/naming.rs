//! How services are named on the mesh (PLAN.md M25).
//!
//! By default a service is `<name>.wg`, resolved out of each agent's managed
//! `/etc/hosts` block and pointing straight at the service's own address. That
//! works everywhere an agent runs and nowhere else — a phone has no hosts file,
//! which is the gap this exists to close.
//!
//! Setting a domain replaces the suffix rather than adding to it, and the
//! replacement is the point. An app has one configured base URL — Gitea's
//! `ROOT_URL`, Grafana's `root_url`, an OIDC `redirect_uri` — so a second
//! working name is not a convenience, it is a source of sessions and redirects
//! that bounce between the two. One service, one name.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::{Proto, ServiceInfo};

/// The suffix services are named under, and which service fronts the ones
/// published on 443.
///
/// Mesh-wide, and carried on every poll and registration the same way
/// [`crate::MeshInfo`] is: nodes that disagreed about the suffix would
/// disagree about their own services' names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceNaming {
    /// The domain services are named under, e.g. `int.example.com`, giving
    /// `plex.int.example.com`. Absent from the wire entirely when unset,
    /// which leaves `<name>.wg` exactly as it was.
    pub domain: String,
    /// The service that terminates TLS for everything published on 443.
    ///
    /// A *service* name rather than a node name, for three reasons: the proxy
    /// is reached at a service address, a node could publish several things on
    /// 443, and this is the same value the operator puts in the wildcard DNS
    /// record. `None` means no proxy is configured yet, and services published
    /// on 443 keep resolving to their own address rather than losing their
    /// names.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub proxy_service: Option<String>,
    /// Where each node's terminator gets its certificates (PLAN.md M33).
    /// Present only when the coordinator publishes DNS records, which is
    /// what makes a certificate for a service name obtainable at all.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub acme: Option<AcmeSettings>,
}

/// The certificate authority every terminator uses, set once on the
/// coordinator (PLAN.md M33).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeSettings {
    /// The ACME directory URL: Let's Encrypt's production one unless the
    /// operator set another.
    pub directory: String,
    /// The contact address given to the CA, if the operator set one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email: Option<String>,
    /// How long to wait after the challenge record is written before
    /// asking the CA to look, so the record has reached every one of the
    /// zone's nameservers.
    pub propagation_secs: u32,
}

/// Let's Encrypt's production ACME directory.
pub const LETS_ENCRYPT_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// The port whose publication means "serve this under its name, with TLS".
///
/// Deliberately an existing field rather than a new per-service attribute: it
/// needs no schema change, and it is what keeps a Postgres or SSH service from
/// acquiring a public hostname and a certificate it never asked for. The proxy
/// still speaks plain HTTP to the backend — 443 is the *published* port, and
/// the owning node's rewrite maps it to whatever the service really listens
/// on, so there is no second TLS hop.
pub const TLS_PUBLIC_PORT: u16 = 443;

/// Whether this service publishes [`TLS_PUBLIC_PORT`] over TCP.
#[must_use]
pub fn publishes_tls(s: &ServiceInfo) -> bool {
    s.port_maps().iter().any(|m| m.public == TLS_PUBLIC_PORT && m.proto == Proto::Tcp)
}

/// A service's own address: the one the coordinator gave it, else its
/// owning node's. Unparsed, as it came off the wire.
#[must_use]
pub fn own_address(s: &ServiceInfo) -> &str {
    s.vip4.as_deref().unwrap_or(&s.ip4)
}

/// What every service is called this cycle and where that name points.
///
/// The one place this is decided (PLAN.md M32): each agent's hosts file
/// and the coordinator's public DNS records both come from it, so a name
/// cannot resolve one way on a node and another way on a phone.
///
/// Resolved once from the coordinator's `naming` and the directory itself,
/// rather than threaded field by field: deciding a service's address needs
/// the proxy's address, and that is only knowable by looking the proxy
/// service up in the same directory.
#[derive(Debug, Default, Clone, Copy)]
pub struct ServiceNames<'a> {
    /// The domain services are named under. `None` keeps `<name>.wg`.
    domain: Option<&'a str>,
    /// The address of the service fronting everything published on 443.
    proxy: Option<Ipv4Addr>,
}

impl<'a> ServiceNames<'a> {
    /// Reads the coordinator's setting against the current directory.
    ///
    /// A configured proxy that is missing, unapproved or malformed leaves
    /// [`Self::proxy`] as `None`, which costs 443 services their proxied
    /// path but not their names — they fall back to resolving directly,
    /// which is what they did before a domain was set.
    #[must_use]
    pub fn new(naming: Option<&'a ServiceNaming>, services: &[ServiceInfo]) -> Self {
        let Some(naming) = naming else {
            return Self::default();
        };
        let proxy = naming.proxy_service.as_deref().and_then(|want| {
            services
                .iter()
                .find(|s| s.name == want)
                .and_then(|s| own_address(s).parse::<Ipv4Addr>().ok())
        });
        Self { domain: Some(&naming.domain), proxy }
    }

    /// The proxy's address, when one is configured and in the directory.
    #[must_use]
    pub fn proxy(&self) -> Option<Ipv4Addr> {
        self.proxy
    }

    /// `<name>.wg`, or `<name>.<domain>` once a domain is set. The suffix is
    /// replaced rather than added to: an app has one configured base URL, so
    /// a second working name produces redirects and sessions that bounce
    /// between the two.
    #[must_use]
    pub fn host_name(&self, s: &ServiceInfo) -> String {
        match self.domain {
            Some(domain) => format!("{}.{domain}", s.name),
            None => format!("{}.wg", s.name),
        }
    }

    /// Where that name points: the proxy for a service published on 443
    /// that its own node does not serve with TLS (PLAN.md M33), its own
    /// address otherwise. `None` for an address that does not parse.
    ///
    /// Publishing 443 is the signal that a service wants to be served under
    /// its name with TLS, so its name has to resolve to the same place from a
    /// node as it does from a phone — otherwise the scheme differs by where
    /// you are standing, and one configured base URL cannot be right in both.
    /// Everything else keeps the direct path, and with it the real client
    /// address and no extra hop.
    #[must_use]
    pub fn address(&self, s: &ServiceInfo) -> Option<Ipv4Addr> {
        match (self.proxy, publishes_tls(s) && !s.terminated) {
            (Some(proxy), true) => Some(proxy),
            _ => own_address(s).parse().ok(),
        }
    }
}
