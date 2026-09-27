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

/// The suffix services are named under, and what every node's terminator
/// needs to serve them with TLS.
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
    /// Where each node's terminator gets its certificates (PLAN.md M33).
    /// Present only when the coordinator publishes DNS records, which is
    /// what makes a certificate for a service name obtainable at all.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub acme: Option<AcmeSettings>,
    /// The sign-in in front of services marked for it (PLAN.md M34), built
    /// into every node's terminator. Absent while none is configured.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sign_in: Option<SignIn>,
}

/// Where the terminators ask whether a request may pass (PLAN.md M34): a
/// `forward_auth` provider such as authward, itself a mesh service
/// published on 443.
///
/// The terminator sends each request to a marked service to
/// `https://<service>.<domain><verify_path>` first — on that service's own
/// address, verified against its certificate — with the original `Host`,
/// `X-Forwarded-Method`, `X-Forwarded-Uri` and cookies. A 2xx lets it
/// through with `copy_headers` copied from the answer; a 401 carrying
/// `X-Login-Url` sends the browser there; anything else is returned as is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignIn {
    /// The service running the provider, e.g. `auth`.
    pub service: String,
    pub verify_path: String,
    /// The provider's identity headers. Every one is removed from the
    /// client's request first, whether or not the provider sends it back.
    pub copy_headers: Vec<String>,
    /// The provider's session cookie, removed from every request any
    /// terminator passes to a backend: it is scoped to the whole domain,
    /// and no backend needs it.
    pub session_cookie: String,
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
/// acquiring a certificate it never asked for. The owning node's terminator
/// (PLAN.md M33) answers on 443 and speaks plain HTTP to the service's real
/// target port on the same node, so there is no second TLS hop.
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
/// cannot resolve one way on a node and another way on a phone. Since M34
/// every name points at the service's own address — a 443 service is served
/// with TLS there by its own node, and there is no central proxy any more.
#[derive(Debug, Default, Clone, Copy)]
pub struct ServiceNames<'a> {
    /// The domain services are named under. `None` keeps `<name>.wg`.
    domain: Option<&'a str>,
}

impl<'a> ServiceNames<'a> {
    #[must_use]
    pub fn new(naming: Option<&'a ServiceNaming>) -> Self {
        Self { domain: naming.map(|n| n.domain.as_str()) }
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

    /// Where that name points: the service's own address. `None` for an
    /// address that does not parse.
    #[must_use]
    pub fn address(&self, s: &ServiceInfo) -> Option<Ipv4Addr> {
        own_address(s).parse().ok()
    }
}
