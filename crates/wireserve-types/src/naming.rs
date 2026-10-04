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
    /// The sign-in restricted services fall back to (PLAN.md M36, M48),
    /// checked by every node's terminator. Absent while none is configured.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sign_in: Option<SignIn>,
    /// The headers a backend learns who is calling from (PLAN.md M36).
    #[serde(default)]
    pub identity_headers: IdentityHeaders,
    /// Further request headers every terminator removes before a backend sees
    /// the request, on top of the built-in list (`WIRESERVE_STRIP_HEADERS`):
    /// for a backend that believes a header of its own naming about who is
    /// calling or where from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strip_headers: Vec<String>,
    /// Nodes whose requests may name their own client (PLAN.md M43,
    /// `WIRESERVE_FORWARDING_NODES`): an operator's reverse proxy — a Caddy
    /// on a public host — whose `X-Forwarded-For` and `X-Forwarded-Host`
    /// the terminators keep instead of removing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwarding_nodes: Vec<String>,
    /// Services that take requests other sites start (PLAN.md #276,
    /// `WIRESERVE_CROSS_SITE_SERVICES`): an app that is itself a sign-in
    /// client and gets its answer as a form POST from the provider, say.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cross_site_services: Vec<String>,
}

/// The headers a terminator tells a backend who is calling in — filled
/// from whoever signed in (PLAN.md M48), or from the calling device's owner
/// (PLAN.md M38) — and removes from every request a client sends, on every
/// service, whether or not anything fills them. Named once, on the
/// coordinator; `X-Auth-*` unless set otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityHeaders {
    pub user: String,
    pub email: String,
    /// Group names, separated by `groups_separator`.
    pub groups: String,
    /// What a backend expects between group names: `,` or `|` (PLAN.md
    /// M47).
    #[serde(default = "comma", skip_serializing_if = "is_comma")]
    pub groups_separator: char,
}

fn comma() -> char {
    ','
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde passes a reference
fn is_comma(c: &char) -> bool {
    *c == ','
}

/// The separators a groups header may use.
pub const GROUPS_SEPARATORS: [char; 2] = [',', '|'];

impl Default for IdentityHeaders {
    fn default() -> Self {
        Self {
            user: "x-auth-user".into(),
            email: "x-auth-email".into(),
            groups: "x-auth-groups".into(),
            groups_separator: comma(),
        }
    }
}

impl IdentityHeaders {
    /// All three, lowercase.
    #[must_use]
    pub fn names(&self) -> [&str; 3] {
        [&self.user, &self.email, &self.groups]
    }

    /// A groups header's value: names split on the separator, trimmed,
    /// empty ones dropped. Only the configured separator splits — a group
    /// called `x|admins` stays one group where the separator is `,`, and
    /// never becomes `admins`.
    #[must_use]
    pub fn split_groups(&self, value: &str) -> Vec<String> {
        value.split(self.groups_separator).map(str::trim).filter(|g| !g.is_empty()).map(str::to_string).collect()
    }

    /// The groups header's value for `groups`. A name holding the separator
    /// could not be read back as itself, so it is left out.
    #[must_use]
    pub fn join_groups(&self, groups: &[String]) -> String {
        let sep = self.groups_separator.to_string();
        groups.iter().filter(|g| !g.contains(self.groups_separator)).map(String::as_str).collect::<Vec<_>>().join(&sep)
    }
}

/// The sign-in (PLAN.md M48): the coordinator signs people in with its own
/// OpenID Connect client, and every terminator checks the session tokens
/// it signs. A terminator never talks to the identity provider, and holds
/// nothing that could make a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignIn {
    /// The coordinator's public key for session tokens
    /// ([`crate::session::public_key`]).
    pub public_key: String,
    /// Where a browser goes to sign in: the coordinator's public address.
    pub login_url: String,
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

/// Where the terminator really listens (PLAN.md M35), on every address:
/// the agent rewrites a service address's [`TLS_PUBLIC_PORT`] to it, so
/// 443 itself stays free for a Caddy, Stalwart or nginx on the same host.
/// Unprivileged, so the terminator needs no capability at all; held by
/// systemd (`wireserve-tls.socket`) so no other local user can take it.
/// Below the Kubernetes NodePort range and the kernel's ephemeral ports,
/// and clear of the alternative HTTPS ports other software claims (4443,
/// 6443, 7443, 8443, 9443).
pub const TLS_LISTEN_PORT: u16 = 11443;

/// Whether this service publishes [`TLS_PUBLIC_PORT`] over TCP.
#[must_use]
pub fn publishes_tls(s: &ServiceInfo) -> bool {
    s.ports.iter().any(|m| m.public == TLS_PUBLIC_PORT && m.proto == Proto::Tcp)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_split_on_the_configured_separator_only() {
        let comma = IdentityHeaders::default();
        assert_eq!(comma.split_groups("family, admins,,  "), ["family", "admins"]);
        assert!(comma.split_groups("").is_empty());
        assert_eq!(comma.split_groups("x|admins"), ["x|admins"], "never admins");
        let pipe = IdentityHeaders { groups_separator: '|', ..IdentityHeaders::default() };
        assert_eq!(pipe.split_groups("family|admins"), ["family", "admins"]);
        assert_eq!(pipe.split_groups("a,b"), ["a,b"]);
    }

    #[test]
    fn a_group_holding_the_separator_is_left_out_when_joined() {
        let pipe = IdentityHeaders { groups_separator: '|', ..IdentityHeaders::default() };
        let groups = vec!["family".to_string(), "x|admins".to_string(), "ops".to_string()];
        assert_eq!(pipe.join_groups(&groups), "family|ops");
        assert_eq!(IdentityHeaders::default().join_groups(&groups), "family,x|admins,ops");
    }

    #[test]
    fn the_separator_is_left_out_of_the_wire_unless_it_is_a_pipe() {
        let json = serde_json::to_string(&IdentityHeaders::default()).unwrap();
        assert!(!json.contains("groups_separator"), "{json}");
        let old: IdentityHeaders =
            serde_json::from_str(r#"{"user":"u","email":"e","groups":"g"}"#).unwrap();
        assert_eq!(old.groups_separator, ',');
        let pipe = IdentityHeaders { groups_separator: '|', ..IdentityHeaders::default() };
        let back: IdentityHeaders = serde_json::from_str(&serde_json::to_string(&pipe).unwrap()).unwrap();
        assert_eq!(back, pipe);
    }
}
