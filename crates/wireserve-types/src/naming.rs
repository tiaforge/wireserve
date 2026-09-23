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

use serde::{Deserialize, Serialize};

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
}

/// The port whose publication means "serve this under its name, with TLS".
///
/// Deliberately an existing field rather than a new per-service attribute: it
/// needs no schema change, and it is what keeps a Postgres or SSH service from
/// acquiring a public hostname and a certificate it never asked for. The proxy
/// still speaks plain HTTP to the backend — 443 is the *published* port, and
/// the owning node's rewrite maps it to whatever the service really listens
/// on, so there is no second TLS hop.
pub const TLS_PUBLIC_PORT: u16 = 443;
