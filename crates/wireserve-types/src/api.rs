//! Every wire struct from spec §4. Single source of truth for the wire
//! format — coordinator, agent, and admin all serialize/deserialize these
//! same types, never hand-duplicated structs.

use serde::{Deserialize, Serialize};

use crate::node::{NodeKind, Proto};
use crate::ports::PortMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
    /// Set only for a `409` from `/poll` caused by a service-name
    /// collision (spec §4.3) — the specific declared name that collided,
    /// as a machine-readable field rather than something the agent has to
    /// string-parse out of `error`. Lets the agent quarantine exactly the
    /// offending declaration instead of the whole poll cycle wedging on
    /// it forever (see PLAN.md decisions log).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub conflicting_service: Option<String>,
}

impl ErrorBody {
    #[must_use]
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            conflicting_service: None,
        }
    }

    #[must_use]
    pub fn service_collision(error: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            conflicting_service: Some(name.into()),
        }
    }
}

// ---- §4.1 Admin: create node ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNodeRequest {
    pub name: String,
    #[serde(default)]
    pub kind: NodeKind,
    /// Override the coordinator's configured join-token lifetime for this
    /// one token, in seconds; `0` means no expiry. Omitted means "use the
    /// coordinator's default" — which is not the same as `Some(0)`, and is
    /// why this is an `Option` rather than a plain `u64` defaulting to 0.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNodeResponse {
    pub name: String,
    pub join_token: String,
    /// When this token stops being redeemable, or `None` if expiry is
    /// disabled. Returned so the operator learns the deadline at the
    /// moment they copy the token, rather than discovering it by having a
    /// `join` fail half an hour later.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub join_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

// ---- Node: address probe (dual-family endpoint self-discovery) ----

/// `GET /probe` response: the bare source address the coordinator saw
/// this request arrive from (via `client_ip::resolve_client`, same as
/// `/register`'s endpoint fallback), no port. Unauthenticated,
/// unrelated to any node's registration state — a node calls it twice,
/// once over a connection forced to IPv4 and once forced to IPv6, purely
/// to learn which families it can actually reach the coordinator over.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResponse {
    pub addr: String,
}

// ---- §4.2 Node: register ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub join_token: String,
    pub pubkey: String,
    #[serde(default)]
    pub kind: NodeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_addr: Option<String>,
    /// Actively self-discovered via the agent's own dual-family probe
    /// against `/probe` (never derived by the coordinator from a single
    /// passively-observed connection, unlike `endpoint_addr`'s fallback) —
    /// see `wireserve-agent`'s `probe` module. Absent for a node that
    /// couldn't reach the coordinator over that family at all, or for an
    /// older agent that predates this field.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint_addr_v4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint_addr_v6: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub bearer_token: String,
    pub ip4: String,
    pub ip6: String,
}

// ---- §4.3 Node: poll ----

/// Upper bound on the services a single node may declare (spec §4.3 puts
/// no limit on the array; this is this project's own cap). Every declared
/// service is fanned out to every other node's `/poll` response and hosts
/// file on every cycle, so without a cap one node could bloat the whole
/// mesh's directory at will.
///
/// **Lives here, not in the coordinator**, for the same reason
/// `is_valid_dns_label` does (spec §3: one definition, called from every
/// place that needs it). The agent enforces the identical limit locally
/// when `serve` queues a declaration: a limit enforced *only* at the
/// coordinator turns an over-eager operator into a permanently wedged
/// agent, because the rejected batch is resent verbatim every cycle and
/// the whole poll — peer reconciliation included — fails with it. That is
/// the same failure shape as the service-name collision handled by
/// `ErrorBody::conflicting_service`, and the cheapest fix is for both
/// sides to agree on the number up front.
pub const MAX_SERVICES_PER_NODE: usize = 64;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDecl {
    pub name: String,
    /// The first mapping's target port and protocol. All a coordinator
    /// from before port mappings understands; a newer one reads `ports`.
    pub port: u16,
    pub proto: Proto,
    /// Public→target mappings on the service's own address. Empty on a
    /// declaration from before port mappings existed, which stands for
    /// the one identity mapping `port:port/proto` — see
    /// [`ServiceDecl::port_maps`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortMap>,
}

impl ServiceDecl {
    /// A declaration of `ports`, which must not be empty (validate with
    /// [`crate::validate_service_ports`] first).
    #[must_use]
    pub fn new(name: impl Into<String>, ports: Vec<PortMap>) -> Self {
        let first = ports[0];
        Self {
            name: name.into(),
            port: first.target,
            proto: first.proto,
            ports,
        }
    }

    /// The mappings this declaration stands for, old form included.
    #[must_use]
    pub fn port_maps(&self) -> Vec<PortMap> {
        effective_ports(&self.ports, self.port, self.proto)
    }
}

fn effective_ports(ports: &[PortMap], port: u16, proto: Proto) -> Vec<PortMap> {
    if ports.is_empty() {
        vec![PortMap::identity(port, proto)]
    } else {
        ports.to_vec()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_addr: Option<String>,
    /// See `RegisterRequest::endpoint_addr_v4`'s doc comment — same
    /// active self-discovery, re-run every poll cycle.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint_addr_v4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint_addr_v6: Option<String>,
    #[serde(default)]
    pub services: Vec<ServiceDecl>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub name: String,
    pub pubkey: String,
    pub ip4: String,
    pub ip6: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_addr: Option<String>,
    /// This peer's actively self-discovered candidates — see
    /// `RegisterRequest::endpoint_addr_v4`. `endpoint_addr` above (an
    /// operator's explicit override, or the older passive fallback) still
    /// wins over both when present; see `wg::choose_peer_endpoint`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint_addr_v4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint_addr_v6: Option<String>,
    /// See PLAN.md decisions log #3: approximated from the coordinator's
    /// own `last_seen` bookkeeping, not a true WireGuard handshake
    /// observation (the coordinator is never itself a WireGuard peer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_handshake: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub node: String,
    /// The owning NODE's address. Older agents write this into their
    /// hosts file; newer ones prefer `vip4`.
    pub ip4: String,
    pub port: u16,
    pub proto: Proto,
    pub online: bool,
    /// The service's own address, which `<name>.wg` resolves to and every
    /// peer routes to the owning node. `None` from a coordinator that
    /// predates service addresses, or for a declaration from an agent
    /// that does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vip4: Option<String>,
    /// Empty from a coordinator that predates port mappings; see
    /// [`ServiceInfo::port_maps`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortMap>,
}

impl ServiceInfo {
    /// The mappings this entry stands for, old form included.
    #[must_use]
    pub fn port_maps(&self) -> Vec<PortMap> {
        effective_ports(&self.ports, self.port, self.proto)
    }
}

/// A declaration the coordinator accepted and stored but has NOT put in
/// the directory, because service approval is required and no admin has
/// approved it for this node yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingService {
    pub name: String,
    pub port: u16,
    pub proto: Proto,
    /// The address the service will have once approved. Sent to its owner
    /// alone, so the owner's firewall is ready the moment approval puts
    /// the service in everyone else's directory — nothing routes to it
    /// before then.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vip4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub declared_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A declaration an admin explicitly refused. The agent drops it from
/// `declared_services` on receipt — exactly as it does for a name
/// collision — which both withdraws the advertisement and closes the
/// local firewall hole, since firewall rules derive from that list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeniedService {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub denied_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Cap on an admin-supplied denial reason.
///
/// It rides back to the declaring node on every poll until that node
/// quarantines the declaration, and then sits in `wireserve list` output.
/// Lives here, not in the coordinator, so `wireserve-admin` can refuse an
/// over-long one before spending a round trip — the same reasoning as
/// [`MAX_SERVICES_PER_NODE`].
pub const MAX_DENY_REASON_LEN: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollResponse {
    pub peers: Vec<PeerInfo>,
    pub services: Vec<ServiceInfo>,
    /// THIS node's own declarations awaiting approval — never anyone
    /// else's.
    ///
    /// Reported on a **successful** response, not as an error, and that
    /// is load-bearing. Any `/poll` error aborts the whole cycle: peer
    /// reconciliation, firewall and hosts sync are all skipped, and since
    /// the agent resends the same declaration every cycle, an error for a
    /// pending declaration would fail identically forever — the node
    /// would stop seeing new peers and would never see its own
    /// revocation. Pending is a normal, possibly long-lived state.
    ///
    /// `skip_serializing_if` also means these bytes are absent whenever
    /// nothing is pending, so "approval disabled behaves exactly as
    /// before" holds at the wire level for free.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_services: Vec<PendingService>,
    /// THIS node's own declarations an admin refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_services: Vec<DeniedService>,
}

/// Approval state of a service, as reported to the admin. Derived from
/// the stored timestamps rather than stored itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceApprovalState {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminServiceInfo {
    pub name: String,
    pub node: String,
    pub ip4: String,
    pub port: u16,
    pub proto: Proto,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vip4: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortMap>,
    pub state: ServiceApprovalState,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub declared_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub approved_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub denied_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub denied_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminServicesResponse {
    pub services: Vec<AdminServiceInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DenyServiceRequest {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
}

// ---- §4.5 Admin: rejoin ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejoinRequest {
    /// Same meaning as `CreateNodeRequest::ttl_secs`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejoinResponse {
    pub name: String,
    pub join_token: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub join_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

// ---- §4.5.1 Admin: list peers ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPeersResponse {
    pub peers: Vec<PeerInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_request_defaults_kind_to_agent_when_omitted() {
        let json = r#"{"join_token":"jtk_x","pubkey":"abc"}"#;
        let req: RegisterRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.kind, NodeKind::Agent);
        assert!(req.listen_port.is_none());
        assert!(req.endpoint_addr.is_none());
        assert!(req.endpoint_addr_v4.is_none());
        assert!(req.endpoint_addr_v6.is_none());
    }

    #[test]
    fn poll_request_defaults_services_to_empty_when_omitted() {
        let json = r#"{}"#;
        let req: PollRequest = serde_json::from_str(json).unwrap();
        assert!(req.services.is_empty());
        assert!(req.endpoint_addr.is_none());
        assert!(req.endpoint_addr_v4.is_none());
        assert!(req.endpoint_addr_v6.is_none());
    }

    #[test]
    fn poll_response_omits_the_approval_fields_when_empty() {
        // The wire half of "approval disabled behaves exactly as before":
        // the keys must be absent from the JSON, not merely empty arrays.
        let resp = PollResponse {
            peers: vec![],
            services: vec![],
            pending_services: vec![],
            denied_services: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("pending_services"), "{json}");
        assert!(!json.contains("denied_services"), "{json}");
    }

    #[test]
    fn poll_response_without_the_approval_fields_still_deserializes() {
        // An older coordinator's response reaching a newer agent, and a
        // state file written before the fields existed.
        let resp: PollResponse = serde_json::from_str(r#"{"peers":[],"services":[]}"#).unwrap();
        assert!(resp.pending_services.is_empty());
        assert!(resp.denied_services.is_empty());
    }

    #[test]
    fn a_declaration_without_ports_stands_for_its_identity_mapping() {
        // What an agent from before port mappings sends, and what its
        // state file holds.
        let d: ServiceDecl = serde_json::from_str(r#"{"name":"plex","port":32400,"proto":"tcp"}"#).unwrap();
        assert!(d.ports.is_empty());
        assert_eq!(d.port_maps(), vec![PortMap::identity(32400, Proto::Tcp)]);
    }

    #[test]
    fn a_new_declaration_still_carries_port_and_proto_for_old_coordinators() {
        let maps = vec!["80:5080".parse().unwrap(), "53/udp".parse().unwrap()];
        let d = ServiceDecl::new("web", maps);
        let json: serde_json::Value = serde_json::to_value(&d).unwrap();
        assert_eq!(json["port"], 5080);
        assert_eq!(json["proto"], "tcp");
        assert_eq!(json["ports"][0], serde_json::json!({"public": 80, "target": 5080, "proto": "tcp"}));
        assert_eq!(d.port_maps(), d.ports);
    }

    #[test]
    fn a_service_entry_from_an_old_coordinator_has_no_address_and_one_mapping() {
        let s: ServiceInfo = serde_json::from_str(
            r#"{"name":"plex","node":"n","ip4":"10.0.0.3","port":32400,"proto":"tcp","online":true}"#,
        )
        .unwrap();
        assert!(s.vip4.is_none());
        assert_eq!(s.port_maps(), vec![PortMap::identity(32400, Proto::Tcp)]);
        // And the new fields stay off the wire when unset, so an old agent
        // sees exactly the shape it always did.
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("vip4") && !json.contains("ports"), "{json}");
    }

    #[test]
    fn poll_response_roundtrips() {
        let resp = PollResponse {
            peers: vec![PeerInfo {
                name: "homeserver".into(),
                pubkey: "abc".into(),
                ip4: "100.90.0.3".into(),
                ip6: "fd00:90::3".into(),
                endpoint_addr: Some("duckdns.example.com:51820".into()),
                endpoint_addr_v4: Some("203.0.113.5:51820".into()),
                endpoint_addr_v6: None,
                last_handshake: None,
            }],
            services: vec![ServiceInfo {
                name: "plex".into(),
                node: "homeserver".into(),
                ip4: "100.90.0.3".into(),
                port: 32400,
                proto: Proto::Tcp,
                online: true,
                vip4: None,
                ports: vec![],
            }],
            pending_services: vec![],
            denied_services: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: PollResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.peers.len(), 1);
        assert_eq!(
            back.peers[0].endpoint_addr_v4.as_deref(),
            Some("203.0.113.5:51820")
        );
        assert!(back.peers[0].endpoint_addr_v6.is_none());
        assert_eq!(back.services[0].name, "plex");
        assert_eq!(back.services[0].proto, Proto::Tcp);
    }
}
