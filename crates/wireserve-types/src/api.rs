//! Every wire struct from spec §4. Single source of truth for the wire
//! format — coordinator, agent, and admin all serialize/deserialize these
//! same types, never hand-duplicated structs.

use serde::{Deserialize, Serialize};

use crate::node::{NodeKind, Proto};

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNodeResponse {
    pub name: String,
    pub join_token: String,
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
    pub port: u16,
    pub proto: Proto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_addr: Option<String>,
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
    pub ip4: String,
    pub port: u16,
    pub proto: Proto,
    pub online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollResponse {
    pub peers: Vec<PeerInfo>,
    pub services: Vec<ServiceInfo>,
}

// ---- §4.5 Admin: rejoin ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejoinResponse {
    pub name: String,
    pub join_token: String,
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
    }

    #[test]
    fn poll_request_defaults_services_to_empty_when_omitted() {
        let json = r#"{}"#;
        let req: PollRequest = serde_json::from_str(json).unwrap();
        assert!(req.services.is_empty());
        assert!(req.endpoint_addr.is_none());
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
                last_handshake: None,
            }],
            services: vec![ServiceInfo {
                name: "plex".into(),
                node: "homeserver".into(),
                ip4: "100.90.0.3".into(),
                port: 32400,
                proto: Proto::Tcp,
                online: true,
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: PollResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.peers.len(), 1);
        assert_eq!(back.services[0].name, "plex");
        assert_eq!(back.services[0].proto, Proto::Tcp);
    }
}
