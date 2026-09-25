//! Agent-local IPC wire format (spec §4.6 — unspecified by the design doc;
//! PLAN.md decisions log #4 resolves it as newline-delimited JSON, one
//! request/response per connection).

use serde::{Deserialize, Serialize};
use wireserve_types::{PeerInfo, PortMap, Proto};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcRequest {
    /// `port`/`proto` is the whole declaration from a CLI that predates
    /// port mappings, and the first mapping's target from one that
    /// doesn't; `ports`, when present, is what is declared.
    Serve {
        name: String,
        port: u16,
        proto: Proto,
        #[serde(default)]
        ports: Vec<PortMap>,
    },
    /// `Serve` for a declaration with at least one mapping onto another
    /// address (PLAN.md M26), under its own op so that a daemon from before
    /// target addresses refuses it as an unknown request instead of
    /// dropping the address it doesn't know and mapping the port onto the
    /// node itself — the router's port 80 turning into the node's own.
    ServeForwarding {
        name: String,
        port: u16,
        proto: Proto,
        ports: Vec<PortMap>,
    },
    Unserve { name: String },
    /// This node's live opt-in to carry transit traffic for other mesh
    /// peers (PLAN.md M23) — `wireserve-agent transit on|off`. Same shape
    /// as `Serve`/`Unserve`: mutates the running daemon's state directly,
    /// takes effect next poll, no rejoin.
    TransitCapable { enabled: bool },
    List,
    Leave,
}

/// A service as shown by `wireserve list`, with `local` distinguishing
/// "declared by this node" from "seen in the directory but owned by
/// someone else" — spec's `wireserve list` needs to show both, but the
/// wire-level `ServiceInfo` (used for `/poll`'s directory) has no such
/// flag, since a coordinator response has no concept of "local".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalServiceView {
    pub name: String,
    pub node: String,
    pub ip4: String,
    pub port: u16,
    pub proto: Proto,
    /// The service's own address and mappings; see `ServiceInfo`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vip4: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortMap>,
    pub online: bool,
    pub local: bool,
    /// Declared by this node and accepted by the coordinator, but waiting
    /// on an admin's approval before any other node's hosts file gets it.
    /// Only ever true for a local declaration.
    ///
    /// A pending service already showed up in `list` before this flag
    /// existed — as a declared name absent from the directory — but was
    /// indistinguishable from "not polled yet". This is what tells the
    /// operator which of the two they are looking at.
    #[serde(default)]
    pub pending: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListView {
    /// Which agent instance answered, and the interface it runs on — with
    /// several agents on one host, the first thing to know about a listing.
    #[serde(default)]
    pub instance: String,
    #[serde(default)]
    pub ifname: String,
    /// This node's own name in the mesh, once a poll has told it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// This node's own live opt-in to carry transit traffic for other
    /// mesh peers (PLAN.md M23) — see `state::AgentState::transit_capable`.
    #[serde(default)]
    pub transit_capable: bool,
    /// Every active transit pairing this node is currently carrying, as
    /// of the last poll — see `wireserve_types::PollResponse::transit_carrying`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transit_carrying: Vec<wireserve_types::TransitPair>,
    /// Opted in, but no admin has approved this node as a carrier yet —
    /// see `wireserve_types::PollResponse::transit_awaiting_approval`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub transit_awaiting_approval: bool,
    /// The domain services are named under (PLAN.md M25), so `list` shows
    /// the same name the hosts file writes. Absent means `.wg`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_domain: Option<String>,
    /// The coordinator's view of every peer, as of the last poll.
    pub peers: Vec<PeerInfo>,
    /// The kernel's view of the same peers, read when `list` asked: the
    /// endpoint WireGuard is really using (the coordinator only knows the
    /// candidates, and this node may have picked another, or the peer may
    /// have roamed) and the real last handshake. Empty when the interface
    /// couldn't be read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tunnel: Vec<TunnelPeer>,
    pub services: Vec<LocalServiceView>,
    /// Declarations the coordinator rejected (name collision, spec §4.3)
    /// — surfaced here rather than silently vanishing (security review
    /// F3) so `wireserve list` tells the operator *why* a `serve` call
    /// didn't take effect.
    #[serde(default)]
    pub rejected_services: Vec<crate::state::RejectedService>,
}

/// One peer as the kernel's WireGuard interface reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelPeer {
    pub pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// `None` until the first handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_handshake: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IpcResponse {
    Ok,
    Error { message: String },
    List(ListView),
}

impl IpcResponse {
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}

/// Parses one line of client input into a request. Used directly by tests
/// that want to exercise malformed-input handling without a real socket,
/// and by the connection handler for the real thing.
pub fn parse_request(line: &str) -> Result<IpcRequest, String> {
    serde_json::from_str(line.trim()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrips_through_json() {
        let req = IpcRequest::Serve {
            name: "plex".into(),
            port: 32400,
            proto: Proto::Tcp,
            ports: vec![],
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: IpcRequest = serde_json::from_str(&json).unwrap();
        match back {
            IpcRequest::Serve { name, port, .. } => {
                assert_eq!(name, "plex");
                assert_eq!(port, 32400);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn response_roundtrips_through_json() {
        let resp = IpcResponse::error("boom");
        let json = serde_json::to_string(&resp).unwrap();
        let back: IpcResponse = serde_json::from_str(&json).unwrap();
        matches!(back, IpcResponse::Error { .. });
    }

    #[test]
    fn parse_request_rejects_malformed_json() {
        assert!(parse_request("not json at all").is_err());
        assert!(parse_request("").is_err());
    }

    #[test]
    fn parse_request_rejects_valid_json_with_unknown_op() {
        assert!(parse_request(r#"{"op":"not_a_real_op"}"#).is_err());
    }

    #[test]
    fn parse_request_accepts_valid_list_request() {
        assert!(matches!(parse_request(r#"{"op":"list"}"#), Ok(IpcRequest::List)));
    }
}
