//! Agent-local IPC wire format (spec §4.6 — unspecified by the design doc;
//! PLAN.md decisions log #4 resolves it as newline-delimited JSON, one
//! request/response per connection).

use serde::{Deserialize, Serialize};
use wireserve_types::{PeerInfo, Proto};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcRequest {
    Serve { name: String, port: u16, proto: Proto },
    Unserve { name: String },
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
    pub peers: Vec<PeerInfo>,
    pub services: Vec<LocalServiceView>,
    /// Declarations the coordinator rejected (name collision, spec §4.3)
    /// — surfaced here rather than silently vanishing (security review
    /// F3) so `wireserve list` tells the operator *why* a `serve` call
    /// didn't take effect.
    #[serde(default)]
    pub rejected_services: Vec<crate::state::RejectedService>,
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
