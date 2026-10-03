//! What the agent and its TLS terminator say to each other (PLAN.md M33),
//! over a socket of their own — never the agent's main one, which can also
//! declare or withdraw services, and `leave`.
//!
//! Newline-delimited JSON, one request and one response per connection,
//! like the main socket. Two requests only: the terminator checks in and
//! gets its configuration, and it asks for an ACME challenge record to be
//! published or withdrawn. An unknown `op` is refused.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::naming::{AcmeSettings, IdentityHeaders};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum TlsRequest {
    /// "I serve exactly these services right now, on this port; what should
    /// I serve?" The port is the one the terminator's socket really has
    /// (PLAN.md M35): the agent rewrites a service's 443 to it. `seen` are
    /// the known devices that connected since the last check-in.
    CheckIn {
        serving: Vec<String>,
        port: u16,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        seen: Vec<Ipv4Addr>,
    },
    /// Publish (`present`) or withdraw one `_acme-challenge` TXT value for
    /// one of this node's own service names.
    Challenge { fqdn: String, value: String, present: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TlsResponse {
    Config(Box<TlsConfig>),
    Ok,
    Error { message: String },
}

/// Everything the terminator needs, rebuilt by the agent on every check-in.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsConfig {
    /// `None` while the coordinator publishes no DNS records: no
    /// certificate is obtainable, so nothing is served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme: Option<AcmeSettings>,
    /// The services to get certificates for and serve.
    #[serde(default)]
    pub services: Vec<TlsService>,
    /// Who is calling, by mesh address: every peer's, and this node's own.
    #[serde(default)]
    pub callers: Vec<Caller>,
    /// The sign-in provider (PLAN.md M34), resolved to where it answers.
    /// `None` while none is configured, or its service is not in the
    /// directory on its own node — nobody gets in by signing in then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_in: Option<SignInTarget>,
    /// Removed from every request, and set only by the terminator.
    #[serde(default)]
    pub identity_headers: IdentityHeaders,
    /// Removed from every request too, beyond the terminator's built-in list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strip_headers: Vec<String>,
    /// Callers, by node name, whose `X-Forwarded-For` and
    /// `X-Forwarded-Host` are kept (PLAN.md M43).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forwarding_nodes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignInTarget {
    /// `<service>.<domain>`: the name its certificate is checked against.
    pub fqdn: String,
    /// Its own address; the request goes to port 443 there.
    pub vip: Ipv4Addr,
    pub verify_path: String,
    pub session_cookie: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsService {
    pub name: String,
    /// The certificate's name, `<name>.<domain>`.
    pub fqdn: String,
    /// The service's own address. Clients reach it on 443, which the agent
    /// rewrites to the terminator's port (PLAN.md M35); the terminator
    /// tells its services apart by the address a connection arrived on.
    pub vip: Ipv4Addr,
    /// Where to send the requests, in plain HTTP: the service's target.
    pub upstream: SocketAddr,
    /// Who may reach it (PLAN.md M36). Missing reads as closed: nobody but
    /// through a sign-in there is none of.
    #[serde(default)]
    pub access: crate::ServiceAccess,
    /// Takes requests a page on another site starts (PLAN.md #276):
    /// otherwise a POST or a WebSocket from one is refused.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cross_site: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caller {
    pub addr: Ipv4Addr,
    pub node: String,
    /// Its owner (PLAN.md M38), named to a backend when the device's grants
    /// let it in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<crate::CallerIdentity>,
}

/// The header naming the calling node (PLAN.md M33). Always set by the
/// terminator, from the connection's own source address; a copy arriving
/// with the request is removed first, so a backend can trust it as far as it
/// trusts the mesh.
pub const NODE_HEADER: &str = "x-wireserve-node";

/// The DNS name an ACME DNS-01 challenge for `fqdn` is published at.
#[must_use]
pub fn challenge_name(fqdn: &str) -> String {
    format!("_acme-challenge.{fqdn}")
}

/// Whether `value` looks like a DNS-01 key authorization digest: 43
/// characters of unpadded base64url (a SHA-256 hash). Everything else is
/// refused before it gets near a DNS record.
#[must_use]
pub fn is_challenge_value(value: &str) -> bool {
    value.len() == 43 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_and_unknown_ones_are_refused() {
        let req = TlsRequest::CheckIn { serving: vec!["plex".into()], port: 11443, seen: vec![] };
        let text = serde_json::to_string(&req).unwrap();
        assert_eq!(text, r#"{"op":"check_in","serving":["plex"],"port":11443}"#);
        assert_eq!(serde_json::from_str::<TlsRequest>(&text).unwrap(), req);
        let with = TlsRequest::CheckIn { serving: vec![], port: 1, seen: vec!["10.9.0.3".parse().unwrap()] };
        let text = serde_json::to_string(&with).unwrap();
        assert_eq!(text, r#"{"op":"check_in","serving":[],"port":1,"seen":["10.9.0.3"]}"#);
        assert_eq!(serde_json::from_str::<TlsRequest>(&text).unwrap(), with);
        assert!(serde_json::from_str::<TlsRequest>(r#"{"op":"leave"}"#).is_err());
        assert!(serde_json::from_str::<TlsRequest>(r#"{"op":"serve","name":"x"}"#).is_err());
    }

    #[test]
    fn challenge_values_are_digests_and_nothing_else() {
        assert!(is_challenge_value("LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"));
        assert!(!is_challenge_value("short"));
        assert!(!is_challenge_value("LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEu\"0"));
        assert!(!is_challenge_value("LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0="));
    }
}
