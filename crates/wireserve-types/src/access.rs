//! Who can reach what (PLAN.md M36): service groups, grants and node tags.
//!
//! A grant lets a source reach every service in one service group. The
//! coordinator turns them into one [`ServiceAccess`] per service and sends
//! each node only its own; the node's firewall and terminator enforce it.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The group every service without an explicit one is in, and which
/// `everyone` is granted on a fresh mesh. It can never be deleted.
pub const DEFAULT_GROUP: &str = "default";

/// Longest group name an identity provider's claim may carry that a grant
/// can name.
pub const MAX_OIDC_GROUP_LEN: usize = 128;

/// At most this many sources are read from one service's access list; a
/// mesh range holds far fewer nodes than a response could otherwise carry.
pub const MAX_SOURCES_PER_SERVICE: usize = 4096;

/// Who a grant is for.
///
/// Written `everyone`, `oidc:<group>` or `tag:<tag>` — on the command line,
/// on the wire and in the admin API alike.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GrantSource {
    /// Every node in the mesh, signed in or not.
    Everyone,
    /// People in this group at the identity provider: the owner of a node
    /// (PLAN.md M38), or whoever signs in through the provider.
    Oidc(String),
    /// Nodes an admin gave this tag: servers, shared devices.
    Tag(String),
}

impl GrantSource {
    /// The kind, as the coordinator stores it.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Everyone => "everyone",
            Self::Oidc(_) => "oidc",
            Self::Tag(_) => "tag",
        }
    }

    /// The name, empty for `everyone`.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Everyone => "",
            Self::Oidc(n) | Self::Tag(n) => n,
        }
    }

    /// From the stored kind and name.
    pub fn from_parts(kind: &str, name: &str) -> Result<Self, String> {
        match kind {
            "everyone" if name.is_empty() => Ok(Self::Everyone),
            "oidc" if is_valid_oidc_group(name) => Ok(Self::Oidc(name.to_string())),
            "tag" if crate::is_valid_dns_label(name) => Ok(Self::Tag(name.to_string())),
            _ => Err(format!("{kind}:{name} is not a grant source")),
        }
    }
}

impl fmt::Display for GrantSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Everyone => f.write_str("everyone"),
            Self::Oidc(n) => write!(f, "oidc:{n}"),
            Self::Tag(n) => write!(f, "tag:{n}"),
        }
    }
}

impl FromStr for GrantSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "everyone" {
            return Ok(Self::Everyone);
        }
        match s.split_once(':') {
            Some(("oidc", name)) => Self::from_parts("oidc", name),
            Some(("tag", name)) => Self::from_parts("tag", &name.to_ascii_lowercase()),
            _ => Err(format!("{s:?} is not everyone, oidc:<group> or tag:<tag>")),
        }
    }
}

impl Serialize for GrantSource {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for GrantSource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

/// A group name as an identity provider sends it: any printable text,
/// compared exactly — but never a comma, which separates groups in the
/// provider's groups header.
#[must_use]
pub fn is_valid_oidc_group(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_OIDC_GROUP_LEN
        && s.trim() == s
        && s.chars().all(|c| !c.is_control() && c != ',')
}

/// One of a node's own services, as the grants have it (PLAN.md M36).
///
/// Sent to the service's owner alone. The owner's firewall and terminator
/// may only narrow what the node itself declared, never open more: a
/// service of its own with no entry here is closed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccess {
    pub name: String,
    /// `everyone` reaches it: no filtering at all, as before grants.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub open: bool,
    /// The mesh addresses of the nodes allowed in when not `open` — always
    /// including the owner's own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<Ipv4Addr>,
    /// Anyone may reach its terminated 443 and try the sign-in; the groups
    /// they prove there must include one of `sign_in_groups`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sign_in: bool,
    /// The identity provider's groups granted this service.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sign_in_groups: Vec<String>,
}

/// The person a calling device belongs to (PLAN.md M38), for a terminator
/// to name to its backends when the device's own grants let it in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerIdentity {
    /// The device's mesh address.
    pub addr: Ipv4Addr,
    /// The owner's subject at the identity provider — what authward sends
    /// as the user too.
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

/// Something about a node's own declaration the node should know, but that
/// does not stop the rest of its declarations — a group it cannot use, or
/// one it named that an admin decides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceNotice {
    pub name: String,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_read_and_write_as_written() {
        for s in ["everyone", "oidc:family", "oidc:Home Admins", "tag:ops"] {
            let parsed: GrantSource = s.parse().unwrap();
            assert_eq!(parsed.to_string(), s);
            assert_eq!(GrantSource::from_parts(parsed.kind(), parsed.name()).unwrap(), parsed);
        }
        assert_eq!("tag:OPS".parse::<GrantSource>().unwrap(), GrantSource::Tag("ops".into()));
        for bad in ["", "all", "oidc:", "oidc:a,b", "oidc: padded", "tag:not a tag", "tag:", "user:tia", "everyone:x"] {
            assert!(bad.parse::<GrantSource>().is_err(), "{bad:?}");
        }
        let json = serde_json::to_string(&GrantSource::Oidc("family".into())).unwrap();
        assert_eq!(json, "\"oidc:family\"");
        assert!(serde_json::from_str::<GrantSource>("\"tag:no way\"").is_err());
    }

    #[test]
    fn an_open_service_is_small_on_the_wire() {
        let open = ServiceAccess { name: "web".into(), open: true, sources: vec![], sign_in: false, sign_in_groups: vec![] };
        assert_eq!(serde_json::to_value(&open).unwrap(), serde_json::json!({"name": "web", "open": true}));
        let closed: ServiceAccess = serde_json::from_value(serde_json::json!({"name": "db"})).unwrap();
        assert!(!closed.open && closed.sources.is_empty(), "missing fields read as closed");
    }
}
