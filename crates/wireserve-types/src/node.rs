use serde::{Deserialize, Serialize};

/// Whether a node runs the full agent (WireGuard + firewall + hosts-file
/// sync) or is a consumer-only peer that never polls (spec §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeKind {
    #[default]
    Agent,
    Static,
}

impl NodeKind {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Static => "static",
        }
    }
}

impl std::str::FromStr for NodeKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "agent" => Ok(Self::Agent),
            "static" => Ok(Self::Static),
            other => Err(format!("unknown node kind: {other}")),
        }
    }
}

/// Transport-layer protocol a declared service listens on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl std::str::FromStr for Proto {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            other => Err(format!("unknown protocol: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_kind_default_is_agent() {
        assert_eq!(NodeKind::default(), NodeKind::Agent);
    }

    #[test]
    fn node_kind_roundtrips_through_str() {
        assert_eq!("agent".parse::<NodeKind>().unwrap(), NodeKind::Agent);
        assert_eq!("static".parse::<NodeKind>().unwrap(), NodeKind::Static);
        assert!("bogus".parse::<NodeKind>().is_err());
    }

    #[test]
    fn proto_roundtrips_through_str() {
        assert_eq!("tcp".parse::<Proto>().unwrap(), Proto::Tcp);
        assert_eq!("udp".parse::<Proto>().unwrap(), Proto::Udp);
        assert!("sctp".parse::<Proto>().is_err());
    }

    #[test]
    fn node_kind_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&NodeKind::Static).unwrap(), "\"static\"");
        assert_eq!(serde_json::to_string(&Proto::Tcp).unwrap(), "\"tcp\"");
    }
}
