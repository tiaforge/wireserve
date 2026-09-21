//! Port mappings of a service: which public port on the service's own
//! address (its VIP) reaches which target port on the owning node.
//!
//! Lives here, not in the agent or coordinator, for the same reason
//! `is_valid_dns_label` does: the agent refuses a bad `serve` before it
//! is ever queued, and the coordinator refuses the same declaration if it
//! arrives anyway, and the two must agree exactly — a limit enforced only
//! at the coordinator turns into a declaration resent and rejected every
//! cycle (see `MAX_SERVICES_PER_NODE`).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::node::Proto;

/// Upper bound on the mappings of one service. Each one becomes a handful
/// of firewall rules on its owner and is fanned out to every node's
/// directory, so the cap keeps one declaration from growing either
/// without bound.
pub const MAX_PORTS_PER_SERVICE: usize = 16;

/// `<svc>.wg:public` reaches the owning node's `target`, over `proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PortMap {
    pub public: u16,
    pub target: u16,
    pub proto: Proto,
}

impl PortMap {
    /// The mapping a pre-VIP declaration (`port`, `proto`) stands for: the
    /// service reachable on the same port it listens on.
    #[must_use]
    pub fn identity(port: u16, proto: Proto) -> Self {
        Self {
            public: port,
            target: port,
            proto,
        }
    }
}

/// `[PUBLIC:]TARGET[/tcp|/udp]` — the `serve` command-line form. The
/// protocol defaults to TCP, and a bare port maps to itself.
impl std::str::FromStr for PortMap {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ports, proto) = match s.split_once('/') {
            Some((ports, proto)) => (ports, proto.parse::<Proto>()?),
            None => (s, Proto::Tcp),
        };
        let port = |p: &str| -> Result<u16, String> {
            match p.parse::<u16>() {
                Ok(0) | Err(_) => Err(format!("invalid port '{p}' in '{s}' (expected 1-65535)")),
                Ok(n) => Ok(n),
            }
        };
        let (public, target) = match ports.split_once(':') {
            Some((public, target)) => (port(public)?, port(target)?),
            None => {
                let p = port(ports)?;
                (p, p)
            }
        };
        Ok(Self { public, target, proto })
    }
}

/// The same form `serve` takes, so a mapping can be copied from `list`
/// straight back into `serve`; an identity mapping is just its port.
impl fmt::Display for PortMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.public == self.target {
            write!(f, "{}/{}", self.public, self.proto.as_str())
        } else {
            write!(f, "{}:{}/{}", self.public, self.target, self.proto.as_str())
        }
    }
}

/// Checks the mappings of ONE service: at least one, at most
/// [`MAX_PORTS_PER_SERVICE`], no port 0, and no public port used twice
/// for the same protocol (the VIP could not tell the two apart).
pub fn validate_service_ports(maps: &[PortMap]) -> Result<(), String> {
    if maps.is_empty() {
        return Err("a service needs at least one port".into());
    }
    if maps.len() > MAX_PORTS_PER_SERVICE {
        return Err(format!(
            "too many ports ({}); the limit is {MAX_PORTS_PER_SERVICE} per service",
            maps.len()
        ));
    }
    for (i, m) in maps.iter().enumerate() {
        if m.public == 0 || m.target == 0 {
            return Err(format!("invalid port 0 in {m}"));
        }
        if maps[..i].iter().any(|o| o.public == m.public && o.proto == m.proto) {
            return Err(format!("public port {}/{} is mapped twice", m.public, m.proto.as_str()));
        }
    }
    Ok(())
}

/// Checks a node's mappings across ALL its services: no target port may
/// be used by two mappings for the same protocol.
///
/// The owner rewrites a reply back to the VIP and public port it came in
/// on by matching the reply's source, which after the rewrite is only the
/// node's own address and the target port. Two mappings onto one target
/// would leave that reply ambiguous — and on a single service,
/// `80:8000` plus `8080:8000` would still answer every client from `:80`.
pub fn validate_node_targets<'a>(maps: impl IntoIterator<Item = (&'a str, &'a PortMap)>) -> Result<(), String> {
    let mut seen: Vec<(&str, &PortMap)> = Vec::new();
    for (name, m) in maps {
        if let Some((other, _)) = seen.iter().find(|(_, o)| o.target == m.target && o.proto == m.proto) {
            return Err(format!(
                "target port {}/{} of '{name}' is already mapped by '{other}'",
                m.target,
                m.proto.as_str()
            ));
        }
        seen.push((name, m));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pm(public: u16, target: u16, proto: Proto) -> PortMap {
        PortMap { public, target, proto }
    }

    #[test]
    fn parses_every_form() {
        assert_eq!("80:5080".parse::<PortMap>().unwrap(), pm(80, 5080, Proto::Tcp));
        assert_eq!("53/udp".parse::<PortMap>().unwrap(), pm(53, 53, Proto::Udp));
        assert_eq!("8080:8000/tcp".parse::<PortMap>().unwrap(), pm(8080, 8000, Proto::Tcp));
        assert_eq!("5080".parse::<PortMap>().unwrap(), pm(5080, 5080, Proto::Tcp));
    }

    #[test]
    fn rejects_malformed_forms() {
        for bad in ["", "0", "80:0", "0:80", "70000", "80:", ":80", "80/sctp", "a:b", "80:81:82", "-1"] {
            assert!(bad.parse::<PortMap>().is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn display_is_the_serve_syntax_and_parses_back() {
        for (map, text) in [
            (pm(80, 5080, Proto::Tcp), "80:5080/tcp"),
            (pm(53, 53, Proto::Udp), "53/udp"),
        ] {
            assert_eq!(map.to_string(), text);
            assert_eq!(text.parse::<PortMap>().unwrap(), map);
        }
    }

    #[test]
    fn a_service_may_map_the_same_port_over_both_protocols() {
        let maps = [pm(53, 53, Proto::Udp), pm(53, 53, Proto::Tcp), pm(8080, 8000, Proto::Tcp)];
        validate_service_ports(&maps).unwrap();
    }

    #[test]
    fn a_public_port_may_not_be_mapped_twice_per_protocol() {
        let err = validate_service_ports(&[pm(80, 5080, Proto::Tcp), pm(80, 6080, Proto::Tcp)]).unwrap_err();
        assert!(err.contains("80/tcp"), "{err}");
    }

    #[test]
    fn a_service_needs_between_one_and_the_cap_ports() {
        assert!(validate_service_ports(&[]).is_err());
        let many: Vec<PortMap> = (1..=MAX_PORTS_PER_SERVICE as u16 + 1).map(|p| pm(p, p, Proto::Tcp)).collect();
        assert!(validate_service_ports(&many).is_err());
        validate_service_ports(&many[..MAX_PORTS_PER_SERVICE]).unwrap();
    }

    #[test]
    fn port_zero_is_refused_even_when_built_directly() {
        assert!(validate_service_ports(&[pm(0, 80, Proto::Tcp)]).is_err());
        assert!(validate_service_ports(&[pm(80, 0, Proto::Tcp)]).is_err());
    }

    #[test]
    fn a_target_port_may_serve_only_one_mapping_per_node() {
        let a = pm(80, 8000, Proto::Tcp);
        let b = pm(8080, 8000, Proto::Tcp);
        let err = validate_node_targets([("web", &a), ("api", &b)]).unwrap_err();
        assert!(err.contains("'api'") && err.contains("'web'"), "{err}");
        // Within one service too.
        assert!(validate_node_targets([("web", &a), ("web", &b)]).is_err());
        // Different protocols are different sockets.
        let c = pm(80, 8000, Proto::Udp);
        validate_node_targets([("web", &a), ("dns", &c)]).unwrap();
    }
}
