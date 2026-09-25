//! Port mappings of a service: which public port on the service's own
//! address (its VIP) reaches which target port — on the owning node, or on
//! an address the owning node reaches for it (PLAN.md M26).
//!
//! Lives here, not in the agent or coordinator, for the same reason
//! `is_valid_dns_label` does: the agent refuses a bad `serve` before it
//! is ever queued, and the coordinator refuses the same declaration if it
//! arrives anyway, and the two must agree exactly — a limit enforced only
//! at the coordinator turns into a declaration resent and rejected every
//! cycle (see `MAX_SERVICES_PER_NODE`).

use std::fmt;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::node::Proto;

/// Upper bound on the mappings of one service. Each one becomes a handful
/// of firewall rules on its owner and is fanned out to every node's
/// directory, so the cap keeps one declaration from growing either
/// without bound.
pub const MAX_PORTS_PER_SERVICE: usize = 16;

/// `<svc>.wg:public` reaches `target` over `proto` — on the owning node
/// itself, or on `addr` when there is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PortMap {
    pub public: u16,
    pub target: u16,
    pub proto: Proto,
    /// Somewhere the owning node forwards to instead of serving itself — a
    /// router or printer on its LAN (PLAN.md M26). Absent means the node
    /// itself, so every declaration from before this field means what it
    /// meant; an older coordinator drops it, which only costs the approver
    /// seeing it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<Ipv4Addr>,
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
            addr: None,
        }
    }
}

/// Whether `addr` may be a mapping's target address: a unicast address
/// something could answer on from the owning node's side. Loopback is out
/// because a rewritten packet arriving from the mesh interface with a
/// loopback destination is a martian the kernel drops, and a service bound
/// only to loopback is out of scope anyway (PLAN.md M20). Whether it lies
/// inside the mesh ranges is checked separately, by whoever knows them.
#[must_use]
pub fn is_valid_target_addr(addr: Ipv4Addr) -> bool {
    !(addr.is_unspecified() || addr.is_loopback() || addr.is_multicast() || addr.is_broadcast())
}

/// `[PUBLIC:][ADDR:]TARGET[/tcp|/udp]` — the `serve` command-line form.
/// The protocol defaults to TCP, a missing public port is the target port,
/// and a missing address is the node itself.
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
        let addr = |a: &str| -> Result<Ipv4Addr, String> {
            let a: Ipv4Addr = a.parse().map_err(|_| format!("invalid IPv4 address '{a}' in '{s}'"))?;
            if !is_valid_target_addr(a) {
                return Err(format!("{a} in '{s}' can't be a target (loopback, multicast, broadcast or unspecified)"));
            }
            Ok(a)
        };
        if ports.contains('[') || ports.matches(':').count() > 2 {
            return Err(format!(
                "IPv6 target addresses are not supported in '{s}': a service's own address is IPv4, and \
                 the kernel cannot forward an IPv4 connection to an IPv6 one"
            ));
        }
        let parts: Vec<&str> = ports.split(':').collect();
        let (public, addr, target) = match parts.as_slice() {
            [target] => {
                let p = port(target)?;
                (p, None, p)
            }
            // A dotted first part is an address, never a port.
            [first, target] if first.contains('.') => {
                let p = port(target)?;
                (p, Some(addr(first)?), p)
            }
            [public, target] => (port(public)?, None, port(target)?),
            [public, a, target] => (port(public)?, Some(addr(a)?), port(target)?),
            _ => unreachable!("at most two colons, checked above"),
        };
        Ok(Self { public, target, proto, addr })
    }
}

/// The same form `serve` takes, so a mapping can be copied from `list`
/// straight back into `serve`; an identity mapping is just its port.
impl fmt::Display for PortMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.public != self.target {
            write!(f, "{}:", self.public)?;
        }
        if let Some(addr) = self.addr {
            write!(f, "{addr}:")?;
        }
        write!(f, "{}/{}", self.target, self.proto.as_str())
    }
}

/// Checks the mappings of ONE service: at least one, at most
/// [`MAX_PORTS_PER_SERVICE`], no port 0, no target address that could
/// never answer (see [`is_valid_target_addr`]), and no public port used
/// twice for the same protocol (the VIP could not tell the two apart).
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
        if m.addr.is_some_and(|a| !is_valid_target_addr(a)) {
            return Err(format!("{m} has a target address that can't be one"));
        }
        if maps[..i].iter().any(|o| o.public == m.public && o.proto == m.proto) {
            return Err(format!("public port {}/{} is mapped twice", m.public, m.proto.as_str()));
        }
    }
    Ok(())
}

/// Checks a node's mappings across ALL its services: no target (address
/// and port) may be used by two mappings for the same protocol.
///
/// The owner rewrites a reply back to the VIP and public port it came in
/// on by matching the reply's source, which after the rewrite is only the
/// target's address — the node's own, or the mapping's `addr` — and the
/// target port. Two mappings onto one target would leave that reply
/// ambiguous — and on a single service, `80:8000` plus `8080:8000` would
/// still answer every client from `:80`. The same port on two different
/// addresses is two different sources, so it is fine.
pub fn validate_node_targets<'a>(maps: impl IntoIterator<Item = (&'a str, &'a PortMap)>) -> Result<(), String> {
    let mut seen: Vec<(&str, &PortMap)> = Vec::new();
    for (name, m) in maps {
        if let Some((other, _)) = seen.iter().find(|(_, o)| same_target(o, m)) {
            return Err(format!("target {} of '{name}' is already mapped by '{other}'", target_label(m)));
        }
        seen.push((name, m));
    }
    Ok(())
}

/// Whether two mappings land on the same socket — and so would have
/// replies [`validate_node_targets`] could not tell apart.
#[must_use]
pub fn same_target(a: &PortMap, b: &PortMap) -> bool {
    a.addr == b.addr && a.target == b.target && a.proto == b.proto
}

/// `192.168.1.1:80/tcp`, or `80/tcp` for the node itself — for messages.
#[must_use]
pub fn target_label(m: &PortMap) -> String {
    match m.addr {
        Some(a) => format!("{a}:{}/{}", m.target, m.proto.as_str()),
        None => format!("port {}/{}", m.target, m.proto.as_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pm(public: u16, target: u16, proto: Proto) -> PortMap {
        PortMap { public, target, proto, addr: None }
    }

    fn remote(public: u16, addr: &str, target: u16) -> PortMap {
        PortMap { public, target, proto: Proto::Tcp, addr: Some(addr.parse().unwrap()) }
    }

    #[test]
    fn parses_every_form() {
        assert_eq!("80:5080".parse::<PortMap>().unwrap(), pm(80, 5080, Proto::Tcp));
        assert_eq!("53/udp".parse::<PortMap>().unwrap(), pm(53, 53, Proto::Udp));
        assert_eq!("8080:8000/tcp".parse::<PortMap>().unwrap(), pm(8080, 8000, Proto::Tcp));
        assert_eq!("5080".parse::<PortMap>().unwrap(), pm(5080, 5080, Proto::Tcp));
    }

    #[test]
    fn parses_a_target_address() {
        assert_eq!("443:192.168.178.1:80".parse::<PortMap>().unwrap(), remote(443, "192.168.178.1", 80));
        assert_eq!("192.168.178.1:80".parse::<PortMap>().unwrap(), remote(80, "192.168.178.1", 80));
        let udp = "53:10.0.0.53:53/udp".parse::<PortMap>().unwrap();
        assert_eq!((udp.proto, udp.addr), (Proto::Udp, Some(Ipv4Addr::new(10, 0, 0, 53))));
    }

    #[test]
    fn refuses_target_addresses_that_cannot_answer() {
        for bad in ["80:127.0.0.1:80", "80:0.0.0.0:80", "80:224.0.0.1:80", "80:255.255.255.255:80", "80:1.2.3:80", "80:1.2.3.4.5:80"] {
            assert!(bad.parse::<PortMap>().is_err(), "{bad:?} should not parse");
        }
        let mut m = remote(80, "192.168.1.1", 80);
        m.addr = Some(Ipv4Addr::LOCALHOST);
        assert!(validate_service_ports(&[m]).is_err(), "a hand-built mapping is checked too");
    }

    #[test]
    fn refuses_ipv6_targets_with_a_reason() {
        for bad in ["443:[fd00::1]:80", "443:fd00::1:80"] {
            let err = bad.parse::<PortMap>().unwrap_err();
            assert!(err.contains("IPv6"), "{bad:?}: {err}");
        }
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
            (remote(443, "192.168.178.1", 80), "443:192.168.178.1:80/tcp"),
            (remote(80, "192.168.178.1", 80), "192.168.178.1:80/tcp"),
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

    #[test]
    fn the_same_port_on_another_address_is_another_target() {
        let local = pm(80, 80, Proto::Tcp);
        let router = remote(443, "192.168.178.1", 80);
        validate_node_targets([("web", &local), ("myrouter", &router)]).unwrap();
        let again = remote(8443, "192.168.178.1", 80);
        let err = validate_node_targets([("myrouter", &router), ("admin", &again)]).unwrap_err();
        assert!(err.contains("192.168.178.1:80/tcp"), "{err}");
    }
}
