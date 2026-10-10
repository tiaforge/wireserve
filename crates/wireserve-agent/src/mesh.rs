//! Keeps this node from acting on directory entries outside the mesh's
//! own address ranges (security review finding #4).
//!
//! Every address in the directory becomes a route into the tunnel and an
//! `AllowedIPs` entry: a peer "at" `192.168.1.1` would capture this
//! node's traffic to its own router, one at a public address its traffic
//! to that host. [`crate::vip::sanitize`] only refused the obviously
//! unusable (loopback, multicast, ...), because the agent didn't know the
//! ranges. Now it does: the coordinator reports them, and the agent pins
//! the first report it can verify — at `join`, or on the first poll for a
//! node that joined before — and checks every later directory against
//! that pin, never against whatever the current response claims. A pin
//! taken from the response being checked would stop a coordinator bug,
//! but not a compromised coordinator or anyone on a plain-HTTP path, who
//! would simply report a range to match.

use std::net::{Ipv4Addr, Ipv6Addr};

use wireserve_types::{MeshInfo, MeshRanges, PollResponse};

/// Whether `offered` is worth pinning for a node at `own_ip4`/`own_ip6`:
/// it parses and contains both of this node's own addresses. A range
/// that doesn't contain the node itself means the coordinator's range was
/// changed after this node joined (or something is lying); pinning it
/// would cut this node off from every peer allocated alongside it, so it
/// is not pinned at all and nothing is filtered.
#[must_use]
pub fn pinnable(offered: &MeshInfo, own_ip4: Option<&str>, own_ip6: Option<&str>) -> bool {
    let Some(ranges) = MeshRanges::parse(offered) else {
        return false;
    };
    let v4_ok = own_ip4.and_then(|a| a.parse::<Ipv4Addr>().ok()).is_some_and(|a| ranges.contains4(a));
    let v6_ok = own_ip6.and_then(|a| a.parse::<Ipv6Addr>().ok()).is_some_and(|a| ranges.contains6(a));
    v4_ok && v6_ok
}

/// Drops every peer with an address outside `ranges` and every service
/// the same is true of, and clears any service address outside them,
/// warning about each. A cleared service address falls back to the owning
/// node's, the same way [`crate::vip::sanitize`] treats one it refuses.
///
/// A peer is dropped whole, not trimmed to its in-range address: a
/// directory entry with an address that isn't the mesh's is not one to
/// half-trust. Anything still naming a dropped peer (a service, a transit
/// hint) no longer finds it, which every consumer already treats as a
/// safe no-op.
pub fn sanitize(directory: &mut PollResponse, ranges: &MeshRanges) {
    let in4 = |a: &str| a.parse::<Ipv4Addr>().is_ok_and(|a| ranges.contains4(a));
    let in6 = |a: &str| a.is_empty() || a.parse::<Ipv6Addr>().is_ok_and(|a| ranges.contains6(a));

    directory.peers.retain(|p| {
        let ok = in4(&p.ip4) && in6(&p.ip6);
        if !ok {
            tracing::warn!(
                peer = %p.name.escape_debug(),
                ip4 = %p.ip4.escape_debug(),
                ip6 = %p.ip6.escape_debug(),
                "ignoring peer: its address is outside the mesh range this node pinned"
            );
        }
        ok
    });
    directory.services.retain(|s| {
        let ok = in4(&s.ip4);
        if !ok {
            tracing::warn!(
                service = %s.name.escape_debug(),
                ip4 = %s.ip4.escape_debug(),
                "ignoring service: its node's address is outside the mesh range this node pinned"
            );
        }
        ok
    });
    for s in &mut directory.services {
        if s.vip4.as_deref().is_some_and(|v| !in4(v)) {
            tracing::warn!(
                service = %s.name.escape_debug(),
                vip = %s.vip4.as_deref().unwrap_or_default().escape_debug(),
                "ignoring service address: outside the mesh range this node pinned"
            );
            s.vip4 = None;
        }
    }
    for p in &mut directory.pending_services {
        if p.vip4.as_deref().is_some_and(|v| !in4(v)) {
            p.vip4 = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::{PeerInfo, PendingService, ServiceInfo};

    fn info() -> MeshInfo {
        MeshInfo { net_v4_cidr: "10.9.0.0/24".into(), net_v6_prefix: "fdb4:d481:7c21::/64".into() }
    }

    fn peer(name: &str, ip4: &str, ip6: &str) -> PeerInfo {
        PeerInfo {
            name: name.into(),
            pubkey: format!("pk-{name}"),
            ip4: ip4.into(),
            ip6: ip6.into(),
            endpoint_addr: None,
            endpoint_addr_v4: None,
            endpoint_addr_v6: None,
            lan_addr: None,
            reflexive_addr: None,
            last_handshake: None,
            relay: Default::default(),
        }
    }

    fn svc(name: &str, ip4: &str, vip4: Option<&str>) -> ServiceInfo {
        ServiceInfo {
            terminated: false,
            reach: None,
            name: name.into(),
            node: "a".into(),
            ip4: ip4.into(),
            online: true,
            vip4: vip4.map(Into::into),
            ports: vec![],
        }
    }

    fn directory(peers: Vec<PeerInfo>, services: Vec<ServiceInfo>) -> PollResponse {
        PollResponse {
            stamp: None,
            delta: None,
            full: false,
            naming: None,
            access: vec![],
            service_notices: vec![],
            identities: vec![],
            peers,
            services,
            pending_services: vec![],
            denied_services: vec![],
            relay_carrying: vec![],
            relay_public: vec![],
            relay_port_base: None,
            port_checks: vec![],
            transit_awaiting_approval: false,
            exit_clients: vec![],
            mesh: None,
        }
    }

    #[test]
    fn a_peer_outside_either_range_is_dropped_whole() {
        let r = MeshRanges::parse(&info()).unwrap();
        let mut d = directory(
            vec![
                peer("a", "10.9.0.1", "fdb4:d481:7c21::1"),
                peer("router", "192.168.1.1", "fdb4:d481:7c21::2"),
                peer("public", "10.9.0.3", "2001:db8::3"),
                peer("v4only", "10.9.0.4", ""),
            ],
            vec![],
        );
        sanitize(&mut d, &r);
        let names: Vec<&str> = d.peers.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["a", "v4only"]);
    }

    #[test]
    fn service_addresses_outside_the_range_are_cleared_and_foreign_services_dropped() {
        let r = MeshRanges::parse(&info()).unwrap();
        let mut d = directory(
            vec![peer("a", "10.9.0.1", "")],
            vec![svc("ok", "10.9.0.1", Some("10.9.0.50")), svc("dns", "10.9.0.1", Some("8.8.8.8")), svc("far", "1.1.1.1", None)],
        );
        d.pending_services = vec![PendingService {
            name: "p".into(),
            ports: vec![],
            vip4: Some("192.168.1.1".into()),
            declared_at: None,
        }];
        sanitize(&mut d, &r);
        let kept: Vec<(&str, Option<&str>)> = d.services.iter().map(|s| (s.name.as_str(), s.vip4.as_deref())).collect();
        assert_eq!(kept, [("ok", Some("10.9.0.50")), ("dns", None)]);
        assert_eq!(d.pending_services[0].vip4, None);
    }

    #[test]
    fn only_a_range_containing_this_node_itself_is_pinned() {
        assert!(pinnable(&info(), Some("10.9.0.7"), Some("fdb4:d481:7c21::7")));
        assert!(!pinnable(&info(), Some("10.8.0.7"), Some("fdb4:d481:7c21::7")), "range changed since this node joined");
        assert!(!pinnable(&info(), Some("10.9.0.7"), Some("fd00::7")));
        assert!(!pinnable(&info(), None, None));
        let garbage = MeshInfo { net_v4_cidr: "x".into(), net_v6_prefix: "y".into() };
        assert!(!pinnable(&garbage, Some("10.9.0.7"), Some("fdb4:d481:7c21::7")));
    }
}
