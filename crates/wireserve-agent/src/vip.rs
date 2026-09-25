//! Service addresses ("VIPs", PLAN.md M20) as this agent receives them.
//!
//! Each service in the directory may carry its own address, which
//! `<name>.wg` resolves to, which every peer routes to the owning node
//! (an extra `AllowedIPs` entry on that peer), and which the owner's
//! firewall rewrites to the service's target port. All three consumers
//! read the address from the directory after [`sanitize`] has run on it,
//! so there is exactly one place deciding which addresses are acted on.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use wireserve_types::PollResponse;

/// Whether `addr` could be a mesh address at all. The coordinator hands
/// these out from the mesh range, so anything else is a bug or a lie.
fn plausible(addr: Ipv4Addr) -> bool {
    !(addr.is_unspecified()
        || addr.is_loopback()
        || addr.is_multicast()
        || addr.is_broadcast()
        || addr.is_link_local())
}

/// Clears every service address in `directory` this agent must not act
/// on, with a warning each: unparseable or implausible ones, one equal to
/// a node's own address (routing it to the service's owner would steal
/// that node's traffic), and any address given to two services.
///
/// A cleared service falls back to how services worked before they had
/// addresses: `<name>.wg` resolves to the owning node. What this does not
/// try to catch is an address outside the mesh range — the agent doesn't
/// know the range, and the coordinator could already route any address
/// it likes to a peer through that peer's own `ip4`.
pub fn sanitize(directory: &mut PollResponse) {
    let node_ips: Vec<&str> = directory.peers.iter().map(|p| p.ip4.as_str()).collect();
    let mut uses: HashMap<Ipv4Addr, usize> = HashMap::new();
    let refuse = |name: &str, vip: &str, why: &str| {
        tracing::warn!(service = %name.escape_debug(), vip = %vip.escape_debug(), "ignoring service address: {why}");
    };

    let mut parsed: Vec<Option<Ipv4Addr>> = Vec::with_capacity(directory.services.len());
    for s in &directory.services {
        let Some(vip) = s.vip4.as_deref() else {
            parsed.push(None);
            continue;
        };
        let addr = match vip.parse::<Ipv4Addr>() {
            Ok(a) if plausible(a) => a,
            _ => {
                refuse(&s.name, vip, "not a usable IPv4 address");
                parsed.push(None);
                continue;
            }
        };
        if node_ips.contains(&addr.to_string().as_str()) {
            refuse(&s.name, vip, "it is a node's own address");
            parsed.push(None);
            continue;
        }
        *uses.entry(addr).or_default() += 1;
        parsed.push(Some(addr));
    }

    for (s, addr) in directory.services.iter_mut().zip(parsed) {
        match addr {
            Some(a) if uses[&a] > 1 => {
                refuse(&s.name, &a.to_string(), "given to more than one service");
                s.vip4 = None;
            }
            Some(a) => s.vip4 = Some(a.to_string()),
            None => s.vip4 = None,
        }
    }

    for p in &mut directory.pending_services {
        if let Some(vip) = p.vip4.as_deref() {
            let ok = vip.parse::<Ipv4Addr>().is_ok_and(|a| plausible(a) && !node_ips.contains(&vip) && !uses.contains_key(&a));
            if !ok {
                refuse(&p.name, vip, "not a usable address for a pending service");
                p.vip4 = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::{PeerInfo, PendingService, Proto, ServiceInfo};

    fn peer(name: &str, ip4: &str) -> PeerInfo {
        PeerInfo {
            name: name.into(),
            pubkey: String::new(),
            ip4: ip4.into(),
            ip6: String::new(),
            endpoint_addr: None,
            endpoint_addr_v4: None,
            endpoint_addr_v6: None,
            lan_addr: None,
            reflexive_addr: None,
            last_handshake: None,
            transit_via: None,
        }
    }

    fn svc(name: &str, vip4: Option<&str>) -> ServiceInfo {
        ServiceInfo {
            auth: false,
            name: name.into(),
            node: "a".into(),
            ip4: "10.9.0.1".into(),
            port: 80,
            proto: Proto::Tcp,
            online: true,
            vip4: vip4.map(Into::into),
            ports: vec![],
        }
    }

    fn directory(services: Vec<ServiceInfo>) -> PollResponse {
        PollResponse {
            naming: None,
            peers: vec![peer("a", "10.9.0.1"), peer("b", "10.9.0.2")],
            services,
            pending_services: vec![],
            denied_services: vec![],
            transit_carrying: vec![],
            transit_awaiting_approval: false,
            exit_clients: vec![],
            mesh: None,
        }
    }

    fn vips(d: &PollResponse) -> Vec<Option<&str>> {
        d.services.iter().map(|s| s.vip4.as_deref()).collect()
    }

    #[test]
    fn a_good_address_is_kept_and_normalised() {
        let mut d = directory(vec![svc("web", Some("10.9.0.50")), svc("old", None)]);
        sanitize(&mut d);
        assert_eq!(vips(&d), [Some("10.9.0.50"), None]);
    }

    #[test]
    fn implausible_addresses_are_cleared() {
        for bad in ["nope", "10.9.0.50\n10.9.0.51 evil.wg", "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "169.254.1.1", "fd00::1"] {
            let mut d = directory(vec![svc("web", Some(bad))]);
            sanitize(&mut d);
            assert_eq!(vips(&d), [None], "{bad:?} should be cleared");
        }
    }

    #[test]
    fn a_nodes_own_address_is_never_a_service_address() {
        let mut d = directory(vec![svc("web", Some("10.9.0.2"))]);
        sanitize(&mut d);
        assert_eq!(vips(&d), [None]);
    }

    #[test]
    fn an_address_given_to_two_services_is_cleared_from_both() {
        let mut d = directory(vec![svc("a", Some("10.9.0.50")), svc("b", Some("10.9.0.50")), svc("c", Some("10.9.0.51"))]);
        sanitize(&mut d);
        assert_eq!(vips(&d), [None, None, Some("10.9.0.51")]);
    }

    #[test]
    fn a_pending_address_may_not_collide_with_a_published_one() {
        let mut d = directory(vec![svc("a", Some("10.9.0.50"))]);
        d.pending_services = vec![
            PendingService { name: "p".into(), port: 1, proto: Proto::Tcp, vip4: Some("10.9.0.50".into()), declared_at: None },
            PendingService { name: "q".into(), port: 1, proto: Proto::Tcp, vip4: Some("10.9.0.52".into()), declared_at: None },
        ];
        sanitize(&mut d);
        assert_eq!(d.pending_services[0].vip4, None);
        assert_eq!(d.pending_services[1].vip4.as_deref(), Some("10.9.0.52"));
    }
}
