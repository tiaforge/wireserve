//! Sending only what changed in the mesh directory (PLAN.md, fix 6).
//!
//! Every node needs the whole directory, but not the whole directory again
//! on every poll: a poll that says which version it holds is answered with
//! the entries that changed since, and a stamp to check the result against.
//! The coordinator and the agent share this module so that both sides keep
//! the same picture and compute the same digest of it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{PeerInfo, ServiceInfo};

/// Which directory a node holds, or which one a response leaves it holding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryStamp {
    /// Random per coordinator process: versions are only comparable within
    /// one, since the counter starts again with a restart.
    pub epoch: u64,
    /// Counts the changes to the directory since this process started.
    pub version: u64,
    /// Of the entries at that version: see [`DirectoryDigest`].
    pub digest: u64,
}

/// A peer's carrier, for the requester alone: the one thing about a peer
/// that differs from node to node, so it is not part of the shared entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerVia {
    pub pubkey: String,
    pub via: String,
}

/// What changed in the shared directory since the version a poll named.
/// Entries to set are complete, not partial.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DirectoryDelta {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers_set: Vec<PeerInfo>,
    /// Pubkeys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers_removed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services_set: Vec<ServiceInfo>,
    /// Names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services_removed: Vec<String>,
    /// Every peer this requester reaches through a carrier, whole each time:
    /// a peer left out has none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_via: Vec<PeerVia>,
}

/// What `GET /reach` answers: what the asking node gets at each service.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachResponse {
    pub reach: BTreeMap<String, crate::Reach>,
}

/// An order-independent digest of a set of directory entries: the wrapping
/// sum of each entry's own hash, so an entry can be added or taken out
/// without visiting the rest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectoryDigest(pub u64);

impl DirectoryDigest {
    pub fn add(&mut self, entry: u64) {
        self.0 = self.0.wrapping_add(entry);
    }

    pub fn remove(&mut self, entry: u64) {
        self.0 = self.0.wrapping_sub(entry);
    }
}

fn entry_hash(kind: u8, canonical_json: &[u8]) -> u64 {
    let mut h = Sha256::new();
    h.update([kind]);
    h.update(canonical_json);
    let d = h.finalize();
    u64::from_be_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

/// The shared form of a peer: no carrier (that is per requester) and no
/// handshake time (which moves on every poll and nobody reads from here).
#[must_use]
pub fn canonical_peer(p: &PeerInfo) -> PeerInfo {
    let mut p = p.clone();
    p.last_handshake = None;
    p.relay.via = None;
    p
}

/// The shared form of a service: what the requester gets at it is not part
/// of it.
#[must_use]
pub fn canonical_service(s: &ServiceInfo) -> ServiceInfo {
    let mut s = s.clone();
    s.reach = None;
    s
}

/// The digest term of a peer, taken in its shared form.
#[must_use]
pub fn peer_hash(p: &PeerInfo) -> u64 {
    entry_hash(b'p', &serde_json::to_vec(&canonical_peer(p)).expect("PeerInfo always serializes"))
}

/// The digest term of a service, taken in its shared form.
#[must_use]
pub fn service_hash(s: &ServiceInfo) -> u64 {
    entry_hash(b's', &serde_json::to_vec(&canonical_service(s)).expect("ServiceInfo always serializes"))
}

/// What a node holds of the directory between polls: the shared entries, as
/// of a version, and their digest. Entries are kept in their shared form;
/// [`Self::peers`] puts the requester's carriers back.
#[derive(Debug, Clone, Default)]
pub struct DirectoryBase {
    peers: BTreeMap<String, PeerInfo>,
    services: BTreeMap<String, ServiceInfo>,
    digest: DirectoryDigest,
}

impl DirectoryBase {
    /// From a full directory. A peer or service listed twice keeps its last.
    #[must_use]
    pub fn from_full(peers: &[PeerInfo], services: &[ServiceInfo]) -> Self {
        let mut base = Self::default();
        for p in peers {
            base.set_peer(canonical_peer(p));
        }
        for s in services {
            base.set_service(canonical_service(s));
        }
        base
    }

    #[must_use]
    pub fn digest(&self) -> u64 {
        self.digest.0
    }

    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    fn set_peer(&mut self, p: PeerInfo) {
        let h = peer_hash(&p);
        if let Some(old) = self.peers.insert(p.pubkey.clone(), p) {
            self.digest.remove(peer_hash(&old));
        }
        self.digest.add(h);
    }

    fn set_service(&mut self, s: ServiceInfo) {
        let h = service_hash(&s);
        if let Some(old) = self.services.insert(s.name.clone(), s) {
            self.digest.remove(service_hash(&old));
        }
        self.digest.add(h);
    }

    /// Applies a delta.
    pub fn apply(&mut self, delta: &DirectoryDelta) {
        for pk in &delta.peers_removed {
            if let Some(old) = self.peers.remove(pk) {
                self.digest.remove(peer_hash(&old));
            }
        }
        for name in &delta.services_removed {
            if let Some(old) = self.services.remove(name) {
                self.digest.remove(service_hash(&old));
            }
        }
        for p in &delta.peers_set {
            self.set_peer(canonical_peer(p));
        }
        for s in &delta.services_set {
            self.set_service(canonical_service(s));
        }
    }

    /// The peers, in pubkey order, each with the carrier `via` names for it.
    #[must_use]
    pub fn peers(&self, via: &[PeerVia]) -> Vec<PeerInfo> {
        let carriers: std::collections::HashMap<&str, &str> = via.iter().map(|v| (v.pubkey.as_str(), v.via.as_str())).collect();
        self.peers
            .values()
            .map(|p| {
                let mut p = p.clone();
                p.relay.via = carriers.get(p.pubkey.as_str()).map(|v| (*v).to_string());
                p
            })
            .collect()
    }

    /// The services, in name order.
    #[must_use]
    pub fn services(&self) -> Vec<ServiceInfo> {
        self.services.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str, pk: &str, ip4: &str) -> PeerInfo {
        PeerInfo {
            name: name.into(),
            pubkey: pk.into(),
            ip4: ip4.into(),
            ip6: String::new(),
            endpoint_addr: None,
            endpoint_addr_v4: None,
            endpoint_addr_v6: None,
            lan_addr: None,
            reflexive_addr: None,
            last_handshake: None,
            relay: Default::default(),
        }
    }

    fn svc(name: &str, node: &str) -> ServiceInfo {
        ServiceInfo {
            name: name.into(),
            node: node.into(),
            ip4: "100.64.0.1".into(),
            online: true,
            vip4: None,
            ports: vec![],
            terminated: false,
            reach: None,
        }
    }

    #[test]
    fn the_digest_does_not_depend_on_order_or_on_per_requester_fields() {
        let (a, b) = (peer("a", "pk-a", "100.64.0.1"), peer("b", "pk-b", "100.64.0.2"));
        let one = DirectoryBase::from_full(&[a.clone(), b.clone()], &[svc("x", "a")]);
        let two = DirectoryBase::from_full(&[b.clone(), a.clone()], &[svc("x", "a")]);
        assert_eq!(one.digest(), two.digest());

        let mut via = a.clone();
        via.relay.via = Some("pk-b".into());
        via.last_handshake = Some(chrono::Utc::now());
        let mut reach = svc("x", "a");
        reach.reach = Some(crate::Reach::Denied);
        assert_eq!(one.digest(), DirectoryBase::from_full(&[via, b], &[reach]).digest());
    }

    #[test]
    fn a_change_in_a_shared_field_changes_the_digest() {
        let a = peer("a", "pk-a", "100.64.0.1");
        let mut moved = a.clone();
        moved.endpoint_addr = Some("203.0.113.1:51820".into());
        assert_ne!(DirectoryBase::from_full(&[a], &[]).digest(), DirectoryBase::from_full(&[moved], &[]).digest());
    }

    #[test]
    fn applying_a_delta_equals_starting_from_the_result() {
        let (a, b, c) = (peer("a", "pk-a", "100.64.0.1"), peer("b", "pk-b", "100.64.0.2"), peer("c", "pk-c", "100.64.0.3"));
        let mut base = DirectoryBase::from_full(&[a.clone(), b.clone()], &[svc("x", "a"), svc("y", "b")]);
        let mut b2 = b.clone();
        b2.endpoint_addr = Some("198.51.100.9:1".into());
        let mut y2 = svc("y", "b");
        y2.online = false;
        base.apply(&DirectoryDelta {
            peers_set: vec![b2.clone(), c.clone()],
            peers_removed: vec!["pk-a".into(), "pk-gone".into()],
            services_set: vec![y2.clone(), svc("z", "c")],
            services_removed: vec!["x".into()],
            relay_via: vec![],
        });
        let want = DirectoryBase::from_full(&[b2, c], &[y2, svc("z", "c")]);
        assert_eq!(base.digest(), want.digest());
        assert_eq!(base.peers(&[]), want.peers(&[]));
        assert_eq!(base.services(), want.services());
    }

    #[test]
    fn via_is_put_back_for_the_requester_and_replaced_each_time() {
        let base = DirectoryBase::from_full(&[peer("a", "pk-a", "100.64.0.1"), peer("b", "pk-b", "100.64.0.2")], &[]);
        let with = base.peers(&[PeerVia { pubkey: "pk-b".into(), via: "pk-a".into() }]);
        assert_eq!(with.iter().find(|p| p.pubkey == "pk-b").unwrap().relay.via.as_deref(), Some("pk-a"));
        assert!(with.iter().find(|p| p.pubkey == "pk-a").unwrap().relay.via.is_none());
        assert!(base.peers(&[]).iter().all(|p| p.relay.via.is_none()));
    }
}
