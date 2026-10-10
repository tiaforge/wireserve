//! The shared directory this agent holds between polls, so that a poll can
//! name the version it has and be answered with only what changed (fix 6).
//!
//! Kept raw, as received: the sanitising that follows (`mesh::sanitize`,
//! `vip::sanitize`) works on a copy, since what it removes is this node's
//! decision and not part of what the coordinator's digest covers.

use wireserve_types::{DirectoryBase, DirectoryStamp, PeerVia, PollResponse};

/// What a poll's response left this agent holding.
pub struct Held {
    base: DirectoryBase,
    stamp: DirectoryStamp,
}

impl Held {
    /// The version to name in the next poll.
    #[must_use]
    pub fn stamp(&self) -> DirectoryStamp {
        self.stamp
    }
}

/// The agent holds something it cannot trust to be what the coordinator has:
/// it is dropped and the next poll asks for all of it.
#[derive(Debug, PartialEq, Eq)]
pub enum OutOfStep {
    /// A delta, but nothing to apply it to.
    NothingHeld,
    /// What the delta left does not match the coordinator's digest.
    Digest,
}

impl std::fmt::Display for OutOfStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutOfStep::NothingHeld => f.write_str("the coordinator sent a delta of a directory this node does not hold"),
            OutOfStep::Digest => f.write_str("the directory this node holds no longer matches the coordinator's"),
        }
    }
}

impl std::error::Error for OutOfStep {}

/// Folds a response into what is held, and leaves `resp` with the whole
/// directory in it, whichever way it came: peers in pubkey order, services in
/// name order, each peer with the carrier this response names for it.
///
/// A response without a stamp (a coordinator that does not number its
/// directory) is used as it is and nothing is held.
pub fn absorb(held: &mut Option<Held>, resp: &mut PollResponse) -> Result<(), OutOfStep> {
    let Some(stamp) = resp.stamp else {
        *held = None;
        return Ok(());
    };
    if let Some(delta) = resp.delta.take() {
        let Some(h) = held.as_mut() else { return Err(OutOfStep::NothingHeld) };
        h.base.apply(&delta);
        if h.base.digest() != stamp.digest {
            *held = None;
            return Err(OutOfStep::Digest);
        }
        h.stamp = stamp;
        resp.peers = h.base.peers(&delta.relay_via);
        resp.services = h.base.services();
        return Ok(());
    }
    let via: Vec<PeerVia> = resp
        .peers
        .iter()
        .filter_map(|p| Some(PeerVia { pubkey: p.pubkey.clone(), via: p.relay.via.clone()? }))
        .collect();
    let base = DirectoryBase::from_full(&resp.peers, &resp.services);
    if base.digest() != stamp.digest {
        *held = None;
        return Err(OutOfStep::Digest);
    }
    resp.peers = base.peers(&via);
    resp.services = base.services();
    *held = Some(Held { base, stamp });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::{DirectoryDelta, PeerInfo, ServiceInfo};

    fn peer(name: &str) -> PeerInfo {
        PeerInfo {
            name: name.into(),
            pubkey: format!("pk-{name}"),
            ip4: "100.64.0.1".into(),
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

    fn svc(name: &str) -> ServiceInfo {
        ServiceInfo {
            name: name.into(),
            node: "a".into(),
            ip4: "100.64.0.1".into(),
            online: true,
            vip4: None,
            ports: vec![],
            terminated: false,
            reach: None,
        }
    }

    fn stamp(version: u64, base: &DirectoryBase) -> DirectoryStamp {
        DirectoryStamp { epoch: 7, version, digest: base.digest() }
    }

    fn full(peers: Vec<PeerInfo>, services: Vec<ServiceInfo>) -> PollResponse {
        let base = DirectoryBase::from_full(&peers, &services);
        PollResponse { stamp: Some(stamp(1, &base)), peers, services, ..Default::default() }
    }

    #[test]
    fn a_whole_directory_is_held_and_a_delta_then_brings_it_up_to_date() {
        let mut held = None;
        let mut first = full(vec![peer("a"), peer("b")], vec![svc("web")]);
        absorb(&mut held, &mut first).unwrap();
        assert_eq!(first.peers.len(), 2);
        assert_eq!(held.as_ref().unwrap().stamp().version, 1);

        let mut b2 = peer("b");
        b2.endpoint_addr = Some("203.0.113.1:51820".into());
        let delta = DirectoryDelta { peers_set: vec![b2.clone()], peers_removed: vec![], services_set: vec![svc("db")], services_removed: vec!["web".into()], relay_via: vec![] };
        let want = DirectoryBase::from_full(&[peer("a"), b2], &[svc("db")]);
        let mut second = PollResponse { stamp: Some(stamp(2, &want)), delta: Some(delta), ..Default::default() };
        absorb(&mut held, &mut second).unwrap();
        assert!(second.delta.is_none());
        assert_eq!(second.peers.len(), 2);
        assert_eq!(second.services.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["db"]);
        assert_eq!(held.as_ref().unwrap().stamp().version, 2);
    }

    #[test]
    fn carriers_are_the_responses_own_each_time() {
        let mut held = None;
        let mut a = peer("a");
        a.relay.via = Some("pk-c".into());
        let mut first = full(vec![a, peer("b"), peer("c")], vec![]);
        absorb(&mut held, &mut first).unwrap();
        assert_eq!(first.peers.iter().find(|p| p.name == "a").unwrap().relay.via.as_deref(), Some("pk-c"));

        let same = DirectoryBase::from_full(&[peer("a"), peer("b"), peer("c")], &[]);
        let mut second = PollResponse {
            stamp: Some(stamp(1, &same)),
            delta: Some(DirectoryDelta { relay_via: vec![PeerVia { pubkey: "pk-b".into(), via: "pk-c".into() }], ..Default::default() }),
            ..Default::default()
        };
        absorb(&mut held, &mut second).unwrap();
        assert!(second.peers.iter().find(|p| p.name == "a").unwrap().relay.via.is_none(), "the old carrier is gone");
        assert_eq!(second.peers.iter().find(|p| p.name == "b").unwrap().relay.via.as_deref(), Some("pk-c"));
    }

    #[test]
    fn a_delta_that_does_not_add_up_drops_what_is_held() {
        let mut held = None;
        absorb(&mut held, &mut full(vec![peer("a")], vec![])).unwrap();
        let wrong = DirectoryStamp { epoch: 7, version: 2, digest: 12345 };
        let mut resp = PollResponse { stamp: Some(wrong), delta: Some(DirectoryDelta::default()), ..Default::default() };
        assert_eq!(absorb(&mut held, &mut resp), Err(OutOfStep::Digest));
        assert!(held.is_none(), "so the next poll asks for all of it");
    }

    #[test]
    fn a_delta_with_nothing_held_and_a_whole_directory_with_a_wrong_digest_are_refused() {
        let mut held = None;
        let mut resp = PollResponse { stamp: Some(DirectoryStamp { epoch: 1, version: 1, digest: 0 }), delta: Some(DirectoryDelta::default()), ..Default::default() };
        assert_eq!(absorb(&mut held, &mut resp), Err(OutOfStep::NothingHeld));
        let mut bad = full(vec![peer("a")], vec![]);
        bad.stamp.as_mut().unwrap().digest ^= 1;
        assert_eq!(absorb(&mut held, &mut bad), Err(OutOfStep::Digest));
        assert!(held.is_none());
    }

    #[test]
    fn a_coordinator_that_does_not_stamp_is_used_as_it_is() {
        let mut held = None;
        absorb(&mut held, &mut full(vec![peer("a")], vec![])).unwrap();
        let mut plain = PollResponse { peers: vec![peer("z"), peer("a")], ..Default::default() };
        absorb(&mut held, &mut plain).unwrap();
        assert!(held.is_none());
        assert_eq!(plain.peers[0].name, "z", "order untouched");
    }
}
