//! Which phone session a packet on the carrier's WireGuard port belongs to,
//! and where it goes (PLAN.md #341). Pure: the thread in `io` feeds it
//! packets and carries out what it answers.
//!
//! A session is one handshake between a phone and a node, as seen from the
//! carrier: the node, the phone's address and the address it dialled, and
//! each end's index once it has been seen. The node's index is what tells
//! the phone's later packets apart from the carrier's own sessions on the
//! same port; the phone's index is what tells the node's packets which
//! phone they are for.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use super::packet::{mac1_key, mac1_matches, Message};

/// How long a session is kept after its last packet: WireGuard's
/// reject-after-time, after which neither end uses its keys any more.
pub const SESSION_LIFETIME: Duration = Duration::from_secs(180);

/// The most sessions kept at once. Past it the one quiet the longest makes
/// room: a flood of handshakes with a valid `mac1` (a node's public key is
/// enough to make one) can only push out idle sessions, never stop new ones.
pub const MAX_SESSIONS: usize = 4096;

/// What to do with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Send it on to this node's WireGuard port, over the mesh.
    ToNode(SocketAddrV4),
    /// Send it to the phone at `phone`, from `from` — the address and port
    /// the phone dialled, so it sees the answer come from where it sent.
    ToPhone { phone: SocketAddrV4, from: SocketAddrV4 },
    /// Not a relayed session's: give it back to this host's own WireGuard
    /// as it came.
    ToKernel,
    Drop,
}

#[derive(Debug, Clone)]
struct Session {
    node: SocketAddrV4,
    phone: SocketAddrV4,
    local: SocketAddrV4,
    node_index: Option<u32>,
    phone_index: Option<u32>,
    seen: Instant,
}

/// A node phones are relayed to: where its WireGuard listens on the mesh,
/// and the key its handshakes' `mac1` is made with.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    addr: SocketAddrV4,
    mac1: [u8; 32],
}

#[derive(Debug, Default)]
pub struct Sorter {
    nodes: Vec<Node>,
    /// Device public key → the key its handshakes' `mac1` is made with.
    devices: Vec<([u8; 32], [u8; 32])>,
    sessions: HashMap<u64, Session>,
    next_id: u64,
    by_node_index: HashMap<u32, u64>,
    by_phone_index: HashMap<(SocketAddrV4, u32), u64>,
    /// Where each device was last seen, and the address it dialled: where
    /// a node's own handshake towards it goes.
    devices_seen: HashMap<[u8; 32], (SocketAddrV4, SocketAddrV4, Instant)>,
    /// Node indexes learned since the last [`Sorter::take_new_indexes`].
    new_indexes: Vec<u32>,
}

impl Sorter {
    /// The nodes this carrier relays to (their mesh address and WireGuard
    /// port, and public key) and the devices allowed to reach them. A node
    /// no longer listed loses its sessions at once.
    pub fn set_peers(&mut self, nodes: &[(SocketAddrV4, [u8; 32])], devices: &[[u8; 32]]) {
        let nodes: Vec<Node> = nodes.iter().map(|(addr, pk)| Node { addr: *addr, mac1: mac1_key(pk) }).collect();
        if nodes != self.nodes {
            self.nodes = nodes;
            let kept: Vec<SocketAddrV4> = self.nodes.iter().map(|n| n.addr).collect();
            let gone: Vec<u64> = self.sessions.iter().filter(|(_, s)| !kept.contains(&s.node)).map(|(id, _)| *id).collect();
            for id in gone {
                self.remove(id);
            }
        }
        self.devices = devices.iter().map(|pk| (*pk, mac1_key(pk))).collect();
        let known: Vec<[u8; 32]> = devices.to_vec();
        self.devices_seen.retain(|pk, _| known.contains(pk));
    }

    /// A packet from a phone, arriving at `local`, the address it dialled.
    pub fn from_phone(&mut self, now: Instant, phone: SocketAddrV4, local: SocketAddrV4, packet: &[u8]) -> Action {
        match Message::parse(packet) {
            Some(Message::Initiation { sender }) => {
                let Some(node) = self.nodes.iter().find(|n| mac1_matches(packet, &n.mac1)).map(|n| n.addr) else {
                    return Action::ToKernel;
                };
                if let Some(old) = self.by_phone_index.get(&(node, sender)).copied() {
                    self.remove(old);
                }
                let id = self.insert(Session { node, phone, local, node_index: None, phone_index: Some(sender), seen: now });
                self.by_phone_index.insert((node, sender), id);
                Action::ToNode(node)
            }
            // The phone answering a node's own handshake.
            Some(Message::Response { sender, receiver }) => {
                let Some(id) = self.by_node_index.get(&receiver).copied() else { return Action::ToKernel };
                let s = self.sessions.get_mut(&id).expect("indexed sessions exist");
                (s.phone, s.local, s.seen) = (phone, local, now);
                let node = s.node;
                if let Some(old) = s.phone_index.replace(sender) {
                    self.by_phone_index.remove(&(node, old));
                }
                self.by_phone_index.insert((node, sender), id);
                Action::ToNode(node)
            }
            Some(Message::CookieReply { receiver } | Message::Data { receiver }) => {
                let Some(id) = self.by_node_index.get(&receiver).copied() else { return Action::ToKernel };
                let s = self.sessions.get_mut(&id).expect("indexed sessions exist");
                // A phone that moved: its answers follow it, as WireGuard's
                // own endpoint would.
                (s.phone, s.local, s.seen) = (phone, local, now);
                Action::ToNode(s.node)
            }
            None => Action::ToKernel,
        }
    }

    /// A packet from `node`'s WireGuard port, over the mesh.
    pub fn from_node(&mut self, now: Instant, node: SocketAddrV4, packet: &[u8]) -> Action {
        if !self.nodes.iter().any(|n| n.addr == node) {
            return Action::Drop;
        }
        match Message::parse(packet) {
            // The node answering a phone's handshake: its index is what the
            // phone's packets will carry from now on.
            Some(Message::Response { sender, receiver }) => {
                let Some(id) = self.by_phone_index.get(&(node, receiver)).copied() else { return Action::Drop };
                if self.by_node_index.get(&sender).is_some_and(|other| *other != id) {
                    // Another session's already: this handshake fails, and
                    // the next one picks another index.
                    return Action::Drop;
                }
                let s = self.sessions.get_mut(&id).expect("indexed sessions exist");
                s.seen = now;
                let (phone, local) = (s.phone, s.local);
                if let Some(old) = s.node_index.replace(sender).filter(|old| *old != sender) {
                    self.by_node_index.remove(&old);
                }
                if self.by_node_index.insert(sender, id).is_none() {
                    self.new_indexes.push(sender);
                }
                // Its `mac1` names the device that started it.
                if let Some((pk, _)) = self.devices.iter().find(|(_, key)| mac1_matches(packet, key)) {
                    self.devices_seen.insert(*pk, (phone, local, now));
                }
                Action::ToPhone { phone, from: local }
            }
            // The node starting a handshake with a device, by its key.
            Some(Message::Initiation { sender }) => {
                let Some(pk) = self.devices.iter().find(|(_, key)| mac1_matches(packet, key)).map(|(pk, _)| *pk) else {
                    return Action::Drop;
                };
                let Some((phone, local, _)) = self.devices_seen.get(&pk).copied() else { return Action::Drop };
                if let Some(old) = self.by_node_index.get(&sender).copied() {
                    if self.sessions.get(&old).is_some_and(|s| s.node != node || s.phone_index.is_some()) {
                        return Action::Drop;
                    }
                    self.remove(old);
                }
                let id = self.insert(Session { node, phone, local, node_index: Some(sender), phone_index: None, seen: now });
                self.by_node_index.insert(sender, id);
                self.new_indexes.push(sender);
                Action::ToPhone { phone, from: local }
            }
            Some(Message::CookieReply { receiver } | Message::Data { receiver }) => {
                let Some(id) = self.by_phone_index.get(&(node, receiver)).copied() else { return Action::Drop };
                let s = self.sessions.get_mut(&id).expect("indexed sessions exist");
                s.seen = now;
                Action::ToPhone { phone: s.phone, from: s.local }
            }
            None => Action::Drop,
        }
    }

    /// Forgets the sessions quiet for longer than [`SESSION_LIFETIME`], and
    /// where devices were seen as long ago.
    pub fn expire(&mut self, now: Instant) {
        let old: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, s)| now.saturating_duration_since(s.seen) > SESSION_LIFETIME)
            .map(|(id, _)| *id)
            .collect();
        for id in old {
            self.remove(id);
        }
        self.devices_seen.retain(|_, (_, _, seen)| now.saturating_duration_since(*seen) <= SESSION_LIFETIME);
    }

    /// Every node index of a live session: what the firewall diverts.
    #[must_use]
    pub fn node_indexes(&self) -> Vec<u32> {
        let mut out: Vec<u32> = self.by_node_index.keys().copied().collect();
        out.sort_unstable();
        out
    }

    /// The node indexes learned since the last call, for the firewall to
    /// divert at once.
    pub fn take_new_indexes(&mut self) -> Vec<u32> {
        let mut out = std::mem::take(&mut self.new_indexes);
        out.retain(|i| self.by_node_index.contains_key(i));
        out
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    fn insert(&mut self, session: Session) -> u64 {
        if self.sessions.len() >= MAX_SESSIONS {
            if let Some(quietest) = self.sessions.iter().min_by_key(|(_, s)| s.seen).map(|(id, _)| *id) {
                self.remove(quietest);
            }
        }
        let id = self.next_id;
        self.next_id += 1;
        self.sessions.insert(id, session);
        id
    }

    fn remove(&mut self, id: u64) {
        if let Some(s) = self.sessions.remove(&id) {
            if let Some(i) = s.node_index {
                self.by_node_index.remove(&i);
            }
            if let Some(i) = s.phone_index {
                self.by_phone_index.remove(&(s.node, i));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phone_relay::packet::tests::{answer, data, initiation, End};
    use crate::phone_relay::packet::Message;
    use defguard_boringtun::noise::Tunn;

    const PHONE: &str = "198.51.100.7:40000";
    const ROAMED: &str = "203.0.113.9:51000";
    const LOCAL: &str = "192.0.2.1:51820";
    const MINIPC: &str = "10.1.0.5:51820";
    const NAS: &str = "10.1.0.6:51820";

    fn a(s: &str) -> SocketAddrV4 {
        s.parse().unwrap()
    }

    /// The phone (key 1), and a carrier relaying it to minipc (key 2) and
    /// the NAS (key 3).
    struct World {
        sorter: Sorter,
        now: Instant,
        phone: End,
    }

    impl World {
        fn new() -> Self {
            let phone = End::new(1);
            let mut sorter = Sorter::default();
            sorter.set_peers(&[(a(MINIPC), End::new(2).public), (a(NAS), End::new(3).public)], &[phone.public]);
            Self { sorter, now: Instant::now(), phone }
        }

        fn phone_sends(&mut self, packet: &[u8]) -> Action {
            self.sorter.from_phone(self.now, a(PHONE), a(LOCAL), packet)
        }

        /// The phone and `node` handshake through the sorter, the phone
        /// starting; returns both tunnels, the session up.
        fn handshake(&mut self, node: &str, peer: &End, phone_index: u32) -> (Tunn, Tunn) {
            let mut p = self.phone.tunnel_to(peer, phone_index);
            let mut n = peer.tunnel_to(&self.phone, phone_index + 100);
            let init = initiation(&mut p);
            assert_eq!(self.phone_sends(&init), Action::ToNode(a(node)));
            let resp = answer(&mut n, &init).unwrap();
            assert_eq!(self.sorter.from_node(self.now, a(node), &resp), Action::ToPhone { phone: a(PHONE), from: a(LOCAL) });
            let keepalive = answer(&mut p, &resp).unwrap();
            assert_eq!(self.phone_sends(&keepalive), Action::ToNode(a(node)));
            assert!(answer(&mut n, &keepalive).is_none());
            (p, n)
        }
    }

    #[test]
    fn a_phone_reaches_each_node_by_its_handshake_and_its_index() {
        let mut w = World::new();
        let (minipc, nas) = (End::new(2), End::new(3));
        let (mut p1, mut n1) = w.handshake(MINIPC, &minipc, 1);
        let (mut p2, mut n2) = w.handshake(NAS, &nas, 2);
        assert_eq!(w.sorter.len(), 2);
        assert_eq!(w.phone_sends(&data(&mut p1)), Action::ToNode(a(MINIPC)));
        assert_eq!(w.phone_sends(&data(&mut p2)), Action::ToNode(a(NAS)));
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), &data(&mut n1)), Action::ToPhone { phone: a(PHONE), from: a(LOCAL) });
        assert_eq!(w.sorter.from_node(w.now, a(NAS), &data(&mut n2)), Action::ToPhone { phone: a(PHONE), from: a(LOCAL) });
        let mut indexes = w.sorter.take_new_indexes();
        indexes.sort_unstable();
        assert_eq!(indexes, w.sorter.node_indexes(), "both node indexes, once each");
        assert_eq!(indexes.len(), 2);
        assert!(w.sorter.take_new_indexes().is_empty());
    }

    #[test]
    fn the_carriers_own_sessions_go_back_to_the_kernel() {
        let mut w = World::new();
        let carrier = End::new(4);
        let mut own = w.phone.tunnel_to(&carrier, 5);
        let mut kernel = carrier.tunnel_to(&w.phone, 6);
        let init = initiation(&mut own);
        assert_eq!(w.phone_sends(&init), Action::ToKernel);
        let resp = answer(&mut kernel, &init).unwrap();
        let keepalive = answer(&mut own, &resp).unwrap();
        assert_eq!(w.phone_sends(&keepalive), Action::ToKernel, "an index no relayed node chose");
        assert_eq!(w.phone_sends(b"not wireguard"), Action::ToKernel);
        assert!(w.sorter.is_empty());
    }

    #[test]
    fn a_node_starts_a_handshake_with_a_phone_it_has_seen() {
        let mut w = World::new();
        let minipc = End::new(2);
        let (_p, _n) = w.handshake(MINIPC, &minipc, 1);
        // Later, the node rekeys first.
        let mut n = minipc.tunnel_to(&w.phone, 300);
        let mut p = w.phone.tunnel_to(&minipc, 400);
        let init = initiation(&mut n);
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), &init), Action::ToPhone { phone: a(PHONE), from: a(LOCAL) });
        let resp = answer(&mut p, &init).unwrap();
        assert_eq!(w.phone_sends(&resp), Action::ToNode(a(MINIPC)), "the response carries the node's index");
        let keepalive = answer(&mut n, &resp).unwrap();
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), &keepalive), Action::ToPhone { phone: a(PHONE), from: a(LOCAL) });
        assert_eq!(w.phone_sends(&data(&mut p)), Action::ToNode(a(MINIPC)));
    }

    #[test]
    fn a_node_cannot_reach_a_device_never_seen_or_not_allowed() {
        let mut w = World::new();
        let stranger = End::new(9);
        let minipc = End::new(2);
        let mut n = minipc.tunnel_to(&w.phone, 300);
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), &initiation(&mut n)), Action::Drop, "never seen");
        let mut n = minipc.tunnel_to(&stranger, 301);
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), &initiation(&mut n)), Action::Drop, "not a device");
        let _ = w.handshake(MINIPC, &minipc, 1);
        let mut n = minipc.tunnel_to(&w.phone, 302);
        assert_eq!(w.sorter.from_node(w.now, a("10.1.0.99:51820"), &initiation(&mut n)), Action::Drop, "not a node");
    }

    #[test]
    fn a_phone_that_moves_is_answered_where_it_is_now() {
        let mut w = World::new();
        let minipc = End::new(2);
        let (mut p, mut n) = w.handshake(MINIPC, &minipc, 1);
        let moved = w.sorter.from_phone(w.now, a(ROAMED), a(LOCAL), &data(&mut p));
        assert_eq!(moved, Action::ToNode(a(MINIPC)));
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), &data(&mut n)), Action::ToPhone { phone: a(ROAMED), from: a(LOCAL) });
    }

    #[test]
    fn a_node_index_another_session_holds_is_refused() {
        let mut w = World::new();
        let (minipc, nas) = (End::new(2), End::new(3));
        let (_p, _n) = w.handshake(MINIPC, &minipc, 1);
        // The NAS picks the index minipc's session already has.
        let mut p = w.phone.tunnel_to(&nas, 2);
        let mut n = nas.tunnel_to(&w.phone, 101);
        let init = initiation(&mut p);
        assert_eq!(w.phone_sends(&init), Action::ToNode(a(NAS)));
        let resp = answer(&mut n, &init).unwrap();
        let held = w.sorter.node_indexes();
        let Some(Message::Response { sender, .. }) = Message::parse(&resp) else { panic!() };
        assert!(held.contains(&sender), "the test needs the same index: {held:?} {sender}");
        assert_eq!(w.sorter.from_node(w.now, a(NAS), &resp), Action::Drop);
        assert_eq!(w.sorter.node_indexes(), held, "minipc's session keeps its index");
    }

    #[test]
    fn quiet_sessions_expire_and_their_packets_go_back_to_the_kernel() {
        let mut w = World::new();
        let minipc = End::new(2);
        let (mut p, _n) = w.handshake(MINIPC, &minipc, 1);
        w.now += SESSION_LIFETIME / 2;
        assert_eq!(w.phone_sends(&data(&mut p)), Action::ToNode(a(MINIPC)));
        w.sorter.expire(w.now + SESSION_LIFETIME / 2);
        assert_eq!(w.sorter.len(), 1, "kept alive by its last packet");
        w.sorter.expire(w.now + SESSION_LIFETIME + Duration::from_secs(1));
        assert!(w.sorter.is_empty() && w.sorter.node_indexes().is_empty());
        assert_eq!(w.phone_sends(&data(&mut p)), Action::ToKernel);
    }

    #[test]
    fn a_node_taken_off_the_list_loses_its_sessions() {
        let mut w = World::new();
        let (minipc, nas) = (End::new(2), End::new(3));
        let (mut p, _n) = w.handshake(MINIPC, &minipc, 1);
        let _ = w.handshake(NAS, &nas, 2);
        w.sorter.set_peers(&[(a(NAS), nas.public)], &[w.phone.public]);
        assert_eq!(w.sorter.len(), 1);
        assert_eq!(w.phone_sends(&data(&mut p)), Action::ToKernel);
    }

    #[test]
    fn a_flood_of_handshakes_pushes_out_only_the_quietest_session() {
        let mut w = World::new();
        let minipc = End::new(2);
        let (mut p, _n) = w.handshake(MINIPC, &minipc, 1);
        // A first session, then MAX_SESSIONS more, each one newer.
        for i in 0..MAX_SESSIONS {
            w.now += Duration::from_millis(1);
            let mut flood = w.phone.tunnel_to(&minipc, 1000 + u32::try_from(i).unwrap());
            assert_eq!(w.phone_sends(&initiation(&mut flood)), Action::ToNode(a(MINIPC)));
        }
        assert_eq!(w.sorter.len(), MAX_SESSIONS);
        assert_eq!(w.phone_sends(&data(&mut p)), Action::ToKernel, "the oldest made room");
    }
}
