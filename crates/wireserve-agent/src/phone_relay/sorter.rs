//! Which phone session a packet on the carrier's WireGuard port belongs to,
//! and where it goes (PLAN.md #341). Pure: the thread in `io` feeds it
//! packets and carries out what it answers.
//!
//! A session is one handshake between a phone and a node, as seen from the
//! carrier: the node, the phone's address and the address it dialled, and
//! each end's index. The node's index is what tells the phone's later
//! packets apart from the carrier's own sessions on the same port; the
//! phone's index is what tells the node's packets which phone they are for.
//!
//! Only the node's side is authenticated here: its packets come over the
//! mesh. A phone's come from the open internet, their indexes in the clear,
//! and anyone who has seen one can send another like it from anywhere. So
//! nothing a phone sends sets where a session's packets go.
//!
//! The node does, as it would with no carrier in between: its WireGuard
//! sends to wherever the last packet it authenticated came from. For it to
//! tell the carrier, each address a phone sends from reaches the node from
//! a port of its own — a pool of sockets on the carrier's mesh address, each
//! port mapped, for each node, to one address — and what the node sends to
//! a port goes to the address mapped there. A phone that moves is answered
//! at its new address as soon as the node has taken one packet from there.
//! A port is never mapped to another address while the node may still send
//! to it: a mapping is never changed, never pushed out to make room, and
//! only forgotten once it has been quiet both ways for [`MAPPING_IDLE`].
//!
//! Without a port of its own — the node's pool full, or no pool — a phone's
//! packets reach the node from the main socket, which every such phone
//! shares, and the node's answers there say nothing about where it is. A
//! handshake is then only pending until the node shows it accepted it —
//! its response to a phone's initiation, or its first packet to the phone's
//! index after the phone answered the node's own — and only then becomes a
//! session, with the address the handshake came from. A phone that moves
//! is answered at its new address from its next handshake on: WireGuard
//! starts one when what it sends goes unanswered.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use super::packet::{mac1_key, mac1_matches, Message};

/// How long a session is kept after its last packet: WireGuard's
/// reject-after-time, after which neither end uses its keys any more.
pub const SESSION_LIFETIME: Duration = Duration::from_secs(180);

/// The most sessions kept at once. Past it the one quiet the longest makes
/// room. Only a handshake the node answered becomes a session, so a flood
/// of handshakes with a valid `mac1` (a node's public key is enough to make
/// one) never gets this far.
pub const MAX_SESSIONS: usize = 4096;

/// How long a handshake waits for the node to accept it: WireGuard's
/// rekey-timeout, after which the initiator gives up on it and sends a new
/// one, with a new index.
pub const PENDING_LIFETIME: Duration = Duration::from_secs(5);

/// The most handshakes pending at once. Past it the oldest makes room. The
/// firewall lets initiations through at 200 a second, 400 at once (PLAN.md
/// #338), so at most 1400 arrive within [`PENDING_LIFETIME`]: a flood at
/// that rate ages out before it can push out a handshake still waiting.
pub const MAX_PENDING: usize = 2048;

/// The most handshakes pending from one address to one node. A phone sends
/// a new one every [`PENDING_LIFETIME`] until one is answered, so it has one
/// or two at a time; past this the oldest of them makes room.
pub const MAX_PENDING_PER_PHONE: usize = 4;

/// How many ports a node's pool has: how many addresses phones can reach
/// that node from at once with a port of their own. A phone holds one for
/// the address it is at, and keeps the one of each address it left for
/// [`MAPPING_IDLE`] more; phones roam a few times an hour at most. The
/// ports are each node's, so this bounds no carrier's phones in all.
pub const POOL_SIZE: u16 = 64;

/// How long a port stays mapped after its last packet, either way. A node
/// sends data only under keys younger than WireGuard's reject-after-time
/// (180 s, [`SESSION_LIFETIME`]). The handshake that made them reached the
/// node from the phone through the port the node now sends to, or a later
/// packet from the phone did, or the node would be sending elsewhere; that
/// packet kept the port mapped. So the node sends data to a port at most
/// 180 s after the phone's last packet through it; the rest covers the
/// carrier's expiry tick and whatever is still on its way.
pub const MAPPING_IDLE: Duration = Duration::from_secs(240);

/// Which of the carrier's sockets on its mesh address a packet leaves from,
/// or arrived at: the main one, or a port of the pool, by its place in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Main,
    Pool(usize),
}

/// What to do with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Send it on to this node's WireGuard port, over the mesh, from this
    /// socket.
    ToNode(SocketAddrV4, Via),
    /// Send it to the phone at `phone`, from `from` — the address and port
    /// the phone dialled, so it sees the answer come from where it sent.
    ToPhone { phone: SocketAddrV4, from: SocketAddrV4 },
    /// Not a relayed session's: give it back to this host's own WireGuard
    /// as it came.
    ToKernel,
    Drop,
}

/// A session, or a node's own handshake the phone has not yet answered
/// (`phone_index` still `None`).
#[derive(Debug, Clone)]
struct Session {
    node: SocketAddrV4,
    phone: SocketAddrV4,
    local: SocketAddrV4,
    node_index: u32,
    phone_index: Option<u32>,
    /// The device, by the `mac1` of the node's handshake message: its
    /// response to the device's initiation, or its own initiation.
    device: Option<[u8; 32]>,
    seen: Instant,
}

/// A handshake from a phone's side the node has not accepted yet: the
/// phone's initiation, or its response to a node's own (`answers`, that
/// session). Keyed by the node and the phone's index, which no session of
/// that node has.
#[derive(Debug, Clone)]
struct Pending {
    phone: SocketAddrV4,
    local: SocketAddrV4,
    answers: Option<u64>,
    since: Instant,
    /// Its place in [`Sorter::pending_order`].
    seq: u64,
}

/// A port of a node's pool, mapped to one address a phone sends from and
/// the address it dialled. Never changed while it lasts.
#[derive(Debug, Clone)]
struct Mapping {
    phone: SocketAddrV4,
    local: SocketAddrV4,
    /// Its last packet, either way.
    seen: Instant,
    /// The device the node's packets through it were for, once the node
    /// sent one: what lets a node's own handshake, which can come long
    /// after, take the port's word for where the device is.
    device: Option<[u8; 32]>,
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
    pending: HashMap<(SocketAddrV4, u32), Pending>,
    /// The pending handshakes, oldest first.
    pending_order: BTreeMap<u64, (SocketAddrV4, u32)>,
    /// The pending handshakes from each address to each node, by the
    /// phone's index, oldest first.
    pending_by_phone: HashMap<(SocketAddrV4, SocketAddrV4), Vec<u32>>,
    /// Where each device was last seen, and the address it dialled: where
    /// a node's own handshake towards it goes.
    devices_seen: HashMap<[u8; 32], (SocketAddrV4, SocketAddrV4, Instant)>,
    /// Node indexes learned since the last [`Sorter::take_new_indexes`].
    new_indexes: Vec<u32>,
    /// How many ports each node's pool has: none until the carrier has
    /// them open and its firewall lets the nodes answer there.
    pool: usize,
    /// The mapped ports, by node and place in the pool.
    ports: HashMap<(SocketAddrV4, usize), Mapping>,
    /// The port of each node, phone address and address dialled.
    port_of: HashMap<(SocketAddrV4, SocketAddrV4, SocketAddrV4), usize>,
}

impl Sorter {
    /// The nodes this carrier relays to (their mesh address and WireGuard
    /// port, and public key) and the devices allowed to reach them. A node
    /// no longer listed loses its sessions and its ports at once.
    pub fn set_peers(&mut self, nodes: &[(SocketAddrV4, [u8; 32])], devices: &[[u8; 32]]) {
        let nodes: Vec<Node> = nodes.iter().map(|(addr, pk)| Node { addr: *addr, mac1: mac1_key(pk) }).collect();
        if nodes != self.nodes {
            self.nodes = nodes;
            let kept: Vec<SocketAddrV4> = self.nodes.iter().map(|n| n.addr).collect();
            let gone: Vec<u64> = self.sessions.iter().filter(|(_, s)| !kept.contains(&s.node)).map(|(id, _)| *id).collect();
            for id in gone {
                self.remove(id);
            }
            let gone: Vec<(SocketAddrV4, u32)> = self.pending.keys().filter(|(node, _)| !kept.contains(node)).copied().collect();
            for key in gone {
                self.remove_pending(key);
            }
            self.ports.retain(|(node, _), _| kept.contains(node));
            self.port_of.retain(|(node, _, _), _| kept.contains(node));
        }
        self.devices = devices.iter().map(|pk| (*pk, mac1_key(pk))).collect();
        let known: Vec<[u8; 32]> = devices.to_vec();
        self.devices_seen.retain(|pk, _| known.contains(pk));
    }

    /// Gives each node a pool of `size` ports. It only ever grows: a port
    /// mapped while the pool was larger may still be the one a node sends
    /// to.
    pub fn set_pool(&mut self, size: usize) {
        self.pool = self.pool.max(size);
    }

    /// A packet from a phone, arriving at `local`, the address it dialled.
    /// Nothing here is authenticated, so nothing here changes a session:
    /// a handshake is only noted, for the node to accept or not. What goes
    /// on to a node leaves from the port mapped to this address for that
    /// node, mapped now if it has none and one is free, or else from the
    /// main socket. A mapping is only ever added here, never changed.
    pub fn from_phone(&mut self, now: Instant, phone: SocketAddrV4, local: SocketAddrV4, packet: &[u8]) -> Action {
        match self.sort_from_phone(now, phone, local, packet) {
            Action::ToNode(node, _) => Action::ToNode(node, self.port_for(now, node, phone, local)),
            other => other,
        }
    }

    fn sort_from_phone(&mut self, now: Instant, phone: SocketAddrV4, local: SocketAddrV4, packet: &[u8]) -> Action {
        match Message::parse(packet) {
            Some(Message::Initiation { sender }) => {
                let Some(node) = self.nodes.iter().find(|n| mac1_matches(packet, &n.mac1)).map(|n| n.addr) else {
                    return Action::ToKernel;
                };
                // The same initiation again — from the phone, or replayed
                // from anywhere: the node has it already, and answers a
                // replay with nothing. It changes nothing here either.
                if self.index_taken(node, sender) {
                    return Action::Drop;
                }
                self.add_pending((node, sender), Pending { phone, local, answers: None, since: now, seq: 0 });
                Action::ToNode(node, Via::Main)
            }
            // The phone answering a node's own handshake, which only that
            // node's next packet to the phone's index settles.
            Some(Message::Response { sender, receiver }) => {
                let Some(id) = self.by_node_index.get(&receiver).copied() else { return Action::ToKernel };
                let s = self.sessions.get(&id).expect("indexed sessions exist");
                let node = s.node;
                // Answered already, or not made for that node: no phone's.
                let made_for_node = self.nodes.iter().any(|n| n.addr == node && mac1_matches(packet, &n.mac1));
                if s.phone_index.is_some() || !made_for_node || self.index_taken(node, sender) {
                    return Action::Drop;
                }
                self.add_pending((node, sender), Pending { phone, local, answers: Some(id), since: now, seq: 0 });
                Action::ToNode(node, Via::Main)
            }
            Some(Message::CookieReply { receiver } | Message::Data { receiver }) => {
                let Some(id) = self.by_node_index.get(&receiver).copied() else { return Action::ToKernel };
                let s = self.sessions.get_mut(&id).expect("indexed sessions exist");
                // From anywhere but where the session is, it still goes on:
                // the node authenticates it and drops what is forged or
                // replayed, and a phone that moved keeps reaching it. It
                // neither moves the session nor keeps it alive — the index
                // is in the clear, and anyone can send one like it.
                if (s.phone, s.local) == (phone, local) {
                    s.seen = now;
                }
                Action::ToNode(s.node, Via::Main)
            }
            None => Action::ToKernel,
        }
    }

    /// The port `phone`'s packets to `node` leave from: the one mapped to
    /// it, kept mapped by this packet, or the first free one, mapped to it
    /// now. A port another address holds is never taken: with the pool
    /// full, the main socket.
    fn port_for(&mut self, now: Instant, node: SocketAddrV4, phone: SocketAddrV4, local: SocketAddrV4) -> Via {
        if let Some(slot) = self.port_of.get(&(node, phone, local)).copied() {
            self.ports.get_mut(&(node, slot)).expect("mapped ports exist").seen = now;
            return Via::Pool(slot);
        }
        let Some(slot) = (0..self.pool).find(|slot| !self.ports.contains_key(&(node, *slot))) else {
            return Via::Main;
        };
        self.ports.insert((node, slot), Mapping { phone, local, seen: now, device: None });
        self.port_of.insert((node, phone, local), slot);
        Via::Pool(slot)
    }

    /// Where a node's packet for `device` goes when it arrived at a port of
    /// the pool: the address mapped there. The node's WireGuard sends to
    /// where the device's last packet it authenticated came from, and the
    /// carrier forwarded that packet from this port, which has had the one
    /// address all along. The port is tied to the first device the node
    /// sends to through it; a port tied to another one vouches for nothing,
    /// and the packet goes where it would from the main socket.
    fn vouched(&mut self, node: SocketAddrV4, on: Via, device: Option<[u8; 32]>) -> Option<(SocketAddrV4, SocketAddrV4)> {
        let Via::Pool(slot) = on else { return None };
        let m = self.ports.get_mut(&(node, slot))?;
        if m.device.is_some() && m.device != device {
            return None;
        }
        m.device = device;
        Some((m.phone, m.local))
    }

    /// A packet from `node`'s WireGuard port, over the mesh, arriving at
    /// the socket `on`.
    pub fn from_node(&mut self, now: Instant, node: SocketAddrV4, on: Via, packet: &[u8]) -> Action {
        if !self.nodes.iter().any(|n| n.addr == node) {
            return Action::Drop;
        }
        // Whatever the node sends to a port keeps it mapped: the node may
        // send there again.
        let mapped = match on {
            Via::Pool(slot) => self.ports.get_mut(&(node, slot)).map(|m| {
                m.seen = now;
                (m.phone, m.local)
            }),
            Via::Main => None,
        };
        match Message::parse(packet) {
            // The node answering a phone's handshake: it becomes a session,
            // at the address it came from, and the node's index is what the
            // phone's packets will carry from now on.
            Some(Message::Response { sender, receiver }) => {
                let key = (node, receiver);
                if !self.pending.get(&key).is_some_and(|p| p.answers.is_none()) {
                    return Action::Drop;
                }
                if self.by_node_index.contains_key(&sender) {
                    // Another session's already: this handshake fails, and
                    // the next one picks another index.
                    return Action::Drop;
                }
                let p = self.remove_pending(key).expect("pending just seen");
                // Its `mac1` names the device that started it.
                let device = self.devices.iter().find(|(_, k)| mac1_matches(packet, k)).map(|(pk, _)| *pk);
                // At a port, the node answers where it took the initiation
                // from: that port's address.
                let (phone, local) = self.vouched(node, on, device).unwrap_or((p.phone, p.local));
                let id = self.insert(Session { node, phone, local, node_index: sender, phone_index: Some(receiver), device, seen: now });
                self.by_node_index.insert(sender, id);
                self.by_phone_index.insert(key, id);
                self.new_indexes.push(sender);
                if let Some(pk) = device {
                    self.devices_seen.insert(pk, (phone, local, now));
                }
                Action::ToPhone { phone, from: local }
            }
            // The node starting a handshake with a device, by its key.
            Some(Message::Initiation { sender }) => {
                let Some(pk) = self.devices.iter().find(|(_, key)| mac1_matches(packet, key)).map(|(pk, _)| *pk) else {
                    return Action::Drop;
                };
                // The node may start one long after the device last sent it
                // anything, to a port mapped to another address since: the
                // port's address is taken only if the node has sent this
                // device's packets through it. Otherwise, where the device
                // was last vouched for.
                let tied = match on {
                    Via::Pool(slot) => self.ports.get(&(node, slot)).filter(|m| m.device == Some(pk)).map(|m| (m.phone, m.local)),
                    Via::Main => None,
                };
                let (phone, local) = match tied {
                    Some(at) => at,
                    None => match self.devices_seen.get(&pk) {
                        Some((phone, local, _)) => (*phone, *local),
                        None => return Action::Drop,
                    },
                };
                if let Some(old) = self.by_node_index.get(&sender).copied() {
                    if self.sessions.get(&old).is_some_and(|s| s.node != node || s.phone_index.is_some()) {
                        return Action::Drop;
                    }
                    self.remove(old);
                }
                if tied.is_some() {
                    self.devices_seen.insert(pk, (phone, local, now));
                }
                let id = self.insert(Session { node, phone, local, node_index: sender, phone_index: None, device: Some(pk), seen: now });
                self.by_node_index.insert(sender, id);
                self.new_indexes.push(sender);
                Action::ToPhone { phone, from: local }
            }
            Some(message @ (Message::CookieReply { receiver } | Message::Data { receiver })) => {
                let key = (node, receiver);
                let cookie = matches!(message, Message::CookieReply { .. });
                if let Some(id) = self.by_phone_index.get(&key).copied() {
                    let device = self.sessions.get(&id).expect("indexed sessions exist").device;
                    // A cookie reply goes back where the handshake it
                    // answers came from, so to the port's address too; but
                    // the node took nothing from there, and it vouches for
                    // nothing.
                    let at = if cookie { mapped } else { self.vouched(node, on, device) };
                    let s = self.sessions.get_mut(&id).expect("indexed sessions exist");
                    s.seen = now;
                    if let Some((phone, local)) = at.filter(|_| !cookie) {
                        (s.phone, s.local) = (phone, local);
                        if let Some(pk) = device {
                            self.devices_seen.insert(pk, (phone, local, now));
                        }
                    }
                    let (phone, local) = at.unwrap_or((s.phone, s.local));
                    return Action::ToPhone { phone, from: local };
                }
                let Some(p) = self.pending.get(&key) else { return Action::Drop };
                let (phone, local, answers) = (p.phone, p.local, p.answers);
                match (message, answers) {
                    // The node too busy to take the handshake, asking for it
                    // again: back to where it came from, settling nothing.
                    (Message::CookieReply { .. }, _) => {
                        let (phone, local) = mapped.unwrap_or((phone, local));
                        Action::ToPhone { phone, from: local }
                    }
                    // The node's first packet to a phone that answered its
                    // handshake: the node took that answer, and the session
                    // is now the phone's at the address it came from.
                    (_, Some(id)) => {
                        self.remove_pending(key);
                        let Some(device) = self.sessions.get(&id).filter(|s| s.phone_index.is_none()).map(|s| s.device) else {
                            return Action::Drop;
                        };
                        let (phone, local) = self.vouched(node, on, device).unwrap_or((phone, local));
                        let s = self.sessions.get_mut(&id).expect("indexed sessions exist");
                        (s.phone, s.local, s.phone_index, s.seen) = (phone, local, Some(receiver), now);
                        self.by_phone_index.insert(key, id);
                        if let Some(pk) = device {
                            self.devices_seen.insert(pk, (phone, local, now));
                        }
                        Action::ToPhone { phone, from: local }
                    }
                    // Data before the node answered the phone's handshake is
                    // nothing WireGuard sends.
                    (_, None) => Action::Drop,
                }
            }
            None => Action::Drop,
        }
    }

    /// Forgets the sessions quiet for longer than [`SESSION_LIFETIME`],
    /// where devices were seen as long ago, the handshakes pending for
    /// longer than [`PENDING_LIFETIME`], and the ports quiet both ways for
    /// longer than [`MAPPING_IDLE`].
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
        let old: Vec<(SocketAddrV4, u32)> = self
            .pending
            .iter()
            .filter(|(_, p)| now.saturating_duration_since(p.since) > PENDING_LIFETIME)
            .map(|(key, _)| *key)
            .collect();
        for key in old {
            self.remove_pending(key);
        }
        let idle: Vec<(SocketAddrV4, usize)> = self
            .ports
            .iter()
            .filter(|(_, m)| now.saturating_duration_since(m.seen) > MAPPING_IDLE)
            .map(|(key, _)| *key)
            .collect();
        for key in idle {
            if let Some(m) = self.ports.remove(&key) {
                self.port_of.remove(&(key.0, m.phone, m.local));
            }
        }
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

    /// How many handshakes wait for their node.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// How many ports are mapped, over every node.
    #[must_use]
    pub fn mapped(&self) -> usize {
        self.ports.len()
    }

    /// Whether `node` already has a session or a pending handshake with
    /// this phone index.
    fn index_taken(&self, node: SocketAddrV4, phone_index: u32) -> bool {
        self.by_phone_index.contains_key(&(node, phone_index)) || self.pending.contains_key(&(node, phone_index))
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
            self.by_node_index.remove(&s.node_index);
            if let Some(i) = s.phone_index {
                self.by_phone_index.remove(&(s.node, i));
            }
        }
    }

    /// Notes a pending handshake, making room first: among that phone's
    /// own to that node, then among all. Only pending handshakes ever make
    /// room for one, never a session.
    fn add_pending(&mut self, key: (SocketAddrV4, u32), mut pending: Pending) {
        let (node, index) = key;
        let oldest_of_phone = self
            .pending_by_phone
            .get(&(node, pending.phone))
            .filter(|indexes| indexes.len() >= MAX_PENDING_PER_PHONE)
            .and_then(|indexes| indexes.first().copied());
        if let Some(oldest) = oldest_of_phone {
            self.remove_pending((node, oldest));
        }
        if self.pending.len() >= MAX_PENDING {
            if let Some(oldest) = self.pending_order.values().next().copied() {
                self.remove_pending(oldest);
            }
        }
        pending.seq = self.next_id;
        self.next_id += 1;
        self.pending_order.insert(pending.seq, key);
        self.pending_by_phone.entry((node, pending.phone)).or_default().push(index);
        self.pending.insert(key, pending);
    }

    fn remove_pending(&mut self, key: (SocketAddrV4, u32)) -> Option<Pending> {
        let p = self.pending.remove(&key)?;
        self.pending_order.remove(&p.seq);
        let by_phone = (key.0, p.phone);
        if let Some(indexes) = self.pending_by_phone.get_mut(&by_phone) {
            indexes.retain(|i| *i != key.1);
            if indexes.is_empty() {
                self.pending_by_phone.remove(&by_phone);
            }
        }
        Some(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phone_relay::packet::tests::{answer, data, initiation, seal_mac1, End};
    use crate::phone_relay::packet::{Message, COOKIE_REPLY_LEN, DATA_MIN_LEN, INITIATION_LEN, RESPONSE_LEN};
    use defguard_boringtun::noise::{Tunn, TunnResult};
    use std::net::Ipv4Addr;

    const PHONE: &str = "198.51.100.7:40000";
    const ROAMED: &str = "203.0.113.9:51000";
    /// Another device behind the phone's NAT.
    const NEIGHBOUR: &str = "198.51.100.7:40001";
    /// Someone who saw the phone's packets go by, sending from elsewhere.
    const SPOOFED: &str = "192.0.2.66:6666";
    const LOCAL: &str = "192.0.2.1:51820";
    const MINIPC: &str = "10.1.0.5:51820";
    const NAS: &str = "10.1.0.6:51820";

    fn a(s: &str) -> SocketAddrV4 {
        s.parse().unwrap()
    }

    /// An initiation for the node with public key `node`, as anyone who
    /// knows that key can make one: a valid `mac1`, nothing else real.
    fn forged_initiation(sender: u32, node: &[u8; 32]) -> Vec<u8> {
        let mut p = vec![0u8; INITIATION_LEN];
        p[0] = 1;
        p[4..8].copy_from_slice(&sender.to_le_bytes());
        seal_mac1(&mut p, &mac1_key(node));
        p
    }

    /// A response to `initiator`'s handshake, made the same way.
    fn forged_response(sender: u32, receiver: u32, initiator: &[u8; 32]) -> Vec<u8> {
        let mut p = vec![0u8; RESPONSE_LEN];
        p[0] = 2;
        p[4..8].copy_from_slice(&sender.to_le_bytes());
        p[8..12].copy_from_slice(&receiver.to_le_bytes());
        seal_mac1(&mut p, &mac1_key(initiator));
        p
    }

    /// A data packet (or with `kind` 3, a cookie reply) for `receiver`.
    fn forged(kind: u8, receiver: u32) -> Vec<u8> {
        let mut p = vec![0u8; if kind == 3 { COOKIE_REPLY_LEN } else { DATA_MIN_LEN }];
        p[0] = kind;
        p[4..8].copy_from_slice(&receiver.to_le_bytes());
        p
    }

    fn sender(packet: &[u8]) -> u32 {
        match Message::parse(packet) {
            Some(Message::Initiation { sender } | Message::Response { sender, .. }) => sender,
            other => panic!("no sender: {other:?}"),
        }
    }

    /// The phone (key 1), and a carrier relaying it to minipc (key 2) and
    /// the NAS (key 3).
    struct World {
        sorter: Sorter,
        now: Instant,
        phone: End,
    }

    /// A node's WireGuard as the kernel's behaves towards the phone: it
    /// sends to the carrier's socket the last packet it authenticated came
    /// from. One forged or replayed moves nothing.
    struct NodeEnd {
        addr: &'static str,
        tunn: Tunn,
        endpoint: Via,
    }

    impl NodeEnd {
        fn new(addr: &'static str, me: &End, phone: &End, index: u32) -> Self {
            Self { addr, tunn: me.tunnel_to(phone, index), endpoint: Via::Main }
        }

        /// Takes what the carrier forwarded as `action` says, and what it
        /// answers.
        fn take(&mut self, action: Action, packet: &[u8]) -> Option<Vec<u8>> {
            let Action::ToNode(to, via) = action else { panic!("not sent on: {action:?}") };
            assert_eq!(to, a(self.addr), "sent to the wrong node");
            let mut buf = vec![0u8; 2048];
            match self.tunn.decapsulate(None, packet, &mut buf) {
                TunnResult::Err(_) => None,
                TunnResult::WriteToNetwork(p) => {
                    let p = p.to_vec();
                    self.endpoint = via;
                    Some(p)
                }
                _ => {
                    self.endpoint = via;
                    None
                }
            }
        }
    }

    fn at(phone: &str) -> Action {
        Action::ToPhone { phone: a(phone), from: a(LOCAL) }
    }

    impl World {
        /// No pool: everything to a node leaves from the main socket, as it
        /// does when a node's pool is full.
        fn new() -> Self {
            let phone = End::new(1);
            let mut sorter = Sorter::default();
            sorter.set_peers(&[(a(MINIPC), End::new(2).public), (a(NAS), End::new(3).public)], &[phone.public]);
            Self { sorter, now: Instant::now(), phone }
        }

        fn pooled(size: usize) -> Self {
            let mut w = Self::new();
            w.sorter.set_pool(size);
            w
        }

        /// `packet` from `from`, on to `node` if the carrier sends it there,
        /// and the node's answer.
        fn up(&mut self, from: &str, node: &mut NodeEnd, packet: &[u8]) -> Option<Vec<u8>> {
            let action = self.sent_from(from, packet);
            node.take(action, packet)
        }

        /// `packet` from `node`, to where its WireGuard sends.
        fn down(&mut self, node: &NodeEnd, packet: &[u8]) -> Action {
            self.sorter.from_node(self.now, a(node.addr), node.endpoint, packet)
        }

        /// A data packet from `node`, to where its WireGuard sends.
        fn node_data(&mut self, node: &mut NodeEnd) -> Action {
            let d = data(&mut node.tunn);
            self.down(node, &d)
        }

        /// The phone at `from` and a node handshake through the sorter's
        /// pool, the phone starting; the session up.
        fn pooled_handshake(&mut self, from: &str, node: &'static str, peer: &End, phone_index: u32) -> (Tunn, NodeEnd) {
            let mut p = self.phone.tunnel_to(peer, phone_index);
            let mut n = NodeEnd::new(node, peer, &self.phone, phone_index + 100);
            let init = initiation(&mut p);
            let resp = self.up(from, &mut n, &init).expect("the node answers");
            assert!(matches!(n.endpoint, Via::Pool(_)), "{:?}", n.endpoint);
            assert_eq!(self.down(&n, &resp), at(from));
            let keepalive = answer(&mut p, &resp).unwrap();
            assert!(self.up(from, &mut n, &keepalive).is_none());
            (p, n)
        }

        fn phone_sends(&mut self, packet: &[u8]) -> Action {
            self.sorter.from_phone(self.now, a(PHONE), a(LOCAL), packet)
        }

        fn sent_from(&mut self, from: &str, packet: &[u8]) -> Action {
            self.sorter.from_phone(self.now, a(from), a(LOCAL), packet)
        }

        fn node_sends(&mut self, node: &str, packet: &[u8]) -> Action {
            self.sorter.from_node(self.now, a(node), Via::Main, packet)
        }

        /// The phone and `node` handshake through the sorter, the phone
        /// starting; returns both tunnels, the session up.
        fn handshake(&mut self, node: &str, peer: &End, phone_index: u32) -> (Tunn, Tunn) {
            let mut p = self.phone.tunnel_to(peer, phone_index);
            let mut n = peer.tunnel_to(&self.phone, phone_index + 100);
            let init = initiation(&mut p);
            assert_eq!(self.phone_sends(&init), Action::ToNode(a(node), Via::Main));
            let resp = answer(&mut n, &init).unwrap();
            assert_eq!(self.node_sends(node, &resp), Action::ToPhone { phone: a(PHONE), from: a(LOCAL) });
            let keepalive = answer(&mut p, &resp).unwrap();
            assert_eq!(self.phone_sends(&keepalive), Action::ToNode(a(node), Via::Main));
            assert!(answer(&mut n, &keepalive).is_none());
            (p, n)
        }
    }

    const AT_PHONE: Action = Action::ToPhone { phone: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 40000), from: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 51820) };
    const AT_ROAMED: Action = Action::ToPhone { phone: SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 51000), from: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 51820) };

    #[test]
    fn a_phone_reaches_each_node_by_its_handshake_and_its_index() {
        let mut w = World::new();
        let (minipc, nas) = (End::new(2), End::new(3));
        let (mut p1, mut n1) = w.handshake(MINIPC, &minipc, 1);
        let (mut p2, mut n2) = w.handshake(NAS, &nas, 2);
        assert_eq!(w.sorter.len(), 2);
        assert_eq!(w.sorter.pending(), 0);
        assert_eq!(w.phone_sends(&data(&mut p1)), Action::ToNode(a(MINIPC), Via::Main));
        assert_eq!(w.phone_sends(&data(&mut p2)), Action::ToNode(a(NAS), Via::Main));
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), Via::Main, &data(&mut n1)), Action::ToPhone { phone: a(PHONE), from: a(LOCAL) });
        assert_eq!(w.sorter.from_node(w.now, a(NAS), Via::Main, &data(&mut n2)), Action::ToPhone { phone: a(PHONE), from: a(LOCAL) });
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
        assert_eq!(w.sorter.pending(), 0);
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
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), Via::Main, &init), Action::ToPhone { phone: a(PHONE), from: a(LOCAL) });
        let resp = answer(&mut p, &init).unwrap();
        assert_eq!(w.phone_sends(&resp), Action::ToNode(a(MINIPC), Via::Main), "the response carries the node's index");
        assert_eq!(w.sorter.pending(), 1, "until the node takes it");
        let keepalive = answer(&mut n, &resp).unwrap();
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), Via::Main, &keepalive), Action::ToPhone { phone: a(PHONE), from: a(LOCAL) });
        assert_eq!(w.sorter.pending(), 0);
        assert_eq!(w.phone_sends(&data(&mut p)), Action::ToNode(a(MINIPC), Via::Main));
        assert_eq!(w.node_sends(MINIPC, &data(&mut n)), AT_PHONE);
    }

    #[test]
    fn a_node_cannot_reach_a_device_never_seen_or_not_allowed() {
        let mut w = World::new();
        let stranger = End::new(9);
        let minipc = End::new(2);
        let mut n = minipc.tunnel_to(&w.phone, 300);
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), Via::Main, &initiation(&mut n)), Action::Drop, "never seen");
        let mut n = minipc.tunnel_to(&stranger, 301);
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), Via::Main, &initiation(&mut n)), Action::Drop, "not a device");
        let _ = w.handshake(MINIPC, &minipc, 1);
        let mut n = minipc.tunnel_to(&w.phone, 302);
        assert_eq!(w.sorter.from_node(w.now, a("10.1.0.99:51820"), Via::Main, &initiation(&mut n)), Action::Drop, "not a node");
    }

    #[test]
    fn without_a_port_of_its_own_a_phone_that_moves_is_answered_where_it_is_now_once_the_node_answers_its_next_handshake() {
        let mut w = World::new();
        let minipc = End::new(2);
        let (mut p, mut n) = w.handshake(MINIPC, &minipc, 1);
        // Its data still reaches the node from the new address, but the
        // node's answers go where the session is until a handshake says
        // otherwise.
        assert_eq!(w.sent_from(ROAMED, &data(&mut p)), Action::ToNode(a(MINIPC), Via::Main));
        assert_eq!(w.node_sends(MINIPC, &data(&mut n)), AT_PHONE);
        // The phone's next handshake, from where it is now.
        let init = initiation(&mut p);
        assert_eq!(w.sent_from(ROAMED, &init), Action::ToNode(a(MINIPC), Via::Main));
        assert_eq!(w.node_sends(MINIPC, &data(&mut n)), AT_PHONE, "pending: the session stays where it was");
        let resp = answer(&mut n, &init).unwrap();
        assert_eq!(w.node_sends(MINIPC, &resp), AT_ROAMED, "the node answered: the new session is at the new address");
        let keepalive = answer(&mut p, &resp).unwrap();
        assert_eq!(w.sent_from(ROAMED, &keepalive), Action::ToNode(a(MINIPC), Via::Main));
        assert!(answer(&mut n, &keepalive).is_none());
        assert_eq!(w.node_sends(MINIPC, &data(&mut n)), AT_ROAMED);
        assert_eq!(w.sent_from(ROAMED, &data(&mut p)), Action::ToNode(a(MINIPC), Via::Main));
        // And a node's own handshake now looks for it there.
        let mut rekey = minipc.tunnel_to(&w.phone, 500);
        assert_eq!(w.node_sends(MINIPC, &initiation(&mut rekey)), AT_ROAMED);
    }

    #[test]
    fn without_a_port_of_its_own_a_spoofed_data_packet_neither_moves_a_session_nor_keeps_it_alive() {
        let mut w = World::new();
        let minipc = End::new(2);
        let (mut p, mut n) = w.handshake(MINIPC, &minipc, 1);
        let node_index = w.sorter.node_indexes()[0];
        let captured = data(&mut p);
        assert_eq!(w.phone_sends(&captured), Action::ToNode(a(MINIPC), Via::Main));
        let last = w.now;
        w.now += SESSION_LIFETIME / 2;
        // The same packet again, and ones made up, from elsewhere: on to
        // the node, which drops them all.
        assert_eq!(w.sent_from(SPOOFED, &captured), Action::ToNode(a(MINIPC), Via::Main));
        assert_eq!(w.sent_from(SPOOFED, &forged(4, node_index)), Action::ToNode(a(MINIPC), Via::Main));
        assert_eq!(w.sent_from(SPOOFED, &forged(3, node_index)), Action::ToNode(a(MINIPC), Via::Main));
        assert_eq!(w.sorter.node_indexes(), vec![node_index]);
        assert_eq!(w.sorter.from_node(last, a(MINIPC), Via::Main, &data(&mut n)), AT_PHONE, "the downlink stays with the phone");
        // The real packets were the session's last: the spoofed ones, later,
        // count for nothing.
        w.sorter.expire(last + SESSION_LIFETIME + Duration::from_secs(1));
        assert!(w.sorter.is_empty());
    }

    #[test]
    fn a_spoofed_response_re_indexes_nothing() {
        let mut w = World::new();
        let minipc = End::new(2);
        let (mut p, mut n) = w.handshake(MINIPC, &minipc, 1);
        let node_index = w.sorter.node_indexes()[0];
        // Made for minipc, with a fresh index of its own, at a session the
        // phone started: no node's handshake waits for it.
        assert_eq!(w.sent_from(SPOOFED, &forged_response(0xdead, node_index, &minipc.public)), Action::Drop);
        assert_eq!(w.sorter.pending(), 0);
        assert_eq!(w.node_sends(MINIPC, &data(&mut n)), AT_PHONE);
        assert_eq!(w.phone_sends(&data(&mut p)), Action::ToNode(a(MINIPC), Via::Main));

        // At a node's own handshake, ahead of the phone's real answer.
        let mut n2 = minipc.tunnel_to(&w.phone, 300);
        let mut p2 = w.phone.tunnel_to(&minipc, 400);
        let init = initiation(&mut n2);
        assert_eq!(w.node_sends(MINIPC, &init), AT_PHONE);
        let theirs = sender(&init);
        assert_eq!(w.sent_from(SPOOFED, &forged_response(0xbeef, theirs, &w.phone.public)), Action::Drop, "not made for the node");
        assert_eq!(w.sent_from(SPOOFED, &forged_response(0xbeef, theirs, &minipc.public)), Action::ToNode(a(MINIPC), Via::Main));
        let resp = answer(&mut p2, &init).unwrap();
        assert_eq!(w.phone_sends(&resp), Action::ToNode(a(MINIPC), Via::Main), "the phone's own answer is not shut out");
        assert_eq!(w.sorter.pending(), 2);
        // The node takes only the real one, and its first packet says which.
        let keepalive = answer(&mut n2, &resp).unwrap();
        assert_eq!(w.node_sends(MINIPC, &keepalive), AT_PHONE);
        assert_eq!(w.node_sends(MINIPC, &forged(4, 0xbeef)), Action::Drop, "the forged answer's index is nobody's");
        assert_eq!(w.sent_from(SPOOFED, &forged_response(0xf00d, theirs, &minipc.public)), Action::Drop, "answered already");
        assert_eq!(w.phone_sends(&data(&mut p2)), Action::ToNode(a(MINIPC), Via::Main));
        assert_eq!(w.node_sends(MINIPC, &data(&mut n2)), AT_PHONE);
    }

    #[test]
    fn a_replayed_initiation_leaves_the_session_it_started_alone() {
        let mut w = World::new();
        let minipc = End::new(2);
        let mut p = w.phone.tunnel_to(&minipc, 1);
        let mut n = minipc.tunnel_to(&w.phone, 101);
        let init = initiation(&mut p);
        assert_eq!(w.phone_sends(&init), Action::ToNode(a(MINIPC), Via::Main));
        assert_eq!(w.sent_from(SPOOFED, &init), Action::Drop, "while it is pending");
        let resp = answer(&mut n, &init).unwrap();
        assert_eq!(w.node_sends(MINIPC, &resp), AT_PHONE, "the node's answer goes to the phone, not the replay");
        let keepalive = answer(&mut p, &resp).unwrap();
        assert_eq!(w.phone_sends(&keepalive), Action::ToNode(a(MINIPC), Via::Main));
        assert!(answer(&mut n, &keepalive).is_none());
        let held = w.sorter.node_indexes();
        assert_eq!(w.sent_from(SPOOFED, &init), Action::Drop, "once it is a session");
        assert_eq!(w.sent_from(PHONE, &init), Action::Drop, "even from the phone's own address");
        assert_eq!((w.sorter.len(), w.sorter.pending()), (1, 0));
        assert_eq!(w.sorter.node_indexes(), held);
        assert_eq!(w.node_sends(MINIPC, &data(&mut n)), AT_PHONE);
        assert_eq!(w.phone_sends(&data(&mut p)), Action::ToNode(a(MINIPC), Via::Main));
    }

    #[test]
    fn without_a_port_of_its_own_a_node_that_rekeys_finds_a_phone_at_a_new_address_once_it_takes_the_phones_answer() {
        let mut w = World::new();
        let minipc = End::new(2);
        let (_p, mut n) = w.handshake(MINIPC, &minipc, 1);
        let mut n2 = minipc.tunnel_to(&w.phone, 300);
        let mut p2 = w.phone.tunnel_to(&minipc, 400);
        let init = initiation(&mut n2);
        assert_eq!(w.node_sends(MINIPC, &init), AT_PHONE, "where the phone was last");
        // The phone's answer leaves from a new address (its NAT moved it).
        let resp = answer(&mut p2, &init).unwrap();
        assert_eq!(w.sent_from(ROAMED, &resp), Action::ToNode(a(MINIPC), Via::Main));
        assert_eq!(w.node_sends(MINIPC, &data(&mut n)), AT_PHONE, "the older session is untouched");
        let keepalive = answer(&mut n2, &resp).unwrap();
        assert_eq!(w.node_sends(MINIPC, &keepalive), AT_ROAMED, "the node took the answer from there");
        assert_eq!(w.sent_from(ROAMED, &data(&mut p2)), Action::ToNode(a(MINIPC), Via::Main));
        assert_eq!(w.node_sends(MINIPC, &data(&mut n2)), AT_ROAMED);
        let mut n3 = minipc.tunnel_to(&w.phone, 301);
        assert_eq!(w.node_sends(MINIPC, &initiation(&mut n3)), AT_ROAMED, "the next one looks there");
    }

    #[test]
    fn a_cookie_reply_goes_where_the_pending_handshake_came_from_and_settles_nothing() {
        let mut w = World::new();
        let minipc = End::new(2);
        let (_p, mut n) = w.handshake(MINIPC, &minipc, 1);
        assert_eq!(w.sent_from(ROAMED, &forged_initiation(77, &minipc.public)), Action::ToNode(a(MINIPC), Via::Main));
        assert_eq!(w.node_sends(MINIPC, &forged(3, 77)), AT_ROAMED);
        assert_eq!(w.node_sends(MINIPC, &forged(4, 77)), Action::Drop, "no data before a response");
        assert_eq!((w.sorter.len(), w.sorter.pending()), (1, 1));
        assert_eq!(w.node_sends(MINIPC, &data(&mut n)), AT_PHONE);
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
        assert_eq!(w.phone_sends(&init), Action::ToNode(a(NAS), Via::Main));
        let resp = answer(&mut n, &init).unwrap();
        let held = w.sorter.node_indexes();
        let Some(Message::Response { sender, .. }) = Message::parse(&resp) else { panic!() };
        assert!(held.contains(&sender), "the test needs the same index: {held:?} {sender}");
        assert_eq!(w.sorter.from_node(w.now, a(NAS), Via::Main, &resp), Action::Drop);
        assert_eq!(w.sorter.node_indexes(), held, "minipc's session keeps its index");
    }

    #[test]
    fn quiet_sessions_expire_and_their_packets_go_back_to_the_kernel() {
        let mut w = World::new();
        let minipc = End::new(2);
        let (mut p, _n) = w.handshake(MINIPC, &minipc, 1);
        w.now += SESSION_LIFETIME / 2;
        assert_eq!(w.phone_sends(&data(&mut p)), Action::ToNode(a(MINIPC), Via::Main));
        w.sorter.expire(w.now + SESSION_LIFETIME / 2);
        assert_eq!(w.sorter.len(), 1, "kept alive by its last packet");
        w.sorter.expire(w.now + SESSION_LIFETIME + Duration::from_secs(1));
        assert!(w.sorter.is_empty() && w.sorter.node_indexes().is_empty());
        assert_eq!(w.phone_sends(&data(&mut p)), Action::ToKernel);
    }

    #[test]
    fn a_handshake_the_node_does_not_answer_in_time_is_forgotten() {
        let mut w = World::new();
        let minipc = End::new(2);
        assert_eq!(w.phone_sends(&forged_initiation(77, &minipc.public)), Action::ToNode(a(MINIPC), Via::Main));
        w.sorter.expire(w.now + PENDING_LIFETIME);
        assert_eq!(w.sorter.pending(), 1);
        w.now += PENDING_LIFETIME + Duration::from_secs(1);
        w.sorter.expire(w.now);
        assert_eq!(w.sorter.pending(), 0);
        assert_eq!(w.node_sends(MINIPC, &forged_response(5, 77, &w.phone.public)), Action::Drop);
        assert!(w.sorter.is_empty());
    }

    #[test]
    fn a_node_taken_off_the_list_loses_its_sessions() {
        let mut w = World::new();
        let (minipc, nas) = (End::new(2), End::new(3));
        let (mut p, _n) = w.handshake(MINIPC, &minipc, 1);
        let _ = w.handshake(NAS, &nas, 2);
        assert_eq!(w.phone_sends(&forged_initiation(77, &minipc.public)), Action::ToNode(a(MINIPC), Via::Main));
        w.sorter.set_peers(&[(a(NAS), nas.public)], &[w.phone.public]);
        assert_eq!((w.sorter.len(), w.sorter.pending()), (1, 0));
        assert_eq!(w.phone_sends(&data(&mut p)), Action::ToKernel);
    }

    #[test]
    fn pending_handshakes_are_bounded_from_each_address_and_overall() {
        let mut w = World::new();
        let minipc = End::new(2);
        for i in 0..=u32::try_from(MAX_PENDING_PER_PHONE).unwrap() {
            w.now += Duration::from_millis(1);
            assert_eq!(w.phone_sends(&forged_initiation(i, &minipc.public)), Action::ToNode(a(MINIPC), Via::Main));
        }
        assert_eq!(w.sorter.pending(), MAX_PENDING_PER_PHONE);
        assert_eq!(w.node_sends(MINIPC, &forged_response(9000, 0, &w.phone.public)), Action::Drop, "the oldest made room");
        assert_eq!(w.node_sends(MINIPC, &forged_response(9001, 1, &w.phone.public)), AT_PHONE);
        // The same index to another node is another handshake.
        assert_eq!(w.phone_sends(&forged_initiation(2, &End::new(3).public)), Action::ToNode(a(NAS), Via::Main));

        let mut w = World::new();
        for i in 0..=u32::try_from(MAX_PENDING).unwrap() {
            w.now += Duration::from_millis(1);
            let from = SocketAddrV4::new(Ipv4Addr::from(0x0a00_0000 + i), 40000);
            assert_eq!(w.sorter.from_phone(w.now, from, a(LOCAL), &forged_initiation(i, &minipc.public)), Action::ToNode(a(MINIPC), Via::Main));
        }
        assert_eq!(w.sorter.pending(), MAX_PENDING);
        assert_eq!(w.node_sends(MINIPC, &forged_response(9000, 0, &w.phone.public)), Action::Drop, "the oldest made room");
        assert_eq!(w.node_sends(MINIPC, &forged_response(9001, 1, &w.phone.public)), Action::ToPhone { phone: SocketAddrV4::new(Ipv4Addr::from(0x0a00_0001), 40000), from: a(LOCAL) });
        assert_eq!(w.sorter.pending(), MAX_PENDING - 1);
    }

    #[test]
    fn a_flood_of_handshakes_the_node_never_answers_pushes_out_no_session() {
        let mut w = World::new();
        let minipc = End::new(2);
        let (mut p, mut n) = w.handshake(MINIPC, &minipc, 1);
        // Idle, and older than every one of them.
        for i in 0..MAX_SESSIONS + MAX_PENDING {
            w.now += Duration::from_millis(1);
            let i = u32::try_from(i).unwrap();
            let from = SocketAddrV4::new(Ipv4Addr::from(0x0a00_0000 + i), 40000);
            assert_eq!(w.sorter.from_phone(w.now, from, a(LOCAL), &forged_initiation(1000 + i, &minipc.public)), Action::ToNode(a(MINIPC), Via::Main));
        }
        assert_eq!((w.sorter.len(), w.sorter.pending()), (1, MAX_PENDING));
        assert_eq!(w.phone_sends(&data(&mut p)), Action::ToNode(a(MINIPC), Via::Main));
        assert_eq!(w.node_sends(MINIPC, &data(&mut n)), AT_PHONE);
    }

    #[test]
    fn a_flood_of_answered_handshakes_pushes_out_only_the_quietest_session() {
        let mut w = World::new();
        let minipc = End::new(2);
        let (mut p, _n) = w.handshake(MINIPC, &minipc, 1);
        // A first session, then MAX_SESSIONS more the node answered, each
        // one newer.
        for i in 0..MAX_SESSIONS {
            w.now += Duration::from_millis(1);
            let i = u32::try_from(i).unwrap();
            assert_eq!(w.phone_sends(&forged_initiation(1000 + i, &minipc.public)), Action::ToNode(a(MINIPC), Via::Main));
            assert_eq!(w.node_sends(MINIPC, &forged_response(1_000_000 + i, 1000 + i, &w.phone.public)), AT_PHONE);
        }
        assert_eq!(w.sorter.len(), MAX_SESSIONS);
        assert_eq!(w.phone_sends(&data(&mut p)), Action::ToKernel, "the oldest made room");
        assert_eq!(w.sorter.node_indexes().len(), MAX_SESSIONS, "and took its index with it");
    }

    // ---- with a port of its own: the node's WireGuard says where it is ----

    #[test]
    fn a_phone_that_moves_is_answered_at_its_new_address_on_the_nodes_very_next_packet() {
        let mut w = World::pooled(POOL_SIZE.into());
        let minipc = End::new(2);
        let (mut p, mut n) = w.pooled_handshake(PHONE, MINIPC, &minipc, 1);
        assert_eq!(n.endpoint, Via::Pool(0));
        assert_eq!(w.node_data(&mut n), AT_PHONE);
        let indexes = w.sorter.node_indexes();
        // One packet from the new address, no handshake: the node takes it,
        // and its next packet goes there.
        assert!(w.up(ROAMED, &mut n, &data(&mut p)).is_none());
        assert_eq!(n.endpoint, Via::Pool(1), "a port of its own for the new address");
        assert_eq!(w.node_data(&mut n), AT_ROAMED);
        assert_eq!((w.sorter.len(), w.sorter.pending(), w.sorter.mapped()), (1, 0, 2));
        assert_eq!(w.sorter.node_indexes(), indexes, "the same session");
        // What reaches the main socket follows too: the node vouched for it.
        assert_eq!(w.node_sends(MINIPC, &data(&mut n.tunn)), AT_ROAMED);
        // And the node's own handshake, through that port, goes there.
        let mut rekey = minipc.tunnel_to(&w.phone, 500);
        let init = initiation(&mut rekey);
        assert_eq!(w.down(&n, &init), AT_ROAMED);
    }

    #[test]
    fn a_spoofed_packet_with_a_live_index_gets_a_port_is_sent_on_and_changes_nothing() {
        let mut w = World::pooled(POOL_SIZE.into());
        let minipc = End::new(2);
        let (mut p, mut n) = w.pooled_handshake(PHONE, MINIPC, &minipc, 1);
        let node_index = w.sorter.node_indexes()[0];
        let captured = data(&mut p);
        assert!(w.up(PHONE, &mut n, &captured).is_none());
        // A copy, and ones made up, from elsewhere: each on to the node
        // from a port of the spoofer's own, and the node takes none of them.
        assert_eq!(w.sent_from(SPOOFED, &captured), Action::ToNode(a(MINIPC), Via::Pool(1)));
        assert!(w.up(SPOOFED, &mut n, &captured).is_none());
        assert!(w.up(SPOOFED, &mut n, &forged(4, node_index)).is_none());
        assert_eq!(w.sent_from(SPOOFED, &forged(3, node_index)), Action::ToNode(a(MINIPC), Via::Pool(1)));
        assert_eq!(n.endpoint, Via::Pool(0), "the node still sends to the phone's port");
        assert_eq!(w.sorter.node_indexes(), vec![node_index]);
        assert_eq!((w.sorter.len(), w.sorter.pending(), w.sorter.mapped()), (1, 0, 2));
        assert_eq!(w.node_data(&mut n), AT_PHONE, "the downlink stays with the phone");
        assert_eq!(w.node_sends(MINIPC, &data(&mut n.tunn)), AT_PHONE, "and at the main socket");
    }

    #[test]
    fn a_phone_still_moves_at_once_among_ports_a_spoofer_holds() {
        let mut w = World::pooled(8);
        let minipc = End::new(2);
        let (mut p, mut n) = w.pooled_handshake(PHONE, MINIPC, &minipc, 1);
        let node_index = w.sorter.node_indexes()[0];
        for port in 7000..7005u16 {
            assert!(w.up(&format!("192.0.2.66:{port}"), &mut n, &forged(4, node_index)).is_none());
        }
        assert_eq!(w.sorter.mapped(), 6);
        assert_eq!(n.endpoint, Via::Pool(0));
        assert!(w.up(ROAMED, &mut n, &data(&mut p)).is_none());
        assert_eq!(n.endpoint, Via::Pool(6));
        assert_eq!(w.node_data(&mut n), AT_ROAMED);
    }

    #[test]
    fn with_its_nodes_pool_full_a_new_address_goes_from_the_main_socket_and_moves_only_with_a_handshake() {
        let mut w = World::pooled(2);
        let (minipc, nas) = (End::new(2), End::new(3));
        let (mut p, mut n) = w.pooled_handshake(PHONE, MINIPC, &minipc, 1);
        let node_index = w.sorter.node_indexes()[0];
        assert!(w.up(SPOOFED, &mut n, &forged(4, node_index)).is_none());
        assert_eq!(w.sorter.mapped(), 2, "minipc's pool is full");
        // The roamed phone's data reaches the node from the main socket; the
        // node takes it, and answers there, which says nothing of where.
        assert_eq!(w.sent_from(ROAMED, &data(&mut p)), Action::ToNode(a(MINIPC), Via::Main));
        assert!(w.up(ROAMED, &mut n, &data(&mut p)).is_none());
        assert_eq!(n.endpoint, Via::Main);
        assert_eq!(w.node_data(&mut n), AT_PHONE, "where the session is, as before there were ports");
        // Its next handshake, from there, moves it.
        let init = initiation(&mut p);
        let resp = w.up(ROAMED, &mut n, &init).unwrap();
        assert_eq!(w.node_data(&mut n), AT_PHONE, "pending: the session stays where it was");
        assert_eq!(w.down(&n, &resp), AT_ROAMED, "the node answered: the new session is at the new address");
        let keepalive = answer(&mut p, &resp).unwrap();
        assert!(w.up(ROAMED, &mut n, &keepalive).is_none());
        assert_eq!(w.node_data(&mut n), AT_ROAMED);
        // The NAS's pool is its own: the same address gets a port there.
        let mut to_nas = w.phone.tunnel_to(&nas, 2);
        assert_eq!(w.sent_from(ROAMED, &initiation(&mut to_nas)), Action::ToNode(a(NAS), Via::Pool(0)));
    }

    #[test]
    fn a_port_is_mapped_again_only_once_it_has_been_quiet_for_its_idle_limit() {
        let mut w = World::pooled(1);
        let minipc = End::new(2);
        let (_p, _n) = w.pooled_handshake(PHONE, MINIPC, &minipc, 1);
        let quiet = w.now;
        // The phone and the node both quiet from here on; somebody else
        // keeps asking for a port.
        w.now = quiet + SESSION_LIFETIME;
        w.sorter.expire(w.now);
        assert_eq!(w.sent_from(SPOOFED, &forged_initiation(70, &minipc.public)), Action::ToNode(a(MINIPC), Via::Main));
        w.now = quiet + MAPPING_IDLE;
        w.sorter.expire(w.now);
        assert_eq!(w.sorter.mapped(), 1, "still the phone's");
        assert_eq!(w.sent_from(SPOOFED, &forged_initiation(71, &minipc.public)), Action::ToNode(a(MINIPC), Via::Main));
        w.now = quiet + MAPPING_IDLE + Duration::from_secs(1);
        w.sorter.expire(w.now);
        assert_eq!(w.sorter.mapped(), 0);
        assert_eq!(w.sent_from(SPOOFED, &forged_initiation(72, &minipc.public)), Action::ToNode(a(MINIPC), Via::Pool(0)));
        // The port is the spoofer's now, and nothing of the phone's is: a
        // node's own handshake for it there finds no device the port knows.
        let mut rekey = minipc.tunnel_to(&w.phone, 500);
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), Via::Pool(0), &initiation(&mut rekey)), Action::Drop);
    }

    #[test]
    fn a_port_the_node_keeps_sending_to_stays_mapped_however_quiet_the_phone() {
        let mut w = World::pooled(1);
        let minipc = End::new(2);
        let (_p, mut n) = w.pooled_handshake(PHONE, MINIPC, &minipc, 1);
        for _ in 0..4 {
            w.now += MAPPING_IDLE / 2;
            w.sorter.expire(w.now);
            assert_eq!(w.node_data(&mut n), AT_PHONE);
        }
        assert_eq!(w.sorter.mapped(), 1);
        assert_eq!(w.sent_from(SPOOFED, &forged_initiation(70, &minipc.public)), Action::ToNode(a(MINIPC), Via::Main), "the pool is still full");
    }

    #[test]
    fn a_phone_that_goes_back_and_forth_finds_its_port_at_each_address() {
        let mut w = World::pooled(POOL_SIZE.into());
        let minipc = End::new(2);
        let (mut p, mut n) = w.pooled_handshake(PHONE, MINIPC, &minipc, 1);
        assert!(w.up(ROAMED, &mut n, &data(&mut p)).is_none());
        assert_eq!((n.endpoint, w.node_data(&mut n)), (Via::Pool(1), AT_ROAMED));
        w.now += Duration::from_secs(30);
        assert!(w.up(PHONE, &mut n, &data(&mut p)).is_none());
        assert_eq!((n.endpoint, w.node_data(&mut n)), (Via::Pool(0), AT_PHONE), "its first port, still its own");
        assert!(w.up(ROAMED, &mut n, &data(&mut p)).is_none());
        assert_eq!((n.endpoint, w.node_data(&mut n)), (Via::Pool(1), AT_ROAMED));
        assert_eq!(w.sorter.mapped(), 2);
    }

    #[test]
    fn a_rekey_while_roamed_stays_with_the_phone_whichever_end_starts_it() {
        let mut w = World::pooled(POOL_SIZE.into());
        let minipc = End::new(2);
        let (mut p, mut n) = w.pooled_handshake(PHONE, MINIPC, &minipc, 1);
        assert!(w.up(ROAMED, &mut n, &data(&mut p)).is_none());
        assert_eq!(w.node_data(&mut n), AT_ROAMED);

        // The phone starts it, from where it is now: through its port there.
        let init = initiation(&mut p);
        let resp = w.up(ROAMED, &mut n, &init).unwrap();
        assert_eq!(n.endpoint, Via::Pool(1));
        assert_eq!(w.down(&n, &resp), AT_ROAMED);
        let keepalive = answer(&mut p, &resp).unwrap();
        assert!(w.up(ROAMED, &mut n, &keepalive).is_none());
        assert_eq!(w.node_data(&mut n), AT_ROAMED);

        // The node starts it: to the port it last heard the phone from.
        let init = initiation(&mut n.tunn);
        assert_eq!(w.down(&n, &init), AT_ROAMED);
        let resp = answer(&mut p, &init).unwrap();
        let keepalive = w.up(ROAMED, &mut n, &resp).expect("the node confirms with its first packet");
        assert_eq!(w.down(&n, &keepalive), AT_ROAMED);
        assert!(w.up(ROAMED, &mut n, &data(&mut p)).is_none());
        assert_eq!(w.node_data(&mut n), AT_ROAMED);
        // Each new session took the phone's address, for the main socket's
        // sake too.
        assert_eq!(w.node_sends(MINIPC, &data(&mut n.tunn)), AT_ROAMED);
        assert_eq!(w.sorter.mapped(), 2);
    }

    #[test]
    fn two_nodes_keep_their_ports_apart() {
        let mut w = World::pooled(2);
        let (minipc, nas) = (End::new(2), End::new(3));
        let (mut p1, mut n1) = w.pooled_handshake(PHONE, MINIPC, &minipc, 1);
        let (mut p2, mut n2) = w.pooled_handshake(PHONE, NAS, &nas, 2);
        assert_eq!((n1.endpoint, n2.endpoint), (Via::Pool(0), Via::Pool(0)), "each node's first port");
        // A spoofer fills minipc's pool and not the NAS's.
        let Some(Message::Data { receiver: minipc_index }) = Message::parse(&data(&mut p1)) else { panic!() };
        assert!(w.up(SPOOFED, &mut n1, &forged(4, minipc_index)).is_none());
        assert!(w.up(ROAMED, &mut n1, &data(&mut p1)).is_none());
        assert!(w.up(ROAMED, &mut n2, &data(&mut p2)).is_none());
        assert_eq!((n1.endpoint, n2.endpoint), (Via::Main, Via::Pool(1)));
        assert_eq!(w.node_data(&mut n1), AT_PHONE, "minipc: from the main socket, until a handshake");
        assert_eq!(w.node_data(&mut n2), AT_ROAMED, "the NAS: at once");
    }

    #[test]
    fn two_devices_behind_one_nat_get_a_port_each() {
        let mut w = World::pooled(POOL_SIZE.into());
        let (minipc, tablet) = (End::new(2), End::new(5));
        w.sorter.set_peers(&[(a(MINIPC), minipc.public), (a(NAS), End::new(3).public)], &[w.phone.public, tablet.public]);
        let (_p, mut n) = w.pooled_handshake(PHONE, MINIPC, &minipc, 1);
        let mut t = tablet.tunnel_to(&minipc, 7);
        let mut nt = NodeEnd::new(MINIPC, &minipc, &tablet, 107);
        let init = initiation(&mut t);
        let resp = w.up(NEIGHBOUR, &mut nt, &init).unwrap();
        assert_eq!(nt.endpoint, Via::Pool(1));
        assert_eq!(w.down(&nt, &resp), at(NEIGHBOUR));
        let keepalive = answer(&mut t, &resp).unwrap();
        assert!(w.up(NEIGHBOUR, &mut nt, &keepalive).is_none());
        assert_eq!(w.node_data(&mut n), AT_PHONE);
        assert_eq!(w.node_data(&mut nt), at(NEIGHBOUR));
        // Each node's own handshake finds its own device.
        let init = initiation(&mut minipc.tunnel_to(&tablet, 600));
        assert_eq!(w.down(&nt, &init), at(NEIGHBOUR));
        let init = initiation(&mut minipc.tunnel_to(&w.phone, 601));
        assert_eq!(w.down(&n, &init), AT_PHONE);
        // The tablet's port is tied to the tablet: a handshake for the
        // phone arriving there is not taken there.
        let init = initiation(&mut minipc.tunnel_to(&w.phone, 602));
        assert_eq!(w.down(&nt, &init), AT_PHONE, "where the phone was last vouched for");
    }

    #[test]
    fn a_node_taken_off_the_list_loses_its_ports() {
        let mut w = World::pooled(1);
        let (minipc, nas) = (End::new(2), End::new(3));
        let _ = w.pooled_handshake(PHONE, MINIPC, &minipc, 1);
        let _ = w.pooled_handshake(PHONE, NAS, &nas, 2);
        assert_eq!(w.sorter.mapped(), 2);
        w.sorter.set_peers(&[(a(NAS), nas.public)], &[w.phone.public]);
        assert_eq!((w.sorter.len(), w.sorter.mapped()), (1, 1));
        // Back on the list, it starts from nothing.
        w.sorter.set_peers(&[(a(MINIPC), minipc.public), (a(NAS), nas.public)], &[w.phone.public]);
        assert_eq!(w.sent_from(SPOOFED, &forged_initiation(70, &minipc.public)), Action::ToNode(a(MINIPC), Via::Pool(0)));
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), Via::Pool(0), &forged(4, 1)), Action::Drop, "no session of its own any more");
    }

    #[test]
    fn a_nodes_own_handshake_goes_to_a_ports_address_only_if_the_port_carried_that_device() {
        let mut w = World::pooled(2);
        let minipc = End::new(2);
        let (mut p, mut n) = w.pooled_handshake(PHONE, MINIPC, &minipc, 1);
        // Through the port it carried the phone's packets on: there.
        let mut rekey = minipc.tunnel_to(&w.phone, 500);
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), Via::Pool(0), &initiation(&mut rekey)), AT_PHONE);
        // The phone moves on and stays in use there; its first port goes
        // quiet, is forgotten, and becomes somebody else's.
        assert!(w.up(ROAMED, &mut n, &data(&mut p)).is_none());
        assert_eq!(w.node_data(&mut n), AT_ROAMED);
        for _ in 0..3 {
            w.now += MAPPING_IDLE / 2;
            assert!(w.up(ROAMED, &mut n, &data(&mut p)).is_none());
            assert_eq!(w.node_data(&mut n), AT_ROAMED);
            w.sorter.expire(w.now);
        }
        assert_eq!(w.sorter.mapped(), 1);
        let mut gone = minipc.tunnel_to(&w.phone, 501);
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), Via::Pool(0), &initiation(&mut gone)), AT_ROAMED, "unmapped: where it was last vouched for");
        assert_eq!(w.sent_from(SPOOFED, &forged_initiation(70, &minipc.public)), Action::ToNode(a(MINIPC), Via::Pool(0)));
        let mut late = minipc.tunnel_to(&w.phone, 502);
        assert_eq!(w.sorter.from_node(w.now, a(MINIPC), Via::Pool(0), &initiation(&mut late)), AT_ROAMED, "mapped to the spoofer: not there");
    }

    #[test]
    fn a_pool_only_grows() {
        let mut w = World::pooled(2);
        w.sorter.set_pool(1);
        let minipc = End::new(2);
        assert_eq!(w.sent_from(PHONE, &forged_initiation(70, &minipc.public)), Action::ToNode(a(MINIPC), Via::Pool(0)));
        assert_eq!(w.sent_from(ROAMED, &forged_initiation(71, &minipc.public)), Action::ToNode(a(MINIPC), Via::Pool(1)));
    }
}
