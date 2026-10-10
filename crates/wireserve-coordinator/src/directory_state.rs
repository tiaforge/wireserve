//! What every node's `/poll` reads of the mesh and none of them changes,
//! kept in memory between polls, with a log of what changed so that a node
//! that holds an earlier version can be sent only the difference (fix 6).
//!
//! The entries (a [`PeerInfo`] per node, a [`ServiceInfo`] per approved
//! service) are updated in place: one node's poll re-reads that node
//! ([`DirectoryCache::refresh_node`]), the TTL and any write through an admin
//! or node route re-read everything ([`DirectoryCache::ensure`]). Either way
//! only entries that really differ are written, and each write is a new
//! version with a line in the log and a step in the digest.
//!
//! Nothing here is one requester's: its carriers, access and identities are
//! built per poll.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Mutex, PoisonError, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant};

use rusqlite::Connection;
use wireserve_types::{peer_hash, service_hash, DirectoryDelta, DirectoryDigest, DirectoryStamp, PeerInfo, ServiceInfo};

use crate::access::{Rules, SignInFacts};
use wireserve_types::ServiceAccess;
use crate::db::nodes::NodeRow;
use crate::db::services::ServiceRow;
use crate::db::DbError;
use crate::directory::{peer_info, service_info, DirectoryContext};
use crate::state::AppState;

/// How long a delta can be served from the log: a node that has not polled in
/// this long is sent the whole directory.
const LOG_MAX_AGE: Duration = Duration::from_secs(300);
const LOG_MAX_ENTRIES: usize = 500_000;

/// What `peer_info` and `service_info` need of the coordinator's settings.
#[derive(Debug, Clone, Copy)]
pub struct Env {
    pub online_threshold_secs: i64,
    pub relay_port_base: u16,
    pub dns: bool,
}

impl Env {
    #[must_use]
    pub fn of(app: &AppState) -> Self {
        Self {
            online_threshold_secs: app.config.online_threshold_secs,
            relay_port_base: app.config.relay_port_base,
            dns: app.dns.is_some(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Peer(String),
    Service(String),
}

/// An approved service: its row, for what depends on the row, and the entry
/// every node's directory carries.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    pub row: ServiceRow,
    pub info: ServiceInfo,
}

/// Everything the directory is made of, as read from the database and the
/// transit state at one moment.
pub struct Loaded {
    pub nodes: Vec<NodeRow>,
    pub services: Vec<ServiceRow>,
    pub tls_ready: HashMap<String, i64>,
    pub rules: Rules,
    pub static_relays: Vec<(i64, i64, i64)>,
    /// Carry ports reported fresh, by pubkey.
    pub carry_ports: HashMap<String, u16>,
    /// Pubkeys that reported `CAP_SIGN_IN` fresh.
    pub sign_in_capable: HashSet<String>,
}

impl Loaded {
    pub fn read(conn: &Connection, app: &AppState) -> Result<Self, DbError> {
        let fresh = app.config.online_threshold_secs;
        Ok(Self {
            nodes: crate::db::nodes::list_all_peers(conn)?,
            services: crate::db::services::list_approved(conn)?,
            tls_ready: crate::db::tls::ready(conn)?,
            rules: crate::access::read_rules(conn)?,
            static_relays: crate::db::nodes::all_static_relays(conn)?,
            carry_ports: app.transit.carry_ports(fresh),
            sign_in_capable: app.transit.with_capability(wireserve_types::CAP_SIGN_IN, fresh),
        })
    }
}

/// One node as read for [`DirectoryState::apply_node`].
pub struct LoadedNode {
    /// `None` when it is gone, revoked or not registered.
    pub row: Option<NodeRow>,
    pub services: Vec<ServiceRow>,
    /// Its services it serves with TLS.
    pub ready: Vec<String>,
    pub carry_port: Option<u16>,
    pub sign_in_capable: bool,
}

impl LoadedNode {
    pub fn read(conn: &Connection, app: &AppState, id: i64) -> Result<Self, DbError> {
        let row = crate::db::nodes::find_by_id(conn, id)?.filter(|n| !n.revoked && n.pubkey.is_some());
        let fresh = app.config.online_threshold_secs;
        let (services, ready) = if row.is_some() {
            (
                crate::db::services::list_for_node(conn, id)?.into_iter().filter(ServiceRow::is_approved).collect(),
                crate::db::tls::ready_for_node(conn, id)?,
            )
        } else {
            (Vec::new(), Vec::new())
        };
        let pk = row.as_ref().and_then(|n| n.pubkey.as_deref());
        Ok(Self {
            carry_port: pk.and_then(|pk| app.transit.carry_port(pk, fresh)),
            sign_in_capable: pk.is_some_and(|pk| app.transit.has_capability(pk, wireserve_types::CAP_SIGN_IN, fresh)),
            row,
            services,
            ready,
        })
    }
}

pub struct DirectoryState {
    pub epoch: u64,
    version: u64,
    digest: DirectoryDigest,
    /// Version, when, and what, oldest first.
    log: VecDeque<(u64, Instant, Key)>,
    /// A delta can start from any version at or after this one.
    floor: u64,
    /// Registered, unrevoked nodes, in id order.
    pub nodes: BTreeMap<i64, NodeRow>,
    by_pubkey: HashMap<String, i64>,
    peers: HashMap<String, PeerInfo>,
    pub services: HashMap<String, ServiceEntry>,
    node_services: HashMap<i64, Vec<String>>,
    pub rules: Rules,
    pub tls_ready: HashMap<String, i64>,
    pub static_relays: Vec<(i64, i64, i64)>,
    relayable: HashSet<String>,
    sign_in_capable: HashSet<String>,
    /// Counts the changes to what [`crate::access::service_access`] depends on
    /// besides the service itself: the rules, and which nodes there are at
    /// which addresses.
    access_generation: u64,
    access_memo: Mutex<HashMap<String, MemoEntry>>,
}

/// A service's access as last worked out, and what it was worked out from.
struct MemoEntry {
    generation: u64,
    owner: (i64, Option<String>),
    facts: SignInFacts,
    access: ServiceAccess,
}

/// Larger than this is not remembered: it costs as much to keep as to make,
/// and is as large a part of the response either way.
const MEMO_MAX_SOURCES: usize = 1024;

fn empty_rules() -> Rules {
    Rules { grants: Vec::new(), members: BTreeMap::new(), tags: BTreeMap::new(), owner_groups: BTreeMap::new() }
}

fn make_peer(env: &Env, n: &NodeRow, carry_port: Option<u16>) -> PeerInfo {
    let mut p = peer_info(n, env.online_threshold_secs, env.relay_port_base);
    // Moves on every poll of every node, and nobody reads it from here.
    p.last_handshake = None;
    p.relay.carry_port = carry_port;
    p
}

impl DirectoryState {
    #[must_use]
    pub fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_nanos() & u128::from(u64::MAX)).unwrap_or(0));
        Self {
            epoch: nanos ^ (u64::from(std::process::id()) << 40) ^ rand::random::<u64>(),
            version: 0,
            digest: DirectoryDigest::default(),
            log: VecDeque::new(),
            floor: 0,
            nodes: BTreeMap::new(),
            by_pubkey: HashMap::new(),
            peers: HashMap::new(),
            services: HashMap::new(),
            node_services: HashMap::new(),
            rules: empty_rules(),
            tls_ready: HashMap::new(),
            static_relays: Vec::new(),
            relayable: HashSet::new(),
            sign_in_capable: HashSet::new(),
            access_generation: 0,
            access_memo: Mutex::new(HashMap::new()),
        }
    }

    /// Who may reach `service`, of `owner`'s, as [`crate::access::service_access`]
    /// works it out, remembered for as long as the rules and the nodes stay
    /// as they are. It visits every node, which `/poll` would otherwise do
    /// for each of a node's own services on every poll.
    #[must_use]
    pub fn access_for(&self, service: &ServiceRow, owner: &NodeRow, facts: &SignInFacts) -> ServiceAccess {
        let mut memo = self.access_memo.lock().unwrap_or_else(PoisonError::into_inner);
        let owner_key = (owner.id, owner.ip4.clone());
        if let Some(m) = memo.get(&service.name) {
            if m.generation == self.access_generation && m.owner == owner_key && m.facts == *facts {
                return m.access.clone();
            }
        }
        let access = crate::access::service_access(service, owner, self.nodes.values(), &self.rules, facts);
        if access.sources.len() <= MEMO_MAX_SOURCES {
            memo.insert(
                service.name.clone(),
                MemoEntry { generation: self.access_generation, owner: owner_key, facts: *facts, access: access.clone() },
            );
        } else {
            memo.remove(&service.name);
        }
        access
    }

    /// Whether a delta from `have` can be served at all.
    #[must_use]
    pub fn can_serve(&self, have: &DirectoryStamp) -> bool {
        have.epoch == self.epoch && have.version <= self.version && have.version >= self.floor
    }

    #[must_use]
    pub fn stamp(&self) -> DirectoryStamp {
        DirectoryStamp { epoch: self.epoch, version: self.version, digest: self.digest.0 }
    }

    /// The node with this pubkey.
    #[must_use]
    pub fn node_by_pubkey(&self, pubkey: &str) -> Option<&NodeRow> {
        self.nodes.get(self.by_pubkey.get(pubkey)?)
    }

    /// Its position in id order, which is the order of the whole directory.
    #[must_use]
    pub fn id_of(&self, pubkey: &str) -> Option<i64> {
        self.by_pubkey.get(pubkey).copied()
    }

    /// Whether a node can be relayed to: a relay port and a carry port.
    #[must_use]
    pub fn relayable(&self, pubkey: &str) -> bool {
        self.relayable.contains(pubkey)
    }

    /// Whether this node's terminator can check devices and fall back to the
    /// sign-in, as of its latest read.
    #[must_use]
    pub fn sign_in_capable(&self, pubkey: &str) -> bool {
        self.sign_in_capable.contains(pubkey)
    }

    #[must_use]
    pub fn context(&self, env: &Env) -> DirectoryContext<'_> {
        DirectoryContext { tls_ready: &self.tls_ready, dns: env.dns, online_threshold_secs: env.online_threshold_secs }
    }

    // ---- the whole directory ----

    /// Every peer, in id order, without carriers.
    #[must_use]
    pub fn all_peers(&self) -> Vec<PeerInfo> {
        self.nodes.values().filter_map(|n| self.peers.get(n.pubkey.as_deref()?).cloned()).collect()
    }

    /// Every service entry, in name order.
    #[must_use]
    pub fn all_services(&self) -> Vec<&ServiceEntry> {
        let mut v: Vec<&ServiceEntry> = self.services.values().collect();
        v.sort_by(|a, b| a.row.name.cmp(&b.row.name));
        v
    }

    // ---- what changed ----

    /// What changed after `version`, or `None` when the log cannot say: it
    /// is of another process, or it has been trimmed past `version`.
    #[must_use]
    pub fn delta_since(&self, have: &DirectoryStamp) -> Option<DirectoryDelta> {
        if !self.can_serve(have) {
            return None;
        }
        let start = self.log.partition_point(|(v, _, _)| *v <= have.version);
        let mut seen: HashSet<&Key> = HashSet::new();
        let mut delta = DirectoryDelta::default();
        for (_, _, key) in self.log.iter().skip(start) {
            if !seen.insert(key) {
                continue;
            }
            match key {
                Key::Peer(pk) => match self.peers.get(pk) {
                    Some(p) => delta.peers_set.push(p.clone()),
                    None => delta.peers_removed.push(pk.clone()),
                },
                Key::Service(name) => match self.services.get(name) {
                    Some(s) => delta.services_set.push(s.info.clone()),
                    None => delta.services_removed.push(name.clone()),
                },
            }
        }
        Some(delta)
    }

    // ---- writing entries ----

    fn record(&mut self, key: Key) {
        self.version += 1;
        let now = Instant::now();
        self.log.push_back((self.version, now, key));
        while let Some((v, at, _)) = self.log.front() {
            if self.log.len() > LOG_MAX_ENTRIES || now.duration_since(*at) > LOG_MAX_AGE {
                self.floor = *v;
                self.log.pop_front();
            } else {
                break;
            }
        }
    }

    fn put_peer(&mut self, p: PeerInfo) {
        match self.peers.get(&p.pubkey) {
            Some(old) if *old == p => return,
            Some(old) => self.digest.remove(peer_hash(old)),
            None => {}
        }
        self.digest.add(peer_hash(&p));
        let pk = p.pubkey.clone();
        self.peers.insert(pk.clone(), p);
        self.record(Key::Peer(pk));
    }

    fn remove_peer(&mut self, pk: &str) {
        if let Some(old) = self.peers.remove(pk) {
            self.digest.remove(peer_hash(&old));
            self.record(Key::Peer(pk.to_string()));
        }
    }

    fn put_service(&mut self, entry: ServiceEntry) {
        let name = entry.info.name.clone();
        match self.services.get(&name) {
            Some(old) if old.info == entry.info => {
                // The row may differ in ways the entry does not show.
                self.services.insert(name, entry);
                return;
            }
            Some(old) => self.digest.remove(service_hash(&old.info)),
            None => {}
        }
        self.digest.add(service_hash(&entry.info));
        self.services.insert(name.clone(), entry);
        self.record(Key::Service(name));
    }

    fn remove_service(&mut self, name: &str) {
        if let Some(old) = self.services.remove(name) {
            self.digest.remove(service_hash(&old.info));
            self.record(Key::Service(name.to_string()));
        }
    }

    // ---- from the database ----

    /// Replaces everything that was read, writing only the entries that
    /// differ.
    pub fn adopt(&mut self, l: Loaded, env: &Env) {
        let nodes: BTreeMap<i64, NodeRow> = l.nodes.into_iter().map(|n| (n.id, n)).collect();
        let mut by_pubkey = HashMap::new();
        let mut peers: HashMap<String, PeerInfo> = HashMap::new();
        let mut relayable = HashSet::new();
        for n in nodes.values() {
            let Some(pk) = n.pubkey.clone() else { continue };
            let p = make_peer(env, n, l.carry_ports.get(&pk).copied());
            if p.relay.port.is_some() && p.relay.carry_port.is_some() {
                relayable.insert(pk.clone());
            }
            by_pubkey.insert(pk.clone(), n.id);
            peers.insert(pk, p);
        }
        let mut services: HashMap<String, ServiceEntry> = HashMap::new();
        let mut node_services: HashMap<i64, Vec<String>> = HashMap::new();
        {
            let ctx = DirectoryContext { tls_ready: &l.tls_ready, dns: env.dns, online_threshold_secs: env.online_threshold_secs };
            for s in l.services {
                let Some(owner) = nodes.get(&s.node_id) else { continue };
                let info = service_info(&s, owner, env.online_threshold_secs, ctx.terminates(&s));
                node_services.entry(s.node_id).or_default().push(s.name.clone());
                services.insert(s.name.clone(), ServiceEntry { row: s, info });
            }
        }

        let gone: Vec<String> = self.peers.keys().filter(|k| !peers.contains_key(*k)).cloned().collect();
        for pk in gone {
            self.remove_peer(&pk);
        }
        for p in peers.into_values() {
            self.put_peer(p);
        }
        let gone: Vec<String> = self.services.keys().filter(|k| !services.contains_key(*k)).cloned().collect();
        for name in gone {
            self.remove_service(&name);
        }
        for e in services.into_values() {
            self.put_service(e);
        }

        let addresses = |m: &BTreeMap<i64, NodeRow>| m.iter().map(|(id, n)| (*id, n.ip4.clone())).collect::<Vec<_>>();
        if self.rules != l.rules || addresses(&self.nodes) != addresses(&nodes) {
            self.access_generation += 1;
        }
        self.nodes = nodes;
        self.by_pubkey = by_pubkey;
        self.node_services = node_services;
        self.rules = l.rules;
        self.tls_ready = l.tls_ready;
        self.static_relays = l.static_relays;
        self.relayable = relayable;
        self.sign_in_capable = l.sign_in_capable;
    }

    /// Replaces what is known of one node.
    pub fn apply_node(&mut self, id: i64, l: LoadedNode, env: &Env) {
        let old_names = self.node_services.remove(&id).unwrap_or_default();
        for name in &old_names {
            if self.tls_ready.get(name) == Some(&id) {
                self.tls_ready.remove(name);
            }
        }
        let old_pubkey = self.nodes.get(&id).and_then(|n| n.pubkey.clone());

        let old_ip4 = self.nodes.get(&id).map(|n| n.ip4.clone());
        let Some(node) = l.row else {
            if old_ip4.is_some() {
                self.access_generation += 1;
            }
            if let Some(pk) = old_pubkey {
                self.remove_peer(&pk);
                self.by_pubkey.remove(&pk);
                self.relayable.remove(&pk);
                self.sign_in_capable.remove(&pk);
            }
            self.nodes.remove(&id);
            for name in old_names {
                self.remove_service(&name);
            }
            return;
        };
        let pk = node.pubkey.clone().unwrap_or_default();
        if let Some(old) = old_pubkey.filter(|old| *old != pk) {
            self.remove_peer(&old);
            self.by_pubkey.remove(&old);
            self.relayable.remove(&old);
            self.sign_in_capable.remove(&old);
        }
        let peer = make_peer(env, &node, l.carry_port);
        if peer.relay.port.is_some() && peer.relay.carry_port.is_some() {
            self.relayable.insert(pk.clone());
        } else {
            self.relayable.remove(&pk);
        }
        if l.sign_in_capable {
            self.sign_in_capable.insert(pk.clone());
        } else {
            self.sign_in_capable.remove(&pk);
        }
        self.by_pubkey.insert(pk, id);
        self.put_peer(peer);
        if old_ip4.as_ref() != Some(&node.ip4) {
            self.access_generation += 1;
        }
        self.nodes.insert(id, node);

        for name in l.ready {
            self.tls_ready.insert(name, id);
        }
        let entries: Vec<ServiceEntry> = {
            let owner = &self.nodes[&id];
            let ctx = DirectoryContext { tls_ready: &self.tls_ready, dns: env.dns, online_threshold_secs: env.online_threshold_secs };
            l.services
                .into_iter()
                .map(|s| ServiceEntry { info: service_info(&s, owner, env.online_threshold_secs, ctx.terminates(&s)), row: s })
                .collect()
        };
        let names: Vec<String> = entries.iter().map(|e| e.row.name.clone()).collect();
        for name in old_names.iter().filter(|n| !names.contains(n)) {
            self.remove_service(name);
        }
        for e in entries {
            self.put_service(e);
        }
        self.node_services.insert(id, names);
    }
}

impl Default for DirectoryState {
    fn default() -> Self {
        Self::new()
    }
}

/// The directory, and when it was last read from the database in full.
pub struct DirectoryCache {
    generation: std::sync::atomic::AtomicU64,
    last: Mutex<Option<(u64, Instant)>>,
    state: RwLock<DirectoryState>,
}

impl Default for DirectoryCache {
    fn default() -> Self {
        Self { generation: std::sync::atomic::AtomicU64::new(0), last: Mutex::new(None), state: RwLock::new(DirectoryState::new()) }
    }
}

impl DirectoryCache {
    /// How long the directory is used without being read in full again when
    /// nothing says it changed. Staleness of up to a poll interval is already
    /// in every directory a node holds; this is the backstop for what
    /// changes without a write to hook (time, the in-memory transit reports)
    /// and for a write that was not hooked.
    pub const TTL: Duration = Duration::from_secs(5);

    /// Something the directory holds may have changed: the next
    /// [`Self::ensure`] reads it all again.
    pub fn changed(&self) {
        self.generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Reads the directory in full if it has not been for [`Self::TTL`] or
    /// [`Self::changed`] was called since. Called with the database lock
    /// held, which is what keeps one read at a time and the generation read
    /// ahead of rows a later write would change.
    pub fn ensure(&self, conn: &Connection, app: &AppState) -> Result<(), DbError> {
        let generation = self.generation.load(std::sync::atomic::Ordering::Acquire);
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|(g, at)| g == generation && at.elapsed() < Self::TTL) {
            return Ok(());
        }
        let loaded = Loaded::read(conn, app)?;
        self.state.write().unwrap_or_else(PoisonError::into_inner).adopt(loaded, &Env::of(app));
        *last = Some((generation, Instant::now()));
        Ok(())
    }

    /// Reads one node again. Called with the database lock held, after the
    /// writes it follows.
    pub fn refresh_node(&self, conn: &Connection, app: &AppState, id: i64) -> Result<(), DbError> {
        let loaded = LoadedNode::read(conn, app, id)?;
        self.state.write().unwrap_or_else(PoisonError::into_inner).apply_node(id, loaded, &Env::of(app));
        Ok(())
    }

    pub fn read(&self) -> RwLockReadGuard<'_, DirectoryState> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::{DirectoryBase, PortMap, Proto};

    const ENV: Env = Env { online_threshold_secs: 180, relay_port_base: wireserve_types::DEFAULT_RELAY_PORT_BASE, dns: false };

    fn node(id: i64, endpoint: Option<&str>) -> NodeRow {
        let mut n = NodeRow::for_test(id, &format!("n{id}"));
        n.ip4 = Some(format!("10.9.0.{id}"));
        n.endpoint_addr = endpoint.map(str::to_string);
        n.last_seen = Some(chrono::Utc::now());
        n
    }

    fn service(node_id: i64, name: &str, public: u16) -> ServiceRow {
        ServiceRow {
            node_id,
            name: name.into(),
            vip4: Some(format!("10.9.1.{public}")),
            ports: vec![PortMap::identity(public, Proto::Tcp)],
            declared_at: None,
            approved_at: Some(chrono::Utc::now()),
            denied_at: None,
            denied_reason: None,
            approved_ports: None,
        }
    }

    fn loaded(nodes: Vec<NodeRow>, services: Vec<ServiceRow>) -> Loaded {
        Loaded {
            nodes,
            services,
            tls_ready: HashMap::new(),
            rules: empty_rules(),
            static_relays: Vec::new(),
            carry_ports: HashMap::new(),
            sign_in_capable: HashSet::new(),
        }
    }

    fn node_load(row: Option<NodeRow>, services: Vec<ServiceRow>) -> LoadedNode {
        LoadedNode { row, services, ready: Vec::new(), carry_port: None, sign_in_capable: false }
    }

    fn base_of(s: &DirectoryState) -> DirectoryBase {
        let services: Vec<ServiceInfo> = s.all_services().into_iter().map(|e| e.info.clone()).collect();
        DirectoryBase::from_full(&s.all_peers(), &services)
    }

    #[test]
    fn a_change_to_one_node_is_one_entry_and_none_at_all_when_nothing_differs() {
        let mut s = DirectoryState::new();
        s.adopt(loaded(vec![node(1, None), node(2, None)], vec![service(1, "web", 80)]), &ENV);
        let before = s.stamp();
        s.adopt(loaded(vec![node(1, None), node(2, None)], vec![service(1, "web", 80)]), &ENV);
        assert_eq!(s.stamp(), before, "reading the same directory again changes nothing");

        s.apply_node(2, node_load(Some(node(2, Some("203.0.113.5:51820"))), vec![]), &ENV);
        let delta = s.delta_since(&before).unwrap();
        assert_eq!(delta.peers_set.len(), 1);
        assert_eq!(delta.peers_set[0].endpoint_addr.as_deref(), Some("203.0.113.5:51820"));
        assert!(delta.services_set.is_empty() && delta.peers_removed.is_empty() && delta.services_removed.is_empty());
    }

    #[test]
    fn a_stale_epoch_or_a_trimmed_log_cannot_be_served_a_delta() {
        let mut s = DirectoryState::new();
        s.adopt(loaded(vec![node(1, None)], vec![]), &ENV);
        let mut other = s.stamp();
        other.epoch ^= 1;
        assert!(s.delta_since(&other).is_none());
        let mut future = s.stamp();
        future.version += 1;
        assert!(s.delta_since(&future).is_none());
        s.floor = s.version;
        let mut old = s.stamp();
        old.version -= 1;
        assert!(s.delta_since(&old).is_none(), "older than the log reaches");
        assert!(s.delta_since(&s.stamp()).is_some());
    }

    #[test]
    fn any_history_of_changes_replays_to_the_state_it_reached() {
        let mut s = DirectoryState::new();
        let mut seed = 0x9e37_79b9_u64;
        let mut next = move |n: u64| {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) % n
        };
        let mut held: Vec<(DirectoryStamp, DirectoryBase)> = Vec::new();
        for step in 0..300 {
            match next(4) {
                0 => {
                    let ids: Vec<i64> = (1..=8).filter(|_| next(3) > 0).collect();
                    let nodes: Vec<NodeRow> = ids.iter().map(|id| node(*id, Some(&format!("198.51.100.{}:{}", id, next(3) + 1)))).collect();
                    let services: Vec<ServiceRow> = ids
                        .iter()
                        .flat_map(|id| (0..next(3)).map(move |j| service(*id, &format!("s{id}x{j}"), 80 + j as u16)))
                        .collect();
                    s.adopt(loaded(nodes, services), &ENV);
                }
                1 => {
                    let id = i64::try_from(next(8)).unwrap() + 1;
                    s.apply_node(id, node_load(None, vec![]), &ENV);
                }
                _ => {
                    let id = i64::try_from(next(8)).unwrap() + 1;
                    let services: Vec<ServiceRow> = (0..next(3)).map(|j| service(id, &format!("s{id}x{j}"), 80 + j as u16)).collect();
                    let mut ln = node_load(Some(node(id, Some(&format!("192.0.2.{id}:{}", next(4))))), services);
                    ln.carry_port = (next(2) == 0).then_some(50000);
                    ln.sign_in_capable = next(2) == 0;
                    s.apply_node(id, ln, &ENV);
                }
            }
            if step % 7 == 0 {
                held.push((s.stamp(), base_of(&s)));
            }
        }
        assert!(held.len() > 20);
        let now = base_of(&s);
        assert_eq!(now.digest(), s.stamp().digest, "the digest follows every write");
        for (stamp, mut base) in held {
            let delta = s.delta_since(&stamp).expect("nothing trimmed");
            base.apply(&delta);
            assert_eq!(base.digest(), s.stamp().digest);
            assert_eq!(base.peers(&[]), now.peers(&[]));
            assert_eq!(base.services(), now.services());
        }
    }

    #[test]
    fn a_node_gone_takes_its_peer_and_services_with_it() {
        let mut s = DirectoryState::new();
        s.adopt(loaded(vec![node(1, None), node(2, None)], vec![service(2, "db", 5432)]), &ENV);
        let at = s.stamp();
        s.apply_node(2, node_load(None, vec![]), &ENV);
        let d = s.delta_since(&at).unwrap();
        assert_eq!(d.peers_removed, ["pk-n2"]);
        assert_eq!(d.services_removed, ["db"]);
        assert!(s.node_by_pubkey("pk-n2").is_none());
        assert_eq!(s.all_peers().len(), 1);
    }

    #[test]
    fn access_is_remembered_until_the_rules_or_the_nodes_change() {
        let facts = SignInFacts { available: false, owner_capable: false, terminated: false };
        let mut s = DirectoryState::new();
        let svc = service(1, "db", 5432);
        let mut l = loaded(vec![node(1, None), node(2, None)], vec![svc.clone()]);
        l.rules.members.insert("db".into(), std::collections::BTreeSet::from(["infra".to_string()]));
        s.adopt(l, &ENV);
        let owner = s.nodes[&1].clone();
        let first = s.access_for(&svc, &owner, &facts);
        assert!(!first.open && first.sources == ["10.9.0.1".parse::<std::net::Ipv4Addr>().unwrap()]);
        let generation = s.access_generation;

        // The same directory read again: nothing to forget.
        let mut l = loaded(vec![node(1, None), node(2, None)], vec![svc.clone()]);
        l.rules.members.insert("db".into(), std::collections::BTreeSet::from(["infra".to_string()]));
        s.adopt(l, &ENV);
        assert_eq!(s.access_generation, generation);

        // A grant arrives: node 2 may now reach it.
        let mut l = loaded(vec![node(1, None), node(2, None)], vec![svc.clone()]);
        l.rules.members.insert("db".into(), std::collections::BTreeSet::from(["infra".to_string()]));
        l.rules.tags.insert(2, std::collections::BTreeSet::from(["ops".to_string()]));
        l.rules.grants.push(crate::db::grants::Grant { source: "tag:ops".parse().unwrap(), group: "infra".into() });
        s.adopt(l, &ENV);
        assert!(s.access_generation > generation);
        let after = s.access_for(&svc, &owner, &facts);
        assert_eq!(after.sources.len(), 2, "{after:?}");
    }
}
