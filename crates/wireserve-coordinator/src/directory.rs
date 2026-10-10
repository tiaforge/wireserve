//! Builds the wire-facing `PeerInfo`/`ServiceInfo` shapes shared by
//! `/poll`'s response and `GET /admin/peers` (§4.3, §4.5.1), including the
//! `online`/`last_handshake` approximation from PLAN.md decisions log #3.

use chrono::Utc;
use wireserve_types::{
    AdminServiceInfo, DeniedService, PeerInfo, PendingService, ServiceApprovalState, ServiceInfo,
};

use crate::db::nodes::NodeRow;
use crate::db::services::ServiceRow;

fn is_recent(last_seen: Option<chrono::DateTime<Utc>>, threshold_secs: i64) -> bool {
    match last_seen {
        Some(t) => (Utc::now() - t).num_seconds() < threshold_secs,
        None => false,
    }
}

pub fn peer_info(node: &NodeRow, online_threshold_secs: i64, relay_base: u16) -> PeerInfo {
    let recent = is_recent(node.last_seen, online_threshold_secs);
    PeerInfo {
        name: node.name.clone(),
        pubkey: node.pubkey.clone().unwrap_or_default(),
        ip4: node.ip4.clone().unwrap_or_default(),
        ip6: node.ip6.clone().unwrap_or_default(),
        endpoint_addr: node.endpoint_addr.clone(),
        endpoint_addr_v4: node.endpoint_addr_v4.clone(),
        endpoint_addr_v6: node.endpoint_addr_v6.clone(),
        lan_addr: node.lan_addr.clone(),
        reflexive_addr: node.reflexive_addr.clone(),
        last_handshake: if recent { node.last_seen } else { None },
        // The carry port and carrier are live facts, filled in by `/poll`.
        relay: wireserve_types::PeerRelay {
            port: wireserve_types::relay_port(relay_base, node.relay_slot),
            listen_port: node.listen_port.and_then(|p| u16::try_from(p).ok()),
            ..Default::default()
        },
    }
}

/// A service as every node's directory carries it. A mapping's target
/// address (PLAN.md M26) is left out: a peer reaches the service on its own
/// address and public port and needs nothing else, and the owner acts only
/// on its own declaration — so the only thing fanning it out would do is
/// tell the whole mesh what the owner's LAN looks like. Admins still see it
/// (`admin_service_info`).
pub fn service_info(
    service: &ServiceRow,
    node: &NodeRow,
    online_threshold_secs: i64,
    terminated: bool,
) -> ServiceInfo {
    ServiceInfo {
        name: service.name.clone(),
        node: node.name.clone(),
        ip4: node.ip4.clone().unwrap_or_default(),
        online: is_recent(node.last_seen, online_threshold_secs),
        vip4: service.vip4.clone(),
        ports: service.ports.iter().map(|m| wireserve_types::PortMap { addr: None, ..*m }).collect(),
        terminated,
        reach: None,
    }
}

/// What decides, beyond a service's own row, how the directory shows it.
pub struct DirectoryContext<'a> {
    /// Names their own node reports serving with TLS, with that node
    /// (PLAN.md M33).
    pub tls_ready: &'a std::collections::HashMap<String, i64>,
    /// Whether the coordinator publishes DNS records — without them no
    /// certificate can be issued, so nothing is terminated.
    pub dns: bool,
    pub online_threshold_secs: i64,
}

impl DirectoryContext<'_> {
    /// Whether `service` is served with TLS by its own node (PLAN.md M33).
    ///
    /// Every condition fails toward the path the service already had: no
    /// records, not on TCP 443, no address of its own, or its own node not
    /// vouching for it right now. A restricted service terminates like any
    /// other (PLAN.md M34, M36): the sign-in is in the terminator.
    #[must_use]
    pub fn terminates(&self, service: &ServiceRow) -> bool {
        self.dns
            && service.vip4.is_some()
            && service.ports.iter()
                .any(|m| m.public == wireserve_types::TLS_PUBLIC_PORT && m.proto == wireserve_types::Proto::Tcp)
            && self.tls_ready.get(&service.name) == Some(&service.node_id)
    }
}

/// The services every node's directory carries: each approved row whose
/// owner is a live peer, shaped by [`service_info`]. Shared by `/poll` and
/// the DNS sync (PLAN.md M32), so the names a phone resolves are built from
/// exactly the directory the nodes see.
pub fn services_directory(services: &[ServiceRow], peers: &[NodeRow], ctx: &DirectoryContext<'_>) -> Vec<ServiceInfo> {
    let peers_by_id: std::collections::HashMap<i64, &NodeRow> = peers.iter().map(|n| (n.id, n)).collect();
    services
        .iter()
        .filter_map(|s| {
            peers_by_id.get(&s.node_id).map(|owner| service_info(s, owner, ctx.online_threshold_secs, ctx.terminates(s)))
        })
        .collect()
}

/// Derived, never stored: `denied_at` is only meaningful while
/// `approved_at` is NULL, so approval wins if a row somehow carries both.
/// No writer produces that state, but `ALTER TABLE` cannot add the
/// table-level CHECK that would forbid it, so the reader resolves it
/// rather than assuming.
#[must_use]
pub fn approval_state(service: &ServiceRow) -> ServiceApprovalState {
    if service.approved_at.is_some() {
        ServiceApprovalState::Approved
    } else if service.denied_at.is_some() {
        ServiceApprovalState::Denied
    } else {
        ServiceApprovalState::Pending
    }
}

#[must_use]
pub fn pending_service(service: &ServiceRow) -> PendingService {
    PendingService {
        name: service.name.clone(),
        ports: service.ports.clone(),
        vip4: service.vip4.clone(),
        declared_at: service.declared_at,
    }
}

#[must_use]
pub fn denied_service(service: &ServiceRow) -> DeniedService {
    DeniedService {
        name: service.name.clone(),
        reason: service.denied_reason.clone(),
        denied_at: service.denied_at,
    }
}

#[must_use]
pub fn admin_service_info(service: &ServiceRow, owner: &NodeRow, groups: Vec<String>) -> AdminServiceInfo {
    AdminServiceInfo {
        name: service.name.clone(),
        node: owner.name.clone(),
        ip4: owner.ip4.clone().unwrap_or_default(),
        vip4: service.vip4.clone(),
        ports: service.ports.clone(),
        state: approval_state(service),
        declared_at: service.declared_at,
        approved_at: service.approved_at,
        denied_at: service.denied_at,
        denied_reason: service.denied_reason.clone(),
        approved_ports: if service.is_awaiting_review() {
            service.approved_ports.clone().unwrap_or_default()
        } else {
            Vec::new()
        },
        groups,
        dns: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use wireserve_types::NodeKind;

    fn node(last_seen: Option<chrono::DateTime<Utc>>) -> NodeRow {
        NodeRow {
            id: 1,
            name: "n1".into(),
            kind: NodeKind::Agent,
            pubkey: Some("pk".into()),
            ip4: Some("100.90.0.1".into()),
            ip6: Some("fd00:90::1".into()),
            endpoint_addr: None,
            endpoint_cleared: false,
            endpoint_addr_v4: None,
            endpoint_addr_v6: None,
            lan_addr: None,
            reflexive_addr: None,
            listen_port: Some(51820),
            revoked: false,
            last_seen,
            transit_approved: false,
            exit_node_id: None,
            exported_at: None,
            created_at: None,
            exit_enabled: false,
            relay_slot: None,
        }
    }

    #[test]
    fn fresh_poll_is_online_with_handshake() {
        let n = node(Some(Utc::now()));
        let info = peer_info(&n, 180, wireserve_types::DEFAULT_RELAY_PORT_BASE);
        assert!(info.last_handshake.is_some());
    }

    #[test]
    fn stale_poll_is_offline_with_null_handshake() {
        let n = node(Some(Utc::now() - Duration::seconds(181)));
        let info = peer_info(&n, 180, wireserve_types::DEFAULT_RELAY_PORT_BASE);
        assert!(info.last_handshake.is_none());
    }

    #[test]
    fn never_polled_is_offline() {
        let n = node(None);
        let info = peer_info(&n, 180, wireserve_types::DEFAULT_RELAY_PORT_BASE);
        assert!(info.last_handshake.is_none());
    }

    #[test]
    fn service_online_tracks_owning_node_last_seen() {
        let n = node(Some(Utc::now()));
        let svc = ServiceRow {
            node_id: 1,
            name: "plex".into(),
            vip4: None,
            ports: vec![],
            declared_at: None,
            approved_at: Some(Utc::now()),
            denied_at: None,
            denied_reason: None,
            approved_ports: None,
        };
        let info = service_info(&svc, &n, 180, false);
        assert!(info.online);
    }

    #[test]
    fn a_target_address_reaches_admins_but_never_the_mesh() {
        let n = node(Some(Utc::now()));
        let svc = ServiceRow {
            node_id: 1,
            name: "myrouter".into(),
            vip4: Some("10.9.0.50".into()),
            ports: vec!["443:192.168.178.1:80".parse().unwrap()],
            declared_at: None,
            approved_at: Some(Utc::now()),
            denied_at: None,
            denied_reason: None,
            approved_ports: None,
        };
        let fanned = service_info(&svc, &n, 180, false);
        assert_eq!(fanned.ports[0].addr, None);
        assert_eq!((fanned.ports[0].public, fanned.ports[0].target), (443, 80));
        assert_eq!(admin_service_info(&svc, &n, vec![]).ports[0].to_string(), "443:192.168.178.1:80/tcp");
    }
}

/// What every node's `/poll` reads of the mesh and none of them changes: the
/// directory rows and the lists built from them, read once and shared, so a
/// poll neither holds the database for them nor builds them again.
///
/// Rebuilt when [`DirectoryCache`] says so: a change through an admin or
/// node route (`AppState::directory_changed`), or after
/// [`DirectoryCache::TTL`], which also bounds how stale what moves with the
/// clock (online, carry ports, owners' groups) can get. Holds nothing that
/// is one requester's: its access, identities and notices are built per poll.
pub struct DirectorySnapshot {
    /// Registered, unrevoked nodes, in id order.
    pub nodes: Vec<NodeRow>,
    pub by_id: std::collections::HashMap<i64, usize>,
    pub by_pubkey: std::collections::HashMap<String, usize>,
    /// Approved services.
    pub services: Vec<ServiceRow>,
    pub rules: crate::access::Rules,
    pub tls_ready: std::collections::HashMap<String, i64>,
    /// `(device, peer, carrier)`, from the exports.
    pub static_relays: Vec<(i64, i64, i64)>,
    /// One per node, in `nodes`' order, carry ports filled in.
    pub peers: Vec<PeerInfo>,
    /// The approved services as nodes see them, in `services`' order less
    /// those whose node is gone.
    pub directory: Vec<ServiceInfo>,
    /// Nodes that can be relayed to: a relay port and a carry port.
    pub relayable: std::collections::HashSet<String>,
}

impl DirectorySnapshot {
    pub fn build(conn: &rusqlite::Connection, state: &crate::state::AppState) -> Result<Self, crate::db::DbError> {
        let nodes = crate::db::nodes::list_all_peers(conn)?;
        let services = crate::db::services::list_approved(conn)?;
        let tls_ready = crate::db::tls::ready(conn)?;
        let rules = crate::access::read_rules(conn)?;
        let static_relays = crate::db::nodes::all_static_relays(conn)?;
        let fresh = state.config.online_threshold_secs;
        let carry = state.transit.carry_ports(fresh);
        let peers: Vec<PeerInfo> = nodes
            .iter()
            .map(|n| {
                let mut p = peer_info(n, fresh, state.config.relay_port_base);
                p.relay.carry_port = carry.get(&p.pubkey).copied();
                p
            })
            .collect();
        let relayable = peers
            .iter()
            .filter(|p| p.relay.port.is_some() && p.relay.carry_port.is_some())
            .map(|p| p.pubkey.clone())
            .collect();
        let directory = services_directory(&services, &nodes, &state.directory_context(&tls_ready));
        let by_id = nodes.iter().enumerate().map(|(i, n)| (n.id, i)).collect();
        let by_pubkey = nodes.iter().enumerate().filter_map(|(i, n)| Some((n.pubkey.clone()?, i))).collect();
        Ok(Self { nodes, by_id, by_pubkey, services, rules, tls_ready, static_relays, peers, directory, relayable })
    }
}

/// The current [`DirectorySnapshot`], and when it stops being so.
#[derive(Default)]
pub struct DirectoryCache {
    generation: std::sync::atomic::AtomicU64,
    slot: std::sync::Mutex<Option<(u64, std::time::Instant, std::sync::Arc<DirectorySnapshot>)>>,
}

impl DirectoryCache {
    /// How long a snapshot is used when nothing says it changed. Staleness
    /// of up to a poll interval is already in every directory a node holds;
    /// this is the backstop for what changes without a write to hook (time,
    /// the in-memory transit reports) and for a write that was not hooked.
    pub const TTL: std::time::Duration = std::time::Duration::from_secs(5);

    /// Something the snapshot holds may have changed: the next [`Self::get`]
    /// builds a new one.
    pub fn changed(&self) {
        self.generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// The snapshot, built with `build` if there is none, it is older than
    /// [`Self::TTL`], or [`Self::changed`] was called since it was. Called
    /// with the database lock held, which is what keeps one build at a time
    /// and the generation read ahead of rows a later write would change.
    pub fn get<E>(&self, build: impl FnOnce() -> Result<DirectorySnapshot, E>) -> Result<std::sync::Arc<DirectorySnapshot>, E> {
        let generation = self.generation.load(std::sync::atomic::Ordering::Acquire);
        let mut slot = self.slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((g, at, snap)) = slot.as_ref() {
            if *g == generation && at.elapsed() < Self::TTL {
                return Ok(snap.clone());
            }
        }
        let snap = std::sync::Arc::new(build()?);
        *slot = Some((generation, std::time::Instant::now(), snap.clone()));
        Ok(snap)
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::cell::Cell;

    fn empty() -> DirectorySnapshot {
        DirectorySnapshot {
            nodes: Vec::new(),
            by_id: Default::default(),
            by_pubkey: Default::default(),
            services: Vec::new(),
            rules: crate::access::Rules {
                grants: Vec::new(),
                members: Default::default(),
                tags: Default::default(),
                owner_groups: Default::default(),
            },
            tls_ready: Default::default(),
            static_relays: Vec::new(),
            peers: Vec::new(),
            directory: Vec::new(),
            relayable: Default::default(),
        }
    }

    #[test]
    fn a_snapshot_is_reused_until_something_changes() {
        let cache = DirectoryCache::default();
        let builds = Cell::new(0);
        let build = || -> Result<_, ()> {
            builds.set(builds.get() + 1);
            Ok(empty())
        };
        let first = cache.get(build).unwrap();
        let second = cache.get(build).unwrap();
        assert_eq!(builds.get(), 1);
        assert!(std::sync::Arc::ptr_eq(&first, &second));
        cache.changed();
        cache.get(build).unwrap();
        assert_eq!(builds.get(), 2, "a change is read again at once");
        cache.get(build).unwrap();
        assert_eq!(builds.get(), 2);
    }

    #[test]
    fn a_failed_build_leaves_the_old_snapshot_and_is_retried() {
        let cache = DirectoryCache::default();
        cache.get(|| Ok::<_, ()>(empty())).unwrap();
        cache.changed();
        assert!(cache.get(|| Err::<DirectorySnapshot, _>(())).is_err());
        assert!(cache.get(|| Ok::<_, ()>(empty())).is_ok());
    }
}
