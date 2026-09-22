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

pub fn peer_info(node: &NodeRow, online_threshold_secs: i64) -> PeerInfo {
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
        // Requester-relative (PLAN.md M23) — a single-peer function
        // structurally can't express it. Filled by a second pass in
        // `routes/poll.rs`, once the requester is known; left `None`
        // here and (deliberately) by `GET /admin/peers`, which has no
        // requester to compute it relative to.
        transit_via: None,
    }
}

pub fn service_info(service: &ServiceRow, node: &NodeRow, online_threshold_secs: i64) -> ServiceInfo {
    ServiceInfo {
        name: service.name.clone(),
        node: node.name.clone(),
        ip4: node.ip4.clone().unwrap_or_default(),
        port: service.port,
        proto: service.proto,
        online: is_recent(node.last_seen, online_threshold_secs),
        vip4: service.vip4.clone(),
        ports: service.ports.clone(),
    }
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
        port: service.port,
        proto: service.proto,
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
pub fn admin_service_info(service: &ServiceRow, owner: &NodeRow) -> AdminServiceInfo {
    AdminServiceInfo {
        name: service.name.clone(),
        node: owner.name.clone(),
        ip4: owner.ip4.clone().unwrap_or_default(),
        port: service.port,
        proto: service.proto,
        vip4: service.vip4.clone(),
        ports: service.ports.clone(),
        state: approval_state(service),
        declared_at: service.declared_at,
        approved_at: service.approved_at,
        denied_at: service.denied_at,
        denied_reason: service.denied_reason.clone(),
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
        }
    }

    #[test]
    fn fresh_poll_is_online_with_handshake() {
        let n = node(Some(Utc::now()));
        let info = peer_info(&n, 180);
        assert!(info.last_handshake.is_some());
    }

    #[test]
    fn stale_poll_is_offline_with_null_handshake() {
        let n = node(Some(Utc::now() - Duration::seconds(181)));
        let info = peer_info(&n, 180);
        assert!(info.last_handshake.is_none());
    }

    #[test]
    fn never_polled_is_offline() {
        let n = node(None);
        let info = peer_info(&n, 180);
        assert!(info.last_handshake.is_none());
    }

    #[test]
    fn service_online_tracks_owning_node_last_seen() {
        let n = node(Some(Utc::now()));
        let svc = ServiceRow {
            node_id: 1,
            name: "plex".into(),
            port: 32400,
            proto: wireserve_types::Proto::Tcp,
            vip4: None,
            ports: vec![],
            declared_at: None,
            approved_at: Some(Utc::now()),
            denied_at: None,
            denied_reason: None,
        };
        let info = service_info(&svc, &n, 180);
        assert!(info.online);
    }
}
