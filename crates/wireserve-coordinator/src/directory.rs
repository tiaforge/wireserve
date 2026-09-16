//! Builds the wire-facing `PeerInfo`/`ServiceInfo` shapes shared by
//! `/poll`'s response and `GET /admin/peers` (§4.3, §4.5.1), including the
//! `online`/`last_handshake` approximation from PLAN.md decisions log #3.

use chrono::Utc;
use wireserve_types::{PeerInfo, ServiceInfo};

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
        last_handshake: if recent { node.last_seen } else { None },
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
            listen_port: Some(51820),
            revoked: false,
            last_seen,
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
        };
        let info = service_info(&svc, &n, 180);
        assert!(info.online);
    }
}
