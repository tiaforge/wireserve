use axum::extract::State;
use axum::Json;
use wireserve_types::{PollRequest, PollResponse, Proto};

use crate::auth::BearerNode;
use crate::db::{nodes, services};
use crate::directory;
use crate::error::AppError;
use crate::state::AppState;

/// Upper bound on services one node may declare. Every declared service is
/// fanned out to every other node's `/poll` response and hosts file on
/// every cycle, so without a cap a single node could bloat the whole
/// mesh's directory at will. Generous for the "a few services per box"
/// shape this project is for.
pub const MAX_SERVICES_PER_NODE: usize = 64;

/// `POST /poll` (spec §4.3): the agent's single call that both reports its
/// own state and pulls the current mesh + service directory.
pub async fn poll(
    State(state): State<AppState>,
    BearerNode { node }: BearerNode,
    Json(req): Json<PollRequest>,
) -> Result<Json<PollResponse>, AppError> {
    if req.services.len() > MAX_SERVICES_PER_NODE {
        return Err(AppError::BadRequest(format!(
            "too many services declared ({}); the limit is {MAX_SERVICES_PER_NODE} per node",
            req.services.len()
        )));
    }
    for decl in &req.services {
        if !wireserve_types::is_valid_dns_label(&decl.name) {
            return Err(AppError::BadRequest(format!(
                "invalid service name: {}",
                decl.name
            )));
        }
        if decl.port == 0 {
            return Err(AppError::BadRequest(format!(
                "invalid port 0 for service '{}'",
                decl.name
            )));
        }
    }
    // S2 (security review): endpoint_addr is redistributed verbatim to
    // every other node's /poll response and into rendered .conf files —
    // same validation as /register, applied here too since a node can
    // change its reported endpoint_addr on every poll (spec §4.3).
    if let Some(endpoint) = &req.endpoint_addr {
        if !wireserve_types::is_valid_endpoint_addr(endpoint) {
            return Err(AppError::BadRequest(
                "endpoint_addr must be a valid host:port".into(),
            ));
        }
    }

    let mut conn = state.db.conn.lock().await;

    nodes::update_poll_state(&conn, node.id, req.endpoint_addr.as_deref())?;

    let desired: Vec<(String, u16, Proto)> = req
        .services
        .iter()
        .map(|d| (d.name.clone(), d.port, d.proto))
        .collect();
    let desired_names: std::collections::HashSet<&str> =
        desired.iter().map(|(n, _, _)| n.as_str()).collect();
    let previous = services::list_for_node(&conn, node.id)?;
    let previous_names: std::collections::HashSet<&str> =
        previous.iter().map(|s| s.name.as_str()).collect();

    services::upsert_for_node(&mut conn, node.id, &desired)?;

    for name in desired_names.difference(&previous_names) {
        tracing::info!(event = "service_declared", node_name = %node.name, service = %name);
    }
    for name in previous_names.difference(&desired_names) {
        tracing::info!(event = "service_withdrawn", node_name = %node.name, service = %name);
    }

    let all_peers = nodes::list_all_peers(&conn)?;
    let all_services = services::list_all(&conn)?;

    let peers = all_peers
        .iter()
        .map(|n| directory::peer_info(n, state.config.online_threshold_secs))
        .collect();

    let peers_by_id: std::collections::HashMap<i64, &nodes::NodeRow> =
        all_peers.iter().map(|n| (n.id, n)).collect();
    let services = all_services
        .iter()
        .filter_map(|s| {
            peers_by_id
                .get(&s.node_id)
                .map(|owner| directory::service_info(s, owner, state.config.online_threshold_secs))
        })
        .collect();

    Ok(Json(PollResponse { peers, services }))
}
