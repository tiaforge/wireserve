use axum::extract::State;
use axum::Json;
use wireserve_types::{PollRequest, PollResponse, Proto};

use crate::auth::BearerNode;
use crate::db::{nodes, services};
use crate::directory;
use crate::error::AppError;
use crate::state::AppState;

/// Re-exported from `wireserve-types`, which is where the number now
/// lives so the agent can enforce the identical limit locally before it
/// ever queues a declaration the coordinator would reject. See that
/// constant's own doc comment for why a coordinator-only limit was a
/// wedge waiting to happen.
pub use wireserve_types::MAX_SERVICES_PER_NODE;

/// `POST /poll` (spec §4.3): the agent's single call that both reports its
/// own state and pulls the current mesh + service directory.
pub async fn poll(
    State(state): State<AppState>,
    BearerNode { node }: BearerNode,
    Json(req): Json<PollRequest>,
) -> Result<Json<PollResponse>, AppError> {
    // Spec §9: a `kind=static` node "never polls" and its `endpoint_addr`
    // "stays NULL forever" — it is a consumer-only device running an
    // official WireGuard client, with no agent to do the polling. Nothing
    // legitimately reaches this line with a static node's bearer token:
    // `export-config` generates that token during registration and drops
    // it on the floor without ever printing or storing it. Enforce the
    // invariant anyway rather than leave it resting on that accident,
    // since `update_poll_state` below would otherwise happily write an
    // `endpoint_addr` onto a static node and every exported `.conf`
    // afterwards would carry an `Endpoint =` line for a peer that is
    // never meant to be dialed into.
    if node.kind == wireserve_types::NodeKind::Static {
        return Err(AppError::Forbidden(
            "this node is registered as kind=static, which never polls (spec §9)".into(),
        ));
    }

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

    let mode = if state.config.require_service_approval {
        services::ApprovalMode::RequireApproval
    } else {
        services::ApprovalMode::AutoApprove
    };
    let outcome = services::upsert_for_node(&mut conn, node.id, &desired, mode)?;

    for name in desired_names.difference(&previous_names) {
        tracing::info!(event = "service_declared", node_name = %node.name, service = %name);
    }
    for name in previous_names.difference(&desired_names) {
        tracing::info!(event = "service_withdrawn", node_name = %node.name, service = %name);
    }
    // Gated on *newly* declared names: a service can sit pending for days,
    // and logging it on every 20-second cycle would bury the audit trail
    // it belongs to.
    for row in &outcome.pending {
        if desired_names.difference(&previous_names).any(|n| *n == row.name) {
            tracing::info!(
                event = "service_pending_approval",
                node_name = %node.name,
                service = %row.name,
                port = row.port,
                proto = row.proto.as_str(),
            );
        }
    }

    let all_peers = nodes::list_all_peers(&conn)?;
    let all_services = services::list_approved(&conn)?;

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

    Ok(Json(PollResponse {
        peers,
        services,
        pending_services: outcome.pending.iter().map(directory::pending_service).collect(),
        denied_services: outcome.denied.iter().map(directory::denied_service).collect(),
    }))
}
