use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use wireserve_types::{
    AdminPeersResponse, CreateNodeRequest, CreateNodeResponse, RejoinResponse, JOIN_TOKEN_PREFIX,
};

use crate::auth::AdminAuth;
use crate::db::nodes;
use crate::error::AppError;
use crate::state::AppState;
use crate::tokengen;

/// `POST /admin/nodes` (spec §4.1).
pub async fn create_node(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(req): Json<CreateNodeRequest>,
) -> Result<(StatusCode, Json<CreateNodeResponse>), AppError> {
    if !wireserve_types::is_valid_dns_label(&req.name) {
        return Err(AppError::BadRequest(format!(
            "invalid node name: {}",
            req.name
        )));
    }

    let join_token = tokengen::generate(JOIN_TOKEN_PREFIX);
    let hash = wireserve_types::hash_token(&join_token);

    let conn = state.db.conn.lock().await;
    nodes::create_node(&conn, &req.name, req.kind, &hash)?;

    tracing::info!(event = "node_created", node_name = %req.name, kind = req.kind.as_str());

    Ok((
        StatusCode::CREATED,
        Json(CreateNodeResponse {
            name: req.name,
            join_token,
        }),
    ))
}

/// `POST /admin/nodes/{name}/revoke` (spec §4.4).
pub async fn revoke_node(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
) -> Result<(), AppError> {
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;
    nodes::revoke(&conn, node.id)?;
    tracing::info!(event = "node_revoked", node_name = %name);
    Ok(())
}

/// `POST /admin/nodes/{name}/rejoin` (spec §4.5).
///
/// Also clears the node's current bearer token immediately (security
/// review S8): spec §4.5 explicitly covers calling this on a node whose
/// key is "suspected compromised" while the node itself isn't yet
/// revoked — leaving the OLD bearer token live until a new `/register`
/// completes would mean a compromised credential keeps working for the
/// entire window between "we suspect this" and "the physical operator
/// gets around to re-registering it," which defeats the point of having
/// this path at all. `revoked` itself still only clears back to `0` on a
/// *successful* subsequent `/register` (unchanged).
pub async fn rejoin_node(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
) -> Result<(StatusCode, Json<RejoinResponse>), AppError> {
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;

    let join_token = tokengen::generate(JOIN_TOKEN_PREFIX);
    let hash = wireserve_types::hash_token(&join_token);
    nodes::reissue_join_token(&conn, node.id, &hash)?;
    nodes::clear_bearer_token(&conn, node.id)?;

    tracing::info!(event = "node_rejoined", node_name = %name);

    Ok((
        StatusCode::CREATED,
        Json(RejoinResponse { name, join_token }),
    ))
}

/// `GET /admin/peers` (spec §4.5.1).
pub async fn list_peers(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<AdminPeersResponse>, AppError> {
    let conn = state.db.conn.lock().await;
    let peers = nodes::list_all_peers(&conn)?
        .iter()
        .map(|n| crate::directory::peer_info(n, state.config.online_threshold_secs))
        .collect();
    Ok(Json(AdminPeersResponse { peers }))
}
