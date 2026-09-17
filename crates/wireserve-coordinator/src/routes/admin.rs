use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use wireserve_types::{
    AdminPeersResponse, CreateNodeRequest, CreateNodeResponse, RejoinRequest, RejoinResponse,
    JOIN_TOKEN_PREFIX,
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
    let ttl = req.ttl_secs.unwrap_or(state.config.join_token_ttl_secs);
    let expires_at = nodes::join_token_expiry(ttl);

    let conn = state.db.conn.lock().await;
    nodes::create_node(&conn, &req.name, req.kind, &hash, expires_at.as_deref())?;

    tracing::info!(
        event = "node_created",
        node_name = %req.name,
        kind = req.kind.as_str(),
        join_token_ttl_secs = ttl,
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateNodeResponse {
            name: req.name,
            join_token,
            join_token_expires_at: parse_expiry(expires_at.as_deref()),
        }),
    ))
}

/// Re-parses the expiry string that was just written to the database, so
/// the response reports exactly what was stored rather than a separately
/// computed value that could drift from it.
fn parse_expiry(raw: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    raw.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
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

/// `DELETE /admin/nodes/{name}` (security review F8 — not in the spec's
/// route list, added so an orphaned or mistyped node record can be
/// removed and its name freed). Refuses with `409` while the node is
/// still active (registered and not revoked): an active node must be
/// revoked first, so that removing a live member of the mesh is always a
/// deliberate two-step action rather than a single slip.
pub async fn delete_node(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
) -> Result<(), AppError> {
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;
    if node.pubkey.is_some() && !node.revoked {
        return Err(AppError::Conflict(
            "node is still active — revoke it first, then delete".into(),
        ));
    }
    nodes::delete_node(&conn, node.id)?;
    tracing::info!(event = "node_deleted", node_name = %name);
    Ok(())
}

/// `DELETE /admin/nodes/{name}/endpoint`.
///
/// Clears a stale advertised endpoint. Not in the spec's route list —
/// added because `/poll`'s `COALESCE` means a node can set an
/// `endpoint_addr` but never unset one, so a node that loses its port
/// forward keeps advertising an address no peer can reach. See
/// `nodes::clear_endpoint` for why the COALESCE stays.
///
/// Unlike `revoke`, this is not a security action and needs no
/// two-step guard: it removes a routing hint, nothing more, and the
/// worst case is one poll interval of peers falling back on
/// WireGuard's own roaming correction.
pub async fn clear_node_endpoint(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
) -> Result<(), AppError> {
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;
    nodes::clear_endpoint(&conn, node.id)?;
    tracing::info!(event = "node_endpoint_cleared", node_name = %name);
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
    // Optional body: a rejoin has never needed one, and an admin CLI
    // built before `--ttl` existed sends none at all. `Option<Json<_>>`
    // keeps that request working rather than turning a missing
    // Content-Type into a 400 on a route that used to accept it.
    body: Option<Json<RejoinRequest>>,
) -> Result<(StatusCode, Json<RejoinResponse>), AppError> {
    let ttl = body
        .and_then(|Json(b)| b.ttl_secs)
        .unwrap_or(state.config.join_token_ttl_secs);
    let expires_at = nodes::join_token_expiry(ttl);

    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;

    let join_token = tokengen::generate(JOIN_TOKEN_PREFIX);
    let hash = wireserve_types::hash_token(&join_token);
    nodes::reissue_join_token(&conn, node.id, &hash, expires_at.as_deref())?;
    nodes::clear_bearer_token(&conn, node.id)?;

    tracing::info!(event = "node_rejoined", node_name = %name, join_token_ttl_secs = ttl);

    Ok((
        StatusCode::CREATED,
        Json(RejoinResponse {
            name,
            join_token,
            join_token_expires_at: parse_expiry(expires_at.as_deref()),
        }),
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
