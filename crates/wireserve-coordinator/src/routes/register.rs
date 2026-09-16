use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::Json;
use wireserve_types::{NodeKind, RegisterRequest, RegisterResponse, BEARER_TOKEN_PREFIX};

use crate::db::nodes::{self, Redemption};
use crate::db::DbError;
use crate::error::AppError;
use crate::state::AppState;
use crate::{ipam, tokengen};

/// `POST /register` (spec §4.2). Redeems a one-time join token, allocates
/// addresses, and issues a bearer token. Reachable without any auth header
/// — the join token itself is the credential — so it's the one endpoint
/// this coordinator rate-limits unconditionally on the failure path.
pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    if req.pubkey.trim().is_empty() {
        return Err(AppError::BadRequest("pubkey must not be empty".into()));
    }

    let hash = wireserve_types::hash_token(&req.join_token);
    let conn = state.db.conn.lock().await;

    let node = match nodes::find_by_unused_join_token_hash(&conn, &hash)? {
        Some(node) => node,
        None => {
            // Unknown and already-used tokens are indistinguishable on
            // purpose (spec: "reject if token already used or unknown" —
            // with the same shape, so a caller learns nothing about
            // whether a guessed token was ever valid).
            if !state.rate_limiter.check(peer_addr.ip()) {
                return Err(AppError::TooManyRequests);
            }
            return Err(AppError::Internal(DbError::JoinTokenInvalid));
        }
    };

    // Judgment call (flagged for PLAN.md): the node's `kind` was fixed at
    // `POST /admin/nodes` creation time and is treated as authoritative;
    // `RegisterRequest.kind` (which defaults to `agent` when omitted, per
    // the wire schema) is validated against it rather than overriding it,
    // so a request can't silently flip a node's kind at registration time.
    if req.kind != node.kind {
        return Err(AppError::BadRequest(format!(
            "kind mismatch: node was created as '{}', register requested '{}'",
            node.kind.as_str(),
            req.kind.as_str()
        )));
    }

    if node.kind == NodeKind::Agent && req.listen_port.is_none() {
        return Err(AppError::BadRequest(
            "listen_port is required for kind=agent".into(),
        ));
    }

    let ip4 = ipam::allocate_v4(&state.config.net_v4_cidr, &nodes::all_allocated_ip4(&conn)?)
        .map_err(DbError::from)?;
    let ip6 = ipam::allocate_v6(&state.config.net_v6_prefix, &nodes::all_allocated_ip6(&conn)?)
        .map_err(DbError::from)?;

    // endpoint_addr fallback (spec §4.2) only ever applies to kind=agent —
    // a kind=static node's endpoint_addr stays NULL forever, since it's
    // never dialed into.
    let (endpoint_addr, listen_port) = if node.kind == NodeKind::Agent {
        let endpoint = req.endpoint_addr.clone().or_else(|| {
            req.listen_port
                .map(|port| format!("{}:{port}", peer_addr.ip()))
        });
        (endpoint, req.listen_port)
    } else {
        (None, None)
    };

    let bearer_token = tokengen::generate(BEARER_TOKEN_PREFIX);
    let bearer_hash = wireserve_types::hash_token(&bearer_token);

    nodes::apply_redemption(
        &conn,
        node.id,
        &Redemption {
            pubkey: &req.pubkey,
            ip4,
            ip6,
            listen_port,
            endpoint_addr: endpoint_addr.as_deref(),
            bearer_token_hash: &bearer_hash,
        },
    )?;

    tracing::info!(
        event = "node_registered",
        node_name = %node.name,
        kind = node.kind.as_str(),
        "node registered"
    );

    Ok(Json(RegisterResponse {
        bearer_token,
        ip4: ip4.to_string(),
        ip6: ip6.to_string(),
    }))
}
