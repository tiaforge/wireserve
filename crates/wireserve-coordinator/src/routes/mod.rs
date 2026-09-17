pub mod admin;
pub mod poll;
pub mod register;

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};
use axum::Router;

/// Cap on a request body, replacing axum's 2MB default.
///
/// The largest body any client legitimately sends is a `/poll` declaring
/// the maximum 64 services, which measures under 3KB. The default let an
/// unauthenticated caller hand `/register` two megabytes of JSON and have
/// it parsed *before* any credential was looked at, and parsing that costs
/// roughly seven milliseconds against the ~0.05ms of the database work it
/// guards. This does not replace rate limiting at the reverse proxy, but
/// it does mean the cheapest request to send is no longer far more
/// expensive to serve than to make. 64KB leaves about twenty times the
/// headroom a real client needs.
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;

use crate::state::AppState;

/// Node-facing router: `/register` (unauthenticated — the join token is
/// itself the credential) and `/poll` (bearer-token authenticated). Meant
/// to sit behind the operator's own TLS-terminating reverse proxy (§7).
pub fn node_router(state: AppState) -> Router {
    Router::new()
        .route("/register", post(register::register))
        .route("/poll", post(poll::poll))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state)
}

/// Admin router: every route here requires `AdminAuth`. Bound to a
/// loopback/internal-only listener independent of that check (§4.0) — see
/// `config::validate_admin_listener`, enforced in `main.rs` before this
/// router is ever served.
pub fn admin_router(state: AppState) -> Router {
    Router::new()
        .route("/admin/nodes", post(admin::create_node))
        .route("/admin/nodes/{name}/revoke", post(admin::revoke_node))
        .route("/admin/nodes/{name}/rejoin", post(admin::rejoin_node))
        .route("/admin/nodes/{name}", delete(admin::delete_node))
        .route(
            "/admin/nodes/{name}/endpoint",
            delete(admin::clear_node_endpoint),
        )
        .route("/admin/peers", get(admin::list_peers))
        .route("/admin/services", get(admin::list_services))
        .route(
            "/admin/nodes/{name}/services/{service}/approve",
            post(admin::approve_service),
        )
        .route(
            "/admin/nodes/{name}/services/{service}/deny",
            post(admin::deny_service),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(state)
}
