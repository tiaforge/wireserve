pub mod admin;
pub mod poll;
pub mod register;

use axum::routing::{delete, get, post};
use axum::Router;

use crate::state::AppState;

/// Node-facing router: `/register` (unauthenticated — the join token is
/// itself the credential) and `/poll` (bearer-token authenticated). Meant
/// to sit behind the operator's own TLS-terminating reverse proxy (§7).
pub fn node_router(state: AppState) -> Router {
    Router::new()
        .route("/register", post(register::register))
        .route("/poll", post(poll::poll))
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
        .route("/admin/peers", get(admin::list_peers))
        .with_state(state)
}
