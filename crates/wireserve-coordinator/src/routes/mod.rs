pub mod admin;
pub mod poll;
pub mod probe;
pub mod register;
pub mod tls;

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
        .route("/probe", get(probe::probe))
        .route("/reach", get(poll::reach))
        .route("/tls/challenge", post(tls::add).delete(tls::remove))
        // Device owners (PLAN.md M38) and the sign-in (PLAN.md M48): pages
        // a browser opens, and where the identity provider sends it back.
        .route("/oidc/callback", get(crate::oidc::claim::callback))
        .route("/claim/confirm", post(crate::oidc::claim::confirm))
        .route("/claim/{code}", get(crate::oidc::claim::start))
        .route("/sign-in", get(crate::oidc::sign_in::start))
        .route("/signed-out", get(crate::oidc::sign_in::signed_out).post(crate::oidc::sign_in::sign_out))
        // The sign-in's node calls (PLAN.md M48), bearer-authenticated.
        .route("/sign-in/redeem", post(crate::oidc::sign_in::redeem))
        .route("/sign-in/renew", post(crate::oidc::sign_in::renew))
        .route("/sign-in/end", post(crate::oidc::sign_in::end))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(axum::middleware::from_fn_with_state(state.clone(), directory_changed_by_node))
        .with_state(state)
}

/// What `/poll` shares between polls (`DirectorySnapshot`) may have moved
/// after any node-facing request but the two that write nothing it holds. A
/// poll says so itself when what it wrote shows. Erring toward a bump costs
/// one rebuild; a missed one is only held off by the snapshot's TTL.
async fn directory_changed_by_node(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let counted = !matches!(req.uri().path(), "/poll" | "/probe" | "/reach");
    let response = next.run(req).await;
    if counted {
        state.directory_changed();
    }
    response
}

/// Every write through the admin surface may move it too.
async fn directory_changed_by_admin(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let writes = !matches!(*req.method(), axum::http::Method::GET | axum::http::Method::HEAD);
    let response = next.run(req).await;
    if writes {
        state.directory_changed();
    }
    response
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
        .route(
            "/admin/nodes/{name}/endpoint/{family}",
            delete(admin::clear_node_endpoint_family),
        )
        .route(
            "/admin/nodes/{name}/transit/approve",
            post(admin::approve_transit),
        )
        .route("/admin/nodes/{name}/transit/deny", post(admin::deny_transit))
        .route("/admin/nodes/{name}/export", axum::routing::put(admin::record_export))
        .route("/admin/relays/plan", post(admin::relay_plan))
        .route("/admin/relay-ports", get(admin::relay_ports))
        .route("/admin/peers", get(admin::list_peers))
        .route("/admin/services", get(admin::list_services))
        .route("/admin/groups", get(admin::list_groups).post(admin::create_group))
        .route("/admin/groups/{group}", axum::routing::delete(admin::delete_group))
        .route(
            "/admin/groups/{group}/services/{service}",
            axum::routing::put(admin::add_group_member).delete(admin::remove_group_member),
        )
        .route(
            "/admin/grants",
            get(admin::list_grants).post(admin::add_grant).delete(admin::remove_grant),
        )
        .route(
            "/admin/nodes/{name}/tags/{tag}",
            axum::routing::put(admin::add_tag).delete(admin::remove_tag),
        )
        .route("/admin/access/services/{name}", get(admin::service_access_report))
        .route("/admin/access/nodes/{name}", get(admin::node_access_report))
        .route("/admin/nodes/{name}/claim", post(admin::claim_link))
        .route("/admin/owners", get(admin::owners_status))
        .route("/admin/sessions/{person}", delete(admin::end_sessions))
        .route("/admin/nodes/{name}/owner", delete(admin::remove_owner))
        .route(
            "/admin/nodes/{name}/services/{service}/approve",
            post(admin::approve_service),
        )
        .route(
            "/admin/nodes/{name}/services/{service}/deny",
            post(admin::deny_service),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(axum::middleware::from_fn_with_state(state.clone(), directory_changed_by_admin))
        .with_state(state)
}
