//! A tiny real HTTP server standing in for the coordinator, used by
//! integration tests to check both response handling and — just as
//! importantly — exactly what `wireserve-admin` sends: every request's
//! method, path, and raw body are captured so tests can assert on them
//! directly (e.g. "the private key never appeared in any request body",
//! "zero requests were made for an invalid name").

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use wireserve_types::{
    AdminPeersResponse, CreateNodeResponse, PeerInfo, RegisterRequest, RegisterResponse,
    RejoinResponse,
};

// method/path are kept for tests that want to debug-print a failing
// assertion (`{captured:?}`) even though no current test reads them
// directly by field.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    pub method: String,
    pub path: String,
    pub body: String,
}

#[derive(Clone)]
struct MockState {
    admin_token: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    peers: Arc<Mutex<Vec<PeerInfo>>>,
}

pub struct MockCoordinator {
    pub base_url: String,
    state: MockState,
}

impl MockCoordinator {
    /// Starts a mock server serving every route (admin + /register) from
    /// one router — convenient for most tests, but NOT how the real
    /// coordinator is deployed (spec §4.0 requires the admin and
    /// node-facing surfaces on two separately-bound listeners). Tests that
    /// need to catch a regression in that split use `start_admin_only`/
    /// `start_register_only` instead.
    pub fn start(admin_token: &str) -> Self {
        Self::start_with_router(admin_token, build_router)
    }

    /// Admin routes only — no `/register` — modeling the real coordinator's
    /// admin listener in isolation.
    pub fn start_admin_only(admin_token: &str) -> Self {
        Self::start_with_router(admin_token, build_admin_only_router)
    }

    /// `/register` only — no admin routes — modeling the real
    /// coordinator's node-facing listener in isolation.
    pub fn start_register_only(admin_token: &str) -> Self {
        Self::start_with_router(admin_token, build_register_only_router)
    }

    /// Starts `router_fn`'s router on an OS-assigned loopback port and
    /// returns once it's ready to accept connections. Runs for the
    /// lifetime of the test process — there's no explicit shutdown,
    /// matching how short-lived test binaries commonly handle background
    /// test servers.
    fn start_with_router(admin_token: &str, router_fn: fn(MockState) -> Router) -> Self {
        let state = MockState {
            admin_token: admin_token.to_string(),
            requests: Arc::new(Mutex::new(Vec::new())),
            peers: Arc::new(Mutex::new(Vec::new())),
        };

        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let thread_state = state.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let app = router_fn(thread_state);
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                addr_tx.send(addr).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        let addr: SocketAddr = addr_rx.recv().unwrap();

        Self {
            base_url: format!("http://{addr}"),
            state,
        }
    }

    pub fn request_count(&self) -> usize {
        self.state.requests.lock().unwrap().len()
    }

    pub fn bodies(&self) -> Vec<String> {
        self.state
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.body.clone())
            .collect()
    }

    /// The route patterns the mock matched, in order. Mirrors `bodies()`.
    /// Handlers record the pattern (`/admin/nodes/:name/endpoint`) rather
    /// than the concrete path, which is what makes an assertion here about
    /// *which endpoint* was called rather than about the name substituted
    /// into it.
    pub fn paths(&self) -> Vec<String> {
        self.state
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.path.clone())
            .collect()
    }

    pub fn set_peers(&self, peers: Vec<PeerInfo>) {
        *self.state.peers.lock().unwrap() = peers;
    }
}

fn record(state: &MockState, method: &str, path: &str, body: &[u8]) {
    state.requests.lock().unwrap().push(CapturedRequest {
        method: method.to_string(),
        path: path.to_string(),
        body: String::from_utf8_lossy(body).to_string(),
    });
}

fn admin_auth_ok(state: &MockState, headers: &HeaderMap) -> bool {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == format!("Bearer {}", state.admin_token))
        .unwrap_or(false)
}

async fn create_node(
    State(state): State<MockState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<CreateNodeResponse>, StatusCode> {
    record(&state, "POST", "/admin/nodes", &body);
    if !admin_auth_ok(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let req: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let name = req["name"].as_str().unwrap_or_default().to_string();
    Ok(Json(CreateNodeResponse {
        join_token_expires_at: None,
        name,
        join_token: "jtk_mock".to_string(),
    }))
}

async fn revoke_node(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(_name): Path<String>,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    record(&state, "POST", "/admin/nodes/:name/revoke", &body);
    if !admin_auth_ok(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(StatusCode::OK)
}

async fn list_services(
    State(state): State<MockState>,
    headers: HeaderMap,
) -> Result<Json<wireserve_types::AdminServicesResponse>, StatusCode> {
    record(&state, "GET", "/admin/services", b"");
    if !admin_auth_ok(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Json(wireserve_types::AdminServicesResponse { services: vec![] }))
}

async fn approve_service(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path((node, service)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    // The concrete names, not the route pattern: these two path segments
    // are what carry the bind-to-the-declaring-node rule over the wire,
    // so a test needs to see which ones actually went out.
    record(
        &state,
        "POST",
        &format!("/admin/nodes/{node}/services/{service}/approve"),
        b"",
    );
    if !admin_auth_ok(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(StatusCode::OK)
}

async fn deny_service(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path((node, service)): Path<(String, String)>,
    body: String,
) -> Result<StatusCode, StatusCode> {
    record(
        &state,
        "POST",
        &format!("/admin/nodes/{node}/services/{service}/deny"),
        body.as_bytes(),
    );
    if !admin_auth_ok(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(StatusCode::OK)
}

async fn clear_endpoint(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(_name): Path<String>,
) -> Result<StatusCode, StatusCode> {
    record(&state, "DELETE", "/admin/nodes/:name/endpoint", b"");
    if !admin_auth_ok(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(StatusCode::OK)
}

async fn delete_node(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(_name): Path<String>,
) -> Result<StatusCode, StatusCode> {
    record(&state, "DELETE", "/admin/nodes/:name", b"");
    if !admin_auth_ok(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(StatusCode::OK)
}

async fn rejoin_node(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Bytes,
) -> Result<Json<RejoinResponse>, StatusCode> {
    record(&state, "POST", "/admin/nodes/:name/rejoin", &body);
    if !admin_auth_ok(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Json(RejoinResponse {
        join_token_expires_at: None,
        name,
        join_token: "jtk_mock2".to_string(),
    }))
}

async fn set_gateway(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    record(&state, "PUT", &format!("/admin/nodes/{name}/gateway"), &body);
    if !admin_auth_ok(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(StatusCode::OK)
}

async fn list_peers(
    State(state): State<MockState>,
    headers: HeaderMap,
) -> Result<Json<AdminPeersResponse>, StatusCode> {
    record(&state, "GET", "/admin/peers", b"");
    if !admin_auth_ok(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let peers = state.peers.lock().unwrap().clone();
    Ok(Json(AdminPeersResponse {
        peers,
        transit_approved: vec![],
        transit_offering: vec![],
        via_gateway: vec![],
        exit_offering: vec![],
        exit_devices: vec![],
        tags: Default::default(),
    }))
}

async fn approve_transit(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<StatusCode, StatusCode> {
    record(&state, "POST", &format!("/admin/nodes/{name}/transit/approve"), b"");
    if !admin_auth_ok(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(StatusCode::OK)
}

async fn deny_transit(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<StatusCode, StatusCode> {
    record(&state, "POST", &format!("/admin/nodes/{name}/transit/deny"), b"");
    if !admin_auth_ok(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(StatusCode::OK)
}

async fn set_via_gateway(
    State(state): State<MockState>,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Bytes,
) -> Result<Json<wireserve_types::SetViaGatewayResponse>, StatusCode> {
    record(&state, "PUT", &format!("/admin/nodes/{name}/via-gateway"), &body);
    if !admin_auth_ok(&state, &headers) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Json(wireserve_types::SetViaGatewayResponse { affected_devices: vec!["phone".into()] }))
}

async fn register(
    State(state): State<MockState>,
    body: Bytes,
) -> Result<Json<RegisterResponse>, StatusCode> {
    record(&state, "POST", "/register", &body);
    let _req: RegisterRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(RegisterResponse {
        bearer_token: "brt_mock".to_string(),
        ip4: "100.90.0.9".to_string(),
        ip6: "fd00:90::9".to_string(),
        mesh: None,
        naming: None,
    }))
}

fn admin_only_routes() -> Router<MockState> {
    Router::new()
        .route("/admin/nodes", post(create_node))
        .route("/admin/nodes/{name}/revoke", post(revoke_node))
        .route("/admin/nodes/{name}/rejoin", post(rejoin_node))
        .route("/admin/nodes/{name}", axum::routing::delete(delete_node))
        .route(
            "/admin/nodes/{name}/endpoint",
            axum::routing::delete(clear_endpoint),
        )
        .route("/admin/nodes/{name}/transit/approve", post(approve_transit))
        .route("/admin/nodes/{name}/transit/deny", post(deny_transit))
        .route("/admin/nodes/{name}/gateway", axum::routing::put(set_gateway))
        .route("/admin/nodes/{name}/via-gateway", axum::routing::put(set_via_gateway))
        .route("/admin/peers", get(list_peers))
        .route("/admin/services", get(list_services))
        .route(
            "/admin/nodes/{name}/services/{service}/approve",
            post(approve_service),
        )
        .route(
            "/admin/nodes/{name}/services/{service}/deny",
            post(deny_service),
        )
}

fn build_router(state: MockState) -> Router {
    admin_only_routes()
        .route("/register", post(register))
        .with_state(state)
}

fn build_admin_only_router(state: MockState) -> Router {
    admin_only_routes().with_state(state)
}

fn build_register_only_router(state: MockState) -> Router {
    Router::new()
        .route("/register", post(register))
        .with_state(state)
}
