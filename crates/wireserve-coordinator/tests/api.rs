//! Integration tests driving the coordinator's HTTP routers directly via
//! `tower::ServiceExt::oneshot` (no real socket). Each test gets a fresh
//! temp-file-backed SQLite DB — not `:memory:`, since `AppState`'s `Db`
//! wraps a single shared `Connection` behind a `tokio::sync::Mutex` and an
//! in-memory DB is scoped to one connection anyway; a temp file keeps the
//! test setup identical to how the real coordinator opens its DB.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use serde_json::{json, Value};
use tower::ServiceExt;

use wireserve_coordinator::{build_state, db::Db, routes, AppState, Config};

const PEER_IP: &str = "203.0.113.10";

fn test_config(db_path: &str) -> Config {
    Config {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        admin_listen_addr: "127.0.0.1:0".parse().unwrap(),
        admin_token: "test-admin-token".to_string(),
        db_path: db_path.to_string(),
        net_v4_cidr: "100.90.0.0/24".to_string(),
        net_v6_prefix: "fd00:90::/64".to_string(),
        online_threshold_secs: 180,
        rate_limit_max: 1000,
        rate_limit_window_secs: 60,
        trust_proxy_headers: false,
    }
}

struct TestApp {
    router: Router,
    state: AppState,
    _db_file: tempfile::NamedTempFile,
}

fn app_with_config(config: Config) -> TestApp {
    let db_file = tempfile::NamedTempFile::new().unwrap();
    let db_path = db_file.path().to_str().unwrap().to_string();
    let mut config = config;
    config.db_path = db_path.clone();
    let db = Db::open(&db_path).unwrap();
    let state = build_state(config, db);
    let router = routes::node_router(state.clone()).merge(routes::admin_router(state.clone()));
    TestApp {
        router,
        state,
        _db_file: db_file,
    }
}

fn test_app() -> TestApp {
    app_with_config(test_config(""))
}

fn json_request(method: &str, uri: &str, auth: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = auth {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let mut req = builder.body(Body::from(body.to_string())).unwrap();
    let peer: SocketAddr = format!("{PEER_IP}:12345").parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    req
}

fn raw_request(method: &str, uri: &str, auth_header: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(h) = auth_header {
        builder = builder.header("authorization", h);
    }
    let mut req = builder.body(Body::empty()).unwrap();
    let peer: SocketAddr = format!("{PEER_IP}:12345").parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    req
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

const ADMIN: &str = "test-admin-token";

/// Deterministically derives a syntactically valid WireGuard pubkey (32
/// bytes, standard base64) from a short human-readable seed, so test call
/// sites can keep writing readable identifiers like `"pk1"` while
/// actually sending something that passes the coordinator's real pubkey
/// validation (security review S2) rather than an arbitrary placeholder
/// string.
fn pubkey_for(seed: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(seed.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(digest)
}

async fn admin_create_node(router: &Router, name: &str) -> String {
    let req = json_request(
        "POST",
        "/admin/nodes",
        Some(ADMIN),
        json!({ "name": name }),
    );
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "create-node should succeed"
    );
    let body = body_json(resp).await;
    body["join_token"].as_str().unwrap().to_string()
}

async fn register_node(
    router: &Router,
    join_token: &str,
    pubkey_seed: &str,
    listen_port: u16,
) -> Value {
    let req = json_request(
        "POST",
        "/register",
        None,
        json!({
            "join_token": join_token,
            "pubkey": pubkey_for(pubkey_seed),
            "listen_port": listen_port,
        }),
    );
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "register should succeed");
    body_json(resp).await
}

// ---- 1. Full lifecycle ----

#[tokio::test]
async fn full_lifecycle_create_register_poll() {
    let app = test_app();
    let join_token = admin_create_node(&app.router, "homeserver").await;
    let reg = register_node(&app.router, &join_token, "pk-homeserver", 51820).await;
    let bearer = reg["bearer_token"].as_str().unwrap();

    let req = json_request("POST", "/poll", Some(bearer), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let peers = body["peers"].as_array().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0]["name"], "homeserver");
    assert!(body["services"].as_array().unwrap().is_empty());
}

// ---- 2. Cross-node service name collision ----

#[tokio::test]
async fn cross_node_service_collision_returns_409_and_leaves_first_untouched() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let t2 = admin_create_node(&app.router, "n2").await;
    let r1 = register_node(&app.router, &t1, "pk1", 51820).await;
    let r2 = register_node(&app.router, &t2, "pk2", 51821).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap();
    let bearer2 = r2["bearer_token"].as_str().unwrap();

    let req = json_request(
        "POST",
        "/poll",
        Some(bearer1),
        json!({ "services": [{"name": "plex", "port": 32400, "proto": "tcp"}] }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = json_request(
        "POST",
        "/poll",
        Some(bearer2),
        json!({ "services": [{"name": "plex", "port": 1, "proto": "tcp"}] }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_json(resp).await;
    assert!(body["error"].as_str().unwrap().contains("plex"));

    // node1's service must be untouched — re-declare the same thing it
    // already has (not an empty list, which would itself withdraw it) and
    // confirm the directory still reflects the original port.
    let req = json_request(
        "POST",
        "/poll",
        Some(bearer1),
        json!({ "services": [{"name": "plex", "port": 32400, "proto": "tcp"}] }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    let services = body["services"].as_array().unwrap();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0]["port"], 32400);
}

// ---- 3. Revoke ----

#[tokio::test]
async fn revoke_rejects_old_bearer_and_removes_peer_and_services() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let t2 = admin_create_node(&app.router, "n2").await;
    let r1 = register_node(&app.router, &t1, "pk1", 51820).await;
    let r2 = register_node(&app.router, &t2, "pk2", 51821).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();
    let bearer2 = r2["bearer_token"].as_str().unwrap().to_string();

    let req = json_request(
        "POST",
        "/poll",
        Some(&bearer1),
        json!({ "services": [{"name": "plex", "port": 32400, "proto": "tcp"}] }),
    );
    app.router.clone().oneshot(req).await.unwrap();

    let req = json_request("POST", "/admin/nodes/n1/revoke", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Old bearer token now rejected.
    let req = json_request("POST", "/poll", Some(&bearer1), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // n2's next poll no longer lists n1, and n1's service is gone.
    let req = json_request("POST", "/poll", Some(&bearer2), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    let peers = body["peers"].as_array().unwrap();
    assert!(peers.iter().all(|p| p["name"] != "n1"));
    assert!(body["services"].as_array().unwrap().is_empty());
}

// ---- 4. Rejoin ----

#[tokio::test]
async fn rejoin_issues_new_token_and_old_bearer_stays_dead_until_reregister() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "pk1", 51820).await;
    let old_bearer = r1["bearer_token"].as_str().unwrap().to_string();

    let req = json_request("POST", "/admin/nodes/n1/revoke", Some(ADMIN), json!({}));
    app.router.clone().oneshot(req).await.unwrap();

    let req = json_request("POST", "/admin/nodes/n1/rejoin", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    let new_join_token = body["join_token"].as_str().unwrap().to_string();

    // Old bearer token is still dead — rejoin alone didn't restore it.
    let req = json_request("POST", "/poll", Some(&old_bearer), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Successful re-registration clears revoked and issues a fresh bearer.
    let r2 = register_node(&app.router, &new_join_token, "pk1-new", 51820).await;
    let new_bearer = r2["bearer_token"].as_str().unwrap();
    let req = json_request("POST", "/poll", Some(new_bearer), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---- 5. Join token is single-use, indistinguishable from unknown ----

#[tokio::test]
async fn join_token_reuse_fails_same_as_unknown_token() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    register_node(&app.router, &t1, "pk1", 51820).await;

    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": t1, "pubkey": pubkey_for("pk-second-try"), "listen_port": 51820 }),
    );
    let resp_reuse = app.router.clone().oneshot(req).await.unwrap();
    let status_reuse = resp_reuse.status();
    let body_reuse = body_json(resp_reuse).await;

    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": "jtk_never_existed", "pubkey": pubkey_for("pk-x"), "listen_port": 51820 }),
    );
    let resp_unknown = app.router.clone().oneshot(req).await.unwrap();
    let status_unknown = resp_unknown.status();
    let body_unknown = body_json(resp_unknown).await;

    assert_eq!(status_reuse, status_unknown);
    assert_eq!(body_reuse, body_unknown);
}

// ---- 6. Admin auth rejects all bad forms uniformly ----

#[tokio::test]
async fn admin_auth_rejects_missing_wrong_scheme_empty_and_wrong_token() {
    let app = test_app();

    let cases: Vec<Request<Body>> = vec![
        raw_request("POST", "/admin/nodes", None),
        raw_request("POST", "/admin/nodes", Some("Basic dXNlcjpwYXNz")),
        raw_request("POST", "/admin/nodes", Some("Bearer ")),
        raw_request("POST", "/admin/nodes", Some("Bearer wrong-token")),
    ];

    let mut statuses = Vec::new();
    let mut bodies = Vec::new();
    for req in cases {
        let resp = app.router.clone().oneshot(req).await.unwrap();
        statuses.push(resp.status());
        bodies.push(body_json(resp).await);
    }

    for s in &statuses {
        assert_eq!(*s, StatusCode::UNAUTHORIZED);
    }
    for b in &bodies[1..] {
        assert_eq!(&bodies[0], b, "all rejection bodies must have the same shape");
    }
}

// ---- 7. Node-facing auth rejects all bad forms ----

#[tokio::test]
async fn poll_auth_rejects_missing_wrong_revoked_and_unknown_tokens() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "pk1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();

    let req = json_request("POST", "/admin/nodes/n1/revoke", Some(ADMIN), json!({}));
    app.router.clone().oneshot(req).await.unwrap();

    let cases = vec![
        raw_request("POST", "/poll", None),
        raw_request("POST", "/poll", Some("Bearer brt_totally_unknown")),
        raw_request("POST", "/poll", Some(&format!("Bearer {bearer1}"))),
    ];
    for req in cases {
        let resp = app.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

// ---- 8. DNS-label validation enforced server-side ----

#[tokio::test]
async fn invalid_node_name_rejected_and_not_created() {
    let app = test_app();
    for bad in ["Bad-Name", "bad_name", "", &"a".repeat(64), "-bad"] {
        let req = json_request("POST", "/admin/nodes", Some(ADMIN), json!({ "name": bad }));
        let resp = app.router.clone().oneshot(req).await.unwrap();
        assert!(
            resp.status().is_client_error(),
            "expected 4xx for name {bad:?}, got {}",
            resp.status()
        );
    }

    // Confirm no node was created for a rejected name by trying to create
    // a *valid* node reusing that exact rejected value is not meaningful
    // (it was invalid), so instead confirm admin/peers stays empty.
    let req = json_request("GET", "/admin/peers", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    assert!(body["peers"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn invalid_service_name_in_poll_rejects_whole_batch() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "pk1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap();

    let req = json_request(
        "POST",
        "/poll",
        Some(bearer1),
        json!({ "services": [
            {"name": "good-one", "port": 1, "proto": "tcp"},
            {"name": "Bad_Name", "port": 2, "proto": "tcp"}
        ] }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_client_error());

    // Neither entry should have been applied.
    let req = json_request("POST", "/poll", Some(bearer1), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    assert!(body["services"].as_array().unwrap().is_empty());
}

// ---- 9. kind=static registration ----

#[tokio::test]
async fn static_node_endpoint_addr_stays_null() {
    let app = test_app();
    let req = json_request(
        "POST",
        "/admin/nodes",
        Some(ADMIN),
        json!({ "name": "phone", "kind": "static" }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    let join_token = body["join_token"].as_str().unwrap();

    let req = json_request(
        "POST",
        "/register",
        None,
        json!({
            "join_token": join_token,
            "pubkey": pubkey_for("pk-phone"),
            "kind": "static",
            "endpoint_addr": "should-be-ignored:51820",
        }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = json_request("GET", "/admin/peers", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    let peers = body["peers"].as_array().unwrap();
    let phone = peers.iter().find(|p| p["name"] == "phone").unwrap();
    assert!(phone["endpoint_addr"].is_null());
}

// ---- 10. Rate limiter ----

#[tokio::test]
async fn rate_limiter_trips_after_threshold_and_is_per_ip() {
    let mut config = test_config("");
    config.rate_limit_max = 2;
    config.rate_limit_window_secs = 60;
    let app = app_with_config(config);

    for _ in 0..2 {
        let req = raw_request("POST", "/admin/nodes", Some("Bearer wrong"));
        let resp = app.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    let req = raw_request("POST", "/admin/nodes", Some("Bearer wrong"));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    // A different source IP is unaffected.
    let mut req = Request::builder()
        .method("POST")
        .uri("/admin/nodes")
        .header("authorization", "Bearer wrong")
        .body(Body::empty())
        .unwrap();
    let other_ip: SocketAddr = "198.51.100.7:9999".parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(other_ip));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---- 13. online / last_handshake threshold ----

#[tokio::test]
async fn online_threshold_reflects_last_seen_staleness() {
    let mut config = test_config("");
    config.online_threshold_secs = 5;
    let app = app_with_config(config);

    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "pk1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap();

    let req = json_request(
        "POST",
        "/poll",
        Some(bearer1),
        json!({ "services": [{"name": "plex", "port": 32400, "proto": "tcp"}] }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    assert!(body["services"][0]["online"].as_bool().unwrap());
    assert!(body["peers"][0]["last_handshake"].is_string());

    // Push last_seen far into the past directly in the DB to simulate
    // staleness without sleeping in a test.
    {
        let conn = app.state.db.conn.lock().await;
        conn.execute(
            "UPDATE nodes SET last_seen = '2000-01-01T00:00:00+00:00' WHERE name = 'n1'",
            [],
        )
        .unwrap();
    }

    let req = json_request("GET", "/admin/peers", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    let peer = &body["peers"][0];
    assert!(peer["last_handshake"].is_null());
}

// ---- Security review regression coverage ----

// S2: a "pubkey" or "endpoint_addr" that isn't validated gets redistributed
// verbatim to every other node's /poll response and into rendered .conf
// files — an attacker holding any valid bearer token could otherwise
// smuggle extra config-file syntax into every downstream consumer.

#[tokio::test]
async fn register_rejects_malformed_pubkey() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": t1, "pubkey": "not-a-real-pubkey", "listen_port": 51820 }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_client_error());

    // The join token must NOT have been consumed by the rejected attempt.
    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": t1, "pubkey": pubkey_for("valid"), "listen_port": 51820 }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn register_rejects_endpoint_addr_config_injection_attempt() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let req = json_request(
        "POST",
        "/register",
        None,
        json!({
            "join_token": t1,
            "pubkey": pubkey_for("n1"),
            "listen_port": 51820,
            "endpoint_addr": "1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0",
        }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn poll_rejects_endpoint_addr_config_injection_attempt() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap();

    let req = json_request(
        "POST",
        "/poll",
        Some(bearer1),
        json!({
            "services": [],
            "endpoint_addr": "1.2.3.4:51820\r\nEndpoint = evil.example:1",
        }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_client_error());
}

// F3: a service-name collision must be machine-readable, not just a string
// the agent has to parse.

#[tokio::test]
async fn service_collision_409_includes_conflicting_service_field() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let t2 = admin_create_node(&app.router, "n2").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let r2 = register_node(&app.router, &t2, "n2", 51821).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap();
    let bearer2 = r2["bearer_token"].as_str().unwrap();

    let req = json_request(
        "POST",
        "/poll",
        Some(bearer1),
        json!({ "services": [{"name": "plex", "port": 32400, "proto": "tcp"}] }),
    );
    app.router.clone().oneshot(req).await.unwrap();

    let req = json_request(
        "POST",
        "/poll",
        Some(bearer2),
        json!({ "services": [{"name": "plex", "port": 1, "proto": "tcp"}] }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_json(resp).await;
    assert_eq!(body["conflicting_service"].as_str(), Some("plex"));
}

// S8: rejoin must invalidate the OLD bearer token immediately, even when
// the node was never separately revoked first — spec §4.5 explicitly
// covers calling rejoin directly on a node whose key is merely "suspected
// compromised."

#[tokio::test]
async fn rejoin_on_non_revoked_node_invalidates_old_bearer_immediately() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let old_bearer = r1["bearer_token"].as_str().unwrap().to_string();

    // No revoke call here — going straight to rejoin.
    let req = json_request("POST", "/admin/nodes/n1/rejoin", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let req = json_request("POST", "/poll", Some(&old_bearer), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "the old bearer token must stop working the moment rejoin is called, not just on revoke"
    );
}

// F4: rejoin must not reallocate the node's address — every static peer's
// exported .conf pointing at it would otherwise go stale.

#[tokio::test]
async fn rejoin_then_reregister_keeps_the_same_address() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let original_ip4 = r1["ip4"].as_str().unwrap().to_string();
    let original_ip6 = r1["ip6"].as_str().unwrap().to_string();

    let req = json_request("POST", "/admin/nodes/n1/revoke", Some(ADMIN), json!({}));
    app.router.clone().oneshot(req).await.unwrap();
    let req = json_request("POST", "/admin/nodes/n1/rejoin", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    let new_join_token = body["join_token"].as_str().unwrap().to_string();

    let r2 = register_node(&app.router, &new_join_token, "n1-new-key", 51820).await;
    assert_eq!(r2["ip4"].as_str().unwrap(), original_ip4);
    assert_eq!(r2["ip6"].as_str().unwrap(), original_ip6);
}

// F7: spec §4.1/§4.5 both specify 201 for create-node and rejoin.

#[tokio::test]
async fn create_node_and_rejoin_return_201() {
    let app = test_app();
    let req = json_request("POST", "/admin/nodes", Some(ADMIN), json!({ "name": "n1" }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let req = json_request("POST", "/admin/nodes/n1/rejoin", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

// S3: rate limiting must not consume budget on successful requests — only
// actual failures should count against it.

#[tokio::test]
async fn successful_admin_auth_never_consumes_rate_limit_budget() {
    let mut config = test_config("");
    config.rate_limit_max = 3;
    let app = app_with_config(config);

    // Far more successful admin requests than the failure budget would
    // allow, back to back — none of them should ever trip the limiter,
    // since success is never recorded as a "hit."
    for i in 0..10 {
        let req = json_request(
            "POST",
            "/admin/nodes",
            Some(ADMIN),
            json!({ "name": format!("node{i}") }),
        );
        let resp = app.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
}
