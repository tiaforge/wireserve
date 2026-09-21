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
        join_token_ttl_secs: 1800,
        // Effectively disabled for most tests: the delay is real wall
        // time, and every existing test that exercises a failure path
        // would otherwise pay for it. The tests that care about the
        // delay lower this deliberately.
        global_auth_failure_max: u32::MAX,
        global_auth_failure_window_secs: 60,
        // Most existing tests predate approval and assert the immediate
        // propagation that was the only behaviour then. They run with it
        // off; the approval tests set it explicitly.
        require_service_approval: false,
        reflexive_rate_limit_max: 1000,
        reflexive_rate_limit_window_secs: 60,
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
async fn register_rejects_config_injection_via_v4_or_v6_endpoint() {
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
            "endpoint_addr_v4": "1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0",
        }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn register_and_poll_propagate_dual_stack_endpoint_candidates() {
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
            "endpoint_addr_v4": "203.0.113.5:51820",
            "endpoint_addr_v6": "[2001:db8::1]:51820",
        }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let r1 = body_json(resp).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();

    // A second node polls and should see n1's dual candidates in its
    // directory.
    let t2 = admin_create_node(&app.router, "n2").await;
    let r2 = register_node(&app.router, &t2, "n2", 51820).await;
    let bearer2 = r2["bearer_token"].as_str().unwrap();
    let req = json_request("POST", "/poll", Some(bearer2), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    let n1_peer = body["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "n1")
        .unwrap();
    assert_eq!(n1_peer["endpoint_addr_v4"], "203.0.113.5:51820");
    assert_eq!(n1_peer["endpoint_addr_v6"], "[2001:db8::1]:51820");

    // n1 polls reporting only a fresh v6 candidate — its v4 one must
    // survive (COALESCE), not get wiped.
    let req = json_request(
        "POST",
        "/poll",
        Some(&bearer1),
        json!({ "services": [], "endpoint_addr_v6": "[2001:db8::2]:51820" }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let conn = app.state.db.conn.lock().await;
    let row = wireserve_coordinator::db::nodes::find_by_name(&conn, "n1")
        .unwrap()
        .unwrap();
    assert_eq!(row.endpoint_addr_v4.as_deref(), Some("203.0.113.5:51820"));
    assert_eq!(row.endpoint_addr_v6.as_deref(), Some("[2001:db8::2]:51820"));
}

#[tokio::test]
async fn register_rejects_a_public_ip_as_lan_addr() {
    // NAT-hairpin fix (PLAN.md decisions log #85): server-side defense in
    // depth against a malicious/buggy agent claiming a public address as
    // its "LAN" address, which would then get redistributed to every peer
    // as a same-LAN candidate.
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
            "lan_addr": "203.0.113.5",
        }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn register_and_poll_propagate_the_lan_addr_candidate() {
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
            "lan_addr": "192.168.1.50",
        }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let t2 = admin_create_node(&app.router, "n2").await;
    let r2 = register_node(&app.router, &t2, "n2", 51820).await;
    let bearer2 = r2["bearer_token"].as_str().unwrap();
    let req = json_request("POST", "/poll", Some(bearer2), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    let n1_peer = body["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "n1")
        .unwrap();
    assert_eq!(n1_peer["lan_addr"], "192.168.1.50");
}

#[tokio::test]
async fn poll_omitting_lan_addr_preserves_the_previous_value() {
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
            "lan_addr": "192.168.1.50",
        }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let r1 = body_json(resp).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();

    // A poll that can't currently read its own interfaces (or simply
    // didn't change networks) omits lan_addr — the previously reported
    // value must survive, same COALESCE contract as endpoint_addr_v4/_v6.
    let req = json_request("POST", "/poll", Some(&bearer1), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let conn = app.state.db.conn.lock().await;
    let row = wireserve_coordinator::db::nodes::find_by_name(&conn, "n1")
        .unwrap()
        .unwrap();
    assert_eq!(row.lan_addr.as_deref(), Some("192.168.1.50"));
}

#[tokio::test]
async fn admin_can_clear_a_single_endpoint_family() {
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
            "endpoint_addr_v4": "203.0.113.5:51820",
            "endpoint_addr_v6": "[2001:db8::1]:51820",
        }),
    );
    app.router.clone().oneshot(req).await.unwrap();

    let req = raw_request(
        "DELETE",
        "/admin/nodes/n1/endpoint/v6",
        Some(&format!("Bearer {ADMIN}")),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let conn = app.state.db.conn.lock().await;
    let row = wireserve_coordinator::db::nodes::find_by_name(&conn, "n1")
        .unwrap()
        .unwrap();
    assert_eq!(row.endpoint_addr_v4.as_deref(), Some("203.0.113.5:51820"));
    assert!(row.endpoint_addr_v6.is_none());
}

#[tokio::test]
async fn admin_clear_endpoint_rejects_an_unknown_family() {
    let app = test_app();
    admin_create_node(&app.router, "n1").await;
    let req = raw_request(
        "DELETE",
        "/admin/nodes/n1/endpoint/v5",
        Some(&format!("Bearer {ADMIN}")),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_client_error());
}

#[tokio::test]
async fn probe_echoes_the_observed_source_address_per_family() {
    let app = test_app();

    let mut req = Request::builder()
        .method("GET")
        .uri("/probe")
        .body(Body::empty())
        .unwrap();
    let v4: SocketAddr = "203.0.113.10:12345".parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(v4));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["addr"], "203.0.113.10");

    let mut req = Request::builder()
        .method("GET")
        .uri("/probe")
        .body(Body::empty())
        .unwrap();
    let v6: SocketAddr = "[2001:db8::5]:12345".parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(v6));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["addr"], "2001:db8::5");
}

#[tokio::test]
async fn probe_uses_the_forwarded_address_when_the_proxy_is_trusted() {
    let mut config = test_config("");
    config.trust_proxy_headers = true;
    let app = app_with_config(config);

    let mut req = Request::builder()
        .method("GET")
        .uri("/probe")
        .header("x-forwarded-for", "192.168.20.5")
        .body(Body::empty())
        .unwrap();
    let proxy: SocketAddr = "10.0.0.9:443".parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(proxy));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["addr"], "192.168.20.5");
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

// ---- Security review, round 2 ----

// S3 on /register: the budget must be checked BEFORE the token lookup, so
// a source that has exhausted its failed attempts is turned away even when
// its next guess is the correct token. Anything else makes the limiter a
// response-code cosmetic rather than a brute-force bound.

#[tokio::test]
async fn register_still_honours_a_correct_token_when_the_source_is_over_budget() {
    // This deliberately reverses what an earlier round asserted here.
    //
    // The limiter is keyed on a source address, and spec §7 puts a
    // reverse proxy in front of this coordinator, so in the topology the
    // spec describes every node shares one key. Refusing a *valid*
    // credential because that shared key is over budget meant any
    // stranger who could reach /register could stop every legitimate node
    // from joining, for the length of the window, by guessing wrong a few
    // times. Nodes behind one NAT share a key the same way. The guard was
    // a better denial of service than the thing it guarded against, which
    // is guessing a 256-bit token.
    //
    // What an over-budget source still cannot do is keep failing, which
    // is asserted below.
    let mut config = test_config("");
    config.rate_limit_max = 2;
    let app = app_with_config(config);
    let real_token = admin_create_node(&app.router, "n1").await;

    for _ in 0..2 {
        let req = json_request(
            "POST",
            "/register",
            None,
            json!({ "join_token": "jtk_wrong", "pubkey": pubkey_for("x"), "listen_port": 51820 }),
        );
        let resp = app.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // Budget spent. A further WRONG guess from this source is now turned
    // away as rate-limited rather than merely rejected.
    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": "jtk_wrong_again", "pubkey": pubkey_for("x"), "listen_port": 51820 }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "an over-budget source must not be able to keep guessing"
    );

    // But the genuine token from that same source still works: this node
    // did nothing wrong and is very likely sharing an address with
    // whoever did.
    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": real_token, "pubkey": pubkey_for("n1"), "listen_port": 51820 }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a valid join token must not be collateral damage of a shared rate-limit key"
    );
}

#[tokio::test]
async fn poll_still_works_for_a_valid_node_when_its_shared_source_is_over_budget() {
    // The mesh-wide version of the same failure: one bad actor behind the
    // proxy, and every node's next poll gets a 429 until the window
    // clears. Peer reconciliation, revocation propagation and hosts-file
    // sync all stop for the whole mesh.
    let mut config = test_config("");
    config.rate_limit_max = 2;
    let app = app_with_config(config);
    let join = admin_create_node(&app.router, "innocent").await;
    let reg = register_node(&app.router, &join, "pk-innocent", 51820).await;
    let bearer = reg["bearer_token"].as_str().unwrap();

    for _ in 0..3 {
        let req = json_request("POST", "/poll", Some("brt_garbage"), json!({ "services": [] }));
        app.router.clone().oneshot(req).await.unwrap();
    }

    let req = json_request("POST", "/poll", Some(bearer), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a node with a valid bearer token must keep polling even when its source address is over budget"
    );

    // And the bad credential from that same source is still refused.
    let req = json_request("POST", "/poll", Some("brt_garbage"), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

// S4 on /register: with trust_proxy_headers on, the rate-limit key is the
// X-Forwarded-For client, so two clients behind one proxy get separate
// budgets instead of sharing (and exhausting) the proxy's.

#[tokio::test]
async fn register_rate_limit_is_keyed_on_forwarded_client_when_proxy_trusted() {
    let mut config = test_config("");
    config.rate_limit_max = 1;
    config.trust_proxy_headers = true;
    let app = app_with_config(config);

    let bad = |xff: &str| {
        let mut req = Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .header("x-forwarded-for", xff)
            .body(Body::from(
                json!({ "join_token": "jtk_wrong", "pubkey": pubkey_for("x"), "listen_port": 1 })
                    .to_string(),
            ))
            .unwrap();
        // Same proxy address for every request.
        let proxy: SocketAddr = "10.0.0.2:4444".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(proxy));
        req
    };

    let resp = app.router.clone().oneshot(bad("203.0.113.5")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = app.router.clone().oneshot(bad("203.0.113.5")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "same client, budget spent");
    let resp = app.router.clone().oneshot(bad("203.0.113.6")).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a different client behind the same proxy must have its own budget"
    );
}

// F8: DELETE /admin/nodes/{name} frees the name, refuses active nodes.

#[tokio::test]
async fn delete_node_frees_name_for_unregistered_and_revoked_nodes() {
    let app = test_app();

    // Never registered (the export-config-failed-halfway case).
    admin_create_node(&app.router, "orphan").await;
    let req = json_request("DELETE", "/admin/nodes/orphan", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Name is free again.
    admin_create_node(&app.router, "orphan").await;

    // Registered, revoked, with a service: delete cascades the service.
    let t = admin_create_node(&app.router, "old").await;
    let r = register_node(&app.router, &t, "old", 51820).await;
    let bearer = r["bearer_token"].as_str().unwrap();
    let req = json_request(
        "POST",
        "/poll",
        Some(bearer),
        json!({ "services": [{"name": "svc", "port": 1, "proto": "tcp"}] }),
    );
    app.router.clone().oneshot(req).await.unwrap();
    let req = json_request("POST", "/admin/nodes/old/revoke", Some(ADMIN), json!({}));
    app.router.clone().oneshot(req).await.unwrap();
    let req = json_request("DELETE", "/admin/nodes/old", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let count: i64 = {
        let conn = app.state.db.conn.lock().await;
        conn.query_row("SELECT COUNT(*) FROM nodes WHERE name = 'old'", [], |r| r.get(0))
            .unwrap()
    };
    assert_eq!(count, 0);

    // Unknown name.
    let req = json_request("DELETE", "/admin/nodes/nope", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_node_refuses_an_active_node_until_revoked() {
    let app = test_app();
    let t = admin_create_node(&app.router, "live").await;
    register_node(&app.router, &t, "live", 51820).await;

    let req = json_request("DELETE", "/admin/nodes/live", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Still there.
    let req = json_request("GET", "/admin/peers", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["peers"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn delete_node_requires_admin_auth() {
    let app = test_app();
    admin_create_node(&app.router, "n1").await;
    let req = raw_request("DELETE", "/admin/nodes/n1", Some("Bearer wrong"));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---- Review round 3: functional fixes ----

#[tokio::test]
async fn poll_rejects_port_zero_and_too_many_services() {
    let app = test_app();
    let t = admin_create_node(&app.router, "n1").await;
    let r = register_node(&app.router, &t, "n1", 51820).await;
    let bearer = r["bearer_token"].as_str().unwrap();

    let req = json_request(
        "POST",
        "/poll",
        Some(bearer),
        json!({ "services": [{"name": "zero", "port": 0, "proto": "tcp"}] }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let too_many: Vec<Value> = (0..65)
        .map(|i| json!({"name": format!("svc{i}"), "port": 1000 + i, "proto": "tcp"}))
        .collect();
    let req = json_request("POST", "/poll", Some(bearer), json!({ "services": too_many }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Nothing from either rejected batch was applied.
    let req = json_request("POST", "/poll", Some(bearer), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    assert!(body["services"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn register_rejects_listen_port_zero() {
    let app = test_app();
    let t = admin_create_node(&app.router, "n1").await;
    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": t, "pubkey": pubkey_for("n1"), "listen_port": 0 }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn duplicate_pubkey_gets_a_pubkey_specific_409() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let t2 = admin_create_node(&app.router, "n2").await;
    register_node(&app.router, &t1, "same-key", 51820).await;

    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": t2, "pubkey": pubkey_for("same-key"), "listen_port": 51821 }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_json(resp).await;
    let msg = body["error"].as_str().unwrap();
    assert!(msg.contains("pubkey"), "error must name the pubkey, got {msg:?}");
    assert!(!msg.contains("name already in use"));

    // The join token was not consumed by the failed attempt.
    register_node(&app.router, &t2, "other-key", 51821).await;
}

// ---- Round-3 security review: revoke must kill an outstanding join token ----

#[tokio::test]
async fn revoke_kills_a_join_token_that_was_never_redeemed() {
    // The scenario this protects against: a node is created, its join
    // token goes out of band, and the token is found to have leaked
    // before the machine ever registered. Revoking is the operator's
    // only lever, and it has to actually close the door — redeeming the
    // leaked token afterwards would otherwise hand out a bearer token
    // AND clear `revoked` back to 0, putting the attacker on the mesh as
    // a fully legitimate member.
    let app = test_app();
    let join_token = admin_create_node(&app.router, "neverjoined").await;

    let req = raw_request("POST", "/admin/nodes/neverjoined/revoke", Some(&format!("Bearer {ADMIN}")));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = json_request(
        "POST",
        "/register",
        None,
        json!({
            "join_token": join_token,
            "pubkey": pubkey_for("attacker"),
            "listen_port": 51820,
        }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "a join token outstanding at revoke time must be dead afterwards"
    );

    // And the node must still be revoked, not resurrected.
    let conn = app.state.db.conn.lock().await;
    let row = wireserve_coordinator::db::nodes::find_by_name(&conn, "neverjoined")
        .unwrap()
        .unwrap();
    assert!(row.revoked, "node must remain revoked");
    assert!(row.pubkey.is_none(), "no pubkey may have been recorded");
}

#[tokio::test]
async fn revoke_then_rejoin_still_lets_the_node_come_back() {
    // The other half of the contract above: killing the outstanding
    // token must not break spec §4.5's supported way back in.
    let app = test_app();
    let t1 = admin_create_node(&app.router, "comeback").await;
    register_node(&app.router, &t1, "pk-comeback", 51820).await;

    let req = raw_request("POST", "/admin/nodes/comeback/revoke", Some(&format!("Bearer {ADMIN}")));
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    let req = raw_request("POST", "/admin/nodes/comeback/rejoin", Some(&format!("Bearer {ADMIN}")));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let new_token = body_json(resp).await["join_token"].as_str().unwrap().to_string();

    let reg = register_node(&app.router, &new_token, "pk-comeback-2", 51820).await;
    let bearer = reg["bearer_token"].as_str().unwrap();
    let req = json_request("POST", "/poll", Some(bearer), json!({ "services": [] }));
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "a rejoined node must be able to poll again"
    );
}

// ---- Round-3: a kind=static node must never poll (spec §9) ----

#[tokio::test]
async fn static_node_is_refused_at_poll() {
    let app = test_app();
    let req = json_request(
        "POST",
        "/admin/nodes",
        Some(ADMIN),
        json!({ "name": "phone", "kind": "static" }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let join_token = body_json(resp).await["join_token"].as_str().unwrap().to_string();

    let req = json_request(
        "POST",
        "/register",
        None,
        json!({
            "join_token": join_token,
            "pubkey": pubkey_for("pk-phone"),
            "kind": "static",
        }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bearer = body_json(resp).await["bearer_token"].as_str().unwrap().to_string();

    // Spec §9: a static peer never polls. Nothing legitimately holds this
    // token (export-config discards it), but the endpoint must not depend
    // on that for the invariant "a static node's endpoint_addr is NULL".
    let req = json_request(
        "POST",
        "/poll",
        Some(&bearer),
        json!({ "endpoint_addr": "1.2.3.4:51820", "services": [] }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let conn = app.state.db.conn.lock().await;
    let row = wireserve_coordinator::db::nodes::find_by_name(&conn, "phone")
        .unwrap()
        .unwrap();
    assert!(
        row.endpoint_addr.is_none(),
        "a refused poll must not have written an endpoint onto a static node"
    );
}

// ---- Round-4: the endpoint fallback in the topology spec §7 mandates ----

#[tokio::test]
async fn proxied_node_gets_an_endpoint_from_its_forwarded_address() {
    // Found by actually standing up nginx in front of the coordinator.
    // With trust_proxy_headers on, a node's real address arrives via
    // X-Forwarded-For and is private, because an internal network is
    // private by definition. Treating "private" alone as unusable meant
    // every node that omitted --endpoint-addr got no endpoint at all, and
    // a peer with no endpoint cannot be dialled — so a mesh where nobody
    // supplied one could never form.
    let mut config = test_config("");
    config.trust_proxy_headers = true;
    let app = app_with_config(config);

    let t1 = admin_create_node(&app.router, "n1").await;
    let mut req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("content-type", "application/json")
        .header("x-forwarded-for", "192.168.20.5")
        .body(Body::from(
            json!({ "join_token": t1, "pubkey": pubkey_for("n1"), "listen_port": 51820 })
                .to_string(),
        ))
        .unwrap();
    let proxy: SocketAddr = "10.0.0.9:443".parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(proxy));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let conn = app.state.db.conn.lock().await;
    let row = wireserve_coordinator::db::nodes::find_by_name(&conn, "n1")
        .unwrap()
        .unwrap();
    assert_eq!(
        row.endpoint_addr.as_deref(),
        Some("192.168.20.5:51820"),
        "the forwarded client address is the node's real one and must be used"
    );
}

#[tokio::test]
async fn proxy_misconfiguration_still_suppresses_a_useless_endpoint() {
    // The other half, and the case the private-range check exists for:
    // trust_proxy_headers is on but no usable header arrived, so the
    // address in hand is the proxy's own. Handing that to every other
    // node as this node's reachable endpoint would be actively wrong.
    let mut config = test_config("");
    config.trust_proxy_headers = true;
    let app = app_with_config(config);

    let t1 = admin_create_node(&app.router, "n1").await;
    let mut req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "join_token": t1, "pubkey": pubkey_for("n1"), "listen_port": 51820 })
                .to_string(),
        ))
        .unwrap();
    let proxy: SocketAddr = "10.0.0.9:443".parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(proxy));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let conn = app.state.db.conn.lock().await;
    let row = wireserve_coordinator::db::nodes::find_by_name(&conn, "n1")
        .unwrap()
        .unwrap();
    assert!(
        row.endpoint_addr.is_none(),
        "the proxy's own address must never be recorded as a node's endpoint"
    );
}

// ---- service approval ----

fn approval_app() -> TestApp {
    let mut config = test_config("");
    config.require_service_approval = true;
    app_with_config(config)
}

async fn declare(router: &Router, bearer: &str, name: &str) -> Value {
    let req = json_request(
        "POST",
        "/poll",
        Some(bearer),
        json!({ "services": [{ "name": name, "port": 32400, "proto": "tcp" }] }),
    );
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "a declaration must never fail the cycle");
    body_json(resp).await
}

async fn admin_post(router: &Router, uri: &str) -> StatusCode {
    let req = raw_request("POST", uri, Some(&format!("Bearer {ADMIN}")));
    router.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn approval_disabled_behaves_exactly_as_before() {
    // test_config leaves approval off, matching every test written before
    // the feature. Asserted on the raw JSON keys rather than deserialized
    // empty vectors: the claim is about the bytes on the wire.
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();

    let body = declare(&app.router, &bearer1, "plex").await;
    assert_eq!(body["services"].as_array().unwrap().len(), 1);
    assert!(body.get("pending_services").is_none(), "{body}");
    assert!(body.get("denied_services").is_none(), "{body}");

    let t2 = admin_create_node(&app.router, "n2").await;
    let r2 = register_node(&app.router, &t2, "n2", 51821).await;
    let bearer2 = r2["bearer_token"].as_str().unwrap().to_string();
    let req = json_request("POST", "/poll", Some(&bearer2), json!({ "services": [] }));
    let body = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(body["services"].as_array().unwrap().len(), 1, "propagates immediately");
}

#[tokio::test]
async fn a_pending_declaration_succeeds_and_is_invisible_to_other_nodes() {
    let app = approval_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();

    let body = declare(&app.router, &bearer1, "plex").await;
    assert!(body["services"].as_array().unwrap().is_empty(), "not in its own directory yet");
    assert_eq!(body["pending_services"][0]["name"], "plex");

    let t2 = admin_create_node(&app.router, "n2").await;
    let r2 = register_node(&app.router, &t2, "n2", 51821).await;
    let bearer2 = r2["bearer_token"].as_str().unwrap().to_string();
    let req = json_request("POST", "/poll", Some(&bearer2), json!({ "services": [] }));
    let body = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    assert!(
        body["services"].as_array().unwrap().is_empty(),
        "an unapproved name must not reach another node's hosts file"
    );
    assert!(body.get("pending_services").is_none(), "and not another node's verdict list");
}

#[tokio::test]
async fn a_pending_declaration_never_wedges_the_poll_cycle() {
    // The failure shape this project has hit twice: a /poll error skips
    // peer reconciliation, firewall and hosts sync, and since the agent
    // resends the same declaration every cycle, every future cycle fails
    // identically -- so the node stops seeing new peers and never sees
    // its own revocation. Pending can last days; it must stay a 200.
    let app = approval_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();
    let t2 = admin_create_node(&app.router, "n2").await;
    register_node(&app.router, &t2, "n2", 51821).await;

    for cycle in 0..5 {
        let body = declare(&app.router, &bearer1, "plex").await;
        assert_eq!(
            body["peers"].as_array().unwrap().len(),
            2,
            "cycle {cycle} must still carry the peer list"
        );
        assert_eq!(body["pending_services"][0]["name"], "plex");
    }
}

#[tokio::test]
async fn approving_propagates_the_service_and_clears_the_pending_report() {
    let app = approval_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();
    declare(&app.router, &bearer1, "plex").await;

    assert_eq!(
        admin_post(&app.router, "/admin/nodes/n1/services/plex/approve").await,
        StatusCode::OK
    );

    let body = declare(&app.router, &bearer1, "plex").await;
    assert_eq!(body["services"][0]["name"], "plex");
    assert!(body.get("pending_services").is_none(), "no longer pending: {body}");

    let t2 = admin_create_node(&app.router, "n2").await;
    let r2 = register_node(&app.router, &t2, "n2", 51821).await;
    let bearer2 = r2["bearer_token"].as_str().unwrap().to_string();
    let req = json_request("POST", "/poll", Some(&bearer2), json!({ "services": [] }));
    let body = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(body["services"][0]["name"], "plex");
}

#[tokio::test]
async fn approving_for_the_wrong_node_is_refused_and_changes_nothing() {
    // Approval binds to (name, node). An operator acting on a stale view
    // of who owns what must get a 409 naming the real owner, never a
    // silent blessing of a squatter's claim.
    let app = approval_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();
    let t2 = admin_create_node(&app.router, "n2").await;
    let r2 = register_node(&app.router, &t2, "n2", 51821).await;
    let bearer2 = r2["bearer_token"].as_str().unwrap().to_string();

    declare(&app.router, &bearer1, "plex").await;

    let req = raw_request(
        "POST",
        "/admin/nodes/n2/services/plex/approve",
        Some(&format!("Bearer {ADMIN}")),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_json(resp).await;
    assert!(
        body["error"].as_str().unwrap().contains("n1"),
        "the refusal must name the real owner: {body}"
    );

    let body = declare(&app.router, &bearer2, "other").await;
    assert!(
        body["services"].as_array().unwrap().is_empty(),
        "nothing was approved for anyone"
    );
}

#[tokio::test]
async fn a_denied_service_is_reported_to_its_owner_and_to_nobody_else() {
    let app = approval_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();
    let t2 = admin_create_node(&app.router, "n2").await;
    let r2 = register_node(&app.router, &t2, "n2", 51821).await;
    let bearer2 = r2["bearer_token"].as_str().unwrap().to_string();
    declare(&app.router, &bearer1, "plex").await;

    let req = json_request(
        "POST",
        "/admin/nodes/n1/services/plex/deny",
        Some(ADMIN),
        json!({ "reason": "reserved for the build box" }),
    );
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    let body = declare(&app.router, &bearer1, "plex").await;
    assert_eq!(body["denied_services"][0]["name"], "plex");
    assert_eq!(body["denied_services"][0]["reason"], "reserved for the build box");

    let req = json_request("POST", "/poll", Some(&bearer2), json!({ "services": [] }));
    let body = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    assert!(body.get("denied_services").is_none(), "another node's verdicts are not its business");
    assert!(body["services"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn denying_an_approved_service_removes_it_from_the_directory() {
    // The per-name re-review lever for a mesh where enabling approval
    // grandfathered everything already declared.
    let app = approval_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();
    declare(&app.router, &bearer1, "plex").await;
    admin_post(&app.router, "/admin/nodes/n1/services/plex/approve").await;
    let body = declare(&app.router, &bearer1, "plex").await;
    assert_eq!(body["services"].as_array().unwrap().len(), 1);

    assert_eq!(
        admin_post(&app.router, "/admin/nodes/n1/services/plex/deny").await,
        StatusCode::OK
    );

    let body = declare(&app.router, &bearer1, "plex").await;
    assert!(body["services"].as_array().unwrap().is_empty());
    assert_eq!(body["denied_services"][0]["name"], "plex");
}

#[tokio::test]
async fn a_revoked_node_must_have_its_services_reapproved_after_rejoin() {
    // revoke() deletes the node's services rows, so its approvals die
    // with it -- which is the point, since revoke is what you reach for
    // when you no longer trust the node's claims.
    let app = approval_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();
    declare(&app.router, &bearer1, "plex").await;
    admin_post(&app.router, "/admin/nodes/n1/services/plex/approve").await;
    assert_eq!(
        declare(&app.router, &bearer1, "plex").await["services"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    admin_post(&app.router, "/admin/nodes/n1/revoke").await;
    let req = raw_request("POST", "/admin/nodes/n1/rejoin", Some(&format!("Bearer {ADMIN}")));
    let rejoin = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    let fresh = rejoin["join_token"].as_str().unwrap().to_string();
    let r1 = register_node(&app.router, &fresh, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();

    let body = declare(&app.router, &bearer1, "plex").await;
    assert!(
        body["services"].as_array().unwrap().is_empty(),
        "a revoked node's approval must not survive its return"
    );
    assert_eq!(body["pending_services"][0]["name"], "plex");
}

#[tokio::test]
async fn a_bare_rejoin_keeps_an_existing_approval() {
    // The documented asymmetry: a bare rejoin is a credential rotation,
    // not a statement of distrust in what the node claims. Blowing away
    // its directory entries would flap every other node's hosts file for
    // a routine operation.
    let app = approval_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();
    declare(&app.router, &bearer1, "plex").await;
    admin_post(&app.router, "/admin/nodes/n1/services/plex/approve").await;

    let req = raw_request("POST", "/admin/nodes/n1/rejoin", Some(&format!("Bearer {ADMIN}")));
    let rejoin = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    let fresh = rejoin["join_token"].as_str().unwrap().to_string();
    let r1 = register_node(&app.router, &fresh, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();

    let body = declare(&app.router, &bearer1, "plex").await;
    assert_eq!(body["services"].as_array().unwrap().len(), 1);
    assert!(body.get("pending_services").is_none());
}

#[tokio::test]
async fn pending_declarations_count_against_the_per_node_limit() {
    // Otherwise an authenticated node could create unbounded pending rows
    // for an admin to wade through.
    let app = approval_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();

    let max: Vec<Value> = (0..64)
        .map(|i| json!({ "name": format!("svc{i}"), "port": 1000 + i, "proto": "tcp" }))
        .collect();
    let req = json_request("POST", "/poll", Some(&bearer1), json!({ "services": max }));
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );
    {
        let conn = app.state.db.conn.lock().await;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM services", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 64, "pending rows are real rows and are bounded");
    }

    let too_many: Vec<Value> = (0..65)
        .map(|i| json!({ "name": format!("svc{i}"), "port": 1000 + i, "proto": "tcp" }))
        .collect();
    let req = json_request("POST", "/poll", Some(&bearer1), json!({ "services": too_many }));
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn admin_service_listing_reports_every_state() {
    let app = approval_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();

    let req = json_request(
        "POST",
        "/poll",
        Some(&bearer1),
        json!({ "services": [
            { "name": "approved-one", "port": 1, "proto": "tcp" },
            { "name": "pending-one", "port": 2, "proto": "tcp" },
            { "name": "denied-one", "port": 3, "proto": "tcp" }
        ] }),
    );
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );
    admin_post(&app.router, "/admin/nodes/n1/services/approved-one/approve").await;
    admin_post(&app.router, "/admin/nodes/n1/services/denied-one/deny").await;

    let req = raw_request("GET", "/admin/services", Some(&format!("Bearer {ADMIN}")));
    let body = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    let by_name: std::collections::HashMap<String, String> = body["services"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["name"].as_str().unwrap().to_string(),
                s["state"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(by_name["approved-one"], "approved");
    assert_eq!(by_name["pending-one"], "pending");
    assert_eq!(by_name["denied-one"], "denied");
}

#[tokio::test]
async fn approval_endpoints_require_admin_auth_and_report_missing_things() {
    let app = approval_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();
    declare(&app.router, &bearer1, "plex").await;

    for uri in [
        "/admin/nodes/n1/services/plex/approve",
        "/admin/nodes/n1/services/plex/deny",
    ] {
        let req = raw_request("POST", uri, Some("Bearer wrong-token"));
        assert_eq!(
            app.router.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "{uri}"
        );
    }

    assert_eq!(
        admin_post(&app.router, "/admin/nodes/n1/services/nothing/approve").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        admin_post(&app.router, "/admin/nodes/nope/services/plex/approve").await,
        StatusCode::NOT_FOUND
    );

    let req = raw_request("GET", "/admin/services", Some("Bearer wrong-token"));
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn an_over_long_denial_reason_is_refused_and_nothing_is_half_applied() {
    let app = approval_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();
    declare(&app.router, &bearer1, "plex").await;

    let req = json_request(
        "POST",
        "/admin/nodes/n1/services/plex/deny",
        Some(ADMIN),
        json!({ "reason": "x".repeat(wireserve_types::MAX_DENY_REASON_LEN + 1) }),
    );
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    let body = declare(&app.router, &bearer1, "plex").await;
    assert_eq!(
        body["pending_services"][0]["name"], "plex",
        "the service must still be merely pending, not denied"
    );
    assert!(body.get("denied_services").is_none());
}

// ---- failed-auth delay ----

#[tokio::test(flavor = "multi_thread")]
async fn a_delayed_failure_never_holds_the_database_lock() {
    // The regression test for the way this mitigation could have been
    // worse than the problem. `state.db.conn` is the process's single
    // Mutex<Connection>; awaiting the failure delay while holding it
    // would queue every other request in the mesh behind whoever is
    // guessing join tokens. `/register` in particular used to hold that
    // lock across its whole failure branch.
    let mut config = test_config("");
    config.global_auth_failure_max = 0; // every failure is delayed
    let app = app_with_config(config);

    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer = r1["bearer_token"].as_str().unwrap().to_string();

    // Put a pile of bad registrations into their delay.
    let mut handles = Vec::new();
    for i in 0..8 {
        let router = app.router.clone();
        handles.push(tokio::spawn(async move {
            let req = json_request(
                "POST",
                "/register",
                None,
                json!({
                    "join_token": format!("jtk_bogus{i}"),
                    "pubkey": pubkey_for("z"),
                    "listen_port": 51830
                }),
            );
            router.oneshot(req).await.unwrap()
        }));
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let start = std::time::Instant::now();
    let req = json_request("POST", "/poll", Some(&bearer), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        elapsed < std::time::Duration::from_millis(150),
        "a valid poll must not queue behind delayed failures (took {elapsed:?})"
    );

    for h in handles {
        let _ = h.await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_valid_credential_is_never_delayed_even_with_the_budget_drained() {
    // What makes the global budget free of collateral damage, unlike the
    // per-source window: the population slowed is exactly the population
    // failing. A legitimate node sharing the proxy's address with an
    // attacker is unaffected, because its credential is good.
    let mut config = test_config("");
    config.global_auth_failure_max = 0;
    let app = app_with_config(config);

    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer = r1["bearer_token"].as_str().unwrap().to_string();

    // Drain the budget with failures, sequentially, so they are finished
    // rather than merely in flight.
    for i in 0..5 {
        let req = json_request(
            "POST",
            "/poll",
            Some(&format!("brt_bogus{i}")),
            json!({ "services": [] }),
        );
        let resp = app.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    let start = std::time::Instant::now();
    let req = json_request("POST", "/poll", Some(&bearer), json!({ "services": [] }));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        elapsed < std::time::Duration::from_millis(150),
        "a good credential must answer at full speed (took {elapsed:?})"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failure_past_the_budget_is_actually_slowed() {
    // The other half — the delay has to exist, or the two tests above
    // would pass against a function that does nothing.
    let mut config = test_config("");
    config.global_auth_failure_max = 0;
    let app = app_with_config(config);

    // First failure: budget already exceeded by the time the delay is
    // consulted, since record_failure runs before it.
    let start = std::time::Instant::now();
    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": "jtk_bogus", "pubkey": pubkey_for("z"), "listen_port": 51830 }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(
        elapsed >= std::time::Duration::from_millis(200),
        "a failure past the budget must be held back (took {elapsed:?})"
    );
}

// ---- join-token expiry ----

#[tokio::test]
async fn an_expired_join_token_is_refused_with_the_same_response_as_an_unknown_one() {
    // The whole point of the expiry check returning Ok(None) rather than
    // its own error: a caller must not be able to probe which of its
    // guesses were ever real tokens. Compared as whole response bodies,
    // not just status codes.
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;

    // Push this token's window into the past.
    {
        let conn = app.state.db.conn.lock().await;
        let past = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        conn.execute(
            "UPDATE nodes SET join_token_expires_at = ?1 WHERE name = 'n1'",
            [past],
        )
        .unwrap();
    }

    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": t1, "pubkey": pubkey_for("n1"), "listen_port": 51820 }),
    );
    let expired_resp = app.router.clone().oneshot(req).await.unwrap();
    let expired_status = expired_resp.status();
    let expired_body = body_json(expired_resp).await;

    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": "jtk_never-existed", "pubkey": pubkey_for("x"), "listen_port": 51820 }),
    );
    let unknown_resp = app.router.clone().oneshot(req).await.unwrap();
    let unknown_status = unknown_resp.status();
    let unknown_body = body_json(unknown_resp).await;

    assert_eq!(expired_status, unknown_status);
    assert_eq!(
        expired_body, unknown_body,
        "an expired token must be indistinguishable from one that never existed"
    );
}

#[tokio::test]
async fn a_join_token_inside_its_window_still_registers() {
    // The other half: the default 30-minute TTL must not break the
    // ordinary create-then-join flow.
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": t1, "pubkey": pubkey_for("n1"), "listen_port": 51820 }),
    );
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn create_node_reports_the_expiry_and_honours_a_ttl_override() {
    let app = test_app();

    let req = json_request("POST", "/admin/nodes", Some(ADMIN), json!({ "name": "n1" }));
    let body = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    let default_expiry = body["join_token_expires_at"]
        .as_str()
        .expect("the default TTL must report an expiry");
    let parsed = chrono::DateTime::parse_from_rfc3339(default_expiry).unwrap();
    let delta = (parsed.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds();
    assert!((1700..=1800).contains(&delta), "expected ~30min, got {delta}s");

    // 0 disables expiry, and is reported by the field being absent rather
    // than by some sentinel date.
    let req = json_request(
        "POST",
        "/admin/nodes",
        Some(ADMIN),
        json!({ "name": "n2", "ttl_secs": 0 }),
    );
    let body = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    assert!(
        body.get("join_token_expires_at").is_none(),
        "ttl_secs=0 must mean no expiry: {body}"
    );

    // And a node created that way still registers.
    let token = body["join_token"].as_str().unwrap().to_string();
    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": token, "pubkey": pubkey_for("n2"), "listen_port": 51821 }),
    );
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn rejoin_mints_a_fresh_window_after_the_old_one_lapsed() {
    // Missing the window has to be recoverable, or a short default TTL
    // would just be a way to brick a node record.
    let app = test_app();
    let _t1 = admin_create_node(&app.router, "n1").await;
    {
        let conn = app.state.db.conn.lock().await;
        let past = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        conn.execute(
            "UPDATE nodes SET join_token_expires_at = ?1 WHERE name = 'n1'",
            [past],
        )
        .unwrap();
    }

    let req = raw_request("POST", "/admin/nodes/n1/rejoin", Some(&format!("Bearer {ADMIN}")));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "a bodiless rejoin must still work — the ttl body is optional"
    );
    let body = body_json(resp).await;
    assert!(body["join_token_expires_at"].as_str().is_some());

    let fresh = body["join_token"].as_str().unwrap().to_string();
    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": fresh, "pubkey": pubkey_for("n1"), "listen_port": 51820 }),
    );
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );
}

// ---- clear-endpoint ----

#[tokio::test]
async fn clear_endpoint_removes_a_stale_endpoint_from_the_directory() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();

    // n1 reports an endpoint, and a second node sees it in the directory.
    let req = json_request(
        "POST",
        "/poll",
        Some(&bearer1),
        json!({ "endpoint_addr": "1.2.3.4:51820", "services": [] }),
    );
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    let t2 = admin_create_node(&app.router, "n2").await;
    let r2 = register_node(&app.router, &t2, "n2", 51821).await;
    let bearer2 = r2["bearer_token"].as_str().unwrap().to_string();
    let req = json_request("POST", "/poll", Some(&bearer2), json!({ "services": [] }));
    let body = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    let n1 = body["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "n1")
        .unwrap()
        .clone();
    assert_eq!(n1["endpoint_addr"], "1.2.3.4:51820");

    // Clear it.
    let req = raw_request("DELETE", "/admin/nodes/n1/endpoint", Some(&format!("Bearer {ADMIN}")));
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    let req = json_request("POST", "/poll", Some(&bearer2), json!({ "services": [] }));
    let body = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    let n1 = body["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "n1")
        .unwrap()
        .clone();
    assert!(
        n1.get("endpoint_addr").is_none(),
        "a cleared endpoint must stop being advertised: {n1}"
    );
}

#[tokio::test]
async fn a_poll_without_an_endpoint_does_not_resurrect_a_cleared_one() {
    // `/poll`'s COALESCE means an omitted endpoint_addr is "no opinion",
    // which is what lets a node registered behind NAT keep the endpoint
    // inferred at register time. It must not also mean "put the old one
    // back" after an admin cleared it.
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();

    let req = json_request(
        "POST",
        "/poll",
        Some(&bearer1),
        json!({ "endpoint_addr": "1.2.3.4:51820", "services": [] }),
    );
    app.router.clone().oneshot(req).await.unwrap();

    let req = raw_request("DELETE", "/admin/nodes/n1/endpoint", Some(&format!("Bearer {ADMIN}")));
    app.router.clone().oneshot(req).await.unwrap();

    // A poll that says nothing about its endpoint.
    let req = json_request("POST", "/poll", Some(&bearer1), json!({ "services": [] }));
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );

    let conn = app.state.db.conn.lock().await;
    let row = wireserve_coordinator::db::nodes::find_by_name(&conn, "n1")
        .unwrap()
        .unwrap();
    assert!(row.endpoint_addr.is_none());
}

#[tokio::test]
async fn a_node_that_still_has_an_endpoint_re_reports_it_after_clearing() {
    // The documented limitation: clearing removes a stale value, it does
    // not stop a node re-asserting one it still has configured locally.
    // Pinned so the limitation is a decision rather than a surprise.
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();

    let req = json_request(
        "POST",
        "/poll",
        Some(&bearer1),
        json!({ "endpoint_addr": "1.2.3.4:51820", "services": [] }),
    );
    app.router.clone().oneshot(req).await.unwrap();

    let req = raw_request("DELETE", "/admin/nodes/n1/endpoint", Some(&format!("Bearer {ADMIN}")));
    app.router.clone().oneshot(req).await.unwrap();

    let req = json_request(
        "POST",
        "/poll",
        Some(&bearer1),
        json!({ "endpoint_addr": "1.2.3.4:51820", "services": [] }),
    );
    app.router.clone().oneshot(req).await.unwrap();

    let conn = app.state.db.conn.lock().await;
    let row = wireserve_coordinator::db::nodes::find_by_name(&conn, "n1")
        .unwrap()
        .unwrap();
    assert_eq!(row.endpoint_addr.as_deref(), Some("1.2.3.4:51820"));
}

#[tokio::test]
async fn poll_self_heals_the_endpoint_as_the_observed_address_changes() {
    // The point of re-deriving the fallback on every poll rather than
    // only at registration: a node with no --endpoint-addr, whose real
    // address changes over time (dynamic WAN IP, no dynamic-DNS name
    // configured), stays reachable without an operator having to notice
    // and force a rejoin.
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();

    // register_node's requests carry the default PEER_IP.
    let conn = app.state.db.conn.lock().await;
    let row = wireserve_coordinator::db::nodes::find_by_name(&conn, "n1")
        .unwrap()
        .unwrap();
    assert_eq!(row.endpoint_addr.as_deref(), Some(format!("{PEER_IP}:51820").as_str()));
    drop(conn);

    // A later poll, with no explicit endpoint_addr, from a different
    // source address.
    let mut req = Request::builder()
        .method("POST")
        .uri("/poll")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer1}"))
        .body(Body::from(json!({ "services": [] }).to_string()))
        .unwrap();
    let new_peer: SocketAddr = "198.51.100.7:22000".parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(new_peer));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let conn = app.state.db.conn.lock().await;
    let row = wireserve_coordinator::db::nodes::find_by_name(&conn, "n1")
        .unwrap()
        .unwrap();
    assert_eq!(
        row.endpoint_addr.as_deref(),
        Some("198.51.100.7:51820"),
        "a poll from a new address should update the auto-detected endpoint, \
         not leave it frozen at whatever was observed during registration"
    );
}

#[tokio::test]
async fn clear_endpoint_is_404_for_an_unknown_node_and_401_without_admin_auth() {
    let app = test_app();
    admin_create_node(&app.router, "n1").await;

    let req = raw_request("DELETE", "/admin/nodes/nope/endpoint", Some(&format!("Bearer {ADMIN}")));
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );

    let req = raw_request("DELETE", "/admin/nodes/n1/endpoint", Some("Bearer wrong-token"));
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    let req = raw_request("DELETE", "/admin/nodes/n1/endpoint", None);
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

// ---- Request body cap ----

#[tokio::test]
async fn an_oversized_request_body_is_refused_before_it_is_parsed() {
    // /register is unauthenticated, so the cheapest request an anonymous
    // caller can send should not be the most expensive one to serve.
    let app = test_app();
    let huge = "a".repeat(wireserve_coordinator::routes::MAX_REQUEST_BODY_BYTES + 1);
    let mut req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "join_token": huge, "pubkey": pubkey_for("x"), "listen_port": 51820 })
                .to_string(),
        ))
        .unwrap();
    let peer: SocketAddr = format!("{PEER_IP}:12345").parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn a_full_size_legitimate_poll_is_still_accepted() {
    // The cap has to sit comfortably above the largest real body, which
    // is a poll declaring the maximum number of services.
    let app = test_app();
    let join = admin_create_node(&app.router, "busy").await;
    let reg = register_node(&app.router, &join, "pk-busy", 51820).await;
    let bearer = reg["bearer_token"].as_str().unwrap();

    let services: Vec<Value> = (0..wireserve_types::MAX_SERVICES_PER_NODE)
        .map(|i| json!({ "name": format!("service-number-{i}"), "port": 1000 + i, "proto": "tcp" }))
        .collect();
    let req = json_request(
        "POST",
        "/poll",
        Some(bearer),
        json!({ "endpoint_addr": "192.0.2.1:51820", "services": services }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---- service addresses and port mappings (PLAN.md M20) ----

async fn poll_with(router: &Router, bearer: &str, services: Value) -> (StatusCode, Value) {
    let req = json_request("POST", "/poll", Some(bearer), json!({ "services": services }));
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

#[tokio::test]
async fn a_mapped_service_gets_its_own_address_in_every_directory() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "owner").await;
    let t2 = admin_create_node(&app.router, "client").await;
    let owner = register_node(&app.router, &t1, "pk1", 51820).await;
    let client = register_node(&app.router, &t2, "pk2", 51821).await;
    let owner_bearer = owner["bearer_token"].as_str().unwrap();

    let web = json!({"name": "web", "port": 5080, "proto": "tcp",
                     "ports": [{"public": 80, "target": 5080, "proto": "tcp"}]});
    let dns = json!({"name": "dns", "port": 53, "proto": "udp",
                     "ports": [{"public": 53, "target": 53, "proto": "udp"},
                               {"public": 8080, "target": 8000, "proto": "tcp"}]});
    let (status, _) = poll_with(&app.router, owner_bearer, json!([web, dns])).await;
    assert_eq!(status, StatusCode::OK);

    let (_, body) = poll_with(&app.router, client["bearer_token"].as_str().unwrap(), json!([])).await;
    let services = body["services"].as_array().unwrap();
    let by_name = |n: &str| services.iter().find(|s| s["name"] == n).unwrap().clone();
    let (web, dns) = (by_name("web"), by_name("dns"));
    // Two nodes hold .1 and .2; the services get the next free addresses.
    assert_eq!(web["vip4"], "100.90.0.3");
    assert_eq!(dns["vip4"], "100.90.0.4");
    assert_eq!(web["ip4"], owner["ip4"], "ip4 stays the owning node's, for older agents");
    assert_eq!(web["ports"], json!([{"public": 80, "target": 5080, "proto": "tcp"}]));
    assert_eq!(dns["ports"].as_array().unwrap().len(), 2);

    // A node registered afterwards doesn't collide with either.
    let t3 = admin_create_node(&app.router, "late").await;
    let late = register_node(&app.router, &t3, "pk3", 51822).await;
    assert_eq!(late["ip4"], "100.90.0.5");
}

#[tokio::test]
async fn an_old_agents_declaration_gets_no_address_and_the_old_wire_shape() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "pk1", 51820).await;
    let (_, body) = poll_with(
        &app.router,
        r1["bearer_token"].as_str().unwrap(),
        json!([{"name": "plex", "port": 32400, "proto": "tcp"}]),
    )
    .await;
    let plex = &body["services"][0];
    assert!(plex.get("vip4").is_none(), "{plex}");
    assert!(plex.get("ports").is_none(), "{plex}");
    assert_eq!(plex["port"], 32400);
}

#[tokio::test]
async fn a_pending_service_tells_only_its_owner_its_address() {
    let mut config = test_config("");
    config.require_service_approval = true;
    let app = app_with_config(config);
    let t1 = admin_create_node(&app.router, "owner").await;
    let t2 = admin_create_node(&app.router, "client").await;
    let owner = register_node(&app.router, &t1, "pk1", 51820).await;
    let client = register_node(&app.router, &t2, "pk2", 51821).await;

    let web = json!([{"name": "web", "port": 5080, "proto": "tcp",
                      "ports": [{"public": 80, "target": 5080, "proto": "tcp"}]}]);
    let (_, body) = poll_with(&app.router, owner["bearer_token"].as_str().unwrap(), web).await;
    assert!(body["services"].as_array().unwrap().is_empty());
    assert_eq!(body["pending_services"][0]["vip4"], "100.90.0.3");

    let (_, body) = poll_with(&app.router, client["bearer_token"].as_str().unwrap(), json!([])).await;
    assert!(!body.to_string().contains("100.90.0.3"), "nobody else learns it before approval: {body}");
}

#[tokio::test]
async fn poll_rejects_a_malformed_port_mapping() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "pk1", 51820).await;
    let bearer = r1["bearer_token"].as_str().unwrap();
    for ports in [
        json!([{"public": 80, "target": 5080, "proto": "tcp"}, {"public": 80, "target": 6080, "proto": "tcp"}]),
        json!([{"public": 0, "target": 5080, "proto": "tcp"}]),
        json!([{"public": 80, "target": 0, "proto": "tcp"}]),
    ] {
        let (status, body) = poll_with(
            &app.router,
            bearer,
            json!([{"name": "web", "port": 5080, "proto": "tcp", "ports": ports}]),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{ports}: {body}");
    }
}
