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

use wireserve_coordinator::{build_state_with_dns, db::Db, routes, AppState, Config};

const PEER_IP: &str = "203.0.113.10";

fn test_config(db_path: &str) -> Config {
    Config {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        admin_listen_addr: "127.0.0.1:0".parse().unwrap(),
        admin_token: "test-admin-token".to_string(),
        db_path: db_path.to_string(),
        net_v4_cidr: "100.90.0.0/24".to_string(),
        net_v6_prefix: "fd00:90::/64".to_string(),
        service_domain: None,
        identity_headers: Default::default(),
        public_url: None,
        oidc: None,
        dns: None,
        acme: wireserve_coordinator::config::acme_from_lookup(|_| None).unwrap(),
        online_threshold_secs: 180,
        relay_port_base: wireserve_types::DEFAULT_RELAY_PORT_BASE,
        rate_limit_max: 1000,
        rate_limit_window_secs: 60,
        trust_proxy_headers: false,
        trusted_proxy: None,
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
        // Off for most tests, which poll far faster than any node does.
        poll_rate_burst: 20,
        poll_rate_per_min: 0,
        reserved_service_names: Vec::new(),
        strip_headers: Vec::new(),
        forwarding_nodes: Vec::new(),
        cross_site_services: Vec::new(),
    }
}

struct TestApp {
    router: Router,
    state: AppState,
    _db_file: tempfile::NamedTempFile,
}

fn app_with_config(config: Config) -> TestApp {
    app_with_dns(config, None)
}

fn app_with_dns(config: Config, dns: Option<std::sync::Arc<dyn wireserve_coordinator::dns::provider::DnsWriter>>) -> TestApp {
    let db_file = tempfile::NamedTempFile::new().unwrap();
    let db_path = db_file.path().to_str().unwrap().to_string();
    let mut config = config;
    config.db_path = db_path.clone();
    let db = Db::open(&db_path).unwrap();
    let state = build_state_with_dns(config, db, dns);
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
    let body = body_raw(response).await;
    // A poll's response is read as a node that holds nothing reads it.
    if body.get("stamp").is_some() {
        whole(body)
    } else {
        body
    }
}

/// The body as it is on the wire.
async fn body_raw(response: axum::response::Response) -> Value {
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
        "node create should succeed"
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
        json!({ "services": [{"name": "plex", "ports": [{"public": 32400, "target": 32400, "proto": "tcp"}]}] }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Read, so that the next whole directory to this node is not refused
    // while this one is still on its way.
    let _ = body_json(resp).await;

    let req = json_request(
        "POST",
        "/poll",
        Some(bearer2),
        json!({ "services": [{"name": "plex", "ports": [{"public": 1, "target": 1, "proto": "tcp"}]}] }),
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
        json!({ "services": [{"name": "plex", "ports": [{"public": 32400, "target": 32400, "proto": "tcp"}]}] }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    let services = body["services"].as_array().unwrap();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0]["ports"][0]["target"], 32400);
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
        json!({ "services": [{"name": "plex", "ports": [{"public": 32400, "target": 32400, "proto": "tcp"}]}] }),
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
            {"name": "good-one", "ports": [{"public": 1, "target": 1, "proto": "tcp"}]},
            {"name": "Bad_Name", "ports": [{"public": 2, "target": 2, "proto": "tcp"}]}
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
        json!({ "services": [{"name": "plex", "ports": [{"public": 32400, "target": 32400, "proto": "tcp"}]}] }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let body = body_json(resp).await;
    assert!(body["services"][0]["online"].as_bool().unwrap());
    // Moves on every poll of every node and nobody reads it from /poll: only
    // the admin listing below carries it.
    assert!(body["peers"][0]["last_handshake"].is_null());

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
        json!({ "services": [{"name": "plex", "ports": [{"public": 32400, "target": 32400, "proto": "tcp"}]}] }),
    );
    app.router.clone().oneshot(req).await.unwrap();

    let req = json_request(
        "POST",
        "/poll",
        Some(bearer2),
        json!({ "services": [{"name": "plex", "ports": [{"public": 1, "target": 1, "proto": "tcp"}]}] }),
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

// PLAN.md M24: `device refresh` for static peers, and the guard that keeps it
// from being aimed at an agent node.

#[tokio::test]
async fn rejoin_of_a_static_node_keeps_its_name_and_address() {
    let app = test_app();
    let req = json_request(
        "POST",
        "/admin/nodes",
        Some(ADMIN),
        json!({ "name": "phone", "kind": "static" }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    let token = body_json(resp).await["join_token"].as_str().unwrap().to_string();

    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": token, "pubkey": pubkey_for("phone"), "kind": "static" }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let first = body_json(resp).await;
    let (ip4, ip6) = (
        first["ip4"].as_str().unwrap().to_string(),
        first["ip6"].as_str().unwrap().to_string(),
    );

    // The refresh: rejoin asserting kind=static, then redeem with a brand
    // new keypair. This is what `device refresh` does.
    let req = json_request(
        "POST",
        "/admin/nodes/phone/rejoin",
        Some(ADMIN),
        json!({ "kind": "static" }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let token2 = body_json(resp).await["join_token"].as_str().unwrap().to_string();

    let req = json_request(
        "POST",
        "/register",
        None,
        json!({ "join_token": token2, "pubkey": pubkey_for("phone-rotated"), "kind": "static" }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let second = body_json(resp).await;

    assert_eq!(second["ip4"].as_str().unwrap(), ip4, "a refresh must not renumber the device");
    assert_eq!(second["ip6"].as_str().unwrap(), ip6);
}

#[tokio::test]
async fn rejoin_refuses_a_kind_mismatch_without_touching_the_node() {
    let app = test_app();
    let t = admin_create_node(&app.router, "homeserver").await;
    register_node(&app.router, &t, "homeserver", 51820).await;

    // `device refresh homeserver` by mistake: the node is an agent.
    let req = json_request(
        "POST",
        "/admin/nodes/homeserver/rejoin",
        Some(ADMIN),
        json!({ "kind": "static" }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // The whole point of checking before `reissue_join_token`: the node must
    // still be registered and visible to every other peer. Catching this at
    // /register instead would already have nulled its pubkey and dropped it
    // out of `list_all_peers`.
    let peers = admin_peers(&app.router).await;
    assert_eq!(
        peers["peers"].as_array().unwrap().len(),
        1,
        "a refused rejoin must leave the node on the mesh: {peers}"
    );
    assert_eq!(peers["peers"][0]["name"].as_str().unwrap(), "homeserver");
}

#[tokio::test]
async fn a_rejoin_without_a_kind_still_works_on_either_kind() {
    // Every caller written before the guard sends no `kind`, including the
    // plain `wireserve-admin node rejoin` command. That must keep working.
    let app = test_app();
    let t = admin_create_node(&app.router, "homeserver").await;
    register_node(&app.router, &t, "homeserver", 51820).await;

    let req = json_request("POST", "/admin/nodes/homeserver/rejoin", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

// F7: spec §4.1/§4.5 both specify 201 for node create and rejoin.

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

    // Never registered (a `device create` that failed halfway).
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
        json!({ "services": [{"name": "svc", "ports": [{"public": 1, "target": 1, "proto": "tcp"}]}] }),
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
        json!({ "services": [{"name": "zero", "ports": [{"public": 0, "target": 0, "proto": "tcp"}]}] }),
    );
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let too_many: Vec<Value> = (0..65)
        .map(|i| json!({"name": format!("svc{i}"), "ports": [{"public": 1000 + i, "target": 1000 + i, "proto": "tcp"}]}))
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
    // token (device create discards it), but the endpoint must not depend
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
    // every node that omitted --endpoint got no endpoint at all, and
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

/// Registers `name` with an `X-Forwarded-For` of `forwarded`, arriving from
/// `peer`, and returns the endpoint the coordinator recorded for it.
async fn endpoint_registered_via(config: Config, name: &str, peer: &str, forwarded: &str) -> Option<String> {
    let app = app_with_config(config);
    let token = admin_create_node(&app.router, name).await;
    let mut req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("content-type", "application/json")
        .header("x-forwarded-for", forwarded)
        .body(Body::from(
            json!({ "join_token": token, "pubkey": pubkey_for(name), "listen_port": 51820 })
                .to_string(),
        ))
        .unwrap();
    let peer: SocketAddr = peer.parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let conn = app.state.db.conn.lock().await;
    wireserve_coordinator::db::nodes::find_by_name(&conn, name).unwrap().unwrap().endpoint_addr
}

#[tokio::test]
async fn a_named_proxy_is_believed_and_nobody_else_is() {
    // PLAN.md M31: with the proxy on another machine the listener is on a
    // LAN address, and anyone on that LAN can reach it directly.
    let mut config = test_config("");
    config.trusted_proxy = Some("10.0.0.9".parse().unwrap());

    assert_eq!(
        endpoint_registered_via(config.clone(), "n1", "10.0.0.9:40000", "203.0.113.7").await.as_deref(),
        Some("203.0.113.7:51820"),
        "the named proxy says where the node really is"
    );
    assert_eq!(
        endpoint_registered_via(config, "n2", "10.0.0.50:40000", "203.0.113.7").await.as_deref(),
        Some("10.0.0.50:51820"),
        "a direct LAN client is taken at its own address, whatever header it sends"
    );
}

#[tokio::test]
async fn a_named_proxy_matches_an_ipv4_peer_seen_on_a_dual_stack_listener() {
    let mut config = test_config("");
    config.trusted_proxy = Some("10.0.0.9".parse().unwrap());
    assert_eq!(
        endpoint_registered_via(config, "n1", "[::ffff:10.0.0.9]:40000", "203.0.113.7").await.as_deref(),
        Some("203.0.113.7:51820")
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
        json!({ "services": [{ "name": name, "ports": [{"public": 32400, "target": 32400, "proto": "tcp"}] }] }),
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
async fn a_change_past_the_approval_leaves_the_directory_and_the_owners_firewall_until_approved() {
    // PLAN.md #315: an approval covers where the service leads. A LAN
    // target added later waits for an admin, and meanwhile the owner is
    // sent no access for it: phones exported while it was approved still
    // route its address to the owner.
    let app = approval_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "n1", 51820).await;
    let bearer1 = r1["bearer_token"].as_str().unwrap().to_string();
    declare(&app.router, &bearer1, "plex").await;
    assert_eq!(admin_post(&app.router, "/admin/nodes/n1/services/plex/approve").await, StatusCode::OK);
    let body = declare(&app.router, &bearer1, "plex").await;
    assert!(body["access"].as_array().unwrap().iter().any(|a| a["name"] == "plex"), "{body}");

    let changed = json!({ "services": [{ "name": "plex", "ports": [
        {"public": 32400, "target": 32400, "proto": "tcp"},
        {"public": 443, "target": 80, "proto": "tcp", "addr": "192.168.178.1"},
    ] }] });
    let poll = |payload: Value| {
        let router = app.router.clone();
        let bearer = bearer1.clone();
        async move { body_json(router.oneshot(json_request("POST", "/poll", Some(&bearer), payload)).await.unwrap()).await }
    };
    let body = poll(changed.clone()).await;
    assert!(body["services"].as_array().unwrap().is_empty(), "out of the directory: {body}");
    assert_eq!(body["pending_services"][0]["name"], "plex", "{body}");
    assert!(body.get("access").and_then(Value::as_array).is_none_or(|a| a.iter().all(|a| a["name"] != "plex")), "{body}");
    let why = body["service_notices"][0]["reason"].as_str().unwrap();
    assert!(why.contains("192.168.178.1"), "{why}");

    let req = raw_request("GET", "/admin/services", Some(&format!("Bearer {ADMIN}")));
    let admin = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(admin["services"][0]["state"], "pending", "{admin}");
    assert_eq!(admin["services"][0]["approved_ports"][0]["target"], 32400, "what was approved: {admin}");

    assert_eq!(admin_post(&app.router, "/admin/nodes/n1/services/plex/approve").await, StatusCode::OK);
    let body = poll(changed).await;
    assert_eq!(body["services"][0]["name"], "plex", "{body}");
    assert!(body["access"].as_array().unwrap().iter().any(|a| a["name"] == "plex"), "{body}");
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
        .map(|i| json!({ "name": format!("svc{i}"), "ports": [{"public": 1000 + i, "target": 1000 + i, "proto": "tcp"}] }))
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
        assert_eq!(
            count,
            i64::try_from(wireserve_types::MAX_UNAPPROVED_SERVICES_PER_NODE).unwrap(),
            "pending rows are real rows and are bounded, well below what one node may declare"
        );
    }

    let too_many: Vec<Value> = (0..65)
        .map(|i| json!({ "name": format!("svc{i}"), "ports": [{"public": 1000 + i, "target": 1000 + i, "proto": "tcp"}] }))
        .collect();
    let req = json_request("POST", "/poll", Some(&bearer1), json!({ "services": too_many }));
    assert_eq!(
        app.router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}

fn many(prefix: &str, n: usize) -> Value {
    Value::Array(
        (0..n)
            .map(|i| json!({ "name": format!("{prefix}{i}"), "ports": [{"public": 1000 + i, "target": 1000 + i, "proto": "tcp"}] }))
            .collect(),
    )
}

async fn admin_vip(app: &TestApp, name: &str) -> Value {
    let (_, listed) = admin_call(&app.router, "GET", "/admin/services", json!(null)).await;
    listed["services"].as_array().unwrap().iter().find(|s| s["name"] == name).map_or(Value::Null, |s| s["vip4"].clone())
}

#[tokio::test]
async fn only_so_many_unapproved_services_are_taken_and_the_rest_are_told_so() {
    let max = wireserve_types::MAX_UNAPPROVED_SERVICES_PER_NODE;
    let app = approval_app();
    let bearer = {
        let t = admin_create_node(&app.router, "n1").await;
        register_node(&app.router, &t, "n1", 51820).await["bearer_token"].as_str().unwrap().to_string()
    };
    let (status, body) = poll_with(&app.router, &bearer, many("svc", max + 4)).await;
    assert_eq!(status, StatusCode::OK, "never a failed poll");
    assert_eq!(body["pending_services"].as_array().unwrap().len(), max, "{body}");
    let notices = body["service_notices"].as_array().unwrap();
    assert_eq!(notices.len(), 4, "{body}");
    assert!(notices[0]["reason"].as_str().unwrap().contains("waiting for approval"), "{body}");

    // Deciding one makes room for one: an approved service no longer counts.
    assert_eq!(admin_post(&app.router, "/admin/nodes/n1/services/svc0/approve").await, StatusCode::OK);
    let (_, body) = poll_with(&app.router, &bearer, many("svc", max + 4)).await;
    assert_eq!(body["pending_services"].as_array().unwrap().len(), max, "one more was taken: {body}");
    assert_eq!(body["service_notices"].as_array().unwrap().len(), 3, "{body}");

    // What is already there is never dropped for being over: the same list again changes nothing.
    let (_, again) = poll_with(&app.router, &bearer, many("svc", max + 4)).await;
    assert_eq!(again["pending_services"].as_array().unwrap().len(), max);
}

#[tokio::test]
async fn reserved_names_and_other_nodes_names_are_not_taken_but_ones_own_and_existing_are() {
    let mut config = test_config("");
    config.reserved_service_names = vec!["www".into()];
    config.service_domain = Some("int.example.com".into());
    config.public_url = Some("https://coord.int.example.com".into());
    let app = app_with_config(config);
    let mut bearers = Vec::new();
    for name in ["minipc", "hetzner"] {
        let t = admin_create_node(&app.router, name).await;
        bearers.push(register_node(&app.router, &t, name, 51820).await["bearer_token"].as_str().unwrap().to_string());
    }
    let ports = json!([{"public": 22, "target": 22, "proto": "tcp"}]);
    let decl = |names: &[&str]| Value::Array(names.iter().map(|n| json!({"name": n, "ports": ports})).collect());

    // A node may have a service called after itself; nobody else may have one called after it.
    let (status, body) = poll_with(&app.router, &bearers[0], decl(&["minipc", "hetzner", "www", "coord", "plex"])).await;
    assert_eq!(status, StatusCode::OK, "never a failed poll: {body}");
    let names: Vec<&str> = body["services"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["minipc", "plex"], "{body}");
    let notices = body["service_notices"].as_array().unwrap();
    assert_eq!(notices.len(), 3, "{body}");
    for (name, why) in [("hetzner", "another node's name"), ("www", "reserved by the operator"), ("coord", "the coordinator's own name")] {
        let n = notices.iter().find(|n| n["name"] == name).unwrap_or_else(|| panic!("{name}: {body}"));
        assert!(n["reason"].as_str().unwrap().contains(why), "{n}");
    }
    let (_, body) = poll_with(&app.router, &bearers[1], decl(&["hetzner"])).await;
    let hetzner = body["services"].as_array().unwrap().iter().find(|s| s["name"] == "hetzner").expect("published");
    assert_eq!(hetzner["node"], "hetzner", "the node itself may: {body}");
    assert!(body.get("service_notices").is_none(), "{body}");

    // A name a node already has is never taken away for being reserved (or another's): it is
    // not the declaration that is new. `www` was there before the operator reserved it.
    {
        let conn = app.state.db.conn.lock().await;
        let id = wireserve_coordinator::db::nodes::find_by_name(&conn, "minipc").unwrap().unwrap().id;
        conn.execute(
            "INSERT INTO services (node_id, name, port, proto, ports, declared_at, approved_at) VALUES (?1, 'www', 22, 'tcp', '[]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [id],
        )
        .unwrap();
    }
    let (status, body) = poll_with(&app.router, &bearers[0], decl(&["minipc", "plex", "www"])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mine: Vec<&str> = body["services"].as_array().unwrap().iter().filter(|s| s["node"] == "minipc").map(|s| s["name"].as_str().unwrap()).collect();
    assert_eq!(mine, ["minipc", "plex", "www"], "{body}");
    assert!(body.get("service_notices").is_none(), "{body}");
}

#[tokio::test]
async fn where_nothing_needs_approval_there_is_no_such_limit() {
    let app = test_app();
    let t = admin_create_node(&app.router, "n1").await;
    let bearer = register_node(&app.router, &t, "n1", 51820).await["bearer_token"].as_str().unwrap().to_string();
    let (_, body) = poll_with(&app.router, &bearer, many("svc", 40)).await;
    assert_eq!(body["services"].as_array().unwrap().len(), 40, "{body}");
    assert!(body.get("service_notices").is_none(), "{body}");
}

#[tokio::test]
async fn a_denied_service_holds_no_address_and_gets_one_if_approved_after_all() {
    let app = approval_app();
    let t = admin_create_node(&app.router, "n1").await;
    let bearer = register_node(&app.router, &t, "n1", 51820).await["bearer_token"].as_str().unwrap().to_string();
    poll_with(&app.router, &bearer, many("s", 2)).await;
    let (a, b) = (admin_vip(&app, "s0").await, admin_vip(&app, "s1").await);
    assert!(a.is_string() && b.is_string(), "a pending one waits with its address: {a} {b}");

    assert_eq!(admin_post(&app.router, "/admin/nodes/n1/services/s0/deny").await, StatusCode::OK);
    assert_eq!(admin_vip(&app, "s0").await, Value::Null, "denied: its address is free");
    poll_with(&app.router, &bearer, many("s", 2)).await;
    assert_eq!(admin_vip(&app, "s0").await, Value::Null, "and re-declaring it does not take one again");

    // The freed address goes to the next service that needs one.
    poll_with(&app.router, &bearer, many("s", 3)).await;
    assert_eq!(admin_vip(&app, "s2").await, a, "the address s0 gave up");

    assert_eq!(admin_post(&app.router, "/admin/nodes/n1/services/s0/approve").await, StatusCode::OK);
    assert!(admin_vip(&app, "s0").await.is_string(), "approved after all: it has an address at once");
}

#[tokio::test]
async fn a_full_address_range_is_said_plainly_and_is_not_a_server_error() {
    let mut config = test_config("");
    config.net_v4_cidr = "100.90.0.0/30".into(); // two usable addresses
    let app = app_with_config(config);
    for name in ["a", "b"] {
        let t = admin_create_node(&app.router, name).await;
        register_node(&app.router, &t, name, 51820).await;
    }
    let t = admin_create_node(&app.router, "c").await;
    let resp = app
        .router
        .clone()
        .oneshot(json_request("POST", "/register", None, json!({"join_token": t, "pubkey": pubkey_for("c"), "listen_port": 51820})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(resp).await;
    assert!(body["error"].as_str().unwrap().contains("address range is full"), "{body}");
}

#[tokio::test]
async fn one_node_cannot_poll_faster_than_its_share_and_the_others_do_not_notice() {
    let mut config = test_config("");
    config.poll_rate_burst = 3;
    config.poll_rate_per_min = 1;
    let app = app_with_config(config);
    let mut bearers = Vec::new();
    for name in ["busy", "quiet"] {
        let t = admin_create_node(&app.router, name).await;
        bearers.push(register_node(&app.router, &t, name, 51820).await["bearer_token"].as_str().unwrap().to_string());
    }
    for _ in 0..3 {
        assert_eq!(poll_with(&app.router, &bearers[0], json!([])).await.0, StatusCode::OK);
    }
    assert_eq!(poll_with(&app.router, &bearers[0], json!([])).await.0, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(poll_with(&app.router, &bearers[1], json!([])).await.0, StatusCode::OK, "another node has its own budget");
}

#[tokio::test]
async fn a_node_whose_polls_used_up_its_allowance_can_still_ask_for_its_reach_and_the_other_way_round() {
    let mut config = test_config("");
    config.poll_rate_burst = 2;
    config.poll_rate_per_min = 1;
    let app = app_with_config(config);
    let t = admin_create_node(&app.router, "n").await;
    let bearer = register_node(&app.router, &t, "n", 51820).await["bearer_token"].as_str().unwrap().to_string();
    let reach = || json_request("GET", "/reach", Some(&bearer), json!({}));

    for _ in 0..2 {
        assert_eq!(poll_with(&app.router, &bearer, json!([])).await.0, StatusCode::OK);
    }
    assert_eq!(poll_with(&app.router, &bearer, json!([])).await.0, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(app.router.clone().oneshot(reach()).await.unwrap().status(), StatusCode::OK, "status is not a poll");

    for _ in 0..wireserve_coordinator::routes::poll::REACH_BURST {
        let _ = app.router.clone().oneshot(reach()).await.unwrap();
    }
    assert_eq!(app.router.clone().oneshot(reach()).await.unwrap().status(), StatusCode::TOO_MANY_REQUESTS);
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
            { "name": "approved-one", "ports": [{"public": 1, "target": 1, "proto": "tcp"}] },
            { "name": "pending-one", "ports": [{"public": 2, "target": 2, "proto": "tcp"}] },
            { "name": "denied-one", "ports": [{"public": 3, "target": 3, "proto": "tcp"}] }
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

    // A first poll reads the whole directory and starts the threads it is
    // built on; it is queueing behind the failures that is timed, not that.
    let req = json_request("POST", "/poll", Some(&bearer), json!({ "services": [] }));
    assert_eq!(app.router.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

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

    // A first poll reads the whole directory and starts the threads it is
    // built on; it is the delay that is timed, not that.
    let req = json_request("POST", "/poll", Some(&bearer), json!({ "services": [] }));
    assert_eq!(app.router.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

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
    // only at registration: a node with no --endpoint, whose real
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
        .map(|i| json!({ "name": format!("service-number-{i}"), "ports": [{"public": 1000 + i, "target": 1000 + i, "proto": "tcp"}] }))
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

/// A poll's response as a node that holds nothing reads it: the whole
/// directory in `peers` and `services` (the shared one with what changed
/// since applied, and each peer's carrier), and no `full` or `delta`.
/// A response that is only a delta is left as it is, with empty arrays.
fn whole(mut body: Value) -> Value {
    let Some(obj) = body.as_object_mut() else { return body };
    if obj.get("full") == Some(&json!(true)) {
        let resp: wireserve_types::PollResponse = serde_json::from_value(Value::Object(obj.clone())).unwrap();
        let mut base = wireserve_types::DirectoryBase::from_full(&resp.peers, &resp.services);
        let via = resp.delta.as_ref().map(|d| d.relay_via.clone()).unwrap_or_default();
        if let Some(d) = &resp.delta {
            base.apply(d);
        }
        obj.insert("peers".into(), serde_json::to_value(base.peers(&via)).unwrap());
        obj.insert("services".into(), serde_json::to_value(base.services()).unwrap());
        obj.remove("delta");
        obj.remove("full");
    }
    for key in ["peers", "services"] {
        obj.entry(key).or_insert_with(|| json!([]));
    }
    body
}

#[tokio::test]
async fn a_mapped_service_gets_its_own_address_in_every_directory() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "owner").await;
    let t2 = admin_create_node(&app.router, "client").await;
    let owner = register_node(&app.router, &t1, "pk1", 51820).await;
    let client = register_node(&app.router, &t2, "pk2", 51821).await;
    let owner_bearer = owner["bearer_token"].as_str().unwrap();

    let web = json!({"name": "web", "ports": [{"public": 80, "target": 5080, "proto": "tcp"}]});
    let dns = json!({"name": "dns", "ports": [{"public": 53, "target": 53, "proto": "udp"},
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
async fn a_pending_service_tells_only_its_owner_its_address() {
    let mut config = test_config("");
    config.require_service_approval = true;
    let app = app_with_config(config);
    let t1 = admin_create_node(&app.router, "owner").await;
    let t2 = admin_create_node(&app.router, "client").await;
    let owner = register_node(&app.router, &t1, "pk1", 51820).await;
    let client = register_node(&app.router, &t2, "pk2", 51821).await;

    let web = json!([{"name": "web", "ports": [{"public": 80, "target": 5080, "proto": "tcp"}]}]);
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
            json!([{"name": "web", "ports": ports}]),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{ports}: {body}");
    }
}

#[tokio::test]
async fn a_target_address_is_stored_shown_to_admins_and_kept_from_the_mesh() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "owner").await;
    let t2 = admin_create_node(&app.router, "client").await;
    let owner = register_node(&app.router, &t1, "pk1", 51820).await;
    let client = register_node(&app.router, &t2, "pk2", 51821).await;
    let router_svc = json!([{"name": "myrouter", "ports": [{"public": 443, "target": 80, "proto": "tcp", "addr": "192.168.178.1"}]}]);
    let (status, body) = poll_with(&app.router, owner["bearer_token"].as_str().unwrap(), router_svc).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, body) = poll_with(&app.router, client["bearer_token"].as_str().unwrap(), json!([])).await;
    let svc = &body["services"][0];
    assert_eq!(svc["ports"], json!([{"public": 443, "target": 80, "proto": "tcp"}]));
    assert!(!body.to_string().contains("192.168.178.1"), "{body}");

    let req = raw_request("GET", "/admin/services", Some(&format!("Bearer {ADMIN}")));
    let body = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(body["services"][0]["ports"][0]["addr"], "192.168.178.1", "{body}");
}

#[tokio::test]
async fn poll_rejects_a_target_address_inside_the_mesh_or_that_cannot_answer() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "pk1", 51820).await;
    let bearer = r1["bearer_token"].as_str().unwrap();
    for addr in ["100.90.0.1", "100.90.0.77", "127.0.0.1", "224.0.0.1", "0.0.0.0"] {
        let ports = json!([{"public": 443, "target": 80, "proto": "tcp", "addr": addr}]);
        let (status, body) = poll_with(
            &app.router,
            bearer,
            json!([{"name": "x", "ports": ports}]),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{addr}: {body}");
    }
}

// ---- Opt-in transit selection (PLAN.md M23) ----

async fn poll_full(router: &Router, bearer: &str, body: Value) -> (StatusCode, Value) {
    let req = json_request("POST", "/poll", Some(bearer), body);
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

/// The response as it is on the wire.
async fn poll_raw(router: &Router, bearer: &str, body: Value) -> (StatusCode, Value) {
    let req = json_request("POST", "/poll", Some(bearer), body);
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_raw(resp).await)
}

/// A poll from a node that can be relayed end to end (PLAN.md M39): a
/// carry port, and the capability. Without them nothing is relayed to or
/// through it — there is no fallback to forwarding in the clear.
fn relay_poll(mut body: Value) -> Value {
    body["capabilities"] = json!(["relay"]);
    body["carry_port"] = json!(50000);
    body
}

/// The carrier the polling node reaches `peer_name` through.
fn carrier_for(body: &Value, peer_name: &str) -> Option<String> {
    body["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == peer_name)
        .and_then(|p| p["relay"]["via"].as_str())
        .map(str::to_string)
}

fn transit_via_for(body: &Value, peer_name: &str) -> Option<String> {
    body["peers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == peer_name)
        .and_then(|p| p["transit_via"].as_str())
        .map(str::to_string)
}

#[tokio::test]
async fn transit_via_is_filled_once_a_capable_node_reports_reaching_both_wanted_peers() {
    let app = test_app();
    let ta = admin_create_node(&app.router, "a").await;
    let tc = admin_create_node(&app.router, "c").await;
    let tb = admin_create_node(&app.router, "b").await;
    let a = register_node(&app.router, &ta, "pk-a", 51820).await;
    let c = register_node(&app.router, &tc, "pk-c", 51821).await;
    let b = register_node(&app.router, &tb, "pk-b", 51822).await;
    let (a_bearer, c_bearer, b_bearer) = (
        a["bearer_token"].as_str().unwrap(),
        c["bearer_token"].as_str().unwrap(),
        b["bearer_token"].as_str().unwrap(),
    );
    let (pk_a, pk_c, pk_b) = (pubkey_for("pk-a"), pubkey_for("pk-c"), pubkey_for("pk-b"));
    assert_eq!(admin_post(&app.router, "/admin/nodes/b/transit/approve").await, StatusCode::OK);
    // C has polled once, so the coordinator knows it can be relayed to.
    poll_full(&app.router, c_bearer, relay_poll(json!({ "services": [] }))).await;

    // A gives up reaching C directly.
    let (status, _) = poll_full(&app.router, a_bearer, relay_poll(json!({ "services": [], "transit_wanted": [pk_c] }))).await;
    assert_eq!(status, StatusCode::OK);

    // B, approved by the admin, opts in and reports it currently,
    // actually reaches both.
    let (status, b_body) = poll_full(
        &app.router,
        b_bearer,
        relay_poll(json!({ "services": [], "transit_capable": true, "transit_reachable": [pk_a, pk_c] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // B's own carrier role this cycle: it discovers it must forward for
    // (a, c) purely from `transit_carrying` — never from a bare
    // `transit_via` on its own peer entries, which stay `None` since B
    // reaches both directly.
    assert!(carrier_for(&b_body, "a").is_none());
    assert!(carrier_for(&b_body, "c").is_none());
    let carrying = b_body["relay_carrying"].as_array().unwrap();
    assert_eq!(carrying.len(), 1);
    let pair: std::collections::HashSet<&str> =
        [carrying[0]["a"].as_str().unwrap(), carrying[0]["c"].as_str().unwrap()].into_iter().collect();
    assert_eq!(pair, [pk_a.as_str(), pk_c.as_str()].into_iter().collect());

    // C's very next poll gets `transit_via = b` for peer a — without C
    // itself ever having reported wanting anything: A's own earlier
    // report was enough, via `either_wants`.
    let (status, c_body) = poll_full(&app.router, c_bearer, relay_poll(json!({ "services": [] }))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(carrier_for(&c_body, "a").as_deref(), Some(pk_b.as_str()));

    // A's next poll gets the same answer for peer c — A must keep
    // resending `transit_wanted` every cycle (same "resend every poll"
    // contract as every other self-reported field, e.g. reflexive_addr)
    // for its own report not to go stale and get wiped by an empty one.
    let (status, a_body) =
        poll_full(&app.router, a_bearer, relay_poll(json!({ "services": [], "transit_wanted": [pk_c] }))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(carrier_for(&a_body, "c").as_deref(), Some(pk_b.as_str()));
}

async fn admin_peers(router: &Router) -> Value {
    let req = raw_request("GET", "/admin/peers", Some(&format!("Bearer {ADMIN}")));
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    body_json(resp).await
}

/// A, B and C registered; A wants transit to C; B offers to carry and
/// claims to reach both. Returns the three bearer tokens.
async fn transit_scenario(app: &TestApp) -> (String, String, String) {
    let ta = admin_create_node(&app.router, "a").await;
    let tc = admin_create_node(&app.router, "c").await;
    let tb = admin_create_node(&app.router, "b").await;
    let bearer = |v: Value| v["bearer_token"].as_str().unwrap().to_string();
    let a = bearer(register_node(&app.router, &ta, "pk-a", 51820).await);
    let c = bearer(register_node(&app.router, &tc, "pk-c", 51821).await);
    let b = bearer(register_node(&app.router, &tb, "pk-b", 51822).await);
    poll_full(&app.router, &c, relay_poll(json!({ "services": [] }))).await;
    let (status, _) =
        poll_full(&app.router, &a, relay_poll(json!({ "services": [], "transit_wanted": [pubkey_for("pk-c")] }))).await;
    assert_eq!(status, StatusCode::OK);
    (a, b, c)
}

fn b_offers_transit() -> Value {
    relay_poll(json!({
        "services": [],
        "transit_capable": true,
        "transit_reachable": [pubkey_for("pk-a"), pubkey_for("pk-c")],
    }))
}

// Security review finding #1: a node's own offer to carry transit, and its
// own claim about which peers it reaches, are unverified — never enough
// to make it the node two others route through.
#[tokio::test]
async fn an_unapproved_node_is_never_chosen_as_a_carrier_however_it_reports() {
    let app = test_app();
    let (_a, b, c) = transit_scenario(&app).await;

    let (status, b_body) = poll_full(&app.router, &b, b_offers_transit()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(b_body.get("relay_carrying").is_none(), "{b_body}");
    assert_eq!(b_body["transit_awaiting_approval"], json!(true), "the node is told why");

    let (_, c_body) = poll_full(&app.router, &c, relay_poll(json!({ "services": [] }))).await;
    assert!(carrier_for(&c_body, "a").is_none(), "nobody is routed through an unapproved node");
}

#[tokio::test]
async fn approving_a_node_lets_it_carry_and_denying_it_stops_selection_at_once() {
    let app = test_app();
    let (_a, b, c) = transit_scenario(&app).await;
    let pk_b = pubkey_for("pk-b");

    assert_eq!(admin_post(&app.router, "/admin/nodes/b/transit/approve").await, StatusCode::OK);
    let (_, b_body) = poll_full(&app.router, &b, b_offers_transit()).await;
    assert!(b_body.get("transit_awaiting_approval").is_none(), "{b_body}");
    assert_eq!(b_body["relay_carrying"].as_array().unwrap().len(), 1);
    let (_, c_body) = poll_full(&app.router, &c, relay_poll(json!({ "services": [] }))).await;
    assert_eq!(carrier_for(&c_body, "a").as_deref(), Some(pk_b.as_str()));
    assert_eq!(admin_peers(&app.router).await["transit_approved"], json!(["b"]));

    // Withdrawn: C's very next poll routes directly again, without B
    // having polled in between to refresh its own report.
    assert_eq!(admin_post(&app.router, "/admin/nodes/b/transit/deny").await, StatusCode::OK);
    let (_, c_body) = poll_full(&app.router, &c, relay_poll(json!({ "services": [] }))).await;
    assert!(carrier_for(&c_body, "a").is_none());
    assert!(admin_peers(&app.router).await.get("transit_approved").is_none());

    let (_, b_body) = poll_full(&app.router, &b, b_offers_transit()).await;
    assert!(b_body.get("relay_carrying").is_none());
    assert_eq!(b_body["transit_awaiting_approval"], json!(true));
}

#[tokio::test]
async fn transit_approval_is_refused_where_it_cannot_mean_anything() {
    let app = test_app();
    assert_eq!(admin_post(&app.router, "/admin/nodes/ghost/transit/approve").await, StatusCode::NOT_FOUND);

    let req = json_request("POST", "/admin/nodes", Some(ADMIN), json!({ "name": "phone", "kind": "static" }));
    assert_eq!(app.router.clone().oneshot(req).await.unwrap().status(), StatusCode::CREATED);
    assert_eq!(admin_post(&app.router, "/admin/nodes/phone/transit/approve").await, StatusCode::BAD_REQUEST);

    let t = admin_create_node(&app.router, "gone").await;
    register_node(&app.router, &t, "pk-gone", 51820).await;
    assert_eq!(admin_post(&app.router, "/admin/nodes/gone/revoke").await, StatusCode::OK);
    assert_eq!(admin_post(&app.router, "/admin/nodes/gone/transit/approve").await, StatusCode::CONFLICT);

    let req = json_request("POST", "/admin/nodes/gone/transit/approve", Some("wrong-token"), json!({}));
    assert_eq!(app.router.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejoin_withdraws_transit_approval_and_the_old_carrier_report() {
    let app = test_app();
    let (_a, b, c) = transit_scenario(&app).await;
    assert_eq!(admin_post(&app.router, "/admin/nodes/b/transit/approve").await, StatusCode::OK);
    poll_full(&app.router, &b, b_offers_transit()).await;

    let req = json_request("POST", "/admin/nodes/b/rejoin", Some(ADMIN), json!({}));
    let body = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    let (_, c_body) = poll_full(&app.router, &c, relay_poll(json!({ "services": [] }))).await;
    assert!(carrier_for(&c_body, "a").is_none(), "the replaced key must stop carrying at once");

    let new_b = register_node(&app.router, body["join_token"].as_str().unwrap(), "pk-b-new", 51822).await;
    let (_, b_body) = poll_full(&app.router, new_b["bearer_token"].as_str().unwrap(), b_offers_transit()).await;
    assert_eq!(b_body["transit_awaiting_approval"], json!(true), "the new identity needs its own approval");
}

// Security review finding #2: rejoin is the path for a key "suspected
// compromised" (spec §4.5), so the old WireGuard key must stop being a
// peer of every other node immediately — not when, or if, the real
// machine re-registers.
#[tokio::test]
async fn rejoin_removes_the_old_key_from_every_other_nodes_directory_at_once() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let t2 = admin_create_node(&app.router, "n2").await;
    register_node(&app.router, &t1, "n1-old", 51820).await;
    let r2 = register_node(&app.router, &t2, "n2", 51821).await;
    let n2_bearer = r2["bearer_token"].as_str().unwrap();
    let old_key = pubkey_for("n1-old");

    let req = json_request("POST", "/admin/nodes/n1/rejoin", Some(ADMIN), json!({}));
    let body = body_json(app.router.clone().oneshot(req).await.unwrap()).await;

    let (_, n2_body) = poll_full(&app.router, n2_bearer, relay_poll(json!({ "services": [] }))).await;
    let pubkeys: Vec<&str> =
        n2_body["peers"].as_array().unwrap().iter().map(|p| p["pubkey"].as_str().unwrap()).collect();
    assert!(!pubkeys.contains(&old_key.as_str()), "old key still handed out: {pubkeys:?}");
    assert!(
        !admin_peers(&app.router).await["peers"].as_array().unwrap().iter().any(|p| p["name"] == "n1"),
        "not a peer at all until it registers again"
    );

    register_node(&app.router, body["join_token"].as_str().unwrap(), "n1-new", 51820).await;
    let (_, n2_body) = poll_full(&app.router, n2_bearer, relay_poll(json!({ "services": [] }))).await;
    let n1 = n2_body["peers"].as_array().unwrap().iter().find(|p| p["name"] == "n1").expect("back under its new key");
    assert_eq!(n1["pubkey"].as_str().unwrap(), pubkey_for("n1-new"));
}

// Security review finding #4: the agent pins the mesh ranges from the
// register response (or, for an older node, its first poll), so both must
// carry them.
#[tokio::test]
async fn register_and_poll_report_the_mesh_ranges() {
    let app = test_app();
    let t = admin_create_node(&app.router, "n1").await;
    let r = register_node(&app.router, &t, "n1", 51820).await;
    let expected = json!({
        "net_v4_cidr": app.state.config.net_v4_cidr,
        "net_v6_prefix": app.state.config.net_v6_prefix,
    });
    assert_eq!(r["mesh"], expected);

    let (_, body) = poll_full(&app.router, r["bearer_token"].as_str().unwrap(), relay_poll(json!({ "services": [] }))).await;
    assert_eq!(body["mesh"], expected);
}

#[tokio::test]
async fn malformed_transit_pubkeys_are_dropped_not_rejected() {
    let app = test_app();
    let t1 = admin_create_node(&app.router, "n1").await;
    let r1 = register_node(&app.router, &t1, "pk1", 51820).await;
    let bearer = r1["bearer_token"].as_str().unwrap();
    let (status, _) = poll_full(
        &app.router,
        bearer,
        relay_poll(json!({
            "services": [],
            "transit_capable": true,
            "transit_reachable": ["not a real pubkey"],
            "transit_wanted": ["also not one"],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "hints, not identity/addressing facts — never a 400 for the whole poll");
}

#[tokio::test]
async fn revoke_removes_a_node_from_transit_consideration() {
    let app = test_app();
    let ta = admin_create_node(&app.router, "a").await;
    let tc = admin_create_node(&app.router, "c").await;
    let tb = admin_create_node(&app.router, "b").await;
    let a = register_node(&app.router, &ta, "pk-a", 51820).await;
    let c = register_node(&app.router, &tc, "pk-c", 51821).await;
    let b = register_node(&app.router, &tb, "pk-b", 51822).await;
    let (a_bearer, b_bearer) = (a["bearer_token"].as_str().unwrap(), b["bearer_token"].as_str().unwrap());
    let (pk_a, pk_c) = (pubkey_for("pk-a"), pubkey_for("pk-c"));
    poll_full(&app.router, c["bearer_token"].as_str().unwrap(), relay_poll(json!({ "services": [] }))).await;
    assert_eq!(admin_post(&app.router, "/admin/nodes/b/transit/approve").await, StatusCode::OK);

    poll_full(&app.router, a_bearer, relay_poll(json!({ "services": [], "transit_wanted": [pk_c] }))).await;
    poll_full(&app.router, b_bearer, relay_poll(json!({ "services": [], "transit_capable": true, "transit_reachable": [pk_a, pk_c] }))).await;

    let (_, a_body) = poll_full(&app.router, a_bearer, relay_poll(json!({ "services": [], "transit_wanted": [pk_c] }))).await;
    assert!(carrier_for(&a_body, "c").is_some(), "relayed before the revoke: {a_body}");

    let revoke = json_request("POST", "/admin/nodes/b/revoke", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(revoke).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (_, a_body) = poll_full(&app.router, a_bearer, relay_poll(json!({ "services": [], "transit_wanted": [pk_c] }))).await;
    assert!(
        carrier_for(&a_body, "c").is_none(),
        "a revoked node's stale report must not linger as a transit candidate: {a_body}"
    );
}

// ---- End-to-end relaying (PLAN.md M39) ----

fn relay_of(body: &Value, peer_name: &str) -> Value {
    body["peers"].as_array().unwrap().iter().find(|p| p["name"] == peer_name).unwrap()["relay"].clone()
}

#[tokio::test]
async fn nothing_is_relayed_to_a_node_that_cannot_be_and_nothing_falls_back_to_forwarding_in_the_clear() {
    let app = test_app();
    let (a, b, c) = transit_scenario(&app).await;
    assert_eq!(admin_post(&app.router, "/admin/nodes/b/transit/approve").await, StatusCode::OK);
    // C polls without the capability: an older agent, or no carry interface.
    poll_full(&app.router, &c, json!({ "services": [] })).await;
    let (_, b_body) = poll_full(&app.router, &b, b_offers_transit()).await;
    assert!(b_body.get("relay_carrying").is_none() && b_body.get("transit_carrying").is_none(), "{b_body}");
    let (_, a_body) = poll_full(&app.router, &a, relay_poll(json!({ "services": [], "transit_wanted": [pubkey_for("pk-c")] }))).await;
    assert!(carrier_for(&a_body, "c").is_none(), "{a_body}");
    assert!(transit_via_for(&a_body, "c").is_none(), "no hop-by-hop transit either: {a_body}");
}

#[tokio::test]
async fn only_a_carrier_that_can_relay_end_to_end_is_chosen() {
    let app = test_app();
    let (a, b, c) = transit_scenario(&app).await;
    let t0 = admin_create_node(&app.router, "aaa").await;
    let old = register_node(&app.router, &t0, "pk-0", 51823).await;
    let old = old["bearer_token"].as_str().unwrap();
    for name in ["b", "aaa"] {
        assert_eq!(admin_post(&app.router, &format!("/admin/nodes/{name}/transit/approve")).await, StatusCode::OK);
    }
    // An older carrier that reaches both but can't relay, and B, which can.
    let mut offer = b_offers_transit();
    offer.as_object_mut().unwrap().remove("capabilities");
    offer.as_object_mut().unwrap().remove("carry_port");
    poll_full(&app.router, old, offer).await;
    poll_full(&app.router, &b, b_offers_transit()).await;
    let (_, c_body) = poll_full(&app.router, &c, relay_poll(json!({ "services": [] }))).await;
    assert_eq!(carrier_for(&c_body, "a").as_deref(), Some(pubkey_for("pk-b").as_str()));
    let (_, a_body) = poll_full(&app.router, &a, relay_poll(json!({ "services": [], "transit_wanted": [pubkey_for("pk-c")] }))).await;
    assert_eq!(carrier_for(&a_body, "c").as_deref(), Some(pubkey_for("pk-b").as_str()));
}

#[tokio::test]
async fn every_node_has_its_own_stable_relay_port_and_its_reported_carry_port() {
    let app = test_app();
    let base = wireserve_types::DEFAULT_RELAY_PORT_BASE;
    let t1 = admin_create_node(&app.router, "n1").await;
    let t2 = admin_create_node(&app.router, "n2").await;
    let t3 = admin_create_node(&app.router, "n3").await;
    let n1 = register_node(&app.router, &t1, "pk1", 51820).await;
    register_node(&app.router, &t2, "pk2", 51821).await;
    register_node(&app.router, &t3, "pk3", 51822).await;
    let n1 = n1["bearer_token"].as_str().unwrap();
    let (_, body) = poll_full(&app.router, n1, relay_poll(json!({ "services": [] }))).await;
    assert_eq!(relay_of(&body, "n1"), json!({"port": base, "carry_port": 50000, "listen_port": 51820}));
    assert_eq!(relay_of(&body, "n2"), json!({"port": base + 1, "listen_port": 51821}), "no carry port before it polls");
    assert_eq!(relay_of(&body, "n3"), json!({"port": base + 2, "listen_port": 51822}));

    // A deleted node's slot is the next one handed out; the rest keep theirs.
    assert_eq!(admin_post(&app.router, "/admin/nodes/n2/revoke").await, StatusCode::OK);
    let req = json_request("DELETE", "/admin/nodes/n2", Some(ADMIN), json!({}));
    assert!(app.router.clone().oneshot(req).await.unwrap().status().is_success());
    let t4 = admin_create_node(&app.router, "n4").await;
    register_node(&app.router, &t4, "pk4", 51823).await;
    let (_, body) = poll_full(&app.router, n1, relay_poll(json!({ "services": [] }))).await;
    assert_eq!(relay_of(&body, "n4")["port"], json!(base + 1));
    assert_eq!(relay_of(&body, "n3")["port"], json!(base + 2));
}

// ---- PLAN.md M40, M41: phones reach every node end to end ----

/// An agent's poll, as one on this version sends it: the relay capability
/// and carry port, whether it is dialable, and a public IPv4 endpoint.
fn phone_era_poll(dialable: bool, endpoint: &str, extra: Value) -> Value {
    let mut body = relay_poll(json!({ "services": [], "dialable_v4": dialable, "endpoint_addr_v4": endpoint }));
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

/// `gw`: approved, `transit on` and `exit on`, dialable at a public address,
/// reaching `minipc`. `minipc`: behind a NAT nothing gets through. `phone`:
/// a registered static peer. Returns the two agents' bearer tokens.
async fn phone_scenario(app: &TestApp) -> (String, String) {
    let bearer = |v: Value| v["bearer_token"].as_str().unwrap().to_string();
    let t = admin_create_node(&app.router, "gw").await;
    let gw = bearer(register_node(&app.router, &t, "gw", 51820).await);
    let t = admin_create_node(&app.router, "minipc").await;
    let minipc = bearer(register_node(&app.router, &t, "minipc", 51820).await);
    let req = json_request("POST", "/admin/nodes", Some(ADMIN), json!({ "name": "phone", "kind": "static" }));
    let pt = body_json(app.router.clone().oneshot(req).await.unwrap()).await["join_token"].as_str().unwrap().to_string();
    let req = json_request("POST", "/register", None, json!({ "join_token": pt, "pubkey": pubkey_for("phone"), "kind": "static" }));
    assert_eq!(app.router.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    assert_eq!(admin_post(&app.router, "/admin/nodes/gw/transit/approve").await, StatusCode::OK);
    poll_full(&app.router, &minipc, phone_era_poll(false, "198.51.100.3:51820", json!({}))).await;
    poll_full(&app.router, &gw, gw_offers()).await;
    (gw, minipc)
}

fn gw_offers() -> Value {
    phone_era_poll(
        true,
        "203.0.113.2:51820",
        json!({ "transit_capable": true, "exit_capable": true, "transit_reachable": [pubkey_for("minipc")] }),
    )
}

async fn admin_get(router: &Router, path: &str) -> Value {
    let req = raw_request("GET", path, Some(&format!("Bearer {ADMIN}")));
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    body_json(resp).await
}

async fn relay_plan(router: &Router, allow_unverified: bool) -> Value {
    let req = json_request("POST", "/admin/relays/plan", Some(ADMIN), json!({ "allow_unverified": allow_unverified }));
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    body_json(resp).await
}

async fn record_export(router: &Router, node: &str, body: Value) -> (StatusCode, Value) {
    let req = json_request("PUT", &format!("/admin/nodes/{node}/export"), Some(ADMIN), body);
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = if status == StatusCode::OK { json!(null) } else { body_json(resp).await };
    (status, body)
}

fn exit_clients(body: &Value) -> Vec<String> {
    body["exit_clients"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

/// What the plan says about `node`'s relay, once `gw` has picked up the
/// port check the plan started and seen its nonce.
async fn plan_with_the_check_answered(app: &TestApp, gw: &str) -> Value {
    let router = app.router.clone();
    let plan = tokio::spawn(async move { relay_plan(&router, false).await });
    let mut checks = Value::Null;
    for _ in 0..40 {
        let (_, body) = poll_full(&app.router, gw, gw_offers()).await;
        if body.get("port_checks").is_some() {
            checks = body["port_checks"].clone();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(checks.is_array(), "the carrier is asked to listen");
    let mut answer = gw_offers();
    answer["port_checks_seen"] = checks;
    poll_full(&app.router, gw, answer).await;
    plan.await.unwrap()
}

#[tokio::test]
async fn a_dialable_node_is_dialled_directly_and_one_that_is_not_is_relayed_through_a_checked_port() {
    let app = test_app();
    let (gw, _minipc) = phone_scenario(&app).await;
    let port = wireserve_types::DEFAULT_RELAY_PORT_BASE + 1;

    let plan = plan_with_the_check_answered(&app, &gw).await;
    assert_eq!(plan["direct"], json!(["gw"]), "{plan}");
    assert_eq!(
        plan["relayed"],
        json!([{ "node": "minipc", "carrier": "gw", "endpoint": format!("203.0.113.2:{port}"), "open": true }]),
        "{plan}"
    );
    assert_eq!(plan["closed"], json!([]), "{plan}");
    assert_eq!(plan["unreachable"], json!([]), "{plan}");

    // Seen open: the next export trusts it without another check.
    let again = relay_plan(&app.router, false).await;
    assert_eq!(again["relayed"][0]["open"], json!(true), "{again}");
    let ports = admin_get(&app.router, "/admin/relay-ports").await;
    assert_eq!(ports["ports"][0]["port"], json!(port), "{ports}");
    assert_eq!(ports["ports"][0]["open"], json!(true), "{ports}");
    assert_eq!(ports["ports"][0]["devices"], json!([]), "no device uses it yet: {ports}");
}

#[tokio::test]
async fn a_node_that_never_said_whether_it_is_dialable_is_relayed_not_guessed_at() {
    // Offline, or an older agent: its last recorded endpoint (here a public
    // one) is no evidence a phone gets through — often it is a home NAT's.
    let app = test_app();
    let (gw, _minipc) = phone_scenario(&app).await;
    let t = admin_create_node(&app.router, "fedora").await;
    let fedora = register_node(&app.router, &t, "fedora", 51820).await["bearer_token"].as_str().unwrap().to_string();
    poll_full(&app.router, &fedora, json!({ "services": [], "endpoint_addr_v4": "198.51.100.3:51820" })).await;
    let plan = plan_with_the_check_answered(&app, &gw).await;
    assert_eq!(plan["direct"], json!(["gw"]), "{plan}");
    let relayed: Vec<&str> = plan["relayed"].as_array().unwrap().iter().map(|r| r["node"].as_str().unwrap()).collect();
    assert!(relayed.contains(&"fedora") && relayed.contains(&"minipc"), "{plan}");
}

#[tokio::test]
async fn nothing_reaches_a_node_no_carrier_qualifies_for_and_the_plan_says_why() {
    let app = test_app();
    let (_gw, _minipc) = phone_scenario(&app).await;
    assert_eq!(admin_post(&app.router, "/admin/nodes/gw/transit/deny").await, StatusCode::OK);
    let plan = relay_plan(&app.router, false).await;
    assert_eq!(plan["relayed"], json!([]), "{plan}");
    assert_eq!(plan["unreachable"][0]["node"], json!("minipc"), "{plan}");
    assert!(plan["unreachable"][0]["reason"].as_str().unwrap().contains("dialable"), "{plan}");
}

#[tokio::test]
async fn an_export_makes_its_carrier_relay_and_its_exit_send_on_and_nobody_else() {
    let app = test_app();
    let (gw, minipc) = phone_scenario(&app).await;
    let (status, body) = record_export(
        &app.router,
        "phone",
        json!({ "exit": "gw", "relays": [{ "node": "minipc", "carrier": "gw" }] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (_, body) = poll_full(&app.router, &gw, gw_offers()).await;
    assert_eq!(body["relay_public"], json!([pubkey_for("minipc")]), "{body}");
    assert_eq!(body["relay_port_base"], json!(wireserve_types::DEFAULT_RELAY_PORT_BASE), "{body}");
    assert_eq!(exit_clients(&body), vec![pubkey_for("phone")], "{body}");
    // The relayed node's own entry says where a phone's session ends.
    let minipc_entry = body["peers"].as_array().unwrap().iter().find(|p| p["name"] == "minipc").unwrap();
    assert_eq!(minipc_entry["relay"]["listen_port"], json!(51820), "{body}");

    let (_, body) = poll_full(&app.router, &minipc, phone_era_poll(false, "198.51.100.3:51820", json!({}))).await;
    assert!(body.get("relay_public").is_none() && exit_clients(&body).is_empty(), "{body}");

    let peers = admin_peers(&app.router).await;
    assert_eq!(peers["exit_devices"], json!(["phone"]), "{peers}");
    assert!(peers.get("stale_devices").is_none(), "{peers}");
    let ports = admin_get(&app.router, "/admin/relay-ports").await;
    assert_eq!(ports["ports"][0]["devices"], json!(["phone"]), "{ports}");
}

#[tokio::test]
async fn an_export_is_refused_where_it_could_not_work() {
    let app = test_app();
    let (gw, _minipc) = phone_scenario(&app).await;
    // The exit's own half of the consent is `exit on`.
    poll_full(&app.router, &gw, phone_era_poll(true, "203.0.113.2:51820", json!({ "transit_capable": true }))).await;
    let (status, body) = record_export(&app.router, "phone", json!({ "exit": "gw" })).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body["error"].as_str().unwrap().contains("exit on"), "{body}");
    // A carrier needs the admin's approval.
    let (status, body) = record_export(&app.router, "phone", json!({ "relays": [{ "node": "gw", "carrier": "minipc" }] })).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    // Only a device has an export, and only agents relay or are relayed to.
    let (status, _) = record_export(&app.router, "gw", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = record_export(&app.router, "phone", json!({ "relays": [{ "node": "phone", "carrier": "gw" }] })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn withdrawing_approval_ends_the_relay_and_the_exit_and_marks_the_device_stale() {
    let app = test_app();
    let (gw, _minipc) = phone_scenario(&app).await;
    let (status, _) = record_export(&app.router, "phone", json!({ "exit": "gw", "relays": [{ "node": "minipc", "carrier": "gw" }] })).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(admin_post(&app.router, "/admin/nodes/gw/transit/deny").await, StatusCode::OK);
    let (_, body) = poll_full(&app.router, &gw, gw_offers()).await;
    assert!(body.get("relay_public").is_none() && exit_clients(&body).is_empty(), "{body}");
    assert_eq!(admin_peers(&app.router).await["stale_devices"], json!(["phone"]));
}

#[tokio::test]
async fn a_device_is_stale_until_exported_and_again_once_a_node_joins_after_it() {
    let app = test_app();
    let (_gw, _minipc) = phone_scenario(&app).await;
    assert_eq!(admin_peers(&app.router).await["stale_devices"], json!(["phone"]), "never exported under this version");
    record_export(&app.router, "phone", json!({})).await;
    assert!(admin_peers(&app.router).await.get("stale_devices").is_none());

    // `created_at` has second resolution; a node created in the same second
    // as the export can't be told apart from one created before it.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let t = admin_create_node(&app.router, "newcomer").await;
    register_node(&app.router, &t, "newcomer", 51820).await;
    assert_eq!(admin_peers(&app.router).await["stale_devices"], json!(["phone"]));
}

#[tokio::test]
async fn a_released_service_address_is_held_for_a_device_until_it_is_exported_again() {
    // PLAN.md #273: the phone's `.conf` still routes the address to minipc.
    let app = test_app();
    let (gw, minipc) = phone_scenario(&app).await;
    let svc = json!([{ "name": "files", "ports": [{ "public": 443, "target": 8443, "proto": "tcp" }] }]);
    poll_full(&app.router, &minipc, phone_era_poll(false, "198.51.100.3:51820", json!({ "services": svc }))).await;
    admin_post(&app.router, "/admin/nodes/minipc/services/files/approve").await;
    let vip = admin_get(&app.router, "/admin/services").await["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "files")
        .unwrap()["vip4"]
        .as_str()
        .unwrap()
        .to_string();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    record_export(&app.router, "phone", json!({})).await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    poll_full(&app.router, &minipc, phone_era_poll(false, "198.51.100.3:51820", json!({}))).await;

    let peers = admin_peers(&app.router).await;
    assert_eq!(peers["held_addresses"], json!({ "phone": [vip] }), "{peers}");
    assert_eq!(peers["stale_devices"], json!(["phone"]));
    // Another node's new service does not get it.
    let other = json!([{ "name": "wiki", "ports": [{ "public": 443, "target": 8080, "proto": "tcp" }] }]);
    poll_full(&app.router, &gw, phone_era_poll(true, "203.0.113.2:51820", json!({ "services": other }))).await;
    admin_post(&app.router, "/admin/nodes/gw/services/wiki/approve").await;
    let services = admin_get(&app.router, "/admin/services").await;
    let wiki = services["services"].as_array().unwrap().iter().find(|s| s["name"] == "wiki").unwrap();
    assert_ne!(wiki["vip4"].as_str().unwrap(), vip, "{services}");

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    record_export(&app.router, "phone", json!({})).await;
    let peers = admin_peers(&app.router).await;
    assert!(peers.get("held_addresses").is_none() && peers.get("stale_devices").is_none(), "{peers}");
}

#[tokio::test]
async fn a_carrier_or_exit_is_not_deleted_while_a_device_relies_on_it() {
    let app = test_app();
    let (_gw, _minipc) = phone_scenario(&app).await;
    record_export(&app.router, "phone", json!({ "relays": [{ "node": "minipc", "carrier": "gw" }] })).await;
    assert_eq!(admin_post(&app.router, "/admin/nodes/gw/revoke").await, StatusCode::OK);
    let req = json_request("DELETE", "/admin/nodes/gw", Some(ADMIN), json!({}));
    let resp = app.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert!(body_json(resp).await["error"].as_str().unwrap().contains("phone"));
}

#[tokio::test]
async fn a_revoked_device_is_no_longer_an_exit_client_nor_relayed() {
    let app = test_app();
    let (gw, _minipc) = phone_scenario(&app).await;
    record_export(&app.router, "phone", json!({ "exit": "gw", "relays": [{ "node": "minipc", "carrier": "gw" }] })).await;
    assert_eq!(admin_post(&app.router, "/admin/nodes/phone/revoke").await, StatusCode::OK);
    let (_, body) = poll_full(&app.router, &gw, gw_offers()).await;
    assert!(exit_clients(&body).is_empty() && body.get("relay_public").is_none(), "{body}");
}

// ---- PLAN.md M36: who can reach what ----

fn named_app() -> TestApp {
    let mut config = test_config("");
    config.service_domain = Some("int.example.com".into());
    app_with_config(config)
}

fn svc(name: &str, public: u16, target: u16) -> Value {
    json!({"name": name, "ports": [{"public": public, "target": target, "proto": "tcp"}]})
}

fn svc_in(name: &str, public: u16, target: u16, group: &str) -> Value {
    json!({"name": name, "ports": [{"public": public, "target": target, "proto": "tcp"}], "group": group})
}

async fn poll_caps(router: &Router, bearer: &str, services: Value, capable: bool) -> Value {
    let caps: Vec<&str> = if capable { vec![wireserve_types::CAP_SIGN_IN] } else { vec![] };
    poll_full(router, bearer, json!({ "services": services, "capabilities": caps })).await.1
}

/// An admin call: its status, and its JSON body if it has one.
async fn admin_call(router: &Router, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(json_request(method, path, Some(ADMIN), body)).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// A gate publishing `auth` on 443, a home node publishing `jellyfin` on
/// 443 and `prom` on 80, and a watcher publishing nothing.
/// Returns (gate, home, watcher) as (bearer, ip4).
async fn access_scenario(app: &TestApp) -> [(String, String); 3] {
    let mut out = Vec::new();
    for name in ["gate", "home", "watcher"] {
        let t = admin_create_node(&app.router, name).await;
        let r = register_node(&app.router, &t, name, 51820).await;
        out.push((r["bearer_token"].as_str().unwrap().to_string(), r["ip4"].as_str().unwrap().to_string()));
    }
    poll_caps(&app.router, &out[0].0, json!([svc("auth", 443, 8080)]), true).await;
    poll_caps(&app.router, &out[1].0, json!([svc("jellyfin", 443, 8096), svc("prom", 80, 9090)]), true).await;
    out.try_into().unwrap()
}

fn directory_entry<'a>(body: &'a Value, name: &str) -> &'a Value {
    body["services"].as_array().unwrap().iter().find(|s| s["name"] == name).unwrap()
}

fn access_entry<'a>(body: &'a Value, name: &str) -> &'a Value {
    body["access"].as_array().and_then(|a| a.iter().find(|s| s["name"] == name)).unwrap_or(&Value::Null)
}

#[tokio::test]
async fn a_fresh_mesh_leaves_every_service_open_and_tells_only_its_owner() {
    let app = named_app();
    let [_, (home, _), (watcher, _)] = access_scenario(&app).await;
    let body = poll_caps(&app.router, &home, json!([svc("jellyfin", 443, 8096), svc("prom", 80, 9090)]), true).await;
    assert_eq!(access_entry(&body, "jellyfin"), &json!({"name": "jellyfin", "open": true}), "{body}");
    assert_eq!(access_entry(&body, "prom")["open"], json!(true));
    let (_, body) = poll_full(&app.router, &watcher, json!({})).await;
    assert!(body.get("access").is_none(), "nobody else's access: {body}");
    assert!(directory_entry(&body, "jellyfin").get("auth").is_none(), "no marks any more: {body}");
}

#[tokio::test]
async fn a_group_closes_a_service_until_something_is_granted() {
    let app = named_app();
    let [_, (home, home_ip), (_, watcher_ip)] = access_scenario(&app).await;
    let services = json!([svc("jellyfin", 443, 8096), svc("prom", 80, 9090)]);

    assert_eq!(admin_call(&app.router, "POST", "/admin/groups", json!({"name": "media"})).await.0, StatusCode::CREATED);
    let (status, body) = admin_call(&app.router, "PUT", "/admin/groups/media/services/jellyfin", json!(null)).await;
    assert_eq!((status, &body["groups"]), (StatusCode::OK, &json!(["media"])));
    let body = poll_caps(&app.router, &home, services.clone(), true).await;
    assert_eq!(access_entry(&body, "jellyfin")["open"], Value::Null, "closed: {body}");
    assert_eq!(access_entry(&body, "jellyfin")["sources"], json!([home_ip]), "its own node only");
    assert_eq!(access_entry(&body, "prom")["open"], json!(true), "the other stays in default");

    // A tag and a grant to it let the watcher in.
    assert_eq!(admin_call(&app.router, "PUT", "/admin/nodes/watcher/tags/tv", json!(null)).await.0, StatusCode::CREATED);
    let grant = json!({"source": "tag:tv", "group": "media"});
    assert_eq!(admin_call(&app.router, "POST", "/admin/grants", grant.clone()).await.0, StatusCode::CREATED);
    let body = poll_caps(&app.router, &home, services.clone(), true).await;
    let mut want = vec![home_ip.clone(), watcher_ip.clone()];
    want.sort_by_key(|ip| ip.parse::<std::net::Ipv4Addr>().unwrap());
    assert_eq!(access_entry(&body, "jellyfin")["sources"], json!(want), "{body}");

    // An identity provider's group is only something to prove at the sign-in.
    admin_call(&app.router, "POST", "/admin/grants", json!({"source": "oidc:family", "group": "media"})).await;
    let body = poll_caps(&app.router, &home, services.clone(), true).await;
    assert_eq!(access_entry(&body, "jellyfin")["sign_in_groups"], json!(["family"]), "{body}");

    let (_, report) = admin_call(&app.router, "GET", "/admin/access/services/jellyfin", json!(null)).await;
    assert_eq!(report["open"], json!(false), "{report}");
    assert_eq!(report["nodes"], json!([{"name": "watcher", "via": ["tag:tv"]}]), "{report}");
    let (_, report) = admin_call(&app.router, "GET", "/admin/access/nodes/watcher", json!(null)).await;
    assert!(report["services"].as_array().unwrap().iter().any(|s| s["name"] == "jellyfin"), "{report}");

    // Taking the grant away closes it again.
    assert_eq!(admin_call(&app.router, "DELETE", "/admin/grants", grant).await.0, StatusCode::OK);
    admin_call(&app.router, "DELETE", "/admin/grants", json!({"source": "oidc:family", "group": "media"})).await;
    let body = poll_caps(&app.router, &home, services, true).await;
    assert_eq!(access_entry(&body, "jellyfin")["sources"], json!([home_ip]));
}

#[tokio::test]
async fn a_group_survives_a_withdraw_and_redeclare() {
    // With approval off a withdrawn and re-declared service is back at
    // once; a group stored on the row would have gone with it, and the
    // service would be back in default, open to everyone.
    let app = named_app();
    let [_, (home, _), _] = access_scenario(&app).await;
    admin_call(&app.router, "POST", "/admin/groups", json!({"name": "media"})).await;
    admin_call(&app.router, "PUT", "/admin/groups/media/services/jellyfin", json!(null)).await;
    poll_caps(&app.router, &home, json!([svc("prom", 80, 9090)]), true).await;
    let body = poll_caps(&app.router, &home, json!([svc("jellyfin", 443, 8096), svc("prom", 80, 9090)]), true).await;
    assert_eq!(access_entry(&body, "jellyfin")["open"], Value::Null, "{body}");
}

#[tokio::test]
async fn a_declaration_names_a_group_once_and_never_an_unknown_one() {
    let app = named_app();
    let [_, (home, _), _] = access_scenario(&app).await;
    let body = poll_caps(&app.router, &home, json!([svc_in("vault", 443, 8200, "infra")]), true).await;
    assert_eq!(body["service_notices"][0]["name"], json!("vault"), "{body}");
    assert!(body["services"].as_array().unwrap().iter().all(|s| s["name"] != "vault"), "not published: {body}");
    assert_eq!(access_entry(&body, "vault"), &Value::Null);

    admin_call(&app.router, "POST", "/admin/groups", json!({"name": "infra"})).await;
    admin_call(&app.router, "POST", "/admin/groups", json!({"name": "media"})).await;
    let body = poll_caps(&app.router, &home, json!([svc_in("vault", 443, 8200, "infra")]), true).await;
    assert!(body.get("service_notices").is_none(), "{body}");
    assert_eq!(access_entry(&body, "vault")["open"], Value::Null, "in infra, not default: {body}");

    // Naming another group later changes nothing, and says so.
    let body = poll_caps(&app.router, &home, json!([svc_in("vault", 443, 8200, "media")]), true).await;
    assert!(body["service_notices"][0]["reason"].as_str().unwrap().contains("infra"), "{body}");
    let (_, listed) = admin_call(&app.router, "GET", "/admin/services", json!(null)).await;
    let vault = listed["services"].as_array().unwrap().iter().find(|s| s["name"] == "vault").unwrap();
    assert_eq!(vault["groups"], json!(["infra"]));
}

#[tokio::test]
async fn groups_in_use_stay_where_they_are() {
    let app = named_app();
    let _ = access_scenario(&app).await;
    admin_call(&app.router, "POST", "/admin/groups", json!({"name": "media"})).await;
    let (status, body) = admin_call(&app.router, "PUT", "/admin/groups/media/services/auth", json!(null)).await;
    assert_eq!(status, StatusCode::OK, "a service called auth is nothing special any more (PLAN.md M48): {body}");
    assert_eq!(admin_call(&app.router, "DELETE", "/admin/groups/default", json!(null)).await.0, StatusCode::BAD_REQUEST);
    admin_call(&app.router, "PUT", "/admin/groups/media/services/jellyfin", json!(null)).await;
    let (status, body) = admin_call(&app.router, "DELETE", "/admin/groups/media", json!(null)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body["error"].as_str().unwrap().contains("jellyfin"), "{body}");
    assert_eq!(admin_call(&app.router, "DELETE", "/admin/groups/nope", json!(null)).await.0, StatusCode::NOT_FOUND);
    let (status, body) = admin_call(&app.router, "POST", "/admin/grants", json!({"source": "tag:x", "group": "nope"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (status, _) = admin_call(&app.router, "POST", "/admin/grants", json!({"source": "oidc:a,b", "group": "media"})).await;
    assert!(status.is_client_error(), "a comma cannot be in a group the provider sends");
    assert_eq!(admin_call(&app.router, "PUT", "/admin/nodes/nobody/tags/tv", json!(null)).await.0, StatusCode::NOT_FOUND);
}

// ---- PLAN.md M38: device owners ----

fn oidc_app() -> TestApp {
    let mut config = test_config("");
    config.service_domain = Some("int.example.com".into());
    config.public_url = Some("http://mesh.test".into());
    // Nothing listens on the discard port: a sign-in cannot start, which is
    // all these tests need of the provider.
    config.oidc = Some(wireserve_coordinator::config::OidcConfig {
        issuer: "http://127.0.0.1:9".into(),
        client_id: "wireserve".into(),
        client_secret: "s3cret".into(),
        scopes: vec!["openid".into()],
        groups_claim: "groups".into(),
        refresh_interval: std::time::Duration::from_secs(900),
        token_key: [7; 32],
        sign_in_key: [9; 32],
        redirect_url: "http://mesh.test/oidc/callback".into(),
    });
    app_with_config(config)
}

async fn own(app: &TestApp, node: &str, sub: &str, groups: &[&str]) {
    let conn = app.state.db.conn.lock().await;
    let n = wireserve_coordinator::db::nodes::find_by_name(&conn, node).unwrap().unwrap();
    wireserve_coordinator::db::owners::set(
        &conn,
        &wireserve_coordinator::db::owners::Owner {
            node_id: n.id,
            sub: sub.into(),
            email: Some(format!("{sub}@example.com")),
            name: None,
            groups: groups.iter().map(|g| (*g).to_string()).collect(),
            refresh_token_enc: "sealed".into(),
            refreshed_at: chrono::Utc::now(),
            stale_since: None,
        },
    )
    .unwrap();
}

async fn get_page(router: &Router, path: &str) -> (StatusCode, String) {
    let req = json_request("GET", path, None, json!(null));
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn only_an_admin_makes_claim_links_and_only_with_an_identity_provider() {
    let app = test_app();
    admin_create_node(&app.router, "phone").await;
    let (status, body) = admin_call(&app.router, "POST", "/admin/nodes/phone/claim", json!(null)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body["error"].as_str().unwrap().contains("setup login"), "{body}");

    let app = oidc_app();
    let req = json_request("POST", "/admin/nodes", Some(ADMIN), json!({ "name": "laptop" }));
    let created = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
    let url = created["claim"]["url"].as_str().expect("node create hands out a claim link");
    assert!(url.starts_with("http://mesh.test/claim/clm_"), "{url}");

    let (status, link) = admin_call(&app.router, "POST", "/admin/nodes/laptop/claim", json!(null)).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(link["url"], created["claim"]["url"], "a fresh one every time");
    assert_eq!(admin_call(&app.router, "POST", "/admin/nodes/nobody/claim", json!(null)).await.0, StatusCode::NOT_FOUND);

    // No node-facing way to make one.
    let (status, _) = get_page(&app.router, "/claim").await;
    assert!(status.is_client_error());
}

#[tokio::test]
async fn a_claim_link_is_checked_before_anything_is_started() {
    let app = oidc_app();
    admin_create_node(&app.router, "laptop").await;
    let (_, link) = admin_call(&app.router, "POST", "/admin/nodes/laptop/claim", json!(null)).await;
    let path = link["url"].as_str().unwrap().trim_start_matches("http://mesh.test").to_string();

    let (status, page) = get_page(&app.router, &format!("/claim/clm_{}", "0".repeat(64))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{page}");
    assert!(page.contains("not valid"));
    let (status, _) = get_page(&app.router, "/claim/nonsense").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A real link gets as far as the identity provider, which is not there.
    let (status, page) = get_page(&app.router, &path).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{page}");
    // And looking did not use it up.
    let (status, _) = get_page(&app.router, &path).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);

    // Revoking the node ends its links.
    admin_call(&app.router, "POST", "/admin/nodes/laptop/revoke", json!(null)).await;
    let (status, _) = get_page(&app.router, &path).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Without a started sign-in, the callback and the confirmation refuse.
    let (status, _) = get_page(&app.router, "/oidc/callback?code=x&state=y").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_owners_groups_count_in_the_grants_until_the_owner_is_cleared() {
    let app = oidc_app();
    let [_, (home, home_ip), (_, watcher_ip)] = access_scenario(&app).await;
    admin_call(&app.router, "POST", "/admin/groups", json!({"name": "media"})).await;
    admin_call(&app.router, "PUT", "/admin/groups/media/services/jellyfin", json!(null)).await;
    admin_call(&app.router, "POST", "/admin/grants", json!({"source": "oidc:family", "group": "media"})).await;
    let services = json!([svc("jellyfin", 443, 8096), svc("prom", 80, 9090)]);

    own(&app, "watcher", "alice", &["family"]).await;
    let body = poll_caps(&app.router, &home, services.clone(), true).await;
    let mut want = vec![home_ip.clone(), watcher_ip.clone()];
    want.sort_by_key(|ip| ip.parse::<std::net::Ipv4Addr>().unwrap());
    assert_eq!(access_entry(&body, "jellyfin")["sources"], json!(want), "the owner's device gets in: {body}");
    let (_, report) = admin_call(&app.router, "GET", "/admin/access/nodes/watcher", json!(null)).await;
    assert_eq!(report["owner"]["sub"], "alice", "{report}");
    assert!(report["principals"].as_array().unwrap().contains(&json!("oidc:family")));

    assert_eq!(admin_call(&app.router, "DELETE", "/admin/nodes/watcher/owner", json!(null)).await.0, StatusCode::OK);
    let body = poll_caps(&app.router, &home, services, true).await;
    assert_eq!(access_entry(&body, "jellyfin")["sources"], json!([home_ip]));
    assert_eq!(admin_call(&app.router, "DELETE", "/admin/nodes/watcher/owner", json!(null)).await.0, StatusCode::NOT_FOUND);
}

// ---- PLAN.md M32: the service names in public DNS ----

mod dns_records {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use wireserve_coordinator::dns::provider::{DnsWriter, WriteFuture};
    use wireserve_coordinator::dns::sync;

    /// Records every call; fails them all while `down` is set.
    #[derive(Default)]
    struct FakeDns {
        calls: Mutex<Vec<String>>,
        down: AtomicBool,
        /// What the zone already holds, by name, as `TYPE value`.
        zone: Mutex<std::collections::HashMap<String, Vec<String>>>,
        /// The names it was asked about.
        looked_up: Mutex<Vec<String>>,
        lookup_fails: AtomicBool,
    }

    impl FakeDns {
        fn take(&self) -> Vec<String> {
            std::mem::take(&mut *self.calls.lock().unwrap())
        }
        fn call(&self, what: String) -> WriteFuture<'_> {
            let down = self.down.load(Ordering::SeqCst);
            self.calls.lock().unwrap().push(what);
            Box::pin(async move { if down { Err("provider down".to_string()) } else { Ok(()) } })
        }
    }

    impl DnsWriter for FakeDns {
        fn existing<'a>(&'a self, fqdn: &'a str) -> wireserve_coordinator::dns::provider::ReadFuture<'a> {
            self.looked_up.lock().unwrap().push(fqdn.to_string());
            let fails = self.lookup_fails.load(Ordering::SeqCst);
            let found = self.zone.lock().unwrap().get(fqdn).cloned().unwrap_or_default();
            Box::pin(async move { if fails { Err("provider unreachable".to_string()) } else { Ok(found) } })
        }
        fn set_a<'a>(&'a self, fqdn: &'a str, addr: std::net::Ipv4Addr) -> WriteFuture<'a> {
            self.call(format!("set {fqdn} {addr}"))
        }
        fn delete_a<'a>(&'a self, fqdn: &'a str) -> WriteFuture<'a> {
            self.call(format!("delete {fqdn}"))
        }
        fn add_txt<'a>(&'a self, fqdn: &'a str, value: &'a str) -> WriteFuture<'a> {
            self.call(format!("add-txt {fqdn} {value}"))
        }
        fn remove_txt<'a>(&'a self, fqdn: &'a str, value: &'a str) -> WriteFuture<'a> {
            self.call(format!("remove-txt {fqdn} {value}"))
        }
    }

    fn app(fake: &Arc<FakeDns>) -> TestApp {
        let mut config = test_config("");
        config.service_domain = Some("int.example.com".into());
        app_with_dns(config, Some(fake.clone() as Arc<dyn DnsWriter>))
    }

    async fn pass(app: &TestApp) -> sync::PassOutcome {
        let dns = app.state.dns.clone().expect("a writer was configured");
        sync::pass(&app.state, &dns, &mut Default::default()).await
    }

    async fn node(app: &TestApp, name: &str) -> String {
        let t = admin_create_node(&app.router, name).await;
        register_node(&app.router, &t, name, 51820).await["bearer_token"].as_str().unwrap().to_string()
    }

    fn vip(body: &Value, name: &str) -> String {
        directory_entry(body, name)["vip4"].as_str().unwrap().to_string()
    }

    async fn admin_dns(app: &TestApp, name: &str) -> Value {
        let req = json_request("GET", "/admin/services", Some(ADMIN), json!({}));
        let listed = body_json(app.router.clone().oneshot(req).await.unwrap()).await;
        listed["services"].as_array().unwrap().iter().find(|s| s["name"] == name).unwrap()["dns"].clone()
    }

    #[tokio::test]
    async fn every_service_gets_the_name_the_hosts_file_gives_it() {
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        let px = node(&app, "px").await;
        let home = node(&app, "home").await;
        poll_with(&app.router, &px, json!([svc("web", 443, 8443)])).await;
        poll_with(&app.router, &home, json!([svc("jellyfin", 443, 8096), svc("prom", 80, 9090)])).await;

        assert!(!pass(&app).await.failed);
        let mut calls = fake.take();
        calls.sort();
        let (_, body) = poll_with(&app.router, &px, json!([svc("web", 443, 8443)])).await;
        assert_eq!(
            calls,
            vec![
                format!("set jellyfin.int.example.com {}", vip(&body, "jellyfin")),
                format!("set prom.int.example.com {}", vip(&body, "prom")),
                format!("set web.int.example.com {}", vip(&body, "web")),
            ],
            "every name at its own service's address"
        );
        assert_eq!(admin_dns(&app, "prom").await, json!({"state": "published"}));

        // A second pass has nothing left to do.
        pass(&app).await;
        assert!(fake.take().is_empty());
    }

    #[tokio::test]
    async fn a_withdrawn_or_revoked_service_leaves_dns() {
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        let home = node(&app, "home").await;
        let other = node(&app, "other").await;
        poll_with(&app.router, &home, json!([svc("prom", 80, 9090), svc("graf", 80, 3000)])).await;
        poll_with(&app.router, &other, json!([svc("git", 80, 3000)])).await;
        pass(&app).await;
        fake.take();

        poll_with(&app.router, &home, json!([svc("prom", 80, 9090)])).await;
        pass(&app).await;
        assert_eq!(fake.take(), vec!["delete graf.int.example.com".to_string()]);

        let req = json_request("POST", "/admin/nodes/other/revoke", Some(ADMIN), json!({}));
        assert_eq!(app.router.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
        pass(&app).await;
        assert_eq!(fake.take(), vec!["delete git.int.example.com".to_string()]);
    }

    #[tokio::test]
    async fn names_the_coordinator_did_not_write_are_never_deleted() {
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        // Nothing declared and nothing recorded: whatever the zone holds is
        // the operator's, and a pass must not touch it.
        pass(&app).await;
        assert!(fake.take().is_empty());
    }

    #[tokio::test]
    async fn a_provider_failure_is_reported_and_retried() {
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        let home = node(&app, "home").await;
        poll_with(&app.router, &home, json!([svc("prom", 80, 9090)])).await;

        fake.down.store(true, Ordering::SeqCst);
        assert!(pass(&app).await.failed);
        fake.take();
        assert_eq!(admin_dns(&app, "prom").await, json!({"state": "error", "error": "provider down"}));

        // Not recorded as written, so the next pass tries again.
        fake.down.store(false, Ordering::SeqCst);
        assert!(!pass(&app).await.failed);
        assert_eq!(fake.take().len(), 1);
        assert_eq!(admin_dns(&app, "prom").await, json!({"state": "published"}));
    }

    #[tokio::test]
    async fn no_provider_means_no_dns_field() {
        let app = named_app();
        let home = node(&app, "home").await;
        poll_with(&app.router, &home, json!([svc("prom", 80, 9090)])).await;
        assert_eq!(admin_dns(&app, "prom").await, Value::Null);
    }

    // ---- PLAN.md M33: terminated on the owner, and its challenges ----

    const DIGEST: &str = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";

    async fn poll_ready(app: &TestApp, bearer: &str, services: Value, ready: &[&str]) -> Value {
        poll_full(&app.router, bearer, json!({ "services": services, "tls_ready": ready })).await.1
    }

    async fn challenge(app: &TestApp, bearer: &str, method: &str, fqdn: &str, value: &str) -> StatusCode {
        let req = json_request(method, "/tls/challenge", Some(bearer), json!({ "fqdn": fqdn, "value": value }));
        app.router.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn a_ready_service_is_terminated_and_its_name_stays_put() {
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        let home = node(&app, "home").await;
        let other = node(&app, "other").await;
        poll_with(&app.router, &other, json!([svc("web", 443, 8443)])).await;
        let body = poll_ready(&app, &home, json!([svc("plex", 443, 32400)]), &[]).await;
        assert!(directory_entry(&body, "plex").get("terminated").is_none(), "{body}");
        pass(&app).await;
        fake.take();

        let body = poll_ready(&app, &home, json!([svc("plex", 443, 32400)]), &["plex", "web"]).await;
        assert_eq!(directory_entry(&body, "plex")["terminated"], json!(true), "{body}");
        assert!(directory_entry(&body, "web").get("terminated").is_none(), "a node vouches only for its own");
        // Its name was at its own address all along: nothing to rewrite.
        pass(&app).await;
        assert!(fake.take().is_empty());

        // A poll that leaves it out stops it at once.
        let body = poll_ready(&app, &home, json!([svc("plex", 443, 32400)]), &[]).await;
        assert!(directory_entry(&body, "plex").get("terminated").is_none(), "{body}");
    }

    #[tokio::test]
    async fn a_restricted_service_terminates_like_any_other() {
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        let home = node(&app, "home").await;
        poll_ready(&app, &home, json!([svc("jellyfin", 443, 8096)]), &[]).await;
        admin_call(&app.router, "POST", "/admin/groups", json!({"name": "media"})).await;
        admin_call(&app.router, "PUT", "/admin/groups/media/services/jellyfin", json!(null)).await;
        let body = poll_ready(&app, &home, json!([svc("jellyfin", 443, 8096)]), &["jellyfin"]).await;
        assert_eq!(directory_entry(&body, "jellyfin")["terminated"], json!(true), "{body}");
        assert_eq!(access_entry(&body, "jellyfin")["open"], Value::Null, "{body}");
    }

    /// One poll that declares `jellyfin` on 443, ready, and says which
    /// devices have connected.
    async fn poll_seen(app: &TestApp, bearer: &str, seen: &[&str]) -> Value {
        poll_full(
            &app.router,
            bearer,
            json!({ "services": [svc("jellyfin", 443, 8096)], "tls_ready": ["jellyfin"], "callers_seen": seen }),
        )
        .await
        .1
    }

    fn address_of(body: &Value, node: &str) -> String {
        body["peers"].as_array().unwrap().iter().find(|p| p["name"] == node).unwrap()["ip4"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn a_terminating_node_learns_who_owns_the_devices_it_lets_in_and_that_have_connected() {
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        let home = node(&app, "home").await;
        let _laptop = node(&app, "laptop").await;
        let _tv = node(&app, "tv").await;
        own(&app, "laptop", "alice", &["family"]).await;
        own(&app, "tv", "bob", &["guests"]).await;
        admin_call(&app.router, "POST", "/admin/groups", json!({"name": "media"})).await;
        admin_call(&app.router, "PUT", "/admin/groups/media/services/jellyfin", json!(null)).await;
        admin_call(&app.router, "POST", "/admin/grants", json!({"source": "oidc:family", "group": "media"})).await;

        // Nothing terminated yet: nobody's identity, whoever connected.
        let body = poll_full(&app.router, &home, json!({ "services": [svc("jellyfin", 443, 8096)], "callers_seen": ["100.90.0.2"] })).await.1;
        assert!(body.get("identities").is_none(), "{body}");
        let (laptop, tv) = (address_of(&body, "laptop"), address_of(&body, "tv"));

        // Terminated, and nobody has connected: nobody's identity either.
        let body = poll_seen(&app, &home, &[]).await;
        assert!(body.get("identities").is_none(), "{body}");

        // The laptop connected: alice, and only her — bob's tv is not let in,
        // and a device never named is not looked for.
        let body = poll_seen(&app, &home, &[&laptop]).await;
        let ids = body["identities"].as_array().expect("identities for a terminating node");
        assert_eq!(ids.len(), 1, "{body}");
        assert_eq!(ids[0]["user"], "alice");
        assert_eq!(ids[0]["groups"], json!(["family"]));

        let body = poll_seen(&app, &home, &[&laptop, &tv, "100.90.0.99"]).await;
        assert_eq!(body["identities"].as_array().unwrap().len(), 1, "the tv is seen but not let in: {body}");
    }

    #[tokio::test]
    async fn an_open_service_does_not_hand_its_node_every_owner() {
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        let home = node(&app, "home").await;
        let _laptop = node(&app, "laptop").await;
        let _tv = node(&app, "tv").await;
        own(&app, "laptop", "alice", &["admins"]).await;
        own(&app, "tv", "bob", &["family"]).await;

        // `jellyfin` is in `default`, which everyone reaches: any device may
        // call, so any owner may be named — once its device has.
        let body = poll_seen(&app, &home, &[]).await;
        assert!(body.get("identities").is_none(), "no owner is told to a node no device has visited: {body}");
        let tv = address_of(&body, "tv");
        let body = poll_seen(&app, &home, &[&tv]).await;
        let ids = body["identities"].as_array().expect("the visiting device's owner");
        assert_eq!((ids.len(), ids[0]["user"].as_str()), (1, Some("bob")), "{body}");
    }

    #[tokio::test]
    async fn a_name_the_zone_already_holds_is_never_overwritten_and_the_rest_carry_on() {
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        let home = node(&app, "home").await;
        fake.zone.lock().unwrap().insert("mail.int.example.com".into(), vec!["A 203.0.113.5".into()]);
        fake.zone.lock().unwrap().insert("wiki.int.example.com".into(), vec!["CNAME wiki.example.net".into()]);
        fake.zone.lock().unwrap().insert("v6.int.example.com".into(), vec!["AAAA 2001:db8::1".into()]);
        poll_with(&app.router, &home, json!([svc("mail", 80, 8080), svc("wiki", 80, 8081), svc("v6", 80, 8082), svc("prom", 80, 9090)])).await;

        let out = pass(&app).await;
        let calls = fake.take();
        assert_eq!(calls.iter().filter(|c| c.starts_with("set ")).count(), 1, "only prom was written: {calls:?}");
        assert!(calls.iter().any(|c| c.starts_with("set prom.int.example.com")));
        assert!(!out.failed, "a name someone else holds is not a provider failure, which would slow every other name");
        for name in ["mail", "wiki", "v6"] {
            let dns = admin_dns(&app, name).await;
            assert_eq!(dns["state"], "error", "{name}: {dns}");
            assert!(dns["error"].as_str().unwrap().contains("not overwriting"), "{dns}");
        }
        assert_eq!(admin_dns(&app, "prom").await, json!({"state": "published"}));

        // It is asked again while it stays taken, and nothing is written; once the zone
        // is clear the name is written.
        pass(&app).await;
        assert!(fake.take().iter().all(|c| !c.starts_with("set ")));
        fake.zone.lock().unwrap().remove("mail.int.example.com");
        pass(&app).await;
        assert!(fake.take().iter().any(|c| c.starts_with("set mail.int.example.com")));
        assert_eq!(admin_dns(&app, "mail").await, json!({"state": "published"}));
    }

    #[tokio::test]
    async fn an_address_of_the_mesh_left_by_an_earlier_run_may_be_written_again_and_a_written_name_is_not_asked_about() {
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        let home = node(&app, "home").await;
        // A previous run wrote it and never recorded it: the zone holds an address of our own range.
        fake.zone.lock().unwrap().insert("prom.int.example.com".into(), vec!["A 100.90.0.99".into()]);
        poll_with(&app.router, &home, json!([svc("prom", 80, 9090)])).await;
        pass(&app).await;
        assert_eq!(admin_dns(&app, "prom").await, json!({"state": "published"}));
        fake.take();
        fake.looked_up.lock().unwrap().clear();

        // Now it is ours: a change is written without asking again, whatever the zone says.
        fake.zone.lock().unwrap().insert("prom.int.example.com".into(), vec!["A 203.0.113.5".into()]);
        poll_with(&app.router, &home, json!([])).await;
        pass(&app).await;
        assert!(fake.looked_up.lock().unwrap().is_empty(), "names already written are not looked up");
    }

    #[tokio::test]
    async fn a_zone_that_cannot_be_read_holds_the_name_back_instead_of_risking_it() {
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        let home = node(&app, "home").await;
        poll_with(&app.router, &home, json!([svc("prom", 80, 9090)])).await;
        fake.lookup_fails.store(true, Ordering::SeqCst);
        let out = pass(&app).await;
        assert!(out.failed, "this one is the provider's fault, and backs off");
        assert!(fake.take().iter().all(|c| !c.starts_with("set ")));
        assert_eq!(admin_dns(&app, "prom").await["state"], "error");
        fake.lookup_fails.store(false, Ordering::SeqCst);
        assert!(!pass(&app).await.failed);
        assert_eq!(admin_dns(&app, "prom").await, json!({"state": "published"}));
    }

    #[tokio::test]
    async fn a_node_cannot_spend_the_dns_providers_allowance_on_challenges() {
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        let home = node(&app, "home").await;
        let other = node(&app, "other").await;
        poll_with(&app.router, &home, json!([svc("plex", 443, 32400)])).await;
        poll_with(&app.router, &other, json!([svc("web", 443, 8443)])).await;

        let burst = wireserve_coordinator::routes::tls::CHALLENGE_BURST as usize;
        for i in 0..burst {
            let value = format!("{i:0>43}");
            assert_eq!(challenge(&app, &home, "POST", "plex.int.example.com", &value).await, StatusCode::CREATED, "{i}");
            // Withdrawing each at once, the way a looping node would, changes nothing.
            assert_eq!(challenge(&app, &home, "DELETE", "plex.int.example.com", &value).await, StatusCode::NO_CONTENT);
        }
        let over = format!("{:0>43}", burst);
        assert_eq!(challenge(&app, &home, "POST", "plex.int.example.com", &over).await, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(fake.take().len(), burst, "the provider was asked exactly the burst's worth, and not for the refused one");

        // Another node's own name has its own budget, and a refused request from
        // one that was never allowed does not spend the first one's.
        assert_eq!(challenge(&app, &other, "POST", "web.int.example.com", DIGEST).await, StatusCode::CREATED);
        assert_eq!(challenge(&app, &other, "POST", "plex.int.example.com", DIGEST).await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn challenges_only_for_a_nodes_own_eligible_names() {
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        let px = node(&app, "px").await;
        let home = node(&app, "home").await;
        poll_with(&app.router, &px, json!([svc("web", 443, 8443)])).await;
        poll_with(&app.router, &home, json!([svc("plex", 443, 32400), svc("prom", 80, 9090)])).await;

        assert_eq!(challenge(&app, &home, "POST", "plex.int.example.com", DIGEST).await, StatusCode::CREATED);
        assert_eq!(fake.take(), vec![format!("add-txt _acme-challenge.plex.int.example.com {DIGEST}")]);
        assert_eq!(challenge(&app, &home, "POST", "plex.int.example.com", DIGEST).await, StatusCode::OK, "idempotent");
        assert!(fake.take().is_empty());

        for (who, fqdn, value, want) in [
            (&px, "plex.int.example.com", DIGEST, StatusCode::FORBIDDEN),   // not its service
            (&home, "prom.int.example.com", DIGEST, StatusCode::FORBIDDEN), // not on 443
            (&home, "plex.other.com", DIGEST, StatusCode::FORBIDDEN),       // not our domain
            (&home, "x.plex.int.example.com", DIGEST, StatusCode::FORBIDDEN),
            (&home, "plex.int.example.com", "not-a-digest", StatusCode::BAD_REQUEST),
        ] {
            assert_eq!(challenge(&app, who, "POST", fqdn, value).await, want, "{fqdn} {value}");
        }
        assert!(fake.take().is_empty(), "nothing refused reached the provider");
        assert_eq!(challenge(&app, "brt_wrong", "POST", "plex.int.example.com", DIGEST).await, StatusCode::UNAUTHORIZED);

        // Withdrawn: the sync loop removes it.
        assert_eq!(challenge(&app, &home, "DELETE", "plex.int.example.com", DIGEST).await, StatusCode::NO_CONTENT);
        pass(&app).await;
        let calls = fake.take();
        assert!(calls.contains(&format!("remove-txt _acme-challenge.plex.int.example.com {DIGEST}")), "{calls:?}");
    }

    #[tokio::test]
    async fn no_challenge_for_a_name_the_zone_holds_for_somebody_else() {
        // PLAN.md #272: the sync leaves such a name alone, and so must the
        // certificate — whether or not the sync has looked yet.
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        let home = node(&app, "home").await;
        fake.zone.lock().unwrap().insert("mail.int.example.com".into(), vec!["A 203.0.113.5".into()]);
        fake.zone.lock().unwrap().insert("wiki.int.example.com".into(), vec!["CNAME wiki.example.net".into()]);
        fake.zone.lock().unwrap().insert("v6.int.example.com".into(), vec!["AAAA 2001:db8::1".into()]);
        fake.zone.lock().unwrap().insert("prom.int.example.com".into(), vec!["A 100.90.0.99".into()]);
        poll_with(
            &app.router,
            &home,
            json!([svc("mail", 443, 8443), svc("wiki", 443, 8080), svc("v6", 443, 8081), svc("prom", 443, 9090), svc("plex", 443, 32400)]),
        )
        .await;
        for fqdn in ["mail.int.example.com", "wiki.int.example.com", "v6.int.example.com"] {
            assert_eq!(challenge(&app, &home, "POST", fqdn, DIGEST).await, StatusCode::FORBIDDEN, "{fqdn}");
        }
        assert!(fake.take().is_empty(), "nothing written for a name that is taken");
        // One of ours from an earlier run, inside the mesh range, and a name
        // with nothing at it.
        assert_eq!(challenge(&app, &home, "POST", "prom.int.example.com", DIGEST).await, StatusCode::CREATED);
        assert_eq!(challenge(&app, &home, "POST", "plex.int.example.com", DIGEST).await, StatusCode::CREATED);
        assert!(fake.looked_up.lock().unwrap().contains(&"plex.int.example.com".to_string()), "asked, not assumed");

        // Asked again for a value already held: refreshed without asking.
        fake.lookup_fails.store(true, Ordering::SeqCst);
        assert_eq!(challenge(&app, &home, "POST", "plex.int.example.com", DIGEST).await, StatusCode::OK);
        // A new value while the provider cannot say: not published.
        let other = DIGEST.replace('A', "B");
        assert_ne!(other, DIGEST);
        fake.take();
        assert_eq!(challenge(&app, &home, "POST", "plex.int.example.com", &other).await, StatusCode::CONFLICT);
        assert!(fake.take().is_empty(), "nothing written on a guess");
    }

    #[tokio::test]
    async fn without_a_provider_there_are_no_challenges() {
        let app = named_app();
        let home = node(&app, "home").await;
        poll_with(&app.router, &home, json!([svc("plex", 443, 32400)])).await;
        assert_eq!(challenge(&app, &home, "POST", "plex.int.example.com", DIGEST).await, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn revoking_forgets_what_a_node_vouched_for() {
        let fake = Arc::new(FakeDns::default());
        let app = app(&fake);
        let home = node(&app, "home").await;
        let watcher = node(&app, "watcher").await;
        poll_ready(&app, &home, json!([svc("plex", 443, 32400)]), &["plex"]).await;
        let req = json_request("POST", "/admin/nodes/home/rejoin", Some(ADMIN), json!({}));
        assert!(app.router.clone().oneshot(req).await.unwrap().status().is_success());
        let (_, body) = poll_full(&app.router, &watcher, json!({})).await;
        assert!(body["services"].as_array().unwrap().iter().all(|s| s.get("terminated").is_none()), "{body}");
    }
}

#[tokio::test]
async fn owner_status_names_the_provider_its_trouble_and_the_people_groups_granted() {
    let app = test_app();
    let (status, body) = admin_call(&app.router, "GET", "/admin/owners", json!(null)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("provider").is_none(), "no provider: {body}");
    assert_eq!(body["owners"], json!([]));

    let app = oidc_app();
    let (status, _) =
        admin_call(&app.router, "POST", "/admin/grants", json!({"source": "oidc:family", "group": "default"})).await;
    assert!(status.is_success());
    let (status, body) = admin_call(&app.router, "GET", "/admin/owners", json!(null)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["provider"]["redirect_url"], "http://mesh.test/oidc/callback");
    assert!(body["provider"]["problem"].as_str().is_some_and(|p| p.contains("discovery")), "nothing listens on :9: {body}");
    assert_eq!(body["granted_groups"], json!(["family"]));

    let req = json_request("GET", "/admin/owners", None, json!(null));
    assert_eq!(app.router.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

// ---- Sending only what changed in the directory (fix 6) ----

fn directory_of(body: &Value) -> wireserve_types::DirectoryBase {
    let resp: wireserve_types::PollResponse = serde_json::from_value(body.clone()).unwrap();
    wireserve_types::DirectoryBase::from_full(&resp.peers, &resp.services)
}

#[tokio::test]
async fn a_poll_that_names_the_directory_it_holds_gets_only_what_changed_since() {
    let app = test_app();
    let (ta, tb, tc) = (
        admin_create_node(&app.router, "a").await,
        admin_create_node(&app.router, "b").await,
        admin_create_node(&app.router, "c").await,
    );
    let a = register_node(&app.router, &ta, "pk-a", 51820).await;
    let b = register_node(&app.router, &tb, "pk-b", 51821).await;
    let (a_bearer, b_bearer) = (a["bearer_token"].as_str().unwrap(), b["bearer_token"].as_str().unwrap());

    // The first poll holds nothing, so it gets everything, and a stamp to hold.
    let (status, first) = poll_full(&app.router, a_bearer, json!({ "services": [] })).await;
    assert_eq!(status, StatusCode::OK);
    assert!(first.get("delta").is_none() && first["peers"].as_array().unwrap().len() == 2, "{first}");
    let mut base = directory_of(&first);
    let stamp = first["stamp"].clone();
    assert_eq!(stamp["digest"].as_u64().unwrap(), base.digest(), "the stamp's digest is the one a node computes");

    // Nothing changed: an empty delta, and the same stamp.
    let (_, same) = poll_full(&app.router, a_bearer, json!({ "services": [], "directory": stamp })).await;
    assert!(same["delta"].is_object() && same["peers"].as_array().unwrap().is_empty(), "{same}");
    assert_eq!(same["stamp"], stamp);

    // B moves and declares a service, a third node joins: one delta for all of it.
    let c = register_node(&app.router, &tc, "pk-c", 51822).await;
    let _ = c;
    let (_, _) = poll_full(
        &app.router,
        b_bearer,
        json!({
            "services": [{"name": "web", "ports": [{"public": 80, "target": 8080, "proto": "tcp"}]}],
            "endpoint_addr": "203.0.113.9:51821",
        }),
    )
    .await;
    let (_, delta) = poll_full(&app.router, a_bearer, json!({ "services": [], "directory": stamp })).await;
    let parsed: wireserve_types::PollResponse = serde_json::from_value(delta.clone()).unwrap();
    assert!(parsed.peers.is_empty() && parsed.services.is_empty(), "{delta}");
    let d = parsed.delta.expect("a delta");
    assert!(d.peers_set.iter().any(|p| p.name == "b" && p.endpoint_addr.as_deref() == Some("203.0.113.9:51821")));
    assert!(d.services_set.iter().any(|s| s.name == "web"));
    base.apply(&d);

    // What the delta leaves a node holding is what a full poll says.
    let (_, full) = poll_full(&app.router, a_bearer, json!({ "services": [] })).await;
    assert_eq!(base.digest(), directory_of(&full).digest());
    assert_eq!(base.digest(), parsed.stamp.unwrap().digest);
    assert_eq!(base.peers(&[]).len(), 3);
}

#[tokio::test]
async fn a_poll_naming_another_coordinators_directory_gets_the_whole_of_this_one() {
    let app = test_app();
    let ta = admin_create_node(&app.router, "a").await;
    let a = register_node(&app.router, &ta, "pk-a", 51820).await;
    let bearer = a["bearer_token"].as_str().unwrap();
    let (_, first) = poll_full(&app.router, bearer, json!({ "services": [] })).await;
    let mut stamp = first["stamp"].clone();
    stamp["epoch"] = json!(stamp["epoch"].as_u64().unwrap() ^ 1);
    let (_, resp) = poll_full(&app.router, bearer, json!({ "services": [], "directory": stamp })).await;
    assert!(resp.get("delta").is_none(), "{resp}");
    assert_eq!(resp["peers"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn only_so_many_whole_directories_are_on_their_way_at_once_and_a_delta_is_not_one() {
    let app = test_app();
    let ta = admin_create_node(&app.router, "a").await;
    let a = register_node(&app.router, &ta, "pk-a", 51820).await;
    let bearer = a["bearer_token"].as_str().unwrap();

    // Every permit taken: a node that holds nothing is told to come back.
    let held = app.state.full_directory_limit.clone().try_acquire_many_owned(u32::try_from(wireserve_coordinator::state::FULL_DIRECTORIES_IN_FLIGHT).unwrap()).unwrap();
    let (status, _) = poll_full(&app.router, bearer, json!({ "services": [] })).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    drop(held);
    let (status, first) = poll_full(&app.router, bearer, json!({ "services": [] })).await;
    assert_eq!(status, StatusCode::OK);
    let stamp = first["stamp"].clone();

    let held = app.state.full_directory_limit.clone().try_acquire_many_owned(u32::try_from(wireserve_coordinator::state::FULL_DIRECTORIES_IN_FLIGHT).unwrap()).unwrap();
    // A node that can be sent a delta is not affected.
    let (status, resp) = poll_full(&app.router, bearer, json!({ "services": [], "directory": stamp })).await;
    assert_eq!(status, StatusCode::OK);
    assert!(resp["peers"].as_array().unwrap().is_empty());
    // One that needs all of it is told to come back, built already or not.
    let (status, _) = poll_full(&app.router, bearer, json!({ "services": [] })).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    drop(held);
}

#[tokio::test]
async fn a_node_is_sent_one_whole_directory_at_a_time_and_told_how_long_it_is() {
    let app = test_app();
    let (ta, tb) = (admin_create_node(&app.router, "a").await, admin_create_node(&app.router, "b").await);
    let a = register_node(&app.router, &ta, "pk-a", 51820).await["bearer_token"].as_str().unwrap().to_string();
    let b = register_node(&app.router, &tb, "pk-b", 51821).await["bearer_token"].as_str().unwrap().to_string();
    let full = |bearer: &str| json_request("POST", "/poll", Some(bearer), json!({ "services": [] }));

    // Not read yet: still on its way.
    let first = app.router.clone().oneshot(full(&a)).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let again = app.router.clone().oneshot(full(&a)).await.unwrap();
    assert_eq!(again.status(), StatusCode::SERVICE_UNAVAILABLE, "a second one to the same node waits for the first");
    let other = app.router.clone().oneshot(full(&b)).await.unwrap();
    assert_eq!(other.status(), StatusCode::OK, "another node is not held up");

    let length: usize = first.headers()[axum::http::header::CONTENT_LENGTH].to_str().unwrap().parse().unwrap();
    let body = axum::body::to_bytes(first.into_body(), usize::MAX).await.unwrap();
    assert_eq!(body.len(), length);
    let stamp = serde_json::from_slice::<Value>(&body).unwrap()["stamp"].clone();
    assert_eq!(app.router.clone().oneshot(full(&a)).await.unwrap().status(), StatusCode::OK, "sent, so the next may go");

    let delta = app.router.clone().oneshot(json_request("POST", "/poll", Some(&a), json!({ "services": [], "directory": stamp }))).await.unwrap();
    let length: usize = delta.headers()[axum::http::header::CONTENT_LENGTH].to_str().unwrap().parse().unwrap();
    assert_eq!(axum::body::to_bytes(delta.into_body(), usize::MAX).await.unwrap().len(), length);
}

#[tokio::test]
async fn a_poll_past_how_many_may_be_in_hand_is_turned_away_before_anything_else() {
    let app = test_app();
    let t = admin_create_node(&app.router, "a").await;
    let bearer = register_node(&app.router, &t, "pk-a", 51820).await["bearer_token"].as_str().unwrap().to_string();
    let all = u32::try_from(wireserve_coordinator::state::POLLS_AT_ONCE).unwrap();
    let held = app.state.polls_at_once.clone().try_acquire_many_owned(all).unwrap();
    assert_eq!(poll_full(&app.router, &bearer, json!({ "services": [] })).await.0, StatusCode::SERVICE_UNAVAILABLE);
    // Not even the credential is looked at.
    assert_eq!(poll_full(&app.router, "brt_bogus", json!({ "services": [] })).await.0, StatusCode::SERVICE_UNAVAILABLE);
    drop(held);
    assert_eq!(poll_full(&app.router, &bearer, json!({ "services": [] })).await.0, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_tokens_waiting_out_their_delay_do_not_hold_the_places_of_polls_in_hand() {
    let mut config = test_config("");
    config.global_auth_failure_max = 0; // every failure is delayed
    let app = app_with_config(config);
    let t = admin_create_node(&app.router, "a").await;
    let bearer = register_node(&app.router, &t, "pk-a", 51820).await["bearer_token"].as_str().unwrap().to_string();
    // All places but one taken, and that one used by a bad token in its delay.
    let all = u32::try_from(wireserve_coordinator::state::POLLS_AT_ONCE).unwrap();
    let held = app.state.polls_at_once.clone().try_acquire_many_owned(all - 1).unwrap();
    let router = app.router.clone();
    let bad = tokio::spawn(async move { poll_full(&router, "brt_bogus", json!({ "services": [] })).await.0 });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(poll_full(&app.router, &bearer, json!({ "services": [] })).await.0, StatusCode::OK);
    assert_eq!(bad.await.unwrap(), StatusCode::UNAUTHORIZED);
    drop(held);
}

/// A poll with a good token whose body never comes.
fn stalled_poll(bearer: &str) -> Request<Body> {
    let body = Body::from_stream(futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>());
    let mut req = Request::builder()
        .method("POST")
        .uri("/poll")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bearer}"))
        .body(body)
        .unwrap();
    let peer: SocketAddr = format!("{PEER_IP}:12345").parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    req
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_sending_its_bodies_slowly_holds_two_places_and_turns_nobody_else_away() {
    let app = test_app();
    let (ta, tb) = (admin_create_node(&app.router, "a").await, admin_create_node(&app.router, "b").await);
    let a = register_node(&app.router, &ta, "pk-a", 51820).await["bearer_token"].as_str().unwrap().to_string();
    let b = register_node(&app.router, &tb, "pk-b", 51821).await["bearer_token"].as_str().unwrap().to_string();
    let stalled: Vec<_> = (0..wireserve_coordinator::routes::poll::POLLS_IN_HAND_PER_NODE)
        .map(|_| tokio::spawn(app.router.clone().oneshot(stalled_poll(&a))))
        .collect();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let places = app.state.polls_at_once.available_permits();
    assert_eq!(places, wireserve_coordinator::state::POLLS_AT_ONCE - wireserve_coordinator::routes::poll::POLLS_IN_HAND_PER_NODE);

    // A's next is refused at once, without holding a place.
    let resp = app.router.clone().oneshot(stalled_poll(&a)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(app.state.polls_at_once.available_permits(), places);
    // B is answered.
    assert_eq!(poll_full(&app.router, &b, json!({ "services": [] })).await.0, StatusCode::OK);

    for s in stalled {
        s.abort();
        let _ = s.await;
    }
    assert_eq!(poll_full(&app.router, &a, json!({ "services": [] })).await.0, StatusCode::OK, "the places came back");
}

#[tokio::test(start_paused = true)]
async fn a_poll_whose_body_does_not_arrive_in_time_is_given_up_on() {
    let app = test_app();
    let t = admin_create_node(&app.router, "a").await;
    let a = register_node(&app.router, &t, "pk-a", 51820).await["bearer_token"].as_str().unwrap().to_string();
    let resp = app.router.clone().oneshot(stalled_poll(&a)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(app.state.polls_at_once.available_permits(), wireserve_coordinator::state::POLLS_AT_ONCE);
    assert!(app.state.polls_in_hand.lock().unwrap().is_empty());
}

#[tokio::test]
async fn pages_anyone_can_open_do_not_make_the_next_poll_read_the_whole_mesh() {
    let app = test_app();
    let (ta, tb, tc) = (
        admin_create_node(&app.router, "a").await,
        admin_create_node(&app.router, "b").await,
        admin_create_node(&app.router, "c").await,
    );
    let a = register_node(&app.router, &ta, "pk-a", 51820).await["bearer_token"].as_str().unwrap().to_string();
    register_node(&app.router, &tb, "pk-b", 51821).await;
    let b_endpoint = |body: &Value| {
        body["peers"].as_array().unwrap().iter().find(|p| p["name"] == "b").unwrap()["endpoint_addr"].clone()
    };
    let (_, first) = poll_full(&app.router, &a, json!({ "services": [] })).await;
    let before = b_endpoint(&first);

    // A write the directory is not told of: only a full read would see it.
    app.state
        .db
        .conn
        .lock()
        .await
        .execute("UPDATE nodes SET endpoint_addr = '198.51.100.7:51821' WHERE name = 'b'", [])
        .unwrap();
    for uri in ["/sign-in", "/claim/nothing", "/oidc/callback"] {
        app.router.clone().oneshot(raw_request("GET", uri, None)).await.unwrap();
    }
    let bad = json_request("POST", "/register", None, json!({ "join_token": "bogus", "pubkey": pubkey_for("x"), "listen_port": 1 }));
    assert_ne!(app.router.clone().oneshot(bad).await.unwrap().status(), StatusCode::OK);
    let (_, after) = poll_full(&app.router, &a, json!({ "services": [] })).await;
    assert_eq!(b_endpoint(&after), before, "not read again for any of them");

    // A registration is a change, and is read.
    register_node(&app.router, &tc, "pk-c", 51822).await;
    let (_, after) = poll_full(&app.router, &a, json!({ "services": [] })).await;
    assert_eq!(b_endpoint(&after), json!("198.51.100.7:51821"));
}

#[tokio::test(flavor = "multi_thread")]
async fn only_so_many_responses_are_built_at_once_and_the_rest_wait_their_turn() {
    let app = test_app();
    let t = admin_create_node(&app.router, "a").await;
    let bearer = register_node(&app.router, &t, "pk-a", 51820).await["bearer_token"].as_str().unwrap().to_string();
    let all = u32::try_from(wireserve_coordinator::state::response_builds()).unwrap();
    let held = app.state.response_builds.clone().try_acquire_many_owned(all).unwrap();

    let router = app.router.clone();
    let mut poll = tokio::spawn(async move { poll_full(&router, &bearer, json!({ "services": [] })).await.0 });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(300), &mut poll).await.is_err(),
        "waits, rather than being refused or built anyway"
    );
    drop(held);
    assert_eq!(poll.await.unwrap(), StatusCode::OK);
}

#[tokio::test]
async fn nodes_that_need_the_whole_directory_are_sent_the_one_serialisation_and_what_changed_since() {
    let app = test_app();
    let (ta, tb, tc) = (
        admin_create_node(&app.router, "a").await,
        admin_create_node(&app.router, "b").await,
        admin_create_node(&app.router, "c").await,
    );
    let a = register_node(&app.router, &ta, "pk-a", 51820).await;
    let b = register_node(&app.router, &tb, "pk-b", 51821).await;
    let (a_bearer, b_bearer) = (a["bearer_token"].as_str().unwrap(), b["bearer_token"].as_str().unwrap());

    let (_, first_a) = poll_raw(&app.router, a_bearer, json!({ "services": [] })).await;
    assert_eq!(first_a["full"], json!(true), "{first_a}");
    assert_eq!(first_a["peers"].as_array().unwrap().len(), 2);

    // A third node joins and B moves; B asks for all of it next.
    let c = register_node(&app.router, &tc, "pk-c", 51822).await;
    let _ = c;
    let (status, moved) = poll_raw(&app.router, b_bearer, json!({ "services": [], "endpoint_addr": "203.0.113.9:51821" })).await;
    assert_eq!(status, StatusCode::OK, "{moved}");
    // (Without it the observed address would take its place again.)
    let (_, first_b) = poll_raw(&app.router, b_bearer, json!({ "services": [], "endpoint_addr": "203.0.113.9:51821" })).await;

    // The arrays are the very ones A was sent, and the delta brings them up to date.
    assert_eq!(first_b["full"], json!(true));
    assert_eq!(first_b["peers"], first_a["peers"], "one serialisation, however much changed since");
    let delta: wireserve_types::DirectoryDelta = serde_json::from_value(first_b["delta"].clone()).unwrap();
    assert!(delta.peers_set.iter().any(|p| p.name == "c"));
    assert!(delta.peers_set.iter().any(|p| p.name == "b" && p.endpoint_addr.as_deref() == Some("203.0.113.9:51821")), "{delta:?}");
    let whole = whole(first_b.clone());
    assert_eq!(whole["peers"].as_array().unwrap().len(), 3);
    assert_eq!(directory_of(&whole).digest(), first_b["stamp"]["digest"].as_u64().unwrap());
}

#[tokio::test]
async fn reach_answers_what_the_asking_node_gets_at_each_service_and_only_to_a_node() {
    let app = test_app();
    let (ta, tb) = (admin_create_node(&app.router, "a").await, admin_create_node(&app.router, "b").await);
    let a = register_node(&app.router, &ta, "pk-a", 51820).await;
    let b = register_node(&app.router, &tb, "pk-b", 51821).await;
    declare(&app.router, a["bearer_token"].as_str().unwrap(), "web").await;

    let b_bearer = b["bearer_token"].as_str().unwrap();
    let resp = app.router.clone().oneshot(json_request("GET", "/reach", Some(b_bearer), json!({}))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["reach"]["web"], "allowed", "{body}");

    // Not carried by the poll any more.
    let (_, polled) = poll_full(&app.router, b_bearer, json!({ "services": [] })).await;
    assert!(polled["services"][0].get("reach").is_none(), "{polled}");

    let resp = app.router.clone().oneshot(json_request("GET", "/reach", None, json!({}))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
