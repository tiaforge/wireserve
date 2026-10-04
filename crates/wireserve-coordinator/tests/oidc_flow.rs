//! A device claimed end to end (PLAN.md M38), and a person signed in to a
//! service (PLAN.md M48), against an identity provider running in this
//! process: discovery, PKCE, the ID token's signature and nonce, the
//! confirmation or the ticket, and refreshing the groups afterwards.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Form, State};
use axum::http::{header, Request, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use openidconnect::core::{
    CoreGenderClaim, CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreResponseType, CoreRsaPrivateSigningKey, CoreSubjectIdentifierType,
};
use openidconnect::{
    AdditionalClaims, Audience, AuthUrl, EmptyAdditionalProviderMetadata, EndUserEmail, IdToken, IdTokenClaims,
    IssuerUrl, JsonWebKeySetUrl, Nonce, PrivateSigningKey, ResponseTypes, StandardClaims, SubjectIdentifier, TokenUrl,
};
use serde::{Deserialize, Serialize};
use tower::ServiceExt;
use wireserve_coordinator::{build_state, db::Db, routes, AppState, Config};

const KEY: &str = include_str!("fixtures/oidc-test-key.pem");

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Groups {
    groups: Vec<String>,
}
impl AdditionalClaims for Groups {}

/// What the provider knows: codes it handed out, and the groups a refresh
/// reports now.
#[derive(Default)]
struct Idp {
    issuer: String,
    /// code -> (nonce, PKCE challenge, sub, groups)
    codes: HashMap<String, (String, String, String, Vec<String>)>,
    groups_now: Vec<String>,
    refuse_refresh: bool,
    /// The email in its tokens is not marked verified (PLAN.md #275).
    unverified_email: bool,
}

type Shared = Arc<Mutex<Idp>>;

fn id_token(issuer: &str, sub: &str, groups: &[String], nonce: Option<&str>, verified: bool) -> String {
    let key = CoreRsaPrivateSigningKey::from_pem(KEY, None).unwrap();
    let now = chrono::Utc::now();
    let mut claims = IdTokenClaims::<Groups, CoreGenderClaim>::new(
        IssuerUrl::new(issuer.into()).unwrap(),
        vec![Audience::new("wireserve".into())],
        now + chrono::Duration::minutes(5),
        now,
        StandardClaims::new(SubjectIdentifier::new(sub.into()))
            .set_email(Some(EndUserEmail::new(format!("{sub}@example.com"))))
            .set_email_verified(Some(verified)),
        Groups { groups: groups.to_vec() },
    );
    if let Some(n) = nonce {
        claims = claims.set_nonce(Some(Nonce::new(n.into())));
    }
    IdToken::<Groups, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>::new(
        claims,
        &key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .unwrap()
    .to_string()
}

async fn discovery(State(idp): State<Shared>) -> impl IntoResponse {
    let issuer = idp.lock().unwrap().issuer.clone();
    let metadata = CoreProviderMetadata::new(
        IssuerUrl::new(issuer.clone()).unwrap(),
        AuthUrl::new(format!("{issuer}/authorize")).unwrap(),
        JsonWebKeySetUrl::new(format!("{issuer}/jwks")).unwrap(),
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Public],
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(TokenUrl::new(format!("{issuer}/token")).unwrap()));
    axum::Json(serde_json::to_value(metadata).unwrap())
}

async fn jwks() -> impl IntoResponse {
    let key = CoreRsaPrivateSigningKey::from_pem(KEY, None).unwrap();
    axum::Json(serde_json::to_value(CoreJsonWebKeySet::new(vec![key.as_verification_key()])).unwrap())
}

async fn token(State(idp): State<Shared>, Form(form): Form<HashMap<String, String>>) -> axum::response::Response {
    use base64::Engine as _;
    use sha2::Digest as _;
    let mut idp = idp.lock().unwrap();
    let issuer = idp.issuer.clone();
    let tokens = |id: String, refresh: &str| {
        axum::Json(serde_json::json!({
            "access_token": "at", "token_type": "Bearer", "expires_in": 300,
            "refresh_token": refresh, "id_token": id,
        }))
        .into_response()
    };
    match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let Some((nonce, challenge, sub, groups)) = form.get("code").and_then(|c| idp.codes.remove(c)) else {
                return (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": "invalid_grant"}))).into_response();
            };
            let verifier = form.get("code_verifier").cloned().unwrap_or_default();
            let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()));
            if digest != challenge {
                return (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": "invalid_grant"}))).into_response();
            }
            tokens(id_token(&issuer, &sub, &groups, Some(&nonce), !idp.unverified_email), "rt-1")
        }
        Some("refresh_token") if idp.refuse_refresh => {
            (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": "invalid_grant"}))).into_response()
        }
        Some("refresh_token") => tokens(id_token(&issuer, "alice", &idp.groups_now, None, !idp.unverified_email), "rt-2"),
        _ => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn start_idp() -> Shared {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let idp: Shared = Arc::new(Mutex::new(Idp { issuer, ..Idp::default() }));
    let app = Router::new()
        .route("/.well-known/openid-configuration", axum::routing::get(discovery))
        .route("/jwks", axum::routing::get(jwks))
        .route("/token", axum::routing::post(token))
        .with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp
}

struct App {
    router: Router,
    state: AppState,
    _db: tempfile::NamedTempFile,
}

fn app(issuer: &str) -> App {
    let db_file = tempfile::NamedTempFile::new().unwrap();
    let config = config(issuer, &db_file);
    let db = Db::open(db_file.path()).unwrap();
    let state = build_state(config, db);
    let router = routes::node_router(state.clone()).merge(routes::admin_router(state.clone()));
    App { router, state, _db: db_file }
}

fn config(issuer: &str, db_file: &tempfile::NamedTempFile) -> Config {
    Config {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        admin_listen_addr: "127.0.0.1:0".parse().unwrap(),
        admin_token: "admin".into(),
        db_path: db_file.path().to_str().unwrap().into(),
        net_v4_cidr: "100.90.0.0/24".into(),
        net_v6_prefix: "fd00:90::/64".into(),
        service_domain: None,
        identity_headers: Default::default(),
        public_url: Some("http://mesh.test".into()),
        oidc: Some(wireserve_coordinator::config::OidcConfig {
            issuer: issuer.into(),
            client_id: "wireserve".into(),
            client_secret: "s3cret".into(),
            scopes: vec!["openid".into(), "groups".into(), "offline_access".into()],
            groups_claim: "groups".into(),
            refresh_interval: std::time::Duration::from_secs(900),
            token_key: [7; 32],
            sign_in_key: [9; 32],
            redirect_url: "http://mesh.test/oidc/callback".into(),
        }),
        dns: None,
        acme: wireserve_coordinator::config::acme_from_lookup(|_| None).unwrap(),
        online_threshold_secs: 180,
        relay_port_base: wireserve_types::DEFAULT_RELAY_PORT_BASE,
        rate_limit_max: 1000,
        rate_limit_window_secs: 60,
        trust_proxy_headers: false,
        trusted_proxy: None,
        join_token_ttl_secs: 1800,
        global_auth_failure_max: u32::MAX,
        global_auth_failure_window_secs: 60,
        require_service_approval: false,
        reflexive_rate_limit_max: 1000,
        reflexive_rate_limit_window_secs: 60,
        poll_rate_burst: 20,
        poll_rate_per_min: 0,
        reserved_service_names: Vec::new(),
        strip_headers: Vec::new(),
        forwarding_nodes: Vec::new(),
        cross_site_services: Vec::new(),
    }
}

async fn call(router: &Router, method: &str, uri: &str, cookie: Option<&str>, form: Option<&str>) -> axum::response::Response {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    if uri.starts_with("/admin") {
        b = b.header(header::AUTHORIZATION, "Bearer admin").header(header::CONTENT_TYPE, "application/json");
    }
    if form.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    let body = match (form, uri.starts_with("/admin/nodes") && method == "POST" && !uri.contains("claim")) {
        (Some(f), _) => Body::from(f.to_string()),
        (None, true) => Body::from(r#"{"name":"laptop"}"#),
        _ => Body::empty(),
    };
    let mut req = b.body(body).unwrap();
    req.extensions_mut().insert(ConnectInfo("203.0.113.10:1234".parse::<SocketAddr>().unwrap()));
    router.clone().oneshot(req).await.unwrap()
}

async fn text(resp: axum::response::Response) -> String {
    String::from_utf8_lossy(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()).into_owned()
}

fn query(url: &str, key: &str) -> String {
    let q = url.split_once('?').unwrap().1;
    q.split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        .map(percent_decode)
        .unwrap_or_else(|| panic!("{key} not in {url}"))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// Starts a claim for `laptop` and plays the provider's part: the browser
/// is sent to sign in, and `sub` does. Returns (cookie, callback path).
async fn signed_in(app: &App, idp: &Shared, sub: &str, groups: &[&str]) -> (String, String) {
    let resp = call(&app.router, "POST", "/admin/nodes/laptop/claim", None, None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let link: serde_json::Value = serde_json::from_str(&text(resp).await).unwrap();
    let path = link["url"].as_str().unwrap().trim_start_matches("http://mesh.test").to_string();

    let resp = call(&app.router, "GET", &path, None, None).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let location = resp.headers()[header::LOCATION].to_str().unwrap().to_string();
    let cookie = resp.headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();
    assert!(location.starts_with(&format!("{}/authorize?", idp.lock().unwrap().issuer)), "{location}");
    assert_eq!(query(&location, "redirect_uri"), "http://mesh.test/oidc/callback");
    assert_eq!(query(&location, "code_challenge_method"), "S256");

    let code = format!("code-{sub}");
    idp.lock().unwrap().codes.insert(
        code.clone(),
        (
            query(&location, "nonce"),
            query(&location, "code_challenge"),
            sub.to_string(),
            groups.iter().map(|g| (*g).to_string()).collect(),
        ),
    );
    (cookie, format!("/oidc/callback?code={code}&state={}", query(&location, "state")))
}

#[tokio::test]
async fn a_device_is_claimed_confirmed_and_its_owners_groups_kept_current() {
    let idp = start_idp().await;
    let issuer = idp.lock().unwrap().issuer.clone();
    let app = app(&issuer);
    call(&app.router, "POST", "/admin/nodes", None, None).await;

    let (cookie, callback) = signed_in(&app, &idp, "alice", &["family"]).await;
    let resp = call(&app.router, "GET", &callback, Some(&cookie), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-frame-options"], "DENY");
    let page = text(resp).await;
    assert!(page.contains("<strong>laptop</strong>") && page.contains("alice@example.com") && page.contains("family"), "{page}");
    let token = page.split("name=\"token\" value=\"").nth(1).unwrap().split('"').next().unwrap().to_string();

    // Not without the browser that started it, nor without its token.
    let resp = call(&app.router, "POST", "/claim/confirm", None, Some(&format!("token={token}"))).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = call(&app.router, "POST", "/claim/confirm", Some(&cookie), Some("token=wrong")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    // Neither spent it: the person's own answer still goes through.
    let resp = call(&app.router, "POST", "/claim/confirm", Some(&cookie), Some(&format!("token={token}"))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(text(resp).await.contains("is yours now"));

    let oidc = app.state.oidc.clone().unwrap();
    let owner = {
        let conn = app.state.db.conn.lock().await;
        let node = wireserve_coordinator::db::nodes::find_by_name(&conn, "laptop").unwrap().unwrap();
        wireserve_coordinator::db::owners::of(&conn, node.id).unwrap().expect("laptop has an owner")
    };
    assert_eq!((owner.sub.as_str(), owner.groups.as_slice()), ("alice", &["family".to_string()][..]));
    assert_eq!(owner.email.as_deref(), Some("alice@example.com"), "verified, so kept");
    assert_eq!(oidc.open(owner.node_id, &owner.refresh_token_enc).as_deref(), Some("rt-1"));
    assert!(!owner.refresh_token_enc.contains("rt-1"), "sealed at rest");

    // Once only.
    let resp = call(&app.router, "POST", "/claim/confirm", Some(&cookie), Some(&format!("token={token}"))).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // The groups follow the provider, and the rotated token is kept.
    idp.lock().unwrap().groups_now = vec!["admins".into()];
    wireserve_coordinator::oidc::refresh::pass(&app.state, &oidc).await;
    let owner = wireserve_coordinator::db::owners::of(&*app.state.db.conn.lock().await, owner.node_id).unwrap().unwrap();
    assert_eq!(owner.groups, ["admins"]);
    assert_eq!(oidc.open(owner.node_id, &owner.refresh_token_enc).as_deref(), Some("rt-2"));

    // A provider refusing the token ends the ownership.
    idp.lock().unwrap().refuse_refresh = true;
    wireserve_coordinator::oidc::refresh::pass(&app.state, &oidc).await;
    assert!(wireserve_coordinator::db::owners::of(&*app.state.db.conn.lock().await, owner.node_id).unwrap().is_none());
}

#[tokio::test]
async fn a_return_that_does_not_match_its_start_is_refused() {
    let idp = start_idp().await;
    let issuer = idp.lock().unwrap().issuer.clone();
    let app = app(&issuer);
    call(&app.router, "POST", "/admin/nodes", None, None).await;

    let (cookie, callback) = signed_in(&app, &idp, "alice", &["family"]).await;
    let forged = callback.split("&state=").next().unwrap().to_string() + "&state=forged";
    assert_eq!(call(&app.router, "GET", &forged, Some(&cookie), None).await.status(), StatusCode::BAD_REQUEST);
    // And that sign-in cannot be finished afterwards either.
    assert_eq!(call(&app.router, "GET", &callback, Some(&cookie), None).await.status(), StatusCode::BAD_REQUEST);

    // Another browser's cookie does not carry someone else's sign-in.
    let (_, callback) = signed_in(&app, &idp, "alice", &["family"]).await;
    let (other_cookie, _) = signed_in(&app, &idp, "mallory", &["family"]).await;
    assert_eq!(call(&app.router, "GET", &callback, Some(&other_cookie), None).await.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn only_an_email_the_provider_verified_is_kept() {
    // PLAN.md #275: the owner's email reaches backends as an identity
    // header; an unverified one is whatever the person typed.
    let idp = start_idp().await;
    let issuer = idp.lock().unwrap().issuer.clone();
    let app = app(&issuer);
    call(&app.router, "POST", "/admin/nodes", None, None).await;
    idp.lock().unwrap().unverified_email = true;

    let (cookie, callback) = signed_in(&app, &idp, "alice", &["family"]).await;
    let page = text(call(&app.router, "GET", &callback, Some(&cookie), None).await).await;
    assert!(!page.contains("alice@example.com"), "not even shown: {page}");
    let token = page.split("name=\"token\" value=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    let resp = call(&app.router, "POST", "/claim/confirm", Some(&cookie), Some(&format!("token={token}"))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let owner = || async {
        let conn = app.state.db.conn.lock().await;
        let node = wireserve_coordinator::db::nodes::find_by_name(&conn, "laptop").unwrap().unwrap();
        wireserve_coordinator::db::owners::of(&conn, node.id).unwrap().expect("laptop has an owner")
    };
    assert_eq!(owner().await.email, None, "claimed, but the email is not kept");

    // Verified later: a refresh brings it.
    let oidc = app.state.oidc.clone().unwrap();
    idp.lock().unwrap().unverified_email = false;
    wireserve_coordinator::oidc::refresh::pass(&app.state, &oidc).await;
    assert_eq!(owner().await.email.as_deref(), Some("alice@example.com"));
    // No longer verified (changed at the provider): a refresh clears it.
    idp.lock().unwrap().unverified_email = true;
    wireserve_coordinator::oidc::refresh::pass(&app.state, &oidc).await;
    assert_eq!(owner().await.email, None);
}

#[tokio::test]
async fn an_issuer_differing_only_in_a_trailing_slash_is_found() {
    // Authentik's issuers end in a slash and Keycloak's do not; whichever
    // way it was typed, the claim reaches the provider's sign-in.
    let idp = start_idp().await;
    let issuer = idp.lock().unwrap().issuer.clone();
    let app = app(&format!("{issuer}/"));
    call(&app.router, "POST", "/admin/nodes", None, None).await;
    let (cookie, callback) = signed_in(&app, &idp, "alice", &["family"]).await;
    let resp = call(&app.router, "GET", &callback, Some(&cookie), None).await;
    assert_eq!(resp.status(), StatusCode::OK, "{}", text(resp).await);
}

// ---- PLAN.md M48: the sign-in ----

/// A DNS provider that takes everything: the sign-in needs DNS records to
/// exist, not to be anywhere.
struct NoDns;

impl wireserve_coordinator::dns::provider::DnsWriter for NoDns {
    fn existing<'a>(&'a self, _: &'a str) -> wireserve_coordinator::dns::provider::ReadFuture<'a> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn set_a<'a>(&'a self, _: &'a str, _: std::net::Ipv4Addr) -> wireserve_coordinator::dns::provider::WriteFuture<'a> {
        Box::pin(async { Ok(()) })
    }
    fn delete_a<'a>(&'a self, _: &'a str) -> wireserve_coordinator::dns::provider::WriteFuture<'a> {
        Box::pin(async { Ok(()) })
    }
    fn add_txt<'a>(&'a self, _: &'a str, _: &'a str) -> wireserve_coordinator::dns::provider::WriteFuture<'a> {
        Box::pin(async { Ok(()) })
    }
    fn remove_txt<'a>(&'a self, _: &'a str, _: &'a str) -> wireserve_coordinator::dns::provider::WriteFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn signing_app(issuer: &str) -> App {
    let db_file = tempfile::NamedTempFile::new().unwrap();
    let mut config = config(issuer, &db_file);
    config.service_domain = Some("int.test".into());
    config.dns = Some(wireserve_coordinator::dns::DnsConfig {
        provider: wireserve_coordinator::dns::config::DnsProvider::Cloudflare { token: "t".into() },
        zone: "int.test".into(),
        ttl: 300,
    });
    let db = Db::open(db_file.path()).unwrap();
    let state = wireserve_coordinator::build_state_with_dns(config, db, Some(Arc::new(NoDns)));
    let router = routes::node_router(state.clone()).merge(routes::admin_router(state.clone()));
    App { router, state, _db: db_file }
}

async fn json(router: &Router, method: &str, uri: &str, bearer: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo("203.0.113.10:1234".parse::<SocketAddr>().unwrap()));
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, serde_json::from_str(&text(resp).await).unwrap_or(serde_json::Value::Null))
}

/// A node joined, its bearer token.
async fn join(app: &App, name: &str) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let (_, created) = json(&app.router, "POST", "/admin/nodes", "admin", serde_json::json!({ "name": name })).await;
    let pubkey = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(name.as_bytes()));
    let body = serde_json::json!({ "join_token": created["join_token"], "pubkey": pubkey, "listen_port": 51820 });
    let (status, joined) = json(&app.router, "POST", "/register", "", body).await;
    assert_eq!(status, StatusCode::OK, "{joined}");
    joined["bearer_token"].as_str().unwrap().to_string()
}

/// `home` serving `grafana` on 443 with TLS, in a group only `oidc:family`
/// is granted. Returns home's and another node's bearer tokens, and the
/// coordinator's public key as nodes are told it.
async fn grafana(app: &App) -> (String, String, wireserve_types::session::VerifyingKey) {
    let home = join(app, "home").await;
    let other = join(app, "other").await;
    let poll = serde_json::json!({
        "services": [{"name": "grafana", "ports": [{"public": 443, "target": 3000, "proto": "tcp"}]}],
        "tls_ready": ["grafana"],
        "capabilities": [wireserve_types::CAP_SIGN_IN],
    });
    json(&app.router, "POST", "/poll", &home, poll.clone()).await;
    json(&app.router, "POST", "/admin/groups", "admin", serde_json::json!({"name": "ops"})).await;
    json(&app.router, "PUT", "/admin/groups/ops/services/grafana", "admin", serde_json::Value::Null).await;
    json(&app.router, "POST", "/admin/grants", "admin", serde_json::json!({"source": "oidc:family", "group": "ops"})).await;
    let (_, body) = json(&app.router, "POST", "/poll", &home, poll).await;
    let access = body["access"].as_array().unwrap().iter().find(|a| a["name"] == "grafana").unwrap().clone();
    assert_eq!((&access["sign_in"], &access["sign_in_groups"]), (&serde_json::json!(true), &serde_json::json!(["family"])), "{body}");
    let si = &body["naming"]["sign_in"];
    assert_eq!(si["login_url"], "http://mesh.test", "{body}");
    let key = wireserve_types::session::parse_public_key(si["public_key"].as_str().unwrap()).unwrap();
    (home, other, key)
}

/// A browser sent to sign in to grafana, signing in at the provider as
/// `sub`: the coordinator's last answer, and the cookies it set.
/// The hash of the browser's bind cookie, as its terminator passes it on.
const BIND: &str = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";

async fn sign_in_as(app: &App, idp: &Shared, sub: &str, groups: &[&str]) -> (axum::response::Response, Vec<String>) {
    let resp = call(&app.router, "GET", &format!("/sign-in?service=grafana.int.test&to=%2Fd%3Fx%3D1&bind={BIND}"), None, None).await;
    assert_eq!(resp.status(), StatusCode::FOUND, "{}", text(resp).await);
    let location = resp.headers()[header::LOCATION].to_str().unwrap().to_string();
    let flow = resp.headers()[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_string();
    assert_eq!(query(&location, "redirect_uri"), "http://mesh.test/oidc/callback", "the one callback, shared with claims");
    let code = format!("code-{sub}-{}", groups.join("-"));
    let entry = (query(&location, "nonce"), query(&location, "code_challenge"), sub.to_string(), groups.iter().map(|g| (*g).to_string()).collect());
    idp.lock().unwrap().codes.insert(code.clone(), entry);
    let callback = format!("/oidc/callback?code={code}&state={}", query(&location, "state"));
    let resp = call(&app.router, "GET", &callback, Some(&flow), None).await;
    let cookies = resp.headers().get_all(header::SET_COOKIE).iter().map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string()).collect();
    (resp, cookies)
}

fn ticket_of(resp: &axum::response::Response) -> String {
    let location = resp.headers()[header::LOCATION].to_str().unwrap();
    assert!(location.starts_with("https://grafana.int.test/.wireserve/callback?ticket="), "{location}");
    query(location, "ticket")
}

#[tokio::test]
async fn a_person_signs_in_to_a_service_and_only_its_own_node_learns_who() {
    let idp = start_idp().await;
    let issuer = idp.lock().unwrap().issuer.clone();
    let app = signing_app(&issuer);
    let (home, other, key) = grafana(&app).await;

    let (resp, cookies) = sign_in_as(&app, &idp, "alice", &["family"]).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    let ticket = ticket_of(&resp);
    let login = cookies.iter().find(|c| c.starts_with("wireserve-login=")).expect("the coordinator's own login").clone();

    // Another node can't redeem it, and trying does not spend it.
    let redeem = serde_json::json!({"fqdn": "grafana.int.test", "ticket": ticket, "bind": BIND});
    let (status, _) = json(&app.router, "POST", "/sign-in/redeem", &other, redeem.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, answer) = json(&app.router, "POST", "/sign-in/redeem", &home, redeem.clone()).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["to"], "/d?x=1");
    let token = answer["token"].as_str().unwrap().to_string();
    let s = wireserve_types::session::verify(&key, &token).expect("signed by the coordinator");
    assert_eq!((s.sub.as_str(), s.aud.as_str(), s.groups.as_slice()), ("alice", "grafana.int.test", &["family".to_string()][..]));
    assert!(s.exp > chrono::Utc::now().timestamp() + 800, "good until the groups are due again");
    assert_eq!(json(&app.router, "POST", "/sign-in/redeem", &home, redeem).await.0, StatusCode::GONE, "once only");

    // Signed in already: the next visit goes straight back with a ticket.
    let resp = call(&app.router, "GET", &format!("/sign-in?service=grafana.int.test&to=%2F&bind={BIND}"), Some(&login), None).await;
    assert_eq!(resp.status(), StatusCode::FOUND);
    ticket_of(&resp);

    // Renewing: only by its own node, only for its own service.
    let renew = serde_json::json!({"fqdn": "grafana.int.test", "token": token});
    assert_eq!(json(&app.router, "POST", "/sign-in/renew", &other, renew.clone()).await.0, StatusCode::FORBIDDEN);
    let elsewhere = serde_json::json!({"fqdn": "vault.int.test", "token": token});
    assert_eq!(json(&app.router, "POST", "/sign-in/renew", &home, elsewhere).await.0, StatusCode::FORBIDDEN);
    let (status, answer) = json(&app.router, "POST", "/sign-in/renew", &home, renew.clone()).await;
    assert_eq!(status, StatusCode::OK, "{answer}");

    // Due: the provider is asked, the groups follow it, the token rotates.
    let backdate = || async {
        app.state.db.conn.lock().await
            .execute("UPDATE sign_in_sessions SET refreshed_at = '2020-01-01T00:00:00+00:00'", [])
            .unwrap();
    };
    backdate().await;
    idp.lock().unwrap().groups_now = vec!["admins".into(), "family".into()];
    let (_, answer) = json(&app.router, "POST", "/sign-in/renew", &home, renew.clone()).await;
    let s = wireserve_types::session::verify(&key, answer["token"].as_str().unwrap()).unwrap();
    assert_eq!(s.groups, ["admins", "family"]);
    let status = text(call(&app.router, "GET", "/admin/owners", None, None).await).await;
    assert!(status.contains("\"sign_in\":true") && status.contains("alice@example.com"), "{status}");

    // The provider refusing the refresh token ends the session.
    backdate().await;
    idp.lock().unwrap().refuse_refresh = true;
    assert_eq!(json(&app.router, "POST", "/sign-in/renew", &home, renew).await.0, StatusCode::GONE);
}

#[tokio::test]
async fn someone_the_service_does_not_admit_gets_no_ticket() {
    let idp = start_idp().await;
    let issuer = idp.lock().unwrap().issuer.clone();
    let app = signing_app(&issuer);
    grafana(&app).await;
    let (resp, _) = sign_in_as(&app, &idp, "mallory", &["guests"]).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(resp.headers().get(header::LOCATION).is_none());
    assert!(text(resp).await.contains("not for any of your groups"));

    // Nor is anywhere but a path on the service somewhere to go back to.
    for bad in ["//evil.example/", "https%3A%2F%2Fevil.example%2F"] {
        let resp = call(&app.router, "GET", &format!("/sign-in?service=grafana.int.test&to={bad}&bind={BIND}"), None, None).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
    let resp = call(&app.router, "GET", &format!("/sign-in?service=nothing.int.test&bind={BIND}"), None, None).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = call(&app.router, "GET", "/sign-in?service=grafana.int.test", None, None).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "not from a service's terminator: no bind");
}

#[tokio::test]
async fn signing_out_at_a_service_ends_the_session_everywhere() {
    let idp = start_idp().await;
    let issuer = idp.lock().unwrap().issuer.clone();
    let app = signing_app(&issuer);
    let (home, _, _) = grafana(&app).await;
    let (resp, cookies) = sign_in_as(&app, &idp, "alice", &["family"]).await;
    let redeem = serde_json::json!({"fqdn": "grafana.int.test", "ticket": ticket_of(&resp), "bind": BIND});
    let (_, answer) = json(&app.router, "POST", "/sign-in/redeem", &home, redeem).await;
    let body = serde_json::json!({"fqdn": "grafana.int.test", "token": answer["token"]});
    assert_eq!(json(&app.router, "POST", "/sign-in/end", &home, body.clone()).await.0, StatusCode::NO_CONTENT);
    assert_eq!(json(&app.router, "POST", "/sign-in/renew", &home, body).await.0, StatusCode::GONE);

    // The coordinator's own login is gone with it: back to the provider.
    let login = cookies.iter().find(|c| c.starts_with("wireserve-login=")).unwrap();
    let resp = call(&app.router, "GET", &format!("/sign-in?service=grafana.int.test&bind={BIND}"), Some(login), None).await;
    assert!(resp.headers()[header::LOCATION].to_str().unwrap().starts_with(&issuer), "asked again");
    let resp = call(&app.router, "GET", "/signed-out", Some(login), None).await;
    assert!(resp.headers()[header::SET_COOKIE].to_str().unwrap().contains("Max-Age=0"));
}

#[tokio::test]
async fn a_ticket_works_only_in_the_browser_that_asked_for_it() {
    // PLAN.md #312: someone who signs in and hands their ticket over must
    // not get the other person signed in as them.
    let idp = start_idp().await;
    let issuer = idp.lock().unwrap().issuer.clone();
    let app = signing_app(&issuer);
    let (home, _, _) = grafana(&app).await;
    let (resp, _) = sign_in_as(&app, &idp, "mallory", &["family"]).await;
    let ticket = ticket_of(&resp);
    let elsewhere = "c2".repeat(32);
    let redeem = |bind: &str| serde_json::json!({"fqdn": "grafana.int.test", "ticket": ticket, "bind": bind});
    assert_eq!(json(&app.router, "POST", "/sign-in/redeem", &home, redeem(&elsewhere)).await.0, StatusCode::FORBIDDEN);
    assert_eq!(json(&app.router, "POST", "/sign-in/redeem", &home, redeem("")).await.0, StatusCode::GONE, "and it is used up");
}

#[tokio::test]
async fn one_address_starts_only_so_many_sign_ins() {
    let idp = start_idp().await;
    let issuer = idp.lock().unwrap().issuer.clone();
    let app = signing_app(&issuer);
    grafana(&app).await;
    let uri = format!("/sign-in?service=grafana.int.test&bind={BIND}");
    for _ in 0..wireserve_coordinator::oidc::sign_in::STARTS_PER_MIN {
        assert_eq!(call(&app.router, "GET", &uri, None, None).await.status(), StatusCode::FOUND);
    }
    assert_eq!(call(&app.router, "GET", &uri, None, None).await.status(), StatusCode::TOO_MANY_REQUESTS);
}
