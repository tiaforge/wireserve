//! A device claimed end to end (PLAN.md M38), against an identity provider
//! running in this process: discovery, PKCE, the ID token's signature and
//! nonce, the confirmation, and refreshing the owner's groups afterwards.

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
}

type Shared = Arc<Mutex<Idp>>;

fn id_token(issuer: &str, sub: &str, groups: &[String], nonce: Option<&str>) -> String {
    let key = CoreRsaPrivateSigningKey::from_pem(KEY, None).unwrap();
    let now = chrono::Utc::now();
    let mut claims = IdTokenClaims::<Groups, CoreGenderClaim>::new(
        IssuerUrl::new(issuer.into()).unwrap(),
        vec![Audience::new("wireserve".into())],
        now + chrono::Duration::minutes(5),
        now,
        StandardClaims::new(SubjectIdentifier::new(sub.into()))
            .set_email(Some(EndUserEmail::new(format!("{sub}@example.com")))),
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
            tokens(id_token(&issuer, &sub, &groups, Some(&nonce)), "rt-1")
        }
        Some("refresh_token") if idp.refuse_refresh => {
            (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": "invalid_grant"}))).into_response()
        }
        Some("refresh_token") => tokens(id_token(&issuer, "alice", &idp.groups_now, None), "rt-2"),
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
    let config = Config {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        admin_listen_addr: "127.0.0.1:0".parse().unwrap(),
        admin_token: "admin".into(),
        db_path: db_file.path().to_str().unwrap().into(),
        net_v4_cidr: "100.90.0.0/24".into(),
        net_v6_prefix: "fd00:90::/64".into(),
        service_domain: None,
        sign_in: None,
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
            redirect_url: "http://mesh.test/claim/callback".into(),
        }),
        dns: None,
        acme: wireserve_coordinator::config::acme_from_lookup(|_| None).unwrap(),
        online_threshold_secs: 180,
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
    };
    let db = Db::open(db_file.path()).unwrap();
    let state = build_state(config, db);
    let router = routes::node_router(state.clone()).merge(routes::admin_router(state.clone()));
    App { router, state, _db: db_file }
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
    assert_eq!(query(&location, "redirect_uri"), "http://mesh.test/claim/callback");
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
    (cookie, format!("/claim/callback?code={code}&state={}", query(&location, "state")))
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
