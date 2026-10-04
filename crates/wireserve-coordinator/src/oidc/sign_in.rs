//! The sign-in (PLAN.md M48): the coordinator signs people in to restricted
//! services through its own client of the identity provider, and each
//! service's terminator checks the session tokens it signs.
//!
//! A browser goes through it like this:
//! 1. A terminator sends it to `GET /sign-in?service=<fqdn>&to=<path>`.
//!    With this coordinator's login cookie for a live session, the provider
//!    is not asked again; otherwise the code flow runs, and the browser
//!    comes back on the shared `/oidc/callback` ([`signed_in`]).
//! 2. Only someone the service admits gets further: their groups must
//!    include one its grants name. Anyone else gets a page saying so, and
//!    the service learns nothing about them.
//! 3. A ticket — single use, a minute, for that service only — goes back
//!    to the service: `https://<fqdn>/.wireserve/callback?ticket=…`.
//! 4. The service's node redeems it (`POST /sign-in/redeem`), and only the
//!    node that owns the service can: the answer is a session token for
//!    that service, which its terminator keeps in a cookie of its own.
//!
//! A token lasts until the person's groups are due to be fetched again
//! (`WIRESERVE_OIDC_REFRESH_SECS`, as for device owners); then the
//! terminator renews it (`POST /sign-in/renew`), and the coordinator asks
//! the provider. A provider refusing the refresh token ends the session.
//! `POST /sign-in/end` ends it from a service's sign-out.

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use wireserve_types::session::{self, CALLBACK_PATH};
use wireserve_types::GrantSource;

use super::claim::{self, Flow, Purpose};
use super::pages::{self, escape};
use super::{Identity, Oidc, RefreshError};
use crate::auth::BearerNode;
use crate::db::{services, sessions, DbError};
use crate::error::AppError;
use crate::state::AppState;

/// This coordinator's own cookie for a signed-in browser.
const LOGIN_COOKIE: &str = "wireserve-login";

/// What one node may ask of the redeem, renew and end calls: each active
/// session renews once per refresh interval and service.
pub const SIGN_IN_BURST: u32 = 60;
pub const SIGN_INS_PER_MIN: u32 = 120;

/// The associated data a session's refresh token is sealed with.
fn aad(id: &str) -> Vec<u8> {
    [b"s:".as_slice(), id.as_bytes()].concat()
}

#[derive(Deserialize)]
pub struct StartQuery {
    service: String,
    to: Option<String>,
}

/// A service a sign-in can be for: `fqdn` names it under the service
/// domain, it is approved and served with TLS now; and the identity
/// provider's groups its grants name.
async fn sign_in_service(state: &AppState, fqdn: &str) -> Result<Option<(String, Vec<String>)>, DbError> {
    let Some(domain) = state.config.service_domain.as_deref() else {
        return Ok(None);
    };
    let Some(name) = fqdn
        .strip_suffix(domain)
        .and_then(|rest| rest.strip_suffix('.'))
        .filter(|label| wireserve_types::is_valid_dns_label(label))
    else {
        return Ok(None);
    };
    let conn = state.db.conn.lock().await;
    let Some(service) = services::find_by_name(&conn, name)?.filter(services::ServiceRow::is_approved) else {
        return Ok(None);
    };
    let ready = crate::db::tls::ready(&conn)?;
    if !state.directory_context(&ready).terminates(&service) {
        return Ok(None);
    }
    let groups = crate::access::read_rules(&conn)?
        .granted(&service.name)
        .into_iter()
        .filter_map(|s| match s {
            GrantSource::Oidc(g) => Some(g),
            _ => None,
        })
        .collect();
    Ok(Some((service.name, groups)))
}

fn admitted(person: &[String], service: &[String]) -> bool {
    person.iter().any(|g| service.contains(g))
}

/// `GET /sign-in`.
pub async fn start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<StartQuery>,
) -> Response {
    let (Some(oidc), Some(_)) = (state.oidc.clone(), state.config.sign_in()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let fqdn = q.service.trim().trim_end_matches('.').to_ascii_lowercase();
    let to = q.to.unwrap_or_else(|| "/".into());
    if !session::is_local_path(&to) {
        return pages::problem(StatusCode::BAD_REQUEST, "That is not a page to come back to.");
    }
    let service = match sign_in_service(&state, &fqdn).await {
        Ok(Some(s)) => s,
        Ok(None) => return pages::problem(StatusCode::NOT_FOUND, "There is no service by that name to sign in to."),
        Err(e) => {
            tracing::error!(error = %e, "sign-in: could not read the service");
            return pages::problem(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong on our side. Try again.");
        }
    };
    // Signed in already, in this browser: the provider is not asked again.
    let login = claim::named_cookie(&state, LOGIN_COOKIE, &headers).map(|c| wireserve_types::hash_token(&c));
    let known = match login {
        Some(hash) => sessions::find_by_login(&*state.db.conn.lock().await, &hash).ok().flatten(),
        None => None,
    };
    if let Some(known) = known {
        match freshen(&state, &oidc, &known.id).await {
            Ok(Fresh::Live(s)) => return go_back(&state, &s, &fqdn, &service, &to, None).await,
            Ok(Fresh::Unavailable) => {
                return pages::problem(StatusCode::BAD_GATEWAY, "The sign-in cannot be reached right now. Try again shortly.");
            }
            Ok(Fresh::Ended) => {}
            Err(e) => tracing::error!(error = %e, "sign-in: could not read the session"),
        }
    }
    let (url, pending) = match oidc.begin().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "sign-in: could not start at the identity provider");
            return pages::problem(StatusCode::BAD_GATEWAY, "The sign-in cannot be reached right now. Try again shortly.");
        }
    };
    let Some(id) = claim::remember(&oidc, Flow::new(Purpose::SignIn { fqdn: fqdn.clone(), to }, pending)) else {
        return pages::problem(StatusCode::SERVICE_UNAVAILABLE, "Too many sign-ins at once. Try again in a few minutes.");
    };
    let client_ip =
        crate::client_ip::resolve_client(&headers, peer.ip(), state.config.trusts_forwarded_from(peer.ip())).ip;
    tracing::info!(event = "sign_in_started", service = %fqdn, client_ip = %client_ip);
    claim::to_provider(&state, url, &id)
}

/// Back from the identity provider, signed in, for a sign-in to `fqdn`:
/// the session is made, and the browser goes back to the service.
pub(super) async fn signed_in(state: &AppState, oidc: &Oidc, identity: Identity, fqdn: &str, to: &str) -> Response {
    let now = Utc::now();
    let id = crate::tokengen::generate("");
    let login = crate::tokengen::generate("");
    let s = sessions::Session {
        id: id.clone(),
        sub: identity.sub,
        email: identity.email,
        name: identity.name,
        groups: identity.groups,
        refresh_token_enc: oidc.seal_for(&aad(&id), &identity.refresh_token),
        created_at: now,
        refreshed_at: now,
        stale_since: None,
        last_used_at: now,
    };
    if let Err(e) = sessions::create(&*state.db.conn.lock().await, &s, &wireserve_types::hash_token(&login)) {
        tracing::error!(error = %e, "sign-in: could not store the session");
        return pages::problem(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong on our side. Try again.");
    }
    tracing::info!(event = "signed_in", sub = %s.sub, groups = %s.groups.join(","), service = %fqdn);
    let login_cookie = claim::set_named_cookie(state, LOGIN_COOKIE, &login, sessions::IDLE_TTL.num_seconds().unsigned_abs());
    let service = match sign_in_service(state, fqdn).await {
        Ok(Some(service)) => service,
        Ok(None) => {
            return with_cookies(
                pages::problem(StatusCode::NOT_FOUND, "There is no service by that name to sign in to any more."),
                &[login_cookie, claim::set_cookie(state, "", 0)],
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "sign-in: could not read the service");
            return pages::problem(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong on our side. Try again.");
        }
    };
    go_back(state, &s, fqdn, &service, to, Some(login_cookie)).await
}

/// To the service with a ticket, if the person is someone it admits;
/// otherwise a page saying they are not.
async fn go_back(
    state: &AppState,
    s: &sessions::Session,
    fqdn: &str,
    service: &(String, Vec<String>),
    to: &str,
    login_cookie: Option<String>,
) -> Response {
    let mut cookies: Vec<String> = login_cookie.into_iter().collect();
    cookies.push(claim::set_cookie(state, "", 0));
    if !admitted(&s.groups, &service.1) {
        tracing::info!(event = "sign_in_not_admitted", sub = %s.sub, service = %fqdn);
        let who = s.email.as_deref().or(s.name.as_deref()).unwrap_or(&s.sub);
        let body = format!(
            "<p>You are signed in as <strong>{}</strong>, but <strong>{}</strong> is not for any of your groups.</p>\
             <p class=\"note\">Ask whoever runs it to grant one of your groups, or sign in as someone else: \
             <a href=\"signed-out\">sign out</a>.</p>",
            escape(who),
            escape(&service.0),
        );
        return with_cookies(pages::html(StatusCode::FORBIDDEN, "Not for you", &body, None), &cookies);
    }
    let ticket = crate::tokengen::generate("tkt_");
    let stored = sessions::create_ticket(&*state.db.conn.lock().await, &wireserve_types::hash_token(&ticket), &s.id, fqdn, to);
    if let Err(e) = stored {
        tracing::error!(error = %e, "sign-in: could not store the ticket");
        return pages::problem(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong on our side. Try again.");
    }
    let url = format!("https://{fqdn}{CALLBACK_PATH}?ticket={ticket}");
    let mut resp = (StatusCode::FOUND, [(header::LOCATION, url)]).into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp.headers_mut().insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    with_cookies(resp, &cookies)
}

fn with_cookies(mut resp: Response, cookies: &[String]) -> Response {
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
}

/// `GET /signed-out`: where a service's sign-out ends up. The session is
/// already over (the service ended it); this browser forgets its login.
pub async fn signed_out(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if state.oidc.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some(login) = claim::named_cookie(&state, LOGIN_COOKIE, &headers) {
        let conn = state.db.conn.lock().await;
        if let Ok(Some(s)) = sessions::find_by_login(&conn, &wireserve_types::hash_token(&login)) {
            let _ = sessions::remove(&conn, &s.id);
            tracing::info!(event = "signed_out", sub = %s.sub);
        }
    }
    let body = "<p>You are signed out. Every service you were signed in to asks again within a few minutes.</p>\
                <p class=\"note\">You can close this page.</p>";
    let cookie = claim::set_named_cookie(&state, LOGIN_COOKIE, "", 0);
    pages::html(StatusCode::OK, "Signed out", body, Some(cookie))
}

/// A session as of now.
enum Fresh {
    Live(sessions::Session),
    /// Gone, or the provider refused its refresh token.
    Ended,
    /// The provider could not be asked for too long: the groups don't
    /// count now, but the session may yet recover.
    Unavailable,
}

/// The session `id`, its groups fetched again first when they are due —
/// one refresh per session at a time.
async fn freshen(state: &AppState, oidc: &Oidc, id: &str) -> Result<Fresh, DbError> {
    let lock = {
        let mut all = oidc.renewing.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        all.retain(|_, l| std::sync::Arc::strong_count(l) > 1);
        all.entry(id.to_string()).or_default().clone()
    };
    let _held = lock.lock().await;
    let Some(s) = sessions::find(&*state.db.conn.lock().await, id)? else {
        return Ok(Fresh::Ended);
    };
    let now = Utc::now();
    let interval = chrono::Duration::from_std(oidc.config.refresh_interval).unwrap_or(chrono::Duration::minutes(15));
    if now - s.refreshed_at < interval {
        sessions::touch(&*state.db.conn.lock().await, id)?;
        return Ok(if s.groups_count(now) { Fresh::Live(s) } else { Fresh::Unavailable });
    }
    let Some(token) = oidc.open_for(&aad(id), &s.refresh_token_enc) else {
        tracing::warn!(event = "session_ended", sub = %s.sub, reason = "unreadable_token");
        sessions::remove(&*state.db.conn.lock().await, id)?;
        return Ok(Fresh::Ended);
    };
    let outcome = oidc.refresh(&token, &s.sub).await;
    let conn = state.db.conn.lock().await;
    match outcome {
        Ok(r) => {
            if r.groups != s.groups {
                tracing::info!(event = "session_groups_changed", sub = %s.sub, groups = %r.groups.join(","));
            }
            let email = r.email.map(|e| e.unwrap_or_default());
            sessions::refreshed(&conn, id, &r.groups, &oidc.seal_for(&aad(id), &r.refresh_token), email.as_deref())?;
        }
        Err(RefreshError::Refused) => {
            tracing::info!(event = "session_ended", sub = %s.sub, reason = "refused");
            sessions::remove(&conn, id)?;
            return Ok(Fresh::Ended);
        }
        Err(RefreshError::Failed(e)) => {
            tracing::warn!(sub = %s.sub, error = %e, "session refresh failed; its groups go stale");
            sessions::refresh_failed(&conn, id)?;
            sessions::touch(&conn, id)?;
        }
    }
    let Some(s) = sessions::find(&conn, id)? else {
        return Ok(Fresh::Ended);
    };
    Ok(if s.groups_count(now) { Fresh::Live(s) } else { Fresh::Unavailable })
}

/// Until when a token for `s` is good: until its groups are due again, or —
/// while the provider cannot be asked — until they stop counting.
fn expires(oidc: &Oidc, s: &sessions::Session, now: DateTime<Utc>) -> DateTime<Utc> {
    let interval = chrono::Duration::from_std(oidc.config.refresh_interval).unwrap_or(chrono::Duration::minutes(15));
    match s.stale_since {
        None => s.refreshed_at + interval,
        Some(since) => (now + interval).min(since + crate::db::owners::STALE_AFTER),
    }
}

/// A session token for `s` at `fqdn`. Kept under the size a browser keeps:
/// past it, only the groups some grant names go in, then only the ones this
/// service's grants name.
async fn token(state: &AppState, oidc: &Oidc, s: &sessions::Session, fqdn: &str, granted: Option<&[String]>) -> Result<String, DbError> {
    let mut claims = session::Session {
        sid: s.id.clone(),
        sub: s.sub.clone(),
        email: s.email.clone(),
        groups: s.groups.clone(),
        aud: fqdn.to_string(),
        exp: expires(oidc, s, Utc::now()).timestamp(),
    };
    let mut signed = session::sign(&oidc.signing_key, &claims);
    if signed.len() > session::MAX_TOKEN_LEN {
        let named: std::collections::BTreeSet<String> = crate::access::read_rules(&*state.db.conn.lock().await)?
            .grants
            .iter()
            .filter_map(|g| match &g.source {
                GrantSource::Oidc(name) => Some(name.clone()),
                _ => None,
            })
            .collect();
        claims.groups.retain(|g| named.contains(g));
        signed = session::sign(&oidc.signing_key, &claims);
        if signed.len() > session::MAX_TOKEN_LEN {
            claims.groups.retain(|g| granted.is_some_and(|ok| ok.contains(g)));
            signed = session::sign(&oidc.signing_key, &claims);
        }
        tracing::info!(sub = %s.sub, "too many groups for a cookie; the token names only those grants use");
    }
    Ok(signed)
}

/// The service `fqdn`, if it is `node`'s own and approved — the only node
/// whose terminator may redeem, renew or end a session there.
async fn own_service(state: &AppState, node: &crate::db::nodes::NodeRow, fqdn: &str) -> Result<String, AppError> {
    let domain = state.config.service_domain.as_deref().ok_or_else(|| AppError::Conflict("no service domain is set".into()))?;
    let name = fqdn
        .strip_suffix(domain)
        .and_then(|rest| rest.strip_suffix('.'))
        .filter(|label| wireserve_types::is_valid_dns_label(label))
        .ok_or_else(|| AppError::Forbidden(format!("{fqdn} is not a service name under {domain}")))?;
    let service = services::find_by_name(&*state.db.conn.lock().await, name)?;
    match service {
        Some(s) if s.node_id == node.id && s.is_approved() => Ok(s.name),
        _ => {
            tracing::warn!(event = "sign_in_refused", node_name = %node.name, fqdn = %fqdn, "a node asked about a service that is not its own");
            Err(AppError::Forbidden(format!("{fqdn}: that service is not this node's")))
        }
    }
}

fn limit(state: &AppState, node: &crate::db::nodes::NodeRow) -> Result<(), AppError> {
    if let crate::rate_limit::Take::Refused { log } = state.sign_in_limiter.take(node.id) {
        if log {
            tracing::warn!(event = "sign_in_rate_limited", node_name = %node.name, "asking about sessions faster than the per-node limit");
        }
        return Err(AppError::TooManyRequests);
    }
    Ok(())
}

fn enabled(state: &AppState) -> Result<std::sync::Arc<Oidc>, AppError> {
    match (state.oidc.clone(), state.config.sign_in()) {
        (Some(oidc), Some(_)) => Ok(oidc),
        _ => Err(AppError::Conflict("this coordinator has no sign-in".into())),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemBody {
    pub fqdn: String,
    pub ticket: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionAnswer {
    pub token: String,
    /// Where on the service the browser goes next (redeem only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

/// `POST /sign-in/redeem`.
pub async fn redeem(
    State(state): State<AppState>,
    BearerNode { node }: BearerNode,
    Json(body): Json<RedeemBody>,
) -> Result<Json<SessionAnswer>, AppError> {
    let oidc = enabled(&state)?;
    limit(&state, &node)?;
    let fqdn = body.fqdn.to_ascii_lowercase();
    own_service(&state, &node, &fqdn).await?;
    let taken = sessions::take_ticket(&*state.db.conn.lock().await, &wireserve_types::hash_token(&body.ticket), &fqdn)?;
    let Some((id, to)) = taken else {
        return Err(AppError::Gone("this sign-in link was used already, or is too old".into()));
    };
    let s = match freshen(&state, &oidc, &id).await? {
        Fresh::Live(s) => s,
        Fresh::Ended => return Err(AppError::Gone("signed out".into())),
        Fresh::Unavailable => return Err(AppError::Unavailable("the identity provider cannot be reached".into())),
    };
    tracing::info!(event = "session_redeemed", node_name = %node.name, service = %fqdn, sub = %s.sub);
    let granted = sign_in_service(&state, &fqdn).await?.map(|(_, g)| g);
    Ok(Json(SessionAnswer { token: token(&state, &oidc, &s, &fqdn, granted.as_deref()).await?, to: Some(to) }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenBody {
    pub fqdn: String,
    pub token: String,
}

/// The session a token a node holds names, if the coordinator signed it for
/// that node's own service `fqdn` — expired or not.
async fn held_session(state: &AppState, oidc: &Oidc, node: &crate::db::nodes::NodeRow, body: &TokenBody) -> Result<(String, String), AppError> {
    let fqdn = body.fqdn.to_ascii_lowercase();
    own_service(state, node, &fqdn).await?;
    let claims = session::verify(&oidc.signing_key.verifying_key(), &body.token)
        .map_err(|e| AppError::Forbidden(format!("not a session token of this coordinator's: {e}")))?;
    if claims.aud != fqdn {
        tracing::warn!(event = "sign_in_refused", node_name = %node.name, fqdn = %fqdn, aud = %claims.aud, "a node presented another service's session token");
        return Err(AppError::Forbidden("that token is for another service".into()));
    }
    Ok((fqdn, claims.sid))
}

/// `POST /sign-in/renew`.
pub async fn renew(
    State(state): State<AppState>,
    BearerNode { node }: BearerNode,
    Json(body): Json<TokenBody>,
) -> Result<Json<SessionAnswer>, AppError> {
    let oidc = enabled(&state)?;
    limit(&state, &node)?;
    let (fqdn, id) = held_session(&state, &oidc, &node, &body).await?;
    let s = match freshen(&state, &oidc, &id).await? {
        Fresh::Live(s) => s,
        Fresh::Ended => return Err(AppError::Gone("signed out".into())),
        Fresh::Unavailable => return Err(AppError::Unavailable("the identity provider cannot be reached".into())),
    };
    let granted = sign_in_service(&state, &fqdn).await?.map(|(_, g)| g);
    Ok(Json(SessionAnswer { token: token(&state, &oidc, &s, &fqdn, granted.as_deref()).await?, to: None }))
}

/// `POST /sign-in/end`: a service's sign-out ends the whole session.
pub async fn end(
    State(state): State<AppState>,
    BearerNode { node }: BearerNode,
    Json(body): Json<TokenBody>,
) -> Result<StatusCode, AppError> {
    let oidc = enabled(&state)?;
    limit(&state, &node)?;
    let (fqdn, id) = held_session(&state, &oidc, &node, &body).await?;
    let conn = state.db.conn.lock().await;
    if let Some(s) = sessions::find(&conn, &id)? {
        sessions::remove(&conn, &id)?;
        tracing::info!(event = "signed_out", sub = %s.sub, service = %fqdn);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_someone_in_a_granted_group_is_admitted() {
        let granted = vec!["family".to_string()];
        assert!(admitted(&["admins".into(), "family".into()], &granted));
        assert!(!admitted(&["admins".into()], &granted));
        assert!(!admitted(&["family".into()], &[]), "a service no group is granted is for nobody signing in");
    }

    #[test]
    fn a_token_lasts_until_the_groups_are_due_or_stop_counting() {
        let oidc = Oidc::new(super::super::test_config());
        let now = Utc::now();
        let mut s = sessions::Session {
            id: "s".into(),
            sub: "anna".into(),
            email: None,
            name: None,
            groups: vec![],
            refresh_token_enc: String::new(),
            created_at: now,
            refreshed_at: now - chrono::Duration::minutes(5),
            stale_since: None,
            last_used_at: now,
        };
        assert_eq!(expires(&oidc, &s, now), now + chrono::Duration::minutes(10));
        s.stale_since = Some(now - chrono::Duration::minutes(55));
        assert_eq!(expires(&oidc, &s, now), now + chrono::Duration::minutes(5), "the stale hour runs out first");
        s.stale_since = Some(now);
        assert_eq!(expires(&oidc, &s, now), now + chrono::Duration::minutes(15));
    }

    #[test]
    fn a_session_token_is_sealed_apart_from_any_nodes() {
        let oidc = Oidc::new(super::super::test_config());
        let sealed = oidc.seal_for(&aad("abc"), "refresh");
        assert_eq!(oidc.open_for(&aad("abc"), &sealed).as_deref(), Some("refresh"));
        assert_eq!(oidc.open_for(&aad("abd"), &sealed), None);
    }
}
