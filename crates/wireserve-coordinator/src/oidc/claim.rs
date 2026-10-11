//! Claiming a device (PLAN.md M38): three requests on the node router.
//!
//! 1. `GET /claim/{code}` — an admin's link. Checked, not used up (a link
//!    previewer opening it must not spend it), and a sign-in started: its
//!    state lives in memory, tied to this browser by a cookie.
//! 2. `GET /oidc/callback` — back from the identity provider (shared with
//!    the sign-in, PLAN.md M48, whose flow is in a cookie of its own; the
//!    state the provider returns says which came back). The state
//!    must match the cookie's, the code is exchanged, the ID token checked,
//!    and the person is asked: "make this node yours?", naming the node,
//!    its tags and its current owner.
//! 3. `POST /claim/confirm` — yes. The link is used up, atomically, and the
//!    person owns the node.
//!
//! Nobody but an admin makes a link, so a node cannot send one around to
//! collect people's groups; the confirmation page is the second line.

use std::time::{Duration, Instant};


use axum::extract::{ConnectInfo, Form, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::pages::{self, escape};
use super::{Identity, Pending};
use crate::db::{grants, nodes, owners};
use crate::state::AppState;

/// How long a started sign-in waits for the person.
const FLOW_TTL: Duration = Duration::from_secs(600);

/// At most this many claims in progress. Each one needs a valid link, so
/// this only bounds what someone holding one can make the process keep.
/// (A sign-in to a service, which anyone can start, keeps nothing here: its
/// flow is in the browser's cookie, see `sign_in::returning`.)
const MAX_CLAIM_FLOWS: usize = 256;

/// The prefix of a claim link's code.
pub const CODE_PREFIX: &str = "clm_";

/// A claim's sign-in at the identity provider, in progress.
pub struct Flow {
    node_id: i64,
    code_hash: String,
    started: Instant,
    pending: Option<Pending>,
    /// Signed in, awaiting "yes": who, and the token the answer must carry.
    signed_in: Option<(Identity, String)>,
}

impl Flow {
    fn new(node_id: i64, code_hash: String, pending: Pending) -> Self {
        Self { node_id, code_hash, started: Instant::now(), pending: Some(pending), signed_in: None }
    }
}

/// A cookie of this coordinator's: `__Host-` (only ever set by this origin,
/// over https, for the whole path) unless the coordinator is plain http —
/// a test setup — which cannot have one.
pub(super) fn cookie_name(state: &AppState, base: &'static str) -> String {
    if state.config.public_url.as_deref().is_some_and(|u| u.starts_with("https://")) {
        format!("__Host-{base}")
    } else {
        base.to_string()
    }
}

pub(super) fn set_named_cookie(state: &AppState, base: &'static str, value: &str, max_age: u64) -> String {
    let name = cookie_name(state, base);
    let secure = if name.starts_with("__Host-") { "; Secure" } else { "" };
    // Lax: the browser comes back from the identity provider by a top-level
    // navigation, which Lax sends the cookie on and a cross-site POST not.
    format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}")
}

pub(super) fn named_cookie(state: &AppState, base: &'static str, headers: &HeaderMap) -> Option<String> {
    let name = cookie_name(state, base);
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix(name.as_str())?.strip_prefix('=').map(str::to_string))
}

/// The cookie tying a browser to its flow.
const FLOW_COOKIE: &str = "wireserve-flow";

pub(super) fn set_cookie(state: &AppState, value: &str, max_age: u64) -> String {
    set_named_cookie(state, FLOW_COOKIE, value, max_age)
}

fn flow_id(state: &AppState, headers: &HeaderMap) -> Option<String> {
    named_cookie(state, FLOW_COOKIE, headers)
}

/// Remembers a claim's flow, tied to the browser by the returned cookie
/// value. `None` when too many claims are in progress.
fn remember(oidc: &super::Oidc, flow: Flow) -> Option<String> {
    let id = crate::tokengen::generate("");
    let mut flows = oidc.flows.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    flows.retain(|_, f| f.started.elapsed() < FLOW_TTL);
    if flows.len() >= MAX_CLAIM_FLOWS {
        return None;
    }
    flows.insert(id.clone(), flow);
    Some(id)
}

/// A 302 to the identity provider, setting the flow's cookie (`cookie`, a
/// whole `Set-Cookie` value).
pub(super) fn to_provider(url: String, cookie: &str) -> Response {
    let mut resp = (StatusCode::FOUND, [(header::LOCATION, url)]).into_response();
    if let Ok(v) = cookie.parse() {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    resp.headers_mut().insert(header::REFERRER_POLICY, header::HeaderValue::from_static("no-referrer"));
    resp
}

pub(super) fn same(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

pub(super) fn expired_flow() -> Response {
    pages::problem(
        StatusCode::BAD_REQUEST,
        "This sign-in was started in another browser, or took too long. Start again from the link or page you came from.",
    )
}

/// `GET /claim/{code}`.
pub async fn start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> Response {
    let Some(oidc) = state.oidc.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let client_ip =
        crate::client_ip::resolve_client(&headers, peer.ip(), state.config.trusts_forwarded_from(peer.ip())).ip;
    let well_formed = code.strip_prefix(CODE_PREFIX).is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
    let code_hash = wireserve_types::hash_token(&code);
    let node = if well_formed {
        let conn = state.db.conn.lock().await;
        match owners::claim_node(&conn, &code_hash) {
            Ok(Some(id)) => nodes::find_by_id(&conn, id).ok().flatten().filter(|n| !n.revoked),
            _ => None,
        }
    } else {
        None
    };
    let Some(node) = node else {
        state.rate_limiter.record_failure(client_ip);
        tracing::warn!(event = "auth_failure", client_ip = %client_ip, endpoint = "/claim", reason = "unknown_claim");
        state.rate_limiter.apply_failure_delay().await;
        return pages::problem(StatusCode::NOT_FOUND, "This link is not valid, or not any more. Ask for a new one.");
    };
    let (url, pending) = match oidc.begin().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "claim: could not start a sign-in");
            return pages::problem(StatusCode::BAD_GATEWAY, "The sign-in cannot be reached right now. Try again shortly.");
        }
    };
    let Some(id) = remember(&oidc, Flow::new(node.id, code_hash, pending)) else {
        return pages::problem(StatusCode::SERVICE_UNAVAILABLE, "Too many sign-ins at once. Try again in a few minutes.");
    };
    tracing::info!(event = "claim_started", node_name = %node.name, client_ip = %client_ip);
    to_provider(url, &set_cookie(&state, &id, FLOW_TTL.as_secs()))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /oidc/callback`: back from the identity provider, for a claim or a
/// sign-in to a service — whichever the state it returned belongs to.
pub async fn callback(State(state): State<AppState>, headers: HeaderMap, Query(q): Query<CallbackQuery>) -> Response {
    let Some(oidc) = state.oidc.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // A sign-in to a service (PLAN.md M48): its flow is the browser's own
    // cookie, gone whatever happens next — a sign-in answers once, and the
    // provider would not take its code twice anyway.
    if let Some(flow) = super::sign_in::returning(&state, &oidc, &headers, q.state.as_deref()) {
        let cleared = [super::sign_in::clear_flow(&state)];
        if let Some(error) = q.error {
            let page = pages::problem(StatusCode::BAD_REQUEST, &format!("The sign-in did not finish ({error}). Start again to retry."));
            return super::sign_in::with_cookies(page, &cleared);
        }
        let Some(code) = q.code else {
            return super::sign_in::with_cookies(expired_flow(), &cleared);
        };
        return match oidc.finish(code, flow.pending).await {
            Ok(identity) => super::sign_in::signed_in(&state, &oidc, identity, &flow.fqdn, &flow.to, &flow.bind).await,
            Err(e) => {
                tracing::warn!(error = %e, "sign-in at the identity provider failed");
                let page = pages::problem(StatusCode::BAD_GATEWAY, &format!("The sign-in failed: {e}"));
                super::sign_in::with_cookies(page, &cleared)
            }
        };
    }
    let Some(id) = flow_id(&state, &headers) else {
        return expired_flow();
    };
    // Taken out, whatever happens next: a sign-in answers once.
    let taken = {
        let mut flows = oidc.flows.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        flows
            .get_mut(&id)
            .filter(|f| f.started.elapsed() < FLOW_TTL)
            .and_then(|f| Some((f.pending.take()?, f.node_id, f.code_hash.clone())))
    };
    let Some((pending, node_id, code_hash)) = taken else {
        return expired_flow();
    };
    if let Some(error) = q.error {
        return pages::problem(StatusCode::BAD_REQUEST, &format!("The sign-in did not finish ({error}). Start again to retry."));
    }
    if !q.state.as_deref().is_some_and(|s| same(s, pending.csrf.secret())) {
        tracing::warn!(event = "oidc_state_mismatch");
        return expired_flow();
    }
    let Some(code) = q.code else {
        return expired_flow();
    };
    let identity = match oidc.finish(code, pending).await {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(error = %e, "sign-in at the identity provider failed");
            return pages::problem(StatusCode::BAD_GATEWAY, &format!("The sign-in failed: {e}"));
        }
    };
    let conn = state.db.conn.lock().await;
    let still_valid = owners::claim_node(&conn, &code_hash).ok().flatten() == Some(node_id);
    let node = nodes::find_by_id(&conn, node_id).ok().flatten().filter(|n| !n.revoked);
    let (Some(node), true) = (node, still_valid) else {
        return pages::problem(StatusCode::GONE, "This link has expired or was used already. Ask for a new one.");
    };
    let tags: Vec<String> = grants::tags(&conn).ok().and_then(|mut t| t.remove(&node_id)).unwrap_or_default().into_iter().collect();
    let current = owners::of(&conn, node_id).ok().flatten().map(|o| o.email.unwrap_or(o.sub));
    drop(conn);
    let who = identity.email.clone().or_else(|| identity.name.clone()).unwrap_or_else(|| identity.sub.clone());
    let token = crate::tokengen::generate("");
    let body = pages::confirm(&node.name, &tags, current.as_deref(), &who, &identity.groups, &token);
    if let Some(f) = oidc.flows.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get_mut(&id) {
        f.signed_in = Some((identity, token));
    }
    pages::html(StatusCode::OK, "Claim this device", &body, None)
}

#[derive(Deserialize)]
pub struct ConfirmForm {
    token: String,
}

/// `POST /claim/confirm`.
pub async fn confirm(State(state): State<AppState>, headers: HeaderMap, Form(form): Form<ConfirmForm>) -> Response {
    let Some(oidc) = state.oidc.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(id) = flow_id(&state, &headers) else {
        return expired_flow();
    };
    let flow = {
        let mut flows = oidc.flows.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let ok = flows.get(&id).is_some_and(|f| {
            f.started.elapsed() < FLOW_TTL && f.signed_in.as_ref().is_some_and(|(_, t)| same(t, &form.token))
        });
        if ok { flows.remove(&id) } else { None }
    };
    let Some(Flow { node_id, code_hash, signed_in: Some((identity, _)), .. }) = flow else {
        return expired_flow();
    };
    let conn = state.db.conn.lock().await;
    if !owners::use_claim(&conn, &code_hash, node_id).unwrap_or(false) {
        return pages::problem(StatusCode::GONE, "This link has expired or was used already. Ask for a new one.");
    }
    let Some(node) = nodes::find_by_id(&conn, node_id).ok().flatten() else {
        return pages::problem(StatusCode::GONE, "This device is gone.");
    };
    let owner = owners::Owner {
        node_id,
        sub: identity.sub.clone(),
        email: identity.email.clone(),
        name: identity.name.clone(),
        groups: identity.groups.clone(),
        refresh_token_enc: oidc.seal(node_id, &identity.refresh_token),
        refreshed_at: chrono::Utc::now(),
        stale_since: None,
    };
    if let Err(e) = owners::set(&conn, &owner) {
        tracing::error!(error = %e, "claim: could not store the owner");
        return pages::problem(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong on our side. Ask for a new link.");
    }
    // The owner's groups are part of the grants every poll reads.
    state.directory_changed();
    drop(conn);
    tracing::info!(event = "node_claimed", node_name = %node.name, sub = %identity.sub, groups = %identity.groups.join(","));
    let who = identity.email.as_deref().unwrap_or(&identity.sub);
    let body = format!(
        "<p><strong>{}</strong> is yours now, <strong>{}</strong>. It reaches what your groups are granted from \
         its next poll, within a minute.</p><p class=\"note\">You can close this page.</p>",
        escape(&node.name),
        escape(who)
    );
    pages::html(StatusCode::OK, "Done", &body, Some(set_cookie(&state, "", 0)))
}

/// A fresh claim link for `node_id`: `<public url>/claim/<code>`, and when
/// it stops working.
pub fn new_link(
    conn: &rusqlite::Connection,
    public_url: &str,
    node_id: i64,
) -> Result<(String, chrono::DateTime<chrono::Utc>), crate::db::DbError> {
    let code = crate::tokengen::generate(CODE_PREFIX);
    let expires = owners::create_claim(conn, node_id, &wireserve_types::hash_token(&code))?;
    Ok((format!("{public_url}/claim/{code}"), expires))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending() -> Pending {
        Pending {
            csrf: openidconnect::CsrfToken::new("c".into()),
            nonce: openidconnect::Nonce::new("n".into()),
            pkce: openidconnect::PkceCodeVerifier::new("v".into()),
        }
    }

    #[test]
    fn claims_in_progress_are_bounded() {
        let oidc = super::super::Oidc::new(super::super::test_config());
        for _ in 0..MAX_CLAIM_FLOWS {
            assert!(remember(&oidc, Flow::new(1, "h".into(), pending())).is_some());
        }
        assert!(remember(&oidc, Flow::new(1, "h".into(), pending())).is_none());
    }
}
