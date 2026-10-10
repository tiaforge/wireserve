//! Claiming a device (PLAN.md M38): three requests on the node router.
//!
//! 1. `GET /claim/{code}` — an admin's link. Checked, not used up (a link
//!    previewer opening it must not spend it), and a sign-in started: its
//!    state lives in memory, tied to this browser by a cookie.
//! 2. `GET /oidc/callback` — back from the identity provider (shared with
//!    the sign-in, PLAN.md M48, which the flow says it is for). The state
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
const MAX_CLAIM_FLOWS: usize = 256;

/// At most this many sign-ins to services in progress. Anyone can start one
/// (PLAN.md #312), so when they are all taken the oldest goes, rather than
/// every new one being refused — a flood started from many addresses can
/// make a sign-in start over, never stop them all, and never touches a
/// claim's.
const MAX_SIGN_IN_FLOWS: usize = 1024;

/// The prefix of a claim link's code.
pub const CODE_PREFIX: &str = "clm_";

/// A sign-in at the identity provider in progress: for a claim link, or for
/// signing in to a service (PLAN.md M48).
pub struct Flow {
    pub(super) purpose: Purpose,
    pub(super) started: Instant,
    pub(super) pending: Option<Pending>,
    /// Signed in, awaiting "yes": who, and the token the answer must carry.
    signed_in: Option<(Identity, String)>,
}

pub(super) enum Purpose {
    Claim { node_id: i64, code_hash: String },
    SignIn { fqdn: String, to: String, bind: String },
}

impl Flow {
    pub(super) fn new(purpose: Purpose, pending: Pending) -> Self {
        Self { purpose, started: Instant::now(), pending: Some(pending), signed_in: None }
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

/// Remembers a flow, tied to the browser by the returned cookie value.
/// `None` when too many claims are in progress; a sign-in takes the oldest
/// sign-in's place instead.
pub(super) fn remember(oidc: &super::Oidc, flow: Flow) -> Option<String> {
    let id = crate::tokengen::generate("");
    let mut flows = oidc.flows.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    flows.retain(|_, f| f.started.elapsed() < FLOW_TTL);
    let signing_in = matches!(flow.purpose, Purpose::SignIn { .. });
    let of_kind = |f: &Flow| matches!(f.purpose, Purpose::SignIn { .. }) == signing_in;
    if flows.values().filter(|f| of_kind(f)).count() >= if signing_in { MAX_SIGN_IN_FLOWS } else { MAX_CLAIM_FLOWS } {
        if !signing_in {
            return None;
        }
        let oldest = flows.iter().filter(|(_, f)| of_kind(f)).min_by_key(|(_, f)| f.started).map(|(k, _)| k.clone());
        if let Some(oldest) = oldest {
            flows.remove(&oldest);
        }
    }
    flows.insert(id.clone(), flow);
    Some(id)
}

/// A 302 to the identity provider, setting the flow's cookie.
pub(super) fn to_provider(state: &AppState, url: String, flow_id: &str) -> Response {
    let mut resp = (StatusCode::FOUND, [(header::LOCATION, url)]).into_response();
    if let Ok(v) = set_cookie(state, flow_id, FLOW_TTL.as_secs()).parse() {
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
    let Some(id) = remember(&oidc, Flow::new(Purpose::Claim { node_id: node.id, code_hash }, pending)) else {
        return pages::problem(StatusCode::SERVICE_UNAVAILABLE, "Too many sign-ins at once. Try again in a few minutes.");
    };
    tracing::info!(event = "claim_started", node_name = %node.name, client_ip = %client_ip);
    to_provider(&state, url, &id)
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /oidc/callback`: back from the identity provider, for a claim or a
/// sign-in to a service — whichever the browser's flow is for.
pub async fn callback(State(state): State<AppState>, headers: HeaderMap, Query(q): Query<CallbackQuery>) -> Response {
    let Some(oidc) = state.oidc.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(id) = flow_id(&state, &headers) else {
        return expired_flow();
    };
    // Taken out, whatever happens next: a sign-in answers once. A sign-in
    // to a service has nothing left to ask, so its flow goes altogether.
    let taken = {
        let mut flows = oidc.flows.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let live = flows.get(&id).is_some_and(|f| f.started.elapsed() < FLOW_TTL && f.pending.is_some());
        match flows.get(&id).map(|f| &f.purpose) {
            Some(Purpose::SignIn { .. }) if live => flows.remove(&id).and_then(|f| {
                let Purpose::SignIn { fqdn, to, bind } = f.purpose else { unreachable!() };
                Some((f.pending?, Err((fqdn, to, bind))))
            }),
            Some(Purpose::Claim { .. }) if live => flows.get_mut(&id).and_then(|f| {
                let Purpose::Claim { node_id, code_hash } = &f.purpose else { unreachable!() };
                let claim = Ok((*node_id, code_hash.clone()));
                Some((f.pending.take()?, claim))
            }),
            _ => None,
        }
    };
    let Some((pending, purpose)) = taken else {
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
    let (node_id, code_hash) = match purpose {
        Ok(claim) => claim,
        Err((fqdn, to, bind)) => return super::sign_in::signed_in(&state, &oidc, identity, &fqdn, &to, &bind).await,
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
    let Some(Flow { purpose: Purpose::Claim { node_id, code_hash }, signed_in: Some((identity, _)), .. }) = flow else {
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

    fn sign_in() -> Flow {
        Flow::new(Purpose::SignIn { fqdn: "a.int.test".into(), to: "/".into(), bind: String::new() }, pending())
    }

    #[test]
    fn a_flood_of_sign_ins_pushes_out_the_oldest_and_never_a_claim() {
        let oidc = super::super::Oidc::new(super::super::test_config());
        let claim = remember(&oidc, Flow::new(Purpose::Claim { node_id: 1, code_hash: "h".into() }, pending())).unwrap();
        let first = remember(&oidc, sign_in()).unwrap();
        for _ in 0..MAX_SIGN_IN_FLOWS {
            assert!(remember(&oidc, sign_in()).is_some(), "a sign-in is never refused");
        }
        let flows = oidc.flows.lock().unwrap();
        assert!(!flows.contains_key(&first), "the oldest went");
        assert!(flows.contains_key(&claim), "the claim stayed");
        assert_eq!(flows.len(), MAX_SIGN_IN_FLOWS + 1);
    }
}
