//! Two deliberately separate auth extractors. Spec §4.0 is explicit that
//! the admin trust surface and the per-node bearer-token surface must
//! never blur together in code — so `AdminAuth` and `BearerNode` do not
//! share a "check either token type" helper, even though the header
//! parsing looks superficially similar.

use std::net::{IpAddr, SocketAddr};

use axum::extract::connect_info::ConnectInfo;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use wireserve_types::hash_token;

use crate::state::AppState;

pub enum AuthError {
    Unauthorized,
    RateLimited,
    /// The token could not be checked at all (the database errored), as
    /// opposed to being checked and found wrong. Kept distinct so a
    /// transient storage failure is not laundered into "your credential
    /// is bad": reporting 401 there would burn the caller's
    /// failed-attempt budget for something it did not do, and a handful
    /// of such cycles would rate-limit every legitimately-polling node
    /// off the mesh while the real fault stayed invisible in the logs.
    Internal,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AuthError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                Json(wireserve_types::ErrorBody::new("unauthorized")),
            )
                .into_response(),
            AuthError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                Json(wireserve_types::ErrorBody::new("too many requests")),
            )
                .into_response(),
            AuthError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(wireserve_types::ErrorBody::new("internal error")),
            )
                .into_response(),
        }
    }
}

fn extract_bearer(parts: &Parts) -> Option<&str> {
    let header = parts.headers.get(axum::http::header::AUTHORIZATION)?;
    let value = header.to_str().ok()?;
    value.strip_prefix("Bearer ").filter(|t| !t.is_empty())
}

/// The IP to key rate limiting on — the raw TCP peer by default, or (if
/// `state.config.trust_proxy_headers` is set) the reverse proxy's own
/// `X-Forwarded-For` value, since spec §7 puts a proxy in front of the
/// coordinator and `ConnectInfo` would otherwise always just be that
/// proxy's own address for every request from every node (S4).
fn source_ip(state: &AppState, parts: &Parts) -> Option<IpAddr> {
    let connect_ip = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())?;
    Some(crate::client_ip::resolve(
        &parts.headers,
        connect_ip,
        state.config.trust_proxy_headers,
    ))
}

/// Checked BEFORE any comparison work — an IP that has already exhausted
/// its failed-attempt budget is turned away immediately, without spending
/// a hash/DB-lookup on a request that was never going to be allowed
/// anyway (spec §7's rate limiting is meant to make guessing costly, which
/// only holds if a blocked request is actually cheap to reject).
fn check_budget(state: &AppState, parts: &Parts) -> Result<(), AuthError> {
    match source_ip(state, parts) {
        Some(ip) if state.rate_limiter.is_blocked(ip) => Err(AuthError::RateLimited),
        _ => Ok(()),
    }
}

/// Records a failed attempt (spec §7: "basic rate limiting on /register
/// and on failed-auth responses from any endpoint") — call only once an
/// attempt has actually failed; successful auth never touches the
/// limiter.
fn record_failed_auth(state: &AppState, parts: &Parts) -> AuthError {
    if let Some(ip) = source_ip(state, parts) {
        state.rate_limiter.record_failure(ip);
    }
    AuthError::Unauthorized
}

/// Authenticates a request against the single static admin token. Compared
/// by hashing both sides with SHA256 first and then comparing digests in
/// constant time — this sidesteps a length-based timing signal from
/// comparing raw strings of different lengths (a `subtle::ConstantTimeEq`
/// on unequal-length byte slices isn't meaningfully constant-time; hashing
/// first fixes both sides at 32 bytes regardless of input length).
pub struct AdminAuth;

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        check_budget(state, parts)?;
        let Some(candidate) = extract_bearer(parts) else {
            return Err(record_failed_auth(state, parts));
        };
        let candidate_digest = Sha256::digest(candidate.as_bytes());
        let expected_digest = Sha256::digest(state.config.admin_token.as_bytes());
        let matches: bool = candidate_digest.ct_eq(&expected_digest).into();
        if matches {
            Ok(AdminAuth)
        } else {
            Err(record_failed_auth(state, parts))
        }
    }
}

/// Authenticates a request against a node's own bearer token. Unlike the
/// admin token, this is not a fixed in-process secret being compared —
/// it's a hash lookup against an indexed DB column, so `subtle`'s
/// constant-time comparison doesn't apply the same way here (there's no
/// single secret value whose comparison time could leak anything; every
/// candidate gets exactly one hash + one indexed lookup regardless of
/// whether it matches).
pub struct BearerNode {
    pub node: crate::db::nodes::NodeRow,
}

impl FromRequestParts<AppState> for BearerNode {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        check_budget(state, parts)?;
        let Some(candidate) = extract_bearer(parts) else {
            return Err(record_failed_auth(state, parts));
        };
        let hash = hash_token(candidate);
        let conn = state.db.conn.lock().await;
        let looked_up = crate::db::nodes::find_by_bearer_hash(&conn, &hash);
        drop(conn);
        match looked_up {
            Ok(Some(node)) => Ok(BearerNode { node }),
            Ok(None) => Err(record_failed_auth(state, parts)),
            Err(err) => {
                // Distinguish "checked, and wrong" from "could not
                // check" — see `AuthError::Internal`.
                tracing::error!(error = %err, "bearer token lookup failed");
                Err(AuthError::Internal)
            }
        }
    }
}
