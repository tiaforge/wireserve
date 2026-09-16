//! Two deliberately separate auth extractors. Spec §4.0 is explicit that
//! the admin trust surface and the per-node bearer-token surface must
//! never blur together in code — so `AdminAuth` and `BearerNode` do not
//! share a "check either token type" helper, even though the header
//! parsing looks superficially similar.

use std::net::SocketAddr;

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
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AuthError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                Json(wireserve_types::ErrorBody {
                    error: "unauthorized".to_string(),
                }),
            )
                .into_response(),
            AuthError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                Json(wireserve_types::ErrorBody {
                    error: "too many requests".to_string(),
                }),
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

/// Consulted only on the failed-auth path (spec §7: "basic rate limiting
/// on /register and on failed-auth responses from any endpoint") —
/// successful auth never touches the limiter. Once a source IP has
/// exhausted its failed-attempt budget, further failures from it get 429
/// instead of 401, until the window rolls over.
fn record_failed_auth(state: &AppState, parts: &Parts) -> AuthError {
    let ip = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());
    match ip {
        Some(ip) if !state.rate_limiter.check(ip) => AuthError::RateLimited,
        _ => AuthError::Unauthorized,
    }
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
        let Some(candidate) = extract_bearer(parts) else {
            return Err(record_failed_auth(state, parts));
        };
        let hash = hash_token(candidate);
        let conn = state.db.conn.lock().await;
        let node = crate::db::nodes::find_by_bearer_hash(&conn, &hash).ok().flatten();
        drop(conn);
        match node {
            Some(node) => Ok(BearerNode { node }),
            None => Err(record_failed_auth(state, parts)),
        }
    }
}
