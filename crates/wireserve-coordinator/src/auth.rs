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

/// Whether this request's source has already spent its failed-attempt
/// budget.
///
/// Consulted before any comparison work, so a source that is over budget
/// and presents a *bad* credential is rejected without the caller having
/// paid for a full verification (security review S3).
///
/// **It does not by itself reject the request**, and that is the
/// correction to S3. The limiter is keyed on a source address, and spec
/// §7 mandates a TLS-terminating reverse proxy in front of this
/// coordinator, so in the deployment the spec actually describes every
/// node shares one key: the proxy's own address. Rejecting purely on the
/// budget therefore meant that ten bad guesses from anyone who could
/// reach the coordinator took *every* node off the mesh until the window
/// expired, because the check ran ahead of authentication and did not
/// care that the credential was perfectly good. Nodes behind one NAT
/// share a key the same way. A brute-force guard that can be turned into
/// a mesh-wide outage by an unauthenticated stranger is worse than the
/// thing it guards against, particularly when the thing it guards against
/// is guessing a 256-bit token.
///
/// So a request that is over budget still gets its credential checked,
/// and is allowed through if the credential is genuinely valid. What an
/// over-budget source cannot do is keep *failing*. The cost of that check
/// is one SHA-256 and one indexed lookup, which is bounded and small; the
/// cost of the alternative is an availability failure in the default
/// topology.
fn over_budget(state: &AppState, parts: &Parts) -> bool {
    source_ip(state, parts).is_some_and(|ip| state.rate_limiter.is_blocked(ip))
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
        // The admin surface keeps the strict early rejection, because the
        // reasoning in `over_budget` does not apply to it: it binds to
        // loopback or an internal address (§4.0), there is exactly one
        // credential and normally one operator, so there is no population
        // of innocent callers sharing the key to be collateral damage.
        if over_budget(state, parts) {
            return Err(AuthError::RateLimited);
        }
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
        let blocked = over_budget(state, parts);
        let Some(candidate) = extract_bearer(parts) else {
            record_failed_auth(state, parts);
            return Err(if blocked {
                AuthError::RateLimited
            } else {
                AuthError::Unauthorized
            });
        };
        let hash = hash_token(candidate);
        let conn = state.db.conn.lock().await;
        let looked_up = crate::db::nodes::find_by_bearer_hash(&conn, &hash);
        drop(conn);
        match looked_up {
            // A valid token is honoured even when the source is over
            // budget: this node has done nothing wrong, and it is very
            // likely sharing a key with whoever did.
            Ok(Some(node)) => Ok(BearerNode { node }),
            Ok(None) => {
                record_failed_auth(state, parts);
                Err(if blocked {
                    AuthError::RateLimited
                } else {
                    AuthError::Unauthorized
                })
            }
            Err(err) => {
                // Distinguish "checked, and wrong" from "could not
                // check" — see `AuthError::Internal`.
                tracing::error!(error = %err, "bearer token lookup failed");
                Err(AuthError::Internal)
            }
        }
    }
}
