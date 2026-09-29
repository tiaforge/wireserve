//! `POST`/`DELETE /tls/challenge` (PLAN.md M33): a node asks the
//! coordinator to publish, or withdraw, one ACME DNS-01 challenge value for
//! one of its own service names.
//!
//! This is how a node gets a certificate while its private key never
//! leaves it and the DNS credential never leaves the coordinator — the
//! arrangement Tailscale uses for `*.ts.net`. The coordinator is the one
//! deciding which names a node may prove control of: its own, approved,
//! published on TCP 443 with an address of their own, and under the service
//! domain. Anything else would let one node obtain a certificate for
//! another's name.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::Deserialize;

use crate::auth::BearerNode;
use crate::db::{services, tls};
use crate::error::AppError;
use crate::state::AppState;

/// How long a published value lives unless withdrawn sooner. An order is
/// validated within a minute or two; this only bounds what a node that
/// crashed mid-order leaves behind.
const CHALLENGE_TTL_MINUTES: i64 = 10;

/// What one node may ask for, at once and then per minute. Every new value
/// is a write to the operator's DNS provider, and a later removal of it
/// another; a node looping on this would spend the provider's API allowance
/// and stop every other record and certificate with it. A real order is one
/// value, and the terminator issues one name at a time, each waiting a minute
/// or more for the record to propagate.
pub const CHALLENGE_BURST: u32 = 10;
pub const CHALLENGES_PER_MIN: u32 = 3;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeBody {
    pub fqdn: String,
    pub value: String,
}

pub async fn add(
    State(state): State<AppState>,
    BearerNode { node }: BearerNode,
    Json(body): Json<ChallengeBody>,
) -> Result<StatusCode, AppError> {
    let (dns, record) = authorize(&state, &node, &body).await?;
    if let crate::rate_limit::Take::Refused { log } = state.challenge_limiter.take(node.id) {
        if log {
            tracing::warn!(event = "challenge_rate_limited", node_name = %node.name, fqdn = %record, "asking for challenge records faster than the per-node limit");
        }
        return Err(AppError::TooManyRequests);
    }
    let expires = Utc::now() + chrono::Duration::minutes(CHALLENGE_TTL_MINUTES);
    {
        let conn = state.db.conn.lock().await;
        match tls::add_challenge(&conn, &record, &body.value, node.id, expires)? {
            tls::AddOutcome::TooMany => return Err(AppError::TooManyRequests),
            tls::AddOutcome::Refreshed => return Ok(StatusCode::OK),
            tls::AddOutcome::Added => {}
        }
    }
    // Written here rather than by the sync loop, so the node knows when the
    // record exists and can time its request to the CA from that. The lock
    // is not held across the provider call.
    match dns.writer.add_txt(&record, &body.value).await {
        Ok(()) => {
            tls::mark_written(&*state.db.conn.lock().await, &record, &body.value)?;
            tracing::info!(event = "acme_challenge_published", node_name = %node.name, fqdn = %record);
            Ok(StatusCode::CREATED)
        }
        Err(e) => {
            tls::delete_challenge(&*state.db.conn.lock().await, &record, &body.value)?;
            tracing::warn!(node_name = %node.name, fqdn = %record, error = %e, "could not publish an ACME challenge");
            Err(AppError::Conflict(format!("the DNS provider refused the challenge record: {e}")))
        }
    }
}

pub async fn remove(
    State(state): State<AppState>,
    BearerNode { node }: BearerNode,
    Json(body): Json<ChallengeBody>,
) -> Result<StatusCode, AppError> {
    let fqdn = body.fqdn.trim_end_matches('.').to_ascii_lowercase();
    let record = wireserve_types::tls::challenge_name(&fqdn);
    let expired = tls::expire_challenge(&*state.db.conn.lock().await, &record, &body.value, node.id)?;
    if expired {
        // The sync loop removes it; poke it rather than wait a minute.
        state.poke_dns();
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Who may prove control of `body.fqdn`: see the module doc. Returns the
/// DNS handle and the challenge record's name.
async fn authorize(
    state: &AppState,
    node: &crate::db::nodes::NodeRow,
    body: &ChallengeBody,
) -> Result<(std::sync::Arc<crate::dns::Dns>, String), AppError> {
    let Some(dns) = state.dns.clone() else {
        return Err(AppError::Conflict("this coordinator publishes no DNS records, so it cannot publish challenges".into()));
    };
    let Some(domain) = state.config.service_domain.as_deref() else {
        return Err(AppError::Conflict("no service domain is set".into()));
    };
    if !wireserve_types::tls::is_challenge_value(&body.value) {
        return Err(AppError::BadRequest("value is not a DNS-01 challenge digest".into()));
    }
    let fqdn = body.fqdn.trim_end_matches('.').to_ascii_lowercase();
    let name = fqdn
        .strip_suffix(domain)
        .and_then(|rest| rest.strip_suffix('.'))
        .filter(|label| wireserve_types::is_valid_dns_label(label))
        .ok_or_else(|| AppError::Forbidden(format!("{fqdn} is not a service name under {domain}")))?
        .to_string();

    let conn = state.db.conn.lock().await;
    let refuse = |why: &str| Err(AppError::Forbidden(format!("{fqdn}: {why}")));
    let Some(service) = services::find_by_name(&conn, &name)? else {
        return refuse("no such service");
    };
    if service.node_id != node.id {
        return refuse("that service is not this node's");
    }
    if !service.is_approved() {
        return refuse("that service is not approved");
    }
    let tls_port = service.ports.iter()
        .any(|m| m.public == wireserve_types::TLS_PUBLIC_PORT && m.proto == wireserve_types::Proto::Tcp);
    if service.vip4.is_none() || !tls_port {
        return refuse("that service is not published on TCP 443 with an address of its own");
    }
    Ok((dns, wireserve_types::tls::challenge_name(&fqdn)))
}
