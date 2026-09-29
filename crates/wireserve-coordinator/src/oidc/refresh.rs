//! Keeps each device owner's groups current (PLAN.md M38): every
//! `WIRESERVE_OIDC_REFRESH_SECS`, each owner's refresh token is exchanged
//! for their groups as the identity provider has them now.
//!
//! A provider refusing the token (`invalid_grant`) ends the ownership: the
//! node keeps its tags and `everyone`, and nothing its owner's groups gave
//! it. Any other failure marks the owner stale; its groups keep counting for
//! an hour (`owners::STALE_AFTER`), so a provider down for a moment does not
//! lock anyone out, and stop counting after that.

use std::sync::Arc;

use super::{Oidc, RefreshError};
use crate::db::owners;
use crate::state::AppState;

/// Runs forever: a first pass shortly after start, then one per interval.
pub async fn run(state: AppState, oidc: Arc<Oidc>) {
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    loop {
        pass(&state, &oidc).await;
        tokio::time::sleep(oidc.config.refresh_interval).await;
    }
}

/// One refresh of every owner. The database is locked per owner, never
/// across a call to the provider.
pub async fn pass(state: &AppState, oidc: &Oidc) {
    let all = match owners::all(&*state.db.conn.lock().await) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "owner refresh: could not read the owners");
            return;
        }
    };
    for owner in all {
        let Some(token) = oidc.open(owner.node_id, &owner.refresh_token_enc) else {
            // Sealed under another key (WIRESERVE_OIDC_TOKEN_KEY changed), or
            // damaged: it can never be used again.
            tracing::warn!(event = "owner_dropped", node_id = owner.node_id, sub = %owner.sub, reason = "unreadable_token");
            let _ = owners::remove(&*state.db.conn.lock().await, owner.node_id, Some(&owner.sub));
            continue;
        };
        let outcome = oidc.refresh(&token, &owner.sub).await;
        let conn = state.db.conn.lock().await;
        let result = match outcome {
            Ok(r) => {
                tracing::info!(event = "owner_refreshed", node_id = owner.node_id, sub = %owner.sub);
                if r.groups != owner.groups {
                    tracing::info!(
                        event = "owner_groups_changed",
                        node_id = owner.node_id,
                        sub = %owner.sub,
                        groups = %r.groups.join(","),
                    );
                }
                owners::refreshed(&conn, owner.node_id, &owner.sub, &r.groups, &oidc.seal(owner.node_id, &r.refresh_token))
            }
            Err(RefreshError::Refused) => {
                tracing::warn!(event = "owner_dropped", node_id = owner.node_id, sub = %owner.sub, reason = "refused");
                owners::remove(&conn, owner.node_id, Some(&owner.sub)).map(|_| ())
            }
            Err(RefreshError::Failed(e)) => {
                tracing::warn!(node_id = owner.node_id, sub = %owner.sub, error = %e, "owner refresh failed; its groups go stale");
                owners::refresh_failed(&conn, owner.node_id, &owner.sub)
            }
        };
        if let Err(e) = result {
            tracing::error!(error = %e, "owner refresh: could not store the outcome");
        }
    }
}
