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
    // Sign-in sessions and tickets are swept on this timer too: otherwise
    // only a new session sweeps them, and tickets — which anyone signed in
    // can have made, many a minute — pile up while nobody signs in afresh.
    if let Err(e) = crate::db::sessions::sweep(&*state.db.conn.lock().await, chrono::Utc::now()) {
        tracing::error!(error = %e, "could not sweep idle sign-in sessions and spent tickets");
    }
    let all = match owners::all(&*state.db.conn.lock().await) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "owner refresh: could not read the owners");
            return;
        }
    };
    let mut unreadable = 0usize;
    for owner in all {
        let Some(token) = oidc.open(owner.node_id, &owner.refresh_token_enc) else {
            // Sealed under another key, most likely: WIRESERVE_OIDC_TOKEN_KEY
            // changed. That is not necessarily for good — a secrets file not
            // mounted has the key generated afresh, a restore test or a typo
            // starts with the wrong one — so the owner only goes stale, as
            // if the provider could not be asked, and is back as soon as the
            // right key is. An admin clearing the owner removes it for good.
            unreadable += 1;
            if let Err(e) = owners::refresh_failed(&*state.db.conn.lock().await, owner.node_id, &owner.sub, None) {
                tracing::error!(error = %e, "owner refresh: could not store the outcome");
            }
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
                // The email follows the provider's latest word on it, when
                // it sent one (PLAN.md #275).
                let email = r.email.map(|e| e.unwrap_or_default());
                owners::refreshed(&conn, owner.node_id, &owner.sub, &r.groups, &oidc.seal(owner.node_id, &r.refresh_token), email.as_deref())
            }
            Err(RefreshError::Refused) => {
                tracing::warn!(event = "owner_dropped", node_id = owner.node_id, sub = %owner.sub, reason = "refused");
                owners::remove(&conn, owner.node_id, Some(&owner.sub)).map(|_| ())
            }
            Err(RefreshError::Failed { error, rotated }) => {
                tracing::warn!(node_id = owner.node_id, sub = %owner.sub, error = %error, "owner refresh failed; its groups go stale");
                let sealed = rotated.map(|t| oidc.seal(owner.node_id, &t));
                owners::refresh_failed(&conn, owner.node_id, &owner.sub, sealed.as_deref())
            }
        };
        if let Err(e) = result {
            tracing::error!(error = %e, "owner refresh: could not store the outcome");
        }
    }
    if unreadable > 0 {
        tracing::warn!(
            event = "owner_tokens_unreadable",
            owners = unreadable,
            "device owners' refresh tokens do not open with this token key, so their groups go stale; \
             WIRESERVE_OIDC_TOKEN_KEY has most likely changed (is coordinator-secrets.env mounted?). \
             Start with the key they were sealed with and they recover; if it is gone for good, \
             clear those owners (wireserve-admin owner clear) and make new claim links"
        );
    }
}
