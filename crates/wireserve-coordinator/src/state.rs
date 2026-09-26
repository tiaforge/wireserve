use std::sync::Arc;

use crate::config::Config;
use crate::db::Db;
use crate::rate_limit::RateLimiter;
use crate::transit::TransitState;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub config: Arc<Config>,
    pub rate_limiter: Arc<RateLimiter>,
    /// Ephemeral transit-selection state (PLAN.md M23) — see
    /// `transit::TransitState`'s module doc for why this lives in memory
    /// rather than the database.
    pub transit: Arc<TransitState>,
    /// The public DNS sync (PLAN.md M32), when a provider is configured.
    pub dns: Option<Arc<crate::dns::Dns>>,
}

impl AppState {
    /// Tells the DNS sync the directory may have changed. Cheap and safe to
    /// call from any handler: pokes coalesce, and the loop spaces its passes.
    pub fn poke_dns(&self) {
        if let Some(dns) = &self.dns {
            dns.wake.notify_one();
        }
    }
}
