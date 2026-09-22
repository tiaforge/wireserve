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
}
