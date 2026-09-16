use std::sync::Arc;

use crate::config::Config;
use crate::db::Db;
use crate::rate_limit::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub config: Arc<Config>,
    pub rate_limiter: Arc<RateLimiter>,
}
