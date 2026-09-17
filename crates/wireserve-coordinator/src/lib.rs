pub mod auth;
pub mod client_ip;
pub mod config;
pub mod db;
pub mod directory;
pub mod error;
pub mod ipam;
pub mod rate_limit;
pub mod routes;
pub mod state;
pub mod tokengen;

use std::sync::Arc;

pub use config::Config;
pub use state::AppState;

/// Builds the shared application state from a loaded `Config`. Split out
/// from `main` so integration tests can construct it against a temp-file
/// DB without going through env-var parsing.
pub fn build_state(config: Config, db: db::Db) -> AppState {
    AppState {
        db: Arc::new(db),
        rate_limiter: Arc::new(rate_limit::RateLimiter::with_global_budget(
            config.rate_limit_max,
            config.rate_limit_window_secs,
            config.global_auth_failure_max,
            config.global_auth_failure_window_secs,
        )),
        config: Arc::new(config),
    }
}
