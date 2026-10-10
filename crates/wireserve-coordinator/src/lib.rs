pub mod access;
pub mod auth;
pub mod bootstrap;
pub mod client_ip;
pub mod config;
pub mod db;
pub mod directory;
pub mod directory_state;
pub mod dns;
pub mod error;
pub mod install;
pub mod ipam;
pub mod oidc;
pub mod rate_limit;
pub mod reflexive;
pub mod routes;
pub mod setup;
pub mod state;
pub mod tokengen;
pub mod transit;

use std::sync::Arc;

pub use config::Config;
pub use state::AppState;

/// Builds the shared application state from a loaded `Config`. Split out
/// from `main` so integration tests can construct it against a temp-file
/// DB without going through env-var parsing.
pub fn build_state(config: Config, db: db::Db) -> AppState {
    build_state_with_dns(config, db, None)
}

/// [`build_state`], with the DNS writer given rather than none — `main`
/// passes the configured provider, tests a fake.
pub fn build_state_with_dns(
    config: Config,
    db: db::Db,
    dns: Option<Arc<dyn dns::provider::DnsWriter>>,
) -> AppState {
    AppState {
        dns: dns.map(|w| Arc::new(dns::Dns::new(w))),
        db: Arc::new(db),
        rate_limiter: Arc::new(rate_limit::RateLimiter::with_global_budget(
            config.rate_limit_max,
            config.rate_limit_window_secs,
            config.global_auth_failure_max,
            config.global_auth_failure_window_secs,
        )),
        poll_limiter: Arc::new(rate_limit::TokenBuckets::new(config.poll_rate_burst, config.poll_rate_per_min)),
        reach_limiter: Arc::new(rate_limit::TokenBuckets::new(routes::poll::REACH_BURST, routes::poll::REACHES_PER_MIN)),
        challenge_limiter: Arc::new(rate_limit::TokenBuckets::new(
            routes::tls::CHALLENGE_BURST,
            routes::tls::CHALLENGES_PER_MIN,
        )),
        sign_in_limiter: Arc::new(rate_limit::TokenBuckets::new(
            oidc::sign_in::SIGN_IN_BURST,
            oidc::sign_in::SIGN_INS_PER_MIN,
        )),
        redeem_limiter: Arc::new(rate_limit::TokenBuckets::new(
            oidc::sign_in::REDEEM_BURST,
            oidc::sign_in::REDEEMS_PER_MIN,
        )),
        sign_in_start_limiter: Arc::new(rate_limit::SlidingWindowLimiter::new(
            oidc::sign_in::STARTS_PER_MIN,
            60,
        )),
        transit: Arc::new(transit::TransitState::default()),
        oidc: config.oidc.clone().map(|c| Arc::new(oidc::Oidc::new(c))),
        released: Arc::default(),
        directory: Arc::default(),
        full_directory_limit: Arc::new(tokio::sync::Semaphore::new(state::FULL_DIRECTORIES_IN_FLIGHT)),
        probe_udp: std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
            .inspect_err(|e| tracing::warn!(error = %e, "no second UDP socket: nodes can't tell whether they are dialable, and relay ports can't be checked"))
            .ok()
            .map(Arc::new),
        config: Arc::new(config),
    }
}
