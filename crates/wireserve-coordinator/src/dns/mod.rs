//! Public DNS records for services (PLAN.md M32): configuration, the
//! provider behind them, and the loop that keeps them in step with the
//! directory.

pub mod config;
pub mod provider;
pub mod sync;

pub use config::DnsConfig;
pub use sync::{Dns, RecordState};
