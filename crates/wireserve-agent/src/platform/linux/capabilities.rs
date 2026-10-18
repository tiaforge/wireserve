//! What Linux can do that not every platform can (see `crate::platform`).

/// nftables rewrites a service address's public port to its target, and
/// forwards to another address (PLAN.md M26).
pub const REWRITES_PORTS: bool = true;

/// Transit, relaying and exit (PLAN.md M23, M27, M39, M40).
pub const CARRIES_TRAFFIC: bool = true;
