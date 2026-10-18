//! What Windows cannot do yet (see `crate::platform`, docs/windows.md).

/// Nothing rewrites a port or forwards elsewhere without a driver of
/// someone's (PLAN.md M50).
pub const REWRITES_PORTS: bool = false;

/// No transit, relaying or exit (PLAN.md M49).
pub const CARRIES_TRAFFIC: bool = false;
