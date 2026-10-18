//! The service addresses the host receives on itself, on Linux: local
//! routes for the ones its terminator answers (PLAN.md M33). Every other
//! one is rewritten onto the node's address, and needs none.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

/// Only the terminated ones get a route.
pub const EVERY_SERVICE: bool = false;

// Moves the terminator's local routes from `old` to `new` (see
/// `routes::sync_local`), returning what is routed afterwards. A failure is
/// logged there and never fails the cycle: the route it concerns simply
/// stays as it was, and the firewall still marks only what the directory
/// and the terminator agree on.
pub fn sync(old: &BTreeSet<Ipv4Addr>, new: &BTreeSet<Ipv4Addr>, node: Option<Ipv4Addr>, _ifname: &str) -> BTreeSet<Ipv4Addr> {
    if old == new {
        return old.clone();
    }
    let Some(node) = node else {
        return old.clone();
    };
    crate::platform::routes::sync_local(old, new, node).0
}

/// What a previous run left behind (PLAN.md M33): the routes recorded in
/// the state file, plus any carrying our protocol number inside this
/// instance's own mesh range `range` — a run that crashed between adding a
/// route and saving the state file recorded nothing. Another instance's
/// routes lie in its own range and are left.
#[must_use]
pub fn left_behind(recorded: &[Ipv4Addr], range: Option<&wireserve_types::MeshRanges>) -> Vec<Ipv4Addr> {
    let mut stale: Vec<Ipv4Addr> = recorded.to_vec();
    match super::routes::own_local_routes() {
        Ok(found) => stale.extend(found.into_iter().filter(|a| range.is_some_and(|r| r.contains4(*a)))),
        Err(e) => tracing::warn!(error = %e, "could not list local routes to sweep"),
    }
    stale.sort_unstable();
    stale.dedup();
    stale
}

/// Takes `addrs` away from the host.
pub fn remove(addrs: &[Ipv4Addr]) {
    let _ = super::routes::remove_local(addrs);
}
