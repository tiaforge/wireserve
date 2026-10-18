//! The service addresses the host receives on itself, on Windows (PLAN.md
//! M50): every one of its services', as addresses of the mesh adapter.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

/// Every service's: nothing rewrites one, so whatever answers it receives
/// it unchanged — and the terminator binds an address before it says it
/// serves it.
pub const EVERY_SERVICE: bool = true;

/// Windows (PLAN.md M50): the service addresses, as addresses of the mesh
/// adapter itself — what the host receives on, nothing rewriting them. Read
/// back from the adapter every time, not only on a change: one that came
/// back up has none.
pub fn sync(old: &BTreeSet<Ipv4Addr>, new: &BTreeSet<Ipv4Addr>, _node: Option<Ipv4Addr>, ifname: &str) -> BTreeSet<Ipv4Addr> {
    let luid = match super::net::luid_by_alias(ifname) {
        Ok(Some(luid)) => luid,
        Ok(None) => return BTreeSet::new(),
        Err(e) => {
            tracing::warn!(error = %e, "could not find the mesh adapter to give it its service addresses");
            return old.clone();
        }
    };
    let (now, result) = super::net::sync_service_addresses(luid, old, new);
    if let Err(e) = result {
        tracing::warn!(error = %e, "could not move every service address onto the mesh adapter");
    }
    now
}

/// Nothing: a previous run's service addresses went with its adapter.
#[must_use]
pub fn left_behind(_recorded: &[Ipv4Addr], _range: Option<&wireserve_types::MeshRanges>) -> Vec<Ipv4Addr> {
    Vec::new()
}

/// Nothing: they go with the adapter, which goes next.
pub fn remove(_addrs: &[Ipv4Addr]) {}
