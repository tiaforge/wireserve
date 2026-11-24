//! The firewall on Windows: the Windows Filtering Platform ([`super::wfp`];
//! see `crate::firewall`). No host-firewall interop: our sublayer sits
//! above every other firewall's.

use std::net::IpAddr;

use super::wfp::WfpBackend;
use crate::firewall::{ForwardWanted, NoopInterop};
use crate::paths::Instance;

pub type Backend = WfpBackend;
/// Nothing to restore from: no other firewall can remove our filters.
#[derive(Clone)]
pub struct OwnTable;
pub type Interop = NoopInterop;

/// The filters for the mesh adapter `ifname`, this node's own addresses
/// `own` and the mesh's range `mesh` (both blocked for as long as the node
/// is joined, see [`super::wfp`]). The terminator's holes (PLAN.md M51)
/// are for its service's own account, which exists once `install` made
/// the service. No carry interface's: the adapter blocks cover it.
pub fn backend(
    ifname: &str,
    _carry: Option<String>,
    own: &[IpAddr],
    mesh: Option<&wireserve_types::MeshRanges>,
    instance: &Instance,
) -> Result<Backend, Box<dyn std::error::Error>> {
    let terminator = super::security::service_sid(&super::service::tls_service_name(instance))?;
    // The host's addresses a range block must not cover: its own networks,
    // and another VPN's tunnel in the same range — the default range is in
    // 100.64.0.0/10, which Tailscale and others use too, and a lasting
    // block there would close that VPN's address on this host. Our own
    // adapters (another instance's, or the last run's, still being
    // removed) carry the mesh's addresses and do not count.
    let elsewhere: Option<Vec<IpAddr>> = match super::net::host_addresses() {
        Ok(addrs) => Some(addrs.into_iter().filter(|a| !super::net::is_ours_or_loopback(a)).map(|a| a.addr).collect()),
        Err(e) => {
            tracing::warn!(error = %e, "could not list the host's addresses");
            None
        }
    };
    Ok(WfpBackend::new(ifname, instance.name(), own, mesh, elsewhere.as_deref(), terminator.as_deref())?)
}

pub fn own_table(_fw: &Backend) -> OwnTable {
    OwnTable
}

pub fn start_interop(_ifname: &str, _forward_wanted: ForwardWanted, _own_table: OwnTable) -> Interop {
    NoopInterop
}

/// The adapter exists now: its own blocks join the lasting ones (see
/// [`super::wfp`]). Failing here leaves the lasting blocks only, which is
/// not enough to run on.
pub fn after_bring_up(fw: &mut Backend) -> std::io::Result<()> {
    fw.refresh()
}

/// After `leave` and the adapter's removal: the blocks that outlive a stop
/// go too, as nothing joined is left for them to guard.
pub fn after_leave(fw: &mut Backend) {
    if let Err(e) = fw.forget() {
        tracing::warn!(error = %e, "could not remove the firewall's blocks; `wireserve leave` removes them again");
    }
}

/// Nothing: the session's filters went with the run that made them, and
/// the lasting blocks belong to the instance, not to an interface name —
/// this start has just replaced them.
pub fn remove_leftover(_name: &str) {}

/// Nothing: a carry adapter goes with the process that made it.
pub fn remove_leftover_carry(_main: &str, _private_key: &str) {}
