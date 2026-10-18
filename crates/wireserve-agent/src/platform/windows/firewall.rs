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

/// The filters for the mesh adapter `ifname` and this node's own addresses
/// `own`. The terminator's holes (PLAN.md M50) are for its service's own
/// account, which exists once `install` made the service. No carry
/// interface's: the adapter blocks cover it.
pub fn backend(ifname: &str, _carry: Option<String>, own: &[IpAddr], instance: &Instance) -> Result<Backend, Box<dyn std::error::Error>> {
    let terminator = super::security::service_sid(&super::service::tls_service_name(instance))?;
    Ok(WfpBackend::new(ifname, own, terminator.as_deref())?)
}

pub fn own_table(_fw: &Backend) -> OwnTable {
    OwnTable
}

pub fn start_interop(_ifname: &str, _forward_wanted: ForwardWanted, _own_table: OwnTable) -> Interop {
    NoopInterop
}

/// The adapter exists now: its own blocks join the mesh addresses' (see
/// [`super::wfp`]). Failing here leaves the address blocks only, which is
/// not enough to run on.
pub fn after_bring_up(fw: &mut Backend) -> std::io::Result<()> {
    fw.refresh()
}

/// Nothing: the filters went with the session of the run that made them.
pub fn remove_leftover(_name: &str) {}

/// Nothing: a carry adapter goes with the process that made it.
pub fn remove_leftover_carry(_main: &str, _private_key: &str) {}
