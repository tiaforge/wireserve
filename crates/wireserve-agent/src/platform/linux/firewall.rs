//! The firewall on Linux: an nftables table of our own, and the
//! host-firewall interop that keeps the host's firewalls from undoing it
//! (see `crate::firewall`).

use std::net::IpAddr;

use wireserve_types::FirewallBackend;

use super::host_interop::{self, HostInterop};
use super::nftables::{NftablesBackend, SharedRuleset};
use crate::firewall::ForwardWanted;
use crate::paths::Instance;
use crate::wg::{Slot, WgInterface};

pub type Backend = NftablesBackend;
/// Where the interop restores our own table from, if something else on the
/// host removes it (see `nftables::SharedRuleset`).
pub type OwnTable = SharedRuleset;
pub type Interop = HostInterop;

/// The table for the mesh interface `ifname`, its carry interface's
/// (PLAN.md M39), and this node's own addresses `own`.
pub fn backend(ifname: &str, carry: Option<String>, own: &[IpAddr], _instance: &Instance) -> Result<Backend, Box<dyn std::error::Error>> {
    Ok(NftablesBackend::new(ifname.to_string())?.with_carry(carry).with_own(own))
}

#[must_use]
pub fn own_table(fw: &Backend) -> OwnTable {
    fw.last_applied()
}

pub fn start_interop(ifname: &str, forward_wanted: ForwardWanted, own_table: OwnTable) -> Interop {
    HostInterop::start(ifname, forward_wanted, own_table)
}

/// Nothing: the table matches the interface by name from the start.
#[allow(clippy::unnecessary_wraps)]
pub fn after_bring_up(_fw: &mut Backend) -> std::io::Result<()> {
    Ok(())
}

/// The firewall state an interface left behind under another name (see
/// `remove_leftover_interfaces`): its interop openings and its table.
pub fn remove_leftover(name: &str) {
    host_interop::remove_for(name);
    match NftablesBackend::new(name.to_string()) {
        Ok(mut fw) => {
            if let Err(e) = fw.teardown() {
                tracing::warn!(ifname = %name, error = %e, "could not remove its firewall table");
            }
        }
        Err(e) => tracing::warn!(ifname = %name, error = %e, "could not remove its firewall table"),
    }
}

/// Removes the carry interface (PLAN.md M39) that went with the mesh
/// interface `main`, if it is this node's own, with its firewall.
pub fn remove_leftover_carry(main: &str, private_key: &str) {
    let name = crate::wg::carry_ifname(main);
    let Ok(carry) = WgInterface::new(&name) else {
        return;
    };
    if carry.classify(private_key) != Slot::Ours {
        return;
    }
    host_interop::remove_for(&name);
    // The mesh interface's table is gone already; removing it again is
    // a no-op, and this is the one call that knows both.
    if let Ok(fw) = NftablesBackend::new(main.to_string()) {
        let mut fw = fw.with_carry(Some(name.clone()));
        if let Err(e) = fw.teardown() {
            tracing::warn!(ifname = %name, error = %e, "could not remove its firewall table");
        }
    }
    if let Err(e) = super::routes::delete_link(&name) {
        tracing::warn!(ifname = %name, error = %e, "could not remove a leftover carry interface");
    }
}
