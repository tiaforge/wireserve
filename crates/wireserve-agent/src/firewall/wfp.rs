//! The Windows firewall backend: the Windows Filtering Platform, directly.
//!
//! A Windows node is a mesh member that serves nothing (no services, no
//! transit, no exit), so its ruleset is the default-deny alone: every new
//! inbound connection over the mesh is refused, and replies to the node's
//! own connections come back as they belong to flows it opened — WFP's
//! ALE layers only ever see the first packet of a flow, which is what
//! nftables' `ct state established` amounts to on Linux.
//!
//! Why WFP and not Windows Defender Firewall rules (PLAN.md #338): the blocks
//! sit in a sublayer of our own at the highest weight and clear the
//! action right, so no other firewall on the host — Defender, or whatever
//! replaced it, all of them WFP clients — can permit what they refuse;
//! they hold whether Defender is on or off and whatever network profile
//! Windows gave the adapter; and a ruleset is replaced in one transaction,
//! like `nft -f`.
//!
//! The filters match two ways, both at `ALE_AUTH_RECV_ACCEPT_V4/V6`:
//! - the node's **mesh addresses**, known from its state before the adapter
//!   exists — so the default-deny is in place before bring-up, as spec §5
//!   asks, with `guarded_bring_up`'s order unchanged;
//! - the **adapter** (its LUID), once it is up: inbound traffic on the mesh
//!   adapter addressed to any other of the host's addresses.
//!
//! Loopback is exempt, as it is on Linux (where the table matches on the
//! mesh interface's name): the host reaching its own mesh address is not
//! traffic from the mesh.
//!
//! The session is dynamic: everything in it goes when the agent's process
//! does. A Windows agent that dies takes its adapter with it (see
//! `wg::nt`), so there is nothing left for the filters to guard.

use std::io;
use std::net::IpAddr;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{FWP_E_FILTER_NOT_FOUND, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0, FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_ADDRESS,
    FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_BYTE_ARRAY16,
    FWP_BYTE_ARRAY16_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_EMPTY, FWP_MATCH_EQUAL,
    FWP_MATCH_FLAGS_NONE_SET, FWP_UINT32, FWP_UINT64, FWP_VALUE0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use wireserve_types::{FirewallBackend, Forwarding, ServiceRule};

use crate::winnet::{self, wide};

/// This instance's sublayer, named after its interface. Not one shared
/// by every agent on the host: what a dynamic session adds, only that
/// session may use (`FWP_E_WRONG_SESSION`), so a second instance could
/// not put its filters into a sublayer the first one made. Only one
/// running agent holds an interface name (`lock::IfnameClaim`).
fn sublayer_key(ifname: &str) -> GUID {
    crate::wg::nt::name_guid(&format!("wireserve-wfp-sublayer:{ifname}"))
}

/// The highest weight a sublayer can have: ours is consulted first.
const SUBLAYER_WEIGHT: u16 = u16::MAX;

/// What makes a filter one of ours: its layer and its one matching condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Match {
    LocalAddress(IpAddr),
    /// The adapter, on one IP version's layer.
    Interface { luid: u64, v6: bool },
}

impl Match {
    fn layer(self) -> GUID {
        let v6 = match self {
            Match::LocalAddress(addr) => addr.is_ipv6(),
            Match::Interface { v6, .. } => v6,
        };
        if v6 {
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
        } else {
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
        }
    }
}

/// The blocks for these mesh addresses, and the adapter when it is up.
fn wanted(own: &[IpAddr], luid: Option<u64>) -> Vec<Match> {
    let mut out: Vec<Match> = own.iter().copied().map(Match::LocalAddress).collect();
    if let Some(luid) = luid {
        out.push(Match::Interface { luid, v6: false });
        out.push(Match::Interface { luid, v6: true });
    }
    out
}

fn check(what: &str, code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!("{what}: {}", io::Error::from_raw_os_error(code as i32))))
    }
}

/// See the module documentation.
pub struct WfpBackend {
    ifname: String,
    own: Vec<IpAddr>,
    engine: HANDLE,
    sublayer: GUID,
    /// What is in place now, with the id WFP gave each filter.
    applied: Vec<(Match, u64)>,
    /// Logged once: a Windows node declaring services is refused before it
    /// gets here, so this should never be seen.
    warned_rules: bool,
}

// SAFETY: a WFP engine handle may be used from any thread, one call at a
// time, which `&mut self` ensures.
unsafe impl Send for WfpBackend {}

impl Drop for WfpBackend {
    fn drop(&mut self) {
        // SAFETY: our own engine handle, closed once. Closing a dynamic
        // session removes everything added through it.
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

impl WfpBackend {
    /// Opens a dynamic session and makes sure our sublayer exists. `own`
    /// is the node's mesh addresses, which are blocked from the first
    /// `apply` on, adapter or not.
    pub fn new(ifname: &str, own: &[IpAddr]) -> io::Result<Self> {
        let mut name = wide("wireserve");
        let mut session_name = wide(&format!("wireserve agent ({ifname})"));
        // SAFETY: all-zero is a valid FWPM_SESSION0 to fill in.
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.displayData.name = session_name.as_mut_ptr();
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        let mut engine: HANDLE = std::ptr::null_mut();
        // SAFETY: a session that outlives the call; `engine` is written by it.
        check("opening the Windows Filtering Platform", unsafe {
            FwpmEngineOpen0(std::ptr::null(), RPC_C_AUTHN_WINNT, std::ptr::null(), &session, &mut engine)
        })?;
        let backend = Self {
            ifname: ifname.to_string(),
            own: own.to_vec(),
            engine,
            sublayer: sublayer_key(ifname),
            applied: Vec::new(),
            warned_rules: false,
        };

        // SAFETY: all-zero is a valid FWPM_SUBLAYER0 to fill in.
        let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sublayer.subLayerKey = backend.sublayer;
        sublayer.displayData = FWPM_DISPLAY_DATA0 { name: name.as_mut_ptr(), description: std::ptr::null_mut() };
        sublayer.weight = SUBLAYER_WEIGHT;
        // SAFETY: a sublayer description that outlives the call.
        check("adding the wireserve sublayer", unsafe {
            FwpmSubLayerAdd0(backend.engine, &sublayer, std::ptr::null_mut())
        })?;
        Ok(backend)
    }

    /// Adds the adapter's blocks once it exists — called after bring-up.
    /// The next `apply` would too; this does not wait for it.
    pub fn refresh(&mut self) -> io::Result<()> {
        self.replace()
    }

    /// Makes the filters in place exactly the wanted ones, in one
    /// transaction: either all of the change happens, or none of it.
    fn replace(&mut self) -> io::Result<()> {
        let luid = winnet::luid_by_alias(&self.ifname)?.map(|l| {
            // SAFETY: the LUID union's plain 64-bit view.
            unsafe { l.Value }
        });
        let wanted = wanted(&self.own, luid);
        if self.applied.iter().map(|(m, _)| *m).eq(wanted.iter().copied()) {
            return Ok(());
        }
        // SAFETY: our engine handle.
        check("starting a filter transaction", unsafe { FwpmTransactionBegin0(self.engine, 0) })?;
        match self.replace_in_transaction(&wanted) {
            Ok(applied) => {
                // SAFETY: the transaction begun above.
                check("committing the filter transaction", unsafe { FwpmTransactionCommit0(self.engine) })?;
                self.applied = applied;
                Ok(())
            }
            Err(e) => {
                // SAFETY: the transaction begun above.
                unsafe { FwpmTransactionAbort0(self.engine) };
                Err(e)
            }
        }
    }

    fn replace_in_transaction(&self, wanted: &[Match]) -> io::Result<Vec<(Match, u64)>> {
        for (_, id) in &self.applied {
            // SAFETY: a filter id this session added.
            match unsafe { FwpmFilterDeleteById0(self.engine, *id) } {
                // The WFP functions return the HRESULT as a `u32`.
                0 => {}
                code if code == FWP_E_FILTER_NOT_FOUND as u32 => {}
                code => check("removing a filter", code)?,
            }
        }
        wanted.iter().map(|m| Ok((*m, self.add_block(*m)?))).collect()
    }

    fn add_block(&self, m: Match) -> io::Result<u64> {
        let mut name = wide(&format!("wireserve: block inbound on {}", self.ifname));
        // Values the conditions point at, alive until FwpmFilterAdd0 returns.
        let mut v6 = FWP_BYTE_ARRAY16 { byteArray16: [0; 16] };
        let mut luid_value: u64 = match m {
            Match::Interface { luid, .. } => luid,
            Match::LocalAddress(_) => 0,
        };
        // SAFETY: all-zero is a valid FWP_CONDITION_VALUE0 to fill in.
        let mut value: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
        let field = match m {
            Match::LocalAddress(IpAddr::V4(a)) => {
                value.r#type = FWP_UINT32;
                // Host byte order, as WFP takes IPv4 addresses.
                value.Anonymous.uint32 = u32::from(a);
                FWPM_CONDITION_IP_LOCAL_ADDRESS
            }
            Match::LocalAddress(IpAddr::V6(a)) => {
                v6.byteArray16 = a.octets();
                value.r#type = FWP_BYTE_ARRAY16_TYPE;
                value.Anonymous.byteArray16 = &mut v6;
                FWPM_CONDITION_IP_LOCAL_ADDRESS
            }
            Match::Interface { .. } => {
                value.r#type = FWP_UINT64;
                value.Anonymous.uint64 = &mut luid_value;
                FWPM_CONDITION_IP_LOCAL_INTERFACE
            }
        };
        // SAFETY: all-zero is a valid FWP_CONDITION_VALUE0 to fill in.
        let mut not_loopback: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
        not_loopback.r#type = FWP_UINT32;
        not_loopback.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
        let mut conditions = [
            FWPM_FILTER_CONDITION0 { fieldKey: field, matchType: FWP_MATCH_EQUAL, conditionValue: value },
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_FLAGS,
                matchType: FWP_MATCH_FLAGS_NONE_SET,
                conditionValue: not_loopback,
            },
        ];

        // SAFETY: all-zero is a valid FWPM_FILTER0 to fill in.
        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        filter.displayData = FWPM_DISPLAY_DATA0 { name: name.as_mut_ptr(), description: std::ptr::null_mut() };
        // A hard block: nothing in a lower sublayer, callouts included, can
        // turn it into a permit.
        filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        filter.layerKey = m.layer();
        filter.subLayerKey = self.sublayer;
        filter.weight = FWP_VALUE0 { r#type: FWP_EMPTY, Anonymous: unsafe { std::mem::zeroed() } };
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = conditions.as_mut_ptr();
        // SAFETY: all-zero is a valid action union to set the type of.
        filter.action = FWPM_ACTION0 { r#type: FWP_ACTION_BLOCK, Anonymous: unsafe { std::mem::zeroed() } };
        let mut id = 0u64;
        // SAFETY: the filter and everything it points at outlive the call.
        check("adding a block filter", unsafe { FwpmFilterAdd0(self.engine, &filter, std::ptr::null_mut(), &mut id) })?;
        Ok(id)
    }
}

impl FirewallBackend for WfpBackend {
    type Error = io::Error;

    /// The default-deny, and nothing else: a Windows node serves nothing
    /// (PLAN.md M49), so `rules` and `forwarding` are always empty here.
    fn apply(&mut self, rules: &[ServiceRule], forwarding: &Forwarding) -> Result<(), Self::Error> {
        if (!rules.is_empty() || *forwarding != Forwarding::default()) && !self.warned_rules {
            tracing::warn!("services and forwarding are not supported on Windows; inbound traffic stays blocked");
            self.warned_rules = true;
        }
        self.replace()
    }

    fn teardown(&mut self) -> Result<(), Self::Error> {
        // SAFETY: our engine handle.
        check("starting a filter transaction", unsafe { FwpmTransactionBegin0(self.engine, 0) })?;
        let result = self.replace_in_transaction(&[]);
        match result {
            Ok(_) => {
                // SAFETY: the transaction begun above.
                check("committing the filter transaction", unsafe { FwpmTransactionCommit0(self.engine) })?;
                self.applied.clear();
                Ok(())
            }
            Err(e) => {
                // SAFETY: the transaction begun above.
                unsafe { FwpmTransactionAbort0(self.engine) };
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn the_mesh_addresses_are_blocked_before_there_is_an_adapter() {
        let own = [IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7)), IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 7))];
        let before = wanted(&own, None);
        assert_eq!(before, vec![Match::LocalAddress(own[0]), Match::LocalAddress(own[1])]);
        assert_eq!(before[0].layer().data1, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4.data1);
        assert_eq!(before[1].layer().data1, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6.data1);

        let after = wanted(&own, Some(42));
        assert_eq!(after.len(), 4);
        assert!(after.contains(&Match::Interface { luid: 42, v6: false }));
        assert!(after.contains(&Match::Interface { luid: 42, v6: true }));
    }

    /// Against the real filtering engine: the blocks go in, are visible to
    /// another session while this one holds them, and are gone after a
    /// teardown — and again when the session closes. Needs an elevated run.
    #[test]
    fn kernel_blocks_go_in_and_come_out_with_the_session() {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{FwpmFilterGetById0, FwpmFreeMemory0};

        if !crate::winsec::is_elevated().unwrap_or(false) {
            assert!(std::env::var_os("WIRESERVE_TEST_STRICT").is_none(), "would skip under WIRESERVE_TEST_STRICT: not elevated");
            eprintln!("SKIPPED: not elevated: the filtering engine takes an administrator");
            return;
        }
        // Another session, to look at what ours did from outside it.
        let observer = WfpBackend::new("observer", &[]).unwrap();
        let exists = |id: u64| {
            let mut filter: *mut FWPM_FILTER0 = std::ptr::null_mut();
            // SAFETY: an observer session; the result is freed straight away.
            let code = unsafe { FwpmFilterGetById0(observer.engine, id, &mut filter) };
            if code == 0 {
                unsafe { FwpmFreeMemory0(std::ptr::from_mut(&mut filter).cast()) };
            }
            code == 0
        };

        let own = [IpAddr::V4(Ipv4Addr::new(100, 64, 251, 1)), IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xfb, 1))];
        let mut fw = WfpBackend::new("wireserve-no-such-adapter", &own).unwrap();
        crate::firewall::startup_sequence(&mut fw).unwrap();
        let ids: Vec<u64> = fw.applied.iter().map(|(_, id)| *id).collect();
        assert_eq!(ids.len(), 2, "one block per mesh address, no adapter yet");
        assert!(ids.iter().all(|id| exists(*id)));

        // Applying the same again changes nothing.
        fw.apply(&[], &Forwarding::default()).unwrap();
        assert_eq!(fw.applied.iter().map(|(_, id)| *id).collect::<Vec<_>>(), ids);

        fw.teardown().unwrap();
        assert!(ids.iter().all(|id| !exists(*id)), "teardown left a filter behind");

        // With a real adapter of that name, its own blocks join in.
        let name = format!("wsfw{}", std::process::id() % 100_000);
        let mut adapter = crate::wg::nt::NtApi::new(name.clone()).unwrap();
        match adapter.create_interface() {
            Ok(()) => {
                let mut fw = WfpBackend::new(&name, &own).unwrap();
                crate::firewall::startup_sequence(&mut fw).unwrap();
                fw.refresh().unwrap();
                assert_eq!(fw.applied.len(), 4, "two address blocks and the adapter's two");
                let ids: Vec<u64> = fw.applied.iter().map(|(_, id)| *id).collect();
                assert!(ids.iter().all(|id| exists(*id)));
                drop(fw);
                adapter.remove_interface();
            }
            Err(e) => {
                assert!(std::env::var_os("WIRESERVE_TEST_STRICT").is_none(), "would skip the adapter part: {e}");
                eprintln!("SKIPPED the adapter part: {e}");
            }
        }

        fw.apply(&[], &Forwarding::default()).unwrap();
        let ids: Vec<u64> = fw.applied.iter().map(|(_, id)| *id).collect();
        drop(fw);
        assert!(ids.iter().all(|id| !exists(*id)), "a filter outlived its session");
    }
}
