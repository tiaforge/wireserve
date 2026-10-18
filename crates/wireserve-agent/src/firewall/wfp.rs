//! The Windows firewall backend: the Windows Filtering Platform, directly.
//!
//! A Windows node is a mesh member whose ruleset is the default-deny with
//! holes for its services (PLAN.md M50) and nothing else: no transit, no
//! exit. Every new inbound connection over the mesh is refused but those,
//! and replies to the node's own connections come back as they belong to
//! flows it opened — WFP's ALE layers only ever see the first packet of a
//! flow, which is what nftables' `ct state established` amounts to on
//! Linux.
//!
//! Why WFP and not Windows Defender Firewall rules (PLAN.md #338): the blocks
//! sit in a sublayer of our own at the highest weight and clear the
//! action right, so no other firewall on the host — Defender, or whatever
//! replaced it, all of them WFP clients — can permit what they refuse;
//! they hold whether Defender is on or off and whatever network profile
//! Windows gave the adapter; and a ruleset is replaced in one transaction,
//! like `nft -f`.
//!
//! The blocks match two ways, both at `ALE_AUTH_RECV_ACCEPT_V4/V6`:
//! - the node's **mesh addresses**, known from its state before the adapter
//!   exists — so the default-deny is in place before bring-up, as spec §5
//!   asks, with `guarded_bring_up`'s order unchanged;
//! - the **adapter** (its LUID), once it is up: inbound traffic on the mesh
//!   adapter addressed to any other of the host's addresses, its services'
//!   among them.
//!
//! Loopback is exempt, as it is on Linux (where the table matches on the
//! mesh interface's name): the host reaching its own mesh address is not
//! traffic from the mesh.
//!
//! A service's hole is a **permit** in the same sublayer, weighted above
//! the blocks: on the adapter, to the service's address and public port,
//! from the addresses its grants admit. Nothing here rewrites a port, as
//! nftables does, so a mapping whose public port is not its target is not
//! opened (`serve` refuses one on Windows): the service address is the
//! host's own (`winnet::sync_service_addresses`), and whatever listens on
//! the port there — the backend, on every address — answers it. The TLS
//! terminator's 443 and 80 are permitted only to connections its own
//! account accepts (`ALE_USER_ID`), so no other process can answer them in
//! its place, as only the terminator's socket gets the rewrite on Linux.
//!
//! The session is dynamic: everything in it goes when the agent's process
//! does. A Windows agent that dies takes its adapter with it (see
//! `wg::nt`), so there is nothing left for the filters to guard.

use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr};

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{FWP_E_FILTER_NOT_FOUND, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0, FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_IP_LOCAL_ADDRESS, FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_LOCAL_PORT,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK,
    FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB, FWP_CONDITION_FLAG_IS_LOOPBACK,
    FWP_CONDITION_VALUE0, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_NONE_SET, FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT16,
    FWP_UINT32, FWP_UINT64, FWP_UINT8, FWP_VALUE0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use wireserve_types::{FirewallBackend, Forwarding, Proto, ServiceRule};

use crate::winnet::{self, wide};
use crate::winsec::SecurityDescriptor;

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

/// Weight ranges (0-15) within our sublayer: a permit is consulted before
/// any block, and the first matching filter decides.
const BLOCK_WEIGHT: u8 = 1;
const PERMIT_WEIGHT: u8 = 15;

/// One service's hole in the default-deny (PLAN.md M50): new connections
/// to `vip:port` over `proto` on the mesh adapter, from `sources` (anyone
/// when `None`), and with `terminator` only those its account accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Permit {
    vip: Ipv4Addr,
    port: u16,
    proto: Proto,
    sources: Option<Vec<Ipv4Addr>>,
    terminator: bool,
}

/// One of our filters, by what it matches: its layer and its conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Match {
    LocalAddress(IpAddr),
    /// The adapter, on one IP version's layer.
    Interface { luid: u64, v6: bool },
    /// A service's hole, on the adapter.
    Permit { luid: u64, permit: Permit },
}

impl Match {
    fn layer(&self) -> GUID {
        let v6 = match self {
            Match::LocalAddress(addr) => addr.is_ipv6(),
            Match::Interface { v6, .. } => *v6,
            Match::Permit { .. } => false,
        };
        if v6 {
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
        } else {
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
        }
    }
}

/// The blocks for these mesh addresses, and when the adapter is up its own
/// blocks and the services' permits.
fn wanted(own: &[IpAddr], luid: Option<u64>, permits: &[Permit]) -> Vec<Match> {
    let mut out: Vec<Match> = own.iter().copied().map(Match::LocalAddress).collect();
    if let Some(luid) = luid {
        out.push(Match::Interface { luid, v6: false });
        out.push(Match::Interface { luid, v6: true });
        out.extend(permits.iter().map(|p| Match::Permit { luid, permit: p.clone() }));
    }
    out
}

/// The permits `rules` call for, and why each of the others is not opened
/// here. `terminator` is whether the terminator's account is known: its
/// holes are only ever opened to it.
fn permits(rules: &[ServiceRule], terminator: bool) -> (Vec<Permit>, Vec<String>) {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for rule in rules {
        let (vip, port, proto, sources, by_terminator) = match rule {
            ServiceRule::Mapped { vip, map, sources, .. } => {
                if map.addr.is_some() {
                    skipped.push(format!("{vip} {map}: forwarding to another address is not supported on Windows"));
                    continue;
                }
                if map.public != map.target {
                    skipped.push(format!("{vip} {map}: Windows does not rewrite one port to another"));
                    continue;
                }
                (*vip, map.public, map.proto, sources, false)
            }
            ServiceRule::Terminated { vip, map, port, sources } => {
                // The terminator listens on the public port itself here.
                if *port != map.public {
                    skipped.push(format!("{vip} {map}: the terminator listens on port {port}, which Windows does not rewrite {} to", map.public));
                    continue;
                }
                if !terminator {
                    skipped.push(format!("{vip} {map}: the TLS terminator's service is not installed"));
                    continue;
                }
                (*vip, map.public, map.proto, sources, true)
            }
        };
        // An empty list admits nobody: no permit at all.
        if sources.as_ref().is_some_and(|s| s.is_empty()) {
            continue;
        }
        out.push(Permit { vip, port, proto, sources: sources.as_ref().map(|s| s.to_vec()), terminator: by_terminator });
    }
    (out, skipped)
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
    /// Who the terminator's holes are for: its account, as the descriptor
    /// `ALE_USER_ID` is checked against.
    terminator: Option<SecurityDescriptor>,
    /// The services' holes, from the last `apply`.
    permits: Vec<Permit>,
    /// What is in place now, with the id WFP gave each filter.
    applied: Vec<(Match, u64)>,
    /// Rules not opened here, logged once each.
    warned: BTreeSet<String>,
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
    /// `apply` on, adapter or not. `terminator` is the SID of the TLS
    /// terminator's account, when its service exists.
    pub fn new(ifname: &str, own: &[IpAddr], terminator: Option<&str>) -> io::Result<Self> {
        // Matched by the access check WFP runs against the accepting
        // process's token: `CC` is FWP_ACTRL_MATCH_FILTER.
        let terminator = terminator.map(|sid| SecurityDescriptor::from_sddl(&format!("D:(A;;CC;;;{sid})"))).transpose()?;
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
            terminator,
            permits: Vec::new(),
            applied: Vec::new(),
            warned: BTreeSet::new(),
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
        let wanted = wanted(&self.own, luid, &self.permits);
        if self.applied.iter().map(|(m, _)| m).eq(wanted.iter()) {
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
        wanted.iter().map(|m| Ok((m.clone(), self.add_filter(m)?))).collect()
    }

    fn add_filter(&self, m: &Match) -> io::Result<u64> {
        let mut name = wide(&match m {
            Match::Permit { permit: p, .. } => {
                format!("wireserve: permit {}:{}/{} on {}", p.vip, p.port, p.proto.as_str(), self.ifname)
            }
            _ => format!("wireserve: block inbound on {}", self.ifname),
        });
        // Values the conditions point at, alive until FwpmFilterAdd0 returns.
        let mut v6 = FWP_BYTE_ARRAY16 { byteArray16: [0; 16] };
        let mut luid_value: u64 = match m {
            Match::Interface { luid, .. } | Match::Permit { luid, .. } => *luid,
            Match::LocalAddress(_) => 0,
        };
        let by_terminator = matches!(m, Match::Permit { permit, .. } if permit.terminator);
        let mut user = match &self.terminator {
            Some(sd) if by_terminator => FWP_BYTE_BLOB { size: sd.bytes().len() as u32, data: sd.bytes().as_ptr().cast_mut() },
            None if by_terminator => return Err(io::Error::other("no TLS terminator account to permit")),
            _ => FWP_BYTE_BLOB { size: 0, data: std::ptr::null_mut() },
        };
        let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
        let equal = |field: GUID, value: FWP_CONDITION_VALUE0| FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: value,
        };
        let v4 = |a: Ipv4Addr| {
            // SAFETY: all-zero is a valid FWP_CONDITION_VALUE0 to fill in.
            let mut value: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
            value.r#type = FWP_UINT32;
            // Host byte order, as WFP takes IPv4 addresses.
            value.Anonymous.uint32 = u32::from(a);
            value
        };
        // SAFETY (for every `zeroed` below): all-zero is a valid
        // FWP_CONDITION_VALUE0 to fill in.
        match m {
            Match::LocalAddress(IpAddr::V4(a)) => conditions.push(equal(FWPM_CONDITION_IP_LOCAL_ADDRESS, v4(*a))),
            Match::LocalAddress(IpAddr::V6(a)) => {
                v6.byteArray16 = a.octets();
                let mut value: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
                value.r#type = FWP_BYTE_ARRAY16_TYPE;
                value.Anonymous.byteArray16 = &mut v6;
                conditions.push(equal(FWPM_CONDITION_IP_LOCAL_ADDRESS, value));
            }
            Match::Interface { .. } | Match::Permit { .. } => {
                let mut value: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
                value.r#type = FWP_UINT64;
                value.Anonymous.uint64 = &mut luid_value;
                conditions.push(equal(FWPM_CONDITION_IP_LOCAL_INTERFACE, value));
            }
        }
        if let Match::Permit { permit: p, .. } = m {
            conditions.push(equal(FWPM_CONDITION_IP_LOCAL_ADDRESS, v4(p.vip)));
            let mut port: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
            port.r#type = FWP_UINT16;
            port.Anonymous.uint16 = p.port;
            conditions.push(equal(FWPM_CONDITION_IP_LOCAL_PORT, port));
            let mut proto: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
            proto.r#type = FWP_UINT8;
            proto.Anonymous.uint8 = match p.proto {
                Proto::Tcp => 6,
                Proto::Udp => 17,
            };
            conditions.push(equal(FWPM_CONDITION_IP_PROTOCOL, proto));
            // Conditions on the same field are OR'ed: any one source will do.
            for source in p.sources.iter().flatten() {
                conditions.push(equal(FWPM_CONDITION_IP_REMOTE_ADDRESS, v4(*source)));
            }
            if p.terminator {
                let mut value: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
                value.r#type = FWP_SECURITY_DESCRIPTOR_TYPE;
                value.Anonymous.sd = &mut user;
                conditions.push(equal(FWPM_CONDITION_ALE_USER_ID, value));
            }
        } else {
            let mut not_loopback: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
            not_loopback.r#type = FWP_UINT32;
            not_loopback.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_FLAGS,
                matchType: FWP_MATCH_FLAGS_NONE_SET,
                conditionValue: not_loopback,
            });
        }
        let (action, weight) = match m {
            Match::Permit { .. } => (FWP_ACTION_PERMIT, PERMIT_WEIGHT),
            _ => (FWP_ACTION_BLOCK, BLOCK_WEIGHT),
        };

        // SAFETY: all-zero is a valid FWPM_FILTER0 to fill in.
        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        filter.displayData = FWPM_DISPLAY_DATA0 { name: name.as_mut_ptr(), description: std::ptr::null_mut() };
        // Hard: a block nothing in a lower sublayer, callouts included, can
        // turn into a permit; a permit only a veto there can override.
        filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        filter.layerKey = m.layer();
        filter.subLayerKey = self.sublayer;
        // SAFETY: all-zero is a valid value union to set.
        let mut weight_value = FWP_VALUE0 { r#type: FWP_UINT8, Anonymous: unsafe { std::mem::zeroed() } };
        weight_value.Anonymous.uint8 = weight;
        filter.weight = weight_value;
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = conditions.as_mut_ptr();
        // SAFETY: all-zero is a valid action union to set the type of.
        filter.action = FWPM_ACTION0 { r#type: action, Anonymous: unsafe { std::mem::zeroed() } };
        let mut id = 0u64;
        // SAFETY: the filter and everything it points at outlive the call.
        check("adding a filter", unsafe { FwpmFilterAdd0(self.engine, &filter, std::ptr::null_mut(), &mut id) })?;
        Ok(id)
    }
}

impl FirewallBackend for WfpBackend {
    type Error = io::Error;

    /// The default-deny and the services' holes. `forwarding` is always
    /// empty here: a Windows node carries nobody's traffic (PLAN.md M49).
    fn apply(&mut self, rules: &[ServiceRule], forwarding: &Forwarding) -> Result<(), Self::Error> {
        // What the agent always fills in (its own address and ports, the
        // mesh's range) asks for nothing to be forwarded; these would.
        let forwards = !forwarding.relay.is_empty() || !forwarding.relay_public.is_empty() || !forwarding.exit.is_empty();
        if forwards && self.warned.insert("forwarding".into()) {
            tracing::warn!("forwarding is not supported on Windows; nothing is forwarded");
        }
        let (permits, skipped) = permits(rules, self.terminator.is_some());
        for why in skipped {
            if self.warned.insert(why.clone()) {
                tracing::warn!("not opening {why}");
            }
        }
        let previous = std::mem::replace(&mut self.permits, permits);
        let result = self.replace();
        if result.is_err() {
            // What is in place is still the previous ruleset.
            self.permits = previous;
        }
        result
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
                self.permits.clear();
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
    use std::net::Ipv6Addr;
    use wireserve_types::PortMap;

    const VIP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 50);
    const NODE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 7);

    fn pm(s: &str) -> PortMap {
        s.parse().unwrap()
    }

    #[test]
    fn the_mesh_addresses_are_blocked_before_there_is_an_adapter() {
        let own = [IpAddr::V4(NODE), IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 7))];
        let permit = Permit { vip: VIP, port: 22, proto: Proto::Tcp, sources: None, terminator: false };
        let before = wanted(&own, None, std::slice::from_ref(&permit));
        assert_eq!(before, vec![Match::LocalAddress(own[0]), Match::LocalAddress(own[1])], "no permit without the adapter");
        assert_eq!(before[0].layer().data1, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4.data1);
        assert_eq!(before[1].layer().data1, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6.data1);

        let after = wanted(&own, Some(42), std::slice::from_ref(&permit));
        assert_eq!(after.len(), 5);
        assert!(after.contains(&Match::Interface { luid: 42, v6: false }));
        assert!(after.contains(&Match::Interface { luid: 42, v6: true }));
        assert!(after.contains(&Match::Permit { luid: 42, permit }));
    }

    #[test]
    fn a_service_is_opened_on_its_own_port_and_never_rewritten() {
        let sources: wireserve_types::Sources = Some(vec![Ipv4Addr::new(100, 64, 0, 9)].into());
        let rules = [
            ServiceRule::Mapped { vip: VIP, node: NODE, map: pm("22"), sources: None },
            ServiceRule::Mapped { vip: VIP, node: NODE, map: pm("53/udp"), sources: sources.clone() },
            // Another port, another address, nobody admitted: not here.
            ServiceRule::Mapped { vip: VIP, node: NODE, map: pm("2222:22"), sources: None },
            ServiceRule::Mapped { vip: VIP, node: NODE, map: pm("8080:192.168.1.1:80"), sources: None },
            ServiceRule::Mapped { vip: VIP, node: NODE, map: pm("5432"), sources: Some(Vec::new().into()) },
        ];
        let (open, skipped) = permits(&rules, false);
        assert_eq!(
            open,
            vec![
                Permit { vip: VIP, port: 22, proto: Proto::Tcp, sources: None, terminator: false },
                Permit { vip: VIP, port: 53, proto: Proto::Udp, sources: Some(vec![Ipv4Addr::new(100, 64, 0, 9)]), terminator: false },
            ]
        );
        assert_eq!(skipped.len(), 2, "{skipped:?}");
    }

    #[test]
    fn the_terminators_ports_are_its_own_and_only_with_its_account() {
        let rules = [
            ServiceRule::Terminated { vip: VIP, map: pm("443:8080"), port: 443, sources: None },
            ServiceRule::Terminated { vip: VIP, map: pm("80:8080"), port: 80, sources: None },
        ];
        let (open, skipped) = permits(&rules, true);
        assert!(skipped.is_empty());
        assert_eq!(open.iter().map(|p| (p.port, p.terminator)).collect::<Vec<_>>(), [(443, true), (80, true)]);
        let (open, skipped) = permits(&rules, false);
        assert!(open.is_empty(), "never opened to whoever binds the port");
        assert_eq!(skipped.len(), 2);
        // A terminator on another port would need the rewrite.
        let (open, _) = permits(&[ServiceRule::Terminated { vip: VIP, map: pm("443:8080"), port: 11443, sources: None }], true);
        assert!(open.is_empty());
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
        let observer = WfpBackend::new("observer", &[], None).unwrap();
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
        let mut fw = WfpBackend::new("wireserve-no-such-adapter", &own, None).unwrap();
        crate::firewall::startup_sequence(&mut fw).unwrap();
        let ids: Vec<u64> = fw.applied.iter().map(|(_, id)| *id).collect();
        assert_eq!(ids.len(), 2, "one block per mesh address, no adapter yet");
        assert!(ids.iter().all(|id| exists(*id)));

        // Applying the same again changes nothing.
        fw.apply(&[], &Forwarding::default()).unwrap();
        assert_eq!(fw.applied.iter().map(|(_, id)| *id).collect::<Vec<_>>(), ids);

        fw.teardown().unwrap();
        assert!(ids.iter().all(|id| !exists(*id)), "teardown left a filter behind");

        // With a real adapter of that name, its own blocks join in, and the
        // services' permits: a plain one, and one for the terminator's
        // account — any service's will do to build its condition.
        let name = format!("wsfw{}", std::process::id() % 100_000);
        let mut adapter = crate::wg::nt::NtApi::new(name.clone()).unwrap();
        match adapter.create_interface() {
            Ok(()) => {
                let account = crate::winsec::service_sid("EventLog").unwrap();
                let mut fw = WfpBackend::new(&name, &own, account.as_deref()).unwrap();
                crate::firewall::startup_sequence(&mut fw).unwrap();
                fw.refresh().unwrap();
                assert_eq!(fw.applied.len(), 4, "two address blocks and the adapter's two");
                let sources: wireserve_types::Sources = Some(vec![Ipv4Addr::new(100, 64, 251, 9)].into());
                let rules = [
                    ServiceRule::Mapped { vip: Ipv4Addr::new(100, 64, 251, 50), node: Ipv4Addr::new(100, 64, 251, 1), map: pm("22"), sources },
                    ServiceRule::Terminated { vip: Ipv4Addr::new(100, 64, 251, 50), map: pm("443:8080"), port: 443, sources: None },
                ];
                fw.apply(&rules, &Forwarding::default()).unwrap();
                assert_eq!(fw.applied.len(), 6, "and a permit for each service port");
                let ids: Vec<u64> = fw.applied.iter().map(|(_, id)| *id).collect();
                assert!(ids.iter().all(|id| exists(*id)));
                fw.apply(&[], &Forwarding::default()).unwrap();
                assert_eq!(fw.applied.len(), 4, "a withdrawn service's permit goes");
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
