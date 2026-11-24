//! The Windows firewall backend: the Windows Filtering Platform, directly.
//!
//! A Windows node is a mesh member whose ruleset is the default-deny with
//! holes for its services (PLAN.md M51) and nothing else: no transit, no
//! exit. Every new inbound connection over the mesh is refused but those,
//! and replies to the node's own connections come back as they belong to
//! flows it opened — WFP's ALE layers only ever see the first packet of a
//! flow, which is what nftables' `ct state established` amounts to on
//! Linux.
//!
//! Why WFP and not Windows Defender Firewall rules (PLAN.md #349): the blocks
//! sit in a sublayer of our own at the highest weight and clear the
//! action right, so no other firewall on the host — Defender, or whatever
//! replaced it, all of them WFP clients — can permit what they refuse;
//! they hold whether Defender is on or off and whatever network profile
//! Windows gave the adapter; and a ruleset is replaced in one transaction,
//! like `nft -f`.
//!
//! Two lifetimes (PLAN.md #362):
//! - **Lasting blocks**, persistent WFP objects, for as long as the node is
//!   joined — past a stop, a crash, a reboot: inbound to the node's **mesh
//!   addresses** and to the **mesh's range** (the service addresses), at
//!   `ALE_AUTH_RECV_ACCEPT_V4/V6`, and **forwarding from the mesh's range**
//!   at `IPFORWARD_V4/V6`. They are in place before bring-up, as spec §5
//!   asks, with `guarded_bring_up`'s order unchanged, and still there in
//!   the seconds Windows takes to remove an adapter whose process is gone
//!   (`super::nt`), service addresses and all. Each has a key derived from
//!   the instance and what it is, so a start replaces them rather than
//!   adding more, and `leave` removes them by the same keys.
//! - **The rest**, in a dynamic session, gone with the process: the
//!   **adapter**'s own blocks once it is up — inbound on it (its LUID) to
//!   any of the host's addresses, and forwarding of anything that arrived
//!   on it (its index) — and the services' **permits**.
//!
//! Every instance's filters, lasting or not, are in one persistent sublayer.
//! A dynamic session's sublayer can be used by that session only
//! (`FWP_E_WRONG_SESSION`, #349), a persistent one by every session, and
//! within one sublayer the weights decide: an instance's permits outweigh
//! every instance's blocks, which matters to two instances in one mesh,
//! whose range blocks cover each other's service addresses.
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

use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr};

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_IN_USE, FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFilterDeleteByKey0, FwpmSubLayerAdd0,
    FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0,
    FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_ADDRESS, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_SOURCE_ADDRESS, FWPM_CONDITION_SOURCE_INTERFACE_INDEX, FWPM_DISPLAY_DATA0, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_FILTER_FLAG_PERSISTENT,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_LAYER_IPFORWARD_V4,
    FWPM_LAYER_IPFORWARD_V6, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWPM_SUBLAYER_FLAG_PERSISTENT,
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_NONE_SET,
    FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use wireserve_types::{FirewallBackend, Forwarding, MeshRanges, Proto, ServiceRule};

use crate::platform::windows::net::{self as winnet, wide};
use crate::platform::windows::security::SecurityDescriptor;

/// The one sublayer every instance's filters go in: persistent, so any
/// session may add to it (see the module documentation). The same key on
/// every start, so adding it again finds it there.
fn sublayer_key() -> GUID {
    crate::platform::windows::nt::name_guid("wireserve-wfp-sublayer")
}

/// The highest weight a sublayer can have: ours is consulted first.
const SUBLAYER_WEIGHT: u16 = u16::MAX;

/// Weight ranges (0-15) within our sublayer: a permit is consulted before
/// any block, and the first matching filter decides.
const BLOCK_WEIGHT: u8 = 1;
const PERMIT_WEIGHT: u8 = 15;

/// The shortest prefix taken for a mesh's range. A coordinator's range
/// wider than this is no mesh's, and blocking it would block the host's own
/// networks with it.
const MIN_RANGE_PREFIX: u8 = 8;

/// Every lasting block an instance can have, by the name its key is derived
/// from: what a start replaces and `leave` removes, whichever of them the
/// last start put in.
const LASTING_SLOTS: [&str; 6] = ["own-v4", "own-v6", "range-v4", "range-v6", "forward-v4", "forward-v6"];

/// The key of `instance`'s lasting block `slot`: the same on every start.
fn lasting_key(instance: &str, slot: &str) -> GUID {
    crate::platform::windows::nt::name_guid(&format!("wireserve-wfp-block:{instance}:{slot}"))
}

/// One service's hole in the default-deny (PLAN.md M51): new connections
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
    /// Lasting: inbound to one of the node's mesh addresses.
    LocalAddress(IpAddr),
    /// Lasting: inbound to any address in the mesh's range (network, prefix).
    LocalRange(IpAddr, u8),
    /// Lasting: forwarding of anything from the mesh's range.
    ForwardedFrom(IpAddr, u8),
    /// The adapter, on one IP version's layer.
    Interface { luid: u64, v6: bool },
    /// Forwarding of anything that arrived on the adapter, by its index.
    ForwardedIn { index: u32, v6: bool },
    /// A service's hole, on the adapter.
    Permit { luid: u64, permit: Permit },
}

impl Match {
    fn layer(&self) -> GUID {
        let (forward, v6) = match self {
            Match::LocalAddress(addr) | Match::LocalRange(addr, _) => (false, addr.is_ipv6()),
            Match::ForwardedFrom(addr, _) => (true, addr.is_ipv6()),
            Match::Interface { v6, .. } => (false, *v6),
            Match::ForwardedIn { v6, .. } => (true, *v6),
            Match::Permit { .. } => (false, false),
        };
        match (forward, v6) {
            (false, false) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            (false, true) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            (true, false) => FWPM_LAYER_IPFORWARD_V4,
            (true, true) => FWPM_LAYER_IPFORWARD_V6,
        }
    }

    /// Which of [`LASTING_SLOTS`] a lasting block is; `None` for the
    /// session's own filters.
    fn slot(&self) -> Option<&'static str> {
        let family = |addr: &IpAddr, v4: &'static str, v6: &'static str| if addr.is_ipv6() { v6 } else { v4 };
        match self {
            Match::LocalAddress(a) => Some(family(a, "own-v4", "own-v6")),
            Match::LocalRange(a, _) => Some(family(a, "range-v4", "range-v6")),
            Match::ForwardedFrom(a, _) => Some(family(a, "forward-v4", "forward-v6")),
            Match::Interface { .. } | Match::ForwardedIn { .. } | Match::Permit { .. } => None,
        }
    }

    /// What `netsh wfp show filters` lists it as.
    fn name(&self, instance: &str, ifname: &str) -> String {
        match self {
            Match::LocalAddress(a) => format!("wireserve ({instance}): block inbound to {a}"),
            Match::LocalRange(a, len) => format!("wireserve ({instance}): block inbound to {a}/{len}"),
            Match::ForwardedFrom(a, len) => format!("wireserve ({instance}): block forwarding from {a}/{len}"),
            Match::Interface { .. } => format!("wireserve: block inbound on {ifname}"),
            Match::ForwardedIn { .. } => format!("wireserve: block forwarding from {ifname}"),
            Match::Permit { permit: p, .. } => {
                format!("wireserve: permit {}:{}/{} on {ifname}", p.vip, p.port, p.proto.as_str())
            }
        }
    }
}

/// The lasting blocks: the node's mesh addresses `own` (one of each
/// family), and the mesh's range when it is known. A range is left out,
/// and why said, when it is wider than any mesh's, when the host's own
/// addresses could not be listed, or when one of them on another
/// interface, `elsewhere`, is in it: a lasting block on it would cut that
/// network off from the host for as long as the node is joined.
fn lasting(own: &[IpAddr], mesh: Option<&MeshRanges>, elsewhere: Option<&[IpAddr]>) -> (Vec<Match>, Vec<String>) {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for v6 in [false, true] {
        if let Some(a) = own.iter().find(|a| a.is_ipv6() == v6) {
            out.push(Match::LocalAddress(*a));
        }
    }
    let Some(mesh) = mesh else {
        return (out, skipped);
    };
    for v6 in [false, true] {
        let (net, len) = if v6 {
            let (a, l) = mesh.v6();
            (IpAddr::V6(a), l)
        } else {
            let (a, l) = mesh.v4();
            (IpAddr::V4(a), l)
        };
        if len < MIN_RANGE_PREFIX {
            skipped.push(format!("the mesh's range {net}/{len}: wider than /{MIN_RANGE_PREFIX}"));
            continue;
        }
        let in_range = |a: &IpAddr| match a {
            IpAddr::V4(a) => !v6 && mesh.contains4(*a),
            IpAddr::V6(a) => v6 && mesh.contains6(*a),
        };
        match elsewhere {
            None => {
                skipped.push(format!("the mesh's range {net}/{len}: the host's addresses could not be listed"));
                continue;
            }
            Some(addrs) => {
                if let Some(a) = addrs.iter().find(|a| in_range(a) && !own.contains(a)) {
                    skipped.push(format!("the mesh's range {net}/{len}: {a}, on another interface, is in it"));
                    continue;
                }
            }
        }
        out.push(Match::LocalRange(net, len));
        out.push(Match::ForwardedFrom(net, len));
    }
    (out, skipped)
}

/// The adapter, once it exists (its LUID and index).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Adapter {
    luid: u64,
    index: u32,
}

/// The session's own filters: none until the adapter is up, then its
/// blocks and the services' permits.
fn wanted(adapter: Option<Adapter>, permits: &[Permit]) -> Vec<Match> {
    let mut out = Vec::new();
    if let Some(Adapter { luid, index }) = adapter {
        out.push(Match::Interface { luid, v6: false });
        out.push(Match::Interface { luid, v6: true });
        out.push(Match::ForwardedIn { index, v6: false });
        out.push(Match::ForwardedIn { index, v6: true });
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

/// `check`, with `ok` (WFP's own HRESULTs, as the `u32`s its functions
/// return) counting as success too.
fn check_but(what: &str, code: u32, ok: &[i32]) -> io::Result<()> {
    if ok.iter().any(|c| *c as u32 == code) {
        Ok(())
    } else {
        check(what, code)
    }
}

/// An open session with the filtering engine, closed on drop. Closing a
/// dynamic one removes everything added through it; closing any other
/// leaves what it added.
struct Engine(HANDLE);

// SAFETY: a WFP engine handle may be used from any thread, one call at a
// time, which every user's `&mut self` (or sole ownership) ensures.
unsafe impl Send for Engine {}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: our own engine handle, closed once.
        unsafe { FwpmEngineClose0(self.0) };
    }
}

impl Engine {
    /// A dynamic session, or one whose objects can be persistent: WFP
    /// refuses a persistent object from a dynamic session
    /// (`FWP_E_DYNAMIC_SESSION_IN_PROGRESS`).
    fn open(dynamic: bool, name: &str) -> io::Result<Self> {
        let mut session_name = wide(name);
        // SAFETY: all-zero is a valid FWPM_SESSION0 to fill in.
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.displayData.name = session_name.as_mut_ptr();
        if dynamic {
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        }
        let mut engine: HANDLE = std::ptr::null_mut();
        // SAFETY: a session that outlives the call; `engine` is written by it.
        check("opening the Windows Filtering Platform", unsafe {
            FwpmEngineOpen0(std::ptr::null(), RPC_C_AUTHN_WINNT, std::ptr::null(), &session, &mut engine)
        })?;
        Ok(Self(engine))
    }

    /// Runs `f` in one transaction: all of what it changes, or none of it.
    fn transaction<T>(&self, f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        // SAFETY: our engine handle.
        check("starting a filter transaction", unsafe { FwpmTransactionBegin0(self.0, 0) })?;
        match f() {
            Ok(out) => {
                // SAFETY: the transaction begun above.
                check("committing the filter transaction", unsafe { FwpmTransactionCommit0(self.0) })?;
                Ok(out)
            }
            Err(e) => {
                // SAFETY: the transaction begun above.
                unsafe { FwpmTransactionAbort0(self.0) };
                Err(e)
            }
        }
    }

    /// Our sublayer, persistent; already there is fine. Needs a session
    /// that is not dynamic.
    fn ensure_sublayer(&self) -> io::Result<()> {
        let mut name = wide("wireserve");
        // SAFETY: all-zero is a valid FWPM_SUBLAYER0 to fill in.
        let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sublayer.subLayerKey = sublayer_key();
        sublayer.displayData = FWPM_DISPLAY_DATA0 { name: name.as_mut_ptr(), description: std::ptr::null_mut() };
        sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        sublayer.weight = SUBLAYER_WEIGHT;
        // SAFETY: a sublayer description that outlives the call.
        check_but(
            "adding the wireserve sublayer",
            unsafe { FwpmSubLayerAdd0(self.0, &sublayer, std::ptr::null_mut()) },
            &[FWP_E_ALREADY_EXISTS],
        )
    }

    /// Adds the filter for `m`, persistent under `key` when there is one,
    /// and returns the id WFP gave it. `terminator` is the descriptor
    /// `ALE_USER_ID` is checked against, for a terminator's permit.
    fn add_filter(&self, m: &Match, name: &str, key: Option<GUID>, terminator: Option<&SecurityDescriptor>) -> io::Result<u64> {
        let mut name = wide(name);
        // Values the conditions point at, alive until FwpmFilterAdd0 returns.
        let mut v6 = FWP_BYTE_ARRAY16 { byteArray16: [0; 16] };
        let mut v4_mask = FWP_V4_ADDR_AND_MASK { addr: 0, mask: 0 };
        let mut v6_mask = FWP_V6_ADDR_AND_MASK { addr: [0; 16], prefixLength: 0 };
        let mut luid_value: u64 = match m {
            Match::Interface { luid, .. } | Match::Permit { luid, .. } => *luid,
            _ => 0,
        };
        let by_terminator = matches!(m, Match::Permit { permit, .. } if permit.terminator);
        let mut user = match terminator {
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
            Match::LocalRange(net, len) | Match::ForwardedFrom(net, len) => {
                // Inbound: to the range. Forwarded: from it — the field the
                // forwarding layers have for a packet's source.
                let field = if matches!(m, Match::LocalRange(..)) {
                    FWPM_CONDITION_IP_LOCAL_ADDRESS
                } else {
                    FWPM_CONDITION_IP_SOURCE_ADDRESS
                };
                let mut value: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
                match net {
                    IpAddr::V4(a) => {
                        // Both in host byte order.
                        v4_mask.addr = u32::from(*a);
                        v4_mask.mask = mask4(*len);
                        value.r#type = FWP_V4_ADDR_MASK;
                        value.Anonymous.v4AddrMask = &mut v4_mask;
                    }
                    IpAddr::V6(a) => {
                        v6_mask.addr = a.octets();
                        v6_mask.prefixLength = *len;
                        value.r#type = FWP_V6_ADDR_MASK;
                        value.Anonymous.v6AddrMask = &mut v6_mask;
                    }
                }
                conditions.push(equal(field, value));
            }
            Match::Interface { .. } | Match::Permit { .. } => {
                let mut value: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
                value.r#type = FWP_UINT64;
                value.Anonymous.uint64 = &mut luid_value;
                conditions.push(equal(FWPM_CONDITION_IP_LOCAL_INTERFACE, value));
            }
            Match::ForwardedIn { index, .. } => {
                // The forwarding layers name the interface a packet arrived
                // on by its index; they have no `IP_LOCAL_INTERFACE`.
                let mut value: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
                value.r#type = FWP_UINT32;
                value.Anonymous.uint32 = *index;
                conditions.push(equal(FWPM_CONDITION_SOURCE_INTERFACE_INDEX, value));
            }
        }
        match m {
            Match::Permit { permit: p, .. } => {
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
            }
            // A forwarded packet is never loopback, and its layers are not
            // asked about flags.
            Match::ForwardedFrom(..) | Match::ForwardedIn { .. } => {}
            Match::LocalAddress(_) | Match::LocalRange(..) | Match::Interface { .. } => {
                let mut not_loopback: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
                not_loopback.r#type = FWP_UINT32;
                not_loopback.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                conditions.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_FLAGS,
                    matchType: FWP_MATCH_FLAGS_NONE_SET,
                    conditionValue: not_loopback,
                });
            }
        }
        let (action, weight) = match m {
            Match::Permit { .. } => (FWP_ACTION_PERMIT, PERMIT_WEIGHT),
            _ => (FWP_ACTION_BLOCK, BLOCK_WEIGHT),
        };

        // SAFETY: all-zero is a valid FWPM_FILTER0 to fill in.
        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        // All-zero lets WFP pick one.
        if let Some(key) = key {
            filter.filterKey = key;
        }
        filter.displayData = FWPM_DISPLAY_DATA0 { name: name.as_mut_ptr(), description: std::ptr::null_mut() };
        // Hard: a block nothing in a lower sublayer, callouts included, can
        // turn into a permit; a permit only a veto there can override.
        filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        if key.is_some() {
            filter.flags |= FWPM_FILTER_FLAG_PERSISTENT;
        }
        filter.layerKey = m.layer();
        filter.subLayerKey = sublayer_key();
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
        check("adding a filter", unsafe { FwpmFilterAdd0(self.0, &filter, std::ptr::null_mut(), &mut id) })?;
        Ok(id)
    }

    /// Removes every lasting block of `instance` there is.
    fn delete_lasting(&self, instance: &str) -> io::Result<()> {
        for slot in LASTING_SLOTS {
            let key = lasting_key(instance, slot);
            // SAFETY: our engine handle and a key that outlives the call.
            check_but("removing a filter", unsafe { FwpmFilterDeleteByKey0(self.0, &key) }, &[FWP_E_FILTER_NOT_FOUND])?;
        }
        Ok(())
    }
}

/// The IPv4 netmask of a prefix length, in host byte order.
fn mask4(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(len.min(32)))
    }
}

/// Makes `blocks` exactly `instance`'s lasting blocks, in one transaction:
/// whatever the last start put in is replaced, so starting again adds
/// nothing and a changed address leaves no stale block behind.
fn put_lasting(instance: &str, blocks: &[Match]) -> io::Result<()> {
    let engine = Engine::open(false, &format!("wireserve agent ({instance}): lasting blocks"))?;
    engine.ensure_sublayer()?;
    engine.transaction(|| {
        engine.delete_lasting(instance)?;
        for m in blocks {
            let slot = m.slot().ok_or_else(|| io::Error::other("not a lasting block"))?;
            engine.add_filter(m, &m.name(instance, ""), Some(lasting_key(instance, slot)), None)?;
        }
        Ok(())
    })
}

/// Removes `instance`'s lasting blocks (see the module documentation), and
/// our sublayer when nothing is left in it: `leave`'s. Another instance's
/// filters still in the sublayer keep it (`FWP_E_IN_USE`). Done is done:
/// nothing there is fine.
pub fn remove_lasting(instance: &str) -> io::Result<()> {
    let engine = Engine::open(false, &format!("wireserve agent ({instance}): leaving"))?;
    engine.transaction(|| engine.delete_lasting(instance))?;
    let key = sublayer_key();
    // SAFETY: our engine handle and a key that outlives the call.
    check_but(
        "removing the wireserve sublayer",
        unsafe { FwpmSubLayerDeleteByKey0(engine.0, &key) },
        &[FWP_E_IN_USE, FWP_E_SUBLAYER_NOT_FOUND],
    )
}

/// See the module documentation.
pub struct WfpBackend {
    ifname: String,
    instance: String,
    /// The dynamic session: everything but the lasting blocks.
    engine: Engine,
    /// Who the terminator's holes are for: its account, as the descriptor
    /// `ALE_USER_ID` is checked against.
    terminator: Option<SecurityDescriptor>,
    /// The services' holes, from the last `apply`.
    permits: Vec<Permit>,
    /// What the dynamic session has in place now, with the id WFP gave
    /// each filter.
    applied: Vec<(Match, u64)>,
    /// Rules not opened here, logged once each.
    warned: BTreeSet<String>,
}

impl WfpBackend {
    /// Puts `instance`'s lasting blocks in — the node's mesh addresses
    /// `own` and, when it is known, the mesh's range `mesh` (`elsewhere`:
    /// the host's addresses on other interfaces, `None` when they could not
    /// be listed; see [`lasting`]) — and opens the dynamic session for the
    /// rest. `terminator` is the SID of the TLS terminator's account, when
    /// its service exists.
    pub fn new(
        ifname: &str,
        instance: &str,
        own: &[IpAddr],
        mesh: Option<&MeshRanges>,
        elsewhere: Option<&[IpAddr]>,
        terminator: Option<&str>,
    ) -> io::Result<Self> {
        // Matched by the access check WFP runs against the accepting
        // process's token: `CC` is FWP_ACTRL_MATCH_FILTER.
        let terminator = terminator.map(|sid| SecurityDescriptor::from_sddl(&format!("D:(A;;CC;;;{sid})"))).transpose()?;
        let (blocks, skipped) = lasting(own, mesh, elsewhere);
        for why in skipped {
            tracing::warn!("not blocking {why}; only the node's own addresses and the adapter are");
        }
        put_lasting(instance, &blocks)?;
        let engine = Engine::open(true, &format!("wireserve agent ({ifname})"))?;
        Ok(Self {
            ifname: ifname.to_string(),
            instance: instance.to_string(),
            engine,
            terminator,
            permits: Vec::new(),
            applied: Vec::new(),
            warned: BTreeSet::new(),
        })
    }

    /// Adds the adapter's blocks once it exists — called after bring-up.
    /// The next `apply` would too; this does not wait for it.
    pub fn refresh(&mut self) -> io::Result<()> {
        self.replace()
    }

    /// `leave`: the session's filters and this instance's lasting blocks
    /// go, once the adapter they guarded has (see `teardown_everything`).
    pub fn forget(&mut self) -> io::Result<()> {
        self.transact(&[])?;
        self.permits.clear();
        remove_lasting(&self.instance)
    }

    /// Makes the session's filters the wanted ones for the adapter as it is
    /// now.
    fn replace(&mut self) -> io::Result<()> {
        let adapter = match winnet::luid_by_alias(&self.ifname)? {
            Some(luid) => Some(Adapter {
                // SAFETY: the LUID union's plain 64-bit view.
                luid: unsafe { luid.Value },
                index: winnet::index_of(luid)?,
            }),
            None => None,
        };
        let wanted = wanted(adapter, &self.permits);
        if self.applied.iter().map(|(m, _)| m).eq(wanted.iter()) {
            return Ok(());
        }
        self.transact(&wanted)
    }

    /// Makes the session's filters exactly `wanted`, in one transaction.
    fn transact(&mut self, wanted: &[Match]) -> io::Result<()> {
        let applied = self.engine.transaction(|| {
            for (_, id) in &self.applied {
                // SAFETY: a filter id this session added.
                check_but("removing a filter", unsafe { FwpmFilterDeleteById0(self.engine.0, *id) }, &[FWP_E_FILTER_NOT_FOUND])?;
            }
            wanted
                .iter()
                .map(|m| Ok((m.clone(), self.engine.add_filter(m, &m.name(&self.instance, &self.ifname), None, self.terminator.as_ref())?)))
                .collect::<io::Result<Vec<_>>>()
        })?;
        self.applied = applied;
        Ok(())
    }
}

impl FirewallBackend for WfpBackend {
    type Error = io::Error;

    /// The default-deny and the services' holes. `forwarding` is always
    /// empty here: a Windows node carries nobody's traffic (PLAN.md M50).
    fn apply(&mut self, rules: &[ServiceRule], forwarding: &Forwarding) -> Result<(), Self::Error> {
        // What the agent always fills in (its own address and ports, the
        // mesh's range) asks for nothing to be forwarded; these would.
        let forwards = !forwarding.relay.is_empty() || forwarding.phone_relay.is_some() || !forwarding.exit.is_empty();
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

    /// Closes every hole: the permits go. The blocks stay — the adapter's
    /// until the session closes with the process, the lasting ones until
    /// `leave` — so the adapter, which a stop removes after the firewall
    /// and Windows only some seconds after that, is never left with its
    /// addresses unguarded. Nothing a block refuses needs undoing.
    fn teardown(&mut self) -> Result<(), Self::Error> {
        let kept: Vec<Match> =
            self.applied.iter().map(|(m, _)| m.clone()).filter(|m| !matches!(m, Match::Permit { .. })).collect();
        self.transact(&kept)?;
        self.permits.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use wireserve_types::{MeshInfo, PortMap};

    const VIP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 50);
    const NODE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 7);

    fn pm(s: &str) -> PortMap {
        s.parse().unwrap()
    }

    fn mesh(v4: &str, v6: &str) -> MeshRanges {
        MeshRanges::parse(&MeshInfo { net_v4_cidr: v4.into(), net_v6_prefix: v6.into() }).unwrap()
    }

    fn own() -> [IpAddr; 2] {
        [IpAddr::V4(NODE), IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 7))]
    }

    #[test]
    fn the_mesh_addresses_and_range_are_blocked_past_the_process() {
        let own = own();
        let range = mesh("100.64.0.0/24", "fd00::/64");
        let (blocks, skipped) = lasting(&own, Some(&range), Some(&[IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))]));
        assert!(skipped.is_empty(), "{skipped:?}");
        let v4net = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0));
        let v6net = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(
            blocks,
            vec![
                Match::LocalAddress(own[0]),
                Match::LocalAddress(own[1]),
                Match::LocalRange(v4net, 24),
                Match::ForwardedFrom(v4net, 24),
                Match::LocalRange(v6net, 64),
                Match::ForwardedFrom(v6net, 64),
            ]
        );
        let layers: Vec<u32> = blocks.iter().map(|m| m.layer().data1).collect();
        assert_eq!(
            layers,
            [
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4.data1,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6.data1,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4.data1,
                FWPM_LAYER_IPFORWARD_V4.data1,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6.data1,
                FWPM_LAYER_IPFORWARD_V6.data1,
            ]
        );
        // Each in a slot of its own, so each has a key of its own.
        let slots: BTreeSet<&str> = blocks.iter().filter_map(Match::slot).collect();
        assert_eq!(slots, LASTING_SLOTS.into_iter().collect());

        // Without a known range, the addresses alone.
        let (blocks, _) = lasting(&own, None, None);
        assert_eq!(blocks, vec![Match::LocalAddress(own[0]), Match::LocalAddress(own[1])]);
    }

    #[test]
    fn a_range_the_host_has_another_address_in_is_not_blocked() {
        let own = own();
        let range = mesh("10.0.0.0/8", "fd00::/64");
        // The LAN is in the mesh's v4 range: blocking it would cut the host
        // off from it.
        let (blocks, skipped) = lasting(&own, Some(&range), Some(&[IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))]));
        assert!(!blocks.iter().any(|m| matches!(m, Match::LocalRange(IpAddr::V4(_), _) | Match::ForwardedFrom(IpAddr::V4(_), _))));
        assert!(blocks.iter().any(|m| matches!(m, Match::LocalRange(IpAddr::V6(_), _))));
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        // The node's own address there (a previous run's adapter, on its way
        // out) is no conflict.
        let (_, skipped) = lasting(&own, Some(&mesh("100.64.0.0/24", "fd00::/64")), Some(&own));
        assert!(skipped.is_empty(), "{skipped:?}");
        // Not knowing the host's addresses, or a range wider than a mesh's:
        // no range block either.
        let (_, skipped) = lasting(&own, Some(&mesh("100.64.0.0/24", "fd00::/64")), None);
        assert_eq!(skipped.len(), 2);
        let (blocks, skipped) = lasting(&own, Some(&mesh("0.0.0.0/0", "::/0")), Some(&[]));
        assert_eq!(blocks.len(), 2);
        assert_eq!(skipped.len(), 2);
    }

    #[test]
    fn lasting_keys_are_stable_and_the_instances_own() {
        // GUID has no `PartialEq`: compared as its fields.
        let k = |g: GUID| (g.data1, g.data2, g.data3, g.data4);
        assert_eq!(k(lasting_key("default", "own-v4")), k(lasting_key("default", "own-v4")));
        assert_ne!(k(lasting_key("default", "own-v4")), k(lasting_key("work", "own-v4")));
        assert_ne!(k(lasting_key("default", "own-v4")), k(lasting_key("default", "own-v6")));
        assert_ne!(k(lasting_key("default", "own-v4")), k(sublayer_key()));
    }

    #[test]
    fn netmasks_follow_the_prefix_length() {
        assert_eq!(mask4(0), 0);
        assert_eq!(mask4(8), 0xff00_0000);
        assert_eq!(mask4(24), 0xffff_ff00);
        assert_eq!(mask4(32), u32::MAX);
    }

    #[test]
    fn the_adapter_is_blocked_inbound_and_forwarded_once_it_is_up() {
        let permit = Permit { vip: VIP, port: 22, proto: Proto::Tcp, sources: None, terminator: false };
        assert!(wanted(None, std::slice::from_ref(&permit)).is_empty(), "no permit without the adapter");

        let after = wanted(Some(Adapter { luid: 42, index: 7 }), std::slice::from_ref(&permit));
        assert_eq!(after.len(), 5);
        assert!(after.contains(&Match::Interface { luid: 42, v6: false }));
        assert!(after.contains(&Match::Interface { luid: 42, v6: true }));
        assert!(after.contains(&Match::ForwardedIn { index: 7, v6: false }));
        assert!(after.contains(&Match::ForwardedIn { index: 7, v6: true }));
        assert!(after.contains(&Match::Permit { luid: 42, permit }));
        assert_eq!(Match::ForwardedIn { index: 7, v6: false }.layer().data1, FWPM_LAYER_IPFORWARD_V4.data1);
        assert_eq!(Match::ForwardedIn { index: 7, v6: true }.layer().data1, FWPM_LAYER_IPFORWARD_V6.data1);
        assert!(after.iter().all(|m| m.slot().is_none()), "none of them outlives the session");
    }

    #[test]
    fn filters_are_named_for_netsh() {
        let m = Match::LocalRange(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 24);
        assert_eq!(m.name("work", "wireserve0"), "wireserve (work): block inbound to 100.64.0.0/24");
        let m = Match::ForwardedIn { index: 7, v6: false };
        assert_eq!(m.name("work", "wireserve0"), "wireserve: block forwarding from wireserve0");
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

    /// Against the real filtering engine: the lasting blocks go in, survive
    /// the session that put them in, are replaced rather than added to by
    /// the next start, and go with `forget`; the session's own filters go
    /// with the session, but for the permits, which `teardown` takes first.
    /// Needs an elevated run.
    #[test]
    fn kernel_blocks_outlive_the_session_and_go_on_leave() {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmFilterGetById0, FwpmFilterGetByKey0, FwpmFreeMemory0,
        };

        if !crate::platform::windows::security::is_elevated().unwrap_or(false) {
            assert!(std::env::var_os("WIRESERVE_TEST_STRICT").is_none(), "would skip under WIRESERVE_TEST_STRICT: not elevated");
            eprintln!("SKIPPED: not elevated: the filtering engine takes an administrator");
            return;
        }
        // Another session, to look at what ours did from outside it.
        let observer = Engine::open(true, "wireserve test observer").unwrap();
        let free = |filter: *mut FWPM_FILTER0| {
            let mut filter = filter;
            // SAFETY: memory the engine allocated, freed once.
            unsafe { FwpmFreeMemory0(std::ptr::from_mut(&mut filter).cast()) };
        };
        let exists = |id: u64| {
            let mut filter: *mut FWPM_FILTER0 = std::ptr::null_mut();
            // SAFETY: an observer session; the result is freed straight away.
            let code = unsafe { FwpmFilterGetById0(observer.0, id, &mut filter) };
            if code == 0 {
                free(filter);
            }
            code == 0
        };
        let instance = format!("wireserve-test-{}", std::process::id());
        let lasting_ids = || -> Vec<u64> {
            LASTING_SLOTS
                .iter()
                .filter_map(|slot| {
                    let key = lasting_key(&instance, slot);
                    let mut filter: *mut FWPM_FILTER0 = std::ptr::null_mut();
                    // SAFETY: as above.
                    if unsafe { FwpmFilterGetByKey0(observer.0, &key, &mut filter) } != 0 {
                        return None;
                    }
                    // SAFETY: a filter the call just returned.
                    let id = unsafe { (*filter).filterId };
                    free(filter);
                    Some(id)
                })
                .collect()
        };

        let own = [IpAddr::V4(Ipv4Addr::new(100, 64, 251, 1)), IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xfb, 1))];
        let range = mesh("100.64.251.0/24", "fd00:0:0:fb::/64");
        let mut fw = WfpBackend::new("wireserve-no-such-adapter", &instance, &own, Some(&range), Some(&[]), None).unwrap();
        crate::firewall::startup_sequence(&mut fw).unwrap();
        assert!(fw.applied.is_empty(), "nothing of the session's own without an adapter");
        assert_eq!(lasting_ids().len(), 6, "the addresses, the range inbound and forwarded, each family");
        drop(fw);
        let first = lasting_ids();
        assert_eq!(first.len(), 6, "the lasting blocks outlived their session");

        // A restart replaces them, rather than failing or adding more.
        let mut fw = WfpBackend::new("wireserve-no-such-adapter", &instance, &own, None, Some(&[]), None).unwrap();
        assert_eq!(lasting_ids().len(), 2, "no range now: its blocks went");
        fw.forget().unwrap();
        assert!(lasting_ids().is_empty(), "leave left a lasting block behind");
        drop(fw);

        // With a real adapter of that name, its own blocks join in, and the
        // services' permits: a plain one, and one for the terminator's
        // account — any service's will do to build its condition.
        let name = format!("wsfw{}", std::process::id() % 100_000);
        let mut adapter = crate::platform::windows::nt::NtApi::new(name.clone()).unwrap();
        match adapter.create_interface() {
            Ok(()) => {
                let account = crate::platform::windows::security::service_sid("EventLog").unwrap();
                let mut fw = WfpBackend::new(&name, &instance, &own, Some(&range), Some(&[]), account.as_deref()).unwrap();
                crate::firewall::startup_sequence(&mut fw).unwrap();
                fw.refresh().unwrap();
                assert_eq!(fw.applied.len(), 4, "the adapter's two inbound blocks and two forwarding ones");
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
                fw.apply(&rules, &Forwarding::default()).unwrap();
                fw.teardown().unwrap();
                assert_eq!(fw.applied.len(), 4, "teardown closes the holes and keeps the blocks");
                let ids: Vec<u64> = fw.applied.iter().map(|(_, id)| *id).collect();
                drop(fw);
                assert!(ids.iter().all(|id| !exists(*id)), "a filter outlived its session");
                assert_eq!(lasting_ids().len(), 6);
                adapter.remove_interface();
            }
            Err(e) => {
                assert!(std::env::var_os("WIRESERVE_TEST_STRICT").is_none(), "would skip the adapter part: {e}");
                eprintln!("SKIPPED the adapter part: {e}");
            }
        }
        remove_lasting(&instance).unwrap();
        assert!(lasting_ids().is_empty());
    }
}
