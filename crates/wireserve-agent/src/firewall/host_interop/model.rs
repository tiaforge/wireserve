//! Pure data types shared by the observer, the planner and the executor.
//! Nothing here touches the system.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;

/// Every rule this module puts into another tool's chain carries a comment
/// starting with this prefix, followed by the interface name. It is the
/// *only* thing used to recognise our rules — never position or shape
/// alone — so cleanup can find every one of them after a crash or an
/// `--ifname` change, and an operator can see at a glance where they came
/// from (`nft list ruleset`, `iptables -S`).
pub const TAG_PREFIX: &str = "wireserve:";

#[must_use]
pub fn tag(ifname: &str) -> String {
    format!("{TAG_PREFIX}{ifname}")
}

/// The interface name a tag belongs to (`wireserve:<ifname>`).
#[must_use]
pub fn tag_owner(comment: &str) -> Option<&str> {
    comment.strip_prefix(TAG_PREFIX)
}

const GUARD_TABLE_PREFIX: &str = "wireserve-interop.";

/// Holds `ifname`'s forward guard — see [`Action::GuardCreate`]. One per
/// interface, so every agent on the host creates and removes its own
/// without ever touching another's.
#[must_use]
pub fn guard_table(ifname: &str) -> String {
    format!("{GUARD_TABLE_PREFIX}{ifname}")
}

/// Tables that belong to wireserve — any agent on this host, running or
/// not. Never treated as "foreign", never
/// written into by the planner's insert logic, and changes to them never
/// trigger a reconcile (each backend replaces its own table on every
/// poll; with several agents, reacting to each other's would have them
/// reconciling in response to one another forever).
#[must_use]
pub fn is_own_table(name: &str) -> bool {
    use crate::firewall::nftables::TABLE_PREFIX;
    name.starts_with(TABLE_PREFIX)
        || name.starts_with(GUARD_TABLE_PREFIX)
}

pub const GUARD_CHAIN: &str = "forward-guard";

/// Which base-chain hook a foreign-firewall rule targets. `Input` is always
/// opened (declared services must reach this host); `Forward` is opened
/// only for a transit-capable node (PLAN.md M23) — see `HostInterop::start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Hook {
    Input,
    Forward,
}

impl Hook {
    /// iptables-nft always names its base chains upper-case, regardless of
    /// how a native nftables config names its own (usually lower-case).
    #[must_use]
    pub fn iptables_chain(self) -> &'static str {
        match self {
            Self::Input => "INPUT",
            Self::Forward => "FORWARD",
        }
    }

    #[must_use]
    pub fn nft_hook(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Forward => "forward",
        }
    }
}

pub use crate::firewall::ForwardWanted;

/// The shape of one accept this module puts into a foreign chain. Each is
/// pinned to the mesh interface on one side, and every `FORWARD` one to
/// something narrower on the other: this same interface, or a flow our own
/// table marked as a service's (`nftables::SERVICE_MARK`) or an exit's
/// (`nftables::EXIT_MARK`) — never routing from the mesh to the host's
/// other networks as such.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Opening {
    /// `iifname <if>` on `INPUT`: declared services reach this host.
    Input,
    /// `iifname <if> oifname <if>` on `FORWARD`: transit, mesh → mesh
    /// (PLAN.md M23).
    Hairpin,
    /// `iifname <if> ct mark & M == M` on `FORWARD`: a request to a
    /// service mapped onto another address, leaving for it (PLAN.md M26).
    ServiceRequest,
    /// `oifname <if> ct mark & M == M` on `FORWARD`: its reply, coming
    /// back into the mesh.
    ServiceReply,
    /// `iifname <if> ct mark & E == E` on `FORWARD`: an exit client's flow
    /// to the internet, which our table marked (PLAN.md M27).
    ExitRequest,
    /// `oifname <if> ct mark & E == E` on `FORWARD`: its reply.
    ExitReply,
    /// `oifname <if> ct mark & R == R` on `FORWARD`: a phone's session,
    /// relayed from this node's public address into the mesh (PLAN.md M40).
    RelayRequest,
    /// `iifname <if> ct mark & R == R` on `FORWARD`: its reply.
    RelayReply,
    /// `ct mark & C == C` on `INPUT`: the coordinator's probe of a relay
    /// port under a check (PLAN.md M40), which our own table marked — from
    /// outside, so the one `INPUT` opening not pinned to the mesh interface,
    /// and pinned instead to a flow only our table marks, on a port only
    /// while a check runs.
    RelayCheck,
}

impl Opening {
    #[must_use]
    pub fn hook(self) -> Hook {
        match self {
            Self::Input | Self::RelayCheck => Hook::Input,
            Self::Hairpin
            | Self::ServiceRequest
            | Self::ServiceReply
            | Self::ExitRequest
            | Self::ExitReply
            | Self::RelayRequest
            | Self::RelayReply => Hook::Forward,
        }
    }

    /// Every opening a chain on `hook` should hold.
    #[must_use]
    pub fn wanted(hook: Hook, forward: ForwardWanted) -> Vec<Self> {
        match hook {
            Hook::Input => {
                let mut out = vec![Self::Input];
                if forward.relay_check {
                    out.push(Self::RelayCheck);
                }
                out
            }
            Hook::Forward => {
                let mut out = Vec::new();
                if forward.transit {
                    out.push(Self::Hairpin);
                }
                if forward.services {
                    out.extend([Self::ServiceRequest, Self::ServiceReply]);
                }
                if forward.exit {
                    out.extend([Self::ExitRequest, Self::ExitReply]);
                }
                if forward.relay {
                    out.extend([Self::RelayRequest, Self::RelayReply]);
                }
                out
            }
        }
    }
}

/// firewalld's own table. firewalld (nftables backend) creates it with the
/// `owner` flag, so writes into it fail with EPERM; firewalld is handled
/// through its zones instead.
pub const FIREWALLD_TABLE: &str = "firewalld";

/// Table names the iptables-nft compat layer uses. Only `filter`'s `INPUT`
/// is where host firewalls like ufw put their default-deny, and that one
/// is handled through the `iptables` binary; the others are left alone.
pub const IPTABLES_TABLES: &[&str] = &["filter", "nat", "mangle", "raw", "security"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    Ip,
    Ip6,
    Inet,
}

impl Family {
    /// Only the families that carry IP traffic through an INPUT hook;
    /// `arp`, `bridge` and `netdev` are never touched.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ip" => Some(Self::Ip),
            "ip6" => Some(Self::Ip6),
            "inet" => Some(Self::Inet),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Ip6 => "ip6",
            Self::Inet => "inet",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChainRef {
    pub family: Family,
    pub table: String,
    pub chain: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableInfo {
    pub family: Family,
    pub name: String,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuleInfo {
    pub handle: u64,
    pub comment: Option<String>,
    /// The rule's statements, kept raw — only compared against shapes we
    /// know, never interpreted in general.
    pub expr: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainInfo {
    pub chain: ChainRef,
    /// `None` for a regular (non-base) chain.
    pub hook: Option<String>,
    pub chain_type: Option<String>,
    pub rules: Vec<RuleInfo>,
}

/// What `nft -j list ruleset` told us, restricted to the families we care
/// about.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NftView {
    pub tables: Vec<TableInfo>,
    pub chains: Vec<ChainInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IpVersion {
    V4,
    V6,
}

/// Which iptables ruleset a binary writes to. They are separate kernel
/// structures: a rule added with `iptables-legacy` is invisible to nft
/// and vice versa, and a host can have both in use at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IptablesVariant {
    Nft,
    Legacy,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IptablesTarget {
    pub version: IpVersion,
    pub variant: IptablesVariant,
    pub binary: PathBuf,
}

/// One `iptables -S INPUT`/`-S FORWARD` observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IptablesObservation {
    pub target: IptablesTarget,
    pub hook: Hook,
    /// Every `-A INPUT …`/`-A FORWARD …` line carrying our tag, verbatim.
    /// `None` when listing failed (binary broken, or the table is not one
    /// iptables can read — a native nftables table that happens to be
    /// called `filter`).
    pub tagged_lines: Option<Vec<String>>,
}

/// firewalld's view of our interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewalldState {
    /// Not installed, not running, or not reachable (e.g. from a
    /// container).
    Unavailable,
    Running {
        /// The zone the interface is in right now.
        runtime_zone: Option<String>,
        /// The zone an operator bound it to permanently. If set, that is a
        /// deliberate choice and we don't touch it.
        permanent_zone: Option<String>,
    },
}

/// Everything the planner looks at.
#[derive(Debug, Clone, PartialEq)]
pub struct Observed {
    /// `None` if `nft` could not be run or its output not parsed — the
    /// planner then plans nothing on the nft side rather than guessing.
    pub nft: Option<NftView>,
    pub iptables: Vec<IptablesObservation>,
    pub firewalld: FirewalldState,
    /// Interface names, other than our own, that tagged rules were seen
    /// for and whose claim a running agent holds (`lock::holder`). Their
    /// rules belong to that agent and are left alone; tagged rules for
    /// any other name are leftovers — a crashed agent, an older version,
    /// a changed `--ifname` — and removed.
    pub live: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    /// Head-insert `<opening's matches> counter accept comment
    /// "wireserve:<ifname>"` — see [`Opening`].
    NftInsert { chain: ChainRef, ifname: String, opening: Opening },
    NftDelete { chain: ChainRef, handle: u64 },
    /// `-I <INPUT|FORWARD> 1 <opening's matches> -m comment --comment
    /// wireserve:<ifname> -j ACCEPT`.
    IptablesInsert { target: IptablesTarget, ifname: String, opening: Opening },
    /// `-D` with the exact spec of one tagged line from `-S INPUT`/`-S FORWARD`.
    IptablesDelete { target: IptablesTarget, line: String },
    /// `firewall-cmd --zone=trusted --change-interface=<ifname>` (runtime only).
    FirewalldTrust { ifname: String },
    /// `firewall-cmd --zone=trusted --remove-interface=<ifname>` (runtime only).
    FirewalldUntrust { ifname: String },
    /// (Re)create table `inet wireserve-interop.<ifname>` with a forward-hook
    /// chain holding `iifname "<ifname>" drop`, plus exceptions ahead of
    /// it: a hairpin one, `iifname "<ifname>" oifname "<ifname>" accept`,
    /// for a transit-capable node (PLAN.md M23), and `iifname "<ifname>"
    /// ct mark & M == M accept` for one forwarding to a service's target
    /// address (PLAN.md M26). firewalld's zone target applies to forwarded
    /// traffic too, so trusting the interface would otherwise let mesh
    /// peers route through this host into its other networks. A drop is
    /// final across all chains, so without the exceptions this keeps
    /// forwarding from the mesh exactly as blocked as it was before either
    /// existed; with them, only traffic routed back onto this same
    /// interface, or a flow our own table rewrote to a declared target,
    /// ever escapes the drop.
    GuardCreate { ifname: String, forward: ForwardWanted },
    /// Delete a guard table, given by its full name (the legacy
    /// fixed-name one included).
    GuardDelete { table: String },
}
