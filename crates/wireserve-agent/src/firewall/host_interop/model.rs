//! Pure data types shared by the observer, the planner and the executor.
//! Nothing here touches the system.

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

/// Our own tables. Never treated as "foreign", never written into by the
/// planner's insert logic, and changes to them never trigger a reconcile
/// (the backend replaces `wireserve` on every poll).
pub const OWN_TABLES: &[&str] = &[super::super::nftables::TABLE_NAME, GUARD_TABLE];

/// Holds the forward guard — see [`Action::GuardCreate`].
pub const GUARD_TABLE: &str = "wireserve-interop";
pub const GUARD_CHAIN: &str = "forward-guard";

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

/// One `iptables -S INPUT` observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IptablesObservation {
    pub target: IptablesTarget,
    /// Every `-A INPUT …` line carrying our tag, verbatim. `None` when
    /// listing failed (binary broken, or the table is not one iptables
    /// can read — a native nftables table that happens to be called
    /// `filter`).
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
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    /// Head-insert `iifname "<ifname>" counter accept comment "wireserve:<ifname>"`.
    NftInsert { chain: ChainRef, ifname: String },
    NftDelete { chain: ChainRef, handle: u64 },
    /// `-I INPUT 1 -i <ifname> -m comment --comment wireserve:<ifname> -j ACCEPT`.
    IptablesInsert { target: IptablesTarget, ifname: String },
    /// `-D` with the exact spec of one tagged line from `-S INPUT`.
    IptablesDelete { target: IptablesTarget, line: String },
    /// `firewall-cmd --zone=trusted --change-interface=<ifname>` (runtime only).
    FirewalldTrust { ifname: String },
    /// `firewall-cmd --zone=trusted --remove-interface=<ifname>` (runtime only).
    FirewalldUntrust { ifname: String },
    /// (Re)create table `inet wireserve-interop` with a forward-hook chain
    /// holding exactly `iifname "<ifname>" drop`. firewalld's zone target
    /// applies to forwarded traffic too, so trusting the interface would
    /// otherwise let mesh peers route through this host into its other
    /// networks. A drop is final across all chains, so this keeps
    /// forwarding from the mesh exactly as blocked as it was before.
    GuardCreate { ifname: String },
    GuardDelete,
}
