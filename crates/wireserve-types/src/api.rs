//! Every wire struct from spec §4. Single source of truth for the wire
//! format — coordinator, agent, and admin all serialize/deserialize these
//! same types, never hand-duplicated structs.

use serde::{Deserialize, Serialize};

use crate::node::NodeKind;
use crate::ports::PortMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
    /// Set only for a `409` from `/poll` caused by a service-name
    /// collision (spec §4.3) — the specific declared name that collided,
    /// as a machine-readable field rather than something the agent has to
    /// string-parse out of `error`. Lets the agent quarantine exactly the
    /// offending declaration instead of the whole poll cycle wedging on
    /// it forever (see PLAN.md decisions log).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub conflicting_service: Option<String>,
}

impl ErrorBody {
    #[must_use]
    pub fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            conflicting_service: None,
        }
    }

    #[must_use]
    pub fn service_collision(error: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            conflicting_service: Some(name.into()),
        }
    }
}

// ---- §4.1 Admin: create node ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNodeRequest {
    pub name: String,
    #[serde(default)]
    pub kind: NodeKind,
    /// Override the coordinator's configured join-token lifetime for this
    /// one token, in seconds; `0` means no expiry. Omitted means "use the
    /// coordinator's default" — which is not the same as `Some(0)`, and is
    /// why this is an `Option` rather than a plain `u64` defaulting to 0.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNodeResponse {
    pub name: String,
    pub join_token: String,
    /// When this token stops being redeemable, or `None` if expiry is
    /// disabled. Returned so the operator learns the deadline at the
    /// moment they copy the token, rather than discovering it by having a
    /// `join` fail half an hour later.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub join_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// A link for the device's owner to claim it with (PLAN.md M38), when
    /// the coordinator signs owners in through an identity provider.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub claim: Option<ClaimLink>,
}

/// A single-use link that makes whoever signs in with it the owner of one
/// node (PLAN.md M38). Only an admin gets one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimLink {
    pub url: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// A node's owner, as the admin sees it (PLAN.md M38).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerInfo {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub groups: Vec<String>,
    /// Refreshing has failed for so long that the groups count for nothing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
}

// ---- Node: address probe (dual-family endpoint self-discovery) ----

/// `GET /probe` response: the bare source address the coordinator saw
/// this request arrive from (via `client_ip::resolve_client`, same as
/// `/register`'s endpoint fallback), no port. Unauthenticated,
/// unrelated to any node's registration state — a node calls it twice,
/// once over a connection forced to IPv4 and once forced to IPv6, purely
/// to learn which families it can actually reach the coordinator over.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResponse {
    pub addr: String,
    /// The UDP port `wireserve-coordinator`'s self-hosted reflexive
    /// responder (`wireserve_types::reflexive`, PLAN.md M22) is bound
    /// on — same port number as this HTTP API, just UDP (see that
    /// module's doc comment for why no separate port exists).
    pub reflexive_port: u16,
    /// The reflexive responder also answers from a second port (PLAN.md
    /// M40), so a node can tell whether traffic it never sent anything to
    /// reaches it. Absent from an older coordinator, which never does.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub answers_twice: bool,
}

// ---- §4.2 Node: register ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub join_token: String,
    pub pubkey: String,
    #[serde(default)]
    pub kind: NodeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_addr: Option<String>,
    /// Actively self-discovered via the agent's own dual-family probe
    /// against `/probe` (never derived by the coordinator from a single
    /// passively-observed connection, unlike `endpoint_addr`'s fallback) —
    /// see `wireserve-agent`'s `probe` module. Absent for a node that
    /// couldn't reach the coordinator over that family at all.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint_addr_v4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint_addr_v6: Option<String>,
    /// This node's own single "best" private-LAN address (bare IPv4, no
    /// port — RFC1918 only, v1), picked by `wireserve-agent`'s
    /// `wg::pick_lan_address` from its own network interfaces. Reported
    /// by default, same as `endpoint_addr_v4`/`_v6` — not an operator
    /// opt-in. Lets a peer on the same LAN dial it directly instead of
    /// round-tripping through a router that may not support NAT
    /// hairpin/loopback (PLAN.md decisions log #85).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub lan_addr: Option<String>,
    /// This node's own `ip:port` as observed by the coordinator's
    /// self-hosted reflexive UDP responder (PLAN.md M22) — learned once
    /// per process lifetime via a one-shot probe run immediately before
    /// `wg::WgInterface::bring_up` claims `listen_port`, since the
    /// kernel WireGuard socket that will actually carry traffic can't be
    /// multiplexed with a userspace probe. Unlike `lan_addr`, this
    /// carries its own port — it comes straight from a real observed
    /// socket address rather than borrowing one. `None` when the probe
    /// failed, or the node has real working IPv6 (this mechanism is
    /// IPv4-only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reflexive_addr: Option<String>,
    /// This node's own opt-in to carry transit traffic for other peers
    /// (PLAN.md M23) — always `false` at join time. Opt-in is a live,
    /// post-join operational decision (`wireserve transit on`), not
    /// an identity fact resolved once at bootstrap, so registration never
    /// reports anything but the default.
    #[serde(default)]
    pub transit_capable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub bearer_token: String,
    pub ip4: String,
    pub ip6: String,
    /// The mesh ranges `ip4`/`ip6` came from, for the agent to pin — see
    /// [`crate::MeshInfo`]. The agent refuses to join without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<crate::MeshInfo>,
    /// How services are named on this mesh (PLAN.md M25). Absent when the
    /// coordinator has no domain configured, which leaves `<name>.wg`
    /// untouched.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub naming: Option<crate::ServiceNaming>,
}

// ---- §4.3 Node: poll ----

/// Upper bound on the services a single node may declare (spec §4.3 puts
/// no limit on the array; this is this project's own cap). Every declared
/// service is fanned out to every other node's `/poll` response and hosts
/// file on every cycle, so without a cap one node could bloat the whole
/// mesh's directory at will.
///
/// **Lives here, not in the coordinator**, for the same reason
/// `is_valid_dns_label` does (spec §3: one definition, called from every
/// place that needs it). The agent enforces the identical limit locally
/// when `serve` queues a declaration: a limit enforced *only* at the
/// coordinator turns an over-eager operator into a permanently wedged
/// agent, because the rejected batch is resent verbatim every cycle and
/// the whole poll — peer reconciliation included — fails with it. That is
/// the same failure shape as the service-name collision handled by
/// `ErrorBody::conflicting_service`, and the cheapest fix is for both
/// sides to agree on the number up front.
pub const MAX_SERVICES_PER_NODE: usize = 64;

/// How many of a node's services may be waiting for approval, or denied, at
/// once, where approval is required. Each holds its name for the whole mesh
/// and, while it waits, an address of the mesh's range: with the limit at
/// [`MAX_SERVICES_PER_NODE`] a handful of nodes could take the whole range
/// (a /24 has 254) with declarations nobody approved, and no new node could
/// join. A node past it is told so (a notice), and declares more once an
/// admin has decided some of these; it is never a failed poll.
pub const MAX_UNAPPROVED_SERVICES_PER_NODE: usize = 16;

/// Upper bound on `PollRequest::transit_reachable` — how many pubkeys a
/// transit-capable node reports itself as currently, actually reaching
/// (PLAN.md M23). Same order of magnitude as [`MAX_SERVICES_PER_NODE`],
/// for the same reason: a self-reported, unbounded-by-spec array fanned
/// into shared state on every poll needs a cap agreed by both sides up
/// front, not enforced coordinator-side alone.
pub const MAX_TRANSIT_REACHABLE_PER_POLL: usize = 64;

/// Upper bound on `PollRequest::transit_wanted` — how many pubkeys a node
/// reports itself as unable to reach directly and wanting transit help
/// for (PLAN.md M23). Same reasoning and value as
/// [`MAX_TRANSIT_REACHABLE_PER_POLL`].
pub const MAX_TRANSIT_WANTED_PER_POLL: usize = 64;

/// What an agent tells the coordinator it can do, beyond what every agent
/// that polls can. Checked by admin actions whose effect is unsafe on an
/// agent that would silently ignore it.
///
/// `tls-terminate` (PLAN.md M33): this agent runs, or can run, the
/// terminator that serves its own 443 services with TLS on their own
/// addresses, as soon as one has checked in, whether or not a service is
/// ready yet.
pub const CAP_TLS_TERMINATE: &str = "tls-terminate";

/// `sign-in` (PLAN.md M34, M36): this agent's terminator lets a caller into
/// a restricted service by its device's grants, or else by the groups it
/// proves at the sign-in, and its firewall opens a restricted service's
/// terminated 443 to everyone only while the terminator decides. Without
/// it, a service's owner is never told to rely on the sign-in.
pub const CAP_SIGN_IN: &str = "sign-in";

/// `relay` (PLAN.md M39): this agent runs a carry interface, so sessions
/// with it can be relayed end to end, and, when it carries, forwards only
/// the ciphertext of other nodes' sessions. Relaying is only ever arranged
/// between nodes that all say so.
pub const CAP_RELAY: &str = "relay";

/// How many relay slots a mesh has (PLAN.md M39): a node's relay port is
/// the coordinator's base plus its slot, so the ports run from the base to
/// the base plus this, less one. The same number again after them is where
/// a carrier's relayed phone sessions leave from (PLAN.md M40).
pub const RELAY_SLOTS: u16 = 1000;

/// The default first relay port (`WIRESERVE_RELAY_PORT_BASE`).
pub const DEFAULT_RELAY_PORT_BASE: u16 = 41000;

/// A node's relay port: `base` plus its slot, or `None` for a node without
/// one or a slot outside the range.
#[must_use]
pub fn relay_port(base: u16, slot: Option<u16>) -> Option<u16> {
    slot.filter(|s| *s < RELAY_SLOTS).and_then(|s| base.checked_add(s))
}

/// At most this many names are read from one poll's `tls_ready`.
pub const MAX_TLS_READY_PER_POLL: usize = 64;

/// At most this many capability strings are read from one poll.
pub const MAX_CAPABILITIES_PER_POLL: usize = 16;

/// At most this many device addresses are read from one poll's
/// `callers_seen`.
pub const MAX_CALLERS_SEEN_PER_POLL: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDecl {
    pub name: String,
    /// Public→target mappings on the service's own address; never empty
    /// (see [`crate::validate_service_ports`]).
    pub ports: Vec<PortMap>,
    /// The service group it should join (PLAN.md M36). Honoured once: when
    /// the service is first approved and has no group yet. After that only
    /// an admin changes its groups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

impl ServiceDecl {
    /// A declaration of `ports`, which must not be empty (validate with
    /// [`crate::validate_service_ports`] first).
    #[must_use]
    pub fn new(name: impl Into<String>, ports: Vec<PortMap>) -> Self {
        Self { name: name.into(), ports, group: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_addr: Option<String>,
    /// See `RegisterRequest::endpoint_addr_v4`'s doc comment — same
    /// active self-discovery, re-run every poll cycle.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint_addr_v4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint_addr_v6: Option<String>,
    /// See `RegisterRequest::lan_addr`'s doc comment — same active
    /// self-discovery, re-run every poll cycle.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub lan_addr: Option<String>,
    /// See `RegisterRequest::reflexive_addr`'s doc comment. Resent
    /// verbatim on every poll (the value itself is learned once, not
    /// re-probed per cycle) so the coordinator's COALESCE contract stays
    /// uniform across every self-reported field.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reflexive_addr: Option<String>,
    /// This node's own live opt-in to carry transit traffic (PLAN.md
    /// M23) — see `RegisterRequest::transit_capable`. Resent every poll,
    /// same as every other self-reported field, since it's a live toggle
    /// (`wireserve transit on/off`) rather than a one-time fact.
    #[serde(default)]
    pub transit_capable: bool,
    /// This node's own live opt-in to be an exit for the devices that use
    /// it as their gateway (PLAN.md M27, `wireserve exit on/off`).
    /// Separate from `transit_capable`: forwarding between mesh members
    /// is one consent, sending a device's traffic to the internet under
    /// this node's own public address is another. Absent when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exit_capable: bool,
    /// Pubkeys this node currently sees a fresh kernel handshake with —
    /// its own ground truth for "I actually reach this peer right now"
    /// (PLAN.md M23). Only meaningful, and only populated, when
    /// `transit_capable` is true; capped at
    /// [`MAX_TRANSIT_REACHABLE_PER_POLL`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transit_reachable: Vec<String>,
    /// Pubkeys this node's own `wg::EndpointTracker` has given up on
    /// every ranked tier for — "I need help reaching these" (PLAN.md
    /// M23). Sent regardless of this node's own `transit_capable` value,
    /// since any node may need transit help even if it can't offer it;
    /// capped at [`MAX_TRANSIT_WANTED_PER_POLL`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transit_wanted: Vec<String>,
    #[serde(default)]
    pub services: Vec<ServiceDecl>,
    /// What this agent can do — see [`CAP_TLS_TERMINATE`] and
    /// [`CAP_SIGN_IN`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// This node's services whose TLS the local terminator is serving right
    /// now — certificate held, `vip:443` bound (PLAN.md M33). Only these are
    /// ever `terminated` in the directory; anything else keeps the path it
    /// had. Capped at [`MAX_TLS_READY_PER_POLL`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls_ready: Vec<String>,
    /// The devices (by mesh address) that have connected to this node's
    /// terminator recently (PLAN.md M38). The coordinator names the owner
    /// of a device to a node only once the node says the device has been
    /// there: a node holds no directory of everyone's e-mail address and
    /// groups on the chance one of them calls. Capped at
    /// [`MAX_CALLERS_SEEN_PER_POLL`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callers_seen: Vec<std::net::Ipv4Addr>,
    /// The listen port of this node's carry interface (PLAN.md M39), when
    /// it has one. Chosen by the kernel, so reported every poll.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carry_port: Option<u16>,
    /// Whether a packet from outside reaches this node's WireGuard port
    /// (PLAN.md M40), as tested once at startup: the coordinator answers the
    /// reflexive probe a second time from another port, which only arrives
    /// where inbound traffic is let in. `None` when it could not be tested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dialable_v4: Option<bool>,
    /// The port checks this node was asked to run (PLAN.md M40) and the
    /// nonce each one received from the coordinator.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_checks_seen: Vec<PortCheck>,
}

/// A check that one of a carrier's public relay ports is open (PLAN.md
/// M40): the carrier listens on `port` for a while, and the coordinator
/// sends `nonce` to it from outside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortCheck {
    pub port: u16,
    /// 16 hex digits.
    pub nonce: String,
}

/// At most this many port checks are read from one poll.
pub const MAX_PORT_CHECKS_PER_POLL: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub name: String,
    pub pubkey: String,
    pub ip4: String,
    pub ip6: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_addr: Option<String>,
    /// This peer's actively self-discovered candidates — see
    /// `RegisterRequest::endpoint_addr_v4`. `endpoint_addr` above (an
    /// operator's explicit override, or the older passive fallback) still
    /// wins over both when present; see `wg::choose_peer_endpoint`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint_addr_v4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint_addr_v6: Option<String>,
    /// This peer's own reported LAN address — see
    /// `RegisterRequest::lan_addr`. Used by `wg::choose_peer_endpoint`
    /// only when this node's own local subnets actually contain it; never
    /// trusted on its own, since unrelated sites commonly share the same
    /// private ranges (PLAN.md decisions log #85).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub lan_addr: Option<String>,
    /// This peer's own reflexive address — see
    /// `RegisterRequest::reflexive_addr`. Used by
    /// `wg::choose_peer_endpoint` once `wg::EndpointTracker` has
    /// actually verified it with a real handshake; never trusted
    /// outright, since a NAT's mapping can be wrong or the peer behind
    /// symmetric NAT (PLAN.md decisions log #90+).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reflexive_addr: Option<String>,
    /// See PLAN.md decisions log #3: approximated from the coordinator's
    /// own `last_seen` bookkeeping, not a true WireGuard handshake
    /// observation (the coordinator is never itself a WireGuard peer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_handshake: Option<chrono::DateTime<chrono::Utc>>,
    /// How this peer is reached through a carrier that forwards only
    /// ciphertext (PLAN.md M39) — see [`PeerRelay`].
    #[serde(default, skip_serializing_if = "PeerRelay::is_empty")]
    pub relay: PeerRelay,
}

/// A peer's part in end-to-end relaying (PLAN.md M39, M40). A carrier
/// forwards the UDP of a WireGuard session between two other nodes without
/// ever holding its keys: packets for this peer arrive at the carrier's
/// mesh address on `port`, are sent on to this peer's `carry_port`, and
/// leave the carrier from the sender's own `port`, so each side sees the
/// other always at the same carrier address and port.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRelay {
    /// This peer's own WireGuard listen port, which a phone's session
    /// relayed through a carrier's public port ends on (PLAN.md M40).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    /// This peer's relay port: the same on every carrier, and stable for
    /// as long as the peer exists. `None` on a coordinator that assigns
    /// none, or for a peer that has none yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The listen port of this peer's carry interface, which relayed
    /// sessions end on. `None` for a peer that cannot be relayed to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carry_port: Option<u16>,
    /// The pubkey of the carrier the *requester* of this poll reaches this
    /// peer through right now, computed afresh for each (requester, peer)
    /// pair — two nodes can get different answers for the same peer.
    /// Always `None` in `GET /admin/peers`, which has no requester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

impl PeerRelay {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub node: String,
    /// The owning node's address.
    pub ip4: String,
    pub online: bool,
    /// The service's own address, which its name resolves to and every
    /// peer routes to the owning node. `None` only while the coordinator
    /// has none left to give it — such a service is reachable nowhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vip4: Option<String>,
    /// Its public→target mappings, target addresses left out (PLAN.md M26).
    pub ports: Vec<PortMap>,
    /// Served with TLS by its own node (PLAN.md M33) right now. Absent when
    /// false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub terminated: bool,
}

/// A declaration the coordinator accepted and stored but has NOT put in
/// the directory, because service approval is required and no admin has
/// approved it for this node yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingService {
    pub name: String,
    pub ports: Vec<PortMap>,
    /// The address the service will have once approved. Sent to its owner
    /// alone, so the owner's firewall is ready the moment approval puts
    /// the service in everyone else's directory — nothing routes to it
    /// before then.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vip4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub declared_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A declaration an admin explicitly refused. The agent drops it from
/// `declared_services` on receipt — exactly as it does for a name
/// collision — which both withdraws the advertisement and closes the
/// local firewall hole, since firewall rules derive from that list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeniedService {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub denied_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Cap on an admin-supplied denial reason.
///
/// It rides back to the declaring node on every poll until that node
/// quarantines the declaration, and then sits in `wireserve list` output.
/// Lives here, not in the coordinator, so `wireserve-admin` can refuse an
/// over-long one before spending a round trip — the same reasoning as
/// [`MAX_SERVICES_PER_NODE`].
pub const MAX_DENY_REASON_LEN: usize = 256;

/// A pair of peers, by pubkey, whose session THIS polling node relays
/// (PLAN.md M39) — only ever in the carrier's own response; the two ends
/// see `PeerRelay::via` on each other's entry instead. Both are peers in
/// the same response, which is where their addresses and ports come from
/// (`wireserve-agent`'s `wg::relay_forwards`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitPair {
    pub a: String,
    pub c: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PollResponse {
    pub peers: Vec<PeerInfo>,
    pub services: Vec<ServiceInfo>,
    /// Every pair whose end-to-end session THIS node relays right now
    /// (PLAN.md M39): it forwards their UDP between the two relay ports and
    /// never sees inside. Both are in `peers`, which is where their
    /// addresses and ports come from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_carrying: Vec<TransitPair>,
    /// The nodes THIS node relays phones to through its public relay port
    /// (PLAN.md M40), by pubkey: each one's relay port on this node's public
    /// address goes on to that node's own WireGuard port.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_public: Vec<String>,
    /// The first relay port (`WIRESERVE_RELAY_PORT_BASE`): relay ports run
    /// from it for [`RELAY_SLOTS`], and the phone sessions a carrier relays
    /// leave it from the [`RELAY_SLOTS`] after those.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_port_base: Option<u16>,
    /// Port checks THIS node should run now (PLAN.md M40).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_checks: Vec<PortCheck>,
    /// THIS node asked to carry transit (`transit_capable`) but no admin
    /// has approved it as a carrier, so the coordinator is ignoring the
    /// offer. A self-reported offer is never enough on its own: a carrier
    /// sees who talks to whom and can drop it, and an exit reads what it
    /// sends on, so only an admin decides who may be one. Reported so
    /// `wireserve list` can say why the node never carries
    /// anything; absent from the JSON when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub transit_awaiting_approval: bool,
    /// Pubkeys of the devices THIS node is the exit for (PLAN.md M27):
    /// static peers routing through it as their gateway whose exported
    /// config included the full-tunnel profile. Each is also in `peers`,
    /// which is where its address comes from. Sent whether or not this node
    /// has opted in with `exit on`; the agent acts on it only if it has.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exit_clients: Vec<String>,
    /// The coordinator's mesh ranges. A node that joined before
    /// registration carried them pins them from here, once; after that a
    /// different value is only ever reported, never adopted — see
    /// [`crate::MeshInfo`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<crate::MeshInfo>,
    /// How services are named on this mesh (PLAN.md M25). Absent when the
    /// coordinator has no domain configured, which leaves `<name>.wg`
    /// untouched.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub naming: Option<crate::ServiceNaming>,
    /// Who may reach each of THIS node's own services, pending ones
    /// included (PLAN.md M36) — never anyone else's. An own service missing
    /// here is closed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub access: Vec<crate::ServiceAccess>,
    /// What THIS node should know about the groups its declarations named
    /// (PLAN.md M36). A declaration with a notice may not be published.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_notices: Vec<crate::ServiceNotice>,
    /// Who owns the devices that may reach THIS node's terminated services
    /// (PLAN.md M38), for its terminator to tell its backends. Only to a
    /// node with a terminated service, and only those devices.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identities: Vec<crate::CallerIdentity>,
    /// THIS node's own declarations awaiting approval — never anyone
    /// else's.
    ///
    /// Reported on a **successful** response, not as an error, and that
    /// is load-bearing. Any `/poll` error aborts the whole cycle: peer
    /// reconciliation, firewall and hosts sync are all skipped, and since
    /// the agent resends the same declaration every cycle, an error for a
    /// pending declaration would fail identically forever — the node
    /// would stop seeing new peers and would never see its own
    /// revocation. Pending is a normal, possibly long-lived state.
    ///
    /// `skip_serializing_if` also means these bytes are absent whenever
    /// nothing is pending, so "approval disabled behaves exactly as
    /// before" holds at the wire level for free.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_services: Vec<PendingService>,
    /// THIS node's own declarations an admin refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_services: Vec<DeniedService>,
}

/// Approval state of a service, as reported to the admin. Derived from
/// the stored timestamps rather than stored itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceApprovalState {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminServiceInfo {
    pub name: String,
    pub node: String,
    pub ip4: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vip4: Option<String>,
    pub ports: Vec<PortMap>,
    pub state: ServiceApprovalState,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub declared_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub approved_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub denied_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub denied_reason: Option<String>,
    /// The service groups it is in (PLAN.md M36): its explicit ones, or
    /// `default`. They belong to the name, so they survive a withdraw and
    /// re-declare.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Where the service's public DNS record stands (PLAN.md M32). Absent
    /// when the coordinator publishes no records, or this service has no
    /// public name.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dns: Option<DnsRecordState>,
}

/// Where one public DNS record stands (PLAN.md M32).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "error")]
pub enum DnsRecordState {
    Published,
    /// Not written yet: a new name before the next pass, or a changed
    /// address that has not held long enough to be written.
    Pending,
    /// The provider refused the last attempt.
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminServicesResponse {
    pub services: Vec<AdminServiceInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DenyServiceRequest {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
}

// ---- §4.5 Admin: rejoin ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejoinRequest {
    /// Same meaning as `CreateNodeRequest::ttl_secs`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ttl_secs: Option<u64>,
    /// The kind the caller believes this node is, checked *before* the
    /// rejoin mutates anything (PLAN.md M24). `None` skips the check, which
    /// is what every caller written before this field did.
    ///
    /// Load-bearing for `export-config --refresh`: a rejoin nulls the node's
    /// pubkey, which drops it out of `list_all_peers` and so off every other
    /// node's directory on their next poll. Registration is where a `kind`
    /// mismatch would otherwise be caught, and that is one round trip too
    /// late — `--refresh` aimed at an agent node by mistake would kick a live
    /// node off the mesh and only *then* fail. An admin CLI cannot pre-check
    /// this itself: `PeerInfo` carries no `kind`, and a separate lookup would
    /// race the rejoin regardless.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kind: Option<NodeKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejoinResponse {
    pub name: String,
    pub join_token: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub join_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// `PUT /admin/nodes/{name}/export` (PLAN.md M40, M41) — records how a
/// static peer's exported `.conf` is shaped: which node is its exit, and
/// which nodes it reaches through which carrier. The `.conf` is a snapshot,
/// and this describes that snapshot; the coordinator acts on it (a carrier
/// forwards exactly these, an exit sends on exactly this device's traffic)
/// rather than on anything re-derived later.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportRecord {
    /// The node whose full-tunnel profile the export rendered (PLAN.md
    /// M27), which must then send this device's internet traffic on.
    /// `None` for a mesh-only export.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<String>,
    /// The nodes the device reaches through a carrier's public relay port,
    /// each with that carrier.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<RelayAssignment>,
}

/// One node a device reaches through a carrier (PLAN.md M40).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAssignment {
    pub node: String,
    pub carrier: String,
}

/// `POST /admin/relays/plan` (PLAN.md M40): how a device exported now
/// reaches each node — directly, or through which carrier's public relay
/// port — with that port checked from the internet first.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayPlanRequest {
    /// Keep a relay whose port could not be confirmed open (`export-config
    /// --allow-unverified`), for an operator who knows better than the
    /// check, which runs from the coordinator's own network.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_unverified: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayPlan {
    /// Nodes a device dials directly: they accept inbound WireGuard.
    #[serde(default)]
    pub direct: Vec<String>,
    /// Nodes it reaches through a carrier.
    #[serde(default)]
    pub relayed: Vec<RelayPlanEntry>,
    /// Nodes nothing reaches from outside: not dialable, and no carrier
    /// qualifies. Left out of the `.conf`, with the reason.
    #[serde(default)]
    pub unreachable: Vec<Unreachable>,
    /// Relay ports that must be opened before the plan can be used — the
    /// export stops with exactly these unless `allow_unverified`.
    #[serde(default)]
    pub closed: Vec<RelayPortStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPlanEntry {
    pub node: String,
    pub carrier: String,
    /// `<carrier public IPv4>:<the node's relay port>`, the `Endpoint =`.
    pub endpoint: String,
    /// Whether the port was seen open from outside; `None` when it could
    /// not be checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<bool>,
    /// The carrier is the coordinator's own host, so a check from here
    /// never leaves the machine and can't see a firewall in front of it:
    /// not checked, and the operator is told to make sure by hand.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unverifiable_here: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unreachable {
    pub node: String,
    pub reason: String,
}

/// `GET /admin/relay-ports` (PLAN.md M40): every public relay port a
/// carrier has or had, what it serves and whether it may be closed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayPortsResponse {
    #[serde(default)]
    pub ports: Vec<RelayPortStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPortStatus {
    pub carrier: String,
    /// The carrier's public IPv4 address, where the port has to be open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    pub port: u16,
    /// The node the port leads to, when one still has it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// The devices whose `.conf` uses it; empty means it may be closed.
    #[serde(default)]
    pub devices: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<bool>,
}

// ---- §4.5.1 Admin: list peers ----

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdminPeersResponse {
    pub peers: Vec<PeerInfo>,
    /// Names of the nodes an admin has approved to carry transit traffic.
    /// Admin-only on purpose: `PeerInfo` also goes to every node, and
    /// which nodes may relay is nothing the rest of the mesh needs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transit_approved: Vec<String>,
    /// Names of the nodes whose own most recent poll offered to carry
    /// traffic — the other half of the pair (PLAN.md M24).
    ///
    /// Both are needed to pick a gateway, and neither implies the other:
    /// approval is the mesh admin's trust, this is whether the daemon is
    /// actually set up to forward. A node approved but never switched on
    /// with `wireserve transit on` never opened its host firewall's
    /// forward hook, so it would accept the forward in its own table while
    /// ufw or firewalld dropped it. Reported here so that is caught before
    /// anything is created rather than after.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transit_offering: Vec<String>,
    /// Whether each agent found itself dialable from outside at its last
    /// start (PLAN.md M40), by name; agents that couldn't tell are left out.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub dialable: std::collections::BTreeMap<String, bool>,
    /// Static peers whose `.conf` no longer matches the mesh (PLAN.md M40):
    /// a node joined after the export, or a carrier it relies on no longer
    /// qualifies. `export-config --refresh` brings one up to date.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale_devices: Vec<String>,
    /// Released service addresses each device still holds back (PLAN.md
    /// #273): its `.conf` may route them to the node that had them, so no
    /// other node's service gets them until it is exported again or
    /// deleted. Such a device is stale too.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub held_addresses: std::collections::BTreeMap<String, Vec<String>>,
    /// Names of the nodes whose most recent poll offered to be an exit
    /// (`wireserve exit on`, PLAN.md M27), approved for transit or
    /// not — the export checks both.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exit_offering: Vec<String>,
    /// Names of the static peers whose last export included the
    /// full-tunnel profile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exit_devices: Vec<String>,
    /// Each node's tags (PLAN.md M36), by node name; nodes without any are
    /// left out. Admin-only: a node never learns who else is tagged what.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub tags: std::collections::BTreeMap<String, Vec<String>>,
}

/// `POST /admin/groups` (PLAN.md M36).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
}

/// One service group, as `GET /admin/groups` lists it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub name: String,
    /// Service names explicitly in it — declared or not. For `default`,
    /// every declared service without an explicit group.
    pub services: Vec<String>,
    /// Who it is granted to.
    pub granted_to: Vec<crate::GrantSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupsResponse {
    pub groups: Vec<GroupInfo>,
}

/// `PUT` / `DELETE /admin/groups/{group}/services/{service}`: the groups
/// the service is in afterwards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipResponse {
    pub service: String,
    pub groups: Vec<String>,
}

/// A grant, as `POST` / `DELETE /admin/grants` take it and
/// `GET /admin/grants` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantInfo {
    pub source: crate::GrantSource,
    pub group: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantsResponse {
    pub grants: Vec<GrantInfo>,
}

/// One node reaching a service, and the principals that let it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessVia {
    pub name: String,
    pub via: Vec<crate::GrantSource>,
}

/// `GET /admin/access/services/{name}`: who reaches a service, and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccessReport {
    pub service: String,
    /// The declaring node, if anything declares it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    pub groups: Vec<String>,
    pub granted_to: Vec<crate::GrantSource>,
    /// Everyone reaches it.
    pub open: bool,
    /// Nodes that reach it by who they are, when not open.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<AccessVia>,
    /// Anyone else may try the sign-in, and gets in with one of
    /// `sign_in_groups`.
    pub sign_in: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sign_in_groups: Vec<String>,
    /// `everyone -> default` has been removed: services without a group
    /// reach nobody but their own node.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub default_closed: bool,
}

/// `GET /admin/access/nodes/{name}`: what a node reaches, and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAccessReport {
    pub node: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<OwnerInfo>,
    pub principals: Vec<crate::GrantSource>,
    pub services: Vec<AccessVia>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub default_closed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_request_defaults_kind_to_agent_when_omitted() {
        let json = r#"{"join_token":"jtk_x","pubkey":"abc"}"#;
        let req: RegisterRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.kind, NodeKind::Agent);
        assert!(req.listen_port.is_none());
        assert!(req.endpoint_addr.is_none());
        assert!(req.endpoint_addr_v4.is_none());
        assert!(req.endpoint_addr_v6.is_none());
        assert!(req.lan_addr.is_none());
        assert!(req.reflexive_addr.is_none());
    }

    #[test]
    fn poll_request_defaults_services_to_empty_when_omitted() {
        let json = r#"{}"#;
        let req: PollRequest = serde_json::from_str(json).unwrap();
        assert!(req.services.is_empty());
        assert!(req.endpoint_addr.is_none());
        assert!(req.endpoint_addr_v4.is_none());
        assert!(req.endpoint_addr_v6.is_none());
        assert!(req.lan_addr.is_none());
        assert!(req.reflexive_addr.is_none());
    }

    #[test]
    fn poll_response_omits_the_approval_fields_when_empty() {
        // The wire half of "approval disabled behaves exactly as before":
        // the keys must be absent from the JSON, not merely empty arrays.
        let resp = PollResponse {
            peers: vec![],
            services: vec![],
            pending_services: vec![],
            denied_services: vec![],
            relay_carrying: vec![],
            relay_public: vec![],
            relay_port_base: None,
            port_checks: vec![],
            transit_awaiting_approval: false,
            exit_clients: vec![],
            mesh: None,
            naming: None,
            access: vec![],
            service_notices: vec![],
            identities: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("pending_services"), "{json}");
        assert!(!json.contains("denied_services"), "{json}");
        assert!(!json.contains("transit_carrying"), "{json}");
        assert!(!json.contains("transit_awaiting_approval"), "{json}");
    }

    #[test]
    fn poll_response_without_the_approval_fields_still_deserializes() {
        // Empty lists are left off the wire; reading them back must work.
        let resp: PollResponse = serde_json::from_str(r#"{"peers":[],"services":[]}"#).unwrap();
        assert!(resp.pending_services.is_empty());
        assert!(resp.denied_services.is_empty());
    }

    #[test]
    fn poll_response_roundtrips() {
        let resp = PollResponse {
            peers: vec![PeerInfo {
                name: "homeserver".into(),
                pubkey: "abc".into(),
                ip4: "100.90.0.3".into(),
                ip6: "fd00:90::3".into(),
                endpoint_addr: Some("duckdns.example.com:51820".into()),
                endpoint_addr_v4: Some("203.0.113.5:51820".into()),
                endpoint_addr_v6: None,
                lan_addr: None,
                reflexive_addr: Some("203.0.113.5:55123".into()),
                last_handshake: None,
                relay: Default::default(),
            }],
            services: vec![ServiceInfo {
                terminated: false,
                name: "plex".into(),
                node: "homeserver".into(),
                ip4: "100.90.0.3".into(),
                online: true,
                vip4: None,
                ports: vec![],
            }],
            pending_services: vec![],
            denied_services: vec![],
            relay_carrying: vec![],
            relay_public: vec![],
            relay_port_base: None,
            port_checks: vec![],
            transit_awaiting_approval: false,
            exit_clients: vec![],
            mesh: None,
            naming: None,
            access: vec![],
            service_notices: vec![],
            identities: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: PollResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.peers.len(), 1);
        assert_eq!(
            back.peers[0].endpoint_addr_v4.as_deref(),
            Some("203.0.113.5:51820")
        );
        assert!(back.peers[0].endpoint_addr_v6.is_none());
        assert_eq!(back.peers[0].reflexive_addr.as_deref(), Some("203.0.113.5:55123"));
        assert_eq!(back.services[0].name, "plex");
    }
}
