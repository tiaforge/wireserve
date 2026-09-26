//! Every wire struct from spec §4. Single source of truth for the wire
//! format — coordinator, agent, and admin all serialize/deserialize these
//! same types, never hand-duplicated structs.

use serde::{Deserialize, Serialize};

use crate::node::{NodeKind, Proto};
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
    /// module's doc comment for why no separate port exists). Absent
    /// for an older coordinator that predates the feature, which an
    /// agent must treat as a clean "nothing to probe," never an error.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reflexive_port: Option<u16>,
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
    /// couldn't reach the coordinator over that family at all, or for an
    /// older agent that predates this field.
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
    /// failed, the node has real working IPv6 (this mechanism is
    /// IPv4-only), or the coordinator predates the feature.
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
    /// [`crate::MeshInfo`]. Absent from a coordinator that predates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<crate::MeshInfo>,
    /// How services are named on this mesh (PLAN.md M25). Absent when the
    /// coordinator has no domain configured, which leaves `<name>.wg`
    /// untouched — and absent from a coordinator that predates it.
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
/// `service-auth` (PLAN.md M29): this agent restricts a service marked for
/// sign-in to the proxy's address, and, as the proxy, puts the sign-in in
/// front of it. An agent without either half would leave a marked service
/// open, one way or the other.
pub const CAP_SERVICE_AUTH: &str = "service-auth";

/// At most this many capability strings are read from one poll.
pub const MAX_CAPABILITIES_PER_POLL: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDecl {
    pub name: String,
    /// The first mapping's target port and protocol. All a coordinator
    /// from before port mappings understands; a newer one reads `ports`.
    pub port: u16,
    pub proto: Proto,
    /// Public→target mappings on the service's own address. Empty on a
    /// declaration from before port mappings existed, which stands for
    /// the one identity mapping `port:port/proto` — see
    /// [`ServiceDecl::port_maps`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortMap>,
}

impl ServiceDecl {
    /// A declaration of `ports`, which must not be empty (validate with
    /// [`crate::validate_service_ports`] first).
    #[must_use]
    pub fn new(name: impl Into<String>, ports: Vec<PortMap>) -> Self {
        let first = ports[0];
        Self {
            name: name.into(),
            port: first.target,
            proto: first.proto,
            ports,
        }
    }

    /// The mappings this declaration stands for, old form included.
    #[must_use]
    pub fn port_maps(&self) -> Vec<PortMap> {
        effective_ports(&self.ports, self.port, self.proto)
    }
}

/// The mappings a declaration stands for: `ports`, or the identity mapping of
/// the single `port`/`proto` a declaration from before port mappings carries.
#[must_use]
pub fn effective_ports(ports: &[PortMap], port: u16, proto: Proto) -> Vec<PortMap> {
    if ports.is_empty() {
        vec![PortMap::identity(port, proto)]
    } else {
        ports.to_vec()
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
    /// this node's own public address is another. Absent when false, so
    /// a coordinator that predates it sees nothing new.
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
    /// What this agent can do — see [`CAP_SERVICE_AUTH`]. Absent from an
    /// agent that predates it, which is exactly the one that must not be
    /// trusted with a service marked for sign-in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

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
    /// The pubkey of the node the *requester* of this poll should route
    /// through to reach this peer (PLAN.md M23), computed fresh per
    /// (requester, peer) pair every poll — `None` when this peer should
    /// be dialed directly, as before this feature existed. Pairwise, not
    /// a property of the peer itself: two different requesters can (and
    /// often will) get different answers for "the same" peer entry.
    /// `GET /admin/peers` always leaves this `None` — an admin isn't "a
    /// requester" polling on behalf of a specific node, so there is no
    /// requester to compute it relative to.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub transit_via: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub node: String,
    /// The owning NODE's address. Older agents write this into their
    /// hosts file; newer ones prefer `vip4`.
    pub ip4: String,
    pub port: u16,
    pub proto: Proto,
    pub online: bool,
    /// The service's own address, which `<name>.wg` resolves to and every
    /// peer routes to the owning node. `None` from a coordinator that
    /// predates service addresses, or for a declaration from an agent
    /// that does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vip4: Option<String>,
    /// Empty from a coordinator that predates port mappings; see
    /// [`ServiceInfo::port_maps`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortMap>,
    /// Published behind the proxy's sign-in (PLAN.md M29): the proxy puts
    /// forward_auth in front of it, and the owning node accepts it from the
    /// proxy's address only, so the sign-in cannot be walked around. Absent
    /// when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auth: bool,
}

impl ServiceInfo {
    /// The mappings this entry stands for, old form included.
    #[must_use]
    pub fn port_maps(&self) -> Vec<PortMap> {
        effective_ports(&self.ports, self.port, self.proto)
    }
}

/// A declaration the coordinator accepted and stored but has NOT put in
/// the directory, because service approval is required and no admin has
/// approved it for this node yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingService {
    pub name: String,
    pub port: u16,
    pub proto: Proto,
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

/// One active transit pairing THIS polling node must carry (PLAN.md M23)
/// — present only in the poll response of the node selected as `via` for
/// this pair, never in `a`'s or `c`'s own response (they instead see
/// `PeerInfo::transit_via` naming this node on the *other* endpoint's own
/// entry). This is how a node discovers its own role as transit carrier:
/// a bare `transit_via` can never fire on a node's own poll response,
/// since `select` only ever picks a node that already reaches both
/// endpoints directly — its own peer entries for `a` and `c` need no
/// routing help and so never carry `transit_via` themselves.
///
/// Both `a` and `c` are guaranteed to be real peers already present in
/// this same response's `peers` array — look up each one's addresses and
/// owned service VIPs there to build the actual forwarding rule
/// (`wireserve-agent`'s `wg::transit_forwards`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitPair {
    pub a: String,
    pub c: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollResponse {
    pub peers: Vec<PeerInfo>,
    pub services: Vec<ServiceInfo>,
    /// Every active transit pairing THIS node currently carries as `via`
    /// (PLAN.md M23) — see [`TransitPair`]. Empty for a node that never
    /// opted in, or that opted in but wasn't selected for anything this
    /// cycle.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transit_carrying: Vec<TransitPair>,
    /// THIS node asked to carry transit (`transit_capable`) but no admin
    /// has approved it as a carrier, so the coordinator is ignoring the
    /// offer. A self-reported offer is never enough on its own: a carrier
    /// sees the traffic it relays in the clear and can send packets as
    /// either end, so only an admin decides who may be one. Reported so
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
    /// untouched — and absent from a coordinator that predates it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub naming: Option<crate::ServiceNaming>,
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
    pub port: u16,
    pub proto: Proto,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vip4: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
    /// Marked for sign-in at the proxy (PLAN.md M29). The mark belongs to
    /// the name, not the declaration, so it survives a withdraw and
    /// re-declare.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auth: bool,
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

/// `PUT /admin/nodes/{name}/gateway` (PLAN.md M24) — records how a static
/// peer's exported `.conf` is shaped, so the coordinator can derive routing
/// that matches it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetGatewayRequest {
    /// The node this device routes through for anything not listed in
    /// `conf_peers`. `None` clears the assignment, which is the pre-gateway
    /// all-direct behaviour.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub gateway: Option<String>,
    /// The peers written into the device's `.conf` as direct `[Peer]` blocks.
    ///
    /// Sent rather than recomputed because the `.conf` is a snapshot and this
    /// describes that snapshot. Deriving it from live endpoint state later
    /// would drift against the file actually on the device, and the drift is
    /// not benign: a node that gains a routable endpoint after export would
    /// stop being routed through the gateway while the device still has no
    /// direct entry for it, breaking that path in both directions at once.
    #[serde(default)]
    pub conf_peers: Vec<String>,
    /// The export also rendered a full-tunnel profile (PLAN.md M27), so the
    /// gateway must send this device's internet traffic onwards. Recorded
    /// per export like `conf_peers`, since it describes the files handed
    /// out: a refresh without `--exit` clears it. Absent when false; a
    /// coordinator that predates it ignores it, which the admin CLI rules
    /// out beforehand by requiring the gateway in `exit_offering`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exit: bool,
}

/// `PUT /admin/services/{name}/auth` (PLAN.md M29) — whether a service is
/// published behind the proxy's sign-in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetServiceAuthRequest {
    pub enabled: bool,
}

/// `PUT /admin/nodes/{name}/via-gateway` (PLAN.md #134) — whether devices
/// exported with a gateway must reach this node through it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetViaGatewayRequest {
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SetViaGatewayResponse {
    /// Static peers whose `.conf` a refresh would change. The flag only
    /// shapes the next export; nothing already on a device changes by itself.
    #[serde(default)]
    pub affected_devices: Vec<String>,
}

// ---- §4.5.1 Admin: list peers ----

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Names of the nodes an admin marked as not dialable from outside the
    /// mesh (`wireserve-admin via-gateway`). Only `export-config` reads it:
    /// a device exported with a gateway reaches these through the gateway
    /// rather than holding a direct `[Peer]`. Admin-only like the two above,
    /// and for the same reason it is not on `PeerInfo` — agents route among
    /// themselves and never act on it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub via_gateway: Vec<String>,
    /// Names of the nodes whose most recent poll offered to be an exit
    /// (`wireserve exit on`, PLAN.md M27), approved for transit or
    /// not — the export checks both. Empty from a coordinator that predates
    /// exits, which makes `export-config --exit` refuse rather than write a
    /// profile nothing would forward.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exit_offering: Vec<String>,
    /// Names of the static peers whose last export included the
    /// full-tunnel profile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exit_devices: Vec<String>,
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
            transit_carrying: vec![],
            transit_awaiting_approval: false,
            exit_clients: vec![],
            mesh: None,
            naming: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("pending_services"), "{json}");
        assert!(!json.contains("denied_services"), "{json}");
        assert!(!json.contains("transit_carrying"), "{json}");
        assert!(!json.contains("transit_awaiting_approval"), "{json}");
    }

    #[test]
    fn poll_response_without_the_approval_fields_still_deserializes() {
        // An older coordinator's response reaching a newer agent, and a
        // state file written before the fields existed.
        let resp: PollResponse = serde_json::from_str(r#"{"peers":[],"services":[]}"#).unwrap();
        assert!(resp.pending_services.is_empty());
        assert!(resp.denied_services.is_empty());
    }

    #[test]
    fn a_declaration_without_ports_stands_for_its_identity_mapping() {
        // What an agent from before port mappings sends, and what its
        // state file holds.
        let d: ServiceDecl = serde_json::from_str(r#"{"name":"plex","port":32400,"proto":"tcp"}"#).unwrap();
        assert!(d.ports.is_empty());
        assert_eq!(d.port_maps(), vec![PortMap::identity(32400, Proto::Tcp)]);
    }

    #[test]
    fn a_new_declaration_still_carries_port_and_proto_for_old_coordinators() {
        let maps = vec!["80:5080".parse().unwrap(), "53/udp".parse().unwrap()];
        let d = ServiceDecl::new("web", maps);
        let json: serde_json::Value = serde_json::to_value(&d).unwrap();
        assert_eq!(json["port"], 5080);
        assert_eq!(json["proto"], "tcp");
        assert_eq!(json["ports"][0], serde_json::json!({"public": 80, "target": 5080, "proto": "tcp"}));
        assert_eq!(d.port_maps(), d.ports);
    }

    #[test]
    fn a_service_entry_from_an_old_coordinator_has_no_address_and_one_mapping() {
        let s: ServiceInfo = serde_json::from_str(
            r#"{"name":"plex","node":"n","ip4":"10.0.0.3","port":32400,"proto":"tcp","online":true}"#,
        )
        .unwrap();
        assert!(s.vip4.is_none());
        assert_eq!(s.port_maps(), vec![PortMap::identity(32400, Proto::Tcp)]);
        // And the new fields stay off the wire when unset, so an old agent
        // sees exactly the shape it always did.
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("vip4") && !json.contains("ports"), "{json}");
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
                transit_via: None,
            }],
            services: vec![ServiceInfo {
                auth: false,
                name: "plex".into(),
                node: "homeserver".into(),
                ip4: "100.90.0.3".into(),
                port: 32400,
                proto: Proto::Tcp,
                online: true,
                vip4: None,
                ports: vec![],
            }],
            pending_services: vec![],
            denied_services: vec![],
            transit_carrying: vec![],
            transit_awaiting_approval: false,
            exit_clients: vec![],
            mesh: None,
            naming: None,
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
        assert_eq!(back.services[0].proto, Proto::Tcp);
    }
}
