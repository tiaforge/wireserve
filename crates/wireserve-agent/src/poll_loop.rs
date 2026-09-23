//! The five-step reconciliation loop (spec §4.3): send `/poll`, reconcile
//! WireGuard peers, reconcile this node's own firewall rules, rewrite the
//! hosts-file managed block, persist merged state. A failed cycle is
//! logged and skipped rather than crashing the daemon or tearing down an
//! already-correctly-configured interface (a transient coordinator/network
//! blip shouldn't make things *more* broken than they already were).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use tokio::sync::Mutex;
use wireserve_types::{FirewallBackend, PollRequest, PollResponse, ServiceDecl, ServiceRule};

use crate::state::AgentState;
use crate::wg::WgInterface;

#[derive(Debug, thiserror::Error)]
pub enum PollError {
    #[error("HTTP error talking to coordinator: {0}")]
    Http(#[from] reqwest::Error),
    /// Carries the status code — not just the body text — so callers can
    /// tell a revoked-node 401 (F9: the daemon should notice and react,
    /// not silently retry forever with a dead bearer token) apart from
    /// any other rejection.
    #[error("coordinator rejected poll ({status}): {message}")]
    Rejected {
        status: reqwest::StatusCode,
        message: String,
    },
    #[error("WireGuard reconciliation failed: {0}")]
    Wg(#[from] defguard_wireguard_rs::error::WireguardInterfaceError),
    #[error("firewall reconciliation failed: {0}")]
    Firewall(String),
    #[error("hosts-file sync failed: {0}")]
    Hosts(#[from] std::io::Error),
    #[error(transparent)]
    State(#[from] crate::state::StateError),
    #[error("agent is not registered yet — run `wireserve-agent join` first")]
    NotRegistered,
    /// One or more of the local steps (peers, firewall, hosts file) failed
    /// while the others were still applied — see `run_once`.
    #[error("reconciliation incomplete: {}", join_failures(.0))]
    Incomplete(Vec<PollError>),
}

fn join_failures(failures: &[PollError]) -> String {
    failures.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
}

impl PollError {
    /// F9 (security review): a 401 specifically means this node's bearer
    /// token no longer works — almost always because an admin revoked it
    /// — as opposed to a transient network/server error that's worth
    /// blindly retrying.
    #[must_use]
    pub fn is_unauthorized(&self) -> bool {
        matches!(
            self,
            PollError::Rejected {
                status,
                ..
            } if *status == reqwest::StatusCode::UNAUTHORIZED
        )
    }

    /// The hosts-file step failed with `EROFS`. Under the shipped systemd
    /// unit that means the agent lost its bind mount of `/etc/hosts`:
    /// `ReadWritePaths=/etc/hosts` mounts the file into the unit's
    /// namespace over a read-only `/etc`, and when anything on the host
    /// replaces the file by rename (`sed -i`, an editor, cloud-init, this
    /// agent run by hand outside the unit) the kernel detaches that mount
    /// in every other namespace. The read-only file underneath is all
    /// that is left, and no write can succeed again until the unit is
    /// restarted and the mount set up afresh.
    #[must_use]
    pub fn hosts_read_only(&self) -> bool {
        match self {
            PollError::Hosts(e) => e.raw_os_error() == Some(libc::EROFS),
            PollError::Incomplete(failures) => failures.iter().any(Self::hosts_read_only),
            _ => false,
        }
    }

    /// The cycle got as far as the hosts file and wrote it (or found it
    /// already current), even though another step failed.
    #[must_use]
    pub fn hosts_synced(&self) -> bool {
        match self {
            PollError::Incomplete(failures) => !failures.iter().any(|e| matches!(e, PollError::Hosts(_))),
            _ => false,
        }
    }
}

/// This node's own transit self-report for one poll cycle (PLAN.md M23) —
/// bundled into its own type rather than three more `build_poll_request`
/// parameters. See `PollRequest`'s own field doc comments for what each
/// one means.
pub struct TransitSelfReport {
    pub capable: bool,
    pub reachable: Vec<String>,
    pub wanted: Vec<String>,
}

/// Builds the request body from currently-declared services — this is the
/// node's own view of what it's serving, independent of anything the
/// coordinator has told it. `dual` is this cycle's actively-probed
/// endpoint candidates (see `probe::probe_both`) — always sent verbatim
/// (including `None`s), same COALESCE-preserving contract the coordinator
/// already applies to them.
pub fn build_poll_request(
    declared: &[ServiceDecl],
    endpoint_addr: Option<String>,
    dual: &crate::probe::DualProbeResult,
    lan_addr: Option<String>,
    reflexive_addr: Option<String>,
    transit: TransitSelfReport,
) -> PollRequest {
    PollRequest {
        endpoint_addr,
        endpoint_addr_v4: dual.v4.clone(),
        endpoint_addr_v6: dual.v6.clone(),
        lan_addr,
        reflexive_addr,
        transit_capable: transit.capable,
        transit_reachable: transit.reachable,
        transit_wanted: transit.wanted,
        services: declared.to_vec(),
    }
}

/// The mesh ranges to check this cycle's directory against (see
/// `crate::mesh`): the pinned ones, pinning `offered` first if nothing is
/// pinned yet and it contains this node's own addresses. `None` — nothing
/// filtered — only while no verifiable range has ever been offered, i.e.
/// against a coordinator that predates them.
async fn pinned_mesh_ranges(
    state: &Mutex<AgentState>,
    state_path: &Path,
    offered: Option<&wireserve_types::MeshInfo>,
) -> Result<Option<wireserve_types::MeshRanges>, PollError> {
    static DIFFERENT_OFFER_REPORTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let mut s = state.lock().await;
    match (&s.mesh, offered) {
        (None, Some(offered)) if crate::mesh::pinnable(offered, s.ip4.as_deref(), s.ip6.as_deref()) => {
            tracing::info!(
                v4 = %offered.net_v4_cidr,
                v6 = %offered.net_v6_prefix,
                "pinned the mesh ranges; directory entries outside them are ignored from now on"
            );
            s.mesh = Some(offered.clone());
            s.save(state_path)?;
        }
        (Some(pinned), Some(offered))
            if pinned != offered && !DIFFERENT_OFFER_REPORTED.swap(true, std::sync::atomic::Ordering::Relaxed) =>
        {
            tracing::warn!(
                pinned_v4 = %pinned.net_v4_cidr,
                pinned_v6 = %pinned.net_v6_prefix,
                offered_v4 = %offered.net_v4_cidr.escape_debug(),
                offered_v6 = %offered.net_v6_prefix.escape_debug(),
                "the coordinator now reports different mesh ranges than this node pinned; keeping \
                 the pinned ones (join again to adopt the new ranges)"
            );
        }
        _ => {}
    }
    Ok(s.mesh.as_ref().and_then(wireserve_types::MeshRanges::parse))
}

/// Firewall rules are derived from what THIS node declared in the request
/// it just sent — never from the full mesh directory (spec §5: "a node
/// only ever firewalls itself").
///
/// The coordinator's response contributes exactly one thing: the address
/// of each of this node's own services, looked up by name among the
/// entries that name this node's address as owner (or among its own
/// pending declarations, so the rules are in place before approval makes
/// anyone route to it). That decides which destination the rewrite
/// matches, never what is opened: every port in every rule comes from
/// `declared`. A service with no address — a coordinator from before
/// service addresses, or one [`crate::vip::sanitize`] refused — is opened
/// on its target ports directly, the way every service was before.
///
/// A service opened directly is opened on this node's own mesh addresses
/// only (`node_ip`, plus `node_ip6` when it has one) — never on the port
/// alone, see `ServiceRule::Open`. With no IPv4 mesh address known there
/// is nothing to scope it to, so nothing is opened at all.
///
/// A target port can carry only one mapping (see
/// `wireserve_types::validate_node_targets`); `serve` refuses a second,
/// but a state file from before port mappings may still alias one port
/// under two names. The first keeps it, and the later ones get no mapping
/// rather than one whose replies would come back from the wrong address.
pub fn service_rules(
    declared: &[ServiceDecl],
    node_ip: Option<Ipv4Addr>,
    node_ip6: Option<Ipv6Addr>,
    directory: &PollResponse,
) -> Vec<ServiceRule> {
    let mut rules = Vec::new();
    let mut targets: Vec<(u16, wireserve_types::Proto)> = Vec::new();
    for d in declared {
        let vip = node_ip.and_then(|node| own_vip(&d.name, node, directory));
        for map in d.port_maps() {
            let rule = match (vip, node_ip) {
                (Some(vip), Some(node)) => {
                    if targets.contains(&(map.target, map.proto)) {
                        tracing::warn!(
                            service = %d.name,
                            port = %map,
                            "target port already mapped by another service — not mapping it again"
                        );
                        continue;
                    }
                    targets.push((map.target, map.proto));
                    ServiceRule::Mapped { vip, node, map }
                }
                (None, Some(node)) => ServiceRule::Open {
                    proto: map.proto,
                    port: map.target,
                    node,
                    node6: node_ip6,
                },
                (_, None) => continue,
            };
            rules.push(rule);
        }
    }
    rules
}

fn own_vip(name: &str, node: Ipv4Addr, directory: &PollResponse) -> Option<Ipv4Addr> {
    let node = node.to_string();
    let published = directory
        .services
        .iter()
        .find(|s| s.name == name && s.ip4 == node)
        .and_then(|s| s.vip4.as_deref());
    let pending = || {
        directory
            .pending_services
            .iter()
            .find(|p| p.name == name)
            .and_then(|p| p.vip4.as_deref())
    };
    published.or_else(pending)?.parse().ok()
}

/// Parses a `/poll` error body for a `conflicting_service` name (spec
/// §4.3's 409, coordinator side) and, if present, removes it from
/// `declared_services` and records why in `rejected_services` (security
/// review F3). Kept pure/testable separately from the network call.
/// Returns whether it actually quarantined anything, so the caller knows
/// whether `state` needs saving.
pub fn quarantine_rejected_service(state: &mut AgentState, error_body: &str) -> bool {
    let Some(name) = serde_json::from_str::<wireserve_types::ErrorBody>(error_body)
        .ok()
        .and_then(|b| b.conflicting_service)
    else {
        return false;
    };
    quarantine(state, name, error_body.to_string());
    true
}

/// Drops a declaration and records why, so it stops being resent every
/// cycle but does not silently vanish from `wireserve list` (security
/// review F3).
///
/// Shared by the name-collision path and the admin-denial path so the two
/// cannot drift — in particular so both get the de-duplication that stops
/// a repeatedly-quarantined name accumulating records.
fn quarantine(state: &mut AgentState, name: String, reason: String) {
    state.declared_services.retain(|d| d.name != name);
    state.rejected_services.retain(|r| r.name != name);
    state.pending_services.retain(|n| n != &name);
    state
        .rejected_services
        .push(crate::state::RejectedService { name, reason });
}

/// Folds the approval verdicts from a SUCCESSFUL poll into local state.
///
/// The asymmetry between the two verdicts is the important part:
///
/// * **pending** stays in `declared_services`. The node keeps declaring
///   it so an admin can still approve it, keeps its own firewall hole
///   open (spec §5 — a node only ever firewalls itself, and nothing
///   resolves `<name>.wg` for it yet anyway), and is simply absent from
///   every other node's directory. It is recorded so `wireserve list` can
///   say "waiting on approval" instead of looking identical to "not
///   polled yet".
///
/// * **denied** is quarantined exactly as a name collision is: dropped
///   from `declared_services` so it stops being resent forever, with the
///   admin's reason kept so the operator can see why. Because
///   `service_rules` derives from `declared_services`, that drop is also
///   what closes the local firewall hole.
///
/// Returns whether anything changed, so the caller knows whether to save.
pub fn apply_approval_verdicts(state: &mut AgentState, directory: &PollResponse) -> bool {
    let mut changed = false;

    for denied in &directory.denied_services {
        if state.declared_services.iter().any(|d| d.name == denied.name) {
            let reason = denied
                .reason
                .clone()
                .unwrap_or_else(|| "denied by an administrator".to_string());
            tracing::error!(
                service = %denied.name,
                reason = ?denied.reason,
                "declared service was denied by an admin — withdrawing it locally"
            );
            quarantine(state, denied.name.clone(), reason);
            changed = true;
        }
    }

    let pending: Vec<String> = directory
        .pending_services
        .iter()
        .map(|p| p.name.clone())
        .collect();
    for name in &pending {
        if !state.pending_services.contains(name) {
            tracing::warn!(
                service = %name,
                "declared service is waiting on admin approval — no other node can \
                 resolve <name>.wg for it yet"
            );
        }
    }
    if pending != state.pending_services {
        state.pending_services = pending;
        changed = true;
    }

    changed
}

pub struct PollContext<'a, F: FirewallBackend> {
    pub client: &'a reqwest::Client,
    pub coordinator_url: &'a str,
    pub hosts_path: &'a Path,
    /// This instance's label on its hosts-file block (see
    /// `hosts::sync`); `None` for the default instance.
    pub hosts_label: Option<&'a str>,
    pub state_path: &'a Path,
    pub wg: &'a mut WgInterface,
    pub firewall: &'a mut F,
    /// NAT-traversal step 1/2 (PLAN.md decisions log #85, #90+): per-peer
    /// endpoint-tier state across poll cycles. Lives exactly as long as
    /// `wg` — see `crate::wg::EndpointTracker`.
    pub endpoint_tracker: &'a mut crate::wg::EndpointTracker,
    /// This node's own reflexive address, learned exactly once at daemon
    /// startup by a one-shot probe run before `wg::WgInterface::bring_up`
    /// claimed `listen_port` (see `crate::reflexive`'s module doc for
    /// why it can't be re-probed mid-run). Resent verbatim on every poll
    /// even though the value itself never changes cycle to cycle, so the
    /// coordinator's COALESCE contract stays uniform across every
    /// self-reported field.
    pub own_reflexive_addr: Option<&'a str>,
    /// The reverse proxy this node fronts services with (PLAN.md M25), or
    /// `None` on the overwhelming majority of nodes, which run none.
    pub proxy: Option<&'a mut dyn crate::proxy::ProxyBackend>,
}

/// Publishes this cycle's services to the node's reverse proxy, if it runs
/// one (PLAN.md M25).
///
/// Returns nothing on purpose, and that is the whole point of it being its
/// own function: a proxy failure must never reach `run_once`'s `failures`
/// vec. That function returns before persisting `last_directory` when any
/// step fails, so a proxy that is down or misconfigured would otherwise
/// freeze `wireserve-agent list` on a stale directory — a baffling symptom
/// for an unrelated cause. The proxy is a convenience layer on top of a
/// working mesh and must not degrade the mesh's own bookkeeping. It is
/// retried next cycle regardless, because the backend compares against what
/// is on disk rather than what it last wrote.
fn publish_to_proxy(
    proxy: Option<&mut (dyn crate::proxy::ProxyBackend + '_)>,
    directory: &PollResponse,
) {
    let (Some(proxy), Some(naming)) = (proxy, directory.naming.as_ref()) else {
        return;
    };
    let vhosts = crate::proxy::vhosts(&directory.services, naming);
    if let Err(e) = proxy.sync(&vhosts) {
        tracing::warn!(error = %e, "could not publish services to the reverse proxy");
    }
}

/// Runs exactly one poll cycle against the daemon's single shared `state`,
/// performing all five steps in order. Returns the fresh directory on
/// success.
///
/// F1 (security review, round 2): `state` is the same `Mutex` the IPC
/// server mutates, and the lock is held only for the moments this
/// function reads or writes it — never across the network round trip —
/// so a `serve`/`unserve`/`list` issued while a poll is in flight is
/// neither blocked nor lost. Only the fields this cycle actually
/// produces (`last_directory`, a quarantined declaration) are written
/// back; `declared_services` is never overwritten wholesale.
pub async fn run_once<F: FirewallBackend>(
    ctx: &mut PollContext<'_, F>,
    state: &Mutex<AgentState>,
) -> Result<PollResponse, PollError>
where
    F::Error: std::fmt::Display,
{
    // Snapshot exactly what this cycle sends, then release the lock.
    let (bearer, self_pubkey, declared, endpoint_addr, listen_port, node_ip, node_ip6, transit_capable) = {
        let s = state.lock().await;
        (
            s.bearer_token.clone().ok_or(PollError::NotRegistered)?,
            s.public_key.clone().unwrap_or_default(),
            s.declared_services.clone(),
            s.endpoint_addr.clone(),
            s.listen_port.unwrap_or(51820),
            s.ip4.as_deref().and_then(|ip| ip.parse::<Ipv4Addr>().ok()),
            s.ip6.as_deref().and_then(|ip| ip.parse::<Ipv6Addr>().ok()),
            s.transit_capable,
        )
    };

    // Actively probe both families against the coordinator this cycle —
    // see `probe` module doc. Reused for two jobs below: the self-report
    // in this poll's own request body, and (via `dual.v6.is_some()`) the
    // "do I have real working IPv6 right now" signal for peer
    // reconciliation's endpoint preference.
    let dual = crate::probe::probe_both(ctx.coordinator_url, listen_port, crate::probe::PROBE_TIMEOUT).await;
    let prefer_ipv6 = dual.v6.is_some();

    // NAT-hairpin fix (PLAN.md decisions log #85): this node's own LAN
    // interfaces, read once per cycle and reused for both the self-report
    // below and the peer-side subnet-containment check in step 2.
    // Best-effort — a probe failure here means "advertise nothing and
    // treat every peer as plain-WAN this cycle", never a failed poll.
    let ifname = ctx.wg.ifname().to_string();
    let lan_ifaces = crate::wg::local_lan_ifaces(&ifname).unwrap_or_default();
    let own_lan_subnets = crate::wg::own_lan_subnets(&lan_ifaces);
    let lan_addr = crate::wg::pick_lan_address(&lan_ifaces).map(|ip| ip.to_string());

    // Transit self-report (PLAN.md M23), read once per cycle from purely
    // local state — same netlink read step 2 below already needs for
    // endpoint-tier resolution, hoisted up here and reused rather than
    // read twice, so it can also go out in THIS cycle's own request
    // rather than lagging a cycle behind.
    let handshakes: std::collections::HashMap<String, Option<chrono::DateTime<chrono::Utc>>> =
        crate::wg::tunnel_peers(&ifname)
            .unwrap_or_default()
            .into_iter()
            .map(|t| (t.pubkey, t.last_handshake))
            .collect();
    let now_utc = chrono::Utc::now();
    let transit_reachable: Vec<String> = if transit_capable {
        let mut r: Vec<String> = crate::wg::transit_reachable_peers(&handshakes, now_utc)
            .into_iter()
            .map(String::from)
            .collect();
        r.truncate(wireserve_types::MAX_TRANSIT_REACHABLE_PER_POLL);
        r
    } else {
        Vec::new()
    };
    // Sent regardless of `transit_capable` — any node may need transit
    // help even if it can't offer it.
    let mut transit_wanted: Vec<String> = ctx
        .endpoint_tracker
        .peers_wanting_transit(&handshakes, now_utc)
        .into_iter()
        .map(String::from)
        .collect();
    transit_wanted.sort_unstable();
    transit_wanted.truncate(wireserve_types::MAX_TRANSIT_WANTED_PER_POLL);

    // 1. send
    let req = build_poll_request(
        &declared,
        endpoint_addr,
        &dual,
        lan_addr,
        ctx.own_reflexive_addr.map(String::from),
        TransitSelfReport { capable: transit_capable, reachable: transit_reachable, wanted: transit_wanted },
    );
    let url = format!("{}/poll", ctx.coordinator_url.trim_end_matches('/'));
    let resp = ctx
        .client
        .post(&url)
        .bearer_auth(&bearer)
        .json(&req)
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();

        // F3 (security review): a single colliding service name used to
        // wedge the whole agent forever — this cycle's poll failed before
        // ever reaching peer reconciliation, and since the same
        // declaration was resent every cycle, EVERY future cycle failed
        // the same way, so the agent stopped seeing new peers or
        // revocations too. Quarantine exactly the offending declaration
        // (drop it from what gets sent, record why) so the *next* cycle
        // succeeds normally instead of repeating this forever. This
        // cycle still reports failure — reconciliation resumes on the
        // next poll interval, not this one.
        {
            let mut s = state.lock().await;
            if quarantine_rejected_service(&mut s, &body_text) {
                s.save(ctx.state_path)?;
            }
        }

        return Err(PollError::Rejected {
            status,
            message: body_text,
        });
    }
    let mut directory: PollResponse = resp.json().await?;
    // Before anything acts on an address: peers, firewall, hosts file and
    // the saved directory all see the same, checked, set.
    if let Some(ranges) = pinned_mesh_ranges(state, ctx.state_path, directory.mesh.as_ref()).await? {
        crate::mesh::sanitize(&mut directory, &ranges);
    }
    crate::vip::sanitize(&mut directory);

    // Approval verdicts are folded in BEFORE the firewall rules are
    // computed, and that ordering is the whole point.
    //
    // `declared` is the snapshot taken before the request was sent. A
    // denial arriving in this response drops the name from
    // `declared_services`, and since `service_rules` derives from that
    // list, recomputing it here is what closes the local firewall hole on
    // *this* cycle rather than the next one. Applying the verdict to
    // persisted state alone and leaving `rules` built from the stale
    // snapshot would leave a denied service reachable for another poll
    // interval — twenty seconds by default, which reads as a bug rather
    // than as a design.
    //
    // This is the one place the coordinator's response influences a
    // node's own firewall, amending the rule stated on step 3 below. It
    // is safe in exactly one direction and must stay that way: a verdict
    // can only ever remove a rule, never add one, so a compromised or
    // buggy coordinator can close ports on a node but can never open one.
    let declared = {
        let mut s = state.lock().await;
        if apply_approval_verdicts(&mut s, &directory) {
            s.save(ctx.state_path)?;
        }
        s.declared_services.clone()
    };

    // Steps 2-4 are all synchronous and can block: netlink round trips,
    // DNS resolution of peer endpoints inside `reconcile`, and file I/O.
    // `block_in_place` moves this worker off the async scheduler for the
    // duration so the IPC server (`list`/`serve`/`leave`) stays
    // responsive on the other workers.
    //
    // Steps 2-4 are independent of one another, so each one runs whatever
    // happened to the one before it. Chaining them with `?` meant a step
    // that failed on every cycle silently froze everything after it: a
    // hosts block written once, empty, while peers and routes (step 2,
    // which ran first) kept tracking the directory perfectly.
    let rules = service_rules(&declared, node_ip, node_ip6, &directory);
    // Transit assignments (PLAN.md M23): the coordinator's per-(requester,
    // peer) routing hint, keyed by the transited peer's own pubkey,
    // filtered to exclude this node's own pubkey as a key — defensive,
    // the coordinator should never send this node a `transit_via` about
    // itself.
    let transit: crate::wg::TransitAssignments<'_> = directory
        .peers
        .iter()
        .filter(|p| p.pubkey != self_pubkey)
        .filter_map(|p| p.transit_via.as_deref().map(|via| (p.pubkey.as_str(), via)))
        .collect();
    // This node's own carrier role this cycle (PLAN.md M23) — built from
    // `transit_carrying`, never from `transit` above: `transit` is about
    // how *this* node reaches *its own* peers, which is never itself a
    // signal that this node is carrying for someone else (see
    // `TransitPair`'s doc comment for why a bare `transit_via` can never
    // fire on this node's own response).
    let transit_forwards =
        crate::wg::transit_forwards(&directory.peers, &directory.services, &directory.transit_carrying);
    let failures = tokio::task::block_in_place(|| {
        let mut failures = Vec::new();

        // NAT-traversal steps 1/2 (PLAN.md decisions log #85, #90+):
        // resolve each peer's best endpoint tier before reconciling.
        // Reuses the `handshakes` map already read above (pre-request),
        // rather than reading the kernel's peer table a second time.
        let now = std::time::Instant::now();
        let endpoint_tiers: std::collections::HashMap<String, crate::wg::EndpointTier> = directory
            .peers
            .iter()
            .filter(|p| p.pubkey != self_pubkey)
            .map(|p| {
                let candidates = crate::wg::peer_tier_candidates(&own_lan_subnets, p);
                let tier = ctx.endpoint_tracker.resolve(
                    &p.pubkey,
                    candidates,
                    handshakes.get(&p.pubkey).copied().flatten(),
                    now,
                );
                (p.pubkey.clone(), tier)
            })
            .collect();
        ctx.endpoint_tracker.prune(directory.peers.iter().map(|p| p.pubkey.as_str()));

        // 2. reconcile WireGuard peers
        if let Err(e) = ctx.wg.reconcile(
            &directory.peers,
            &directory.services,
            &self_pubkey,
            prefer_ipv6,
            &endpoint_tiers,
            &transit,
        ) {
            failures.push(PollError::Wg(e));
        }

        // 3. reconcile this node's own firewall rules — from what this
        //    node declared (spec §5), not from the coordinator's
        //    directory and not from whatever `serve` may have queued
        //    since. The one exception is an admin denial, already folded
        //    in above, which can only ever close a hole; see there.
        //    `transit_forwards` (PLAN.md M23) is this node's own role as
        //    a transit carrier this cycle — empty whenever it carries
        //    none, whether or not it opted in.
        if let Err(e) = ctx.firewall.apply(&rules, &transit_forwards) {
            failures.push(PollError::Firewall(e.to_string()));
        }
        // Interface-scoped forwarding (PLAN.md M23) — touched only when
        // this node currently carries at least one active transit pair,
        // so opting in but never being selected leaves the host's
        // forwarding posture completely alone. See `ip_forward` module
        // doc for why this is scoped to `ifname` and never the host's
        // global/`all` forwarding switches.
        crate::firewall::ip_forward::set_enabled(&ifname, !transit_forwards.is_empty());

        // 4. rewrite the hosts-file managed block from the full directory.
        // Step 4b (PLAN.md M25): publish services to this node's reverse
        // proxy, if it runs one.
        //
        // Warn-only, and deliberately NOT a member of `failures`. This
        // function returns before persisting `last_directory` when any step
        // fails, so a proxy that is down or misconfigured would otherwise
        // freeze `wireserve-agent list` on a stale directory — a baffling
        // symptom for an unrelated cause. The proxy is a convenience layer on
        // top of a working mesh; it must not degrade the mesh's own
        // bookkeeping. Retried next cycle regardless, since the backend
        // compares against what is on disk rather than what it last wrote.
        publish_to_proxy(ctx.proxy.as_deref_mut(), &directory);

        let naming = crate::hosts::Naming::new(directory.naming.as_ref(), &directory.services);
        if let Err(e) =
            crate::hosts::sync(ctx.hosts_path, ctx.hosts_label, &directory.services, naming)
        {
            failures.push(PollError::Hosts(e));
        }
        failures
    });
    // `last_directory` stays what was last applied in full, so `list`
    // never shows a directory this node only partly acted on.
    if !failures.is_empty() {
        return Err(PollError::Incomplete(failures));
    }

    // 5. persist merged state.
    {
        let mut s = state.lock().await;
        s.last_directory = Some(directory.clone());
        s.save(ctx.state_path)?;
    }

    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::{MeshInfo, PortMap, Proto, ServiceInfo};

    fn mesh(v4: &str) -> MeshInfo {
        MeshInfo { net_v4_cidr: v4.into(), net_v6_prefix: "fdb4:d481:7c21::/64".into() }
    }

    fn joined_state() -> AgentState {
        AgentState {
            ip4: Some("10.9.0.7".into()),
            ip6: Some("fdb4:d481:7c21::7".into()),
            ..AgentState::default()
        }
    }

    #[tokio::test]
    async fn the_first_verifiable_offer_is_pinned_and_saved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let state = Mutex::new(joined_state());

        let r = pinned_mesh_ranges(&state, &path, Some(&mesh("10.9.0.0/24"))).await.unwrap();
        assert!(r.is_some_and(|r| r.contains4("10.9.0.1".parse().unwrap())));
        assert_eq!(state.lock().await.mesh, Some(mesh("10.9.0.0/24")));
        assert_eq!(AgentState::load(&path).unwrap().mesh, Some(mesh("10.9.0.0/24")), "persisted");
    }

    #[tokio::test]
    async fn a_later_different_offer_never_replaces_the_pin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let state = Mutex::new(AgentState { mesh: Some(mesh("10.9.0.0/24")), ..joined_state() });

        // Wider, and still containing this node: exactly what an attacker
        // rewriting the response would send to widen what it may route.
        let r = pinned_mesh_ranges(&state, &path, Some(&mesh("0.0.0.0/0"))).await.unwrap().unwrap();
        assert!(!r.contains4("192.168.1.1".parse().unwrap()));
        assert_eq!(state.lock().await.mesh, Some(mesh("10.9.0.0/24")));
    }

    #[tokio::test]
    async fn an_offer_not_containing_this_node_is_not_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let state = Mutex::new(joined_state());

        assert!(pinned_mesh_ranges(&state, &path, Some(&mesh("10.8.0.0/24"))).await.unwrap().is_none());
        assert!(pinned_mesh_ranges(&state, &path, None).await.unwrap().is_none(), "an old coordinator: nothing to check against");
        assert!(state.lock().await.mesh.is_none());
    }

    #[test]
    fn build_poll_request_carries_declared_services_verbatim() {
        let declared = vec![ServiceDecl { name: "plex".into(), port: 32400, proto: Proto::Tcp, ports: vec![] }];
        let dual = crate::probe::DualProbeResult {
            v4: Some("203.0.113.5:51820".into()),
            v6: None,
        };
        let req = build_poll_request(
            &declared,
            Some("host:51820".into()),
            &dual,
            Some("192.168.1.5".into()),
            Some("203.0.113.5:55123".into()),
            TransitSelfReport {
                capable: true,
                reachable: vec!["reachable-pk".into()],
                wanted: vec!["wanted-pk".into()],
            },
        );
        assert_eq!(req.services.len(), 1);
        assert_eq!(req.endpoint_addr.as_deref(), Some("host:51820"));
        assert_eq!(req.endpoint_addr_v4.as_deref(), Some("203.0.113.5:51820"));
        assert!(req.endpoint_addr_v6.is_none());
        assert_eq!(req.lan_addr.as_deref(), Some("192.168.1.5"));
        assert_eq!(req.reflexive_addr.as_deref(), Some("203.0.113.5:55123"));
        assert!(req.transit_capable);
        assert_eq!(req.transit_reachable, vec!["reachable-pk".to_string()]);
        assert_eq!(req.transit_wanted, vec!["wanted-pk".to_string()]);
    }

    const NODE: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
    const VIP: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 50);

    fn pm(s: &str) -> PortMap {
        s.parse().unwrap()
    }

    fn published(name: &str, owner: Ipv4Addr, vip4: Option<Ipv4Addr>) -> ServiceInfo {
        ServiceInfo {
            name: name.into(),
            node: "n".into(),
            ip4: owner.to_string(),
            port: 1,
            proto: Proto::Tcp,
            online: true,
            vip4: vip4.map(|v| v.to_string()),
            ports: vec![],
        }
    }

    fn with_services(services: Vec<ServiceInfo>) -> PollResponse {
        PollResponse {
            naming: None, services, ..directory_with(&[], &[]) }
    }

    /// Whether any rule makes `port` reachable in some form — opened
    /// directly or as a mapping's target.
    fn reaches(rules: &[ServiceRule], port: u16) -> bool {
        rules.iter().any(|r| match r {
            ServiceRule::Open { port: p, .. } => *p == port,
            ServiceRule::Mapped { map, .. } => map.target == port,
        })
    }

    #[test]
    fn a_service_with_an_address_gets_one_mapped_rule_per_port() {
        let declared = vec![ServiceDecl::new("dns", vec![pm("53/udp"), pm("53/tcp"), pm("8080:8000")])];
        let rules = service_rules(&declared, Some(NODE), None, &with_services(vec![published("dns", NODE, Some(VIP))]));
        assert_eq!(
            rules,
            vec![
                ServiceRule::Mapped { vip: VIP, node: NODE, map: pm("53/udp") },
                ServiceRule::Mapped { vip: VIP, node: NODE, map: pm("53/tcp") },
                ServiceRule::Mapped { vip: VIP, node: NODE, map: pm("8080:8000") },
            ]
        );
    }

    #[test]
    fn a_service_without_an_address_is_opened_on_its_target_ports() {
        // A coordinator from before service addresses: every service
        // works exactly as it used to, on the node's own address.
        let declared = vec![
            ServiceDecl { name: "plex".into(), port: 32400, proto: Proto::Tcp, ports: vec![] },
            ServiceDecl::new("web", vec![pm("80:5080")]),
        ];
        let rules = service_rules(&declared, Some(NODE), None, &with_services(vec![published("plex", NODE, None)]));
        assert_eq!(
            rules,
            vec![
                ServiceRule::Open { proto: Proto::Tcp, port: 32400, node: NODE, node6: None },
                ServiceRule::Open { proto: Proto::Tcp, port: 5080, node: NODE, node6: None },
            ]
        );
    }

    #[test]
    fn a_directly_opened_service_is_scoped_to_both_of_the_nodes_own_addresses() {
        let declared = vec![ServiceDecl::new("web", vec![pm("80:5080")])];
        let node6: Ipv6Addr = "fd00:90::2".parse().unwrap();
        assert_eq!(
            service_rules(&declared, Some(NODE), Some(node6), &with_services(vec![])),
            vec![ServiceRule::Open { proto: Proto::Tcp, port: 5080, node: NODE, node6: Some(node6) }]
        );
    }

    #[test]
    fn without_a_mesh_address_nothing_is_opened() {
        // Nothing to scope the hole to — an unscoped one is exactly the
        // relay `ServiceRule::Open`'s addresses exist to prevent.
        let declared = vec![ServiceDecl::new("web", vec![pm("80:5080")])];
        assert!(service_rules(&declared, None, None, &with_services(vec![])).is_empty());
    }

    #[test]
    fn a_pending_service_gets_its_rules_from_the_pending_address() {
        let declared = vec![ServiceDecl::new("web", vec![pm("80:5080")])];
        let mut dir = directory_with(&["web"], &[]);
        dir.pending_services[0].vip4 = Some(VIP.to_string());
        assert_eq!(
            service_rules(&declared, Some(NODE), None, &dir),
            vec![ServiceRule::Mapped { vip: VIP, node: NODE, map: pm("80:5080") }]
        );
    }

    #[test]
    fn the_directory_can_pick_an_address_but_never_a_port() {
        // The coordinator's entry claims other ports; only what this node
        // declared is ever in a rule.
        let declared = vec![ServiceDecl::new("web", vec![pm("80:5080")])];
        let mut entry = published("web", NODE, Some(VIP));
        entry.ports = vec![pm("22:22"), pm("80:22")];
        let rules = service_rules(&declared, Some(NODE), None, &with_services(vec![entry]));
        assert_eq!(rules, vec![ServiceRule::Mapped { vip: VIP, node: NODE, map: pm("80:5080") }]);
    }

    #[test]
    fn another_nodes_entry_of_the_same_name_is_not_ours() {
        let declared = vec![ServiceDecl::new("web", vec![pm("80:5080")])];
        let other = Ipv4Addr::new(10, 9, 0, 2);
        let rules = service_rules(&declared, Some(NODE), None, &with_services(vec![published("web", other, Some(VIP))]));
        assert_eq!(rules, vec![ServiceRule::Open { proto: Proto::Tcp, port: 5080, node: NODE, node6: None }]);
    }

    #[test]
    fn an_aliased_target_port_is_mapped_once() {
        // Two names on one port, as an old state file can hold.
        let declared = vec![
            ServiceDecl { name: "plex".into(), port: 32400, proto: Proto::Tcp, ports: vec![] },
            ServiceDecl { name: "media".into(), port: 32400, proto: Proto::Tcp, ports: vec![] },
        ];
        let other = Ipv4Addr::new(10, 9, 0, 51);
        let dir = with_services(vec![published("plex", NODE, Some(VIP)), published("media", NODE, Some(other))]);
        assert_eq!(
            service_rules(&declared, Some(NODE), None, &dir),
            vec![ServiceRule::Mapped { vip: VIP, node: NODE, map: PortMap::identity(32400, Proto::Tcp) }]
        );
    }

    #[test]
    fn nothing_undeclared_is_ever_in_a_rule() {
        let rules = service_rules(&[], Some(NODE), None, &with_services(vec![published("web", NODE, Some(VIP))]));
        assert!(rules.is_empty());
    }

    // ---- service approval verdicts ----

    fn directory_with(
        pending: &[&str],
        denied: &[(&str, Option<&str>)],
    ) -> PollResponse {
        PollResponse {
            naming: None,
            peers: vec![],
            services: vec![],
            pending_services: pending
                .iter()
                .map(|n| wireserve_types::PendingService {
                    name: (*n).to_string(),
                    port: 1,
                    proto: Proto::Tcp,
                    vip4: None,
                    declared_at: None,
                })
                .collect(),
            denied_services: denied
                .iter()
                .map(|(n, r)| wireserve_types::DeniedService {
                    name: (*n).to_string(),
                    reason: r.map(str::to_string),
                    denied_at: None,
                })
                .collect(),
            transit_carrying: vec![],
            transit_awaiting_approval: false,
            mesh: None,
        }
    }

    #[test]
    fn a_denied_service_is_quarantined_from_a_successful_poll() {
        let mut state = state_with_declared(&["plex", "git"]);
        let changed = apply_approval_verdicts(
            &mut state,
            &directory_with(&[], &[("plex", Some("reserved for the build box"))]),
        );

        assert!(changed);
        assert_eq!(state.declared_services.len(), 1);
        assert_eq!(state.declared_services[0].name, "git");
        assert_eq!(state.rejected_services.len(), 1);
        assert_eq!(state.rejected_services[0].name, "plex");
        assert!(state.rejected_services[0].reason.contains("reserved for the build box"));
    }

    #[test]
    fn a_denied_service_loses_its_firewall_hole_because_it_leaves_declared_services() {
        // The mechanism behind same-cycle closure: firewall rules derive
        // from `declared_services`, so quarantining the name is what shuts
        // the port. `run_once` recomputes `rules` after this call for
        // exactly that reason.
        let mut state = state_with_declared(&["plex", "git"]);
        state.declared_services[0].port = 32400;
        assert!(reaches(&service_rules(&state.declared_services, Some(NODE), None, &directory_with(&[], &[])), 32400));

        apply_approval_verdicts(&mut state, &directory_with(&[], &[("plex", None)]));

        assert!(
            !reaches(&service_rules(&state.declared_services, Some(NODE), None, &directory_with(&[], &[])), 32400),
            "a denied service's port must not survive in the rule set"
        );
    }

    #[test]
    fn a_pending_service_is_recorded_but_never_quarantined() {
        // Pending keeps being declared (so an admin can still approve it)
        // and keeps its own firewall hole — the node is only firewalling
        // itself, and nothing resolves <name>.wg for it yet anyway.
        let mut state = state_with_declared(&["plex"]);
        state.declared_services[0].port = 32400;

        let changed = apply_approval_verdicts(&mut state, &directory_with(&["plex"], &[]));

        assert!(changed);
        assert_eq!(state.declared_services.len(), 1, "still declared");
        assert!(state.rejected_services.is_empty(), "pending is not a rejection");
        assert_eq!(state.pending_services, vec!["plex".to_string()]);
        assert!(reaches(&service_rules(&state.declared_services, Some(NODE), None, &directory_with(&[], &[])), 32400));
    }

    #[test]
    fn pending_services_are_replaced_not_merged() {
        // An approval is observed as a name *disappearing* from the
        // coordinator's pending list, so merging would mean a service
        // stayed flagged "waiting" forever after it was approved.
        let mut state = state_with_declared(&["plex", "git"]);
        apply_approval_verdicts(&mut state, &directory_with(&["plex", "git"], &[]));
        assert_eq!(state.pending_services.len(), 2);

        apply_approval_verdicts(&mut state, &directory_with(&["git"], &[]));
        assert_eq!(state.pending_services, vec!["git".to_string()]);
    }

    #[test]
    fn a_response_without_the_approval_fields_changes_nothing() {
        // What an older coordinator, or one with approval disabled,
        // returns. Must be a no-op, not an implicit "everything denied".
        let mut state = state_with_declared(&["plex"]);
        let changed = apply_approval_verdicts(&mut state, &directory_with(&[], &[]));

        assert!(!changed);
        assert_eq!(state.declared_services.len(), 1);
        assert!(state.rejected_services.is_empty());
        assert!(state.pending_services.is_empty());
    }

    #[test]
    fn denying_a_name_this_node_no_longer_declares_is_a_no_op() {
        let mut state = state_with_declared(&["git"]);
        let changed = apply_approval_verdicts(&mut state, &directory_with(&[], &[("plex", None)]));
        assert!(!changed);
        assert!(state.rejected_services.is_empty());
    }

    // ---- F3: quarantine_rejected_service ----

    fn state_with_declared(names: &[&str]) -> AgentState {
        AgentState {
            declared_services: names
                .iter()
                .map(|n| ServiceDecl { name: (*n).to_string(), port: 1, proto: Proto::Tcp, ports: vec![] })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn quarantine_removes_the_named_service_and_records_why() {
        let mut state = state_with_declared(&["plex", "homeassistant"]);
        let body = serde_json::to_string(&wireserve_types::ErrorBody::service_collision(
            "service name 'plex' is already in use",
            "plex",
        ))
        .unwrap();

        let quarantined = quarantine_rejected_service(&mut state, &body);

        assert!(quarantined);
        assert_eq!(state.declared_services.len(), 1);
        assert_eq!(state.declared_services[0].name, "homeassistant");
        assert_eq!(state.rejected_services.len(), 1);
        assert_eq!(state.rejected_services[0].name, "plex");
    }

    #[test]
    fn quarantine_is_a_no_op_for_a_body_without_conflicting_service() {
        let mut state = state_with_declared(&["plex"]);
        let quarantined = quarantine_rejected_service(&mut state, r#"{"error":"invalid join token"}"#);

        assert!(!quarantined);
        assert_eq!(state.declared_services.len(), 1);
        assert!(state.rejected_services.is_empty());
    }

    #[test]
    fn quarantine_is_a_no_op_for_unparseable_body() {
        let mut state = state_with_declared(&["plex"]);
        let quarantined = quarantine_rejected_service(&mut state, "not json at all");

        assert!(!quarantined);
        assert_eq!(state.declared_services.len(), 1);
    }

    #[test]
    fn requarantining_the_same_name_does_not_duplicate_the_record() {
        let mut state = state_with_declared(&["plex"]);
        let body = serde_json::to_string(&wireserve_types::ErrorBody::service_collision(
            "service name 'plex' is already in use",
            "plex",
        ))
        .unwrap();

        quarantine_rejected_service(&mut state, &body);
        quarantine_rejected_service(&mut state, &body);

        assert_eq!(state.rejected_services.len(), 1);
    }

    // ---- F9: PollError::is_unauthorized ----

    #[test]
    fn is_unauthorized_true_only_for_401() {
        let unauthorized = PollError::Rejected {
            status: reqwest::StatusCode::UNAUTHORIZED,
            message: "unauthorized".into(),
        };
        assert!(unauthorized.is_unauthorized());

        let conflict = PollError::Rejected {
            status: reqwest::StatusCode::CONFLICT,
            message: "conflict".into(),
        };
        assert!(!conflict.is_unauthorized());

        assert!(!PollError::NotRegistered.is_unauthorized());
    }

    // ---- a lost /etc/hosts mount, and steps failing independently ----

    fn io(errno: i32) -> PollError {
        PollError::Hosts(std::io::Error::from_raw_os_error(errno))
    }

    #[test]
    fn hosts_read_only_only_for_a_hosts_step_erofs() {
        assert!(io(libc::EROFS).hosts_read_only());
        assert!(PollError::Incomplete(vec![PollError::Firewall("x".into()), io(libc::EROFS)]).hosts_read_only());

        assert!(!io(libc::EACCES).hosts_read_only());
        assert!(!PollError::Incomplete(vec![PollError::Firewall("x".into())]).hosts_read_only());
        assert!(!PollError::NotRegistered.hosts_read_only());
    }

    #[test]
    fn hosts_synced_when_only_another_step_failed() {
        assert!(PollError::Incomplete(vec![PollError::Firewall("x".into())]).hosts_synced());
        assert!(!PollError::Incomplete(vec![PollError::Firewall("x".into()), io(libc::EROFS)]).hosts_synced());
        // Failures before the local steps never reached the hosts file.
        assert!(!PollError::NotRegistered.hosts_synced());
    }

    #[test]
    fn an_incomplete_cycle_names_every_failed_step() {
        let msg = PollError::Incomplete(vec![PollError::Firewall("nft said no".into()), io(libc::EROFS)]).to_string();
        assert!(msg.contains("firewall reconciliation failed: nft said no"), "{msg}");
        assert!(msg.contains("hosts-file sync failed"), "{msg}");
    }
}

#[cfg(test)]
mod proxy_step_tests {
    use super::*;
    use crate::proxy::fake::FakeProxyBackend;
    use wireserve_types::{PortMap, Proto, ServiceInfo, ServiceNaming};

    fn directory(naming: Option<ServiceNaming>) -> PollResponse {
        PollResponse {
            naming,
            peers: vec![],
            services: vec![ServiceInfo {
                name: "plex".into(),
                node: "n".into(),
                ip4: "10.9.0.3".into(),
                port: 443,
                proto: Proto::Tcp,
                online: true,
                vip4: Some("10.9.0.50".into()),
                ports: vec![PortMap { public: 443, target: 32400, proto: Proto::Tcp }],
            }],
            pending_services: vec![],
            denied_services: vec![],
            transit_carrying: vec![],
            transit_awaiting_approval: false,
            mesh: None,
        }
    }

    fn naming() -> ServiceNaming {
        ServiceNaming { domain: "int.example.com".into(), proxy_service: None }
    }

    #[test]
    fn a_failing_proxy_never_fails_the_cycle() {
        // The property that keeps a down Caddy from freezing the directory
        // cache: this returns `()`, so there is nothing for `run_once` to
        // fold into `failures`.
        let mut backend = FakeProxyBackend { fail: true, ..Default::default() };
        publish_to_proxy(Some(&mut backend), &directory(Some(naming())));
        assert_eq!(backend.calls.lock().unwrap().len(), 1, "it must still have tried");
    }

    #[test]
    fn services_reach_the_backend_as_vhosts() {
        let mut backend = FakeProxyBackend::default();
        publish_to_proxy(Some(&mut backend), &directory(Some(naming())));
        let calls = backend.calls.lock().unwrap();
        assert_eq!(calls[0].len(), 1);
        assert_eq!(calls[0][0].host, "plex.int.example.com");
    }

    #[test]
    fn a_coordinator_with_no_domain_configured_publishes_nothing() {
        let mut backend = FakeProxyBackend::default();
        publish_to_proxy(Some(&mut backend), &directory(None));
        assert!(
            backend.calls.lock().unwrap().is_empty(),
            "without a domain there are no names to publish, so the proxy is left alone"
        );
    }
}
