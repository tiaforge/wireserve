//! The five-step reconciliation loop (spec §4.3): send `/poll`, reconcile
//! WireGuard peers, reconcile this node's own firewall rules, rewrite the
//! hosts-file managed block, persist merged state. A failed cycle is
//! logged and skipped rather than crashing the daemon or tearing down an
//! already-correctly-configured interface (a transient coordinator/network
//! blip shouldn't make things *more* broken than they already were).

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
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
    #[error("agent is not registered yet — run `wireserve join` first")]
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
    /// `exit on` (PLAN.md M27) — reported alongside, since it is the same
    /// kind of live, local opt-in.
    pub exit_capable: bool,
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
    tls: TlsSelfReport,
) -> PollRequest {
    PollRequest {
        endpoint_addr,
        endpoint_addr_v4: dual.v4.clone(),
        endpoint_addr_v6: dual.v6.clone(),
        lan_addr,
        reflexive_addr,
        transit_capable: transit.capable,
        exit_capable: transit.exit_capable,
        transit_reachable: transit.reachable,
        transit_wanted: transit.wanted,
        services: declared.to_vec(),
        capabilities: {
            if tls.capable {
                vec![wireserve_types::CAP_TLS_TERMINATE.to_string(), wireserve_types::CAP_SIGN_IN.to_string()]
            } else {
                Vec::new()
            }
        },
        tls_ready: {
            let mut ready = tls.ready;
            ready.truncate(wireserve_types::MAX_TLS_READY_PER_POLL);
            ready
        },
    }
}

/// This node's TLS terminator, as reported to the coordinator (PLAN.md
/// M33): whether one is running, and which services it serves — latched,
/// see `tls_link`.
#[derive(Debug, Clone, Default)]
pub struct TlsSelfReport {
    pub capable: bool,
    pub ready: Vec<String>,
}

/// This node's own services the directory says are terminated here AND the
/// terminator says it serves right now (PLAN.md M33). Both, because each
/// alone would leave a service address answered by nothing: the directory
/// flag lags a terminator that just stopped, and the terminator can serve a
/// name the rest of the mesh does not resolve to this address yet.
#[must_use]
pub fn terminating_here(node: Option<Ipv4Addr>, directory: &PollResponse, serving: &BTreeSet<String>) -> BTreeSet<String> {
    let Some(node) = node.map(|n| n.to_string()) else {
        return BTreeSet::new();
    };
    directory
        .services
        .iter()
        .filter(|s| s.terminated && s.ip4 == node && serving.contains(&s.name))
        .map(|s| s.name.clone())
        .collect()
}

/// The mesh ranges to check this cycle's directory against (see
/// `crate::mesh`): the ones pinned at join. A different offer never
/// replaces them — wider ranges are exactly what a rewritten response would
/// send to widen what it may route — and is reported once.
async fn pinned_mesh_ranges(
    state: &Mutex<AgentState>,
    offered: Option<&wireserve_types::MeshInfo>,
) -> Option<wireserve_types::MeshRanges> {
    static DIFFERENT_OFFER_REPORTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let s = state.lock().await;
    if let (Some(pinned), Some(offered)) = (&s.mesh, offered) {
        if pinned != offered && !DIFFERENT_OFFER_REPORTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                pinned_v4 = %pinned.net_v4_cidr,
                pinned_v6 = %pinned.net_v6_prefix,
                offered_v4 = %offered.net_v4_cidr.escape_debug(),
                offered_v6 = %offered.net_v6_prefix.escape_debug(),
                "the coordinator now reports different mesh ranges than this node pinned; keeping \
                 the pinned ones (join again to adopt the new ranges)"
            );
        }
    }
    s.mesh.as_ref().and_then(wireserve_types::MeshRanges::parse)
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
/// `declared`. A service with no address — the range was exhausted, or
/// [`crate::vip::sanitize`] refused it — is opened nowhere: there is
/// nothing to scope a hole to but the node's own address, and a port open
/// there to the whole mesh is what service addresses exist to avoid.
///
/// A target can carry only one mapping (see
/// `wireserve_types::validate_node_targets`); `serve` refuses a second,
/// and a hand-edited state file that aliases one anyway keeps it for the
/// first name only — a second mapping's replies would come back from the
/// wrong address.
///
/// A mapping onto another address (PLAN.md M26) whose address lies in the
/// mesh ranges (`mesh`) gets no rule,
/// which `serve` refuses but a hand-edited state file could still hold:
/// forwarding into the mesh is transit's business, with its own opt-in.
///
/// A service in `terminating` (PLAN.md M33) has its TCP 443 mapping answered
/// by this node's TLS terminator, listening on `tls_port` (PLAN.md M35):
/// that mapping becomes [`ServiceRule::Terminated`], which rewrites the
/// request to that port on the service address and opens nothing of its
/// target. Its other mappings stay
/// rewrites. The target is still reserved against every other mapping.
///
/// A service marked for sign-in (PLAN.md M29, M34) is reached through its
/// terminator's sign-in and nothing else: only its terminated 443 mapping
/// is opened — every other mapping would be a door around the sign-in — and
/// while its terminator does not serve it, nothing at all. The mark only
/// ever narrows what this node's own declaration opens, so taking it from
/// the coordinator keeps the rule stated in `run_once` step 3.
pub fn service_rules(
    declared: &[ServiceDecl],
    node_ip: Option<Ipv4Addr>,
    directory: &PollResponse,
    mesh: Option<&wireserve_types::MeshRanges>,
    terminating: &BTreeSet<String>,
    tls_port: u16,
) -> Vec<ServiceRule> {
    let mut rules = Vec::new();
    let mut targets: Vec<wireserve_types::PortMap> = Vec::new();
    let Some(node) = node_ip else {
        return rules;
    };
    for d in declared {
        let Some(vip) = own_vip(&d.name, node, directory) else {
            tracing::warn!(service = %d.name, "service has no address of its own yet; not opening it");
            continue;
        };
        let marked = marked_for_auth(&d.name, node, directory);
        if marked && !terminating.contains(&d.name) {
            tracing::warn!(
                service = %d.name,
                "service is marked for sign-in but this node's terminator does not serve it yet; \
                 not opening it at all rather than opening it to everyone"
            );
            continue;
        }
        for map in d.ports.clone() {
            if map.addr.is_some_and(|addr| addr == node || mesh.is_some_and(|m| m.contains4(addr))) {
                tracing::warn!(service = %d.name, port = %map, "not forwarding to a target address inside the mesh");
                continue;
            }
            if targets.iter().any(|t| wireserve_types::same_target(t, &map)) {
                tracing::warn!(
                    service = %d.name,
                    port = %map,
                    "target already mapped by another service — not mapping it again"
                );
                continue;
            }
            targets.push(map);
            let tls = map.public == wireserve_types::TLS_PUBLIC_PORT && map.proto == wireserve_types::Proto::Tcp;
            let rule = if tls && terminating.contains(&d.name) {
                ServiceRule::Terminated { vip, map, port: tls_port }
            } else if marked {
                // Every other door of a marked service stays shut.
                continue;
            } else {
                ServiceRule::Mapped { vip, node, map }
            };
            rules.push(rule);
        }
    }
    rules
}

/// The interfaces replies from this cycle's target addresses (PLAN.md M26)
/// arrive on, as the kernel routes to them now. A target the host delivers
/// locally needs none; one routed into the mesh interface is refused
/// earlier (`service_rules`) and never needs forwarding turned on here.
#[cfg(target_os = "linux")]
fn egress_interfaces(rules: &[ServiceRule], mesh_ifname: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let targets: BTreeSet<Ipv4Addr> = rules.iter().filter_map(ServiceRule::remote_target).collect();
    for addr in targets {
        match crate::routes::egress_ifname(addr) {
            Ok(Some(name)) if name == mesh_ifname => {
                tracing::warn!(%addr, "a service's target address is routed into the mesh; not forwarding to it");
            }
            Ok(Some(name)) => {
                out.insert(name);
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(%addr, error = %e, "no route to a service's target address"),
        }
    }
    out
}

#[cfg(not(target_os = "linux"))]
fn egress_interfaces(_rules: &[ServiceRule], _mesh_ifname: &str) -> BTreeSet<String> {
    BTreeSet::new()
}

/// The interface this host reaches the internet through, for an exit
/// (PLAN.md M27): where the replies to its clients' traffic arrive. A route
/// lookup only — nothing is sent to the address. A real global one rather
/// than a documentation range, which a host may route to a blackhole.
#[cfg(target_os = "linux")]
fn internet_egress(mesh_ifname: &str) -> Option<String> {
    const ANY_GLOBAL: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    match crate::routes::egress_ifname(ANY_GLOBAL) {
        Ok(Some(name)) if name != mesh_ifname => Some(name),
        Ok(_) => {
            tracing::warn!("this node's default route leads into the mesh; not acting as an exit");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "this node has no route to the internet; not acting as an exit");
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn internet_egress(_mesh_ifname: &str) -> Option<String> {
    None
}

/// The mesh IPv4 addresses of the devices this node is the exit for, from
/// the pubkeys the coordinator named and the directory's own entries for
/// them. A pubkey not in the directory is skipped: its address is exactly
/// what the forwarding rule matches, so there is nothing to guess.
fn exit_client_addrs(directory: &PollResponse) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = directory
        .exit_clients
        .iter()
        .filter_map(|pk| directory.peers.iter().find(|p| &p.pubkey == pk))
        .filter_map(|p| p.ip4.parse().ok())
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Whether this node's own service `name` is marked for sign-in (PLAN.md
/// M29), per the directory's entry for it.
fn marked_for_auth(name: &str, node: Ipv4Addr, directory: &PollResponse) -> bool {
    let node = node.to_string();
    directory.services.iter().any(|s| s.name == name && s.ip4 == node && s.auth)
}

pub(crate) fn own_vip(name: &str, node: Ipv4Addr, directory: &PollResponse) -> Option<Ipv4Addr> {
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
    /// This node's TLS terminator's check-ins (PLAN.md M33); `None` where
    /// the daemon runs without one (tests, non-Linux).
    pub tls: Option<&'a crate::tls_link::TlsLink>,
}

/// Moves the terminator's local routes from `old` to `new` (see
/// `routes::sync_local`), returning what is routed afterwards. A failure is
/// logged there and never fails the cycle: the route it concerns simply
/// stays as it was, and the firewall still marks only what the directory
/// and the terminator agree on.
#[cfg(target_os = "linux")]
fn sync_local_routes(old: &BTreeSet<Ipv4Addr>, new: &BTreeSet<Ipv4Addr>, node: Option<Ipv4Addr>) -> BTreeSet<Ipv4Addr> {
    if old == new {
        return old.clone();
    }
    let Some(node) = node else {
        return old.clone();
    };
    crate::routes::sync_local(old, new, node).0
}

#[cfg(not(target_os = "linux"))]
fn sync_local_routes(old: &BTreeSet<Ipv4Addr>, _new: &BTreeSet<Ipv4Addr>, _node: Option<Ipv4Addr>) -> BTreeSet<Ipv4Addr> {
    old.clone()
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
    let (bearer, self_pubkey, declared, endpoint_addr, listen_port, node_ip, transit_capable, exit_capable) = {
        let s = state.lock().await;
        (
            s.bearer_token.clone().ok_or(PollError::NotRegistered)?,
            s.public_key.clone().unwrap_or_default(),
            s.declared_services.clone(),
            s.endpoint_addr.clone(),
            s.listen_port.unwrap_or(51820),
            s.ip4.as_deref().and_then(|ip| ip.parse::<Ipv4Addr>().ok()),
            s.transit_capable,
            s.exit_capable,
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
        .peers_wanting_transit(&handshakes, now_utc, std::time::Instant::now())
        .into_iter()
        .map(String::from)
        .collect();
    transit_wanted.sort_unstable();
    transit_wanted.truncate(wireserve_types::MAX_TRANSIT_WANTED_PER_POLL);

    let tls_now = std::time::Instant::now();
    let tls_report = ctx.tls.map_or_else(TlsSelfReport::default, |link| TlsSelfReport {
        capable: link.present(tls_now),
        ready: link.reported(tls_now),
    });

    // 1. send
    let req = build_poll_request(
        &declared,
        endpoint_addr,
        &dual,
        lan_addr,
        ctx.own_reflexive_addr.map(String::from),
        TransitSelfReport {
            capable: transit_capable,
            exit_capable,
            reachable: transit_reachable,
            wanted: transit_wanted,
        },
        tls_report,
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
    let mesh_ranges = pinned_mesh_ranges(state, directory.mesh.as_ref()).await;
    if let Some(ranges) = &mesh_ranges {
        crate::mesh::sanitize(&mut directory, ranges);
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
    let (declared, owned_egress, local_routes_before) = {
        let mut s = state.lock().await;
        if apply_approval_verdicts(&mut s, &directory) {
            s.save(ctx.state_path)?;
        }
        (
            s.declared_services.clone(),
            s.forwarding_owned.iter().cloned().collect::<BTreeSet<String>>(),
            s.local_routes.iter().copied().collect::<BTreeSet<Ipv4Addr>>(),
        )
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
    // Both from the same check-in: a port only while it is recent, and what
    // it served then. Without one nothing is terminated, so the 0 is never
    // written into a rule.
    let (serving, tls_port) = ctx
        .tls
        .and_then(|link| link.port(tls_now).map(|port| (link.serving(tls_now), port)))
        .unwrap_or_default();
    let terminating = terminating_here(node_ip, &directory, &serving);
    let rules = service_rules(&declared, node_ip, &directory, mesh_ranges.as_ref(), &terminating, tls_port);
    // The addresses the terminator must receive on (PLAN.md M33): routed to
    // the host itself, so they arrive at its sockets rather than looping
    // back into the mesh interface.
    let local_routes_wanted: BTreeSet<Ipv4Addr> = rules
        .iter()
        .filter_map(|r| match r {
            ServiceRule::Terminated { vip, .. } => Some(*vip),
            _ => None,
        })
        .collect();
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
    ctx.endpoint_tracker.note_transit(&transit);
    // This node's own carrier role this cycle (PLAN.md M23) — built from
    // `transit_carrying`, never from `transit` above: `transit` is about
    // how *this* node reaches *its own* peers, which is never itself a
    // signal that this node is carrying for someone else (see
    // `TransitPair`'s doc comment for why a bare `transit_via` can never
    // fire on this node's own response).
    let transit_forwards =
        crate::wg::transit_forwards(&directory.peers, &directory.services, &directory.transit_carrying);
    // The devices this node is the exit for (PLAN.md M27). Only while this
    // node itself opted in — the coordinator's list is the device side of
    // the consent, never the whole of it — and only with a pinned mesh
    // range, without which the mesh itself would look like the internet.
    let exit = if exit_capable && mesh_ranges.is_some() {
        exit_client_addrs(&directory)
    } else {
        Vec::new()
    };
    let (failures, owned_egress_now, local_routes_now) = tokio::task::block_in_place(|| {
        let mut failures = Vec::new();

        // NAT-traversal steps 1/2 (PLAN.md decisions log #85, #90+):
        // resolve each peer's best endpoint tier before reconciling.
        // Reuses the `handshakes` map already read above (pre-request),
        // rather than reading the kernel's peer table a second time.
        //
        // This node's own public addresses — from its own directory entry
        // plus its startup reflexive probe — tell a peer on this LAN apart
        // from one on another LAN that reuses the same private range.
        let own_public = directory
            .peers
            .iter()
            .find(|p| p.pubkey == self_pubkey)
            .map(|p| crate::wg::public_v4s(p, ctx.own_reflexive_addr))
            .unwrap_or_default();
        let now = std::time::Instant::now();
        let endpoint_tiers: std::collections::HashMap<String, crate::wg::EndpointTier> = directory
            .peers
            .iter()
            .filter(|p| p.pubkey != self_pubkey)
            .map(|p| {
                let candidates = crate::wg::peer_tier_candidates(&own_lan_subnets, &own_public, p);
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
        //
        //    Egress forwarding for services mapped onto other addresses
        //    (PLAN.md M26) goes around the same transaction: a switch this
        //    agent owns is turned off before the ruleset that guards it is
        //    replaced (inside `begin_egress`), and a new one turned on only
        //    once the ruleset guarding it is in place — never forwarding
        //    unguarded in between.
        //
        //    An exit (PLAN.md M27) is one more egress: replies from the
        //    internet arrive on the default route's interface, which goes
        //    through the same owned, guarded switch.
        let mut egress = egress_interfaces(&rules, &ifname);
        if !exit.is_empty() {
            egress.extend(internet_egress(&ifname));
        }
        let plan = crate::firewall::ip_forward::begin_egress(&egress, &owned_egress);
        let forwarding = wireserve_types::Forwarding {
            transit: transit_forwards.clone(),
            guarded: plan.guard.iter().cloned().collect(),
            exit: exit.clone(),
            mesh_v4: mesh_ranges.as_ref().map(wireserve_types::MeshRanges::v4),
        };
        // New local routes go in before the ruleset that sends traffic to
        // them, stale ones come out after the ruleset that stopped: a
        // service address is never marked for a terminator it cannot reach,
        // nor routed to the host while the rewrite still expects it not to be.
        let local_routes = sync_local_routes(
            &local_routes_before,
            &local_routes_before.union(&local_routes_wanted).copied().collect(),
            node_ip,
        );
        let owned_now = match ctx.firewall.apply(&rules, &forwarding) {
            Ok(()) => {
                crate::firewall::ip_forward::take_egress(&plan.take);
                plan.guard
            }
            Err(e) => {
                failures.push(PollError::Firewall(e.to_string()));
                // The previous ruleset is still in place, guarding what
                // was owned; nothing new was turned on.
                plan.guard.difference(&plan.take).cloned().collect()
            }
        };
        // Interface-scoped forwarding (PLAN.md M23) — touched only when
        // this node currently carries at least one active transit pair
        // or forwards to a service's target address (M26), so otherwise
        // the host's forwarding posture is left completely alone. See
        // `ip_forward` module doc for why this is scoped to `ifname` and
        // never the host's global/`all` forwarding switches.
        let local_routes = sync_local_routes(&local_routes, &local_routes_wanted, node_ip);
        let forwards_services = rules.iter().any(|r| r.remote_target().is_some());
        crate::firewall::ip_forward::set_enabled(
            &ifname,
            !transit_forwards.is_empty() || forwards_services || !exit.is_empty(),
        );

        // 4. rewrite the hosts-file managed block from the full directory.
        let naming = crate::hosts::Naming::new(directory.naming.as_ref());
        if let Err(e) =
            crate::hosts::sync(ctx.hosts_path, ctx.hosts_label, &directory.services, naming)
        {
            failures.push(PollError::Hosts(e));
        }
        (failures, owned_now, local_routes)
    });
    // Recorded whatever else failed: it is what the kernel now holds, and
    // what stop has to turn back off.
    {
        let owned: Vec<String> = owned_egress_now.into_iter().collect();
        let routed: Vec<Ipv4Addr> = local_routes_now.into_iter().collect();
        let mut s = state.lock().await;
        if s.forwarding_owned != owned || s.local_routes != routed {
            s.forwarding_owned = owned;
            s.local_routes = routed;
            s.save(ctx.state_path)?;
        }
    }
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

    #[test]
    fn exit_clients_resolve_to_their_mesh_addresses_and_nothing_else() {
        let directory: PollResponse = serde_json::from_value(serde_json::json!({
            "peers": [
                {"name": "phone", "pubkey": "pk-phone", "ip4": "100.90.0.9", "ip6": "fd00:90::9"},
                {"name": "tablet", "pubkey": "pk-tablet", "ip4": "100.90.0.8", "ip6": "fd00:90::8"},
                {"name": "odd", "pubkey": "pk-odd", "ip4": "not an address", "ip6": ""},
            ],
            "services": [],
            // Twice, one unknown, one unparsable: none of it may widen the
            // rule beyond the addresses the directory itself holds.
            "exit_clients": ["pk-phone", "pk-phone", "pk-unknown", "pk-odd"],
        }))
        .unwrap();
        assert_eq!(exit_client_addrs(&directory), vec![Ipv4Addr::new(100, 90, 0, 9)]);
    }
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
    async fn a_later_different_offer_never_replaces_the_pin() {
        let state = Mutex::new(AgentState { mesh: Some(mesh("10.9.0.0/24")), ..joined_state() });

        // Wider, and still containing this node: exactly what an attacker
        // rewriting the response would send to widen what it may route.
        let r = pinned_mesh_ranges(&state, Some(&mesh("0.0.0.0/0"))).await.unwrap();
        assert!(!r.contains4("192.168.1.1".parse().unwrap()));
        assert_eq!(state.lock().await.mesh, Some(mesh("10.9.0.0/24")));
    }

    #[test]
    fn build_poll_request_carries_declared_services_verbatim() {
        let declared = vec![ServiceDecl { name: "plex".into(), ports: vec![] }];
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
                exit_capable: true,
                reachable: vec!["reachable-pk".into()],
                wanted: vec!["wanted-pk".into()],
            },
            TlsSelfReport::default(),
        );
        assert_eq!(req.services.len(), 1);
        assert_eq!(req.endpoint_addr.as_deref(), Some("host:51820"));
        assert_eq!(req.endpoint_addr_v4.as_deref(), Some("203.0.113.5:51820"));
        assert!(req.endpoint_addr_v6.is_none());
        assert_eq!(req.lan_addr.as_deref(), Some("192.168.1.5"));
        assert_eq!(req.reflexive_addr.as_deref(), Some("203.0.113.5:55123"));
        assert!(req.transit_capable);
        assert!(req.exit_capable);
        assert_eq!(req.transit_reachable, vec!["reachable-pk".to_string()]);
        assert_eq!(req.transit_wanted, vec!["wanted-pk".to_string()]);
    }

    const NODE: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
    const VIP: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 50);
    const TLS_PORT: u16 = wireserve_types::TLS_LISTEN_PORT;

    fn pm(s: &str) -> PortMap {
        s.parse().unwrap()
    }

    fn published(name: &str, owner: Ipv4Addr, vip4: Option<Ipv4Addr>) -> ServiceInfo {
        ServiceInfo {
            auth: false,
            terminated: false,
            name: name.into(),
            node: "n".into(),
            ip4: owner.to_string(),
            online: true,
            vip4: vip4.map(|v| v.to_string()),
            ports: vec![],
        }
    }

    fn with_services(services: Vec<ServiceInfo>) -> PollResponse {
        PollResponse {
            naming: None, services, ..directory_with(&[], &[]) }
    }

    /// Whether any rule makes target `port` reachable.
    fn reaches(rules: &[ServiceRule], port: u16) -> bool {
        rules.iter().any(|r| match r {
            ServiceRule::Mapped { map, .. } | ServiceRule::Terminated { map, .. } => map.target == port,
        })
    }

    #[test]
    fn a_service_with_an_address_gets_one_mapped_rule_per_port() {
        let declared = vec![ServiceDecl::new("dns", vec![pm("53/udp"), pm("53/tcp"), pm("8080:8000")])];
        let rules = service_rules(&declared, Some(NODE), &with_services(vec![published("dns", NODE, Some(VIP))]), None, &BTreeSet::new(), TLS_PORT);
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
    fn a_service_without_an_address_is_opened_nowhere() {
        // An exhausted range, or an address `vip::sanitize` refused: there
        // is nothing to scope a hole to but the node's own address, open to
        // the whole mesh.
        let declared = vec![ServiceDecl::new("web", vec![pm("80:5080")])];
        assert!(service_rules(&declared, Some(NODE), &with_services(vec![published("web", NODE, None)]), None, &BTreeSet::new(), TLS_PORT).is_empty());
        assert!(service_rules(&declared, Some(NODE), &with_services(vec![]), None, &BTreeSet::new(), TLS_PORT).is_empty());
    }

    #[test]
    fn without_a_mesh_address_nothing_is_opened() {
        let declared = vec![ServiceDecl::new("web", vec![pm("80:5080")])];
        assert!(service_rules(&declared, None, &with_services(vec![published("web", NODE, Some(VIP))]), None, &BTreeSet::new(), TLS_PORT).is_empty());
    }

    #[test]
    fn a_pending_service_gets_its_rules_from_the_pending_address() {
        let declared = vec![ServiceDecl::new("web", vec![pm("80:5080")])];
        let mut dir = directory_with(&["web"], &[]);
        dir.pending_services[0].vip4 = Some(VIP.to_string());
        assert_eq!(
            service_rules(&declared, Some(NODE), &dir, None, &BTreeSet::new(), TLS_PORT),
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
        let rules = service_rules(&declared, Some(NODE), &with_services(vec![entry]), None, &BTreeSet::new(), TLS_PORT);
        assert_eq!(rules, vec![ServiceRule::Mapped { vip: VIP, node: NODE, map: pm("80:5080") }]);
    }

    // ---- behind the proxy's sign-in (PLAN.md M29) ----


    fn marked(name: &str, vip: Option<Ipv4Addr>) -> ServiceInfo {
        let mut s = published(name, NODE, vip);
        s.auth = true;
        s.terminated = vip.is_some();
        s
    }

    #[test]
    fn a_marked_service_opens_its_terminated_443_and_nothing_else() {
        // PLAN.md M34: the sign-in is in the terminator, so its 443 is the
        // only way in; the second mapping would otherwise walk round it.
        let declared = vec![ServiceDecl::new("jellyfin", vec![pm("443:8096"), pm("8920")])];
        let serving = BTreeSet::from(["jellyfin".to_string()]);
        let rules = service_rules(&declared, Some(NODE), &with_services(vec![marked("jellyfin", Some(VIP))]), None, &serving, TLS_PORT);
        assert_eq!(rules, vec![ServiceRule::Terminated { vip: VIP, map: pm("443:8096"), port: TLS_PORT }]);
    }

    #[test]
    fn a_marked_service_is_not_opened_at_all_while_its_terminator_does_not_serve_it() {
        let declared = vec![ServiceDecl::new("jellyfin", vec![pm("443:8096"), pm("8920")])];
        let rules = service_rules(&declared, Some(NODE), &with_services(vec![marked("jellyfin", Some(VIP))]), None, &BTreeSet::new(), TLS_PORT);
        assert!(rules.is_empty(), "{rules:?}");
        // No address of its own: the fallback would open the node's port to
        // the whole mesh, which is exactly what the mark forbids.
        let serving = BTreeSet::from(["jellyfin".to_string()]);
        let rules = service_rules(&declared, Some(NODE), &with_services(vec![marked("jellyfin", None)]), None, &serving, TLS_PORT);
        assert!(rules.is_empty(), "{rules:?}");
    }

    #[test]
    fn polls_say_this_agent_understands_the_mark() {
        let req = build_poll_request(
            &[],
            None,
            &crate::probe::DualProbeResult::default(),
            None,
            None,
            TransitSelfReport { capable: false, exit_capable: false, reachable: vec![], wanted: vec![] },
            TlsSelfReport::default(),
        );
        assert!(req.capabilities.is_empty(), "no terminator, nothing to claim");
        assert!(req.tls_ready.is_empty());

        let req = build_poll_request(
            &[],
            None,
            &crate::probe::DualProbeResult::default(),
            None,
            None,
            TransitSelfReport { capable: false, exit_capable: false, reachable: vec![], wanted: vec![] },
            TlsSelfReport { capable: true, ready: vec!["plex".into()] },
        );
        assert!(req.capabilities.contains(&wireserve_types::CAP_TLS_TERMINATE.to_string()));
        assert_eq!(req.tls_ready, vec!["plex".to_string()]);
    }

    // ---- PLAN.md M33: termination on this node ----

    fn terminated_entry(name: &str, node: Ipv4Addr, vip: Ipv4Addr) -> ServiceInfo {
        let mut e = published(name, node, Some(vip));
        e.terminated = true;
        e
    }

    #[test]
    fn only_what_the_directory_and_the_terminator_agree_on_terminates() {
        let other = Ipv4Addr::new(10, 9, 0, 2);
        let dir = with_services(vec![
            terminated_entry("plex", NODE, VIP),
            published("git", NODE, Some(Ipv4Addr::new(10, 9, 0, 21))),
            terminated_entry("far", other, Ipv4Addr::new(10, 9, 0, 22)),
        ]);
        let serving: BTreeSet<String> = ["plex", "git", "far"].iter().map(|s| (*s).to_string()).collect();
        let here = terminating_here(Some(NODE), &dir, &serving);
        assert_eq!(here, BTreeSet::from(["plex".to_string()]), "git is not terminated, far is not ours");
        assert!(terminating_here(Some(NODE), &dir, &BTreeSet::new()).is_empty(), "a silent terminator gets nothing");
        assert!(terminating_here(None, &dir, &serving).is_empty());
    }

    #[test]
    fn a_terminated_service_keeps_its_other_ports_and_its_443_target_reserved() {
        let declared = vec![
            ServiceDecl::new("plex", vec![pm("443:32400"), pm("8443:32401")]),
            ServiceDecl::new("clash", vec![pm("80:32400")]),
        ];
        let dir = with_services(vec![
            terminated_entry("plex", NODE, VIP),
            published("clash", NODE, Some(Ipv4Addr::new(10, 9, 0, 30))),
        ]);
        let rules = service_rules(&declared, Some(NODE), &dir, None, &BTreeSet::from(["plex".to_string()]), TLS_PORT);
        assert_eq!(rules.len(), 2, "{rules:?}");
        assert!(matches!(rules[0], ServiceRule::Terminated { vip, map, port } if vip == VIP && map.public == 443 && port == TLS_PORT));
        assert!(matches!(rules[1], ServiceRule::Mapped { map, .. } if map.public == 8443));
        assert!(rules.iter().all(|r| r.remote_target().is_none()));
    }

    #[test]
    fn another_nodes_entry_of_the_same_name_is_not_ours() {
        let declared = vec![ServiceDecl::new("web", vec![pm("80:5080")])];
        let other = Ipv4Addr::new(10, 9, 0, 2);
        let rules = service_rules(&declared, Some(NODE), &with_services(vec![published("web", other, Some(VIP))]), None, &BTreeSet::new(), TLS_PORT);
        assert!(rules.is_empty(), "no address of our own: {rules:?}");
    }

    #[test]
    fn an_aliased_target_port_is_mapped_once() {
        // Two names on one target, as a hand-edited state file can hold.
        let declared = vec![
            ServiceDecl::new("plex", vec![PortMap::identity(32400, Proto::Tcp)]),
            ServiceDecl::new("media", vec![PortMap::identity(32400, Proto::Tcp)]),
        ];
        let other = Ipv4Addr::new(10, 9, 0, 51);
        let dir = with_services(vec![published("plex", NODE, Some(VIP)), published("media", NODE, Some(other))]);
        assert_eq!(
            service_rules(&declared, Some(NODE), &dir, None, &BTreeSet::new(), TLS_PORT),
            vec![ServiceRule::Mapped { vip: VIP, node: NODE, map: PortMap::identity(32400, Proto::Tcp) }]
        );
    }

    #[test]
    fn a_mapping_onto_another_address_is_a_mapped_rule_to_it() {
        let declared = vec![ServiceDecl::new("myrouter", vec![pm("443:192.168.178.1:80"), pm("8080")])];
        let rules = service_rules(&declared, Some(NODE), &with_services(vec![published("myrouter", NODE, Some(VIP))]), None, &BTreeSet::new(), TLS_PORT);
        assert_eq!(
            rules,
            vec![
                ServiceRule::Mapped { vip: VIP, node: NODE, map: pm("443:192.168.178.1:80") },
                ServiceRule::Mapped { vip: VIP, node: NODE, map: pm("8080") },
            ]
        );
        assert_eq!(rules[0].remote_target(), Some(Ipv4Addr::new(192, 168, 178, 1)));
    }

    #[test]
    fn a_target_address_inside_the_mesh_gets_no_rule() {
        let ranges = wireserve_types::MeshRanges::parse(&mesh("10.9.0.0/24")).unwrap();
        let dir = with_services(vec![published("x", NODE, Some(VIP))]);
        for target in ["443:10.9.0.33:80", &format!("443:{NODE}:80")] {
            let declared = vec![ServiceDecl::new("x", vec![pm(target)])];
            assert!(service_rules(&declared, Some(NODE), &dir, Some(&ranges), &BTreeSet::new(), TLS_PORT).is_empty(), "{target}");
        }
        let declared = vec![ServiceDecl::new("x", vec![pm("443:192.168.178.1:80")])];
        assert_eq!(service_rules(&declared, Some(NODE), &dir, Some(&ranges), &BTreeSet::new(), TLS_PORT).len(), 1);
    }

    #[test]
    fn the_same_port_on_the_node_and_on_another_address_are_both_mapped() {
        let declared = vec![
            ServiceDecl::new("web", vec![pm("80")]),
            ServiceDecl::new("myrouter", vec![pm("443:192.168.178.1:80")]),
        ];
        let other = Ipv4Addr::new(10, 9, 0, 51);
        let dir = with_services(vec![published("web", NODE, Some(VIP)), published("myrouter", NODE, Some(other))]);
        assert_eq!(service_rules(&declared, Some(NODE), &dir, None, &BTreeSet::new(), TLS_PORT).len(), 2);
    }

    #[test]
    fn nothing_undeclared_is_ever_in_a_rule() {
        let rules = service_rules(&[], Some(NODE), &with_services(vec![published("web", NODE, Some(VIP))]), None, &BTreeSet::new(), TLS_PORT);
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
                    ports: vec![PortMap::identity(32400, Proto::Tcp)],
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
            exit_clients: vec![],
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
        let dir = with_services(vec![published("plex", NODE, Some(VIP)), published("git", NODE, Some(Ipv4Addr::new(10, 9, 0, 51)))]);
        assert!(reaches(&service_rules(&state.declared_services, Some(NODE), &dir, None, &BTreeSet::new(), TLS_PORT), 32400));

        apply_approval_verdicts(&mut state, &directory_with(&[], &[("plex", None)]));

        assert!(
            !reaches(&service_rules(&state.declared_services, Some(NODE), &dir, None, &BTreeSet::new(), TLS_PORT), 32400),
            "a denied service's port must not survive in the rule set"
        );
    }

    #[test]
    fn a_pending_service_is_recorded_but_never_quarantined() {
        // Pending keeps being declared (so an admin can still approve it)
        // and keeps its own firewall hole — the node is only firewalling
        // itself, and nothing resolves <name>.wg for it yet anyway.
        let mut state = state_with_declared(&["plex"]);

        let mut pending = directory_with(&["plex"], &[]);
        pending.pending_services[0].vip4 = Some(VIP.to_string());
        let changed = apply_approval_verdicts(&mut state, &pending);

        assert!(changed);
        assert_eq!(state.declared_services.len(), 1, "still declared");
        assert!(state.rejected_services.is_empty(), "pending is not a rejection");
        assert_eq!(state.pending_services, vec!["plex".to_string()]);
        assert!(reaches(&service_rules(&state.declared_services, Some(NODE), &pending, None, &BTreeSet::new(), TLS_PORT), 32400));
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
        // What a coordinator with approval disabled returns. Must be a
        // no-op, not an implicit "everything denied".
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
                .enumerate()
                .map(|(i, n)| ServiceDecl::new(*n, vec![PortMap::identity(32400 + i as u16, Proto::Tcp)]))
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
