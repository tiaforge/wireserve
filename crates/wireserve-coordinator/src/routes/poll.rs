use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::Json;
use wireserve_types::{PollRequest, PollResponse};

use crate::auth::BearerNode;
use crate::db::{nodes, services};
use crate::directory;
use crate::error::AppError;
use crate::state::AppState;

/// Re-exported from `wireserve-types`, which is where the number now
/// lives so the agent can enforce the identical limit locally before it
/// ever queues a declaration the coordinator would reject. See that
/// constant's own doc comment for why a coordinator-only limit was a
/// wedge waiting to happen.
pub use wireserve_types::MAX_SERVICES_PER_NODE;

/// `POST /poll` (spec §4.3): the agent's single call that both reports its
/// own state and pulls the current mesh + service directory.
pub async fn poll(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    BearerNode { node }: BearerNode,
    Json(req): Json<PollRequest>,
) -> Result<Json<PollResponse>, AppError> {
    // Spec §9: a `kind=static` node "never polls" and its `endpoint_addr`
    // "stays NULL forever" — it is a consumer-only device running an
    // official WireGuard client, with no agent to do the polling. Nothing
    // legitimately reaches this line with a static node's bearer token:
    // `export-config` generates that token during registration and drops
    // it on the floor without ever printing or storing it. Enforce the
    // invariant anyway rather than leave it resting on that accident,
    // since `update_poll_state` below would otherwise happily write an
    // `endpoint_addr` onto a static node and every exported `.conf`
    // afterwards would carry an `Endpoint =` line for a peer that is
    // never meant to be dialed into.
    if node.kind == wireserve_types::NodeKind::Static {
        return Err(AppError::Forbidden(
            "this node is registered as kind=static, which never polls (spec §9)".into(),
        ));
    }

    if req.services.len() > MAX_SERVICES_PER_NODE {
        return Err(AppError::BadRequest(format!(
            "too many services declared ({}); the limit is {MAX_SERVICES_PER_NODE} per node",
            req.services.len()
        )));
    }
    for decl in &req.services {
        if !wireserve_types::is_valid_dns_label(&decl.name) {
            return Err(AppError::BadRequest(format!(
                "invalid service name: {}",
                decl.name
            )));
        }
        // The same per-service check the agent's `serve` makes (no empty
        // list, no port 0). The per-node one (a target port mapped once) is
        // left to the agent: it concerns only its own firewall.
        if let Err(e) = wireserve_types::validate_service_ports(&decl.ports) {
            return Err(AppError::BadRequest(format!("service '{}': {e}", decl.name)));
        }
        // A target address inside the mesh (PLAN.md M26) — the agent's
        // `serve` refuses it too, against the ranges it pinned from here.
        let ranges = wireserve_types::MeshRanges::parse(&state.config.mesh_info());
        if let Some(m) = decl.ports.iter().find(|m| m.addr.is_some_and(|a| ranges.is_some_and(|r| r.contains4(a)))) {
            return Err(AppError::BadRequest(format!(
                "service '{}': {m} forwards to an address inside the mesh",
                decl.name
            )));
        }
    }
    // S2 (security review): endpoint_addr is redistributed verbatim to
    // every other node's /poll response and into rendered .conf files —
    // same validation as /register, applied here too since a node can
    // change its reported endpoint_addr on every poll (spec §4.3).
    for endpoint in [
        req.endpoint_addr.as_deref(),
        req.endpoint_addr_v4.as_deref(),
        req.endpoint_addr_v6.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !wireserve_types::is_valid_endpoint_addr(endpoint) {
            return Err(AppError::BadRequest(
                "endpoint_addr must be a valid host:port".into(),
            ));
        }
    }
    if let Some(lan) = req.lan_addr.as_deref() {
        if !wireserve_types::is_valid_lan_addr(lan) {
            return Err(AppError::BadRequest(
                "lan_addr must be a private-range (RFC1918) IPv4 address".into(),
            ));
        }
    }
    if let Some(reflexive) = req.reflexive_addr.as_deref() {
        if !wireserve_types::is_valid_reflexive_addr(reflexive) {
            return Err(AppError::BadRequest(
                "reflexive_addr must be a valid IPv4 ip:port".into(),
            ));
        }
    }
    // Transit self-report (PLAN.md M23): hints, not identity/addressing
    // facts, so a malformed entry is dropped silently rather than
    // rejecting the whole poll the way an invalid endpoint_addr does —
    // the same posture `transit_wanted`/`transit_reachable`'s own doc
    // comments describe.
    let self_pubkey = node.pubkey.clone().unwrap_or_default();
    let transit_reachable: Vec<String> = req
        .transit_reachable
        .iter()
        .filter(|pk| wireserve_types::is_valid_wg_pubkey(pk))
        .cloned()
        .collect();
    let transit_wanted: Vec<String> = req
        .transit_wanted
        .iter()
        .filter(|pk| wireserve_types::is_valid_wg_pubkey(pk))
        .cloned()
        .collect();
    // Only an admin makes a node a carrier (security review finding #1).
    // A carrier sees what it relays in the clear, and the two ends put
    // the other end's addresses in its `AllowedIPs`, so it can also send
    // packets as either of them. Everything a node reports about itself —
    // that it is willing, which peers it reaches — is unverified, so the
    // offer alone would let any one compromised node volunteer for every
    // pair in the mesh (and win the lowest-pubkey tie-break with a ground
    // key). Unapproved, the offer is recorded as no offer at all.
    let transit_capable = req.transit_capable && node.transit_approved;
    let transit_awaiting_approval = req.transit_capable && !node.transit_approved;
    state.transit.report(&self_pubkey, transit_capable, &transit_reachable, &transit_wanted);
    // Recorded as offered, approved or not: the export checks the transit
    // approval itself, and names whichever half is missing (PLAN.md M27).
    state.transit.report_exit(&self_pubkey, req.exit_capable);
    let capabilities: Vec<String> = req
        .capabilities
        .iter()
        .take(wireserve_types::MAX_CAPABILITIES_PER_POLL)
        .filter(|c| c.len() <= 64)
        .cloned()
        .collect();
    state.transit.report_capabilities(&self_pubkey, &capabilities);

    // Same observed-source-address fallback as `/register` (spec §4.2),
    // re-applied on every poll rather than frozen at join time — see
    // `client_ip::endpoint_fallback`'s doc comment for why (an operator's
    // own explicit --endpoint-addr, sent every poll, still always wins).
    //
    // But never when an admin has explicitly cleared this node's endpoint
    // (`node.endpoint_cleared`) — self-healing would otherwise undo that
    // clear on the very next poll, which is the one guarantee
    // `clear_endpoint` exists to make. An explicit report from the node
    // itself is exempt from that gate (and resets it): the node asserting
    // its own address is not the coordinator guessing again.
    //
    // This column is family-blind by design (a dual-stack node's poll can
    // arrive over either family depending on nothing more than routing on
    // that one request) — `wg::choose_peer_endpoint` is responsible for
    // not handing an IPv6 value out of it to a peer that can't use v6,
    // falling back to the actively-probed `endpoint_addr_v4`/`_v6` pair
    // instead when that happens. Do not duplicate that family check here.
    let explicit = req.endpoint_addr.as_deref();
    let endpoint_addr = if explicit.is_some() {
        explicit.map(str::to_string)
    } else if node.endpoint_cleared {
        None
    } else {
        let client = crate::client_ip::resolve_client(
            &headers,
            peer_addr.ip(),
            state.config.trusts_forwarded_from(peer_addr.ip()),
        );
        let listen_port = node.listen_port.and_then(|p| u16::try_from(p).ok());
        crate::client_ip::endpoint_fallback(
            None,
            &client,
            listen_port,
            state.config.trusts_forwarded_from(peer_addr.ip()),
        )
    };

    let mut conn = state.db.conn.lock().await;

    nodes::update_poll_state(
        &conn,
        node.id,
        &nodes::EndpointUpdate {
            explicit: endpoint_addr.as_deref(),
            reset_cleared: explicit.is_some(),
            v4: req.endpoint_addr_v4.as_deref(),
            v6: req.endpoint_addr_v6.as_deref(),
            lan: req.lan_addr.as_deref(),
            reflexive: req.reflexive_addr.as_deref(),
        },
    )?;

    let desired = &req.services;
    let desired_names: std::collections::HashSet<&str> =
        desired.iter().map(|d| d.name.as_str()).collect();
    let previous = services::list_for_node(&conn, node.id)?;
    let previous_names: std::collections::HashSet<&str> =
        previous.iter().map(|s| s.name.as_str()).collect();

    let mode = if state.config.require_service_approval {
        services::ApprovalMode::RequireApproval
    } else {
        services::ApprovalMode::AutoApprove
    };
    let outcome = services::upsert_for_node(&mut conn, node.id, desired, mode, &state.config.net_v4_cidr)?;
    // Which of its services this node serves with TLS right now (PLAN.md
    // M33). Replaced wholesale, so a name left out stops being terminated
    // on this very poll; only names the node owns are kept.
    let tls_ready: Vec<String> = req
        .tls_ready
        .iter()
        .take(wireserve_types::MAX_TLS_READY_PER_POLL)
        .filter(|n| wireserve_types::is_valid_dns_label(n))
        .cloned()
        .collect();
    crate::db::tls::set_ready(&mut conn, node.id, &tls_ready)?;
    // A declaration, withdrawal or address change on any poll moves the
    // public names; the loop spaces its passes, so poking every time is
    // cheaper than working out whether anything changed.
    state.poke_dns();

    for name in desired_names.difference(&previous_names) {
        tracing::info!(event = "service_declared", node_name = %node.name, service = %name);
    }
    for name in previous_names.difference(&desired_names) {
        tracing::info!(event = "service_withdrawn", node_name = %node.name, service = %name);
    }
    // Gated on *newly* declared names: a service can sit pending for days,
    // and logging it on every 20-second cycle would bury the audit trail
    // it belongs to.
    for row in &outcome.pending {
        if desired_names.difference(&previous_names).any(|n| *n == row.name) {
            tracing::info!(
                event = "service_pending_approval",
                node_name = %node.name,
                service = %row.name,
                ports = %row.ports.iter().map(ToString::to_string).collect::<Vec<_>>().join(","),
            );
        }
    }

    let all_peers = nodes::list_all_peers(&conn)?;
    let all_services = services::list_approved(&conn)?;

    let mut peers: Vec<wireserve_types::PeerInfo> = all_peers
        .iter()
        .map(|n| directory::peer_info(n, state.config.online_threshold_secs))
        .collect();

    // Second pass (PLAN.md M23): `transit_via` is requester-relative —
    // "how THIS polling node should reach each peer" — which
    // `directory::peer_info` structurally can't express on its own.
    // `GET /admin/peers` deliberately skips this and leaves it always
    // `None`: an admin isn't "a requester" polling on behalf of a
    // specific node, so there is no requester to compute it relative to.
    //
    // Gateway routing for static peers (PLAN.md M24) is computed here too,
    // and takes precedence. It is DB-driven and deliberately bypasses
    // `either_wants`/`select`: a static peer never polls, so it can never
    // file a `TransitState` report and the dynamic path can structurally
    // never fire for one. The precedence is made explicit rather than left
    // resting on that — the dynamic branch below assigns unconditionally,
    // so an assignment made here must not be reachable by it.
    let conf_peers: std::collections::HashSet<(i64, i64)> =
        nodes::all_static_conf_peers(&conn)?.into_iter().collect();
    let live_by_id: std::collections::HashMap<i64, &nodes::NodeRow> =
        all_peers.iter().map(|n| (n.id, n)).collect();

    // The gateway a node routes through, *if* it can still serve as one.
    // `all_peers` is already filtered to registered, non-revoked nodes, so
    // presence in `live_by_id` covers revoke and delete; approval is checked
    // on top so `deny-transit` takes effect on the next poll rather than
    // waiting for anything to be re-exported.
    //
    // Resolving this live, instead of trusting the stored id, is what keeps a
    // withdrawn gateway from erasing the phone: `wg::desired_peers` drops a
    // transited peer's entry in pass 1 and only re-adds it folded into the
    // via peer in pass 2, so a `transit_via` naming a node that is no longer
    // in the directory leaves the phone with no entry anywhere. Falling back
    // to `None` here degrades to an ordinary direct entry instead.
    let gateway_id_of = |n: &nodes::NodeRow| -> Option<i64> {
        let gw = live_by_id.get(&n.gateway_node_id?)?;
        gw.transit_approved.then_some(gw.id)
    };

    for (peer, row) in peers.iter_mut().zip(all_peers.iter()) {
        if peer.pubkey == self_pubkey {
            continue;
        }
        if let Some(gw_id) = gateway_id_of(row) {
            // The gateway itself terminates this peer's tunnel, so it keeps a
            // direct entry and must never be told to route via itself.
            if gw_id == node.id {
                continue;
            }
            // Whoever was written into this device's `.conf` as a direct
            // `[Peer]` also keeps a direct entry. Naming them here would make
            // them drop the device while it still dials them — its /32 in the
            // conf outranks the gateway's covering route, and WireGuard has
            // no failover — which is a black hole, not a fallback.
            if conf_peers.contains(&(row.id, node.id)) {
                continue;
            }
            peer.transit_via = live_by_id.get(&gw_id).and_then(|g| g.pubkey.clone());
            continue;
        }
        if state.transit.either_wants(&self_pubkey, &peer.pubkey) {
            peer.transit_via = state
                .transit
                .select(&self_pubkey, &peer.pubkey, state.config.online_threshold_secs)
                .filter(|via| via != &self_pubkey);
        }
    }

    // This requester's own carrier role this cycle (PLAN.md M23): every
    // OTHER pair (x, y) — neither of them this requester — that wants
    // transit help and for which `select` names this requester as `via`.
    // A node discovers its own role as `via` purely from this list; it
    // never appears via a bare `transit_via` on its own response (by
    // construction, `select` only ever picks a node that already reaches
    // both endpoints directly, so its own peer-a/peer-c entries never
    // need routing help and so never carry `transit_via` themselves).
    let all_pubkeys: Vec<&str> = all_peers.iter().filter_map(|n| n.pubkey.as_deref()).collect();
    let mut transit_carrying = Vec::new();
    for (i, &x) in all_pubkeys.iter().enumerate() {
        if x == self_pubkey {
            continue;
        }
        for &y in &all_pubkeys[i + 1..] {
            if y == self_pubkey {
                continue;
            }
            if state.transit.either_wants(x, y)
                && state.transit.select(x, y, state.config.online_threshold_secs).as_deref() == Some(self_pubkey.as_str())
            {
                transit_carrying.push(wireserve_types::TransitPair { a: x.to_string(), c: y.to_string() });
            }
        }
    }

    // This requester's gateway role (PLAN.md M24), on the same wire field as
    // M23's dynamic pairs: for every static peer routing through it, forward
    // between that peer and everything the peer does not reach directly.
    //
    // Iterating all peers rather than only agents is what covers phone↔phone
    // — a second static peer has no endpoint, so it is never in anyone's conf
    // and always falls into this set. Pairs are normalised and de-duplicated
    // because that case is reachable from both ends.
    if node.transit_approved {
        let mut gateway_pairs: std::collections::BTreeSet<(String, String)> =
            std::collections::BTreeSet::new();
        for client in all_peers.iter().filter(|n| gateway_id_of(n) == Some(node.id)) {
            let Some(client_pk) = client.pubkey.as_deref() else { continue };
            for other in &all_peers {
                if other.id == client.id || other.id == node.id {
                    continue;
                }
                if conf_peers.contains(&(client.id, other.id)) {
                    continue;
                }
                let Some(other_pk) = other.pubkey.as_deref() else { continue };
                gateway_pairs.insert(if client_pk < other_pk {
                    (client_pk.to_string(), other_pk.to_string())
                } else {
                    (other_pk.to_string(), client_pk.to_string())
                });
            }
        }
        for (a, c) in gateway_pairs {
            if !transit_carrying.iter().any(|p| (p.a == a && p.c == c) || (p.a == c && p.c == a)) {
                transit_carrying.push(wireserve_types::TransitPair { a, c });
            }
        }
    }

    // This requester's exit role (PLAN.md M27): the devices routing through
    // it whose last export included the full-tunnel profile. Derived through
    // `gateway_id_of`, so a gateway that stops qualifying — revoked, deleted,
    // transit approval withdrawn — loses its exit clients on the same poll
    // it loses its gateway clients, and a revoked device leaves `all_peers`.
    // Whether the node itself still offers is its own business: the agent
    // acts on this only while `exit on`.
    let exit_clients: Vec<String> = all_peers
        .iter()
        .filter(|n| n.exit_enabled && gateway_id_of(n) == Some(node.id))
        .filter_map(|n| n.pubkey.clone())
        .collect();

    let auth = services::auth_names(&conn)?;
    let tls_ready = crate::db::tls::ready(&conn)?;
    let services = directory::services_directory(&all_services, &all_peers, &state.directory_context(&auth, &tls_ready));

    Ok(Json(PollResponse {
        peers,
        services,
        pending_services: outcome.pending.iter().map(directory::pending_service).collect(),
        denied_services: outcome.denied.iter().map(directory::denied_service).collect(),
        transit_carrying,
        transit_awaiting_approval,
        exit_clients,
        mesh: Some(state.config.mesh_info()),
        naming: state.config.service_naming(),
    }))
}
