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
    // `device create` generates that token during registration and drops
    // it on the floor without ever printing or storing it. Enforce the
    // invariant anyway rather than leave it resting on that accident,
    // since `update_poll_state` below would otherwise happily write an
    // `endpoint_addr` onto a static node and every exported `.conf`
    // afterwards would carry an `Endpoint =` line for a peer that is
    // never meant to be dialed into.
    if let crate::rate_limit::Take::Refused { log } = state.poll_limiter.take(node.id) {
        if log {
            tracing::warn!(event = "poll_rate_limited", node_name = %node.name, "polling faster than the per-node limit");
        }
        return Err(AppError::TooManyRequests);
    }
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
    state.transit.report_carry_port(&self_pubkey, req.carry_port);
    state.transit.report_dialable(&self_pubkey, req.dialable_v4);
    let seen: Vec<wireserve_types::PortCheck> =
        req.port_checks_seen.iter().take(wireserve_types::MAX_PORT_CHECKS_PER_POLL).cloned().collect();
    state.transit.record_seen(&self_pubkey, &seen);

    // Same observed-source-address fallback as `/register` (spec §4.2),
    // re-applied on every poll rather than frozen at join time — see
    // `client_ip::endpoint_fallback`'s doc comment for why (an operator's
    // own explicit --endpoint, sent every poll, still always wins).
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

    let previous = services::list_for_node(&conn, node.id)?;
    let previous_names: std::collections::HashSet<&str> =
        previous.iter().map(|s| s.name.as_str()).collect();
    // A name nobody may newly take: reserved, or another node's own name — a
    // node may have a service called after itself, and nobody else may. One
    // the node already has is left alone; it is not the declaration that is
    // new. Told to the node as a notice, never a failed poll.
    let node_names: std::collections::HashSet<String> =
        nodes::list_all_names(&conn)?.into_iter().filter(|n| *n != node.name).collect();
    let mut refused: Vec<wireserve_types::ServiceNotice> = Vec::new();
    let desired_owned: Vec<wireserve_types::ServiceDecl> = req
        .services
        .iter()
        .filter(|d| {
            if previous_names.contains(d.name.as_str()) {
                return true;
            }
            let why = state
                .config
                .reserved_reason(&d.name)
                .map(str::to_string)
                .or_else(|| node_names.contains(&d.name).then(|| "another node's name; only that node may have a service by it".to_string()));
            match why {
                Some(why) => {
                    refused.push(wireserve_types::ServiceNotice { name: d.name.clone(), reason: format!("not published: {why}") });
                    false
                }
                None => true,
            }
        })
        .cloned()
        .collect();
    let desired = &desired_owned;
    let desired_names: std::collections::HashSet<&str> =
        desired.iter().map(|d| d.name.as_str()).collect();

    let mode = if state.config.require_service_approval {
        services::ApprovalMode::RequireApproval
    } else {
        services::ApprovalMode::AutoApprove
    };
    let mut outcome = services::upsert_for_node(&mut conn, node.id, desired, mode, &state.config.net_v4_cidr)?;
    outcome.notices.extend(refused);
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
        .map(|n| directory::peer_info(n, state.config.online_threshold_secs, state.config.relay_port_base))
        .collect();

    // End-to-end relaying (PLAN.md M39). A node takes part only while its
    // own latest poll says it can: a carry port, and the capability.
    let fresh = state.config.online_threshold_secs;
    for peer in &mut peers {
        peer.relay.carry_port = state.transit.carry_port(&peer.pubkey, fresh);
    }
    let relayable: std::collections::HashSet<String> = peers
        .iter()
        .filter(|p| p.relay.port.is_some() && p.relay.carry_port.is_some())
        .map(|p| p.pubkey.clone())
        .collect();
    let can_carry = |pk: &str| state.transit.has_capability(pk, wireserve_types::CAP_RELAY, fresh);
    // The carrier for a pair that can't reach each other directly: only
    // ever one relaying end to end. There is no fallback to forwarding the
    // pair's traffic in the clear — every node upgrades together.
    let relay_carrier = |a: &str, c: &str| -> Option<String> {
        if !relayable.contains(a) || !relayable.contains(c) || !state.transit.either_wants(a, c) {
            return None;
        }
        state.transit.select_where(a, c, fresh, &can_carry)
    };

    for peer in &mut peers {
        if peer.pubkey == self_pubkey {
            continue;
        }
        peer.relay.via = relay_carrier(&self_pubkey, &peer.pubkey).filter(|via| via != &self_pubkey);
    }

    // This requester's own carrier role this cycle (PLAN.md M39): every
    // OTHER pair (x, y) — neither of them this requester — for which
    // `relay_carrier` names this requester. A carrier learns its role from
    // this list alone: its own entries for x and y never carry a `via`,
    // since it is only ever chosen when it reaches both directly.
    let all_pubkeys: Vec<&str> = all_peers.iter().filter_map(|n| n.pubkey.as_deref()).collect();
    let mut relay_carrying = Vec::new();
    for (i, &x) in all_pubkeys.iter().enumerate() {
        if x == self_pubkey {
            continue;
        }
        for &y in &all_pubkeys[i + 1..] {
            if y == self_pubkey {
                continue;
            }
            if relay_carrier(x, y).as_deref() == Some(self_pubkey.as_str()) {
                relay_carrying.push(wireserve_types::TransitPair { a: x.to_string(), c: y.to_string() });
            }
        }
    }

    // This requester's exit role (PLAN.md M27): the devices whose last export
    // named it as their exit, while it is still approved — withdrawing the
    // approval ends the exit on the same poll — and a revoked device leaves
    // `all_peers`. Whether the node itself still offers is its own
    // business: the agent acts on this only while `exit on`.
    let exit_clients: Vec<String> = if node.transit_approved {
        all_peers
            .iter()
            .filter(|n| n.exit_enabled && n.exit_node_id == Some(node.id))
            .filter_map(|n| n.pubkey.clone())
            .collect()
    } else {
        Vec::new()
    };

    // This requester's public relays (PLAN.md M40): the nodes devices reach
    // through its public address, from their exports — only while it is
    // approved to carry, and only nodes still in the directory.
    let relay_public: Vec<String> = if node.transit_approved {
        let live: std::collections::HashMap<i64, &nodes::NodeRow> = all_peers.iter().map(|n| (n.id, n)).collect();
        let mut dests: Vec<String> = nodes::all_static_relays(&conn)?
            .into_iter()
            .filter(|(device, _, carrier)| *carrier == node.id && live.contains_key(device))
            .filter_map(|(_, peer, _)| live.get(&peer)?.pubkey.clone())
            .collect();
        dests.sort();
        dests.dedup();
        dests
    } else {
        Vec::new()
    };
    let port_checks = state.transit.checks_for(&self_pubkey);

    let tls_ready = crate::db::tls::ready(&conn)?;
    let ctx = state.directory_context(&tls_ready);
    let services = directory::services_directory(&all_services, &all_peers, &ctx);

    // Who may reach each of this node's own services (PLAN.md M36), pending
    // ones included, so its firewall is ready the moment approval publishes
    // them. Sent to this node alone.
    let rules = crate::access::read_rules(&conn)?;
    let owner_capable = state.transit.has_capability(
        &self_pubkey,
        wireserve_types::CAP_SIGN_IN,
        state.config.online_threshold_secs,
    );
    let provider = state.config.sign_in.as_ref().map(|si| (si.service.as_str(), si.node.as_str()));
    let own_rows = services::list_for_node(&conn, node.id)?;
    let access: Vec<wireserve_types::ServiceAccess> = own_rows
        .iter()
        .filter(|s| s.denied_at.is_none() || s.approved_at.is_some())
        .map(|s| {
            let facts = crate::access::SignInFacts { provider, owner_capable, terminated: ctx.terminates(s) };
            crate::access::service_access(s, &node, &all_peers, &rules, &facts)
        })
        .collect();

    // Who owns the devices its terminator lets in by their grants (PLAN.md
    // M38), so it can name them to its backends: those allowed into any of
    // its terminated services — every device, when one is open — and that
    // the node says have connected to it. Without the second, a node with
    // one open service would be told every owner's subject, e-mail address
    // and groups; a node that lies about who came still gets no more than
    // it asks for, one device at a time, each logged the first time.
    let terminated: Vec<&wireserve_types::ServiceAccess> = access
        .iter()
        .filter(|a| own_rows.iter().any(|r| r.name == a.name && ctx.terminates(r)))
        .collect();
    let seen: std::collections::HashSet<std::net::Ipv4Addr> =
        req.callers_seen.iter().take(wireserve_types::MAX_CALLERS_SEEN_PER_POLL).copied().collect();
    let identities = if terminated.is_empty() || seen.is_empty() {
        Vec::new()
    } else {
        let every = terminated.iter().any(|a| a.open);
        let allowed: std::collections::BTreeSet<std::net::Ipv4Addr> =
            terminated.iter().flat_map(|a| a.sources.iter().copied()).collect();
        let now = chrono::Utc::now();
        crate::db::owners::all(&conn)?
            .into_iter()
            .filter(|o| o.groups_count(now))
            .filter_map(|o| {
                let device = all_peers.iter().find(|p| p.id == o.node_id)?;
                let addr: std::net::Ipv4Addr = device.ip4.as_deref()?.parse().ok()?;
                if !seen.contains(&addr) || !(every || allowed.contains(&addr)) {
                    return None;
                }
                if state.first_release(node.id, device.id) {
                    tracing::info!(event = "owner_identity_released", node_name = %node.name, device = %device.name, sub = %o.sub);
                }
                Some(wireserve_types::CallerIdentity { addr, user: o.sub, email: o.email, groups: o.groups })
            })
            .collect()
    };

    Ok(Json(PollResponse {
        peers,
        services,
        pending_services: outcome.pending.iter().map(directory::pending_service).collect(),
        denied_services: outcome.denied.iter().map(directory::denied_service).collect(),
        relay_carrying,
        relay_public,
        relay_port_base: Some(state.config.relay_port_base),
        port_checks,
        transit_awaiting_approval,
        exit_clients,
        mesh: Some(state.config.mesh_info()),
        naming: state.config.service_naming(),
        access,
        service_notices: outcome.notices,
        identities,
    }))
}
