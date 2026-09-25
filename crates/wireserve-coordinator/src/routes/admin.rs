use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use wireserve_types::{
    AdminPeersResponse, AdminServicesResponse, CreateNodeRequest, CreateNodeResponse,
    DenyServiceRequest, RejoinRequest, RejoinResponse, JOIN_TOKEN_PREFIX, MAX_DENY_REASON_LEN,
};

use crate::auth::AdminAuth;
use crate::db::{nodes, services};
use crate::error::AppError;
use crate::state::AppState;
use crate::tokengen;

/// `POST /admin/nodes` (spec §4.1).
pub async fn create_node(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(req): Json<CreateNodeRequest>,
) -> Result<(StatusCode, Json<CreateNodeResponse>), AppError> {
    if !wireserve_types::is_valid_dns_label(&req.name) {
        return Err(AppError::BadRequest(format!(
            "invalid node name: {}",
            req.name
        )));
    }

    let join_token = tokengen::generate(JOIN_TOKEN_PREFIX);
    let hash = wireserve_types::hash_token(&join_token);
    let ttl = req.ttl_secs.unwrap_or(state.config.join_token_ttl_secs);
    let expires_at = nodes::join_token_expiry(ttl);

    let conn = state.db.conn.lock().await;
    nodes::create_node(&conn, &req.name, req.kind, &hash, expires_at.as_deref())?;

    tracing::info!(
        event = "node_created",
        node_name = %req.name,
        kind = req.kind.as_str(),
        join_token_ttl_secs = ttl,
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateNodeResponse {
            name: req.name,
            join_token,
            join_token_expires_at: parse_expiry(expires_at.as_deref()),
        }),
    ))
}

/// Re-parses the expiry string that was just written to the database, so
/// the response reports exactly what was stored rather than a separately
/// computed value that could drift from it.
fn parse_expiry(raw: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    raw.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

/// `POST /admin/nodes/{name}/revoke` (spec §4.4).
pub async fn revoke_node(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
) -> Result<(), AppError> {
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;
    nodes::revoke(&conn, node.id)?;
    // PLAN.md M23: a revoked node's transit report can't linger and still
    // get selected as transit, or still show up as wanting help, for up
    // to one `online_threshold_secs` window after revocation.
    if let Some(pubkey) = &node.pubkey {
        state.transit.forget(pubkey);
    }
    // PLAN.md M24: warn, never refuse. Revoking is how a compromised node is
    // cut off, so it must not be blockable by a routing dependency — and it
    // degrades safely, because `/poll` resolves a gateway against the live
    // directory and falls back to direct entries when it is gone.
    let dependents = nodes::static_nodes_using_gateway(&conn, node.id)?;
    if !dependents.is_empty() {
        tracing::warn!(
            event = "gateway_revoked_with_dependents",
            node_name = %name,
            dependents = %dependents.join(","),
            "revoked node was the gateway for these devices; they now reach only \
             the peers written directly into their config until re-exported"
        );
    }
    tracing::info!(event = "node_revoked", node_name = %name);
    Ok(())
}

/// `DELETE /admin/nodes/{name}` (security review F8 — not in the spec's
/// route list, added so an orphaned or mistyped node record can be
/// removed and its name freed). Refuses with `409` while the node is
/// still active (registered and not revoked): an active node must be
/// revoked first, so that removing a live member of the mesh is always a
/// deliberate two-step action rather than a single slip.
pub async fn delete_node(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
) -> Result<(), AppError> {
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;
    if node.pubkey.is_some() && !node.revoked {
        return Err(AppError::Conflict(
            "node is still active — revoke it first, then delete".into(),
        ));
    }
    // PLAN.md M24. The FK would set `gateway_node_id` back to NULL on its
    // own, so nothing dangles — but the devices routing through this node
    // would silently lose every path they do not hold a direct `[Peer]` for,
    // and nothing would say so. Refusing is the same shape as the guard just
    // above, and deleting a node is never the urgent operation: `revoke`
    // already cut it off.
    let dependents = nodes::static_nodes_using_gateway(&conn, node.id)?;
    if !dependents.is_empty() {
        return Err(AppError::Conflict(format!(
            "node is the gateway for {}: re-export {} against another gateway first, \
             or clear the assignment",
            dependents.join(", "),
            if dependents.len() == 1 { "it" } else { "them" },
        )));
    }
    nodes::delete_node(&conn, node.id)?;
    tracing::info!(event = "node_deleted", node_name = %name);
    Ok(())
}

/// `DELETE /admin/nodes/{name}/endpoint`.
///
/// Clears a stale advertised endpoint. Not in the spec's route list —
/// added because `/poll`'s `COALESCE` means a node can set an
/// `endpoint_addr` but never unset one, so a node that loses its port
/// forward keeps advertising an address no peer can reach. See
/// `nodes::clear_endpoint` for why the COALESCE stays.
///
/// Unlike `revoke`, this is not a security action and needs no
/// two-step guard: it removes a routing hint, nothing more, and the
/// worst case is one poll interval of peers falling back on
/// WireGuard's own roaming correction.
pub async fn clear_node_endpoint(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
) -> Result<(), AppError> {
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;
    nodes::clear_endpoint(&conn, node.id, None)?;
    tracing::info!(event = "node_endpoint_cleared", node_name = %name);
    Ok(())
}

/// `DELETE /admin/nodes/{name}/endpoint/{family}` (`family` = `v4`|`v6`).
///
/// The family-scoped sibling of [`clear_node_endpoint`], for when only
/// one of a node's two actively-probed candidates has gone stale (the
/// node lost its IPv6 route but its IPv4 one is still fine, say) —
/// clearing both via the unqualified route would be needlessly
/// destructive to the family that's still working.
pub async fn clear_node_endpoint_family(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path((name, family_str)): Path<(String, String)>,
) -> Result<(), AppError> {
    let family = match family_str.as_str() {
        "v4" => nodes::EndpointFamily::V4,
        "v6" => nodes::EndpointFamily::V6,
        _ => return Err(AppError::BadRequest("family must be v4 or v6".into())),
    };
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;
    nodes::clear_endpoint(&conn, node.id, Some(family))?;
    tracing::info!(event = "node_endpoint_cleared", node_name = %name, family = %family_str);
    Ok(())
}

/// `POST /admin/nodes/{name}/rejoin` (spec §4.5).
///
/// Also cuts off the node's current identity immediately — its bearer
/// token (security review S8) and its WireGuard pubkey (finding #2), see
/// `nodes::reissue_join_token`. Spec §4.5 explicitly covers calling this
/// on a node whose key is "suspected compromised" while the node itself
/// isn't yet revoked; leaving either credential live until a new
/// `/register` completes would mean the compromised one keeps working for
/// the entire window between "we suspect this" and "the physical
/// operator gets around to re-registering it," which defeats the point of
/// having this path at all. `revoked` itself still only clears back to
/// `0` on a *successful* subsequent `/register` (unchanged).
pub async fn rejoin_node(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
    // Optional body: a rejoin has never needed one, and an admin CLI
    // built before `--ttl` existed sends none at all. `Option<Json<_>>`
    // keeps that request working rather than turning a missing
    // Content-Type into a 400 on a route that used to accept it.
    body: Option<Json<RejoinRequest>>,
) -> Result<(StatusCode, Json<RejoinResponse>), AppError> {
    let body = body.map(|Json(b)| b);
    let ttl = body
        .as_ref()
        .and_then(|b| b.ttl_secs)
        .unwrap_or(state.config.join_token_ttl_secs);
    let expected_kind = body.as_ref().and_then(|b| b.kind);
    let expires_at = nodes::join_token_expiry(ttl);

    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;

    // PLAN.md M24: checked here, before `reissue_join_token`, and not at
    // `/register` where every other `kind` mismatch surfaces. A rejoin nulls
    // the pubkey, and `list_all_peers` filters on `pubkey IS NOT NULL`, so by
    // the time a mismatch reached registration this node would already be off
    // every other node's directory. `export-config --refresh` pointed at an
    // agent node by mistake would kick a live node off the mesh and only then
    // report the error.
    if let Some(expected) = expected_kind {
        if expected != node.kind {
            return Err(AppError::BadRequest(format!(
                "kind mismatch: node '{}' is kind={}, but the request expects kind={}",
                name,
                node.kind.as_str(),
                expected.as_str()
            )));
        }
    }

    let join_token = tokengen::generate(JOIN_TOKEN_PREFIX);
    let hash = wireserve_types::hash_token(&join_token);
    nodes::reissue_join_token(&conn, node.id, &hash, expires_at.as_deref())?;
    // Same as revoke: the old key must not linger as a carrier or as a
    // node wanting transit help until its report goes stale.
    if let Some(pubkey) = &node.pubkey {
        state.transit.forget(pubkey);
    }

    tracing::info!(event = "node_rejoined", node_name = %name, join_token_ttl_secs = ttl);

    Ok((
        StatusCode::CREATED,
        Json(RejoinResponse {
            name,
            join_token,
            join_token_expires_at: parse_expiry(expires_at.as_deref()),
        }),
    ))
}

/// `GET /admin/services` — every declared service in every approval
/// state.
///
/// The admin has no other view of the service directory: `/admin/peers`
/// lists nodes only, and the directory is otherwise visible solely to
/// nodes via `/poll`.
pub async fn list_services(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<AdminServicesResponse>, AppError> {
    let conn = state.db.conn.lock().await;
    let rows = services::list_all_for_admin(&conn)?;
    let owners: std::collections::HashMap<i64, nodes::NodeRow> = nodes::list_all_peers(&conn)?
        .into_iter()
        .map(|n| (n.id, n))
        .collect();
    let out = rows
        .iter()
        .filter_map(|s| {
            owners
                .get(&s.node_id)
                .map(|owner| crate::directory::admin_service_info(s, owner))
        })
        .collect();
    Ok(Json(AdminServicesResponse { services: out }))
}

/// Shared shape for the two approval endpoints: validate the service
/// label, resolve the node, then act. Kept together so approve and deny
/// cannot drift on validation or on what a missing node means.
async fn resolve_node_for_service(
    state: &AppState,
    node_name: &str,
    service: &str,
) -> Result<i64, AppError> {
    if !wireserve_types::is_valid_dns_label(service) {
        return Err(AppError::BadRequest(format!(
            "invalid service name: {service}"
        )));
    }
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, node_name)?.ok_or(AppError::NotFound)?;
    Ok(node.id)
}

/// `POST /admin/nodes/{name}/services/{service}/approve`.
///
/// **The node name is in the path on purpose.** There is deliberately no
/// `/admin/services/{name}/approve` form at any layer of this codebase
/// that would approve "whoever currently holds this name" — approval
/// binds to the pair, so an operator acting on a stale view of the
/// directory gets a 409 naming the real owner instead of silently
/// blessing a squatter's claim.
pub async fn approve_service(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path((name, service)): Path<(String, String)>,
) -> Result<(), AppError> {
    let node_id = resolve_node_for_service(&state, &name, &service).await?;
    let conn = state.db.conn.lock().await;
    match services::approve(&conn, node_id, &service)? {
        services::ApproveOutcome::Approved => {
            tracing::info!(event = "service_approved", node_name = %name, service = %service);
            Ok(())
        }
        services::ApproveOutcome::AlreadyApproved => Ok(()),
        services::ApproveOutcome::OwnedByAnotherNode { owner_node_id } => {
            let owner = nodes::find_by_id(&conn, owner_node_id)?
                .map_or_else(|| "another node".to_string(), |n| n.name);
            Err(AppError::Conflict(format!(
                "service '{service}' is declared by node '{owner}', not '{name}' — \
                 approval binds to the declaring node"
            )))
        }
        services::ApproveOutcome::NotDeclared => Err(AppError::NotFound),
    }
}

/// `POST /admin/nodes/{name}/services/{service}/deny`.
pub async fn deny_service(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path((name, service)): Path<(String, String)>,
    body: Option<Json<DenyServiceRequest>>,
) -> Result<(), AppError> {
    let reason = body.and_then(|Json(b)| b.reason);
    if let Some(r) = &reason {
        if r.len() > MAX_DENY_REASON_LEN {
            return Err(AppError::BadRequest(format!(
                "denial reason is {} bytes; the limit is {MAX_DENY_REASON_LEN}",
                r.len()
            )));
        }
    }
    let node_id = resolve_node_for_service(&state, &name, &service).await?;
    let conn = state.db.conn.lock().await;
    match services::deny(&conn, node_id, &service, reason.as_deref())? {
        services::DenyOutcome::Denied => {
            // `?` (Debug), not `%` (Display): this is operator-supplied
            // free text entering an audit log, and Debug for &str quotes
            // and escapes control characters, so a reason containing
            // newlines or ANSI escapes cannot forge extra log lines.
            // PLAN.md #51 records this project already being bitten by
            // ANSI escapes in tracing output.
            tracing::info!(
                event = "service_denied",
                node_name = %name,
                service = %service,
                reason = ?reason,
            );
            Ok(())
        }
        services::DenyOutcome::AlreadyDenied => Ok(()),
        services::DenyOutcome::OwnedByAnotherNode { owner_node_id } => {
            let owner = nodes::find_by_id(&conn, owner_node_id)?
                .map_or_else(|| "another node".to_string(), |n| n.name);
            Err(AppError::Conflict(format!(
                "service '{service}' is declared by node '{owner}', not '{name}'"
            )))
        }
        services::DenyOutcome::NotDeclared => Err(AppError::NotFound),
    }
}

/// `PUT /admin/nodes/{name}/gateway` (PLAN.md M24).
///
/// Records the shape of a static peer's exported `.conf`: which node it
/// routes through, and which peers it holds direct `[Peer]` blocks for.
/// `/poll` derives `transit_via` from exactly this, so the two can never
/// disagree about a device's routing.
pub async fn set_gateway(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
    Json(body): Json<wireserve_types::SetGatewayRequest>,
) -> Result<(), AppError> {
    let mut conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;
    if node.kind != wireserve_types::NodeKind::Static {
        return Err(AppError::BadRequest(
            "only a kind=static node routes through a gateway; an agent reaches peers itself"
                .into(),
        ));
    }

    let gateway_id = match &body.gateway {
        None => None,
        Some(gateway_name) => {
            let gw = nodes::find_by_name(&conn, gateway_name)?.ok_or_else(|| {
                AppError::BadRequest(format!("no such node '{gateway_name}' to use as a gateway"))
            })?;
            if gw.id == node.id {
                return Err(AppError::BadRequest(
                    "a node cannot be its own gateway".into(),
                ));
            }
            if gw.kind != wireserve_types::NodeKind::Agent {
                return Err(AppError::BadRequest(format!(
                    "'{gateway_name}' is kind=static and never polls, so it cannot forward for anyone"
                )));
            }
            // Gateway forwarding is transit forwarding: the carrier sees the
            // traffic in the clear and can send as either end. It is gated on
            // the same approval rather than a second one of its own.
            if !gw.transit_approved {
                return Err(AppError::Conflict(format!(
                    "'{gateway_name}' is not approved to carry traffic — run \
                     `wireserve-admin approve-transit {gateway_name}` first"
                )));
            }
            // Approval alone is not enough to make forwarding actually work.
            // The agent opens the *host* firewall's FORWARD hook from its own
            // `transit_capable`, captured once when the daemon starts — so a
            // node approved here but never switched on there would accept the
            // forward in its own nftables table while ufw or firewalld still
            // dropped it. That failure is invisible from every other node, so
            // it is worth refusing up front rather than baking a dead gateway
            // into a config that cannot be changed without re-exporting.
            let offering = gw
                .pubkey
                .as_deref()
                .is_some_and(|pk| state.transit.is_offering(pk, state.config.online_threshold_secs));
            if !offering {
                return Err(AppError::Conflict(format!(
                    "'{gateway_name}' is approved but is not currently offering to carry \
                     traffic — run `wireserve-agent transit on` on it (and restart it, so it \
                     reopens the host firewall's forward hook), then try again"
                )));
            }
            Some(gw.id)
        }
    };

    let mut conf_peer_ids = Vec::with_capacity(body.conf_peers.len());
    for peer_name in &body.conf_peers {
        let peer = nodes::find_by_name(&conn, peer_name)?.ok_or_else(|| {
            AppError::BadRequest(format!("no such node '{peer_name}' in the config's peer list"))
        })?;
        conf_peer_ids.push(peer.id);
    }

    nodes::set_gateway(&mut conn, node.id, gateway_id, &conf_peer_ids)?;
    tracing::info!(
        event = "gateway_set",
        node_name = %name,
        gateway = body.gateway.as_deref().unwrap_or("-"),
        direct_peers = conf_peer_ids.len(),
    );
    Ok(())
}

/// `POST /admin/nodes/{name}/transit/approve`.
///
/// Lets a node carry transit traffic for other peers, from its next poll
/// on, provided it has also opted in itself (`wireserve-agent transit
/// on`). Both halves are required: the node's own opt-in is its
/// operator's consent to spend the bandwidth, this is the mesh admin's
/// trust in it — a carrier sees relayed traffic in the clear and can
/// send packets as either end (security review finding #1).
///
/// Granted to the node's current identity: revoke and rejoin both
/// withdraw it.
pub async fn approve_transit(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
) -> Result<(), AppError> {
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;
    if node.kind == wireserve_types::NodeKind::Static {
        return Err(AppError::BadRequest(
            "a kind=static node never polls, so it can never carry transit".into(),
        ));
    }
    if node.revoked {
        return Err(AppError::Conflict(
            "node is revoked — rejoin and re-register it before approving it".into(),
        ));
    }
    nodes::set_transit_approved(&conn, node.id, true)?;
    tracing::info!(event = "transit_approved", node_name = %name);
    Ok(())
}

/// `POST /admin/nodes/{name}/transit/deny` — withdraws transit approval.
/// Effective immediately for carrier selection, not at the node's next
/// poll: pairs it was carrying get a new carrier (or none) on their own
/// next polls.
pub async fn deny_transit(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
) -> Result<(), AppError> {
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;
    let dependents = nodes::static_nodes_using_gateway(&conn, node.id)?;
    if !dependents.is_empty() {
        tracing::warn!(
            event = "gateway_approval_withdrawn_with_dependents",
            node_name = %name,
            dependents = %dependents.join(","),
            "node was the gateway for these devices; withdrawing approval also stops \
             it forwarding for them from their next poll"
        );
    }
    nodes::set_transit_approved(&conn, node.id, false)?;
    if let Some(pubkey) = &node.pubkey {
        state.transit.withdraw_carrier(pubkey);
    }
    tracing::info!(event = "transit_denied", node_name = %name);
    Ok(())
}

/// `PUT /admin/nodes/{name}/via-gateway` (PLAN.md #134).
///
/// Marks a node as not dialable from outside the mesh, or clears that. Read
/// by `export-config` only: a device exported with a gateway then reaches the
/// node through the gateway instead of holding a direct `[Peer]` for it. No
/// agent, and nothing in `/poll`, reads it — the routing follows from the
/// conf membership the export records, exactly as for a node with no public
/// endpoint at all.
///
/// Nothing already on a device changes: the response names the devices whose
/// config the next refresh would change.
pub async fn set_via_gateway(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
    Json(body): Json<wireserve_types::SetViaGatewayRequest>,
) -> Result<Json<wireserve_types::SetViaGatewayResponse>, AppError> {
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;
    if node.kind == wireserve_types::NodeKind::Static {
        return Err(AppError::BadRequest(
            "a kind=static node has no endpoint and is never dialled by another device".into(),
        ));
    }
    nodes::set_export_via_gateway(&conn, node.id, body.enabled)?;
    let mut affected = nodes::static_nodes_affected_by_via_gateway(&conn, node.id, body.enabled)?;
    if body.enabled {
        // A device dials its gateway by the one `Endpoint =` line it has, so a
        // gateway nobody can dial is already broken for those devices. The
        // flag is still the truth about the node, so it is recorded — and
        // those devices are named, since they need another gateway.
        let dependents = nodes::static_nodes_using_gateway(&conn, node.id)?;
        if !dependents.is_empty() {
            tracing::warn!(
                event = "via_gateway_set_on_a_gateway",
                node_name = %name,
                dependents = %dependents.join(","),
                "node is the gateway for these devices, which must dial it directly; \
                 re-export them with another gateway"
            );
        }
        affected.extend(dependents);
        affected.sort();
        affected.dedup();
    }
    tracing::info!(event = "via_gateway_set", node_name = %name, enabled = body.enabled);
    Ok(Json(wireserve_types::SetViaGatewayResponse { affected_devices: affected }))
}

/// `GET /admin/peers` (spec §4.5.1).
///
/// Every entry's `transit_via` (PLAN.md M23) is always `None` here —
/// deliberately, not an oversight: it's requester-relative ("how THIS
/// polling node should reach this peer"), and an admin browsing the
/// directory isn't a requester polling on behalf of a specific node, so
/// there is no requester to compute it relative to. `POST /poll` fills it
/// in for real; see `routes::poll::poll`.
pub async fn list_peers(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<AdminPeersResponse>, AppError> {
    let conn = state.db.conn.lock().await;
    let rows = nodes::list_all_peers(&conn)?;
    let peers = rows
        .iter()
        .map(|n| crate::directory::peer_info(n, state.config.online_threshold_secs))
        .collect();
    let transit_approved = rows
        .iter()
        .filter(|n| n.transit_approved)
        .map(|n| n.name.clone())
        .collect();
    let transit_offering = rows
        .iter()
        .filter(|n| {
            n.pubkey
                .as_deref()
                .is_some_and(|pk| state.transit.is_offering(pk, state.config.online_threshold_secs))
        })
        .map(|n| n.name.clone())
        .collect();
    let via_gateway = rows
        .iter()
        .filter(|n| n.export_via_gateway)
        .map(|n| n.name.clone())
        .collect();
    Ok(Json(AdminPeersResponse { peers, transit_approved, transit_offering, via_gateway }))
}
