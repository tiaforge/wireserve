use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use wireserve_types::{
    AdminPeersResponse, AdminServicesResponse, CreateNodeRequest, CreateNodeResponse,
    DenyServiceRequest, RejoinRequest, RejoinResponse, JOIN_TOKEN_PREFIX, MAX_DENY_REASON_LEN,
};

use crate::auth::AdminAuth;
use crate::db::{grants, nodes, services};
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
    let node_id = nodes::create_node(&conn, &req.name, req.kind, &hash, expires_at.as_deref())?;
    // Whoever will own it can claim it right away (PLAN.md M38).
    let claim = match (&state.oidc, state.config.public_url.as_deref()) {
        (Some(_), Some(public)) => {
            let (url, expires_at) = crate::oidc::claim::new_link(&conn, public, node_id)?;
            Some(wireserve_types::ClaimLink { url, expires_at })
        }
        _ => None,
    };

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
            claim,
        }),
    ))
}

/// `POST /admin/nodes/{name}/claim` (PLAN.md M38): a single-use link,
/// good for ten minutes, that makes whoever signs in with it the node's
/// owner. Only an admin makes one: a node handing its own around could
/// collect other people's groups.
pub async fn claim_link(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
) -> Result<Json<wireserve_types::ClaimLink>, AppError> {
    check_label("node", &name)?;
    let (Some(_), Some(public)) = (&state.oidc, state.config.public_url.as_deref()) else {
        return Err(AppError::Conflict(
            "device owners need an identity provider: set WIRESERVE_OIDC_ISSUER, _CLIENT_ID, _CLIENT_SECRET and \
             WIRESERVE_PUBLIC_URL"
                .into(),
        ));
    };
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or_else(|| AppError::NoSuch(format!("no node {name}")))?;
    if node.revoked {
        return Err(AppError::Conflict(format!("{name} is revoked")));
    }
    let (url, expires_at) = crate::oidc::claim::new_link(&conn, public, node.id)?;
    tracing::info!(event = "claim_link_created", node_name = %name);
    Ok(Json(wireserve_types::ClaimLink { url, expires_at }))
}

/// `DELETE /admin/nodes/{name}/owner` (PLAN.md M38): the node belongs to
/// nobody again, and its outstanding claim links stop working.
pub async fn remove_owner(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
) -> Result<(), AppError> {
    check_label("node", &name)?;
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or_else(|| AppError::NoSuch(format!("no node {name}")))?;
    let had = crate::db::owners::of(&conn, node.id)?.is_some();
    crate::db::owners::forget(&conn, node.id)?;
    if !had {
        return Err(AppError::NoSuch(format!("{name} has no owner")));
    }
    tracing::info!(event = "owner_removed", node_name = %name);
    Ok(())
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
    // Nor its word that it serves anything with TLS (PLAN.md M33).
    crate::db::tls::clear_node(&conn, node.id)?;
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
    state.poke_dns();
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
    state.poke_dns();
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
    crate::db::tls::clear_node(&conn, node.id)?;
    // Same as revoke: the old key must not linger as a carrier or as a
    // node wanting transit help until its report goes stale.
    if let Some(pubkey) = &node.pubkey {
        state.transit.forget(pubkey);
    }

    tracing::info!(event = "node_rejoined", node_name = %name, join_token_ttl_secs = ttl);
    state.poke_dns();

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
    let members = crate::db::grants::members(&conn)?;
    let owners: std::collections::HashMap<i64, nodes::NodeRow> = nodes::list_all_peers(&conn)?
        .into_iter()
        .map(|n| (n.id, n))
        .collect();
    let out = rows
        .iter()
        .filter_map(|s| {
            owners
                .get(&s.node_id)
                .map(|owner| {
                    let groups = crate::db::grants::effective_groups(&members, &s.name).into_iter().collect();
                    let mut info = crate::directory::admin_service_info(s, owner, groups);
                    if s.is_approved() {
                        info.dns = state.dns.as_ref().and_then(|d| d.state_of(&s.name));
                    }
                    info
                })
        })
        .collect();
    Ok(Json(AdminServicesResponse { services: out }))
}

fn check_label(what: &str, name: &str) -> Result<(), AppError> {
    if wireserve_types::is_valid_dns_label(name) {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!("invalid {what} name: {name}")))
    }
}

/// `GET /admin/groups` (PLAN.md M36): every service group, what is in it
/// and who it is granted to.
pub async fn list_groups(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<wireserve_types::GroupsResponse>, AppError> {
    let conn = state.db.conn.lock().await;
    let rules = crate::access::read_rules(&conn)?;
    let declared: Vec<String> = services::list_all_for_admin(&conn)?.into_iter().map(|s| s.name).collect();
    let groups = grants::list_groups(&conn)?
        .into_iter()
        .map(|name| {
            let services: Vec<String> = if name == wireserve_types::DEFAULT_GROUP {
                let mut in_default: std::collections::BTreeSet<String> = declared
                    .iter()
                    .filter(|s| !rules.members.contains_key(*s))
                    .cloned()
                    .collect();
                in_default.extend(rules.members.iter().filter(|(_, g)| g.contains(&name)).map(|(s, _)| s.clone()));
                in_default.into_iter().collect()
            } else {
                rules.members.iter().filter(|(_, g)| g.contains(&name)).map(|(s, _)| s.clone()).collect()
            };
            let granted_to = rules.grants.iter().filter(|g| g.group == name).map(|g| g.source.clone()).collect();
            wireserve_types::GroupInfo { name, services, granted_to }
        })
        .collect();
    Ok(Json(wireserve_types::GroupsResponse { groups }))
}

/// `POST /admin/groups`: a new, empty service group. Creating one that
/// exists is not an error.
pub async fn create_group(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<wireserve_types::CreateGroupRequest>,
) -> Result<StatusCode, AppError> {
    check_label("group", &body.name)?;
    let conn = state.db.conn.lock().await;
    if grants::create_group(&conn, &body.name)? {
        tracing::info!(event = "service_group_created", group = %body.name);
        Ok(StatusCode::CREATED)
    } else {
        Ok(StatusCode::OK)
    }
}

/// `DELETE /admin/groups/{group}`. Refused for `default`, and while any
/// service, grant or pending declaration uses the group: deleting it would
/// drop its services back into `default`, which everyone may reach.
pub async fn delete_group(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(group): Path<String>,
) -> Result<(), AppError> {
    check_label("group", &group)?;
    let conn = state.db.conn.lock().await;
    match grants::delete_group(&conn, &group)? {
        grants::DeleteGroupOutcome::Deleted => {
            tracing::info!(event = "service_group_deleted", group = %group);
            Ok(())
        }
        grants::DeleteGroupOutcome::NotFound => Err(AppError::NoSuch(format!("no group {group}"))),
        grants::DeleteGroupOutcome::Builtin => {
            Err(AppError::BadRequest("default is where every service without a group is; it stays".into()))
        }
        grants::DeleteGroupOutcome::InUse { services, grants, declared_by } => {
            let mut why = Vec::new();
            if !services.is_empty() {
                why.push(format!("it holds {} (they would fall back into default)", services.join(", ")));
            }
            if grants > 0 {
                why.push(format!("{grants} grant(s) name it"));
            }
            if !declared_by.is_empty() {
                why.push(format!("{} declared it and wait(s) for approval", declared_by.join(", ")));
            }
            Err(AppError::Conflict(format!("group {group} is in use: {}", why.join("; "))))
        }
    }
}

/// `PUT /admin/groups/{group}/services/{service}`: puts a service name in a
/// group, declared or not — which takes it out of `default`.
pub async fn add_group_member(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path((group, service)): Path<(String, String)>,
) -> Result<Json<wireserve_types::MembershipResponse>, AppError> {
    check_label("group", &group)?;
    check_label("service", &service)?;
    if state.config.sign_in.as_ref().is_some_and(|si| si.service == service) {
        return Err(AppError::BadRequest(format!(
            "{service} is the sign-in: every terminator and every browser signing in must reach it, so it stays open"
        )));
    }
    let conn = state.db.conn.lock().await;
    match grants::add_member(&conn, &group, &service)? {
        grants::AddMemberOutcome::NoSuchGroup => return Err(AppError::NoSuch(format!("no group {group}"))),
        grants::AddMemberOutcome::Added => {
            tracing::info!(event = "service_group_member_added", group = %group, service = %service);
        }
        grants::AddMemberOutcome::AlreadyMember => {}
    }
    membership(&conn, service)
}

/// `DELETE /admin/groups/{group}/services/{service}`. Removing its last
/// group puts the service back in `default`; the answer says so by listing
/// it.
pub async fn remove_group_member(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path((group, service)): Path<(String, String)>,
) -> Result<Json<wireserve_types::MembershipResponse>, AppError> {
    check_label("group", &group)?;
    check_label("service", &service)?;
    let conn = state.db.conn.lock().await;
    match grants::remove_member(&conn, &group, &service)? {
        grants::RemoveMemberOutcome::NotMember => {
            return Err(AppError::NoSuch(format!("{service} is not in group {group}")));
        }
        grants::RemoveMemberOutcome::Removed { now_default } => {
            tracing::info!(event = "service_group_member_removed", group = %group, service = %service, now_default);
        }
    }
    membership(&conn, service)
}

fn membership(
    conn: &rusqlite::Connection,
    service: String,
) -> Result<Json<wireserve_types::MembershipResponse>, AppError> {
    let groups = grants::effective_groups(&grants::members(conn)?, &service).into_iter().collect();
    Ok(Json(wireserve_types::MembershipResponse { service, groups }))
}

/// `GET /admin/grants`.
pub async fn list_grants(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<wireserve_types::GrantsResponse>, AppError> {
    let conn = state.db.conn.lock().await;
    let grants = grants::list_grants(&conn)?
        .into_iter()
        .map(|g| wireserve_types::GrantInfo { source: g.source, group: g.group })
        .collect();
    Ok(Json(wireserve_types::GrantsResponse { grants }))
}

/// `POST /admin/grants`: lets a source reach every service in a group.
pub async fn add_grant(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<wireserve_types::GrantInfo>,
) -> Result<StatusCode, AppError> {
    check_label("group", &body.group)?;
    let conn = state.db.conn.lock().await;
    match grants::add_grant(&conn, &body.source, &body.group)? {
        grants::AddGrantOutcome::NoSuchGroup => Err(AppError::NoSuch(format!("no group {}", body.group))),
        grants::AddGrantOutcome::Added => {
            tracing::info!(event = "grant_added", source = %body.source, group = %body.group);
            Ok(StatusCode::CREATED)
        }
        grants::AddGrantOutcome::AlreadyGranted => Ok(StatusCode::OK),
    }
}

/// `DELETE /admin/grants`, with the grant in the body.
pub async fn remove_grant(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<wireserve_types::GrantInfo>,
) -> Result<(), AppError> {
    check_label("group", &body.group)?;
    let conn = state.db.conn.lock().await;
    if !grants::remove_grant(&conn, &body.source, &body.group)? {
        return Err(AppError::NoSuch(format!("{} is not granted {}", body.source, body.group)));
    }
    tracing::info!(event = "grant_removed", source = %body.source, group = %body.group);
    Ok(())
}

/// `PUT /admin/nodes/{name}/tags/{tag}`: tags are admin-only, since a tag
/// grants access — a node never tags itself.
pub async fn add_tag(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path((name, tag)): Path<(String, String)>,
) -> Result<StatusCode, AppError> {
    check_label("node", &name)?;
    check_label("tag", &tag)?;
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or_else(|| AppError::NoSuch(format!("no node {name}")))?;
    if grants::add_tag(&conn, node.id, &tag)? {
        tracing::info!(event = "node_tag_added", node_name = %name, tag = %tag);
        Ok(StatusCode::CREATED)
    } else {
        Ok(StatusCode::OK)
    }
}

/// `DELETE /admin/nodes/{name}/tags/{tag}`.
pub async fn remove_tag(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path((name, tag)): Path<(String, String)>,
) -> Result<(), AppError> {
    check_label("node", &name)?;
    check_label("tag", &tag)?;
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or_else(|| AppError::NoSuch(format!("no node {name}")))?;
    if !grants::remove_tag(&conn, node.id, &tag)? {
        return Err(AppError::NoSuch(format!("{name} has no tag {tag}")));
    }
    tracing::info!(event = "node_tag_removed", node_name = %name, tag = %tag);
    Ok(())
}

fn default_closed(rules: &crate::access::Rules) -> bool {
    !rules
        .grants
        .iter()
        .any(|g| g.source == wireserve_types::GrantSource::Everyone && g.group == wireserve_types::DEFAULT_GROUP)
}

/// `GET /admin/access/services/{name}`: who reaches a service and why —
/// computed by the same function `/poll` hands its owner.
pub async fn service_access_report(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
) -> Result<Json<wireserve_types::ServiceAccessReport>, AppError> {
    check_label("service", &name)?;
    let conn = state.db.conn.lock().await;
    let rules = crate::access::read_rules(&conn)?;
    let peers = nodes::list_all_peers(&conn)?;
    let row = services::find_by_name(&conn, &name)?;
    let owner = row.as_ref().and_then(|r| peers.iter().find(|n| n.id == r.node_id));
    let tls_ready = crate::db::tls::ready(&conn)?;
    let ctx = state.directory_context(&tls_ready);
    let granted = rules.granted(&name);
    let (open, sign_in, sign_in_groups) = match (&row, owner) {
        (Some(row), Some(owner)) => {
            let owner_capable = owner.pubkey.as_deref().is_some_and(|pk| {
                state.transit.has_capability(pk, wireserve_types::CAP_SIGN_IN, state.config.online_threshold_secs)
            });
            let facts = crate::access::SignInFacts {
                provider: state.config.sign_in.as_ref().map(|si| (si.service.as_str(), si.node.as_str())),
                owner_capable,
                terminated: ctx.terminates(row),
            };
            let a = crate::access::service_access(row, owner, &peers, &rules, &facts);
            (a.open, a.sign_in, a.sign_in_groups)
        }
        _ => (granted.contains(&wireserve_types::GrantSource::Everyone), false, Vec::new()),
    };
    let nodes = if open {
        Vec::new()
    } else {
        peers
            .iter()
            .filter_map(|n| {
                let via: Vec<_> = rules.matching(n.id, &name).into_iter().collect();
                (!via.is_empty()).then(|| wireserve_types::AccessVia { name: n.name.clone(), via })
            })
            .collect()
    };
    Ok(Json(wireserve_types::ServiceAccessReport {
        service: name.clone(),
        node: owner.map(|o| o.name.clone()),
        groups: rules.groups_of(&name).into_iter().collect(),
        granted_to: granted.into_iter().collect(),
        open,
        nodes,
        sign_in,
        sign_in_groups,
        default_closed: default_closed(&rules),
    }))
}

/// `GET /admin/access/nodes/{name}`: what a node reaches by who it is.
pub async fn node_access_report(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
) -> Result<Json<wireserve_types::NodeAccessReport>, AppError> {
    check_label("node", &name)?;
    let conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or_else(|| AppError::NoSuch(format!("no node {name}")))?;
    let rules = crate::access::read_rules(&conn)?;
    let services = services::list_approved(&conn)?
        .into_iter()
        .filter(|s| s.node_id != node.id)
        .filter_map(|s| {
            let via: Vec<_> = rules.matching(node.id, &s.name).into_iter().collect();
            (!via.is_empty()).then_some(wireserve_types::AccessVia { name: s.name, via })
        })
        .collect();
    let owner = crate::db::owners::of(&conn, node.id)?.map(|o| wireserve_types::OwnerInfo {
        stale: !o.groups_count(chrono::Utc::now()),
        sub: o.sub,
        email: o.email,
        name: o.name,
        groups: o.groups,
    });
    Ok(Json(wireserve_types::NodeAccessReport {
        node: name,
        owner,
        principals: rules.principals(node.id).into_iter().collect(),
        services,
        default_closed: default_closed(&rules),
    }))
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
    match services::approve(&conn, node_id, &service, &state.config.net_v4_cidr)? {
        services::ApproveOutcome::Approved => {
            tracing::info!(event = "service_approved", node_name = %name, service = %service);
            state.poke_dns();
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
            state.poke_dns();
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
                     traffic — run `wireserve transit on` on it (and restart it, so it \
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

    // The device's half of the exit consent is this export; the gateway's
    // half is its own `exit on`, checked here as well as by the CLI so an
    // older CLI or a hand-made request cannot record a profile nothing
    // forwards (PLAN.md M27).
    if body.exit {
        let Some(gateway_name) = &body.gateway else {
            return Err(AppError::BadRequest(
                "a full-tunnel profile routes through the device's gateway; name one".into(),
            ));
        };
        let gw = nodes::find_by_name(&conn, gateway_name)?.ok_or(AppError::NotFound)?;
        let offering = gw
            .pubkey
            .as_deref()
            .is_some_and(|pk| state.transit.is_offering_exit(pk, state.config.online_threshold_secs));
        if !offering {
            return Err(AppError::Conflict(format!(
                "'{gateway_name}' is not offering to be an exit — run `wireserve exit on` \
                 on it, then try again"
            )));
        }
    }

    nodes::set_gateway(&mut conn, node.id, gateway_id, &conf_peer_ids, body.exit)?;
    tracing::info!(
        event = "gateway_set",
        node_name = %name,
        gateway = body.gateway.as_deref().unwrap_or("-"),
        direct_peers = conf_peer_ids.len(),
        exit = body.exit,
    );
    Ok(())
}

/// `POST /admin/nodes/{name}/transit/approve`.
///
/// Lets a node carry transit traffic for other peers, from its next poll
/// on, provided it has also opted in itself (`wireserve transit
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
        .map(|n| crate::directory::peer_info(n, state.config.online_threshold_secs, state.config.relay_port_base))
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
    let exit_offering = rows
        .iter()
        .filter(|n| {
            n.pubkey
                .as_deref()
                .is_some_and(|pk| state.transit.is_offering_exit(pk, state.config.online_threshold_secs))
        })
        .map(|n| n.name.clone())
        .collect();
    let exit_devices = rows
        .iter()
        .filter(|n| n.exit_enabled && n.gateway_node_id.is_some())
        .map(|n| n.name.clone())
        .collect();
    let tags_by_id = grants::tags(&conn)?;
    let tags = rows
        .iter()
        .filter_map(|n| Some((n.name.clone(), tags_by_id.get(&n.id)?.iter().cloned().collect())))
        .collect();
    Ok(Json(AdminPeersResponse {
        peers,
        transit_approved,
        transit_offering,
        via_gateway,
        exit_offering,
        exit_devices,
        tags,
    }))
}
