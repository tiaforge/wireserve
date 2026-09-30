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
    // Warn, never refuse. Revoking is how a compromised node is cut off, so
    // it must not be blockable by a device depending on it — and it degrades
    // safely: an exit or carrier that is revoked simply stops forwarding.
    let dependents = nodes::static_nodes_depending_on(&conn, node.id)?;
    if !dependents.is_empty() {
        tracing::warn!(
            event = "revoked_with_dependents",
            node_name = %name,
            dependents = %dependents.join(","),
            "revoked node was the exit or a carrier for these devices; re-export them"
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
    // The foreign keys would clear the references on their own, so nothing
    // dangles — but the devices that use this node as their exit or carrier
    // would silently lose that, and nothing would say so. Deleting is never
    // the urgent operation: `revoke` already cut the node off.
    let dependents = nodes::static_nodes_depending_on(&conn, node.id)?;
    if !dependents.is_empty() {
        return Err(AppError::Conflict(format!(
            "node is the exit or a carrier for {}: re-export {} first",
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

/// `PUT /admin/nodes/{name}/export` (PLAN.md M40, M41).
///
/// Records the shape of a static peer's exported `.conf`: its exit, and the
/// nodes it reaches through which carrier. The exit then sends on exactly
/// this device's traffic, and each carrier forwards exactly these relays.
pub async fn record_export(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Path(name): Path<String>,
    Json(body): Json<wireserve_types::ExportRecord>,
) -> Result<(), AppError> {
    let mut conn = state.db.conn.lock().await;
    let node = nodes::find_by_name(&conn, &name)?.ok_or(AppError::NotFound)?;
    if node.kind != wireserve_types::NodeKind::Static {
        return Err(AppError::BadRequest("only a kind=static node has an exported config".into()));
    }
    let fresh = state.config.online_threshold_secs;
    let agent = |conn: &rusqlite::Connection, what: &str, n: &str| -> Result<nodes::NodeRow, AppError> {
        let row = nodes::find_by_name(conn, n)?.ok_or_else(|| AppError::BadRequest(format!("no such node '{n}' ({what})")))?;
        if row.kind != wireserve_types::NodeKind::Agent || row.revoked || row.pubkey.is_none() {
            return Err(AppError::BadRequest(format!("'{n}' is not a registered agent, so it cannot be a device's {what}")));
        }
        Ok(row)
    };
    // The device's half of the exit consent is this export; the exit's own
    // half is `exit on`, and the admin's is the transit approval — checked
    // here as well as by the CLI, so a hand-made request cannot record a
    // profile nothing forwards (PLAN.md M27).
    let exit_id = match &body.exit {
        None => None,
        Some(exit_name) => {
            let exit = agent(&conn, "exit", exit_name)?;
            if !exit.transit_approved {
                return Err(AppError::Conflict(format!(
                    "'{exit_name}' is not approved to send others' traffic on — run                      `wireserve-admin approve-transit {exit_name}` first"
                )));
            }
            if !exit.pubkey.as_deref().is_some_and(|pk| state.transit.is_offering_exit(pk, fresh)) {
                return Err(AppError::Conflict(format!(
                    "'{exit_name}' is not offering to be an exit — run `wireserve exit on` on it, then try again"
                )));
            }
            Some(exit.id)
        }
    };
    let mut relays = Vec::with_capacity(body.relays.len());
    for r in &body.relays {
        let peer = agent(&conn, "relayed node", &r.node)?;
        let carrier = agent(&conn, "carrier", &r.carrier)?;
        if !carrier.transit_approved {
            return Err(AppError::Conflict(format!(
                "'{}' is not approved to carry traffic — run `wireserve-admin approve-transit {}` first",
                r.carrier, r.carrier
            )));
        }
        if carrier.id == peer.id {
            return Err(AppError::BadRequest(format!("'{}' cannot relay to itself", r.node)));
        }
        relays.push((peer.id, carrier.id));
    }
    nodes::record_export(&mut conn, node.id, exit_id, &relays)?;
    tracing::info!(
        event = "export_recorded",
        node_name = %name,
        exit = body.exit.as_deref().unwrap_or("-"),
        relays = relays.len(),
    );
    Ok(())
}

/// How long a port found open stays trusted before an export checks it
/// again (PLAN.md M40).
const RELAY_PORT_TRUSTED_DAYS: i64 = 30;
/// How long an export waits for a port check: the carrier has to poll to
/// learn of it, listen, and poll again to report it.
const PORT_CHECK_WAIT: std::time::Duration = std::time::Duration::from_secs(50);

/// A node's public IPv4 `ip`, from its endpoint, if it has a globally
/// routable one — where a device off the mesh can reach it.
fn public_v4(peer: &wireserve_types::PeerInfo) -> Option<std::net::Ipv4Addr> {
    [peer.endpoint_addr_v4.as_deref(), peer.endpoint_addr.as_deref()]
        .into_iter()
        .flatten()
        .filter(|e| wireserve_types::is_globally_routable_endpoint(e))
        .find_map(|e| e.parse::<std::net::SocketAddrV4>().ok().map(|a| *a.ip()))
}

/// Whether `addr` is one of this host's own addresses: binding to it works
/// only then.
fn is_own_address(addr: std::net::Ipv4Addr) -> bool {
    std::net::UdpSocket::bind((addr, 0)).is_ok()
}

/// `POST /admin/relays/plan` (PLAN.md M40): how a device exported now
/// reaches each node, with every relay port it needs checked from outside
/// first (or recently).
///
/// A node that reported itself dialable is dialled directly. Every other
/// one — including one that never said (offline, or an older agent), whose
/// last recorded endpoint is no evidence a phone gets through — gets a
/// carrier: approved, offering, able to relay, itself dialable, with a
/// public IPv4 address. Preferred, in order: one that reaches the node right
/// now (an offline node gets one anyway, which works once it is back), one
/// whose port for that node was already seen open, one already serving
/// devices — so as few ports as possible need opening. A port on the
/// coordinator's own host isn't checked: the check couldn't see a firewall
/// in front of it (`RelayPlanEntry::unverifiable_here`).
pub async fn relay_plan(
    State(state): State<AppState>,
    _admin: AdminAuth,
    Json(body): Json<wireserve_types::RelayPlanRequest>,
) -> Result<Json<wireserve_types::RelayPlan>, AppError> {
    let fresh = state.config.online_threshold_secs;
    let (rows, relays, ports) = {
        let conn = state.db.conn.lock().await;
        (nodes::list_all_peers(&conn)?, nodes::all_static_relays(&conn)?, nodes::relay_ports(&conn)?)
    };
    let infos: Vec<wireserve_types::PeerInfo> =
        rows.iter().map(|n| crate::directory::peer_info(n, fresh, state.config.relay_port_base)).collect();
    let agents: Vec<(&nodes::NodeRow, &wireserve_types::PeerInfo)> = rows
        .iter()
        .zip(&infos)
        .filter(|(n, _)| n.kind == wireserve_types::NodeKind::Agent)
        .collect();
    let carriers: Vec<(&nodes::NodeRow, &wireserve_types::PeerInfo, std::net::Ipv4Addr)> = agents
        .iter()
        .filter(|(n, p)| {
            n.transit_approved
                && state.transit.is_offering(&p.pubkey, fresh)
                && state.transit.has_capability(&p.pubkey, wireserve_types::CAP_RELAY, fresh)
                && state.transit.dialable(&p.pubkey, fresh) == Some(true)
        })
        .filter_map(|(n, p)| Some((*n, *p, public_v4(p)?)))
        .collect();
    let serving: std::collections::HashSet<i64> = relays.iter().map(|(_, _, c)| *c).collect();
    let now = chrono::Utc::now();
    let trusted_open = |carrier: i64, port: u16, address: std::net::Ipv4Addr| {
        ports.iter().any(|r| {
            r.carrier_node_id == carrier
                && r.port == port
                && r.open
                && r.address == address.to_string()
                && r.checked_at.is_some_and(|t| (now - t).num_days() < RELAY_PORT_TRUSTED_DAYS)
        })
    };

    let mut plan = wireserve_types::RelayPlan::default();
    let mut to_check: Vec<(usize, i64, String, u16, std::net::SocketAddrV4)> = Vec::new();
    for (node, peer) in &agents {
        let dialable = state.transit.dialable(&peer.pubkey, fresh);
        // Only a node that said so is dialled directly. One that didn't —
        // offline, or an older agent — would otherwise get whatever endpoint
        // was last recorded for it, often a home NAT's address that a phone
        // can't get through; a relay works for it either way.
        if dialable == Some(true) {
            plan.direct.push(node.name.clone());
            continue;
        }
        let (Some(port), Some(_)) = (peer.relay.port, peer.relay.listen_port) else {
            plan.unreachable.push(wireserve_types::Unreachable {
                node: node.name.clone(),
                reason: "it has no relay port or no known listen port".into(),
            });
            continue;
        };
        // Preferably a carrier that reaches the node right now; a node that is
        // offline gets one anyway, and its relay works once it is back.
        let mut candidates: Vec<&(&nodes::NodeRow, &wireserve_types::PeerInfo, std::net::Ipv4Addr)> =
            carriers.iter().filter(|(c, _, _)| c.id != node.id).collect();
        candidates.sort_by_key(|(c, cp, addr)| {
            (
                !state.transit.reaches(&cp.pubkey, &peer.pubkey, fresh),
                !trusted_open(c.id, port, *addr),
                !serving.contains(&c.id),
                cp.pubkey.clone(),
            )
        });
        let Some((carrier, _, addr)) = candidates.first() else {
            plan.unreachable.push(wireserve_types::Unreachable {
                node: node.name.clone(),
                reason: "it isn't known to be dialable from outside, and no node qualifies as a \
                         carrier (approved, `transit on`, relaying, itself dialable with a public IPv4)"
                    .into(),
            });
            continue;
        };
        let endpoint = format!("{addr}:{port}");
        // A check sent to the coordinator's own address never leaves the
        // machine, so it would read "open" whatever a firewall in front of
        // it does. Such a port isn't checked, and the operator is told.
        if is_own_address(*addr) {
            plan.relayed.push(wireserve_types::RelayPlanEntry {
                node: node.name.clone(),
                carrier: carrier.name.clone(),
                endpoint,
                open: None,
                unverifiable_here: true,
            });
            continue;
        }
        let open = trusted_open(carrier.id, port, *addr).then_some(true);
        if open.is_none() {
            to_check.push((plan.relayed.len(), carrier.id, carrier.pubkey.clone().unwrap_or_default(), port, std::net::SocketAddrV4::new(*addr, port)));
        }
        plan.relayed.push(wireserve_types::RelayPlanEntry {
            node: node.name.clone(),
            carrier: carrier.name.clone(),
            endpoint,
            open,
            unverifiable_here: false,
        });
    }

    // Check every port that needs it, together.
    if !to_check.is_empty() {
        if let Some(socket) = state.probe_udp.clone() {
            let nonces: Vec<[u8; 8]> =
                to_check.iter().map(|(_, _, pk, port, _)| state.transit.start_check(pk, *port)).collect();
            let deadline = tokio::time::Instant::now() + PORT_CHECK_WAIT;
            loop {
                let pending: Vec<usize> = (0..to_check.len())
                    .filter(|i| state.transit.check_state(&to_check[*i].2, to_check[*i].3) != Some(crate::transit::CheckState::Seen))
                    .collect();
                if pending.is_empty() || tokio::time::Instant::now() >= deadline {
                    break;
                }
                for i in &pending {
                    let (_, _, pk, _, target) = &to_check[*i];
                    if state.transit.check_state(pk, target.port()) == Some(crate::transit::CheckState::Listening) {
                        let datagram = wireserve_types::reflexive::build_response(nonces[*i], *target);
                        let _ = socket.send_to(&datagram, target);
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            let conn = state.db.conn.lock().await;
            for (entry, carrier_id, pk, port, target) in &to_check {
                let open = match state.transit.check_state(pk, *port) {
                    Some(crate::transit::CheckState::Seen) => Some(true),
                    Some(crate::transit::CheckState::Listening) => Some(false),
                    _ => None,
                };
                state.transit.finish_check(pk, *port);
                if let Some(open) = open {
                    nodes::record_relay_port(&conn, *carrier_id, *port, &target.ip().to_string(), open)?;
                }
                plan.relayed[*entry].open = open;
            }
        }
    }
    for entry in &plan.relayed {
        if entry.open != Some(true) && !entry.unverifiable_here {
            let port = entry.endpoint.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(0);
            plan.closed.push(wireserve_types::RelayPortStatus {
                carrier: entry.carrier.clone(),
                address: entry.endpoint.rsplit_once(':').map(|(a, _)| a.to_string()),
                port,
                node: Some(entry.node.clone()),
                devices: Vec::new(),
                checked_at: None,
                open: entry.open,
            });
        }
    }
    if !plan.closed.is_empty() && !body.allow_unverified {
        tracing::info!(event = "relay_plan_ports_closed", ports = plan.closed.len());
    }
    Ok(Json(plan))
}

/// `GET /admin/relay-ports` (PLAN.md M40): every public relay port a
/// carrier has had checked or has in use, what it leads to, which devices
/// use it, and whether it was open.
pub async fn relay_ports(
    State(state): State<AppState>,
    _admin: AdminAuth,
) -> Result<Json<wireserve_types::RelayPortsResponse>, AppError> {
    let conn = state.db.conn.lock().await;
    let rows = nodes::list_all_peers(&conn)?;
    let by_id: std::collections::HashMap<i64, &nodes::NodeRow> = rows.iter().map(|n| (n.id, n)).collect();
    let port_of = |id: i64| by_id.get(&id).and_then(|n| wireserve_types::relay_port(state.config.relay_port_base, n.relay_slot));
    let mut out: std::collections::BTreeMap<(String, u16), wireserve_types::RelayPortStatus> = std::collections::BTreeMap::new();
    for r in nodes::relay_ports(&conn)? {
        let Some(carrier) = by_id.get(&r.carrier_node_id) else { continue };
        out.insert((carrier.name.clone(), r.port), wireserve_types::RelayPortStatus {
            carrier: carrier.name.clone(),
            address: Some(r.address.clone()),
            port: r.port,
            node: rows.iter().find(|n| port_of(n.id) == Some(r.port)).map(|n| n.name.clone()),
            devices: Vec::new(),
            checked_at: r.checked_at,
            open: Some(r.open),
        });
    }
    for (device, peer, carrier) in nodes::all_static_relays(&conn)? {
        let (Some(d), Some(p), Some(c), Some(port)) = (by_id.get(&device), by_id.get(&peer), by_id.get(&carrier), port_of(peer)) else {
            continue;
        };
        let entry = out.entry((c.name.clone(), port)).or_insert_with(|| wireserve_types::RelayPortStatus {
            carrier: c.name.clone(),
            address: None,
            port,
            node: Some(p.name.clone()),
            devices: Vec::new(),
            checked_at: None,
            open: None,
        });
        entry.devices.push(d.name.clone());
    }
    Ok(Json(wireserve_types::RelayPortsResponse { ports: out.into_values().collect() }))
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
    let dependents = nodes::static_nodes_depending_on(&conn, node.id)?;
    if !dependents.is_empty() {
        tracing::warn!(
            event = "transit_approval_withdrawn_with_dependents",
            node_name = %name,
            dependents = %dependents.join(","),
            "node was the exit or a carrier for these devices; withdrawing approval also stops \
             that from their next poll — re-export them"
        );
    }
    nodes::set_transit_approved(&conn, node.id, false)?;
    if let Some(pubkey) = &node.pubkey {
        state.transit.withdraw_carrier(pubkey);
    }
    tracing::info!(event = "transit_denied", node_name = %name);
    Ok(())
}

/// `GET /admin/peers` (spec §4.5.1).
///
/// Every entry's `relay.via` (PLAN.md M39) is always `None` here —
/// deliberately, not an oversight: it's requester-relative ("how THIS
/// polling node should reach this peer"), and an admin browsing the
/// directory isn't a requester polling on behalf of a specific node.
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
        .filter(|n| n.exit_enabled && n.exit_node_id.is_some())
        .map(|n| n.name.clone())
        .collect();
    // A device's `.conf` is a snapshot (PLAN.md M40): stale once a node
    // joined after it was written, or a carrier or exit it names no longer
    // qualifies.
    let live: std::collections::HashMap<i64, &nodes::NodeRow> = rows.iter().map(|n| (n.id, n)).collect();
    let relays = nodes::all_static_relays(&conn)?;
    let qualifies = |id: i64| live.get(&id).is_some_and(|n| n.transit_approved);
    let stale_devices = rows
        .iter()
        .filter(|n| n.kind == wireserve_types::NodeKind::Static)
        .filter(|d| {
            let newer_node = rows.iter().any(|n| {
                n.kind == wireserve_types::NodeKind::Agent
                    && matches!((n.created_at, d.exported_at), (Some(c), Some(e)) if c > e)
            });
            let lost_carrier = relays.iter().any(|(dev, _, carrier)| *dev == d.id && !qualifies(*carrier));
            let lost_exit = d.exit_node_id.is_some_and(|e| !qualifies(e));
            // Never recorded since the gateway went (PLAN.md M41): its
            // `.conf` still sends the mesh to a gateway that forwards nothing.
            let never = d.exported_at.is_none();
            never || newer_node || lost_carrier || lost_exit
        })
        .map(|n| n.name.clone())
        .collect();
    let tags_by_id = grants::tags(&conn)?;
    let tags = rows
        .iter()
        .filter_map(|n| Some((n.name.clone(), tags_by_id.get(&n.id)?.iter().cloned().collect())))
        .collect();
    let dialable = rows
        .iter()
        .filter_map(|n| Some((n.name.clone(), state.transit.dialable(n.pubkey.as_deref()?, state.config.online_threshold_secs)?)))
        .collect();
    Ok(Json(AdminPeersResponse {
        dialable,
        peers,
        transit_approved,
        transit_offering,
        stale_devices,
        exit_offering,
        exit_devices,
        tags,
    }))
}

#[cfg(test)]
mod relay_plan_tests {
    #[test]
    fn only_this_hosts_own_addresses_count_as_its_own() {
        assert!(super::is_own_address(std::net::Ipv4Addr::LOCALHOST));
        assert!(!super::is_own_address("203.0.113.254".parse().unwrap()));
    }
}
