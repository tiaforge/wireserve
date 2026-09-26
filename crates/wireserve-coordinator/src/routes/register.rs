use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::Json;
use wireserve_types::{NodeKind, RegisterRequest, RegisterResponse, BEARER_TOKEN_PREFIX};

use crate::db::nodes::{self, Redemption};
use crate::db::DbError;
use crate::error::AppError;
use crate::state::AppState;
use crate::{ipam, tokengen};

/// `POST /register` (spec §4.2). Redeems a one-time join token, allocates
/// addresses, and issues a bearer token. Reachable without any auth header
/// — the join token itself is the credential — so it's the one endpoint
/// this coordinator rate-limits unconditionally on the failure path.
pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    // S2 (security review): a pubkey/endpoint_addr that isn't validated
    // here gets stored and later redistributed verbatim — to every other
    // node's /poll response, to wireserve-admin's list-peers output, and
    // (for endpoint_addr especially) into a rendered .conf file via
    // export-config. An attacker holding any valid bearer token could
    // otherwise smuggle extra config-file syntax (e.g. an embedded
    // newline + "AllowedIPs = 0.0.0.0/0") into every downstream consumer
    // of the peer directory. Reject anything malformed at the door.
    if !wireserve_types::is_valid_wg_pubkey(&req.pubkey) {
        return Err(AppError::BadRequest(
            "pubkey must be a standard-base64-encoded 32-byte WireGuard public key".into(),
        ));
    }
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

    // The budget is read before the lookup and keyed on the
    // proxy-resolved client IP, not the raw TCP peer (which behind spec
    // §7's mandated reverse proxy is always the proxy itself, S4).
    //
    // What that budget does and does not do: it selects the status code
    // for a request that goes on to fail, and nothing more. It does NOT
    // turn away a request carrying a valid join token — see the comment
    // on the lookup below, and `rate_limit`'s module doc. An earlier
    // version of this comment claimed the opposite ("an actual
    // brute-force bound rather than a response-code cosmetic") while the
    // code ten lines down did the reverse; the bound is the global
    // failed-auth delay applied on the failure path, not this.
    let client =
        crate::client_ip::resolve_client(
        &headers,
        peer_addr.ip(),
        state.config.trusts_forwarded_from(peer_addr.ip()),
    );
    let observed_ip = client.ip;
    let blocked = state.rate_limiter.is_blocked(observed_ip);

    let hash = wireserve_types::hash_token(&req.join_token);
    let conn = state.db.conn.lock().await;

    // Same correction as the auth extractors: being over budget does not
    // reject a request carrying a genuinely valid credential, it only
    // stops one from continuing to fail. Behind spec §7's mandated
    // reverse proxy, or behind any shared NAT, every node registers from
    // one address, so rejecting on the budget alone let a stranger's bad
    // guesses block a legitimate node from ever joining.
    let found = nodes::find_by_unused_join_token_hash(&conn, &hash)?;
    let node = match found {
        Some(node) => node,
        None => {
            // Unknown, already-used and expired tokens are
            // indistinguishable on purpose (spec: "reject if token
            // already used or unknown" — with the same shape, so a caller
            // learns nothing about whether a guessed token was ever
            // valid).
            //
            // Release the database lock BEFORE the delay below. `conn` is
            // the process's single `Mutex<Connection>`: sleeping while
            // holding it would queue every other request in the mesh
            // behind whoever is guessing, which is a far worse outcome
            // than the guessing itself. The success path deliberately
            // keeps the lock instead — dropping and re-acquiring it there
            // would open a window for two callers to redeem the same
            // one-time token concurrently.
            drop(conn);
            state.rate_limiter.record_failure(observed_ip);
            tracing::warn!(
                event = "auth_failure",
                client_ip = %observed_ip,
                endpoint = "/register",
                reason = "unknown_token",
            );
            state.rate_limiter.apply_failure_delay().await;
            return Err(if blocked {
                AppError::TooManyRequests
            } else {
                AppError::Internal(DbError::JoinTokenInvalid)
            });
        }
    };

    // Judgment call (flagged for PLAN.md): the node's `kind` was fixed at
    // `POST /admin/nodes` creation time and is treated as authoritative;
    // `RegisterRequest.kind` (which defaults to `agent` when omitted, per
    // the wire schema) is validated against it rather than overriding it,
    // so a request can't silently flip a node's kind at registration time.
    if req.kind != node.kind {
        return Err(AppError::BadRequest(format!(
            "kind mismatch: node was created as '{}', register requested '{}'",
            node.kind.as_str(),
            req.kind.as_str()
        )));
    }

    if node.kind == NodeKind::Agent && req.listen_port.is_none() {
        return Err(AppError::BadRequest(
            "listen_port is required for kind=agent".into(),
        ));
    }
    if req.listen_port == Some(0) {
        return Err(AppError::BadRequest("listen_port must not be 0".into()));
    }

    // F4 (spec §4.5: rejoin works "without freeing its name or IP"):
    // reuse the node's existing addresses if it has any — i.e. this is a
    // re-registration after rejoin/revoke, not a brand-new node — rather
    // than always allocating fresh ones. Every static peer's exported
    // .conf pointing at this node's IP would otherwise silently go stale
    // on every rejoin.
    let ip4 = match node.ip4.as_deref().and_then(|s| s.parse().ok()) {
        Some(existing) => existing,
        None => ipam::allocate_v4(&state.config.net_v4_cidr, &nodes::all_allocated_ip4(&conn)?)
            .map_err(DbError::from)?,
    };
    let ip6 = match node.ip6.as_deref().and_then(|s| s.parse().ok()) {
        Some(existing) => existing,
        None => ipam::allocate_v6(&state.config.net_v6_prefix, &nodes::all_allocated_ip6(&conn)?)
            .map_err(DbError::from)?,
    };

    // endpoint_addr fallback (spec §4.2) only ever applies to kind=agent —
    // a kind=static node's endpoint_addr stays NULL forever, since it's
    // never dialed into. S4 (security review): the fallback also never
    // fires when the observed source is loopback/private — spec §7 puts a
    // reverse proxy in front of the coordinator, so an unqualified
    // fallback would hand out the proxy's own useless local address to
    // every other node as this node's "reachable" endpoint.
    let (endpoint_addr, endpoint_addr_v4, endpoint_addr_v6, listen_port) = if node.kind == NodeKind::Agent {
        // Loopback is unconditionally useless to any other peer, in any
        // topology. A private-range address is only suspect when we've
        // been told to expect a proxy (trust_proxy_headers) yet still
        // ended up with a raw, unresolved observed address — see
        // client_ip::is_loopback's doc comment for why a direct,
        // proxy-less private-network deployment must NOT have this
        // fallback disabled.
        // The private-range half of this check applies ONLY when we were
        // told to expect a proxy and did not actually get an address from
        // it. Without that qualification it fired on the recommended
        // topology itself: a proxy on an internal network forwards the
        // node's real address, that address is private because the whole
        // network is, and suppressing the fallback there left every node
        // that omitted --endpoint-addr with no endpoint at all. Since a
        // peer with no endpoint cannot be dialled, and a node only learns
        // a peer's real address from traffic that peer sent first, a mesh
        // where nobody has an endpoint never forms at all.
        let endpoint = crate::client_ip::endpoint_fallback(
            req.endpoint_addr.as_deref(),
            &client,
            req.listen_port,
            state.config.trusts_forwarded_from(peer_addr.ip()),
        );
        (
            endpoint,
            req.endpoint_addr_v4.clone(),
            req.endpoint_addr_v6.clone(),
            req.listen_port,
        )
    } else {
        (None, None, None, None)
    };

    let bearer_token = tokengen::generate(BEARER_TOKEN_PREFIX);
    let bearer_hash = wireserve_types::hash_token(&bearer_token);

    nodes::apply_redemption(
        &conn,
        node.id,
        &Redemption {
            pubkey: &req.pubkey,
            ip4,
            ip6,
            listen_port,
            endpoint_addr: endpoint_addr.as_deref(),
            endpoint_addr_v4: endpoint_addr_v4.as_deref(),
            endpoint_addr_v6: endpoint_addr_v6.as_deref(),
            lan_addr: req.lan_addr.as_deref(),
            reflexive_addr: req.reflexive_addr.as_deref(),
            bearer_token_hash: &bearer_hash,
        },
    )?;

    tracing::info!(
        event = "node_registered",
        node_name = %node.name,
        kind = node.kind.as_str(),
        "node registered"
    );

    Ok(Json(RegisterResponse {
        bearer_token,
        ip4: ip4.to_string(),
        ip6: ip6.to_string(),
        mesh: Some(state.config.mesh_info()),
        naming: state.config.service_naming(),
    }))
}
