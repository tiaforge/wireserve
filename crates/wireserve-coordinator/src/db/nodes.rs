use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension};
use wireserve_types::NodeKind;

use super::DbError;

#[derive(Debug, Clone)]
pub struct NodeRow {
    pub id: i64,
    pub name: String,
    pub kind: NodeKind,
    pub pubkey: Option<String>,
    pub ip4: Option<String>,
    pub ip6: Option<String>,
    pub endpoint_addr: Option<String>,
    /// Set by the `DELETE /admin/nodes/:name/endpoint` admin action; see
    /// `clear_endpoint`'s doc comment. Gates whether `/poll` is allowed to
    /// re-derive `endpoint_addr` from the observed source address.
    pub endpoint_cleared: bool,
    /// Actively self-reported by the agent's own dual-family probe (see
    /// `update_poll_state`'s doc comment) — never derived by the
    /// coordinator from a single observed connection, unlike
    /// `endpoint_addr` above.
    pub endpoint_addr_v4: Option<String>,
    pub endpoint_addr_v6: Option<String>,
    /// This node's own self-reported private-LAN address (NAT-hairpin
    /// fix, PLAN.md decisions log #85) — self-reported like `_v4`/`_v6`
    /// above, never derived by the coordinator, and coalesced rather than
    /// overwritten on a poll that omits it, for the same reason.
    pub lan_addr: Option<String>,
    /// This node's own reflexive (NAT-mapped) address, as observed by
    /// the coordinator's self-hosted UDP responder (PLAN.md M22) —
    /// self-reported like `lan_addr`, never derived by the coordinator.
    pub reflexive_addr: Option<String>,
    pub listen_port: Option<i64>,
    pub revoked: bool,
    pub last_seen: Option<DateTime<Utc>>,
    /// Whether an admin has approved this node to carry transit traffic
    /// for other peers (`transit_approved_at IS NOT NULL`). The node's own
    /// `transit_capable` report counts for nothing without it.
    pub transit_approved: bool,
    /// For a `kind=static` node, the node it routes through to reach
    /// anything not written directly into its `.conf` (PLAN.md M24). `None`
    /// for every agent node and for a static peer exported without one.
    pub gateway_node_id: Option<i64>,
    /// An admin's statement that nothing outside the mesh can dial this node,
    /// whatever endpoint it advertises (PLAN.md #134). Read by `export-config`
    /// only: a device exported with a gateway reaches this node through it
    /// instead of holding a direct `[Peer]` for it. Deliberately absent from
    /// `PeerInfo`, so no agent ever sees it.
    pub export_via_gateway: bool,
    /// For a `kind=static` node: its last export included the full-tunnel
    /// profile, so its gateway is its exit (PLAN.md M27).
    pub exit_enabled: bool,
}

#[cfg(test)]
impl NodeRow {
    /// A registered agent with nothing else set.
    #[must_use]
    pub fn for_test(id: i64, name: &str) -> Self {
        Self {
            id,
            name: name.into(),
            kind: NodeKind::Agent,
            pubkey: Some(format!("pk-{name}")),
            ip4: None,
            ip6: None,
            endpoint_addr: None,
            endpoint_cleared: false,
            endpoint_addr_v4: None,
            endpoint_addr_v6: None,
            lan_addr: None,
            reflexive_addr: None,
            listen_port: None,
            revoked: false,
            last_seen: None,
            transit_approved: false,
            gateway_node_id: None,
            export_via_gateway: false,
            exit_enabled: false,
        }
    }
}

fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NodeRow> {
    let kind_str: String = row.get("kind")?;
    let kind = kind_str.parse::<NodeKind>().unwrap_or_default();
    let last_seen_str: Option<String> = row.get("last_seen")?;
    Ok(NodeRow {
        id: row.get("id")?,
        name: row.get("name")?,
        kind,
        pubkey: row.get("pubkey")?,
        ip4: row.get("ip4")?,
        ip6: row.get("ip6")?,
        endpoint_addr: row.get("endpoint_addr")?,
        endpoint_cleared: row.get("endpoint_cleared")?,
        endpoint_addr_v4: row.get("endpoint_addr_v4")?,
        endpoint_addr_v6: row.get("endpoint_addr_v6")?,
        lan_addr: row.get("lan_addr")?,
        reflexive_addr: row.get("reflexive_addr")?,
        listen_port: row.get("listen_port")?,
        revoked: row.get("revoked")?,
        last_seen: last_seen_str.and_then(|s| parse_dt(&s)),
        transit_approved: row.get::<_, Option<String>>("transit_approved_at")?.is_some(),
        gateway_node_id: row.get("gateway_node_id")?,
        export_via_gateway: row.get("export_via_gateway")?,
        exit_enabled: row.get("exit_enabled")?,
    })
}

fn parse_dt(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

pub fn now_str() -> String {
    Utc::now().to_rfc3339()
}

/// The `join_token_expires_at` value for a token minted now with `ttl_secs`
/// of life, or `None` when `ttl_secs` is 0 (expiry disabled).
///
/// Returns `None` rather than a far-future timestamp for the disabled
/// case, so "no expiry" is one representation everywhere — the column, the
/// wire, and the check in `find_by_unused_join_token_hash` — instead of a
/// sentinel date that some future comparison forgets to special-case.
#[must_use]
pub fn join_token_expiry(ttl_secs: u64) -> Option<String> {
    if ttl_secs == 0 {
        return None;
    }
    let ttl = chrono::Duration::try_seconds(i64::try_from(ttl_secs).ok()?)?;
    Some((Utc::now() + ttl).to_rfc3339())
}

/// Maps a UNIQUE-constraint SQLite error into the matching `DbError`
/// (`PubkeyTaken` for the `nodes.pubkey` column, `NameTaken` otherwise);
/// any other error passes through unchanged. SQLite names the violated
/// column in its message (`UNIQUE constraint failed: nodes.pubkey`),
/// which is the only way to tell the two apart without a pre-query.
fn map_unique_violation(err: rusqlite::Error) -> DbError {
    if let rusqlite::Error::SqliteFailure(ref e, ref msg) = err {
        if e.code == rusqlite::ErrorCode::ConstraintViolation {
            if msg.as_deref().is_some_and(|m| m.contains("nodes.pubkey")) {
                return DbError::PubkeyTaken;
            }
            return DbError::NameTaken;
        }
    }
    DbError::Sqlite(err)
}

/// Create a node record with a fresh join token hash (spec §4.1). Returns
/// the new node's id.
pub fn create_node(
    conn: &Connection,
    name: &str,
    kind: NodeKind,
    join_token_hash: &str,
    join_token_expires_at: Option<&str>,
) -> Result<i64, DbError> {
    conn.execute(
        "INSERT INTO nodes (name, kind, join_token_hash, join_token_used, join_token_expires_at) \
         VALUES (?1, ?2, ?3, 0, ?4)",
        rusqlite::params![name, kind.as_str(), join_token_hash, join_token_expires_at],
    )
    .map_err(map_unique_violation)?;
    Ok(conn.last_insert_rowid())
}

/// Looks up a node by its row id — used to turn an `OwnedByAnotherNode`
/// outcome into a name the operator recognises.
pub fn find_by_id(conn: &Connection, id: i64) -> Result<Option<NodeRow>, DbError> {
    conn.query_row("SELECT * FROM nodes WHERE id = ?1", [id], map_row)
        .optional()
        .map_err(DbError::from)
}

pub fn find_by_name(conn: &Connection, name: &str) -> Result<Option<NodeRow>, DbError> {
    conn.query_row("SELECT * FROM nodes WHERE name = ?1", [name], map_row)
        .optional()
        .map_err(DbError::from)
}

/// Look up a node by an unredeemed join-token hash only — a token that's
/// already been used matches nothing here, which is what makes double
/// redemption indistinguishable from an unknown token to the caller.
pub fn find_by_unused_join_token_hash(
    conn: &Connection,
    hash: &str,
) -> Result<Option<NodeRow>, DbError> {
    let found: Option<(NodeRow, Option<String>)> = conn
        .query_row(
            "SELECT * FROM nodes WHERE join_token_hash = ?1 AND join_token_used = 0",
            [hash],
            |row| Ok((map_row(row)?, row.get("join_token_expires_at")?)),
        )
        .optional()?;

    let Some((node, expires_at)) = found else {
        return Ok(None);
    };

    // The expiry check lives here, in Rust, rather than as a predicate in
    // the SQL above, so the comparison is between two parsed timestamps
    // instead of two strings. Lexicographic comparison of RFC3339 happens
    // to be correct only while every writer emits an identical format,
    // which is not a property worth betting a credential check on.
    //
    // Returning `Ok(None)` for an expired token — the same value an
    // unknown or already-redeemed one produces — is what keeps all three
    // indistinguishable to the caller, and therefore in the response.
    if let Some(raw) = expires_at {
        match parse_dt(&raw) {
            Some(expiry) if Utc::now() >= expiry => return Ok(None),
            // Unparseable: fail closed. A timestamp this code cannot read
            // is a corrupt or hand-edited row, and the safe reading of
            // "I don't know when this expires" is "it has".
            None => return Ok(None),
            Some(_) => {}
        }
    }
    Ok(Some(node))
}

pub struct Redemption<'a> {
    pub pubkey: &'a str,
    pub ip4: Ipv4Addr,
    pub ip6: Ipv6Addr,
    pub listen_port: Option<u16>,
    pub endpoint_addr: Option<&'a str>,
    /// Actively self-reported dual-family candidates, straight from this
    /// `/register` request — see `NodeRow::endpoint_addr_v4`'s doc
    /// comment. Set directly, not COALESCEd, same as `endpoint_addr`: a
    /// fresh register/rejoin fully re-derives from this request, not from
    /// history.
    pub endpoint_addr_v4: Option<&'a str>,
    pub endpoint_addr_v6: Option<&'a str>,
    /// Same treatment as `endpoint_addr_v4`/`_v6` — see `NodeRow::lan_addr`.
    pub lan_addr: Option<&'a str>,
    /// Same treatment as `lan_addr` — see `NodeRow::reflexive_addr`.
    pub reflexive_addr: Option<&'a str>,
    pub bearer_token_hash: &'a str,
}

/// Applies a `/register` redemption to a node found via
/// `find_by_unused_join_token_hash`. Clears the join token, sets the
/// pubkey/addresses/bearer token, and clears `revoked` back to 0 — this is
/// the only path that clears `revoked` (spec §4.5: rejoin issues a new join
/// token but does not itself clear `revoked`; only a *successful*
/// subsequent `/register` does).
pub fn apply_redemption(conn: &Connection, node_id: i64, r: &Redemption<'_>) -> Result<(), DbError> {
    conn.execute(
        "UPDATE nodes SET pubkey = ?1, ip4 = ?2, ip6 = ?3, listen_port = ?4, \
         endpoint_addr = ?5, bearer_token_hash = ?6, join_token_hash = NULL, \
         join_token_used = 1, revoked = 0, revoked_at = NULL, endpoint_cleared = 0, \
         endpoint_addr_v4 = ?7, endpoint_addr_v6 = ?8, lan_addr = ?9, reflexive_addr = ?10 \
         WHERE id = ?11",
        rusqlite::params![
            r.pubkey,
            r.ip4.to_string(),
            r.ip6.to_string(),
            r.listen_port,
            r.endpoint_addr,
            r.bearer_token_hash,
            r.endpoint_addr_v4,
            r.endpoint_addr_v6,
            r.lan_addr,
            r.reflexive_addr,
            node_id,
        ],
    )
    .map_err(map_unique_violation)?;
    Ok(())
}

/// Finds a non-revoked node by its bearer token hash. Revoked nodes never
/// match here — this is what makes a revoked bearer token get a uniform
/// 401 on its very next poll, per spec §4.4.
pub fn find_by_bearer_hash(conn: &Connection, hash: &str) -> Result<Option<NodeRow>, DbError> {
    conn.query_row(
        "SELECT * FROM nodes WHERE bearer_token_hash = ?1 AND revoked = 0",
        [hash],
        map_row,
    )
    .optional()
    .map_err(DbError::from)
}

/// `explicit` is the singular-`endpoint_addr` value to write (if any —
/// `None` means "no opinion this poll," preserved via `COALESCE` exactly
/// as before). `reset_cleared` is true exactly when the node itself
/// reported an explicit `endpoint_addr` this poll: an explicit assertion
/// always un-clears (see `clear_endpoint`'s doc comment), regardless of
/// whether the auto-detected fallback was gated off by a previous clear.
///
/// `v4`/`v6` are the agent's actively self-probed candidates (see
/// `NodeRow::endpoint_addr_v4`'s doc comment) — also COALESCEd, so a
/// node that couldn't reach a given family this cycle doesn't erase a
/// candidate it successfully reported on some earlier cycle. Unlike
/// `endpoint_addr`, these are never gated by `endpoint_cleared`: nothing
/// coordinator-side ever derives them passively, so a plain write here
/// already is the only kind of "self-heal" that exists for them.
pub struct EndpointUpdate<'a> {
    pub explicit: Option<&'a str>,
    pub reset_cleared: bool,
    pub v4: Option<&'a str>,
    pub v6: Option<&'a str>,
    /// Same COALESCE treatment as `v4`/`v6` — see `NodeRow::lan_addr`.
    pub lan: Option<&'a str>,
    /// Same COALESCE treatment as `lan` — see `NodeRow::reflexive_addr`.
    pub reflexive: Option<&'a str>,
}

pub fn update_poll_state(
    conn: &Connection,
    node_id: i64,
    update: &EndpointUpdate<'_>,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE nodes SET last_seen = ?1, endpoint_addr = COALESCE(?2, endpoint_addr), \
         endpoint_cleared = CASE WHEN ?3 THEN 0 ELSE endpoint_cleared END, \
         endpoint_addr_v4 = COALESCE(?4, endpoint_addr_v4), \
         endpoint_addr_v6 = COALESCE(?5, endpoint_addr_v6), \
         lan_addr = COALESCE(?6, lan_addr), \
         reflexive_addr = COALESCE(?7, reflexive_addr) \
         WHERE id = ?8",
        rusqlite::params![
            now_str(),
            update.explicit,
            update.reset_cleared,
            update.v4,
            update.v6,
            update.lan,
            update.reflexive,
            node_id
        ],
    )?;
    Ok(())
}

/// Revokes a node: clears its bearer token (so its very next `/poll` gets
/// 401), invalidates any join token still outstanding, marks it revoked,
/// and removes its `services` rows.
///
/// The `services.node_id` foreign key is declared `ON DELETE CASCADE`
/// (spec §3's DDL, kept verbatim), but that only fires when the *node row
/// itself* is deleted — and per spec §4.4 the node row is deliberately
/// kept (not hard-deleted) on revoke, so the FK cascade never triggers
/// here. The `services` deletion below is therefore explicit, not a
/// reliance on the FK. (Caught by
/// `db::nodes::tests::cascade_delete_removes_services_on_revoke`, whose
/// name is now slightly misleading but is left as-is since it documents
/// exactly this gotcha for the next reader.)
///
/// **`join_token_hash` is cleared too, and that is load-bearing, not
/// tidiness.** Spec §4.4 lists only `bearer_token_hash` because it
/// describes revoking a node that has already registered. But a node that
/// was created and never registered still holds a live, unredeemed join
/// token, and `apply_redemption` sets `revoked = 0` — so without this,
/// revoking such a node would not actually cut it off: whoever holds that
/// join token could redeem it afterwards and come back as a fully
/// un-revoked member of the mesh. That is precisely the case revoke
/// exists for (a credential issued out of band and then found to have
/// leaked). Rejoin (§4.5) remains the supported way back in, and it
/// issues a *fresh* token rather than reviving this one.
pub fn revoke(conn: &Connection, node_id: i64) -> Result<(), DbError> {
    // One transaction: a crash between the statements must not leave a
    // node revoked but its services still in the directory, or its join
    // token still redeemable.
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "UPDATE nodes SET revoked = 1, revoked_at = ?1, bearer_token_hash = NULL, \
         join_token_hash = NULL, join_token_used = 1, transit_approved_at = NULL \
         WHERE id = ?2",
        rusqlite::params![now_str(), node_id],
    )?;
    tx.execute("DELETE FROM services WHERE node_id = ?1", [node_id])?;
    // Its owner (PLAN.md M38) was the owner of the identity revoked.
    super::owners::forget(&tx, node_id)?;
    tx.commit()?;
    Ok(())
}

/// Issues a fresh join token for a node (spec §4.5) and, in the same
/// statement, cuts off the identity it had: bearer token, WireGuard
/// pubkey and transit approval. Does NOT touch `revoked` — see
/// `apply_redemption`.
///
/// **The pubkey is cleared, not just the bearer token (security review
/// S8, then finding #2).** Rejoin is the path for a key "suspected
/// compromised" (spec §4.5), and `list_all_peers` hands out every node
/// with a non-NULL pubkey. Clearing only the bearer token stopped the old
/// credential polling, but left the old WireGuard key configured as a
/// peer on every other node — so whoever held the stolen private key kept
/// full access to the mesh until the real machine re-registered, and
/// forever if it never did. With the pubkey gone the node drops out of
/// the directory (and its services with it) on everyone's next poll, and
/// `apply_redemption` brings it back under its new key. Its addresses
/// are kept, so a static peer's exported `.conf` still points at the
/// right IP afterwards.
///
/// Transit approval goes too: it was granted to the identity being
/// replaced — and so does its owner (PLAN.md M38): the new token may go to
/// another device.
///
/// `gateway_node_id` and the node's `static_conf_peers` rows deliberately
/// stay (PLAN.md M24). They describe how the device is *addressed*, in the
/// same category as `ip4`/`ip6` just above, not what it is allowed to do
/// under a key that is being rotated — and `export-config --refresh` depends
/// on that, since a refresh should not silently re-home a phone onto a
/// different gateway.
pub fn reissue_join_token(
    conn: &Connection,
    node_id: i64,
    join_token_hash: &str,
    join_token_expires_at: Option<&str>,
) -> Result<(), DbError> {
    let tx = conn.unchecked_transaction()?;
    tx.execute(
        "UPDATE nodes SET join_token_hash = ?1, join_token_used = 0, join_token_expires_at = ?2, \
         bearer_token_hash = NULL, pubkey = NULL, transit_approved_at = NULL \
         WHERE id = ?3",
        rusqlite::params![join_token_hash, join_token_expires_at, node_id],
    )
    .map_err(map_unique_violation)?;
    super::owners::forget(&tx, node_id)?;
    tx.commit()?;
    Ok(())
}

/// Grants (`true`) or withdraws (`false`) a node's approval to carry
/// transit traffic. Idempotent in both directions; an existing grant
/// keeps its original timestamp.
pub fn set_transit_approved(conn: &Connection, node_id: i64, approved: bool) -> Result<(), DbError> {
    if approved {
        conn.execute(
            "UPDATE nodes SET transit_approved_at = COALESCE(transit_approved_at, ?1) WHERE id = ?2",
            rusqlite::params![now_str(), node_id],
        )?;
    } else {
        conn.execute("UPDATE nodes SET transit_approved_at = NULL WHERE id = ?1", [node_id])?;
    }
    Ok(())
}

/// Records which gateway a static peer routes through, and which peers were
/// written into its `.conf` as direct `[Peer]` blocks, in one transaction
/// (PLAN.md M24).
///
/// The two are written together because they are two halves of one fact: the
/// conf's shape. `transit_via` is later derived from `conf_peer_ids` — it must
/// name exactly the nodes *absent* from the conf — so a gateway recorded
/// without its membership list, or vice versa, would misroute. Whether the
/// export included a full-tunnel profile (PLAN.md M27) is the third half of
/// the same fact, and is written with them.
pub fn set_gateway(
    conn: &mut Connection,
    static_node_id: i64,
    gateway_node_id: Option<i64>,
    conf_peer_ids: &[i64],
    exit: bool,
) -> Result<(), DbError> {
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE nodes SET gateway_node_id = ?1, exit_enabled = ?2 WHERE id = ?3",
        rusqlite::params![gateway_node_id, exit && gateway_node_id.is_some(), static_node_id],
    )?;
    tx.execute(
        "DELETE FROM static_conf_peers WHERE static_node_id = ?1",
        [static_node_id],
    )?;
    for peer_id in conf_peer_ids {
        tx.execute(
            "INSERT INTO static_conf_peers (static_node_id, peer_node_id) VALUES (?1, ?2)",
            rusqlite::params![static_node_id, peer_id],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Sets or clears [`NodeRow::export_via_gateway`]. Idempotent.
///
/// Left alone by `revoke` and `reissue_join_token`: whether the node can be
/// dialled from outside is a fact about its network, not about its key.
pub fn set_export_via_gateway(conn: &Connection, node_id: i64, enabled: bool) -> Result<(), DbError> {
    conn.execute(
        "UPDATE nodes SET export_via_gateway = ?1 WHERE id = ?2",
        rusqlite::params![enabled, node_id],
    )?;
    Ok(())
}

/// The static peers whose `.conf` a refresh would change after
/// [`set_export_via_gateway`] flips to `enabled` for `node_id`, by name.
///
/// Turning it on affects every device with a gateway that holds `node_id` as
/// a direct `[Peer]` (a device without a gateway has no other way to reach it,
/// so its export keeps the direct entry). Turning it off affects every device that routes through a
/// gateway and does *not* hold one, since its next export would add it — but
/// only the first group is broken meanwhile; the second keeps working through
/// the gateway until it is refreshed.
pub fn static_nodes_affected_by_via_gateway(
    conn: &Connection,
    node_id: i64,
    enabled: bool,
) -> Result<Vec<String>, DbError> {
    let sql = if enabled {
        "SELECT n.name FROM nodes n \
         JOIN static_conf_peers c ON c.static_node_id = n.id \
         WHERE c.peer_node_id = ?1 AND n.gateway_node_id IS NOT NULL ORDER BY n.name"
    } else {
        "SELECT n.name FROM nodes n \
         WHERE n.kind = 'static' AND n.gateway_node_id IS NOT NULL AND n.gateway_node_id != ?1 \
         AND NOT EXISTS (SELECT 1 FROM static_conf_peers c \
                         WHERE c.static_node_id = n.id AND c.peer_node_id = ?1) \
         ORDER BY n.name"
    };
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt
        .query_map([node_id], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Every `(static_node_id, peer_node_id)` pair recorded by [`set_gateway`].
pub fn all_static_conf_peers(conn: &Connection) -> Result<Vec<(i64, i64)>, DbError> {
    let mut stmt =
        conn.prepare("SELECT static_node_id, peer_node_id FROM static_conf_peers")?;
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// The static nodes that route through `gateway_node_id`, by name. Used to
/// refuse or warn on lifecycle operations that would strand them.
pub fn static_nodes_using_gateway(
    conn: &Connection,
    gateway_node_id: i64,
) -> Result<Vec<String>, DbError> {
    let mut stmt = conn.prepare("SELECT name FROM nodes WHERE gateway_node_id = ?1 ORDER BY name")?;
    let rows = stmt
        .query_map([gateway_node_id], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Clears a node's advertised `endpoint_addr`, leaving everything else
/// about the node untouched.
///
/// Exists because `update_poll_state` writes the column with
/// `COALESCE(?2, endpoint_addr)`, so a node can set an endpoint but never
/// unset one: a `/poll` that omits `endpoint_addr` means "no opinion,
/// keep what you have", not "clear it". That COALESCE is load-bearing and
/// is deliberately left alone — a node that registered without
/// `--endpoint-addr` had one inferred from its observed source address
/// (spec §4.2) and never learned the value, so it sends no
/// `endpoint_addr` on its very first poll. Dropping the COALESCE would
/// wipe that inferred endpoint immediately and break exactly the NAT-ed
/// deployment the register-time fallback exists to serve.
///
/// So clearing is an operator action instead, which is the right shape
/// anyway: a stale endpoint (a lost port forward, a move behind CGNAT)
/// is noticed by the person watching the mesh, not by the node that no
/// longer knows how it is reached.
///
/// **This clears a stale value; it does not stop a node re-asserting
/// one.** If the node still has an endpoint set locally it will report
/// it again on its next poll and the column comes back. To stop that,
/// change it at the node.
///
/// Also sets `endpoint_cleared`, so `/poll`'s observed-source-address
/// self-healing (`client_ip::endpoint_fallback`) does not immediately
/// undo this by re-deriving a value on the very next poll — that flag is
/// what actually makes the guarantee above true for the *auto-detected*
/// case, not just the "node reports its own" case the doc comment above
/// already covered before self-healing existed.
/// `None` clears everything (the singular override, both probed
/// candidates, the self-reported LAN address, and the self-reported
/// reflexive address) — today's default and the only behavior that
/// existed before dual-stack tracking.
/// `Some(family)` clears only that probed
/// candidate, leaving the singular `endpoint_addr` and the other family
/// untouched — for the narrower case where only one family's advertised
/// address has gone stale (e.g. this node lost its IPv6 route but its
/// IPv4 one is still fine).
///
/// No family-scoped `_cleared` flag: unlike `endpoint_addr`, nothing
/// coordinator-side ever re-derives `endpoint_addr_v4`/`_v6` passively —
/// they're only ever set to whatever the node's own probe asserted that
/// cycle — so a plain `NULL` here already is the complete "stop
/// advertising it" action, same documented limitation as below (the node
/// re-probing successfully next cycle re-asserts it).
pub enum EndpointFamily {
    V4,
    V6,
}

pub fn clear_endpoint(
    conn: &Connection,
    node_id: i64,
    family: Option<EndpointFamily>,
) -> Result<(), DbError> {
    match family {
        None => conn.execute(
            "UPDATE nodes SET endpoint_addr = NULL, endpoint_cleared = 1, \
             endpoint_addr_v4 = NULL, endpoint_addr_v6 = NULL, lan_addr = NULL, \
             reflexive_addr = NULL \
             WHERE id = ?1",
            [node_id],
        ),
        Some(EndpointFamily::V4) => conn.execute(
            "UPDATE nodes SET endpoint_addr_v4 = NULL WHERE id = ?1",
            [node_id],
        ),
        Some(EndpointFamily::V6) => conn.execute(
            "UPDATE nodes SET endpoint_addr_v6 = NULL WHERE id = ?1",
            [node_id],
        ),
    }?;
    Ok(())
}

/// Hard-deletes a node record (security review F8: there was no way to
/// free a name burned by e.g. a failed `export-config` between create and
/// register). `services` rows go with it via the schema's
/// `ON DELETE CASCADE` — this is the one path where that cascade
/// actually fires, unlike `revoke` (see its doc comment). The caller is
/// responsible for refusing to delete a node that is still active.
pub fn delete_node(conn: &Connection, node_id: i64) -> Result<(), DbError> {
    conn.execute("DELETE FROM nodes WHERE id = ?1", [node_id])?;
    Ok(())
}

/// All addresses currently allocated (any node, regardless of registration
/// state, and every service address) — used by the IP allocator to avoid
/// handing out a duplicate. Nodes and services share one range (migration
/// 0006), so each allocation must avoid both.
pub fn all_allocated_ip4(conn: &Connection) -> Result<Vec<Ipv4Addr>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT ip4 FROM nodes WHERE ip4 IS NOT NULL \
         UNION SELECT vip4 FROM services WHERE vip4 IS NOT NULL",
    )?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        if let Ok(addr) = r?.parse() {
            out.push(addr);
        }
    }
    Ok(out)
}

/// Every node's name.
pub fn list_all_names(conn: &Connection) -> Result<Vec<String>, DbError> {
    let mut stmt = conn.prepare("SELECT name FROM nodes")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub fn all_allocated_ip6(conn: &Connection) -> Result<Vec<Ipv6Addr>, DbError> {
    let mut stmt = conn.prepare("SELECT ip6 FROM nodes WHERE ip6 IS NOT NULL")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        if let Ok(addr) = r?.parse() {
            out.push(addr);
        }
    }
    Ok(out)
}

/// Peers eligible to be shown in a directory: registered (non-NULL pubkey)
/// and not revoked.
pub fn list_all_peers(conn: &Connection) -> Result<Vec<NodeRow>, DbError> {
    let mut stmt = conn.prepare(
        "SELECT * FROM nodes WHERE pubkey IS NOT NULL AND revoked = 0 ORDER BY id",
    )?;
    let rows = stmt.query_map([], map_row)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn test_db() -> Db {
        Db::open_in_memory_for_test()
    }

    #[tokio::test]
    async fn create_and_find_by_name() {
        let db = test_db();
        let conn = db.conn.lock().await;
        create_node(&conn, "homeserver", NodeKind::Agent, "hash1", None).unwrap();
        let row = find_by_name(&conn, "homeserver").unwrap().unwrap();
        assert_eq!(row.name, "homeserver");
        assert!(!row.revoked);
        assert!(row.pubkey.is_none());
    }

    #[tokio::test]
    async fn duplicate_name_is_rejected() {
        let db = test_db();
        let conn = db.conn.lock().await;
        create_node(&conn, "dup", NodeKind::Agent, "hash1", None).unwrap();
        let err = create_node(&conn, "dup", NodeKind::Agent, "hash2", None).unwrap_err();
        assert!(matches!(err, DbError::NameTaken));
    }

    #[tokio::test]
    async fn join_token_is_single_use() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1", None).unwrap();
        assert!(find_by_unused_join_token_hash(&conn, "hash1")
            .unwrap()
            .is_some());
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk1",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: Some("1.2.3.4:51820"),
                bearer_token_hash: "bearerhash1",
                endpoint_addr_v4: None,
                endpoint_addr_v6: None,
                lan_addr: None,
                reflexive_addr: None,
            },
        )
        .unwrap();
        // Same hash no longer matches — indistinguishable from unknown.
        assert!(find_by_unused_join_token_hash(&conn, "hash1")
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn an_expired_join_token_is_indistinguishable_from_an_unknown_one() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let past = (Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        create_node(&conn, "n1", NodeKind::Agent, "joinhash1", Some(&past)).unwrap();

        // Both return Ok(None) — the same value, so the caller cannot
        // tell "this token was real but you were too slow" from "this
        // token never existed", and neither can the response.
        assert!(find_by_unused_join_token_hash(&conn, "joinhash1")
            .unwrap()
            .is_none());
        assert!(find_by_unused_join_token_hash(&conn, "never-existed")
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_join_token_inside_its_window_still_redeems() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let future = (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
        create_node(&conn, "n1", NodeKind::Agent, "joinhash1", Some(&future)).unwrap();
        assert!(find_by_unused_join_token_hash(&conn, "joinhash1")
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn a_null_expiry_never_expires() {
        // What every row created before this feature has, and what
        // ttl_secs = 0 produces.
        let db = test_db();
        let conn = db.conn.lock().await;
        create_node(&conn, "n1", NodeKind::Agent, "joinhash1", None).unwrap();
        assert!(find_by_unused_join_token_hash(&conn, "joinhash1")
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn an_unparseable_expiry_fails_closed() {
        // A corrupt or hand-edited row. "I cannot tell when this expires"
        // must read as "it has", not as "it hasn't".
        let db = test_db();
        let conn = db.conn.lock().await;
        create_node(&conn, "n1", NodeKind::Agent, "joinhash1", Some("not-a-timestamp")).unwrap();
        assert!(find_by_unused_join_token_hash(&conn, "joinhash1")
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn rejoin_issues_a_token_with_a_fresh_expiry() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let past = (Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        let id = create_node(&conn, "n1", NodeKind::Agent, "joinhash1", Some(&past)).unwrap();
        assert!(find_by_unused_join_token_hash(&conn, "joinhash1")
            .unwrap()
            .is_none());

        let future = (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
        reissue_join_token(&conn, id, "joinhash2", Some(&future)).unwrap();
        assert!(
            find_by_unused_join_token_hash(&conn, "joinhash2")
                .unwrap()
                .is_some(),
            "missing the window must be recoverable with a fresh token"
        );
    }

    #[test]
    fn join_token_expiry_treats_zero_as_disabled() {
        assert!(join_token_expiry(0).is_none());
        let some = join_token_expiry(1800).expect("a non-zero ttl yields an expiry");
        let parsed = parse_dt(&some).expect("and it must be parseable by our own reader");
        let delta = (parsed - Utc::now()).num_seconds();
        assert!((1700..=1800).contains(&delta), "expiry ~30min out, got {delta}s");
    }

    #[tokio::test]
    async fn revoke_clears_bearer_token_and_sets_flag() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1", None).unwrap();
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk1",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: None,
                bearer_token_hash: "bearerhash1",
                endpoint_addr_v4: None,
                endpoint_addr_v6: None,
                lan_addr: None,
                reflexive_addr: None,
            },
        )
        .unwrap();
        assert!(find_by_bearer_hash(&conn, "bearerhash1").unwrap().is_some());
        revoke(&conn, id).unwrap();
        assert!(find_by_bearer_hash(&conn, "bearerhash1").unwrap().is_none());
        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert!(row.revoked);
    }

    #[tokio::test]
    async fn rejoin_does_not_clear_revoked_but_redemption_does() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1", None).unwrap();
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk1",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: None,
                bearer_token_hash: "bearerhash1",
                endpoint_addr_v4: None,
                endpoint_addr_v6: None,
                lan_addr: None,
                reflexive_addr: None,
            },
        )
        .unwrap();
        revoke(&conn, id).unwrap();

        reissue_join_token(&conn, id, "hash2", None).unwrap();
        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert!(row.revoked, "rejoin alone must not clear revoked");

        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk2",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: None,
                bearer_token_hash: "bearerhash2",
                endpoint_addr_v4: None,
                endpoint_addr_v6: None,
                lan_addr: None,
                reflexive_addr: None,
            },
        )
        .unwrap();
        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert!(!row.revoked, "successful re-registration clears revoked");
    }

    #[tokio::test]
    async fn revoke_invalidates_an_outstanding_unredeemed_join_token() {
        // The node was created but never registered, so it still holds a
        // live join token. Revoking it must make that token dead — an
        // un-redeemed token that survives revoke would let whoever holds
        // it join afterwards, and `apply_redemption` would clear
        // `revoked` back to 0 in the process.
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "joinhash1", None).unwrap();
        assert!(find_by_unused_join_token_hash(&conn, "joinhash1")
            .unwrap()
            .is_some());

        revoke(&conn, id).unwrap();

        assert!(
            find_by_unused_join_token_hash(&conn, "joinhash1")
                .unwrap()
                .is_none(),
            "a join token outstanding at revoke time must not stay redeemable"
        );
    }

    #[tokio::test]
    async fn rejoin_after_revoke_still_issues_a_working_token() {
        // The flip side of the test above: revoke must not break the
        // supported way back in (spec §4.5). A fresh rejoin token is
        // redeemable even though revoke killed the previous one.
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "joinhash1", None).unwrap();
        revoke(&conn, id).unwrap();

        reissue_join_token(&conn, id, "joinhash2", None).unwrap();
        assert!(find_by_unused_join_token_hash(&conn, "joinhash2")
            .unwrap()
            .is_some());

        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk1",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: None,
                bearer_token_hash: "bearerhash1",
                endpoint_addr_v4: None,
                endpoint_addr_v6: None,
                lan_addr: None,
                reflexive_addr: None,
            },
        )
        .unwrap();
        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert!(!row.revoked, "rejoin + register is still the way back in");
    }

    fn register(conn: &Connection, id: i64, pubkey: &str, bearer_hash: &str) {
        apply_redemption(
            conn,
            id,
            &Redemption {
                pubkey,
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: None,
                bearer_token_hash: bearer_hash,
                endpoint_addr_v4: None,
                endpoint_addr_v6: None,
                lan_addr: None,
                reflexive_addr: None,
            },
        )
        .unwrap();
    }

    #[tokio::test]
    async fn rejoin_drops_the_old_key_from_the_directory_but_keeps_the_addresses() {
        // Rejoin is for a suspected-compromised key: the old key must stop
        // being handed out as a peer at once, not when (or if) the real
        // machine gets around to re-registering.
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "joinhash1", None).unwrap();
        register(&conn, id, "pk-old", "bearer-old");
        set_transit_approved(&conn, id, true).unwrap();

        reissue_join_token(&conn, id, "joinhash2", None).unwrap();

        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert!(row.pubkey.is_none(), "the old key must be gone");
        assert!(!row.transit_approved, "approval belonged to the old identity");
        assert_eq!(row.ip4.as_deref(), Some("100.90.0.1"), "addresses survive rejoin");
        assert!(find_by_bearer_hash(&conn, "bearer-old").unwrap().is_none());
        assert!(list_all_peers(&conn).unwrap().is_empty(), "no longer a peer of anyone");

        register(&conn, id, "pk-new", "bearer-new");
        let peers = list_all_peers(&conn).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].pubkey.as_deref(), Some("pk-new"));
        assert_eq!(peers[0].ip4.as_deref(), Some("100.90.0.1"));
    }

    #[tokio::test]
    async fn transit_approval_is_off_by_default_and_toggles_idempotently() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "joinhash1", None).unwrap();
        assert!(!find_by_id(&conn, id).unwrap().unwrap().transit_approved);

        set_transit_approved(&conn, id, true).unwrap();
        set_transit_approved(&conn, id, true).unwrap();
        assert!(find_by_id(&conn, id).unwrap().unwrap().transit_approved);

        set_transit_approved(&conn, id, false).unwrap();
        set_transit_approved(&conn, id, false).unwrap();
        assert!(!find_by_id(&conn, id).unwrap().unwrap().transit_approved);
    }

    #[tokio::test]
    async fn revoke_withdraws_transit_approval() {
        // Otherwise a revoke followed by rejoin + register would bring the
        // node back as an approved carrier nobody re-approved.
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "joinhash1", None).unwrap();
        register(&conn, id, "pk1", "bearer1");
        set_transit_approved(&conn, id, true).unwrap();

        revoke(&conn, id).unwrap();

        assert!(!find_by_id(&conn, id).unwrap().unwrap().transit_approved);
    }

    #[tokio::test]
    async fn export_via_gateway_is_off_by_default_and_survives_revoke_and_rejoin() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "joinhash1", None).unwrap();
        register(&conn, id, "pk1", "bearer1");
        assert!(!find_by_id(&conn, id).unwrap().unwrap().export_via_gateway);

        set_export_via_gateway(&conn, id, true).unwrap();
        set_export_via_gateway(&conn, id, true).unwrap();
        assert!(find_by_id(&conn, id).unwrap().unwrap().export_via_gateway);

        // Whether the node can be dialled from outside is about its network,
        // not its key: neither a new key nor a revoke changes that.
        reissue_join_token(&conn, id, "joinhash2", None).unwrap();
        assert!(find_by_id(&conn, id).unwrap().unwrap().export_via_gateway);
        revoke(&conn, id).unwrap();
        assert!(find_by_id(&conn, id).unwrap().unwrap().export_via_gateway);

        set_export_via_gateway(&conn, id, false).unwrap();
        set_export_via_gateway(&conn, id, false).unwrap();
        assert!(!find_by_id(&conn, id).unwrap().unwrap().export_via_gateway);
    }

    #[tokio::test]
    async fn via_gateway_names_the_devices_a_refresh_would_change() {
        let db = test_db();
        let mut conn = db.conn.lock().await;
        let gw = create_node(&conn, "gw", NodeKind::Agent, "h-gw", None).unwrap();
        let home = create_node(&conn, "home", NodeKind::Agent, "h-home", None).unwrap();
        let dials = create_node(&conn, "dials-home", NodeKind::Static, "h-p1", None).unwrap();
        let routed = create_node(&conn, "routed", NodeKind::Static, "h-p2", None).unwrap();
        let no_gw = create_node(&conn, "no-gateway", NodeKind::Static, "h-p3", None).unwrap();
        set_gateway(&mut conn, dials, Some(gw), &[home], false).unwrap();
        set_gateway(&mut conn, routed, Some(gw), &[], false).unwrap();
        set_gateway(&mut conn, no_gw, None, &[gw, home], false).unwrap();

        // On: only a device that both dials `home` and has a gateway to fall
        // back on. The gateway-less one keeps its direct entry regardless.
        assert_eq!(static_nodes_affected_by_via_gateway(&conn, home, true).unwrap(), vec!["dials-home"]);
        // Off: devices that reach `home` through a gateway today and would
        // get a direct entry on their next export.
        assert_eq!(static_nodes_affected_by_via_gateway(&conn, home, false).unwrap(), vec!["routed"]);
        // A device's own gateway is never a direct entry to add or remove.
        assert!(static_nodes_affected_by_via_gateway(&conn, gw, false).unwrap().is_empty());
    }

    #[tokio::test]
    async fn clear_endpoint_removes_only_the_endpoint() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1", None).unwrap();
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk1",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: Some("1.2.3.4:51820"),
                bearer_token_hash: "bearerhash1",
                endpoint_addr_v4: None,
                endpoint_addr_v6: None,
                lan_addr: None,
                reflexive_addr: None,
            },
        )
        .unwrap();

        clear_endpoint(&conn, id, None).unwrap();

        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert!(row.endpoint_addr.is_none());
        // Everything else about the node survives — this is not a revoke.
        assert_eq!(row.listen_port, Some(51820));
        assert!(!row.revoked);
        assert!(find_by_bearer_hash(&conn, "bearerhash1").unwrap().is_some());
    }

    #[tokio::test]
    async fn a_poll_that_omits_an_endpoint_does_not_resurrect_a_cleared_one() {
        // The COALESCE in `update_poll_state` means "no opinion", so a
        // cleared endpoint must stay cleared until the node actually
        // reports one. (The node re-asserting a locally-configured
        // endpoint is the documented limitation, covered separately.)
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1", None).unwrap();
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk1",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: Some("1.2.3.4:51820"),
                bearer_token_hash: "bearerhash1",
                endpoint_addr_v4: None,
                endpoint_addr_v6: None,
                lan_addr: None,
                reflexive_addr: None,
            },
        )
        .unwrap();
        clear_endpoint(&conn, id, None).unwrap();

        update_poll_state(
            &conn,
            id,
            &EndpointUpdate {
                explicit: None,
                reset_cleared: false,
                v4: None,
                v6: None,
                lan: None,
                reflexive: None,
            },
        )
        .unwrap();
        assert!(find_by_name(&conn, "n1").unwrap().unwrap().endpoint_addr.is_none());

        update_poll_state(
            &conn,
            id,
            &EndpointUpdate {
                explicit: Some("5.6.7.8:51820"),
                reset_cleared: true,
                v4: None,
                v6: None,
                lan: None,
                reflexive: None,
            },
        )
        .unwrap();
        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert_eq!(
            row.endpoint_addr.as_deref(),
            Some("5.6.7.8:51820"),
            "a node that does report an endpoint still sets it"
        );
        assert!(
            !row.endpoint_cleared,
            "an explicit report resets the cleared flag too"
        );
    }

    #[tokio::test]
    async fn clear_endpoint_can_target_a_single_family() {
        // The direct regression test for the incident this feature
        // exists to fix: an admin clearing a specific stale family (say,
        // v6 stopped working) must not also wipe the still-good v4
        // candidate or the unrelated singular override.
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1", None).unwrap();
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk1",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: Some("explicit.example.com:51820"),
                bearer_token_hash: "bearerhash1",
                endpoint_addr_v4: Some("203.0.113.5:51820"),
                endpoint_addr_v6: Some("[2001:db8::1]:51820"),
                lan_addr: None,
                reflexive_addr: None,
            },
        )
        .unwrap();

        clear_endpoint(&conn, id, Some(EndpointFamily::V6)).unwrap();

        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert_eq!(row.endpoint_addr_v4.as_deref(), Some("203.0.113.5:51820"));
        assert!(row.endpoint_addr_v6.is_none());
        assert_eq!(
            row.endpoint_addr.as_deref(),
            Some("explicit.example.com:51820"),
            "a family-scoped clear leaves the singular override alone"
        );
    }

    #[tokio::test]
    async fn update_poll_state_coalesces_v4_and_v6_independently() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1", None).unwrap();
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk1",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: None,
                bearer_token_hash: "bearerhash1",
                endpoint_addr_v4: Some("203.0.113.5:51820"),
                endpoint_addr_v6: None,
                lan_addr: None,
                reflexive_addr: None,
            },
        )
        .unwrap();

        // A poll that only succeeded probing v6 this cycle must not erase
        // the v4 candidate learned earlier.
        update_poll_state(
            &conn,
            id,
            &EndpointUpdate {
                explicit: None,
                reset_cleared: false,
                v4: None,
                v6: Some("[2001:db8::1]:51820"),
                lan: None,
                reflexive: None,
            },
        )
        .unwrap();

        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert_eq!(
            row.endpoint_addr_v4.as_deref(),
            Some("203.0.113.5:51820"),
            "an omitted v4 this cycle preserves the earlier one"
        );
        assert_eq!(row.endpoint_addr_v6.as_deref(), Some("[2001:db8::1]:51820"));
    }

    // ---- NAT-hairpin fix: lan_addr (PLAN.md decisions log #85) ----

    #[tokio::test]
    async fn apply_redemption_stores_lan_addr() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1", None).unwrap();
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk1",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: None,
                bearer_token_hash: "bearerhash1",
                endpoint_addr_v4: None,
                endpoint_addr_v6: None,
                lan_addr: Some("192.168.1.50"),
                reflexive_addr: None,
            },
        )
        .unwrap();

        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert_eq!(row.lan_addr.as_deref(), Some("192.168.1.50"));
    }

    #[tokio::test]
    async fn apply_redemption_stores_reflexive_addr() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1", None).unwrap();
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk1",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: None,
                bearer_token_hash: "bearerhash1",
                endpoint_addr_v4: None,
                endpoint_addr_v6: None,
                lan_addr: None,
                reflexive_addr: Some("203.0.113.5:55123"),
            },
        )
        .unwrap();

        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert_eq!(row.reflexive_addr.as_deref(), Some("203.0.113.5:55123"));
    }

    #[tokio::test]
    async fn update_poll_state_coalesces_lan_addr_independently_of_v4_v6() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1", None).unwrap();
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk1",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: None,
                bearer_token_hash: "bearerhash1",
                endpoint_addr_v4: Some("203.0.113.5:51820"),
                endpoint_addr_v6: None,
                lan_addr: Some("192.168.1.50"),
                reflexive_addr: None,
            },
        )
        .unwrap();

        // A poll that couldn't read its own interfaces this cycle omits
        // lan_addr — it must not erase the previously reported one, same
        // COALESCE contract as v4/v6, and independent of them.
        update_poll_state(
            &conn,
            id,
            &EndpointUpdate {
                explicit: None,
                reset_cleared: false,
                v4: None,
                v6: Some("[2001:db8::1]:51820"),
                lan: None,
                reflexive: None,
            },
        )
        .unwrap();

        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert_eq!(
            row.lan_addr.as_deref(),
            Some("192.168.1.50"),
            "an omitted lan_addr this cycle preserves the earlier one"
        );
        assert_eq!(row.endpoint_addr_v6.as_deref(), Some("[2001:db8::1]:51820"));
    }

    #[tokio::test]
    async fn update_poll_state_coalesces_reflexive_addr_independently_of_v4_v6_and_lan() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1", None).unwrap();
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk1",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: None,
                bearer_token_hash: "bearerhash1",
                endpoint_addr_v4: Some("203.0.113.5:51820"),
                endpoint_addr_v6: None,
                lan_addr: Some("192.168.1.50"),
                reflexive_addr: Some("203.0.113.5:55123"),
            },
        )
        .unwrap();

        // A cycle that can't (re-)probe omits reflexive — it must not
        // erase the previously learned value, and must not disturb v4/
        // lan_addr either.
        update_poll_state(
            &conn,
            id,
            &EndpointUpdate {
                explicit: None,
                reset_cleared: false,
                v4: None,
                v6: Some("[2001:db8::1]:51820"),
                lan: None,
                reflexive: None,
            },
        )
        .unwrap();

        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert_eq!(
            row.reflexive_addr.as_deref(),
            Some("203.0.113.5:55123"),
            "an omitted reflexive_addr this cycle preserves the earlier one"
        );
        assert_eq!(row.lan_addr.as_deref(), Some("192.168.1.50"));
        assert_eq!(row.endpoint_addr_v4.as_deref(), Some("203.0.113.5:51820"));
    }

    #[tokio::test]
    async fn clear_endpoint_none_also_clears_lan_and_reflexive_addr() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1", None).unwrap();
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk1",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: Some("explicit.example.com:51820"),
                bearer_token_hash: "bearerhash1",
                endpoint_addr_v4: Some("203.0.113.5:51820"),
                endpoint_addr_v6: Some("[2001:db8::1]:51820"),
                lan_addr: Some("192.168.1.50"),
                reflexive_addr: Some("203.0.113.5:55123"),
            },
        )
        .unwrap();

        clear_endpoint(&conn, id, None).unwrap();

        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert!(row.lan_addr.is_none());
        assert!(row.reflexive_addr.is_none());
    }

    #[tokio::test]
    async fn cascade_delete_removes_services_on_revoke() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1", None).unwrap();
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: "pk1",
                ip4: "100.90.0.1".parse().unwrap(),
                ip6: "fd00:90::1".parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: None,
                bearer_token_hash: "bearerhash1",
                endpoint_addr_v4: None,
                endpoint_addr_v6: None,
                lan_addr: None,
                reflexive_addr: None,
            },
        )
        .unwrap();
        conn.execute(
            "INSERT INTO services (node_id, name, port, proto) VALUES (?1, 'svc', 80, 'tcp')",
            [id],
        )
        .unwrap();
        let count_before: i64 = conn
            .query_row("SELECT COUNT(*) FROM services", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count_before, 1);

        revoke(&conn, id).unwrap();

        let count_after: i64 = conn
            .query_row("SELECT COUNT(*) FROM services", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count_after, 0, "PRAGMA foreign_keys must be ON for cascade delete to fire");
    }
}
