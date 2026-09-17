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
    pub listen_port: Option<i64>,
    pub revoked: bool,
    pub last_seen: Option<DateTime<Utc>>,
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
        listen_port: row.get("listen_port")?,
        revoked: row.get("revoked")?,
        last_seen: last_seen_str.and_then(|s| parse_dt(&s)),
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
         join_token_used = 1, revoked = 0, revoked_at = NULL \
         WHERE id = ?7",
        rusqlite::params![
            r.pubkey,
            r.ip4.to_string(),
            r.ip6.to_string(),
            r.listen_port,
            r.endpoint_addr,
            r.bearer_token_hash,
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

pub fn update_poll_state(
    conn: &Connection,
    node_id: i64,
    endpoint_addr: Option<&str>,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE nodes SET last_seen = ?1, endpoint_addr = COALESCE(?2, endpoint_addr) \
         WHERE id = ?3",
        rusqlite::params![now_str(), endpoint_addr, node_id],
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
         join_token_hash = NULL, join_token_used = 1 \
         WHERE id = ?2",
        rusqlite::params![now_str(), node_id],
    )?;
    tx.execute("DELETE FROM services WHERE node_id = ?1", [node_id])?;
    tx.commit()?;
    Ok(())
}

/// Issues a fresh one-time join token for an existing node record (spec
/// §4.5). Does NOT clear `revoked` — see `apply_redemption`.
pub fn reissue_join_token(
    conn: &Connection,
    node_id: i64,
    join_token_hash: &str,
    join_token_expires_at: Option<&str>,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE nodes SET join_token_hash = ?1, join_token_used = 0, \
         join_token_expires_at = ?2 WHERE id = ?3",
        rusqlite::params![join_token_hash, join_token_expires_at, node_id],
    )
    .map_err(map_unique_violation)?;
    Ok(())
}

/// Clears a node's current bearer token without touching `revoked` (see
/// `reissue_join_token`'s doc comment / PLAN.md decisions log — security
/// review S8). The node simply can't `/poll` until it redeems a new join
/// token via `/register`.
pub fn clear_bearer_token(conn: &Connection, node_id: i64) -> Result<(), DbError> {
    conn.execute(
        "UPDATE nodes SET bearer_token_hash = NULL WHERE id = ?1",
        [node_id],
    )?;
    Ok(())
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
pub fn clear_endpoint(conn: &Connection, node_id: i64) -> Result<(), DbError> {
    conn.execute(
        "UPDATE nodes SET endpoint_addr = NULL WHERE id = ?1",
        [node_id],
    )?;
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
/// state) — used by the IP allocator to avoid handing out a duplicate.
pub fn all_allocated_ip4(conn: &Connection) -> Result<Vec<Ipv4Addr>, DbError> {
    let mut stmt = conn.prepare("SELECT ip4 FROM nodes WHERE ip4 IS NOT NULL")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        if let Ok(addr) = r?.parse() {
            out.push(addr);
        }
    }
    Ok(out)
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
            },
        )
        .unwrap();
        let row = find_by_name(&conn, "n1").unwrap().unwrap();
        assert!(!row.revoked, "rejoin + register is still the way back in");
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
            },
        )
        .unwrap();

        clear_endpoint(&conn, id).unwrap();

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
            },
        )
        .unwrap();
        clear_endpoint(&conn, id).unwrap();

        update_poll_state(&conn, id, None).unwrap();
        assert!(find_by_name(&conn, "n1").unwrap().unwrap().endpoint_addr.is_none());

        update_poll_state(&conn, id, Some("5.6.7.8:51820")).unwrap();
        assert_eq!(
            find_by_name(&conn, "n1").unwrap().unwrap().endpoint_addr.as_deref(),
            Some("5.6.7.8:51820"),
            "a node that does report an endpoint still sets it"
        );
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
