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

/// Maps a UNIQUE-constraint SQLite error into `DbError::NameTaken`; any
/// other error passes through unchanged.
fn map_unique_violation(err: rusqlite::Error) -> DbError {
    if let rusqlite::Error::SqliteFailure(ref e, _) = err {
        if e.code == rusqlite::ErrorCode::ConstraintViolation {
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
) -> Result<i64, DbError> {
    conn.execute(
        "INSERT INTO nodes (name, kind, join_token_hash, join_token_used) \
         VALUES (?1, ?2, ?3, 0)",
        rusqlite::params![name, kind.as_str(), join_token_hash],
    )
    .map_err(map_unique_violation)?;
    Ok(conn.last_insert_rowid())
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
    conn.query_row(
        "SELECT * FROM nodes WHERE join_token_hash = ?1 AND join_token_used = 0",
        [hash],
        map_row,
    )
    .optional()
    .map_err(DbError::from)
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
/// 401), marks it revoked, and removes its `services` rows.
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
pub fn revoke(conn: &Connection, node_id: i64) -> Result<(), DbError> {
    conn.execute(
        "UPDATE nodes SET revoked = 1, revoked_at = ?1, bearer_token_hash = NULL \
         WHERE id = ?2",
        rusqlite::params![now_str(), node_id],
    )?;
    conn.execute("DELETE FROM services WHERE node_id = ?1", [node_id])?;
    Ok(())
}

/// Issues a fresh one-time join token for an existing node record (spec
/// §4.5). Does NOT clear `revoked` — see `apply_redemption`.
pub fn reissue_join_token(
    conn: &Connection,
    node_id: i64,
    join_token_hash: &str,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE nodes SET join_token_hash = ?1, join_token_used = 0 WHERE id = ?2",
        rusqlite::params![join_token_hash, node_id],
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
        create_node(&conn, "homeserver", NodeKind::Agent, "hash1").unwrap();
        let row = find_by_name(&conn, "homeserver").unwrap().unwrap();
        assert_eq!(row.name, "homeserver");
        assert!(!row.revoked);
        assert!(row.pubkey.is_none());
    }

    #[tokio::test]
    async fn duplicate_name_is_rejected() {
        let db = test_db();
        let conn = db.conn.lock().await;
        create_node(&conn, "dup", NodeKind::Agent, "hash1").unwrap();
        let err = create_node(&conn, "dup", NodeKind::Agent, "hash2").unwrap_err();
        assert!(matches!(err, DbError::NameTaken));
    }

    #[tokio::test]
    async fn join_token_is_single_use() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1").unwrap();
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
    async fn revoke_clears_bearer_token_and_sets_flag() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1").unwrap();
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
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1").unwrap();
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

        reissue_join_token(&conn, id, "hash2").unwrap();
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
    async fn cascade_delete_removes_services_on_revoke() {
        let db = test_db();
        let conn = db.conn.lock().await;
        let id = create_node(&conn, "n1", NodeKind::Agent, "hash1").unwrap();
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
