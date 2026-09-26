//! Per-node TLS termination bookkeeping (PLAN.md M33): which services their
//! own node reports serving with TLS, and the ACME challenge records nodes
//! asked the coordinator to publish.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use rusqlite::Connection;

use super::DbError;

/// Every service reported ready, by name, with the node that reported it.
pub fn ready(conn: &Connection) -> Result<HashMap<String, i64>, DbError> {
    let mut stmt = conn.prepare("SELECT name, node_id FROM tls_ready")?;
    let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Replaces `node_id`'s report with `names`. A name the node does not own
/// is dropped: a node vouches only for its own services.
pub fn set_ready(conn: &mut Connection, node_id: i64, names: &[String]) -> Result<(), DbError> {
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM tls_ready WHERE node_id = ?1", [node_id])?;
    let now = super::nodes::now_str();
    for name in names {
        tx.execute(
            "INSERT INTO tls_ready (name, node_id, reported_at)
             SELECT name, node_id, ?3 FROM services WHERE name = ?1 AND node_id = ?2
             ON CONFLICT(name) DO UPDATE SET node_id = excluded.node_id, reported_at = excluded.reported_at",
            rusqlite::params![name, node_id, now],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Forgets everything `node_id` reported: on revoke and on re-join, when
/// the key that made the report is no longer the node's.
pub fn clear_node(conn: &Connection, node_id: i64) -> Result<(), DbError> {
    conn.execute("DELETE FROM tls_ready WHERE node_id = ?1", [node_id])?;
    conn.execute("UPDATE acme_challenges SET expires_at = ?2 WHERE node_id = ?1", rusqlite::params![node_id, super::nodes::now_str()])?;
    Ok(())
}

/// One challenge value a node asked to have published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The record's own name, `_acme-challenge.<service fqdn>`.
    pub fqdn: String,
    pub value: String,
    pub node_id: i64,
    pub expires_at: DateTime<Utc>,
    pub written: bool,
}

/// At most this many values are outstanding for one name: one order, plus
/// one overlapping it (a renewal racing a retry). More is a node looping.
pub const MAX_CHALLENGES_PER_NAME: usize = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum AddOutcome {
    Added,
    /// Already there; its expiry was pushed out.
    Refreshed,
    TooMany,
}

pub fn add_challenge(
    conn: &Connection,
    fqdn: &str,
    value: &str,
    node_id: i64,
    expires_at: DateTime<Utc>,
) -> Result<AddOutcome, DbError> {
    let now = Utc::now();
    let live: Vec<(String, String)> = {
        let mut stmt = conn.prepare("SELECT value, expires_at FROM acme_challenges WHERE fqdn = ?1")?;
        let rows = stmt.query_map([fqdn], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    if live.iter().any(|(v, _)| v == value) {
        conn.execute(
            "UPDATE acme_challenges SET expires_at = ?3 WHERE fqdn = ?1 AND value = ?2",
            rusqlite::params![fqdn, value, expires_at.to_rfc3339()],
        )?;
        return Ok(AddOutcome::Refreshed);
    }
    let unexpired = live.iter().filter(|(_, e)| parse(e).is_some_and(|e| e > now)).count();
    if unexpired >= MAX_CHALLENGES_PER_NAME {
        return Ok(AddOutcome::TooMany);
    }
    conn.execute(
        "INSERT INTO acme_challenges (fqdn, value, node_id, expires_at) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![fqdn, value, node_id, expires_at.to_rfc3339()],
    )?;
    Ok(AddOutcome::Added)
}

/// Marks a value done: the DNS sync removes it on its next pass. Only the
/// node that added it may.
pub fn expire_challenge(conn: &Connection, fqdn: &str, value: &str, node_id: i64) -> Result<bool, DbError> {
    let n = conn.execute(
        "UPDATE acme_challenges SET expires_at = ?4 WHERE fqdn = ?1 AND value = ?2 AND node_id = ?3",
        rusqlite::params![fqdn, value, node_id, super::nodes::now_str()],
    )?;
    Ok(n > 0)
}

pub fn challenges(conn: &Connection) -> Result<Vec<Challenge>, DbError> {
    let mut stmt =
        conn.prepare("SELECT fqdn, value, node_id, expires_at, written_at IS NOT NULL FROM acme_challenges")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, bool>(4)?,
        ))
    })?;
    Ok(rows
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|(fqdn, value, node_id, expires, written)| Challenge {
            fqdn,
            value,
            node_id,
            // An unreadable timestamp counts as already expired: removing a
            // record early costs one retried validation, keeping it forever
            // costs a stray TXT record.
            expires_at: parse(&expires).unwrap_or(DateTime::<Utc>::MIN_UTC),
            written,
        })
        .collect())
}

pub fn mark_written(conn: &Connection, fqdn: &str, value: &str) -> Result<(), DbError> {
    conn.execute(
        "UPDATE acme_challenges SET written_at = ?3 WHERE fqdn = ?1 AND value = ?2",
        rusqlite::params![fqdn, value, super::nodes::now_str()],
    )?;
    Ok(())
}

pub fn delete_challenge(conn: &Connection, fqdn: &str, value: &str) -> Result<(), DbError> {
    conn.execute("DELETE FROM acme_challenges WHERE fqdn = ?1 AND value = ?2", rusqlite::params![fqdn, value])?;
    Ok(())
}

fn parse(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn node_with_service(conn: &Connection, name: &str, service: &str) -> i64 {
        conn.execute("INSERT INTO nodes (name, kind, created_at) VALUES (?1, 'agent', ?2)", rusqlite::params![name, crate::db::nodes::now_str()])
            .unwrap();
        let id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO services (node_id, name, port, proto, declared_at, approved_at) VALUES (?1, ?2, 443, 'tcp', ?3, ?3)",
            rusqlite::params![id, service, crate::db::nodes::now_str()],
        )
        .unwrap();
        id
    }

    #[test]
    fn a_node_vouches_only_for_its_own_services_and_a_new_report_replaces_the_old() {
        let db = Db::open_in_memory_for_test();
        let mut conn = db.conn.blocking_lock();
        let a = node_with_service(&conn, "a", "plex");
        let b = node_with_service(&conn, "b", "git");
        set_ready(&mut conn, a, &["plex".into(), "git".into()]).unwrap();
        assert_eq!(ready(&conn).unwrap(), HashMap::from([("plex".to_string(), a)]));
        set_ready(&mut conn, b, &["git".into()]).unwrap();
        set_ready(&mut conn, a, &[]).unwrap();
        assert_eq!(ready(&conn).unwrap(), HashMap::from([("git".to_string(), b)]));
        clear_node(&conn, b).unwrap();
        assert!(ready(&conn).unwrap().is_empty());
    }

    #[test]
    fn challenges_are_capped_per_name_and_only_their_node_expires_them() {
        let db = Db::open_in_memory_for_test();
        let conn = db.conn.blocking_lock();
        let a = node_with_service(&conn, "a", "plex");
        let later = Utc::now() + chrono::Duration::minutes(10);
        let f = "_acme-challenge.plex.int.test";
        assert_eq!(add_challenge(&conn, f, "v1", a, later).unwrap(), AddOutcome::Added);
        assert_eq!(add_challenge(&conn, f, "v1", a, later).unwrap(), AddOutcome::Refreshed);
        assert_eq!(add_challenge(&conn, f, "v2", a, later).unwrap(), AddOutcome::Added);
        assert_eq!(add_challenge(&conn, f, "v3", a, later).unwrap(), AddOutcome::TooMany);

        assert!(!expire_challenge(&conn, f, "v1", a + 1).unwrap(), "another node cannot");
        assert!(expire_challenge(&conn, f, "v1", a).unwrap());
        // An expired one no longer counts against the cap.
        assert_eq!(add_challenge(&conn, f, "v3", a, later).unwrap(), AddOutcome::Added);
        assert_eq!(challenges(&conn).unwrap().len(), 3);
    }
}
