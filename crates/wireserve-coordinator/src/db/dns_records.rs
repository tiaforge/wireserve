//! The public DNS records this coordinator wrote (PLAN.md M32). See
//! `migrations/0014_dns_records.sql` for why this table, and only this
//! table, decides what may be deleted.

use std::collections::BTreeMap;

use rusqlite::Connection;

use super::DbError;

/// Every record written so far, name to value.
pub fn all(conn: &Connection) -> Result<BTreeMap<String, String>, DbError> {
    let mut stmt = conn.prepare("SELECT fqdn, value FROM dns_records")?;
    let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Records that `fqdn` now holds `value`, after the provider accepted it.
pub fn record(conn: &Connection, fqdn: &str, value: &str) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO dns_records (fqdn, value, written_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(fqdn) DO UPDATE SET value = excluded.value, written_at = excluded.written_at",
        rusqlite::params![fqdn, value, super::nodes::now_str()],
    )?;
    Ok(())
}

/// Forgets `fqdn`, after the provider deleted it.
pub fn forget(conn: &Connection, fqdn: &str) -> Result<(), DbError> {
    conn.execute("DELETE FROM dns_records WHERE fqdn = ?1", [fqdn])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn record_overwrites_and_forget_removes() {
        let db = Db::open_in_memory_for_test();
        let conn = db.conn.blocking_lock();
        record(&conn, "plex.int.test", "10.77.0.10").unwrap();
        record(&conn, "plex.int.test", "10.77.0.11").unwrap();
        record(&conn, "prom.int.test", "10.77.0.12").unwrap();
        let rows = all(&conn).unwrap();
        assert_eq!(rows.get("plex.int.test").map(String::as_str), Some("10.77.0.11"));
        assert_eq!(rows.len(), 2);
        forget(&conn, "plex.int.test").unwrap();
        assert_eq!(all(&conn).unwrap().len(), 1);
    }
}
