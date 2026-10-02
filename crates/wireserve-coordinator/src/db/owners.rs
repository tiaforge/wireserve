//! Device owners and claim links (PLAN.md M38, migration 0018).

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, OptionalExtension};

use super::DbError;

/// Groups stop counting once refreshing has failed for this long.
pub const STALE_AFTER: Duration = Duration::hours(1);

/// How long a claim link works.
pub const CLAIM_TTL: Duration = Duration::minutes(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub node_id: i64,
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub groups: Vec<String>,
    /// Sealed; see `oidc::seal`.
    pub refresh_token_enc: String,
    pub refreshed_at: DateTime<Utc>,
    pub stale_since: Option<DateTime<Utc>>,
}

impl Owner {
    /// Whether the groups still count, `now`.
    #[must_use]
    pub fn groups_count(&self, now: DateTime<Utc>) -> bool {
        self.stale_since.is_none_or(|since| now - since < STALE_AFTER)
    }
}

fn parse_dt(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))
}

fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Owner> {
    let groups: String = row.get("groups")?;
    Ok(Owner {
        node_id: row.get("node_id")?,
        sub: row.get("sub")?,
        email: row.get("email")?,
        name: row.get("name")?,
        groups: serde_json::from_str(&groups).unwrap_or_default(),
        refresh_token_enc: row.get("refresh_token_enc")?,
        refreshed_at: row.get::<_, String>("refreshed_at").ok().as_deref().and_then(parse_dt).unwrap_or_default(),
        stale_since: row.get::<_, Option<String>>("stale_since")?.as_deref().and_then(parse_dt),
    })
}

pub fn all(conn: &Connection) -> Result<Vec<Owner>, DbError> {
    let mut stmt = conn.prepare("SELECT * FROM node_owners")?;
    let rows = stmt.query_map([], map_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub fn of(conn: &Connection, node_id: i64) -> Result<Option<Owner>, DbError> {
    Ok(conn.query_row("SELECT * FROM node_owners WHERE node_id = ?1", [node_id], map_row).optional()?)
}

/// Each node's owner's groups, where they still count.
pub fn groups_by_node(conn: &Connection, now: DateTime<Utc>) -> Result<BTreeMap<i64, BTreeSet<String>>, DbError> {
    Ok(all(conn)?
        .into_iter()
        .filter(|o| o.groups_count(now))
        .map(|o| (o.node_id, o.groups.into_iter().collect()))
        .collect())
}

/// Makes `owner` the node's owner, replacing whoever was.
pub fn set(conn: &Connection, owner: &Owner) -> Result<(), DbError> {
    let now = super::nodes::now_str();
    conn.execute(
        "INSERT INTO node_owners (node_id, sub, email, name, groups, refresh_token_enc, claimed_at, refreshed_at, stale_since) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, NULL) \
         ON CONFLICT(node_id) DO UPDATE SET sub = excluded.sub, email = excluded.email, name = excluded.name, \
           groups = excluded.groups, refresh_token_enc = excluded.refresh_token_enc, \
           claimed_at = excluded.claimed_at, refreshed_at = excluded.refreshed_at, stale_since = NULL",
        rusqlite::params![
            owner.node_id,
            owner.sub,
            owner.email,
            owner.name,
            serde_json::to_string(&owner.groups).expect("strings serialize"),
            owner.refresh_token_enc,
            now,
        ],
    )?;
    Ok(())
}

/// A successful refresh: new groups, the (possibly rotated) token, fresh.
/// Only while the node still has that same owner — a claim may have
/// replaced it while the refresh was in flight.
///
/// `email`: the refreshed ID token's verified email (PLAN.md #275) — `""`
/// when it has none, which clears the one stored; `None` when there was no
/// ID token, which leaves it.
pub fn refreshed(
    conn: &Connection,
    node_id: i64,
    sub: &str,
    groups: &[String],
    token_enc: &str,
    email: Option<&str>,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE node_owners SET groups = ?1, refresh_token_enc = ?2, refreshed_at = ?3, stale_since = NULL, \
         email = CASE WHEN ?6 IS NULL THEN email ELSE NULLIF(?6, '') END \
         WHERE node_id = ?4 AND sub = ?5",
        rusqlite::params![
            serde_json::to_string(groups).expect("strings serialize"),
            token_enc,
            super::nodes::now_str(),
            node_id,
            sub,
            email
        ],
    )?;
    Ok(())
}

/// A refresh that failed for a reason other than the provider refusing
/// the token: marks the owner stale, from the first failure on.
pub fn refresh_failed(conn: &Connection, node_id: i64, sub: &str) -> Result<(), DbError> {
    conn.execute(
        "UPDATE node_owners SET stale_since = COALESCE(stale_since, ?1) WHERE node_id = ?2 AND sub = ?3",
        rusqlite::params![super::nodes::now_str(), node_id, sub],
    )?;
    Ok(())
}

/// Removes the node's owner (if it is still `sub`, when given) and its
/// outstanding claim links. `true` when there was an owner to remove.
pub fn remove(conn: &Connection, node_id: i64, sub: Option<&str>) -> Result<bool, DbError> {
    let n = match sub {
        Some(sub) => conn.execute("DELETE FROM node_owners WHERE node_id = ?1 AND sub = ?2", rusqlite::params![node_id, sub])?,
        None => conn.execute("DELETE FROM node_owners WHERE node_id = ?1", [node_id])?,
    };
    Ok(n == 1)
}

/// The node's owner and every claim link for it, gone — on revoke and
/// rejoin, whose new identity may be another device.
pub fn forget(conn: &Connection, node_id: i64) -> Result<(), DbError> {
    conn.execute("DELETE FROM node_owners WHERE node_id = ?1", [node_id])?;
    conn.execute("DELETE FROM claims WHERE node_id = ?1", [node_id])?;
    Ok(())
}

/// Stores a new claim link's code hash for `node_id`, valid for
/// [`CLAIM_TTL`]; returns when it expires. Expired and used ones are swept
/// on the way.
pub fn create_claim(conn: &Connection, node_id: i64, code_hash: &str) -> Result<DateTime<Utc>, DbError> {
    let now = Utc::now();
    conn.execute("DELETE FROM claims WHERE used = 1 OR expires_at < ?1", [now.to_rfc3339()])?;
    let expires = now + CLAIM_TTL;
    conn.execute(
        "INSERT INTO claims (code_hash, node_id, expires_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![code_hash, node_id, expires.to_rfc3339()],
    )?;
    Ok(expires)
}

/// The node a claim link is for, while it is unused and unexpired. Does not
/// use it up: a link previewer opening it must not spend it.
pub fn claim_node(conn: &Connection, code_hash: &str) -> Result<Option<i64>, DbError> {
    let row: Option<(i64, String)> = conn
        .query_row("SELECT node_id, expires_at FROM claims WHERE code_hash = ?1 AND used = 0", [code_hash], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    Ok(row.and_then(|(node, expires)| (parse_dt(&expires)? > Utc::now()).then_some(node)))
}

/// Uses a claim link up, once: `true` only for the one caller that does.
pub fn use_claim(conn: &Connection, code_hash: &str, node_id: i64) -> Result<bool, DbError> {
    let n = conn.execute(
        "UPDATE claims SET used = 1 WHERE code_hash = ?1 AND node_id = ?2 AND used = 0 AND expires_at > ?3",
        rusqlite::params![code_hash, node_id, Utc::now().to_rfc3339()],
    )?;
    Ok(n == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    async fn node(db: &Db, name: &str) -> i64 {
        let conn = db.conn.lock().await;
        crate::db::nodes::create_node(&conn, name, wireserve_types::NodeKind::Agent, &format!("h-{name}"), None).unwrap()
    }

    fn owner(node_id: i64, sub: &str, groups: &[&str]) -> Owner {
        Owner {
            node_id,
            sub: sub.into(),
            email: Some(format!("{sub}@example.com")),
            name: None,
            groups: groups.iter().map(|g| (*g).to_string()).collect(),
            refresh_token_enc: "sealed".into(),
            refreshed_at: Utc::now(),
            stale_since: None,
        }
    }

    #[tokio::test]
    async fn a_claim_link_works_once_and_only_for_its_node() {
        let db = Db::open_in_memory_for_test();
        let a = node(&db, "a").await;
        let b = node(&db, "b").await;
        let conn = db.conn.lock().await;
        create_claim(&conn, a, "h1").unwrap();
        assert_eq!(claim_node(&conn, "h1").unwrap(), Some(a));
        assert_eq!(claim_node(&conn, "h1").unwrap(), Some(a), "looking does not use it up");
        assert!(!use_claim(&conn, "h1", b).unwrap(), "not for another node");
        assert!(use_claim(&conn, "h1", a).unwrap());
        assert!(!use_claim(&conn, "h1", a).unwrap(), "once");
        assert_eq!(claim_node(&conn, "h1").unwrap(), None);
        conn.execute("INSERT INTO claims (code_hash, node_id, expires_at) VALUES ('old', ?1, '2020-01-01T00:00:00Z')", [a])
            .unwrap();
        assert_eq!(claim_node(&conn, "old").unwrap(), None, "expired");
        assert!(!use_claim(&conn, "old", a).unwrap());
    }

    #[tokio::test]
    async fn owners_are_replaced_refreshed_and_go_stale() {
        let db = Db::open_in_memory_for_test();
        let a = node(&db, "a").await;
        let conn = db.conn.lock().await;
        set(&conn, &owner(a, "alice", &["family"])).unwrap();
        set(&conn, &owner(a, "bob", &["guests"])).unwrap();
        assert_eq!(of(&conn, a).unwrap().unwrap().sub, "bob", "one owner, the latest");

        refreshed(&conn, a, "alice", &["admins".into()], "x", None).unwrap();
        assert_eq!(of(&conn, a).unwrap().unwrap().groups, ["guests"], "a refresh for a replaced owner changes nothing");
        refreshed(&conn, a, "bob", &["family".into()], "rotated", None).unwrap();
        let o = of(&conn, a).unwrap().unwrap();
        assert_eq!((o.groups.as_slice(), o.refresh_token_enc.as_str()), (&["family".to_string()][..], "rotated"));

        refresh_failed(&conn, a, "bob").unwrap();
        let o = of(&conn, a).unwrap().unwrap();
        assert!(o.groups_count(Utc::now()), "stale, but not for long yet");
        assert!(!o.groups_count(Utc::now() + Duration::hours(2)));
        assert!(groups_by_node(&conn, Utc::now() + Duration::hours(2)).unwrap().is_empty());
        refreshed(&conn, a, "bob", &["family".into()], "again", None).unwrap();
        assert!(of(&conn, a).unwrap().unwrap().stale_since.is_none());

        // The email follows the refreshed ID token (PLAN.md #275): none
        // there leaves it, a verified one replaces it, none verified clears it.
        let email = |conn: &Connection| of(conn, a).unwrap().unwrap().email;
        let before = email(&conn);
        refreshed(&conn, a, "bob", &["family".into()], "t", None).unwrap();
        assert_eq!(email(&conn), before);
        refreshed(&conn, a, "bob", &["family".into()], "t", Some("bob@example.com")).unwrap();
        assert_eq!(email(&conn).as_deref(), Some("bob@example.com"));
        refreshed(&conn, a, "bob", &["family".into()], "t", Some("")).unwrap();
        assert_eq!(email(&conn), None);
    }

    #[tokio::test]
    async fn revoke_and_rejoin_forget_the_owner_and_its_links() {
        let db = Db::open_in_memory_for_test();
        let a = node(&db, "a").await;
        let conn = db.conn.lock().await;
        set(&conn, &owner(a, "alice", &["family"])).unwrap();
        create_claim(&conn, a, "h1").unwrap();
        crate::db::nodes::reissue_join_token(&conn, a, "new-hash", None).unwrap();
        assert!(of(&conn, a).unwrap().is_none());
        assert_eq!(claim_node(&conn, "h1").unwrap(), None);
        set(&conn, &owner(a, "alice", &["family"])).unwrap();
        crate::db::nodes::revoke(&conn, a).unwrap();
        assert!(of(&conn, a).unwrap().is_none());
    }
}
