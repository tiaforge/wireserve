//! Sign-in sessions and their tickets (PLAN.md M48, migration 0023).

use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, OptionalExtension};

use super::DbError;

/// How long a ticket works: the browser follows the redirect at once.
pub const TICKET_TTL: Duration = Duration::seconds(60);

/// The most sessions one person keeps (PLAN.md #313): one per browser, and
/// a new one pushes out the one least recently used. Signing in again and
/// again must not grow the table, nor the provider's own list of refresh
/// tokens it keeps.
pub const MAX_PER_PERSON: usize = 10;

/// A session nobody has used for this long is forgotten. This keeps the
/// table small; it says nothing about how fresh anyone's groups are, which
/// the refresh interval decides.
pub const IDLE_TTL: Duration = Duration::days(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub groups: Vec<String>,
    /// Sealed; see `oidc::Oidc::seal_for`.
    pub refresh_token_enc: String,
    pub created_at: DateTime<Utc>,
    pub refreshed_at: DateTime<Utc>,
    pub stale_since: Option<DateTime<Utc>>,
    pub last_used_at: DateTime<Utc>,
}

impl Session {
    /// Whether the groups still count, `now` — as for an owner.
    #[must_use]
    pub fn groups_count(&self, now: DateTime<Utc>) -> bool {
        self.stale_since.is_none_or(|since| now - since < super::owners::STALE_AFTER)
    }
}

fn parse_dt(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))
}

fn dt(row: &rusqlite::Row<'_>, col: &str) -> rusqlite::Result<DateTime<Utc>> {
    Ok(row.get::<_, String>(col).ok().as_deref().and_then(parse_dt).unwrap_or_default())
}

fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Session> {
    let groups: String = row.get("groups")?;
    Ok(Session {
        id: row.get("id")?,
        sub: row.get("sub")?,
        email: row.get("email")?,
        name: row.get("name")?,
        groups: serde_json::from_str(&groups).unwrap_or_default(),
        refresh_token_enc: row.get("refresh_token_enc")?,
        created_at: dt(row, "created_at")?,
        refreshed_at: dt(row, "refreshed_at")?,
        stale_since: row.get::<_, Option<String>>("stale_since")?.as_deref().and_then(parse_dt),
        last_used_at: dt(row, "last_used_at")?,
    })
}

/// Stores a new session, whose login cookie hashes to `login_hash`. Idle
/// sessions and spent tickets are swept on the way, and the person's least
/// recently used session goes when they have [`MAX_PER_PERSON`].
pub fn create(conn: &Connection, session: &Session, login_hash: &str) -> Result<(), DbError> {
    sweep(conn, Utc::now())?;
    let keep = i64::try_from(MAX_PER_PERSON - 1).unwrap_or(i64::MAX);
    conn.execute(
        "DELETE FROM sign_in_tickets WHERE session_id IN (SELECT id FROM sign_in_sessions WHERE sub = ?1 \
           AND id NOT IN (SELECT id FROM sign_in_sessions WHERE sub = ?1 ORDER BY last_used_at DESC LIMIT ?2))",
        rusqlite::params![session.sub, keep],
    )?;
    conn.execute(
        "DELETE FROM sign_in_sessions WHERE sub = ?1 \
           AND id NOT IN (SELECT id FROM sign_in_sessions WHERE sub = ?1 ORDER BY last_used_at DESC LIMIT ?2)",
        rusqlite::params![session.sub, keep],
    )?;
    conn.execute(
        "INSERT INTO sign_in_sessions (id, login_hash, sub, email, name, groups, refresh_token_enc, \
           created_at, refreshed_at, stale_since, last_used_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10)",
        rusqlite::params![
            session.id,
            login_hash,
            session.sub,
            session.email,
            session.name,
            serde_json::to_string(&session.groups).expect("strings serialize"),
            session.refresh_token_enc,
            session.created_at.to_rfc3339(),
            session.refreshed_at.to_rfc3339(),
            session.last_used_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn find(conn: &Connection, id: &str) -> Result<Option<Session>, DbError> {
    Ok(conn.query_row("SELECT * FROM sign_in_sessions WHERE id = ?1", [id], map_row).optional()?)
}

/// The session a browser's login cookie stands for.
pub fn find_by_login(conn: &Connection, login_hash: &str) -> Result<Option<Session>, DbError> {
    Ok(conn.query_row("SELECT * FROM sign_in_sessions WHERE login_hash = ?1", [login_hash], map_row).optional()?)
}

pub fn all(conn: &Connection) -> Result<Vec<Session>, DbError> {
    let mut stmt = conn.prepare("SELECT * FROM sign_in_sessions ORDER BY sub, created_at")?;
    let rows = stmt.query_map([], map_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// A successful refresh, as for an owner: new groups, the (possibly
/// rotated) token, fresh. `email` as in `owners::refreshed`.
pub fn refreshed(conn: &Connection, id: &str, groups: &[String], token_enc: &str, email: Option<&str>) -> Result<(), DbError> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE sign_in_sessions SET groups = ?1, refresh_token_enc = ?2, refreshed_at = ?3, last_used_at = ?3, \
           stale_since = NULL, email = CASE WHEN ?5 IS NULL THEN email ELSE NULLIF(?5, '') END \
         WHERE id = ?4",
        rusqlite::params![serde_json::to_string(groups).expect("strings serialize"), token_enc, now, id, email],
    )?;
    Ok(())
}

/// A refresh that failed for a reason other than the provider refusing
/// the token: stale from the first failure on.
pub fn refresh_failed(conn: &Connection, id: &str) -> Result<(), DbError> {
    conn.execute(
        "UPDATE sign_in_sessions SET stale_since = COALESCE(stale_since, ?1) WHERE id = ?2",
        rusqlite::params![Utc::now().to_rfc3339(), id],
    )?;
    Ok(())
}

/// Someone used the session just now.
pub fn touch(conn: &Connection, id: &str) -> Result<(), DbError> {
    conn.execute("UPDATE sign_in_sessions SET last_used_at = ?1 WHERE id = ?2", rusqlite::params![Utc::now().to_rfc3339(), id])?;
    Ok(())
}

/// Ends one session, and its tickets with it. `true` when there was one.
pub fn remove(conn: &Connection, id: &str) -> Result<bool, DbError> {
    conn.execute("DELETE FROM sign_in_tickets WHERE session_id = ?1", [id])?;
    Ok(conn.execute("DELETE FROM sign_in_sessions WHERE id = ?1", [id])? == 1)
}

/// Ends every session of the person whose subject or e-mail is `who`;
/// returns how many there were.
pub fn remove_person(conn: &Connection, who: &str) -> Result<usize, DbError> {
    conn.execute(
        "DELETE FROM sign_in_tickets WHERE session_id IN (SELECT id FROM sign_in_sessions WHERE sub = ?1 OR email = ?1)",
        [who],
    )?;
    Ok(conn.execute("DELETE FROM sign_in_sessions WHERE sub = ?1 OR email = ?1", [who])?)
}

/// Forgets idle sessions and spent tickets.
pub fn sweep(conn: &Connection, now: DateTime<Utc>) -> Result<(), DbError> {
    conn.execute("DELETE FROM sign_in_tickets WHERE expires_at < ?1", [now.to_rfc3339()])?;
    let idle = (now - IDLE_TTL).to_rfc3339();
    conn.execute("DELETE FROM sign_in_tickets WHERE session_id IN (SELECT id FROM sign_in_sessions WHERE last_used_at < ?1)", [&idle])?;
    conn.execute("DELETE FROM sign_in_sessions WHERE last_used_at < ?1", [&idle])?;
    Ok(())
}

/// A ticket, taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub session_id: String,
    /// The path on the service the browser goes on to.
    pub to: String,
    /// The hash of the bind cookie of the browser that started the sign-in.
    pub bind: String,
}

/// Stores a ticket for session `id` and the service `fqdn`, going on to
/// the path `to` there, for the browser whose bind cookie hashes to `bind`.
pub fn create_ticket(conn: &Connection, ticket_hash: &str, id: &str, fqdn: &str, to: &str, bind: &str) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO sign_in_tickets (ticket_hash, session_id, fqdn, to_path, expires_at, bind) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![ticket_hash, id, fqdn, to, (Utc::now() + TICKET_TTL).to_rfc3339(), bind],
    )?;
    Ok(())
}

/// Uses a ticket up: what it stands for, if it is unexpired and for
/// `fqdn`. A ticket presented for another service is used up all the
/// same — whoever has it is not the service it was for.
pub fn take_ticket(conn: &Connection, ticket_hash: &str, fqdn: &str) -> Result<Option<Ticket>, DbError> {
    let found: Option<(String, String, String, String, String)> = conn
        .query_row(
            "SELECT session_id, fqdn, to_path, expires_at, bind FROM sign_in_tickets WHERE ticket_hash = ?1",
            [ticket_hash],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((session_id, for_fqdn, to, expires_at, bind)) = found else {
        return Ok(None);
    };
    if conn.execute("DELETE FROM sign_in_tickets WHERE ticket_hash = ?1", [ticket_hash])? != 1 {
        return Ok(None);
    }
    let fresh = parse_dt(&expires_at).is_some_and(|e| Utc::now() < e);
    Ok((fresh && for_fqdn == fqdn).then_some(Ticket { session_id, to, bind }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(id: &str, sub: &str) -> Session {
        let now = Utc::now();
        Session {
            id: id.into(),
            sub: sub.into(),
            email: Some(format!("{sub}@example.com")),
            name: None,
            groups: vec!["family".into()],
            refresh_token_enc: "sealed".into(),
            created_at: now,
            refreshed_at: now,
            stale_since: None,
            last_used_at: now,
        }
    }

    #[test]
    fn a_ticket_works_once_and_for_its_own_service_only() {
        let db = crate::db::Db::open_in_memory_for_test();
        let conn = db.conn.blocking_lock();
        create(&conn, &session("s1", "anna"), "login1").unwrap();
        create_ticket(&conn, "t1", "s1", "grafana.int.test", "/d", "b1").unwrap();
        create_ticket(&conn, "t2", "s1", "grafana.int.test", "/", "b2").unwrap();
        let t = take_ticket(&conn, "t1", "grafana.int.test").unwrap().unwrap();
        assert_eq!((t.session_id.as_str(), t.to.as_str(), t.bind.as_str()), ("s1", "/d", "b1"));
        assert_eq!(take_ticket(&conn, "t1", "grafana.int.test").unwrap(), None, "used up");
        assert_eq!(take_ticket(&conn, "t2", "vault.int.test").unwrap(), None, "another service's");
        assert_eq!(take_ticket(&conn, "t2", "grafana.int.test").unwrap(), None, "spent by the wrong service too");
        assert_eq!(find_by_login(&conn, "login1").unwrap().unwrap().id, "s1");
    }

    #[test]
    fn a_person_signs_out_of_every_browser_at_once() {
        let db = crate::db::Db::open_in_memory_for_test();
        let conn = db.conn.blocking_lock();
        create(&conn, &session("s1", "anna"), "l1").unwrap();
        create(&conn, &session("s2", "anna"), "l2").unwrap();
        create(&conn, &session("s3", "ben"), "l3").unwrap();
        assert_eq!(remove_person(&conn, "anna@example.com").unwrap(), 2);
        assert_eq!(all(&conn).unwrap().len(), 1);
        assert!(remove(&conn, "s3").unwrap());
        assert!(!remove(&conn, "s3").unwrap());
    }

    #[test]
    fn a_person_keeps_only_so_many_sessions_the_least_used_going_first() {
        let db = crate::db::Db::open_in_memory_for_test();
        let conn = db.conn.blocking_lock();
        for i in 0..MAX_PER_PERSON {
            let mut s = session(&format!("s{i}"), "anna");
            s.last_used_at = Utc::now() - Duration::minutes(i64::try_from(i).unwrap());
            create(&conn, &s, &format!("l{i}")).unwrap();
        }
        create(&conn, &session("ben", "ben"), "lb").unwrap();
        create(&conn, &session("new", "anna"), "ln").unwrap();
        let all = all(&conn).unwrap();
        assert_eq!(all.iter().filter(|s| s.sub == "anna").count(), MAX_PER_PERSON);
        let last = format!("s{}", MAX_PER_PERSON - 1);
        assert!(!all.iter().any(|s| s.id == last), "the least recently used went");
        assert!(all.iter().any(|s| s.id == "new") && all.iter().any(|s| s.id == "ben"));
    }

    #[test]
    fn idle_sessions_are_forgotten() {
        let db = crate::db::Db::open_in_memory_for_test();
        let conn = db.conn.blocking_lock();
        create(&conn, &session("s1", "anna"), "l1").unwrap();
        sweep(&conn, Utc::now() + IDLE_TTL - Duration::minutes(1)).unwrap();
        assert!(find(&conn, "s1").unwrap().is_some());
        sweep(&conn, Utc::now() + IDLE_TTL + Duration::minutes(1)).unwrap();
        assert!(find(&conn, "s1").unwrap().is_none());
    }

    #[test]
    fn a_refresh_updates_the_groups_and_a_failure_goes_stale_once() {
        let db = crate::db::Db::open_in_memory_for_test();
        let conn = db.conn.blocking_lock();
        create(&conn, &session("s1", "anna"), "l1").unwrap();
        refresh_failed(&conn, "s1").unwrap();
        let first = find(&conn, "s1").unwrap().unwrap().stale_since.unwrap();
        refresh_failed(&conn, "s1").unwrap();
        assert_eq!(find(&conn, "s1").unwrap().unwrap().stale_since, Some(first));
        refreshed(&conn, "s1", &["admins".into()], "sealed2", Some("")).unwrap();
        let s = find(&conn, "s1").unwrap().unwrap();
        assert_eq!((s.groups, s.stale_since, s.email), (vec!["admins".to_string()], None, None));
    }
}
