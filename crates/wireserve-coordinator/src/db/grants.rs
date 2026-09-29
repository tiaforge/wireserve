//! Service groups, grants and node tags (PLAN.md M36, migration 0017).
//!
//! Membership is by service **name**, and a name with none is in
//! [`DEFAULT_GROUP`]. Only an admin changes any of it; a node's declaration
//! can name a group once, for a service that has none yet — see
//! [`promote_declared_group`].

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, OptionalExtension};
use wireserve_types::{GrantSource, DEFAULT_GROUP};

use super::DbError;

/// A grant as stored.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Grant {
    pub source: GrantSource,
    pub group: String,
}

pub fn group_exists(conn: &Connection, name: &str) -> Result<bool, DbError> {
    Ok(conn
        .query_row("SELECT 1 FROM service_groups WHERE name = ?1", [name], |_| Ok(()))
        .optional()?
        .is_some())
}

/// Every group, in name order.
pub fn list_groups(conn: &Connection) -> Result<Vec<String>, DbError> {
    let mut stmt = conn.prepare("SELECT name FROM service_groups ORDER BY name")?;
    let rows = stmt.query_map([], |row| row.get(0))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// `false` when it already existed.
pub fn create_group(conn: &Connection, name: &str) -> Result<bool, DbError> {
    let n = conn.execute(
        "INSERT INTO service_groups (name, created_at) VALUES (?1, ?2) ON CONFLICT(name) DO NOTHING",
        rusqlite::params![name, super::nodes::now_str()],
    )?;
    Ok(n == 1)
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeleteGroupOutcome {
    Deleted,
    NotFound,
    /// `default` is where every service without a group is.
    Builtin,
    /// Deleting it would drop its services back into `default`, where
    /// everyone reaches them — or strand a declaration waiting to join it.
    InUse { services: Vec<String>, grants: usize, declared_by: Vec<String> },
}

pub fn delete_group(conn: &Connection, name: &str) -> Result<DeleteGroupOutcome, DbError> {
    if name == DEFAULT_GROUP {
        return Ok(DeleteGroupOutcome::Builtin);
    }
    if !group_exists(conn, name)? {
        return Ok(DeleteGroupOutcome::NotFound);
    }
    let services = strings(conn, "SELECT service FROM service_group_members WHERE grp = ?1 ORDER BY service", name)?;
    let declared_by = strings(conn, "SELECT name FROM services WHERE declared_group = ?1 ORDER BY name", name)?;
    let grants: i64 = conn.query_row("SELECT COUNT(*) FROM grants WHERE grp = ?1", [name], |row| row.get(0))?;
    let grants = usize::try_from(grants).unwrap_or(usize::MAX);
    if !services.is_empty() || grants > 0 || !declared_by.is_empty() {
        return Ok(DeleteGroupOutcome::InUse { services, grants, declared_by });
    }
    conn.execute("DELETE FROM service_groups WHERE name = ?1", [name])?;
    Ok(DeleteGroupOutcome::Deleted)
}

fn strings(conn: &Connection, sql: &str, arg: &str) -> Result<Vec<String>, DbError> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([arg], |row| row.get(0))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Every service name with explicit groups, and those groups. A name
/// missing here is in `default`.
pub fn members(conn: &Connection) -> Result<BTreeMap<String, BTreeSet<String>>, DbError> {
    let mut stmt = conn.prepare("SELECT service, grp FROM service_group_members")?;
    let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in rows {
        let (service, group) = row?;
        out.entry(service).or_default().insert(group);
    }
    Ok(out)
}

/// The groups `service` is in: its explicit ones, or `default`.
#[must_use]
pub fn effective_groups(members: &BTreeMap<String, BTreeSet<String>>, service: &str) -> BTreeSet<String> {
    members.get(service).cloned().unwrap_or_else(|| BTreeSet::from([DEFAULT_GROUP.to_string()]))
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddMemberOutcome {
    Added,
    AlreadyMember,
    NoSuchGroup,
}

pub fn add_member(conn: &Connection, group: &str, service: &str) -> Result<AddMemberOutcome, DbError> {
    if !group_exists(conn, group)? {
        return Ok(AddMemberOutcome::NoSuchGroup);
    }
    let n = conn.execute(
        "INSERT INTO service_group_members (service, grp) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
        [service, group],
    )?;
    Ok(if n == 1 { AddMemberOutcome::Added } else { AddMemberOutcome::AlreadyMember })
}

#[derive(Debug, PartialEq, Eq)]
pub enum RemoveMemberOutcome {
    /// `now_default`: that was its last group, so it is in `default` again.
    Removed { now_default: bool },
    NotMember,
}

pub fn remove_member(conn: &Connection, group: &str, service: &str) -> Result<RemoveMemberOutcome, DbError> {
    let n = conn.execute("DELETE FROM service_group_members WHERE service = ?1 AND grp = ?2", [service, group])?;
    if n == 0 {
        return Ok(RemoveMemberOutcome::NotMember);
    }
    let left: i64 =
        conn.query_row("SELECT COUNT(*) FROM service_group_members WHERE service = ?1", [service], |row| row.get(0))?;
    Ok(RemoveMemberOutcome::Removed { now_default: left == 0 })
}

/// Every grant, sorted.
pub fn list_grants(conn: &Connection) -> Result<Vec<Grant>, DbError> {
    let mut stmt = conn.prepare("SELECT source_kind, source, grp FROM grants")?;
    let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))?;
    let mut out = Vec::new();
    for row in rows {
        let (kind, name, group) = row?;
        // The CHECK constraint and every writer keep these valid; one that
        // is not grants nothing rather than failing every poll.
        match GrantSource::from_parts(&kind, &name) {
            Ok(source) => out.push(Grant { source, group }),
            Err(e) => tracing::warn!(error = %e, group = %group, "ignoring an unreadable grant"),
        }
    }
    out.sort();
    Ok(out)
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddGrantOutcome {
    Added,
    AlreadyGranted,
    NoSuchGroup,
}

pub fn add_grant(conn: &Connection, source: &GrantSource, group: &str) -> Result<AddGrantOutcome, DbError> {
    if !group_exists(conn, group)? {
        return Ok(AddGrantOutcome::NoSuchGroup);
    }
    let n = conn.execute(
        "INSERT INTO grants (source_kind, source, grp) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
        [source.kind(), source.name(), group],
    )?;
    Ok(if n == 1 { AddGrantOutcome::Added } else { AddGrantOutcome::AlreadyGranted })
}

/// `false` when there was no such grant.
pub fn remove_grant(conn: &Connection, source: &GrantSource, group: &str) -> Result<bool, DbError> {
    let n = conn.execute(
        "DELETE FROM grants WHERE source_kind = ?1 AND source = ?2 AND grp = ?3",
        [source.kind(), source.name(), group],
    )?;
    Ok(n == 1)
}

/// Every node's tags, by node id.
pub fn tags(conn: &Connection) -> Result<BTreeMap<i64, BTreeSet<String>>, DbError> {
    let mut stmt = conn.prepare("SELECT node_id, tag FROM node_tags")?;
    let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?;
    let mut out: BTreeMap<i64, BTreeSet<String>> = BTreeMap::new();
    for row in rows {
        let (node, tag) = row?;
        out.entry(node).or_default().insert(tag);
    }
    Ok(out)
}

/// `false` when the node already had it.
pub fn add_tag(conn: &Connection, node_id: i64, tag: &str) -> Result<bool, DbError> {
    let n = conn.execute(
        "INSERT INTO node_tags (node_id, tag) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
        rusqlite::params![node_id, tag],
    )?;
    Ok(n == 1)
}

/// `false` when the node did not have it.
pub fn remove_tag(conn: &Connection, node_id: i64, tag: &str) -> Result<bool, DbError> {
    let n = conn.execute("DELETE FROM node_tags WHERE node_id = ?1 AND tag = ?2", rusqlite::params![node_id, tag])?;
    Ok(n == 1)
}

/// Turns the group a node named when declaring `name` into membership —
/// once, when the row is approved, and only if the name has no groups yet.
/// Cleared either way, so an admin who later empties the name's groups is
/// not overruled by a declaration made long before. Call inside the
/// transaction that approves the row.
///
/// `Some(group)` when it became a member.
pub fn promote_declared_group(conn: &Connection, name: &str) -> Result<Option<String>, DbError> {
    let declared: Option<String> = conn
        .query_row(
            "SELECT declared_group FROM services WHERE name = ?1 AND approved_at IS NOT NULL AND denied_at IS NULL",
            [name],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    let Some(group) = declared else {
        return Ok(None);
    };
    conn.execute("UPDATE services SET declared_group = NULL WHERE name = ?1", [name])?;
    let has_groups: bool =
        conn.query_row("SELECT EXISTS (SELECT 1 FROM service_group_members WHERE service = ?1)", [name], |row| {
            row.get(0)
        })?;
    if has_groups || !group_exists(conn, &group)? {
        return Ok(None);
    }
    conn.execute("INSERT INTO service_group_members (service, grp) VALUES (?1, ?2)", [name, &group])?;
    tracing::info!(event = "service_group_from_declaration", service = %name, group = %group);
    Ok(Some(group))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::services::{approve, upsert_for_node, ApprovalMode};
    use crate::db::Db;
    use wireserve_types::{PortMap, Proto, ServiceDecl};

    const RANGE: &str = "100.90.0.0/24";

    fn decl(name: &str, group: Option<&str>) -> ServiceDecl {
        let mut d = ServiceDecl::new(name, vec![PortMap::identity(80, Proto::Tcp)]);
        d.group = group.map(str::to_string);
        d
    }

    async fn node(db: &Db, name: &str) -> i64 {
        let conn = db.conn.lock().await;
        crate::db::nodes::create_node(&conn, name, wireserve_types::NodeKind::Agent, &format!("h-{name}"), None).unwrap()
    }

    #[tokio::test]
    async fn a_fresh_mesh_grants_everyone_the_default_group() {
        let db = Db::open_in_memory_for_test();
        let conn = db.conn.lock().await;
        assert_eq!(list_groups(&conn).unwrap(), vec!["default"]);
        assert_eq!(list_grants(&conn).unwrap(), vec![Grant { source: GrantSource::Everyone, group: "default".into() }]);
        assert_eq!(effective_groups(&members(&conn).unwrap(), "anything"), BTreeSet::from(["default".to_string()]));
    }

    #[tokio::test]
    async fn a_group_in_use_or_the_default_one_cannot_be_deleted() {
        let db = Db::open_in_memory_for_test();
        let conn = db.conn.lock().await;
        assert_eq!(delete_group(&conn, "default").unwrap(), DeleteGroupOutcome::Builtin);
        assert_eq!(delete_group(&conn, "infra").unwrap(), DeleteGroupOutcome::NotFound);
        assert!(create_group(&conn, "infra").unwrap());
        assert!(!create_group(&conn, "infra").unwrap());
        assert_eq!(add_member(&conn, "infra", "db").unwrap(), AddMemberOutcome::Added);
        assert!(matches!(delete_group(&conn, "infra").unwrap(), DeleteGroupOutcome::InUse { services, .. } if services == ["db"]));
        assert_eq!(remove_member(&conn, "infra", "db").unwrap(), RemoveMemberOutcome::Removed { now_default: true });
        assert_eq!(add_grant(&conn, &GrantSource::Tag("ops".into()), "infra").unwrap(), AddGrantOutcome::Added);
        assert!(matches!(delete_group(&conn, "infra").unwrap(), DeleteGroupOutcome::InUse { grants: 1, .. }));
        assert!(remove_grant(&conn, &GrantSource::Tag("ops".into()), "infra").unwrap());
        assert_eq!(delete_group(&conn, "infra").unwrap(), DeleteGroupOutcome::Deleted);
        assert_eq!(add_member(&conn, "infra", "db").unwrap(), AddMemberOutcome::NoSuchGroup);
    }

    #[tokio::test]
    async fn a_declared_group_joins_once_on_approval_and_never_overrules_an_admin() {
        let db = Db::open_in_memory_for_test();
        let id = node(&db, "n1").await;
        let mut conn = db.conn.lock().await;
        create_group(&conn, "infra").unwrap();
        create_group(&conn, "media").unwrap();

        // Pending: nothing yet, and the group cannot be deleted under it.
        upsert_for_node(&mut conn, id, &[decl("db", Some("infra"))], ApprovalMode::RequireApproval, RANGE).unwrap();
        assert!(members(&conn).unwrap().is_empty(), "a pending declaration seeds nothing");
        assert!(matches!(delete_group(&conn, "infra").unwrap(), DeleteGroupOutcome::InUse { declared_by, .. } if declared_by == ["db"]));

        approve(&conn, id, "db").unwrap();
        assert_eq!(effective_groups(&members(&conn).unwrap(), "db"), BTreeSet::from(["infra".to_string()]));

        // An admin moves it; re-declaring with the old group changes nothing.
        add_member(&conn, "media", "db").unwrap();
        remove_member(&conn, "infra", "db").unwrap();
        let out = upsert_for_node(&mut conn, id, &[decl("db", Some("infra"))], ApprovalMode::RequireApproval, RANGE).unwrap();
        assert_eq!(effective_groups(&members(&conn).unwrap(), "db"), BTreeSet::from(["media".to_string()]));
        assert_eq!(out.notices.len(), 1, "{:?}", out.notices);

        // Emptied by the admin: back in default, not re-seeded by the old
        // declaration.
        remove_member(&conn, "media", "db").unwrap();
        upsert_for_node(&mut conn, id, &[decl("db", Some("infra"))], ApprovalMode::AutoApprove, RANGE).unwrap();
        assert!(members(&conn).unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unknown_group_publishes_nothing_and_says_why() {
        let db = Db::open_in_memory_for_test();
        let id = node(&db, "n1").await;
        let mut conn = db.conn.lock().await;
        let out = upsert_for_node(
            &mut conn,
            id,
            &[decl("db", Some("nope")), decl("web", None)],
            ApprovalMode::AutoApprove,
            RANGE,
        )
        .unwrap();
        assert!(crate::db::services::find_by_name(&conn, "db").unwrap().is_none(), "never falls back to default");
        assert!(crate::db::services::find_by_name(&conn, "web").unwrap().is_some(), "the rest still apply");
        assert_eq!(out.notices.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(), ["db"]);

        // Auto-approved with a group that exists: a member at once.
        create_group(&conn, "infra").unwrap();
        upsert_for_node(&mut conn, id, &[decl("db", Some("infra")), decl("web", None)], ApprovalMode::AutoApprove, RANGE)
            .unwrap();
        assert_eq!(effective_groups(&members(&conn).unwrap(), "db"), BTreeSet::from(["infra".to_string()]));
    }

    #[tokio::test]
    async fn tags_belong_to_nodes() {
        let db = Db::open_in_memory_for_test();
        let id = node(&db, "n1").await;
        let conn = db.conn.lock().await;
        assert!(add_tag(&conn, id, "ops").unwrap());
        assert!(!add_tag(&conn, id, "ops").unwrap());
        assert_eq!(tags(&conn).unwrap()[&id], BTreeSet::from(["ops".to_string()]));
        assert!(remove_tag(&conn, id, "ops").unwrap());
        assert!(!remove_tag(&conn, id, "ops").unwrap());
    }
}
