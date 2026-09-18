use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension};
use wireserve_types::Proto;

use super::DbError;

#[derive(Debug, Clone)]
pub struct ServiceRow {
    pub node_id: i64,
    pub name: String,
    pub port: u16,
    pub proto: Proto,
    pub declared_at: Option<DateTime<Utc>>,
    /// Non-NULL means an admin has approved this node's claim to this
    /// name. NULL with `denied_at` also NULL means pending; NULL with
    /// `denied_at` set means refused. See migration 0003 for why the
    /// pending direction is the one you get by forgetting the column.
    pub approved_at: Option<DateTime<Utc>>,
    pub denied_at: Option<DateTime<Utc>>,
    pub denied_reason: Option<String>,
}

impl ServiceRow {
    /// Whether this row may appear in the directory other nodes receive.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        self.approved_at.is_some() && self.denied_at.is_none()
    }
}

/// Parses a timestamp written either as RFC3339 (everything this code
/// writes, via `nodes::now_str`) or in SQLite's own `CURRENT_TIMESTAMP`
/// format, which is what the `declared_at` column DEFAULT still produces
/// for any INSERT that omits it.
///
/// Migration 0003 rewrites the historical rows, but the DEFAULT itself
/// cannot be dropped without a full table rebuild, so a future INSERT
/// that forgets the column would reintroduce the second format — and a
/// strict RFC3339 parse turns that into `None` with no error anywhere.
fn parse_dt(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|naive| naive.and_utc())
}

fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ServiceRow> {
    let proto_str: String = row.get("proto")?;
    let port: i64 = row.get("port")?;
    let dt = |col: &str| -> rusqlite::Result<Option<DateTime<Utc>>> {
        Ok(row
            .get::<_, Option<String>>(col)?
            .as_deref()
            .and_then(parse_dt))
    };
    Ok(ServiceRow {
        node_id: row.get("node_id")?,
        name: row.get("name")?,
        port: port as u16,
        proto: proto_str.parse().unwrap_or(Proto::Tcp),
        declared_at: dt("declared_at")?,
        approved_at: dt("approved_at")?,
        denied_at: dt("denied_at")?,
        denied_reason: row.get("denied_reason")?,
    })
}

/// Whether a declaration lands approved on arrival or waits for an admin.
///
/// Passed in from `/poll` rather than read from config here, so this
/// module stays free of `AppState` and every unit test can exercise both
/// modes without constructing a `Config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    AutoApprove,
    RequireApproval,
}

impl ApprovalMode {
    /// The value written into `approved_at` for a newly-inserted row.
    ///
    /// This single `Option` is the entire feature flag inside the DB
    /// layer. Under `AutoApprove` every row this node owns is written
    /// with a non-NULL `approved_at`, so "flag off behaves exactly as
    /// before" is a mechanical property rather than an assertion.
    fn stamp(self) -> Option<String> {
        match self {
            ApprovalMode::AutoApprove => Some(super::nodes::now_str()),
            ApprovalMode::RequireApproval => None,
        }
    }
}

/// Names a node declared that are not in the directory, split by why.
///
/// Returned from inside the same transaction that wrote the
/// declarations, so `/poll` reports a verdict consistent with the
/// directory it returns in the same response.
#[derive(Debug, Default)]
pub struct UpsertOutcome {
    pub pending: Vec<ServiceRow>,
    pub denied: Vec<ServiceRow>,
}

pub fn list_for_node(conn: &Connection, node_id: i64) -> Result<Vec<ServiceRow>, DbError> {
    let mut stmt = conn.prepare("SELECT * FROM services WHERE node_id = ?1")?;
    let rows = stmt.query_map([node_id], map_row)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
}

/// Every service eligible to appear in the directory.
///
/// **This query is the choke point for the whole approval feature.**
/// `/poll`'s `services` array is built from it, and every agent writes
/// that array verbatim into its `/etc/hosts` managed block as
/// `<name>.wg -> <owner ip4>`. A row that leaves this filter must be
/// invisible to every node but its owner.
///
/// Both conditions are checked even though `approve`, `deny` and
/// `upsert_for_node` all keep `approved_at` and `denied_at` mutually
/// exclusive. The directory should not depend on an invariant maintained
/// three functions away.
pub fn list_approved(conn: &Connection) -> Result<Vec<ServiceRow>, DbError> {
    let mut stmt = conn
        .prepare("SELECT * FROM services WHERE approved_at IS NOT NULL AND denied_at IS NULL")?;
    let rows = stmt.query_map([], map_row)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
}

/// Every service in every approval state, for `GET /admin/services`.
///
/// Deliberately a separate function rather than a boolean parameter on
/// [`list_approved`] — a `list_all(conn, include_pending: true)` is one
/// mistyped argument away from publishing unapproved names to the whole
/// mesh.
pub fn list_all_for_admin(conn: &Connection) -> Result<Vec<ServiceRow>, DbError> {
    let mut stmt = conn.prepare("SELECT * FROM services ORDER BY name")?;
    let rows = stmt.query_map([], map_row)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
}

/// Returns the node_id that owns `name`, if any exists anywhere in the
/// table (uniqueness is enforced across the whole table, not per-node —
/// spec §3).
///
/// A **pending or denied row still reserves its name** here, deliberately.
/// If pending rows did not reserve, two nodes could hold simultaneous
/// pending claims on `plex`, and approving one would strand the other
/// holding a row that can never be inserted — with no error the agent
/// could act on. A denied row's name is freed the ordinary way instead:
/// the declaring node stops declaring it, and the withdraw-diff below
/// deletes the row.
fn owner_of(conn: &Connection, name: &str) -> Result<Option<i64>, DbError> {
    conn.query_row(
        "SELECT node_id FROM services WHERE name = ?1",
        [name],
        |row| row.get(0),
    )
    .optional()
    .map_err(DbError::from)
}

/// Diffs `desired` against `node_id`'s currently-declared services and
/// applies insert/delete accordingly (spec §4.3). Runs inside a
/// transaction: either the whole batch applies, or none of it does — a
/// collision partway through must not leave earlier entries in the same
/// request half-applied.
///
/// Approval behaviour, all of it in the `ON CONFLICT` clause:
///
/// * **An existing approval survives a port or proto change.** What the
///   admin approved is the *name binding*, and the name is the part that
///   reaches every other node's `/etc/hosts`. The port is the node's own
///   business — it already controls its listener and its own firewall
///   hole (spec §5), and a peer can reach that port by IP with or
///   without a directory entry. Re-approving on every `serve plex 32401`
///   would also drop a working service out of the directory for as long
///   as the admin took to notice.
/// * **A denied row re-declared stays denied.** `excluded.approved_at` is
///   NULL under `RequireApproval`, so the `COALESCE` keeps NULL and the
///   `CASE` preserves `denied_at`. Denial is sticky across the
///   re-declaration the agent performs on its very next cycle, which is
///   what gives it time to learn about the denial and withdraw.
/// * **A pending row heals to approved under `AutoApprove`**, which is
///   what an operator turning the flag back off should get.
pub fn upsert_for_node(
    conn: &mut Connection,
    node_id: i64,
    desired: &[(String, u16, Proto)],
    mode: ApprovalMode,
) -> Result<UpsertOutcome, DbError> {
    let tx = conn.transaction()?;

    // Validate every desired name against other nodes BEFORE mutating
    // anything, so a collision on entry N doesn't leave entries 1..N-1
    // applied.
    for (name, _, _) in desired {
        if let Some(owner) = owner_of(&tx, name)? {
            if owner != node_id {
                return Err(DbError::ServiceNameCollision(name.clone()));
            }
        }
    }

    let current: Vec<String> = {
        let mut stmt = tx.prepare("SELECT name FROM services WHERE node_id = ?1")?;
        let rows = stmt.query_map([node_id], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    let desired_names: Vec<&str> = desired.iter().map(|(n, _, _)| n.as_str()).collect();

    for name in &current {
        if !desired_names.contains(&name.as_str()) {
            tx.execute(
                "DELETE FROM services WHERE node_id = ?1 AND name = ?2",
                rusqlite::params![node_id, name],
            )?;
        }
    }

    let now = super::nodes::now_str();
    let stamp = mode.stamp();
    for (name, port, proto) in desired {
        tx.execute(
            "INSERT INTO services (node_id, name, port, proto, declared_at, approved_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(name) DO UPDATE SET \
               port = excluded.port, \
               proto = excluded.proto, \
               approved_at = COALESCE(services.approved_at, excluded.approved_at), \
               denied_at = CASE \
                 WHEN COALESCE(services.approved_at, excluded.approved_at) IS NULL \
                 THEN services.denied_at ELSE NULL END, \
               denied_reason = CASE \
                 WHEN COALESCE(services.approved_at, excluded.approved_at) IS NULL \
                 THEN services.denied_reason ELSE NULL END \
             WHERE node_id = excluded.node_id",
            rusqlite::params![node_id, name, port, proto.as_str(), now, stamp],
        )?;
    }

    // Read the verdict back inside the same transaction, so what `/poll`
    // tells the node matches the directory it returns in the same body.
    //
    // Scoping by node_id alone is correct: after the withdraw-diff above,
    // this node's rows are exactly `desired`.
    let outcome = {
        let mut pending = tx.prepare(
            "SELECT * FROM services \
             WHERE node_id = ?1 AND approved_at IS NULL AND denied_at IS NULL ORDER BY name",
        )?;
        let pending: Vec<ServiceRow> = pending
            .query_map([node_id], map_row)?
            .collect::<Result<_, _>>()?;
        let mut denied = tx.prepare(
            "SELECT * FROM services \
             WHERE node_id = ?1 AND approved_at IS NULL AND denied_at IS NOT NULL ORDER BY name",
        )?;
        let denied: Vec<ServiceRow> = denied
            .query_map([node_id], map_row)?
            .collect::<Result<_, _>>()?;
        UpsertOutcome { pending, denied }
    };

    tx.commit()?;
    Ok(outcome)
}

/// Outcome of [`approve`]. An enum rather than a `DbError` variant so the
/// handler must `match` every case — none of these can be accidentally
/// `?`-ed into a 500.
#[derive(Debug, PartialEq, Eq)]
pub enum ApproveOutcome {
    Approved,
    AlreadyApproved,
    /// The name is declared, but by a different node. Approving must
    /// never cross that boundary: this is what stops an operator acting
    /// on a stale view of the directory from blessing a squatter's claim.
    OwnedByAnotherNode {
        owner_node_id: i64,
    },
    NotDeclared,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DenyOutcome {
    Denied,
    AlreadyDenied,
    OwnedByAnotherNode { owner_node_id: i64 },
    NotDeclared,
}

/// The row currently holding `name`, whoever owns it. One place so
/// `approve` and `deny` agree on what "declared by someone else" means.
fn row_for_name(conn: &Connection, name: &str) -> Result<Option<ServiceRow>, DbError> {
    conn.query_row("SELECT * FROM services WHERE name = ?1", [name], map_row)
        .optional()
        .map_err(DbError::from)
}

/// Approves `name` **for `node_id` specifically**.
///
/// Takes the node id, not just the name: there is deliberately no
/// "approve whoever currently holds this name" operation anywhere in this
/// codebase, at any layer. Approval binds to the pair, because a
/// `services` row *is* that pair.
pub fn approve(conn: &Connection, node_id: i64, name: &str) -> Result<ApproveOutcome, DbError> {
    let tx = conn.unchecked_transaction()?;
    let Some(row) = row_for_name(&tx, name)? else {
        return Ok(ApproveOutcome::NotDeclared);
    };
    if row.node_id != node_id {
        return Ok(ApproveOutcome::OwnedByAnotherNode {
            owner_node_id: row.node_id,
        });
    }
    if row.is_approved() {
        // Idempotent, and the timestamp deliberately does not move —
        // re-running the command must not look like a fresh decision in
        // the audit trail.
        return Ok(ApproveOutcome::AlreadyApproved);
    }
    tx.execute(
        "UPDATE services SET approved_at = ?1, denied_at = NULL, denied_reason = NULL \
         WHERE name = ?2 AND node_id = ?3",
        // The `AND node_id = ?3` is redundant given the check above and
        // stays anyway: it is the last line of defence for the
        // bind-to-the-declaring-node rule, and costs nothing.
        rusqlite::params![super::nodes::now_str(), name, node_id],
    )?;
    tx.commit()?;
    Ok(ApproveOutcome::Approved)
}

/// Denies `name` for `node_id`, optionally recording a reason the
/// declaring node will see in `wireserve list`.
///
/// Denying an already-**approved** service withdraws that approval and
/// removes it from the directory immediately. That is the only way an
/// operator who enabled approval over an existing mesh — where migration
/// 0003 grandfathered every pre-existing service as approved — can force
/// a specific name back through review.
///
/// **Deny is for mistakes. For a node you no longer trust, use `revoke`.**
/// A denied row still holds its globally-unique name until the declaring
/// node withdraws it, and a compromised node will not withdraw anything.
/// `revoke` deletes every one of the node's rows and kills its token,
/// which is the actual answer to a hostile node parking a name.
pub fn deny(
    conn: &Connection,
    node_id: i64,
    name: &str,
    reason: Option<&str>,
) -> Result<DenyOutcome, DbError> {
    let tx = conn.unchecked_transaction()?;
    let Some(row) = row_for_name(&tx, name)? else {
        return Ok(DenyOutcome::NotDeclared);
    };
    if row.node_id != node_id {
        return Ok(DenyOutcome::OwnedByAnotherNode {
            owner_node_id: row.node_id,
        });
    }
    if row.denied_at.is_some() && row.approved_at.is_none() {
        return Ok(DenyOutcome::AlreadyDenied);
    }
    tx.execute(
        "UPDATE services SET denied_at = ?1, denied_reason = ?2, approved_at = NULL \
         WHERE name = ?3 AND node_id = ?4",
        rusqlite::params![super::nodes::now_str(), reason, name, node_id],
    )?;
    tx.commit()?;
    Ok(DenyOutcome::Denied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::nodes::{apply_redemption, create_node, Redemption};
    use crate::db::Db;
    use wireserve_types::NodeKind;

    async fn node_with_id(db: &Db, name: &str, hash: &str) -> i64 {
        let conn = db.conn.lock().await;
        let id = create_node(&conn, name, NodeKind::Agent, hash, None).unwrap();
        // Every UNIQUE column (pubkey, ip4, ip6, bearer_token_hash) must be
        // distinct per node, or apply_redemption fails with a constraint
        // violation — derive them from `id` so callers with different
        // `name`s never collide.
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: &format!("pk-{id}"),
                ip4: format!("100.90.0.{id}").parse().unwrap(),
                ip6: format!("fd00:90::{id}").parse().unwrap(),
                listen_port: Some(51820),
                endpoint_addr: None,
                endpoint_addr_v4: None,
                endpoint_addr_v6: None,
                bearer_token_hash: &format!("bearer-{name}"),
            },
        )
        .unwrap();
        id
    }

    #[tokio::test]
    async fn insert_and_withdraw() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[("plex".into(), 32400, Proto::Tcp)], ApprovalMode::AutoApprove).unwrap();
        assert_eq!(list_for_node(&conn, id).unwrap().len(), 1);

        upsert_for_node(&mut conn, id, &[], ApprovalMode::AutoApprove).unwrap();
        assert_eq!(list_for_node(&conn, id).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn auto_approve_puts_a_declaration_straight_into_the_directory() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        let outcome = upsert_for_node(&mut conn, id, &[("plex".into(), 32400, Proto::Tcp)], ApprovalMode::AutoApprove).unwrap();
        assert_eq!(list_approved(&conn).unwrap().len(), 1);
        assert!(outcome.pending.is_empty());
        assert!(outcome.denied.is_empty());
    }

    #[tokio::test]
    async fn require_approval_keeps_a_declaration_out_of_the_directory() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        let outcome = upsert_for_node(&mut conn, id, &[("plex".into(), 32400, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap();
        assert!(list_approved(&conn).unwrap().is_empty(), "no other node may see it");
        assert_eq!(list_for_node(&conn, id).unwrap().len(), 1, "its owner still does");
        assert_eq!(outcome.pending.len(), 1);
        assert_eq!(outcome.pending[0].name, "plex");
    }

    #[tokio::test]
    async fn approval_binds_to_the_declaring_node_not_to_the_name() {
        // n1 gets `plex` approved, then withdraws it. n2 claiming the
        // freed name must start from pending — an approval is never a
        // property of the name alone.
        let db = Db::open_in_memory_for_test();
        let id1 = node_with_id(&db, "n1", "h1").await;
        let id2 = node_with_id(&db, "n2", "h2").await;
        let mut conn = db.conn.lock().await;

        upsert_for_node(&mut conn, id1, &[("plex".into(), 1, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap();
        assert_eq!(approve(&conn, id1, "plex").unwrap(), ApproveOutcome::Approved);
        assert_eq!(list_approved(&conn).unwrap().len(), 1);

        upsert_for_node(&mut conn, id1, &[], ApprovalMode::RequireApproval).unwrap();
        let outcome = upsert_for_node(&mut conn, id2, &[("plex".into(), 1, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap();

        assert!(list_approved(&conn).unwrap().is_empty());
        assert_eq!(outcome.pending.len(), 1, "n2 inherits nothing from n1's approval");
    }

    #[tokio::test]
    async fn approve_refuses_a_name_declared_by_another_node() {
        let db = Db::open_in_memory_for_test();
        let id1 = node_with_id(&db, "n1", "h1").await;
        let id2 = node_with_id(&db, "n2", "h2").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id1, &[("plex".into(), 1, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap();

        assert_eq!(
            approve(&conn, id2, "plex").unwrap(),
            ApproveOutcome::OwnedByAnotherNode { owner_node_id: id1 }
        );
        assert!(list_approved(&conn).unwrap().is_empty(), "a refused approval must leave no trace");
    }

    #[tokio::test]
    async fn approve_is_idempotent_and_does_not_move_the_timestamp() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[("plex".into(), 1, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap();

        approve(&conn, id, "plex").unwrap();
        let first = list_approved(&conn).unwrap()[0].approved_at;
        assert_eq!(approve(&conn, id, "plex").unwrap(), ApproveOutcome::AlreadyApproved);
        assert_eq!(list_approved(&conn).unwrap()[0].approved_at, first);
    }

    #[tokio::test]
    async fn approve_on_an_undeclared_name_reports_not_declared() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let conn = db.conn.lock().await;
        assert_eq!(approve(&conn, id, "nothing").unwrap(), ApproveOutcome::NotDeclared);
    }

    #[tokio::test]
    async fn a_port_change_keeps_an_existing_approval() {
        // What was approved is the name binding. Re-approving on every
        // `serve plex 32401` would drop a working service out of the
        // directory until an admin noticed.
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[("plex".into(), 32400, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap();
        approve(&conn, id, "plex").unwrap();

        let outcome = upsert_for_node(&mut conn, id, &[("plex".into(), 32401, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap();

        assert!(outcome.pending.is_empty(), "a port change is not a re-claim");
        let rows = list_approved(&conn).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].port, 32401);
    }

    #[tokio::test]
    async fn redeclaring_a_denied_service_stays_denied() {
        // The agent re-sends its whole declaration list on the very next
        // cycle, so a denial that did not stick would be undone before
        // the node ever learned about it.
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[("plex".into(), 1, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap();
        assert_eq!(deny(&conn, id, "plex", Some("not this one")).unwrap(), DenyOutcome::Denied);

        let outcome = upsert_for_node(&mut conn, id, &[("plex".into(), 1, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap();

        assert!(outcome.pending.is_empty());
        assert_eq!(outcome.denied.len(), 1);
        assert_eq!(outcome.denied[0].denied_reason.as_deref(), Some("not this one"));
        assert!(list_approved(&conn).unwrap().is_empty());
    }

    #[tokio::test]
    async fn withdrawing_a_denied_service_frees_the_name() {
        let db = Db::open_in_memory_for_test();
        let id1 = node_with_id(&db, "n1", "h1").await;
        let id2 = node_with_id(&db, "n2", "h2").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id1, &[("plex".into(), 1, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap();
        deny(&conn, id1, "plex", None).unwrap();

        upsert_for_node(&mut conn, id1, &[], ApprovalMode::RequireApproval).unwrap();
        upsert_for_node(&mut conn, id2, &[("plex".into(), 1, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap();

        assert_eq!(owner_of(&conn, "plex").unwrap(), Some(id2));
    }

    #[tokio::test]
    async fn deny_withdraws_an_approval_already_granted() {
        // The re-review lever for a mesh where enabling approval
        // grandfathered everything already declared.
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[("plex".into(), 1, Proto::Tcp)], ApprovalMode::AutoApprove).unwrap();
        assert_eq!(list_approved(&conn).unwrap().len(), 1);

        assert_eq!(deny(&conn, id, "plex", None).unwrap(), DenyOutcome::Denied);
        assert!(list_approved(&conn).unwrap().is_empty());
        assert_eq!(deny(&conn, id, "plex", None).unwrap(), DenyOutcome::AlreadyDenied);
    }

    #[tokio::test]
    async fn approving_a_denied_service_un_denies_it() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[("plex".into(), 1, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap();
        deny(&conn, id, "plex", Some("on reflection, no")).unwrap();

        assert_eq!(approve(&conn, id, "plex").unwrap(), ApproveOutcome::Approved);
        let rows = list_approved(&conn).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].denied_at.is_none(), "the denial must be cleared, not merely outvoted");
        assert!(rows[0].denied_reason.is_none());
    }

    #[tokio::test]
    async fn turning_approval_off_heals_pending_and_denied_rows() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[("a".into(), 1, Proto::Tcp), ("b".into(), 2, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap();
        deny(&conn, id, "b", None).unwrap();

        let outcome = upsert_for_node(&mut conn, id, &[("a".into(), 1, Proto::Tcp), ("b".into(), 2, Proto::Tcp)], ApprovalMode::AutoApprove).unwrap();

        assert!(outcome.pending.is_empty());
        assert!(outcome.denied.is_empty());
        assert_eq!(list_approved(&conn).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_pending_row_still_reserves_its_name_against_another_node() {
        let db = Db::open_in_memory_for_test();
        let id1 = node_with_id(&db, "n1", "h1").await;
        let id2 = node_with_id(&db, "n2", "h2").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id1, &[("plex".into(), 1, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap();

        let err = upsert_for_node(&mut conn, id2, &[("plex".into(), 1, Proto::Tcp)], ApprovalMode::RequireApproval).unwrap_err();
        assert!(matches!(err, DbError::ServiceNameCollision(_)));
    }

    #[tokio::test]
    async fn cross_node_collision_rejected_and_first_nodes_service_untouched() {
        let db = Db::open_in_memory_for_test();
        let id1 = node_with_id(&db, "n1", "h1").await;
        let id2 = node_with_id(&db, "n2", "h2").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id1, &[("plex".into(), 32400, Proto::Tcp)], ApprovalMode::AutoApprove).unwrap();

        let err = upsert_for_node(&mut conn, id2, &[("plex".into(), 1, Proto::Tcp)], ApprovalMode::AutoApprove).unwrap_err();
        match err {
            DbError::ServiceNameCollision(name) => assert_eq!(name, "plex"),
            other => panic!("expected collision error, got {other:?}"),
        }

        // node1's own service must be untouched.
        let n1_services = list_for_node(&conn, id1).unwrap();
        assert_eq!(n1_services.len(), 1);
        assert_eq!(n1_services[0].port, 32400);
        let n2_services = list_for_node(&conn, id2).unwrap();
        assert!(n2_services.is_empty());
    }

    #[tokio::test]
    async fn partial_batch_does_not_apply_when_one_entry_collides() {
        let db = Db::open_in_memory_for_test();
        let id1 = node_with_id(&db, "n1", "h1").await;
        let id2 = node_with_id(&db, "n2", "h2").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id1, &[("taken".into(), 1, Proto::Tcp)], ApprovalMode::AutoApprove).unwrap();

        let err = upsert_for_node(
            &mut conn,
            id2,
            &[
                ("free-one".into(), 2, Proto::Tcp),
                ("taken".into(), 3, Proto::Tcp),
            ],
            ApprovalMode::AutoApprove,
        )
        .unwrap_err();
        assert!(matches!(err, DbError::ServiceNameCollision(_)));

        // Neither entry from node2's batch should have been applied.
        assert!(list_for_node(&conn, id2).unwrap().is_empty());
    }
}
