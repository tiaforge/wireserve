use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension};
use wireserve_types::{PortMap, ServiceDecl};

use super::DbError;

#[derive(Debug, Clone)]
pub struct ServiceRow {
    pub node_id: i64,
    pub name: String,
    /// The service's own address; see migration 0006. `None` only when the
    /// range had none left to give.
    pub vip4: Option<String>,
    pub ports: Vec<PortMap>,
    pub declared_at: Option<DateTime<Utc>>,
    /// Non-NULL means an admin has approved this node's claim to this
    /// name. NULL with `denied_at` also NULL means pending; NULL with
    /// `denied_at` set means refused. See migration 0003 for why the
    /// pending direction is the one you get by forgetting the column.
    pub approved_at: Option<DateTime<Utc>>,
    pub denied_at: Option<DateTime<Utc>>,
    pub denied_reason: Option<String>,
    /// The mappings as they stood when an admin approved them (PLAN.md
    /// #315, migration 0025). `None` on a row never approved, and on a
    /// denied one.
    pub approved_ports: Option<Vec<PortMap>>,
}

impl ServiceRow {
    /// Whether this row may appear in the directory other nodes receive.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        self.approved_at.is_some() && self.denied_at.is_none()
    }

    /// Approved once, waiting for an admin again since its declaration
    /// went past what was approved ([`needs_review`]).
    #[must_use]
    pub fn is_awaiting_review(&self) -> bool {
        self.approved_at.is_none() && self.denied_at.is_none() && self.approved_ports.is_some()
    }
}

/// Why `declared` needs an admin to approve it again, after `approved` was
/// (PLAN.md #315); `None` while it stays inside what was approved.
///
/// An approval covers the name and where it leads: the target addresses
/// (the node itself, or a device on its LAN) and whether it answers on TCP
/// 443, where its node can get a certificate for the name and every
/// sign-in's session there. A port changing on a target already approved
/// does not count: that node's own listener is its own business, and a
/// re-approval each time would take a working service out of the
/// directory until an admin noticed.
#[must_use]
pub fn needs_review(approved: &[PortMap], declared: &[PortMap]) -> Option<String> {
    let tls = |maps: &[PortMap]| {
        maps.iter().any(|m| m.public == wireserve_types::TLS_PUBLIC_PORT && m.proto == wireserve_types::Proto::Tcp)
    };
    let mut why: Vec<String> = Vec::new();
    let mut new_targets: Vec<Option<std::net::Ipv4Addr>> = Vec::new();
    for m in declared {
        if !approved.iter().any(|a| a.addr == m.addr) && !new_targets.contains(&m.addr) {
            new_targets.push(m.addr);
        }
    }
    for t in new_targets {
        why.push(match t {
            Some(addr) => format!("it now forwards to {addr}"),
            None => "it now forwards to its node's own ports".to_string(),
        });
    }
    if tls(declared) && !tls(approved) {
        why.push("it now answers on TCP 443, which gets its node a certificate for the name".to_string());
    }
    (!why.is_empty()).then(|| why.join("; "))
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
    let dt = |col: &str| -> rusqlite::Result<Option<DateTime<Utc>>> {
        Ok(row
            .get::<_, Option<String>>(col)?
            .as_deref()
            .and_then(parse_dt))
    };
    Ok(ServiceRow {
        node_id: row.get("node_id")?,
        name: row.get("name")?,
        vip4: row.get("vip4")?,
        ports: row
            .get::<_, Option<String>>("ports")?
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default(),
        declared_at: dt("declared_at")?,
        approved_at: dt("approved_at")?,
        denied_at: dt("denied_at")?,
        denied_reason: row.get("denied_reason")?,
        approved_ports: row
            .get::<_, Option<String>>("approved_ports")?
            .map(|json| serde_json::from_str(&json).unwrap_or_default()),
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
    /// What the node should know about the groups it named (PLAN.md M36),
    /// and about a declaration that went past its approval (PLAN.md #315).
    pub notices: Vec<wireserve_types::ServiceNotice>,
    /// Approvals this declaration took back or gave back, for the log.
    pub reviews: Vec<Review>,
}

/// What [`upsert_for_node`] did to one approved name (PLAN.md #315).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Review {
    /// Its declaration went past what was approved; it waits again, for this.
    Again { name: String, why: String },
    /// Its declaration came back inside what was approved.
    Restored { name: String },
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
/// * **An existing approval survives a port or proto change, and nothing
///   more** (PLAN.md #315). What the admin approved is the name and where
///   it leads: its target addresses, and whether it answers on TCP 443. A
///   declaration going past that waits for an admin again ([`review`],
///   [`needs_review`]); a changed port on a target already approved does
///   not, since re-approving on every `serve plex 32401` would drop a
///   working service out of the directory for as long as the admin took to
///   notice.
/// * **A denied row re-declared stays denied.** `excluded.approved_at` is
///   NULL under `RequireApproval`, so the `COALESCE` keeps NULL and the
///   `CASE` preserves `denied_at`. Denial is sticky across the
///   re-declaration the agent performs on its very next cycle, which is
///   what gives it time to learn about the denial and withdraw.
/// * **A pending row heals to approved under `AutoApprove`**, which is
///   what an operator turning the flag back off should get.
///
/// Service addresses (migration 0006): every declaration gets one from
/// `vip_range` the first time, and keeps it for as long as the row lives —
/// across re-declarations, port changes and approval. An exhausted range
/// is logged and leaves the service without one — reachable nowhere —
/// rather than failing the poll: the agent would resend the same
/// declaration every cycle and never get a directory again.
///
/// Groups (PLAN.md M36): a declaration's `group` is stored on a **new** row
/// only, and joins it once the row is approved (see
/// [`super::grants::promote_declared_group`]). A new name naming a group
/// that does not exist is not published at all — it must never land in
/// `default`, where everyone reaches it — and neither kind of problem fails
/// the poll: each becomes a notice, and the other declarations apply.
pub fn upsert_for_node(
    conn: &mut Connection,
    node_id: i64,
    desired: &[ServiceDecl],
    mode: ApprovalMode,
    vip_range: &str,
) -> Result<UpsertOutcome, DbError> {
    let tx = conn.transaction()?;

    // Validate every desired name against other nodes BEFORE mutating
    // anything, so a collision on entry N doesn't leave entries 1..N-1
    // applied.
    for ServiceDecl { name, .. } in desired {
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

    // A new name naming a group it cannot join is left out entirely; since
    // it has no row yet, leaving it out withdraws nothing.
    let mut notices = Vec::new();
    let explicit = super::grants::members(&tx)?;
    let mut accepted: Vec<&ServiceDecl> = Vec::with_capacity(desired.len());
    // Where approval is required, only so many of a node's services may wait
    // for it or be denied: see `MAX_UNAPPROVED_SERVICES_PER_NODE`. Counted
    // once, then as new names are taken.
    let mut unapproved: usize = if mode == ApprovalMode::RequireApproval {
        let n: i64 = tx.query_row(
            "SELECT COUNT(*) FROM services WHERE node_id = ?1 AND approved_at IS NULL",
            [node_id],
            |row| row.get(0),
        )?;
        usize::try_from(n).unwrap_or(usize::MAX)
    } else {
        0
    };
    for d in desired {
        let exists = current.contains(&d.name);
        if !exists && mode == ApprovalMode::RequireApproval {
            if unapproved >= wireserve_types::MAX_UNAPPROVED_SERVICES_PER_NODE {
                notices.push(notice(&d.name, format!(
                    "not published: {} of this node's services are already waiting for approval or denied, which is the \
                     limit; declare it again once an admin has decided some of them",
                    wireserve_types::MAX_UNAPPROVED_SERVICES_PER_NODE
                )));
                continue;
            }
            unapproved += 1;
        }
        match (&d.group, exists) {
            (None, _) => accepted.push(d),
            (Some(group), true) => {
                let groups = super::grants::effective_groups(&explicit, &d.name);
                if !groups.contains(group) {
                    let list = groups.into_iter().collect::<Vec<_>>().join(", ");
                    notices.push(notice(&d.name, format!(
                        "stays in {list}: a declaration names a group only the first time; an admin changes it"
                    )));
                }
                accepted.push(d);
            }
            (Some(group), false) if !wireserve_types::is_valid_dns_label(group) => {
                notices.push(notice(&d.name, format!("{group:?} is not a group name; not published")));
            }
            (Some(group), false) if !super::grants::group_exists(&tx, group)? => {
                notices.push(notice(&d.name, format!("there is no group {group}; not published until an admin creates it")));
            }
            (Some(_), false) => accepted.push(d),
        }
    }

    let desired_names: Vec<&str> = desired.iter().map(|d| d.name.as_str()).collect();

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
    let mut reviews = Vec::new();
    for ServiceDecl { name, ports, group } in accepted {
        // `port` and `proto` are the first mapping's target, kept only
        // because the columns are NOT NULL from migration 0001; nothing
        // reads them.
        let first = ports.first().copied().unwrap_or(PortMap::identity(0, wireserve_types::Proto::Tcp));
        let (port, proto) = (first.target, first.proto);
        let ports_json = serde_json::to_string(ports).expect("PortMap always serializes");
        tx.execute(
            "INSERT INTO services (node_id, name, port, proto, ports, declared_at, approved_at, declared_group) \
             VALUES (?1, ?2, ?3, ?4, ?7, ?5, ?6, ?8) \
             ON CONFLICT(name) DO UPDATE SET \
               port = excluded.port, \
               proto = excluded.proto, \
               ports = excluded.ports, \
               approved_at = COALESCE(services.approved_at, excluded.approved_at), \
               denied_at = CASE \
                 WHEN COALESCE(services.approved_at, excluded.approved_at) IS NULL \
                 THEN services.denied_at ELSE NULL END, \
               denied_reason = CASE \
                 WHEN COALESCE(services.approved_at, excluded.approved_at) IS NULL \
                 THEN services.denied_reason ELSE NULL END \
             WHERE node_id = excluded.node_id",
            rusqlite::params![node_id, name, port, proto.as_str(), now, stamp, ports_json, group],
        )?;
        reviews.extend(review(&tx, node_id, name, mode)?);
        assign_vip(&tx, node_id, name, vip_range)?;
        super::grants::promote_declared_group(&tx, name)?;
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
        // Said on every poll while it waits: the agent keeps only the
        // latest poll's notices.
        for row in pending.iter().filter(|r| r.is_awaiting_review()) {
            let why = needs_review(row.approved_ports.as_deref().unwrap_or_default(), &row.ports)
                .unwrap_or_else(|| "what it declares changed since it was approved".to_string());
            notices.push(notice(&row.name, format!("waiting for an admin to approve it again: {why}")));
        }
        UpsertOutcome { pending, denied, notices, reviews }
    };

    tx.commit()?;
    Ok(outcome)
}

/// Keeps `name`'s approval to what an admin approved (PLAN.md #315). With
/// approval required, an approved declaration that went past it
/// ([`needs_review`]) waits for an admin again — out of the directory, its
/// public name and its certificate with it — and one waiting that came back
/// inside it is approved again. With approval off, what is declared is what
/// is approved.
fn review(tx: &Connection, node_id: i64, name: &str, mode: ApprovalMode) -> Result<Option<Review>, DbError> {
    let Some(row) = row_for_name(tx, name)?.filter(|r| r.node_id == node_id) else {
        return Ok(None);
    };
    let params = rusqlite::params![name, node_id];
    match mode {
        ApprovalMode::AutoApprove => {
            if row.is_approved() {
                tx.execute("UPDATE services SET approved_ports = ports WHERE name = ?1 AND node_id = ?2", params)?;
            }
            Ok(None)
        }
        ApprovalMode::RequireApproval => {
            let approved = row.approved_ports.as_deref().unwrap_or_default();
            if row.is_approved() {
                let Some(why) = needs_review(approved, &row.ports) else {
                    return Ok(None);
                };
                // An approval with nothing on record approved nothing.
                tx.execute(
                    "UPDATE services SET approved_at = NULL, approved_ports = COALESCE(approved_ports, '[]') \
                     WHERE name = ?1 AND node_id = ?2",
                    params,
                )?;
                Ok(Some(Review::Again { name: name.to_string(), why }))
            } else if row.is_awaiting_review() && needs_review(approved, &row.ports).is_none() {
                tx.execute(
                    "UPDATE services SET approved_at = ?1 WHERE name = ?2 AND node_id = ?3",
                    rusqlite::params![super::nodes::now_str(), name, node_id],
                )?;
                Ok(Some(Review::Restored { name: name.to_string() }))
            } else {
                Ok(None)
            }
        }
    }
}

fn notice(name: &str, reason: String) -> wireserve_types::ServiceNotice {
    wireserve_types::ServiceNotice { name: name.to_string(), reason }
}

/// A released service address still held back (PLAN.md #273, migration
/// 0021), and the devices holding it: every live phone whose `.conf` may
/// still route it to the node that had it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hold {
    pub vip4: std::net::Ipv4Addr,
    /// The node that had it; `None` once that node is gone.
    pub node_id: Option<i64>,
    /// Device names, sorted.
    pub devices: Vec<String>,
}

/// Every address still held, and by whom. A held address is released for
/// good once no live device was exported before its release — never
/// exported counts as before — and its row is removed then.
pub fn holds(conn: &Connection) -> Result<Vec<Hold>, DbError> {
    let released: Vec<(String, Option<i64>, String)> = {
        let mut stmt = conn.prepare("SELECT vip4, node_id, released_at FROM released_service_addresses ORDER BY vip4")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    if released.is_empty() {
        return Ok(Vec::new());
    }
    // Phones whose `.conf` works: registered, not revoked. A revoked or
    // rejoined one's key is gone from every node.
    let devices: Vec<(String, Option<DateTime<Utc>>)> = {
        let mut stmt = conn.prepare(
            "SELECT name, exported_at FROM nodes WHERE kind = 'static' AND revoked = 0 AND pubkey IS NOT NULL ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)))?;
        rows.map(|r| r.map(|(n, e)| (n, e.as_deref().and_then(parse_dt)))).collect::<Result<_, _>>()?
    };
    let mut out = Vec::new();
    for (vip4, node_id, released_at) in released {
        // Unparseable: held for as long as any device exists, rather than
        // let go on a guess. The trigger stamps milliseconds, so an export
        // within the same millisecond counts as before.
        let released_at = parse_dt(&released_at);
        let holders: Vec<String> = devices
            .iter()
            .filter(|(_, exported)| match (exported, released_at) {
                (Some(e), Some(r)) => e.timestamp_millis() <= r.timestamp_millis(),
                _ => true,
            })
            .map(|(n, _)| n.clone())
            .collect();
        match (holders.is_empty(), vip4.parse()) {
            (false, Ok(vip4)) => out.push(Hold { vip4, node_id, devices: holders }),
            _ => {
                conn.execute("DELETE FROM released_service_addresses WHERE vip4 = ?1", [&vip4])?;
            }
        }
    }
    Ok(out)
}

/// Gives `name` an address from `vip_range` unless it already has one.
///
/// Not for a denied one: it holds its name until its node withdraws it, but
/// an address of the mesh's range is not worth holding for a service nobody
/// reaches. It gets one if it is approved after all (`approve`).
///
/// A held address (PLAN.md #273) goes to nobody but the node that had it,
/// which takes its own back first: phones that are not up to date send it
/// to that node anyway. When only held addresses are left, the service gets
/// none, and the log names the devices to refresh.
fn assign_vip(tx: &Connection, node_id: i64, name: &str, vip_range: &str) -> Result<(), DbError> {
    let (has, denied): (Option<String>, bool) = tx.query_row(
        "SELECT vip4, approved_at IS NULL AND denied_at IS NOT NULL FROM services WHERE node_id = ?1 AND name = ?2",
        rusqlite::params![node_id, name],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if has.is_some() || denied {
        return Ok(());
    }
    let mut used = super::nodes::all_allocated_ip4(tx)?;
    let holds = holds(tx)?;
    let own = holds.iter().filter(|h| h.node_id == Some(node_id) && !used.contains(&h.vip4)).map(|h| h.vip4).min();
    used.extend(holds.iter().map(|h| h.vip4));
    match own.map_or_else(|| crate::ipam::allocate_v4(vip_range, &used), Ok) {
        Ok(vip) => {
            tx.execute(
                "UPDATE services SET vip4 = ?1 WHERE node_id = ?2 AND name = ?3",
                rusqlite::params![vip.to_string(), node_id, name],
            )?;
            tx.execute("DELETE FROM released_service_addresses WHERE vip4 = ?1", [vip.to_string()])?;
            tracing::info!(event = "service_address_assigned", service = %name, vip4 = %vip);
        }
        Err(crate::ipam::IpamError::Exhausted) if !holds.is_empty() => {
            let mut devices: Vec<&str> = holds.iter().flat_map(|h| h.devices.iter().map(String::as_str)).collect();
            devices.sort_unstable();
            devices.dedup();
            tracing::warn!(
                service = %name,
                range = %vip_range,
                held = holds.len(),
                devices = %devices.join(","),
                "no address left for a service but ones held back for devices not exported since they were released; \
                 `device refresh` or delete those devices to free them. It stays reachable at its node's address only"
            );
        }
        Err(e) => tracing::warn!(
            service = %name,
            range = %vip_range,
            error = %e,
            "no address left for a service; it stays reachable at its node's address only"
        ),
    }
    Ok(())
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

/// The row declaring `name`, whoever owns it.
pub fn find_by_name(conn: &Connection, name: &str) -> Result<Option<ServiceRow>, DbError> {
    row_for_name(conn, name)
}

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
pub fn approve(conn: &Connection, node_id: i64, name: &str, vip_range: &str) -> Result<ApproveOutcome, DbError> {
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
        "UPDATE services SET approved_at = ?1, denied_at = NULL, denied_reason = NULL, approved_ports = ports \
         WHERE name = ?2 AND node_id = ?3",
        // The `AND node_id = ?3` is redundant given the check above and
        // stays anyway: it is the last line of defence for the
        // bind-to-the-declaring-node rule, and costs nothing.
        rusqlite::params![super::nodes::now_str(), name, node_id],
    )?;
    // Approved after a denial, it has no address yet.
    assign_vip(&tx, node_id, name, vip_range)?;
    super::grants::promote_declared_group(&tx, name)?;
    tx.commit()?;
    Ok(ApproveOutcome::Approved)
}

/// Denies `name` for `node_id`, optionally recording a reason the
/// declaring node will see in `wireserve status`.
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
        "UPDATE services SET denied_at = ?1, denied_reason = ?2, approved_at = NULL, approved_ports = NULL, \
         vip4 = NULL WHERE name = ?3 AND node_id = ?4",
        rusqlite::params![super::nodes::now_str(), reason, name, node_id],
    )?;
    tx.commit()?;
    Ok(DenyOutcome::Denied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::Proto;
    use crate::db::nodes::{apply_redemption, create_node, Redemption};
    use crate::db::Db;
    use wireserve_types::NodeKind;

    const RANGE: &str = "100.90.0.0/24";

    /// A declaration of one identity mapping.
    fn decl(name: &str, port: u16, proto: Proto) -> ServiceDecl {
        ServiceDecl::new(name, vec![PortMap::identity(port, proto)])
    }

    fn mapped(name: &str, maps: &[&str]) -> ServiceDecl {
        ServiceDecl::new(name, maps.iter().map(|m| m.parse().unwrap()).collect())
    }

    fn vip_of(conn: &Connection, name: &str) -> Option<String> {
        row_for_name(conn, name).unwrap().unwrap().vip4
    }

    #[tokio::test]
    async fn a_declaration_with_ports_gets_an_address_off_every_node() {
        let db = Db::open_in_memory_for_test();
        let id1 = node_with_id(&db, "n1", "h1").await; // 100.90.0.1
        let id2 = node_with_id(&db, "n2", "h2").await; // 100.90.0.2
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id1, &[mapped("web", &["80:5080"]), mapped("dns", &["53/udp"])], ApprovalMode::AutoApprove, RANGE).unwrap();
        let web = vip_of(&conn, "web").unwrap();
        let dns = vip_of(&conn, "dns").unwrap();
        assert_eq!(web, "100.90.0.3");
        assert_eq!(dns, "100.90.0.4");
        // And a node registered next avoids them.
        let used = crate::db::nodes::all_allocated_ip4(&conn).unwrap();
        assert_eq!(crate::ipam::allocate_v4(RANGE, &used).unwrap().to_string(), "100.90.0.5");
        let row = row_for_name(&conn, "web").unwrap().unwrap();
        assert_eq!(row.ports, vec!["80:5080".parse::<PortMap>().unwrap()]);
        let _ = id2;
    }

    #[tokio::test]
    async fn a_service_keeps_its_address_across_redeclarations_and_approval() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[mapped("web", &["80:5080"])], ApprovalMode::RequireApproval, RANGE).unwrap();
        let first = vip_of(&conn, "web").unwrap();
        // A pending service already has its address (its owner's firewall
        // gets ready before approval).
        upsert_for_node(&mut conn, id, &[mapped("other", &["1"]), mapped("web", &["80:5080", "443:5443"])], ApprovalMode::RequireApproval, RANGE).unwrap();
        approve(&conn, id, "web", "10.9.0.0/24").unwrap();
        upsert_for_node(&mut conn, id, &[mapped("web", &["8080:5080"])], ApprovalMode::RequireApproval, RANGE).unwrap();
        assert_eq!(vip_of(&conn, "web").unwrap(), first);
        assert_eq!(row_for_name(&conn, "web").unwrap().unwrap().ports, vec!["8080:5080".parse::<PortMap>().unwrap()]);
    }

    #[tokio::test]
    async fn withdrawing_a_service_frees_its_address() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[mapped("web", &["80:5080"])], ApprovalMode::AutoApprove, RANGE).unwrap();
        let vip = vip_of(&conn, "web").unwrap();
        upsert_for_node(&mut conn, id, &[], ApprovalMode::AutoApprove, RANGE).unwrap();
        upsert_for_node(&mut conn, id, &[mapped("api", &["80:6080"])], ApprovalMode::AutoApprove, RANGE).unwrap();
        assert_eq!(vip_of(&conn, "api").unwrap(), vip, "the freed address is the first free one again");
    }

    // ---- held addresses (PLAN.md #273) ----

    /// A registered phone, exported now unless `exported` is false.
    async fn device(db: &Db, name: &str, exported: bool) -> i64 {
        let conn = db.conn.lock().await;
        let id = create_node(&conn, name, NodeKind::Static, &format!("h-{name}"), None).unwrap();
        apply_redemption(
            &conn,
            id,
            &Redemption {
                pubkey: &format!("pk-{id}"),
                ip4: format!("100.90.0.{}", 200 + id).parse().unwrap(),
                ip6: format!("fd00:90::{}", 200 + id).parse().unwrap(),
                listen_port: None,
                endpoint_addr: None,
                endpoint_addr_v4: None,
                endpoint_addr_v6: None,
                lan_addr: None,
                reflexive_addr: None,
                bearer_token_hash: &format!("bearer-{name}"),
            },
        )
        .unwrap();
        drop(conn);
        if exported {
            export(db, id).await;
        }
        id
    }

    async fn export(db: &Db, id: i64) {
        // The release trigger stamps milliseconds: keep each step apart.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        crate::db::nodes::record_export(&mut *db.conn.lock().await, id, None, &[]).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    fn held(conn: &Connection) -> Vec<(String, Option<i64>, Vec<String>)> {
        holds(conn).unwrap().into_iter().map(|h| (h.vip4.to_string(), h.node_id, h.devices)).collect()
    }

    #[tokio::test]
    async fn a_released_address_waits_for_the_phones_exported_before_it() {
        let db = Db::open_in_memory_for_test();
        let x = node_with_id(&db, "x", "hx").await; // .1
        let y = node_with_id(&db, "y", "hy").await; // .2
        upsert_for_node(&mut *db.conn.lock().await, x, &[mapped("a", &["80"])], ApprovalMode::AutoApprove, RANGE).unwrap();
        let a = vip_of(&*db.conn.lock().await, "a").unwrap();
        let phone = device(&db, "phone", true).await;
        upsert_for_node(&mut *db.conn.lock().await, x, &[], ApprovalMode::AutoApprove, RANGE).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let late = device(&db, "late", true).await;

        let mut conn = db.conn.lock().await;
        assert_eq!(held(&conn), [(a.clone(), Some(x), vec!["phone".to_string()])], "only the phone exported before");
        upsert_for_node(&mut conn, y, &[mapped("b", &["80"])], ApprovalMode::AutoApprove, RANGE).unwrap();
        assert_ne!(vip_of(&conn, "b").unwrap(), a, "another node's service does not get it");
        drop(conn);

        export(&db, phone).await;
        let mut conn = db.conn.lock().await;
        assert!(held(&conn).is_empty(), "exported again: let go");
        upsert_for_node(&mut conn, y, &[mapped("b", &["80"]), mapped("c", &["80"])], ApprovalMode::AutoApprove, RANGE).unwrap();
        assert_eq!(vip_of(&conn, "c").unwrap(), a, "free for anyone now");
        let _ = late;
    }

    #[tokio::test]
    async fn its_own_node_takes_a_held_address_back_first() {
        let db = Db::open_in_memory_for_test();
        let x = node_with_id(&db, "x", "hx").await;
        upsert_for_node(&mut *db.conn.lock().await, x, &[mapped("a", &["80"]), mapped("z", &["80"])], ApprovalMode::AutoApprove, RANGE).unwrap();
        let (a, z) = {
            let conn = db.conn.lock().await;
            (vip_of(&conn, "a").unwrap(), vip_of(&conn, "z").unwrap())
        };
        device(&db, "phone", true).await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, x, &[mapped("z", &["80"])], ApprovalMode::AutoApprove, RANGE).unwrap();
        upsert_for_node(&mut conn, x, &[mapped("z", &["80"]), mapped("b", &["80"])], ApprovalMode::AutoApprove, RANGE).unwrap();
        assert_eq!(vip_of(&conn, "b").unwrap(), a);
        assert!(held(&conn).is_empty(), "taken back, no longer held");
        let _ = z;
    }

    #[tokio::test]
    async fn a_device_never_exported_or_revoked_counts_as_it_should() {
        let db = Db::open_in_memory_for_test();
        let x = node_with_id(&db, "x", "hx").await;
        upsert_for_node(&mut *db.conn.lock().await, x, &[mapped("a", &["80"])], ApprovalMode::AutoApprove, RANGE).unwrap();
        let never = device(&db, "never", false).await;
        upsert_for_node(&mut *db.conn.lock().await, x, &[], ApprovalMode::AutoApprove, RANGE).unwrap();
        let conn = db.conn.lock().await;
        assert_eq!(held(&conn)[0].2, ["never"], "never exported: its .conf may hold anything");
        crate::db::nodes::revoke(&conn, never).unwrap();
        assert!(held(&conn).is_empty(), "a revoked device's key is gone everywhere");
    }

    #[tokio::test]
    async fn only_an_approved_services_address_is_held() {
        let db = Db::open_in_memory_for_test();
        let x = node_with_id(&db, "x", "hx").await;
        device(&db, "phone", true).await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, x, &[mapped("p", &["80"])], ApprovalMode::RequireApproval, RANGE).unwrap();
        upsert_for_node(&mut conn, x, &[], ApprovalMode::RequireApproval, RANGE).unwrap();
        assert!(held(&conn).is_empty(), "pending: no device was ever given it");

        upsert_for_node(&mut conn, x, &[mapped("q", &["80"])], ApprovalMode::RequireApproval, RANGE).unwrap();
        approve(&conn, x, "q", RANGE).unwrap();
        let q = vip_of(&conn, "q").unwrap();
        deny(&conn, x, "q", None).unwrap();
        assert_eq!(held(&conn), [(q, Some(x), vec!["phone".to_string()])], "denied after approval");
    }

    #[tokio::test]
    async fn a_deleted_nodes_addresses_are_held_and_nobody_takes_them_back() {
        let db = Db::open_in_memory_for_test();
        let x = node_with_id(&db, "x", "hx").await;
        upsert_for_node(&mut *db.conn.lock().await, x, &[mapped("a", &["80"])], ApprovalMode::AutoApprove, RANGE).unwrap();
        let a = vip_of(&*db.conn.lock().await, "a").unwrap();
        device(&db, "phone", true).await;
        let conn = db.conn.lock().await;
        crate::db::nodes::revoke(&conn, x).unwrap();
        assert_eq!(held(&conn), [(a.clone(), Some(x), vec!["phone".to_string()])], "revoked: its services go, and are held");
        crate::db::nodes::delete_node(&conn, x).unwrap();
        assert_eq!(held(&conn), [(a, None, vec!["phone".to_string()])], "deleted: held for nobody in particular");
    }

    #[tokio::test]
    async fn a_range_left_with_only_held_addresses_gives_none() {
        let db = Db::open_in_memory_for_test();
        let x = node_with_id(&db, "x", "hx").await; // .1
        let y = node_with_id(&db, "y", "hy").await; // .2
        let range = "100.90.0.0/29"; // .1 to .6
        upsert_for_node(&mut *db.conn.lock().await, x, &[mapped("a", &["1"]), mapped("b", &["2"]), mapped("c", &["3"])], ApprovalMode::AutoApprove, range).unwrap();
        device(&db, "phone", true).await; // takes no address of this range
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, x, &[], ApprovalMode::AutoApprove, range).unwrap();
        upsert_for_node(&mut conn, y, &[mapped("d", &["1"])], ApprovalMode::AutoApprove, range).unwrap();
        assert_eq!(vip_of(&conn, "d").as_deref(), Some("100.90.0.6"));
        upsert_for_node(&mut conn, y, &[mapped("d", &["1"]), mapped("e", &["1"])], ApprovalMode::AutoApprove, range).unwrap();
        assert_eq!(vip_of(&conn, "e"), None, "never one held for a phone");
    }

    #[tokio::test]
    async fn an_exhausted_range_leaves_the_service_without_an_address_but_declared() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await; // 100.90.0.1, the only host of a /30 besides .2
        let mut conn = db.conn.lock().await;
        let range = "100.90.0.0/30";
        let outcome = upsert_for_node(&mut conn, id, &[mapped("a", &["1"]), mapped("b", &["2"])], ApprovalMode::AutoApprove, range).unwrap();
        assert!(outcome.pending.is_empty());
        assert_eq!(vip_of(&conn, "a").as_deref(), Some("100.90.0.2"));
        assert_eq!(vip_of(&conn, "b"), None);
        assert_eq!(list_for_node(&conn, id).unwrap().len(), 2);
    }

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
                lan_addr: None,
                reflexive_addr: None,
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
        upsert_for_node(&mut conn, id, &[decl("plex", 32400, Proto::Tcp)], ApprovalMode::AutoApprove, RANGE).unwrap();
        assert_eq!(list_for_node(&conn, id).unwrap().len(), 1);

        upsert_for_node(&mut conn, id, &[], ApprovalMode::AutoApprove, RANGE).unwrap();
        assert_eq!(list_for_node(&conn, id).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn auto_approve_puts_a_declaration_straight_into_the_directory() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        let outcome = upsert_for_node(&mut conn, id, &[decl("plex", 32400, Proto::Tcp)], ApprovalMode::AutoApprove, RANGE).unwrap();
        assert_eq!(list_approved(&conn).unwrap().len(), 1);
        assert!(outcome.pending.is_empty());
        assert!(outcome.denied.is_empty());
    }

    #[tokio::test]
    async fn require_approval_keeps_a_declaration_out_of_the_directory() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        let outcome = upsert_for_node(&mut conn, id, &[decl("plex", 32400, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap();
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

        upsert_for_node(&mut conn, id1, &[decl("plex", 1, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap();
        assert_eq!(approve(&conn, id1, "plex", "10.9.0.0/24").unwrap(), ApproveOutcome::Approved);
        assert_eq!(list_approved(&conn).unwrap().len(), 1);

        upsert_for_node(&mut conn, id1, &[], ApprovalMode::RequireApproval, RANGE).unwrap();
        let outcome = upsert_for_node(&mut conn, id2, &[decl("plex", 1, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap();

        assert!(list_approved(&conn).unwrap().is_empty());
        assert_eq!(outcome.pending.len(), 1, "n2 inherits nothing from n1's approval");
    }

    #[tokio::test]
    async fn approve_refuses_a_name_declared_by_another_node() {
        let db = Db::open_in_memory_for_test();
        let id1 = node_with_id(&db, "n1", "h1").await;
        let id2 = node_with_id(&db, "n2", "h2").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id1, &[decl("plex", 1, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap();

        assert_eq!(
            approve(&conn, id2, "plex", "10.9.0.0/24").unwrap(),
            ApproveOutcome::OwnedByAnotherNode { owner_node_id: id1 }
        );
        assert!(list_approved(&conn).unwrap().is_empty(), "a refused approval must leave no trace");
    }

    #[tokio::test]
    async fn approve_is_idempotent_and_does_not_move_the_timestamp() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[decl("plex", 1, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap();

        approve(&conn, id, "plex", "10.9.0.0/24").unwrap();
        let first = list_approved(&conn).unwrap()[0].approved_at;
        assert_eq!(approve(&conn, id, "plex", "10.9.0.0/24").unwrap(), ApproveOutcome::AlreadyApproved);
        assert_eq!(list_approved(&conn).unwrap()[0].approved_at, first);
    }

    #[tokio::test]
    async fn approve_on_an_undeclared_name_reports_not_declared() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let conn = db.conn.lock().await;
        assert_eq!(approve(&conn, id, "nothing", "10.9.0.0/24").unwrap(), ApproveOutcome::NotDeclared);
    }

    #[tokio::test]
    async fn a_port_change_keeps_an_existing_approval() {
        // What was approved is the name binding. Re-approving on every
        // `serve plex 32401` would drop a working service out of the
        // directory until an admin noticed.
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[decl("plex", 32400, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap();
        approve(&conn, id, "plex", "10.9.0.0/24").unwrap();

        let outcome = upsert_for_node(&mut conn, id, &[decl("plex", 32401, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap();

        assert!(outcome.pending.is_empty(), "a port change is not a re-claim");
        let rows = list_approved(&conn).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ports, vec![PortMap::identity(32401, Proto::Tcp)]);
    }

    fn maps(list: &[&str]) -> Vec<PortMap> {
        list.iter().map(|m| m.parse().unwrap()).collect()
    }

    #[test]
    fn an_approval_covers_its_targets_and_whether_it_answers_on_443() {
        let approved = maps(&["80:32400", "443:192.168.178.1:80"]);
        assert_eq!(needs_review(&approved, &maps(&["8080:32401", "443:192.168.178.1:8443"])), None, "ports alone");
        assert_eq!(
            needs_review(&approved, &maps(&["443:192.168.178.2:80"])).as_deref(),
            Some("it now forwards to 192.168.178.2"),
        );
        assert_eq!(
            needs_review(&maps(&["443:192.168.178.1:80"]), &maps(&["443:192.168.178.1:80", "22"])).as_deref(),
            Some("it now forwards to its node's own ports"),
        );
        let why = needs_review(&maps(&["80:32400"]), &maps(&["80:32400", "443:32400"])).unwrap();
        assert!(why.starts_with("it now answers on TCP 443"), "{why}");
        assert_eq!(needs_review(&maps(&["443/udp"]), &maps(&["443"])).as_deref().map(|w| w.contains("443")), Some(true));
        assert!(needs_review(&[], &maps(&["80"])).is_some(), "nothing on record approved nothing");
    }

    #[tokio::test]
    async fn going_past_an_approval_waits_for_an_admin_again_and_coming_back_does_not() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        let declare = |conn: &mut Connection, list: &[&str]| {
            upsert_for_node(conn, id, &[mapped("plex", list)], ApprovalMode::RequireApproval, RANGE).unwrap()
        };
        declare(&mut conn, &["80:32400"]);
        approve(&conn, id, "plex", RANGE).unwrap();
        let vip = vip_of(&conn, "plex");

        let out = declare(&mut conn, &["80:32400", "443:192.168.178.1:80"]);
        assert_eq!(out.pending.len(), 1, "back to waiting");
        assert!(list_approved(&conn).unwrap().is_empty(), "out of the directory");
        let why = &out.notices.iter().find(|n| n.name == "plex").expect("told why").reason;
        assert!(why.contains("192.168.178.1") && why.contains("TCP 443"), "{why}");
        assert!(matches!(&out.reviews[..], [Review::Again { name, .. }] if name == "plex"));
        let row = row_for_name(&conn, "plex").unwrap().unwrap();
        assert!(row.is_awaiting_review());
        assert_eq!(row.approved_ports, Some(maps(&["80:32400"])), "what was approved stays on record");
        assert_eq!(row.vip4, vip, "it keeps its address");

        // Told again on the next poll, not only the first: the agent keeps
        // the latest poll's notices alone.
        let out = declare(&mut conn, &["80:32400", "443:192.168.178.1:80"]);
        assert!(out.notices.iter().any(|n| n.name == "plex"), "still told");
        assert!(out.reviews.is_empty(), "nothing changed this time");

        // Back inside what was approved, a port aside: approved again.
        let out = declare(&mut conn, &["8080:32400"]);
        assert!(out.pending.is_empty() && out.notices.is_empty());
        assert!(matches!(&out.reviews[..], [Review::Restored { name }] if name == "plex"));
        assert_eq!(list_approved(&conn).unwrap().len(), 1);

        // An admin approving the change makes it what is approved.
        declare(&mut conn, &["443:192.168.178.1:80"]);
        assert_eq!(approve(&conn, id, "plex", RANGE).unwrap(), ApproveOutcome::Approved);
        let out = declare(&mut conn, &["443:192.168.178.1:80"]);
        assert!(out.pending.is_empty() && out.reviews.is_empty());
        assert_eq!(row_for_name(&conn, "plex").unwrap().unwrap().approved_ports, Some(maps(&["443:192.168.178.1:80"])));
    }

    #[tokio::test]
    async fn a_denial_takes_back_what_was_approved() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[mapped("plex", &["80"])], ApprovalMode::RequireApproval, RANGE).unwrap();
        approve(&conn, id, "plex", RANGE).unwrap();
        upsert_for_node(&mut conn, id, &[mapped("plex", &["80", "443"])], ApprovalMode::RequireApproval, RANGE).unwrap();
        deny(&conn, id, "plex", None).unwrap();
        // Back inside the old approval, it stays denied.
        let out = upsert_for_node(&mut conn, id, &[mapped("plex", &["80"])], ApprovalMode::RequireApproval, RANGE).unwrap();
        assert_eq!(out.denied.len(), 1);
        let row = row_for_name(&conn, "plex").unwrap().unwrap();
        assert!(row.approved_ports.is_none() && !row.is_awaiting_review());
    }

    #[tokio::test]
    async fn with_approval_off_what_is_declared_is_what_is_approved() {
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[mapped("plex", &["80"])], ApprovalMode::AutoApprove, RANGE).unwrap();
        let out = upsert_for_node(&mut conn, id, &[mapped("plex", &["443:192.168.178.1:80"])], ApprovalMode::AutoApprove, RANGE).unwrap();
        assert!(out.pending.is_empty() && out.reviews.is_empty());
        assert_eq!(row_for_name(&conn, "plex").unwrap().unwrap().approved_ports, Some(maps(&["443:192.168.178.1:80"])));
        // Switched on later, the approval covers what was last declared.
        let out = upsert_for_node(&mut conn, id, &[mapped("plex", &["443:192.168.178.1:80"])], ApprovalMode::RequireApproval, RANGE).unwrap();
        assert!(out.pending.is_empty());
    }

    #[tokio::test]
    async fn redeclaring_a_denied_service_stays_denied() {
        // The agent re-sends its whole declaration list on the very next
        // cycle, so a denial that did not stick would be undone before
        // the node ever learned about it.
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[decl("plex", 1, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap();
        assert_eq!(deny(&conn, id, "plex", Some("not this one")).unwrap(), DenyOutcome::Denied);

        let outcome = upsert_for_node(&mut conn, id, &[decl("plex", 1, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap();

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
        upsert_for_node(&mut conn, id1, &[decl("plex", 1, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap();
        deny(&conn, id1, "plex", None).unwrap();

        upsert_for_node(&mut conn, id1, &[], ApprovalMode::RequireApproval, RANGE).unwrap();
        upsert_for_node(&mut conn, id2, &[decl("plex", 1, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap();

        assert_eq!(owner_of(&conn, "plex").unwrap(), Some(id2));
    }

    #[tokio::test]
    async fn deny_withdraws_an_approval_already_granted() {
        // The re-review lever for a mesh where enabling approval
        // grandfathered everything already declared.
        let db = Db::open_in_memory_for_test();
        let id = node_with_id(&db, "n1", "h1").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id, &[decl("plex", 1, Proto::Tcp)], ApprovalMode::AutoApprove, RANGE).unwrap();
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
        upsert_for_node(&mut conn, id, &[decl("plex", 1, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap();
        deny(&conn, id, "plex", Some("on reflection, no")).unwrap();

        assert_eq!(approve(&conn, id, "plex", "10.9.0.0/24").unwrap(), ApproveOutcome::Approved);
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
        upsert_for_node(&mut conn, id, &[decl("a", 1, Proto::Tcp), decl("b", 2, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap();
        deny(&conn, id, "b", None).unwrap();

        let outcome = upsert_for_node(&mut conn, id, &[decl("a", 1, Proto::Tcp), decl("b", 2, Proto::Tcp)], ApprovalMode::AutoApprove, RANGE).unwrap();

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
        upsert_for_node(&mut conn, id1, &[decl("plex", 1, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap();

        let err = upsert_for_node(&mut conn, id2, &[decl("plex", 1, Proto::Tcp)], ApprovalMode::RequireApproval, RANGE).unwrap_err();
        assert!(matches!(err, DbError::ServiceNameCollision(_)));
    }

    #[tokio::test]
    async fn cross_node_collision_rejected_and_first_nodes_service_untouched() {
        let db = Db::open_in_memory_for_test();
        let id1 = node_with_id(&db, "n1", "h1").await;
        let id2 = node_with_id(&db, "n2", "h2").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id1, &[decl("plex", 32400, Proto::Tcp)], ApprovalMode::AutoApprove, RANGE).unwrap();

        let err = upsert_for_node(&mut conn, id2, &[decl("plex", 1, Proto::Tcp)], ApprovalMode::AutoApprove, RANGE).unwrap_err();
        match err {
            DbError::ServiceNameCollision(name) => assert_eq!(name, "plex"),
            other => panic!("expected collision error, got {other:?}"),
        }

        // node1's own service must be untouched.
        let n1_services = list_for_node(&conn, id1).unwrap();
        assert_eq!(n1_services.len(), 1);
        assert_eq!(n1_services[0].ports, vec![PortMap::identity(32400, Proto::Tcp)]);
        let n2_services = list_for_node(&conn, id2).unwrap();
        assert!(n2_services.is_empty());
    }

    #[tokio::test]
    async fn partial_batch_does_not_apply_when_one_entry_collides() {
        let db = Db::open_in_memory_for_test();
        let id1 = node_with_id(&db, "n1", "h1").await;
        let id2 = node_with_id(&db, "n2", "h2").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id1, &[decl("taken", 1, Proto::Tcp)], ApprovalMode::AutoApprove, RANGE).unwrap();

        let err = upsert_for_node(
            &mut conn,
            id2,
            &[
                decl("free-one", 2, Proto::Tcp),
                decl("taken", 3, Proto::Tcp),
            ],
            ApprovalMode::AutoApprove,
            RANGE,
        )
        .unwrap_err();
        assert!(matches!(err, DbError::ServiceNameCollision(_)));

        // Neither entry from node2's batch should have been applied.
        assert!(list_for_node(&conn, id2).unwrap().is_empty());
    }
}
