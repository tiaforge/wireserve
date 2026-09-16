use rusqlite::{Connection, OptionalExtension};
use wireserve_types::Proto;

use super::DbError;

#[derive(Debug, Clone)]
pub struct ServiceRow {
    pub node_id: i64,
    pub name: String,
    pub port: u16,
    pub proto: Proto,
}

fn map_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ServiceRow> {
    let proto_str: String = row.get("proto")?;
    let port: i64 = row.get("port")?;
    Ok(ServiceRow {
        node_id: row.get("node_id")?,
        name: row.get("name")?,
        port: port as u16,
        proto: proto_str.parse().unwrap_or(Proto::Tcp),
    })
}

pub fn list_for_node(conn: &Connection, node_id: i64) -> Result<Vec<ServiceRow>, DbError> {
    let mut stmt = conn.prepare("SELECT * FROM services WHERE node_id = ?1")?;
    let rows = stmt.query_map([node_id], map_row)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
}

pub fn list_all(conn: &Connection) -> Result<Vec<ServiceRow>, DbError> {
    let mut stmt = conn.prepare("SELECT * FROM services")?;
    let rows = stmt.query_map([], map_row)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(DbError::from)
}

/// Returns the node_id that owns `name`, if any exists anywhere in the
/// table (uniqueness is enforced across the whole table, not per-node —
/// spec §3).
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
pub fn upsert_for_node(
    conn: &mut Connection,
    node_id: i64,
    desired: &[(String, u16, Proto)],
) -> Result<(), DbError> {
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

    for (name, port, proto) in desired {
        tx.execute(
            "INSERT INTO services (node_id, name, port, proto) VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(name) DO UPDATE SET port = excluded.port, proto = excluded.proto \
             WHERE node_id = excluded.node_id",
            rusqlite::params![node_id, name, port, proto.as_str()],
        )?;
    }

    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::nodes::{apply_redemption, create_node, Redemption};
    use crate::db::Db;
    use wireserve_types::NodeKind;

    async fn node_with_id(db: &Db, name: &str, hash: &str) -> i64 {
        let conn = db.conn.lock().await;
        let id = create_node(&conn, name, NodeKind::Agent, hash).unwrap();
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
        upsert_for_node(&mut conn, id, &[("plex".into(), 32400, Proto::Tcp)]).unwrap();
        assert_eq!(list_for_node(&conn, id).unwrap().len(), 1);

        upsert_for_node(&mut conn, id, &[]).unwrap();
        assert_eq!(list_for_node(&conn, id).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn cross_node_collision_rejected_and_first_nodes_service_untouched() {
        let db = Db::open_in_memory_for_test();
        let id1 = node_with_id(&db, "n1", "h1").await;
        let id2 = node_with_id(&db, "n2", "h2").await;
        let mut conn = db.conn.lock().await;
        upsert_for_node(&mut conn, id1, &[("plex".into(), 32400, Proto::Tcp)]).unwrap();

        let err = upsert_for_node(&mut conn, id2, &[("plex".into(), 1, Proto::Tcp)]).unwrap_err();
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
        upsert_for_node(&mut conn, id1, &[("taken".into(), 1, Proto::Tcp)]).unwrap();

        let err = upsert_for_node(
            &mut conn,
            id2,
            &[
                ("free-one".into(), 2, Proto::Tcp),
                ("taken".into(), 3, Proto::Tcp),
            ],
        )
        .unwrap_err();
        assert!(matches!(err, DbError::ServiceNameCollision(_)));

        // Neither entry from node2's batch should have been applied.
        assert!(list_for_node(&conn, id2).unwrap().is_empty());
    }
}
