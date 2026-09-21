pub mod nodes;
pub mod services;

use std::path::Path;

use rusqlite::Connection;
use rusqlite_migration::{Migrations, M};
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Migration(#[from] rusqlite_migration::Error),
    #[error("join token unknown or already used")]
    JoinTokenInvalid,
    #[error("node not found")]
    NodeNotFound,
    #[error("name already in use")]
    NameTaken,
    #[error("pubkey already registered to another node")]
    PubkeyTaken,
    #[error("service name '{0}' is already in use")]
    ServiceNameCollision(String),
    #[error(transparent)]
    Ipam(#[from] crate::ipam::IpamError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct Db {
    // Not pub(crate): integration tests in `tests/` compile against this
    // crate as an external dependent and need direct access to poke DB
    // state for tests like the online-threshold staleness check. This
    // crate is an application binary, not a published library, so the
    // usual argument for hiding this behind an accessor doesn't apply.
    pub conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DbError> {
        let path = path.as_ref();
        let mut conn = Connection::open(path)?;
        // Hardened here, BEFORE anything writes, rather than at the end.
        // SQLite creates the `-wal` and `-shm` sidecars with whatever
        // permissions the main database file has at the moment it makes
        // them, and those sidecars hold the same rows the database does.
        // Tightening the main file afterwards would leave them at the
        // umask default.
        #[cfg(unix)]
        harden_file_permissions(path)?;
        // Must be set per-connection, not inside a migration (SQLite does
        // not enforce foreign keys by default, and rusqlite_migration's own
        // docs warn PRAGMA statements inside migrations aren't applied
        // consistently).
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        set_write_mode(&conn)?;
        run_migrations(&mut conn)?;
        // The sidecars are created during the migration above, so they
        // are swept once more here for the case where the main file
        // already existed at looser permissions before this process
        // opened it.
        #[cfg(unix)]
        harden_sidecars(path)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    #[cfg(test)]
    pub fn open_in_memory_for_test() -> Self {
        // Not used for the shared-connection integration tests (those use a
        // temp file, since :memory: is per-connection and this Db is meant
        // to be used behind a single shared Mutex anyway) — kept for
        // possible unit-level DB tests that want a throwaway instance.
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        run_migrations(&mut conn).unwrap();
        Self {
            conn: Mutex::new(conn),
        }
    }
}

fn migrations() -> Migrations<'static> {
    // Order is the schema version: `rusqlite_migration` derives it from
    // the index in this vector, so entries are only ever appended and an
    // existing file is never edited once shipped.
    Migrations::new(vec![
        M::up(include_str!("../../migrations/0001_init.sql")),
        M::up(include_str!("../../migrations/0002_join_token_expiry.sql")),
        M::up(include_str!("../../migrations/0003_service_approval.sql")),
        M::up(include_str!("../../migrations/0004_endpoint_cleared.sql")),
        M::up(include_str!("../../migrations/0005_dual_stack_endpoints.sql")),
        M::up(include_str!("../../migrations/0006_service_vips.sql")),
        M::up(include_str!("../../migrations/0007_lan_addr.sql")),
    ])
}

fn run_migrations(conn: &mut Connection) -> Result<(), DbError> {
    migrations().to_latest(conn)?;
    Ok(())
}

/// Write-ahead logging, plus the `synchronous` setting that normally
/// accompanies it.
///
/// Every `/poll` writes (`last_seen` at minimum), and in SQLite's default
/// rollback journal at `synchronous=FULL` each of those transactions
/// costs several fsyncs. That work happens while holding the single
/// connection's mutex, so it is also exactly the window during which no
/// other request can be served. WAL turns it into an append and lets a
/// reader proceed against the last committed snapshot while a write is in
/// flight.
///
/// `synchronous=NORMAL` is the standard pairing and the reason it is safe
/// here: in WAL mode it still guarantees consistency across an
/// application crash, and gives up only durability of the most recent
/// transactions in a power loss or kernel panic. The most recent
/// transaction on this database is a node's `last_seen` timestamp, which
/// the next poll rewrites within seconds anyway.
///
/// Neither pragma is load-bearing for correctness, and neither is a fix
/// for a bottleneck anyone reaches legitimately — a poll-shaped
/// transaction measured about 0.05ms before this change. It shortens the
/// critical section on hardware where fsync is honest, which is where the
/// default would actually hurt.
fn set_write_mode(conn: &Connection) -> Result<(), DbError> {
    // `PRAGMA journal_mode` returns a row, so it cannot go through
    // `execute_batch`. An in-memory database cannot use WAL and answers
    // "memory" instead; that is expected and not an error.
    let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    conn.execute_batch("PRAGMA synchronous = NORMAL;")?;
    Ok(())
}

#[cfg(unix)]
fn harden_file_permissions(path: &Path) -> Result<(), DbError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// The `-wal` and `-shm` files hold the same data the database does and
/// must not be left readable by other local users.
#[cfg(unix)]
fn harden_sidecars(path: &Path) -> Result<(), DbError> {
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = std::path::PathBuf::from(sidecar);
        if sidecar.exists() {
            harden_file_permissions(&sidecar)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::NodeKind;

    #[cfg(unix)]
    #[test]
    fn open_hardens_db_file_to_mode_600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wireserve.db");
        // Start deliberately permissive, so the assertion proves `open`
        // actively tightens permissions rather than merely inheriting a
        // strict umask by accident.
        std::fs::write(&path, []).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let _db = Db::open(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "coordinator DB file must be hardened to mode 600 on open");
    }

    #[cfg(unix)]
    #[test]
    fn wal_sidecar_files_are_also_mode_600() {
        // The -wal file holds the same rows the database does, so it is
        // exactly as sensitive. It inherits the main file's permissions
        // at the moment SQLite creates it, which is why the main file is
        // hardened before WAL is switched on rather than after.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wireserve.db");
        std::fs::write(&path, []).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let db = Db::open(&path).unwrap();
        // Force a write so the sidecars definitely exist.
        {
            let conn = db.conn.blocking_lock();
            crate::db::nodes::create_node(&conn, "n1", NodeKind::Agent, "h1", None).unwrap();
        }

        let wal = dir.path().join("wireserve.db-wal");
        assert!(wal.exists(), "WAL mode should have produced a -wal file");
        for f in ["wireserve.db", "wireserve.db-wal", "wireserve.db-shm"] {
            let p = dir.path().join(f);
            if !p.exists() {
                continue;
            }
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{f} must not be readable by other local users");
        }
    }

    #[test]
    fn migrating_an_existing_database_leaves_outstanding_join_tokens_redeemable() {
        // Upgrading must not invalidate a token an operator sent out five
        // minutes ago and is still waiting on. ADD COLUMN gives every
        // existing row NULL, which reads as "never expires".
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();

        // A database at the pre-expiry schema version, with a node that
        // holds a live join token.
        migrations().to_version(&mut conn, 1).unwrap();
        conn.execute(
            "INSERT INTO nodes (name, kind, join_token_hash, join_token_used) \
             VALUES ('n1', 'agent', 'joinhash1', 0)",
            [],
        )
        .unwrap();

        migrations().to_latest(&mut conn).unwrap();

        let expiry: Option<String> = conn
            .query_row(
                "SELECT join_token_expires_at FROM nodes WHERE name = 'n1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(expiry.is_none(), "an existing row must not acquire an expiry");
        assert!(
            crate::db::nodes::find_by_unused_join_token_hash(&conn, "joinhash1")
                .unwrap()
                .is_some(),
            "a token outstanding across the upgrade must still redeem"
        );
    }

    #[test]
    fn migration_grandfathers_existing_services_as_approved() {
        // The most dangerous line in the approval change. Service
        // approval defaults ON, so without the backfill in migration
        // 0003 every service in every existing mesh would drop out of the
        // directory -- and out of every node's managed /etc/hosts block
        // -- on the first poll after the upgrade.
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();

        // A database at the pre-approval schema version, carrying a
        // registered node with a declared service, written the old way
        // (including declared_at's SQLite-format column DEFAULT).
        migrations().to_version(&mut conn, 2).unwrap();
        conn.execute(
            "INSERT INTO nodes (name, kind, pubkey, ip4, ip6, join_token_used) \
             VALUES ('n1', 'agent', 'pk1', '100.90.0.1', 'fd00:90::1', 1)",
            [],
        )
        .unwrap();
        let node_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO services (node_id, name, port, proto) VALUES (?1, 'plex', 32400, 'tcp')",
            [node_id],
        )
        .unwrap();

        migrations().to_latest(&mut conn).unwrap();

        let approved = crate::db::services::list_approved(&conn).unwrap();
        assert_eq!(
            approved.len(),
            1,
            "a service declared before the upgrade must keep propagating"
        );
        assert_eq!(approved[0].name, "plex");
        assert!(approved[0].approved_at.is_some());
        assert!(approved[0].denied_at.is_none());
    }

    #[test]
    fn migration_normalises_a_legacy_sqlite_timestamp() {
        // SQLite's CURRENT_TIMESTAMP default writes "YYYY-MM-DD HH:MM:SS",
        // which parse_from_rfc3339 rejects by returning None -- silently.
        // Dormant until ServiceRow started reading declared_at.
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        migrations().to_version(&mut conn, 2).unwrap();
        conn.execute(
            "INSERT INTO nodes (name, kind, pubkey, ip4, ip6, join_token_used) \
             VALUES ('n1', 'agent', 'pk1', '100.90.0.1', 'fd00:90::1', 1)",
            [],
        )
        .unwrap();
        let node_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO services (node_id, name, port, proto, declared_at) \
             VALUES (?1, 'plex', 32400, 'tcp', '2026-01-01 00:00:00')",
            [node_id],
        )
        .unwrap();

        migrations().to_latest(&mut conn).unwrap();

        let rows = crate::db::services::list_all_for_admin(&conn).unwrap();
        assert!(
            rows[0].declared_at.is_some(),
            "a legacy timestamp must survive as a parsed value, not silently become None"
        );
    }

    #[test]
    fn migration_grandfathers_existing_nodes_as_not_endpoint_cleared() {
        // ADD COLUMN ... DEFAULT 0 already gives every existing row
        // `false` for free, but pinned anyway: if that default were ever
        // dropped or changed, every already-registered node would
        // silently stop self-healing its endpoint on poll (see
        // client_ip::endpoint_fallback), with no error anywhere.
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        migrations().to_version(&mut conn, 3).unwrap();
        conn.execute(
            "INSERT INTO nodes (name, kind, pubkey, ip4, ip6, join_token_used) \
             VALUES ('n1', 'agent', 'pk1', '100.90.0.1', 'fd00:90::1', 1)",
            [],
        )
        .unwrap();

        migrations().to_latest(&mut conn).unwrap();

        let row = crate::db::nodes::find_by_name(&conn, "n1").unwrap().unwrap();
        assert!(!row.endpoint_cleared);
    }

    #[test]
    fn migration_grandfathers_existing_nodes_with_no_v4_v6_endpoint() {
        // An existing node acquires no v4/v6 candidate for free on
        // upgrade -- None, not an empty string that downstream code might
        // mistake for a real (if empty) address.
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        migrations().to_version(&mut conn, 4).unwrap();
        conn.execute(
            "INSERT INTO nodes (name, kind, pubkey, ip4, ip6, join_token_used) \
             VALUES ('n1', 'agent', 'pk1', '100.90.0.1', 'fd00:90::1', 1)",
            [],
        )
        .unwrap();

        migrations().to_latest(&mut conn).unwrap();

        let row = crate::db::nodes::find_by_name(&conn, "n1").unwrap().unwrap();
        assert!(row.endpoint_addr_v4.is_none());
        assert!(row.endpoint_addr_v6.is_none());
    }

    #[test]
    fn migration_leaves_existing_services_without_an_address() {
        // An existing service keeps resolving to its node until its (then
        // upgraded) agent declares mappings: no address, no mappings.
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        migrations().to_version(&mut conn, 5).unwrap();
        conn.execute(
            "INSERT INTO nodes (name, kind, pubkey, ip4, ip6, join_token_used) \
             VALUES ('n1', 'agent', 'pk1', '100.90.0.1', 'fd00:90::1', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO services (node_id, name, port, proto, declared_at, approved_at) \
             VALUES (1, 'plex', 32400, 'tcp', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();

        migrations().to_latest(&mut conn).unwrap();

        let rows = crate::db::services::list_approved(&conn).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].vip4.is_none());
        assert!(rows[0].ports.is_empty());
        // And the unique index is there: one address, one service.
        conn.execute("UPDATE services SET vip4 = '100.90.0.9'", []).unwrap();
        conn.execute(
            "INSERT INTO services (node_id, name, port, proto, vip4) VALUES (1, 'x', 1, 'tcp', '100.90.0.9')",
            [],
        )
        .unwrap_err();
    }

    #[test]
    fn open_actually_enables_wal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wireserve.db");
        let db = Db::open(&path).unwrap();
        let conn = db.conn.blocking_lock();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
    }
}
