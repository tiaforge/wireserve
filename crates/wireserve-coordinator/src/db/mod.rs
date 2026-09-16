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
        // Must be set per-connection, not inside a migration (SQLite does
        // not enforce foreign keys by default, and rusqlite_migration's own
        // docs warn PRAGMA statements inside migrations aren't applied
        // consistently).
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        run_migrations(&mut conn)?;
        // Milestone 5 hardening pass: the DB holds hashed (not plaintext)
        // tokens by design (§3), but it's still node metadata — pubkeys,
        // IPs, hashed credentials — worth keeping off-limits to other
        // local users as a second layer, the same instinct as §7's
        // mode-600 requirement for the agent's own local state files
        // (which the spec states explicitly; this one is this project's
        // own added precaution, not spec-mandated, since §7's file-mode
        // bullet is scoped to "the node's own disk," i.e. the agent side).
        #[cfg(unix)]
        harden_file_permissions(path)?;
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
    Migrations::new(vec![M::up(include_str!(
        "../../migrations/0001_init.sql"
    ))])
}

fn run_migrations(conn: &mut Connection) -> Result<(), DbError> {
    migrations().to_latest(conn)?;
    Ok(())
}

#[cfg(unix)]
fn harden_file_permissions(path: &Path) -> Result<(), DbError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
