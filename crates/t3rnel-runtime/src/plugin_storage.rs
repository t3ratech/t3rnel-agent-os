//! Per-plugin storage host service (`17-implementation-guide.md` §9.6,
//! storage first in the mandated order).
//!
//! Each plugin gets its own SQLite database under
//! `<t3rnel_home>/plugins/<plugin_id>/data/plugin.db`. The host — never the
//! plugin — owns the connection, runs migrations, and takes a file snapshot
//! before every migration so a bad migration can be rolled back.
//!
//! Plugins reach storage only through the `storage` host service RPC; they
//! never receive a connection, a path outside their grant, or access to the
//! shared substrate `usage_conn`. This module is the host side of that
//! boundary.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("invalid plugin id {0:?}: must be reverse-domain, no path separators")]
    BadPluginId(String),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("plugin {0:?} storage is not initialized")]
    NotInitialized(String),
    #[error("migration {0} failed: {1}")]
    MigrationFailed(i64, String),
}

/// Validate a plugin id is safe as a single directory name component.
pub fn validate_plugin_id(id: &str) -> Result<(), StorageError> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_'
        });
    if ok && !id.contains("..") {
        Ok(())
    } else {
        Err(StorageError::BadPluginId(id.to_string()))
    }
}

/// Host-side per-plugin storage. Owns the SQLite connection for exactly one
/// plugin's data directory.
pub struct PluginStorage {
    plugin_id: String,
    /// `<home>/plugins/<id>/data/plugin.db`
    pub db_path: PathBuf,
    conn: Connection,
}

impl PluginStorage {
    /// Open (creating if needed) the plugin's database. `home` is the
    /// T3rnel home directory (scratch dir in tests — never live data).
    pub fn open(home: &Path, plugin_id: &str) -> Result<Self, StorageError> {
        validate_plugin_id(plugin_id)?;
        let dir = home.join("plugins").join(plugin_id).join("data");
        std::fs::create_dir_all(&dir)?;
        let db_path = dir.join("plugin.db");
        let conn = Connection::open(&db_path)?;
        // Per-connection pragmas: WAL for concurrent host access, foreign
        // keys on so plugin schemas can't orphan rows silently.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5000i64)?;
        Ok(PluginStorage {
            plugin_id: plugin_id.to_string(),
            db_path,
            conn,
        })
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// Ensure the migration bookkeeping table exists.
    fn ensure_migrations_table(&self) -> Result<(), StorageError> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS plugin_schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now')),
                description TEXT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }

    /// Applied migration versions, ascending.
    pub fn applied_versions(&self) -> Result<Vec<i64>, StorageError> {
        self.ensure_migrations_table()?;
        let mut stmt = self
            .conn
            .prepare("SELECT version FROM plugin_schema_migrations ORDER BY version")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Take a pre-migration snapshot: a consistent copy of the DB file under
    /// `<plugin_dir>/data/snapshots/pre-migration-<version>.db`. Uses SQLite's
    /// backup API via `VACUUM INTO` so the snapshot is transactionally clean.
    pub fn snapshot_before_migration(&self, version: i64) -> Result<PathBuf, StorageError> {
        let snap_dir = self.db_path.parent().unwrap().join("snapshots");
        std::fs::create_dir_all(&snap_dir)?;
        let snap = snap_dir.join(format!("pre-migration-{version}.db"));
        if snap.exists() {
            std::fs::remove_file(&snap)?;
        }
        self.conn
            .execute("VACUUM INTO ?1", [snap.to_string_lossy().to_string()])?;
        Ok(snap)
    }

    /// Run host-side migrations. `migrations` is `(version, description,
    /// sql)` ascending; each already-applied version is skipped. A snapshot
    /// is taken before the first pending migration of this call.
    /// Returns the versions applied by this call.
    pub fn migrate(&self, migrations: &[(i64, &str, &str)]) -> Result<Vec<i64>, StorageError> {
        self.ensure_migrations_table()?;
        let applied: std::collections::HashSet<i64> =
            self.applied_versions()?.into_iter().collect();
        let pending: Vec<_> = migrations
            .iter()
            .filter(|(v, _, _)| !applied.contains(v))
            .collect();
        if pending.is_empty() {
            return Ok(Vec::new());
        }
        // Snapshot once before applying this batch.
        let first = pending.first().unwrap().0;
        self.snapshot_before_migration(first)?;

        let tx = self.conn.unchecked_transaction()?;
        let mut ran = Vec::new();
        for (version, desc, sql) in pending {
            tx.execute_batch(sql)
                .map_err(|e| StorageError::MigrationFailed(*version, e.to_string()))?;
            tx.execute(
                "INSERT INTO plugin_schema_migrations (version, description) VALUES (?1, ?2)",
                rusqlite::params![version, desc],
            )?;
            ran.push(*version);
        }
        tx.commit()?;
        Ok(ran)
    }

    /// The **plugin-facing** key-value store (the `storage` host service). A
    /// plugin may read and write any key here and nothing the host relies on
    /// is kept here: crash counts, approvals, schedules, queued notifications
    /// and memory labels live in the host-only table behind
    /// [`state_get`](Self::state_get), which no plugin-facing call reaches.
    pub fn kv_get(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.ensure_kv_table()?;
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM plugin_kv WHERE key = ?1")?;
        let mut rows = stmt.query(rusqlite::params![key])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get::<_, String>(0)?)),
            None => Ok(None),
        }
    }

    pub fn kv_set(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.ensure_kv_table()?;
        self.conn.execute(
            "INSERT INTO plugin_kv (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    /// Host-only state. Same shape as the plugin KV but a separate table, and
    /// nothing exposed to a plugin reads or writes it — so a plugin cannot reset
    /// its own crash log, approve its own request, or relabel its own memory.
    pub fn state_get(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.ensure_state_table()?;
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM host_state WHERE key = ?1")?;
        let mut rows = stmt.query(rusqlite::params![key])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get::<_, String>(0)?)),
            None => Ok(None),
        }
    }

    pub fn state_set(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.ensure_state_table()?;
        self.conn.execute(
            "INSERT INTO host_state (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    /// Compare-and-set: write `new` only if the current value is exactly
    /// `expected`. Returns whether it wrote. This is how a single-use approval is
    /// consumed: two racing callers cannot both succeed.
    pub fn state_cas(&self, key: &str, expected: &str, new: &str) -> Result<bool, StorageError> {
        self.ensure_state_table()?;
        let changed = self.conn.execute(
            "UPDATE host_state SET value = ?3 WHERE key = ?1 AND value = ?2",
            rusqlite::params![key, expected, new],
        )?;
        Ok(changed == 1)
    }

    fn ensure_state_table(&self) -> Result<(), StorageError> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS host_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }

    fn ensure_kv_table(&self) -> Result<(), StorageError> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS plugin_kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }

    /// Append an audit record. The audit *service* (9.6 second in order)
    /// wraps this; storage keeps its own trail too so plugin state and its
    /// history can't diverge.
    pub fn audit_append(&self, action: &str, detail: &str) -> Result<(), StorageError> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS plugin_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL DEFAULT (datetime('now')),
                action TEXT NOT NULL,
                detail TEXT NOT NULL
            )",
            [],
        )?;
        self.conn.execute(
            "INSERT INTO plugin_audit (action, detail) VALUES (?1, ?2)",
            rusqlite::params![action, detail],
        )?;
        Ok(())
    }

    pub fn audit_tail(&self, limit: usize) -> Result<Vec<(String, String, String)>, StorageError> {
        let mut stmt = self
            .conn
            .prepare("SELECT ts, action, detail FROM plugin_audit ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_id_validation_rejects_traversal() {
        assert!(validate_plugin_id("org.example.plugin").is_ok());
        assert!(validate_plugin_id("a_b-c.d").is_ok());
        for bad in ["", "../x", "a/b", "a b", "A.B", "..", "x..y/z"] {
            assert!(validate_plugin_id(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn per_plugin_databases_are_isolated() {
        let home = tempfile::tempdir().unwrap();
        let a = PluginStorage::open(home.path(), "org.a.one").unwrap();
        let b = PluginStorage::open(home.path(), "org.b.two").unwrap();
        a.kv_set("k", "value-a").unwrap();
        b.kv_set("k", "value-b").unwrap();
        assert_eq!(a.kv_get("k").unwrap().as_deref(), Some("value-a"));
        assert_eq!(b.kv_get("k").unwrap().as_deref(), Some("value-b"));
        // Files live under distinct per-plugin dirs.
        assert!(a.db_path.to_string_lossy().contains("org.a.one"));
        assert!(b.db_path.to_string_lossy().contains("org.b.two"));
    }

    #[test]
    fn migrations_run_once_and_snapshot_is_taken() {
        let home = tempfile::tempdir().unwrap();
        let s = PluginStorage::open(home.path(), "org.example.mig").unwrap();
        let migrations: [(i64, &str, &str); 2] = [
            (1, "create kv", "CREATE TABLE t1 (id INTEGER PRIMARY KEY)"),
            (
                2,
                "add col",
                "ALTER TABLE plugin_schema_migrations ADD COLUMN note TEXT",
            ),
        ];
        let ran = s.migrate(&migrations).unwrap();
        assert_eq!(ran, vec![1, 2]);
        // Second call: nothing pending, no new snapshot.
        let ran2 = s.migrate(&migrations).unwrap();
        assert!(ran2.is_empty());
        assert_eq!(s.applied_versions().unwrap(), vec![1, 2]);
        // Snapshot exists for version 1.
        let snaps = s.db_path.parent().unwrap().join("snapshots");
        assert!(snaps.join("pre-migration-1.db").exists());
    }

    #[test]
    fn failed_migration_rolls_back_and_records_nothing() {
        let home = tempfile::tempdir().unwrap();
        let s = PluginStorage::open(home.path(), "org.example.fail").unwrap();
        let bad: [(i64, &str, &str); 1] = [(1, "bad", "THIS IS NOT SQL")];
        assert!(s.migrate(&bad).is_err());
        assert!(s.applied_versions().unwrap().is_empty());
    }

    #[test]
    fn audit_trail_is_append_only_and_ordered() {
        let home = tempfile::tempdir().unwrap();
        let s = PluginStorage::open(home.path(), "org.example.audit").unwrap();
        s.audit_append("install", "v1").unwrap();
        s.audit_append("call", "storage.kv_set").unwrap();
        let tail = s.audit_tail(10).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].1, "call"); // newest first
        assert_eq!(tail[1].1, "install");
    }

    #[test]
    fn host_state_is_a_separate_table_from_the_plugin_facing_kv() {
        let home = tempfile::tempdir().unwrap();
        let s = PluginStorage::open(home.path(), "org.test.state").unwrap();
        s.kv_set("crashlog", "plugin wrote this").unwrap();
        assert_eq!(s.state_get("crashlog").unwrap(), None, "a plugin write must not reach host state");
        s.state_set("crashlog", "[1,2,3]").unwrap();
        assert_eq!(s.kv_get("crashlog").unwrap().as_deref(), Some("plugin wrote this"), "a host write must not reach the plugin kv");
        assert_eq!(s.state_get("crashlog").unwrap().as_deref(), Some("[1,2,3]"));
    }

    #[test]
    fn compare_and_set_lets_exactly_one_writer_win() {
        let home = tempfile::tempdir().unwrap();
        let s = PluginStorage::open(home.path(), "org.test.cas").unwrap();
        s.state_set("k", "a").unwrap();
        assert!(s.state_cas("k", "a", "b").unwrap());
        assert!(!s.state_cas("k", "a", "c").unwrap(), "the second writer saw a stale value");
        assert_eq!(s.state_get("k").unwrap().as_deref(), Some("b"));
        assert!(!s.state_cas("missing", "a", "b").unwrap());
    }
}
