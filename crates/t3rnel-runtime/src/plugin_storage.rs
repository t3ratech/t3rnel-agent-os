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
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rusqlite::hooks::{AuthAction, Authorization};
use rusqlite::{params_from_iter, Connection};

/// Host-owned tables a plugin may never touch through `SqlExec`/`SqlExecBatch`.
/// `host_state` carries approvals, schedules, crash quarantine and memory
/// labels; `plugin_audit` and `plugin_schema_migrations` are the host's own
/// bookkeeping. `plugin_kv` is plugin-facing but has exactly one write path
/// (the KV RPCs) so values stay well-formed text.
const PROTECTED_TABLES: &[&str] = &[
    "host_state",
    "plugin_audit",
    "plugin_schema_migrations",
    "plugin_kv",
];

/// Namespaces the plugin-facing KV/Blob APIs accept: single path-safe
/// component, no separators, no `..`.
pub fn validate_namespace(ns: &str) -> Result<(), StorageError> {
    let ok = !ns.is_empty()
        && ns.len() <= 64
        && !ns.contains("..")
        && ns
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(StorageError::BadPluginId(format!("namespace {ns:?}")))
    }
}

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
    /// Host connection, mutex-guarded so `PluginStorage` is `Sync` and can
    /// be shared by the async gRPC dispatch (rusqlite::Connection is !Sync).
    conn: Mutex<Connection>,
    /// Second connection to the same database used ONLY for plugin-facing
    /// `SqlExec`/`SqlExecBatch`. It carries an authorizer that makes the
    /// host-owned tables unreachable even to arbitrary plugin SQL, and a
    /// progress handler that enforces the per-call timeout. Keeping it
    /// separate means host state access (`state_*`, migrations, audit) can
    /// never be broken by — or laundered through — plugin SQL.
    sql_conn: Mutex<Option<Connection>>,
    /// Deadline the progress handler interrupts at; `None` = no deadline.
    sql_deadline: Arc<Mutex<Option<Instant>>>,
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
            conn: Mutex::new(conn),
            sql_conn: Mutex::new(None),
            sql_deadline: Arc::new(Mutex::new(None)),
        })
    }

    /// Lazily open the plugin-SQL connection: same file, WAL so it coexists
    /// with the host connection, authorizer denying every action on the
    /// protected host tables plus ATTACH, and a progress handler enforcing
    /// the deadline stored in `sql_deadline`.
    fn sql_connection(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<Connection>>, StorageError> {
        let mut guard = self.sql_conn.lock().unwrap();
        if guard.is_none() {
            let conn = Connection::open(&self.db_path)?;
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "busy_timeout", 5000i64)?;
            conn.pragma_update(None, "foreign_keys", "ON")?;
            // Deny-by-default posture for host tables: ANY action (read,
            // write, schema change) naming a protected table is refused at
            // prepare time, before a byte executes. ATTACH would let plugin
            // SQL reach other databases on disk — refused outright.
            conn.authorizer(Some(|ctx: rusqlite::hooks::AuthContext| {
                let is_protected = |name: &str| {
                    PROTECTED_TABLES
                        .iter()
                        .any(|t| name.eq_ignore_ascii_case(t))
                };
                // Any action that names a protected table — read, write or
                // schema change — is refused at prepare time. A plugin view
                // or trigger over a protected table still trips Read/Insert
                // on the underlying table, so it cannot launder access.
                let table_hit = match ctx.action {
                    AuthAction::CreateIndex { table_name, .. }
                    | AuthAction::CreateTable { table_name }
                    | AuthAction::CreateTempIndex { table_name, .. }
                    | AuthAction::CreateTempTable { table_name }
                    | AuthAction::CreateTempTrigger { table_name, .. }
                    | AuthAction::CreateTrigger { table_name, .. }
                    | AuthAction::Delete { table_name }
                    | AuthAction::DropIndex { table_name, .. }
                    | AuthAction::DropTable { table_name }
                    | AuthAction::DropTempIndex { table_name, .. }
                    | AuthAction::DropTempTable { table_name }
                    | AuthAction::DropTempTrigger { table_name, .. }
                    | AuthAction::DropTrigger { table_name, .. }
                    | AuthAction::Insert { table_name }
                    | AuthAction::Read { table_name, .. }
                    | AuthAction::Update { table_name, .. }
                    | AuthAction::AlterTable { table_name, .. }
                    | AuthAction::Analyze { table_name }
                    | AuthAction::CreateVtable { table_name, .. }
                    | AuthAction::DropVtable { table_name, .. } => is_protected(table_name),
                    AuthAction::CreateTempView { view_name }
                    | AuthAction::CreateView { view_name }
                    | AuthAction::DropTempView { view_name }
                    | AuthAction::DropView { view_name } => is_protected(view_name),
                    _ => false,
                };
                if table_hit {
                    return Authorization::Deny;
                }
                match ctx.action {
                    // A second database file would escape the plugin's own
                    // data dir entirely.
                    AuthAction::Attach { .. } | AuthAction::Detach { .. } => Authorization::Deny,
                    // PRAGMA writable_schema / journal_mode etc. are host
                    // concerns; plugin SQL gets none of them.
                    AuthAction::Pragma { .. } => Authorization::Deny,
                    _ => Authorization::Allow,
                }
            }))?;
            // Progress handler: every N VM ops check the shared deadline and
            // interrupt the running statement when it has passed.
            let deadline = Arc::clone(&self.sql_deadline);
            conn.progress_handler(
                1000,
                Some(move || {
                    deadline
                        .lock()
                        .unwrap()
                        .map(|d| Instant::now() > d)
                        .unwrap_or(false)
                }),
            )?;
            *guard = Some(conn);
        }
        Ok(guard)
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// Ensure the migration bookkeeping table exists.
    fn ensure_migrations_table(&self) -> Result<(), StorageError> {
        self.conn.lock().unwrap().execute(
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
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT version FROM plugin_schema_migrations ORDER BY version")?;
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
            .lock()
            .unwrap()
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

        let conn_guard = self.conn.lock().unwrap();
        let tx = conn_guard.unchecked_transaction()?;
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM plugin_kv WHERE key = ?1")?;
        let mut rows = stmt.query(rusqlite::params![key])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get::<_, String>(0)?)),
            None => Ok(None),
        }
    }

    pub fn kv_set(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.ensure_kv_table()?;
        self.conn.lock().unwrap().execute(
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
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM host_state WHERE key = ?1")?;
        let mut rows = stmt.query(rusqlite::params![key])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get::<_, String>(0)?)),
            None => Ok(None),
        }
    }

    pub fn state_set(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.ensure_state_table()?;
        self.conn.lock().unwrap().execute(
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
        let changed = self.conn.lock().unwrap().execute(
            "UPDATE host_state SET value = ?3 WHERE key = ?1 AND value = ?2",
            rusqlite::params![key, expected, new],
        )?;
        Ok(changed == 1)
    }

    /// Scan `host_state` keys with a prefix, returning `(key, value)` pairs,
    /// capped at `limit`. Used by the memory query path — host_state has no
    /// other enumeration surface.
    pub fn state_prefix_scan(
        &self,
        prefix: &str,
        limit: usize,
    ) -> Result<Vec<(String, String)>, StorageError> {
        self.ensure_state_table()?;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT key, value FROM host_state WHERE substr(key, 1, length(?1)) = ?1
             ORDER BY key LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![prefix, limit as i64], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    fn ensure_state_table(&self) -> Result<(), StorageError> {
        self.conn.lock().unwrap().execute(
            "CREATE TABLE IF NOT EXISTS host_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }

    fn ensure_kv_table(&self) -> Result<(), StorageError> {
        self.conn.lock().unwrap().execute(
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
        self.conn.lock().unwrap().execute(
            "CREATE TABLE IF NOT EXISTS plugin_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL DEFAULT (datetime('now')),
                action TEXT NOT NULL,
                detail TEXT NOT NULL
            )",
            [],
        )?;
        self.conn.lock().unwrap().execute(
            "INSERT INTO plugin_audit (action, detail) VALUES (?1, ?2)",
            rusqlite::params![action, detail],
        )?;
        Ok(())
    }

    pub fn audit_tail(&self, limit: usize) -> Result<Vec<(String, String, String)>, StorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT ts, action, detail FROM plugin_audit ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Like [`audit_append`](Self::audit_append) but returns the new rowid —
    /// the `audit_id` the proto contract hands back to callers.
    pub fn audit_append_id(&self, action: &str, detail: &str) -> Result<i64, StorageError> {
        self.conn.lock().unwrap().execute(
            "CREATE TABLE IF NOT EXISTS plugin_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL DEFAULT (datetime('now')),
                action TEXT NOT NULL,
                detail TEXT NOT NULL
            )",
            [],
        )?;
        self.conn.lock().unwrap().execute(
            "INSERT INTO plugin_audit (action, detail) VALUES (?1, ?2)",
            rusqlite::params![action, detail],
        )?;
        Ok(self.conn.lock().unwrap().last_insert_rowid())
    }

    // ------------------------------------------------------------------
    // storage host service — namespaced KV (proto `namespace` + `key`)
    // ------------------------------------------------------------------

    /// Internal key encoding: `ns\u{1f}key`. The unit separator cannot appear
    /// in validated namespaces or keys, so the encoding is unambiguous and
    /// prefix scans stay correct.
    fn ns_key(namespace: &str, key: &str) -> String {
        format!("{namespace}\u{1f}{key}")
    }

    pub fn kv_get_ns(&self, namespace: &str, key: &str) -> Result<Option<String>, StorageError> {
        validate_namespace(namespace)?;
        self.kv_get(&Self::ns_key(namespace, key))
    }

    pub fn kv_set_ns(&self, namespace: &str, key: &str, value: &str) -> Result<(), StorageError> {
        validate_namespace(namespace)?;
        self.kv_set(&Self::ns_key(namespace, key), value)
    }

    pub fn kv_delete_ns(&self, namespace: &str, key: &str) -> Result<bool, StorageError> {
        validate_namespace(namespace)?;
        self.kv_delete(&Self::ns_key(namespace, key))
    }

    /// Delete a key from `plugin_kv`; returns whether a row existed.
    pub fn kv_delete(&self, key: &str) -> Result<bool, StorageError> {
        self.ensure_kv_table()?;
        let changed = self.conn.lock().unwrap().execute(
            "DELETE FROM plugin_kv WHERE key = ?1",
            rusqlite::params![key],
        )?;
        Ok(changed > 0)
    }

    /// List keys (and values are NOT returned — the proto returns keys only)
    /// under `namespace`/`prefix`, capped at `limit` (0 = default 1000).
    /// Returns `(keys, truncated)`.
    pub fn kv_list_ns(
        &self,
        namespace: &str,
        prefix: &str,
        limit: u32,
    ) -> Result<(Vec<String>, bool), StorageError> {
        validate_namespace(namespace)?;
        self.ensure_kv_table()?;
        let cap = if limit == 0 { 1000 } else { limit as usize };
        let ns_prefix = format!("{}\u{1f}", namespace);
        let full_prefix = format!("{ns_prefix}{prefix}");
        // Fetch cap+1 rows to detect truncation without a second query.
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT key FROM plugin_kv WHERE substr(key, 1, length(?1)) = ?1
             ORDER BY key LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![full_prefix, (cap + 1) as i64], |r| {
            r.get::<_, String>(0)
        })?;
        let mut keys: Vec<String> = rows.collect::<Result<_, _>>()?;
        let truncated = keys.len() > cap;
        keys.truncate(cap);
        // Strip the namespace encoding before returning.
        let stripped: Vec<String> = keys
            .into_iter()
            .filter_map(|k| k.strip_prefix(&ns_prefix).map(|s| s.to_string()))
            .collect();
        Ok((stripped, truncated))
    }

    /// Delete every key in `namespace`; returns rows removed.
    pub fn kv_delete_namespace(&self, namespace: &str) -> Result<u64, StorageError> {
        validate_namespace(namespace)?;
        self.ensure_kv_table()?;
        let ns_prefix = format!("{}\u{1f}", namespace);
        let changed = self.conn.lock().unwrap().execute(
            "DELETE FROM plugin_kv WHERE substr(key, 1, length(?1)) = ?1",
            rusqlite::params![ns_prefix],
        )?;
        Ok(changed as u64)
    }

    // ------------------------------------------------------------------
    // storage host service — SQL on the plugin connection
    // ------------------------------------------------------------------

    /// Execute one statement on the plugin SQL connection (authorizer +
    /// deadline enforced). `timeout_ms` of 0 means the default 5s.
    pub fn sql_exec(
        &self,
        statement: &str,
        params: &[SqlParam],
        timeout_ms: u32,
    ) -> Result<SqlOutcome, StorageError> {
        if statement.trim().is_empty() {
            return Err(StorageError::MigrationFailed(0, "empty statement".into()));
        }
        let timeout = if timeout_ms == 0 {
            5000
        } else {
            timeout_ms.min(30_000)
        };
        *self.sql_deadline.lock().unwrap() =
            Some(Instant::now() + std::time::Duration::from_millis(timeout as u64));
        let result = self.sql_exec_inner(statement, params);
        *self.sql_deadline.lock().unwrap() = None;
        result
    }

    fn sql_exec_inner(
        &self,
        statement: &str,
        params: &[SqlParam],
    ) -> Result<SqlOutcome, StorageError> {
        let mut conn_guard = self.sql_connection()?;
        let conn = conn_guard.as_mut().unwrap();
        let values: Vec<rusqlite::types::Value> = params.iter().map(SqlParam::to_value).collect();
        let mut stmt = conn.prepare(statement)?;
        let column_count = stmt.column_count();
        let mut columns = Vec::with_capacity(column_count);
        for i in 0..column_count {
            columns.push(stmt.column_name(i)?.to_string());
        }
        let mut out = SqlOutcome {
            columns,
            rows: Vec::new(),
            rows_affected: 0,
            last_insert_rowid: 0,
        };
        if column_count > 0 {
            let mut rows = stmt.query(params_from_iter(values))?;
            while let Some(row) = rows.next()? {
                let mut vals = Vec::with_capacity(column_count);
                for i in 0..column_count {
                    let v: rusqlite::types::Value = row.get(i)?;
                    vals.push(match v {
                        rusqlite::types::Value::Null => SqlParam::Null,
                        rusqlite::types::Value::Integer(i) => SqlParam::Integer(i),
                        rusqlite::types::Value::Real(f) => SqlParam::Real(f),
                        rusqlite::types::Value::Text(s) => SqlParam::Text(s),
                        rusqlite::types::Value::Blob(b) => SqlParam::Blob(b),
                    });
                }
                out.rows.push(vals);
            }
        } else {
            out.rows_affected = stmt.execute(params_from_iter(values))? as u64;
            out.last_insert_rowid = conn.last_insert_rowid();
        }
        Ok(out)
    }

    /// Execute statements in ONE transaction on the plugin SQL connection.
    /// Any failure rolls the whole batch back.
    pub fn sql_exec_batch(
        &self,
        statements: &[(&str, &[SqlParam])],
        timeout_ms: u32,
    ) -> Result<Vec<SqlOutcome>, StorageError> {
        let timeout = if timeout_ms == 0 {
            5000
        } else {
            timeout_ms.min(30_000)
        };
        *self.sql_deadline.lock().unwrap() =
            Some(Instant::now() + std::time::Duration::from_millis(timeout as u64));
        let result = (|| {
            let mut conn_guard = self.sql_connection()?;
            let conn = conn_guard.as_mut().unwrap();
            let tx = conn.transaction()?;
            let mut outs = Vec::with_capacity(statements.len());
            for (sql, params) in statements {
                let values: Vec<rusqlite::types::Value> =
                    params.iter().map(SqlParam::to_value).collect();
                let mut stmt = tx.prepare(sql)?;
                let column_count = stmt.column_count();
                let mut out = SqlOutcome::default();
                if column_count > 0 {
                    for i in 0..column_count {
                        out.columns.push(stmt.column_name(i)?.to_string());
                    }
                    let mut rows = stmt.query(params_from_iter(values))?;
                    while let Some(row) = rows.next()? {
                        let mut vals = Vec::with_capacity(column_count);
                        for i in 0..column_count {
                            vals.push(match row.get::<_, rusqlite::types::Value>(i)? {
                                rusqlite::types::Value::Null => SqlParam::Null,
                                rusqlite::types::Value::Integer(i) => SqlParam::Integer(i),
                                rusqlite::types::Value::Real(f) => SqlParam::Real(f),
                                rusqlite::types::Value::Text(s) => SqlParam::Text(s),
                                rusqlite::types::Value::Blob(b) => SqlParam::Blob(b),
                            });
                        }
                        out.rows.push(vals);
                    }
                } else {
                    out.rows_affected = stmt.execute(params_from_iter(values))? as u64;
                    out.last_insert_rowid = tx.last_insert_rowid();
                }
                outs.push(out);
            }
            tx.commit()?;
            Ok(outs)
        })();
        *self.sql_deadline.lock().unwrap() = None;
        result
    }

    // ------------------------------------------------------------------
    // storage host service — content-addressed blobs
    // ------------------------------------------------------------------

    fn blob_dir(&self, namespace: &str) -> Result<PathBuf, StorageError> {
        validate_namespace(namespace)?;
        let dir = self.db_path.parent().unwrap().join("blobs").join(namespace);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Store `data` under its SHA-256. Idempotent: an existing blob is not
    /// rewritten. Returns `(sha256_hex, size)`.
    pub fn blob_put(&self, namespace: &str, data: &[u8]) -> Result<(String, u64), StorageError> {
        use sha2::{Digest, Sha256};
        let sha = hex::encode(Sha256::digest(data));
        let path = self.blob_dir(namespace)?.join(&sha);
        if !path.exists() {
            // Write-then-rename so a concurrent reader never sees a partial
            // blob; content addressing makes the tmp name unique per sha.
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, data)?;
            std::fs::rename(&tmp, &path)?;
        }
        Ok((sha, data.len() as u64))
    }

    /// Fetch a blob by sha256. `Ok(None)` when absent.
    pub fn blob_get(&self, namespace: &str, sha256: &str) -> Result<Option<Vec<u8>>, StorageError> {
        if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(StorageError::BadPluginId(format!(
                "bad blob sha256 {sha256:?}"
            )));
        }
        let path = self.blob_dir(namespace)?.join(sha256);
        match std::fs::read(&path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// One bound value for plugin SQL (proto `SqlValue`).
#[derive(Debug, Clone)]
pub enum SqlParam {
    Text(String),
    Integer(i64),
    Real(f64),
    Boolean(bool),
    Blob(Vec<u8>),
    Null,
}

impl SqlParam {
    fn to_value(&self) -> rusqlite::types::Value {
        match self {
            SqlParam::Text(s) => rusqlite::types::Value::Text(s.clone()),
            SqlParam::Integer(i) => rusqlite::types::Value::Integer(*i),
            SqlParam::Real(f) => rusqlite::types::Value::Real(*f),
            SqlParam::Boolean(b) => rusqlite::types::Value::Integer(*b as i64),
            SqlParam::Blob(b) => rusqlite::types::Value::Blob(b.clone()),
            SqlParam::Null => rusqlite::types::Value::Null,
        }
    }
}

/// Result of one plugin SQL statement.
#[derive(Debug, Default)]
pub struct SqlOutcome {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<SqlParam>>,
    pub rows_affected: u64,
    pub last_insert_rowid: i64,
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
        assert_eq!(
            s.state_get("crashlog").unwrap(),
            None,
            "a plugin write must not reach host state"
        );
        s.state_set("crashlog", "[1,2,3]").unwrap();
        assert_eq!(
            s.kv_get("crashlog").unwrap().as_deref(),
            Some("plugin wrote this"),
            "a host write must not reach the plugin kv"
        );
        assert_eq!(s.state_get("crashlog").unwrap().as_deref(), Some("[1,2,3]"));
    }

    #[test]
    fn compare_and_set_lets_exactly_one_writer_win() {
        let home = tempfile::tempdir().unwrap();
        let s = PluginStorage::open(home.path(), "org.test.cas").unwrap();
        s.state_set("k", "a").unwrap();
        assert!(s.state_cas("k", "a", "b").unwrap());
        assert!(
            !s.state_cas("k", "a", "c").unwrap(),
            "the second writer saw a stale value"
        );
        assert_eq!(s.state_get("k").unwrap().as_deref(), Some("b"));
        assert!(!s.state_cas("missing", "a", "b").unwrap());
    }
}
