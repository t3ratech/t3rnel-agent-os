//! Merkle hash chain audit trail for security-critical actions.
//!
//! Every auditable event is appended to an append-only log where each entry
//! contains the SHA-256 hash of its own contents concatenated with the hash of
//! the previous entry, forming a tamper-evident chain (similar to a blockchain).
//!
//! When a database connection is provided (`with_db`), entries are persisted to
//! the `audit_entries` table (schema V8) so the trail survives daemon restarts.

use chrono::Utc;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

/// Categories of auditable actions within the agent runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    ToolInvoke,
    CapabilityCheck,
    AgentSpawn,
    AgentKill,
    AgentMessage,
    MemoryAccess,
    FileAccess,
    NetworkAccess,
    ShellExec,
    AuthAttempt,
    WireConnect,
    ConfigChange,
    /// A request refused by the ingress/egress sentinel. Detail carries the
    /// route and finding kinds; the refused payload is never recorded.
    SecurityDenial,
    /// Plugin package lifecycle event (install/update/rollback). Detail
    /// carries the dotted event kind, e.g. `plugin.dev_mode.install`.
    PluginLifecycle,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A single entry in the Merkle hash chain audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonically increasing sequence number (0-indexed).
    pub seq: u64,
    /// ISO-8601 timestamp of when this entry was recorded.
    pub timestamp: String,
    /// The agent that triggered (or is the subject of) this action.
    pub agent_id: String,
    /// The category of action being audited.
    pub action: AuditAction,
    /// Free-form detail about the action (e.g. tool name, file path).
    pub detail: String,
    /// The outcome of the action (e.g. "ok", "denied", an error message).
    pub outcome: String,
    /// SHA-256 hash of the previous entry (or all-zeros for the genesis).
    pub prev_hash: String,
    /// SHA-256 hash of this entry's content concatenated with `prev_hash`.
    pub hash: String,
}

/// Computes the SHA-256 hash for a single audit entry from its fields.
fn compute_entry_hash(
    seq: u64,
    timestamp: &str,
    agent_id: &str,
    action: &AuditAction,
    detail: &str,
    outcome: &str,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seq.to_string().as_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(agent_id.as_bytes());
    hasher.update(action.to_string().as_bytes());
    hasher.update(detail.as_bytes());
    hasher.update(outcome.as_bytes());
    hasher.update(prev_hash.as_bytes());
    hex::encode(hasher.finalize())
}

/// An append-only, tamper-evident audit log using a Merkle hash chain.
///
/// Thread-safe — all access is serialised through internal mutexes.
/// Optionally backed by SQLite for persistence across daemon restarts.
pub struct AuditLog {
    entries: Mutex<Vec<AuditEntry>>,
    tip: Mutex<String>,
    /// Optional database connection for persistent storage.
    db: Option<Arc<Mutex<Connection>>>,
}

impl AuditLog {
    /// Creates a new empty audit log (in-memory only, no persistence).
    ///
    /// The initial tip hash is 64 zero characters (the "genesis" sentinel).
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            tip: Mutex::new("0".repeat(64)),
            db: None,
        }
    }

    /// Creates an audit log backed by a database connection.
    ///
    /// On construction, loads all existing entries from the `audit_entries`
    /// table and verifies the Merkle chain integrity. New entries are written
    /// to both the in-memory chain and the database.
    pub fn with_db(conn: Arc<Mutex<Connection>>) -> Self {
        let mut entries = Vec::new();
        let mut tip = "0".repeat(64);

        // Load existing entries from database
        if let Ok(db) = conn.lock() {
            let result = db.prepare(
                "SELECT seq, timestamp, agent_id, action, detail, outcome, prev_hash, hash FROM audit_entries ORDER BY seq ASC",
            );
            if let Ok(mut stmt) = result {
                let rows = stmt.query_map([], |row| {
                    let action_str: String = row.get(3)?;
                    let seq: i64 = row.get(0)?;
                    let seq = u64::try_from(seq).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?;
                    let action = match action_str.as_str() {
                        "ToolInvoke" => AuditAction::ToolInvoke,
                        "CapabilityCheck" => AuditAction::CapabilityCheck,
                        "AgentSpawn" => AuditAction::AgentSpawn,
                        "AgentKill" => AuditAction::AgentKill,
                        "AgentMessage" => AuditAction::AgentMessage,
                        "MemoryAccess" => AuditAction::MemoryAccess,
                        "FileAccess" => AuditAction::FileAccess,
                        "NetworkAccess" => AuditAction::NetworkAccess,
                        "ShellExec" => AuditAction::ShellExec,
                        "AuthAttempt" => AuditAction::AuthAttempt,
                        "WireConnect" => AuditAction::WireConnect,
                        "ConfigChange" => AuditAction::ConfigChange,
                        "PluginLifecycle" => AuditAction::PluginLifecycle,
                        "SecurityDenial" => AuditAction::SecurityDenial,
                        _ => AuditAction::ToolInvoke, // fallback
                    };
                    Ok(AuditEntry {
                        seq,
                        timestamp: row.get(1)?,
                        agent_id: row.get(2)?,
                        action,
                        detail: row.get(4)?,
                        outcome: row.get(5)?,
                        prev_hash: row.get(6)?,
                        hash: row.get(7)?,
                    })
                });
                if let Ok(rows) = rows {
                    for entry in rows.flatten() {
                        tip = entry.hash.clone();
                        entries.push(entry);
                    }
                }
            }
        }

        let count = entries.len();
        let log = Self {
            entries: Mutex::new(entries),
            tip: Mutex::new(tip),
            db: Some(conn),
        };

        // Verify chain integrity on load
        if count > 0 {
            if let Err(e) = log.verify_integrity() {
                tracing::error!(
                    breaks = log.chain_breaks().len(),
                    "Audit trail integrity check FAILED on boot: {e}"
                );
            } else {
                tracing::info!("Audit trail loaded: {count} entries, chain integrity OK");
            }
        }

        log
    }

    /// Records a new auditable event and returns the SHA-256 hash of the entry.
    ///
    /// The entry is atomically appended to the chain with the current tip as
    /// its `prev_hash`, and the tip is advanced to the new hash.
    /// If a database connection is available, the entry is also persisted.
    pub fn record(
        &self,
        agent_id: impl Into<String>,
        action: AuditAction,
        detail: impl Into<String>,
        outcome: impl Into<String>,
    ) -> String {
        let agent_id = agent_id.into();
        let detail = detail.into();
        let outcome = outcome.into();
        let timestamp = Utc::now().to_rfc3339();

        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut tip = self.tip.lock().unwrap_or_else(|e| e.into_inner());

        // Last sequence number + 1, NOT the number of entries: after a gap (a row that failed to persist) the count is smaller than the
        // highest seq, every new row then collided with an existing primary key, the insert failed silently, and each restart lost more.
        let seq = entries.last().map(|e| e.seq + 1).unwrap_or(0);
        let prev_hash = tip.clone();

        let hash = compute_entry_hash(
            seq, &timestamp, &agent_id, &action, &detail, &outcome, &prev_hash,
        );

        let entry = AuditEntry {
            seq,
            timestamp,
            agent_id,
            action,
            detail,
            outcome,
            prev_hash,
            hash: hash.clone(),
        };

        // Persist to database if available
        if let Some(ref db) = self.db {
            if let Ok(conn) = db.lock() {
                // A failed insert leaves the persisted chain with a hole that no later row can bridge, so it must be loud.
                if let Err(e) = conn.execute(
                    "INSERT INTO audit_entries (seq, timestamp, agent_id, action, detail, outcome, prev_hash, hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        entry.seq as i64,
                        &entry.timestamp,
                        &entry.agent_id,
                        entry.action.to_string(),
                        &entry.detail,
                        &entry.outcome,
                        &entry.prev_hash,
                        &entry.hash,
                    ],
                ) {
                    tracing::error!(seq = entry.seq, "audit entry was NOT persisted (the stored chain now has a gap): {e}");
                }
            }
        }

        entries.push(entry);
        *tip = hash.clone();
        hash
    }

    /// Every seq whose `prev_hash` does not match the entry before it (the whole chain, not just the first break).
    pub fn chain_breaks(&self) -> Vec<u64> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut expected_prev = "0".repeat(64);
        let mut breaks = Vec::new();
        for entry in entries.iter() {
            if entry.prev_hash != expected_prev {
                breaks.push(entry.seq);
            }
            expected_prev = entry.hash.clone();
        }
        breaks
    }

    /// Walks the entire chain and recomputes every hash to detect tampering.
    ///
    /// Returns `Ok(())` if the chain is intact, or `Err(msg)` describing
    /// the first inconsistency found.
    pub fn verify_integrity(&self) -> Result<(), String> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut expected_prev = "0".repeat(64);

        for entry in entries.iter() {
            if entry.prev_hash != expected_prev {
                return Err(format!(
                    "chain break at seq {}: expected prev_hash {} but found {}",
                    entry.seq, expected_prev, entry.prev_hash
                ));
            }

            let recomputed = compute_entry_hash(
                entry.seq,
                &entry.timestamp,
                &entry.agent_id,
                &entry.action,
                &entry.detail,
                &entry.outcome,
                &entry.prev_hash,
            );

            if recomputed != entry.hash {
                return Err(format!(
                    "hash mismatch at seq {}: expected {} but found {}",
                    entry.seq, recomputed, entry.hash
                ));
            }

            expected_prev = entry.hash.clone();
        }

        Ok(())
    }

    /// Returns the current tip hash (the hash of the most recent entry,
    /// or the genesis sentinel if the log is empty).
    pub fn tip_hash(&self) -> String {
        self.tip.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Returns the number of entries in the log.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Returns whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }

    /// Returns up to the most recent `n` entries (cloned).
    pub fn recent(&self, n: usize) -> Vec<AuditEntry> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let start = entries.len().saturating_sub(n);
        entries[start..].to_vec()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

// ------------------------------------------------------------------
// Security config audit (Ruflo pattern: auditSecurityConfig)
// ------------------------------------------------------------------

/// A single security finding from the config audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityFinding {
    /// Severity level of the finding.
    pub severity: FindingSeverity,
    /// Short category name (e.g. "hardcoded-secret", "weak-permission").
    pub category: String,
    /// Human-readable description of the issue.
    pub message: String,
    /// File path or config key where the issue was found.
    pub location: String,
}

/// Severity levels for security findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    /// Informational — no action required.
    Info,
    /// Warning — should be reviewed.
    Warning,
    /// Error — must be fixed before production.
    Error,
    /// Critical — blocks boot.
    Critical,
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSeverity::Info => write!(f, "INFO"),
            FindingSeverity::Warning => write!(f, "WARNING"),
            FindingSeverity::Error => write!(f, "ERROR"),
            FindingSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Audit the security posture of T3rnel configuration.
///
/// Scans the runtime environment for:
/// - Hardcoded secrets in config files (API keys, tokens, passwords)
/// - Missing required API keys when drivers are enabled
/// - World-readable config files on Unix
/// - Insecure default settings
/// - Disabled security features
///
/// Returns a list of findings. An empty list means the config passes audit.
/// Critical findings should block daemon boot.
pub fn audit_security_config() -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    // 1. Check for hardcoded secrets in common config locations
    let home_dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(std::path::PathBuf::from);
    let config_paths = [
        home_dir.map(|h| h.join(".t3rnel/config.toml")),
        Some(std::path::PathBuf::from("./config.toml")),
        Some(std::path::PathBuf::from("/etc/t3rnel/config.toml")),
    ];

    for path in config_paths.iter().flatten() {
        if let Ok(contents) = std::fs::read_to_string(path) {
            // Scan for common secret patterns
            let secret_patterns = [
                (r#"api_key\s*=\s*['"][^$][^'"]+['"]"#, "hardcoded API key"),
                (r#"password\s*=\s*['"][^$][^'"]+['"]"#, "hardcoded password"),
                (r#"token\s*=\s*['"][^$][^'"]+['"]"#, "hardcoded token"),
                (r#"secret\s*=\s*['"][^$][^'"]+['"]"#, "hardcoded secret"),
                (r"sk-[a-zA-Z0-9]{20,}", "hardcoded OpenAI-style key"),
                (r"nvapi-[a-zA-Z0-9]{20,}", "hardcoded NVIDIA API key"),
            ];

            for (pattern, desc) in &secret_patterns {
                if let Ok(re) = regex_lite::Regex::new(pattern) {
                    for mat in re.find_iter(&contents) {
                        findings.push(SecurityFinding {
                            severity: FindingSeverity::Critical,
                            category: "hardcoded-secret".to_string(),
                            message: format!("Found {} in config file", desc),
                            location: format!("{}:{}", path.display(), mat.start()),
                        });
                    }
                }
            }

            // 2. Check file permissions on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(path) {
                    let mode = metadata.permissions().mode();
                    let world_readable = mode & 0o044;
                    let world_writable = mode & 0o022;
                    if world_writable != 0 {
                        findings.push(SecurityFinding {
                            severity: FindingSeverity::Error,
                            category: "weak-permission".to_string(),
                            message: format!(
                                "Config file is world-writable (mode {:o})",
                                mode & 0o777
                            ),
                            location: path.display().to_string(),
                        });
                    } else if world_readable != 0 {
                        findings.push(SecurityFinding {
                            severity: FindingSeverity::Warning,
                            category: "weak-permission".to_string(),
                            message: format!(
                                "Config file is world-readable (mode {:o}); consider restricting to owner only",
                                mode & 0o777
                            ),
                            location: path.display().to_string(),
                        });
                    }
                }
            }
        }
    }

    // 3. Check that required API keys are present in environment (not missing)
    let required_keys = [
        ("NVIDIA_API_KEY", "nvidia provider"),
        ("OPENROUTER_API_KEY", "openrouter fallback"),
        ("GROQ_API_KEY", "groq fallback"),
    ];

    for (key, usage) in &required_keys {
        if std::env::var(key).unwrap_or_default().is_empty() {
            findings.push(SecurityFinding {
                severity: FindingSeverity::Info,
                category: "missing-env-key".to_string(),
                message: format!("{} not set; {} will be unavailable", key, usage),
                location: "environment".to_string(),
            });
        }
    }

    // 4. Check for insecure default settings
    if std::env::var("T3RNEL_DISABLE_SANDBOX").unwrap_or_default() == "1" {
        findings.push(SecurityFinding {
            severity: FindingSeverity::Critical,
            category: "insecure-default".to_string(),
            message: "Sandbox is disabled via T3RNEL_DISABLE_SANDBOX=1".to_string(),
            location: "environment".to_string(),
        });
    }

    if std::env::var("T3RNEL_DEBUG_LOG_SECRETS").unwrap_or_default() == "1" {
        findings.push(SecurityFinding {
            severity: FindingSeverity::Critical,
            category: "insecure-default".to_string(),
            message: "Secret logging enabled via T3RNEL_DEBUG_LOG_SECRETS=1".to_string(),
            location: "environment".to_string(),
        });
    }

    // 5. Check for overly permissive CORS
    if let Ok(cors) = std::env::var("T3RNEL_CORS_ALLOW_ALL") {
        if cors == "1" || cors == "true" {
            findings.push(SecurityFinding {
                severity: FindingSeverity::Error,
                category: "insecure-default".to_string(),
                message: "CORS allow-all is enabled; restrict to known origins in production"
                    .to_string(),
                location: "environment".to_string(),
            });
        }
    }

    findings
}

/// Run the security config audit and log findings at appropriate levels.
///
/// Returns `true` if no critical findings were found, `false` otherwise.
/// Critical findings should be treated as boot-blocking errors.
pub fn run_security_audit() -> bool {
    let findings = audit_security_config();

    if findings.is_empty() {
        tracing::info!("Security config audit passed: no findings");
        return true;
    }

    let mut critical_count = 0;
    let mut error_count = 0;
    let mut warning_count = 0;

    for finding in &findings {
        match finding.severity {
            FindingSeverity::Critical => {
                critical_count += 1;
                tracing::error!(
                    category = %finding.category,
                    location = %finding.location,
                    "CRITICAL: {}",
                    finding.message
                );
            }
            FindingSeverity::Error => {
                error_count += 1;
                tracing::error!(
                    category = %finding.category,
                    location = %finding.location,
                    "{}",
                    finding.message
                );
            }
            FindingSeverity::Warning => {
                warning_count += 1;
                tracing::warn!(
                    category = %finding.category,
                    location = %finding.location,
                    "{}",
                    finding.message
                );
            }
            FindingSeverity::Info => {
                tracing::info!(
                    category = %finding.category,
                    location = %finding.location,
                    "{}",
                    finding.message
                );
            }
        }
    }

    tracing::info!(
        total = findings.len(),
        critical = critical_count,
        errors = error_count,
        warnings = warning_count,
        "Security config audit complete"
    );

    critical_count == 0
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_gap_in_the_stored_sequence_does_not_make_new_rows_collide() {
        // Rows 0, 1 and 3 exist (2 failed to persist): the next row must be 4, not 3 (the count), or its insert would hit the primary key.
        let log = AuditLog::new();
        {
            let mut entries = log.entries.lock().unwrap();
            for seq in [0u64, 1, 3] {
                entries.push(AuditEntry {
                    seq,
                    timestamp: "t".into(),
                    agent_id: "a".into(),
                    action: AuditAction::ToolInvoke,
                    detail: "d".into(),
                    outcome: "ok".into(),
                    prev_hash: "p".into(),
                    hash: format!("h{seq}"),
                });
            }
            *log.tip.lock().unwrap() = "h3".into();
        }
        log.record("a", AuditAction::ToolInvoke, "next", "ok");
        let last = log.entries.lock().unwrap().last().unwrap().seq;
        assert_eq!(last, 4);
    }

    #[test]
    fn chain_breaks_lists_every_break_not_only_the_first() {
        let log = AuditLog::new();
        log.record("a", AuditAction::ToolInvoke, "one", "ok");
        log.record("a", AuditAction::ToolInvoke, "two", "ok");
        log.record("a", AuditAction::ToolInvoke, "three", "ok");
        assert!(log.chain_breaks().is_empty());
        {
            let mut entries = log.entries.lock().unwrap();
            entries[1].prev_hash = "forged".into();
            entries[2].prev_hash = "forged-too".into();
        }
        assert_eq!(log.chain_breaks(), vec![1, 2]);
    }

    use super::*;

    #[test]
    fn test_audit_chain_integrity() {
        let log = AuditLog::new();
        log.record(
            "agent-1",
            AuditAction::ToolInvoke,
            "read_file /etc/passwd",
            "ok",
        );
        log.record("agent-1", AuditAction::ShellExec, "ls -la", "ok");
        log.record("agent-2", AuditAction::AgentSpawn, "spawning helper", "ok");
        log.record(
            "agent-1",
            AuditAction::NetworkAccess,
            "https://example.com",
            "denied",
        );

        assert_eq!(log.len(), 4);
        assert!(log.verify_integrity().is_ok());

        // Verify the chain links are correct
        let entries = log.recent(4);
        assert_eq!(entries[0].prev_hash, "0".repeat(64));
        assert_eq!(entries[1].prev_hash, entries[0].hash);
        assert_eq!(entries[2].prev_hash, entries[1].hash);
        assert_eq!(entries[3].prev_hash, entries[2].hash);
    }

    #[test]
    fn test_audit_tamper_detection() {
        let log = AuditLog::new();
        log.record("agent-1", AuditAction::ToolInvoke, "read_file /tmp/a", "ok");
        log.record("agent-1", AuditAction::ShellExec, "rm -rf /", "denied");
        log.record("agent-1", AuditAction::MemoryAccess, "read key foo", "ok");

        // Tamper with an entry
        {
            let mut entries = log.entries.lock().unwrap();
            entries[1].detail = "echo hello".to_string(); // change the detail
        }

        let result = log.verify_integrity();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("hash mismatch at seq 1"));
    }

    #[test]
    fn test_audit_tip_changes() {
        let log = AuditLog::new();
        let genesis_tip = log.tip_hash();
        assert_eq!(genesis_tip, "0".repeat(64));

        let h1 = log.record("a", AuditAction::AgentSpawn, "spawn", "ok");
        assert_eq!(log.tip_hash(), h1);
        assert_ne!(log.tip_hash(), genesis_tip);

        let h2 = log.record("b", AuditAction::AgentKill, "kill", "ok");
        assert_eq!(log.tip_hash(), h2);
        assert_ne!(h2, h1);
    }

    #[test]
    fn test_audit_persists_to_db() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE audit_entries (
                seq INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL,
                outcome TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            )",
        )
        .unwrap();

        let db = Arc::new(Mutex::new(conn));

        // Record entries with DB
        let log = AuditLog::with_db(Arc::clone(&db));
        log.record("agent-1", AuditAction::AgentSpawn, "spawn test", "ok");
        log.record("agent-1", AuditAction::ShellExec, "ls", "ok");
        assert_eq!(log.len(), 2);

        // Verify entries in database
        let db_conn = db.lock().unwrap();
        let count: i64 = db_conn
            .query_row("SELECT COUNT(*) FROM audit_entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
        drop(db_conn);

        // Simulate restart: create new AuditLog from same DB
        let log2 = AuditLog::with_db(Arc::clone(&db));
        assert_eq!(log2.len(), 2);
        assert!(log2.verify_integrity().is_ok());

        // Chain continues correctly after restart
        log2.record("agent-2", AuditAction::ToolInvoke, "file_read", "ok");
        assert_eq!(log2.len(), 3);
        assert!(log2.verify_integrity().is_ok());

        // Verify tip is correct
        let entries = log2.recent(3);
        assert_eq!(entries[2].prev_hash, entries[1].hash);
    }
}
