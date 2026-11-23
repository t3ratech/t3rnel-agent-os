//! MemorySubstrate: unified implementation of the `Memory` trait.
//!
//! Composes the structured store, semantic store, knowledge store,
//! session store, and consolidation engine behind a single async API.

use crate::consolidation::ConsolidationEngine;
use crate::event_store::{EventRecord, EventStore};
use crate::knowledge::KnowledgeStore;
use crate::migration::run_migrations;
use crate::semantic::{ProgressiveMemoryDisclosure, SemanticStore};
use crate::session::{Session, SessionStore};
use crate::structured::StructuredStore;
use crate::usage::UsageStore;

use async_trait::async_trait;
use rusqlite::Connection;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use t3rnel_types::agent::{AgentEntry, AgentId, SessionId};
use t3rnel_types::config::MemoryConfig;
use t3rnel_types::error::{T3rnelError, T3rnelResult};
use t3rnel_types::memory::{
    ConsolidationReport, Entity, ExportFormat, GraphMatch, GraphPattern, ImportReport, Memory,
    MemoryFilter, MemoryFragment, MemoryId, MemorySource, Relation,
};
use tracing::{info, warn};

/// The unified memory substrate. Implements the `Memory` trait by delegating
/// to specialized stores backed by a shared SQLite connection.
pub struct MemorySubstrate {
    conn: Arc<Mutex<Connection>>,
    structured: StructuredStore,
    semantic: SemanticStore,
    knowledge: KnowledgeStore,
    sessions: SessionStore,
    consolidation: ConsolidationEngine,
    usage: UsageStore,
    events: EventStore,
}

/// A paired-device persistence record.
pub struct PairedDeviceRecord<'a> {
    pub device_id: &'a str,
    pub display_name: &'a str,
    pub platform: &'a str,
    pub paired_at: &'a str,
    pub last_seen: &'a str,
    pub push_token: Option<&'a str>,
    pub biometric_public_key: Option<&'a [u8]>,
}

fn task_row_to_json(row: &rusqlite::Row<'_>) -> rusqlite::Result<serde_json::Value> {
    let payload_bytes: Vec<u8> = row.get(9)?;
    let payload = if payload_bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&payload_bytes).unwrap_or(serde_json::Value::Null)
    };
    Ok(serde_json::json!({
        "id": row.get::<_, String>(0)?,
        "title": row.get::<_, String>(1).unwrap_or_default(),
        "description": row.get::<_, String>(2).unwrap_or_default(),
        "status": row.get::<_, String>(3)?,
        "assigned_to": row.get::<_, String>(4).unwrap_or_default(),
        "created_by": row.get::<_, String>(5).unwrap_or_default(),
        "created_at": row.get::<_, String>(6).unwrap_or_default(),
        "completed_at": row.get::<_, Option<String>>(7).unwrap_or(None),
        "result": row.get::<_, Option<String>>(8).unwrap_or(None),
        "payload": payload,
        "agent_id": row.get::<_, String>(10).unwrap_or_default(),
        "task_type": row.get::<_, String>(11).unwrap_or_default(),
    }))
}

impl MemorySubstrate {
    /// Open or create a memory substrate at the given database path.
    ///
    /// When `memory_config.backend == "http"` and `http_url`/`http_token_env` are set,
    /// the semantic store routes `remember`/`recall` to the memory-api gateway.
    /// When `memory_config.backend == "lancedb"` and `lancedb_url` is set,
    /// semantic vectors are stored and searched through the Python LanceDB sidecar.
    /// All other stores (KV, knowledge graph, sessions) remain local SQLite.
    pub fn open(
        db_path: &Path,
        decay_rate: f32,
        memory_config: &MemoryConfig,
    ) -> T3rnelResult<Self> {
        let conn = Connection::open(db_path).map_err(|e| T3rnelError::Memory(e.to_string()))?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        run_migrations(&conn).map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let shared = Arc::new(Mutex::new(conn));

        let semantic = Self::create_semantic_store(Arc::clone(&shared), memory_config)?;

        let memory = Self {
            conn: Arc::clone(&shared),
            structured: StructuredStore::new(Arc::clone(&shared)),
            semantic,
            knowledge: KnowledgeStore::new(Arc::clone(&shared)),
            sessions: SessionStore::new(Arc::clone(&shared)),
            usage: UsageStore::new(Arc::clone(&shared)),
            events: EventStore::new(Arc::clone(&shared)),
            consolidation: ConsolidationEngine::new(shared, decay_rate),
        };
        memory
            .import_legacy_shared_memory()
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        Ok(memory)
    }

    /// Create the semantic store, optionally with HTTP backend.
    fn create_semantic_store(
        conn: Arc<Mutex<Connection>>,
        memory_config: &MemoryConfig,
    ) -> T3rnelResult<SemanticStore> {
        if memory_config.backend == "lancedb" {
            let Some(url) = memory_config.lancedb_url.as_ref() else {
                return Err(T3rnelError::Memory(
                    "memory.backend='lancedb' requires memory.lancedb_url".to_string(),
                ));
            };
            let client = crate::lancedb_client::LanceDbClient::new(
                url,
                memory_config.lancedb_token_env.as_deref(),
            )
            .map_err(|e| T3rnelError::Memory(format!("LanceDB client init failed: {e}")))?;
            client
                .health_check()
                .map_err(|e| T3rnelError::Memory(format!("LanceDB sidecar health failed: {e}")))?;
            info!(url = %url, "LanceDB memory sidecar connected");
            return Ok(SemanticStore::new_with_lancedb(conn, client));
        }

        #[cfg(feature = "http-memory")]
        if memory_config.backend == "http" {
            if let (Some(url), Some(token_env)) =
                (&memory_config.http_url, &memory_config.http_token_env)
            {
                match crate::http_client::MemoryApiClient::new(url, token_env) {
                    Ok(client) => {
                        // Best-effort health check on startup
                        match client.health_check() {
                            Ok(()) => info!(url = %url, "HTTP memory backend connected"),
                            Err(e) => {
                                warn!(url = %url, error = %e, "HTTP memory backend health check failed, will retry on use")
                            }
                        }
                        return Ok(SemanticStore::new_with_http(conn, client));
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to create HTTP memory client, falling back to SQLite");
                    }
                }
            } else {
                warn!("backend=http but http_url/http_token_env not set, falling back to SQLite");
            }
        }

        #[cfg(not(feature = "http-memory"))]
        let _ = memory_config;

        Ok(SemanticStore::new(conn))
    }

    /// Create an in-memory substrate (for testing). Always uses SQLite backend.
    pub fn open_in_memory(decay_rate: f32) -> T3rnelResult<Self> {
        let conn = Connection::open_in_memory().map_err(|e| T3rnelError::Memory(e.to_string()))?;
        run_migrations(&conn).map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let shared = Arc::new(Mutex::new(conn));

        Ok(Self {
            conn: Arc::clone(&shared),
            structured: StructuredStore::new(Arc::clone(&shared)),
            semantic: SemanticStore::new(Arc::clone(&shared)),
            knowledge: KnowledgeStore::new(Arc::clone(&shared)),
            sessions: SessionStore::new(Arc::clone(&shared)),
            usage: UsageStore::new(Arc::clone(&shared)),
            events: EventStore::new(Arc::clone(&shared)),
            consolidation: ConsolidationEngine::new(shared, decay_rate),
        })
    }

    /// Get a reference to the usage store.
    pub fn usage(&self) -> &UsageStore {
        &self.usage
    }

    /// Get the append-only event store used for memory/team projections.
    pub fn events(&self) -> &EventStore {
        &self.events
    }

    /// Append a generic event to the shared event log.
    pub fn append_event(
        &self,
        source_agent: &str,
        target: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) -> T3rnelResult<EventRecord> {
        self.events
            .append(source_agent, target, event_type, payload)
    }

    /// List append-only events for a projection target.
    pub fn list_events_for_target(
        &self,
        target: &str,
        limit: usize,
    ) -> T3rnelResult<Vec<EventRecord>> {
        self.events.list_target(target, limit)
    }

    /// Get the shared database connection (for constructing stores from outside).
    pub fn usage_conn(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    /// Save an agent entry to persistent storage.
    pub fn save_agent(&self, entry: &AgentEntry) -> T3rnelResult<()> {
        self.structured.save_agent(entry)
    }

    /// Load an agent entry from persistent storage.
    pub fn load_agent(&self, agent_id: AgentId) -> T3rnelResult<Option<AgentEntry>> {
        self.structured.load_agent(agent_id)
    }

    /// Remove an agent from persistent storage and cascade-delete sessions.
    pub fn remove_agent(&self, agent_id: AgentId) -> T3rnelResult<()> {
        // Delete associated sessions first
        let _ = self.sessions.delete_agent_sessions(agent_id);
        self.structured.remove_agent(agent_id)
    }

    /// Load all agent entries from persistent storage.
    pub fn load_all_agents(&self) -> T3rnelResult<Vec<AgentEntry>> {
        self.structured.load_all_agents()
    }

    /// List all saved agents.
    pub fn list_agents(&self) -> T3rnelResult<Vec<(String, String, String)>> {
        self.structured.list_agents()
    }

    /// Synchronous get from the structured store (for kernel handle use).
    pub fn structured_get(
        &self,
        agent_id: AgentId,
        key: &str,
    ) -> T3rnelResult<Option<serde_json::Value>> {
        self.structured.get(agent_id, key)
    }

    /// List all KV pairs for an agent.
    pub fn list_kv(&self, agent_id: AgentId) -> T3rnelResult<Vec<(String, serde_json::Value)>> {
        self.structured.list_kv(agent_id)
    }

    /// Delete a KV entry for an agent.
    pub fn structured_delete(&self, agent_id: AgentId, key: &str) -> T3rnelResult<()> {
        self.structured.delete(agent_id, key)
    }

    // ------------------------------------------------------------------
    // Team-scoped memory (shared within a team, isolated from others)
    // ------------------------------------------------------------------

    /// Set a team-scoped key-value pair.
    pub fn set_team_memory(
        &self,
        team_id: &str,
        key: &str,
        value: serde_json::Value,
    ) -> T3rnelResult<()> {
        self.structured.set_team(team_id, key, value)
    }

    /// Get a team-scoped value by key.
    pub fn get_team_memory(
        &self,
        team_id: &str,
        key: &str,
    ) -> T3rnelResult<Option<serde_json::Value>> {
        self.structured.get_team(team_id, key)
    }

    /// List all team-scoped key-value pairs.
    pub fn list_team_memory(
        &self,
        team_id: &str,
    ) -> T3rnelResult<Vec<(String, serde_json::Value)>> {
        self.structured.list_team_kv(team_id)
    }

    /// Delete a team-scoped key.
    pub fn delete_team_memory(&self, team_id: &str, key: &str) -> T3rnelResult<()> {
        self.structured.delete_team(team_id, key)
    }

    /// Synchronous set in the structured store (for kernel handle use).
    pub fn structured_set(
        &self,
        agent_id: AgentId,
        key: &str,
        value: serde_json::Value,
    ) -> T3rnelResult<()> {
        self.structured.set(agent_id, key, value)
    }

    /// Get a session by ID.
    pub fn get_session(&self, session_id: SessionId) -> T3rnelResult<Option<Session>> {
        self.sessions.get_session(session_id)
    }

    /// Save a session.
    pub fn save_session(&self, session: &Session) -> T3rnelResult<()> {
        self.sessions.save_session(session)
    }

    /// Save a session asynchronously — runs the SQLite write in a blocking
    /// thread so the tokio runtime stays responsive.
    pub async fn save_session_async(&self, session: &Session) -> T3rnelResult<()> {
        let sessions = self.sessions.clone();
        let session = session.clone();
        tokio::task::spawn_blocking(move || sessions.save_session(&session))
            .await
            .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    /// Create a new empty session for an agent.
    pub fn create_session(&self, agent_id: AgentId) -> T3rnelResult<Session> {
        self.sessions.create_session(agent_id)
    }

    /// List all sessions with metadata.
    pub fn list_sessions(&self) -> T3rnelResult<Vec<serde_json::Value>> {
        self.sessions.list_sessions()
    }

    /// Delete a session by ID.
    pub fn delete_session(&self, session_id: SessionId) -> T3rnelResult<()> {
        self.sessions.delete_session(session_id)
    }

    /// Delete all sessions belonging to an agent.
    pub fn delete_agent_sessions(&self, agent_id: AgentId) -> T3rnelResult<()> {
        self.sessions.delete_agent_sessions(agent_id)
    }

    /// Delete the canonical (cross-channel) session for an agent.
    pub fn delete_canonical_session(&self, agent_id: AgentId) -> T3rnelResult<()> {
        self.sessions.delete_canonical_session(agent_id)
    }

    /// Set or clear a session label.
    pub fn set_session_label(
        &self,
        session_id: SessionId,
        label: Option<&str>,
    ) -> T3rnelResult<()> {
        self.sessions.set_session_label(session_id, label)
    }

    /// Find a session by label for a given agent.
    pub fn find_session_by_label(
        &self,
        agent_id: AgentId,
        label: &str,
    ) -> T3rnelResult<Option<Session>> {
        self.sessions.find_session_by_label(agent_id, label)
    }

    /// List all sessions for a specific agent.
    pub fn list_agent_sessions(&self, agent_id: AgentId) -> T3rnelResult<Vec<serde_json::Value>> {
        self.sessions.list_agent_sessions(agent_id)
    }

    /// Create a new session with an optional label.
    pub fn create_session_with_label(
        &self,
        agent_id: AgentId,
        label: Option<&str>,
    ) -> T3rnelResult<Session> {
        self.sessions.create_session_with_label(agent_id, label)
    }

    /// Load canonical session context for cross-channel memory.
    ///
    /// Returns the compacted summary (if any) and recent messages from the
    /// agent's persistent canonical session.
    pub fn canonical_context(
        &self,
        agent_id: AgentId,
        window_size: Option<usize>,
    ) -> T3rnelResult<(Option<String>, Vec<t3rnel_types::message::Message>)> {
        self.sessions.canonical_context(agent_id, window_size)
    }

    /// Store an LLM-generated summary, replacing older messages with the kept subset.
    ///
    /// Used by the compactor to replace text-truncation compaction with an
    /// LLM-generated summary of older conversation history.
    pub fn store_llm_summary(
        &self,
        agent_id: AgentId,
        summary: &str,
        kept_messages: Vec<t3rnel_types::message::Message>,
    ) -> T3rnelResult<()> {
        self.sessions
            .store_llm_summary(agent_id, summary, kept_messages)
    }

    /// Write a human-readable JSONL mirror of a session to disk.
    ///
    /// Best-effort — errors are returned but should be logged,
    /// never affecting the primary SQLite store.
    pub fn write_jsonl_mirror(
        &self,
        session: &Session,
        sessions_dir: &Path,
    ) -> Result<(), std::io::Error> {
        self.sessions.write_jsonl_mirror(session, sessions_dir)
    }

    /// Append messages to the agent's canonical session for cross-channel persistence.
    pub fn append_canonical(
        &self,
        agent_id: AgentId,
        messages: &[t3rnel_types::message::Message],
        compaction_threshold: Option<usize>,
    ) -> T3rnelResult<()> {
        self.sessions
            .append_canonical(agent_id, messages, compaction_threshold)?;
        Ok(())
    }

    /// Reconcile a reconnecting client with the canonical session.
    pub fn reconcile_canonical(
        &self,
        agent_id: AgentId,
        client_updated_at: Option<&str>,
        client_message_count: Option<usize>,
        window_size: Option<usize>,
    ) -> T3rnelResult<crate::session::SessionReconciliation> {
        self.sessions.reconcile_canonical(
            agent_id,
            client_updated_at,
            client_message_count,
            window_size,
        )
    }

    // -----------------------------------------------------------------
    // Paired devices persistence
    // -----------------------------------------------------------------

    /// Load all paired devices from the database.
    pub fn load_paired_devices(&self) -> T3rnelResult<Vec<serde_json::Value>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT device_id, display_name, platform, paired_at, last_seen, push_token, biometric_public_key FROM paired_devices"
        ).map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(serde_json::json!({
                    "device_id": row.get::<_, String>(0)?,
                    "display_name": row.get::<_, String>(1)?,
                    "platform": row.get::<_, String>(2)?,
                    "paired_at": row.get::<_, String>(3)?,
                    "last_seen": row.get::<_, String>(4)?,
                    "push_token": row.get::<_, Option<String>>(5)?,
                    "biometric_public_key": row.get::<_, Option<Vec<u8>>>(6)?,
                }))
            })
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let mut devices = Vec::new();
        for row in rows {
            devices.push(row.map_err(|e| T3rnelError::Memory(e.to_string()))?);
        }
        Ok(devices)
    }

    /// Save a paired device to the database (insert or replace).
    pub fn save_paired_device(&self, device: PairedDeviceRecord<'_>) -> T3rnelResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO paired_devices (device_id, display_name, platform, paired_at, last_seen, push_token, biometric_public_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                device.device_id,
                device.display_name,
                device.platform,
                device.paired_at,
                device.last_seen,
                device.push_token,
                device.biometric_public_key
            ],
        ).map_err(|e| T3rnelError::Memory(e.to_string()))?;
        Ok(())
    }

    /// Remove a paired device from the database.
    pub fn remove_paired_device(&self, device_id: &str) -> T3rnelResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        conn.execute(
            "DELETE FROM paired_devices WHERE device_id = ?1",
            rusqlite::params![device_id],
        )
        .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        Ok(())
    }

    // -----------------------------------------------------------------
    // Approval persistence
    // -----------------------------------------------------------------

    /// Save a pending approval request to SQLite.
    pub fn save_approval_request(
        &self,
        req: &t3rnel_types::approval::ApprovalRequest,
    ) -> T3rnelResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO approvals (
                id, agent_id, tool_name, description, action_summary,
                risk_level, requested_at, timeout_secs, resolved
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
            rusqlite::params![
                req.id.to_string(),
                &req.agent_id,
                &req.tool_name,
                &req.description,
                &req.action_summary,
                format!("{:?}", req.risk_level),
                req.requested_at.to_rfc3339(),
                req.timeout_secs as i64,
            ],
        )
        .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        Ok(())
    }

    /// Mark an approval as resolved in SQLite.
    pub fn resolve_approval(
        &self,
        id: uuid::Uuid,
        decision: &str,
        decided_by: Option<&str>,
    ) -> T3rnelResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        conn.execute(
            "UPDATE approvals SET resolved = 1, decision = ?1, decided_at = ?2, decided_by = ?3 WHERE id = ?4",
            rusqlite::params![
                decision,
                chrono::Utc::now().to_rfc3339(),
                decided_by,
                id.to_string(),
            ],
        )
        .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        Ok(())
    }

    /// Load all unresolved (pending) approval requests from SQLite.
    pub fn load_pending_approvals(
        &self,
    ) -> T3rnelResult<Vec<t3rnel_types::approval::ApprovalRequest>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, agent_id, tool_name, description, action_summary,
                        risk_level, requested_at, timeout_secs
                 FROM approvals WHERE resolved = 0",
            )
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let risk_str: String = row.get(5)?;
                let risk = match risk_str.as_str() {
                    "Low" => t3rnel_types::approval::RiskLevel::Low,
                    "Medium" => t3rnel_types::approval::RiskLevel::Medium,
                    "High" => t3rnel_types::approval::RiskLevel::High,
                    "Critical" => t3rnel_types::approval::RiskLevel::Critical,
                    _ => t3rnel_types::approval::RiskLevel::Medium,
                };
                let requested_at: String = row.get(6)?;
                let requested_at = chrono::DateTime::parse_from_rfc3339(&requested_at)
                    .unwrap_or_else(|_| chrono::DateTime::UNIX_EPOCH.into())
                    .with_timezone(&chrono::Utc);
                Ok(t3rnel_types::approval::ApprovalRequest {
                    id: uuid::Uuid::parse_str(&row.get::<_, String>(0)?)
                        .unwrap_or_else(|_| uuid::Uuid::nil()),
                    agent_id: row.get(1)?,
                    tool_name: row.get(2)?,
                    description: row.get(3)?,
                    action_summary: row.get(4)?,
                    risk_level: risk,
                    requested_at,
                    timeout_secs: row.get::<_, i64>(7)? as u64,
                })
            })
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| T3rnelError::Memory(e.to_string()))?);
        }
        Ok(out)
    }

    /// Load recent resolved approvals (newest first).
    pub fn load_recent_approvals(
        &self,
        limit: usize,
    ) -> T3rnelResult<
        Vec<(
            t3rnel_types::approval::ApprovalRequest,
            String,
            Option<String>,
        )>,
    > {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, agent_id, tool_name, description, action_summary,
                        risk_level, requested_at, timeout_secs, decision, decided_by
                 FROM approvals WHERE resolved = 1 ORDER BY decided_at DESC LIMIT ?1",
            )
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let rows = stmt
            .query_map([limit as i64], |row| {
                let risk_str: String = row.get(5)?;
                let risk = match risk_str.as_str() {
                    "Low" => t3rnel_types::approval::RiskLevel::Low,
                    "Medium" => t3rnel_types::approval::RiskLevel::Medium,
                    "High" => t3rnel_types::approval::RiskLevel::High,
                    "Critical" => t3rnel_types::approval::RiskLevel::Critical,
                    _ => t3rnel_types::approval::RiskLevel::Medium,
                };
                let requested_at: String = row.get(6)?;
                let requested_at = chrono::DateTime::parse_from_rfc3339(&requested_at)
                    .unwrap_or_else(|_| chrono::DateTime::UNIX_EPOCH.into())
                    .with_timezone(&chrono::Utc);
                let req = t3rnel_types::approval::ApprovalRequest {
                    id: uuid::Uuid::parse_str(&row.get::<_, String>(0)?)
                        .unwrap_or_else(|_| uuid::Uuid::nil()),
                    agent_id: row.get(1)?,
                    tool_name: row.get(2)?,
                    description: row.get(3)?,
                    action_summary: row.get(4)?,
                    risk_level: risk,
                    requested_at,
                    timeout_secs: row.get::<_, i64>(7)? as u64,
                };
                let decision: String = row.get(8)?;
                let decided_by: Option<String> = row.get(9)?;
                Ok((req, decision, decided_by))
            })
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| T3rnelError::Memory(e.to_string()))?);
        }
        Ok(out)
    }

    // -----------------------------------------------------------------
    // Embedding-aware memory operations
    // -----------------------------------------------------------------

    /// Store a memory with an embedding vector.
    pub fn remember_with_embedding(
        &self,
        agent_id: AgentId,
        content: &str,
        source: MemorySource,
        scope: &str,
        metadata: HashMap<String, serde_json::Value>,
        embedding: Option<&[f32]>,
    ) -> T3rnelResult<MemoryId> {
        self.semantic
            .remember_with_embedding(agent_id, content, source, scope, metadata, embedding)
    }

    /// Recall memories using vector similarity when a query embedding is provided.
    pub fn recall_with_embedding(
        &self,
        query: &str,
        limit: usize,
        filter: Option<MemoryFilter>,
        query_embedding: Option<&[f32]>,
    ) -> T3rnelResult<Vec<MemoryFragment>> {
        self.semantic
            .recall_with_embedding(query, limit, filter, query_embedding)
    }

    /// Progressive disclosure memory retrieval.
    pub fn progressive_recall(
        &self,
        query: &str,
        filter: Option<MemoryFilter>,
        query_embedding: Option<&[f32]>,
        index_limit: usize,
        timeline_per_anchor: usize,
        full_limit: usize,
    ) -> T3rnelResult<ProgressiveMemoryDisclosure> {
        self.semantic.progressive_recall(
            query,
            filter,
            query_embedding,
            index_limit,
            timeline_per_anchor,
            full_limit,
        )
    }

    /// Async wrapper for progressive disclosure recall.
    pub async fn progressive_recall_async(
        &self,
        query: &str,
        filter: Option<MemoryFilter>,
        query_embedding: Option<&[f32]>,
        index_limit: usize,
        timeline_per_anchor: usize,
        full_limit: usize,
    ) -> T3rnelResult<ProgressiveMemoryDisclosure> {
        let store = self.semantic.clone();
        let query = query.to_string();
        let embedding_owned = query_embedding.map(|embedding| embedding.to_vec());
        tokio::task::spawn_blocking(move || {
            store.progressive_recall(
                &query,
                filter,
                embedding_owned.as_deref(),
                index_limit,
                timeline_per_anchor,
                full_limit,
            )
        })
        .await
        .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    /// Number of semantic vectors currently resident in the hot HNSW cache.
    pub fn semantic_hot_index_len(&self) -> usize {
        self.semantic.hot_index_len()
    }

    /// Update the embedding for an existing memory.
    pub fn update_embedding(&self, id: MemoryId, embedding: &[f32]) -> T3rnelResult<()> {
        self.semantic.update_embedding(id, embedding)
    }

    /// Async wrapper for `recall_with_embedding` — runs in a blocking thread.
    pub async fn recall_with_embedding_async(
        &self,
        query: &str,
        limit: usize,
        filter: Option<MemoryFilter>,
        query_embedding: Option<&[f32]>,
    ) -> T3rnelResult<Vec<MemoryFragment>> {
        let store = self.semantic.clone();
        let query = query.to_string();
        let embedding_owned = query_embedding.map(|e| e.to_vec());
        tokio::task::spawn_blocking(move || {
            store.recall_with_embedding(&query, limit, filter, embedding_owned.as_deref())
        })
        .await
        .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    /// Async wrapper for `remember_with_embedding` — runs in a blocking thread.
    pub async fn remember_with_embedding_async(
        &self,
        agent_id: AgentId,
        content: &str,
        source: MemorySource,
        scope: &str,
        metadata: HashMap<String, serde_json::Value>,
        embedding: Option<&[f32]>,
    ) -> T3rnelResult<MemoryId> {
        let store = self.semantic.clone();
        let content = content.to_string();
        let scope = scope.to_string();
        let embedding_owned = embedding.map(|e| e.to_vec());
        tokio::task::spawn_blocking(move || {
            store.remember_with_embedding(
                agent_id,
                &content,
                source,
                &scope,
                metadata,
                embedding_owned.as_deref(),
            )
        })
        .await
        .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    // -----------------------------------------------------------------
    // Task queue operations
    // -----------------------------------------------------------------

    /// Post a new task to the shared queue. Returns the task ID.
    pub async fn task_post(
        &self,
        title: &str,
        description: &str,
        assigned_to: Option<&str>,
        created_by: Option<&str>,
    ) -> T3rnelResult<String> {
        self.task_post_with_payload(
            title,
            description,
            assigned_to,
            created_by,
            serde_json::Value::Null,
        )
        .await
    }

    /// Post a new task with structured payload metadata. Returns the task ID.
    pub async fn task_post_with_payload(
        &self,
        title: &str,
        description: &str,
        assigned_to: Option<&str>,
        created_by: Option<&str>,
        payload: serde_json::Value,
    ) -> T3rnelResult<String> {
        let conn = Arc::clone(&self.conn);
        let title = title.to_string();
        let description = description.to_string();
        let assigned_to = assigned_to.unwrap_or("").to_string();
        let created_by = created_by.unwrap_or("").to_string();
        let payload =
            serde_json::to_vec(&payload).map_err(|e| T3rnelError::Serialization(e.to_string()))?;

        tokio::task::spawn_blocking(move || {
            let id = uuid::Uuid::new_v4().to_string();
            let now = chrono::Utc::now().to_rfc3339();
            let db = conn.lock().map_err(|e| T3rnelError::Internal(e.to_string()))?;
            db.execute(
                "INSERT INTO task_queue (id, agent_id, task_type, payload, status, priority, created_at, title, description, assigned_to, created_by)
                 VALUES (?1, ?2, ?3, ?4, 'pending', 0, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![id, &created_by, &title, payload, now, title, description, assigned_to, created_by],
            )
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
            Ok(id)
        })
        .await
        .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    /// Load a task by ID from the shared queue.
    pub async fn task_get(&self, task_id: &str) -> T3rnelResult<Option<serde_json::Value>> {
        let conn = Arc::clone(&self.conn);
        let task_id = task_id.to_string();

        tokio::task::spawn_blocking(move || {
            let db = conn
                .lock()
                .map_err(|e| T3rnelError::Internal(e.to_string()))?;
            let mut stmt = db
                .prepare(
                    "SELECT id, title, description, status, assigned_to, created_by, created_at,
                        completed_at, result, payload, agent_id, task_type
                 FROM task_queue
                 WHERE id = ?1
                 LIMIT 1",
                )
                .map_err(|e| T3rnelError::Memory(e.to_string()))?;

            let result = stmt.query_row(rusqlite::params![task_id], task_row_to_json);
            match result {
                Ok(task) => Ok(Some(task)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(T3rnelError::Memory(e.to_string())),
            }
        })
        .await
        .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    /// Mark a task as in-progress for an agent.
    pub async fn task_start(&self, task_id: &str, agent_id: &str) -> T3rnelResult<()> {
        let conn = Arc::clone(&self.conn);
        let task_id = task_id.to_string();
        let agent_id = agent_id.to_string();

        tokio::task::spawn_blocking(move || {
            let db = conn
                .lock()
                .map_err(|e| T3rnelError::Internal(e.to_string()))?;
            let rows = db
                .execute(
                    "UPDATE task_queue
                 SET status = 'in_progress', assigned_to = ?2, completed_at = NULL, result = ''
                 WHERE id = ?1 AND status IN ('pending', 'in_progress')",
                    rusqlite::params![task_id, agent_id],
                )
                .map_err(|e| T3rnelError::Memory(e.to_string()))?;
            if rows == 0 {
                return Err(T3rnelError::Internal(format!(
                    "Task not found or not startable: {task_id}"
                )));
            }
            Ok(())
        })
        .await
        .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    /// Claim the next pending task (optionally for a specific assignee). Returns task JSON or None.
    pub async fn task_claim(&self, agent_id: &str) -> T3rnelResult<Option<serde_json::Value>> {
        let conn = Arc::clone(&self.conn);
        let agent_id = agent_id.to_string();

        tokio::task::spawn_blocking(move || {
            let db = conn.lock().map_err(|e| T3rnelError::Internal(e.to_string()))?;
            // Find first pending task assigned to this agent, or any unassigned pending task
            let mut stmt = db.prepare(
                "SELECT id, title, description, assigned_to, created_by, created_at
                 FROM task_queue
                 WHERE status = 'pending' AND (assigned_to = ?1 OR assigned_to = '')
                 ORDER BY priority DESC, created_at ASC
                 LIMIT 1"
            ).map_err(|e| T3rnelError::Memory(e.to_string()))?;

            let result = stmt.query_row(rusqlite::params![agent_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            });

            match result {
                Ok((id, title, description, assigned, created_by, created_at)) => {
                    // Update status to in_progress
                    db.execute(
                        "UPDATE task_queue SET status = 'in_progress', assigned_to = ?2 WHERE id = ?1",
                        rusqlite::params![id, agent_id],
                    ).map_err(|e| T3rnelError::Memory(e.to_string()))?;

                    Ok(Some(serde_json::json!({
                        "id": id,
                        "title": title,
                        "description": description,
                        "status": "in_progress",
                        "assigned_to": if assigned.is_empty() { &agent_id } else { &assigned },
                        "created_by": created_by,
                        "created_at": created_at,
                    })))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(T3rnelError::Memory(e.to_string())),
            }
        })
        .await
        .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    /// Mark a task as completed with a result string.
    pub async fn task_complete(&self, task_id: &str, result: &str) -> T3rnelResult<()> {
        self.task_finish(task_id, "completed", result).await
    }

    /// Mark a task as cancelled.
    pub async fn task_cancel(&self, task_id: &str, reason: &str) -> T3rnelResult<()> {
        self.task_finish(task_id, "cancelled", reason).await
    }

    /// Mark a task as failed.
    pub async fn task_fail(&self, task_id: &str, error: &str) -> T3rnelResult<()> {
        self.task_finish(task_id, "failed", error).await
    }

    async fn task_finish(&self, task_id: &str, status: &str, result: &str) -> T3rnelResult<()> {
        let conn = Arc::clone(&self.conn);
        let task_id = task_id.to_string();
        let status = status.to_string();
        let result = result.to_string();

        tokio::task::spawn_blocking(move || {
            let now = chrono::Utc::now().to_rfc3339();
            let db = conn
                .lock()
                .map_err(|e| T3rnelError::Internal(e.to_string()))?;
            let transition_guard = match status.as_str() {
                "cancelled" => "status != 'completed'",
                "completed" | "failed" => "status NOT IN ('completed', 'failed', 'cancelled')",
                _ => "1 = 1",
            };
            let rows = db
                .execute(
                    &format!(
                        "UPDATE task_queue
                         SET status = ?2, result = ?3, completed_at = ?4
                         WHERE id = ?1 AND {transition_guard}"
                    ),
                    rusqlite::params![task_id, status, result, now],
                )
                .map_err(|e| T3rnelError::Memory(e.to_string()))?;
            if rows == 0 {
                let exists: i64 = db
                    .query_row(
                        "SELECT COUNT(*) FROM task_queue WHERE id = ?1",
                        rusqlite::params![task_id],
                        |row| row.get(0),
                    )
                    .map_err(|e| T3rnelError::Memory(e.to_string()))?;
                if exists == 0 {
                    return Err(T3rnelError::Internal(format!("Task not found: {task_id}")));
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    /// List tasks, optionally filtered by status.
    pub async fn task_list(&self, status: Option<&str>) -> T3rnelResult<Vec<serde_json::Value>> {
        let conn = Arc::clone(&self.conn);
        let status = status.map(|s| s.to_string());

        tokio::task::spawn_blocking(move || {
            let db = conn.lock().map_err(|e| T3rnelError::Internal(e.to_string()))?;
            let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match &status {
                Some(s) => (
                    "SELECT id, title, description, status, assigned_to, created_by, created_at, completed_at, result FROM task_queue WHERE status = ?1 ORDER BY created_at DESC",
                    vec![Box::new(s.clone())],
                ),
                None => (
                    "SELECT id, title, description, status, assigned_to, created_by, created_at, completed_at, result FROM task_queue ORDER BY created_at DESC",
                    vec![],
                ),
            };

            let mut stmt = db.prepare(sql).map_err(|e| T3rnelError::Memory(e.to_string()))?;
            let params_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
            let rows = stmt.query_map(params_refs.as_slice(), |row| {
                Ok(serde_json::json!({
                    "id": row.get::<_, String>(0)?,
                    "title": row.get::<_, String>(1).unwrap_or_default(),
                    "description": row.get::<_, String>(2).unwrap_or_default(),
                    "status": row.get::<_, String>(3)?,
                    "assigned_to": row.get::<_, String>(4).unwrap_or_default(),
                    "created_by": row.get::<_, String>(5).unwrap_or_default(),
                    "created_at": row.get::<_, String>(6).unwrap_or_default(),
                    "completed_at": row.get::<_, Option<String>>(7).unwrap_or(None),
                    "result": row.get::<_, Option<String>>(8).unwrap_or(None),
                }))
            }).map_err(|e| T3rnelError::Memory(e.to_string()))?;

            let mut tasks = Vec::new();
            for row in rows {
                tasks.push(row.map_err(|e| T3rnelError::Memory(e.to_string()))?);
            }
            Ok(tasks)
        })
        .await
        .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }
}

#[async_trait]
impl Memory for MemorySubstrate {
    async fn get(&self, agent_id: AgentId, key: &str) -> T3rnelResult<Option<serde_json::Value>> {
        let store = self.structured.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || store.get(agent_id, &key))
            .await
            .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    async fn set(
        &self,
        agent_id: AgentId,
        key: &str,
        value: serde_json::Value,
    ) -> T3rnelResult<()> {
        let store = self.structured.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || store.set(agent_id, &key, value))
            .await
            .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    async fn delete(&self, agent_id: AgentId, key: &str) -> T3rnelResult<()> {
        let store = self.structured.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || store.delete(agent_id, &key))
            .await
            .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    async fn remember(
        &self,
        agent_id: AgentId,
        content: &str,
        source: MemorySource,
        scope: &str,
        metadata: HashMap<String, serde_json::Value>,
    ) -> T3rnelResult<MemoryId> {
        let store = self.semantic.clone();
        let content = content.to_string();
        let scope = scope.to_string();
        tokio::task::spawn_blocking(move || {
            store.remember(agent_id, &content, source, &scope, metadata)
        })
        .await
        .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    async fn recall(
        &self,
        query: &str,
        limit: usize,
        filter: Option<MemoryFilter>,
    ) -> T3rnelResult<Vec<MemoryFragment>> {
        let store = self.semantic.clone();
        let query = query.to_string();
        tokio::task::spawn_blocking(move || store.recall(&query, limit, filter))
            .await
            .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    async fn forget(&self, id: MemoryId) -> T3rnelResult<()> {
        let store = self.semantic.clone();
        tokio::task::spawn_blocking(move || store.forget(id))
            .await
            .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    async fn add_entity(&self, entity: Entity) -> T3rnelResult<String> {
        let store = self.knowledge.clone();
        tokio::task::spawn_blocking(move || store.add_entity(entity))
            .await
            .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    async fn add_relation(&self, relation: Relation) -> T3rnelResult<String> {
        let store = self.knowledge.clone();
        tokio::task::spawn_blocking(move || store.add_relation(relation))
            .await
            .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    async fn query_graph(&self, pattern: GraphPattern) -> T3rnelResult<Vec<GraphMatch>> {
        let store = self.knowledge.clone();
        tokio::task::spawn_blocking(move || store.query_graph(pattern))
            .await
            .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    async fn consolidate(&self) -> T3rnelResult<ConsolidationReport> {
        let engine = self.consolidation.clone();
        tokio::task::spawn_blocking(move || engine.consolidate())
            .await
            .map_err(|e| T3rnelError::Internal(e.to_string()))?
    }

    async fn export(&self, format: ExportFormat) -> T3rnelResult<Vec<u8>> {
        let _ = format;
        Ok(Vec::new())
    }

    async fn import(&self, _data: &[u8], _format: ExportFormat) -> T3rnelResult<ImportReport> {
        Ok(ImportReport {
            entities_imported: 0,
            relations_imported: 0,
            memories_imported: 0,
            errors: vec!["Import not yet implemented in Phase 1".to_string()],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_substrate_kv() {
        let substrate = MemorySubstrate::open_in_memory(0.1).unwrap();
        let agent_id = AgentId::new();
        substrate
            .set(agent_id, "key", serde_json::json!("value"))
            .await
            .unwrap();
        let val = substrate.get(agent_id, "key").await.unwrap();
        assert_eq!(val, Some(serde_json::json!("value")));
    }

    #[tokio::test]
    async fn test_substrate_remember_recall() {
        let substrate = MemorySubstrate::open_in_memory(0.1).unwrap();
        let agent_id = AgentId::new();
        substrate
            .remember(
                agent_id,
                "Rust is a great language",
                MemorySource::Conversation,
                "episodic",
                HashMap::new(),
            )
            .await
            .unwrap();
        let results = substrate.recall("Rust", 10, None).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_task_post_and_list() {
        let substrate = MemorySubstrate::open_in_memory(0.1).unwrap();
        let id = substrate
            .task_post(
                "Review code",
                "Check the auth module for issues",
                Some("auditor"),
                Some("orchestrator"),
            )
            .await
            .unwrap();
        assert!(!id.is_empty());

        let tasks = substrate.task_list(Some("pending")).await.unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0]["title"], "Review code");
        assert_eq!(tasks[0]["assigned_to"], "auditor");
        assert_eq!(tasks[0]["status"], "pending");
    }

    #[tokio::test]
    async fn test_task_claim_and_complete() {
        let substrate = MemorySubstrate::open_in_memory(0.1).unwrap();
        let task_id = substrate
            .task_post(
                "Audit endpoint",
                "Security audit the /api/login endpoint",
                Some("auditor"),
                None,
            )
            .await
            .unwrap();

        // Claim the task
        let claimed = substrate.task_claim("auditor").await.unwrap();
        assert!(claimed.is_some());
        let claimed = claimed.unwrap();
        assert_eq!(claimed["id"], task_id);
        assert_eq!(claimed["status"], "in_progress");

        // Complete the task
        substrate
            .task_complete(&task_id, "No vulnerabilities found")
            .await
            .unwrap();

        // Verify it shows as completed
        let tasks = substrate.task_list(Some("completed")).await.unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0]["result"], "No vulnerabilities found");
    }

    #[tokio::test]
    async fn test_task_get_start_cancel_and_fail() {
        let substrate = MemorySubstrate::open_in_memory(0.1).unwrap();
        let task_id = substrate
            .task_post_with_payload(
                "gRPC task",
                "Execute a real task",
                Some("agent-1"),
                Some("grpc"),
                serde_json::json!({"trace": "abc"}),
            )
            .await
            .unwrap();

        let task = substrate.task_get(&task_id).await.unwrap().unwrap();
        assert_eq!(task["id"], task_id);
        assert_eq!(task["status"], "pending");
        assert_eq!(task["payload"]["trace"], "abc");

        substrate.task_start(&task_id, "agent-1").await.unwrap();
        let task = substrate.task_get(&task_id).await.unwrap().unwrap();
        assert_eq!(task["status"], "in_progress");

        substrate
            .task_cancel(&task_id, "operator cancelled")
            .await
            .unwrap();
        let task = substrate.task_get(&task_id).await.unwrap().unwrap();
        assert_eq!(task["status"], "cancelled");
        assert_eq!(task["result"], "operator cancelled");
        substrate
            .task_fail(&task_id, "late worker error")
            .await
            .unwrap();
        let task = substrate.task_get(&task_id).await.unwrap().unwrap();
        assert_eq!(task["status"], "cancelled");
        assert_eq!(task["result"], "operator cancelled");

        let failed_id = substrate
            .task_post("failing task", "fail it", Some("agent-2"), Some("grpc"))
            .await
            .unwrap();
        substrate
            .task_fail(&failed_id, "provider error")
            .await
            .unwrap();
        let failed = substrate.task_get(&failed_id).await.unwrap().unwrap();
        assert_eq!(failed["status"], "failed");
        assert_eq!(failed["result"], "provider error");
        substrate
            .task_cancel(&failed_id, "operator override")
            .await
            .unwrap();
        let cancelled = substrate.task_get(&failed_id).await.unwrap().unwrap();
        assert_eq!(cancelled["status"], "cancelled");
        assert_eq!(cancelled["result"], "operator override");
    }

    #[tokio::test]
    async fn test_task_claim_empty() {
        let substrate = MemorySubstrate::open_in_memory(0.1).unwrap();
        let claimed = substrate.task_claim("nobody").await.unwrap();
        assert!(claimed.is_none());
    }
}
