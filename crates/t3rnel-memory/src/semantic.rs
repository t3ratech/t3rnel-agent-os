//! Semantic memory store with vector embedding support.
//!
//! SQLite stores embeddings locally for cosine re-ranking, and production
//! deployments can route semantic operations through the LanceDB sidecar.
//!
//! Embeddings are stored as BLOBs in the `embedding` column of the memories table.
//! When a query embedding is provided, recall uses cosine similarity ranking.
//! When no embeddings are available, falls back to LIKE matching.

use chrono::{DateTime, Utc};
use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use t3rnel_types::agent::AgentId;
use t3rnel_types::error::{T3rnelError, T3rnelResult};
use t3rnel_types::memory::{MemoryFilter, MemoryFragment, MemoryId, MemorySource};
use tracing::{debug, warn};

use crate::hnsw_lite::{HnswLite, Vector};
#[cfg(feature = "http-memory")]
use crate::http_client::MemoryApiClient;
use crate::lancedb_client::LanceDbClient;

/// Semantic store backed by SQLite with optional vector search.
///
/// Supports two backends:
/// - **SQLite** (default): Local LIKE matching / cosine similarity.
/// - **HTTP**: Routes `remember`/`recall` to the memory-api gateway
///   (PostgreSQL + pgvector + Jina AI embeddings).
/// - **LanceDB**: Routes semantic vector writes/searches to the local
///   Python embedding sidecar backed by LanceDB.
#[derive(Clone)]
pub struct SemanticStore {
    conn: Arc<Mutex<Connection>>,
    #[cfg(feature = "http-memory")]
    http_client: Option<MemoryApiClient>,
    lancedb_client: Option<LanceDbClient>,
    hot_index: Arc<Mutex<HnswLite>>,
    hot_fragments: Arc<Mutex<HashMap<String, MemoryFragment>>>,
}

/// First-stage progressive disclosure hit. This is intentionally compact and
/// safe to place in prompt context.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryIndexHit {
    pub id: MemoryId,
    pub agent_id: AgentId,
    pub scope: String,
    pub source: MemorySource,
    pub score: f32,
    pub preview: String,
    pub created_at: DateTime<Utc>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Three-stage memory retrieval result:
/// index hits -> timeline context -> selected full observations.
#[derive(Debug, Clone, Default)]
pub struct ProgressiveMemoryDisclosure {
    pub index_hits: Vec<MemoryIndexHit>,
    pub timeline_context: Vec<MemoryFragment>,
    pub full_observations: Vec<MemoryFragment>,
}

struct LanceDbRememberInput<'a> {
    agent_id: AgentId,
    content: &'a str,
    source: MemorySource,
    scope: &'a str,
    metadata: HashMap<String, serde_json::Value>,
    embedding: Option<&'a [f32]>,
}

impl SemanticStore {
    /// Create a new semantic store wrapping the given connection (SQLite backend).
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        let store = Self {
            conn,
            #[cfg(feature = "http-memory")]
            http_client: None,
            lancedb_client: None,
            hot_index: Arc::new(Mutex::new(HnswLite::new(16, 200))),
            hot_fragments: Arc::new(Mutex::new(HashMap::new())),
        };
        store.warm_hot_index_from_sqlite();
        store
    }

    /// Create a semantic store with an HTTP backend for the memory-api gateway.
    ///
    /// The SQLite connection is still required for local fallback and other stores.
    #[cfg(feature = "http-memory")]
    pub fn new_with_http(conn: Arc<Mutex<Connection>>, client: MemoryApiClient) -> Self {
        let store = Self {
            conn,
            http_client: Some(client),
            lancedb_client: None,
            hot_index: Arc::new(Mutex::new(HnswLite::new(16, 200))),
            hot_fragments: Arc::new(Mutex::new(HashMap::new())),
        };
        store.warm_hot_index_from_sqlite();
        store
    }

    /// Create a semantic store with a LanceDB sidecar backend.
    pub fn new_with_lancedb(conn: Arc<Mutex<Connection>>, client: LanceDbClient) -> Self {
        let store = Self {
            conn,
            #[cfg(feature = "http-memory")]
            http_client: None,
            lancedb_client: Some(client),
            hot_index: Arc::new(Mutex::new(HnswLite::new(16, 200))),
            hot_fragments: Arc::new(Mutex::new(HashMap::new())),
        };
        store.warm_hot_index_from_sqlite();
        store
    }

    /// Store a new memory fragment (without embedding).
    pub fn remember(
        &self,
        agent_id: AgentId,
        content: &str,
        source: MemorySource,
        scope: &str,
        metadata: HashMap<String, serde_json::Value>,
    ) -> T3rnelResult<MemoryId> {
        self.remember_with_embedding(agent_id, content, source, scope, metadata, None)
    }

    /// Store a new memory fragment with an optional embedding vector.
    ///
    /// When HTTP backend is configured, stores via memory-api (which handles
    /// embedding generation and deduplication). Falls back to local SQLite.
    pub fn remember_with_embedding(
        &self,
        agent_id: AgentId,
        content: &str,
        source: MemorySource,
        scope: &str,
        metadata: HashMap<String, serde_json::Value>,
        embedding: Option<&[f32]>,
    ) -> T3rnelResult<MemoryId> {
        // HTTP backend: route to memory-api
        #[cfg(feature = "http-memory")]
        if let Some(ref client) = self.http_client {
            return self.remember_via_http(client, agent_id, content, source, scope, &metadata);
        }

        if let Some(ref client) = self.lancedb_client {
            return self.remember_via_lancedb(
                client,
                LanceDbRememberInput {
                    agent_id,
                    content,
                    source,
                    scope,
                    metadata,
                    embedding,
                },
            );
        }

        // SQLite backend (default)
        self.remember_sqlite(agent_id, content, source, scope, metadata, embedding)
    }

    /// SQLite implementation of remember_with_embedding.
    fn remember_sqlite(
        &self,
        agent_id: AgentId,
        content: &str,
        source: MemorySource,
        scope: &str,
        metadata: HashMap<String, serde_json::Value>,
        embedding: Option<&[f32]>,
    ) -> T3rnelResult<MemoryId> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;
        let id = MemoryId::new();
        let now = Utc::now().to_rfc3339();
        let source_str = serde_json::to_string(&source)
            .map_err(|e| T3rnelError::Serialization(e.to_string()))?;
        let meta_str = serde_json::to_string(&metadata)
            .map_err(|e| T3rnelError::Serialization(e.to_string()))?;
        let embedding_bytes: Option<Vec<u8>> = embedding.map(embedding_to_bytes);

        conn.execute(
            "INSERT INTO memories (id, agent_id, content, source, scope, confidence, metadata, created_at, accessed_at, access_count, deleted, embedding)
             VALUES (?1, ?2, ?3, ?4, ?5, 1.0, ?6, ?7, ?7, 0, 0, ?8)",
            rusqlite::params![
                id.0.to_string(),
                agent_id.0.to_string(),
                content,
                source_str,
                scope,
                meta_str,
                now,
                embedding_bytes,
            ],
        )
        .map_err(|e| T3rnelError::Memory(e.to_string()))?;

        let _ = crate::event_store::append_event_locked(
            &conn,
            &agent_id.0.to_string(),
            &format!("memory:{}", id.0),
            "memory.remembered",
            serde_json::json!({
                "memory_id": id.0.to_string(),
                "agent_id": agent_id.0.to_string(),
                "source": source_str,
                "scope": scope,
                "metadata": metadata.clone(),
            }),
        );
        drop(conn);

        if let Some(vector) = embedding {
            let created_at = DateTime::parse_from_rfc3339(&now)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            self.insert_hot_fragment(MemoryFragment {
                id,
                agent_id,
                content: content.to_string(),
                embedding: Some(vector.to_vec()),
                metadata,
                source,
                confidence: 1.0,
                created_at,
                accessed_at: created_at,
                access_count: 0,
                scope: scope.to_string(),
            });
        }
        Ok(id)
    }

    fn remember_via_lancedb(
        &self,
        client: &LanceDbClient,
        input: LanceDbRememberInput<'_>,
    ) -> T3rnelResult<MemoryId> {
        let id = MemoryId::new();
        let now = Utc::now().to_rfc3339();
        let source_str = format!("{:?}", input.source).to_lowercase();
        let stored_id = client
            .store(
                &id.0.to_string(),
                input.content,
                &input.agent_id.0.to_string(),
                &source_str,
                input.scope,
                &input.metadata,
                &now,
                input.embedding,
                Some(input.scope),
            )
            .map_err(|e| T3rnelError::Memory(format!("LanceDB store failed: {e}")))?;
        let parsed_id = uuid::Uuid::parse_str(&stored_id)
            .map(MemoryId)
            .map_err(|e| T3rnelError::Memory(format!("LanceDB returned invalid id: {e}")))?;
        let created_at = DateTime::parse_from_rfc3339(&now)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let fragment = MemoryFragment {
            id: parsed_id,
            agent_id: input.agent_id,
            content: input.content.to_string(),
            embedding: input.embedding.map(|v| v.to_vec()),
            metadata: input.metadata.clone(),
            source: input.source.clone(),
            confidence: 1.0,
            created_at,
            accessed_at: created_at,
            access_count: 0,
            scope: input.scope.to_string(),
        };
        if input.embedding.is_some() {
            self.insert_hot_fragment(fragment);
        }
        if let Ok(conn) = self.conn.lock() {
            let _ = crate::event_store::append_event_locked(
                &conn,
                &input.agent_id.0.to_string(),
                &format!("memory:{}", parsed_id.0),
                "memory.remembered",
                serde_json::json!({
                    "memory_id": parsed_id.0.to_string(),
                    "agent_id": input.agent_id.0.to_string(),
                    "source": source_str,
                    "scope": input.scope,
                    "metadata": input.metadata,
                    "backend": "lancedb",
                }),
            );
        }
        Ok(parsed_id)
    }

    /// HTTP implementation of remember — routes to memory-api POST /memory/store.
    #[cfg(feature = "http-memory")]
    fn remember_via_http(
        &self,
        client: &MemoryApiClient,
        agent_id: AgentId,
        content: &str,
        source: MemorySource,
        scope: &str,
        metadata: &HashMap<String, serde_json::Value>,
    ) -> T3rnelResult<MemoryId> {
        let source_str = format!("{:?}", source).to_lowercase();
        let importance = metadata
            .get("importance")
            .and_then(|v| v.as_u64())
            .map(|v| v.min(10) as u8)
            .unwrap_or(5);
        let tags: Option<Vec<String>> = metadata
            .get("tags")
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        match client.store(
            content,
            Some(scope),
            Some(&agent_id.0.to_string()),
            Some(&source_str),
            Some(importance),
            tags,
        ) {
            Ok(resp) => {
                debug!(id = %resp.id, "Stored memory via HTTP backend");
                Ok(MemoryId::new())
            }
            Err(e) => {
                warn!(error = %e, "HTTP memory store failed, falling back to SQLite");
                self.remember_sqlite(agent_id, content, source, scope, metadata.clone(), None)
            }
        }
    }

    /// Search for memories using text matching (fallback, no embeddings).
    pub fn recall(
        &self,
        query: &str,
        limit: usize,
        filter: Option<MemoryFilter>,
    ) -> T3rnelResult<Vec<MemoryFragment>> {
        self.recall_with_embedding(query, limit, filter, None)
    }

    /// Search for memories using vector similarity when a query embedding is provided,
    /// falling back to LIKE matching otherwise.
    ///
    /// When HTTP backend is configured, searches via memory-api (hybrid vector+BM25).
    /// Falls back to local SQLite on HTTP errors.
    pub fn recall_with_embedding(
        &self,
        query: &str,
        limit: usize,
        filter: Option<MemoryFilter>,
        query_embedding: Option<&[f32]>,
    ) -> T3rnelResult<Vec<MemoryFragment>> {
        let hot_hits = query_embedding
            .map(|embedding| self.recall_hot(limit, filter.as_ref(), embedding))
            .unwrap_or_default();
        if hot_hits.len() >= limit && limit > 0 {
            self.touch_fragments(&hot_hits);
            return Ok(hot_hits);
        }

        // HTTP backend: route to memory-api
        #[cfg(feature = "http-memory")]
        if let Some(ref client) = self.http_client {
            match self.recall_via_http(client, query, limit, &filter) {
                Ok(results) => {
                    let merged = self.merge_hot_results(hot_hits, results, limit, query_embedding);
                    self.touch_fragments(&merged);
                    return Ok(merged);
                }
                Err(e) => {
                    warn!(error = %e, "HTTP memory search failed, falling back to SQLite");
                }
            }
        }

        if let Some(ref client) = self.lancedb_client {
            let results =
                self.recall_via_lancedb(client, query, limit, &filter, query_embedding)?;
            let merged = self.merge_hot_results(hot_hits, results, limit, query_embedding);
            self.touch_fragments(&merged);
            return Ok(merged);
        }

        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;

        // Build SQL: fetch candidates (broader than limit for vector re-ranking)
        let needs_post_filter = filter
            .as_ref()
            .map(|f| !f.metadata.is_empty())
            .unwrap_or(false);
        let fetch_limit = if query_embedding.is_some() || needs_post_filter {
            // Fetch more candidates for vector search re-ranking
            (limit * 10).max(100)
        } else {
            limit
        };

        let mut sql = String::from(
            "SELECT id, agent_id, content, source, scope, confidence, metadata, created_at, accessed_at, access_count, embedding
             FROM memories WHERE deleted = 0",
        );
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut param_idx = 1;

        // Text search filter (only when no embeddings — vector search handles relevance)
        if query_embedding.is_none() && !query.is_empty() {
            sql.push_str(&format!(" AND content LIKE ?{param_idx}"));
            params.push(Box::new(format!("%{query}%")));
            param_idx += 1;
        }

        // Apply filters
        if let Some(ref f) = filter {
            if let Some(agent_id) = f.agent_id {
                sql.push_str(&format!(" AND agent_id = ?{param_idx}"));
                params.push(Box::new(agent_id.0.to_string()));
                param_idx += 1;
            }
            if let Some(ref scope) = f.scope {
                sql.push_str(&format!(" AND scope = ?{param_idx}"));
                params.push(Box::new(scope.clone()));
                param_idx += 1;
            }
            if let Some(after) = f.after.as_ref() {
                sql.push_str(&format!(" AND created_at >= ?{param_idx}"));
                params.push(Box::new(after.to_rfc3339()));
                param_idx += 1;
            }
            if let Some(before) = f.before.as_ref() {
                sql.push_str(&format!(" AND created_at <= ?{param_idx}"));
                params.push(Box::new(before.to_rfc3339()));
                param_idx += 1;
            }
            if let Some(min_conf) = f.min_confidence {
                sql.push_str(&format!(" AND confidence >= ?{param_idx}"));
                params.push(Box::new(min_conf as f64));
                param_idx += 1;
            }
            if let Some(ref source) = f.source {
                let source_str = serde_json::to_string(source)
                    .map_err(|e| T3rnelError::Serialization(e.to_string()))?;
                sql.push_str(&format!(" AND source = ?{param_idx}"));
                params.push(Box::new(source_str));
            }
        }

        sql.push_str(" ORDER BY accessed_at DESC, access_count DESC");
        sql.push_str(&format!(" LIMIT {fetch_limit}"));

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                let id_str: String = row.get(0)?;
                let agent_str: String = row.get(1)?;
                let content: String = row.get(2)?;
                let source_str: String = row.get(3)?;
                let scope: String = row.get(4)?;
                let confidence: f64 = row.get(5)?;
                let meta_str: String = row.get(6)?;
                let created_str: String = row.get(7)?;
                let accessed_str: String = row.get(8)?;
                let access_count: i64 = row.get(9)?;
                let embedding_bytes: Option<Vec<u8>> = row.get(10)?;
                Ok((
                    id_str,
                    agent_str,
                    content,
                    source_str,
                    scope,
                    confidence,
                    meta_str,
                    created_str,
                    accessed_str,
                    access_count,
                    embedding_bytes,
                ))
            })
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;

        let mut fragments = Vec::new();
        for row_result in rows {
            let (
                id_str,
                agent_str,
                content,
                source_str,
                scope,
                confidence,
                meta_str,
                created_str,
                accessed_str,
                access_count,
                embedding_bytes,
            ) = row_result.map_err(|e| T3rnelError::Memory(e.to_string()))?;

            let id = uuid::Uuid::parse_str(&id_str)
                .map(MemoryId)
                .map_err(|e| T3rnelError::Memory(e.to_string()))?;
            let agent_id = uuid::Uuid::parse_str(&agent_str)
                .map(t3rnel_types::agent::AgentId)
                .map_err(|e| T3rnelError::Memory(e.to_string()))?;
            let source: MemorySource =
                serde_json::from_str(&source_str).unwrap_or(MemorySource::System);
            let metadata: HashMap<String, serde_json::Value> =
                serde_json::from_str(&meta_str).unwrap_or_default();
            let created_at = chrono::DateTime::parse_from_rfc3339(&created_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let accessed_at = chrono::DateTime::parse_from_rfc3339(&accessed_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            let embedding = embedding_bytes.as_deref().map(embedding_from_bytes);

            fragments.push(MemoryFragment {
                id,
                agent_id,
                content,
                embedding,
                metadata,
                source,
                confidence: confidence as f32,
                created_at,
                accessed_at,
                access_count: access_count.max(0) as u64,
                scope,
            });
        }
        if filter.as_ref().is_some_and(|f| !f.metadata.is_empty()) {
            fragments.retain(|fragment| fragment_matches_filter(fragment, filter.as_ref()));
        }

        // If we have a query embedding, re-rank by cosine similarity
        if let Some(qe) = query_embedding {
            fragments.sort_by(|a, b| {
                let sim_a = a
                    .embedding
                    .as_deref()
                    .map(|e| cosine_similarity(qe, e))
                    .unwrap_or(-1.0);
                let sim_b = b
                    .embedding
                    .as_deref()
                    .map(|e| cosine_similarity(qe, e))
                    .unwrap_or(-1.0);
                sim_b
                    .partial_cmp(&sim_a)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            fragments.truncate(limit);
            debug!(
                "Vector recall: {} results from {} candidates",
                fragments.len(),
                fetch_limit
            );
        }
        fragments = self.merge_hot_results(hot_hits, fragments, limit, query_embedding);

        // Update access counts for returned memories
        for frag in &fragments {
            let _ = conn.execute(
                "UPDATE memories SET access_count = access_count + 1, accessed_at = ?1 WHERE id = ?2",
                rusqlite::params![Utc::now().to_rfc3339(), frag.id.0.to_string()],
            );
        }

        Ok(fragments)
    }

    fn recall_via_lancedb(
        &self,
        client: &LanceDbClient,
        query: &str,
        limit: usize,
        filter: &Option<MemoryFilter>,
        query_embedding: Option<&[f32]>,
    ) -> T3rnelResult<Vec<MemoryFragment>> {
        let fetch_limit = (limit * 4).max(limit).max(20);
        let ns = filter.as_ref().and_then(|f| f.scope.as_deref());
        let rows = client
            .search(query, fetch_limit, query_embedding, ns)
            .map_err(|e| T3rnelError::Memory(format!("LanceDB search failed: {e}")))?;
        let mut fragments = Vec::with_capacity(rows.len());
        for row in rows {
            let id = uuid::Uuid::parse_str(&row.id)
                .map(MemoryId)
                .map_err(|e| T3rnelError::Memory(format!("LanceDB row id invalid: {e}")))?;
            let agent_id = uuid::Uuid::parse_str(&row.agent_id)
                .map(t3rnel_types::agent::AgentId)
                .unwrap_or_else(|_| filter.as_ref().and_then(|f| f.agent_id).unwrap_or_default());
            let metadata: HashMap<String, serde_json::Value> =
                serde_json::from_str(&row.metadata_json).unwrap_or_default();
            let source = match row.source.as_str() {
                "conversation" => MemorySource::Conversation,
                "document" => MemorySource::Document,
                "observation" => MemorySource::Observation,
                "inference" => MemorySource::Inference,
                "userprovided" | "user_provided" => MemorySource::UserProvided,
                _ => MemorySource::System,
            };
            let created_at = chrono::DateTime::parse_from_rfc3339(&row.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let distance = row.distance.unwrap_or(1.0).max(0.0);
            let confidence = (1.0 / (1.0 + distance)) as f32;
            fragments.push(MemoryFragment {
                id,
                agent_id,
                content: row.content,
                embedding: None,
                metadata,
                source,
                confidence,
                created_at,
                accessed_at: Utc::now(),
                access_count: 0,
                scope: row.scope,
            });
        }
        fragments.retain(|fragment| fragment_matches_filter(fragment, filter.as_ref()));
        fragments.truncate(limit);
        Ok(fragments)
    }

    /// Soft-delete a memory fragment.
    ///
    /// In HTTP mode, logs a warning (memory-api doesn't support delete yet)
    /// and performs the soft-delete locally only.
    pub fn forget(&self, id: MemoryId) -> T3rnelResult<()> {
        if let Some(ref client) = self.lancedb_client {
            let ns = self
                .hot_fragments
                .lock()
                .ok()
                .and_then(|m| m.get(&id.0.to_string()).map(|f| f.scope.clone()));
            client
                .delete(&id.0.to_string(), ns.as_deref())
                .map_err(|e| T3rnelError::Memory(format!("LanceDB delete failed: {e}")))?;
            self.delete_hot_fragment(id);
            if let Ok(conn) = self.conn.lock() {
                let _ = crate::event_store::append_event_locked(
                    &conn,
                    "system",
                    &format!("memory:{}", id.0),
                    "memory.forgotten",
                    serde_json::json!({
                        "memory_id": id.0.to_string(),
                        "backend": "lancedb",
                    }),
                );
            }
            return Ok(());
        }

        #[cfg(feature = "http-memory")]
        if self.http_client.is_some() {
            warn!(id = %id.0, "forget() not supported via HTTP backend, local-only soft-delete");
        }

        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;
        conn.execute(
            "UPDATE memories SET deleted = 1 WHERE id = ?1",
            rusqlite::params![id.0.to_string()],
        )
        .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let _ = crate::event_store::append_event_locked(
            &conn,
            "system",
            &format!("memory:{}", id.0),
            "memory.forgotten",
            serde_json::json!({
                "memory_id": id.0.to_string(),
                "backend": "sqlite",
            }),
        );
        drop(conn);
        self.delete_hot_fragment(id);
        Ok(())
    }

    /// Update the embedding for an existing memory.
    pub fn update_embedding(&self, id: MemoryId, embedding: &[f32]) -> T3rnelResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;
        let bytes = embedding_to_bytes(embedding);
        conn.execute(
            "UPDATE memories SET embedding = ?1 WHERE id = ?2",
            rusqlite::params![bytes, id.0.to_string()],
        )
        .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let fragment = Self::load_fragment_by_id_locked(&conn, id)?;
        let _ = crate::event_store::append_event_locked(
            &conn,
            "system",
            &format!("memory:{}", id.0),
            "memory.embedding_updated",
            serde_json::json!({
                "memory_id": id.0.to_string(),
                "dimensions": embedding.len(),
            }),
        );
        drop(conn);
        if let Some(mut fragment) = fragment {
            fragment.embedding = Some(embedding.to_vec());
            self.insert_hot_fragment(fragment);
        }
        Ok(())
    }

    /// HTTP implementation of recall — routes to memory-api POST /memory/search.
    ///
    /// Maps memory-api search results to `MemoryFragment` structs. Fields not
    /// available from the HTTP API (agent_id, embedding, access_count) use defaults.
    #[cfg(feature = "http-memory")]
    fn recall_via_http(
        &self,
        client: &MemoryApiClient,
        query: &str,
        limit: usize,
        filter: &Option<MemoryFilter>,
    ) -> T3rnelResult<Vec<MemoryFragment>> {
        let category = filter.as_ref().and_then(|f| f.scope.as_deref());

        let results = client
            .search(query, limit, category)
            .map_err(|e| T3rnelError::Memory(format!("HTTP search failed: {e}")))?;

        let fragments: Vec<MemoryFragment> = results
            .into_iter()
            .map(|r| {
                let created_at = r
                    .created_at
                    .map(|ms| {
                        chrono::DateTime::from_timestamp_millis(ms as i64).unwrap_or_else(Utc::now)
                    })
                    .unwrap_or_else(Utc::now);

                MemoryFragment {
                    id: MemoryId::new(),
                    agent_id: filter.as_ref().and_then(|f| f.agent_id).unwrap_or_default(),
                    content: r.content,
                    embedding: None,
                    metadata: HashMap::new(),
                    source: MemorySource::System,
                    confidence: r.score as f32,
                    created_at,
                    accessed_at: Utc::now(),
                    access_count: 0,
                    scope: r.category.unwrap_or_else(|| "general".to_string()),
                }
            })
            .collect();

        debug!(
            count = fragments.len(),
            "Recalled memories via HTTP backend"
        );
        Ok(fragments)
    }

    /// Number of vectors currently resident in the hot HNSW cache.
    pub fn hot_index_len(&self) -> usize {
        self.hot_index.lock().map(|index| index.len()).unwrap_or(0)
    }

    /// Compact first-stage recall. Intended for prompt hydration where only
    /// memory handles/snippets should be disclosed initially.
    pub fn recall_index(
        &self,
        query: &str,
        limit: usize,
        filter: Option<MemoryFilter>,
        query_embedding: Option<&[f32]>,
    ) -> T3rnelResult<Vec<MemoryIndexHit>> {
        let memories = self.recall_with_embedding(query, limit, filter, query_embedding)?;
        Ok(memories
            .into_iter()
            .map(|memory| MemoryIndexHit {
                id: memory.id,
                agent_id: memory.agent_id,
                scope: memory.scope,
                source: memory.source,
                score: memory.confidence,
                preview: preview_text(&memory.content, 240),
                created_at: memory.created_at,
                metadata: memory.metadata,
            })
            .collect())
    }

    /// Fetch full observations by memory ID after the index stage has selected
    /// specific records that deserve detailed context.
    pub fn fetch_full_observations(&self, ids: &[MemoryId]) -> T3rnelResult<Vec<MemoryFragment>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(fragment) = Self::load_fragment_by_id_locked(&conn, *id)? {
                out.push(fragment);
            }
        }
        Ok(out)
    }

    /// Fetch nearby timeline memories around anchor IDs.
    pub fn timeline_context(
        &self,
        anchor_ids: &[MemoryId],
        per_anchor: usize,
    ) -> T3rnelResult<Vec<MemoryFragment>> {
        if anchor_ids.is_empty() || per_anchor == 0 {
            return Ok(Vec::new());
        }
        let anchors = self.fetch_full_observations(anchor_ids)?;
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;
        let mut by_id = HashMap::<String, MemoryFragment>::new();
        for anchor in anchors {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {MEMORY_SELECT_COLUMNS}
                     FROM memories
                     WHERE deleted = 0 AND agent_id = ?1 AND scope = ?2
                     ORDER BY ABS(julianday(created_at) - julianday(?3)) ASC
                     LIMIT ?4"
                ))
                .map_err(|e| T3rnelError::Memory(e.to_string()))?;
            let rows = stmt
                .query_map(
                    rusqlite::params![
                        anchor.agent_id.0.to_string(),
                        anchor.scope,
                        anchor.created_at.to_rfc3339(),
                        per_anchor as i64,
                    ],
                    fragment_from_row,
                )
                .map_err(|e| T3rnelError::Memory(e.to_string()))?;
            for row in rows {
                let fragment = row.map_err(|e| T3rnelError::Memory(e.to_string()))?;
                by_id.insert(fragment.id.0.to_string(), fragment);
            }
        }
        let mut fragments: Vec<_> = by_id.into_values().collect();
        fragments.sort_by_key(|fragment| fragment.created_at);
        Ok(fragments)
    }

    /// Progressive disclosure retrieval:
    /// 1. HNSW/LanceDB/SQLite index snippets.
    /// 2. Nearby timeline context.
    /// 3. Full records for the most relevant observations.
    #[allow(clippy::too_many_arguments)]
    pub fn progressive_recall(
        &self,
        query: &str,
        filter: Option<MemoryFilter>,
        query_embedding: Option<&[f32]>,
        index_limit: usize,
        timeline_per_anchor: usize,
        full_limit: usize,
    ) -> T3rnelResult<ProgressiveMemoryDisclosure> {
        let index_hits = self.recall_index(query, index_limit, filter, query_embedding)?;
        let selected_ids: Vec<MemoryId> = index_hits
            .iter()
            .take(full_limit.max(timeline_per_anchor))
            .map(|hit| hit.id)
            .collect();
        let timeline_context = self.timeline_context(&selected_ids, timeline_per_anchor)?;
        let full_ids: Vec<MemoryId> = index_hits
            .iter()
            .take(full_limit)
            .map(|hit| hit.id)
            .collect();
        let full_observations = self.fetch_full_observations(&full_ids)?;
        Ok(ProgressiveMemoryDisclosure {
            index_hits,
            timeline_context,
            full_observations,
        })
    }

    fn warm_hot_index_from_sqlite(&self) {
        let Ok(conn) = self.conn.lock() else {
            return;
        };
        let Ok(mut stmt) = conn.prepare(&format!(
            "SELECT {MEMORY_SELECT_COLUMNS}
             FROM memories
             WHERE deleted = 0 AND embedding IS NOT NULL
             ORDER BY accessed_at DESC
             LIMIT 10000"
        )) else {
            return;
        };
        let Ok(rows) = stmt.query_map([], fragment_from_row) else {
            return;
        };
        let fragments: Vec<MemoryFragment> = rows.filter_map(Result::ok).collect();
        drop(stmt);
        drop(conn);
        for fragment in fragments {
            self.insert_hot_fragment(fragment);
        }
    }

    fn insert_hot_fragment(&self, fragment: MemoryFragment) {
        let Some(embedding) = fragment.embedding.as_ref() else {
            return;
        };
        if embedding.is_empty() {
            return;
        }
        let mut vector = Vector::from(embedding.clone());
        vector.normalize();
        let id = fragment.id.0.to_string();
        if let Ok(mut index) = self.hot_index.lock() {
            index.insert(&id, vector);
        }
        if let Ok(mut fragments) = self.hot_fragments.lock() {
            fragments.insert(id, fragment);
        }
    }

    fn delete_hot_fragment(&self, id: MemoryId) {
        let key = id.0.to_string();
        if let Ok(mut index) = self.hot_index.lock() {
            let _ = index.delete(&key);
        }
        if let Ok(mut fragments) = self.hot_fragments.lock() {
            fragments.remove(&key);
        }
    }

    fn recall_hot(
        &self,
        limit: usize,
        filter: Option<&MemoryFilter>,
        query_embedding: &[f32],
    ) -> Vec<MemoryFragment> {
        if limit == 0 || query_embedding.is_empty() {
            return Vec::new();
        }
        let mut query = Vector::from(query_embedding.to_vec());
        query.normalize();
        let results = self
            .hot_index
            .lock()
            .map(|index| index.search(&query, (limit * 4).max(limit)))
            .unwrap_or_default();
        let fragments = self.hot_fragments.lock();
        let Ok(fragments) = fragments else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for result in results {
            if let Some(fragment) = fragments.get(&result.id) {
                if !fragment_matches_filter(fragment, filter) {
                    continue;
                }
                let mut fragment = fragment.clone();
                fragment.confidence = 1.0 / (1.0 + result.distance);
                out.push(fragment);
                if out.len() >= limit {
                    break;
                }
            }
        }
        out
    }

    fn merge_hot_results(
        &self,
        hot_hits: Vec<MemoryFragment>,
        backend_hits: Vec<MemoryFragment>,
        limit: usize,
        query_embedding: Option<&[f32]>,
    ) -> Vec<MemoryFragment> {
        if hot_hits.is_empty() {
            return backend_hits.into_iter().take(limit).collect();
        }
        let mut by_id = HashMap::<String, MemoryFragment>::new();
        for fragment in backend_hits.into_iter().chain(hot_hits) {
            let key = fragment.id.0.to_string();
            match by_id.get(&key) {
                Some(existing)
                    if query_embedding.is_some()
                        && existing.embedding.is_some()
                        && fragment.embedding.is_none() => {}
                Some(existing)
                    if query_embedding.is_some()
                        && existing.embedding.is_none()
                        && fragment.embedding.is_some() =>
                {
                    by_id.insert(key, fragment);
                }
                Some(existing) if existing.confidence >= fragment.confidence => {}
                _ => {
                    by_id.insert(key, fragment);
                }
            }
        }
        let mut merged: Vec<_> = by_id.into_values().collect();
        if let Some(query_embedding) = query_embedding {
            merged.sort_by(|a, b| {
                rank_score(b, query_embedding)
                    .partial_cmp(&rank_score(a, query_embedding))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        } else {
            merged.sort_by(|a, b| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.accessed_at.cmp(&a.accessed_at))
            });
        }
        merged.truncate(limit);
        merged
    }

    fn touch_fragments(&self, fragments: &[MemoryFragment]) {
        let Ok(conn) = self.conn.lock() else {
            return;
        };
        for fragment in fragments {
            let _ = conn.execute(
                "UPDATE memories SET access_count = access_count + 1, accessed_at = ?1 WHERE id = ?2",
                rusqlite::params![Utc::now().to_rfc3339(), fragment.id.0.to_string()],
            );
        }
    }

    fn load_fragment_by_id_locked(
        conn: &Connection,
        id: MemoryId,
    ) -> T3rnelResult<Option<MemoryFragment>> {
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {MEMORY_SELECT_COLUMNS}
                 FROM memories
                 WHERE deleted = 0 AND id = ?1
                 LIMIT 1"
            ))
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        match stmt.query_row(rusqlite::params![id.0.to_string()], fragment_from_row) {
            Ok(fragment) => Ok(Some(fragment)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(T3rnelError::Memory(e.to_string())),
        }
    }
}

const MEMORY_SELECT_COLUMNS: &str = "id, agent_id, content, source, scope, confidence, metadata, created_at, accessed_at, access_count, embedding";

/// Compute cosine similarity between two vectors.
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom < f32::EPSILON {
        0.0
    } else {
        dot / denom
    }
}

fn rank_score(fragment: &MemoryFragment, query_embedding: &[f32]) -> f32 {
    fragment
        .embedding
        .as_deref()
        .map(|embedding| cosine_similarity(query_embedding, embedding))
        .unwrap_or(-1.0)
}

fn fragment_matches_filter(fragment: &MemoryFragment, filter: Option<&MemoryFilter>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    if filter
        .agent_id
        .is_some_and(|agent_id| agent_id != fragment.agent_id)
    {
        return false;
    }
    if filter
        .scope
        .as_ref()
        .is_some_and(|scope| scope != &fragment.scope)
    {
        return false;
    }
    if filter
        .source
        .as_ref()
        .is_some_and(|source| source != &fragment.source)
    {
        return false;
    }
    if filter
        .min_confidence
        .is_some_and(|min_confidence| fragment.confidence < min_confidence)
    {
        return false;
    }
    if filter
        .after
        .as_ref()
        .is_some_and(|after| fragment.created_at < *after)
    {
        return false;
    }
    if filter
        .before
        .as_ref()
        .is_some_and(|before| fragment.created_at > *before)
    {
        return false;
    }
    filter
        .metadata
        .iter()
        .all(|(key, expected)| fragment.metadata.get(key) == Some(expected))
}

fn preview_text(content: &str, max_chars: usize) -> String {
    let mut preview = String::new();
    for ch in content.chars().take(max_chars) {
        preview.push(ch);
    }
    if content.chars().count() > max_chars {
        preview.push_str("...");
    }
    preview
}

fn fragment_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryFragment> {
    let id_str: String = row.get(0)?;
    let agent_str: String = row.get(1)?;
    let content: String = row.get(2)?;
    let source_str: String = row.get(3)?;
    let scope: String = row.get(4)?;
    let confidence: f64 = row.get(5)?;
    let meta_str: String = row.get(6)?;
    let created_str: String = row.get(7)?;
    let accessed_str: String = row.get(8)?;
    let access_count: i64 = row.get(9)?;
    let embedding_bytes: Option<Vec<u8>> = row.get(10)?;

    let id = uuid::Uuid::parse_str(&id_str).map(MemoryId).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let agent_id = uuid::Uuid::parse_str(&agent_str)
        .map(AgentId)
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
        })?;
    let source: MemorySource = serde_json::from_str(&source_str).unwrap_or(MemorySource::System);
    let metadata: HashMap<String, serde_json::Value> =
        serde_json::from_str(&meta_str).unwrap_or_default();
    let created_at = DateTime::parse_from_rfc3339(&created_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let accessed_at = DateTime::parse_from_rfc3339(&accessed_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let embedding = embedding_bytes.as_deref().map(embedding_from_bytes);

    Ok(MemoryFragment {
        id,
        agent_id,
        content,
        embedding,
        metadata,
        source,
        confidence: confidence as f32,
        created_at,
        accessed_at,
        access_count: access_count.max(0) as u64,
        scope,
    })
}

/// Serialize embedding to bytes for SQLite BLOB storage.
fn embedding_to_bytes(embedding: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(embedding.len() * 4);
    for &val in embedding {
        bytes.extend_from_slice(&val.to_le_bytes());
    }
    bytes
}

/// Deserialize embedding from bytes.
fn embedding_from_bytes(bytes: &[u8]) -> Vec<f32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::run_migrations;

    fn setup_with_conn() -> (SemanticStore, Arc<Mutex<Connection>>) {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        let conn = Arc::new(Mutex::new(conn));
        (SemanticStore::new(Arc::clone(&conn)), conn)
    }

    fn setup() -> SemanticStore {
        setup_with_conn().0
    }

    #[test]
    fn test_remember_and_recall() {
        let store = setup();
        let agent_id = AgentId::new();
        store
            .remember(
                agent_id,
                "The user likes Rust programming",
                MemorySource::Conversation,
                "episodic",
                HashMap::new(),
            )
            .unwrap();
        let results = store.recall("Rust", 10, None).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].content.contains("Rust"));
    }

    #[test]
    fn test_recall_with_filter() {
        let store = setup();
        let agent_id = AgentId::new();
        store
            .remember(
                agent_id,
                "Memory A",
                MemorySource::Conversation,
                "episodic",
                HashMap::new(),
            )
            .unwrap();
        store
            .remember(
                AgentId::new(),
                "Memory B",
                MemorySource::Conversation,
                "episodic",
                HashMap::new(),
            )
            .unwrap();
        let filter = MemoryFilter::agent(agent_id);
        let results = store.recall("Memory", 10, Some(filter)).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "Memory A");
    }

    #[test]
    fn test_forget() {
        let store = setup();
        let agent_id = AgentId::new();
        let id = store
            .remember(
                agent_id,
                "To forget",
                MemorySource::Conversation,
                "episodic",
                HashMap::new(),
            )
            .unwrap();
        store.forget(id).unwrap();
        let results = store.recall("To forget", 10, None).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_remember_with_embedding() {
        let store = setup();
        let agent_id = AgentId::new();
        let embedding = vec![0.1, 0.2, 0.3, 0.4];
        let id = store
            .remember_with_embedding(
                agent_id,
                "Rust is great",
                MemorySource::Conversation,
                "episodic",
                HashMap::new(),
                Some(&embedding),
            )
            .unwrap();
        assert_ne!(id.0.to_string(), "");
    }

    #[test]
    fn test_vector_recall_ranking() {
        let store = setup();
        let agent_id = AgentId::new();

        // Store 3 memories with embeddings pointing in different directions
        let emb_rust = vec![0.9, 0.1, 0.0, 0.0]; // "Rust" direction
        let emb_python = vec![0.0, 0.0, 0.9, 0.1]; // "Python" direction
        let emb_mixed = vec![0.5, 0.5, 0.0, 0.0]; // mixed

        store
            .remember_with_embedding(
                agent_id,
                "Rust is a systems language",
                MemorySource::Conversation,
                "episodic",
                HashMap::new(),
                Some(&emb_rust),
            )
            .unwrap();
        store
            .remember_with_embedding(
                agent_id,
                "Python is interpreted",
                MemorySource::Conversation,
                "episodic",
                HashMap::new(),
                Some(&emb_python),
            )
            .unwrap();
        store
            .remember_with_embedding(
                agent_id,
                "Both are popular",
                MemorySource::Conversation,
                "episodic",
                HashMap::new(),
                Some(&emb_mixed),
            )
            .unwrap();

        // Query with a "Rust"-like embedding
        let query_emb = vec![0.85, 0.15, 0.0, 0.0];
        let results = store
            .recall_with_embedding("", 3, None, Some(&query_emb))
            .unwrap();

        assert_eq!(results.len(), 3);
        // Rust memory should be first (highest cosine similarity)
        assert!(results[0].content.contains("Rust"));
        // Python memory should be last (lowest similarity)
        assert!(results[2].content.contains("Python"));
    }

    #[test]
    fn test_update_embedding() {
        let store = setup();
        let agent_id = AgentId::new();
        let id = store
            .remember(
                agent_id,
                "No embedding yet",
                MemorySource::Conversation,
                "episodic",
                HashMap::new(),
            )
            .unwrap();

        // Update with embedding
        let emb = vec![1.0, 0.0, 0.0];
        store.update_embedding(id, &emb).unwrap();

        // Verify the embedding is stored by doing vector recall
        let query_emb = vec![1.0, 0.0, 0.0];
        let results = store
            .recall_with_embedding("", 10, None, Some(&query_emb))
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].embedding.is_some());
        assert_eq!(results[0].embedding.as_ref().unwrap().len(), 3);
    }

    #[test]
    fn test_mixed_embedded_and_non_embedded() {
        let store = setup();
        let agent_id = AgentId::new();

        // One memory with embedding, one without
        store
            .remember_with_embedding(
                agent_id,
                "Has embedding",
                MemorySource::Conversation,
                "episodic",
                HashMap::new(),
                Some(&[1.0, 0.0]),
            )
            .unwrap();
        store
            .remember(
                agent_id,
                "No embedding",
                MemorySource::Conversation,
                "episodic",
                HashMap::new(),
            )
            .unwrap();

        // Vector recall should rank embedded memory higher
        let results = store
            .recall_with_embedding("", 10, None, Some(&[1.0, 0.0]))
            .unwrap();
        assert_eq!(results.len(), 2);
        // Embedded memory should rank first
        assert_eq!(results[0].content, "Has embedding");
    }

    #[test]
    fn test_hnsw_hot_index_tracks_embedding_lifecycle() {
        let store = setup();
        let agent_id = AgentId::new();
        let id = store
            .remember_with_embedding(
                agent_id,
                "Hot path memory",
                MemorySource::Observation,
                "episodic",
                HashMap::new(),
                Some(&[0.2, 0.8]),
            )
            .unwrap();

        assert_eq!(store.hot_index_len(), 1);
        let results = store
            .recall_with_embedding("", 1, None, Some(&[0.1, 0.9]))
            .unwrap();
        assert_eq!(results[0].id, id);

        store.forget(id).unwrap();
        assert_eq!(store.hot_index_len(), 0);
    }

    #[test]
    fn test_progressive_recall_returns_index_timeline_and_full_records() {
        let store = setup();
        let agent_id = AgentId::new();
        let scope = "profile/default/team/personal/project/default/semantic";
        for (content, embedding) in [
            ("Rust ownership prevents data races", vec![1.0, 0.0]),
            ("Rust lifetimes describe borrow validity", vec![0.9, 0.1]),
            ("Python has a dynamic runtime", vec![0.0, 1.0]),
        ] {
            store
                .remember_with_embedding(
                    agent_id,
                    content,
                    MemorySource::Conversation,
                    scope,
                    HashMap::new(),
                    Some(&embedding),
                )
                .unwrap();
        }
        let filter = MemoryFilter {
            agent_id: Some(agent_id),
            scope: Some(scope.to_string()),
            ..Default::default()
        };
        let disclosure = store
            .progressive_recall("Rust", Some(filter), Some(&[1.0, 0.0]), 2, 2, 1)
            .unwrap();

        assert_eq!(disclosure.index_hits.len(), 2);
        assert!(disclosure.index_hits[0].preview.contains("Rust"));
        assert!(!disclosure.timeline_context.is_empty());
        assert_eq!(disclosure.full_observations.len(), 1);
        assert!(disclosure.full_observations[0].content.contains("Rust"));
    }

    #[test]
    fn test_semantic_remember_appends_event() {
        let (store, conn) = setup_with_conn();
        let agent_id = AgentId::new();
        let id = store
            .remember(
                agent_id,
                "Append-only memory event",
                MemorySource::System,
                "episodic",
                HashMap::new(),
            )
            .unwrap();
        let events = crate::event_store::EventStore::new(conn)
            .list_target(&format!("memory:{}", id.0), 10)
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "memory.remembered");
        assert_eq!(events[0].version, 1);
    }
}
