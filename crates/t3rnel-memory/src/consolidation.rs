//! Memory consolidation and decay logic.
//!
//! Reduces confidence of old, unaccessed memories and merges
//! duplicate/similar memories.

use chrono::Utc;
use rusqlite::Connection;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use t3rnel_types::error::{T3rnelError, T3rnelResult};
use t3rnel_types::memory::ConsolidationReport;

/// Memory consolidation engine.
#[derive(Clone)]
pub struct ConsolidationEngine {
    conn: Arc<Mutex<Connection>>,
    /// Decay rate: how much to reduce confidence per consolidation cycle.
    decay_rate: f32,
}

impl ConsolidationEngine {
    /// Create a new consolidation engine.
    pub fn new(conn: Arc<Mutex<Connection>>, decay_rate: f32) -> Self {
        Self { conn, decay_rate }
    }

    /// Run a consolidation cycle: decay old memories.
    pub fn consolidate(&self) -> T3rnelResult<ConsolidationReport> {
        let start = std::time::Instant::now();
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;

        // Decay confidence of memories not accessed in the last 7 days
        let cutoff = (Utc::now() - chrono::Duration::days(7)).to_rfc3339();
        let decay_factor = 1.0 - self.decay_rate as f64;

        let decayed = conn
            .execute(
                "UPDATE memories SET confidence = MAX(0.1, confidence * ?1)
                 WHERE deleted = 0 AND accessed_at < ?2 AND confidence > 0.1",
                rusqlite::params![decay_factor, cutoff],
            )
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ConsolidationReport {
            memories_merged: 0, // Phase 1: no merging
            memories_decayed: decayed as u64,
            duration_ms,
        })
    }

    // ------------------------------------------------------------------
    // Taint labels (05-security §14.9/§14.10)
    // ------------------------------------------------------------------

    /// Union two taint JSON arrays. Labels can only grow — this is the
    /// permanence rule: consolidation/summarisation may add labels, never
    /// remove them.
    pub fn union_taint(a: &str, b: &str) -> String {
        let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for blob in [a, b] {
            if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(blob) {
                for item in items {
                    if let Some(s) = item.as_str() {
                        set.insert(s.to_string());
                    }
                }
            }
        }
        serde_json::to_string(&set.into_iter().collect::<Vec<_>>()).unwrap_or_else(|_| "[]".into())
    }

    /// Read a memory's taint labels.
    pub fn taint_of(&self, id: &str) -> T3rnelResult<Vec<String>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;
        let blob: String = conn
            .query_row("SELECT taint FROM memories WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap_or_else(|_| "[]".to_string());
        Ok(serde_json::from_str::<Vec<String>>(&blob).unwrap_or_default())
    }

    /// Set a memory's taint labels (host-side classification only).
    pub fn set_taint(&self, id: &str, labels: &[&str]) -> T3rnelResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;
        let blob = serde_json::to_string(labels).unwrap_or_else(|_| "[]".into());
        conn.execute(
            "UPDATE memories SET taint = ?1 WHERE id = ?2",
            rusqlite::params![blob, id],
        )
        .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        Ok(())
    }

    /// Merge `drop_id` into `keep_id`: content is concatenated, taint labels
    /// are UNIONED (never intersected), and the dropped row is soft-deleted.
    /// This is the only merge primitive — callers must use it so taint
    /// permanence is structural, not conventional.
    pub fn merge_memories(&self, keep_id: &str, drop_id: &str) -> T3rnelResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;
        let (keep_content, keep_taint): (String, String) = conn
            .query_row(
                "SELECT content, taint FROM memories WHERE id = ?1 AND deleted = 0",
                [keep_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let (drop_content, drop_taint): (String, String) = conn
            .query_row(
                "SELECT content, taint FROM memories WHERE id = ?1 AND deleted = 0",
                [drop_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let merged_taint = Self::union_taint(&keep_taint, &drop_taint);
        let merged_content = format!(
            "{keep_content}
{drop_content}"
        );
        conn.execute(
            "UPDATE memories SET content = ?1, taint = ?2 WHERE id = ?3",
            rusqlite::params![merged_content, merged_taint, keep_id],
        )
        .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        conn.execute("UPDATE memories SET deleted = 1 WHERE id = ?1", [drop_id])
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::run_migrations;

    fn setup() -> ConsolidationEngine {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        ConsolidationEngine::new(Arc::new(Mutex::new(conn)), 0.1)
    }

    #[test]
    fn test_consolidation_empty() {
        let engine = setup();
        let report = engine.consolidate().unwrap();
        assert_eq!(report.memories_decayed, 0);
    }

    #[test]
    fn test_consolidation_decays_old_memories() {
        let engine = setup();
        let conn = engine.conn.lock().unwrap();
        // Insert an old memory
        let old_date = (Utc::now() - chrono::Duration::days(30)).to_rfc3339();
        conn.execute(
            "INSERT INTO memories (id, agent_id, content, source, scope, confidence, metadata, created_at, accessed_at, access_count, deleted)
             VALUES ('test-id', 'agent-1', 'old memory', '\"conversation\"', 'episodic', 0.9, '{}', ?1, ?1, 0, 0)",
            rusqlite::params![old_date],
        ).unwrap();
        drop(conn);

        let report = engine.consolidate().unwrap();
        assert_eq!(report.memories_decayed, 1);

        // Verify confidence was reduced
        let conn = engine.conn.lock().unwrap();
        let confidence: f64 = conn
            .query_row(
                "SELECT confidence FROM memories WHERE id = 'test-id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(confidence < 0.9);
    }

    // ---- §14.9 planted-instruction permanence ----

    fn insert_memory(conn: &Connection, id: &str, taint: &str) {
        conn.execute(
            "INSERT INTO memories (id, agent_id, content, source, scope, confidence, metadata, created_at, accessed_at, access_count, deleted, taint)
             VALUES (?1, 'agent-1', 'planted instruction content', 'conversation', 'episodic', 0.9, '{}', datetime('now'), datetime('now'), 0, 0, ?2)",
            rusqlite::params![id, taint],
        ).unwrap();
    }

    #[test]
    fn taint_survives_three_consolidation_passes() {
        let engine = setup();
        {
            let conn = engine.conn.lock().unwrap();
            insert_memory(&conn, "m-tainted", "[\"untrusted\",\"prompt-injection\"]");
            insert_memory(&conn, "m-clean", "[]");
        }
        // Three consolidation cycles — labels must be untouched.
        for _ in 0..3 {
            engine.consolidate().unwrap();
        }
        let labels = engine.taint_of("m-tainted").unwrap();
        assert!(labels.contains(&"untrusted".to_string()), "{labels:?}");
        assert!(
            labels.contains(&"prompt-injection".to_string()),
            "{labels:?}"
        );
        assert!(engine.taint_of("m-clean").unwrap().is_empty());
    }

    #[test]
    fn merge_unions_taint_and_never_drops() {
        let engine = setup();
        {
            let conn = engine.conn.lock().unwrap();
            insert_memory(&conn, "keep", "[\"public\"]");
            insert_memory(&conn, "drop", "[\"financial\",\"untrusted\"]");
        }
        engine.merge_memories("keep", "drop").unwrap();
        let labels = engine.taint_of("keep").unwrap();
        assert!(labels.contains(&"public".to_string()));
        assert!(labels.contains(&"financial".to_string()));
        assert!(labels.contains(&"untrusted".to_string()));
        // The merged-away row is gone; its labels live on in `keep`.
        let conn = engine.conn.lock().unwrap();
        let deleted: i64 = conn
            .query_row("SELECT deleted FROM memories WHERE id='drop'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(deleted, 1);
    }

    #[test]
    fn union_taint_is_a_true_union() {
        let u = ConsolidationEngine::union_taint("[\"a\",\"b\"]", "[\"b\",\"c\"]");
        let v: Vec<String> = serde_json::from_str(&u).unwrap();
        assert_eq!(v, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        // Empty sides don't lose labels.
        let u2 = ConsolidationEngine::union_taint("[\"x\"]", "[]");
        assert!(u2.contains("x"));
    }
}
