//! Append-only event store used for memory/team projections.

use chrono::Utc;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use t3rnel_types::error::{T3rnelError, T3rnelResult};

/// Decoded append-only event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventRecord {
    pub id: String,
    pub source_agent: String,
    pub target: String,
    pub event_type: String,
    pub version: u64,
    pub payload: serde_json::Value,
    pub timestamp: String,
}

#[derive(Clone)]
pub struct EventStore {
    conn: Arc<Mutex<Connection>>,
}

impl EventStore {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    pub fn append(
        &self,
        source_agent: &str,
        target: &str,
        event_type: &str,
        payload: serde_json::Value,
    ) -> T3rnelResult<EventRecord> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;
        append_event_locked(&conn, source_agent, target, event_type, payload)
    }

    pub fn list_target(&self, target: &str, limit: usize) -> T3rnelResult<Vec<EventRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, source_agent, target, payload, timestamp
                 FROM events
                 WHERE target = ?1
                 ORDER BY timestamp ASC
                 LIMIT ?2",
            )
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params![target, limit as i64], decode_event_row)
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| T3rnelError::Memory(e.to_string()))?);
        }
        Ok(out)
    }
}

pub(crate) fn append_event_locked(
    conn: &Connection,
    source_agent: &str,
    target: &str,
    event_type: &str,
    payload: serde_json::Value,
) -> T3rnelResult<EventRecord> {
    let version = next_target_version(conn, target)?;
    let id = uuid::Uuid::new_v4().to_string();
    let timestamp = Utc::now().to_rfc3339();
    let wrapped_payload = serde_json::json!({
        "event_type": event_type,
        "version": version,
        "payload": payload,
    });
    let bytes = serde_json::to_vec(&wrapped_payload)
        .map_err(|e| T3rnelError::Serialization(e.to_string()))?;

    conn.execute(
        "INSERT INTO events (id, source_agent, target, payload, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![id, source_agent, target, bytes, timestamp],
    )
    .map_err(|e| T3rnelError::Memory(e.to_string()))?;

    Ok(EventRecord {
        id,
        source_agent: source_agent.to_string(),
        target: target.to_string(),
        event_type: event_type.to_string(),
        version,
        payload,
        timestamp,
    })
}

fn next_target_version(conn: &Connection, target: &str) -> T3rnelResult<u64> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE target = ?1",
            rusqlite::params![target],
            |row| row.get(0),
        )
        .map_err(|e| T3rnelError::Memory(e.to_string()))?;
    Ok(count.max(0) as u64 + 1)
}

fn decode_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EventRecord> {
    let payload_bytes: Vec<u8> = row.get(3)?;
    let wrapped: serde_json::Value =
        serde_json::from_slice(&payload_bytes).unwrap_or(serde_json::Value::Null);
    let event_type = wrapped
        .get("event_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let version = wrapped.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    let payload = wrapped
        .get("payload")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Ok(EventRecord {
        id: row.get(0)?,
        source_agent: row.get(1)?,
        target: row.get(2)?,
        event_type,
        version,
        payload,
        timestamp: row.get(4)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::run_migrations;

    #[test]
    fn appends_monotonic_events_per_target() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        let store = EventStore::new(Arc::new(Mutex::new(conn)));

        let first = store
            .append(
                "agent-a",
                "memory:1",
                "memory.remembered",
                serde_json::json!({"a": 1}),
            )
            .unwrap();
        let second = store
            .append(
                "agent-a",
                "memory:1",
                "memory.forgotten",
                serde_json::json!({"a": 2}),
            )
            .unwrap();

        assert_eq!(first.version, 1);
        assert_eq!(second.version, 2);
        let events = store.list_target("memory:1", 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].event_type, "memory.forgotten");
    }
}
