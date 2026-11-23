//! Knowledge graph backed by SQLite.
//!
//! Stores entities and relations with support for graph pattern queries.

use chrono::Utc;
use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use t3rnel_types::error::{T3rnelError, T3rnelResult};
use t3rnel_types::memory::{Entity, EntityType, GraphMatch, GraphPattern, Relation, RelationType};
use uuid::Uuid;

/// Input for writing a completed-task lesson to the knowledge graph.
#[derive(Debug, Clone)]
pub struct LessonInput {
    pub task_id: String,
    pub summary: String,
    pub outcome: String,
    pub source_agent: Option<String>,
    pub approval_reason: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Knowledge graph store backed by SQLite.
#[derive(Clone)]
pub struct KnowledgeStore {
    conn: Arc<Mutex<Connection>>,
}

impl KnowledgeStore {
    /// Create a new knowledge store wrapping the given connection.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    /// Add an entity to the knowledge graph.
    pub fn add_entity(&self, entity: Entity) -> T3rnelResult<String> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;
        let id = if entity.id.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            entity.id.clone()
        };
        let entity_type_str = serde_json::to_string(&entity.entity_type)
            .map_err(|e| T3rnelError::Serialization(e.to_string()))?;
        let props_str = serde_json::to_string(&entity.properties)
            .map_err(|e| T3rnelError::Serialization(e.to_string()))?;
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO entities (id, entity_type, name, properties, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(id) DO UPDATE SET name = ?3, properties = ?4, updated_at = ?5",
            rusqlite::params![id, entity_type_str, entity.name, props_str, now],
        )
        .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        Ok(id)
    }

    /// Add a relation between two entities.
    pub fn add_relation(&self, relation: Relation) -> T3rnelResult<String> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;
        let id = Uuid::new_v4().to_string();
        let rel_type_str = serde_json::to_string(&relation.relation)
            .map_err(|e| T3rnelError::Serialization(e.to_string()))?;
        let props_str = serde_json::to_string(&relation.properties)
            .map_err(|e| T3rnelError::Serialization(e.to_string()))?;
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO relations (id, source_entity, relation_type, target_entity, properties, confidence, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                id,
                relation.source,
                rel_type_str,
                relation.target,
                props_str,
                relation.confidence as f64,
                now,
            ],
        )
        .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        Ok(id)
    }

    /// Query the knowledge graph with a pattern.
    pub fn query_graph(&self, pattern: GraphPattern) -> T3rnelResult<Vec<GraphMatch>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| T3rnelError::Internal(e.to_string()))?;

        let mut sql = String::from(
            "SELECT
                s.id, s.entity_type, s.name, s.properties, s.created_at, s.updated_at,
                r.id, r.source_entity, r.relation_type, r.target_entity, r.properties, r.confidence, r.created_at,
                t.id, t.entity_type, t.name, t.properties, t.created_at, t.updated_at
             FROM relations r
             JOIN entities s ON r.source_entity = s.id
             JOIN entities t ON r.target_entity = t.id
             WHERE 1=1",
        );
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(ref source) = pattern.source {
            sql.push_str(&format!(" AND (s.id = ?{} OR s.name = ?{})", idx, idx + 1));
            params.push(Box::new(source.clone()));
            params.push(Box::new(source.clone()));
            idx += 2;
        }
        if let Some(ref relation) = pattern.relation {
            let rel_str = serde_json::to_string(relation)
                .map_err(|e| T3rnelError::Serialization(e.to_string()))?;
            sql.push_str(&format!(" AND r.relation_type = ?{idx}"));
            params.push(Box::new(rel_str));
            idx += 1;
        }
        if let Some(ref target) = pattern.target {
            sql.push_str(&format!(" AND (t.id = ?{} OR t.name = ?{})", idx, idx + 1));
            params.push(Box::new(target.clone()));
            params.push(Box::new(target.clone()));
            idx += 2;
        }
        let _ = idx;

        sql.push_str(" LIMIT 100");

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();

        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok(RawGraphRow {
                    s_id: row.get(0)?,
                    s_type: row.get(1)?,
                    s_name: row.get(2)?,
                    s_props: row.get(3)?,
                    s_created: row.get(4)?,
                    s_updated: row.get(5)?,
                    r_id: row.get(6)?,
                    r_source: row.get(7)?,
                    r_type: row.get(8)?,
                    r_target: row.get(9)?,
                    r_props: row.get(10)?,
                    r_confidence: row.get(11)?,
                    r_created: row.get(12)?,
                    t_id: row.get(13)?,
                    t_type: row.get(14)?,
                    t_name: row.get(15)?,
                    t_props: row.get(16)?,
                    t_created: row.get(17)?,
                    t_updated: row.get(18)?,
                })
            })
            .map_err(|e| T3rnelError::Memory(e.to_string()))?;

        let mut matches = Vec::new();
        for row_result in rows {
            let r = row_result.map_err(|e| T3rnelError::Memory(e.to_string()))?;
            matches.push(GraphMatch {
                source: parse_entity(
                    &r.s_id,
                    &r.s_type,
                    &r.s_name,
                    &r.s_props,
                    &r.s_created,
                    &r.s_updated,
                ),
                relation: parse_relation(
                    &r.r_source,
                    &r.r_type,
                    &r.r_target,
                    &r.r_props,
                    r.r_confidence,
                    &r.r_created,
                ),
                target: parse_entity(
                    &r.t_id,
                    &r.t_type,
                    &r.t_name,
                    &r.t_props,
                    &r.t_created,
                    &r.t_updated,
                ),
            });
        }
        Ok(matches)
    }

    /// Write a lesson entity and link it to its task.
    pub fn write_lesson(&self, input: LessonInput) -> T3rnelResult<String> {
        if input.task_id.trim().is_empty() {
            return Err(T3rnelError::InvalidInput(
                "lesson task_id must not be empty".to_string(),
            ));
        }
        if input.summary.trim().is_empty() {
            return Err(T3rnelError::InvalidInput(
                "lesson summary must not be empty".to_string(),
            ));
        }

        let now = Utc::now();
        let mut task_props = HashMap::new();
        task_props.insert(
            "task_id".to_string(),
            serde_json::Value::String(input.task_id.clone()),
        );
        let task_entity = Entity {
            id: format!("task:{}", input.task_id),
            entity_type: EntityType::Ticket,
            name: input.task_id.clone(),
            properties: task_props,
            created_at: now,
            updated_at: now,
        };
        let task_id = self.add_entity(task_entity)?;

        let lesson_id = format!("lesson:{}:{}", input.task_id, Uuid::new_v4());
        let mut lesson_props = input.metadata;
        lesson_props.insert(
            "summary".to_string(),
            serde_json::Value::String(input.summary),
        );
        lesson_props.insert(
            "outcome".to_string(),
            serde_json::Value::String(input.outcome),
        );
        if let Some(source_agent) = input.source_agent {
            lesson_props.insert(
                "source_agent".to_string(),
                serde_json::Value::String(source_agent),
            );
        }
        if let Some(reason) = input.approval_reason {
            lesson_props.insert(
                "approval_reason".to_string(),
                serde_json::Value::String(reason),
            );
        }

        let lesson_entity = Entity {
            id: lesson_id.clone(),
            entity_type: EntityType::Lesson,
            name: format!("Lesson from {}", input.task_id),
            properties: lesson_props,
            created_at: now,
            updated_at: now,
        };
        let written_lesson_id = self.add_entity(lesson_entity)?;
        self.add_relation(Relation {
            source: written_lesson_id.clone(),
            relation: RelationType::References,
            target: task_id,
            properties: HashMap::new(),
            confidence: 1.0,
            created_at: now,
        })?;
        Ok(written_lesson_id)
    }
}

/// Raw row from a graph query.
struct RawGraphRow {
    s_id: String,
    s_type: String,
    s_name: String,
    s_props: String,
    s_created: String,
    s_updated: String,
    r_id: String,
    r_source: String,
    r_type: String,
    r_target: String,
    r_props: String,
    r_confidence: f64,
    r_created: String,
    t_id: String,
    t_type: String,
    t_name: String,
    t_props: String,
    t_created: String,
    t_updated: String,
}

// Suppress the unused field warning — r_id is part of the schema
impl RawGraphRow {
    #[allow(dead_code)]
    fn relation_id(&self) -> &str {
        &self.r_id
    }
}

fn parse_entity(
    id: &str,
    etype: &str,
    name: &str,
    props: &str,
    created: &str,
    updated: &str,
) -> Entity {
    let entity_type: EntityType =
        serde_json::from_str(etype).unwrap_or(EntityType::Custom("unknown".to_string()));
    let properties: HashMap<String, serde_json::Value> =
        serde_json::from_str(props).unwrap_or_default();
    let created_at = chrono::DateTime::parse_from_rfc3339(created)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let updated_at = chrono::DateTime::parse_from_rfc3339(updated)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    Entity {
        id: id.to_string(),
        entity_type,
        name: name.to_string(),
        properties,
        created_at,
        updated_at,
    }
}

fn parse_relation(
    source: &str,
    rtype: &str,
    target: &str,
    props: &str,
    confidence: f64,
    created: &str,
) -> Relation {
    let relation: RelationType = serde_json::from_str(rtype).unwrap_or(RelationType::RelatedTo);
    let properties: HashMap<String, serde_json::Value> =
        serde_json::from_str(props).unwrap_or_default();
    let created_at = chrono::DateTime::parse_from_rfc3339(created)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    Relation {
        source: source.to_string(),
        relation,
        target: target.to_string(),
        properties,
        confidence: confidence as f32,
        created_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::run_migrations;

    fn setup() -> KnowledgeStore {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        KnowledgeStore::new(Arc::new(Mutex::new(conn)))
    }

    #[test]
    fn test_add_and_query_entity() {
        let store = setup();
        let id = store
            .add_entity(Entity {
                id: String::new(),
                entity_type: EntityType::Person,
                name: "Alice".to_string(),
                properties: HashMap::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .unwrap();
        assert!(!id.is_empty());
    }

    #[test]
    fn test_add_relation_and_query() {
        let store = setup();
        let alice_id = store
            .add_entity(Entity {
                id: "alice".to_string(),
                entity_type: EntityType::Person,
                name: "Alice".to_string(),
                properties: HashMap::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .unwrap();
        let company_id = store
            .add_entity(Entity {
                id: "acme".to_string(),
                entity_type: EntityType::Organization,
                name: "Acme Corp".to_string(),
                properties: HashMap::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .unwrap();
        store
            .add_relation(Relation {
                source: alice_id.clone(),
                relation: RelationType::WorksAt,
                target: company_id,
                properties: HashMap::new(),
                confidence: 0.95,
                created_at: Utc::now(),
            })
            .unwrap();

        let matches = store
            .query_graph(GraphPattern {
                source: Some(alice_id),
                relation: Some(RelationType::WorksAt),
                target: None,
                max_depth: 1,
            })
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].target.name, "Acme Corp");
    }

    #[test]
    fn test_phase_one_entity_and_relation_vocabulary_roundtrip() {
        let store = setup();
        let file_id = store
            .add_entity(Entity {
                id: "file:src/lib.rs".to_string(),
                entity_type: EntityType::File,
                name: "src/lib.rs".to_string(),
                properties: HashMap::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .unwrap();
        let error_id = store
            .add_entity(Entity {
                id: "error:E001".to_string(),
                entity_type: EntityType::Error,
                name: "E001".to_string(),
                properties: HashMap::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .unwrap();
        store
            .add_relation(Relation {
                source: file_id.clone(),
                relation: RelationType::Fixes,
                target: error_id,
                properties: HashMap::new(),
                confidence: 1.0,
                created_at: Utc::now(),
            })
            .unwrap();

        let matches = store
            .query_graph(GraphPattern {
                source: Some(file_id),
                relation: Some(RelationType::Fixes),
                target: None,
                max_depth: 1,
            })
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].source.entity_type, EntityType::File);
        assert_eq!(matches[0].relation.relation, RelationType::Fixes);
        assert_eq!(matches[0].target.entity_type, EntityType::Error);
    }

    #[test]
    fn test_write_lesson_links_to_task() {
        let store = setup();
        let lesson_id = store
            .write_lesson(LessonInput {
                task_id: "task-123".to_string(),
                summary: "Use targeted tests before broad suites.".to_string(),
                outcome: "Subsequent validation completed faster.".to_string(),
                source_agent: Some("reviewer".to_string()),
                approval_reason: Some("Accepted low-risk patch.".to_string()),
                metadata: HashMap::new(),
            })
            .unwrap();

        let matches = store
            .query_graph(GraphPattern {
                source: Some(lesson_id),
                relation: Some(RelationType::References),
                target: Some("task-123".to_string()),
                max_depth: 1,
            })
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].source.entity_type, EntityType::Lesson);
        assert_eq!(matches[0].target.entity_type, EntityType::Ticket);
        assert_eq!(
            matches[0].source.properties["approval_reason"],
            serde_json::Value::String("Accepted low-risk patch.".to_string())
        );
    }
}
