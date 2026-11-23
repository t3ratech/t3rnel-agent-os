//! Durable team store for agent grouping, task progress, and A2A messaging.
//!
//! Team metadata and task state live in the shared SQLite memory database.
//! A2A payloads are encrypted before storage with a local AES-GCM data key so
//! plaintext messages never rest in SQLite.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};

const SOFTWARE_TEAM_ID: &str = "software-engineering";
const SOFTWARE_TEAM_NAME: &str = "Software Engineering";
const A2A_NONCE_LEN: usize = 12;
const DEFAULT_LIST_LIMIT: usize = 50;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Team {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub created_at: String,
    pub updated_at: String,
    pub member_ids: Vec<String>,
    pub config: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeamMember {
    pub team_id: String,
    pub agent_id: String,
    pub role_tag: String,
    pub joined_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TeamTask {
    pub id: String,
    pub team_id: String,
    pub title: String,
    pub description: String,
    pub status: String,
    pub assignee_id: Option<String>,
    pub percent: u8,
    pub current_step: u32,
    pub total_steps: u32,
    pub blockers: Vec<String>,
    pub priority: String,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct A2aMessage {
    pub id: String,
    pub team_id: String,
    pub sender_id: String,
    pub recipient_id: String,
    pub msg_type: String,
    pub payload: serde_json::Value,
    pub timestamp: String,
    pub sequence: u64,
    pub trace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

#[derive(Clone)]
pub struct TeamStore {
    conn: Arc<Mutex<Connection>>,
    a2a_key: Arc<[u8; 32]>,
    events: tokio::sync::broadcast::Sender<A2aMessage>,
}

impl TeamStore {
    pub fn new() -> Self {
        let conn = Arc::new(Mutex::new(
            Connection::open_in_memory().expect("failed to create in-memory team store database"),
        ));
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self::from_key(conn, key).expect("failed to initialize in-memory team store")
    }

    pub fn persistent(conn: Arc<Mutex<Connection>>, key_path: &Path) -> Result<Self, String> {
        let key = load_or_create_data_key(key_path)?;
        Self::from_key(conn, key)
    }

    fn from_key(conn: Arc<Mutex<Connection>>, key: [u8; 32]) -> Result<Self, String> {
        let (events, _) = tokio::sync::broadcast::channel(512);
        let store = Self {
            conn,
            a2a_key: Arc::new(key),
            events,
        };
        store.ensure_schema()?;
        store.seed_software_engineering_team()?;
        Ok(store)
    }

    pub fn list_teams(&self) -> Result<Vec<Team>, String> {
        let db = self.lock_conn()?;
        let mut stmt = db
            .prepare(
                "SELECT id, name, kind, created_at, updated_at, config_json
                 FROM teams
                 ORDER BY kind DESC, name ASC",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(db_err)?;

        let mut teams = Vec::new();
        for row in rows {
            let (id, name, kind, created_at, updated_at, config_json) = row.map_err(db_err)?;
            teams.push(Team {
                member_ids: Self::member_ids_locked(&db, &id)?,
                config: parse_json(&config_json, "team config")?,
                id,
                name,
                kind,
                created_at,
                updated_at,
            });
        }
        Ok(teams)
    }

    pub fn get_team(&self, id: &str) -> Result<Option<Team>, String> {
        let db = self.lock_conn()?;
        let row = db
            .query_row(
                "SELECT id, name, kind, created_at, updated_at, config_json
                 FROM teams
                 WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(db_err)?;

        row.map(|(id, name, kind, created_at, updated_at, config_json)| {
            Ok(Team {
                member_ids: Self::member_ids_locked(&db, &id)?,
                config: parse_json(&config_json, "team config")?,
                id,
                name,
                kind,
                created_at,
                updated_at,
            })
        })
        .transpose()
    }

    pub fn create_team(
        &self,
        id: &str,
        name: &str,
        kind: &str,
        config: serde_json::Value,
    ) -> Result<Team, String> {
        let id = normalize_identifier(id, "team id")?;
        let name = normalize_required(name, "team name")?;
        let kind = normalize_team_kind(kind)?;
        let now = chrono::Utc::now().to_rfc3339();
        let config_json = serde_json::to_string(&config).map_err(json_err)?;
        let db = self.lock_conn()?;
        db.execute(
            "INSERT INTO teams (id, name, kind, created_at, updated_at, config_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, name, kind, now, now, config_json],
        )
        .map_err(db_err)?;
        append_team_event_locked(
            &db,
            "team-store",
            &format!("team:{id}"),
            "team.created",
            serde_json::json!({
                "team_id": id.clone(),
                "name": name.clone(),
                "kind": kind.clone(),
            }),
        )?;
        Ok(Team {
            id,
            name,
            kind,
            created_at: now.clone(),
            updated_at: now,
            member_ids: Vec::new(),
            config,
        })
    }

    pub fn update_team(
        &self,
        id: &str,
        name: Option<&str>,
        kind: Option<&str>,
        config: Option<serde_json::Value>,
    ) -> Result<Option<Team>, String> {
        let Some(existing) = self.get_team(id)? else {
            return Ok(None);
        };
        let name = match name {
            Some(value) => normalize_required(value, "team name")?,
            None => existing.name,
        };
        let kind = match kind {
            Some(value) => normalize_team_kind(value)?,
            None => existing.kind,
        };
        let config = config.unwrap_or(existing.config);
        let updated_at = chrono::Utc::now().to_rfc3339();
        let config_json = serde_json::to_string(&config).map_err(json_err)?;
        let db = self.lock_conn()?;
        db.execute(
            "UPDATE teams
             SET name = ?2, kind = ?3, config_json = ?4, updated_at = ?5
             WHERE id = ?1",
            params![id, name, kind, config_json, updated_at],
        )
        .map_err(db_err)?;
        append_team_event_locked(
            &db,
            "team-store",
            &format!("team:{id}"),
            "team.updated",
            serde_json::json!({
                "team_id": id,
                "name": name.clone(),
                "kind": kind.clone(),
            }),
        )?;
        drop(db);
        self.get_team(id)
    }

    pub fn delete_team(&self, id: &str) -> Result<bool, String> {
        let db = self.lock_conn()?;
        let deleted = db
            .execute("DELETE FROM teams WHERE id = ?1", params![id])
            .map_err(db_err)?;
        if deleted == 0 {
            return Ok(false);
        }
        db.execute("DELETE FROM team_members WHERE team_id = ?1", params![id])
            .map_err(db_err)?;
        db.execute("DELETE FROM team_tasks WHERE team_id = ?1", params![id])
            .map_err(db_err)?;
        db.execute("DELETE FROM a2a_messages WHERE team_id = ?1", params![id])
            .map_err(db_err)?;
        append_team_event_locked(
            &db,
            "team-store",
            &format!("team:{id}"),
            "team.deleted",
            serde_json::json!({ "team_id": id }),
        )?;
        Ok(true)
    }

    pub fn list_members(&self, team_id: &str) -> Result<Vec<TeamMember>, String> {
        let db = self.lock_conn()?;
        let mut stmt = db
            .prepare(
                "SELECT team_id, agent_id, role_tag, joined_at
                 FROM team_members
                 WHERE team_id = ?1
                 ORDER BY joined_at ASC, agent_id ASC",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![team_id], |row| {
                Ok(TeamMember {
                    team_id: row.get(0)?,
                    agent_id: row.get(1)?,
                    role_tag: row.get(2)?,
                    joined_at: row.get(3)?,
                })
            })
            .map_err(db_err)?;
        let mut members = Vec::new();
        for row in rows {
            members.push(row.map_err(db_err)?);
        }
        Ok(members)
    }

    pub fn upsert_member(
        &self,
        team_id: &str,
        agent_id: &str,
        role_tag: &str,
    ) -> Result<Option<TeamMember>, String> {
        if self.get_team(team_id)?.is_none() {
            return Ok(None);
        }
        let agent_id = normalize_identifier(agent_id, "agent id")?;
        let role_tag = normalize_role_tag(role_tag)?;
        let now = chrono::Utc::now().to_rfc3339();
        let db = self.lock_conn()?;
        db.execute(
            "INSERT INTO team_members (team_id, agent_id, role_tag, joined_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(team_id, agent_id) DO UPDATE SET role_tag = excluded.role_tag",
            params![team_id, agent_id, role_tag, now],
        )
        .map_err(db_err)?;
        append_team_event_locked(
            &db,
            "team-store",
            &format!("team:{team_id}"),
            "team.member_upserted",
            serde_json::json!({
                "team_id": team_id,
                "agent_id": agent_id.clone(),
                "role_tag": role_tag.clone(),
            }),
        )?;
        Ok(Some(TeamMember {
            team_id: team_id.to_string(),
            agent_id,
            role_tag,
            joined_at: now,
        }))
    }

    pub fn remove_member(&self, team_id: &str, agent_id: &str) -> Result<bool, String> {
        let db = self.lock_conn()?;
        let deleted = db
            .execute(
                "DELETE FROM team_members WHERE team_id = ?1 AND agent_id = ?2",
                params![team_id, agent_id],
            )
            .map_err(db_err)?;
        if deleted > 0 {
            append_team_event_locked(
                &db,
                "team-store",
                &format!("team:{team_id}"),
                "team.member_removed",
                serde_json::json!({
                    "team_id": team_id,
                    "agent_id": agent_id,
                }),
            )?;
        }
        Ok(deleted > 0)
    }

    pub fn list_tasks(&self, team_id: Option<&str>) -> Result<Vec<TeamTask>, String> {
        let db = self.lock_conn()?;
        let mut tasks = Vec::new();
        if let Some(team_id) = team_id {
            let mut stmt = db
                .prepare(
                    "SELECT id, team_id, title, description, status, assignee_id, percent,
                            current_step, total_steps, blockers_json, created_at, updated_at,
                            priority, completed_at
                     FROM team_tasks
                     WHERE team_id = ?1
                     ORDER BY CASE WHEN status IN ('completed', 'done', 'cancelled', 'failed') THEN 1 ELSE 0 END,
                              CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                              updated_at DESC, id ASC",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map(params![team_id], team_task_from_row)
                .map_err(db_err)?;
            for row in rows {
                tasks.push(row.map_err(db_err)?);
            }
        } else {
            let mut stmt = db
                .prepare(
                    "SELECT id, team_id, title, description, status, assignee_id, percent,
                            current_step, total_steps, blockers_json, created_at, updated_at,
                            priority, completed_at
                     FROM team_tasks
                     ORDER BY CASE WHEN status IN ('completed', 'done', 'cancelled', 'failed') THEN 1 ELSE 0 END,
                              CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 WHEN 'normal' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                              updated_at DESC, id ASC",
                )
                .map_err(db_err)?;
            let rows = stmt.query_map([], team_task_from_row).map_err(db_err)?;
            for row in rows {
                tasks.push(row.map_err(db_err)?);
            }
        }
        Ok(tasks)
    }

    pub fn get_task(&self, id: &str) -> Result<Option<TeamTask>, String> {
        let db = self.lock_conn()?;
        db.query_row(
            "SELECT id, team_id, title, description, status, assignee_id, percent,
                    current_step, total_steps, blockers_json, created_at, updated_at,
                    priority, completed_at
             FROM team_tasks
             WHERE id = ?1",
            params![id],
            team_task_from_row,
        )
        .optional()
        .map_err(db_err)
    }

    pub fn create_task_assignment(
        &self,
        team_id: &str,
        title: &str,
        description: &str,
        assignee_id: &str,
        blockers: Vec<String>,
    ) -> Result<TeamTask, String> {
        self.create_task_assignment_with_priority(
            team_id,
            title,
            description,
            assignee_id,
            blockers,
            "normal",
        )
    }

    pub fn create_task_assignment_with_priority(
        &self,
        team_id: &str,
        title: &str,
        description: &str,
        assignee_id: &str,
        blockers: Vec<String>,
        priority: &str,
    ) -> Result<TeamTask, String> {
        if self.get_team(team_id)?.is_none() {
            return Err(format!("team not found: {team_id}"));
        }
        let title = normalize_required(title, "task title")?;
        let description = if description.trim().is_empty() {
            title.clone()
        } else {
            description.trim().to_string()
        };
        let assignee_id = normalize_identifier(assignee_id, "assignee id")?;
        let priority = normalize_task_priority(priority)?;
        let now = chrono::Utc::now().to_rfc3339();
        let status = if blockers.is_empty() {
            "in_progress"
        } else {
            "blocked"
        };
        let task = TeamTask {
            id: format!("task-{}", uuid::Uuid::new_v4()),
            team_id: team_id.to_string(),
            title,
            description,
            status: status.to_string(),
            assignee_id: Some(assignee_id),
            percent: if blockers.is_empty() { 10 } else { 0 },
            current_step: if blockers.is_empty() { 1 } else { 0 },
            total_steps: 10,
            blockers,
            priority,
            created_at: now.clone(),
            updated_at: now.clone(),
            completed_at: None,
        };
        self.upsert_task(&task, &now)?;
        Ok(task)
    }

    pub fn save_task(&self, task: &mut TeamTask) -> Result<TeamTask, String> {
        task.priority = normalize_task_priority(&task.priority)?;
        task.percent = task.percent.min(100);
        task.current_step = task.current_step.min(task.total_steps.max(1));
        task.total_steps = task.total_steps.max(1);
        let now = chrono::Utc::now().to_rfc3339();
        task.updated_at = now.clone();
        if is_terminal_task_status(&task.status) {
            task.percent = 100;
            task.current_step = task.total_steps;
            if task.completed_at.is_none() {
                task.completed_at = Some(now.clone());
            }
            task.blockers.clear();
        } else {
            task.completed_at = None;
        }
        self.upsert_task(task, &now)?;
        Ok(task.clone())
    }

    pub fn finish_task(
        &self,
        team_id: &str,
        task_id: &str,
        status: &str,
    ) -> Result<Option<TeamTask>, String> {
        let Some(mut task) = self.get_task(task_id)? else {
            return Ok(None);
        };
        if task.team_id != team_id {
            return Ok(None);
        }
        task.status = status.to_string();
        if matches!(status, "completed" | "done" | "cancelled" | "failed") {
            task.percent = 100;
            task.current_step = task.total_steps.max(1);
            task.completed_at = Some(chrono::Utc::now().to_rfc3339());
        } else {
            task.completed_at = None;
        }
        task.blockers.clear();
        task.updated_at = chrono::Utc::now().to_rfc3339();
        self.upsert_task(&task, &task.updated_at)?;
        Ok(Some(task))
    }

    pub fn finish_all_tasks(&self, team_id: &str, status: &str) -> Result<Vec<TeamTask>, String> {
        let tasks = self.list_tasks(Some(team_id))?;
        let mut finished = Vec::new();
        for task in tasks {
            if matches!(
                task.status.as_str(),
                "completed" | "done" | "cancelled" | "failed"
            ) {
                finished.push(task);
                continue;
            }
            if let Some(task) = self.finish_task(team_id, &task.id, status)? {
                finished.push(task);
            }
        }
        Ok(finished)
    }

    pub fn list_messages(
        &self,
        team_id: &str,
        since: Option<&str>,
        limit: usize,
    ) -> Result<Vec<A2aMessage>, String> {
        let db = self.lock_conn()?;
        let limit = limit.clamp(1, 500);
        let mut messages = Vec::new();
        if let Some(since) = since {
            let mut stmt = db
                .prepare(
                    "SELECT id, team_id, sender_id, recipient_id, msg_type, payload_ciphertext,
                            timestamp, sequence, trace_id, task_id
                     FROM a2a_messages
                     WHERE team_id = ?1 AND timestamp >= ?2
                     ORDER BY timestamp ASC, sequence ASC
                     LIMIT ?3",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map(params![team_id, since, limit as i64], |row| {
                    self.message_from_row(row)
                })
                .map_err(db_err)?;
            for row in rows {
                messages.push(row.map_err(db_err)?);
            }
        } else {
            let mut stmt = db
                .prepare(
                    "SELECT id, team_id, sender_id, recipient_id, msg_type, payload_ciphertext,
                            timestamp, sequence, trace_id, task_id
                     FROM (
                         SELECT id, team_id, sender_id, recipient_id, msg_type, payload_ciphertext,
                                timestamp, sequence, trace_id, task_id
                         FROM a2a_messages
                         WHERE team_id = ?1
                         ORDER BY timestamp DESC, sequence DESC
                         LIMIT ?2
                     )
                     ORDER BY timestamp ASC, sequence ASC",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map(params![team_id, limit as i64], |row| {
                    self.message_from_row(row)
                })
                .map_err(db_err)?;
            for row in rows {
                messages.push(row.map_err(db_err)?);
            }
        }
        Ok(messages)
    }

    pub fn add_message(&self, mut msg: A2aMessage, marker: &str) -> Result<(), String> {
        msg.payload = sanitize_private_json(&msg.payload);
        let payload_ciphertext = self.encrypt_payload(&msg.payload)?;
        let db = self.lock_conn()?;
        db.execute(
            "INSERT INTO a2a_messages (
                id, team_id, sender_id, recipient_id, msg_type, payload_ciphertext,
                timestamp, sequence, marker, trace_id, task_id
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                msg.id,
                msg.team_id,
                msg.sender_id,
                msg.recipient_id,
                msg.msg_type,
                payload_ciphertext,
                msg.timestamp,
                msg.sequence as i64,
                marker,
                msg.trace_id,
                msg.task_id,
            ],
        )
        .map_err(db_err)?;
        append_team_event_locked(
            &db,
            &msg.sender_id,
            &format!("team:{}", msg.team_id),
            "a2a.message_added",
            serde_json::json!({
                "message_id": msg.id.clone(),
                "team_id": msg.team_id.clone(),
                "sender_id": msg.sender_id.clone(),
                "recipient_id": msg.recipient_id.clone(),
                "msg_type": msg.msg_type.clone(),
                "sequence": msg.sequence,
                "trace_id": msg.trace_id.clone(),
                "task_id": msg.task_id.clone(),
            }),
        )?;
        let _ = self.events.send(msg);
        Ok(())
    }

    /// Atomically check fanout limit and add message if under limit.
    /// Returns `Ok(true)` if added, `Ok(false)` if limit exceeded.
    pub fn add_message_with_fanout_limit(
        &self,
        mut msg: A2aMessage,
        marker: &str,
        msg_type: &str,
        limit: usize,
    ) -> Result<bool, String> {
        msg.payload = sanitize_private_json(&msg.payload);
        let payload_ciphertext = self.encrypt_payload(&msg.payload)?;
        let db = self.lock_conn()?;
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM a2a_messages WHERE team_id = ?1 AND marker = ?2 AND msg_type = ?3",
                params![msg.team_id, marker, msg_type],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        if count.max(0) as usize >= limit {
            return Ok(false);
        }
        db.execute(
            "INSERT INTO a2a_messages (
                id, team_id, sender_id, recipient_id, msg_type, payload_ciphertext,
                timestamp, sequence, marker, trace_id, task_id
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                msg.id,
                msg.team_id,
                msg.sender_id,
                msg.recipient_id,
                msg.msg_type,
                payload_ciphertext,
                msg.timestamp,
                msg.sequence as i64,
                marker,
                msg.trace_id,
                msg.task_id,
            ],
        )
        .map_err(db_err)?;
        append_team_event_locked(
            &db,
            &msg.sender_id,
            &format!("team:{}", msg.team_id),
            "a2a.message_added",
            serde_json::json!({
                "message_id": msg.id.clone(),
                "team_id": msg.team_id.clone(),
                "sender_id": msg.sender_id.clone(),
                "recipient_id": msg.recipient_id.clone(),
                "msg_type": msg.msg_type.clone(),
                "sequence": msg.sequence,
                "trace_id": msg.trace_id.clone(),
                "task_id": msg.task_id.clone(),
            }),
        )?;
        let _ = self.events.send(msg);
        Ok(true)
    }

    pub fn next_sequence(&self, team_id: &str) -> Result<u64, String> {
        let db = self.lock_conn()?;
        let seq: i64 = db
            .query_row(
                "SELECT COALESCE(MAX(sequence), -1) + 1 FROM a2a_messages WHERE team_id = ?1",
                params![team_id],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(seq.max(0) as u64)
    }

    pub fn count_marker_messages(
        &self,
        team_id: &str,
        marker: &str,
        msg_type: &str,
    ) -> Result<usize, String> {
        let db = self.lock_conn()?;
        let count: i64 = db
            .query_row(
                "SELECT COUNT(*)
                 FROM a2a_messages
                 WHERE team_id = ?1 AND marker = ?2 AND msg_type = ?3",
                params![team_id, marker, msg_type],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(count.max(0) as usize)
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<A2aMessage> {
        self.events.subscribe()
    }

    fn upsert_task(&self, task: &TeamTask, now: &str) -> Result<(), String> {
        let blockers_json = serde_json::to_string(&task.blockers).map_err(json_err)?;
        let db = self.lock_conn()?;
        db.execute(
            "INSERT INTO team_tasks (
                id, team_id, title, description, status, assignee_id, percent,
                current_step, total_steps, blockers_json, created_at, updated_at,
                priority, completed_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(id) DO UPDATE SET
                title = excluded.title,
                description = excluded.description,
                status = excluded.status,
                assignee_id = excluded.assignee_id,
                percent = excluded.percent,
                current_step = excluded.current_step,
                total_steps = excluded.total_steps,
                blockers_json = excluded.blockers_json,
                updated_at = excluded.updated_at,
                priority = excluded.priority,
                completed_at = excluded.completed_at",
            params![
                task.id,
                task.team_id,
                task.title,
                task.description,
                task.status,
                task.assignee_id,
                task.percent as i64,
                task.current_step as i64,
                task.total_steps as i64,
                blockers_json,
                now,
                task.updated_at,
                task.priority,
                task.completed_at,
            ],
        )
        .map_err(db_err)?;
        append_team_event_locked(
            &db,
            task.assignee_id.as_deref().unwrap_or("team-store"),
            &format!("team_task:{}", task.id),
            "team.task_upserted",
            serde_json::json!({
                "task_id": task.id.clone(),
                "team_id": task.team_id.clone(),
                "status": task.status.clone(),
                "assignee_id": task.assignee_id.clone(),
                "percent": task.percent,
                "priority": task.priority.clone(),
                "current_step": task.current_step,
                "total_steps": task.total_steps,
                "completed_at": task.completed_at.clone(),
            }),
        )?;
        Ok(())
    }

    fn seed_software_engineering_team(&self) -> Result<(), String> {
        let now = chrono::Utc::now().to_rfc3339();
        let config = serde_json::json!({
            "description": "Permanent software engineering team building the T3rnel platform",
            "goal": "Build, test, review, secure, document, and ship software end to end"
        });
        let config_json = serde_json::to_string(&config).map_err(json_err)?;
        let members = software_engineering_members();
        {
            let db = self.lock_conn()?;
            db.execute(
                "INSERT INTO teams (id, name, kind, created_at, updated_at, config_json)
                 VALUES (?1, ?2, 'permanent', ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    kind = excluded.kind,
                    updated_at = excluded.updated_at,
                    config_json = excluded.config_json",
                params![SOFTWARE_TEAM_ID, SOFTWARE_TEAM_NAME, now, now, config_json],
            )
            .map_err(db_err)?;
            for (agent_id, role_tag) in members {
                db.execute(
                    "INSERT INTO team_members (team_id, agent_id, role_tag, joined_at)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(team_id, agent_id) DO UPDATE SET role_tag = excluded.role_tag",
                    params![SOFTWARE_TEAM_ID, agent_id, role_tag, now],
                )
                .map_err(db_err)?;
            }
        }

        if self.get_task("task-frontend-ui")?.is_none() {
            let task = TeamTask {
                id: "task-frontend-ui".to_string(),
                team_id: SOFTWARE_TEAM_ID.to_string(),
                title: "Build the frontend UI for the Control Center".to_string(),
                description: "Implement team progress, A2A streams, approvals, and cross-surface parity in the web and Windsurf surfaces.".to_string(),
                status: "in_progress".to_string(),
                assignee_id: Some("frontend-builder".to_string()),
                percent: 65,
                current_step: 13,
                total_steps: 20,
                blockers: Vec::new(),
                priority: "normal".to_string(),
                created_at: now.clone(),
                updated_at: now.clone(),
                completed_at: None,
            };
            self.upsert_task(&task, &now)?;
        }
        Ok(())
    }

    fn ensure_schema(&self) -> Result<(), String> {
        let db = self.lock_conn()?;
        db.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS teams (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('permanent', 'ephemeral')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                config_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS team_members (
                team_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                role_tag TEXT NOT NULL DEFAULT '',
                joined_at TEXT NOT NULL,
                PRIMARY KEY (team_id, agent_id)
            );
            CREATE TABLE IF NOT EXISTS team_tasks (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL,
                assignee_id TEXT,
                percent INTEGER NOT NULL DEFAULT 0,
                current_step INTEGER NOT NULL DEFAULT 0,
                total_steps INTEGER NOT NULL DEFAULT 1,
                blockers_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                priority TEXT NOT NULL DEFAULT 'normal',
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS a2a_messages (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                msg_type TEXT NOT NULL,
                payload_ciphertext TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                marker TEXT NOT NULL DEFAULT '',
                trace_id TEXT NOT NULL,
                task_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_a2a_messages_marker ON a2a_messages(team_id, marker, msg_type);
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                source_agent TEXT NOT NULL,
                target TEXT NOT NULL,
                payload BLOB NOT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_source ON events(source_agent);
            ",
        )
        .map_err(db_err)?;
        ensure_column_locked(
            &db,
            "team_tasks",
            "priority",
            "TEXT NOT NULL DEFAULT 'normal'",
        )?;
        ensure_column_locked(&db, "team_tasks", "completed_at", "TEXT")?;
        Ok(())
    }

    fn lock_conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>, String> {
        self.conn
            .lock()
            .map_err(|e| format!("team store SQLite mutex poisoned: {e}"))
    }

    fn member_ids_locked(db: &Connection, team_id: &str) -> Result<Vec<String>, String> {
        let mut stmt = db
            .prepare(
                "SELECT agent_id
                 FROM team_members
                 WHERE team_id = ?1
                 ORDER BY joined_at ASC, agent_id ASC",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![team_id], |row| row.get::<_, String>(0))
            .map_err(db_err)?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row.map_err(db_err)?);
        }
        Ok(ids)
    }

    fn encrypt_payload(&self, payload: &serde_json::Value) -> Result<String, String> {
        let plaintext = serde_json::to_vec(payload).map_err(json_err)?;
        let cipher = Aes256Gcm::new_from_slice(self.a2a_key.as_ref())
            .map_err(|e| format!("failed to initialize A2A payload cipher: {e:?}"))?;
        let mut nonce_bytes = [0u8; A2A_NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .map_err(|e| format!("failed to encrypt A2A payload: {e:?}"))?;
        let mut envelope = Vec::with_capacity(A2A_NONCE_LEN + ciphertext.len());
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        Ok(base64::engine::general_purpose::STANDARD.encode(envelope))
    }

    fn decrypt_payload(&self, ciphertext: &str) -> Result<serde_json::Value, String> {
        let envelope = base64::engine::general_purpose::STANDARD
            .decode(ciphertext)
            .map_err(|e| format!("invalid encrypted A2A payload: {e}"))?;
        if envelope.len() <= A2A_NONCE_LEN {
            return Err("invalid encrypted A2A payload: missing ciphertext".to_string());
        }
        let (nonce, body) = envelope.split_at(A2A_NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(self.a2a_key.as_ref())
            .map_err(|e| format!("failed to initialize A2A payload cipher: {e:?}"))?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), body)
            .map_err(|e| format!("failed to decrypt A2A payload: {e:?}"))?;
        serde_json::from_slice(&plaintext).map_err(json_err)
    }

    fn message_from_row(&self, row: &rusqlite::Row<'_>) -> rusqlite::Result<A2aMessage> {
        let payload_ciphertext: String = row.get(5)?;
        let payload = self.decrypt_payload(&payload_ciphertext).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            )
        })?;
        let sequence: i64 = row.get(7)?;
        Ok(A2aMessage {
            id: row.get(0)?,
            team_id: row.get(1)?,
            sender_id: row.get(2)?,
            recipient_id: row.get(3)?,
            msg_type: row.get(4)?,
            payload,
            timestamp: row.get(6)?,
            sequence: sequence.max(0) as u64,
            trace_id: row.get(8)?,
            task_id: row.get(9)?,
        })
    }
}

impl Default for TeamStore {
    fn default() -> Self {
        Self::new()
    }
}

fn team_task_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TeamTask> {
    let blockers_json: String = row.get(9)?;
    let blockers = serde_json::from_str::<Vec<String>>(&blockers_json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let percent: i64 = row.get(6)?;
    let current_step: i64 = row.get(7)?;
    let total_steps: i64 = row.get(8)?;
    Ok(TeamTask {
        id: row.get(0)?,
        team_id: row.get(1)?,
        title: row.get(2)?,
        description: row.get(3)?,
        status: row.get(4)?,
        assignee_id: row.get(5)?,
        percent: percent.clamp(0, 100) as u8,
        current_step: current_step.max(0) as u32,
        total_steps: total_steps.max(1) as u32,
        blockers,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
        priority: row.get(12)?,
        completed_at: row.get(13)?,
    })
}

fn normalize_identifier(value: &str, label: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} is required"));
    }
    if trimmed.len() > 120 {
        return Err(format!("{label} must be 120 characters or fewer"));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(format!(
            "{label} may only contain letters, numbers, dots, dashes, and underscores"
        ));
    }
    Ok(trimmed.to_string())
}

fn normalize_required(value: &str, label: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} is required"));
    }
    if trimmed.len() > 240 {
        return Err(format!("{label} must be 240 characters or fewer"));
    }
    Ok(trimmed.to_string())
}

fn normalize_team_kind(value: &str) -> Result<String, String> {
    match value.trim() {
        "permanent" => Ok("permanent".to_string()),
        "ephemeral" => Ok("ephemeral".to_string()),
        other => Err(format!(
            "team kind must be 'permanent' or 'ephemeral', got '{other}'"
        )),
    }
}

fn normalize_role_tag(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok("member".to_string());
    }
    if trimmed.len() > 80 {
        return Err("role tag must be 80 characters or fewer".to_string());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ' '))
    {
        return Err(
            "role tag may only contain letters, numbers, spaces, dashes, and underscores"
                .to_string(),
        );
    }
    Ok(trimmed.replace(' ', "_").to_ascii_lowercase())
}

fn normalize_task_priority(value: &str) -> Result<String, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "urgent" => Ok("urgent".to_string()),
        "high" => Ok("high".to_string()),
        "" | "normal" => Ok("normal".to_string()),
        "low" => Ok("low".to_string()),
        other => Err(format!(
            "task priority must be urgent, high, normal, or low, got '{other}'"
        )),
    }
}

fn is_terminal_task_status(status: &str) -> bool {
    matches!(status, "completed" | "done" | "cancelled" | "failed")
}

fn ensure_column_locked(
    db: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), String> {
    let mut stmt = db
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(db_err)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(db_err)?;
    for row in rows {
        if row.map_err(db_err)? == column {
            return Ok(());
        }
    }
    db.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )
    .map_err(db_err)?;
    Ok(())
}

fn software_engineering_members() -> Vec<(&'static str, &'static str)> {
    vec![
        ("t3rnel", "orchestrator"),
        ("architect", "architect"),
        ("project-manager", "project_manager"),
        ("researcher", "researcher"),
        ("backend-builder", "backend_builder"),
        ("frontend-builder", "frontend_builder"),
        ("coder", "coder"),
        ("reviewer", "reviewer"),
        ("security-auditor", "security_auditor"),
        ("test-engineer", "test_engineer"),
        ("qa-engineer", "qa_engineer"),
        ("ui-ux-designer", "ui_ux_designer"),
        ("devops-lead", "devops_lead"),
        ("data-scientist", "data_scientist"),
        ("doc-writer", "doc_writer"),
        ("release-manager", "release_manager"),
        ("browser-hand", "browser_hand"),
    ]
}

fn load_or_create_data_key(path: &Path) -> Result<[u8; 32], String> {
    if path.exists() {
        let encoded = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read A2A data key {}: {e}", path.display()))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|e| format!("invalid A2A data key {}: {e}", path.display()))?;
        if bytes.len() != 32 {
            return Err(format!(
                "invalid A2A data key {}: expected 32 bytes, got {}",
                path.display(),
                bytes.len()
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create A2A data-key directory {}: {e}",
                parent.display()
            )
        })?;
    }
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let encoded = base64::engine::general_purpose::STANDARD.encode(key);
    std::fs::write(path, encoded)
        .map_err(|e| format!("failed to write A2A data key {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to restrict A2A data key {}: {e}", path.display()))?;
    }
    Ok(key)
}

fn parse_json(value: &str, label: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(value).map_err(|e| format!("invalid {label} JSON in SQLite: {e}"))
}

fn db_err(error: rusqlite::Error) -> String {
    format!("team store SQLite error: {error}")
}

fn json_err(error: serde_json::Error) -> String {
    format!("team store JSON error: {error}")
}

fn append_team_event_locked(
    db: &Connection,
    source_agent: &str,
    target: &str,
    event_type: &str,
    payload: serde_json::Value,
) -> Result<(), String> {
    let version: i64 = db
        .query_row(
            "SELECT COUNT(*) + 1 FROM events WHERE target = ?1",
            params![target],
            |row| row.get(0),
        )
        .map_err(db_err)?;
    let wrapped = serde_json::json!({
        "event_type": event_type,
        "version": version.max(1),
        "payload": payload,
    });
    let payload = serde_json::to_vec(&wrapped).map_err(json_err)?;
    db.execute(
        "INSERT INTO events (id, source_agent, target, payload, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            uuid::Uuid::new_v4().to_string(),
            source_agent,
            target,
            payload,
            chrono::Utc::now().to_rfc3339(),
        ],
    )
    .map_err(db_err)?;
    Ok(())
}

fn sanitize_private_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) => serde_json::Value::String(strip_private_tags(text)),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(sanitize_private_json).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), sanitize_private_json(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn strip_private_tags(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    while let Some((start, start_end)) = find_private_start(input, cursor) {
        output.push_str(&input[cursor..start]);
        if let Some((_, end_end)) = find_case_insensitive(input, "</private>", start_end) {
            cursor = end_end;
        } else {
            cursor = input.len();
            break;
        }
    }
    if cursor < input.len() {
        output.push_str(&input[cursor..]);
    }
    output
}

fn find_private_start(input: &str, from: usize) -> Option<(usize, usize)> {
    let (start, _) = find_case_insensitive(input, "<private", from)?;
    let tag_tail = &input[start..];
    let close_rel = tag_tail.find('>')?;
    Some((start, start + close_rel + 1))
}

fn find_case_insensitive(input: &str, needle: &str, from: usize) -> Option<(usize, usize)> {
    if from >= input.len() {
        return None;
    }
    let haystack = input[from..].to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    let rel = haystack.find(&needle)?;
    let start = from + rel;
    Some((start, start + needle.len()))
}

#[allow(dead_code)]
pub fn default_list_limit() -> usize {
    DEFAULT_LIST_LIMIT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_load_persist_encrypts_messages_and_restores_tasks() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("teams.sqlite");
        let key_path = tmp.path().join("a2a-payload.key");
        let task_id;

        {
            let conn = Arc::new(Mutex::new(
                Connection::open(&db_path).expect("open team store database"),
            ));
            let store =
                TeamStore::persistent(conn.clone(), &key_path).expect("create persistent store");

            let team = store
                .get_team(SOFTWARE_TEAM_ID)
                .expect("load team")
                .expect("seeded software team");
            assert!(team.member_ids.contains(&"t3rnel".to_string()));
            assert!(team.member_ids.contains(&"coder".to_string()));

            let task = store
                .create_task_assignment(
                    SOFTWARE_TEAM_ID,
                    "Persist task",
                    "Verify task state survives a store reload",
                    "coder",
                    vec![],
                )
                .expect("create task");
            task_id = task.id.clone();

            let message = A2aMessage {
                id: "msg-persist".to_string(),
                team_id: SOFTWARE_TEAM_ID.to_string(),
                sender_id: "t3rnel".to_string(),
                recipient_id: "coder".to_string(),
                msg_type: "question".to_string(),
                payload: serde_json::json!({
                    "content": "shared-secret",
                    "marker": "persist-marker"
                }),
                timestamp: chrono::Utc::now().to_rfc3339(),
                sequence: store
                    .next_sequence(SOFTWARE_TEAM_ID)
                    .expect("allocate sequence"),
                trace_id: "trace-persist".to_string(),
                task_id: Some(task_id.clone()),
            };
            store
                .add_message(message, "persist-marker")
                .expect("persist encrypted message");

            let raw_payload: String = conn
                .lock()
                .expect("lock sqlite")
                .query_row(
                    "SELECT payload_ciphertext FROM a2a_messages WHERE id = ?1",
                    params!["msg-persist"],
                    |row| row.get(0),
                )
                .expect("read encrypted payload");
            assert!(!raw_payload.contains("shared-secret"));
            assert!(key_path.exists());
        }

        let conn = Arc::new(Mutex::new(
            Connection::open(&db_path).expect("reopen team store database"),
        ));
        let restored = TeamStore::persistent(conn, &key_path).expect("restore persistent store");

        let restored_task = restored
            .get_task(&task_id)
            .expect("load restored task")
            .expect("task should persist");
        assert_eq!(restored_task.title, "Persist task");
        assert_eq!(restored_task.assignee_id.as_deref(), Some("coder"));
        assert_eq!(restored_task.priority, "normal");
        assert!(restored_task.completed_at.is_none());

        let messages = restored
            .list_messages(SOFTWARE_TEAM_ID, None, 10)
            .expect("load restored messages");
        let restored_message = messages
            .iter()
            .find(|message| message.id == "msg-persist")
            .expect("message should persist");
        assert_eq!(restored_message.payload["content"], "shared-secret");
        assert_eq!(restored_message.sequence, 0);
        assert_eq!(restored_message.trace_id, "trace-persist");
        assert_eq!(restored_message.task_id.as_deref(), Some(task_id.as_str()));
    }

    #[test]
    fn manages_teams_members_priorities_and_task_completion_history() {
        let store = TeamStore::new();
        let team = store
            .create_team(
                "mobile-ops",
                "Mobile Operations",
                "permanent",
                serde_json::json!({"goal": "Operate T3rnel from a phone"}),
            )
            .expect("create team");
        assert_eq!(team.member_ids.len(), 0);

        let member = store
            .upsert_member("mobile-ops", "t3rnel", "lead_operator")
            .expect("upsert member")
            .expect("team exists");
        assert_eq!(member.role_tag, "lead_operator");
        assert_eq!(
            store
                .list_members("mobile-ops")
                .expect("list members")
                .len(),
            1
        );

        let task = store
            .create_task_assignment_with_priority(
                "mobile-ops",
                "Ship mobile controls",
                "Make production mobile controls usable",
                "t3rnel",
                Vec::new(),
                "urgent",
            )
            .expect("create prioritized task");
        assert_eq!(task.priority, "urgent");
        assert_eq!(task.percent, 10);
        assert!(task.created_at <= task.updated_at);

        let finished = store
            .finish_task("mobile-ops", &task.id, "done")
            .expect("finish task")
            .expect("task exists");
        assert_eq!(finished.percent, 100);
        assert_eq!(finished.priority, "urgent");
        assert!(finished.completed_at.is_some());

        assert!(store
            .remove_member("mobile-ops", "t3rnel")
            .expect("remove member"));
        assert!(store.delete_team("mobile-ops").expect("delete team"));
        assert!(store
            .get_team("mobile-ops")
            .expect("load deleted")
            .is_none());
    }
}
