//! IDE Driver Platform — delegate tasks to external IDE/agent runtimes.
//!
//! T3rnel agents can hand whole tasks to Windsurf/Devin Desktop, Cursor, or
//! Google Antigravity via the `ide_delegate` tool. Each driver talks to the
//! vendor's programmatic agent API (not the IDE UI). The user watches the
//! resulting session in their IDE of choice.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use t3rnel_types::config::{
    AntigravityIdeDriverConfig, CursorIdeDriverConfig, DevinIdeDriverConfig, IdeDriverConfig,
    WindsurfIdeDriverConfig,
};
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Request to delegate a task to an IDE agent runtime.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdeTaskRequest {
    /// High-level task description.
    pub task: String,
    /// Optional context (file paths, constraints, prior work).
    #[serde(default)]
    pub context: String,
    /// Optional JSON schema for structured output.
    #[serde(default)]
    pub output_schema: Option<Value>,
    /// Optional tags to attach to the session.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Optional spending cap for this task (platform-specific units).
    #[serde(default)]
    pub budget_units: Option<u64>,
}

/// Opaque handle returned by a successful delegation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdeTaskHandle {
    /// Driver that owns the handle.
    pub platform: String,
    /// Vendor session / agent / interaction id.
    pub session_id: String,
    /// Human-readable URL where the session can be watched.
    pub url: String,
    /// Arbitrary driver-specific state needed for polling.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Snapshot of an ongoing or completed IDE task.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdeTaskStatus {
    /// One of: queued, working, blocked, finished, errored, cancelled.
    pub state: String,
    /// Latest message / summary from the IDE agent.
    #[serde(default)]
    pub message: String,
    /// Structured output, if the platform supports it and the task is done.
    #[serde(default)]
    pub structured_output: Option<Value>,
    /// Estimated cost in the platform's own currency (USD for Devin/Cursor,
    /// ACUs for Devin legacy, etc.). Only present when finished or billed.
    #[serde(default)]
    pub cost: Option<f64>,
    /// Platform-specific raw status payload.
    #[serde(default)]
    pub raw: Value,
}

/// Errors returned by IDE drivers.
#[derive(Debug, thiserror::Error)]
pub enum IdeDriverError {
    #[error("driver '{0}' is not configured")]
    NotConfigured(String),
    #[error("missing required environment variable: {0}")]
    MissingEnv(String),
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API error {status}: {body}")]
    Api { status: u16, body: String },
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("task did not complete within {0} minutes")]
    Timeout(u64),
    #[error("task was cancelled")]
    Cancelled,
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Driver trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait IdeDriver: Send + Sync {
    fn name(&self) -> &'static str;

    /// Create a session/agent/interaction and return a handle.
    async fn delegate(&self, request: IdeTaskRequest) -> Result<IdeTaskHandle, IdeDriverError>;

    /// Poll for the current status of a handle.
    async fn poll(&self, handle: &IdeTaskHandle) -> Result<IdeTaskStatus, IdeDriverError>;

    /// Cancel an in-flight task.
    async fn cancel(&self, handle: &IdeTaskHandle) -> Result<(), IdeDriverError>;
}

// ---------------------------------------------------------------------------
// Registry / factory
// ---------------------------------------------------------------------------

/// Build the active IDE driver from kernel config.
pub fn build_ide_driver(
    config: &IdeDriverConfig,
) -> Result<Option<Box<dyn IdeDriver>>, IdeDriverError> {
    let active = config.active.trim().to_lowercase();
    if active.is_empty() {
        return Ok(None);
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| IdeDriverError::Other(format!("failed to build HTTP client: {e}")))?;

    match active.as_str() {
        "devin" => Ok(Some(Box::new(DevinIdeDriver::new(
            client,
            config.devin.clone(),
        )))),
        "cursor" => Ok(Some(Box::new(CursorIdeDriver::new(
            client,
            config.cursor.clone(),
        )))),
        "antigravity" => Ok(Some(Box::new(AntigravityIdeDriver::new(
            client,
            config.antigravity.clone(),
        )))),
        other => Err(IdeDriverError::NotConfigured(other.to_string())),
    }
}

fn require_env(name: &str) -> Result<String, IdeDriverError> {
    std::env::var(name).map_err(|_| IdeDriverError::MissingEnv(name.to_string()))
}

// ---------------------------------------------------------------------------
// Devin driver
// ---------------------------------------------------------------------------

pub struct DevinIdeDriver {
    client: reqwest::Client,
    config: DevinIdeDriverConfig,
}

impl DevinIdeDriver {
    pub fn new(client: reqwest::Client, config: DevinIdeDriverConfig) -> Self {
        Self { client, config }
    }

    fn base_url(&self) -> &str {
        &self.config.base_url
    }

    fn api_key(&self) -> Result<String, IdeDriverError> {
        require_env(&self.config.api_key_env)
    }

    fn org_id(&self) -> Result<String, IdeDriverError> {
        require_env(&self.config.org_id_env)
    }

    fn headers(&self) -> Result<reqwest::header::HeaderMap, IdeDriverError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        let key = self.api_key()?;
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {key}").parse().unwrap(),
        );
        Ok(headers)
    }

    async fn post_json(&self, path: &str, body: Value) -> Result<Value, IdeDriverError> {
        let url = format!("{}{path}", self.base_url());
        let resp = self
            .client
            .post(&url)
            .headers(self.headers()?)
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(IdeDriverError::Api {
                status: status.as_u16(),
                body: body_text,
            });
        }
        Ok(serde_json::from_str(&body_text)?)
    }

    async fn get_json(&self, path: &str) -> Result<Value, IdeDriverError> {
        let url = format!("{}{path}", self.base_url());
        let resp = self
            .client
            .get(&url)
            .headers(self.headers()?)
            .send()
            .await?;
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(IdeDriverError::Api {
                status: status.as_u16(),
                body: body_text,
            });
        }
        Ok(serde_json::from_str(&body_text)?)
    }
}

#[async_trait]
impl IdeDriver for DevinIdeDriver {
    fn name(&self) -> &'static str {
        "devin"
    }

    async fn delegate(&self, request: IdeTaskRequest) -> Result<IdeTaskHandle, IdeDriverError> {
        let org_id = self.org_id()?;
        let prompt = format!(
            "{task}\n\nContext:\n{context}",
            task = request.task,
            context = request.context
        );

        let mut body = serde_json::json!({
            "prompt": prompt,
        });

        if let Some(schema) = request.output_schema {
            body["structured_output_schema"] = schema;
        }
        if !request.tags.is_empty() {
            body["tags"] = serde_json::json!(request.tags);
        }
        if let Some(budget) = request.budget_units {
            body["max_acu_limit"] = serde_json::json!(budget);
        }

        info!(platform = "devin", "creating Devin session");
        let result = self
            .post_json(&format!("/organizations/{org_id}/sessions"), body)
            .await?;

        let session_id = result["session_id"]
            .as_str()
            .or_else(|| result["id"].as_str())
            .ok_or_else(|| {
                IdeDriverError::Other("Devin response missing session_id/id".to_string())
            })?
            .to_string();
        let url = result["url"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("https://app.devin.ai/sessions/{session_id}"));

        Ok(IdeTaskHandle {
            platform: "devin".to_string(),
            session_id,
            url,
            extra: HashMap::new(),
        })
    }

    async fn poll(&self, handle: &IdeTaskHandle) -> Result<IdeTaskStatus, IdeDriverError> {
        let org_id = self.org_id()?;
        let raw = self
            .get_json(&format!(
                "/organizations/{org_id}/sessions/{}",
                handle.session_id
            ))
            .await?;

        let status_enum = raw["status_enum"].as_str().unwrap_or("unknown");
        let message = raw["summary"]
            .as_str()
            .or_else(|| raw["last_message"].as_str())
            .unwrap_or("")
            .to_string();

        let state = match status_enum {
            "queued" => "queued",
            "running" | "working" => "working",
            "blocked" => "blocked",
            "finished" => "finished",
            "errored" | "error" => "errored",
            "cancelled" => "cancelled",
            _ => "unknown",
        }
        .to_string();

        let structured_output = raw.get("structured_output").cloned();
        let cost = raw["cost"].as_f64().or_else(|| raw["acu_cost"].as_f64());

        Ok(IdeTaskStatus {
            state,
            message,
            structured_output,
            cost,
            raw,
        })
    }

    async fn cancel(&self, handle: &IdeTaskHandle) -> Result<(), IdeDriverError> {
        let org_id = self.org_id()?;
        let _ = self
            .post_json(
                &format!(
                    "/organizations/{org_id}/sessions/{}/terminate",
                    handle.session_id
                ),
                serde_json::json!({}),
            )
            .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Cursor driver
// ---------------------------------------------------------------------------

pub struct CursorIdeDriver {
    client: reqwest::Client,
    config: CursorIdeDriverConfig,
}

impl CursorIdeDriver {
    pub fn new(client: reqwest::Client, config: CursorIdeDriverConfig) -> Self {
        Self { client, config }
    }

    fn api_key(&self) -> Result<String, IdeDriverError> {
        require_env(&self.config.api_key_env)
    }

    fn headers(&self) -> Result<reqwest::header::HeaderMap, IdeDriverError> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        let key = self.api_key()?;
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {key}").parse().unwrap(),
        );
        Ok(headers)
    }

    async fn post_json(&self, path: &str, body: Value) -> Result<Value, IdeDriverError> {
        let url = format!("{}{path}", self.config.base_url);
        let resp = self
            .client
            .post(&url)
            .headers(self.headers()?)
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(IdeDriverError::Api {
                status: status.as_u16(),
                body: body_text,
            });
        }
        Ok(serde_json::from_str(&body_text)?)
    }

    async fn get_json(&self, path: &str) -> Result<Value, IdeDriverError> {
        let url = format!("{}{path}", self.config.base_url);
        let resp = self
            .client
            .get(&url)
            .headers(self.headers()?)
            .send()
            .await?;
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(IdeDriverError::Api {
                status: status.as_u16(),
                body: body_text,
            });
        }
        Ok(serde_json::from_str(&body_text)?)
    }
}

#[async_trait]
impl IdeDriver for CursorIdeDriver {
    fn name(&self) -> &'static str {
        "cursor"
    }

    async fn delegate(&self, request: IdeTaskRequest) -> Result<IdeTaskHandle, IdeDriverError> {
        let mode = self.config.mode.trim().to_lowercase();
        let prompt = format!(
            "{task}\n\nContext:\n{context}",
            task = request.task,
            context = request.context
        );

        let mut body = serde_json::json!({
            "prompt": { "text": prompt },
        });

        if mode == "local" {
            body["local"] = serde_json::json!({ "cwd": std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| ".".to_string()) });
        }

        if let Some(schema) = request.output_schema {
            body["output_schema"] = schema;
        }

        info!(platform = "cursor", mode = %mode, "creating Cursor agent");
        let result = self.post_json("/agents", body).await?;

        let agent_id = result["agent"]["id"]
            .as_str()
            .or_else(|| result["id"].as_str())
            .ok_or_else(|| IdeDriverError::Other("Cursor response missing agent id".to_string()))?
            .to_string();
        let run_id = result["initialRun"]["id"]
            .as_str()
            .or_else(|| result["latestRunId"].as_str())
            .map(|s| s.to_string());

        let url = format!("https://cursor.com/agents/{agent_id}");

        let mut extra = HashMap::new();
        if let Some(run_id) = run_id {
            extra.insert("run_id".to_string(), serde_json::json!(run_id));
        }

        Ok(IdeTaskHandle {
            platform: "cursor".to_string(),
            session_id: agent_id,
            url,
            extra,
        })
    }

    async fn poll(&self, handle: &IdeTaskHandle) -> Result<IdeTaskStatus, IdeDriverError> {
        let run_id = handle
            .extra
            .get("run_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&handle.session_id);

        let raw = self
            .get_json(&format!("/agents/{}/runs/{}", handle.session_id, run_id))
            .await?;

        let status = raw["status"].as_str().unwrap_or("unknown");
        let state = match status {
            "pending" | "queued" => "queued",
            "running" | "in_progress" => "working",
            "completed" | "success" | "finished" => "finished",
            "failed" | "error" => "errored",
            "cancelled" => "cancelled",
            _ => "unknown",
        }
        .to_string();

        let message = raw["result"]
            .as_str()
            .or_else(|| raw["message"].as_str())
            .unwrap_or("")
            .to_string();
        let structured_output = raw.get("structured_output").cloned();

        Ok(IdeTaskStatus {
            state,
            message,
            structured_output,
            cost: None,
            raw,
        })
    }

    async fn cancel(&self, handle: &IdeTaskHandle) -> Result<(), IdeDriverError> {
        let _ = self
            .post_json(
                &format!("/agents/{}/cancel", handle.session_id),
                serde_json::json!({}),
            )
            .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Antigravity driver
// ---------------------------------------------------------------------------

pub struct AntigravityIdeDriver {
    client: reqwest::Client,
    config: AntigravityIdeDriverConfig,
}

impl AntigravityIdeDriver {
    pub fn new(client: reqwest::Client, config: AntigravityIdeDriverConfig) -> Self {
        Self { client, config }
    }

    fn api_key(&self) -> Result<String, IdeDriverError> {
        require_env(&self.config.api_key_env)
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}{path}?key={}",
            self.config.base_url,
            self.api_key().unwrap_or_default()
        )
    }

    async fn post_json(&self, path: &str, body: Value) -> Result<Value, IdeDriverError> {
        let url = self.endpoint(path);
        let resp = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(IdeDriverError::Api {
                status: status.as_u16(),
                body: body_text,
            });
        }
        Ok(serde_json::from_str(&body_text)?)
    }

    async fn get_json(&self, path: &str) -> Result<Value, IdeDriverError> {
        let url = self.endpoint(path);
        let resp = self
            .client
            .get(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .send()
            .await?;
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(IdeDriverError::Api {
                status: status.as_u16(),
                body: body_text,
            });
        }
        Ok(serde_json::from_str(&body_text)?)
    }
}

#[async_trait]
impl IdeDriver for AntigravityIdeDriver {
    fn name(&self) -> &'static str {
        "antigravity"
    }

    async fn delegate(&self, request: IdeTaskRequest) -> Result<IdeTaskHandle, IdeDriverError> {
        let _ = self.api_key()?; // fail fast if missing

        let mut body = serde_json::json!({
            "agent": self.config.model,
            "input": request.task,
            "environment": "remote",
        });

        if !request.context.is_empty() {
            body["input"] =
                serde_json::json!(format!("{}\n\nContext:\n{}", request.task, request.context));
        }

        if let Some(schema) = request.output_schema {
            body["output_schema"] = schema;
        }

        info!(platform = "antigravity", "creating Antigravity interaction");
        let result = self.post_json("/v1beta/interactions", body).await?;

        let interaction_id = result["id"]
            .as_str()
            .ok_or_else(|| IdeDriverError::Other("Antigravity response missing id".to_string()))?
            .to_string();
        let environment_id = result["environment_id"].as_str().unwrap_or("").to_string();

        let mut extra = HashMap::new();
        if !environment_id.is_empty() {
            extra.insert(
                "environment_id".to_string(),
                serde_json::json!(environment_id),
            );
        }

        Ok(IdeTaskHandle {
            platform: "antigravity".to_string(),
            session_id: interaction_id.clone(),
            url: format!(
                "https://aistudio.google.com/app/apps/drive/{}?showPreview=true",
                interaction_id
            ),
            extra,
        })
    }

    async fn poll(&self, handle: &IdeTaskHandle) -> Result<IdeTaskStatus, IdeDriverError> {
        let raw = self
            .get_json(&format!("/v1beta/interactions/{}", handle.session_id))
            .await?;

        let state_str = raw["state"].as_str().unwrap_or("ACTIVE");
        let state = match state_str {
            "ACTIVE" => "working",
            "COMPLETED" => "finished",
            "FAILED" => "errored",
            "CANCELLED" => "cancelled",
            _ => "working",
        }
        .to_string();

        let message = raw["output_text"].as_str().unwrap_or("").to_string();
        let structured_output = raw.get("output").cloned();

        Ok(IdeTaskStatus {
            state,
            message,
            structured_output,
            cost: None,
            raw,
        })
    }

    async fn cancel(&self, handle: &IdeTaskHandle) -> Result<(), IdeDriverError> {
        let _ = self
            .post_json(
                &format!("/v1beta/interactions/{}/cancel", handle.session_id),
                serde_json::json!({}),
            )
            .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Windsurf driver
// ---------------------------------------------------------------------------

pub struct WindsurfIdeDriver {
    client: reqwest::Client,
    config: WindsurfIdeDriverConfig,
}

impl WindsurfIdeDriver {
    pub fn new(client: reqwest::Client, config: WindsurfIdeDriverConfig) -> Self {
        Self { client, config }
    }

    async fn post_json(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, IdeDriverError> {
        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);
        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| IdeDriverError::Other(format!("HTTP request failed: {e}")))?;

        let status = response.status();
        let body_text = response
            .text()
            .await
            .map_err(|e| IdeDriverError::Other(format!("failed to read response body: {e}")))?;

        if !status.is_success() {
            return Err(IdeDriverError::Api {
                status: status.as_u16(),
                body: body_text,
            });
        }

        serde_json::from_str(&body_text).map_err(IdeDriverError::Json)
    }

    async fn get_json(&self, path: &str) -> Result<serde_json::Value, IdeDriverError> {
        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| IdeDriverError::Other(format!("HTTP request failed: {e}")))?;

        let status = response.status();
        let body_text = response
            .text()
            .await
            .map_err(|e| IdeDriverError::Other(format!("failed to read response body: {e}")))?;

        if !status.is_success() {
            return Err(IdeDriverError::Api {
                status: status.as_u16(),
                body: body_text,
            });
        }

        serde_json::from_str(&body_text).map_err(IdeDriverError::Json)
    }
}

#[async_trait]
impl IdeDriver for WindsurfIdeDriver {
    fn name(&self) -> &'static str {
        "windsurf"
    }

    async fn delegate(&self, request: IdeTaskRequest) -> Result<IdeTaskHandle, IdeDriverError> {
        let session_id = uuid::Uuid::new_v4().to_string();

        let body = serde_json::json!({
            "session_id": session_id,
            "task": request.task,
            "context": request.context,
            "output_schema": request.output_schema,
            "tags": request.tags,
            "budget_units": request.budget_units,
        });

        info!(platform = "windsurf", session_id = %session_id, "posting Windsurf IDE command");
        let result = self.post_json("/api/ide-commands", body).await?;

        let session_id = result["session_id"]
            .as_str()
            .ok_or_else(|| {
                IdeDriverError::Other("Windsurf response missing session_id".to_string())
            })?
            .to_string();

        Ok(IdeTaskHandle {
            platform: "windsurf".to_string(),
            session_id,
            url: "vscode://t3rnel.ide".to_string(),
            extra: HashMap::new(),
        })
    }

    async fn poll(&self, handle: &IdeTaskHandle) -> Result<IdeTaskStatus, IdeDriverError> {
        let raw = self
            .get_json(&format!("/api/ide-commands/{}", handle.session_id))
            .await?;

        let state = raw["state"].as_str().unwrap_or("queued").to_string();
        let message = raw["message"].as_str().unwrap_or("").to_string();
        let structured_output = raw.get("structured_output").cloned();

        Ok(IdeTaskStatus {
            state,
            message,
            structured_output,
            cost: None,
            raw,
        })
    }

    async fn cancel(&self, handle: &IdeTaskHandle) -> Result<(), IdeDriverError> {
        let _ = self
            .post_json(
                &format!("/api/ide-commands/{}/cancel", handle.session_id),
                serde_json::json!({}),
            )
            .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Wait for a task to settle, polling with the driver's configured interval.
/// Returns the final status. Times out after `max_poll_minutes`.
pub async fn wait_for_ide_task(
    driver: &dyn IdeDriver,
    handle: &IdeTaskHandle,
    poll_interval_secs: u64,
    max_poll_minutes: u64,
) -> Result<IdeTaskStatus, IdeDriverError> {
    let max_polls = (max_poll_minutes * 60).max(1) / poll_interval_secs.max(1);
    for _ in 0..max_polls {
        tokio::time::sleep(Duration::from_secs(poll_interval_secs)).await;
        let status = driver.poll(handle).await?;
        debug!(platform = %handle.platform, state = %status.state, "IDE task poll");
        if matches!(
            status.state.as_str(),
            "finished" | "blocked" | "errored" | "cancelled"
        ) {
            return Ok(status);
        }
    }
    Err(IdeDriverError::Timeout(max_poll_minutes))
}
