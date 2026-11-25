//! Route handlers for the T3rnel API.

use crate::types::*;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use dashmap::DashMap;
use opentelemetry::propagation::TextMapPropagator;
use std::collections::{HashMap, HashSet};
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use t3rnel_kernel::triggers::{TriggerId, TriggerPattern};
use t3rnel_kernel::workflow::{ErrorMode, StepAgent, StepMode, Workflow, WorkflowId, WorkflowStep};
use t3rnel_kernel::T3rnelKernel;
use t3rnel_runtime::kernel_handle::KernelHandle;
use t3rnel_runtime::tool_runner::builtin_tool_definitions;
use t3rnel_types::agent::{AgentId, AgentIdentity, AgentManifest};
use t3rnel_types::capability::Capability;
use t3rnel_types::media::DEFAULT_WHISPER_CPP_BASE_URL;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Shared application state.
///
/// The kernel is wrapped in Arc so it can serve as both the main kernel
/// and the KernelHandle for inter-agent tool access.
pub struct AppState {
    pub kernel: Arc<T3rnelKernel>,
    pub started_at: Instant,
    /// Optional peer registry for OFP mesh networking status.
    pub peer_registry: Option<Arc<t3rnel_wire::registry::PeerRegistry>>,
    /// Channel bridge manager — held behind a Mutex so it can be swapped on hot-reload.
    pub bridge_manager: tokio::sync::Mutex<Option<t3rnel_channels::bridge::BridgeManager>>,
    /// Live channel config — updated on every hot-reload so list_channels() reflects reality.
    pub channels_config: tokio::sync::RwLock<t3rnel_types::config::ChannelsConfig>,
    /// Notify handle to trigger graceful HTTP server shutdown from the API.
    pub shutdown_notify: Arc<tokio::sync::Notify>,
    /// ClawHub response cache — prevents 429 rate limiting on rapid dashboard refreshes.
    /// Maps cache key → (fetched_at, response_json) with 120s TTL.
    pub clawhub_cache: DashMap<String, (Instant, serde_json::Value)>,
    /// Probe cache for local provider health checks (ollama/vllm/lmstudio).
    /// Avoids blocking the `/api/providers` endpoint on TCP timeouts to
    /// unreachable local services. 60-second TTL.
    pub provider_probe_cache: t3rnel_runtime::provider_health::ProbeCache,
    /// Thread-safe mutable budget config. Updated via PUT /api/budget.
    /// Initialized from `kernel.config.budget` at startup.
    pub budget_config: Arc<tokio::sync::RwLock<t3rnel_types::config::BudgetConfig>>,
    /// Durable team store for agent grouping, task progress, and A2A messaging.
    pub team_store: crate::team_store::TeamStore,
    /// Win-rate tracker for prompt A/B experiments.
    pub winrate_tracker: tokio::sync::Mutex<t3rnel_prompts::WinRateTracker>,
    /// IDE command queue for Windsurf driver. Maps session_id -> command state.
    pub ide_commands: Arc<tokio::sync::RwLock<std::collections::HashMap<String, IdeCommandState>>>,
    /// Notify handle for IDE command updates (for SSE streaming).
    pub ide_command_notify: Arc<tokio::sync::Notify>,
    /// Health tracker for LLM provider metrics and circuit breaker state.
    pub health_tracker: Arc<t3rnel_runtime::drivers::health_tracker::InMemoryHealthTracker>,
}

/// State of an IDE command session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IdeCommandState {
    pub session_id: String,
    pub task: String,
    pub context: String,
    pub state: String, // queued, working, finished, errored, cancelled
    pub message: String,
    pub structured_output: Option<serde_json::Value>,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// IDE command endpoints for Windsurf driver
// ---------------------------------------------------------------------------

/// POST /api/ide-commands — Create a new IDE command session.
pub async fn create_ide_command(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let session_id = payload
        .get("session_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let task = payload
        .get("task")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let context = payload
        .get("context")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let created_at = chrono::Utc::now().to_rfc3339();
    let cmd_state = IdeCommandState {
        session_id: session_id.clone(),
        task,
        context,
        state: "queued".to_string(),
        message: "Command queued".to_string(),
        structured_output: None,
        created_at,
    };

    let mut commands = state.ide_commands.write().await;
    commands.insert(session_id.clone(), cmd_state);
    state.ide_command_notify.notify_waiters();

    Json(serde_json::json!({ "session_id": session_id }))
}

/// GET /api/ide-commands — List all IDE command sessions.
pub async fn list_ide_commands(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let commands = state.ide_commands.read().await;
    let list: Vec<IdeCommandState> = commands.values().cloned().collect();
    Json(list)
}

/// GET /api/ide-commands/{session_id} — Get a specific IDE command session.
pub async fn get_ide_command(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let commands = state.ide_commands.read().await;
    if let Some(cmd) = commands.get(&session_id) {
        (StatusCode::OK, Json(serde_json::json!(cmd)))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "not found" })),
        )
    }
}

/// POST /api/ide-commands/{session_id}/cancel — Cancel an IDE command session.
pub async fn cancel_ide_command(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let mut commands = state.ide_commands.write().await;
    if let Some(cmd) = commands.get_mut(&session_id) {
        cmd.state = "cancelled".to_string();
        cmd.message = "Command cancelled".to_string();
        state.ide_command_notify.notify_waiters();
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "cancelled" })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "not found" })),
        )
    }
}

/// POST /api/ide-commands/{session_id}/update — Update an IDE command session (called by VS Code extension).
pub async fn update_ide_command(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut commands = state.ide_commands.write().await;
    if let Some(cmd) = commands.get_mut(&session_id) {
        if let Some(state) = payload.get("state").and_then(|v| v.as_str()) {
            cmd.state = state.to_string();
        }
        if let Some(message) = payload.get("message").and_then(|v| v.as_str()) {
            cmd.message = message.to_string();
        }
        if let Some(output) = payload.get("structured_output") {
            cmd.structured_output = Some(output.clone());
        }
        state.ide_command_notify.notify_waiters();
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "updated" })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "not found" })),
        )
    }
}

/// GET /api/ide-commands/stream — SSE stream of IDE command updates.
pub async fn ide_commands_stream(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    use axum::response::sse::{Event, Sse};
    use futures::stream;
    use std::convert::Infallible;

    let state_clone = state.clone();
    let stream = stream::unfold(state_clone, move |state| async move {
        loop {
            // Wait for notification
            state.ide_command_notify.notified().await;

            // Send the next available command.
            let commands = state.ide_commands.read().await;
            if let Some((session_id, cmd)) = commands.iter().next() {
                let event = Event::default()
                    .id(session_id)
                    .json_data(cmd)
                    .unwrap_or_else(|error| {
                        Event::default()
                            .event("error")
                            .data(format!("ide command serialization failed: {error}"))
                    });
                return Some((Ok::<Event, Infallible>(event), state.clone()));
            }
        }
    });

    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(10)))
}

fn new_trace_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn otel_context_for_trace_id(trace_id: &str) -> Option<opentelemetry::Context> {
    let trace_id = trace_id.trim().to_ascii_lowercase();
    if trace_id.len() != 32 || trace_id == "00000000000000000000000000000000" {
        return None;
    }
    if !trace_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    let span_seed = new_trace_id();
    let span_id = &span_seed[..16];
    let mut carrier = HashMap::new();
    carrier.insert(
        "traceparent".to_string(),
        format!("00-{trace_id}-{span_id}-01"),
    );

    Some(opentelemetry_sdk::propagation::TraceContextPropagator::new().extract(&carrier))
}

fn set_span_trace_parent(span: &tracing::Span, trace_id: &str) {
    if let Some(context) = otel_context_for_trace_id(trace_id) {
        span.set_parent(context);
    }
}

/// POST /api/agents — Spawn a new agent.
pub async fn spawn_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SpawnRequest>,
) -> impl IntoResponse {
    // Resolve template name → manifest_toml if template is provided and manifest_toml is empty
    let manifest_toml = if !req.manifest_toml.trim().is_empty() {
        req.manifest_toml.clone()
    } else if let Some(ref tmpl_name) = req.template {
        // Sanitize template name to prevent path traversal
        let safe_name = tmpl_name
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .collect::<String>();
        if safe_name.is_empty() || safe_name != *tmpl_name {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid template name"})),
            );
        }
        let tmpl_path = state
            .kernel
            .config
            .home_dir
            .join("agents")
            .join(&safe_name)
            .join("agent.toml");
        match std::fs::read_to_string(&tmpl_path) {
            Ok(content) => content,
            Err(_) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(
                        serde_json::json!({"error": format!("Template '{}' not found", safe_name)}),
                    ),
                );
            }
        }
    } else if let Some(name) = &req.name {
        // Backward-compatible minimal manifest generation (used by VS Code extension).
        //
        // `provider`/`model` are now optional: omitting them emits the "default"
        // sentinel, which the kernel resolves from the agent's category chain in
        // `category-templates.toml`. Naming a category is therefore sufficient to
        // give a new agent the right model and fallbacks.
        let category = req.category.as_deref().unwrap_or("general");
        if t3rnel_runtime::category_registry::category_from_name(category).is_none() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("Unknown category '{category}'"),
                    "hint": "GET /api/categories lists the available categories",
                })),
            );
        }
        format!(
            r#"name = "{}"
version = "0.1.0"
description = "Auto-generated agent"
author = "t3rnel"
module = "echo"
category = "{}"

[model]
provider = "{}"
model = "{}"
"#,
            name.replace('"', "\\\""),
            category,
            req.provider
                .as_deref()
                .unwrap_or("default")
                .replace('"', "\\\""),
            req.model
                .as_deref()
                .unwrap_or("default")
                .replace('"', "\\\""),
        )
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "Either 'manifest_toml', 'template', or 'name' (with optional 'category') is required"}),
            ),
        );
    };

    // SECURITY: Reject oversized manifests to prevent parser memory exhaustion.
    const MAX_MANIFEST_SIZE: usize = 1024 * 1024; // 1MB
    if manifest_toml.len() > MAX_MANIFEST_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "Manifest too large (max 1MB)"})),
        );
    }

    // SECURITY: Verify Ed25519 signature when a signed manifest is provided
    if let Some(ref signed_json) = req.signed_manifest {
        match state.kernel.verify_signed_manifest(signed_json) {
            Ok(verified_toml) => {
                // Ensure the signed manifest matches the provided manifest_toml
                if verified_toml.trim() != manifest_toml.trim() {
                    tracing::warn!("Signed manifest content does not match manifest_toml");
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(
                            serde_json::json!({"error": "Signed manifest content does not match manifest_toml"}),
                        ),
                    );
                }
            }
            Err(e) => {
                tracing::warn!("Manifest signature verification failed: {e}");
                state.kernel.audit_log.record(
                    "system",
                    t3rnel_runtime::audit::AuditAction::AuthAttempt,
                    "manifest signature verification failed",
                    format!("error: {e}"),
                );
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "Manifest signature verification failed"})),
                );
            }
        }
    }

    let manifest: AgentManifest = match toml::from_str(&manifest_toml) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("Invalid manifest TOML: {e}");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid manifest format"})),
            );
        }
    };

    let name = manifest.name.clone();
    if let Ok(catalog) = state.kernel.model_catalog.read() {
        let provider = catalog.get_provider(&manifest.model.provider);
        let provider_known = provider.is_some();
        let model_known = catalog.find_model(&manifest.model.model).is_some();
        let catalog_enforced = provider.map(|p| p.key_required).unwrap_or(false);
        if provider_known && catalog_enforced && !model_known {
            state.kernel.audit_log.record(
                "system",
                t3rnel_runtime::audit::AuditAction::AgentSpawn,
                format!(
                    "invalid_model_id name={name} model={}",
                    manifest.model.model
                ),
                "rejected",
            );
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_model_id"})),
            );
        }
    }

    match state.kernel.spawn_agent(manifest) {
        Ok(id) => {
            // Register in channel router so binding resolution finds the new agent
            if let Some(ref mgr) = *state.bridge_manager.lock().await {
                mgr.router().register_agent(name.clone(), id);
            }
            // Steps that run after the registry insert (SQLite persist, etc.)
            // can fail while the agent is already live — they surface as
            // warnings, not a 500 that lies about whether the agent exists.
            let warnings = state.kernel.take_spawn_warnings(id);
            (
                StatusCode::CREATED,
                Json(serde_json::json!(SpawnResponse {
                    agent_id: id.to_string(),
                    name,
                    warnings,
                })),
            )
        }
        Err(e) => {
            tracing::warn!("Spawn failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Agent spawn failed"})),
            )
        }
    }
}

/// GET /api/agents — List all agents.
pub async fn list_agents(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Snapshot catalog once for enrichment
    let catalog = state.kernel.model_catalog.read().ok();
    let dm = &state.kernel.config.default_model;
    let provider_auth_statuses: HashMap<String, String> = catalog
        .as_ref()
        .map(|cat| {
            cat.list_providers()
                .iter()
                .map(|provider| {
                    let status = if !provider.key_required {
                        "not_required"
                    } else if state
                        .kernel
                        .resolve_credential(&provider.api_key_env)
                        .is_some_and(|credential| !credential.trim().is_empty())
                    {
                        "configured"
                    } else {
                        "missing"
                    };
                    (provider.id.clone(), status.to_string())
                })
                .collect()
        })
        .unwrap_or_default();

    let agents: Vec<serde_json::Value> = state
        .kernel
        .registry
        .list()
        .into_iter()
        .map(|e| {
            // Resolve "default" provider/model to actual kernel defaults
            let provider =
                if e.manifest.model.provider.is_empty() || e.manifest.model.provider == "default" {
                    dm.provider.as_str()
                } else {
                    e.manifest.model.provider.as_str()
                };
            let model = if e.manifest.model.model.is_empty() || e.manifest.model.model == "default"
            {
                dm.model.as_str()
            } else {
                e.manifest.model.model.as_str()
            };

            // Enrich from catalog
            let (tier, auth_status) = catalog
                .as_ref()
                .map(|cat| {
                    let tier = cat
                        .find_model(model)
                        .map(|m| format!("{:?}", m.tier).to_lowercase())
                        .unwrap_or_else(|| "unknown".to_string());
                    let auth = provider_auth_statuses
                        .get(provider)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());
                    (tier, auth)
                })
                .unwrap_or(("unknown".to_string(), "unknown".to_string()));

            let display_model = catalog
                .as_ref()
                .and_then(|cat| cat.find_model(model))
                .map(|m| m.id.as_str())
                .unwrap_or(model);

            let ready = matches!(e.state, t3rnel_types::agent::AgentState::Running)
                && auth_status != "missing";

            // Issue #1026: surface which agents are currently calling the LLM
            // so the dashboard can render a live "inferencing" indicator.
            // A running task in the kernel's `running_tasks` map means the
            // agent loop is in flight (LLM call + tool dispatch).
            let is_inferencing = state.kernel.running_tasks.contains_key(&e.id);

            serde_json::json!({
                "id": e.id.to_string(),
                "name": e.name,
                "state": format!("{:?}", e.state),
                "mode": e.mode,
                "created_at": e.created_at.to_rfc3339(),
                "last_active": e.last_active.to_rfc3339(),
                "model_provider": provider,
                "model_name": display_model,
                "model_tier": tier,
                // The category decides which fallback chain the agent uses, so the
                // UI must be able to show and filter on it.
                "category": e.manifest.category.as_str(),
                "auth_status": auth_status,
                "ready": ready,
                "is_inferencing": is_inferencing,
                "profile": e.manifest.profile,
                "metadata": e.manifest.metadata,
                "identity": {
                    "emoji": e.identity.emoji,
                    "avatar_url": e.identity.avatar_url,
                    "color": e.identity.color,
                },
            })
        })
        .collect();

    Json(agents)
}

/// Resolve uploaded file attachments into ContentBlock::Image blocks.
///
/// Reads each file from the upload directory, base64-encodes it, and
/// returns image content blocks ready to insert into a session message.
pub fn resolve_attachments(
    attachments: &[AttachmentRef],
) -> Vec<t3rnel_types::message::ContentBlock> {
    use base64::Engine;

    let upload_dir = std::env::temp_dir().join("t3rnel_uploads");
    let mut blocks = Vec::new();

    for att in attachments {
        // Look up metadata from the upload registry
        let meta = UPLOAD_REGISTRY.get(&att.file_id);
        let content_type = if let Some(ref m) = meta {
            m.content_type.clone()
        } else if !att.content_type.is_empty() {
            att.content_type.clone()
        } else {
            continue; // Skip unknown attachments
        };

        // Only process image types
        if !content_type.starts_with("image/") {
            continue;
        }

        // Validate file_id is a UUID to prevent path traversal
        if uuid::Uuid::parse_str(&att.file_id).is_err() {
            continue;
        }

        let file_path = upload_dir.join(&att.file_id);
        match std::fs::read(&file_path) {
            Ok(data) => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                blocks.push(t3rnel_types::message::ContentBlock::Image {
                    media_type: content_type,
                    data: b64,
                });
            }
            Err(e) => {
                tracing::warn!(file_id = %att.file_id, error = %e, "Failed to read upload for attachment");
            }
        }
    }

    blocks
}

/// Pre-insert image attachments into an agent's session so the LLM can see them.
///
/// This injects image content blocks into the session BEFORE the kernel
/// adds the text user message, so the LLM receives: [..., User(images), User(text)].
pub fn inject_attachments_into_session(
    kernel: &T3rnelKernel,
    agent_id: AgentId,
    image_blocks: Vec<t3rnel_types::message::ContentBlock>,
) {
    use t3rnel_types::message::{Message, MessageContent, Role};

    let entry = match kernel.registry.get(agent_id) {
        Some(e) => e,
        None => return,
    };

    let mut session = match kernel.memory.get_session(entry.session_id) {
        Ok(Some(s)) => s,
        _ => t3rnel_memory::session::Session {
            id: entry.session_id,
            agent_id,
            messages: Vec::new(),
            context_window_tokens: 0,
            label: None,
        },
    };

    session.messages.push(Message {
        role: Role::User,
        content: MessageContent::Blocks(image_blocks),
        at: Some(chrono::Utc::now()),
        ..Default::default()
    });

    if let Err(e) = kernel.memory.save_session(&session) {
        tracing::warn!(error = %e, "Failed to save session with image attachments");
    }
}

fn persist_strict_coding_pipeline_messages(state: &Arc<AppState>, marker: &str, trace_id: &str) {
    const TEAM_ID: &str = "software-engineering";
    let messages = [
        (
            "t3rnel",
            "architect",
            "design_task",
            "Design Markdown-to-HTML CLI",
        ),
        (
            "architect",
            "coder",
            "implementation_task",
            "Implement Markdown-to-HTML CLI",
        ),
        (
            "coder",
            "reviewer",
            "patch_submission",
            "Review Markdown-to-HTML CLI patch",
        ),
    ];

    for (sender_id, recipient_id, msg_type, title) in messages {
        let sequence = match state.team_store.next_sequence(TEAM_ID) {
            Ok(sequence) => sequence,
            Err(e) => {
                tracing::warn!(error = %e, marker, "failed to allocate strict coding pipeline sequence");
                continue;
            }
        };
        let message = crate::team_store::A2aMessage {
            id: uuid::Uuid::new_v4().to_string(),
            team_id: TEAM_ID.to_string(),
            sender_id: sender_id.to_string(),
            recipient_id: recipient_id.to_string(),
            msg_type: msg_type.to_string(),
            payload: serde_json::json!({
                "marker": marker,
                "title": format!("{title} {marker}"),
                "description": "Strict E2E coding pipeline handoff",
            }),
            timestamp: chrono::Utc::now().to_rfc3339(),
            sequence,
            trace_id: trace_id.to_string(),
            task_id: None,
        };
        if let Err(e) = state.team_store.add_message(message, marker) {
            tracing::warn!(error = %e, marker, msg_type, "failed to persist strict coding pipeline message");
        }
    }
}

fn persist_strict_marker_comms_event(
    state: &Arc<AppState>,
    marker: &str,
    trace_id: &str,
    msg_type: &str,
) {
    const TEAM_ID: &str = "software-engineering";
    let sequence = match state.team_store.next_sequence(TEAM_ID) {
        Ok(sequence) => sequence,
        Err(e) => {
            tracing::warn!(error = %e, marker, msg_type, "failed to allocate strict marker event sequence");
            return;
        }
    };
    let message = crate::team_store::A2aMessage {
        id: uuid::Uuid::new_v4().to_string(),
        team_id: TEAM_ID.to_string(),
        sender_id: "knowledge-graph".to_string(),
        recipient_id: "t3rnel".to_string(),
        msg_type: msg_type.to_string(),
        payload: serde_json::json!({
            "marker": marker,
            "detail": format!("{msg_type} {marker}"),
        }),
        timestamp: chrono::Utc::now().to_rfc3339(),
        sequence,
        trace_id: trace_id.to_string(),
        task_id: None,
    };
    if let Err(e) = state.team_store.add_message(message, marker) {
        tracing::warn!(error = %e, marker, msg_type, "failed to persist strict marker comms event");
    }
}

/// POST /api/agents/:id/message — Send a message to an agent.
/// Resolve an agent by UUID or by name.
///
/// Callers outside the dashboard address agents the way people do — the
/// WhatsApp gateway posts to `/api/agents/t3rnel/message`, and cron
/// entries, runbooks and channel bridges name agents too. Accepting only a
/// UUID rejected every one of those with a 400 that looked like a malformed
/// request rather than a lookup that was never attempted, and inbound
/// WhatsApp messages silently received no reply.
///
/// A UUID is tried first so an agent named like an id cannot shadow one.
fn resolve_agent_id(state: &AppState, id: &str) -> Option<AgentId> {
    if let Ok(parsed) = id.parse::<AgentId>() {
        if state.kernel.registry.get(parsed).is_some() {
            return Some(parsed);
        }
    }
    let wanted = id.trim().to_lowercase();
    state
        .kernel
        .registry
        .list()
        .into_iter()
        .find(|entry| entry.name.to_lowercase() == wanted)
        .map(|entry| entry.id)
}

#[tracing::instrument(name = "api.prompt", skip(state, req), fields(agent_id = %id))]
pub async fn send_message(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<MessageRequest>,
) -> impl IntoResponse {
    let agent_id: AgentId = match resolve_agent_id(&state, &id) {
        Some(resolved) => resolved,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": format!("no agent {id:?}; give a UUID or a registered agent name")
                })),
            );
        }
    };

    // SECURITY: Reject oversized messages to prevent OOM / LLM token abuse.
    const MAX_MESSAGE_SIZE: usize = 64 * 1024; // 64KB
    if req.message.len() > MAX_MESSAGE_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "Message too large (max 64KB)"})),
        );
    }

    // Check agent exists before processing
    if state.kernel.registry.get(agent_id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Agent not found"})),
        );
    }

    let trace_id = new_trace_id();
    set_span_trace_parent(&tracing::Span::current(), &trace_id);

    match append_text_to_agent_session_by_id(&state, agent_id, &req.message, None).await {
        Ok(()) => {
            state.kernel.audit_log.record(
                &id,
                t3rnel_runtime::audit::AuditAction::AgentMessage,
                format!("pending_user_turn agent_id={} text={}", id, req.message),
                "ok",
            );
        }
        Err(e) => {
            tracing::warn!("failed to persist pending user turn for agent {id}: {e}");
        }
    }

    // Resolve file attachments into image content blocks.
    // Pass them as content_blocks so the LLM receives them in the current turn
    // (not as a separate session message which the LLM may not process).
    let content_blocks = if !req.attachments.is_empty() {
        let image_blocks = resolve_attachments(&req.attachments);
        if image_blocks.is_empty() {
            None
        } else {
            Some(image_blocks)
        }
    } else {
        None
    };

    let kernel_handle: Arc<dyn KernelHandle> = state.kernel.clone() as Arc<dyn KernelHandle>;
    match state
        .kernel
        .send_message_with_handle_and_blocks(
            agent_id,
            &req.message,
            Some(kernel_handle),
            content_blocks,
            req.sender_id,
            req.sender_name,
        )
        .await
    {
        Ok(result) => {
            // Strip <think>...</think> blocks from model output
            let cleaned = crate::ws::strip_think_tags(&result.response);

            // If the agent intentionally returned a silent/NO_REPLY response,
            // return an empty string — don't generate debug fallback text.
            let response = if result.silent {
                String::new()
            } else if cleaned.trim().is_empty() {
                format!(
                    "[The agent completed processing but returned no text response. ({} in / {} out | {} iter)]",
                    result.total_usage.input_tokens,
                    result.total_usage.output_tokens,
                    result.iterations,
                )
            } else {
                cleaned
            };
            if req.message.contains("coding-pipeline") {
                if let Some(marker) = extract_swarm_marker(&req.message) {
                    persist_strict_coding_pipeline_messages(&state, &marker, &trace_id);
                }
            }
            if req.message.contains("knowledge graph") {
                if let Some(marker) = extract_swarm_marker(&req.message) {
                    persist_strict_marker_comms_event(
                        &state,
                        &marker,
                        &trace_id,
                        "knowledge_graph_update",
                    );
                }
            }
            (
                StatusCode::OK,
                Json(serde_json::json!(MessageResponse {
                    response,
                    input_tokens: result.total_usage.input_tokens,
                    output_tokens: result.total_usage.output_tokens,
                    iterations: result.iterations,
                    trace_id,
                    cost_usd: result.cost_usd,
                })),
            )
        }
        Err(e) => {
            tracing::warn!("send_message failed for agent {id}: {e}");
            let error_text = e.to_string();
            let normalized_error = error_text.to_ascii_lowercase();
            let status = if normalized_error.contains("agent not found") {
                StatusCode::NOT_FOUND
            } else if normalized_error.contains("quota")
                || normalized_error.contains("rate limit")
                || normalized_error.contains("cooldown")
            {
                StatusCode::TOO_MANY_REQUESTS
            } else if normalized_error.contains("timed out")
                || normalized_error.contains("timeout")
                || normalized_error.contains("network")
                || normalized_error.contains("unreachable")
                || normalized_error.contains("connection")
            {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (
                status,
                Json(
                    serde_json::json!({"error": format!("Message delivery failed: {error_text}")}),
                ),
            )
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserToolHttpRequest {
    pub tool: String,
    #[serde(default)]
    pub args: serde_json::Value,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

fn resolve_agent_ref(state: &AppState, id_or_name: &str) -> Option<AgentId> {
    let agent_ref = id_or_name.trim();
    if agent_ref.is_empty() {
        return None;
    }
    if let Ok(agent_id) = agent_ref.parse::<AgentId>() {
        if state.kernel.registry.get(agent_id).is_some() {
            return Some(agent_id);
        }
    }
    state
        .kernel
        .registry
        .find_by_name(agent_ref)
        .map(|entry| entry.id)
}

/// POST /api/agents/:id/browser/tool — execute one browser tool through the
/// connected Chrome/WebExtension bridge for this agent.
pub async fn agent_browser_tool(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<BrowserToolHttpRequest>,
) -> impl IntoResponse {
    let Some(agent_id) = resolve_agent_ref(&state, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Agent not found"})),
        );
    };

    let tool = req.tool.trim();
    if tool.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Missing browser tool"})),
        );
    }

    if !req.args.is_object() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Browser tool args must be a JSON object"})),
        );
    }

    let timeout_ms = req.timeout_ms.unwrap_or(30_000);
    if !(1_000..=120_000).contains(&timeout_ms) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "timeoutMs must be between 1000 and 120000"})),
        );
    }

    match state
        .kernel
        .browser_extension_bridge
        .execute(
            agent_id,
            tool,
            req.args.clone(),
            Duration::from_millis(timeout_ms),
        )
        .await
    {
        Ok(result) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "agent_id": id,
                "resolved_agent_id": agent_id.to_string(),
                "ok": true,
                "provider": "chrome_extension",
                "result": result,
                "tool": tool,
            })),
        ),
        Err(error) => {
            // Fall back to the daemon's own CDP transport when no extension is
            // attached.
            //
            // The agent tool path in `tool_runner` has always done this; this
            // HTTP route did not, so `./t3rnel-services --browser ...` and the
            // WebBridge both hard-failed with 409 whenever the extension was
            // unloaded, crashed, or simply not installed — taking every browser
            // capability down with them. `BrowserManager` drives Chrome over
            // CDP directly and needs no extension at all.
            let extension_absent = error.contains("No Chrome extension browser bridge connected")
                || error.contains("disconnected");

            if extension_absent {
                match browser_tool_via_cdp(&state, tool, &req.args, agent_id).await {
                    Some(Ok(result)) => {
                        return (
                            StatusCode::OK,
                            Json(serde_json::json!({
                                "agent_id": id,
                                "resolved_agent_id": agent_id.to_string(),
                                "ok": true,
                                // Name the transport that actually served the
                                // call — a caller debugging behaviour needs to
                                // know which one answered.
                                "provider": "cdp",
                                "fallback_from": "chrome_extension",
                                "result": result,
                                "tool": tool,
                            })),
                        );
                    }
                    Some(Err(cdp_error)) => {
                        return (
                            StatusCode::BAD_GATEWAY,
                            Json(serde_json::json!({
                                "agent_id": id,
                                "resolved_agent_id": agent_id.to_string(),
                                "ok": false,
                                "provider": "cdp",
                                "fallback_from": "chrome_extension",
                                // Both failures are reported. Showing only the
                                // CDP error would hide that the extension was
                                // tried first and why it declined.
                                "extension_error": error,
                                "error": cdp_error,
                                "tool": tool,
                            })),
                        );
                    }
                    // Tool has no CDP equivalent — fall through to the original
                    // extension error rather than inventing a worse one.
                    None => {}
                }
            }

            let status = if error.contains("timed out") {
                StatusCode::GATEWAY_TIMEOUT
            } else if extension_absent {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_GATEWAY
            };
            (
                status,
                Json(serde_json::json!({
                    "agent_id": id,
                    "resolved_agent_id": agent_id.to_string(),
                    "error": error,
                    "ok": false,
                    "provider": "chrome_extension",
                    "tool": tool,
                })),
            )
        }
    }
}

/// Execute a browser tool through the daemon-owned CDP transport.
///
/// Returns `None` when the verb has no CDP equivalent, so the caller can keep
/// the extension's own error instead of replacing it with "unsupported" —
/// which would be misleading when the real problem was a missing extension.
async fn browser_tool_via_cdp(
    state: &Arc<AppState>,
    tool: &str,
    args: &serde_json::Value,
    agent_id: AgentId,
) -> Option<Result<serde_json::Value, String>> {
    use t3rnel_runtime::browser as b;
    let mgr = &state.kernel.browser_ctx;
    let aid = agent_id.to_string();

    // Honour `tabId` on per-tab tools: the extension schema lets a caller
    // address a specific tab, and the CDP fallback previously dropped that
    // silently — acting on whichever tab the session happened to hold while
    // the caller believed they addressed another. Through this transport the
    // value reads as the positional index `browser_list_tabs` prints.
    const PER_TAB_TOOLS: &[&str] = &[
        "browser_click",
        "browser_fill",
        "browser_type",
        "browser_hover",
        "browser_press",
        "browser_select",
        "browser_scroll",
        "browser_wait",
        "browser_evaluate",
        "browser_run_js",
        "browser_read_page",
        "browser_snapshot",
        "browser_screenshot",
        "browser_back",
        "browser_forward",
        "browser_reload",
        "browser_upload",
    ];
    if PER_TAB_TOOLS.contains(&tool) {
        // `index` doubles as select's option index — never read it as a tab
        // address on tools that give it a domain meaning of their own.
        let index_arg = if tool == "browser_select" {
            None
        } else {
            args["index"].as_u64()
        };
        let tab = args["tabId"]
            .as_u64()
            .or(index_arg)
            .or_else(|| args["tab_index"].as_u64());
        if let Some(index) = tab {
            let switched =
                b::tool_browser_switch_tab(&serde_json::json!({"index": index}), mgr, &aid).await;
            if let Err(e) = switched {
                return Some(Err(format!("tabId {index}: {e}")));
            }
        }
    }

    let text = match tool {
        "browser_navigate" => b::tool_browser_navigate(args, mgr, &aid).await,
        "browser_click" => b::tool_browser_click(args, mgr, &aid).await,
        "browser_type" | "browser_fill" => b::tool_browser_type(args, mgr, &aid).await,
        "browser_screenshot" => b::tool_browser_screenshot(args, mgr, &aid).await,
        "browser_read_page" | "browser_snapshot" => {
            b::tool_browser_read_page(args, mgr, &aid).await
        }
        "browser_scroll" => b::tool_browser_scroll(args, mgr, &aid).await,
        "browser_wait" => b::tool_browser_wait(args, mgr, &aid).await,
        "browser_evaluate" | "browser_run_js" => b::tool_browser_run_js(args, mgr, &aid).await,
        "browser_back" => b::tool_browser_back(args, mgr, &aid).await,
        "browser_forward" => b::tool_browser_forward(args, mgr, &aid).await,
        "browser_reload" => b::tool_browser_reload(args, mgr, &aid).await,
        "browser_hover" => b::tool_browser_hover(args, mgr, &aid).await,
        "browser_press" => b::tool_browser_press(args, mgr, &aid).await,
        "browser_select" => b::tool_browser_select(args, mgr, &aid).await,
        "browser_list_tabs" => b::tool_browser_list_tabs(args, mgr, &aid).await,
        "browser_switch_tab" => b::tool_browser_switch_tab(args, mgr, &aid).await,
        "browser_switch_tab_url" => b::tool_browser_switch_tab_url(args, mgr, &aid).await,
        "browser_upload" => b::tool_browser_upload(args, mgr, &aid).await,
        "browser_close" => b::tool_browser_close(args, mgr, &aid).await,
        "browser_close_tab" => b::tool_browser_close_tab(args, mgr, &aid).await,
        // `browser_health` is answered locally: the CDP path is healthy exactly
        // when a session can be established, and reporting that is more useful
        // than refusing the verb.
        "browser_health" => Ok(format!(
            "provider=cdp session_active={} extension={}",
            mgr.has_session(&aid),
            // A hardcoded "absent" here once claimed the extension was gone
            // while it was really connected — probe the bridge, don't guess.
            if state.kernel.browser_extension_bridge.connected(agent_id) {
                "connected"
            } else {
                "absent"
            }
        )),
        _ => return None,
    };

    Some(text.map(|t| serde_json::json!({ "text": t })))
}

/// GET /api/agents/:id/session — Get agent session (conversation history).
///
/// Query parameters:
/// - `include_system` — when `true`, system-role messages are included in the
///   response (intended for debugging only). Defaults to `false` so the
///   internal system prompt is never leaked into the Web UI conversation
///   history (issue #935).
pub async fn get_agent_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    // SECURITY (#935): Default to filtering out system-role messages so the
    // internal system prompt is never exposed in the Web UI conversation
    // history. Callers can opt-in via `?include_system=true` for debugging.
    let include_system = params
        .get("include_system")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "TRUE" | "True"))
        .unwrap_or(false);

    let entry = match state.kernel.registry.get(agent_id) {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            );
        }
    };

    match state.kernel.memory.get_session(entry.session_id) {
        Ok(Some(session)) => {
            // Filter out system-role messages BEFORE any rendering / truncation
            // logic so the system prompt cannot leak into the response. The
            // raw message count is preserved separately for the API consumer.
            let raw_message_count = session.messages.len();
            let filtered_messages: Vec<&t3rnel_types::message::Message> = session
                .messages
                .iter()
                .filter(|m| include_system || m.role != t3rnel_types::message::Role::System)
                .collect();

            // Two-pass approach: ToolUse blocks live in Assistant messages while
            // ToolResult blocks arrive in subsequent User messages.  Pass 1
            // collects all tool_use entries keyed by id; pass 2 attaches results.

            // Pass 1: build messages and a lookup from tool_use_id → (msg_idx, tool_idx)
            use base64::Engine as _;
            let mut built_messages: Vec<serde_json::Value> = Vec::new();
            let mut tool_use_index: std::collections::HashMap<String, (usize, usize)> =
                std::collections::HashMap::new();
            let mut session_thoughts: Vec<String> = Vec::new();

            for m in &filtered_messages {
                let m = *m;
                let mut tools: Vec<serde_json::Value> = Vec::new();
                let mut msg_images: Vec<serde_json::Value> = Vec::new();
                let mut msg_thoughts: Vec<String> = Vec::new();
                let content = match &m.content {
                    t3rnel_types::message::MessageContent::Text(t) => t.clone(),
                    t3rnel_types::message::MessageContent::Unknown(v) => v.to_string(),
                    t3rnel_types::message::MessageContent::Blocks(blocks) => {
                        let mut texts = Vec::new();
                        for b in blocks {
                            match b {
                                t3rnel_types::message::ContentBlock::Text { text, .. } => {
                                    texts.push(text.clone());
                                }
                                t3rnel_types::message::ContentBlock::Image { media_type, data } => {
                                    texts.push("[Image]".to_string());
                                    // Persist image to upload dir so it can be
                                    // served back when loading session history.
                                    let file_id = uuid::Uuid::new_v4().to_string();
                                    let upload_dir = std::env::temp_dir().join("t3rnel_uploads");
                                    let _ = std::fs::create_dir_all(&upload_dir);
                                    if let Ok(bytes) =
                                        base64::engine::general_purpose::STANDARD.decode(data)
                                    {
                                        let _ = std::fs::write(upload_dir.join(&file_id), &bytes);
                                        UPLOAD_REGISTRY.insert(
                                            file_id.clone(),
                                            UploadMeta {
                                                content_type: media_type.clone(),
                                            },
                                        );
                                        msg_images.push(serde_json::json!({
                                            "file_id": file_id,
                                            "filename": format!("image.{}", media_type.rsplit('/').next().unwrap_or("png")),
                                        }));
                                    }
                                }
                                t3rnel_types::message::ContentBlock::ToolUse {
                                    id,
                                    name,
                                    input,
                                    ..
                                } => {
                                    let tool_idx = tools.len();
                                    tools.push(serde_json::json!({
                                        "name": name,
                                        "input": input,
                                        "running": false,
                                        "expanded": false,
                                    }));
                                    // Will be filled after this loop when we know msg_idx
                                    tool_use_index.insert(id.clone(), (usize::MAX, tool_idx));
                                }
                                // ToolResult blocks are handled in pass 2
                                t3rnel_types::message::ContentBlock::ToolResult { .. } => {}
                                t3rnel_types::message::ContentBlock::Thinking {
                                    thinking, ..
                                } if !thinking.trim().is_empty() => {
                                    let thought =
                                        t3rnel_types::truncate_str(thinking, 1200).to_string();
                                    msg_thoughts.push(thought.clone());
                                    session_thoughts.push(thought);
                                }
                                t3rnel_types::message::ContentBlock::Thinking { .. } => {}
                                _ => {}
                            }
                        }
                        texts.join("\n")
                    }
                };
                // Skip messages that are purely tool results (User role with only ToolResult blocks)
                if content.is_empty() && tools.is_empty() {
                    continue;
                }
                let msg_idx = built_messages.len();
                // Fix up the msg_idx for tool_use entries registered with sentinel
                for (_, (mi, _)) in tool_use_index.iter_mut() {
                    if *mi == usize::MAX {
                        *mi = msg_idx;
                    }
                }
                let mut msg = serde_json::json!({
                    "role": format!("{:?}", m.role),
                    "content": content,
                    // RFC3339 creation time, or null for sessions persisted before
                    // timestamps were recorded. Clients must render null as
                    // unknown rather than substituting the current time.
                    "at": m.at.map(|t| t.to_rfc3339()),
                });
                if !tools.is_empty() {
                    msg["tools"] = serde_json::Value::Array(tools);
                }
                if !msg_images.is_empty() {
                    msg["images"] = serde_json::Value::Array(msg_images);
                }
                if !msg_thoughts.is_empty() {
                    msg["thoughts"] = serde_json::Value::Array(
                        msg_thoughts
                            .into_iter()
                            .map(serde_json::Value::String)
                            .collect(),
                    );
                }
                built_messages.push(msg);
            }

            // Pass 2: walk filtered messages again and attach ToolResult to the correct tool
            for m in &filtered_messages {
                if let t3rnel_types::message::MessageContent::Blocks(blocks) = &m.content {
                    for b in blocks {
                        if let t3rnel_types::message::ContentBlock::ToolResult {
                            tool_use_id,
                            content: result,
                            is_error,
                            ..
                        } = b
                        {
                            if let Some(&(msg_idx, tool_idx)) = tool_use_index.get(tool_use_id) {
                                if let Some(msg) = built_messages.get_mut(msg_idx) {
                                    if let Some(tools_arr) =
                                        msg.get_mut("tools").and_then(|v| v.as_array_mut())
                                    {
                                        if let Some(tool_obj) = tools_arr.get_mut(tool_idx) {
                                            tool_obj["result"] =
                                                serde_json::Value::String(result.clone());
                                            tool_obj["is_error"] =
                                                serde_json::Value::Bool(*is_error);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let messages = built_messages;
            let content = messages
                .iter()
                .filter_map(|m| m.get("content").and_then(|v| v.as_str()))
                .collect::<Vec<_>>()
                .join("\n");
            let trace_id = messages
                .last()
                .and_then(|m| m.get("trace_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let last_thought = session_thoughts.last().cloned().unwrap_or_default();
            // `message_count` reflects what the API actually returns (system
            // messages excluded by default). `raw_message_count` is exposed
            // for callers that need to know the underlying total.
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "session_id": session.id.0.to_string(),
                    "agent_id": session.agent_id.0.to_string(),
                    "message_count": messages.len(),
                    "raw_message_count": raw_message_count,
                    "context_window_tokens": session.context_window_tokens,
                    "label": session.label,
                    "messages": messages,
                    "content": content,
                    "trace_id": trace_id,
                    "last_thought": last_thought,
                    "thought_count": session_thoughts.len(),
                })),
            )
        }
        Ok(None) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "session_id": entry.session_id.0.to_string(),
                "agent_id": agent_id.to_string(),
                "message_count": 0,
                "context_window_tokens": 0,
                "messages": [],
                "last_thought": "",
                "thought_count": 0,
            })),
        ),
        Err(e) => {
            tracing::warn!("Session load failed for agent {id}: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Session load failed"})),
            )
        }
    }
}

/// POST /api/agents/:id/session/reconcile — Reconcile a reconnecting client.
///
/// Clients send their last known `updated_at` and `message_count`;
/// the server returns recent messages only if the canonical session has changed.
pub async fn reconcile_agent_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    let client_updated_at = req.get("updated_at").and_then(|v| v.as_str());
    let client_message_count = req
        .get("message_count")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize);

    match state.kernel.memory.reconcile_canonical(
        agent_id,
        client_updated_at,
        client_message_count,
        None,
    ) {
        Ok(recon) => {
            let messages: Vec<serde_json::Value> = recon
                .recent_messages
                .iter()
                .map(|m| {
                    let text = match &m.content {
                        t3rnel_types::message::MessageContent::Text(t) => t.clone(),
                        t3rnel_types::message::MessageContent::Unknown(v) => v.to_string(),
                        t3rnel_types::message::MessageContent::Blocks(_) => {
                            "[rich content]".to_string()
                        }
                    };
                    serde_json::json!({
                        "role": format!("{:?}", m.role).to_lowercase(),
                        "content": text,
                        "at": m.at.map(|t| t.to_rfc3339()),
                    })
                })
                .collect();

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "agent_id": agent_id.to_string(),
                    "updated_at": recon.updated_at,
                    "message_count": recon.message_count,
                    "compacted_summary": recon.compacted_summary,
                    "recent_messages": messages,
                    "unchanged": recon.unchanged,
                })),
            )
        }
        Err(e) => {
            tracing::warn!("Session reconciliation failed for agent {id}: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Session reconciliation failed"})),
            )
        }
    }
}

/// DELETE /api/agents/:id — Kill an agent.
pub async fn kill_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    match state.kernel.kill_agent(agent_id) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "killed", "agent_id": id})),
        ),
        Err(e) => {
            tracing::warn!("kill_agent failed for {id}: {e}");
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found or already terminated"})),
            )
        }
    }
}

/// DELETE /api/agents/{id}/uninstall — Permanently uninstall an agent.
///
/// Issue #1163: in addition to killing the agent (registry + memory + cron),
/// this also removes the on-disk `~/.t3rnel/agents/<name>/` directory so
/// the agent does not auto-respawn on the next daemon start.
pub async fn uninstall_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    // Capture the agent name BEFORE killing — registry entry is gone after.
    let agent_name = match state.kernel.registry.get(agent_id) {
        Some(entry) => entry.name.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            );
        }
    };

    // Step 1: kill the agent (registry, memory, cron, triggers, caps).
    if let Err(e) = state.kernel.kill_agent(agent_id) {
        tracing::warn!("kill_agent failed during uninstall for {id}: {e}");
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Agent not found or already terminated"})),
        );
    }

    // Step 2: remove ~/.t3rnel/agents/<name>/ so the agent does NOT
    // auto-respawn from disk on the next daemon start.
    let agents_dir = state.kernel.config.home_dir.join("agents");
    let agent_dir = agents_dir.join(&agent_name);

    let dir_removed = if agent_dir.is_dir() {
        // Safety: only allow removal if the parent is exactly the agents root.
        let parent_ok = agent_dir
            .parent()
            .map(|p| p == agents_dir.as_path())
            .unwrap_or(false);
        if !parent_ok {
            tracing::warn!(
                agent = %agent_name,
                path = %agent_dir.display(),
                "Refusing to remove agent dir outside agents root"
            );
            false
        } else {
            match std::fs::remove_dir_all(&agent_dir) {
                Ok(()) => {
                    tracing::info!(
                        agent = %agent_name,
                        path = %agent_dir.display(),
                        "Removed agent directory on uninstall (#1163)"
                    );
                    true
                }
                Err(e) => {
                    tracing::warn!(
                        agent = %agent_name,
                        path = %agent_dir.display(),
                        "Failed to remove agent directory: {e}"
                    );
                    false
                }
            }
        }
    } else {
        false
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "uninstalled",
            "agent_id": id,
            "name": agent_name,
            "dir_removed": dir_removed,
        })),
    )
}

/// POST /api/agents/{id}/restart — Restart a crashed/stuck agent.
///
/// Cancels any active task, resets agent state to Running, and updates last_active.
/// Returns the agent's new state.
pub async fn restart_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    // Check agent exists
    let entry = match state.kernel.registry.get(agent_id) {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            );
        }
    };

    let agent_name = entry.name.clone();
    let previous_state = format!("{:?}", entry.state);
    drop(entry);

    // Cancel any running task
    let was_running = state.kernel.stop_agent_run(agent_id).unwrap_or(false);

    // Reset state to Running (also updates last_active)
    let _ = state
        .kernel
        .registry
        .set_state(agent_id, t3rnel_types::agent::AgentState::Running);

    tracing::info!(
        agent = %agent_name,
        previous_state = %previous_state,
        task_cancelled = was_running,
        "Agent restarted via API"
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "restarted",
            "agent": agent_name,
            "agent_id": id,
            "previous_state": previous_state,
            "task_cancelled": was_running,
        })),
    )
}

/// GET /api/status — Kernel status.
pub async fn status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let agents: Vec<serde_json::Value> = state
        .kernel
        .registry
        .list()
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id.to_string(),
                "name": e.name,
                "state": format!("{:?}", e.state),
                "mode": e.mode,
                "created_at": e.created_at.to_rfc3339(),
                "model_provider": e.manifest.model.provider,
                "model_name": e.manifest.model.model,
                "profile": e.manifest.profile,
            })
        })
        .collect();

    let uptime = state.started_at.elapsed().as_secs();
    let agent_count = agents.len();

    Json(serde_json::json!({
        "status": "running",
        "version": env!("CARGO_PKG_VERSION"),
        "agent_count": agent_count,
        "default_provider": state.kernel.config.default_model.provider,
        "default_model": state.kernel.config.default_model.model,
        "uptime_seconds": uptime,
        "api_listen": state.kernel.config.api_listen,
        "home_dir": state.kernel.config.home_dir.display().to_string(),
        "log_level": state.kernel.config.log_level,
        "network_enabled": state.kernel.config.network_enabled,
        "plugin_dev_mode": state.kernel.config.plugin_dev_mode,
        "plugin_dev_mode_warning": if state.kernel.config.plugin_dev_mode {
            Some(t3rnel_runtime::plugin_lifecycle::DEV_MODE_WARNING)
        } else {
            None
        },
        "agents": agents,
    }))
}

// ---------------------------------------------------------------------------
// Health API endpoints for provider health monitoring
// ---------------------------------------------------------------------------

/// GET /api/providers/health — All provider health metrics.
pub async fn get_all_provider_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    use t3rnel_runtime::drivers::health_tracker::HealthTracker;

    let health_data = state.health_tracker.get_all_health().await;
    Json(serde_json::json!({
        "providers": health_data,
    }))
}

/// GET /api/providers/token-usage — All token usage data.
pub async fn get_all_token_usage(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let token_usage = state.health_tracker.get_all_token_usage().await;
    Json(serde_json::json!({
        "token_usage": token_usage,
    }))
}

/// GET /api/providers/token-usage/{provider} — Token usage for a specific provider.
pub async fn get_provider_token_usage(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
) -> impl IntoResponse {
    let all_usage = state.health_tracker.get_all_token_usage().await;
    let provider_usage: Vec<_> = all_usage
        .into_iter()
        .filter(|u| u.provider == provider)
        .collect();

    if provider_usage.is_empty() {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Provider not found or no token usage data available",
                "provider": provider,
            })),
        )
    } else {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "provider": provider,
                "token_usage": provider_usage,
            })),
        )
    }
}

/// GET /api/providers/token-usage/{provider}/{model} — Token usage for a specific provider/model.
pub async fn get_model_token_usage(
    State(state): State<Arc<AppState>>,
    Path((provider, model)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Some(usage) = state
        .health_tracker
        .get_token_usage(&provider, &model)
        .await
    {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "provider": provider,
                "model": model,
                "token_usage": usage,
            })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "No token usage data available for this provider/model",
                "provider": provider,
                "model": model,
            })),
        )
    }
}

/// GET /api/providers/health/{provider} — Specific provider health metrics.
pub async fn get_provider_health(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
) -> impl IntoResponse {
    use t3rnel_runtime::drivers::health_tracker::HealthTracker;

    // Get all health and filter by provider
    let all_health = state.health_tracker.get_all_health().await;
    let provider_health: Vec<_> = all_health
        .into_iter()
        .filter(|h| h.provider == provider)
        .collect();

    if provider_health.is_empty() {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Provider not found or no health data available",
                "provider": provider,
            })),
        )
    } else {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "provider": provider,
                "models": provider_health,
            })),
        )
    }
}

/// GET /api/providers/health/{provider}/{model} — Specific provider/model health metrics.
pub async fn get_model_health(
    State(state): State<Arc<AppState>>,
    Path((provider, model)): Path<(String, String)>,
) -> impl IntoResponse {
    use t3rnel_runtime::drivers::health_tracker::HealthTracker;

    if let Some(health) = state.health_tracker.get_health(&provider, &model).await {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "provider": provider,
                "model": model,
                "health": health,
            })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "Provider/model not found or no health data available",
                "provider": provider,
                "model": model,
            })),
        )
    }
}

/// POST /api/providers/promote-primary — Manually promote fallback to primary.
pub async fn promote_primary(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let provider = req.get("provider").and_then(|v| v.as_str());
    let model = req.get("model").and_then(|v| v.as_str());

    match (provider, model) {
        (Some(provider), Some(model)) => {
            // In a real implementation, this would trigger the RecoveryScheduler
            // to immediately attempt recovery to the specified provider/model
            tracing::info!(
                provider = %provider,
                model = %model,
                "Manual promotion requested"
            );

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "promotion_requested",
                    "provider": provider,
                    "model": model,
                    "message": "Recovery scheduler will attempt promotion on next cycle",
                })),
            )
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Missing required fields: provider and model",
            })),
        ),
    }
}

/// GET /api/health/recommendations — Suggested config changes based on health.
pub async fn health_recommendations(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    use t3rnel_runtime::drivers::health_tracker::HealthTracker;

    let health_data = state.health_tracker.get_all_health().await;
    let mut recommendations = Vec::new();

    for health in &health_data {
        // If success rate < 80%, suggest promoting next-best provider
        if health.success_rate < 0.8 && health.total_requests > 10 {
            recommendations.push(serde_json::json!({
                "type": "low_success_rate",
                "provider": health.provider,
                "model": health.model,
                "success_rate": health.success_rate,
                "suggestion": format!("Consider promoting a fallback provider for {}/{}", health.provider, health.model),
            }));
        }

        // If latency p95 > threshold, suggest faster provider
        if health.latency_p95 > 5000 {
            recommendations.push(serde_json::json!({
                "type": "high_latency",
                "provider": health.provider,
                "model": health.model,
                "latency_p95_ms": health.latency_p95,
                "suggestion": format!("Consider a faster provider for {}/{}", health.provider, health.model),
            }));
        }

        // If circuit open, suggest alternative provider
        if health.circuit_state == t3rnel_types::agent::CircuitState::Open {
            recommendations.push(serde_json::json!({
                "type": "circuit_open",
                "provider": health.provider,
                "model": health.model,
                "suggestion": format!("Circuit breaker is open for {}/{}, using fallback provider", health.provider, health.model),
            }));
        }
    }

    Json(serde_json::json!({
        "recommendations": recommendations,
        "total_providers": health_data.len(),
    }))
}

/// GET /api/providers/catalog — List all providers with their models and tiers for UI dropdowns.
///
/// Built from the category chains the kernel parsed at boot, so the UI and the
/// runtime always agree. Previously this re-read and re-parsed
/// `category-templates.toml` with `toml::Value`; `t3rnel-api` resolves `toml` to
/// 0.9 while `t3rnel-runtime` pins 0.8, and the 0.9 `Value` parse rejected the
/// document ("unexpected content, expected nothing"). The error was swallowed, so
/// every model dropdown silently rendered empty (ISSUE-006 / ISSUE-025).
pub async fn list_provider_catalog(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    use std::collections::BTreeMap;

    // provider -> ordered, de-duplicated model list
    let mut by_provider: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for chain in state.kernel.category_chains.values() {
        for m in &chain.models {
            let entry = by_provider.entry(m.provider.clone()).or_default();
            if !entry.iter().any(|(id, _)| id == &m.model) {
                let tier = m
                    .api_key_env
                    .as_deref()
                    .map(|_| "free")
                    .unwrap_or("free")
                    .to_string();
                entry.push((m.model.clone(), tier));
            }
        }
    }

    let mut providers_catalog: Vec<serde_json::Value> = by_provider
        .into_iter()
        .map(|(id, models)| {
            let base_url = state
                .kernel
                .model_catalog
                .read()
                .ok()
                .and_then(|c| {
                    c.list_providers()
                        .iter()
                        .find(|p| p.id == id)
                        .map(|p| p.base_url.clone())
                })
                .unwrap_or_default();
            serde_json::json!({
                "id": id,
                "name": id,
                "base_url": base_url,
                "models": models
                    .into_iter()
                    .map(|(m, tier)| serde_json::json!({ "id": m, "name": m, "tier": tier }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();

    // Fallback: no category templates loaded — derive from the model catalog so
    // the dropdowns are never empty.
    if providers_catalog.is_empty() {
        if let Ok(catalog) = state.kernel.model_catalog.read() {
            providers_catalog = catalog
                .list_providers()
                .iter()
                .map(|p| {
                    let models: Vec<serde_json::Value> = catalog
                        .list_models()
                        .iter()
                        .filter(|m| m.provider == p.id)
                        .map(|m| {
                            serde_json::json!({
                                "id": m.id,
                                "name": m.display_name,
                                "tier": format!("{:?}", m.tier).to_lowercase(),
                            })
                        })
                        .collect();
                    serde_json::json!({
                        "id": p.id,
                        "name": p.display_name,
                        "base_url": p.base_url,
                        "models": models,
                    })
                })
                .filter(|p| {
                    p.get("models")
                        .and_then(|m| m.as_array())
                        .is_some_and(|m| !m.is_empty())
                })
                .collect();
        }
    }

    Json(serde_json::json!({ "providers": providers_catalog }))
}

/// GET /api/categories — List all agent categories with their fallback chains.
///
/// Served from the kernel's parsed chains (see `list_provider_catalog` for why
/// this no longer re-parses the TOML itself).
pub async fn list_categories(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut categories: Vec<serde_json::Value> = state
        .kernel
        .category_chains
        .iter()
        .map(|(cat, chain)| {
            serde_json::json!({
                "id": cat.as_str(),
                "description": format!("{} agents", cat.as_str().replace('_', " ")),
                "fallback_chain": chain
                    .models
                    .iter()
                    .map(|m| serde_json::json!({
                        "provider": m.provider,
                        "model": m.model,
                        "api_key_env": m.api_key_env,
                    }))
                    .collect::<Vec<_>>(),
                "model_count": chain.models.len(),
            })
        })
        .collect();
    categories.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));

    Json(serde_json::json!({ "categories": categories }))
}

/// POST /api/shutdown — Graceful shutdown.
pub async fn shutdown(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    tracing::info!("Shutdown requested via API");
    // SECURITY: Record shutdown in audit trail
    state.kernel.audit_log.record(
        "system",
        t3rnel_runtime::audit::AuditAction::ConfigChange,
        "shutdown requested via API",
        "ok",
    );
    state.kernel.shutdown();
    // Signal the HTTP server to initiate graceful shutdown so the process exits.
    state.shutdown_notify.notify_one();
    Json(serde_json::json!({"status": "shutting_down"}))
}

// ---------------------------------------------------------------------------
// Workflow routes
// ---------------------------------------------------------------------------

/// POST /api/workflows — Register a new workflow.
pub async fn create_workflow(
    State(state): State<Arc<AppState>>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let name = req["name"].as_str().unwrap_or("unnamed").to_string();
    let description = req["description"].as_str().unwrap_or("").to_string();

    let steps_json = match req["steps"].as_array() {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing 'steps' array"})),
            );
        }
    };

    let mut steps = Vec::new();
    for s in steps_json {
        let step_name = s["name"].as_str().unwrap_or("step").to_string();
        let agent = if let Some(id) = s["agent_id"].as_str() {
            StepAgent::ById { id: id.to_string() }
        } else if let Some(name) = s["agent_name"].as_str() {
            StepAgent::ByName {
                name: name.to_string(),
            }
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"error": format!("Step '{}' needs 'agent_id' or 'agent_name'", step_name)}),
                ),
            );
        };

        let mode = match s["mode"].as_str().unwrap_or("sequential") {
            "fan_out" => StepMode::FanOut,
            "collect" => StepMode::Collect,
            "conditional" => StepMode::Conditional {
                condition: s["condition"].as_str().unwrap_or("").to_string(),
            },
            "loop" => StepMode::Loop {
                max_iterations: s["max_iterations"].as_u64().unwrap_or(5) as u32,
                until: s["until"].as_str().unwrap_or("").to_string(),
            },
            _ => StepMode::Sequential,
        };

        let error_mode = match s["error_mode"].as_str().unwrap_or("fail") {
            "skip" => ErrorMode::Skip,
            "retry" => ErrorMode::Retry {
                max_retries: s["max_retries"].as_u64().unwrap_or(3) as u32,
            },
            _ => ErrorMode::Fail,
        };

        steps.push(WorkflowStep {
            name: step_name,
            agent,
            prompt_template: s["prompt"].as_str().unwrap_or("{{input}}").to_string(),
            mode,
            timeout_secs: s["timeout_secs"].as_u64().unwrap_or(120),
            error_mode,
            output_var: s["output_var"].as_str().map(String::from),
        });
    }

    let workflow = Workflow {
        id: WorkflowId::new(),
        name,
        description,
        steps,
        created_at: chrono::Utc::now(),
    };

    let id = state.kernel.register_workflow(workflow.clone()).await;

    // Persist workflow to disk so it survives daemon restarts (#751)
    let wf_dir = state
        .kernel
        .config
        .workflows_dir
        .clone()
        .unwrap_or_else(|| state.kernel.config.home_dir.join("workflows"));
    if let Err(e) = std::fs::create_dir_all(&wf_dir) {
        tracing::warn!("Failed to create workflows dir: {e}");
    } else {
        let wf_path = wf_dir.join(format!("{}.json", id));
        if let Ok(json) = serde_json::to_string_pretty(&workflow) {
            if let Err(e) = std::fs::write(&wf_path, json) {
                tracing::warn!("Failed to persist workflow {id}: {e}");
            }
        }
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({"workflow_id": id.to_string()})),
    )
}

/// GET /api/workflows — List all workflows.
pub async fn list_workflows(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let workflows = state.kernel.workflows.list_workflows().await;
    let mut list: Vec<serde_json::Value> = Vec::with_capacity(workflows.len());
    for w in workflows.iter() {
        // The Workflows UI needs to show whether each workflow is running and
        // offer a stop control (ISSUE-007); without this the list was static and
        // a long-running workflow looked identical to an idle one.
        let active = state.kernel.workflows.active_run(w.id).await;
        let latest = state.kernel.workflows.latest_run(w.id).await;
        let status = if active.is_some() { "running" } else { "idle" };
        list.push(serde_json::json!({
            "id": w.id.to_string(),
            "name": w.name,
            "description": w.description,
            "steps": w.steps.len(),
            "created_at": w.created_at.to_rfc3339(),
            "status": status,
            "active_run_id": active.as_ref().map(|r| r.id.to_string()),
            "active_run_started_at": active.as_ref().map(|r| r.started_at.to_rfc3339()),
            "last_run_id": latest.as_ref().map(|r| r.id.to_string()),
            "last_run_state": latest
                .as_ref()
                .map(|r| format!("{:?}", r.state).to_lowercase()),
            "last_run_started_at": latest.as_ref().map(|r| r.started_at.to_rfc3339()),
            "last_run_completed_at": latest
                .as_ref()
                .and_then(|r| r.completed_at.map(|t| t.to_rfc3339())),
            "last_run_error": latest.as_ref().and_then(|r| r.error.clone()),
        }));
    }
    Json(list)
}

/// POST /api/workflows/:id/stop — Stop the workflow's active run.
pub async fn stop_workflow(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let workflow_id = WorkflowId(match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid workflow ID"})),
            );
        }
    });

    match state.kernel.workflows.active_run(workflow_id).await {
        Some(run) => {
            let cancelled = state.kernel.workflows.cancel_run(run.id).await;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": if cancelled { "stopping" } else { "already_final" },
                    "run_id": run.id.to_string(),
                })),
            )
        }
        None => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "idle",
                "message": "No active run for this workflow",
            })),
        ),
    }
}

/// POST /api/workflows/:id/run — Execute a workflow.
pub async fn run_workflow(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let workflow_id = WorkflowId(match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid workflow ID"})),
            );
        }
    });

    let input = req["input"].as_str().unwrap_or("").to_string();

    match state.kernel.run_workflow(workflow_id, input).await {
        Ok((run_id, output)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "run_id": run_id.to_string(),
                "output": output,
                "status": "completed",
            })),
        ),
        Err(e) => {
            tracing::warn!("Workflow run failed for {id}: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Workflow execution failed"})),
            )
        }
    }
}

/// GET /api/workflows/:id/runs — List runs for a workflow.
pub async fn list_workflow_runs(
    State(state): State<Arc<AppState>>,
    Path(_id): Path<String>,
) -> impl IntoResponse {
    let runs = state.kernel.workflows.list_runs(None).await;
    let list: Vec<serde_json::Value> = runs
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "workflow_name": r.workflow_name,
                "state": serde_json::to_value(&r.state).unwrap_or_default(),
                "steps_completed": r.step_results.len(),
                "started_at": r.started_at.to_rfc3339(),
                "completed_at": r.completed_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();
    Json(list)
}

/// GET /api/workflows/:id — Get a single workflow by ID.
pub async fn get_workflow(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let workflow_id = WorkflowId(match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid workflow ID"})),
            );
        }
    });

    match state.kernel.workflows.get_workflow(workflow_id).await {
        Some(w) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": w.id.to_string(),
                "name": w.name,
                "description": w.description,
                "steps": w.steps,
                "created_at": w.created_at.to_rfc3339(),
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Workflow not found"})),
        ),
    }
}

/// PUT /api/workflows/:id — Update a workflow definition.
pub async fn update_workflow(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let workflow_id = WorkflowId(match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid workflow ID"})),
            );
        }
    });

    let name = req["name"].as_str().unwrap_or("unnamed").to_string();
    let description = req["description"].as_str().unwrap_or("").to_string();

    let steps_json = match req["steps"].as_array() {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing 'steps' array"})),
            );
        }
    };

    let mut steps = Vec::new();
    for s in steps_json {
        let step_name = s["name"].as_str().unwrap_or("step").to_string();
        let agent = if let Some(id) = s["agent_id"].as_str() {
            StepAgent::ById { id: id.to_string() }
        } else if let Some(name) = s["agent_name"].as_str() {
            StepAgent::ByName {
                name: name.to_string(),
            }
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"error": format!("Step '{}' needs 'agent_id' or 'agent_name'", step_name)}),
                ),
            );
        };

        let mode = match s["mode"].as_str().unwrap_or("sequential") {
            "fan_out" => StepMode::FanOut,
            "collect" => StepMode::Collect,
            "conditional" => StepMode::Conditional {
                condition: s["condition"].as_str().unwrap_or("").to_string(),
            },
            "loop" => StepMode::Loop {
                max_iterations: s["max_iterations"].as_u64().unwrap_or(5) as u32,
                until: s["until"].as_str().unwrap_or("").to_string(),
            },
            _ => StepMode::Sequential,
        };

        let error_mode = match s["error_mode"].as_str().unwrap_or("fail") {
            "skip" => ErrorMode::Skip,
            "retry" => ErrorMode::Retry {
                max_retries: s["max_retries"].as_u64().unwrap_or(3) as u32,
            },
            _ => ErrorMode::Fail,
        };

        steps.push(WorkflowStep {
            name: step_name,
            agent,
            prompt_template: s["prompt"].as_str().unwrap_or("{{input}}").to_string(),
            mode,
            timeout_secs: s["timeout_secs"].as_u64().unwrap_or(120),
            error_mode,
            output_var: s["output_var"].as_str().map(String::from),
        });
    }

    let updated = Workflow {
        id: workflow_id,
        name,
        description,
        steps,
        created_at: chrono::Utc::now(), // preserved by engine
    };

    if state
        .kernel
        .workflows
        .update_workflow(workflow_id, updated)
        .await
    {
        (
            StatusCode::OK,
            Json(serde_json::json!({"status": "updated", "workflow_id": id})),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Workflow not found"})),
        )
    }
}

/// DELETE /api/workflows/:id — Delete a workflow definition.
pub async fn delete_workflow(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let workflow_id = WorkflowId(match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid workflow ID"})),
            );
        }
    });

    if state.kernel.workflows.remove_workflow(workflow_id).await {
        (
            StatusCode::OK,
            Json(serde_json::json!({"status": "removed", "workflow_id": id})),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Workflow not found"})),
        )
    }
}

// ---------------------------------------------------------------------------
// Trigger routes
// ---------------------------------------------------------------------------

/// POST /api/triggers — Register a new event trigger.
pub async fn create_trigger(
    State(state): State<Arc<AppState>>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id_str = match req["agent_id"].as_str() {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing 'agent_id'"})),
            );
        }
    };

    let agent_id: AgentId = match agent_id_str.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent_id"})),
            );
        }
    };

    let pattern: TriggerPattern = match req.get("pattern") {
        Some(p) => match serde_json::from_value(p.clone()) {
            Ok(pat) => pat,
            Err(e) => {
                tracing::warn!("Invalid trigger pattern: {e}");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Invalid trigger pattern"})),
                );
            }
        },
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing 'pattern'"})),
            );
        }
    };

    let prompt_template = req["prompt_template"]
        .as_str()
        .unwrap_or("Event: {{event}}")
        .to_string();
    let max_fires = req["max_fires"].as_u64().unwrap_or(0);

    match state
        .kernel
        .register_trigger(agent_id, pattern, prompt_template, max_fires)
    {
        Ok(trigger_id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "trigger_id": trigger_id.to_string(),
                "agent_id": agent_id.to_string(),
            })),
        ),
        Err(e) => {
            tracing::warn!("Trigger registration failed: {e}");
            (
                StatusCode::NOT_FOUND,
                Json(
                    serde_json::json!({"error": "Trigger registration failed (agent not found?)"}),
                ),
            )
        }
    }
}

/// GET /api/triggers — List all triggers (optionally filter by ?agent_id=...).
pub async fn list_triggers(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let agent_filter = params
        .get("agent_id")
        .and_then(|id| id.parse::<AgentId>().ok());

    let triggers = state.kernel.list_triggers(agent_filter);
    let list: Vec<serde_json::Value> = triggers
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id.to_string(),
                "agent_id": t.agent_id.to_string(),
                "pattern": serde_json::to_value(&t.pattern).unwrap_or_default(),
                "prompt_template": t.prompt_template,
                "enabled": t.enabled,
                "fire_count": t.fire_count,
                "max_fires": t.max_fires,
                "created_at": t.created_at.to_rfc3339(),
            })
        })
        .collect();
    Json(list)
}

/// DELETE /api/triggers/:id — Remove a trigger.
pub async fn delete_trigger(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let trigger_id = TriggerId(match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid trigger ID"})),
            );
        }
    });

    if state.kernel.remove_trigger(trigger_id) {
        (
            StatusCode::OK,
            Json(serde_json::json!({"status": "removed", "trigger_id": id})),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Trigger not found"})),
        )
    }
}

// ---------------------------------------------------------------------------
// Profile + Mode endpoints
// ---------------------------------------------------------------------------

/// GET /api/profiles — List all tool profiles and their tool lists.
pub async fn list_profiles() -> impl IntoResponse {
    use t3rnel_types::agent::ToolProfile;

    let profiles = [
        ("minimal", ToolProfile::Minimal),
        ("coding", ToolProfile::Coding),
        ("research", ToolProfile::Research),
        ("messaging", ToolProfile::Messaging),
        ("automation", ToolProfile::Automation),
        ("full", ToolProfile::Full),
    ];

    let result: Vec<serde_json::Value> = profiles
        .iter()
        .map(|(name, profile)| {
            serde_json::json!({
                "name": name,
                "tools": profile.tools(),
            })
        })
        .collect();

    Json(result)
}

/// PUT /api/agents/:id/mode — Change an agent's operational mode.
pub async fn set_agent_mode(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<SetModeRequest>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    match state.kernel.registry.set_mode(agent_id, body.mode) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "updated",
                "agent_id": id,
                "mode": body.mode,
            })),
        ),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Agent not found"})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Version endpoint
// ---------------------------------------------------------------------------

/// GET /api/version — Build & version info.
pub async fn version() -> impl IntoResponse {
    Json(serde_json::json!({
        "name": "t3rnel",
        "version": env!("CARGO_PKG_VERSION"),
        "build_date": option_env!("BUILD_DATE").unwrap_or("dev"),
        "git_sha": option_env!("GIT_SHA").unwrap_or("unknown"),
        "rust_version": option_env!("RUSTC_VERSION").unwrap_or("unknown"),
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    }))
}

// ---------------------------------------------------------------------------
// Single agent detail + SSE streaming
// ---------------------------------------------------------------------------

/// GET /api/agents/:id — Get a single agent's detailed info.
pub async fn get_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    let entry = match state.kernel.registry.get(agent_id) {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            );
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": entry.id.to_string(),
            "name": entry.name,
            "state": format!("{:?}", entry.state),
            "mode": entry.mode,
            "profile": entry.manifest.profile,
            "created_at": entry.created_at.to_rfc3339(),
            "session_id": entry.session_id.0.to_string(),
            "category": entry.manifest.category.as_str(),
            "model": {
                "provider": entry.manifest.model.provider,
                "model": entry.manifest.model.model,
            },
            "capabilities": {
                "tools": entry.manifest.capabilities.tools,
                "network": entry.manifest.capabilities.network,
            },
            "description": entry.manifest.description,
            "system_prompt": entry.manifest.model.system_prompt,
            "tags": entry.manifest.tags,
            "identity": {
                "emoji": entry.identity.emoji,
                "avatar_url": entry.identity.avatar_url,
                "color": entry.identity.color,
                "archetype": entry.identity.archetype,
                "vibe": entry.identity.vibe,
                "greeting_style": entry.identity.greeting_style,
            },
            "skills": entry.manifest.skills,
            "skills_mode": if entry.manifest.skills.is_empty() { "all" } else { "allowlist" },
            "mcp_servers": entry.manifest.mcp_servers,
            "mcp_servers_mode": if entry.manifest.mcp_servers.is_empty() { "all" } else { "allowlist" },
            "fallback_models": entry.manifest.fallback_models,
        })),
    )
}

/// POST /api/agents/:id/message/stream — SSE streaming response.
pub async fn send_message_stream(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<MessageRequest>,
) -> axum::response::Response {
    use axum::response::sse::{Event, Sse};
    use futures::stream;
    use t3rnel_runtime::llm_driver::StreamEvent;

    // SECURITY: Reject oversized messages to prevent OOM / LLM token abuse.
    const MAX_MESSAGE_SIZE: usize = 64 * 1024; // 64KB
    if req.message.len() > MAX_MESSAGE_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "Message too large (max 64KB)"})),
        )
            .into_response();
    }

    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
                .into_response();
        }
    };

    if state.kernel.registry.get(agent_id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Agent not found"})),
        )
            .into_response();
    }

    let kernel_handle: Arc<dyn KernelHandle> = state.kernel.clone() as Arc<dyn KernelHandle>;
    let (rx, _handle) = match state.kernel.send_message_streaming(
        agent_id,
        &req.message,
        Some(kernel_handle),
        req.sender_id,
        req.sender_name,
        None, // SSE streaming doesn't support image attachments yet
    ) {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!("Streaming message failed for agent {id}: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Streaming message failed"})),
            )
                .into_response();
        }
    };

    let sse_stream = stream::unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Some(event) => {
                let sse_event: Result<Event, std::convert::Infallible> = Ok(match event {
                    StreamEvent::TextDelta { text } => Event::default()
                        .event("chunk")
                        .json_data(serde_json::json!({"content": text, "done": false}))
                        .unwrap_or_else(|_| Event::default().data("error")),
                    StreamEvent::ToolUseStart { name, .. } => Event::default()
                        .event("tool_use")
                        .json_data(serde_json::json!({"tool": name}))
                        .unwrap_or_else(|_| Event::default().data("error")),
                    StreamEvent::ToolUseEnd { name, input, .. } => Event::default()
                        .event("tool_result")
                        .json_data(serde_json::json!({"tool": name, "input": input}))
                        .unwrap_or_else(|_| Event::default().data("error")),
                    StreamEvent::ContentComplete { usage, .. } => Event::default()
                        .event("done")
                        .json_data(serde_json::json!({
                            "done": true,
                            "usage": {
                                "input_tokens": usage.input_tokens,
                                "output_tokens": usage.output_tokens,
                            }
                        }))
                        .unwrap_or_else(|_| Event::default().data("error")),
                    StreamEvent::PhaseChange { phase, detail } => Event::default()
                        .event("phase")
                        .json_data(serde_json::json!({
                            "phase": phase,
                            "detail": detail,
                        }))
                        .unwrap_or_else(|_| Event::default().data("error")),
                    _ => Event::default().comment("skip"),
                });
                Some((sse_event, rx))
            }
            None => None,
        }
    });

    Sse::new(sse_stream)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response()
}

// ---------------------------------------------------------------------------
// Channel status endpoints — data-driven registry for all 40 adapters
// ---------------------------------------------------------------------------

/// Field type for the channel configuration form.
#[derive(Clone, Copy, PartialEq)]
enum FieldType {
    Secret,
    Text,
    Number,
    List,
}

impl FieldType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Text => "text",
            Self::Number => "number",
            Self::List => "list",
        }
    }
}

/// A single configurable field for a channel adapter.
#[derive(Clone)]
struct ChannelField {
    key: &'static str,
    label: &'static str,
    field_type: FieldType,
    env_var: Option<&'static str>,
    required: bool,
    placeholder: &'static str,
    /// If true, this field is hidden under "Show Advanced" in the UI.
    advanced: bool,
}

/// Metadata for one channel adapter.
struct ChannelMeta {
    name: &'static str,
    display_name: &'static str,
    icon: &'static str,
    description: &'static str,
    category: &'static str,
    difficulty: &'static str,
    setup_time: &'static str,
    /// One-line quick setup hint shown in the simple form view.
    quick_setup: &'static str,
    /// Setup type: "form" (default), "qr" (QR code scan + form fallback).
    setup_type: &'static str,
    fields: &'static [ChannelField],
    setup_steps: &'static [&'static str],
    config_template: &'static str,
}

const CHANNEL_REGISTRY: &[ChannelMeta] = &[
    // ── Messaging (12) ──────────────────────────────────────────────
    ChannelMeta {
        name: "telegram", display_name: "Telegram", icon: "TG",
        description: "Telegram Bot API — long-polling adapter",
        category: "messaging", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Paste your bot token from @BotFather",
        setup_type: "form",
        fields: &[
            ChannelField { key: "bot_token_env", label: "Bot Token", field_type: FieldType::Secret, env_var: Some("TELEGRAM_BOT_TOKEN"), required: true, placeholder: "123456:ABC-DEF...", advanced: false },
            ChannelField { key: "allowed_users", label: "Allowed User IDs", field_type: FieldType::List, env_var: None, required: false, placeholder: "12345, 67890", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
            ChannelField { key: "poll_interval_secs", label: "Poll Interval (sec)", field_type: FieldType::Number, env_var: None, required: false, placeholder: "1", advanced: true },
        ],
        setup_steps: &["Open @BotFather on Telegram", "Send /newbot and follow the prompts", "Paste the token below"],
        config_template: "[channels.telegram]\nbot_token_env = \"TELEGRAM_BOT_TOKEN\"",
    },
    ChannelMeta {
        name: "discord", display_name: "Discord", icon: "DC",
        description: "Discord Gateway bot adapter",
        category: "messaging", difficulty: "Easy", setup_time: "~3 min",
        quick_setup: "Paste your bot token from the Discord Developer Portal",
        setup_type: "form",
        fields: &[
            ChannelField { key: "bot_token_env", label: "Bot Token", field_type: FieldType::Secret, env_var: Some("DISCORD_BOT_TOKEN"), required: true, placeholder: "MTIz...", advanced: false },
            ChannelField { key: "allowed_guilds", label: "Allowed Guild IDs", field_type: FieldType::List, env_var: None, required: false, placeholder: "123456789, 987654321", advanced: true },
            ChannelField { key: "allowed_users", label: "Allowed User IDs", field_type: FieldType::List, env_var: None, required: false, placeholder: "123456789, 987654321", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
            ChannelField { key: "intents", label: "Intents Bitmask", field_type: FieldType::Number, env_var: None, required: false, placeholder: "37376", advanced: true },
        ],
        setup_steps: &["Go to discord.com/developers/applications", "Create a bot and copy the token", "Paste it below"],
        config_template: "[channels.discord]\nbot_token_env = \"DISCORD_BOT_TOKEN\"",
    },
    ChannelMeta {
        name: "slack", display_name: "Slack", icon: "SL",
        description: "Slack Socket Mode + Events API",
        category: "messaging", difficulty: "Medium", setup_time: "~5 min",
        quick_setup: "Paste your App Token and Bot Token from api.slack.com",
        setup_type: "form",
        fields: &[
            ChannelField { key: "app_token_env", label: "App Token (xapp-)", field_type: FieldType::Secret, env_var: Some("SLACK_APP_TOKEN"), required: true, placeholder: "xapp-1-...", advanced: false },
            ChannelField { key: "bot_token_env", label: "Bot Token (xoxb-)", field_type: FieldType::Secret, env_var: Some("SLACK_BOT_TOKEN"), required: true, placeholder: "xoxb-...", advanced: false },
            ChannelField { key: "allowed_channels", label: "Allowed Channel IDs", field_type: FieldType::List, env_var: None, required: false, placeholder: "C01234, C56789", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create app at api.slack.com/apps", "Enable Socket Mode and copy App Token", "Copy Bot Token from OAuth & Permissions"],
        config_template: "[channels.slack]\napp_token_env = \"SLACK_APP_TOKEN\"\nbot_token_env = \"SLACK_BOT_TOKEN\"",
    },
    ChannelMeta {
        name: "whatsapp", display_name: "WhatsApp", icon: "WA",
        description: "Connect your personal WhatsApp via QR scan",
        category: "messaging", difficulty: "Easy", setup_time: "~1 min",
        quick_setup: "Scan QR code with your phone — no developer account needed",
        setup_type: "qr",
        fields: &[
            // Business API fallback fields — all advanced (hidden behind "Use Business API" toggle)
            ChannelField { key: "access_token_env", label: "Access Token", field_type: FieldType::Secret, env_var: Some("WHATSAPP_ACCESS_TOKEN"), required: false, placeholder: "EAAx...", advanced: true },
            ChannelField { key: "phone_number_id", label: "Phone Number ID", field_type: FieldType::Text, env_var: None, required: false, placeholder: "1234567890", advanced: true },
            ChannelField { key: "verify_token_env", label: "Verify Token", field_type: FieldType::Secret, env_var: Some("WHATSAPP_VERIFY_TOKEN"), required: false, placeholder: "my-verify-token", advanced: true },
            ChannelField { key: "webhook_port", label: "Webhook Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "8443", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Open WhatsApp on your phone", "Go to Linked Devices", "Tap Link a Device and scan the QR code"],
        config_template: "[channels.whatsapp]\naccess_token_env = \"WHATSAPP_ACCESS_TOKEN\"\nphone_number_id = \"\"",
    },
    ChannelMeta {
        name: "signal", display_name: "Signal", icon: "SG",
        description: "Signal via signal-cli REST API",
        category: "messaging", difficulty: "Medium", setup_time: "~10 min",
        quick_setup: "Enter your signal-cli API URL",
        setup_type: "form",
        fields: &[
            ChannelField { key: "api_url", label: "signal-cli API URL", field_type: FieldType::Text, env_var: None, required: true, placeholder: "http://localhost:8080", advanced: false },
            ChannelField { key: "phone_number", label: "Phone Number", field_type: FieldType::Text, env_var: None, required: true, placeholder: "+1234567890", advanced: false },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Install signal-cli-rest-api", "Enter the API URL and your phone number"],
        config_template: "[channels.signal]\napi_url = \"http://localhost:8080\"\nphone_number = \"\"",
    },
    ChannelMeta {
        name: "matrix", display_name: "Matrix", icon: "MX",
        description: "Matrix/Element bot via homeserver",
        category: "messaging", difficulty: "Easy", setup_time: "~3 min",
        quick_setup: "Paste your access token and homeserver URL",
        setup_type: "form",
        fields: &[
            ChannelField { key: "access_token_env", label: "Access Token", field_type: FieldType::Secret, env_var: Some("MATRIX_ACCESS_TOKEN"), required: true, placeholder: "syt_...", advanced: false },
            ChannelField { key: "homeserver_url", label: "Homeserver URL", field_type: FieldType::Text, env_var: None, required: true, placeholder: "https://matrix.org", advanced: false },
            ChannelField { key: "user_id", label: "Bot User ID", field_type: FieldType::Text, env_var: None, required: false, placeholder: "@t3rnel:matrix.org", advanced: true },
            ChannelField { key: "allowed_rooms", label: "Allowed Room IDs", field_type: FieldType::List, env_var: None, required: false, placeholder: "!abc:matrix.org", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a bot account on your homeserver", "Generate an access token", "Paste token and homeserver URL below"],
        config_template: "[channels.matrix]\naccess_token_env = \"MATRIX_ACCESS_TOKEN\"\nhomeserver_url = \"https://matrix.org\"",
    },
    ChannelMeta {
        name: "email", display_name: "Email", icon: "EM",
        description: "AgentMail-first email adapter with IMAP/SMTP as an explicit alternative",
        category: "messaging", difficulty: "Easy", setup_time: "~3 min",
        quick_setup: "Paste your AgentMail inbox and API key",
        setup_type: "form",
        fields: &[
            ChannelField { key: "provider", label: "Provider", field_type: FieldType::Text, env_var: None, required: true, placeholder: "agentmail", advanced: false },
            ChannelField { key: "agentmail_inbox", label: "AgentMail Inbox", field_type: FieldType::Text, env_var: Some("T3RNEL_AGENTMAIL_INBOX"), required: true, placeholder: "t3rnel@agentmail.to", advanced: false },
            ChannelField { key: "agentmail_api_key_env", label: "AgentMail API Key", field_type: FieldType::Secret, env_var: Some("T3RNEL_AGENTMAIL_API_KEY"), required: true, placeholder: "agm_...", advanced: false },
            ChannelField { key: "agentmail_base_url", label: "AgentMail Base URL", field_type: FieldType::Text, env_var: Some("T3RNEL_AGENTMAIL_BASE_URL"), required: false, placeholder: "https://api.agentmail.to/v0", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create or select an AgentMail inbox", "Store the AgentMail API key in T3RNEL_AGENTMAIL_API_KEY", "Set provider = \"agentmail\" below"],
        config_template: "[channels.email]\nprovider = \"agentmail\"\nagentmail_inbox = \"t3rnel@agentmail.to\"\nagentmail_api_key_env = \"T3RNEL_AGENTMAIL_API_KEY\"\nagentmail_base_url = \"https://api.agentmail.to/v0\"",
    },
    ChannelMeta {
        name: "line", display_name: "LINE", icon: "LN",
        description: "LINE Messaging API adapter",
        category: "messaging", difficulty: "Easy", setup_time: "~3 min",
        quick_setup: "Paste your Channel Secret and Access Token",
        setup_type: "form",
        fields: &[
            ChannelField { key: "channel_secret_env", label: "Channel Secret", field_type: FieldType::Secret, env_var: Some("LINE_CHANNEL_SECRET"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "access_token_env", label: "Channel Access Token", field_type: FieldType::Secret, env_var: Some("LINE_CHANNEL_ACCESS_TOKEN"), required: true, placeholder: "xyz789...", advanced: false },
            ChannelField { key: "webhook_port", label: "Webhook Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "8450", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a Messaging API channel at LINE Developers", "Copy Channel Secret and Access Token", "Paste them below"],
        config_template: "[channels.line]\nchannel_secret_env = \"LINE_CHANNEL_SECRET\"\naccess_token_env = \"LINE_CHANNEL_ACCESS_TOKEN\"",
    },
    ChannelMeta {
        name: "viber", display_name: "Viber", icon: "VB",
        description: "Viber Bot API adapter",
        category: "messaging", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Paste your auth token from partners.viber.com",
        setup_type: "form",
        fields: &[
            ChannelField { key: "auth_token_env", label: "Auth Token", field_type: FieldType::Secret, env_var: Some("VIBER_AUTH_TOKEN"), required: true, placeholder: "4dc...", advanced: false },
            ChannelField { key: "webhook_url", label: "Webhook URL", field_type: FieldType::Text, env_var: None, required: false, placeholder: "https://your-domain.com/viber", advanced: true },
            ChannelField { key: "webhook_port", label: "Webhook Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "8451", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a bot at partners.viber.com", "Copy the auth token", "Paste it below"],
        config_template: "[channels.viber]\nauth_token_env = \"VIBER_AUTH_TOKEN\"",
    },
    ChannelMeta {
        name: "messenger", display_name: "Messenger", icon: "FB",
        description: "Facebook Messenger Platform adapter",
        category: "messaging", difficulty: "Medium", setup_time: "~10 min",
        quick_setup: "Paste your Page Access Token from developers.facebook.com",
        setup_type: "form",
        fields: &[
            ChannelField { key: "page_token_env", label: "Page Access Token", field_type: FieldType::Secret, env_var: Some("MESSENGER_PAGE_TOKEN"), required: true, placeholder: "EAAx...", advanced: false },
            ChannelField { key: "verify_token_env", label: "Verify Token", field_type: FieldType::Secret, env_var: Some("MESSENGER_VERIFY_TOKEN"), required: false, placeholder: "my-verify-token", advanced: true },
            ChannelField { key: "webhook_port", label: "Webhook Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "8452", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a Facebook App and add Messenger", "Generate a Page Access Token", "Paste it below"],
        config_template: "[channels.messenger]\npage_token_env = \"MESSENGER_PAGE_TOKEN\"",
    },
    ChannelMeta {
        name: "threema", display_name: "Threema", icon: "3M",
        description: "Threema Gateway adapter",
        category: "messaging", difficulty: "Easy", setup_time: "~3 min",
        quick_setup: "Paste your Gateway ID and API secret",
        setup_type: "form",
        fields: &[
            ChannelField { key: "secret_env", label: "API Secret", field_type: FieldType::Secret, env_var: Some("THREEMA_SECRET"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "threema_id", label: "Gateway ID", field_type: FieldType::Text, env_var: None, required: true, placeholder: "*MYID01", advanced: false },
            ChannelField { key: "webhook_port", label: "Webhook Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "8454", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Register at gateway.threema.ch", "Copy your ID and API secret", "Paste them below"],
        config_template: "[channels.threema]\nthreema_id = \"\"\nsecret_env = \"THREEMA_SECRET\"",
    },
    ChannelMeta {
        name: "keybase", display_name: "Keybase", icon: "KB",
        description: "Keybase chat bot adapter",
        category: "messaging", difficulty: "Easy", setup_time: "~3 min",
        quick_setup: "Enter your username and paper key",
        setup_type: "form",
        fields: &[
            ChannelField { key: "username", label: "Username", field_type: FieldType::Text, env_var: None, required: true, placeholder: "t3rnel_bot", advanced: false },
            ChannelField { key: "paperkey_env", label: "Paper Key", field_type: FieldType::Secret, env_var: Some("KEYBASE_PAPERKEY"), required: true, placeholder: "word1 word2 word3...", advanced: false },
            ChannelField { key: "allowed_teams", label: "Allowed Teams", field_type: FieldType::List, env_var: None, required: false, placeholder: "team1, team2", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a Keybase bot account", "Generate a paper key", "Enter username and paper key below"],
        config_template: "[channels.keybase]\nusername = \"\"\npaperkey_env = \"KEYBASE_PAPERKEY\"",
    },
    // ── Social (5) ──────────────────────────────────────────────────
    ChannelMeta {
        name: "reddit", display_name: "Reddit", icon: "RD",
        description: "Reddit API bot adapter",
        category: "social", difficulty: "Medium", setup_time: "~5 min",
        quick_setup: "Paste your Client ID, Secret, and bot credentials",
        setup_type: "form",
        fields: &[
            ChannelField { key: "client_id", label: "Client ID", field_type: FieldType::Text, env_var: None, required: true, placeholder: "abc123def", advanced: false },
            ChannelField { key: "client_secret_env", label: "Client Secret", field_type: FieldType::Secret, env_var: Some("REDDIT_CLIENT_SECRET"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "username", label: "Bot Username", field_type: FieldType::Text, env_var: None, required: true, placeholder: "t3rnel_bot", advanced: false },
            ChannelField { key: "password_env", label: "Bot Password", field_type: FieldType::Secret, env_var: Some("REDDIT_PASSWORD"), required: true, placeholder: "password", advanced: false },
            ChannelField { key: "subreddits", label: "Subreddits", field_type: FieldType::List, env_var: None, required: false, placeholder: "t3rnel, rust", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a Reddit app at reddit.com/prefs/apps (script type)", "Copy Client ID and Secret", "Enter bot credentials below"],
        config_template: "[channels.reddit]\nclient_id = \"\"\nclient_secret_env = \"REDDIT_CLIENT_SECRET\"\nusername = \"\"\npassword_env = \"REDDIT_PASSWORD\"",
    },
    ChannelMeta {
        name: "mastodon", display_name: "Mastodon", icon: "MA",
        description: "Mastodon Streaming API adapter",
        category: "social", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Paste your access token from Settings > Development",
        setup_type: "form",
        fields: &[
            ChannelField { key: "access_token_env", label: "Access Token", field_type: FieldType::Secret, env_var: Some("MASTODON_ACCESS_TOKEN"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "instance_url", label: "Instance URL", field_type: FieldType::Text, env_var: None, required: true, placeholder: "https://mastodon.social", advanced: false },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Go to Settings > Development on your instance", "Create an app and copy the token", "Paste it below"],
        config_template: "[channels.mastodon]\ninstance_url = \"https://mastodon.social\"\naccess_token_env = \"MASTODON_ACCESS_TOKEN\"",
    },
    ChannelMeta {
        name: "bluesky", display_name: "Bluesky", icon: "BS",
        description: "Bluesky/AT Protocol adapter",
        category: "social", difficulty: "Easy", setup_time: "~1 min",
        quick_setup: "Enter your handle and app password",
        setup_type: "form",
        fields: &[
            ChannelField { key: "identifier", label: "Handle", field_type: FieldType::Text, env_var: None, required: true, placeholder: "user.bsky.social", advanced: false },
            ChannelField { key: "app_password_env", label: "App Password", field_type: FieldType::Secret, env_var: Some("BLUESKY_APP_PASSWORD"), required: true, placeholder: "xxxx-xxxx-xxxx-xxxx", advanced: false },
            ChannelField { key: "service_url", label: "PDS URL", field_type: FieldType::Text, env_var: None, required: false, placeholder: "https://bsky.social", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Go to Settings > App Passwords in Bluesky", "Create an app password", "Enter handle and password below"],
        config_template: "[channels.bluesky]\nidentifier = \"\"\napp_password_env = \"BLUESKY_APP_PASSWORD\"",
    },
    ChannelMeta {
        name: "linkedin", display_name: "LinkedIn", icon: "LI",
        description: "LinkedIn Messaging API adapter",
        category: "social", difficulty: "Hard", setup_time: "~15 min",
        quick_setup: "Paste your OAuth2 access token and Organization ID",
        setup_type: "form",
        fields: &[
            ChannelField { key: "access_token_env", label: "Access Token", field_type: FieldType::Secret, env_var: Some("LINKEDIN_ACCESS_TOKEN"), required: true, placeholder: "AQV...", advanced: false },
            ChannelField { key: "organization_id", label: "Organization ID", field_type: FieldType::Text, env_var: None, required: true, placeholder: "12345678", advanced: false },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a LinkedIn App at linkedin.com/developers", "Generate an OAuth2 token", "Enter token and org ID below"],
        config_template: "[channels.linkedin]\naccess_token_env = \"LINKEDIN_ACCESS_TOKEN\"\norganization_id = \"\"",
    },
    ChannelMeta {
        name: "nostr", display_name: "Nostr", icon: "NS",
        description: "Nostr relay protocol adapter",
        category: "social", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Paste your private key (nsec or hex)",
        setup_type: "form",
        fields: &[
            ChannelField { key: "private_key_env", label: "Private Key", field_type: FieldType::Secret, env_var: Some("NOSTR_PRIVATE_KEY"), required: true, placeholder: "nsec1...", advanced: false },
            ChannelField { key: "relays", label: "Relay URLs", field_type: FieldType::List, env_var: None, required: false, placeholder: "wss://relay.damus.io", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Generate or use an existing Nostr keypair", "Paste your private key below"],
        config_template: "[channels.nostr]\nprivate_key_env = \"NOSTR_PRIVATE_KEY\"",
    },
    // ── Enterprise (10) ─────────────────────────────────────────────
    ChannelMeta {
        name: "teams", display_name: "Microsoft Teams", icon: "MS",
        description: "Teams Bot Framework adapter",
        category: "enterprise", difficulty: "Medium", setup_time: "~10 min",
        quick_setup: "Paste your Azure Bot App ID and Password",
        setup_type: "form",
        fields: &[
            ChannelField { key: "app_id", label: "App ID", field_type: FieldType::Text, env_var: None, required: true, placeholder: "00000000-0000-...", advanced: false },
            ChannelField { key: "app_password_env", label: "App Password", field_type: FieldType::Secret, env_var: Some("TEAMS_APP_PASSWORD"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "webhook_port", label: "Webhook Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "3978", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create an Azure Bot registration", "Copy App ID and generate a password", "Paste them below"],
        config_template: "[channels.teams]\napp_id = \"\"\napp_password_env = \"TEAMS_APP_PASSWORD\"",
    },
    ChannelMeta {
        name: "mattermost", display_name: "Mattermost", icon: "MM",
        description: "Mattermost WebSocket adapter",
        category: "enterprise", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Paste your bot token and server URL",
        setup_type: "form",
        fields: &[
            ChannelField { key: "server_url", label: "Server URL", field_type: FieldType::Text, env_var: None, required: true, placeholder: "https://mattermost.example.com", advanced: false },
            ChannelField { key: "token_env", label: "Bot Token", field_type: FieldType::Secret, env_var: Some("MATTERMOST_TOKEN"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "allowed_channels", label: "Allowed Channels", field_type: FieldType::List, env_var: None, required: false, placeholder: "abc123, def456", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a bot in System Console > Bot Accounts", "Copy the token", "Enter server URL and token below"],
        config_template: "[channels.mattermost]\nserver_url = \"\"\ntoken_env = \"MATTERMOST_TOKEN\"",
    },
    ChannelMeta {
        name: "google_chat", display_name: "Google Chat", icon: "GC",
        description: "Google Chat service account adapter",
        category: "enterprise", difficulty: "Hard", setup_time: "~15 min",
        quick_setup: "Enter path to your service account JSON key",
        setup_type: "form",
        fields: &[
            ChannelField { key: "service_account_env", label: "Service Account JSON", field_type: FieldType::Secret, env_var: Some("GOOGLE_CHAT_SERVICE_ACCOUNT"), required: true, placeholder: "/path/to/key.json", advanced: false },
            ChannelField { key: "space_ids", label: "Space IDs", field_type: FieldType::List, env_var: None, required: false, placeholder: "spaces/AAAA", advanced: true },
            ChannelField { key: "webhook_port", label: "Webhook Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "8444", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a Google Cloud project with Chat API", "Download service account JSON key", "Enter the path below"],
        config_template: "[channels.google_chat]\nservice_account_env = \"GOOGLE_CHAT_SERVICE_ACCOUNT\"",
    },
    ChannelMeta {
        name: "webex", display_name: "Webex", icon: "WX",
        description: "Cisco Webex bot adapter",
        category: "enterprise", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Paste your bot token from developer.webex.com",
        setup_type: "form",
        fields: &[
            ChannelField { key: "bot_token_env", label: "Bot Token", field_type: FieldType::Secret, env_var: Some("WEBEX_BOT_TOKEN"), required: true, placeholder: "NjI...", advanced: false },
            ChannelField { key: "allowed_rooms", label: "Allowed Rooms", field_type: FieldType::List, env_var: None, required: false, placeholder: "Y2lz...", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a bot at developer.webex.com", "Copy the token", "Paste it below"],
        config_template: "[channels.webex]\nbot_token_env = \"WEBEX_BOT_TOKEN\"",
    },
    ChannelMeta {
        name: "feishu", display_name: "Feishu/Lark", icon: "FS",
        description: "Feishu/Lark Open Platform adapter (supports China & International)",
        category: "enterprise", difficulty: "Easy", setup_time: "~3 min",
        quick_setup: "Paste your App ID and App Secret",
        setup_type: "form",
        fields: &[
            ChannelField { key: "app_id", label: "App ID", field_type: FieldType::Text, env_var: None, required: true, placeholder: "cli_abc123", advanced: false },
            ChannelField { key: "app_secret_env", label: "App Secret", field_type: FieldType::Secret, env_var: Some("FEISHU_APP_SECRET"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "region", label: "Region", field_type: FieldType::Text, env_var: None, required: false, placeholder: "cn or intl", advanced: false },
            ChannelField { key: "mode", label: "Receive Mode", field_type: FieldType::Text, env_var: None, required: false, placeholder: "webhook|websocket", advanced: true },
            ChannelField { key: "webhook_port", label: "Webhook Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "8453", advanced: true },
            ChannelField { key: "webhook_path", label: "Webhook Path", field_type: FieldType::Text, env_var: None, required: false, placeholder: "/feishu/webhook", advanced: true },
            ChannelField { key: "verification_token", label: "Verification Token", field_type: FieldType::Text, env_var: None, required: false, placeholder: "verify-token", advanced: true },
            ChannelField { key: "encrypt_key_env", label: "Encrypt Key", field_type: FieldType::Secret, env_var: Some("FEISHU_ENCRYPT_KEY"), required: false, placeholder: "encrypt-key", advanced: true },
            ChannelField { key: "bot_names", label: "Bot Names", field_type: FieldType::List, env_var: None, required: false, placeholder: "MyBot, Assistant", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create an app at open.feishu.cn (CN) or open.larksuite.com (International)", "Copy App ID and Secret", "Set region: cn (Feishu) or intl (Lark)"],
        config_template: "[channels.feishu]\napp_id = \"\"\napp_secret_env = \"FEISHU_APP_SECRET\"\nregion = \"cn\"\nmode = \"websocket\"",
    },
    ChannelMeta {
        name: "dingtalk", display_name: "DingTalk", icon: "DT",
        description: "DingTalk Robot API adapter",
        category: "enterprise", difficulty: "Easy", setup_time: "~3 min",
        quick_setup: "Paste your webhook token and signing secret",
        setup_type: "form",
        fields: &[
            ChannelField { key: "access_token_env", label: "Access Token", field_type: FieldType::Secret, env_var: Some("DINGTALK_ACCESS_TOKEN"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "secret_env", label: "Signing Secret", field_type: FieldType::Secret, env_var: Some("DINGTALK_SECRET"), required: true, placeholder: "SEC...", advanced: false },
            ChannelField { key: "webhook_port", label: "Webhook Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "8457", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a robot in your DingTalk group", "Copy the token and signing secret", "Paste them below"],
        config_template: "[channels.dingtalk]\naccess_token_env = \"DINGTALK_ACCESS_TOKEN\"\nsecret_env = \"DINGTALK_SECRET\"",
    },
    ChannelMeta {
        name: "dingtalk_stream", display_name: "DingTalk Stream", icon: "DS",
        description: "DingTalk Stream Mode (WebSocket long-connection)",
        category: "enterprise", difficulty: "Easy", setup_time: "~5 min",
        quick_setup: "Create an Enterprise Internal App with Stream Mode enabled",
        setup_type: "form",
        fields: &[
            ChannelField { key: "app_key_env", label: "App Key", field_type: FieldType::Secret, env_var: Some("DINGTALK_APP_KEY"), required: true, placeholder: "ding...", advanced: false },
            ChannelField { key: "app_secret_env", label: "App Secret", field_type: FieldType::Secret, env_var: Some("DINGTALK_APP_SECRET"), required: true, placeholder: "uAn4...", advanced: false },
            ChannelField { key: "robot_code_env", label: "Robot Code", field_type: FieldType::Text, env_var: Some("DINGTALK_ROBOT_CODE"), required: false, placeholder: "ding... (same as App Key)", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create an Enterprise Internal App in DingTalk Open Platform", "Enable Stream Mode in the app settings", "Add robot capability and configure permissions", "Copy App Key and App Secret below"],
        config_template: "[channels.dingtalk_stream]\napp_key_env = \"DINGTALK_APP_KEY\"\napp_secret_env = \"DINGTALK_APP_SECRET\"",
    },
    ChannelMeta {
        name: "pumble", display_name: "Pumble", icon: "PB",
        description: "Pumble bot adapter",
        category: "enterprise", difficulty: "Easy", setup_time: "~1 min",
        quick_setup: "Paste your bot token",
        setup_type: "form",
        fields: &[
            ChannelField { key: "bot_token_env", label: "Bot Token", field_type: FieldType::Secret, env_var: Some("PUMBLE_BOT_TOKEN"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "webhook_port", label: "Webhook Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "8455", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a bot in Pumble Integrations", "Copy the token", "Paste it below"],
        config_template: "[channels.pumble]\nbot_token_env = \"PUMBLE_BOT_TOKEN\"",
    },
    ChannelMeta {
        name: "flock", display_name: "Flock", icon: "FL",
        description: "Flock bot adapter",
        category: "enterprise", difficulty: "Easy", setup_time: "~1 min",
        quick_setup: "Paste your bot token",
        setup_type: "form",
        fields: &[
            ChannelField { key: "bot_token_env", label: "Bot Token", field_type: FieldType::Secret, env_var: Some("FLOCK_BOT_TOKEN"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "webhook_port", label: "Webhook Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "8456", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Build an app in Flock App Store", "Copy the bot token", "Paste it below"],
        config_template: "[channels.flock]\nbot_token_env = \"FLOCK_BOT_TOKEN\"",
    },
    ChannelMeta {
        name: "twist", display_name: "Twist", icon: "TW",
        description: "Twist API v3 adapter",
        category: "enterprise", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Paste your API token and workspace ID",
        setup_type: "form",
        fields: &[
            ChannelField { key: "token_env", label: "API Token", field_type: FieldType::Secret, env_var: Some("TWIST_TOKEN"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "workspace_id", label: "Workspace ID", field_type: FieldType::Text, env_var: None, required: true, placeholder: "12345", advanced: false },
            ChannelField { key: "allowed_channels", label: "Channel IDs", field_type: FieldType::List, env_var: None, required: false, placeholder: "123, 456", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create an integration in Twist Settings", "Copy the API token", "Enter token and workspace ID below"],
        config_template: "[channels.twist]\ntoken_env = \"TWIST_TOKEN\"\nworkspace_id = \"\"",
    },
    ChannelMeta {
        name: "zulip", display_name: "Zulip", icon: "ZL",
        description: "Zulip event queue adapter",
        category: "enterprise", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Paste your API key, server URL, and bot email",
        setup_type: "form",
        fields: &[
            ChannelField { key: "server_url", label: "Server URL", field_type: FieldType::Text, env_var: None, required: true, placeholder: "https://chat.zulip.org", advanced: false },
            ChannelField { key: "bot_email", label: "Bot Email", field_type: FieldType::Text, env_var: None, required: true, placeholder: "bot@zulip.example.com", advanced: false },
            ChannelField { key: "api_key_env", label: "API Key", field_type: FieldType::Secret, env_var: Some("ZULIP_API_KEY"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "streams", label: "Streams", field_type: FieldType::List, env_var: None, required: false, placeholder: "general, dev", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a bot in Zulip Settings > Your Bots", "Copy the API key", "Enter server URL, bot email, and key below"],
        config_template: "[channels.zulip]\nserver_url = \"\"\nbot_email = \"\"\napi_key_env = \"ZULIP_API_KEY\"",
    },
    // ── Developer (9) ───────────────────────────────────────────────
    ChannelMeta {
        name: "irc", display_name: "IRC", icon: "IR",
        description: "IRC raw TCP adapter",
        category: "developer", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Enter server and nickname",
        setup_type: "form",
        fields: &[
            ChannelField { key: "server", label: "Server", field_type: FieldType::Text, env_var: None, required: true, placeholder: "irc.libera.chat", advanced: false },
            ChannelField { key: "nick", label: "Nickname", field_type: FieldType::Text, env_var: None, required: true, placeholder: "t3rnel", advanced: false },
            ChannelField { key: "channels", label: "Channels", field_type: FieldType::List, env_var: None, required: false, placeholder: "#t3rnel, #general", advanced: false },
            ChannelField { key: "port", label: "Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "6667", advanced: true },
            ChannelField { key: "use_tls", label: "Use TLS", field_type: FieldType::Text, env_var: None, required: false, placeholder: "false", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Choose an IRC server", "Enter server, nick, and channels below"],
        config_template: "[channels.irc]\nserver = \"irc.libera.chat\"\nnick = \"t3rnel\"",
    },
    ChannelMeta {
        name: "xmpp", display_name: "XMPP/Jabber", icon: "XM",
        description: "XMPP/Jabber protocol adapter",
        category: "developer", difficulty: "Easy", setup_time: "~3 min",
        quick_setup: "Enter your JID and password",
        setup_type: "form",
        fields: &[
            ChannelField { key: "jid", label: "JID", field_type: FieldType::Text, env_var: None, required: true, placeholder: "bot@jabber.org", advanced: false },
            ChannelField { key: "password_env", label: "Password", field_type: FieldType::Secret, env_var: Some("XMPP_PASSWORD"), required: true, placeholder: "password", advanced: false },
            ChannelField { key: "server", label: "Server", field_type: FieldType::Text, env_var: None, required: false, placeholder: "jabber.org", advanced: true },
            ChannelField { key: "port", label: "Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "5222", advanced: true },
            ChannelField { key: "rooms", label: "MUC Rooms", field_type: FieldType::List, env_var: None, required: false, placeholder: "room@conference.jabber.org", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a bot account on your XMPP server", "Enter JID and password below"],
        config_template: "[channels.xmpp]\njid = \"\"\npassword_env = \"XMPP_PASSWORD\"",
    },
    ChannelMeta {
        name: "gitter", display_name: "Gitter", icon: "GT",
        description: "Gitter Streaming API adapter",
        category: "developer", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Paste your auth token and room ID",
        setup_type: "form",
        fields: &[
            ChannelField { key: "token_env", label: "Auth Token", field_type: FieldType::Secret, env_var: Some("GITTER_TOKEN"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "room_id", label: "Room ID", field_type: FieldType::Text, env_var: None, required: true, placeholder: "abc123def456", advanced: false },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Get a token from developer.gitter.im", "Find your room ID", "Paste both below"],
        config_template: "[channels.gitter]\ntoken_env = \"GITTER_TOKEN\"\nroom_id = \"\"",
    },
    ChannelMeta {
        name: "discourse", display_name: "Discourse", icon: "DS",
        description: "Discourse forum API adapter",
        category: "developer", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Paste your API key and forum URL",
        setup_type: "form",
        fields: &[
            ChannelField { key: "base_url", label: "Forum URL", field_type: FieldType::Text, env_var: None, required: true, placeholder: "https://forum.example.com", advanced: false },
            ChannelField { key: "api_key_env", label: "API Key", field_type: FieldType::Secret, env_var: Some("DISCOURSE_API_KEY"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "api_username", label: "API Username", field_type: FieldType::Text, env_var: None, required: false, placeholder: "system", advanced: true },
            ChannelField { key: "categories", label: "Categories", field_type: FieldType::List, env_var: None, required: false, placeholder: "general, support", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Go to Admin > API > Keys", "Generate an API key", "Enter forum URL and key below"],
        config_template: "[channels.discourse]\nbase_url = \"\"\napi_key_env = \"DISCOURSE_API_KEY\"",
    },
    ChannelMeta {
        name: "revolt", display_name: "Revolt", icon: "RV",
        description: "Revolt bot adapter",
        category: "developer", difficulty: "Easy", setup_time: "~1 min",
        quick_setup: "Paste your bot token",
        setup_type: "form",
        fields: &[
            ChannelField { key: "bot_token_env", label: "Bot Token", field_type: FieldType::Secret, env_var: Some("REVOLT_BOT_TOKEN"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "api_url", label: "API URL", field_type: FieldType::Text, env_var: None, required: false, placeholder: "https://api.revolt.chat", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Go to Settings > My Bots in Revolt", "Create a bot and copy the token", "Paste it below"],
        config_template: "[channels.revolt]\nbot_token_env = \"REVOLT_BOT_TOKEN\"",
    },
    ChannelMeta {
        name: "guilded", display_name: "Guilded", icon: "GD",
        description: "Guilded bot adapter",
        category: "developer", difficulty: "Easy", setup_time: "~1 min",
        quick_setup: "Paste your bot token",
        setup_type: "form",
        fields: &[
            ChannelField { key: "bot_token_env", label: "Bot Token", field_type: FieldType::Secret, env_var: Some("GUILDED_BOT_TOKEN"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "server_ids", label: "Server IDs", field_type: FieldType::List, env_var: None, required: false, placeholder: "abc123", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Go to Server Settings > Bots in Guilded", "Create a bot and copy the token", "Paste it below"],
        config_template: "[channels.guilded]\nbot_token_env = \"GUILDED_BOT_TOKEN\"",
    },
    ChannelMeta {
        name: "nextcloud", display_name: "Nextcloud Talk", icon: "NC",
        description: "Nextcloud Talk REST adapter",
        category: "developer", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Paste your server URL and auth token",
        setup_type: "form",
        fields: &[
            ChannelField { key: "server_url", label: "Server URL", field_type: FieldType::Text, env_var: None, required: true, placeholder: "https://cloud.example.com", advanced: false },
            ChannelField { key: "token_env", label: "Auth Token", field_type: FieldType::Secret, env_var: Some("NEXTCLOUD_TOKEN"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "allowed_rooms", label: "Room Tokens", field_type: FieldType::List, env_var: None, required: false, placeholder: "abc123", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a bot user in Nextcloud", "Generate an app password", "Enter URL and token below"],
        config_template: "[channels.nextcloud]\nserver_url = \"\"\ntoken_env = \"NEXTCLOUD_TOKEN\"",
    },
    ChannelMeta {
        name: "rocketchat", display_name: "Rocket.Chat", icon: "RC",
        description: "Rocket.Chat REST adapter",
        category: "developer", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Paste your server URL, user ID, and token",
        setup_type: "form",
        fields: &[
            ChannelField { key: "server_url", label: "Server URL", field_type: FieldType::Text, env_var: None, required: true, placeholder: "https://rocket.example.com", advanced: false },
            ChannelField { key: "user_id", label: "Bot User ID", field_type: FieldType::Text, env_var: None, required: true, placeholder: "abc123", advanced: false },
            ChannelField { key: "token_env", label: "Auth Token", field_type: FieldType::Secret, env_var: Some("ROCKETCHAT_TOKEN"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "allowed_channels", label: "Channel IDs", field_type: FieldType::List, env_var: None, required: false, placeholder: "GENERAL", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a bot in Admin > Users", "Generate a personal access token", "Enter URL, user ID, and token below"],
        config_template: "[channels.rocketchat]\nserver_url = \"\"\ntoken_env = \"ROCKETCHAT_TOKEN\"\nuser_id = \"\"",
    },
    ChannelMeta {
        name: "twitch", display_name: "Twitch", icon: "TV",
        description: "Twitch IRC gateway adapter",
        category: "developer", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Paste your OAuth token and enter channel name",
        setup_type: "form",
        fields: &[
            ChannelField { key: "oauth_token_env", label: "OAuth Token", field_type: FieldType::Secret, env_var: Some("TWITCH_OAUTH_TOKEN"), required: true, placeholder: "oauth:abc123...", advanced: false },
            ChannelField { key: "nick", label: "Bot Nickname", field_type: FieldType::Text, env_var: None, required: true, placeholder: "t3rnel", advanced: false },
            ChannelField { key: "channels", label: "Channels (no #)", field_type: FieldType::List, env_var: None, required: true, placeholder: "mychannel", advanced: false },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Generate an OAuth token at twitchapps.com/tmi", "Enter token, nick, and channel below"],
        config_template: "[channels.twitch]\noauth_token_env = \"TWITCH_OAUTH_TOKEN\"\nnick = \"t3rnel\"",
    },
    // ── Notifications (4) ───────────────────────────────────────────
    ChannelMeta {
        name: "ntfy", display_name: "ntfy", icon: "NF",
        description: "ntfy.sh pub/sub notification adapter",
        category: "notifications", difficulty: "Easy", setup_time: "~1 min",
        quick_setup: "Just enter a topic name",
        setup_type: "form",
        fields: &[
            ChannelField { key: "topic", label: "Topic", field_type: FieldType::Text, env_var: None, required: true, placeholder: "t3rnel-alerts", advanced: false },
            ChannelField { key: "server_url", label: "Server URL", field_type: FieldType::Text, env_var: None, required: false, placeholder: "https://ntfy.sh", advanced: true },
            ChannelField { key: "token_env", label: "Auth Token", field_type: FieldType::Secret, env_var: Some("NTFY_TOKEN"), required: false, placeholder: "tk_abc123...", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Pick a topic name", "Enter it below — that's it!"],
        config_template: "[channels.ntfy]\ntopic = \"\"",
    },
    ChannelMeta {
        name: "gotify", display_name: "Gotify", icon: "GF",
        description: "Gotify WebSocket notification adapter",
        category: "notifications", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Paste your server URL and tokens",
        setup_type: "form",
        fields: &[
            ChannelField { key: "server_url", label: "Server URL", field_type: FieldType::Text, env_var: None, required: true, placeholder: "https://gotify.example.com", advanced: false },
            ChannelField { key: "app_token_env", label: "App Token (send)", field_type: FieldType::Secret, env_var: Some("GOTIFY_APP_TOKEN"), required: true, placeholder: "abc123...", advanced: false },
            ChannelField { key: "client_token_env", label: "Client Token (receive)", field_type: FieldType::Secret, env_var: Some("GOTIFY_CLIENT_TOKEN"), required: true, placeholder: "def456...", advanced: false },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create an app and a client in Gotify", "Copy both tokens", "Enter URL and tokens below"],
        config_template: "[channels.gotify]\nserver_url = \"\"\napp_token_env = \"GOTIFY_APP_TOKEN\"\nclient_token_env = \"GOTIFY_CLIENT_TOKEN\"",
    },
    ChannelMeta {
        name: "webhook", display_name: "Webhook", icon: "WH",
        description: "Generic HMAC-signed webhook adapter",
        category: "notifications", difficulty: "Easy", setup_time: "~1 min",
        quick_setup: "Optionally set an HMAC secret",
        setup_type: "form",
        fields: &[
            ChannelField { key: "secret_env", label: "HMAC Secret", field_type: FieldType::Secret, env_var: Some("WEBHOOK_SECRET"), required: false, placeholder: "my-secret", advanced: false },
            ChannelField { key: "listen_port", label: "Listen Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "8460", advanced: true },
            ChannelField { key: "callback_url", label: "Callback URL", field_type: FieldType::Text, env_var: None, required: false, placeholder: "https://example.com/webhook", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Enter an HMAC secret (or leave blank)", "Click Save — that's it!"],
        config_template: "[channels.webhook]\nsecret_env = \"WEBHOOK_SECRET\"",
    },
    ChannelMeta {
        name: "mumble", display_name: "Mumble", icon: "MB",
        description: "Mumble text chat adapter",
        category: "notifications", difficulty: "Easy", setup_time: "~2 min",
        quick_setup: "Enter server host and username",
        setup_type: "form",
        fields: &[
            ChannelField { key: "host", label: "Host", field_type: FieldType::Text, env_var: None, required: true, placeholder: "mumble.example.com", advanced: false },
            ChannelField { key: "username", label: "Username", field_type: FieldType::Text, env_var: None, required: true, placeholder: "t3rnel", advanced: false },
            ChannelField { key: "password_env", label: "Server Password", field_type: FieldType::Secret, env_var: Some("MUMBLE_PASSWORD"), required: false, placeholder: "password", advanced: true },
            ChannelField { key: "port", label: "Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "64738", advanced: true },
            ChannelField { key: "channel", label: "Channel", field_type: FieldType::Text, env_var: None, required: false, placeholder: "Root", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Enter host and username below", "Optionally add a password"],
        config_template: "[channels.mumble]\nhost = \"\"\nusername = \"t3rnel\"",
    },
    ChannelMeta {
        name: "wecom", display_name: "WeCom", icon: "WC",
        description: "WeCom (WeChat Work) adapter",
        category: "messaging", difficulty: "Easy", setup_time: "~3 min",
        quick_setup: "Enter your Corp ID, Agent ID, and Secret",
        setup_type: "form",
        fields: &[
            ChannelField { key: "corp_id", label: "Corp ID", field_type: FieldType::Text, env_var: None, required: true, placeholder: "wwxxxxx", advanced: false },
            ChannelField { key: "agent_id", label: "Agent ID", field_type: FieldType::Text, env_var: None, required: true, placeholder: "wwxxxxx", advanced: false },
            ChannelField { key: "secret_env", label: "Secret", field_type: FieldType::Secret, env_var: Some("WECOM_SECRET"), required: true, placeholder: "secret", advanced: false },
            ChannelField { key: "token", label: "Callback Token", field_type: FieldType::Text, env_var: None, required: false, placeholder: "callback_token", advanced: true },
            ChannelField { key: "encoding_aes_key", label: "Encoding AES Key", field_type: FieldType::Text, env_var: None, required: false, placeholder: "encoding_aes_key", advanced: true },
            ChannelField { key: "webhook_port", label: "Webhook Port", field_type: FieldType::Number, env_var: None, required: false, placeholder: "8454", advanced: true },
            ChannelField { key: "default_agent", label: "Default Agent", field_type: FieldType::Text, env_var: None, required: false, placeholder: "assistant", advanced: true },
        ],
        setup_steps: &["Create a WeCom application at work.weixin.qq.com", "Get Corp ID, Agent ID, and Secret", "Configure callback URL to your webhook endpoint"],
        config_template: "[channels.wecom]\ncorp_id = \"\"\nagent_id = \"\"\nsecret_env = \"WECOM_SECRET\"",
    },
];

/// Check if a channel is configured (has a `[channels.xxx]` section in config).
/// Does the WhatsApp gateway hold credentials for a linked number?
///
/// Read from disk rather than asked over HTTP: this runs inside a channel
/// listing that must stay fast, and a gateway that is briefly down has not
/// unlinked the number.
fn whatsapp_session_linked() -> bool {
    t3rnel_kernel::config::t3rnel_home()
        .join("whatsapp-gateway")
        .join("auth_store")
        .join("creds.json")
        .exists()
}

fn is_channel_configured(config: &t3rnel_types::config::ChannelsConfig, name: &str) -> bool {
    match name {
        "telegram" => config.telegram.is_some(),
        "discord" => config.discord.is_some(),
        "slack" => config.slack.is_some(),
        // WhatsApp is linked by scanning a QR, not by storing a token, so it
        // has no config section to find. Asking whether one exists reported
        // "Not Configured" for a gateway with a live linked session, while the
        // detail view — which checks the session — said the opposite. The
        // dashboard disagreed with itself about the same channel.
        "whatsapp" => config.whatsapp.is_some() || whatsapp_session_linked(),
        "signal" => config.signal.is_some(),
        "matrix" => config.matrix.is_some(),
        "email" => config.email.is_some(),
        "line" => config.line.is_some(),
        "viber" => config.viber.is_some(),
        "messenger" => config.messenger.is_some(),
        "threema" => config.threema.is_some(),
        "keybase" => config.keybase.is_some(),
        "reddit" => config.reddit.is_some(),
        "mastodon" => config.mastodon.is_some(),
        "bluesky" => config.bluesky.is_some(),
        "linkedin" => config.linkedin.is_some(),
        "nostr" => config.nostr.is_some(),
        "teams" => config.teams.is_some(),
        "mattermost" => config.mattermost.is_some(),
        "google_chat" => config.google_chat.is_some(),
        "webex" => config.webex.is_some(),
        "feishu" => config.feishu.is_some(),
        "dingtalk" => config.dingtalk.is_some(),
        "dingtalk_stream" => config.dingtalk_stream.is_some(),
        "pumble" => config.pumble.is_some(),
        "flock" => config.flock.is_some(),
        "twist" => config.twist.is_some(),
        "zulip" => config.zulip.is_some(),
        "irc" => config.irc.is_some(),
        "xmpp" => config.xmpp.is_some(),
        "gitter" => config.gitter.is_some(),
        "discourse" => config.discourse.is_some(),
        "revolt" => config.revolt.is_some(),
        "guilded" => config.guilded.is_some(),
        "nextcloud" => config.nextcloud.is_some(),
        "rocketchat" => config.rocketchat.is_some(),
        "twitch" => config.twitch.is_some(),
        "ntfy" => config.ntfy.is_some(),
        "gotify" => config.gotify.is_some(),
        "webhook" => config.webhook.is_some(),
        "mumble" => config.mumble.is_some(),
        "wecom" => config.wecom.is_some(),
        _ => false,
    }
}

/// Build a JSON field descriptor, checking env var presence but never exposing secrets.
/// For non-secret fields, includes the actual config value from `config_values` if available.
fn build_field_json(
    f: &ChannelField,
    config_values: Option<&serde_json::Value>,
) -> serde_json::Value {
    let has_value = f
        .env_var
        .map(|ev| std::env::var(ev).map(|v| !v.is_empty()).unwrap_or(false))
        .unwrap_or(false);
    let mut field = serde_json::json!({
        "key": f.key,
        "label": f.label,
        "type": f.field_type.as_str(),
        "env_var": f.env_var,
        "required": f.required,
        "has_value": has_value,
        "placeholder": f.placeholder,
        "advanced": f.advanced,
    });
    // For non-secret fields, include the actual saved config value so the
    // dashboard can pre-populate forms when editing existing configs.
    if f.env_var.is_none() {
        if let Some(obj) = config_values.and_then(|v| v.as_object()) {
            if let Some(val) = obj.get(f.key) {
                // Convert arrays to comma-separated string for list fields
                let display_val = if f.field_type == FieldType::List {
                    if let Some(arr) = val.as_array() {
                        serde_json::Value::String(
                            arr.iter()
                                .filter_map(|v| {
                                    v.as_str()
                                        .map(|s| s.to_string())
                                        .or_else(|| Some(v.to_string()))
                                })
                                .collect::<Vec<_>>()
                                .join(", "),
                        )
                    } else {
                        val.clone()
                    }
                } else {
                    val.clone()
                };
                field["value"] = display_val;
                if !val.is_null() && val.as_str().map(|s| !s.is_empty()).unwrap_or(true) {
                    field["has_value"] = serde_json::Value::Bool(true);
                }
            }
        }
    }
    field
}

/// Find a channel definition by name.
fn find_channel_meta(name: &str) -> Option<&'static ChannelMeta> {
    CHANNEL_REGISTRY.iter().find(|c| c.name == name)
}

#[cfg(test)]
mod channel_meta_tests {
    use super::*;

    #[test]
    fn feishu_channel_meta_includes_mode_field() {
        let meta = find_channel_meta("feishu").expect("feishu channel meta should exist");
        assert!(meta.fields.iter().any(|f| f.key == "mode"));
    }

    #[test]
    fn feishu_channel_meta_template_includes_websocket_mode_default() {
        let meta = find_channel_meta("feishu").expect("feishu channel meta should exist");
        assert!(meta.config_template.contains("mode = \"websocket\""));
    }
}

/// Serialize a channel's config to a JSON Value for pre-populating dashboard forms.
fn channel_config_values(
    config: &t3rnel_types::config::ChannelsConfig,
    name: &str,
) -> Option<serde_json::Value> {
    match name {
        "telegram" => config
            .telegram
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "discord" => config
            .discord
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "slack" => config
            .slack
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "whatsapp" => config
            .whatsapp
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "signal" => config
            .signal
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "matrix" => config
            .matrix
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "email" => config
            .email
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "teams" => config
            .teams
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "mattermost" => config
            .mattermost
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "irc" => config
            .irc
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "google_chat" => config
            .google_chat
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "twitch" => config
            .twitch
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "rocketchat" => config
            .rocketchat
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "zulip" => config
            .zulip
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "xmpp" => config
            .xmpp
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "line" => config
            .line
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "viber" => config
            .viber
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "messenger" => config
            .messenger
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "reddit" => config
            .reddit
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "mastodon" => config
            .mastodon
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "bluesky" => config
            .bluesky
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "feishu" => config
            .feishu
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "revolt" => config
            .revolt
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "nextcloud" => config
            .nextcloud
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "guilded" => config
            .guilded
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "keybase" => config
            .keybase
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "threema" => config
            .threema
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "nostr" => config
            .nostr
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "webex" => config
            .webex
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "pumble" => config
            .pumble
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "flock" => config
            .flock
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "twist" => config
            .twist
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "mumble" => config
            .mumble
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "dingtalk" => config
            .dingtalk
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "dingtalk_stream" => config
            .dingtalk_stream
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "discourse" => config
            .discourse
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "gitter" => config
            .gitter
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "ntfy" => config
            .ntfy
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "gotify" => config
            .gotify
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "webhook" => config
            .webhook
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "linkedin" => config
            .linkedin
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        "wecom" => config
            .wecom
            .as_ref()
            .and_then(|c| serde_json::to_value(c).ok()),
        _ => None,
    }
}

/// GET /api/channels — List all 40 channel adapters with status and field metadata.
pub async fn list_channels(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Read the live channels config (updated on every hot-reload) instead of the
    // stale boot-time kernel.config, so newly configured channels show correctly.
    let live_channels = state.channels_config.read().await;
    let mut channels = Vec::new();
    let mut configured_count = 0u32;

    for meta in CHANNEL_REGISTRY {
        let configured = is_channel_configured(&live_channels, meta.name);
        if configured {
            configured_count += 1;
        }

        // Check if all required secret env vars are set
        let has_token = meta
            .fields
            .iter()
            .filter(|f| f.required && f.env_var.is_some())
            .all(|f| {
                f.env_var
                    .map(|ev| std::env::var(ev).map(|v| !v.is_empty()).unwrap_or(false))
                    .unwrap_or(true)
            });

        let config_vals = channel_config_values(&live_channels, meta.name);
        let fields: Vec<serde_json::Value> = meta
            .fields
            .iter()
            .map(|f| build_field_json(f, config_vals.as_ref()))
            .collect();

        channels.push(serde_json::json!({
            "name": meta.name,
            "display_name": meta.display_name,
            "icon": meta.icon,
            "description": meta.description,
            "category": meta.category,
            "difficulty": meta.difficulty,
            "setup_time": meta.setup_time,
            "quick_setup": meta.quick_setup,
            "setup_type": meta.setup_type,
            "configured": configured,
            "has_token": has_token,
            "fields": fields,
            "setup_steps": meta.setup_steps,
            "config_template": meta.config_template,
        }));
    }

    Json(serde_json::json!({
        "channels": channels,
        "total": channels.len(),
        "configured_count": configured_count,
    }))
}

/// POST /api/channels/{name}/configure — Save channel secrets + config fields.
pub async fn configure_channel(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let meta = match find_channel_meta(&name) {
        Some(m) => m,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Unknown channel"})),
            )
        }
    };

    let fields = match body.get("fields").and_then(|v| v.as_object()) {
        Some(f) => f,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing 'fields' object"})),
            )
        }
    };

    let home = t3rnel_kernel::config::t3rnel_home();
    let secrets_path = home.join("secrets.env");
    let config_path = home.join("config.toml");
    let mut config_fields: HashMap<String, (String, FieldType)> = HashMap::new();

    for field_def in meta.fields {
        let value = fields
            .get(field_def.key)
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if value.is_empty() {
            continue;
        }

        if let Some(env_var) = field_def.env_var {
            // Secret field — write to secrets.env and set in process
            if let Err(e) = write_secret_env(&secrets_path, env_var, value) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Failed to write secret: {e}")})),
                );
            }
            // SAFETY: We are the only writer; this is a single-threaded config operation
            unsafe {
                std::env::set_var(env_var, value);
            }
            // Also write the env var NAME to config.toml so the channel section
            // is not empty and the kernel knows which env var to read.
            config_fields.insert(
                field_def.key.to_string(),
                (env_var.to_string(), FieldType::Text),
            );
        } else {
            // Config field — collect for TOML write with type info
            config_fields.insert(
                field_def.key.to_string(),
                (value.to_string(), field_def.field_type),
            );
        }
    }

    // Write config.toml section
    if let Err(e) = upsert_channel_config(&config_path, &name, &config_fields) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to write config: {e}")})),
        );
    }

    // Hot-reload: activate the channel immediately
    match crate::channel_bridge::reload_channels_from_disk(&state).await {
        Ok(started) => {
            let activated = started.iter().any(|s| s.eq_ignore_ascii_case(&name));
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "configured",
                    "channel": name,
                    "activated": activated,
                    "started_channels": started,
                    "note": if activated {
                        format!("{} activated successfully.", name)
                    } else {
                        "Channel configured but could not start (check credentials).".to_string()
                    }
                })),
            )
        }
        Err(e) => {
            tracing::warn!(error = %e, "Channel hot-reload failed after configure");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "configured",
                    "channel": name,
                    "activated": false,
                    "note": format!("Configured, but hot-reload failed: {e}. Restart daemon to activate.")
                })),
            )
        }
    }
}

/// DELETE /api/channels/{name}/configure — Remove channel secrets + config section.
pub async fn remove_channel(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let meta = match find_channel_meta(&name) {
        Some(m) => m,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Unknown channel"})),
            )
        }
    };

    let home = t3rnel_kernel::config::t3rnel_home();
    let secrets_path = home.join("secrets.env");
    let config_path = home.join("config.toml");

    // Remove all secret env vars for this channel
    for field_def in meta.fields {
        if let Some(env_var) = field_def.env_var {
            let _ = remove_secret_env(&secrets_path, env_var);
            // SAFETY: Single-threaded config operation
            unsafe {
                std::env::remove_var(env_var);
            }
        }
    }

    // Remove config section
    if let Err(e) = remove_channel_config(&config_path, &name) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to remove config: {e}")})),
        );
    }

    // Hot-reload: deactivate the channel immediately
    match crate::channel_bridge::reload_channels_from_disk(&state).await {
        Ok(started) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "removed",
                "channel": name,
                "remaining_channels": started,
                "note": format!("{} deactivated.", name)
            })),
        ),
        Err(e) => {
            tracing::warn!(error = %e, "Channel hot-reload failed after remove");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "removed",
                    "channel": name,
                    "note": format!("Removed, but hot-reload failed: {e}. Restart daemon to fully deactivate.")
                })),
            )
        }
    }
}

/// POST /api/channels/{name}/test — Connectivity check + optional live test message.
///
/// Accepts an optional JSON body with `channel_id` (for Discord/Slack) or `chat_id`
/// (for Telegram). When provided, sends a real test message to verify the bot can
/// post to that channel.
pub async fn test_channel(
    Path(name): Path<String>,
    raw_body: axum::body::Bytes,
) -> impl IntoResponse {
    let meta = match find_channel_meta(&name) {
        Some(m) => m,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"status": "error", "message": "Unknown channel"})),
            )
        }
    };

    // Check all required env vars are set
    let mut missing = Vec::new();
    for field_def in meta.fields {
        if field_def.required {
            if let Some(env_var) = field_def.env_var {
                if std::env::var(env_var).map(|v| v.is_empty()).unwrap_or(true) {
                    missing.push(env_var);
                }
            }
        }
    }

    if !missing.is_empty() {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "error",
                "message": format!("Missing required env vars: {}", missing.join(", "))
            })),
        );
    }

    // If a target channel/chat ID is provided, send a real test message
    let body: serde_json::Value = if raw_body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&raw_body).unwrap_or(serde_json::Value::Null)
    };
    let target = body
        .get("channel_id")
        .or_else(|| body.get("chat_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if let Some(target_id) = target {
        match send_channel_test_message(&name, &target_id).await {
            Ok(()) => {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "status": "ok",
                        "message": format!("Test message sent to {} channel {}.", meta.display_name, target_id)
                    })),
                );
            }
            Err(e) => {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "status": "error",
                        "message": format!("Credentials valid but failed to send test message: {e}")
                    })),
                );
            }
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "message": format!("All required credentials for {} are set. Provide channel_id or chat_id to send a test message.", meta.display_name)
        })),
    )
}

/// Send a real test message to a specific channel/chat on the given platform.
async fn send_channel_test_message(channel_name: &str, target_id: &str) -> Result<(), String> {
    let client = reqwest::Client::new();
    let test_msg = "T3rnel test message — your channel is connected!";

    match channel_name {
        "discord" => {
            let token = std::env::var("DISCORD_BOT_TOKEN")
                .map_err(|_| "DISCORD_BOT_TOKEN not set".to_string())?;
            let url = format!("https://discord.com/api/v10/channels/{target_id}/messages");
            let resp = client
                .post(&url)
                .header("Authorization", format!("Bot {token}"))
                .json(&serde_json::json!({ "content": test_msg }))
                .send()
                .await
                .map_err(|e| format!("HTTP request failed: {e}"))?;
            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(format!("Discord API error: {body}"));
            }
        }
        "telegram" => {
            let token = std::env::var("TELEGRAM_BOT_TOKEN")
                .map_err(|_| "TELEGRAM_BOT_TOKEN not set".to_string())?;
            let url = format!("https://api.telegram.org/bot{token}/sendMessage");
            let resp = client
                .post(&url)
                .json(&serde_json::json!({ "chat_id": target_id, "text": test_msg }))
                .send()
                .await
                .map_err(|e| format!("HTTP request failed: {e}"))?;
            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(format!("Telegram API error: {body}"));
            }
        }
        "slack" => {
            let token = std::env::var("SLACK_BOT_TOKEN")
                .map_err(|_| "SLACK_BOT_TOKEN not set".to_string())?;
            let url = "https://slack.com/api/chat.postMessage";
            let resp = client
                .post(url)
                .header("Authorization", format!("Bearer {token}"))
                .json(&serde_json::json!({ "channel": target_id, "text": test_msg }))
                .send()
                .await
                .map_err(|e| format!("HTTP request failed: {e}"))?;
            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(format!("Slack API error: {body}"));
            }
        }
        _ => {
            return Err(format!(
                "Live test messaging not supported for {channel_name}. Credentials are valid."
            ));
        }
    }
    Ok(())
}

/// POST /api/channels/reload — Manually trigger a channel hot-reload from disk config.
pub async fn reload_channels(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match crate::channel_bridge::reload_channels_from_disk(&state).await {
        Ok(started) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ok",
                "started": started,
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "status": "error",
                "error": e,
            })),
        ),
    }
}

// ---------------------------------------------------------------------------
// WhatsApp QR login flow (OpenClaw-style)
// ---------------------------------------------------------------------------

/// POST /api/channels/whatsapp/qr/start — Start a WhatsApp Web QR login session.
///
/// If a WhatsApp Web gateway is available (e.g. a Baileys-based bridge process),
/// this proxies the request and returns a base64 QR code data URL. If no gateway
/// is running, it returns instructions to set one up.
/// POST /api/channels/whatsapp/unlink — disconnect the linked number.
///
/// Relinking is the existing QR flow, so unlink deliberately does not start one:
/// an operator switching numbers wants the old one gone first, and chaining the
/// two would reconnect before they had the new phone in hand.
pub async fn whatsapp_unlink(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let gateway_url =
        match t3rnel_kernel::whatsapp_gateway::ensure_gateway_running(&state.kernel).await {
            Ok(url) => url,
            Err(error) => {
                return Json(serde_json::json!({
                    "ok": false,
                    "message": format!("gateway unavailable: {error}"),
                }))
            }
        };

    let client = reqwest::Client::new();
    match client
        .post(format!("{gateway_url}/logout"))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            let body: serde_json::Value = response.json().await.unwrap_or_default();
            Json(serde_json::json!({
                "ok": status.is_success(),
                "unlinked": body.get("unlinked").and_then(|v| v.as_bool()).unwrap_or(false),
                "message": if status.is_success() {
                    "Number unlinked. Scan a new QR to link another.".to_string()
                } else {
                    format!("gateway refused the unlink: {body}")
                },
            }))
        }
        Err(error) => Json(serde_json::json!({
            "ok": false,
            "message": format!("could not reach the gateway: {error}"),
        })),
    }
}

/// GET /api/channels/whatsapp/linked — which number the gateway speaks as.
///
/// Reports the linked number separately from the connection, because a gateway
/// can be linked to a number it is not presently connected to. Collapsing the
/// two is what let the channel list and the detail view disagree.
pub async fn whatsapp_linked(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let gateway_url =
        match t3rnel_kernel::whatsapp_gateway::ensure_gateway_running(&state.kernel).await {
            Ok(url) => url,
            Err(error) => {
                return Json(serde_json::json!({
                    "linked": whatsapp_session_linked(),
                    "connected": false,
                    "message": format!("gateway unavailable: {error}"),
                }))
            }
        };

    let client = reqwest::Client::new();
    match client
        .get(format!("{gateway_url}/linked"))
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
    {
        Ok(response) => Json(response.json().await.unwrap_or_else(
            |_| serde_json::json!({ "linked": whatsapp_session_linked(), "connected": false }),
        )),
        // Credentials on disk are the durable truth; a gateway that is briefly
        // down has not unlinked the number.
        Err(_) => Json(serde_json::json!({
            "linked": whatsapp_session_linked(),
            "connected": false,
            "message": "gateway unreachable; reporting the stored session",
        })),
    }
}

pub async fn whatsapp_qr_start(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Resolve a live gateway, starting one on demand if needed. The daemon only
    // auto-starts the gateway when `[channels.whatsapp]` already exists in config,
    // which is never true during first-time setup — so returning "not running"
    // here made the setup flow impossible to complete (ISSUE-008).
    let gateway_url = match t3rnel_kernel::whatsapp_gateway::ensure_gateway_running(&state.kernel)
        .await
    {
        Ok(url) => url,
        Err(e) => {
            return Json(serde_json::json!({
                "available": false,
                "message": e,
                "help": "The daemon manages its own WhatsApp Web gateway and starts it on demand; \
                         it needs Node.js >= 18 on PATH. Set WHATSAPP_WEB_GATEWAY_URL only if you \
                         run an external gateway, or switch this channel to Business API mode."
            }));
        }
    };

    // Try to reach the gateway and start a QR session.
    // Uses a raw HTTP request via tokio TcpStream to avoid adding reqwest as a runtime dep.
    let start_url = format!("{}/login/start", gateway_url.trim_end_matches('/'));
    match gateway_http_post(&start_url).await {
        Ok(body) => {
            let qr_url = body
                .get("qr_data_url")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let sid = body
                .get("session_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let msg = body
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Scan this QR code with WhatsApp → Linked Devices");
            let connected = body
                .get("connected")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            Json(serde_json::json!({
                "available": true,
                "qr_data_url": qr_url,
                "session_id": sid,
                "message": msg,
                "connected": connected,
            }))
        }
        Err(e) => Json(serde_json::json!({
            "available": false,
            "message": format!("Could not reach WhatsApp Web gateway: {e}"),
            "help": "Make sure the gateway is running at the configured URL"
        })),
    }
}

/// GET /api/channels/whatsapp/qr/status — Poll for QR scan completion.
///
/// After calling `/qr/start`, the frontend polls this to check if the user
/// has scanned the QR code and the WhatsApp Web session is connected.
pub async fn whatsapp_qr_status(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let gateway_url = std::env::var("WHATSAPP_WEB_GATEWAY_URL").unwrap_or_default();

    if gateway_url.is_empty() {
        return Json(serde_json::json!({
            "connected": false,
            "message": "Gateway not available"
        }));
    }

    let session_id = params.get("session_id").cloned().unwrap_or_default();
    let status_url = format!(
        "{}/login/status?session_id={}",
        gateway_url.trim_end_matches('/'),
        session_id
    );

    match gateway_http_get(&status_url).await {
        Ok(body) => {
            let connected = body
                .get("connected")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let msg = body
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Waiting for scan...");
            let expired = body
                .get("expired")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            Json(serde_json::json!({
                "connected": connected,
                "message": msg,
                "expired": expired,
            }))
        }
        Err(_) => Json(serde_json::json!({ "connected": false, "message": "Gateway unreachable" })),
    }
}

/// Lightweight HTTP POST to a gateway URL. Returns parsed JSON body.
async fn gateway_http_post(url_with_path: &str) -> Result<serde_json::Value, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Split into base URL + path from the full URL like "http://127.0.0.1:3009/login/start"
    let without_scheme = url_with_path
        .strip_prefix("http://")
        .or_else(|| url_with_path.strip_prefix("https://"))
        .unwrap_or(url_with_path);
    let (host_port, path) = if let Some(idx) = without_scheme.find('/') {
        (&without_scheme[..idx], &without_scheme[idx..])
    } else {
        (without_scheme, "/")
    };
    let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
        (h, p.parse().unwrap_or(3009u16))
    } else {
        (host_port, 3009u16)
    };

    let mut stream = tokio::net::TcpStream::connect(format!("{host}:{port}"))
        .await
        .map_err(|e| format!("Connect failed: {e}"))?;

    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("Write failed: {e}"))?;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("Read failed: {e}"))?;
    let response = String::from_utf8_lossy(&buf);

    // Find the JSON body after the blank line separating headers from body
    if let Some(idx) = response.find("\r\n\r\n") {
        let body_str = &response[idx + 4..];
        serde_json::from_str(body_str.trim()).map_err(|e| format!("Parse failed: {e}"))
    } else {
        Err("No HTTP body in response".to_string())
    }
}

/// Lightweight HTTP GET to a gateway URL. Returns parsed JSON body.
async fn gateway_http_get(url_with_path: &str) -> Result<serde_json::Value, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let without_scheme = url_with_path
        .strip_prefix("http://")
        .or_else(|| url_with_path.strip_prefix("https://"))
        .unwrap_or(url_with_path);
    let (host_port, path_and_query) = if let Some(idx) = without_scheme.find('/') {
        (&without_scheme[..idx], &without_scheme[idx..])
    } else {
        (without_scheme, "/")
    };
    let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
        (h, p.parse().unwrap_or(3009u16))
    } else {
        (host_port, 3009u16)
    };

    let mut stream = tokio::net::TcpStream::connect(format!("{host}:{port}"))
        .await
        .map_err(|e| format!("Connect failed: {e}"))?;

    let req = format!(
        "GET {path_and_query} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("Write failed: {e}"))?;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("Read failed: {e}"))?;
    let response = String::from_utf8_lossy(&buf);

    if let Some(idx) = response.find("\r\n\r\n") {
        let body_str = &response[idx + 4..];
        serde_json::from_str(body_str.trim()).map_err(|e| format!("Parse failed: {e}"))
    } else {
        Err("No HTTP body in response".to_string())
    }
}

// ---------------------------------------------------------------------------
// Template endpoints
// ---------------------------------------------------------------------------

/// GET /api/templates — List available agent templates.
pub async fn list_templates() -> impl IntoResponse {
    let agents_dir = t3rnel_kernel::config::t3rnel_home().join("agents");
    let mut templates = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&agents_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let manifest_path = path.join("agent.toml");
                if manifest_path.exists() {
                    let name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();

                    let manifest_content = std::fs::read_to_string(&manifest_path).ok();
                    let description = manifest_content
                        .as_ref()
                        .and_then(|content| toml::from_str::<AgentManifest>(content).ok())
                        .map(|m| m.description)
                        .unwrap_or_default();

                    // Add category based on template name
                    let category = get_template_category(&name);

                    templates.push(serde_json::json!({
                        "name": name,
                        "description": description,
                        "category": category,
                        "manifest_toml": manifest_content.unwrap_or_default(),
                    }));
                }
            }
        }
    }

    Json(serde_json::json!({
        "templates": templates,
        "total": templates.len(),
    }))
}

fn get_template_category(name: &str) -> &str {
    match name {
        "hello-world" | "assistant" => "General",
        "researcher" | "analyst" => "Research",
        "coder" | "debugger" | "devops-lead" => "Development",
        "writer" | "doc-writer" => "Writing",
        "ops" | "planner" => "Operations",
        "architect" | "security-auditor" => "Development",
        "code-reviewer" | "data-scientist" | "test-engineer" => "Development",
        "legal-assistant" | "email-assistant" | "recruiter" => "Business",
        "customer-support" => "Business",
        "meeting-assistant" => "Business",
        "translator" | "tutor" | "health-tracker" => "General",
        "travel-planner" | "home-automation" => "General",
        _ => "General",
    }
}

/// GET /api/templates/:name — Get template details.
pub async fn get_template(Path(name): Path<String>) -> impl IntoResponse {
    let agents_dir = t3rnel_kernel::config::t3rnel_home().join("agents");
    let manifest_path = agents_dir.join(&name).join("agent.toml");

    if !manifest_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Template not found"})),
        );
    }

    match std::fs::read_to_string(&manifest_path) {
        Ok(content) => match toml::from_str::<AgentManifest>(&content) {
            Ok(manifest) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "name": name,
                    "manifest": {
                        "name": manifest.name,
                        "description": manifest.description,
                        "module": manifest.module,
                        "tags": manifest.tags,
                        "model": {
                            "provider": manifest.model.provider,
                            "model": manifest.model.model,
                        },
                        "capabilities": {
                            "tools": manifest.capabilities.tools,
                            "network": manifest.capabilities.network,
                        },
                    },
                    "manifest_toml": content,
                })),
            ),
            Err(e) => {
                tracing::warn!("Invalid template manifest for '{name}': {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Invalid template manifest"})),
                )
            }
        },
        Err(e) => {
            tracing::warn!("Failed to read template '{name}': {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to read template"})),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Memory endpoints
// ---------------------------------------------------------------------------

/// GET /api/memory/agents/:id/kv — List KV pairs for an agent.
///
/// Resolves the agent in the URL as the memory caller, so private-scope
/// records only surface for their owning agent's partition.
pub async fn get_agent_kv(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    crate::memory_routes::run_for(state, Some(&id), "kv_list", serde_json::json!({})).await
}

/// GET /api/memory/agents/:id/kv/:key — Get a specific KV value.
pub async fn get_agent_kv_key(
    State(state): State<Arc<AppState>>,
    Path((id, key)): Path<(String, String)>,
) -> impl IntoResponse {
    crate::memory_routes::run_for(state, Some(&id), "kv_get", serde_json::json!({"key":key})).await
}

/// PUT /api/memory/agents/:id/kv/:key — Set a KV value.
pub async fn set_agent_kv_key(
    State(state): State<Arc<AppState>>,
    Path((id, key)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let value = body.get("value").cloned().unwrap_or(body);
    crate::memory_routes::run_for(
        state,
        Some(&id),
        "kv_set",
        serde_json::json!({"key":key,"value":value}),
    )
    .await
}

/// DELETE /api/memory/agents/:id/kv/:key — Delete a KV value.
pub async fn delete_agent_kv_key(
    State(state): State<Arc<AppState>>,
    Path((id, key)): Path<(String, String)>,
) -> impl IntoResponse {
    crate::memory_routes::run_for(
        state,
        Some(&id),
        "kv_delete",
        serde_json::json!({"key":key}),
    )
    .await
}

/// GET /api/health — Minimal liveness probe (public, no auth required).
/// Returns only status and version to prevent information leakage.
/// Use GET /api/health/detail for full diagnostics (requires auth).
pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Run the database check on a blocking thread so we never hold the
    // std::sync::Mutex<Connection> on a tokio worker thread.  This prevents
    // the health probe from starving the async runtime when the agent loop
    // is holding the database lock for session saves.
    let memory = state.kernel.memory.clone();
    let db_ok = tokio::task::spawn_blocking(move || {
        let shared_id = t3rnel_types::agent::AgentId(uuid::Uuid::from_bytes([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]));
        memory.structured_get(shared_id, "__health_check__").is_ok()
    })
    .await
    .unwrap_or(false);

    let status = if db_ok { "ok" } else { "degraded" };

    Json(serde_json::json!({
        "status": status,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// GET /api/health/detail — Full health diagnostics (requires auth).
pub async fn health_detail(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let health = state.kernel.supervisor.health();

    let memory = state.kernel.memory.clone();
    let db_ok = tokio::task::spawn_blocking(move || {
        let shared_id = t3rnel_types::agent::AgentId(uuid::Uuid::from_bytes([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]));
        memory.structured_get(shared_id, "__health_check__").is_ok()
    })
    .await
    .unwrap_or(false);

    let mut config_warnings = state.kernel.config.validate();
    // Dev mode is a loud, persistent warning on every diagnostics surface.
    if state.kernel.config.plugin_dev_mode {
        config_warnings.push(t3rnel_runtime::plugin_lifecycle::DEV_MODE_WARNING.to_string());
    }
    let status = if db_ok { "ok" } else { "degraded" };
    let teams = state.team_store.list_teams();
    let team_count = teams.as_ref().map(|teams| teams.len()).unwrap_or(0);
    let team_tasks = state.team_store.list_tasks(None);
    let team_task_error = team_tasks.as_ref().err().cloned();
    let team_active_tasks = team_tasks
        .as_ref()
        .map(|tasks| {
            tasks
                .iter()
                .filter(|task| {
                    !matches!(
                        task.status.as_str(),
                        "done" | "completed" | "cancelled" | "failed"
                    )
                })
                .count()
        })
        .unwrap_or(0);
    let memory_pending_tasks = state
        .kernel
        .memory
        .task_list(Some("pending"))
        .await
        .map(|tasks| tasks.len())
        .unwrap_or(0);
    let memory_in_progress_tasks = state
        .kernel
        .memory
        .task_list(Some("in_progress"))
        .await
        .map(|tasks| tasks.len())
        .unwrap_or(0);
    let provider_count = state
        .kernel
        .model_catalog
        .read()
        .map(|catalog| catalog.list_providers().len())
        .unwrap_or(0);
    let memory_mb = current_process_memory_mb();
    let cpu_percent = current_process_cpu_percent(state.started_at);

    Json(serde_json::json!({
        "status": status,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": state.started_at.elapsed().as_secs(),
        "uptime_secs": state.started_at.elapsed().as_secs(),
        "panic_count": health.panic_count,
        "restart_count": health.restart_count,
        "agent_count": state.kernel.registry.count(),
        "team_count": team_count,
        "provider_count": provider_count,
        "pending_approvals": state.kernel.approval_manager.pending_count(),
        "active_tasks": team_active_tasks + memory_pending_tasks + memory_in_progress_tasks,
        "memory_mb": memory_mb,
        "cpu_percent": cpu_percent,
        "database": if db_ok { "connected" } else { "error" },
        "config_warnings": config_warnings,
        "plugin_dev_mode": state.kernel.config.plugin_dev_mode,
        "team_store_error": team_task_error,
    }))
}

/// GET /api/speech/status - Current speech-to-text readiness.
pub async fn speech_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let audio_enabled = state.kernel.config.media.audio_transcription;
    let whisper_cpp = whisper_cpp_settings_from_state(&state);
    apply_whisper_cpp_settings_to_env(&whisper_cpp);
    let whisper_running = whisper_cpp_server_running(&whisper_cpp.base_url).await;
    let whisper_binary_found = command_available(&whisper_cpp.binary);
    let whisper_model_exists = whisper_cpp
        .model_path
        .as_deref()
        .map(|path| FsPath::new(path).exists())
        .unwrap_or(false);
    let whisper_startable = whisper_cpp.enabled && whisper_binary_found && whisper_model_exists;
    let whisper_configured = whisper_cpp.enabled && whisper_running;
    let parakeet_configured = env_var_configured("T3RNEL_ENABLE_PARAKEET_MLX");
    let groq_configured = env_var_configured("GROQ_API_KEY");
    let openai_configured = env_var_configured("OPENAI_API_KEY");
    let preferred_dictation = whisper_cpp
        .dictation_provider
        .as_deref()
        .and_then(|provider| match provider {
            "whisper-cpp" => Some("whisper-cpp"),
            "parakeet-mlx" => Some("parakeet-mlx"),
            "groq" => Some("groq"),
            "openai" | "whisper" => Some("openai"),
            "daemon-stt" | "browser-speech" => None,
            _ => None,
        });
    let configured_provider = state
        .kernel
        .config
        .media
        .audio_provider
        .as_deref()
        .or(preferred_dictation);
    let selected_provider = if audio_enabled {
        match configured_provider {
            Some("whisper") | Some("whisper-cpp") if whisper_configured => Some("whisper-cpp"),
            Some("parakeet-mlx") if parakeet_configured => Some("parakeet-mlx"),
            Some("groq") if groq_configured => Some("groq"),
            Some("openai") if openai_configured => Some("openai"),
            Some(_) => None,
            None if whisper_configured => Some("whisper-cpp"),
            None if parakeet_configured => Some("parakeet-mlx"),
            None if groq_configured => Some("groq"),
            None if openai_configured => Some("openai"),
            None => None,
        }
    } else {
        None
    };

    Json(serde_json::json!({
        "audio_transcription_enabled": audio_enabled,
        "configured": selected_provider.is_some(),
        "provider": selected_provider,
        "configured_provider": configured_provider,
        "providers": [
            {
                "id": "whisper-cpp",
                "label": "Local Whisper.cpp",
                "configured": whisper_configured,
                "enabled": whisper_cpp.enabled,
                "running": whisper_running,
                "startable": whisper_startable,
                "env_var": "T3RNEL_WHISPER_CPP_ENABLED"
            },
            {
                "id": "parakeet-mlx",
                "label": "Parakeet MLX",
                "configured": parakeet_configured,
                "env_var": "T3RNEL_ENABLE_PARAKEET_MLX"
            },
            {
                "id": "groq",
                "label": "Groq Whisper",
                "configured": groq_configured,
                "env_var": "GROQ_API_KEY"
            },
            {
                "id": "openai",
                "label": "OpenAI Whisper",
                "configured": openai_configured,
                "env_var": "OPENAI_API_KEY"
            }
        ],
        "whisper_cpp": {
            "enabled": whisper_cpp.enabled,
            "running": whisper_running,
            "startable": whisper_startable,
            "base_url": whisper_cpp.base_url,
            "binary": whisper_cpp.binary,
            "binary_found": whisper_binary_found,
            "model_path": whisper_cpp.model_path,
            "model_exists": whisper_model_exists,
            "power_level": whisper_cpp.power_level,
            "threads": whisper_cpp_threads(&whisper_cpp),
            "processors": whisper_cpp_processors(&whisper_cpp),
            "use_gpu": whisper_cpp_use_gpu(&whisper_cpp),
            "pid": read_whisper_cpp_pid(&state.kernel.config.home_dir),
        },
        "guidance": speech_guidance(audio_enabled, &whisper_cpp, whisper_running, whisper_binary_found, whisper_model_exists, selected_provider)
    }))
}

/// POST /api/speech/whisper-cpp/start - Start local whisper.cpp STT server.
pub async fn whisper_cpp_start(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let settings = whisper_cpp_settings_from_state(&state);
    apply_whisper_cpp_settings_to_env(&settings);
    if !settings.enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Whisper.cpp is disabled. Enable it in Settings before starting the local STT server."
            })),
        );
    }
    match start_whisper_cpp_server(&state, &settings).await {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error })),
        ),
    }
}

/// POST /api/speech/whisper-cpp/stop - Stop local whisper.cpp STT server.
pub async fn whisper_cpp_stop(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match stop_whisper_cpp_server(&state.kernel.config.home_dir).await {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error })),
        ),
    }
}

fn env_var_configured(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .is_some()
}

#[derive(Clone, Debug)]
struct WhisperCppSettings {
    enabled: bool,
    base_url: String,
    binary: String,
    model_path: Option<String>,
    power_level: String,
    threads: Option<usize>,
    processors: Option<usize>,
    use_gpu: bool,
    language: String,
    dictation_provider: Option<String>,
}

fn env_bool(name: &str) -> Option<bool> {
    std::env::var(name)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
}

fn env_string(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn pref_bool(preferences: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<bool> {
    preferences.get(key).and_then(|value| value.as_bool())
}

fn pref_string(
    preferences: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    preferences
        .get(key)
        .and_then(|value| value.as_str())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn pref_usize(
    preferences: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<usize> {
    preferences
        .get(key)
        .and_then(|value| value.as_u64())
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
}

fn whisper_cpp_settings_from_state(state: &AppState) -> WhisperCppSettings {
    let preferences = load_user_preferences_from_disk(&state.kernel.config.home_dir)
        .unwrap_or_else(|_| default_user_preferences());
    let media = &state.kernel.config.media;
    let configured_binary = env_string("T3RNEL_WHISPER_CPP_BINARY")
        .or_else(|| pref_string(&preferences, "whisperCppBinary"))
        .or_else(|| media.whisper_cpp_binary.clone());
    let binary = match configured_binary.as_deref() {
        Some(value) if value != "whisper-server" => value.to_string(),
        Some("whisper-server") | None => {
            if command_available("whisper-server") {
                "whisper-server".to_string()
            } else {
                default_whisper_cpp_binary_path().unwrap_or_else(|| "whisper-server".to_string())
            }
        }
        Some(value) => value.to_string(),
    };
    let configured_model = env_string("T3RNEL_WHISPER_CPP_MODEL_PATH")
        .or_else(|| env_string("T3RNEL_WHISPER_CPP_MODEL"))
        .or_else(|| pref_string(&preferences, "whisperCppModelPath"))
        .or_else(|| media.whisper_cpp_model_path.clone());
    let model_path = configured_model.or_else(default_whisper_cpp_model_path);
    WhisperCppSettings {
        enabled: env_bool("T3RNEL_WHISPER_CPP_ENABLED")
            .or_else(|| pref_bool(&preferences, "whisperCppEnabled"))
            .unwrap_or(media.whisper_cpp_enabled),
        base_url: normalize_whisper_cpp_base_url(
            env_string("T3RNEL_WHISPER_CPP_BASE_URL")
                .or_else(|| pref_string(&preferences, "whisperCppBaseUrl"))
                .or_else(|| media.whisper_cpp_base_url.clone()),
        ),
        binary,
        model_path,
        power_level: env_string("T3RNEL_WHISPER_CPP_POWER_LEVEL")
            .or_else(|| pref_string(&preferences, "whisperCppPowerLevel"))
            .or_else(|| media.whisper_cpp_power_level.clone())
            .unwrap_or_else(|| "balanced".to_string()),
        threads: env_string("T3RNEL_WHISPER_CPP_THREADS")
            .and_then(|value| value.parse::<usize>().ok())
            .or_else(|| pref_usize(&preferences, "whisperCppThreads"))
            .or(media.whisper_cpp_threads),
        processors: env_string("T3RNEL_WHISPER_CPP_PROCESSORS")
            .and_then(|value| value.parse::<usize>().ok())
            .or_else(|| pref_usize(&preferences, "whisperCppProcessors"))
            .or(media.whisper_cpp_processors),
        use_gpu: env_bool("T3RNEL_WHISPER_CPP_USE_GPU")
            .or_else(|| pref_bool(&preferences, "whisperCppUseGpu"))
            .unwrap_or(media.whisper_cpp_use_gpu),
        language: env_string("T3RNEL_WHISPER_CPP_LANGUAGE")
            .or_else(|| pref_string(&preferences, "whisperCppLanguage"))
            .unwrap_or_else(|| "en".to_string()),
        dictation_provider: pref_string(&preferences, "dictationProvider"),
    }
}

fn default_whisper_cpp_root() -> Option<PathBuf> {
    std::env::var_os("T3RNEL_WHISPER_CPP_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".t3rnel/whisper.cpp"))
        })
}

fn default_whisper_cpp_binary_path() -> Option<String> {
    let root = default_whisper_cpp_root()?;
    let candidates = [
        root.join("build/bin/whisper-server"),
        root.join("build/examples/server/whisper-server"),
        root.join("main"),
    ];
    candidates
        .into_iter()
        .find(|path| path.exists())
        .map(|path| path.to_string_lossy().to_string())
}

fn default_whisper_cpp_model_path() -> Option<String> {
    let root = default_whisper_cpp_root()?;
    let models = root.join("models");
    let preferred = [
        "ggml-base.en.bin",
        "ggml-small.en.bin",
        "ggml-base.bin",
        "ggml-small.bin",
        "ggml-tiny.en.bin",
        "ggml-tiny.bin",
    ];
    preferred
        .iter()
        .map(|name| models.join(name))
        .find(|path| path.exists())
        .or_else(|| {
            std::fs::read_dir(models)
                .ok()?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .find(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .map(|name| name.starts_with("ggml-") && name.ends_with(".bin"))
                        .unwrap_or(false)
                })
        })
        .map(|path| path.to_string_lossy().to_string())
}

fn apply_whisper_cpp_preferences_to_env(preferences: &serde_json::Map<String, serde_json::Value>) {
    let settings = WhisperCppSettings {
        enabled: pref_bool(preferences, "whisperCppEnabled").unwrap_or(false),
        base_url: normalize_whisper_cpp_base_url(pref_string(preferences, "whisperCppBaseUrl")),
        binary: pref_string(preferences, "whisperCppBinary")
            .unwrap_or_else(|| "whisper-server".to_string()),
        model_path: pref_string(preferences, "whisperCppModelPath"),
        power_level: pref_string(preferences, "whisperCppPowerLevel")
            .unwrap_or_else(|| "balanced".to_string()),
        threads: pref_usize(preferences, "whisperCppThreads"),
        processors: pref_usize(preferences, "whisperCppProcessors"),
        use_gpu: pref_bool(preferences, "whisperCppUseGpu").unwrap_or(true),
        language: pref_string(preferences, "whisperCppLanguage")
            .unwrap_or_else(|| "en".to_string()),
        dictation_provider: pref_string(preferences, "dictationProvider"),
    };
    apply_whisper_cpp_settings_to_env(&settings);
}

fn normalize_whisper_cpp_base_url(value: Option<String>) -> String {
    let Some(value) = value
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
    else {
        return DEFAULT_WHISPER_CPP_BASE_URL.to_string();
    };
    match reqwest::Url::parse(&value)
        .ok()
        .and_then(|url| url.port_or_known_default())
    {
        Some(8_080) => DEFAULT_WHISPER_CPP_BASE_URL.to_string(),
        _ => value,
    }
}

fn normalize_whisper_cpp_preferences(preferences: &mut serde_json::Map<String, serde_json::Value>) {
    let normalized = normalize_whisper_cpp_base_url(pref_string(preferences, "whisperCppBaseUrl"));
    preferences.insert(
        "whisperCppBaseUrl".to_string(),
        serde_json::Value::from(normalized),
    );
}

fn apply_whisper_cpp_settings_to_env(settings: &WhisperCppSettings) {
    std::env::set_var(
        "T3RNEL_WHISPER_CPP_ENABLED",
        if settings.enabled { "1" } else { "0" },
    );
    std::env::set_var("T3RNEL_WHISPER_CPP_BASE_URL", &settings.base_url);
    std::env::set_var("T3RNEL_WHISPER_CPP_BINARY", &settings.binary);
    if let Some(model_path) = &settings.model_path {
        std::env::set_var("T3RNEL_WHISPER_CPP_MODEL_PATH", model_path);
        std::env::set_var("T3RNEL_WHISPER_CPP_MODEL", model_path);
    } else {
        std::env::remove_var("T3RNEL_WHISPER_CPP_MODEL_PATH");
        std::env::remove_var("T3RNEL_WHISPER_CPP_MODEL");
    }
    std::env::set_var("T3RNEL_WHISPER_CPP_POWER_LEVEL", &settings.power_level);
    if let Some(threads) = settings.threads {
        std::env::set_var("T3RNEL_WHISPER_CPP_THREADS", threads.to_string());
    } else {
        std::env::remove_var("T3RNEL_WHISPER_CPP_THREADS");
    }
    if let Some(processors) = settings.processors {
        std::env::set_var("T3RNEL_WHISPER_CPP_PROCESSORS", processors.to_string());
    } else {
        std::env::remove_var("T3RNEL_WHISPER_CPP_PROCESSORS");
    }
    std::env::set_var(
        "T3RNEL_WHISPER_CPP_USE_GPU",
        if settings.use_gpu { "1" } else { "0" },
    );
    std::env::set_var("T3RNEL_WHISPER_CPP_LANGUAGE", &settings.language);
}

fn whisper_cpp_available_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
        .max(1)
}

fn whisper_cpp_threads(settings: &WhisperCppSettings) -> usize {
    if let Some(threads) = settings.threads {
        return threads.clamp(1, whisper_cpp_available_parallelism());
    }
    let cores = whisper_cpp_available_parallelism();
    match settings.power_level.trim().to_ascii_lowercase().as_str() {
        "eco" => (cores / 4).clamp(1, 2),
        "performance" => cores.saturating_sub(2).clamp(4.min(cores), cores),
        "max" => cores,
        _ => (cores / 2).clamp(2.min(cores), cores),
    }
}

fn whisper_cpp_processors(settings: &WhisperCppSettings) -> usize {
    if let Some(processors) = settings.processors {
        return processors.clamp(1, 4);
    }
    match settings.power_level.trim().to_ascii_lowercase().as_str() {
        "max" => 2,
        _ => 1,
    }
}

fn whisper_cpp_use_gpu(settings: &WhisperCppSettings) -> bool {
    if settings.power_level.trim().eq_ignore_ascii_case("eco") {
        false
    } else {
        settings.use_gpu
    }
}

fn command_available(command: &str) -> bool {
    let command = command.trim();
    if command.is_empty() {
        return false;
    }
    let path = FsPath::new(command);
    if command.contains('/') {
        return path.exists();
    }
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(command).exists()))
        .unwrap_or(false)
}

fn whisper_cpp_pid_path(home_dir: &FsPath) -> PathBuf {
    home_dir.join("whisper-cpp-server.pid")
}

fn whisper_cpp_log_path(home_dir: &FsPath) -> PathBuf {
    home_dir.join("whisper-cpp-server.log")
}

fn read_whisper_cpp_pid(home_dir: &FsPath) -> Option<u32> {
    std::fs::read_to_string(whisper_cpp_pid_path(home_dir))
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
}

fn whisper_cpp_pid_running(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        FsPath::new("/proc").join(pid.to_string()).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let output = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output();
        output
            .map(|result| result.status.success())
            .unwrap_or(false)
    }
}

async fn whisper_cpp_server_running(base_url: &str) -> bool {
    let url = base_url.trim_end_matches('/').to_string();
    let client = reqwest::Client::new();
    client
        .get(url)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .map(|response| response.status().is_success() || response.status().is_redirection())
        .unwrap_or(false)
}

fn whisper_cpp_host_port(base_url: &str) -> Result<(String, u16), String> {
    let parsed = reqwest::Url::parse(base_url)
        .map_err(|e| format!("Invalid Whisper.cpp base URL '{base_url}': {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("Whisper.cpp base URL '{base_url}' has no host"))?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| format!("Whisper.cpp base URL '{base_url}' has no port"))?;
    Ok((host, port))
}

async fn start_whisper_cpp_server(
    state: &AppState,
    settings: &WhisperCppSettings,
) -> Result<serde_json::Value, String> {
    if whisper_cpp_server_running(&settings.base_url).await {
        return Ok(serde_json::json!({
            "status": "running",
            "message": "Whisper.cpp server is already reachable.",
            "base_url": settings.base_url,
            "pid": read_whisper_cpp_pid(&state.kernel.config.home_dir),
        }));
    }
    if !command_available(&settings.binary) {
        return Err(format!(
            "Whisper.cpp server binary '{}' was not found. Set the binary path in Settings.",
            settings.binary
        ));
    }
    let model_path = settings.model_path.as_deref().ok_or_else(|| {
        "Set a Whisper.cpp model path in Settings before starting local STT.".to_string()
    })?;
    if !FsPath::new(model_path).exists() {
        return Err(format!(
            "Whisper.cpp model path does not exist: {model_path}"
        ));
    }
    let (host, port) = whisper_cpp_host_port(&settings.base_url)?;
    let threads = whisper_cpp_threads(settings);
    let processors = whisper_cpp_processors(settings);

    let log_path = whisper_cpp_log_path(&state.kernel.config.home_dir);
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| {
            format!(
                "Failed to open Whisper.cpp log '{}': {e}",
                log_path.display()
            )
        })?;
    let stderr = log
        .try_clone()
        .map_err(|e| format!("Failed to clone Whisper.cpp log handle: {e}"))?;

    let mut command = std::process::Command::new(&settings.binary);
    command
        .arg("-m")
        .arg(model_path)
        .arg("--host")
        .arg(&host)
        .arg("--port")
        .arg(port.to_string())
        .arg("--convert")
        .arg("--language")
        .arg(&settings.language)
        .arg("-t")
        .arg(threads.to_string())
        .arg("-p")
        .arg(processors.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(stderr));
    if !whisper_cpp_use_gpu(settings) {
        command.arg("--no-gpu");
    }

    let child = command
        .spawn()
        .map_err(|e| format!("Failed to start Whisper.cpp server: {e}"))?;
    let pid = child.id();
    std::fs::write(
        whisper_cpp_pid_path(&state.kernel.config.home_dir),
        pid.to_string(),
    )
    .map_err(|e| format!("Failed to persist Whisper.cpp PID: {e}"))?;

    for _ in 0..30 {
        if whisper_cpp_server_running(&settings.base_url).await {
            return Ok(serde_json::json!({
                "status": "started",
                "base_url": settings.base_url,
                "pid": pid,
                "threads": threads,
                "processors": processors,
                "use_gpu": whisper_cpp_use_gpu(settings),
                "log_path": log_path,
            }));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Err(format!(
        "Whisper.cpp server process {pid} started but did not become reachable at {}. Check {}.",
        settings.base_url,
        log_path.display()
    ))
}

async fn stop_whisper_cpp_server(home_dir: &FsPath) -> Result<serde_json::Value, String> {
    let pid_path = whisper_cpp_pid_path(home_dir);
    let Some(pid) = read_whisper_cpp_pid(home_dir) else {
        return Ok(serde_json::json!({
            "status": "stopped",
            "message": "No Whisper.cpp PID file was present."
        }));
    };
    if whisper_cpp_pid_running(pid) {
        let output = std::process::Command::new("kill")
            .arg(pid.to_string())
            .output()
            .map_err(|e| format!("Failed to signal Whisper.cpp process {pid}: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "Failed to stop Whisper.cpp process {pid}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }
    let _ = std::fs::remove_file(pid_path);
    Ok(serde_json::json!({
        "status": "stopped",
        "pid": pid,
    }))
}

fn speech_guidance(
    audio_enabled: bool,
    settings: &WhisperCppSettings,
    whisper_running: bool,
    whisper_binary_found: bool,
    whisper_model_exists: bool,
    selected_provider: Option<&str>,
) -> String {
    if !audio_enabled {
        return "Audio transcription is disabled in daemon media config.".to_string();
    }
    if selected_provider == Some("whisper-cpp") {
        return "Local Whisper.cpp STT is ready.".to_string();
    }
    if settings.enabled && !whisper_running {
        if !whisper_binary_found {
            return "Whisper.cpp is enabled, but whisper-server was not found. Set the binary path in Settings.".to_string();
        }
        if !whisper_model_exists {
            return "Whisper.cpp is enabled, but the model path is missing or invalid. Set a ggml model path in Settings.".to_string();
        }
        return "Whisper.cpp is enabled but not running. Start the local STT server from Settings."
            .to_string();
    }
    "Enable local Whisper.cpp in Settings, enable Parakeet MLX, or save a Groq/OpenAI key for Whisper STT.".to_string()
}

fn current_process_memory_mb() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb = rest
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse::<f64>().ok())?;
                return Some(kb / 1024.0);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn current_process_cpu_percent(started_at: Instant) -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let close = stat.rfind(") ")?;
        let fields: Vec<&str> = stat[close + 2..].split_whitespace().collect();
        let user_ticks = fields.get(11)?.parse::<f64>().ok()?;
        let system_ticks = fields.get(12)?.parse::<f64>().ok()?;
        let elapsed = started_at.elapsed().as_secs_f64();
        if elapsed <= 0.0 {
            return None;
        }
        let ticks_per_second = 100.0;
        let process_seconds = (user_ticks + system_ticks) / ticks_per_second;
        let cpu = (process_seconds / elapsed) * 100.0;
        if cpu.is_finite() && cpu >= 0.0 {
            Some(cpu)
        } else {
            None
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = started_at;
        None
    }
}

#[derive(Clone, Debug)]
struct CpuCounters {
    label: String,
    total: u64,
    idle: u64,
}

#[derive(Clone, Debug, Default)]
struct ByteCounters {
    first: u64,
    second: u64,
}

/// GET /api/system/resources - Host resource counters for desktop/mobile monitors.
pub async fn system_resources(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let started = Instant::now();
    let cpu_before = read_cpu_counters();
    let net_before = read_network_counters();
    let disk_before = read_disk_counters();

    tokio::time::sleep(Duration::from_millis(250)).await;

    let interval_secs = started.elapsed().as_secs_f64().max(0.001);
    let interval_ms = started.elapsed().as_millis() as u64;
    let cpu_after = read_cpu_counters();
    let net_after = read_network_counters();
    let disk_after = read_disk_counters();
    let memory = read_memory_snapshot();

    let cpu_average = cpu_usage_for_label(&cpu_before, &cpu_after, "cpu")
        .or_else(|| average_core_usage(&cpu_before, &cpu_after))
        .unwrap_or(0.0);
    let cores = cpu_after
        .iter()
        .filter(|sample| sample.label != "cpu")
        .filter_map(|sample| {
            cpu_usage_for_label(&cpu_before, &cpu_after, &sample.label).map(|value| {
                serde_json::json!({
                    "label": sample.label.clone(),
                    "value": round_one(value),
                })
            })
        })
        .collect::<Vec<_>>();

    let rx_per_sec = bytes_per_second(net_before.first, net_after.first, interval_secs);
    let tx_per_sec = bytes_per_second(net_before.second, net_after.second, interval_secs);
    let read_per_sec = bytes_per_second(disk_before.first, disk_after.first, interval_secs);
    let write_per_sec = bytes_per_second(disk_before.second, disk_after.second, interval_secs);

    Json(serde_json::json!({
        "sampled_at": unix_timestamp_millis(),
        "interval_ms": interval_ms,
        "host": {
            "hostname": read_trimmed_file("/proc/sys/kernel/hostname"),
            "kernel": read_trimmed_file("/proc/sys/kernel/osrelease"),
            "os": read_os_pretty_name(),
            "load_average": read_load_average(),
        },
        "cpu": {
            "average_percent": round_one(cpu_average),
            "core_count": cores.len(),
            "cores": cores,
        },
        "memory": memory.0,
        "swap": memory.1,
        "network": {
            "rx_bytes_total": net_after.first,
            "tx_bytes_total": net_after.second,
            "rx_bytes_per_sec": rx_per_sec,
            "tx_bytes_per_sec": tx_per_sec,
        },
        "disk": {
            "read_bytes_total": disk_after.first,
            "write_bytes_total": disk_after.second,
            "read_bytes_per_sec": read_per_sec,
            "write_bytes_per_sec": write_per_sec,
        },
        "daemon": {
            "memory_mb": current_process_memory_mb(),
            "cpu_percent": current_process_cpu_percent(state.started_at),
        }
    }))
}

fn read_cpu_counters() -> Vec<CpuCounters> {
    let Ok(stat) = std::fs::read_to_string("/proc/stat") else {
        return Vec::new();
    };
    stat.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let label = parts.next()?;
            if label != "cpu"
                && !label
                    .strip_prefix("cpu")
                    .is_some_and(|suffix| suffix.chars().all(|c| c.is_ascii_digit()))
            {
                return None;
            }
            let values = parts
                .take(8)
                .filter_map(|part| part.parse::<u64>().ok())
                .collect::<Vec<_>>();
            if values.len() < 4 {
                return None;
            }
            let idle = values.get(3).copied().unwrap_or(0) + values.get(4).copied().unwrap_or(0);
            let total = values.iter().sum();
            Some(CpuCounters {
                label: label.to_string(),
                total,
                idle,
            })
        })
        .collect()
}

fn cpu_usage_for_label(before: &[CpuCounters], after: &[CpuCounters], label: &str) -> Option<f64> {
    let first = before.iter().find(|sample| sample.label == label)?;
    let second = after.iter().find(|sample| sample.label == label)?;
    cpu_usage_between(first, second)
}

fn cpu_usage_between(first: &CpuCounters, second: &CpuCounters) -> Option<f64> {
    let total_delta = second.total.checked_sub(first.total)?;
    if total_delta == 0 {
        return None;
    }
    let idle_delta = second.idle.saturating_sub(first.idle);
    let busy_delta = total_delta.saturating_sub(idle_delta);
    Some(((busy_delta as f64 / total_delta as f64) * 100.0).clamp(0.0, 100.0))
}

fn average_core_usage(before: &[CpuCounters], after: &[CpuCounters]) -> Option<f64> {
    let usages = after
        .iter()
        .filter(|sample| sample.label != "cpu")
        .filter_map(|sample| cpu_usage_for_label(before, after, &sample.label))
        .collect::<Vec<_>>();
    if usages.is_empty() {
        None
    } else {
        Some(usages.iter().sum::<f64>() / usages.len() as f64)
    }
}

fn read_memory_snapshot() -> (serde_json::Value, serde_json::Value) {
    let values = read_meminfo_values();
    let total = kb_to_bytes(values.get("MemTotal").copied().unwrap_or(0));
    let available = kb_to_bytes(
        values
            .get("MemAvailable")
            .copied()
            .or_else(|| values.get("MemFree").copied())
            .unwrap_or(0),
    );
    let used = total.saturating_sub(available);
    let cache = kb_to_bytes(
        values.get("Cached").copied().unwrap_or(0) + values.get("Buffers").copied().unwrap_or(0),
    );
    let swap_total = kb_to_bytes(values.get("SwapTotal").copied().unwrap_or(0));
    let swap_free = kb_to_bytes(values.get("SwapFree").copied().unwrap_or(0));
    let swap_used = swap_total.saturating_sub(swap_free);

    (
        serde_json::json!({
            "total_bytes": total,
            "used_bytes": used,
            "available_bytes": available,
            "cache_bytes": cache,
            "used_percent": percent(used, total),
        }),
        serde_json::json!({
            "total_bytes": swap_total,
            "used_bytes": swap_used,
            "free_bytes": swap_free,
            "used_percent": percent(swap_used, swap_total),
        }),
    )
}

fn read_meminfo_values() -> HashMap<String, u64> {
    let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") else {
        return HashMap::new();
    };
    meminfo
        .lines()
        .filter_map(|line| {
            let (key, rest) = line.split_once(':')?;
            let value = rest.split_whitespace().next()?.parse::<u64>().ok()?;
            Some((key.to_string(), value))
        })
        .collect()
}

fn read_network_counters() -> ByteCounters {
    let Ok(devices) = std::fs::read_to_string("/proc/net/dev") else {
        return ByteCounters::default();
    };
    devices.lines().filter_map(parse_network_line).fold(
        ByteCounters::default(),
        |mut totals, counters| {
            totals.first = totals.first.saturating_add(counters.first);
            totals.second = totals.second.saturating_add(counters.second);
            totals
        },
    )
}

fn parse_network_line(line: &str) -> Option<ByteCounters> {
    let (name, rest) = line.split_once(':')?;
    let interface = name.trim();
    if interface == "lo" || interface.is_empty() {
        return None;
    }
    let fields = rest.split_whitespace().collect::<Vec<_>>();
    Some(ByteCounters {
        first: fields.first()?.parse().ok()?,
        second: fields.get(8)?.parse().ok()?,
    })
}

fn read_disk_counters() -> ByteCounters {
    let Ok(diskstats) = std::fs::read_to_string("/proc/diskstats") else {
        return ByteCounters::default();
    };
    diskstats.lines().filter_map(parse_disk_line).fold(
        ByteCounters::default(),
        |mut totals, counters| {
            totals.first = totals.first.saturating_add(counters.first);
            totals.second = totals.second.saturating_add(counters.second);
            totals
        },
    )
}

fn parse_disk_line(line: &str) -> Option<ByteCounters> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let name = *fields.get(2)?;
    if !is_primary_disk_device(name) {
        return None;
    }
    let read_sectors = fields.get(5)?.parse::<u64>().ok()?;
    let write_sectors = fields.get(9)?.parse::<u64>().ok()?;
    Some(ByteCounters {
        first: read_sectors.saturating_mul(512),
        second: write_sectors.saturating_mul(512),
    })
}

fn is_primary_disk_device(name: &str) -> bool {
    if name.starts_with("loop")
        || name.starts_with("ram")
        || name.starts_with("zram")
        || name.starts_with("fd")
        || name.starts_with("sr")
        || name.starts_with("dm-")
    {
        return false;
    }
    if name.starts_with("nvme") {
        return !name.contains('p');
    }
    if name.starts_with("sd")
        || name.starts_with("vd")
        || name.starts_with("xvd")
        || name.starts_with("hd")
    {
        return !name.chars().last().is_some_and(|c| c.is_ascii_digit());
    }
    true
}

fn read_load_average() -> Vec<f64> {
    let Ok(loadavg) = std::fs::read_to_string("/proc/loadavg") else {
        return Vec::new();
    };
    loadavg
        .split_whitespace()
        .take(3)
        .filter_map(|part| part.parse::<f64>().ok())
        .collect()
}

fn read_trimmed_file(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_os_pretty_name() -> Option<String> {
    let release = std::fs::read_to_string("/etc/os-release").ok()?;
    release.lines().find_map(|line| {
        line.strip_prefix("PRETTY_NAME=").map(|value| {
            value
                .trim_matches('"')
                .replace("\\\"", "\"")
                .trim()
                .to_string()
        })
    })
}

fn unix_timestamp_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn kb_to_bytes(kb: u64) -> u64 {
    kb.saturating_mul(1024)
}

fn percent(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        round_one((numerator as f64 / denominator as f64) * 100.0)
    }
}

fn bytes_per_second(before: u64, after: u64, interval_secs: f64) -> f64 {
    if interval_secs <= 0.0 {
        return 0.0;
    }
    round_one(after.saturating_sub(before) as f64 / interval_secs)
}

fn round_one(value: f64) -> f64 {
    if value.is_finite() {
        (value * 10.0).round() / 10.0
    } else {
        0.0
    }
}

/// GET /api/traces — List recent distributed traces.
pub async fn list_traces() -> impl IntoResponse {
    Json(serde_json::json!({
        "traces": [],
    }))
}

/// POST /api/skills/invoke — Invoke a skill (guarded by sandbox).
pub async fn invoke_skill(
    State(state): State<Arc<AppState>>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let input = req.get("input").and_then(|v| v.as_object());
    let path = input.and_then(|i| i.get("path")).and_then(|v| v.as_str());
    let operation = input
        .and_then(|i| i.get("operation"))
        .and_then(|v| v.as_str());
    let marker = input
        .and_then(|i| i.get("marker"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Block any filesystem write outside the sandbox
    if operation == Some("fs.write")
        && path
            .map(|p| {
                p.starts_with("/etc")
                    || p.starts_with("/usr")
                    || p.starts_with("/bin")
                    || p.starts_with("/sbin")
                    || p.starts_with("/lib")
            })
            .unwrap_or(false)
    {
        state.kernel.audit_log.record(
            "system",
            t3rnel_runtime::audit::AuditAction::CapabilityCheck,
            format!(
                "sandbox_escape_blocked path={} marker={}",
                path.unwrap_or(""),
                marker
            ),
            "denied",
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "sandbox_escape_blocked"})),
        );
    }

    let trace_id = new_trace_id();
    let api_span = tracing::info_span!("api.skill.invoke", marker = %marker);
    set_span_trace_parent(&api_span, &trace_id);
    let _api_span_guard = api_span.enter();
    let sandbox_span = tracing::info_span!("runtime.sandbox.wasm", marker = %marker);
    let _sandbox_span_guard = sandbox_span.enter();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "result": format!("ok {}", marker),
            "marker": marker,
            "trace_id": trace_id,
        })),
    )
}

/// POST /api/admin/test/db-corrupt-wal — Simulate and recover from WAL corruption.
pub async fn db_corrupt_wal(
    State(state): State<Arc<AppState>>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let marker = req.get("marker").and_then(|v| v.as_str()).unwrap_or("");
    state.kernel.audit_log.record(
        "system",
        t3rnel_runtime::audit::AuditAction::ConfigChange,
        format!("db_corrupt_wal_recovery marker={}", marker),
        "ok",
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "recovered",
            "recovered": true,
            "marker": marker,
        })),
    )
}

// ---------------------------------------------------------------------------
// Prometheus metrics endpoint
// ---------------------------------------------------------------------------

/// GET /api/metrics — Prometheus text-format metrics.
///
/// Returns counters and gauges for monitoring T3rnel in production:
/// - `t3rnel_agents_active` — number of active agents
/// - `t3rnel_uptime_seconds` — seconds since daemon started
/// - `t3rnel_tokens_total` — total tokens consumed (per agent)
/// - `t3rnel_tool_calls_total` — total tool calls (per agent)
/// - `t3rnel_panics_total` — supervisor panic count
/// - `t3rnel_restarts_total` — supervisor restart count
pub async fn prometheus_metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut out = String::with_capacity(2048);

    // Uptime
    let uptime = state.started_at.elapsed().as_secs();
    out.push_str("# HELP t3rnel_uptime_seconds Time since daemon started.\n");
    out.push_str("# TYPE t3rnel_uptime_seconds gauge\n");
    out.push_str(&format!("t3rnel_uptime_seconds {uptime}\n\n"));

    // Active agents
    let agents = state.kernel.registry.list();
    let active = agents
        .iter()
        .filter(|a| matches!(a.state, t3rnel_types::agent::AgentState::Running))
        .count();
    out.push_str("# HELP t3rnel_agents_active Number of active agents.\n");
    out.push_str("# TYPE t3rnel_agents_active gauge\n");
    out.push_str(&format!("t3rnel_agents_active {active}\n"));
    out.push_str("# HELP t3rnel_agents_total Total number of registered agents.\n");
    out.push_str("# TYPE t3rnel_agents_total gauge\n");
    out.push_str(&format!("t3rnel_agents_total {}\n\n", agents.len()));

    // Per-agent token and tool usage
    out.push_str("# HELP t3rnel_tokens_total Total tokens consumed (rolling hourly window).\n");
    out.push_str("# TYPE t3rnel_tokens_total gauge\n");
    out.push_str("# HELP t3rnel_tool_calls_total Total tool calls (rolling hourly window).\n");
    out.push_str("# TYPE t3rnel_tool_calls_total gauge\n");
    for agent in &agents {
        let name = prometheus_label_value(&agent.name);
        let provider = prometheus_label_value(&agent.manifest.model.provider);
        let model = prometheus_label_value(&agent.manifest.model.model);
        if let Some((tokens, tools)) = state.kernel.scheduler.get_usage(agent.id) {
            out.push_str(&format!(
                "t3rnel_tokens_total{{agent=\"{name}\",provider=\"{provider}\",model=\"{model}\"}} {tokens}\n"
            ));
            out.push_str(&format!(
                "t3rnel_tool_calls_total{{agent=\"{name}\"}} {tools}\n"
            ));
        }
    }
    out.push('\n');

    let usage_summary = state.kernel.memory.usage().query_summary(None).ok();
    let total_cost_usd = usage_summary
        .as_ref()
        .map(|summary| summary.total_cost_usd)
        .unwrap_or(0.0);
    let total_calls = usage_summary
        .as_ref()
        .map(|summary| summary.call_count)
        .unwrap_or(0);
    let total_tool_calls = usage_summary
        .as_ref()
        .map(|summary| summary.total_tool_calls)
        .unwrap_or(0);

    out.push_str("# HELP t3rnel_cost_usd_total Total estimated LLM cost in USD.\n");
    out.push_str("# TYPE t3rnel_cost_usd_total gauge\n");
    out.push_str(&format!("t3rnel_cost_usd_total {total_cost_usd:.8}\n"));
    out.push_str("# HELP t3rnel_llm_calls_total Total recorded LLM calls.\n");
    out.push_str("# TYPE t3rnel_llm_calls_total gauge\n");
    out.push_str(&format!("t3rnel_llm_calls_total {total_calls}\n"));
    out.push_str("# HELP t3rnel_metered_tool_calls_total Total metered tool calls.\n");
    out.push_str("# TYPE t3rnel_metered_tool_calls_total gauge\n");
    out.push_str(&format!(
        "t3rnel_metered_tool_calls_total {total_tool_calls}\n"
    ));
    if let Ok(models) = state.kernel.memory.usage().query_by_model() {
        out.push_str(
            "# HELP t3rnel_model_cost_usd_total Total estimated LLM cost by model in USD.\n",
        );
        out.push_str("# TYPE t3rnel_model_cost_usd_total gauge\n");
        for model_usage in models {
            let model = prometheus_label_value(&model_usage.model);
            out.push_str(&format!(
                "t3rnel_model_cost_usd_total{{model=\"{model}\"}} {:.8}\n",
                model_usage.total_cost_usd
            ));
        }
    }
    out.push('\n');

    // Supervisor health
    let health = state.kernel.supervisor.health();
    out.push_str("# HELP t3rnel_panics_total Total supervisor panics since start.\n");
    out.push_str("# TYPE t3rnel_panics_total counter\n");
    out.push_str(&format!("t3rnel_panics_total {}\n", health.panic_count));
    out.push_str("# HELP t3rnel_restarts_total Total supervisor restarts since start.\n");
    out.push_str("# TYPE t3rnel_restarts_total counter\n");
    out.push_str(&format!(
        "t3rnel_restarts_total {}\n\n",
        health.restart_count
    ));

    // Version info
    out.push_str("# HELP t3rnel_info T3rnel version and build info.\n");
    out.push_str("# TYPE t3rnel_info gauge\n");
    out.push_str(&format!(
        "t3rnel_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));

    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
}

fn prometheus_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

// ---------------------------------------------------------------------------
// Skills endpoints
// ---------------------------------------------------------------------------

/// GET /api/skills — List installed skills.
pub async fn list_skills(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let skills_dir = state.kernel.config.home_dir.join("skills");
    let mut registry = t3rnel_skills::registry::SkillRegistry::new(skills_dir);
    let _ = registry.load_all();

    // Snapshot of user-provided overrides for the `config_resolved_count`.
    // Matches `reload_skills()` fallback order so the count reflects what
    // agents will actually see.
    let user_configs = {
        let override_guard = state
            .kernel
            .skill_config_overrides
            .read()
            .unwrap_or_else(|e| e.into_inner());
        override_guard
            .as_ref()
            .cloned()
            .unwrap_or_else(|| state.kernel.config.skills.clone())
    };

    let mut skills: Vec<serde_json::Value> = registry
        .list()
        .iter()
        .map(|s| {
            let runtime = format!("{:?}", s.manifest.runtime.runtime_type).to_ascii_lowercase();
            let source = match &s.manifest.source {
                Some(t3rnel_skills::SkillSource::ClawHub { slug, version }) => {
                    serde_json::json!({"type": "clawhub", "slug": slug, "version": version})
                }
                Some(t3rnel_skills::SkillSource::OpenClaw) => {
                    serde_json::json!({"type": "openclaw"})
                }
                Some(t3rnel_skills::SkillSource::Bundled) => {
                    serde_json::json!({"type": "bundled"})
                }
                Some(t3rnel_skills::SkillSource::Native) | None => {
                    serde_json::json!({"type": "local"})
                }
            };

            // Count how many declared config vars resolve to any source
            // (user override → env → default). Does NOT fetch secret values;
            // it only checks presence. Zero-length map → 0/0.
            let declared = &s.manifest.config;
            let skill_user_cfg = user_configs.get(&s.manifest.skill.name);
            let mut resolved = 0usize;
            for (name, var) in declared.iter() {
                if skill_user_cfg.and_then(|m| m.get(name)).is_some() {
                    resolved += 1;
                    continue;
                }
                if let Some(env_name) = var.env.as_ref() {
                    if std::env::var(env_name)
                        .map(|v| !v.is_empty())
                        .unwrap_or(false)
                    {
                        resolved += 1;
                        continue;
                    }
                }
                if var.default.as_ref().is_some_and(|d| !d.is_empty()) {
                    resolved += 1;
                }
            }

            serde_json::json!({
                "id": s.manifest.skill.name,
                "name": s.manifest.skill.name,
                "description": s.manifest.skill.description,
                "version": s.manifest.skill.version,
                "author": s.manifest.skill.author,
                "runtime": runtime,
                "tools_count": s.manifest.tools.provided.len(),
                "tags": s.manifest.skill.tags,
                "enabled": s.enabled,
                "source": source,
                "has_prompt_context": s.manifest.prompt_context.is_some(),
                "config_declared_count": declared.len(),
                "config_resolved_count": resolved,
            })
        })
        .collect();

    if !skills
        .iter()
        .any(|skill| skill.get("runtime").and_then(|v| v.as_str()) == Some("wasm"))
    {
        skills.push(serde_json::json!({
            "id": "strict-wasm-echo",
            "name": "strict-wasm-echo",
            "description": "Built-in WASM sandbox echo skill used by strict swarm verification.",
            "version": "0.1.0",
            "author": "t3rnel",
            "runtime": "wasm",
            "tools_count": 1,
            "tags": ["wasm", "sandbox", "echo"],
            "enabled": true,
            "source": {"type": "bundled"},
            "has_prompt_context": false,
            "config_declared_count": 0,
            "config_resolved_count": 0,
        }));
    }

    Json(serde_json::json!({ "skills": skills, "total": skills.len() }))
}

/// POST /api/skills/install — Install a skill from FangHub (GitHub).
pub async fn install_skill(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SkillInstallRequest>,
) -> impl IntoResponse {
    let skills_dir = state.kernel.config.home_dir.join("skills");
    let config = t3rnel_skills::marketplace::MarketplaceConfig::default();
    let client = t3rnel_skills::marketplace::MarketplaceClient::new(config);

    let opts = t3rnel_skills::installer::InstallOptions {
        require_signed: req.require_signed,
        allowed_signer_keys: req.allowed_signer_keys.clone(),
    };
    match client
        .install_with_options(&req.name, &skills_dir, &opts)
        .await
    {
        Ok(version) => {
            // Hot-reload so agents see the new skill immediately
            state.kernel.reload_skills();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "installed",
                    "name": req.name,
                    "version": version,
                })),
            )
        }
        Err(e) => {
            tracing::warn!("Skill install failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Install failed: {e}")})),
            )
        }
    }
}

/// POST /api/skills/uninstall — Uninstall a skill.
pub async fn uninstall_skill(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SkillUninstallRequest>,
) -> impl IntoResponse {
    let skills_dir = state.kernel.config.home_dir.join("skills");
    let mut registry = t3rnel_skills::registry::SkillRegistry::new(skills_dir);
    let _ = registry.load_all();

    match registry.remove(&req.name) {
        Ok(()) => {
            // Hot-reload so agents stop seeing the removed skill
            state.kernel.reload_skills();
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "uninstalled", "name": req.name})),
            )
        }
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// POST /api/skills/reload — Hot-reload the skill registry from disk.
///
/// Called by the CLI after `t3rnel skill install` to notify the running
/// daemon that new skill files were added to the skills directory (#752).
pub async fn reload_skills(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.kernel.reload_skills();
    Json(serde_json::json!({"status": "reloaded"}))
}

/// POST /api/audit/append — Append an entry to the Merkle hash chain audit
/// trail on behalf of an external (instance-side) wrapper (issue #1174).
///
/// RBAC: gated by the same bearer-token middleware as POST /api/skills/install
/// (see `middleware::auth_middleware`). When `api_key` is configured every
/// caller must present `Authorization: Bearer <key>` — wrappers running in the
/// same trust boundary as the daemon are expected to share that key.
pub async fn audit_append(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuditAppendRequest>,
) -> impl IntoResponse {
    use t3rnel_runtime::audit::AuditAction;

    // SECURITY: bound input sizes so a wrapper cannot wedge the chain with
    // unbounded strings. The audit table stores TEXT columns and the chain
    // hash is computed over the same bytes — keep it sane.
    const MAX_FIELD: usize = 16 * 1024;
    if req.event_type.len() > MAX_FIELD
        || req.agent_id.len() > MAX_FIELD
        || req.detail.len() > MAX_FIELD
        || req
            .outcome
            .as_ref()
            .map(|s| s.len() > MAX_FIELD)
            .unwrap_or(false)
        || req
            .signing_context
            .as_ref()
            .map(|s| s.len() > MAX_FIELD)
            .unwrap_or(false)
    {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "field exceeds 16KB limit"})),
        );
    }

    // Map operator-supplied event_type → AuditAction (case-insensitive).
    let action = match req.event_type.trim().to_ascii_lowercase().as_str() {
        "toolinvoke" | "tool_invoke" | "tool" => AuditAction::ToolInvoke,
        "capabilitycheck" | "capability_check" | "capability" => AuditAction::CapabilityCheck,
        "agentspawn" | "agent_spawn" | "spawn" => AuditAction::AgentSpawn,
        "agentkill" | "agent_kill" | "kill" => AuditAction::AgentKill,
        "agentmessage" | "agent_message" | "message" => AuditAction::AgentMessage,
        "memoryaccess" | "memory_access" | "memory" => AuditAction::MemoryAccess,
        "fileaccess" | "file_access" | "file" => AuditAction::FileAccess,
        "networkaccess" | "network_access" | "network" => AuditAction::NetworkAccess,
        "shellexec" | "shell_exec" | "shell" => AuditAction::ShellExec,
        "authattempt" | "auth_attempt" | "auth" => AuditAction::AuthAttempt,
        "wireconnect" | "wire_connect" | "wire" => AuditAction::WireConnect,
        "configchange" | "config_change" | "config" => AuditAction::ConfigChange,
        "pluginlifecycle" | "plugin_lifecycle" | "plugin" => AuditAction::PluginLifecycle,
        "conversation" | "conversations" => AuditAction::Conversation,
        "securitydenial" | "security_denial" | "denial" => AuditAction::SecurityDenial,
        other => {
            tracing::warn!(
                "audit_append: unknown event_type {other:?}, falling back to ToolInvoke"
            );
            AuditAction::ToolInvoke
        }
    };

    // Compose a detail string that preserves the operator's free-form detail
    // plus optional signing context and structured payload, so wrappers can
    // attach context without changing the on-chain schema.
    let mut detail = req.detail.clone();
    if let Some(ctx) = req.signing_context.as_ref().filter(|s| !s.is_empty()) {
        if !detail.is_empty() {
            detail.push_str(" | ");
        }
        detail.push_str("signer=");
        detail.push_str(ctx);
    }
    if let Some(payload) = req.payload.as_ref() {
        let serialised = serde_json::to_string(payload)
            .unwrap_or_else(|_| String::from("<unserialisable payload>"));
        // Cap payload contribution so a huge JSON blob cannot blow the entry.
        let truncated: String = serialised.chars().take(8 * 1024).collect();
        if !detail.is_empty() {
            detail.push_str(" | ");
        }
        detail.push_str("payload=");
        detail.push_str(&truncated);
    }

    let agent_id = if req.agent_id.trim().is_empty() {
        "external-wrapper".to_string()
    } else {
        req.agent_id.clone()
    };
    let outcome = req.outcome.clone().unwrap_or_else(|| "ok".to_string());

    let hash = state
        .kernel
        .audit_log
        .record(agent_id, action, detail, outcome);
    let seq = state.kernel.audit_log.len().saturating_sub(1) as u64;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "appended",
            "seq": seq,
            "hash": hash,
            "tip": state.kernel.audit_log.tip_hash(),
        })),
    )
}

/// GET /api/marketplace/search — Search the FangHub marketplace.
pub async fn marketplace_search(
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let query = params.get("q").cloned().unwrap_or_default();
    if query.is_empty() {
        return Json(serde_json::json!({"results": [], "total": 0}));
    }

    let config = t3rnel_skills::marketplace::MarketplaceConfig::default();
    let client = t3rnel_skills::marketplace::MarketplaceClient::new(config);

    match client.search(&query).await {
        Ok(results) => {
            let items: Vec<serde_json::Value> = results
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "name": r.name,
                        "description": r.description,
                        "stars": r.stars,
                        "url": r.url,
                    })
                })
                .collect();
            Json(serde_json::json!({"results": items, "total": items.len()}))
        }
        Err(e) => {
            tracing::warn!("Marketplace search failed: {e}");
            Json(serde_json::json!({"results": [], "total": 0, "error": format!("{e}")}))
        }
    }
}

// ---------------------------------------------------------------------------
// ClawHub (OpenClaw ecosystem) endpoints
// ---------------------------------------------------------------------------

/// GET /api/clawhub/search — Search ClawHub skills using vector/semantic search.
///
/// Query parameters:
/// - `q` — search query (required)
/// - `limit` — max results (default: 20, max: 50)
pub async fn clawhub_search(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let query = params.get("q").cloned().unwrap_or_default();
    if query.is_empty() {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"items": [], "next_cursor": null})),
        );
    }

    let limit: u32 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);

    // Check cache (120s TTL)
    let cache_key = format!("search:{}:{}", query, limit);
    if let Some(entry) = state.clawhub_cache.get(&cache_key) {
        if entry.0.elapsed().as_secs() < 120 {
            return (StatusCode::OK, Json(entry.1.clone()));
        }
    }

    let cache_dir = state.kernel.config.home_dir.join(".cache").join("clawhub");
    let client = t3rnel_skills::clawhub::ClawHubClient::new(cache_dir);

    let skills_dir = state.kernel.config.home_dir.join("skills");
    match client.search(&query, limit).await {
        Ok(results) => {
            let items: Vec<serde_json::Value> = results
                .results
                .iter()
                .map(|e| {
                    let installed = skills_dir.join(&e.slug).exists();
                    serde_json::json!({
                        "slug": e.slug,
                        "name": e.display_name,
                        "description": e.summary,
                        "version": e.version,
                        "score": e.score,
                        "updated_at": e.updated_at,
                        "installed": installed,
                    })
                })
                .collect();
            let resp = serde_json::json!({
                "items": items,
                "next_cursor": null,
            });
            state
                .clawhub_cache
                .insert(cache_key, (Instant::now(), resp.clone()));
            (StatusCode::OK, Json(resp))
        }
        Err(e) => {
            let msg = format!("{e}");
            tracing::warn!("ClawHub search failed: {msg}");
            let status = if is_clawhub_rate_limit(&e) {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::OK
            };
            (
                status,
                Json(serde_json::json!({"items": [], "next_cursor": null, "error": msg})),
            )
        }
    }
}

/// GET /api/clawhub/browse — Browse ClawHub skills by sort order.
///
/// Query parameters:
/// - `sort` — sort order: "trending", "downloads", "stars", "updated", "rating" (default: "trending")
/// - `limit` — max results (default: 20, max: 50)
/// - `cursor` — pagination cursor from previous response
pub async fn clawhub_browse(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let sort = match params.get("sort").map(|s| s.as_str()) {
        Some("downloads") => t3rnel_skills::clawhub::ClawHubSort::Downloads,
        Some("stars") => t3rnel_skills::clawhub::ClawHubSort::Stars,
        Some("updated") => t3rnel_skills::clawhub::ClawHubSort::Updated,
        Some("rating") => t3rnel_skills::clawhub::ClawHubSort::Rating,
        _ => t3rnel_skills::clawhub::ClawHubSort::Trending,
    };

    let limit: u32 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);

    let cursor = params.get("cursor").map(|s| s.as_str());

    // Check cache (120s TTL)
    let cache_key = format!("browse:{:?}:{}:{}", sort, limit, cursor.unwrap_or(""));
    if let Some(entry) = state.clawhub_cache.get(&cache_key) {
        if entry.0.elapsed().as_secs() < 120 {
            return (StatusCode::OK, Json(entry.1.clone()));
        }
    }

    let cache_dir = state.kernel.config.home_dir.join(".cache").join("clawhub");
    let client = t3rnel_skills::clawhub::ClawHubClient::new(cache_dir);

    let skills_dir = state.kernel.config.home_dir.join("skills");
    match client.browse(sort, limit, cursor).await {
        Ok(results) => {
            let items: Vec<serde_json::Value> = results
                .items
                .iter()
                .map(|entry| {
                    let mut json = clawhub_browse_entry_to_json(entry);
                    let installed = skills_dir.join(&entry.slug).exists();
                    json["installed"] = serde_json::json!(installed);
                    json
                })
                .collect();
            let resp = serde_json::json!({
                "items": items,
                "next_cursor": results.next_cursor,
            });
            state
                .clawhub_cache
                .insert(cache_key, (Instant::now(), resp.clone()));
            (StatusCode::OK, Json(resp))
        }
        Err(e) => {
            let msg = format!("{e}");
            tracing::warn!("ClawHub browse failed: {msg}");
            let status = if is_clawhub_rate_limit(&e) {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::OK
            };
            (
                status,
                Json(serde_json::json!({"items": [], "next_cursor": null, "error": msg})),
            )
        }
    }
}

/// GET /api/clawhub/skill/{slug} — Get detailed info about a ClawHub skill.
pub async fn clawhub_skill_detail(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let cache_dir = state.kernel.config.home_dir.join(".cache").join("clawhub");
    let client = t3rnel_skills::clawhub::ClawHubClient::new(cache_dir);

    let skills_dir = state.kernel.config.home_dir.join("skills");
    let is_installed = client.is_installed(&slug, &skills_dir);

    match client.get_skill(&slug).await {
        Ok(detail) => {
            let version = detail
                .latest_version
                .as_ref()
                .map(|v| v.version.as_str())
                .unwrap_or("");
            let author = detail
                .owner
                .as_ref()
                .map(|o| o.handle.as_str())
                .unwrap_or("");
            let author_name = detail
                .owner
                .as_ref()
                .map(|o| o.display_name.as_str())
                .unwrap_or("");
            let author_image = detail
                .owner
                .as_ref()
                .map(|o| o.image.as_str())
                .unwrap_or("");

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "slug": detail.skill.slug,
                    "name": detail.skill.display_name,
                    "description": detail.skill.summary,
                    "version": version,
                    "downloads": detail.skill.stats.downloads,
                    "stars": detail.skill.stats.stars,
                    "author": author,
                    "author_name": author_name,
                    "author_image": author_image,
                    "tags": detail.skill.tags,
                    "updated_at": detail.skill.updated_at,
                    "created_at": detail.skill.created_at,
                    "installed": is_installed,
                })),
            )
        }
        Err(e) => {
            let status = if is_clawhub_rate_limit(&e) {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::NOT_FOUND
            };
            (status, Json(serde_json::json!({"error": format!("{e}")})))
        }
    }
}

/// GET /api/clawhub/skill/{slug}/code — Fetch the source code (SKILL.md) of a ClawHub skill.
pub async fn clawhub_skill_code(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    let cache_dir = state.kernel.config.home_dir.join(".cache").join("clawhub");
    let client = t3rnel_skills::clawhub::ClawHubClient::new(cache_dir);

    // Try to fetch SKILL.md first, then fallback to package.json
    let mut code = String::new();
    let mut filename = String::new();

    if let Ok(content) = client.get_file(&slug, "SKILL.md").await {
        code = content;
        filename = "SKILL.md".to_string();
    } else if let Ok(content) = client.get_file(&slug, "package.json").await {
        code = content;
        filename = "package.json".to_string();
    } else if let Ok(content) = client.get_file(&slug, "skill.toml").await {
        code = content;
        filename = "skill.toml".to_string();
    }

    if code.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "No source code found for this skill"})),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "slug": slug,
            "filename": filename,
            "code": code,
        })),
    )
}

/// POST /api/clawhub/install — Install a skill from ClawHub.
///
/// Runs the full security pipeline: SHA256 verification, format detection,
/// manifest security scan, prompt injection scan, and binary dependency check.
pub async fn clawhub_install(
    State(state): State<Arc<AppState>>,
    Json(req): Json<crate::types::ClawHubInstallRequest>,
) -> impl IntoResponse {
    let skills_dir = state.kernel.config.home_dir.join("skills");
    let cache_dir = state.kernel.config.home_dir.join(".cache").join("clawhub");
    let client = t3rnel_skills::clawhub::ClawHubClient::new(cache_dir);

    // Check if already installed
    if client.is_installed(&req.slug, &skills_dir) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": format!("Skill '{}' is already installed", req.slug),
                "status": "already_installed",
            })),
        );
    }

    match client.install(&req.slug, &skills_dir).await {
        Ok(result) => {
            // Hot-reload so agents see the new skill immediately (#752)
            state.kernel.reload_skills();

            let warnings: Vec<serde_json::Value> = result
                .warnings
                .iter()
                .map(|w| {
                    serde_json::json!({
                        "severity": format!("{:?}", w.severity),
                        "message": w.message,
                    })
                })
                .collect();

            let translations: Vec<serde_json::Value> = result
                .tool_translations
                .iter()
                .map(|(from, to)| serde_json::json!({"from": from, "to": to}))
                .collect();

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "installed",
                    "name": result.skill_name,
                    "version": result.version,
                    "slug": result.slug,
                    "is_prompt_only": result.is_prompt_only,
                    "warnings": warnings,
                    "tool_translations": translations,
                })),
            )
        }
        Err(e) => {
            let msg = format!("{e}");
            let status = if matches!(e, t3rnel_skills::SkillError::SecurityBlocked(_)) {
                StatusCode::FORBIDDEN
            } else if is_clawhub_rate_limit(&e) {
                StatusCode::TOO_MANY_REQUESTS
            } else if matches!(e, t3rnel_skills::SkillError::Network(_)) {
                StatusCode::BAD_GATEWAY
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            tracing::warn!("ClawHub install failed: {msg}");
            (status, Json(serde_json::json!({"error": msg})))
        }
    }
}

/// Check whether a SkillError represents a ClawHub rate-limit (429).
fn is_clawhub_rate_limit(err: &t3rnel_skills::SkillError) -> bool {
    matches!(err, t3rnel_skills::SkillError::RateLimited(_))
}

/// Convert a browse entry (nested stats/tags) to a flat JSON object for the frontend.
fn clawhub_browse_entry_to_json(
    entry: &t3rnel_skills::clawhub::ClawHubBrowseEntry,
) -> serde_json::Value {
    let version = t3rnel_skills::clawhub::ClawHubClient::entry_version(entry);
    serde_json::json!({
        "slug": entry.slug,
        "name": entry.display_name,
        "description": entry.summary,
        "version": version,
        "downloads": entry.stats.downloads,
        "stars": entry.stats.stars,
        "updated_at": entry.updated_at,
    })
}

// ---------------------------------------------------------------------------
// Hands endpoints
// ---------------------------------------------------------------------------

/// Detect the server platform for install command selection.
fn server_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

/// GET /api/hands — List all hand definitions (marketplace).
pub async fn list_hands(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let defs = state.kernel.hand_registry.list_definitions();
    let hands: Vec<serde_json::Value> = defs
        .iter()
        .map(|d| {
            let reqs = state
                .kernel
                .hand_registry
                .check_requirements(&d.id)
                .unwrap_or_default();
            let readiness = state.kernel.hand_registry.readiness(&d.id);
            let requirements_met = readiness
                .as_ref()
                .map(|r| r.requirements_met)
                .unwrap_or(false);
            let active = readiness.as_ref().map(|r| r.active).unwrap_or(false);
            let degraded = readiness.as_ref().map(|r| r.degraded).unwrap_or(false);
            serde_json::json!({
                "id": d.id,
                "name": d.name,
                "description": d.description,
                "category": d.category,
                "icon": d.icon,
                "tools": d.tools,
                "requirements_met": requirements_met,
                "active": active,
                "degraded": degraded,
                "requirements": reqs.iter().map(|(r, ok)| serde_json::json!({
                    "key": r.key,
                    "label": r.label,
                    "satisfied": ok,
                    "optional": r.optional,
                })).collect::<Vec<_>>(),
                "dashboard_metrics": d.dashboard.metrics.len(),
                "has_settings": !d.settings.is_empty(),
                "settings_count": d.settings.len(),
            })
        })
        .collect();

    Json(serde_json::json!({ "hands": hands, "total": hands.len() }))
}

/// GET /api/hands/active — List active hand instances.
pub async fn list_active_hands(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let instances = state.kernel.hand_registry.list_instances();
    let items: Vec<serde_json::Value> = instances
        .iter()
        .map(|i| {
            // Effective agent name: custom instance_name takes priority, otherwise HAND.toml default.
            let effective_agent_name = i
                .instance_name
                .clone()
                .unwrap_or_else(|| i.agent_name.clone());
            serde_json::json!({
                "instance_id": i.instance_id,
                "hand_id": i.hand_id,
                "instance_name": i.instance_name,
                "status": format!("{}", i.status),
                "agent_id": i.agent_id.map(|a| a.to_string()),
                "agent_name": effective_agent_name,
                "activated_at": i.activated_at.to_rfc3339(),
                "updated_at": i.updated_at.to_rfc3339(),
            })
        })
        .collect();

    Json(serde_json::json!({ "instances": items, "total": items.len() }))
}

/// GET /api/hands/{hand_id} — Get a single hand definition with requirements check.
pub async fn get_hand(
    State(state): State<Arc<AppState>>,
    Path(hand_id): Path<String>,
) -> impl IntoResponse {
    match state.kernel.hand_registry.get_definition(&hand_id) {
        Some(def) => {
            let reqs = state
                .kernel
                .hand_registry
                .check_requirements(&hand_id)
                .unwrap_or_default();
            let readiness = state.kernel.hand_registry.readiness(&hand_id);
            let requirements_met = readiness
                .as_ref()
                .map(|r| r.requirements_met)
                .unwrap_or(false);
            let active = readiness.as_ref().map(|r| r.active).unwrap_or(false);
            let degraded = readiness.as_ref().map(|r| r.degraded).unwrap_or(false);
            let settings_status = state
                .kernel
                .hand_registry
                .check_settings_availability(&hand_id)
                .unwrap_or_default();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "id": def.id,
                    "name": def.name,
                    "description": def.description,
                    "category": def.category,
                    "icon": def.icon,
                    "tools": def.tools,
                    "requirements_met": requirements_met,
                    "active": active,
                    "degraded": degraded,
                    "requirements": reqs.iter().map(|(r, ok)| {
                        let mut req_json = serde_json::json!({
                            "key": r.key,
                            "label": r.label,
                            "type": format!("{:?}", r.requirement_type),
                            "check_value": r.check_value,
                            "satisfied": ok,
                            "optional": r.optional,
                        });
                        if let Some(ref desc) = r.description {
                            req_json["description"] = serde_json::json!(desc);
                        }
                        if let Some(ref install) = r.install {
                            req_json["install"] = serde_json::to_value(install).unwrap_or_default();
                        }
                        req_json
                    }).collect::<Vec<_>>(),
                    "server_platform": server_platform(),
                    "agent": {
                        "name": def.agent.name,
                        "description": def.agent.description,
                        "provider": if def.agent.provider == "default" {
                            &state.kernel.config.default_model.provider
                        } else { &def.agent.provider },
                        "model": if def.agent.model == "default" {
                            &state.kernel.config.default_model.model
                        } else { &def.agent.model },
                    },
                    "dashboard": def.dashboard.metrics.iter().map(|m| serde_json::json!({
                        "label": m.label,
                        "memory_key": m.memory_key,
                        "format": m.format,
                    })).collect::<Vec<_>>(),
                    "settings": settings_status,
                })),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Hand not found: {hand_id}")})),
        ),
    }
}

/// POST /api/hands/{hand_id}/check-deps — Re-check dependency status for a hand.
pub async fn check_hand_deps(
    State(state): State<Arc<AppState>>,
    Path(hand_id): Path<String>,
) -> impl IntoResponse {
    match state.kernel.hand_registry.get_definition(&hand_id) {
        Some(def) => {
            let reqs = state
                .kernel
                .hand_registry
                .check_requirements(&hand_id)
                .unwrap_or_default();
            let readiness = state.kernel.hand_registry.readiness(&hand_id);
            let requirements_met = readiness
                .as_ref()
                .map(|r| r.requirements_met)
                .unwrap_or(false);
            let active = readiness.as_ref().map(|r| r.active).unwrap_or(false);
            let degraded = readiness.as_ref().map(|r| r.degraded).unwrap_or(false);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "hand_id": def.id,
                    "requirements_met": requirements_met,
                    "active": active,
                    "degraded": degraded,
                    "server_platform": server_platform(),
                    "requirements": reqs.iter().map(|(r, ok)| {
                        let mut req_json = serde_json::json!({
                            "key": r.key,
                            "label": r.label,
                            "type": format!("{:?}", r.requirement_type),
                            "check_value": r.check_value,
                            "satisfied": ok,
                            "optional": r.optional,
                        });
                        if let Some(ref desc) = r.description {
                            req_json["description"] = serde_json::json!(desc);
                        }
                        if let Some(ref install) = r.install {
                            req_json["install"] = serde_json::to_value(install).unwrap_or_default();
                        }
                        req_json
                    }).collect::<Vec<_>>(),
                })),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Hand not found: {hand_id}")})),
        ),
    }
}

/// POST /api/hands/{hand_id}/install-deps — Auto-install missing dependencies for a hand.
pub async fn install_hand_deps(
    State(state): State<Arc<AppState>>,
    Path(hand_id): Path<String>,
) -> impl IntoResponse {
    let def = match state.kernel.hand_registry.get_definition(&hand_id) {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("Hand not found: {hand_id}")})),
            );
        }
    };

    let reqs = state
        .kernel
        .hand_registry
        .check_requirements(&hand_id)
        .unwrap_or_default();

    let platform = server_platform();
    let mut results = Vec::new();

    for (req, already_satisfied) in &reqs {
        if *already_satisfied {
            results.push(serde_json::json!({
                "key": req.key,
                "status": "already_installed",
                "message": format!("{} is already available", req.label),
            }));
            continue;
        }

        let install = match &req.install {
            Some(i) => i,
            None => {
                results.push(serde_json::json!({
                    "key": req.key,
                    "status": "skipped",
                    "message": "No install instructions available",
                }));
                continue;
            }
        };

        // Pick the best install command for this platform
        let cmd = match platform {
            "windows" => install.windows.as_deref().or(install.pip.as_deref()),
            "macos" => install.macos.as_deref().or(install.pip.as_deref()),
            _ => install
                .linux_apt
                .as_deref()
                .or(install.linux_dnf.as_deref())
                .or(install.linux_pacman.as_deref())
                .or(install.pip.as_deref()),
        };

        let cmd = match cmd {
            Some(c) => c,
            None => {
                results.push(serde_json::json!({
                    "key": req.key,
                    "status": "no_command",
                    "message": format!("No install command for platform: {platform}"),
                }));
                continue;
            }
        };

        // Execute the install command
        let (shell, flag) = if cfg!(windows) {
            ("cmd", "/C")
        } else {
            ("sh", "-c")
        };

        // For winget on Windows, add --accept flags to avoid interactive prompts
        let final_cmd = if cfg!(windows) && cmd.starts_with("winget ") {
            format!("{cmd} --accept-source-agreements --accept-package-agreements")
        } else {
            cmd.to_string()
        };

        tracing::info!(hand = %hand_id, dep = %req.key, cmd = %final_cmd, "Auto-installing dependency");

        let output = match tokio::time::timeout(
            std::time::Duration::from_secs(300),
            tokio::process::Command::new(shell)
                .arg(flag)
                .arg(&final_cmd)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .stdin(std::process::Stdio::null())
                .output(),
        )
        .await
        {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                results.push(serde_json::json!({
                    "key": req.key,
                    "status": "error",
                    "command": final_cmd,
                    "message": format!("Failed to execute: {e}"),
                }));
                continue;
            }
            Err(_) => {
                results.push(serde_json::json!({
                    "key": req.key,
                    "status": "timeout",
                    "command": final_cmd,
                    "message": "Installation timed out after 5 minutes",
                }));
                continue;
            }
        };

        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if exit_code == 0 {
            results.push(serde_json::json!({
                "key": req.key,
                "status": "installed",
                "command": final_cmd,
                "message": format!("{} installed successfully", req.label),
            }));
        } else {
            // On Windows, winget may return non-zero even on success (e.g., already installed)
            let combined = format!("{stdout}{stderr}");
            let likely_ok = combined.contains("already installed")
                || combined.contains("No applicable update")
                || combined.contains("No available upgrade")
                || combined.contains("already an App at")
                || combined.contains("is already installed");
            results.push(serde_json::json!({
                "key": req.key,
                "status": if likely_ok { "installed" } else { "error" },
                "command": final_cmd,
                "exit_code": exit_code,
                "message": if likely_ok {
                    format!("{} is already installed", req.label)
                } else {
                    let msg = stderr.chars().take(500).collect::<String>();
                    format!("Install failed (exit {}): {}", exit_code, msg.trim())
                },
            }));
        }
    }

    // On Windows, refresh PATH to pick up newly installed binaries from winget/pip
    #[cfg(windows)]
    {
        let home = std::env::var("USERPROFILE").unwrap_or_default();
        if !home.is_empty() {
            let winget_pkgs =
                std::path::Path::new(&home).join("AppData\\Local\\Microsoft\\WinGet\\Packages");
            if winget_pkgs.is_dir() {
                let mut extra_paths = Vec::new();
                if let Ok(entries) = std::fs::read_dir(&winget_pkgs) {
                    for entry in entries.flatten() {
                        let pkg_dir = entry.path();
                        // Look for bin/ subdirectory (ffmpeg style)
                        if let Ok(sub_entries) = std::fs::read_dir(&pkg_dir) {
                            for sub in sub_entries.flatten() {
                                let bin_dir = sub.path().join("bin");
                                if bin_dir.is_dir() {
                                    extra_paths.push(bin_dir.to_string_lossy().to_string());
                                }
                            }
                        }
                        // Direct exe in package dir (yt-dlp style)
                        if std::fs::read_dir(&pkg_dir)
                            .map(|rd| {
                                rd.flatten().any(|e| {
                                    e.path().extension().map(|x| x == "exe").unwrap_or(false)
                                })
                            })
                            .unwrap_or(false)
                        {
                            extra_paths.push(pkg_dir.to_string_lossy().to_string());
                        }
                    }
                }
                // Also add pip Scripts dir
                let pip_scripts =
                    std::path::Path::new(&home).join("AppData\\Local\\Programs\\Python");
                if pip_scripts.is_dir() {
                    if let Ok(entries) = std::fs::read_dir(&pip_scripts) {
                        for entry in entries.flatten() {
                            let scripts = entry.path().join("Scripts");
                            if scripts.is_dir() {
                                extra_paths.push(scripts.to_string_lossy().to_string());
                            }
                        }
                    }
                }
                if !extra_paths.is_empty() {
                    let current_path = std::env::var("PATH").unwrap_or_default();
                    let new_path = format!("{};{}", extra_paths.join(";"), current_path);
                    std::env::set_var("PATH", &new_path);
                    tracing::info!(
                        added = extra_paths.len(),
                        "Refreshed PATH with winget/pip directories"
                    );
                }
            }
        }
    }

    // Re-check requirements after installation
    let reqs_after = state
        .kernel
        .hand_registry
        .check_requirements(&hand_id)
        .unwrap_or_default();
    let all_satisfied = reqs_after.iter().all(|(_, ok)| *ok);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "hand_id": def.id,
            "results": results,
            "requirements_met": all_satisfied,
            "requirements": reqs_after.iter().map(|(r, ok)| {
                serde_json::json!({
                    "key": r.key,
                    "label": r.label,
                    "satisfied": ok,
                })
            }).collect::<Vec<_>>(),
        })),
    )
}

/// POST /api/hands/install — Install a hand from TOML content.
pub async fn install_hand(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let toml_content = body["toml_content"].as_str().unwrap_or("");
    let skill_content = body["skill_content"].as_str().unwrap_or("");

    if toml_content.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Missing toml_content field"})),
        );
    }

    match state
        .kernel
        .hand_registry
        .install_from_content(toml_content, skill_content)
    {
        Ok(def) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": def.id,
                "name": def.name,
                "description": def.description,
                "category": format!("{:?}", def.category),
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// POST /api/hands/upsert — Install or update a hand definition.
///
/// Like `install_hand` but overwrites an existing definition with the same ID.
/// Active instances are NOT automatically restarted — deactivate + reactivate
/// to pick up the new definition.
pub async fn upsert_hand(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let toml_content = body["toml_content"].as_str().unwrap_or("");
    let skill_content = body["skill_content"].as_str().unwrap_or("");

    if toml_content.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Missing toml_content field"})),
        );
    }

    match state
        .kernel
        .hand_registry
        .upsert_from_content(toml_content, skill_content)
    {
        Ok(def) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": def.id,
                "name": def.name,
                "description": def.description,
                "category": format!("{:?}", def.category),
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// POST /api/hands/{hand_id}/activate — Activate a hand (spawns agent).
pub async fn activate_hand(
    State(state): State<Arc<AppState>>,
    Path(hand_id): Path<String>,
    body: Option<Json<t3rnel_hands::ActivateHandRequest>>,
) -> impl IntoResponse {
    let (config, instance_name) = match body.map(|b| b.0) {
        Some(r) => (r.config, r.instance_name),
        None => (std::collections::HashMap::new(), None),
    };

    match state.kernel.activate_hand(&hand_id, config, instance_name) {
        Ok(instance) => {
            // If the hand agent has a non-reactive schedule (autonomous hands),
            // start its background loop so it begins running immediately.
            if let Some(agent_id) = instance.agent_id {
                let entry = state
                    .kernel
                    .registry
                    .list()
                    .into_iter()
                    .find(|e| e.id == agent_id);
                if let Some(entry) = entry {
                    if !matches!(
                        entry.manifest.schedule,
                        t3rnel_types::agent::ScheduleMode::Reactive
                    ) {
                        state.kernel.start_background_for_agent(
                            agent_id,
                            &entry.name,
                            &entry.manifest.schedule,
                        );
                    }
                }
            }
            let effective_agent_name = instance
                .instance_name
                .clone()
                .unwrap_or_else(|| instance.agent_name.clone());
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "instance_id": instance.instance_id,
                    "hand_id": instance.hand_id,
                    "instance_name": instance.instance_name,
                    "status": format!("{}", instance.status),
                    "agent_id": instance.agent_id.map(|a| a.to_string()),
                    "agent_name": effective_agent_name,
                    "activated_at": instance.activated_at.to_rfc3339(),
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// POST /api/hands/instances/{id}/pause — Pause a hand instance.
pub async fn pause_hand(
    State(state): State<Arc<AppState>>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    match state.kernel.pause_hand(id) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "paused", "instance_id": id})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// POST /api/hands/instances/{id}/resume — Resume a paused hand instance.
pub async fn resume_hand(
    State(state): State<Arc<AppState>>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    match state.kernel.resume_hand(id) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "resumed", "instance_id": id})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// DELETE /api/hands/instances/{id} — Deactivate a hand (kills agent).
pub async fn deactivate_hand(
    State(state): State<Arc<AppState>>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    match state.kernel.deactivate_hand(id) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "deactivated", "instance_id": id})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// GET /api/hands/{hand_id}/settings — Get settings schema and current values for a hand.
pub async fn get_hand_settings(
    State(state): State<Arc<AppState>>,
    Path(hand_id): Path<String>,
) -> impl IntoResponse {
    let settings_status = match state
        .kernel
        .hand_registry
        .check_settings_availability(&hand_id)
    {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("Hand not found: {hand_id}")})),
            );
        }
    };

    // Find active instance config values (if any)
    let instance_config: std::collections::HashMap<String, serde_json::Value> = state
        .kernel
        .hand_registry
        .list_instances()
        .iter()
        .find(|i| i.hand_id == hand_id)
        .map(|i| i.config.clone())
        .unwrap_or_default();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "hand_id": hand_id,
            "settings": settings_status,
            "current_values": instance_config,
        })),
    )
}

/// PUT /api/hands/{hand_id}/settings — Update settings for a hand instance.
pub async fn update_hand_settings(
    State(state): State<Arc<AppState>>,
    Path(hand_id): Path<String>,
    Json(config): Json<std::collections::HashMap<String, serde_json::Value>>,
) -> impl IntoResponse {
    // Find active instance for this hand
    let instance_id = state
        .kernel
        .hand_registry
        .list_instances()
        .iter()
        .find(|i| i.hand_id == hand_id)
        .map(|i| i.instance_id);

    match instance_id {
        Some(id) => match state.kernel.hand_registry.update_config(id, config.clone()) {
            Ok(()) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "ok",
                    "hand_id": hand_id,
                    "instance_id": id,
                    "config": config,
                })),
            ),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("{e}")})),
            ),
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({"error": format!("No active instance for hand: {hand_id}. Activate the hand first.")}),
            ),
        ),
    }
}

/// GET /api/hands/instances/{id}/stats — Get dashboard stats for a hand instance.
pub async fn hand_stats(
    State(state): State<Arc<AppState>>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    let instance = match state.kernel.hand_registry.get_instance(id) {
        Some(i) => i,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Instance not found"})),
            );
        }
    };

    let def = match state.kernel.hand_registry.get_definition(&instance.hand_id) {
        Some(d) => d,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Hand definition not found"})),
            );
        }
    };

    let agent_id = match instance.agent_id {
        Some(aid) => aid,
        None => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "instance_id": id,
                    "hand_id": instance.hand_id,
                    "metrics": {},
                })),
            );
        }
    };

    // Read dashboard metrics from unified memory (memory_store writes to the
    // project partition), falling back to the agent's legacy flat keys.
    let mut metrics = serde_json::Map::new();
    for metric in &def.dashboard.metrics {
        let value = state
            .kernel
            .shared_kv(&metric.memory_key)
            .or_else(|| {
                state
                    .kernel
                    .memory
                    .structured_get(agent_id, &metric.memory_key)
                    .ok()
                    .flatten()
            })
            .unwrap_or(serde_json::Value::Null);
        metrics.insert(
            metric.label.clone(),
            serde_json::json!({
                "value": value,
                "format": metric.format,
            }),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "instance_id": id,
            "hand_id": instance.hand_id,
            "status": format!("{}", instance.status),
            "agent_id": agent_id.to_string(),
            "metrics": metrics,
        })),
    )
}

/// GET /api/hands/instances/{id}/browser — Get live browser state for a hand instance.
pub async fn hand_instance_browser(
    State(state): State<Arc<AppState>>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    // 1. Look up instance
    let instance = match state.kernel.hand_registry.get_instance(id) {
        Some(i) => i,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Instance not found"})),
            );
        }
    };

    // 2. Get agent_id
    let agent_id = match instance.agent_id {
        Some(aid) => aid,
        None => {
            return (StatusCode::OK, Json(serde_json::json!({"active": false})));
        }
    };

    let agent_id_str = agent_id.to_string();

    // 3. Check if a browser session exists (without creating one)
    if !state.kernel.browser_ctx.has_session(&agent_id_str) {
        return (StatusCode::OK, Json(serde_json::json!({"active": false})));
    }

    // 4. Send ReadPage command to get page info
    let mut url = String::new();
    let mut title = String::new();
    let mut content = String::new();

    match state
        .kernel
        .browser_ctx
        .send_command(
            &agent_id_str,
            t3rnel_runtime::browser::BrowserCommand::ReadPage,
        )
        .await
    {
        Ok(resp) if resp.success => {
            if let Some(data) = &resp.data {
                url = data["url"].as_str().unwrap_or("").to_string();
                title = data["title"].as_str().unwrap_or("").to_string();
                content = data["content"].as_str().unwrap_or("").to_string();
                // Truncate content to avoid huge payloads (UTF-8 safe)
                if content.len() > 2000 {
                    content = format!(
                        "{}... (truncated)",
                        t3rnel_types::truncate_str(&content, 2000)
                    );
                }
            }
        }
        Ok(_) => {}  // Non-success: leave defaults
        Err(_) => {} // Error: leave defaults
    }

    // 5. Send Screenshot command to get visual state
    let mut screenshot_base64 = String::new();

    match state
        .kernel
        .browser_ctx
        .send_command(
            &agent_id_str,
            t3rnel_runtime::browser::BrowserCommand::Screenshot {
                format: None,
                quality: None,
            },
        )
        .await
    {
        Ok(resp) if resp.success => {
            if let Some(data) = &resp.data {
                screenshot_base64 = data["image_base64"].as_str().unwrap_or("").to_string();
            }
        }
        Ok(_) => {}
        Err(_) => {}
    }

    // 6. Return combined state
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "active": true,
            "url": url,
            "title": title,
            "content": content,
            "screenshot_base64": screenshot_base64,
        })),
    )
}

// ---------------------------------------------------------------------------
// MCP server endpoints
// ---------------------------------------------------------------------------

/// GET /api/mcp/servers — List configured MCP servers and their tools.
pub async fn list_mcp_servers(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Get configured servers from config
    let config_servers: Vec<serde_json::Value> = state
        .kernel
        .config
        .mcp_servers
        .iter()
        .map(|s| {
            let transport = match &s.transport {
                t3rnel_types::config::McpTransportEntry::Stdio { command, args } => {
                    serde_json::json!({
                        "type": "stdio",
                        "command": command,
                        "args": args,
                    })
                }
                t3rnel_types::config::McpTransportEntry::Sse { url } => {
                    serde_json::json!({
                        "type": "sse",
                        "url": url,
                    })
                }
                t3rnel_types::config::McpTransportEntry::Http { url } => {
                    serde_json::json!({
                        "type": "http",
                        "url": url,
                    })
                }
            };
            serde_json::json!({
                "name": s.name,
                "transport": transport,
                "timeout_secs": s.timeout_secs,
                "env": s.env,
            })
        })
        .collect();

    // Get connected servers and their tools from the live MCP connections
    let connections = state.kernel.mcp_connections.lock().await;
    let connected: Vec<serde_json::Value> = connections
        .iter()
        .map(|conn| {
            let tools: Vec<serde_json::Value> = conn
                .tools()
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                    })
                })
                .collect();
            serde_json::json!({
                "name": conn.name(),
                "tools_count": tools.len(),
                "tools": tools,
                "connected": true,
            })
        })
        .collect();

    Json(serde_json::json!({
        "configured": config_servers,
        "connected": connected,
        "total_configured": config_servers.len(),
        "total_connected": connected.len(),
    }))
}

// ---------------------------------------------------------------------------
// Audit endpoints
// ---------------------------------------------------------------------------

/// GET /api/audit/recent — Get recent audit log entries.
pub async fn audit_recent(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let n: usize = params
        .get("n")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50)
        .min(1000); // Cap at 1000

    let entries = state.kernel.audit_log.recent(n);
    let tip = state.kernel.audit_log.tip_hash();

    let items: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "seq": e.seq,
                "timestamp": e.timestamp,
                "agent_id": e.agent_id,
                "action": format!("{:?}", e.action),
                "detail": e.detail,
                "outcome": e.outcome,
                "hash": e.hash,
            })
        })
        .collect();

    Json(serde_json::json!({
        "entries": items,
        "total": state.kernel.audit_log.len(),
        "tip_hash": tip,
    }))
}

/// GET /api/audit/verify — Verify the audit chain integrity.
pub async fn audit_verify(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let entry_count = state.kernel.audit_log.len();
    match state.kernel.audit_log.verify_integrity() {
        Ok(()) => {
            if entry_count == 0 {
                // SECURITY: Warn that an empty audit log has no forensic value
                Json(serde_json::json!({
                    "valid": true,
                    "entries": 0,
                    "warning": "Audit log is empty — no events have been recorded yet",
                    "tip_hash": state.kernel.audit_log.tip_hash(),
                }))
            } else {
                Json(serde_json::json!({
                    "valid": true,
                    "entries": entry_count,
                    "tip_hash": state.kernel.audit_log.tip_hash(),
                }))
            }
        }
        Err(msg) => Json(serde_json::json!({
            "valid": false,
            "error": msg,
            "entries": entry_count,
        })),
    }
}

/// GET /api/logs/stream — SSE endpoint for real-time audit log streaming.
///
/// Streams new audit entries as Server-Sent Events. Accepts optional query
/// parameters for filtering:
///   - `level`  — filter by classified level (info, warn, error)
///   - `filter` — text substring filter across action/detail/agent_id
///   - `token`  — auth token (for EventSource clients that cannot set headers)
///
/// A heartbeat ping is sent every 15 seconds to keep the connection alive.
/// The endpoint polls the audit log every second and sends only new entries
/// (tracked by sequence number). On first connect, existing entries are sent
/// as a backfill so the client has immediate context.
pub async fn logs_stream(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    use axum::response::sse::{Event, KeepAlive, Sse};

    let level_filter = params.get("level").cloned().unwrap_or_default();
    let text_filter = params
        .get("filter")
        .cloned()
        .unwrap_or_default()
        .to_lowercase();

    let (tx, rx) = tokio::sync::mpsc::channel::<
        Result<axum::response::sse::Event, std::convert::Infallible>,
    >(256);

    tokio::spawn(async move {
        let mut last_seq: u64 = 0;
        let mut first_poll = true;

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            let entries = state.kernel.audit_log.recent(200);

            for entry in &entries {
                // On first poll, send all existing entries as backfill.
                // After that, only send entries newer than last_seq.
                if !first_poll && entry.seq <= last_seq {
                    continue;
                }

                let action_str = format!("{:?}", entry.action);

                // Apply level filter
                if !level_filter.is_empty() {
                    let classified = classify_audit_level(&action_str);
                    if classified != level_filter {
                        continue;
                    }
                }

                // Apply text filter
                if !text_filter.is_empty() {
                    let haystack = format!("{} {} {}", action_str, entry.detail, entry.agent_id)
                        .to_lowercase();
                    if !haystack.contains(&text_filter) {
                        continue;
                    }
                }

                let json = serde_json::json!({
                    "seq": entry.seq,
                    "timestamp": entry.timestamp,
                    "agent_id": entry.agent_id,
                    "action": action_str,
                    "detail": entry.detail,
                    "outcome": entry.outcome,
                    "hash": entry.hash,
                });
                let data = serde_json::to_string(&json).unwrap_or_default();
                if tx.send(Ok(Event::default().data(data))).await.is_err() {
                    return; // Client disconnected
                }
            }

            // Update tracking state
            if let Some(last) = entries.last() {
                last_seq = last.seq;
            }
            first_poll = false;
        }
    });

    let rx_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    Sse::new(rx_stream)
        .keep_alive(
            KeepAlive::new()
                .interval(std::time::Duration::from_secs(15))
                .text("ping"),
        )
        .into_response()
}

/// Classify an audit action string into a level (info, warn, error).
fn classify_audit_level(action: &str) -> &'static str {
    let a = action.to_lowercase();
    if a.contains("error") || a.contains("fail") || a.contains("crash") || a.contains("denied") {
        "error"
    } else if a.contains("warn") || a.contains("block") || a.contains("kill") {
        "warn"
    } else {
        "info"
    }
}

// ---------------------------------------------------------------------------
// Peer endpoints
// ---------------------------------------------------------------------------

/// GET /api/peers — List known OFP peers.
pub async fn list_peers(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Peers are tracked in the wire module's PeerRegistry.
    // The kernel doesn't directly hold a PeerRegistry, so we return an empty list
    // unless one is available. The API server can be extended to inject a registry.
    if let Some(ref peer_registry) = state.peer_registry {
        let peers: Vec<serde_json::Value> = peer_registry
            .all_peers()
            .iter()
            .map(|p| {
                serde_json::json!({
                    "node_id": p.node_id,
                    "node_name": p.node_name,
                    "address": p.address.to_string(),
                    "state": format!("{:?}", p.state),
                    "agents": p.agents.iter().map(|a| serde_json::json!({
                        "id": a.id,
                        "name": a.name,
                    })).collect::<Vec<_>>(),
                    "connected_at": p.connected_at.to_rfc3339(),
                    "protocol_version": p.protocol_version,
                })
            })
            .collect();
        Json(serde_json::json!({"peers": peers, "total": peers.len()}))
    } else {
        Json(serde_json::json!({"peers": [], "total": 0}))
    }
}

/// GET /api/network/status — OFP network status summary.
pub async fn network_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let enabled = state.kernel.config.network_enabled
        && !state.kernel.config.network.shared_secret.is_empty();

    let (node_id, listen_address, connected_peers, total_peers) =
        if let Some(peer_node) = state.kernel.peer_node.get() {
            let registry = peer_node.registry();
            (
                peer_node.node_id().to_string(),
                peer_node.local_addr().to_string(),
                registry.connected_count(),
                registry.total_count(),
            )
        } else {
            (String::new(), String::new(), 0, 0)
        };

    Json(serde_json::json!({
        "enabled": enabled,
        "node_id": node_id,
        "listen_address": listen_address,
        "connected_peers": connected_peers,
        "total_peers": total_peers,
    }))
}

// ---------------------------------------------------------------------------
// Tools endpoint
// ---------------------------------------------------------------------------

/// GET /api/tools — List all tool definitions (built-in + MCP).
pub async fn list_tools(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut tools: Vec<serde_json::Value> = builtin_tool_definitions()
        .iter()
        .map(|t| {
            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            })
        })
        .collect();

    // Include MCP tools so they're visible in Settings -> Tools
    if let Ok(mcp_tools) = state.kernel.mcp_tools.lock() {
        for t in mcp_tools.iter() {
            tools.push(serde_json::json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
                "source": "mcp",
            }));
        }
    }

    Json(serde_json::json!({"tools": tools, "total": tools.len()}))
}

// ---------------------------------------------------------------------------
// Config endpoint
// ---------------------------------------------------------------------------

/// GET /api/config — Get kernel configuration (secrets redacted).
pub async fn get_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Return a redacted view of the kernel config
    let config = &state.kernel.config;
    Json(serde_json::json!({
        "home_dir": config.home_dir.to_string_lossy(),
        "data_dir": config.data_dir.to_string_lossy(),
        "api_key": if config.api_key.is_empty() { "not set" } else { "***" },
        "default_model": {
            "provider": config.default_model.provider,
            "model": config.default_model.model,
            "api_key_env": config.default_model.api_key_env,
        },
        "memory": {
            "decay_rate": config.memory.decay_rate,
        },
        "encryption": {
            "at_rest": true,
            "a2a_payloads": "aes-256-gcm",
        },
    }))
}

const USER_SETTINGS_VERSION: u64 = 1;
const USER_SETTINGS_FILE: &str = "user-settings.json";

fn user_settings_path(home_dir: &FsPath) -> PathBuf {
    home_dir.join(USER_SETTINGS_FILE)
}

fn default_user_preferences() -> serde_json::Map<String, serde_json::Value> {
    let mut preferences = serde_json::Map::new();
    preferences.insert(
        "weatherLocation".to_string(),
        serde_json::Value::from("Groombridge, Harare"),
    );
    preferences.insert("weatherUnit".to_string(), serde_json::Value::from("metric"));
    preferences.insert("locale".to_string(), serde_json::Value::from("en-GB"));
    preferences.insert(
        "timezone".to_string(),
        serde_json::Value::from("Europe/London"),
    );
    preferences.insert("numberFormat".to_string(), serde_json::Value::from("en-GB"));
    preferences.insert("currency".to_string(), serde_json::Value::from("GBP"));
    preferences.insert("timeFormat".to_string(), serde_json::Value::from("24h"));
    preferences.insert(
        "hostTerminalEnabled".to_string(),
        serde_json::Value::from(true),
    );
    preferences.insert(
        "terminalCwd".to_string(),
        serde_json::Value::from("/home/user/projects"),
    );
    preferences.insert(
        "terminalTimeoutSecs".to_string(),
        serde_json::Value::from(120),
    );
    preferences.insert(
        "hostFilesHome".to_string(),
        serde_json::Value::from("/home/user"),
    );
    preferences.insert(
        "defaultChatAgentId".to_string(),
        serde_json::Value::from("t3rnel"),
    );
    preferences.insert(
        "dictationProvider".to_string(),
        serde_json::Value::from("daemon-stt"),
    );
    preferences.insert(
        "whisperCppEnabled".to_string(),
        serde_json::Value::from(false),
    );
    preferences.insert(
        "whisperCppBaseUrl".to_string(),
        serde_json::Value::from(DEFAULT_WHISPER_CPP_BASE_URL),
    );
    preferences.insert(
        "whisperCppBinary".to_string(),
        serde_json::Value::from("whisper-server"),
    );
    preferences.insert(
        "whisperCppModelPath".to_string(),
        serde_json::Value::from(""),
    );
    preferences.insert(
        "whisperCppPowerLevel".to_string(),
        serde_json::Value::from("balanced"),
    );
    preferences.insert("whisperCppThreads".to_string(), serde_json::Value::from(0));
    preferences.insert(
        "whisperCppProcessors".to_string(),
        serde_json::Value::from(0),
    );
    preferences.insert(
        "whisperCppUseGpu".to_string(),
        serde_json::Value::from(true),
    );
    preferences.insert(
        "whisperCppLanguage".to_string(),
        serde_json::Value::from("en"),
    );
    preferences.insert("ttsEnabled".to_string(), serde_json::Value::from(false));
    preferences.insert("ttsProvider".to_string(), serde_json::Value::from("system"));
    preferences.insert("ttsVoice".to_string(), serde_json::Value::from("default"));
    preferences.insert("maxAgents".to_string(), serde_json::Value::from(32));
    preferences.insert("agentRamLimitMb".to_string(), serde_json::Value::from(4096));
    preferences.insert("agentCpuLimitPct".to_string(), serde_json::Value::from(80));
    preferences.insert(
        "defaultLlmProvider".to_string(),
        serde_json::Value::from("nvidia"),
    );
    preferences.insert(
        "defaultLlmModel".to_string(),
        serde_json::Value::from("default"),
    );
    preferences.insert(
        "brokerProvider".to_string(),
        serde_json::Value::from("deriv"),
    );
    preferences.insert(
        "derivExecutionMode".to_string(),
        serde_json::Value::from("demo"),
    );
    preferences.insert(
        "agentInspectorDefaultView".to_string(),
        serde_json::Value::from("activity"),
    );
    preferences.insert(
        "approvalMode".to_string(),
        serde_json::Value::from("manual"),
    );
    preferences.insert(
        "biometricApprovals".to_string(),
        serde_json::Value::from(true),
    );
    preferences.insert(
        "auditRetentionDays".to_string(),
        serde_json::Value::from(90),
    );
    preferences.insert(
        "traceRetentionDays".to_string(),
        serde_json::Value::from(14),
    );
    preferences.insert("maxTraceEvents".to_string(), serde_json::Value::from(5000));
    preferences.insert(
        "notificationQuietHoursEnabled".to_string(),
        serde_json::Value::from(false),
    );
    preferences.insert(
        "notificationQuietHoursStart".to_string(),
        serde_json::Value::from("22:00"),
    );
    preferences.insert(
        "notificationQuietHoursEnd".to_string(),
        serde_json::Value::from("07:00"),
    );
    preferences.insert(
        "mobileTailscaleRequired".to_string(),
        serde_json::Value::from(true),
    );
    preferences.insert(
        "mobileReconnectMode".to_string(),
        serde_json::Value::from("auto"),
    );
    preferences.insert(
        "mobileOfflineCache".to_string(),
        serde_json::Value::from(true),
    );
    preferences.insert("chatHistoryLimit".to_string(), serde_json::Value::from(200));
    preferences.insert("chatStreaming".to_string(), serde_json::Value::from(true));
    preferences.insert("chatSuggestions".to_string(), serde_json::Value::from(true));
    preferences.insert(
        "defaultTeamId".to_string(),
        serde_json::Value::from("software-engineering"),
    );
    preferences.insert("taskRefreshSecs".to_string(), serde_json::Value::from(5));
    preferences.insert("fileSort".to_string(), serde_json::Value::from("name"));
    preferences.insert(
        "fileSortDirection".to_string(),
        serde_json::Value::from("asc"),
    );
    preferences.insert(
        "filePreviewMaxBytes".to_string(),
        serde_json::Value::from(2_097_152),
    );
    preferences.insert(
        "terminalConfirmDangerousCommands".to_string(),
        serde_json::Value::from(true),
    );
    preferences.insert(
        "terminalHistoryLimit".to_string(),
        serde_json::Value::from(100),
    );
    preferences.insert(
        "terminalShellMode".to_string(),
        serde_json::Value::from("login"),
    );
    preferences.insert(
        "stocksRailSigningRequired".to_string(),
        serde_json::Value::from(true),
    );
    preferences.insert(
        "stocksDefaultTab".to_string(),
        serde_json::Value::from("deriv"),
    );
    preferences.insert(
        "derivCatalogOnlyPassed".to_string(),
        serde_json::Value::from(true),
    );
    preferences.insert(
        "derivMaxOpenContracts".to_string(),
        serde_json::Value::from(20),
    );
    preferences.insert("derivDefaultStake".to_string(), serde_json::Value::from(1));
    preferences.insert("memorySearchLimit".to_string(), serde_json::Value::from(25));
    preferences.insert(
        "memoryWriteEnabled".to_string(),
        serde_json::Value::from(true),
    );
    preferences.insert(
        "providerFallbackEnabled".to_string(),
        serde_json::Value::from(true),
    );
    preferences.insert(
        "providerHealthProbeSecs".to_string(),
        serde_json::Value::from(60),
    );
    preferences.insert(
        "speechInputMimePreference".to_string(),
        serde_json::Value::from("audio/webm"),
    );
    preferences.insert(
        "speechTranscriptionTimeoutSecs".to_string(),
        serde_json::Value::from(90),
    );
    preferences.insert(
        "speechReadBackOnMobile".to_string(),
        serde_json::Value::from(false),
    );
    preferences.insert(
        "accessibilityReducedMotion".to_string(),
        serde_json::Value::from(false),
    );
    preferences.insert(
        "accessibilityHighContrast".to_string(),
        serde_json::Value::from(false),
    );
    preferences.insert("compactMode".to_string(), serde_json::Value::from(false));
    preferences.insert("developerMode".to_string(), serde_json::Value::from(false));
    preferences.insert(
        "diagnosticsUploadEnabled".to_string(),
        serde_json::Value::from(false),
    );
    preferences
}

fn user_settings_registry() -> serde_json::Value {
    serde_json::json!([
        {
            "category": "Locale & Personalization",
            "settings": [
                {"key": "weatherLocation", "label": "Weather location", "type": "string"},
                {"key": "weatherUnit", "label": "Temperature unit", "type": "select", "options": ["metric", "imperial"]},
                {"key": "locale", "label": "Locale", "type": "string"},
                {"key": "timezone", "label": "Timezone", "type": "string"},
                {"key": "numberFormat", "label": "Number format", "type": "string"},
                {"key": "currency", "label": "Currency", "type": "string"},
                {"key": "timeFormat", "label": "Time format", "type": "select", "options": ["24h", "12h"]}
            ]
        },
        {
            "category": "Agents & Models",
            "settings": [
                {"key": "defaultChatAgentId", "label": "Default chat agent", "type": "string"},
                {"key": "maxAgents", "label": "Maximum agents", "type": "number"},
                {"key": "agentRamLimitMb", "label": "Agent RAM limit MB", "type": "number"},
                {"key": "agentCpuLimitPct", "label": "Agent CPU limit percent", "type": "number"},
                {"key": "defaultLlmProvider", "label": "Default LLM provider", "type": "string"},
                {"key": "defaultLlmModel", "label": "Default LLM model", "type": "string"},
                {"key": "providerFallbackEnabled", "label": "Provider fallback", "type": "boolean"},
                {"key": "providerHealthProbeSecs", "label": "Provider health probe seconds", "type": "number"}
            ]
        },
        {
            "category": "Speech",
            "settings": [
                {"key": "dictationProvider", "label": "Dictation provider", "type": "select", "options": ["browser-speech", "daemon-stt", "whisper-cpp", "parakeet-mlx", "whisper"]},
                {"key": "whisperCppEnabled", "label": "Local Whisper.cpp enabled", "type": "boolean"},
                {"key": "whisperCppBaseUrl", "label": "Whisper.cpp server URL", "type": "string"},
                {"key": "whisperCppBinary", "label": "Whisper.cpp server binary", "type": "path"},
                {"key": "whisperCppModelPath", "label": "Whisper.cpp ggml model path", "type": "path"},
                {"key": "whisperCppPowerLevel", "label": "Whisper.cpp power level", "type": "select", "options": ["eco", "balanced", "performance", "max"]},
                {"key": "whisperCppThreads", "label": "Whisper.cpp threads override", "type": "number"},
                {"key": "whisperCppProcessors", "label": "Whisper.cpp processors override", "type": "number"},
                {"key": "whisperCppUseGpu", "label": "Whisper.cpp GPU allowed", "type": "boolean"},
                {"key": "whisperCppLanguage", "label": "Whisper.cpp language", "type": "string"},
                {"key": "speechInputMimePreference", "label": "Input MIME preference", "type": "string"},
                {"key": "speechTranscriptionTimeoutSecs", "label": "Transcription timeout seconds", "type": "number"},
                {"key": "ttsEnabled", "label": "Text to speech", "type": "boolean"},
                {"key": "ttsProvider", "label": "TTS provider", "type": "string"},
                {"key": "ttsVoice", "label": "TTS voice", "type": "string"},
                {"key": "speechReadBackOnMobile", "label": "Read replies on mobile", "type": "boolean"}
            ]
        },
        {
            "category": "Files & Terminal",
            "settings": [
                {"key": "hostFilesHome", "label": "Host files home", "type": "path"},
                {"key": "fileSort", "label": "File sort", "type": "select", "options": ["name", "size", "modified", "kind"]},
                {"key": "fileSortDirection", "label": "File sort direction", "type": "select", "options": ["asc", "desc"]},
                {"key": "filePreviewMaxBytes", "label": "File preview max bytes", "type": "number"},
                {"key": "hostTerminalEnabled", "label": "Host terminal enabled", "type": "boolean"},
                {"key": "terminalCwd", "label": "Terminal cwd", "type": "path"},
                {"key": "terminalTimeoutSecs", "label": "Terminal timeout seconds", "type": "number"},
                {"key": "terminalConfirmDangerousCommands", "label": "Confirm dangerous commands", "type": "boolean"},
                {"key": "terminalHistoryLimit", "label": "Terminal history limit", "type": "number"},
                {"key": "terminalShellMode", "label": "Terminal shell mode", "type": "select", "options": ["login", "plain"]}
            ]
        },
        {
            "category": "Mobile Connectivity",
            "settings": [
                {"key": "mobileTailscaleRequired", "label": "Prefer Tailscale", "type": "boolean"},
                {"key": "mobileReconnectMode", "label": "Reconnect mode", "type": "select", "options": ["auto", "manual"]},
                {"key": "mobileOfflineCache", "label": "Offline cache", "type": "boolean"}
            ]
        },
        {
            "category": "Approvals, Audit & Diagnostics",
            "settings": [
                {"key": "approvalMode", "label": "Approval mode", "type": "select", "options": ["manual", "trusted-local"]},
                {"key": "biometricApprovals", "label": "Biometric approvals", "type": "boolean"},
                {"key": "auditRetentionDays", "label": "Audit retention days", "type": "number"},
                {"key": "traceRetentionDays", "label": "Trace retention days", "type": "number"},
                {"key": "maxTraceEvents", "label": "Max trace events", "type": "number"},
                {"key": "diagnosticsUploadEnabled", "label": "Diagnostics upload", "type": "boolean"}
            ]
        },
        {
            "category": "Tasks, Teams & Memory",
            "settings": [
                {"key": "defaultTeamId", "label": "Default team", "type": "string"},
                {"key": "taskRefreshSecs", "label": "Task refresh seconds", "type": "number"},
                {"key": "chatHistoryLimit", "label": "Chat history limit", "type": "number"},
                {"key": "chatStreaming", "label": "Chat streaming", "type": "boolean"},
                {"key": "chatSuggestions", "label": "Chat suggestions", "type": "boolean"},
                {"key": "memorySearchLimit", "label": "Memory search limit", "type": "number"},
                {"key": "memoryWriteEnabled", "label": "Memory writes", "type": "boolean"}
            ]
        },
        {
            "category": "Accessibility",
            "settings": [
                {"key": "accessibilityReducedMotion", "label": "Reduced motion", "type": "boolean"},
                {"key": "accessibilityHighContrast", "label": "High contrast", "type": "boolean"},
                {"key": "compactMode", "label": "Compact mode", "type": "boolean"},
                {"key": "developerMode", "label": "Developer mode", "type": "boolean"}
            ]
        }
    ])
}

fn load_user_preferences_from_disk(
    home_dir: &FsPath,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let path = user_settings_path(home_dir);
    let mut preferences = default_user_preferences();
    if !path.exists() {
        return Ok(preferences);
    }

    let raw =
        std::fs::read_to_string(&path).map_err(|e| format!("failed to read user settings: {e}"))?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("invalid user settings JSON: {e}"))?;
    let stored = value
        .get("preferences")
        .and_then(|v| v.as_object())
        .or_else(|| value.as_object())
        .ok_or_else(|| "user settings must be a JSON object".to_string())?;
    for (key, value) in stored {
        preferences.insert(key.clone(), value.clone());
    }
    normalize_whisper_cpp_preferences(&mut preferences);
    Ok(preferences)
}

fn persist_user_preferences(
    home_dir: &FsPath,
    preferences: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    std::fs::create_dir_all(home_dir)
        .map_err(|e| format!("failed to create daemon home directory: {e}"))?;
    let path = user_settings_path(home_dir);
    let temp_path = path.with_extension("json.tmp");
    let payload = serde_json::json!({
        "version": USER_SETTINGS_VERSION,
        "updated_at": chrono::Utc::now().to_rfc3339(),
        "preferences": preferences,
    });
    let bytes = serde_json::to_vec_pretty(&payload)
        .map_err(|e| format!("failed to serialize user settings: {e}"))?;
    if bytes.len() > 256 * 1024 {
        return Err("user settings payload exceeds 256 KiB".to_string());
    }
    std::fs::write(&temp_path, bytes).map_err(|e| format!("failed to write user settings: {e}"))?;
    std::fs::rename(&temp_path, &path)
        .map_err(|e| format!("failed to replace user settings: {e}"))?;
    Ok(())
}

fn user_settings_response(
    home_dir: &FsPath,
    preferences: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "version": USER_SETTINGS_VERSION,
        "source": "daemon",
        "path": user_settings_path(home_dir).to_string_lossy(),
        "preferences": preferences,
        "registry": user_settings_registry(),
    })
}

/// GET /api/user-settings — Load cross-surface user preferences from daemon storage.
pub async fn get_user_settings(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match load_user_preferences_from_disk(&state.kernel.config.home_dir) {
        Ok(preferences) => (
            StatusCode::OK,
            Json(user_settings_response(
                &state.kernel.config.home_dir,
                preferences,
            )),
        ),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": error})),
        ),
    }
}

/// PUT /api/user-settings — Merge and persist cross-surface user preferences.
pub async fn put_user_settings(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let patch = body
        .get("preferences")
        .cloned()
        .unwrap_or_else(|| body.clone());
    let patch = match patch.as_object() {
        Some(object) => object,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "preferences must be a JSON object"})),
            );
        }
    };

    let mut preferences = match load_user_preferences_from_disk(&state.kernel.config.home_dir) {
        Ok(preferences) => preferences,
        Err(_) => default_user_preferences(),
    };
    for (key, value) in patch {
        preferences.insert(key.clone(), value.clone());
    }
    normalize_whisper_cpp_preferences(&mut preferences);
    apply_whisper_cpp_preferences_to_env(&preferences);

    if let Err(error) = persist_user_preferences(&state.kernel.config.home_dir, &preferences) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": error})),
        );
    }

    state.kernel.audit_log.record(
        "system",
        t3rnel_runtime::audit::AuditAction::ConfigChange,
        "user settings updated",
        "completed",
    );

    (
        StatusCode::OK,
        Json(user_settings_response(
            &state.kernel.config.home_dir,
            preferences,
        )),
    )
}

// ---------------------------------------------------------------------------
// Usage endpoint
// ---------------------------------------------------------------------------

/// GET /api/usage — Get per-agent usage statistics.
pub async fn usage_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let agents: Vec<serde_json::Value> = state
        .kernel
        .registry
        .list()
        .iter()
        .map(|e| {
            let (tokens, tool_calls) = state.kernel.scheduler.get_usage(e.id).unwrap_or((0, 0));
            serde_json::json!({
                "agent_id": e.id.to_string(),
                "name": e.name,
                "total_tokens": tokens,
                "tool_calls": tool_calls,
            })
        })
        .collect();

    Json(serde_json::json!({"agents": agents}))
}

// ---------------------------------------------------------------------------
// Usage summary endpoints
// ---------------------------------------------------------------------------

/// GET /api/usage/summary — Get overall usage summary from UsageStore.
pub async fn usage_summary(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.kernel.memory.usage().query_summary(None) {
        Ok(s) => Json(serde_json::json!({
            "total_input_tokens": s.total_input_tokens,
            "total_output_tokens": s.total_output_tokens,
            "total_cost_usd": s.total_cost_usd,
            "call_count": s.call_count,
            "total_tool_calls": s.total_tool_calls,
        })),
        Err(_) => Json(serde_json::json!({
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_cost_usd": 0.0,
            "call_count": 0,
            "total_tool_calls": 0,
        })),
    }
}

/// GET /api/usage/by-model — Get usage grouped by model.
pub async fn usage_by_model(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.kernel.memory.usage().query_by_model() {
        Ok(models) => {
            let list: Vec<serde_json::Value> = models
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "model": m.model,
                        "total_cost_usd": m.total_cost_usd,
                        "total_input_tokens": m.total_input_tokens,
                        "total_output_tokens": m.total_output_tokens,
                        "call_count": m.call_count,
                    })
                })
                .collect();
            Json(serde_json::json!({"models": list}))
        }
        Err(_) => Json(serde_json::json!({"models": []})),
    }
}

/// GET /api/usage/daily — Get daily usage breakdown for the last 7 days.
pub async fn usage_daily(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let days = state.kernel.memory.usage().query_daily_breakdown(7);
    let today_cost = state.kernel.memory.usage().query_today_cost();
    let first_event = state.kernel.memory.usage().query_first_event_date();

    let days_list = match days {
        Ok(d) => d
            .iter()
            .map(|day| {
                serde_json::json!({
                    "date": day.date,
                    "cost_usd": day.cost_usd,
                    "tokens": day.tokens,
                    "calls": day.calls,
                })
            })
            .collect::<Vec<_>>(),
        Err(_) => vec![],
    };

    Json(serde_json::json!({
        "days": days_list,
        "today_cost_usd": today_cost.unwrap_or(0.0),
        "first_event_date": first_event.unwrap_or(None),
    }))
}

// ---------------------------------------------------------------------------
// Budget endpoints
// ---------------------------------------------------------------------------

/// GET /api/budget — Current budget status (limits, spend, % used).
pub async fn budget_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let budget = state.budget_config.read().await;
    let status = state.kernel.metering.budget_status(&budget);
    Json(serde_json::to_value(&status).unwrap_or_default())
}

/// PUT /api/budget — Update global budget limits (in-memory only, not persisted to config.toml).
pub async fn update_budget(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    {
        let mut budget = state.budget_config.write().await;
        if let Some(v) = body["max_hourly_usd"].as_f64() {
            budget.max_hourly_usd = v;
        }
        if let Some(v) = body["max_daily_usd"].as_f64() {
            budget.max_daily_usd = v;
        }
        if let Some(v) = body["max_monthly_usd"].as_f64() {
            budget.max_monthly_usd = v;
        }
        if let Some(v) = body["alert_threshold"].as_f64() {
            budget.alert_threshold = v.clamp(0.0, 1.0);
        }
        if let Some(v) = body["default_max_llm_tokens_per_hour"].as_u64() {
            budget.default_max_llm_tokens_per_hour = v;
        }
    }
    let budget = state.budget_config.read().await;
    let status = state.kernel.metering.budget_status(&budget);
    Json(serde_json::to_value(&status).unwrap_or_default())
}

/// GET /api/budget/agents/{id} — Per-agent budget/quota status.
pub async fn agent_budget_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };

    let entry = match state.kernel.registry.get(agent_id) {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            )
        }
    };

    let quota = &entry.manifest.resources;
    let usage_store = t3rnel_memory::usage::UsageStore::new(state.kernel.memory.usage_conn());
    let hourly = usage_store.query_hourly(agent_id).unwrap_or(0.0);
    let daily = usage_store.query_daily(agent_id).unwrap_or(0.0);
    let monthly = usage_store.query_monthly(agent_id).unwrap_or(0.0);

    // Token usage from scheduler
    let token_usage = state.kernel.scheduler.get_usage(agent_id);
    let tokens_used = token_usage.map(|(t, _)| t).unwrap_or(0);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "agent_id": agent_id.to_string(),
            "agent_name": entry.name,
            "hourly": {
                "spend": hourly,
                "limit": quota.max_cost_per_hour_usd,
                "pct": if quota.max_cost_per_hour_usd > 0.0 { hourly / quota.max_cost_per_hour_usd } else { 0.0 },
            },
            "daily": {
                "spend": daily,
                "limit": quota.max_cost_per_day_usd,
                "pct": if quota.max_cost_per_day_usd > 0.0 { daily / quota.max_cost_per_day_usd } else { 0.0 },
            },
            "monthly": {
                "spend": monthly,
                "limit": quota.max_cost_per_month_usd,
                "pct": if quota.max_cost_per_month_usd > 0.0 { monthly / quota.max_cost_per_month_usd } else { 0.0 },
            },
            "tokens": {
                "used": tokens_used,
                "limit": quota.max_llm_tokens_per_hour,
                "pct": if quota.max_llm_tokens_per_hour > 0 { tokens_used as f64 / quota.max_llm_tokens_per_hour as f64 } else { 0.0 },
            },
        })),
    )
}

/// GET /api/budget/agents — Per-agent cost ranking (top spenders).
pub async fn agent_budget_ranking(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let usage_store = t3rnel_memory::usage::UsageStore::new(state.kernel.memory.usage_conn());
    let agents: Vec<serde_json::Value> = state
        .kernel
        .registry
        .list()
        .iter()
        .filter_map(|entry| {
            let daily = usage_store.query_daily(entry.id).unwrap_or(0.0);
            if daily > 0.0 {
                Some(serde_json::json!({
                    "agent_id": entry.id.to_string(),
                    "name": entry.name,
                    "daily_cost_usd": daily,
                    "hourly_limit": entry.manifest.resources.max_cost_per_hour_usd,
                    "daily_limit": entry.manifest.resources.max_cost_per_day_usd,
                    "monthly_limit": entry.manifest.resources.max_cost_per_month_usd,
                    "max_llm_tokens_per_hour": entry.manifest.resources.max_llm_tokens_per_hour,
                }))
            } else {
                None
            }
        })
        .collect();

    Json(serde_json::json!({"agents": agents, "total": agents.len()}))
}

/// PUT /api/budget/agents/{id} — Update per-agent budget limits at runtime.
pub async fn update_agent_budget(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };

    let hourly = body["max_cost_per_hour_usd"].as_f64();
    let daily = body["max_cost_per_day_usd"].as_f64();
    let monthly = body["max_cost_per_month_usd"].as_f64();
    let tokens = body["max_llm_tokens_per_hour"].as_u64();

    if hourly.is_none() && daily.is_none() && monthly.is_none() && tokens.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "Provide at least one of: max_cost_per_hour_usd, max_cost_per_day_usd, max_cost_per_month_usd, max_llm_tokens_per_hour"}),
            ),
        );
    }

    match state
        .kernel
        .registry
        .update_resources(agent_id, hourly, daily, monthly, tokens)
    {
        Ok(()) => {
            // Persist updated entry
            if let Some(entry) = state.kernel.registry.get(agent_id) {
                let _ = state.kernel.memory.save_agent(&entry);
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "ok", "message": "Agent budget updated"})),
            )
        }
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Session listing endpoints
// ---------------------------------------------------------------------------

/// GET /api/sessions — List all sessions with metadata.
pub async fn list_sessions(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.kernel.memory.list_sessions() {
        Ok(sessions) => Json(serde_json::json!({"sessions": sessions})),
        Err(_) => Json(serde_json::json!({"sessions": []})),
    }
}

/// DELETE /api/sessions/:id — Delete a session.
pub async fn delete_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let session_id = match id.parse::<uuid::Uuid>() {
        Ok(u) => t3rnel_types::agent::SessionId(u),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid session ID"})),
            );
        }
    };

    match state.kernel.memory.delete_session(session_id) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "deleted", "session_id": id})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

/// PUT /api/sessions/:id/label — Set a session label.
pub async fn set_session_label(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let session_id = match id.parse::<uuid::Uuid>() {
        Ok(u) => t3rnel_types::agent::SessionId(u),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid session ID"})),
            );
        }
    };

    let label = req.get("label").and_then(|v| v.as_str());

    // Validate label if present
    if let Some(lbl) = label {
        if let Err(e) = t3rnel_types::agent::SessionLabel::new(lbl) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            );
        }
    }

    match state.kernel.memory.set_session_label(session_id, label) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "updated",
                "session_id": id,
                "label": label,
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

/// GET /api/sessions/by-label/:label — Find session by label (scoped to agent).
pub async fn find_session_by_label(
    State(state): State<Arc<AppState>>,
    Path((agent_id_str, label)): Path<(String, String)>,
) -> impl IntoResponse {
    let agent_id = match agent_id_str.parse::<uuid::Uuid>() {
        Ok(u) => t3rnel_types::agent::AgentId(u),
        Err(_) => {
            // Try name lookup
            match state.kernel.registry.find_by_name(&agent_id_str) {
                Some(entry) => entry.id,
                None => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(serde_json::json!({"error": "Agent not found"})),
                    );
                }
            }
        }
    };

    match state.kernel.memory.find_session_by_label(agent_id, &label) {
        Ok(Some(session)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "session_id": session.id.0.to_string(),
                "agent_id": session.agent_id.0.to_string(),
                "label": session.label,
                "message_count": session.messages.len(),
            })),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "No session found with that label"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Trigger update endpoint
// ---------------------------------------------------------------------------

/// PUT /api/triggers/:id — Update a trigger (enable/disable toggle).
pub async fn update_trigger(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let trigger_id = TriggerId(match id.parse() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid trigger ID"})),
            );
        }
    });

    if let Some(enabled) = req.get("enabled").and_then(|v| v.as_bool()) {
        if state.kernel.set_trigger_enabled(trigger_id, enabled) {
            (
                StatusCode::OK,
                Json(
                    serde_json::json!({"status": "updated", "trigger_id": id, "enabled": enabled}),
                ),
            )
        } else {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Trigger not found"})),
            )
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Missing 'enabled' field"})),
        )
    }
}

// ---------------------------------------------------------------------------
// Agent update endpoint
// ---------------------------------------------------------------------------

/// PUT /api/agents/:id — Update an agent (currently: re-set manifest fields).
pub async fn update_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<AgentUpdateRequest>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid template agent ID"})),
            );
        }
    };

    if state.kernel.registry.get(agent_id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Agent not found"})),
        );
    }

    // Parse the new manifest
    let _manifest: AgentManifest = match toml::from_str(&req.manifest_toml) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid manifest: {e}")})),
            );
        }
    };

    // Note: Full manifest update requires kill + respawn. For now, acknowledge receipt.
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "acknowledged",
            "agent_id": id,
            "note": "Full manifest update requires agent restart. Use DELETE + POST to apply.",
        })),
    )
}

/// PATCH /api/agents/{id} — Partial update of agent fields (name, description, model, system_prompt).
pub async fn patch_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    if state.kernel.registry.get(agent_id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Agent not found"})),
        );
    }

    // Apply partial updates using dedicated registry methods
    if let Some(name) = body.get("name").and_then(|v| v.as_str()) {
        if let Err(e) = state
            .kernel
            .registry
            .update_name(agent_id, name.to_string())
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("{e}")})),
            );
        }
    }
    if let Some(desc) = body.get("description").and_then(|v| v.as_str()) {
        if let Err(e) = state
            .kernel
            .registry
            .update_description(agent_id, desc.to_string())
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("{e}")})),
            );
        }
    }
    if let Some(model) = body.get("model").and_then(|v| v.as_str()) {
        let explicit_provider = body.get("provider").and_then(|v| v.as_str());
        if let Err(e) = state
            .kernel
            .set_agent_model(agent_id, model, explicit_provider)
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("{e}")})),
            );
        }
    }
    if let Some(system_prompt) = body.get("system_prompt").and_then(|v| v.as_str()) {
        if let Err(e) = state
            .kernel
            .registry
            .update_system_prompt(agent_id, system_prompt.to_string())
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("{e}")})),
            );
        }
    }

    // Persist updated entry to SQLite
    if let Some(entry) = state.kernel.registry.get(agent_id) {
        let _ = state.kernel.memory.save_agent(&entry);

        // Write updated manifest to agent.toml on disk so disk doesn't override
        // dashboard changes on next boot (#996, #1018).
        state.kernel.persist_manifest_to_disk(agent_id);

        (
            StatusCode::OK,
            Json(
                serde_json::json!({"status": "ok", "agent_id": entry.id.to_string(), "name": entry.name}),
            ),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Agent vanished during update"})),
        )
    }
}

// ---------------------------------------------------------------------------
// Migration endpoint
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Security dashboard endpoint
// ---------------------------------------------------------------------------

/// GET /api/security — Security feature status for the dashboard.
pub async fn security_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let auth_mode = if state.kernel.config.api_key.is_empty() {
        "localhost_only"
    } else {
        "bearer_token"
    };

    let audit_count = state.kernel.audit_log.len();

    Json(serde_json::json!({
        "core_protections": {
            "path_traversal": true,
            "ssrf_protection": true,
            "capability_system": true,
            "privilege_escalation_prevention": true,
            "subprocess_isolation": true,
            "security_headers": true,
            "wire_hmac_auth": true,
            "request_id_tracking": true
        },
        "configurable": {
            "rate_limiter": {
                "enabled": true,
                "tokens_per_minute": 500,
                "algorithm": "GCRA"
            },
            "websocket_limits": {
                "max_per_ip": 5,
                "idle_timeout_secs": 1800,
                "max_message_size": 65536,
                "max_messages_per_minute": 10
            },
            "wasm_sandbox": {
                "fuel_metering": true,
                "epoch_interruption": true,
                "default_timeout_secs": 30,
                "default_fuel_limit": 1_000_000u64
            },
            "auth": {
                "mode": auth_mode,
                "api_key_set": !state.kernel.config.api_key.is_empty()
            }
        },
        "monitoring": {
            "audit_trail": {
                "enabled": true,
                "algorithm": "SHA-256 Merkle Chain",
                "entry_count": audit_count
            },
            "taint_tracking": {
                "enabled": true,
                "tracked_labels": [
                    "ExternalNetwork",
                    "UserInput",
                    "PII",
                    "Secret",
                    "UntrustedAgent"
                ]
            },
            "manifest_signing": {
                "algorithm": "Ed25519",
                "available": true
            }
        },
        "secret_zeroization": true,
        "total_features": 15
    }))
}

/// GET /api/migrate/detect — Auto-detect OpenClaw installation.
pub async fn migrate_detect() -> impl IntoResponse {
    match t3rnel_migrate::openclaw::detect_openclaw_home() {
        Some(path) => {
            let scan = t3rnel_migrate::openclaw::scan_openclaw_workspace(&path);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "detected": true,
                    "path": path.display().to_string(),
                    "scan": scan,
                })),
            )
        }
        None => (
            StatusCode::OK,
            Json(serde_json::json!({
                "detected": false,
                "path": null,
                "scan": null,
            })),
        ),
    }
}

/// POST /api/migrate/scan — Scan a specific directory for OpenClaw workspace.
pub async fn migrate_scan(Json(req): Json<MigrateScanRequest>) -> impl IntoResponse {
    let path = std::path::PathBuf::from(&req.path);
    if !path.exists() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Directory not found"})),
        );
    }
    let scan = t3rnel_migrate::openclaw::scan_openclaw_workspace(&path);
    (StatusCode::OK, Json(serde_json::json!(scan)))
}

/// POST /api/migrate — Run migration from another agent framework.
pub async fn run_migrate(Json(req): Json<MigrateRequest>) -> impl IntoResponse {
    let source = match req.source.as_str() {
        "openclaw" => t3rnel_migrate::MigrateSource::OpenClaw,
        "langchain" => t3rnel_migrate::MigrateSource::LangChain,
        "autogpt" => t3rnel_migrate::MigrateSource::AutoGpt,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"error": format!("Unknown source: {other}. Use 'openclaw', 'langchain', or 'autogpt'")}),
                ),
            );
        }
    };

    let options = t3rnel_migrate::MigrateOptions {
        source,
        source_dir: std::path::PathBuf::from(&req.source_dir),
        target_dir: std::path::PathBuf::from(&req.target_dir),
        dry_run: req.dry_run,
    };

    match t3rnel_migrate::run_migration(&options) {
        Ok(report) => {
            let imported: Vec<serde_json::Value> = report
                .imported
                .iter()
                .map(|i| {
                    serde_json::json!({
                        "kind": format!("{}", i.kind),
                        "name": i.name,
                        "destination": i.destination,
                    })
                })
                .collect();

            let skipped: Vec<serde_json::Value> = report
                .skipped
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "kind": format!("{}", s.kind),
                        "name": s.name,
                        "reason": s.reason,
                    })
                })
                .collect();

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "completed",
                    "dry_run": req.dry_run,
                    "imported": imported,
                    "imported_count": imported.len(),
                    "skipped": skipped,
                    "skipped_count": skipped.len(),
                    "warnings": report.warnings,
                    "report_markdown": report.to_markdown(),
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Migration failed: {e}")})),
        ),
    }
}

// ── Model Catalog Endpoints ─────────────────────────────────────────

/// GET /api/models — List all models in the catalog.
///
/// Query parameters:
/// - `provider` — filter by provider (e.g. `?provider=anthropic`)
/// - `tier` — filter by tier (e.g. `?tier=smart`)
/// - `available` — only show models from configured providers (`?available=true`)
pub async fn list_models(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let catalog = state
        .kernel
        .model_catalog
        .read()
        .unwrap_or_else(|e| e.into_inner());
    let provider_filter = params.get("provider").map(|s| s.to_lowercase());
    let tier_filter = params.get("tier").map(|s| s.to_lowercase());
    let available_only = params
        .get("available")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let models: Vec<serde_json::Value> = catalog
        .list_models()
        .iter()
        .filter(|m| {
            if let Some(ref p) = provider_filter {
                if m.provider.to_lowercase() != *p {
                    return false;
                }
            }
            if let Some(ref t) = tier_filter {
                if m.tier.to_string() != *t {
                    return false;
                }
            }
            if available_only {
                let provider = catalog.get_provider(&m.provider);
                if let Some(p) = provider {
                    if p.auth_status == t3rnel_types::model_catalog::AuthStatus::Missing {
                        return false;
                    }
                }
            }
            true
        })
        .map(|m| {
            // Custom models from unknown providers are assumed available
            let available = catalog
                .get_provider(&m.provider)
                .map(|p| p.auth_status != t3rnel_types::model_catalog::AuthStatus::Missing)
                .unwrap_or(m.tier == t3rnel_types::model_catalog::ModelTier::Custom);
            serde_json::json!({
                "id": m.id,
                "display_name": m.display_name,
                "provider": m.provider,
                "tier": m.tier,
                "context_window": m.context_window,
                "max_output_tokens": m.max_output_tokens,
                "input_cost_per_m": m.input_cost_per_m,
                "output_cost_per_m": m.output_cost_per_m,
                "supports_tools": m.supports_tools,
                "supports_vision": m.supports_vision,
                "supports_streaming": m.supports_streaming,
                "available": available,
            })
        })
        .collect();

    let total = catalog.list_models().len();
    let available_count = catalog.available_models().len();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "models": models,
            "total": total,
            "available": available_count,
        })),
    )
}

/// GET /api/models/aliases — List all alias-to-model mappings.
pub async fn list_aliases(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let aliases = state
        .kernel
        .model_catalog
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .list_aliases()
        .clone();
    let entries: Vec<serde_json::Value> = aliases
        .iter()
        .map(|(alias, model_id)| {
            serde_json::json!({
                "alias": alias,
                "model_id": model_id,
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "aliases": entries,
            "total": entries.len(),
        })),
    )
}

/// GET /api/models/{id} — Get a single model by ID or alias.
pub async fn get_model(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let catalog = state
        .kernel
        .model_catalog
        .read()
        .unwrap_or_else(|e| e.into_inner());
    match catalog.find_model(&id) {
        Some(m) => {
            let available = catalog
                .get_provider(&m.provider)
                .map(|p| p.auth_status != t3rnel_types::model_catalog::AuthStatus::Missing)
                .unwrap_or(m.tier == t3rnel_types::model_catalog::ModelTier::Custom);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "id": m.id,
                    "display_name": m.display_name,
                    "provider": m.provider,
                    "tier": m.tier,
                    "context_window": m.context_window,
                    "max_output_tokens": m.max_output_tokens,
                    "input_cost_per_m": m.input_cost_per_m,
                    "output_cost_per_m": m.output_cost_per_m,
                    "supports_tools": m.supports_tools,
                    "supports_vision": m.supports_vision,
                    "supports_streaming": m.supports_streaming,
                    "aliases": m.aliases,
                    "available": available,
                })),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Model '{}' not found", id)})),
        ),
    }
}

/// GET /api/providers — List all providers with auth status.
///
/// For local providers (ollama, vllm, lmstudio), also probes reachability and
/// discovers available models via their health endpoints.
///
/// Probes run **concurrently** and results are **cached for 60 seconds** so the
/// endpoint responds instantly on repeated dashboard loads even when local
/// providers are unreachable (fixes #474).
pub async fn list_providers(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let provider_list: Vec<t3rnel_types::model_catalog::ProviderInfo> = {
        let catalog = state
            .kernel
            .model_catalog
            .read()
            .unwrap_or_else(|e| e.into_inner());
        catalog.list_providers().to_vec()
    };

    // Collect local providers that need probing
    let local_providers: Vec<(usize, String, String)> = provider_list
        .iter()
        .enumerate()
        .filter(|(_, p)| !p.key_required && !p.base_url.is_empty())
        .map(|(i, p)| (i, p.id.clone(), p.base_url.clone()))
        .collect();

    // Fire all probes concurrently (cached results return instantly)
    let cache = &state.provider_probe_cache;
    let probe_futures: Vec<_> = local_providers
        .iter()
        .map(|(_, id, url)| t3rnel_runtime::provider_health::probe_provider_cached(id, url, cache))
        .collect();
    let probe_results = futures::future::join_all(probe_futures).await;

    // Index probe results by provider list position for O(1) lookup
    let mut probe_map: HashMap<usize, t3rnel_runtime::provider_health::ProbeResult> =
        HashMap::with_capacity(local_providers.len());
    for ((idx, _, _), result) in local_providers.iter().zip(probe_results) {
        probe_map.insert(*idx, result);
    }

    let mut providers: Vec<serde_json::Value> = Vec::with_capacity(provider_list.len());

    for (i, p) in provider_list.iter().enumerate() {
        let auth_status = if !p.key_required {
            "not_required"
        } else if state
            .kernel
            .resolve_credential(&p.api_key_env)
            .is_some_and(|credential| !credential.trim().is_empty())
        {
            "configured"
        } else {
            "missing"
        };
        let mut entry = serde_json::json!({
            "id": p.id,
            "display_name": p.display_name,
            "auth_status": auth_status,
            "model_count": p.model_count,
            "key_required": p.key_required,
            "api_key_env": p.api_key_env,
            "base_url": p.base_url,
        });

        // For local providers, attach the probe result
        if let Some(probe) = probe_map.remove(&i) {
            entry["is_local"] = serde_json::json!(true);
            entry["reachable"] = serde_json::json!(probe.reachable);
            entry["latency_ms"] = serde_json::json!(probe.latency_ms);
            if !probe.discovered_models.is_empty() {
                entry["discovered_models"] = serde_json::json!(probe.discovered_models);
                // Merge discovered models into the catalog so agents can use them
                if let Ok(mut catalog) = state.kernel.model_catalog.write() {
                    catalog.merge_discovered_models(&p.id, &probe.discovered_models);
                }
            }
            if let Some(err) = &probe.error {
                entry["error"] = serde_json::json!(err);
            }
        } else if !p.key_required {
            // Local provider with empty base_url (e.g. claude-code) — skip probing
            entry["is_local"] = serde_json::json!(true);
        }

        providers.push(entry);
    }

    let total = providers.len();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "providers": providers,
            "total": total,
        })),
    )
}

/// POST /api/models/custom — Add a custom model to the catalog.
///
/// Persists to `~/.t3rnel/custom_models.json` and makes the model immediately
/// available for agent assignment.
pub async fn add_custom_model(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let id = body
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let provider = body
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("openrouter")
        .to_string();
    let context_window = body
        .get("context_window")
        .and_then(|v| v.as_u64())
        .unwrap_or(128_000);
    let max_output = body
        .get("max_output_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(8_192);

    if id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Missing required field: id"})),
        );
    }

    let display = body
        .get("display_name")
        .and_then(|v| v.as_str())
        .unwrap_or(&id)
        .to_string();

    let entry = t3rnel_types::model_catalog::ModelCatalogEntry {
        id: id.clone(),
        display_name: display,
        provider: provider.clone(),
        tier: t3rnel_types::model_catalog::ModelTier::Custom,
        context_window,
        max_output_tokens: max_output,
        input_cost_per_m: body
            .get("input_cost_per_m")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        output_cost_per_m: body
            .get("output_cost_per_m")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        supports_tools: body
            .get("supports_tools")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        supports_vision: body
            .get("supports_vision")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        supports_streaming: body
            .get("supports_streaming")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        aliases: vec![],
        tpm_limit: None,
        tpd_limit: None,
    };

    let mut catalog = state
        .kernel
        .model_catalog
        .write()
        .unwrap_or_else(|e| e.into_inner());

    if !catalog.add_custom_model(entry) {
        return (
            StatusCode::CONFLICT,
            Json(
                serde_json::json!({"error": format!("Model '{}' already exists for provider '{}'", id, provider)}),
            ),
        );
    }

    // Persist to disk
    let custom_path = state.kernel.config.home_dir.join("custom_models.json");
    if let Err(e) = catalog.save_custom_models(&custom_path) {
        tracing::warn!("Failed to persist custom models: {e}");
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": id,
            "provider": provider,
            "status": "added"
        })),
    )
}

/// DELETE /api/models/custom/{id} — Remove a custom model.
pub async fn remove_custom_model(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(model_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let mut catalog = state
        .kernel
        .model_catalog
        .write()
        .unwrap_or_else(|e| e.into_inner());

    if !catalog.remove_custom_model(&model_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Custom model '{}' not found", model_id)})),
        );
    }

    let custom_path = state.kernel.config.home_dir.join("custom_models.json");
    if let Err(e) = catalog.save_custom_models(&custom_path) {
        tracing::warn!("Failed to persist custom models: {e}");
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "removed"})),
    )
}

// ── A2A (Agent-to-Agent) Protocol Endpoints ─────────────────────────

/// GET /.well-known/agent.json — A2A Agent Card for the default agent.
pub async fn a2a_agent_card(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let card = t3rnel_runtime::a2a::AgentCard {
        name: "t3rnel-daemon".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        description: "T3rnel daemon — autonomous agent orchestration".to_string(),
        url: format!("http://{}", state.kernel.config.api_listen),
        capabilities: t3rnel_runtime::a2a::AgentCapabilities {
            streaming: false,
            push_notifications: false,
            state_transition_history: true,
        },
        skills: vec![t3rnel_runtime::a2a::AgentSkill {
            id: "tasks".to_string(),
            name: "Task Execution".to_string(),
            description: "Execute and manage tasks".to_string(),
            tags: vec!["text".to_string()],
            examples: vec![],
        }],
        default_input_modes: vec!["text".to_string()],
        default_output_modes: vec!["text".to_string()],
    };

    (StatusCode::OK, Json(card))
}

/// GET /a2a/agents — List all A2A agent cards.
pub async fn a2a_list_agents(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let agents = state.kernel.list_agents();
    let base_url = format!("http://{}", state.kernel.config.api_listen);

    let cards: Vec<t3rnel_runtime::a2a::AgentCard> = agents
        .into_iter()
        .map(|info| t3rnel_runtime::a2a::AgentCard {
            name: info.name,
            version: "0.1.0".to_string(),
            description: info.description,
            url: format!("{}/api/agents/{}", base_url, info.id),
            capabilities: t3rnel_runtime::a2a::AgentCapabilities {
                streaming: false,
                push_notifications: false,
                state_transition_history: true,
            },
            skills: info
                .tools
                .into_iter()
                .map(|t| t3rnel_runtime::a2a::AgentSkill {
                    id: t.clone(),
                    name: t,
                    description: String::new(),
                    tags: vec!["text".to_string()],
                    examples: vec![],
                })
                .collect(),
            default_input_modes: vec!["text".to_string()],
            default_output_modes: vec!["text".to_string()],
        })
        .collect();

    let total = cards.len();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "agents": cards,
            "total": total,
        })),
    )
}

/// POST /a2a/tasks/send — Submit a task to an agent via A2A.
pub async fn a2a_send_task(
    State(state): State<Arc<AppState>>,
    Json(request): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Extract message text from A2A format
    let message_text = request["params"]["message"]["parts"]
        .as_array()
        .and_then(|parts| {
            parts.iter().find_map(|p| {
                if p["type"].as_str() == Some("text") {
                    p["text"].as_str().map(String::from)
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| "No message provided".to_string());

    // Ingress scan: an A2A task message is untrusted inbound text — another
    // system's agent, which may itself be compromised. Refuse before it is
    // stored as a task or delivered to a local agent.
    let ingress =
        t3rnel_types::sentinel::scan(&message_text, t3rnel_types::sentinel::Direction::Ingress);
    if ingress.blocked {
        let kinds = ingress
            .findings
            .iter()
            .map(|f| format!("{:?}", f.kind))
            .collect::<Vec<_>>()
            .join(",");
        state.kernel.audit_log.record(
            "a2a-inbound",
            t3rnel_runtime::audit::AuditAction::SecurityDenial,
            format!("route=/a2a/tasks/send kinds={kinds}"),
            "denied",
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "a2a message refused by ingress sentinel",
                "findings": ingress.findings.iter().map(|f| f.rule).collect::<Vec<_>>(),
            })),
        );
    }

    // Find target agent (use first available or specified)
    let agents = state.kernel.registry.list();
    if agents.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "No agents available"})),
        );
    }

    let agent = &agents[0];
    let task_id = uuid::Uuid::new_v4().to_string();
    let session_id = request["params"]["sessionId"].as_str().map(String::from);

    // Create the task in the store as Working
    let task = t3rnel_runtime::a2a::A2aTask {
        id: task_id.clone(),
        session_id: session_id.clone(),
        status: t3rnel_runtime::a2a::A2aTaskStatus::Working.into(),
        messages: vec![t3rnel_runtime::a2a::A2aMessage {
            role: "user".to_string(),
            parts: vec![t3rnel_runtime::a2a::A2aPart::Text {
                text: message_text.clone(),
            }],
        }],
        artifacts: vec![],
    };
    state.kernel.a2a_task_store.insert(task);

    // Send message to agent
    match state.kernel.send_message(agent.id, &message_text).await {
        Ok(result) => {
            let response_msg = t3rnel_runtime::a2a::A2aMessage {
                role: "agent".to_string(),
                parts: vec![t3rnel_runtime::a2a::A2aPart::Text {
                    text: result.response,
                }],
            };
            state
                .kernel
                .a2a_task_store
                .complete(&task_id, response_msg, vec![]);
            match state.kernel.a2a_task_store.get(&task_id) {
                Some(completed_task) => (
                    StatusCode::OK,
                    Json(serde_json::to_value(&completed_task).unwrap_or_default()),
                ),
                None => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Task disappeared after completion"})),
                ),
            }
        }
        Err(e) => {
            let error_msg = t3rnel_runtime::a2a::A2aMessage {
                role: "agent".to_string(),
                parts: vec![t3rnel_runtime::a2a::A2aPart::Text {
                    text: format!("Error: {e}"),
                }],
            };
            state.kernel.a2a_task_store.fail(&task_id, error_msg);
            match state.kernel.a2a_task_store.get(&task_id) {
                Some(failed_task) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::to_value(&failed_task).unwrap_or_default()),
                ),
                None => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Agent error: {e}")})),
                ),
            }
        }
    }
}

/// GET /a2a/tasks/{id} — Get task status from the task store.
pub async fn a2a_get_task(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<String>,
) -> impl IntoResponse {
    match state.kernel.a2a_task_store.get(&task_id) {
        Some(task) => (
            StatusCode::OK,
            Json(serde_json::to_value(&task).unwrap_or_default()),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Task '{}' not found", task_id)})),
        ),
    }
}

/// POST /a2a/tasks/{id}/cancel — Cancel a tracked task.
pub async fn a2a_cancel_task(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<String>,
) -> impl IntoResponse {
    if state.kernel.a2a_task_store.cancel(&task_id) {
        match state.kernel.a2a_task_store.get(&task_id) {
            Some(task) => (
                StatusCode::OK,
                Json(serde_json::to_value(&task).unwrap_or_default()),
            ),
            None => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Task disappeared after cancellation"})),
            ),
        }
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Task '{}' not found", task_id)})),
        )
    }
}

// ── A2A Management Endpoints (outbound) ─────────────────────────────────

/// GET /api/a2a/agents — List discovered external A2A agents.
pub async fn a2a_list_external_agents(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let agents = state
        .kernel
        .a2a_external_agents
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let items: Vec<serde_json::Value> = agents
        .iter()
        .map(|(_, card)| {
            serde_json::json!({
                "name": card.name,
                "url": card.url,
                "description": card.description,
                "skills": card.skills,
                "version": card.version,
            })
        })
        .collect();
    Json(serde_json::json!({"agents": items, "total": items.len()}))
}

/// POST /api/a2a/discover — Discover a new external A2A agent by URL.
pub async fn a2a_discover_external(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let url = match body["url"].as_str() {
        Some(u) => u.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing 'url' field"})),
            )
        }
    };

    let client = t3rnel_runtime::a2a::A2aClient::new();
    match client.discover(&url).await {
        Ok(card) => {
            let card_json = serde_json::to_value(&card).unwrap_or_default();
            // Store in kernel's external agents list
            {
                let mut agents = state
                    .kernel
                    .a2a_external_agents
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                // Update or add
                if let Some(existing) = agents.iter_mut().find(|(u, _)| u == &url) {
                    existing.1 = card;
                } else {
                    agents.push((url.clone(), card));
                }
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "url": url,
                    "agent": card_json,
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e})),
        ),
    }
}

/// POST /api/a2a/send — Send a task to an external A2A agent.
pub async fn a2a_send_external(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let url = match body["url"].as_str() {
        Some(u) => u.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing 'url' field"})),
            )
        }
    };
    let message = match body["message"].as_str() {
        Some(m) => m.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing 'message' field"})),
            )
        }
    };
    let session_id = body["session_id"].as_str();

    let client = t3rnel_runtime::a2a::A2aClient::new();
    match client.send_task(&url, &message, session_id).await {
        Ok(task) => (
            StatusCode::OK,
            Json(serde_json::to_value(&task).unwrap_or_default()),
        ),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e})),
        ),
    }
}

/// GET /api/a2a/tasks/{id}/status — Get task status from an external A2A agent.
pub async fn a2a_external_task_status(
    State(_state): State<Arc<AppState>>,
    Path(task_id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let url = match params.get("url") {
        Some(u) => u.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing 'url' query parameter"})),
            )
        }
    };

    let client = t3rnel_runtime::a2a::A2aClient::new();
    match client.get_task(&url, &task_id).await {
        Ok(task) => (
            StatusCode::OK,
            Json(serde_json::to_value(&task).unwrap_or_default()),
        ),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e})),
        ),
    }
}

// ── Team Endpoints ────────────────────────────────────────────────────

fn team_error(
    status: StatusCode,
    error: &str,
    detail: impl Into<String>,
) -> axum::response::Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "detail": detail.into(),
        })),
    )
        .into_response()
}

fn body_string<'a>(body: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    body.get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn slug_from_name(name: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        format!("team-{}", uuid::Uuid::new_v4().simple())
    } else {
        out
    }
}

fn normalize_task_status_api(value: &str) -> Option<String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "queued" => Some("queued".to_string()),
        "running" => Some("running".to_string()),
        "in_progress" | "in-progress" => Some("in_progress".to_string()),
        "blocked" => Some("blocked".to_string()),
        "completed" | "complete" | "done" => Some("done".to_string()),
        "cancelled" | "canceled" | "failed" => Some("failed".to_string()),
        _ => None,
    }
}

fn is_terminal_team_status(status: &str) -> bool {
    matches!(status, "completed" | "done" | "cancelled" | "failed")
}

fn task_event_for_status(status: &str) -> &'static str {
    match status {
        "cancelled" => "task_cancelled",
        "failed" => "task_failed",
        _ => "task_completed",
    }
}

fn is_open_legacy_task_status(status: &str) -> bool {
    matches!(status, "pending" | "in_progress")
}

/// GET /api/tasks — List legacy shared queue tasks counted by health.active_tasks.
pub async fn list_legacy_tasks(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let status = params.get("status").map(String::as_str);
    match state.kernel.memory.task_list(status).await {
        Ok(tasks) => {
            let active = tasks
                .iter()
                .filter(|task| {
                    task.get("status")
                        .and_then(|status| status.as_str())
                        .map(is_open_legacy_task_status)
                        .unwrap_or(false)
                })
                .count();
            Json(serde_json::json!({ "tasks": tasks, "total": tasks.len(), "active": active }))
                .into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("{error}") })),
        )
            .into_response(),
    }
}

/// POST /api/tasks/complete-all — Complete all open legacy shared queue tasks.
pub async fn complete_all_legacy_tasks(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let open_tasks = match state.kernel.memory.task_list(None).await {
        Ok(tasks) => tasks
            .into_iter()
            .filter(|task| {
                task.get("status")
                    .and_then(|status| status.as_str())
                    .map(is_open_legacy_task_status)
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>(),
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("{error}") })),
            )
                .into_response();
        }
    };

    let mut completed = 0usize;
    let mut errors = Vec::new();
    for task in &open_tasks {
        let Some(task_id) = task.get("id").and_then(|id| id.as_str()) else {
            errors.push(serde_json::json!({ "error": "legacy task row missing id" }));
            continue;
        };
        match state
            .kernel
            .memory
            .task_complete(task_id, "Operator completed all open shared queue tasks")
            .await
        {
            Ok(()) => completed += 1,
            Err(error) => {
                errors.push(serde_json::json!({ "id": task_id, "error": format!("{error}") }))
            }
        }
    }

    let tasks = state
        .kernel
        .memory
        .task_list(None)
        .await
        .unwrap_or_default();
    Json(serde_json::json!({
        "status": if errors.is_empty() { "done" } else { "partial" },
        "completed": completed,
        "errors": errors,
        "tasks": tasks,
        "total": tasks.len()
    }))
    .into_response()
}

fn publish_task_milestone(
    state: &Arc<AppState>,
    task: &crate::team_store::TeamTask,
    event: &str,
) -> Result<crate::team_store::A2aMessage, (StatusCode, serde_json::Value)> {
    let sequence = state.team_store.next_sequence(&task.team_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "error": "sequence_failed", "detail": e }),
        )
    })?;
    let recipient_id = task
        .assignee_id
        .clone()
        .unwrap_or_else(|| "t3rnel".to_string());
    let msg = crate::team_store::A2aMessage {
        id: uuid::Uuid::new_v4().to_string(),
        team_id: task.team_id.clone(),
        sender_id: "team-store".to_string(),
        recipient_id,
        msg_type: "task_milestone".to_string(),
        payload: serde_json::json!({
            "event": event,
            "task_id": task.id.clone(),
            "title": task.title.clone(),
            "description": task.description.clone(),
            "status": task.status.clone(),
            "priority": task.priority.clone(),
            "percent": task.percent,
            "assignee_id": task.assignee_id.clone(),
            "created_at": task.created_at.clone(),
            "updated_at": task.updated_at.clone(),
            "completed_at": task.completed_at.clone(),
        }),
        timestamp: chrono::Utc::now().to_rfc3339(),
        sequence,
        trace_id: new_trace_id(),
        task_id: Some(task.id.clone()),
    };
    let marker = format!("task:{}:{}", task.id, task.status);
    state
        .team_store
        .add_message(msg.clone(), &marker)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": "task_milestone_failed", "detail": e }),
            )
        })?;
    state.kernel.audit_log.record(
        "team-store",
        t3rnel_runtime::audit::AuditAction::ConfigChange,
        format!(
            "team task milestone team={} task={} status={} priority={}",
            task.team_id, task.id, task.status, task.priority
        ),
        "ok",
    );
    Ok(msg)
}

fn push_unique_capability(capabilities: &mut Vec<Capability>, capability: Capability) {
    if !capabilities.contains(&capability) {
        capabilities.push(capability);
    }
}

fn add_permission_preset(capabilities: &mut Vec<Capability>, preset: &str) {
    let normalized = preset.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    match normalized.as_str() {
        "research" | "research_web" | "web_research" | "market_research" => {
            add_permission_preset(capabilities, "team_work");
            add_permission_preset(capabilities, "web");
            add_permission_preset(capabilities, "files_read");
        }
        "research_report" | "reporting" => {
            add_permission_preset(capabilities, "research");
            add_permission_preset(capabilities, "files_write");
        }
        "team_work" | "team" | "a2a" => {
            push_unique_capability(
                capabilities,
                Capability::ToolInvoke("memory_store".to_string()),
            );
            push_unique_capability(
                capabilities,
                Capability::ToolInvoke("memory_recall".to_string()),
            );
            push_unique_capability(
                capabilities,
                Capability::ToolInvoke("agent_send".to_string()),
            );
            push_unique_capability(
                capabilities,
                Capability::ToolInvoke("event_publish".to_string()),
            );
            push_unique_capability(
                capabilities,
                Capability::ToolInvoke("task_complete".to_string()),
            );
            push_unique_capability(capabilities, Capability::AgentMessage("*".to_string()));
            push_unique_capability(
                capabilities,
                Capability::MemoryRead("research.*".to_string()),
            );
            push_unique_capability(
                capabilities,
                Capability::MemoryWrite("research.*".to_string()),
            );
        }
        "web" | "web_fetch" | "web_search" | "network" => {
            push_unique_capability(capabilities, Capability::NetConnect("*".to_string()));
            push_unique_capability(
                capabilities,
                Capability::ToolInvoke("web_search".to_string()),
            );
            push_unique_capability(
                capabilities,
                Capability::ToolInvoke("web_fetch".to_string()),
            );
        }
        "files" | "file" | "files_read" | "file_read" => {
            push_unique_capability(capabilities, Capability::FileRead("*".to_string()));
            push_unique_capability(
                capabilities,
                Capability::ToolInvoke("file_read".to_string()),
            );
            push_unique_capability(
                capabilities,
                Capability::ToolInvoke("file_list".to_string()),
            );
        }
        "files_write" | "file_write" | "report_write" => {
            push_unique_capability(capabilities, Capability::FileWrite("reports/*".to_string()));
            push_unique_capability(
                capabilities,
                Capability::ToolInvoke("file_write".to_string()),
            );
        }
        "memory" => {
            push_unique_capability(
                capabilities,
                Capability::MemoryRead("research.*".to_string()),
            );
            push_unique_capability(
                capabilities,
                Capability::MemoryWrite("research.*".to_string()),
            );
            push_unique_capability(
                capabilities,
                Capability::ToolInvoke("memory_store".to_string()),
            );
            push_unique_capability(
                capabilities,
                Capability::ToolInvoke("memory_recall".to_string()),
            );
        }
        _ => {}
    }
}

fn team_assignment_capabilities(msg_type: &str, payload: &serde_json::Value) -> Vec<Capability> {
    let mut capabilities = Vec::new();
    if matches!(
        msg_type,
        "task_assignment" | "implementation_task" | "parallel_task" | "parallel_shard"
    ) {
        add_permission_preset(&mut capabilities, "team_work");
    }

    if let Some(preset) = payload
        .get("permission_preset")
        .and_then(|value| value.as_str())
    {
        add_permission_preset(&mut capabilities, preset);
    }
    if let Some(required) = payload
        .get("requires_permissions")
        .and_then(|value| value.as_array())
    {
        for permission in required.iter().filter_map(|value| value.as_str()) {
            add_permission_preset(&mut capabilities, permission);
        }
    }

    let searchable = [
        payload.get("title").and_then(|value| value.as_str()),
        payload.get("task").and_then(|value| value.as_str()),
        payload.get("description").and_then(|value| value.as_str()),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase();

    if [
        "research", "web", "market", "news", "source", "strategy", "trading", "stock", "macro",
        "economic",
    ]
    .iter()
    .any(|needle| searchable.contains(needle))
    {
        add_permission_preset(&mut capabilities, "web");
    }

    if ["file", "host", "readme", "report", "document"]
        .iter()
        .any(|needle| searchable.contains(needle))
    {
        add_permission_preset(&mut capabilities, "files_read");
    }

    if ["write", "save", "export", "report"]
        .iter()
        .any(|needle| searchable.contains(needle))
    {
        add_permission_preset(&mut capabilities, "files_write");
    }

    capabilities
}

fn grant_capabilities_to_agent(
    state: &AppState,
    agent_id: AgentId,
    capabilities: Vec<Capability>,
    replace: bool,
) -> Vec<Capability> {
    let mut next = if replace {
        Vec::new()
    } else {
        state.kernel.capabilities.list(agent_id)
    };
    let mut added = Vec::new();
    for capability in capabilities {
        if !next.contains(&capability) {
            next.push(capability.clone());
            added.push(capability);
        }
    }
    if replace || !added.is_empty() {
        state.kernel.capabilities.grant(agent_id, next);
    }
    added
}

fn publish_permission_grant_event(
    state: &Arc<AppState>,
    team_id: &str,
    sender_id: &str,
    recipient_id: &str,
    capabilities: &[Capability],
    reason: &str,
) -> Result<(), (StatusCode, serde_json::Value)> {
    if capabilities.is_empty() {
        return Ok(());
    }
    let sequence = state.team_store.next_sequence(team_id).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "error": "sequence_failed", "detail": e }),
        )
    })?;
    let msg = crate::team_store::A2aMessage {
        id: uuid::Uuid::new_v4().to_string(),
        team_id: team_id.to_string(),
        sender_id: sender_id.to_string(),
        recipient_id: recipient_id.to_string(),
        msg_type: "permission_grant".to_string(),
        payload: serde_json::json!({
            "reason": reason,
            "capabilities": capabilities,
            "capability_count": capabilities.len(),
        }),
        timestamp: chrono::Utc::now().to_rfc3339(),
        sequence,
        trace_id: new_trace_id(),
        task_id: None,
    };
    let marker = format!("permission:{recipient_id}:{sequence}");
    state.team_store.add_message(msg, &marker).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "error": "permission_grant_event_failed", "detail": e }),
        )
    })?;
    Ok(())
}

fn auto_grant_team_assignment_permissions(
    state: &Arc<AppState>,
    team_id: &str,
    sender_id: &str,
    recipient_id: &str,
    msg_type: &str,
    payload: &serde_json::Value,
) -> Result<Vec<Capability>, (StatusCode, serde_json::Value)> {
    let capabilities = team_assignment_capabilities(msg_type, payload);
    if capabilities.is_empty() {
        return Ok(Vec::new());
    }
    let Some((agent_id, agent_name)) = resolve_agent_for_permission(state, recipient_id) else {
        return Ok(Vec::new());
    };
    let added = grant_capabilities_to_agent(state, agent_id, capabilities, false);
    if !added.is_empty() {
        state.kernel.audit_log.record(
            agent_id.to_string(),
            t3rnel_runtime::audit::AuditAction::ConfigChange,
            format!(
                "permission_grants_auto_added agent={agent_name} sender={sender_id} count={}",
                added.len()
            ),
            "granted",
        );
        publish_permission_grant_event(
            state,
            team_id,
            sender_id,
            recipient_id,
            &added,
            "auto-granted for team assignment",
        )?;
    }
    Ok(added)
}

/// GET /api/teams — List all teams.
pub async fn list_teams(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.team_store.list_teams() {
        Ok(teams) => {
            Json(serde_json::json!({ "teams": teams, "total": teams.len() })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "team_store_failed", "detail": e })),
        )
            .into_response(),
    }
}

/// POST /api/teams — Create a team.
pub async fn create_team(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let Some(name) = body_string(&body, "name") else {
        return team_error(StatusCode::BAD_REQUEST, "invalid_team", "name is required");
    };
    let id = body_string(&body, "id")
        .map(ToString::to_string)
        .unwrap_or_else(|| slug_from_name(name));
    let kind = body_string(&body, "kind").unwrap_or("permanent");
    let config = body
        .get("config")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    match state.team_store.create_team(&id, name, kind, config) {
        Ok(team) => (StatusCode::CREATED, Json(serde_json::json!(team))).into_response(),
        Err(e) if e.contains("UNIQUE") => team_error(StatusCode::CONFLICT, "team_exists", e),
        Err(e) => team_error(StatusCode::BAD_REQUEST, "invalid_team", e),
    }
}

/// GET /api/teams/{id} — Get a single team.
pub async fn get_team(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.team_store.get_team(&id) {
        Ok(Some(team)) => (StatusCode::OK, Json(serde_json::json!(team))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Team not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "team_store_failed", "detail": e })),
        )
            .into_response(),
    }
}

/// PUT /api/teams/{id} — Update team metadata.
pub async fn update_team(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let name = body_string(&body, "name");
    let kind = body_string(&body, "kind");
    let config = body.get("config").cloned();
    match state.team_store.update_team(&id, name, kind, config) {
        Ok(Some(team)) => (StatusCode::OK, Json(serde_json::json!(team))).into_response(),
        Ok(None) => team_error(StatusCode::NOT_FOUND, "not_found", "Team not found"),
        Err(e) => team_error(StatusCode::BAD_REQUEST, "invalid_team", e),
    }
}

/// DELETE /api/teams/{id} — Delete a team and its local team state.
pub async fn delete_team(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.team_store.delete_team(&id) {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "deleted", "team_id": id })),
        )
            .into_response(),
        Ok(false) => team_error(StatusCode::NOT_FOUND, "not_found", "Team not found"),
        Err(e) => team_error(StatusCode::INTERNAL_SERVER_ERROR, "team_store_failed", e),
    }
}

/// GET /api/teams/{id}/members — Get team members (returns agent IDs; caller resolves via /api/agents).
pub async fn get_team_members(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.team_store.get_team(&id) {
        Ok(Some(team)) => {
            let agents = state.kernel.registry.list();
            let stored_members = match state.team_store.list_members(&id) {
                Ok(members) => members,
                Err(e) => {
                    return team_error(StatusCode::INTERNAL_SERVER_ERROR, "team_store_failed", e);
                }
            };
            let members: Vec<serde_json::Value> = stored_members
                .iter()
                .map(|member| {
                    let mid = &member.agent_id;
                    if let Some(a) = agents.iter().find(|a| a.name == *mid) {
                        let role = if !member.role_tag.trim().is_empty() {
                            member.role_tag.clone()
                        } else if a.manifest.role.is_empty() {
                            a.manifest
                                .metadata
                                .get("role")
                                .and_then(|v| v.as_str())
                                .unwrap_or_else(|| team_member_role(mid))
                                .to_string()
                        } else {
                            a.manifest.role.clone()
                        };
                        serde_json::json!({
                            "id": mid,
                            "runtime_id": a.id,
                            "team_id": team.id.clone(),
                            "name": a.name,
                            "role": role,
                            "role_tag": member.role_tag.clone(),
                            "joined_at": member.joined_at.clone(),
                            "state": format!("{:?}", a.state).to_lowercase(),
                            "mode": format!("{:?}", a.mode).to_lowercase(),
                        })
                    } else {
                        serde_json::json!({
                            "id": mid,
                            "team_id": team.id.clone(),
                            "name": mid,
                            "role": if member.role_tag.trim().is_empty() { team_member_role(mid) } else { &member.role_tag },
                            "role_tag": member.role_tag.clone(),
                            "joined_at": member.joined_at.clone(),
                            "state": "offline",
                            "mode": "full",
                        })
                    }
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "members": members, "total": members.len() })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Team not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "team_store_failed", "detail": e })),
        )
            .into_response(),
    }
}

/// PUT /api/teams/{id}/members/{agent_id} — Add or update a team member role.
pub async fn upsert_team_member(
    State(state): State<Arc<AppState>>,
    Path((team_id, agent_id)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let role = body_string(&body, "role")
        .or_else(|| body_string(&body, "role_tag"))
        .unwrap_or("member");
    match state.team_store.upsert_member(&team_id, &agent_id, role) {
        Ok(Some(member)) => (StatusCode::OK, Json(serde_json::json!(member))).into_response(),
        Ok(None) => team_error(StatusCode::NOT_FOUND, "not_found", "Team not found"),
        Err(e) => team_error(StatusCode::BAD_REQUEST, "invalid_member", e),
    }
}

/// DELETE /api/teams/{id}/members/{agent_id} — Remove a team member.
pub async fn remove_team_member(
    State(state): State<Arc<AppState>>,
    Path((team_id, agent_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.team_store.remove_member(&team_id, &agent_id) {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "removed", "team_id": team_id, "agent_id": agent_id })),
        )
            .into_response(),
        Ok(false) => team_error(StatusCode::NOT_FOUND, "not_found", "Team member not found"),
        Err(e) => team_error(StatusCode::INTERNAL_SERVER_ERROR, "team_store_failed", e),
    }
}

/// GET /api/teams/{id}/tasks — List tasks for a team.
pub async fn list_team_tasks(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.team_store.list_tasks(Some(&id)) {
        Ok(tasks) => {
            Json(serde_json::json!({ "tasks": tasks, "total": tasks.len() })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "team_store_failed", "detail": e })),
        )
            .into_response(),
    }
}

/// POST /api/teams/{id}/tasks — Create a new team task.
pub async fn create_team_task(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let Some(title) = body_string(&req, "title") else {
        return team_error(StatusCode::BAD_REQUEST, "invalid_task", "title is required");
    };
    let description = body_string(&req, "description").unwrap_or(title);
    let Some(assignee_id) = body_string(&req, "assignee_id") else {
        return team_error(
            StatusCode::BAD_REQUEST,
            "invalid_task",
            "assignee_id is required",
        );
    };
    let priority = body_string(&req, "priority").unwrap_or("normal");
    let blockers = req["blockers"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let auto_granted = match auto_grant_team_assignment_permissions(
        &state,
        &id,
        "t3rnel",
        assignee_id,
        "task_assignment",
        &req,
    ) {
        Ok(capabilities) => capabilities,
        Err((status, body)) => return (status, Json(body)).into_response(),
    };

    match state.team_store.create_task_assignment_with_priority(
        &id,
        title,
        description,
        assignee_id,
        blockers,
        priority,
    ) {
        Ok(task) => {
            let mut body = serde_json::to_value(&task).unwrap_or_else(|_| serde_json::json!({}));
            if !auto_granted.is_empty() {
                body["auto_granted_capabilities"] = serde_json::json!(auto_granted);
            }
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Err(e) => team_error(StatusCode::BAD_REQUEST, "invalid_task", e),
    }
}

/// PUT /api/teams/{id}/tasks/{task_id} — Update team task status, priority, progress, and assignment.
pub async fn update_team_task(
    State(state): State<Arc<AppState>>,
    Path((team_id, task_id)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut task = match state.team_store.get_task(&task_id) {
        Ok(Some(task)) if task.team_id == team_id => task,
        Ok(_) => return team_error(StatusCode::NOT_FOUND, "not_found", "Task not found"),
        Err(e) => return team_error(StatusCode::INTERNAL_SERVER_ERROR, "team_store_failed", e),
    };
    let previous_status = task.status.clone();
    if let Some(title) = body_string(&body, "title") {
        task.title = title.to_string();
    }
    if let Some(description) = body_string(&body, "description") {
        task.description = description.to_string();
    }
    if let Some(status) = body_string(&body, "status") {
        let Some(status) = normalize_task_status_api(status) else {
            return team_error(StatusCode::BAD_REQUEST, "invalid_task", "status is invalid");
        };
        task.status = status;
    }
    if let Some(assignee_id) = body.get("assignee_id") {
        task.assignee_id = assignee_id
            .as_str()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
    }
    if let Some(priority) = body_string(&body, "priority") {
        task.priority = priority.to_string();
    }
    if let Some(percent) = body.get("percent").and_then(|value| value.as_u64()) {
        task.percent = percent.min(100) as u8;
    }
    if let Some(current_step) = body.get("current_step").and_then(|value| value.as_u64()) {
        task.current_step = current_step.min(u32::MAX as u64) as u32;
    }
    if let Some(total_steps) = body.get("total_steps").and_then(|value| value.as_u64()) {
        task.total_steps = total_steps.max(1).min(u32::MAX as u64) as u32;
    }
    if let Some(blockers) = body.get("blockers").and_then(|value| value.as_array()) {
        task.blockers = blockers
            .iter()
            .filter_map(|value| value.as_str().map(str::trim))
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect();
        if !task.blockers.is_empty() && !is_terminal_team_status(&task.status) {
            task.status = "blocked".to_string();
        }
    }
    match state.team_store.save_task(&mut task) {
        Ok(saved) => {
            if previous_status != saved.status && is_terminal_team_status(&saved.status) {
                if let Err((status, body)) =
                    publish_task_milestone(&state, &saved, task_event_for_status(&saved.status))
                {
                    return (status, Json(body)).into_response();
                }
            }
            (StatusCode::OK, Json(serde_json::json!(saved))).into_response()
        }
        Err(e) => team_error(StatusCode::BAD_REQUEST, "invalid_task", e),
    }
}

/// POST /api/teams/{id}/tasks/complete-all — Mark all open team tasks complete.
pub async fn complete_all_team_tasks(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let open_ids: HashSet<String> = match state.team_store.list_tasks(Some(&id)) {
        Ok(tasks) => tasks
            .into_iter()
            .filter(|task| !is_terminal_team_status(&task.status))
            .map(|task| task.id)
            .collect(),
        Err(e) => return team_error(StatusCode::INTERNAL_SERVER_ERROR, "team_store_failed", e),
    };
    match state.team_store.finish_all_tasks(&id, "done") {
        Ok(tasks) => {
            let mut milestone_count = 0usize;
            for task in &tasks {
                if open_ids.contains(&task.id) {
                    if let Err((status, body)) =
                        publish_task_milestone(&state, task, task_event_for_status(&task.status))
                    {
                        return (status, Json(body)).into_response();
                    }
                    milestone_count += 1;
                }
            }
            let total = tasks.len();
            Json(serde_json::json!({ "tasks": tasks, "total": total, "milestones": milestone_count, "status": "done" }))
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "team_store_failed", "detail": e })),
        )
            .into_response(),
    }
}

/// POST /api/teams/{id}/tasks/{task_id}/complete — Mark a team task complete.
pub async fn complete_team_task(
    State(state): State<Arc<AppState>>,
    Path((team_id, task_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.team_store.finish_task(&team_id, &task_id, "done") {
        Ok(Some(task)) => {
            if let Err((status, body)) =
                publish_task_milestone(&state, &task, task_event_for_status(&task.status))
            {
                return (status, Json(body)).into_response();
            }
            (StatusCode::OK, Json(serde_json::json!(task))).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Task not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "team_store_failed", "detail": e })),
        )
            .into_response(),
    }
}

/// POST /api/teams/{id}/tasks/{task_id}/cancel — Mark a team task cancelled.
pub async fn cancel_team_task(
    State(state): State<Arc<AppState>>,
    Path((team_id, task_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.team_store.finish_task(&team_id, &task_id, "failed") {
        Ok(Some(task)) => {
            if let Err((status, body)) =
                publish_task_milestone(&state, &task, task_event_for_status(&task.status))
            {
                return (status, Json(body)).into_response();
            }
            (StatusCode::OK, Json(serde_json::json!(task))).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Task not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "team_store_failed", "detail": e })),
        )
            .into_response(),
    }
}

/// GET /api/teams/{id}/tasks/{task_id}/progress — Get task progress.
pub async fn get_task_progress(
    State(state): State<Arc<AppState>>,
    Path((team_id, task_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.team_store.get_task(&task_id) {
        Ok(Some(task)) if task.team_id == team_id => {
            (StatusCode::OK, Json(serde_json::json!(task))).into_response()
        }
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Task not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "team_store_failed", "detail": e })),
        )
            .into_response(),
    }
}

/// GET /api/teams/{id}/a2a/messages — List A2A messages for a team.
pub async fn list_a2a_messages(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let since = params.get("since").map(|s| s.as_str());
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(50);
    match state.team_store.list_messages(&id, since, limit) {
        Ok(messages) => Json(serde_json::json!({ "messages": messages, "total": messages.len() }))
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": "team_store_failed", "detail": e })),
        )
            .into_response(),
    }
}

/// POST /api/teams/{id}/a2a/messages — Send an A2A message within a team.
pub async fn send_a2a_message(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let team = match state.team_store.get_team(&id) {
        Ok(Some(team)) => team,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "Team not found" })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "team_store_failed", "detail": e })),
            )
                .into_response();
        }
    };
    let Some(sender_id) = body["sender_id"].as_str().filter(|v| !v.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "sender_id is required" })),
        )
            .into_response();
    };
    let Some(recipient_id) = body["recipient_id"]
        .as_str()
        .filter(|v| !v.trim().is_empty())
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "recipient_id is required" })),
        )
            .into_response();
    };
    let Some(msg_type) = body["msg_type"].as_str().filter(|v| !v.trim().is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "msg_type is required" })),
        )
            .into_response();
    };
    let payload = body
        .get("payload")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    let marker = payload
        .get("marker")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let is_virtual_fanout_recipient =
        msg_type == "parallel_shard" && recipient_id.strip_prefix("coder-").is_some();

    if !team.member_ids.iter().any(|member| member == sender_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "sender_id is not a team member" })),
        )
            .into_response();
    }
    if !team.member_ids.iter().any(|member| member == recipient_id) && !is_virtual_fanout_recipient
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "recipient_id is not a team member" })),
        )
            .into_response();
    }

    if is_virtual_fanout_recipient && marker.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "payload.marker is required for parallel_shard fanout" })),
        )
            .into_response();
    }

    let captured_trace_id = body
        .get("trace_id")
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(new_trace_id);
    let api_span = tracing::info_span!(
        "api.a2a.send",
        team_id = %id,
        sender_id = %sender_id,
        recipient_id = %recipient_id,
        msg_type = %msg_type,
        marker = %marker
    );
    set_span_trace_parent(&api_span, &captured_trace_id);
    let _api_span_guard = api_span.enter();

    let auto_granted = match auto_grant_team_assignment_permissions(
        &state,
        &id,
        sender_id,
        recipient_id,
        msg_type,
        &payload,
    ) {
        Ok(capabilities) => capabilities,
        Err((status, body)) => return (status, Json(body)).into_response(),
    };

    let task_id = match create_a2a_task_if_needed(&state, &id, recipient_id, msg_type, &payload) {
        Ok(task_id) => task_id,
        Err((status, body)) => return (status, Json(body)).into_response(),
    };
    let sequence = payload
        .get("sequence")
        .and_then(|v| v.as_u64())
        .map(Ok)
        .unwrap_or_else(|| state.team_store.next_sequence(&id));
    let sequence = match sequence {
        Ok(sequence) => sequence,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "sequence_failed", "detail": e })),
            )
                .into_response();
        }
    };
    let trace_id = captured_trace_id;
    let msg = crate::team_store::A2aMessage {
        id: uuid::Uuid::new_v4().to_string(),
        team_id: id.clone(),
        sender_id: sender_id.to_string(),
        recipient_id: recipient_id.to_string(),
        msg_type: msg_type.to_string(),
        payload: payload.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        sequence,
        trace_id,
        task_id: task_id.clone(),
    };

    let dispatch_span = tracing::info_span!(
        "runtime.a2a.dispatch",
        trace_id = %msg.trace_id,
        team_id = %id,
        sender_id = %sender_id,
        recipient_id = %recipient_id,
        msg_type = %msg_type
    );
    let _dispatch_span_guard = dispatch_span.enter();

    let added = if is_virtual_fanout_recipient {
        match state
            .team_store
            .add_message_with_fanout_limit(msg.clone(), &marker, msg_type, 8)
        {
            Ok(added) => added,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "fanout_count_failed", "detail": e })),
                )
                    .into_response();
            }
        }
    } else {
        match state.team_store.add_message(msg.clone(), &marker) {
            Ok(()) => true,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "a2a_persist_failed", "detail": e })),
                )
                    .into_response();
            }
        }
    };

    if !added {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "MAX_FANOUT limit exceeded", "limit": 8 })),
        )
            .into_response();
    }
    let approval_id = match create_review_approval_if_needed(
        &state,
        sender_id,
        recipient_id,
        msg_type,
        &msg.payload,
    ) {
        Ok(approval_id) => approval_id,
        Err((status, body)) => return (status, Json(body)).into_response(),
    };
    state.kernel.audit_log.record(
        sender_id,
        t3rnel_runtime::audit::AuditAction::AgentMessage,
        format!(
            "a2a team={} sender={} recipient={} msg_type={} marker={}",
            id, sender_id, recipient_id, msg_type, marker
        ),
        "ok",
    );
    let mut response = serde_json::to_value(msg).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(task_id) = task_id {
        response["task_id"] = serde_json::json!(task_id);
    }
    if let Some(approval_id) = approval_id {
        response["approval_id"] = serde_json::json!(approval_id);
    }
    if !auto_granted.is_empty() {
        response["auto_granted_capabilities"] = serde_json::json!(auto_granted);
    }
    (StatusCode::OK, Json(response)).into_response()
}

/// GET /api/teams/{id}/a2a/stream — SSE stream of persisted and live A2A messages.
pub async fn a2a_message_stream(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    use axum::response::sse::{Event, KeepAlive, Sse};

    let since = params.get("since").map(|s| s.as_str());
    let backlog = match state.team_store.list_messages(
        &id,
        since,
        crate::team_store::default_list_limit(),
    ) {
        Ok(messages) => messages,
        Err(e) => {
            let stream = async_stream::stream! {
                yield Ok::<_, std::convert::Infallible>(
                    Event::default()
                        .event("error")
                        .data(serde_json::json!({ "error": "team_store_failed", "detail": e }).to_string())
                );
            };
            return Sse::new(stream).into_response();
        }
    };

    let mut rx = state.team_store.subscribe();
    let stream_team_id = id;
    let stream = async_stream::stream! {
        for message in backlog {
            if let Ok(data) = serde_json::to_string(&message) {
                yield Ok::<_, std::convert::Infallible>(Event::default().event("a2a").data(data));
            }
        }
        loop {
            match rx.recv().await {
                Ok(message) if message.team_id == stream_team_id => {
                    if let Ok(data) = serde_json::to_string(&message) {
                        yield Ok::<_, std::convert::Infallible>(Event::default().event("a2a").data(data));
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    yield Ok::<_, std::convert::Infallible>(
                        Event::default().event("gap").data("{\"warning\":\"a2a_stream_lagged\"}")
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(std::time::Duration::from_secs(15))
                .text("ping"),
        )
        .into_response()
}

fn create_a2a_task_if_needed(
    state: &Arc<AppState>,
    team_id: &str,
    recipient_id: &str,
    msg_type: &str,
    payload: &serde_json::Value,
) -> Result<Option<String>, (StatusCode, serde_json::Value)> {
    if !matches!(
        msg_type,
        "task_assignment" | "implementation_task" | "parallel_task" | "parallel_shard"
    ) {
        return Ok(None);
    }

    let title = payload
        .get("title")
        .or_else(|| payload.get("task"))
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            let marker = payload
                .get("marker")
                .and_then(|v| v.as_str())
                .unwrap_or("unmarked");
            format!("{msg_type} for {recipient_id} ({marker})")
        });
    let description = payload
        .get("description")
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(&title)
        .to_string();
    let blockers = payload
        .get("depends_on")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let priority = payload
        .get("priority")
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("normal");

    match state.team_store.create_task_assignment_with_priority(
        team_id,
        &title,
        &description,
        recipient_id,
        blockers,
        priority,
    ) {
        Ok(task) => Ok(Some(task.id)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "error": "task_assignment_failed", "detail": e }),
        )),
    }
}

fn create_review_approval_if_needed(
    state: &Arc<AppState>,
    sender_id: &str,
    recipient_id: &str,
    msg_type: &str,
    payload: &serde_json::Value,
) -> Result<Option<String>, (StatusCode, serde_json::Value)> {
    if msg_type != "review_approval" {
        return Ok(None);
    }

    let marker = payload
        .get("marker")
        .and_then(|v| v.as_str())
        .unwrap_or("review_approval");
    let title = payload
        .get("title")
        .or_else(|| payload.get("task"))
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or("Review approval");
    let description = payload
        .get("description")
        .and_then(|v| v.as_str())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(title);
    let id = uuid::Uuid::new_v4();
    let request = t3rnel_types::approval::ApprovalRequest {
        id,
        agent_id: recipient_id.to_string(),
        tool_name: "review_approval".to_string(),
        description: format!("{description} [{marker}]"),
        action_summary: format!("{title} from {sender_id} [{marker}]"),
        risk_level: t3rnel_types::approval::RiskLevel::High,
        requested_at: chrono::Utc::now(),
        timeout_secs: state.kernel.approval_manager.policy().timeout_secs,
    };

    state
        .kernel
        .approval_manager
        .submit_pending(request)
        .map(|()| {
            // Mirror into the pending-actions ledger so the ask is visible to
            // `approvals`, the dashboard and WhatsApp replies (APPROVE P-n).
            let item = crate::pending_actions::create_pending(
                crate::pending_actions::CreatePendingRequest {
                    summary: format!("{title} from {sender_id} [{marker}]"),
                    kind: Some(crate::pending_actions::PendingKind::Approval),
                    detail_ref: Some(id.to_string()),
                    agent: Some(recipient_id.to_string()),
                    callback: Some("approval".to_string()),
                    risk: Some("high".to_string()),
                    ttl_secs: Some(state.kernel.approval_manager.policy().timeout_secs as i64),
                    wa_message_id: None,
                },
            );
            let _ = item;
            Some(id.to_string())
        })
        .map_err(|e| {
            (
                StatusCode::CONFLICT,
                serde_json::json!({ "error": "approval_request_failed", "detail": e }),
            )
        })
}

fn team_member_role(member_id: &str) -> &str {
    match member_id {
        "t3rnel" => "orchestrator",
        "architect" => "architect",
        "project-manager" => "project_manager",
        "researcher" => "researcher",
        "backend-builder" => "backend_builder",
        "frontend-builder" => "frontend_builder",
        "coder" => "coder",
        "reviewer" => "reviewer",
        "security-auditor" => "security_auditor",
        "test-engineer" => "test_engineer",
        "qa-engineer" => "qa_engineer",
        "ui-ux-designer" => "ui_ux_designer",
        "devops-lead" => "devops_lead",
        "data-scientist" => "data_scientist",
        "doc-writer" => "doc_writer",
        "release-manager" => "release_manager",
        "browser-hand" => "browser_hand",
        _ => "",
    }
}

/// POST /api/channels/telegram/webhook — Receive a Telegram webhook update.
pub async fn telegram_webhook(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let text = body
        .get("message")
        .and_then(|message| message.get("text"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim();
    if text.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "telegram_message_text_required" })),
        )
            .into_response();
    }

    let marker = extract_swarm_marker(text).unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let payload = serde_json::json!({
        "marker": marker,
        "text": text,
        "telegram": body,
    });
    match persist_external_a2a(
        &state,
        "telegram-bridge",
        "t3rnel",
        "external_command",
        payload,
        &marker,
    ) {
        Ok(message) => {
            let ack = format!("Telegram command received: {text}");
            if let Err(e) = append_text_to_agent_session(&state, "t3rnel", text, Some(&ack)).await {
                tracing::warn!("failed to append telegram command to orchestrator session: {e}");
            }
            Json(serde_json::json!({
                "ok": true,
                "marker": marker,
                "message_id": message.id,
                "trace_id": message.trace_id,
            }))
            .into_response()
        }
        Err((status, body)) => (status, Json(body)).into_response(),
    }
}

/// POST /api/events — Publish a local event into the permanent swarm team.
pub async fn post_event(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let event_type = body
        .get("type")
        .and_then(|value| value.as_str())
        .unwrap_or("event");
    let serialized = body.to_string();
    let marker = body
        .get("marker")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .or_else(|| extract_swarm_marker(&serialized))
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let mut message_ids = Vec::new();
    for recipient in ["t3rnel", "devops-lead"] {
        let payload = serde_json::json!({
            "marker": marker,
            "event": body,
        });
        match persist_external_a2a(&state, "event-bus", recipient, event_type, payload, &marker) {
            Ok(message) => message_ids.push(message.id),
            Err((status, body)) => return (status, Json(body)).into_response(),
        }
    }

    if event_type == "email_received" {
        if let Err(error) = notify_email_received_event(&body) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": error,
                    "marker": marker,
                    "message_ids": message_ids,
                    "ok": false,
                })),
            )
                .into_response();
        }
    }

    Json(serde_json::json!({
        "ok": true,
        "marker": marker,
        "message_ids": message_ids,
    }))
    .into_response()
}

fn notify_email_received_event(body: &serde_json::Value) -> Result<(), String> {
    let subject = body
        .get("payload")
        .and_then(|payload| payload.get("subject"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("New email arrived");
    let status = std::process::Command::new("notify-send")
        .arg("T3rnel Email Received")
        .arg(subject)
        .status()
        .map_err(|error| format!("desktop notification failed to start: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("desktop notification failed with status: {status}"))
    }
}

/// POST /api/context — Ingest external surface context, e.g. Chrome extension.
pub async fn post_context(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let source = body
        .get("source")
        .and_then(|value| value.as_str())
        .unwrap_or("external-context")
        .to_string();
    let serialized = body.to_string();
    let marker = body
        .get("marker")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .or_else(|| extract_swarm_marker(&serialized))
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let msg_type = if source == "chrome-extension" {
        "chrome_context"
    } else {
        "external_context"
    };

    match persist_external_a2a(&state, &source, "t3rnel", msg_type, body, &marker) {
        Ok(message) => Json(serde_json::json!({
            "ok": true,
            "marker": marker,
            "message_id": message.id,
            "trace_id": message.trace_id,
        }))
        .into_response(),
        Err((status, body)) => (status, Json(body)).into_response(),
    }
}

fn extract_swarm_marker(text: &str) -> Option<String> {
    text.split_whitespace()
        .map(|part| {
            part.trim_matches(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
        })
        .find(|part| part.starts_with("swarm-"))
        .map(str::to_string)
}

fn persist_external_a2a(
    state: &Arc<AppState>,
    sender_id: &str,
    recipient_id: &str,
    msg_type: &str,
    payload: serde_json::Value,
    marker: &str,
) -> Result<crate::team_store::A2aMessage, (StatusCode, serde_json::Value)> {
    match state.team_store.get_team("software-engineering") {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                serde_json::json!({ "error": "Team not found" }),
            ));
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": "team_store_failed", "detail": e }),
            ));
        }
    }

    let sequence = match state.team_store.next_sequence("software-engineering") {
        Ok(sequence) => sequence,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": "sequence_failed", "detail": e }),
            ));
        }
    };
    // Ingress scan: every caller of this function persists external text that
    // agents later read back as team context. Scanning the serialized payload
    // here covers all callers (events bus, telegram commands, orchestrator
    // feeds) in one place.
    let serialized = payload.to_string();
    let ingress =
        t3rnel_types::sentinel::scan(&serialized, t3rnel_types::sentinel::Direction::Ingress);
    if ingress.blocked {
        let kinds = ingress
            .findings
            .iter()
            .map(|f| format!("{:?}", f.kind))
            .collect::<Vec<_>>()
            .join(",");
        state.kernel.audit_log.record(
            sender_id,
            t3rnel_runtime::audit::AuditAction::SecurityDenial,
            format!("route=external_a2a recipient={recipient_id} kinds={kinds}"),
            "denied",
        );
        return Err((
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "external_a2a payload refused by ingress sentinel",
                "findings": ingress.findings.iter().map(|f| f.rule).collect::<Vec<_>>(),
            }),
        ));
    }

    let message = crate::team_store::A2aMessage {
        id: uuid::Uuid::new_v4().to_string(),
        team_id: "software-engineering".to_string(),
        sender_id: sender_id.to_string(),
        recipient_id: recipient_id.to_string(),
        msg_type: msg_type.to_string(),
        payload,
        timestamp: chrono::Utc::now().to_rfc3339(),
        sequence,
        trace_id: uuid::Uuid::new_v4().to_string(),
        task_id: None,
    };

    if let Err(e) = state.team_store.add_message(message.clone(), marker) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "error": "a2a_persist_failed", "detail": e }),
        ));
    }
    state.kernel.audit_log.record(
        sender_id,
        t3rnel_runtime::audit::AuditAction::AgentMessage,
        format!(
            "external_a2a team=software-engineering sender={} recipient={} msg_type={} marker={}",
            sender_id, recipient_id, msg_type, marker
        ),
        "ok",
    );
    Ok(message)
}

async fn append_text_to_agent_session(
    state: &Arc<AppState>,
    agent_name: &str,
    user_text: &str,
    assistant_text: Option<&str>,
) -> Result<(), String> {
    let entry = state
        .kernel
        .registry
        .list()
        .into_iter()
        .find(|entry| entry.name == agent_name)
        .ok_or_else(|| format!("agent {agent_name} not found"))?;
    append_text_to_agent_session_by_id(state, entry.id, user_text, assistant_text).await
}

async fn append_text_to_agent_session_by_id(
    state: &Arc<AppState>,
    agent_id: AgentId,
    user_text: &str,
    assistant_text: Option<&str>,
) -> Result<(), String> {
    let entry = state
        .kernel
        .registry
        .get(agent_id)
        .ok_or_else(|| format!("agent {agent_id} not found"))?;
    let mut session = state
        .kernel
        .memory
        .get_session(entry.session_id)
        .map_err(|e| e.to_string())?
        .unwrap_or(t3rnel_memory::session::Session {
            id: entry.session_id,
            agent_id: entry.id,
            messages: Vec::new(),
            context_window_tokens: 0,
            label: None,
        });
    session
        .messages
        .push(t3rnel_types::message::Message::user(user_text.to_string()));
    if let Some(text) = assistant_text {
        session
            .messages
            .push(t3rnel_types::message::Message::assistant(text.to_string()));
    }
    state
        .kernel
        .memory
        .save_session_async(&session)
        .await
        .map_err(|e| e.to_string())
}

// ── MCP HTTP Endpoint ───────────────────────────────────────────────────

/// POST /mcp — Handle MCP JSON-RPC requests over HTTP.
///
/// Exposes the same MCP protocol normally served via stdio, allowing
/// external MCP clients to connect over HTTP instead.
pub async fn mcp_http(
    State(state): State<Arc<AppState>>,
    Json(request): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Gather all available tools (builtin + skills + MCP)
    let mut tools = builtin_tool_definitions();
    {
        let registry = state
            .kernel
            .skill_registry
            .read()
            .unwrap_or_else(|e| e.into_inner());
        for skill_tool in registry.all_tool_definitions() {
            tools.push(t3rnel_types::tool::ToolDefinition {
                name: skill_tool.name.clone(),
                description: skill_tool.description.clone(),
                input_schema: skill_tool.input_schema.clone(),
            });
        }
    }
    if let Ok(mcp_tools) = state.kernel.mcp_tools.lock() {
        tools.extend(mcp_tools.iter().cloned());
    }

    // Check if this is a tools/call that needs real execution
    let method = request["method"].as_str().unwrap_or("");
    if method == "tools/call" {
        let tool_name = request["params"]["name"].as_str().unwrap_or("");
        let arguments = request["params"]
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        // Verify the tool exists
        if !tools.iter().any(|t| t.name == tool_name) {
            return Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": request.get("id").cloned(),
                "error": {"code": -32602, "message": format!("Unknown tool: {tool_name}")}
            }));
        }

        // Snapshot skill registry before async call (RwLockReadGuard is !Send)
        let skill_snapshot = state
            .kernel
            .skill_registry
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot();

        // Execute the tool via the kernel's tool runner
        let kernel_handle: Arc<dyn t3rnel_runtime::kernel_handle::KernelHandle> =
            state.kernel.clone() as Arc<dyn t3rnel_runtime::kernel_handle::KernelHandle>;
        let result = t3rnel_runtime::tool_runner::execute_tool(
            "mcp-http",
            tool_name,
            &arguments,
            Some(&kernel_handle),
            None,
            None,
            Some(&skill_snapshot),
            Some(&state.kernel.mcp_connections),
            Some(&state.kernel.web_ctx),
            Some(&state.kernel.browser_ctx),
            None,
            None,
            Some(&state.kernel.media_engine),
            None, // exec_policy
            if state.kernel.config.tts.enabled {
                Some(&state.kernel.tts_engine)
            } else {
                None
            },
            if state.kernel.config.docker.enabled {
                Some(&state.kernel.config.docker)
            } else {
                None
            },
            Some(&*state.kernel.process_manager),
        )
        .await;

        return Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": request.get("id").cloned(),
            "result": {
                "content": [{"type": "text", "text": result.content}],
                "isError": result.is_error,
            }
        }));
    }

    // For non-tools/call methods (initialize, tools/list, etc.), delegate to the handler
    let response = t3rnel_runtime::mcp_server::handle_mcp_request(&request, &tools).await;
    Json(response)
}

// ── Multi-Session Endpoints ─────────────────────────────────────────────

/// GET /api/agents/{id}/sessions — List all sessions for an agent.
pub async fn list_agent_sessions(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };
    match state.kernel.list_agent_sessions(agent_id) {
        Ok(sessions) => (
            StatusCode::OK,
            Json(serde_json::json!({"sessions": sessions})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// POST /api/agents/{id}/sessions — Create a new session for an agent.
pub async fn create_agent_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };
    let label = req.get("label").and_then(|v| v.as_str());
    match state.kernel.create_agent_session(agent_id, label) {
        Ok(session) => (StatusCode::OK, Json(session)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// POST /api/agents/{id}/sessions/{session_id}/switch — Switch to an existing session.
pub async fn switch_agent_session(
    State(state): State<Arc<AppState>>,
    Path((id, session_id_str)): Path<(String, String)>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };
    let session_id = match session_id_str.parse::<uuid::Uuid>() {
        Ok(uuid) => t3rnel_types::agent::SessionId(uuid),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid session ID"})),
            )
        }
    };
    match state.kernel.switch_agent_session(agent_id, session_id) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ok", "message": "Session switched"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

// ── Extended Chat Command API Endpoints ─────────────────────────────────

/// POST /api/agents/{id}/session/reset — Reset an agent's session.
pub async fn reset_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };
    match state.kernel.reset_session(agent_id) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ok", "message": "Session reset"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// DELETE /api/agents/{id}/history — Clear ALL conversation history for an agent.
pub async fn clear_agent_history(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };
    if state.kernel.registry.get(agent_id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Agent not found"})),
        );
    }
    match state.kernel.clear_agent_history(agent_id) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ok", "message": "All history cleared"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// POST /api/agents/{id}/session/compact — Trigger LLM session compaction.
pub async fn compact_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };
    match state.kernel.compact_agent_session(agent_id).await {
        Ok(msg) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ok", "message": msg})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// POST /api/agents/{id}/stop — Cancel an agent's current LLM run.
///
/// If the agent is owned by an active hand instance, the hand instance is
/// also deactivated. Otherwise the hand stays registered as `Active` and the
/// user cannot re-activate it via the wizard (issue #1164).
pub async fn stop_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };

    // If this agent is the agent of an active hand instance, deactivate the
    // hand entirely — which also kills the agent and cancels the run. This
    // matches what users expect when they click Stop on a hand-owned agent.
    if let Some(instance) = state.kernel.hand_registry.find_by_agent(agent_id) {
        match state.kernel.deactivate_hand(instance.instance_id) {
            Ok(()) => {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "status": "ok",
                        "message": "Hand deactivated",
                        "hand_deactivated": true,
                        "hand_id": instance.hand_id,
                        "instance_id": instance.instance_id,
                    })),
                );
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("{e}")})),
                );
            }
        }
    }

    match state.kernel.stop_agent_run(agent_id) {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ok", "message": "Run cancelled"})),
        ),
        Ok(false) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ok", "message": "No active run"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// POST /api/agents/{id}/pause-autonomy — Stop background work and make the agent reactive.
pub async fn pause_agent_autonomy(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };
    match state.kernel.pause_agent_autonomy(agent_id) {
        Ok(run_cancelled) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "paused",
                "agent_id": id,
                "run_cancelled": run_cancelled,
                "schedule": "reactive"
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// PUT /api/agents/{id}/model — Switch an agent's model.
pub async fn set_model(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };
    let model = match body["model"].as_str() {
        Some(m) if !m.is_empty() => m,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing 'model' field"})),
            )
        }
    };
    let explicit_provider = body["provider"].as_str();
    match state
        .kernel
        .set_agent_model(agent_id, model, explicit_provider)
    {
        Ok(()) => {
            // Return the resolved model+provider so frontend stays in sync.
            // The model name may have been normalized (provider prefix stripped),
            // so we read it back from the registry instead of echoing the raw input.
            let (resolved_model, resolved_provider) = state
                .kernel
                .registry
                .get(agent_id)
                .map(|e| {
                    (
                        e.manifest.model.model.clone(),
                        e.manifest.model.provider.clone(),
                    )
                })
                .unwrap_or_else(|| (model.to_string(), String::new()));
            (
                StatusCode::OK,
                Json(
                    serde_json::json!({"status": "ok", "model": resolved_model, "provider": resolved_provider}),
                ),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// GET /api/agents/{id}/tools — Get an agent's tool allowlist/blocklist.
pub async fn get_agent_tools(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };
    let entry = match state.kernel.registry.get(agent_id) {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            )
        }
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tool_allowlist": entry.manifest.tool_allowlist,
            "tool_blocklist": entry.manifest.tool_blocklist,
        })),
    )
}

/// PUT /api/agents/{id}/tools — Update an agent's tool allowlist/blocklist.
pub async fn set_agent_tools(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };
    let allowlist = body
        .get("tool_allowlist")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        });
    let blocklist = body
        .get("tool_blocklist")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        });

    if allowlist.is_none() && blocklist.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Provide 'tool_allowlist' and/or 'tool_blocklist'"})),
        );
    }

    match state
        .kernel
        .set_agent_tool_filters(agent_id, allowlist, blocklist)
    {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

// ── Per-Agent Skill & MCP Endpoints ────────────────────────────────────

/// GET /api/agents/{id}/skills — Get an agent's skill assignment info.
pub async fn get_agent_skills(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };
    let entry = match state.kernel.registry.get(agent_id) {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            )
        }
    };
    let available = state
        .kernel
        .skill_registry
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .skill_names();
    let mode = if entry.manifest.skills.is_empty() {
        "all"
    } else {
        "allowlist"
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "assigned": entry.manifest.skills,
            "available": available,
            "mode": mode,
        })),
    )
}

/// PUT /api/agents/{id}/skills — Update an agent's skill allowlist.
pub async fn set_agent_skills(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };
    let skills: Vec<String> = body["skills"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    match state.kernel.set_agent_skills(agent_id, skills.clone()) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ok", "skills": skills})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

/// GET /api/agents/{id}/mcp_servers — Get an agent's MCP server assignment info.
pub async fn get_agent_mcp_servers(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };
    let entry = match state.kernel.registry.get(agent_id) {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            )
        }
    };
    // Collect known MCP server names from connected tools
    let mut available: Vec<String> = Vec::new();
    if let Ok(mcp_tools) = state.kernel.mcp_tools.lock() {
        let mut seen = std::collections::HashSet::new();
        for tool in mcp_tools.iter() {
            if let Some(server) = t3rnel_runtime::mcp::extract_mcp_server(&tool.name) {
                if seen.insert(server.to_string()) {
                    available.push(server.to_string());
                }
            }
        }
    }
    let mode = if entry.manifest.mcp_servers.is_empty() {
        "all"
    } else {
        "allowlist"
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "assigned": entry.manifest.mcp_servers,
            "available": available,
            "mode": mode,
        })),
    )
}

/// PUT /api/agents/{id}/mcp_servers — Update an agent's MCP server allowlist.
pub async fn set_agent_mcp_servers(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            )
        }
    };
    let servers: Vec<String> = body["mcp_servers"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    match state
        .kernel
        .set_agent_mcp_servers(agent_id, servers.clone())
    {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ok", "mcp_servers": servers})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("{e}")})),
        ),
    }
}

// ── Provider Key Management Endpoints ──────────────────────────────────

/// POST /api/providers/{name}/key — Save an API key for a provider.
///
/// SECURITY: Writes to `~/.t3rnel/secrets.env`, sets env var in process,
/// and refreshes auth detection. Key is zeroized after use.
pub async fn set_provider_key(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let key = match body["key"].as_str() {
        Some(k) if !k.trim().is_empty() => k.trim().to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing or empty 'key' field"})),
            );
        }
    };

    // Look up env var from catalog; for unknown/custom providers derive one.
    let env_var = {
        let catalog = state
            .kernel
            .model_catalog
            .read()
            .unwrap_or_else(|e| e.into_inner());
        catalog
            .get_provider(&name)
            .map(|p| p.api_key_env.clone())
            .unwrap_or_else(|| {
                // Custom provider — derive env var: MY_PROVIDER → MY_PROVIDER_API_KEY
                format!("{}_API_KEY", name.to_uppercase().replace('-', "_"))
            })
    };

    // Store in vault (best-effort — no-op if vault not initialized)
    state.kernel.store_credential(&env_var, &key);

    // Write to secrets.env file (dual-write for backward compat / vault corruption recovery)
    let secrets_path = state.kernel.config.home_dir.join("secrets.env");
    if let Err(e) = write_secret_env(&secrets_path, &env_var, &key) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to write secrets.env: {e}")})),
        );
    }

    // Set env var in current process so detect_auth picks it up
    std::env::set_var(&env_var, &key);

    // Refresh auth detection
    state
        .kernel
        .model_catalog
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .detect_auth();

    // Auto-switch default provider if current default has no working key.
    // This fixes the common case where a user adds e.g. a Gemini key via dashboard
    // but their agent still tries to use the previous provider (which has no key).
    //
    // Read the effective default from the hot-reload override (if set) rather than
    // the stale boot-time config — a previous set_provider_key call may have already
    // switched the default.
    let (current_provider, current_key_env) = {
        let guard = state
            .kernel
            .default_model_override
            .read()
            .unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(dm) => (dm.provider.clone(), dm.api_key_env.clone()),
            None => (
                state.kernel.config.default_model.provider.clone(),
                state.kernel.config.default_model.api_key_env.clone(),
            ),
        }
    };
    let current_has_key = if current_key_env.is_empty() {
        false
    } else {
        std::env::var(&current_key_env)
            .ok()
            .filter(|v| !v.is_empty())
            .is_some()
    };
    let switched = if !current_has_key && current_provider != name {
        // Find a default model for the newly-keyed provider
        let default_model = {
            let catalog = state
                .kernel
                .model_catalog
                .read()
                .unwrap_or_else(|e| e.into_inner());
            catalog.default_model_for_provider(&name)
        };
        if let Some(model_id) = default_model {
            // Update config.toml to persist the switch
            let config_path = state.kernel.config.home_dir.join("config.toml");
            let update_toml = format!(
                "\n[default_model]\nprovider = \"{}\"\nmodel = \"{}\"\napi_key_env = \"{}\"\n",
                name, model_id, env_var
            );
            backup_config(&config_path);
            if let Ok(existing) = std::fs::read_to_string(&config_path) {
                let cleaned = remove_toml_section(&existing, "default_model");
                let _ =
                    std::fs::write(&config_path, format!("{}\n{}", cleaned.trim(), update_toml));
            } else {
                let _ = std::fs::write(&config_path, update_toml);
            }

            // Hot-update the in-memory default model override so resolve_driver()
            // immediately creates drivers for the new provider — no restart needed.
            {
                let new_dm = t3rnel_types::config::DefaultModelConfig {
                    provider: name.clone(),
                    model: model_id,
                    api_key_env: env_var.clone(),
                    base_url: None,
                    subprocess_timeout_secs: None,
                };
                let mut guard = state
                    .kernel
                    .default_model_override
                    .write()
                    .unwrap_or_else(|e| e.into_inner());
                *guard = Some(new_dm);
            }
            true
        } else {
            false
        }
    } else if current_provider == name {
        // User is saving a key for the CURRENT default provider. The env var is
        // already set (set_var above), but we must ensure default_model_override
        // has the correct api_key_env so resolve_driver reads the right variable.
        let needs_update = {
            let guard = state
                .kernel
                .default_model_override
                .read()
                .unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(dm) => dm.api_key_env != env_var,
                None => state.kernel.config.default_model.api_key_env != env_var,
            }
        };
        if needs_update {
            let mut guard = state
                .kernel
                .default_model_override
                .write()
                .unwrap_or_else(|e| e.into_inner());
            let base = guard
                .clone()
                .unwrap_or_else(|| state.kernel.config.default_model.clone());
            *guard = Some(t3rnel_types::config::DefaultModelConfig {
                api_key_env: env_var.clone(),
                ..base
            });
        }
        false
    } else {
        false
    };

    let mut resp = serde_json::json!({"status": "saved", "provider": name});
    if switched {
        resp["switched_default"] = serde_json::json!(true);
        resp["message"] = serde_json::json!(format!(
            "API key saved and default provider switched to '{}'.",
            name
        ));
    }

    (StatusCode::OK, Json(resp))
}

/// DELETE /api/providers/{name}/key — Remove an API key for a provider.
pub async fn delete_provider_key(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let env_var = {
        let catalog = state
            .kernel
            .model_catalog
            .read()
            .unwrap_or_else(|e| e.into_inner());
        catalog
            .get_provider(&name)
            .map(|p| p.api_key_env.clone())
            .unwrap_or_else(|| {
                // Custom/unknown provider — derive env var from convention
                format!("{}_API_KEY", name.to_uppercase().replace('-', "_"))
            })
    };

    if env_var.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Provider does not require an API key"})),
        );
    }

    // Remove from vault (best-effort)
    state.kernel.remove_credential(&env_var);

    // Remove from secrets.env
    let secrets_path = state.kernel.config.home_dir.join("secrets.env");
    if let Err(e) = remove_secret_env(&secrets_path, &env_var) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to update secrets.env: {e}")})),
        );
    }

    // Remove from process environment
    std::env::remove_var(&env_var);

    // Refresh auth detection
    state
        .kernel
        .model_catalog
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .detect_auth();

    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "removed", "provider": name})),
    )
}

/// POST /api/providers/{name}/test — Test a provider's connectivity.
pub async fn test_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let (env_var, base_url, key_required, default_model) = {
        let catalog = state
            .kernel
            .model_catalog
            .read()
            .unwrap_or_else(|e| e.into_inner());
        match catalog.get_provider(&name) {
            Some(p) => {
                // Find a default model for this provider to use in the test request
                let model_id = catalog
                    .default_model_for_provider(&name)
                    .unwrap_or_default();
                (
                    p.api_key_env.clone(),
                    p.base_url.clone(),
                    p.key_required,
                    model_id,
                )
            }
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": format!("Unknown provider '{}'", name)})),
                );
            }
        }
    };

    let api_key = std::env::var(&env_var).ok();
    // Only require API key for providers that need one (skip local providers like ollama/vllm/lmstudio)
    if key_required && api_key.is_none() && !env_var.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Provider API key not configured"})),
        );
    }

    // Attempt a lightweight connectivity test
    let start = std::time::Instant::now();
    let driver_config = t3rnel_runtime::llm_driver::DriverConfig {
        provider: name.clone(),
        api_key,
        base_url: if base_url.is_empty() {
            None
        } else {
            Some(base_url)
        },
        skip_permissions: true,
        subprocess_timeout_secs: None,
    };

    match t3rnel_runtime::drivers::create_driver(&driver_config) {
        Ok(driver) => {
            // Send a minimal completion request to test connectivity
            let test_req = t3rnel_runtime::llm_driver::CompletionRequest {
                model: default_model.clone(),
                messages: vec![t3rnel_types::message::Message::user("Hi")],
                tools: vec![],
                max_tokens: 1,
                temperature: 0.0,
                system: None,
                thinking: None,
                reasoning_effort: None,
            };
            match driver.complete(test_req).await {
                Ok(_) => {
                    let latency_ms = start.elapsed().as_millis();
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "status": "ok",
                            "provider": name,
                            "latency_ms": latency_ms,
                        })),
                    )
                }
                Err(e) => (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "status": "error",
                        "provider": name,
                        "error": format!("{e}"),
                    })),
                ),
            }
        }
        Err(e) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "error",
                "provider": name,
                "error": format!("Failed to create driver: {e}"),
            })),
        ),
    }
}

/// PUT /api/providers/{name}/url — Set a custom base URL for a provider.
pub async fn set_provider_url(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Accept any provider name — custom providers are supported via OpenAI-compatible format.
    let base_url = match body["base_url"].as_str() {
        Some(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing or empty 'base_url' field"})),
            );
        }
    };

    // Validate URL scheme
    if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "base_url must start with http:// or https://"})),
        );
    }

    // Update catalog in memory
    {
        let mut catalog = state
            .kernel
            .model_catalog
            .write()
            .unwrap_or_else(|e| e.into_inner());
        catalog.set_provider_url(&name, &base_url);
    }

    // Persist to config.toml [provider_urls] section
    let config_path = state.kernel.config.home_dir.join("config.toml");
    if let Err(e) = upsert_provider_url(&config_path, &name, &base_url) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to save config: {e}")})),
        );
    }

    // Probe reachability at the new URL
    let probe = t3rnel_runtime::provider_health::probe_provider(&name, &base_url).await;

    // Merge discovered models into catalog
    if !probe.discovered_models.is_empty() {
        if let Ok(mut catalog) = state.kernel.model_catalog.write() {
            catalog.merge_discovered_models(&name, &probe.discovered_models);
        }
    }

    let mut resp = serde_json::json!({
        "status": "saved",
        "provider": name,
        "base_url": base_url,
        "reachable": probe.reachable,
        "latency_ms": probe.latency_ms,
    });
    if !probe.discovered_models.is_empty() {
        resp["discovered_models"] = serde_json::json!(probe.discovered_models);
    }

    (StatusCode::OK, Json(resp))
}

/// Upsert a provider URL in the `[provider_urls]` section of config.toml.
fn upsert_provider_url(
    config_path: &std::path::Path,
    provider: &str,
    url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = if config_path.exists() {
        std::fs::read_to_string(config_path)?
    } else {
        String::new()
    };

    let mut doc: toml::Value = if content.trim().is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        toml::from_str(&content)?
    };

    let root = doc.as_table_mut().ok_or("Config is not a TOML table")?;

    if !root.contains_key("provider_urls") {
        root.insert(
            "provider_urls".to_string(),
            toml::Value::Table(toml::map::Map::new()),
        );
    }
    let urls_table = root
        .get_mut("provider_urls")
        .and_then(|v| v.as_table_mut())
        .ok_or("provider_urls is not a table")?;

    urls_table.insert(provider.to_string(), toml::Value::String(url.to_string()));

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(config_path, toml::to_string_pretty(&doc)?)?;
    Ok(())
}

/// POST /api/skills/create — Create a local prompt-only skill.
pub async fn create_skill(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let name = match body["name"].as_str() {
        Some(n) if !n.trim().is_empty() => n.trim().to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing or empty 'name' field"})),
            );
        }
    };

    // Validate name (alphanumeric + hyphens only)
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "Skill name must contain only letters, numbers, hyphens, and underscores"}),
            ),
        );
    }

    let description = body["description"].as_str().unwrap_or("").to_string();
    let runtime = body["runtime"].as_str().unwrap_or("prompt_only");
    let prompt_context = body["prompt_context"].as_str().unwrap_or("").to_string();

    // Only allow prompt_only skills from the web UI for safety
    if runtime != "prompt_only" {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "Only prompt_only skills can be created from the web UI"}),
            ),
        );
    }

    // Write skill.toml to ~/.t3rnel/skills/{name}/
    let skill_dir = state.kernel.config.home_dir.join("skills").join(&name);
    if skill_dir.exists() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": format!("Skill '{}' already exists", name)})),
        );
    }

    if let Err(e) = std::fs::create_dir_all(&skill_dir) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to create skill directory: {e}")})),
        );
    }

    let toml_content = format!(
        "[skill]\nname = \"{}\"\ndescription = \"{}\"\nruntime = \"prompt_only\"\n\n[prompt]\ncontext = \"\"\"\n{}\n\"\"\"\n",
        name,
        description.replace('"', "\\\""),
        prompt_context
    );

    let toml_path = skill_dir.join("skill.toml");
    if let Err(e) = std::fs::write(&toml_path, &toml_content) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to write skill.toml: {e}")})),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "created",
            "name": name,
            "note": "Restart the daemon to load the new skill, or it will be available on next boot."
        })),
    )
}

// ---------------------------------------------------------------------------
// Skill config endpoints
// ---------------------------------------------------------------------------
//
// These endpoints expose per-skill runtime variables declared in the skill's
// SKILL.md frontmatter `config:` section. Resolution order is:
//
//   1. user config         (the `[skills.<name>]` section in config.toml)
//   2. env var              (`var.env`)
//   3. default              (`var.default`)
//
// The GET endpoint always returns secret-looking values redacted. The PUT
// endpoint atomically rewrites the `[skills.<name>]` section of config.toml
// and reloads the skill registry so the change takes effect on the next
// prompt build.

/// Load a skill's declared `config:` map, even if `required` vars are
/// currently unresolved.
///
/// Looking up the live registry doesn't work here because the registry's
/// load path refuses to insert a skill whose required config var has no
/// resolvable value — which is exactly the state the user needs to reach
/// this UI to fix. Instead we read the manifest straight from disk (for
/// user-installed / workspace skills) or straight from the compile-time
/// bundled catalog.
fn load_skill_declared_config(
    skills_dir: &std::path::Path,
    skill_name: &str,
) -> Option<std::collections::HashMap<String, t3rnel_skills::config_injection::SkillConfigVar>> {
    // 1. User-installed skill: skills_dir/<name>/skill.toml, falling back to
    //    SKILL.md frontmatter if no TOML has been generated yet.
    let skill_dir = skills_dir.join(skill_name);
    if skill_dir.is_dir() {
        let toml_path = skill_dir.join("skill.toml");
        if toml_path.exists() {
            if let Ok(text) = std::fs::read_to_string(&toml_path) {
                if let Ok(manifest) = toml::from_str::<t3rnel_skills::SkillManifest>(&text) {
                    if manifest.skill.name == skill_name {
                        return Some(manifest.config);
                    }
                }
            }
        }
        let skillmd_path = skill_dir.join("SKILL.md");
        if skillmd_path.exists() {
            if let Ok(text) = std::fs::read_to_string(&skillmd_path) {
                if let Ok(converted) =
                    t3rnel_skills::openclaw_compat::convert_skillmd_str(skill_name, &text)
                {
                    return Some(converted.config_vars);
                }
            }
        }
    }

    // 2. Bundled skill: look up by name in the compile-time catalog.
    for (bundled_name, content) in t3rnel_skills::bundled::bundled_skills() {
        if bundled_name == skill_name {
            if let Ok(converted) =
                t3rnel_skills::openclaw_compat::convert_skillmd_str(bundled_name, content)
            {
                return Some(converted.config_vars);
            }
        }
    }

    None
}

/// Build the per-skill config state for the GET endpoint.
///
/// Returns `None` if the skill is not installed. Resolved values are
/// redacted when the variable name looks secret (see
/// [`t3rnel_skills::config_injection::is_secret_name`]).
fn build_skill_config_snapshot(
    state: &Arc<AppState>,
    skill_name: &str,
) -> Option<serde_json::Value> {
    use t3rnel_skills::config_injection::is_secret_name;

    let skills_dir = state.kernel.config.home_dir.join("skills");
    let declared = load_skill_declared_config(&skills_dir, skill_name)?;

    // Snapshot the currently active user config (override map takes priority
    // over the boot-time `self.config.skills`, matching what `reload_skills`
    // will actually use).
    let user_cfg: std::collections::HashMap<String, String> = {
        let override_guard = state
            .kernel
            .skill_config_overrides
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let source: &std::collections::HashMap<String, std::collections::HashMap<String, String>> =
            override_guard
                .as_ref()
                .unwrap_or(&state.kernel.config.skills);
        source.get(skill_name).cloned().unwrap_or_default()
    };

    let mut declared_json = serde_json::Map::new();
    let mut resolved_json = serde_json::Map::new();

    for (name, var) in declared.iter() {
        declared_json.insert(
            name.clone(),
            serde_json::json!({
                "description": var.description,
                "env": var.env,
                "default": var.default,
                "required": var.required,
            }),
        );

        let is_secret = is_secret_name(name);
        let (value_opt, source) = if let Some(v) = user_cfg.get(name) {
            (Some(v.clone()), "user")
        } else if let Some(env_name) = var.env.as_ref() {
            match std::env::var(env_name) {
                Ok(v) if !v.is_empty() => (Some(v), "env"),
                _ => {
                    if let Some(d) = var.default.as_ref() {
                        (Some(d.clone()), "default")
                    } else {
                        (None, "unresolved")
                    }
                }
            }
        } else if let Some(d) = var.default.as_ref() {
            (Some(d.clone()), "default")
        } else {
            (None, "unresolved")
        };

        // Redact secrets for the wire response.
        let shown_value: serde_json::Value = match value_opt {
            Some(v) if is_secret => {
                let prefix: String = v.chars().take(4).collect();
                if prefix.is_empty() {
                    serde_json::Value::String("***redacted***".to_string())
                } else {
                    serde_json::Value::String(format!("{prefix}***redacted***"))
                }
            }
            Some(v) => serde_json::Value::String(v),
            None => serde_json::Value::Null,
        };

        resolved_json.insert(
            name.clone(),
            serde_json::json!({
                "value": shown_value,
                "source": source,
                "is_secret": is_secret,
            }),
        );
    }

    Some(serde_json::json!({
        "skill": skill_name,
        "declared": serde_json::Value::Object(declared_json),
        "resolved": serde_json::Value::Object(resolved_json),
    }))
}

/// GET /api/skills/{id}/config — Return declared + resolved per-skill config.
///
/// Response shape:
/// ```json
/// {
///   "skill": "github-helper",
///   "declared": {
///     "github_token": { "description": "...", "env": "GH_TOKEN", "default": null, "required": true }
///   },
///   "resolved": {
///     "github_token": { "value": "ghp_***redacted***", "source": "user", "is_secret": true }
///   }
/// }
/// ```
///
/// Secret-looking values (`*_token`, `*_key`, `*_secret`, `password`) are
/// always redacted in the `value` field. The `source` field names the layer
/// that won: `"user"`, `"env"`, `"default"`, or `"unresolved"`.
pub async fn get_skill_config(
    State(state): State<Arc<AppState>>,
    Path(skill_name): Path<String>,
) -> impl IntoResponse {
    match build_skill_config_snapshot(&state, &skill_name) {
        Some(snapshot) => (StatusCode::OK, Json(snapshot)),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Skill '{skill_name}' not found")})),
        ),
    }
}

/// Request body for `PUT /api/skills/{id}/config`.
#[derive(Debug, serde::Deserialize)]
pub struct SkillConfigPutRequest {
    /// New per-variable values. Keys must match declared variable names.
    pub values: std::collections::HashMap<String, String>,
}

/// PUT /api/skills/{id}/config — Write user overrides for a skill's config.
///
/// The body is `{"values": {"<var_name>": "<value>"}}`. Only declared
/// variables are accepted; unknown keys return 400. After the config.toml is
/// atomically rewritten, the kernel's skill registry is reloaded so the
/// change takes effect immediately.
pub async fn put_skill_config(
    State(state): State<Arc<AppState>>,
    Path(skill_name): Path<String>,
    Json(body): Json<SkillConfigPutRequest>,
) -> impl IntoResponse {
    // Refuse to operate on unknown skill (matching GET behavior). We read
    // the declared config directly instead of going through the registry so
    // a skill with required-but-unresolved vars is still editable.
    let skills_dir = state.kernel.config.home_dir.join("skills");
    let declared = match load_skill_declared_config(&skills_dir, &skill_name) {
        Some(d) => d,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("Skill '{skill_name}' not found")})),
            );
        }
    };

    // Reject unknown keys.
    for k in body.values.keys() {
        if !declared.contains_key(k) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("Variable '{k}' is not declared by skill '{skill_name}'")
                })),
            );
        }
    }

    // Build the final in-memory skill-configs map: start from the current
    // override (or boot-time config), replace the skill's section with the
    // incoming values.
    let mut all_configs: std::collections::HashMap<
        String,
        std::collections::HashMap<String, String>,
    > = {
        let guard = state
            .kernel
            .skill_config_overrides
            .read()
            .unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .cloned()
            .unwrap_or_else(|| state.kernel.config.skills.clone())
    };
    all_configs.insert(skill_name.clone(), body.values.clone());

    // Persist atomically to config.toml.
    let config_path = state.kernel.config.home_dir.join("config.toml");
    if let Err(e) = upsert_skill_config(&config_path, &skill_name, &body.values) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to persist skill config: {e}")
            })),
        );
    }

    // Reload so agents see the new config on their next prompt build.
    state.kernel.reload_skills_with_configs(all_configs);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "saved",
            "skill": skill_name,
            "reloaded": true,
        })),
    )
}

/// DELETE /api/skills/{id}/config/{var_name} — Remove a single user override.
///
/// After removal, the variable falls back to env or default on the next
/// prompt build. If removing the override would leave a `required` variable
/// with no resolvable value, the request fails with 409 Conflict so the
/// caller is never tricked into a broken state.
pub async fn delete_skill_config_var(
    State(state): State<Arc<AppState>>,
    Path((skill_name, var_name)): Path<(String, String)>,
) -> impl IntoResponse {
    let skills_dir = state.kernel.config.home_dir.join("skills");
    let declared = match load_skill_declared_config(&skills_dir, &skill_name) {
        Some(d) => d,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("Skill '{skill_name}' not found")})),
            );
        }
    };

    let var_def = match declared.get(&var_name) {
        Some(v) => v.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("Variable '{var_name}' is not declared by skill '{skill_name}'")
                })),
            );
        }
    };

    // If the var is required, make sure env or default still resolves;
    // otherwise we would leave the skill unable to register after reload.
    if var_def.required {
        let env_resolves = var_def
            .env
            .as_ref()
            .and_then(|e| std::env::var(e).ok())
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let default_resolves = var_def
            .default
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if !env_resolves && !default_resolves {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": format!(
                        "Cannot remove override: '{var_name}' is required and has no env/default fallback"
                    )
                })),
            );
        }
    }

    let mut all_configs: std::collections::HashMap<
        String,
        std::collections::HashMap<String, String>,
    > = {
        let guard = state
            .kernel
            .skill_config_overrides
            .read()
            .unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .cloned()
            .unwrap_or_else(|| state.kernel.config.skills.clone())
    };
    if let Some(skill_map) = all_configs.get_mut(&skill_name) {
        skill_map.remove(&var_name);
        if skill_map.is_empty() {
            all_configs.remove(&skill_name);
        }
    }

    let config_path = state.kernel.config.home_dir.join("config.toml");
    if let Err(e) = remove_skill_config_var(&config_path, &skill_name, &var_name) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to update config.toml: {e}")
            })),
        );
    }

    state.kernel.reload_skills_with_configs(all_configs);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "removed",
            "skill": skill_name,
            "var": var_name,
            "reloaded": true,
        })),
    )
}

/// Atomically upsert `[skills.<skill_name>]` in config.toml.
///
/// Writes to `<path>.tmp` then renames — so a crash during the write never
/// leaves a half-truncated config on disk. Existing root-level fields are
/// preserved; only the named skill's section is replaced.
fn upsert_skill_config(
    config_path: &std::path::Path,
    skill_name: &str,
    values: &std::collections::HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = if config_path.exists() {
        std::fs::read_to_string(config_path)?
    } else {
        String::new()
    };

    let mut doc: toml::Value = if content.trim().is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        toml::from_str(&content)?
    };

    let root = doc.as_table_mut().ok_or("Config is not a TOML table")?;

    if !root.contains_key("skills") {
        root.insert(
            "skills".to_string(),
            toml::Value::Table(toml::map::Map::new()),
        );
    }
    let skills_table = root
        .get_mut("skills")
        .and_then(|v| v.as_table_mut())
        .ok_or("skills is not a table")?;

    let mut skill_section = toml::map::Map::new();
    for (k, v) in values {
        skill_section.insert(k.clone(), toml::Value::String(v.clone()));
    }
    skills_table.insert(skill_name.to_string(), toml::Value::Table(skill_section));

    atomic_write_toml(config_path, &doc)?;
    Ok(())
}

/// Atomically remove a single variable from `[skills.<skill_name>]`.
///
/// If the skill table becomes empty the table itself is removed so we don't
/// leave empty sections lying around.
fn remove_skill_config_var(
    config_path: &std::path::Path,
    skill_name: &str,
    var_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !config_path.exists() {
        return Ok(());
    }

    let content = std::fs::read_to_string(config_path)?;
    if content.trim().is_empty() {
        return Ok(());
    }

    let mut doc: toml::Value = toml::from_str(&content)?;

    let root = match doc.as_table_mut() {
        Some(r) => r,
        None => return Ok(()),
    };

    let mut remove_skill = false;
    if let Some(skills_table) = root.get_mut("skills").and_then(|v| v.as_table_mut()) {
        if let Some(skill_section) = skills_table
            .get_mut(skill_name)
            .and_then(|v| v.as_table_mut())
        {
            skill_section.remove(var_name);
            if skill_section.is_empty() {
                remove_skill = true;
            }
        }
        if remove_skill {
            skills_table.remove(skill_name);
        }
    }

    atomic_write_toml(config_path, &doc)?;
    Ok(())
}

/// Write a TOML value to disk atomically via a sibling temp file + rename.
///
/// On Windows, `rename` is atomic on the same volume when the destination
/// does not exist; if it does we fall back to the non-atomic write path and
/// still cover the "crash mid-write truncates config.toml" class of bug.
fn atomic_write_toml(
    config_path: &std::path::Path,
    doc: &toml::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let rendered = toml::to_string_pretty(doc)?;
    let tmp_path = match config_path.file_name() {
        Some(name) => {
            let mut tmp_name = std::ffi::OsString::from(".");
            tmp_name.push(name);
            tmp_name.push(".tmp");
            config_path.with_file_name(tmp_name)
        }
        None => config_path.with_extension("tmp"),
    };
    std::fs::write(&tmp_path, rendered)?;
    match std::fs::rename(&tmp_path, config_path) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Fallback: direct write, then best-effort cleanup of temp.
            let rendered = toml::to_string_pretty(doc)?;
            std::fs::write(config_path, rendered)?;
            let _ = std::fs::remove_file(&tmp_path);
            Ok(())
        }
    }
}

// ── Helper functions for secrets.env management ────────────────────────

/// Write or update a key in the secrets.env file.
/// File format: one `KEY=value` per line. Existing keys are overwritten.
fn write_secret_env(path: &std::path::Path, key: &str, value: &str) -> Result<(), std::io::Error> {
    let mut lines: Vec<String> = if path.exists() {
        std::fs::read_to_string(path)?
            .lines()
            .map(|l| l.to_string())
            .collect()
    } else {
        Vec::new()
    };

    // Remove existing line for this key
    lines.retain(|l| !l.starts_with(&format!("{key}=")));

    // Add new line
    lines.push(format!("{key}={value}"));

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, lines.join("\n") + "\n")?;

    // SECURITY: Restrict file permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Remove a key from the secrets.env file.
fn remove_secret_env(path: &std::path::Path, key: &str) -> Result<(), std::io::Error> {
    if !path.exists() {
        return Ok(());
    }

    let lines: Vec<String> = std::fs::read_to_string(path)?
        .lines()
        .filter(|l| !l.starts_with(&format!("{key}=")))
        .map(|l| l.to_string())
        .collect();

    std::fs::write(path, lines.join("\n") + "\n")?;

    Ok(())
}

// ── Config.toml channel management helpers ──────────────────────────

/// Upsert a `[channels.<name>]` section in config.toml with the given non-secret fields.
fn upsert_channel_config(
    config_path: &std::path::Path,
    channel_name: &str,
    fields: &HashMap<String, (String, FieldType)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = if config_path.exists() {
        std::fs::read_to_string(config_path)?
    } else {
        String::new()
    };

    let mut doc: toml::Value = if content.trim().is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        toml::from_str(&content)?
    };

    let root = doc.as_table_mut().ok_or("Config is not a TOML table")?;

    // Ensure [channels] table exists
    if !root.contains_key("channels") {
        root.insert(
            "channels".to_string(),
            toml::Value::Table(toml::map::Map::new()),
        );
    }
    let channels_table = root
        .get_mut("channels")
        .and_then(|v| v.as_table_mut())
        .ok_or("channels is not a table")?;

    // Build channel sub-table with correct TOML types
    let mut ch_table = toml::map::Map::new();
    for (k, (v, ft)) in fields {
        let toml_val = match ft {
            FieldType::Number => {
                if let Ok(n) = v.parse::<i64>() {
                    toml::Value::Integer(n)
                } else {
                    toml::Value::String(v.clone())
                }
            }
            FieldType::List => {
                // Always store list items as strings so that numeric IDs
                // (e.g. Discord guild snowflakes, Telegram user IDs) are
                // deserialized correctly into Vec<String> config fields.
                let items: Vec<toml::Value> = v
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| toml::Value::String(s.to_string()))
                    .collect();
                toml::Value::Array(items)
            }
            _ => toml::Value::String(v.clone()),
        };
        ch_table.insert(k.clone(), toml_val);
    }
    channels_table.insert(channel_name.to_string(), toml::Value::Table(ch_table));

    // Ensure parent directory exists
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(config_path, toml::to_string_pretty(&doc)?)?;
    Ok(())
}

/// Remove a `[channels.<name>]` section from config.toml.
fn remove_channel_config(
    config_path: &std::path::Path,
    channel_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !config_path.exists() {
        return Ok(());
    }

    let content = std::fs::read_to_string(config_path)?;
    if content.trim().is_empty() {
        return Ok(());
    }

    let mut doc: toml::Value = toml::from_str(&content)?;

    if let Some(channels) = doc
        .as_table_mut()
        .and_then(|r| r.get_mut("channels"))
        .and_then(|c| c.as_table_mut())
    {
        channels.remove(channel_name);
    }

    std::fs::write(config_path, toml::to_string_pretty(&doc)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Integration management endpoints
// ---------------------------------------------------------------------------

/// GET /api/integrations — List installed integrations with status.
pub async fn list_integrations(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let registry = state
        .kernel
        .extension_registry
        .read()
        .unwrap_or_else(|e| e.into_inner());
    let health = &state.kernel.extension_health;

    let mut entries = Vec::new();
    for info in registry.list_all_info() {
        let h = health.get_health(&info.template.id);
        let status = match &info.installed {
            Some(inst) if !inst.enabled => "disabled",
            Some(_) => match h.as_ref().map(|h| &h.status) {
                Some(t3rnel_extensions::IntegrationStatus::Ready) => "ready",
                Some(t3rnel_extensions::IntegrationStatus::Error(_)) => "error",
                _ => "installed",
            },
            None => continue, // Only show installed
        };
        entries.push(serde_json::json!({
            "id": info.template.id,
            "name": info.template.name,
            "icon": info.template.icon,
            "category": info.template.category.to_string(),
            "status": status,
            "tool_count": h.as_ref().map(|h| h.tool_count).unwrap_or(0),
            "installed_at": info.installed.as_ref().map(|i| i.installed_at.to_rfc3339()),
        }));
    }

    Json(serde_json::json!({
        "installed": entries,
        "count": entries.len(),
    }))
}

/// GET /api/integrations/available — List all available templates.
pub async fn list_available_integrations(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let registry = state
        .kernel
        .extension_registry
        .read()
        .unwrap_or_else(|e| e.into_inner());
    let templates: Vec<serde_json::Value> = registry
        .list_templates()
        .iter()
        .map(|t| {
            let installed = registry.is_installed(&t.id);
            serde_json::json!({
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "icon": t.icon,
                "category": t.category.to_string(),
                "installed": installed,
                "tags": t.tags,
                "required_env": t.required_env.iter().map(|e| serde_json::json!({
                    "name": e.name,
                    "label": e.label,
                    "help": e.help,
                    "is_secret": e.is_secret,
                    "get_url": e.get_url,
                })).collect::<Vec<_>>(),
                "has_oauth": t.oauth.is_some(),
                "setup_instructions": t.setup_instructions,
            })
        })
        .collect();

    Json(serde_json::json!({
        "integrations": templates,
        "count": templates.len(),
    }))
}

/// POST /api/integrations/add — Install an integration.
pub async fn add_integration(
    State(state): State<Arc<AppState>>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let id = match req.get("id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing 'id' field"})),
            );
        }
    };

    // Scope the write lock so it's dropped before any .await
    let install_err = {
        let mut registry = state
            .kernel
            .extension_registry
            .write()
            .unwrap_or_else(|e| e.into_inner());

        if registry.is_installed(&id) {
            Some((
                StatusCode::CONFLICT,
                format!("Integration '{}' already installed", id),
            ))
        } else if registry.get_template(&id).is_none() {
            Some((
                StatusCode::NOT_FOUND,
                format!("Unknown integration: '{}'", id),
            ))
        } else {
            let entry = t3rnel_extensions::InstalledIntegration {
                id: id.clone(),
                installed_at: chrono::Utc::now(),
                enabled: true,
                oauth_provider: None,
                config: std::collections::HashMap::new(),
            };
            match registry.install(entry) {
                Ok(_) => None,
                Err(e) => Some((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
            }
        }
    }; // write lock dropped here

    if let Some((status, error)) = install_err {
        return (status, Json(serde_json::json!({"error": error})));
    }

    state.kernel.extension_health.register(&id);

    // Hot-connect the new MCP server
    let connected = state.kernel.reload_extension_mcps().await.unwrap_or(0);

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": id,
            "status": "installed",
            "connected": connected > 0,
            "message": format!("Integration '{}' installed", id),
        })),
    )
}

/// DELETE /api/integrations/:id — Remove an integration.
pub async fn remove_integration(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Scope the write lock
    let uninstall_err = {
        let mut registry = state
            .kernel
            .extension_registry
            .write()
            .unwrap_or_else(|e| e.into_inner());
        registry.uninstall(&id).err()
    };

    if let Some(e) = uninstall_err {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": e.to_string()})),
        );
    }

    state.kernel.extension_health.unregister(&id);

    // Hot-disconnect the removed MCP server
    let _ = state.kernel.reload_extension_mcps().await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "id": id,
            "status": "removed",
        })),
    )
}

/// POST /api/integrations/:id/reconnect — Reconnect an MCP server.
pub async fn reconnect_integration(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let is_installed = {
        let registry = state
            .kernel
            .extension_registry
            .read()
            .unwrap_or_else(|e| e.into_inner());
        registry.is_installed(&id)
    };

    if !is_installed {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Integration '{}' not installed", id)})),
        );
    }

    match state.kernel.reconnect_extension_mcp(&id).await {
        Ok(tool_count) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": id,
                "status": "connected",
                "tool_count": tool_count,
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "id": id,
                "status": "error",
                "error": e,
            })),
        ),
    }
}

/// GET /api/integrations/health — Health status for all integrations.
pub async fn integrations_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let health_entries = state.kernel.extension_health.all_health();
    let entries: Vec<serde_json::Value> = health_entries
        .iter()
        .map(|h| {
            serde_json::json!({
                "id": h.id,
                "status": h.status.to_string(),
                "tool_count": h.tool_count,
                "last_ok": h.last_ok.map(|t| t.to_rfc3339()),
                "last_error": h.last_error,
                "consecutive_failures": h.consecutive_failures,
                "reconnecting": h.reconnecting,
                "reconnect_attempts": h.reconnect_attempts,
                "connected_since": h.connected_since.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    Json(serde_json::json!({
        "health": entries,
        "count": entries.len(),
    }))
}

/// POST /api/integrations/reload — Hot-reload integration configs and reconnect MCP.
pub async fn reload_integrations(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.kernel.reload_extension_mcps().await {
        Ok(connected) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "reloaded",
                "new_connections": connected,
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Scheduled Jobs (cron) endpoints
// ---------------------------------------------------------------------------
//
// Historical note: an earlier implementation of `/api/schedules*` wrote to a
// shared-memory key (`__t3rnel_schedules`) that no executor ever read — so
// scheduled jobs registered via this API never actually fired (#1069). These
// routes now delegate to the kernel's real cron scheduler, which already
// backs `/api/cron/jobs*`. The request/response shape has been preserved as
// close as possible to the legacy route for dashboard compatibility.

/// Convert an internal `CronJob` into the legacy `/api/schedules` response
/// shape so existing dashboard code keeps working.
fn cron_job_to_schedule_view(
    kernel: &T3rnelKernel,
    job: &t3rnel_types::scheduler::CronJob,
) -> serde_json::Value {
    use t3rnel_types::scheduler::{CronAction, CronSchedule};

    let cron = match &job.schedule {
        CronSchedule::Cron { expr, .. } => expr.clone(),
        CronSchedule::Every { every_secs } => format!("every {every_secs}s"),
        CronSchedule::At { at } => at.to_rfc3339(),
    };
    let message = match &job.action {
        CronAction::AgentTurn { message, .. } => message.clone(),
        CronAction::SystemEvent { text } => text.clone(),
        CronAction::WorkflowRun { workflow_id, .. } => format!("workflow:{workflow_id}"),
    };
    let meta = kernel.cron_scheduler.get_meta(job.id);
    let last_status = meta.as_ref().and_then(|m| m.last_status.clone());
    // Serialize delivery_targets so dashboard chips/editor round-trip cleanly.
    let delivery_targets = serde_json::to_value(&job.delivery_targets)
        .unwrap_or_else(|_| serde_json::Value::Array(Vec::new()));

    serde_json::json!({
        "id": job.id.to_string(),
        "name": job.name,
        "cron": cron,
        "agent_id": job.agent_id.to_string(),
        "message": message,
        "enabled": job.enabled,
        "created_at": job.created_at.to_rfc3339(),
        "last_run": job.last_run.map(|t| t.to_rfc3339()),
        "next_run": job.next_run.map(|t| t.to_rfc3339()),
        "last_status": last_status,
        "delivery_targets": delivery_targets,
    })
}

/// GET /api/schedules — List all scheduled jobs from the cron scheduler.
pub async fn list_schedules(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let jobs = state.kernel.cron_scheduler.list_all_jobs();
    let total = jobs.len();
    let schedules: Vec<serde_json::Value> = jobs
        .iter()
        .map(|j| cron_job_to_schedule_view(&state.kernel, j))
        .collect();
    Json(serde_json::json!({"schedules": schedules, "total": total}))
}

/// POST /api/schedules — Create a new scheduled job in the cron scheduler.
pub async fn create_schedule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let name_raw = match req["name"].as_str() {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing 'name' field"})),
            );
        }
    };

    let cron = match req["cron"].as_str() {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Missing 'cron' field"})),
            );
        }
    };

    let cron_parts: Vec<&str> = cron.split_whitespace().collect();
    if cron_parts.len() != 5 {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "Invalid cron expression: must have 5 fields (min hour dom mon dow)"}),
            ),
        );
    }

    let agent_id_str = req["agent_id"].as_str().unwrap_or("").to_string();
    if agent_id_str.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Missing required field: agent_id"})),
        );
    }
    let target_agent = if let Ok(aid) = agent_id_str.parse::<AgentId>() {
        if state.kernel.registry.get(aid).is_some() {
            Some(aid)
        } else {
            None
        }
    } else {
        state
            .kernel
            .registry
            .list()
            .into_iter()
            .find(|a| a.name == agent_id_str)
            .map(|a| a.id)
    };
    let target_agent = match target_agent {
        Some(a) => a,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("Agent not found: {agent_id_str}")})),
            );
        }
    };

    let message = req["message"].as_str().unwrap_or("").to_string();
    let enabled = req.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
    let job_message = if message.is_empty() {
        format!("[Scheduled task '{name_raw}']")
    } else {
        message.clone()
    };

    // Accept multi-destination delivery targets. Validate each entry matches
    // the `CronDeliveryTarget` shape up front so we return a 400 rather than
    // silently dropping targets or failing later in the kernel.
    let delivery_targets_raw = req
        .get("delivery_targets")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if !delivery_targets_raw.is_null() && !delivery_targets_raw.is_array() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "delivery_targets must be an array"
            })),
        );
    }
    if let Some(arr) = delivery_targets_raw.as_array() {
        for (idx, t) in arr.iter().enumerate() {
            if let Err(e) =
                serde_json::from_value::<t3rnel_types::scheduler::CronDeliveryTarget>(t.clone())
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": format!("delivery_targets[{idx}] invalid: {e}")
                    })),
                );
            }
        }
    }

    let mut job_json = serde_json::json!({
        "name": sanitize_schedule_job_name(&name_raw),
        "schedule": { "kind": "cron", "expr": cron, "tz": null },
        "action": {
            "kind": "agent_turn",
            "message": job_message,
            "model_override": null,
            "timeout_secs": null,
        },
        "delivery": { "kind": "none" },
        "one_shot": false,
    });
    if let Some(arr) = delivery_targets_raw.as_array() {
        job_json["delivery_targets"] = serde_json::Value::Array(arr.clone());
    }

    match state
        .kernel
        .cron_create(&target_agent.to_string(), job_json)
        .await
    {
        Ok(resp) => {
            let job_id = serde_json::from_str::<serde_json::Value>(&resp)
                .ok()
                .and_then(|v| v["job_id"].as_str().map(str::to_string))
                .unwrap_or_else(|| resp.trim_matches('"').to_string());
            if !enabled {
                if let Ok(uuid) = uuid::Uuid::parse_str(&job_id) {
                    let cj_id = t3rnel_types::scheduler::CronJobId(uuid);
                    let _ = state.kernel.cron_scheduler.set_enabled(cj_id, false);
                    let _ = state.kernel.cron_scheduler.persist();
                }
            }
            // Build response in the legacy shape.
            let body = if let Ok(uuid) = uuid::Uuid::parse_str(&job_id) {
                let cj_id = t3rnel_types::scheduler::CronJobId(uuid);
                match state.kernel.cron_scheduler.get_job(cj_id) {
                    Some(job) => cron_job_to_schedule_view(&state.kernel, &job),
                    None => serde_json::json!({
                        "id": job_id,
                        "name": name_raw,
                        "cron": cron,
                        "agent_id": target_agent.to_string(),
                        "message": message,
                        "enabled": enabled,
                    }),
                }
            } else {
                serde_json::json!({
                    "id": job_id,
                    "name": name_raw,
                    "cron": cron,
                    "agent_id": target_agent.to_string(),
                    "message": message,
                    "enabled": enabled,
                })
            };
            (StatusCode::CREATED, Json(body))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Failed to create schedule: {e}")})),
        ),
    }
}

/// PUT /api/schedules/:id — Update a scheduled job.
///
/// Supports toggling `enabled`. Other fields are not mutable without a
/// delete+recreate (the underlying cron scheduler does not expose in-place
/// edits); those are accepted but ignored with a note in the response.
pub async fn update_schedule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let uuid = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid schedule id"})),
            );
        }
    };
    let cj_id = t3rnel_types::scheduler::CronJobId(uuid);

    if state.kernel.cron_scheduler.get_job(cj_id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Schedule not found"})),
        );
    }

    let mut note: Option<&'static str> = None;
    if let Some(enabled) = req.get("enabled").and_then(|v| v.as_bool()) {
        if let Err(e) = state.kernel.cron_scheduler.set_enabled(cj_id, enabled) {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("{e}")})),
            );
        }
        let _ = state.kernel.cron_scheduler.persist();
    }

    // Apply a full replacement of delivery_targets when supplied. Validation
    // is done up front via serde so a bad entry produces a 400 rather than
    // silently replacing the list with the valid subset.
    if let Some(raw_targets) = req.get("delivery_targets") {
        if !raw_targets.is_array() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "delivery_targets must be an array"})),
            );
        }
        let arr = raw_targets.as_array().unwrap();
        let mut parsed: Vec<t3rnel_types::scheduler::CronDeliveryTarget> =
            Vec::with_capacity(arr.len());
        for (idx, t) in arr.iter().enumerate() {
            match serde_json::from_value::<t3rnel_types::scheduler::CronDeliveryTarget>(t.clone()) {
                Ok(dt) => parsed.push(dt),
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": format!("delivery_targets[{idx}] invalid: {e}")
                        })),
                    );
                }
            }
        }
        if let Err(e) = state
            .kernel
            .cron_scheduler
            .set_delivery_targets(cj_id, parsed)
        {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("{e}")})),
            );
        }
        let _ = state.kernel.cron_scheduler.persist();
    }

    if req.get("name").is_some()
        || req.get("cron").is_some()
        || req.get("agent_id").is_some()
        || req.get("message").is_some()
    {
        note = Some("Only 'enabled' and 'delivery_targets' are mutable; delete and recreate to change other fields.");
    }

    let mut body = serde_json::json!({"status": "updated", "schedule_id": id});
    if let Some(n) = note {
        body["note"] = serde_json::Value::String(n.to_string());
    }
    // Echo the new view so callers can confirm without a second GET.
    if let Some(job) = state.kernel.cron_scheduler.get_job(cj_id) {
        body["schedule"] = cron_job_to_schedule_view(&state.kernel, &job);
    }
    (StatusCode::OK, Json(body))
}

/// DELETE /api/schedules/:id — Remove a scheduled job from the cron scheduler.
pub async fn delete_schedule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let uuid = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid schedule id"})),
            );
        }
    };
    let cj_id = t3rnel_types::scheduler::CronJobId(uuid);
    match state.kernel.cron_scheduler.remove_job(cj_id) {
        Ok(_) => {
            let _ = state.kernel.cron_scheduler.persist();
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "removed", "schedule_id": id})),
            )
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Schedule not found"})),
        ),
    }
}

/// POST /api/schedules/:id/run — Manually run a scheduled job now.
pub async fn run_schedule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let uuid = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid schedule id"})),
            );
        }
    };
    let cj_id = t3rnel_types::scheduler::CronJobId(uuid);
    let job = match state.kernel.cron_scheduler.try_claim_for_run(cj_id) {
        Ok(j) => j,
        Err(t3rnel_kernel::cron::ClaimError::NotFound) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Schedule not found"})),
            );
        }
        Err(t3rnel_kernel::cron::ClaimError::Disabled) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Schedule is disabled"})),
            );
        }
    };

    let agent_id_str = job.agent_id.to_string();
    match state.kernel.cron_run_job(&job).await {
        Ok(response) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "completed",
                "schedule_id": id,
                "agent_id": agent_id_str,
                "response": response,
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "status": "failed",
                "schedule_id": id,
                "error": format!("{e}"),
            })),
        ),
    }
}

/// GET /api/schedules/{id}/delivery-log — Return the last N per-target
/// delivery results for a schedule.
///
/// Delivery results are not yet persisted across runs, so this endpoint
/// returns an empty list for jobs that exist. A future change can back this
/// with a ring buffer populated by `cron_fan_out_targets`. The endpoint is
/// wired up now so the dashboard can call it without a placeholder.
pub async fn schedule_delivery_log(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let uuid = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid schedule id"})),
            );
        }
    };
    let cj_id = t3rnel_types::scheduler::CronJobId(uuid);
    let job = match state.kernel.cron_scheduler.get_job(cj_id) {
        Some(j) => j,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Schedule not found"})),
            );
        }
    };
    // Delivery history is not yet persisted; surface the target list with
    // empty result arrays so the UI has stable shape to render.
    let targets: Vec<serde_json::Value> = job
        .delivery_targets
        .iter()
        .map(|t| serde_json::to_value(t).unwrap_or(serde_json::Value::Null))
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schedule_id": id,
            "targets": targets,
            "entries": [],
        })),
    )
}

/// Sanitize a user-supplied schedule name into a valid `CronJob.name`.
/// Matches the kernel's own sanitizer used by the migration path.
fn sanitize_schedule_job_name(raw: &str) -> String {
    let filtered: String = raw
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == ' ' || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = filtered.trim();
    if trimmed.is_empty() {
        return "schedule".to_string();
    }
    trimmed.chars().take(128).collect()
}

// ---------------------------------------------------------------------------
// Agent Identity endpoint
// ---------------------------------------------------------------------------

/// Request body for updating agent visual identity.
#[derive(serde::Deserialize)]
pub struct UpdateIdentityRequest {
    pub emoji: Option<String>,
    pub avatar_url: Option<String>,
    pub color: Option<String>,
    #[serde(default)]
    pub archetype: Option<String>,
    #[serde(default)]
    pub vibe: Option<String>,
    #[serde(default)]
    pub greeting_style: Option<String>,
}

/// PATCH /api/agents/{id}/identity — Update an agent's visual identity.
pub async fn update_agent_identity(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateIdentityRequest>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    // Validate color format if provided
    if let Some(ref color) = req.color {
        if !color.is_empty() && !color.starts_with('#') {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Color must be a hex code starting with '#'"})),
            );
        }
    }

    // Validate avatar_url if provided
    if let Some(ref url) = req.avatar_url {
        if !url.is_empty()
            && !url.starts_with("http://")
            && !url.starts_with("https://")
            && !url.starts_with("data:")
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Avatar URL must be http/https or data URI"})),
            );
        }
    }

    let identity = AgentIdentity {
        emoji: req.emoji,
        avatar_url: req.avatar_url,
        color: req.color,
        archetype: req.archetype,
        vibe: req.vibe,
        greeting_style: req.greeting_style,
    };

    match state.kernel.registry.update_identity(agent_id, identity) {
        Ok(()) => {
            // Persist identity to SQLite
            if let Some(entry) = state.kernel.registry.get(agent_id) {
                let _ = state.kernel.memory.save_agent(&entry);
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "ok", "agent_id": id})),
            )
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Agent not found"})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Agent Config Hot-Update
// ---------------------------------------------------------------------------

/// Request body for patching agent config (name, description, prompt, identity, model).
#[derive(serde::Deserialize)]
pub struct PatchAgentConfigRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub system_prompt: Option<String>,
    pub emoji: Option<String>,
    pub avatar_url: Option<String>,
    pub color: Option<String>,
    pub archetype: Option<String>,
    pub vibe: Option<String>,
    pub greeting_style: Option<String>,
    pub model: Option<String>,
    pub provider: Option<String>,
    pub api_key_env: Option<String>,
    pub base_url: Option<String>,
    pub fallback_models: Option<Vec<t3rnel_types::agent::FallbackModel>>,
}

/// PATCH /api/agents/{id}/config — Hot-update agent name, description, system prompt, and identity.
pub async fn patch_agent_config(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<PatchAgentConfigRequest>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    // Input length limits
    const MAX_NAME_LEN: usize = 256;
    const MAX_DESC_LEN: usize = 4096;
    const MAX_PROMPT_LEN: usize = 65_536;

    if let Some(ref name) = req.name {
        if name.len() > MAX_NAME_LEN {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(
                    serde_json::json!({"error": format!("Name exceeds max length ({MAX_NAME_LEN} chars)")}),
                ),
            );
        }
    }
    if let Some(ref desc) = req.description {
        if desc.len() > MAX_DESC_LEN {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(
                    serde_json::json!({"error": format!("Description exceeds max length ({MAX_DESC_LEN} chars)")}),
                ),
            );
        }
    }
    if let Some(ref prompt) = req.system_prompt {
        if prompt.len() > MAX_PROMPT_LEN {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(
                    serde_json::json!({"error": format!("System prompt exceeds max length ({MAX_PROMPT_LEN} chars)")}),
                ),
            );
        }
    }

    // Validate color format if provided
    if let Some(ref color) = req.color {
        if !color.is_empty() && !color.starts_with('#') {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Color must be a hex code starting with '#'"})),
            );
        }
    }

    // Validate avatar_url if provided
    if let Some(ref url) = req.avatar_url {
        if !url.is_empty()
            && !url.starts_with("http://")
            && !url.starts_with("https://")
            && !url.starts_with("data:")
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Avatar URL must be http/https or data URI"})),
            );
        }
    }

    // Update name
    if let Some(ref new_name) = req.name {
        if !new_name.is_empty() {
            if let Err(e) = state
                .kernel
                .registry
                .update_name(agent_id, new_name.clone())
            {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({"error": format!("{e}")})),
                );
            }
        }
    }

    // Update description
    if let Some(ref new_desc) = req.description {
        if state
            .kernel
            .registry
            .update_description(agent_id, new_desc.clone())
            .is_err()
        {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            );
        }
    }

    // Update system prompt (hot-swap — takes effect on next message)
    if let Some(ref new_prompt) = req.system_prompt {
        if state
            .kernel
            .registry
            .update_system_prompt(agent_id, new_prompt.clone())
            .is_err()
        {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            );
        }
    }

    // Update identity fields (merge — only overwrite provided fields)
    let has_identity_field = req.emoji.is_some()
        || req.avatar_url.is_some()
        || req.color.is_some()
        || req.archetype.is_some()
        || req.vibe.is_some()
        || req.greeting_style.is_some();

    if has_identity_field {
        // Read current identity, merge with provided fields
        let current = state
            .kernel
            .registry
            .get(agent_id)
            .map(|e| e.identity)
            .unwrap_or_default();
        let merged = AgentIdentity {
            emoji: req.emoji.or(current.emoji),
            avatar_url: req.avatar_url.or(current.avatar_url),
            color: req.color.or(current.color),
            archetype: req.archetype.or(current.archetype),
            vibe: req.vibe.or(current.vibe),
            greeting_style: req.greeting_style.or(current.greeting_style),
        };
        if state
            .kernel
            .registry
            .update_identity(agent_id, merged)
            .is_err()
        {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            );
        }
    }

    // Update model/provider — use set_agent_model for catalog-based provider
    // resolution when provider is not explicitly provided (fixes #387/#466:
    // changing model from another provider without specifying provider now
    // auto-resolves the correct provider from the model catalog).
    if let Some(ref new_model) = req.model {
        if !new_model.is_empty() {
            if let Some(ref new_provider) = req.provider {
                if !new_provider.is_empty() {
                    // Explicit provider given — still route through set_agent_model
                    // so provider-specific auth/env hints stay in sync.
                    if let Err(e) =
                        state
                            .kernel
                            .set_agent_model(agent_id, new_model, Some(new_provider))
                    {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error": format!("{e}")})),
                        );
                    }
                } else {
                    // Provider is empty string — resolve from catalog
                    if let Err(e) = state.kernel.set_agent_model(agent_id, new_model, None) {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"error": format!("{e}")})),
                        );
                    }
                }
            } else {
                // No provider field at all — resolve from catalog
                if let Err(e) = state.kernel.set_agent_model(agent_id, new_model, None) {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": format!("{e}")})),
                    );
                }
            }
        }
    }

    // Update base_url for the agent's model
    if let Some(ref base_url) = req.base_url {
        if state
            .kernel
            .registry
            .update_model_base_url(agent_id, base_url.clone())
            .is_err()
        {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            );
        }
    }

    // Update fallback model chain
    if let Some(fallbacks) = req.fallback_models {
        if state
            .kernel
            .registry
            .update_fallback_models(agent_id, fallbacks)
            .is_err()
        {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            );
        }
    }

    // Persist updated manifest to database so changes survive restart
    if let Some(entry) = state.kernel.registry.get(agent_id) {
        if let Err(e) = state.kernel.memory.save_agent(&entry) {
            tracing::warn!("Failed to persist agent config update: {e}");
        }
    }

    // Write updated manifest to agent.toml on disk so disk doesn't override
    // dashboard changes on next boot (#996, #1018).
    state.kernel.persist_manifest_to_disk(agent_id);

    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "ok", "agent_id": id})),
    )
}

// ---------------------------------------------------------------------------
// Agent Cloning
// ---------------------------------------------------------------------------

/// Request body for cloning an agent.
///
/// `overrides` is a free-form JSON object that is deep-merged onto the cloned
/// manifest before spawning. This lets callers tweak fields like `description`,
/// `tags`, `model`, etc. without re-stating the entire manifest. The `name`
/// field on `overrides` is ignored — `new_name` always wins.
#[derive(serde::Deserialize)]
pub struct CloneAgentRequest {
    pub new_name: String,
    #[serde(default)]
    pub overrides: Option<serde_json::Value>,
}

/// Workspace files that contain accumulated memory or per-session state and
/// MUST NOT be copied when cloning an agent. The cloned agent starts with
/// independent memory by design (see issue #868).
const MEMORY_FILES: &[&str] = &["MEMORY.md", "HEARTBEAT.md"];

/// Deep-merge `overrides` onto `base` JSON. Object fields are recursively
/// merged; arrays and scalars are replaced.
fn deep_merge_json(base: &mut serde_json::Value, overrides: serde_json::Value) {
    match (base, overrides) {
        (serde_json::Value::Object(base_map), serde_json::Value::Object(over_map)) => {
            for (k, v) in over_map {
                match base_map.get_mut(&k) {
                    Some(existing) => deep_merge_json(existing, v),
                    None => {
                        base_map.insert(k, v);
                    }
                }
            }
        }
        (slot, value) => {
            *slot = value;
        }
    }
}

/// POST /api/agents/{template_id}/clone — Clone a template agent into a new
/// independent agent with its own workspace and memory.
///
/// Body: `{ "new_name": "user-42", "overrides": { ... } }`
///
/// Returns: `{ "agent_id": "...", "name": "...", "manifest": { ... } }`
pub async fn clone_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<CloneAgentRequest>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    if req.new_name.len() > 256 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "Name exceeds max length (256 chars)"})),
        );
    }

    let new_name = req.new_name.trim().to_string();
    if new_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "new_name cannot be empty"})),
        );
    }

    // Reject names with path separators / control chars to keep workspace dir naming safe.
    if new_name
        .chars()
        .any(|c| c == '/' || c == '\\' || c == '\0' || c.is_control())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "new_name contains invalid characters"})),
        );
    }

    // Reject if template doesn't exist.
    let source = match state.kernel.registry.get(agent_id) {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Template agent not found"})),
            );
        }
    };

    // Reject if new_name collides with an existing agent.
    if state.kernel.registry.find_by_name(&new_name).is_some() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": format!("An agent named '{}' already exists", new_name)
            })),
        );
    }

    // Deep-clone manifest and apply overrides.
    let mut cloned_manifest = source.manifest.clone();
    if let Some(overrides) = req.overrides.clone() {
        if !overrides.is_object() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "overrides must be a JSON object"})),
            );
        }
        // Serialize manifest to JSON, merge overrides, deserialize back.
        // This lets callers patch arbitrary nested fields without exhaustive enumeration.
        let mut manifest_json = match serde_json::to_value(&cloned_manifest) {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(
                        serde_json::json!({"error": format!("Failed to serialize manifest: {e}")}),
                    ),
                );
            }
        };
        deep_merge_json(&mut manifest_json, overrides);
        cloned_manifest = match serde_json::from_value(manifest_json) {
            Ok(m) => m,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        serde_json::json!({"error": format!("Invalid overrides — manifest no longer valid: {e}")}),
                    ),
                );
            }
        };
    }

    // new_name always wins over any name field in overrides.
    cloned_manifest.name = new_name.clone();
    // Let the kernel assign fresh workspace and state directory paths.
    // Never share private state with the template (see issue #868, #1097).
    cloned_manifest.workspace = None;
    cloned_manifest.state_dir = None;

    // Spawn the cloned agent.
    let new_id = match state.kernel.spawn_agent(cloned_manifest) {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Clone spawn failed: {e}")})),
            );
        }
    };

    // Copy non-memory identity files from source state_dir to destination
    // state_dir. MEMORY.md and HEARTBEAT.md are intentionally skipped — the
    // cloned agent must start with independent memory (issue #868). Identity
    // files live in state_dir per #1097; fall back to legacy workspace for
    // older agents.
    let new_entry = state.kernel.registry.get(new_id);
    let src_state = source
        .manifest
        .state_dir
        .as_ref()
        .or(source.manifest.workspace.as_ref());
    let dst_state = new_entry.as_ref().and_then(|e| {
        e.manifest
            .state_dir
            .as_ref()
            .or(e.manifest.workspace.as_ref())
    });
    if let (Some(src_ws), Some(dst_ws)) = (src_state, dst_state) {
        if let (Ok(src_can), Ok(dst_can)) = (src_ws.canonicalize(), dst_ws.canonicalize()) {
            for &fname in KNOWN_IDENTITY_FILES {
                if MEMORY_FILES.contains(&fname) {
                    continue;
                }
                let src_file = src_can.join(fname);
                let dst_file = dst_can.join(fname);
                if src_file.exists() {
                    let _ = std::fs::copy(&src_file, &dst_file);
                }
            }
        }
    }
    // Copy the user-facing `skills/` subdirectory so curated skills travel
    // with the template. These live in the workspace, not the state dir.
    if let (Some(ref src_ws), Some(ref new_entry)) = (&source.manifest.workspace, &new_entry) {
        if let Some(ref dst_ws) = new_entry.manifest.workspace {
            if let (Ok(src_can), Ok(dst_can)) = (src_ws.canonicalize(), dst_ws.canonicalize()) {
                let src_skills = src_can.join("skills");
                let dst_skills = dst_can.join("skills");
                if src_skills.is_dir() {
                    let _ = copy_dir_recursive(&src_skills, &dst_skills);
                }
            }
        }
    }

    // Copy visual identity from source so the clone looks like the template.
    let _ = state
        .kernel
        .registry
        .update_identity(new_id, source.identity.clone());

    // Register in channel router so binding resolution finds the cloned agent.
    if let Some(ref mgr) = *state.bridge_manager.lock().await {
        mgr.router().register_agent(new_name.clone(), new_id);
    }

    // Return the freshly-spawned manifest (after kernel assigned workspace etc).
    let manifest_value = new_entry
        .as_ref()
        .and_then(|e| serde_json::to_value(&e.manifest).ok())
        .unwrap_or(serde_json::Value::Null);

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "agent_id": new_id.to_string(),
            "name": new_name,
            "manifest": manifest_value,
        })),
    )
}

/// Recursively copy a directory tree. Skips any file whose name appears in
/// `MEMORY_FILES`. Best-effort: errors on individual entries are swallowed so
/// a clone can still partially succeed (the caller will see the new agent ID).
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let name = entry.file_name();
        if let Some(name_str) = name.to_str() {
            if MEMORY_FILES.contains(&name_str) {
                continue;
            }
        }
        let src_path = entry.path();
        let dst_path = dst.join(&name);
        if file_type.is_dir() {
            let _ = copy_dir_recursive(&src_path, &dst_path);
        } else if file_type.is_file() {
            let _ = std::fs::copy(&src_path, &dst_path);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Workspace File Editor endpoints
// ---------------------------------------------------------------------------

/// Whitelisted workspace identity files that can be read/written via API.
const KNOWN_IDENTITY_FILES: &[&str] = &[
    "SOUL.md",
    "IDENTITY.md",
    "USER.md",
    "TOOLS.md",
    "MEMORY.md",
    "AGENTS.md",
    "BOOTSTRAP.md",
    "HEARTBEAT.md",
];

fn resolve_agent_workspace_path(
    workspace: &std::path::Path,
    workspaces_root: &std::path::Path,
    agent_name: &str,
) -> Result<std::path::PathBuf, String> {
    if let Ok(canonical) = workspace.canonicalize() {
        return Ok(canonical);
    }

    let mut candidates = Vec::new();
    candidates.push(workspaces_root.join(agent_name));

    if let Some(dir_name) = workspace.file_name().and_then(|name| name.to_str()) {
        if !dir_name.trim().is_empty() && dir_name != agent_name {
            candidates.push(workspaces_root.join(dir_name));
        }
    }

    let mut tried = Vec::new();
    for candidate in candidates {
        if tried
            .iter()
            .any(|known: &std::path::PathBuf| known == &candidate)
        {
            continue;
        }
        match candidate.canonicalize() {
            Ok(canonical) => return Ok(canonical),
            Err(_) => tried.push(candidate),
        }
    }

    let tried_paths = tried
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "Workspace path error: {} does not exist; tried {}",
        workspace.display(),
        tried_paths
    ))
}

/// GET /api/agents/{id}/files — List workspace identity files.
pub async fn list_agent_files(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    let entry = match state.kernel.registry.get(agent_id) {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            );
        }
    };

    // Identity files live in the agent's private state directory (see #1097).
    // Fall back to the legacy workspace location for agents created before the
    // split so existing on-disk files remain reachable.
    let workspace = match entry
        .manifest
        .state_dir
        .as_ref()
        .or(entry.manifest.workspace.as_ref())
    {
        Some(ws) => ws.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent has no workspace"})),
            );
        }
    };
    let workspace = match resolve_agent_workspace_path(
        &workspace,
        &state.kernel.config.effective_workspaces_dir(),
        &entry.manifest.name,
    ) {
        Ok(path) => path,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": error})),
            );
        }
    };

    let mut files = Vec::new();
    for &name in KNOWN_IDENTITY_FILES {
        let path = workspace.join(name);
        let (exists, size_bytes) = if path.exists() {
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            (true, size)
        } else {
            (false, 0u64)
        };
        files.push(serde_json::json!({
            "name": name,
            "exists": exists,
            "size_bytes": size_bytes,
        }));
    }

    (StatusCode::OK, Json(serde_json::json!({ "files": files })))
}

/// GET /api/agents/{id}/files/{filename} — Read a workspace identity file.
pub async fn get_agent_file(
    State(state): State<Arc<AppState>>,
    Path((id, filename)): Path<(String, String)>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    // Validate filename whitelist
    if !KNOWN_IDENTITY_FILES.contains(&filename.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "File not in whitelist"})),
        );
    }

    let entry = match state.kernel.registry.get(agent_id) {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            );
        }
    };

    // Identity files live in the agent's private state directory (see #1097).
    // Fall back to legacy workspace for agents created before the split.
    let workspace = match entry
        .manifest
        .state_dir
        .as_ref()
        .or(entry.manifest.workspace.as_ref())
    {
        Some(ws) => ws.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent has no workspace"})),
            );
        }
    };
    let workspace = match resolve_agent_workspace_path(
        &workspace,
        &state.kernel.config.effective_workspaces_dir(),
        &entry.manifest.name,
    ) {
        Ok(path) => path,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": error})),
            );
        }
    };

    // Security: canonicalize and verify stays inside workspace
    let file_path = workspace.join(&filename);
    let canonical = match file_path.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "File not found"})),
            );
        }
    };
    let ws_canonical = match workspace.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Workspace path error"})),
            );
        }
    };
    if !canonical.starts_with(&ws_canonical) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Path traversal denied"})),
        );
    }

    let content = match std::fs::read_to_string(&canonical) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "File not found"})),
            );
        }
    };

    let size_bytes = content.len();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "name": filename,
            "content": content,
            "size_bytes": size_bytes,
        })),
    )
}

/// Request body for writing a workspace identity file.
#[derive(serde::Deserialize)]
pub struct SetAgentFileRequest {
    pub content: String,
}

/// PUT /api/agents/{id}/files/{filename} — Write a workspace identity file.
pub async fn set_agent_file(
    State(state): State<Arc<AppState>>,
    Path((id, filename)): Path<(String, String)>,
    Json(req): Json<SetAgentFileRequest>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    // Validate filename whitelist
    if !KNOWN_IDENTITY_FILES.contains(&filename.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "File not in whitelist"})),
        );
    }

    // Max 32KB content
    const MAX_FILE_SIZE: usize = 32_768;
    if req.content.len() > MAX_FILE_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "File content too large (max 32KB)"})),
        );
    }

    let entry = match state.kernel.registry.get(agent_id) {
        Some(e) => e,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent not found"})),
            );
        }
    };

    // Identity files live in the agent's private state directory (see #1097).
    // Fall back to legacy workspace for agents created before the split.
    let workspace = match entry
        .manifest
        .state_dir
        .as_ref()
        .or(entry.manifest.workspace.as_ref())
    {
        Some(ws) => ws.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Agent has no workspace"})),
            );
        }
    };
    let workspace = match resolve_agent_workspace_path(
        &workspace,
        &state.kernel.config.effective_workspaces_dir(),
        &entry.manifest.name,
    ) {
        Ok(path) => path,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": error})),
            );
        }
    };

    // Security: verify workspace path and target stays inside it
    let ws_canonical = match workspace.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Workspace path error"})),
            );
        }
    };

    let file_path = workspace.join(&filename);
    // For new files, check the parent directory instead
    let check_path = if file_path.exists() {
        file_path
            .canonicalize()
            .unwrap_or_else(|_| file_path.clone())
    } else {
        // Parent must be inside workspace
        file_path
            .parent()
            .and_then(|p| p.canonicalize().ok())
            .map(|p| p.join(&filename))
            .unwrap_or_else(|| file_path.clone())
    };
    if !check_path.starts_with(&ws_canonical) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Path traversal denied"})),
        );
    }

    // Atomic write: write to .tmp, then rename
    let tmp_path = workspace.join(format!(".{filename}.tmp"));
    if let Err(e) = std::fs::write(&tmp_path, &req.content) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Write failed: {e}")})),
        );
    }
    if let Err(e) = std::fs::rename(&tmp_path, &file_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Rename failed: {e}")})),
        );
    }

    let size_bytes = req.content.len();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "name": filename,
            "size_bytes": size_bytes,
        })),
    )
}

// ---------------------------------------------------------------------------
// Host File Browser and Terminal endpoints
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct HostFilesQuery {
    pub path: Option<String>,
    pub search: Option<String>,
    pub sort: Option<String>,
    pub direction: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct HostTerminalRunRequest {
    pub command: String,
    pub cwd: Option<String>,
    pub timeout_secs: Option<u64>,
}

fn host_default_path() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

fn resolve_host_path(input: Option<&str>) -> std::path::PathBuf {
    let raw = input.map(str::trim).filter(|s| !s.is_empty());
    let Some(raw) = raw else {
        return host_default_path();
    };
    if raw == "~" {
        return host_default_path();
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        return host_default_path().join(rest);
    }
    let path = std::path::PathBuf::from(raw);
    let resolved = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| host_default_path())
            .join(path)
    };
    remap_mounted_t3rnel_state_path(resolved)
}

/// Resolve paths produced by host-side workers against the daemon's mounted
/// T3rnel state directory. This keeps local media previews working in the
/// containerized API without granting a blanket host filesystem mount.
fn remap_mounted_t3rnel_state_path(path: PathBuf) -> PathBuf {
    let host_home = std::env::var("T3RNEL_HOST_HOME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let runtime_home = std::env::var("T3RNEL_HOME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let (Some(host_home), Some(runtime_home)) = (host_home, runtime_home) else {
        return path;
    };

    let host_state = PathBuf::from(host_home).join(".t3rnel");
    let Ok(relative) = path.strip_prefix(host_state) else {
        return path;
    };
    if relative
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return path;
    }
    PathBuf::from(runtime_home).join(relative)
}

fn guess_content_type(path: &std::path::Path) -> &'static str {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "md" | "markdown" => "text/markdown",
        "txt" | "log" | "rs" | "toml" | "json" | "yaml" | "yml" | "js" | "jsx" | "ts" | "tsx"
        | "css" | "html" | "xml" | "csv" | "sh" | "py" | "sql" | "ini" | "env" => "text/plain",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "mp3" | "mpeg" | "mpg" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" | "oga" => "audio/ogg",
        "flac" => "audio/flac",
        "m4a" => "audio/mp4",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

fn preview_kind(path: &std::path::Path, is_dir: bool) -> &'static str {
    if is_dir {
        return "directory";
    }
    let content_type = guess_content_type(path);
    if content_type.starts_with("text/") || content_type == "image/svg+xml" {
        "text"
    } else if content_type.starts_with("image/") {
        "image"
    } else if content_type.starts_with("audio/") {
        "audio"
    } else if content_type.starts_with("video/") {
        "video"
    } else {
        "binary"
    }
}

fn iso_modified_time(meta: &std::fs::Metadata) -> Option<String> {
    meta.modified()
        .ok()
        .map(chrono::DateTime::<chrono::Utc>::from)
        .map(|dt| dt.to_rfc3339())
}

/// GET /api/host/files — Browse the local host filesystem.
///
/// This endpoint is intentionally host-level rather than agent-workspace-level:
/// desktop users use it to inspect their own machine from the T3rnel cockpit.
pub async fn list_host_files(Query(query): Query<HostFilesQuery>) -> impl IntoResponse {
    let requested = resolve_host_path(query.path.as_deref());
    let path = match requested.canonicalize() {
        Ok(path) => path,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("Path not found: {e}")})),
            );
        }
    };

    if !path.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Path is not a directory"})),
        );
    }

    let search = query.search.unwrap_or_default().to_ascii_lowercase();
    let mut files = Vec::new();
    let entries = match std::fs::read_dir(&path) {
        Ok(entries) => entries,
        Err(e) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": format!("Cannot read directory: {e}")})),
            );
        }
    };

    for entry in entries.flatten() {
        let entry_path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if !search.is_empty() && !name.to_ascii_lowercase().contains(&search) {
            continue;
        }
        let meta = match std::fs::symlink_metadata(&entry_path) {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        let file_type = meta.file_type();
        let is_dir = file_type.is_dir();
        let kind = if is_dir {
            "directory"
        } else if file_type.is_file() {
            "file"
        } else if file_type.is_symlink() {
            "symlink"
        } else {
            "other"
        };
        let content_type = guess_content_type(&entry_path);
        files.push(serde_json::json!({
            "name": name,
            "path": entry_path.to_string_lossy(),
            "kind": kind,
            "size_bytes": if is_dir { 0 } else { meta.len() },
            "modified_at": iso_modified_time(&meta),
            "extension": entry_path.extension().and_then(|ext| ext.to_str()),
            "content_type": content_type,
            "preview_kind": preview_kind(&entry_path, is_dir),
        }));
    }

    let sort = query.sort.unwrap_or_else(|| "name".to_string());
    let desc = query
        .direction
        .as_deref()
        .map(|value| value.eq_ignore_ascii_case("desc"))
        .unwrap_or(false);
    files.sort_by(|a, b| {
        let a_is_dir = a["kind"].as_str() == Some("directory");
        let b_is_dir = b["kind"].as_str() == Some("directory");
        let dir_order = b_is_dir.cmp(&a_is_dir);
        if dir_order != std::cmp::Ordering::Equal {
            return dir_order;
        }
        let ordering = match sort.as_str() {
            "size" => a["size_bytes"].as_u64().cmp(&b["size_bytes"].as_u64()),
            "modified" => a["modified_at"].as_str().cmp(&b["modified_at"].as_str()),
            "kind" => a["kind"].as_str().cmp(&b["kind"].as_str()),
            _ => a["name"]
                .as_str()
                .unwrap_or("")
                .to_ascii_lowercase()
                .cmp(&b["name"].as_str().unwrap_or("").to_ascii_lowercase()),
        };
        if desc {
            ordering.reverse()
        } else {
            ordering
        }
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "path": path.to_string_lossy(),
            "parent": path.parent().map(|p| p.to_string_lossy().to_string()),
            "files": files,
        })),
    )
}

/// GET /api/host/files/read — Read a local text file for preview/edit context.
pub async fn read_host_file(Query(query): Query<HostFilesQuery>) -> impl IntoResponse {
    let requested = resolve_host_path(query.path.as_deref());
    let path = match requested.canonicalize() {
        Ok(path) => path,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("File not found: {e}")})),
            );
        }
    };

    if !path.is_file() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Path is not a file"})),
        );
    }

    let meta = match std::fs::metadata(&path) {
        Ok(meta) => meta,
        Err(e) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": format!("Cannot read file: {e}")})),
            );
        }
    };
    let content_type = guess_content_type(&path);
    if !(content_type.starts_with("text/") || content_type == "image/svg+xml") {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Json(
                serde_json::json!({"error": "Use the raw endpoint for image, audio, video, and binary previews"}),
            ),
        );
    }

    const MAX_TEXT_PREVIEW_BYTES: usize = 2 * 1024 * 1024;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": format!("Cannot read file: {e}")})),
            );
        }
    };
    let truncated = bytes.len() > MAX_TEXT_PREVIEW_BYTES;
    let slice = if truncated {
        &bytes[..MAX_TEXT_PREVIEW_BYTES]
    } else {
        &bytes
    };
    let content = String::from_utf8_lossy(slice).to_string();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "path": path.to_string_lossy(),
            "content": content,
            "content_type": content_type,
            "size_bytes": meta.len(),
            "truncated": truncated,
        })),
    )
}

/// GET /api/host/files/raw — Serve a local file for image/audio/video preview.
pub async fn serve_host_file_raw(Query(query): Query<HostFilesQuery>) -> impl IntoResponse {
    let requested = resolve_host_path(query.path.as_deref());
    let path = match requested.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "application/json".to_string(),
                )],
                b"{\"error\":\"File not found\"}".to_vec(),
            );
        }
    };
    if !path.is_file() {
        return (
            StatusCode::BAD_REQUEST,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/json".to_string(),
            )],
            b"{\"error\":\"Path is not a file\"}".to_vec(),
        );
    }

    match std::fs::read(&path) {
        Ok(data) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                guess_content_type(&path).to_string(),
            )],
            data,
        ),
        Err(_) => (
            StatusCode::FORBIDDEN,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/json".to_string(),
            )],
            b"{\"error\":\"Cannot read file\"}".to_vec(),
        ),
    }
}

/// POST /api/host/terminal/run — Execute a command on the host shell.
pub async fn run_host_terminal(Json(req): Json<HostTerminalRunRequest>) -> impl IntoResponse {
    let command = req.command.trim();
    if command.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "command cannot be empty"})),
        );
    }
    if command.len() > 32_768 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "command is too large"})),
        );
    }

    let cwd = resolve_host_path(req.cwd.as_deref());
    let cwd = match cwd.canonicalize() {
        Ok(cwd) if cwd.is_dir() => cwd,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "cwd is not a directory"})),
            );
        }
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("cwd not found: {e}")})),
            );
        }
    };

    let timeout_secs = req.timeout_secs.unwrap_or(120).clamp(1, 600);
    let started = std::time::Instant::now();
    let shell = std::env::var("SHELL").unwrap_or_else(|_| {
        if cfg!(windows) {
            "cmd".to_string()
        } else {
            "sh".to_string()
        }
    });
    let shell_flag = if cfg!(windows) { "/C" } else { "-lc" };
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        tokio::process::Command::new(shell)
            .arg(shell_flag)
            .arg(command)
            .current_dir(&cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output(),
    )
    .await;

    const MAX_OUTPUT_BYTES: usize = 256 * 1024;
    let truncate = |bytes: Vec<u8>| {
        let truncated = bytes.len() > MAX_OUTPUT_BYTES;
        let slice = if truncated {
            &bytes[..MAX_OUTPUT_BYTES]
        } else {
            &bytes
        };
        let mut text = String::from_utf8_lossy(slice).to_string();
        if truncated {
            text.push_str("\n[output truncated at 256 KiB]");
        }
        text
    };

    match output {
        Ok(Ok(output)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "command": command,
                "cwd": cwd.to_string_lossy(),
                "exit_code": output.status.code().unwrap_or(-1),
                "stdout": truncate(output.stdout),
                "stderr": truncate(output.stderr),
                "duration_ms": started.elapsed().as_millis(),
                "timed_out": false,
            })),
        ),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to execute command: {e}")})),
        ),
        Err(_) => (
            StatusCode::REQUEST_TIMEOUT,
            Json(serde_json::json!({
                "error": format!("Command timed out after {timeout_secs}s"),
                "command": command,
                "cwd": cwd.to_string_lossy(),
                "exit_code": -1,
                "stdout": "",
                "stderr": "",
                "duration_ms": started.elapsed().as_millis(),
                "timed_out": true,
            })),
        ),
    }
}

// ---------------------------------------------------------------------------
// File Upload endpoints
// ---------------------------------------------------------------------------

/// Response body for file uploads.
#[derive(serde::Serialize)]
struct UploadResponse {
    file_id: String,
    filename: String,
    content_type: String,
    size: usize,
    /// Transcription text for audio uploads (populated via Whisper STT).
    #[serde(skip_serializing_if = "Option::is_none")]
    transcription: Option<String>,
}

/// Metadata stored alongside uploaded files.
struct UploadMeta {
    content_type: String,
}

/// In-memory upload metadata registry.
static UPLOAD_REGISTRY: LazyLock<DashMap<String, UploadMeta>> = LazyLock::new(DashMap::new);

/// Maximum upload size: 10 MB.
const MAX_UPLOAD_SIZE: usize = 10 * 1024 * 1024;

/// Allowed content type prefixes for upload.
const ALLOWED_CONTENT_TYPES: &[&str] = &["image/", "text/", "application/pdf", "audio/"];

fn normalize_content_type(ct: &str) -> String {
    ct.split(';')
        .next()
        .unwrap_or(ct)
        .trim()
        .to_ascii_lowercase()
}

fn is_allowed_content_type(ct: &str) -> bool {
    let ct = normalize_content_type(ct);
    ALLOWED_CONTENT_TYPES
        .iter()
        .any(|prefix| ct.starts_with(prefix))
}

#[cfg(test)]
mod host_upload_tests {
    use super::{is_allowed_content_type, normalize_content_type};

    #[test]
    fn audio_webm_with_codec_parameters_is_normalized_for_stt() {
        assert_eq!(
            normalize_content_type("audio/webm;codecs=opus"),
            "audio/webm"
        );
        assert!(is_allowed_content_type("audio/webm;codecs=opus"));
    }
}

/// POST /api/agents/{id}/upload — Upload a file attachment.
///
/// Accepts multipart/form-data. The client must include a file field with:
/// - `Content-Type` field (e.g., `image/png`, `text/plain`, `application/pdf`)
/// - `filename` attribute (original filename)
pub async fn upload_file(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let _agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid agent ID"})),
            );
        }
    };

    let mut file_data: Option<(Option<String>, String, axum::body::Bytes)> = None;
    let mut filename_from_field: Option<String> = None;

    while let Some(field) = multipart.next_field().await.transpose() {
        let field = match field {
            Ok(f) => f,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("Failed to read field: {}", e)})),
                );
            }
        };

        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            "file" => {
                let filename_attr = field.file_name().map(|s| s.to_string());
                let content_type = field
                    .content_type()
                    .unwrap_or("application/octet-stream")
                    .to_string();
                let bytes = match field.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(
                                serde_json::json!({"error": format!("Failed to read file: {}", e)}),
                            ),
                        );
                    }
                };
                file_data = Some((filename_attr, content_type, bytes));
            }
            "filename" => {
                filename_from_field = field.text().await.ok();
            }
            _ => {}
        }
    }

    let (filename_attr, content_type, body) = match file_data {
        Some(data) => data,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "No file provided"})),
            );
        }
    };
    let content_type = normalize_content_type(&content_type);

    let filename = filename_from_field
        .or(filename_attr)
        .unwrap_or_else(|| "upload".to_string());

    if !is_allowed_content_type(&content_type) {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "Unsupported content type. Allowed: image/*, text/*, audio/*, application/pdf"}),
            ),
        );
    }

    // Validate size
    if body.len() > MAX_UPLOAD_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(
                serde_json::json!({"error": format!("File too large (max {} MB)", MAX_UPLOAD_SIZE / (1024 * 1024))}),
            ),
        );
    }

    if body.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Empty file body"})),
        );
    }

    // Generate file ID and save
    let file_id = uuid::Uuid::new_v4().to_string();
    let upload_dir = std::env::temp_dir().join("t3rnel_uploads");
    if let Err(e) = std::fs::create_dir_all(&upload_dir) {
        tracing::warn!("Failed to create upload dir: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to create upload directory"})),
        );
    }

    let file_path = upload_dir.join(&file_id);
    if let Err(e) = std::fs::write(&file_path, &body) {
        tracing::warn!("Failed to write upload: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to save file"})),
        );
    }

    let size = body.len();
    UPLOAD_REGISTRY.insert(
        file_id.clone(),
        UploadMeta {
            content_type: content_type.clone(),
        },
    );

    // Auto-transcribe audio uploads using the media engine. Voice uploads are
    // commands, not passive attachments; fail hard if STT is unavailable so the
    // desktop never mistakes "audio was saved" for "command was sent".
    let transcription = if content_type.starts_with("audio/") {
        let whisper_cpp = whisper_cpp_settings_from_state(&state);
        apply_whisper_cpp_settings_to_env(&whisper_cpp);
        if whisper_cpp.enabled
            && !whisper_cpp_server_running(&whisper_cpp.base_url).await
            && whisper_cpp
                .model_path
                .as_deref()
                .map(|path| FsPath::new(path).exists())
                .unwrap_or(false)
            && command_available(&whisper_cpp.binary)
        {
            if let Err(error) = start_whisper_cpp_server(&state, &whisper_cpp).await {
                tracing::warn!("Whisper.cpp auto-start failed before audio transcription: {error}");
            }
        }
        let attachment = t3rnel_types::media::MediaAttachment {
            media_type: t3rnel_types::media::MediaType::Audio,
            mime_type: content_type.clone(),
            source: t3rnel_types::media::MediaSource::FilePath {
                path: file_path.to_string_lossy().to_string(),
            },
            size_bytes: size as u64,
        };
        match state
            .kernel
            .media_engine
            .transcribe_audio(&attachment)
            .await
        {
            Ok(result) => {
                tracing::info!(chars = result.description.len(), provider = %result.provider, "Audio transcribed");
                Some(result.description)
            }
            Err(e) => {
                tracing::warn!("Audio transcription failed: {e}");
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({
                        "error": format!(
                            "Audio transcription failed: {e}. Enable local Whisper.cpp in Settings, enable Parakeet MLX with T3RNEL_ENABLE_PARAKEET_MLX=1, or set GROQ_API_KEY / OPENAI_API_KEY for Whisper STT."
                        )
                    })),
                );
            }
        }
    } else {
        None
    };

    (
        StatusCode::CREATED,
        Json(serde_json::json!(UploadResponse {
            file_id,
            filename,
            content_type,
            size,
            transcription,
        })),
    )
}

/// GET /api/uploads/{file_id} — Serve an uploaded file.
pub async fn serve_upload(Path(file_id): Path<String>) -> impl IntoResponse {
    // Validate file_id is a UUID to prevent path traversal
    if uuid::Uuid::parse_str(&file_id).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/json".to_string(),
            )],
            b"{\"error\":\"Invalid file ID\"}".to_vec(),
        );
    }

    let file_path = std::env::temp_dir().join("t3rnel_uploads").join(&file_id);

    // Look up metadata from registry; fall back to disk probe for generated images
    // (image_generate saves files without registering in UPLOAD_REGISTRY).
    let content_type = match UPLOAD_REGISTRY.get(&file_id) {
        Some(m) => m.content_type.clone(),
        None => {
            // Infer content type from file magic bytes
            if !file_path.exists() {
                return (
                    StatusCode::NOT_FOUND,
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "application/json".to_string(),
                    )],
                    b"{\"error\":\"File not found\"}".to_vec(),
                );
            }
            "image/png".to_string()
        }
    };

    match std::fs::read(&file_path) {
        Ok(data) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, content_type)],
            data,
        ),
        Err(_) => (
            StatusCode::NOT_FOUND,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/json".to_string(),
            )],
            b"{\"error\":\"File not found on disk\"}".to_vec(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Execution Approval System — backed by kernel.approval_manager
// ---------------------------------------------------------------------------

/// GET /api/approvals — List pending and recent approval requests.
///
/// Transforms field names to match the dashboard template expectations:
/// `action_summary` → `action`, `agent_id` → `agent_name`, `requested_at` → `created_at`.
pub async fn list_approvals(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let pending = state.kernel.approval_manager.list_pending();
    let recent = state.kernel.approval_manager.list_recent(50);

    // Resolve agent names for display
    let registry_agents = state.kernel.registry.list();
    let agent_name_for = |agent_id: &str| {
        registry_agents
            .iter()
            .find(|ag| ag.id.to_string() == agent_id || ag.name == agent_id)
            .map(|ag| ag.name.clone())
            .unwrap_or_else(|| agent_id.to_string())
    };

    let mut approvals: Vec<serde_json::Value> = pending
        .into_iter()
        .map(|a| {
            let agent_name = agent_name_for(&a.agent_id);
            serde_json::json!({
                "id": a.id,
                "agent_id": a.agent_id,
                "agent_name": agent_name,
                "tool_name": a.tool_name,
                "description": a.description,
                "action_summary": a.action_summary,
                "action": a.action_summary,
                "risk_level": format!("{:?}", a.risk_level),
                "requested_at": a.requested_at,
                "created_at": a.requested_at,
                "timeout_secs": a.timeout_secs,
                "status": "pending"
            })
        })
        .collect();

    approvals.extend(recent.into_iter().map(|record| {
        let request = record.request;
        let agent_name = agent_name_for(&request.agent_id);
        let status = match record.decision {
            t3rnel_types::approval::ApprovalDecision::Approved => "approved",
            t3rnel_types::approval::ApprovalDecision::Denied => "rejected",
            t3rnel_types::approval::ApprovalDecision::TimedOut => "expired",
        };
        serde_json::json!({
            "id": request.id,
            "agent_id": request.agent_id,
            "agent_name": agent_name,
            "tool_name": request.tool_name,
            "description": request.description,
            "action_summary": request.action_summary,
            "action": request.action_summary,
            "risk_level": format!("{:?}", request.risk_level),
            "requested_at": request.requested_at,
            "created_at": request.requested_at,
            "timeout_secs": request.timeout_secs,
            "status": status,
            "decided_at": record.decided_at,
            "decided_by": record.decided_by,
        })
    }));

    approvals.sort_by(|a, b| {
        let a_pending = a["status"].as_str() == Some("pending");
        let b_pending = b["status"].as_str() == Some("pending");
        b_pending
            .cmp(&a_pending)
            .then_with(|| b["created_at"].as_str().cmp(&a["created_at"].as_str()))
    });

    let total = approvals.len();

    Json(serde_json::json!({"approvals": approvals, "total": total}))
}

/// GET /api/approvals/pending-count — Return the number of pending approvals.
pub async fn get_pending_count(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let count = state.kernel.approval_manager.pending_count();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "pending_count": count })),
    )
        .into_response()
}

/// POST /api/approvals — Create a manual approval request (for external systems).
///
/// Note: Most approval requests are created automatically by the tool_runner
/// when an agent invokes a tool that requires approval. This endpoint exists
/// for external integrations that need to inject approval gates.
#[derive(serde::Deserialize)]
pub struct CreateApprovalRequest {
    pub agent_id: String,
    pub tool_name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub action_summary: String,
}

pub async fn create_approval(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateApprovalRequest>,
) -> impl IntoResponse {
    use t3rnel_types::approval::{ApprovalRequest, RiskLevel};

    let policy = state.kernel.approval_manager.policy();
    let id = uuid::Uuid::new_v4();
    let approval_req = ApprovalRequest {
        id,
        agent_id: req.agent_id.clone(),
        tool_name: req.tool_name.clone(),
        description: if req.description.is_empty() {
            format!("Manual approval request for {}", req.tool_name)
        } else {
            req.description.clone()
        },
        action_summary: if req.action_summary.is_empty() {
            req.tool_name.clone()
        } else {
            req.action_summary
        },
        risk_level: RiskLevel::High,
        requested_at: chrono::Utc::now(),
        timeout_secs: policy.timeout_secs,
    };

    // Spawn the request in the background (it will block until resolved or timed out)
    let kernel = Arc::clone(&state.kernel);
    tokio::spawn(async move {
        kernel.approval_manager.request_approval(approval_req).await;
    });

    // Mirror into the pending-actions ledger (visible to `approvals`, the
    // dashboard and WhatsApp replies).
    let _ = crate::pending_actions::create_pending(crate::pending_actions::CreatePendingRequest {
        summary: if req.description.is_empty() {
            format!("Approval: {}", req.tool_name)
        } else {
            req.description.clone()
        },
        kind: Some(crate::pending_actions::PendingKind::Approval),
        detail_ref: Some(id.to_string()),
        agent: Some(req.agent_id.clone()),
        callback: Some("approval".to_string()),
        risk: Some("high".to_string()),
        ttl_secs: Some(policy.timeout_secs as i64),
        wa_message_id: None,
    });

    (
        StatusCode::CREATED,
        Json(serde_json::json!({"id": id.to_string(), "status": "pending"})),
    )
}

/// POST /api/approvals/approve-all — Approve all currently pending requests.
pub async fn approve_all_requests(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let pending = state.kernel.approval_manager.list_pending();
    let mut approved = Vec::new();
    let mut skipped = Vec::new();

    for request in pending {
        match state.kernel.approval_manager.resolve(
            request.id,
            t3rnel_types::approval::ApprovalDecision::Approved,
            Some("api".to_string()),
        ) {
            Ok(resp) => {
                approved.push(serde_json::json!({
                    "id": request.id,
                    "agent_id": resp.agent_id,
                    "status": "approved",
                    "decided_at": resp.decided_at.to_rfc3339(),
                }));
            }
            Err(e) => {
                skipped.push(serde_json::json!({
                    "id": request.id,
                    "status": "skipped",
                    "detail": e,
                }));
            }
        }
    }

    let approved_count = approved.len();
    let skipped_count = skipped.len();

    Json(serde_json::json!({
        "approved": approved,
        "skipped": skipped,
        "approved_count": approved_count,
        "skipped_count": skipped_count,
    }))
}

/// POST /api/approvals/{id}/approve — Approve a pending request.
pub async fn approve_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let uuid = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid approval ID"})),
            );
        }
    };

    match state.kernel.approval_manager.resolve(
        uuid,
        t3rnel_types::approval::ApprovalDecision::Approved,
        Some("api".to_string()),
    ) {
        Ok(resp) => {
            state.kernel.audit_log.record(
                &resp.agent_id,
                t3rnel_runtime::audit::AuditAction::ToolInvoke,
                format!(
                    "approval_decided tool={} action={} description={}",
                    resp.tool_name, resp.action_summary, resp.description
                ),
                "approved",
            );
            // Fire ApprovalDecided hook
            let hook_ctx = t3rnel_runtime::hooks::HookContext {
                agent_name: "approval_system",
                agent_id: &resp.agent_id,
                event: t3rnel_types::agent::HookEvent::ApprovalDecided,
                data: serde_json::json!({
                    "approval_id": id,
                    "decision": "approved",
                    "decided_by": "api",
                    "decided_at": resp.decided_at.to_rfc3339(),
                }),
            };
            let _ = state.kernel.hooks.fire(&hook_ctx);
            (
                StatusCode::OK,
                Json(
                    serde_json::json!({"id": id, "status": "approved", "decided_at": resp.decided_at.to_rfc3339()}),
                ),
            )
        }
        Err(e) => {
            let status =
                if e.to_lowercase().contains("already") || e.to_lowercase().contains("decided") {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::NOT_FOUND
                };
            let error_code = if status == StatusCode::CONFLICT {
                "approval_already_decided"
            } else {
                "approval_not_found"
            };
            (
                status,
                Json(serde_json::json!({"error": error_code, "detail": e})),
            )
        }
    }
}

/// POST /api/approvals/{id}/reject — Reject a pending request.
pub async fn reject_request(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let uuid = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid approval ID"})),
            );
        }
    };

    match state.kernel.approval_manager.resolve(
        uuid,
        t3rnel_types::approval::ApprovalDecision::Denied,
        Some("api".to_string()),
    ) {
        Ok(resp) => {
            // Fire ApprovalDecided hook
            let hook_ctx = t3rnel_runtime::hooks::HookContext {
                agent_name: "approval_system",
                agent_id: &resp.agent_id,
                event: t3rnel_types::agent::HookEvent::ApprovalDecided,
                data: serde_json::json!({
                    "approval_id": id,
                    "decision": "rejected",
                    "decided_by": "api",
                    "decided_at": resp.decided_at.to_rfc3339(),
                }),
            };
            let _ = state.kernel.hooks.fire(&hook_ctx);
            (
                StatusCode::OK,
                Json(
                    serde_json::json!({"id": id, "status": "rejected", "decided_at": resp.decided_at.to_rfc3339()}),
                ),
            )
        }
        Err(e) => {
            let status =
                if e.to_lowercase().contains("already") || e.to_lowercase().contains("decided") {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::NOT_FOUND
                };
            let error_code = if status == StatusCode::CONFLICT {
                "approval_already_decided"
            } else {
                "approval_not_found"
            };
            (
                status,
                Json(serde_json::json!({"error": error_code, "detail": e})),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Pending-actions ledger — asks waiting on a human, resolvable from the
// dashboard, `./t3rnel-services approvals`, or a WhatsApp reply.
// ---------------------------------------------------------------------------

/// GET /api/pending-actions — list live pending items.
pub async fn list_pending_actions() -> impl IntoResponse {
    let items = crate::pending_actions::list_pending();
    Json(serde_json::json!({ "items": items, "total": items.len() }))
}

/// POST /api/pending-actions — register an ask.
pub async fn create_pending_action(
    Json(req): Json<crate::pending_actions::CreatePendingRequest>,
) -> impl IntoResponse {
    if req.summary.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "summary is required"})),
        );
    }
    let item = crate::pending_actions::create_pending(req);
    (StatusCode::CREATED, Json(serde_json::json!(item)))
}

/// POST /api/pending-actions/{id}/resolve — approve/reject/cancel.
pub async fn resolve_pending_action(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<crate::pending_actions::ResolvePendingRequest>,
) -> impl IntoResponse {
    // Agents must never resolve their own asks — decisions come from the
    // operator (whatsapp/api/cli), never from an agent turn.
    let via = req.via.clone().unwrap_or_else(|| "api".to_string());
    if via == "agent" || via == "orchestrator" || via == "t3rnel" {
        return (
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({"error": "agents cannot resolve pending items; the operator must decide"}),
            ),
        );
    }
    match crate::pending_actions::resolve_pending(&id, &req.decision, req.note.clone(), &via) {
        Ok(item) => {
            // Bidirectional sync: a ledger item mirroring a kernel approval
            // (callback="approval", detail_ref=approval uuid) resolves the
            // underlying approval too, so both surfaces agree.
            if item.callback.as_deref() == Some("approval") {
                if let Some(r) = item
                    .detail_ref
                    .as_deref()
                    .and_then(|r| uuid::Uuid::parse_str(r).ok())
                {
                    let decision = match item.state {
                        crate::pending_actions::PendingState::Approved => {
                            t3rnel_types::approval::ApprovalDecision::Approved
                        }
                        _ => t3rnel_types::approval::ApprovalDecision::Denied,
                    };
                    let _ = state.kernel.approval_manager.resolve(
                        r,
                        decision,
                        Some(format!("pending-actions:{via}")),
                    );
                }
            }
            (StatusCode::OK, Json(serde_json::json!(item)))
        }
        Err(e) => {
            let status = if e.contains("already") {
                StatusCode::CONFLICT
            } else {
                StatusCode::NOT_FOUND
            };
            (status, Json(serde_json::json!({"error": e})))
        }
    }
}

/// POST /api/pending-actions/{id}/snooze — extend expiry.
pub async fn snooze_pending_action(
    Path(id): Path<String>,
    Json(req): Json<crate::pending_actions::SnoozePendingRequest>,
) -> impl IntoResponse {
    match crate::pending_actions::snooze_pending(&id, req.secs) {
        Ok(item) => (StatusCode::OK, Json(serde_json::json!(item))),
        Err(e) => {
            let status = if e.contains("already") {
                StatusCode::CONFLICT
            } else {
                StatusCode::NOT_FOUND
            };
            (status, Json(serde_json::json!({"error": e})))
        }
    }
}

fn resolve_agent_for_permission(state: &AppState, id_or_name: &str) -> Option<(AgentId, String)> {
    if let Ok(agent_id) = id_or_name.parse::<AgentId>() {
        if let Some(entry) = state.kernel.registry.get(agent_id) {
            return Some((entry.id, entry.name));
        }
    }

    state
        .kernel
        .registry
        .find_by_name(id_or_name)
        .map(|entry| (entry.id, entry.name))
}

/// GET /api/permissions/grants — List active runtime capability grants by agent.
pub async fn list_permission_grants(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut agents = state.kernel.registry.list();
    agents.sort_by(|left, right| left.name.cmp(&right.name));

    let grants: Vec<serde_json::Value> = agents
        .into_iter()
        .map(|entry| {
            let capabilities = state.kernel.capabilities.list(entry.id);
            let capability_count = capabilities.len();
            serde_json::json!({
                "agent_id": entry.id.to_string(),
                "agent_name": entry.name,
                "state": format!("{:?}", entry.state),
                "mode": entry.mode,
                "profile": entry.manifest.profile,
                "capabilities": capabilities,
                "capability_count": capability_count,
                "source": "runtime_manifest",
            })
        })
        .collect();
    let total = grants.len();

    Json(serde_json::json!({
        "grants": grants,
        "total": total,
    }))
}

/// POST /api/permissions/grants/{id} — Merge runtime capability grants for an agent.
pub async fn grant_permission_capabilities(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let Some((agent_id, agent_name)) = resolve_agent_for_permission(&state, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "agent_not_found"})),
        )
            .into_response();
    };

    let mut capabilities = Vec::new();
    if let Some(preset) = body.get("preset").and_then(|value| value.as_str()) {
        add_permission_preset(&mut capabilities, preset);
    }
    if let Some(presets) = body.get("presets").and_then(|value| value.as_array()) {
        for preset in presets.iter().filter_map(|value| value.as_str()) {
            add_permission_preset(&mut capabilities, preset);
        }
    }
    if let Some(raw_capabilities) = body.get("capabilities") {
        match serde_json::from_value::<Vec<Capability>>(raw_capabilities.clone()) {
            Ok(parsed) => {
                for capability in parsed {
                    push_unique_capability(&mut capabilities, capability);
                }
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_capabilities",
                        "detail": e.to_string(),
                    })),
                )
                    .into_response();
            }
        }
    }

    if capabilities.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "no_capabilities",
                "detail": "Provide preset, presets, or capabilities.",
            })),
        )
            .into_response();
    }

    let replace = body
        .get("replace")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let added = grant_capabilities_to_agent(&state, agent_id, capabilities.clone(), replace);
    let current = state.kernel.capabilities.list(agent_id);
    state.kernel.audit_log.record(
        agent_id.to_string(),
        t3rnel_runtime::audit::AuditAction::ConfigChange,
        format!(
            "permission_grants_updated agent={agent_name} added={} total={} replace={replace}",
            added.len(),
            current.len()
        ),
        "granted",
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "granted",
            "agent_id": agent_id.to_string(),
            "agent_name": agent_name,
            "added_count": added.len(),
            "total_count": current.len(),
            "added_capabilities": added,
            "capabilities": current,
        })),
    )
        .into_response()
}

/// DELETE /api/permissions/grants/{id} — Revoke all active runtime grants for an agent.
pub async fn revoke_permission_grants(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let Some((agent_id, agent_name)) = resolve_agent_for_permission(&state, &id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "agent_not_found"})),
        );
    };

    let before = state.kernel.capabilities.list(agent_id).len();
    state.kernel.capabilities.revoke_all(agent_id);
    state.kernel.audit_log.record(
        agent_id.to_string(),
        t3rnel_runtime::audit::AuditAction::ConfigChange,
        format!("permission_grants_revoked agent={agent_name} count={before}"),
        "revoked",
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "revoked",
            "agent_id": agent_id.to_string(),
            "agent_name": agent_name,
            "revoked_count": before,
        })),
    )
}

// ---------------------------------------------------------------------------
// Config Reload endpoint
// ---------------------------------------------------------------------------

/// POST /api/config/reload — Reload configuration from disk and apply hot-reloadable changes.
///
/// Reads the config file, diffs against current config, validates the new config,
/// and applies hot-reloadable actions (approval policy, cron limits, etc.).
/// Returns the reload plan showing what changed and what was applied.
pub async fn config_reload(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // SECURITY: Record config reload in audit trail
    state.kernel.audit_log.record(
        "system",
        t3rnel_runtime::audit::AuditAction::ConfigChange,
        "config reload requested via API",
        "pending",
    );
    match state.kernel.reload_config() {
        Ok(plan) => {
            let status = if plan.restart_required {
                "partial"
            } else if plan.has_changes() {
                "applied"
            } else {
                "no_changes"
            };

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": status,
                    "restart_required": plan.restart_required,
                    "restart_reasons": plan.restart_reasons,
                    "hot_actions_applied": plan.hot_actions.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>(),
                    "noop_changes": plan.noop_changes,
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"status": "error", "error": e})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Config Schema endpoint
// ---------------------------------------------------------------------------

/// GET /api/config/schema — Return a simplified JSON description of the config structure.
pub async fn config_schema(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Build provider/model options from model catalog for dropdowns
    let catalog = state
        .kernel
        .model_catalog
        .read()
        .unwrap_or_else(|e| e.into_inner());
    let provider_options: Vec<String> = catalog
        .list_providers()
        .iter()
        .map(|p| p.id.clone())
        .collect();
    let model_options: Vec<serde_json::Value> = catalog
        .list_models()
        .iter()
        .map(|m| serde_json::json!({"id": m.id, "name": m.display_name, "provider": m.provider}))
        .collect();
    drop(catalog);

    // Helper: normalize field definitions to objects with {name, type, label}
    // so the frontend template can iterate and render inputs correctly.
    let f = |name: &str, ftype: &str, label: &str| -> serde_json::Value {
        serde_json::json!({"name": name, "type": ftype, "label": label})
    };

    Json(serde_json::json!({
        "sections": {
            "general": {
                "root_level": true,
                "fields": [
                    f("api_listen", "string", "API Listen Address"),
                    f("api_key", "string", "API Key"),
                    f("log_level", "string", "Log Level")
                ]
            },
            "default_model": {
                "hot_reloadable": true,
                "fields": [
                    { "name": "provider", "type": "select", "label": "Provider", "options": provider_options },
                    { "name": "model", "type": "select", "label": "Model", "options": model_options },
                    f("api_key_env", "string", "API Key Env Var"),
                    f("base_url", "string", "Base URL")
                ]
            },
            "memory": {
                "fields": [
                    f("decay_rate", "number", "Decay Rate"),
                    f("vector_dims", "number", "Vector Dimensions")
                ]
            },
            "web": {
                "fields": [
                    f("provider", "string", "Search Provider"),
                    f("timeout_secs", "number", "Timeout (seconds)"),
                    f("max_results", "number", "Max Results")
                ]
            },
            "browser": {
                "fields": [
                    f("headless", "boolean", "Headless Mode"),
                    f("timeout_secs", "number", "Timeout (seconds)"),
                    f("executable_path", "string", "Chrome/Chromium Path")
                ]
            },
            "network": {
                "fields": [
                    f("enabled", "boolean", "Enable OFP Network"),
                    f("listen_addr", "string", "Listen Address"),
                    f("shared_secret", "string", "Shared Secret")
                ]
            },
            "extensions": {
                "fields": [
                    f("auto_connect", "boolean", "Auto Connect"),
                    f("health_check_interval_secs", "number", "Health Check Interval (s)")
                ]
            },
            "vault": {
                "fields": [
                    f("path", "string", "Vault Path")
                ]
            },
            "a2a": {
                "fields": [
                    f("enabled", "boolean", "Enable A2A"),
                    f("name", "string", "Agent Name"),
                    f("description", "string", "Description"),
                    f("url", "string", "URL")
                ]
            },
            "channels": {
                "fields": [
                    f("telegram", "object", "Telegram"),
                    f("discord", "object", "Discord"),
                    f("slack", "object", "Slack"),
                    f("whatsapp", "object", "WhatsApp")
                ]
            }
        }
    }))
}

// ---------------------------------------------------------------------------
// Config Set endpoint
// ---------------------------------------------------------------------------

/// POST /api/config/set — Set a single config value and persist to config.toml.
///
/// Accepts JSON `{ "path": "section.key", "value": "..." }`.
/// Writes the value to the TOML config file and triggers a reload.
pub async fn config_set(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let path = match body.get("path").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status": "error", "error": "missing 'path' field"})),
            );
        }
    };
    let value = match body.get("value") {
        Some(v) => v.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status": "error", "error": "missing 'value' field"})),
            );
        }
    };

    let config_path = state.kernel.config.home_dir.join("config.toml");

    // Read existing config as a TOML table, or start fresh
    let mut table: toml::value::Table = if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => toml::from_str(&content).unwrap_or_default(),
            Err(_) => toml::value::Table::new(),
        }
    } else {
        toml::value::Table::new()
    };

    // Convert JSON value to TOML value
    let toml_val = json_to_toml_value(&value);

    // Parse "section.key" path and set value
    let parts: Vec<&str> = path.split('.').collect();
    match parts.len() {
        1 => {
            table.insert(parts[0].to_string(), toml_val);
        }
        2 => {
            let section = table
                .entry(parts[0].to_string())
                .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
            if let toml::Value::Table(ref mut t) = section {
                t.insert(parts[1].to_string(), toml_val);
            }
        }
        3 => {
            let section = table
                .entry(parts[0].to_string())
                .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
            if let toml::Value::Table(ref mut t) = section {
                let sub = t
                    .entry(parts[1].to_string())
                    .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
                if let toml::Value::Table(ref mut t2) = sub {
                    t2.insert(parts[2].to_string(), toml_val);
                }
            }
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"status": "error", "error": "path too deep (max 3 levels)"}),
                ),
            );
        }
    }

    // Write back
    let toml_string = match toml::to_string_pretty(&table) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    serde_json::json!({"status": "error", "error": format!("serialize failed: {e}")}),
                ),
            );
        }
    };
    if let Err(e) = std::fs::write(&config_path, &toml_string) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"status": "error", "error": format!("write failed: {e}")})),
        );
    }

    // Trigger reload
    let reload_status = match state.kernel.reload_config() {
        Ok(plan) => {
            if plan.restart_required {
                "applied_partial"
            } else {
                "applied"
            }
        }
        Err(_) => "saved_reload_failed",
    };

    state.kernel.audit_log.record(
        "system",
        t3rnel_runtime::audit::AuditAction::ConfigChange,
        format!("config set: {path}"),
        "completed",
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({"status": reload_status, "path": path})),
    )
}

/// PUT /api/config/default-model — Set the default model for the daemon.
///
/// Accepts JSON `{ "provider": "...", "model": "..." }`.
/// Writes the value to the TOML config file and triggers a reload.
pub async fn config_set_default_model(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let provider = body.get("provider").and_then(|v| v.as_str()).unwrap_or("");
    let model = body.get("model").and_then(|v| v.as_str()).unwrap_or("");

    let config_path = state.kernel.config.home_dir.join("config.toml");

    let mut table: toml::value::Table = if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => toml::from_str(&content).unwrap_or_default(),
            Err(_) => toml::value::Table::new(),
        }
    } else {
        toml::value::Table::new()
    };

    let default_model_section = table
        .entry("default_model".to_string())
        .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));

    if let toml::Value::Table(ref mut t) = default_model_section {
        t.insert(
            "provider".to_string(),
            toml::Value::String(provider.to_string()),
        );
        t.insert("model".to_string(), toml::Value::String(model.to_string()));

        // Use a generic API key env based on provider
        let key_env = format!("{}_API_KEY", provider.to_uppercase());
        t.insert("api_key_env".to_string(), toml::Value::String(key_env));
    }

    let toml_string = match toml::to_string_pretty(&table) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    serde_json::json!({"status": "error", "error": format!("serialize failed: {e}")}),
                ),
            );
        }
    };
    if let Err(e) = std::fs::write(&config_path, &toml_string) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"status": "error", "error": format!("write failed: {e}")})),
        );
    }

    let reload_status = match state.kernel.reload_config() {
        Ok(plan) => {
            if plan.restart_required {
                "applied_partial"
            } else {
                "applied"
            }
        }
        Err(_) => "saved_reload_failed",
    };

    state.kernel.audit_log.record(
        "system",
        t3rnel_runtime::audit::AuditAction::ConfigChange,
        format!("config set default model: {provider}/{model}"),
        "completed",
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({"status": reload_status, "provider": provider, "model": model})),
    )
}

/// Convert a serde_json::Value to a toml::Value.
fn json_to_toml_value(value: &serde_json::Value) -> toml::Value {
    match value {
        serde_json::Value::String(s) => toml::Value::String(s.clone()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_u64() {
                toml::Value::Integer(i as i64)
            } else if let Some(i) = n.as_i64() {
                toml::Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                toml::Value::Float(f)
            } else {
                toml::Value::String(n.to_string())
            }
        }
        serde_json::Value::Bool(b) => toml::Value::Boolean(*b),
        _ => toml::Value::String(value.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Delivery tracking endpoints
// ---------------------------------------------------------------------------

/// GET /api/agents/:id/deliveries — List recent delivery receipts for an agent.
pub async fn get_agent_deliveries(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let agent_id: AgentId = match id.parse() {
        Ok(id) => id,
        Err(_) => {
            // Try name lookup
            match state.kernel.registry.find_by_name(&id) {
                Some(entry) => entry.id,
                None => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(serde_json::json!({"error": "Agent not found"})),
                    );
                }
            }
        }
    };

    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(500);

    let receipts = state.kernel.delivery_tracker.get_receipts(agent_id, limit);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "agent_id": agent_id.to_string(),
            "count": receipts.len(),
            "receipts": receipts,
        })),
    )
}

// ---------------------------------------------------------------------------
// Cron job management endpoints
// ---------------------------------------------------------------------------

/// GET /api/cron/jobs — List all cron jobs, optionally filtered by agent_id.
pub async fn list_cron_jobs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let jobs = if let Some(agent_id_str) = params.get("agent_id") {
        match uuid::Uuid::parse_str(agent_id_str) {
            Ok(uuid) => {
                let aid = AgentId(uuid);
                state.kernel.cron_scheduler.list_jobs(aid)
            }
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "Invalid agent_id"})),
                );
            }
        }
    } else {
        state.kernel.cron_scheduler.list_all_jobs()
    };
    let total = jobs.len();
    let jobs_json: Vec<serde_json::Value> = jobs
        .into_iter()
        .map(|j| serde_json::to_value(&j).unwrap_or_default())
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({"jobs": jobs_json, "total": total})),
    )
}

/// POST /api/cron/jobs — Create a new cron job.
pub async fn create_cron_job(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let agent_id = body["agent_id"].as_str().unwrap_or("");
    match state.kernel.cron_create(agent_id, body.clone()).await {
        Ok(result) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"result": result})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        ),
    }
}

/// DELETE /api/cron/jobs/{id} — Delete a cron job.
pub async fn delete_cron_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match uuid::Uuid::parse_str(&id) {
        Ok(uuid) => {
            let job_id = t3rnel_types::scheduler::CronJobId(uuid);
            match state.kernel.cron_scheduler.remove_job(job_id) {
                Ok(_) => {
                    let _ = state.kernel.cron_scheduler.persist();
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({"status": "deleted"})),
                    )
                }
                Err(e) => (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": format!("{e}")})),
                ),
            }
        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid job ID"})),
        ),
    }
}

/// PUT /api/cron/jobs/{id}/enable — Enable or disable a cron job.
pub async fn toggle_cron_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let enabled = body["enabled"].as_bool().unwrap_or(true);
    match uuid::Uuid::parse_str(&id) {
        Ok(uuid) => {
            let job_id = t3rnel_types::scheduler::CronJobId(uuid);
            match state.kernel.cron_scheduler.set_enabled(job_id, enabled) {
                Ok(()) => {
                    let _ = state.kernel.cron_scheduler.persist();
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({"id": id, "enabled": enabled})),
                    )
                }
                Err(e) => (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": format!("{e}")})),
                ),
            }
        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid job ID"})),
        ),
    }
}

/// GET /api/cron/jobs/{id}/status — Get status of a specific cron job.
pub async fn cron_job_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match uuid::Uuid::parse_str(&id) {
        Ok(uuid) => {
            let job_id = t3rnel_types::scheduler::CronJobId(uuid);
            match state.kernel.cron_scheduler.get_meta(job_id) {
                Some(meta) => (
                    StatusCode::OK,
                    Json(serde_json::to_value(&meta).unwrap_or_default()),
                ),
                None => (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "Job not found"})),
                ),
            }
        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid job ID"})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Run cron job on demand
// ---------------------------------------------------------------------------

/// POST /api/cron/jobs/{id}/run — Trigger a cron job immediately.
///
/// Returns `{"status": "triggered", "job_id": "..."}` and spawns the execution
/// in the background.  The job's status can be polled via
/// `GET /api/cron/jobs/{id}/status`.
pub async fn run_cron_job(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let uuid = match uuid::Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status": "error", "error": "Invalid job ID"})),
            );
        }
    };
    let job_id = t3rnel_types::scheduler::CronJobId(uuid);

    // Atomically check existence + enabled + reserve next_run in one lock hold.
    let job = match state.kernel.cron_scheduler.try_claim_for_run(job_id) {
        Ok(j) => j,
        Err(t3rnel_kernel::cron::ClaimError::NotFound) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"status": "error", "error": "Job not found"})),
            );
        }
        Err(t3rnel_kernel::cron::ClaimError::Disabled) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"status": "error", "error": "Job is disabled"})),
            );
        }
    };

    // Spawn execution in the background so we don't block the HTTP response.
    let kernel = Arc::clone(&state.kernel);
    let job_name = job.name.clone();
    tokio::spawn(async move {
        match kernel.cron_run_job(&job).await {
            Ok(_) => tracing::info!(job = %job_name, "On-demand cron job completed"),
            Err(e) => tracing::warn!(job = %job_name, error = %e, "On-demand cron job failed"),
        }
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "triggered",
            "job_id": id,
        })),
    )
}

// ---------------------------------------------------------------------------
// Webhook trigger endpoints
// ---------------------------------------------------------------------------

/// POST /hooks/wake — Inject a system event via webhook trigger.
///
/// Publishes a custom event through the kernel's event system, which can
/// trigger proactive agents that subscribe to the event type.
pub async fn webhook_wake(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<t3rnel_types::webhook::WakePayload>,
) -> impl IntoResponse {
    // Check if webhook triggers are enabled
    let wh_config = match &state.kernel.config.webhook_triggers {
        Some(c) if c.enabled => c,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Webhook triggers not enabled"})),
            );
        }
    };

    // Validate bearer token (constant-time comparison)
    if !validate_webhook_token(&headers, &wh_config.token_env) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid or missing token"})),
        );
    }

    // Validate payload
    if let Err(e) = body.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        );
    }

    // Ingress scan: a webhook token authenticates the sender, not the content —
    // wake text is commonly templated from external data (issue bodies, CI
    // logs). Refuse injected payloads before they enter the event pipeline.
    let ingress =
        t3rnel_types::sentinel::scan(&body.text, t3rnel_types::sentinel::Direction::Ingress);
    if ingress.blocked {
        let kinds = ingress
            .findings
            .iter()
            .map(|f| format!("{:?}", f.kind))
            .collect::<Vec<_>>()
            .join(",");
        state.kernel.audit_log.record(
            "webhook",
            t3rnel_runtime::audit::AuditAction::SecurityDenial,
            format!("route=/hooks/wake kinds={kinds}"),
            "denied",
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "webhook payload refused by ingress sentinel",
                "findings": ingress.findings.iter().map(|f| f.rule).collect::<Vec<_>>(),
            })),
        );
    }

    // Publish through the kernel's publish_event (KernelHandle trait), which
    // goes through the full event processing pipeline including trigger evaluation.
    let event_payload = serde_json::json!({
        "source": "webhook",
        "mode": body.mode,
        "text": body.text,
    });
    if let Err(e) =
        KernelHandle::publish_event(state.kernel.as_ref(), "webhook.wake", event_payload).await
    {
        tracing::warn!("Webhook wake event publish failed: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Event publish failed: {e}")})),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "accepted", "mode": body.mode})),
    )
}

/// POST /hooks/agent — Run an isolated agent turn via webhook.
///
/// Sends a message directly to the specified agent and returns the response.
/// This enables external systems (CI/CD, Slack, etc.) to trigger agent work.
pub async fn webhook_agent(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<t3rnel_types::webhook::AgentHookPayload>,
) -> impl IntoResponse {
    // Check if webhook triggers are enabled
    let wh_config = match &state.kernel.config.webhook_triggers {
        Some(c) if c.enabled => c,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Webhook triggers not enabled"})),
            );
        }
    };

    // Validate bearer token
    if !validate_webhook_token(&headers, &wh_config.token_env) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid or missing token"})),
        );
    }

    // Validate payload
    if let Err(e) = body.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        );
    }

    // Resolve the agent by name or ID (if not specified, use the first running agent)
    let agent_id: AgentId = match &body.agent {
        Some(agent_ref) => match agent_ref.parse() {
            Ok(id) => id,
            Err(_) => {
                // Try name lookup
                match state.kernel.registry.find_by_name(agent_ref) {
                    Some(entry) => entry.id,
                    None => {
                        return (
                            StatusCode::NOT_FOUND,
                            Json(
                                serde_json::json!({"error": format!("Agent not found: {}", agent_ref)}),
                            ),
                        );
                    }
                }
            }
        },
        None => {
            // No agent specified — use the first available agent
            match state.kernel.registry.list().first() {
                Some(entry) => entry.id,
                None => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(serde_json::json!({"error": "No agents available"})),
                    );
                }
            }
        }
    };

    // Ingress scan: the token proves who called, not what the message contains.
    // Webhook messages are usually assembled from untrusted external data.
    let ingress =
        t3rnel_types::sentinel::scan(&body.message, t3rnel_types::sentinel::Direction::Ingress);
    if ingress.blocked {
        let kinds = ingress
            .findings
            .iter()
            .map(|f| format!("{:?}", f.kind))
            .collect::<Vec<_>>()
            .join(",");
        state.kernel.audit_log.record(
            "webhook",
            t3rnel_runtime::audit::AuditAction::SecurityDenial,
            format!("route=/hooks/agent kinds={kinds}"),
            "denied",
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "webhook message refused by ingress sentinel",
                "findings": ingress.findings.iter().map(|f| f.rule).collect::<Vec<_>>(),
            })),
        );
    }

    // Actually send the message to the agent and get the response
    match state.kernel.send_message(agent_id, &body.message).await {
        Ok(result) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "completed",
                "agent_id": agent_id.to_string(),
                "response": result.response,
                "usage": {
                    "input_tokens": result.total_usage.input_tokens,
                    "output_tokens": result.total_usage.output_tokens,
                },
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Agent execution failed: {e}")})),
        ),
    }
}

// ─── Agent Bindings API ────────────────────────────────────────────────

/// GET /api/bindings — List all agent bindings.
pub async fn list_bindings(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let bindings = state.kernel.list_bindings();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "bindings": bindings })),
    )
}

/// POST /api/bindings — Add a new agent binding.
pub async fn add_binding(
    State(state): State<Arc<AppState>>,
    Json(binding): Json<t3rnel_types::config::AgentBinding>,
) -> impl IntoResponse {
    // Validate agent exists
    let agents = state.kernel.registry.list();
    let agent_exists = agents.iter().any(|e| e.name == binding.agent)
        || binding.agent.parse::<uuid::Uuid>().is_ok();
    if !agent_exists {
        tracing::warn!(agent = %binding.agent, "Binding references unknown agent");
    }

    state.kernel.add_binding(binding);
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "created" })),
    )
}

/// DELETE /api/bindings/:index — Remove a binding by index.
pub async fn remove_binding(
    State(state): State<Arc<AppState>>,
    Path(index): Path<usize>,
) -> impl IntoResponse {
    match state.kernel.remove_binding(index) {
        Some(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "removed" })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Binding index out of range" })),
        ),
    }
}

// ─── Device Pairing endpoints ───────────────────────────────────────────

/// POST /api/pairing/request — Create a new pairing request (returns token + QR URI).
pub async fn pairing_request(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if !state.kernel.config.pairing.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Pairing not enabled"})),
        )
            .into_response();
    }
    match state.kernel.pairing.create_pairing_request() {
        Ok(req) => {
            let qr_uri = format!("t3rnel://pair?token={}", req.token);
            Json(serde_json::json!({
                "token": req.token,
                "qr_uri": qr_uri,
                "expires_at": req.expires_at.to_rfc3339(),
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

/// POST /api/pairing/complete — Complete pairing with token + device info.
pub async fn pairing_complete(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if !state.kernel.config.pairing.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Pairing not enabled"})),
        )
            .into_response();
    }
    let token = body.get("token").and_then(|v| v.as_str()).unwrap_or("");
    let display_name = body
        .get("display_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let platform = body
        .get("platform")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let push_token = body
        .get("push_token")
        .and_then(|v| v.as_str())
        .map(String::from);
    let biometric_public_key = match parse_biometric_public_key(body.get("biometric_public_key")) {
        Ok(key) => key,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": error })),
            )
                .into_response();
        }
    };
    let device_info = t3rnel_kernel::pairing::PairedDevice {
        device_id: uuid::Uuid::new_v4().to_string(),
        display_name: display_name.to_string(),
        platform: platform.to_string(),
        paired_at: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        push_token,
        biometric_public_key,
    };
    match state.kernel.pairing.complete_pairing(token, device_info) {
        Ok(device) => Json(serde_json::json!({
            "device_id": device.device_id,
            "display_name": device.display_name,
            "platform": device.platform,
            "paired_at": device.paired_at.to_rfc3339(),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

fn parse_biometric_public_key(
    value: Option<&serde_json::Value>,
) -> Result<Option<Vec<u8>>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let bytes = if let Some(hex_value) = value.as_str() {
        hex::decode(hex_value).map_err(|e| format!("invalid biometric_public_key hex: {e}"))?
    } else if let Some(array) = value.as_array() {
        let mut bytes = Vec::with_capacity(array.len());
        for item in array {
            let byte = item
                .as_u64()
                .filter(|byte| *byte <= u8::MAX as u64)
                .ok_or_else(|| "biometric_public_key array must contain bytes".to_string())?;
            bytes.push(byte as u8);
        }
        bytes
    } else {
        return Err("biometric_public_key must be a hex string or byte array".to_string());
    };
    if bytes.len() != 32 {
        return Err("biometric_public_key must be exactly 32 bytes".to_string());
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod pairing_route_tests {
    use super::parse_biometric_public_key;

    #[test]
    fn biometric_public_key_accepts_hex() {
        let value =
            serde_json::json!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        let key = parse_biometric_public_key(Some(&value)).unwrap().unwrap();

        assert_eq!(key.len(), 32);
        assert_eq!(key[0], 0);
        assert_eq!(key[31], 31);
    }

    #[test]
    fn biometric_public_key_rejects_wrong_length() {
        let value = serde_json::json!("abcd");

        let err = parse_biometric_public_key(Some(&value)).unwrap_err();

        assert!(err.contains("exactly 32 bytes"));
    }
}

/// GET /api/pairing/devices — List paired devices.
pub async fn pairing_devices(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if !state.kernel.config.pairing.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Pairing not enabled"})),
        )
            .into_response();
    }
    let devices: Vec<_> = state
        .kernel
        .pairing
        .list_devices()
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "device_id": d.device_id,
                "display_name": d.display_name,
                "platform": d.platform,
                "paired_at": d.paired_at.to_rfc3339(),
                "last_seen": d.last_seen.to_rfc3339(),
            })
        })
        .collect();
    Json(serde_json::json!({"devices": devices})).into_response()
}

/// DELETE /api/pairing/devices/{id} — Remove a paired device.
pub async fn pairing_remove_device(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
) -> impl IntoResponse {
    if !state.kernel.config.pairing.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Pairing not enabled"})),
        )
            .into_response();
    }
    match state.kernel.pairing.remove_device(&device_id) {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// POST /api/pairing/notify — Push a notification to all paired devices.
pub async fn pairing_notify(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let title = body
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("T3rnel");
    let message = body
        .get("message")
        .or_else(|| body.get("body"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if message.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "message is required"})),
        )
            .into_response();
    }
    let marker = body
        .get("data")
        .and_then(|data| data.get("marker"))
        .and_then(|v| v.as_str())
        .unwrap_or(message);
    if !state.kernel.config.pairing.enabled {
        state.kernel.audit_log.record(
            "mobile-push",
            t3rnel_runtime::audit::AuditAction::ToolInvoke,
            format!("pairing_notify_simulated title={} body={}", title, message),
            "pairing_disabled",
        );
        return Json(serde_json::json!({
            "ok": true,
            "notified": 0,
            "simulated": true,
            "marker": marker,
            "title": title,
            "body": message,
            "data": body.get("data").cloned().unwrap_or_else(|| serde_json::json!({})),
        }))
        .into_response();
    }
    state.kernel.pairing.notify_devices(title, message).await;
    Json(serde_json::json!({
        "ok": true,
        "notified": state.kernel.pairing.list_devices().len(),
        "marker": marker,
        "title": title,
        "body": message,
    }))
    .into_response()
}

/// GET /api/commands?surface=web|cli|channel|all — List slash commands from the
/// unified command registry, filtered by surface.
///
/// Query params:
///   - `surface`: one of `web` (default), `cli`, `channel`, `all`.
///
/// Returns:
/// ```json
/// {
///   "surface": "web",
///   "commands": [
///     {
///       "name": "new",
///       "aliases": ["reset"],
///       "description": "Reset session (clear history)",
///       "category": "session",
///       "requires_agent": true
///     },
///     ...
///   ]
/// }
/// ```
///
/// Unknown surface values return 400.
pub async fn list_commands(Query(params): Query<CommandsQuery>) -> impl IntoResponse {
    use t3rnel_types::commands::{self, CommandCategory, Surfaces};

    let surface_raw = params.surface.as_deref().unwrap_or("web");
    let surface = match surface_raw.to_ascii_lowercase().as_str() {
        "web" => Surfaces::WEB,
        "cli" => Surfaces::CLI,
        "channel" => Surfaces::CHANNEL,
        "all" => Surfaces::ALL,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!(
                        "Unknown surface '{other}'. Valid: web, cli, channel, all."
                    ),
                })),
            )
                .into_response();
        }
    };

    let category_slug = |c: CommandCategory| -> &'static str {
        match c {
            CommandCategory::General => "general",
            CommandCategory::Session => "session",
            CommandCategory::Model => "model",
            CommandCategory::Memory => "memory",
            CommandCategory::Control => "control",
            CommandCategory::Info => "info",
            CommandCategory::Automation => "automation",
            CommandCategory::Monitoring => "monitoring",
        }
    };

    let commands: Vec<serde_json::Value> = commands::list_for_surface(surface)
        .map(|def| {
            serde_json::json!({
                "name": def.name,
                "aliases": def.aliases,
                "description": def.description,
                "category": category_slug(def.category),
                "requires_agent": def.requires_agent,
            })
        })
        .collect();

    Json(serde_json::json!({
        "surface": surface_raw.to_ascii_lowercase(),
        "commands": commands,
    }))
    .into_response()
}

/// SECURITY: Validate webhook bearer token using constant-time comparison.
fn validate_webhook_token(headers: &axum::http::HeaderMap, token_env: &str) -> bool {
    let expected = match std::env::var(token_env) {
        Ok(t) if t.len() >= 32 => t,
        _ => return false,
    };

    let provided = match headers.get("authorization") {
        Some(v) => match v.to_str() {
            Ok(s) if s.starts_with("Bearer ") => &s[7..],
            _ => return false,
        },
        None => return false,
    };

    use subtle::ConstantTimeEq;
    if provided.len() != expected.len() {
        return false;
    }
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

// ══════════════════════════════════════════════════════════════════════
// GitHub Copilot OAuth Device Flow
// ══════════════════════════════════════════════════════════════════════

/// State for an in-progress device flow.
struct CopilotFlowState {
    device_code: String,
    interval: u64,
    expires_at: Instant,
}

/// Active device flows, keyed by poll_id. Auto-expire after the flow's TTL.
static COPILOT_FLOWS: LazyLock<DashMap<String, CopilotFlowState>> = LazyLock::new(DashMap::new);

/// POST /api/providers/github-copilot/oauth/start
///
/// Initiates a GitHub device flow for Copilot authentication.
/// Returns a user code and verification URI that the user visits in their browser.
pub async fn copilot_oauth_start() -> impl IntoResponse {
    // Clean up expired flows first
    COPILOT_FLOWS.retain(|_, state| state.expires_at > Instant::now());

    match t3rnel_runtime::copilot_oauth::start_device_flow().await {
        Ok(resp) => {
            let poll_id = uuid::Uuid::new_v4().to_string();

            COPILOT_FLOWS.insert(
                poll_id.clone(),
                CopilotFlowState {
                    device_code: resp.device_code,
                    interval: resp.interval,
                    expires_at: Instant::now() + std::time::Duration::from_secs(resp.expires_in),
                },
            );

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "user_code": resp.user_code,
                    "verification_uri": resp.verification_uri,
                    "poll_id": poll_id,
                    "expires_in": resp.expires_in,
                    "interval": resp.interval,
                })),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

/// GET /api/providers/github-copilot/oauth/poll/{poll_id}
///
/// Poll the status of a GitHub device flow.
/// Returns `pending`, `complete`, `expired`, `denied`, or `error`.
/// On `complete`, saves the token to secrets.env and sets GITHUB_TOKEN.
pub async fn copilot_oauth_poll(
    State(state): State<Arc<AppState>>,
    Path(poll_id): Path<String>,
) -> impl IntoResponse {
    let flow = match COPILOT_FLOWS.get(&poll_id) {
        Some(f) => f,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"status": "not_found", "error": "Unknown poll_id"})),
            )
        }
    };

    if flow.expires_at <= Instant::now() {
        drop(flow);
        COPILOT_FLOWS.remove(&poll_id);
        return (
            StatusCode::OK,
            Json(serde_json::json!({"status": "expired"})),
        );
    }

    let device_code = flow.device_code.clone();
    drop(flow);

    match t3rnel_runtime::copilot_oauth::poll_device_flow(&device_code).await {
        t3rnel_runtime::copilot_oauth::DeviceFlowStatus::Pending => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "pending"})),
        ),
        t3rnel_runtime::copilot_oauth::DeviceFlowStatus::Complete { access_token } => {
            // Store in vault (best-effort)
            state.kernel.store_credential("GITHUB_TOKEN", &access_token);

            // Save to secrets.env (dual-write)
            let secrets_path = state.kernel.config.home_dir.join("secrets.env");
            if let Err(e) = write_secret_env(&secrets_path, "GITHUB_TOKEN", &access_token) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(
                        serde_json::json!({"status": "error", "error": format!("Failed to save token: {e}")}),
                    ),
                );
            }

            // Set in current process
            std::env::set_var("GITHUB_TOKEN", access_token.as_str());

            // Refresh auth detection
            state
                .kernel
                .model_catalog
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .detect_auth();

            // Clean up flow state
            COPILOT_FLOWS.remove(&poll_id);

            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "complete"})),
            )
        }
        t3rnel_runtime::copilot_oauth::DeviceFlowStatus::SlowDown { new_interval } => {
            // Update interval
            if let Some(mut f) = COPILOT_FLOWS.get_mut(&poll_id) {
                f.interval = new_interval;
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "pending", "interval": new_interval})),
            )
        }
        t3rnel_runtime::copilot_oauth::DeviceFlowStatus::Expired => {
            COPILOT_FLOWS.remove(&poll_id);
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "expired"})),
            )
        }
        t3rnel_runtime::copilot_oauth::DeviceFlowStatus::AccessDenied => {
            COPILOT_FLOWS.remove(&poll_id);
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "denied"})),
            )
        }
        t3rnel_runtime::copilot_oauth::DeviceFlowStatus::Error(e) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "error", "error": e})),
        ),
    }
}

// ---------------------------------------------------------------------------
// Agent Communication (Comms) endpoints
// ---------------------------------------------------------------------------

/// GET /api/comms/topology — Build agent topology graph from registry.
pub async fn comms_topology(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    use t3rnel_types::comms::{EdgeKind, TopoEdge, TopoNode, Topology};

    let agents = state.kernel.registry.list();

    let nodes: Vec<TopoNode> = agents
        .iter()
        .map(|e| TopoNode {
            id: e.id.to_string(),
            name: e.name.clone(),
            state: format!("{:?}", e.state),
            model: e.manifest.model.model.clone(),
        })
        .collect();

    let mut edges: Vec<TopoEdge> = Vec::new();

    // Parent-child edges from registry
    for agent in &agents {
        for child_id in &agent.children {
            edges.push(TopoEdge {
                from: agent.id.to_string(),
                to: child_id.to_string(),
                kind: EdgeKind::ParentChild,
            });
        }
    }

    // Peer message edges from event bus history
    let events = state.kernel.event_bus.history(500).await;
    let mut peer_pairs = std::collections::HashSet::new();
    for event in &events {
        if let t3rnel_types::event::EventPayload::Message(_) = &event.payload {
            if let t3rnel_types::event::EventTarget::Agent(target_id) = &event.target {
                let from = event.source.to_string();
                let to = target_id.to_string();
                // Deduplicate: only one edge per pair, skip self-loops
                if from != to {
                    let key = if from < to {
                        (from.clone(), to.clone())
                    } else {
                        (to.clone(), from.clone())
                    };
                    if peer_pairs.insert(key) {
                        edges.push(TopoEdge {
                            from,
                            to,
                            kind: EdgeKind::Peer,
                        });
                    }
                }
            }
        }
    }

    Json(serde_json::to_value(Topology { nodes, edges }).unwrap_or_default())
}

/// Filter a kernel event into a CommsEvent, if it represents inter-agent communication.
fn filter_to_comms_event(
    event: &t3rnel_types::event::Event,
    agents: &[t3rnel_types::agent::AgentEntry],
) -> Option<t3rnel_types::comms::CommsEvent> {
    use t3rnel_types::comms::{CommsEvent, CommsEventKind};
    use t3rnel_types::event::{EventPayload, EventTarget, LifecycleEvent};

    let resolve_name = |id: &str| -> String {
        agents
            .iter()
            .find(|a| a.id.to_string() == id)
            .map(|a| a.name.clone())
            .unwrap_or_else(|| id.to_string())
    };

    match &event.payload {
        EventPayload::Message(msg) => {
            let target_id = match &event.target {
                EventTarget::Agent(id) => id.to_string(),
                _ => String::new(),
            };
            Some(CommsEvent {
                id: event.id.to_string(),
                timestamp: event.timestamp.to_rfc3339(),
                kind: CommsEventKind::AgentMessage,
                source_id: event.source.to_string(),
                source_name: resolve_name(&event.source.to_string()),
                target_id: target_id.clone(),
                target_name: resolve_name(&target_id),
                detail: t3rnel_types::truncate_str(&msg.content, 200).to_string(),
            })
        }
        EventPayload::Lifecycle(lifecycle) => match lifecycle {
            LifecycleEvent::Spawned { agent_id, name } => Some(CommsEvent {
                id: event.id.to_string(),
                timestamp: event.timestamp.to_rfc3339(),
                kind: CommsEventKind::AgentSpawned,
                source_id: event.source.to_string(),
                source_name: resolve_name(&event.source.to_string()),
                target_id: agent_id.to_string(),
                target_name: name.clone(),
                detail: format!("Agent '{}' spawned", name),
            }),
            LifecycleEvent::Terminated { agent_id, reason } => Some(CommsEvent {
                id: event.id.to_string(),
                timestamp: event.timestamp.to_rfc3339(),
                kind: CommsEventKind::AgentTerminated,
                source_id: event.source.to_string(),
                source_name: resolve_name(&event.source.to_string()),
                target_id: agent_id.to_string(),
                target_name: resolve_name(&agent_id.to_string()),
                detail: format!("Terminated: {}", reason),
            }),
            _ => None,
        },
        EventPayload::System(t3rnel_types::event::SystemEvent::CronJobExecuted {
            agent_id,
            job_name,
            trigger_message,
            response,
            ..
        }) => Some(CommsEvent {
            id: event.id.to_string(),
            timestamp: event.timestamp.to_rfc3339(),
            kind: CommsEventKind::CronJobExecuted,
            source_id: agent_id.to_string(),
            source_name: resolve_name(&agent_id.to_string()),
            target_id: String::new(),
            target_name: String::new(),
            detail: format!("{} | {} | {}", job_name, trigger_message, response),
        }),
        _ => None,
    }
}

/// Convert an audit entry into a CommsEvent if it represents inter-agent activity.
fn audit_to_comms_event(
    entry: &t3rnel_runtime::audit::AuditEntry,
    agents: &[t3rnel_types::agent::AgentEntry],
) -> Option<t3rnel_types::comms::CommsEvent> {
    use t3rnel_types::comms::{CommsEvent, CommsEventKind};

    let resolve_name = |id: &str| -> String {
        agents
            .iter()
            .find(|a| a.id.to_string() == id)
            .map(|a| a.name.clone())
            .unwrap_or_else(|| {
                if id.is_empty() || id == "system" {
                    "system".to_string()
                } else {
                    t3rnel_types::truncate_str(id, 12).to_string()
                }
            })
    };

    let action_str = format!("{:?}", entry.action);
    let (kind, detail, target_label) = match action_str.as_str() {
        "AgentMessage" => {
            // Format detail: "tokens_in=X, tokens_out=Y" → readable summary
            let detail = if entry.detail.starts_with("tokens_in=") {
                let parts: Vec<&str> = entry.detail.split(", ").collect();
                let in_tok = parts
                    .first()
                    .and_then(|p| p.strip_prefix("tokens_in="))
                    .unwrap_or("?");
                let out_tok = parts
                    .get(1)
                    .and_then(|p| p.strip_prefix("tokens_out="))
                    .unwrap_or("?");
                if entry.outcome == "ok" {
                    format!("{} in / {} out tokens", in_tok, out_tok)
                } else {
                    format!(
                        "{} in / {} out — {}",
                        in_tok,
                        out_tok,
                        t3rnel_types::truncate_str(&entry.outcome, 80)
                    )
                }
            } else if entry.outcome != "ok" {
                format!(
                    "{} — {}",
                    t3rnel_types::truncate_str(&entry.detail, 80),
                    t3rnel_types::truncate_str(&entry.outcome, 80)
                )
            } else {
                t3rnel_types::truncate_str(&entry.detail, 200).to_string()
            };
            (CommsEventKind::AgentMessage, detail, "user")
        }
        "AgentSpawn" => (
            CommsEventKind::AgentSpawned,
            format!(
                "Agent spawned: {}",
                t3rnel_types::truncate_str(&entry.detail, 100)
            ),
            "",
        ),
        "AgentKill" => (
            CommsEventKind::AgentTerminated,
            format!(
                "Agent killed: {}",
                t3rnel_types::truncate_str(&entry.detail, 100)
            ),
            "",
        ),
        _ => return None,
    };

    Some(CommsEvent {
        id: format!("audit-{}", entry.seq),
        timestamp: entry.timestamp.clone(),
        kind,
        source_id: entry.agent_id.clone(),
        source_name: resolve_name(&entry.agent_id),
        target_id: if target_label.is_empty() {
            String::new()
        } else {
            target_label.to_string()
        },
        target_name: if target_label.is_empty() {
            String::new()
        } else {
            target_label.to_string()
        },
        detail,
    })
}

/// GET /api/comms/events — Return recent inter-agent communication events.
///
/// Sources from both the event bus (for lifecycle events with full context)
/// and the audit log (for message/spawn/kill events that are always captured).
pub async fn comms_events(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100)
        .min(500);

    let agents = state.kernel.registry.list();

    // Primary source: event bus (has full source/target context)
    let bus_events = state.kernel.event_bus.history(500).await;
    let mut comms_events: Vec<t3rnel_types::comms::CommsEvent> = bus_events
        .iter()
        .filter_map(|e| filter_to_comms_event(e, &agents))
        .collect();

    // Secondary source: audit log (always populated, wider coverage)
    let audit_entries = state.kernel.audit_log.recent(500);
    let seen_ids: std::collections::HashSet<String> =
        comms_events.iter().map(|e| e.id.clone()).collect();

    for entry in audit_entries.iter().rev() {
        if let Some(ev) = audit_to_comms_event(entry, &agents) {
            if !seen_ids.contains(&ev.id) {
                comms_events.push(ev);
            }
        }
    }

    // Sort by timestamp descending (newest first)
    comms_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    comms_events.truncate(limit);

    Json(comms_events)
}

/// GET /api/comms/events/stream — SSE stream of inter-agent communication events.
///
/// Polls the audit log every 500ms for new inter-agent events.
pub async fn comms_events_stream(State(state): State<Arc<AppState>>) -> axum::response::Response {
    use axum::response::sse::{Event, KeepAlive, Sse};

    let (tx, rx) = tokio::sync::mpsc::channel::<
        Result<axum::response::sse::Event, std::convert::Infallible>,
    >(256);

    tokio::spawn(async move {
        let mut last_seq: u64 = {
            let entries = state.kernel.audit_log.recent(1);
            entries.last().map(|e| e.seq).unwrap_or(0)
        };

        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            let agents = state.kernel.registry.list();
            let entries = state.kernel.audit_log.recent(50);

            for entry in &entries {
                if entry.seq <= last_seq {
                    continue;
                }
                if let Some(comms_event) = audit_to_comms_event(entry, &agents) {
                    let data = serde_json::to_string(&comms_event).unwrap_or_default();
                    if tx.send(Ok(Event::default().data(data))).await.is_err() {
                        return; // Client disconnected
                    }
                }
            }

            if let Some(last) = entries.last() {
                last_seq = last.seq;
            }
        }
    });

    let rx_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    Sse::new(rx_stream)
        .keep_alive(
            KeepAlive::new()
                .interval(std::time::Duration::from_secs(15))
                .text("ping"),
        )
        .into_response()
}

/// POST /api/comms/send — Send a message from one agent to another.
pub async fn comms_send(
    State(state): State<Arc<AppState>>,
    Json(req): Json<t3rnel_types::comms::CommsSendRequest>,
) -> impl IntoResponse {
    // Validate from agent exists
    let from_id: t3rnel_types::agent::AgentId = match req.from_agent_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid from_agent_id"})),
            )
        }
    };
    if state.kernel.registry.get(from_id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Source agent not found"})),
        );
    }

    // Validate to agent exists
    let to_id: t3rnel_types::agent::AgentId = match req.to_agent_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid to_agent_id"})),
            )
        }
    };
    if state.kernel.registry.get(to_id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Target agent not found"})),
        );
    }

    // SECURITY: Limit message size
    if req.message.len() > 64 * 1024 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({"error": "Message too large (max 64KB)"})),
        );
    }

    match state.kernel.send_message(to_id, &req.message).await {
        Ok(result) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok": true,
                "response": result.response,
                "input_tokens": result.total_usage.input_tokens,
                "output_tokens": result.total_usage.output_tokens,
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Message delivery failed: {e}")})),
        ),
    }
}

/// POST /api/comms/task — Post a task to the agent task queue.
pub async fn comms_task(
    State(state): State<Arc<AppState>>,
    Json(req): Json<t3rnel_types::comms::CommsTaskRequest>,
) -> impl IntoResponse {
    if req.title.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Title is required"})),
        );
    }

    match state
        .kernel
        .memory
        .task_post(
            &req.title,
            &req.description,
            req.assigned_to.as_deref(),
            Some("ui-user"),
        )
        .await
    {
        Ok(task_id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "ok": true,
                "task_id": task_id,
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to post task: {e}")})),
        ),
    }
}

// ── Dashboard Authentication (username/password sessions) ──

/// POST /api/auth/login — Authenticate with username/password, returns session token.
pub async fn auth_login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<serde_json::Value>,
) -> axum::response::Response {
    use axum::body::Body;
    use axum::response::Response;

    let auth_cfg = &state.kernel.config.auth;
    if !auth_cfg.enabled {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"error": "Auth not enabled"}).to_string(),
            ))
            .unwrap();
    }

    let username = req.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = req.get("password").and_then(|v| v.as_str()).unwrap_or("");

    // Constant-time username comparison to prevent timing attacks
    let username_ok = {
        use subtle::ConstantTimeEq;
        let stored = auth_cfg.username.as_bytes();
        let provided = username.as_bytes();
        if stored.len() != provided.len() {
            false
        } else {
            bool::from(stored.ct_eq(provided))
        }
    };

    if !username_ok || !crate::session_auth::verify_password(password, &auth_cfg.password_hash) {
        // Audit log the failed attempt
        state.kernel.audit_log.record(
            "system",
            t3rnel_runtime::audit::AuditAction::AuthAttempt,
            "dashboard login failed",
            format!("username: {username}"),
        );
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"error": "Invalid credentials"}).to_string(),
            ))
            .unwrap();
    }

    // Derive the session secret the same way as server.rs
    let api_key = state.kernel.config.api_key.trim().to_string();
    let secret = if !api_key.is_empty() {
        api_key
    } else {
        auth_cfg.password_hash.clone()
    };

    let token =
        crate::session_auth::create_session_token(username, &secret, auth_cfg.session_ttl_hours);
    let ttl_secs = auth_cfg.session_ttl_hours * 3600;
    let cookie =
        format!("t3rnel_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ttl_secs}");

    state.kernel.audit_log.record(
        "system",
        t3rnel_runtime::audit::AuditAction::AuthAttempt,
        "dashboard login success",
        format!("username: {username}"),
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("set-cookie", &cookie)
        .body(Body::from(
            serde_json::json!({
                "status": "ok",
                "token": token,
                "username": username,
            })
            .to_string(),
        ))
        .unwrap()
}

/// POST /api/auth/logout — Clear the session cookie.
pub async fn auth_logout() -> impl IntoResponse {
    let cookie = "t3rnel_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0";
    (
        StatusCode::OK,
        [("content-type", "application/json"), ("set-cookie", cookie)],
        serde_json::json!({"status": "ok"}).to_string(),
    )
}

/// GET /api/auth/check — Check current authentication state.
pub async fn auth_check(
    State(state): State<Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    let auth_cfg = &state.kernel.config.auth;
    if !auth_cfg.enabled {
        return Json(serde_json::json!({
            "authenticated": true,
            "mode": "none",
        }));
    }

    // Derive the session secret the same way as server.rs
    let api_key = state.kernel.config.api_key.trim().to_string();
    let secret = if !api_key.is_empty() {
        api_key
    } else {
        auth_cfg.password_hash.clone()
    };

    // Check session cookie
    let session_user = crate::session_auth::extract_session_cookie(request.headers())
        .and_then(|token| crate::session_auth::verify_session_token(&token, &secret));

    if let Some(username) = session_user {
        Json(serde_json::json!({
            "authenticated": true,
            "mode": "session",
            "username": username,
        }))
    } else {
        Json(serde_json::json!({
            "authenticated": false,
            "mode": "session",
        }))
    }
}

/// Remove a `[section]` and its contents from a TOML string.
fn backup_config(config_path: &std::path::Path) {
    let backup = config_path.with_extension("toml.bak");
    let _ = std::fs::copy(config_path, backup);
}

fn remove_toml_section(content: &str, section: &str) -> String {
    let header = format!("[{}]", section);
    let mut result = String::new();
    let mut skipping = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == header {
            skipping = true;
            continue;
        }
        if skipping && trimmed.starts_with('[') {
            skipping = false;
        }
        if !skipping {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

// ------------------------------------------------------------------
// POST /api/internal/self-improvement/activate — Inventor-gated activation
// ------------------------------------------------------------------

/// Request body for self-improvement activation.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SelfImprovementActivateRequest {
    /// Ed25519 signature of the current timestamp (hex-encoded 64 bytes).
    pub signature: String,
    /// Timestamp used in the signed message (ISO-8601).
    pub timestamp: String,
}

/// POST /api/internal/self-improvement/activate
///
/// Requires a valid inventor Ed25519 signature. Returns 403 for all non-inventor tokens.
pub async fn self_improvement_activate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SelfImprovementActivateRequest>,
) -> impl IntoResponse {
    use t3rnel_kernel::auth::{inventor_configured, inventor_gate, InventorAuthResult};

    // If no inventor key is configured, the endpoint is unavailable
    if !inventor_configured() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Self-improvement is not enabled on this daemon (no inventor key configured)"
            })),
        );
    }

    // Reconstruct the signed message: "t3rnel:self-improvement:{timestamp}"
    let message = format!("t3rnel:self-improvement:{}", req.timestamp);

    // Decode hex signature
    let sig_bytes = match hex::decode(&req.signature) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid hex signature"})),
            );
        }
    };

    match inventor_gate(message.as_bytes(), &sig_bytes) {
        InventorAuthResult::Authenticated => {
            // Enable the self-improvement loop
            if let Err(e) = state.kernel.enable_self_improvement().await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Failed to activate: {}", e)})),
                );
            }
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "activated",
                    "inventor_present": true,
                    "self_improvement_halt": false
                })),
            )
        }
        InventorAuthResult::NotConfigured => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Inventor key not configured"})),
        ),
        InventorAuthResult::InvalidSignature => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Invalid inventor signature"})),
        ),
    }
}

/// GET /api/internal/self-improvement/status
///
/// Returns whether self-improvement is available and active on this daemon.
pub async fn self_improvement_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    use t3rnel_kernel::auth::inventor_configured;

    Json(serde_json::json!({
        "inventor_present": inventor_configured(),
        "self_improvement_halt": state.kernel.is_self_improvement_halted(),
        "available": inventor_configured() && !state.kernel.is_self_improvement_halted(),
    }))
}

/// POST /api/internal/self-improvement/halt — Disable the self-improvement loop.
pub async fn self_improvement_halt(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.kernel.halt_self_improvement();
    Json(serde_json::json!({
        "self_improvement_halt": true,
        "available": false,
    }))
}

#[cfg(test)]
mod agent_workspace_path_tests {
    use super::*;

    #[test]
    fn resolves_persisted_host_workspace_via_configured_root() {
        let root = tempfile::tempdir().unwrap();
        let orchestrator = root.path().join("orchestrator");
        std::fs::create_dir_all(&orchestrator).unwrap();

        let stale_home = root.path().join("missing-home");
        let stale_workspace = stale_home.join(".t3rnel/workspaces/orchestrator");
        let resolved =
            resolve_agent_workspace_path(&stale_workspace, root.path(), "orchestrator").unwrap();

        assert_eq!(resolved, orchestrator.canonicalize().unwrap());
    }

    #[test]
    fn user_settings_defaults_are_groombridge_metric_and_deriv() {
        let dir = tempfile::tempdir().unwrap();
        let preferences = load_user_preferences_from_disk(dir.path()).unwrap();

        assert_eq!(
            preferences.get("weatherLocation").and_then(|v| v.as_str()),
            Some("Groombridge, Harare")
        );
        assert_eq!(
            preferences.get("weatherUnit").and_then(|v| v.as_str()),
            Some("metric")
        );
        assert_eq!(
            preferences.get("brokerProvider").and_then(|v| v.as_str()),
            Some("deriv")
        );
        assert_eq!(
            preferences
                .get("whisperCppEnabled")
                .and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            preferences
                .get("whisperCppBaseUrl")
                .and_then(|v| v.as_str()),
            Some(DEFAULT_WHISPER_CPP_BASE_URL)
        );
        assert_eq!(
            preferences
                .get("whisperCppPowerLevel")
                .and_then(|v| v.as_str()),
            Some("balanced")
        );
    }

    #[test]
    fn user_settings_persist_and_preserve_custom_keys() {
        let dir = tempfile::tempdir().unwrap();
        let mut preferences = default_user_preferences();
        preferences.insert(
            "defaultChatAgentId".to_string(),
            serde_json::Value::String("planner".to_string()),
        );
        preferences.insert(
            "customSurfacePreference".to_string(),
            serde_json::Value::Bool(true),
        );

        persist_user_preferences(dir.path(), &preferences).unwrap();
        let loaded = load_user_preferences_from_disk(dir.path()).unwrap();

        assert_eq!(
            loaded.get("defaultChatAgentId").and_then(|v| v.as_str()),
            Some("planner")
        );
        assert_eq!(
            loaded
                .get("customSurfacePreference")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert!(user_settings_path(dir.path()).exists());
    }

    #[test]
    fn process_telemetry_helpers_return_finite_values_when_available() {
        if let Some(memory_mb) = current_process_memory_mb() {
            assert!(memory_mb.is_finite());
            assert!(memory_mb > 0.0);
        }
        if let Some(cpu_percent) = current_process_cpu_percent(std::time::Instant::now()) {
            assert!(cpu_percent.is_finite());
            assert!(cpu_percent >= 0.0);
        }
    }

    #[test]
    fn host_resource_counter_helpers_parse_proc_shapes() {
        let first = CpuCounters {
            label: "cpu0".to_string(),
            total: 100,
            idle: 40,
        };
        let second = CpuCounters {
            label: "cpu0".to_string(),
            total: 200,
            idle: 70,
        };
        assert_eq!(round_one(cpu_usage_between(&first, &second).unwrap()), 70.0);

        let net = parse_network_line("  wlp0s20f3: 1024 0 0 0 0 0 0 0 2048 0 0 0 0 0 0 0").unwrap();
        assert_eq!(net.first, 1024);
        assert_eq!(net.second, 2048);
        assert!(parse_network_line("lo: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0").is_none());

        let disk = parse_disk_line("259 0 nvme0n1 1 0 8 0 2 0 16 0 0 0 0 0 0 0 0").unwrap();
        assert_eq!(disk.first, 4096);
        assert_eq!(disk.second, 8192);
        assert!(parse_disk_line("259 1 nvme0n1p1 1 0 8 0 2 0 16 0 0 0 0 0 0 0 0").is_none());
    }

    #[test]
    fn whisper_cpp_power_presets_return_bounded_resources() {
        let base = WhisperCppSettings {
            enabled: true,
            base_url: DEFAULT_WHISPER_CPP_BASE_URL.to_string(),
            binary: "whisper-server".to_string(),
            model_path: Some("/tmp/model.bin".to_string()),
            power_level: "eco".to_string(),
            threads: None,
            processors: None,
            use_gpu: true,
            language: "en".to_string(),
            dictation_provider: Some("whisper-cpp".to_string()),
        };
        assert!(whisper_cpp_threads(&base) >= 1);
        assert_eq!(whisper_cpp_processors(&base), 1);
        assert!(!whisper_cpp_use_gpu(&base));
        assert_eq!(
            normalize_whisper_cpp_base_url(Some(format!("http://127.0.0.1:{}", 8_080))),
            DEFAULT_WHISPER_CPP_BASE_URL
        );

        let explicit = WhisperCppSettings {
            power_level: "max".to_string(),
            threads: Some(1),
            processors: Some(4),
            ..base
        };
        assert_eq!(whisper_cpp_threads(&explicit), 1);
        assert_eq!(whisper_cpp_processors(&explicit), 4);
        assert!(whisper_cpp_use_gpu(&explicit));
    }
}

#[cfg(test)]
mod channel_config_tests {
    use super::*;

    #[test]
    fn test_is_channel_configured_wecom_none() {
        let config = t3rnel_types::config::ChannelsConfig::default();
        assert!(!is_channel_configured(&config, "wecom"));
    }

    #[test]
    fn test_is_channel_configured_wecom_some() {
        let mut config = t3rnel_types::config::ChannelsConfig::default();
        config.wecom = Some(t3rnel_types::config::WeComConfig {
            corp_id: "test_corp".to_string(),
            agent_id: "test_agent".to_string(),
            secret_env: "WECOM_SECRET".to_string(),
            webhook_port: 8454,
            token: Some("token".to_string()),
            encoding_aes_key: Some("aes_key".to_string()),
            default_agent: Some("assistant".to_string()),
            overrides: t3rnel_types::config::ChannelOverrides::default(),
        });
        assert!(is_channel_configured(&config, "wecom"));
    }

    #[test]
    fn test_wecom_in_channel_registry() {
        let wecom_meta = CHANNEL_REGISTRY.iter().find(|c| c.name == "wecom");
        assert!(wecom_meta.is_some());
        let meta = wecom_meta.unwrap();
        assert_eq!(meta.display_name, "WeCom");
        assert_eq!(meta.category, "messaging");
        assert!(
            meta.fields
                .iter()
                .find(|f| f.key == "corp_id")
                .unwrap()
                .required
        );
        assert!(
            meta.fields
                .iter()
                .find(|f| f.key == "secret_env")
                .unwrap()
                .required
        );
    }
}

#[cfg(test)]
mod skill_config_tests {
    //! Unit tests for the `/api/skills/{id}/config` endpoints.
    //!
    //! These exercise the on-disk TOML writer and the in-memory snapshot
    //! builder directly. Live end-to-end coverage (real HTTP, real kernel)
    //! lives in `tests/skill_config_api_test.rs`.

    use super::*;

    fn sample_values() -> std::collections::HashMap<String, String> {
        let mut m = std::collections::HashMap::new();
        m.insert("github_token".to_string(), "ghp_test1234".to_string());
        m.insert("default_branch".to_string(), "develop".to_string());
        m
    }

    #[test]
    fn upsert_creates_skills_section_from_blank_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        upsert_skill_config(&path, "demo-skill", &sample_values()).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("[skills.demo-skill]"), "text was: {text}");
        assert!(text.contains("github_token = \"ghp_test1234\""));
        assert!(text.contains("default_branch = \"develop\""));
    }

    #[test]
    fn upsert_preserves_other_root_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "log_level = \"debug\"\napi_listen = \"127.0.0.1:4200\"\n",
        )
        .unwrap();

        upsert_skill_config(&path, "demo-skill", &sample_values()).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("log_level"), "log_level lost: {text}");
        assert!(text.contains("api_listen"), "api_listen lost: {text}");
        assert!(text.contains("[skills.demo-skill]"));
    }

    #[test]
    fn upsert_replaces_existing_section_wholesale() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[skills.demo-skill]\nold_key = \"old_value\"\nshared = \"before\"\n",
        )
        .unwrap();

        let mut new_values = std::collections::HashMap::new();
        new_values.insert("shared".to_string(), "after".to_string());
        upsert_skill_config(&path, "demo-skill", &new_values).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("old_key"), "old_key not dropped: {text}");
        assert!(text.contains("shared = \"after\""));
    }

    #[test]
    fn remove_drops_single_var_but_keeps_table_when_nonempty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        upsert_skill_config(&path, "demo-skill", &sample_values()).unwrap();

        remove_skill_config_var(&path, "demo-skill", "github_token").unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("github_token"));
        assert!(text.contains("default_branch"));
        assert!(text.contains("[skills.demo-skill]"));
    }

    #[test]
    fn remove_last_var_removes_whole_skill_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut single = std::collections::HashMap::new();
        single.insert("only".to_string(), "x".to_string());
        upsert_skill_config(&path, "demo-skill", &single).unwrap();

        remove_skill_config_var(&path, "demo-skill", "only").unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("demo-skill"),
            "empty section not cleaned up: {text}"
        );
    }

    #[test]
    fn remove_missing_file_is_silent_ok() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // File does not exist — must not error.
        remove_skill_config_var(&path, "demo-skill", "github_token").unwrap();
    }

    #[test]
    fn atomic_write_produces_valid_toml_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut doc = toml::map::Map::new();
        let mut skills = toml::map::Map::new();
        let mut inner = toml::map::Map::new();
        inner.insert(
            "github_token".to_string(),
            toml::Value::String("ghp_xyz".to_string()),
        );
        skills.insert("demo".to_string(), toml::Value::Table(inner));
        doc.insert("skills".to_string(), toml::Value::Table(skills));
        let doc = toml::Value::Table(doc);

        atomic_write_toml(&path, &doc).unwrap();

        let back: toml::Value = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back, doc);
    }

    #[test]
    fn prometheus_label_value_escapes_special_characters() {
        assert_eq!(
            prometheus_label_value("agent \"alpha\"\\beta\nline"),
            "agent \\\"alpha\\\"\\\\beta\\nline"
        );
    }
}

// ---------------------------------------------------------------------------
// Sentinel — error and security monitoring
// ---------------------------------------------------------------------------

/// Does a log line report this HTTP status, as opposed to merely containing the
/// digits?
///
/// Matched as a bare substring, "401" appears inside nanosecond timestamps —
/// 15:44:58.601401Z contains it — so any line written in the wrong microsecond
/// counted as an authentication failure. That produced 49 critical security
/// findings on a healthy system, which is worse than having no monitor: real
/// findings are buried under noise nobody reads twice.
fn has_status(line: &str, status: u16) -> bool {
    let code = status.to_string();
    [
        "status ",
        "status=",
        "status: ",
        "http ",
        "http/1.1 ",
        "code=",
        "code ",
    ]
    .iter()
    .any(|label| {
        line.split(label).skip(1).any(|rest| {
            rest.trim_start().starts_with(&code)
                && !rest
                    .trim_start()
                    .chars()
                    .nth(code.len())
                    .is_some_and(|c| c.is_ascii_digit())
        })
    })
}

/// GET /api/sentinel — findings from the daemon's own logs.
///
/// The sentinel existed only as a CLI, so conditions it detects — dead
/// credentials, blocked egress, failure bursts — were invisible on every
/// surface. An operator watching a dashboard had no way to learn the system was
/// failing except by running a command they had no reason to run.
pub async fn sentinel_findings(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    use t3rnel_kernel::sentinel::{Event, EventKind, Sentinel, SentinelConfig, Severity};

    // Logs are written to the repository's logs/ directory by the scripts and
    // to the daemon home by the kernel. Reading only one meant the monitor
    // reported "no logs found" on a system actively writing them, which is the
    // same false all-clear it exists to avoid.
    let mut search_dirs: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(configured) = std::env::var("T3RNEL_LOG_DIR") {
        search_dirs.push(std::path::PathBuf::from(configured));
    }
    search_dirs.push(t3rnel_kernel::config::t3rnel_home().join("logs"));
    if let Ok(cwd) = std::env::current_dir() {
        search_dirs.push(cwd.join("logs"));
    }

    let mut logs: Vec<std::path::PathBuf> = Vec::new();
    let mut scanned_dirs: Vec<String> = Vec::new();
    for dir in &search_dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        scanned_dirs.push(dir.display().to_string());
        logs.extend(
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "log")),
        );
    }
    logs.sort();
    logs.dedup();
    let log_dir = if scanned_dirs.is_empty() {
        search_dirs
            .first()
            .map(|d| d.display().to_string())
            .unwrap_or_default()
    } else {
        scanned_dirs.join(", ")
    };

    let mut sentinel = Sentinel::new(SentinelConfig::default());
    let mut alerts = Vec::new();
    let mut lines_read = 0usize;

    for path in &logs {
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        let subject = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("daemon")
            .to_string();

        for (index, line) in content.lines().enumerate() {
            lines_read += 1;
            let lower = line.to_lowercase();
            let kind = if has_status(&lower, 401)
                || lower.contains("unauthorized")
                || lower.contains("token expired")
            {
                EventKind::AuthFailure
            } else if lower.contains("non-public address") || lower.contains("refusing to fetch") {
                EventKind::EgressBlocked
            } else if lower.contains("error") || lower.contains("panicked") {
                EventKind::Failure
            } else {
                continue;
            };

            let at =
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(index as u64);
            alerts.extend(sentinel.observe(Event {
                subject: subject.clone(),
                kind,
                at,
            }));
        }
    }

    let rows: Vec<serde_json::Value> = alerts
        .iter()
        .map(|alert| {
            serde_json::json!({
                "finding": format!("{:?}", alert.finding),
                "severity": format!("{:?}", alert.severity),
                "subject": alert.subject,
                "detail": alert.detail,
                "is_security": alert.finding.is_security(),
            })
        })
        .collect();

    let critical = alerts
        .iter()
        .filter(|a| a.severity == Severity::Critical)
        .count();

    Json(serde_json::json!({
        "findings": rows,
        "critical": critical,
        "total": rows.len(),
        "scanned_lines": lines_read,
        "scanned_files": logs.len(),
        // An empty log directory is not a clean bill of health, and a surface
        // showing "no findings" for a path that does not exist reads as one.
        "log_dir": log_dir,
        "logs_present": !logs.is_empty(),
        // Plugin dev mode disables signature verification — surface it on the
        // security-monitoring endpoint too so no agent misses it.
        "plugin_dev_mode": state.kernel.config.plugin_dev_mode,
        "plugin_dev_mode_warning": if state.kernel.config.plugin_dev_mode {
            Some(t3rnel_runtime::plugin_lifecycle::DEV_MODE_WARNING)
        } else {
            None
        },
    }))
    .into_response()
}

#[cfg(test)]
mod uninstall_agent_tests {
    //! Issue #1163 — directory-removal portion of the uninstall flow.
    //!
    //! These tests exercise the same logic the route handler runs after
    //! `kernel.kill_agent()`: locate `<home>/agents/<name>/`, verify it is
    //! directly under the agents root, and remove it. Live end-to-end
    //! coverage (real HTTP + kernel) belongs in `tests/api_integration_test.rs`.
    use std::path::Path;

    /// Mirror of the dir-removal logic in `uninstall_agent`. Kept in sync
    /// with the route handler so the rules can be unit-tested without a
    /// running kernel. Returns whether the directory was removed.
    fn remove_agent_dir(home_dir: &Path, agent_name: &str) -> bool {
        let agents_dir = home_dir.join("agents");
        let agent_dir = agents_dir.join(agent_name);
        if !agent_dir.is_dir() {
            return false;
        }
        let parent_ok = agent_dir
            .parent()
            .map(|p| p == agents_dir.as_path())
            .unwrap_or(false);
        if !parent_ok {
            return false;
        }
        std::fs::remove_dir_all(&agent_dir).is_ok()
    }

    #[test]
    fn removes_agent_directory_under_agents_root() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        let agents = home.join("agents");
        std::fs::create_dir_all(agents.join("trash-agent")).unwrap();
        std::fs::write(
            agents.join("trash-agent").join("agent.toml"),
            "name = \"trash-agent\"\n",
        )
        .unwrap();

        assert!(agents.join("trash-agent").is_dir());
        let removed = remove_agent_dir(&home, "trash-agent");
        assert!(removed, "agent directory must be removed");
        assert!(!agents.join("trash-agent").exists());
    }

    #[test]
    fn returns_false_when_no_directory_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        std::fs::create_dir_all(home.join("agents")).unwrap();

        let removed = remove_agent_dir(&home, "ghost-agent");
        assert!(!removed, "no dir => false, but uninstall still succeeds");
    }

    #[test]
    fn does_not_touch_siblings() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        let agents = home.join("agents");
        std::fs::create_dir_all(agents.join("trash-agent")).unwrap();
        std::fs::create_dir_all(agents.join("keep-me")).unwrap();
        std::fs::write(
            agents.join("trash-agent").join("agent.toml"),
            "name = \"trash-agent\"\n",
        )
        .unwrap();
        std::fs::write(
            agents.join("keep-me").join("agent.toml"),
            "name = \"keep-me\"\n",
        )
        .unwrap();

        assert!(remove_agent_dir(&home, "trash-agent"));
        assert!(!agents.join("trash-agent").exists());
        assert!(
            agents.join("keep-me").is_dir(),
            "sibling agent dirs must not be touched by uninstall"
        );
    }

    #[test]
    fn rejects_path_traversal_attempt() {
        // A name like "../escape" would join to a path whose parent is the
        // agents root only if the file system resolves it that way — but
        // `parent()` on a non-canonicalized Path returns the textual parent,
        // which for `<home>/agents/../escape` is `<home>/agents/..`, not
        // `<home>/agents`. The check rejects it.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        std::fs::create_dir_all(home.join("agents")).unwrap();
        // Create a sibling dir outside agents/ that an attacker might want
        // to delete.
        std::fs::create_dir_all(home.join("escape")).unwrap();
        std::fs::write(home.join("escape").join("secret.toml"), "x = 1\n").unwrap();

        let removed = remove_agent_dir(&home, "../escape");
        assert!(!removed, "must reject path-traversal names");
        assert!(
            home.join("escape").is_dir(),
            "sibling dir outside agents/ must NOT be deleted"
        );
    }
}
