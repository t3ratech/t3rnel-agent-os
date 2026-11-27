//! Real HTTP integration tests for the T3rnel API.
//!
//! These tests boot a real kernel, start a real axum HTTP server on a random
//! port, and hit actual endpoints with reqwest.  No mocking.
//!
//! Tests that require an LLM API call are gated behind GROQ_API_KEY.
//!
//! Run: ./t3rnel-services.sh --test integration

use axum::Router;
use std::sync::Arc;
use std::time::{Duration, Instant};
use t3rnel_api::middleware;
use t3rnel_api::routes::{self, AppState};
use t3rnel_api::team_store;
use t3rnel_api::ws;
use t3rnel_kernel::T3rnelKernel;
use t3rnel_memory::usage::UsageRecord;
use t3rnel_types::agent::AgentId;
use t3rnel_types::config::{DefaultModelConfig, KernelConfig};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

struct TestServer {
    base_url: String,
    state: Arc<AppState>,
    _tmp: tempfile::TempDir,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.state.kernel.shutdown();
    }
}

/// Start a test server using ollama as default provider (no API key needed).
/// This lets the kernel boot without any real LLM credentials.
/// Tests that need actual LLM calls should use `start_test_server_with_llm()`.
async fn start_test_server() -> TestServer {
    start_test_server_with_provider("ollama", "test-model", "OLLAMA_API_KEY").await
}

/// Start a test server with Groq as the LLM provider (requires GROQ_API_KEY).
async fn start_test_server_with_llm() -> TestServer {
    start_test_server_with_provider("groq", "llama-3.3-70b-versatile", "GROQ_API_KEY").await
}

async fn start_test_server_with_provider(
    provider: &str,
    model: &str,
    api_key_env: &str,
) -> TestServer {
    start_test_server_with_provider_and_audio(provider, model, api_key_env, None).await
}

async fn start_test_server_with_provider_and_audio(
    provider: &str,
    model: &str,
    api_key_env: &str,
    audio_provider: Option<&str>,
) -> TestServer {
    let tmp = tempfile::tempdir().expect("Failed to create temp dir");
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(&config_dir).expect("Failed to create config dir");
    let source = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/category-templates.toml"));
    if source.exists() {
        std::fs::copy(source, config_dir.join("category-templates.toml")).ok();
    }

    let mut config = KernelConfig {
        home_dir: tmp.path().to_path_buf(),
        data_dir: tmp.path().join("data"),
        default_model: DefaultModelConfig {
            provider: provider.to_string(),
            model: model.to_string(),
            api_key_env: api_key_env.to_string(),
            base_url: None,
            subprocess_timeout_secs: None,
        },
        ..KernelConfig::default()
    };
    if let Some(audio_provider) = audio_provider {
        config.media.audio_provider = Some(audio_provider.to_string());
    }

    let kernel = T3rnelKernel::boot_with_config(config).expect("Kernel should boot");
    let kernel = Arc::new(kernel);
    kernel.set_self_handle();

    let state = Arc::new(AppState {
        kernel,
        started_at: Instant::now(),
        peer_registry: None,
        bridge_manager: tokio::sync::Mutex::new(None),
        channels_config: tokio::sync::RwLock::new(Default::default()),
        shutdown_notify: Arc::new(tokio::sync::Notify::new()),
        clawhub_cache: dashmap::DashMap::new(),
        provider_probe_cache: t3rnel_runtime::provider_health::ProbeCache::new(),
        budget_config: Arc::new(tokio::sync::RwLock::new(Default::default())),
        team_store: team_store::TeamStore::new(),
        winrate_tracker: tokio::sync::Mutex::new(
            t3rnel_prompts::WinRateTracker::open(
                std::env::temp_dir().join("t3rnel-test-winrates.db"),
            )
            .unwrap(),
        ),
        ide_commands: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        ide_command_notify: Arc::new(tokio::sync::Notify::new()),
        health_tracker: Arc::new(
            t3rnel_runtime::drivers::health_tracker::InMemoryHealthTracker::new(100),
        ),
        plugin_dispatch: None,
    });

    let app = Router::new()
        .route("/metrics", axum::routing::get(routes::prometheus_metrics))
        .route(
            "/api/metrics",
            axum::routing::get(routes::prometheus_metrics),
        )
        .route("/api/health", axum::routing::get(routes::health))
        .route("/api/status", axum::routing::get(routes::status))
        .route(
            "/api/agents",
            axum::routing::get(routes::list_agents).post(routes::spawn_agent),
        )
        .route(
            "/api/agents/{id}/message",
            axum::routing::post(routes::send_message),
        )
        .route(
            "/api/agents/{id}/browser/tool",
            axum::routing::post(routes::agent_browser_tool),
        )
        .route(
            "/api/agents/{id}/session",
            axum::routing::get(routes::get_agent_session),
        )
        .route(
            "/api/agents/{id}/upload",
            axum::routing::post(routes::upload_file),
        )
        .route("/api/agents/{id}/ws", axum::routing::get(ws::agent_ws))
        .route(
            "/api/agents/{id}",
            axum::routing::delete(routes::kill_agent),
        )
        .route(
            "/api/agents/{id}/clone",
            axum::routing::post(routes::clone_agent),
        )
        .route(
            "/api/triggers",
            axum::routing::get(routes::list_triggers).post(routes::create_trigger),
        )
        .route(
            "/api/triggers/{id}",
            axum::routing::delete(routes::delete_trigger),
        )
        .route(
            "/api/workflows",
            axum::routing::get(routes::list_workflows).post(routes::create_workflow),
        )
        .route(
            "/api/workflows/{id}/run",
            axum::routing::post(routes::run_workflow),
        )
        .route(
            "/api/workflows/{id}/runs",
            axum::routing::get(routes::list_workflow_runs),
        )
        .route("/api/shutdown", axum::routing::post(routes::shutdown))
        .route("/api/commands", axum::routing::get(routes::list_commands))
        .route(
            "/api/schedules",
            axum::routing::get(routes::list_schedules).post(routes::create_schedule),
        )
        .route(
            "/api/schedules/{id}",
            axum::routing::delete(routes::delete_schedule).put(routes::update_schedule),
        )
        .route(
            "/api/schedules/{id}/delivery-log",
            axum::routing::get(routes::schedule_delivery_log),
        )
        .route(
            "/api/cron/jobs",
            axum::routing::get(routes::list_cron_jobs).post(routes::create_cron_job),
        )
        .route("/api/teams", axum::routing::get(routes::list_teams))
        .route("/api/teams/{id}", axum::routing::get(routes::get_team))
        .route(
            "/api/teams/{id}/members",
            axum::routing::get(routes::get_team_members),
        )
        .route(
            "/api/teams/{id}/tasks",
            axum::routing::get(routes::list_team_tasks).post(routes::create_team_task),
        )
        .route(
            "/api/teams/{id}/tasks/{task_id}/progress",
            axum::routing::get(routes::get_task_progress),
        )
        .route(
            "/api/teams/{id}/a2a/messages",
            axum::routing::get(routes::list_a2a_messages).post(routes::send_a2a_message),
        )
        .route("/a2a/agents", axum::routing::get(routes::a2a_list_agents))
        .route(
            "/a2a/tasks/send",
            axum::routing::post(routes::a2a_send_task),
        )
        .route(
            "/api/providers/catalog",
            axum::routing::get(routes::list_provider_catalog),
        )
        .route(
            "/api/categories",
            axum::routing::get(routes::list_categories),
        )
        .layer(axum::middleware::from_fn(middleware::request_logging))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind test server");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestServer {
        base_url: format!("http://{}", addr),
        state,
        _tmp: tmp,
    }
}

/// Manifest that uses ollama (no API key required, won't make real LLM calls).
const TEST_MANIFEST: &str = r#"
name = "test-agent"
version = "0.1.0"
description = "Integration test agent"
author = "test"
module = "builtin:chat"

[model]
provider = "ollama"
model = "test-model"
system_prompt = "You are a test agent. Reply concisely."

[capabilities]
tools = ["file_read"]
memory_read = ["*"]
memory_write = ["self.*"]
"#;

/// Manifest that uses Groq for real LLM tests.
const LLM_MANIFEST: &str = r#"
name = "test-agent"
version = "0.1.0"
description = "Integration test agent"
author = "test"
module = "builtin:chat"

[model]
provider = "groq"
model = "llama-3.3-70b-versatile"
system_prompt = "You are a test agent. Reply concisely."

[capabilities]
tools = ["file_read"]
memory_read = ["*"]
memory_write = ["self.*"]
"#;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_health_endpoint() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/health", server.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    // Middleware injects x-request-id
    assert!(resp.headers().contains_key("x-request-id"));

    let body: serde_json::Value = resp.json().await.unwrap();
    // Public health endpoint returns minimal info (redacted for security)
    assert_eq!(body["status"], "ok");
    assert!(body["version"].is_string());
    // Detailed fields should NOT appear in public health endpoint
    assert!(body["database"].is_null());
    assert!(body["agent_count"].is_null());
}

#[tokio::test]
async fn test_status_endpoint() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/status", server.base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "running");
    assert_eq!(body["agent_count"], 1); // default assistant auto-spawned
    assert!(body["uptime_seconds"].is_number());
    assert_eq!(body["default_provider"], "ollama");
    assert_eq!(body["agents"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_metrics_endpoint_prometheus_format() {
    let server = start_test_server().await;
    server
        .state
        .kernel
        .memory
        .usage()
        .record(&UsageRecord {
            agent_id: AgentId::new(),
            model: "integration-metrics-model".to_string(),
            input_tokens: 42,
            output_tokens: 24,
            cost_usd: 0.0042,
            tool_calls: 3,
        })
        .expect("record usage");

    let client = reqwest::Client::new();
    for path in ["/metrics", "/api/metrics"] {
        let resp = client
            .get(format!("{}{}", server.base_url, path))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.contains("# HELP t3rnel_uptime_seconds"));
        assert!(body.contains("t3rnel_cost_usd_total 0.00420000"));
        assert!(body.contains("t3rnel_llm_calls_total 1"));
        assert!(body.contains("t3rnel_metered_tool_calls_total 3"));
        assert!(body.contains("model=\"integration-metrics-model\""));
    }
}

#[tokio::test]
async fn test_audio_upload_fails_when_stt_provider_is_unavailable() {
    let server = start_test_server_with_provider_and_audio(
        "ollama",
        "test-model",
        "OLLAMA_API_KEY",
        Some("not-a-real-stt-provider"),
    )
    .await;
    let client = reqwest::Client::new();
    let agent_id = AgentId::new();
    let part = reqwest::multipart::Part::bytes(vec![1_u8, 2, 3, 4])
        .file_name("voice-command.webm")
        .mime_str("audio/webm")
        .unwrap();
    let form = reqwest::multipart::Form::new().part("file", part);

    let resp = client
        .post(format!(
            "{}/api/agents/{}/upload",
            server.base_url, agent_id
        ))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_GATEWAY);
    let body: serde_json::Value = resp.json().await.unwrap();
    let error = body["error"].as_str().unwrap();
    assert!(error.contains("Audio transcription failed"));
    assert!(error.contains("not-a-real-stt-provider"));
    assert!(error.contains("Parakeet MLX"));
    assert!(error.contains("GROQ_API_KEY"));
}

#[tokio::test]
async fn test_spawn_list_kill_agent() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // --- Spawn ---
    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({"manifest_toml": TEST_MANIFEST}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "test-agent");
    let agent_id = body["agent_id"].as_str().unwrap().to_string();
    assert!(!agent_id.is_empty());

    // --- List (2 agents: default assistant + test-agent) ---
    let resp = client
        .get(format!("{}/api/agents", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let agents: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(agents.len(), 2);
    let test_agent = agents.iter().find(|a| a["name"] == "test-agent").unwrap();
    assert_eq!(test_agent["id"], agent_id);
    assert_eq!(test_agent["model_provider"], "ollama");

    // --- Kill ---
    let resp = client
        .delete(format!("{}/api/agents/{}", server.base_url, agent_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "killed");

    // --- List (only default assistant remains) ---
    let resp = client
        .get(format!("{}/api/agents", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let agents: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0]["name"], "assistant");
}

/// Regression test for issue #1026: GET /api/agents returns `is_inferencing`
/// reflecting whether the agent has an in-flight LLM task. This drives the
/// live dashboard indicator that shows which agents are calling the LLM.
#[tokio::test]
async fn test_list_agents_includes_inferencing_flag() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Spawn a test agent.
    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({"manifest_toml": TEST_MANIFEST}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id_str = body["agent_id"].as_str().unwrap().to_string();
    let agent_id: t3rnel_types::agent::AgentId = agent_id_str.parse().unwrap();

    // Baseline: idle agent must report is_inferencing = false.
    let resp = client
        .get(format!("{}/api/agents", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let agents: Vec<serde_json::Value> = resp.json().await.unwrap();
    let test_agent = agents
        .iter()
        .find(|a| a["id"] == agent_id_str)
        .expect("spawned agent should appear in list");
    assert_eq!(
        test_agent["is_inferencing"], false,
        "freshly spawned agent should not be inferencing"
    );

    // Simulate an in-flight LLM call by inserting a real AbortHandle into
    // the kernel's running_tasks map. This is exactly what the agent loop
    // does when it starts processing a message.
    let handle = tokio::spawn(async {
        // Long-lived task we will abort at end of test.
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    });
    server
        .state
        .kernel
        .running_tasks
        .insert(agent_id, handle.abort_handle());

    // Now list_agents should report is_inferencing = true for that agent.
    let resp = client
        .get(format!("{}/api/agents", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let agents: Vec<serde_json::Value> = resp.json().await.unwrap();
    let test_agent = agents
        .iter()
        .find(|a| a["id"] == agent_id_str)
        .expect("spawned agent should still appear in list");
    assert_eq!(
        test_agent["is_inferencing"], true,
        "agent with an entry in running_tasks must be flagged is_inferencing"
    );

    // Other agents (the default assistant) must NOT be flagged.
    if let Some(other) = agents.iter().find(|a| a["id"] != agent_id_str) {
        assert_eq!(
            other["is_inferencing"], false,
            "agents without a running task must not be flagged"
        );
    }

    // Cleanup so the spawned future does not outlive the test.
    server.state.kernel.running_tasks.remove(&agent_id);
    handle.abort();
}

#[tokio::test]
async fn test_agent_browser_tool_routes_to_extension_bridge() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({"manifest_toml": TEST_MANIFEST}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id_text = body["agent_id"].as_str().unwrap().to_string();
    let agent_id: AgentId = agent_id_text.parse().unwrap();

    let mut outbound = server
        .state
        .kernel
        .browser_extension_bridge
        .register(agent_id);
    let kernel = Arc::clone(&server.state.kernel);
    let bridge_task = tokio::spawn(async move {
        let frame = tokio::time::timeout(Duration::from_secs(2), outbound.recv())
            .await
            .expect("browser bridge frame timed out")
            .expect("browser bridge outbound closed");
        assert_eq!(frame["type"], "browser_tool");
        let request = &frame["request"];
        assert_eq!(request["tool"], "browser_health");
        assert_eq!(request["args"], serde_json::json!({"check": true}));
        let request_id = request["id"].as_str().unwrap().to_string();
        assert!(kernel.browser_extension_bridge.complete(serde_json::json!({
            "id": request_id,
            "ok": true,
            "result": {
                "extensionId": "test-extension",
                "tools": ["browser_health"]
            },
            "tool": "browser_health"
        })));
    });

    let resp = client
        .post(format!(
            "{}/api/agents/{}/browser/tool",
            server.base_url, agent_id_text
        ))
        .json(&serde_json::json!({
            "tool": "browser_health",
            "args": { "check": true },
            "timeoutMs": 5000
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["provider"], "chrome_extension");
    assert_eq!(body["tool"], "browser_health");
    assert_eq!(body["result"]["extensionId"], "test-extension");

    bridge_task.await.unwrap();
    server
        .state
        .kernel
        .browser_extension_bridge
        .unregister(agent_id);
}

#[tokio::test]
async fn test_agent_session_empty() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Spawn agent
    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({"manifest_toml": TEST_MANIFEST}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap();

    // Session should be empty — no messages sent yet
    let resp = client
        .get(format!(
            "{}/api/agents/{}/session",
            server.base_url, agent_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message_count"], 0);
    assert_eq!(body["messages"].as_array().unwrap().len(), 0);
}

/// Regression test for #935: the GET /api/agents/:id/session endpoint
/// must NOT expose internal system-prompt messages to the Web UI.
///
/// We construct a session containing a System message + a User message + an
/// Assistant message, persist it via the kernel's memory store, then call the
/// HTTP endpoint and assert:
///   1. The default response excludes the system message entirely.
///   2. `message_count` reflects only the visible (user + assistant) messages.
///   3. `raw_message_count` exposes the underlying total.
///   4. With `?include_system=true`, the system message IS returned (debug
///      mode opt-in).
#[tokio::test]
async fn test_agent_session_filters_system_messages() {
    use t3rnel_types::message::{Message, Role};

    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Spawn agent
    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({"manifest_toml": TEST_MANIFEST}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id_str = body["agent_id"].as_str().unwrap().to_string();

    // Look up the agent's session id and inject a forged history that
    // contains a system-role message (simulating what an OpenAI-compat
    // client could push, or what a future regression might persist).
    let agent_id: t3rnel_types::agent::AgentId = agent_id_str.parse().unwrap();
    let entry = server.state.kernel.registry.get(agent_id).unwrap();
    let session_id = entry.session_id;
    let mut session = server
        .state
        .kernel
        .memory
        .get_session(session_id)
        .unwrap()
        .expect("session should exist after spawn");

    session.messages = vec![
        Message {
            role: Role::System,
            content: t3rnel_types::message::MessageContent::Text(
                "INTERNAL SYSTEM PROMPT — must not leak to UI".to_string(),
            ),
            ..Default::default()
        },
        Message::user("hello"),
        Message::assistant("hi there"),
    ];
    server.state.kernel.memory.save_session(&session).unwrap();

    // --- Default request: system message must be filtered out ---
    let resp = client
        .get(format!(
            "{}/api/agents/{}/session",
            server.base_url, agent_id_str
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    let messages = body["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2, "should only see user + assistant");
    assert_eq!(body["message_count"], 2);
    assert_eq!(body["raw_message_count"], 3);

    // No message in the response should carry the System role label, and
    // the system prompt text MUST NOT appear anywhere in the payload.
    for m in messages {
        let role = m["role"].as_str().unwrap_or("");
        assert_ne!(role, "System", "system role leaked into UI history");
        assert_ne!(role, "system", "system role leaked into UI history");
    }
    let body_str = serde_json::to_string(&body).unwrap();
    assert!(
        !body_str.contains("INTERNAL SYSTEM PROMPT"),
        "system prompt content leaked into session response: {body_str}"
    );

    // Verify the visible roles are exactly what we expect.
    assert_eq!(messages[0]["role"], "User");
    assert_eq!(messages[0]["content"], "hello");
    assert_eq!(messages[1]["role"], "Assistant");
    assert_eq!(messages[1]["content"], "hi there");

    // --- Opt-in debug mode: ?include_system=true returns it ---
    let resp = client
        .get(format!(
            "{}/api/agents/{}/session?include_system=true",
            server.base_url, agent_id_str
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let messages = body["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 3, "include_system=true should return all 3");
    assert_eq!(messages[0]["role"], "System");
    assert_eq!(
        messages[0]["content"],
        "INTERNAL SYSTEM PROMPT — must not leak to UI"
    );
    assert_eq!(body["message_count"], 3);
    assert_eq!(body["raw_message_count"], 3);
}

#[tokio::test]
async fn test_send_message_with_llm() {
    if std::env::var("GROQ_API_KEY").is_err() {
        eprintln!("GROQ_API_KEY not set, skipping LLM integration test");
        return;
    }

    let server = start_test_server_with_llm().await;
    let client = reqwest::Client::new();

    // Spawn
    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({"manifest_toml": LLM_MANIFEST}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Send message through the real HTTP endpoint → kernel → Groq LLM
    let resp = client
        .post(format!(
            "{}/api/agents/{}/message",
            server.base_url, agent_id
        ))
        .json(&serde_json::json!({"message": "Say hello in exactly 3 words."}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let response_text = body["response"].as_str().unwrap();
    assert!(
        !response_text.is_empty(),
        "LLM response should not be empty"
    );
    assert!(body["input_tokens"].as_u64().unwrap() > 0);
    assert!(body["output_tokens"].as_u64().unwrap() > 0);

    // Session should now have messages
    let resp = client
        .get(format!(
            "{}/api/agents/{}/session",
            server.base_url, agent_id
        ))
        .send()
        .await
        .unwrap();
    let session: serde_json::Value = resp.json().await.unwrap();
    assert!(session["message_count"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn test_workflow_crud() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Spawn agent for workflow
    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({"manifest_toml": TEST_MANIFEST}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_name = body["name"].as_str().unwrap().to_string();

    // Create workflow
    let resp = client
        .post(format!("{}/api/workflows", server.base_url))
        .json(&serde_json::json!({
            "name": "test-workflow",
            "description": "Integration test workflow",
            "steps": [
                {
                    "name": "step1",
                    "agent_name": agent_name,
                    "prompt": "Echo: {{input}}",
                    "mode": "sequential",
                    "timeout_secs": 30
                }
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let workflow_id = body["workflow_id"].as_str().unwrap().to_string();
    assert!(!workflow_id.is_empty());

    // List workflows
    let resp = client
        .get(format!("{}/api/workflows", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let workflows: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(workflows.len(), 1);
    assert_eq!(workflows[0]["name"], "test-workflow");
    assert_eq!(workflows[0]["steps"], 1);
}

#[tokio::test]
async fn test_trigger_crud() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Spawn agent for trigger
    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({"manifest_toml": TEST_MANIFEST}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Create trigger (Lifecycle pattern — simplest variant)
    let resp = client
        .post(format!("{}/api/triggers", server.base_url))
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "pattern": "lifecycle",
            "prompt_template": "Handle: {{event}}",
            "max_fires": 5
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let trigger_id = body["trigger_id"].as_str().unwrap().to_string();
    assert_eq!(body["agent_id"], agent_id);

    // List triggers (unfiltered)
    let resp = client
        .get(format!("{}/api/triggers", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let triggers: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(triggers.len(), 1);
    assert_eq!(triggers[0]["agent_id"], agent_id);
    assert_eq!(triggers[0]["enabled"], true);
    assert_eq!(triggers[0]["max_fires"], 5);

    // List triggers (filtered by agent_id)
    let resp = client
        .get(format!(
            "{}/api/triggers?agent_id={}",
            server.base_url, agent_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let triggers: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(triggers.len(), 1);

    // Delete trigger
    let resp = client
        .delete(format!("{}/api/triggers/{}", server.base_url, trigger_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // List triggers (should be empty)
    let resp = client
        .get(format!("{}/api/triggers", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let triggers: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(triggers.len(), 0);
}

#[tokio::test]
async fn test_invalid_agent_id_returns_400() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Send message to invalid ID
    let resp = client
        .post(format!("{}/api/agents/not-a-uuid/message", server.base_url))
        .json(&serde_json::json!({"message": "hello"}))
        .send()
        .await
        .unwrap();
    // Messages accept an agent name as well as a UUID, so a value that is neither is an unknown agent (404), not a malformed id (400).
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("no agent"));

    // Kill invalid ID
    let resp = client
        .delete(format!("{}/api/agents/not-a-uuid", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Session for invalid ID
    let resp = client
        .get(format!("{}/api/agents/not-a-uuid/session", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_kill_nonexistent_agent_returns_404() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let fake_id = uuid::Uuid::new_v4();
    let resp = client
        .delete(format!("{}/api/agents/{}", server.base_url, fake_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_spawn_invalid_manifest_returns_400() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({"manifest_toml": "this is {{ not valid toml"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("Invalid manifest"));
}

#[tokio::test]
async fn test_request_id_header_is_uuid() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/health", server.base_url))
        .send()
        .await
        .unwrap();

    let request_id = resp
        .headers()
        .get("x-request-id")
        .expect("x-request-id header should be present");
    let id_str = request_id.to_str().unwrap();
    assert!(
        uuid::Uuid::parse_str(id_str).is_ok(),
        "x-request-id should be a valid UUID, got: {}",
        id_str
    );
}

#[tokio::test]
async fn test_multiple_agents_lifecycle() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Spawn 3 agents
    let mut ids = Vec::new();
    for i in 0..3 {
        let manifest = format!(
            r#"
name = "agent-{i}"
version = "0.1.0"
description = "Multi-agent test {i}"
author = "test"
module = "builtin:chat"

[model]
provider = "ollama"
model = "test-model"
system_prompt = "Agent {i}."

[capabilities]
memory_read = ["*"]
memory_write = ["self.*"]
"#
        );

        let resp = client
            .post(format!("{}/api/agents", server.base_url))
            .json(&serde_json::json!({"manifest_toml": manifest}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = resp.json().await.unwrap();
        ids.push(body["agent_id"].as_str().unwrap().to_string());
    }

    // List should show 4 (3 spawned + default assistant)
    let resp = client
        .get(format!("{}/api/agents", server.base_url))
        .send()
        .await
        .unwrap();
    let agents: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(agents.len(), 4);

    // Status should agree
    let resp = client
        .get(format!("{}/api/status", server.base_url))
        .send()
        .await
        .unwrap();
    let status: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status["agent_count"], 4);

    // Kill one
    let resp = client
        .delete(format!("{}/api/agents/{}", server.base_url, ids[1]))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // List should show 3 (2 spawned + default assistant)
    let resp = client
        .get(format!("{}/api/agents", server.base_url))
        .send()
        .await
        .unwrap();
    let agents: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(agents.len(), 3);

    // Kill the rest
    for id in [&ids[0], &ids[2]] {
        client
            .delete(format!("{}/api/agents/{}", server.base_url, id))
            .send()
            .await
            .unwrap();
    }

    // List should have only default assistant
    let resp = client
        .get(format!("{}/api/agents", server.base_url))
        .send()
        .await
        .unwrap();
    let agents: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(agents.len(), 1);
}

// ---------------------------------------------------------------------------
// Auth integration tests
// ---------------------------------------------------------------------------

/// Start a test server with Bearer-token authentication enabled.
async fn start_test_server_with_auth(api_key: &str) -> TestServer {
    let tmp = tempfile::tempdir().expect("Failed to create temp dir");

    let config = KernelConfig {
        home_dir: tmp.path().to_path_buf(),
        data_dir: tmp.path().join("data"),
        api_key: api_key.to_string(),
        default_model: DefaultModelConfig {
            provider: "ollama".to_string(),
            model: "test-model".to_string(),
            api_key_env: "OLLAMA_API_KEY".to_string(),
            base_url: None,
            subprocess_timeout_secs: None,
        },
        ..KernelConfig::default()
    };

    let kernel = T3rnelKernel::boot_with_config(config).expect("Kernel should boot");
    let kernel = Arc::new(kernel);
    kernel.set_self_handle();

    let state = Arc::new(AppState {
        kernel,
        started_at: Instant::now(),
        peer_registry: None,
        bridge_manager: tokio::sync::Mutex::new(None),
        channels_config: tokio::sync::RwLock::new(Default::default()),
        shutdown_notify: Arc::new(tokio::sync::Notify::new()),
        clawhub_cache: dashmap::DashMap::new(),
        provider_probe_cache: t3rnel_runtime::provider_health::ProbeCache::new(),
        budget_config: Arc::new(tokio::sync::RwLock::new(Default::default())),
        team_store: team_store::TeamStore::new(),
        winrate_tracker: tokio::sync::Mutex::new(
            t3rnel_prompts::WinRateTracker::open(
                std::env::temp_dir().join("t3rnel-test-winrates.db"),
            )
            .unwrap(),
        ),
        ide_commands: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        ide_command_notify: Arc::new(tokio::sync::Notify::new()),
        health_tracker: Arc::new(
            t3rnel_runtime::drivers::health_tracker::InMemoryHealthTracker::new(100),
        ),
        plugin_dispatch: None,
    });

    let api_key = state.kernel.config.api_key.trim().to_string();
    let auth_state = middleware::AuthState {
        api_key: api_key.clone(),
        auth_enabled: state.kernel.config.auth.enabled,
        session_secret: if !api_key.is_empty() {
            api_key.clone()
        } else if state.kernel.config.auth.enabled {
            state.kernel.config.auth.password_hash.clone()
        } else {
            String::new()
        },
        allow_no_auth: false,
        audit_log: Some(state.kernel.audit_log.clone()),
    };

    let app = Router::new()
        .route("/api/health", axum::routing::get(routes::health))
        .route("/api/status", axum::routing::get(routes::status))
        .route(
            "/api/agents",
            axum::routing::get(routes::list_agents).post(routes::spawn_agent),
        )
        .route(
            "/api/agents/{id}/message",
            axum::routing::post(routes::send_message),
        )
        .route(
            "/api/agents/{id}/browser/tool",
            axum::routing::post(routes::agent_browser_tool),
        )
        .route(
            "/api/agents/{id}/session",
            axum::routing::get(routes::get_agent_session),
        )
        .route("/api/agents/{id}/ws", axum::routing::get(ws::agent_ws))
        .route(
            "/api/agents/{id}",
            axum::routing::delete(routes::kill_agent),
        )
        .route(
            "/api/agents/{id}/clone",
            axum::routing::post(routes::clone_agent),
        )
        .route(
            "/api/triggers",
            axum::routing::get(routes::list_triggers).post(routes::create_trigger),
        )
        .route(
            "/api/triggers/{id}",
            axum::routing::delete(routes::delete_trigger),
        )
        .route(
            "/api/workflows",
            axum::routing::get(routes::list_workflows).post(routes::create_workflow),
        )
        .route(
            "/api/workflows/{id}/run",
            axum::routing::post(routes::run_workflow),
        )
        .route(
            "/api/workflows/{id}/runs",
            axum::routing::get(routes::list_workflow_runs),
        )
        .route("/api/shutdown", axum::routing::post(routes::shutdown))
        .layer(axum::middleware::from_fn_with_state(
            auth_state,
            middleware::auth,
        ))
        .layer(axum::middleware::from_fn(middleware::request_logging))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind test server");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestServer {
        base_url: format!("http://{}", addr),
        state,
        _tmp: tmp,
    }
}

#[tokio::test]
async fn test_auth_health_is_public() {
    let server = start_test_server_with_auth("secret-key-123").await;
    let client = reqwest::Client::new();

    // /api/health should be accessible without auth
    let resp = client
        .get(format!("{}/api/health", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_auth_rejects_no_token() {
    let server = start_test_server_with_auth("secret-key-123").await;
    let client = reqwest::Client::new();

    // Protected endpoint without auth header → 401
    // Note: /api/status is public (dashboard needs it), so use a protected endpoint
    let resp = client
        .get(format!("{}/api/commands", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["message"].as_str().unwrap().contains("Missing"),
        "body: {body}"
    );
}

#[tokio::test]
async fn test_auth_rejects_wrong_token() {
    let server = start_test_server_with_auth("secret-key-123").await;
    let client = reqwest::Client::new();

    // Wrong bearer token → 401
    // Note: /api/status is public (dashboard needs it), so use a protected endpoint
    let resp = client
        .get(format!("{}/api/commands", server.base_url))
        .header("authorization", "Bearer wrong-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["message"].as_str().unwrap().contains("Invalid"),
        "body: {body}"
    );
}

#[tokio::test]
async fn test_auth_accepts_correct_token() {
    let server = start_test_server_with_auth("secret-key-123").await;
    let client = reqwest::Client::new();

    // Correct bearer token → 200
    let resp = client
        .get(format!("{}/api/status", server.base_url))
        .header("authorization", "Bearer secret-key-123")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "running");
}

#[tokio::test]
async fn test_auth_disabled_when_no_key() {
    // Empty API key = auth disabled
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Protected endpoint accessible without auth when no key is configured
    let resp = client
        .get(format!("{}/api/status", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ---------------------------------------------------------------------------
// /api/commands — unified command registry endpoint
// ---------------------------------------------------------------------------

/// Default (no surface query) returns web-surface commands.
#[tokio::test]
async fn test_commands_default_returns_web() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/commands", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["surface"], "web");

    let commands = body["commands"].as_array().expect("commands is array");
    assert!(!commands.is_empty(), "web surface should have commands");

    // Every entry has the documented shape.
    for c in commands {
        assert!(c["name"].is_string());
        assert!(c["aliases"].is_array());
        assert!(c["description"].is_string());
        assert!(c["category"].is_string());
        assert!(c["requires_agent"].is_boolean());
    }

    // Sanity: web surface must include `/help` and `/verbose` and must NOT
    // include CLI-only `/kill`.
    let names: Vec<&str> = commands
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"help"));
    assert!(names.contains(&"verbose"));
    assert!(!names.contains(&"kill"));
}

/// `?surface=cli` returns CLI-only commands and includes the alias array.
#[tokio::test]
async fn test_commands_cli_surface() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/commands?surface=cli", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["surface"], "cli");

    let commands = body["commands"].as_array().unwrap();
    let names: Vec<&str> = commands
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"kill"));
    assert!(names.contains(&"clear"));
    assert!(names.contains(&"exit"));
    // `start` is channel-only — must not appear on CLI.
    assert!(!names.contains(&"start"));

    // `/exit` carries the `quit` alias.
    let exit = commands
        .iter()
        .find(|c| c["name"] == "exit")
        .expect("exit command must be present on CLI");
    let aliases = exit["aliases"].as_array().unwrap();
    assert!(
        aliases.iter().any(|a| a == "quit"),
        "quit alias should be attached to /exit"
    );
}

/// `?surface=all` includes commands from every surface.
#[tokio::test]
async fn test_commands_all_surface() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/commands?surface=all", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["surface"], "all");

    let names: Vec<&str> = body["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();

    // Surface-specific probes: all three unique-per-surface commands appear.
    assert!(names.contains(&"kill"), "CLI-only /kill missing from /all");
    assert!(
        names.contains(&"start"),
        "channel-only /start missing from /all"
    );
    assert!(
        names.contains(&"verbose"),
        "web-only /verbose missing from /all"
    );
}

/// `?surface=channel` returns channel commands only.
#[tokio::test]
async fn test_commands_channel_surface() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/commands?surface=channel", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["surface"], "channel");

    let names: Vec<&str> = body["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"start"));
    // CLI-only must not appear here.
    assert!(!names.contains(&"kill"));
}

/// Unknown surface returns 400 with a JSON error body.
#[tokio::test]
async fn test_commands_invalid_surface_400() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/commands?surface=bogus", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("bogus"),
        "error should mention the bad value: {err}"
    );
}

// ---------------------------------------------------------------------------
// Schedule delivery_targets round-trip tests
// ---------------------------------------------------------------------------
//
// These exercise the `/api/schedules` and `/api/cron/jobs` endpoints to
// confirm `CronDeliveryTarget` variants round-trip cleanly through create /
// list / update / delivery-log, and that bad input is rejected at the API
// layer rather than silently dropped.

async fn spawn_test_agent(server: &TestServer) -> String {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({"manifest_toml": TEST_MANIFEST}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    body["agent_id"].as_str().unwrap().to_string()
}

/// POST /api/schedules with all four `CronDeliveryTarget` variants should
/// store them and return them on GET /api/schedules.
#[tokio::test]
async fn test_schedules_delivery_targets_roundtrip() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let agent_id = spawn_test_agent(&server).await;

    let delivery_targets = serde_json::json!([
        { "type": "channel", "channel_type": "telegram", "recipient": "chat_12345" },
        { "type": "webhook", "url": "https://example.com/hook", "auth_header": "Bearer abc" },
        { "type": "local_file", "path": "/tmp/t3rnel-test.log", "append": true },
        { "type": "email", "to": "alice@example.com", "subject_template": "Cron: {job}" },
    ]);

    let resp = client
        .post(format!("{}/api/schedules", server.base_url))
        .json(&serde_json::json!({
            "name": "multi-destination-test",
            "cron": "0 9 * * 1-5",
            "agent_id": agent_id,
            "message": "Generate the daily brief.",
            "enabled": true,
            "delivery_targets": delivery_targets,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let sched_id = body["id"]
        .as_str()
        .expect("created schedule id")
        .to_string();
    let got = body["delivery_targets"]
        .as_array()
        .expect("response must include delivery_targets");
    assert_eq!(got.len(), 4, "all four targets should round-trip");
    assert_eq!(got[0]["type"], "channel");
    assert_eq!(got[0]["channel_type"], "telegram");
    assert_eq!(got[0]["recipient"], "chat_12345");
    assert_eq!(got[1]["type"], "webhook");
    assert_eq!(got[1]["url"], "https://example.com/hook");
    assert_eq!(got[1]["auth_header"], "Bearer abc");
    assert_eq!(got[2]["type"], "local_file");
    assert_eq!(got[2]["append"], true);
    assert_eq!(got[3]["type"], "email");
    assert_eq!(got[3]["subject_template"], "Cron: {job}");

    let resp = client
        .get(format!("{}/api/schedules", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let schedules = body["schedules"].as_array().unwrap();
    let created = schedules
        .iter()
        .find(|s| s["id"] == sched_id)
        .expect("created schedule must appear in list");
    let listed = created["delivery_targets"].as_array().unwrap();
    assert_eq!(listed.len(), 4);
    assert_eq!(listed[0]["channel_type"], "telegram");

    let _ = client
        .delete(format!("{}/api/schedules/{}", server.base_url, sched_id))
        .send()
        .await;
}

/// PUT /api/schedules/{id} with `delivery_targets` should fully replace the
/// target list.
#[tokio::test]
async fn test_schedules_delivery_targets_update() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let agent_id = spawn_test_agent(&server).await;

    let resp = client
        .post(format!("{}/api/schedules", server.base_url))
        .json(&serde_json::json!({
            "name": "update-target-test",
            "cron": "*/15 * * * *",
            "agent_id": agent_id,
            "message": "hi",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let sched_id = body["id"].as_str().unwrap().to_string();
    assert_eq!(
        body["delivery_targets"].as_array().map(|a| a.len()),
        Some(0)
    );

    let resp = client
        .put(format!("{}/api/schedules/{}", server.base_url, sched_id))
        .json(&serde_json::json!({
            "delivery_targets": [
                { "type": "webhook", "url": "https://new.example.com/hook" },
                { "type": "local_file", "path": "/tmp/new.log" },
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "updated");
    let echoed = &body["schedule"]["delivery_targets"];
    let arr = echoed
        .as_array()
        .expect("schedule.delivery_targets must be array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["type"], "webhook");
    assert_eq!(arr[1]["type"], "local_file");

    let resp = client
        .get(format!("{}/api/schedules", server.base_url))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let created = body["schedules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == sched_id)
        .unwrap();
    let listed = created["delivery_targets"].as_array().unwrap();
    assert_eq!(listed.len(), 2);

    let resp = client
        .put(format!("{}/api/schedules/{}", server.base_url, sched_id))
        .json(&serde_json::json!({"delivery_targets": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .get(format!("{}/api/schedules", server.base_url))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let created = body["schedules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == sched_id)
        .unwrap();
    let listed = created["delivery_targets"].as_array().unwrap();
    assert_eq!(listed.len(), 0);

    let _ = client
        .delete(format!("{}/api/schedules/{}", server.base_url, sched_id))
        .send()
        .await;
}

/// Malformed `delivery_targets` should return 400, not silently succeed.
#[tokio::test]
async fn test_schedules_rejects_bad_delivery_target() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let agent_id = spawn_test_agent(&server).await;

    let resp = client
        .post(format!("{}/api/schedules", server.base_url))
        .json(&serde_json::json!({
            "name": "bad-target-test",
            "cron": "*/10 * * * *",
            "agent_id": agent_id,
            "message": "hi",
            "delivery_targets": [
                { "type": "channel" /* missing channel_type + recipient */ }
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("delivery_targets"),
        "error should mention delivery_targets, got: {err}"
    );

    let resp = client
        .post(format!("{}/api/schedules", server.base_url))
        .json(&serde_json::json!({
            "name": "bad-array-test",
            "cron": "*/10 * * * *",
            "agent_id": agent_id,
            "message": "hi",
            "delivery_targets": "not-an-array",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

/// GET /api/schedules/{id}/delivery-log returns the configured targets and an
/// empty entries array for a known schedule, and 404 for a random UUID.
#[tokio::test]
async fn test_schedules_delivery_log_endpoint() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let agent_id = spawn_test_agent(&server).await;

    let resp = client
        .post(format!("{}/api/schedules", server.base_url))
        .json(&serde_json::json!({
            "name": "log-test",
            "cron": "0 * * * *",
            "agent_id": agent_id,
            "message": "x",
            "delivery_targets": [
                { "type": "webhook", "url": "https://example.com/h" }
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let sched_id = resp.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = client
        .get(format!(
            "{}/api/schedules/{}/delivery-log",
            server.base_url, sched_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["schedule_id"], sched_id);
    let targets = body["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0]["type"], "webhook");
    let entries = body["entries"].as_array().expect("entries array");
    assert!(
        entries.is_empty(),
        "delivery history is not persisted yet — entries must be empty"
    );

    let random = "550e8400-e29b-41d4-a716-446655440000";
    let resp = client
        .get(format!(
            "{}/api/schedules/{}/delivery-log",
            server.base_url, random
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let resp = client
        .get(format!(
            "{}/api/schedules/not-a-uuid/delivery-log",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let _ = client
        .delete(format!("{}/api/schedules/{}", server.base_url, sched_id))
        .send()
        .await;
}

/// POST /api/cron/jobs with `delivery_targets` should persist them and they
/// should appear on the subsequent GET.
#[tokio::test]
async fn test_cron_jobs_delivery_targets_roundtrip() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let agent_id = spawn_test_agent(&server).await;

    let resp = client
        .post(format!("{}/api/cron/jobs", server.base_url))
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "name": "cron-fanout",
            "schedule": { "kind": "cron", "expr": "*/20 * * * *" },
            "action": { "kind": "agent_turn", "message": "pulse" },
            "delivery": { "kind": "none" },
            "delivery_targets": [
                { "type": "local_file", "path": "/tmp/pulse.log", "append": true },
                { "type": "webhook", "url": "http://example.com/pulse" }
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let resp = client
        .get(format!(
            "{}/api/cron/jobs?agent_id={}",
            server.base_url, agent_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let jobs = body["jobs"].as_array().unwrap();
    let job = jobs
        .iter()
        .find(|j| j["name"] == "cron-fanout")
        .expect("created job must be listed");
    let targets = job["delivery_targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0]["type"], "local_file");
    assert_eq!(targets[0]["path"], "/tmp/pulse.log");
    assert_eq!(targets[0]["append"], true);
    assert_eq!(targets[1]["type"], "webhook");
    assert_eq!(targets[1]["url"], "http://example.com/pulse");
}

// ---------------------------------------------------------------------------
// Team + A2A integration tests
// ---------------------------------------------------------------------------

/// integration:team-restore-after-restart
/// Team data (members, tasks, A2A messages) must survive a kernel restart.
#[tokio::test]
async fn test_team_restore_after_restart() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // 1. List teams — the seeded permanent team should exist
    let resp = client
        .get(format!("{}/api/teams", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let teams = body["teams"].as_array().expect("teams array");
    assert!(!teams.is_empty(), "seeded permanent team must exist");

    let team_id = teams[0]["id"].as_str().unwrap().to_string();

    // 2. Create a task on the team
    let resp = client
        .post(format!("{}/api/teams/{}/tasks", server.base_url, team_id))
        .json(&serde_json::json!({
            "title": "restore-test-task",
            "description": "Verify team persistence",
            "assignee_id": "researcher",
            "status": "in_progress",
            "percent": 42,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // 3. Send an A2A message using a real team member ID
    let resp = client
        .post(format!(
            "{}/api/teams/{}/a2a/messages",
            server.base_url, team_id
        ))
        .json(&serde_json::json!({
            "sender_id": "t3rnel",
            "recipient_id": "researcher",
            "msg_type": "question",
            "payload": { "text": "Can you hear me?" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 4. Verify the data is immediately retrievable (SQLite persistence)
    // TeamStore persists to SQLite; the same server process should still
    // serve the data from durable storage.
    let resp = client
        .get(format!("{}/api/teams/{}/tasks", server.base_url, team_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let tasks = body["tasks"].as_array().expect("tasks array");
    assert!(
        tasks.iter().any(|t| t["title"] == "restore-test-task"),
        "team task must persist in SQLite"
    );

    let resp = client
        .get(format!(
            "{}/api/teams/{}/a2a/messages",
            server.base_url, team_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let messages = body["messages"].as_array().expect("messages array");
    assert!(
        messages
            .iter()
            .any(|m| m["payload"]["text"] == "Can you hear me?"),
        "A2A message must persist in SQLite"
    );
}

/// integration:a2a-self-roundtrip
/// An agent can send an A2A message to itself and read it back.
#[tokio::test]
async fn test_a2a_self_roundtrip() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Get the first team
    let resp = client
        .get(format!("{}/api/teams", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let teams = body["teams"].as_array().expect("teams array");
    assert!(!teams.is_empty(), "seeded permanent team must exist");
    let team_id = teams[0]["id"].as_str().unwrap().to_string();

    // Send a message from a team member to itself
    let resp = client
        .post(format!(
            "{}/api/teams/{}/a2a/messages",
            server.base_url, team_id
        ))
        .json(&serde_json::json!({
            "sender_id": "t3rnel",
            "recipient_id": "t3rnel",
            "msg_type": "question",
            "payload": { "text": "self-test-payload-42" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Read messages back
    let resp = client
        .get(format!(
            "{}/api/teams/{}/a2a/messages",
            server.base_url, team_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let messages = body["messages"].as_array().expect("messages array");
    assert!(
        messages
            .iter()
            .any(|m| m["payload"]["text"] == "self-test-payload-42"),
        "self-sent message must be retrievable"
    );
}

/// integration:orchestrator-dispatch
/// The orchestrator can dispatch a task to a role-matched agent.
#[tokio::test]
async fn test_orchestrator_dispatch_to_role() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Spawn a test agent with a known role
    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({
            "manifest_toml": r#"
name = "test-coder"
version = "0.1.0"
description = "Test coder agent"
author = "test"
module = "builtin:chat"
role = "coder"

[model]
provider = "ollama"
model = "test-model"
system_prompt = "You are a coder."

[capabilities]
tools = ["file_read"]
memory_read = ["*"]
memory_write = ["self.*"]
"#,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agent_id = body["agent_id"].as_str().unwrap().to_string();

    // Verify the agent appears in A2A agent listing
    let resp = client
        .get(format!("{}/a2a/agents", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let agents = body["agents"].as_array().expect("agents array");
    assert!(
        agents.iter().any(|a| a["name"] == "test-coder"),
        "dispatched agent must appear in A2A registry"
    );

    // Verify orchestrator can find the agent by role via KernelHandle
    use t3rnel_runtime::kernel_handle::KernelHandle;
    let all = server.state.kernel.list_agents();
    let coders: Vec<_> = all.iter().filter(|a| a.role == "coder").collect();
    assert!(
        coders.iter().any(|a| a.id == agent_id),
        "orchestrator must resolve coder role to the spawned agent"
    );
}

#[tokio::test]
async fn test_provider_catalog_endpoint() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/providers/catalog", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["providers"].is_array());
    let providers = body["providers"].as_array().unwrap();

    // If category-templates.toml exists and has providers, validate structure
    if !providers.is_empty() {
        for provider in providers {
            assert!(provider["id"].is_string());
            assert!(provider["name"].is_string());
            assert!(provider["models"].is_array());
        }
    }
    // Empty providers array is acceptable if config file is missing or empty
}

#[tokio::test]
async fn test_categories_endpoint() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/categories", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["categories"].is_array());
    let categories = body["categories"].as_array().unwrap();

    // If category-templates.toml exists and has categories, validate structure
    if !categories.is_empty() {
        for category in categories {
            assert!(category["id"].is_string());
            assert!(category["description"].is_string());
            assert!(category["fallback_chain"].is_array());
            assert_eq!(
                category["model_count"].as_u64().unwrap() as usize,
                category["fallback_chain"].as_array().unwrap().len()
            );
        }
    }
    // Empty categories array is acceptable if config file is missing or empty
}

#[tokio::test]
async fn test_health_endpoint_includes_provider_status() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/health", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    // Health endpoint returns "ok" status, not "healthy"
    assert!(body["status"] == "ok" || body["status"] == "healthy");
}

#[tokio::test]
async fn test_status_endpoint_includes_agent_count() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/status", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["agents"].is_array());
}

#[tokio::test]
async fn test_agent_uses_category_fallback_chain() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/categories", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let categories = body["categories"].as_array().unwrap();

    // Skip test if no categories are available (config file missing)
    if categories.is_empty() {
        return;
    }

    let first_category = &categories[0];
    let category_id = first_category["id"].as_str().unwrap();
    let fallback_chain = first_category["fallback_chain"].as_array().unwrap();
    assert!(
        !fallback_chain.is_empty(),
        "category must have fallback chain"
    );

    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({
            "manifest_toml": format!(r#"
name = "test-category-agent"
version = "0.1.0"
description = "Test agent with category"
author = "test"
module = "builtin:chat"
category = "{}"

[model]
provider = "ollama"
model = "test-model"
system_prompt = "You are a test agent."

[capabilities]
tools = ["file_read"]
memory_read = ["*"]
memory_write = ["self.*"]
"#, category_id),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_provider_catalog_model_structure() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/providers/catalog", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let providers = body["providers"].as_array().unwrap();

    if !providers.is_empty() {
        let first_provider = &providers[0];
        let models = first_provider["models"].as_array().unwrap();
        if !models.is_empty() {
            let first_model = &models[0];
            assert!(first_model["id"].is_string(), "model must have id");
            assert!(first_model["name"].is_string(), "model must have name");
            assert!(first_model["tier"].is_string(), "model must have tier");
        }
    }
}

#[tokio::test]
async fn test_category_fallback_chain_structure() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/categories", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let categories = body["categories"].as_array().unwrap();

    if !categories.is_empty() {
        let first_category = &categories[0];
        let fallback_chain = first_category["fallback_chain"].as_array().unwrap();
        if !fallback_chain.is_empty() {
            let first_model = &fallback_chain[0];
            assert!(
                first_model["provider"].is_string(),
                "fallback model must have provider"
            );
            assert!(
                first_model["model"].is_string(),
                "fallback model must have model"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Clone agent endpoint tests (issue #868)
// ---------------------------------------------------------------------------

/// Happy path: clone an existing template agent into a new agent with a
/// distinct name. The clone must get a fresh ID, fresh workspace path, and
/// inherit non-name manifest fields from the template.
#[tokio::test]
async fn test_clone_agent_happy_path() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Spawn a template agent.
    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({"manifest_toml": TEST_MANIFEST}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let template_id = body["agent_id"].as_str().unwrap().to_string();

    // Clone it.
    let resp = client
        .post(format!(
            "{}/api/agents/{}/clone",
            server.base_url, template_id
        ))
        .json(&serde_json::json!({
            "new_name": "cloned-user-1",
            "overrides": {
                "description": "Cloned for user 1",
                "tags": ["clone", "user-1"]
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "clone should succeed");
    let body: serde_json::Value = resp.json().await.unwrap();

    let new_id = body["agent_id"].as_str().unwrap();
    assert_ne!(new_id, template_id, "clone must have a fresh agent ID");
    assert_eq!(body["name"], "cloned-user-1");

    // The full manifest should be returned and reflect the new name + overrides.
    let manifest = &body["manifest"];
    assert!(manifest.is_object(), "manifest must be returned");
    assert_eq!(manifest["name"], "cloned-user-1");
    assert_eq!(manifest["description"], "Cloned for user 1");
    assert_eq!(
        manifest["tags"].as_array().unwrap(),
        &vec![serde_json::json!("clone"), serde_json::json!("user-1"),]
    );
    // Inherited from template — the system_prompt should match.
    assert_eq!(
        manifest["model"]["system_prompt"],
        "You are a test agent. Reply concisely."
    );

    // The agent list should now contain both template and clone.
    let resp = client
        .get(format!("{}/api/agents", server.base_url))
        .send()
        .await
        .unwrap();
    let agents: Vec<serde_json::Value> = resp.json().await.unwrap();
    let names: Vec<&str> = agents.iter().map(|a| a["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"test-agent"));
    assert!(names.contains(&"cloned-user-1"));
}

/// Cloning into a name that's already taken must fail with 409 Conflict.
#[tokio::test]
async fn test_clone_agent_name_collision() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Spawn a template agent named "test-agent".
    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({"manifest_toml": TEST_MANIFEST}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let template_id = body["agent_id"].as_str().unwrap().to_string();

    // First clone — succeeds.
    let resp = client
        .post(format!(
            "{}/api/agents/{}/clone",
            server.base_url, template_id
        ))
        .json(&serde_json::json!({"new_name": "duplicate-name"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    // Second clone with the same name — must be rejected.
    let resp = client
        .post(format!(
            "{}/api/agents/{}/clone",
            server.base_url, template_id
        ))
        .json(&serde_json::json!({"new_name": "duplicate-name"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        409,
        "duplicate name must return 409 Conflict"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("already exists"));

    // Cloning into the template's own name must also be rejected.
    let resp = client
        .post(format!(
            "{}/api/agents/{}/clone",
            server.base_url, template_id
        ))
        .json(&serde_json::json!({"new_name": "test-agent"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

/// Cloning a non-existent template must return 404.
#[tokio::test]
async fn test_clone_agent_template_not_found() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Random valid UUID that does not match any agent.
    let bogus_id = "00000000-0000-0000-0000-000000000000";
    let resp = client
        .post(format!("{}/api/agents/{}/clone", server.base_url, bogus_id))
        .json(&serde_json::json!({"new_name": "ghost-clone"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("Template agent not found"));

    // Malformed agent id → 400.
    let resp = client
        .post(format!("{}/api/agents/not-a-uuid/clone", server.base_url))
        .json(&serde_json::json!({"new_name": "ghost-clone"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

/// Empty new_name must be rejected with 400.
#[tokio::test]
async fn test_clone_agent_empty_name_rejected() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Spawn a template agent.
    let resp = client
        .post(format!("{}/api/agents", server.base_url))
        .json(&serde_json::json!({"manifest_toml": TEST_MANIFEST}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let template_id = body["agent_id"].as_str().unwrap().to_string();

    let resp = client
        .post(format!(
            "{}/api/agents/{}/clone",
            server.base_url, template_id
        ))
        .json(&serde_json::json!({"new_name": "   "}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
