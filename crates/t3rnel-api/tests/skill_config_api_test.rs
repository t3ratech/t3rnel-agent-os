//! Integration tests for the `/api/skills/{id}/config` surface.
//!
//! These boot a real kernel, start a real axum server on a random port, plant
//! a synthetic skill on disk whose SKILL.md declares a `config:` section, and
//! exercise GET / PUT / DELETE end to end. Bundled skills currently declare
//! no runtime config, so the synthetic skill fixture is what lets us prove
//! the wire contract.
//!
//! Run: ./t3rnel-services.sh --test integration

use axum::Router;
use futures::StreamExt;
use std::sync::Arc;
use std::time::Instant;
use t3rnel_api::middleware;
use t3rnel_api::routes::{self, AppState};
use t3rnel_api::team_store;
use t3rnel_kernel::T3rnelKernel;
use t3rnel_types::config::{DefaultModelConfig, KernelConfig};
use tower_http::cors::CorsLayer;

// ---------------------------------------------------------------------------
// Test server harness
// ---------------------------------------------------------------------------

struct TestServer {
    base_url: String,
    home_dir: std::path::PathBuf,
    #[allow(dead_code)]
    state: Arc<AppState>,
    _tmp: tempfile::TempDir,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.state.kernel.shutdown();
    }
}

/// Write a skill fixture under `<home>/skills/<name>/SKILL.md` that declares
/// a `config:` section. This matches the on-disk format that OpenClaw skills
/// use, so the loader's real `parse_skillmd_str` path is exercised.
fn plant_skill_with_config(home: &std::path::Path, skill_name: &str) {
    let skill_dir = home.join("skills").join(skill_name);
    std::fs::create_dir_all(&skill_dir).unwrap();
    // Leading four spaces inside YAML lists matter — keep them.
    let skillmd = format!(
        "---
name: {skill_name}
description: Synthetic skill for config endpoint tests
config:
  github_token:
    description: GitHub personal access token
    env: T3RNEL_TEST_SKILLCFG_GH_TOKEN
    required: true
  default_branch:
    description: Default branch name
    default: main
    required: false
---
# Test Skill

Placeholder body so the parser accepts this as a valid prompt-only skill.
"
    );
    std::fs::write(skill_dir.join("SKILL.md"), skillmd).unwrap();
}

async fn start_test_server() -> TestServer {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().to_path_buf();

    let config = KernelConfig {
        home_dir: home.clone(),
        data_dir: home.join("data"),
        default_model: DefaultModelConfig {
            provider: "ollama".to_string(),
            model: "test-model".to_string(),
            api_key_env: "OLLAMA_API_KEY".to_string(),
            base_url: None,
            subprocess_timeout_secs: None,
        },
        ..KernelConfig::default()
    };

    // Plant synthetic skill BEFORE booting so the initial skill load picks it up.
    plant_skill_with_config(&home, "test-config-skill");

    let kernel = T3rnelKernel::boot_with_config(config).expect("kernel boot");
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
    });

    let app = Router::new()
        .route("/api/skills", axum::routing::get(routes::list_skills))
        .route(
            "/api/skills/{id}/config",
            axum::routing::get(routes::get_skill_config).put(routes::put_skill_config),
        )
        .route(
            "/api/skills/{id}/config/{var_name}",
            axum::routing::delete(routes::delete_skill_config_var),
        )
        .route(
            "/api/approvals/pending-count",
            axum::routing::get(routes::get_pending_count),
        )
        .route(
            "/api/approvals",
            axum::routing::get(routes::list_approvals).post(routes::create_approval),
        )
        .route(
            "/api/approvals/approve-all",
            axum::routing::post(routes::approve_all_requests),
        )
        .route(
            "/api/approvals/{id}/approve",
            axum::routing::post(routes::approve_request),
        )
        .route(
            "/api/approvals/{id}/reject",
            axum::routing::post(routes::reject_request),
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
            "/api/teams/{id}/tasks/complete-all",
            axum::routing::post(routes::complete_all_team_tasks),
        )
        .route(
            "/api/teams/{id}/tasks/{task_id}/complete",
            axum::routing::post(routes::complete_team_task),
        )
        .route(
            "/api/teams/{id}/tasks/{task_id}/cancel",
            axum::routing::post(routes::cancel_team_task),
        )
        .route(
            "/api/teams/{id}/tasks/{task_id}/progress",
            axum::routing::get(routes::get_task_progress),
        )
        .route(
            "/api/teams/{id}/a2a/messages",
            axum::routing::get(routes::list_a2a_messages).post(routes::send_a2a_message),
        )
        .route(
            "/api/teams/{id}/a2a/stream",
            axum::routing::get(routes::a2a_message_stream),
        )
        .route(
            "/api/internal/self-improvement/status",
            axum::routing::get(routes::self_improvement_status),
        )
        .route(
            "/api/internal/self-improvement/halt",
            axum::routing::post(routes::self_improvement_halt),
        )
        .layer(axum::middleware::from_fn(middleware::request_logging))
        .layer(CorsLayer::permissive())
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test port");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestServer {
        base_url: format!("http://{}", addr),
        home_dir: home,
        state,
        _tmp: tmp,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_config_returns_declared_and_resolved() {
    // Make sure no host leak from prior tests interferes.
    // SAFETY: single-threaded test, env var is unique to this test suite.
    unsafe { std::env::remove_var("T3RNEL_TEST_SKILLCFG_GH_TOKEN") };

    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "{}/api/skills/test-config-skill/config",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(body["skill"], "test-config-skill");
    // Both vars declared
    assert!(body["declared"]["github_token"].is_object());
    assert!(body["declared"]["default_branch"].is_object());
    assert_eq!(body["declared"]["github_token"]["required"], true);
    assert_eq!(body["declared"]["default_branch"]["required"], false);

    // github_token has no user override, no env, no default -> unresolved.
    assert_eq!(
        body["resolved"]["github_token"]["source"], "unresolved",
        "github_token should be unresolved without env"
    );
    assert!(body["resolved"]["github_token"]["is_secret"]
        .as_bool()
        .unwrap());

    // default_branch falls back to default "main".
    assert_eq!(body["resolved"]["default_branch"]["source"], "default");
    assert_eq!(body["resolved"]["default_branch"]["value"], "main");
}

#[tokio::test]
async fn get_config_redacts_secret_values_after_put() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Write a real-looking token via PUT.
    let payload = serde_json::json!({
        "values": {
            "github_token": "ghp_realsecretvalue_DO_NOT_LEAK",
            "default_branch": "develop"
        }
    });
    let resp = client
        .put(format!(
            "{}/api/skills/test-config-skill/config",
            server.base_url
        ))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "PUT should succeed");

    // GET back and confirm the secret is redacted and non-secret is visible.
    let resp = client
        .get(format!(
            "{}/api/skills/test-config-skill/config",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();

    let returned_token = body["resolved"]["github_token"]["value"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        !returned_token.contains("realsecretvalue"),
        "secret leaked on the wire: {returned_token}"
    );
    assert!(
        returned_token.contains("redacted"),
        "expected redaction marker, got: {returned_token}"
    );
    assert_eq!(body["resolved"]["github_token"]["source"], "user");

    // Non-secret var kept as-is.
    assert_eq!(body["resolved"]["default_branch"]["value"], "develop");
    assert_eq!(body["resolved"]["default_branch"]["source"], "user");

    // config.toml persisted the change, including the full secret value
    // (redaction is only on the wire — disk is the source of truth).
    let cfg = std::fs::read_to_string(server.home_dir.join("config.toml")).unwrap();
    assert!(
        cfg.contains("[skills.test-config-skill]"),
        "skills section missing: {cfg}"
    );
    assert!(cfg.contains("realsecretvalue"));
    assert!(cfg.contains("develop"));
}

#[tokio::test]
async fn put_rejects_unknown_variable() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    let payload = serde_json::json!({
        "values": { "nonexistent_var": "value" }
    });
    let resp = client
        .put(format!(
            "{}/api/skills/test-config-skill/config",
            server.base_url
        ))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("nonexistent_var"));
}

#[tokio::test]
async fn delete_override_reverts_to_default() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Set override first.
    client
        .put(format!(
            "{}/api/skills/test-config-skill/config",
            server.base_url
        ))
        .json(&serde_json::json!({
            "values": { "default_branch": "develop" }
        }))
        .send()
        .await
        .unwrap();

    // Remove it.
    let resp = client
        .delete(format!(
            "{}/api/skills/test-config-skill/config/default_branch",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Now source should be "default" again with value "main".
    let body: serde_json::Value = client
        .get(format!(
            "{}/api/skills/test-config-skill/config",
            server.base_url
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["resolved"]["default_branch"]["source"], "default");
    assert_eq!(body["resolved"]["default_branch"]["value"], "main");
}

#[tokio::test]
async fn delete_refuses_to_strand_required_var() {
    // github_token is required, has no default, and no env — so removing an
    // override would leave it unresolvable. The endpoint must refuse.
    // SAFETY: single-threaded test.
    unsafe { std::env::remove_var("T3RNEL_TEST_SKILLCFG_GH_TOKEN") };

    let server = start_test_server().await;
    let client = reqwest::Client::new();

    // Set an override.
    client
        .put(format!(
            "{}/api/skills/test-config-skill/config",
            server.base_url
        ))
        .json(&serde_json::json!({
            "values": { "github_token": "ghp_value" }
        }))
        .send()
        .await
        .unwrap();

    // Try to delete — should 409.
    let resp = client
        .delete(format!(
            "{}/api/skills/test-config-skill/config/github_token",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

#[tokio::test]
async fn get_unknown_skill_returns_404() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{}/api/skills/this-skill-does-not-exist/config",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn put_reloads_registry_so_agents_see_change() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();

    client
        .put(format!(
            "{}/api/skills/test-config-skill/config",
            server.base_url
        ))
        .json(&serde_json::json!({
            "values": {
                "github_token": "ghp_new",
                "default_branch": "release"
            }
        }))
        .send()
        .await
        .unwrap();

    // The kernel's live override map must now hold the new values.
    let guard = server.state.kernel.skill_config_overrides.read().unwrap();
    let overrides = guard.as_ref().expect("override map set after PUT");
    let skill_cfg = overrides.get("test-config-skill").expect("skill present");
    assert_eq!(skill_cfg.get("github_token").unwrap(), "ghp_new");
    assert_eq!(skill_cfg.get("default_branch").unwrap(), "release");
}

#[tokio::test]
async fn test_approvals_pending_count_returns_number() {
    let server = start_test_server().await;

    let resp = reqwest::get(format!("{}/api/approvals/pending-count", server.base_url))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["pending_count"].is_number());
}

#[tokio::test]
async fn test_create_approval_returns_201() {
    let server = start_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/approvals", server.base_url))
        .json(&serde_json::json!({
            "agent_id": "test-agent",
            "tool_name": "shell_exec",
            "description": "Test approval",
            "action_summary": "Run ls"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["id"].is_string());
    assert_eq!(body["status"].as_str(), Some("pending"));
}

#[tokio::test]
async fn test_list_approvals_returns_list() {
    let server = start_test_server().await;

    let resp = reqwest::get(format!("{}/api/approvals", server.base_url))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["approvals"].is_array());
    assert!(body["total"].is_number());
}

#[tokio::test]
async fn test_approve_approval_changes_status() {
    let server = start_test_server().await;

    let client = reqwest::Client::new();

    // Create an approval
    let resp = client
        .post(format!("{}/api/approvals", server.base_url))
        .json(&serde_json::json!({
            "agent_id": "test-agent",
            "tool_name": "shell_exec",
            "description": "Test approval",
            "action_summary": "Run ls"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let id = body["id"].as_str().unwrap();

    // Approve it
    let resp = client
        .post(format!("{}/api/approvals/{id}/approve", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str(), Some("approved"));
}

#[tokio::test]
async fn test_approve_all_approvals_clears_pending_queue() {
    let server = start_test_server().await;

    let client = reqwest::Client::new();
    for summary in ["Run smoke test", "Read audit log"] {
        let resp = client
            .post(format!("{}/api/approvals", server.base_url))
            .json(&serde_json::json!({
                "agent_id": "test-agent",
                "tool_name": "shell_exec",
                "description": "Bulk approval test",
                "action_summary": summary
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
    }

    let resp = client
        .post(format!("{}/api/approvals/approve-all", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["approved_count"].as_u64(), Some(2));
    assert_eq!(body["skipped_count"].as_u64(), Some(0));

    let resp = reqwest::get(format!("{}/api/approvals", server.base_url))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["total"].as_u64(), Some(2));
    let approvals = body["approvals"].as_array().unwrap();
    assert_eq!(approvals.len(), 2);
    assert!(approvals
        .iter()
        .all(|approval| approval["status"].as_str() == Some("approved")));

    let resp = reqwest::get(format!("{}/api/approvals/pending-count", server.base_url))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["pending_count"].as_u64(), Some(0));
}

#[tokio::test]
async fn test_list_teams_returns_list() {
    let server = start_test_server().await;

    let resp = reqwest::get(format!("{}/api/teams", server.base_url))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["teams"].is_array());
}

#[tokio::test]
async fn test_get_team_members_returns_list() {
    let server = start_test_server().await;

    let resp = reqwest::get(format!(
        "{}/api/teams/software-engineering/members",
        server.base_url
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["members"].is_array());
}

#[tokio::test]
async fn test_get_team_returns_team() {
    let server = start_test_server().await;

    let resp = reqwest::get(format!(
        "{}/api/teams/software-engineering",
        server.base_url
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["id"].is_string());
    assert!(body["name"].is_string());
}

#[tokio::test]
async fn test_team_task_progress_returns_json() {
    let server = start_test_server().await;

    let resp = reqwest::get(format!(
        "{}/api/teams/software-engineering/tasks/task-1/progress",
        server.base_url
    ))
    .await
    .unwrap();
    // Task may not exist; endpoint should still return structured response
    assert!(resp.status().is_success() || resp.status().is_client_error());
}

#[tokio::test]
async fn test_a2a_messages_returns_list() {
    let server = start_test_server().await;

    let resp = reqwest::get(format!(
        "{}/api/teams/software-engineering/a2a/messages",
        server.base_url
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["messages"].is_array());
}

#[tokio::test]
async fn test_send_a2a_message_returns_ok() {
    let server = start_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/api/teams/software-engineering/a2a/messages",
            server.base_url
        ))
        .json(&serde_json::json!({
            "sender_id": "t3rnel",
            "recipient_id": "coder",
            "msg_type": "question",
            "payload": {
                "content": "Please review the API changes",
                "marker": "roundtrip-test"
            },
            "trace_id": "trace-roundtrip-test"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["team_id"].as_str(), Some("software-engineering"));
    assert_eq!(body["sender_id"].as_str(), Some("t3rnel"));
    assert_eq!(body["recipient_id"].as_str(), Some("coder"));
    assert_eq!(body["msg_type"].as_str(), Some("question"));
    assert_eq!(
        body["payload"]["content"].as_str(),
        Some("Please review the API changes")
    );
    assert_eq!(body["trace_id"].as_str(), Some("trace-roundtrip-test"));
}

#[tokio::test]
async fn test_a2a_sse_stream_receives_live_message_in_order() {
    let server = start_test_server().await;
    let client = reqwest::Client::new();
    let marker = format!("sse-marker-{}", uuid::Uuid::new_v4());

    let stream_resp = client
        .get(format!(
            "{}/api/teams/software-engineering/a2a/stream?since=9999-01-01T00:00:00Z",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(stream_resp.status(), 200);
    let mut stream = stream_resp.bytes_stream();

    let send_resp = client
        .post(format!(
            "{}/api/teams/software-engineering/a2a/messages",
            server.base_url
        ))
        .json(&serde_json::json!({
            "sender_id": "t3rnel",
            "recipient_id": "coder",
            "msg_type": "task_assignment",
            "payload": {
                "title": "SSE test task",
                "description": "Verify the A2A stream receives live messages",
                "content": "stream me",
                "marker": marker
            },
            "trace_id": "trace-sse-test"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(send_resp.status(), 200);

    let frame = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut body = String::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.expect("SSE chunk");
            body.push_str(&String::from_utf8_lossy(&chunk));
            if body.contains(&marker) {
                return body;
            }
        }
        body
    })
    .await
    .expect("timed out waiting for A2A SSE message");

    assert!(frame.contains("event: a2a"), "{frame}");
    assert!(frame.contains("\"sequence\":0"), "{frame}");
    assert!(frame.contains("\"trace_id\":\"trace-sse-test\""), "{frame}");
    assert!(frame.contains("\"task_id\""), "{frame}");
}

#[tokio::test]
async fn test_create_team_task_returns_201() {
    let server = start_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/api/teams/software-engineering/tasks",
            server.base_url
        ))
        .json(&serde_json::json!({
            "title": "Implement auth middleware",
            "description": "Add Bearer token validation to all API routes",
            "assignee_id": "coder",
            "blockers": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["id"].is_string());
    assert_eq!(body["team_id"].as_str(), Some("software-engineering"));
    assert_eq!(body["title"].as_str(), Some("Implement auth middleware"));
}

#[tokio::test]
async fn test_complete_team_task_marks_task_done() {
    let server = start_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/api/teams/software-engineering/tasks",
            server.base_url
        ))
        .json(&serde_json::json!({
            "title": "Complete live task",
            "description": "Task should close through the REST control endpoint",
            "assignee_id": "coder",
            "blockers": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let created: serde_json::Value = resp.json().await.unwrap();
    let id = created["id"].as_str().unwrap();

    let resp = client
        .post(format!(
            "{}/api/teams/software-engineering/tasks/{id}/complete",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["id"].as_str(), Some(id));
    assert_eq!(body["status"].as_str(), Some("done"));
    assert_eq!(body["percent"].as_u64(), Some(100));
    assert_eq!(body["current_step"], body["total_steps"]);
}

#[tokio::test]
async fn test_cancel_team_task_marks_task_failed() {
    let server = start_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/api/teams/software-engineering/tasks",
            server.base_url
        ))
        .json(&serde_json::json!({
            "title": "Cancel live task",
            "description": "Task should close through the cancel endpoint",
            "assignee_id": "coder",
            "blockers": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let created: serde_json::Value = resp.json().await.unwrap();
    let id = created["id"].as_str().unwrap();

    let resp = client
        .post(format!(
            "{}/api/teams/software-engineering/tasks/{id}/cancel",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["id"].as_str(), Some(id));
    assert_eq!(body["status"].as_str(), Some("failed"));
    assert_eq!(body["percent"].as_u64(), Some(100));
}

#[tokio::test]
async fn test_complete_all_team_tasks_marks_only_open_tasks_done() {
    let server = start_test_server().await;

    let client = reqwest::Client::new();
    let mut ids = Vec::new();
    for title in ["Bulk task one", "Bulk task two"] {
        let resp = client
            .post(format!(
                "{}/api/teams/software-engineering/tasks",
                server.base_url
            ))
            .json(&serde_json::json!({
                "title": title,
                "description": "Task should close through the bulk control endpoint",
                "assignee_id": "coder",
                "blockers": []
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 201);
        let body: serde_json::Value = resp.json().await.unwrap();
        ids.push(body["id"].as_str().unwrap().to_string());
    }

    let resp = client
        .post(format!(
            "{}/api/teams/software-engineering/tasks/complete-all",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str(), Some("done"));
    assert!(body["total"].as_u64().unwrap() >= 2);

    let tasks = body["tasks"].as_array().unwrap();
    for id in ids {
        let task = tasks
            .iter()
            .find(|task| task["id"].as_str() == Some(id.as_str()))
            .expect("completed task returned by bulk endpoint");
        assert_eq!(task["status"].as_str(), Some("done"));
        assert_eq!(task["percent"].as_u64(), Some(100));
        assert_eq!(task["current_step"], task["total_steps"]);
    }

    let resp = reqwest::get(format!(
        "{}/api/teams/software-engineering/tasks",
        server.base_url
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let tasks = body["tasks"].as_array().unwrap();
    assert!(tasks.iter().all(|task| matches!(
        task["status"].as_str(),
        Some("done" | "completed" | "cancelled" | "failed")
    )));
}

#[tokio::test]
async fn test_self_improvement_halt_disables_availability() {
    let server = start_test_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/api/internal/self-improvement/halt",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["self_improvement_halt"].as_bool(), Some(true));
    assert_eq!(body["available"].as_bool(), Some(false));

    let resp = reqwest::get(format!(
        "{}/api/internal/self-improvement/status",
        server.base_url
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["self_improvement_halt"].as_bool(), Some(true));
    assert_eq!(body["available"].as_bool(), Some(false));
}
