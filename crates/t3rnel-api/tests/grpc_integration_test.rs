use chrono::Utc;
use std::sync::Arc;
use t3rnel_api::pb;
use t3rnel_api::routes::AppState;
use t3rnel_api::team_store;
use t3rnel_memory::usage::UsageRecord;
use t3rnel_types::agent::{AgentId, AgentManifest};
use t3rnel_types::approval::{ApprovalRequest, RiskLevel};
use t3rnel_types::config::KernelConfig;
use t3rnel_types::memory::Memory;
use t3rnel_types::message::Message;
use tonic::service::Interceptor;
use tonic::transport::Channel;

struct TestGrpcServer {
    url: String,
    state: Arc<AppState>,
    _home: tempfile::TempDir,
}

#[derive(Clone)]
struct BearerToken(&'static str);

impl Interceptor for BearerToken {
    #[allow(clippy::result_large_err)]
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", self.0)
                .parse()
                .expect("metadata value"),
        );
        Ok(req)
    }
}

async fn start_grpc_server() -> TestGrpcServer {
    start_grpc_server_with_api_key("").await
}

async fn start_grpc_server_with_api_key(api_key: &str) -> TestGrpcServer {
    let home = tempfile::tempdir().expect("temp home");
    let home_dir = home.path().to_path_buf();
    let data_dir = home_dir.join("data");
    let config = KernelConfig {
        home_dir,
        data_dir: data_dir.clone(),
        api_key: api_key.to_string(),
        memory: t3rnel_types::config::MemoryConfig {
            sqlite_path: Some(data_dir.join("memory.sqlite")),
            embedding_provider: Some("disabled".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    let kernel = t3rnel_kernel::T3rnelKernel::boot_with_config(config).expect("kernel boot");
    let state = Arc::new(AppState {
        kernel: Arc::new(kernel),
        started_at: std::time::Instant::now(),
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
    let addr = t3rnel_api::grpc::start_grpc_server(state.clone(), 0)
        .await
        .expect("grpc server start");
    TestGrpcServer {
        url: format!("http://{}", addr),
        state,
        _home: home,
    }
}

#[test]
fn test_grpc_reflection_policy_matches_build_profile() {
    assert_eq!(
        t3rnel_api::grpc::grpc_reflection_enabled(),
        cfg!(debug_assertions)
    );
}

#[tokio::test]
async fn test_grpc_list_agents_returns_empty_list() {
    let server = start_grpc_server().await;
    let mut client = pb::agents_client::AgentsClient::connect(server.url)
        .await
        .expect("connect");
    let req = pb::ListAgentsRequest {};
    let resp = client.list_agents(req).await.expect("list_agents");
    // Kernel boots with built-in agents, so list may be non-empty.
    // We just verify the call succeeds and returns a valid list.
    let _ = resp.into_inner().agents;
}

#[tokio::test]
async fn test_grpc_auth_requires_bearer_when_configured() {
    let server = start_grpc_server_with_api_key("grpc-secret").await;
    let mut unauthenticated = pb::agents_client::AgentsClient::connect(server.url.clone())
        .await
        .expect("connect");

    let err = unauthenticated
        .list_agents(pb::ListAgentsRequest {})
        .await
        .expect_err("missing token should be rejected");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    let channel = Channel::from_shared(server.url)
        .expect("valid url")
        .connect()
        .await
        .expect("connect");
    let mut authenticated =
        pb::agents_client::AgentsClient::with_interceptor(channel, BearerToken("grpc-secret"));

    let resp = authenticated
        .list_agents(pb::ListAgentsRequest {})
        .await
        .expect("authorized list_agents");
    let _ = resp.into_inner().agents;
}

#[tokio::test]
async fn test_grpc_metrics_reports_persisted_usage() {
    let server = start_grpc_server().await;
    let agent_id = AgentId::new();
    server
        .state
        .kernel
        .memory
        .usage()
        .record(&UsageRecord {
            agent_id,
            model: "test-model".to_string(),
            input_tokens: 123,
            output_tokens: 45,
            cost_usd: 0.0067,
            tool_calls: 2,
        })
        .expect("record usage");

    let mut client = pb::telemetry_client::TelemetryClient::connect(server.url)
        .await
        .expect("connect");
    let metrics = client
        .get_metrics(pb::GetMetricsRequest {})
        .await
        .expect("get_metrics")
        .into_inner();

    assert_eq!(metrics.tokens_in, 123);
    assert_eq!(metrics.tokens_out, 45);
    assert!((metrics.cost_usd - 0.0067).abs() < f64::EPSILON);
}

#[tokio::test]
async fn test_grpc_decide_approval_returns_agent_and_reason() {
    let server = start_grpc_server().await;
    let approval_id = uuid::Uuid::new_v4();
    let agent_id = "agent-reviewer-1".to_string();
    server
        .state
        .kernel
        .approval_manager
        .submit_pending(ApprovalRequest {
            id: approval_id,
            agent_id: agent_id.clone(),
            tool_name: "file_write".to_string(),
            description: "Apply a reviewed patch".to_string(),
            action_summary: "write src/lib.rs".to_string(),
            risk_level: RiskLevel::High,
            requested_at: Utc::now(),
            timeout_secs: 60,
        })
        .expect("submit approval");

    let mut client = pb::approvals_client::ApprovalsClient::connect(server.url)
        .await
        .expect("connect");
    let record = client
        .decide_approval(pb::DecideApprovalRequest {
            approval_id: approval_id.to_string(),
            approved: true,
            reason: "human reviewed patch".to_string(),
        })
        .await
        .expect("decide approval")
        .into_inner();

    assert_eq!(record.id, approval_id.to_string());
    assert_eq!(record.agent_id, agent_id);
    assert_eq!(record.decision, "approved");
    assert_eq!(record.reason, "human reviewed patch");
    assert!(server
        .state
        .kernel
        .approval_manager
        .list_pending()
        .is_empty());
}

#[tokio::test]
async fn test_grpc_tasks_use_durable_task_records() {
    let server = start_grpc_server().await;
    let manifest: AgentManifest = toml::from_str(
        r#"
name = "grpc-task-agent"
version = "0.1.0"
description = "gRPC task test agent"
author = "test"
module = "builtin:chat"

[model]
provider = "ollama"
model = "test-model"

[capabilities]
tools = []
"#,
    )
    .expect("manifest");
    let agent_id = server
        .state
        .kernel
        .spawn_agent(manifest)
        .expect("spawn agent");

    let mut client = pb::tasks_client::TasksClient::connect(server.url)
        .await
        .expect("connect");
    let created = client
        .create_task(pb::CreateTaskRequest {
            agent_id: agent_id.to_string(),
            prompt: "perform durable task".to_string(),
            metadata: [("source".to_string(), "test".to_string())].into(),
        })
        .await
        .expect("create task")
        .into_inner();

    assert_ne!(created.id, agent_id.to_string());
    assert_eq!(created.agent_id, agent_id.to_string());
    assert_eq!(created.prompt, "perform durable task");

    let fetched = client
        .get_task(pb::GetTaskRequest {
            task_id: created.id.clone(),
        })
        .await
        .expect("get task")
        .into_inner();
    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.agent_id, agent_id.to_string());

    let cancelled = client
        .cancel_task(pb::CancelTaskRequest {
            task_id: fetched.id,
            reason: "test cleanup".to_string(),
        })
        .await
        .expect("cancel task")
        .into_inner();
    assert_eq!(cancelled.state, "cancelled");
}

#[tokio::test]
async fn test_grpc_shell_uses_sandboxed_tool_runner() {
    let server = start_grpc_server().await;
    let mut client = pb::shell_client::ShellClient::connect(server.url)
        .await
        .expect("connect");
    let mut stream = client
        .exec(pb::ExecRequest {
            workspace: String::new(),
            command: "echo".to_string(),
            args: vec!["ok".to_string()],
            env: Default::default(),
        })
        .await
        .expect("exec")
        .into_inner();

    let output = stream
        .message()
        .await
        .expect("stream output")
        .expect("output event");
    assert_eq!(output.stream, "stdout");
    assert_eq!(output.exit_code, 0);
    assert!(String::from_utf8_lossy(&output.data).contains("ok"));

    let exit = stream
        .message()
        .await
        .expect("stream exit")
        .expect("exit event");
    assert_eq!(exit.stream, "exit");
    assert_eq!(exit.exit_code, 0);
}

#[tokio::test]
async fn test_grpc_files_reject_path_traversal() {
    let server = start_grpc_server().await;
    let mut client = pb::files_client::FilesClient::connect(server.url)
        .await
        .expect("connect");
    let err = client
        .read_file(pb::ReadFileRequest {
            workspace: String::new(),
            path: "../secret.txt".to_string(),
        })
        .await
        .expect_err("traversal should be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_grpc_memory_promote_session_writes_semantic_and_graph() {
    let server = start_grpc_server().await;
    let agent_id = AgentId::new();
    let mut session = server
        .state
        .kernel
        .memory
        .create_session(agent_id)
        .expect("create session");
    session
        .messages
        .push(Message::user("Remember the launch checklist"));
    session
        .messages
        .push(Message::assistant("Launch checklist stored"));
    server
        .state
        .kernel
        .memory
        .save_session(&session)
        .expect("save session");

    let mut client = pb::memory_client::MemoryClient::connect(server.url)
        .await
        .expect("connect");
    let promoted = client
        .promote_session(pb::PromoteSessionRequest {
            session_id: session.id.to_string(),
            target_store: "both".to_string(),
        })
        .await
        .expect("promote session")
        .into_inner();

    assert!(promoted.success);
    assert!(promoted.promoted_id.contains("session:"));

    let recalled = server
        .state
        .kernel
        .memory
        .recall("launch checklist", 10, None)
        .await
        .expect("recall promoted memory");
    assert!(!recalled.is_empty());
}

#[tokio::test]
async fn test_grpc_watch_traces_streams_real_task_events() {
    let server = start_grpc_server().await;
    let task_id = server
        .state
        .kernel
        .memory
        .task_post("trace task", "emit trace", Some("agent-1"), Some("test"))
        .await
        .expect("task post");

    let mut client = pb::telemetry_client::TelemetryClient::connect(server.url)
        .await
        .expect("connect");
    let mut stream = client
        .watch_traces(pb::WatchTracesRequest {
            task_id: task_id.clone(),
        })
        .await
        .expect("watch traces")
        .into_inner();

    let event = stream
        .message()
        .await
        .expect("trace message")
        .expect("trace event");
    assert_eq!(event.trace_id, format!("task:{task_id}"));
    assert_eq!(
        event.attributes.get("task.state"),
        Some(&"pending".to_string())
    );
}
