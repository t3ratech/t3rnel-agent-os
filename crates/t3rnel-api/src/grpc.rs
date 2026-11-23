//! gRPC service implementations for the T3rnel daemon.
//!
//! Serves the `t3rnel.v1` proto services on a dedicated port.
//! This avoids axum version conflicts between tonic 0.12 (axum 0.7)
//! and the main API router (axum 0.8).

use crate::pb;
use crate::routes::AppState;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use t3rnel_types::memory::Memory;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{debug, info};

pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("t3rnel_descriptor");

pub fn grpc_reflection_enabled() -> bool {
    cfg!(debug_assertions)
}

#[derive(Clone)]
struct GrpcAuthInterceptor {
    api_key: Arc<str>,
}

impl GrpcAuthInterceptor {
    fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: Arc::<str>::from(api_key.into()),
        }
    }

    fn is_authorized(&self, authorization: &str) -> bool {
        if self.api_key.is_empty() {
            return true;
        }

        let token = authorization
            .strip_prefix("Bearer ")
            .unwrap_or(authorization)
            .trim();
        token.as_bytes().ct_eq(self.api_key.as_bytes()).into()
    }
}

impl tonic::service::Interceptor for GrpcAuthInterceptor {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        if self.api_key.is_empty() {
            return Ok(request);
        }

        let Some(value) = request.metadata().get("authorization") else {
            return Err(Status::unauthenticated("missing authorization metadata"));
        };
        let authorization = value
            .to_str()
            .map_err(|_| Status::unauthenticated("invalid authorization metadata"))?;
        if self.is_authorized(authorization) {
            Ok(request)
        } else {
            Err(Status::unauthenticated("invalid authorization token"))
        }
    }
}

fn timestamp_now() -> prost_types::Timestamp {
    let now = chrono::Utc::now();
    prost_types::Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos() as i32,
    }
}

fn timestamp_from_rfc3339(raw: Option<&str>) -> Option<prost_types::Timestamp> {
    let raw = raw?;
    chrono::DateTime::parse_from_rfc3339(raw).ok().map(|dt| {
        let utc = dt.with_timezone(&chrono::Utc);
        prost_types::Timestamp {
            seconds: utc.timestamp(),
            nanos: utc.timestamp_subsec_nanos() as i32,
        }
    })
}

fn json_str<'a>(value: &'a serde_json::Value, key: &str) -> &'a str {
    value.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

#[allow(clippy::result_large_err)]
fn task_json_to_proto(task: &serde_json::Value) -> Result<pb::Task, Status> {
    let id = json_str(task, "id");
    if id.is_empty() {
        return Err(Status::internal("task row missing id"));
    }
    let created_at = timestamp_from_rfc3339(task.get("created_at").and_then(|v| v.as_str()));
    let updated_at = timestamp_from_rfc3339(
        task.get("completed_at")
            .and_then(|v| v.as_str())
            .or_else(|| task.get("created_at").and_then(|v| v.as_str())),
    );
    Ok(pb::Task {
        id: id.to_string(),
        agent_id: json_str(task, "assigned_to").to_string(),
        state: json_str(task, "status").to_string(),
        prompt: json_str(task, "description").to_string(),
        created_at,
        updated_at,
    })
}

fn task_signature(task: &serde_json::Value) -> String {
    format!(
        "{}:{}:{}",
        json_str(task, "status"),
        task.get("completed_at").unwrap_or(&serde_json::Value::Null),
        task.get("result").unwrap_or(&serde_json::Value::Null)
    )
}

fn task_trace_event(task: &serde_json::Value) -> pb::TraceEvent {
    let task_id = json_str(task, "id");
    let status = json_str(task, "status");
    let mut attributes = HashMap::new();
    attributes.insert("task.id".to_string(), task_id.to_string());
    attributes.insert("task.state".to_string(), status.to_string());
    attributes.insert(
        "agent.id".to_string(),
        json_str(task, "assigned_to").to_string(),
    );
    attributes.insert(
        "task.title".to_string(),
        json_str(task, "title").to_string(),
    );
    if let Some(result) = task.get("result").and_then(|v| v.as_str()) {
        if !result.is_empty() {
            attributes.insert(
                "task.result.preview".to_string(),
                t3rnel_types::truncate_str(result, 256).to_string(),
            );
        }
    }
    pb::TraceEvent {
        trace_id: format!("task:{task_id}"),
        span_id: format!("task:{task_id}:{status}"),
        name: format!("t3rnel.task.{status}"),
        attributes,
        timestamp: timestamp_from_rfc3339(
            task.get("completed_at")
                .and_then(|v| v.as_str())
                .or_else(|| task.get("created_at").and_then(|v| v.as_str())),
        )
        .or_else(|| Some(timestamp_now())),
    }
}

#[allow(clippy::result_large_err)]
fn resolve_agent_id(state: &AppState, raw: &str) -> Result<t3rnel_types::agent::AgentId, Status> {
    if raw.trim().is_empty() {
        return Err(Status::invalid_argument("agent_id is required"));
    }
    if let Ok(id) = raw.parse::<t3rnel_types::agent::AgentId>() {
        if state.kernel.registry.get(id).is_some() {
            return Ok(id);
        }
    }
    state
        .kernel
        .registry
        .find_by_name(raw)
        .map(|entry| entry.id)
        .ok_or_else(|| Status::not_found(format!("agent not found: {raw}")))
}

// ---------------------------------------------------------------------------
// Agents service
// ---------------------------------------------------------------------------

pub struct AgentsService {
    state: Arc<AppState>,
}

impl AgentsService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl pb::agents_server::Agents for AgentsService {
    async fn list_agents(
        &self,
        _request: Request<pb::ListAgentsRequest>,
    ) -> Result<Response<pb::ListAgentsResponse>, Status> {
        debug!("gRPC ListAgents called");
        let entries = self.state.kernel.registry.list();
        let agents: Vec<pb::Agent> = entries
            .into_iter()
            .map(|e| pb::Agent {
                id: e.id.to_string(),
                name: e.name,
                state: format!("{:?}", e.state).to_lowercase(),
                provider: e.manifest.model.provider.clone(),
                model: e.manifest.model.model.clone(),
                created_at: None,
                last_active: None,
            })
            .collect();
        Ok(Response::new(pb::ListAgentsResponse { agents }))
    }

    async fn spawn_agent(
        &self,
        request: Request<pb::SpawnAgentRequest>,
    ) -> Result<Response<pb::Agent>, Status> {
        let req = request.into_inner();
        info!("gRPC SpawnAgent called");

        let manifest: t3rnel_types::agent::AgentManifest = toml::from_str(&req.manifest_toml)
            .map_err(|e| Status::invalid_argument(format!("Invalid manifest TOML: {e}")))?;

        let id = self
            .state
            .kernel
            .spawn_agent(manifest)
            .map_err(|e| Status::internal(format!("Spawn failed: {e}")))?;

        let entry = self
            .state
            .kernel
            .registry
            .get(id)
            .ok_or_else(|| Status::internal("Agent spawned but not found in registry"))?;

        Ok(Response::new(pb::Agent {
            id: entry.id.to_string(),
            name: entry.name,
            state: format!("{:?}", entry.state).to_lowercase(),
            provider: entry.manifest.model.provider.clone(),
            model: entry.manifest.model.model.clone(),
            created_at: None,
            last_active: None,
        }))
    }

    async fn kill_agent(
        &self,
        request: Request<pb::KillAgentRequest>,
    ) -> Result<Response<pb::KillAgentResponse>, Status> {
        let req = request.into_inner();
        let agent_id = t3rnel_types::agent::AgentId::from_string(&req.agent_id);

        info!(agent_id = %agent_id, "gRPC KillAgent called");

        self.state
            .kernel
            .kill_agent(agent_id)
            .map_err(|e| Status::internal(format!("Kill failed: {e}")))?;

        Ok(Response::new(pb::KillAgentResponse {
            agent_id: req.agent_id,
            killed: true,
        }))
    }

    type WatchAgentsStream = Pin<Box<dyn Stream<Item = Result<pb::AgentEvent, Status>> + Send>>;

    async fn watch_agents(
        &self,
        _request: Request<pb::WatchAgentsRequest>,
    ) -> Result<Response<Self::WatchAgentsStream>, Status> {
        let state = self.state.clone();

        let stream = async_stream::stream! {
            let mut seen = std::collections::HashSet::new();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));

            loop {
                interval.tick().await;
                for entry in state.kernel.registry.list() {
                    let agent = pb::Agent {
                        id: entry.id.to_string(),
                        name: entry.name,
                        state: format!("{:?}", entry.state).to_lowercase(),
                        provider: entry.manifest.model.provider.clone(),
                        model: entry.manifest.model.model.clone(),
                        created_at: Some(prost_types::Timestamp {
                            seconds: entry.created_at.timestamp(),
                            nanos: entry.created_at.timestamp_subsec_nanos() as i32,
                        }),
                        last_active: Some(prost_types::Timestamp {
                            seconds: entry.last_active.timestamp(),
                            nanos: entry.last_active.timestamp_subsec_nanos() as i32,
                        }),
                    };
                    let event_type = if seen.insert(entry.id) {
                        "added"
                    } else {
                        "updated"
                    };
                    yield Ok(pb::AgentEvent {
                        r#type: event_type.to_string(),
                        agent: Some(agent),
                    });
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }
}

// ---------------------------------------------------------------------------
// Tasks service
// ---------------------------------------------------------------------------

pub struct TasksService {
    state: Arc<AppState>,
}

impl TasksService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl pb::tasks_server::Tasks for TasksService {
    async fn create_task(
        &self,
        request: Request<pb::CreateTaskRequest>,
    ) -> Result<Response<pb::Task>, Status> {
        let req = request.into_inner();
        let agent_id = resolve_agent_id(&self.state, &req.agent_id)?;

        info!(agent_id = %agent_id, "gRPC CreateTask called");

        let task_id = self
            .state
            .kernel
            .memory
            .task_post_with_payload(
                "grpc-task",
                &req.prompt,
                Some(&agent_id.to_string()),
                Some("grpc"),
                serde_json::json!({
                    "metadata": req.metadata,
                    "source": "grpc",
                }),
            )
            .await
            .map_err(|e| Status::internal(format!("Task create failed: {e}")))?;

        let state = self.state.clone();
        let prompt = req.prompt;
        let task_id_for_worker = task_id.clone();
        tokio::spawn(async move {
            if let Err(e) = state
                .kernel
                .memory
                .task_start(&task_id_for_worker, &agent_id.to_string())
                .await
            {
                tracing::error!(task_id = %task_id_for_worker, error = %e, "failed to mark gRPC task in_progress");
                return;
            }

            match state.kernel.send_message(agent_id, &prompt).await {
                Ok(result) => {
                    if let Err(e) = state
                        .kernel
                        .memory
                        .task_complete(&task_id_for_worker, &result.response)
                        .await
                    {
                        tracing::error!(task_id = %task_id_for_worker, error = %e, "failed to mark gRPC task completed");
                    }
                }
                Err(e) => {
                    if let Err(update_err) = state
                        .kernel
                        .memory
                        .task_fail(&task_id_for_worker, &e.to_string())
                        .await
                    {
                        tracing::error!(task_id = %task_id_for_worker, error = %update_err, "failed to mark gRPC task failed");
                    }
                }
            }
        });

        let task = self
            .state
            .kernel
            .memory
            .task_get(&task_id)
            .await
            .map_err(|e| Status::internal(format!("Task lookup failed: {e}")))?
            .ok_or_else(|| Status::internal("Task created but not found"))?;
        Ok(Response::new(task_json_to_proto(&task)?))
    }

    async fn get_task(
        &self,
        request: Request<pb::GetTaskRequest>,
    ) -> Result<Response<pb::Task>, Status> {
        let req = request.into_inner();
        let task = self
            .state
            .kernel
            .memory
            .task_get(&req.task_id)
            .await
            .map_err(|e| Status::internal(format!("Task lookup failed: {e}")))?
            .ok_or_else(|| Status::not_found("task not found"))?;
        Ok(Response::new(task_json_to_proto(&task)?))
    }

    async fn cancel_task(
        &self,
        request: Request<pb::CancelTaskRequest>,
    ) -> Result<Response<pb::Task>, Status> {
        let req = request.into_inner();

        info!(task_id = %req.task_id, "gRPC CancelTask called");

        let task = self
            .state
            .kernel
            .memory
            .task_get(&req.task_id)
            .await
            .map_err(|e| Status::internal(format!("Task lookup failed: {e}")))?
            .ok_or_else(|| Status::not_found("task not found"))?;

        if let Some(agent_id) = task
            .get("assigned_to")
            .and_then(|v| v.as_str())
            .and_then(|id| id.parse::<t3rnel_types::agent::AgentId>().ok())
        {
            let _ = self.state.kernel.stop_agent_run(agent_id);
        }

        self.state
            .kernel
            .memory
            .task_cancel(&req.task_id, &req.reason)
            .await
            .map_err(|e| Status::internal(format!("Cancel failed: {e}")))?;

        let updated = self
            .state
            .kernel
            .memory
            .task_get(&req.task_id)
            .await
            .map_err(|e| Status::internal(format!("Task lookup failed: {e}")))?
            .ok_or_else(|| Status::not_found("task not found"))?;
        Ok(Response::new(task_json_to_proto(&updated)?))
    }

    type WatchTaskStream = Pin<Box<dyn Stream<Item = Result<pb::TaskEvent, Status>> + Send>>;

    async fn watch_task(
        &self,
        request: Request<pb::WatchTaskRequest>,
    ) -> Result<Response<Self::WatchTaskStream>, Status> {
        let req = request.into_inner();
        let task_id = req.task_id;
        let state = self.state.clone();
        if state
            .kernel
            .memory
            .task_get(&task_id)
            .await
            .map_err(|e| Status::internal(format!("Task lookup failed: {e}")))?
            .is_none()
        {
            return Err(Status::not_found("task not found"));
        }

        let stream = async_stream::stream! {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
            let mut last_signature = String::new();

            loop {
                interval.tick().await;
                match state.kernel.memory.task_get(&task_id).await {
                    Ok(Some(task)) => {
                        let signature = task_signature(&task);
                        if signature != last_signature {
                            last_signature = signature;
                            let status = json_str(&task, "status").to_string();
                            let message = task
                                .get("result")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let proto_task = match task_json_to_proto(&task) {
                                Ok(task) => task,
                                Err(status) => {
                                    yield Err(status);
                                    break;
                                }
                            };
                            yield Ok(pb::TaskEvent {
                                r#type: status.clone(),
                                task: Some(proto_task),
                                message,
                            });
                            if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
                                break;
                            }
                        }
                    }
                    Ok(None) => {
                        yield Err(Status::not_found("task not found"));
                        break;
                    }
                    Err(e) => {
                        yield Err(Status::internal(format!("Task watch failed: {e}")));
                        break;
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }
}

// ---------------------------------------------------------------------------
// Approvals service
// ---------------------------------------------------------------------------

pub struct ApprovalsService {
    state: Arc<AppState>,
}

impl ApprovalsService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl pb::approvals_server::Approvals for ApprovalsService {
    type WatchApprovalsStream =
        Pin<Box<dyn Stream<Item = Result<pb::ApprovalRequest, Status>> + Send>>;

    async fn watch_approvals(
        &self,
        request: Request<pb::WatchApprovalsRequest>,
    ) -> Result<Response<Self::WatchApprovalsStream>, Status> {
        let req = request.into_inner();
        let agent_id_filter = req.agent_id;
        let state = self.state.clone();

        let stream = async_stream::stream! {
            let mut seen = std::collections::HashSet::new();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));

            loop {
                interval.tick().await;
                let pending = state.kernel.approval_manager.list_pending();
                for approval in pending {
                    if !agent_id_filter.is_empty() && approval.agent_id != agent_id_filter {
                        continue;
                    }
                    if seen.insert(approval.id) {
                        yield Ok(pb::ApprovalRequest {
                            id: approval.id.to_string(),
                            agent_id: approval.agent_id,
                            risk: format!("{:?}", approval.risk_level).to_lowercase(),
                            action: approval.action_summary,
                            description: approval.description,
                            created_at: Some(prost_types::Timestamp {
                                seconds: approval.requested_at.timestamp(),
                                nanos: approval.requested_at.timestamp_subsec_nanos() as i32,
                            }),
                        });
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    async fn decide_approval(
        &self,
        request: Request<pb::DecideApprovalRequest>,
    ) -> Result<Response<pb::ApprovalRecord>, Status> {
        let req = request.into_inner();
        let approval_id = req
            .approval_id
            .parse::<uuid::Uuid>()
            .map_err(|_| Status::invalid_argument("Invalid approval id"))?;

        info!(approval_id = %approval_id, approved = req.approved, "gRPC DecideApproval called");

        let decision = if req.approved {
            t3rnel_types::approval::ApprovalDecision::Approved
        } else {
            t3rnel_types::approval::ApprovalDecision::Denied
        };

        let reason = req.reason.trim().to_string();
        let decided_by = if reason.is_empty() {
            None
        } else {
            Some(reason.clone())
        };

        let record = self
            .state
            .kernel
            .approval_manager
            .resolve(approval_id, decision, decided_by)
            .map_err(|e| Status::internal(format!("Decision failed: {e}")))?;

        Ok(Response::new(pb::ApprovalRecord {
            id: record.request_id.to_string(),
            agent_id: record.agent_id,
            decision: format!("{:?}", record.decision).to_lowercase(),
            reason,
            decided_at: Some(prost_types::Timestamp {
                seconds: record.decided_at.timestamp(),
                nanos: record.decided_at.timestamp_subsec_nanos() as i32,
            }),
        }))
    }
}

// ---------------------------------------------------------------------------
// Telemetry service
// ---------------------------------------------------------------------------

pub struct TelemetryService {
    state: Arc<AppState>,
}

impl TelemetryService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl pb::telemetry_server::Telemetry for TelemetryService {
    type WatchTracesStream = Pin<Box<dyn Stream<Item = Result<pb::TraceEvent, Status>> + Send>>;

    async fn watch_traces(
        &self,
        request: Request<pb::WatchTracesRequest>,
    ) -> Result<Response<Self::WatchTracesStream>, Status> {
        let req = request.into_inner();
        let state = self.state.clone();
        let task_filter = req.task_id;
        if !task_filter.is_empty()
            && state
                .kernel
                .memory
                .task_get(&task_filter)
                .await
                .map_err(|e| Status::internal(format!("Trace task lookup failed: {e}")))?
                .is_none()
        {
            return Err(Status::not_found("task not found"));
        }

        let stream = async_stream::stream! {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
            let mut seen = HashMap::<String, String>::new();
            loop {
                interval.tick().await;
                let tasks = if task_filter.is_empty() {
                    match state.kernel.memory.task_list(None).await {
                        Ok(tasks) => tasks,
                        Err(e) => {
                            yield Err(Status::internal(format!("Trace task list failed: {e}")));
                            break;
                        }
                    }
                } else {
                    match state.kernel.memory.task_get(&task_filter).await {
                        Ok(Some(task)) => vec![task],
                        Ok(None) => {
                            yield Err(Status::not_found("task not found"));
                            break;
                        }
                        Err(e) => {
                            yield Err(Status::internal(format!("Trace task lookup failed: {e}")));
                            break;
                        }
                    }
                };

                for task in tasks {
                    let id = json_str(&task, "id").to_string();
                    let signature = task_signature(&task);
                    if seen.get(&id) == Some(&signature) {
                        continue;
                    }
                    seen.insert(id, signature);
                    yield Ok(task_trace_event(&task));
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_metrics(
        &self,
        _request: Request<pb::GetMetricsRequest>,
    ) -> Result<Response<pb::MetricsSnapshot>, Status> {
        let agents = self.state.kernel.registry.list();
        let active = agents
            .iter()
            .filter(|a| matches!(a.state, t3rnel_types::agent::AgentState::Running))
            .count();
        let usage = self
            .state
            .kernel
            .memory
            .usage()
            .query_summary(None)
            .map_err(|e| Status::internal(format!("Usage metrics unavailable: {e}")))?;
        Ok(Response::new(pb::MetricsSnapshot {
            cost_usd: usage.total_cost_usd,
            tokens_in: usage.total_input_tokens,
            tokens_out: usage.total_output_tokens,
            active_agents: active as u64,
        }))
    }
}

// ---------------------------------------------------------------------------
// CodeReview service
// ---------------------------------------------------------------------------

pub struct CodeReviewService {
    state: Arc<AppState>,
}

impl CodeReviewService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[allow(clippy::result_large_err)]
fn target_from_proto(
    t: &Option<pb::ReviewTarget>,
) -> Result<t3rnel_runtime::review::ReviewTarget, Status> {
    let Some(t) = t else {
        return Err(Status::invalid_argument("Missing review target"));
    };
    use t3rnel_runtime::review::ReviewTarget;
    match t.kind {
        1 => Ok(ReviewTarget::LocalDiff(std::path::PathBuf::from(&t.value))),
        2 => Ok(ReviewTarget::LocalBranch(t.value.clone())),
        3 => Ok(ReviewTarget::GitHubPR(t.value.clone())),
        4 => Ok(ReviewTarget::CodebasePath(std::path::PathBuf::from(
            &t.value,
        ))),
        _ => Err(Status::invalid_argument("Unknown review target kind")),
    }
}

fn report_to_proto(report: &t3rnel_runtime::review::ReviewReport) -> pb::ReviewReport {
    pb::ReviewReport {
        target: Some(pb::ReviewTarget {
            kind: match report.target {
                t3rnel_runtime::review::ReviewTarget::LocalDiff(_) => 1,
                t3rnel_runtime::review::ReviewTarget::LocalBranch(_) => 2,
                t3rnel_runtime::review::ReviewTarget::GitHubPR(_) => 3,
                t3rnel_runtime::review::ReviewTarget::CodebasePath(_) => 4,
            },
            value: format!("{:?}", report.target),
        }),
        summary: report.summary.clone(),
        findings: report
            .findings
            .iter()
            .map(|f| pb::ReviewFinding {
                severity: format!("{:?}", f.severity).to_lowercase(),
                category: format!("{:?}", f.category).to_lowercase(),
                message: f.message.clone(),
                location: Some(pb::ReviewLocation {
                    file: f.location.file.to_string_lossy().to_string(),
                    start_line: f.location.start_line,
                    end_line: f.location.end_line,
                }),
                suggestion: f.suggestion.as_ref().map(|s| pb::ReviewSuggestion {
                    tool: s.tool.clone(),
                    patch: s.patch.clone(),
                }),
            })
            .collect(),
    }
}

#[tonic::async_trait]
impl pb::code_review_server::CodeReview for CodeReviewService {
    type StartReviewStream = Pin<Box<dyn Stream<Item = Result<pb::ReviewEvent, Status>> + Send>>;

    async fn start_review(
        &self,
        request: Request<pb::StartReviewRequest>,
    ) -> Result<Response<Self::StartReviewStream>, Status> {
        let req = request.into_inner();
        let target = target_from_proto(&req.target)?;
        let review_id = uuid::Uuid::new_v4().to_string();
        let cwd = self.state.kernel.config.home_dir.clone();
        let report = t3rnel_runtime::review::preflight_review(target, &cwd);
        let proto_report = report_to_proto(&report);
        let stream = async_stream::stream! {
            yield Ok(pb::ReviewEvent {
                review_id: review_id.clone(),
                r#type: "report".to_string(),
                report: Some(proto_report),
                finding: None,
                message: String::new(),
            });
            for finding in &report.findings {
                yield Ok(pb::ReviewEvent {
                    review_id: review_id.clone(),
                    r#type: "finding".to_string(),
                    report: None,
                    finding: Some(pb::ReviewFinding {
                        severity: format!("{:?}", finding.severity).to_lowercase(),
                        category: format!("{:?}", finding.category).to_lowercase(),
                        message: finding.message.clone(),
                        location: Some(pb::ReviewLocation {
                            file: finding.location.file.to_string_lossy().to_string(),
                            start_line: finding.location.start_line,
                            end_line: finding.location.end_line,
                        }),
                        suggestion: finding.suggestion.as_ref().map(|s| pb::ReviewSuggestion {
                            tool: s.tool.clone(),
                            patch: s.patch.clone(),
                        }),
                    }),
                    message: finding.message.clone(),
                });
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }

    async fn comment_review(
        &self,
        request: Request<pb::CommentReviewRequest>,
    ) -> Result<Response<pb::ReviewComment>, Status> {
        let req = request.into_inner();
        let comment_id = uuid::Uuid::new_v4().to_string();
        tracing::info!(
            review_id = %req.review_id,
            finding_id = %req.finding_id,
            "Review comment added"
        );
        Ok(Response::new(pb::ReviewComment {
            id: comment_id,
            review_id: req.review_id,
            finding_id: req.finding_id,
            body: req.body,
            resolved: false,
        }))
    }

    async fn resolve_review(
        &self,
        request: Request<pb::ResolveReviewRequest>,
    ) -> Result<Response<pb::ReviewComment>, Status> {
        let req = request.into_inner();
        let comment_id = uuid::Uuid::new_v4().to_string();
        tracing::info!(
            review_id = %req.review_id,
            finding_id = %req.finding_id,
            reason = %req.reason,
            "Review finding resolved"
        );
        Ok(Response::new(pb::ReviewComment {
            id: comment_id,
            review_id: req.review_id,
            finding_id: req.finding_id,
            body: req.reason,
            resolved: true,
        }))
    }
}

// ---------------------------------------------------------------------------
// Prompts service
// ---------------------------------------------------------------------------

pub struct PromptsService {
    state: Arc<AppState>,
}

impl PromptsService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    #[allow(clippy::result_large_err)]
    fn load_cache(&self) -> Result<t3rnel_prompts::PromptCache, Status> {
        let prompts_dir = self.state.kernel.config.home_dir.join("prompts");
        if !prompts_dir.exists() {
            return Ok(t3rnel_prompts::PromptCache::default());
        }
        t3rnel_prompts::PromptCache::load_dir(&prompts_dir)
            .map_err(|e| Status::internal(format!("Failed to load prompts: {e}")))
    }
}

#[tonic::async_trait]
impl pb::prompts_server::Prompts for PromptsService {
    async fn list_prompts(
        &self,
        _request: Request<pb::ListPromptsRequest>,
    ) -> Result<Response<pb::ListPromptsResponse>, Status> {
        let cache = self.load_cache()?;
        let prompts = cache.list();
        let items = prompts
            .into_iter()
            .map(|p| pb::PromptDocument {
                id: p.id.clone(),
                role: p.frontmatter.role.clone(),
                name: p.frontmatter.name.clone().unwrap_or_default(),
                variant: p
                    .frontmatter
                    .variant
                    .clone()
                    .unwrap_or_else(|| "A".to_string()),
                version: p.frontmatter.version.clone(),
                sha256: p.sha256.clone(),
                body: p.body.clone(),
                model_hints: p.frontmatter.model_hints.clone(),
                eval_set: p.frontmatter.eval_set.clone(),
                parents: p.frontmatter.parents.clone(),
            })
            .collect();
        Ok(Response::new(pb::ListPromptsResponse { prompts: items }))
    }

    async fn get_prompt_variant(
        &self,
        request: Request<pb::GetPromptVariantRequest>,
    ) -> Result<Response<pb::PromptDocument>, Status> {
        let req = request.into_inner();
        let cache = self.load_cache()?;
        let variants: Vec<String> = req.variants;
        let selected = if variants.is_empty() {
            req.name.clone()
        } else {
            t3rnel_prompts::select_variant(&req.task_id, &req.name, &variants)
                .unwrap_or_else(|| req.name.clone())
        };
        let prompt = cache
            .get(&selected)
            .ok_or_else(|| Status::not_found(format!("Prompt {} not found", selected)))?;
        Ok(Response::new(pb::PromptDocument {
            id: prompt.id.clone(),
            role: prompt.frontmatter.role.clone(),
            name: prompt.frontmatter.name.clone().unwrap_or_default(),
            variant: prompt
                .frontmatter
                .variant
                .clone()
                .unwrap_or_else(|| "A".to_string()),
            version: prompt.frontmatter.version.clone(),
            sha256: prompt.sha256.clone(),
            body: prompt.body.clone(),
            model_hints: prompt.frontmatter.model_hints.clone(),
            eval_set: prompt.frontmatter.eval_set.clone(),
            parents: prompt.frontmatter.parents.clone(),
        }))
    }

    async fn report_prompt_outcome(
        &self,
        request: Request<pb::ReportPromptOutcomeRequest>,
    ) -> Result<Response<pb::ReportPromptOutcomeResponse>, Status> {
        let req = request.into_inner();
        let outcome = match req.outcome.as_str() {
            "win" => t3rnel_prompts::PromptOutcome::Win,
            "loss" => t3rnel_prompts::PromptOutcome::Loss,
            _ => t3rnel_prompts::PromptOutcome::Draw,
        };
        let tracker = self.state.winrate_tracker.lock().await;
        tracker
            .record_outcome(
                &req.prompt_id,
                &req.variant,
                if req.experiment_id.is_empty() {
                    None
                } else {
                    Some(&req.experiment_id)
                },
                outcome,
                if req.metric_value == 0.0 {
                    None
                } else {
                    Some(req.metric_value)
                },
            )
            .map_err(|e| Status::internal(format!("Failed to record outcome: {e}")))?;
        Ok(Response::new(pb::ReportPromptOutcomeResponse {
            success: true,
        }))
    }

    async fn get_prompt_win_rate(
        &self,
        request: Request<pb::GetPromptWinRateRequest>,
    ) -> Result<Response<pb::GetPromptWinRateResponse>, Status> {
        let req = request.into_inner();
        let tracker = self.state.winrate_tracker.lock().await;
        let stats = tracker
            .get_win_rate(&req.prompt_id, &req.variant)
            .map_err(|e| Status::internal(format!("Failed to get win rate: {e}")))?;
        Ok(Response::new(pb::GetPromptWinRateResponse {
            total: stats.total,
            wins: stats.wins,
            losses: stats.losses,
            draws: stats.draws,
            win_rate: stats.win_rate(),
            avg_metric: stats.avg_metric.unwrap_or(0.0),
        }))
    }
}

// ---------------------------------------------------------------------------
// Files service
// ---------------------------------------------------------------------------

pub struct FilesService {
    state: Arc<AppState>,
}

impl FilesService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    #[allow(clippy::result_large_err)]
    fn resolve_workspace_path(&self, workspace: &str, rel: &str) -> Result<PathBuf, Status> {
        let base = self.state.kernel.config.effective_workspaces_dir();
        std::fs::create_dir_all(&base).map_err(|e| {
            Status::internal(format!(
                "Failed to create workspace root {}: {e}",
                base.display()
            ))
        })?;
        let canonical_base = base.canonicalize().map_err(|e| {
            Status::internal(format!(
                "Failed to canonicalize workspace root {}: {e}",
                base.display()
            ))
        })?;

        let mut combined = PathBuf::new();
        for segment in [workspace, rel] {
            if segment.trim().is_empty() || segment == "." {
                continue;
            }
            let path = Path::new(segment);
            if path.is_absolute() {
                return Err(Status::invalid_argument(
                    "Absolute paths are not allowed in workspace APIs",
                ));
            }
            for component in path.components() {
                match component {
                    Component::Normal(part) => combined.push(part),
                    Component::CurDir => {}
                    Component::ParentDir => {
                        return Err(Status::invalid_argument(
                            "Path traversal is not allowed in workspace APIs",
                        ));
                    }
                    Component::RootDir | Component::Prefix(_) => {
                        return Err(Status::invalid_argument(
                            "Absolute paths are not allowed in workspace APIs",
                        ));
                    }
                }
            }
        }

        let path = canonical_base.join(combined);
        let containment_check = if path.exists() {
            path.canonicalize().map_err(|e| {
                Status::internal(format!("Failed to canonicalize {}: {e}", path.display()))
            })?
        } else {
            let parent = path.parent().unwrap_or(&canonical_base);
            let canonical_parent = parent.canonicalize().map_err(|e| {
                Status::invalid_argument(format!(
                    "Parent directory does not exist or is not accessible: {e}"
                ))
            })?;
            if !canonical_parent.starts_with(&canonical_base) {
                return Err(Status::invalid_argument("Path escapes workspace"));
            }
            path.clone()
        };

        if !containment_check.starts_with(&canonical_base) {
            return Err(Status::invalid_argument("Path escapes workspace"));
        }
        Ok(path)
    }
}

#[tonic::async_trait]
impl pb::files_server::Files for FilesService {
    async fn list_files(
        &self,
        request: Request<pb::ListFilesRequest>,
    ) -> Result<Response<pb::ListFilesResponse>, Status> {
        let req = request.into_inner();
        let dir = self.resolve_workspace_path(&req.workspace, &req.path)?;
        if !dir.is_dir() {
            return Err(Status::invalid_argument("Not a directory"));
        }
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&dir).map_err(|e| Status::internal(e.to_string()))? {
            let entry = entry.map_err(|e| Status::internal(e.to_string()))?;
            let meta = entry
                .metadata()
                .map_err(|e| Status::internal(e.to_string()))?;
            entries.push(pb::FileEntry {
                path: entry.file_name().to_string_lossy().to_string(),
                directory: meta.is_dir(),
                size_bytes: meta.len(),
            });
        }
        Ok(Response::new(pb::ListFilesResponse { entries }))
    }

    async fn read_file(
        &self,
        request: Request<pb::ReadFileRequest>,
    ) -> Result<Response<pb::ReadFileResponse>, Status> {
        let req = request.into_inner();
        let workspace = self.resolve_workspace_path(&req.workspace, &req.path)?;
        let content =
            std::fs::read(&workspace).map_err(|e| Status::internal(format!("Read failed: {e}")))?;
        Ok(Response::new(pb::ReadFileResponse {
            path: req.path,
            content,
        }))
    }

    async fn propose_patch(
        &self,
        request: Request<pb::ProposePatchRequest>,
    ) -> Result<Response<pb::PatchProposal>, Status> {
        let req = request.into_inner();
        let _workspace = self.resolve_workspace_path(&req.workspace, "")?;
        let diff = req.unified_diff;
        let ops = t3rnel_runtime::apply_patch::parse_patch(&diff)
            .map_err(|e| Status::invalid_argument(format!("Invalid patch: {e}")))?;
        let mut touched = Vec::new();
        for op in &ops {
            match op {
                t3rnel_runtime::apply_patch::PatchOp::AddFile { path, .. } => {
                    touched.push(path.clone())
                }
                t3rnel_runtime::apply_patch::PatchOp::UpdateFile { path, .. } => {
                    touched.push(path.clone())
                }
                t3rnel_runtime::apply_patch::PatchOp::DeleteFile { path } => {
                    touched.push(path.clone())
                }
            }
        }
        Ok(Response::new(pb::PatchProposal {
            id: uuid::Uuid::new_v4().to_string(),
            unified_diff: diff,
            touched_paths: touched,
        }))
    }

    async fn apply_patch(
        &self,
        request: Request<pb::ApplyPatchRequest>,
    ) -> Result<Response<pb::ApplyPatchResponse>, Status> {
        let req = request.into_inner();
        let workspace = self.resolve_workspace_path(&req.workspace, "")?;
        std::fs::create_dir_all(&workspace).map_err(|e| {
            Status::internal(format!(
                "Failed to create patch workspace {}: {e}",
                workspace.display()
            ))
        })?;
        let ops = t3rnel_runtime::apply_patch::parse_patch(&req.unified_diff)
            .map_err(|e| Status::invalid_argument(format!("Invalid patch: {e}")))?;
        let mut touched_paths = Vec::new();
        for op in &ops {
            match op {
                t3rnel_runtime::apply_patch::PatchOp::AddFile { path, .. } => {
                    touched_paths.push(path.clone())
                }
                t3rnel_runtime::apply_patch::PatchOp::UpdateFile { path, .. } => {
                    touched_paths.push(path.clone())
                }
                t3rnel_runtime::apply_patch::PatchOp::DeleteFile { path } => {
                    touched_paths.push(path.clone())
                }
            }
        }
        let result = t3rnel_runtime::apply_patch::apply_patch(&ops, &workspace).await;
        let applied = result.errors.is_empty();
        Ok(Response::new(pb::ApplyPatchResponse {
            proposal_id: req.proposal_id,
            applied,
            touched_paths,
        }))
    }
}

// ---------------------------------------------------------------------------
// Shell service
// ---------------------------------------------------------------------------

pub struct ShellService {
    state: Arc<AppState>,
}

impl ShellService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

fn shell_quote_arg(arg: &str) -> String {
    if !arg.is_empty()
        && arg.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b':' | b'=')
        })
    {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn parse_tool_exit_code(content: &str) -> i32 {
    content
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("Exit code: "))
        .and_then(|raw| raw.trim().parse::<i32>().ok())
        .unwrap_or(1)
}

#[tonic::async_trait]
impl pb::shell_server::Shell for ShellService {
    type ExecStream = Pin<Box<dyn Stream<Item = Result<pb::ExecEvent, Status>> + Send>>;

    async fn exec(
        &self,
        request: Request<pb::ExecRequest>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let req = request.into_inner();
        if req.command.trim().is_empty() {
            return Err(Status::invalid_argument("command is required"));
        }
        if !req.env.is_empty() {
            return Err(Status::invalid_argument(
                "per-request environment injection is not allowed; configure allowed environment in agent/kernel policy",
            ));
        }

        let workspace =
            FilesService::new(self.state.clone()).resolve_workspace_path(&req.workspace, "")?;
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<pb::ExecEvent, Status>>(64);
        let mut command = req.command;
        for arg in req.args {
            command.push(' ');
            command.push_str(&shell_quote_arg(&arg));
        }
        let state = self.state.clone();
        tokio::spawn(async move {
            let allowed_tools = [String::from("shell_exec")];
            let allowed_env: Vec<String> = Vec::new();
            let result = t3rnel_runtime::tool_runner::execute_tool(
                "grpc-shell",
                "shell_exec",
                &serde_json::json!({
                    "command": command,
                    "timeout_seconds": state.kernel.config.exec_policy.timeout_secs,
                }),
                None,
                Some(&allowed_tools),
                Some("grpc"),
                None,
                None,
                None,
                None,
                Some(&allowed_env),
                Some(&workspace),
                None,
                Some(&state.kernel.config.exec_policy),
                None,
                Some(&state.kernel.config.docker),
                Some(state.kernel.process_manager.as_ref()),
            )
            .await;

            let exit_code = if result.is_error {
                1
            } else {
                parse_tool_exit_code(&result.content)
            };
            let stream_name = if result.is_error { "stderr" } else { "stdout" };
            let _ = tx
                .send(Ok(pb::ExecEvent {
                    stream: stream_name.to_string(),
                    data: result.content.into_bytes(),
                    exit_code,
                }))
                .await;
            let _ = tx
                .send(Ok(pb::ExecEvent {
                    stream: "exit".to_string(),
                    data: vec![],
                    exit_code,
                }))
                .await;
        });
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as Self::ExecStream))
    }
}

// ---------------------------------------------------------------------------
// Memory service — Knowledge Graph queries and lesson writing
// ---------------------------------------------------------------------------

pub struct MemoryService {
    state: Arc<AppState>,
}

impl MemoryService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl pb::memory_server::Memory for MemoryService {
    async fn query_graph(
        &self,
        request: Request<pb::QueryGraphRequest>,
    ) -> Result<Response<pb::QueryGraphResponse>, Status> {
        let req = request.into_inner();
        let conn = self.state.kernel.memory.usage_conn();
        let store = t3rnel_memory::knowledge::KnowledgeStore::new(conn);

        let pattern = t3rnel_types::memory::GraphPattern {
            source: if req.source.is_empty() {
                None
            } else {
                Some(req.source)
            },
            relation: if req.relation.is_empty() {
                None
            } else {
                serde_json::from_str(&req.relation).ok()
            },
            target: if req.target.is_empty() {
                None
            } else {
                Some(req.target)
            },
            max_depth: req.max_depth,
        };

        let matches = store
            .query_graph(pattern)
            .map_err(|e| Status::internal(format!("Graph query failed: {e}")))?;

        let proto_matches = matches
            .into_iter()
            .map(|m| pb::GraphMatch {
                source: Some(pb::Entity {
                    id: m.source.id,
                    entity_type: format!("{:?}", m.source.entity_type),
                    name: m.source.name,
                    properties_json: serde_json::to_string(&m.source.properties)
                        .unwrap_or_default(),
                }),
                relation: Some(pb::Relation {
                    id: String::new(),
                    source: m.relation.source,
                    relation_type: format!("{:?}", m.relation.relation),
                    target: m.relation.target,
                    confidence: m.relation.confidence as f64,
                }),
                target: Some(pb::Entity {
                    id: m.target.id,
                    entity_type: format!("{:?}", m.target.entity_type),
                    name: m.target.name,
                    properties_json: serde_json::to_string(&m.target.properties)
                        .unwrap_or_default(),
                }),
            })
            .collect();

        Ok(Response::new(pb::QueryGraphResponse {
            matches: proto_matches,
        }))
    }

    async fn write_lesson(
        &self,
        request: Request<pb::WriteLessonRequest>,
    ) -> Result<Response<pb::WriteLessonResponse>, Status> {
        let req = request.into_inner();
        let conn = self.state.kernel.memory.usage_conn();
        let store = t3rnel_memory::knowledge::KnowledgeStore::new(conn);

        let lesson_id = store
            .write_lesson(t3rnel_memory::knowledge::LessonInput {
                task_id: req.task_id,
                summary: req.summary,
                outcome: req.outcome,
                source_agent: if req.source_agent.is_empty() {
                    None
                } else {
                    Some(req.source_agent)
                },
                approval_reason: if req.approval_reason.is_empty() {
                    None
                } else {
                    Some(req.approval_reason)
                },
                metadata: std::collections::HashMap::new(),
            })
            .map_err(|e| Status::internal(format!("Write lesson failed: {e}")))?;

        Ok(Response::new(pb::WriteLessonResponse {
            lesson_id,
            success: true,
        }))
    }

    async fn promote_session(
        &self,
        request: Request<pb::PromoteSessionRequest>,
    ) -> Result<Response<pb::PromoteSessionResponse>, Status> {
        let req = request.into_inner();
        let session_uuid = uuid::Uuid::parse_str(&req.session_id)
            .map_err(|_| Status::invalid_argument("invalid session_id"))?;
        let session_id = t3rnel_types::agent::SessionId(session_uuid);
        let session = self
            .state
            .kernel
            .memory
            .get_session(session_id)
            .map_err(|e| Status::internal(format!("Session lookup failed: {e}")))?
            .ok_or_else(|| Status::not_found("session not found"))?;

        let target = req.target_store.trim().to_lowercase();
        if !target.is_empty() && !matches!(target.as_str(), "semantic" | "knowledge" | "both") {
            return Err(Status::invalid_argument(
                "target_store must be 'semantic', 'knowledge', 'both', or empty",
            ));
        }
        let promote_semantic = target.is_empty() || matches!(target.as_str(), "semantic" | "both");
        let promote_knowledge =
            target.is_empty() || matches!(target.as_str(), "knowledge" | "both");

        let mut promoted_ids = Vec::new();
        if promote_semantic {
            for (idx, msg) in session.messages.iter().enumerate() {
                let content = msg.content.text_content();
                let content = content.trim();
                if content.is_empty() {
                    continue;
                }
                let mut metadata = HashMap::new();
                metadata.insert(
                    "session_id".to_string(),
                    serde_json::Value::String(req.session_id.clone()),
                );
                metadata.insert("message_index".to_string(), serde_json::json!(idx));
                metadata.insert(
                    "role".to_string(),
                    serde_json::Value::String(format!("{:?}", msg.role).to_lowercase()),
                );
                let embedding = if let Some(driver) = self.state.kernel.embedding_driver.as_ref() {
                    Some(
                        driver
                            .embed_one(content)
                            .await
                            .map_err(|e| Status::internal(format!("Embedding failed: {e}")))?,
                    )
                } else {
                    None
                };
                let memory_id = self
                    .state
                    .kernel
                    .memory
                    .remember_with_embedding_async(
                        session.agent_id,
                        content,
                        t3rnel_types::memory::MemorySource::Conversation,
                        "session",
                        metadata,
                        embedding.as_deref(),
                    )
                    .await
                    .map_err(|e| Status::internal(format!("Semantic promotion failed: {e}")))?;
                promoted_ids.push(memory_id.to_string());
            }
        }

        if promote_knowledge {
            let now = chrono::Utc::now();
            let session_entity_id = format!("session:{}", req.session_id);
            let mut properties = HashMap::new();
            properties.insert(
                "session_id".to_string(),
                serde_json::Value::String(req.session_id.clone()),
            );
            properties.insert(
                "agent_id".to_string(),
                serde_json::Value::String(session.agent_id.to_string()),
            );
            properties.insert(
                "message_count".to_string(),
                serde_json::json!(session.messages.len()),
            );
            if let Some(label) = session.label.clone() {
                properties.insert("label".to_string(), serde_json::Value::String(label));
            }
            self.state
                .kernel
                .memory
                .add_entity(t3rnel_types::memory::Entity {
                    id: session_entity_id.clone(),
                    entity_type: t3rnel_types::memory::EntityType::Document,
                    name: format!("Session {}", req.session_id),
                    properties,
                    created_at: now,
                    updated_at: now,
                })
                .await
                .map_err(|e| Status::internal(format!("Knowledge promotion failed: {e}")))?;

            let agent_entity_id = format!("agent:{}", session.agent_id);
            self.state
                .kernel
                .memory
                .add_entity(t3rnel_types::memory::Entity {
                    id: agent_entity_id.clone(),
                    entity_type: t3rnel_types::memory::EntityType::Agent,
                    name: session.agent_id.to_string(),
                    properties: HashMap::new(),
                    created_at: now,
                    updated_at: now,
                })
                .await
                .map_err(|e| Status::internal(format!("Knowledge promotion failed: {e}")))?;

            self.state
                .kernel
                .memory
                .add_relation(t3rnel_types::memory::Relation {
                    source: session_entity_id.clone(),
                    relation: t3rnel_types::memory::RelationType::CreatedBy,
                    target: agent_entity_id,
                    properties: HashMap::new(),
                    confidence: 1.0,
                    created_at: now,
                })
                .await
                .map_err(|e| Status::internal(format!("Knowledge promotion failed: {e}")))?;
            promoted_ids.push(session_entity_id);
        }

        if promoted_ids.is_empty() {
            return Err(Status::failed_precondition(
                "session contains no promotable content",
            ));
        }

        Ok(Response::new(pb::PromoteSessionResponse {
            success: true,
            promoted_id: promoted_ids.join(","),
        }))
    }
}

// ---------------------------------------------------------------------------
// Build the gRPC server (standalone on a dedicated port)
// ---------------------------------------------------------------------------

/// Start the gRPC server on a dedicated port.
///
/// Returns the bound address. The caller must keep the returned handle alive
/// to keep the server running.
pub async fn start_grpc_server(
    state: Arc<AppState>,
    port: u16,
) -> Result<std::net::SocketAddr, Box<dyn std::error::Error>> {
    let auth = GrpcAuthInterceptor::new(state.kernel.config.api_key.trim().to_string());
    let agents = pb::agents_server::AgentsServer::with_interceptor(
        AgentsService::new(state.clone()),
        auth.clone(),
    );
    let tasks = pb::tasks_server::TasksServer::with_interceptor(
        TasksService::new(state.clone()),
        auth.clone(),
    );
    let approvals = pb::approvals_server::ApprovalsServer::with_interceptor(
        ApprovalsService::new(state.clone()),
        auth.clone(),
    );
    let telemetry = pb::telemetry_server::TelemetryServer::with_interceptor(
        TelemetryService::new(state.clone()),
        auth.clone(),
    );
    let code_review = pb::code_review_server::CodeReviewServer::with_interceptor(
        CodeReviewService::new(state.clone()),
        auth.clone(),
    );
    let prompts = pb::prompts_server::PromptsServer::with_interceptor(
        PromptsService::new(state.clone()),
        auth.clone(),
    );
    let files = pb::files_server::FilesServer::with_interceptor(
        FilesService::new(state.clone()),
        auth.clone(),
    );
    let shell = pb::shell_server::ShellServer::with_interceptor(
        ShellService::new(state.clone()),
        auth.clone(),
    );
    let memory = pb::memory_server::MemoryServer::with_interceptor(MemoryService::new(state), auth);

    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let router = tonic::transport::Server::builder()
        .accept_http1(true)
        .layer(tower_http::cors::CorsLayer::permissive())
        .layer(tonic_web::GrpcWebLayer::new())
        .add_service(agents)
        .add_service(tasks)
        .add_service(approvals)
        .add_service(telemetry)
        .add_service(code_review)
        .add_service(prompts)
        .add_service(files)
        .add_service(shell)
        .add_service(memory);

    #[cfg(debug_assertions)]
    let router = {
        let reflection = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
            .build_v1()?;
        router.add_service(reflection)
    };

    let server = router.serve_with_incoming(incoming);

    tokio::spawn(server);
    Ok(bound)
}
