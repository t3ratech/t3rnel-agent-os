//! Task scheduler and fanout dispatcher.
//!
//! Routes incoming tasks to appropriate agents based on their role and
//! the orchestrator's dispatch plan. Supports parallel fanout for
//! independent subtasks and sequential chaining for dependent ones.

use crate::kernel_handle::KernelHandle;
use std::collections::{HashMap, HashSet};
use tokio::time::{sleep, timeout, Duration};
use tracing::{debug, error, info, warn};

/// Maximum number of parallel agent dispatches.
const MAX_FANOUT: usize = 8;

/// Default timeout for each dispatch step (seconds).
const DEFAULT_STEP_TIMEOUT_SECS: u64 = 300;

/// Retry backoff base in milliseconds.
const RETRY_BACKOFF_MS: u64 = 1000;

/// Scheduler configuration.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    pub max_fanout: usize,
    pub timeout_secs: u64,
    pub retry_count: u32,
    /// Maximum budget in USD for a single dispatch plan.
    pub budget_usd_max: f64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_fanout: MAX_FANOUT,
            timeout_secs: DEFAULT_STEP_TIMEOUT_SECS,
            retry_count: 2,
            budget_usd_max: 10.0,
        }
    }
}

/// Budget guard tracks cumulative spend and halts when limit exceeded.
#[derive(Debug, Clone)]
pub struct BudgetGuard {
    pub usd_max: f64,
    pub usd_spent: f64,
    pub tokens_in: u64,
    pub tokens_out: u64,
}

impl BudgetGuard {
    pub fn new(usd_max: f64) -> Self {
        Self {
            usd_max,
            usd_spent: 0.0,
            tokens_in: 0,
            tokens_out: 0,
        }
    }

    pub fn check(&self, additional_cost: f64) -> Result<(), SchedulerError> {
        if self.usd_spent + additional_cost > self.usd_max {
            Err(SchedulerError::BudgetExceeded(self.usd_max))
        } else {
            Ok(())
        }
    }

    pub fn spend(&mut self, cost: f64, tokens_in: u64, tokens_out: u64) {
        self.usd_spent += cost;
        self.tokens_in += tokens_in;
        self.tokens_out += tokens_out;
    }
}

/// A dispatch plan describing how a task should be split across agents.
#[derive(Debug, Clone)]
pub struct DispatchPlan {
    pub task_id: String,
    pub steps: Vec<DispatchStep>,
}

/// A single step in a dispatch plan.
#[derive(Debug, Clone)]
pub struct DispatchStep {
    pub role: String,
    pub prompt: String,
    pub depends_on: Vec<usize>,
    pub metadata: HashMap<String, String>,
    /// Estimated cost in USD for this step.
    pub estimated_cost_usd: f64,
}

impl DispatchStep {
    pub fn new(role: &str, prompt: &str) -> Self {
        Self {
            role: role.to_string(),
            prompt: prompt.to_string(),
            depends_on: vec![],
            metadata: HashMap::new(),
            estimated_cost_usd: 0.0,
        }
    }

    pub fn with_deps(mut self, deps: Vec<usize>) -> Self {
        self.depends_on = deps;
        self
    }

    pub fn with_cost(mut self, cost: f64) -> Self {
        self.estimated_cost_usd = cost;
        self
    }
}

/// Task decomposition result from the orchestrator.
#[derive(Debug, Clone)]
pub struct SubTask {
    pub title: String,
    pub description: String,
    pub agent_hint: String,
    pub blockers: Vec<String>,
    pub estimated_cost_usd: f64,
    pub priority: u8,
}

/// Scheduler that manages task dispatch and fanout.
pub struct Scheduler {
    config: SchedulerConfig,
}

impl Scheduler {
    pub fn new(config: SchedulerConfig) -> Self {
        Self { config }
    }

    /// Build a dispatch plan for a given high-level task.
    ///
    /// Decomposes the task into subtasks based on keyword heuristics.
    /// For complex tasks, the orchestrator LLM would decompose; this
    /// scheduler provides a fast rule-based fallback.
    pub fn build_plan(&self, task: &str) -> DispatchPlan {
        let subtasks = self.decompose_task(task);
        let steps: Vec<DispatchStep> = subtasks
            .into_iter()
            .enumerate()
            .map(|(idx, st)| {
                let deps: Vec<usize> = st
                    .blockers
                    .iter()
                    .filter_map(|b| b.parse::<usize>().ok())
                    .collect();
                DispatchStep {
                    role: st.agent_hint,
                    prompt: format!("{}: {}", st.title, st.description),
                    depends_on: deps,
                    metadata: {
                        let mut m = HashMap::new();
                        m.insert("priority".to_string(), st.priority.to_string());
                        m.insert("step_index".to_string(), idx.to_string());
                        m
                    },
                    estimated_cost_usd: st.estimated_cost_usd,
                }
            })
            .collect();

        info!(task = %task, steps = steps.len(), "built dispatch plan");
        DispatchPlan {
            task_id: uuid::Uuid::new_v4().to_string(),
            steps,
        }
    }

    /// Decompose a task into subtasks using keyword heuristics.
    fn decompose_task(&self, task: &str) -> Vec<SubTask> {
        let lower = task.to_lowercase();

        // Coding tasks
        if lower.contains("implement")
            || lower.contains("code")
            || lower.contains("write")
            || lower.contains("refactor")
            || lower.contains("bug")
            || lower.contains("fix")
        {
            return self.decompose_coding_task(task);
        }

        // Review tasks
        if lower.contains("review") || lower.contains("audit") || lower.contains("security check") {
            return self.decompose_review_task(task);
        }

        // Documentation tasks
        if lower.contains("document") || lower.contains("readme") || lower.contains("docs") {
            return self.decompose_doc_task(task);
        }

        // Test tasks
        if lower.contains("test") || lower.contains("unit test") || lower.contains("e2e") {
            return self.decompose_test_task(task);
        }

        // Default: single orchestrator step
        vec![SubTask {
            title: "orchestrate".to_string(),
            description: task.to_string(),
            agent_hint: "t3rnel".to_string(),
            blockers: vec![],
            estimated_cost_usd: 0.5,
            priority: 5,
        }]
    }

    fn decompose_coding_task(&self, task: &str) -> Vec<SubTask> {
        vec![
            SubTask {
                title: "design".to_string(),
                description: format!("Design the approach for: {}", task),
                agent_hint: "architect".to_string(),
                blockers: vec![],
                estimated_cost_usd: 0.3,
                priority: 5,
            },
            SubTask {
                title: "implement".to_string(),
                description: format!("Implement: {}", task),
                agent_hint: "coder".to_string(),
                blockers: vec!["0".to_string()],
                estimated_cost_usd: 1.0,
                priority: 5,
            },
            SubTask {
                title: "test".to_string(),
                description: format!("Write tests for: {}", task),
                agent_hint: "test_engineer".to_string(),
                blockers: vec!["1".to_string()],
                estimated_cost_usd: 0.5,
                priority: 5,
            },
            SubTask {
                title: "review".to_string(),
                description: format!("Review the implementation of: {}", task),
                agent_hint: "reviewer".to_string(),
                blockers: vec!["1".to_string(), "2".to_string()],
                estimated_cost_usd: 0.3,
                priority: 5,
            },
            SubTask {
                title: "security_audit".to_string(),
                description: format!("Security audit for: {}", task),
                agent_hint: "security_auditor".to_string(),
                blockers: vec!["1".to_string()],
                estimated_cost_usd: 0.4,
                priority: 5,
            },
            SubTask {
                title: "docs".to_string(),
                description: format!("Document: {}", task),
                agent_hint: "doc_writer".to_string(),
                blockers: vec!["3".to_string()],
                estimated_cost_usd: 0.2,
                priority: 3,
            },
        ]
    }

    fn decompose_review_task(&self, task: &str) -> Vec<SubTask> {
        vec![
            SubTask {
                title: "review_code".to_string(),
                description: format!("Review code for: {}", task),
                agent_hint: "reviewer".to_string(),
                blockers: vec![],
                estimated_cost_usd: 0.3,
                priority: 5,
            },
            SubTask {
                title: "security_audit".to_string(),
                description: format!("Security audit for: {}", task),
                agent_hint: "security_auditor".to_string(),
                blockers: vec![],
                estimated_cost_usd: 0.4,
                priority: 5,
            },
        ]
    }

    fn decompose_doc_task(&self, task: &str) -> Vec<SubTask> {
        vec![SubTask {
            title: "write_docs".to_string(),
            description: task.to_string(),
            agent_hint: "doc_writer".to_string(),
            blockers: vec![],
            estimated_cost_usd: 0.2,
            priority: 3,
        }]
    }

    fn decompose_test_task(&self, task: &str) -> Vec<SubTask> {
        vec![
            SubTask {
                title: "write_tests".to_string(),
                description: format!("Write tests for: {}", task),
                agent_hint: "test_engineer".to_string(),
                blockers: vec![],
                estimated_cost_usd: 0.5,
                priority: 5,
            },
            SubTask {
                title: "review_tests".to_string(),
                description: format!("Review tests for: {}", task),
                agent_hint: "reviewer".to_string(),
                blockers: vec!["0".to_string()],
                estimated_cost_usd: 0.2,
                priority: 4,
            },
        ]
    }

    /// Execute a dispatch plan by spawning agents and collecting results.
    ///
    /// Steps with no dependencies run in parallel (up to max_fanout).
    /// Steps with dependencies wait for their blockers to complete.
    /// Budget guard halts if total cost exceeds budget.
    pub async fn execute_plan(
        &self,
        kernel: &std::sync::Arc<dyn KernelHandle>,
        plan: &DispatchPlan,
    ) -> Result<Vec<String>, SchedulerError> {
        info!(task_id = %plan.task_id, steps = plan.steps.len(), "executing dispatch plan");

        let mut budget = BudgetGuard::new(self.config.budget_usd_max);
        let mut results: Vec<Option<String>> = vec![None; plan.steps.len()];
        let mut completed: HashSet<usize> = HashSet::new();

        while completed.len() < plan.steps.len() {
            // Find ready steps (all dependencies completed)
            let ready: Vec<usize> = plan
                .steps
                .iter()
                .enumerate()
                .filter(|(idx, step)| {
                    !completed.contains(idx)
                        && results[*idx].is_none()
                        && step.depends_on.iter().all(|d| completed.contains(d))
                })
                .map(|(idx, _)| idx)
                .collect();

            if ready.is_empty() && completed.len() < plan.steps.len() {
                // Deadlock detection
                let pending: Vec<usize> = (0..plan.steps.len())
                    .filter(|i| !completed.contains(i))
                    .collect();
                error!(pending = ?pending, "deadlock detected in dispatch plan");
                return Err(SchedulerError::Deadlock(pending));
            }

            // Enforce budget before dispatching
            for &idx in &ready {
                let step = &plan.steps[idx];
                if let Err(e) = budget.check(step.estimated_cost_usd) {
                    warn!(step = idx, error = %e, "budget exceeded; halting fanout");
                    return Err(e);
                }
            }

            // Dispatch ready steps with fanout limit
            let chunk_size = self.config.max_fanout.min(ready.len());
            let chunk: Vec<usize> = ready.into_iter().take(chunk_size).collect();

            let mut handles = Vec::with_capacity(chunk.len());
            for idx in chunk {
                let step = &plan.steps[idx];
                let kernel = kernel.clone();
                let role = step.role.clone();
                let prompt = step.prompt.clone();
                let retry_count = self.config.retry_count;
                let timeout_secs = self.config.timeout_secs;
                let estimated_cost = step.estimated_cost_usd;

                handles.push(tokio::spawn(async move {
                    let result =
                        Self::dispatch_step(&kernel, &role, &prompt, retry_count, timeout_secs)
                            .await;
                    (idx, result, estimated_cost)
                }));
            }

            // Collect results
            for handle in handles {
                match handle.await {
                    Ok((idx, Ok(result), cost)) => {
                        budget.spend(cost, 0, 0);
                        results[idx] = Some(result);
                        completed.insert(idx);
                    }
                    Ok((idx, Err(e), _)) => {
                        error!(step = idx, error = %e, "step failed after retries");
                        return Err(SchedulerError::DispatchFailed(idx, e.to_string()));
                    }
                    Err(e) => {
                        return Err(SchedulerError::DispatchFailed(
                            0,
                            format!("task join error: {e}"),
                        ));
                    }
                }
            }
        }

        Ok(results.into_iter().flatten().collect())
    }

    /// Dispatch a single step to an agent, with retries and timeout.
    async fn dispatch_step(
        kernel: &std::sync::Arc<dyn KernelHandle>,
        role: &str,
        prompt: &str,
        retry_count: u32,
        timeout_secs: u64,
    ) -> Result<String, SchedulerError> {
        let mut last_err = None;

        for attempt in 0..=retry_count {
            if attempt > 0 {
                let backoff = RETRY_BACKOFF_MS * (1_u64 << attempt.saturating_sub(1));
                debug!(role = %role, attempt, backoff_ms = backoff, "retrying step");
                sleep(Duration::from_millis(backoff)).await;
            }

            // Try to find existing agent by role
            let agents = kernel.find_agents(role);
            let agent_id = match agents
                .into_iter()
                .find(|a| a.role == role || a.name == role)
            {
                Some(agent) => agent.id,
                None => {
                    // Spawn new agent from manifest
                    let manifest = Self::manifest_for_role(role);
                    match kernel.spawn_agent(&manifest, None).await {
                        Ok((id, _name)) => id,
                        Err(e) => {
                            last_err = Some(format!("spawn failed: {e}"));
                            continue;
                        }
                    }
                }
            };

            // Send task to agent with timeout
            let send_fut = kernel.send_to_agent(&agent_id, prompt);
            match timeout(Duration::from_secs(timeout_secs), send_fut).await {
                Ok(Ok(result)) => {
                    debug!(role = %role, attempt, "step completed");
                    return Ok(result);
                }
                Ok(Err(e)) => {
                    warn!(role = %role, attempt, error = %e, "agent returned error");
                    last_err = Some(e);
                }
                Err(_) => {
                    warn!(role = %role, attempt, "step timed out");
                    last_err = Some("timeout".to_string());
                }
            }
        }

        Err(SchedulerError::DispatchFailed(
            0,
            last_err.unwrap_or_else(|| "all retries exhausted".to_string()),
        ))
    }

    /// Generate a minimal agent manifest TOML for a given role.
    fn manifest_for_role(role: &str) -> String {
        let system_prompt = match role {
            "coder" => "You are an expert software engineer. Write clean, tested, documented code.",
            "reviewer" => {
                "You are a senior code reviewer. Identify bugs, style issues, and security risks."
            }
            "security_auditor" => {
                "You are a security auditor. Find vulnerabilities and suggest fixes."
            }
            "test_engineer" => {
                "You are a test engineer. Write comprehensive unit and integration tests."
            }
            "doc_writer" => "You are a technical writer. Write clear, accurate documentation.",
            "architect" => "You are a software architect. Design robust, scalable systems.",
            "browser_hand" => {
                "You are a web automation specialist. Use browser tools to gather information."
            }
            _ => "You are a helpful AI assistant.",
        };
        format!(
            r#"name = "{}"
module = "builtin:chat"

[model]
provider = "default"
model = "default"
system_prompt = "{}"
"#,
            role, system_prompt
        )
    }

    /// Merge multiple branch results using a strategy.
    pub fn merge_results(
        results: &[String],
        strategy: MergeStrategy,
    ) -> Result<String, SchedulerError> {
        match strategy {
            MergeStrategy::Concat => Ok(results.join("\n---\n")),
            MergeStrategy::Diff3 => {
                // Simple diff3: take the longest result as authoritative
                let longest = results
                    .iter()
                    .max_by_key(|r| r.len())
                    .cloned()
                    .unwrap_or_default();
                Ok(longest)
            }
            MergeStrategy::Vote => {
                // Simple voting: return the most common result
                let mut counts: HashMap<String, usize> = HashMap::new();
                for r in results {
                    *counts.entry(r.clone()).or_insert(0) += 1;
                }
                counts
                    .into_iter()
                    .max_by_key(|(_, count)| *count)
                    .map(|(result, _)| result)
                    .ok_or_else(|| SchedulerError::MergeFailed("empty results".to_string()))
            }
        }
    }
}

/// A node in the orchestrator task graph.
#[derive(Debug, Clone)]
pub struct TaskNode {
    pub id: String,
    pub role: String,
    pub command: String,
    pub args: Vec<String>,
    pub depends_on: Vec<String>,
    pub status: TaskStatus,
    pub result: Option<String>,
}

/// Status of a task node in the orchestrator graph.
#[derive(Debug, Clone, PartialEq)]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

/// Orchestrator owns the task graph and routes sub-tasks to agents via A2A.
#[derive(Debug, Clone)]
pub struct Orchestrator {
    pub nodes: HashMap<String, TaskNode>,
    pub a2a_router: A2aRouter,
}

impl Orchestrator {
    /// Create a new orchestrator with the given A2A router.
    pub fn new(a2a_router: A2aRouter) -> Self {
        Self {
            nodes: HashMap::new(),
            a2a_router,
        }
    }

    /// Add a task node to the graph.
    pub fn add_node(&mut self, node: TaskNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    /// Resolve the execution order of the task graph using topological sort.
    pub fn resolve_order(&self) -> Result<Vec<String>, SchedulerError> {
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut adj: HashMap<String, Vec<String>> = HashMap::new();

        for (id, node) in &self.nodes {
            in_degree.entry(id.clone()).or_insert(0);
            for dep in &node.depends_on {
                adj.entry(dep.clone()).or_default().push(id.clone());
                *in_degree.entry(id.clone()).or_insert(0) += 1;
            }
        }

        let mut queue: Vec<String> = in_degree
            .iter()
            .filter(|(_, d)| **d == 0)
            .map(|(id, _)| id.clone())
            .collect();
        let mut order = Vec::new();

        while let Some(id) = queue.pop() {
            order.push(id.clone());
            for next in adj.get(&id).unwrap_or(&Vec::new()) {
                let deg = in_degree.get_mut(next).unwrap();
                *deg -= 1;
                if *deg == 0 {
                    queue.push(next.clone());
                }
            }
        }

        if order.len() != self.nodes.len() {
            return Err(SchedulerError::Deadlock(vec![]));
        }

        Ok(order)
    }

    /// Serialize the current task graph state to a checkpoint.
    pub fn checkpoint(&self) -> OrchestratorCheckpoint {
        let mut nodes: Vec<_> = self
            .nodes
            .values()
            .map(|n| TaskNodeRecord {
                id: n.id.clone(),
                role: n.role.clone(),
                command: n.command.clone(),
                args: n.args.clone(),
                depends_on: n.depends_on.clone(),
                status: format!("{:?}", n.status),
                result: n.result.clone(),
            })
            .collect();
        nodes.sort_by(|a, b| a.id.cmp(&b.id));
        OrchestratorCheckpoint { nodes }
    }

    /// Restore the task graph from a checkpoint, skipping already-completed nodes.
    pub fn resume_from_checkpoint(&mut self, checkpoint: &OrchestratorCheckpoint) {
        for record in &checkpoint.nodes {
            if let Some(existing) = self.nodes.get_mut(&record.id) {
                existing.status = match record.status.as_str() {
                    "Completed" => TaskStatus::Completed,
                    "Failed" => TaskStatus::Failed,
                    "Running" => TaskStatus::Running,
                    _ => TaskStatus::Pending,
                };
                existing.result = record.result.clone();
            }
        }
    }

    /// Execute the task graph, dispatching each ready node via A2A.
    pub async fn execute_graph(
        &mut self,
        scheduler: &Scheduler,
        kernel: &std::sync::Arc<dyn KernelHandle>,
    ) -> Result<HashMap<String, String>, SchedulerError> {
        let order = self.resolve_order()?;
        let mut results = HashMap::new();

        for id in order {
            let node = self
                .nodes
                .get_mut(&id)
                .ok_or_else(|| SchedulerError::AgentNotFound(format!("node {} missing", id)))?;

            // Skip already-completed nodes (durable resume)
            if node.status == TaskStatus::Completed {
                if let Some(ref result) = node.result {
                    results.insert(id.clone(), result.clone());
                }
                continue;
            }

            node.status = TaskStatus::Running;

            let plan = scheduler.build_plan(&node.command);
            match scheduler.execute_plan(kernel, &plan).await {
                Ok(result) => {
                    node.status = TaskStatus::Completed;
                    let joined = result.join("\n");
                    node.result = Some(joined.clone());
                    results.insert(id.clone(), joined);
                }
                Err(e) => {
                    node.status = TaskStatus::Failed;
                    return Err(e);
                }
            }
        }

        Ok(results)
    }

    /// Write a lesson to the knowledge graph after task completion.
    pub fn record_lesson(
        &self,
        task_id: &str,
        summary: &str,
        outcome: &str,
        source_agent: Option<&str>,
        approval_reason: Option<&str>,
        knowledge_store: &t3rnel_memory::knowledge::KnowledgeStore,
    ) -> Result<String, t3rnel_types::error::T3rnelError> {
        knowledge_store.write_lesson(t3rnel_memory::knowledge::LessonInput {
            task_id: task_id.to_string(),
            summary: summary.to_string(),
            outcome: outcome.to_string(),
            source_agent: source_agent.map(|s| s.to_string()),
            approval_reason: approval_reason.map(|s| s.to_string()),
            metadata: std::collections::HashMap::new(),
        })
    }
}

/// Serializable checkpoint of an orchestrator task graph.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OrchestratorCheckpoint {
    pub nodes: Vec<TaskNodeRecord>,
}

/// Serializable record of a task node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TaskNodeRecord {
    pub id: String,
    pub role: String,
    pub command: String,
    pub args: Vec<String>,
    pub depends_on: Vec<String>,
    pub status: String,
    pub result: Option<String>,
}

/// A2A router for dispatching tasks to remote agents.
#[derive(Debug, Clone, Default)]
pub struct A2aRouter {
    pub agents: Vec<crate::a2a::AgentCard>,
}

impl A2aRouter {
    /// Create a new A2A router.
    pub fn new() -> Self {
        Self { agents: Vec::new() }
    }

    /// Discover agents from a remote daemon's well-known endpoint.
    pub async fn discover_agents(&mut self, url: &str) -> Result<(), String> {
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/.well-known/agent.json", url))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let card: crate::a2a::AgentCard = resp.json().await.map_err(|e| e.to_string())?;
        self.agents.push(card);
        Ok(())
    }

    /// Route a task to the agent matching the requested role.
    pub fn route_to_role(&self, role: &str) -> Option<&crate::a2a::AgentCard> {
        self.agents.iter().find(|a| {
            a.name.to_lowercase().contains(&role.to_lowercase())
                || a.description.to_lowercase().contains(&role.to_lowercase())
        })
    }
}

/// Strategy for merging divergent branch results.
#[derive(Debug, Clone, Copy)]
pub enum MergeStrategy {
    /// Concatenate all results with separators.
    Concat,
    /// Use diff3-like merge (take longest/most complete).
    Diff3,
    /// Return the most common result (majority vote).
    Vote,
}

/// Backpressure policy for limiting concurrent fanout.
#[derive(Debug, Clone, Copy)]
pub struct FanoutPolicy {
    /// Maximum concurrent dispatches (semaphore limit).
    pub max_concurrent: usize,
    /// Delay between dispatch waves in milliseconds.
    pub wave_delay_ms: u64,
    /// Whether to enable conflict detection.
    pub conflict_detection: bool,
}

impl Default for FanoutPolicy {
    fn default() -> Self {
        Self {
            max_concurrent: MAX_FANOUT,
            wave_delay_ms: 0,
            conflict_detection: true,
        }
    }
}

/// Tracks file-path assignments across parallel coder tasks to detect conflicts.
#[derive(Debug, Clone, Default)]
pub struct FileConflictTracker {
    /// Maps file paths to the step index that claimed them.
    claims: HashMap<String, usize>,
    /// Conflicts detected during tracking.
    pub conflicts: Vec<FileConflict>,
}

/// A detected file conflict between two parallel coding steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileConflict {
    pub path: String,
    pub step_a: usize,
    pub step_b: usize,
}

impl FileConflictTracker {
    /// Create a new conflict tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Claim a set of file paths for a given step index.
    /// Returns any conflicts that were detected.
    pub fn claim(&mut self, step_index: usize, paths: &[String]) -> Vec<FileConflict> {
        let mut new_conflicts = Vec::new();
        for path in paths {
            if let Some(existing) = self.claims.get(path) {
                if *existing != step_index {
                    let conflict = FileConflict {
                        path: path.clone(),
                        step_a: *existing,
                        step_b: step_index,
                    };
                    self.conflicts.push(conflict.clone());
                    new_conflicts.push(conflict);
                }
            } else {
                self.claims.insert(path.clone(), step_index);
            }
        }
        new_conflicts
    }

    /// Check if any conflicts have been detected.
    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }

    /// Resolve conflicts using the given strategy and return the authoritative step for each path.
    pub fn resolve(&self, strategy: ConflictResolutionStrategy) -> HashMap<String, usize> {
        let mut resolved: HashMap<String, usize> = HashMap::new();
        for (path, step) in &self.claims {
            if let Some(existing_conflict) = self.conflicts.iter().find(|c| &c.path == path) {
                match strategy {
                    ConflictResolutionStrategy::LastWriteWins => {
                        resolved.insert(path.clone(), existing_conflict.step_b);
                    }
                    ConflictResolutionStrategy::FirstWriterWins => {
                        resolved.insert(path.clone(), existing_conflict.step_a);
                    }
                    ConflictResolutionStrategy::RequireReview => {
                        // Leave unresolved — reviewer must arbitrate
                    }
                }
            } else {
                resolved.insert(path.clone(), *step);
            }
        }
        resolved
    }
}

/// Strategy for resolving file conflicts between parallel coders.
#[derive(Debug, Clone, Copy)]
pub enum ConflictResolutionStrategy {
    /// The later step overwrites the earlier one.
    LastWriteWins,
    /// The first step to claim the file keeps it.
    FirstWriterWins,
    /// Leave unresolved and require human/arbitrator review.
    RequireReview,
}

/// Errors that can occur during scheduling.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("agent not found for role: {0}")]
    AgentNotFound(String),
    #[error("fanout limit exceeded: {0}")]
    FanoutLimitExceeded(usize),
    #[error("dispatch timeout")]
    Timeout,
    #[error("budget exceeded: max ${0:.2} USD")]
    BudgetExceeded(f64),
    #[error("dispatch failed at step {0}: {1}")]
    DispatchFailed(usize, String),
    #[error("deadlock detected in steps {0:?}")]
    Deadlock(Vec<usize>),
    #[error("merge failed: {0}")]
    MergeFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orchestrator_resolve_order_linear() {
        let router = A2aRouter::new();
        let mut orchestrator = Orchestrator::new(router);

        orchestrator.add_node(TaskNode {
            id: "step-a".to_string(),
            role: "coder".to_string(),
            command: "write tests".to_string(),
            args: vec![],
            depends_on: vec![],
            status: TaskStatus::Pending,
            result: None,
        });
        orchestrator.add_node(TaskNode {
            id: "step-b".to_string(),
            role: "tester".to_string(),
            command: "run tests".to_string(),
            args: vec![],
            depends_on: vec!["step-a".to_string()],
            status: TaskStatus::Pending,
            result: None,
        });
        orchestrator.add_node(TaskNode {
            id: "step-c".to_string(),
            role: "reviewer".to_string(),
            command: "review".to_string(),
            args: vec![],
            depends_on: vec!["step-b".to_string()],
            status: TaskStatus::Pending,
            result: None,
        });

        let order = orchestrator.resolve_order().unwrap();
        assert_eq!(order, vec!["step-a", "step-b", "step-c"]);
    }

    #[test]
    fn orchestrator_resolve_order_parallel() {
        let router = A2aRouter::new();
        let mut orchestrator = Orchestrator::new(router);

        orchestrator.add_node(TaskNode {
            id: "step-a".to_string(),
            role: "coder".to_string(),
            command: "write code".to_string(),
            args: vec![],
            depends_on: vec![],
            status: TaskStatus::Pending,
            result: None,
        });
        orchestrator.add_node(TaskNode {
            id: "step-b".to_string(),
            role: "coder".to_string(),
            command: "write docs".to_string(),
            args: vec![],
            depends_on: vec![],
            status: TaskStatus::Pending,
            result: None,
        });
        orchestrator.add_node(TaskNode {
            id: "step-c".to_string(),
            role: "tester".to_string(),
            command: "run tests".to_string(),
            args: vec![],
            depends_on: vec!["step-a".to_string(), "step-b".to_string()],
            status: TaskStatus::Pending,
            result: None,
        });

        let order = orchestrator.resolve_order().unwrap();
        assert_eq!(order[2], "step-c");
        let first_two: std::collections::HashSet<_> = order[..2].iter().cloned().collect();
        assert_eq!(
            first_two,
            ["step-a".to_string(), "step-b".to_string()]
                .iter()
                .cloned()
                .collect()
        );
    }

    #[test]
    fn orchestrator_detects_deadlock() {
        let router = A2aRouter::new();
        let mut orchestrator = Orchestrator::new(router);

        orchestrator.add_node(TaskNode {
            id: "step-a".to_string(),
            role: "coder".to_string(),
            command: "write code".to_string(),
            args: vec![],
            depends_on: vec!["step-b".to_string()],
            status: TaskStatus::Pending,
            result: None,
        });
        orchestrator.add_node(TaskNode {
            id: "step-b".to_string(),
            role: "tester".to_string(),
            command: "run tests".to_string(),
            args: vec![],
            depends_on: vec!["step-a".to_string()],
            status: TaskStatus::Pending,
            result: None,
        });

        assert!(matches!(
            orchestrator.resolve_order(),
            Err(SchedulerError::Deadlock(_))
        ));
    }

    #[test]
    fn a2a_router_route_to_role() {
        let router = A2aRouter::new();
        let card = crate::a2a::AgentCard {
            name: "coder-agent".to_string(),
            version: "0.1.0".to_string(),
            description: "Writes code".to_string(),
            url: "http://localhost:8080".to_string(),
            capabilities: crate::a2a::AgentCapabilities {
                streaming: false,
                push_notifications: false,
                state_transition_history: true,
            },
            skills: vec![crate::a2a::AgentSkill {
                id: "rust".to_string(),
                name: "Rust".to_string(),
                description: "Write Rust code".to_string(),
                tags: vec!["text".to_string()],
                examples: vec![],
            }],
            default_input_modes: vec!["text".to_string()],
            default_output_modes: vec!["text".to_string()],
        };

        let mut router = router;
        router.agents.push(card);

        let matched = router.route_to_role("coder");
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().name, "coder-agent");

        let not_matched = router.route_to_role("reviewer");
        assert!(not_matched.is_none());
    }

    #[test]
    fn fanout_policy_default_limits_to_max_fanout() {
        let policy = FanoutPolicy::default();
        assert_eq!(policy.max_concurrent, MAX_FANOUT);
        assert_eq!(policy.wave_delay_ms, 0);
        assert!(policy.conflict_detection);
    }

    #[test]
    fn conflict_tracker_detects_overlapping_claims() {
        let mut tracker = FileConflictTracker::new();
        tracker.claim(0, &["src/lib.rs".to_string(), "src/main.rs".to_string()]);
        let conflicts = tracker.claim(1, &["src/lib.rs".to_string()]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].path, "src/lib.rs");
        assert_eq!(conflicts[0].step_a, 0);
        assert_eq!(conflicts[0].step_b, 1);
        assert!(tracker.has_conflicts());
    }

    #[test]
    fn conflict_tracker_ignores_duplicate_same_step_claims() {
        let mut tracker = FileConflictTracker::new();
        tracker.claim(0, &["src/lib.rs".to_string()]);
        let conflicts = tracker.claim(0, &["src/lib.rs".to_string()]);
        assert!(conflicts.is_empty());
        assert!(!tracker.has_conflicts());
    }

    #[test]
    fn conflict_resolution_last_write_wins() {
        let mut tracker = FileConflictTracker::new();
        tracker.claim(0, &["src/lib.rs".to_string()]);
        tracker.claim(1, &["src/lib.rs".to_string()]);
        let resolved = tracker.resolve(ConflictResolutionStrategy::LastWriteWins);
        assert_eq!(resolved.get("src/lib.rs").copied(), Some(1));
    }

    #[test]
    fn conflict_resolution_first_writer_wins() {
        let mut tracker = FileConflictTracker::new();
        tracker.claim(0, &["src/lib.rs".to_string()]);
        tracker.claim(1, &["src/lib.rs".to_string()]);
        let resolved = tracker.resolve(ConflictResolutionStrategy::FirstWriterWins);
        assert_eq!(resolved.get("src/lib.rs").copied(), Some(0));
    }

    #[test]
    fn conflict_resolution_require_review_leaves_conflict_unresolved() {
        let mut tracker = FileConflictTracker::new();
        tracker.claim(0, &["src/lib.rs".to_string()]);
        tracker.claim(1, &["src/lib.rs".to_string()]);
        let resolved = tracker.resolve(ConflictResolutionStrategy::RequireReview);
        assert!(resolved.is_empty());
    }

    #[test]
    fn budget_guard_blocks_over_budget() {
        let mut guard = BudgetGuard::new(10.0);
        assert!(guard.check(5.0).is_ok());
        guard.spend(6.0, 1000, 500);
        assert!(guard.check(5.0).is_err());
        assert!(guard.check(3.0).is_ok());
    }

    #[test]
    fn orchestrator_checkpoint_roundtrip() {
        let router = A2aRouter::new();
        let mut orchestrator = Orchestrator::new(router);
        orchestrator.add_node(TaskNode {
            id: "step-a".to_string(),
            role: "coder".to_string(),
            command: "write code".to_string(),
            args: vec![],
            depends_on: vec![],
            status: TaskStatus::Completed,
            result: Some("done".to_string()),
        });
        orchestrator.add_node(TaskNode {
            id: "step-b".to_string(),
            role: "tester".to_string(),
            command: "run tests".to_string(),
            args: vec![],
            depends_on: vec!["step-a".to_string()],
            status: TaskStatus::Pending,
            result: None,
        });

        let checkpoint = orchestrator.checkpoint();
        assert_eq!(checkpoint.nodes.len(), 2);
        assert_eq!(checkpoint.nodes[0].status, "Completed");

        let router2 = A2aRouter::new();
        let mut resumed = Orchestrator::new(router2);
        resumed.add_node(TaskNode {
            id: "step-a".to_string(),
            role: "coder".to_string(),
            command: "write code".to_string(),
            args: vec![],
            depends_on: vec![],
            status: TaskStatus::Pending,
            result: None,
        });
        resumed.add_node(TaskNode {
            id: "step-b".to_string(),
            role: "tester".to_string(),
            command: "run tests".to_string(),
            args: vec![],
            depends_on: vec!["step-a".to_string()],
            status: TaskStatus::Pending,
            result: None,
        });
        resumed.resume_from_checkpoint(&checkpoint);
        assert_eq!(
            resumed.nodes.get("step-a").unwrap().status,
            TaskStatus::Completed
        );
        assert_eq!(
            resumed.nodes.get("step-b").unwrap().status,
            TaskStatus::Pending
        );
    }
}
