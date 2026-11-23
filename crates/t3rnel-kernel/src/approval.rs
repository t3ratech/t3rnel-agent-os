//! Execution approval manager — gates dangerous operations behind human approval.

use chrono::Utc;
use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use t3rnel_types::approval::{
    ApprovalDecision, ApprovalPolicy, ApprovalRequest, ApprovalResponse, RiskLevel,
};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Max pending requests per agent.
const MAX_PENDING_PER_AGENT: usize = 5;
/// Max recent approval records to retain for history and UI visibility.
const MAX_RECENT_APPROVALS: usize = 100;

/// Manages approval requests with oneshot channels for blocking resolution.
pub struct ApprovalManager {
    pending: DashMap<Uuid, PendingRequest>,
    recent: std::sync::Mutex<VecDeque<ApprovalRecord>>,
    policy: std::sync::RwLock<ApprovalPolicy>,
    /// Optional memory substrate for SQLite persistence of approvals.
    memory: std::sync::RwLock<Option<Arc<t3rnel_memory::MemorySubstrate>>>,
}

struct PendingRequest {
    request: ApprovalRequest,
    sender: tokio::sync::oneshot::Sender<ApprovalDecision>,
}

#[derive(Debug, Clone)]
pub struct ApprovalRecord {
    pub request: ApprovalRequest,
    pub decision: ApprovalDecision,
    pub decided_at: chrono::DateTime<Utc>,
    pub decided_by: Option<String>,
}

/// Approval behavior selected from a tool's risk classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalGate {
    Auto,
    Notify,
    Block,
    BlockWithBiometric,
}

/// Path to the WhatsApp notifier, if it can be found.
///
/// `T3RNEL_REPO_DIR` wins; otherwise the executable's ancestors are searched,
/// which covers a daemon started from a build directory. Returning `None` is
/// correct rather than a fallback guess — a wrong path spawns a process that
/// fails invisibly, which is worse than not notifying.
fn notifier_script() -> Option<std::path::PathBuf> {
    if let Ok(repo) = std::env::var("T3RNEL_REPO_DIR") {
        let candidate = std::path::Path::new(&repo).join("scripts/whatsapp_notify.py");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    let exe = std::env::current_exe().ok()?;
    exe.ancestors()
        .map(|dir| dir.join("scripts/whatsapp_notify.py"))
        .find(|candidate| candidate.exists())
}

impl ApprovalManager {
    pub fn new(policy: ApprovalPolicy) -> Self {
        Self {
            pending: DashMap::new(),
            recent: std::sync::Mutex::new(VecDeque::new()),
            policy: std::sync::RwLock::new(policy),
            memory: std::sync::RwLock::new(None),
        }
    }

    /// Attach a memory substrate for persistent approval storage.
    pub fn set_memory(&self, memory: Arc<t3rnel_memory::MemorySubstrate>) {
        *self.memory.write().unwrap_or_else(|e| e.into_inner()) = Some(memory);
    }

    /// Load pending approvals from SQLite and re-inject them as timed-out requests.
    /// Called once at daemon boot after `set_memory`.
    pub fn load_pending_from_db(&self) {
        let memory = self
            .memory
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(memory) = memory else { return };
        match memory.load_pending_approvals() {
            Ok(requests) => {
                for req in requests {
                    info!(request_id = %req.id, agent_id = %req.agent_id, "Loaded pending approval from DB");
                    // Re-insert as a request that will immediately time out since
                    // the oneshot receiver is gone after restart. The agent will
                    // need to retry, and the approval will surface again.
                    let (tx, _rx) = tokio::sync::oneshot::channel();
                    self.pending.insert(
                        req.id,
                        PendingRequest {
                            request: req,
                            sender: tx,
                        },
                    );
                }
            }
            Err(e) => {
                warn!("Failed to load pending approvals from DB: {e}");
            }
        }
    }

    /// Check if a tool requires approval based on current policy.
    pub fn requires_approval(&self, tool_name: &str) -> bool {
        matches!(
            self.gate_for_tool(tool_name),
            ApprovalGate::Block | ApprovalGate::BlockWithBiometric
        )
    }

    /// Determine the approval gate for a tool invocation.
    pub fn gate_for_tool(&self, tool_name: &str) -> ApprovalGate {
        let policy = self.policy.read().unwrap_or_else(|e| e.into_inner());
        let risk_gate = Self::gate_for_risk(Self::classify_risk(tool_name));
        if policy.require_approval.iter().any(|t| t == tool_name) {
            match risk_gate {
                ApprovalGate::Auto | ApprovalGate::Notify => ApprovalGate::Block,
                gate => gate,
            }
        } else {
            risk_gate
        }
    }

    /// Map a risk tag to its default approval behavior.
    pub fn gate_for_risk(risk_level: RiskLevel) -> ApprovalGate {
        match risk_level {
            RiskLevel::Low => ApprovalGate::Auto,
            RiskLevel::Medium => ApprovalGate::Notify,
            RiskLevel::High => ApprovalGate::Block,
            RiskLevel::Critical => ApprovalGate::BlockWithBiometric,
        }
    }

    /// Submit an approval request. Returns a future that resolves when approved/denied/timed out.
    pub async fn request_approval(&self, req: ApprovalRequest) -> ApprovalDecision {
        // Check per-agent pending limit
        let agent_pending = self
            .pending
            .iter()
            .filter(|r| r.value().request.agent_id == req.agent_id)
            .count();
        if agent_pending >= MAX_PENDING_PER_AGENT {
            warn!(agent_id = %req.agent_id, "Approval request rejected: too many pending");
            return ApprovalDecision::Denied;
        }

        let timeout = std::time::Duration::from_secs(req.timeout_secs);
        let id = req.id;
        let req_for_timeout = req.clone();

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.insert(
            id,
            PendingRequest {
                request: req.clone(),
                sender: tx,
            },
        );

        if let Some(memory) = self
            .memory
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            if let Err(e) = memory.save_approval_request(&req) {
                warn!(request_id = %id, "Failed to persist approval request: {e}");
            }
        }

        info!(request_id = %id, "Approval request submitted, waiting for resolution");

        // Notify only for approvals that actually need a person.
        //
        // Auto-granted requests never reach here — they short-circuit in the
        // kernel and are recorded as decided — so anything at this point is
        // genuinely waiting on a human. That is the whole test for whether an
        // interruption is warranted: a phone buzzing for a permission the
        // system was about to grant itself teaches the operator to ignore the
        // next one that actually blocks work.
        //
        // Both channels are fire-and-forget. A notification that cannot be
        // delivered must never block the kernel or fail the request; the
        // approval is already pending and visible in the dashboard.
        let agent_id_clone = req.agent_id.clone();
        let tool_name_clone = req.tool_name.clone();
        let action_clone = req.action_summary.clone();
        tokio::task::spawn_blocking(move || {
            let summary =
                format!("{agent_id_clone} wants to execute {tool_name_clone}: {action_clone}");

            let _ = std::process::Command::new("notify-send")
                .arg("T3rnel Approval Required")
                .arg(&summary)
                .arg("--urgency=normal")
                .arg("--icon=dialog-question")
                .spawn();

            // The operator is rarely at the machine when autonomous work
            // stalls, which is exactly when an approval blocks earning.
            // Located from the repository root rather than guessed relative to
            // the daemon home: the two are unrelated paths, and deriving one
            // from the other silently pointed at a script that does not exist.
            let Some(script) = notifier_script() else {
                return;
            };
            let _ = std::process::Command::new("python3")
                .arg(script)
                .arg("approval")
                .arg("--title")
                .arg(format!("{agent_id_clone} needs {tool_name_clone}"))
                .arg("--body")
                .arg(&summary)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        });

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(decision)) => {
                debug!(request_id = %id, ?decision, "Approval resolved");
                decision
            }
            _ => {
                let request = self
                    .pending
                    .remove(&id)
                    .map(|(_, pending)| pending.request)
                    .unwrap_or(req_for_timeout);
                self.push_recent(
                    request.clone(),
                    ApprovalDecision::TimedOut,
                    None,
                    Utc::now(),
                );
                if let Some(memory) = self
                    .memory
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
                {
                    if let Err(e) = memory.resolve_approval(id, "timed_out", None) {
                        warn!(request_id = %id, "Failed to persist approval timeout: {e}");
                    }
                }
                warn!(request_id = %id, "Approval request timed out");
                ApprovalDecision::TimedOut
            }
        }
    }

    /// Resolve a pending request (called by API/UI).
    pub fn resolve(
        &self,
        request_id: Uuid,
        decision: ApprovalDecision,
        decided_by: Option<String>,
    ) -> Result<ApprovalResponse, String> {
        match self.pending.remove(&request_id) {
            Some((_, pending)) => {
                let response = ApprovalResponse {
                    request_id,
                    decision,
                    decided_at: Utc::now(),
                    decided_by: decided_by.clone(),
                    agent_id: pending.request.agent_id.clone(),
                    tool_name: pending.request.tool_name.clone(),
                    description: pending.request.description.clone(),
                    action_summary: pending.request.action_summary.clone(),
                };
                self.push_recent(
                    pending.request.clone(),
                    decision,
                    response.decided_by.clone(),
                    response.decided_at,
                );
                // Send decision to waiting agent (ignore error if receiver dropped)
                let _ = pending.sender.send(decision);
                if let Some(memory) = self
                    .memory
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
                {
                    let decision_str = format!("{:?}", decision).to_lowercase();
                    if let Err(e) =
                        memory.resolve_approval(request_id, &decision_str, decided_by.as_deref())
                    {
                        warn!(request_id = %request_id, "Failed to persist approval resolution: {e}");
                    }
                }
                info!(request_id = %request_id, ?decision, "Approval request resolved");
                Ok(response)
            }
            None => {
                // Check if it was recently resolved (concurrent race)
                let recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
                if recent.iter().any(|r| r.request.id == request_id) {
                    Err(format!("Approval request {request_id} was already decided"))
                } else {
                    Err(format!("No pending approval request with id {request_id}"))
                }
            }
        }
    }

    pub fn record_decision(
        &self,
        request: ApprovalRequest,
        decision: ApprovalDecision,
        decided_by: Option<String>,
    ) {
        let id = request.id;
        self.push_recent(request.clone(), decision, decided_by.clone(), Utc::now());
        if let Some(memory) = self
            .memory
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            if let Err(e) = memory.save_approval_request(&request) {
                warn!(request_id = %id, "Failed to persist approval request: {e}");
                return;
            }
            let decision_str = format!("{:?}", decision).to_lowercase();
            if let Err(e) = memory.resolve_approval(id, &decision_str, decided_by.as_deref()) {
                warn!(request_id = %id, "Failed to persist approval resolution: {e}");
            }
        }
    }

    /// List all pending requests (for API/dashboard display).
    pub fn list_pending(&self) -> Vec<ApprovalRequest> {
        self.pending
            .iter()
            .map(|r| r.value().request.clone())
            .collect()
    }

    /// Submit a pending approval request without blocking a caller on a decision.
    ///
    /// This is used by external coordination surfaces, such as A2A review
    /// handoffs, where the approval should appear in the inbox immediately.
    pub fn submit_pending(&self, req: ApprovalRequest) -> Result<(), String> {
        let agent_pending = self
            .pending
            .iter()
            .filter(|r| r.value().request.agent_id == req.agent_id)
            .count();
        if agent_pending >= MAX_PENDING_PER_AGENT {
            return Err(format!(
                "approval request rejected for {}: too many pending",
                req.agent_id
            ));
        }

        let id = req.id;
        let (tx, _rx) = tokio::sync::oneshot::channel();
        self.pending.insert(
            id,
            PendingRequest {
                request: req.clone(),
                sender: tx,
            },
        );

        if let Some(memory) = self
            .memory
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            if let Err(e) = memory.save_approval_request(&req) {
                warn!(request_id = %id, "Failed to persist approval request: {e}");
            }
        }

        info!(request_id = %id, "Approval request submitted for external resolution");
        Ok(())
    }

    /// List recent non-pending approvals, newest first.
    pub fn list_recent(&self, limit: usize) -> Vec<ApprovalRecord> {
        let recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        recent.iter().take(limit).cloned().collect()
    }

    /// Number of pending requests.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Update the approval policy (for hot-reload).
    pub fn update_policy(&self, policy: ApprovalPolicy) {
        *self.policy.write().unwrap_or_else(|e| e.into_inner()) = policy;
    }

    /// Get a copy of the current policy.
    pub fn policy(&self) -> ApprovalPolicy {
        self.policy
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Classify the risk level of a tool invocation.
    pub fn classify_risk(tool_name: &str) -> RiskLevel {
        match tool_name {
            "shell_exec" => RiskLevel::Critical,
            "file_write" | "file_delete" | "apply_patch" | "browser_click" | "browser_type"
            | "browser_run_js" | "channel_send" | "ide_delegate" => RiskLevel::High,
            "web_fetch" | "web_search" | "browser_navigate" | "browser_read_page"
            | "browser_screenshot" => RiskLevel::Medium,
            _ => RiskLevel::Low,
        }
    }

    fn push_recent(
        &self,
        request: ApprovalRequest,
        decision: ApprovalDecision,
        decided_by: Option<String>,
        decided_at: chrono::DateTime<Utc>,
    ) {
        let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        recent.push_front(ApprovalRecord {
            request,
            decision,
            decided_at,
            decided_by,
        });
        while recent.len() > MAX_RECENT_APPROVALS {
            recent.pop_back();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use t3rnel_types::approval::ApprovalPolicy;
    use t3rnel_types::config::MemoryConfig;

    fn default_manager() -> ApprovalManager {
        ApprovalManager::new(ApprovalPolicy::default())
    }

    fn make_request(agent_id: &str, tool_name: &str, timeout_secs: u64) -> ApprovalRequest {
        ApprovalRequest {
            id: Uuid::new_v4(),
            agent_id: agent_id.to_string(),
            tool_name: tool_name.to_string(),
            description: "test operation".to_string(),
            action_summary: "test action".to_string(),
            risk_level: RiskLevel::High,
            requested_at: Utc::now(),
            timeout_secs,
        }
    }

    // -----------------------------------------------------------------------
    // requires_approval
    // -----------------------------------------------------------------------

    #[test]
    fn test_requires_approval_default() {
        let mgr = default_manager();
        assert!(mgr.requires_approval("shell_exec"));
        assert!(mgr.requires_approval("file_write"));
        assert!(!mgr.requires_approval("web_fetch"));
        assert!(!mgr.requires_approval("file_read"));
    }

    #[test]
    fn test_requires_approval_custom_policy() {
        let policy = ApprovalPolicy {
            require_approval: vec!["file_write".to_string(), "file_delete".to_string()],
            timeout_secs: 30,
            auto_approve_autonomous: false,
            auto_approve: false,
            ..ApprovalPolicy::default()
        };
        let mgr = ApprovalManager::new(policy);
        assert!(mgr.requires_approval("file_write"));
        assert!(mgr.requires_approval("file_delete"));
        assert!(mgr.requires_approval("shell_exec"));
        assert!(!mgr.requires_approval("file_read"));
    }

    // -----------------------------------------------------------------------
    // classify_risk
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_risk() {
        assert_eq!(
            ApprovalManager::classify_risk("shell_exec"),
            RiskLevel::Critical
        );
        assert_eq!(
            ApprovalManager::classify_risk("file_write"),
            RiskLevel::High
        );
        assert_eq!(
            ApprovalManager::classify_risk("file_delete"),
            RiskLevel::High
        );
        assert_eq!(
            ApprovalManager::classify_risk("web_fetch"),
            RiskLevel::Medium
        );
        assert_eq!(
            ApprovalManager::classify_risk("browser_navigate"),
            RiskLevel::Medium
        );
        assert_eq!(
            ApprovalManager::classify_risk("browser_click"),
            RiskLevel::High
        );
        assert_eq!(
            ApprovalManager::classify_risk("browser_type"),
            RiskLevel::High
        );
        assert_eq!(
            ApprovalManager::classify_risk("channel_send"),
            RiskLevel::High
        );
        assert_eq!(ApprovalManager::classify_risk("file_read"), RiskLevel::Low);
        assert_eq!(
            ApprovalManager::classify_risk("unknown_tool"),
            RiskLevel::Low
        );
        assert_eq!(
            ApprovalManager::classify_risk("ide_delegate"),
            RiskLevel::High
        );
        assert_eq!(ApprovalManager::classify_risk("ide_poll"), RiskLevel::Low);
    }

    #[test]
    fn test_gate_for_risk_contract() {
        assert_eq!(
            ApprovalManager::gate_for_risk(RiskLevel::Low),
            ApprovalGate::Auto
        );
        assert_eq!(
            ApprovalManager::gate_for_risk(RiskLevel::Medium),
            ApprovalGate::Notify
        );
        assert_eq!(
            ApprovalManager::gate_for_risk(RiskLevel::High),
            ApprovalGate::Block
        );
        assert_eq!(
            ApprovalManager::gate_for_risk(RiskLevel::Critical),
            ApprovalGate::BlockWithBiometric
        );
    }

    #[test]
    fn test_policy_can_escalate_low_or_medium_tools_to_blocking() {
        let policy = ApprovalPolicy {
            require_approval: vec!["web_fetch".to_string(), "file_read".to_string()],
            timeout_secs: 30,
            auto_approve_autonomous: false,
            auto_approve: false,
            ..ApprovalPolicy::default()
        };
        let mgr = ApprovalManager::new(policy);
        assert_eq!(mgr.gate_for_tool("web_fetch"), ApprovalGate::Block);
        assert_eq!(mgr.gate_for_tool("file_read"), ApprovalGate::Block);
    }

    // -----------------------------------------------------------------------
    // resolve nonexistent
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_nonexistent() {
        let mgr = default_manager();
        let result = mgr.resolve(Uuid::new_v4(), ApprovalDecision::Approved, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No pending approval request"));
    }

    // -----------------------------------------------------------------------
    // list_pending empty
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_pending_empty() {
        let mgr = default_manager();
        assert!(mgr.list_pending().is_empty());
        assert!(mgr.list_recent(10).is_empty());
    }

    // -----------------------------------------------------------------------
    // update_policy
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_policy() {
        let mgr = default_manager();
        assert!(mgr.requires_approval("shell_exec"));
        assert!(mgr.requires_approval("file_write"));
        assert!(!mgr.requires_approval("web_fetch"));

        let new_policy = ApprovalPolicy {
            require_approval: vec!["file_write".to_string()],
            timeout_secs: 120,
            auto_approve_autonomous: true,
            auto_approve: false,
            ..ApprovalPolicy::default()
        };
        mgr.update_policy(new_policy);

        assert!(mgr.requires_approval("shell_exec"));
        assert!(mgr.requires_approval("file_write"));

        let policy = mgr.policy();
        assert_eq!(policy.timeout_secs, 120);
        assert!(policy.auto_approve_autonomous);
    }

    // -----------------------------------------------------------------------
    // pending_count
    // -----------------------------------------------------------------------

    #[test]
    fn test_pending_count() {
        let mgr = default_manager();
        assert_eq!(mgr.pending_count(), 0);
    }

    // -----------------------------------------------------------------------
    // request_approval — timeout
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_request_approval_timeout() {
        let mgr = Arc::new(default_manager());
        let req = make_request("agent-1", "shell_exec", 10);
        let decision = mgr.request_approval(req).await;
        assert_eq!(decision, ApprovalDecision::TimedOut);
        // After timeout, pending map should be cleaned up
        assert_eq!(mgr.pending_count(), 0);
        let recent = mgr.list_recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].decision, ApprovalDecision::TimedOut);
        assert_eq!(recent[0].request.tool_name, "shell_exec");
    }

    // -----------------------------------------------------------------------
    // request_approval — approve
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_request_approval_approve() {
        let mgr = Arc::new(default_manager());
        let req = make_request("agent-1", "shell_exec", 60);
        let request_id = req.id;

        let mgr2 = Arc::clone(&mgr);
        tokio::spawn(async move {
            // Small delay to let the request register
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let result = mgr2.resolve(
                request_id,
                ApprovalDecision::Approved,
                Some("admin".to_string()),
            );
            assert!(result.is_ok());
            let resp = result.unwrap();
            assert_eq!(resp.decision, ApprovalDecision::Approved);
            assert_eq!(resp.decided_by, Some("admin".to_string()));
        });

        let decision = mgr.request_approval(req).await;
        assert_eq!(decision, ApprovalDecision::Approved);
        let recent = mgr.list_recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].decision, ApprovalDecision::Approved);
        assert_eq!(recent[0].decided_by.as_deref(), Some("admin"));
    }

    // -----------------------------------------------------------------------
    // request_approval — deny
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_request_approval_deny() {
        let mgr = Arc::new(default_manager());
        let req = make_request("agent-1", "shell_exec", 60);
        let request_id = req.id;

        let mgr2 = Arc::clone(&mgr);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let result = mgr2.resolve(request_id, ApprovalDecision::Denied, None);
            assert!(result.is_ok());
        });

        let decision = mgr.request_approval(req).await;
        assert_eq!(decision, ApprovalDecision::Denied);
        let recent = mgr.list_recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].decision, ApprovalDecision::Denied);
    }

    // -----------------------------------------------------------------------
    // max pending per agent
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_max_pending_per_agent() {
        let mgr = Arc::new(default_manager());

        // Fill up 5 pending requests for agent-1 (they will all be waiting)
        let mut ids = Vec::new();
        for _ in 0..MAX_PENDING_PER_AGENT {
            let req = make_request("agent-1", "shell_exec", 300);
            ids.push(req.id);
            let mgr_clone = Arc::clone(&mgr);
            tokio::spawn(async move {
                mgr_clone.request_approval(req).await;
            });
        }

        // Give spawned tasks time to register
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(mgr.pending_count(), MAX_PENDING_PER_AGENT);

        // 6th request for the same agent should be immediately denied
        let req6 = make_request("agent-1", "shell_exec", 300);
        let decision = mgr.request_approval(req6).await;
        assert_eq!(decision, ApprovalDecision::Denied);

        // A different agent should still be able to submit
        let req_other = make_request("agent-2", "shell_exec", 300);
        let other_id = req_other.id;
        let mgr2 = Arc::clone(&mgr);
        tokio::spawn(async move {
            mgr2.request_approval(req_other).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(mgr.pending_count(), MAX_PENDING_PER_AGENT + 1);

        // Cleanup: resolve all pending to avoid hanging tasks
        for id in &ids {
            let _ = mgr.resolve(*id, ApprovalDecision::Denied, None);
        }
        let _ = mgr.resolve(other_id, ApprovalDecision::Denied, None);
    }

    // -----------------------------------------------------------------------
    // persistence across restart
    // -----------------------------------------------------------------------

    #[test]
    fn test_persistent_pending_approvals_survive_manager_restart() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let db_path = tmp.path().join("memory.sqlite");
        let memory = Arc::new(
            t3rnel_memory::MemorySubstrate::open(&db_path, 0.1, &MemoryConfig::default())
                .expect("memory opens"),
        );
        let req = make_request("agent-1", "file_write", 60);

        let mgr = default_manager();
        mgr.set_memory(memory.clone());
        mgr.submit_pending(req.clone()).expect("submit pending");
        assert_eq!(mgr.pending_count(), 1);

        let reloaded = default_manager();
        reloaded.set_memory(memory.clone());
        reloaded.load_pending_from_db();
        let pending = reloaded.list_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, req.id);
        assert_eq!(pending[0].agent_id, req.agent_id);
        assert_eq!(pending[0].tool_name, req.tool_name);

        let response = reloaded
            .resolve(
                req.id,
                ApprovalDecision::Approved,
                Some("restart-test".to_string()),
            )
            .expect("resolve reloaded pending approval");
        assert_eq!(response.agent_id, "agent-1");
        assert_eq!(response.decided_by.as_deref(), Some("restart-test"));
        assert!(reloaded.list_pending().is_empty());
        assert!(memory
            .load_pending_approvals()
            .expect("load pending approvals")
            .is_empty());
    }

    // -----------------------------------------------------------------------
    // policy defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_defaults() {
        let mgr = default_manager();
        let policy = mgr.policy();
        assert_eq!(policy.require_approval, vec!["shell_exec".to_string()]);
        assert_eq!(policy.timeout_secs, 60);
        assert!(!policy.auto_approve_autonomous);
    }
}
