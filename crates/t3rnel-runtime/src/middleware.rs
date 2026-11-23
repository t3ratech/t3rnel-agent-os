//! Agent middleware pipeline — ordered chain of before_model / after_model hooks.
//!
//! Each middleware is a trait object with `before_model` and `after_model` async
//! hooks. The orchestrator iterates the chain in order, aborting on first fatal error.

use async_trait::async_trait;
use t3rnel_types::agent::AgentManifest;
use t3rnel_types::message::{Message, TokenUsage};
use t3rnel_types::tool::ToolDefinition;
use tracing::{debug, warn};

use crate::llm_driver::CompletionResponse;
use crate::loop_guard::{LoopGuard, LoopGuardVerdict};
use crate::tool_policy::{resolve_tool_access, ToolAccessResult, ToolPolicy};
use t3rnel_memory::session::Session;

// ---------------------------------------------------------------------------
// MiddlewareContext
// ---------------------------------------------------------------------------

/// Mutable context passed to every middleware hook.
pub struct MiddlewareContext<'a> {
    pub manifest: &'a AgentManifest,
    pub session: &'a mut Session,
    pub messages: &'a mut Vec<Message>,
    pub system_prompt: &'a mut String,
    pub available_tools: &'a [ToolDefinition],
    pub total_usage: &'a mut TokenUsage,
    pub iteration: u32,
    pub response: Option<&'a mut CompletionResponse>,
}

impl<'a> MiddlewareContext<'a> {
    pub fn response_text(&self) -> Option<String> {
        self.response.as_ref().map(|r| r.text())
    }
    pub fn tool_calls(&self) -> Option<&[t3rnel_types::tool::ToolCall]> {
        self.response.as_ref().map(|r| r.tool_calls.as_slice())
    }
}

// ---------------------------------------------------------------------------
// AgentMiddleware trait
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum MiddlewareError {
    Fatal(String),
    Warning(String),
}

impl std::fmt::Display for MiddlewareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MiddlewareError::Fatal(msg) => write!(f, "Middleware fatal: {msg}"),
            MiddlewareError::Warning(msg) => write!(f, "Middleware warning: {msg}"),
        }
    }
}

impl std::error::Error for MiddlewareError {}

pub type MiddlewareResult = Result<(), MiddlewareError>;

#[async_trait]
pub trait AgentMiddleware: Send + Sync {
    fn name(&self) -> &'static str;
    async fn before_model(&mut self, _ctx: &mut MiddlewareContext<'_>) -> MiddlewareResult {
        Ok(())
    }
    async fn after_model(&mut self, _ctx: &mut MiddlewareContext<'_>) -> MiddlewareResult {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MiddlewareChain
// ---------------------------------------------------------------------------

pub struct MiddlewareChain {
    middlewares: Vec<Box<dyn AgentMiddleware>>,
}

impl MiddlewareChain {
    pub fn new() -> Self {
        Self {
            middlewares: Vec::new(),
        }
    }
    pub fn from_vec(middlewares: Vec<Box<dyn AgentMiddleware>>) -> Self {
        Self { middlewares }
    }
    pub fn push(&mut self, mw: Box<dyn AgentMiddleware>) {
        self.middlewares.push(mw);
    }
    pub async fn run_before_model(&mut self, ctx: &mut MiddlewareContext<'_>) -> MiddlewareResult {
        for mw in &mut self.middlewares {
            debug!(middleware = mw.name(), "running before_model");
            match mw.before_model(ctx).await {
                Ok(()) => {}
                Err(MiddlewareError::Fatal(e)) => {
                    warn!(middleware = mw.name(), error = %e, "before_model fatal");
                    return Err(MiddlewareError::Fatal(e));
                }
                Err(MiddlewareError::Warning(e)) => {
                    warn!(middleware = mw.name(), error = %e, "before_model warning");
                }
            }
        }
        Ok(())
    }
    pub async fn run_after_model(&mut self, ctx: &mut MiddlewareContext<'_>) -> MiddlewareResult {
        for mw in &mut self.middlewares {
            debug!(middleware = mw.name(), "running after_model");
            match mw.after_model(ctx).await {
                Ok(()) => {}
                Err(MiddlewareError::Fatal(e)) => {
                    warn!(middleware = mw.name(), error = %e, "after_model fatal");
                    return Err(MiddlewareError::Fatal(e));
                }
                Err(MiddlewareError::Warning(e)) => {
                    warn!(middleware = mw.name(), error = %e, "after_model warning");
                }
            }
        }
        Ok(())
    }
    pub fn len(&self) -> usize {
        self.middlewares.len()
    }
    pub fn is_empty(&self) -> bool {
        self.middlewares.is_empty()
    }
}

impl Default for MiddlewareChain {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GuardrailMiddleware
// ---------------------------------------------------------------------------

pub struct GuardrailMiddleware {
    policy: ToolPolicy,
    subagent_depth: u32,
}

impl GuardrailMiddleware {
    pub fn new(policy: ToolPolicy, subagent_depth: u32) -> Self {
        Self {
            policy,
            subagent_depth,
        }
    }

    pub fn from_manifest(manifest: &AgentManifest) -> Self {
        let mut policy = ToolPolicy::default();
        for tool in &manifest.tool_allowlist {
            policy.agent_rules.push(crate::tool_policy::ToolPolicyRule {
                pattern: tool.clone(),
                effect: crate::tool_policy::PolicyEffect::Allow,
            });
        }
        for tool in &manifest.tool_blocklist {
            policy.agent_rules.push(crate::tool_policy::ToolPolicyRule {
                pattern: tool.clone(),
                effect: crate::tool_policy::PolicyEffect::Deny,
            });
        }
        Self {
            policy,
            subagent_depth: 0,
        }
    }
}

#[async_trait]
impl AgentMiddleware for GuardrailMiddleware {
    fn name(&self) -> &'static str {
        "GuardrailMiddleware"
    }

    async fn after_model(&mut self, ctx: &mut MiddlewareContext<'_>) -> MiddlewareResult {
        let Some(response) = ctx.response.as_mut() else {
            return Ok(());
        };
        let mut allowed = Vec::new();
        let mut denied = Vec::new();
        for tc in &response.tool_calls {
            match resolve_tool_access(&tc.name, &self.policy, self.subagent_depth) {
                ToolAccessResult::Allowed => allowed.push(tc.clone()),
                ToolAccessResult::Denied {
                    rule_pattern,
                    source,
                } => {
                    denied.push((tc.name.clone(), rule_pattern, source));
                }
                ToolAccessResult::DepthExceeded { current, max } => {
                    denied.push((
                        tc.name.clone(),
                        format!("depth {current}>{max}"),
                        "depth".into(),
                    ));
                }
            }
        }
        if !denied.is_empty() {
            let names: Vec<String> = denied.iter().map(|(n, _, _)| n.clone()).collect();
            warn!(tools = ?names, "Guardrail denied tool calls");
            let notice = format!(
                "[System: The following tool calls were blocked by policy: {}. Do not retry them.]",
                names.join(", ")
            );
            ctx.system_prompt.push_str("\n\n");
            ctx.system_prompt.push_str(&notice);
        }
        response.tool_calls = allowed;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LoopDetectionMiddleware
// ---------------------------------------------------------------------------

pub struct LoopDetectionMiddleware {
    loop_guard: LoopGuard,
}

impl LoopDetectionMiddleware {
    pub fn new(config: crate::loop_guard::LoopGuardConfig) -> Self {
        Self {
            loop_guard: LoopGuard::new(config),
        }
    }
}

#[async_trait]
impl AgentMiddleware for LoopDetectionMiddleware {
    fn name(&self) -> &'static str {
        "LoopDetectionMiddleware"
    }

    async fn after_model(&mut self, ctx: &mut MiddlewareContext<'_>) -> MiddlewareResult {
        let Some(response) = ctx.response.as_ref() else {
            return Ok(());
        };
        for tc in &response.tool_calls {
            let verdict = self.loop_guard.check(&tc.name, &tc.input);
            match verdict {
                LoopGuardVerdict::Allow => {}
                LoopGuardVerdict::Warn(msg) => {
                    warn!("LoopDetection warning: {msg}");
                    ctx.system_prompt.push_str("\n\n[System: ");
                    ctx.system_prompt.push_str(&msg);
                    ctx.system_prompt.push(']');
                }
                LoopGuardVerdict::Block(msg) => {
                    warn!("LoopDetection block: {msg}");
                    return Err(MiddlewareError::Fatal(format!("Loop detected: {msg}")));
                }
                LoopGuardVerdict::CircuitBreak(msg) => {
                    warn!("LoopDetection circuit-break: {msg}");
                    return Err(MiddlewareError::Fatal(format!("Circuit broken: {msg}")));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TokenUsageMiddleware
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct TokenUsageMiddleware {
    /// Per-tool-call cached usage for subagent attribution.
    pub subagent_usage: std::collections::HashMap<String, TokenUsage>,
}

impl TokenUsageMiddleware {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AgentMiddleware for TokenUsageMiddleware {
    fn name(&self) -> &'static str {
        "TokenUsageMiddleware"
    }

    async fn after_model(&mut self, ctx: &mut MiddlewareContext<'_>) -> MiddlewareResult {
        let Some(response) = ctx.response.as_ref() else {
            return Ok(());
        };
        ctx.total_usage.input_tokens += response.usage.input_tokens;
        ctx.total_usage.output_tokens += response.usage.output_tokens;
        // Cache subagent usage by tool_call_id for later merging
        for tc in &response.tool_calls {
            if tc.name == "agent_spawn" || tc.name == "agent_send" {
                self.subagent_usage.insert(
                    tc.id.clone(),
                    TokenUsage {
                        input_tokens: response.usage.input_tokens,
                        output_tokens: response.usage.output_tokens,
                    },
                );
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ToolErrorHandlingMiddleware
// ---------------------------------------------------------------------------

pub struct ToolErrorHandlingMiddleware;

impl Default for ToolErrorHandlingMiddleware {
    fn default() -> Self {
        Self
    }
}

impl ToolErrorHandlingMiddleware {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AgentMiddleware for ToolErrorHandlingMiddleware {
    fn name(&self) -> &'static str {
        "ToolErrorHandlingMiddleware"
    }

    async fn after_model(&mut self, _ctx: &mut MiddlewareContext<'_>) -> MiddlewareResult {
        // Tool errors are handled inline in the agent loop via
        // TOOL_ERROR_GUIDANCE injection. This middleware is a no-op
        // placeholder for future structured error classification.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DanglingToolCallMiddleware
// ---------------------------------------------------------------------------

/// Validates that tool_call/tool_result pairs are well-formed before
/// every LLM call. Detects orphaned ToolUse blocks (assistant called a
/// tool but the result was never injected) and orphaned ToolResult blocks
/// (result present without a matching call). Logs warnings so the operator
/// can investigate session corruption.
pub struct DanglingToolCallMiddleware;

impl Default for DanglingToolCallMiddleware {
    fn default() -> Self {
        Self
    }
}

impl DanglingToolCallMiddleware {
    pub fn new() -> Self {
        Self
    }

    fn find_dangling(messages: &[Message]) -> Vec<String> {
        use t3rnel_types::message::{ContentBlock, MessageContent, Role};
        let mut tool_use_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut tool_result_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for msg in messages {
            let blocks = match &msg.content {
                MessageContent::Blocks(bs) => bs.as_slice(),
                _ => continue,
            };
            if msg.role == Role::Assistant {
                for b in blocks {
                    if let ContentBlock::ToolUse { id, .. } = b {
                        tool_use_ids.insert(id.clone());
                    }
                }
            } else if msg.role == Role::User {
                for b in blocks {
                    if let ContentBlock::ToolResult { tool_use_id, .. } = b {
                        tool_result_ids.insert(tool_use_id.clone());
                    }
                }
            }
        }
        let mut issues = Vec::new();
        for id in &tool_use_ids {
            if !tool_result_ids.contains(id) {
                issues.push(format!("orphaned ToolUse id={id}"));
            }
        }
        for id in &tool_result_ids {
            if !tool_use_ids.contains(id) {
                issues.push(format!("orphaned ToolResult id={id}"));
            }
        }
        issues
    }
}

#[async_trait]
impl AgentMiddleware for DanglingToolCallMiddleware {
    fn name(&self) -> &'static str {
        "DanglingToolCallMiddleware"
    }

    async fn before_model(&mut self, ctx: &mut MiddlewareContext<'_>) -> MiddlewareResult {
        let issues = Self::find_dangling(ctx.messages);
        if !issues.is_empty() {
            warn!(issues = ?issues, "Dangling tool call pairs detected");
            let notice = format!(
                "[System: Session has dangling tool calls: {}. This may cause provider errors.]",
                issues.join("; ")
            );
            ctx.system_prompt.push('\n');
            ctx.system_prompt.push_str(&notice);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SubagentLimitMiddleware
// ---------------------------------------------------------------------------

/// Tracks concurrent subagent usage and enforces per-agent limits.
pub struct SubagentLimitMiddleware {
    max_concurrent: u32,
    max_depth: u32,
    /// Number of active subagent_spawn calls observed.
    active_count: u32,
}

impl SubagentLimitMiddleware {
    pub fn new(max_concurrent: u32, max_depth: u32) -> Self {
        Self {
            max_concurrent,
            max_depth,
            active_count: 0,
        }
    }

    pub fn from_manifest(_manifest: &AgentManifest) -> Self {
        // Default to 5 concurrent / 10 depth, matching ToolPolicy defaults
        Self::new(5, 10)
    }
}

#[async_trait]
impl AgentMiddleware for SubagentLimitMiddleware {
    fn name(&self) -> &'static str {
        "SubagentLimitMiddleware"
    }

    async fn after_model(&mut self, ctx: &mut MiddlewareContext<'_>) -> MiddlewareResult {
        let Some(response) = ctx.response.as_ref() else {
            return Ok(());
        };
        let spawn_count = response
            .tool_calls
            .iter()
            .filter(|tc| tc.name == "agent_spawn")
            .count() as u32;
        if spawn_count > 0 {
            // Enforce a per-response limit. The previous active_count-based check leaked
            // because spawned subagents are never explicitly marked as finished by this
            // middleware, so the count would grow indefinitely across agent loop turns.
            if spawn_count > self.max_concurrent {
                return Err(MiddlewareError::Fatal(format!(
                    "Subagent concurrency limit exceeded: tried to spawn {} in a single response (max {})",
                    spawn_count, self.max_concurrent
                )));
            }
            self.active_count += spawn_count;
        }
        // Check depth via metadata hint (kernel injects current depth into manifest metadata)
        if let Some(depth_val) = ctx.manifest.metadata.get("subagent_depth") {
            if let Some(depth) = depth_val.as_u64() {
                if depth > self.max_depth as u64 {
                    return Err(MiddlewareError::Fatal(format!(
                        "Subagent depth limit exceeded: {}/{}",
                        depth, self.max_depth
                    )));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TitleMiddleware
// ---------------------------------------------------------------------------

/// Auto-generates a session label from the first user message when the
/// session does not yet have a label. This helps identify sessions in
/// the UI without requiring the user to manually name them.
pub struct TitleMiddleware;

impl Default for TitleMiddleware {
    fn default() -> Self {
        Self
    }
}

impl TitleMiddleware {
    pub fn new() -> Self {
        Self
    }

    fn generate_title(user_text: &str) -> String {
        let trimmed = user_text.trim();
        if trimmed.is_empty() {
            return "New conversation".to_string();
        }
        let max_len = 40;
        if trimmed.len() <= max_len {
            trimmed.to_string()
        } else {
            let mut cut = trimmed[..max_len].to_string();
            if let Some(idx) = cut.rfind(' ') {
                cut.truncate(idx);
            }
            cut.push_str("...");
            cut
        }
    }
}

#[async_trait]
impl AgentMiddleware for TitleMiddleware {
    fn name(&self) -> &'static str {
        "TitleMiddleware"
    }

    async fn before_model(&mut self, ctx: &mut MiddlewareContext<'_>) -> MiddlewareResult {
        if ctx.session.label.is_some() {
            return Ok(());
        }
        // Find the first user message with text content
        for msg in &ctx.session.messages {
            if msg.role == t3rnel_types::message::Role::User {
                let text = match &msg.content {
                    t3rnel_types::message::MessageContent::Text(t) => t.clone(),
                    t3rnel_types::message::MessageContent::Blocks(bs) => bs
                        .iter()
                        .filter_map(|b| match b {
                            t3rnel_types::message::ContentBlock::Text { text, .. } => {
                                Some(text.clone())
                            }
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join(" "),
                    _ => String::new(),
                };
                let title = Self::generate_title(&text);
                ctx.session.label = Some(title);
                break;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ClarificationMiddleware
// ---------------------------------------------------------------------------

/// Detects when the agent response is asking for clarification rather
/// than providing an answer or calling tools. Instructs the system to
/// treat the next user message as a continuation of the same turn.
pub struct ClarificationMiddleware;

impl Default for ClarificationMiddleware {
    fn default() -> Self {
        Self
    }
}

impl ClarificationMiddleware {
    pub fn new() -> Self {
        Self
    }

    fn is_clarification(text: &str) -> bool {
        let lower = text.to_lowercase();
        let phrases = [
            "could you clarify",
            "can you clarify",
            "could you provide more",
            "i need more information",
            "please specify",
            "what do you mean by",
            "could you elaborate",
            "i'm not sure i understand",
        ];
        phrases.iter().any(|p| lower.contains(p))
    }
}

#[async_trait]
impl AgentMiddleware for ClarificationMiddleware {
    fn name(&self) -> &'static str {
        "ClarificationMiddleware"
    }

    async fn after_model(&mut self, ctx: &mut MiddlewareContext<'_>) -> MiddlewareResult {
        if let Some(text) = ctx.response_text() {
            if Self::is_clarification(&text)
                && ctx
                    .response
                    .as_ref()
                    .is_none_or(|r| r.tool_calls.is_empty())
            {
                debug!("Agent asked for clarification — marking response as clarification");
                // Inject a system hint so the agent knows to wait for user input
                ctx.system_prompt.push('\n');
                ctx.system_prompt.push_str(
                    "[System: The agent has asked for clarification. Awaiting user response.]",
                );
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TodoListMiddleware
// ---------------------------------------------------------------------------

/// Tracks action items and todo markers extracted from agent responses.
/// Scans response text for patterns like "TODO:", "Action item:",
/// "Next steps:" and accumulates them in the session metadata for
/// display in the UI or follow-up scheduling.
#[derive(Default)]
pub struct TodoListMiddleware {
    todos: Vec<String>,
}

impl TodoListMiddleware {
    pub fn new() -> Self {
        Self::default()
    }

    fn extract_todos(text: &str) -> Vec<String> {
        let mut found = Vec::new();
        let patterns = [
            ("TODO:", 5),
            ("ACTION ITEM:", 12),
            ("Next steps:", 11),
            ("Follow-up:", 10),
        ];
        for &(prefix, len) in &patterns {
            for line in text.lines() {
                if let Some(idx) = line.to_uppercase().find(&prefix.to_uppercase()) {
                    let start = idx + len;
                    let item = line[start..].trim().to_string();
                    if !item.is_empty() && !found.contains(&item) {
                        found.push(item);
                    }
                }
            }
        }
        found
    }
}

#[async_trait]
impl AgentMiddleware for TodoListMiddleware {
    fn name(&self) -> &'static str {
        "TodoListMiddleware"
    }

    async fn after_model(&mut self, ctx: &mut MiddlewareContext<'_>) -> MiddlewareResult {
        if let Some(text) = ctx.response_text() {
            let new_todos = Self::extract_todos(&text);
            if !new_todos.is_empty() {
                self.todos.extend(new_todos.clone());
                // Inject a system summary of open todos
                let summary = format!("[System: Open action items: {}]", new_todos.join("; "));
                ctx.system_prompt.push('\n');
                ctx.system_prompt.push_str(&summary);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DeferredToolFilterMiddleware
// ---------------------------------------------------------------------------

/// Identifies expensive or side-effect-heavy tool calls and defers them
/// to a later iteration when the agent has gathered enough context to
/// use them efficiently. Prevents premature API calls, file writes, or
/// shell executions that might be re-issued on the next turn.
pub struct DeferredToolFilterMiddleware {
    deferred_tools: std::collections::HashSet<String>,
}

impl Default for DeferredToolFilterMiddleware {
    fn default() -> Self {
        let mut set = std::collections::HashSet::new();
        // Default deferred tools: expensive or state-mutating operations
        set.insert("web_fetch".to_string());
        set.insert("shell_exec".to_string());
        set.insert("file_write".to_string());
        set.insert("agent_spawn".to_string());
        Self {
            deferred_tools: set,
        }
    }
}

impl DeferredToolFilterMiddleware {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tools(tools: &[String]) -> Self {
        Self {
            deferred_tools: tools.iter().cloned().collect(),
        }
    }
}

#[async_trait]
impl AgentMiddleware for DeferredToolFilterMiddleware {
    fn name(&self) -> &'static str {
        "DeferredToolFilterMiddleware"
    }

    async fn after_model(&mut self, ctx: &mut MiddlewareContext<'_>) -> MiddlewareResult {
        let Some(response) = ctx.response.as_mut() else {
            return Ok(());
        };
        let mut allowed = Vec::new();
        let mut deferred = Vec::new();
        for tc in &response.tool_calls {
            if self.deferred_tools.contains(&tc.name) && ctx.iteration == 0 {
                deferred.push(tc.name.clone());
            } else {
                allowed.push(tc.clone());
            }
        }
        if !deferred.is_empty() {
            let notice = format!(
                "[System: The following expensive tools were deferred from iteration 0: {}. They may be called in a subsequent turn if still needed.]",
                deferred.join(", ")
            );
            ctx.system_prompt.push('\n');
            ctx.system_prompt.push_str(&notice);
            response.tool_calls = allowed;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Default chain builder
// ---------------------------------------------------------------------------

/// Build the standard middleware chain for an agent.
pub fn build_default_chain(manifest: &AgentManifest) -> MiddlewareChain {
    let mut chain = MiddlewareChain::new();
    chain.push(Box::new(TitleMiddleware::new()));
    chain.push(Box::new(DanglingToolCallMiddleware::new()));
    chain.push(Box::new(TokenUsageMiddleware::new()));
    chain.push(Box::new(GuardrailMiddleware::from_manifest(manifest)));
    chain.push(Box::new(SubagentLimitMiddleware::from_manifest(manifest)));
    chain.push(Box::new(LoopDetectionMiddleware::new(
        crate::loop_guard::LoopGuardConfig::default(),
    )));
    chain.push(Box::new(ToolErrorHandlingMiddleware::new()));
    chain.push(Box::new(ClarificationMiddleware::new()));
    chain.push(Box::new(TodoListMiddleware::new()));
    chain.push(Box::new(DeferredToolFilterMiddleware::new()));
    chain
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use t3rnel_memory::session::Session;
    use t3rnel_types::agent::AgentManifest;
    use t3rnel_types::agent::{AgentId, SessionId};
    use t3rnel_types::message::{ContentBlock, Message, TokenUsage};
    use t3rnel_types::tool::ToolCall;

    fn dummy_manifest() -> AgentManifest {
        AgentManifest::default()
    }

    fn dummy_session() -> Session {
        Session {
            id: SessionId::new(),
            agent_id: AgentId::new(),
            messages: vec![],
            context_window_tokens: 0,
            label: None,
        }
    }

    #[tokio::test]
    async fn test_guardrail_denies_blocked_tools() {
        let mut manifest = dummy_manifest();
        manifest.tool_blocklist = vec!["shell_exec".to_string()];
        let mut mw = GuardrailMiddleware::from_manifest(&manifest);

        let mut session = dummy_session();
        let mut messages = vec![];
        let mut system_prompt = String::new();
        let mut total_usage = TokenUsage::default();

        let mut response = CompletionResponse {
            content: vec![],
            stop_reason: t3rnel_types::message::StopReason::ToolUse,
            tool_calls: vec![
                ToolCall {
                    id: "1".to_string(),
                    name: "shell_exec".to_string(),
                    input: serde_json::json!({"cmd":"echo hi"}),
                },
                ToolCall {
                    id: "2".to_string(),
                    name: "file_read".to_string(),
                    input: serde_json::json!({"path":"/tmp/a"}),
                },
            ],
            usage: TokenUsage::default(),
        };

        let mut ctx = MiddlewareContext {
            manifest: &manifest,
            session: &mut session,
            messages: &mut messages,
            system_prompt: &mut system_prompt,
            available_tools: &[],
            total_usage: &mut total_usage,
            iteration: 0,
            response: Some(&mut response),
        };

        mw.after_model(&mut ctx).await.unwrap();

        // shell_exec should be stripped
        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].name, "file_read");
        assert!(system_prompt.contains("blocked by policy"));
    }

    #[tokio::test]
    async fn test_title_middleware_sets_label() {
        let mut mw = TitleMiddleware::new();
        let manifest = dummy_manifest();
        let mut session = dummy_session();
        session.messages.push(Message::user(
            "How do I deploy a Rust web app to production?",
        ));
        let mut messages = vec![];
        let mut system_prompt = String::new();
        let mut total_usage = TokenUsage::default();

        let mut ctx = MiddlewareContext {
            manifest: &manifest,
            session: &mut session,
            messages: &mut messages,
            system_prompt: &mut system_prompt,
            available_tools: &[],
            total_usage: &mut total_usage,
            iteration: 0,
            response: None,
        };

        mw.before_model(&mut ctx).await.unwrap();

        assert_eq!(
            session.label,
            Some("How do I deploy a Rust web app to...".to_string())
        );
    }

    #[tokio::test]
    async fn test_title_middleware_skips_if_already_labeled() {
        let mut mw = TitleMiddleware::new();
        let manifest = dummy_manifest();
        let mut session = dummy_session();
        session.label = Some("Existing".to_string());
        session.messages.push(Message::user("New question here"));
        let mut messages = vec![];
        let mut system_prompt = String::new();
        let mut total_usage = TokenUsage::default();

        let mut ctx = MiddlewareContext {
            manifest: &manifest,
            session: &mut session,
            messages: &mut messages,
            system_prompt: &mut system_prompt,
            available_tools: &[],
            total_usage: &mut total_usage,
            iteration: 0,
            response: None,
        };

        mw.before_model(&mut ctx).await.unwrap();

        assert_eq!(session.label, Some("Existing".to_string()));
    }

    #[tokio::test]
    async fn test_dangling_tool_call_detects_orphans() {
        let mut mw = DanglingToolCallMiddleware::new();
        let manifest = dummy_manifest();
        let mut session = dummy_session();

        // Assistant calls a tool
        session.messages.push(Message::assistant_with_blocks(vec![
            ContentBlock::ToolUse {
                id: "t1".to_string(),
                name: "shell_exec".to_string(),
                input: serde_json::json!({}),
                provider_metadata: None,
            },
        ]));
        // No matching tool result — user just sends text
        session.messages.push(Message::user("Please continue"));

        let mut messages = session.messages.clone();
        let mut system_prompt = String::new();
        let mut total_usage = TokenUsage::default();

        let mut ctx = MiddlewareContext {
            manifest: &manifest,
            session: &mut session,
            messages: &mut messages,
            system_prompt: &mut system_prompt,
            available_tools: &[],
            total_usage: &mut total_usage,
            iteration: 0,
            response: None,
        };

        mw.before_model(&mut ctx).await.unwrap();

        assert!(system_prompt.contains("dangling tool calls"));
    }

    #[tokio::test]
    async fn test_clarification_detects_question() {
        let mut mw = ClarificationMiddleware::new();
        let manifest = dummy_manifest();
        let mut session = dummy_session();
        let mut messages = vec![];
        let mut system_prompt = String::new();
        let mut total_usage = TokenUsage::default();

        let mut response = CompletionResponse {
            content: vec![ContentBlock::Text {
                text: "Could you clarify what you mean by 'production'?".to_string(),
                provider_metadata: None,
            }],
            stop_reason: t3rnel_types::message::StopReason::EndTurn,
            tool_calls: vec![],
            usage: TokenUsage::default(),
        };

        let mut ctx = MiddlewareContext {
            manifest: &manifest,
            session: &mut session,
            messages: &mut messages,
            system_prompt: &mut system_prompt,
            available_tools: &[],
            total_usage: &mut total_usage,
            iteration: 0,
            response: Some(&mut response),
        };

        mw.after_model(&mut ctx).await.unwrap();

        assert!(system_prompt.contains("Awaiting user response"));
    }

    #[tokio::test]
    async fn test_todo_list_extracts_items() {
        let mut mw = TodoListMiddleware::new();
        let manifest = dummy_manifest();
        let mut session = dummy_session();
        let mut messages = vec![];
        let mut system_prompt = String::new();
        let mut total_usage = TokenUsage::default();

        let mut response = CompletionResponse {
            content: vec![ContentBlock::Text {
                text: "I found the issue. TODO: fix the race condition. Next steps: add mutex."
                    .to_string(),
                provider_metadata: None,
            }],
            stop_reason: t3rnel_types::message::StopReason::EndTurn,
            tool_calls: vec![],
            usage: TokenUsage::default(),
        };

        let mut ctx = MiddlewareContext {
            manifest: &manifest,
            session: &mut session,
            messages: &mut messages,
            system_prompt: &mut system_prompt,
            available_tools: &[],
            total_usage: &mut total_usage,
            iteration: 0,
            response: Some(&mut response),
        };

        mw.after_model(&mut ctx).await.unwrap();

        assert!(system_prompt.contains("Open action items"));
        assert!(system_prompt.contains("fix the race condition"));
        assert!(system_prompt.contains("add mutex"));
    }

    #[tokio::test]
    async fn test_deferred_tool_filter_strips_on_first_iteration() {
        let mut mw = DeferredToolFilterMiddleware::new();
        let manifest = dummy_manifest();
        let mut session = dummy_session();
        let mut messages = vec![];
        let mut system_prompt = String::new();
        let mut total_usage = TokenUsage::default();

        let mut response = CompletionResponse {
            content: vec![],
            stop_reason: t3rnel_types::message::StopReason::ToolUse,
            tool_calls: vec![
                ToolCall {
                    id: "1".to_string(),
                    name: "shell_exec".to_string(),
                    input: serde_json::json!({"cmd":"ls"}),
                },
                ToolCall {
                    id: "2".to_string(),
                    name: "file_read".to_string(),
                    input: serde_json::json!({"path":"/tmp/a"}),
                },
            ],
            usage: TokenUsage::default(),
        };

        let mut ctx = MiddlewareContext {
            manifest: &manifest,
            session: &mut session,
            messages: &mut messages,
            system_prompt: &mut system_prompt,
            available_tools: &[],
            total_usage: &mut total_usage,
            iteration: 0,
            response: Some(&mut response),
        };

        mw.after_model(&mut ctx).await.unwrap();

        // shell_exec should be deferred on iteration 0
        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].name, "file_read");
        assert!(system_prompt.contains("deferred"));
    }

    #[tokio::test]
    async fn test_deferred_tool_filter_allows_on_later_iteration() {
        let mut mw = DeferredToolFilterMiddleware::new();
        let manifest = dummy_manifest();
        let mut session = dummy_session();
        let mut messages = vec![];
        let mut system_prompt = String::new();
        let mut total_usage = TokenUsage::default();

        let mut response = CompletionResponse {
            content: vec![],
            stop_reason: t3rnel_types::message::StopReason::ToolUse,
            tool_calls: vec![ToolCall {
                id: "1".to_string(),
                name: "shell_exec".to_string(),
                input: serde_json::json!({"cmd":"ls"}),
            }],
            usage: TokenUsage::default(),
        };

        let mut ctx = MiddlewareContext {
            manifest: &manifest,
            session: &mut session,
            messages: &mut messages,
            system_prompt: &mut system_prompt,
            available_tools: &[],
            total_usage: &mut total_usage,
            iteration: 2,
            response: Some(&mut response),
        };

        mw.after_model(&mut ctx).await.unwrap();

        // shell_exec should be allowed on iteration 2
        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].name, "shell_exec");
        assert!(!system_prompt.contains("deferred"));
    }

    #[tokio::test]
    async fn test_middleware_chain_order() {
        let manifest = dummy_manifest();
        let chain = build_default_chain(&manifest);
        assert_eq!(chain.len(), 10);
    }
}
