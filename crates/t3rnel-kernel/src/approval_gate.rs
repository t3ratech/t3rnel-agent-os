//! Approval gate — pre-tool-use rule matching patterned on ruflo GuidanceControlPlane.
//!
//! Every tool invocation is checked against a configurable policy before execution.
//! The gate can: allow, deny, or escalate to human approval (Inbox).

/// Decision from the approval gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    /// Execute immediately.
    Allow,
    /// Block execution.
    Deny,
    /// Escalate to human approval via Inbox.
    Escalate,
}

/// A rule that matches tool invocations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateRule {
    /// Human-readable rule name.
    pub name: String,
    /// Tool ID pattern (glob: `*`, `file_*`, `shell_exec`).
    pub tool_pattern: String,
    /// Agent role pattern (glob).
    pub agent_role_pattern: String,
    /// Required capability the agent must hold.
    pub required_capability: Option<String>,
    /// Decision when matched.
    pub decision: GateDecision,
    /// Rationale logged to audit trail.
    pub rationale: String,
}

impl GateRule {
    /// Check if this rule matches a tool invocation.
    pub fn matches(&self, tool_id: &str, agent_role: &str) -> bool {
        glob_match(&self.tool_pattern, tool_id) && glob_match(&self.agent_role_pattern, agent_role)
    }
}

/// Approval gate engine.
pub struct ApprovalGate {
    /// Ordered rules: first match wins.
    rules: Vec<GateRule>,
    /// Default decision when no rule matches.
    default: GateDecision,
}

impl ApprovalGate {
    /// Create a new gate with the built-in default rules.
    pub fn new() -> Self {
        Self {
            rules: default_rules(),
            default: GateDecision::Escalate,
        }
    }

    /// Evaluate a tool invocation against all rules.
    ///
    /// Returns the decision and the matching rule name (if any).
    pub fn evaluate(
        &self,
        tool_id: &str,
        agent_role: &str,
        agent_caps: &[String],
    ) -> (GateDecision, Option<String>) {
        for rule in &self.rules {
            if rule.matches(tool_id, agent_role) {
                // Check capability requirement
                if let Some(ref cap) = rule.required_capability {
                    if !agent_caps.contains(cap) {
                        return (
                            GateDecision::Deny,
                            Some(format!("{} (missing cap: {})", rule.name, cap)),
                        );
                    }
                }
                return (rule.decision, Some(rule.name.clone()));
            }
        }
        (self.default, None)
    }

    /// Add a custom rule (prepended so it takes priority).
    pub fn prepend_rule(&mut self, rule: GateRule) {
        self.rules.insert(0, rule);
    }

    /// Add a custom rule (appended).
    pub fn append_rule(&mut self, rule: GateRule) {
        self.rules.push(rule);
    }

    /// Replace all rules.
    pub fn set_rules(&mut self, rules: Vec<GateRule>) {
        self.rules = rules;
    }

    /// List current rules.
    pub fn list_rules(&self) -> &[GateRule] {
        &self.rules
    }
}

impl Default for ApprovalGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Built-in default rules — conservative, deny-by-default for sensitive tools.
fn default_rules() -> Vec<GateRule> {
    vec![
        // ── Orchestrator: command centre — allow core management tools ──
        GateRule {
            name: "orchestrator-shell".to_string(),
            tool_pattern: "shell_exec".to_string(),
            agent_role_pattern: "orchestrator".to_string(),
            required_capability: Some("shell".to_string()),
            decision: GateDecision::Allow,
            rationale: "Orchestrator may execute shell commands".to_string(),
        },
        GateRule {
            name: "orchestrator-file-write".to_string(),
            tool_pattern: "file_write".to_string(),
            agent_role_pattern: "orchestrator".to_string(),
            required_capability: Some("file_write".to_string()),
            decision: GateDecision::Allow,
            rationale: "Orchestrator may write files".to_string(),
        },
        GateRule {
            name: "orchestrator-file-read".to_string(),
            tool_pattern: "file_read".to_string(),
            agent_role_pattern: "orchestrator".to_string(),
            required_capability: None,
            decision: GateDecision::Allow,
            rationale: "Orchestrator may read files".to_string(),
        },
        GateRule {
            name: "orchestrator-agent-mgmt".to_string(),
            tool_pattern: "agent_*".to_string(),
            agent_role_pattern: "orchestrator".to_string(),
            required_capability: None,
            decision: GateDecision::Allow,
            rationale: "Orchestrator may manage agents".to_string(),
        },
        GateRule {
            name: "orchestrator-memory".to_string(),
            tool_pattern: "memory_*".to_string(),
            agent_role_pattern: "orchestrator".to_string(),
            required_capability: None,
            decision: GateDecision::Allow,
            rationale: "Orchestrator may access shared memory".to_string(),
        },
        GateRule {
            name: "orchestrator-tasks".to_string(),
            tool_pattern: "task_*".to_string(),
            agent_role_pattern: "orchestrator".to_string(),
            required_capability: None,
            decision: GateDecision::Allow,
            rationale: "Orchestrator may manage tasks".to_string(),
        },
        // ── Critical safety: always escalate kill-switch to human ──
        GateRule {
            name: "kill-switch-escalation".to_string(),
            tool_pattern: "kill_switch*".to_string(),
            agent_role_pattern: "*".to_string(),
            required_capability: None,
            decision: GateDecision::Escalate,
            rationale: "Kill-switch mutations require human approval (safety)".to_string(),
        },
        // ── Security scope fence: deny auto-modification ──
        GateRule {
            name: "scope-fence-deny".to_string(),
            tool_pattern: "*scope_fence*".to_string(),
            agent_role_pattern: "*".to_string(),
            required_capability: None,
            decision: GateDecision::Deny,
            rationale: "Scope fence rules cannot be modified by agents".to_string(),
        },
        GateRule {
            name: "audit-deny".to_string(),
            tool_pattern: "*audit*".to_string(),
            agent_role_pattern: "*".to_string(),
            required_capability: None,
            decision: GateDecision::Deny,
            rationale: "Audit chain is tamper-evident; agents cannot modify it".to_string(),
        },
        GateRule {
            name: "vault-deny".to_string(),
            tool_pattern: "*vault*".to_string(),
            agent_role_pattern: "*".to_string(),
            required_capability: None,
            decision: GateDecision::Deny,
            rationale: "Credential vault access is inventor-only".to_string(),
        },
        // ── High-risk shell: escalate unless explicitly granted ──
        GateRule {
            name: "shell-escalate".to_string(),
            tool_pattern: "shell_exec".to_string(),
            agent_role_pattern: "*".to_string(),
            required_capability: Some("shell".to_string()),
            decision: GateDecision::Escalate,
            rationale: "Shell execution requires human approval unless pre-authorized".to_string(),
        },
        // ── Code modification: escalate for non-coder roles ──
        GateRule {
            name: "file-write-coder".to_string(),
            tool_pattern: "file_write".to_string(),
            agent_role_pattern: "coder".to_string(),
            required_capability: Some("file_write".to_string()),
            decision: GateDecision::Allow,
            rationale: "Coder agents with file_write capability may edit files".to_string(),
        },
        GateRule {
            name: "file-write-escalate".to_string(),
            tool_pattern: "file_write".to_string(),
            agent_role_pattern: "*".to_string(),
            required_capability: None,
            decision: GateDecision::Escalate,
            rationale: "Non-coder agents require approval for file modifications".to_string(),
        },
        // ── Network: allow http-fetch for researchers ──
        GateRule {
            name: "http-fetch-researcher".to_string(),
            tool_pattern: "http_fetch".to_string(),
            agent_role_pattern: "researcher".to_string(),
            required_capability: Some("web".to_string()),
            decision: GateDecision::Allow,
            rationale: "Researchers may fetch web content".to_string(),
        },
    ]
}

/// Simple glob matching: `*` matches any substring.
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(inner) = pattern.strip_prefix('*').and_then(|s| s.strip_suffix('*')) {
        return text.contains(inner);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return text.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return text.ends_with(suffix);
    }
    pattern == text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate_allows_orchestrator_shell() {
        let gate = ApprovalGate::new();
        let (decision, rule) = gate.evaluate("shell_exec", "orchestrator", &["shell".to_string()]);
        assert_eq!(decision, GateDecision::Allow);
        assert_eq!(rule.unwrap(), "orchestrator-shell");
    }

    #[test]
    fn test_gate_allows_orchestrator_file_write() {
        let gate = ApprovalGate::new();
        let (decision, rule) =
            gate.evaluate("file_write", "orchestrator", &["file_write".to_string()]);
        assert_eq!(decision, GateDecision::Allow);
        assert_eq!(rule.unwrap(), "orchestrator-file-write");
    }

    #[test]
    fn test_gate_allows_orchestrator_agent_mgmt() {
        let gate = ApprovalGate::new();
        let (decision, rule) = gate.evaluate("agent_spawn", "orchestrator", &[]);
        assert_eq!(decision, GateDecision::Allow);
        assert_eq!(rule.unwrap(), "orchestrator-agent-mgmt");
    }

    #[test]
    fn test_gate_allows_orchestrator_file_read() {
        let gate = ApprovalGate::new();
        let (decision, rule) = gate.evaluate("file_read", "orchestrator", &[]);
        assert_eq!(decision, GateDecision::Allow);
        assert_eq!(rule.unwrap(), "orchestrator-file-read");
    }

    #[test]
    fn test_gate_allows_coder_file_write() {
        let gate = ApprovalGate::new();
        let (decision, rule) = gate.evaluate("file_write", "coder", &["file_write".to_string()]);
        assert_eq!(decision, GateDecision::Allow);
        assert!(rule.is_some());
    }

    #[test]
    fn test_gate_denies_shell_for_uncapped() {
        let gate = ApprovalGate::new();
        let (decision, rule) = gate.evaluate("shell_exec", "browser-hand", &[]);
        assert_eq!(decision, GateDecision::Deny);
        assert!(rule.is_some());
    }

    #[test]
    fn test_gate_escalates_shell_for_non_orchestrator_with_cap() {
        let gate = ApprovalGate::new();
        let (decision, rule) = gate.evaluate("shell_exec", "coder", &["shell".to_string()]);
        assert_eq!(decision, GateDecision::Escalate);
        assert!(rule.is_some());
    }

    #[test]
    fn test_gate_denies_shell_for_orchestrator_without_cap() {
        let gate = ApprovalGate::new();
        let (decision, rule) = gate.evaluate("shell_exec", "orchestrator", &[]);
        // Missing shell capability → shell-escalate rule matches but denies due to missing cap
        assert_eq!(decision, GateDecision::Deny);
        assert!(rule.is_some());
    }

    #[test]
    fn test_gate_denies_audit() {
        let gate = ApprovalGate::new();
        let (decision, _) = gate.evaluate("audit_chain", "coder", &["file_write".to_string()]);
        assert_eq!(decision, GateDecision::Deny);
    }

    #[test]
    fn test_gate_allows_http_fetch_for_researcher() {
        let gate = ApprovalGate::new();
        let (decision, rule) = gate.evaluate("http_fetch", "researcher", &["web".to_string()]);
        assert_eq!(decision, GateDecision::Allow);
        assert_eq!(rule.unwrap(), "http-fetch-researcher");
    }

    #[test]
    fn test_default_escalates_unmatched() {
        let gate = ApprovalGate::new();
        let (decision, rule) = gate.evaluate("unknown_tool", "random", &[]);
        assert_eq!(decision, GateDecision::Escalate);
        assert!(rule.is_none());
    }

    #[test]
    fn test_custom_rule_takes_priority() {
        let mut gate = ApprovalGate::new();
        gate.prepend_rule(GateRule {
            name: "custom-deny".to_string(),
            tool_pattern: "*".to_string(),
            agent_role_pattern: "*".to_string(),
            required_capability: None,
            decision: GateDecision::Deny,
            rationale: "Test".to_string(),
        });
        let (decision, _) = gate.evaluate("any_tool", "any_role", &[]);
        assert_eq!(decision, GateDecision::Deny);
    }
}
