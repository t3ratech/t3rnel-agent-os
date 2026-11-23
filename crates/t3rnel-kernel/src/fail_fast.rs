//! Fail-fast guard — circuit-breaker for agent execution.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use t3rnel_types::fail_fast::{
    AbortReason, AbortRecord, FailFastPolicy, HealthEvent, HealthStatus,
};

/// Per-task (and per-agent) failure tracker.
#[derive(Debug, Clone, Default)]
struct FailureWindow {
    tool_errors: Vec<Instant>,
    driver_failures: Vec<Instant>,
}

/// Fail-fast guard shared across the kernel.
pub struct FailFastGuard {
    policy: FailFastPolicy,
    windows: Arc<Mutex<HashMap<(String, String), FailureWindow>>>,
    health_tx: Option<tokio::sync::mpsc::UnboundedSender<HealthEvent>>,
}

impl FailFastGuard {
    pub fn new(policy: FailFastPolicy) -> Self {
        Self {
            policy,
            windows: Arc::new(Mutex::new(HashMap::new())),
            health_tx: None,
        }
    }

    pub fn with_health_stream(
        mut self,
        tx: tokio::sync::mpsc::UnboundedSender<HealthEvent>,
    ) -> Self {
        self.health_tx = Some(tx);
        self
    }

    /// Register a tool error for the given task+agent. Returns `Some(AbortReason)`
    /// if the policy threshold is breached.
    pub fn record_tool_error(&self, task_id: &str, agent_id: &str) -> Option<AbortReason> {
        let now = Instant::now();
        let mut windows = self.windows.lock().unwrap();
        let window = windows
            .entry((task_id.to_string(), agent_id.to_string()))
            .or_default();

        window.tool_errors.push(now);
        let cutoff = now - Duration::from_secs(self.policy.tool_error_window_secs);
        window.tool_errors.retain(|t| *t >= cutoff);

        let count = window.tool_errors.len() as u32;
        if count >= self.policy.max_consecutive_tool_errors {
            return Some(AbortReason::MaxConsecutiveToolErrors {
                count,
                window_secs: self.policy.tool_error_window_secs,
            });
        }
        None
    }

    /// Register a driver failure for the given task+agent. Returns `Some(AbortReason)`
    /// if the policy threshold is breached.
    pub fn record_driver_failure(&self, task_id: &str, agent_id: &str) -> Option<AbortReason> {
        let now = Instant::now();
        let mut windows = self.windows.lock().unwrap();
        let window = windows
            .entry((task_id.to_string(), agent_id.to_string()))
            .or_default();

        window.driver_failures.push(now);
        let cutoff = now - Duration::from_secs(self.policy.tool_error_window_secs);
        window.driver_failures.retain(|t| *t >= cutoff);

        let count = window.driver_failures.len() as u32;
        if count >= self.policy.max_driver_failures {
            return Some(AbortReason::MaxDriverFailures { count });
        }
        None
    }

    /// Check if a task should be aborted after a failure. If so, emits a health event
    /// and returns the abort reason.
    pub fn check_and_abort(
        &self,
        task_id: &str,
        agent_id: &str,
        reason: AbortReason,
    ) -> AbortRecord {
        let record = AbortRecord {
            task_id: task_id.to_string(),
            agent_id: agent_id.to_string(),
            reason: reason.clone(),
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        };

        if self.policy.emit_health_event {
            if let Some(tx) = &self.health_tx {
                let status = HealthStatus::Failed {
                    reason: format!("{:?}", reason),
                };
                let _ = tx.send(HealthEvent {
                    task_id: Some(task_id.to_string()),
                    agent_id: Some(agent_id.to_string()),
                    status,
                    timestamp_ms: record.timestamp_ms,
                });
            }
        }

        record
    }

    /// Emit a degraded health event without aborting.
    pub fn emit_degraded(&self, task_id: &str, agent_id: &str, reason: &str) {
        if let Some(tx) = &self.health_tx {
            let _ = tx.send(HealthEvent {
                task_id: Some(task_id.to_string()),
                agent_id: Some(agent_id.to_string()),
                status: HealthStatus::Degraded {
                    reason: reason.to_string(),
                },
                timestamp_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            });
        }
    }

    /// Clear failure history for a task+agent (e.g. on successful turn completion).
    pub fn clear(&self, task_id: &str, agent_id: &str) {
        let mut windows = self.windows.lock().unwrap();
        windows.remove(&(task_id.to_string(), agent_id.to_string()));
    }

    /// Reset all windows (e.g. on policy reload).
    pub fn reset_all(&self) {
        let mut windows = self.windows.lock().unwrap();
        windows.clear();
    }

    /// Get a copy of the current policy.
    pub fn policy(&self) -> &FailFastPolicy {
        &self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_error_threshold() {
        let policy = FailFastPolicy {
            max_consecutive_tool_errors: 3,
            tool_error_window_secs: 60,
            ..Default::default()
        };
        let guard = FailFastGuard::new(policy);

        assert!(guard.record_tool_error("t1", "a1").is_none());
        assert!(guard.record_tool_error("t1", "a1").is_none());
        let r = guard.record_tool_error("t1", "a1");
        assert!(
            matches!(
                r,
                Some(AbortReason::MaxConsecutiveToolErrors { count: 3, .. })
            ),
            "expected abort after 3 tool errors, got {:?}",
            r
        );
    }

    #[test]
    fn driver_failure_threshold() {
        let policy = FailFastPolicy {
            max_driver_failures: 2,
            ..Default::default()
        };
        let guard = FailFastGuard::new(policy);

        assert!(guard.record_driver_failure("t1", "a1").is_none());
        let r = guard.record_driver_failure("t1", "a1");
        assert!(
            matches!(r, Some(AbortReason::MaxDriverFailures { count: 2 })),
            "expected abort after 2 driver failures, got {:?}",
            r
        );
    }

    #[test]
    fn clear_resets_window() {
        let policy = FailFastPolicy {
            max_consecutive_tool_errors: 2,
            tool_error_window_secs: 60,
            ..Default::default()
        };
        let guard = FailFastGuard::new(policy);

        assert!(guard.record_tool_error("t1", "a1").is_none());
        guard.clear("t1", "a1");
        assert!(guard.record_tool_error("t1", "a1").is_none());
    }

    #[test]
    fn check_and_abort_emits_record() {
        let guard = FailFastGuard::new(FailFastPolicy::default());
        let record = guard.check_and_abort("t1", "a1", AbortReason::ManualKill);
        assert_eq!(record.task_id, "t1");
        assert_eq!(record.agent_id, "a1");
        assert!(matches!(record.reason, AbortReason::ManualKill));
    }
}
