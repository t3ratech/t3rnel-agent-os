//! Fail-fast contract types — circuit-breaker for agent execution.

use serde::{Deserialize, Serialize};

/// Policy controlling when the kernel should abort a task graph
/// due to repeated failures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FailFastPolicy {
    /// Max consecutive tool errors before the task is aborted.
    pub max_consecutive_tool_errors: u32,
    /// Max driver-level (LLM) failures before the task is aborted.
    pub max_driver_failures: u32,
    /// Time window in seconds for counting consecutive errors.
    pub tool_error_window_secs: u64,
    /// Whether to emit a `HealthStream` degraded event on breach.
    pub emit_health_event: bool,
}

impl Default for FailFastPolicy {
    fn default() -> Self {
        Self {
            // Sized against the fallback chain, which is ~30 slots deep: one bad
            // turn can legitimately burn many driver attempts, so the old limit of
            // 10 aborted healthy agents. The real bug was that the failure window
            // was never pruned (see `FailFastGuard::record_driver_failure`), so
            // these stay finite — a guard that never trips is not a guard.
            max_consecutive_tool_errors: 15,
            max_driver_failures: 40,
            tool_error_window_secs: 300,
            emit_health_event: true,
        }
    }
}

/// Current health status of a task or the overall kernel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Degraded { reason: String },
    Failed { reason: String },
}

/// Health update streamed to gRPC subscribers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthEvent {
    pub task_id: Option<String>,
    pub agent_id: Option<String>,
    pub status: HealthStatus,
    pub timestamp_ms: u64,
}

/// Reason for a fail-fast abort.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AbortReason {
    MaxConsecutiveToolErrors { count: u32, window_secs: u64 },
    MaxDriverFailures { count: u32 },
    ManualKill,
}

/// Record of a fail-fast abort.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbortRecord {
    pub task_id: String,
    pub agent_id: String,
    pub reason: AbortReason,
    pub timestamp_ms: u64,
}
