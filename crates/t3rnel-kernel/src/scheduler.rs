//! Agent scheduler — manages agent execution and resource tracking.

use dashmap::DashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;
use t3rnel_types::agent::{AgentId, ResourceQuota};
use t3rnel_types::error::{T3rnelError, T3rnelResult};
use t3rnel_types::message::TokenUsage;
use tokio::task::JoinHandle;
use tracing::debug;

/// Tracks resource usage for an agent with a rolling hourly window.
#[derive(Debug)]
pub struct UsageTracker {
    /// Total tokens consumed within the current window.
    pub total_tokens: u64,
    /// Total tool calls made within the current window.
    pub tool_calls: u64,
    /// Start of the current usage window.
    pub window_start: Instant,
}

impl Default for UsageTracker {
    fn default() -> Self {
        Self {
            total_tokens: 0,
            tool_calls: 0,
            window_start: Instant::now(),
        }
    }
}

impl UsageTracker {
    /// Reset counters if the current window has expired (1 hour).
    fn reset_if_expired(&mut self) {
        if self.window_start.elapsed() >= std::time::Duration::from_secs(3600) {
            self.total_tokens = 0;
            self.tool_calls = 0;
            self.window_start = Instant::now();
        }
    }
}

/// The agent scheduler manages execution ordering and resource quotas.
pub struct AgentScheduler {
    /// Resource quotas per agent.
    quotas: DashMap<AgentId, ResourceQuota>,
    /// Usage tracking per agent.
    usage: DashMap<AgentId, UsageTracker>,
    /// Active task handles per agent.
    tasks: DashMap<AgentId, JoinHandle<()>>,
    /// File write claims for concurrent coder fanout.
    write_claims: DashMap<PathBuf, WriteClaim>,
}

impl AgentScheduler {
    /// Create a new scheduler.
    pub fn new() -> Self {
        Self {
            quotas: DashMap::new(),
            usage: DashMap::new(),
            tasks: DashMap::new(),
            write_claims: DashMap::new(),
        }
    }

    /// Register an agent with its resource quota.
    pub fn register(&self, agent_id: AgentId, quota: ResourceQuota) {
        self.quotas.insert(agent_id, quota);
        self.usage.insert(agent_id, UsageTracker::default());
    }

    /// Record token usage for an agent.
    pub fn record_usage(&self, agent_id: AgentId, usage: &TokenUsage) {
        if let Some(mut tracker) = self.usage.get_mut(&agent_id) {
            tracker.reset_if_expired();
            tracker.total_tokens += usage.total();
        }
    }

    /// Check if an agent has exceeded its quota.
    pub fn check_quota(&self, agent_id: AgentId) -> T3rnelResult<()> {
        let quota = match self.quotas.get(&agent_id) {
            Some(q) => q.clone(),
            None => return Ok(()), // No quota = no limit
        };
        let mut tracker = match self.usage.get_mut(&agent_id) {
            Some(t) => t,
            None => return Ok(()),
        };

        // Reset the window if an hour has passed
        tracker.reset_if_expired();

        if quota.max_llm_tokens_per_hour > 0 && tracker.total_tokens > quota.max_llm_tokens_per_hour
        {
            return Err(T3rnelError::QuotaExceeded(format!(
                "Token limit exceeded: {} / {}",
                tracker.total_tokens, quota.max_llm_tokens_per_hour
            )));
        }

        Ok(())
    }

    /// Reset usage tracking for an agent (e.g. on session reset).
    pub fn reset_usage(&self, agent_id: AgentId) {
        if let Some(mut tracker) = self.usage.get_mut(&agent_id) {
            tracker.total_tokens = 0;
            tracker.tool_calls = 0;
            tracker.window_start = Instant::now();
        }
    }

    /// Track an active task handle for an agent.
    pub fn track_task(&self, agent_id: AgentId, handle: JoinHandle<()>) {
        self.tasks.insert(agent_id, handle);
    }

    /// Abort an agent's active task.
    pub fn abort_task(&self, agent_id: AgentId) {
        if let Some((_, handle)) = self.tasks.remove(&agent_id) {
            handle.abort();
            debug!(agent = %agent_id, "Aborted agent task");
        }
    }

    /// Remove an agent from the scheduler.
    pub fn unregister(&self, agent_id: AgentId) {
        self.abort_task(agent_id);
        self.quotas.remove(&agent_id);
        self.usage.remove(&agent_id);
    }

    /// Get usage stats for an agent.
    pub fn get_usage(&self, agent_id: AgentId) -> Option<(u64, u64)> {
        self.usage
            .get(&agent_id)
            .map(|t| (t.total_tokens, t.tool_calls))
    }

    /// Returns remaining token headroom before quota is hit.
    /// Returns `None` if no token quota is configured (unlimited).
    pub fn token_headroom(&self, agent_id: AgentId) -> Option<u64> {
        let quota = self.quotas.get(&agent_id)?;
        if quota.max_llm_tokens_per_hour == 0 {
            return None;
        }
        let mut tracker = self.usage.get_mut(&agent_id)?;
        tracker.reset_if_expired();
        let used = tracker.total_tokens;
        Some(quota.max_llm_tokens_per_hour.saturating_sub(used))
    }

    /// Evaluate coder fanout admission with queue backpressure.
    pub fn plan_fanout(
        &self,
        coder_ids: &[AgentId],
        pending_tasks: usize,
        policy: &FanoutPolicy,
    ) -> FanoutDecision {
        if pending_tasks == 0 {
            return FanoutDecision::Admit { slots: 0 };
        }
        if pending_tasks > policy.max_queue_depth {
            return FanoutDecision::Backpressure {
                reason: format!(
                    "fanout queue depth {} exceeds limit {}",
                    pending_tasks, policy.max_queue_depth
                ),
                retry_after_secs: policy.retry_after_secs,
            };
        }

        let active = coder_ids
            .iter()
            .filter(|agent_id| self.tasks.contains_key(agent_id))
            .count();
        if active >= policy.max_parallel_coders {
            return FanoutDecision::Backpressure {
                reason: format!(
                    "active coder count {} reached limit {}",
                    active, policy.max_parallel_coders
                ),
                retry_after_secs: policy.retry_after_secs,
            };
        }

        let slots = (policy.max_parallel_coders - active).min(pending_tasks);
        FanoutDecision::Admit { slots }
    }

    /// Aggregate token usage for a set of agents in the current rolling window.
    pub fn aggregate_token_usage(&self, agent_ids: &[AgentId]) -> u64 {
        agent_ids
            .iter()
            .filter_map(|agent_id| self.get_usage(*agent_id).map(|(tokens, _)| tokens))
            .sum()
    }

    /// Enforce an aggregate token cap across a fanout group.
    pub fn check_aggregate_token_cap(&self, agent_ids: &[AgentId], cap: u64) -> T3rnelResult<()> {
        if cap == 0 {
            return Ok(());
        }
        let used = self.aggregate_token_usage(agent_ids);
        if used > cap {
            return Err(T3rnelError::QuotaExceeded(format!(
                "Aggregate token limit exceeded: {used} / {cap}"
            )));
        }
        Ok(())
    }

    /// Claim a path for a coder task. If another coder already owns the path,
    /// the new writer loses and reviewer arbitration is required.
    pub fn claim_write(
        &self,
        agent_id: AgentId,
        task_id: impl Into<String>,
        path: impl AsRef<Path>,
    ) -> WriteClaimDecision {
        let incoming = WriteClaim {
            agent_id,
            task_id: task_id.into(),
        };
        let path = path.as_ref().to_path_buf();
        if let Some(existing) = self.write_claims.get(&path) {
            if existing.agent_id == incoming.agent_id && existing.task_id == incoming.task_id {
                return WriteClaimDecision::Accepted { path };
            }
            return WriteClaimDecision::ReviewerArbitration {
                path,
                winner: existing.clone(),
                rejected: incoming,
            };
        }
        self.write_claims.insert(path.clone(), incoming);
        WriteClaimDecision::Accepted { path }
    }

    /// Clear every write claim owned by an agent.
    pub fn clear_write_claims(&self, agent_id: AgentId) {
        self.write_claims
            .retain(|_, claim| claim.agent_id != agent_id);
    }
}

impl Default for AgentScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Fanout admission policy for parallel coder execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanoutPolicy {
    pub max_parallel_coders: usize,
    pub max_queue_depth: usize,
    pub retry_after_secs: u64,
}

impl Default for FanoutPolicy {
    fn default() -> Self {
        Self {
            max_parallel_coders: 4,
            max_queue_depth: 32,
            retry_after_secs: 5,
        }
    }
}

/// Scheduler decision for a pending fanout batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FanoutDecision {
    Admit {
        slots: usize,
    },
    Backpressure {
        reason: String,
        retry_after_secs: u64,
    },
}

/// Owner of an in-flight write path during coder fanout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteClaim {
    pub agent_id: AgentId,
    pub task_id: String,
}

/// Result of claiming a path for mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteClaimDecision {
    Accepted {
        path: PathBuf,
    },
    ReviewerArbitration {
        path: PathBuf,
        winner: WriteClaim,
        rejected: WriteClaim,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_usage() {
        let scheduler = AgentScheduler::new();
        let id = AgentId::new();
        scheduler.register(id, ResourceQuota::default());
        scheduler.record_usage(
            id,
            &TokenUsage {
                input_tokens: 100,
                output_tokens: 50,
            },
        );
        let (tokens, _) = scheduler.get_usage(id).unwrap();
        assert_eq!(tokens, 150);
    }

    #[test]
    fn test_quota_check() {
        let scheduler = AgentScheduler::new();
        let id = AgentId::new();
        let quota = ResourceQuota {
            max_llm_tokens_per_hour: 100,
            ..Default::default()
        };
        scheduler.register(id, quota);
        scheduler.record_usage(
            id,
            &TokenUsage {
                input_tokens: 60,
                output_tokens: 50,
            },
        );
        assert!(scheduler.check_quota(id).is_err());
    }

    #[test]
    fn test_fanout_admits_available_slots() {
        let scheduler = AgentScheduler::new();
        let coders = vec![AgentId::new(), AgentId::new(), AgentId::new()];
        let policy = FanoutPolicy {
            max_parallel_coders: 2,
            max_queue_depth: 8,
            retry_after_secs: 3,
        };

        assert_eq!(
            scheduler.plan_fanout(&coders, 5, &policy),
            FanoutDecision::Admit { slots: 2 }
        );
    }

    #[tokio::test]
    async fn test_fanout_backpressures_when_parallel_limit_reached() {
        let scheduler = AgentScheduler::new();
        let coders = vec![AgentId::new(), AgentId::new()];
        let handle = tokio::spawn(async {});
        scheduler.track_task(coders[0], handle);
        let policy = FanoutPolicy {
            max_parallel_coders: 1,
            max_queue_depth: 8,
            retry_after_secs: 7,
        };

        match scheduler.plan_fanout(&coders, 2, &policy) {
            FanoutDecision::Backpressure {
                reason,
                retry_after_secs,
            } => {
                assert!(reason.contains("active coder count"));
                assert_eq!(retry_after_secs, 7);
            }
            other => panic!("expected backpressure, got {other:?}"),
        }
    }

    #[test]
    fn test_fanout_backpressures_when_queue_limit_exceeded() {
        let scheduler = AgentScheduler::new();
        let policy = FanoutPolicy {
            max_parallel_coders: 4,
            max_queue_depth: 2,
            retry_after_secs: 11,
        };

        match scheduler.plan_fanout(&[AgentId::new()], 3, &policy) {
            FanoutDecision::Backpressure {
                reason,
                retry_after_secs,
            } => {
                assert!(reason.contains("queue depth"));
                assert_eq!(retry_after_secs, 11);
            }
            other => panic!("expected backpressure, got {other:?}"),
        }
    }

    #[test]
    fn test_aggregate_token_cap() {
        let scheduler = AgentScheduler::new();
        let first = AgentId::new();
        let second = AgentId::new();
        scheduler.register(first, ResourceQuota::default());
        scheduler.register(second, ResourceQuota::default());
        scheduler.record_usage(
            first,
            &TokenUsage {
                input_tokens: 40,
                output_tokens: 10,
            },
        );
        scheduler.record_usage(
            second,
            &TokenUsage {
                input_tokens: 25,
                output_tokens: 25,
            },
        );

        assert_eq!(scheduler.aggregate_token_usage(&[first, second]), 100);
        assert!(scheduler
            .check_aggregate_token_cap(&[first, second], 99)
            .is_err());
        assert!(scheduler
            .check_aggregate_token_cap(&[first, second], 100)
            .is_ok());
    }

    #[test]
    fn test_write_claim_conflict_routes_to_reviewer_arbitration() {
        let scheduler = AgentScheduler::new();
        let first = AgentId::new();
        let second = AgentId::new();
        assert_eq!(
            scheduler.claim_write(first, "task-a", "src/lib.rs"),
            WriteClaimDecision::Accepted {
                path: PathBuf::from("src/lib.rs")
            }
        );

        match scheduler.claim_write(second, "task-b", "src/lib.rs") {
            WriteClaimDecision::ReviewerArbitration {
                path,
                winner,
                rejected,
            } => {
                assert_eq!(path, PathBuf::from("src/lib.rs"));
                assert_eq!(winner.agent_id, first);
                assert_eq!(winner.task_id, "task-a");
                assert_eq!(rejected.agent_id, second);
                assert_eq!(rejected.task_id, "task-b");
            }
            other => panic!("expected reviewer arbitration, got {other:?}"),
        }
    }
}
