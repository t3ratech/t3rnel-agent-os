//! Process supervision — graceful shutdown, signal handling, and health monitoring.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use t3rnel_types::agent::AgentId;
use tokio::sync::watch;
use tracing::{info, warn};

/// Shutdown signal manager with health monitoring.
pub struct Supervisor {
    /// Send side of the shutdown signal.
    shutdown_tx: watch::Sender<bool>,
    /// Receive side of the shutdown signal (clonable).
    shutdown_rx: watch::Receiver<bool>,
    /// Restart count (how many times agents have been restarted).
    restart_count: AtomicU64,
    /// Total panics caught across all agents.
    panic_count: AtomicU64,
    /// Per-agent restart counts for enforcing max_restarts.
    agent_restarts: DashMap<AgentId, u32>,
}

impl Supervisor {
    /// Create a new supervisor.
    pub fn new() -> Self {
        let (tx, rx) = watch::channel(false);
        Self {
            shutdown_tx: tx,
            shutdown_rx: rx,
            restart_count: AtomicU64::new(0),
            panic_count: AtomicU64::new(0),
            agent_restarts: DashMap::new(),
        }
    }

    /// Get a receiver that will be notified on shutdown.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }

    /// Trigger a graceful shutdown.
    pub fn shutdown(&self) {
        info!("Supervisor: initiating graceful shutdown");
        let _ = self.shutdown_tx.send(true);
    }

    /// Check if shutdown has been requested.
    pub fn is_shutting_down(&self) -> bool {
        *self.shutdown_rx.borrow()
    }

    /// Record that a panic was caught during agent execution.
    pub fn record_panic(&self) {
        self.panic_count.fetch_add(1, Ordering::Relaxed);
        warn!(
            total_panics = self.panic_count.load(Ordering::Relaxed),
            "Agent panic recorded"
        );
    }

    /// Record that an agent was restarted.
    pub fn record_restart(&self) {
        self.restart_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total number of panics caught.
    pub fn panic_count(&self) -> u64 {
        self.panic_count.load(Ordering::Relaxed)
    }

    /// Get the total number of restarts.
    pub fn restart_count(&self) -> u64 {
        self.restart_count.load(Ordering::Relaxed)
    }

    /// Record a restart for a specific agent and check if limit is exceeded.
    ///
    /// Returns Ok(restart_count) if within limit, or Err(count) if limit exceeded.
    pub fn record_agent_restart(&self, agent_id: AgentId, max_restarts: u32) -> Result<u32, u32> {
        let mut count = self.agent_restarts.entry(agent_id).or_insert(0);
        *count += 1;
        self.record_restart();

        if max_restarts > 0 && *count > max_restarts {
            warn!(
                agent = %agent_id,
                restarts = *count,
                max = max_restarts,
                "Agent exceeded max restart limit"
            );
            Err(*count)
        } else {
            Ok(*count)
        }
    }

    /// Record a restart and return the capped exponential backoff delay.
    pub fn plan_agent_restart(
        &self,
        agent_id: AgentId,
        max_restarts: u32,
        policy: RestartBackoffPolicy,
    ) -> Result<RestartDecision, RestartDecision> {
        match self.record_agent_restart(agent_id, max_restarts) {
            Ok(count) => Ok(RestartDecision::Restart {
                count,
                delay: policy.delay_for_attempt(count),
            }),
            Err(count) => Err(RestartDecision::PermanentStop {
                count,
                reason: format!("agent exceeded max_restarts ({max_restarts})"),
            }),
        }
    }

    /// Get the restart count for a specific agent.
    pub fn agent_restart_count(&self, agent_id: AgentId) -> u32 {
        self.agent_restarts.get(&agent_id).map(|r| *r).unwrap_or(0)
    }

    /// Reset restart counter for an agent (e.g., on manual intervention).
    pub fn reset_agent_restarts(&self, agent_id: AgentId) {
        self.agent_restarts.remove(&agent_id);
    }

    /// Get a health summary.
    pub fn health(&self) -> SupervisorHealth {
        SupervisorHealth {
            is_shutting_down: self.is_shutting_down(),
            panic_count: self.panic_count(),
            restart_count: self.restart_count(),
        }
    }
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

/// Health report from the supervisor.
#[derive(Debug, Clone)]
pub struct SupervisorHealth {
    pub is_shutting_down: bool,
    pub panic_count: u64,
    pub restart_count: u64,
}

/// Exponential restart backoff policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartBackoffPolicy {
    pub base_delay_secs: u64,
    pub max_delay_secs: u64,
}

impl RestartBackoffPolicy {
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let exponent = attempt.saturating_sub(1).min(31);
        let multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
        let secs = self
            .base_delay_secs
            .saturating_mul(multiplier)
            .min(self.max_delay_secs);
        Duration::from_secs(secs)
    }
}

impl Default for RestartBackoffPolicy {
    fn default() -> Self {
        Self {
            base_delay_secs: 1,
            max_delay_secs: 300,
        }
    }
}

/// Supervisor decision after an agent failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartDecision {
    Restart { count: u32, delay: Duration },
    PermanentStop { count: u32, reason: String },
}

/// Entry in the dead letter queue for permanently failed agents.
#[derive(Debug, Clone)]
pub struct DeadLetterEntry {
    pub agent_id: AgentId,
    pub reason: String,
    pub restart_count: u32,
    pub timestamp: std::time::SystemTime,
}

impl Supervisor {
    /// Record a dead letter entry for an agent that permanently failed.
    pub fn record_dead_letter(&self, agent_id: AgentId, reason: String, restart_count: u32) {
        let entry = DeadLetterEntry {
            agent_id,
            reason,
            restart_count,
            timestamp: std::time::SystemTime::now(),
        };
        warn!(
            agent = %entry.agent_id,
            restarts = entry.restart_count,
            reason = %entry.reason,
            "Agent moved to dead letter queue"
        );
        // Store in a global dead letter queue (simplified — could be persisted to disk)
        dead_letter_queue().lock().unwrap().push(entry);
    }

    /// Get all dead letter entries.
    pub fn dead_letters() -> Vec<DeadLetterEntry> {
        dead_letter_queue().lock().unwrap().clone()
    }

    /// Clear all dead letter entries.
    pub fn clear_dead_letters() {
        dead_letter_queue().lock().unwrap().clear();
    }
}

use std::sync::{Mutex, OnceLock};

fn dead_letter_queue() -> &'static Mutex<Vec<DeadLetterEntry>> {
    static QUEUE: OnceLock<Mutex<Vec<DeadLetterEntry>>> = OnceLock::new();
    QUEUE.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown() {
        let supervisor = Supervisor::new();
        assert!(!supervisor.is_shutting_down());
        supervisor.shutdown();
        assert!(supervisor.is_shutting_down());
    }

    #[test]
    fn test_subscribe() {
        let supervisor = Supervisor::new();
        let rx = supervisor.subscribe();
        assert!(!*rx.borrow());
        supervisor.shutdown();
        assert!(rx.has_changed().unwrap());
    }

    #[test]
    fn test_panic_tracking() {
        let supervisor = Supervisor::new();
        assert_eq!(supervisor.panic_count(), 0);
        supervisor.record_panic();
        supervisor.record_panic();
        assert_eq!(supervisor.panic_count(), 2);
    }

    #[test]
    fn test_restart_tracking() {
        let supervisor = Supervisor::new();
        assert_eq!(supervisor.restart_count(), 0);
        supervisor.record_restart();
        assert_eq!(supervisor.restart_count(), 1);
    }

    #[test]
    fn test_health() {
        let supervisor = Supervisor::new();
        let health = supervisor.health();
        assert!(!health.is_shutting_down);
        assert_eq!(health.panic_count, 0);
        assert_eq!(health.restart_count, 0);
    }

    #[test]
    fn test_agent_restart_within_limit() {
        let supervisor = Supervisor::new();
        let agent_id = AgentId::new();

        // Allow up to 3 restarts
        assert!(supervisor.record_agent_restart(agent_id, 3).is_ok());
        assert_eq!(supervisor.agent_restart_count(agent_id), 1);
        assert!(supervisor.record_agent_restart(agent_id, 3).is_ok());
        assert!(supervisor.record_agent_restart(agent_id, 3).is_ok());
        assert_eq!(supervisor.agent_restart_count(agent_id), 3);
    }

    #[test]
    fn test_agent_restart_exceeds_limit() {
        let supervisor = Supervisor::new();
        let agent_id = AgentId::new();

        assert!(supervisor.record_agent_restart(agent_id, 2).is_ok());
        assert!(supervisor.record_agent_restart(agent_id, 2).is_ok());
        // 3rd restart exceeds max_restarts=2
        let result = supervisor.record_agent_restart(agent_id, 2);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), 3);
    }

    #[test]
    fn test_agent_restart_zero_limit_unlimited() {
        let supervisor = Supervisor::new();
        let agent_id = AgentId::new();

        // max_restarts=0 means unlimited
        for _ in 0..100 {
            assert!(supervisor.record_agent_restart(agent_id, 0).is_ok());
        }
    }

    #[test]
    fn test_reset_agent_restarts() {
        let supervisor = Supervisor::new();
        let agent_id = AgentId::new();

        supervisor.record_agent_restart(agent_id, 10).unwrap();
        supervisor.record_agent_restart(agent_id, 10).unwrap();
        assert_eq!(supervisor.agent_restart_count(agent_id), 2);

        supervisor.reset_agent_restarts(agent_id);
        assert_eq!(supervisor.agent_restart_count(agent_id), 0);
    }

    #[test]
    fn test_restart_backoff_doubles_until_cap() {
        let policy = RestartBackoffPolicy {
            base_delay_secs: 2,
            max_delay_secs: 10,
        };

        assert_eq!(policy.delay_for_attempt(1), Duration::from_secs(2));
        assert_eq!(policy.delay_for_attempt(2), Duration::from_secs(4));
        assert_eq!(policy.delay_for_attempt(3), Duration::from_secs(8));
        assert_eq!(policy.delay_for_attempt(4), Duration::from_secs(10));
    }

    #[test]
    fn test_plan_agent_restart_returns_backoff() {
        let supervisor = Supervisor::new();
        let agent_id = AgentId::new();
        let policy = RestartBackoffPolicy {
            base_delay_secs: 5,
            max_delay_secs: 60,
        };

        assert_eq!(
            supervisor.plan_agent_restart(agent_id, 3, policy).unwrap(),
            RestartDecision::Restart {
                count: 1,
                delay: Duration::from_secs(5),
            }
        );
        assert_eq!(
            supervisor.plan_agent_restart(agent_id, 3, policy).unwrap(),
            RestartDecision::Restart {
                count: 2,
                delay: Duration::from_secs(10),
            }
        );
    }

    #[test]
    fn test_plan_agent_restart_permanent_stop_after_limit() {
        let supervisor = Supervisor::new();
        let agent_id = AgentId::new();
        let policy = RestartBackoffPolicy::default();

        assert!(supervisor.plan_agent_restart(agent_id, 1, policy).is_ok());
        let decision = supervisor
            .plan_agent_restart(agent_id, 1, policy)
            .unwrap_err();
        match decision {
            RestartDecision::PermanentStop { count, reason } => {
                assert_eq!(count, 2);
                assert!(reason.contains("max_restarts"));
            }
            other => panic!("expected permanent stop, got {other:?}"),
        }
    }
}
