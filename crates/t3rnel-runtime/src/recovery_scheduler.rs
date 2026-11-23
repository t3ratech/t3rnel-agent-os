//! Recovery scheduler for automatic primary model recovery.
//!
//! Background task that attempts to recover to primary models after failures
//! using exponential backoff and success thresholds.

use crate::drivers::health_tracker::{HealthTracker, InMemoryHealthTracker};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use t3rnel_types::agent::{ChainState, RecoveryConfig};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// Recovery scheduler for automatic primary model recovery.
#[allow(dead_code)]
pub struct RecoveryScheduler {
    /// Chain states per agent ID.
    chains: Arc<RwLock<HashMap<String, ChainState>>>,
    /// Health tracker for checking provider health.
    health: Arc<InMemoryHealthTracker>,
    /// Task handle for the recovery loop.
    task_handle: JoinHandle<()>,
}

impl RecoveryScheduler {
    /// Create a new recovery scheduler.
    ///
    /// Panics if called outside a Tokio runtime — prefer [`Self::try_start`]
    /// from synchronous callers such as the kernel boot sequence.
    pub fn new(
        health: Arc<InMemoryHealthTracker>,
        check_interval: Duration,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let chains = Arc::new(RwLock::new(HashMap::new()));
        let chains_clone = chains.clone();
        let health_clone = health.clone();

        let task_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(check_interval);
            loop {
                interval.tick().await;
                Self::run_recovery_cycle(chains_clone.clone(), health_clone.clone()).await;
            }
        });

        Ok(Self {
            chains,
            health,
            task_handle,
        })
    }

    /// Start the scheduler only if a Tokio runtime is available.
    ///
    /// The kernel's boot sequence is synchronous, but it is normally invoked
    /// from inside the daemon's async runtime. `tokio::spawn` panics when no
    /// runtime is present — which would turn "recovery is unavailable" into
    /// "the kernel will not boot", a strictly worse outcome for a background
    /// optimisation. Returns `None` (with a warning) instead of panicking, so
    /// sync callers and unit tests are safe.
    pub fn try_start(health: Arc<InMemoryHealthTracker>, check_interval: Duration) -> Option<Self> {
        if tokio::runtime::Handle::try_current().is_err() {
            warn!(
                "No Tokio runtime available at kernel boot — automatic primary-model \
                 recovery is disabled for this process. Agents demoted to a fallback \
                 model will stay there until restart."
            );
            return None;
        }
        match Self::new(health, check_interval) {
            Ok(s) => {
                info!(
                    interval_secs = check_interval.as_secs(),
                    "Recovery scheduler started — demoted agents will be re-promoted \
                     to their primary model once it recovers"
                );
                Some(s)
            }
            Err(e) => {
                warn!("Recovery scheduler failed to start: {e}");
                None
            }
        }
    }

    /// Run a single recovery cycle.
    async fn run_recovery_cycle(
        chains: Arc<RwLock<HashMap<String, ChainState>>>,
        health: Arc<InMemoryHealthTracker>,
    ) {
        let mut chains = chains.write().await;
        let now = Utc::now();

        for (agent_id, state) in chains.iter_mut() {
            // Skip if currently at primary (index 0)
            if state.current_index == 0 {
                continue;
            }

            // Check if backoff has elapsed
            if let Some(backoff_until) = state.backoff_until {
                if backoff_until > now {
                    continue;
                }
            }

            // Check retry pattern
            let should_retry = Self::should_retry(state);
            if !should_retry {
                info!(
                    agent_id = %agent_id,
                    "Recovery stopped: retry pattern exhausted"
                );
                continue;
            }

            // Attempt recovery to primary
            info!(
                agent_id = %agent_id,
                current_index = state.current_index,
                "Attempting recovery to primary model"
            );

            // In a real implementation, this would trigger a test request
            // to the primary provider to verify it's healthy
            // For now, we'll simulate recovery by checking health metrics
            if let Some(primary_health) = health.get_all_health().await.first() {
                if primary_health.success_rate > 0.8
                    && primary_health.circuit_state == t3rnel_types::agent::CircuitState::Closed
                {
                    // Primary is healthy, promote back to index 0
                    state.current_index = 0;
                    state.consecutive_failures = 0;
                    state.consecutive_successes = 0;
                    state.backoff_until = None;
                    info!(
                        agent_id = %agent_id,
                        "Successfully recovered to primary model"
                    );
                } else {
                    // Primary still unhealthy, increase backoff
                    state.consecutive_failures += 1;
                    let backoff_ms = Self::calculate_backoff(state.consecutive_failures);
                    state.backoff_until =
                        Some(now + chrono::Duration::milliseconds(backoff_ms as i64));
                    warn!(
                        agent_id = %agent_id,
                        backoff_ms = backoff_ms,
                        "Primary still unhealthy, backing off"
                    );
                }
            }
        }
    }

    /// Calculate exponential backoff delay.
    fn calculate_backoff(failure_count: u32) -> u64 {
        const BASE_MS: u64 = 1000;
        const MAX_MS: u64 = 30000;
        let backoff = BASE_MS * 2_u64.pow(failure_count.min(5));
        backoff.min(MAX_MS)
    }

    /// Check if retry pattern allows another attempt.
    fn should_retry(_state: &ChainState) -> bool {
        // Default to retry forever if no pattern is configured
        // In a real implementation, this would check the agent's retry_pattern config
        true
    }

    /// Register a new chain for recovery monitoring.
    pub async fn register_chain(&self, agent_id: String, _recovery_config: &RecoveryConfig) {
        let mut chains = self.chains.write().await;
        chains.entry(agent_id).or_insert_with(|| ChainState {
            current_index: 0,
            last_fail_time: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
            backoff_until: None,
        });
    }

    /// Update chain state after a failure.
    pub async fn record_failure(&self, agent_id: &str, _recovery_config: &RecoveryConfig) {
        let mut chains = self.chains.write().await;
        if let Some(state) = chains.get_mut(agent_id) {
            state.current_index += 1;
            state.last_fail_time = Some(Utc::now());
            state.consecutive_failures += 1;
            state.consecutive_successes = 0;
            let backoff_ms = Self::calculate_backoff(state.consecutive_failures);
            state.backoff_until =
                Some(Utc::now() + chrono::Duration::milliseconds(backoff_ms as i64));
        }
    }

    /// Get current chain state for an agent.
    pub async fn get_chain_state(&self, agent_id: &str) -> Option<ChainState> {
        let chains = self.chains.read().await;
        chains.get(agent_id).cloned()
    }

    /// Manually trigger recovery for an agent.
    pub async fn trigger_recovery(&self, agent_id: &str) {
        let mut chains = self.chains.write().await;
        if let Some(state) = chains.get_mut(agent_id) {
            state.backoff_until = None;
            state.consecutive_failures = 0;
        }
    }
}

impl Drop for RecoveryScheduler {
    fn drop(&mut self) {
        self.task_handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::health_tracker::InMemoryHealthTracker;

    #[test]
    fn test_exponential_backoff() {
        assert_eq!(RecoveryScheduler::calculate_backoff(0), 1000);
        assert_eq!(RecoveryScheduler::calculate_backoff(1), 2000);
        assert_eq!(RecoveryScheduler::calculate_backoff(2), 4000);
        assert_eq!(RecoveryScheduler::calculate_backoff(3), 8000);
        assert_eq!(RecoveryScheduler::calculate_backoff(4), 16000);
        assert_eq!(RecoveryScheduler::calculate_backoff(5), 30000); // Capped at max
        assert_eq!(RecoveryScheduler::calculate_backoff(10), 30000); // Still capped
    }

    #[test]
    fn test_should_retry_default() {
        let state = ChainState {
            current_index: 1,
            last_fail_time: None,
            consecutive_failures: 5,
            consecutive_successes: 0,
            backoff_until: None,
        };
        assert!(RecoveryScheduler::should_retry(&state));
    }

    #[tokio::test]
    async fn test_register_chain() {
        let health = Arc::new(InMemoryHealthTracker::new(100));
        let scheduler = RecoveryScheduler::new(health, Duration::from_secs(5)).unwrap();
        let config = RecoveryConfig::default();

        scheduler
            .register_chain("test-agent".to_string(), &config)
            .await;
        let state = scheduler.get_chain_state("test-agent").await;
        assert!(state.is_some());
        assert_eq!(state.unwrap().current_index, 0);
    }

    #[tokio::test]
    async fn test_record_failure() {
        let health = Arc::new(InMemoryHealthTracker::new(100));
        let scheduler = RecoveryScheduler::new(health, Duration::from_secs(5)).unwrap();
        let config = RecoveryConfig::default();

        scheduler
            .register_chain("test-agent".to_string(), &config)
            .await;
        scheduler.record_failure("test-agent", &config).await;

        let state = scheduler.get_chain_state("test-agent").await.unwrap();
        assert_eq!(state.current_index, 1);
        assert_eq!(state.consecutive_failures, 1);
        assert!(state.backoff_until.is_some());
    }

    #[tokio::test]
    async fn test_trigger_recovery() {
        let health = Arc::new(InMemoryHealthTracker::new(100));
        let scheduler = RecoveryScheduler::new(health, Duration::from_secs(5)).unwrap();
        let config = RecoveryConfig::default();

        scheduler
            .register_chain("test-agent".to_string(), &config)
            .await;
        scheduler.record_failure("test-agent", &config).await;
        scheduler.trigger_recovery("test-agent").await;

        let state = scheduler.get_chain_state("test-agent").await.unwrap();
        assert!(state.backoff_until.is_none());
        assert_eq!(state.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn test_chain_state_persistence() {
        let health = Arc::new(InMemoryHealthTracker::new(100));
        let scheduler = RecoveryScheduler::new(health, Duration::from_secs(5)).unwrap();
        let config = RecoveryConfig::default();

        scheduler
            .register_chain("test-agent".to_string(), &config)
            .await;
        scheduler.record_failure("test-agent", &config).await;
        scheduler.record_failure("test-agent", &config).await;

        let state = scheduler.get_chain_state("test-agent").await.unwrap();
        assert_eq!(state.current_index, 2);
        assert_eq!(state.consecutive_failures, 2);
    }
}
