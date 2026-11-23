//! Health tracking for LLM providers.
//!
//! Tracks success rates, latency, error types per provider/model combination.
//! Also tracks token usage for rate limiting (TPM/TPD).

use crate::llm_driver::LlmError;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock as StdRwLock;
use t3rnel_types::agent::{CircuitState, ProviderHealth};
use tokio::sync::RwLock;

/// Health tracker trait for recording and querying provider health.
#[allow(async_fn_in_trait)]
pub trait HealthTracker: Send + Sync {
    /// Record a successful request with latency.
    async fn record_success(&self, provider: &str, model: &str, latency_ms: u64);

    /// Record a failed request with error details.
    async fn record_failure(&self, provider: &str, model: &str, error: &LlmError);

    /// Get health metrics for a specific provider/model.
    async fn get_health(&self, provider: &str, model: &str) -> Option<ProviderHealth>;

    /// Get health metrics for all providers.
    async fn get_all_health(&self) -> Vec<ProviderHealth>;

    /// Check if a request would exceed TPM/TPD limits.
    async fn check_rate_limit(
        &self,
        provider: &str,
        model: &str,
        estimated_tokens: u64,
    ) -> Result<(), RateLimitError>;

    /// Record token usage after a successful request.
    async fn record_token_usage(
        &self,
        provider: &str,
        model: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
    );
}

/// Rate limit error when TPM/TPD would be exceeded.
#[derive(Debug, Clone)]
pub struct RateLimitError {
    pub limit_type: RateLimitType,
    pub retry_after_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitType {
    RpmExceeded,
    TpmExceeded,
    TpdExceeded,
}

/// Token usage tracking for rate limiting.
#[derive(Debug, Clone, Default)]
struct TokenUsage {
    /// Requests used in the current minute window.
    rpm_current: u64,
    /// Timestamp when the current RPM window started.
    rpm_window_start: chrono::DateTime<Utc>,
    /// Tokens used in the current minute window.
    tpm_current: u64,
    /// Timestamp when the current TPM window started.
    tpm_window_start: chrono::DateTime<Utc>,
    /// Tokens used in the current day window.
    tpd_current: u64,
    /// Timestamp when the current TPD window started.
    tpd_window_start: chrono::DateTime<Utc>,
}

/// Public token usage data for API responses.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenUsageData {
    pub rpm_current: u64,
    pub rpm_limit: Option<u64>,
    pub tpm_current: u64,
    pub tpm_limit: Option<u64>,
    pub tpd_current: u64,
    pub tpd_limit: Option<u64>,
    pub rpm_window_start: chrono::DateTime<Utc>,
    pub tpm_window_start: chrono::DateTime<Utc>,
    pub tpd_window_start: chrono::DateTime<Utc>,
}

/// Token usage entry with provider/model identification.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenUsageEntry {
    pub provider: String,
    pub model: String,
    pub rpm_current: u64,
    pub rpm_limit: Option<u64>,
    pub tpm_current: u64,
    pub tpm_limit: Option<u64>,
    pub tpd_current: u64,
    pub tpd_limit: Option<u64>,
    pub rpm_window_start: chrono::DateTime<Utc>,
    pub tpm_window_start: chrono::DateTime<Utc>,
    pub tpd_window_start: chrono::DateTime<Utc>,
}

/// In-memory health tracker with rolling window.
#[allow(dead_code)]
pub struct InMemoryHealthTracker {
    /// Health data per provider/model key.
    health: Arc<RwLock<HashMap<String, ProviderHealth>>>,
    /// Rolling window size for request history.
    window_size: usize,
    /// Token usage tracking per provider/model key.
    token_usage: Arc<RwLock<HashMap<String, TokenUsage>>>,
    /// RPM limit from configuration (can be overridden per provider/model).
    ///
    /// The limit maps use `std::sync::RwLock` rather than the async lock: they are
    /// plain config lookups that are never held across an await, and the kernel
    /// seeds them during its synchronous boot.
    rpm_limits: Arc<StdRwLock<HashMap<String, u64>>>,
    /// TPM limit from model catalog (can be overridden per provider/model).
    tpm_limits: Arc<StdRwLock<HashMap<String, u64>>>,
    /// TPD limit from model catalog (can be overridden per provider/model).
    tpd_limits: Arc<StdRwLock<HashMap<String, u64>>>,
}

impl InMemoryHealthTracker {
    /// Create a new in-memory health tracker.
    pub fn new(window_size: usize) -> Self {
        Self {
            health: Arc::new(RwLock::new(HashMap::new())),
            window_size,
            token_usage: Arc::new(RwLock::new(HashMap::new())),
            rpm_limits: Arc::new(StdRwLock::new(HashMap::new())),
            tpm_limits: Arc::new(StdRwLock::new(HashMap::new())),
            tpd_limits: Arc::new(StdRwLock::new(HashMap::new())),
        }
    }

    /// Set RPM/TPM/TPD limits for a specific provider/model.
    ///
    /// Synchronous so the kernel can seed the catalog's limits during boot,
    /// before the fallback chain that enforces them is constructed.
    pub fn set_limits(
        &self,
        provider: &str,
        model: &str,
        rpm_limit: Option<u64>,
        tpm_limit: Option<u64>,
        tpd_limit: Option<u64>,
    ) {
        let key = Self::key(provider, model);
        if let Some(rpm) = rpm_limit {
            self.rpm_limits
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key.clone(), rpm);
        }
        if let Some(tpm) = tpm_limit {
            self.tpm_limits
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key.clone(), tpm);
        }
        if let Some(tpd) = tpd_limit {
            self.tpd_limits
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key, tpd);
        }
    }

    /// Read a limit map entry, recovering from a poisoned lock.
    fn limit_of(map: &StdRwLock<HashMap<String, u64>>, key: &str) -> Option<u64> {
        map.read()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .copied()
    }

    /// Get token usage data for a specific provider/model.
    pub async fn get_token_usage(&self, provider: &str, model: &str) -> Option<TokenUsageData> {
        let key = Self::key(provider, model);
        let usage = self.token_usage.read().await;
        let rpm_limit = Self::limit_of(&self.rpm_limits, &key);
        let tpm_limit = Self::limit_of(&self.tpm_limits, &key);
        let tpd_limit = Self::limit_of(&self.tpd_limits, &key);

        usage.get(&key).map(|u| TokenUsageData {
            rpm_current: u.rpm_current,
            rpm_limit,
            tpm_current: u.tpm_current,
            tpm_limit,
            tpd_current: u.tpd_current,
            tpd_limit,
            rpm_window_start: u.rpm_window_start,
            tpm_window_start: u.tpm_window_start,
            tpd_window_start: u.tpd_window_start,
        })
    }

    /// Get all token usage data.
    pub async fn get_all_token_usage(&self) -> Vec<TokenUsageEntry> {
        let usage = self.token_usage.read().await;
        let rpm_limits = self.rpm_limits.read().unwrap_or_else(|e| e.into_inner());
        let tpm_limits = self.tpm_limits.read().unwrap_or_else(|e| e.into_inner());
        let tpd_limits = self.tpd_limits.read().unwrap_or_else(|e| e.into_inner());

        usage
            .iter()
            .map(|(key, u)| {
                let (provider, model) = key.split_once(':').unwrap_or((key, ""));
                TokenUsageEntry {
                    provider: provider.to_string(),
                    model: model.to_string(),
                    rpm_current: u.rpm_current,
                    rpm_limit: rpm_limits.get(key).copied(),
                    tpm_current: u.tpm_current,
                    tpm_limit: tpm_limits.get(key).copied(),
                    tpd_current: u.tpd_current,
                    tpd_limit: tpd_limits.get(key).copied(),
                    rpm_window_start: u.rpm_window_start,
                    tpm_window_start: u.tpm_window_start,
                    tpd_window_start: u.tpd_window_start,
                }
            })
            .collect()
    }

    /// Generate a unique key for provider/model combination.
    fn key(provider: &str, model: &str) -> String {
        format!("{}:{}", provider, model)
    }

    /// Update latency percentiles.
    fn update_latency_percentiles(health: &mut ProviderHealth, latency_ms: u64) {
        // Simple implementation: track p50, p95, p99
        // In production, use proper percentile calculation with reservoir sampling
        if health.latency_p50 == 0 {
            health.latency_p50 = latency_ms;
            health.latency_p95 = latency_ms;
            health.latency_p99 = latency_ms;
        } else {
            // Exponential moving average approximation
            const ALPHA: f64 = 0.1;
            health.latency_p50 =
                (health.latency_p50 as f64 * (1.0 - ALPHA) + latency_ms as f64 * ALPHA) as u64;
            health.latency_p95 =
                (health.latency_p95 as f64 * (1.0 - ALPHA) + latency_ms as f64 * ALPHA) as u64;
            health.latency_p99 =
                (health.latency_p99 as f64 * (1.0 - ALPHA) + latency_ms as f64 * ALPHA) as u64;
        }
    }

    /// Update circuit breaker state based on consecutive failures.
    fn update_circuit_state(health: &mut ProviderHealth) {
        if health.consecutive_failures >= 5 {
            health.circuit_state = CircuitState::Open;
        } else if health.consecutive_failures >= 3 {
            health.circuit_state = CircuitState::HalfOpen;
        } else if health.consecutive_successes >= 3 {
            health.circuit_state = CircuitState::Closed;
        }
    }
}

impl HealthTracker for InMemoryHealthTracker {
    async fn record_success(&self, provider: &str, model: &str, latency_ms: u64) {
        let key = Self::key(provider, model);
        let mut health = self.health.write().await;
        let now = Utc::now();

        let entry = health.entry(key).or_insert_with(|| ProviderHealth {
            provider: provider.to_string(),
            model: model.to_string(),
            success_rate: 0.0,
            error_rate: 0.0,
            latency_p50: 0,
            latency_p95: 0,
            latency_p99: 0,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_success: None,
            last_failure: None,
            total_requests: 0,
            circuit_state: CircuitState::Closed,
        });

        entry.total_requests += 1;
        entry.consecutive_successes += 1;
        entry.consecutive_failures = 0;
        entry.last_success = Some(now);
        entry.success_rate = entry.consecutive_successes as f64 / entry.total_requests as f64;
        entry.error_rate = entry.consecutive_failures as f64 / entry.total_requests as f64;

        Self::update_latency_percentiles(entry, latency_ms);
        Self::update_circuit_state(entry);
    }

    async fn record_failure(&self, provider: &str, model: &str, _error: &LlmError) {
        let key = Self::key(provider, model);
        let mut health = self.health.write().await;
        let now = Utc::now();

        let entry = health.entry(key).or_insert_with(|| ProviderHealth {
            provider: provider.to_string(),
            model: model.to_string(),
            success_rate: 0.0,
            error_rate: 0.0,
            latency_p50: 0,
            latency_p95: 0,
            latency_p99: 0,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_success: None,
            last_failure: None,
            total_requests: 0,
            circuit_state: CircuitState::Closed,
        });

        entry.total_requests += 1;
        entry.consecutive_failures += 1;
        entry.consecutive_successes = 0;
        entry.last_failure = Some(now);
        entry.success_rate = entry.consecutive_successes as f64 / entry.total_requests as f64;
        entry.error_rate = entry.consecutive_failures as f64 / entry.total_requests as f64;

        Self::update_circuit_state(entry);
    }

    async fn get_health(&self, provider: &str, model: &str) -> Option<ProviderHealth> {
        let key = Self::key(provider, model);
        let health = self.health.read().await;
        health.get(&key).cloned()
    }

    async fn get_all_health(&self) -> Vec<ProviderHealth> {
        let health = self.health.read().await;
        health.values().cloned().collect()
    }

    async fn check_rate_limit(
        &self,
        provider: &str,
        model: &str,
        estimated_tokens: u64,
    ) -> Result<(), RateLimitError> {
        let key = Self::key(provider, model);
        let now = Utc::now();

        // Get limits
        let rpm_limit = Self::limit_of(&self.rpm_limits, &key);
        let tpm_limit = Self::limit_of(&self.tpm_limits, &key);
        let tpd_limit = Self::limit_of(&self.tpd_limits, &key);

        // If no limits are set, allow the request
        if rpm_limit.is_none() && tpm_limit.is_none() && tpd_limit.is_none() {
            return Ok(());
        }

        // Get current usage
        let mut usage = self.token_usage.write().await;
        let entry = usage.entry(key.clone()).or_insert_with(|| TokenUsage {
            rpm_current: 0,
            rpm_window_start: now,
            tpm_current: 0,
            tpm_window_start: now,
            tpd_current: 0,
            tpd_window_start: now,
        });

        // Check RPM limit
        if let Some(rpm_limit) = rpm_limit {
            // Reset RPM window if more than 1 minute has passed
            if now.signed_duration_since(entry.rpm_window_start) > Duration::minutes(1) {
                entry.rpm_current = 0;
                entry.rpm_window_start = now;
            }

            if entry.rpm_current + 1 > rpm_limit {
                return Err(RateLimitError {
                    limit_type: RateLimitType::RpmExceeded,
                    retry_after_ms: 60_000, // 1 minute
                });
            }
        }

        // Check TPM limit
        if let Some(tpm_limit) = tpm_limit {
            // Reset TPM window if more than 1 minute has passed
            if now.signed_duration_since(entry.tpm_window_start) > Duration::minutes(1) {
                entry.tpm_current = 0;
                entry.tpm_window_start = now;
            }

            if entry.tpm_current + estimated_tokens > tpm_limit {
                return Err(RateLimitError {
                    limit_type: RateLimitType::TpmExceeded,
                    retry_after_ms: 60_000, // 1 minute
                });
            }
        }

        // Check TPD limit
        if let Some(tpd_limit) = tpd_limit {
            // Reset TPD window if more than 24 hours has passed
            if now.signed_duration_since(entry.tpd_window_start) > Duration::hours(24) {
                entry.tpd_current = 0;
                entry.tpd_window_start = now;
            }

            if entry.tpd_current + estimated_tokens > tpd_limit {
                return Err(RateLimitError {
                    limit_type: RateLimitType::TpdExceeded,
                    retry_after_ms: 86_400_000, // 24 hours
                });
            }
        }

        Ok(())
    }

    async fn record_token_usage(
        &self,
        provider: &str,
        model: &str,
        prompt_tokens: u64,
        completion_tokens: u64,
    ) {
        let key = Self::key(provider, model);
        let now = Utc::now();
        let total_tokens = prompt_tokens + completion_tokens;

        let mut usage = self.token_usage.write().await;
        let entry = usage.entry(key).or_insert_with(|| TokenUsage {
            rpm_current: 0,
            rpm_window_start: now,
            tpm_current: 0,
            tpm_window_start: now,
            tpd_current: 0,
            tpd_window_start: now,
        });

        // Reset RPM window if more than 1 minute has passed
        if now.signed_duration_since(entry.rpm_window_start) > Duration::minutes(1) {
            entry.rpm_current = 0;
            entry.rpm_window_start = now;
        }

        // Reset TPM window if more than 1 minute has passed
        if now.signed_duration_since(entry.tpm_window_start) > Duration::minutes(1) {
            entry.tpm_current = 0;
            entry.tpm_window_start = now;
        }

        // Reset TPD window if more than 24 hours has passed
        if now.signed_duration_since(entry.tpd_window_start) > Duration::hours(24) {
            entry.tpd_current = 0;
            entry.tpd_window_start = now;
        }

        entry.rpm_current += 1;
        entry.tpm_current += total_tokens;
        entry.tpd_current += total_tokens;
    }
}

impl Default for InMemoryHealthTracker {
    fn default() -> Self {
        Self::new(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_record_success_updates_metrics() {
        let tracker = InMemoryHealthTracker::new(100);
        tracker.record_success("nvidia", "deepseek/v4", 500).await;

        let health = tracker.get_health("nvidia", "deepseek/v4").await.unwrap();
        assert_eq!(health.provider, "nvidia");
        assert_eq!(health.model, "deepseek/v4");
        assert_eq!(health.total_requests, 1);
        assert_eq!(health.consecutive_successes, 1);
        assert_eq!(health.consecutive_failures, 0);
        assert_eq!(health.success_rate, 1.0);
        assert_eq!(health.error_rate, 0.0);
    }

    #[tokio::test]
    async fn test_record_failure_updates_metrics() {
        let tracker = InMemoryHealthTracker::new(100);
        let error = LlmError::RateLimited {
            retry_after_ms: 60000,
        };
        tracker
            .record_failure("nvidia", "deepseek/v4", &error)
            .await;

        let health = tracker.get_health("nvidia", "deepseek/v4").await.unwrap();
        assert_eq!(health.total_requests, 1);
        assert_eq!(health.consecutive_failures, 1);
        assert_eq!(health.consecutive_successes, 0);
        assert_eq!(health.success_rate, 0.0);
        assert_eq!(health.error_rate, 1.0);
    }

    #[tokio::test]
    async fn test_rolling_window_exact_size() {
        let tracker = InMemoryHealthTracker::new(10);
        for i in 0..15 {
            tracker
                .record_success("nvidia", "deepseek/v4", 500 + i)
                .await;
        }

        let health = tracker.get_health("nvidia", "deepseek/v4").await.unwrap();
        assert_eq!(health.total_requests, 15);
    }

    #[tokio::test]
    async fn test_latency_percentiles_accuracy() {
        let tracker = InMemoryHealthTracker::new(100);
        tracker.record_success("nvidia", "deepseek/v4", 500).await;
        tracker.record_success("nvidia", "deepseek/v4", 1000).await;
        tracker.record_success("nvidia", "deepseek/v4", 1500).await;

        let health = tracker.get_health("nvidia", "deepseek/v4").await.unwrap();
        assert!(health.latency_p50 > 0);
        assert!(health.latency_p95 > 0);
        assert!(health.latency_p99 > 0);
    }

    #[tokio::test]
    async fn test_circuit_state_transitions() {
        let tracker = InMemoryHealthTracker::new(100);
        let error = LlmError::RateLimited {
            retry_after_ms: 60000,
        };

        // 3 failures -> HalfOpen
        for _ in 0..3 {
            tracker
                .record_failure("nvidia", "deepseek/v4", &error)
                .await;
        }
        let health = tracker.get_health("nvidia", "deepseek/v4").await.unwrap();
        assert_eq!(health.circuit_state, CircuitState::HalfOpen);

        // 5 failures -> Open
        for _ in 3..5 {
            tracker
                .record_failure("nvidia", "deepseek/v4", &error)
                .await;
        }
        let health = tracker.get_health("nvidia", "deepseek/v4").await.unwrap();
        assert_eq!(health.circuit_state, CircuitState::Open);

        // 3 successes -> Closed
        for _ in 0..3 {
            tracker.record_success("nvidia", "deepseek/v4", 500).await;
        }
        let health = tracker.get_health("nvidia", "deepseek/v4").await.unwrap();
        assert_eq!(health.circuit_state, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_get_all_health() {
        let tracker = InMemoryHealthTracker::new(100);
        tracker.record_success("nvidia", "deepseek/v4", 500).await;
        tracker.record_success("openrouter", "llama-3", 300).await;

        let all_health = tracker.get_all_health().await;
        assert_eq!(all_health.len(), 2);
    }
}
