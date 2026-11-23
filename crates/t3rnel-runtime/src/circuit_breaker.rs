//! Circuit breaker for LLM driver resilience.
//!
//! Patterned on ruflo `BaseProvider` circuit breaker (3-state:
//! closed → open → half-open → closed).
//!
//! When a driver fails `failure_threshold` times within the window,
//! the breaker opens and all requests fast-fail with `LlmError::CircuitOpen`
//! for `reset_timeout_ms`. After the timeout, one probe request is allowed
//! (half-open). If it succeeds, the breaker closes; if it fails, it re-opens.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation — requests pass through.
    Closed,
    /// Failure threshold exceeded — requests fast-fail.
    Open,
    /// Probe period — one request allowed to test recovery.
    HalfOpen,
}

/// Configuration for a circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening.
    pub failure_threshold: u32,
    /// How long to stay open before allowing a probe (half-open).
    pub reset_timeout_ms: u64,
    /// How many successes in half-open needed to close.
    pub success_threshold_half_open: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout_ms: 30_000,
            success_threshold_half_open: 2,
        }
    }
}

/// Per-provider circuit breaker.
#[derive(Debug)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Mutex<CircuitBreakerInner>,
    provider: String,
    model: String,
}

#[derive(Debug)]
struct CircuitBreakerInner {
    state: CircuitState,
    /// Consecutive failures in closed or half-open state.
    consecutive_failures: u32,
    /// Consecutive successes in half-open state.
    consecutive_successes: u32,
    /// When the breaker was last opened (for reset timeout).
    opened_at: Option<Instant>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker for a provider/model pair.
    pub fn new(
        provider: impl Into<String>,
        model: impl Into<String>,
        config: CircuitBreakerConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            state: Mutex::new(CircuitBreakerInner {
                state: CircuitState::Closed,
                consecutive_failures: 0,
                consecutive_successes: 0,
                opened_at: None,
            }),
            provider: provider.into(),
            model: model.into(),
        })
    }

    /// Create with default config.
    pub fn default_config(provider: impl Into<String>, model: impl Into<String>) -> Arc<Self> {
        Self::new(provider, model, CircuitBreakerConfig::default())
    }

    /// Current state (for metrics/health checks).
    pub fn current_state(&self) -> CircuitState {
        let inner = self.state.lock().unwrap();
        inner.state
    }

    /// Provider name.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Model id.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Check if a request should be allowed through.
    /// Returns `Ok(())` if allowed, `Err(LlmError::CircuitOpen)` if not.
    pub fn allow(&self) -> Result<(), crate::llm_driver::LlmError> {
        let mut inner = self.state.lock().unwrap();

        match inner.state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                // Check if reset timeout has elapsed
                if let Some(opened_at) = inner.opened_at {
                    let elapsed = opened_at.elapsed();
                    let reset = Duration::from_millis(self.config.reset_timeout_ms);
                    if elapsed >= reset {
                        tracing::info!(
                            provider = %self.provider,
                            model = %self.model,
                            "Circuit breaker entering half-open after {}ms",
                            self.config.reset_timeout_ms
                        );
                        inner.state = CircuitState::HalfOpen;
                        inner.consecutive_failures = 0;
                        inner.consecutive_successes = 0;
                        return Ok(());
                    }
                }
                let retry_after = self.config.reset_timeout_ms;
                tracing::warn!(
                    provider = %self.provider,
                    model = %self.model,
                    "Circuit breaker open — request rejected"
                );
                Err(crate::llm_driver::LlmError::CircuitOpen {
                    provider: self.provider.clone(),
                    model: self.model.clone(),
                    retry_after_ms: retry_after,
                })
            }
            CircuitState::HalfOpen => Ok(()),
        }
    }

    /// Record a successful request.
    pub fn record_success(&self) {
        let mut inner = self.state.lock().unwrap();
        match inner.state {
            CircuitState::Closed => {
                inner.consecutive_failures = 0;
            }
            CircuitState::HalfOpen => {
                inner.consecutive_successes += 1;
                if inner.consecutive_successes >= self.config.success_threshold_half_open {
                    tracing::info!(
                        provider = %self.provider,
                        model = %self.model,
                        "Circuit breaker closed after {} consecutive successes in half-open",
                        inner.consecutive_successes
                    );
                    inner.state = CircuitState::Closed;
                    inner.consecutive_failures = 0;
                    inner.consecutive_successes = 0;
                    inner.opened_at = None;
                }
            }
            CircuitState::Open => {
                // Should not happen, but recover gracefully
                inner.state = CircuitState::Closed;
                inner.consecutive_failures = 0;
                inner.opened_at = None;
            }
        }
    }

    /// Record a failed request.
    pub fn record_failure(&self) {
        let mut inner = self.state.lock().unwrap();
        match inner.state {
            CircuitState::Closed => {
                inner.consecutive_failures += 1;
                if inner.consecutive_failures >= self.config.failure_threshold {
                    tracing::warn!(
                        provider = %self.provider,
                        model = %self.model,
                        failures = inner.consecutive_failures,
                        threshold = self.config.failure_threshold,
                        "Circuit breaker opened"
                    );
                    inner.state = CircuitState::Open;
                    inner.opened_at = Some(Instant::now());
                }
            }
            CircuitState::HalfOpen => {
                tracing::warn!(
                    provider = %self.provider,
                    model = %self.model,
                    "Circuit breaker re-opened after failure in half-open"
                );
                inner.state = CircuitState::Open;
                inner.opened_at = Some(Instant::now());
                inner.consecutive_successes = 0;
            }
            CircuitState::Open => {
                // Already open, nothing to do
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_closed() {
        let cb = CircuitBreaker::default_config("test", "model-1");
        assert_eq!(cb.current_state(), CircuitState::Closed);
        assert!(cb.allow().is_ok());
    }

    #[test]
    fn opens_after_threshold_failures() {
        let cb = CircuitBreaker::new(
            "test",
            "model-1",
            CircuitBreakerConfig {
                failure_threshold: 3,
                reset_timeout_ms: 100,
                success_threshold_half_open: 1,
            },
        );

        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Closed);

        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);
        assert!(cb.allow().is_err());
    }

    #[test]
    fn half_open_after_timeout() {
        let cb = CircuitBreaker::new(
            "test",
            "model-1",
            CircuitBreakerConfig {
                failure_threshold: 1,
                reset_timeout_ms: 50,
                success_threshold_half_open: 1,
            },
        );

        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);
        assert!(cb.allow().is_err());

        std::thread::sleep(Duration::from_millis(60));
        assert!(cb.allow().is_ok());
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
    }

    #[test]
    fn closes_after_success_in_half_open() {
        let cb = CircuitBreaker::new(
            "test",
            "model-1",
            CircuitBreakerConfig {
                failure_threshold: 1,
                reset_timeout_ms: 1,
                success_threshold_half_open: 1,
            },
        );

        cb.record_failure();
        std::thread::sleep(Duration::from_millis(10));
        assert!(cb.allow().is_ok());
        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    #[test]
    fn reopens_after_failure_in_half_open() {
        let cb = CircuitBreaker::new(
            "test",
            "model-1",
            CircuitBreakerConfig {
                failure_threshold: 1,
                reset_timeout_ms: 1,
                success_threshold_half_open: 2,
            },
        );

        cb.record_failure();
        std::thread::sleep(Duration::from_millis(10));
        assert!(cb.allow().is_ok());
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);
    }

    #[test]
    fn resets_failure_count_on_success() {
        let cb = CircuitBreaker::new(
            "test",
            "model-1",
            CircuitBreakerConfig {
                failure_threshold: 3,
                reset_timeout_ms: 1000,
                success_threshold_half_open: 1,
            },
        );

        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }
}
