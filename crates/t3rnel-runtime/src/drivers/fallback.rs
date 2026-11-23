//! Fallback driver — tries multiple LLM drivers in sequence.
//!
//! If the primary driver fails with a non-retryable error, the fallback driver
//! moves to the next driver in the chain.
//!
//! Each driver slot has an independent 3-state circuit breaker
//! (`closed` / `open` / `half-open`) to prevent hammering a dead backend.

use crate::drivers::health_tracker::{HealthTracker, InMemoryHealthTracker};
use crate::llm_driver::{CompletionRequest, CompletionResponse, LlmDriver, LlmError, StreamEvent};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use t3rnel_types::message::MessageContent;
use tracing::warn;

const DEFAULT_DRIVER_ATTEMPT_TIMEOUT_SECS: u64 = 25;
const DEFAULT_FALLBACK_CHAIN_TIMEOUT_SECS: u64 = 75;

fn timeout_from_env(name: &str, default_secs: u64) -> Duration {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(default_secs))
}

/// Circuit-breaker state for a single driver slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BreakerState {
    /// Normal operation; failures are counted.
    Closed,
    /// Too many failures; requests are rejected fast.
    Open,
    /// After timeout, one probe request is allowed to test recovery.
    HalfOpen,
}

/// Per-driver circuit breaker.
///
/// - `failure_threshold`: consecutive failures before opening.
/// - `open_duration`: how long to stay open before becoming half-open.
/// - `half_open_max_requests`: how many probe requests to allow in half-open
///   (set to 1 for a single probe).
#[derive(Debug)]
struct CircuitBreaker {
    state: BreakerState,
    consecutive_failures: u32,
    last_failure_time: Option<Instant>,
    failure_threshold: u32,
    open_duration: Duration,
    half_open_max_requests: u32,
    half_open_requests: u32,
    provider: String,
    model: String,
}

impl CircuitBreaker {
    fn new(provider: &str, model: &str) -> Self {
        Self {
            state: BreakerState::Closed,
            consecutive_failures: 0,
            last_failure_time: None,
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
            half_open_max_requests: 1,
            half_open_requests: 0,
            provider: provider.to_string(),
            model: model.to_string(),
        }
    }

    /// Returns `Ok(())` if the request may proceed, or `Err(LlmError::CircuitOpen)`
    /// if the breaker is open and the timeout has not yet elapsed.
    fn allow(&mut self) -> Result<(), LlmError> {
        match self.state {
            BreakerState::Closed => Ok(()),
            BreakerState::Open => {
                if let Some(last) = self.last_failure_time {
                    if Instant::now().duration_since(last) >= self.open_duration {
                        self.state = BreakerState::HalfOpen;
                        self.half_open_requests = 0;
                        return self.allow();
                    }
                }
                Err(LlmError::CircuitOpen {
                    provider: self.provider.clone(),
                    model: self.model.clone(),
                    retry_after_ms: self.open_duration.as_millis() as u64,
                })
            }
            BreakerState::HalfOpen => {
                if self.half_open_requests < self.half_open_max_requests {
                    self.half_open_requests += 1;
                    Ok(())
                } else {
                    Err(LlmError::CircuitOpen {
                        provider: self.provider.clone(),
                        model: self.model.clone(),
                        retry_after_ms: self.open_duration.as_millis() as u64,
                    })
                }
            }
        }
    }

    /// Call after a successful request to reset failure count and close the breaker.
    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.last_failure_time = None;
        self.state = BreakerState::Closed;
        self.half_open_requests = 0;
    }

    /// Call after a failed request to increment failure count and possibly open the breaker.
    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.last_failure_time = Some(Instant::now());
        if self.consecutive_failures >= self.failure_threshold {
            self.state = BreakerState::Open;
        }
    }
}

/// Characters per token used when estimating prompt size before a request.
///
/// English text averages ~4 chars/token; 3 is deliberately pessimistic so the
/// pre-flight check errs toward skipping a slot rather than overshooting a
/// provider's TPM budget and eating an HTTP 413.
const CHARS_PER_TOKEN_ESTIMATE: usize = 3;

/// Estimate the input tokens a request will consume, including the system prompt
/// and tool schemas — both are billed and both are large enough to blow a small
/// free-tier TPM budget on their own.
pub fn estimate_request_tokens(request: &CompletionRequest) -> u64 {
    use t3rnel_types::message::ContentBlock;

    let message_chars: usize = request
        .messages
        .iter()
        .map(|m| match &m.content {
            MessageContent::Text(text) => text.len(),
            MessageContent::Blocks(blocks) => blocks
                .iter()
                .map(|b| match b {
                    ContentBlock::Text { text, .. } => text.len(),
                    ContentBlock::ToolResult { content, .. } => content.len(),
                    ContentBlock::Thinking { thinking, .. } => thinking.len(),
                    ContentBlock::ToolUse { name, input, .. } => {
                        name.len() + input.to_string().len()
                    }
                    // Images are not chars; charge a flat nominal cost so a
                    // vision request is not estimated as free.
                    ContentBlock::Image { .. } => 1_000 * CHARS_PER_TOKEN_ESTIMATE,
                    // Opaque provider blob — estimate by payload size.
                    ContentBlock::RedactedThinking { data } => data.len(),
                    ContentBlock::Unknown => 0,
                })
                .sum::<usize>(),
            MessageContent::Unknown(v) => v.to_string().len(),
        })
        .sum();

    let system_chars = request.system.as_ref().map_or(0, |s| s.len());
    let tool_chars: usize = request
        .tools
        .iter()
        .map(|t| t.name.len() + t.description.len() + t.input_schema.to_string().len())
        .sum();

    ((message_chars + system_chars + tool_chars) / CHARS_PER_TOKEN_ESTIMATE) as u64
}

/// One slot in the fallback chain: the driver, the provider that serves it, and
/// the model name to request.
///
/// The provider is carried explicitly rather than parsed out of `model`. Model
/// IDs are not reliably `provider/model` — `llama-3.1-8b-instant` has no prefix,
/// `openai/gpt-oss-120b` is served by Groq, and `@cf/meta/...` is Cloudflare — so
/// splitting on `/` produced rate-limit keys (`unknown`, `openai`, `@cf`) that
/// never matched the keys the catalog registers limits under, silently disabling
/// every TPM/TPD check.
#[derive(Clone)]
pub struct FallbackEntry {
    pub driver: Arc<dyn LlmDriver>,
    pub provider: String,
    pub model: String,
}

impl FallbackEntry {
    /// Create an entry with an explicit provider.
    pub fn new(
        driver: Arc<dyn LlmDriver>,
        provider: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        Self {
            driver,
            provider: provider.into(),
            model: model.into(),
        }
    }
}

/// A driver that wraps multiple LLM drivers and tries each in order.
///
/// On failure (including rate-limit and overload), moves to the next driver.
/// Only returns an error when ALL drivers in the chain are exhausted.
/// Each driver is paired with the provider and model name it should use.
pub struct FallbackDriver {
    drivers: Vec<FallbackEntry>,
    breakers: Mutex<Vec<CircuitBreaker>>,
    attempt_timeout: Duration,
    chain_timeout: Duration,
    health_tracker: Option<Arc<InMemoryHealthTracker>>,
}

impl FallbackDriver {
    /// Create a new fallback driver from an ordered chain of drivers.
    ///
    /// The first entry is the primary; subsequent are fallbacks.
    pub fn new(drivers: Vec<Arc<dyn LlmDriver>>) -> Self {
        Self::with_entries_and_health_tracker(
            drivers
                .into_iter()
                .map(|d| FallbackEntry::new(d, "", ""))
                .collect(),
            None,
        )
    }

    /// Create a new fallback driver with explicit model names for each driver.
    ///
    /// Prefer [`Self::with_entries_and_health_tracker`], which also carries the
    /// provider so rate limiting can key on it.
    pub fn with_models(drivers: Vec<(Arc<dyn LlmDriver>, String)>) -> Self {
        Self::with_entries_and_health_tracker(
            drivers
                .into_iter()
                .map(|(d, model)| FallbackEntry::new(d, "", model))
                .collect(),
            None,
        )
    }

    /// Create a new fallback driver with explicit model names and a health tracker for rate limiting.
    pub fn with_models_and_health_tracker(
        drivers: Vec<(Arc<dyn LlmDriver>, String)>,
        health_tracker: Option<Arc<InMemoryHealthTracker>>,
    ) -> Self {
        Self::with_entries_and_health_tracker(
            drivers
                .into_iter()
                .map(|(d, model)| FallbackEntry::new(d, "", model))
                .collect(),
            health_tracker,
        )
    }

    /// Create a new fallback driver from provider-tagged entries plus an optional
    /// health tracker used for pre-flight TPM/TPD enforcement.
    pub fn with_entries_and_health_tracker(
        drivers: Vec<FallbackEntry>,
        health_tracker: Option<Arc<InMemoryHealthTracker>>,
    ) -> Self {
        let breakers: Vec<CircuitBreaker> = drivers
            .iter()
            .map(|e| {
                let provider = if e.provider.is_empty() {
                    "fallback"
                } else {
                    e.provider.as_str()
                };
                CircuitBreaker::new(provider, e.model.as_str())
            })
            .collect();
        Self {
            drivers,
            breakers: Mutex::new(breakers),
            attempt_timeout: timeout_from_env(
                "T3RNEL_LLM_PROVIDER_TIMEOUT_SECS",
                DEFAULT_DRIVER_ATTEMPT_TIMEOUT_SECS,
            ),
            chain_timeout: timeout_from_env(
                "T3RNEL_LLM_FALLBACK_TIMEOUT_SECS",
                DEFAULT_FALLBACK_CHAIN_TIMEOUT_SECS,
            ),
            health_tracker,
        }
    }

    async fn complete_with_fallbacks(
        &self,
        request: CompletionRequest,
    ) -> Result<CompletionResponse, LlmError> {
        let mut last_error = None;

        for (i, entry) in self.drivers.iter().enumerate() {
            let driver = &entry.driver;
            let model_name = &entry.model;
            {
                let mut breakers = self.breakers.lock().unwrap();
                if let Some(breaker) = breakers.get_mut(i) {
                    if let Err(e) = breaker.allow() {
                        warn!(
                            driver_index = i,
                            model = %model_name,
                            error = %e,
                            "Circuit breaker open, skipping driver"
                        );
                        last_error = Some(e);
                        continue;
                    }
                }
            }

            // Check rate limits if health tracker is available.
            //
            // The estimate must NOT be clamped to a context-window figure: the whole
            // point is to detect that a request is too large for this slot's TPM
            // budget and skip to the next one. Clamping made a 13k-token request look
            // like 2.5k, so the check passed and the provider returned HTTP 413.
            if let Some(ref tracker) = self.health_tracker {
                let estimated_tokens =
                    estimate_request_tokens(&request) + request.max_tokens as u64;

                if let Err(e) = tracker
                    .as_ref()
                    .check_rate_limit(&entry.provider, model_name, estimated_tokens)
                    .await
                {
                    warn!(
                        driver_index = i,
                        provider = %entry.provider,
                        model = %model_name,
                        estimated_tokens,
                        error = ?e,
                        "Rate limit would be exceeded, trying next fallback"
                    );
                    last_error = Some(LlmError::RateLimited {
                        retry_after_ms: e.retry_after_ms,
                    });
                    continue;
                }
            }

            let mut req = request.clone();
            if !model_name.is_empty() {
                req.model = model_name.clone();
            }

            match tokio::time::timeout(self.attempt_timeout, driver.complete(req)).await {
                Ok(Ok(response)) => {
                    {
                        let mut breakers = self.breakers.lock().unwrap();
                        if let Some(breaker) = breakers.get_mut(i) {
                            breaker.record_success();
                        }
                    }

                    // Record actual token usage against the same key the
                    // pre-flight check reads, so the window reflects reality.
                    if let Some(ref tracker) = self.health_tracker {
                        let input_tokens = response.usage.input_tokens;
                        let output_tokens = response.usage.output_tokens;
                        tracker
                            .as_ref()
                            .record_token_usage(
                                &entry.provider,
                                model_name,
                                input_tokens,
                                output_tokens,
                            )
                            .await;
                    }

                    return Ok(response);
                }
                Ok(Err(e @ LlmError::RateLimited { .. }))
                | Ok(Err(e @ LlmError::Overloaded { .. }))
                | Ok(Err(e @ LlmError::CircuitOpen { .. })) => {
                    warn!(
                        driver_index = i,
                        model = %model_name,
                        error = %e,
                        "Driver rate-limited/overloaded/circuit-open, trying next fallback"
                    );
                    last_error = Some(e);
                }
                Ok(Err(e)) => {
                    warn!(
                        driver_index = i,
                        model = %model_name,
                        error = %e,
                        "Fallback driver failed, trying next"
                    );
                    let mut breakers = self.breakers.lock().unwrap();
                    if let Some(breaker) = breakers.get_mut(i) {
                        breaker.record_failure();
                    }
                    last_error = Some(e);
                }
                Err(_) => {
                    let e = LlmError::Http(format!(
                        "LLM provider request timed out after {}s",
                        self.attempt_timeout.as_secs()
                    ));
                    warn!(
                        driver_index = i,
                        model = %model_name,
                        error = %e,
                        "Fallback driver attempt timed out, trying next"
                    );
                    let mut breakers = self.breakers.lock().unwrap();
                    if let Some(breaker) = breakers.get_mut(i) {
                        breaker.record_failure();
                    }
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| LlmError::Api {
            status: 0,
            message: "No drivers configured in fallback chain".to_string(),
        }))
    }

    async fn stream_with_fallbacks(
        &self,
        request: CompletionRequest,
        tx: tokio::sync::mpsc::Sender<StreamEvent>,
    ) -> Result<CompletionResponse, LlmError> {
        let mut last_error = None;

        for (i, entry) in self.drivers.iter().enumerate() {
            let driver = &entry.driver;
            let model_name = &entry.model;
            {
                let mut breakers = self.breakers.lock().unwrap();
                if let Some(breaker) = breakers.get_mut(i) {
                    if let Err(e) = breaker.allow() {
                        warn!(
                            driver_index = i,
                            model = %model_name,
                            error = %e,
                            "Circuit breaker open (stream), skipping driver"
                        );
                        last_error = Some(e);
                        continue;
                    }
                }
            }

            let mut req = request.clone();
            if !model_name.is_empty() {
                req.model = model_name.clone();
            }

            match tokio::time::timeout(self.attempt_timeout, driver.stream(req, tx.clone())).await {
                Ok(Ok(response)) => {
                    let mut breakers = self.breakers.lock().unwrap();
                    if let Some(breaker) = breakers.get_mut(i) {
                        breaker.record_success();
                    }
                    return Ok(response);
                }
                Ok(Err(e @ LlmError::RateLimited { .. }))
                | Ok(Err(e @ LlmError::Overloaded { .. }))
                | Ok(Err(e @ LlmError::CircuitOpen { .. })) => {
                    warn!(
                        driver_index = i,
                        model = %model_name,
                        error = %e,
                        "Driver rate-limited/overloaded/circuit-open (stream), trying next fallback"
                    );
                    last_error = Some(e);
                }
                Ok(Err(e)) => {
                    warn!(
                        driver_index = i,
                        model = %model_name,
                        error = %e,
                        "Fallback driver (stream) failed, trying next"
                    );
                    let mut breakers = self.breakers.lock().unwrap();
                    if let Some(breaker) = breakers.get_mut(i) {
                        breaker.record_failure();
                    }
                    last_error = Some(e);
                }
                Err(_) => {
                    let e = LlmError::Http(format!(
                        "LLM provider stream timed out after {}s",
                        self.attempt_timeout.as_secs()
                    ));
                    warn!(
                        driver_index = i,
                        model = %model_name,
                        error = %e,
                        "Fallback driver stream attempt timed out, trying next"
                    );
                    let mut breakers = self.breakers.lock().unwrap();
                    if let Some(breaker) = breakers.get_mut(i) {
                        breaker.record_failure();
                    }
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| LlmError::Api {
            status: 0,
            message: "No drivers configured in fallback chain".to_string(),
        }))
    }
}

#[async_trait]
impl LlmDriver for FallbackDriver {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        match tokio::time::timeout(self.chain_timeout, self.complete_with_fallbacks(request)).await
        {
            Ok(result) => result,
            Err(_) => Err(LlmError::Http(format!(
                "LLM fallback chain timed out after {}s",
                self.chain_timeout.as_secs()
            ))),
        }
    }

    async fn stream(
        &self,
        request: CompletionRequest,
        tx: tokio::sync::mpsc::Sender<StreamEvent>,
    ) -> Result<CompletionResponse, LlmError> {
        match tokio::time::timeout(self.chain_timeout, self.stream_with_fallbacks(request, tx))
            .await
        {
            Ok(result) => result,
            Err(_) => Err(LlmError::Http(format!(
                "LLM fallback chain timed out after {}s",
                self.chain_timeout.as_secs()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm_driver::CompletionResponse;
    use t3rnel_types::message::{ContentBlock, Message, Role, StopReason, TokenUsage};

    fn sized_request(prompt_chars: usize) -> CompletionRequest {
        CompletionRequest {
            model: "m".into(),
            messages: vec![Message {
                role: Role::User,
                content: MessageContent::Text("x".repeat(prompt_chars)),
                ..Default::default()
            }],
            tools: vec![],
            max_tokens: 1024,
            temperature: 0.0,
            system: None,
            thinking: None,
            reasoning_effort: None,
        }
    }

    /// The estimate must scale with the real prompt. It was previously clamped
    /// with `.min(2500)`, so a 13k-token request was checked as ~2.5k, passed the
    /// TPM gate, and the provider answered with HTTP 413.
    #[test]
    fn token_estimate_is_not_clamped() {
        let small = estimate_request_tokens(&sized_request(3_000));
        let large = estimate_request_tokens(&sized_request(60_000));
        assert!(small < 1_500, "small estimate was {small}");
        assert!(
            large > 15_000,
            "large prompt must not be clamped, estimate was {large}"
        );
        assert!(large > small * 10);
    }

    /// The system prompt and tool schemas are billed too, and are big enough to
    /// blow a small free-tier budget on their own.
    #[test]
    fn token_estimate_includes_system_prompt_and_tools() {
        let mut req = sized_request(100);
        let baseline = estimate_request_tokens(&req);
        req.system = Some("s".repeat(9_000));
        let with_system = estimate_request_tokens(&req);
        assert!(
            with_system >= baseline + 2_900,
            "system prompt ignored: {baseline} -> {with_system}"
        );
    }

    struct FailDriver;

    #[async_trait]
    impl LlmDriver for FailDriver {
        async fn complete(&self, _req: CompletionRequest) -> Result<CompletionResponse, LlmError> {
            Err(LlmError::Api {
                status: 500,
                message: "Internal error".to_string(),
            })
        }
    }

    struct OkDriver;

    #[async_trait]
    impl LlmDriver for OkDriver {
        async fn complete(&self, _req: CompletionRequest) -> Result<CompletionResponse, LlmError> {
            Ok(CompletionResponse {
                content: vec![ContentBlock::Text {
                    text: "OK".to_string(),
                    provider_metadata: None,
                }],
                stop_reason: StopReason::EndTurn,
                tool_calls: vec![],
                usage: TokenUsage {
                    input_tokens: 10,
                    output_tokens: 5,
                },
            })
        }
    }

    fn test_request() -> CompletionRequest {
        CompletionRequest {
            model: "test".to_string(),
            messages: vec![],
            tools: vec![],
            max_tokens: 100,
            temperature: 0.0,
            system: None,
            thinking: None,
            reasoning_effort: None,
        }
    }

    #[tokio::test]
    async fn test_fallback_primary_succeeds() {
        let driver = FallbackDriver::new(vec![
            Arc::new(OkDriver) as Arc<dyn LlmDriver>,
            Arc::new(FailDriver) as Arc<dyn LlmDriver>,
        ]);
        let result = driver.complete(test_request()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().text(), "OK");
    }

    #[tokio::test]
    async fn test_fallback_primary_fails_secondary_succeeds() {
        let driver = FallbackDriver::new(vec![
            Arc::new(FailDriver) as Arc<dyn LlmDriver>,
            Arc::new(OkDriver) as Arc<dyn LlmDriver>,
        ]);
        let result = driver.complete(test_request()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fallback_all_fail() {
        let driver = FallbackDriver::new(vec![
            Arc::new(FailDriver) as Arc<dyn LlmDriver>,
            Arc::new(FailDriver) as Arc<dyn LlmDriver>,
        ]);
        let result = driver.complete(test_request()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rate_limit_falls_through() {
        struct RateLimitDriver;

        #[async_trait]
        impl LlmDriver for RateLimitDriver {
            async fn complete(
                &self,
                _req: CompletionRequest,
            ) -> Result<CompletionResponse, LlmError> {
                Err(LlmError::RateLimited {
                    retry_after_ms: 5000,
                })
            }
        }

        let driver = FallbackDriver::new(vec![
            Arc::new(RateLimitDriver) as Arc<dyn LlmDriver>,
            Arc::new(OkDriver) as Arc<dyn LlmDriver>,
        ]);
        let result = driver.complete(test_request()).await;
        // Rate limit should fall through to the OkDriver fallback
        assert!(result.is_ok());
        assert_eq!(result.unwrap().text(), "OK");
    }

    #[tokio::test]
    async fn test_rate_limit_all_fail() {
        struct RateLimitDriver;

        #[async_trait]
        impl LlmDriver for RateLimitDriver {
            async fn complete(
                &self,
                _req: CompletionRequest,
            ) -> Result<CompletionResponse, LlmError> {
                Err(LlmError::RateLimited {
                    retry_after_ms: 5000,
                })
            }
        }

        let driver = FallbackDriver::new(vec![
            Arc::new(RateLimitDriver) as Arc<dyn LlmDriver>,
            Arc::new(RateLimitDriver) as Arc<dyn LlmDriver>,
        ]);
        let result = driver.complete(test_request()).await;
        // All drivers rate-limited — error should bubble up
        assert!(matches!(result, Err(LlmError::RateLimited { .. })));
    }

    /// Regression test for #1003: when the primary driver returns a network /
    /// connection error (e.g. LM Studio shut down → reqwest connection refused),
    /// the FallbackDriver MUST escalate to the next driver in the chain instead
    /// of bubbling the error up to the agent loop (which would then retry the
    /// dead primary forever).
    #[tokio::test]
    async fn test_network_error_falls_through_to_secondary() {
        struct NetworkFailDriver;

        #[async_trait]
        impl LlmDriver for NetworkFailDriver {
            async fn complete(
                &self,
                _req: CompletionRequest,
            ) -> Result<CompletionResponse, LlmError> {
                // Simulates `reqwest::Error` from a connection refused — exactly
                // what an offline LM Studio looks like in production.
                Err(LlmError::Http(
                    "error sending request: connection refused (os error 10061)".to_string(),
                ))
            }
        }

        let driver = FallbackDriver::new(vec![
            Arc::new(NetworkFailDriver) as Arc<dyn LlmDriver>,
            Arc::new(OkDriver) as Arc<dyn LlmDriver>,
        ]);
        let result = driver.complete(test_request()).await;
        assert!(
            result.is_ok(),
            "FallbackDriver should escalate network errors to the next driver"
        );
        assert_eq!(result.unwrap().text(), "OK");
    }

    /// Same as above but for streaming. The streaming path is what the agent
    /// loop hits in practice for LM Studio etc., so it must also fall through.
    #[tokio::test]
    async fn test_network_error_falls_through_streaming() {
        struct NetworkFailDriver;

        #[async_trait]
        impl LlmDriver for NetworkFailDriver {
            async fn complete(
                &self,
                _req: CompletionRequest,
            ) -> Result<CompletionResponse, LlmError> {
                Err(LlmError::Http("connection refused".to_string()))
            }

            async fn stream(
                &self,
                _req: CompletionRequest,
                _tx: tokio::sync::mpsc::Sender<StreamEvent>,
            ) -> Result<CompletionResponse, LlmError> {
                Err(LlmError::Http("connection refused".to_string()))
            }
        }

        let driver = FallbackDriver::new(vec![
            Arc::new(NetworkFailDriver) as Arc<dyn LlmDriver>,
            Arc::new(OkDriver) as Arc<dyn LlmDriver>,
        ]);
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let result = driver.stream(test_request(), tx).await;
        assert!(
            result.is_ok(),
            "FallbackDriver::stream should also escalate network errors"
        );
    }

    // ── Circuit breaker tests ──────────────────────────────────────────────

    #[test]
    fn test_circuit_breaker_closes_after_success() {
        let mut breaker = CircuitBreaker::new("test", "model");
        assert_eq!(breaker.state, BreakerState::Closed);
        breaker.record_success();
        assert_eq!(breaker.state, BreakerState::Closed);
        assert_eq!(breaker.consecutive_failures, 0);
    }

    #[test]
    fn test_circuit_breaker_opens_after_threshold() {
        let mut breaker = CircuitBreaker::new("test", "model");
        let threshold = breaker.failure_threshold;
        for _ in 0..threshold {
            assert_eq!(breaker.state, BreakerState::Closed);
            breaker.record_failure();
        }
        assert_eq!(breaker.state, BreakerState::Open);
    }

    #[test]
    fn test_circuit_breaker_blocks_when_open() {
        let mut breaker = CircuitBreaker::new("test", "model");
        breaker.state = BreakerState::Open;
        breaker.last_failure_time = Some(Instant::now());
        let result = breaker.allow();
        assert!(matches!(result, Err(LlmError::CircuitOpen { .. })));
    }

    #[test]
    fn test_circuit_breaker_half_open_after_timeout() {
        let mut breaker = CircuitBreaker::new("test", "model");
        breaker.state = BreakerState::Open;
        breaker.last_failure_time = Some(Instant::now() - Duration::from_secs(60));
        assert!(breaker.allow().is_ok());
        assert_eq!(breaker.state, BreakerState::HalfOpen);
        assert_eq!(breaker.half_open_requests, 1);
    }

    #[test]
    fn test_circuit_breaker_half_open_blocks_excess_probes() {
        let mut breaker = CircuitBreaker::new("test", "model");
        breaker.state = BreakerState::HalfOpen;
        breaker.half_open_requests = breaker.half_open_max_requests;
        let result = breaker.allow();
        assert!(matches!(result, Err(LlmError::CircuitOpen { .. })));
    }

    #[test]
    fn test_circuit_breaker_closes_from_half_open_on_success() {
        let mut breaker = CircuitBreaker::new("test", "model");
        breaker.state = BreakerState::HalfOpen;
        breaker.half_open_requests = 1;
        breaker.record_success();
        assert_eq!(breaker.state, BreakerState::Closed);
        assert_eq!(breaker.half_open_requests, 0);
    }

    #[tokio::test]
    async fn test_fallback_skips_open_breaker() {
        // Primary has an open breaker, secondary succeeds.
        let driver = FallbackDriver::new(vec![
            Arc::new(FailDriver) as Arc<dyn LlmDriver>,
            Arc::new(OkDriver) as Arc<dyn LlmDriver>,
        ]);

        // Force the primary breaker open by recording failures
        {
            let mut breakers = driver.breakers.lock().unwrap();
            breakers[0].state = BreakerState::Open;
            breakers[0].last_failure_time = Some(Instant::now());
        }

        let result = driver.complete(test_request()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().text(), "OK");
    }

    #[tokio::test]
    async fn test_fallback_opens_breaker_after_repeated_failures() {
        struct AlwaysFailDriver;

        #[async_trait]
        impl LlmDriver for AlwaysFailDriver {
            async fn complete(
                &self,
                _req: CompletionRequest,
            ) -> Result<CompletionResponse, LlmError> {
                Err(LlmError::Api {
                    status: 500,
                    message: "fail".to_string(),
                })
            }
        }

        let driver = FallbackDriver::new(vec![
            Arc::new(AlwaysFailDriver) as Arc<dyn LlmDriver>,
            Arc::new(OkDriver) as Arc<dyn LlmDriver>,
        ]);

        // Exceed the failure threshold on the primary
        let threshold = {
            let breakers = driver.breakers.lock().unwrap();
            breakers[0].failure_threshold
        };

        for _ in 0..threshold {
            let _ = driver.complete(test_request()).await;
        }

        // Primary breaker should now be open
        {
            let breakers = driver.breakers.lock().unwrap();
            assert_eq!(breakers[0].state, BreakerState::Open);
        }

        // Next call should skip primary and succeed via secondary
        let result = driver.complete(test_request()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().text(), "OK");
    }
}
