//! Shared error types for the T3rnel system.

use thiserror::Error;

/// Top-level error type for the T3rnel system.
#[derive(Error, Debug)]
pub enum T3rnelError {
    /// The requested agent was not found.
    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    /// An agent with this name or ID already exists.
    #[error("Agent already exists: {0}")]
    AgentAlreadyExists(String),

    /// A capability check failed.
    #[error("Capability denied: {0}")]
    CapabilityDenied(String),

    /// A resource quota was exceeded.
    #[error("Resource quota exceeded: {0}")]
    QuotaExceeded(String),

    /// The agent is in an invalid state for the requested operation.
    #[error("Agent is in invalid state '{current}' for operation '{operation}'")]
    InvalidState {
        /// The current state of the agent.
        current: String,
        /// The operation that was attempted.
        operation: String,
    },

    /// The requested session was not found.
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    /// A memory substrate error occurred.
    #[error("Memory error: {0}")]
    Memory(String),

    /// A tool execution failed.
    #[error("Tool execution failed: {tool_id} — {reason}")]
    ToolExecution {
        /// The tool that failed.
        tool_id: String,
        /// Why it failed.
        reason: String,
    },

    /// An LLM driver error occurred.
    #[error("LLM driver error: {0}")]
    LlmDriver(String),

    /// The provider is in a rate-limit/backoff cooldown and should not be called.
    #[error("Provider '{provider}' is in rate-limit cooldown; retry in {retry_after_secs}s")]
    ProviderCooldown {
        /// The provider name (e.g., "openai" or "nvidia").
        provider: String,
        /// How many seconds to wait before the provider can be probed again.
        retry_after_secs: u64,
    },

    /// A configuration error occurred.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Failed to parse an agent manifest.
    #[error("Manifest parsing error: {0}")]
    ManifestParse(String),

    /// A WASM sandbox error occurred.
    #[error("WASM sandbox error: {0}")]
    Sandbox(String),

    /// A network error occurred.
    #[error("Network error: {0}")]
    Network(String),

    /// A serialization/deserialization error occurred.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// The agent loop exceeded the maximum iteration count.
    #[error("Max iterations exceeded ({0}). Configure a higher limit in agent.toml under [autonomous] max_iterations")]
    MaxIterationsExceeded(u32),

    /// The agent loop was aborted by the fail-fast circuit breaker.
    #[error("Fail-fast abort: {0}")]
    FailFastAbort(String),

    /// The kernel is shutting down.
    #[error("Shutdown in progress")]
    ShuttingDown,

    /// An I/O error occurred.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// An internal error occurred.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Authentication/authorization denied.
    #[error("Auth denied: {0}")]
    AuthDenied(String),

    /// Metering/cost tracking error.
    #[error("Metering error: {0}")]
    MeteringError(String),

    /// Invalid user input.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// A spend/budget cap was reached.
    #[error("Budget exceeded: {0}")]
    BudgetExceeded(String),
}

/// Alias for Result with T3rnelError.
pub type T3rnelResult<T> = Result<T, T3rnelError>;
