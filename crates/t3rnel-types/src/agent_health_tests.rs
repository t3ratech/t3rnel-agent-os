//! Unit tests for health-related agent types.

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_provider_health_serialization() {
        let health = ProviderHealth {
            provider: "nvidia".to_string(),
            model: "deepseek/deepseek-v4-pro".to_string(),
            success_rate: 0.95,
            error_rate: 0.05,
            latency_p50: 500,
            latency_p95: 1000,
            latency_p99: 2000,
            consecutive_failures: 0,
            consecutive_successes: 10,
            last_success: Some(Utc::now()),
            last_failure: None,
            total_requests: 100,
            circuit_state: CircuitState::Closed,
        };

        let json = serde_json::to_string(&health).expect("Failed to serialize");
        let deserialized: ProviderHealth = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.provider, health.provider);
        assert_eq!(deserialized.model, health.model);
        assert_eq!(deserialized.success_rate, health.success_rate);
        assert_eq!(deserialized.circuit_state, health.circuit_state);
    }

    #[test]
    fn test_agent_category_serialization() {
        let categories = vec![
            AgentCategory::Coding,
            AgentCategory::VoiceVideo,
            AgentCategory::Browser,
            AgentCategory::General,
        ];

        for category in categories {
            let json = serde_json::to_string(&category).expect("Failed to serialize");
            let deserialized: AgentCategory = serde_json::from_str(&json).expect("Failed to deserialize");
            assert_eq!(deserialized, category);
        }
    }

    #[test]
    fn test_fallback_chain_serialization() {
        let chain = FallbackChain {
            category: AgentCategory::Coding,
            models: vec![
                FallbackModel {
                    provider: "nvidia".to_string(),
                    model: "deepseek/deepseek-v4-pro".to_string(),
                    api_key_env: Some("NVIDIA_API_KEY".to_string()),
                    base_url: None,
                    weight: Some(100),
                    handles_errors: vec!["429".to_string(), "timeout".to_string()],
                },
                FallbackModel {
                    provider: "openrouter".to_string(),
                    model: "deepseek/deepseek-chat:free".to_string(),
                    api_key_env: Some("OPENROUTER_API_KEY".to_string()),
                    base_url: None,
                    weight: Some(90),
                    handles_errors: vec![],
                },
            ],
            recovery_config: RecoveryConfig::default(),
        };

        let json = serde_json::to_string(&chain).expect("Failed to serialize");
        let deserialized: FallbackChain = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.category, chain.category);
        assert_eq!(deserialized.models.len(), chain.models.len());
        assert_eq!(deserialized.models[0].provider, chain.models[0].provider);
    }

    #[test]
    fn test_recovery_config_serialization() {
        let config = RecoveryConfig {
            strategy: RecoveryStrategy::ExponentialBackoff {
                base_ms: 1000,
                max_ms: 30000,
            },
            retry_pattern: RetryPattern::RetryForever,
            initial_backoff_ms: 1000,
            max_backoff_ms: 30000,
            success_threshold: 3,
        };

        let json = serde_json::to_string(&config).expect("Failed to serialize");
        let deserialized: RecoveryConfig = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.initial_backoff_ms, config.initial_backoff_ms);
        assert_eq!(deserialized.success_threshold, config.success_threshold);
    }

    #[test]
    fn test_recovery_config_default() {
        let config = RecoveryConfig::default();
        assert_eq!(config.initial_backoff_ms, 1000);
        assert_eq!(config.max_backoff_ms, 30000);
        assert_eq!(config.success_threshold, 3);
        assert!(matches!(config.strategy, RecoveryStrategy::ExponentialBackoff { .. }));
        assert!(matches!(config.retry_pattern, RetryPattern::RetryForever));
    }

    #[test]
    fn test_fallback_config_default() {
        let config = FallbackConfig::default();
        assert!(config.retry_pattern.is_none());
        assert!(config.max_retry_attempts.is_none());
        assert!(config.max_retry_duration_seconds.is_none());
    }

    #[test]
    fn test_chain_state_serialization() {
        let state = ChainState {
            current_index: 0,
            last_fail_time: Some(Utc::now()),
            consecutive_failures: 5,
            consecutive_successes: 0,
            backoff_until: Some(Utc::now()),
        };

        let json = serde_json::to_string(&state).expect("Failed to serialize");
        let deserialized: ChainState = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.current_index, state.current_index);
        assert_eq!(deserialized.consecutive_failures, state.consecutive_failures);
    }

    #[test]
    fn test_fallback_model_with_optional_fields() {
        let model = FallbackModel {
            provider: "nvidia".to_string(),
            model: "deepseek/deepseek-v4-pro".to_string(),
            api_key_env: None,
            base_url: None,
            weight: None,
            handles_errors: vec![],
        };

        let json = serde_json::to_string(&model).expect("Failed to serialize");
        let deserialized: FallbackModel = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.provider, model.provider);
        assert!(deserialized.weight.is_none());
        assert!(deserialized.handles_errors.is_empty());
    }

    #[test]
    fn test_circuit_state_serialization() {
        let states = vec![
            CircuitState::Closed,
            CircuitState::Open,
            CircuitState::HalfOpen,
        ];

        for state in states {
            let json = serde_json::to_string(&state).expect("Failed to serialize");
            let deserialized: CircuitState = serde_json::from_str(&json).expect("Failed to deserialize");
            assert_eq!(deserialized, state);
        }
    }

    #[test]
    fn test_retry_pattern_serialization() {
        let patterns = vec![
            RetryPattern::RetryForever,
            RetryPattern::StopAfterAttempts(5),
            RetryPattern::StopAfterDurationSeconds(300),
            RetryPattern::Adaptive,
        ];

        for pattern in patterns {
            let json = serde_json::to_string(&pattern).expect("Failed to serialize");
            let deserialized: RetryPattern = serde_json::from_str(&json).expect("Failed to deserialize");
            assert_eq!(deserialized, pattern);
        }
    }

    #[test]
    fn test_agent_manifest_with_category() {
        let manifest = AgentManifest {
            name: "coder".to_string(),
            version: "0.1.0".to_string(),
            description: "Coding agent".to_string(),
            author: "t3rnel".to_string(),
            module: "builtin:chat".to_string(),
            schedule: ScheduleMode::default(),
            model: ModelConfig::default(),
            fallback_models: vec![],
            resources: ResourceQuota::default(),
            priority: Priority::default(),
            capabilities: ManifestCapabilities::default(),
            profile: None,
            tools: std::collections::HashMap::new(),
            skills: vec![],
            mcp_servers: vec![],
            metadata: std::collections::HashMap::new(),
            role: "coder".to_string(),
            tags: vec![],
            category: AgentCategory::Coding,
            fallback_config: FallbackConfig::default(),
            routing: None,
            autonomous: None,
            pinned_model: None,
            workspace: None,
            generate_identity_files: true,
            exec_policy: None,
            tool_allowlist: vec![],
            tool_blocklist: vec![],
            cache_context: false,
        };

        let json = serde_json::to_string(&manifest).expect("Failed to serialize");
        let deserialized: AgentManifest = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.category, AgentCategory::Coding);
        assert_eq!(deserialized.name, "coder");
    }
}
