//! Agent runtime and execution environment.
//!
//! Manages the agent execution loop, LLM driver abstraction,
//! tool execution, and WASM sandboxing for untrusted skill/plugin code.

/// Default User-Agent header sent with all outgoing HTTP requests.
/// Some LLM providers (e.g. Moonshot, Qwen) reject requests without one.
pub const USER_AGENT: &str = "t3rnel/0.3.48";

pub mod a2a;
pub mod agent_context;
pub mod agent_loop;
pub mod apply_patch;
pub mod audit;
pub mod auth_cooldown;
pub mod briefing;
pub mod browser;
pub mod category_registry;
pub mod channels;
pub mod circuit_breaker;
pub mod command_lane;
pub mod compactor;
pub mod context_budget;
pub mod context_overflow;
pub mod conversations;
pub mod copilot_oauth;
pub mod docker_sandbox;
pub mod drivers;
pub mod egress_guard;
pub mod egress_taint;
pub mod embedding;
pub mod graceful_shutdown;
pub mod hooks;
pub mod host_functions;
pub mod ide_driver;
pub mod image_gen;
pub mod kernel_handle;
pub mod link_understanding;
pub mod llm_driver;
pub mod llm_errors;
pub mod loop_guard;
pub mod mcp;
pub mod mcp_server;
pub mod media_understanding;
pub mod message_bus;
pub mod middleware;
pub mod model_catalog;
pub mod nested_call;
pub mod plugin_auth;
pub mod plugin_dev;
pub mod plugin_grpc;
pub mod plugin_host;
pub mod plugin_lifecycle;
pub mod plugin_proxy;
pub mod plugin_sandbox;
pub mod plugin_services;
pub mod plugin_sign;
pub mod plugin_storage;
pub mod plugin_vault;
pub mod privacy;
pub mod process_manager;
pub mod prompt_builder;
pub mod provider_health;
pub mod python_runtime;
pub mod recovery_scheduler;
pub mod reply_directives;
pub mod retry;
pub mod review;
pub mod routing;
pub mod sandbox;
pub mod scheduler;
pub mod session_repair;
pub mod shell_bleed;
pub mod str_utils;
pub mod subprocess_sandbox;
pub mod think_filter;
pub mod tool_policy;
pub mod tool_runner;
pub mod tts;
pub mod web_cache;
pub mod web_content;
pub mod web_fetch;
pub mod web_search;
pub mod workspace_context;
pub mod workspace_sandbox;
