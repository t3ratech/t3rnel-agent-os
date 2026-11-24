//! JCode CLI backend driver.
//!
//! Spawns the `jcode` CLI as a subprocess (`jcode run -p <provider> -m <model>
//! --json <prompt>`), which is non-interactive and handles its own auth
//! (OAuth stores, API keys, and `AWS_BEARER_TOKEN_BEDROCK` for the Bedrock
//! route). JCode is the official coding-agent harness: coding agents route
//! through it so the model-of-record (GPT-6 Astra via Bedrock) is enforced by
//! JCode's config, not per-agent preferences.
//!
//! Tracks active subprocess PIDs and enforces message timeouts to prevent
//! hung CLI processes from blocking agents indefinitely — same discipline as
//! the Claude Code driver.

use crate::llm_driver::{CompletionRequest, CompletionResponse, LlmDriver, LlmError, StreamEvent};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::Deserialize;
use std::sync::Arc;
use t3rnel_types::message::{ContentBlock, Role, StopReason, TokenUsage};
use tokio::io::AsyncReadExt;
use tracing::{debug, info, warn};

/// Environment variables stripped from the subprocess so keys belonging to
/// other providers cannot leak into the JCode process. JCode's own auth
/// variables (`JCODE_*`, `AWS_BEARER_TOKEN_BEDROCK`, `AWS_REGION`) survive —
/// they are how the Bedrock route authenticates.
const SENSITIVE_ENV_EXACT: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GROQ_API_KEY",
    "DEEPSEEK_API_KEY",
    "MISTRAL_API_KEY",
    "TOGETHER_API_KEY",
    "FIREWORKS_API_KEY",
    "OPENROUTER_API_KEY",
    "PERPLEXITY_API_KEY",
    "COHERE_API_KEY",
    "AI21_API_KEY",
    "CEREBRAS_API_KEY",
    "SAMBANOVA_API_KEY",
    "HUGGINGFACE_API_KEY",
    "XAI_API_KEY",
    "REPLICATE_API_TOKEN",
    "BRAVE_API_KEY",
    "TAVILY_API_KEY",
    "ELEVENLABS_API_KEY",
];

/// Suffixes that mark a secret — removed unless the name is one JCode needs.
const SENSITIVE_SUFFIXES: &[&str] = &["_SECRET", "_TOKEN", "_PASSWORD"];
const ENV_KEEP_PREFIXES: &[&str] = &["JCODE_", "CLAUDE_"];
const ENV_KEEP_EXACT: &[&str] = &[
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_REGION",
    "AWS_PROFILE",
    "JCODE_BEDROCK_REGION",
];

/// Default subprocess timeout in seconds (5 minutes).
const DEFAULT_MESSAGE_TIMEOUT_SECS: u64 = 300;

/// LLM driver that delegates to the JCode CLI.
pub struct JcodeDriver {
    cli_path: String,
    /// Provider passed to `jcode -p`. Defaults to `bedrock` — JCode's config
    /// resolves the inference profile; the model flag below can pin it.
    provider: String,
    /// Active subprocess PIDs keyed by a caller-provided label (e.g. model).
    active_pids: Arc<DashMap<String, u32>>,
    message_timeout_secs: u64,
}

impl JcodeDriver {
    /// `cli_path` overrides the CLI binary; defaults to `jcode` on PATH.
    /// `provider` overrides the `jcode -p` value; defaults to `bedrock`.
    pub fn new(cli_path: Option<String>, provider: Option<String>) -> Self {
        Self {
            cli_path: cli_path
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "jcode".to_string()),
            provider: provider
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "bedrock".to_string()),
            active_pids: Arc::new(DashMap::new()),
            message_timeout_secs: DEFAULT_MESSAGE_TIMEOUT_SECS,
        }
    }

    pub fn with_timeout(
        cli_path: Option<String>,
        provider: Option<String>,
        timeout_secs: u64,
    ) -> Self {
        let mut driver = Self::new(cli_path, provider);
        driver.message_timeout_secs = timeout_secs;
        driver
    }

    /// Snapshot of (label, pid) for external monitoring.
    pub fn active_pids(&self) -> Vec<(String, u32)> {
        self.active_pids
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect()
    }

    /// Detect the CLI on PATH, returning its version string.
    pub fn detect() -> Option<String> {
        let output = std::process::Command::new("jcode")
            .arg("version")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Flatten the request into a single prompt for `jcode run <message>`.
    fn build_prompt(request: &CompletionRequest) -> String {
        let mut parts = Vec::new();
        if let Some(ref sys) = request.system {
            parts.push(format!("[System]\n{sys}"));
        }
        for msg in &request.messages {
            let role_label = match msg.role {
                Role::User => "User",
                Role::Assistant => "Assistant",
                Role::System => "System",
            };
            let text = msg.content.text_content();
            if !text.is_empty() {
                parts.push(format!("[{role_label}]\n{text}"));
            }
        }
        parts.join("\n\n")
    }

    /// Map a T3rnel model id to a `-m` flag. `jcode/<x>` unwraps to `<x>`;
    /// `default`/`auto`/empty defer to JCode's configured default model —
    /// the model-of-record then lives in one file, not per call site.
    fn model_flag(model: &str) -> Option<String> {
        let stripped = model.strip_prefix("jcode/").unwrap_or(model);
        match stripped {
            "" | "default" | "auto" => None,
            other => Some(other.to_string()),
        }
    }

    /// Strip other providers' secrets while keeping JCode's own auth surface.
    fn apply_env_filter(cmd: &mut tokio::process::Command) {
        for key in SENSITIVE_ENV_EXACT {
            cmd.env_remove(key);
        }
        for (key, _) in std::env::vars() {
            if ENV_KEEP_EXACT.contains(&key.as_str())
                || ENV_KEEP_PREFIXES.iter().any(|p| key.starts_with(p))
            {
                continue;
            }
            let upper = key.to_uppercase();
            if SENSITIVE_SUFFIXES.iter().any(|s| upper.ends_with(s)) {
                cmd.env_remove(&key);
            }
        }
    }
}

/// JSON output from `jcode run --json`.
///
/// Field names vary across builds: the response text arrives as `result`,
/// `response`, `content`, or `text`. All optional so older and newer CLIs
/// both deserialize.
#[derive(Debug, Deserialize)]
struct JcodeJsonOutput {
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    response: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    usage: Option<JcodeUsage>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct JcodeUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
}

#[async_trait]
impl LlmDriver for JcodeDriver {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        let prompt = Self::build_prompt(&request);
        let model_flag = Self::model_flag(&request.model);

        let mut cmd = tokio::process::Command::new(&self.cli_path);
        cmd.arg("run").arg("-p").arg(&self.provider).arg("--json");
        if let Some(ref model) = model_flag {
            cmd.arg("-m").arg(model);
        }
        cmd.arg(&prompt);

        Self::apply_env_filter(&mut cmd);
        if let Some(home) = home_dir() {
            cmd.env("HOME", &home);
        }
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        debug!(cli = %self.cli_path, provider = %self.provider, "Spawning JCode CLI");

        let mut child = cmd.spawn().map_err(|e| {
            LlmError::Http(format!(
                "JCode CLI not found or failed to start ({e}). \
                 Install jcode and configure `jcode login bedrock`."
            ))
        })?;

        let pid_label = request.model.clone();
        if let Some(pid) = child.id() {
            self.active_pids.insert(pid_label.clone(), pid);
            debug!(pid = pid, model = %pid_label, "JCode subprocess started");
        }

        let child_stdout = child.stdout.take();
        let child_stderr = child.stderr.take();
        let stdout_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            if let Some(mut out) = child_stdout {
                let _ = out.read_to_end(&mut buf).await;
            }
            buf
        });
        let stderr_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            if let Some(mut err) = child_stderr {
                let _ = err.read_to_end(&mut buf).await;
            }
            buf
        });

        let wait_result = tokio::time::timeout(
            std::time::Duration::from_secs(self.message_timeout_secs),
            child.wait(),
        )
        .await;
        let stdout_bytes = stdout_task.await.unwrap_or_default();
        let stderr_bytes = stderr_task.await.unwrap_or_default();
        self.active_pids.remove(&pid_label);

        let status = match wait_result {
            Ok(Ok(status)) => status,
            Ok(Err(e)) => {
                warn!(error = %e, model = %pid_label, "JCode subprocess failed");
                return Err(LlmError::Http(format!("JCode subprocess failed: {e}")));
            }
            Err(_) => {
                warn!(
                    timeout_secs = self.message_timeout_secs,
                    model = %pid_label,
                    "JCode subprocess timed out, killing process"
                );
                let _ = child.kill().await;
                return Err(LlmError::Http(format!(
                    "JCode subprocess timed out after {}s — process killed",
                    self.message_timeout_secs
                )));
            }
        };

        if !status.success() {
            let stderr = String::from_utf8_lossy(&stderr_bytes).trim().to_string();
            let stdout_str = String::from_utf8_lossy(&stdout_bytes).trim().to_string();
            let detail = if !stderr.is_empty() {
                &stderr
            } else {
                &stdout_str
            };
            let code = status.code().unwrap_or(1);
            warn!(exit_code = code, model = %pid_label, stderr = %detail, "JCode CLI exited with error");
            let message = if detail.contains("auth") || detail.contains("login") {
                format!(
                    "JCode is not authenticated for {}. Run: jcode login {}\nDetail: {detail}",
                    self.provider, self.provider
                )
            } else {
                format!("JCode CLI exited with code {code}: {detail}")
            };
            return Err(LlmError::Api {
                status: code as u16,
                message,
            });
        }

        info!(model = %pid_label, "JCode subprocess completed");

        let stdout = String::from_utf8_lossy(&stdout_bytes);
        if let Ok(parsed) = serde_json::from_str::<JcodeJsonOutput>(&stdout) {
            if let Some(err) = parsed.error {
                return Err(LlmError::Api {
                    status: 500,
                    message: format!("JCode reported an error: {err}"),
                });
            }
            let text = parsed
                .result
                .or(parsed.response)
                .or(parsed.content)
                .or(parsed.text)
                .unwrap_or_default();
            let usage = parsed.usage.unwrap_or_default();
            return Ok(CompletionResponse {
                content: vec![ContentBlock::Text {
                    text,
                    provider_metadata: None,
                }],
                stop_reason: StopReason::EndTurn,
                tool_calls: Vec::new(),
                usage: TokenUsage {
                    input_tokens: usage.input_tokens,
                    output_tokens: usage.output_tokens,
                },
            });
        }

        // Non-JSON output: treat stdout as plain text.
        Ok(CompletionResponse {
            content: vec![ContentBlock::Text {
                text: stdout.trim().to_string(),
                provider_metadata: None,
            }],
            stop_reason: StopReason::EndTurn,
            tool_calls: Vec::new(),
            usage: TokenUsage {
                input_tokens: 0,
                output_tokens: 0,
            },
        })
    }

    async fn stream(
        &self,
        request: CompletionRequest,
        tx: tokio::sync::mpsc::Sender<StreamEvent>,
    ) -> Result<CompletionResponse, LlmError> {
        // JCode's run mode has no documented incremental stream; emit the
        // completed response as a single text delta so streaming callers
        // still receive content.
        let response = self.complete(request).await?;
        for block in &response.content {
            if let ContentBlock::Text { text, .. } = block {
                let _ = tx.send(StreamEvent::TextDelta { text: text.clone() }).await;
            }
        }
        Ok(response)
    }
}

fn home_dir() -> Option<String> {
    std::env::var("HOME").ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jcode_prefixed_models_unwrap_and_defaults_defer_to_jcode_config() {
        assert_eq!(
            JcodeDriver::model_flag("jcode/global.openai.gpt-6-astra").as_deref(),
            Some("global.openai.gpt-6-astra")
        );
        assert_eq!(JcodeDriver::model_flag("jcode/default"), None);
        assert_eq!(JcodeDriver::model_flag("default"), None);
        assert_eq!(JcodeDriver::model_flag(""), None);
    }

    #[test]
    fn the_env_filter_keeps_jcode_auth_but_strips_other_providers() {
        // Safety: the suffix sweep must not remove the bearer token that
        // authenticates the Bedrock route.
        assert!(ENV_KEEP_EXACT.contains(&"AWS_BEARER_TOKEN_BEDROCK"));
        assert!(!SENSITIVE_ENV_EXACT.contains(&"AWS_BEARER_TOKEN_BEDROCK"));
        assert!(SENSITIVE_ENV_EXACT.contains(&"OPENAI_API_KEY"));
    }
}
