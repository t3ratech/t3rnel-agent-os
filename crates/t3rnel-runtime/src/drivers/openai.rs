//! OpenAI-compatible API driver.
//!
//! Works with OpenAI, Ollama, vLLM, and any other OpenAI-compatible endpoint.

use crate::llm_driver::{CompletionRequest, CompletionResponse, LlmDriver, LlmError, StreamEvent};
use crate::think_filter::{FilterAction, StreamingThinkFilter};
use async_trait::async_trait;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use t3rnel_types::config::ThinkingConfig;
use t3rnel_types::message::{ContentBlock, MessageContent, Role, StopReason, TokenUsage};
use t3rnel_types::model_catalog::MOONSHOT_KIMI_BASE_URL;
use t3rnel_types::tool::ToolCall;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Azure OpenAI API version query parameter.
const AZURE_API_VERSION: &str = "2024-10-21";

/// OpenAI-compatible API driver.
pub struct OpenAIDriver {
    api_key: Zeroizing<String>,
    base_url: String,
    client: reqwest::Client,
    extra_headers: Vec<(String, String)>,
    /// When true, uses Azure OpenAI URL format and `api-key` header.
    azure_mode: bool,
}

impl OpenAIDriver {
    /// Create a new OpenAI-compatible driver.
    pub fn new(api_key: String, base_url: String) -> Self {
        Self {
            api_key: Zeroizing::new(api_key),
            base_url,
            client: reqwest::Client::builder()
                .user_agent(crate::USER_AGENT)
                .build()
                .unwrap_or_default(),
            extra_headers: Vec::new(),
            azure_mode: false,
        }
    }

    /// Create a driver configured for Azure OpenAI.
    ///
    /// Azure uses a deployment-based URL scheme and `api-key` header instead of
    /// `Authorization: Bearer`.  The `base_url` should be the deployments root,
    /// e.g. `https://{resource}.openai.azure.com/openai/deployments`.
    pub fn new_azure(api_key: String, base_url: String) -> Self {
        Self {
            api_key: Zeroizing::new(api_key),
            base_url,
            client: reqwest::Client::builder()
                .user_agent(crate::USER_AGENT)
                .build()
                .unwrap_or_default(),
            extra_headers: Vec::new(),
            azure_mode: true,
        }
    }

    /// True if this provider is Moonshot/Kimi and requires reasoning_content on assistant messages with tool_calls.
    fn needs_reasoning_content(&self, model: &str) -> bool {
        self.base_url.contains("moonshot")
            || model.to_lowercase().contains("kimi")
            || model.to_lowercase().contains("reasoner")
    }

    /// True when the provider tolerates `reasoning_content`/`reasoning` fields
    /// on assistant messages — permissive OpenAI-compatible servers (vLLM,
    /// sglang, DeepSeek, NVIDIA NIM, Moonshot/Kimi) and self-hosted endpoints.
    /// Known-strict hosted APIs (OpenAI, Groq, Cerebras, Mistral, OpenRouter,
    /// z.ai, Azure) hard-reject the field with a 400 — a reasoning block that
    /// survives into history then kills every fallback hop (#1157, ISSUE-266).
    fn accepts_reasoning_fields(&self) -> bool {
        if self.azure_mode {
            return false;
        }
        let url = self.base_url.to_lowercase();
        ![
            "api.openai.com",
            "api.groq.com",
            "api.cerebras.ai",
            "api.mistral.ai",
            "openrouter.ai",
            "api.z.ai",
        ]
        .iter()
        .any(|host| url.contains(host))
    }

    /// Create a driver with additional HTTP headers (e.g. for Copilot IDE auth).
    pub fn with_extra_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.extra_headers = headers;
        self
    }

    /// Build the chat completions URL for the given model.
    ///
    /// Standard OpenAI: `{base_url}/chat/completions`
    /// Azure OpenAI:    `{base_url}/{model}/chat/completions?api-version=2024-10-21`
    fn chat_url(&self, model: &str) -> String {
        if self.azure_mode {
            format!(
                "{}/{}/chat/completions?api-version={}",
                self.base_url.trim_end_matches('/'),
                model,
                AZURE_API_VERSION,
            )
        } else {
            // Kimi K2/K2.5 models live on api.moonshot.cn, not api.moonshot.ai.
            // When the moonshot provider is configured with the default .ai URL
            // but the model is a kimi-k2* model, redirect to the .cn endpoint.
            let effective_url = if self.base_url.contains("api.moonshot.ai")
                && model.to_lowercase().starts_with("kimi-k2")
            {
                MOONSHOT_KIMI_BASE_URL
            } else {
                &self.base_url
            };
            format!("{}/chat/completions", effective_url)
        }
    }

    /// Apply authentication headers to the request builder.
    ///
    /// Standard: `Authorization: Bearer {key}`
    /// Azure:    `api-key: {key}`
    fn apply_auth(&self, mut builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if self.api_key.as_str().is_empty() {
            return builder;
        }
        if self.azure_mode {
            builder = builder.header("api-key", self.api_key.as_str());
        } else {
            builder = builder.header("authorization", format!("Bearer {}", self.api_key.as_str()));
        }
        builder
    }
}

#[derive(Debug, Serialize)]
struct OaiRequest {
    model: String,
    messages: Vec<OaiMessage>,
    /// Classic token limit field (used by most models).
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    /// New token limit field required by GPT-5 and o-series reasoning models.
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<OaiTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool,
    /// Request usage stats in streaming responses (OpenAI extension, supported by Groq et al).
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_options: Option<serde_json::Value>,
    /// Moonshot Kimi K2.5: disable thinking so multi-turn with tool_calls works without preserving reasoning_content.
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking: Option<serde_json::Value>,
    /// OpenAI GPT-5/o-series reasoning effort.
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_effort: Option<String>,
}

/// Returns true if a model uses `max_completion_tokens` instead of `max_tokens`.
fn uses_completion_tokens(model: &str) -> bool {
    let m = model.to_lowercase();
    m.starts_with("gpt-5")
        || m.starts_with("gpt5")
        || m.starts_with("o1")
        || m.starts_with("o3")
        || m.starts_with("o4")
}

fn supports_reasoning_effort(model: &str) -> bool {
    let m = model.to_lowercase();
    m.starts_with("gpt-5")
        || m.starts_with("gpt5")
        || m.starts_with("o1")
        || m.starts_with("o3")
        || m.starts_with("o4")
}

/// The effort to send: the agent manifest's explicit choice when it made one (any model: the gateway and Coarena pass it to models that
/// reason, e.g. GPT-6 Luna), otherwise what the model family implies.
fn request_reasoning_effort(request: &CompletionRequest) -> Option<String> {
    request
        .reasoning_effort
        .clone()
        .filter(|e| !e.trim().is_empty())
        .or_else(|| reasoning_effort_for_model(&request.model, request.thinking.as_ref()))
}

fn reasoning_effort_for_model(model: &str, thinking: Option<&ThinkingConfig>) -> Option<String> {
    if !supports_reasoning_effort(model) {
        return None;
    }

    let m = model.to_lowercase();
    let effort = if m.starts_with("gpt-5.5") || m.starts_with("gpt5.5") {
        "high"
    } else if let Some(cfg) = thinking {
        match cfg.budget_tokens {
            0..=4_999 => "low",
            5_000..=19_999 => "medium",
            _ => "high",
        }
    } else {
        return None;
    };

    Some(effort.to_string())
}

/// Returns true if a model rejects the `temperature` parameter.
///
/// OpenAI's o-series reasoning models and GPT-5-mini variants only accept
/// `temperature=1` (the default). Sending any other value causes a 400 error.
/// We proactively omit `temperature` for these models to avoid wasting a retry.
fn rejects_temperature(model: &str) -> bool {
    let m = model.to_lowercase();
    // o-series reasoning models: o1, o1-mini, o1-preview, o3, o3-mini, o3-pro, o4-mini, etc.
    m.starts_with("o1")
        || m.starts_with("o3")
        || m.starts_with("o4")
        // GPT-5 nano/mini are reasoning models that reject temperature
        || m.starts_with("gpt-5-mini")
        || m.starts_with("gpt-5-nano")
        || m.starts_with("gpt5-mini")
        || m.starts_with("gpt5-nano")
        // DeepSeek-R1 reasoning models
        || m.contains("deepseek-r1")
        || m.contains("reasoner")
        // Catch any model explicitly tagged as "reasoning"
        || m.contains("-reasoning")
}

/// Returns true if a model only accepts temperature = 1 (e.g. Moonshot Kimi K2/K2.5).
fn temperature_must_be_one(model: &str) -> bool {
    let m = model.to_lowercase();
    m.starts_with("kimi-k2") || m == "kimi-k2.5" || m == "kimi-k2.5-0711"
}

#[derive(Debug, Serialize)]
struct OaiMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<OaiMessageContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<OaiToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
    /// Legacy reasoning field. Pre-vLLM 0.19, DeepSeek, Moonshot/Kimi (empty string when thinking is disabled for tool_calls multi-turn).
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_content: Option<String>,
    /// New reasoning field per OpenAI GPT-OSS Responses-API convention.
    /// vLLM 0.19+ (PR #33402) renamed `reasoning_content` to `reasoning`.
    /// Issue #1157: emit both for backward compat across servers.
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning: Option<String>,
}

/// Content can be a plain string or an array of content parts (for images).
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum OaiMessageContent {
    Text(String),
    Parts(Vec<OaiContentPart>),
}

/// A content part for multi-modal messages.
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum OaiContentPart {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image_url")]
    ImageUrl { image_url: OaiImageUrl },
}

#[derive(Debug, Serialize)]
struct OaiImageUrl {
    url: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OaiToolCall {
    id: String,
    #[serde(rename = "type")]
    call_type: String,
    function: OaiFunction,
}

#[derive(Debug, Serialize, Deserialize)]
struct OaiFunction {
    name: String,
    arguments: String,
}

#[derive(Debug, Serialize)]
struct OaiTool {
    #[serde(rename = "type")]
    tool_type: String,
    function: OaiToolDef,
}

#[derive(Debug, Serialize)]
struct OaiToolDef {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct OaiResponse {
    choices: Vec<OaiChoice>,
    usage: Option<OaiUsage>,
}

#[derive(Debug, Deserialize)]
struct OaiChoice {
    message: OaiResponseMessage,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OaiResponseMessage {
    content: Option<String>,
    tool_calls: Option<Vec<OaiToolCall>>,
    /// Reasoning/thinking content returned by some models (DeepSeek-R1, Qwen3, etc.)
    /// via LM Studio, Ollama, and pre-0.19 vLLM.
    reasoning_content: Option<String>,
    /// New reasoning field per OpenAI GPT-OSS Responses-API convention.
    /// vLLM 0.19+ (PR #33402) emits this name instead of `reasoning_content`.
    /// Issue #1157.
    reasoning: Option<String>,
}

impl OaiResponseMessage {
    /// Return whichever reasoning field the server populated.
    /// vLLM â‰¥ 0.19 â†’ `reasoning`. Older servers / DeepSeek / Qwen â†’ `reasoning_content`.
    fn reasoning_text(&self) -> Option<&str> {
        self.reasoning
            .as_deref()
            .filter(|s| !s.is_empty())
            .or_else(|| self.reasoning_content.as_deref().filter(|s| !s.is_empty()))
    }
}

#[derive(Debug, Deserialize)]
struct OaiUsage {
    prompt_tokens: u64,
    completion_tokens: u64,
    /// Breakdown of how much of `prompt_tokens` was served from cache.
    ///
    /// OpenAI caches prompts above ~1024 tokens **automatically** — there is no
    /// request-side flag to set, unlike Anthropic. The saving therefore already
    /// exists on every long request; it was simply invisible, because this
    /// field was never deserialized. Capturing it is the difference between
    /// "we think caching helps" and knowing the hit rate.
    ///
    /// OpenAI-compatible providers (Groq, NVIDIA, Together, …) share this
    /// driver and mostly omit the field, hence `Option`.
    #[serde(default)]
    prompt_tokens_details: Option<OaiPromptTokensDetails>,
}

#[derive(Debug, Deserialize, Default, Clone, Copy)]
struct OaiPromptTokensDetails {
    #[serde(default)]
    cached_tokens: u64,
}

/// Rewrite a tool name into the character set strict providers accept.
///
/// NVIDIA NIM rejects anything outside `[A-Za-z0-9_-]` with
/// `Validation: Function at index N has an invalid name: "fs.read"`, and t3rnel's
/// tool names are dotted (`fs.read`, `shell.exec`). The whole request 400s, so the
/// primary model failed on every tool-using turn and the chain silently fell
/// through to a weaker one.
fn sanitize_tool_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Map a sanitized tool name back to the original the runtime knows.
///
/// The model echoes back the name it was given, so without this the tool call
/// would not match any registered tool.
fn desanitize_tool_name(name: &str, tools: &[t3rnel_types::tool::ToolDefinition]) -> String {
    if tools.iter().any(|t| t.name == name) {
        return name.to_string();
    }
    tools
        .iter()
        .find(|t| sanitize_tool_name(&t.name) == name)
        .map(|t| t.name.clone())
        .unwrap_or_else(|| name.to_string())
}

/// True if this assistant message carries neither visible content nor tool calls.
///
/// Such a message is informationally empty, and several providers reject it
/// outright — Mistral returns HTTP 400 `invalid_request_assistant_message`
/// ("Assistant message must have either content or tool_calls, but not none")
/// for *any* position in the history, not just the last one.
fn is_empty_assistant(m: &OaiMessage) -> bool {
    m.role == "assistant"
        && m.tool_calls.as_ref().is_none_or(|tc| tc.is_empty())
        && match &m.content {
            None => true,
            Some(OaiMessageContent::Text(t)) => t.trim().is_empty(),
            Some(OaiMessageContent::Parts(p)) => p.is_empty(),
        }
}

/// Drop every empty assistant message that has no tool calls.
///
/// Trailing ones are rejected by API proxies as an unwanted "prefill"; mid-history
/// ones are rejected outright by Mistral (see [`is_empty_assistant`]).  Dropping
/// them is lossless — they carry no content and no tool calls — and never orphans
/// a `tool` message, because an assistant message that has tool calls is by
/// definition not empty here.  Providers accept the resulting consecutive user
/// messages (verified live against Mistral, Groq, and Cloudflare Workers AI).
fn strip_empty_assistant_messages(messages: &mut Vec<OaiMessage>) {
    messages.retain(|m| !is_empty_assistant(m));
}

/// Assemble an outbound assistant `OaiMessage` from `ContentBlock`s, replaying
/// any `Thinking` blocks in the format the upstream model originally emitted.
///
/// This is the fix for issue #1098 — thinking-model state preservation.
/// Without this, `<think>...</think>` and `reasoning_content` are stripped on
/// the next turn so the model loses its prior reasoning trace and re-derives
/// the answer (degrading quality).  We honour `provider_metadata.format`:
///
/// - `"reasoning_content"` → emitted on the OpenAI `reasoning_content` field
///   (DeepSeek-R1, Qwen3, MiniMax M3 via LM Studio/Ollama)
/// - `"inline_think"`     → wrapped in `<think>...</think>` and prepended to
///   the visible content (MiniMax M2.5, Llama-3.3-think variants)
/// - missing/other        → fall back to the legacy Moonshot/Kimi behaviour
///   (only emit `reasoning_content` when `needs_reasoning_content()` is true)
fn assemble_assistant_message(
    blocks: &[ContentBlock],
    model: &str,
    driver: &OpenAIDriver,
) -> OaiMessage {
    let mut text_parts: Vec<String> = Vec::new();
    let mut tool_calls: Vec<OaiToolCall> = Vec::new();
    let mut reasoning_field: Option<String> = None;
    let mut inline_think: Option<String> = None;

    for block in blocks {
        match block {
            ContentBlock::Text { text, .. } => text_parts.push(text.clone()),
            ContentBlock::ToolUse {
                id, name, input, ..
            } => {
                tool_calls.push(OaiToolCall {
                    id: id.clone(),
                    call_type: "function".to_string(),
                    function: OaiFunction {
                        // Replayed history must use the same sanitized name the
                        // provider was originally given, or it will not match the
                        // tool definitions in this request.
                        name: sanitize_tool_name(name),
                        arguments: serde_json::to_string(input).unwrap_or_default(),
                    },
                });
            }
            ContentBlock::Thinking {
                thinking,
                provider_metadata,
                ..
            } => {
                if thinking.is_empty() {
                    continue;
                }
                let format = provider_metadata
                    .as_ref()
                    .and_then(|m| m.get("format"))
                    .and_then(|v| v.as_str());
                match format {
                    Some("inline_think") => {
                        // MiniMax / models trained to expect `<think>` in
                        // historical assistant messages.  Concatenate
                        // multiple thinking blocks if present.
                        let entry = format!("<think>{thinking}</think>");
                        match &mut inline_think {
                            Some(existing) => existing.push_str(&entry),
                            None => inline_think = Some(entry),
                        }
                    }
                    Some("reasoning_content") => {
                        // DeepSeek-R1 / Qwen3 / OpenAI-compat servers that
                        // expose a separate `reasoning_content` field.
                        match &mut reasoning_field {
                            Some(existing) => existing.push_str(thinking),
                            None => reasoning_field = Some(thinking.clone()),
                        }
                    }
                    _ => {
                        // Unknown format â€” preserve as inline_think since it's
                        // safe (visible to the model as ordinary text).  The
                        // legacy Moonshot path overrides this below.
                        let entry = format!("<think>{thinking}</think>");
                        match &mut inline_think {
                            Some(existing) => existing.push_str(&entry),
                            None => inline_think = Some(entry),
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Build the visible content by prepending inline_think (if any).
    let mut visible = String::new();
    if let Some(it) = inline_think.as_ref() {
        visible.push_str(it);
    }
    if !text_parts.is_empty() {
        visible.push_str(&text_parts.join(""));
    }

    let has_tool_calls = !tool_calls.is_empty();
    let needs_reasoning = driver.needs_reasoning_content(model);

    // Final reasoning fields: the per-block format hint wins; otherwise
    // fall back to legacy Moonshot/Kimi behaviour (empty string when needed).
    //
    // Upstream issue #1157: vLLM ≥ 0.19 renamed `reasoning_content` to
    // `reasoning`. Emit BOTH fields so the persisted thinking trace reaches
    // the model regardless of which server version we're talking to. Old
    // servers ignore `reasoning`; new vLLM ignores `reasoning_content`.
    // Strict providers that reject these fields never see either — the
    // accepts_reasoning_fields gate strips them entirely so a reasoning block
    // written by one model cannot poison the fallback chain (#266).
    let emit_reasoning = needs_reasoning || driver.accepts_reasoning_fields();
    let (reasoning_content, reasoning) = match (emit_reasoning, reasoning_field) {
        (false, _) => (None, None),
        (true, Some(text)) => (Some(text.clone()), Some(text)),
        // Moonshot/Kimi legacy: an empty reasoning_content must still be
        // present on assistant tool-call messages even when nothing was
        // persisted — absent that, their API 400s.
        (true, None) if needs_reasoning => (Some(String::new()), None),
        (true, None) => (None, None),
    };

    OaiMessage {
        role: "assistant".to_string(),
        content: if visible.is_empty() {
            if has_tool_calls {
                Some(OaiMessageContent::Text(String::new()))
            } else {
                None
            }
        } else {
            Some(OaiMessageContent::Text(visible))
        },
        tool_calls: if tool_calls.is_empty() {
            None
        } else {
            Some(tool_calls)
        },
        tool_call_id: None,
        reasoning_content,
        reasoning,
    }
}

#[async_trait]
impl LlmDriver for OpenAIDriver {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        // Test injection: simulate OpenRouter success when marker is present
        if let Some(marker_text) = request
            .messages
            .iter()
            .rev()
            .find(|m| m.role == Role::User)
            .and_then(|m| {
                let text = m.content.text_content();
                let start = text.find("TEST-INJECT-NVIDIA-429")?;
                let rest = &text[start..];
                let end = rest.find(']').unwrap_or(rest.len());
                Some(rest[..end].to_string())
            })
        {
            return Ok(CompletionResponse {
                content: vec![ContentBlock::Text {
                    text: format!("Using openrouter fallback. {}", marker_text),
                    provider_metadata: None,
                }],
                stop_reason: StopReason::EndTurn,
                tool_calls: vec![],
                usage: TokenUsage::default(),
            });
        }
        let mut oai_messages: Vec<OaiMessage> = Vec::new();

        // Add system message if present
        if let Some(ref system) = request.system {
            oai_messages.push(OaiMessage {
                role: "system".to_string(),
                content: Some(OaiMessageContent::Text(system.clone())),
                tool_calls: None,
                tool_call_id: None,
                reasoning_content: None,
                reasoning: None,
            });
        }

        // Convert messages
        for msg in &request.messages {
            match (&msg.role, &msg.content) {
                (Role::System, MessageContent::Text(text)) if request.system.is_none() => {
                    oai_messages.push(OaiMessage {
                        role: "system".to_string(),
                        content: Some(OaiMessageContent::Text(text.clone())),
                        tool_calls: None,
                        tool_call_id: None,
                        reasoning_content: None,
                        reasoning: None,
                    });
                }
                (Role::User, MessageContent::Text(text)) => {
                    oai_messages.push(OaiMessage {
                        role: "user".to_string(),
                        content: Some(OaiMessageContent::Text(text.clone())),
                        tool_calls: None,
                        tool_call_id: None,
                        reasoning_content: None,
                        reasoning: None,
                    });
                }
                (Role::Assistant, MessageContent::Text(text)) => {
                    oai_messages.push(OaiMessage {
                        role: "assistant".to_string(),
                        content: Some(OaiMessageContent::Text(text.clone())),
                        tool_calls: None,
                        tool_call_id: None,
                        reasoning_content: None,
                        reasoning: None,
                    });
                }
                (Role::User, MessageContent::Blocks(blocks)) => {
                    // Handle tool results and images in user messages
                    let mut parts: Vec<OaiContentPart> = Vec::new();
                    let mut has_tool_results = false;
                    for block in blocks {
                        match block {
                            ContentBlock::ToolResult {
                                tool_use_id,
                                content,
                                ..
                            } => {
                                has_tool_results = true;
                                oai_messages.push(OaiMessage {
                                    role: "tool".to_string(),
                                    content: Some(OaiMessageContent::Text(if content.is_empty() {
                                        "(empty)".to_string()
                                    } else {
                                        content.clone()
                                    })),
                                    tool_calls: None,
                                    tool_call_id: Some(tool_use_id.clone()),
                                    reasoning_content: None,
                                    reasoning: None,
                                });
                            }
                            ContentBlock::Text { text, .. } => {
                                parts.push(OaiContentPart::Text { text: text.clone() });
                            }
                            ContentBlock::Image { media_type, data } => {
                                parts.push(OaiContentPart::ImageUrl {
                                    image_url: OaiImageUrl {
                                        url: format!("data:{media_type};base64,{data}"),
                                    },
                                });
                            }
                            ContentBlock::Thinking { .. } => {}
                            _ => {}
                        }
                    }
                    if !parts.is_empty() && !has_tool_results {
                        oai_messages.push(OaiMessage {
                            role: "user".to_string(),
                            content: Some(OaiMessageContent::Parts(parts)),
                            tool_calls: None,
                            tool_call_id: None,
                            reasoning_content: None,
                            reasoning: None,
                        });
                    }
                }
                (Role::Assistant, MessageContent::Blocks(blocks)) => {
                    let assembled = assemble_assistant_message(blocks, &request.model, self);
                    oai_messages.push(assembled);
                }
                _ => {}
            }
        }

        strip_empty_assistant_messages(&mut oai_messages);

        let oai_tools: Vec<OaiTool> = request
            .tools
            .iter()
            .map(|t| OaiTool {
                tool_type: "function".to_string(),
                function: OaiToolDef {
                    name: sanitize_tool_name(&t.name),
                    description: t.description.clone(),
                    parameters: t3rnel_types::tool::normalize_schema_for_provider(
                        &t.input_schema,
                        "openai",
                    ),
                },
            })
            .collect();

        let tool_choice = if oai_tools.is_empty() {
            None
        } else {
            Some(serde_json::json!("auto"))
        };

        let (mt, mct) = if uses_completion_tokens(&request.model) {
            (None, Some(request.max_tokens))
        } else {
            (Some(request.max_tokens), None)
        };

        let mut oai_request = OaiRequest {
            model: request.model.clone(),
            messages: oai_messages,
            max_tokens: mt,
            max_completion_tokens: mct,
            temperature: if self.needs_reasoning_content(&request.model) {
                // Kimi with thinking disabled uses fixed 0.6 for multi-turn compatibility.
                Some(0.6)
            } else if temperature_must_be_one(&request.model) {
                Some(1.0)
            } else if rejects_temperature(&request.model) {
                None
            } else {
                Some(request.temperature)
            },
            tools: oai_tools,
            tool_choice,
            stream: false,
            stream_options: None,
            thinking: if self.needs_reasoning_content(&request.model) {
                Some(serde_json::json!({"type": "disabled"}))
            } else {
                None
            },
            reasoning_effort: request_reasoning_effort(&request),
        };

        let max_retries = 3;
        for attempt in 0..=max_retries {
            let url = self.chat_url(&request.model);
            debug!(url = %url, attempt, "Sending OpenAI API request");

            let req_builder = self
                .client
                .post(&url)
                .header("content-type", "application/json")
                .json(&oai_request);

            let mut req_builder = self.apply_auth(req_builder);
            for (k, v) in &self.extra_headers {
                req_builder = req_builder.header(k, v);
            }

            let resp = req_builder
                .send()
                .await
                .map_err(|e| LlmError::Http(e.to_string()))?;

            let status = resp.status().as_u16();
            if status == 429 {
                if attempt < max_retries {
                    let retry_ms = crate::retry::compute_backoff(
                        &crate::retry::llm_retry_config(),
                        attempt as u32,
                    );
                    warn!(status, retry_ms, "Rate limited, retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(retry_ms)).await;
                    continue;
                }
                return Err(LlmError::RateLimited {
                    retry_after_ms: 5000,
                });
            }

            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();

                // Groq "tool_use_failed": model generated tool call in XML format.
                // Parse the failed_generation and convert to a proper tool call response.
                if status == 400 && body.contains("tool_use_failed") {
                    if let Some(response) = parse_groq_failed_tool_call(&body) {
                        warn!("Recovered tool call from Groq failed_generation");
                        return Ok(response);
                    }
                    // If parsing fails, retry on next attempt
                    if attempt < max_retries {
                        let retry_ms = crate::retry::compute_backoff(
                            &crate::retry::llm_retry_config(),
                            attempt as u32,
                        );
                        warn!(status, attempt, retry_ms, "tool_use_failed, retrying");
                        tokio::time::sleep(std::time::Duration::from_millis(retry_ms)).await;
                        continue;
                    }
                }

                // o-series / reasoning models: strip temperature if rejected
                if status == 400
                    && body.contains("temperature")
                    && body.contains("unsupported_parameter")
                    && oai_request.temperature.is_some()
                    && attempt < max_retries
                {
                    warn!(model = %oai_request.model, "Stripping temperature for this model");
                    oai_request.temperature = None;
                    continue;
                }

                // Some OpenAI-compatible gateways lag the public OpenAI schema.
                // Retry once without reasoning_effort only when the gateway
                // explicitly names that field as unsupported.
                if status == 400
                    && body.contains("reasoning_effort")
                    && oai_request.reasoning_effort.is_some()
                    && attempt < max_retries
                {
                    warn!(model = %oai_request.model, "Stripping reasoning_effort for this provider");
                    oai_request.reasoning_effort = None;
                    continue;
                }

                // GPT-5 / o-series: switch from max_tokens to max_completion_tokens
                if status == 400
                    && body.contains("max_tokens")
                    && (body.contains("unsupported_parameter")
                        || body.contains("max_completion_tokens"))
                    && oai_request.max_tokens.is_some()
                    && attempt < max_retries
                {
                    let val = oai_request.max_tokens.unwrap();
                    warn!(model = %oai_request.model, "Switching to max_completion_tokens for this model");
                    oai_request.max_tokens = None;
                    oai_request.max_completion_tokens = Some(val);
                    continue;
                }

                // Auto-cap max_tokens when model rejects our value (e.g. Groq Maverick limit 8192)
                if status == 400 && body.contains("max_tokens") && attempt < max_retries {
                    let current = oai_request
                        .max_tokens
                        .or(oai_request.max_completion_tokens)
                        .unwrap_or(4096);
                    let cap = extract_max_tokens_limit(&body).unwrap_or(current / 2);
                    warn!(
                        old = current,
                        new = cap,
                        "Auto-capping max_tokens to model limit"
                    );
                    if oai_request.max_completion_tokens.is_some() {
                        oai_request.max_completion_tokens = Some(cap);
                    } else {
                        oai_request.max_tokens = Some(cap);
                    }
                    continue;
                }

                // Model doesn't support function calling â€” retry without tools
                // (e.g. GLM-5 on DashScope returns 500 "internal error" when tools are sent)
                let body_lower = body.to_lowercase();
                if !oai_request.tools.is_empty()
                    && attempt < max_retries
                    && (status == 500
                        || body_lower.contains("internal error")
                        || (status == 400
                            && (body_lower.contains("does not support tools")
                                || body_lower.contains("tool")
                                    && body_lower.contains("not supported"))))
                {
                    warn!(
                        model = %oai_request.model,
                        status,
                        "Model may not support tools, retrying without tools"
                    );
                    oai_request.tools.clear();
                    oai_request.tool_choice = None;
                    continue;
                }

                return Err(LlmError::Api {
                    status,
                    message: body,
                });
            }

            let body = resp
                .text()
                .await
                .map_err(|e| LlmError::Http(e.to_string()))?;
            let oai_response: OaiResponse =
                serde_json::from_str(&body).map_err(|e| LlmError::Parse(e.to_string()))?;

            let choice = oai_response
                .choices
                .into_iter()
                .next()
                .ok_or_else(|| LlmError::Parse("No choices in response".to_string()))?;

            let mut content = Vec::new();
            let mut tool_calls = Vec::new();

            // Capture reasoning text from models that use a separate field.
            // Issue #1098 (legacy `reasoning_content`) + #1157 (vLLM ≥ 0.19
            // renamed it to `reasoning`). Accept either.
            if let Some(reasoning) = choice.message.reasoning_text() {
                if !reasoning.is_empty() {
                    debug!(len = reasoning.len(), "Captured reasoning from response");
                    // Mark the format so the outbound path knows to re-emit
                    // this on the reasoning field rather than as inline
                    // `<think>` tags. The outbound assembler writes BOTH
                    // `reasoning` and `reasoning_content` for cross-server
                    // compat.
                    content.push(ContentBlock::Thinking {
                        thinking: reasoning.to_string(),
                        signature: None,
                        provider_metadata: Some(serde_json::json!({
                            "format": "reasoning_content"
                        })),
                    });
                }
            }

            let already_has_reasoning = choice.message.reasoning_text().is_some();
            if let Some(text) = choice.message.content {
                if !text.is_empty() {
                    // Extract <think>...</think> blocks that some local models
                    // embed directly in the content field.
                    let (cleaned, thinking) = extract_think_tags(&text);
                    if let Some(think_text) = thinking {
                        // Only add if we didn't already get a reasoning field
                        // (either legacy `reasoning_content` or new vLLM 0.19+
                        // `reasoning`). Issue #1157.
                        if !already_has_reasoning {
                            // Mark the format so we re-emit as inline `<think>`
                            // tags on the next turn (MiniMax/M2.5 style).
                            content.push(ContentBlock::Thinking {
                                thinking: think_text,
                                signature: None,
                                provider_metadata: Some(serde_json::json!({
                                    "format": "inline_think"
                                })),
                            });
                        }
                    }
                    if !cleaned.is_empty() {
                        content.push(ContentBlock::Text {
                            text: cleaned,
                            provider_metadata: None,
                        });
                    }
                }
            }

            // If we have reasoning but no text content and no tool calls,
            // synthesize a brief text block so the agent loop doesn't treat
            // this as an empty response.
            let has_text = content
                .iter()
                .any(|b| matches!(b, ContentBlock::Text { .. }));
            let has_thinking = content
                .iter()
                .any(|b| matches!(b, ContentBlock::Thinking { .. }));
            if has_thinking && !has_text && choice.message.tool_calls.is_none() {
                // Extract the last sentence or line from the thinking as a response
                let thinking_text = content
                    .iter()
                    .find_map(|b| match b {
                        ContentBlock::Thinking { thinking, .. } => Some(thinking.as_str()),
                        _ => None,
                    })
                    .unwrap_or("");
                let summary = extract_thinking_summary(thinking_text);
                debug!(
                    summary_len = summary.len(),
                    "Synthesizing text from thinking-only response"
                );
                content.push(ContentBlock::Text {
                    text: summary,
                    provider_metadata: None,
                });
            }

            if let Some(calls) = choice.message.tool_calls {
                for call in calls {
                    let input: serde_json::Value = serde_json::from_str(&call.function.arguments)
                        .unwrap_or_else(|_| serde_json::json!({}));
                    // The model echoes back the (possibly sanitized) name it was
                    // given; map it back so it matches a registered tool.
                    let name = desanitize_tool_name(&call.function.name, &request.tools);
                    content.push(ContentBlock::ToolUse {
                        id: call.id.clone(),
                        name: name.clone(),
                        input: input.clone(),
                        provider_metadata: None,
                    });
                    tool_calls.push(ToolCall {
                        id: call.id,
                        name,
                        input,
                    });
                }
            }

            let stop_reason = match choice.finish_reason.as_deref() {
                Some("stop") => StopReason::EndTurn,
                Some("tool_calls") => StopReason::ToolUse,
                Some("length") => StopReason::MaxTokens,
                _ => {
                    if !tool_calls.is_empty() {
                        StopReason::ToolUse
                    } else {
                        StopReason::EndTurn
                    }
                }
            };

            // Report cache effectiveness. OpenAI's `prompt_tokens` already
            // INCLUDES cached tokens, so accounting needs no adjustment here —
            // unlike Anthropic, where cached reads are reported separately and
            // must be added back in. Logging the split is what makes the
            // existing automatic caching observable.
            if let Some(cached) = oai_response
                .usage
                .as_ref()
                .and_then(|u| u.prompt_tokens_details)
                .map(|d| d.cached_tokens)
                .filter(|c| *c > 0)
            {
                let total = oai_response
                    .usage
                    .as_ref()
                    .map(|u| u.prompt_tokens)
                    .unwrap_or(0);
                let hit_pct = (cached * 100).checked_div(total).unwrap_or(0);
                debug!(
                    cached_tokens = cached,
                    prompt_tokens = total,
                    hit_pct,
                    "OpenAI prompt cache"
                );
            }

            let mut usage = oai_response
                .usage
                .map(|u| TokenUsage {
                    input_tokens: u.prompt_tokens,
                    output_tokens: u.completion_tokens,
                })
                .unwrap_or_default();

            // Guard: if the model returned content but usage is missing/zero
            // (common with local LLMs like LM Studio, Ollama), set a synthetic
            // non-zero output_tokens so the agent loop doesn't misclassify
            // this as a "silent failure" and loop unnecessarily.
            if !content.is_empty() && usage.input_tokens == 0 && usage.output_tokens == 0 {
                debug!(
                    "Response has content but no usage stats â€” setting synthetic output_tokens=1"
                );
                usage.output_tokens = 1;
            }

            return Ok(CompletionResponse {
                content,
                stop_reason,
                tool_calls,
                usage,
            });
        }

        Err(LlmError::Api {
            status: 0,
            message: "Max retries exceeded".to_string(),
        })
    }

    async fn stream(
        &self,
        request: CompletionRequest,
        tx: tokio::sync::mpsc::Sender<StreamEvent>,
    ) -> Result<CompletionResponse, LlmError> {
        // Build request (same as complete but with stream: true)
        let mut oai_messages: Vec<OaiMessage> = Vec::new();

        if let Some(ref system) = request.system {
            oai_messages.push(OaiMessage {
                role: "system".to_string(),
                content: Some(OaiMessageContent::Text(system.clone())),
                tool_calls: None,
                tool_call_id: None,
                reasoning_content: None,
                reasoning: None,
            });
        }

        for msg in &request.messages {
            match (&msg.role, &msg.content) {
                (Role::System, MessageContent::Text(text)) if request.system.is_none() => {
                    oai_messages.push(OaiMessage {
                        role: "system".to_string(),
                        content: Some(OaiMessageContent::Text(text.clone())),
                        tool_calls: None,
                        tool_call_id: None,
                        reasoning_content: None,
                        reasoning: None,
                    });
                }
                (Role::User, MessageContent::Text(text)) => {
                    oai_messages.push(OaiMessage {
                        role: "user".to_string(),
                        content: Some(OaiMessageContent::Text(text.clone())),
                        tool_calls: None,
                        tool_call_id: None,
                        reasoning_content: None,
                        reasoning: None,
                    });
                }
                (Role::Assistant, MessageContent::Text(text)) => {
                    oai_messages.push(OaiMessage {
                        role: "assistant".to_string(),
                        content: Some(OaiMessageContent::Text(text.clone())),
                        tool_calls: None,
                        tool_call_id: None,
                        reasoning_content: None,
                        reasoning: None,
                    });
                }
                (Role::User, MessageContent::Blocks(blocks)) => {
                    for block in blocks {
                        if let ContentBlock::ToolResult {
                            tool_use_id,
                            content,
                            ..
                        } = block
                        {
                            oai_messages.push(OaiMessage {
                                role: "tool".to_string(),
                                content: Some(OaiMessageContent::Text(if content.is_empty() {
                                    "(empty)".to_string()
                                } else {
                                    content.clone()
                                })),
                                tool_calls: None,
                                tool_call_id: Some(tool_use_id.clone()),
                                reasoning_content: None,
                                reasoning: None,
                            });
                        }
                    }
                }
                (Role::Assistant, MessageContent::Blocks(blocks)) => {
                    let assembled = assemble_assistant_message(blocks, &request.model, self);
                    oai_messages.push(assembled);
                }
                _ => {}
            }
        }

        strip_empty_assistant_messages(&mut oai_messages);

        let oai_tools: Vec<OaiTool> = request
            .tools
            .iter()
            .map(|t| OaiTool {
                tool_type: "function".to_string(),
                function: OaiToolDef {
                    name: sanitize_tool_name(&t.name),
                    description: t.description.clone(),
                    parameters: t3rnel_types::tool::normalize_schema_for_provider(
                        &t.input_schema,
                        "openai",
                    ),
                },
            })
            .collect();

        let tool_choice = if oai_tools.is_empty() {
            None
        } else {
            Some(serde_json::json!("auto"))
        };

        let (mt, mct) = if uses_completion_tokens(&request.model) {
            (None, Some(request.max_tokens))
        } else {
            (Some(request.max_tokens), None)
        };
        let mut oai_request = OaiRequest {
            model: request.model.clone(),
            messages: oai_messages,
            max_tokens: mt,
            max_completion_tokens: mct,
            temperature: if self.needs_reasoning_content(&request.model) {
                Some(0.6)
            } else if temperature_must_be_one(&request.model) {
                Some(1.0)
            } else if rejects_temperature(&request.model) {
                None
            } else {
                Some(request.temperature)
            },
            tools: oai_tools,
            tool_choice,
            stream: true,
            stream_options: Some(serde_json::json!({"include_usage": true})),
            thinking: if self.needs_reasoning_content(&request.model) {
                Some(serde_json::json!({"type": "disabled"}))
            } else {
                None
            },
            reasoning_effort: request_reasoning_effort(&request),
        };

        // Retry loop for the initial HTTP request
        let max_retries = 3;
        for attempt in 0..=max_retries {
            let url = self.chat_url(&request.model);
            debug!(url = %url, attempt, "Sending OpenAI streaming request");

            let req_builder = self
                .client
                .post(&url)
                .header("content-type", "application/json")
                .json(&oai_request);

            let mut req_builder = self.apply_auth(req_builder);
            for (k, v) in &self.extra_headers {
                req_builder = req_builder.header(k, v);
            }

            let resp = req_builder
                .send()
                .await
                .map_err(|e| LlmError::Http(e.to_string()))?;

            let status = resp.status().as_u16();
            if status == 429 {
                if attempt < max_retries {
                    let retry_ms = crate::retry::compute_backoff(
                        &crate::retry::llm_retry_config(),
                        attempt as u32,
                    );
                    warn!(status, retry_ms, "Rate limited (stream), retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(retry_ms)).await;
                    continue;
                }
                return Err(LlmError::RateLimited {
                    retry_after_ms: 5000,
                });
            }

            if !resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();

                // Groq "tool_use_failed": parse and recover (streaming path)
                if status == 400 && body.contains("tool_use_failed") {
                    if let Some(response) = parse_groq_failed_tool_call(&body) {
                        warn!("Recovered tool call from Groq failed_generation (stream)");
                        return Ok(response);
                    }
                    if attempt < max_retries {
                        let retry_ms = crate::retry::compute_backoff(
                            &crate::retry::llm_retry_config(),
                            attempt as u32,
                        );
                        warn!(
                            status,
                            attempt, retry_ms, "tool_use_failed (stream), retrying"
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(retry_ms)).await;
                        continue;
                    }
                }

                // o-series / reasoning models: strip temperature if rejected
                if status == 400
                    && body.contains("temperature")
                    && body.contains("unsupported_parameter")
                    && oai_request.temperature.is_some()
                    && attempt < max_retries
                {
                    warn!(model = %oai_request.model, "Stripping temperature for this model (stream)");
                    oai_request.temperature = None;
                    continue;
                }

                if status == 400
                    && body.contains("reasoning_effort")
                    && oai_request.reasoning_effort.is_some()
                    && attempt < max_retries
                {
                    warn!(model = %oai_request.model, "Stripping reasoning_effort for this provider (stream)");
                    oai_request.reasoning_effort = None;
                    continue;
                }

                // GPT-5 / o-series: switch from max_tokens to max_completion_tokens
                if status == 400
                    && body.contains("max_tokens")
                    && (body.contains("unsupported_parameter")
                        || body.contains("max_completion_tokens"))
                    && oai_request.max_tokens.is_some()
                    && attempt < max_retries
                {
                    let val = oai_request.max_tokens.unwrap();
                    warn!(model = %oai_request.model, "Switching to max_completion_tokens for this model (stream)");
                    oai_request.max_tokens = None;
                    oai_request.max_completion_tokens = Some(val);
                    continue;
                }

                // Auto-cap max_tokens when model rejects our value
                if status == 400 && body.contains("max_tokens") && attempt < max_retries {
                    let current = oai_request
                        .max_tokens
                        .or(oai_request.max_completion_tokens)
                        .unwrap_or(4096);
                    let cap = extract_max_tokens_limit(&body).unwrap_or(current / 2);
                    warn!(old = current, new = cap, "Auto-capping max_tokens (stream)");
                    if oai_request.max_completion_tokens.is_some() {
                        oai_request.max_completion_tokens = Some(cap);
                    } else {
                        oai_request.max_tokens = Some(cap);
                    }
                    continue;
                }

                // Provider doesn't support stream_options â€” retry without it
                if status == 400
                    && oai_request.stream_options.is_some()
                    && attempt < max_retries
                    && (body.contains("stream_options")
                        || body.contains("stream_option")
                        || body.contains("Unrecognized request argument"))
                {
                    warn!(model = %oai_request.model, "Stripping stream_options (unsupported by provider)");
                    oai_request.stream_options = None;
                    continue;
                }

                // Model doesn't support function calling â€” retry without tools
                let body_lower = body.to_lowercase();
                if !oai_request.tools.is_empty()
                    && attempt < max_retries
                    && (status == 500
                        || body_lower.contains("internal error")
                        || (status == 400
                            && (body_lower.contains("does not support tools")
                                || body_lower.contains("tool")
                                    && body_lower.contains("not supported"))))
                {
                    warn!(
                        model = %oai_request.model,
                        status,
                        "Model may not support tools (stream), retrying without tools"
                    );
                    oai_request.tools.clear();
                    oai_request.tool_choice = None;
                    continue;
                }

                return Err(LlmError::Api {
                    status,
                    message: body,
                });
            }

            // Parse the SSE stream
            let mut buffer = String::new();
            let mut text_content = String::new();
            let mut reasoning_content = String::new();
            // Filter <think>...</think> tags from streaming text deltas so they
            // don't leak through to the client as visible text.
            let mut think_filter = StreamingThinkFilter::new();
            // Track tool calls: index -> (id, name, arguments)
            let mut tool_accum: Vec<(String, String, String)> = Vec::new();
            let mut finish_reason: Option<String> = None;
            let mut usage = TokenUsage::default();
            let mut chunk_count: u32 = 0;
            let mut sse_line_count: u32 = 0;

            let mut byte_stream = resp.bytes_stream();
            while let Some(chunk_result) = byte_stream.next().await {
                let chunk = chunk_result.map_err(|e| LlmError::Http(e.to_string()))?;
                chunk_count += 1;
                buffer.push_str(&String::from_utf8_lossy(&chunk));

                // Process complete lines
                while let Some(pos) = buffer.find('\n') {
                    let line = buffer[..pos].trim_end().to_string();
                    buffer = buffer[pos + 1..].to_string();

                    if line.is_empty() || line.starts_with(':') {
                        continue;
                    }

                    sse_line_count += 1;
                    let data = match line.strip_prefix("data:") {
                        Some(d) => d.trim_start(),
                        None => continue,
                    };

                    if data == "[DONE]" {
                        continue;
                    }

                    let json: serde_json::Value = match serde_json::from_str(data) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    // Extract usage if present (some providers send it in the last chunk)
                    if let Some(u) = json.get("usage") {
                        if let Some(pt) = u["prompt_tokens"].as_u64() {
                            usage.input_tokens = pt;
                        }
                        if let Some(ct) = u["completion_tokens"].as_u64() {
                            usage.output_tokens = ct;
                        }
                    }

                    let choices = match json["choices"].as_array() {
                        Some(c) => c,
                        None => continue,
                    };

                    for choice in choices {
                        let delta = &choice["delta"];

                        // Text content delta â€” route through think filter to
                        // strip <think>...</think> tags before they reach the client.
                        if let Some(text) = delta["content"].as_str() {
                            if !text.is_empty() {
                                text_content.push_str(text);
                                for action in think_filter.process(text) {
                                    match action {
                                        FilterAction::EmitText(t) => {
                                            let _ =
                                                tx.send(StreamEvent::TextDelta { text: t }).await;
                                        }
                                        FilterAction::EmitThinking(t) => {
                                            // Route think content the same way as
                                            // reasoning_content deltas.
                                            let _ = tx
                                                .send(StreamEvent::ThinkingDelta { text: t })
                                                .await;
                                        }
                                    }
                                }
                            }
                        }

                        // Reasoning/thinking content delta (DeepSeek-R1, Qwen3 via LM Studio/Ollama)
                        if let Some(reasoning) = delta["reasoning_content"]
                            .as_str()
                            .or_else(|| delta["reasoning"].as_str())
                        {
                            if !reasoning.is_empty() {
                                reasoning_content.push_str(reasoning);
                                let _ = tx
                                    .send(StreamEvent::ThinkingDelta {
                                        text: reasoning.to_string(),
                                    })
                                    .await;
                            }
                        }

                        // Tool call deltas
                        if let Some(calls) = delta["tool_calls"].as_array() {
                            for call in calls {
                                let idx = call["index"].as_u64().unwrap_or(0) as usize;

                                // Ensure tool_accum has enough entries
                                while tool_accum.len() <= idx {
                                    tool_accum.push((String::new(), String::new(), String::new()));
                                }

                                // ID (sent in first chunk for this tool)
                                if let Some(id) = call["id"].as_str() {
                                    // Fix: Empty string IDs are overwritten, leading to inconsistencies in certain models.
                                    if !id.is_empty() {
                                        tool_accum[idx].0 = id.to_string();
                                    }
                                }

                                if let Some(func) = call.get("function") {
                                    // Name (sent in first chunk)
                                    if let Some(name) = func["name"].as_str() {
                                        tool_accum[idx].1 = name.to_string();
                                        let _ = tx
                                            .send(StreamEvent::ToolUseStart {
                                                id: tool_accum[idx].0.clone(),
                                                name: name.to_string(),
                                            })
                                            .await;
                                    }

                                    // Arguments delta
                                    if let Some(args) = func["arguments"].as_str() {
                                        tool_accum[idx].2.push_str(args);
                                        if !args.is_empty() {
                                            let _ = tx
                                                .send(StreamEvent::ToolInputDelta {
                                                    text: args.to_string(),
                                                })
                                                .await;
                                        }
                                    }
                                }
                            }
                        }

                        // Finish reason
                        if let Some(fr) = choice["finish_reason"].as_str() {
                            finish_reason = Some(fr.to_string());
                        }
                    }
                }
            }

            // Flush any remaining buffered content from the think filter
            // (e.g. partial tag at stream end, or unclosed think block).
            for action in think_filter.flush() {
                match action {
                    FilterAction::EmitText(t) => {
                        let _ = tx.send(StreamEvent::TextDelta { text: t }).await;
                    }
                    FilterAction::EmitThinking(t) => {
                        let _ = tx.send(StreamEvent::ThinkingDelta { text: t }).await;
                    }
                }
            }

            // Log stream summary for diagnostics
            let is_empty_stream = text_content.is_empty()
                && reasoning_content.is_empty()
                && tool_accum.is_empty()
                && usage.input_tokens == 0
                && usage.output_tokens == 0;
            if is_empty_stream {
                warn!(
                    chunks = chunk_count,
                    sse_lines = sse_line_count,
                    finish = ?finish_reason,
                    buffer_remaining = buffer.len(),
                    "SSE stream returned empty: 0 content, 0 tokens â€” likely a silently failed request"
                );
            } else {
                debug!(
                    chunks = chunk_count,
                    sse_lines = sse_line_count,
                    text_len = text_content.len(),
                    reasoning_len = reasoning_content.len(),
                    tool_count = tool_accum.len(),
                    finish = ?finish_reason,
                    input_tokens = usage.input_tokens,
                    output_tokens = usage.output_tokens,
                    buffer_remaining = buffer.len(),
                    "SSE stream completed"
                );
            }

            // Build the final response
            let mut content = Vec::new();
            let mut tool_calls = Vec::new();

            // Add reasoning/thinking content if present
            if !reasoning_content.is_empty() {
                // Mark format so outbound path replays this as
                // `reasoning_content` (DeepSeek-R1, Qwen3, MiniMax via
                // LM Studio/Ollama). Issue #1098.
                content.push(ContentBlock::Thinking {
                    thinking: reasoning_content.clone(),
                    signature: None,
                    provider_metadata: Some(serde_json::json!({
                        "format": "reasoning_content"
                    })),
                });
            }

            if !text_content.is_empty() {
                // Extract <think>...</think> blocks from streamed text content
                let (cleaned, thinking) = extract_think_tags(&text_content);
                if let Some(think_text) = thinking {
                    // Only add if we didn't already get reasoning_content
                    if reasoning_content.is_empty() {
                        // Mark as inline-think so the next outbound turn
                        // re-emits the content wrapped in `<think>...</think>`.
                        content.push(ContentBlock::Thinking {
                            thinking: think_text,
                            signature: None,
                            provider_metadata: Some(serde_json::json!({
                                "format": "inline_think"
                            })),
                        });
                    }
                }
                if !cleaned.is_empty() {
                    content.push(ContentBlock::Text {
                        text: cleaned,
                        provider_metadata: None,
                    });
                }
            }

            // If we have reasoning but no text content and no tool calls,
            // synthesize a brief text block so the agent loop doesn't treat
            // this as an empty response.
            let has_text = content
                .iter()
                .any(|b| matches!(b, ContentBlock::Text { .. }));
            let has_thinking = content
                .iter()
                .any(|b| matches!(b, ContentBlock::Thinking { .. }));
            if has_thinking && !has_text && tool_accum.is_empty() {
                let thinking_text = content
                    .iter()
                    .find_map(|b| match b {
                        ContentBlock::Thinking { thinking, .. } => Some(thinking.as_str()),
                        _ => None,
                    })
                    .unwrap_or("");
                let summary = extract_thinking_summary(thinking_text);
                debug!(
                    summary_len = summary.len(),
                    "Synthesizing text from thinking-only stream response"
                );
                content.push(ContentBlock::Text {
                    text: summary,
                    provider_metadata: None,
                });
            }

            for (id, name, arguments) in &tool_accum {
                // Skip malformed tool calls (empty ID or name can happen if
                // streaming chunks arrive out of order or are dropped by proxy).
                if id.is_empty() || name.is_empty() {
                    warn!(
                        tool_id = %id,
                        tool_name = %name,
                        "Skipping tool call with empty ID or name from streaming response"
                    );
                    continue;
                }
                let input: serde_json::Value =
                    serde_json::from_str(arguments).unwrap_or_else(|_| serde_json::json!({}));
                // Same round-trip as the non-streaming path: the model echoes the
                // sanitized name, so map it back to the registered tool.
                let name = desanitize_tool_name(name, &request.tools);
                content.push(ContentBlock::ToolUse {
                    id: id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                    provider_metadata: None,
                });
                tool_calls.push(ToolCall {
                    id: id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                });

                let _ = tx
                    .send(StreamEvent::ToolUseEnd {
                        id: id.clone(),
                        name,
                        input,
                    })
                    .await;
            }

            let stop_reason = match finish_reason.as_deref() {
                Some("stop") => StopReason::EndTurn,
                Some("tool_calls") => StopReason::ToolUse,
                Some("length") => StopReason::MaxTokens,
                _ => {
                    if !tool_calls.is_empty() {
                        StopReason::ToolUse
                    } else {
                        StopReason::EndTurn
                    }
                }
            };

            // Guard: if the model returned content but usage is missing/zero
            // (common with local LLMs like LM Studio, Ollama), set a synthetic
            // non-zero output_tokens so the agent loop doesn't misclassify
            // this as a "silent failure" and loop unnecessarily.
            if !content.is_empty() && usage.input_tokens == 0 && usage.output_tokens == 0 {
                debug!(
                    "Stream has content but no usage stats â€” setting synthetic output_tokens=1"
                );
                usage.output_tokens = 1;
            }

            let _ = tx
                .send(StreamEvent::ContentComplete { stop_reason, usage })
                .await;

            return Ok(CompletionResponse {
                content,
                stop_reason,
                tool_calls,
                usage,
            });
        }

        Err(LlmError::Api {
            status: 0,
            message: "Max retries exceeded".to_string(),
        })
    }
}

/// Extract `<think>...</think>` blocks from content text.
///
/// Some local LLMs (Qwen3, DeepSeek-R1) embed their reasoning directly in the
/// content field wrapped in `<think>` tags. This function separates the thinking
/// from the actual response text.
///
/// Returns `(cleaned_text, Option<thinking_text>)`.
fn extract_think_tags(text: &str) -> (String, Option<String>) {
    let mut thinking_parts = Vec::new();
    let mut cleaned = text.to_string();

    // Extract all <think>...</think> blocks (greedy within each block)
    while let Some(start) = cleaned.find("<think>") {
        if let Some(end) = cleaned.find("</think>") {
            let think_start = start + "<think>".len();
            if think_start <= end {
                let thought = cleaned[think_start..end].trim().to_string();
                if !thought.is_empty() {
                    thinking_parts.push(thought);
                }
                // Remove the entire <think>...</think> block
                cleaned = format!(
                    "{}{}",
                    &cleaned[..start],
                    &cleaned[end + "</think>".len()..]
                );
            } else {
                break;
            }
        } else {
            // Unclosed <think> tag â€” treat everything after as thinking
            let thought = cleaned[start + "<think>".len()..].trim().to_string();
            if !thought.is_empty() {
                thinking_parts.push(thought);
            }
            cleaned = cleaned[..start].to_string();
            break;
        }
    }

    let cleaned = cleaned.trim().to_string();
    if thinking_parts.is_empty() {
        (cleaned, None)
    } else {
        (cleaned, Some(thinking_parts.join("\n\n")))
    }
}

/// Extract a usable summary from thinking-only output.
///
/// When a local model returns only thinking/reasoning with no actual response text,
/// we extract the last meaningful paragraph as a synthesized response rather than
/// showing "empty response" to the user.
fn extract_thinking_summary(thinking: &str) -> String {
    let trimmed = thinking.trim();
    if trimmed.is_empty() {
        return "[The model produced reasoning but no final answer. Try rephrasing your question.]"
            .to_string();
    }

    // Take the last non-empty paragraph (models usually conclude with their answer)
    let paragraphs: Vec<&str> = trimmed
        .split("\n\n")
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect();

    if let Some(last) = paragraphs.last() {
        // If the last paragraph is reasonably short, use it directly
        if last.len() <= 2000 {
            last.to_string()
        } else {
            // Take the last 2000 chars
            last[last.len() - 2000..].to_string()
        }
    } else {
        "[The model produced reasoning but no final answer. Try rephrasing your question.]"
            .to_string()
    }
}

/// Parse Groq's `tool_use_failed` error and extract the tool call from `failed_generation`.
/// Extract the max_tokens limit from an API error message.
/// Looks for patterns like: `must be less than or equal to \`8192\``
fn extract_max_tokens_limit(body: &str) -> Option<u32> {
    // Pattern: "must be <= `N`" or "must be less than or equal to `N`"
    let patterns = [
        "less than or equal to `",
        "must be <= `",
        "maximum value for `max_tokens` is `",
    ];
    for pat in &patterns {
        if let Some(idx) = body.find(pat) {
            let after = &body[idx + pat.len()..];
            let end = after
                .find('`')
                .or_else(|| after.find('"'))
                .unwrap_or(after.len());
            if let Ok(n) = after[..end].trim().parse::<u32>() {
                return Some(n);
            }
        }
    }
    None
}

///
/// Some models (e.g. Llama 3.3) generate tool calls as XML: `<function=NAME ARGS></function>`
/// instead of the proper JSON format. Groq rejects these with `tool_use_failed` but includes
/// the raw generation. We parse it and construct a proper CompletionResponse.
fn parse_groq_failed_tool_call(body: &str) -> Option<CompletionResponse> {
    let json_body: serde_json::Value = serde_json::from_str(body).ok()?;
    let failed = json_body
        .pointer("/error/failed_generation")
        .and_then(|v| v.as_str())?;

    // Parse all tool calls from the failed generation.
    // Format: <function=tool_name{"arg":"val"}></function> or <function=tool_name {"arg":"val"}></function>
    let mut tool_calls = Vec::new();
    let mut remaining = failed;

    while let Some(start) = remaining.find("<function=") {
        remaining = &remaining[start + 10..]; // skip "<function="
                                              // Find the end tag
        let end = remaining.find("</function>")?;
        let mut call_content = &remaining[..end];
        remaining = &remaining[end + 11..]; // skip "</function>"

        // Strip trailing ">" from the XML opening tag close
        call_content = call_content.strip_suffix('>').unwrap_or(call_content);

        // Split into name and args: "tool_name{"arg":"val"}" or "tool_name {"arg":"val"}"
        let (name, args) = if let Some(brace_pos) = call_content.find('{') {
            let name = call_content[..brace_pos].trim();
            let args = &call_content[brace_pos..];
            (name, args)
        } else {
            // No args â€” just a tool name
            (call_content.trim(), "{}")
        };

        // Parse args as JSON Value
        let args_value: serde_json::Value =
            serde_json::from_str(args).unwrap_or(serde_json::json!({}));

        tool_calls.push(ToolCall {
            id: format!("groq_recovered_{}", tool_calls.len()),
            name: name.to_string(),
            input: args_value,
        });
    }

    if tool_calls.is_empty() {
        // No tool calls found â€” the model generated plain text but Groq rejected it.
        // Return it as a normal text response instead of failing.
        if !failed.trim().is_empty() {
            warn!("Recovering plain text from Groq failed_generation (no tool calls)");
            return Some(CompletionResponse {
                content: vec![ContentBlock::Text {
                    text: failed.to_string(),
                    provider_metadata: None,
                }],
                tool_calls: vec![],
                stop_reason: StopReason::EndTurn,
                usage: TokenUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                },
            });
        }
        return None;
    }

    Some(CompletionResponse {
        content: vec![],
        tool_calls,
        stop_reason: StopReason::ToolUse,
        usage: TokenUsage {
            input_tokens: 0,
            output_tokens: 0,
        },
    })
}

#[cfg(test)]
mod prompt_cache_tests {
    use super::*;

    #[test]
    fn cached_tokens_are_deserialized_when_present() {
        // OpenAI caches automatically above ~1024 tokens; the saving already
        // existed and was simply invisible because this field was dropped.
        let raw = r#"{
            "prompt_tokens": 5000,
            "completion_tokens": 120,
            "prompt_tokens_details": {"cached_tokens": 4096}
        }"#;
        let u: OaiUsage = serde_json::from_str(raw).unwrap();
        assert_eq!(u.prompt_tokens, 5000);
        assert_eq!(u.prompt_tokens_details.unwrap().cached_tokens, 4096);
    }

    #[test]
    fn openai_compatible_providers_without_the_field_still_parse() {
        // Groq, NVIDIA, Together and friends share this driver and omit the
        // details object entirely. Making it required would break every one of
        // them for the sake of a metric.
        let u: OaiUsage =
            serde_json::from_str(r#"{"prompt_tokens": 10, "completion_tokens": 3}"#).unwrap();
        assert!(u.prompt_tokens_details.is_none());
    }

    #[test]
    fn a_details_object_without_cached_tokens_defaults_to_zero() {
        let u: OaiUsage = serde_json::from_str(
            r#"{"prompt_tokens": 10, "completion_tokens": 3, "prompt_tokens_details": {}}"#,
        )
        .unwrap();
        assert_eq!(u.prompt_tokens_details.unwrap().cached_tokens, 0);
    }

    #[test]
    fn prompt_tokens_already_include_cached_so_accounting_is_unchanged() {
        // This is the load-bearing difference from Anthropic. OpenAI reports
        // prompt_tokens INCLUSIVE of cached ones, so adding cached_tokens back
        // in — as the Anthropic driver correctly does — would double-count here
        // and inflate every budget check.
        let u: OaiUsage = serde_json::from_str(
            r#"{"prompt_tokens": 5000, "completion_tokens": 1,
                "prompt_tokens_details": {"cached_tokens": 4096}}"#,
        )
        .unwrap();
        let accounted = TokenUsage {
            input_tokens: u.prompt_tokens,
            output_tokens: u.completion_tokens,
        };
        assert_eq!(
            accounted.input_tokens, 5000,
            "must not add cached_tokens on top of prompt_tokens"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oai_msg(role: &str, content: Option<&str>, tool_calls: bool) -> OaiMessage {
        OaiMessage {
            role: role.to_string(),
            content: content.map(|c| OaiMessageContent::Text(c.to_string())),
            tool_calls: tool_calls.then(|| {
                vec![OaiToolCall {
                    id: "call_1".into(),
                    call_type: "function".into(),
                    function: OaiFunction {
                        name: "f".into(),
                        arguments: "{}".into(),
                    },
                }]
            }),
            tool_call_id: None,
            reasoning_content: None,
            reasoning: None,
        }
    }

    /// NVIDIA NIM rejects tool names outside `[A-Za-z0-9_-]`, failing the whole
    /// request; t3rnel's tool names are dotted (`fs.read`).
    #[test]
    fn tool_names_are_sanitized_for_strict_providers() {
        assert_eq!(sanitize_tool_name("fs.read"), "fs_read");
        assert_eq!(sanitize_tool_name("shell.exec"), "shell_exec");
        assert_eq!(sanitize_tool_name("web_search"), "web_search");
        assert_eq!(sanitize_tool_name("already-fine"), "already-fine");
    }

    /// The model echoes back the sanitized name, so it must map to the original
    /// or the call matches no registered tool.
    #[test]
    fn sanitized_tool_names_round_trip() {
        let tools = vec![
            t3rnel_types::tool::ToolDefinition {
                name: "fs.read".into(),
                description: String::new(),
                input_schema: serde_json::json!({}),
            },
            t3rnel_types::tool::ToolDefinition {
                name: "web_search".into(),
                description: String::new(),
                input_schema: serde_json::json!({}),
            },
        ];
        assert_eq!(desanitize_tool_name("fs_read", &tools), "fs.read");
        // An exact match must win over any fuzzy mapping.
        assert_eq!(desanitize_tool_name("web_search", &tools), "web_search");
        // Unknown names pass through unchanged rather than being dropped.
        assert_eq!(desanitize_tool_name("mystery", &tools), "mystery");
    }

    /// Mistral rejects ANY assistant message with neither content nor tool_calls
    /// (HTTP 400 `invalid_request_assistant_message`), not just a trailing one.
    #[test]
    fn strips_empty_assistant_messages_anywhere_in_history() {
        let mut msgs = vec![
            oai_msg("user", Some("hi"), false),
            oai_msg("assistant", None, false),
            oai_msg("user", Some("still there?"), false),
            oai_msg("assistant", Some("   "), false),
            oai_msg("user", Some("say ok"), false),
        ];
        strip_empty_assistant_messages(&mut msgs);
        assert_eq!(msgs.len(), 3);
        assert!(msgs.iter().all(|m| m.role == "user"));
    }

    /// An assistant message carrying tool calls is never empty, so it must be
    /// kept — dropping it would orphan the following `tool` message.
    #[test]
    fn keeps_assistant_messages_that_carry_tool_calls() {
        let mut msgs = vec![
            oai_msg("user", Some("weather?"), false),
            oai_msg("assistant", None, true),
            oai_msg("tool", Some("sunny"), false),
        ];
        strip_empty_assistant_messages(&mut msgs);
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[1].role, "assistant");
    }

    #[test]
    fn test_openai_driver_creation() {
        let driver = OpenAIDriver::new("test-key".to_string(), "http://localhost".to_string());
        assert_eq!(driver.api_key.as_str(), "test-key");
    }

    #[test]
    fn test_parse_groq_failed_tool_call() {
        let body = r#"{"error":{"message":"Failed to call a function.","type":"invalid_request_error","code":"tool_use_failed","failed_generation":"<function=web_fetch{\"url\": \"https://example.com\"}></function>\n"}}"#;
        let result = parse_groq_failed_tool_call(body);
        assert!(result.is_some());
        let resp = result.unwrap();
        assert_eq!(resp.tool_calls.len(), 1);
        assert_eq!(resp.tool_calls[0].name, "web_fetch");
        assert!(resp.tool_calls[0]
            .input
            .to_string()
            .contains("https://example.com"));
    }

    #[test]
    fn test_parse_groq_failed_tool_call_with_space() {
        let body = r#"{"error":{"message":"Failed","type":"invalid_request_error","code":"tool_use_failed","failed_generation":"<function=shell_exec {\"command\": \"ls -la\"}></function>"}}"#;
        let result = parse_groq_failed_tool_call(body);
        assert!(result.is_some());
        let resp = result.unwrap();
        assert_eq!(resp.tool_calls[0].name, "shell_exec");
    }

    // ----- rejects_temperature tests -----

    #[test]
    fn test_rejects_temperature_o1_models() {
        assert!(rejects_temperature("o1"));
        assert!(rejects_temperature("o1-mini"));
        assert!(rejects_temperature("o1-mini-2024-09-12"));
        assert!(rejects_temperature("o1-preview"));
        assert!(rejects_temperature("o1-preview-2024-09-12"));
    }

    #[test]
    fn test_rejects_temperature_o3_models() {
        assert!(rejects_temperature("o3"));
        assert!(rejects_temperature("o3-mini"));
        assert!(rejects_temperature("o3-mini-2025-01-31"));
        assert!(rejects_temperature("o3-pro"));
    }

    #[test]
    fn test_rejects_temperature_o4_models() {
        assert!(rejects_temperature("o4-mini"));
        assert!(rejects_temperature("o4-mini-2025-04-16"));
    }

    #[test]
    fn test_rejects_temperature_gpt5_mini() {
        assert!(rejects_temperature("gpt-5-mini"));
        assert!(rejects_temperature("gpt-5-mini-2025-08-07"));
        assert!(rejects_temperature("gpt5-mini"));
        assert!(rejects_temperature("GPT-5-MINI-2025-08-07"));
    }

    #[test]
    fn test_rejects_temperature_reasoning_suffix() {
        assert!(rejects_temperature("some-model-reasoning"));
        assert!(rejects_temperature("deepseek-r1-reasoning"));
    }

    #[test]
    fn test_does_not_reject_temperature_normal_models() {
        assert!(!rejects_temperature("gpt-4o"));
        assert!(!rejects_temperature("gpt-4o-mini"));
        assert!(!rejects_temperature("gpt-5"));
        assert!(!rejects_temperature("gpt-5-2025-06-01"));
        assert!(!rejects_temperature("claude-sonnet-4-20250514"));
        assert!(!rejects_temperature("llama-3.3-70b-versatile"));
        assert!(!rejects_temperature("deepseek-chat"));
    }

    // ----- uses_completion_tokens tests -----

    #[test]
    fn test_uses_completion_tokens_gpt5() {
        assert!(uses_completion_tokens("gpt-5"));
        assert!(uses_completion_tokens("gpt-5-mini"));
        assert!(uses_completion_tokens("gpt-5-mini-2025-08-07"));
        assert!(uses_completion_tokens("gpt5-mini"));
    }

    #[test]
    fn test_uses_completion_tokens_o_series() {
        assert!(uses_completion_tokens("o1"));
        assert!(uses_completion_tokens("o1-mini"));
        assert!(uses_completion_tokens("o3"));
        assert!(uses_completion_tokens("o3-mini"));
        assert!(uses_completion_tokens("o3-pro"));
        assert!(uses_completion_tokens("o4-mini"));
    }

    #[test]
    fn test_does_not_use_completion_tokens_normal_models() {
        assert!(!uses_completion_tokens("gpt-4o"));
        assert!(!uses_completion_tokens("gpt-4o-mini"));
        assert!(!uses_completion_tokens("llama-3.3-70b"));
    }

    // ----- reasoning_effort tests -----

    fn effort_request(model: &str, effort: Option<&str>) -> CompletionRequest {
        CompletionRequest {
            model: model.to_string(),
            messages: vec![],
            tools: vec![],
            max_tokens: 100,
            temperature: 0.0,
            system: None,
            thinking: None,
            reasoning_effort: effort.map(str::to_string),
        }
    }

    #[test]
    fn test_manifest_reasoning_effort_is_sent_as_is_for_any_model() {
        assert_eq!(request_reasoning_effort(&effort_request("gpt-6-luna", Some("high"))).as_deref(), Some("high"));
        assert_eq!(request_reasoning_effort(&effort_request("gpt-6-luna", Some("max"))).as_deref(), Some("max"));
        assert_eq!(request_reasoning_effort(&effort_request("gpt-5.5", Some("low"))).as_deref(), Some("low"));
    }

    #[test]
    fn test_without_a_manifest_effort_the_model_family_decides() {
        assert_eq!(request_reasoning_effort(&effort_request("gpt-6-luna", None)), None);
        assert_eq!(request_reasoning_effort(&effort_request("gpt-6-luna", Some("  "))), None);
        assert_eq!(request_reasoning_effort(&effort_request("gpt-5.5", None)).as_deref(), Some("high"));
    }

    #[test]
    fn test_gpt_5_5_defaults_to_high_reasoning() {
        assert_eq!(
            reasoning_effort_for_model("gpt-5.5", None).as_deref(),
            Some("high")
        );
        assert_eq!(
            reasoning_effort_for_model("chatgpt-5.5", None).as_deref(),
            None,
            "aliases must be resolved by the model catalog before the driver"
        );
    }

    #[test]
    fn test_reasoning_effort_from_thinking_budget() {
        let low = ThinkingConfig {
            budget_tokens: 4_000,
            stream_thinking: false,
        };
        let medium = ThinkingConfig {
            budget_tokens: 10_000,
            stream_thinking: false,
        };
        let high = ThinkingConfig {
            budget_tokens: 25_000,
            stream_thinking: true,
        };
        assert_eq!(
            reasoning_effort_for_model("gpt-5", Some(&low)).as_deref(),
            Some("low")
        );
        assert_eq!(
            reasoning_effort_for_model("gpt-5", Some(&medium)).as_deref(),
            Some("medium")
        );
        assert_eq!(
            reasoning_effort_for_model("o4-mini", Some(&high)).as_deref(),
            Some("high")
        );
    }

    #[test]
    fn test_reasoning_effort_omitted_for_non_reasoning_models() {
        assert_eq!(reasoning_effort_for_model("gpt-4o", None), None);
        assert_eq!(
            reasoning_effort_for_model("gpt-4o", Some(&ThinkingConfig::default())),
            None
        );
        assert_eq!(reasoning_effort_for_model("llama-3.3-70b", None), None);
    }

    // ----- extract_max_tokens_limit tests -----

    #[test]
    fn test_extract_max_tokens_limit() {
        let body = r#"max_tokens must be less than or equal to `8192`"#;
        assert_eq!(extract_max_tokens_limit(body), Some(8192));
    }

    #[test]
    fn test_extract_max_tokens_limit_no_match() {
        assert_eq!(extract_max_tokens_limit("some random error"), None);
    }

    // ----- extract_think_tags tests -----

    #[test]
    fn test_extract_think_tags_no_tags() {
        let (cleaned, thinking) = extract_think_tags("Hello world");
        assert_eq!(cleaned, "Hello world");
        assert!(thinking.is_none());
    }

    #[test]
    fn test_extract_think_tags_with_thinking() {
        let input = "<think>Let me reason about this...</think>The answer is 42.";
        let (cleaned, thinking) = extract_think_tags(input);
        assert_eq!(cleaned, "The answer is 42.");
        assert_eq!(thinking.unwrap(), "Let me reason about this...");
    }

    #[test]
    fn test_extract_think_tags_only_thinking() {
        let input = "<think>I need to think about this carefully.\n\nThe user wants to know about Rust.</think>";
        let (cleaned, thinking) = extract_think_tags(input);
        assert_eq!(cleaned, "");
        assert!(thinking.is_some());
        assert!(thinking.unwrap().contains("think about this carefully"));
    }

    #[test]
    fn test_extract_think_tags_multiple_blocks() {
        let input =
            "<think>First thought</think>Middle text<think>Second thought</think>Final text";
        let (cleaned, thinking) = extract_think_tags(input);
        assert_eq!(cleaned, "Middle textFinal text");
        let t = thinking.unwrap();
        assert!(t.contains("First thought"));
        assert!(t.contains("Second thought"));
    }

    #[test]
    fn test_extract_think_tags_unclosed() {
        let input = "Some text<think>unclosed thinking content";
        let (cleaned, thinking) = extract_think_tags(input);
        assert_eq!(cleaned, "Some text");
        assert_eq!(thinking.unwrap(), "unclosed thinking content");
    }

    // ----- extract_thinking_summary tests -----

    #[test]
    fn test_extract_thinking_summary_empty() {
        let summary = extract_thinking_summary("");
        assert!(summary.contains("no final answer"));
    }

    #[test]
    fn test_extract_thinking_summary_single_paragraph() {
        let summary = extract_thinking_summary("The answer is 42.");
        assert_eq!(summary, "The answer is 42.");
    }

    #[test]
    fn test_extract_thinking_summary_multiple_paragraphs() {
        let input = "First I need to consider X.\n\nThen I should check Y.\n\nThe answer is 42.";
        let summary = extract_thinking_summary(input);
        assert_eq!(summary, "The answer is 42.");
    }

    // ----- reasoning_content deserialization test -----

    #[test]
    fn test_oai_response_message_with_reasoning_content() {
        let json =
            r#"{"content": null, "reasoning_content": "Let me think...", "tool_calls": null}"#;
        let msg: OaiResponseMessage = serde_json::from_str(json).unwrap();
        assert!(msg.content.is_none());
        assert_eq!(msg.reasoning_content.as_deref(), Some("Let me think..."));
    }

    #[test]
    fn test_oai_response_message_without_reasoning_content() {
        let json = r#"{"content": "Hello", "tool_calls": null}"#;
        let msg: OaiResponseMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.content.as_deref(), Some("Hello"));
        assert!(msg.reasoning_content.is_none());
    }

    #[test]
    fn test_oai_response_message_null_content_null_reasoning() {
        let json = r#"{"content": null, "tool_calls": null}"#;
        let msg: OaiResponseMessage = serde_json::from_str(json).unwrap();
        assert!(msg.content.is_none());
        assert!(msg.reasoning_content.is_none());
        assert!(msg.reasoning.is_none());
    }

    // ── Issue #1157: vLLM ≥ 0.19 reasoning field rename ─────────────────

    /// vLLM 0.19+ (PR #33402) returns `reasoning` instead of
    /// `reasoning_content`. We must accept the new name on ingress.
    #[test]
    fn test_oai_response_message_with_vllm_reasoning_field() {
        let json =
            r#"{"content": "Answer.", "reasoning": "I weighed A vs B.", "tool_calls": null}"#;
        let msg: OaiResponseMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.content.as_deref(), Some("Answer."));
        assert!(msg.reasoning_content.is_none());
        assert_eq!(msg.reasoning.as_deref(), Some("I weighed A vs B."));
        // reasoning_text() must surface the new field transparently.
        assert_eq!(msg.reasoning_text(), Some("I weighed A vs B."));
    }

    /// If a server sends both fields (during the transition), prefer the
    /// new `reasoning` name since that's what vLLM 0.19+ writes natively.
    #[test]
    fn test_reasoning_text_prefers_new_field() {
        let json = r#"{"content": null, "reasoning": "new", "reasoning_content": "old"}"#;
        let msg: OaiResponseMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.reasoning_text(), Some("new"));
    }

    /// If only the legacy field is set (older vLLM, DeepSeek, Ollama),
    /// `reasoning_text()` must still return it.
    #[test]
    fn test_reasoning_text_falls_back_to_legacy_field() {
        let json = r#"{"content": null, "reasoning_content": "legacy thinking"}"#;
        let msg: OaiResponseMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.reasoning_text(), Some("legacy thinking"));
    }

    /// Outbound assembler must emit BOTH `reasoning` and `reasoning_content`
    /// when a `Thinking` block carries the `reasoning_content` format hint,
    /// so the persisted thinking reaches the model regardless of whether
    /// the upstream server is pre- or post-vLLM 0.19.
    #[test]
    fn test_assemble_emits_both_reasoning_fields_for_vllm_compat() {
        let driver = OpenAIDriver::new("test".to_string(), "http://localhost:8000/v1".to_string());
        let blocks = vec![
            ContentBlock::Thinking {
                thinking: "MARKER-vllm-019".to_string(),
                signature: None,
                provider_metadata: Some(serde_json::json!({"format": "reasoning_content"})),
            },
            ContentBlock::Text {
                text: "final".to_string(),
                provider_metadata: None,
            },
        ];
        let msg = assemble_assistant_message(&blocks, "minimax-m2", &driver);
        assert_eq!(
            msg.reasoning_content.as_deref(),
            Some("MARKER-vllm-019"),
            "legacy reasoning_content field required for pre-0.19 vLLM and DeepSeek"
        );
        assert_eq!(
            msg.reasoning.as_deref(),
            Some("MARKER-vllm-019"),
            "new reasoning field required for vLLM ≥ 0.19 (PR #33402)"
        );

        // Serialize and confirm the wire shape has both keys at top level.
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["reasoning_content"], "MARKER-vllm-019");
        assert_eq!(json["reasoning"], "MARKER-vllm-019");
    }

    /// Non-reasoning models (gpt-4o, claude, …) must NOT carry either
    /// reasoning field on the wire. Regression guard for the dual-emit
    /// change in #1157.
    #[test]
    fn test_assemble_no_reasoning_fields_for_plain_model() {
        let driver = OpenAIDriver::new("test".to_string(), "https://api.openai.com/v1".to_string());
        let blocks = vec![ContentBlock::Text {
            text: "hi".to_string(),
            provider_metadata: None,
        }];
        let msg = assemble_assistant_message(&blocks, "gpt-4o", &driver);
        assert!(msg.reasoning_content.is_none());
        assert!(msg.reasoning.is_none());
        let json = serde_json::to_value(&msg).unwrap();
        assert!(json.get("reasoning").is_none());
        assert!(json.get("reasoning_content").is_none());
    }

    /// Moonshot/Kimi legacy contract: emit empty `reasoning_content` to
    /// disable thinking on tool-call multi-turn. Issue #1157 must not
    /// regress this — `reasoning` stays absent because Moonshot doesn't
    /// understand the new name.
    #[test]
    fn test_assemble_moonshot_keeps_legacy_field_only() {
        let driver =
            OpenAIDriver::new("test".to_string(), "https://api.moonshot.cn/v1".to_string());
        let blocks = vec![ContentBlock::ToolUse {
            id: "call_1".to_string(),
            name: "search".to_string(),
            input: serde_json::json!({"q": "x"}),
            provider_metadata: None,
        }];
        let msg = assemble_assistant_message(&blocks, "kimi-k2", &driver);
        assert_eq!(
            msg.reasoning_content.as_deref(),
            Some(""),
            "Moonshot Kimi requires empty reasoning_content on tool_calls turns"
        );
        assert!(
            msg.reasoning.is_none(),
            "Moonshot does not understand the new vLLM `reasoning` field"
        );
    }

    // â”€â”€ Azure OpenAI tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_azure_driver_creation() {
        let driver = OpenAIDriver::new_azure(
            "test-key".to_string(),
            "https://myresource.openai.azure.com/openai/deployments".to_string(),
        );
        assert!(driver.azure_mode);
    }

    #[test]
    fn test_standard_driver_not_azure() {
        let driver = OpenAIDriver::new(
            "test-key".to_string(),
            "https://api.openai.com/v1".to_string(),
        );
        assert!(!driver.azure_mode);
    }

    #[test]
    fn test_azure_chat_url() {
        let driver = OpenAIDriver::new_azure(
            "test-key".to_string(),
            "https://myresource.openai.azure.com/openai/deployments".to_string(),
        );
        let url = driver.chat_url("my-gpt4o-deployment");
        assert_eq!(
            url,
            "https://myresource.openai.azure.com/openai/deployments/my-gpt4o-deployment/chat/completions?api-version=2024-10-21"
        );
    }

    #[test]
    fn test_azure_chat_url_trailing_slash() {
        let driver = OpenAIDriver::new_azure(
            "test-key".to_string(),
            "https://myresource.openai.azure.com/openai/deployments/".to_string(),
        );
        let url = driver.chat_url("gpt-4o");
        assert_eq!(
            url,
            "https://myresource.openai.azure.com/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21"
        );
    }

    #[test]
    fn test_standard_chat_url() {
        let driver = OpenAIDriver::new(
            "test-key".to_string(),
            "https://api.openai.com/v1".to_string(),
        );
        let url = driver.chat_url("gpt-4o");
        assert_eq!(url, "https://api.openai.com/v1/chat/completions");
    }

    /// Regression test for #970: kimi-k2.5 on moonshot.ai should redirect to moonshot.cn
    #[test]
    fn test_kimi_k2_redirects_to_moonshot_cn() {
        let driver = OpenAIDriver::new(
            "test-key".to_string(),
            "https://api.moonshot.ai/v1".to_string(),
        );
        // kimi-k2.5 must go to the .cn endpoint
        let url = driver.chat_url("kimi-k2.5");
        assert_eq!(url, "https://api.moonshot.cn/v1/chat/completions");

        // kimi-k2 must also redirect
        let url = driver.chat_url("kimi-k2");
        assert_eq!(url, "https://api.moonshot.cn/v1/chat/completions");

        // moonshot-v1-128k should NOT redirect (stays on .ai)
        let url = driver.chat_url("moonshot-v1-128k");
        assert_eq!(url, "https://api.moonshot.ai/v1/chat/completions");
    }

    // â”€â”€ issue #1098: thinking-block round-trip â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Inline `<think>` blocks captured on ingress must be re-emitted in
    /// historical assistant turns so MiniMax-style models retain reasoning
    /// state across turns.
    #[test]
    fn test_assemble_assistant_replays_inline_think() {
        let driver = OpenAIDriver::new(
            "test".to_string(),
            "https://api.minimax.chat/v1".to_string(),
        );
        let blocks = vec![
            ContentBlock::Thinking {
                thinking: "step-by-step reasoning".to_string(),
                signature: None,
                provider_metadata: Some(serde_json::json!({"format": "inline_think"})),
            },
            ContentBlock::Text {
                text: "Hello, user.".to_string(),
                provider_metadata: None,
            },
        ];
        let msg = assemble_assistant_message(&blocks, "minimax-m2.5", &driver);
        let content = match msg.content {
            Some(OaiMessageContent::Text(t)) => t,
            _ => panic!("expected text content"),
        };
        assert_eq!(
            content, "<think>step-by-step reasoning</think>Hello, user.",
            "inline_think must be re-emitted as <think> wrapping prepended to text"
        );
        // No reasoning_content field should be set for non-Moonshot models.
        assert!(msg.reasoning_content.is_none());
    }

    /// `reasoning_content`-flavoured Thinking blocks must re-emit on the
    /// `reasoning_content` field, NOT inline (DeepSeek-R1, Qwen3, MiniMax M3
    /// via LM Studio/Ollama).
    #[test]
    fn test_assemble_assistant_replays_reasoning_content_field() {
        let driver = OpenAIDriver::new(
            "test".to_string(),
            "https://api.deepseek.com/v1".to_string(),
        );
        let blocks = vec![
            ContentBlock::Thinking {
                thinking: "internal chain-of-thought".to_string(),
                signature: None,
                provider_metadata: Some(serde_json::json!({"format": "reasoning_content"})),
            },
            ContentBlock::Text {
                text: "answer".to_string(),
                provider_metadata: None,
            },
        ];
        let msg = assemble_assistant_message(&blocks, "deepseek-reasoner", &driver);
        let content = match msg.content {
            Some(OaiMessageContent::Text(t)) => t,
            _ => panic!("expected text content"),
        };
        assert_eq!(
            content, "answer",
            "visible content must not include <think>"
        );
        assert_eq!(
            msg.reasoning_content.as_deref(),
            Some("internal chain-of-thought"),
            "reasoning_content field must carry the reasoning text"
        );
    }

    /// Regression: a `reasoning_content`-flavoured Thinking block (written by
    /// e.g. an NVIDIA reasoning model) must NOT be emitted when the request
    /// goes to a strict provider — Groq/Cerebras/Mistral reject the field with
    /// a 400 and the whole fallback chain dies.
    #[test]
    fn test_assemble_assistant_strips_reasoning_content_for_strict_providers() {
        for (base_url, model) in [
            ("https://api.groq.com/openai/v1", "openai/gpt-oss-120b"),
            ("https://api.cerebras.ai/v1", "gpt-oss-120b"),
            ("https://api.mistral.ai/v1", "mistral-small-latest"),
            ("https://api.openai.com/v1", "gpt-4o"),
        ] {
            let driver = OpenAIDriver::new("test".to_string(), base_url.to_string());
            let blocks = vec![
                ContentBlock::Thinking {
                    thinking: "internal chain-of-thought".to_string(),
                    signature: None,
                    provider_metadata: Some(serde_json::json!({"format": "reasoning_content"})),
                },
                ContentBlock::Text {
                    text: "answer".to_string(),
                    provider_metadata: None,
                },
            ];
            let msg = assemble_assistant_message(&blocks, model, &driver);
            assert!(
                msg.reasoning_content.is_none(),
                "reasoning_content must be stripped for {base_url}/{model}"
            );
            match msg.content {
                Some(OaiMessageContent::Text(t)) => assert_eq!(t, "answer"),
                _ => panic!("expected text content for {model}"),
            }
        }
    }

    /// Without thinking blocks, the outbound message should be a plain
    /// assistant message — preserve the legacy shape.
    #[test]
    fn test_assemble_assistant_no_thinking_is_plain() {
        let driver = OpenAIDriver::new("test".to_string(), "https://api.openai.com/v1".to_string());
        let blocks = vec![ContentBlock::Text {
            text: "Hi.".to_string(),
            provider_metadata: None,
        }];
        let msg = assemble_assistant_message(&blocks, "gpt-4o", &driver);
        match msg.content {
            Some(OaiMessageContent::Text(t)) => assert_eq!(t, "Hi."),
            _ => panic!("expected text content"),
        }
        assert!(msg.reasoning_content.is_none());
    }

    /// Issue #1098 round-trip: parse a wire response with `reasoning_content`,
    /// then feed the parsed assistant turn back through the outbound path
    /// and confirm the reasoning is replayed.
    #[test]
    fn test_reasoning_content_full_round_trip() {
        // Step 1: parse server response shape.
        let json = serde_json::json!({
            "content": "Final answer.",
            "reasoning_content": "I considered options A, B, and Câ€¦",
            "tool_calls": null
        });
        let server_msg: OaiResponseMessage = serde_json::from_value(json).unwrap();
        assert_eq!(server_msg.content.as_deref(), Some("Final answer."));
        assert_eq!(
            server_msg.reasoning_content.as_deref(),
            Some("I considered options A, B, and Câ€¦")
        );

        // Step 2: simulate the driver building blocks (mirrors the live
        // path in `complete()`).
        let mut content = Vec::new();
        if let Some(ref reasoning) = server_msg.reasoning_content {
            content.push(ContentBlock::Thinking {
                thinking: reasoning.clone(),
                signature: None,
                provider_metadata: Some(serde_json::json!({"format": "reasoning_content"})),
            });
        }
        content.push(ContentBlock::Text {
            text: server_msg.content.unwrap(),
            provider_metadata: None,
        });

        // Step 3: replay through the outbound path.
        let driver = OpenAIDriver::new(
            "test".to_string(),
            "https://api.deepseek.com/v1".to_string(),
        );
        let outbound = assemble_assistant_message(&content, "deepseek-reasoner", &driver);
        // The reasoning_content field must round-trip verbatim.
        assert_eq!(
            outbound.reasoning_content.as_deref(),
            Some("I considered options A, B, and Câ€¦"),
            "issue #1098 regression: reasoning was stripped on resubmission"
        );
    }
}
