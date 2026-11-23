use crate::audit::{append as append_audit, AuditEntry};
use crate::auth::{check_tool_access, CapabilityTier, ToolRisk};
use crate::client::{DaemonClient, DaemonError};
use rmcp::model::{
    CallToolRequestParams, CallToolResult, JsonObject, ListToolsResult, PaginatedRequestParams,
    ServerCapabilities, ServerInfo, Tool, ToolAnnotations,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler};
use serde_json::{json, Value};
use std::borrow::Cow;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct T3rnelMcpServer {
    daemon: DaemonClient,
    tier: CapabilityTier,
    tier_name: String,
    is_inventor: bool,
}

impl T3rnelMcpServer {
    pub fn new(
        client: reqwest::Client,
        daemon_url: String,
        api_key: Option<String>,
        capability_tier: String,
        is_inventor: bool,
    ) -> anyhow::Result<Self> {
        let tier = CapabilityTier::from_str(&capability_tier)
            .map_err(|e| anyhow::anyhow!("invalid T3RNEL_MCP_TIER: {e}"))?;
        Ok(Self {
            daemon: DaemonClient::new(client, daemon_url, api_key),
            tier,
            tier_name: capability_tier,
            is_inventor,
        })
    }

    fn tools(&self) -> Vec<Tool> {
        vec![
            tool(
                "t3rnel_list_agents",
                "List live T3rnel agents registered in the daemon.",
                json!({"type": "object", "additionalProperties": false, "properties": {}}),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_agent_status",
                "Get status for one T3rnel agent by id.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["agent_id"],
                    "properties": {
                        "agent_id": {"type": "string", "minLength": 1}
                    }
                }),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_agent_session",
                "Fetch the canonical session snapshot for one T3rnel agent.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["agent_id"],
                    "properties": {
                        "agent_id": {"type": "string", "minLength": 1}
                    }
                }),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_list_teams",
                "List persistent T3rnel teams.",
                json!({"type": "object", "additionalProperties": false, "properties": {}}),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_send_message",
                "Send a message to an existing T3rnel agent.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["agent_id", "message"],
                    "properties": {
                        "agent_id": {"type": "string", "minLength": 1},
                        "message": {"type": "string", "minLength": 1},
                        "async": {"type": "boolean", "default": true}
                    }
                }),
                ToolRisk::TokenCost,
            ),
            tool(
                "t3rnel_spawn_agent",
                "Spawn a T3rnel agent from a named template or manifest-backed role.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["name"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "template": {"type": "string", "minLength": 1}
                    }
                }),
                ToolRisk::Lifecycle,
            ),
            tool(
                "t3rnel_kill_agent",
                "Terminate a T3rnel agent by id.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["agent_id"],
                    "properties": {
                        "agent_id": {"type": "string", "minLength": 1}
                    }
                }),
                ToolRisk::Destructive,
            ),
            tool(
                "t3rnel_ide_delegate",
                "Delegate a whole task to the user's configured IDE (Windsurf/Devin, Cursor, or Antigravity). Returns a session handle that can be polled with t3rnel_ide_poll.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["task"],
                    "properties": {
                        "task": {"type": "string", "minLength": 1, "description": "High-level task description for the IDE agent"},
                        "context": {"type": "string", "description": "Optional file paths, constraints, and prior work context"},
                        "output_schema": {"type": "object", "description": "Optional JSON schema for structured output"},
                        "tags": {"type": "array", "items": {"type": "string"}, "description": "Optional tags for the session"},
                        "budget_units": {"type": "integer", "description": "Optional spending cap in platform units"}
                    }
                }),
                ToolRisk::TokenCost,
            ),
            tool(
                "t3rnel_ide_poll",
                "Poll the status of a session created by t3rnel_ide_delegate.",
                json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["session_id"],
                    "properties": {
                        "platform": {"type": "string", "description": "Platform name from the t3rnel_ide_delegate handle"},
                        "session_id": {"type": "string", "minLength": 1, "description": "Session id from the t3rnel_ide_delegate handle"},
                        "url": {"type": "string", "description": "Session URL from the t3rnel_ide_delegate handle"},
                        "extra": {"type": "object", "description": "Extra state from the t3rnel_ide_delegate handle"}
                    }
                }),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_memory_ls",
                "List scoped T3rnel memory references at index depth (no record bodies).",
                memory_schema("memory_ls"),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_memory_search",
                "Search scoped T3rnel memory; results are budgeted and sentinel-redacted by the daemon.",
                memory_schema("memory_search"),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_memory_facts",
                "List fact records in scoped T3rnel memory.",
                memory_schema("memory_search"),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_memory_handover",
                "Read the latest scoped handover digest and whether newer records make it stale.",
                memory_schema("memory_handover"),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_memory_get",
                "Read one permitted full memory record by UUID or t3rnel URI.",
                memory_schema("memory_get"),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_memory_code_graph",
                "Search code knowledge (codefact) records in scoped T3rnel memory.",
                memory_schema("memory_search"),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_memory_remember",
                "Store a deduplicated scoped fact, lesson, decision, or handover in T3rnel memory; sentinel refuses secrets.",
                memory_schema("memory_remember"),
                ToolRisk::MemoryWrite,
            ),
            tool(
                "t3rnel_memory_brief",
                "Assemble a salience-ranked briefing: handover, lessons, decisions, recent outcomes within budget.",
                memory_schema("memory_brief"),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_memory_events",
                "Tail the scoped memory event log since a sequence cursor (ops: remember, supersede, expire, restore, delete).",
                json!({"type":"object","additionalProperties":false,"properties":{
                    "since":{"type":"integer","minimum":0,"default":0,"description":"Sequence cursor; only events after it are returned"},
                    "limit":{"type":"integer","minimum":1,"maximum":1000,"default":100}
                }}),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_memory_conflicts",
                "List likely contradictions among active records in scope for review.",
                json!({"type":"object","additionalProperties":false,"properties":{
                    "limit":{"type":"integer","minimum":1,"maximum":100,"default":20}
                }}),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_memory_history",
                "Read the full version chain of one record, oldest first.",
                json!({"type":"object","additionalProperties":false,"required":["id"],"properties":{
                    "id":{"type":"string","description":"Record UUID or t3rnel URI"}
                }}),
                ToolRisk::ReadOnly,
            ),
            tool(
                "t3rnel_memory_supersede",
                "Replace a record's belief, archiving the prior body so as-of recall stays correct.",
                memory_schema("memory_supersede"),
                ToolRisk::MemoryWrite,
            ),
            tool(
                "t3rnel_memory_expire",
                "Retire a record under a named reason; expired records still recall with their stamp.",
                memory_schema("memory_expire"),
                ToolRisk::MemoryWrite,
            ),
            tool(
                "t3rnel_memory_restore",
                "Return an expired record to active.",
                memory_schema("memory_restore"),
                ToolRisk::MemoryWrite,
            ),
        ]
    }

    fn risk_for(name: &str) -> Option<ToolRisk> {
        match name {
            "t3rnel_list_agents"
            | "t3rnel_agent_status"
            | "t3rnel_agent_session"
            | "t3rnel_list_teams" => Some(ToolRisk::ReadOnly),
            "t3rnel_send_message" => Some(ToolRisk::TokenCost),
            "t3rnel_spawn_agent" => Some(ToolRisk::Lifecycle),
            "t3rnel_kill_agent" => Some(ToolRisk::Destructive),
            "t3rnel_ide_delegate" => Some(ToolRisk::TokenCost),
            "t3rnel_ide_poll" => Some(ToolRisk::ReadOnly),
            "t3rnel_memory_ls"
            | "t3rnel_memory_search"
            | "t3rnel_memory_facts"
            | "t3rnel_memory_handover"
            | "t3rnel_memory_get"
            | "t3rnel_memory_code_graph"
            | "t3rnel_memory_brief"
            | "t3rnel_memory_events"
            | "t3rnel_memory_conflicts"
            | "t3rnel_memory_history" => Some(ToolRisk::ReadOnly),
            "t3rnel_memory_remember"
            | "t3rnel_memory_supersede"
            | "t3rnel_memory_expire"
            | "t3rnel_memory_restore" => Some(ToolRisk::MemoryWrite),
            _ => None,
        }
    }

    async fn execute(&self, name: &str, args: JsonObject) -> Result<Value, ErrorData> {
        let risk = Self::risk_for(name)
            .ok_or_else(|| ErrorData::invalid_params(format!("unknown tool: {name}"), None))?;
        if let Err(reason) = check_tool_access(name, risk, &self.tier, self.is_inventor) {
            append_audit(
                AuditEntry::new(
                    name,
                    Value::Object(args.clone()),
                    "denied",
                    self.tier_name.clone(),
                    self.is_inventor,
                )
                .with_error(reason.clone()),
            )
            .await;
            return Err(ErrorData::invalid_request(reason, None));
        }

        let outcome = match name {
            "t3rnel_list_agents" => self.daemon.list_agents().await.map(|agents| json!(agents)),
            "t3rnel_agent_status" => {
                let agent_id = required_string(&args, "agent_id")?;
                self.daemon
                    .get_agent_status(&agent_id)
                    .await
                    .map(|status| json!(status))
            }
            "t3rnel_agent_session" => {
                let agent_id = required_string(&args, "agent_id")?;
                self.daemon.get_agent_session(&agent_id).await
            }
            "t3rnel_list_teams" => self.daemon.list_teams().await.map(|teams| json!(teams)),
            "t3rnel_send_message" => {
                let agent_id = required_string(&args, "agent_id")?;
                let message = required_string(&args, "message")?;
                let async_flag = args.get("async").and_then(Value::as_bool).unwrap_or(true);
                self.daemon
                    .send_message(&agent_id, &message, async_flag)
                    .await
                    .map(|response| json!(response))
            }
            "t3rnel_spawn_agent" => {
                let name = required_string(&args, "name")?;
                let template = args.get("template").and_then(Value::as_str);
                self.daemon.spawn_agent(&name, template).await
            }
            "t3rnel_kill_agent" => {
                let agent_id = required_string(&args, "agent_id")?;
                self.daemon
                    .kill_agent(&agent_id)
                    .await
                    .map(|_| json!({"agent_id": agent_id, "killed": true}))
            }
            "t3rnel_ide_delegate" => {
                self.daemon
                    .invoke_tool("ide_delegate", Value::Object(args.clone()))
                    .await
            }
            "t3rnel_ide_poll" => {
                self.daemon
                    .invoke_tool("ide_poll", Value::Object(args.clone()))
                    .await
            }
            "t3rnel_memory_get" => {
                let id = required_string(&args, "id")?;
                self.daemon.memory_command("get", json!({"id": id})).await
            }
            "t3rnel_memory_code_graph" => {
                let mut code_args = args.clone();
                code_args.insert("kind".into(), Value::String("codefact".into()));
                self.daemon
                    .memory_command("search", Value::Object(code_args))
                    .await
            }
            "t3rnel_memory_ls"
            | "t3rnel_memory_search"
            | "t3rnel_memory_facts"
            | "t3rnel_memory_handover"
            | "t3rnel_memory_brief"
            | "t3rnel_memory_events"
            | "t3rnel_memory_conflicts"
            | "t3rnel_memory_history"
            | "t3rnel_memory_supersede"
            | "t3rnel_memory_expire"
            | "t3rnel_memory_restore"
            | "t3rnel_memory_remember" => {
                self.daemon
                    .memory_command(name.trim_start_matches("t3rnel_memory_"), Value::Object(args.clone()))
                    .await
            }
            _ => unreachable!("tool name is validated before dispatch"),
        };

        match outcome {
            Ok(value) => {
                append_audit(AuditEntry::new(
                    name,
                    Value::Object(args),
                    "ok",
                    self.tier_name.clone(),
                    self.is_inventor,
                ))
                .await;
                Ok(value)
            }
            Err(err) => {
                let message = daemon_error_message(err);
                append_audit(
                    AuditEntry::new(
                        name,
                        Value::Object(args),
                        "error",
                        self.tier_name.clone(),
                        self.is_inventor,
                    )
                    .with_error(message.clone()),
                )
                .await;
                Err(ErrorData::internal_error(message, None))
            }
        }
    }
}

impl ServerHandler for T3rnelMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions =
            Some("T3rnel daemon MCP bridge. Tool access is gated by T3RNEL_MCP_TIER.".to_string());
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(self.tools()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let name = request.name.to_string();
        let args = request.arguments.unwrap_or_default();
        let value = self.execute(&name, args).await?;
        Ok(CallToolResult::structured(value))
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.tools().into_iter().find(|tool| tool.name == name)
    }
}

fn tool(name: &'static str, description: &'static str, schema: Value, risk: ToolRisk) -> Tool {
    let mut tool = Tool::new(name, description, json_object(schema));
    tool.annotations = Some(match risk {
        ToolRisk::ReadOnly => ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
        ToolRisk::TokenCost => ToolAnnotations::new()
            .read_only(false)
            .destructive(false)
            .idempotent(false)
            .open_world(false),
        // Deduplicated keyed writes converge; safe to retry
        ToolRisk::MemoryWrite => ToolAnnotations::new()
            .read_only(false)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
        ToolRisk::Lifecycle => ToolAnnotations::new()
            .read_only(false)
            .destructive(false)
            .idempotent(false)
            .open_world(false),
        ToolRisk::Destructive => ToolAnnotations::new()
            .read_only(false)
            .destructive(true)
            .idempotent(false)
            .open_world(false),
    });
    tool
}

/// Reuse the daemon's own unified-memory input schemas so the MCP surface can
/// never drift from the agent-facing contract.
fn memory_schema(tool_name: &str) -> Value {
    t3rnel_types::unified_memory::tool_definitions()
        .into_iter()
        .find(|def| def.name == tool_name)
        .expect("unified memory tool schema must exist")
        .input_schema
}

fn json_object(value: Value) -> JsonObject {
    value
        .as_object()
        .cloned()
        .expect("MCP tool schemas must be JSON objects")
}

fn required_string(args: &JsonObject, key: &'static str) -> Result<String, ErrorData> {
    match args.get(key).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => Ok(value.to_string()),
        _ => Err(ErrorData::invalid_params(
            Cow::from(format!("missing or empty required string argument: {key}")),
            None,
        )),
    }
}

fn daemon_error_message(err: DaemonError) -> String {
    match err {
        DaemonError::Http(err) => format!("daemon HTTP request failed: {err}"),
        DaemonError::Api { status, body } => {
            format!("daemon API returned status {status}: {body}")
        }
        DaemonError::Json(err) => format!("daemon JSON decode failed: {err}"),
        DaemonError::AgentNotFound(agent_id) => format!("agent not found: {agent_id}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_catalog_exports_expected_tools_with_annotations() {
        let server = T3rnelMcpServer::new(
            reqwest::Client::new(),
            "http://127.0.0.1:50051".to_string(),
            None,
            "observe".to_string(),
            false,
        )
        .unwrap();

        let tools = server.tools();
        let names: Vec<_> = tools.iter().map(|tool| tool.name.as_ref()).collect();
        assert_eq!(
            names,
            vec![
                "t3rnel_list_agents",
                "t3rnel_agent_status",
                "t3rnel_agent_session",
                "t3rnel_list_teams",
                "t3rnel_send_message",
                "t3rnel_spawn_agent",
                "t3rnel_kill_agent",
                "t3rnel_ide_delegate",
                "t3rnel_ide_poll",
                "t3rnel_memory_ls",
                "t3rnel_memory_search",
                "t3rnel_memory_facts",
                "t3rnel_memory_handover",
                "t3rnel_memory_get",
                "t3rnel_memory_code_graph",
                "t3rnel_memory_remember",
                "t3rnel_memory_brief",
                "t3rnel_memory_events",
                "t3rnel_memory_conflicts",
                "t3rnel_memory_history",
                "t3rnel_memory_supersede",
                "t3rnel_memory_expire",
                "t3rnel_memory_restore",
            ]
        );

        let list_agents = tools
            .iter()
            .find(|tool| tool.name == "t3rnel_list_agents")
            .unwrap();
        let annotations = list_agents.annotations.as_ref().unwrap();
        assert_eq!(annotations.read_only_hint, Some(true));
        assert_eq!(annotations.destructive_hint, Some(false));

        let kill_agent = tools
            .iter()
            .find(|tool| tool.name == "t3rnel_kill_agent")
            .unwrap();
        let annotations = kill_agent.annotations.as_ref().unwrap();
        assert_eq!(annotations.read_only_hint, Some(false));
        assert_eq!(annotations.destructive_hint, Some(true));
    }

    #[test]
    fn invalid_capability_tier_is_rejected_at_startup() {
        let err = T3rnelMcpServer::new(
            reqwest::Client::new(),
            "http://127.0.0.1:50051".to_string(),
            None,
            "root".to_string(),
            false,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("invalid T3RNEL_MCP_TIER"));
    }

    #[test]
    fn required_string_rejects_missing_and_blank_values() {
        let args = JsonObject::new();
        assert!(required_string(&args, "agent_id").is_err());

        let mut args = JsonObject::new();
        args.insert("agent_id".to_string(), Value::String("   ".to_string()));
        assert!(required_string(&args, "agent_id").is_err());

        args.insert("agent_id".to_string(), Value::String("agent-1".to_string()));
        assert_eq!(required_string(&args, "agent_id").unwrap(), "agent-1");
    }

    #[test]
    fn risk_lookup_matches_tool_contract() {
        assert_eq!(
            T3rnelMcpServer::risk_for("t3rnel_list_agents"),
            Some(ToolRisk::ReadOnly)
        );
        assert_eq!(
            T3rnelMcpServer::risk_for("t3rnel_send_message"),
            Some(ToolRisk::TokenCost)
        );
        assert_eq!(
            T3rnelMcpServer::risk_for("t3rnel_spawn_agent"),
            Some(ToolRisk::Lifecycle)
        );
        assert_eq!(
            T3rnelMcpServer::risk_for("t3rnel_ide_delegate"),
            Some(ToolRisk::TokenCost)
        );
        assert_eq!(
            T3rnelMcpServer::risk_for("t3rnel_ide_poll"),
            Some(ToolRisk::ReadOnly)
        );
        assert_eq!(
            T3rnelMcpServer::risk_for("t3rnel_kill_agent"),
            Some(ToolRisk::Destructive)
        );
        for read in [
            "t3rnel_memory_ls",
            "t3rnel_memory_search",
            "t3rnel_memory_facts",
            "t3rnel_memory_handover",
            "t3rnel_memory_get",
            "t3rnel_memory_code_graph",
            "t3rnel_memory_brief",
            "t3rnel_memory_events",
            "t3rnel_memory_conflicts",
            "t3rnel_memory_history",
        ] {
            assert_eq!(
                T3rnelMcpServer::risk_for(read),
                Some(ToolRisk::ReadOnly),
                "{read}"
            );
        }
        for write in [
            "t3rnel_memory_remember",
            "t3rnel_memory_supersede",
            "t3rnel_memory_expire",
            "t3rnel_memory_restore",
        ] {
            assert_eq!(
                T3rnelMcpServer::risk_for(write),
                Some(ToolRisk::MemoryWrite),
                "{write}"
            );
        }
        assert_eq!(T3rnelMcpServer::risk_for("unknown"), None);
    }

    /// Minimal loopback HTTP daemon that serves one JSON response and reports
    /// the raw request it received, so tests can verify the MCP layer sends the
    /// right operation, scope, and headers to the real API contract.
    fn mock_daemon(
        status_line: &'static str,
        response: Value,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                let n = match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&chunk[..n]);
                let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                    continue;
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let len = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.trim()
                            .eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if buf.len() >= head_end + 4 + len {
                    break;
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&buf).to_string());
            let body = response.to_string();
            let _ = stream.write_all(
                format!(
                    "{status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        });
        (format!("http://127.0.0.1:{port}"), rx)
    }

    fn args_object(pairs: &[(&str, Value)]) -> JsonObject {
        let mut args = JsonObject::new();
        for (key, value) in pairs {
            args.insert((*key).to_string(), value.clone());
        }
        args
    }

    #[tokio::test]
    async fn memory_search_passes_scope_and_text_to_daemon_command() {
        let (url, rx) = mock_daemon(
            "HTTP/1.1 200 OK",
            json!({"records": [], "stale": null, "used_bytes": 2}),
        );
        let server = T3rnelMcpServer::new(
            reqwest::Client::new(),
            url,
            Some("test-key".to_string()),
            "observe".to_string(),
            false,
        )
        .unwrap();

        let out = server
            .execute(
                "t3rnel_memory_search",
                args_object(&[
                    ("text", json!("deploy")),
                    (
                        "scope",
                        json!({"visibility": "project", "project_id": "t3rnel"}),
                    ),
                ]),
            )
            .await
            .unwrap();

        assert_eq!(out["records"], json!([]));
        let req = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(req.contains("POST /api/memory/command"));
        assert!(req.contains("\"operation\":\"search\""));
        assert!(req.contains("\"text\":\"deploy\""));
        assert!(req.contains("\"project_id\":\"t3rnel\""));
        assert!(req.contains("test-key"));
    }

    #[tokio::test]
    async fn memory_reads_return_daemon_redacted_records_verbatim() {
        let (url, _rx) = mock_daemon(
            "HTTP/1.1 200 OK",
            json!({"records": [{"id": "r1", "content": "[REDACTED]", "summary": "credential material removed"}], "stale": null, "used_bytes": 80}),
        );
        let server = T3rnelMcpServer::new(
            reqwest::Client::new(),
            url,
            None,
            "observe".to_string(),
            false,
        )
        .unwrap();

        let out = server
            .execute("t3rnel_memory_facts", JsonObject::new())
            .await
            .unwrap();

        assert_eq!(out["records"][0]["content"], "[REDACTED]");
        assert_eq!(
            out["records"][0]["summary"],
            "credential material removed"
        );
    }

    #[tokio::test]
    async fn memory_remember_is_denied_at_observe_tier_before_daemon_call() {
        let (url, rx) = mock_daemon("HTTP/1.1 200 OK", json!({"id": "r1"}));
        let server = T3rnelMcpServer::new(
            reqwest::Client::new(),
            url,
            None,
            "observe".to_string(),
            false,
        )
        .unwrap();

        let err = server
            .execute(
                "t3rnel_memory_remember",
                args_object(&[("content", json!("lesson: always scan nested JSON"))]),
            )
            .await
            .unwrap_err();

        assert!(err.message.contains("higher capability tier"));
        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_err());
    }

    #[tokio::test]
    async fn memory_remember_reaches_daemon_at_message_tier() {
        let (url, rx) = mock_daemon(
            "HTTP/1.1 200 OK",
            json!({"id": "r1", "uri": "t3rnel://project/lesson/r1", "revision": 1}),
        );
        let server = T3rnelMcpServer::new(
            reqwest::Client::new(),
            url,
            None,
            "message".to_string(),
            false,
        )
        .unwrap();

        let out = server
            .execute(
                "t3rnel_memory_remember",
                args_object(&[
                    ("content", json!("lesson: always scan nested JSON")),
                    ("kind", json!("lesson")),
                ]),
            )
            .await
            .unwrap();

        assert_eq!(out["revision"], 1);
        let req = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(req.contains("\"operation\":\"remember\""));
        assert!(req.contains("\"kind\":\"lesson\""));
    }

    #[tokio::test]
    async fn memory_get_and_code_graph_dispatch_correct_operations() {
        let (url, rx) = mock_daemon(
            "HTTP/1.1 200 OK",
            json!({"id": "r1", "content": "body"}),
        );
        let server = T3rnelMcpServer::new(
            reqwest::Client::new(),
            url,
            None,
            "observe".to_string(),
            false,
        )
        .unwrap();

        server
            .execute(
                "t3rnel_memory_get",
                args_object(&[("id", json!("t3rnel://project/fact/r1"))]),
            )
            .await
            .unwrap();
        let req = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(req.contains("\"operation\":\"get\""));
        assert!(req.contains("t3rnel://project/fact/r1"));

        let (url, rx) = mock_daemon("HTTP/1.1 200 OK", json!({"records": []}));
        let server = T3rnelMcpServer::new(
            reqwest::Client::new(),
            url,
            None,
            "observe".to_string(),
            false,
        )
        .unwrap();
        server
            .execute(
                "t3rnel_memory_code_graph",
                args_object(&[("text", json!("facade"))]),
            )
            .await
            .unwrap();
        let req = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(req.contains("\"operation\":\"search\""));
        assert!(req.contains("\"kind\":\"codefact\""));
        assert!(req.contains("\"text\":\"facade\""));
    }

    #[tokio::test]
    async fn memory_daemon_errors_surface_to_mcp_client() {
        let (url, _rx) = mock_daemon(
            "HTTP/1.1 403 Forbidden",
            json!({"error": "Memory caller denied"}),
        );
        let server = T3rnelMcpServer::new(
            reqwest::Client::new(),
            url,
            None,
            "observe".to_string(),
            false,
        )
        .unwrap();

        let err = server
            .execute("t3rnel_memory_ls", JsonObject::new())
            .await
            .unwrap_err();
        assert!(err.message.contains("403"));
    }

    #[test]
    fn daemon_errors_are_translated_for_mcp_clients() {
        assert_eq!(
            daemon_error_message(DaemonError::Api {
                status: 503,
                body: "busy".to_string(),
            }),
            "daemon API returned status 503: busy"
        );
        assert_eq!(
            daemon_error_message(DaemonError::AgentNotFound("agent-1".to_string())),
            "agent not found: agent-1"
        );
    }
}
