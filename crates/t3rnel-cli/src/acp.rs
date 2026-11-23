//! ACP (Agent Client Protocol) server for T3rnel.
//!
//! Exposes T3rnel as a selectable agent in Windsurf / Devin Desktop's
//! Agent Command Center. The protocol is line-delimited JSON-RPC 2.0 over
//! stdin/stdout and mirrors the surface contract described in
//! `ARCHITECTURE.md` section 10.8.
//!
//! Lifecycle:
//! 1. Client sends `agent/discover` to fetch the agent card.
//! 2. Client sends `agent/run` with a prompt.
//! 3. Server routes the prompt to the orchestrator agent (or boots an
//!    in-process kernel) and returns the final response.
//!
//! The T3rnel agent may itself call `ide_delegate` to hand work to the
//! user's IDE, closing the loop between headless agents and desktop IDEs.

use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use t3rnel_kernel::T3rnelKernel;

const ORCHESTRATOR_AGENT_NAME: &str = "t3rnel";

/// Backend for ACP: either a running daemon or an in-process kernel.
enum AcpBackend {
    Daemon {
        base_url: String,
        client: reqwest::blocking::Client,
    },
    InProcess {
        kernel: Box<T3rnelKernel>,
        rt: tokio::runtime::Runtime,
    },
}

impl AcpBackend {
    /// Return a JSON agent card describing T3rnel's ACP agent.
    fn agent_card(&self) -> Value {
        let name = match self {
            AcpBackend::Daemon { .. } => "t3rnel-orchestrator",
            AcpBackend::InProcess { .. } => "t3rnel-standalone",
        };
        json!({
            "agent": {
                "name": name,
                "display_name": "T3rnel Orchestrator",
                "description": "Permanent command center of the T3rnel Agent OS Swarm. Manages teams, spawns specialists, routes tasks, and can delegate to your IDE via ide_delegate.",
                "version": env!("CARGO_PKG_VERSION"),
                "capabilities": {
                    "streaming": false,
                    "tools": ["ide_delegate", "ide_poll"],
                    "multi_turn": true,
                    "max_prompt_chars": 100000
                },
                "provider": {
                    "name": "T3rnel",
                    "url": "https://github.com/t3ratech/t3rnel"
                }
            }
        })
    }

    /// Send a prompt to the orchestrator and return the text response.
    fn run_prompt(&self, prompt: &str, _session_id: Option<&str>) -> Result<String, String> {
        match self {
            AcpBackend::Daemon { base_url, client } => {
                // Find the orchestrator agent by name, creating it if absent.
                let agents: Vec<Value> = client
                    .get(format!("{base_url}/api/agents"))
                    .send()
                    .map_err(|e| format!("HTTP error listing agents: {e}"))?
                    .json()
                    .map_err(|e| format!("Parse error listing agents: {e}"))?;

                let agent_id = agents
                    .iter()
                    .filter_map(|a| {
                        if a["name"].as_str()? == ORCHESTRATOR_AGENT_NAME {
                            a["id"].as_str().map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                    .next();

                let agent_id = match agent_id {
                    Some(id) => id,
                    None => {
                        let resp: Value = client
                            .post(format!("{base_url}/api/agents"))
                            .json(&json!({ "name": ORCHESTRATOR_AGENT_NAME }))
                            .send()
                            .map_err(|e| format!("HTTP error spawning orchestrator: {e}"))?
                            .json()
                            .map_err(|e| format!("Parse error spawning orchestrator: {e}"))?;
                        resp["id"]
                            .as_str()
                            .ok_or("Daemon did not return an agent id")?
                            .to_string()
                    }
                };

                let resp: Value = client
                    .post(format!("{base_url}/api/agents/{agent_id}/message"))
                    .json(&json!({"message": prompt}))
                    .send()
                    .map_err(|e| format!("HTTP error sending message: {e}"))?
                    .json()
                    .map_err(|e| format!("Parse error sending message: {e}"))?;

                resp["response"]
                    .as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| {
                        resp["error"]
                            .as_str()
                            .unwrap_or("Unknown daemon error")
                            .to_string()
                    })
            }
            AcpBackend::InProcess { kernel, rt } => {
                let entry = kernel
                    .registry
                    .find_by_name(ORCHESTRATOR_AGENT_NAME)
                    .ok_or_else(|| {
                        format!(
                            "No {ORCHESTRATOR_AGENT_NAME} agent registered in in-process kernel"
                        )
                    })?;
                let result = rt
                    .block_on(kernel.send_message(entry.id, prompt))
                    .map_err(|e| format!("{e}"))?;
                Ok(result.response)
            }
        }
    }
}

/// Run the ACP server over stdio.
pub fn run_acp_server(config: Option<std::path::PathBuf>) {
    let backend = create_backend(config);

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Some(response) = handle_message(&backend, line) {
                    if writeln!(
                        writer,
                        "{}",
                        serde_json::to_string(&response).unwrap_or_default()
                    )
                    .is_err()
                    {
                        break;
                    }
                    if writer.flush().is_err() {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
}

fn create_backend(config: Option<std::path::PathBuf>) -> AcpBackend {
    // Prefer an already-running daemon so ACP shares the live swarm state.
    if let Some(base_url) = super::find_daemon() {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .expect("Failed to build HTTP client");
        return AcpBackend::Daemon { base_url, client };
    }

    // Fall back to a private in-process kernel.
    let kernel = match T3rnelKernel::boot(config.as_deref()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Failed to boot kernel for ACP: {e}");
            std::process::exit(1);
        }
    };
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    AcpBackend::InProcess {
        kernel: Box::new(kernel),
        rt,
    }
}

fn handle_message(backend: &AcpBackend, line: &str) -> Option<Value> {
    let msg: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Some(jsonrpc_error(
                Value::Null,
                -32700,
                &format!("Parse error: {e}"),
            ));
        }
    };

    let method = msg["method"].as_str().unwrap_or("");
    let id = msg.get("id").cloned().unwrap_or(Value::Null);

    match method {
        "agent/discover" => Some(jsonrpc_response(id, backend.agent_card())),

        "agent/run" => {
            let params = &msg["params"];
            let prompt = params["prompt"].as_str().unwrap_or("").trim();
            if prompt.is_empty() {
                return Some(jsonrpc_error(id, -32602, "Missing 'prompt' parameter"));
            }
            let session_id = params["session_id"].as_str();

            match backend.run_prompt(prompt, session_id) {
                Ok(response) => Some(jsonrpc_response(
                    id,
                    json!({
                        "status": "completed",
                        "output": {
                            "type": "text",
                            "text": response
                        }
                    }),
                )),
                Err(e) => Some(jsonrpc_response(
                    id,
                    json!({
                        "status": "errored",
                        "error": e
                    }),
                )),
            }
        }

        "notifications/cancel" => None,

        _ => Some(jsonrpc_error(
            id,
            -32601,
            &format!("Method not found: {method}"),
        )),
    }
}

fn jsonrpc_response(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn jsonrpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_card_contains_required_fields() {
        let backend = AcpBackend::Daemon {
            base_url: "http://127.0.0.1:50051".to_string(),
            client: reqwest::blocking::Client::new(),
        };
        let card = backend.agent_card();
        let agent = &card["agent"];
        assert_eq!(agent["name"].as_str().unwrap(), "t3rnel-orchestrator");
        assert!(agent["display_name"].as_str().is_some());
        assert!(agent["description"].as_str().is_some());
        assert!(agent["capabilities"]["tools"].is_array());
    }

    #[test]
    fn handle_discover_returns_agent_card() {
        let backend = AcpBackend::Daemon {
            base_url: "http://127.0.0.1:50051".to_string(),
            client: reqwest::blocking::Client::new(),
        };
        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"agent/discover"}"#;
        let resp = handle_message(&backend, msg).unwrap();
        assert_eq!(resp["id"], 1);
        assert!(resp["result"]["agent"].is_object());
    }

    #[test]
    fn handle_run_rejects_missing_prompt() {
        let backend = AcpBackend::Daemon {
            base_url: "http://127.0.0.1:50051".to_string(),
            client: reqwest::blocking::Client::new(),
        };
        let msg = r#"{"jsonrpc":"2.0","id":2,"method":"agent/run","params":{}}"#;
        let resp = handle_message(&backend, msg).unwrap();
        assert_eq!(resp["id"], 2);
        assert!(resp["error"].is_object());
    }

    #[test]
    fn handle_unknown_method_returns_error() {
        let backend = AcpBackend::Daemon {
            base_url: "http://127.0.0.1:50051".to_string(),
            client: reqwest::blocking::Client::new(),
        };
        let msg = r#"{"jsonrpc":"2.0","id":3,"method":"agent/unknown"}"#;
        let resp = handle_message(&backend, msg).unwrap();
        assert_eq!(resp["id"], 3);
        assert!(resp["error"].is_object());
    }
}
