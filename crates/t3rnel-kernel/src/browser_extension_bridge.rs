//! Browser extension bridge for headed Chrome automation.
//!
//! The API WebSocket transport registers an outbound channel per agent. Runtime
//! browser tools can then send a `browser_tool` frame to the Chrome extension
//! and wait for the matching `browser_tool_result`.

use dashmap::DashMap;
use serde_json::Value;
use std::time::Duration;
use t3rnel_types::agent::AgentId;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

#[derive(Default)]
pub struct BrowserExtensionBridge {
    connections: DashMap<AgentId, mpsc::Sender<Value>>,
    pending: DashMap<String, oneshot::Sender<Value>>,
}

impl BrowserExtensionBridge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, agent_id: AgentId) -> mpsc::Receiver<Value> {
        let (tx, rx) = mpsc::channel(64);
        self.connections.insert(agent_id, tx);
        rx
    }

    pub fn unregister(&self, agent_id: AgentId) {
        self.connections.remove(&agent_id);
    }

    pub fn connected(&self, agent_id: AgentId) -> bool {
        self.connections.contains_key(&agent_id)
    }

    pub async fn execute(
        &self,
        agent_id: AgentId,
        tool: &str,
        args: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        let tx = self
            .connections
            .get(&agent_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| {
                format!("No Chrome extension browser bridge connected for agent {agent_id}")
            })?;

        let request_id = Uuid::new_v4().to_string();
        let (result_tx, result_rx) = oneshot::channel();
        self.pending.insert(request_id.clone(), result_tx);

        let frame = serde_json::json!({
            "type": "browser_tool",
            "request": {
                "id": request_id,
                "tool": tool,
                "args": args,
            }
        });

        if tx.send(frame).await.is_err() {
            self.pending.remove(&request_id);
            self.connections.remove(&agent_id);
            return Err(format!(
                "Chrome extension browser bridge disconnected for agent {agent_id}"
            ));
        }

        let response = match tokio::time::timeout(timeout, result_rx).await {
            Ok(Ok(value)) => value,
            Ok(Err(_)) => {
                return Err(format!(
                    "Chrome extension browser bridge response channel closed for {tool}"
                ))
            }
            Err(_) => {
                self.pending.remove(&request_id);
                return Err(format!(
                    "Chrome extension browser tool {tool} timed out after {}s",
                    timeout.as_secs()
                ));
            }
        };

        if response.get("ok").and_then(Value::as_bool).unwrap_or(false) {
            Ok(response.get("result").cloned().unwrap_or(Value::Null))
        } else {
            Err(response
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("Chrome extension browser tool failed")
                .to_string())
        }
    }

    pub fn complete(&self, response: Value) -> bool {
        let Some(request_id) = response
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            return false;
        };
        if let Some((_, tx)) = self.pending.remove(&request_id) {
            let _ = tx.send(response);
            true
        } else {
            false
        }
    }
}
