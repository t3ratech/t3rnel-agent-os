use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct DaemonClient {
    client: Client,
    base_url: String,
    api_key: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API returned {status}: {body}")]
    Api { status: u16, body: String },
    #[error("JSON decode failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Agent not found: {0}")]
    AgentNotFound(String),
}

impl DaemonClient {
    pub fn new(client: Client, base_url: String, api_key: Option<String>) -> Self {
        Self {
            client,
            base_url,
            api_key,
        }
    }

    fn headers(&self) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        if let Some(ref key) = self.api_key {
            headers.insert("X-API-Key", key.parse().unwrap());
        }
        headers
    }

    pub async fn list_agents(&self) -> Result<Vec<AgentSummary>, DaemonError> {
        let resp = self
            .client
            .get(format!("{}/api/agents", self.base_url))
            .headers(self.headers())
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DaemonError::Api {
                status: status.as_u16(),
                body,
            });
        }
        let agents: Vec<AgentSummary> = resp.json().await?;
        Ok(agents)
    }

    pub async fn get_agent_status(&self, agent_id: &str) -> Result<AgentStatus, DaemonError> {
        let resp = self
            .client
            .get(format!("{}/api/agents/{}/status", self.base_url, agent_id))
            .headers(self.headers())
            .send()
            .await?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Err(DaemonError::AgentNotFound(agent_id.to_string()));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DaemonError::Api {
                status: status.as_u16(),
                body,
            });
        }
        let s: AgentStatus = resp.json().await?;
        Ok(s)
    }

    pub async fn send_message(
        &self,
        agent_id: &str,
        message: &str,
        async_flag: bool,
    ) -> Result<MessageResponse, DaemonError> {
        let resp = self
            .client
            .post(format!("{}/api/agents/{}/message", self.base_url, agent_id))
            .headers(self.headers())
            .json(&serde_json::json!({
                "message": message,
                "async": async_flag,
            }))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DaemonError::Api {
                status: status.as_u16(),
                body,
            });
        }
        let msg: MessageResponse = resp.json().await?;
        Ok(msg)
    }

    pub async fn kill_agent(&self, agent_id: &str) -> Result<(), DaemonError> {
        let resp = self
            .client
            .post(format!("{}/api/agents/{}/kill", self.base_url, agent_id))
            .headers(self.headers())
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DaemonError::Api {
                status: status.as_u16(),
                body,
            });
        }
        Ok(())
    }

    pub async fn list_teams(&self) -> Result<Vec<Value>, DaemonError> {
        let resp = self
            .client
            .get(format!("{}/api/teams", self.base_url))
            .headers(self.headers())
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DaemonError::Api {
                status: status.as_u16(),
                body,
            });
        }
        let teams: Vec<Value> = resp.json().await?;
        Ok(teams)
    }

    pub async fn get_agent_session(&self, agent_id: &str) -> Result<Value, DaemonError> {
        let resp = self
            .client
            .get(format!("{}/api/agents/{}/session", self.base_url, agent_id))
            .headers(self.headers())
            .send()
            .await?;
        let status = resp.status();
        if status.as_u16() == 404 {
            return Err(DaemonError::AgentNotFound(agent_id.to_string()));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DaemonError::Api {
                status: status.as_u16(),
                body,
            });
        }
        let session: Value = resp.json().await?;
        Ok(session)
    }

    pub async fn spawn_agent(
        &self,
        name: &str,
        template: Option<&str>,
    ) -> Result<Value, DaemonError> {
        let body = if let Some(tpl) = template {
            serde_json::json!({ "name": name, "template": tpl })
        } else {
            serde_json::json!({ "name": name })
        };
        let resp = self
            .client
            .post(format!("{}/api/agents", self.base_url))
            .headers(self.headers())
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DaemonError::Api {
                status: status.as_u16(),
                body,
            });
        }
        let result: Value = resp.json().await?;
        Ok(result)
    }

    /// Run a unified memory operation through the daemon's scoped memory API.
    ///
    /// The daemon resolves the caller context, enforces scope visibility, and
    /// applies sentinel redaction on every read; this client only ever sees
    /// records the operator context is permitted to read.
    pub async fn memory_command(
        &self,
        operation: &str,
        args: Value,
    ) -> Result<Value, DaemonError> {
        let resp = self
            .client
            .post(format!("{}/api/memory/command", self.base_url))
            .headers(self.headers())
            .json(&serde_json::json!({
                "operation": operation,
                "args": args,
            }))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DaemonError::Api {
                status: status.as_u16(),
                body,
            });
        }
        let result: Value = resp.json().await?;
        Ok(result)
    }

    /// Invoke a T3rnel built-in tool by name through the daemon's /mcp HTTP endpoint.
    pub async fn invoke_tool(
        &self,
        tool_name: &str,
        arguments: Value,
    ) -> Result<Value, DaemonError> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        });
        let resp = self
            .client
            .post(format!("{}/mcp", self.base_url))
            .headers(self.headers())
            .json(&request)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(DaemonError::Api {
                status: status.as_u16(),
                body,
            });
        }
        let result: Value = resp.json().await?;
        if let Some(error) = result.get("error") {
            let message = error["message"]
                .as_str()
                .unwrap_or("tool invocation failed");
            return Err(DaemonError::Api {
                status: 500,
                body: message.to_string(),
            });
        }
        Ok(result["result"].clone())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentSummary {
    pub id: String,
    pub name: String,
    pub state: String,
    pub ready: bool,
    pub last_active: String,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentStatus {
    pub id: String,
    pub name: String,
    pub state: String,
    pub ready: bool,
    pub running: bool,
    pub last_active: String,
    pub model_name: Option<String>,
    pub model_provider: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MessageResponse {
    pub message_id: Option<String>,
    pub status: String,
}
