use chrono::Utc;
use serde_json::Value;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

/// Audit every MCP tool invocation with the same schema as t3rnel HTTP API events.
/// This ensures a single, unified audit trail regardless of entry point.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: String,
    pub source: String, // "mcp"
    pub tool_name: String,
    pub arguments: Value,
    pub result: String, // "ok", "denied", "error"
    pub error_detail: Option<String>,
    pub client_identity: Option<String>,
    pub capability_tier: String,
    pub inventor_mode: bool,
}

impl AuditEntry {
    pub fn new(
        tool_name: impl Into<String>,
        arguments: Value,
        result: impl Into<String>,
        tier: impl Into<String>,
        inventor: bool,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            source: "mcp".to_string(),
            tool_name: tool_name.into(),
            arguments,
            result: result.into(),
            error_detail: None,
            client_identity: std::env::var("USER").ok(),
            capability_tier: tier.into(),
            inventor_mode: inventor,
        }
    }

    pub fn with_error(mut self, detail: impl Into<String>) -> Self {
        self.error_detail = Some(detail.into());
        self
    }

    pub fn to_jsonl(&self) -> String {
        match serde_json::to_string(self) {
            Ok(s) => format!("{}\n", s),
            Err(_) => String::new(),
        }
    }
}

impl serde::Serialize for AuditEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("AuditEntry", 9)?;
        s.serialize_field("timestamp", &self.timestamp)?;
        s.serialize_field("source", &self.source)?;
        s.serialize_field("tool_name", &self.tool_name)?;
        s.serialize_field("arguments", &self.arguments)?;
        s.serialize_field("result", &self.result)?;
        s.serialize_field("error_detail", &self.error_detail)?;
        s.serialize_field("client_identity", &self.client_identity)?;
        s.serialize_field("capability_tier", &self.capability_tier)?;
        s.serialize_field("inventor_mode", &self.inventor_mode)?;
        s.end()
    }
}

/// Append an audit entry to the MCP audit log file.
pub async fn append(entry: AuditEntry) {
    let log_dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("t3rnel")
        .join("logs");
    let _ = tokio::fs::create_dir_all(&log_dir).await;
    let log_path = log_dir.join("mcp-audit.jsonl");

    let line = entry.to_jsonl();
    if let Ok(mut file) = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .await
    {
        let _ = file.write_all(line.as_bytes()).await;
        let _ = file.flush().await;
    }

    // Also emit structured trace for centralized collectors
    match entry.result.as_str() {
        "denied" => {
            tracing::warn!(
                tool = %entry.tool_name,
                tier = %entry.capability_tier,
                inventor = entry.inventor_mode,
                "MCP tool access denied"
            );
        }
        "error" => {
            tracing::error!(
                tool = %entry.tool_name,
                error = ?entry.error_detail,
                "MCP tool execution error"
            );
        }
        _ => {
            tracing::info!(
                tool = %entry.tool_name,
                tier = %entry.capability_tier,
                inventor = entry.inventor_mode,
                "MCP tool executed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn audit_entry_serializes_as_jsonl() {
        let line = AuditEntry::new(
            "t3rnel_list_agents",
            json!({"limit": 10}),
            "ok",
            "observe",
            false,
        )
        .to_jsonl();

        assert!(line.ends_with('\n'));
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value["source"], "mcp");
        assert_eq!(value["tool_name"], "t3rnel_list_agents");
        assert_eq!(value["arguments"]["limit"], 10);
        assert_eq!(value["result"], "ok");
        assert_eq!(value["capability_tier"], "observe");
        assert_eq!(value["inventor_mode"], false);
    }

    #[test]
    fn audit_entry_preserves_error_detail() {
        let line = AuditEntry::new(
            "t3rnel_send_message",
            json!({"agent_id": "a1"}),
            "denied",
            "observe",
            false,
        )
        .with_error("requires full tier")
        .to_jsonl();

        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value["error_detail"], "requires full tier");
    }
}
