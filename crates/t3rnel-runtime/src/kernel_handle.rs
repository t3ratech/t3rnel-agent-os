//! Trait abstraction for kernel operations needed by the agent runtime.
//!
//! This trait allows `t3rnel-runtime` to call back into the kernel for
//! inter-agent operations (spawn, send, list, kill) without creating
//! a circular dependency. The kernel implements this trait and passes
//! it into the agent loop.

use async_trait::async_trait;

use crate::ide_driver::IdeDriver;

/// Agent info returned by list and discovery operations.
#[derive(Debug, Clone)]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub state: String,
    pub model_provider: String,
    pub model_name: String,
    pub role: String,
    pub description: String,
    pub tags: Vec<String>,
    pub tools: Vec<String>,
}

/// Handle to kernel operations, passed into the agent loop so agents
/// can interact with each other via tools.
#[allow(clippy::too_many_arguments)]
#[async_trait]
pub trait KernelHandle: Send + Sync {
    /// Spawn a new agent from a TOML manifest string.
    /// `parent_id` is the UUID string of the spawning agent (for lineage tracking).
    /// Returns (agent_id, agent_name) on success.
    async fn spawn_agent(
        &self,
        manifest_toml: &str,
        parent_id: Option<&str>,
    ) -> Result<(String, String), String>;

    /// Send a message to another agent and get the response.
    async fn send_to_agent(&self, agent_id: &str, message: &str) -> Result<String, String>;

    /// List all running agents.
    fn list_agents(&self) -> Vec<AgentInfo>;

    /// Kill an agent by ID.
    fn kill_agent(&self, agent_id: &str) -> Result<(), String>;

    /// Activate (wake up) an inactive agent by ID, flipping its state to Running.
    /// Used by orchestrator agents to dispatch work to currently inactive agents
    /// (Suspended, Crashed, or never-started). Terminated agents cannot be revived.
    /// Returns the agent's name on success.
    fn activate_agent(&self, agent_id: &str) -> Result<String, String> {
        let _ = agent_id;
        Err("Agent activation not available".to_string())
    }

    /// Pause autonomous execution for the given agent. Switches its schedule to
    /// Reactive and cancels the background loop so it does not consume tokens.
    async fn pause_agent_autonomy(&self, agent_id: &str) -> Result<(), String> {
        let _ = agent_id;
        Err("Pause agent autonomy not available".to_string())
    }

    /// Store a value in shared memory (cross-agent accessible).
    fn memory_store(&self, key: &str, value: serde_json::Value) -> Result<(), String>;

    /// Recall a value from shared memory.
    fn memory_recall(&self, key: &str) -> Result<Option<serde_json::Value>, String>;

    fn memory_command(
        &self,
        caller: &str,
        operation: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let _ = (caller, operation, args);
        Err("Scoped memory unavailable".into())
    }

    /// Find agents by query (matches on name substring, tag, or tool name; case-insensitive).
    fn find_agents(&self, query: &str) -> Vec<AgentInfo>;

    /// Post a task to the shared task queue. Returns the task ID.
    async fn task_post(
        &self,
        title: &str,
        description: &str,
        assigned_to: Option<&str>,
        created_by: Option<&str>,
    ) -> Result<String, String>;

    /// Claim the next available task (optionally filtered by assignee). Returns task JSON or None.
    async fn task_claim(&self, agent_id: &str) -> Result<Option<serde_json::Value>, String>;

    /// Mark a task as completed with a result string.
    async fn task_complete(&self, task_id: &str, result: &str) -> Result<(), String>;

    /// List tasks, optionally filtered by status.
    async fn task_list(&self, status: Option<&str>) -> Result<Vec<serde_json::Value>, String>;

    /// Publish a custom event that can trigger proactive agents.
    async fn publish_event(
        &self,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Result<(), String>;

    /// Execute a browser tool through a connected Chrome extension transport.
    async fn browser_extension_tool(
        &self,
        agent_id: &str,
        tool: &str,
        args: serde_json::Value,
        timeout_secs: u64,
    ) -> Result<serde_json::Value, String> {
        let _ = (agent_id, tool, args, timeout_secs);
        Err("Chrome extension browser bridge not available".to_string())
    }

    /// Add an entity to the knowledge graph.
    async fn knowledge_add_entity(
        &self,
        entity: t3rnel_types::memory::Entity,
    ) -> Result<String, String>;

    /// Add a relation to the knowledge graph.
    async fn knowledge_add_relation(
        &self,
        relation: t3rnel_types::memory::Relation,
    ) -> Result<String, String>;

    /// Query the knowledge graph with a pattern.
    async fn knowledge_query(
        &self,
        pattern: t3rnel_types::memory::GraphPattern,
    ) -> Result<Vec<t3rnel_types::memory::GraphMatch>, String>;

    /// Create a cron job for the calling agent.
    async fn cron_create(
        &self,
        agent_id: &str,
        job_json: serde_json::Value,
    ) -> Result<String, String> {
        let _ = (agent_id, job_json);
        Err("Cron scheduler not available".to_string())
    }

    /// List cron jobs for the calling agent.
    async fn cron_list(&self, agent_id: &str) -> Result<Vec<serde_json::Value>, String> {
        let _ = agent_id;
        Err("Cron scheduler not available".to_string())
    }

    /// Cancel a cron job by ID.
    async fn cron_cancel(&self, job_id: &str) -> Result<(), String> {
        let _ = job_id;
        Err("Cron scheduler not available".to_string())
    }

    /// Record a tool error for fail-fast tracking. Returns abort reason if threshold breached.
    fn record_tool_error(
        &self,
        task_id: &str,
        agent_id: &str,
    ) -> Option<t3rnel_types::fail_fast::AbortReason> {
        let _ = (task_id, agent_id);
        None
    }

    /// Record a driver failure for fail-fast tracking. Returns abort reason if threshold breached.
    fn record_driver_failure(
        &self,
        task_id: &str,
        agent_id: &str,
    ) -> Option<t3rnel_types::fail_fast::AbortReason> {
        let _ = (task_id, agent_id);
        None
    }

    /// Return the configured IDE driver, if any.
    fn ide_driver(&self) -> Option<&dyn IdeDriver> {
        None
    }

    /// Check if a tool requires approval based on current policy.
    fn requires_approval(&self, tool_name: &str) -> bool {
        let _ = tool_name;
        false
    }

    /// Request approval for a tool execution. Blocks until approved/denied/timed out.
    /// Returns `Ok(true)` if approved, `Ok(false)` if denied or timed out.
    async fn request_approval(
        &self,
        agent_id: &str,
        tool_name: &str,
        action_summary: &str,
    ) -> Result<bool, String> {
        let _ = (agent_id, tool_name, action_summary);
        Ok(true) // Default: auto-approve
    }

    /// List available Hands and their activation status.
    async fn hand_list(&self) -> Result<Vec<serde_json::Value>, String> {
        Err("Hands system not available".to_string())
    }

    /// Install a Hand from TOML content.
    async fn hand_install(
        &self,
        toml_content: &str,
        skill_content: &str,
    ) -> Result<serde_json::Value, String> {
        let _ = (toml_content, skill_content);
        Err("Hands system not available".to_string())
    }

    /// Activate a Hand — spawns a specialized autonomous agent.
    async fn hand_activate(
        &self,
        hand_id: &str,
        config: std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        let _ = (hand_id, config);
        Err("Hands system not available".to_string())
    }

    /// Check the status and dashboard metrics of an active Hand.
    async fn hand_status(&self, hand_id: &str) -> Result<serde_json::Value, String> {
        let _ = hand_id;
        Err("Hands system not available".to_string())
    }

    /// Deactivate a running Hand and stop its agent.
    async fn hand_deactivate(&self, instance_id: &str) -> Result<(), String> {
        let _ = instance_id;
        Err("Hands system not available".to_string())
    }

    /// List discovered external A2A agents as (name, url) pairs.
    fn list_a2a_agents(&self) -> Vec<(String, String)> {
        vec![]
    }

    /// Get the URL of a discovered external A2A agent by name.
    fn get_a2a_agent_url(&self, name: &str) -> Option<String> {
        let _ = name;
        None
    }

    /// Send a message to a user on a named channel adapter (e.g., "email", "telegram").
    /// When `thread_id` is provided, the message is sent as a thread reply.
    /// Returns a confirmation string on success.
    /// Get the default recipient for a channel (e.g. default_chat_id for Telegram).
    async fn get_channel_default_recipient(&self, channel: &str) -> Option<String> {
        let _ = channel;
        None
    }

    async fn send_channel_message(
        &self,
        channel: &str,
        recipient: &str,
        message: &str,
        thread_id: Option<&str>,
    ) -> Result<String, String> {
        let _ = (channel, recipient, message, thread_id);
        Err("Channel send not available".to_string())
    }

    /// Send media content (image/file) to a user on a named channel adapter.
    /// `media_type` is "image" or "file", `media_url` is the URL, `caption` is optional text.
    /// When `thread_id` is provided, the media is sent as a thread reply.
    async fn send_channel_media(
        &self,
        channel: &str,
        recipient: &str,
        media_type: &str,
        media_url: &str,
        caption: Option<&str>,
        filename: Option<&str>,
        thread_id: Option<&str>,
    ) -> Result<String, String> {
        let _ = (
            channel, recipient, media_type, media_url, caption, filename, thread_id,
        );
        Err("Channel media send not available".to_string())
    }

    /// Send a local file (raw bytes) to a user on a named channel adapter.
    /// Used by the `channel_send` tool when `file_path` is provided.
    /// When `thread_id` is provided, the file is sent as a thread reply.
    async fn send_channel_file_data(
        &self,
        channel: &str,
        recipient: &str,
        data: Vec<u8>,
        filename: &str,
        mime_type: &str,
        thread_id: Option<&str>,
    ) -> Result<String, String> {
        let _ = (channel, recipient, data, filename, mime_type, thread_id);
        Err("Channel file data send not available".to_string())
    }

    /// Refresh an agent's last_active timestamp without changing any other state.
    /// Called by the agent loop before long LLM calls to prevent heartbeat false-positives.
    fn touch_agent(&self, agent_id: &str) {
        let _ = agent_id;
    }

    /// Spawn an agent with capability inheritance enforcement.
    /// `parent_caps` are the parent's granted capabilities. The kernel MUST verify
    /// that every capability in the child manifest is covered by `parent_caps`.
    async fn spawn_agent_checked(
        &self,
        manifest_toml: &str,
        parent_id: Option<&str>,
        parent_caps: &[t3rnel_types::capability::Capability],
    ) -> Result<(String, String), String> {
        // Default: delegate to spawn_agent (no enforcement)
        // The kernel MUST override this with real enforcement
        let _ = parent_caps;
        self.spawn_agent(manifest_toml, parent_id).await
    }

    /// Grant execution-policy rights to another agent.
    /// `granter_id` is the UUID of the agent performing the grant.
    /// `target_id` is the UUID or name of the agent receiving the rights.
    /// `mode` is the execution-policy mode to grant ("full", "allowlist", "deny").
    /// Returns Ok(()) on success, or an error string if the granter lacks authority.
    async fn grant_rights(
        &self,
        granter_id: &str,
        target_id: &str,
        mode: &str,
    ) -> Result<(), String> {
        let _ = (granter_id, target_id, mode);
        Err("Rights delegation not available".to_string())
    }

    /// Update the shell execution policy at runtime.
    /// `add_read_only` — commands to add to the read-only allowlist.
    /// `remove_read_only` — commands to remove from the read-only allowlist.
    /// `add_write_patterns` — patterns to add to the write-pattern deny list.
    /// `remove_write_patterns` — patterns to remove from the write-pattern deny list.
    /// Returns Ok(()) on success, or an error string.
    fn update_shell_policy(
        &self,
        add_read_only: Vec<String>,
        remove_read_only: Vec<String>,
        add_write_patterns: Vec<String>,
        remove_write_patterns: Vec<String>,
    ) -> Result<(), String> {
        let _ = (
            add_read_only,
            remove_read_only,
            add_write_patterns,
            remove_write_patterns,
        );
        Err("Shell policy update not available".to_string())
    }
}
