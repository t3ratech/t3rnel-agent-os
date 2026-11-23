/// Capability tier enforcement for MCP tools.
///
/// Default tier is `observe` (read-only). Users can escalate by setting
/// `T3RNEL_MCP_TIER=message` or `T3RNEL_MCP_TIER=full`.
///
/// `T3RNEL_INVENTOR_MODE=true` bypasses all gates (FULL POWER).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CapabilityTier {
    /// Read-only observability tools only
    #[default]
    Observe,
    /// Read + async messaging to agents
    Message,
    /// Read + write + spawn + kill + execute
    Full,
}

impl std::str::FromStr for CapabilityTier {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "observe" | "obs" | "readonly" | "read" => Ok(CapabilityTier::Observe),
            "message" | "msg" | "chat" => Ok(CapabilityTier::Message),
            "full" | "all" | "admin" | "power" => Ok(CapabilityTier::Full),
            _ => Err(format!(
                "unknown tier: {}. Use observe, message, or full",
                s
            )),
        }
    }
}

/// Tool classification for gate decisions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolRisk {
    ReadOnly,
    MemoryWrite,
    /// Sends data to LLM (costs tokens)
    TokenCost,
    /// Mutates agent lifecycle
    Lifecycle,
    /// Destructive / irreversible
    Destructive,
}

impl ToolRisk {
    pub fn requires_approval(&self, tier: &CapabilityTier, is_inventor: bool) -> bool {
        // Inventor bypasses everything
        if is_inventor {
            return false;
        }
        match (self, tier) {
            // Read-only always allowed
            (ToolRisk::ReadOnly, _) => false,
            // Memory writes mutate shared state; require at least Message tier
            (ToolRisk::MemoryWrite, CapabilityTier::Observe) => true,
            (ToolRisk::MemoryWrite, _) => false,
            // TokenCost requires at least Message tier
            (ToolRisk::TokenCost, CapabilityTier::Observe) => true,
            (ToolRisk::TokenCost, _) => false,
            // Lifecycle requires Full tier
            (ToolRisk::Lifecycle, CapabilityTier::Full) => false,
            (ToolRisk::Lifecycle, _) => true,
            // Destructive always requires approval unless inventor
            (ToolRisk::Destructive, _) => true,
        }
    }
}

/// Check if a tool is permitted under the current tier.
/// Returns `Ok(())` if allowed, `Err(reason)` if blocked.
pub fn check_tool_access(
    tool_name: &str,
    risk: ToolRisk,
    tier: &CapabilityTier,
    is_inventor: bool,
) -> Result<(), String> {
    if is_inventor {
        return Ok(());
    }
    let needs_approval = risk.requires_approval(tier, is_inventor);
    if needs_approval {
        let tier_name = match tier {
            CapabilityTier::Observe => "observe",
            CapabilityTier::Message => "message",
            CapabilityTier::Full => "full",
        };
        Err(format!(
            "tool '{}' requires a higher capability tier (current: {}). \
             Set T3RNEL_MCP_TIER=full or T3RNEL_INVENTOR_MODE=true",
            tool_name, tier_name
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn capability_tier_aliases_parse() {
        assert_eq!(
            CapabilityTier::from_str("readonly").unwrap(),
            CapabilityTier::Observe
        );
        assert_eq!(
            CapabilityTier::from_str("chat").unwrap(),
            CapabilityTier::Message
        );
        assert_eq!(
            CapabilityTier::from_str("admin").unwrap(),
            CapabilityTier::Full
        );
        assert!(CapabilityTier::from_str("unknown").is_err());
    }

    #[test]
    fn observe_tier_is_read_only() {
        assert!(check_tool_access(
            "t3rnel_list_agents",
            ToolRisk::ReadOnly,
            &CapabilityTier::Observe,
            false
        )
        .is_ok());

        let denied = check_tool_access(
            "t3rnel_send_message",
            ToolRisk::TokenCost,
            &CapabilityTier::Observe,
            false,
        )
        .unwrap_err();
        assert!(denied.contains("requires a higher capability tier"));
    }

    #[test]
    fn memory_writes_require_message_tier() {
        assert!(check_tool_access(
            "t3rnel_memory_remember",
            ToolRisk::MemoryWrite,
            &CapabilityTier::Observe,
            false
        )
        .is_err());
        assert!(check_tool_access(
            "t3rnel_memory_remember",
            ToolRisk::MemoryWrite,
            &CapabilityTier::Message,
            false
        )
        .is_ok());
        assert!(check_tool_access(
            "t3rnel_memory_search",
            ToolRisk::ReadOnly,
            &CapabilityTier::Observe,
            false
        )
        .is_ok());
    }

    #[test]
    fn destructive_tools_require_inventor_mode_even_at_full_tier() {
        assert!(check_tool_access(
            "t3rnel_kill_agent",
            ToolRisk::Destructive,
            &CapabilityTier::Full,
            false
        )
        .is_err());
        assert!(check_tool_access(
            "t3rnel_kill_agent",
            ToolRisk::Destructive,
            &CapabilityTier::Observe,
            true
        )
        .is_ok());
    }
}
