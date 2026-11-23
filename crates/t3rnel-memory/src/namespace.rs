//! Memory namespace helpers for profile/team/project isolation.
//!
//! The semantic layer stores the namespace in `scope` so SQLite, HTTP memory,
//! and LanceDB can share the same isolation contract without backend-specific
//! schema forks.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use t3rnel_types::agent::AgentId;
use t3rnel_types::memory::MemoryFilter;

const DEFAULT_PROFILE: &str = "default";
const DEFAULT_TEAM: &str = "personal";
const DEFAULT_PROJECT: &str = "default";

/// Profile/team/project namespace for semantic memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryNamespace {
    /// User/profile partition, normally read from `T3RNEL_PROFILE`.
    pub profile: String,
    /// Team partition. `personal` means no team has been selected.
    pub team_id: String,
    /// Project/workspace partition.
    pub project_id: String,
}

impl MemoryNamespace {
    /// Build a namespace from explicit values.
    pub fn new(
        profile: impl Into<String>,
        team_id: impl Into<String>,
        project_id: impl Into<String>,
    ) -> Self {
        Self {
            profile: sanitize_component(profile.into(), DEFAULT_PROFILE),
            team_id: sanitize_component(team_id.into(), DEFAULT_TEAM),
            project_id: sanitize_component(project_id.into(), DEFAULT_PROJECT),
        }
    }

    /// Build a namespace from `T3RNEL_PROFILE` plus explicit team/project values.
    pub fn from_env(team_id: Option<&str>, project_id: Option<&str>) -> Self {
        let profile = std::env::var("T3RNEL_PROFILE").unwrap_or_else(|_| DEFAULT_PROFILE.into());
        Self::new(
            profile,
            team_id.unwrap_or(DEFAULT_TEAM),
            project_id.unwrap_or(DEFAULT_PROJECT),
        )
    }

    /// True when this namespace addresses a shared team partition.
    pub fn is_team_scoped(&self) -> bool {
        self.team_id != DEFAULT_TEAM
    }

    /// Stable scope string for a memory tier such as `semantic`, `session`, or `lesson`.
    pub fn scope(&self, tier: &str) -> String {
        format!(
            "profile/{}/team/{}/project/{}/{}",
            self.profile,
            self.team_id,
            self.project_id,
            sanitize_component(tier, "semantic")
        )
    }

    /// Metadata tags written alongside each memory record.
    pub fn metadata(&self) -> HashMap<String, serde_json::Value> {
        HashMap::from([
            (
                "t3rnel_profile".to_string(),
                serde_json::Value::String(self.profile.clone()),
            ),
            (
                "team_id".to_string(),
                serde_json::Value::String(self.team_id.clone()),
            ),
            (
                "project_id".to_string(),
                serde_json::Value::String(self.project_id.clone()),
            ),
        ])
    }

    /// Recall filter for this namespace.
    ///
    /// Team-scoped memories are shared by team members through `scope`; personal
    /// memories remain agent-local as an extra guardrail.
    pub fn filter_for(&self, tier: &str, agent_id: AgentId) -> MemoryFilter {
        let mut filter = MemoryFilter {
            scope: Some(self.scope(tier)),
            ..Default::default()
        };
        if !self.is_team_scoped() {
            filter.agent_id = Some(agent_id);
        }
        filter
    }
}

impl Default for MemoryNamespace {
    fn default() -> Self {
        Self::new(DEFAULT_PROFILE, DEFAULT_TEAM, DEFAULT_PROJECT)
    }
}

fn sanitize_component(input: impl AsRef<str>, fallback: &str) -> String {
    let sanitized: String = input
        .as_ref()
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        fallback.to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_scope_is_stable_and_sanitized() {
        let ns = MemoryNamespace::new("prod east", "team/a", "core");
        assert_eq!(
            ns.scope("semantic"),
            "profile/prod_east/team/team_a/project/core/semantic"
        );
        assert!(ns.is_team_scoped());
    }

    #[test]
    fn personal_filter_keeps_agent_boundary() {
        let agent_id = AgentId::new();
        let filter = MemoryNamespace::default().filter_for("semantic", agent_id);
        assert_eq!(filter.agent_id, Some(agent_id));
        assert_eq!(
            filter.scope.as_deref(),
            Some("profile/default/team/personal/project/default/semantic")
        );
    }

    #[test]
    fn team_filter_uses_scope_boundary() {
        let agent_id = AgentId::new();
        let filter = MemoryNamespace::new("p", "team-1", "repo").filter_for("semantic", agent_id);
        assert_eq!(filter.agent_id, None);
        assert_eq!(
            filter.scope.as_deref(),
            Some("profile/p/team/team-1/project/repo/semantic")
        );
    }
}
