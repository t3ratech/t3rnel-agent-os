//! Compile-time embedded Hand definitions.

use crate::{parse_hand_toml, HandDefinition, HandError};

/// Returns all bundled hand definitions as (id, HAND.toml content, SKILL.md content).
pub fn bundled_hands() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "clip",
            include_str!("../bundled/clip/HAND.toml"),
            include_str!("../bundled/clip/SKILL.md"),
        ),
        (
            "collector",
            include_str!("../bundled/collector/HAND.toml"),
            include_str!("../bundled/collector/SKILL.md"),
        ),
        (
            "predictor",
            include_str!("../bundled/predictor/HAND.toml"),
            include_str!("../bundled/predictor/SKILL.md"),
        ),
        (
            "researcher",
            include_str!("../bundled/researcher/HAND.toml"),
            include_str!("../bundled/researcher/SKILL.md"),
        ),
        (
            "browser",
            include_str!("../bundled/browser/HAND.toml"),
            include_str!("../bundled/browser/SKILL.md"),
        ),
        (
            "infisical-sync",
            include_str!("../bundled/infisical-sync/HAND.toml"),
            include_str!("../bundled/infisical-sync/SKILL.md"),
        ),
    ]
}

/// Parse a bundled HAND.toml into a HandDefinition with its skill content attached.
pub fn parse_bundled(
    _id: &str,
    toml_content: &str,
    skill_content: &str,
) -> Result<HandDefinition, HandError> {
    let mut def: HandDefinition =
        parse_hand_toml(toml_content).map_err(|e| HandError::TomlParse(e.to_string()))?;
    if !skill_content.is_empty() {
        def.skill_content = Some(skill_content.to_string());
    }
    Ok(def)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_hands_not_empty() {
        let hands = bundled_hands();
        assert!(!hands.is_empty());
        assert_eq!(hands[0].0, "clip");
    }

    #[test]
    fn bundled_hands_count() {
        let hands = bundled_hands();
        assert_eq!(hands.len(), 6);
    }

    #[test]
    fn parse_clip_hand() {
        let hands = bundled_hands();
        let (id, toml_content, skill_content) = hands[0];
        let def = parse_bundled(id, toml_content, skill_content).unwrap();
        assert_eq!(def.id, "clip");
        assert_eq!(def.name, "Clip Hand");
        assert_eq!(def.category, crate::HandCategory::Content);
        assert!(def.skill_content.is_some());
        assert!(!def.requires.is_empty());
        assert!(!def.tools.is_empty());
        assert!(!def.agent.system_prompt.is_empty());
        assert!(!def.dashboard.metrics.is_empty());
    }


    #[test]
    fn parse_collector_hand() {
        let (id, toml_content, skill_content) = bundled_hands()
            .into_iter()
            .find(|(id, _, _)| *id == "collector")
            .unwrap();
        let def = parse_bundled(id, toml_content, skill_content).unwrap();
        assert_eq!(def.id, "collector");
        assert_eq!(def.name, "Collector Hand");
        assert_eq!(def.category, crate::HandCategory::Data);
        assert!(def.skill_content.is_some());
        assert!(def.requires.is_empty());
        assert!(def.tools.contains(&"event_publish".to_string()));
        assert!(!def.settings.is_empty());
        assert!(!def.dashboard.metrics.is_empty());
    }

    #[test]
    fn parse_predictor_hand() {
        let (id, toml_content, skill_content) = bundled_hands()
            .into_iter()
            .find(|(id, _, _)| *id == "predictor")
            .unwrap();
        let def = parse_bundled(id, toml_content, skill_content).unwrap();
        assert_eq!(def.id, "predictor");
        assert_eq!(def.name, "Predictor Hand");
        assert_eq!(def.category, crate::HandCategory::Data);
        assert!(def.skill_content.is_some());
        assert!(def.requires.is_empty());
        assert!(!def.settings.is_empty());
        assert!(!def.dashboard.metrics.is_empty());
        assert!((def.agent.temperature - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn parse_researcher_hand() {
        let (id, toml_content, skill_content) = bundled_hands()
            .into_iter()
            .find(|(id, _, _)| *id == "researcher")
            .unwrap();
        let def = parse_bundled(id, toml_content, skill_content).unwrap();
        assert_eq!(def.id, "researcher");
        assert_eq!(def.name, "Researcher Hand");
        assert_eq!(def.category, crate::HandCategory::Productivity);
        assert!(def.skill_content.is_some());
        assert!(def.requires.is_empty());
        assert!(def.tools.contains(&"event_publish".to_string()));
        assert!(!def.settings.is_empty());
        assert!(!def.dashboard.metrics.is_empty());
        assert_eq!(def.agent.max_iterations, Some(25));
    }


    #[test]
    fn parse_browser_hand() {
        let (id, toml_content, skill_content) = bundled_hands()
            .into_iter()
            .find(|(id, _, _)| *id == "browser")
            .unwrap();
        let def = parse_bundled(id, toml_content, skill_content).unwrap();
        assert_eq!(def.id, "browser");
        assert_eq!(def.name, "Browser Hand");
        assert_eq!(def.category, crate::HandCategory::Productivity);
        assert!(def.skill_content.is_some());
        assert!(!def.requires.is_empty()); // requires python3 + chromium
        assert_eq!(def.requires.len(), 2);
        assert!(def.tools.contains(&"browser_navigate".to_string()));
        assert!(def.tools.contains(&"browser_click".to_string()));
        assert!(def.tools.contains(&"browser_type".to_string()));
        assert!(def.tools.contains(&"browser_screenshot".to_string()));
        assert!(def.tools.contains(&"browser_read_page".to_string()));
        assert!(def.tools.contains(&"browser_close".to_string()));
        assert!(!def.settings.is_empty());
        assert!(!def.dashboard.metrics.is_empty());
        assert!((def.agent.temperature - 0.3).abs() < f32::EPSILON);
        assert_eq!(def.agent.max_iterations, Some(60));
    }

    /// Every tool the Browser skill names must be one the manifest declares.
    ///
    /// The skill's frontmatter listed six tools, and it was written against an earlier
    /// manifest: the reader was handed a tool list that did not match the tools it would
    /// actually be given. A skill is injected into the agent's context as fact, so a name
    /// in it that the hand cannot call is a tool call that fails for no visible reason.
    #[test]
    fn browser_skill_names_only_tools_the_hand_has() {
        let (id, toml_content, skill_content) = bundled_hands()
            .into_iter()
            .find(|(id, _, _)| *id == "browser")
            .unwrap();
        let def = parse_bundled(id, toml_content, skill_content).unwrap();
        let skill = def.skill_content.as_deref().unwrap();

        let listed = skill
            .lines()
            .find(|line| line.starts_with("tools: ["))
            .expect("the Browser skill no longer declares its tools");
        let named: Vec<&str> = listed
            .trim_start_matches("tools: [")
            .trim_end_matches(']')
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .collect();

        assert!(
            named.len() >= 10,
            "the skill names only {} tools, which is too few to be the real surface",
            named.len()
        );
        for name in named {
            assert!(
                def.tools.iter().any(|tool| tool == name),
                "the Browser skill names `{name}`, which HAND.toml does not declare"
            );
        }
    }

    /// The skill has to be able to get the provider installed, because without one every
    /// other instruction in it describes something that cannot happen.
    ///
    /// This is also the product's install funnel: the skill is published to the agent-skill
    /// registries, where its reader has no extension, no bridge and no reason to guess that
    /// the native messaging host is a separate step. Each of these was absent from the
    /// first version, which told the reader to call a tool it did not have yet.
    #[test]
    fn browser_skill_carries_the_install_path() {
        let (id, toml_content, skill_content) = bundled_hands()
            .into_iter()
            .find(|(id, _, _)| *id == "browser")
            .unwrap();
        let def = parse_bundled(id, toml_content, skill_content).unwrap();
        let skill = def.skill_content.as_deref().unwrap();

        for required in [
            // The bridge's whole setup since 1.3.0. This used to demand
            // `npm install -g` plus `mcp-session-bridge --install`, the native-host
            // registration 1.3.0 made unnecessary; requiring it here kept a stale
            // instruction in the skill.
            "npx -y @t3ratech/mcp-session-bridge",
            // The stores that are actually live. Opera is still in review and must not
            // be offered here as though a reader could install from it.
            "https://chromewebstore.google.com/detail/egpckhdpkoeimoekciejbmbbcackhdmd",
            "https://microsoftedge.microsoft.com/addons/detail/t3rnel-browser/dnplmolfblplbeclnglmjamppekpbcjo",
            "https://addons.mozilla.org/en-US/firefox/addon/t3rnel-browser/",
            // The free path, so the skill is not a paywall dressed as instructions.
            "T3RNEL_SESSION_MODE=standalone",
        ] {
            assert!(
                skill.contains(required),
                "the Browser skill no longer tells the reader `{required}`"
            );
        }

        assert!(
            !skill.contains("addons.opera.com"),
            "the Browser skill offers the Opera listing, which is not published yet"
        );
    }

    #[test]
    fn all_bundled_hands_parse() {
        for (id, toml_content, skill_content) in bundled_hands() {
            let def = parse_bundled(id, toml_content, skill_content)
                .unwrap_or_else(|e| panic!("Failed to parse hand '{}': {}", id, e));
            assert_eq!(def.id, id);
            assert!(!def.name.is_empty());
            assert!(!def.tools.is_empty());
            assert!(!def.agent.system_prompt.is_empty());
            assert!(def.skill_content.is_some());
        }
    }

    #[test]
    fn all_einstein_hands_have_schedules() {
        let einstein_ids = [
            "collector",
            "predictor",
            "researcher",
        ];
        for (id, toml_content, skill_content) in bundled_hands() {
            if einstein_ids.contains(&id) {
                let def = parse_bundled(id, toml_content, skill_content).unwrap();
                assert!(
                    def.tools.contains(&"schedule_create".to_string()),
                    "Einstein hand '{}' must have schedule_create tool",
                    id
                );
                assert!(
                    def.tools.contains(&"schedule_list".to_string()),
                    "Einstein hand '{}' must have schedule_list tool",
                    id
                );
                assert!(
                    def.tools.contains(&"schedule_delete".to_string()),
                    "Einstein hand '{}' must have schedule_delete tool",
                    id
                );
            }
        }
    }

    #[test]
    fn all_einstein_hands_have_memory() {
        let einstein_ids = [
            "collector",
            "predictor",
            "researcher",
        ];
        for (id, toml_content, skill_content) in bundled_hands() {
            if einstein_ids.contains(&id) {
                let def = parse_bundled(id, toml_content, skill_content).unwrap();
                assert!(
                    def.tools.contains(&"memory_store".to_string()),
                    "Einstein hand '{}' must have memory_store tool",
                    id
                );
                assert!(
                    def.tools.contains(&"memory_recall".to_string()),
                    "Einstein hand '{}' must have memory_recall tool",
                    id
                );
            }
        }
    }

    #[test]
    fn parse_infisical_sync_hand() {
        let (id, toml_content, skill_content) = bundled_hands()
            .into_iter()
            .find(|(id, _, _)| *id == "infisical-sync")
            .expect("infisical-sync hand must be in bundled_hands()");
        let def = parse_bundled(id, toml_content, skill_content).unwrap();
        assert_eq!(def.id, "infisical-sync");
        assert_eq!(def.name, "Infisical Sync Hand");
        assert_eq!(def.category, crate::HandCategory::Security);
        assert!(def.skill_content.is_some());
        // Required env vars
        assert!(
            !def.requires.is_empty(),
            "infisical-sync must declare env var requirements"
        );
        let req_keys: Vec<&str> = def.requires.iter().map(|r| r.key.as_str()).collect();
        assert!(
            req_keys.contains(&"INFISICAL_URL"),
            "must require INFISICAL_URL"
        );
        assert!(
            req_keys.contains(&"INFISICAL_CLIENT_ID"),
            "must require INFISICAL_CLIENT_ID"
        );
        assert!(
            req_keys.contains(&"INFISICAL_CLIENT_SECRET"),
            "must require INFISICAL_CLIENT_SECRET"
        );
        // Einstein scheduling tools
        assert!(
            def.tools.contains(&"schedule_create".to_string()),
            "must have schedule_create"
        );
        assert!(
            def.tools.contains(&"schedule_list".to_string()),
            "must have schedule_list"
        );
        assert!(
            def.tools.contains(&"schedule_delete".to_string()),
            "must have schedule_delete"
        );
        // Memory tools
        assert!(
            def.tools.contains(&"memory_store".to_string()),
            "must have memory_store"
        );
        assert!(
            def.tools.contains(&"memory_recall".to_string()),
            "must have memory_recall"
        );
        // Knowledge graph tools
        assert!(
            def.tools.contains(&"knowledge_add_entity".to_string()),
            "must have knowledge_add_entity"
        );
        assert!(
            def.tools.contains(&"knowledge_add_relation".to_string()),
            "must have knowledge_add_relation"
        );
        assert!(
            def.tools.contains(&"knowledge_query".to_string()),
            "must have knowledge_query"
        );
        // Event bus
        assert!(
            def.tools.contains(&"event_publish".to_string()),
            "must have event_publish"
        );
        // Infisical-specific tools
        assert!(
            def.tools.contains(&"shell_exec".to_string()),
            "must have shell_exec"
        );
        assert!(
            def.tools.contains(&"vault_set".to_string()),
            "must have vault_set"
        );
        assert!(
            def.tools.contains(&"vault_get".to_string()),
            "must have vault_get"
        );
        assert!(
            def.tools.contains(&"vault_list".to_string()),
            "must have vault_list"
        );
        assert!(
            def.tools.contains(&"vault_delete".to_string()),
            "must have vault_delete"
        );
        // Dashboard
        assert!(
            !def.dashboard.metrics.is_empty(),
            "must have dashboard metrics"
        );
        let metric_keys: Vec<&str> = def
            .dashboard
            .metrics
            .iter()
            .map(|m| m.memory_key.as_str())
            .collect();
        assert!(
            metric_keys.contains(&"infisical_sync_secrets_count"),
            "must have secrets_count metric"
        );
        assert!(
            metric_keys.contains(&"infisical_sync_last_sync"),
            "must have last_sync metric"
        );
        // Agent config
        assert!(
            !def.agent.system_prompt.is_empty(),
            "must have system_prompt"
        );
        assert!(
            def.agent.temperature < 0.2,
            "security hand should use low temperature"
        );
    }

    #[test]
    fn all_einstein_hands_have_knowledge_graph() {
        let einstein_ids = [
            "collector",
            "predictor",
            "researcher",
        ];
        for (id, toml_content, skill_content) in bundled_hands() {
            if einstein_ids.contains(&id) {
                let def = parse_bundled(id, toml_content, skill_content).unwrap();
                assert!(
                    def.tools.contains(&"knowledge_add_entity".to_string()),
                    "Einstein hand '{}' must have knowledge_add_entity tool",
                    id
                );
                assert!(
                    def.tools.contains(&"knowledge_add_relation".to_string()),
                    "Einstein hand '{}' must have knowledge_add_relation tool",
                    id
                );
                assert!(
                    def.tools.contains(&"knowledge_query".to_string()),
                    "Einstein hand '{}' must have knowledge_query tool",
                    id
                );
            }
        }
    }
}
