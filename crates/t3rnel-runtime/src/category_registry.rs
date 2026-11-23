//! Category registry for agent categorization and fallback chains.
//!
//! Manages template-based agent categorization with inheritable 6-layer fallback chains.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use t3rnel_types::agent::{AgentCategory, FallbackChain, FallbackModel, RecoveryConfig};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Map a `category-templates.toml` section name to an [`AgentCategory`].
///
/// Delegates to the shared lenient parser so template section names, manifest
/// `category = ...` values and API payloads all accept the same spellings
/// (case- and separator-insensitive).
pub fn category_from_name(name: &str) -> Option<AgentCategory> {
    AgentCategory::parse_lenient(name)
}

/// Category registry for managing agent categories and fallback chains.
pub struct CategoryRegistry {
    /// Fallback chains per category.
    chains: Arc<RwLock<HashMap<AgentCategory, FallbackChain>>>,
}

impl CategoryRegistry {
    /// Create a new category registry.
    pub fn new() -> Self {
        Self {
            chains: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Parse category templates from TOML text.
    ///
    /// Synchronous and pure so the kernel can load the chains during its
    /// (blocking) boot sequence, before the driver chain is built.
    pub fn parse_templates(
        content: &str,
    ) -> Result<HashMap<AgentCategory, FallbackChain>, Box<dyn std::error::Error>> {
        let config: CategoryTemplates = toml::from_str(content)?;
        let mut chains = HashMap::new();

        for (category_name, template) in config.categories {
            let Some(category) = category_from_name(&category_name) else {
                warn!("Unknown category: {}, skipping", category_name);
                continue;
            };

            chains.insert(
                category,
                FallbackChain {
                    category,
                    models: template
                        .models
                        .into_iter()
                        .map(|m| FallbackModel {
                            provider: m.provider,
                            model: m.model,
                            api_key_env: m.api_key_env,
                            base_url: m.base_url,
                            weight: m.weight,
                            handles_errors: m.handles_errors.unwrap_or_default(),
                        })
                        .collect(),
                    recovery_config: RecoveryConfig::default(),
                },
            );
        }
        Ok(chains)
    }

    /// Load category templates from a TOML file.
    pub async fn load_from_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let content = tokio::fs::read_to_string(path).await?;
        let parsed = Self::parse_templates(&content)?;
        let mut chains = self.chains.write().await;
        for (category, chain) in parsed {
            info!("Loaded fallback chain for category: {:?}", category);
            chains.insert(category, chain);
        }
        Ok(())
    }

    /// Get the fallback chain for a category.
    pub async fn get_chain(&self, category: AgentCategory) -> Option<FallbackChain> {
        let chains = self.chains.read().await;
        chains.get(&category).cloned()
    }

    /// Register a fallback chain for a category.
    pub async fn register_chain(&self, chain: FallbackChain) {
        let mut chains = self.chains.write().await;
        chains.insert(chain.category, chain);
    }

    /// Get all registered categories.
    pub async fn get_categories(&self) -> Vec<AgentCategory> {
        let chains = self.chains.read().await;
        chains.keys().copied().collect()
    }
}

impl Default for CategoryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Category templates configuration from TOML.
#[derive(Debug, serde::Deserialize)]
struct CategoryTemplates {
    categories: HashMap<String, CategoryTemplate>,
}

/// Template for a single category.
#[derive(Debug, serde::Deserialize)]
struct CategoryTemplate {
    #[serde(rename = "fallback_chain")]
    models: Vec<ModelTemplate>,
}

/// Template for a single model in a fallback chain.
#[derive(Debug, serde::Deserialize)]
struct ModelTemplate {
    provider: String,
    model: String,
    #[serde(default)]
    api_key_env: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    weight: Option<u32>,
    #[serde(default)]
    handles_errors: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registry_creation() {
        let registry = CategoryRegistry::new();
        assert_eq!(registry.get_categories().await.len(), 0);
    }

    #[tokio::test]
    async fn test_register_chain() {
        let registry = CategoryRegistry::new();
        let chain = FallbackChain {
            category: AgentCategory::Coding,
            models: vec![FallbackModel {
                provider: "nvidia".to_string(),
                model: "deepseek/v4".to_string(),
                api_key_env: Some("NVIDIA_API_KEY".to_string()),
                base_url: None,
                weight: Some(100),
                handles_errors: vec![],
            }],
            recovery_config: RecoveryConfig::default(),
        };

        registry.register_chain(chain).await;
        assert_eq!(registry.get_categories().await.len(), 1);

        let retrieved = registry.get_chain(AgentCategory::Coding).await;
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_get_chain_nonexistent() {
        let registry = CategoryRegistry::new();
        let retrieved = registry.get_chain(AgentCategory::Coding).await;
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_load_from_toml() {
        let registry = CategoryRegistry::new();
        let toml_content = r#"
[categories.coding]
fallback_chain = [
    { provider = "nvidia", model = "deepseek/v4", api_key_env = "NVIDIA_API_KEY", weight = 100 },
    { provider = "openrouter", model = "llama-3", weight = 90 }
]

[categories.general]
fallback_chain = [
    { provider = "openai", model = "gpt-4o", api_key_env = "OPENAI_API_KEY", weight = 100 }
]
"#;

        let temp_file = "/tmp/test_categories.toml";
        tokio::fs::write(temp_file, toml_content).await.unwrap();

        let result = registry.load_from_file(temp_file).await;
        assert!(result.is_ok());

        assert_eq!(registry.get_categories().await.len(), 2);

        let coding_chain = registry.get_chain(AgentCategory::Coding).await;
        assert!(coding_chain.is_some());
        assert_eq!(coding_chain.unwrap().models.len(), 2);

        tokio::fs::remove_file(temp_file).await.unwrap();
    }

    #[tokio::test]
    async fn test_default_registry() {
        let registry = CategoryRegistry::default();
        assert_eq!(registry.get_categories().await.len(), 0);
    }

    // ---- Regression tests for the category-routing repair ----
    //
    // Each of these fails against the pre-fix state. They exist because
    // "all agents display one model" had three independent causes, and a
    // green build told us nothing about any of them.

    /// The shipped config must actually parse. It once did not: a duplicate
    /// `[categories.orchestration]` made it invalid TOML, and the API route
    /// swallowed the parse error and served an empty catalog — so the config
    /// was broken for weeks while every surface reported success.
    #[test]
    fn test_shipped_template_file_parses() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/category-templates.toml"
        );
        let content = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("shipped template must be readable at {path}: {e}"));

        let chains = CategoryRegistry::parse_templates(&content)
            .unwrap_or_else(|e| panic!("shipped category-templates.toml must parse: {e}"));

        assert!(
            chains.len() >= 20,
            "expected the full category set, got {}",
            chains.len()
        );
        for (category, chain) in &chains {
            assert!(
                !chain.models.is_empty(),
                "{category:?} has an empty fallback chain — an agent in this \
                 category would have nothing to fall back to"
            );
        }
    }

    /// A duplicate category table is a hard error, not a silently-kept last value.
    #[test]
    fn test_duplicate_category_key_is_rejected_loudly() {
        let dup = r#"
[categories.coding]
fallback_chain = [{ provider = "nvidia", model = "a", weight = 100 }]

[categories.coding]
fallback_chain = [{ provider = "groq", model = "b", weight = 100 }]
"#;
        assert!(
            CategoryRegistry::parse_templates(dup).is_err(),
            "a duplicate [categories.*] table must fail parsing rather than \
             silently discard one of the chains"
        );
    }

    /// Manifests in the repo use `coding`; deployed manifests use `Coding`.
    /// Category is non-optional, so a strict parse failed the whole manifest
    /// and those agents never spawned at all.
    #[test]
    fn test_category_names_parse_across_casing_conventions() {
        // Repo manifests use `coding`; deployed manifests use `Coding`. Both
        // must land on the same category or the two sets of agents route
        // differently for no reason a reader could see.
        for name in ["coding", "Coding", "CODING", "  coding  "] {
            assert!(
                category_from_name(name).is_some(),
                "{name:?} must resolve to a category"
            );
        }
        assert_eq!(category_from_name("coding"), category_from_name("Coding"));

        // Documented aliases for names real manifests use that are not variants.
        assert_eq!(
            category_from_name("qa"),
            category_from_name("testing"),
            "`qa` is an alias for testing"
        );
        assert_eq!(category_from_name("ops"), category_from_name("operations"));

        // An unknown name yields None here. Degrading to `general` is the
        // *deserializer's* job, not this function's — keeping the distinction
        // means a caller that needs to know "was this recognised?" still can.
        assert!(
            category_from_name("no-such-category-xyz").is_none(),
            "parse must report non-recognition; the Deserialize impl chooses the default"
        );
    }

    /// The degrade-to-default contract, asserted where it actually lives.
    /// `category` is a non-optional field, so a strict parse failed the entire
    /// manifest and those agents never spawned at all.
    #[test]
    fn test_unknown_category_degrades_instead_of_failing_the_manifest() {
        let parsed: Result<AgentCategory, _> = serde_json::from_str("\"totally-unknown-category\"");
        let category = parsed.expect("an unknown category must not fail deserialization");
        assert_eq!(
            category,
            AgentCategory::General,
            "unknown categories route through the general chain"
        );

        // And the common real-world casings still deserialize to themselves.
        let lower: AgentCategory = serde_json::from_str("\"coding\"").unwrap();
        let pascal: AgentCategory = serde_json::from_str("\"Coding\"").unwrap();
        assert_eq!(lower, pascal);
    }

    /// Chain resolution is per-category: two categories must not collapse to
    /// the same chain, which is what "every agent shows one model" looked like.
    #[tokio::test]
    async fn test_chain_resolution_is_per_category() {
        let registry = CategoryRegistry::new();
        let toml = r#"
[categories.coding]
fallback_chain = [
    { provider = "nvidia", model = "coder-a", weight = 100 },
    { provider = "groq", model = "coder-b", weight = 90 }
]

[categories.creative]
fallback_chain = [
    { provider = "gemini", model = "writer-a", weight = 100 }
]
"#;
        for (cat, chain) in CategoryRegistry::parse_templates(toml).unwrap() {
            registry.register_chain(chain).await;
            let _ = cat;
        }

        let coding = registry
            .get_chain(AgentCategory::Coding)
            .await
            .expect("coding chain");
        let creative = registry
            .get_chain(AgentCategory::Creative)
            .await
            .expect("creative chain");

        assert_eq!(coding.models.len(), 2);
        assert_eq!(creative.models.len(), 1);
        assert_ne!(
            coding.models[0].model, creative.models[0].model,
            "categories must resolve to distinct chains"
        );
    }

    /// An agent whose category has no template must be detectable, so it can
    /// fall through to the global chain deliberately rather than by accident.
    #[tokio::test]
    async fn test_missing_category_is_reported_not_guessed() {
        let registry = CategoryRegistry::new();
        let toml = r#"
[categories.coding]
fallback_chain = [{ provider = "nvidia", model = "a", weight = 100 }]
"#;
        for (_, chain) in CategoryRegistry::parse_templates(toml).unwrap() {
            registry.register_chain(chain).await;
        }
        assert!(registry.get_chain(AgentCategory::Coding).await.is_some());
        assert!(
            registry.get_chain(AgentCategory::Media).await.is_none(),
            "an absent category must return None so the caller chooses the \
             fallback explicitly"
        );
    }

    /// Re-registering a category replaces its chain — this is what makes
    /// reloading `category-templates.toml` at runtime coherent.
    #[tokio::test]
    async fn test_reregistering_a_category_replaces_its_chain() {
        let registry = CategoryRegistry::new();
        let mk = |model: &str| FallbackChain {
            category: AgentCategory::Coding,
            models: vec![FallbackModel {
                provider: "nvidia".to_string(),
                model: model.to_string(),
                api_key_env: None,
                base_url: None,
                weight: Some(100),
                handles_errors: vec![],
            }],
            recovery_config: RecoveryConfig::default(),
        };

        registry.register_chain(mk("old-model")).await;
        registry.register_chain(mk("new-model")).await;

        assert_eq!(
            registry.get_categories().await.len(),
            1,
            "re-registering must replace, not duplicate"
        );
        let chain = registry.get_chain(AgentCategory::Coding).await.unwrap();
        assert_eq!(chain.models[0].model, "new-model");
    }
}
