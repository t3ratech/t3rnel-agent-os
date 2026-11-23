//! Versioned prompt loader with frontmatter validation and A/B selection.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum PromptError {
    #[error("prompt must start with YAML frontmatter")]
    MissingFrontmatter,
    #[error("prompt frontmatter is missing closing delimiter")]
    MissingFrontmatterEnd,
    #[error("invalid prompt frontmatter: {0}")]
    InvalidFrontmatter(String),
    #[error("missing required prompt field: {0}")]
    MissingField(&'static str),
    #[error("prompt I/O error: {0}")]
    Io(String),
}

/// Version-pinning configuration: force a specific prompt SHA or version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinConfig {
    /// If set, only this exact sha256 is ever served.
    #[serde(default)]
    pub sha256: Option<String>,
    /// If set, only this exact version string is ever served.
    #[serde(default)]
    pub version: Option<String>,
    /// Human-readable reason for the pin (e.g. "regression in v2.0.1").
    #[serde(default)]
    pub reason: Option<String>,
}

/// A/B test configuration attached to a prompt frontmatter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbTestConfig {
    /// Whether this prompt participates in an active A/B experiment.
    #[serde(default)]
    pub active: bool,
    /// Target traffic split percentage for this variant (0–100).
    #[serde(default)]
    pub traffic_pct: u8,
    /// Name of the experiment this variant belongs to.
    #[serde(default)]
    pub experiment_id: Option<String>,
    /// Success metric to optimise (e.g. "pass_rate", "latency_ms", "human_rating").
    #[serde(default)]
    pub metric: Option<String>,
}

/// YAML frontmatter schema for `prompts/<role>/<name>.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptFrontmatter {
    pub version: String,
    pub role: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub variant: Option<String>,
    #[serde(default)]
    pub model_hints: Vec<String>,
    pub eval_set: String,
    #[serde(default)]
    pub parents: Vec<String>,
    #[serde(default)]
    pub pin_config: Option<PinConfig>,
    #[serde(default)]
    pub ab_test: Option<AbTestConfig>,
}

impl PromptFrontmatter {
    fn validate(&self) -> Result<(), PromptError> {
        if self.version.trim().is_empty() {
            return Err(PromptError::MissingField("version"));
        }
        if self.role.trim().is_empty() {
            return Err(PromptError::MissingField("role"));
        }
        if self.eval_set.trim().is_empty() {
            return Err(PromptError::MissingField("eval_set"));
        }
        Ok(())
    }
}

/// Loaded prompt document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PromptDocument {
    pub path: PathBuf,
    pub id: String,
    pub frontmatter: PromptFrontmatter,
    pub body: String,
    pub sha256: String,
}

impl PromptDocument {
    pub fn version_attribute(&self) -> String {
        format!("{}@{}:{}", self.id, self.frontmatter.version, self.sha256)
    }
}

/// Parse a prompt markdown document with YAML frontmatter.
pub fn parse_prompt(
    path: impl Into<PathBuf>,
    content: &str,
) -> Result<PromptDocument, PromptError> {
    if !content.starts_with("---\n") {
        return Err(PromptError::MissingFrontmatter);
    }
    let rest = &content[4..];
    let Some(end) = rest.find("\n---\n") else {
        return Err(PromptError::MissingFrontmatterEnd);
    };
    let yaml = &rest[..end];
    let body = rest[end + 5..].trim_start_matches('\n').to_string();
    let frontmatter: PromptFrontmatter = serde_yaml::from_str(yaml)
        .map_err(|err| PromptError::InvalidFrontmatter(err.to_string()))?;
    frontmatter.validate()?;

    let path = path.into();
    let name = frontmatter.name.clone().unwrap_or_else(|| {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("prompt")
            .to_string()
    });
    let variant = frontmatter.variant.as_deref().unwrap_or("A");
    let id = format!("{}/{}@{variant}", frontmatter.role, name);
    let sha256 = hex::encode(Sha256::digest(content.as_bytes()));

    Ok(PromptDocument {
        path,
        id,
        frontmatter,
        body,
        sha256,
    })
}

/// In-memory prompt cache.
#[derive(Debug, Clone, Default)]
pub struct PromptCache {
    prompts: HashMap<String, PromptDocument>,
}

impl PromptCache {
    pub fn load_dir(root: impl AsRef<Path>) -> Result<Self, PromptError> {
        let root = root.as_ref();
        let mut cache = Self::default();
        for entry in walkdir::WalkDir::new(root) {
            let entry = entry.map_err(|err| PromptError::Io(err.to_string()))?;
            if !entry.file_type().is_file()
                || entry.path().extension().and_then(|ext| ext.to_str()) != Some("md")
            {
                continue;
            }
            let content = std::fs::read_to_string(entry.path())
                .map_err(|err| PromptError::Io(err.to_string()))?;
            let prompt = parse_prompt(entry.path().to_path_buf(), &content)?;
            cache.prompts.insert(prompt.id.clone(), prompt);
        }
        Ok(cache)
    }

    pub fn get(&self, id: &str) -> Option<&PromptDocument> {
        self.prompts.get(id)
    }

    /// Resolve a prompt by id, logging its version attribute on every invocation (P1.S18).
    pub fn resolve(&self, id: &str, task_id: Option<&str>) -> Option<&PromptDocument> {
        let prompt = self.prompts.get(id)?;
        tracing::info!(
            prompt_id = %prompt.id,
            version = %prompt.frontmatter.version,
            sha256 = %prompt.sha256,
            task_id = task_id.unwrap_or("-"),
            "Prompt invoked"
        );
        Some(prompt)
    }

    /// Rollback: return the prompt with the given id that has the specified version.
    /// This is used for deterministic replay or rollback to a known-good prompt.
    pub fn get_at_version(&self, id: &str, version: &str) -> Option<&PromptDocument> {
        let prompt = self.prompts.get(id)?;
        if prompt.frontmatter.version == version {
            tracing::info!(
                prompt_id = %prompt.id,
                version = %prompt.frontmatter.version,
                sha256 = %prompt.sha256,
                "Prompt rollback resolved"
            );
            Some(prompt)
        } else {
            tracing::warn!(
                prompt_id = %prompt.id,
                requested_version = %version,
                current_version = %prompt.frontmatter.version,
                "Prompt version mismatch for rollback"
            );
            None
        }
    }

    pub fn list(&self) -> Vec<&PromptDocument> {
        let mut prompts: Vec<&PromptDocument> = self.prompts.values().collect();
        prompts.sort_by(|left, right| left.id.cmp(&right.id));
        prompts
    }
}

/// Deterministically choose a prompt variant from a task id and prompt name.
pub fn select_variant(task_id: &str, name: &str, variants: &[String]) -> Option<String> {
    if variants.is_empty() {
        return None;
    }
    let mut sorted = variants.to_vec();
    sorted.sort();
    let digest = Sha256::digest(format!("{task_id}:{name}").as_bytes());
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    let index = (u64::from_be_bytes(bytes) as usize) % sorted.len();
    Some(sorted[index].clone())
}

/// Outcome of a single prompt invocation used for win-rate tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromptOutcome {
    Win,
    Loss,
    Draw,
}

/// SQLite-backed tracker for prompt A/B win rates.
pub struct WinRateTracker {
    conn: rusqlite::Connection,
}

impl WinRateTracker {
    /// Open or create the win-rate database at the given path.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, PromptError> {
        let conn = rusqlite::Connection::open(path).map_err(|e| PromptError::Io(e.to_string()))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS prompt_outcomes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                prompt_id TEXT NOT NULL,
                variant TEXT NOT NULL,
                experiment_id TEXT,
                outcome TEXT NOT NULL CHECK(outcome IN ('win','loss','draw')),
                metric_value REAL,
                recorded_at TEXT NOT NULL
            )",
            [],
        )
        .map_err(|e| PromptError::Io(e.to_string()))?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_outcomes_prompt ON prompt_outcomes(prompt_id, variant)",
            [],
        )
        .map_err(|e| PromptError::Io(e.to_string()))?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_outcomes_experiment ON prompt_outcomes(experiment_id)",
            [],
        )
        .map_err(|e| PromptError::Io(e.to_string()))?;
        Ok(Self { conn })
    }

    /// Record the outcome of a prompt invocation.
    pub fn record_outcome(
        &self,
        prompt_id: &str,
        variant: &str,
        experiment_id: Option<&str>,
        outcome: PromptOutcome,
        metric_value: Option<f64>,
    ) -> Result<(), PromptError> {
        let outcome_str = match outcome {
            PromptOutcome::Win => "win",
            PromptOutcome::Loss => "loss",
            PromptOutcome::Draw => "draw",
        };
        let now = chrono::Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO prompt_outcomes
                 (prompt_id, variant, experiment_id, outcome, metric_value, recorded_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    prompt_id,
                    variant,
                    experiment_id,
                    outcome_str,
                    metric_value,
                    now,
                ],
            )
            .map_err(|e| PromptError::Io(e.to_string()))?;
        Ok(())
    }

    /// Get win-rate statistics for a given prompt + variant.
    pub fn get_win_rate(
        &self,
        prompt_id: &str,
        variant: &str,
    ) -> Result<WinRateStats, PromptError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN outcome = 'win' THEN 1 ELSE 0 END) as wins,
                    SUM(CASE WHEN outcome = 'loss' THEN 1 ELSE 0 END) as losses,
                    SUM(CASE WHEN outcome = 'draw' THEN 1 ELSE 0 END) as draws,
                    AVG(metric_value) as avg_metric
                 FROM prompt_outcomes
                 WHERE prompt_id = ?1 AND variant = ?2",
            )
            .map_err(|e| PromptError::Io(e.to_string()))?;
        let row = stmt
            .query_row([prompt_id, variant], |row| {
                let total: i64 = row.get(0)?;
                let wins: i64 = row.get(1)?;
                let losses: i64 = row.get(2)?;
                let draws: i64 = row.get(3)?;
                let avg_metric: Option<f64> = row.get(4)?;
                Ok(WinRateStats {
                    total: total.max(0) as u64,
                    wins: wins.max(0) as u64,
                    losses: losses.max(0) as u64,
                    draws: draws.max(0) as u64,
                    avg_metric,
                })
            })
            .map_err(|e| PromptError::Io(e.to_string()))?;
        Ok(row)
    }

    /// Summarise all variants in an experiment.
    pub fn experiment_summary(
        &self,
        experiment_id: &str,
    ) -> Result<Vec<ExperimentVariantSummary>, PromptError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT
                    prompt_id,
                    variant,
                    COUNT(*) as total,
                    SUM(CASE WHEN outcome = 'win' THEN 1 ELSE 0 END) as wins,
                    AVG(metric_value) as avg_metric
                 FROM prompt_outcomes
                 WHERE experiment_id = ?1
                 GROUP BY prompt_id, variant
                 ORDER BY total DESC",
            )
            .map_err(|e| PromptError::Io(e.to_string()))?;
        let rows = stmt
            .query_map([experiment_id], |row| {
                let total: i64 = row.get(2)?;
                let wins: i64 = row.get(3)?;
                let avg_metric: Option<f64> = row.get(4)?;
                Ok(ExperimentVariantSummary {
                    prompt_id: row.get(0)?,
                    variant: row.get(1)?,
                    total: total.max(0) as u64,
                    wins: wins.max(0) as u64,
                    avg_metric,
                    win_rate: if total > 0 {
                        (wins as f64) / (total as f64)
                    } else {
                        0.0
                    },
                })
            })
            .map_err(|e| PromptError::Io(e.to_string()))?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|e| PromptError::Io(e.to_string()))?);
        }
        Ok(results)
    }
}

/// Win-rate statistics for a single prompt variant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WinRateStats {
    pub total: u64,
    pub wins: u64,
    pub losses: u64,
    pub draws: u64,
    pub avg_metric: Option<f64>,
}

impl WinRateStats {
    /// Computed win rate as a fraction (0.0 – 1.0).
    pub fn win_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.wins as f64) / (self.total as f64)
        }
    }
}

/// Summary row for one variant within an experiment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExperimentVariantSummary {
    pub prompt_id: String,
    pub variant: String,
    pub total: u64,
    pub wins: u64,
    pub avg_metric: Option<f64>,
    pub win_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROMPT: &str = r#"---
version: 1.2.3
role: coder
name: system
variant: B
model_hints:
  - default
eval_set: cli-todo-app
parents: []
---

# Coder

Implement the task.
"#;

    #[test]
    fn frontmatter_parses_and_hashes_prompt() {
        let prompt = parse_prompt("prompts/coder/system.md", PROMPT).unwrap();
        assert_eq!(prompt.id, "coder/system@B");
        assert_eq!(prompt.frontmatter.version, "1.2.3");
        assert_eq!(prompt.frontmatter.model_hints, vec!["default"]);
        assert_eq!(prompt.body.trim(), "# Coder\n\nImplement the task.");
        assert_eq!(prompt.sha256.len(), 64);
        assert!(prompt
            .version_attribute()
            .starts_with("coder/system@B@1.2.3:"));
    }

    #[test]
    fn frontmatter_rejects_missing_required_fields() {
        let err = parse_prompt(
            "bad.md",
            "---\nversion: 1\nrole: ''\neval_set: eval\n---\nbody",
        )
        .unwrap_err();
        assert!(matches!(err, PromptError::MissingField("role")));
    }

    #[test]
    fn ab_selection_is_stable_and_sorted() {
        let variants = vec!["B".to_string(), "A".to_string(), "C".to_string()];
        let first = select_variant("task-1", "coder/system", &variants).unwrap();
        let second = select_variant("task-1", "coder/system", &variants).unwrap();
        assert_eq!(first, second);
        assert!(["A", "B", "C"].contains(&first.as_str()));
    }

    #[test]
    fn resolve_logs_and_returns_prompt() {
        let prompt = parse_prompt("prompts/coder/system.md", PROMPT).unwrap();
        let mut cache = PromptCache::default();
        cache.prompts.insert(prompt.id.clone(), prompt);
        let resolved = cache.resolve("coder/system@B", Some("task-42"));
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().frontmatter.version, "1.2.3");
    }

    #[test]
    fn rollback_returns_matching_version() {
        let prompt = parse_prompt("prompts/coder/system.md", PROMPT).unwrap();
        let mut cache = PromptCache::default();
        cache.prompts.insert(prompt.id.clone(), prompt);
        let rolled = cache.get_at_version("coder/system@B", "1.2.3");
        assert!(rolled.is_some());
        assert_eq!(rolled.unwrap().sha256.len(), 64);
    }

    #[test]
    fn rollback_rejects_mismatched_version() {
        let prompt = parse_prompt("prompts/coder/system.md", PROMPT).unwrap();
        let mut cache = PromptCache::default();
        cache.prompts.insert(prompt.id.clone(), prompt);
        let rolled = cache.get_at_version("coder/system@B", "0.0.1");
        assert!(rolled.is_none());
    }

    #[test]
    fn cache_loads_prompt_directory() {
        let dir = tempfile::tempdir().unwrap();
        let prompt_dir = dir.path().join("coder");
        std::fs::create_dir_all(&prompt_dir).unwrap();
        std::fs::write(prompt_dir.join("system.md"), PROMPT).unwrap();

        let cache = PromptCache::load_dir(dir.path()).unwrap();
        assert_eq!(cache.list().len(), 1);
        assert!(cache.get("coder/system@B").is_some());
    }

    #[test]
    fn repo_prompt_library_loads() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../prompts");
        let cache = PromptCache::load_dir(root).unwrap();
        assert!(cache.get("coder/system@A").is_some());
        assert!(cache.get("reviewer/system@A").is_some());
    }

    #[test]
    fn win_rate_tracker_records_and_summarises() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("winrates.db");
        let tracker = WinRateTracker::open(&db).unwrap();

        tracker
            .record_outcome(
                "coder/system@B",
                "B",
                Some("exp-1"),
                PromptOutcome::Win,
                Some(0.95),
            )
            .unwrap();
        tracker
            .record_outcome(
                "coder/system@B",
                "B",
                Some("exp-1"),
                PromptOutcome::Loss,
                None,
            )
            .unwrap();
        tracker
            .record_outcome(
                "coder/system@B",
                "B",
                Some("exp-1"),
                PromptOutcome::Win,
                Some(0.88),
            )
            .unwrap();

        let stats = tracker.get_win_rate("coder/system@B", "B").unwrap();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.wins, 2);
        assert_eq!(stats.losses, 1);
        assert_eq!(stats.win_rate(), 2.0 / 3.0);
        assert!(stats.avg_metric.unwrap() > 0.9);

        let summary = tracker.experiment_summary("exp-1").unwrap();
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].total, 3);
    }

    #[test]
    fn pin_config_and_ab_test_fields_parse() {
        let raw = r#"---
version: 2.0.0
role: tester
name: ab-demo
eval_set: smoke
pin_config:
  sha256: abc123
  reason: baseline
ab_test:
  active: true
  traffic_pct: 50
  experiment_id: exp-42
  metric: pass_rate
---
body here
"#;
        let prompt = parse_prompt("prompts/tester/ab-demo.md", raw).unwrap();
        assert_eq!(prompt.frontmatter.version, "2.0.0");
        assert!(prompt.frontmatter.pin_config.is_some());
        assert_eq!(
            prompt.frontmatter.pin_config.as_ref().unwrap().sha256,
            Some("abc123".to_string())
        );
        assert!(prompt.frontmatter.ab_test.as_ref().unwrap().active);
        assert_eq!(prompt.frontmatter.ab_test.as_ref().unwrap().traffic_pct, 50);
    }
}
