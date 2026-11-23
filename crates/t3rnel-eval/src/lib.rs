//! Deterministic eval and parity harness primitives.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum EvalError {
    #[error("eval I/O error: {0}")]
    Io(String),
    #[error("invalid eval fixture: {0}")]
    InvalidFixture(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenTask {
    pub id: String,
    pub prompt: String,
    pub acceptance: Vec<String>,
    #[serde(default)]
    pub required_commands: Vec<String>,
}

impl GoldenTask {
    pub fn validate(&self) -> Result<(), EvalError> {
        if self.id.trim().is_empty() {
            return Err(EvalError::InvalidFixture("task id is empty".to_string()));
        }
        if self.prompt.trim().is_empty() {
            return Err(EvalError::InvalidFixture(
                "task prompt is empty".to_string(),
            ));
        }
        if self.acceptance.is_empty() {
            return Err(EvalError::InvalidFixture(
                "task acceptance criteria are empty".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scorecard {
    pub task_id: String,
    pub build_passed: bool,
    pub tests_passed: bool,
    pub security_passed: bool,
    pub docs_present: bool,
}

impl Scorecard {
    pub fn deterministic_score(&self) -> f64 {
        let passed = [
            self.build_passed,
            self.tests_passed,
            self.security_passed,
            self.docs_present,
        ]
        .into_iter()
        .filter(|passed| *passed)
        .count();
        passed as f64 / 4.0
    }

    pub fn is_green(&self) -> bool {
        self.build_passed && self.tests_passed && self.security_passed && self.docs_present
    }
}

/// LLM-as-judge rubric for scoring task outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JudgeRubric {
    pub name: String,
    pub criteria: Vec<String>,
    pub max_score: u8,
}

impl JudgeRubric {
    /// Correctness rubric: does the output solve the stated problem?
    pub fn correctness() -> Self {
        Self {
            name: "correctness".to_string(),
            criteria: vec![
                "output compiles or parses without errors".to_string(),
                "stated requirements are met".to_string(),
                "no logical errors in the solution".to_string(),
            ],
            max_score: 10,
        }
    }

    /// Security rubric: are there obvious vulnerabilities?
    pub fn security() -> Self {
        Self {
            name: "security".to_string(),
            criteria: vec![
                "no hardcoded secrets".to_string(),
                "input is validated or sanitized".to_string(),
                "no obvious injection vectors".to_string(),
            ],
            max_score: 10,
        }
    }

    /// Documentation rubric: is the code/documented adequately?
    pub fn documentation() -> Self {
        Self {
            name: "documentation".to_string(),
            criteria: vec![
                "public API has doc comments".to_string(),
                "README or usage instructions present".to_string(),
                "complex logic is explained".to_string(),
            ],
            max_score: 10,
        }
    }

    /// UX rubric: is the interface intuitive?
    pub fn ux() -> Self {
        Self {
            name: "ux".to_string(),
            criteria: vec![
                "error messages are helpful".to_string(),
                "defaults are sensible".to_string(),
                "no surprising behaviour".to_string(),
            ],
            max_score: 10,
        }
    }
}

/// Score from a single judge rubric.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeScore {
    pub rubric: String,
    pub score: f64,
    pub max_score: u8,
    pub reasoning: String,
}

impl JudgeScore {
    pub fn normalised(&self) -> f64 {
        if self.max_score == 0 {
            0.0
        } else {
            self.score / self.max_score as f64
        }
    }
}

/// Composite scorecard including deterministic checks and LLM judge scores.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompositeScorecard {
    pub task_id: String,
    pub deterministic: Scorecard,
    pub judge_scores: Vec<JudgeScore>,
}

impl CompositeScorecard {
    pub fn overall_score(&self) -> f64 {
        let det = self.deterministic.deterministic_score();
        if self.judge_scores.is_empty() {
            return det;
        }
        let judge_avg: f64 = self
            .judge_scores
            .iter()
            .map(|s| s.normalised())
            .sum::<f64>()
            / self.judge_scores.len() as f64;
        // Weight: 60% deterministic, 40% judge
        det * 0.6 + judge_avg * 0.4
    }

    pub fn is_green(&self) -> bool {
        self.deterministic.is_green() && self.judge_scores.iter().all(|s| s.normalised() >= 0.7)
    }
}

/// Golden-task runner: spawns a fresh sandbox, runs the pipeline, and scores.
pub struct GoldenTaskRunner {
    pub lake: EvalLake,
    pub rubrics: Vec<JudgeRubric>,
}

impl GoldenTaskRunner {
    pub fn new(lake: EvalLake, rubrics: Vec<JudgeRubric>) -> Self {
        Self { lake, rubrics }
    }

    /// Run a single golden task and store the result in the lake.
    pub fn run_task(
        &self,
        task: &GoldenTask,
        run_id: &str,
        scorecard: CompositeScorecard,
    ) -> Result<(), String> {
        let details = serde_json::to_string(&scorecard).map_err(|e| e.to_string())?;
        self.lake.store_result(
            &task.id,
            run_id,
            scorecard.overall_score(),
            scorecard.is_green(),
            &details,
        )
    }
}

pub fn load_golden_tasks(root: impl AsRef<Path>) -> Result<Vec<GoldenTask>, EvalError> {
    let mut tasks = Vec::new();
    for entry in walkdir::WalkDir::new(root.as_ref()) {
        let entry = entry.map_err(|err| EvalError::Io(err.to_string()))?;
        if !entry.file_type().is_file()
            || entry.path().extension().and_then(|ext| ext.to_str()) != Some("json")
        {
            continue;
        }
        let content =
            std::fs::read_to_string(entry.path()).map_err(|err| EvalError::Io(err.to_string()))?;
        let task: GoldenTask = serde_json::from_str(&content)
            .map_err(|err| EvalError::InvalidFixture(err.to_string()))?;
        task.validate()?;
        tasks.push(task);
    }
    tasks.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(tasks)
}

pub fn parity_fixtures(root: impl AsRef<Path>) -> Result<Vec<PathBuf>, EvalError> {
    let mut fixtures = Vec::new();
    for entry in walkdir::WalkDir::new(root.as_ref()) {
        let entry = entry.map_err(|err| EvalError::Io(err.to_string()))?;
        if entry.file_type().is_file()
            && entry.path().extension().and_then(|ext| ext.to_str()) == Some("json")
        {
            fixtures.push(entry.path().to_path_buf());
        }
    }
    fixtures.sort();
    Ok(fixtures)
}

/// EvalLake — persistent SQLite store for evaluation results and regression tracking.
#[derive(Debug, Clone)]
pub struct EvalLake {
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl EvalLake {
    /// Open (or create) the eval lake database.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let conn = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
        let this = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        this.init_schema().map_err(|e| e.to_string())?;
        Ok(this)
    }

    /// Open an in-memory eval lake (for tests).
    pub fn open_in_memory() -> Result<Self, String> {
        let conn = rusqlite::Connection::open_in_memory().map_err(|e| e.to_string())?;
        let this = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        this.init_schema().map_err(|e| e.to_string())?;
        Ok(this)
    }

    fn init_schema(&self) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS eval_results (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id     TEXT NOT NULL,
                run_id      TEXT NOT NULL,
                timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
                score       REAL NOT NULL,
                is_green    INTEGER NOT NULL,
                details     TEXT
            )",
            [],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_eval_task ON eval_results(task_id)",
            [],
        )
        .map_err(|e| e.to_string())?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_eval_run ON eval_results(run_id)",
            [],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Store a single evaluation result.
    pub fn store_result(
        &self,
        task_id: &str,
        run_id: &str,
        score: f64,
        is_green: bool,
        details: &str,
    ) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO eval_results (task_id, run_id, score, is_green, details)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![task_id, run_id, score, is_green as i32, details],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Retrieve all results for a given run.
    pub fn results_for_run(&self, run_id: &str) -> Result<Vec<(String, f64, bool)>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT task_id, score, is_green FROM eval_results
                 WHERE run_id = ?1 ORDER BY id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([run_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, i32>(2)? != 0,
                ))
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// Compute regression delta between two runs.
    /// Returns a map: task_id -> (old_score, new_score, delta).
    pub fn regression_delta(
        &self,
        old_run_id: &str,
        new_run_id: &str,
    ) -> Result<HashMap<String, (f64, f64, f64)>, String> {
        let old_results = self.results_for_run(old_run_id)?;
        let new_results = self.results_for_run(new_run_id)?;

        let old_map: HashMap<String, f64> =
            old_results.into_iter().map(|(id, s, _)| (id, s)).collect();
        let new_map: HashMap<String, f64> =
            new_results.into_iter().map(|(id, s, _)| (id, s)).collect();

        let mut delta = HashMap::new();
        for (task_id, new_score) in &new_map {
            let old_score = old_map.get(task_id).copied().unwrap_or(0.0);
            delta.insert(
                task_id.clone(),
                (old_score, *new_score, new_score - old_score),
            );
        }
        Ok(delta)
    }

    /// CI-blocking check: returns `Err` if pass rate < threshold.
    pub fn ci_check(&self, run_id: &str, threshold: f64) -> Result<(), String> {
        let results = self.results_for_run(run_id)?;
        if results.is_empty() {
            return Err("no eval results for run".to_string());
        }
        let passed = results.iter().filter(|(_, _, green)| *green).count();
        let rate = passed as f64 / results.len() as f64;
        if rate < threshold {
            Err(format!(
                "CI BLOCKED: pass rate {:.2}% < threshold {:.2}% ({} / {} tasks)",
                rate * 100.0,
                threshold * 100.0,
                passed,
                results.len()
            ))
        } else {
            Ok(())
        }
    }

    /// Get the latest run_id stored in the lake.
    pub fn latest_run_id(&self) -> Result<Option<String>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT run_id FROM eval_results ORDER BY id DESC LIMIT 1")
            .map_err(|e| e.to_string())?;
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            Ok(Some(row.get(0).map_err(|e| e.to_string())?))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn smoke_golden_task_fixtures_load() {
        let tasks = load_golden_tasks(repo_root().join("evals/golden-tasks")).unwrap();
        assert!(tasks.iter().any(|task| task.id == "cli-todo-app"));
    }

    #[test]
    fn eval_scorecard_is_deterministic() {
        let scorecard = Scorecard {
            task_id: "cli-todo-app".to_string(),
            build_passed: true,
            tests_passed: true,
            security_passed: true,
            docs_present: false,
        };
        assert_eq!(scorecard.deterministic_score(), 0.75);
        assert!(!scorecard.is_green());
    }

    #[test]
    fn parity_fixture_set_is_present() {
        let fixtures = parity_fixtures(repo_root().join("evals/parity-harness")).unwrap();
        assert!(fixtures
            .iter()
            .any(|path| path.ends_with("nim/streaming.json")));
    }

    #[test]
    fn judge_rubric_correctness_has_criteria() {
        let rubric = JudgeRubric::correctness();
        assert_eq!(rubric.name, "correctness");
        assert_eq!(rubric.max_score, 10);
        assert!(!rubric.criteria.is_empty());
    }

    #[test]
    fn judge_score_normalisation() {
        let score = JudgeScore {
            rubric: "correctness".to_string(),
            score: 7.0,
            max_score: 10,
            reasoning: "mostly correct".to_string(),
        };
        assert!((score.normalised() - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn composite_scorecard_with_empty_judge_scores() {
        let composite = CompositeScorecard {
            task_id: "test".to_string(),
            deterministic: Scorecard {
                task_id: "test".to_string(),
                build_passed: true,
                tests_passed: true,
                security_passed: true,
                docs_present: true,
            },
            judge_scores: vec![],
        };
        assert_eq!(composite.overall_score(), 1.0);
        assert!(composite.is_green());
    }

    #[test]
    fn composite_scorecard_with_judge_scores() {
        let composite = CompositeScorecard {
            task_id: "test".to_string(),
            deterministic: Scorecard {
                task_id: "test".to_string(),
                build_passed: true,
                tests_passed: true,
                security_passed: true,
                docs_present: true,
            },
            judge_scores: vec![
                JudgeScore {
                    rubric: "correctness".to_string(),
                    score: 8.0,
                    max_score: 10,
                    reasoning: "good".to_string(),
                },
                JudgeScore {
                    rubric: "security".to_string(),
                    score: 9.0,
                    max_score: 10,
                    reasoning: "clean".to_string(),
                },
            ],
        };
        // det=1.0, judge_avg=(0.8+0.9)/2=0.85, overall=1.0*0.6+0.85*0.4=0.94
        let expected = 1.0_f64 * 0.6 + 0.85_f64 * 0.4;
        assert!((composite.overall_score() - expected).abs() < 0.001);
    }

    #[test]
    fn golden_task_runner_stores_result() {
        let lake = EvalLake::open_in_memory().unwrap();
        let runner = GoldenTaskRunner::new(lake.clone(), vec![]);
        let task = GoldenTask {
            id: "test-task".to_string(),
            prompt: "do something".to_string(),
            acceptance: vec!["it works".to_string()],
            required_commands: vec![],
        };
        let scorecard = CompositeScorecard {
            task_id: "test-task".to_string(),
            deterministic: Scorecard {
                task_id: "test-task".to_string(),
                build_passed: true,
                tests_passed: true,
                security_passed: true,
                docs_present: true,
            },
            judge_scores: vec![],
        };
        runner.run_task(&task, "run-1", scorecard).unwrap();
        let results = lake.results_for_run("run-1").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "test-task");
        assert!(results[0].2); // is_green
    }
}
