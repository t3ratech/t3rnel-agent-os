//! Code-review target parsing and report schema.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Target accepted by the code-review surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ReviewTarget {
    /// Review a local diff file or diff-producing path.
    LocalDiff(PathBuf),
    /// Review a local branch or ref against the current checkout.
    LocalBranch(String),
    /// Review a GitHub pull request URL.
    GitHubPR(String),
    /// Review a local codebase directory.
    CodebasePath(PathBuf),
}

impl ReviewTarget {
    /// Parse a review target from CLI/user input.
    pub fn parse(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err("review target is empty".to_string());
        }

        if let Some(path) = trimmed.strip_prefix("diff:") {
            return non_empty_path(path, "diff").map(Self::LocalDiff);
        }
        if let Some(branch) = trimmed.strip_prefix("branch:") {
            let branch = branch.trim();
            if branch.is_empty() {
                return Err("branch review target is empty".to_string());
            }
            return Ok(Self::LocalBranch(branch.to_string()));
        }
        if let Some(url) = trimmed.strip_prefix("pr:") {
            return parse_pr_url(url);
        }
        if let Some(path) = trimmed.strip_prefix("codebase:") {
            return non_empty_path(path, "codebase").map(Self::CodebasePath);
        }

        if looks_like_github_pr(trimmed) {
            return Ok(Self::GitHubPR(trimmed.to_string()));
        }

        let path = PathBuf::from(trimmed);
        if path.is_dir() {
            return Ok(Self::CodebasePath(path));
        }
        if path.is_file() {
            return Ok(Self::LocalDiff(path));
        }

        Ok(Self::LocalBranch(trimmed.to_string()))
    }

    /// Stable human-readable display string.
    pub fn label(&self) -> String {
        match self {
            Self::LocalDiff(path) => format!("diff:{}", path.display()),
            Self::LocalBranch(branch) => format!("branch:{branch}"),
            Self::GitHubPR(url) => format!("pr:{url}"),
            Self::CodebasePath(path) => format!("codebase:{}", path.display()),
        }
    }
}

impl FromStr for ReviewTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn non_empty_path(value: &str, kind: &str) -> Result<PathBuf, String> {
    let value = value.trim();
    if value.is_empty() {
        Err(format!("{kind} review target is empty"))
    } else {
        Ok(PathBuf::from(value))
    }
}

fn parse_pr_url(url: &str) -> Result<ReviewTarget, String> {
    let url = url.trim();
    if looks_like_github_pr(url) {
        Ok(ReviewTarget::GitHubPR(url.to_string()))
    } else {
        Err(format!("not a GitHub pull request URL: {url}"))
    }
}

fn looks_like_github_pr(value: &str) -> bool {
    value.starts_with("https://github.com/") && value.contains("/pull/")
}

/// Finding severity ordered from informational to release-blocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewSeverity {
    Info,
    Low,
    Medium,
    High,
    Blocker,
}

/// Review finding category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewCategory {
    Correctness,
    Security,
    Style,
    Perf,
    Doc,
    Test,
}

/// Source location for a review finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewLocation {
    pub file: PathBuf,
    pub start_line: u32,
    pub end_line: u32,
}

impl ReviewLocation {
    pub fn new(file: impl Into<PathBuf>, start_line: u32, end_line: u32) -> Result<Self, String> {
        if start_line == 0 {
            return Err("review location start_line must be greater than zero".to_string());
        }
        if end_line < start_line {
            return Err(
                "review location end_line must be greater than or equal to start_line".to_string(),
            );
        }
        Ok(Self {
            file: file.into(),
            start_line,
            end_line,
        })
    }
}

/// Optional patch suggestion attached to a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSuggestion {
    pub tool: String,
    pub patch: String,
}

impl ReviewSuggestion {
    pub fn fs_propose_patch(patch: impl Into<String>) -> Self {
        Self {
            tool: "fs.propose_patch".to_string(),
            patch: patch.into(),
        }
    }
}

/// One structured review finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewFinding {
    pub severity: ReviewSeverity,
    pub category: ReviewCategory,
    pub message: String,
    pub location: ReviewLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<ReviewSuggestion>,
}

/// Structured code-review output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewReport {
    pub target: ReviewTarget,
    pub summary: String,
    pub findings: Vec<ReviewFinding>,
}

impl ReviewReport {
    pub fn new(target: ReviewTarget, summary: impl Into<String>) -> Self {
        Self {
            target,
            summary: summary.into(),
            findings: Vec::new(),
        }
    }

    pub fn with_finding(mut self, finding: ReviewFinding) -> Self {
        self.findings.push(finding);
        self
    }
}

/// Fast local preflight used by the CLI shortcut before daemon-backed review.
pub fn preflight_review(target: ReviewTarget, cwd: &Path) -> ReviewReport {
    match &target.clone() {
        ReviewTarget::LocalDiff(path) | ReviewTarget::CodebasePath(path) => {
            let resolved = if path.is_absolute() {
                path.clone()
            } else {
                cwd.join(path)
            };
            if resolved.exists() {
                ReviewReport::new(
                    target,
                    format!("Review target is accessible at {}.", resolved.display()),
                )
            } else {
                ReviewReport::new(
                    target,
                    format!("Review target is not accessible at {}.", resolved.display()),
                )
                .with_finding(ReviewFinding {
                    severity: ReviewSeverity::Blocker,
                    category: ReviewCategory::Correctness,
                    message: "Review target path does not exist.".to_string(),
                    location: ReviewLocation {
                        file: path.clone(),
                        start_line: 1,
                        end_line: 1,
                    },
                    suggestion: None,
                })
            }
        }
        ReviewTarget::LocalBranch(branch) => ReviewReport::new(
            target,
            format!("Review branch target parsed as '{branch}'."),
        ),
        ReviewTarget::GitHubPR(url) => ReviewReport::new(
            target,
            format!("Review pull request target parsed as {url}."),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parse_handles_explicit_forms() {
        assert_eq!(
            ReviewTarget::parse("diff:changes.patch").unwrap(),
            ReviewTarget::LocalDiff(PathBuf::from("changes.patch"))
        );
        assert_eq!(
            ReviewTarget::parse("branch:feature/review").unwrap(),
            ReviewTarget::LocalBranch("feature/review".to_string())
        );
        assert_eq!(
            ReviewTarget::parse("codebase:.").unwrap(),
            ReviewTarget::CodebasePath(PathBuf::from("."))
        );
        assert_eq!(
            ReviewTarget::parse("pr:https://github.com/t3ratech/t3rnel/pull/1").unwrap(),
            ReviewTarget::GitHubPR("https://github.com/t3ratech/t3rnel/pull/1".to_string())
        );
    }

    #[test]
    fn target_parse_rejects_invalid_pr_url() {
        let err = ReviewTarget::parse("pr:https://example.com/pull/1").unwrap_err();
        assert!(err.contains("not a GitHub pull request URL"));
    }

    #[test]
    fn report_schema_serializes_findings_and_suggestions() {
        let location = ReviewLocation::new("src/lib.rs", 7, 9).unwrap();
        let report = ReviewReport::new(
            ReviewTarget::LocalBranch("main".to_string()),
            "Found one issue.",
        )
        .with_finding(ReviewFinding {
            severity: ReviewSeverity::High,
            category: ReviewCategory::Correctness,
            message: "Incorrect branch condition.".to_string(),
            location,
            suggestion: Some(ReviewSuggestion::fs_propose_patch(
                "*** Begin Patch\n*** End Patch\n",
            )),
        });

        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["findings"][0]["severity"], "high");
        assert_eq!(value["findings"][0]["category"], "correctness");
        assert_eq!(
            value["findings"][0]["suggestion"]["tool"],
            "fs.propose_patch"
        );
    }

    #[test]
    fn preflight_reports_missing_local_path_as_blocker() {
        let target = ReviewTarget::LocalDiff(PathBuf::from("missing.patch"));
        let report = preflight_review(target, Path::new("/tmp/t3rnel-review-test-no-such-dir"));
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, ReviewSeverity::Blocker);
    }
}
