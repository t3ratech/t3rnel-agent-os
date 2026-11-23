//! Golden-task runner CLI for CI-blocking eval harness.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let root = std::env::var("EVAL_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("evals/golden-tasks")
        });

    let tasks = t3rnel_eval::load_golden_tasks(&root).unwrap_or_else(|e| {
        eprintln!("Failed to load golden tasks from {}: {e}", root.display());
        std::process::exit(1);
    });

    if tasks.is_empty() {
        eprintln!("No golden tasks found in {}", root.display());
        std::process::exit(1);
    }

    let mut all_green = true;
    let mut scorecards = Vec::new();
    let cwd = eval_cwd();

    for task in &tasks {
        println!("\n=== Running golden task: {} ===", task.id);
        let mut scorecard = t3rnel_eval::Scorecard {
            task_id: task.id.clone(),
            build_passed: false,
            tests_passed: false,
            security_passed: false,
            docs_present: false,
        };

        for cmd_str in &task.required_commands {
            println!("  > {cmd_str}");
            if cmd_str.trim().is_empty() {
                continue;
            }
            let status = run_required_command(cmd_str, &cwd);

            match status {
                Ok(st) if st.success() => {
                    println!("    ✓ passed");
                    mark_successful_command(&mut scorecard, cmd_str);
                }
                Ok(st) => {
                    println!("    ✗ failed (exit code: {:?})", st.code());
                    all_green = false;
                }
                Err(e) => {
                    println!("    ✗ spawn error: {e}");
                    all_green = false;
                }
            }
        }

        derive_acceptance_checks(task, &cwd, &mut scorecard);

        let score = scorecard.deterministic_score();
        let green = scorecard.is_green();
        println!(
            "  Score: {:.0}% | Green: {}",
            score * 100.0,
            if green { "YES" } else { "NO" }
        );
        if !green {
            all_green = false;
        }
        scorecards.push(scorecard);
    }

    println!("\n=== Eval Summary ===");
    for sc in &scorecards {
        println!(
            "  {}: {:.0}% {}",
            sc.task_id,
            sc.deterministic_score() * 100.0,
            if sc.is_green() { "✓" } else { "✗" }
        );
    }

    if all_green {
        println!("\nAll golden tasks passed.");
        std::process::exit(0);
    } else {
        println!("\nSome golden tasks failed.");
        std::process::exit(1);
    }
}

fn eval_cwd() -> PathBuf {
    std::env::var("EVAL_CWD")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn run_required_command(cmd_str: &str, cwd: &Path) -> std::io::Result<std::process::ExitStatus> {
    Command::new("bash")
        .args(["-lc", cmd_str])
        .current_dir(cwd)
        .status()
}

fn mark_successful_command(scorecard: &mut t3rnel_eval::Scorecard, cmd_str: &str) {
    let lower = cmd_str.to_lowercase();
    if lower.contains("--build") || lower.contains(" build") || lower.starts_with("build") {
        scorecard.build_passed = true;
    }
    if lower.contains("--test")
        || lower.contains(" test")
        || lower.starts_with("test")
        || lower.contains("cargo test")
    {
        scorecard.tests_passed = true;
    }
    if lower.contains("security") || lower.contains("audit") || lower.contains("snyk") {
        scorecard.security_passed = true;
    }
    if lower.contains("doc") || lower.contains("readme") {
        scorecard.docs_present = true;
    }
}

fn derive_acceptance_checks(
    task: &t3rnel_eval::GoldenTask,
    cwd: &Path,
    scorecard: &mut t3rnel_eval::Scorecard,
) {
    if !scorecard.security_passed && !acceptance_mentions(&task.acceptance, &["security", "audit"])
    {
        scorecard.security_passed = true;
    }

    if !scorecard.docs_present {
        let docs_required = acceptance_mentions(&task.acceptance, &["readme", "doc"]);
        scorecard.docs_present = !docs_required || docs_artifact_exists(cwd);
    }
}

fn acceptance_mentions(acceptance: &[String], needles: &[&str]) -> bool {
    acceptance.iter().any(|criterion| {
        let lower = criterion.to_lowercase();
        needles.iter().any(|needle| lower.contains(needle))
    })
}

fn docs_artifact_exists(cwd: &Path) -> bool {
    [
        cwd.join("README.md"),
        cwd.join("README"),
        cwd.join("docs"),
        cwd.join("docs/README.md"),
    ]
    .iter()
    .any(|path| path.exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task_with_acceptance(acceptance: &[&str]) -> t3rnel_eval::GoldenTask {
        t3rnel_eval::GoldenTask {
            id: "fixture".to_string(),
            prompt: "do the thing".to_string(),
            acceptance: acceptance.iter().map(|item| item.to_string()).collect(),
            required_commands: Vec::new(),
        }
    }

    #[test]
    fn successful_commands_map_to_scorecard_dimensions() {
        let mut scorecard = t3rnel_eval::Scorecard {
            task_id: "fixture".to_string(),
            build_passed: false,
            tests_passed: false,
            security_passed: false,
            docs_present: false,
        };

        mark_successful_command(&mut scorecard, "cargo build --workspace --lib");
        mark_successful_command(&mut scorecard, "cargo test --workspace");
        mark_successful_command(&mut scorecard, "./t3rnel-services.sh --test security");
        mark_successful_command(&mut scorecard, "test -f README.md");

        assert!(scorecard.build_passed);
        assert!(scorecard.tests_passed);
        assert!(scorecard.security_passed);
        assert!(scorecard.docs_present);
    }

    #[test]
    fn acceptance_checks_treat_unrequested_security_as_not_applicable() {
        let task = task_with_acceptance(&["The project builds.", "README documents usage."]);
        let mut scorecard = t3rnel_eval::Scorecard {
            task_id: "fixture".to_string(),
            build_passed: true,
            tests_passed: true,
            security_passed: false,
            docs_present: false,
        };
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

        derive_acceptance_checks(&task, &repo_root, &mut scorecard);

        assert!(scorecard.security_passed);
        assert!(scorecard.docs_present);
    }

    #[test]
    fn acceptance_checks_require_explicit_security_signal_when_requested() {
        let task = task_with_acceptance(&["Security audit passes."]);
        let mut scorecard = t3rnel_eval::Scorecard {
            task_id: "fixture".to_string(),
            build_passed: true,
            tests_passed: true,
            security_passed: false,
            docs_present: false,
        };

        derive_acceptance_checks(&task, Path::new(env!("CARGO_MANIFEST_DIR")), &mut scorecard);

        assert!(!scorecard.security_passed);
        assert!(scorecard.docs_present);
    }
}
