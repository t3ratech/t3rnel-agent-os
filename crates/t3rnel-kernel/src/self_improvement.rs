//! Self-improvement loop — T3rnel's dog-food engine.
//!
//! When `SELF_IMPROVEMENT_HALT` is false, the kernel periodically evaluates
//! pending `IdeaProposal`s, routes approved ones through the team pipeline,
//! and enforces budget / scope / branch guardrails.

use crate::metering::MeteringEngine;
use crate::scope_fence;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use t3rnel_types::config::BudgetConfig;
use tracing::{info, warn};

/// Global halt flag — set to `true` to immediately stop the self-improvement loop.
///
/// This is checked at the top of every iteration. Setting it does NOT affect
/// tasks already in-flight; it only prevents new ones from being created.
pub static SELF_IMPROVEMENT_HALT: AtomicBool = AtomicBool::new(true);

/// Status of the self-improvement engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfImprovementStatus {
    /// Running and evaluating proposals.
    Running,
    /// Halted by the kill-switch.
    Halted,
    /// Paused because the daily budget cap was reached.
    BudgetExceeded,
}

/// A single self-improvement idea / proposal.
#[derive(Debug, Clone)]
pub struct IdeaProposal {
    pub id: String,
    pub title: String,
    pub description: String,
    pub affected_paths: Vec<String>,
    pub estimated_cost_usd: f64,
    pub source: IdeaSource,
}

/// Where an idea came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdeaSource {
    GitHubTrending,
    HackerNews,
    ArXiv,
    Telemetry,
    KnowledgeGraph,
    Speculative,
}

/// Decision produced by the architect-mode evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdrDecision {
    Approve,
    Reject,
    NeedsHuman,
}

/// The self-improvement engine.
pub struct SelfImprovementEngine {
    metering: Arc<MeteringEngine>,
    budget: BudgetConfig,
}

impl SelfImprovementEngine {
    pub fn new(metering: Arc<MeteringEngine>, budget: BudgetConfig) -> Self {
        Self { metering, budget }
    }

    /// Check whether the loop is permitted to run this iteration.
    pub fn status(&self) -> SelfImprovementStatus {
        if SELF_IMPROVEMENT_HALT.load(Ordering::SeqCst) {
            return SelfImprovementStatus::Halted;
        }
        match self.metering.check_global_budget(&self.budget) {
            Ok(()) => SelfImprovementStatus::Running,
            Err(_) => SelfImprovementStatus::BudgetExceeded,
        }
    }

    /// Evaluate a proposal against scope fence and budget.
    ///
    /// Returns `Ok(decision)` if the proposal is within scope and budget,
    /// or `Err(reason)` if it breaches the fence or exceeds the cap.
    pub fn evaluate(&self, proposal: &IdeaProposal) -> Result<AdrDecision, String> {
        // Scope fence check
        let paths: Vec<&Path> = proposal.affected_paths.iter().map(Path::new).collect();
        if let Err(breached) = scope_fence::check_proposal(&paths) {
            warn!(
                idea_id = %proposal.id,
                breached = ?breached,
                "Scope fence breach — human approval required"
            );
            return Ok(AdrDecision::NeedsHuman);
        }

        // Budget sanity check
        if proposal.estimated_cost_usd > 0.0 {
            let status = self.budget_status();
            if status.daily_limit > 0.0
                && status.daily_spend + proposal.estimated_cost_usd > status.daily_limit
            {
                warn!(
                    idea_id = %proposal.id,
                    estimated = proposal.estimated_cost_usd,
                    daily_spend = status.daily_spend,
                    daily_limit = status.daily_limit,
                    "Proposal would exceed daily budget"
                );
                return Err("Daily budget cap would be exceeded".to_string());
            }
        }

        Ok(AdrDecision::Approve)
    }

    /// Generate a canonical git branch name for this proposal.
    pub fn branch_name(&self, proposal: &IdeaProposal) -> String {
        let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
        let slug: String = proposal
            .title
            .to_lowercase()
            .replace(|c: char| !c.is_alphanumeric() && c != '-', "-")
            .replace("--", "-")
            .trim_matches('-')
            .to_string();
        format!("self-improvement/{ts}-{slug}")
    }

    fn budget_status(&self) -> crate::metering::BudgetStatus {
        self.metering.budget_status(&self.budget)
    }
}

/// Convenience: halt the self-improvement loop immediately.
pub fn halt() {
    SELF_IMPROVEMENT_HALT.store(true, Ordering::SeqCst);
    info!("Self-improvement loop halted");
}

/// Convenience: resume the self-improvement loop (if budget allows).
pub fn resume() {
    SELF_IMPROVEMENT_HALT.store(false, Ordering::SeqCst);
    info!("Self-improvement loop resumed");
}

/// Query whether the loop is currently halted.
pub fn is_halted() -> bool {
    SELF_IMPROVEMENT_HALT.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_halt_is_true() {
        assert!(is_halted());
    }

    #[test]
    fn resume_and_halt() {
        resume();
        assert!(!is_halted());
        halt();
        assert!(is_halted());
        // Reset to default
        SELF_IMPROVEMENT_HALT.store(true, Ordering::SeqCst);
    }

    #[test]
    fn branch_name_format() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        t3rnel_memory::migration::run_migrations(&conn).unwrap();
        let store = Arc::new(t3rnel_memory::usage::UsageStore::new(Arc::new(
            std::sync::Mutex::new(conn),
        )));
        let engine = SelfImprovementEngine::new(
            Arc::new(MeteringEngine::new(store)),
            BudgetConfig::default(),
        );
        let proposal = IdeaProposal {
            id: "test-1".to_string(),
            title: "Fix bug in auth".to_string(),
            description: "desc".to_string(),
            affected_paths: vec!["src/auth.rs".to_string()],
            estimated_cost_usd: 0.01,
            source: IdeaSource::Telemetry,
        };
        let branch = engine.branch_name(&proposal);
        assert!(branch.starts_with("self-improvement/"));
        assert!(branch.contains("fix-bug-in-auth"));
    }
}
