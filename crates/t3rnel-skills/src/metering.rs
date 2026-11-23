//! Per-skill metering and cost tracking.
//!
//! Tracks invocation counts, execution duration, and token usage
//! per skill so the kernel can enforce per-skill budgets.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Usage snapshot for a single skill.
#[derive(Debug, Clone, Default)]
pub struct SkillUsage {
    pub invocations: u64,
    pub total_duration_ms: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
}

/// Per-skill metering engine.
#[derive(Debug, Clone, Default)]
pub struct SkillMetering {
    inner: Arc<Mutex<HashMap<String, SkillUsage>>>,
}

impl SkillMetering {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a skill invocation.
    pub fn record_invocation(&self, skill_name: &str, duration_ms: u64) {
        let mut map = self.inner.lock().unwrap();
        let entry = map.entry(skill_name.to_string()).or_default();
        entry.invocations += 1;
        entry.total_duration_ms += duration_ms;
    }

    /// Record token usage for a skill.
    pub fn record_tokens(&self, skill_name: &str, input: u64, output: u64) {
        let mut map = self.inner.lock().unwrap();
        let entry = map.entry(skill_name.to_string()).or_default();
        entry.total_input_tokens += input;
        entry.total_output_tokens += output;
    }

    /// Get usage for a specific skill.
    pub fn usage(&self, skill_name: &str) -> SkillUsage {
        let map = self.inner.lock().unwrap();
        map.get(skill_name).cloned().unwrap_or_default()
    }

    /// Get all skill usage snapshots.
    pub fn all_usage(&self) -> HashMap<String, SkillUsage> {
        let map = self.inner.lock().unwrap();
        map.clone()
    }

    /// Reset usage for a specific skill.
    pub fn reset(&self, skill_name: &str) {
        let mut map = self.inner.lock().unwrap();
        map.remove(skill_name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_metering_tracks_invocations() {
        let meter = SkillMetering::new();
        meter.record_invocation("test-skill", 100);
        meter.record_invocation("test-skill", 200);
        let usage = meter.usage("test-skill");
        assert_eq!(usage.invocations, 2);
        assert_eq!(usage.total_duration_ms, 300);
    }

    #[test]
    fn skill_metering_tracks_tokens() {
        let meter = SkillMetering::new();
        meter.record_tokens("test-skill", 1000, 500);
        let usage = meter.usage("test-skill");
        assert_eq!(usage.total_input_tokens, 1000);
        assert_eq!(usage.total_output_tokens, 500);
    }

    #[test]
    fn skill_metering_reset_clears() {
        let meter = SkillMetering::new();
        meter.record_invocation("test-skill", 100);
        meter.reset("test-skill");
        let usage = meter.usage("test-skill");
        assert_eq!(usage.invocations, 0);
    }
}
