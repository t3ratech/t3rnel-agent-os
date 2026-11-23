// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) T3raTech Solutions (Pvt) Ltd. All rights reserved.

//! Error and security monitoring.
//!
//! An agent operating system fails quietly. Agents run unattended, so a failing
//! credential, a runaway spend, or a tool being called far outside its normal
//! pattern produces no visible symptom until revenue stops or a bill arrives.
//! The sentinel watches the event stream for those shapes and raises them while
//! they are still cheap.
//!
//! It reports rather than acts. Automatic remediation on a false positive is
//! more damaging than the condition it responds to — disabling a working
//! integration mid-drop, or halting an agent partway through a paid job. The one
//! exception is the spend ceiling, which is a hard stop by design: money spent
//! cannot be recovered by noticing afterwards.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// How bad a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Worth knowing; no action required.
    Info,
    /// Something is degrading and will fail if ignored.
    Warning,
    /// Acting now prevents loss.
    Critical,
}

/// What kind of condition was seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Finding {
    /// Repeated failures from one component.
    ErrorBurst,
    /// Repeated authentication failures — a credential is dead or being guessed.
    AuthFailures,
    /// A tool invoked far more often than its established pattern.
    ToolAnomaly,
    /// Spend crossed its ceiling.
    BudgetBreach,
    /// A capability was exercised that this actor has never used before.
    NewCapability,
    /// An outbound request aimed at a non-public address.
    BlockedEgress,
}

impl Finding {
    /// Findings that mean "credentials or access are being probed", as opposed
    /// to ordinary breakage.
    pub fn is_security(self) -> bool {
        matches!(
            self,
            Finding::AuthFailures | Finding::NewCapability | Finding::BlockedEgress
        )
    }
}

/// A raised condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub finding: Finding,
    pub severity: Severity,
    /// Which component or agent this concerns.
    pub subject: String,
    /// What was seen, in terms an operator can act on.
    pub detail: String,
    pub observed_at: SystemTime,
}

/// One observed event.
#[derive(Debug, Clone)]
pub struct Event {
    pub subject: String,
    pub kind: EventKind,
    pub at: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Success,
    Failure,
    AuthFailure,
    ToolCall,
    /// An outbound request refused for pointing at a non-public address.
    EgressBlocked,
}

/// Thresholds governing what counts as abnormal.
///
/// Every value is explicit. A monitor with invented defaults either cries wolf
/// until it is ignored, or stays silent through the incident it exists to catch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    /// Window over which occurrences are counted.
    pub window: Duration,
    /// Failures from one subject within the window before raising.
    pub error_burst_threshold: usize,
    /// Auth failures within the window before raising.
    pub auth_failure_threshold: usize,
    /// Multiple of a subject's established rate that counts as anomalous.
    pub tool_anomaly_factor: f64,
    /// Minimum calls before a rate is considered established.
    ///
    /// Without it, a subject's first two calls look like a doubling and every
    /// new agent alerts on its own startup.
    pub tool_anomaly_min_baseline: usize,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(300),
            error_burst_threshold: 5,
            auth_failure_threshold: 3,
            tool_anomaly_factor: 4.0,
            tool_anomaly_min_baseline: 20,
        }
    }
}

/// Rolling counts for one subject.
#[derive(Debug, Default, Clone)]
struct SubjectState {
    events: Vec<(SystemTime, EventKind)>,
    /// Calls seen before the current window — the established pattern.
    baseline_tool_calls: usize,
    seen_capabilities: Vec<String>,
}

/// Watches events and raises findings.
pub struct Sentinel {
    config: SentinelConfig,
    subjects: HashMap<String, SubjectState>,
}

impl Sentinel {
    pub fn new(config: SentinelConfig) -> Self {
        Self {
            config,
            subjects: HashMap::new(),
        }
    }

    /// Record an event and return anything it makes true.
    ///
    /// Alerts are returned rather than dispatched, so the caller decides where
    /// they go and the monitor stays testable without a delivery channel.
    pub fn observe(&mut self, event: Event) -> Vec<Alert> {
        let window = self.config.window;
        let state = self.subjects.entry(event.subject.clone()).or_default();

        // Drop events that have aged out before counting, so a subject failing
        // steadily for hours does not accumulate into a permanent alert.
        let cutoff = event.at.checked_sub(window).unwrap_or(event.at);
        state.events.retain(|(at, _)| *at >= cutoff);
        state.events.push((event.at, event.kind));

        let count = |kind: EventKind| state.events.iter().filter(|(_, k)| *k == kind).count();

        let mut alerts = Vec::new();

        // Each finding is evaluated only when an event of its own kind arrives.
        // Checking every count on every event re-fires a threshold that is
        // already met, so one burst alerts once per unrelated event that
        // follows it — which is exactly the noise that gets alerting ignored.
        let failures = count(EventKind::Failure);
        if event.kind == EventKind::Failure && failures == self.config.error_burst_threshold {
            alerts.push(Alert {
                finding: Finding::ErrorBurst,
                severity: Severity::Warning,
                subject: event.subject.clone(),
                detail: format!("{failures} failures within {}s", window.as_secs()),
                observed_at: event.at,
            });
        }

        let auth_failures = count(EventKind::AuthFailure);
        if event.kind == EventKind::AuthFailure
            && auth_failures == self.config.auth_failure_threshold
        {
            alerts.push(Alert {
                finding: Finding::AuthFailures,
                severity: Severity::Critical,
                subject: event.subject.clone(),
                detail: format!(
                    "{auth_failures} authentication failures within {}s; \
                     the credential is dead or is being guessed",
                    window.as_secs()
                ),
                observed_at: event.at,
            });
        }

        if event.kind == EventKind::EgressBlocked {
            alerts.push(Alert {
                finding: Finding::BlockedEgress,
                severity: Severity::Critical,
                subject: event.subject.clone(),
                detail: "an outbound request targeted a non-public address".to_string(),
                observed_at: event.at,
            });
        }

        let tool_calls = count(EventKind::ToolCall);
        if event.kind == EventKind::ToolCall
            && state.baseline_tool_calls >= self.config.tool_anomaly_min_baseline
        {
            let expected = state.baseline_tool_calls as f64;
            if tool_calls as f64 >= expected * self.config.tool_anomaly_factor {
                alerts.push(Alert {
                    finding: Finding::ToolAnomaly,
                    severity: Severity::Warning,
                    subject: event.subject.clone(),
                    detail: format!(
                        "{tool_calls} tool calls against an established rate of {}",
                        state.baseline_tool_calls
                    ),
                    observed_at: event.at,
                });
            }
        }

        alerts
    }

    /// Note that a subject used a capability, raising it the first time.
    ///
    /// A capability an actor has never exercised is the clearest signal that its
    /// behaviour changed — whether by a prompt injection, a bad config, or a
    /// compromised credential.
    pub fn observe_capability(&mut self, subject: &str, capability: &str) -> Option<Alert> {
        let state = self.subjects.entry(subject.to_string()).or_default();
        if state
            .seen_capabilities
            .iter()
            .any(|seen| seen == capability)
        {
            return None;
        }
        state.seen_capabilities.push(capability.to_string());
        Some(Alert {
            finding: Finding::NewCapability,
            severity: Severity::Warning,
            subject: subject.to_string(),
            detail: format!("first use of capability {capability:?}"),
            observed_at: SystemTime::now(),
        })
    }

    /// Raise when spend crosses its ceiling.
    ///
    /// Critical without qualification: unlike the other findings this one cannot
    /// be undone by noticing it later.
    pub fn check_budget(&self, subject: &str, spent: f64, ceiling: f64) -> Option<Alert> {
        if ceiling <= 0.0 || spent < ceiling {
            return None;
        }
        Some(Alert {
            finding: Finding::BudgetBreach,
            severity: Severity::Critical,
            subject: subject.to_string(),
            detail: format!("spend {spent:.2} reached the ceiling of {ceiling:.2}"),
            observed_at: SystemTime::now(),
        })
    }

    /// Fold the current window into a subject's established rate.
    ///
    /// Called at window boundaries so ordinary growth becomes the new normal and
    /// only genuine departures keep alerting.
    pub fn settle_baseline(&mut self, subject: &str) {
        if let Some(state) = self.subjects.get_mut(subject) {
            let calls = state
                .events
                .iter()
                .filter(|(_, kind)| *kind == EventKind::ToolCall)
                .count();
            state.baseline_tool_calls = calls;
        }
    }

    /// Subjects currently being tracked.
    pub fn subject_count(&self) -> usize {
        self.subjects.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(subject: &str, kind: EventKind, offset_secs: u64) -> Event {
        Event {
            subject: subject.to_string(),
            kind,
            at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000 + offset_secs),
        }
    }

    fn sentinel() -> Sentinel {
        Sentinel::new(SentinelConfig::default())
    }

    #[test]
    fn a_burst_of_failures_raises_once_at_the_threshold() {
        let mut s = sentinel();
        let mut alerts = Vec::new();
        for i in 0..5 {
            alerts.extend(s.observe(event("publisher", EventKind::Failure, i)));
        }
        assert_eq!(alerts.len(), 1, "one alert, not one per failure");
        assert_eq!(alerts[0].finding, Finding::ErrorBurst);
    }

    #[test]
    fn a_met_threshold_does_not_refire_on_unrelated_events() {
        // One burst must alert once. Re-checking every count on every event
        // makes a single burst alert again for each later event of any kind,
        // which is the noise that trains an operator to ignore the report.
        let mut s = sentinel();
        for i in 0..5 {
            s.observe(event("publisher", EventKind::Failure, i));
        }
        let later = s.observe(event("publisher", EventKind::Success, 6));
        assert!(
            later.is_empty(),
            "an unrelated event must not refire the burst"
        );
        let auth = s.observe(event("publisher", EventKind::AuthFailure, 7));
        assert!(
            !auth.iter().any(|a| a.finding == Finding::ErrorBurst),
            "an auth failure must not refire the error burst"
        );
    }

    #[test]
    fn failures_below_the_threshold_stay_quiet() {
        let mut s = sentinel();
        for i in 0..4 {
            assert!(s
                .observe(event("publisher", EventKind::Failure, i))
                .is_empty());
        }
    }

    #[test]
    fn failures_that_age_out_do_not_accumulate() {
        // A component failing slowly for hours is not a burst; treating it as
        // one produces a permanent alert that gets ignored.
        let mut s = sentinel();
        for i in 0..4 {
            s.observe(event("publisher", EventKind::Failure, i));
        }
        let alerts = s.observe(event("publisher", EventKind::Failure, 10_000));
        assert!(alerts.is_empty(), "stale failures must not count");
    }

    #[test]
    fn auth_failures_are_critical() {
        let mut s = sentinel();
        let mut alerts = Vec::new();
        for i in 0..3 {
            alerts.extend(s.observe(event("x-provider", EventKind::AuthFailure, i)));
        }
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Critical);
        assert!(alerts[0].finding.is_security());
    }

    #[test]
    fn blocked_egress_raises_immediately() {
        // One attempt to reach a private address is already the whole signal.
        let mut s = sentinel();
        let alerts = s.observe(event("media-fetch", EventKind::EgressBlocked, 0));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].finding, Finding::BlockedEgress);
        assert_eq!(alerts[0].severity, Severity::Critical);
    }

    #[test]
    fn subjects_are_tracked_independently() {
        let mut s = sentinel();
        for i in 0..4 {
            s.observe(event("agent-a", EventKind::Failure, i));
        }
        assert!(
            s.observe(event("agent-b", EventKind::Failure, 5))
                .is_empty(),
            "one subject's failures must not raise for another"
        );
    }

    #[test]
    fn a_new_capability_raises_once() {
        let mut s = sentinel();
        assert!(s.observe_capability("agent-a", "shell.exec").is_some());
        assert!(
            s.observe_capability("agent-a", "shell.exec").is_none(),
            "an established capability is not news"
        );
    }

    #[test]
    fn capability_alerts_are_per_subject() {
        let mut s = sentinel();
        s.observe_capability("agent-a", "wallet.sign");
        assert!(
            s.observe_capability("agent-b", "wallet.sign").is_some(),
            "a second agent using it is a separate first use"
        );
    }

    #[test]
    fn tool_anomalies_need_an_established_baseline() {
        // Without a baseline every new agent alerts on its own startup.
        let mut s = sentinel();
        let mut alerts = Vec::new();
        for i in 0..50 {
            alerts.extend(s.observe(event("fresh-agent", EventKind::ToolCall, i)));
        }
        assert!(
            alerts.is_empty(),
            "a subject with no history cannot be anomalous"
        );
    }

    #[test]
    fn a_rate_far_above_the_baseline_raises() {
        let mut s = sentinel();
        for i in 0..20 {
            s.observe(event("agent-a", EventKind::ToolCall, i));
        }
        s.settle_baseline("agent-a");

        let mut alerts = Vec::new();
        for i in 0..80 {
            alerts.extend(s.observe(event("agent-a", EventKind::ToolCall, 100 + i)));
        }
        assert!(
            alerts.iter().any(|a| a.finding == Finding::ToolAnomaly),
            "a fourfold jump must raise"
        );
    }

    #[test]
    fn spend_below_the_ceiling_is_quiet() {
        assert!(sentinel().check_budget("agent-a", 9.99, 10.0).is_none());
    }

    #[test]
    fn spend_at_the_ceiling_is_critical() {
        let alert = sentinel()
            .check_budget("agent-a", 10.0, 10.0)
            .expect("reaching the ceiling raises");
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.finding, Finding::BudgetBreach);
    }

    #[test]
    fn an_unset_ceiling_never_raises() {
        // A zero ceiling means unconfigured, not "everything breaches".
        assert!(sentinel().check_budget("agent-a", 500.0, 0.0).is_none());
    }

    #[test]
    fn security_findings_are_distinguished_from_breakage() {
        assert!(Finding::AuthFailures.is_security());
        assert!(Finding::BlockedEgress.is_security());
        assert!(!Finding::ErrorBurst.is_security());
        assert!(!Finding::BudgetBreach.is_security());
    }

    #[test]
    fn success_events_never_raise() {
        let mut s = sentinel();
        for i in 0..100 {
            assert!(s
                .observe(event("agent-a", EventKind::Success, i))
                .is_empty());
        }
    }
}
