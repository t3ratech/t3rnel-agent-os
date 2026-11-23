//! Generic retry backoff schedules.
//!
//! Schedules are comma-separated steps. Duration steps retry after that delay;
//! a `0` step is terminal and means "stop retrying and return failure".
//! If the last step is a duration, that delay is reused forever.

use std::time::Duration;

/// Legacy environment variable name for model/provider rate-limit backoff.
pub const RATE_LIMIT_BACKOFF_ENV: &str = "T3RNEL_RATE_LIMIT_BACKOFF";
/// Generic model/provider rate-limit schedule.
pub const RETRY_BACKOFF_RATE_LIMIT_ENV: &str = "T3RNEL_RETRY_BACKOFF_RATE_LIMIT";
/// LLM provider/model cooldown schedule.
pub const RETRY_BACKOFF_MODEL_ENV: &str = "T3RNEL_RETRY_BACKOFF_MODEL";
/// Email polling and sending schedule.
pub const RETRY_BACKOFF_EMAIL_ENV: &str = "T3RNEL_RETRY_BACKOFF_EMAIL";
/// HTTP client request schedule.
pub const RETRY_BACKOFF_HTTP_ENV: &str = "T3RNEL_RETRY_BACKOFF_HTTP";
/// Human-facing website/browser automation schedule.
pub const RETRY_BACKOFF_WEBSITE_ENV: &str = "T3RNEL_RETRY_BACKOFF_WEBSITE";
/// Local/network connectivity schedule.
pub const RETRY_BACKOFF_CONNECTIVITY_ENV: &str = "T3RNEL_RETRY_BACKOFF_CONNECTIVITY";

const DEFAULT_RATE_LIMIT_BACKOFF: &str = "1h,3h,8h,24h,48h";
const DEFAULT_MODEL_BACKOFF: &str = "1h,3h,8h,24h";
const DEFAULT_EMAIL_BACKOFF: &str = "1h,3h,8h,24h,48h";
const DEFAULT_HTTP_BACKOFF: &str = "5s,1m,3m,15m,0";
const DEFAULT_WEBSITE_BACKOFF: &str = "1h,0";
const DEFAULT_CONNECTIVITY_BACKOFF: &str = "1m,2m,5m,30m,3h,8h,24h";

/// Named retry profiles used by subsystem call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffProfile {
    RateLimit,
    Model,
    Email,
    Http,
    Website,
    Connectivity,
}

/// One configured backoff step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffStep {
    RetryAfter(Duration),
    Stop,
}

/// Runtime decision for an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffDecision {
    RetryAfter(Duration),
    Stop,
}

impl BackoffDecision {
    /// Return the retry delay, or `None` when the schedule is terminal.
    pub fn retry_after(self) -> Option<Duration> {
        match self {
            Self::RetryAfter(delay) => Some(delay),
            Self::Stop => None,
        }
    }

    /// Whether this decision is terminal.
    pub fn is_stop(self) -> bool {
        matches!(self, Self::Stop)
    }
}

/// A pluggable backoff schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackoffSchedule {
    steps: Vec<BackoffStep>,
}

impl Default for BackoffSchedule {
    fn default() -> Self {
        Self::parse(DEFAULT_RATE_LIMIT_BACKOFF).expect("default backoff schedule must parse")
    }
}

impl BackoffSchedule {
    /// Create a schedule from a list of delays.
    pub fn from_delays(delays: &[Duration]) -> Self {
        Self {
            steps: delays
                .iter()
                .copied()
                .map(BackoffStep::RetryAfter)
                .collect(),
        }
    }

    /// Parse a schedule string such as `1h,3h,8h,24h,48h` or
    /// `5s,1m,3m,15m,0`.
    ///
    /// Supported units: `d` (days), `h` (hours), `m` (minutes), `s` (seconds).
    /// Whitespace is trimmed. Empty entries are ignored. A zero duration is a
    /// terminal stop step. If the parsed list is empty, the default schedule is
    /// returned.
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut steps = Vec::new();
        for token in s.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if token == "0" {
                steps.push(BackoffStep::Stop);
                continue;
            }
            let delay = parse_duration(token)?;
            if delay.is_zero() {
                steps.push(BackoffStep::Stop);
            } else {
                steps.push(BackoffStep::RetryAfter(delay));
            }
        }
        if steps.is_empty() {
            return Ok(Self::default());
        }
        Ok(Self { steps })
    }

    /// Load the legacy generic rate-limit schedule from the environment.
    pub fn from_env() -> Self {
        Self::for_profile(BackoffProfile::RateLimit)
    }

    /// Load a named profile from the environment.
    pub fn for_profile(profile: BackoffProfile) -> Self {
        let (primary, aliases, default_value) = profile_env(profile);
        Self::from_env_names(primary, aliases, default_value)
    }

    /// Load a schedule from explicit env names with a default literal.
    pub fn from_env_names(primary: &str, aliases: &[&str], default_value: &str) -> Self {
        for env_name in std::iter::once(primary).chain(aliases.iter().copied()) {
            if let Ok(raw) = std::env::var(env_name) {
                if raw.trim().is_empty() {
                    continue;
                }
                match Self::parse(&raw) {
                    Ok(schedule) => return schedule,
                    Err(_err) => {}
                }
            }
        }
        Self::parse(default_value).expect("default backoff schedule must parse")
    }

    /// Return the retry/stop decision for the given attempt (0-indexed).
    pub fn decision_for_attempt(&self, attempt: u32) -> BackoffDecision {
        if self.steps.is_empty() {
            return BackoffDecision::Stop;
        }
        let idx = (attempt as usize).min(self.steps.len().saturating_sub(1));
        match self.steps[idx] {
            BackoffStep::RetryAfter(delay) => BackoffDecision::RetryAfter(delay),
            BackoffStep::Stop => BackoffDecision::Stop,
        }
    }

    /// Return the delay for the given attempt, or zero when the schedule stops.
    ///
    /// Prefer `decision_for_attempt` in new retry loops so terminal schedules
    /// are handled explicitly.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        self.decision_for_attempt(attempt)
            .retry_after()
            .unwrap_or(Duration::ZERO)
    }

    /// All configured steps.
    pub fn steps(&self) -> &[BackoffStep] {
        &self.steps
    }

    /// Whether the schedule ever reaches a terminal stop.
    pub fn has_terminal_stop(&self) -> bool {
        self.steps
            .iter()
            .any(|step| matches!(step, BackoffStep::Stop))
    }
}

fn profile_env(profile: BackoffProfile) -> (&'static str, &'static [&'static str], &'static str) {
    match profile {
        BackoffProfile::RateLimit => (
            RETRY_BACKOFF_RATE_LIMIT_ENV,
            &[RATE_LIMIT_BACKOFF_ENV],
            DEFAULT_RATE_LIMIT_BACKOFF,
        ),
        BackoffProfile::Model => (
            RETRY_BACKOFF_MODEL_ENV,
            &[RATE_LIMIT_BACKOFF_ENV],
            DEFAULT_MODEL_BACKOFF,
        ),
        BackoffProfile::Email => (
            RETRY_BACKOFF_EMAIL_ENV,
            &[RATE_LIMIT_BACKOFF_ENV],
            DEFAULT_EMAIL_BACKOFF,
        ),
        BackoffProfile::Http => (RETRY_BACKOFF_HTTP_ENV, &[], DEFAULT_HTTP_BACKOFF),
        BackoffProfile::Website => (RETRY_BACKOFF_WEBSITE_ENV, &[], DEFAULT_WEBSITE_BACKOFF),
        BackoffProfile::Connectivity => (
            RETRY_BACKOFF_CONNECTIVITY_ENV,
            &[],
            DEFAULT_CONNECTIVITY_BACKOFF,
        ),
    }
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit() && c != '.')
            .ok_or_else(|| format!("duration '{s}' has no unit"))?,
    );
    let num: f64 = num
        .parse()
        .map_err(|_| format!("duration '{s}' has invalid number"))?;
    let secs = match unit.trim().to_lowercase().as_str() {
        "d" | "day" | "days" => num * 86400.0,
        "h" | "hr" | "hrs" | "hour" | "hours" => num * 3600.0,
        "m" | "min" | "mins" | "minute" | "minutes" => num * 60.0,
        "s" | "sec" | "secs" | "second" | "seconds" => num,
        _ => return Err(format!("duration '{s}' has unsupported unit '{unit}'")),
    };
    Ok(Duration::from_secs_f64(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default() {
        let s = BackoffSchedule::parse("1h,3h,8h,24h,48h").unwrap();
        assert_eq!(s, BackoffSchedule::default());
    }

    #[test]
    fn delay_for_attempt() {
        let s = BackoffSchedule::parse("1h,3h,8h,24h,48h").unwrap();
        assert_eq!(s.delay_for_attempt(0), Duration::from_secs(3600));
        assert_eq!(s.delay_for_attempt(1), Duration::from_secs(3 * 3600));
        assert_eq!(s.delay_for_attempt(2), Duration::from_secs(8 * 3600));
        assert_eq!(s.delay_for_attempt(3), Duration::from_secs(24 * 3600));
        assert_eq!(s.delay_for_attempt(4), Duration::from_secs(48 * 3600));
        assert_eq!(s.delay_for_attempt(5), Duration::from_secs(48 * 3600));
        assert_eq!(s.delay_for_attempt(100), Duration::from_secs(48 * 3600));
    }

    #[test]
    fn parse_mixed_units() {
        let s = BackoffSchedule::parse("30m, 2h, 1d").unwrap();
        assert_eq!(s.delay_for_attempt(0), Duration::from_secs(1800));
        assert_eq!(s.delay_for_attempt(1), Duration::from_secs(7200));
        assert_eq!(s.delay_for_attempt(2), Duration::from_secs(86400));
        assert_eq!(s.delay_for_attempt(3), Duration::from_secs(86400));
    }

    #[test]
    fn terminal_zero_stops_retrying() {
        let s = BackoffSchedule::parse("5s,1m,0").unwrap();
        assert_eq!(
            s.decision_for_attempt(0),
            BackoffDecision::RetryAfter(Duration::from_secs(5))
        );
        assert_eq!(
            s.decision_for_attempt(1),
            BackoffDecision::RetryAfter(Duration::from_secs(60))
        );
        assert_eq!(s.decision_for_attempt(2), BackoffDecision::Stop);
        assert_eq!(s.decision_for_attempt(99), BackoffDecision::Stop);
        assert_eq!(s.delay_for_attempt(99), Duration::ZERO);
    }

    #[test]
    fn profile_defaults_match_retry_policy() {
        let http = BackoffSchedule::from_env_names(
            "__T3RNEL_TEST_HTTP_BACKOFF",
            &[],
            DEFAULT_HTTP_BACKOFF,
        );
        assert!(http.has_terminal_stop());
        let connectivity = BackoffSchedule::from_env_names(
            "__T3RNEL_TEST_CONNECTIVITY_BACKOFF",
            &[],
            DEFAULT_CONNECTIVITY_BACKOFF,
        );
        assert_eq!(
            connectivity.decision_for_attempt(100),
            BackoffDecision::RetryAfter(Duration::from_secs(24 * 3600))
        );
    }
}
