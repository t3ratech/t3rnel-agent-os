//! Policy-driven memory lifecycle.
//!
//! Expiry is a decision a policy makes, not a side effect: nothing expires on
//! its own, a sweep applies the policy and stamps `status` / `expired_by` onto
//! each match so a recalled record can say when it expired and which rule did
//! it. Design follows memanto's two-half policy — a per-kind `retention`
//! table for broad strokes plus named first-match-wins `rules` for sharper
//! cases — with the evaluation kept pure so it is testable without storage.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use t3rnel_types::unified_memory::{MemoryKind, MemoryRecord, MemoryStatus};

/// A named expiry rule. `name` is stamped onto the record as `expired_by`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyRule {
    pub name: String,
    #[serde(rename = "match")]
    pub match_: PolicyMatch,
    /// Duration string ("30d", "12h", "never"); `never` pins a match active.
    pub expire_after: String,
}

/// Conditions a record must satisfy for a rule to fire. Every set field must
/// match (AND); an empty match block is the catch-all.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyMatch {
    #[serde(rename = "type")]
    pub kind: Option<Vec<String>>,
    pub provenance: Option<Vec<String>>,
    pub key_prefix: Option<String>,
    pub confidence_below: Option<f32>,
}

impl PolicyMatch {
    pub fn matches(&self, record: &MemoryRecord) -> bool {
        if let Some(kinds) = &self.kind {
            if !kinds.iter().any(|k| k == record.kind.as_str()) {
                return false;
            }
        }
        if let Some(sources) = &self.provenance {
            if !sources.iter().any(|s| s == &record.provenance.source) {
                return false;
            }
        }
        if let Some(prefix) = &self.key_prefix {
            if !record
                .key
                .as_deref()
                .is_some_and(|k| k.starts_with(prefix.as_str()))
            {
                return false;
            }
        }
        if let Some(floor) = self.confidence_below {
            if !(record.confidence.is_finite() && record.confidence < floor) {
                return false;
            }
        }
        true
    }
}

/// The full expiry policy for one scope.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryPolicy {
    /// Per-kind expiry windows: `{"episode":"7d","fact":"never"}`.
    pub retention: BTreeMap<String, String>,
    pub rules: Vec<PolicyRule>,
    /// Hard-delete records expired longer than this; absent disables purging.
    pub purge_expired_after: Option<String>,
}

impl MemoryPolicy {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
            && !self
                .retention
                .values()
                .any(|d| parse_duration(d).is_ok_and(|s| s.is_some()))
    }
}

/// Parse "7d" / "12h" / "3mo" / "never" into seconds; None means never.
pub fn parse_duration(value: &str) -> Result<Option<i64>, String> {
    let token = value.trim().to_lowercase();
    if token.is_empty() || token == "never" {
        return Ok(None);
    }
    let (digits, unit) = token.split_at(
        token
            .find(|c: char| c.is_ascii_alphabetic())
            .ok_or_else(|| format!("invalid duration '{value}'"))?,
    );
    let amount: i64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration '{value}'"))?;
    if amount <= 0 {
        return Err(format!("invalid duration '{value}': must be positive"));
    }
    let seconds = match unit.trim() {
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "w" => 604800,
        "mo" => 2_592_000,
        "y" => 31_536_000,
        other => return Err(format!("invalid duration unit '{other}'")),
    };
    Ok(Some(amount * seconds))
}

/// The timestamp a record's age is measured from: an edit is evidence the
/// belief is still live, so `updated_at` wins over `created_at`.
fn age_basis(record: &MemoryRecord) -> DateTime<Utc> {
    record.updated_at
}

/// Decide whether `record` should expire under `policy` at `now`.
/// Returns `(should_expire, reason)` where reason becomes `expired_by`.
/// The first matching rule wins and short-circuits the retention table, so a
/// rule with `expire_after: never` pins a record active.
pub fn evaluate(
    record: &MemoryRecord,
    policy: &MemoryPolicy,
    now: DateTime<Utc>,
) -> (bool, Option<String>) {
    if record.status != MemoryStatus::Active {
        return (false, None);
    }
    let age = now - age_basis(record);
    for rule in &policy.rules {
        if rule.match_.matches(record) {
            match parse_duration(&rule.expire_after) {
                Ok(None) => return (false, None),
                Ok(Some(window)) if age >= Duration::seconds(window) => {
                    return (true, Some(rule.name.clone()));
                }
                _ => return (false, None),
            }
        }
    }
    let kind = record.kind.as_str();
    if let Some(duration) = policy.retention.get(kind) {
        if let Ok(Some(window)) = parse_duration(duration) {
            if age >= Duration::seconds(window) {
                return (true, Some(format!("retention.{kind}")));
            }
        }
    }
    (false, None)
}

/// Validate a policy payload: every rule name must be unique and every
/// duration and kind must parse — reject at write time, not at sweep time.
pub fn validate(policy: &MemoryPolicy) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for rule in &policy.rules {
        if rule.name.is_empty() || rule.name.len() > 100 {
            return Err("rule names must be 1..100 chars".into());
        }
        if !seen.insert(rule.name.clone()) {
            return Err(format!("duplicate rule name '{}'", rule.name));
        }
        parse_duration(&rule.expire_after)?;
    }
    for kind in policy.retention.keys() {
        let parsed = serde_json::from_value::<MemoryKind>(serde_json::json!(kind));
        if parsed.is_err() {
            return Err(format!("unknown memory kind '{kind}' in retention table"));
        }
        parse_duration(&policy.retention[kind])?;
    }
    if let Some(purge) = &policy.purge_expired_after {
        parse_duration(purge)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use t3rnel_types::unified_memory::MemoryKind;

    fn record(kind: MemoryKind, age_days: i64) -> MemoryRecord {
        let at = Utc::now() - Duration::days(age_days);
        MemoryRecord {
            id: "r".into(),
            uri: "t3rnel://private/fact/r".into(),
            agent_id: "a".into(),
            kind,
            scope: Default::default(),
            key: None,
            content: "c".into(),
            summary: "s".into(),
            confidence: 1.0,
            provenance: Default::default(),
            metadata: serde_json::json!({}),
            retention: t3rnel_types::unified_memory::RetentionClass::Durable,
            recall_weight: 1.0,
            created_at: at,
            updated_at: at,
            depth: Default::default(),
            truncated: false,
            revision: 1,
            status: MemoryStatus::Active,
            valid_from: None,
            valid_to: None,
            recorded_from: None,
            recorded_to: None,
            expired_by: None,
            supersedes: None,
        }
    }

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration("7d").unwrap(), Some(604800));
        assert_eq!(parse_duration("never").unwrap(), None);
        assert!(parse_duration("bogus").is_err());
    }

    #[test]
    fn retention_expires_old_kind() {
        let policy = MemoryPolicy {
            retention: BTreeMap::from([("episode".into(), "7d".into())]),
            ..Default::default()
        };
        let (expire, reason) = evaluate(&record(MemoryKind::Episode, 10), &policy, Utc::now());
        assert!(expire);
        assert_eq!(reason.as_deref(), Some("retention.episode"));
        let (expire, _) = evaluate(&record(MemoryKind::Episode, 2), &policy, Utc::now());
        assert!(!expire);
        let (expire, _) = evaluate(&record(MemoryKind::Fact, 400), &policy, Utc::now());
        assert!(!expire);
    }

    #[test]
    fn first_rule_wins_and_pins() {
        let policy = MemoryPolicy {
            retention: BTreeMap::from([("episode".into(), "7d".into())]),
            rules: vec![PolicyRule {
                name: "pinned".into(),
                match_: PolicyMatch {
                    key_prefix: Some("keep:".into()),
                    ..Default::default()
                },
                expire_after: "never".into(),
            }],
            ..Default::default()
        };
        let mut pinned = record(MemoryKind::Episode, 90);
        pinned.key = Some("keep:important".into());
        assert!(!evaluate(&pinned, &policy, Utc::now()).0);
        assert!(evaluate(&record(MemoryKind::Episode, 90), &policy, Utc::now()).0);
    }

    #[test]
    fn low_confidence_rule_expires() {
        let policy = MemoryPolicy {
            rules: vec![PolicyRule {
                name: "guesses".into(),
                match_: PolicyMatch {
                    confidence_below: Some(0.5),
                    ..Default::default()
                },
                expire_after: "14d".into(),
            }],
            ..Default::default()
        };
        let mut guess = record(MemoryKind::Fact, 30);
        guess.confidence = 0.3;
        assert_eq!(
            evaluate(&guess, &policy, Utc::now()).1.as_deref(),
            Some("guesses")
        );
    }

    #[test]
    fn validation_rejects_bad_policy() {
        let mut policy = MemoryPolicy::default();
        assert!(validate(&policy).is_ok());
        policy.retention.insert("nonsense".into(), "7d".into());
        assert!(validate(&policy).is_err());
    }
}
