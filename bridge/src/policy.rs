//! The permission engine (`05-security-and-trust.md` §3): grants, standing rules and the allow / approve / deny decision.
//!
//! Time is passed in as seconds since the Unix epoch so decisions are reproducible and testable.

use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityId, RiskClass};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(String);

impl AgentId {
    pub fn new(id: impl Into<String>) -> Result<AgentId, PolicyError> {
        let id = id.into();
        if id.trim().is_empty() || id.chars().any(char::is_control) {
            return Err(PolicyError::BadAgentId);
        }
        Ok(AgentId(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How far a grant reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    /// The whole application. Reversible writes still ask unless a standing rule covers them.
    App,
    /// Confined to approved folders or a workspace. Reversible writes inside are allowed; anything outside needs a grant.
    Folders,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub agent: AgentId,
    pub capability: CapabilityId,
    pub scope: Scope,
    /// Seconds since the epoch. `None` never expires; grants are time-boxed by default, so callers pass `Some`.
    pub expires_at: Option<u64>,
}

/// "Always let this agent do this", for `read` and `write-reversible` capabilities only. It always expires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingRule {
    pub id: u64,
    pub agent: AgentId,
    pub capability: CapabilityId,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalLevel {
    /// A human decision in the dashboard or on the phone.
    Standard,
    /// Settings that change the system: a stronger, explicit confirmation.
    Elevated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    UnknownCapability,
    NotGranted,
    GrantExpired,
    OutsideGrantedScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Ask a human first. `kernel_limit` means the kernel also enforces a spending limit on the call.
    Approval {
        level: ApprovalLevel,
        kernel_limit: bool,
    },
    Deny(DenyReason),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("agent id must be non-empty and free of control characters")]
    BadAgentId,
    #[error("a standing rule may only cover read and write-reversible capabilities, but {capability} is {class}")]
    StandingRuleClassNotAllowed { capability: CapabilityId, class: RiskClass },
    #[error("capability {0} is not in the reference table")]
    UnknownCapability(CapabilityId),
    #[error("a standing rule must expire in the future (expires_at {expires_at}, now {now})")]
    StandingRuleAlreadyExpired { expires_at: u64, now: u64 },
    #[error("no standing rule with id {0}")]
    NoSuchRule(u64),
}

#[derive(Debug, Clone, Default)]
pub struct PolicyEngine {
    grants: Vec<Grant>,
    standing: Vec<StandingRule>,
    next_rule_id: u64,
}

impl PolicyEngine {
    pub fn new() -> PolicyEngine {
        PolicyEngine::default()
    }

    /// Record a grant. Whether a human approved it is the caller's responsibility: this engine never creates one itself.
    pub fn grant(&mut self, grant: Grant) -> Result<(), PolicyError> {
        if grant.capability.reference_risk().is_none() {
            return Err(PolicyError::UnknownCapability(grant.capability));
        }
        self.grants.retain(|g| !(g.agent == grant.agent && g.capability == grant.capability));
        self.grants.push(grant);
        Ok(())
    }

    pub fn revoke_grant(&mut self, agent: &AgentId, capability: &CapabilityId) -> bool {
        let before = self.grants.len();
        self.grants.retain(|g| !(&g.agent == agent && &g.capability == capability));
        self.grants.len() != before
    }

    /// Add a standing rule. Refused for any class beyond `write-reversible`, and when it would already be expired.
    pub fn add_standing_rule(&mut self, now: u64, agent: AgentId, capability: CapabilityId, expires_at: u64) -> Result<u64, PolicyError> {
        let class = capability.reference_risk().ok_or_else(|| PolicyError::UnknownCapability(capability.clone()))?;
        if class > RiskClass::WriteReversible {
            return Err(PolicyError::StandingRuleClassNotAllowed { capability, class });
        }
        if expires_at <= now {
            return Err(PolicyError::StandingRuleAlreadyExpired { expires_at, now });
        }
        let id = self.next_rule_id;
        self.next_rule_id += 1;
        self.standing.push(StandingRule { id, agent, capability, expires_at });
        Ok(id)
    }

    pub fn revoke_standing_rule(&mut self, id: u64) -> Result<(), PolicyError> {
        let before = self.standing.len();
        self.standing.retain(|r| r.id != id);
        if self.standing.len() == before {
            return Err(PolicyError::NoSuchRule(id));
        }
        Ok(())
    }

    /// The single screen of live standing rules.
    pub fn standing_rules(&self, now: u64) -> Vec<&StandingRule> {
        self.standing.iter().filter(|r| r.expires_at > now).collect()
    }

    /// Decide one call. `target_in_scope` says whether the file, folder or document the call touches lies inside the grant's reach.
    pub fn decide(&self, now: u64, agent: &AgentId, capability: &CapabilityId, target_in_scope: bool) -> Decision {
        let Some(class) = capability.reference_risk() else {
            return Decision::Deny(DenyReason::UnknownCapability);
        };
        let mine: Vec<&Grant> = self.grants.iter().filter(|g| &g.agent == agent && &g.capability == capability).collect();
        let Some(grant) = mine.iter().find(|g| g.expires_at.is_none_or(|t| t > now)) else {
            return Decision::Deny(if mine.is_empty() { DenyReason::NotGranted } else { DenyReason::GrantExpired });
        };
        if !target_in_scope {
            return Decision::Deny(DenyReason::OutsideGrantedScope);
        }
        let ask = |level| Decision::Approval { level, kernel_limit: false };
        match class {
            RiskClass::Read => Decision::Allow,
            RiskClass::WriteReversible => {
                let standing = self.standing.iter().any(|r| &r.agent == agent && &r.capability == capability && r.expires_at > now);
                if grant.scope == Scope::Folders || standing {
                    Decision::Allow
                } else {
                    ask(ApprovalLevel::Standard)
                }
            }
            RiskClass::WriteIrreversible | RiskClass::ExternalEffect => ask(ApprovalLevel::Standard),
            RiskClass::Financial => Decision::Approval { level: ApprovalLevel::Standard, kernel_limit: true },
            RiskClass::System => ask(ApprovalLevel::Elevated),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn agent(s: &str) -> AgentId {
        AgentId::new(s).unwrap()
    }

    fn cap(s: &str) -> CapabilityId {
        s.parse().unwrap()
    }

    fn engine_with(capability: &str, scope: Scope, expires_at: Option<u64>) -> PolicyEngine {
        let mut e = PolicyEngine::new();
        e.grant(Grant { agent: agent("hermes"), capability: cap(capability), scope, expires_at }).unwrap();
        e
    }

    fn decide(e: &PolicyEngine, capability: &str) -> Decision {
        e.decide(NOW, &agent("hermes"), &cap(capability), true)
    }

    #[test]
    fn without_a_grant_everything_is_denied_even_reads() {
        let e = PolicyEngine::new();
        assert_eq!(decide(&e, "fs.search"), Decision::Deny(DenyReason::NotGranted));
        assert_eq!(decide(&e, "media.playlist.read"), Decision::Deny(DenyReason::NotGranted));
    }

    #[test]
    fn a_grant_is_per_agent_and_per_capability() {
        let e = engine_with("fs.search", Scope::App, Some(NOW + 60));
        assert_eq!(decide(&e, "fs.search"), Decision::Allow);
        assert_eq!(decide(&e, "fs.inspect"), Decision::Deny(DenyReason::NotGranted));
        assert_eq!(e.decide(NOW, &agent("other"), &cap("fs.search"), true), Decision::Deny(DenyReason::NotGranted));
    }

    #[test]
    fn an_expired_grant_is_denied_with_its_own_reason() {
        let e = engine_with("fs.search", Scope::App, Some(NOW));
        assert_eq!(decide(&e, "fs.search"), Decision::Deny(DenyReason::GrantExpired));
        assert_eq!(e.decide(NOW - 1, &agent("hermes"), &cap("fs.search"), true), Decision::Allow);
    }

    #[test]
    fn a_target_outside_the_grant_is_denied() {
        let e = engine_with("editor.write", Scope::Folders, Some(NOW + 60));
        assert_eq!(e.decide(NOW, &agent("hermes"), &cap("editor.write"), false), Decision::Deny(DenyReason::OutsideGrantedScope));
    }

    #[test]
    fn reversible_writes_are_allowed_inside_a_folder_grant_and_ask_for_an_app_grant() {
        assert_eq!(decide(&engine_with("editor.write", Scope::Folders, None), "editor.write"), Decision::Allow);
        assert_eq!(
            decide(&engine_with("media.pause", Scope::App, None), "media.pause"),
            Decision::Approval { level: ApprovalLevel::Standard, kernel_limit: false }
        );
    }

    #[test]
    fn a_standing_rule_lets_a_reversible_write_through_until_it_expires_or_is_revoked() {
        let mut e = engine_with("media.pause", Scope::App, None);
        let id = e.add_standing_rule(NOW, agent("hermes"), cap("media.pause"), NOW + 100).unwrap();
        assert_eq!(decide(&e, "media.pause"), Decision::Allow);
        assert_eq!(
            e.decide(NOW + 100, &agent("hermes"), &cap("media.pause"), true),
            Decision::Approval { level: ApprovalLevel::Standard, kernel_limit: false }
        );
        assert_eq!(e.standing_rules(NOW).len(), 1);
        assert!(e.standing_rules(NOW + 100).is_empty());
        e.revoke_standing_rule(id).unwrap();
        assert_ne!(decide(&e, "media.pause"), Decision::Allow);
        assert_eq!(e.revoke_standing_rule(id), Err(PolicyError::NoSuchRule(id)));
    }

    #[test]
    fn a_standing_rule_never_widens_what_the_grant_covers() {
        let mut e = PolicyEngine::new();
        e.add_standing_rule(NOW, agent("hermes"), cap("media.pause"), NOW + 100).unwrap();
        assert_eq!(decide(&e, "media.pause"), Decision::Deny(DenyReason::NotGranted));
    }

    #[test]
    fn standing_rules_are_refused_beyond_write_reversible() {
        let mut e = PolicyEngine::new();
        for name in ["fs.delete", "browser.click", "trade.order.place", "terminal.execute"] {
            let err = e.add_standing_rule(NOW, agent("hermes"), cap(name), NOW + 100).unwrap_err();
            assert!(matches!(err, PolicyError::StandingRuleClassNotAllowed { .. }), "{name}: {err}");
        }
        assert!(e.add_standing_rule(NOW, agent("hermes"), cap("fs.search"), NOW + 100).is_ok());
    }

    #[test]
    fn standing_rules_must_expire_in_the_future_and_name_a_known_capability() {
        let mut e = PolicyEngine::new();
        assert_eq!(
            e.add_standing_rule(NOW, agent("hermes"), cap("media.pause"), NOW),
            Err(PolicyError::StandingRuleAlreadyExpired { expires_at: NOW, now: NOW })
        );
        assert_eq!(
            e.add_standing_rule(NOW, agent("hermes"), cap("media.teleport"), NOW + 1),
            Err(PolicyError::UnknownCapability(cap("media.teleport")))
        );
    }

    #[test]
    fn dangerous_classes_always_ask_and_a_grant_alone_never_allows_them() {
        let std = Decision::Approval { level: ApprovalLevel::Standard, kernel_limit: false };
        assert_eq!(decide(&engine_with("fs.delete", Scope::Folders, None), "fs.delete"), std);
        assert_eq!(decide(&engine_with("browser.click", Scope::Folders, None), "browser.click"), std);
        assert_eq!(
            decide(&engine_with("trade.order.place", Scope::App, None), "trade.order.place"),
            Decision::Approval { level: ApprovalLevel::Standard, kernel_limit: true }
        );
        assert_eq!(
            decide(&engine_with("terminal.execute", Scope::App, None), "terminal.execute"),
            Decision::Approval { level: ApprovalLevel::Elevated, kernel_limit: false }
        );
    }

    #[test]
    fn granting_an_unknown_capability_is_refused_and_a_new_grant_replaces_the_old_one() {
        let mut e = PolicyEngine::new();
        let bogus = Grant { agent: agent("hermes"), capability: cap("media.teleport"), scope: Scope::App, expires_at: None };
        assert_eq!(e.grant(bogus), Err(PolicyError::UnknownCapability(cap("media.teleport"))));
        e.grant(Grant { agent: agent("hermes"), capability: cap("fs.search"), scope: Scope::App, expires_at: Some(NOW) }).unwrap();
        e.grant(Grant { agent: agent("hermes"), capability: cap("fs.search"), scope: Scope::App, expires_at: Some(NOW + 60) }).unwrap();
        assert_eq!(decide(&e, "fs.search"), Decision::Allow, "the renewed grant replaced the expired one");
    }

    #[test]
    fn revoking_a_grant_takes_effect_at_once() {
        let mut e = engine_with("fs.search", Scope::App, None);
        assert!(e.revoke_grant(&agent("hermes"), &cap("fs.search")));
        assert_eq!(decide(&e, "fs.search"), Decision::Deny(DenyReason::NotGranted));
        assert!(!e.revoke_grant(&agent("hermes"), &cap("fs.search")));
    }

    #[test]
    fn agent_ids_cannot_be_blank_or_carry_control_characters() {
        assert_eq!(AgentId::new("  "), Err(PolicyError::BadAgentId));
        assert_eq!(AgentId::new("a\nb"), Err(PolicyError::BadAgentId));
        assert_eq!(AgentId::new("hermes").unwrap().as_str(), "hermes");
    }
}
