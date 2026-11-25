//! Capability names (`<domain>.<verb>`) and the reference risk table.
//!
//! The capability is the unit of permission. Every capability has a risk class, and a manifest cannot declare a class
//! lower than the one in [`REFERENCE`].

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// How much harm a capability can do. Declaration order is severity order: a later variant is more severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskClass {
    Read,
    WriteReversible,
    WriteIrreversible,
    ExternalEffect,
    Financial,
    System,
}

impl fmt::Display for RiskClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RiskClass::Read => "read",
            RiskClass::WriteReversible => "write-reversible",
            RiskClass::WriteIrreversible => "write-irreversible",
            RiskClass::ExternalEffect => "external-effect",
            RiskClass::Financial => "financial",
            RiskClass::System => "system",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityError {
    #[error("capability name {0:?} must be `<domain>.<verb>` with lowercase letters, digits and underscores in each dot-separated part")]
    Malformed(String),
}

/// A validated capability name such as `media.playlist.read`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CapabilityId(String);

impl CapabilityId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `media` for `media.playlist.read`.
    pub fn domain(&self) -> &str {
        self.0.split('.').next().unwrap_or_default()
    }

    /// The risk class this capability has in the reference table, or `None` for a name the table does not know.
    pub fn reference_risk(&self) -> Option<RiskClass> {
        REFERENCE
            .binary_search_by(|(name, _)| (*name).cmp(self.0.as_str()))
            .ok()
            .map(|i| REFERENCE[i].1)
    }
}

impl FromStr for CapabilityId {
    type Err = CapabilityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = 0;
        for part in s.split('.') {
            let mut chars = part.chars();
            let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
            if !first_ok || !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                return Err(CapabilityError::Malformed(s.to_string()));
            }
            parts += 1;
        }
        if parts < 2 {
            return Err(CapabilityError::Malformed(s.to_string()));
        }
        Ok(CapabilityId(s.to_string()))
    }
}

impl TryFrom<String> for CapabilityId {
    type Error = CapabilityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<CapabilityId> for String {
    fn from(id: CapabilityId) -> String {
        id.0
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

use RiskClass::{ExternalEffect, Financial, Read, System, WriteIrreversible, WriteReversible};

/// The reference risk table, sorted by name (binary search depends on it; a test enforces the order).
///
/// Clicking in a browser can submit a form or send a message, so `browser.click` is `external-effect` rather than the
/// friendlier `write-reversible`; `terminal.execute` is `system` because it runs arbitrary commands.
pub const REFERENCE: &[(&str, RiskClass)] = &[
    // bounty.* — the bounty-hunter connector plugin domain. Scanning public
    // bounty boards is a read; queueing a dispatch order or tracking a
    // receivable mutates plugin-private state but reversibly.
    ("bounty.market.scan", Read),
    ("bounty.order.dispatch", WriteReversible),
    ("bounty.receivable.track", Read),
    ("browser.click", ExternalEffect),
    ("browser.download", WriteReversible),
    ("browser.fill", WriteReversible),
    ("browser.navigate", WriteReversible),
    ("browser.read", Read),
    ("browser.screenshot", Read),
    ("browser.tabs.list", Read),
    // comms.* — the 2-way messaging plugin domain
    // (docs/sections/18 §8 step 3). Sending anything over a channel is an
    // external effect; reading thread state is a read.
    ("comms.approval.request", ExternalEffect),
    ("comms.message.reply", ExternalEffect),
    ("comms.notify.send", ExternalEffect),
    ("comms.thread.read", Read),
    ("diagnostics.read", Read),
    ("doc.edit", WriteReversible),
    ("doc.export", WriteReversible),
    ("doc.open", WriteReversible),
    ("doc.read", Read),
    ("editor.read", Read),
    ("editor.replace", WriteReversible),
    ("editor.save", WriteReversible),
    ("editor.tabs.list", Read),
    ("editor.write", WriteReversible),
    ("fs.delete", WriteIrreversible),
    ("fs.inspect", Read),
    ("fs.mkdir", WriteReversible),
    ("fs.move", WriteReversible),
    ("fs.open_location", WriteReversible),
    ("fs.rename", WriteReversible),
    ("fs.search", Read),
    ("git.diff", Read),
    ("git.status", Read),
    // google.* — the Google connector plugins (search-console, analytics)
    // sharing the core OAuth broker (docs/sections/18 §8). All are reads of
    // Google reporting APIs except sitemap submission, which writes back to
    // Search Console and is therefore write-reversible.
    ("google.analytics.properties", Read),
    ("google.analytics.report", Read),
    ("google.searchconsole.query", Read),
    ("google.searchconsole.sitemap.submit", WriteReversible),
    ("google.searchconsole.sitemaps", Read),
    ("google.searchconsole.sites", Read),
    // job.* — the job-hunter connector plugin domain. Polling agent-work
    // marketplaces is a read; drafting an application is plugin-private and
    // reversible (nothing is sent — delivery stays a host decision).
    ("job.application.draft", WriteReversible),
    ("job.market.scan", Read),
    ("media.audio.set", WriteReversible),
    ("media.metadata.read", Read),
    ("media.pause", WriteReversible),
    ("media.play", WriteReversible),
    ("media.playlist.read", Read),
    ("media.playlist.write", WriteReversible),
    ("media.seek", WriteReversible),
    ("media.stop", WriteReversible),
    ("media.subtitle.set", WriteReversible),
    // social.* — the social connector plugin domain. Publishing a post is an
    // external effect on a third-party platform; composing, scheduling and
    // reading the queue are plugin-private and reversible.
    ("social.account.status", Read),
    ("social.post.draft", WriteReversible),
    ("social.post.publish", ExternalEffect),
    ("social.post.schedule", WriteReversible),
    ("social.queue.read", Read),
    ("terminal.execute", System),
    ("terminal.read", Read),
    ("trade.account.read", Read),
    ("trade.chart.read", Read),
    ("trade.order.place", Financial),
    ("trade.positions.read", Read),
    ("ui.event.emit", WriteReversible),
    ("ui.widget.provide", WriteReversible),
    ("workspace.list", Read),
    ("workspace.open", WriteReversible),
    ("workspace.read", Read),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn id(s: &str) -> CapabilityId {
        s.parse().unwrap()
    }

    #[test]
    fn the_reference_table_is_sorted_and_free_of_duplicates() {
        for pair in REFERENCE.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "{} must sort before {}",
                pair[0].0,
                pair[1].0
            );
        }
    }

    #[test]
    fn every_name_in_the_reference_table_is_a_valid_capability_id() {
        for (name, _) in REFERENCE {
            assert!(name.parse::<CapabilityId>().is_ok(), "{name} is malformed");
        }
    }

    #[test]
    fn the_reference_table_matches_the_taxonomy_in_the_specification() {
        // Truth rule 1: the document and the code are pinned together. The table in section 04 lists `domain.*` rows.
        let doc = crate::spec_section("04-app-bridge-and-connectors.md");
        let text =
            std::fs::read_to_string(&doc).unwrap_or_else(|e| panic!("{}: {e}", doc.display()));
        let mut documented = BTreeSet::new();
        let start = text
            .find("## 2. Capability taxonomy")
            .expect("taxonomy section");
        let end = text[start..]
            .find("**Every capability declares")
            .expect("end of taxonomy table")
            + start;
        for line in text[start..end].lines().filter(|l| l.starts_with("| `")) {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            let domain = cells[1].trim_matches('`').trim_end_matches(".*");
            let mut rest = cells[2];
            while let Some(open) = rest.find('`') {
                let close = rest[open + 1..].find('`').expect("closing backtick") + open + 1;
                documented.insert(format!("{domain}.{}", &rest[open + 1..close]));
                rest = &rest[close + 1..];
            }
        }
        let coded: BTreeSet<String> = REFERENCE.iter().map(|(n, _)| n.to_string()).collect();
        assert_eq!(
            coded, documented,
            "the code table and the specification's taxonomy disagree"
        );
    }

    #[test]
    fn names_need_a_domain_and_a_verb() {
        for bad in [
            "",
            "media",
            "Media.play",
            "media..play",
            ".play",
            "media.",
            "media.pl ay",
            "1media.play",
            "media.play-now",
        ] {
            assert!(
                bad.parse::<CapabilityId>().is_err(),
                "{bad:?} must be rejected"
            );
        }
        assert_eq!(id("media.playlist.read").domain(), "media");
    }

    #[test]
    fn unknown_names_have_no_reference_risk() {
        assert_eq!(id("media.teleport").reference_risk(), None);
        assert_eq!(id("fs.delete").reference_risk(), Some(WriteIrreversible));
        assert_eq!(id("trade.order.place").reference_risk(), Some(Financial));
    }

    #[test]
    fn severity_follows_declaration_order() {
        assert!(Read < WriteReversible && WriteReversible < WriteIrreversible);
        assert!(
            WriteIrreversible < ExternalEffect && ExternalEffect < Financial && Financial < System
        );
    }

    #[test]
    fn a_capability_id_round_trips_through_json_and_rejects_bad_input() {
        let original = id("editor.tabs.list");
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"editor.tabs.list\"");
        assert_eq!(
            serde_json::from_str::<CapabilityId>(&json).unwrap(),
            original
        );
        assert!(serde_json::from_str::<CapabilityId>("\"NOPE\"").is_err());
    }
}
