//! The audit chain (`04` §1, `05` §6): every call is recorded with the integration level that served it, and each record
//! carries the hash of the one before, so an edit, a deletion or a reordering is detectable.
//!
//! Truncating the tail cannot be detected from the chain alone; [`AuditChain::anchor`] returns the head to store elsewhere,
//! and [`AuditChain::verify_anchored`] checks the chain still contains it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The `prev` of the first record.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    Approved,
    Denied,
    Failed,
}

impl Outcome {
    fn tag(self) -> &'static str {
        match self {
            Outcome::Allowed => "allowed",
            Outcome::Approved => "approved",
            Outcome::Denied => "denied",
            Outcome::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub seq: u64,
    /// Seconds since the epoch.
    pub at: u64,
    pub agent: String,
    pub capability: String,
    /// Integration level that served the call, 1 to 4.
    pub level: u8,
    pub outcome: Outcome,
    pub detail: String,
    pub prev: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub len: u64,
    pub head: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    #[error("integration level {0} is not 1 to 4")]
    BadLevel(u8),
    #[error("record {seq} has sequence number {found}")]
    WrongSequence { seq: u64, found: u64 },
    #[error("record {0} does not link to the record before it")]
    BrokenLink(u64),
    #[error("record {0} does not match its own hash")]
    Tampered(u64),
    #[error("the chain is shorter than the anchor: {have} records, anchor covers {anchored}")]
    Truncated { have: u64, anchored: u64 },
    #[error("the chain does not contain the anchored head at record {0}")]
    AnchorMismatch(u64),
    #[error("line {line} is not a valid record: {message}")]
    BadLine { line: usize, message: String },
}

#[derive(Debug, Clone, Default)]
pub struct AuditChain {
    records: Vec<Record>,
}

fn field(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

fn digest(r: &Record) -> String {
    let mut h = Sha256::new();
    field(&mut h, &r.seq.to_be_bytes());
    field(&mut h, &r.at.to_be_bytes());
    field(&mut h, r.agent.as_bytes());
    field(&mut h, r.capability.as_bytes());
    field(&mut h, &[r.level]);
    field(&mut h, r.outcome.tag().as_bytes());
    field(&mut h, r.detail.as_bytes());
    field(&mut h, r.prev.as_bytes());
    hex::encode(h.finalize())
}

impl AuditChain {
    pub fn new() -> AuditChain {
        AuditChain::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn records(&self) -> &[Record] {
        &self.records
    }

    pub fn append(
        &mut self,
        at: u64,
        agent: &str,
        capability: &str,
        level: u8,
        outcome: Outcome,
        detail: &str,
    ) -> Result<&Record, AuditError> {
        if !(1..=4).contains(&level) {
            return Err(AuditError::BadLevel(level));
        }
        let mut record = Record {
            seq: self.records.len() as u64,
            at,
            agent: agent.to_string(),
            capability: capability.to_string(),
            level,
            outcome,
            detail: detail.to_string(),
            prev: self.records.last().map_or_else(|| GENESIS.to_string(), |r| r.hash.clone()),
            hash: String::new(),
        };
        record.hash = digest(&record);
        self.records.push(record);
        Ok(self.records.last().expect("just pushed"))
    }

    pub fn verify(&self) -> Result<(), AuditError> {
        let mut prev = GENESIS;
        for (i, r) in self.records.iter().enumerate() {
            if r.seq != i as u64 {
                return Err(AuditError::WrongSequence { seq: i as u64, found: r.seq });
            }
            if r.prev != prev {
                return Err(AuditError::BrokenLink(r.seq));
            }
            if digest(r) != r.hash {
                return Err(AuditError::Tampered(r.seq));
            }
            prev = &r.hash;
        }
        Ok(())
    }

    /// The head to keep somewhere the chain's writer cannot rewrite.
    pub fn anchor(&self) -> Anchor {
        Anchor { len: self.records.len() as u64, head: self.records.last().map_or_else(|| GENESIS.to_string(), |r| r.hash.clone()) }
    }

    pub fn verify_anchored(&self, anchor: &Anchor) -> Result<(), AuditError> {
        self.verify()?;
        let have = self.records.len() as u64;
        if have < anchor.len {
            return Err(AuditError::Truncated { have, anchored: anchor.len });
        }
        let head = if anchor.len == 0 { GENESIS } else { &self.records[anchor.len as usize - 1].hash };
        if head != anchor.head {
            return Err(AuditError::AnchorMismatch(anchor.len.saturating_sub(1)));
        }
        Ok(())
    }

    pub fn to_jsonl(&self) -> String {
        self.records.iter().map(|r| serde_json::to_string(r).expect("a record always serialises") + "\n").collect()
    }

    /// Load and verify. A file that does not verify is an error, never a partial chain.
    pub fn from_jsonl(text: &str) -> Result<AuditChain, AuditError> {
        let mut records = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let record: Record = serde_json::from_str(line).map_err(|e| AuditError::BadLine { line: i + 1, message: e.to_string() })?;
            records.push(record);
        }
        let chain = AuditChain { records };
        chain.verify()?;
        Ok(chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AuditChain {
        let mut c = AuditChain::new();
        c.append(100, "hermes", "media.play", 2, Outcome::Allowed, "").unwrap();
        c.append(101, "hermes", "fs.delete", 2, Outcome::Denied, "user declined").unwrap();
        c.append(102, "claude", "editor.write", 1, Outcome::Approved, "src/main.rs").unwrap();
        c.append(103, "claude", "browser.click", 3, Outcome::Failed, "element not found").unwrap();
        c
    }

    #[test]
    fn an_empty_and_a_normal_chain_verify() {
        assert!(AuditChain::new().verify().is_ok());
        assert!(sample().verify().is_ok());
    }

    #[test]
    fn records_link_to_the_one_before_starting_at_genesis() {
        let c = sample();
        assert_eq!(c.records()[0].prev, GENESIS);
        for pair in c.records().windows(2) {
            assert_eq!(pair[1].prev, pair[0].hash);
        }
    }

    #[test]
    fn changing_any_field_of_any_record_is_detected() {
        for (name, edit) in [
            ("agent", (|r: &mut Record| r.agent = "mallory".into()) as fn(&mut Record)),
            ("capability", |r| r.capability = "media.pause".into()),
            ("level", |r| r.level = 1),
            ("outcome", |r| r.outcome = Outcome::Allowed),
            ("detail", |r| r.detail.push('!')),
            ("at", |r| r.at += 1),
        ] {
            let mut c = sample();
            edit(&mut c.records[1]);
            assert_eq!(c.verify(), Err(AuditError::Tampered(1)), "editing {name}");
        }
    }

    #[test]
    fn a_rehashed_edit_still_breaks_the_next_link() {
        let mut c = sample();
        c.records[1].detail = "approved after all".into();
        c.records[1].hash = digest(&c.records[1]);
        assert_eq!(c.verify(), Err(AuditError::BrokenLink(2)));
    }

    #[test]
    fn deleting_or_reordering_records_is_detected() {
        let mut deleted = sample();
        deleted.records.remove(1);
        assert_eq!(deleted.verify(), Err(AuditError::WrongSequence { seq: 1, found: 2 }));
        let mut swapped = sample();
        swapped.records.swap(1, 2);
        assert!(swapped.verify().is_err());
    }

    #[test]
    fn the_first_record_cannot_be_deleted_either() {
        let mut c = sample();
        c.records.remove(0);
        assert_eq!(c.verify(), Err(AuditError::WrongSequence { seq: 0, found: 1 }));
    }

    #[test]
    fn truncating_the_tail_is_caught_only_with_an_anchor() {
        let mut c = sample();
        let anchor = c.anchor();
        c.records.truncate(2);
        assert!(c.verify().is_ok(), "the chain alone cannot see a cut tail");
        assert_eq!(c.verify_anchored(&anchor), Err(AuditError::Truncated { have: 2, anchored: 4 }));
    }

    #[test]
    fn an_anchor_from_another_history_does_not_match_and_a_prefix_anchor_does() {
        let c = sample();
        let mut other = AuditChain::new();
        other.append(100, "hermes", "media.play", 2, Outcome::Allowed, "different").unwrap();
        assert_eq!(c.verify_anchored(&other.anchor()), Err(AuditError::AnchorMismatch(0)));
        let mut earlier = sample();
        earlier.records.truncate(2);
        let anchor = earlier.anchor();
        assert!(c.verify_anchored(&anchor).is_ok(), "a longer chain that extends the anchored one is fine");
        assert!(c.verify_anchored(&AuditChain::new().anchor()).is_ok());
    }

    #[test]
    fn levels_outside_one_to_four_are_refused() {
        let mut c = AuditChain::new();
        assert_eq!(c.append(1, "a", "media.play", 0, Outcome::Allowed, "").unwrap_err(), AuditError::BadLevel(0));
        assert_eq!(c.append(1, "a", "media.play", 5, Outcome::Allowed, "").unwrap_err(), AuditError::BadLevel(5));
        assert!(c.is_empty(), "a refused record leaves no trace");
    }

    #[test]
    fn field_boundaries_cannot_be_shifted_to_forge_a_hash() {
        let mut a = AuditChain::new();
        a.append(1, "ab", "media.play", 2, Outcome::Allowed, "c").unwrap();
        let mut b = AuditChain::new();
        b.append(1, "a", "media.play", 2, Outcome::Allowed, "bc").unwrap();
        assert_ne!(a.records()[0].hash, b.records()[0].hash);
    }

    #[test]
    fn a_chain_round_trips_through_jsonl_and_loading_verifies() {
        let c = sample();
        let loaded = AuditChain::from_jsonl(&c.to_jsonl()).unwrap();
        assert_eq!(loaded.records(), c.records());
        let tampered = c.to_jsonl().replace("user declined", "user agreed");
        assert_eq!(AuditChain::from_jsonl(&tampered).unwrap_err(), AuditError::Tampered(1));
        assert!(matches!(AuditChain::from_jsonl("not json\n"), Err(AuditError::BadLine { line: 1, .. })));
    }

    #[test]
    fn a_record_with_an_extra_field_is_refused_on_load() {
        let line = sample().to_jsonl().lines().next().unwrap().replace('}', ",\"admin\":true}");
        assert!(matches!(AuditChain::from_jsonl(&line), Err(AuditError::BadLine { line: 1, .. })));
    }
}
