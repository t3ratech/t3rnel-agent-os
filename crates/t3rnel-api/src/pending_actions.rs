//! Pending-actions ledger — the single list of asks waiting on a human.
//!
//! Every producer (kernel approvals, scripts, agents, sitesmith) registers an
//! item here; the operator resolves it from the dashboard, `./t3rnel-services
//! approvals`, or a WhatsApp reply (`APPROVE P-103`, quoted yes/no, 👍/👎).
//!
//! Persisted as `~/.t3rnel/pending-actions.json` so asks survive restarts.
//! IDs are `P-<n>` short codes allocated monotonically, never reused.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PendingKind {
    Approval,
    Script,
    Sitesmith,
    Agent,
}

impl PendingKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Script => "script",
            Self::Sitesmith => "sitesmith",
            Self::Agent => "agent",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PendingState {
    Pending,
    Approved,
    Rejected,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAction {
    pub id: String,
    pub kind: PendingKind,
    pub summary: String,
    #[serde(default)]
    pub detail_ref: Option<String>,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub callback: Option<String>,
    #[serde(default)]
    pub risk: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    pub state: PendingState,
    #[serde(default)]
    pub decision_note: Option<String>,
    #[serde(default)]
    pub decided_by: Option<String>,
    #[serde(default)]
    pub decided_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub wa_message_id: Option<String>,
}

#[derive(Debug, Default)]
pub struct PendingStore {
    items: Vec<PendingAction>,
    next_seq: u64,
    path: Option<PathBuf>,
}

fn store_path() -> PathBuf {
    t3rnel_kernel::config::t3rnel_home().join("pending-actions.json")
}

static STORE: LazyLock<Mutex<PendingStore>> = LazyLock::new(|| {
    let mut store = PendingStore { path: Some(store_path()), ..Default::default() };
    store.load();
    Mutex::new(store)
});

impl PendingStore {
    fn load(&mut self) {
        let Some(path) = &self.path else { return };
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(items) = serde_json::from_str::<Vec<PendingAction>>(&text) {
                self.next_seq = items
                    .iter()
                    .filter_map(|i| i.id.strip_prefix("P-").and_then(|n| n.parse::<u64>().ok()))
                    .max()
                    .unwrap_or(0)
                    + 1;
                self.items = items;
            }
        }
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.items) {
            let _ = std::fs::write(path, json);
        }
    }

    /// Live = pending and not past expiry.
    fn is_live(item: &PendingAction, now: DateTime<Utc>) -> bool {
        item.state == PendingState::Pending
            && item.expires_at.map(|e| e > now).unwrap_or(true)
    }

    pub fn list(&self) -> Vec<PendingAction> {
        let now = Utc::now();
        self.items
            .iter()
            .filter(|i| Self::is_live(i, now) || i.state == PendingState::Pending)
            .cloned()
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<PendingAction> {
        self.items.iter().find(|i| i.id.eq_ignore_ascii_case(id)).cloned()
    }

    pub fn create(&mut self, mut item: PendingAction) -> PendingAction {
        self.next_seq += 1;
        item.id = format!("P-{}", self.next_seq);
        if item.state != PendingState::Pending {
            item.state = PendingState::Pending;
        }
        self.items.push(item.clone());
        self.save();
        item
    }

    /// Resolve a pending item. Returns the updated record, or an error string
    /// when the id is unknown or already resolved (idempotent-safe: callers
    /// distinguish "already" from "not found").
    pub fn resolve(
        &mut self,
        id: &str,
        decision: PendingState,
        note: Option<String>,
        decided_by: &str,
    ) -> Result<PendingAction, String> {
        if !matches!(decision, PendingState::Approved | PendingState::Rejected | PendingState::Cancelled) {
            return Err("decision must be approved, rejected or cancelled".into());
        }
        let now = Utc::now();
        let expired = {
            let item = self
                .items
                .iter_mut()
                .find(|i| i.id.eq_ignore_ascii_case(id))
                .ok_or_else(|| format!("no pending item {id}"))?;
            if item.state != PendingState::Pending {
                return Err(format!("{} is already {}", item.id, state_name(&item.state)));
            }
            if item.expires_at.map(|e| e <= now).unwrap_or(false) {
                item.state = PendingState::Expired;
                true
            } else {
                item.state = decision;
                item.decision_note = note;
                item.decided_by = Some(decided_by.to_string());
                item.decided_at = Some(now);
                false
            }
        };
        self.save();
        if expired {
            return Err(format!("{id} has expired"));
        }
        Ok(self.items.iter().find(|i| i.id.eq_ignore_ascii_case(id)).unwrap().clone())
    }

    pub fn snooze(&mut self, id: &str, secs: i64) -> Result<PendingAction, String> {
        let item = self
            .items
            .iter_mut()
            .find(|i| i.id.eq_ignore_ascii_case(id))
            .ok_or_else(|| format!("no pending item {id}"))?;
        if item.state != PendingState::Pending {
            return Err(format!("{} is already {}", item.id, state_name(&item.state)));
        }
        let base = item.expires_at.unwrap_or_else(Utc::now);
        item.expires_at = Some(base + chrono::Duration::seconds(secs.max(60)));
        let out = item.clone();
        self.save();
        Ok(out)
    }
}

fn state_name(s: &PendingState) -> &'static str {
    match s {
        PendingState::Pending => "pending",
        PendingState::Approved => "approved",
        PendingState::Rejected => "rejected",
        PendingState::Expired => "expired",
        PendingState::Cancelled => "cancelled",
    }
}

// ---------------------------------------------------------------------------
// Route-facing API used by routes.rs
// ---------------------------------------------------------------------------

pub fn list_pending() -> Vec<PendingAction> {
    STORE.lock().unwrap().list()
}

pub fn get_pending(id: &str) -> Option<PendingAction> {
    STORE.lock().unwrap().get(id)
}

pub fn create_pending(req: CreatePendingRequest) -> PendingAction {
    STORE.lock().unwrap().create(PendingAction {
        id: String::new(),
        kind: req.kind.unwrap_or(PendingKind::Script),
        summary: req.summary,
        detail_ref: req.detail_ref,
        agent: req.agent,
        callback: req.callback,
        risk: req.risk,
        created_at: Utc::now(),
        expires_at: req.ttl_secs.map(|s| Utc::now() + chrono::Duration::seconds(s)),
        state: PendingState::Pending,
        decision_note: None,
        decided_by: None,
        decided_at: None,
        wa_message_id: req.wa_message_id,
    })
}

pub fn resolve_pending(id: &str, decision: &str, note: Option<String>, via: &str) -> Result<PendingAction, String> {
    let state = match decision {
        "approve" | "approved" | "yes" => PendingState::Approved,
        "reject" | "rejected" | "no" => PendingState::Rejected,
        "cancel" | "cancelled" => PendingState::Cancelled,
        other => return Err(format!("unknown decision {other:?}; use approve|reject|cancel")),
    };
    STORE.lock().unwrap().resolve(id, state, note, via)
}

pub fn snooze_pending(id: &str, secs: i64) -> Result<PendingAction, String> {
    STORE.lock().unwrap().snooze(id, secs)
}

#[derive(Debug, Deserialize)]
pub struct CreatePendingRequest {
    pub summary: String,
    #[serde(default)]
    pub kind: Option<PendingKind>,
    #[serde(default)]
    pub detail_ref: Option<String>,
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub callback: Option<String>,
    #[serde(default)]
    pub risk: Option<String>,
    #[serde(default)]
    pub ttl_secs: Option<i64>,
    #[serde(default)]
    pub wa_message_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResolvePendingRequest {
    pub decision: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub via: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SnoozePendingRequest {
    pub secs: i64,
}
