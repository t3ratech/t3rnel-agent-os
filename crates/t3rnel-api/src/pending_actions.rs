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

/// The file a store keeps its items in, under the home it is bound to.
fn store_file(home: &std::path::Path) -> PathBuf {
    home.join("pending-actions.json")
}

/// The process-wide store. It starts unbound and in-memory: it only ever touches a file once a
/// kernel has told it which home it belongs to ([`bind_home`]). A store that opened the real
/// `~/.t3rnel` by itself let every test that raised an approval leave it in the operator's
/// live approvals, and from there in the briefing and in chat prompts.
static STORE: LazyLock<Mutex<PendingStore>> = LazyLock::new(|| Mutex::new(PendingStore::default()));

/// Bind the store to `home`: load what is saved there and keep saving there. The first binding
/// wins; later calls (a second kernel in the same process) leave it where it is.
pub fn bind_home(home: &std::path::Path) {
    STORE.lock().unwrap().bind(store_file(home));
}

impl PendingStore {
    /// Bind to `path` and load it, unless already bound.
    fn bind(&mut self, path: PathBuf) {
        if self.path.is_some() {
            return;
        }
        self.path = Some(path);
        let in_memory = std::mem::take(&mut self.items);
        self.load();
        // Items raised before binding (none in the daemon) are kept, after the saved ones.
        self.items.extend(in_memory);
        self.next_seq = self
            .items
            .iter()
            .filter_map(|i| i.id.strip_prefix("P-").and_then(|n| n.parse::<u64>().ok()))
            .max()
            .unwrap_or(self.next_seq);
    }

    /// Mark every pending item whose time has passed as expired. True when any changed.
    fn sweep_expired(&mut self) -> bool {
        let now = Utc::now();
        let mut changed = false;
        for item in &mut self.items {
            if item.state == PendingState::Pending && item.expires_at.is_some_and(|e| e <= now) {
                item.state = PendingState::Expired;
                changed = true;
            }
        }
        changed
    }

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

    /// What still waits for a decision. Callers sweep first, so nothing past its time is here.
    pub fn list(&self) -> Vec<PendingAction> {
        self.items
            .iter()
            .filter(|i| i.state == PendingState::Pending)
            .cloned()
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<PendingAction> {
        self.items
            .iter()
            .find(|i| i.id.eq_ignore_ascii_case(id))
            .cloned()
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
        if !matches!(
            decision,
            PendingState::Approved | PendingState::Rejected | PendingState::Cancelled
        ) {
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
                return Err(format!(
                    "{} is already {}",
                    item.id,
                    state_name(&item.state)
                ));
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
        Ok(self
            .items
            .iter()
            .find(|i| i.id.eq_ignore_ascii_case(id))
            .unwrap()
            .clone())
    }

    pub fn snooze(&mut self, id: &str, secs: i64) -> Result<PendingAction, String> {
        let item = self
            .items
            .iter_mut()
            .find(|i| i.id.eq_ignore_ascii_case(id))
            .ok_or_else(|| format!("no pending item {id}"))?;
        if item.state != PendingState::Pending {
            return Err(format!(
                "{} is already {}",
                item.id,
                state_name(&item.state)
            ));
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
    let mut store = STORE.lock().unwrap();
    if store.sweep_expired() {
        store.save();
    }
    store.list()
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
        expires_at: req
            .ttl_secs
            .map(|s| Utc::now() + chrono::Duration::seconds(s)),
        state: PendingState::Pending,
        decision_note: None,
        decided_by: None,
        decided_at: None,
        wa_message_id: req.wa_message_id,
    })
}

pub fn resolve_pending(
    id: &str,
    decision: &str,
    note: Option<String>,
    via: &str,
) -> Result<PendingAction, String> {
    let state = match decision {
        "approve" | "approved" | "yes" => PendingState::Approved,
        "reject" | "rejected" | "no" => PendingState::Rejected,
        "cancel" | "cancelled" => PendingState::Cancelled,
        other => {
            return Err(format!(
                "unknown decision {other:?}; use approve|reject|cancel"
            ))
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn item(summary: &str, expires_in_secs: Option<i64>) -> PendingAction {
        PendingAction {
            id: String::new(),
            kind: PendingKind::Approval,
            summary: summary.into(),
            detail_ref: None,
            agent: None,
            callback: None,
            risk: None,
            created_at: Utc::now(),
            expires_at: expires_in_secs.map(|s| Utc::now() + chrono::Duration::seconds(s)),
            state: PendingState::Pending,
            decision_note: None,
            decided_by: None,
            decided_at: None,
            wa_message_id: None,
        }
    }

    #[test]
    fn a_store_that_was_never_bound_keeps_everything_in_memory() {
        let mut store = PendingStore::default();
        store.create(item("raised by a test", Some(60)));
        assert_eq!(store.list().len(), 1);
        assert!(store.path.is_none(), "an unbound store must not know any file");
    }

    #[test]
    fn a_bound_store_saves_under_its_home_and_a_rebound_one_reads_it_back() {
        let home = tempfile::tempdir().unwrap();
        let mut a = PendingStore::default();
        a.bind(store_file(home.path()));
        let first = a.create(item("one", Some(3600)));
        let mut b = PendingStore::default();
        b.bind(store_file(home.path()));
        assert_eq!(b.list().len(), 1);
        assert_eq!(b.list()[0].summary, "one");
        // The next id continues after the saved ones.
        assert_ne!(b.create(item("two", None)).id, first.id);
    }

    #[test]
    fn the_first_home_a_store_is_bound_to_is_the_one_it_keeps() {
        let (one, two) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut store = PendingStore::default();
        store.bind(store_file(one.path()));
        store.bind(store_file(two.path()));
        store.create(item("x", None));
        assert!(store_file(one.path()).is_file());
        assert!(!store_file(two.path()).exists());
    }

    #[test]
    fn an_item_past_its_time_stops_being_listed_and_cannot_be_approved() {
        let mut store = PendingStore::default();
        let stale = store.create(item("old", Some(-5)));
        let live = store.create(item("fresh", Some(600)));
        assert!(store.sweep_expired());
        let listed: Vec<_> = store.list().into_iter().map(|i| i.id).collect();
        assert_eq!(listed, vec![live.id.clone()]);
        let err = store
            .resolve(&stale.id, PendingState::Approved, None, "test")
            .unwrap_err();
        assert!(err.contains("already expired"), "{err}");
        assert!(!store.sweep_expired(), "nothing more to sweep");
    }
}
