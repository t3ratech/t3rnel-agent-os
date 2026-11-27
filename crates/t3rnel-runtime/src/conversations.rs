//! Conversation service (`docs/sections/18 §2, §5.3, §6`).
//!
//! Four cooperating parts behind one service:
//!
//! - **Inbound router** — every [`ChannelAdapter`](crate::channels) normalizes
//!   platform traffic into [`ConversationEvent`]s; [`ConversationService::
//!   handle_inbound`] resolves each event to a pending approval binding, an
//!   agent thread, or an unbound thread.
//! - **Approval binding** — a kernel/plugin approval ask is *delivered* to a
//!   conversation; the reply (YES/NO/DEFER) is matched to the binding,
//!   re-validated against policy at decision time, applied single-use, and
//!   audited on the Merkle chain. Channel words alone never decide anything.
//! - **Notification fan-out** — kernel/plugin events fan out to every linked
//!   channel account with per-channel templates, quiet hours and rate limits.
//! - **Threads** — per-(channel, account, counterpart) conversation records
//!   persisted under `<home>/conversations/`.
//!
//! Inbound message text is tainted `untrusted` + channel provenance (§6); it
//! can inform drafts but can never justify a risky action without a fresh
//! approval — approval replies are the ONLY text this service acts on, and
//! they still pass policy re-validation.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Local, NaiveTime, Utc};
use serde::{Deserialize, Serialize};

use crate::audit::{AuditAction, AuditLog};
use crate::channels::{AttachmentRef, ChannelRegistry, OutboundMessage};

// ---------------------------------------------------------------------------
// Inbound events
// ---------------------------------------------------------------------------

/// Where inbound content came from and how much it can be trusted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    /// e.g. "channel:whatsapp", "channel:telegram", "route:/api/x".
    pub source: String,
    /// Always true for anything arriving over a channel (§6 taint rule).
    pub untrusted: bool,
    /// Data classes the content carries (closed set per 05 §14.10).
    #[serde(default)]
    pub data_classes: BTreeSet<String>,
}

/// The normalized inbound message every adapter produces (§2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationEvent {
    /// Channel adapter id, e.g. "whatsapp", "telegram", "local:web".
    pub channel: String,
    /// Linked account the message arrived on.
    pub account: String,
    /// Channel-side sender id (phone, user id, email, ...).
    pub sender: String,
    /// Channel thread/conversation key; equals `sender` for DMs.
    pub thread_key: String,
    /// Channel-native message id for dedup/audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// Message text (bounded by the adapter).
    pub text: String,
    #[serde(default)]
    pub attachments: Vec<AttachmentRef>,
    pub timestamp: DateTime<Utc>,
    pub provenance: Provenance,
}

impl ConversationEvent {
    /// Stable identity of the conversation this event belongs to.
    pub fn conversation_key(&self) -> String {
        format!("{}|{}|{}", self.channel, self.account, self.thread_key)
    }
}

// ---------------------------------------------------------------------------
// Approval port — the seam to the kernel/pending-action backend
// ---------------------------------------------------------------------------

/// What the approval backend knows about one ask.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSnapshot {
    pub id: String,
    pub capability: String,
    pub summary: String,
    /// "low" | "medium" | "high" | "critical" | plugin RiskClass name.
    pub risk: String,
    /// "pending" | "approved" | "denied" | "expired" | "cancelled"
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// The verdict a human reply maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalVerdict {
    Approve,
    Deny,
    /// "Remind me later" — extends the binding without deciding.
    Defer,
}

/// Backend seam: the kernel approval manager, the pending-actions ledger,
/// or (for plugin-originated asks) a register-then-decide store. The
/// conversation service never trusts the channel's word — every decision
/// goes through [`ApprovalPort::revalidate`] then [`ApprovalPort::decide`].
#[async_trait]
pub trait ApprovalPort: Send + Sync {
    /// Look up one approval by backend id.
    async fn lookup(&self, approval_ref: &str) -> Result<Option<ApprovalSnapshot>, String>;

    /// All currently pending approvals (briefing core-data + listing).
    async fn pending(&self) -> Result<Vec<ApprovalSnapshot>, String>;

    /// Register a NEW ask and return its backend id. Used when a plugin or
    /// briefing action needs a real approval record to bind to. Implementors
    /// that cannot register return an error and the binding falls back to
    /// self-contained mode.
    async fn register(&self, _request: &NewApprovalRequest) -> Result<String, String> {
        Err("approval registration unsupported".to_string())
    }

    /// Apply a decision. Implementations MUST enforce single-use and expiry
    /// themselves — the conversation layer checks first for clear errors but
    /// the backend is the authority.
    async fn decide(
        &self,
        approval_ref: &str,
        verdict: ApprovalVerdict,
        note: Option<String>,
        via: &str,
    ) -> Result<(), String>;

    /// Policy re-validation at decision time (§2): re-check that the ask is
    /// still pending, unexpired, and still requires a human decision under
    /// CURRENT policy — a YES sent yesterday approves nothing today.
    fn revalidate(&self, binding: &ApprovalBinding) -> Result<(), String>;
}

/// What a caller asks the backend to register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewApprovalRequest {
    pub capability: String,
    pub summary: String,
    pub risk: String,
    pub detail_ref: Option<String>,
    pub agent: Option<String>,
    /// Seconds until the ask expires.
    pub ttl_secs: Option<i64>,
}

// ---------------------------------------------------------------------------
// Bindings, threads, routing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingState {
    Pending,
    Approved,
    Denied,
    /// Deferred once or more; still pending with extended expiry.
    Deferred,
    Expired,
    Cancelled,
}

/// A delivered approval ask bound to one conversation. Single-use: once
/// decided it can never be decided again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalBinding {
    /// "AB-<seq>" — stable, shown to the user in the prompt.
    pub id: String,
    /// The backend approval id this binding decides.
    pub approval_ref: String,
    pub capability: String,
    pub summary: String,
    pub risk: String,
    pub channel: String,
    pub account: String,
    pub sender: String,
    pub thread_key: String,
    pub state: BindingState,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_note: Option<String>,
    /// Capability+risk fingerprint captured at request time; re-validated
    /// against the live backend record at decision time.
    pub policy_fingerprint: String,
    /// How many times the ask was deferred.
    #[serde(default)]
    pub defer_count: u32,
}

impl ApprovalBinding {
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        matches!(self.state, BindingState::Pending | BindingState::Deferred)
            && self.expires_at > now
    }
}

/// A conversation thread record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadRecord {
    /// "<channel>|<account>|<thread_key>"
    pub id: String,
    pub channel: String,
    pub account: String,
    pub counterpart: String,
    /// Agent this thread routes to, when bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Currently bound approval (at most one live binding per thread is
    /// enforced by routing preference, though several may exist).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_approval: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_inbound_at: Option<DateTime<Utc>>,
    pub last_outbound_at: Option<DateTime<Utc>>,
    pub inbound_count: u64,
}

/// What the router decided an inbound event means.
#[derive(Debug, Clone)]
pub enum RoutedInbound {
    /// The text decided a pending approval binding.
    ApprovalDecided {
        binding_id: String,
        verdict: ApprovalVerdict,
    },
    /// Routed to an agent-bound thread (or awaiting agent binding).
    AgentMessage {
        thread_id: String,
        agent_id: Option<String>,
        event: ConversationEvent,
    },
    /// No approval matched and no agent is bound — stored for later.
    Unbound {
        thread_id: String,
        event: ConversationEvent,
    },
    /// Dropped by rate limiting.
    RateLimited,
}

#[derive(Debug, thiserror::Error)]
pub enum ConversationError {
    #[error("unknown binding {0}")]
    UnknownBinding(String),
    #[error("binding {0} already resolved ({1:?})")]
    AlreadyResolved(String, BindingState),
    #[error("binding {0} expired at {1}")]
    Expired(String, DateTime<Utc>),
    #[error("policy re-validation failed for {0}: {1}")]
    Policy(String, String),
    #[error("backend decision failed for {0}: {1}")]
    Backend(String, String),
    /// The approval backend could not record the ask, so nothing was sent: a
    /// prompt whose YES decides nothing would make the person think they had
    /// authorised something they had not.
    #[error("the approval could not be registered, so no prompt was sent: {0}")]
    NotRegistered(String),
    #[error("no adapter for channel {0}")]
    NoChannel(String),
    #[error("send failed on {0}: {1}")]
    Send(String, String),
    #[error("rate limited: too many inbound events")]
    RateLimited,
    #[error("io error: {0}")]
    Io(String),
}

#[async_trait]
impl crate::plugin_grpc::ConversationsPort for ConversationService {
    async fn send(
        &self,
        channel: &str,
        account: &str,
        thread_key: &str,
        text: &str,
    ) -> Result<String, String> {
        self.send_message(channel, account, thread_key, text)
            .await
            .map(|r| r.message_id.unwrap_or_else(|| r.accepted_at.to_rfc3339()))
            .map_err(|e| e.to_string())
    }

    fn counters(&self) -> crate::plugin_grpc::ConversationCounters {
        let since = Utc::now() - chrono::Duration::hours(24);
        let threads = self.threads();
        let pending = self
            .bindings()
            .iter()
            .filter(|b| matches!(b.state, BindingState::Pending | BindingState::Deferred))
            .count() as u64;
        crate::plugin_grpc::ConversationCounters {
            threads_total: threads.len() as u64,
            // A thread is unread when the last thing in it was inbound.
            unread_threads: threads
                .iter()
                .filter(|t| match (t.last_inbound_at, t.last_outbound_at) {
                    (Some(i), Some(o)) => i > o,
                    (Some(_), None) => true,
                    _ => false,
                })
                .count() as u64,
            inbound_today: threads
                .iter()
                .filter(|t| t.last_inbound_at.is_some_and(|i| i > since))
                .count() as u64,
            outbound_today: threads
                .iter()
                .filter(|t| t.last_outbound_at.is_some_and(|o| o > since))
                .count() as u64,
            pending_approvals: pending,
        }
    }
}

// ---------------------------------------------------------------------------
// Notification fan-out configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuietHours {
    /// Local-time window, "HH:MM". May wrap midnight (22:00→07:00).
    pub start: String,
    pub end: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyConfig {
    /// During quiet hours only `action-required` notifications are delivered;
    /// the rest are deferred and flushed on the next non-quiet notify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quiet_hours: Option<QuietHours>,
    /// Max notifications per linked account per hour (0 = unlimited).
    #[serde(default = "default_notify_rate")]
    pub per_account_per_hour: usize,
    /// Per-channel text templates; placeholders {title} {body} {link}.
    /// Channels without an entry use `default_template`.
    #[serde(default)]
    pub templates: BTreeMap<String, String>,
    #[serde(default = "default_template")]
    pub default_template: String,
}

fn default_notify_rate() -> usize {
    30
}
fn default_template() -> String {
    "{title}\n{body}{link}".to_string()
}

impl Default for NotifyConfig {
    fn default() -> Self {
        NotifyConfig {
            quiet_hours: None,
            per_account_per_hour: default_notify_rate(),
            templates: BTreeMap::new(),
            default_template: default_template(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotifyLevel {
    Info,
    Warning,
    /// Approval-needed and other asks — never suppressed by quiet hours.
    ActionRequired,
}

/// A fan-out notification from kernel/plugin events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub level: NotifyLevel,
    pub title: String,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    /// Optional correlation id for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeferredNotification {
    notification: Notification,
    account: LinkedTarget,
    deferred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LinkedTarget {
    channel: String,
    account: String,
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
struct ThreadsFile {
    threads: Vec<ThreadRecord>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct BindingsFile {
    next_seq: u64,
    bindings: Vec<ApprovalBinding>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct DeferredFile {
    deferred: Vec<DeferredNotification>,
}

// ---------------------------------------------------------------------------
// The service
// ---------------------------------------------------------------------------

pub struct ConversationService {
    home: PathBuf,
    registry: Arc<ChannelRegistry>,
    approvals: Arc<dyn ApprovalPort>,
    threads: Mutex<BTreeMap<String, ThreadRecord>>,
    bindings: Mutex<BTreeMap<String, ApprovalBinding>>,
    binding_seq: Mutex<u64>,
    audit: Option<Arc<AuditLog>>,
    notify_cfg: Mutex<NotifyConfig>,
    /// Inbound rate limit: (channel,account,sender) → recent event instants.
    inbound_rate: Mutex<BTreeMap<(String, String, String), VecDeque<Instant>>>,
    /// Outbound notify rate limit: (channel,account) → recent send instants.
    notify_rate: Mutex<BTreeMap<(String, String), VecDeque<Instant>>>,
    deferred: Mutex<Vec<DeferredNotification>>,
    /// Bindings being decided right now. A decision awaits the approval backend, so
    /// without this two near-simultaneous replies could both pass the "still pending"
    /// check and both be applied.
    deciding: Mutex<HashSet<String>>,
}

/// Inbound events allowed per sender per minute before dropping.
const INBOUND_PER_SENDER_PER_MIN: usize = 60;
/// Default approval-binding lifetime.
const DEFAULT_BINDING_TTL: Duration = Duration::from_secs(24 * 3600);
/// Defer extends a binding by this much (bounded).
const DEFER_EXTENSION: Duration = Duration::from_secs(3600);
const MAX_DEFER_COUNT: u32 = 5;

impl ConversationService {
    /// Open (or create) the conversation store under `home`. `registry` is
    /// the shared channel registry; `approvals` is the backend port.
    pub fn open(
        home: &Path,
        registry: Arc<ChannelRegistry>,
        approvals: Arc<dyn ApprovalPort>,
    ) -> std::io::Result<Self> {
        let dir = home.join("conversations");
        std::fs::create_dir_all(&dir)?;

        let mut threads = BTreeMap::new();
        let threads_path = dir.join("threads.json");
        if let Ok(text) = std::fs::read_to_string(&threads_path) {
            if let Ok(file) = serde_json::from_str::<ThreadsFile>(&text) {
                for t in file.threads {
                    threads.insert(t.id.clone(), t);
                }
            }
        }

        let mut bindings = BTreeMap::new();
        let mut next_seq = 1u64;
        let bindings_path = dir.join("bindings.json");
        if let Ok(text) = std::fs::read_to_string(&bindings_path) {
            if let Ok(file) = serde_json::from_str::<BindingsFile>(&text) {
                next_seq = file.next_seq.max(1);
                for b in file.bindings {
                    bindings.insert(b.id.clone(), b);
                }
            }
        }

        let deferred_path = dir.join("deferred.json");
        let mut deferred = Vec::new();
        if let Ok(text) = std::fs::read_to_string(&deferred_path) {
            if let Ok(file) = serde_json::from_str::<DeferredFile>(&text) {
                deferred = file.deferred;
            }
        }

        Ok(ConversationService {
            home: home.to_path_buf(),
            registry,
            approvals,
            threads: Mutex::new(threads),
            bindings: Mutex::new(bindings),
            binding_seq: Mutex::new(next_seq),
            audit: None,
            notify_cfg: Mutex::new(NotifyConfig::default()),
            inbound_rate: Mutex::new(BTreeMap::new()),
            notify_rate: Mutex::new(BTreeMap::new()),
            deferred: Mutex::new(deferred),
            deciding: Mutex::new(HashSet::new()),
        })
    }

    /// Attach the Merkle audit chain — every delivery, reply-binding and
    /// approval decision lands on it (§6).
    pub fn set_audit_log(&mut self, audit: Arc<AuditLog>) {
        self.audit = Some(audit);
    }

    pub fn set_notify_config(&self, cfg: NotifyConfig) {
        *self.notify_cfg.lock().unwrap() = cfg;
    }

    /// Shared channel registry (adapters + linked accounts).
    pub fn registry(&self) -> &Arc<ChannelRegistry> {
        &self.registry
    }

    pub fn notify_config(&self) -> NotifyConfig {
        self.notify_cfg.lock().unwrap().clone()
    }

    fn audit(&self, agent: &str, detail: &str, outcome: &str) {
        if let Some(log) = &self.audit {
            log.record(agent, AuditAction::Conversation, detail, outcome);
        }
    }

    // -- persistence -------------------------------------------------------

    fn save_threads(&self) -> std::io::Result<()> {
        let dir = self.home.join("conversations");
        let file = ThreadsFile {
            threads: self.threads.lock().unwrap().values().cloned().collect(),
        };
        let tmp = dir.join("threads.json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&file)?)?;
        std::fs::rename(&tmp, dir.join("threads.json"))?;
        Ok(())
    }

    fn save_bindings(&self) -> std::io::Result<()> {
        let dir = self.home.join("conversations");
        let file = BindingsFile {
            next_seq: *self.binding_seq.lock().unwrap(),
            bindings: self.bindings.lock().unwrap().values().cloned().collect(),
        };
        let tmp = dir.join("bindings.json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&file)?)?;
        std::fs::rename(&tmp, dir.join("bindings.json"))?;
        Ok(())
    }

    fn save_deferred(&self) -> std::io::Result<()> {
        let dir = self.home.join("conversations");
        let file = DeferredFile {
            deferred: self.deferred.lock().unwrap().clone(),
        };
        let tmp = dir.join("deferred.json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&file)?)?;
        std::fs::rename(&tmp, dir.join("deferred.json"))?;
        Ok(())
    }

    // -- rate limiting ------------------------------------------------------

    fn inbound_allowed(&self, event: &ConversationEvent) -> bool {
        let key = (
            event.channel.clone(),
            event.account.clone(),
            event.sender.clone(),
        );
        let mut map = self.inbound_rate.lock().unwrap();
        let window = map.entry(key).or_default();
        let cutoff = Instant::now() - Duration::from_secs(60);
        while window.front().map(|t| *t < cutoff).unwrap_or(false) {
            window.pop_front();
        }
        if window.len() >= INBOUND_PER_SENDER_PER_MIN {
            return false;
        }
        window.push_back(Instant::now());
        true
    }

    fn notify_allowed(&self, channel: &str, account: &str) -> bool {
        let cfg = self.notify_config();
        if cfg.per_account_per_hour == 0 {
            return true;
        }
        let key = (channel.to_string(), account.to_string());
        let mut map = self.notify_rate.lock().unwrap();
        let window = map.entry(key).or_default();
        let cutoff = Instant::now() - Duration::from_secs(3600);
        while window.front().map(|t| *t < cutoff).unwrap_or(false) {
            window.pop_front();
        }
        if window.len() >= cfg.per_account_per_hour {
            return false;
        }
        window.push_back(Instant::now());
        true
    }

    // -- quiet hours ---------------------------------------------------------

    fn in_quiet_hours(&self) -> bool {
        let cfg = self.notify_config();
        let Some(q) = &cfg.quiet_hours else {
            return false;
        };
        let (Ok(start), Ok(end)) = (
            NaiveTime::parse_from_str(&q.start, "%H:%M"),
            NaiveTime::parse_from_str(&q.end, "%H:%M"),
        ) else {
            return false;
        };
        let now = Local::now().time();
        if start <= end {
            now >= start && now < end
        } else {
            // Wraps midnight.
            now >= start || now < end
        }
    }

    // -- threads -------------------------------------------------------------

    fn thread_id(channel: &str, account: &str, thread_key: &str) -> String {
        format!("{channel}|{account}|{thread_key}")
    }

    fn upsert_thread(&self, event: &ConversationEvent) -> ThreadRecord {
        let id = Self::thread_id(&event.channel, &event.account, &event.thread_key);
        let mut threads = self.threads.lock().unwrap();
        let thread = threads.entry(id.clone()).or_insert_with(|| ThreadRecord {
            id: id.clone(),
            channel: event.channel.clone(),
            account: event.account.clone(),
            counterpart: event.sender.clone(),
            agent_id: None,
            bound_approval: None,
            created_at: Utc::now(),
            last_inbound_at: None,
            last_outbound_at: None,
            inbound_count: 0,
        });
        thread.last_inbound_at = Some(event.timestamp);
        thread.inbound_count += 1;
        thread.clone()
    }

    /// List all threads (for the API/dashboard).
    pub fn threads(&self) -> Vec<ThreadRecord> {
        self.threads.lock().unwrap().values().cloned().collect()
    }

    pub fn thread(&self, id: &str) -> Option<ThreadRecord> {
        self.threads.lock().unwrap().get(id).cloned()
    }

    /// Bind (or rebind) an agent to a thread. `thread_key` may be a full
    /// thread id or a bare counterpart id resolved within channel+account.
    pub fn bind_agent(
        &self,
        channel: &str,
        account: &str,
        thread_key: &str,
        agent_id: &str,
    ) -> Result<ThreadRecord, ConversationError> {
        let id = Self::thread_id(channel, account, thread_key);
        let mut threads = self.threads.lock().unwrap();
        let thread = threads
            .get_mut(&id)
            .ok_or_else(|| ConversationError::UnknownBinding(id.clone()))?;
        thread.agent_id = Some(agent_id.to_string());
        let out = thread.clone();
        drop(threads);
        let _ = self.save_threads();
        self.audit(
            "conversations",
            &format!("thread.bind_agent {id} -> {agent_id}"),
            "ok",
        );
        Ok(out)
    }

    /// Send an outbound message on behalf of an agent/plugin. Routes through
    /// the channel registry; the *what* is the caller's, the *how* (transport
    /// + credentials) is the conversation service's (§2 outbound).
    pub async fn send_message(
        &self,
        channel: &str,
        account: &str,
        thread_key: &str,
        text: &str,
    ) -> Result<crate::channels::Receipt, ConversationError> {
        let msg = OutboundMessage {
            account: account.to_string(),
            thread_key: thread_key.to_string(),
            text: text.to_string(),
            attachments: vec![],
            metadata: BTreeMap::new(),
        };
        let receipt = self
            .registry
            .send(channel, &msg)
            .await
            .map_err(|e| ConversationError::Send(channel.to_string(), e.to_string()))?;
        let id = Self::thread_id(channel, account, thread_key);
        if let Some(thread) = self.threads.lock().unwrap().get_mut(&id) {
            thread.last_outbound_at = Some(Utc::now());
        }
        let _ = self.save_threads();
        self.audit(
            "conversations",
            &format!("message.send {id}"),
            &format!("receipt={:?}", receipt.message_id),
        );
        Ok(receipt)
    }

    // -- inbound routing -----------------------------------------------------

    /// Parse an approval reply out of message text. Returns the verdict and
    /// an optional explicit binding id ("YES AB-000003", "NO P-12").
    pub fn parse_reply(text: &str) -> Option<(ApprovalVerdict, Option<String>)> {
        let upper = text.trim().to_ascii_uppercase();
        let mut parts = upper.split_whitespace();
        let first = parts.next()?;
        let rest = parts.next().map(|s| {
            s.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                .to_string()
        });
        // A reply is the verdict word, optionally followed by one approval id: nothing else.
        // "yes but only if..." or "ok thanks" is conversation, not consent; and a bare
        // "ok" is far too common a word to authorise a payment.
        if parts.next().is_some() {
            return None;
        }
        let verdict = match first.trim_matches(|c: char| !c.is_ascii_alphanumeric()) {
            "YES" | "Y" | "APPROVE" | "APPROVED" | "CONFIRM" => ApprovalVerdict::Approve,
            "NO" | "N" | "DENY" | "DENIED" | "REJECT" | "REJECTED" | "DECLINE" => {
                ApprovalVerdict::Deny
            }
            "DEFER" | "LATER" | "SNOOZE" | "REMIND" => ApprovalVerdict::Defer,
            _ => return None,
        };
        Some((verdict, rest.filter(|r| !r.is_empty())))
    }

    /// Route one inbound event. This is THE entry point every adapter feeds.
    pub async fn handle_inbound(
        &self,
        event: ConversationEvent,
    ) -> Result<RoutedInbound, ConversationError> {
        if !self.inbound_allowed(&event) {
            self.audit(
                "conversations",
                &format!("inbound.rate_limited {}", event.conversation_key()),
                "denied",
            );
            return Ok(RoutedInbound::RateLimited);
        }

        // 1. Approval replies take precedence — a YES/NO/DEFER in a thread
        //    with a live binding decides it; an explicit id decides that one.
        if let Some((verdict, explicit_id)) = Self::parse_reply(&event.text) {
            if let Some(binding_id) = self.resolve_reply_target(&event, explicit_id.as_deref()) {
                match self
                    .resolve_binding(&binding_id, verdict, &reply_via(&event), None)
                    .await
                {
                    Ok(()) => {
                        return Ok(RoutedInbound::ApprovalDecided {
                            binding_id,
                            verdict,
                        })
                    }
                    // Expired/unknown bindings fall through to normal routing
                    // so the message still reaches the agent.
                    Err(ConversationError::Expired(..) | ConversationError::UnknownBinding(_)) => {}
                    Err(e) => return Err(e),
                }
            }
        }

        // 2. Thread → agent routing.
        let thread = self.upsert_thread(&event);
        let _ = self.save_threads();
        Ok(RoutedInbound::AgentMessage {
            thread_id: thread.id.clone(),
            agent_id: thread.agent_id.clone(),
            event,
        })
    }

    /// Find which live binding a reply targets: explicit id in text first,
    /// then the thread's bound approval, then a unique sender match.
    fn resolve_reply_target(
        &self,
        event: &ConversationEvent,
        explicit_id: Option<&str>,
    ) -> Option<String> {
        let now = Utc::now();
        let bindings = self.bindings.lock().unwrap();
        if let Some(id) = explicit_id {
            // Accept "AB-3", "ab-000003"-ish and backend refs like "P-12".
            let want = id.to_ascii_uppercase();
            if let Some(b) = bindings.get(&want).or_else(|| {
                bindings
                    .values()
                    .find(|b| b.approval_ref.eq_ignore_ascii_case(id))
            }) {
                if b.is_live(now)
                    && b.channel == event.channel
                    && b.account == event.account
                    && b.sender == event.sender
                {
                    return Some(b.id.clone());
                }
            }
            return None;
        }
        // Thread-bound approval first.
        let thread_id = Self::thread_id(&event.channel, &event.account, &event.thread_key);
        if let Some(bound) = self
            .threads
            .lock()
            .unwrap()
            .get(&thread_id)
            .and_then(|t| t.bound_approval.clone())
        {
            if let Some(b) = bindings.get(&bound) {
                // The thread can be a group: only the person the ask was sent to may answer it.
                if b.is_live(now) && b.sender == event.sender {
                    return Some(b.id.clone());
                }
            }
        }
        // Unique live binding for this sender on this channel/account.
        let matches: Vec<&ApprovalBinding> = bindings
            .values()
            .filter(|b| {
                b.is_live(now)
                    && b.channel == event.channel
                    && b.account == event.account
                    && b.sender == event.sender
            })
            .collect();
        if matches.len() == 1 {
            return Some(matches[0].id.clone());
        }
        None
    }

    // -- approval delivery + decision ----------------------------------------

    /// Deliver an approval ask to a conversation. Creates the binding,
    /// attempts backend registration when no `approval_ref` is supplied,
    /// sends the prompt, and audits. Returns the binding.
    #[allow(clippy::too_many_arguments)] // mirrors the delivery request shape
    pub async fn deliver_approval(
        &self,
        channel: &str,
        account: &str,
        sender: &str,
        thread_key: &str,
        capability: &str,
        summary: &str,
        risk: &str,
        approval_ref: Option<String>,
        ttl: Option<Duration>,
    ) -> Result<ApprovalBinding, ConversationError> {
        // Resolve or register the backend record. If it cannot be registered the
        // ask fails here, before anything is sent: every approval a person is
        // asked for must be one the backend will actually act on.
        let approval_ref = match approval_ref {
            Some(r) => r,
            None => self
                .approvals
                .register(&NewApprovalRequest {
                    capability: capability.to_string(),
                    summary: summary.to_string(),
                    risk: risk.to_string(),
                    detail_ref: None,
                    agent: None,
                    ttl_secs: ttl.map(|d| d.as_secs() as i64),
                })
                .await
                .map_err(|e| {
                    self.audit(
                        "conversations",
                        &format!("approval.register_failed cap={capability}"),
                        &format!("refused: {e}"),
                    );
                    ConversationError::NotRegistered(e)
                })?,
        };

        let id = {
            let mut seq = self.binding_seq.lock().unwrap();
            *seq += 1;
            format!("AB-{:06}", *seq)
        };
        let ttl = ttl.unwrap_or(DEFAULT_BINDING_TTL);
        let binding = ApprovalBinding {
            id: id.clone(),
            approval_ref,
            capability: capability.to_string(),
            summary: summary.to_string(),
            risk: risk.to_string(),
            channel: channel.to_string(),
            account: account.to_string(),
            sender: sender.to_string(),
            thread_key: thread_key.to_string(),
            state: BindingState::Pending,
            created_at: Utc::now(),
            expires_at: Utc::now()
                + chrono::Duration::from_std(ttl).unwrap_or_else(|_| {
                    chrono::Duration::seconds(DEFAULT_BINDING_TTL.as_secs() as i64)
                }),
            decided_at: None,
            decided_by: None,
            decision_note: None,
            policy_fingerprint: format!("{capability}|{risk}"),
            defer_count: 0,
        };

        self.bindings
            .lock()
            .unwrap()
            .insert(id.clone(), binding.clone());
        // Point the thread at this binding for reply routing.
        {
            let tid = Self::thread_id(channel, account, thread_key);
            if let Some(t) = self.threads.lock().unwrap().get_mut(&tid) {
                t.bound_approval = Some(id.clone());
            }
        }
        let _ = self.save_bindings();
        let _ = self.save_threads();

        // Deliver the prompt through the normal outbound path.
        let prompt = format!(
            "Approval needed [{id}] ({}): {}\nReply YES to approve, NO to deny, DEFER to snooze. Expires {}.",
            risk.to_ascii_uppercase(),
            summary,
            binding.expires_at.format("%Y-%m-%d %H:%M UTC"),
        );
        self.send_message(channel, account, thread_key, &prompt)
            .await?;
        self.audit(
            "conversations",
            &format!(
                "approval.deliver {id} ref={} cap={capability}",
                binding.approval_ref
            ),
            "ok",
        );
        Ok(binding)
    }

    /// Apply a verdict to a binding. Order of checks (§2/§6):
    /// exists → live → single-use → policy re-validation → backend decide →
    /// record + audit. A YES from yesterday decides nothing.
    pub async fn resolve_binding(
        &self,
        binding_id: &str,
        verdict: ApprovalVerdict,
        via: &str,
        note: Option<String>,
    ) -> Result<(), ConversationError> {
        let now = Utc::now();
        // One decision at a time per binding. Released on every exit path.
        struct Deciding<'a>(&'a Mutex<HashSet<String>>, String);
        impl Drop for Deciding<'_> {
            fn drop(&mut self) {
                if let Ok(mut set) = self.0.lock() {
                    set.remove(&self.1);
                }
            }
        }
        if !self.deciding.lock().unwrap().insert(binding_id.to_string()) {
            return Err(ConversationError::AlreadyResolved(
                binding_id.to_string(),
                BindingState::Pending,
            ));
        }
        let _deciding = Deciding(&self.deciding, binding_id.to_string());
        // Snapshot + liveness checks under one lock.
        {
            let bindings = self.bindings.lock().unwrap();
            let b = bindings
                .get(binding_id)
                .ok_or_else(|| ConversationError::UnknownBinding(binding_id.to_string()))?;
            if !matches!(b.state, BindingState::Pending | BindingState::Deferred) {
                return Err(ConversationError::AlreadyResolved(
                    binding_id.to_string(),
                    b.state,
                ));
            }
            if b.expires_at <= now {
                return Err(ConversationError::Expired(
                    binding_id.to_string(),
                    b.expires_at,
                ));
            }
        }

        if verdict == ApprovalVerdict::Defer {
            {
                enum DeferOutcome {
                    Deferred {
                        count: u32,
                        channel: String,
                        account: String,
                        thread_key: String,
                    },
                    LimitReached,
                }
                let outcome = {
                    let mut bindings = self.bindings.lock().unwrap();
                    let b = bindings.get_mut(binding_id).unwrap();
                    if b.defer_count >= MAX_DEFER_COUNT {
                        b.state = BindingState::Expired;
                        b.decided_at = Some(now);
                        b.decided_by = Some(via.to_string());
                        b.decision_note = Some("defer limit reached".to_string());
                        DeferOutcome::LimitReached
                    } else {
                        b.defer_count += 1;
                        // Defer keeps the binding pending with extended expiry.
                        b.expires_at = now
                            + chrono::Duration::from_std(DEFER_EXTENSION)
                                .unwrap_or_else(|_| chrono::Duration::hours(1));
                        DeferOutcome::Deferred {
                            count: b.defer_count,
                            channel: b.channel.clone(),
                            account: b.account.clone(),
                            thread_key: b.thread_key.clone(),
                        }
                    }
                };
                let _ = self.save_bindings();
                match outcome {
                    DeferOutcome::LimitReached => {
                        self.audit(
                            "conversations",
                            &format!("approval.defer_limit {binding_id}"),
                            "denied",
                        );
                        return Err(ConversationError::Policy(
                            binding_id.to_string(),
                            "defer limit reached".to_string(),
                        ));
                    }
                    DeferOutcome::Deferred {
                        count,
                        channel,
                        account,
                        thread_key,
                    } => {
                        self.audit(
                            "conversations",
                            &format!("approval.defer {binding_id} count={count}"),
                            "ok",
                        );
                        // Tell the user it was deferred.
                        let _ = self
                            .send_message(
                                &channel,
                                &account,
                                &thread_key,
                                "Deferred — I'll ask again later.",
                            )
                            .await;
                        return Ok(());
                    }
                }
            }
        }

        // Policy re-validation against CURRENT state — never trust the
        // channel's word or a stale snapshot (§2, §6).
        let binding = {
            let bindings = self.bindings.lock().unwrap();
            bindings.get(binding_id).unwrap().clone()
        };
        self.approvals
            .revalidate(&binding)
            .map_err(|e| ConversationError::Policy(binding_id.to_string(), e))?;

        // Backend decide (single-use + expiry enforced there too).
        self.approvals
            .decide(&binding.approval_ref, verdict, note.clone(), via)
            .await
            .map_err(|e| ConversationError::Backend(binding.approval_ref.clone(), e))?;

        // Record on the binding.
        {
            let mut bindings = self.bindings.lock().unwrap();
            let b = bindings.get_mut(binding_id).unwrap();
            b.state = match verdict {
                ApprovalVerdict::Approve => BindingState::Approved,
                ApprovalVerdict::Deny => BindingState::Denied,
                ApprovalVerdict::Defer => unreachable!(),
            };
            b.decided_at = Some(now);
            b.decided_by = Some(via.to_string());
            b.decision_note = note;
        }
        // Clear thread pointer if it referenced this binding.
        {
            let tid = Self::thread_id(&binding.channel, &binding.account, &binding.thread_key);
            if let Some(t) = self.threads.lock().unwrap().get_mut(&tid) {
                if t.bound_approval.as_deref() == Some(binding_id) {
                    t.bound_approval = None;
                }
            }
        }
        let _ = self.save_bindings();
        let _ = self.save_threads();
        self.audit(
            "conversations",
            &format!(
                "approval.decide {binding_id} verdict={verdict:?} via={via} ref={}",
                binding.approval_ref
            ),
            "ok",
        );
        // Confirm to the user on the same thread.
        let confirm = match verdict {
            ApprovalVerdict::Approve => format!("Approved [{binding_id}]."),
            ApprovalVerdict::Deny => format!("Denied [{binding_id}]."),
            ApprovalVerdict::Defer => unreachable!(),
        };
        let _ = self
            .send_message(
                &binding.channel,
                &binding.account,
                &binding.thread_key,
                &confirm,
            )
            .await;
        Ok(())
    }

    /// Public listing for API/dashboard.
    pub fn bindings(&self) -> Vec<ApprovalBinding> {
        self.bindings.lock().unwrap().values().cloned().collect()
    }

    pub fn binding(&self, id: &str) -> Option<ApprovalBinding> {
        self.bindings.lock().unwrap().get(id).cloned()
    }

    // -- notification fan-out -------------------------------------------------

    /// Fan a kernel/plugin event out to every linked channel account.
    /// Per-channel templates, quiet hours (action-required always passes)
    /// and per-account rate limits apply; every delivery + suppression is
    /// audited (§5.3, §6).
    pub async fn notify(&self, notification: Notification) -> Vec<(String, Result<(), String>)> {
        // Flush deferred notifications first when quiet hours have ended.
        if !self.in_quiet_hours() {
            self.flush_deferred().await;
        }

        let quiet = self.in_quiet_hours();
        let suppressed_by_quiet = quiet && notification.level != NotifyLevel::ActionRequired;
        let mut results = Vec::new();
        for account in self.registry.linked_accounts() {
            let target = LinkedTarget {
                channel: account.channel.clone(),
                account: account.account.clone(),
            };
            if suppressed_by_quiet {
                self.defer(&notification, &target);
                results.push((
                    format!("{}:{}", account.channel, account.account),
                    Err("deferred: quiet hours".to_string()),
                ));
                continue;
            }
            if !self.notify_allowed(&account.channel, &account.account) {
                self.audit(
                    "conversations",
                    &format!(
                        "notify.rate_limited {}:{}",
                        account.channel, account.account
                    ),
                    "denied",
                );
                results.push((
                    format!("{}:{}", account.channel, account.account),
                    Err("rate limited".to_string()),
                ));
                continue;
            }
            let text = self.render(&account.channel, &notification);
            let outcome = self
                .send_message(
                    &account.channel,
                    &account.account,
                    &account.account, // DM thread = account id
                    &text,
                )
                .await
                .map(|_| ())
                .map_err(|e| e.to_string());
            let label = format!("{}:{}", account.channel, account.account);
            match &outcome {
                Ok(()) => self.audit(
                    "conversations",
                    &format!(
                        "notify.deliver {label} level={:?} corr={:?}",
                        notification.level, notification.correlation_id
                    ),
                    "ok",
                ),
                Err(e) => self.audit(
                    "conversations",
                    &format!("notify.failed {label}: {e}"),
                    "error",
                ),
            }
            results.push((label, outcome));
        }
        results
    }

    fn render(&self, channel: &str, n: &Notification) -> String {
        let cfg = self.notify_config();
        let template = cfg.templates.get(channel).unwrap_or(&cfg.default_template);
        let link = n.link.clone().unwrap_or_default();
        template
            .replace("{title}", &n.title)
            .replace("{body}", &n.body)
            .replace("{link}", &link)
    }

    fn defer(&self, n: &Notification, target: &LinkedTarget) {
        {
            let mut deferred = self.deferred.lock().unwrap();
            // Coalesce: one pending copy per (account, title).
            deferred.retain(|d| {
                !(d.account.channel == target.channel
                    && d.account.account == target.account
                    && d.notification.title == n.title)
            });
            deferred.push(DeferredNotification {
                notification: n.clone(),
                account: target.clone(),
                deferred_at: Utc::now(),
            });
        }
        let _ = self.save_deferred();
    }

    /// Deliver everything deferred during quiet hours. Called automatically
    /// by `notify` when quiet hours end; also callable directly.
    pub async fn flush_deferred(&self) -> usize {
        let pending: Vec<DeferredNotification> = {
            let mut d = self.deferred.lock().unwrap();
            std::mem::take(&mut *d)
        };
        let count = pending.len();
        for d in pending {
            let text = self.render(&d.account.channel, &d.notification);
            let _ = self
                .send_message(
                    &d.account.channel,
                    &d.account.account,
                    &d.account.account,
                    &text,
                )
                .await;
            self.audit(
                "conversations",
                &format!(
                    "notify.flush {}:{} title={}",
                    d.account.channel, d.account.account, d.notification.title
                ),
                "ok",
            );
        }
        let _ = self.save_deferred();
        count
    }

    pub fn deferred_count(&self) -> usize {
        self.deferred.lock().unwrap().len()
    }
}

fn reply_via(event: &ConversationEvent) -> String {
    format!("{}:{}:{}", event.channel, event.account, event.sender)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::{ChannelAdapter, ChannelRegistry, LinkedAccount, LocalChannel};
    use crate::plugin_vault::VaultBroker;
    use zeroize::Zeroizing;

    /// In-memory approval backend for tests — stands in for the kernel
    /// pending store; exercises the same port contract.
    struct MemApprovals {
        items: Mutex<BTreeMap<String, ApprovalSnapshot>>,
        seq: Mutex<u64>,
    }

    impl MemApprovals {
        fn new() -> Self {
            MemApprovals {
                items: Mutex::new(BTreeMap::new()),
                seq: Mutex::new(0),
            }
        }
        fn add(&self, capability: &str, summary: &str) -> String {
            let mut seq = self.seq.lock().unwrap();
            *seq += 1;
            let id = format!("P-{}", *seq);
            self.items.lock().unwrap().insert(
                id.clone(),
                ApprovalSnapshot {
                    id: id.clone(),
                    capability: capability.into(),
                    summary: summary.into(),
                    risk: "high".into(),
                    state: "pending".into(),
                    expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
                },
            );
            id
        }
    }

    #[async_trait]
    impl ApprovalPort for MemApprovals {
        async fn lookup(&self, id: &str) -> Result<Option<ApprovalSnapshot>, String> {
            Ok(self.items.lock().unwrap().get(id).cloned())
        }
        async fn pending(&self) -> Result<Vec<ApprovalSnapshot>, String> {
            Ok(self
                .items
                .lock()
                .unwrap()
                .values()
                .filter(|s| s.state == "pending")
                .cloned()
                .collect())
        }
        async fn decide(
            &self,
            id: &str,
            verdict: ApprovalVerdict,
            _note: Option<String>,
            _via: &str,
        ) -> Result<(), String> {
            let mut items = self.items.lock().unwrap();
            let s = items.get_mut(id).ok_or("unknown")?;
            if s.state != "pending" {
                return Err("already resolved".into());
            }
            s.state = match verdict {
                ApprovalVerdict::Approve => "approved",
                ApprovalVerdict::Deny => "denied",
                ApprovalVerdict::Defer => "pending",
            }
            .into();
            Ok(())
        }
        fn revalidate(&self, binding: &ApprovalBinding) -> Result<(), String> {
            let items = self.items.lock().unwrap();
            match items.get(&binding.approval_ref) {
                Some(s) if s.state == "pending" => Ok(()),
                Some(_) => Err("no longer pending".into()),
                None => Err("unknown approval".into()),
            }
        }
    }

    struct Fixture {
        _home: tempfile::TempDir,
        service: Arc<ConversationService>,
        adapter: Arc<LocalChannel>,
        approvals: Arc<MemApprovals>,
    }

    fn fixture() -> Fixture {
        let home = tempfile::tempdir().unwrap();
        let mut registry = ChannelRegistry::new(home.path());
        registry.load().unwrap();
        let adapter = LocalChannel::new("web");
        registry.register_adapter(adapter.clone());
        registry
            .link_account(LinkedAccount {
                channel: adapter.id().to_string(),
                account: "web".into(),
                label: None,
                secret_names: vec![],
                linked_at: Utc::now(),
            })
            .unwrap();
        let vault = Arc::new(VaultBroker::open(
            home.path().join(t3rnel_extensions::vault::VAULT_FILE_NAME),
            false,
        ));
        vault
            .unlock_ordered(Some(Zeroizing::new([3u8; 32])))
            .unwrap();
        registry.set_vault(vault);
        let registry = Arc::new(registry);
        let approvals = Arc::new(MemApprovals::new());
        let service =
            Arc::new(ConversationService::open(home.path(), registry, approvals.clone()).unwrap());
        Fixture {
            _home: home,
            service,
            adapter,
            approvals,
        }
    }

    fn inbound(text: &str) -> ConversationEvent {
        ConversationEvent {
            channel: "local:web".into(),
            account: "web".into(),
            sender: "+1555".into(),
            thread_key: "+1555".into(),
            message_id: None,
            text: text.into(),
            attachments: vec![],
            timestamp: Utc::now(),
            provenance: Provenance {
                source: "channel:local".into(),
                untrusted: true,
                data_classes: ["personal".to_string()].into_iter().collect(),
            },
        }
    }

    #[tokio::test]
    async fn approval_lifecycle_yes_denies_single_use() {
        let f = fixture();
        f.service
            .registry()
            .connect_all()
            .await
            .into_iter()
            .for_each(|(_, r)| r.unwrap());
        let pref = f.approvals.add("trade.order.place", "place order #1234");
        let binding = f
            .service
            .deliver_approval(
                "local:web",
                "web",
                "+1555",
                "+1555",
                "trade.order.place",
                "place order #1234",
                "high",
                Some(pref.clone()),
                None,
            )
            .await
            .unwrap();
        assert_eq!(binding.state, BindingState::Pending);
        // Prompt was delivered to the local adapter.
        assert_eq!(f.adapter.outbound_len(), 1);

        // YES approves via backend.
        let routed = f.service.handle_inbound(inbound("YES")).await.unwrap();
        assert!(matches!(
            routed,
            RoutedInbound::ApprovalDecided {
                verdict: ApprovalVerdict::Approve,
                ..
            }
        ));
        assert_eq!(
            f.approvals.lookup(&pref).await.unwrap().unwrap().state,
            "approved"
        );
        assert_eq!(
            f.service.binding(&binding.id).unwrap().state,
            BindingState::Approved
        );

        // Single-use: second YES cannot decide again.
        let err = f
            .service
            .resolve_binding(&binding.id, ApprovalVerdict::Approve, "test", None)
            .await
            .unwrap_err();
        assert!(matches!(err, ConversationError::AlreadyResolved(..)));
    }

    #[tokio::test]
    async fn no_reply_denies_and_explicit_id_works() {
        let f = fixture();
        f.service
            .registry()
            .connect_all()
            .await
            .into_iter()
            .for_each(|(_, r)| r.unwrap());
        let pref = f.approvals.add("cap.x", "do x");
        let b1 = f
            .service
            .deliver_approval(
                "local:web",
                "web",
                "+1555",
                "+1555",
                "cap.x",
                "do x",
                "medium",
                Some(pref.clone()),
                None,
            )
            .await
            .unwrap();
        let b2 = f
            .service
            .deliver_approval(
                "local:web",
                "web",
                "+1555",
                "+1555",
                "cap.x",
                "do y",
                "medium",
                Some(f.approvals.add("cap.y", "do y")),
                None,
            )
            .await
            .unwrap();
        // Two live bindings for the same sender → bare YES is ambiguous,
        // explicit id decides.
        let routed = f
            .service
            .handle_inbound(inbound(&format!("NO {}", b1.id)))
            .await
            .unwrap();
        assert!(matches!(
            routed,
            RoutedInbound::ApprovalDecided {
                verdict: ApprovalVerdict::Deny,
                ..
            }
        ));
        assert_eq!(
            f.service.binding(&b1.id).unwrap().state,
            BindingState::Denied
        );
        assert_eq!(
            f.service.binding(&b2.id).unwrap().state,
            BindingState::Pending
        );
    }

    #[tokio::test]
    async fn expired_binding_refuses_decision() {
        let f = fixture();
        f.service
            .registry()
            .connect_all()
            .await
            .into_iter()
            .for_each(|(_, r)| r.unwrap());
        let pref = f.approvals.add("cap.z", "z");
        let b = f
            .service
            .deliver_approval(
                "local:web",
                "web",
                "+1555",
                "+1555",
                "cap.z",
                "z",
                "low",
                Some(pref),
                Some(Duration::from_millis(1)),
            )
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let err = f
            .service
            .resolve_binding(&b.id, ApprovalVerdict::Approve, "t", None)
            .await
            .unwrap_err();
        assert!(matches!(err, ConversationError::Expired(..)));
    }

    #[tokio::test]
    async fn defer_extends_without_deciding() {
        let f = fixture();
        f.service
            .registry()
            .connect_all()
            .await
            .into_iter()
            .for_each(|(_, r)| r.unwrap());
        let pref = f.approvals.add("cap.d", "d");
        let b = f
            .service
            .deliver_approval(
                "local:web",
                "web",
                "+1555",
                "+1555",
                "cap.d",
                "d",
                "low",
                Some(pref.clone()),
                None,
            )
            .await
            .unwrap();
        f.service
            .resolve_binding(&b.id, ApprovalVerdict::Defer, "t", None)
            .await
            .unwrap();
        let after = f.service.binding(&b.id).unwrap();
        assert_eq!(after.state, BindingState::Pending);
        assert_eq!(after.defer_count, 1);
        // Backend untouched.
        assert_eq!(
            f.approvals.lookup(&pref).await.unwrap().unwrap().state,
            "pending"
        );
    }

    #[tokio::test]
    async fn notify_fans_out_with_template_and_quiet_hours() {
        let f = fixture();
        f.service
            .registry()
            .connect_all()
            .await
            .into_iter()
            .for_each(|(_, r)| r.unwrap());
        let mut cfg = NotifyConfig::default();
        cfg.templates
            .insert("local:web".into(), "[{title}] {body}".into());
        f.service.set_notify_config(cfg);

        f.service
            .notify(Notification {
                level: NotifyLevel::Info,
                title: "Job done".into(),
                body: "bounty #1 submitted".into(),
                link: None,
                correlation_id: None,
            })
            .await;
        assert_eq!(f.adapter.outbound_len(), 1);
        let msgs = f.adapter.drain_outbound();
        assert!(msgs[0].text.contains("[Job done] bounty #1 submitted"));

        // Quiet hours: info deferred, action-required delivered.
        let now = Local::now().time();
        let start = (now - chrono::Duration::hours(1))
            .format("%H:%M")
            .to_string();
        let end = (now + chrono::Duration::hours(1))
            .format("%H:%M")
            .to_string();
        let cfg = NotifyConfig {
            quiet_hours: Some(QuietHours { start, end }),
            ..Default::default()
        };
        f.service.set_notify_config(cfg);

        f.service
            .notify(Notification {
                level: NotifyLevel::Info,
                title: "quiet info".into(),
                body: "x".into(),
                link: None,
                correlation_id: None,
            })
            .await;
        assert_eq!(f.service.deferred_count(), 1);
        f.service
            .notify(Notification {
                level: NotifyLevel::ActionRequired,
                title: "approval needed".into(),
                body: "y".into(),
                link: None,
                correlation_id: None,
            })
            .await;
        // Action-required passes even in quiet hours.
        assert_eq!(f.adapter.outbound_len(), 1);

        // Quiet hours over → flush delivers the deferred one. Clearing
        // quiet hours entirely guarantees non-quiet regardless of now.
        f.service.set_notify_config(NotifyConfig::default());
        let flushed = f.service.flush_deferred().await;
        assert_eq!(flushed, 1);
        assert_eq!(f.service.deferred_count(), 0);
    }

    #[tokio::test]
    async fn unbound_message_creates_thread_and_agent_binding_routes() {
        let f = fixture();
        f.service
            .registry()
            .connect_all()
            .await
            .into_iter()
            .for_each(|(_, r)| r.unwrap());
        let routed = f
            .service
            .handle_inbound(inbound("what is the weather"))
            .await
            .unwrap();
        let RoutedInbound::AgentMessage {
            thread_id,
            agent_id,
            ..
        } = routed
        else {
            panic!("expected agent route");
        };
        assert!(agent_id.is_none());
        f.service
            .bind_agent("local:web", "web", "+1555", "agent-weather")
            .unwrap();
        let routed = f
            .service
            .handle_inbound(inbound("and tomorrow?"))
            .await
            .unwrap();
        match routed {
            RoutedInbound::AgentMessage { agent_id, .. } => {
                assert_eq!(agent_id.as_deref(), Some("agent-weather"));
            }
            other => panic!("expected agent route, got {other:?}"),
        }
        assert!(f.service.thread(&thread_id).is_some());
    }

    #[test]
    fn reply_parser_covers_yes_no_defer_and_ids() {
        assert_eq!(
            ConversationService::parse_reply("YES"),
            Some((ApprovalVerdict::Approve, None))
        );
        assert_eq!(
            ConversationService::parse_reply("yes."),
            Some((ApprovalVerdict::Approve, None))
        );
        assert_eq!(
            ConversationService::parse_reply("no ab-000007"),
            Some((ApprovalVerdict::Deny, Some("AB-000007".into())))
        );
        assert_eq!(
            ConversationService::parse_reply("Defer"),
            Some((ApprovalVerdict::Defer, None))
        );
        assert_eq!(ConversationService::parse_reply("maybe later?"), None);
        assert_eq!(ConversationService::parse_reply(""), None);
    }

    #[test]
    fn casual_replies_are_not_consent() {
        // These all began with an approving first word and so approved a pending payment.
        for text in [
            "ok",
            "OK",
            "ok thanks",
            "yes but only if it is under $5",
            "yes please do it now",
            "sure",
            "yep",
            "approve it later maybe",
            "k",
        ] {
            assert_eq!(
                ConversationService::parse_reply(text),
                None,
                "{text:?} must not decide an approval"
            );
        }
    }

    #[tokio::test]
    async fn counters_report_unread_threads_and_pending_approvals_from_real_state() {
        use crate::plugin_grpc::ConversationsPort;
        let f = fixture();
        f.service
            .registry()
            .connect_all()
            .await
            .into_iter()
            .for_each(|(_, r)| r.unwrap());
        assert_eq!(f.service.counters(), Default::default());
        // One inbound message: one thread, unread, active today.
        f.service.handle_inbound(inbound("hello")).await.unwrap();
        let c = f.service.counters();
        assert_eq!((c.threads_total, c.unread_threads, c.inbound_today), (1, 1, 1));
        assert_eq!(c.pending_approvals, 0);
        // Replying through the port reads it: no longer unread.
        let receipt = ConversationsPort::send(&*f.service, "local:web", "web", "+1555", "hi").await.unwrap();
        assert!(!receipt.is_empty());
        let c = f.service.counters();
        assert_eq!((c.unread_threads, c.outbound_today), (0, 1));
        // A delivered approval counts as pending.
        let pref = f.approvals.add("cap.x", "do x");
        f.service
            .deliver_approval("local:web", "web", "+1555", "+1555", "cap.x", "do x", "medium", Some(pref), None)
            .await
            .unwrap();
        assert_eq!(f.service.counters().pending_approvals, 1);
    }

    #[tokio::test]
    async fn an_approval_the_backend_cannot_register_fails_loudly_and_sends_nothing() {
        let f = fixture();
        f.service
            .registry()
            .connect_all()
            .await
            .into_iter()
            .for_each(|(_, r)| r.unwrap());
        let before = f.service.bindings().len();
        // approval_ref=None asks the backend to register; MemApprovals cannot.
        let err = f
            .service
            .deliver_approval(
                "local:web",
                "web",
                "+1555",
                "+1555",
                "plugin.ask",
                "plugin wants X",
                "medium",
                None,
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ConversationError::NotRegistered(_)), "{err:?}");
        // No binding was created, so there is no YES that could decide nothing.
        assert_eq!(f.service.bindings().len(), before);
        // And no prompt went out to the person.
        assert_eq!(f.adapter.outbound_len(), 0, "no approval prompt may be sent");
    }

    #[tokio::test]
    async fn another_member_of_a_group_thread_cannot_answer_for_the_person_asked() {
        let f = fixture();
        f.service
            .registry()
            .connect_all()
            .await
            .into_iter()
            .for_each(|(_, r)| r.unwrap());
        // The owner talks in a shared thread first, so the thread exists.
        let mut hello = inbound("hello");
        hello.thread_key = "group-1".into();
        f.service.handle_inbound(hello).await.unwrap();
        let pref = f.approvals.add("pay.send", "pay 500 to supplier");
        let binding = f
            .service
            .deliver_approval(
                "local:web",
                "web",
                "+1555",
                "group-1",
                "pay.send",
                "pay 500 to supplier",
                "high",
                Some(pref.clone()),
                None,
            )
            .await
            .unwrap();
        // Someone else in the same thread says YES. Before the fix this approved the payment.
        let mut intruder = inbound("YES");
        intruder.sender = "+1999".into();
        intruder.thread_key = "group-1".into();
        let routed = f.service.handle_inbound(intruder).await.unwrap();
        assert!(
            matches!(routed, RoutedInbound::AgentMessage { .. }),
            "a non-addressee reply is ordinary chat: {routed:?}"
        );
        assert_eq!(
            f.service.binding(&binding.id).unwrap().state,
            BindingState::Pending
        );
        assert_eq!(
            f.approvals.lookup(&pref).await.unwrap().unwrap().state,
            "pending"
        );
        // The person who was asked can still answer.
        let mut owner = inbound("YES");
        owner.thread_key = "group-1".into();
        assert!(matches!(
            f.service.handle_inbound(owner).await.unwrap(),
            RoutedInbound::ApprovalDecided { .. }
        ));
    }

    #[tokio::test]
    async fn two_simultaneous_replies_decide_a_binding_once() {
        let f = fixture();
        f.service
            .registry()
            .connect_all()
            .await
            .into_iter()
            .for_each(|(_, r)| r.unwrap());
        let pref = f.approvals.add("pay.send", "pay 5");
        let binding = f
            .service
            .deliver_approval(
                "local:web",
                "web",
                "+1555",
                "+1555",
                "pay.send",
                "pay 5",
                "high",
                Some(pref),
                None,
            )
            .await
            .unwrap();
        let (a, b) = tokio::join!(
            f.service
                .resolve_binding(&binding.id, ApprovalVerdict::Approve, "reply-1", None),
            f.service
                .resolve_binding(&binding.id, ApprovalVerdict::Approve, "reply-2", None),
        );
        assert_eq!(
            [a.is_ok(), b.is_ok()].iter().filter(|ok| **ok).count(),
            1,
            "exactly one decision: {a:?} / {b:?}"
        );
        assert_eq!(
            f.service.binding(&binding.id).unwrap().state,
            BindingState::Approved
        );
    }
}
