//! Per-plugin host services (`17-implementation-guide.md` §9.6).
//!
//! Every plugin gets isolated instances of the 14 host services, in the
//! mandated order. This module implements the services that can be real
//! without external kernels: **audit, tools, routes, schedule, events,
//! approval, memory, sentinel, ui, agents, notify** — all backed by the
//! plugin's own [`PluginStorage`] database or per-plugin in-memory state.
//! `http` is served by [`crate::plugin_host::PluginHost::http`]; `llm`
//! requires the host's model backend and is behind the [`LlmBackend`] seam
//! (callers must inject the real one — there is no built-in stand-in).
//!
//! Isolation invariants enforced here and tested:
//! - every service's state lives in the plugin's own DB/tables — two plugins
//!   never share rows;
//! - `memory` entries carry taint labels that can only widen (union), never
//!   shrink, through consolidation — the §14.9 permanence rule;
//! - `memory`/`storage` writes are checked against the manifest's declared
//!   `data_classes` — a plugin cannot launder `personal` data into
//!   `public`;
//! - `approval` gates every `external-effect`/`financial` action until the
//!   user approves: an approval names one exact action, expires, and works once;
//! - everything the host relies on (approvals, schedules, queued notifications,
//!   memory labels) lives in host-only state that no plugin-facing call can write,
//!   so a plugin cannot approve itself or relabel its own data;
//! - nothing here exposes the substrate `usage_conn`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::plugin_storage::{PluginStorage, StorageError};

// ---------------------------------------------------------------------------
// Shared small types
// ---------------------------------------------------------------------------

/// Taint/data class labels per `05-security-and-trust.md` §14.10. The closed
/// set — mirrors `bridge::manifest::DataClass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DataClass {
    Public,
    PluginPrivate,
    Personal,
    Financial,
    CredentialAdjacent,
    Unclassified,
}

impl DataClass {
    pub fn as_str(self) -> &'static str {
        match self {
            DataClass::Public => "public",
            DataClass::PluginPrivate => "plugin-private",
            DataClass::Personal => "personal",
            DataClass::Financial => "financial",
            DataClass::CredentialAdjacent => "credential-adjacent",
            DataClass::Unclassified => "unclassified",
        }
    }
}

/// Risk classes per the capability taxonomy (`04` §14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskClass {
    Read,
    WriteReversible,
    WriteIrreversible,
    ExternalEffect,
    Financial,
    System,
}

/// An entry in the plugin's labelled memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub key: String,
    pub value: String,
    /// Taint labels — union-only through consolidation (§14.9).
    pub taint: BTreeSet<DataClass>,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// Service: audit (wraps storage's append-only trail with typed events)
// ---------------------------------------------------------------------------

pub struct AuditService<'a> {
    storage: &'a PluginStorage,
}

impl<'a> AuditService<'a> {
    pub fn new(storage: &'a PluginStorage) -> Self {
        AuditService { storage }
    }
    /// Append a typed audit event. `detail` must never contain secret
    /// material — callers pass references only.
    pub fn record(&self, service: &str, action: &str, detail: &str) -> Result<(), StorageError> {
        self.storage
            .audit_append(&format!("{service}.{action}"), detail)
    }
    pub fn tail(&self, limit: usize) -> Result<Vec<(String, String, String)>, StorageError> {
        self.storage.audit_tail(limit)
    }
}

// ---------------------------------------------------------------------------
// Service: tools — registry of capabilities the plugin may invoke
// ---------------------------------------------------------------------------

/// A tool the host exposes to the plugin, gated by the manifest.
pub struct ToolRegistry {
    /// capability id (`<domain>.<verb>`) → risk class.
    allowed: BTreeMap<String, RiskClass>,
}

impl ToolRegistry {
    pub fn new(allowed: impl IntoIterator<Item = (String, RiskClass)>) -> Self {
        ToolRegistry {
            allowed: allowed.into_iter().collect(),
        }
    }
    /// Whether the plugin may invoke `capability`. High-risk classes are
    /// still allowed here — approval gating happens in the approval service.
    pub fn permits(&self, capability: &str) -> bool {
        self.allowed.contains_key(capability)
    }
    pub fn risk_of(&self, capability: &str) -> Option<RiskClass> {
        self.allowed.get(capability).copied()
    }
}

// ---------------------------------------------------------------------------
// Service: routes — plugin-registered HTTP routes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub method: String,
    pub path: String,
    /// Opaque handler id the plugin binary maps to its callback.
    pub handler: String,
}

pub struct RouteRegistry {
    routes: Mutex<Vec<RouteEntry>>,
}

impl RouteRegistry {
    pub fn new() -> Self {
        RouteRegistry {
            routes: Mutex::new(Vec::new()),
        }
    }
    pub fn register(&self, method: &str, path: &str, handler: &str) {
        self.routes.lock().unwrap().push(RouteEntry {
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
            handler: handler.to_string(),
        });
    }
    /// Exact method+path match only — plugins cannot shadow host routes.
    pub fn lookup(&self, method: &str, path: &str) -> Option<String> {
        self.routes
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.method == method.to_ascii_uppercase() && r.path == path)
            .map(|r| r.handler.clone())
    }
    pub fn len(&self) -> usize {
        self.routes.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.routes.lock().unwrap().is_empty()
    }
}
impl Default for RouteRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Service: schedule — persisted one-shot/interval jobs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledJob {
    pub id: String,
    /// Interval in seconds between fires (0 = one-shot at `fire_at`).
    pub interval_secs: u64,
    /// Earliest unix-time fire.
    pub fire_at: u64,
    /// Opaque callback id.
    pub callback: String,
    pub enabled: bool,
}

/// Schedule state persists in the plugin DB so restarts don't lose jobs.
pub struct ScheduleService<'a> {
    storage: &'a PluginStorage,
}

impl<'a> ScheduleService<'a> {
    pub fn new(storage: &'a PluginStorage) -> Self {
        ScheduleService { storage }
    }

    /// Store a job. Returns the job id.
    pub fn add(&self, job: &ScheduledJob) -> Result<(), StorageError> {
        let blob = serde_json::to_string(job)
            .map_err(|e| StorageError::MigrationFailed(0, e.to_string()))?;
        // Jobs live in plugin_kv under a namespaced key — per-plugin by
        // construction, no shared table needed.
        self.storage.state_set(&format!("schedule:{}", job.id), &blob)
    }

    pub fn remove(&self, id: &str) -> Result<(), StorageError> {
        self.storage.state_set(&format!("schedule:{}", id), "")
    }

    /// Jobs whose `fire_at` is due, as of `now`. Caller decides whether to
    /// reschedule; this is a pure read.
    pub fn due(&self, now: u64) -> Result<Vec<ScheduledJob>, StorageError> {
        // plugin_kv has no prefix scan; enumerate via audit? Simplest real
        // approach: keep an index key listing ids.
        let idx = self
            .storage
            .state_get("schedule:index")
            .unwrap_or(None)
            .unwrap_or_default();
        let mut out = Vec::new();
        for id in idx.lines().filter(|l| !l.is_empty()) {
            if let Some(blob) = self.storage.state_get(&format!("schedule:{id}"))? {
                if blob.is_empty() {
                    continue;
                }
                if let Ok(job) = serde_json::from_str::<ScheduledJob>(&blob) {
                    if job.enabled && job.fire_at <= now {
                        out.push(job);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Register id in the index (call after `add`).
    pub fn index(&self, id: &str) -> Result<(), StorageError> {
        let idx = self
            .storage
            .state_get("schedule:index")
            .unwrap_or(None)
            .unwrap_or_default();
        if idx.lines().any(|l| l == id) {
            return Ok(());
        }
        self.storage
            .state_set("schedule:index", &format!("{idx}{id}\n"))
    }
}

// ---------------------------------------------------------------------------
// Service: events — per-plugin pub/sub, in-memory (ephemeral by design)
// ---------------------------------------------------------------------------

pub struct EventBus {
    /// topic → subscriber callback ids (plugin-internal routing).
    subscribers: Mutex<BTreeMap<String, Vec<String>>>,
    /// recent events for late-join inspection (bounded).
    recent: Mutex<VecDeque<(String, String)>>,
}

impl EventBus {
    pub fn new() -> Self {
        EventBus {
            subscribers: Mutex::new(BTreeMap::new()),
            recent: Mutex::new(VecDeque::with_capacity(256)),
        }
    }
    pub fn subscribe(&self, topic: &str, subscriber: &str) {
        self.subscribers
            .lock()
            .unwrap()
            .entry(topic.to_string())
            .or_default()
            .push(subscriber.to_string());
    }
    /// Publish returns the subscriber ids that will be notified — delivery
    /// is the dispatch layer's job.
    pub fn publish(&self, topic: &str, payload_ref: &str) -> Vec<String> {
        {
            let mut recent = self.recent.lock().unwrap();
            if recent.len() >= 256 {
                recent.pop_front();
            }
            recent.push_back((topic.to_string(), payload_ref.to_string()));
        }
        self.subscribers
            .lock()
            .unwrap()
            .get(topic)
            .cloned()
            .unwrap_or_default()
    }
    pub fn subscriber_count(&self, topic: &str) -> usize {
        self.subscribers
            .lock()
            .unwrap()
            .get(topic)
            .map(|v| v.len())
            .unwrap_or(0)
    }
}
impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Service: approval — gates risky actions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub capability: String,
    pub risk: RiskClass,
    /// What the user is shown. Never trusted to identify the action: that is `action_hash`.
    pub detail: String,
    pub state: ApprovalState,
    /// SHA-256 over the capability and the exact action (its arguments), so an
    /// approval for "send this message to Alice" cannot authorise another message
    /// or another recipient.
    pub action_hash: String,
    /// Unix seconds after which the approval is void.
    pub expires_at: i64,
    /// Set when the approval has been spent. An approval works once.
    #[serde(default)]
    pub used: bool,
}

/// Longest an approval may stay valid.
pub const MAX_APPROVAL_TTL_SECS: i64 = 24 * 3600;

impl ApprovalRequest {
    /// A pending request for exactly `action` (the canonical text or JSON of the
    /// call's arguments). `ttl_secs` is clamped to [`MAX_APPROVAL_TTL_SECS`].
    pub fn new(
        id: impl Into<String>,
        capability: &str,
        risk: RiskClass,
        detail: impl Into<String>,
        action: &str,
        ttl_secs: i64,
    ) -> Self {
        ApprovalRequest {
            id: id.into(),
            capability: capability.to_string(),
            risk,
            detail: detail.into(),
            state: ApprovalState::Pending,
            action_hash: Self::hash_action(capability, action),
            expires_at: chrono::Utc::now().timestamp() + ttl_secs.clamp(1, MAX_APPROVAL_TTL_SECS),
            used: false,
        }
    }

    /// Hash of one capability call. The NUL separator keeps `("a", "bc")` and `("ab", "c")` apart.
    pub fn hash_action(capability: &str, action: &str) -> String {
        let mut h = Sha256::new();
        h.update(capability.as_bytes());
        h.update([0u8]);
        h.update(action.as_bytes());
        hex::encode(h.finalize())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
}

/// Approval queue kept in host-only state. Risky capabilities
/// (write-irreversible, external-effect, financial, system) MUST pass
/// through here before execution.
pub struct ApprovalService<'a> {
    storage: &'a PluginStorage,
}

impl<'a> ApprovalService<'a> {
    pub const GATED: &'static [RiskClass] = &[
        RiskClass::WriteIrreversible,
        RiskClass::ExternalEffect,
        RiskClass::Financial,
        RiskClass::System,
    ];

    pub fn new(storage: &'a PluginStorage) -> Self {
        ApprovalService { storage }
    }

    pub fn requires_approval(risk: RiskClass) -> bool {
        Self::GATED.contains(&risk)
    }

    fn key(id: &str) -> String {
        format!("approval:{id}")
    }

    /// File a pending request. An id that already exists is refused, so a request
    /// cannot overwrite an approved (or spent) one.
    pub fn request(&self, req: &ApprovalRequest) -> Result<(), StorageError> {
        if self.storage.state_get(&Self::key(&req.id))?.is_some() {
            return Err(StorageError::MigrationFailed(
                0,
                format!("approval {} already exists", req.id),
            ));
        }
        if req.state != ApprovalState::Pending || req.used {
            return Err(StorageError::MigrationFailed(
                0,
                "a new approval request must be pending and unused".into(),
            ));
        }
        let blob = serde_json::to_string(req)
            .map_err(|e| StorageError::MigrationFailed(0, e.to_string()))?;
        self.storage.state_set(&Self::key(&req.id), &blob)?;
        let idx = self.storage.state_get("approval:index")?.unwrap_or_default();
        if !idx.lines().any(|l| l == req.id) {
            self.storage
                .state_set("approval:index", &format!("{idx}{}\n", req.id))?;
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<Option<ApprovalRequest>, StorageError> {
        match self.storage.state_get(&Self::key(id))? {
            Some(blob) if !blob.is_empty() => serde_json::from_str(&blob)
                .map(Some)
                .map_err(|e| StorageError::MigrationFailed(0, e.to_string())),
            _ => Ok(None),
        }
    }

    /// The user's decision. Only a pending request can be decided: an approval
    /// cannot be flipped afterwards, and a spent one cannot be re-opened.
    pub fn resolve(&self, id: &str, state: ApprovalState) -> Result<(), StorageError> {
        let key = Self::key(id);
        let current = self
            .storage
            .state_get(&key)?
            .ok_or_else(|| StorageError::NotInitialized(format!("approval {id}")))?;
        let mut req: ApprovalRequest = serde_json::from_str(&current)
            .map_err(|e| StorageError::MigrationFailed(0, e.to_string()))?;
        if req.state != ApprovalState::Pending || state == ApprovalState::Pending {
            return Err(StorageError::MigrationFailed(
                0,
                format!("approval {id} is already decided"),
            ));
        }
        req.state = state;
        let next = serde_json::to_string(&req)
            .map_err(|e| StorageError::MigrationFailed(0, e.to_string()))?;
        if self.storage.state_cas(&key, &current, &next)? {
            Ok(())
        } else {
            Err(StorageError::MigrationFailed(0, format!("approval {id} changed while deciding")))
        }
    }

    /// The gate: may `capability` at `risk` run `action` now? Read and
    /// write-reversible pass. A gated call needs an approval that is approved,
    /// unexpired, unspent, and issued for exactly this capability and action. A
    /// successful check **spends** the approval, atomically: two callers racing
    /// on one approval cannot both pass.
    pub fn check(
        &self,
        capability: &str,
        risk: RiskClass,
        approval_id: Option<&str>,
        action: &str,
    ) -> Result<bool, StorageError> {
        if !Self::requires_approval(risk) {
            return Ok(true);
        }
        let Some(id) = approval_id else {
            return Ok(false);
        };
        let key = Self::key(id);
        let Some(current) = self.storage.state_get(&key)? else {
            return Ok(false);
        };
        let Ok(mut req) = serde_json::from_str::<ApprovalRequest>(&current) else {
            return Ok(false);
        };
        let valid = req.state == ApprovalState::Approved
            && !req.used
            && req.capability == capability
            && req.action_hash == ApprovalRequest::hash_action(capability, action)
            && chrono::Utc::now().timestamp() < req.expires_at;
        if !valid {
            return Ok(false);
        }
        req.used = true;
        let spent = serde_json::to_string(&req)
            .map_err(|e| StorageError::MigrationFailed(0, e.to_string()))?;
        self.storage.state_cas(&key, &current, &spent)
    }
}

// ---------------------------------------------------------------------------
// Service: memory — labelled KV with taint permanence (§14.9/§14.10)
// ---------------------------------------------------------------------------

/// Per-plugin labelled memory. Taint labels form a union semilattice:
/// consolidation can add labels, never remove them.
pub struct MemoryService<'a> {
    storage: &'a PluginStorage,
    /// Classes this plugin declared in its manifest — writes outside the
    /// declared set are rejected (data-class enforcement, §14.10).
    allowed_classes: BTreeSet<DataClass>,
}

impl<'a> MemoryService<'a> {
    pub fn new(
        storage: &'a PluginStorage,
        allowed_classes: impl IntoIterator<Item = DataClass>,
    ) -> Self {
        MemoryService {
            storage,
            allowed_classes: allowed_classes.into_iter().collect(),
        }
    }

    /// Write a memory entry. Every taint label must be in the plugin's
    /// declared data classes — otherwise the write is refused.
    pub fn set(
        &self,
        key: &str,
        value: &str,
        taint: &BTreeSet<DataClass>,
    ) -> Result<(), StorageError> {
        for class in taint {
            if !self.allowed_classes.contains(class) {
                return Err(StorageError::MigrationFailed(
                    0,
                    format!("data class {} not declared by plugin", class.as_str()),
                ));
            }
        }
        let entry = MemoryEntry {
            key: key.to_string(),
            value: value.to_string(),
            taint: taint.clone(),
            updated_at: chrono::Utc::now().to_rfc3339(),
        };
        let blob = serde_json::to_string(&entry)
            .map_err(|e| StorageError::MigrationFailed(0, e.to_string()))?;
        self.storage.state_set(&format!("mem:{key}"), &blob)
    }

    pub fn get(&self, key: &str) -> Result<Option<MemoryEntry>, StorageError> {
        match self.storage.state_get(&format!("mem:{key}"))? {
            Some(blob) if !blob.is_empty() => serde_json::from_str(&blob)
                .map(Some)
                .map_err(|e| StorageError::MigrationFailed(0, e.to_string())),
            _ => Ok(None),
        }
    }

    /// Consolidation/compaction merge: union the taint labels of `source`
    /// into `target`. Labels can only grow — this is the §14.9 permanence
    /// rule that stops taint being laundered away by summarisation.
    pub fn consolidate(&self, target: &str, sources: &[&str]) -> Result<MemoryEntry, StorageError> {
        let mut merged: BTreeSet<DataClass> = BTreeSet::new();
        let mut value = String::new();
        for src in sources {
            if let Some(entry) = self.get(src)? {
                merged.extend(entry.taint);
                if !value.is_empty() {
                    value.push('\n');
                }
                value.push_str(&entry.value);
            }
        }
        // Ensure merged labels are still within declared classes.
        for class in &merged {
            if !self.allowed_classes.contains(class) {
                return Err(StorageError::MigrationFailed(
                    0,
                    format!(
                        "consolidated taint {} exceeds declared classes",
                        class.as_str()
                    ),
                ));
            }
        }
        self.set(target, &value, &merged)?;
        self.get(target)?
            .ok_or_else(|| StorageError::NotInitialized(target.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Service: sentinel — security event sink
// ---------------------------------------------------------------------------

pub struct SentinelService<'a> {
    audit: AuditService<'a>,
}

impl<'a> SentinelService<'a> {
    pub fn new(storage: &'a PluginStorage) -> Self {
        SentinelService {
            audit: AuditService::new(storage),
        }
    }
    /// Report a security finding; severity is recorded, findings are
    /// append-only and cannot be deleted by the plugin.
    pub fn report(&self, severity: &str, finding: &str) -> Result<(), StorageError> {
        self.audit.record(
            "sentinel",
            "report",
            &format!("severity={severity} {finding}"),
        )
    }
}

// ---------------------------------------------------------------------------
// Service: ui — registered views
// ---------------------------------------------------------------------------

pub struct UiService {
    /// view name → schema/version the plugin renders.
    views: Mutex<BTreeMap<String, String>>,
}

impl UiService {
    pub fn new() -> Self {
        UiService {
            views: Mutex::new(BTreeMap::new()),
        }
    }
    pub fn register_view(&self, name: &str, schema: &str) {
        self.views
            .lock()
            .unwrap()
            .insert(name.to_string(), schema.to_string());
    }
    pub fn view(&self, name: &str) -> Option<String> {
        self.views.lock().unwrap().get(name).cloned()
    }
}
impl Default for UiService {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Service: agents — inter-agent requests (gated, audited)
// ---------------------------------------------------------------------------

pub struct AgentsService<'a> {
    audit: AuditService<'a>,
}

impl<'a> AgentsService<'a> {
    pub fn new(storage: &'a PluginStorage) -> Self {
        AgentsService {
            audit: AuditService::new(storage),
        }
    }
    /// Request another agent do something. Always audited; the actual spawn
    /// is the dispatch layer's job after capability checks.
    pub fn request(&self, target: &str, task_ref: &str) -> Result<(), StorageError> {
        self.audit.record(
            "agents",
            "request",
            &format!("target={target} task={task_ref}"),
        )
    }
}

// ---------------------------------------------------------------------------
// Service: notify — outbound notifications via host channels
// ---------------------------------------------------------------------------

/// Notifications are queued in the plugin DB; the host dispatcher delivers
/// them through configured channels (desktop, webhook). Plugins never open
/// sockets themselves.
pub struct NotifyService<'a> {
    storage: &'a PluginStorage,
}

impl<'a> NotifyService<'a> {
    pub fn new(storage: &'a PluginStorage) -> Self {
        NotifyService { storage }
    }
    pub fn enqueue(&self, channel: &str, message_ref: &str) -> Result<(), StorageError> {
        // message_ref is an opaque reference/id — bodies stay host-side.
        self.storage.state_set(
            &format!("notify:{}", uuid::Uuid::new_v4()),
            &format!("channel={channel} ref={message_ref}"),
        )?;
        self.storage.audit_append("notify.enqueue", channel)
    }
}

// ---------------------------------------------------------------------------
// LLM seam — no stand-in backend; the host injects the real one
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
pub trait LlmBackend: Send + Sync {
    async fn complete(&self, prompt_ref: &str) -> Result<String, String>;
}

pub struct LlmService<'a, B: LlmBackend> {
    backend: &'a B,
    audit: AuditService<'a>,
}

impl<'a, B: LlmBackend> LlmService<'a, B> {
    pub fn new(storage: &'a PluginStorage, backend: &'a B) -> Self {
        LlmService {
            backend,
            audit: AuditService::new(storage),
        }
    }
    /// Prompt material is passed by reference; the backend decides what it
    /// may see (data-class filtering is the backend's contract).
    pub async fn complete(&self, prompt_ref: &str) -> Result<String, String> {
        let out = self.backend.complete(prompt_ref).await;
        let _ = self.audit.record(
            "llm",
            "complete",
            &format!("ok={} ref={prompt_ref}", out.is_ok()),
        );
        out
    }
}

// ---------------------------------------------------------------------------
// Composition: all services for one plugin
// ---------------------------------------------------------------------------

/// Bundles every per-plugin service. Constructed by `PluginHost` once the
/// manifest's declared data classes/capabilities are known.
pub struct PluginServices<'a> {
    pub audit: AuditService<'a>,
    pub tools: ToolRegistry,
    pub routes: RouteRegistry,
    pub schedule: ScheduleService<'a>,
    pub events: EventBus,
    pub approval: ApprovalService<'a>,
    pub memory: MemoryService<'a>,
    pub sentinel: SentinelService<'a>,
    pub ui: UiService,
    pub agents: AgentsService<'a>,
    pub notify: NotifyService<'a>,
}

impl<'a> PluginServices<'a> {
    pub fn new(
        storage: &'a PluginStorage,
        tools: ToolRegistry,
        allowed_classes: impl IntoIterator<Item = DataClass>,
    ) -> Self {
        PluginServices {
            audit: AuditService::new(storage),
            tools,
            routes: RouteRegistry::new(),
            schedule: ScheduleService::new(storage),
            events: EventBus::new(),
            approval: ApprovalService::new(storage),
            memory: MemoryService::new(storage, allowed_classes),
            sentinel: SentinelService::new(storage),
            ui: UiService::new(),
            agents: AgentsService::new(storage),
            notify: NotifyService::new(storage),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, PluginStorage) {
        let dir = tempfile::tempdir().unwrap();
        let s = PluginStorage::open(dir.path(), "org.test.svc").unwrap();
        (dir, s)
    }

    #[test]
    fn two_plugins_have_isolated_service_state() {
        let home = tempfile::tempdir().unwrap();
        let a = PluginStorage::open(home.path(), "org.a.svc").unwrap();
        let b = PluginStorage::open(home.path(), "org.b.svc").unwrap();
        let sa = PluginServices::new(
            &a,
            ToolRegistry::new(std::iter::empty()),
            [DataClass::Public],
        );
        let sb = PluginServices::new(
            &b,
            ToolRegistry::new(std::iter::empty()),
            [DataClass::Public],
        );
        sa.memory
            .set("k", "a-value", &BTreeSet::from([DataClass::Public]))
            .unwrap();
        sb.memory
            .set("k", "b-value", &BTreeSet::from([DataClass::Public]))
            .unwrap();
        assert_eq!(sa.memory.get("k").unwrap().unwrap().value, "a-value");
        assert_eq!(sb.memory.get("k").unwrap().unwrap().value, "b-value");
        // Event buses are per-plugin too.
        sa.events.subscribe("t", "sub-a");
        assert_eq!(sa.events.subscriber_count("t"), 1);
        assert_eq!(sb.events.subscriber_count("t"), 0);
    }

    #[test]
    fn memory_taint_unions_through_consolidation_and_never_shrinks() {
        let (_d, s) = store();
        let svc = PluginServices::new(
            &s,
            ToolRegistry::new(std::iter::empty()),
            [
                DataClass::Public,
                DataClass::Unclassified,
                DataClass::Personal,
            ],
        );
        svc.memory
            .set("src1", "clean", &BTreeSet::from([DataClass::Public]))
            .unwrap();
        svc.memory
            .set(
                "src2",
                "tainted",
                &BTreeSet::from([DataClass::Unclassified, DataClass::Personal]),
            )
            .unwrap();
        let merged = svc.memory.consolidate("dst", &["src1", "src2"]).unwrap();
        // Union: public + unclassified + personal — nothing dropped.
        assert!(merged.taint.contains(&DataClass::Public));
        assert!(merged.taint.contains(&DataClass::Unclassified));
        assert!(merged.taint.contains(&DataClass::Personal));
        // Consolidating dst with itself must not lose labels either.
        let again = svc.memory.consolidate("dst2", &["dst"]).unwrap();
        assert_eq!(again.taint, merged.taint);
    }

    #[test]
    fn memory_rejects_undeclared_data_class() {
        let (_d, s) = store();
        // Plugin declared only `public` — cannot write `personal` taint.
        let svc = PluginServices::new(
            &s,
            ToolRegistry::new(std::iter::empty()),
            [DataClass::Public],
        );
        let err = svc
            .memory
            .set("k", "v", &BTreeSet::from([DataClass::Personal]))
            .unwrap_err();
        assert!(err.to_string().contains("not declared"), "{err}");
    }

    fn svc_for(s: &PluginStorage) -> PluginServices<'_> {
        PluginServices::new(s, ToolRegistry::new(std::iter::empty()), [DataClass::Public])
    }

    fn pending(id: &str, action: &str) -> ApprovalRequest {
        ApprovalRequest::new(id, "pay.send", RiskClass::Financial, "pay 5 to alice", action, 600)
    }

    #[test]
    fn approval_gates_only_high_risk_classes() {
        let (_d, s) = store();
        let svc = svc_for(&s);
        assert!(!ApprovalService::requires_approval(RiskClass::Read));
        assert!(!ApprovalService::requires_approval(RiskClass::WriteReversible));
        for gated in [RiskClass::Financial, RiskClass::ExternalEffect, RiskClass::System, RiskClass::WriteIrreversible] {
            assert!(ApprovalService::requires_approval(gated), "{gated:?}");
        }
        assert!(svc.approval.check("fs.read", RiskClass::Read, None, "").unwrap());
        assert!(!svc.approval.check("pay.send", RiskClass::Financial, None, "x").unwrap());
        assert!(!svc.approval.check("pay.send", RiskClass::Financial, Some("nope"), "x").unwrap());
    }

    #[test]
    fn an_approval_names_one_exact_action_and_works_once() {
        let (_d, s) = store();
        let svc = svc_for(&s);
        svc.approval.request(&pending("ap1", "to=alice;amount=5")).unwrap();
        // Pending is not enough.
        assert!(!svc.approval.check("pay.send", RiskClass::Financial, Some("ap1"), "to=alice;amount=5").unwrap());
        svc.approval.resolve("ap1", ApprovalState::Approved).unwrap();
        // The approval covers the action the user was shown and nothing else.
        assert!(!svc.approval.check("pay.send", RiskClass::Financial, Some("ap1"), "to=mallory;amount=5").unwrap(), "another recipient");
        assert!(!svc.approval.check("pay.send", RiskClass::Financial, Some("ap1"), "to=alice;amount=5000").unwrap(), "another amount");
        assert!(!svc.approval.check("pay.other", RiskClass::Financial, Some("ap1"), "to=alice;amount=5").unwrap(), "another capability");
        // The right action passes - once.
        assert!(svc.approval.check("pay.send", RiskClass::Financial, Some("ap1"), "to=alice;amount=5").unwrap());
        assert!(!svc.approval.check("pay.send", RiskClass::Financial, Some("ap1"), "to=alice;amount=5").unwrap(), "an approval is spent by use");
        assert!(svc.approval.get("ap1").unwrap().unwrap().used);
    }

    #[test]
    fn an_expired_approval_is_void() {
        let (_d, s) = store();
        let svc = svc_for(&s);
        let mut req = pending("old", "a");
        req.expires_at = chrono::Utc::now().timestamp() - 1;
        svc.approval.request(&req).unwrap();
        svc.approval.resolve("old", ApprovalState::Approved).unwrap();
        assert!(!svc.approval.check("pay.send", RiskClass::Financial, Some("old"), "a").unwrap());
        // And no request may ask for more than a day.
        let long = ApprovalRequest::new("long", "pay.send", RiskClass::Financial, "d", "a", 10 * 365 * 24 * 3600);
        assert!(long.expires_at <= chrono::Utc::now().timestamp() + MAX_APPROVAL_TTL_SECS + 1);
    }

    #[test]
    fn a_decision_cannot_be_flipped_and_a_request_cannot_overwrite_an_approval() {
        let (_d, s) = store();
        let svc = svc_for(&s);
        svc.approval.request(&pending("d1", "a")).unwrap();
        svc.approval.resolve("d1", ApprovalState::Denied).unwrap();
        assert!(svc.approval.resolve("d1", ApprovalState::Approved).is_err(), "a denial is final");
        assert!(svc.approval.resolve("missing", ApprovalState::Approved).is_err());
        // Re-filing the same id (to replace a denied request with a fresh pending one) is refused.
        assert!(svc.approval.request(&pending("d1", "a")).is_err());
        // A request cannot arrive already approved or already spent.
        let mut pre = pending("d2", "a");
        pre.state = ApprovalState::Approved;
        assert!(svc.approval.request(&pre).is_err());
        let mut spent = pending("d3", "a");
        spent.used = true;
        assert!(svc.approval.request(&spent).is_err());
    }

    #[test]
    fn two_racing_callers_cannot_both_spend_one_approval() {
        let home = tempfile::tempdir().unwrap();
        let a = PluginStorage::open(home.path(), "org.test.race").unwrap();
        let b = PluginStorage::open(home.path(), "org.test.race").unwrap();
        let sa = svc_for(&a);
        sa.approval.request(&pending("r1", "x")).unwrap();
        sa.approval.resolve("r1", ApprovalState::Approved).unwrap();
        let sb = svc_for(&b);
        let first = sa.approval.check("pay.send", RiskClass::Financial, Some("r1"), "x").unwrap();
        let second = sb.approval.check("pay.send", RiskClass::Financial, Some("r1"), "x").unwrap();
        assert_eq!([first, second].iter().filter(|ok| **ok).count(), 1, "exactly one winner");
    }

    #[test]
    fn a_plugin_writing_its_own_key_value_store_cannot_forge_host_state() {
        let (_d, s) = store();
        let svc = svc_for(&s);
        svc.approval.request(&pending("f1", "to=alice")).unwrap();
        // The plugin-facing store is the only thing a plugin can write. Forge every host key.
        let forged = serde_json::to_string(&ApprovalRequest {
            state: ApprovalState::Approved,
            ..pending("f1", "to=alice")
        })
        .unwrap();
        s.kv_set("approval:f1", &forged).unwrap();
        s.kv_set("approval:index", "f1\n").unwrap();
        s.kv_set("crashlog", "[]").unwrap();
        assert!(!svc.approval.check("pay.send", RiskClass::Financial, Some("f1"), "to=alice").unwrap(), "self-approval must fail");
        assert_eq!(svc.approval.get("f1").unwrap().unwrap().state, ApprovalState::Pending);
    }

    #[test]
    fn memory_labels_cannot_be_rewritten_through_the_plugin_kv() {
        let (_d, s) = store();
        let mem = MemoryService::new(&s, [DataClass::Public, DataClass::Personal]);
        mem.set("note", "tainted text", &[DataClass::Personal].into_iter().collect()).unwrap();
        // A plugin overwrites the record with the same key and empty labels, trying to launder it.
        let laundered = serde_json::to_string(&MemoryEntry {
            key: "note".into(),
            value: "tainted text".into(),
            taint: BTreeSet::new(),
            updated_at: "now".into(),
        })
        .unwrap();
        s.kv_set("mem:note", &laundered).unwrap();
        assert!(mem.get("note").unwrap().unwrap().taint.contains(&DataClass::Personal));
    }

    #[test]
    fn schedule_persists_and_finds_due_jobs() {
        let (_d, s) = store();
        let svc = PluginServices::new(
            &s,
            ToolRegistry::new(std::iter::empty()),
            [DataClass::Public],
        );
        svc.schedule
            .add(&ScheduledJob {
                id: "j1".into(),
                interval_secs: 60,
                fire_at: 100,
                callback: "cb".into(),
                enabled: true,
            })
            .unwrap();
        svc.schedule.index("j1").unwrap();
        assert!(svc.schedule.due(50).unwrap().is_empty());
        assert_eq!(svc.schedule.due(150).unwrap().len(), 1);
        // Disabled jobs never fire.
        svc.schedule
            .add(&ScheduledJob {
                id: "j2".into(),
                interval_secs: 0,
                fire_at: 10,
                callback: "cb".into(),
                enabled: false,
            })
            .unwrap();
        svc.schedule.index("j2").unwrap();
        assert_eq!(svc.schedule.due(999).unwrap().len(), 1);
    }

    #[test]
    fn routes_tools_events_notify_sentinel_ui_agents_all_function() {
        let (_d, s) = store();
        let svc = PluginServices::new(
            &s,
            ToolRegistry::new([("fs.read".to_string(), RiskClass::Read)]),
            [DataClass::Public],
        );
        assert!(svc.tools.permits("fs.read"));
        assert!(!svc.tools.permits("fs.write"));
        svc.routes.register("GET", "/api/x", "handler1");
        assert_eq!(
            svc.routes.lookup("get", "/api/x").as_deref(),
            Some("handler1")
        );
        assert!(svc.routes.lookup("GET", "/api/y").is_none());
        svc.events.subscribe("alerts", "sub1");
        assert_eq!(
            svc.events.publish("alerts", "ref-1"),
            vec!["sub1".to_string()]
        );
        svc.notify.enqueue("desktop", "msg-ref").unwrap();
        svc.sentinel.report("high", "test finding").unwrap();
        svc.ui.register_view("main", "schema-v1");
        assert_eq!(svc.ui.view("main").as_deref(), Some("schema-v1"));
        svc.agents.request("agent-2", "task-ref").unwrap();
        // Everything above must appear in the plugin's own audit trail.
        let tail = svc.audit.tail(50).unwrap();
        let actions: Vec<&str> = tail.iter().map(|(_, a, _)| a.as_str()).collect();
        assert!(actions.contains(&"sentinel.report"), "{actions:?}");
        assert!(actions.contains(&"notify.enqueue"), "{actions:?}");
        assert!(actions.contains(&"agents.request"), "{actions:?}");
    }
}
