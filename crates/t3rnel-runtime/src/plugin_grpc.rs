//! gRPC/tonic dispatch for the plugin host contract
//! (`proto/t3rnel/plugin/v1/plugin.proto`).
//!
//! [`PluginDispatch`] is the core side of the two-stream contract:
//!
//! - **Host services (plugin → core).** One tonic server per plugin
//!   connection implements all 14 proto services (`Http`, `Storage`,
//!   `Memory`, `Tools`, `Routes`, `Schedule`, `Events`, `Approval`, `Llm`,
//!   `Sentinel`, `Ui`, `Agents`, `Notify`, `Audit`, `Auth`, `Conversations`).
//!   The connection is a **pre-connected stream the supervisor inherited into
//!   the sandboxed plugin** ([`PluginDispatch::serve_stream`]); there is no
//!   listening port. The core therefore knows which plugin is on the other end
//!   because it created the stream for that plugin, and a request naming any
//!   other plugin is refused. Plugin identity is **not** taken from what the
//!   plugin says about itself.
//!
//! - **PluginCallbacks (core → plugin).** A second inherited stream carries the
//!   plugin's own `PluginCallbacks` gRPC server; the supervisor attaches it with
//!   [`PluginDispatch::attach_callbacks`]. Core→plugin calls — `CallTool`,
//!   `HandleRoute`, `ScheduleTick`, `OnEvent`, `RenderView`, `Health`,
//!   `BriefingQuery`, `StatusQuery` — go through [`PluginDispatch::callbacks`]
//!   and the `*_plugin` helpers below.
//!
//! Trust rules enforced here:
//!
//! - A plugin can only reach state inside its own install dir / plugin DB —
//!   the per-plugin [`PluginHost`] is keyed by the signed manifest's id and
//!   `manifest_digest` is verified against `manifest.json` when supplied.
//! - Egress/auth/data-classes come from the *signed* manifest's
//!   `permissions` block via [`crate::plugin_host::host_config_from_manifest`]
//!   — a package signed before that block existed gets empty rules and
//!   fails closed.
//! - `Approval.Request` blocks until a host-side decision arrives through
//!   [`PluginDispatch::resolve_approval`]; plugins cannot approve
//!   themselves (decisions only come through the host API).
//! - `Llm` and `Agents.SpawnAgent` are honest seams: without an injected
//!   backend/dispatcher they return `UNAVAILABLE`, never a made-up success.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use prost::Message as _;
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tonic::transport::Channel;
use tonic::{Request, Response, Status};

use crate::plugin_host::{host_config_from_manifest, PluginHost, PluginHostConfig};
use crate::plugin_lifecycle::PluginManifestLite;
use crate::plugin_services::{
    ApprovalRequest, ApprovalState, DataClass as SvcDataClass, MemoryService,
    RiskClass as SvcRiskClass, RouteRegistry, ScheduleService, ScheduledJob,
};
use crate::plugin_storage::{SqlParam, StorageError};

pub mod pb {
    tonic::include_proto!("t3rnel.plugin.v1");
}

pub use pb::plugin_callbacks_client::PluginCallbacksClient;
use pb::plugin_callbacks_client::PluginCallbacksClient as CallbacksClient;

/// Metadata keys the plugin client sets on every host-service call.
pub const META_PLUGIN_ID: &str = "x-plugin-id";
pub const META_PLUGIN_VERSION: &str = "x-plugin-version";

// ---------------------------------------------------------------------------
// Small conversions
// ---------------------------------------------------------------------------

fn ts_to_proto(t: chrono::DateTime<chrono::Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: t.timestamp(),
        nanos: t.timestamp_subsec_nanos() as i32,
    }
}

fn ts_from_proto(ts: Option<&prost_types::Timestamp>) -> Option<chrono::DateTime<chrono::Utc>> {
    ts.and_then(|t| chrono::DateTime::from_timestamp(t.seconds, t.nanos.max(0) as u32))
}

fn payload_to_bytes(p: Option<&pb::Payload>) -> Vec<u8> {
    p.map(|p| p.data.clone()).unwrap_or_default()
}

fn bytes_to_payload(data: Vec<u8>, content_type: &str, taint: Option<pb::Taint>) -> pb::Payload {
    pb::Payload {
        sha256: hex::encode(Sha256::digest(&data)),
        data,
        content_type: content_type.to_string(),
        taint: Some(taint.unwrap_or_default()),
    }
}

fn svc_data_class(c: i32) -> Option<SvcDataClass> {
    use pb::DataClass as P;
    Some(match P::try_from(c).unwrap_or(P::Unspecified) {
        P::Public => SvcDataClass::Public,
        P::PluginPrivate => SvcDataClass::PluginPrivate,
        P::Personal => SvcDataClass::Personal,
        P::Financial => SvcDataClass::Financial,
        P::CredentialAdjacent => SvcDataClass::CredentialAdjacent,
        P::Unclassified | P::Unspecified => SvcDataClass::Unclassified,
    })
}

fn svc_risk_class(c: i32) -> SvcRiskClass {
    use pb::RiskClass as P;
    match P::try_from(c).unwrap_or(P::Unspecified) {
        P::Read => SvcRiskClass::Read,
        P::WriteReversible => SvcRiskClass::WriteReversible,
        P::WriteIrreversible => SvcRiskClass::WriteIrreversible,
        P::ExternalEffect => SvcRiskClass::ExternalEffect,
        P::Financial => SvcRiskClass::Financial,
        P::System => SvcRiskClass::System,
        P::Unspecified => SvcRiskClass::Read,
    }
}

fn storage_err(e: StorageError) -> Status {
    Status::invalid_argument(e.to_string())
}

// ---------------------------------------------------------------------------
// Per-plugin runtime state
// ---------------------------------------------------------------------------

/// Host-side state for one connected plugin: the composed [`PluginHost`]
/// plus the service registries that are not borrowed from storage.
struct PluginRuntime {
    host: PluginHost,
    /// Host services the signed manifest declared; gated services check it.
    host_services: std::collections::BTreeSet<String>,
    routes: RouteRegistry,
    /// Registered tool defs the plugin offered via `Tools.Register`
    /// (tool_id → JSON ToolDef for CallTool routing/audit).
    tools: Mutex<BTreeMap<String, String>>,
    /// view_id → spec_json declared via `Ui.DeclareViews`.
    views: Mutex<BTreeMap<String, String>>,
    // Schedule jobs live entirely in host_state via ScheduleService — the
    // due() scan reads them each tick; no hot index needed.
}

// ---------------------------------------------------------------------------
// LLM + agent-dispatch seams (host-injected; honest Unavailable default)
// ---------------------------------------------------------------------------

/// Host-injected LLM backend for the `llm` service. The production wiring
/// (kernel model router) plugs in here; without it `Llm.Complete` returns
/// UNAVAILABLE rather than an invented answer.
#[async_trait::async_trait]
pub trait LlmCompleter: Send + Sync {
    async fn complete(
        &self,
        plugin_id: &str,
        prompt: &str,
        system: &str,
        model_class: &str,
        temperature: f64,
        max_tokens: u32,
    ) -> Result<(String, u32, u32), String>;
}

/// Host-injected agent dispatcher for `Agents.SpawnAgent` and the
/// agent-message consumer. Implementations route to the kernel's agent
/// runtime; without one, spawn returns UNAVAILABLE.
#[async_trait::async_trait]
pub trait AgentDispatcher: Send + Sync {
    async fn spawn(&self, plugin_id: &str, agent_id: &str, mission: &str)
        -> Result<String, String>;
}

/// Let the egress rules for the hosts the owner granted reach private addresses.
/// A host the manifest did not declare has no rule here, so it cannot be added.
fn lift_private(rules: &mut [t3rnel_egress::EgressRule], granted: &[String]) {
    for rule in rules.iter_mut().filter(|r| granted.contains(&r.host)) {
        rule.allow_private = true;
    }
}

#[cfg(test)]
mod private_host_grant_tests {
    use super::*;

    fn rule(host: &str) -> t3rnel_egress::EgressRule {
        t3rnel_egress::EgressRule {
            host: host.into(),
            methods: vec!["*".into()],
            paths: vec!["*".into()],
            allow_private: false,
            allow_encoded_slash: false,
        }
    }

    #[test]
    fn only_the_granted_declared_host_is_lifted() {
        let mut rules = vec![rule("127.0.0.1:3001"), rule("api.example.com")];
        // The owner also named a host the manifest never declared: it changes nothing.
        lift_private(&mut rules, &["127.0.0.1:3001".into(), "10.0.0.9".into()]);
        assert!(rules[0].allow_private);
        assert!(!rules[1].allow_private);
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn no_grant_lifts_nothing() {
        let mut rules = vec![rule("127.0.0.1:3001")];
        lift_private(&mut rules, &[]);
        assert!(!rules[0].allow_private);
    }
}

/// Counters the core's conversation service reports to a plugin's briefing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConversationCounters {
    pub threads_total: u64,
    pub unread_threads: u64,
    /// Threads with an inbound message in the last 24 hours (not messages).
    pub inbound_today: u64,
    /// Threads with an outbound message in the last 24 hours (not messages).
    pub outbound_today: u64,
    pub pending_approvals: u64,
}

/// What `Conversations.Send`/`Stats` need from the core's conversation service.
/// The service lives in the API layer, which attaches it after boot
/// ([`PluginDispatch::attach_conversations`]); until then both calls answer
/// UNAVAILABLE.
#[async_trait::async_trait]
pub trait ConversationsPort: Send + Sync {
    /// Send `text` on a linked account's thread; returns a receipt id.
    async fn send(
        &self,
        channel: &str,
        account: &str,
        thread_key: &str,
        text: &str,
    ) -> Result<String, String>;
    fn counters(&self) -> ConversationCounters;
}

/// Longest message a plugin may send in one call.
const MAX_CONVERSATION_TEXT: usize = 4000;

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub struct PluginDispatch {
    inner: Arc<DispatchInner>,
}

struct DispatchInner {
    home: PathBuf,
    dev_mode: bool,
    vault_key: Option<zeroize::Zeroizing<[u8; 32]>>,
    /// Owner grants: plugin id -> declared hosts that may be private/loopback.
    private_hosts: std::collections::BTreeMap<String, Vec<String>>,
    plugins: Mutex<HashMap<String, Arc<PluginRuntime>>>,
    callbacks: Mutex<HashMap<String, CallbacksClient<Channel>>>,
    /// topic → plugin_id → subscriber tag. Glob suffix `.*` supported.
    event_subs: Mutex<HashMap<String, HashMap<String, String>>>,
    /// approval_id → decision channel for in-flight `Approval.Request` RPCs.
    approval_waiters: Mutex<HashMap<String, watch::Sender<String>>>,
    llm: Option<Arc<dyn LlmCompleter>>,
    agents: Option<Arc<dyn AgentDispatcher>>,
    /// Set once by the API layer when the conversation service exists.
    conversations: std::sync::OnceLock<Arc<dyn ConversationsPort>>,
}

impl PluginDispatch {
    pub fn new(home: impl Into<PathBuf>, dev_mode: bool) -> Self {
        PluginDispatch {
            inner: Arc::new(DispatchInner {
                home: home.into(),
                dev_mode,
                vault_key: None,
                private_hosts: Default::default(),
                plugins: Mutex::new(HashMap::new()),
                callbacks: Mutex::new(HashMap::new()),
                event_subs: Mutex::new(HashMap::new()),
                approval_waiters: Mutex::new(HashMap::new()),
                llm: None,
                agents: None,
                conversations: std::sync::OnceLock::new(),
            }),
        }
    }

    /// Give plugins that declared `conversations` access to the core's
    /// conversation service. Callable once, after the dispatch is shared.
    pub fn attach_conversations(&self, port: Arc<dyn ConversationsPort>) {
        let _ = self.inner.conversations.set(port);
    }

    /// Owner-granted private upstreams (`KernelConfig::plugin_private_hosts`).
    /// Call before the dispatch is shared.
    pub fn with_private_hosts(mut self, grants: std::collections::BTreeMap<String, Vec<String>>) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("dispatch must be configured before sharing")
            .private_hosts = grants;
        self
    }

    pub fn with_vault_key(mut self, key: zeroize::Zeroizing<[u8; 32]>) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("dispatch must be configured before sharing")
            .vault_key = Some(key);
        self
    }

    pub fn with_llm(mut self, llm: Arc<dyn LlmCompleter>) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("dispatch must be configured before sharing")
            .llm = Some(llm);
        self
    }

    pub fn with_agent_dispatcher(mut self, agents: Arc<dyn AgentDispatcher>) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("dispatch must be configured before sharing")
            .agents = Some(agents);
        self
    }

    /// Resolve (or lazily create) the runtime for `plugin_id`, verifying the
    /// caller-supplied manifest digest against the installed manifest.json
    /// when present.
    async fn ensure_plugin(
        &self,
        identity: Option<&pb::PluginIdentity>,
    ) -> Result<Arc<PluginRuntime>, Status> {
        let plugin_id = identity
            .map(|i| i.id.clone())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Status::invalid_argument("plugin identity required"))?;
        crate::plugin_storage::validate_plugin_id(&plugin_id)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let manifest_path = self
            .inner
            .home
            .join("plugins")
            .join(&plugin_id)
            .join("manifest.json");
        let manifest_bytes = std::fs::read(&manifest_path)
            .map_err(|_| Status::not_found(format!("plugin {plugin_id} is not installed")))?;
        // When the caller asserts a manifest digest it must match the
        // installed (signed) manifest byte-for-byte.
        if let Some(digest) = identity.and_then(|i| {
            if i.manifest_digest.is_empty() {
                None
            } else {
                Some(i.manifest_digest.clone())
            }
        }) {
            let actual = hex::encode(Sha256::digest(&manifest_bytes));
            if actual != digest {
                return Err(Status::permission_denied(
                    "manifest_digest does not match installed manifest",
                ));
            }
        }
        let manifest: PluginManifestLite = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| Status::internal(format!("manifest unreadable: {e}")))?;
        if manifest.id != plugin_id {
            return Err(Status::permission_denied(
                "plugin id does not match installed manifest",
            ));
        }

        let existing = {
            let plugins = self.inner.plugins.lock().unwrap();
            plugins.get(&plugin_id).cloned()
        };
        if let Some(rt) = existing {
            return Ok(rt);
        }
        let mut cfg: PluginHostConfig =
            host_config_from_manifest(&manifest, self.inner.vault_key.clone(), self.inner.dev_mode);
        // Only a host the signed manifest already declares can be lifted.
        if let Some(granted) = self.inner.private_hosts.get(&plugin_id) {
            lift_private(&mut cfg.egress, granted);
        }
        let host = PluginHost::open(&self.inner.home, cfg)
            .map_err(|e| Status::internal(format!("plugin host open failed: {e}")))?;
        let host_services = manifest
            .permissions
            .as_ref()
            .map(|p| p.host_services.iter().cloned().collect())
            .unwrap_or_default();
        let rt = Arc::new(PluginRuntime {
            host,
            host_services,
            routes: RouteRegistry::new(),
            tools: Mutex::new(BTreeMap::new()),
            views: Mutex::new(BTreeMap::new()),
        });
        // Confine the mutex guard to a sync block — no await while held.
        let rt = {
            let mut plugins = self.inner.plugins.lock().unwrap();
            match plugins.get(&plugin_id) {
                // A racing RPC may have inserted while we opened the host.
                Some(existing) => existing.clone(),
                None => {
                    plugins.insert(plugin_id.clone(), rt.clone());
                    rt.clone()
                }
            }
        };
        Ok(rt)
    }

    /// Attach the plugin's `PluginCallbacks` server, reached over the second
    /// inherited stream. Called by the supervisor right after launch; replaces any
    /// earlier channel (a restarted plugin gets a fresh one).
    pub async fn attach_callbacks(
        &self,
        plugin_id: &str,
        stream: tokio::net::UnixStream,
    ) -> Result<(), Status> {
        crate::plugin_storage::validate_plugin_id(plugin_id)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        // The connector hands out the one stream we have. A second connection
        // attempt (after the plugin died) fails, which is what we want.
        let slot = Arc::new(Mutex::new(Some(stream)));
        let channel = tonic::transport::Endpoint::try_from("http://plugin.invalid")
            .map_err(|e| Status::internal(e.to_string()))?
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let slot = slot.clone();
                async move {
                    let stream = slot.lock().unwrap().take().ok_or_else(|| {
                        std::io::Error::other("the plugin's callback stream was already used")
                    })?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await
            .map_err(|e| Status::unavailable(format!("plugin callback stream: {e}")))?;
        self.inner
            .callbacks
            .lock()
            .unwrap()
            .insert(plugin_id.to_string(), PluginCallbacksClient::new(channel));
        Ok(())
    }

    /// Forget a plugin's callback channel and runtime state (it stopped).
    pub fn detach(&self, plugin_id: &str) {
        self.inner.callbacks.lock().unwrap().remove(plugin_id);
        self.inner.plugins.lock().unwrap().remove(plugin_id);
    }

    /// The PluginCallbacks client for `plugin_id`, if the plugin connected
    /// one. Core→plugin calls fail UNAVAILABLE until then.
    pub fn callbacks(&self, plugin_id: &str) -> Result<CallbacksClient<Channel>, Box<Status>> {
        self.inner
            .callbacks
            .lock()
            .unwrap()
            .get(plugin_id)
            .cloned()
            .ok_or_else(|| {
                Box::new(Status::unavailable(format!(
                    "plugin {plugin_id} has no callback channel"
                )))
            })
    }

    /// The plugin id a request asserts: `x-plugin-id`, when present, must equal
    /// `identity.id`. (The connection-bound check in [`PluginHostGrpc`] runs
    /// first; this keeps the two statements about identity consistent.)
    fn asserted_identity(
        &self,
        md: &tonic::metadata::MetadataMap,
        identity: Option<&pb::PluginIdentity>,
    ) -> Result<Option<String>, Box<Status>> {
        let meta_id = md
            .get(META_PLUGIN_ID)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        if let (Some(m), Some(i)) = (&meta_id, identity) {
            if !i.id.is_empty() && m != &i.id {
                return Err(Box::new(Status::permission_denied(
                    "x-plugin-id metadata does not match plugin identity",
                )));
            }
        }
        Ok(meta_id.or_else(|| identity.map(|i| i.id.clone())))
    }

    /// Shared per-RPC preamble: validate identity, resolve runtime.
    async fn runtime_for(
        &self,
        md: &tonic::metadata::MetadataMap,
        identity: Option<&pb::PluginIdentity>,
    ) -> Result<Arc<PluginRuntime>, Status> {
        self.asserted_identity(md, identity).map_err(|e| *e)?;
        self.ensure_plugin(identity).await
    }

    // ------------------------------------------------------------------
    // Core→plugin helpers (used by briefing, schedule ticks, events, UI)
    // ------------------------------------------------------------------

    /// `PluginCallbacks.CallTool` — route a capability call to the plugin.
    pub async fn call_tool(
        &self,
        plugin_id: &str,
        request: pb::ToolCallRequest,
    ) -> Result<pb::ToolCallResponse, Status> {
        let mut client = self.callbacks(plugin_id).map_err(|e| *e)?;
        client
            .call_tool(request)
            .await
            .map(|r| r.into_inner())
            .map_err(|e| Status::from_error(e.into()))
    }

    /// `PluginCallbacks.HandleRoute` — forward an authenticated route hit.
    pub async fn handle_route(
        &self,
        plugin_id: &str,
        request: pb::RouteRequest,
    ) -> Result<pb::RouteResponse, Status> {
        let mut client = self.callbacks(plugin_id).map_err(|e| *e)?;
        client
            .handle_route(request)
            .await
            .map(|r| r.into_inner())
            .map_err(|e| Status::from_error(e.into()))
    }

    /// `PluginCallbacks.Health`.
    pub async fn plugin_health(
        &self,
        plugin_id: &str,
        request: pb::HealthRequest,
    ) -> Result<pb::HealthResponse, Status> {
        let mut client = self.callbacks(plugin_id).map_err(|e| *e)?;
        client
            .health(request)
            .await
            .map(|r| r.into_inner())
            .map_err(|e| Status::from_error(e.into()))
    }

    /// `PluginCallbacks.BriefingQuery` — used by `briefing::BriefingSource`
    /// adapters; non-responders surface as UNAVAILABLE → core marks
    /// UNREACHABLE per §5.3.
    pub async fn briefing_query(
        &self,
        plugin_id: &str,
        request: pb::BriefingQueryRequest,
    ) -> Result<pb::BriefingReport, Status> {
        let mut client = self.callbacks(plugin_id).map_err(|e| *e)?;
        client
            .briefing_query(request)
            .await
            .map(|r| r.into_inner())
            .map_err(|e| Status::from_error(e.into()))
    }

    /// `PluginCallbacks.StatusQuery`.
    pub async fn status_query(
        &self,
        plugin_id: &str,
        request: pb::StatusQueryRequest,
    ) -> Result<pb::StatusReport, Status> {
        let mut client = self.callbacks(plugin_id).map_err(|e| *e)?;
        client
            .status_query(request)
            .await
            .map(|r| r.into_inner())
            .map_err(|e| Status::from_error(e.into()))
    }

    /// Fire every due schedule job across connected plugins: read due jobs
    /// from each plugin's host_state, call `ScheduleTick`, reschedule or
    /// disable per result. Returns (plugin_id, job_id, outcome) triples.
    pub async fn fire_due_schedules(&self, now_unix: u64) -> Vec<(String, String, String)> {
        let plugin_ids: Vec<String> = self.inner.plugins.lock().unwrap().keys().cloned().collect();
        let mut out = Vec::new();
        for pid in plugin_ids {
            let Ok(rt) = self
                .ensure_plugin(
                    Some(&pb::PluginIdentity {
                        id: pid.clone(),
                        ..Default::default()
                    }))
                .await
            else {
                continue;
            };
            let svc = ScheduleService::new(&rt.host.storage);
            let due = match svc.due(now_unix) {
                Ok(d) => d,
                Err(_) => continue,
            };
            for job in due {
                let mut client = match self.callbacks(&pid).map_err(|e| *e) {
                    Ok(c) => c,
                    Err(_) => {
                        out.push((pid.clone(), job.id.clone(), "no-callback".into()));
                        continue;
                    }
                };
                // Move the job on BEFORE firing it. The handler may reschedule
                // itself under the same id (the morning briefing does), and a
                // write after the call would overwrite that with the stale
                // copy; a slow handler must also not be fired twice by the
                // next pass.
                let mut next = job.clone();
                if next.interval_secs > 0 {
                    next.fire_at = now_unix + next.interval_secs;
                } else {
                    next.enabled = false;
                }
                if svc.add(&next).is_err() {
                    out.push((pid.clone(), job.id.clone(), "state-write-failed".into()));
                    continue;
                }
                let resp = client
                    .schedule_tick(pb::ScheduleTickRequest {
                        job_id: job.id.clone(),
                        description: String::new(),
                        scheduled_at: None,
                        fired_at: Some(ts_to_proto(chrono::Utc::now())),
                    })
                    .await;
                let failure = match resp {
                    Ok(r) => {
                        let tick = r.into_inner();
                        if tick.status == "ok" {
                            out.push((pid.clone(), job.id.clone(), "ok".into()));
                            None
                        } else {
                            Some(format!("error:{}", tick.error))
                        }
                    }
                    Err(e) => Some(format!("transport:{e}")),
                };
                if let Some(outcome) = failure {
                    // A one-shot that failed is not lost: if it is still retired
                    // (the handler did not reschedule it), try again shortly.
                    if job.interval_secs == 0 {
                        let still_retired = rt
                            .host
                            .storage
                            .state_get(&format!("schedule:{}", job.id))
                            .ok()
                            .flatten()
                            .and_then(|b| serde_json::from_str::<ScheduledJob>(&b).ok())
                            .is_some_and(|j| !j.enabled);
                        if still_retired {
                            let mut retry = job.clone();
                            retry.fire_at = now_unix + 300;
                            retry.enabled = true;
                            let _ = svc.add(&retry);
                        }
                    }
                    out.push((pid.clone(), job.id.clone(), outcome));
                }
            }
        }
        out
    }

    /// Host-side approval resolution: the ONLY way an `Approval.Request`
    /// RPC completes. `approved=true` → Approved, else Denied.
    pub async fn resolve_approval(
        &self,
        plugin_id: &str,
        approval_id: &str,
        approved: bool,
    ) -> Result<(), Status> {
        let rt = self
            .ensure_plugin(
                Some(&pb::PluginIdentity {
                    id: plugin_id.to_string(),
                    ..Default::default()
                }))
            .await?;
        let svc = crate::plugin_services::ApprovalService::new(&rt.host.storage);
        svc.resolve(
            approval_id,
            if approved {
                ApprovalState::Approved
            } else {
                ApprovalState::Denied
            },
        )
        .map_err(storage_err)?;
        let decision = if approved { "approved" } else { "denied" };
        if let Some(tx) = self
            .inner
            .approval_waiters
            .lock()
            .unwrap()
            .remove(approval_id)
        {
            let _ = tx.send(decision.to_string());
        }
        Ok(())
    }

    /// Registered plugin ids (for briefing source enumeration etc.).
    pub fn plugin_ids(&self) -> Vec<String> {
        self.inner.plugins.lock().unwrap().keys().cloned().collect()
    }

    /// Installed plugin ids on disk (whether or not they have connected).
    pub fn installed_plugin_ids(&self) -> Vec<String> {
        let dir = self.inner.home.join("plugins");
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() && p.join("manifest.json").exists() {
                    if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                        out.push(name.to_string());
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// Serve all 14 host services to **one** plugin over its inherited stream,
    /// until the plugin closes it. Every request on this connection is treated
    /// as coming from `plugin_id`, whatever it claims; a request naming another
    /// plugin is refused. Takes `Arc<Self>` so the dispatch stays shared with the
    /// API layer.
    pub async fn serve_stream(
        self: Arc<Self>,
        plugin_id: String,
        stream: tokio::net::UnixStream,
    ) -> Result<(), tonic::transport::Error> {
        use pb::{
            agents_server, approval_server, audit_server, auth_server, conversations_server,
            events_server, http_server, llm_server, memory_server, notify_server, routes_server,
            schedule_server, sentinel_server, storage_server, tools_server, ui_server,
        };
        let svc = PluginHostGrpc {
            dispatch: self,
            bound: Some(plugin_id),
        };
        let incoming = tokio_stream::iter([Ok::<_, std::io::Error>(stream)]);
        tonic::transport::Server::builder()
            .add_service(http_server::HttpServer::new(svc.clone()))
            .add_service(storage_server::StorageServer::new(svc.clone()))
            .add_service(memory_server::MemoryServer::new(svc.clone()))
            .add_service(tools_server::ToolsServer::new(svc.clone()))
            .add_service(routes_server::RoutesServer::new(svc.clone()))
            .add_service(schedule_server::ScheduleServer::new(svc.clone()))
            .add_service(events_server::EventsServer::new(svc.clone()))
            .add_service(approval_server::ApprovalServer::new(svc.clone()))
            .add_service(llm_server::LlmServer::new(svc.clone()))
            .add_service(sentinel_server::SentinelServer::new(svc.clone()))
            .add_service(ui_server::UiServer::new(svc.clone()))
            .add_service(agents_server::AgentsServer::new(svc.clone()))
            .add_service(notify_server::NotifyServer::new(svc.clone()))
            .add_service(audit_server::AuditServer::new(svc.clone()))
            .add_service(auth_server::AuthServer::new(svc.clone()))
            .add_service(conversations_server::ConversationsServer::new(svc.clone()))
            .serve_with_incoming(incoming)
            .await
    }
}

// ---------------------------------------------------------------------------
// The 14 host-service trait impls on one struct
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct PluginHostGrpc {
    dispatch: Arc<PluginDispatch>,
    /// The plugin this connection belongs to. Set by the supervisor, never by the plugin.
    bound: Option<String>,
}

impl PluginHostGrpc {
    /// Resolve the plugin for one request. A request on a bound connection may
    /// only be for the plugin that owns the connection; the identity it carries
    /// is checked against that, and an absent identity is filled in from it.
    async fn runtime_for(
        &self,
        md: &tonic::metadata::MetadataMap,
        identity: Option<&pb::PluginIdentity>,
    ) -> Result<Arc<PluginRuntime>, Status> {
        let Some(bound) = &self.bound else {
            return self.dispatch.runtime_for(md, identity).await;
        };
        if let Some(claimed) = identity.map(|i| i.id.as_str()).filter(|s| !s.is_empty()) {
            if claimed != bound {
                return Err(Status::permission_denied(
                    "this connection belongs to a different plugin",
                ));
            }
        }
        if let Some(meta) = md.get(META_PLUGIN_ID).and_then(|v| v.to_str().ok()) {
            if meta != bound {
                return Err(Status::permission_denied(
                    "this connection belongs to a different plugin",
                ));
            }
        }
        let mut ident = identity.cloned().unwrap_or_default();
        ident.id = bound.clone();
        self.dispatch.runtime_for(md, Some(&ident)).await
    }
}

use pb::*;
use pb::{
    agents_server, approval_server, audit_server, auth_server, conversations_server, events_server,
    http_server, llm_server, memory_server, notify_server, routes_server, schedule_server,
    sentinel_server, storage_server, tools_server, ui_server,
};

macro_rules! ident {
    ($req:expr) => {
        $req.plugin.as_ref()
    };
}

#[tonic::async_trait]
impl http_server::Http for PluginHostGrpc {
    async fn request(
        &self,
        request: Request<HttpRequest>,
    ) -> Result<Response<HttpResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let proxy_req = crate::plugin_proxy::ProxyRequest {
            url: req.url.clone(),
            method: req.method.clone(),
            headers: req
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            body: if req
                .body
                .as_ref()
                .map(|b| !b.data.is_empty())
                .unwrap_or(false)
            {
                Some(payload_to_bytes(req.body.as_ref()))
            } else {
                None
            },
            content_length: None,
            transfer_encoding_chunked: false,
        };
        let (resp, audit_id) = rt.host.http_audited(&proxy_req).await.map_err(|e| {
            let code = tonic::Code::from(crate::plugin_host::status_for_proxy_error(&e).code());
            Status::new(code, e.to_string())
        })?;
        let body = if req.return_body {
            Some(bytes_to_payload(
                resp.body,
                "application/octet-stream",
                None,
            ))
        } else {
            // return_body=false: status/headers/sha only — never the bytes.
            None
        };
        Ok(Response::new(HttpResponse {
            status: resp.status as u32,
            headers: resp.headers.into_iter().collect(),
            body,
            blocked_redirects: resp.blocked_redirects,
            audit_id: audit_id.to_string(),
        }))
    }
}

#[tonic::async_trait]
impl storage_server::Storage for PluginHostGrpc {
    async fn kv_get(
        &self,
        request: Request<KvGetRequest>,
    ) -> Result<Response<KvGetResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let value = rt
            .host
            .storage
            .kv_get_ns(&req.namespace, &req.key)
            .map_err(storage_err)?;
        let (found, payload) = match value {
            Some(v) => (
                true,
                Some(bytes_to_payload(v.into_bytes(), "text/plain", None)),
            ),
            None => (false, None),
        };
        Ok(Response::new(KvGetResponse {
            found,
            value: payload,
            updated_at: None,
        }))
    }

    async fn kv_put(&self, request: Request<KvPutRequest>) -> Result<Response<()>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let value = String::from_utf8(payload_to_bytes(req.value.as_ref()))
            .map_err(|_| Status::invalid_argument("kv value must be utf-8 text"))?;
        rt.host
            .storage
            .kv_set_ns(&req.namespace, &req.key, &value)
            .map_err(storage_err)?;
        Ok(Response::new(()))
    }

    async fn kv_delete(
        &self,
        request: Request<KvDeleteRequest>,
    ) -> Result<Response<KvDeleteResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let deleted = rt
            .host
            .storage
            .kv_delete_ns(&req.namespace, &req.key)
            .map_err(storage_err)?;
        Ok(Response::new(KvDeleteResponse { deleted }))
    }

    async fn kv_list(
        &self,
        request: Request<KvListRequest>,
    ) -> Result<Response<KvListResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let (keys, truncated) = rt
            .host
            .storage
            .kv_list_ns(&req.namespace, &req.prefix, req.limit)
            .map_err(storage_err)?;
        Ok(Response::new(KvListResponse { keys, truncated }))
    }

    async fn kv_delete_namespace(
        &self,
        request: Request<KvDeleteNamespaceRequest>,
    ) -> Result<Response<KvDeleteNamespaceResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let deleted = rt
            .host
            .storage
            .kv_delete_namespace(&req.namespace)
            .map_err(storage_err)?;
        Ok(Response::new(KvDeleteNamespaceResponse { deleted }))
    }

    async fn sql_exec(
        &self,
        request: Request<SqlExecRequest>,
    ) -> Result<Response<SqlExecResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let params: Vec<SqlParam> = req.params.iter().map(sql_param_from).collect();
        // SQLite is blocking; keep it off the async executor. The whole
        // runtime Arc moves in — PluginStorage is Sync (mutex-guarded conn).
        let rt2 = rt.clone();
        let statement = req.statement.clone();
        let timeout = req.timeout_ms;
        let outcome = tokio::task::spawn_blocking(move || {
            rt2.host.storage.sql_exec(&statement, &params, timeout)
        })
        .await
        .map_err(|e| Status::internal(format!("sql task: {e}")))?
        .map_err(storage_err)?;
        Ok(Response::new(SqlExecResponse {
            result: Some(sql_result_to(&outcome)),
        }))
    }

    async fn sql_exec_batch(
        &self,
        request: Request<SqlExecBatchRequest>,
    ) -> Result<Response<SqlExecBatchResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let statements: Vec<(String, Vec<SqlParam>)> = req
            .statements
            .iter()
            .map(|s| (s.sql.clone(), s.params.iter().map(sql_param_from).collect()))
            .collect();
        let rt2 = rt.clone();
        let owned: Vec<(String, Vec<SqlParam>)> = statements;
        let timeout = 5000u32;
        let results = tokio::task::spawn_blocking(move || {
            let pairs: Vec<(&str, &[SqlParam])> = owned
                .iter()
                .map(|(s, p)| (s.as_str(), p.as_slice()))
                .collect();
            rt2.host.storage.sql_exec_batch(&pairs, timeout)
        })
        .await
        .map_err(|e| Status::internal(format!("sql task: {e}")))?
        .map_err(storage_err)?;
        Ok(Response::new(SqlExecBatchResponse {
            results: results.iter().map(sql_result_to).collect(),
        }))
    }

    async fn blob_put(
        &self,
        request: Request<BlobPutRequest>,
    ) -> Result<Response<BlobPutResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let data = payload_to_bytes(req.value.as_ref());
        let (sha256, size) = rt
            .host
            .storage
            .blob_put(&req.namespace, &data)
            .map_err(storage_err)?;
        Ok(Response::new(BlobPutResponse { sha256, size }))
    }

    async fn blob_get(
        &self,
        request: Request<BlobGetRequest>,
    ) -> Result<Response<BlobGetResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        match rt
            .host
            .storage
            .blob_get(&req.namespace, &req.sha256)
            .map_err(storage_err)?
        {
            Some(data) => Ok(Response::new(BlobGetResponse {
                found: true,
                value: Some(bytes_to_payload(data, "application/octet-stream", None)),
            })),
            None => Ok(Response::new(BlobGetResponse {
                found: false,
                value: None,
            })),
        }
    }

    async fn migrate(
        &self,
        request: Request<MigrateRequest>,
    ) -> Result<Response<MigrateResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        // Snapshot before the first pending migration (same rule as
        // PluginStorage::migrate, surfaced so the caller gets the path).
        let storage = &rt.host.storage;
        let applied_versions = storage.applied_versions().map_err(storage_err)?;
        let pending: Vec<&Migration> = req
            .migrations
            .iter()
            .filter(|m| !applied_versions.contains(&(m.version as i64)))
            .collect();
        let mut snapshot_path = String::new();
        if let Some(first) = pending.first() {
            if let Ok(p) = storage.snapshot_before_migration(first.version as i64) {
                snapshot_path = p.display().to_string();
            }
        }
        let migrations: Vec<(i64, String, String)> = req
            .migrations
            .iter()
            .map(|m| {
                (
                    m.version as i64,
                    m.description.clone(),
                    m.statements.join(";\n"),
                )
            })
            .collect();
        let refs: Vec<(i64, &str, &str)> = migrations
            .iter()
            .map(|(v, d, s)| (*v, d.as_str(), s.as_str()))
            .collect();
        let ran = storage.migrate(&refs).map_err(storage_err)?;
        let current = storage
            .applied_versions()
            .map_err(storage_err)?
            .last()
            .copied()
            .unwrap_or(0) as u32;
        Ok(Response::new(MigrateResponse {
            current_version: current,
            applied: ran.iter().map(|v| *v as u32).collect(),
            snapshot_path,
        }))
    }
}

fn sql_param_from(v: &SqlValue) -> SqlParam {
    match &v.kind {
        Some(sql_value::Kind::Text(s)) => SqlParam::Text(s.clone()),
        Some(sql_value::Kind::Integer(i)) => SqlParam::Integer(*i),
        Some(sql_value::Kind::Real(f)) => SqlParam::Real(*f),
        Some(sql_value::Kind::Boolean(b)) => SqlParam::Boolean(*b),
        Some(sql_value::Kind::Blob(b)) => SqlParam::Blob(b.clone()),
        Some(sql_value::Kind::NullValue(_)) | None => SqlParam::Null,
    }
}

fn sql_value_to(p: &SqlParam) -> SqlValue {
    let kind = match p {
        SqlParam::Text(s) => sql_value::Kind::Text(s.clone()),
        SqlParam::Integer(i) => sql_value::Kind::Integer(*i),
        SqlParam::Real(f) => sql_value::Kind::Real(*f),
        SqlParam::Boolean(b) => sql_value::Kind::Boolean(*b),
        SqlParam::Blob(b) => sql_value::Kind::Blob(b.clone()),
        SqlParam::Null => sql_value::Kind::NullValue(true),
    };
    SqlValue { kind: Some(kind) }
}

fn sql_result_to(o: &crate::plugin_storage::SqlOutcome) -> SqlResult {
    SqlResult {
        columns: o.columns.clone(),
        rows: o
            .rows
            .iter()
            .map(|vals| SqlRow {
                columns: o.columns.clone(),
                values: vals.iter().map(sql_value_to).collect(),
            })
            .collect(),
        rows_affected: o.rows_affected,
        last_insert_rowid: o.last_insert_rowid,
    }
}

#[tonic::async_trait]
impl memory_server::Memory for PluginHostGrpc {
    async fn write(&self, request: Request<MemoryWriteRequest>) -> Result<Response<()>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        // Only the plugin's own namespace (its id) is writable.
        if req.namespace != rt.host.plugin_id {
            return Err(Status::permission_denied(
                "memory namespace must be the plugin's own id",
            ));
        }
        let classes: Vec<SvcDataClass> = req
            .data_classes
            .iter()
            .filter_map(|c| svc_data_class(*c))
            .collect();
        let mem = MemoryService::new(&rt.host.storage, rt.host.data_classes.iter().copied());
        let value = String::from_utf8_lossy(&payload_to_bytes(req.content.as_ref())).to_string();
        mem.set(&req.key, &value, &classes.iter().copied().collect())
            .map_err(storage_err)?;
        Ok(Response::new(()))
    }

    async fn read(
        &self,
        request: Request<MemoryReadRequest>,
    ) -> Result<Response<MemoryReadResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        if req.namespace != rt.host.plugin_id {
            return Err(Status::permission_denied(
                "memory namespace must be the plugin's own id",
            ));
        }
        let mem = MemoryService::new(&rt.host.storage, rt.host.data_classes.iter().copied());
        match mem.get(&req.key).map_err(storage_err)? {
            Some(entry) => Ok(Response::new(MemoryReadResponse {
                found: true,
                record: Some(MemoryRecord {
                    key: entry.key,
                    content: Some(bytes_to_payload(
                        entry.value.into_bytes(),
                        "text/plain",
                        None,
                    )),
                    namespace: req.namespace,
                }),
            })),
            None => Ok(Response::new(MemoryReadResponse {
                found: false,
                record: None,
            })),
        }
    }

    async fn query(
        &self,
        request: Request<MemoryQueryRequest>,
    ) -> Result<Response<MemoryQueryResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        if req.namespace != rt.host.plugin_id {
            return Err(Status::permission_denied(
                "memory namespace must be the plugin's own id",
            ));
        }
        // Memory entries live in host_state under `mem:<key>`; prefix-scan
        // them (bounded by limit, default 100).
        let mem = MemoryService::new(&rt.host.storage, rt.host.data_classes.iter().copied());
        let _ = &mem;
        let limit = if req.limit == 0 {
            100
        } else {
            req.limit as usize
        };
        let records = mem_prefix_scan(&rt.host.storage, &req.query, limit).map_err(|e| *e)?;
        Ok(Response::new(MemoryQueryResponse { records }))
    }
}

/// Scan `mem:` entries in host_state matching a key prefix. Bounded.
fn mem_prefix_scan(
    storage: &crate::plugin_storage::PluginStorage,
    prefix: &str,
    limit: usize,
) -> Result<Vec<MemoryRecord>, Box<Status>> {
    let entries = storage
        .state_prefix_scan(&format!("mem:{prefix}"), limit)
        .map_err(|e| Box::new(storage_err(e)))?;
    let mut out = Vec::new();
    for (_key, blob) in entries {
        if let Ok(entry) = serde_json::from_str::<crate::plugin_services::MemoryEntry>(&blob) {
            out.push(MemoryRecord {
                key: entry.key,
                content: Some(bytes_to_payload(
                    entry.value.into_bytes(),
                    "text/plain",
                    None,
                )),
                namespace: storage.plugin_id().to_string(),
            });
        }
    }
    Ok(out)
}

#[tonic::async_trait]
impl tools_server::Tools for PluginHostGrpc {
    async fn register(
        &self,
        request: Request<RegisterToolsRequest>,
    ) -> Result<Response<RegisterToolsResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let mut accepted = Vec::new();
        let mut rejected = std::collections::HashMap::new();
        for t in &req.tools {
            // Capability id shape: <domain>.<verb>, lowercase.
            let ok = !t.id.is_empty()
                && t.id.len() <= 128
                && t.id.contains('.')
                && t.id.chars().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_'
                });
            if !ok {
                rejected.insert(t.id.clone(), "invalid capability id".to_string());
                continue;
            }
            if t.risk_class == RiskClass::Unspecified as i32 {
                rejected.insert(t.id.clone(), "risk_class required".to_string());
                continue;
            }
            rt.tools
                .lock()
                .unwrap()
                .insert(t.id.clone(), hex::encode(t.encode_to_vec()));
            accepted.push(t.id.clone());
        }
        let _ = rt.host.storage.audit_append_id(
            "tools.register",
            &format!("accepted={} rejected={}", accepted.len(), rejected.len()),
        );
        Ok(Response::new(RegisterToolsResponse { accepted, rejected }))
    }

    async fn unregister(
        &self,
        request: Request<UnregisterToolsRequest>,
    ) -> Result<Response<UnregisterToolsResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let mut tools = rt.tools.lock().unwrap();
        let mut removed = Vec::new();
        if req.ids.is_empty() {
            removed = tools.keys().cloned().collect();
            tools.clear();
        } else {
            for id in &req.ids {
                if tools.remove(id).is_some() {
                    removed.push(id.clone());
                }
            }
        }
        Ok(Response::new(UnregisterToolsResponse { removed }))
    }
}

#[tonic::async_trait]
impl routes_server::Routes for PluginHostGrpc {
    async fn mount(
        &self,
        request: Request<MountRoutesRequest>,
    ) -> Result<Response<MountRoutesResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let mut mounted = Vec::new();
        let mut rejected = std::collections::HashMap::new();
        for r in &req.routes {
            if !r.path.starts_with('/') || r.path.contains("..") {
                rejected.insert(r.path.clone(), "path must start with / and be clean".into());
                continue;
            }
            if r.methods.is_empty() {
                rejected.insert(r.path.clone(), "at least one method required".into());
                continue;
            }
            for m in &r.methods {
                rt.routes.register(m, &r.path, &r.path);
            }
            mounted.push(r.path.clone());
        }
        let _ = rt
            .host
            .storage
            .audit_append_id("routes.mount", &format!("mounted={}", mounted.len()));
        Ok(Response::new(MountRoutesResponse { mounted, rejected }))
    }

    async fn unmount(
        &self,
        request: Request<UnmountRoutesRequest>,
    ) -> Result<Response<UnmountRoutesResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        // RouteRegistry has no remove; rebuild keeping wanted entries.
        // (routes are per-plugin; unmount all when ids empty)
        let removed_paths: Vec<String> = if req.paths.is_empty() {
            // Remove every route this plugin registered — RouteRegistry is
            // per-plugin so clearing is exact.
            rt.routes.clear();
            Vec::new() // paths unknown after clear; report mounted count before
        } else {
            req.paths.clone()
        };
        for p in &req.paths {
            rt.routes.remove_path(p);
        }
        Ok(Response::new(UnmountRoutesResponse {
            removed: removed_paths,
        }))
    }
}

#[tonic::async_trait]
impl schedule_server::Schedule for PluginHostGrpc {
    async fn add(
        &self,
        request: Request<ScheduleAddRequest>,
    ) -> Result<Response<ScheduleAddResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let svc = ScheduleService::new(&rt.host.storage);
        let now = chrono::Utc::now().timestamp() as u64;
        let mut added = Vec::new();
        let mut rejected = std::collections::HashMap::new();
        for j in &req.jobs {
            let spec = j
                .spec
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("schedule job requires spec"))?;
            let (interval_secs, fire_at) = match &spec.kind {
                Some(schedule_spec::Kind::IntervalSeconds(secs)) if *secs > 0 => {
                    (*secs as u64, now + *secs as u64)
                }
                Some(schedule_spec::Kind::RunAt(ts)) => {
                    let t = ts_from_proto(Some(ts))
                        .ok_or_else(|| Status::invalid_argument("bad run_at"))?;
                    (0, t.timestamp().max(0) as u64)
                }
                Some(schedule_spec::Kind::Cron(_)) => {
                    rejected.insert(j.job_id.clone(), "cron specs are not yet supported".into());
                    continue;
                }
                _ => {
                    rejected.insert(j.job_id.clone(), "empty schedule spec".into());
                    continue;
                }
            };
            let job = ScheduledJob {
                id: j.job_id.clone(),
                interval_secs,
                fire_at,
                callback: j.description.clone(),
                enabled: true,
            };
            svc.add(&job).map_err(storage_err)?;
            svc.index(&j.job_id).map_err(storage_err)?;
            added.push(j.job_id.clone());
        }
        Ok(Response::new(ScheduleAddResponse { added, rejected }))
    }

    async fn remove(
        &self,
        request: Request<ScheduleRemoveRequest>,
    ) -> Result<Response<ScheduleRemoveResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let svc = ScheduleService::new(&rt.host.storage);
        let mut removed = Vec::new();
        if req.job_ids.is_empty() {
            // Remove all: enumerate via due-far-future is wrong; use index.
            if let Ok(Some(idx)) = rt.host.storage.state_get("schedule:index") {
                for id in idx.lines().filter(|l| !l.is_empty()) {
                    let _ = svc.remove(id);
                    removed.push(id.to_string());
                }
            }
            let _ = rt.host.storage.state_set("schedule:index", "");
        } else {
            for id in &req.job_ids {
                svc.remove(id).map_err(storage_err)?;
                removed.push(id.clone());
            }
        }
        Ok(Response::new(ScheduleRemoveResponse { removed }))
    }

    async fn list(
        &self,
        request: Request<ScheduleListRequest>,
    ) -> Result<Response<ScheduleListResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let idx = rt
            .host
            .storage
            .state_get("schedule:index")
            .map_err(storage_err)?
            .unwrap_or_default();
        let mut jobs = Vec::new();
        for id in idx.lines().filter(|l| !l.is_empty()) {
            if let Some(blob) = rt
                .host
                .storage
                .state_get(&format!("schedule:{id}"))
                .map_err(storage_err)?
            {
                if blob.is_empty() {
                    continue;
                }
                if let Ok(j) = serde_json::from_str::<ScheduledJob>(&blob) {
                    let spec = if j.interval_secs > 0 {
                        schedule_spec::Kind::IntervalSeconds(j.interval_secs as u32)
                    } else {
                        schedule_spec::Kind::RunAt(ts_to_proto(
                            chrono::DateTime::from_timestamp(j.fire_at as i64, 0)
                                .unwrap_or_else(chrono::Utc::now),
                        ))
                    };
                    jobs.push(ScheduleJob {
                        job_id: j.id,
                        spec: Some(ScheduleSpec { kind: Some(spec) }),
                        description: j.callback,
                        missed_run_policy: String::new(),
                    });
                }
            }
        }
        Ok(Response::new(ScheduleListResponse { jobs }))
    }
}

#[tonic::async_trait]
impl events_server::Events for PluginHostGrpc {
    async fn subscribe(
        &self,
        request: Request<EventSubscribeRequest>,
    ) -> Result<Response<EventSubscribeResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let plugin_id = ident!(&req)
            .map(|i| i.id.clone())
            .ok_or_else(|| Status::invalid_argument("plugin identity required"))?;
        let _rt = self.runtime_for(&md, ident!(&req)).await?;
        let mut subs = self.dispatch.inner.event_subs.lock().unwrap();
        let mut granted = Vec::new();
        for topic in &req.topics {
            if topic.is_empty() || topic.len() > 256 {
                continue;
            }
            subs.entry(topic.clone())
                .or_default()
                .insert(plugin_id.clone(), plugin_id.clone());
            granted.push(topic.clone());
        }
        Ok(Response::new(EventSubscribeResponse {
            subscriptions: granted,
        }))
    }

    async fn unsubscribe(
        &self,
        request: Request<EventUnsubscribeRequest>,
    ) -> Result<Response<EventUnsubscribeResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let plugin_id = ident!(&req)
            .map(|i| i.id.clone())
            .ok_or_else(|| Status::invalid_argument("plugin identity required"))?;
        let _rt = self.runtime_for(&md, ident!(&req)).await?;
        let mut subs = self.dispatch.inner.event_subs.lock().unwrap();
        let mut removed = Vec::new();
        if req.subscriptions.is_empty() {
            for (_topic, plugins) in subs.iter_mut() {
                if plugins.remove(&plugin_id).is_some() {
                    removed.push(_topic.clone());
                }
            }
        } else {
            for sub in &req.subscriptions {
                if let Some(plugins) = subs.get_mut(sub) {
                    if plugins.remove(&plugin_id).is_some() {
                        removed.push(sub.clone());
                    }
                }
            }
        }
        Ok(Response::new(EventUnsubscribeResponse { removed }))
    }

    async fn emit(
        &self,
        request: Request<EventEmitRequest>,
    ) -> Result<Response<EventEmitResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let plugin_id = ident!(&req)
            .map(|i| i.id.clone())
            .ok_or_else(|| Status::invalid_argument("plugin identity required"))?;
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        // Topic must be namespaced under the plugin id or end in a declared
        // wildcard subscription target; emitting to arbitrary core topics is
        // refused unless the topic starts with the plugin's own id.
        if !req.topic.is_empty() && !req.topic.starts_with(&format!("{}.", plugin_id)) {
            return Err(Status::permission_denied(
                "event topic must be namespaced under the plugin id",
            ));
        }
        let event_id = uuid::Uuid::new_v4().to_string();
        // Find subscribers: exact topic or `prefix.*` glob.
        let subscribers: Vec<String> = {
            let subs = self.dispatch.inner.event_subs.lock().unwrap();
            let mut out: Vec<String> = Vec::new();
            for (pattern, plugins) in subs.iter() {
                let matched = if let Some(prefix) = pattern.strip_suffix(".*") {
                    req.topic.starts_with(prefix)
                } else {
                    pattern == &req.topic
                };
                if matched {
                    for pid in plugins.keys() {
                        if pid != &plugin_id && !out.contains(pid) {
                            out.push(pid.clone());
                        }
                    }
                }
            }
            out
        };
        let payload = req.payload.clone().unwrap_or_default();
        let mut delivered = 0u64;
        for pid in subscribers {
            let dispatch = self.dispatch.clone();
            let delivery = EventDelivery {
                event_id: event_id.clone(),
                topic: req.topic.clone(),
                source_plugin: plugin_id.clone(),
                payload: Some(payload.clone()),
                emitted_at: Some(ts_to_proto(chrono::Utc::now())),
            };
            tokio::spawn(async move {
                if let Ok(mut client) = dispatch.callbacks(&pid) {
                    let _ = client.on_event(delivery).await;
                }
            });
            delivered += 1;
        }
        let _ = rt.host.storage.audit_append_id(
            "events.emit",
            &format!("topic={} delivered={}", req.topic, delivered),
        );
        Ok(Response::new(EventEmitResponse {
            event_id,
            delivered,
        }))
    }
}

#[tonic::async_trait]
impl approval_server::Approval for PluginHostGrpc {
    async fn request(
        &self,
        request: Request<RequestApprovalRequest>,
    ) -> Result<Response<ApprovalDecision>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let plugin_id = ident!(&req)
            .map(|i| i.id.clone())
            .ok_or_else(|| Status::invalid_argument("plugin identity required"))?;
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let evidence = req.evidence.clone().unwrap_or_default();
        let risk = svc_risk_class(evidence.risk_class);
        let approval_id = uuid::Uuid::new_v4().to_string();
        let action = hex::encode(evidence.encode_to_vec());
        let ttl_ms = if req.timeout_ms == 0 {
            60_000
        } else {
            req.timeout_ms
        }
        .min(24 * 3600 * 1000);
        let areq = ApprovalRequest::new(
            &approval_id,
            &evidence.capability,
            risk,
            &evidence.summary,
            &action,
            (ttl_ms / 1000).max(1) as i64,
        );
        let svc = crate::plugin_services::ApprovalService::new(&rt.host.storage);
        svc.request(&areq).map_err(storage_err)?;
        // Waiter: resolve_approval() sends the decision string here.
        let (tx, mut rx) = watch::channel(String::new());
        self.dispatch
            .inner
            .approval_waiters
            .lock()
            .unwrap()
            .insert(approval_id.clone(), tx);
        let wait = tokio::time::timeout(
            std::time::Duration::from_millis(ttl_ms as u64),
            rx.changed(),
        )
        .await;
        self.dispatch
            .inner
            .approval_waiters
            .lock()
            .unwrap()
            .remove(&approval_id);
        let decision = match wait {
            Ok(Ok(())) => rx.borrow().clone(),
            _ => "expired".to_string(),
        };
        let _ = rt.host.storage.audit_append_id(
            "approval.request",
            &format!(
                "id={} plugin={} decision={}",
                approval_id, plugin_id, decision
            ),
        );
        Ok(Response::new(ApprovalDecision {
            decision,
            decided_by: "host".into(),
            decided_at: Some(ts_to_proto(chrono::Utc::now())),
            note: String::new(),
            audit_id: approval_id,
        }))
    }
}

#[tonic::async_trait]
impl llm_server::Llm for PluginHostGrpc {
    async fn complete(
        &self,
        request: Request<LlmCompleteRequest>,
    ) -> Result<Response<LlmCompleteResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let plugin_id = ident!(&req)
            .map(|i| i.id.clone())
            .ok_or_else(|| Status::invalid_argument("plugin identity required"))?;
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let llm = self
            .dispatch
            .inner
            .llm
            .clone()
            .ok_or_else(|| Status::unavailable("no LLM backend configured on this host"))?;
        // Data-class ceiling: the request's declared classes must be within
        // the manifest's declared set (union rule — plugin can't widen).
        let allowed = &rt.host.data_classes;
        for c in &req.data_classes {
            if let Some(sc) = svc_data_class(*c) {
                if !allowed.contains(&sc) {
                    return Err(Status::permission_denied(format!(
                        "data class {} not declared by plugin",
                        sc.as_str()
                    )));
                }
            }
        }
        let (text, tin, tout) = llm
            .complete(
                &plugin_id,
                &req.prompt,
                &req.system,
                &req.model_class,
                req.temperature,
                req.max_tokens,
            )
            .await
            .map_err(Status::unavailable)?;
        let audit_id = rt
            .host
            .storage
            .audit_append_id("llm.complete", &format!("plugin={plugin_id}"))
            .unwrap_or(0);
        Ok(Response::new(LlmCompleteResponse {
            text,
            model_class_used: req.model_class,
            tokens_in: tin,
            tokens_out: tout,
            audit_id: audit_id.to_string(),
        }))
    }
}

#[tonic::async_trait]
impl sentinel_server::Sentinel for PluginHostGrpc {
    async fn report_finding(
        &self,
        request: Request<ReportFindingRequest>,
    ) -> Result<Response<ReportFindingResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let sev =
            match FindingSeverity::try_from(req.severity).unwrap_or(FindingSeverity::Unspecified) {
                FindingSeverity::Info => "info",
                FindingSeverity::Low => "low",
                FindingSeverity::Medium => "medium",
                FindingSeverity::High => "high",
                FindingSeverity::Critical => "critical",
                FindingSeverity::Unspecified => "unspecified",
            };
        let detail = format!(
            "kind={} {} refs={}",
            req.kind,
            req.detail,
            req.evidence_refs.join(",")
        );
        let finding_id = rt
            .host
            .storage
            .audit_append_id("sentinel.report", &format!("severity={sev} {detail}"))
            .map_err(storage_err)?;
        Ok(Response::new(ReportFindingResponse {
            finding_id: finding_id.to_string(),
        }))
    }

    async fn canary_status(
        &self,
        request: Request<CanaryStatusRequest>,
    ) -> Result<Response<CanaryStatusResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        // Canary count is host-side bookkeeping in host_state.
        let count = rt
            .host
            .storage
            .state_get("canary:issued")
            .map_err(storage_err)?
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        Ok(Response::new(CanaryStatusResponse {
            canaries_issued: count,
            canary_breach_detected: false,
        }))
    }
}

#[tonic::async_trait]
impl ui_server::Ui for PluginHostGrpc {
    async fn declare_views(
        &self,
        request: Request<DeclareViewsRequest>,
    ) -> Result<Response<DeclareViewsResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let mut declared = Vec::new();
        let mut rejected = std::collections::HashMap::new();
        for v in &req.views {
            if v.view_id.is_empty() || v.view_id.len() > 128 {
                rejected.insert(v.view_id.clone(), "invalid view_id".into());
                continue;
            }
            rt.views
                .lock()
                .unwrap()
                .insert(v.view_id.clone(), v.spec_json.clone());
            declared.push(v.view_id.clone());
        }
        Ok(Response::new(DeclareViewsResponse { declared, rejected }))
    }

    async fn remove_views(
        &self,
        request: Request<RemoveViewsRequest>,
    ) -> Result<Response<RemoveViewsResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let mut views = rt.views.lock().unwrap();
        let removed: Vec<String> = if req.view_ids.is_empty() {
            views.keys().cloned().collect()
        } else {
            req.view_ids.clone()
        };
        for id in &removed {
            views.remove(id);
        }
        Ok(Response::new(RemoveViewsResponse { removed }))
    }
}

#[tonic::async_trait]
impl agents_server::Agents for PluginHostGrpc {
    async fn register_agents(
        &self,
        request: Request<RegisterAgentsRequest>,
    ) -> Result<Response<RegisterAgentsResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let mut registered = Vec::new();
        let mut rejected = std::collections::HashMap::new();
        for a in &req.agents {
            if a.agent_id.is_empty() {
                rejected.insert(a.agent_id.clone(), "empty agent_id".into());
                continue;
            }
            let blob = hex::encode(a.encode_to_vec());
            if let Err(e) = rt
                .host
                .storage
                .state_set(&format!("agentdef:{}", a.agent_id), &blob)
            {
                rejected.insert(a.agent_id.clone(), e.to_string());
                continue;
            }
            registered.push(a.agent_id.clone());
        }
        Ok(Response::new(RegisterAgentsResponse {
            registered,
            rejected,
        }))
    }

    async fn spawn_agent(
        &self,
        request: Request<SpawnAgentRequest>,
    ) -> Result<Response<SpawnAgentResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let plugin_id = ident!(&req)
            .map(|i| i.id.clone())
            .ok_or_else(|| Status::invalid_argument("plugin identity required"))?;
        let _rt = self.runtime_for(&md, ident!(&req)).await?;
        // The agent def must exist (registered by this plugin).
        let def = _rt
            .host
            .storage
            .state_get(&format!("agentdef:{}", req.agent_id))
            .map_err(storage_err)?
            .ok_or_else(|| Status::not_found(format!("agent {} not registered", req.agent_id)))?;
        let _ = def;
        let dispatcher =
            self.dispatch.inner.agents.clone().ok_or_else(|| {
                Status::unavailable("no agent dispatcher configured on this host")
            })?;
        let spawned = dispatcher
            .spawn(&plugin_id, &req.agent_id, &req.mission)
            .await
            .map_err(Status::unavailable)?;
        Ok(Response::new(SpawnAgentResponse {
            spawned_agent_id: spawned,
        }))
    }

    async fn remove_agents(
        &self,
        request: Request<RemoveAgentsRequest>,
    ) -> Result<Response<RemoveAgentsResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let mut removed = Vec::new();
        if req.agent_ids.is_empty() {
            // Enumerate via index if present.
            if let Some(idx) = rt
                .host
                .storage
                .state_get("agentdef:index")
                .map_err(storage_err)?
            {
                for id in idx.lines().filter(|l| !l.is_empty()) {
                    let _ = rt.host.storage.state_set(&format!("agentdef:{id}"), "");
                    removed.push(id.to_string());
                }
                let _ = rt.host.storage.state_set("agentdef:index", "");
            }
        } else {
            for id in &req.agent_ids {
                rt.host
                    .storage
                    .state_set(&format!("agentdef:{id}"), "")
                    .map_err(storage_err)?;
                removed.push(id.clone());
            }
        }
        Ok(Response::new(RemoveAgentsResponse { removed }))
    }
}

#[tonic::async_trait]
impl notify_server::Notify for PluginHostGrpc {
    async fn send(
        &self,
        request: Request<NotifyRequest>,
    ) -> Result<Response<NotifyResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let svc = crate::plugin_services::NotifyService::new(&rt.host.storage);
        // The message body is the reference payload; keep it JSON so the
        // host dispatcher can render level/title/body/link.
        let message_ref = serde_json::json!({
            "level": req.level,
            "title": req.title,
            "body": req.body,
            "link": req.link,
        })
        .to_string();
        svc.enqueue("plugin", &message_ref).map_err(storage_err)?;
        let notice_id = uuid::Uuid::new_v4().to_string();
        Ok(Response::new(NotifyResponse { notice_id }))
    }
}

#[tonic::async_trait]
impl audit_server::Audit for PluginHostGrpc {
    async fn append(
        &self,
        request: Request<AuditAppendRequest>,
    ) -> Result<Response<AuditAppendResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let entry = req
            .entry
            .ok_or_else(|| Status::invalid_argument("entry required"))?;
        let rt = self
            .dispatch
            .runtime_for(&md, entry.plugin.as_ref())
            .await?;
        // References and hashes only — never content or secrets (05 §14.2).
        let detail = format!(
            "subject={} outcome={} sha256={} taint={:?} meta={}",
            entry.subject, entry.outcome, entry.payload_sha256, entry.taint, entry.metadata_json
        );
        let audit_id = rt
            .host
            .storage
            .audit_append_id(&entry.kind, &detail)
            .map_err(storage_err)?;
        Ok(Response::new(AuditAppendResponse {
            audit_id: audit_id.to_string(),
        }))
    }
}

#[tonic::async_trait]
impl auth_server::Auth for PluginHostGrpc {
    async fn token(
        &self,
        request: Request<AuthTokenRequest>,
    ) -> Result<Response<AuthTokenResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let grant = rt
            .host
            .auth()
            .issue(
                &req.provider,
                &req.scopes,
                if req.ttl_seconds == 0 {
                    None
                } else {
                    Some(req.ttl_seconds as u64)
                },
            )
            .await
            .map_err(|e| {
                Status::new(
                    tonic::Code::from(crate::plugin_host::PluginStatus::PermissionDenied.code()),
                    e.to_string(),
                )
            })?;
        Ok(Response::new(AuthTokenResponse {
            token_ref: grant.token_ref,
            expires_at: Some(ts_to_proto(grant.expires_at)),
            granted_scopes: grant.scopes,
            token_type: grant.token_type,
        }))
    }
}

// ---------------------------------------------------------------------------
// conversations — gated to plugins that declared the service
// ---------------------------------------------------------------------------
//
// A plugin may send on a linked account's thread only if its signed manifest
// `requires` the `conversations` service. Every send is audited in the
// plugin's own log (channel, account and length; never the text).

impl PluginHostGrpc {
    #[allow(clippy::result_large_err)] // tonic's Status is the error type of every handler here
    fn conversations_for(
        &self,
        rt: &PluginRuntime,
    ) -> Result<Arc<dyn ConversationsPort>, Status> {
        if !rt.host_services.contains("conversations") {
            return Err(Status::permission_denied(
                "this plugin's signed manifest does not require the conversations service",
            ));
        }
        self.dispatch
            .inner
            .conversations
            .get()
            .cloned()
            .ok_or_else(|| Status::unavailable("the conversation service is not running"))
    }
}

#[tonic::async_trait]
impl conversations_server::Conversations for PluginHostGrpc {
    async fn send(
        &self,
        request: Request<ConversationSendRequest>,
    ) -> Result<Response<ConversationSendResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let port = self.conversations_for(&rt)?;
        if req.channel.is_empty() || req.account.is_empty() || req.thread_key.is_empty() {
            return Err(Status::invalid_argument("channel, account and thread_key are required"));
        }
        if req.text.trim().is_empty() {
            return Err(Status::invalid_argument("text must not be empty"));
        }
        if req.text.chars().count() > MAX_CONVERSATION_TEXT {
            return Err(Status::invalid_argument(format!(
                "text is longer than {MAX_CONVERSATION_TEXT} characters"
            )));
        }
        let outcome = port
            .send(&req.channel, &req.account, &req.thread_key, &req.text)
            .await;
        let _ = crate::plugin_services::AuditService::new(&rt.host.storage).record(
            "conversations",
            "send",
            &format!(
                "channel={} account={} chars={} ok={}",
                req.channel,
                req.account,
                req.text.chars().count(),
                outcome.is_ok()
            ),
        );
        let receipt = outcome.map_err(|e| Status::unavailable(format!("send failed: {e}")))?;
        Ok(Response::new(ConversationSendResponse { receipt }))
    }

    async fn stats(
        &self,
        request: Request<ConversationStatsRequest>,
    ) -> Result<Response<ConversationStatsResponse>, Status> {
        let md = request.metadata().clone();
        let req = request.into_inner();
        let rt = self.runtime_for(&md, ident!(&req)).await?;
        let c = self.conversations_for(&rt)?.counters();
        Ok(Response::new(ConversationStatsResponse {
            threads_total: c.threads_total,
            unread_threads: c.unread_threads,
            inbound_today: c.inbound_today,
            outbound_today: c.outbound_today,
            pending_approvals: c.pending_approvals,
        }))
    }
}

// ---------------------------------------------------------------------------
// briefing source — a running plugin's report, collected through the dispatch
// ---------------------------------------------------------------------------

/// Feeds one plugin's `BriefingQuery`/`StatusQuery` answers into the morning
/// briefing. A plugin that is not running answers UNAVAILABLE, which the
/// briefing service reports as UNREACHABLE instead of skipping it.
pub struct DispatchBriefingSource {
    dispatch: Arc<PluginDispatch>,
    plugin_id: String,
}

impl DispatchBriefingSource {
    pub fn new(dispatch: Arc<PluginDispatch>, plugin_id: impl Into<String>) -> Self {
        DispatchBriefingSource { dispatch, plugin_id: plugin_id.into() }
    }
}

fn briefing_level(l: i32) -> crate::briefing::StatusLevel {
    use crate::briefing::StatusLevel as B;
    match pb::StatusLevel::try_from(l).unwrap_or(pb::StatusLevel::Unspecified) {
        pb::StatusLevel::Ok => B::Ok,
        pb::StatusLevel::Critical => B::Critical,
        // A plugin cannot claim UNREACHABLE, and an unspecified level is not "fine".
        _ => B::Attention,
    }
}

fn data_class_name(c: i32) -> &'static str {
    use pb::DataClass as P;
    match P::try_from(c).unwrap_or(P::Unspecified) {
        P::Public => "public",
        P::PluginPrivate => "plugin-private",
        P::Personal => "personal",
        P::Financial => "financial",
        P::CredentialAdjacent => "credential-adjacent",
        P::Unclassified | P::Unspecified => "unclassified",
    }
}

fn action_risk(c: i32) -> SvcRiskClass {
    // An action that does not say how risky it is is treated as the riskiest.
    match pb::RiskClass::try_from(c).unwrap_or(pb::RiskClass::Unspecified) {
        pb::RiskClass::Unspecified => SvcRiskClass::System,
        other => svc_risk_class(other as i32),
    }
}

/// Convert a plugin's report. `plugin_id` is the core's own knowledge of who
/// answered; whatever identity the body claims is ignored.
fn briefing_from_pb(plugin_id: &str, r: pb::BriefingReport) -> crate::briefing::BriefingReport {
    crate::briefing::BriefingReport {
        plugin: plugin_id.to_string(),
        level: briefing_level(r.level),
        items: r
            .items
            .into_iter()
            .map(|i| crate::briefing::BriefingItem {
                id: i.id,
                text: i.text,
                // Everything a plugin says is untrusted data, whatever it claims.
                taint: Some(crate::conversations::Provenance {
                    source: format!("plugin:{plugin_id}"),
                    untrusted: true,
                    data_classes: i
                        .taint
                        .map(|t| t.data_classes.iter().map(|c| data_class_name(*c).to_string()).collect())
                        .unwrap_or_default(),
                }),
                tags: i.tags,
                template_id: (!i.template_id.is_empty()).then_some(i.template_id),
                template_slots: i.template_slots.into_iter().collect(),
            })
            .collect(),
        actions: r
            .actions
            .into_iter()
            .map(|a| crate::briefing::ActionRequest {
                id: a.id,
                label: a.label,
                detail: a.detail,
                risk_class: action_risk(a.risk_class),
                capability: a.capability,
                // Only the core assigns a binding id.
                approval_binding_id: None,
            })
            .collect(),
        metrics: r.metrics.into_iter().collect(),
        headline: r.headline,
    }
}

#[async_trait::async_trait]
impl crate::briefing::BriefingSource for DispatchBriefingSource {
    fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    async fn briefing_query(
        &self,
        q: &crate::briefing::BriefingQuery,
    ) -> Result<crate::briefing::BriefingReport, String> {
        let req = pb::BriefingQueryRequest {
            plugin: Some(pb::PluginIdentity { id: self.plugin_id.clone(), ..Default::default() }),
            report_date: q.report_date.clone(),
            as_of: Some(ts_to_proto(q.as_of)),
        };
        let r = self
            .dispatch
            .briefing_query(&self.plugin_id, req)
            .await
            .map_err(|s| s.message().to_string())?;
        Ok(briefing_from_pb(&self.plugin_id, r))
    }

    async fn status_query(
        &self,
        q: &crate::briefing::StatusQuery,
    ) -> Result<crate::briefing::StatusReport, String> {
        let req = pb::StatusQueryRequest {
            plugin: Some(pb::PluginIdentity { id: self.plugin_id.clone(), ..Default::default() }),
            since: q.since.map(ts_to_proto),
        };
        let r = self
            .dispatch
            .status_query(&self.plugin_id, req)
            .await
            .map_err(|s| s.message().to_string())?;
        Ok(crate::briefing::StatusReport {
            plugin: self.plugin_id.clone(),
            level: briefing_level(r.level),
            headline: r.headline,
            metrics: r.metrics.into_iter().collect(),
            detail: r.detail,
        })
    }
}

#[cfg(test)]
mod briefing_source_tests {
    use super::*;

    #[test]
    fn a_report_is_converted_with_the_cores_identity_and_untrusted_taint() {
        let r = pb::BriefingReport {
            plugin: Some(pb::PluginIdentity { id: "org.evil.claims-to-be-someone".into(), ..Default::default() }),
            level: pb::StatusLevel::Ok as i32,
            items: vec![pb::BriefingItem {
                id: "i".into(),
                text: "hello".into(),
                taint: Some(pb::Taint { untrusted: false, ..Default::default() }),
                ..Default::default()
            }],
            actions: vec![pb::ActionRequest {
                id: "a".into(),
                label: "pay".into(),
                risk_class: pb::RiskClass::Unspecified as i32,
                approval_binding_id: "AB-000001".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let b = briefing_from_pb("org.real.plugin", r);
        assert_eq!(b.plugin, "org.real.plugin");
        let taint = b.items[0].taint.as_ref().unwrap();
        assert!(taint.untrusted, "plugin text is always untrusted");
        assert_eq!(taint.source, "plugin:org.real.plugin");
        // An unstated risk is the highest one, and the binding id is the core's to assign.
        assert_eq!(b.actions[0].risk_class, SvcRiskClass::System);
        assert!(b.actions[0].approval_binding_id.is_none());
    }

    #[test]
    fn a_plugin_cannot_claim_unreachable_and_an_unspecified_level_is_attention() {
        assert_eq!(briefing_level(pb::StatusLevel::Unreachable as i32), crate::briefing::StatusLevel::Attention);
        assert_eq!(briefing_level(pb::StatusLevel::Unspecified as i32), crate::briefing::StatusLevel::Attention);
        assert_eq!(briefing_level(pb::StatusLevel::Ok as i32), crate::briefing::StatusLevel::Ok);
        assert_eq!(briefing_level(pb::StatusLevel::Critical as i32), crate::briefing::StatusLevel::Critical);
    }
}
