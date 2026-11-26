//! Morning briefing service (`docs/sections/18 §5`).
//!
//! A scheduled core job (default 07:00 local) that produces the user's daily
//! briefing. The contract is **fixed-schema in, core-rendered out**: plugins
//! return typed [`BriefingReport`]s through the `BriefingQuery` callback —
//! never prose, never structure — and core owns section ordering, templates
//! and per-channel adaptation.
//!
//! Flow (§5.3):
//! 1. **Collect** — `BriefingQuery` on every installed plugin in parallel
//!    with a timeout; non-responders are reported [`StatusLevel::Unreachable`],
//!    never skipped. Core overnight data (pending approvals, jobs, budget,
//!    sentinel findings) merges alongside.
//! 2. **Compile** — one [`BriefingDocument`]; every `needs_action` item gets
//!    an approval-binding id from the conversation service, so the briefing
//!    doubles as the morning approval inbox.
//! 3. **Deliver** — through the conversation service to linked channels;
//!    stored in memory under `briefing:<date>`.
//!
//! Plugin-supplied text is tainted `untrusted` data — rendered as data,
//! never interpreted as instructions (§5.1, §14.9).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Local, NaiveTime, Utc};
use serde::{Deserialize, Serialize};

use crate::conversations::{ApprovalSnapshot, ConversationService, Notification, NotifyLevel};
use crate::plugin_services::RiskClass;

// ---------------------------------------------------------------------------
// Wire-contract mirrors (proto/t3rnel/plugin/v1 BriefingReport et al.)
// ---------------------------------------------------------------------------
// These Rust types mirror the proto messages one-to-one; the gRPC dispatch
// layer maps between them once tonic codegen exists. Field names match the
// proto contract so the mapping is mechanical.

/// Health/attention level — mirrors proto `StatusLevel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StatusLevel {
    Ok,
    Attention,
    Critical,
    /// Assigned by CORE on timeout — a plugin cannot claim it.
    Unreachable,
}

impl StatusLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            StatusLevel::Ok => "OK",
            StatusLevel::Attention => "ATTENTION",
            StatusLevel::Critical => "CRITICAL",
            StatusLevel::Unreachable => "UNREACHABLE",
        }
    }
}

/// One item inside a plugin report — mirrors proto `BriefingItem`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BriefingItem {
    pub id: String,
    /// Tainted untrusted text — rendered as data only.
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taint: Option<crate::conversations::Provenance>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Optional core `briefing_template` id + named slots. Plugins cannot
    /// supply arbitrary markup (§5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(default)]
    pub template_slots: BTreeMap<String, String>,
}

/// An item needing a user decision — mirrors proto `ActionRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    /// Plugin-chosen id within the report.
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub detail: String,
    pub risk_class: RiskClass,
    pub capability: String,
    /// Core-assigned approval-binding id, filled at compile time. A
    /// plugin-supplied value is only an idempotency hint — never trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_binding_id: Option<String>,
}

/// The typed report — mirrors proto `BriefingReport`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BriefingReport {
    /// Plugin id, e.g. "org.t3rnel.vlc-bridge".
    pub plugin: String,
    pub level: StatusLevel,
    #[serde(default)]
    pub items: Vec<BriefingItem>,
    #[serde(default)]
    pub actions: Vec<ActionRequest>,
    #[serde(default)]
    pub metrics: BTreeMap<String, String>,
    #[serde(default)]
    pub headline: String,
}

/// Mirrors proto `BriefingQueryRequest`.
#[derive(Debug, Clone)]
pub struct BriefingQuery {
    pub plugin: String,
    /// Local report date, YYYY-MM-DD.
    pub report_date: String,
    pub as_of: DateTime<Utc>,
}

/// Mirrors proto `StatusQueryRequest`.
#[derive(Debug, Clone)]
pub struct StatusQuery {
    pub plugin: String,
    #[allow(dead_code)]
    pub since: Option<DateTime<Utc>>,
}

/// Mirrors proto `StatusReport`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub plugin: String,
    pub level: StatusLevel,
    #[serde(default)]
    pub headline: String,
    #[serde(default)]
    pub metrics: BTreeMap<String, String>,
    #[serde(default)]
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Sources and core data
// ---------------------------------------------------------------------------

/// A plugin (or any installed briefing contributor). The gRPC dispatch
/// layer implements this over the `BriefingQuery`/`StatusQuery` callbacks;
/// tests and embedded hosts can register any implementation.
#[async_trait]
pub trait BriefingSource: Send + Sync {
    fn plugin_id(&self) -> &str;

    /// Produce this plugin's report section. Must complete within the
    /// core-imposed timeout; the service marks timeouts UNREACHABLE.
    async fn briefing_query(&self, query: &BriefingQuery) -> Result<BriefingReport, String>;

    /// Lightweight status poll; default derives from a briefing query.
    async fn status_query(&self, _query: &StatusQuery) -> Result<StatusReport, String> {
        Err("status query unsupported".to_string())
    }
}

/// Core-collected overnight data merged into every briefing (§5.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoreOvernight {
    #[serde(default)]
    pub pending_approvals: Vec<ApprovalSnapshot>,
    #[serde(default)]
    pub jobs_finished: Vec<String>,
    #[serde(default)]
    pub budget_summary: Option<String>,
    #[serde(default)]
    pub sentinel_findings: Vec<String>,
    #[serde(default)]
    pub metrics: BTreeMap<String, String>,
}

/// Seam for core overnight data — the API layer wires this to the kernel's
/// pending store, scheduler, budget and sentinel surfaces.
#[async_trait]
pub trait CoreDataProvider: Send + Sync {
    async fn overnight(&self, since: DateTime<Utc>) -> Result<CoreOvernight, String>;
}

/// In-memory sink for `briefing:<date>` records — the API layer implements
/// this over the kernel's unified memory (`memory_recall`).
pub trait BriefingMemory: Send + Sync {
    fn store(&self, key: &str, value: serde_json::Value) -> Result<(), String>;
}

/// Durable briefing document store. `FileBriefingStore` is the built-in;
/// richer backends can implement the trait.
#[async_trait]
pub trait BriefingStore: Send + Sync {
    async fn save(&self, doc: &BriefingDocument) -> Result<(), String>;
    async fn latest(&self) -> Result<Option<BriefingDocument>, String>;
    async fn get(&self, date: &str) -> Result<Option<BriefingDocument>, String>;
}

/// JSON-file briefing store under `<home>/briefings/`.
pub struct FileBriefingStore {
    dir: PathBuf,
}

impl FileBriefingStore {
    pub fn new(home: &Path) -> Self {
        FileBriefingStore {
            dir: home.join("briefings"),
        }
    }

    fn path(&self, date: &str) -> PathBuf {
        // date is YYYY-MM-DD generated internally; still validate to keep
        // the store traversal-proof.
        let safe: String = date
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(format!("{safe}.json"))
    }
}

#[async_trait]
impl BriefingStore for FileBriefingStore {
    async fn save(&self, doc: &BriefingDocument) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let tmp = self.path(&doc.date).with_extension("json.tmp");
        std::fs::write(
            &tmp,
            serde_json::to_string_pretty(doc).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        std::fs::rename(tmp, self.path(&doc.date)).map_err(|e| e.to_string())
    }

    async fn latest(&self) -> Result<Option<BriefingDocument>, String> {
        let mut best: Option<(String, PathBuf)> = None;
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".json") && name != "latest.json" {
                let date = name.trim_end_matches(".json").to_string();
                if best.as_ref().map(|(d, _)| date > *d).unwrap_or(true) {
                    best = Some((date, entry.path()));
                }
            }
        }
        match best {
            Some((_, path)) => {
                let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
                serde_json::from_str(&text)
                    .map(Some)
                    .map_err(|e| e.to_string())
            }
            None => Ok(None),
        }
    }

    async fn get(&self, date: &str) -> Result<Option<BriefingDocument>, String> {
        let path = self.path(date);
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|e| e.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration + compiled document
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BriefingConfig {
    /// Local time the briefing runs (default 07:00).
    pub time_local: NaiveTime,
    /// Per-plugin query timeout.
    pub query_timeout: Duration,
    /// How far back "overnight" reaches for core data.
    pub lookback: Duration,
    /// Deliver the compiled briefing through the conversation service.
    pub deliver: bool,
}

impl Default for BriefingConfig {
    fn default() -> Self {
        BriefingConfig {
            time_local: NaiveTime::from_hms_opt(7, 0, 0).unwrap(),
            query_timeout: Duration::from_secs(10),
            lookback: Duration::from_secs(24 * 3600),
            deliver: true,
        }
    }
}

/// One plugin's compiled section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSection {
    pub plugin: String,
    pub level: StatusLevel,
    #[serde(default)]
    pub headline: String,
    #[serde(default)]
    pub items: Vec<BriefingItem>,
    #[serde(default)]
    pub actions: Vec<ActionRequest>,
    #[serde(default)]
    pub metrics: BTreeMap<String, String>,
    /// Set when the plugin failed to answer inside the timeout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreachable_reason: Option<String>,
}

/// A compiled action with its approval-binding id assigned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundAction {
    pub plugin: String,
    pub action: ActionRequest,
    /// Approval-binding id issued by the conversation service.
    pub approval_binding_id: String,
    /// Delivery error, when the prompt could not be sent anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_error: Option<String>,
}

/// The single briefing document — core-rendered, plugin-content bounded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BriefingDocument {
    /// Local report date, YYYY-MM-DD.
    pub date: String,
    pub generated_at: DateTime<Utc>,
    /// "core" section first, then plugins in registration order.
    pub core: CoreOvernight,
    #[serde(default)]
    pub plugins: Vec<PluginSection>,
    /// Every action needing a decision, with binding ids.
    #[serde(default)]
    pub needs_action: Vec<BoundAction>,
    /// Rendered plain-text document (the channel-agnostic base form;
    /// per-channel adaptation happens at delivery).
    pub text: String,
}

impl BriefingDocument {
    /// Memory key for `memory_recall briefing:<date>` (§5.3 step 3).
    pub fn memory_key(&self) -> String {
        format!("briefing:{}", self.date)
    }
}

// ---------------------------------------------------------------------------
// The service
// ---------------------------------------------------------------------------

pub struct BriefingService {
    sources: Mutex<Vec<Arc<dyn BriefingSource>>>,
    core_data: Arc<dyn CoreDataProvider>,
    conversations: Arc<ConversationService>,
    memory: Option<Arc<dyn BriefingMemory>>,
    store: Arc<dyn BriefingStore>,
    config: BriefingConfig,
    /// Last local date a briefing ran (prevents double-runs).
    last_run_date: Mutex<Option<String>>,
}

impl BriefingService {
    pub fn new(
        core_data: Arc<dyn CoreDataProvider>,
        conversations: Arc<ConversationService>,
        store: Arc<dyn BriefingStore>,
        config: BriefingConfig,
    ) -> Self {
        BriefingService {
            sources: Mutex::new(Vec::new()),
            core_data,
            conversations,
            memory: None,
            store,
            config,
            last_run_date: Mutex::new(None),
        }
    }

    /// Attach the memory sink for `briefing:<date>` records.
    pub fn set_memory(&mut self, memory: Arc<dyn BriefingMemory>) {
        self.memory = Some(memory);
    }

    pub fn set_config(&mut self, config: BriefingConfig) {
        self.config = config;
    }

    /// Register a briefing source (installed plugin).
    pub fn register_source(&self, source: Arc<dyn BriefingSource>) {
        self.sources.lock().unwrap().push(source);
    }

    pub fn sources(&self) -> Vec<String> {
        self.sources
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.plugin_id().to_string())
            .collect()
    }

    fn today_local() -> (String, DateTime<Utc>) {
        let now_local = Local::now();
        (now_local.format("%Y-%m-%d").to_string(), Utc::now())
    }

    /// Whether the scheduled job is due (past configured local time and not
    /// yet run today).
    pub fn due(&self) -> bool {
        let (date, _) = Self::today_local();
        if self.last_run_date.lock().unwrap().as_deref() == Some(date.as_str()) {
            return false;
        }
        Local::now().time() >= self.config.time_local
    }

    /// Run the full collect → compile → deliver → store cycle. Callable on
    /// schedule (`run_due`) or manually (API trigger).
    pub async fn run(&self) -> Result<BriefingDocument, String> {
        let (date, as_of) = Self::today_local();
        *self.last_run_date.lock().unwrap() = Some(date.clone());

        // 1. Collect — BriefingQuery on every installed plugin IN PARALLEL
        //    (§5.3 step 1) with a per-plugin timeout; non-responders are
        //    reported UNREACHABLE, never skipped.
        let sources: Vec<Arc<dyn BriefingSource>> = self.sources.lock().unwrap().clone();
        let timeout = self.config.query_timeout;
        let queries: Vec<_> = sources
            .iter()
            .map(|source| {
                let plugin = source.plugin_id().to_string();
                let q = BriefingQuery {
                    plugin: plugin.clone(),
                    report_date: date.clone(),
                    as_of,
                };
                async move {
                    let outcome = tokio::time::timeout(timeout, source.briefing_query(&q)).await;
                    (plugin, outcome)
                }
            })
            .collect();
        let mut sections = Vec::with_capacity(queries.len());
        for (plugin, outcome) in futures::future::join_all(queries).await {
            let section = match outcome {
                Ok(Ok(mut report)) => {
                    report.plugin = plugin.clone();
                    PluginSection {
                        plugin,
                        level: report.level,
                        headline: report.headline,
                        items: report.items,
                        actions: report.actions,
                        metrics: report.metrics,
                        unreachable_reason: None,
                    }
                }
                Ok(Err(e)) => unreachable_section(plugin, format!("query failed: {e}")),
                Err(_) => unreachable_section(
                    plugin,
                    format!("timeout after {:?}", self.config.query_timeout),
                ),
            };
            sections.push(section);
        }

        // 2. Core overnight data.
        let since = as_of
            - chrono::Duration::from_std(self.config.lookback)
                .unwrap_or_else(|_| chrono::Duration::hours(24));
        let core = self
            .core_data
            .overnight(since)
            .await
            .unwrap_or_else(|e| CoreOvernight {
                sentinel_findings: vec![format!("core data provider error: {e}")],
                ..Default::default()
            });

        // 3. Compile — bind every action to an approval binding.
        let mut needs_action = Vec::new();
        // Core pending approvals first (they already have backend refs).
        for approval in &core.pending_approvals {
            let target = self.primary_target();
            let bound = self
                .bind_action(
                    "core",
                    approval.id.clone(),
                    &approval.summary,
                    &approval.capability,
                    &approval.risk,
                    Some(approval.id.clone()),
                    target.as_ref(),
                )
                .await;
            needs_action.push(bound);
        }
        // Plugin actions.
        for section in &sections {
            for action in &section.actions {
                let target = self.primary_target();
                let bound = self
                    .bind_action(
                        &section.plugin,
                        action.id.clone(),
                        &action.label,
                        &action.capability,
                        risk_name(action.risk_class),
                        None,
                        target.as_ref(),
                    )
                    .await;
                needs_action.push(BoundAction {
                    plugin: section.plugin.clone(),
                    action: action.clone(),
                    approval_binding_id: bound.approval_binding_id,
                    delivery_error: bound.delivery_error,
                });
            }
        }

        let mut doc = BriefingDocument {
            date: date.clone(),
            generated_at: as_of,
            core,
            plugins: sections,
            needs_action,
            text: String::new(),
        };
        doc.text = render_document(&doc);

        // 4. Deliver + store + memory.
        if self.config.deliver {
            let level = if doc.needs_action.is_empty() {
                NotifyLevel::Info
            } else {
                NotifyLevel::ActionRequired
            };
            let title = format!("Morning briefing — {}", doc.date);
            let deliveries = self
                .conversations
                .notify(Notification {
                    level,
                    title,
                    body: doc.text.clone(),
                    link: None,
                    correlation_id: Some(format!("briefing:{}", doc.date)),
                })
                .await;
            let failed = deliveries.iter().filter(|(_, r)| r.is_err()).count();
            if failed > 0 {
                tracing::warn!("briefing {}: {failed} channel deliveries failed", doc.date);
            }
        }
        self.store.save(&doc).await?;
        if let Some(memory) = &self.memory {
            let value = serde_json::to_value(&doc).map_err(|e| e.to_string())?;
            memory.store(&doc.memory_key(), value)?;
        }
        Ok(doc)
    }

    /// Scheduled entry point: runs only when due.
    pub async fn run_due(&self) -> Result<Option<BriefingDocument>, String> {
        if !self.due() {
            return Ok(None);
        }
        self.run().await.map(Some)
    }

    /// First linked account as the approval-delivery target, when any.
    fn primary_target(&self) -> Option<(String, String)> {
        self.conversations
            .registry()
            .linked_accounts()
            .first()
            .map(|a| (a.channel.clone(), a.account.clone()))
    }

    /// Create the approval binding for one action and deliver its prompt.
    #[allow(clippy::too_many_arguments)] // mirrors the action/binding fields
    async fn bind_action(
        &self,
        plugin: &str,
        action_id: String,
        label: &str,
        capability: &str,
        risk: &str,
        approval_ref: Option<String>,
        target: Option<&(String, String)>,
    ) -> BoundAction {
        let Some((channel, account)) = target else {
            return BoundAction {
                plugin: plugin.to_string(),
                action: ActionRequest {
                    id: action_id,
                    label: label.to_string(),
                    detail: String::new(),
                    risk_class: parse_risk(risk),
                    capability: capability.to_string(),
                    approval_binding_id: None,
                },
                approval_binding_id: String::new(),
                delivery_error: Some("no linked channel account".to_string()),
            };
        };
        match self
            .conversations
            .deliver_approval(
                channel,
                account,
                account, // local/dashboard principal: sender == account
                account,
                capability,
                &format!("[{plugin}] {label}"),
                risk,
                approval_ref,
                None,
            )
            .await
        {
            Ok(binding) => BoundAction {
                plugin: plugin.to_string(),
                action: ActionRequest {
                    id: action_id,
                    label: label.to_string(),
                    detail: String::new(),
                    risk_class: parse_risk(risk),
                    capability: capability.to_string(),
                    approval_binding_id: Some(binding.id.clone()),
                },
                approval_binding_id: binding.id,
                delivery_error: None,
            },
            Err(e) => BoundAction {
                plugin: plugin.to_string(),
                action: ActionRequest {
                    id: action_id,
                    label: label.to_string(),
                    detail: String::new(),
                    risk_class: parse_risk(risk),
                    capability: capability.to_string(),
                    approval_binding_id: None,
                },
                approval_binding_id: String::new(),
                delivery_error: Some(e.to_string()),
            },
        }
    }

    /// Latest stored document (for API status).
    pub async fn latest(&self) -> Result<Option<BriefingDocument>, String> {
        self.store.latest().await
    }

    pub async fn get(&self, date: &str) -> Result<Option<BriefingDocument>, String> {
        self.store.get(date).await
    }

    /// Poll every source's StatusQuery in parallel with the same timeout —
    /// used by dashboard status surfaces and the briefing fallback path.
    pub async fn collect_status(&self) -> Vec<StatusReport> {
        let sources: Vec<Arc<dyn BriefingSource>> = self.sources.lock().unwrap().clone();
        let timeout = self.config.query_timeout;
        let queries: Vec<_> = sources
            .iter()
            .map(|source| {
                let plugin = source.plugin_id().to_string();
                let q = StatusQuery {
                    plugin: plugin.clone(),
                    since: None,
                };
                async move {
                    let outcome = tokio::time::timeout(timeout, source.status_query(&q)).await;
                    (plugin, outcome)
                }
            })
            .collect();
        futures::future::join_all(queries)
            .await
            .into_iter()
            .map(|(plugin, outcome)| match outcome {
                Ok(Ok(mut r)) => {
                    r.plugin = plugin;
                    r
                }
                Ok(Err(e)) => StatusReport {
                    plugin,
                    level: StatusLevel::Unreachable,
                    headline: String::new(),
                    metrics: BTreeMap::new(),
                    detail: format!("status query failed: {e}"),
                },
                Err(_) => StatusReport {
                    plugin,
                    level: StatusLevel::Unreachable,
                    headline: String::new(),
                    metrics: BTreeMap::new(),
                    detail: format!("timeout after {:?}", timeout),
                },
            })
            .collect()
    }
}

fn unreachable_section(plugin: String, reason: String) -> PluginSection {
    PluginSection {
        plugin: plugin.clone(),
        level: StatusLevel::Unreachable,
        headline: String::new(),
        items: vec![],
        actions: vec![],
        metrics: BTreeMap::new(),
        unreachable_reason: Some(reason),
    }
}

fn risk_name(risk: RiskClass) -> &'static str {
    match risk {
        RiskClass::Read => "read",
        RiskClass::WriteReversible => "write-reversible",
        RiskClass::WriteIrreversible => "write-irreversible",
        RiskClass::ExternalEffect => "external-effect",
        RiskClass::Financial => "financial",
        RiskClass::System => "system",
    }
}

fn parse_risk(name: &str) -> RiskClass {
    match name {
        "read" => RiskClass::Read,
        "write-reversible" => RiskClass::WriteReversible,
        "write-irreversible" => RiskClass::WriteIrreversible,
        "external-effect" => RiskClass::ExternalEffect,
        "financial" => RiskClass::Financial,
        "system" => RiskClass::System,
        _ => RiskClass::WriteIrreversible,
    }
}

/// Core-rendered document text. Plugin content is interpolated as data —
/// it is never scanned for or obeyed as instructions.
fn render_document(doc: &BriefingDocument) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Morning briefing {}\n\n", doc.date));

    // Core section.
    out.push_str("## Core\n\n");
    if doc.core.pending_approvals.is_empty()
        && doc.core.jobs_finished.is_empty()
        && doc.core.sentinel_findings.is_empty()
        && doc.core.budget_summary.is_none()
        && doc.core.metrics.is_empty()
    {
        out.push_str("Nothing overnight.\n\n");
    }
    if let Some(b) = &doc.core.budget_summary {
        out.push_str(&format!("- Budget: {b}\n"));
    }
    for j in &doc.core.jobs_finished {
        out.push_str(&format!("- Job finished: {j}\n"));
    }
    for s in &doc.core.sentinel_findings {
        out.push_str(&format!("- Sentinel: {s}\n"));
    }
    for a in &doc.core.pending_approvals {
        out.push_str(&format!(
            "- Pending approval {} ({}): {}\n",
            a.id, a.risk, a.summary
        ));
    }
    for (k, v) in &doc.core.metrics {
        out.push_str(&format!("- {k}: {v}\n"));
    }
    out.push('\n');

    // Plugin sections.
    for section in &doc.plugins {
        out.push_str(&format!(
            "## {} ({})\n\n",
            section.plugin,
            section.level.as_str()
        ));
        if let Some(reason) = &section.unreachable_reason {
            out.push_str(&format!("Unreachable: {reason}\n\n"));
            continue;
        }
        if !section.headline.is_empty() {
            out.push_str(&format!("{}\n\n", section.headline));
        }
        for item in &section.items {
            out.push_str(&format!("- {}\n", item.text));
        }
        for (k, v) in &section.metrics {
            out.push_str(&format!("- {k}: {v}\n"));
        }
        out.push('\n');
    }

    // Needs action.
    if !doc.needs_action.is_empty() {
        out.push_str("## Needs your decision\n\n");
        for a in &doc.needs_action {
            out.push_str(&format!(
                "- [{}] {} — reply with the binding id {}\n",
                a.plugin, a.action.label, a.approval_binding_id
            ));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::{ChannelAdapter, ChannelRegistry, LinkedAccount, LocalChannel};
    use crate::conversations::{
        ApprovalPort, ApprovalSnapshot, ApprovalVerdict, ConversationService, NewApprovalRequest,
    };
    use crate::plugin_vault::VaultBroker;
    use zeroize::Zeroizing;

    struct StaticCore(CoreOvernight);
    #[async_trait]
    impl CoreDataProvider for StaticCore {
        async fn overnight(&self, _since: DateTime<Utc>) -> Result<CoreOvernight, String> {
            Ok(self.0.clone())
        }
    }

    struct MemApprovals {
        items: Mutex<BTreeMap<String, ApprovalSnapshot>>,
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
        async fn register(&self, req: &NewApprovalRequest) -> Result<String, String> {
            let id = format!("P-{}", self.items.lock().unwrap().len() + 1);
            self.items.lock().unwrap().insert(
                id.clone(),
                ApprovalSnapshot {
                    id: id.clone(),
                    capability: req.capability.clone(),
                    summary: req.summary.clone(),
                    risk: req.risk.clone(),
                    state: "pending".into(),
                    expires_at: None,
                },
            );
            Ok(id)
        }
        async fn decide(
            &self,
            id: &str,
            verdict: ApprovalVerdict,
            _n: Option<String>,
            _v: &str,
        ) -> Result<(), String> {
            let mut items = self.items.lock().unwrap();
            if let Some(s) = items.get_mut(id) {
                s.state = match verdict {
                    ApprovalVerdict::Approve => "approved",
                    ApprovalVerdict::Deny => "denied",
                    ApprovalVerdict::Defer => "pending",
                }
                .into();
            }
            Ok(())
        }
        fn revalidate(&self, _b: &crate::conversations::ApprovalBinding) -> Result<(), String> {
            Ok(())
        }
    }

    struct Fixture {
        _home: tempfile::TempDir,
        service: Arc<BriefingService>,
        conversations: Arc<ConversationService>,
        adapter: Arc<LocalChannel>,
    }

    async fn fixture(sources: Vec<Arc<dyn BriefingSource>>, core: CoreOvernight) -> Fixture {
        fixture_with_config(sources, core, BriefingConfig::default()).await
    }

    async fn fixture_with_config(
        sources: Vec<Arc<dyn BriefingSource>>,
        core: CoreOvernight,
        config: BriefingConfig,
    ) -> Fixture {
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
            .unlock_ordered(Some(Zeroizing::new([8u8; 32])))
            .unwrap();
        registry.set_vault(vault.clone());
        let registry = Arc::new(registry);
        // Connect the local adapter so approval prompts + briefing delivery
        // actually send.
        let creds = crate::channels::BrokeredCreds::new(vault, "web", vec![]);
        adapter.connect(&creds).await.unwrap();
        let approvals = Arc::new(MemApprovals {
            items: Mutex::new(BTreeMap::new()),
        });
        let conversations =
            Arc::new(ConversationService::open(home.path(), registry, approvals).unwrap());
        let service = Arc::new(BriefingService::new(
            Arc::new(StaticCore(core)),
            conversations.clone(),
            Arc::new(FileBriefingStore::new(home.path())),
            config,
        ));
        for s in sources {
            service.register_source(s);
        }
        Fixture {
            _home: home,
            service,
            conversations,
            adapter,
        }
    }

    struct FakeSource {
        id: String,
        report: BriefingReport,
        delay: Duration,
    }
    #[async_trait]
    impl BriefingSource for FakeSource {
        fn plugin_id(&self) -> &str {
            &self.id
        }
        async fn briefing_query(&self, _q: &BriefingQuery) -> Result<BriefingReport, String> {
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            Ok(self.report.clone())
        }
    }

    fn report(plugin: &str, level: StatusLevel) -> BriefingReport {
        BriefingReport {
            plugin: plugin.into(),
            level,
            headline: format!("{plugin} headline"),
            items: vec![BriefingItem {
                id: "i1".into(),
                text: format!("{plugin} did a thing"),
                taint: None,
                tags: vec![],
                template_id: None,
                template_slots: BTreeMap::new(),
            }],
            actions: vec![],
            metrics: [("orders".to_string(), "3".to_string())]
                .into_iter()
                .collect(),
        }
    }

    #[tokio::test]
    async fn run_collects_plugins_core_and_delivers() {
        // 50ms timeout: org.fast answers, org.slow times out → UNREACHABLE.
        let config = BriefingConfig {
            query_timeout: Duration::from_millis(50),
            ..BriefingConfig::default()
        };
        let f = fixture_with_config(
            vec![
                Arc::new(FakeSource {
                    id: "org.a".into(),
                    report: report("org.a", StatusLevel::Ok),
                    delay: Duration::ZERO,
                }),
                Arc::new(FakeSource {
                    id: "org.slow".into(),
                    report: report("org.slow", StatusLevel::Ok),
                    delay: Duration::from_millis(500),
                }),
            ],
            CoreOvernight {
                pending_approvals: vec![ApprovalSnapshot {
                    id: "P-7".into(),
                    capability: "payout.send".into(),
                    summary: "send payout".into(),
                    risk: "financial".into(),
                    state: "pending".into(),
                    expires_at: None,
                }],
                jobs_finished: vec!["job-1".into()],
                budget_summary: Some("$1.20 today".into()),
                sentinel_findings: vec![],
                metrics: BTreeMap::new(),
            },
            config,
        )
        .await;
        let doc = f.service.run().await.unwrap();
        assert_eq!(doc.date.len(), 10);
        let fast = doc.plugins.iter().find(|p| p.plugin == "org.a").unwrap();
        assert_eq!(fast.level, StatusLevel::Ok);
        let slow = doc.plugins.iter().find(|p| p.plugin == "org.slow").unwrap();
        assert_eq!(slow.level, StatusLevel::Unreachable);
        assert!(slow.unreachable_reason.is_some());
        assert!(doc.text.contains("Morning briefing"));
        assert!(doc.text.contains("org.a did a thing"));
        assert!(doc.text.contains("send payout"));
        // The pending approval became a bound action.
        assert_eq!(doc.needs_action.len(), 1);
        assert!(doc.needs_action[0].approval_binding_id.starts_with("AB-"));
        // Delivered to the linked local account.
        assert!(f.adapter.outbound_len() >= 1);
        // Stored + memory key shape.
        assert_eq!(doc.memory_key(), format!("briefing:{}", doc.date));
        let stored = f.service.latest().await.unwrap().unwrap();
        assert_eq!(stored.date, doc.date);
    }

    #[tokio::test]
    async fn unreachable_plugin_reported_not_skipped() {
        struct DeadSource;
        #[async_trait]
        impl BriefingSource for DeadSource {
            fn plugin_id(&self) -> &str {
                "org.dead"
            }
            async fn briefing_query(&self, _q: &BriefingQuery) -> Result<BriefingReport, String> {
                Err("connection refused".into())
            }
        }
        let f = fixture(vec![Arc::new(DeadSource)], CoreOvernight::default()).await;
        let doc = f.service.run().await.unwrap();
        let section = doc.plugins.iter().find(|p| p.plugin == "org.dead").unwrap();
        assert_eq!(section.level, StatusLevel::Unreachable);
        assert!(section.unreachable_reason.is_some());
    }

    #[tokio::test]
    async fn plugin_action_gets_binding_id() {
        let mut r = report("org.act", StatusLevel::Attention);
        r.actions.push(ActionRequest {
            id: "a1".into(),
            label: "Approve campaign spend".into(),
            detail: String::new(),
            risk_class: RiskClass::Financial,
            capability: "ads.spend".into(),
            approval_binding_id: None,
        });
        let f = fixture(
            vec![Arc::new(FakeSource {
                id: "org.act".into(),
                report: r,
                delay: Duration::ZERO,
            })],
            CoreOvernight::default(),
        )
        .await;
        let doc = f.service.run().await.unwrap();
        assert_eq!(doc.needs_action.len(), 1);
        let bound = &doc.needs_action[0];
        assert!(bound.approval_binding_id.starts_with("AB-"));
        assert!(bound.delivery_error.is_none());
        // The binding exists in the conversation service and is pending;
        // the test backend registered a real approval ref for it.
        let b = f.conversations.binding(&bound.approval_binding_id).unwrap();
        assert_eq!(b.state, crate::conversations::BindingState::Pending);
        assert_eq!(b.approval_ref, "P-1");
    }

    #[tokio::test]
    async fn run_marks_today_so_due_is_false() {
        let f = fixture(vec![], CoreOvernight::default()).await;
        // A manual run records today as done; run_due must then skip.
        f.service.run().await.unwrap();
        assert!(f.service.run_due().await.unwrap().is_none());
        assert!(!f.service.due());
    }

    #[test]
    fn render_orders_core_first_and_bounds_plugin_text() {
        let mut doc = BriefingDocument {
            date: "2026-11-24".into(),
            generated_at: Utc::now(),
            core: CoreOvernight::default(),
            plugins: vec![PluginSection {
                plugin: "org.x".into(),
                level: StatusLevel::Ok,
                headline: "all good".into(),
                items: vec![BriefingItem {
                    id: "i".into(),
                    text: "line".into(),
                    taint: None,
                    tags: vec![],
                    template_id: None,
                    template_slots: BTreeMap::new(),
                }],
                actions: vec![],
                metrics: BTreeMap::new(),
                unreachable_reason: None,
            }],
            needs_action: vec![],
            text: String::new(),
        };
        doc.text = render_document(&doc);
        assert!(doc.text.find("## Core").unwrap() < doc.text.find("## org.x").unwrap());
        assert!(doc.text.contains("all good"));
        assert!(doc.text.contains("line"));
    }
}
