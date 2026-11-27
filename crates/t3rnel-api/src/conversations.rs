//! Conversation / approval / briefing REST routes
//! (`docs/sections/18-conversations-approvals-and-briefings.md`).
//!
//! Thin axum surface over the runtime services:
//! [`t3rnel_runtime::conversations::ConversationService`] and
//! [`t3rnel_runtime::briefing::BriefingService`]. Mounted in `server.rs`
//! with the same middleware stack as the plugin admin router.
//!
//! These routes NEVER return secret material: channel accounts expose
//! secret *names* only, approval replies go through the port's
//! re-validation, and briefing documents carry tainted plugin text as data.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use t3rnel_runtime::briefing::{BriefingService, CoreDataProvider, CoreOvernight};
use t3rnel_runtime::channels::ChannelRegistry;
use t3rnel_runtime::conversations::{
    ApprovalBinding, ApprovalPort, ApprovalSnapshot, ApprovalVerdict, ConversationError,
    ConversationEvent, ConversationService, NewApprovalRequest, Notification, Provenance,
};

use crate::pending_actions;

#[derive(Clone)]
pub struct ConversationState {
    pub service: Arc<ConversationService>,
    pub briefing: Arc<BriefingService>,
    pub channels: Arc<ChannelRegistry>,
    /// Shared webhook inbox for the WhatsApp Business (Cloud API) adapter —
    /// `Some` only when `[channels.whatsapp] phone_number_id` is configured.
    pub whatsapp_business: Option<Arc<t3rnel_runtime::channels::whatsapp::BusinessWebhookState>>,
}

// ---------------------------------------------------------------------------
// ApprovalPort over the pending-actions ledger (kernel approvals + asks)
// ---------------------------------------------------------------------------

/// Maps `P-<n>` pending items onto the conversation approval port.
/// Re-validation re-reads the live store — a stale channel YES decides
/// nothing (§2, §6).
pub struct PendingApprovalPort;

fn snapshot(item: &pending_actions::PendingAction) -> ApprovalSnapshot {
    ApprovalSnapshot {
        id: item.id.clone(),
        capability: item.kind.as_str().to_string(),
        summary: item.summary.clone(),
        risk: item.risk.clone().unwrap_or_else(|| "medium".to_string()),
        state: match item.state {
            pending_actions::PendingState::Pending => "pending".to_string(),
            pending_actions::PendingState::Approved => "approved".to_string(),
            pending_actions::PendingState::Rejected => "denied".to_string(),
            pending_actions::PendingState::Expired => "expired".to_string(),
            pending_actions::PendingState::Cancelled => "cancelled".to_string(),
        },
        expires_at: item.expires_at,
    }
}

#[async_trait::async_trait]
impl ApprovalPort for PendingApprovalPort {
    async fn lookup(&self, approval_ref: &str) -> Result<Option<ApprovalSnapshot>, String> {
        Ok(pending_actions::get_pending(approval_ref)
            .as_ref()
            .map(snapshot))
    }

    async fn pending(&self) -> Result<Vec<ApprovalSnapshot>, String> {
        Ok(pending_actions::list_pending()
            .iter()
            .filter(|i| i.state == pending_actions::PendingState::Pending)
            .map(snapshot)
            .collect())
    }

    async fn register(&self, request: &NewApprovalRequest) -> Result<String, String> {
        let item = pending_actions::create_pending(pending_actions::CreatePendingRequest {
            summary: request.summary.clone(),
            kind: Some(pending_actions::PendingKind::Approval),
            detail_ref: request.detail_ref.clone(),
            agent: request.agent.clone(),
            callback: None,
            risk: Some(request.risk.clone()),
            ttl_secs: request.ttl_secs,
            wa_message_id: None,
        });
        Ok(item.id)
    }

    async fn decide(
        &self,
        approval_ref: &str,
        verdict: ApprovalVerdict,
        note: Option<String>,
        via: &str,
    ) -> Result<(), String> {
        let decision = match verdict {
            ApprovalVerdict::Approve => "approve",
            ApprovalVerdict::Deny => "reject",
            // Defer never reaches decide() — handled by the service.
            ApprovalVerdict::Defer => return Err("defer is not a decision".to_string()),
        };
        pending_actions::resolve_pending(approval_ref, decision, note, via).map(|_| ())
    }

    fn revalidate(&self, binding: &ApprovalBinding) -> Result<(), String> {
        // Policy re-check at decision time: the backend record must still
        // exist, still be pending, and still be unexpired.
        let item = pending_actions::get_pending(&binding.approval_ref)
            .ok_or_else(|| format!("approval {} no longer exists", binding.approval_ref))?;
        if item.state != pending_actions::PendingState::Pending {
            return Err(format!(
                "approval {} is already {}",
                item.id,
                match item.state {
                    pending_actions::PendingState::Approved => "approved",
                    pending_actions::PendingState::Rejected => "rejected",
                    pending_actions::PendingState::Expired => "expired",
                    pending_actions::PendingState::Cancelled => "cancelled",
                    pending_actions::PendingState::Pending => "pending",
                }
            ));
        }
        if let Some(exp) = item.expires_at {
            if exp <= chrono::Utc::now() {
                return Err(format!("approval {} expired", item.id));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CoreDataProvider over the pending-actions ledger + kernel surfaces
// ---------------------------------------------------------------------------

/// Real overnight data: pending approvals from the ledger; jobs/budget/
/// sentinel sections are populated when their producers register data —
/// empty sections render as "nothing overnight", never invented.
pub struct LedgerCoreData;

#[async_trait::async_trait]
impl CoreDataProvider for LedgerCoreData {
    async fn overnight(
        &self,
        _since: chrono::DateTime<chrono::Utc>,
    ) -> Result<CoreOvernight, String> {
        let pending: Vec<ApprovalSnapshot> =
            PendingApprovalPort.pending().await.unwrap_or_default();
        Ok(CoreOvernight {
            metrics: [("pending_approvals".to_string(), pending.len().to_string())]
                .into_iter()
                .collect(),
            pending_approvals: pending,
            ..Default::default()
        })
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

fn cerr(e: ConversationError) -> (StatusCode, String) {
    let code = match &e {
        ConversationError::UnknownBinding(_) => StatusCode::NOT_FOUND,
        ConversationError::AlreadyResolved(..)
        | ConversationError::Expired(..)
        | ConversationError::Policy(..) => StatusCode::CONFLICT,
        ConversationError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        ConversationError::NoChannel(_) | ConversationError::NotRegistered(_) => {
            StatusCode::BAD_GATEWAY
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, e.to_string())
}

/// Build the router. `home` is the T3rnel home; `registry`/`service`/
/// `briefing` are shared with the rest of the daemon.
pub fn router(state: ConversationState) -> Router {
    Router::new()
        // Threads
        .route("/api/conversations/threads", get(list_threads))
        .route(
            "/api/conversations/threads/{id}",
            get(get_thread).post(send_thread_message),
        )
        .route(
            "/api/conversations/threads/{id}/agent",
            post(bind_thread_agent),
        )
        // Inbound injection (webchat/local channel + adapters feed the same path)
        .route("/api/conversations/inbound", post(inbound_event))
        // Approval bindings
        .route("/api/conversations/approvals", get(list_bindings))
        .route("/api/conversations/approvals/{id}", get(get_binding))
        .route(
            "/api/conversations/approvals/deliver",
            post(deliver_approval),
        )
        .route(
            "/api/conversations/approvals/{id}/reply",
            post(reply_approval),
        )
        // Notification fan-out (kernel/plugin events)
        .route("/api/conversations/notify", post(notify))
        // Channels — nested under /api/conversations because /api/channels
        // is already owned by the legacy channel-config surface (server.rs).
        .route("/api/conversations/channels", get(list_channels))
        .route(
            "/api/conversations/channels/accounts",
            get(list_accounts).post(link_account),
        )
        .route(
            "/api/conversations/channels/accounts/{channel}/{account}",
            axum::routing::delete(unlink_account),
        )
        // WhatsApp Business Cloud API webhook (18 §3/§7): Meta GET
        // verification handshake + POST message events. Registered always;
        // handlers fail closed when the adapter is not configured.
        .route(
            "/api/conversations/channels/whatsapp-business/webhook",
            get(wa_business_verify).post(wa_business_events),
        )
        // Briefing
        .route("/api/briefing/run", post(run_briefing))
        .route("/api/briefing/status", get(briefing_status))
        .route("/api/briefing/latest", get(briefing_latest))
        .route("/api/briefing/{date}", get(briefing_get))
        .with_state(state)
}

// -- threads ---------------------------------------------------------------

async fn list_threads(State(st): State<ConversationState>) -> impl IntoResponse {
    Json(serde_json::json!({ "threads": st.service.threads() }))
}

async fn get_thread(
    State(st): State<ConversationState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    st.service
        .thread(&id)
        .map(|t| Json(serde_json::to_value(t).unwrap()))
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no thread {id}")))
}

#[derive(Debug, Deserialize)]
struct SendMessageRequest {
    text: String,
    /// Channel account override; defaults to the thread's own account.
    #[serde(default)]
    account: Option<String>,
}

async fn send_thread_message(
    State(st): State<ConversationState>,
    Path(id): Path<String>,
    Json(req): Json<SendMessageRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let thread = st
        .service
        .thread(&id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no thread {id}")))?;
    let account = req.account.unwrap_or(thread.account);
    let receipt = st
        .service
        .send_message(
            &thread.channel,
            &account,
            thread_key_of(&thread.id),
            &req.text,
        )
        .await
        .map_err(cerr)?;
    Ok(Json(serde_json::to_value(receipt).unwrap()))
}

/// Thread id is "channel|account|thread_key"; recover the key portion.
fn thread_key_of(id: &str) -> &str {
    id.rsplit('|').next().unwrap_or(id)
}

#[derive(Debug, Deserialize)]
struct BindAgentRequest {
    agent_id: String,
}

async fn bind_thread_agent(
    State(st): State<ConversationState>,
    Path(id): Path<String>,
    Json(req): Json<BindAgentRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let thread = st
        .service
        .thread(&id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no thread {id}")))?;
    let thread_key = thread_key_of(&thread.id).to_string();
    let updated = st
        .service
        .bind_agent(&thread.channel, &thread.account, &thread_key, &req.agent_id)
        .map_err(cerr)?;
    Ok(Json(serde_json::to_value(updated).unwrap()))
}

// -- inbound ---------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct InboundRequest {
    channel: String,
    account: String,
    sender: String,
    #[serde(default)]
    thread_key: Option<String>,
    text: String,
    #[serde(default)]
    message_id: Option<String>,
}

async fn inbound_event(
    State(st): State<ConversationState>,
    Json(req): Json<InboundRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let thread_key = req.thread_key.unwrap_or_else(|| req.sender.clone());
    let event = ConversationEvent {
        channel: req.channel,
        account: req.account,
        sender: req.sender,
        thread_key,
        message_id: req.message_id,
        text: req.text,
        attachments: vec![],
        timestamp: chrono::Utc::now(),
        provenance: Provenance {
            source: "route:/api/conversations/inbound".into(),
            untrusted: true,
            data_classes: ["unclassified".to_string()].into_iter().collect(),
        },
    };
    let routed = st.service.handle_inbound(event).await.map_err(cerr)?;
    Ok(Json(serde_json::json!({ "routed": format!("{routed:?}") })))
}

// -- approvals --------------------------------------------------------------

async fn list_bindings(State(st): State<ConversationState>) -> impl IntoResponse {
    Json(serde_json::json!({ "bindings": st.service.bindings() }))
}

async fn get_binding(
    State(st): State<ConversationState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    st.service
        .binding(&id)
        .map(|b| Json(serde_json::to_value(b).unwrap()))
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("no binding {id}")))
}

#[derive(Debug, Deserialize)]
struct DeliverApprovalRequest {
    channel: String,
    account: String,
    sender: String,
    #[serde(default)]
    thread_key: Option<String>,
    capability: String,
    summary: String,
    #[serde(default = "default_risk")]
    risk: String,
    /// Existing backend approval id (e.g. "P-12"); omit to register a new ask.
    #[serde(default)]
    approval_ref: Option<String>,
    #[serde(default)]
    ttl_secs: Option<u64>,
}

fn default_risk() -> String {
    "medium".to_string()
}

async fn deliver_approval(
    State(st): State<ConversationState>,
    Json(req): Json<DeliverApprovalRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let thread_key = req.thread_key.unwrap_or_else(|| req.sender.clone());
    let ttl = req.ttl_secs.map(std::time::Duration::from_secs);
    let binding = st
        .service
        .deliver_approval(
            &req.channel,
            &req.account,
            &req.sender,
            &thread_key,
            &req.capability,
            &req.summary,
            &req.risk,
            req.approval_ref,
            ttl,
        )
        .await
        .map_err(cerr)?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::to_value(binding).unwrap()),
    ))
}

#[derive(Debug, Deserialize)]
struct ReplyRequest {
    /// "approve" | "deny" | "defer" (aliases yes/no/later accepted).
    verdict: String,
    #[serde(default)]
    note: Option<String>,
    /// Who decided — defaults to "api".
    #[serde(default = "default_via")]
    via: String,
}

fn default_via() -> String {
    "api".to_string()
}

async fn reply_approval(
    State(st): State<ConversationState>,
    Path(id): Path<String>,
    Json(req): Json<ReplyRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let verdict = match req.verdict.trim().to_ascii_lowercase().as_str() {
        "approve" | "approved" | "yes" => ApprovalVerdict::Approve,
        "deny" | "denied" | "reject" | "rejected" | "no" => ApprovalVerdict::Deny,
        "defer" | "later" | "snooze" => ApprovalVerdict::Defer,
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown verdict {other:?}; use approve|deny|defer"),
            ))
        }
    };
    st.service
        .resolve_binding(&id, verdict, &req.via, req.note)
        .await
        .map_err(cerr)?;
    Ok(Json(serde_json::json!({ "id": id, "resolved": true })))
}

// -- notify -----------------------------------------------------------------

async fn notify(
    State(st): State<ConversationState>,
    Json(n): Json<Notification>,
) -> impl IntoResponse {
    let results = st.service.notify(n).await;
    Json(
        serde_json::json!({ "deliveries": results.into_iter().map(|(k, r)| serde_json::json!({"target": k, "result": r})).collect::<Vec<_>>() }),
    )
}

// -- channels ---------------------------------------------------------------

async fn list_channels(State(st): State<ConversationState>) -> impl IntoResponse {
    let adapters = st
        .channels
        .adapter_ids()
        .into_iter()
        .map(|id| {
            let caps = st.channels.adapter(&id).map(|a| a.capabilities()).map(|c| {
                serde_json::json!({
                    "text": c.text, "media": c.media, "buttons": c.buttons,
                    "threads": c.threads, "receipts": c.receipts,
                })
            });
            serde_json::json!({ "id": id, "capabilities": caps })
        })
        .collect::<Vec<_>>();
    Json(serde_json::json!({ "adapters": adapters }))
}

async fn list_accounts(State(st): State<ConversationState>) -> impl IntoResponse {
    // Secret names are references only — never values (§3, §6).
    Json(serde_json::json!({ "accounts": st.channels.linked_accounts() }))
}

#[derive(Debug, Deserialize)]
struct LinkAccountRequest {
    channel: String,
    account: String,
    #[serde(default)]
    label: Option<String>,
    /// Vault secret names this account may resolve at connect.
    #[serde(default)]
    secret_names: Vec<String>,
}

async fn link_account(
    State(st): State<ConversationState>,
    Json(req): Json<LinkAccountRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    st.channels
        .link_account(t3rnel_runtime::channels::LinkedAccount {
            channel: req.channel,
            account: req.account,
            label: req.label,
            secret_names: req.secret_names,
            linked_at: chrono::Utc::now(),
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::CREATED)
}

async fn unlink_account(
    State(st): State<ConversationState>,
    Path((channel, account)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if st.channels.unlink_account(&channel, &account) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "account not linked".to_string()))
    }
}

// -- WhatsApp Business webhook (Cloud API mode, 18 §3/§7) ----------------------
//
// Meta calls these unauthenticated-by-design endpoints; the verify-token
// handshake plus the vault-brokered access token are the trust anchors.
// Payloads are normalized into ConversationEvents (tainted `untrusted`)
// and drained by the adapter's poll_inbound on the regular tick.

async fn wa_business_verify(
    State(st): State<ConversationState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some(biz) = &st.whatsapp_business else {
        return (
            StatusCode::NOT_FOUND,
            "whatsapp-business channel not configured",
        )
            .into_response();
    };
    let mode = q.get("hub.mode").map(String::as_str).unwrap_or("");
    let token = q.get("hub.verify_token").map(String::as_str).unwrap_or("");
    let challenge = q.get("hub.challenge").cloned().unwrap_or_default();
    if mode == "subscribe" && biz.verify_token_matches(token) {
        (StatusCode::OK, challenge).into_response()
    } else {
        (StatusCode::FORBIDDEN, "verify token mismatch").into_response()
    }
}

async fn wa_business_events(
    State(st): State<ConversationState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let Some(biz) = &st.whatsapp_business else {
        return Err((
            StatusCode::NOT_FOUND,
            "whatsapp-business channel not configured".to_string(),
        ));
    };
    if !biz.is_configured() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "whatsapp-business credentials not connected — link the account first".to_string(),
        ));
    }
    // X-Hub-Signature-256 (fail closed when an app secret is configured):
    // Meta signs the raw body with the app secret; a missing/bad signature
    // means the payload did not come from Meta.
    let sig = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok());
    match biz.signature_valid(&body, sig) {
        Some(true) => {}
        Some(false) => {
            return Err((
                StatusCode::FORBIDDEN,
                "X-Hub-Signature-256 verification failed".to_string(),
            ))
        }
        None => {} // no app secret configured — verify-token remains the anchor
    }
    let payload: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid json".to_string()))?;
    let ingested = biz.ingest(&payload);
    Ok(Json(
        serde_json::json!({ "ok": true, "ingested": ingested }),
    ))
}

// -- briefing ----------------------------------------------------------------

async fn run_briefing(State(st): State<ConversationState>) -> Result<impl IntoResponse, String> {
    st.briefing
        .run()
        .await
        .map(|doc| Json(serde_json::to_value(doc).unwrap()))
}

async fn briefing_status(State(st): State<ConversationState>) -> impl IntoResponse {
    let status = st.briefing.collect_status().await;
    Json(serde_json::json!({
        "sources": st.briefing.sources(),
        "plugin_status": status,
        "latest_date": st.briefing.latest().await.ok().flatten().map(|d| d.date),
    }))
}

async fn briefing_latest(
    State(st): State<ConversationState>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    match st.briefing.latest().await {
        Ok(Some(doc)) => Ok(Json(serde_json::to_value(doc).unwrap())),
        Ok(None) => Err((StatusCode::NOT_FOUND, "no briefing stored yet".into())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

async fn briefing_get(
    State(st): State<ConversationState>,
    Path(date): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    match st.briefing.get(&date).await {
        Ok(Some(doc)) => Ok(Json(serde_json::to_value(doc).unwrap())),
        Ok(None) => Err((StatusCode::NOT_FOUND, format!("no briefing for {date}"))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

/// `briefing:<date>` records land in the kernel's unified memory so
/// `memory_recall` surfaces them (§5.3 step 3).
pub struct KernelBriefingMemory {
    kernel: Arc<t3rnel_kernel::T3rnelKernel>,
}

impl KernelBriefingMemory {
    pub fn new(kernel: Arc<t3rnel_kernel::T3rnelKernel>) -> Self {
        KernelBriefingMemory { kernel }
    }
}

impl t3rnel_runtime::briefing::BriefingMemory for KernelBriefingMemory {
    fn store(&self, key: &str, value: serde_json::Value) -> Result<(), String> {
        use t3rnel_runtime::kernel_handle::KernelHandle;
        self.kernel.memory_store(key, value)
    }
}

/// Build the shared conversation stack for `build_router`: channel registry
/// (with the local dashboard adapter + vault broker), conversation service
/// (audit-chained), and briefing service (kernel memory sink).
pub fn build_conversation_stack(
    kernel: &Arc<t3rnel_kernel::T3rnelKernel>,
) -> (
    ConversationState,
    Arc<t3rnel_runtime::channels::LocalChannel>,
) {
    use t3rnel_runtime::channels::{ChannelAdapter, ChannelRegistry, LinkedAccount, LocalChannel};
    use t3rnel_runtime::plugin_vault::VaultBroker;

    let home = &kernel.config.home_dir;
    let mut registry = ChannelRegistry::new(home);
    let _ = registry.load();

    // Vault broker for channel credentials — same file the plugin hosts use.
    // Unlock is best-effort: the local adapter needs no secrets, and locked
    // credentialed adapters simply fail their connect until unlocked.
    let vault = Arc::new(VaultBroker::open(
        home.join(t3rnel_extensions::vault::VAULT_FILE_NAME),
        kernel.config.plugin_dev_mode,
    ));
    let _ = vault.unlock_ordered(None);
    registry.set_vault(vault);
    let registry = Arc::new(registry);

    // The dashboard/webchat is always a linked local account — it is the
    // user's own surface, not an external party.
    let local = LocalChannel::new("dashboard");
    registry.register_adapter(local.clone());
    let _ = registry.link_account(LinkedAccount {
        channel: local.id().to_string(),
        account: "dashboard".into(),
        label: Some("dashboard/webchat".into()),
        secret_names: vec![],
        linked_at: chrono::Utc::now(),
    });

    // -- WhatsApp adapters (docs/sections/18 §7 step 4) --------------------
    //
    // Personal mode wraps the Baileys gateway: the kernel process manager
    // (`ensure_gateway_running`) resolves/starts the gateway and returns its
    // loopback URL. The session credential is the gateway's own auth_store —
    // never a vault secret, never plugin-visible.
    let wa_kernel = kernel.clone();
    let wa_starter: t3rnel_runtime::channels::whatsapp::GatewayStarter = Arc::new(move || {
        let k = wa_kernel.clone();
        Box::pin(async move { t3rnel_kernel::whatsapp_gateway::ensure_gateway_running(&k).await })
    });
    let whatsapp =
        t3rnel_runtime::channels::whatsapp::WhatsAppAdapter::new().with_starter(wa_starter);
    registry.register_adapter(Arc::new(whatsapp));

    // Auto-link the personal account when WhatsApp is configured OR a
    // linked session already exists on disk (the QR flow predates the
    // channel registry — a stored auth_store IS the link). Account "default"
    // is the single gateway session; the linked phone number is reported by
    // the adapter's link state, not by the account id.
    let wa_configured = kernel.config.channels.whatsapp.is_some();
    let wa_session_exists = home
        .join("whatsapp-gateway")
        .join("auth_store")
        .join("creds.json")
        .exists();
    if wa_configured || wa_session_exists {
        let _ = registry.link_account(LinkedAccount {
            channel: "whatsapp".to_string(),
            account: "default".into(),
            label: Some("whatsapp (personal)".into()),
            secret_names: vec![],
            linked_at: chrono::Utc::now(),
        });
    }

    // Business mode (Cloud API): registered when a phone_number_id is
    // configured. Credentials are vault secrets declared on the linked
    // account (`channel:whatsapp-business:<acct>:access-token` etc.) — no
    // auto-link, since there is nothing to link without secrets.
    let mut whatsapp_business = None;
    if let Some(wa_cfg) = kernel.config.channels.whatsapp.as_ref() {
        if !wa_cfg.phone_number_id.is_empty() {
            let biz_state = t3rnel_runtime::channels::whatsapp::BusinessWebhookState::new();
            let biz =
                t3rnel_runtime::channels::whatsapp::WhatsAppBusinessAdapter::new(biz_state.clone())
                    .with_phone_number_id(wa_cfg.phone_number_id.clone());
            registry.register_adapter(Arc::new(biz));
            whatsapp_business = Some(biz_state);
        }
    }

    let mut conversations =
        ConversationService::open(home, registry.clone(), Arc::new(PendingApprovalPort))
            .expect("conversation store");
    conversations.set_audit_log(kernel.audit_log.clone());
    let conversations = Arc::new(conversations);

    let mut briefing = BriefingService::new(
        Arc::new(LedgerCoreData),
        conversations.clone(),
        Arc::new(t3rnel_runtime::briefing::FileBriefingStore::new(home)),
        t3rnel_runtime::briefing::BriefingConfig::default(),
    );
    briefing.set_memory(Arc::new(KernelBriefingMemory::new(kernel.clone())));
    let briefing = Arc::new(briefing);

    (
        ConversationState {
            service: conversations,
            briefing,
            channels: registry,
            whatsapp_business,
        },
        local,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use t3rnel_runtime::briefing::{
        BriefingConfig, BriefingDocument, BriefingService, BriefingStore, CoreDataProvider,
        CoreOvernight, FileBriefingStore,
    };
    use t3rnel_runtime::channels::{ChannelAdapter, ChannelRegistry, LinkedAccount, LocalChannel};
    use t3rnel_runtime::conversations::{ApprovalBinding, ApprovalVerdict, ConversationService};
    use t3rnel_runtime::plugin_vault::VaultBroker;
    use tower::ServiceExt as _;
    use zeroize::Zeroizing;

    /// In-memory approval backend for route tests — keeps the pending-actions
    /// store (and the live ~/.t3rnel home) out of the test path entirely.
    struct MemPort {
        items: Mutex<BTreeMap<String, ApprovalSnapshot>>,
        seq: Mutex<u64>,
    }

    impl MemPort {
        fn new() -> Arc<Self> {
            Arc::new(MemPort {
                items: Mutex::new(BTreeMap::new()),
                seq: Mutex::new(0),
            })
        }
        fn add(&self, summary: &str) -> String {
            let mut seq = self.seq.lock().unwrap();
            *seq += 1;
            let id = format!("P-{}", *seq);
            self.items.lock().unwrap().insert(
                id.clone(),
                ApprovalSnapshot {
                    id: id.clone(),
                    capability: "cap.test".into(),
                    summary: summary.into(),
                    risk: "high".into(),
                    state: "pending".into(),
                    expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
                },
            );
            id
        }
    }

    #[async_trait::async_trait]
    impl ApprovalPort for MemPort {
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
            _n: Option<String>,
            _v: &str,
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
            match self.items.lock().unwrap().get(&binding.approval_ref) {
                Some(s) if s.state == "pending" => Ok(()),
                Some(_) => Err("no longer pending".into()),
                None => Err("unknown".into()),
            }
        }
    }

    struct EmptyCore;
    #[async_trait::async_trait]
    impl CoreDataProvider for EmptyCore {
        async fn overnight(
            &self,
            _s: chrono::DateTime<chrono::Utc>,
        ) -> Result<CoreOvernight, String> {
            Ok(CoreOvernight::default())
        }
    }

    struct TestStore {
        inner: FileBriefingStore,
        saved: Mutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl BriefingStore for TestStore {
        async fn save(&self, doc: &BriefingDocument) -> Result<(), String> {
            self.saved.lock().unwrap().push(doc.date.clone());
            self.inner.save(doc).await
        }
        async fn latest(&self) -> Result<Option<BriefingDocument>, String> {
            self.inner.latest().await
        }
        async fn get(&self, date: &str) -> Result<Option<BriefingDocument>, String> {
            self.inner.get(date).await
        }
    }

    struct Fx {
        _home: tempfile::TempDir,
        app: Router,
        adapter: Arc<LocalChannel>,
        port: Arc<MemPort>,
    }

    fn fixture() -> Fx {
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
                linked_at: chrono::Utc::now(),
            })
            .unwrap();
        let vault = Arc::new(VaultBroker::open(
            home.path().join(t3rnel_extensions::vault::VAULT_FILE_NAME),
            false,
        ));
        vault
            .unlock_ordered(Some(Zeroizing::new([4u8; 32])))
            .unwrap();
        registry.set_vault(vault);
        let registry = Arc::new(registry);

        let port = MemPort::new();
        let mut conversations =
            ConversationService::open(home.path(), registry.clone(), port.clone()).unwrap();
        conversations.set_audit_log(Arc::new(t3rnel_runtime::audit::AuditLog::new()));
        let conversations = Arc::new(conversations);

        let briefing = Arc::new(BriefingService::new(
            Arc::new(EmptyCore),
            conversations.clone(),
            Arc::new(TestStore {
                inner: FileBriefingStore::new(home.path()),
                saved: Mutex::new(Vec::new()),
            }),
            BriefingConfig::default(),
        ));

        let state = ConversationState {
            service: conversations,
            briefing,
            channels: registry,
            whatsapp_business: None,
        };
        Fx {
            _home: home,
            app: router(state),
            adapter,
            port,
        }
    }

    async fn connect(f: &Fx) {
        f.service_connect().await;
    }

    impl Fx {
        async fn service_connect(&self) {
            // Connect the local adapter through the registry (vault attached).
            let creds = t3rnel_runtime::channels::BrokeredCreds::new(
                Arc::new({
                    let v = VaultBroker::open(
                        self._home
                            .path()
                            .join(t3rnel_extensions::vault::VAULT_FILE_NAME),
                        false,
                    );
                    v.unlock_ordered(Some(Zeroizing::new([4u8; 32]))).unwrap();
                    v
                }),
                "web",
                vec![],
            );
            self.adapter.connect(&creds).await.unwrap();
        }
    }

    fn post_json(uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::post(uri)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    #[tokio::test]
    async fn threads_and_inbound_roundtrip() {
        let f = fixture();
        connect(&f).await;
        // Inbound creates a thread.
        let res = f
            .app
            .clone()
            .oneshot(post_json(
                "/api/conversations/inbound",
                serde_json::json!({
                    "channel": "local:web", "account": "web", "sender": "+1555",
                    "text": "hello agent"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let res = f
            .app
            .clone()
            .oneshot(
                Request::get("/api/conversations/threads")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let threads = v["threads"].as_array().unwrap();
        assert_eq!(threads.len(), 1);
        let tid = threads[0]["id"].as_str().unwrap().to_string();
        assert!(tid.contains("+1555"));

        // Send a message on the thread.
        let res = f
            .app
            .clone()
            .oneshot(post_json(
                &format!("/api/conversations/threads/{tid}"),
                serde_json::json!({"text": "hi back"}),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(f.adapter.outbound_len(), 1);
    }

    #[tokio::test]
    async fn approval_deliver_reply_via_api() {
        let f = fixture();
        connect(&f).await;
        let pref = f.port.add("place order #9");
        // Deliver binding via API.
        let res = f
            .app
            .clone()
            .oneshot(post_json(
                "/api/conversations/approvals/deliver",
                serde_json::json!({
                    "channel": "local:web", "account": "web", "sender": "+1555",
                    "capability": "trade.order", "summary": "place order #9",
                    "risk": "high", "approval_ref": pref
                }),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let bid = v["id"].as_str().unwrap().to_string();
        assert!(bid.starts_with("AB-"));

        // YES via inbound decides it.
        let res = f
            .app
            .clone()
            .oneshot(post_json(
                "/api/conversations/inbound",
                serde_json::json!({
                    "channel": "local:web", "account": "web", "sender": "+1555",
                    "text": "YES"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["routed"].as_str().unwrap().contains("ApprovalDecided"));

        // Backend record approved; binding single-use.
        assert_eq!(
            f.port.items.lock().unwrap().get(&pref).unwrap().state,
            "approved"
        );
        let res = f
            .app
            .clone()
            .oneshot(post_json(
                &format!("/api/conversations/approvals/{bid}/reply"),
                serde_json::json!({"verdict": "deny"}),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn reply_endpoint_rejects_unknown_verdict() {
        let f = fixture();
        let res = f
            .app
            .clone()
            .oneshot(post_json(
                "/api/conversations/approvals/AB-999999/reply",
                serde_json::json!({"verdict": "shrug"}),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn channels_and_accounts_listing() {
        let f = fixture();
        let res = f
            .app
            .clone()
            .oneshot(
                Request::get("/api/conversations/channels")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["adapters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["id"].as_str().unwrap().starts_with("local:")));

        let res = f
            .app
            .clone()
            .oneshot(
                Request::get("/api/conversations/channels/accounts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["accounts"].as_array().unwrap().len(), 1);
        // Secret names are references only — account has none here.
        assert!(v["accounts"][0]["secret_names"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn briefing_run_and_latest() {
        let f = fixture();
        connect(&f).await;
        let res = f
            .app
            .clone()
            .oneshot(
                Request::post("/api/briefing/run")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["date"].as_str().unwrap().len() == 10);
        assert!(v["text"].as_str().unwrap().contains("Morning briefing"));

        let res = f
            .app
            .clone()
            .oneshot(
                Request::get("/api/briefing/latest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        let res = f
            .app
            .clone()
            .oneshot(
                Request::get("/api/briefing/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn notify_endpoint_fans_out() {
        let f = fixture();
        connect(&f).await;
        let res = f
            .app
            .clone()
            .oneshot(post_json(
                "/api/conversations/notify",
                serde_json::json!({
                    "level": "info", "title": "t", "body": "b"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(f.adapter.outbound_len(), 1);
    }
}
