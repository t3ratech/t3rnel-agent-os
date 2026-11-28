//! Plugin lifecycle REST routes (`17-implementation-guide.md` §9.7).
//!
//! Thin axum surface over [`t3rnel_runtime::plugin_lifecycle::PluginManager`].
//! Mount with `.merge(plugin_admin::router(manager, supervisor, opts))` in `server.rs` — the
//! exact mount line is recorded in `CLI-WIRING-REQUESTS.md`.
//!
//! These routes NEVER return secret material: manifests carry secret names
//! only, and InstallReport exposes the permission summary the user approved.

use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use t3rnel_runtime::plugin_auth::{ScopedTokenService, StoredGrant};
use t3rnel_runtime::plugin_lifecycle::{
    InstallOptions, LifecycleError, PluginManager, DEV_MODE_WARNING,
};
use t3rnel_runtime::plugin_supervisor::{PluginState, PluginSupervisor, SupervisorError};

#[derive(Clone)]
pub struct PluginAdminState {
    pub manager: Arc<PluginManager>,
    /// Starts, stops and watches plugin processes. `None` only where a test
    /// exercises the install surface alone.
    pub supervisor: Option<Arc<PluginSupervisor>>,
    pub install_opts: InstallOptions,
    /// Where an installed plugin's morning-briefing section is registered.
    pub briefing: Option<(
        Arc<t3rnel_runtime::plugin_grpc::PluginDispatch>,
        Arc<t3rnel_runtime::briefing::BriefingService>,
    )>,
    /// In-flight PKCE consent flows keyed by provider (single active flow
    /// per provider — starting a new one replaces the old).
    pub oauth_flows: Arc<dashmap::DashMap<String, PendingConsent>>,
}

#[derive(Debug, Deserialize)]
pub struct InstallRequest {
    /// Filesystem path to the unpacked plugin package directory.
    pub package_path: String,
    /// Dev-mode installs (unsigned) — only honoured when the host enabled it.
    #[serde(default)]
    pub dev_mode: bool,
}

/// The HTTP status a lifecycle failure maps to.
fn lifecycle_status(e: &LifecycleError) -> StatusCode {
    match e {
        LifecycleError::Manifest(_) | LifecycleError::MissingEntry(_) => StatusCode::BAD_REQUEST,
        LifecycleError::Signature(_) | LifecycleError::Revoked(_) => StatusCode::FORBIDDEN,
        LifecycleError::AccountBinding => StatusCode::FORBIDDEN,
        LifecycleError::Quarantined(_, _) => StatusCode::TOO_MANY_REQUESTS,
        LifecycleError::NoPrevious => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn err(e: LifecycleError) -> (StatusCode, String) {
    (lifecycle_status(&e), e.to_string())
}

/// Build the router. `home` is the T3rnel home (scratch dir in tests).
pub fn router(
    manager: Arc<PluginManager>,
    supervisor: Option<Arc<PluginSupervisor>>,
    opts: InstallOptions,
    briefing: Option<(
        Arc<t3rnel_runtime::plugin_grpc::PluginDispatch>,
        Arc<t3rnel_runtime::briefing::BriefingService>,
    )>,
) -> Router {
    Router::new()
        .route("/api/plugins", get(list_plugins))
        .route("/api/plugins/install", post(install_plugin))
        .route(
            "/api/plugins/{id}",
            get(get_plugin).delete(uninstall_plugin),
        )
        .route("/api/plugins/{id}/update", post(update_plugin))
        .route("/api/plugins/{id}/rollback", post(rollback_plugin))
        .route("/api/plugins/{id}/launch-check", get(launch_check))
        .route("/api/plugins/oauth/start", post(oauth_start))
        .route("/api/plugins/oauth/complete", post(oauth_complete))
        .route("/api/plugins/oauth/status", get(oauth_status))
        .route("/api/plugins/oauth/bind", post(oauth_bind))
        .route("/api/plugins/{id}/start", post(start_plugin))
        .route("/api/plugins/{id}/stop", post(stop_plugin))
        .route("/api/plugins/{id}/restart", post(restart_plugin))
        .route("/api/plugins/{id}/state", get(plugin_state))
        .route("/api/plugins/{id}/status", get(plugin_status))
        .route("/api/plugins/{id}/clear-quarantine", post(clear_quarantine))
        .route("/api/plugins/{id}/route/{*path}", axum::routing::any(plugin_route))
        .with_state(PluginAdminState {
            manager,
            supervisor,
            install_opts: opts,
            briefing,
            oauth_flows: Arc::new(dashmap::DashMap::new()),
        })
}

/// Resolve the effective install options for a request. A `dev_mode` flag in
/// the request body is honoured ONLY when the host itself runs with
/// `plugin_dev_mode` — production hosts ignore it entirely.
fn effective_opts(st: &PluginAdminState, req_dev_mode: bool) -> InstallOptions {
    let mut opts = st.install_opts.clone();
    if req_dev_mode && st.install_opts.dev_mode {
        opts.dev_mode = true;
        opts.require_signature = false;
    }
    opts
}

fn supervisor_err(e: SupervisorError) -> (StatusCode, String) {
    let code = match &e {
        SupervisorError::NotPermitted(_, inner) => lifecycle_status(inner),
        SupervisorError::Unconfined(..) => StatusCode::SERVICE_UNAVAILABLE,
        SupervisorError::NotRunning(_) => StatusCode::CONFLICT,
        SupervisorError::Launch(..) | SupervisorError::NotReady(..) => StatusCode::BAD_GATEWAY,
    };
    (code, e.to_string())
}

fn supervisor_of(st: &PluginAdminState) -> Result<&Arc<PluginSupervisor>, (StatusCode, String)> {
    st.supervisor.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "this host does not supervise plugins".to_string(),
    ))
}

async fn start_plugin(
    State(st): State<PluginAdminState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    supervisor_of(&st)?.start(&id).await.map_err(supervisor_err)?;
    Ok(Json(serde_json::json!({ "id": id, "state": supervisor_of(&st)?.state(&id) })))
}

async fn stop_plugin(
    State(st): State<PluginAdminState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    supervisor_of(&st)?.stop(&id).await.map_err(supervisor_err)?;
    Ok(Json(serde_json::json!({ "id": id, "state": PluginState::Stopped })))
}

async fn restart_plugin(
    State(st): State<PluginAdminState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    supervisor_of(&st)?.restart(&id).await.map_err(supervisor_err)?;
    Ok(Json(serde_json::json!({ "id": id, "state": supervisor_of(&st)?.state(&id) })))
}

async fn plugin_state(
    State(st): State<PluginAdminState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    Ok(Json(serde_json::json!({ "id": id, "state": supervisor_of(&st)?.state(&id) })))
}

/// How long a plugin gets to answer a status question before it is reported as unreachable.
const STATUS_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);

fn level_name(level: i32) -> &'static str {
    match level {
        1 => "ok",
        2 => "attention",
        3 => "critical",
        4 => "unreachable",
        _ => "unspecified",
    }
}

/// Everything an operator or agent needs to see about one plugin: the installed version
/// (from the signed manifest on disk), what the supervisor is doing with it, and, when it
/// is running, the status report it gives the core.
async fn plugin_detail(st: &PluginAdminState, id: &str) -> serde_json::Value {
    let version = std::fs::read(st.manager.plugins_dir().join(id).join("manifest.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|m| m.get("version").and_then(|v| v.as_str()).map(str::to_owned));
    let state = st.supervisor.as_ref().map(|s| s.state(id));
    let running = matches!(state, Some(PluginState::Running { .. }));
    let status = match (&st.briefing, running) {
        (Some((dispatch, _)), true) => {
            let ident = Some(t3rnel_runtime::plugin_grpc::pb::PluginIdentity {
                id: id.to_owned(),
                ..Default::default()
            });
            let ask = dispatch.status_query(
                id,
                t3rnel_runtime::plugin_grpc::pb::StatusQueryRequest { plugin: ident, since: None },
            );
            match tokio::time::timeout(STATUS_DEADLINE, ask).await {
                Ok(Ok(r)) => serde_json::json!({
                    "level": level_name(r.level),
                    "headline": r.headline,
                    "metrics": r.metrics,
                    "detail": r.detail,
                }),
                Ok(Err(e)) => serde_json::json!({ "level": "unreachable", "headline": e.message() }),
                Err(_) => serde_json::json!({ "level": "unreachable", "headline": "no answer within the deadline" }),
            }
        }
        _ => serde_json::Value::Null,
    };
    serde_json::json!({ "id": id, "version": version, "state": state, "status": status })
}

async fn plugin_status(
    State(st): State<PluginAdminState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !st.manager.list().contains(&id) {
        return Err((StatusCode::NOT_FOUND, format!("plugin {id} is not installed")));
    }
    Ok(Json(plugin_detail(&st, &id).await))
}

/// Forget a plugin's crashes and start it again. The owner's action; a plugin cannot reach it.
async fn clear_quarantine(
    State(st): State<PluginAdminState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let forgotten = st.manager.clear_quarantine(&id).map_err(err)?;
    if let Some(sup) = &st.supervisor {
        sup.start(&id).await.map_err(supervisor_err)?;
    }
    Ok(Json(serde_json::json!({
        "id": id,
        "crashes_forgotten": forgotten,
        "state": st.supervisor.as_ref().map(|s| s.state(&id)),
    })))
}

/// Largest request body forwarded to a plugin route.
const ROUTE_BODY_LIMIT: usize = 1024 * 1024;
/// How long a plugin gets to answer a forwarded route call.
const ROUTE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// The front door for a plugin's own HTTP routes: `/api/plugins/{id}/route/<path>` is forwarded to
/// the plugin over the connection the core holds with it (`PluginCallbacks.HandleRoute`). The
/// caller has already passed the daemon's own authentication; the plugin sees only the principal
/// `api`, never the caller's credentials, because `authorization` and `cookie` are not forwarded.
async fn plugin_route(
    State(st): State<PluginAdminState>,
    Path((id, tail)): Path<(String, String)>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let Some((dispatch, _)) = &st.briefing else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "this host does not dispatch to plugins".into()));
    };
    if !st.manager.list().contains(&id) {
        return Err((StatusCode::NOT_FOUND, format!("plugin {id} is not installed")));
    }
    if body.len() > ROUTE_BODY_LIMIT {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "request body too large".into()));
    }
    let path = match uri.query() {
        Some(q) => format!("/{tail}?{q}"),
        None => format!("/{tail}"),
    };
    let forwarded: std::collections::HashMap<String, String> = headers
        .iter()
        .filter(|(k, _)| {
            !matches!(k.as_str(), "authorization" | "cookie" | "host" | "content-length" | "x-api-key")
        })
        .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
        .collect();
    let request = t3rnel_runtime::plugin_grpc::pb::RouteRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        method: method.as_str().to_string(),
        path,
        headers: forwarded,
        body: Some(t3rnel_runtime::plugin_grpc::pb::Payload {
            data: body.to_vec(),
            content_type: headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_string(),
            ..Default::default()
        }),
        principal: "api".to_string(),
    };
    let reply = tokio::time::timeout(ROUTE_DEADLINE, dispatch.handle_route(&id, request))
        .await
        .map_err(|_| (StatusCode::GATEWAY_TIMEOUT, format!("plugin {id} did not answer in time")))?
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("plugin {id}: {}", e.message())))?;
    let status = StatusCode::from_u16(reply.status as u16).unwrap_or(StatusCode::BAD_GATEWAY);
    let (data, content_type) = reply
        .body
        .map(|b| (b.data, if b.content_type.is_empty() { "application/json".to_string() } else { b.content_type }))
        .unwrap_or_default();
    axum::response::Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(axum::body::Body::from(data))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn list_plugins(State(st): State<PluginAdminState>) -> impl IntoResponse {
    let dev_mode = st.install_opts.dev_mode;
    let ids = st.manager.list();
    let details = futures::future::join_all(ids.iter().map(|id| plugin_detail(&st, id))).await;
    Json(serde_json::json!({
        "plugins": ids,
        "details": details,
        // What each plugin is doing right now (running, restarting, quarantined, refused).
        "states": st.supervisor.as_ref().map(|s| s.states().into_iter().collect::<std::collections::BTreeMap<_, _>>()),
        // Persistent, machine-readable dev-mode warning — any UI or agent that
        // lists plugins sees that this host accepts unsigned packages.
        "dev_mode": dev_mode,
        "dev_mode_warning": if dev_mode { Some(DEV_MODE_WARNING) } else { None },
        "dev_mode_banner": if dev_mode {
            Some(format!(
                "⚠ DEV MODE: plugin dev mode ENABLED on this host — {DEV_MODE_WARNING}"
            ))
        } else {
            None
        },
    }))
}

async fn install_plugin(
    State(st): State<PluginAdminState>,
    Json(req): Json<InstallRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let opts = effective_opts(&st, req.dev_mode);
    let report = st
        .manager
        .install(PathBuf::from(&req.package_path).as_path(), &opts)
        .map_err(err)?;
    // Installing a plugin starts it. A refusal here (cannot confine, tampered) is
    // reported by the state endpoint, not turned into an install failure: the
    // package is installed either way.
    if let Some((dispatch, briefing)) = &st.briefing {
        briefing.register_source(Arc::new(
            t3rnel_runtime::plugin_grpc::DispatchBriefingSource::new(
                dispatch.clone(),
                report.plugin_id.clone(),
            ),
        ));
    }
    if let Some(sup) = &st.supervisor {
        if let Err(e) = sup.start(&report.plugin_id).await {
            tracing::warn!(plugin = %report.plugin_id, "installed but not started: {e}");
        }
    }
    Ok((
        StatusCode::CREATED,
        Json(serde_json::to_value(report).unwrap()),
    ))
}

async fn get_plugin(
    State(st): State<PluginAdminState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if !st.manager.list().contains(&id) {
        return Err((StatusCode::NOT_FOUND, format!("plugin {id} not installed")));
    }
    Ok(Json(serde_json::json!({ "id": id, "installed": true })))
}

async fn uninstall_plugin(
    State(st): State<PluginAdminState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if let Some(sup) = &st.supervisor {
        // Stop the process first; a plugin that was never running is fine.
        let _ = sup.stop(&id).await;
    }
    st.manager.uninstall(&id).map_err(err)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn update_plugin(
    State(st): State<PluginAdminState>,
    Path(id): Path<String>,
    Json(req): Json<InstallRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _ = id; // update targets the manifest's own id; path must match install
    let opts = effective_opts(&st, req.dev_mode);
    let report = st
        .manager
        .update(PathBuf::from(&req.package_path).as_path(), &opts)
        .map_err(err)?;
    if let Some(sup) = &st.supervisor {
        // The new files are in place: run them, not the old process.
        if let Err(e) = sup.restart(&report.plugin_id).await {
            tracing::warn!(plugin = %report.plugin_id, "updated but not restarted: {e}");
        }
    }
    Ok(Json(serde_json::to_value(report).unwrap()))
}

async fn rollback_plugin(
    State(st): State<PluginAdminState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if let Some(sup) = &st.supervisor {
        let _ = sup.stop(&id).await;
    }
    st.manager.rollback(&id).map_err(err)?;
    if let Some(sup) = &st.supervisor {
        if let Err(e) = sup.start(&id).await {
            tracing::warn!(plugin = %id, "rolled back but not started: {e}");
        }
    }
    Ok(Json(serde_json::json!({ "id": id, "rolled_back": true })))
}

async fn launch_check(
    State(st): State<PluginAdminState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    match st.manager.launch_permitted(&id) {
        Ok(()) => Ok(Json(serde_json::json!({ "id": id, "launch": "permitted" }))),
        Err(e) => Err(err(e)),
    }
}

// ---------------------------------------------------------------------------
// OAuth consent → vault grant (18 §8)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct OAuthStartRequest {
    /// Provider key: "google" | "github" | "microsoft" | "slack" (or any
    /// bundled integration whose template declares `[oauth]`).
    pub provider: String,
    /// Optional OAuth client id override (defaults come from config).
    #[serde(default)]
    pub client_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthCompleteRequest {
    pub provider: String,
    /// Authorization code — normally delivered by the loopback callback;
    /// supplied explicitly for non-browser test flows.
    pub code: String,
}

/// Find the bundled template whose `[oauth]` block serves `provider`.
fn oauth_template(provider: &str) -> Option<t3rnel_extensions::OAuthTemplate> {
    for (_id, toml_str) in t3rnel_extensions::bundled::bundled_integrations() {
        if let Ok(t) = toml::from_str::<t3rnel_extensions::IntegrationTemplate>(toml_str) {
            if let Some(oauth) = t.oauth {
                if oauth.provider == provider {
                    return Some(oauth);
                }
            }
        }
    }
    None
}

/// Build the vault-backed token service used to persist consent grants.
/// Grants are provider-keyed (`oauth:<provider>`), shared by every plugin —
/// `plugin_id` only labels issued `authref:` tokens, so "host" is correct
/// for user-level consent.
fn consent_token_service(
    st: &PluginAdminState,
) -> Result<ScopedTokenService, (StatusCode, String)> {
    let home = st.manager.home().to_path_buf();
    let vault = std::sync::Arc::new(t3rnel_runtime::plugin_vault::VaultBroker::open(
        home.join(t3rnel_extensions::vault::VAULT_FILE_NAME),
        st.install_opts.dev_mode,
    ));
    vault
        .unlock_ordered(None)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(ScopedTokenService::new(vault, "host"))
}

/// Host-side record of an in-flight consent flow — everything `/complete`
/// and `/status` need without holding the callback receiver (owned by the
/// background task).
pub struct PendingConsent {
    pub auth_url: String,
    pub state: String,
    pub callback_port: u16,
    pub redirect_uri: String,
    pub token_url: String,
    pub client_id: String,
    /// PKCE verifier — credential-adjacent, lives only in this process.
    pub verifier: zeroize::Zeroizing<String>,
    /// Aborts the loopback callback server when the flow is completed
    /// explicitly or superseded.
    pub abort: tokio::task::AbortHandle,
    pub started_at: String,
}

/// Persist OAuth tokens as a vault grant (`oauth:<provider>`) via the same
/// `ScopedTokenService::store_grant` path plugin Auth.Token issuance reads.
async fn store_consent_grant(
    st: &PluginAdminState,
    provider: &str,
    template: &t3rnel_extensions::OAuthTemplate,
    client_id: &str,
    tokens: t3rnel_extensions::oauth::OAuthTokens,
) -> Result<(), String> {
    let svc = consent_token_service(st).map_err(|(_, m)| m)?;
    let scopes: Vec<String> = tokens
        .scope
        .split_whitespace()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let expires_at = if tokens.expires_in == 0 {
        None
    } else {
        Some(chrono::Utc::now().timestamp() + tokens.expires_in as i64)
    };
    svc.store_grant(
        provider,
        StoredGrant {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_at,
            scopes: if scopes.is_empty() {
                template.scopes.clone()
            } else {
                scopes
            },
            token_endpoint: Some(template.token_url.clone()),
            client_id: Some(client_id.to_string()),
            client_secret: None,
            service_account: None,
            // The plugins installed now whose signed manifest binds this
            // provider; any other plugin must be bound explicitly.
            bound_plugins: st
                .manager
                .plugins_binding_secret(&format!("oauth-access:{provider}")),
        },
    )
    .map_err(|e| e.to_string())
}

/// POST /api/plugins/oauth/start — begin a PKCE consent flow. Returns the
/// authorization URL; the loopback callback completes the flow in the
/// background and stores the grant. `client_id` overrides the configured
/// default for this provider.
async fn oauth_start(
    State(st): State<PluginAdminState>,
    Json(req): Json<OAuthStartRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let provider = req.provider.trim().to_string();
    let template = oauth_template(&provider).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("no OAuth template for provider {provider:?}"),
        )
    })?;
    let client_id = req.client_id.unwrap_or_else(|| {
        t3rnel_extensions::oauth::resolve_client_ids(&t3rnel_types::config::OAuthConfig::default())
            .get(&provider)
            .cloned()
            .unwrap_or_default()
    });
    if client_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("no client_id configured for provider {provider:?}"),
        ));
    }
    let flow = t3rnel_extensions::oauth::begin_pkce_flow(&template, &client_id)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let auth_url = flow.auth_url.clone();
    let callback_port = flow.callback_port;
    let state = flow.state.clone();

    // Register the pending flow for /status + /complete, then spawn the
    // background completion that awaits the loopback callback.
    st.oauth_flows.insert(
        provider.clone(),
        PendingConsent {
            auth_url: auth_url.clone(),
            state: state.clone(),
            callback_port,
            redirect_uri: flow.redirect_uri.clone(),
            token_url: flow.token_url.clone(),
            client_id: client_id.clone(),
            verifier: zeroize::Zeroizing::new(flow.verifier.to_string()),
            abort: flow.server_handle.abort_handle(),
            started_at: chrono::Utc::now().to_rfc3339(),
        },
    );
    {
        let flows = st.oauth_flows.clone();
        let provider_bg = provider.clone();
        let st_bg = st.clone();
        tokio::spawn(async move {
            let outcome = async {
                let code = tokio::time::timeout(std::time::Duration::from_secs(300), flow.code_rx)
                    .await
                    .map_err(|_| "oauth callback timed out".to_string())?
                    .map_err(|_| "oauth callback channel closed".to_string())?
                    .map_err(|e| e.to_string())?;
                flow.server_handle.abort();
                let tokens = t3rnel_extensions::oauth::exchange_code(
                    &flow.token_url,
                    &flow.redirect_uri,
                    &flow.client_id,
                    flow.verifier.as_str(),
                    &code,
                )
                .await
                .map_err(|e| e.to_string())?;
                store_consent_grant(&st_bg, &provider_bg, &template, &client_id, tokens).await
            }
            .await;
            flows.remove(&provider_bg);
            match outcome {
                Ok(()) => tracing::info!("oauth consent stored for {provider_bg}"),
                Err(e) => tracing::warn!("oauth consent for {provider_bg} failed: {e}"),
            }
        });
    }

    Ok(Json(serde_json::json!({
        "provider": provider,
        "auth_url": auth_url,
        "callback_port": callback_port,
        "state": state,
    })))
}

/// POST /api/plugins/oauth/complete — finish a started flow explicitly with
/// an authorization code (non-browser test-provider path; the loopback
/// callback path completes in the background without this call).
async fn oauth_complete(
    State(st): State<PluginAdminState>,
    Json(req): Json<OAuthCompleteRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let provider = req.provider.trim().to_string();
    let pending = st
        .oauth_flows
        .remove(&provider)
        .map(|(_, p)| p)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("no pending oauth flow for {provider:?}"),
            )
        })?;
    pending.abort.abort();
    let template = oauth_template(&provider).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("no OAuth template for provider {provider:?}"),
        )
    })?;
    let tokens = t3rnel_extensions::oauth::exchange_code(
        &pending.token_url,
        &pending.redirect_uri,
        &pending.client_id,
        pending.verifier.as_str(),
        &req.code,
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    store_consent_grant(&st, &provider, &template, &pending.client_id, tokens)
        .await
        .map_err(|m| (StatusCode::INTERNAL_SERVER_ERROR, m))?;
    Ok(Json(
        serde_json::json!({ "provider": provider, "linked": true }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct OAuthBindRequest {
    pub provider: String,
    pub plugin: String,
}

/// POST /api/plugins/oauth/bind — let one more installed plugin have this
/// provider's token injected for it. The plugin's signed manifest must bind
/// `oauth-access:<provider>`; the owner is saying "yes, this plugin too".
async fn oauth_bind(
    State(st): State<PluginAdminState>,
    Json(req): Json<OAuthBindRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let secret = format!("oauth-access:{}", req.provider);
    if !st.manager.plugins_binding_secret(&secret).contains(&req.plugin) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{} is not installed or does not bind {secret}", req.plugin),
        ));
    }
    let svc = consent_token_service(&st)?;
    svc.bind_plugin(&req.provider, &req.plugin)
        .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    Ok(Json(serde_json::json!({ "bound": req.plugin, "provider": req.provider })))
}

/// GET /api/plugins/oauth/status?provider=X — pending-flow and stored-grant
/// state. Never returns token material.
async fn oauth_status(
    State(st): State<PluginAdminState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let provider = q.get("provider").cloned().unwrap_or_default();
    let pending = st.oauth_flows.get(&provider).map(|p| {
        serde_json::json!({
            "auth_url": p.auth_url,
            "callback_port": p.callback_port,
            "state": p.state,
            "started_at": p.started_at,
        })
    });
    let linked = match consent_token_service(&st) {
        Ok(svc) => {
            svc.issue(&provider, &[], Some(1)).await.is_ok() || grant_present(&st, &provider).await
        }
        Err(_) => false,
    };
    Ok(Json(serde_json::json!({
        "provider": provider,
        "pending": pending,
        "linked": linked,
    })))
}

/// Vault presence check for `oauth:<provider>` — `issue()` requires a
/// non-empty scope list, so it can never prove presence on its own; the
/// service's `grant_usable` checks the stored grant directly.
async fn grant_present(st: &PluginAdminState, provider: &str) -> bool {
    let Ok(svc) = consent_token_service(st) else {
        return false;
    };
    svc.grant_usable(provider).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    fn test_router() -> (Router, tempfile::TempDir) {
        let home = tempfile::tempdir().unwrap();
        let mgr = Arc::new(PluginManager::new(home.path()));
        let opts = InstallOptions {
            require_signature: false,
            trusted_keys: vec![],
            dev_mode: true,
        };
        (router(mgr, None, opts, None), home)
    }

    #[tokio::test]
    async fn list_empty_and_install_roundtrip() {
        let (app, _home) = test_router();
        let res = app
            .clone()
            .oneshot(Request::get("/api/plugins").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);

        // Build a minimal package on disk.
        let pkg = tempfile::tempdir().unwrap();
        let manifest = serde_json::json!({
            "id": "org.test.api",
            "version": "1.0.0",
            "name": "API Test Plugin",
            "runtime": "process",
            "entry": "plugin",
            "migrations": [],
            "permissions_summary": ["capability: fs.read"]
        });
        std::fs::write(
            pkg.path().join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let entry = pkg.path().join("plugin");
        std::fs::write(&entry, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let res = app
            .clone()
            .oneshot(
                Request::post("/api/plugins/install")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "package_path": pkg.path().to_string_lossy(),
                            "dev_mode": true
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);

        let res = app
            .oneshot(Request::get("/api/plugins").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["plugins"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("org.test.api")));
        // The list carries each plugin's version and state, not only its id.
        let detail = &v["details"][0];
        assert_eq!(detail["id"], "org.test.api");
        assert_eq!(detail["version"], "1.0.0");
    }

    #[tokio::test]
    async fn one_plugins_status_names_its_version_and_unknown_ids_are_404() {
        let (app, home) = test_router();
        let plugin_dir = home.path().join("plugins").join("org.test.one");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(
            plugin_dir.join("manifest.json"),
            br#"{"id":"org.test.one","version":"2.3.4","name":"One"}"#,
        )
        .unwrap();
        let res = app
            .clone()
            .oneshot(Request::get("/api/plugins/org.test.one/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["version"], "2.3.4");
        // No supervisor in this router, so there is no state and no status to report.
        assert!(v["state"].is_null() && v["status"].is_null());

        let res = app
            .oneshot(Request::get("/api/plugins/org.test.nope/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_route_call_for_an_unknown_plugin_or_without_dispatch_is_refused() {
        // This router has no dispatch (None): the front door says so instead of guessing.
        let (app, _home) = test_router();
        let res = app
            .oneshot(Request::get("/api/plugins/org.test.nope/route/plugin/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn every_status_level_has_a_stable_name() {
        let names: Vec<_> = (0..=5).map(level_name).collect();
        assert_eq!(names, ["unspecified", "ok", "attention", "critical", "unreachable", "unspecified"]);
    }

    #[tokio::test]
    async fn account_binding_maps_to_forbidden() {
        let (app, _home) = test_router();
        let pkg = tempfile::tempdir().unwrap();
        // entitlement_account bound to a fingerprint this home will never
        // produce — signature checks pass (dev mode, unsigned) but the
        // account binding must refuse with 403, not 500.
        let manifest = serde_json::json!({
            "id": "org.test.bound",
            "version": "1.0.0",
            "name": "Bound Plugin",
            "runtime": "process",
            "entry": "plugin",
            "migrations": [],
            "permissions_summary": [],
            "entitlement_account": "00".repeat(32)
        });
        std::fs::write(
            pkg.path().join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let entry = pkg.path().join("plugin");
        std::fs::write(&entry, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let res = app
            .oneshot(
                Request::post("/api/plugins/install")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "package_path": pkg.path().to_string_lossy(),
                            "dev_mode": true
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("entitlement_account mismatch"), "got {text}");
    }
}
