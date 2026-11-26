//! T3rnel daemon server — boots the kernel and serves the HTTP API.

use crate::channel_bridge;
use crate::middleware;
use crate::rate_limiter;
use crate::routes::{self, AppState};
use crate::webchat;
use crate::ws;
use axum::Router;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use t3rnel_kernel::T3rnelKernel;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Daemon info written to `~/.t3rnel/daemon.json` so the CLI can find us.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DaemonInfo {
    pub pid: u32,
    pub listen_addr: String,
    pub started_at: String,
    pub version: String,
    pub platform: String,
}

/// Build the full API router with all routes, middleware, and state.
///
/// This is extracted from `run_daemon()` so embedders can share the API router.
/// can create the router without starting the full daemon lifecycle.
///
/// Returns `(router, shared_state)`. The caller can use `state.bridge_manager`
/// to shut down the bridge on exit.
pub async fn build_router(
    kernel: Arc<T3rnelKernel>,
    listen_addr: SocketAddr,
) -> (Router<()>, Arc<AppState>) {
    // Start channel bridges (Telegram, etc.)
    let bridge = channel_bridge::start_channel_bridge(kernel.clone()).await;

    let channels_config = kernel.config.channels.clone();
    // Share the kernel's tracker — it is the instance the LLM fallback chain
    // enforces against, and it was already seeded from the model catalog at boot.
    // Creating a second one here would show usage the drivers never consult.
    let health_tracker = kernel.health_tracker.clone();

    // Plugin gRPC dispatch (plugin.proto host services + PluginCallbacks
    // client cache). Loopback by default; `plugin_grpc_addr = ""` disables.
    let plugin_dispatch = {
        let addr = kernel.config.plugin_grpc_addr.trim();
        if addr.is_empty() {
            None
        } else {
            let dispatch = Arc::new(t3rnel_runtime::plugin_grpc::PluginDispatch::new(
                kernel.config.home_dir.clone(),
                kernel.config.plugin_dev_mode,
            ));
            match addr.parse::<std::net::SocketAddr>() {
                Ok(sock) => {
                    let d = dispatch.clone();
                    tokio::spawn(async move {
                        if let Err(e) = d.serve(sock).await {
                            tracing::error!("plugin gRPC dispatch exited: {e}");
                        }
                    });
                    tracing::info!("plugin gRPC dispatch listening on {sock}");
                    Some(dispatch)
                }
                Err(_) => {
                    tracing::error!(
                        "plugin_grpc_addr {addr:?} is not a socket address — dispatch disabled"
                    );
                    None
                }
            }
        }
    };

    let state = Arc::new(AppState {
        kernel: kernel.clone(),
        started_at: Instant::now(),
        peer_registry: kernel.peer_registry.get().map(|r| Arc::new(r.clone())),
        bridge_manager: tokio::sync::Mutex::new(bridge),
        channels_config: tokio::sync::RwLock::new(channels_config),
        shutdown_notify: Arc::new(tokio::sync::Notify::new()),
        clawhub_cache: dashmap::DashMap::new(),
        provider_probe_cache: t3rnel_runtime::provider_health::ProbeCache::new(),
        budget_config: Arc::new(tokio::sync::RwLock::new(kernel.config.budget.clone())),
        team_store: crate::team_store::TeamStore::persistent(
            kernel.memory.usage_conn(),
            &kernel.config.home_dir.join("a2a-payload.key"),
        )
        .unwrap_or_else(|e| panic!("failed to initialize durable team store: {e}")),
        winrate_tracker: tokio::sync::Mutex::new(
            t3rnel_prompts::WinRateTracker::open(kernel.config.home_dir.join("prompt-winrates.db"))
                .unwrap_or_else(|e| panic!("failed to initialize win-rate tracker: {e}")),
        ),
        ide_commands: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        ide_command_notify: Arc::new(tokio::sync::Notify::new()),
        health_tracker,
        plugin_dispatch,
    });

    // Start WS cron broadcaster — subscribes to kernel event bus and pushes
    // cron job results to all connected WebSocket clients in real-time.
    ws::start_ws_cron_broadcaster(kernel.clone());

    // CORS: allow localhost origins by default. If API key is set, the API
    // is protected anyway. For development, permissive CORS is convenient.
    let cors = if state.kernel.config.api_key.trim().is_empty() {
        // No auth → restrict CORS to localhost origins (include both 127.0.0.1 and localhost)
        let port = listen_addr.port();
        let mut origins: Vec<axum::http::HeaderValue> = vec![
            format!("http://{listen_addr}").parse().unwrap(),
            format!("http://localhost:{port}").parse().unwrap(),
            "null".parse().unwrap(), // For Electron file://
        ];
        // Also allow common dev ports
        for p in [3000u16, 8080] {
            if p != port {
                if let Ok(v) = format!("http://127.0.0.1:{p}").parse() {
                    origins.push(v);
                }
                if let Ok(v) = format!("http://localhost:{p}").parse() {
                    origins.push(v);
                }
            }
        }
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
    } else {
        // Auth enabled → we can be more permissive with CORS because the API
        // key protects all sensitive endpoints. Still restrict to known-safe
        // origins rather than fully permissive.
        let allowed_origins =
            tower_http::cors::AllowOrigin::predicate(|origin: &axum::http::HeaderValue, _| {
                let s = origin.as_bytes();
                s == b"null"
                    || s.starts_with(b"http://127.0.0.1:")
                    || s.starts_with(b"http://localhost:")
                    || s.starts_with(b"https://127.0.0.1:")
                    || s.starts_with(b"https://localhost:")
                    || s.starts_with(b"vscode-webview://")
            });
        CorsLayer::new()
            .allow_origin(allowed_origins)
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
    };

    // Warn if dashboard auth is enabled but the password hash is not Argon2id.
    let ph = &state.kernel.config.auth.password_hash;
    if state.kernel.config.auth.enabled && !ph.is_empty() && !ph.starts_with("$argon2") {
        tracing::warn!(
            "Dashboard auth password_hash is not in Argon2id format. \
             Login will fail. Regenerate with: t3rnel auth hash-password"
        );
    }

    // Trim whitespace so `api_key = ""` or `api_key = "  "` both disable auth.
    let api_key = state.kernel.config.api_key.trim().to_string();
    let allow_no_auth = std::env::var("T3RNEL_ALLOW_NO_AUTH")
        .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false);

    // Fail-closed warning: if no api_key and no dashboard auth, and the
    // server is bound to a non-loopback address without an explicit opt-in,
    // shout about it. The middleware will reject non-loopback traffic.
    let bind_is_loopback = listen_addr.ip().is_loopback();
    if api_key.is_empty() && !state.kernel.config.auth.enabled && !bind_is_loopback {
        if allow_no_auth {
            tracing::warn!(
                "T3RNEL_ALLOW_NO_AUTH=1 is set. Running WITHOUT authentication on {}. \
                 Anyone reachable at this address can read/write agents, channels, and keys.",
                listen_addr
            );
        } else {
            tracing::warn!(
                "No api_key configured and server is bound to {} (non-loopback). \
                 Non-loopback requests will be rejected with 401. \
                 Set T3RNEL_API_KEY (or api_key in config.toml), or bind to 127.0.0.1, \
                 or set T3RNEL_ALLOW_NO_AUTH=1 to explicitly run open.",
                listen_addr
            );
        }
    }

    let auth_state = crate::middleware::AuthState {
        api_key: api_key.clone(),
        auth_enabled: state.kernel.config.auth.enabled,
        session_secret: if !api_key.is_empty() {
            api_key.clone()
        } else if state.kernel.config.auth.enabled {
            state.kernel.config.auth.password_hash.clone()
        } else {
            String::new()
        },
        audit_log: Some(kernel.audit_log.clone()),
        allow_no_auth,
    };
    let gcra_limiter = rate_limiter::create_rate_limiter();

    let app = Router::new()
        .route("/", axum::routing::get(webchat::webchat_page))
        .route("/app", axum::routing::get(webchat::react_app_page))
        .route(
            "/classic",
            axum::routing::get(webchat::classic_dashboard_page),
        )
        .route("/assets/{*path}", axum::routing::get(webchat::react_asset))
        .route(
            "/.well-known/{*path}",
            axum::routing::get(webchat::react_well_known),
        )
        .route("/{file}", axum::routing::get(webchat::react_agent_surface))
        .route("/logo.png", axum::routing::get(webchat::logo_png))
        .route("/favicon.ico", axum::routing::get(webchat::favicon_ico))
        .route("/manifest.json", axum::routing::get(webchat::manifest_json))
        .route("/sw.js", axum::routing::get(webchat::sw_js))
        .route("/metrics", axum::routing::get(routes::prometheus_metrics))
        .route(
            "/api/metrics",
            axum::routing::get(routes::prometheus_metrics),
        )
        .route("/api/health", axum::routing::get(routes::health))
        .route(
            "/api/health/detail",
            axum::routing::get(routes::health_detail),
        )
        .route(
            "/api/providers/catalog",
            axum::routing::get(routes::list_provider_catalog),
        )
        .route(
            "/api/categories",
            axum::routing::get(routes::list_categories),
        )
        .route(
            "/api/system/resources",
            axum::routing::get(routes::system_resources),
        )
        .route(
            "/api/speech/status",
            axum::routing::get(routes::speech_status),
        )
        .route(
            "/api/speech/whisper-cpp/start",
            axum::routing::post(routes::whisper_cpp_start),
        )
        .route(
            "/api/speech/whisper-cpp/stop",
            axum::routing::post(routes::whisper_cpp_stop),
        )
        .route("/api/traces", axum::routing::get(routes::list_traces))
        .route("/api/status", axum::routing::get(routes::status))
        .route("/api/version", axum::routing::get(routes::version))
        .route(
            "/api/agents",
            axum::routing::get(routes::list_agents).post(routes::spawn_agent),
        )
        .route(
            "/api/agents/{id}",
            axum::routing::get(routes::get_agent)
                .delete(routes::kill_agent)
                .patch(routes::patch_agent),
        )
        .route(
            "/api/agents/{id}/uninstall",
            axum::routing::delete(routes::uninstall_agent),
        )
        .route(
            "/api/agents/{id}/mode",
            axum::routing::put(routes::set_agent_mode),
        )
        .route("/api/profiles", axum::routing::get(routes::list_profiles))
        .route(
            "/api/host/files",
            axum::routing::get(routes::list_host_files),
        )
        .route(
            "/api/host/files/read",
            axum::routing::get(routes::read_host_file),
        )
        .route(
            "/api/host/files/raw",
            axum::routing::get(routes::serve_host_file_raw),
        )
        .route(
            "/api/host/terminal/run",
            axum::routing::post(routes::run_host_terminal),
        )
        .route(
            "/api/user-settings",
            axum::routing::get(routes::get_user_settings).put(routes::put_user_settings),
        )
        .route(
            "/api/agents/{id}/restart",
            axum::routing::post(routes::restart_agent),
        )
        .route(
            "/api/agents/{id}/start",
            axum::routing::post(routes::restart_agent),
        )
        .route(
            // Issue #890 — alias so dashboards and external orchestrators can
            // wake an inactive agent via a verb that matches the agent_activate tool.
            "/api/agents/{id}/activate",
            axum::routing::post(routes::restart_agent),
        )
        .route(
            "/api/agents/{id}/message",
            axum::routing::post(routes::send_message),
        )
        .route(
            "/api/agents/{id}/browser/tool",
            axum::routing::post(routes::agent_browser_tool),
        )
        .route(
            "/api/agents/{id}/message/stream",
            axum::routing::post(routes::send_message_stream),
        )
        .route(
            "/api/agents/{id}/session",
            axum::routing::get(routes::get_agent_session),
        )
        .route(
            "/api/agents/{id}/session/reconcile",
            axum::routing::post(routes::reconcile_agent_session),
        )
        .route(
            "/api/agents/{id}/sessions",
            axum::routing::get(routes::list_agent_sessions).post(routes::create_agent_session),
        )
        .route(
            "/api/agents/{id}/sessions/{session_id}/switch",
            axum::routing::post(routes::switch_agent_session),
        )
        .route(
            "/api/agents/{id}/session/reset",
            axum::routing::post(routes::reset_session),
        )
        .route(
            "/api/agents/{id}/history",
            axum::routing::delete(routes::clear_agent_history),
        )
        .route(
            "/api/agents/{id}/session/compact",
            axum::routing::post(routes::compact_session),
        )
        .route(
            "/api/agents/{id}/stop",
            axum::routing::post(routes::stop_agent),
        )
        .route(
            "/api/agents/{id}/pause-autonomy",
            axum::routing::post(routes::pause_agent_autonomy),
        )
        .route(
            "/api/agents/{id}/model",
            axum::routing::put(routes::set_model),
        )
        .route(
            "/api/agents/{id}/tools",
            axum::routing::get(routes::get_agent_tools).put(routes::set_agent_tools),
        )
        .route(
            "/api/agents/{id}/skills",
            axum::routing::get(routes::get_agent_skills).put(routes::set_agent_skills),
        )
        .route(
            "/api/agents/{id}/mcp_servers",
            axum::routing::get(routes::get_agent_mcp_servers).put(routes::set_agent_mcp_servers),
        )
        .route(
            "/api/agents/{id}/identity",
            axum::routing::patch(routes::update_agent_identity),
        )
        .route(
            "/api/agents/{id}/config",
            axum::routing::patch(routes::patch_agent_config),
        )
        .route(
            "/api/agents/{id}/clone",
            axum::routing::post(routes::clone_agent),
        )
        .route(
            "/api/agents/{id}/files",
            axum::routing::get(routes::list_agent_files),
        )
        .route(
            "/api/agents/{id}/files/{filename}",
            axum::routing::get(routes::get_agent_file).put(routes::set_agent_file),
        )
        .route(
            "/api/agents/{id}/deliveries",
            axum::routing::get(routes::get_agent_deliveries),
        )
        .route(
            "/api/agents/{id}/upload",
            axum::routing::post(routes::upload_file),
        )
        .route("/api/agents/{id}/ws", axum::routing::get(ws::agent_ws))
        // Upload serving
        .route(
            "/api/uploads/{file_id}",
            axum::routing::get(routes::serve_upload),
        )
        // Channel endpoints
        .route("/api/channels", axum::routing::get(routes::list_channels))
        .route(
            "/api/channels/{name}/configure",
            axum::routing::post(routes::configure_channel).delete(routes::remove_channel),
        )
        .route(
            "/api/channels/{name}/test",
            axum::routing::post(routes::test_channel),
        )
        .route(
            "/api/channels/telegram/webhook",
            axum::routing::post(routes::telegram_webhook),
        )
        .route(
            "/api/channels/reload",
            axum::routing::post(routes::reload_channels),
        )
        // WhatsApp QR login flow
        .route(
            "/api/channels/whatsapp/unlink",
            axum::routing::post(routes::whatsapp_unlink),
        )
        .route(
            "/api/channels/whatsapp/linked",
            axum::routing::get(routes::whatsapp_linked),
        )
        .route(
            "/api/channels/whatsapp/qr/start",
            axum::routing::post(routes::whatsapp_qr_start),
        )
        .route(
            "/api/channels/whatsapp/qr/status",
            axum::routing::get(routes::whatsapp_qr_status),
        )
        // Template endpoints
        .route("/api/templates", axum::routing::get(routes::list_templates))
        .route(
            "/api/templates/{name}",
            axum::routing::get(routes::get_template),
        )
        // Memory endpoints
        .route(
            "/api/memory/command",
            axum::routing::post(crate::memory_routes::command)
                .layer(axum::extract::DefaultBodyLimit::max(65_536)),
        )
        .route(
            "/api/memory/records",
            axum::routing::get(crate::memory_routes::search)
                .post(crate::memory_routes::remember)
                .layer(axum::extract::DefaultBodyLimit::max(65_536)),
        )
        .route(
            "/api/memory/records/{id}",
            axum::routing::get(crate::memory_routes::get),
        )
        .route(
            "/api/memory/handover",
            axum::routing::get(crate::memory_routes::handover),
        )
        .route(
            "/api/memory/events",
            axum::routing::get(crate::memory_routes::events),
        )
        .route(
            "/api/memory/conflicts",
            axum::routing::get(crate::memory_routes::conflicts),
        )
        .route(
            "/api/memory/brief",
            axum::routing::get(crate::memory_routes::brief),
        )
        .route(
            "/api/memory/export",
            axum::routing::get(crate::memory_routes::export),
        )
        .route(
            "/api/memory/kv/{key}",
            axum::routing::get(crate::memory_routes::kv_get)
                .put(crate::memory_routes::kv_set)
                .layer(axum::extract::DefaultBodyLimit::max(65_536)),
        )
        .route(
            "/api/memory/agents/{id}/kv",
            axum::routing::get(routes::get_agent_kv),
        )
        .route(
            "/api/memory/agents/{id}/kv/{key}",
            axum::routing::get(routes::get_agent_kv_key)
                .put(routes::set_agent_kv_key)
                .delete(routes::delete_agent_kv_key),
        )
        // A2A endpoints
        .route(
            "/.well-known/agent.json",
            axum::routing::get(routes::a2a_agent_card),
        )
        .route(
            "/api/a2a/agents",
            axum::routing::get(routes::a2a_list_agents),
        )
        // Trigger endpoints
        .route(
            "/api/triggers",
            axum::routing::get(routes::list_triggers).post(routes::create_trigger),
        )
        .route(
            "/api/triggers/{id}",
            axum::routing::delete(routes::delete_trigger).put(routes::update_trigger),
        )
        // Schedule (cron job) endpoints
        .route(
            "/api/schedules",
            axum::routing::get(routes::list_schedules).post(routes::create_schedule),
        )
        .route(
            "/api/schedules/{id}",
            axum::routing::delete(routes::delete_schedule).put(routes::update_schedule),
        )
        .route(
            "/api/schedules/{id}/run",
            axum::routing::post(routes::run_schedule),
        )
        .route(
            "/api/schedules/{id}/delivery-log",
            axum::routing::get(routes::schedule_delivery_log),
        )
        // Workflow endpoints
        .route(
            "/api/workflows",
            axum::routing::get(routes::list_workflows).post(routes::create_workflow),
        )
        .route(
            "/api/workflows/{id}",
            axum::routing::get(routes::get_workflow)
                .put(routes::update_workflow)
                .delete(routes::delete_workflow),
        )
        .route(
            "/api/workflows/{id}/run",
            axum::routing::post(routes::run_workflow),
        )
        .route(
            "/api/workflows/{id}/stop",
            axum::routing::post(routes::stop_workflow),
        )
        .route(
            "/api/workflows/{id}/runs",
            axum::routing::get(routes::list_workflow_runs),
        )
        // Skills endpoints
        .route("/api/skills", axum::routing::get(routes::list_skills))
        .route(
            "/api/skills/install",
            axum::routing::post(routes::install_skill),
        )
        .route(
            "/api/skills/uninstall",
            axum::routing::post(routes::uninstall_skill),
        )
        .route(
            "/api/skills/reload",
            axum::routing::post(routes::reload_skills),
        )
        // Audit trail (issue #1174 — instance-side wrapper integration)
        .route(
            "/api/audit/append",
            axum::routing::post(routes::audit_append),
        )
        .route(
            "/api/skills/{id}/config",
            axum::routing::get(routes::get_skill_config).put(routes::put_skill_config),
        )
        .route(
            "/api/skills/{id}/config/{var_name}",
            axum::routing::delete(routes::delete_skill_config_var),
        )
        .route(
            "/api/skills/invoke",
            axum::routing::post(routes::invoke_skill),
        )
        .route(
            "/api/admin/test/db-corrupt-wal",
            axum::routing::post(routes::db_corrupt_wal),
        )
        .route(
            "/api/marketplace/search",
            axum::routing::get(routes::marketplace_search),
        )
        // ClawHub (OpenClaw ecosystem) endpoints
        .route(
            "/api/clawhub/search",
            axum::routing::get(routes::clawhub_search),
        )
        .route(
            "/api/clawhub/browse",
            axum::routing::get(routes::clawhub_browse),
        )
        .route(
            "/api/clawhub/skill/{slug}",
            axum::routing::get(routes::clawhub_skill_detail),
        )
        .route(
            "/api/clawhub/skill/{slug}/code",
            axum::routing::get(routes::clawhub_skill_code),
        )
        .route(
            "/api/clawhub/install",
            axum::routing::post(routes::clawhub_install),
        )
        // Hands endpoints
        .route("/api/hands", axum::routing::get(routes::list_hands))
        .route(
            "/api/hands/install",
            axum::routing::post(routes::install_hand),
        )
        .route(
            "/api/hands/upsert",
            axum::routing::post(routes::upsert_hand),
        )
        .route(
            "/api/hands/active",
            axum::routing::get(routes::list_active_hands),
        )
        .route("/api/hands/{hand_id}", axum::routing::get(routes::get_hand))
        .route(
            "/api/hands/{hand_id}/activate",
            axum::routing::post(routes::activate_hand),
        )
        .route(
            "/api/hands/{hand_id}/check-deps",
            axum::routing::post(routes::check_hand_deps),
        )
        .route(
            "/api/hands/{hand_id}/install-deps",
            axum::routing::post(routes::install_hand_deps),
        )
        .route(
            "/api/hands/{hand_id}/settings",
            axum::routing::get(routes::get_hand_settings).put(routes::update_hand_settings),
        )
        .route(
            "/api/hands/instances/{id}/pause",
            axum::routing::post(routes::pause_hand),
        )
        .route(
            "/api/hands/instances/{id}/resume",
            axum::routing::post(routes::resume_hand),
        )
        .route(
            "/api/hands/instances/{id}",
            axum::routing::delete(routes::deactivate_hand),
        )
        .route(
            "/api/hands/instances/{id}/stats",
            axum::routing::get(routes::hand_stats),
        )
        .route(
            "/api/hands/instances/{id}/browser",
            axum::routing::get(routes::hand_instance_browser),
        )
        // MCP server endpoints
        .route(
            "/api/mcp/servers",
            axum::routing::get(routes::list_mcp_servers),
        )
        // Audit endpoints
        .route(
            "/api/audit/recent",
            axum::routing::get(routes::audit_recent),
        )
        .route(
            "/api/audit/verify",
            axum::routing::get(routes::audit_verify),
        )
        // Live log streaming (SSE)
        .route("/api/logs/stream", axum::routing::get(routes::logs_stream))
        // Peer/Network endpoints
        .route("/api/peers", axum::routing::get(routes::list_peers))
        .route(
            "/api/network/status",
            axum::routing::get(routes::network_status),
        )
        // Agent communication (Comms) endpoints
        .route(
            "/api/comms/topology",
            axum::routing::get(routes::comms_topology),
        )
        .route(
            "/api/comms/events",
            axum::routing::get(routes::comms_events),
        )
        .route(
            "/api/comms/events/stream",
            axum::routing::get(routes::comms_events_stream),
        )
        .route("/api/events", axum::routing::post(routes::post_event))
        .route("/api/context", axum::routing::post(routes::post_context))
        .route("/api/comms/send", axum::routing::post(routes::comms_send))
        .route("/api/comms/task", axum::routing::post(routes::comms_task))
        // IDE command endpoints for Windsurf driver
        .route(
            "/api/ide-commands",
            axum::routing::post(routes::create_ide_command).get(routes::list_ide_commands),
        )
        .route(
            "/api/ide-commands/{session_id}",
            axum::routing::get(routes::get_ide_command),
        )
        .route(
            "/api/ide-commands/{session_id}/cancel",
            axum::routing::post(routes::cancel_ide_command),
        )
        .route(
            "/api/ide-commands/{session_id}/update",
            axum::routing::post(routes::update_ide_command),
        )
        .route(
            "/api/ide-commands/stream",
            axum::routing::get(routes::ide_commands_stream),
        );

    // Split into a second router chunk to stay within axum's type nesting limit.
    let app = app
        // Tools endpoint
        .route("/api/tools", axum::routing::get(routes::list_tools))
        // Config endpoints
        .route("/api/config", axum::routing::get(routes::get_config))
        .route(
            "/api/config/schema",
            axum::routing::get(routes::config_schema),
        )
        .route("/api/config/set", axum::routing::post(routes::config_set))
        .route(
            "/api/config/default-model",
            axum::routing::put(routes::config_set_default_model),
        )
        // Approval endpoints
        .route(
            "/api/approvals",
            axum::routing::get(routes::list_approvals).post(routes::create_approval),
        )
        .route(
            "/api/approvals/pending-count",
            axum::routing::get(routes::get_pending_count),
        )
        .route(
            "/api/approvals/approve-all",
            axum::routing::post(routes::approve_all_requests),
        )
        .route(
            "/api/approvals/{id}/approve",
            axum::routing::post(routes::approve_request),
        )
        .route(
            "/api/approvals/{id}/reject",
            axum::routing::post(routes::reject_request),
        )
        .route(
            "/api/pending-actions",
            axum::routing::get(routes::list_pending_actions).post(routes::create_pending_action),
        )
        .route(
            "/api/pending-actions/{id}/resolve",
            axum::routing::post(routes::resolve_pending_action),
        )
        .route(
            "/api/pending-actions/{id}/snooze",
            axum::routing::post(routes::snooze_pending_action),
        )
        .route(
            "/api/permissions/grants",
            axum::routing::get(routes::list_permission_grants),
        )
        .route(
            "/api/permissions/grants/{id}",
            axum::routing::post(routes::grant_permission_capabilities)
                .delete(routes::revoke_permission_grants),
        )
        // Usage endpoints
        .route("/api/usage", axum::routing::get(routes::usage_stats))
        .route(
            "/api/usage/summary",
            axum::routing::get(routes::usage_summary),
        )
        .route(
            "/api/usage/by-model",
            axum::routing::get(routes::usage_by_model),
        )
        .route("/api/usage/daily", axum::routing::get(routes::usage_daily))
        // Sentinel — error and security monitoring
        .route(
            "/api/sentinel",
            axum::routing::get(routes::sentinel_findings),
        )
        // Budget endpoints
        .route(
            "/api/budget",
            axum::routing::get(routes::budget_status).put(routes::update_budget),
        )
        .route(
            "/api/budget/agents",
            axum::routing::get(routes::agent_budget_ranking),
        )
        .route(
            "/api/budget/agents/{id}",
            axum::routing::get(routes::agent_budget_status).put(routes::update_agent_budget),
        )
        // Session endpoints
        .route("/api/sessions", axum::routing::get(routes::list_sessions))
        .route(
            "/api/sessions/{id}",
            axum::routing::delete(routes::delete_session),
        )
        .route(
            "/api/sessions/{id}/label",
            axum::routing::put(routes::set_session_label),
        )
        .route(
            "/api/agents/{id}/sessions/by-label/{label}",
            axum::routing::get(routes::find_session_by_label),
        )
        // Agent update
        .route(
            "/api/agents/{id}/update",
            axum::routing::put(routes::update_agent),
        )
        // Security dashboard endpoint
        .route("/api/security", axum::routing::get(routes::security_status))
        // Model catalog endpoints
        .route("/api/models", axum::routing::get(routes::list_models))
        .route(
            "/api/models/aliases",
            axum::routing::get(routes::list_aliases),
        )
        .route(
            "/api/models/custom",
            axum::routing::post(routes::add_custom_model),
        )
        .route(
            "/api/models/custom/{*id}",
            axum::routing::delete(routes::remove_custom_model),
        )
        .route("/api/models/{*id}", axum::routing::get(routes::get_model))
        .route("/api/providers", axum::routing::get(routes::list_providers))
        // Health monitoring endpoints
        .route(
            "/api/providers/health",
            axum::routing::get(routes::get_all_provider_health),
        )
        .route(
            "/api/providers/health/{provider}",
            axum::routing::get(routes::get_provider_health),
        )
        .route(
            "/api/providers/health/{provider}/{model}",
            axum::routing::get(routes::get_model_health),
        )
        .route(
            "/api/providers/token-usage",
            axum::routing::get(routes::get_all_token_usage),
        )
        .route(
            "/api/providers/token-usage/{provider}",
            axum::routing::get(routes::get_provider_token_usage),
        )
        .route(
            "/api/providers/token-usage/{provider}/{model}",
            axum::routing::get(routes::get_model_token_usage),
        )
        .route(
            "/api/providers/promote-primary",
            axum::routing::post(routes::promote_primary),
        )
        .route(
            "/api/health/recommendations",
            axum::routing::get(routes::health_recommendations),
        )
        // Copilot OAuth (must be before parametric {name} routes)
        .route(
            "/api/providers/github-copilot/oauth/start",
            axum::routing::post(routes::copilot_oauth_start),
        )
        .route(
            "/api/providers/github-copilot/oauth/poll/{poll_id}",
            axum::routing::get(routes::copilot_oauth_poll),
        )
        .route(
            "/api/providers/{name}/key",
            axum::routing::post(routes::set_provider_key).delete(routes::delete_provider_key),
        )
        .route(
            "/api/providers/{name}/test",
            axum::routing::post(routes::test_provider),
        )
        .route(
            "/api/providers/{name}/url",
            axum::routing::put(routes::set_provider_url),
        )
        .route(
            "/api/skills/create",
            axum::routing::post(routes::create_skill),
        )
        // Migration endpoints
        .route(
            "/api/migrate/detect",
            axum::routing::get(routes::migrate_detect),
        )
        .route(
            "/api/migrate/scan",
            axum::routing::post(routes::migrate_scan),
        )
        .route("/api/migrate", axum::routing::post(routes::run_migrate))
        // Cron job management endpoints
        .route(
            "/api/cron/jobs",
            axum::routing::get(routes::list_cron_jobs).post(routes::create_cron_job),
        )
        .route(
            "/api/cron/jobs/{id}",
            axum::routing::delete(routes::delete_cron_job),
        )
        .route(
            "/api/cron/jobs/{id}/enable",
            axum::routing::put(routes::toggle_cron_job),
        )
        .route(
            "/api/cron/jobs/{id}/status",
            axum::routing::get(routes::cron_job_status),
        )
        .route(
            "/api/cron/jobs/{id}/run",
            axum::routing::post(routes::run_cron_job),
        )
        // Webhook trigger endpoints (external event injection)
        .route("/hooks/wake", axum::routing::post(routes::webhook_wake))
        .route("/hooks/agent", axum::routing::post(routes::webhook_agent))
        .route("/api/shutdown", axum::routing::post(routes::shutdown))
        // Chat commands endpoint (dynamic slash menu)
        .route("/api/commands", axum::routing::get(routes::list_commands))
        // Config reload endpoint
        .route(
            "/api/config/reload",
            axum::routing::post(routes::config_reload),
        )
        // Agent binding routes
        .route(
            "/api/bindings",
            axum::routing::get(routes::list_bindings).post(routes::add_binding),
        )
        .route(
            "/api/bindings/{index}",
            axum::routing::delete(routes::remove_binding),
        )
        // A2A (Agent-to-Agent) Protocol endpoints
        .route("/a2a/agents", axum::routing::get(routes::a2a_list_agents))
        .route(
            "/a2a/tasks/send",
            axum::routing::post(routes::a2a_send_task),
        )
        .route("/a2a/tasks/{id}", axum::routing::get(routes::a2a_get_task))
        .route(
            "/a2a/tasks/{id}/cancel",
            axum::routing::post(routes::a2a_cancel_task),
        )
        // A2A management (outbound) endpoints
        .route(
            "/api/a2a/external-agents",
            axum::routing::get(routes::a2a_list_external_agents),
        )
        .route(
            "/api/a2a/discover",
            axum::routing::post(routes::a2a_discover_external),
        )
        .route(
            "/api/a2a/send",
            axum::routing::post(routes::a2a_send_external),
        )
        .route(
            "/api/a2a/tasks/{id}/status",
            axum::routing::get(routes::a2a_external_task_status),
        )
        // Legacy shared task queue endpoints
        .route("/api/tasks", axum::routing::get(routes::list_legacy_tasks))
        .route(
            "/api/tasks/complete-all",
            axum::routing::post(routes::complete_all_legacy_tasks),
        )
        // Team endpoints
        .route(
            "/api/teams",
            axum::routing::get(routes::list_teams).post(routes::create_team),
        )
        .route(
            "/api/teams/{id}",
            axum::routing::get(routes::get_team)
                .put(routes::update_team)
                .delete(routes::delete_team),
        )
        .route(
            "/api/teams/{id}/members",
            axum::routing::get(routes::get_team_members),
        )
        .route(
            "/api/teams/{id}/members/{agent_id}",
            axum::routing::put(routes::upsert_team_member).delete(routes::remove_team_member),
        )
        .route(
            "/api/teams/{id}/tasks",
            axum::routing::get(routes::list_team_tasks).post(routes::create_team_task),
        )
        .route(
            "/api/teams/{id}/tasks/complete-all",
            axum::routing::post(routes::complete_all_team_tasks),
        )
        .route(
            "/api/teams/{id}/tasks/{task_id}/complete",
            axum::routing::post(routes::complete_team_task),
        )
        .route(
            "/api/teams/{id}/tasks/{task_id}/cancel",
            axum::routing::post(routes::cancel_team_task),
        )
        .route(
            "/api/teams/{id}/tasks/{task_id}",
            axum::routing::put(routes::update_team_task),
        )
        .route(
            "/api/teams/{id}/tasks/{task_id}/progress",
            axum::routing::get(routes::get_task_progress),
        )
        .route(
            "/api/teams/{id}/a2a/messages",
            axum::routing::get(routes::list_a2a_messages).post(routes::send_a2a_message),
        )
        .route(
            "/api/teams/{id}/a2a/stream",
            axum::routing::get(routes::a2a_message_stream),
        )
        // Integration management endpoints
        .route(
            "/api/integrations",
            axum::routing::get(routes::list_integrations),
        )
        .route(
            "/api/integrations/available",
            axum::routing::get(routes::list_available_integrations),
        )
        .route(
            "/api/integrations/add",
            axum::routing::post(routes::add_integration),
        )
        .route(
            "/api/integrations/{id}",
            axum::routing::delete(routes::remove_integration),
        )
        .route(
            "/api/integrations/{id}/reconnect",
            axum::routing::post(routes::reconnect_integration),
        )
        .route(
            "/api/integrations/health",
            axum::routing::get(routes::integrations_health),
        )
        .route(
            "/api/integrations/reload",
            axum::routing::post(routes::reload_integrations),
        )
        // Device pairing endpoints
        .route(
            "/api/pairing/request",
            axum::routing::post(routes::pairing_request),
        )
        .route(
            "/api/pairing/complete",
            axum::routing::post(routes::pairing_complete),
        )
        .route(
            "/api/pairing/devices",
            axum::routing::get(routes::pairing_devices),
        )
        .route(
            "/api/pairing/devices/{id}",
            axum::routing::delete(routes::pairing_remove_device),
        )
        .route(
            "/api/pairing/notify",
            axum::routing::post(routes::pairing_notify),
        )
        // MCP HTTP endpoint (exposes MCP protocol over HTTP)
        .route("/mcp", axum::routing::post(routes::mcp_http))
        // OpenAI-compatible API
        .route(
            "/v1/chat/completions",
            axum::routing::post(crate::openai_compat::chat_completions),
        )
        .route(
            "/v1/models",
            axum::routing::get(crate::openai_compat::list_models),
        )
        // Dashboard authentication endpoints
        .route("/api/auth/login", axum::routing::post(routes::auth_login))
        .route("/api/auth/logout", axum::routing::post(routes::auth_logout))
        .route("/api/auth/check", axum::routing::get(routes::auth_check))
        // Internal self-improvement endpoints (inventor-gated)
        .route(
            "/api/internal/self-improvement/activate",
            axum::routing::post(routes::self_improvement_activate),
        )
        .route(
            "/api/internal/self-improvement/status",
            axum::routing::get(routes::self_improvement_status),
        )
        .route(
            "/api/internal/self-improvement/halt",
            axum::routing::post(routes::self_improvement_halt),
        )
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            middleware::auth,
        ))
        .layer(axum::middleware::from_fn_with_state(
            gcra_limiter.clone(),
            rate_limiter::gcra_rate_limit,
        ))
        .layer(axum::middleware::from_fn(middleware::security_headers))
        .layer(axum::middleware::from_fn(middleware::request_logging))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state.clone());

    // ------------------------------------------------------------------
    // Plugin admin routes (9.7): /api/plugins{,/{id},/install,/update,
    // /rollback,/launch-check}. The router carries its own
    // PluginAdminState, so it is merged AFTER `.with_state(state)` — axum
    // only merges routers with identical state types. The same middleware
    // stack (auth → rate limit → security headers → request logging) is
    // re-applied so these routes are not less protected than the rest.
    // ------------------------------------------------------------------
    if kernel.config.plugin_dev_mode {
        // EXTREMELY LOUD: dev mode disables package signature verification.
        warn!(
            "{}",
            t3rnel_runtime::plugin_lifecycle::DEV_MODE_BOOT_WARNING
        );
    }
    let mut plugin_mgr =
        t3rnel_runtime::plugin_lifecycle::PluginManager::new(&kernel.config.home_dir);
    plugin_mgr.set_audit_log(kernel.audit_log.clone());
    let plugin_opts = t3rnel_runtime::plugin_lifecycle::InstallOptions {
        require_signature: !kernel.config.plugin_dev_mode,
        trusted_keys: resolve_plugin_trusted_signers(&kernel.config.plugin_trusted_signers),
        dev_mode: kernel.config.plugin_dev_mode,
    };
    let plugin_router = crate::plugin_admin::router(Arc::new(plugin_mgr), plugin_opts)
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            middleware::auth,
        ))
        .layer(axum::middleware::from_fn_with_state(
            gcra_limiter.clone(),
            rate_limiter::gcra_rate_limit,
        ))
        .layer(axum::middleware::from_fn(middleware::security_headers))
        .layer(axum::middleware::from_fn(middleware::request_logging));
    let app = app.merge(plugin_router);

    // ------------------------------------------------------------------
    // Conversation / approval / briefing routes (docs/sections/18):
    // /api/conversations/*, /api/conversations/channels*, /api/briefing/*.
    // (/api/channels itself belongs to the legacy channel-config surface.)
    // Same post-.with_state merge pattern and middleware stack as plugins.
    // ------------------------------------------------------------------
    let (conv_state, _local_channel) = crate::conversations::build_conversation_stack(&kernel);
    // Connect every linked channel account through the vault broker
    // (18 §3). Per-account failures are logged, never fatal — the local
    // dashboard adapter is always present.
    for (label, result) in conv_state.channels.connect_all().await {
        match result {
            Ok(()) => tracing::info!("channel {label} connected"),
            Err(e) => tracing::warn!("channel {label} connect failed: {e}"),
        }
    }
    // Inbound router loop (18 §2): adapters emit normalized
    // ConversationEvents via poll_inbound; each is routed to an approval
    // binding, an agent thread, or stored unbound.
    {
        let channels = conv_state.channels.clone();
        let service = conv_state.service.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tick.tick().await;
                for (id, result) in channels.poll_all().await {
                    match result {
                        Ok(events) => {
                            for event in events {
                                match service.handle_inbound(event).await {
                                    Ok(t3rnel_runtime::conversations::RoutedInbound::AgentMessage {
                                        agent_id: Some(agent_ref),
                                        event,
                                        ..
                                    }) => {
                                        // Agent-message consumer (18 §2):
                                        // resolve the bound agent and run a
                                        // real turn; the reply goes back out
                                        // through the same channel adapter.
                                        let st = state.clone();
                                        let svc = service.clone();
                                        tokio::spawn(async move {
                                            let Some(agent_id) =
                                                crate::routes::resolve_agent_id(&st, &agent_ref)
                                            else {
                                                tracing::warn!(
                                                    "inbound for unknown agent {agent_ref:?} on {}",
                                                    event.conversation_key()
                                                );
                                                return;
                                            };
                                            let kernel_handle: Arc<dyn t3rnel_runtime::kernel_handle::KernelHandle> =
                                                st.kernel.clone();
                                            match st
                                                .kernel
                                                .send_message_with_handle_and_blocks(
                                                    agent_id,
                                                    &event.text,
                                                    Some(kernel_handle),
                                                    None,
                                                    Some(event.sender.clone()),
                                                    None,
                                                )
                                                .await
                                            {
                                                Ok(result) => {
                                                    let reply = result.response.trim().to_string();
                                                    if reply.is_empty() || result.silent {
                                                        return;
                                                    }
                                                    if let Err(e) = svc
                                                        .send_message(
                                                            &event.channel,
                                                            &event.account,
                                                            &event.thread_key,
                                                            &reply,
                                                        )
                                                        .await
                                                    {
                                                        tracing::warn!(
                                                            "agent reply send on {} failed: {e}",
                                                            event.conversation_key()
                                                        );
                                                    }
                                                }
                                                Err(e) => tracing::warn!(
                                                    "agent dispatch for {agent_ref} failed: {e}"
                                                ),
                                            }
                                        });
                                    }
                                    Ok(_) => {}
                                    Err(e) => {
                                        tracing::warn!("inbound route on {id} failed: {e}")
                                    }
                                }
                            }
                        }
                        Err(e) => tracing::debug!("channel {id} inbound poll: {e}"),
                    }
                }
            }
        });
    }
    let conv_router = crate::conversations::router(conv_state)
        .layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            middleware::auth,
        ))
        .layer(axum::middleware::from_fn_with_state(
            gcra_limiter.clone(),
            rate_limiter::gcra_rate_limit,
        ))
        .layer(axum::middleware::from_fn(middleware::security_headers))
        .layer(axum::middleware::from_fn(middleware::request_logging));
    let app = app.merge(conv_router);

    (app, state)
}

/// Resolve `plugin_trusted_signers` config entries into signer pubkey hex.
/// Each entry may be a 64-char hex pubkey OR a filesystem path to a file
/// containing one (whitespace-trimmed). Unreadable paths are kept verbatim —
/// they simply won't match any signer, which fails closed.
fn resolve_plugin_trusted_signers(entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .map(|e| {
            let trimmed = e.trim();
            let path = Path::new(trimmed);
            if path.is_file() {
                std::fs::read_to_string(path)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| trimmed.to_string())
            } else {
                trimmed.to_string()
            }
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// Initialize opentelemetry tracing if `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
pub fn init_telemetry() {
    let Some(endpoint) = configured_otlp_endpoint() else {
        return;
    };

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(endpoint);

    let provider = match opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(opentelemetry_sdk::trace::Config::default().with_resource(
            opentelemetry_sdk::Resource::new(vec![
                opentelemetry::KeyValue::new("service.name", "t3rnel-api"),
                opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            ]),
        ))
        .install_batch(opentelemetry_sdk::runtime::Tokio)
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Failed to initialize opentelemetry: {e}");
            return;
        }
    };

    let tracer = provider.tracer("t3rnel-api");
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(otel_layer)
        .try_init()
        .is_ok()
    {
        tracing::info!("OpenTelemetry tracing initialized");
    }
}

fn configured_otlp_endpoint() -> Option<String> {
    choose_otlp_endpoint(
        std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok(),
        std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").ok(),
    )
}

fn choose_otlp_endpoint(
    endpoint: Option<String>,
    traces_endpoint: Option<String>,
) -> Option<String> {
    traces_endpoint
        .filter(|value| !value.trim().is_empty())
        .or_else(|| endpoint.filter(|value| !value.trim().is_empty()))
}

/// Start the T3rnel daemon: boot kernel + HTTP API server.
///
/// This function blocks until Ctrl+C or a shutdown request.
pub async fn run_daemon(
    kernel: T3rnelKernel,
    listen_addr: &str,
    daemon_info_path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    init_telemetry();

    let addr: SocketAddr = listen_addr.parse()?;

    let kernel = Arc::new(kernel);
    kernel.set_self_handle();
    kernel.start_background_agents();

    // Config file hot-reload watcher (polls every 30 seconds)
    {
        let k = kernel.clone();
        let config_path = kernel.config.home_dir.join("config.toml");
        tokio::spawn(async move {
            let mut last_modified = std::fs::metadata(&config_path)
                .and_then(|m| m.modified())
                .ok();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let current = std::fs::metadata(&config_path)
                    .and_then(|m| m.modified())
                    .ok();
                if current != last_modified && current.is_some() {
                    last_modified = current;
                    tracing::info!("Config file changed, reloading...");
                    match k.reload_config() {
                        Ok(plan) => {
                            if plan.has_changes() {
                                tracing::info!("Config hot-reload applied: {:?}", plan.hot_actions);
                            } else {
                                tracing::debug!("Config hot-reload: no actionable changes");
                            }
                        }
                        Err(e) => tracing::warn!("Config hot-reload failed: {e}"),
                    }
                }
            }
        });
    }

    let (app, state) = build_router(kernel.clone(), addr).await;

    // Start gRPC server on the port after the HTTP API port.
    let grpc_port = addr.port() + 1;
    match crate::grpc::start_grpc_server(state.clone(), grpc_port).await {
        Ok(grpc_addr) => {
            info!("T3rnel gRPC server listening on http://{grpc_addr}");
        }
        Err(e) => {
            tracing::warn!("Failed to start gRPC server: {e}");
        }
    }

    // Write daemon info file
    if let Some(info_path) = daemon_info_path {
        // Check if another daemon is already running with this PID file
        if info_path.exists() {
            if let Ok(existing) = std::fs::read_to_string(info_path) {
                if let Ok(info) = serde_json::from_str::<DaemonInfo>(&existing) {
                    // PID alive AND the health endpoint responds → truly running
                    if is_process_alive(info.pid) && is_daemon_responding(&info.listen_addr) {
                        return Err(format!(
                            "Another daemon (PID {}) is already running at {}",
                            info.pid, info.listen_addr
                        )
                        .into());
                    }
                }
            }
            // Stale PID file (process dead or different process reused PID), remove it
            info!("Removing stale daemon info file");
            let _ = std::fs::remove_file(info_path);
        }

        // The daemon-info write moved below the socket bind — a file that
        // claims "listening on {addr}" before the bind lands is the lie
        // ISSUE-259 caught (daemon.json said 50051 while nothing held it).
    }

    // Use SO_REUSEADDR to allow binding immediately after reboot (avoids TIME_WAIT).
    let socket = socket2::Socket::new(
        if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::STREAM,
        None,
    )?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into()).map_err(|e| {
        // ISSUE-259: this error previously surfaced only as a `?` after the
        // "listening" line had already logged — the daemon claimed a listener
        // it never had. Name it loudly; the caller exits non-zero so systemd
        // restarts onto a healthy boot instead of running deaf for hours.
        format!("HTTP bind on {addr} failed: {e} — daemon cannot serve without its listener")
    })?;
    socket.listen(1024)?;
    let listener = tokio::net::TcpListener::from_std(std::net::TcpListener::from(socket))?;

    // Listener bound — now the daemon-info file tells the truth about the addr.
    if let Some(info_path) = daemon_info_path {
        let daemon_info = DaemonInfo {
            pid: std::process::id(),
            listen_addr: addr.to_string(),
            started_at: chrono::Utc::now().to_rfc3339(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            platform: std::env::consts::OS.to_string(),
        };
        if let Ok(json) = serde_json::to_string_pretty(&daemon_info) {
            let _ = std::fs::write(info_path, json);
            // SECURITY: Restrict daemon info file permissions (contains PID and port).
            restrict_permissions(info_path);
        }
    }

    // Post-boot self-check: a process that cannot answer its own /api/health
    // is deaf — exit non-zero so systemd restarts instead of idling dead.
    {
        let self_addr = addr;
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            // An unspecified listen addr (0.0.0.0) still answers on loopback —
            // probe through the concrete loopback address rather than the
            // wildcard literal.
            let probe_addr = if self_addr.ip().is_unspecified() {
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    self_addr.port(),
                )
            } else {
                self_addr
            };
            let url = format!("http://{probe_addr}/api/health");
            match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
            {
                Ok(client) => match client.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {}
                    other => {
                        tracing::error!(
                            result = ?other.map(|r| r.status().as_u16()),
                            "Daemon self-check failed: /api/health unreachable on own listener — exiting"
                        );
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    tracing::error!("Daemon self-check could not build HTTP client: {e} — exiting");
                    std::process::exit(1);
                }
            }
        });
    }

    // The listener exists — only now is "listening" true.
    info!("T3rnel API server listening on http://{addr}");
    info!("WebChat UI available at http://{addr}/",);
    info!("WebSocket endpoint: ws://{addr}/api/agents/{{id}}/ws",);

    // Run server with graceful shutdown.
    // SECURITY: `into_make_service_with_connect_info` injects the peer
    // SocketAddr so the auth middleware can check for loopback connections.
    let api_shutdown = state.shutdown_notify.clone();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(api_shutdown))
    .await?;

    // Ordered teardown.
    //
    // Previously this block ran as three unsequenced statements with no
    // timeout and no record of what completed. A kill during any of them left
    // no way to tell which subsystems had flushed. `ShutdownCoordinator`
    // existed for exactly this and was never constructed.
    let shutdown = t3rnel_runtime::graceful_shutdown::ShutdownCoordinator::new(
        t3rnel_runtime::graceful_shutdown::ShutdownConfig {
            shutdown_reason: "daemon received termination signal".to_string(),
            ..Default::default()
        },
    );
    shutdown.initiate();

    run_shutdown_phase(
        &shutdown,
        t3rnel_runtime::graceful_shutdown::ShutdownPhase::Draining,
        async {
            if let Some(info_path) = daemon_info_path {
                std::fs::remove_file(info_path)
                    .map_err(|e| format!("daemon info file: {e}"))
                    .or_else(|e| {
                        // Absent is the desired end state, not a failure.
                        if e.contains("No such file") {
                            Ok(())
                        } else {
                            Err(e)
                        }
                    })?;
            }
            Ok(())
        },
    )
    .await;

    run_shutdown_phase(
        &shutdown,
        t3rnel_runtime::graceful_shutdown::ShutdownPhase::StoppingBackground,
        async {
            if let Some(ref mut b) = *state.bridge_manager.lock().await {
                b.stop().await;
            }
            Ok(())
        },
    )
    .await;

    run_shutdown_phase(
        &shutdown,
        t3rnel_runtime::graceful_shutdown::ShutdownPhase::ClosingDatabase,
        async {
            kernel.shutdown();
            Ok(())
        },
    )
    .await;

    shutdown.advance_phase(
        t3rnel_runtime::graceful_shutdown::ShutdownPhase::Complete,
        true,
        None,
    );

    let status = shutdown.status();
    info!(
        elapsed_secs = status.elapsed_secs,
        phases = status.phases_completed.len(),
        "T3rnel daemon stopped"
    );
    Ok(())
}

/// Run one shutdown phase, recording its outcome and bounding its runtime.
///
/// A phase that hangs must not hold the whole shutdown open — the operator
/// already asked the process to stop, and an unbounded wait turns a graceful
/// shutdown into a hung one, which is strictly worse than a hard kill because
/// it looks like progress.
async fn run_shutdown_phase<F>(
    coordinator: &t3rnel_runtime::graceful_shutdown::ShutdownCoordinator,
    phase: t3rnel_runtime::graceful_shutdown::ShutdownPhase,
    work: F,
) where
    F: std::future::Future<Output = Result<(), String>>,
{
    let timeout = coordinator.drain_timeout();
    match tokio::time::timeout(timeout, work).await {
        Ok(Ok(())) => coordinator.advance_phase(phase, true, None),
        Ok(Err(e)) => {
            warn!(%phase, error = %e, "Shutdown phase failed");
            coordinator.advance_phase(phase, false, Some(e));
        }
        Err(_) => {
            warn!(%phase, timeout_secs = timeout.as_secs(), "Shutdown phase timed out");
            coordinator.advance_phase(phase, false, Some("timed out".to_string()));
        }
    }
}

/// SECURITY: Restrict file permissions to owner-only (0600) on Unix.
/// On non-Unix platforms this is a no-op.
#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

/// Read daemon info from the standard location.
pub fn read_daemon_info(home_dir: &Path) -> Option<DaemonInfo> {
    let info_path = home_dir.join("daemon.json");
    let contents = std::fs::read_to_string(info_path).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Wait for an OS termination signal OR an API shutdown request.
///
/// On Unix: listens for SIGINT, SIGTERM, and API notify.
/// On Windows: listens for Ctrl+C and API notify.
async fn shutdown_signal(api_shutdown: Arc<tokio::sync::Notify>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to listen for SIGINT");
        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to listen for SIGTERM");

        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT (Ctrl+C), shutting down...");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down...");
            }
            _ = api_shutdown.notified() => {
                info!("Shutdown requested via API, shutting down...");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C received, shutting down...");
            }
            _ = api_shutdown.notified() => {
                info!("Shutdown requested via API, shutting down...");
            }
        }
    }
}

/// Check if a process with the given PID is still alive.
fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // Use kill -0 to check if process exists without sending a signal
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(windows)]
    {
        // tasklist /FI "PID eq N" returns "INFO: No tasks..." when no match,
        // or a table row with the PID when found. Check exit code and that
        // "INFO:" is NOT in the output to confirm the process exists.
        std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .map(|o| {
                o.status.success() && {
                    let out = String::from_utf8_lossy(&o.stdout);
                    !out.contains("INFO:") && out.contains(&pid.to_string())
                }
            })
            .unwrap_or(false)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

/// Check if an T3rnel daemon is actually responding at the given address.
/// This avoids false positives where a different process reused the same PID
/// after a system reboot.
fn is_daemon_responding(addr: &str) -> bool {
    // Quick TCP connect check — don't make a full HTTP request to avoid delays
    let addr_only = addr
        .strip_prefix("http://")
        .or_else(|| addr.strip_prefix("https://"))
        .unwrap_or(addr);
    if let Ok(sock_addr) = addr_only.parse::<std::net::SocketAddr>() {
        std::net::TcpStream::connect_timeout(&sock_addr, std::time::Duration::from_millis(500))
            .is_ok()
    } else {
        // Fallback: try connecting to hostname
        std::net::TcpStream::connect(addr_only)
            .map(|_| true)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod telemetry_tests {
    use super::choose_otlp_endpoint;

    #[test]
    fn jaeger_trace_endpoint_is_preferred_over_generic_otlp_endpoint() {
        let endpoint = choose_otlp_endpoint(
            Some("http://collector:4317".to_string()),
            Some("http://jaeger:4317".to_string()),
        );
        assert_eq!(endpoint.as_deref(), Some("http://jaeger:4317"));
    }

    #[test]
    fn generic_otlp_endpoint_is_used_when_trace_endpoint_is_absent() {
        let endpoint = choose_otlp_endpoint(Some("http://collector:4317".to_string()), None);
        assert_eq!(endpoint.as_deref(), Some("http://collector:4317"));
    }

    #[test]
    fn blank_otlp_endpoints_disable_export() {
        let endpoint = choose_otlp_endpoint(Some("  ".to_string()), Some(String::new()));
        assert_eq!(endpoint, None);
    }
}
