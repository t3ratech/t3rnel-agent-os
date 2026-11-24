use crate::routes::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use t3rnel_memory::facade::FacadeError;
use t3rnel_types::unified_memory::{MemoryBudget, MemoryDepth, MemoryKind, MemoryQuery};

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SearchParams {
    query: String,
    kind: Option<MemoryKind>,
    limit: Option<usize>,
    budget: Option<usize>,
    offset: usize,
    depth: MemoryDepth,
    key: Option<String>,
    key_prefix: Option<String>,
    as_of: Option<chrono::DateTime<chrono::Utc>>,
    include_inactive: bool,
}

async fn run(state: Arc<AppState>, operation: &'static str, args: Value) -> Response {
    run_for(state, None, operation, args).await
}

pub(crate) async fn run_for(
    state: Arc<AppState>,
    caller: Option<&str>,
    operation: &'static str,
    args: Value,
) -> Response {
    let (context, scope) = match state.kernel.unified_memory_context(caller) {
        Ok(context) => context,
        Err(_) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error":"Memory caller denied"})),
            )
                .into_response()
        }
    };
    let memory = state.kernel.memory.clone();
    match tokio::task::spawn_blocking(move || {
        memory.unified_command(&context, &scope, operation, args)
    })
    .await
    {
        Ok(Ok(value)) if value.is_null() => (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"Memory record not found"})),
        )
            .into_response(),
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => {
            let status = match error {
                FacadeError::Invalid(_) => StatusCode::BAD_REQUEST,
                FacadeError::Forbidden | FacadeError::Blocked => StatusCode::FORBIDDEN,
                FacadeError::Conflict => StatusCode::CONFLICT,
                FacadeError::Storage => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status, Json(json!({"error":error.to_string()}))).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"Memory worker unavailable"})),
        )
            .into_response(),
    }
}

fn query_args(params: SearchParams) -> Value {
    let mut query = MemoryQuery {
        text: params.query,
        kind: params.kind,
        depth: params.depth,
        offset: params.offset,
        key: params.key,
        key_prefix: params.key_prefix,
        as_of: params.as_of,
        include_inactive: params.include_inactive,
        ..Default::default()
    };
    if let Some(limit) = params.limit {
        query.limit = limit;
    }
    if let Some(budget) = params.budget {
        query.budget = MemoryBudget {
            max_tokens: budget,
            max_bytes: budget,
        };
    }
    json!(query)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    operation: String,
    args: Value,
}

pub async fn command(State(state): State<Arc<AppState>>, Json(request): Json<Command>) -> Response {
    let operation = match request.operation.as_str() {
        "remember" => "remember",
        "search" => "search",
        "ls" => "ls",
        "facts" => "facts",
        "handover" => "handover",
        "get" => "get",
        "kv_get" => "kv_get",
        "kv_set" => "kv_set",
        "supersede" => "supersede",
        "expire" => "expire",
        "restore" => "restore",
        "expire_sweep" => "expire_sweep",
        "purge_expired" => "purge_expired",
        "policy_set" => "policy_set",
        "policy_get" => "policy_get",
        "brief" => "brief",
        "conflicts" => "conflicts",
        "history" => "history",
        "events" => "events",
        "export" => "export",
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error":"Unknown memory operation"})),
            )
                .into_response()
        }
    };
    run(state, operation, request.args).await
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EventsParams {
    since: i64,
    limit: Option<usize>,
}

/// GET /api/memory/events — tail the append-only memory event log.
///
/// The feed only carries events for scopes the resolved caller may read, and
/// each payload is sentinel-scanned on egress before leaving the daemon.
/// Pipelines and dashboards poll `since=<last seq>` instead
/// of scraping state files.
pub async fn events(
    State(state): State<Arc<AppState>>,
    Query(params): Query<EventsParams>,
) -> Response {
    run(
        state,
        "events",
        json!({"since":params.since,"limit":params.limit.unwrap_or(100)}),
    )
    .await
}

/// GET /api/memory/conflicts — list likely contradictions in the scope.
pub async fn conflicts(State(state): State<Arc<AppState>>) -> Response {
    run(state, "conflicts", json!({})).await
}

/// GET /api/memory/brief — the salience-ranked briefing for this caller.
pub async fn brief(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchParams>,
) -> Response {
    run(
        state,
        "brief",
        json!({"key":params.key,"budget":params.budget.unwrap_or(8192)}),
    )
    .await
}

/// GET /api/memory/export — the readable estate as one JSON bundle for
/// vault/markdown renderers (`--memory-export` in t3rnel-services).
pub async fn export(State(state): State<Arc<AppState>>) -> Response {
    run(state, "export", json!({})).await
}

pub async fn search(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchParams>,
) -> Response {
    run(state, "search", query_args(params)).await
}

pub async fn remember(State(state): State<Arc<AppState>>, Json(request): Json<Value>) -> Response {
    run(state, "remember", request).await
}

pub async fn get(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    run(state, "get", json!({"id":id})).await
}

pub async fn handover(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchParams>,
) -> Response {
    run(state, "handover", query_args(params)).await
}

pub async fn kv_get(State(state): State<Arc<AppState>>, Path(key): Path<String>) -> Response {
    run(state, "kv_get", json!({"key":key})).await
}

pub async fn kv_set(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Json(mut body): Json<Value>,
) -> Response {
    let Some(fields) = body.as_object_mut() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"Expected an object with value and optional expected_revision"})),
        )
            .into_response();
    };
    if fields.contains_key("key") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"The key belongs in the URL only"})),
        )
            .into_response();
    }
    fields.insert("key".into(), Value::String(key));
    run(state, "kv_set", body).await
}
