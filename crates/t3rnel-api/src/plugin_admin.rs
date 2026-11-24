//! Plugin lifecycle REST routes (`17-implementation-guide.md` §9.7).
//!
//! Thin axum surface over [`t3rnel_runtime::plugin_lifecycle::PluginManager`].
//! Mount with `.merge(plugin_admin::router(manager))` in `server.rs` — the
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
use t3rnel_runtime::plugin_lifecycle::{
    InstallOptions, LifecycleError, PluginManager, DEV_MODE_WARNING,
};

#[derive(Clone)]
pub struct PluginAdminState {
    pub manager: Arc<PluginManager>,
    pub install_opts: InstallOptions,
}

#[derive(Debug, Deserialize)]
pub struct InstallRequest {
    /// Filesystem path to the unpacked plugin package directory.
    pub package_path: String,
    /// Dev-mode installs (unsigned) — only honoured when the host enabled it.
    #[serde(default)]
    pub dev_mode: bool,
}

fn err(e: LifecycleError) -> (StatusCode, String) {
    let code = match &e {
        LifecycleError::Manifest(_) | LifecycleError::MissingEntry(_) => StatusCode::BAD_REQUEST,
        LifecycleError::Signature(_) | LifecycleError::Revoked(_) => StatusCode::FORBIDDEN,
        LifecycleError::Quarantined(_, _) => StatusCode::TOO_MANY_REQUESTS,
        LifecycleError::NoPrevious => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, e.to_string())
}

/// Build the router. `home` is the T3rnel home (scratch dir in tests).
pub fn router(manager: Arc<PluginManager>, opts: InstallOptions) -> Router {
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
        .with_state(PluginAdminState {
            manager,
            install_opts: opts,
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

async fn list_plugins(State(st): State<PluginAdminState>) -> impl IntoResponse {
    let dev_mode = st.install_opts.dev_mode;
    Json(serde_json::json!({
        "plugins": st.manager.list(),
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
    Ok(Json(serde_json::to_value(report).unwrap()))
}

async fn rollback_plugin(
    State(st): State<PluginAdminState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    st.manager.rollback(&id).map_err(err)?;
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
        (router(mgr, opts), home)
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
    }
}
