//! Embedded WebChat UI served as static HTML.
//!
//! The production dashboard is assembled at compile time from separate
//! HTML/CSS/JS files under `static/` using `include_str!()`. This keeps
//! single-binary deployment while allowing organized source files.
//!
//! Features:
//! - Alpine.js SPA with hash-based routing (10 panels)
//! - Dark/light theme toggle with system preference detection
//! - Responsive layout with collapsible sidebar
//! - Markdown rendering + syntax highlighting (bundled locally)
//! - WebSocket real-time chat with HTTP fallback
//! - Agent management, workflows, memory browser, audit log, and more

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use std::path::{Component, PathBuf};

/// Nonce placeholder in compile-time HTML, replaced at request time.
const NONCE_PLACEHOLDER: &str = "__NONCE__";

/// Landing page offered at `/` when both dashboards are available.
///
/// Deliberately script-free: it is the recovery path when a front-end build
/// has gone wrong, so it must render even if the React bundle is broken.
const CHOOSER_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>T3rnel — Choose a dashboard</title>
<link rel="icon" type="image/png" href="/logo.png" />
<style nonce="__NONCE__">
  :root { color-scheme: dark; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center;
    justify-content: center; background: #0a0e14; color: #e6edf3;
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    padding: 2rem 1rem;
  }
  main { width: 100%; max-width: 46rem; }
  h1 { font-size: 1.5rem; margin: 0 0 .5rem; font-weight: 650; }
  p.sub { margin: 0 0 2rem; color: #8b949e; font-size: .95rem; line-height: 1.5; }
  .grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); }
  a.card {
    display: block; padding: 1.25rem; border: 1px solid #21262d; border-radius: .75rem;
    background: #0d1117; text-decoration: none; color: inherit; transition: border-color .15s, background .15s;
  }
  a.card:hover, a.card:focus-visible { border-color: #388bfd; background: #10161f; outline: none; }
  a.card h2 { margin: 0 0 .4rem; font-size: 1.05rem; font-weight: 600; color: #e6edf3; }
  a.card span { display: block; font-size: .875rem; color: #8b949e; line-height: 1.45; }
  footer { margin-top: 2rem; font-size: .8rem; color: #6e7681; line-height: 1.6; }
  code { background: #161b22; padding: .1rem .35rem; border-radius: .25rem; font-size: .8rem; }
</style>
</head>
<body>
<main>
  <h1>Choose a dashboard</h1>
  <p class="sub">Both interfaces are served by this daemon and talk to the same API.</p>
  <div class="grid">
    <a class="card" href="/app">
      <h2>Web app &rarr;</h2>
      <span>The React interface, shared with the desktop and mobile shells. Chat, media.</span>
    </a>
    <a class="card" href="/classic">
      <h2>Classic dashboard &rarr;</h2>
      <span>The built-in operator console. Providers, models, ClawHub, jobs, memory, triggers, security.</span>
    </a>
  </div>
  <footer>
    Skip this page permanently with <code>T3RNEL_DEFAULT_UI=app</code> or <code>T3RNEL_DEFAULT_UI=classic</code>.
  </footer>
</main>
</body>
</html>
"#;

/// Compile-time ETag based on the crate version.
/// Not used for the dashboard page (nonce prevents caching) but retained
/// for potential future use by static asset handlers.
#[allow(dead_code)]
const ETAG: &str = concat!("\"t3rnel-", env!("CARGO_PKG_VERSION"), "\"");

/// Embedded logo PNG for single-binary deployment.
const LOGO_PNG: &[u8] = include_bytes!("../static/logo.png");

/// Embedded favicon ICO for browser tabs.
const FAVICON_ICO: &[u8] = include_bytes!("../static/favicon.ico");

/// GET /logo.png — Serve the T3rnel logo.
pub async fn logo_png() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=86400, immutable"),
        ],
        LOGO_PNG,
    )
}

/// GET /favicon.ico — Serve the T3rnel favicon.
pub async fn favicon_ico() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/x-icon"),
            (header::CACHE_CONTROL, "public, max-age=86400, immutable"),
        ],
        FAVICON_ICO,
    )
}

/// Embedded PWA manifest for installable web app support.
const MANIFEST_JSON: &str = include_str!("../static/manifest.json");

/// Embedded service worker for PWA support.
const SW_JS: &str = include_str!("../static/sw.js");

/// GET /manifest.json — Serve the PWA web app manifest.
pub async fn manifest_json() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/manifest+json"),
            (header::CACHE_CONTROL, "public, max-age=86400, immutable"),
        ],
        MANIFEST_JSON,
    )
}

/// GET /sw.js — Serve the PWA service worker.
pub async fn sw_js() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/javascript"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        SW_JS,
    )
}

/// Which UI `/` should serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootUi {
    /// Let the operator pick — both UIs are available.
    Chooser,
    /// The React single-page app from `clients/web/dist`.
    React,
    /// The dashboard compiled into the binary.
    Classic,
}

/// Decide what `/` serves.
///
/// Kept free of I/O so the precedence rules are directly testable: an explicit
/// operator preference wins, otherwise the operator is offered the choice, and
/// with no React build on disk there is nothing to choose between.
pub(crate) fn resolve_root_ui(
    default_ui: Option<&str>,
    classic_pin: Option<&str>,
    dist_present: bool,
) -> RootUi {
    if !dist_present {
        return RootUi::Classic;
    }

    if matches!(
        classic_pin.map(str::trim),
        Some("1") | Some("true") | Some("yes")
    ) {
        return RootUi::Classic;
    }

    match default_ui
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("classic") => RootUi::Classic,
        Some("app") | Some("react") | Some("web") => RootUi::React,
        _ => RootUi::Chooser,
    }
}

/// GET / — Serve the chosen T3rnel dashboard, or offer the choice.
///
/// A `clients/web/dist` build shadows the built-in dashboard the moment it
/// exists, which silently removes the operator tabs (providers, models,
/// ClawHub, jobs, triggers, security) with no way back. When both UIs are
/// available the operator picks; `T3RNEL_DEFAULT_UI=app|classic` skips the
/// landing page for good.
pub async fn webchat_page() -> Response {
    let dist_html = read_react_dist_text("index.html");
    let choice = resolve_root_ui(
        std::env::var("T3RNEL_DEFAULT_UI").ok().as_deref(),
        std::env::var("T3RNEL_CLASSIC_UI").ok().as_deref(),
        dist_html.is_some(),
    );

    match choice {
        RootUi::React => match dist_html {
            Some(html) => react_html_response(html),
            None => classic_dashboard_response(),
        },
        RootUi::Classic => classic_dashboard_response(),
        RootUi::Chooser => chooser_response(),
    }
}

/// GET /app — Serve the React single-page app.
///
/// Falls back to the built-in dashboard rather than 404ing, so this link is
/// never a dead end when the front-end has not been built.
pub async fn react_app_page() -> Response {
    match read_react_dist_text("index.html") {
        Some(html) => react_html_response(html),
        None => classic_dashboard_response(),
    }
}

/// GET /classic — Serve the built-in dashboard even when a React build exists.
///
/// This dashboard is compiled into the binary, so it cannot be shadowed by a
/// front-end build or go missing.
pub async fn classic_dashboard_page() -> Response {
    classic_dashboard_response()
}

fn chooser_response() -> Response {
    let nonce = uuid::Uuid::new_v4().to_string();
    let html = CHOOSER_HTML.replace(NONCE_PLACEHOLDER, &nonce);
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (
                header::HeaderName::from_static("content-security-policy"),
                format!(
                    "default-src 'self'; script-src 'none'; style-src 'nonce-{nonce}'; \
                     img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'"
                ),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        html,
    )
        .into_response()
}

fn classic_dashboard_response() -> Response {
    let nonce = uuid::Uuid::new_v4().to_string();
    let html = WEBCHAT_HTML.replace(NONCE_PLACEHOLDER, &nonce);
    let csp = format!(
        "default-src 'self'; \
         script-src 'self' 'nonce-{nonce}' 'unsafe-eval' https://cdn.jsdelivr.net; \
         style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com https://cdn.jsdelivr.net; \
         img-src 'self' data: blob:; \
         connect-src 'self' ws://localhost:* ws://127.0.0.1:* wss://localhost:* wss://127.0.0.1:* https://cdn.jsdelivr.net; \
         font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; \
         media-src 'self' blob:; \
         frame-src 'self' blob:; \
         object-src 'none'; \
         base-uri 'self'; \
         form-action 'self'"
    );
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (
                header::HeaderName::from_static("content-security-policy"),
                csp,
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        html,
    )
        .into_response()
}

/// GET /assets/{path} — Serve the shared React dashboard build assets.
pub async fn react_asset(Path(path): Path<String>) -> Response {
    serve_react_dist_file(format!("assets/{path}"))
}

/// GET /.well-known/{path} — agent-discovery manifests shipped by the React
/// build's `public/` (agent-card, mcp-server-card, agent-rules).
pub async fn react_well_known(Path(path): Path<String>) -> Response {
    serve_react_dist_file(format!(".well-known/{path}"))
}

/// GET /{file} for the flat agent surfaces — the allowlist is the contract,
/// not a glob; anything else 404s exactly as before.
pub async fn react_agent_surface(Path(file): Path<String>) -> Response {
    match file.as_str() {
        "AGENTS.md" | "llms.txt" | "robots.txt" | "openapi.json" | "agents.json" => {
            serve_react_dist_file(file)
        }
        _ => (StatusCode::NOT_FOUND, "asset not found").into_response(),
    }
}

fn react_html_response(html: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (
                header::CACHE_CONTROL,
                "no-store",
            ),
            (
                header::HeaderName::from_static("content-security-policy"),
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ws://localhost:* ws://127.0.0.1:* wss://localhost:* wss://127.0.0.1:*; font-src 'self'; media-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'self'",
            ),
        ],
        html,
    )
        .into_response()
}

fn serve_react_dist_file(path: String) -> Response {
    let Some(bytes) = read_react_dist_bytes(&path) else {
        return (StatusCode::NOT_FOUND, "asset not found").into_response();
    };
    (
        [
            (header::CONTENT_TYPE, content_type_for_path(&path)),
            (
                header::CACHE_CONTROL,
                if path.starts_with("assets/") {
                    "public, max-age=31536000, immutable"
                } else {
                    "no-cache"
                },
            ),
        ],
        bytes,
    )
        .into_response()
}

fn read_react_dist_text(path: &str) -> Option<String> {
    String::from_utf8(read_react_dist_bytes(path)?).ok()
}

fn read_react_dist_bytes(path: &str) -> Option<Vec<u8>> {
    let relative = sanitize_dist_path(path)?;
    std::fs::read(react_dist_dir()?.join(relative)).ok()
}

fn react_dist_dir() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("T3RNEL_WEB_DIST") {
        let dir = PathBuf::from(path);
        if dir.join("index.html").is_file() {
            return Some(dir);
        }
    }

    let cwd_dir = std::env::current_dir().ok()?.join("clients/web/dist");
    if cwd_dir.join("index.html").is_file() {
        return Some(cwd_dir);
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_dir = manifest_dir.parent()?.parent()?;
    let dist_dir = repo_dir.join("clients/web/dist");
    if dist_dir.join("index.html").is_file() {
        return Some(dist_dir);
    }
    None
}

fn sanitize_dist_path(path: &str) -> Option<PathBuf> {
    let mut clean = PathBuf::new();
    for component in std::path::Path::new(path).components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if clean.as_os_str().is_empty() {
        None
    } else {
        Some(clean)
    }
}

fn content_type_for_path(path: &str) -> &'static str {
    if path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".json") {
        "application/json; charset=utf-8"
    } else if path.ends_with(".md") {
        "text/markdown; charset=utf-8"
    } else if path.ends_with(".txt") {
        "text/plain; charset=utf-8"
    } else if path.ends_with(".xml") {
        "application/xml; charset=utf-8"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else {
        "application/octet-stream"
    }
}

/// The embedded HTML/CSS/JS for the T3rnel Dashboard.
///
/// Assembled at compile time from organized static files.
/// All vendor libraries (Alpine.js, marked.js, highlight.js) are bundled
/// locally — no CDN dependency. Alpine.js is included LAST because it
/// immediately processes x-data directives and fires alpine:init on load.
/// KaTeX is loaded dynamically from jsdelivr CDN when needed for LaTeX rendering.
const WEBCHAT_HTML: &str = concat!(
    include_str!("../static/index_head.html"),
    "<style>\n",
    include_str!("../static/css/theme.css"),
    "\n",
    include_str!("../static/css/layout.css"),
    "\n",
    include_str!("../static/css/components.css"),
    "\n",
    include_str!("../static/vendor/github-dark.min.css"),
    "\n</style>\n",
    include_str!("../static/index_body.html"),
    // Vendor libs: marked + highlight first (used by app.js), then Chart.js
    "<script nonce=\"__NONCE__\">\n",
    include_str!("../static/vendor/marked.min.js"),
    "\n</script>\n",
    "<script nonce=\"__NONCE__\">\n",
    include_str!("../static/vendor/highlight.min.js"),
    "\n</script>\n",
    "<script nonce=\"__NONCE__\">\n",
    include_str!("../static/vendor/chart.umd.min.js"),
    "\n</script>\n",
    // App code
    "<script nonce=\"__NONCE__\">\n",
    include_str!("../static/js/api.js"),
    "\n",
    include_str!("../static/js/app.js"),
    "\n",
    include_str!("../static/js/pages/overview.js"),
    "\n",
    include_str!("../static/js/katex.js"),
    "\n",
    include_str!("../static/js/pages/chat.js"),
    "\n",
    include_str!("../static/js/pages/agents.js"),
    "\n",
    include_str!("../static/js/pages/workflows.js"),
    "\n",
    include_str!("../static/js/pages/workflow-builder.js"),
    "\n",
    include_str!("../static/js/pages/channels.js"),
    "\n",
    include_str!("../static/js/pages/skills.js"),
    "\n",
    include_str!("../static/js/pages/hands.js"),
    "\n",
    include_str!("../static/js/pages/scheduler.js"),
    "\n",
    include_str!("../static/js/pages/settings.js"),
    "\n",
    include_str!("../static/js/pages/usage.js"),
    "\n",
    include_str!("../static/js/pages/sessions.js"),
    "\n",
    include_str!("../static/js/pages/logs.js"),
    "\n",
    include_str!("../static/js/pages/wizard.js"),
    "\n",
    include_str!("../static/js/pages/approvals.js"),
    "\n",
    include_str!("../static/js/pages/comms.js"),
    "\n",
    include_str!("../static/js/pages/runtime.js"),
    "\n</script>\n",
    // Alpine.js MUST be last — it processes x-data and fires alpine:init
    "<script nonce=\"__NONCE__\">\n",
    include_str!("../static/vendor/alpine.min.js"),
    "\n</script>\n",
    "</body></html>"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_react_build_means_no_choice_to_offer() {
        assert_eq!(resolve_root_ui(None, None, false), RootUi::Classic);
        // Even an explicit React preference cannot be honoured without a build.
        assert_eq!(resolve_root_ui(Some("app"), None, false), RootUi::Classic);
    }

    #[test]
    fn both_uis_available_offers_the_choice() {
        assert_eq!(resolve_root_ui(None, None, true), RootUi::Chooser);
    }

    #[test]
    fn explicit_preference_skips_the_landing_page() {
        assert_eq!(resolve_root_ui(Some("app"), None, true), RootUi::React);
        assert_eq!(resolve_root_ui(Some("react"), None, true), RootUi::React);
        assert_eq!(resolve_root_ui(Some("web"), None, true), RootUi::React);
        assert_eq!(
            resolve_root_ui(Some("classic"), None, true),
            RootUi::Classic
        );
    }

    #[test]
    fn preference_is_case_and_whitespace_insensitive() {
        assert_eq!(resolve_root_ui(Some("  APP  "), None, true), RootUi::React);
        assert_eq!(
            resolve_root_ui(Some("Classic"), None, true),
            RootUi::Classic
        );
    }

    #[test]
    fn unrecognised_preference_falls_back_to_the_chooser() {
        // A typo must not silently pick a UI the operator did not ask for.
        assert_eq!(resolve_root_ui(Some("alpine"), None, true), RootUi::Chooser);
        assert_eq!(resolve_root_ui(Some(""), None, true), RootUi::Chooser);
    }

    #[test]
    fn classic_pin_wins_over_the_chooser() {
        assert_eq!(resolve_root_ui(None, Some("1"), true), RootUi::Classic);
        assert_eq!(resolve_root_ui(None, Some("true"), true), RootUi::Classic);
        assert_eq!(resolve_root_ui(None, Some("yes"), true), RootUi::Classic);
        assert_eq!(resolve_root_ui(None, Some("0"), true), RootUi::Chooser);
    }

    async fn body_text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn classic_route_serves_the_built_in_dashboard() {
        let response = classic_dashboard_page().await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        // The Alpine root element only exists in the built-in dashboard.
        assert!(body.contains("x-data=\"app\""));
        assert!(
            !body.contains(NONCE_PLACEHOLDER),
            "nonce must be substituted"
        );
    }

    #[tokio::test]
    async fn app_route_never_dead_ends() {
        // Serves the React build when present, the built-in dashboard when not,
        // but always something renderable.
        let response = react_app_page().await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        assert!(body.contains("<html") || body.contains("<!doctype"));
    }

    #[test]
    fn chooser_links_to_both_dashboards_without_script() {
        assert!(CHOOSER_HTML.contains("href=\"/app\""));
        assert!(CHOOSER_HTML.contains("href=\"/classic\""));
        // The chooser is the recovery path for a broken front-end build, so it
        // must not depend on any script executing.
        assert!(!CHOOSER_HTML.contains("<script"));
        assert!(CHOOSER_HTML.contains(NONCE_PLACEHOLDER));
    }

    #[tokio::test]
    async fn agent_surface_allowlist_refuses_everything_else() {
        // The route is a param segment — only the named discovery files may
        // resolve, even when a React build happens to be on disk.
        for file in [
            "sw.js",
            "manifest.json",
            "../index.html",
            "index.html",
            "agent-card.json", // only legal under /.well-known/
            "evil.sh",
        ] {
            let response = react_agent_surface(axum::extract::Path(file.to_string())).await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{file}");
        }
    }

    #[tokio::test]
    async fn agent_surface_serves_shipped_files_from_dist() {
        let dir = std::env::temp_dir().join(format!("t3rnel-web-dist-{}", std::process::id()));
        std::fs::create_dir_all(dir.join(".well-known")).unwrap();
        std::fs::write(dir.join("index.html"), "<!doctype html>").unwrap();
        std::fs::write(dir.join("AGENTS.md"), "# test contract").unwrap();
        std::fs::write(dir.join(".well-known/agent-card.json"), "{\"name\":\"t\"}").unwrap();
        std::env::set_var("T3RNEL_WEB_DIST", &dir);

        let md = react_agent_surface(axum::extract::Path("AGENTS.md".to_string())).await;
        assert_eq!(md.status(), StatusCode::OK);
        assert_eq!(
            md.headers()[header::CONTENT_TYPE],
            "text/markdown; charset=utf-8"
        );
        assert!(body_text(md).await.contains("test contract"));

        let card = react_well_known(axum::extract::Path("agent-card.json".to_string())).await;
        assert_eq!(card.status(), StatusCode::OK);
        assert_eq!(
            card.headers()[header::CONTENT_TYPE],
            "application/json; charset=utf-8"
        );

        // Traversal into .well-known stays refused.
        let traversal = react_well_known(axum::extract::Path("../AGENTS.md".to_string())).await;
        assert_eq!(traversal.status(), StatusCode::NOT_FOUND);

        std::env::remove_var("T3RNEL_WEB_DIST");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
