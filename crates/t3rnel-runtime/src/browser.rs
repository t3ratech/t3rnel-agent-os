//! Native browser automation via Chrome DevTools Protocol (CDP).
//!
//! Direct WebSocket connection to Chromium. No Python, no Playwright.
//! Launches a Chromium process, connects over CDP WebSocket, and sends
//! JSON-RPC commands for navigation, interaction, screenshots, etc.
//!
//! # Security
//! - SSRF check runs in Rust before navigate commands
//! - All page content wrapped with `wrap_external_content()` markers
//! - Session limits: max concurrent, idle timeout, 1 per agent
//! - No subprocess bridge, no env leakage, no Python code execution

use dashmap::DashMap;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use t3rnel_types::config::BrowserConfig;
use tokio::io::AsyncBufReadExt;
use tokio::sync::{oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, info, warn};

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

// ── Constants ──────────────────────────────────────────────────────────────

const CDP_CONNECT_TIMEOUT_SECS: u64 = 15;
const CDP_COMMAND_TIMEOUT_SECS: u64 = 30;
const PAGE_LOAD_POLL_INTERVAL_MS: u64 = 200;
const PAGE_LOAD_MAX_POLLS: u32 = 150; // 30 seconds
#[allow(dead_code)]
const MAX_CONTENT_CHARS: usize = 50_000;

// ── Public types ───────────────────────────────────────────────────────────

/// Command sent to the browser.
///
/// Field names deliberately accept both the daemon-native names
/// (`expression`, `text`, `index`) and the extension/MCP schema names
/// (`code`, `value`, `tabId`) — the HTTP route and the ops probe forward the
/// extension's arguments verbatim, so a name that differs between the two
/// surfaces silently broke the CDP fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action")]
pub enum BrowserCommand {
    Navigate {
        url: String,
        /// Open the URL in a new tab and re-point this session at it.
        #[serde(default)]
        new_tab: bool,
        /// Drive the navigation on this tab first (extension `tabId` maps to
        /// the positional index `ListTabs` prints).
        #[serde(default)]
        tab_index: Option<usize>,
    },
    Click {
        selector: String,
    },
    Type {
        selector: String,
        text: String,
    },
    Screenshot {
        #[serde(default)]
        format: Option<String>,
        #[serde(default)]
        quality: Option<u8>,
    },
    ReadPage,
    /// Close the whole browser session (kept for `browser_close`).
    Close,
    /// Close one page target by the positional index `ListTabs` reports.
    CloseTab {
        index: usize,
    },
    Scroll {
        direction: String,
        amount: i32,
        /// Optional element to scroll; absent scrolls the window.
        #[serde(default)]
        selector: Option<String>,
    },
    Wait {
        /// `selector` (default), `load` or `url` — mirrors the extension
        /// schema's `condition` values.
        condition: String,
        /// Selector string for `selector`, URL substring for `url`,
        /// unused for `load`.
        target: String,
        timeout_ms: u64,
    },
    RunJs {
        expression: String,
    },
    Back,
    Forward,
    Reload,
    Hover {
        selector: String,
    },
    /// Press a key, optionally after focusing `selector`.
    ///
    /// Distinct from `Type`: a form often needs Tab to move between fields,
    /// Enter to submit, or Escape to dismiss an overlay — none of which are
    /// expressible as text input.
    Press {
        selector: Option<String>,
        key: String,
    },
    /// Choose an option in a `<select>` by value, visible label or index.
    Select {
        selector: String,
        #[serde(default)]
        value: Option<String>,
        #[serde(default)]
        index: Option<usize>,
    },
    ListTabs,
    SwitchTab {
        index: usize,
    },
    /// Re-point the session at the first tab whose URL contains this substring.
    SwitchTabUrl {
        url_match: String,
    },
    /// Set files on a `<input type=file>` without an OS file dialog.
    ///
    /// `nth` selects among matching inputs — pages routinely carry several
    /// (avatar, banner, post media) that are indistinguishable by selector.
    Upload {
        selector: String,
        files: Vec<String>,
        nth: usize,
    },
}

/// Response from a browser command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserResponse {
    pub success: bool,
    pub data: Option<serde_json::Value>,
    pub error: Option<String>,
}

impl BrowserResponse {
    fn ok(data: serde_json::Value) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

// ── CDP connection ─────────────────────────────────────────────────────────

/// Low-level Chrome DevTools Protocol connection over WebSocket.
struct CdpConnection {
    write: Arc<Mutex<SplitSink<WsStream, WsMessage>>>,
    pending: Arc<DashMap<u64, oneshot::Sender<Result<serde_json::Value, String>>>>,
    next_id: AtomicU64,
    _reader_handle: tokio::task::JoinHandle<()>,
}

impl CdpConnection {
    /// Connect to a CDP WebSocket endpoint.
    async fn connect(ws_url: &str) -> Result<Self, String> {
        let (stream, _) = tokio::time::timeout(
            Duration::from_secs(CDP_CONNECT_TIMEOUT_SECS),
            tokio_tungstenite::connect_async(ws_url),
        )
        .await
        .map_err(|_| format!("CDP WebSocket connect timed out: {ws_url}"))?
        .map_err(|e| format!("CDP WebSocket connect failed: {e}"))?;

        let (write, read) = stream.split();
        let write = Arc::new(Mutex::new(write));
        let pending: Arc<DashMap<u64, oneshot::Sender<Result<serde_json::Value, String>>>> =
            Arc::new(DashMap::new());

        let reader_pending = Arc::clone(&pending);
        let reader_handle = tokio::spawn(Self::reader_loop(read, reader_pending));

        Ok(Self {
            write,
            pending,
            next_id: AtomicU64::new(1),
            _reader_handle: reader_handle,
        })
    }

    /// Background task: read WebSocket messages and route responses.
    async fn reader_loop(
        mut read: SplitStream<WsStream>,
        pending: Arc<DashMap<u64, oneshot::Sender<Result<serde_json::Value, String>>>>,
    ) {
        while let Some(msg) = read.next().await {
            let text = match msg {
                Ok(WsMessage::Text(t)) => t.to_string(),
                Ok(WsMessage::Close(_)) => break,
                Err(e) => {
                    debug!("CDP WebSocket read error: {e}");
                    break;
                }
                _ => continue,
            };

            let json: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) => continue,
            };

            // Route response to waiting caller by id
            if let Some(id) = json.get("id").and_then(|v| v.as_u64()) {
                if let Some((_, sender)) = pending.remove(&id) {
                    if let Some(error) = json.get("error") {
                        let msg = error["message"].as_str().unwrap_or("CDP error").to_string();
                        let _ = sender.send(Err(msg));
                    } else {
                        let result = json
                            .get("result")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null);
                        let _ = sender.send(Ok(result));
                    }
                }
            }
            // Events (method field, no id) are ignored for now.
            // Future: handle Fetch.requestPaused for CDP-level SSRF.
        }
    }

    /// Send a CDP command and wait for the response.
    async fn send(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.insert(id, tx);

        let msg = serde_json::json!({ "id": id, "method": method, "params": params });
        self.write
            .lock()
            .await
            .send(WsMessage::Text(msg.to_string()))
            .await
            .map_err(|e| format!("CDP send failed: {e}"))?;

        match tokio::time::timeout(Duration::from_secs(CDP_COMMAND_TIMEOUT_SECS), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err("CDP response channel closed".to_string()),
            Err(_) => {
                self.pending.remove(&id);
                Err("CDP command timed out".to_string())
            }
        }
    }

    /// Evaluate JavaScript in the browser page and return the value.
    async fn run_js(&self, expression: &str) -> Result<serde_json::Value, String> {
        let result = self
            .send(
                "Runtime.evaluate",
                serde_json::json!({
                    "expression": expression,
                    "returnByValue": true,
                    "awaitPromise": true,
                }),
            )
            .await?;

        // Check for JS exceptions
        if let Some(desc) = result
            .get("exceptionDetails")
            .and_then(|e| e.get("text"))
            .and_then(|t| t.as_str())
        {
            return Err(format!("JS error: {desc}"));
        }

        Ok(result
            .get("result")
            .and_then(|r| r.get("value"))
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }
}

impl Drop for CdpConnection {
    fn drop(&mut self) {
        self._reader_handle.abort();
    }
}

// ── Browser session ────────────────────────────────────────────────────────

/// A live browser session: one Chromium process + one CDP connection per agent.
struct BrowserSession {
    /// `None` when attached to a browser T3rnel did not start.
    ///
    /// Load-bearing: the `Drop` impl kills this process. Attaching to the
    /// operator's own browser and then killing it on session teardown would
    /// close every tab they had open, which is a far worse outcome than any
    /// leaked session.
    process: Option<tokio::process::Child>,
    cdp: CdpConnection,
    #[allow(dead_code)]
    last_active: Instant,
    /// Per-launch Chrome profile, removed on drop. `None` when attached.
    ///
    /// Each launch gets a fresh directory, so without cleanup every browser
    /// session would leave a multi-megabyte profile behind in the temp dir —
    /// on a machine already running at 87% disk, that is a slow outage.
    profile_dir: Option<std::path::PathBuf>,
    /// HTTP base of the debug endpoint this session attached to
    /// (`http://127.0.0.1:<port>`). Switching and closing tabs need it to
    /// rebind — the previous code hardcoded port 9222, so `SwitchTab` could
    /// never work on a launched session, which binds a random port.
    debug_base: String,
    /// Target id of the page `cdp` is currently attached to. Closing that
    /// tab without re-pointing the session would leave every later command
    /// failing on a dead socket, so `CloseTab` needs to know which it is.
    attached_target: Option<String>,
}

impl BrowserSession {
    /// Launch Chromium and establish a CDP connection.
    async fn launch(config: &BrowserConfig) -> Result<Self, String> {
        // Attach mode: drive a browser the operator already started, sharing
        // their profile and signed-in sessions. Opt-in via `cdp_endpoint`.
        if let Some(endpoint) = config
            .cdp_endpoint
            .as_deref()
            .map(str::trim)
            .filter(|e| !e.is_empty())
        {
            return Self::attach(endpoint).await;
        }

        let chrome_path = find_chromium(config)?;
        debug!(path = %chrome_path.display(), "Launching Chromium");

        // Isolated profile directory, per launch.
        //
        // Two problems, one fix. Without `--user-data-dir` Chrome uses the
        // operator's DEFAULT profile:
        //
        //  1. Headed mode silently fails. If any Chrome is already running on
        //     that profile — 58 processes on this workstation — the new launch
        //     hands off to the existing instance and exits immediately, which
        //     surfaces as "Chromium exited before printing DevTools URL. Is
        //     Chrome installed?" while Chrome is installed and working.
        //     `--headless=new` sidesteps the collision, which is why this stayed
        //     hidden until the first headed run.
        //
        //  2. It is a privacy hole. The agent would drive the human's real
        //     profile, with their logged-in sessions and cookies attached to
        //     every navigation the agent performs.
        //
        // A per-launch directory under the OS temp dir fixes both. It is not
        // reused across launches deliberately: a persistent agent profile would
        // accumulate cookies and become a tracking surface of its own.
        let profile_dir = std::env::temp_dir().join(format!(
            "t3rnel-browser-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        if let Err(e) = std::fs::create_dir_all(&profile_dir) {
            return Err(format!(
                "Failed to create isolated browser profile at {}: {e}",
                profile_dir.display()
            ));
        }

        let mut args = vec![
            "--remote-debugging-port=0".to_string(),
            format!("--user-data-dir={}", profile_dir.display()),
            "--no-first-run".to_string(),
            "--no-default-browser-check".to_string(),
            "--disable-extensions".to_string(),
            "--disable-background-networking".to_string(),
            "--disable-sync".to_string(),
            "--disable-translate".to_string(),
            "--disable-features=TranslateUI".to_string(),
            "--metrics-recording-only".to_string(),
            format!(
                "--window-size={},{}",
                config.viewport_width, config.viewport_height
            ),
            "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string(),
            "about:blank".to_string(),
        ];
        if config.headless {
            args.insert(0, "--headless=new".to_string());
            args.push("--disable-gpu".to_string());
        }
        // Chromium refuses to run as root without --no-sandbox. Detect this
        // without adding a libc dependency by reading the effective UID from
        // /proc/self/status (Linux) or falling back to the HOME env var.
        if is_running_as_root() {
            args.push("--no-sandbox".to_string());
        }

        let mut cmd = tokio::process::Command::new(&chrome_path);
        cmd.args(&args);
        cmd.stderr(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::null());
        cmd.stdin(std::process::Stdio::null());

        // SECURITY: clear environment, pass only essentials
        cmd.env_clear();
        for key in &[
            "PATH",
            "HOME",
            "USERPROFILE",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "APPDATA",
            "LOCALAPPDATA",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            // Required for headed mode. `DISPLAY` alone tells Chrome *where*
            // the X server is; without `XAUTHORITY` it cannot authenticate to
            // it and exits before printing the DevTools URL — surfacing as the
            // misleading "Chromium exited before printing DevTools URL. Is
            // Chrome installed?" while Chrome is installed and works fine from
            // a shell that has the cookie. Headless never needed it, so this
            // stayed hidden until the first headed run.
            "XAUTHORITY",
            // Wayland/portal sockets live here; without it a headed browser on
            // a Wayland session falls back to a broken X path.
            "XDG_RUNTIME_DIR",
        ] {
            if let Ok(val) = std::env::var(key) {
                cmd.env(key, val);
            }
        }

        let mut child = cmd.spawn().map_err(|e| {
            format!(
                "Failed to launch Chromium at {}: {e}",
                chrome_path.display()
            )
        })?;

        // Parse stderr for the DevTools WebSocket URL
        let stderr = child.stderr.take().ok_or("No stderr from Chromium")?;
        let ws_url = Self::read_devtools_url(stderr).await?;
        debug!(ws_url = %ws_url, "Got CDP WebSocket URL");

        // GET /json/list to find the page target
        let port = ws_url
            .split("://")
            .nth(1)
            .and_then(|s| s.split(':').nth(1))
            .and_then(|s| s.split('/').next())
            .ok_or("Cannot parse port from CDP URL")?;
        let list_url = format!("http://127.0.0.1:{port}/json/list");

        let page_ws = Self::find_page_ws(&list_url).await?;
        debug!(page_ws = %page_ws, "Connecting to page");

        let attached_target = Self::target_id_from_ws(&page_ws);
        let cdp = CdpConnection::connect(&page_ws).await?;

        // Enable required domains
        let _ = cdp.send("Page.enable", serde_json::json!({})).await;
        let _ = cdp.send("Runtime.enable", serde_json::json!({})).await;

        Ok(Self {
            process: Some(child),
            cdp,
            last_active: Instant::now(),
            profile_dir: Some(profile_dir),
            debug_base: format!("http://127.0.0.1:{port}"),
            attached_target,
        })
    }

    /// Read stderr until we find "DevTools listening on ws://...".
    /// Attach to a browser started outside T3rnel.
    ///
    /// The operator opted into sharing their real profile, so this session
    /// inherits every login and cookie in it. It therefore owns nothing: no
    /// process to kill, no profile directory to delete.
    async fn attach(endpoint: &str) -> Result<Self, String> {
        let base = endpoint.trim_end_matches('/');
        let list_url = format!("{base}/json/list");
        let page_ws = Self::find_page_ws(&list_url).await.map_err(|e| {
            format!(
                "Could not attach to a browser at {base}: {e}. Start it with \
                 --remote-debugging-port and confirm {base}/json/version responds."
            )
        })?;
        let attached_target = Self::target_id_from_ws(&page_ws);
        let cdp = CdpConnection::connect(&page_ws).await?;
        let _ = cdp.send("Page.enable", serde_json::json!({})).await;
        let _ = cdp.send("Runtime.enable", serde_json::json!({})).await;
        info!(endpoint = %base, "Attached to an existing browser (shared profile)");
        Ok(Self {
            process: None,
            cdp,
            last_active: Instant::now(),
            profile_dir: None,
            debug_base: base.to_string(),
            attached_target,
        })
    }

    /// Extract the target id from a `…/devtools/page/<id>` WebSocket URL.
    fn target_id_from_ws(ws_url: &str) -> Option<String> {
        ws_url
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    /// Rebind this session's CDP socket to another page target and mark it
    /// attached. Shared by switch-tab, new-tab navigation and close-tab,
    /// which all die in confusing ways if they leave a stale socket behind.
    async fn attach_target(&mut self, target_id: &str) -> Result<(), String> {
        let ws = format!(
            "{}/devtools/page/{target_id}",
            self.debug_base.replacen("http", "ws", 1)
        );
        let conn = CdpConnection::connect(&ws)
            .await
            .map_err(|e| format!("Found the tab but could not attach to it: {e}"))?;
        let _ = conn.send("Page.enable", serde_json::json!({})).await;
        let _ = conn.send("Runtime.enable", serde_json::json!({})).await;
        self.cdp = conn;
        self.attached_target = Some(target_id.to_string());
        Ok(())
    }

    async fn read_devtools_url(stderr: tokio::process::ChildStderr) -> Result<String, String> {
        let reader = tokio::io::BufReader::new(stderr);
        let mut lines = reader.lines();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(CDP_CONNECT_TIMEOUT_SECS);

        loop {
            let line = tokio::time::timeout_at(deadline, lines.next_line())
                .await
                .map_err(|_| {
                    "Timed out waiting for Chromium to start. Is Chrome/Chromium installed?"
                        .to_string()
                })?
                .map_err(|e| format!("Failed to read Chromium stderr: {e}"))?;

            match line {
                Some(l) if l.contains("DevTools listening on") => {
                    let url = l
                        .split("DevTools listening on ")
                        .nth(1)
                        .ok_or("Malformed DevTools URL line")?
                        .trim()
                        .to_string();
                    return Ok(url);
                }
                Some(_) => continue,
                None => {
                    return Err(
                        "Chromium exited before printing DevTools URL. Is Chrome installed?"
                            .to_string(),
                    );
                }
            }
        }
    }

    /// Fetch /json/list and find the page WebSocket URL.
    async fn find_page_ws(list_url: &str) -> Result<String, String> {
        for attempt in 0..10 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            let resp = match reqwest::get(list_url).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let targets: Vec<serde_json::Value> = match resp.json().await {
                Ok(t) => t,
                Err(_) => continue,
            };
            for target in &targets {
                if target["type"].as_str() == Some("page") {
                    if let Some(ws) = target["webSocketDebuggerUrl"].as_str() {
                        return Ok(ws.to_string());
                    }
                }
            }
        }
        Err("No page target found in Chromium".to_string())
    }

    /// Execute a browser command via CDP.
    async fn execute(&mut self, cmd: BrowserCommand) -> BrowserResponse {
        self.last_active = Instant::now();
        match cmd {
            BrowserCommand::Navigate {
                url,
                new_tab,
                tab_index,
            } => self.cmd_navigate(&url, new_tab, tab_index).await,
            BrowserCommand::Click { selector } => self.cmd_click(&selector).await,
            BrowserCommand::Type { selector, text } => self.cmd_type(&selector, &text).await,
            BrowserCommand::Screenshot { format, quality } => {
                self.cmd_screenshot(format.as_deref(), quality).await
            }
            BrowserCommand::ReadPage => self.cmd_read_page().await,
            BrowserCommand::Close => BrowserResponse::ok(serde_json::json!({"closed": true})),
            BrowserCommand::CloseTab { index } => self.cmd_close_tab(index).await,
            BrowserCommand::Scroll {
                direction,
                amount,
                selector,
            } => {
                self.cmd_scroll(&direction, amount, selector.as_deref())
                    .await
            }
            BrowserCommand::Wait {
                condition,
                target,
                timeout_ms,
            } => self.cmd_wait(&condition, &target, timeout_ms).await,
            BrowserCommand::RunJs { expression } => self.cmd_run_js(&expression).await,
            BrowserCommand::Back => self.cmd_back().await,
            BrowserCommand::Forward => self.cmd_history(1).await,
            BrowserCommand::Reload => self.cmd_reload().await,
            BrowserCommand::Hover { selector } => self.cmd_hover(&selector).await,
            BrowserCommand::Press { selector, key } => {
                self.cmd_press(selector.as_deref(), &key).await
            }
            BrowserCommand::Select {
                selector,
                value,
                index,
            } => self.cmd_select(&selector, value.as_deref(), index).await,
            BrowserCommand::ListTabs => self.cmd_list_tabs().await,
            BrowserCommand::SwitchTab { index } => {
                self.cmd_switch_tab_impl(Some(index), None).await
            }
            BrowserCommand::SwitchTabUrl { url_match } => {
                self.cmd_switch_tab_impl(None, Some(&url_match)).await
            }
            BrowserCommand::Upload {
                selector,
                files,
                nth,
            } => self.cmd_upload(&selector, &files, nth).await,
        }
    }

    // ── Command implementations ────────────────────────────────────────

    async fn cmd_navigate(
        &mut self,
        url: &str,
        new_tab: bool,
        tab_index: Option<usize>,
    ) -> BrowserResponse {
        // Honour the caller's target choice before navigating. Without this,
        // `navigate --new-tab` would steer whatever tab the session happened
        // to hold — visibly wrong in a headed browser.
        if new_tab {
            match self
                .cdp
                .send(
                    "Target.createTarget",
                    serde_json::json!({"url": "about:blank"}),
                )
                .await
            {
                Ok(v) => {
                    let target_id = v["targetId"].as_str().unwrap_or_default().to_string();
                    if target_id.is_empty() {
                        return BrowserResponse::err(
                            "Target.createTarget returned no targetId".to_string(),
                        );
                    }
                    if let Err(e) = self.attach_target(&target_id).await {
                        return BrowserResponse::err(e);
                    }
                }
                Err(e) => {
                    return BrowserResponse::err(format!("New tab failed: {e}"));
                }
            }
        } else if let Some(index) = tab_index {
            let switched = self.cmd_switch_tab_impl(Some(index), None).await;
            if !switched.success {
                return switched;
            }
        }

        let result = self
            .cdp
            .send("Page.navigate", serde_json::json!({ "url": url }))
            .await;

        if let Err(e) = result {
            return BrowserResponse::err(format!("Navigate failed: {e}"));
        }

        // Wait for page load
        self.wait_for_load().await;

        match self.page_info().await {
            Ok(info) => BrowserResponse::ok(info),
            Err(e) => BrowserResponse::err(format!("Navigate succeeded but page info failed: {e}")),
        }
    }

    async fn cmd_click(&self, selector: &str) -> BrowserResponse {
        let sel_json = serde_json::to_string(selector).unwrap_or_default();
        let js = format!(
            r#"(() => {{
    let sel = {sel_json};
    let el = document.querySelector(sel);
    if (!el) {{
        const all = document.querySelectorAll('a, button, [role="button"], input[type="submit"], [onclick]');
        const lower = sel.toLowerCase();
        for (const e of all) {{
            if (e.textContent.trim().toLowerCase().includes(lower)) {{ el = e; break; }}
        }}
    }}
    if (!el) return JSON.stringify({{success: false, error: 'Element not found: ' + sel}});
    el.scrollIntoView({{block: 'center'}});
    el.click();
    return JSON.stringify({{success: true, tag: el.tagName, text: el.textContent.substring(0, 100).trim()}});
}})()"#
        );

        match self.cdp.run_js(&js).await {
            Ok(val) => {
                let parsed: serde_json::Value = val
                    .as_str()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(val);
                if parsed["success"].as_bool() == Some(false) {
                    return BrowserResponse::err(
                        parsed["error"]
                            .as_str()
                            .unwrap_or("Click failed")
                            .to_string(),
                    );
                }
                // Wait briefly for any navigation triggered by click
                tokio::time::sleep(Duration::from_millis(500)).await;
                self.wait_for_load().await;
                match self.page_info().await {
                    Ok(info) => BrowserResponse::ok(info),
                    Err(_) => BrowserResponse::ok(parsed),
                }
            }
            Err(e) => BrowserResponse::err(format!("Click failed: {e}")),
        }
    }

    async fn cmd_type(&self, selector: &str, text: &str) -> BrowserResponse {
        let sel_json = serde_json::to_string(selector).unwrap_or_default();
        let text_json = serde_json::to_string(text).unwrap_or_default();
        let js = format!(
            r#"(() => {{
    let sel = {sel_json};
    let txt = {text_json};
    let el = document.querySelector(sel);
    if (!el) return JSON.stringify({{success: false, error: 'Input not found: ' + sel}});
    el.scrollIntoView({{block: 'center'}});
    el.focus();
    const editable = el.isContentEditable;
    if (!editable) {{
        // React and Vue track value through the prototype setter; assigning
        // el.value directly updates the DOM while leaving framework state
        // stale, so the form submits the OLD value.
        const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement : HTMLInputElement;
        const setter = Object.getOwnPropertyDescriptor(proto.prototype, 'value');
        if (setter && setter.set) {{ setter.set.call(el, txt); }} else {{ el.value = txt; }}
        el.dispatchEvent(new Event('input', {{bubbles: true}}));
        el.dispatchEvent(new Event('change', {{bubbles: true}}));
    }}
    return JSON.stringify({{success: true, selector: sel, contentEditable: editable,
                            typed: txt.length + ' chars'}});
}})()"#
        );

        // Rich-text editors (Draft.js on x.com, Lexical, ProseMirror) keep their
        // own document model. Neither a value assignment nor execCommand updates
        // it reliably — the text renders on screen while the editor still
        // believes it is empty, so a post goes out with media and no words. Only
        // trusted input via CDP drives the real pipeline.
        let is_editable = match self.cdp.run_js(&js).await {
            Ok(val) => {
                let parsed: serde_json::Value = val
                    .as_str()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(val);
                if parsed["success"].as_bool() == Some(false) {
                    return BrowserResponse::err(parsed["error"].as_str().unwrap_or("Type failed"));
                }
                parsed["contentEditable"].as_bool().unwrap_or(false)
            }
            Err(e) => return BrowserResponse::err(format!("Type failed: {e}")),
        };

        if is_editable {
            // Clear any existing content first: these editors persist drafts,
            // and insertText appends.
            let _ = self
                .cdp
                .send(
                    "Input.dispatchKeyEvent",
                    serde_json::json!({"type": "keyDown", "key": "a", "code": "KeyA",
                                       "windowsVirtualKeyCode": 65, "modifiers": 2}),
                )
                .await;
            let _ = self
                .cdp
                .send(
                    "Input.dispatchKeyEvent",
                    serde_json::json!({"type": "keyUp", "key": "a", "code": "KeyA",
                                       "windowsVirtualKeyCode": 65, "modifiers": 2}),
                )
                .await;
            if let Err(e) = self
                .cdp
                .send("Input.insertText", serde_json::json!({"text": text}))
                .await
            {
                return BrowserResponse::err(format!("Trusted text insert failed: {e}"));
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
            return BrowserResponse::ok(serde_json::json!({
                "success": true, "selector": selector, "contentEditable": true,
                "typed": format!("{} chars (trusted input)", text.len())
            }));
        }

        match self.cdp.run_js(&js).await {
            Ok(val) => {
                let parsed: serde_json::Value = val
                    .as_str()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(val);
                if parsed["success"].as_bool() == Some(false) {
                    BrowserResponse::err(parsed["error"].as_str().unwrap_or("Type failed"))
                } else {
                    BrowserResponse::ok(parsed)
                }
            }
            Err(e) => BrowserResponse::err(format!("Type failed: {e}")),
        }
    }

    async fn cmd_screenshot(&self, format: Option<&str>, quality: Option<u8>) -> BrowserResponse {
        let format = match format.unwrap_or("png") {
            // CDP only accepts these three; anything else would be silently
            // reinterpreted, so reject it at the boundary instead.
            f @ ("png" | "jpeg" | "webp") => f,
            other => {
                return BrowserResponse::err(format!(
                    "Unsupported screenshot format '{other}' (png|jpeg|webp)"
                ));
            }
        };
        let mut params = serde_json::json!({ "format": format });
        // `quality` is only valid for lossy formats — Chrome rejects it on png.
        if format != "png" {
            if let Some(q) = quality {
                params["quality"] = serde_json::json!(q.min(100));
            }
        }
        match self.cdp.send("Page.captureScreenshot", params).await {
            Ok(result) => {
                let b64 = result["data"].as_str().unwrap_or("");
                let url = self
                    .cdp
                    .run_js("location.href")
                    .await
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_default();
                BrowserResponse::ok(
                    serde_json::json!({"image_base64": b64, "url": url, "format": format}),
                )
            }
            Err(e) => BrowserResponse::err(format!("Screenshot failed: {e}")),
        }
    }

    async fn cmd_read_page(&self) -> BrowserResponse {
        match self.cdp.run_js(EXTRACT_CONTENT_JS).await {
            Ok(val) => {
                let parsed: serde_json::Value = val
                    .as_str()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(val);
                BrowserResponse::ok(parsed)
            }
            Err(e) => BrowserResponse::err(format!("ReadPage failed: {e}")),
        }
    }

    async fn cmd_scroll(
        &self,
        direction: &str,
        amount: i32,
        selector: Option<&str>,
    ) -> BrowserResponse {
        let (dx, dy) = match direction {
            "up" => (0, -amount),
            "down" => (0, amount),
            "left" => (-amount, 0),
            "right" => (amount, 0),
            _ => (0, amount),
        };
        let js = if let Some(sel) = selector {
            let sel_json = serde_json::to_string(sel).unwrap_or_default();
            // Scroll the element itself — the probe's --selector must not
            // silently become a window scroll while reporting success.
            format!(
                r#"(() => {{
    const el = document.querySelector({sel_json});
    if (!el) return JSON.stringify({{success: false, error: 'Element not found: ' + {sel_json}}});
    el.scrollBy({dx}, {dy});
    return JSON.stringify({{success: true, scrollX: el.scrollLeft, scrollY: el.scrollTop}});
}})()"#
            )
        } else {
            format!("window.scrollBy({dx}, {dy}); JSON.stringify({{scrollX: window.scrollX, scrollY: window.scrollY}})")
        };
        match self.cdp.run_js(&js).await {
            Ok(val) => {
                let parsed: serde_json::Value = val
                    .as_str()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(val);
                if parsed["success"].as_bool() == Some(false) {
                    return BrowserResponse::err(
                        parsed["error"]
                            .as_str()
                            .unwrap_or("Scroll failed")
                            .to_string(),
                    );
                }
                BrowserResponse::ok(parsed)
            }
            Err(e) => BrowserResponse::err(format!("Scroll failed: {e}")),
        }
    }

    /// Wait for a page condition: a selector, `load`, or a URL substring.
    ///
    /// The extension's `browser_wait` accepts `condition` + `value`; the ops
    /// probe forwards those verbatim, so a selector-only implementation made
    /// every `wait` call fail before this.
    async fn cmd_wait(&self, condition: &str, target: &str, timeout_ms: u64) -> BrowserResponse {
        let max_ms = timeout_ms.min(30_000);
        let polls = (max_ms / PAGE_LOAD_POLL_INTERVAL_MS).max(1);
        let tgt_json = serde_json::to_string(target).unwrap_or_default();
        let probe = match condition {
            "load" => "document.readyState === 'complete'".to_string(),
            "url" => format!("location.href.includes({tgt_json})"),
            _ => format!("document.querySelector({tgt_json}) !== null"),
        };

        for _ in 0..polls {
            let js = format!("({probe}) ? 'found' : null");
            if let Ok(val) = self.cdp.run_js(&js).await {
                if val.as_str() == Some("found") {
                    return BrowserResponse::ok(serde_json::json!({
                        "found": true,
                        "condition": condition,
                        "target": target,
                    }));
                }
            }
            tokio::time::sleep(Duration::from_millis(PAGE_LOAD_POLL_INTERVAL_MS)).await;
        }

        BrowserResponse::err(format!(
            "Timed out waiting for {condition}: {target} ({max_ms}ms)"
        ))
    }

    async fn cmd_run_js(&self, expression: &str) -> BrowserResponse {
        match self.cdp.run_js(expression).await {
            Ok(val) => BrowserResponse::ok(serde_json::json!({"result": val})),
            Err(e) => BrowserResponse::err(format!("JS execution failed: {e}")),
        }
    }

    async fn cmd_back(&self) -> BrowserResponse {
        match self.cdp.run_js("history.back(); 'ok'").await {
            Ok(_) => {
                tokio::time::sleep(Duration::from_millis(500)).await;
                self.wait_for_load().await;
                match self.page_info().await {
                    Ok(info) => BrowserResponse::ok(info),
                    Err(e) => {
                        BrowserResponse::err(format!("Back succeeded but page info failed: {e}"))
                    }
                }
            }
            Err(e) => BrowserResponse::err(format!("Back failed: {e}")),
        }
    }

    /// Go forward (delta 1) or back through session history.
    async fn cmd_history(&self, delta: i32) -> BrowserResponse {
        match self.cdp.run_js(&format!("history.go({delta}); 'ok'")).await {
            Ok(_) => {
                tokio::time::sleep(Duration::from_millis(500)).await;
                self.wait_for_load().await;
                match self.page_info().await {
                    Ok(info) => BrowserResponse::ok(info),
                    Err(e) => BrowserResponse::err(format!("History move failed: {e}")),
                }
            }
            Err(e) => BrowserResponse::err(format!("History move failed: {e}")),
        }
    }

    /// Reload through the CDP Page domain rather than `location.reload()`.
    ///
    /// `location.reload()` from an evaluated script can be blocked by the page
    /// and does not reliably clear the cache; `Page.reload` is driven by the
    /// browser itself and cannot be intercepted by page script.
    async fn cmd_reload(&self) -> BrowserResponse {
        if let Err(e) = self
            .cdp
            .send("Page.reload", serde_json::json!({"ignoreCache": false}))
            .await
        {
            return BrowserResponse::err(format!("Reload failed: {e}"));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        self.wait_for_load().await;
        match self.page_info().await {
            Ok(info) => BrowserResponse::ok(info),
            Err(e) => BrowserResponse::err(format!("Reload succeeded but page info failed: {e}")),
        }
    }

    /// Hover an element by dispatching a real mouse move to its centre.
    ///
    /// Uses trusted CDP input rather than a synthetic `mouseover` event,
    /// because menus and tooltips that gate on `:hover` CSS or on
    /// `event.isTrusted` do not respond to a dispatched event.
    async fn cmd_hover(&self, selector: &str) -> BrowserResponse {
        let sel_json = serde_json::to_string(selector).unwrap_or_default();
        let js = format!(
            r#"(() => {{
    const el = document.querySelector({sel_json});
    if (!el) return JSON.stringify({{success: false, error: 'Element not found: ' + {sel_json}}});
    el.scrollIntoView({{block: 'center'}});
    const r = el.getBoundingClientRect();
    return JSON.stringify({{success: true, x: r.left + r.width / 2, y: r.top + r.height / 2,
                            tag: el.tagName}});
}})()"#
        );
        let parsed = match self.cdp.run_js(&js).await {
            Ok(v) => v
                .as_str()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
                .unwrap_or(v),
            Err(e) => return BrowserResponse::err(format!("Hover failed: {e}")),
        };
        if parsed["success"].as_bool() == Some(false) {
            return BrowserResponse::err(
                parsed["error"]
                    .as_str()
                    .unwrap_or("Hover failed")
                    .to_string(),
            );
        }
        let (x, y) = (
            parsed["x"].as_f64().unwrap_or(0.0),
            parsed["y"].as_f64().unwrap_or(0.0),
        );
        if let Err(e) = self
            .cdp
            .send(
                "Input.dispatchMouseEvent",
                serde_json::json!({"type": "mouseMoved", "x": x, "y": y, "buttons": 0}),
            )
            .await
        {
            return BrowserResponse::err(format!("Hover dispatch failed: {e}"));
        }
        // Hover effects are usually CSS transitions; give them a beat to apply
        // before the caller reads the page.
        tokio::time::sleep(Duration::from_millis(250)).await;
        BrowserResponse::ok(serde_json::json!({
            "hovered": true, "selector": selector, "tag": parsed["tag"], "x": x, "y": y
        }))
    }

    /// Press a key, optionally focusing `selector` first.
    ///
    /// Sent as trusted CDP key events so that framework handlers, form
    /// submission on Enter, and `keydown` listeners all fire — a dispatched
    /// `KeyboardEvent` has `isTrusted=false` and will not submit a form.
    async fn cmd_press(&self, selector: Option<&str>, key: &str) -> BrowserResponse {
        if let Some(sel) = selector {
            let sel_json = serde_json::to_string(sel).unwrap_or_default();
            let js = format!(
                r#"(() => {{
    const el = document.querySelector({sel_json});
    if (!el) return JSON.stringify({{success: false, error: 'Element not found: ' + {sel_json}}});
    el.scrollIntoView({{block: 'center'}});
    el.focus();
    return JSON.stringify({{success: true}});
}})()"#
            );
            match self.cdp.run_js(&js).await {
                Ok(v) => {
                    let parsed: serde_json::Value = v
                        .as_str()
                        .and_then(|s| serde_json::from_str(s).ok())
                        .unwrap_or(v);
                    if parsed["success"].as_bool() == Some(false) {
                        return BrowserResponse::err(
                            parsed["error"]
                                .as_str()
                                .unwrap_or("Focus failed")
                                .to_string(),
                        );
                    }
                }
                Err(e) => return BrowserResponse::err(format!("Focus failed: {e}")),
            }
        }

        let Some((code, vk, text)) = key_descriptor(key) else {
            return BrowserResponse::err(format!(
                "Unsupported key '{key}'. Supported: Enter, Tab, Escape, Backspace, Delete, \
                 ArrowUp/Down/Left/Right, Home, End, PageUp, PageDown, Space, or a single character."
            ));
        };

        let mut down = serde_json::json!({
            "type": if text.is_some() { "keyDown" } else { "rawKeyDown" },
            "key": key, "code": code, "windowsVirtualKeyCode": vk, "nativeVirtualKeyCode": vk,
        });
        if let Some(txt) = text {
            down["text"] = serde_json::json!(txt);
            down["unmodifiedText"] = serde_json::json!(txt);
        }
        if let Err(e) = self.cdp.send("Input.dispatchKeyEvent", down).await {
            return BrowserResponse::err(format!("Key down failed: {e}"));
        }
        let up = serde_json::json!({
            "type": "keyUp", "key": key, "code": code,
            "windowsVirtualKeyCode": vk, "nativeVirtualKeyCode": vk,
        });
        if let Err(e) = self.cdp.send("Input.dispatchKeyEvent", up).await {
            return BrowserResponse::err(format!("Key up failed: {e}"));
        }

        // Enter frequently submits, which navigates. Settle before reporting so
        // the caller does not read the old page.
        tokio::time::sleep(Duration::from_millis(300)).await;
        self.wait_for_load().await;
        let info = self.page_info().await.unwrap_or(serde_json::json!({}));
        BrowserResponse::ok(serde_json::json!({"pressed": key, "page": info}))
    }

    /// Choose an option in a `<select>` by value, then by visible label.
    ///
    /// Setting `.value` alone does not notify frameworks — React and Vue listen
    /// for `change`/`input`, so a silent assignment leaves their state stale and
    /// the form submits the old value.
    async fn cmd_select(
        &self,
        selector: &str,
        value: Option<&str>,
        index: Option<usize>,
    ) -> BrowserResponse {
        let sel_json = serde_json::to_string(selector).unwrap_or_default();
        let val_json = serde_json::to_string(value.unwrap_or_default()).unwrap_or_default();
        let idx_json = index
            .map(|i| i.to_string())
            .unwrap_or_else(|| "null".to_string());
        let js = format!(
            r#"(() => {{
    const el = document.querySelector({sel_json});
    if (!el) return JSON.stringify({{success: false, error: 'Element not found: ' + {sel_json}}});
    if (el.tagName !== 'SELECT') return JSON.stringify({{success: false, error: 'Not a <select>: ' + el.tagName}});
    const want = {val_json};
    const wantIdx = {idx_json};
    let idx;
    if (wantIdx !== null) {{
        if (wantIdx < 0 || wantIdx >= el.options.length) return JSON.stringify({{success: false,
            error: 'Option index ' + wantIdx + ' out of range (' + el.options.length + ' options)'}});
        idx = wantIdx;
    }} else {{
        idx = [...el.options].findIndex(o => o.value === want);
        if (idx < 0) idx = [...el.options].findIndex(o => o.text.trim() === want);
        if (idx < 0) idx = [...el.options].findIndex(o => o.text.trim().toLowerCase().includes(want.toLowerCase()));
        if (idx < 0) return JSON.stringify({{success: false,
            error: 'No option matching ' + want + '. Available: ' + [...el.options].map(o => o.text.trim()).join(' | ')}});
    }}
    el.scrollIntoView({{block: 'center'}});
    el.selectedIndex = idx;
    el.dispatchEvent(new Event('input', {{bubbles: true}}));
    el.dispatchEvent(new Event('change', {{bubbles: true}}));
    return JSON.stringify({{success: true, selected: el.options[idx].text.trim(), value: el.value}});
}})()"#
        );
        match self.cdp.run_js(&js).await {
            Ok(v) => {
                let parsed: serde_json::Value = v
                    .as_str()
                    .and_then(|s| serde_json::from_str(s).ok())
                    .unwrap_or(v);
                if parsed["success"].as_bool() == Some(false) {
                    return BrowserResponse::err(
                        parsed["error"]
                            .as_str()
                            .unwrap_or("Select failed")
                            .to_string(),
                    );
                }
                BrowserResponse::ok(parsed)
            }
            Err(e) => BrowserResponse::err(format!("Select failed: {e}")),
        }
    }

    /// List page targets known to this browser instance.
    async fn cmd_list_tabs(&self) -> BrowserResponse {
        match self
            .cdp
            .send("Target.getTargets", serde_json::json!({}))
            .await
        {
            Ok(v) => {
                let tabs: Vec<serde_json::Value> = v["targetInfos"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter(|t| t["type"].as_str() == Some("page"))
                            .enumerate()
                            .map(|(i, t)| {
                                serde_json::json!({
                                    "index": i,
                                    "title": t["title"],
                                    "url": t["url"],
                                    "target_id": t["targetId"],
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                BrowserResponse::ok(serde_json::json!({"count": tabs.len(), "tabs": tabs}))
            }
            Err(e) => BrowserResponse::err(format!("List tabs failed: {e}")),
        }
    }

    /// Bring a tab to the front by index.
    ///
    /// This session's CDP socket is bound to one page target, so switching
    /// activates the tab but does not re-point subsequent commands at it. That
    /// is stated rather than hidden: silently activating a tab the caller then
    /// cannot drive would be worse than a clear partial result.
    /// Re-point this session at another tab, by index or URL substring.
    ///
    /// The previous version only called `Target.activateTarget`, which raises
    /// the tab visually while every subsequent command still went to the
    /// original page. That is worse than not switching: it looks like it worked.
    ///
    /// Attach mode makes this essential. `find_page_ws` binds to whichever page
    /// target happens to be first, which in a real browser is an arbitrary tab —
    /// so driving a signed-in site meant navigating someone's unrelated tab and
    /// landing on a login wall, while their authenticated tab sat untouched two
    /// slots away.
    async fn cmd_switch_tab_impl(
        &mut self,
        index: Option<usize>,
        url_match: Option<&str>,
    ) -> BrowserResponse {
        let targets = match self
            .cdp
            .send("Target.getTargets", serde_json::json!({}))
            .await
        {
            Ok(v) => v,
            Err(e) => return BrowserResponse::err(format!("Switch tab failed: {e}")),
        };
        let pages: Vec<&serde_json::Value> = targets["targetInfos"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|t| t["type"].as_str() == Some("page"))
                    .collect()
            })
            .unwrap_or_default();

        let chosen = if let Some(pat) = url_match {
            let pat_l = pat.to_lowercase();
            pages.iter().find(|t| {
                t["url"]
                    .as_str()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&pat_l)
            })
        } else {
            pages.get(index.unwrap_or(0))
        };
        let Some(target) = chosen else {
            return BrowserResponse::err(format!(
                "No page target matching {:?} ({} open)",
                url_match
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("index {index:?}")),
                pages.len()
            ));
        };

        let target_id = target["targetId"].as_str().unwrap_or_default().to_string();
        let url = target["url"].as_str().unwrap_or("").to_string();
        let title = target["title"].as_str().unwrap_or("").to_string();

        // Rebind: fetch this target's own debugger socket and replace the
        // connection, so every later command lands on the tab we selected.
        match self.attach_target(&target_id).await {
            Ok(()) => {
                let _ = self
                    .cdp
                    .send(
                        "Target.activateTarget",
                        serde_json::json!({"targetId": target_id}),
                    )
                    .await;
                BrowserResponse::ok(serde_json::json!({
                    "switched": true, "url": url, "title": title, "target_id": target_id
                }))
            }
            Err(e) => BrowserResponse::err(e),
        }
    }

    /// Close one page target by index, then keep the session usable.
    ///
    /// Two failure modes shaped this: closing a tab the session is attached
    /// to leaves a dead socket every later command fails on, and treating
    /// `browser_close_tab` as `browser_close` (the previous mapping) killed
    /// the whole session when the caller asked for one tab.
    async fn cmd_close_tab(&mut self, index: usize) -> BrowserResponse {
        let targets = match self
            .cdp
            .send("Target.getTargets", serde_json::json!({}))
            .await
        {
            Ok(v) => v,
            Err(e) => return BrowserResponse::err(format!("Close tab failed: {e}")),
        };
        let pages: Vec<serde_json::Value> = targets["targetInfos"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|t| t["type"].as_str() == Some("page"))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let Some(target) = pages.get(index) else {
            return BrowserResponse::err(format!(
                "Tab index {index} out of range ({} page target(s))",
                pages.len()
            ));
        };
        let target_id = target["targetId"].as_str().unwrap_or_default().to_string();
        let url = target["url"].as_str().unwrap_or("").to_string();
        let title = target["title"].as_str().unwrap_or("").to_string();

        match self
            .cdp
            .send(
                "Target.closeTarget",
                serde_json::json!({"targetId": target_id}),
            )
            .await
        {
            Ok(v) if v["success"].as_bool() == Some(true) => {}
            Ok(v) => {
                return BrowserResponse::err(format!(
                    "Target.closeTarget refused: {}",
                    serde_json::to_string(&v).unwrap_or_default()
                ));
            }
            Err(e) => return BrowserResponse::err(format!("Close tab failed: {e}")),
        }

        let was_current = self.attached_target.as_deref() == Some(target_id.as_str());
        let remaining = pages.len().saturating_sub(1);
        let mut out = serde_json::json!({
            "closed": true,
            "index": index,
            "url": url,
            "title": title,
            "remaining_tabs": remaining,
        });
        if was_current {
            // Rebind to the first remaining page so the session is not left
            // pointing at a dead socket. `pages` was taken before the close,
            // so every other entry is still a candidate.
            let next = pages
                .iter()
                .find(|t| t["targetId"].as_str() != Some(target_id.as_str()))
                .and_then(|t| t["targetId"].as_str())
                .map(str::to_string);
            match next {
                Some(next_id) => match self.attach_target(&next_id).await {
                    Ok(()) => {
                        out["rebound_to_target"] = serde_json::json!(next_id);
                    }
                    Err(e) => {
                        out["session_empty"] = serde_json::json!(true);
                        out["note"] = serde_json::json!(format!(
                            "Closed the attached tab and could not rebind: {e}"
                        ));
                    }
                },
                None => {
                    out["session_empty"] = serde_json::json!(true);
                    out["note"] =
                        serde_json::json!("Closed the last page target; the session has no page");
                }
            }
        }
        BrowserResponse::ok(out)
    }

    #[allow(dead_code)]
    async fn cmd_switch_tab_legacy(&self, index: usize) -> BrowserResponse {
        let targets = match self
            .cdp
            .send("Target.getTargets", serde_json::json!({}))
            .await
        {
            Ok(v) => v,
            Err(e) => return BrowserResponse::err(format!("Switch tab failed: {e}")),
        };
        let pages: Vec<&serde_json::Value> = targets["targetInfos"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|t| t["type"].as_str() == Some("page"))
                    .collect()
            })
            .unwrap_or_default();
        let Some(target) = pages.get(index) else {
            return BrowserResponse::err(format!(
                "Tab index {index} out of range ({} page target(s))",
                pages.len()
            ));
        };
        let target_id = target["targetId"].as_str().unwrap_or_default().to_string();
        if let Err(e) = self
            .cdp
            .send(
                "Target.activateTarget",
                serde_json::json!({"targetId": target_id}),
            )
            .await
        {
            return BrowserResponse::err(format!("Switch tab failed: {e}"));
        }
        BrowserResponse::ok(serde_json::json!({
            "activated": true,
            "index": index,
            "url": target["url"],
            "note": "tab activated; this session's commands still target the original page",
        }))
    }

    /// Attach files to a file input via CDP.
    ///
    /// `DOM.setFileInputFiles` is the only approach that works headlessly and
    /// without driving a native file dialog — a dialog is an OS window, not a
    /// DOM element, so no amount of clicking reaches it.
    ///
    /// Paths are verified to exist first. Chrome accepts a nonexistent path
    /// silently and simply attaches nothing, which surfaces later as an
    /// unexplained empty upload rather than an error at the point of mistake.
    async fn cmd_upload(&self, selector: &str, files: &[String], nth: usize) -> BrowserResponse {
        for f in files {
            if !std::path::Path::new(f).is_file() {
                return BrowserResponse::err(format!("File not found: {f}"));
            }
        }

        let doc = match self
            .cdp
            .send("DOM.getDocument", serde_json::json!({"depth": 0}))
            .await
        {
            Ok(v) => v,
            Err(e) => return BrowserResponse::err(format!("Upload failed (getDocument): {e}")),
        };
        let Some(root_id) = doc["root"]["nodeId"].as_i64() else {
            return BrowserResponse::err("Upload failed: no document root".to_string());
        };

        let found = match self
            .cdp
            .send(
                "DOM.querySelectorAll",
                serde_json::json!({"nodeId": root_id, "selector": selector}),
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                return BrowserResponse::err(format!("Upload failed (querySelectorAll): {e}"))
            }
        };
        let node_ids: Vec<i64> = found["nodeIds"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_i64()).collect())
            .unwrap_or_default();
        let Some(&node_id) = node_ids.get(nth) else {
            return BrowserResponse::err(format!(
                "No file input at index {nth} for selector '{selector}' ({} match(es))",
                node_ids.len()
            ));
        };

        if let Err(e) = self
            .cdp
            .send(
                "DOM.setFileInputFiles",
                serde_json::json!({"files": files, "nodeId": node_id}),
            )
            .await
        {
            return BrowserResponse::err(format!("Upload failed (setFileInputFiles): {e}"));
        }
        // The page reacts to the `change` event, not to the property write.
        tokio::time::sleep(Duration::from_millis(600)).await;
        BrowserResponse::ok(serde_json::json!({
            "uploaded": true, "selector": selector, "nth": nth, "files": files
        }))
    }

    // ── Helpers ────────────────────────────────────────────────────────

    /// Poll until document.readyState is 'complete' or 'interactive'.
    async fn wait_for_load(&self) {
        for _ in 0..PAGE_LOAD_MAX_POLLS {
            if let Ok(val) = self.cdp.run_js("document.readyState").await {
                let state = val.as_str().unwrap_or("");
                if state == "complete" || state == "interactive" {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(PAGE_LOAD_POLL_INTERVAL_MS)).await;
        }
    }

    /// Get current page title, URL, and readable content.
    async fn page_info(&self) -> Result<serde_json::Value, String> {
        let info = self
            .cdp
            .run_js("JSON.stringify({title: document.title, url: location.href})")
            .await?;
        let parsed: serde_json::Value = info
            .as_str()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(info);

        let content_val = self
            .cdp
            .run_js(EXTRACT_CONTENT_JS)
            .await
            .unwrap_or_default();
        let content_obj: serde_json::Value = content_val
            .as_str()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(content_val);
        let content_text = content_obj["content"].as_str().unwrap_or("");

        Ok(serde_json::json!({
            "title": parsed["title"],
            "url": parsed["url"],
            "content": content_text,
        }))
    }
}

impl Drop for BrowserSession {
    fn drop(&mut self) {
        // Only tear down what this session created. An attached session
        // borrows the operator's browser; killing it would close all their tabs.
        if let Some(child) = self.process.as_mut() {
            let _ = child.start_kill();
        }
        if let Some(dir) = self.profile_dir.as_ref() {
            // Best-effort: the process may still hold file handles for a moment,
            // and a failure here must not panic a drop. The temp dir is
            // namespaced by pid+nanos, so a leftover cannot collide.
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Map a key name to the `(code, windowsVirtualKeyCode, text)` CDP needs.
///
/// Chrome ignores a key event whose virtual key code it does not recognise, so
/// sending only `key` silently does nothing — the most confusing possible
/// failure, because the call succeeds and the page does not move. `text` is
/// `Some` only for keys that insert a character; navigation keys must not carry
/// text or they get typed literally.
fn key_descriptor(key: &str) -> Option<(&'static str, u32, Option<String>)> {
    Some(match key {
        "Enter" | "Return" => ("Enter", 13, Some("\r".to_string())),
        "Tab" => ("Tab", 9, Some("\t".to_string())),
        "Escape" | "Esc" => ("Escape", 27, None),
        "Backspace" => ("Backspace", 8, None),
        "Delete" | "Del" => ("Delete", 46, None),
        "ArrowUp" | "Up" => ("ArrowUp", 38, None),
        "ArrowDown" | "Down" => ("ArrowDown", 40, None),
        "ArrowLeft" | "Left" => ("ArrowLeft", 37, None),
        "ArrowRight" | "Right" => ("ArrowRight", 39, None),
        "Home" => ("Home", 36, None),
        "End" => ("End", 35, None),
        "PageUp" => ("PageUp", 33, None),
        "PageDown" => ("PageDown", 34, None),
        "Space" | " " => ("Space", 32, Some(" ".to_string())),
        other => {
            // Single printable character: send it as text. The virtual key code
            // for an uppercased ASCII letter/digit is its codepoint.
            let mut chars = other.chars();
            let c = chars.next()?;
            if chars.next().is_some() {
                return None;
            }
            let vk = c.to_ascii_uppercase() as u32;
            return Some(("", vk, Some(c.to_string())));
        }
    })
}

// ── Chromium discovery ─────────────────────────────────────────────────────

/// Find a Chromium-based browser binary on this system.
fn find_chromium(config: &BrowserConfig) -> Result<PathBuf, String> {
    // 1. User-configured path
    if let Some(ref path) = config.chromium_path {
        if !path.is_empty() {
            let p = PathBuf::from(path);
            if p.exists() {
                return Ok(p);
            }
            return Err(format!("Configured chromium_path not found: {path}"));
        }
    }

    // 2. CHROME_PATH env var
    if let Ok(path) = std::env::var("CHROME_PATH") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Ok(p);
        }
    }

    // 3. Platform-specific search
    let candidates = chromium_candidates();
    for candidate in &candidates {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Ok(p);
        }
    }

    // 4. Try PATH lookup
    for name in &[
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "chrome",
    ] {
        if let Ok(output) = std::process::Command::new("which").arg(name).output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Ok(PathBuf::from(path));
                }
            }
        }
        // Windows: use where.exe
        #[cfg(windows)]
        if let Ok(output) = std::process::Command::new("where.exe").arg(name).output() {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !path.is_empty() {
                    return Ok(PathBuf::from(path));
                }
            }
        }
    }

    Err(
        "Chromium/Chrome not found. Install Chrome or set CHROME_PATH. \
         Checked: Chrome, Chromium, Edge, Brave in standard locations."
            .to_string(),
    )
}

/// Platform-specific candidate paths for Chromium-based browsers.
fn chromium_candidates() -> Vec<String> {
    let mut paths = Vec::new();

    #[cfg(windows)]
    {
        let program_files = std::env::var("ProgramFiles").unwrap_or_default();
        let program_files_x86 = std::env::var("ProgramFiles(x86)").unwrap_or_default();
        let local_app = std::env::var("LOCALAPPDATA").unwrap_or_default();

        for pf in &[&program_files, &program_files_x86] {
            if pf.is_empty() {
                continue;
            }
            paths.push(format!("{pf}\\Google\\Chrome\\Application\\chrome.exe"));
            paths.push(format!("{pf}\\Microsoft\\Edge\\Application\\msedge.exe"));
            paths.push(format!(
                "{pf}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
            ));
        }
        if !local_app.is_empty() {
            paths.push(format!(
                "{local_app}\\Google\\Chrome\\Application\\chrome.exe"
            ));
            paths.push(format!(
                "{local_app}\\Microsoft\\Edge\\Application\\msedge.exe"
            ));
        }
    }

    #[cfg(target_os = "macos")]
    {
        paths.push("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into());
        paths.push("/Applications/Chromium.app/Contents/MacOS/Chromium".into());
        paths.push("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge".into());
        paths.push("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser".into());
    }

    #[cfg(target_os = "linux")]
    {
        paths.push("/usr/bin/google-chrome".into());
        paths.push("/usr/bin/google-chrome-stable".into());
        paths.push("/usr/bin/chromium".into());
        paths.push("/usr/bin/chromium-browser".into());
        paths.push("/snap/bin/chromium".into());
        paths.push("/usr/bin/microsoft-edge".into());
        paths.push("/usr/bin/brave-browser".into());
    }

    paths
}

// ── Browser manager ────────────────────────────────────────────────────────

/// Manages browser sessions for all agents.
pub struct BrowserManager {
    sessions: DashMap<String, Arc<Mutex<BrowserSession>>>,
    config: BrowserConfig,
}

impl BrowserManager {
    /// Create a new BrowserManager with the given configuration.
    pub fn new(config: BrowserConfig) -> Self {
        Self {
            sessions: DashMap::new(),
            config,
        }
    }

    /// The browser configuration this manager was built with.
    pub fn config(&self) -> &BrowserConfig {
        &self.config
    }

    /// Check whether an agent has an active browser session.
    pub fn has_session(&self, agent_id: &str) -> bool {
        self.sessions.contains_key(agent_id)
    }

    /// Send a command to an agent's browser session (creating one if needed).
    pub async fn send_command(
        &self,
        agent_id: &str,
        cmd: BrowserCommand,
    ) -> Result<BrowserResponse, String> {
        let session = self.get_or_create(agent_id).await?;
        let mut guard = session.lock().await;
        let resp = guard.execute(cmd).await;

        if !resp.success {
            if let Some(ref err) = resp.error {
                warn!(agent_id, error = %err, "Browser command failed");
            }
        }

        Ok(resp)
    }

    /// Close an agent's browser session.
    pub async fn close_session(&self, agent_id: &str) {
        if let Some((_, session)) = self.sessions.remove(agent_id) {
            drop(session);
            info!(agent_id, "Browser session closed");
        }
    }

    /// Clean up an agent's browser session (called after agent loop ends).
    pub async fn cleanup_agent(&self, agent_id: &str) {
        self.close_session(agent_id).await;
    }

    /// Get existing session or create a new one.
    async fn get_or_create(&self, agent_id: &str) -> Result<Arc<Mutex<BrowserSession>>, String> {
        if let Some(entry) = self.sessions.get(agent_id) {
            return Ok(Arc::clone(entry.value()));
        }

        if self.sessions.len() >= self.config.max_sessions {
            return Err(format!(
                "Maximum browser sessions reached ({}). Close an existing session first.",
                self.config.max_sessions
            ));
        }

        let session = BrowserSession::launch(&self.config).await?;
        let arc = Arc::new(Mutex::new(session));
        self.sessions.insert(agent_id.to_string(), Arc::clone(&arc));
        info!(agent_id, "Browser session created (native CDP)");
        Ok(arc)
    }
}

// ── Tool handler functions ─────────────────────────────────────────────────

// ── Tool argument aliases ──────────────────────────────────────────────────
//
// Two callers reach these functions with two different vocabularies: the
// daemon's own tool schemas (`expression`, `text`, `index`, `timeout_ms`) and
// the extension/MCP schema (`code`, `value`, `tabId`, `timeoutMs`), which the
// HTTP route and `browser_hand_probe.py` forward verbatim. Every reader below
// accepts both — a name that only one side honours is a silent break on the
// other path.

/// First non-empty string among the accepted keys.
fn arg_str<'a>(input: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|k| input[*k].as_str().filter(|s| !s.is_empty()))
}

/// First unsigned integer among the accepted keys.
fn arg_u64(input: &serde_json::Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|k| input[*k].as_u64())
}

/// True when any accepted key is explicitly true.
fn arg_bool(input: &serde_json::Value, keys: &[&str]) -> bool {
    keys.iter().any(|k| input[*k].as_bool() == Some(true))
}

/// Tab index keys, in precedence order. The extension schema's `tabId` is a
/// Chrome tab id; through the CDP fallback the only meaningful reading is the
/// positional index `browser_list_tabs` prints (`[0]`, `[1]`, …).
const TAB_INDEX_KEYS: &[&str] = &["index", "tab_index", "tabId"];

/// browser_navigate: Navigate to a URL. SSRF-checked before sending.
pub async fn tool_browser_navigate(
    input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let url = input["url"].as_str().ok_or("Missing 'url' parameter")?;
    // Honour the operator's browser allowlist rather than a hardcoded empty
    // one. Defaults to empty, so behaviour is unchanged unless configured.
    // Without this the browser hand cannot drive T3rnel's own dashboard on
    // loopback, which is precisely what headed UI verification requires.
    crate::web_fetch::check_ssrf(url, &mgr.config().ssrf_allowed_hosts)?;

    let resp = mgr
        .send_command(
            agent_id,
            BrowserCommand::Navigate {
                url: url.to_string(),
                new_tab: arg_bool(input, &["new_tab", "newTab"]),
                tab_index: arg_u64(input, TAB_INDEX_KEYS).map(|i| i as usize),
            },
        )
        .await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "Navigate failed".to_string()));
    }

    let data = resp.data.unwrap_or_default();
    let title = data["title"].as_str().unwrap_or("(no title)");
    let page_url = data["url"].as_str().unwrap_or(url);
    let content = data["content"].as_str().unwrap_or("");
    let wrapped = crate::web_content::wrap_external_content(page_url, content);

    Ok(format!(
        "Navigated to: {page_url}\nTitle: {title}\n\n{wrapped}"
    ))
}

/// browser_click: Click an element by CSS selector or visible text.
pub async fn tool_browser_click(
    input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let selector = input["selector"]
        .as_str()
        .ok_or("Missing 'selector' parameter")?;

    let resp = mgr
        .send_command(
            agent_id,
            BrowserCommand::Click {
                selector: selector.to_string(),
            },
        )
        .await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "Click failed".to_string()));
    }

    let data = resp.data.unwrap_or_default();
    let title = data["title"].as_str().unwrap_or("(no title)");
    let url = data["url"].as_str().unwrap_or("");
    Ok(format!("Clicked: {selector}\nPage: {title}\nURL: {url}"))
}

/// browser_type / browser_fill: Type text into an input field.
///
/// `browser_fill` is the extension name and sends `value`; the daemon-native
/// `browser_type` sends `text`. Both map here.
pub async fn tool_browser_type(
    input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let selector = input["selector"]
        .as_str()
        .ok_or("Missing 'selector' parameter")?;
    let text = arg_str(input, &["text", "value"]).ok_or("Missing 'text' parameter")?;

    let resp = mgr
        .send_command(
            agent_id,
            BrowserCommand::Type {
                selector: selector.to_string(),
                text: text.to_string(),
            },
        )
        .await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "Type failed".to_string()));
    }
    Ok(format!("Typed into {selector}: {text}"))
}

/// browser_screenshot: Take a screenshot of the current page.
pub async fn tool_browser_screenshot(
    input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let resp = mgr
        .send_command(
            agent_id,
            BrowserCommand::Screenshot {
                format: arg_str(input, &["format"]).map(str::to_string),
                quality: arg_u64(input, &["quality"]).map(|q| q.min(255) as u8),
            },
        )
        .await?;
    if !resp.success {
        return Err(resp
            .error
            .unwrap_or_else(|| "Screenshot failed".to_string()));
    }

    let data = resp.data.unwrap_or_default();
    let b64 = data["image_base64"].as_str().unwrap_or("");
    let url = data["url"].as_str().unwrap_or("");

    let mut image_urls: Vec<String> = Vec::new();
    if !b64.is_empty() {
        use base64::Engine;
        let upload_dir = std::env::temp_dir().join("t3rnel_uploads");
        let _ = std::fs::create_dir_all(&upload_dir);
        let file_id = uuid::Uuid::new_v4().to_string();
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64) {
            let path = upload_dir.join(&file_id);
            if std::fs::write(&path, &decoded).is_ok() {
                image_urls.push(format!("/api/uploads/{file_id}"));
            }
        }
    }

    Ok(serde_json::json!({
        "screenshot": true,
        "url": url,
        "image_urls": image_urls,
    })
    .to_string())
}

/// browser_read_page: Read current page content as markdown.
pub async fn tool_browser_read_page(
    _input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let resp = mgr.send_command(agent_id, BrowserCommand::ReadPage).await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "ReadPage failed".to_string()));
    }

    let data = resp.data.unwrap_or_default();
    let title = data["title"].as_str().unwrap_or("(no title)");
    let url = data["url"].as_str().unwrap_or("");
    let content = data["content"].as_str().unwrap_or("");
    let wrapped = crate::web_content::wrap_external_content(url, content);

    Ok(format!("Page: {title}\nURL: {url}\n\n{wrapped}"))
}

/// browser_close: Close the browser session.
pub async fn tool_browser_close(
    _input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    mgr.close_session(agent_id).await;
    Ok("Browser session closed.".to_string())
}

/// browser_close_tab: Close one page target by the index `browser_list_tabs`
/// prints. Previously this routed to `tool_browser_close`, which killed the
/// entire session when the caller asked for one tab.
pub async fn tool_browser_close_tab(
    input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let index = arg_u64(input, TAB_INDEX_KEYS).ok_or("Missing 'tabId' parameter")? as usize;
    let resp = mgr
        .send_command(agent_id, BrowserCommand::CloseTab { index })
        .await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "Close tab failed".to_string()));
    }
    let d = resp.data.unwrap_or_default();
    // The closed tab was the session's own page and nothing else is open —
    // drop the session so the next command attaches fresh instead of
    // failing on a socket bound to a dead target.
    if d["session_empty"].as_bool() == Some(true) {
        mgr.close_session(agent_id).await;
    }
    Ok(format!(
        "Closed tab [{index}] {}{}",
        d["url"].as_str().unwrap_or(""),
        if d["session_empty"].as_bool() == Some(true) {
            "\nNote: session has no remaining pages."
        } else {
            ""
        }
    ))
}

/// browser_scroll: Scroll the page in a direction.
pub async fn tool_browser_scroll(
    input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let direction = input["direction"].as_str().unwrap_or("down").to_string();
    let amount = input["amount"].as_i64().unwrap_or(600) as i32;
    let selector = arg_str(input, &["selector"]).map(str::to_string);

    let resp = mgr
        .send_command(
            agent_id,
            BrowserCommand::Scroll {
                direction,
                amount,
                selector,
            },
        )
        .await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "Scroll failed".to_string()));
    }
    let data = resp.data.unwrap_or_default();
    Ok(format!(
        "Scrolled. Position: scrollX={}, scrollY={}",
        data["scrollX"], data["scrollY"]
    ))
}

/// browser_wait: Wait for a page condition — selector (default), `load`,
/// or a URL substring.
///
/// The extension/probe schema sends `condition`, `value` and `timeoutMs`;
/// the daemon-native call sends `selector` and `timeout_ms`. All are read.
pub async fn tool_browser_wait(
    input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let condition = input["condition"].as_str().unwrap_or("selector");
    match condition {
        "selector" | "load" | "url" => {}
        other => {
            return Err(format!(
                "Unknown wait condition '{other}' (selector|load|url)"
            ));
        }
    }
    let target = arg_str(input, &["selector", "value"]).unwrap_or("");
    if condition != "load" && target.is_empty() {
        return Err("Missing 'selector' (or 'value') parameter".to_string());
    }
    let timeout_ms = arg_u64(input, &["timeout_ms", "timeoutMs"]).unwrap_or(5000);

    let resp = mgr
        .send_command(
            agent_id,
            BrowserCommand::Wait {
                condition: condition.to_string(),
                target: target.to_string(),
                timeout_ms,
            },
        )
        .await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "Wait timed out".to_string()));
    }
    Ok(format!("Wait satisfied: {condition} {target}"))
}

/// browser_run_js / browser_evaluate: Run JavaScript on the current page.
///
/// The extension schema calls the argument `code`; the daemon-native tool
/// calls it `expression`. Both map here.
pub async fn tool_browser_run_js(
    input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let expression = arg_str(input, &["expression", "code"])
        .ok_or("Missing 'expression' (or 'code') parameter")?;

    let resp = mgr
        .send_command(
            agent_id,
            BrowserCommand::RunJs {
                expression: expression.to_string(),
            },
        )
        .await?;
    if !resp.success {
        return Err(resp
            .error
            .unwrap_or_else(|| "JS execution failed".to_string()));
    }
    let data = resp.data.unwrap_or_default();
    Ok(serde_json::to_string_pretty(&data["result"]).unwrap_or_else(|_| "null".to_string()))
}

/// browser_back: Go back in browser history.
pub async fn tool_browser_back(
    _input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let resp = mgr.send_command(agent_id, BrowserCommand::Back).await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "Back failed".to_string()));
    }
    let data = resp.data.unwrap_or_default();
    let title = data["title"].as_str().unwrap_or("(no title)");
    let url = data["url"].as_str().unwrap_or("");
    Ok(format!("Went back.\nPage: {title}\nURL: {url}"))
}

// ── Embedded JavaScript ────────────────────────────────────────────────────

/// JavaScript to extract readable page content as markdown.
const EXTRACT_CONTENT_JS: &str = r#"(() => {
    const title = document.title || '';
    const url = location.href || '';
    const body = document.body;
    if (!body) return JSON.stringify({title, url, content: ''});

    const clone = body.cloneNode(true);
    const remove = ['script','style','nav','footer','header','aside','iframe','noscript','svg','canvas'];
    remove.forEach(tag => clone.querySelectorAll(tag).forEach(el => el.remove()));

    let root = clone.querySelector('main, article, [role="main"], .content, #content');
    if (!root) root = clone;

    const lines = [];
    function walk(node) {
        if (node.nodeType === 3) {
            const t = node.textContent.trim();
            if (t) lines.push(t);
            return;
        }
        if (node.nodeType !== 1) return;
        const tag = node.tagName.toLowerCase();
        if (['h1','h2','h3','h4','h5','h6'].includes(tag)) {
            const level = '#'.repeat(parseInt(tag[1]));
            lines.push('\n' + level + ' ' + node.textContent.trim());
            return;
        }
        if (tag === 'a' && node.href && node.textContent.trim()) {
            lines.push('[' + node.textContent.trim() + '](' + node.href + ')');
            return;
        }
        if (tag === 'li') {
            lines.push('- ' + node.textContent.trim());
            return;
        }
        if (tag === 'br') { lines.push(''); return; }
        if (['p','div','section','tr'].includes(tag)) lines.push('');
        for (const child of node.childNodes) walk(child);
        if (['p','div','section','tr'].includes(tag)) lines.push('');
    }
    walk(root);

    let content = lines.join('\n').replace(/\n{3,}/g, '\n\n').trim();
    if (content.length > 50000) content = content.substring(0, 50000) + '\n... (truncated)';
    return JSON.stringify({title, url, content});
})()"#;

// ── Root detection ─────────────────────────────────────────────────────────

/// Returns true if the current process is running as root (UID 0).
///
/// On Linux, reads `/proc/self/status` to get the effective UID without
/// requiring a `libc` dependency. Falls back to checking the `HOME` env var
/// on systems where `/proc` is not available.
fn is_running_as_root() -> bool {
    #[cfg(unix)]
    {
        // Primary: read effective UID from /proc/self/status (Linux)
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    // Format: "Uid:	<real> <effective> <saved> <fs>"
                    if let Some(euid_str) = rest.split_whitespace().nth(1) {
                        return euid_str == "0";
                    }
                }
            }
        }
        // Fallback: HOME=/root is a reliable indicator on most Unix systems
        std::env::var("HOME").map(|h| h == "/root").unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// browser_forward: Go forward in session history.
pub async fn tool_browser_forward(
    _input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let resp = mgr.send_command(agent_id, BrowserCommand::Forward).await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "Forward failed".to_string()));
    }
    let d = resp.data.unwrap_or_default();
    Ok(format!(
        "Went forward.\nPage: {}\nURL: {}",
        d["title"].as_str().unwrap_or("(no title)"),
        d["url"].as_str().unwrap_or("")
    ))
}

/// browser_reload: Reload the current page.
pub async fn tool_browser_reload(
    _input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let resp = mgr.send_command(agent_id, BrowserCommand::Reload).await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "Reload failed".to_string()));
    }
    let d = resp.data.unwrap_or_default();
    Ok(format!(
        "Reloaded.\nPage: {}\nURL: {}",
        d["title"].as_str().unwrap_or("(no title)"),
        d["url"].as_str().unwrap_or("")
    ))
}

/// browser_hover: Move the mouse over an element.
pub async fn tool_browser_hover(
    input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let selector = input["selector"]
        .as_str()
        .ok_or("Missing 'selector' parameter")?;
    let resp = mgr
        .send_command(
            agent_id,
            BrowserCommand::Hover {
                selector: selector.to_string(),
            },
        )
        .await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "Hover failed".to_string()));
    }
    Ok(format!("Hovered over: {selector}"))
}

/// browser_press: Send a key, optionally focusing an element first.
pub async fn tool_browser_press(
    input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let key = input["key"]
        .as_str()
        .ok_or("Missing 'key' parameter (e.g. Enter, Tab, Escape)")?;
    let selector = input["selector"].as_str().map(str::to_string);
    let resp = mgr
        .send_command(
            agent_id,
            BrowserCommand::Press {
                selector,
                key: key.to_string(),
            },
        )
        .await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "Press failed".to_string()));
    }
    let d = resp.data.unwrap_or_default();
    let page = &d["page"];
    Ok(format!(
        "Pressed {key}.\nPage: {}\nURL: {}",
        page["title"].as_str().unwrap_or("(unchanged)"),
        page["url"].as_str().unwrap_or("")
    ))
}

/// browser_select: Choose an option in a `<select>` by value or label.
pub async fn tool_browser_select(
    input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let selector = input["selector"]
        .as_str()
        .ok_or("Missing 'selector' parameter")?;
    let value = arg_str(input, &["value", "option", "text"]).map(str::to_string);
    let index = arg_u64(input, &["index"]).map(|i| i as usize);
    if value.is_none() && index.is_none() {
        return Err("Missing 'value', 'text' or 'index' parameter".to_string());
    }
    let resp = mgr
        .send_command(
            agent_id,
            BrowserCommand::Select {
                selector: selector.to_string(),
                value: value.clone(),
                index,
            },
        )
        .await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "Select failed".to_string()));
    }
    let d = resp.data.unwrap_or_default();
    Ok(format!(
        "Selected \"{}\" (value={}) in {selector}",
        d["selected"]
            .as_str()
            .map(str::to_string)
            .or(value)
            .unwrap_or_default(),
        d["value"].as_str().unwrap_or("")
    ))
}

/// browser_list_tabs: List open page targets.
pub async fn tool_browser_list_tabs(
    _input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let resp = mgr.send_command(agent_id, BrowserCommand::ListTabs).await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "List tabs failed".to_string()));
    }
    let d = resp.data.unwrap_or_default();
    let mut out = format!("{} tab(s):\n", d["count"].as_u64().unwrap_or(0));
    for tab in d["tabs"].as_array().unwrap_or(&vec![]) {
        out.push_str(&format!(
            "  [{}] {} — {}\n",
            tab["index"].as_u64().unwrap_or(0),
            tab["title"].as_str().unwrap_or("(no title)"),
            tab["url"].as_str().unwrap_or("")
        ));
    }
    Ok(out)
}

/// browser_switch_tab: Activate a tab by index (extension `tabId` reads as
/// the positional index `browser_list_tabs` prints on this transport).
pub async fn tool_browser_switch_tab(
    input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let index = arg_u64(input, TAB_INDEX_KEYS).ok_or("Missing 'index' parameter")? as usize;
    let resp = mgr
        .send_command(agent_id, BrowserCommand::SwitchTab { index })
        .await?;
    if !resp.success {
        return Err(resp
            .error
            .unwrap_or_else(|| "Switch tab failed".to_string()));
    }
    let d = resp.data.unwrap_or_default();
    Ok(format!(
        "Activated tab [{index}] {}\nNote: {}",
        d["url"].as_str().unwrap_or(""),
        d["note"].as_str().unwrap_or("")
    ))
}

/// browser_upload: Attach local files to a file input.
pub async fn tool_browser_upload(
    input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let selector = input["selector"]
        .as_str()
        .unwrap_or("input[type=file]")
        .to_string();
    let nth = input["nth"].as_u64().unwrap_or(0) as usize;
    let files: Vec<String> = match &input["files"] {
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        serde_json::Value::String(s) => vec![s.clone()],
        _ => match input["path"].as_str() {
            Some(p) => vec![p.to_string()],
            None => return Err("Missing 'files' (array) or 'path' (string)".to_string()),
        },
    };
    if files.is_empty() {
        return Err("No files given".to_string());
    }
    let resp = mgr
        .send_command(
            agent_id,
            BrowserCommand::Upload {
                selector: selector.clone(),
                files: files.clone(),
                nth,
            },
        )
        .await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "Upload failed".to_string()));
    }
    Ok(format!(
        "Attached {} file(s) to {selector}[{nth}]: {}",
        files.len(),
        files.join(", ")
    ))
}

/// browser_switch_tab_url: Re-point the session at a tab by URL substring.
pub async fn tool_browser_switch_tab_url(
    input: &serde_json::Value,
    mgr: &BrowserManager,
    agent_id: &str,
) -> Result<String, String> {
    let pat = input["url"]
        .as_str()
        .or_else(|| input["match"].as_str())
        .ok_or("Missing 'url' substring to match")?;
    let resp = mgr
        .send_command(
            agent_id,
            BrowserCommand::SwitchTabUrl {
                url_match: pat.to_string(),
            },
        )
        .await?;
    if !resp.success {
        return Err(resp.error.unwrap_or_else(|| "Switch failed".to_string()));
    }
    let d = resp.data.unwrap_or_default();
    Ok(format!(
        "Now driving: {} — {}",
        d["title"].as_str().unwrap_or("(no title)"),
        d["url"].as_str().unwrap_or("")
    ))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_browser_config_defaults() {
        let config = BrowserConfig::default();
        assert!(config.headless);
        assert_eq!(config.viewport_width, 1280);
        assert_eq!(config.viewport_height, 720);
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.idle_timeout_secs, 300);
        assert_eq!(config.max_sessions, 5);
        assert!(config.chromium_path.is_none());
    }

    #[test]
    fn test_browser_command_serialize_navigate() {
        let cmd = BrowserCommand::Navigate {
            url: "https://example.com".to_string(),
            new_tab: false,
            tab_index: None,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"action\":\"Navigate\""));
        assert!(json.contains("\"url\":\"https://example.com\""));
    }

    #[test]
    fn test_browser_command_serialize_click() {
        let cmd = BrowserCommand::Click {
            selector: "#submit-btn".to_string(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"action\":\"Click\""));
        assert!(json.contains("\"selector\":\"#submit-btn\""));
    }

    #[test]
    fn test_browser_command_serialize_type() {
        let cmd = BrowserCommand::Type {
            selector: "input[name='email']".to_string(),
            text: "test@example.com".to_string(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"action\":\"Type\""));
        assert!(json.contains("test@example.com"));
    }

    #[test]
    fn test_browser_command_serialize_screenshot() {
        let cmd = BrowserCommand::Screenshot {
            format: None,
            quality: None,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"action\":\"Screenshot\""));
        // Old serialized form `{"action":"Screenshot"}` still decodes.
        let parsed: BrowserCommand = serde_json::from_str(r#"{"action":"Screenshot"}"#).unwrap();
        assert!(matches!(
            parsed,
            BrowserCommand::Screenshot {
                format: None,
                quality: None
            }
        ));
    }

    #[test]
    fn test_browser_command_serialize_read_page() {
        let cmd = BrowserCommand::ReadPage;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"action\":\"ReadPage\""));
    }

    #[test]
    fn test_browser_command_serialize_close() {
        let cmd = BrowserCommand::Close;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"action\":\"Close\""));
    }

    #[test]
    fn test_browser_command_serialize_scroll() {
        let cmd = BrowserCommand::Scroll {
            direction: "down".to_string(),
            amount: 500,
            selector: None,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"action\":\"Scroll\""));
        assert!(json.contains("\"amount\":500"));
    }

    #[test]
    fn test_browser_command_serialize_run_js() {
        let cmd = BrowserCommand::RunJs {
            expression: "document.title".to_string(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"action\":\"RunJs\""));
    }

    #[test]
    fn test_browser_command_serialize_back() {
        let cmd = BrowserCommand::Back;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"action\":\"Back\""));
    }

    #[test]
    fn test_browser_command_serialize_wait() {
        let cmd = BrowserCommand::Wait {
            condition: "selector".to_string(),
            target: "#loaded".to_string(),
            timeout_ms: 3000,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"action\":\"Wait\""));
        assert!(json.contains("\"timeout_ms\":3000"));
    }

    #[test]
    fn test_browser_response_deserialize() {
        let json =
            r#"{"success": true, "data": {"title": "Example", "url": "https://example.com"}}"#;
        let resp: BrowserResponse = serde_json::from_str(json).unwrap();
        assert!(resp.success);
        assert!(resp.data.is_some());
        assert!(resp.error.is_none());
        let data = resp.data.unwrap();
        assert_eq!(data["title"], "Example");
    }

    #[test]
    fn test_browser_response_error_deserialize() {
        let json = r#"{"success": false, "error": "Element not found"}"#;
        let resp: BrowserResponse = serde_json::from_str(json).unwrap();
        assert!(!resp.success);
        assert!(resp.data.is_none());
        assert_eq!(resp.error.unwrap(), "Element not found");
    }

    #[test]
    fn test_browser_manager_new() {
        let config = BrowserConfig::default();
        let mgr = BrowserManager::new(config);
        assert!(mgr.sessions.is_empty());
    }

    #[test]
    fn test_is_running_as_root_returns_bool() {
        // Just verify it doesn't panic and returns a bool.
        let _ = is_running_as_root();
    }

    #[test]
    fn test_chromium_candidates_not_empty() {
        let paths = chromium_candidates();
        assert!(
            !paths.is_empty(),
            "Should have platform-specific candidates"
        );
    }

    #[test]
    fn test_response_helpers() {
        let ok = BrowserResponse::ok(serde_json::json!({"a": 1}));
        assert!(ok.success);
        assert!(ok.error.is_none());

        let err = BrowserResponse::err("bad");
        assert!(!err.success);
        assert_eq!(err.error.unwrap(), "bad");
    }

    // ── Argument alias tests ─────────────────────────────────────────────
    //
    // The extension/MCP schema and the daemon-native tool schema name the
    // same argument differently (`code`/`expression`, `value`/`text`,
    // `tabId`/`index`, `timeoutMs`/`timeout_ms`). The HTTP route forwards
    // extension arguments verbatim, so each alias below guards a call that
    // previously failed on the CDP fallback with a missing-parameter error.

    #[test]
    fn test_arg_str_accepts_extension_and_daemon_names() {
        let input = serde_json::json!({"code": "document.title"});
        assert_eq!(
            arg_str(&input, &["expression", "code"]),
            Some("document.title")
        );
        let input = serde_json::json!({"expression": "1+1"});
        assert_eq!(arg_str(&input, &["expression", "code"]), Some("1+1"));
        // Empty strings do not satisfy the requirement.
        let input = serde_json::json!({"expression": "", "code": "x"});
        assert_eq!(arg_str(&input, &["expression", "code"]), Some("x"));
        let input = serde_json::json!({});
        assert_eq!(arg_str(&input, &["expression", "code"]), None);
    }

    #[test]
    fn test_arg_u64_accepts_tab_index_aliases() {
        assert_eq!(
            arg_u64(&serde_json::json!({"tabId": 2}), TAB_INDEX_KEYS),
            Some(2)
        );
        assert_eq!(
            arg_u64(&serde_json::json!({"tab_index": 1}), TAB_INDEX_KEYS),
            Some(1)
        );
        // Explicit index wins over tabId when both arrive.
        assert_eq!(
            arg_u64(&serde_json::json!({"index": 0, "tabId": 9}), TAB_INDEX_KEYS),
            Some(0)
        );
        assert_eq!(arg_u64(&serde_json::json!({}), TAB_INDEX_KEYS), None);
    }

    #[test]
    fn test_arg_bool_accepts_new_tab_aliases() {
        assert!(arg_bool(
            &serde_json::json!({"newTab": true}),
            &["new_tab", "newTab"]
        ));
        assert!(arg_bool(
            &serde_json::json!({"new_tab": true}),
            &["new_tab", "newTab"]
        ));
        assert!(!arg_bool(
            &serde_json::json!({"newTab": false}),
            &["new_tab", "newTab"]
        ));
        assert!(!arg_bool(&serde_json::json!({}), &["new_tab", "newTab"]));
    }

    #[test]
    fn test_select_command_accepts_value_and_index_forms() {
        // Extension `browser_select` may send value, text (label), or index —
        // all must reach the command the session executes.
        let by_value = BrowserCommand::Select {
            selector: "select".to_string(),
            value: Some("usd".to_string()),
            index: None,
        };
        let by_index = BrowserCommand::Select {
            selector: "select".to_string(),
            value: None,
            index: Some(2),
        };
        let json = serde_json::to_string(&by_index).unwrap();
        assert!(json.contains("\"index\":2"));
        // Old serialized form `{"action":"Select","selector":"s","value":"v"}`
        // still decodes with index absent.
        let parsed: BrowserCommand =
            serde_json::from_str(r#"{"action":"Select","selector":"s","value":"v"}"#).unwrap();
        assert!(matches!(
            parsed,
            BrowserCommand::Select {
                value: Some(_),
                index: None,
                ..
            }
        ));
        drop(by_value);
    }

    #[test]
    fn test_wait_command_round_trips_conditions() {
        for condition in ["selector", "load", "url"] {
            let cmd = BrowserCommand::Wait {
                condition: condition.to_string(),
                target: "#x".to_string(),
                timeout_ms: 1000,
            };
            let parsed: BrowserCommand =
                serde_json::from_str(&serde_json::to_string(&cmd).unwrap()).unwrap();
            assert!(matches!(
                parsed,
                BrowserCommand::Wait {
                    timeout_ms: 1000,
                    ..
                }
            ));
        }
    }

    #[test]
    fn test_close_tab_command_serialize() {
        let cmd = BrowserCommand::CloseTab { index: 1 };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"action\":\"CloseTab\""));
        assert!(json.contains("\"index\":1"));
    }
}
