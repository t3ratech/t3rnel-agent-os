//! Plugin supervisor (`17-implementation-guide.md` §9.6–§9.7).
//!
//! The one component that starts plugin programs. It joins the pieces the rest
//! of the plugin infrastructure builds:
//!
//! 1. **Verify.** [`PluginManager::launch_permitted`] re-checks, at every start,
//!    that the installed files still match the signed hash list, that the signer
//!    has not been revoked since install, and that the plugin is not
//!    quarantined for crashing.
//! 2. **Confine.** The plugin runs under [`crate::plugin_sandbox`]: no sockets,
//!    no files outside its own `data/` folder, read-only installed files, a
//!    scrubbed environment, hard resource limits, no core dumps. If the kernel
//!    cannot confine it, it does not start.
//! 3. **Connect.** Two pre-connected streams are inherited into the plugin at
//!    fixed descriptors: [`HOST_FD`] (the plugin calls the core's 14 host
//!    services) and [`CALLBACK_FD`] (the core calls the plugin's
//!    `PluginCallbacks`). The plugin cannot open any other connection, so these
//!    streams are its only way to do anything, and the core knows which plugin
//!    is on each one because it made them.
//! 4. **Watch.** The process is waited on; a crash is recorded (three in an hour
//!    quarantine the plugin) and the plugin is restarted with exponential
//!    back-off.
//!
//! The plugin never sees a secret: everything it sends or receives goes through
//! the host services, whose egress proxy injects credentials the plugin cannot
//! read.

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::watch;

use crate::plugin_grpc::PluginDispatch;
use crate::plugin_lifecycle::{
    valid_entry_name, LifecycleError, PluginManager, PluginManifestLite,
};
use crate::plugin_sandbox::{confined_command, confinement_available, SandboxPolicy};

/// Where the plugin finds its host-service stream (the plugin is the client).
pub const HOST_FD: i32 = 3;
/// Where the plugin finds its callbacks stream (the plugin is the server).
pub const CALLBACK_FD: i32 = 4;
/// Environment variable telling the plugin it is supervised, and where the
/// streams are: `"<host fd>,<callback fd>"`. Absent means the plugin was started
/// by hand for development and uses its development host instead.
pub const STREAMS_ENV: &str = "T3RNEL_HOST_STREAMS";

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("plugin {0:?} may not start: {1}")]
    NotPermitted(String, LifecycleError),
    #[error("plugin {0:?} cannot be confined on this machine: {1}")]
    Unconfined(String, String),
    #[error("plugin {0:?} could not be launched: {1}")]
    Launch(String, String),
    #[error("plugin {0:?} did not answer its health check: {1}")]
    NotReady(String, String),
    #[error("plugin {0:?} is not running")]
    NotRunning(String),
}

/// What a plugin is doing, for the admin API and the dashboard.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PluginState {
    /// Launching or waiting for its first health answer.
    Starting,
    Running { pid: u32 },
    /// Crashed; will be restarted after the back-off.
    Backoff { restarts: u32, retry_in_secs: u64 },
    /// Three crashes in an hour. Needs a person.
    Quarantined { crashes: usize },
    /// Refused at start (tampered files, revoked signer, cannot confine).
    Refused { reason: String },
    Stopped,
}

#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// First restart delay; doubles each crash up to `restart_max`.
    pub restart_base: Duration,
    pub restart_max: Duration,
    /// How long a started plugin has to answer `Health`.
    pub ready_timeout: Duration,
    /// A plugin that stays up this long has its restart count reset.
    pub stable_after: Duration,
    /// How long `stop` waits after SIGTERM before SIGKILL.
    pub stop_grace: Duration,
    /// How often due schedule jobs are fired.
    pub tick_every: Duration,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        SupervisorConfig {
            restart_base: Duration::from_secs(1),
            restart_max: Duration::from_secs(60),
            ready_timeout: Duration::from_secs(20),
            stable_after: Duration::from_secs(60),
            stop_grace: Duration::from_secs(5),
            tick_every: Duration::from_secs(15),
        }
    }
}

struct Handle {
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

pub struct PluginSupervisor {
    home: PathBuf,
    manager: Arc<PluginManager>,
    dispatch: Arc<PluginDispatch>,
    config: SupervisorConfig,
    handles: Mutex<HashMap<String, Handle>>,
    states: Arc<Mutex<HashMap<String, PluginState>>>,
}

impl PluginSupervisor {
    pub fn new(
        home: impl Into<PathBuf>,
        manager: Arc<PluginManager>,
        dispatch: Arc<PluginDispatch>,
        config: SupervisorConfig,
    ) -> Self {
        PluginSupervisor {
            home: home.into(),
            manager,
            dispatch,
            config,
            handles: Mutex::new(HashMap::new()),
            states: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn state(&self, id: &str) -> PluginState {
        self.states
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .unwrap_or(PluginState::Stopped)
    }

    pub fn states(&self) -> Vec<(String, PluginState)> {
        let mut v: Vec<_> = self.states.lock().unwrap().clone().into_iter().collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Start every installed plugin that is not already running. A plugin that
    /// is refused does not stop the others.
    pub async fn start_all(self: &Arc<Self>) {
        for id in self.manager.list() {
            if let Err(e) = self.start(&id).await {
                tracing::warn!(plugin = %id, "not started: {e}");
            }
        }
    }

    /// Start `id`: check it may run, then supervise it in the background.
    /// Returns once the checks pass and the supervision task is running; use
    /// [`state`](Self::state) to see whether the plugin itself came up.
    pub async fn start(self: &Arc<Self>, id: &str) -> Result<(), SupervisorError> {
        {
            // A supervision task that already ended (quarantined, refused on a
            // restart) is not "running": forget it so this start re-checks.
            let mut handles = self.handles.lock().unwrap();
            match handles.get(id) {
                Some(h) if !h.task.is_finished() => return Ok(()),
                Some(_) => {
                    handles.remove(id);
                }
                None => {}
            }
        }
        // Check before spawning anything, so a refusal is an error to the
        // caller and not a log line.
        if let Err(e) = self.preflight(id) {
            let state = match &e {
                SupervisorError::NotPermitted(_, LifecycleError::Quarantined(_, n)) => {
                    PluginState::Quarantined { crashes: *n }
                }
                other => PluginState::Refused {
                    reason: other.to_string(),
                },
            };
            self.states.lock().unwrap().insert(id.to_string(), state);
            return Err(e);
        }
        let (stop_tx, stop_rx) = watch::channel(false);
        let this = self.clone();
        let plugin_id = id.to_string();
        let task = tokio::spawn(async move { this.supervise(plugin_id, stop_rx).await });
        self.handles
            .lock()
            .unwrap()
            .insert(id.to_string(), Handle { stop: stop_tx, task });
        Ok(())
    }

    /// Fire every due schedule job on every connected plugin, once. Returns
    /// `(plugin, job, outcome)` for each job that was due.
    pub async fn tick_once(&self) -> Vec<(String, String, String)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.dispatch.fire_due_schedules(now).await
    }

    /// Run [`tick_once`](Self::tick_once) every `tick_every` for the life of
    /// the daemon. Without this a plugin's scheduled work (morning briefings,
    /// scans) never runs, because the plugin has no clock of its own to call.
    pub fn spawn_ticker(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(this.config.tick_every);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                for (plugin, job, outcome) in this.tick_once().await {
                    if outcome == "ok" {
                        tracing::info!(plugin = %plugin, job = %job, "schedule job fired");
                    } else {
                        tracing::warn!(plugin = %plugin, job = %job, "schedule job: {outcome}");
                    }
                }
            }
        })
    }

    /// Stop `id` and wait until it has gone.
    pub async fn stop(&self, id: &str) -> Result<(), SupervisorError> {
        let handle = self.handles.lock().unwrap().remove(id);
        let Some(handle) = handle else {
            return Err(SupervisorError::NotRunning(id.to_string()));
        };
        let _ = handle.stop.send(true);
        let _ = handle.task.await;
        self.dispatch.detach(id);
        self.states
            .lock()
            .unwrap()
            .insert(id.to_string(), PluginState::Stopped);
        Ok(())
    }

    /// Stop and start again (after an update or rollback).
    pub async fn restart(self: &Arc<Self>, id: &str) -> Result<(), SupervisorError> {
        let _ = self.stop(id).await;
        self.start(id).await
    }

    /// Stop everything (daemon shutdown).
    pub async fn stop_all(&self) {
        let ids: Vec<String> = self.handles.lock().unwrap().keys().cloned().collect();
        for id in ids {
            let _ = self.stop(&id).await;
        }
    }

    fn plugin_dir(&self, id: &str) -> PathBuf {
        self.home.join("plugins").join(id)
    }

    fn read_manifest(&self, id: &str) -> Result<PluginManifestLite, SupervisorError> {
        let bytes = std::fs::read(self.plugin_dir(id).join("manifest.json")).map_err(|e| {
            SupervisorError::Launch(id.to_string(), format!("manifest.json unreadable: {e}"))
        })?;
        serde_json::from_slice(&bytes)
            .map_err(|e| SupervisorError::Launch(id.to_string(), format!("manifest: {e}")))
    }

    fn preflight(&self, id: &str) -> Result<(), SupervisorError> {
        // Verified files, unrevoked signer, not quarantined.
        self.manager
            .launch_permitted(id)
            .map_err(|e| SupervisorError::NotPermitted(id.to_string(), e))?;
        // Fail closed: no confinement, no plugin.
        confinement_available()
            .map_err(|e| SupervisorError::Unconfined(id.to_string(), e.to_string()))?;
        let manifest = self.read_manifest(id)?;
        if manifest.runtime != "process" {
            return Err(SupervisorError::Launch(
                id.to_string(),
                format!("runtime {:?} is not a process plugin", manifest.runtime),
            ));
        }
        if !valid_entry_name(&manifest.entry) {
            return Err(SupervisorError::Launch(
                id.to_string(),
                "entry is not a plain file name".into(),
            ));
        }
        Ok(())
    }

    /// The long-lived task: launch, wait, restart with back-off.
    async fn supervise(self: Arc<Self>, id: String, mut stop: watch::Receiver<bool>) {
        let mut restarts: u32 = 0;
        loop {
            if *stop.borrow() {
                return;
            }
            // Re-check on every start: files may have been tampered with, the
            // signer revoked, or the crash budget used up since the last one.
            if let Err(e) = self.preflight(&id) {
                let state = match &e {
                    SupervisorError::NotPermitted(_, LifecycleError::Quarantined(_, n)) => {
                        PluginState::Quarantined { crashes: *n }
                    }
                    other => PluginState::Refused {
                        reason: other.to_string(),
                    },
                };
                tracing::error!(plugin = %id, "will not restart: {e}");
                self.states.lock().unwrap().insert(id.clone(), state);
                return;
            }
            self.states
                .lock()
                .unwrap()
                .insert(id.clone(), PluginState::Starting);
            let started = Instant::now();
            let outcome = self.run_once(&id, &mut stop).await;
            if *stop.borrow() {
                return;
            }
            match &outcome {
                Ok(()) => tracing::warn!(plugin = %id, "exited"),
                Err(e) => tracing::warn!(plugin = %id, "failed: {e}"),
            }
            if started.elapsed() >= self.config.stable_after {
                restarts = 0;
            }
            // Every unexpected exit counts toward quarantine.
            let crashes = self.manager.record_crash(&id).unwrap_or(0);
            if crashes >= 3 {
                self.states
                    .lock()
                    .unwrap()
                    .insert(id.clone(), PluginState::Quarantined { crashes });
                tracing::error!(plugin = %id, crashes, "quarantined");
                self.dispatch.detach(&id);
                return;
            }
            restarts += 1;
            let delay = self
                .config
                .restart_base
                .saturating_mul(1u32 << restarts.min(16).saturating_sub(1))
                .min(self.config.restart_max);
            self.states.lock().unwrap().insert(
                id.clone(),
                PluginState::Backoff {
                    restarts,
                    retry_in_secs: delay.as_secs(),
                },
            );
            self.dispatch.detach(&id);
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = stop.changed() => { return; }
            }
        }
    }

    /// One launch, from spawn to exit.
    async fn run_once(
        &self,
        id: &str,
        stop: &mut watch::Receiver<bool>,
    ) -> Result<(), SupervisorError> {
        let manifest = self.read_manifest(id)?;
        let dir = self.plugin_dir(id);
        let data = dir.join("data");
        std::fs::create_dir_all(&data)
            .map_err(|e| SupervisorError::Launch(id.to_string(), e.to_string()))?;

        // Two pre-connected streams. The core keeps one end of each; the
        // plugin gets the other end at a fixed descriptor number.
        let (host_core, host_plugin) = std::os::unix::net::UnixStream::pair()
            .map_err(|e| SupervisorError::Launch(id.to_string(), e.to_string()))?;
        let (cb_core, cb_plugin) = std::os::unix::net::UnixStream::pair()
            .map_err(|e| SupervisorError::Launch(id.to_string(), e.to_string()))?;

        let mut policy = SandboxPolicy::for_plugin(&dir);
        policy.inherit = vec![
            (host_plugin.as_raw_fd(), HOST_FD),
            (cb_plugin.as_raw_fd(), CALLBACK_FD),
        ];
        let mut cmd = std::process::Command::new(dir.join(&manifest.entry));
        confined_command(&mut cmd, &policy);
        cmd.current_dir(&data)
            .env("HOME", &data)
            .env("TMPDIR", &data)
            .env("T3RNEL_PLUGIN_ID", id)
            .env("T3RNEL_PLUGIN_HOME", &data)
            .env(STREAMS_ENV, format!("{HOST_FD},{CALLBACK_FD}"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = tokio::process::Command::from(cmd)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| SupervisorError::Launch(id.to_string(), e.to_string()))?;
        // The plugin's ends are in the child now; close ours so that the
        // streams end when the plugin does.
        drop(host_plugin);
        drop(cb_plugin);
        let pid = child.id().unwrap_or(0);

        // Forward the plugin's output into the daemon's log, tagged.
        for (stream, label) in [
            (child.stdout.take().map(StreamKind::Out), "stdout"),
            (child.stderr.take().map(StreamKind::Err), "stderr"),
        ] {
            if let Some(stream) = stream {
                let plugin = id.to_string();
                tokio::spawn(async move { forward_log(plugin, label, stream).await });
            }
        }

        host_core
            .set_nonblocking(true)
            .and_then(|_| cb_core.set_nonblocking(true))
            .map_err(|e| SupervisorError::Launch(id.to_string(), e.to_string()))?;
        let host_core = tokio::net::UnixStream::from_std(host_core)
            .map_err(|e| SupervisorError::Launch(id.to_string(), e.to_string()))?;
        let cb_core = tokio::net::UnixStream::from_std(cb_core)
            .map_err(|e| SupervisorError::Launch(id.to_string(), e.to_string()))?;

        // Serve the host services on this plugin's stream until it closes.
        let dispatch = self.dispatch.clone();
        let plugin_id = id.to_string();
        let server = tokio::spawn(async move {
            if let Err(e) = dispatch.serve_stream(plugin_id.clone(), host_core).await {
                tracing::warn!(plugin = %plugin_id, "host stream ended: {e}");
            }
        });

        // The plugin answers on its callback stream once it has booted. The one
        // deadline covers connecting AND the first health answer: a plugin that
        // holds its streams open and never speaks must not stall the supervisor.
        let ready = async {
            let check = async {
                self.dispatch
                    .attach_callbacks(id, cb_core)
                    .await
                    .map_err(|e| e.to_string())?;
                let answer = self
                    .dispatch
                    .plugin_health(
                        id,
                        crate::plugin_grpc::pb::HealthRequest {
                            plugin: Some(crate::plugin_grpc::pb::PluginIdentity {
                                id: id.to_string(),
                                ..Default::default()
                            }),
                            since: None,
                        },
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                if answer.status == "ok" {
                    Ok(())
                } else {
                    Err(format!("health is {:?}: {}", answer.status, answer.detail))
                }
            };
            tokio::time::timeout(self.config.ready_timeout, check)
                .await
                .map_err(|_| {
                    format!(
                        "no healthy answer within {} ms",
                        self.config.ready_timeout.as_millis()
                    )
                })?
        };
        let result = tokio::select! {
            r = ready => r.map(|_| ()),
            status = child.wait() => {
                // Died before it was ready.
                server.abort();
                return Err(SupervisorError::Launch(
                    id.to_string(),
                    format!(
                        "exited during start: {}",
                        status.map(|s| describe_exit(&s)).unwrap_or_default()
                    ),
                ));
            }
            _ = stop.changed() => {
                terminate(&mut child, self.config.stop_grace).await;
                server.abort();
                return Ok(());
            }
        };
        if let Err(mut reason) = result {
            // If the plugin is already gone, say how: a signal here is usually
            // the sandbox refusing a system call, which a person must see.
            if let Ok(Ok(status)) =
                tokio::time::timeout(Duration::from_millis(500), child.wait()).await
            {
                reason = format!("{reason} (the process exited: {})", describe_exit(&status));
            }
            terminate(&mut child, self.config.stop_grace).await;
            server.abort();
            return Err(SupervisorError::NotReady(id.to_string(), reason));
        }
        self.states
            .lock()
            .unwrap()
            .insert(id.to_string(), PluginState::Running { pid });
        tracing::info!(plugin = %id, pid, "running (confined)");

        let exit = tokio::select! {
            status = child.wait() => status.map_err(|e| e.to_string()),
            _ = stop.changed() => {
                terminate(&mut child, self.config.stop_grace).await;
                server.abort();
                return Ok(());
            }
        };
        server.abort();
        match exit {
            Ok(s) => Err(SupervisorError::Launch(
                id.to_string(),
                format!("exited: {}", describe_exit(&s)),
            )),
            Err(e) => Err(SupervisorError::Launch(id.to_string(), e)),
        }
    }
}

/// `exit code 3` or `killed by signal 31 (SIGSYS: a refused system call)`.
fn describe_exit(status: &std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit code {code}"),
        (None, Some(31)) => "killed by signal 31 (SIGSYS: the sandbox refused a system call)".into(),
        (None, Some(sig)) => format!("killed by signal {sig}"),
        _ => status.to_string(),
    }
}

enum StreamKind {
    Out(tokio::process::ChildStdout),
    Err(tokio::process::ChildStderr),
}

async fn forward_log(plugin: String, label: &'static str, stream: StreamKind) {
    async fn pump<R: tokio::io::AsyncRead + Unpin>(plugin: &str, label: &str, r: R) {
        let mut lines = BufReader::new(r).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            // One line at a time, capped, so a noisy plugin cannot flood the log.
            let line: String = line.chars().take(2000).collect();
            tracing::info!(plugin = %plugin, stream = label, "{line}");
        }
    }
    match stream {
        StreamKind::Out(r) => pump(&plugin, label, r).await,
        StreamKind::Err(r) => pump(&plugin, label, r).await,
    }
}

/// SIGTERM, then SIGKILL after the grace period.
async fn terminate(child: &mut tokio::process::Child, grace: Duration) {
    if let Some(pid) = child.id() {
        // SAFETY: kill takes scalar arguments.
        unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    }
    if tokio::time::timeout(grace, child.wait()).await.is_err() {
        let _ = child.kill().await;
    }
}
