//! End-to-end proof of the plugin supervisor: a real signed package, installed
//! by the real lifecycle manager, launched by the real supervisor under the real
//! sandbox, talking to the real dispatch over the inherited streams.
//!
//! The plugin is `plugin-conformance-fixture` (`src/bin`), which attempts the
//! things a malicious plugin would and records the outcome in `probe.json`.
//! Every assertion here can fail: a sandbox or dispatch that stopped enforcing
//! one of these rules turns a test red.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use t3rnel_runtime::plugin_grpc::PluginDispatch;
use t3rnel_runtime::plugin_lifecycle::{InstallOptions, PluginManager};
use t3rnel_runtime::plugin_sandbox::confinement_available;
use t3rnel_runtime::plugin_sign::{package_plugin, ReleaseSigner};
use t3rnel_runtime::plugin_supervisor::{
    PluginState, PluginSupervisor, SupervisorConfig, SupervisorError,
};

const ID: &str = "org.test.fixture";
const FIXTURE: &str = env!("CARGO_BIN_EXE_plugin-conformance-fixture");

const MANIFEST: &str = r#"
id: "org.test.fixture"
name: "Conformance Fixture"
version: "0.1.0"
description: "supervisor end-to-end proof"
plugin:
  type: "process"
  min_t3rnel_version: "0.6.4"
targets: ["linux"]
entry: "plugin"
permissions:
  auth: []
  data_classes: ["public"]
  local: []
requires:
  host_services: ["storage", "http"]
"#;

struct World {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    manager: Arc<PluginManager>,
    supervisor: Arc<PluginSupervisor>,
}

impl World {
    fn data(&self) -> PathBuf {
        self.home.join("plugins").join(ID).join("data")
    }
    fn installed(&self) -> PathBuf {
        self.home.join("plugins").join(ID)
    }
}

fn fast() -> SupervisorConfig {
    SupervisorConfig {
        restart_base: Duration::from_millis(20),
        restart_max: Duration::from_millis(100),
        ready_timeout: Duration::from_secs(15),
        stable_after: Duration::from_secs(3600),
        stop_grace: Duration::from_secs(2),
        tick_every: Duration::from_secs(3600),
    }
}

/// Build, sign and install the fixture, with `mode` written to its data folder.
fn world(mode: &str, config: SupervisorConfig) -> World {
    world_with(mode, config, MANIFEST, None)
}

fn world_with(
    mode: &str,
    config: SupervisorConfig,
    manifest: &str,
    conversations: Option<Arc<dyn t3rnel_runtime::plugin_grpc::ConversationsPort>>,
) -> World {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("manifest.yaml"), manifest).unwrap();
    std::fs::copy(FIXTURE, src.join("plugin")).unwrap();
    let keys = tmp.path().join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let signer = ReleaseSigner::generate(&keys).unwrap();
    let pkg = tmp.path().join("pkg");
    package_plugin(&src, &pkg, &signer, Some(&home)).unwrap();

    let manager = Arc::new(PluginManager::new(&home));
    manager
        .install(
            &pkg,
            &InstallOptions {
                require_signature: true,
                trusted_keys: vec![signer.pubkey_hex()],
                dev_mode: false,
            },
        )
        .unwrap();
    let data = home.join("plugins").join(ID).join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("mode"), mode).unwrap();

    // The daemon hands dispatch the vault key once the vault is unlocked.
    let dispatch = Arc::new(
        PluginDispatch::new(&home, false).with_vault_key(zeroize::Zeroizing::new([9u8; 32])),
    );
    if let Some(port) = conversations {
        dispatch.attach_conversations(port);
    }
    let supervisor = Arc::new(PluginSupervisor::new(
        &home,
        manager.clone(),
        dispatch,
        config,
    ));
    World {
        _tmp: tmp,
        home,
        manager,
        supervisor,
    }
}

async fn wait_for<F: Fn() -> bool>(what: &str, secs: u64, check: F, show: impl Fn() -> String) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}; now: {}", show());
}

fn pid_alive(pid: u32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

fn read_probe(data: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(data.join("probe.json")).expect("probe.json"))
        .expect("probe json")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signed_plugin_runs_confined_and_every_escape_attempt_fails() {
    confinement_available().expect("this test needs a kernel that can confine (Landlock + seccomp)");
    let w = world("ok", fast());
    // A secret in the daemon's environment must never reach the plugin.
    std::env::set_var("T3RNEL_TEST_SECRET_TOKEN", "must-not-be-visible");

    w.supervisor.start(ID).await.unwrap();
    let sup = w.supervisor.clone();
    wait_for(
        "the plugin to be running",
        30,
        || matches!(sup.state(ID), PluginState::Running { .. }),
        || format!("{:?}", sup.state(ID)),
    )
    .await;
    let data = w.data();
    wait_for("probe.json", 30, || data.join("probe.json").exists(), || "no probe".into()).await;
    let p = read_probe(&data);

    // No network of any kind.
    assert!(p["raw_socket_error"].is_string(), "raw TCP connect must fail: {p}");
    assert!(p["udp_socket_error"].is_string(), "UDP socket must fail: {p}");
    // Files: nothing outside its folder, installed files are read-only, its folder works.
    assert!(p["read_outside_error"].is_string(), "/etc/passwd must be unreadable: {p}");
    assert_eq!(p["read_own_manifest_ok"], true, "{p}");
    assert!(p["write_own_manifest_error"].is_string(), "manifest must be read-only: {p}");
    assert!(p["write_own_binary_dir_error"].is_string(), "installed dir must be read-only: {p}");
    assert_eq!(p["write_data_ok"], true, "{p}");
    // Environment: scrubbed.
    let names: Vec<String> = p["env_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(!names.iter().any(|n| n == "T3RNEL_TEST_SECRET_TOKEN"), "secret leaked: {names:?}");
    for n in &names {
        assert!(
            ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"].contains(&n.as_str()) || n.starts_with("T3RNEL_"),
            "unexpected variable {n} in {names:?}"
        );
    }
    // No core dumps.
    assert_eq!(p["core_limit"], 0, "{p}");
    // The host proxy refuses a host the manifest did not declare.
    assert!(p["http_undeclared"].is_string(), "undeclared host must be refused: {p}");
    // Its own storage works; claiming to be another plugin does not.
    assert_eq!(p["storage_own_ok"], true, "{p}");
    assert!(p["storage_as_other_plugin"].is_string(), "identity forgery must be refused: {p}");
    // This manifest does not require `conversations`, so sending is refused.
    assert_eq!(p["conversations_send"], "PermissionDenied", "{p}");

    // Scheduling: a job the plugin registered is fired by the core, exactly once.
    assert_eq!(p["schedule_add"]["Ok"][0], "probe-tick", "{p}");
    let fired = w.supervisor.tick_once().await;
    assert_eq!(
        fired,
        vec![(ID.to_string(), "probe-tick".to_string(), "ok".to_string())],
        "the due job must be fired and succeed"
    );
    let ticks = std::fs::read_to_string(data.join("ticks.log")).unwrap();
    assert_eq!(ticks.lines().collect::<Vec<_>>(), vec!["probe-tick"], "fired once: {ticks:?}");
    assert!(w.supervisor.tick_once().await.is_empty(), "a retired one-shot must not fire again");
    assert_eq!(std::fs::read_to_string(data.join("ticks.log")).unwrap().lines().count(), 1);

    // Stop: the process really goes away.
    let pid = match w.supervisor.state(ID) {
        PluginState::Running { pid } => pid,
        other => panic!("not running: {other:?}"),
    };
    assert!(pid_alive(pid));
    w.supervisor.stop(ID).await.unwrap();
    assert_eq!(w.supervisor.state(ID), PluginState::Stopped);
    wait_for("the process to exit", 10, || !pid_alive(pid), || "still alive".into()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plugin_that_keeps_crashing_is_backed_off_then_quarantined() {
    confinement_available().expect("needs confinement");
    let w = world("crash", fast());
    w.supervisor.start(ID).await.unwrap();
    let sup = w.supervisor.clone();
    wait_for(
        "quarantine",
        30,
        || matches!(sup.state(ID), PluginState::Quarantined { .. }),
        || format!("{:?}", sup.state(ID)),
    )
    .await;
    // Quarantine survives: asking again is refused, with the reason.
    let again = w.supervisor.start(ID).await.unwrap_err();
    assert!(
        matches!(again, SupervisorError::NotPermitted(_, _)),
        "a quarantined plugin must not start: {again:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plugin_that_never_answers_health_is_killed_and_not_called_running() {
    confinement_available().expect("needs confinement");
    let mut cfg = fast();
    cfg.ready_timeout = Duration::from_millis(800);
    let w = world("hang", cfg);
    w.supervisor.start(ID).await.unwrap();
    let sup = w.supervisor.clone();
    wait_for(
        "a failed start",
        30,
        || matches!(sup.state(ID), PluginState::Backoff { .. } | PluginState::Quarantined { .. }),
        || format!("{:?}", sup.state(ID)),
    )
    .await;
    assert!(
        !matches!(w.supervisor.state(ID), PluginState::Running { .. }),
        "a plugin that does not answer health must never be reported running"
    );
    w.supervisor.stop(ID).await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tampered_installed_file_is_refused_at_start() {
    confinement_available().expect("needs confinement");
    let w = world("ok", fast());
    // Someone edits the installed program after it was signed.
    let entry = w.installed().join("plugin");
    let mut perms = std::fs::metadata(&entry).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(&entry, perms).unwrap();
    let mut bytes = std::fs::read(&entry).unwrap();
    bytes.extend_from_slice(b"\n# injected");
    std::fs::write(&entry, bytes).unwrap();

    let err = w.supervisor.start(ID).await.unwrap_err();
    assert!(matches!(err, SupervisorError::NotPermitted(_, _)), "{err:?}");
    assert!(
        matches!(w.supervisor.state(ID), PluginState::Refused { .. }),
        "{:?}",
        w.supervisor.state(ID)
    );
    // And nothing ran: no probe file.
    assert!(!w.data().join("probe.json").exists());
    let _ = &w.manager;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_signer_is_refused_at_start() {
    confinement_available().expect("needs confinement");
    let w = world("ok", fast());
    let signer = std::fs::read_to_string(w.installed().join("signer.pub")).unwrap();
    std::fs::write(w.home.join("revoked-signers"), format!("{}\n", signer.trim())).unwrap();
    let err = w.supervisor.start(ID).await.unwrap_err();
    assert!(matches!(err, SupervisorError::NotPermitted(_, _)), "{err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plugin_that_boots_slowly_is_still_reached_and_stays_up() {
    confinement_available().expect("needs confinement");
    let w = world("slow", fast());
    w.supervisor.start(ID).await.unwrap();
    let sup = w.supervisor.clone();
    wait_for(
        "the slow plugin to be running",
        30,
        || matches!(sup.state(ID), PluginState::Running { .. }),
        || format!("{:?}", sup.state(ID)),
    )
    .await;
    // And it stays running after the first health answer.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(matches!(w.supervisor.state(ID), PluginState::Running { .. }), "{:?}", w.supervisor.state(ID));
    w.supervisor.stop(ID).await.unwrap();
}

struct RecordingPort(std::sync::Mutex<Vec<(String, String, String, String)>>);

#[async_trait::async_trait]
impl t3rnel_runtime::plugin_grpc::ConversationsPort for RecordingPort {
    async fn send(&self, channel: &str, account: &str, thread: &str, text: &str) -> Result<String, String> {
        self.0.lock().unwrap().push((channel.into(), account.into(), thread.into(), text.into()));
        Ok("receipt-1".into())
    }
    fn counters(&self) -> t3rnel_runtime::plugin_grpc::ConversationCounters {
        Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plugin_that_declared_conversations_can_send_and_the_send_is_audited() {
    confinement_available().expect("needs confinement");
    let port = Arc::new(RecordingPort(Default::default()));
    let manifest = MANIFEST.replace(
        "host_services: [\"storage\", \"http\"]",
        "host_services: [\"storage\", \"http\", \"conversations\"]",
    );
    assert_ne!(manifest, MANIFEST);
    let w = world_with("ok", fast(), &manifest, Some(port.clone()));
    w.supervisor.start(ID).await.unwrap();
    let data = w.data();
    wait_for("probe.json", 30, || data.join("probe.json").exists(), || "no probe".into()).await;
    let p = read_probe(&data);
    assert_eq!(p["conversations_send"], "ok:receipt-1", "{p}");
    assert_eq!(
        port.0.lock().unwrap().clone(),
        vec![(
            "local:web".to_string(),
            "web".to_string(),
            "t1".to_string(),
            "hello from the fixture".to_string()
        )]
    );
    w.supervisor.stop(ID).await.unwrap();
}
