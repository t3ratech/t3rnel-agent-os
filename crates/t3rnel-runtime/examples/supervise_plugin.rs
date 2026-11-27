//! Run a real plugin under the real supervisor, sandbox and dispatch, in a
//! scratch home, and show what the core sees.
//!
//! ```text
//! cargo run -p t3rnel-runtime --example supervise_plugin -- <source dir with manifest.yaml> <plugin binary> [seconds]
//! ```
//!
//! The scratch home is deleted afterwards; nothing touches `~/.t3rnel`.

use std::sync::Arc;
use std::time::Duration;

use t3rnel_runtime::plugin_grpc::{pb, PluginDispatch};
use t3rnel_runtime::plugin_lifecycle::{InstallOptions, PluginManager};
use t3rnel_runtime::plugin_sign::{package_plugin, ReleaseSigner};
use t3rnel_runtime::plugin_supervisor::{PluginState, PluginSupervisor, SupervisorConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter("info").with_writer(std::io::stderr).init();
    let args: Vec<String> = std::env::args().collect::<Vec<_>>().split_off(1);
    let (Some(src_dir), Some(binary)) = (args.first(), args.get(1)) else {
        eprintln!("usage: supervise_plugin <source dir> <plugin binary> [seconds]");
        std::process::exit(2);
    };
    let seconds: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);

    let tmp = tempfile::tempdir()?;
    let home = tmp.path().join("home");
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src)?;
    std::fs::copy(std::path::Path::new(src_dir).join("manifest.yaml"), src.join("manifest.yaml"))?;
    std::fs::copy(binary, src.join("plugin"))?;
    let keys = tmp.path().join("keys");
    std::fs::create_dir_all(&keys)?;
    let signer = ReleaseSigner::generate(&keys)?;
    let pkg = tmp.path().join("pkg");
    let report = package_plugin(&src, &pkg, &signer, Some(&home))?;
    let manager = Arc::new(PluginManager::new(&home));
    manager.install(
        &pkg,
        &InstallOptions {
            require_signature: true,
            trusted_keys: vec![signer.pubkey_hex()],
            dev_mode: false,
        },
    )?;
    println!("installed {} {} (signed by {}…)", report.plugin_id, report.version, &signer.pubkey_hex()[..12]);

    let dispatch = Arc::new(
        PluginDispatch::new(&home, false).with_vault_key(zeroize::Zeroizing::new([9u8; 32])),
    );
    let supervisor = Arc::new(PluginSupervisor::new(
        &home,
        manager,
        dispatch.clone(),
        SupervisorConfig { ready_timeout: Duration::from_secs(30), ..Default::default() },
    ));
    supervisor.start(&report.plugin_id).await?;
    let id = report.plugin_id.clone();
    for _ in 0..300 {
        match supervisor.state(&id) {
            PluginState::Running { .. } => break,
            PluginState::Quarantined { .. } | PluginState::Refused { .. } => break,
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    println!("state: {:?}", supervisor.state(&id));
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    println!("state after {seconds}s: {:?}", supervisor.state(&id));

    let ident = Some(pb::PluginIdentity { id: id.clone(), ..Default::default() });
    match dispatch
        .status_query(&id, pb::StatusQueryRequest { plugin: ident.clone(), since: None })
        .await
    {
        Ok(s) => println!("status: level={} headline={:?} metrics={:?}", s.level, s.headline, s.metrics),
        Err(e) => println!("status: {e}"),
    }
    match dispatch
        .briefing_query(&id, pb::BriefingQueryRequest { plugin: ident, ..Default::default() })
        .await
    {
        Ok(b) => {
            println!("briefing: headline={:?} items={} actions={}", b.headline, b.items.len(), b.actions.len());
            for item in &b.items {
                println!("  - {}", item.text);
            }
        }
        Err(e) => println!("briefing: {e}"),
    }
    println!("tick: {:?}", supervisor.tick_once().await);
    supervisor.stop_all().await;
    println!("stopped: {:?}", supervisor.state(&id));
    Ok(())
}
