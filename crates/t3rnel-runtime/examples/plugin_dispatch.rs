//! Smoke host for the plugin gRPC dispatch: serves PluginDispatch on
//! 127.0.0.1:50099 against a scratch T3RNEL_HOME, then proves a real
//! plugin binary round-trips host services + PluginCallbacks.
//! Usage: plugin_dispatch <scratch_home>
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let home = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/t3rnel-plugin-smoke".into());
    std::fs::create_dir_all(format!("{home}/plugins/org.t3rnel.comms"))?;
    std::fs::write(
        format!("{home}/plugins/org.t3rnel.comms/manifest.json"),
        serde_json::json!({
            "id": "org.t3rnel.comms", "version": "0.1.0", "name": "comms",
            "runtime": "process", "entry": "plugin"
        })
        .to_string(),
    )?;
    let dispatch = Arc::new(
        t3rnel_runtime::plugin_grpc::PluginDispatch::new(home.clone(), true)
            // Scratch-home smoke host: provide the §14.14 host key so the
            // plugin vault initializes instead of reporting Locked.
            .with_vault_key(zeroize::Zeroizing::new([7u8; 32])),
    );
    let d = dispatch.clone();
    tokio::spawn(async move {
        d.serve("127.0.0.1:50099".parse().unwrap()).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("dispatch serving on 127.0.0.1:50099 home={home}");

    // Wait for the plugin to connect, then prove core->plugin callbacks.
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if !dispatch.plugin_ids().is_empty() {
            break;
        }
    }
    println!("connected plugins: {:?}", dispatch.plugin_ids());
    match dispatch
        .plugin_health(
            "org.t3rnel.comms",
            t3rnel_runtime::plugin_grpc::pb::HealthRequest {
                plugin: Some(t3rnel_runtime::plugin_grpc::pb::PluginIdentity {
                    id: "org.t3rnel.comms".into(),
                    ..Default::default()
                }),
                since: None,
            },
        )
        .await
    {
        Ok(h) => println!(
            "PLUGIN HEALTH OK: {} routes={:?}",
            h.status, h.active_routes
        ),
        Err(e) => println!("PLUGIN HEALTH FAIL: {e}"),
    }
    println!("installed: {:?}", dispatch.installed_plugin_ids());
    tokio::time::sleep(Duration::from_secs(3600)).await;
    Ok(())
}
