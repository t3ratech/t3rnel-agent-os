//! Move a plugin's development-host state into the core.
//!
//! Before the supervisor existed a plugin ran with a file-backed development host:
//! its secrets lay as files under `<state>/host/secrets/`, its memory in
//! `<state>/memory.json`, its config in `<state>/config.toml`. A supervised plugin
//! has none of that: secrets live in the core's vault, memory in the core's
//! per-plugin storage, config in its own `data/` folder. This tool moves the
//! state over once so nothing the plugin had learned is lost.
//!
//! ```text
//! cargo run -p t3rnel-runtime --example migrate_dev_state -- <t3rnel home> <state root> [--delete-secret-files]
//! ```
//!
//! `<state root>` holds one folder per plugin id (`~/.t3rnel/plugin-state`). Run it
//! as the daemon runs (unset `USER`, `USERNAME`, `HOSTNAME`) so the vault opens
//! with the same key. Secret values are never printed. Existing vault entries
//! and memory keys are left alone, so running it twice is harmless.

use std::path::{Path, PathBuf};

use t3rnel_runtime::plugin_host::{host_config_from_manifest, manifest_data_classes, PluginHost};
use t3rnel_runtime::plugin_lifecycle::PluginManifestLite;
use t3rnel_runtime::plugin_services::{DataClass, MemoryService};
use zeroize::Zeroizing;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect::<Vec<_>>().split_off(1);
    let (Some(home), Some(root)) = (args.first(), args.get(1)) else {
        eprintln!("usage: migrate_dev_state <t3rnel home> <state root> [--delete-secret-files]");
        std::process::exit(2);
    };
    let delete_files = args.iter().any(|a| a == "--delete-secret-files");
    let (home, root) = (PathBuf::from(home), PathBuf::from(root));

    let mut ids: Vec<String> = std::fs::read_dir(&root)?
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    ids.sort();

    let mut failures = 0;
    for id in ids {
        let installed = home.join("plugins").join(&id);
        let Ok(bytes) = std::fs::read(installed.join("manifest.json")) else {
            println!("{id}: not installed, skipped");
            continue;
        };
        match migrate_one(&installed, &root.join(&id), &home, &bytes, delete_files) {
            Ok(summary) => println!("{id}: {summary}"),
            Err(e) => {
                failures += 1;
                println!("{id}: FAILED: {e}");
            }
        }
    }
    if failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn migrate_one(
    installed: &Path,
    state: &Path,
    home: &Path,
    manifest_bytes: &[u8],
    delete_files: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let manifest: PluginManifestLite = serde_json::from_slice(manifest_bytes)?;
    let cfg = host_config_from_manifest(&manifest, None, false);
    let host = PluginHost::open(home, cfg)?;

    // 1. Secrets: one file per secret name; the file's text is the value.
    let (mut moved, mut kept) = (0, 0);
    let secrets_dir = state.join("host").join("secrets");
    if let Ok(entries) = std::fs::read_dir(&secrets_dir) {
        for e in entries.flatten() {
            let Ok(name) = e.file_name().into_string() else { continue };
            if !e.path().is_file() {
                continue;
            }
            if host.vault.resolve(&name).is_ok() {
                kept += 1; // already in the vault
            } else {
                let value = Zeroizing::new(std::fs::read_to_string(e.path())?.trim().to_string());
                if value.is_empty() {
                    continue;
                }
                host.vault.provision(&name, value)?;
                moved += 1;
            }
            if delete_files {
                // Confirm the vault has it before the file goes.
                host.vault.resolve(&name)?;
                std::fs::remove_file(e.path())?;
            }
        }
    }

    // 2. Memory: the dev host stored `{key: value-string}`. Records keep the
    //    plugin-private label (every migrated plugin declares it).
    let classes: Vec<DataClass> = manifest_data_classes(manifest.permissions.as_ref());
    let label: std::collections::BTreeSet<DataClass> = if classes.contains(&DataClass::PluginPrivate)
    {
        [DataClass::PluginPrivate].into()
    } else {
        classes.first().copied().into_iter().collect()
    };
    let mem = MemoryService::new(&host.storage, classes.iter().copied());
    let (mut imported, mut present) = (0, 0);
    if let Ok(text) = std::fs::read_to_string(state.join("memory.json")) {
        let map: std::collections::BTreeMap<String, serde_json::Value> = serde_json::from_str(&text)?;
        for (key, value) in map {
            if mem.get(&key)?.is_some() {
                present += 1;
                continue;
            }
            let value = match value {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            };
            mem.set(&key, &value, &label)?;
            imported += 1;
        }
    }

    // 3. Config: the plugin reads `$T3RNEL_PLUGIN_HOME/config.toml`, and that is its `data/` folder now.
    let mut config = "no config";
    let cfg_file = state.join("config.toml");
    if cfg_file.is_file() {
        let data = installed.join("data");
        std::fs::create_dir_all(&data)?;
        let target = data.join("config.toml");
        if target.exists() {
            config = "config already present";
        } else {
            std::fs::copy(&cfg_file, &target)?;
            config = "config copied";
        }
    }
    Ok(format!(
        "{moved} secret(s) moved to the vault ({kept} already there), {imported} memory key(s) imported ({present} already present), {config}"
    ))
}
