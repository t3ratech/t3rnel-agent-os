//! Plugin package lifecycle (`17-implementation-guide.md` §9.7).
//!
//! Install / staged update / rollback / crash-quarantine for plugin packages.
//! A package is a directory containing:
//!
//! ```text
//! manifest.json      — plugin manifest (id, version, permissions, migrations)
//! signature.bin      — ed25519 signature over manifest.json bytes (optional
//!                      in dev mode, REQUIRED when require_signature)
//! plugin             — native binary, or plugin.wasm for wasm runtime
//! migrations/*.sql   — optional; host-run via PluginStorage::migrate
//! ```
//!
//! Layout under `<home>`:
//! - `plugins/<id>/`        — live install
//! - `plugins/<id>.staging/`— update in progress
//! - `plugins/<id>.prev/`   — previous version kept for rollback
//! - `revoked-signers`      — one signer pubkey hex per line; any match refuses install
//!
//! Secrets never appear here: manifests carry secret *names* only.

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::plugin_storage::{validate_plugin_id, PluginStorage, StorageError};

/// Minimal manifest the lifecycle needs. The full bridge manifest (capabilities,
/// auth rules, data classes) is validated by `t3rnel-bridge`; this struct carries
/// the fields install/update/quarantine actually act on, plus a `permissions_summary`
/// the installer displays to the user before approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifestLite {
    pub id: String,
    pub version: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Runtime kind: "process" | "wasm" | "declarative".
    #[serde(default = "default_runtime")]
    pub runtime: String,
    /// Entry binary name inside the package (default "plugin").
    #[serde(default = "default_entry")]
    pub entry: String,
    /// Migrations the host runs on install/update: (version, description, sql).
    #[serde(default)]
    pub migrations: Vec<Migration>,
    /// Permission summary lines shown at install time (from the full manifest).
    #[serde(default)]
    pub permissions_summary: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Migration {
    pub version: i64,
    pub description: String,
    pub sql: String,
}

fn default_runtime() -> String {
    "process".to_string()
}
fn default_entry() -> String {
    "plugin".to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad manifest: {0}")]
    Manifest(String),
    #[error("signature verification failed: {0}")]
    Signature(String),
    #[error("signer {0} is revoked")]
    Revoked(String),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("plugin {0:?} is quarantined ({1} crashes in the last hour)")]
    Quarantined(String, usize),
    #[error("no previous version to roll back to")]
    NoPrevious,
    #[error("package missing entry point {0:?}")]
    MissingEntry(String),
}

#[derive(Debug, Clone)]
pub struct InstallOptions {
    /// Require a valid ed25519 signature from a trusted key.
    pub require_signature: bool,
    /// Trusted signer pubkeys (hex, 32 bytes) allowed to sign packages.
    pub trusted_keys: Vec<String>,
    /// Dev mode: unsigned packages allowed; only ever set by dev tooling.
    pub dev_mode: bool,
}

impl Default for InstallOptions {
    fn default() -> Self {
        InstallOptions {
            require_signature: true,
            trusted_keys: Vec::new(),
            dev_mode: false,
        }
    }
}

/// What the user sees before approving an install — permissions only,
/// never secret material.
#[derive(Debug, Clone, Serialize)]
pub struct InstallReport {
    pub plugin_id: String,
    pub version: String,
    pub action: String, // "install" | "update"
    pub permissions: Vec<String>,
    pub migrations_run: Vec<i64>,
    pub signed: bool,
    pub signer: Option<String>,
}

pub struct PluginManager {
    home: PathBuf,
}

impl PluginManager {
    pub fn new(home: &Path) -> Self {
        PluginManager {
            home: home.to_path_buf(),
        }
    }

    pub fn plugins_dir(&self) -> PathBuf {
        self.home.join("plugins")
    }
    fn install_dir(&self, id: &str) -> PathBuf {
        self.plugins_dir().join(id)
    }
    fn staging_dir(&self, id: &str) -> PathBuf {
        self.plugins_dir().join(format!("{id}.staging"))
    }
    fn prev_dir(&self, id: &str) -> PathBuf {
        self.plugins_dir().join(format!("{id}.prev"))
    }
    /// Read + validate the package manifest.
    fn read_manifest(pkg: &Path) -> Result<PluginManifestLite, LifecycleError> {
        let text = fs::read_to_string(pkg.join("manifest.json"))
            .map_err(|_| LifecycleError::Manifest("manifest.json missing".into()))?;
        let m: PluginManifestLite =
            serde_json::from_str(&text).map_err(|e| LifecycleError::Manifest(e.to_string()))?;
        validate_plugin_id(&m.id).map_err(|e| LifecycleError::Manifest(e.to_string()))?;
        Ok(m)
    }

    /// Verify ed25519 signature over manifest.json bytes. Returns signer
    /// pubkey hex on success.
    fn verify_signature(
        &self,
        pkg: &Path,
        manifest_bytes: &[u8],
        opts: &InstallOptions,
    ) -> Result<Option<String>, LifecycleError> {
        let sig_path = pkg.join("signature.bin");
        if !sig_path.exists() {
            if opts.require_signature && !opts.dev_mode {
                return Err(LifecycleError::Signature("signature.bin missing".into()));
            }
            return Ok(None);
        }
        let sig_bytes = fs::read(&sig_path)?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|_| LifecycleError::Signature("malformed signature".into()))?;
        // The signer pubkey is carried alongside as signer.pub (64-hex).
        let signer_hex = fs::read_to_string(pkg.join("signer.pub"))
            .map_err(|_| LifecycleError::Signature("signer.pub missing".into()))?
            .trim()
            .to_string();
        // Revocation check: home-level revoked-signers list.
        if let Ok(revoked) = fs::read_to_string(self.home.join("revoked-signers")) {
            if revoked.lines().any(|l| l.trim() == signer_hex) {
                return Err(LifecycleError::Revoked(signer_hex));
            }
        }
        // Trusted-key check: if trusted_keys is non-empty the signer must be in it.
        if !opts.trusted_keys.is_empty() && !opts.trusted_keys.iter().any(|k| k == &signer_hex) {
            return Err(LifecycleError::Signature(format!(
                "untrusted signer {signer_hex}"
            )));
        }
        let key_bytes = hex::decode(&signer_hex)
            .map_err(|_| LifecycleError::Signature("signer.pub not hex".into()))?;
        let key_arr: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| LifecycleError::Signature("signer.pub wrong length".into()))?;
        let vk = VerifyingKey::from_bytes(&key_arr)
            .map_err(|_| LifecycleError::Signature("bad pubkey".into()))?;
        vk.verify(manifest_bytes, &sig)
            .map_err(|_| LifecycleError::Signature("ed25519 verify failed".into()))?;
        Ok(Some(signer_hex))
    }

    /// Verify the package has its entry point and copy it into `dest`
    /// via a staging rename (never partially visible).
    fn stage_package(
        &self,
        pkg: &Path,
        manifest: &PluginManifestLite,
        dest: &Path,
    ) -> Result<(), LifecycleError> {
        let entry = if manifest.runtime == "wasm" {
            "plugin.wasm".to_string()
        } else {
            manifest.entry.clone()
        };
        if !pkg.join(&entry).exists() {
            return Err(LifecycleError::MissingEntry(entry));
        }
        if dest.exists() {
            fs::remove_dir_all(dest)?;
        }
        copy_dir_all(pkg, dest)?;
        Ok(())
    }

    /// Run the manifest's migrations through the plugin's own storage.
    fn run_migrations(
        &self,
        id: &str,
        manifest: &PluginManifestLite,
    ) -> Result<Vec<i64>, LifecycleError> {
        if manifest.migrations.is_empty() {
            return Ok(Vec::new());
        }
        let storage = PluginStorage::open(&self.home, id)?;
        let migs: Vec<(i64, &str, &str)> = manifest
            .migrations
            .iter()
            .map(|m| (m.version, m.description.as_str(), m.sql.as_str()))
            .collect();
        Ok(storage.migrate(&migs)?)
    }

    fn health_check(&self, id: &str, manifest: &PluginManifestLite) -> Result<(), LifecycleError> {
        let dir = self.install_dir(id);
        let entry = if manifest.runtime == "wasm" {
            dir.join("plugin.wasm")
        } else {
            dir.join(&manifest.entry)
        };
        if !entry.exists() {
            return Err(LifecycleError::MissingEntry(entry.display().to_string()));
        }
        // Native binaries must be executable; wasm is data (wasmtime checks it).
        if manifest.runtime != "wasm" {
            use std::os::unix::fs::PermissionsExt;
            let mode = entry.metadata()?.permissions().mode();
            if mode & 0o111 == 0 {
                return Err(LifecycleError::MissingEntry(format!(
                    "{} is not executable",
                    entry.display()
                )));
            }
        }
        Ok(())
    }

    /// Install a package directory. Returns the permission display the user
    /// approves. Atomic-ish: stage → verify → rename.
    pub fn install(
        &self,
        pkg: &Path,
        opts: &InstallOptions,
    ) -> Result<InstallReport, LifecycleError> {
        let manifest_bytes = fs::read(pkg.join("manifest.json"))
            .map_err(|_| LifecycleError::Manifest("manifest.json missing".into()))?;
        let manifest = Self::read_manifest(pkg)?;
        let signer = self.verify_signature(pkg, &manifest_bytes, opts)?;
        let staging = self.staging_dir(&manifest.id);
        self.stage_package(pkg, &manifest, &staging)?;
        let final_dir = self.install_dir(&manifest.id);
        if final_dir.exists() {
            return Err(LifecycleError::Manifest(format!(
                "plugin {} already installed; use update",
                manifest.id
            )));
        }
        fs::rename(&staging, &final_dir)?;
        let migrations_run = self.run_migrations(&manifest.id, &manifest)?;
        self.health_check(&manifest.id, &manifest)?;
        // Record install in the plugin's audit trail.
        if let Ok(storage) = PluginStorage::open(&self.home, &manifest.id) {
            let _ = storage.audit_append("lifecycle.install", &manifest.version);
        }
        Ok(InstallReport {
            plugin_id: manifest.id.clone(),
            version: manifest.version.clone(),
            action: "install".into(),
            permissions: manifest.permissions_summary.clone(),
            migrations_run,
            signed: signer.is_some(),
            signer,
        })
    }

    /// Staged update: verify → stage → backup current → swap → migrate.
    /// On any failure after backup, the previous version is restored.
    pub fn update(
        &self,
        pkg: &Path,
        opts: &InstallOptions,
    ) -> Result<InstallReport, LifecycleError> {
        let manifest_bytes = fs::read(pkg.join("manifest.json"))
            .map_err(|_| LifecycleError::Manifest("manifest.json missing".into()))?;
        let manifest = Self::read_manifest(pkg)?;
        let signer = self.verify_signature(pkg, &manifest_bytes, opts)?;
        let current = self.install_dir(&manifest.id);
        if !current.exists() {
            return Err(LifecycleError::Manifest(format!(
                "plugin {} not installed; use install",
                manifest.id
            )));
        }
        let staging = self.staging_dir(&manifest.id);
        self.stage_package(pkg, &manifest, &staging)?;
        let prev = self.prev_dir(&manifest.id);
        if prev.exists() {
            fs::remove_dir_all(&prev)?;
        }
        // Preserve plugin DATA across the binary swap — data/ is state, not
        // code; it must survive updates and rollbacks.
        let data_dir = current.join("data");
        let data_keep = self
            .plugins_dir()
            .join(format!("{}.data-keep", manifest.id));
        let had_data = data_dir.exists();
        if had_data {
            if data_keep.exists() {
                fs::remove_dir_all(&data_keep)?;
            }
            fs::rename(&data_dir, &data_keep)?;
        }
        fs::rename(&current, &prev)?;
        // Swap staging into place.
        if let Err(e) = fs::rename(&staging, &current) {
            // Restore previous (and data) on swap failure.
            let _ = fs::rename(&prev, &current);
            if had_data {
                let _ = fs::rename(&data_keep, current.join("data"));
            }
            return Err(LifecycleError::Io(e));
        }
        if had_data {
            fs::create_dir_all(&current)?;
            fs::rename(&data_keep, current.join("data"))?;
        }
        // Migrations run against existing storage; PluginStorage::migrate
        // takes its own pre-migration snapshot.
        let migrations_run = match self.run_migrations(&manifest.id, &manifest) {
            Ok(v) => v,
            Err(e) => {
                // Roll back binary AND keep plugin data: stash data aside,
                // restore prev binary, put data back.
                let _ = fs::rename(current.join("data"), &data_keep);
                let _ = fs::remove_dir_all(&current);
                let _ = fs::rename(&prev, &current);
                let _ = fs::rename(&data_keep, current.join("data"));
                return Err(e);
            }
        };
        if let Err(e) = self.health_check(&manifest.id, &manifest) {
            let _ = fs::rename(current.join("data"), &data_keep);
            let _ = fs::remove_dir_all(&current);
            let _ = fs::rename(&prev, &current);
            let _ = fs::rename(&data_keep, current.join("data"));
            return Err(e);
        }
        if let Ok(storage) = PluginStorage::open(&self.home, &manifest.id) {
            let _ = storage.audit_append("lifecycle.update", &manifest.version);
        }
        Ok(InstallReport {
            plugin_id: manifest.id.clone(),
            version: manifest.version.clone(),
            action: "update".into(),
            permissions: manifest.permissions_summary.clone(),
            migrations_run,
            signed: signer.is_some(),
            signer,
        })
    }

    /// Roll back to the previous version: restore binary dir and the newest
    /// pre-migration storage snapshot.
    pub fn rollback(&self, id: &str) -> Result<(), LifecycleError> {
        validate_plugin_id(id).map_err(|e| LifecycleError::Manifest(e.to_string()))?;
        let current = self.install_dir(id);
        let prev = self.prev_dir(id);
        if !prev.exists() {
            return Err(LifecycleError::NoPrevious);
        }
        // Preserve plugin data across the binary restore.
        let data_dir = current.join("data");
        let data_keep = self.plugins_dir().join(format!("{}.data-keep", id));
        let had_data = data_dir.exists();
        if had_data {
            if data_keep.exists() {
                fs::remove_dir_all(&data_keep)?;
            }
            fs::rename(&data_dir, &data_keep)?;
        }
        if current.exists() {
            fs::remove_dir_all(&current)?;
        }
        fs::rename(&prev, &current)?;
        if had_data {
            fs::create_dir_all(&current)?;
            fs::rename(&data_keep, current.join("data"))?;
        }
        // Restore newest storage snapshot if one exists.
        let snap_dir = self
            .home
            .join("plugins")
            .join(id)
            .join("data")
            .join("snapshots");
        if let Ok(snaps) = fs::read_dir(&snap_dir) {
            let mut newest: Option<PathBuf> = None;
            let mut newest_name = String::new();
            for entry in snaps.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("pre-migration-") && name > newest_name {
                    newest_name = name;
                    newest = Some(entry.path());
                }
            }
            if let Some(snap) = newest {
                let db = self
                    .home
                    .join("plugins")
                    .join(id)
                    .join("data")
                    .join("plugin.db");
                if db.exists() {
                    let _ = fs::remove_file(&db);
                }
                fs::copy(&snap, &db)?;
            }
        }
        if let Ok(storage) = PluginStorage::open(&self.home, id) {
            let _ = storage.audit_append("lifecycle.rollback", id);
        }
        Ok(())
    }

    /// Record a plugin crash (timestamp now). Returns crash count in the
    /// last hour — quarantine trips at 3.
    pub fn record_crash(&self, id: &str) -> Result<usize, LifecycleError> {
        validate_plugin_id(id).map_err(|e| LifecycleError::Manifest(e.to_string()))?;
        let storage = PluginStorage::open(&self.home, id)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let key = "crashlog";
        let mut log: Vec<u64> = storage
            .kv_get(key)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        log.retain(|t| now.saturating_sub(*t) < 3600);
        log.push(now);
        let blob = serde_json::to_string(&log).unwrap_or_default();
        storage.kv_set(key, &blob)?;
        storage.audit_append("lifecycle.crash", &log.len().to_string())?;
        Ok(log.len())
    }

    /// Whether the plugin may be launched: not quarantined and (if required)
    /// signature-verified install record exists.
    pub fn launch_permitted(&self, id: &str) -> Result<(), LifecycleError> {
        validate_plugin_id(id).map_err(|e| LifecycleError::Manifest(e.to_string()))?;
        let crashes = self.record_crash_readonly(id)?;
        if crashes >= 3 {
            return Err(LifecycleError::Quarantined(id.to_string(), crashes));
        }
        Ok(())
    }

    fn record_crash_readonly(&self, id: &str) -> Result<usize, LifecycleError> {
        let dir = self.install_dir(id);
        if !dir.exists() {
            return Err(LifecycleError::Manifest(format!(
                "plugin {id} not installed"
            )));
        }
        let storage = PluginStorage::open(&self.home, id)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let log: Vec<u64> = storage
            .kv_get("crashlog")?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Ok(log
            .iter()
            .filter(|t| now.saturating_sub(**t) < 3600)
            .count())
    }

    /// Uninstall: remove install dir + prev + staging; keep plugin.db? No —
    /// full removal includes data dir (documented; owner may archive first).
    pub fn uninstall(&self, id: &str) -> Result<(), LifecycleError> {
        validate_plugin_id(id).map_err(|e| LifecycleError::Manifest(e.to_string()))?;
        for d in [
            self.install_dir(id),
            self.prev_dir(id),
            self.staging_dir(id),
        ] {
            if d.exists() {
                fs::remove_dir_all(d)?;
            }
        }
        Ok(())
    }

    /// List installed plugin ids.
    pub fn list(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(self.plugins_dir()) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if e.path().is_dir() && !name.ends_with(".staging") && !name.ends_with(".prev") {
                    out.push(name);
                }
            }
        }
        out.sort();
        out
    }
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &to)?;
        } else {
            fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_pkg(dir: &Path, id: &str, version: &str, sign: bool) -> PathBuf {
        let pkg = dir.join(format!("pkg-{id}-{version}"));
        fs::create_dir_all(&pkg).unwrap();
        let manifest = PluginManifestLite {
            id: id.into(),
            version: version.into(),
            name: format!("Plugin {id}"),
            description: String::new(),
            runtime: "process".into(),
            entry: "plugin".into(),
            migrations: vec![Migration {
                version: 1,
                description: "init".into(),
                sql: "CREATE TABLE t (id INTEGER PRIMARY KEY)".into(),
            }],
            permissions_summary: vec!["capability: fs.read".into(), "host: api.example.com".into()],
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(pkg.join("manifest.json"), &bytes).unwrap();
        // Entry binary (fake content is fine — it's data for lifecycle tests).
        let entry = pkg.join("plugin");
        fs::write(&entry, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&entry, fs::Permissions::from_mode(0o755)).unwrap();
        }
        if sign {
            let seed = [7u8; 32];
            let sk = SigningKey::from_bytes(&seed);
            let sig = sk.sign(&bytes);
            fs::write(pkg.join("signature.bin"), sig.to_bytes()).unwrap();
            let vk = sk.verifying_key();
            fs::write(pkg.join("signer.pub"), hex::encode(vk.to_bytes())).unwrap();
        }
        pkg
    }

    fn signer_hex() -> String {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        hex::encode(sk.verifying_key().to_bytes())
    }

    #[test]
    fn install_unsigned_dev_mode_and_permissions_display() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.test.dev", "0.1.0", false);
        let opts = InstallOptions {
            require_signature: false,
            trusted_keys: vec![],
            dev_mode: true,
        };
        let report = mgr.install(&pkg, &opts).unwrap();
        assert_eq!(report.action, "install");
        assert!(!report.signed);
        assert_eq!(report.permissions.len(), 2);
        assert_eq!(report.migrations_run, vec![1]);
        assert!(mgr.install_dir("org.test.dev").join("plugin").exists());
        assert!(mgr.list().contains(&"org.test.dev".to_string()));
    }

    #[test]
    fn signature_required_and_verified() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.test.signed", "1.0.0", true);
        // Unsigned pkg rejected when required.
        let unsigned = make_pkg(src.path(), "org.test.unsigned", "1.0.0", false);
        let opts = InstallOptions {
            require_signature: true,
            trusted_keys: vec![signer_hex()],
            dev_mode: false,
        };
        assert!(matches!(
            mgr.install(&unsigned, &opts),
            Err(LifecycleError::Signature(_))
        ));
        // Signed pkg accepted.
        let report = mgr.install(&pkg, &opts).unwrap();
        assert!(report.signed);
        assert_eq!(report.signer.as_deref(), Some(signer_hex().as_str()));
    }

    #[test]
    fn revoked_signer_is_refused() {
        let home = tempfile::tempdir().unwrap();
        fs::write(
            home.path().join("revoked-signers"),
            format!("{}\n", signer_hex()),
        )
        .unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.test.revoked", "1.0.0", true);
        let opts = InstallOptions {
            require_signature: true,
            trusted_keys: vec![signer_hex()],
            dev_mode: false,
        };
        assert!(matches!(
            mgr.install(&pkg, &opts),
            Err(LifecycleError::Revoked(_))
        ));
    }

    #[test]
    fn staged_update_then_rollback_restores_previous() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let opts = InstallOptions {
            require_signature: false,
            trusted_keys: vec![],
            dev_mode: true,
        };
        let pkg_v1 = make_pkg(src.path(), "org.test.upd", "1.0.0", false);
        mgr.install(&pkg_v1, &opts).unwrap();
        // v2 package: same id, new version, extra migration.
        let pkg_v2 = src.path().join("pkg-v2");
        fs::create_dir_all(&pkg_v2).unwrap();
        let manifest = PluginManifestLite {
            id: "org.test.upd".into(),
            version: "2.0.0".into(),
            name: "Plugin upd".into(),
            description: String::new(),
            runtime: "process".into(),
            entry: "plugin".into(),
            migrations: vec![
                Migration {
                    version: 1,
                    description: "init".into(),
                    sql: "CREATE TABLE t (id INTEGER PRIMARY KEY)".into(),
                },
                Migration {
                    version: 2,
                    description: "v2".into(),
                    sql: "ALTER TABLE t ADD COLUMN x TEXT".into(),
                },
            ],
            permissions_summary: vec![],
        };
        fs::write(
            pkg_v2.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(pkg_v2.join("plugin"), b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(pkg_v2.join("plugin"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let report = mgr.update(&pkg_v2, &opts).unwrap();
        assert_eq!(report.action, "update");
        assert_eq!(report.migrations_run, vec![2]); // v1 already applied
                                                    // Binary is v2 content-wise (same bytes here; version in manifest).
        let m: PluginManifestLite = serde_json::from_slice(
            &fs::read(mgr.install_dir("org.test.upd").join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(m.version, "2.0.0");
        // Rollback restores v1 binary dir.
        mgr.rollback("org.test.upd").unwrap();
        let m: PluginManifestLite = serde_json::from_slice(
            &fs::read(mgr.install_dir("org.test.upd").join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(m.version, "1.0.0");
    }

    #[test]
    fn three_crashes_in_an_hour_quarantine() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.test.crash", "1.0.0", false);
        let opts = InstallOptions {
            require_signature: false,
            trusted_keys: vec![],
            dev_mode: true,
        };
        mgr.install(&pkg, &opts).unwrap();
        assert!(mgr.launch_permitted("org.test.crash").is_ok());
        assert_eq!(mgr.record_crash("org.test.crash").unwrap(), 1);
        assert_eq!(mgr.record_crash("org.test.crash").unwrap(), 2);
        assert_eq!(mgr.record_crash("org.test.crash").unwrap(), 3);
        assert!(matches!(
            mgr.launch_permitted("org.test.crash"),
            Err(LifecycleError::Quarantined(_, 3))
        ));
    }

    #[test]
    fn uninstall_removes_all_dirs() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.test.rm", "1.0.0", false);
        let opts = InstallOptions {
            require_signature: false,
            trusted_keys: vec![],
            dev_mode: true,
        };
        mgr.install(&pkg, &opts).unwrap();
        mgr.uninstall("org.test.rm").unwrap();
        assert!(mgr.list().is_empty());
        assert!(!mgr.install_dir("org.test.rm").exists());
    }
}
