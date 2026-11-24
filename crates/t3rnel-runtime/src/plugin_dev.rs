//! Plugin developer loop (`04-app-bridge-and-connectors.md` §14.6, guide §9.8).
//!
//! Dev mode exists so plugin authors can iterate without release signing:
//!
//! - **Dev signer**: an ed25519 keypair generated once per T3rnel home under
//!   `dev-keys/plugin-dev.signing` (+ `.pub`). `sign_package()` produces the
//!   `signature.bin`/`signer.pub` files the lifecycle verifier expects, so a
//!   dev-signed package passes the *same* verification path as release —
//!   the only difference is which key is trusted.
//! - **Unsigned dev install**: [`PluginManager::install`] with
//!   `dev_mode: true` — for throwaway iteration before signing exists.
//! - **Hot reload**: [`DevLoop::check_reload`] compares the package's
//!   manifest mtime/version against the installed copy and returns
//!   `ReloadAction::Reinstall` when the source changed; the caller re-runs
//!   `update()`. File watching itself is the host's job (notify/inotify) —
//!   this module provides the decision, not the watcher.
//! - **Canary secrets only**: in dev mode the vault broker provisions ONLY
//!   `t3rn:canary:*` and `dev:*` names; [`DevLoop::assert_dev_secret_name`]
//!   rejects anything else so a dev plugin can never be handed a real
//!   credential.
//!
//! Dev mode must never be reachable in production builds: callers gate it
//! behind `cfg!(debug_assertions)` or an explicit host flag.

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};

use crate::plugin_lifecycle::{InstallOptions, LifecycleError, PluginManager};
use crate::plugin_vault::VaultBroker;

/// Dev signing key material, persisted under `<home>/dev-keys/`.
pub struct DevSigner {
    home: PathBuf,
}

impl DevSigner {
    pub fn new(home: &Path) -> Self {
        DevSigner {
            home: home.to_path_buf(),
        }
    }

    fn key_path(&self) -> PathBuf {
        self.home.join("dev-keys").join("plugin-dev.signing")
    }
    /// Load or generate the dev signing key. The seed file is 32 raw bytes;
    /// it is a *dev* key — never used for release packages.
    pub fn load_or_generate(&self) -> Result<SigningKey, LifecycleError> {
        let path = self.key_path();
        if path.exists() {
            let bytes = fs::read(&path)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| LifecycleError::Manifest("dev key wrong length".into()))?;
            return Ok(SigningKey::from_bytes(&arr));
        }
        fs::create_dir_all(path.parent().unwrap())?;
        let mut seed = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut seed);
        fs::write(&path, seed)?;
        // Best-effort restriction to owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(SigningKey::from_bytes(&seed))
    }

    /// The dev signer's pubkey hex — add to `trusted_keys` for dev installs.
    pub fn pubkey_hex(&self) -> Result<String, LifecycleError> {
        let sk = self.load_or_generate()?;
        Ok(hex::encode(sk.verifying_key().to_bytes()))
    }

    /// Sign a package directory in place: writes `signature.bin` and
    /// `signer.pub` over the manifest.json bytes — exactly what
    /// [`PluginManager::verify_signature`] checks.
    pub fn sign_package(&self, pkg: &Path) -> Result<(), LifecycleError> {
        let manifest_bytes = fs::read(pkg.join("manifest.json"))
            .map_err(|_| LifecycleError::Manifest("manifest.json missing".into()))?;
        let sk = self.load_or_generate()?;
        let sig = sk.sign(&manifest_bytes);
        fs::write(pkg.join("signature.bin"), sig.to_bytes())?;
        fs::write(
            pkg.join("signer.pub"),
            hex::encode(sk.verifying_key().to_bytes()),
        )?;
        Ok(())
    }
}

/// What the dev loop should do when the source package changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadAction {
    /// Source manifest mtime/version differs from installed — re-run update.
    Reinstall,
    /// Nothing changed.
    Unchanged,
    /// Plugin not installed yet — run install.
    Install,
}

/// The developer loop state for one plugin.
pub struct DevLoop {
    manager: PluginManager,
    home: PathBuf,
}

impl DevLoop {
    /// `home` is the T3rnel home (scratch in tests). `manager` shares it.
    pub fn new(home: &Path) -> Self {
        DevLoop {
            manager: PluginManager::new(home),
            home: home.to_path_buf(),
        }
    }

    pub fn manager(&self) -> &PluginManager {
        &self.manager
    }

    /// Dev install options: signature NOT required, but if the package is
    /// dev-signed the dev pubkey is trusted so verification still runs.
    pub fn dev_install_options(&self) -> Result<InstallOptions, LifecycleError> {
        let signer = DevSigner::new(&self.home);
        Ok(InstallOptions {
            require_signature: false,
            trusted_keys: vec![signer.pubkey_hex()?],
            dev_mode: true,
        })
    }

    /// Decide whether a changed source package needs reinstall. Compares the
    /// package manifest's (version, mtime) against the installed copy.
    pub fn check_reload(
        &self,
        plugin_id: &str,
        pkg: &Path,
    ) -> Result<ReloadAction, LifecycleError> {
        let installed_manifest = self
            .manager
            .plugins_dir()
            .join(plugin_id)
            .join("manifest.json");
        if !installed_manifest.exists() {
            return Ok(ReloadAction::Install);
        }
        let src_manifest = pkg.join("manifest.json");
        let src_meta = fs::metadata(&src_manifest)
            .map_err(|_| LifecycleError::Manifest("source manifest.json missing".into()))?;
        let inst_meta = fs::metadata(&installed_manifest)?;
        let src_bytes = fs::read(&src_manifest)?;
        let inst_bytes = fs::read(&installed_manifest)?;
        if src_bytes != inst_bytes {
            return Ok(ReloadAction::Reinstall);
        }
        // Same content but newer mtime → still reinstall (author may have
        // touched binary without changing manifest — compare entry too).
        let entry_changed = self.entry_differs(plugin_id, pkg)?;
        if entry_changed || src_meta.modified()? != inst_meta.modified()? {
            return Ok(ReloadAction::Reinstall);
        }
        Ok(ReloadAction::Unchanged)
    }

    fn entry_differs(&self, plugin_id: &str, pkg: &Path) -> Result<bool, LifecycleError> {
        // Compare every file except manifest.json/signature.* between source
        // and installed trees (shallow — enough for hot reload decisions).
        let inst_dir = self.manager.plugins_dir().join(plugin_id);
        for entry in fs::read_dir(pkg)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if matches!(
                name.as_str(),
                "manifest.json" | "signature.bin" | "signer.pub"
            ) {
                continue;
            }
            let inst = inst_dir.join(&name);
            if !inst.exists() {
                return Ok(true);
            }
            let a = fs::metadata(entry.path())?;
            let b = fs::metadata(&inst)?;
            if a.len() != b.len() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Dev-mode secret gate: only canary/dev names may be provisioned for a
    /// dev plugin. Returns Err for anything that looks like a real credential.
    pub fn assert_dev_secret_name(name: &str) -> Result<(), LifecycleError> {
        let ok = name.starts_with("t3rn:canary:") || name.starts_with("dev:");
        if ok {
            Ok(())
        } else {
            Err(LifecycleError::Manifest(format!(
                "dev mode may only use canary/dev secrets, not {name:?}"
            )))
        }
    }

    /// Provision a canary secret for the dev plugin through the vault.
    /// Refuses non-canary names.
    pub fn provision_dev_secret(
        &self,
        vault: &VaultBroker,
        plugin_id: &str,
        name: &str,
        value: zeroize::Zeroizing<String>,
    ) -> Result<(), LifecycleError> {
        Self::assert_dev_secret_name(name)?;
        let _ = plugin_id;
        vault
            .provision(name, value)
            .map_err(|e| LifecycleError::Manifest(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_lifecycle::PluginManifestLite;

    fn make_pkg(dir: &Path, id: &str) -> PathBuf {
        let pkg = dir.join("src-pkg");
        fs::create_dir_all(&pkg).unwrap();
        let manifest = PluginManifestLite {
            id: id.into(),
            version: "0.1.0".into(),
            name: "Dev Plugin".into(),
            description: String::new(),
            runtime: "process".into(),
            entry: "plugin".into(),
            migrations: vec![],
            permissions_summary: vec![],
            entitlement_account: None,
        };
        fs::write(
            pkg.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let entry = pkg.join("plugin");
        fs::write(&entry, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&entry, fs::Permissions::from_mode(0o755)).unwrap();
        }
        pkg
    }

    #[test]
    fn dev_signer_roundtrip_produces_verifiable_signature() {
        let home = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let pkg = make_pkg(src.path(), "org.dev.sign");
        let signer = DevSigner::new(home.path());
        signer.sign_package(&pkg).unwrap();
        assert!(pkg.join("signature.bin").exists());
        assert!(pkg.join("signer.pub").exists());
        // The dev pubkey verifies through the SAME lifecycle path.
        let mgr = PluginManager::new(home.path());
        let opts = InstallOptions {
            require_signature: true,
            trusted_keys: vec![signer.pubkey_hex().unwrap()],
            dev_mode: false, // signature path fully enforced
        };
        let report = mgr.install(&pkg, &opts).unwrap();
        assert!(report.signed);
        // Key persists across DevSigner instances.
        let signer2 = DevSigner::new(home.path());
        assert_eq!(signer.pubkey_hex().unwrap(), signer2.pubkey_hex().unwrap());
    }

    #[test]
    fn unsigned_dev_install_and_hot_reload_decisions() {
        let home = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let loop_ = DevLoop::new(home.path());
        let pkg = make_pkg(src.path(), "org.dev.hot");
        // Not installed → Install.
        assert_eq!(
            loop_.check_reload("org.dev.hot", &pkg).unwrap(),
            ReloadAction::Install
        );
        let opts = loop_.dev_install_options().unwrap();
        loop_.manager().install(&pkg, &opts).unwrap();
        // Unchanged → Unchanged (allow mtime equality; same bytes).
        std::thread::sleep(std::time::Duration::from_millis(1100));
        // Bump mtime only → Reinstall.
        let f = pkg.join("manifest.json");
        let meta = fs::metadata(&f).unwrap();
        let _ = meta;
        filetime_touch(&f);
        assert_eq!(
            loop_.check_reload("org.dev.hot", &pkg).unwrap(),
            ReloadAction::Reinstall
        );
        // Change binary → Reinstall.
        fs::write(pkg.join("plugin"), b"#!/bin/sh\nexit 1\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(pkg.join("plugin"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(
            loop_.check_reload("org.dev.hot", &pkg).unwrap(),
            ReloadAction::Reinstall
        );
    }

    fn filetime_touch(p: &Path) {
        // Set mtime to now via filetime-free approach: rewrite same bytes.
        let b = fs::read(p).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(p, b).unwrap();
    }

    #[test]
    fn dev_secret_gate_rejects_real_credential_names() {
        assert!(DevLoop::assert_dev_secret_name("t3rn:canary:org.dev.x").is_ok());
        assert!(DevLoop::assert_dev_secret_name("dev:test-key").is_ok());
        for bad in [
            "OPENAI_API_KEY",
            "vault:prod/db",
            "api.key",
            "stripe.secret",
        ] {
            assert!(
                DevLoop::assert_dev_secret_name(bad).is_err(),
                "{bad} must be refused"
            );
        }
    }
}
