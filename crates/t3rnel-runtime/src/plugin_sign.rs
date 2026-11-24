//! Release plugin package signing (`17-implementation-guide.md` §9.7, §14.11).
//!
//! This is the *signing* half of the plugin pipeline — the counterpart to
//! [`crate::plugin_lifecycle::PluginManager`], which only verifies. It turns a
//! plugin source directory (the layout reference plugins use: `manifest.yaml`
//! plus entry files) into the installable package layout the lifecycle
//! expects:
//!
//! ```text
//! <out>/manifest.json     — PluginManifestLite (JSON) the verifier parses
//! <out>/signature.bin     — ed25519 signature over the manifest.json bytes
//! <out>/signer.pub        — signer pubkey, hex-encoded 32 bytes
//! <out>/<entry>           — payload files copied from the source dir
//! ```
//!
//! Signing keys are ordinary ed25519 seed files (32 raw bytes, mode 0600)
//! plus a `.pub` hex file — the same on-disk shape [`crate::plugin_dev::DevSigner`]
//! uses under `dev-keys/`, but release keys live OUTSIDE any T3rnel home so a
//! home wipe cannot destroy them.
//!
//! Account binding: pass `account_home` (the target machine's T3rnel home) to
//! [`package_plugin`] and the manifest's `entitlement_account` is set to
//! [`crate::plugin_lifecycle::local_plugin_account_fingerprint`] BEFORE
//! signing, so the binding is covered by the signature and cannot be stripped.
//!
//! Release-key CUSTODY (isolated signer, TUF root, transparency log — guide
//! §14.11) is still future work; this module only proves the sign → verify →
//! install pipeline end to end.

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;

use crate::plugin_lifecycle::{
    local_plugin_account_fingerprint, LifecycleError, PluginManifestLite,
};

/// Error type for the signing pipeline. Wraps [`LifecycleError`] so callers
/// can treat build/sign failures uniformly with install failures.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad source manifest: {0}")]
    Manifest(String),
    #[error("lifecycle error: {0}")]
    Lifecycle(#[from] LifecycleError),
}

/// What [`package_plugin`] produced.
#[derive(Debug, Clone)]
pub struct PackageReport {
    pub plugin_id: String,
    pub version: String,
    pub package_dir: PathBuf,
    /// Hex pubkey of the signer — this is what goes into
    /// `plugin_trusted_signers` in config.toml.
    pub signer_pubkey: String,
    /// True when the manifest was bound to `account_home`'s fingerprint.
    pub account_bound: bool,
}

/// A loaded or freshly generated ed25519 release signing key.
pub struct ReleaseSigner {
    sk: SigningKey,
}

impl ReleaseSigner {
    /// Generate a new keypair and persist it under `key_dir`:
    /// `release-signing.key` (32-byte seed, mode 0600) and
    /// `release-signing.pub` (hex pubkey). Returns the signer.
    pub fn generate(key_dir: &Path) -> Result<Self, SignError> {
        fs::create_dir_all(key_dir)?;
        let key_path = key_dir.join("release-signing.key");
        let pub_path = key_dir.join("release-signing.pub");
        if key_path.exists() {
            return Err(SignError::Manifest(format!(
                "refusing to overwrite existing release key {}",
                key_path.display()
            )));
        }
        let mut seed = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut seed);
        fs::write(&key_path, seed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
        }
        let sk = SigningKey::from_bytes(&seed);
        fs::write(&pub_path, hex::encode(sk.verifying_key().to_bytes()))?;
        Ok(ReleaseSigner { sk })
    }

    /// Load a signing key from a 32-byte seed file.
    pub fn load(key_path: &Path) -> Result<Self, SignError> {
        let bytes = fs::read(key_path)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            SignError::Manifest(format!("{} is not a 32-byte seed", key_path.display()))
        })?;
        Ok(ReleaseSigner {
            sk: SigningKey::from_bytes(&arr),
        })
    }

    /// Hex-encoded verifying key — the value for `plugin_trusted_signers`.
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.sk.verifying_key().to_bytes())
    }

    /// Write `signature.bin` + `signer.pub` into an already-built package
    /// directory, signing the exact `manifest.json` bytes on disk.
    pub fn sign_package_dir(&self, pkg: &Path) -> Result<(), SignError> {
        let manifest_bytes = fs::read(pkg.join("manifest.json"))
            .map_err(|_| SignError::Manifest("manifest.json missing".into()))?;
        let sig = self.sk.sign(&manifest_bytes);
        fs::write(pkg.join("signature.bin"), sig.to_bytes())?;
        fs::write(pkg.join("signer.pub"), self.pubkey_hex())?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Source manifest (the layout reference plugins ship: manifest.yaml)
// ---------------------------------------------------------------------------

/// The plugin source manifest schema — `manifest.yaml` at the root of a
/// plugin source directory. Strict: unknown keys are rejected so a field the
/// signer does not understand can never be silently dropped from the signed
/// package.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceManifest {
    id: String,
    name: String,
    version: String,
    #[serde(default)]
    description: String,
    plugin: SourcePlugin,
    #[serde(default)]
    targets: Vec<String>,
    /// Entry file inside the package (default `plugin`).
    #[serde(default = "default_source_entry")]
    entry: String,
    #[serde(default)]
    permissions: SourcePermissions,
    #[serde(default)]
    requires: SourceRequires,
    /// Accepted but not carried into the lite manifest — non-secret settings
    /// schema is enforced by the bridge/host, not the lifecycle.
    #[serde(default)]
    #[allow(dead_code)]
    config_schema: Option<serde_yaml::Value>,
}

fn default_source_entry() -> String {
    "plugin".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePlugin {
    /// "process" | "wasm" — maps to PluginManifestLite.runtime.
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    #[allow(dead_code)]
    min_t3rnel_version: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePermissions {
    #[serde(default)]
    auth: Vec<SourceAuthRule>,
    #[serde(default)]
    data_classes: Vec<String>,
    #[serde(default)]
    local: Vec<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceAuthRule {
    secret: String,
    scheme: String,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRequires {
    /// `host_services` may be a list (reference plugins) — kept as a list.
    #[serde(default)]
    host_services: Vec<String>,
}

fn runtime_for(kind: &str) -> Result<String, SignError> {
    match kind {
        "process" => Ok("process".into()),
        "wasm" => Ok("wasm".into()),
        other => Err(SignError::Manifest(format!(
            "unsupported plugin.type {other:?} (expected \"process\" or \"wasm\")"
        ))),
    }
}

fn permissions_summary(src: &SourceManifest) -> Vec<String> {
    let mut lines = Vec::new();
    for rule in &src.permissions.auth {
        let scope = match (rule.methods.is_empty(), rule.paths.is_empty()) {
            (true, true) => String::new(),
            (false, true) => format!(" {}", rule.methods.join(",")),
            (true, false) => format!(" {}", rule.paths.join(",")),
            (false, false) => format!(" {} {}", rule.methods.join(","), rule.paths.join(",")),
        };
        lines.push(format!(
            "auth: {} via {} → {}{}",
            rule.secret,
            rule.scheme,
            if rule.hosts.is_empty() {
                "(any host)".to_string()
            } else {
                rule.hosts.join(", ")
            },
            scope
        ));
    }
    if !src.permissions.data_classes.is_empty() {
        lines.push(format!(
            "data classes: {}",
            src.permissions.data_classes.join(", ")
        ));
    }
    if !src.permissions.local.is_empty() {
        lines.push(format!("local brokers: {}", src.permissions.local.len()));
    }
    if !src.requires.host_services.is_empty() {
        lines.push(format!(
            "requires host services: {}",
            src.requires.host_services.join(", ")
        ));
    }
    if !src.targets.is_empty() {
        lines.push(format!("targets: {}", src.targets.join(", ")));
    }
    lines
}

// ---------------------------------------------------------------------------
// Package build + sign
// ---------------------------------------------------------------------------

/// Files/dirs never copied into a package: manifests are regenerated, signing
/// artefacts are produced by the signer, and interpreter caches are dev junk.
fn is_payload_excluded(rel: &Path) -> bool {
    let name = rel.file_name().map(|n| n.to_string_lossy().to_string());
    let Some(name) = name else { return true };
    matches!(
        name.as_str(),
        "manifest.yaml" | "manifest.json" | "signature.bin" | "signer.pub"
    ) || name == "__pycache__"
        || name.ends_with(".pyc")
        || name.starts_with(".git")
}

fn copy_payload(src: &Path, dst: &Path) -> Result<(), SignError> {
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if is_payload_excluded(Path::new(&name)) {
            continue;
        }
        let ty = entry.file_type()?;
        let to = dst.join(&name);
        if ty.is_dir() {
            copy_dir_filtered(&entry.path(), &to)?;
        } else if ty.is_file() || ty.is_symlink() {
            fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

fn copy_dir_filtered(src: &Path, dst: &Path) -> Result<(), SignError> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if is_payload_excluded(Path::new(&name)) {
            continue;
        }
        let ty = entry.file_type()?;
        let to = dst.join(&name);
        if ty.is_dir() {
            copy_dir_filtered(&entry.path(), &to)?;
        } else if ty.is_file() || ty.is_symlink() {
            fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

/// Build an unsigned package directory from a plugin source dir:
/// parses `manifest.yaml`, writes `manifest.json`, copies payload files,
/// marks the entry executable. Does NOT write signature.bin/signer.pub —
/// call [`ReleaseSigner::sign_package_dir`] (or [`package_plugin`]) for that.
pub fn build_package(src: &Path, dst: &Path) -> Result<PluginManifestLite, SignError> {
    let yaml_path = src.join("manifest.yaml");
    let yaml = fs::read_to_string(&yaml_path)
        .map_err(|_| SignError::Manifest(format!("{} missing", yaml_path.display())))?;
    let src_manifest: SourceManifest = serde_yaml::from_str(&yaml)
        .map_err(|e| SignError::Manifest(format!("{}: {e}", yaml_path.display())))?;

    let lite = PluginManifestLite {
        id: src_manifest.id.clone(),
        version: src_manifest.version.clone(),
        name: src_manifest.name.clone(),
        description: src_manifest.description.clone(),
        runtime: runtime_for(&src_manifest.plugin.kind)?,
        entry: src_manifest.entry.clone(),
        migrations: Vec::new(),
        permissions_summary: permissions_summary(&src_manifest),
        entitlement_account: None,
    };

    if dst.exists() {
        fs::remove_dir_all(dst)?;
    }
    fs::create_dir_all(dst)?;
    let manifest_bytes =
        serde_json::to_vec_pretty(&lite).map_err(|e| SignError::Manifest(e.to_string()))?;
    fs::write(dst.join("manifest.json"), &manifest_bytes)?;
    copy_payload(src, dst)?;

    // The lifecycle health-check requires the entry to be executable for
    // non-wasm runtimes. Source trees may not carry the bit (e.g. a fresh
    // checkout); the packaged copy must.
    if lite.runtime != "wasm" {
        let entry_path = dst.join(&lite.entry);
        if !entry_path.exists() {
            return Err(SignError::Manifest(format!(
                "entry {:?} not found in package payload",
                lite.entry
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&entry_path)?.permissions();
            perms.set_mode(perms.mode() | 0o111);
            fs::set_permissions(&entry_path, perms)?;
        }
    }
    Ok(lite)
}

/// Full pipeline: build the package from `src` into `dst`, optionally bind it
/// to the account fingerprint of `account_home`, then sign with `signer`.
/// Returns what was produced.
pub fn package_plugin(
    src: &Path,
    dst: &Path,
    signer: &ReleaseSigner,
    account_home: Option<&Path>,
) -> Result<PackageReport, SignError> {
    // Bind BEFORE writing manifest.json so the fingerprint is inside the
    // signed bytes.
    let account = match account_home {
        Some(home) => Some(local_plugin_account_fingerprint(home)?),
        None => None,
    };

    // Re-read source manifest to inject the binding into the lite manifest.
    let lite = build_package(src, dst)?;
    let lite = if let Some(fp) = account {
        let mut m = lite;
        m.entitlement_account = Some(fp);
        let bytes =
            serde_json::to_vec_pretty(&m).map_err(|e| SignError::Manifest(e.to_string()))?;
        fs::write(dst.join("manifest.json"), &bytes)?;
        m
    } else {
        lite
    };

    signer.sign_package_dir(dst)?;
    Ok(PackageReport {
        plugin_id: lite.id,
        version: lite.version,
        package_dir: dst.to_path_buf(),
        signer_pubkey: signer.pubkey_hex(),
        account_bound: lite.entitlement_account.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_lifecycle::{InstallOptions, PluginManager};

    const SRC_YAML: &str = r#"
id: "org.test.sign"
name: "Sign Test"
version: "0.1.0"
description: "pipeline proof"
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
  host_services: ["storage"]
"#;

    fn make_src(dir: &Path) -> PathBuf {
        let src = dir.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("manifest.yaml"), SRC_YAML).unwrap();
        fs::write(src.join("plugin"), b"#!/bin/sh\nexit 0\n").unwrap();
        fs::write(src.join("test_plugin.py"), b"# dev-only, still payload\n").unwrap();
        fs::create_dir_all(src.join("__pycache__")).unwrap();
        fs::write(src.join("__pycache__/x.pyc"), b"junk").unwrap();
        src
    }

    fn key_dir(dir: &Path) -> PathBuf {
        let d = dir.join("keys");
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn package_build_sign_install_roundtrip_dev_mode_off() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let src = make_src(tmp.path());
        let dst = tmp.path().join("pkg");
        let signer = ReleaseSigner::generate(&key_dir(tmp.path())).unwrap();

        let report = package_plugin(&src, &dst, &signer, Some(&home)).unwrap();
        assert_eq!(report.plugin_id, "org.test.sign");
        assert!(report.account_bound);
        assert!(dst.join("signature.bin").exists());
        assert!(dst.join("signer.pub").exists());
        assert!(dst.join("manifest.json").exists());
        assert!(dst.join("plugin").exists());
        assert!(!dst.join("manifest.yaml").exists());
        assert!(!dst.join("__pycache__").exists());

        // dev_mode OFF, require_signature ON, trusted_keys = release pubkey.
        let mgr = PluginManager::new(&home);
        let opts = InstallOptions {
            require_signature: true,
            trusted_keys: vec![signer.pubkey_hex()],
            dev_mode: false,
        };
        let install = mgr.install(&dst, &opts).unwrap();
        assert!(install.signed);
        assert!(install.account_bound);
        assert!(!install.dev_mode);
        assert_eq!(
            install.signer.as_deref(),
            Some(signer.pubkey_hex().as_str())
        );
    }

    #[test]
    fn tampered_manifest_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let src = make_src(tmp.path());
        let dst = tmp.path().join("pkg");
        let signer = ReleaseSigner::generate(&key_dir(tmp.path())).unwrap();
        package_plugin(&src, &dst, &signer, Some(&home)).unwrap();

        // Tamper: bump version inside the signed manifest bytes.
        let mpath = dst.join("manifest.json");
        let mut m: serde_json::Value = serde_json::from_slice(&fs::read(&mpath).unwrap()).unwrap();
        m["version"] = serde_json::json!("9.9.9");
        fs::write(&mpath, serde_json::to_vec(&m).unwrap()).unwrap();

        let mgr = PluginManager::new(&home);
        let opts = InstallOptions {
            require_signature: true,
            trusted_keys: vec![signer.pubkey_hex()],
            dev_mode: false,
        };
        let err = mgr.install(&dst, &opts).unwrap_err();
        assert!(matches!(err, LifecycleError::Signature(_)), "got {err:?}");
    }

    #[test]
    fn unsigned_package_is_rejected_when_signature_required() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let src = make_src(tmp.path());
        let dst = tmp.path().join("pkg");
        build_package(&src, &dst).unwrap(); // no signature.bin / signer.pub

        let mgr = PluginManager::new(&home);
        let opts = InstallOptions {
            require_signature: true,
            trusted_keys: vec![],
            dev_mode: false,
        };
        let err = mgr.install(&dst, &opts).unwrap_err();
        assert!(matches!(err, LifecycleError::Signature(_)), "got {err:?}");
    }

    #[test]
    fn wrong_account_home_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let home_a = tmp.path().join("home-a");
        let home_b = tmp.path().join("home-b");
        let src = make_src(tmp.path());
        let dst = tmp.path().join("pkg");
        let signer = ReleaseSigner::generate(&key_dir(tmp.path())).unwrap();
        // Bound to home A's fingerprint.
        package_plugin(&src, &dst, &signer, Some(&home_a)).unwrap();

        // Install into home B — signature is valid, binding must fail.
        let mgr_b = PluginManager::new(&home_b);
        let opts = InstallOptions {
            require_signature: true,
            trusted_keys: vec![signer.pubkey_hex()],
            dev_mode: false,
        };
        let err = mgr_b.install(&dst, &opts).unwrap_err();
        assert!(matches!(err, LifecycleError::AccountBinding), "got {err:?}");

        // Same package installs fine on the bound home.
        let mgr_a = PluginManager::new(&home_a);
        let report = mgr_a.install(&dst, &opts).unwrap();
        assert!(report.account_bound);
    }

    #[test]
    fn untrusted_signer_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let src = make_src(tmp.path());
        let dst = tmp.path().join("pkg");
        let signer = ReleaseSigner::generate(&key_dir(tmp.path())).unwrap();
        let other_dir = tmp.path().join("other-keys");
        fs::create_dir_all(&other_dir).unwrap();
        let other = ReleaseSigner::generate(&other_dir).unwrap();
        package_plugin(&src, &dst, &signer, Some(&home)).unwrap();

        let mgr = PluginManager::new(&home);
        let opts = InstallOptions {
            require_signature: true,
            trusted_keys: vec![other.pubkey_hex()], // wrong key trusted
            dev_mode: false,
        };
        let err = mgr.install(&dst, &opts).unwrap_err();
        assert!(matches!(err, LifecycleError::Signature(_)), "got {err:?}");
    }

    #[test]
    fn keygen_refuses_overwrite_and_load_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let kd = key_dir(tmp.path());
        let s1 = ReleaseSigner::generate(&kd).unwrap();
        assert!(ReleaseSigner::generate(&kd).is_err());
        let key_path = kd.join("release-signing.key");
        let s2 = ReleaseSigner::load(&key_path).unwrap();
        assert_eq!(s1.pubkey_hex(), s2.pubkey_hex());
    }

    #[test]
    fn bad_yaml_and_missing_entry_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("manifest.yaml"), "id: [unclosed\n").unwrap();
        assert!(build_package(&src, &tmp.path().join("p1")).is_err());

        // Valid yaml, entry missing from payload.
        fs::write(
            src.join("manifest.yaml"),
            SRC_YAML.replace("entry: \"plugin\"", "entry: \"nope\""),
        )
        .unwrap();
        assert!(build_package(&src, &tmp.path().join("p2")).is_err());
    }
}
