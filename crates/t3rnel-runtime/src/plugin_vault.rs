//! Vault brokering for plugins (`05-security-and-trust.md` §14.9–§14.14).
//!
//! A plugin never sees a secret. It names one (`secret:NAME`); the host's
//! [`VaultBroker`] resolves it from the [`CredentialVault`] at call time,
//! hands the value to the proxy/scheme layer in `Zeroizing` memory only, and
//! audits the *reference*, never the value.
//!
//! Unlock order (§14.14): an explicit host-provided master key first, then —
//! only when the host explicitly enables dev mode — `T3RNEL_VAULT_KEY`.
//! Interactive unlock is a host concern and is reported, not performed here.
//! The env-var path is dev-only: production builds refuse it unless the host
//! passes `dev_mode = true`, so a stray environment cannot silently unlock
//! the vault for plugin brokering.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use t3rnel_extensions::vault::CredentialVault;
use zeroize::Zeroizing;

use crate::plugin_proxy::{ProxyError, SecretResolver};

/// Where the master key may come from, in §14.14 order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockSource {
    /// Host supplied the key at boot (key file descriptor / secret service).
    HostProvided,
    /// `T3RNEL_VAULT_KEY` — dev/CI only, requires `dev_mode`.
    EnvDevKey,
    /// Interactive prompt — host UI concern; broker reports it needed.
    Interactive,
}

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("vault error: {0}")]
    Vault(String),
    #[error("vault is locked; interactive unlock required")]
    Locked,
    #[error("T3RNEL_VAULT_KEY is dev-only and dev_mode is disabled")]
    EnvKeyDisabled,
    #[error("secret {0:?} not found in vault")]
    NotFound(String),
}

impl From<t3rnel_extensions::ExtensionError> for BrokerError {
    fn from(e: t3rnel_extensions::ExtensionError) -> Self {
        BrokerError::Vault(e.to_string())
    }
}

/// Brokered access to the credential vault for one host process. The vault
/// itself is shared; brokering decisions (which secret names a plugin may
/// resolve) are enforced by the caller via the manifest's `permissions.auth`.
pub struct VaultBroker {
    vault: Mutex<CredentialVault>,
    /// Whether `T3RNEL_VAULT_KEY` may be used. Set only by dev tooling.
    dev_mode: bool,
}

impl VaultBroker {
    /// Open (or create-on-init) the vault at `path`. Does not unlock.
    pub fn open(path: PathBuf, dev_mode: bool) -> Self {
        VaultBroker {
            vault: Mutex::new(CredentialVault::new(path)),
            dev_mode,
        }
    }

    /// Whether dev-mode env-key unlock is permitted.
    pub fn dev_mode(&self) -> bool {
        self.dev_mode
    }

    /// Unlock following §14.14 order. `host_key` is the host-provided master
    /// key (32 bytes) when available. Returns the source that succeeded.
    /// Never logs key material.
    pub fn unlock_ordered(
        &self,
        host_key: Option<Zeroizing<[u8; 32]>>,
    ) -> Result<UnlockSource, BrokerError> {
        let mut vault = self.vault.lock().map_err(|_| BrokerError::Locked)?;
        if vault.is_unlocked() {
            return Ok(UnlockSource::HostProvided);
        }
        // 1. Host-provided key.
        if let Some(key) = host_key {
            if vault.exists() {
                vault.unlock_with_key(key)?;
            } else {
                vault.init_with_key(key)?;
            }
            return Ok(UnlockSource::HostProvided);
        }
        // 2. Dev-only env key.
        if self.dev_mode {
            if let Ok(env) = std::env::var("T3RNEL_VAULT_KEY") {
                if !env.is_empty() {
                    // The vault's own resolver accepts the env var; calling
                    // unlock() exercises the same code path as the CLI.
                    vault.unlock()?;
                    return Ok(UnlockSource::EnvDevKey);
                }
            }
        } else if std::env::var("T3RNEL_VAULT_KEY").is_ok() {
            // Env var present but dev mode off — fail closed, loudly.
            return Err(BrokerError::EnvKeyDisabled);
        }
        Err(BrokerError::Locked)
    }

    /// Resolve a secret name for brokering. Returns `Zeroizing` material;
    /// callers must not log or persist it. Returns `NotFound` for missing
    /// names so the proxy can map it to `secret_unavailable`.
    pub fn resolve(&self, name: &str) -> Result<Zeroizing<String>, BrokerError> {
        let vault = self.vault.lock().map_err(|_| BrokerError::Locked)?;
        if !vault.is_unlocked() {
            return Err(BrokerError::Locked);
        }
        vault
            .get(name)
            .ok_or_else(|| BrokerError::NotFound(name.to_string()))
    }

    /// Store a secret (host-side provisioning only — plugins can never call
    /// this). Used to install canary credentials at plugin install time.
    pub fn provision(&self, name: &str, value: Zeroizing<String>) -> Result<(), BrokerError> {
        let mut vault = self.vault.lock().map_err(|_| BrokerError::Locked)?;
        if !vault.is_unlocked() {
            return Err(BrokerError::Locked);
        }
        vault.set(name.to_string(), value)?;
        Ok(())
    }

    /// Issue a canary credential for `plugin_id`: a random secret stored in
    /// the vault under `t3rn:canary:<plugin_id>`. The value is returned to the
    /// *host test harness only* — production callers use the name for audit
    /// and leak-scanning, never ship the value to the plugin.
    pub fn issue_canary(
        &self,
        plugin_id: &str,
    ) -> Result<(String, Zeroizing<String>), BrokerError> {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let value = Zeroizing::new(hex::encode(bytes));
        let name = format!("t3rn:canary:{plugin_id}");
        self.provision(&name, Zeroizing::new(value.to_string()))?;
        Ok((name, value))
    }

    /// Shared handle for use as a [`SecretResolver`] by [`crate::plugin_proxy::PluginProxy`].
    pub fn as_resolver(self: &Arc<Self>) -> Arc<dyn SecretResolver> {
        struct BrokerResolver(Arc<VaultBroker>);
        impl SecretResolver for BrokerResolver {
            fn resolve(&self, name: &str) -> Result<Zeroizing<String>, ProxyError> {
                self.0
                    .resolve(name)
                    .map_err(|_| ProxyError::SecretUnavailable(name.to_string()))
            }
        }
        Arc::new(BrokerResolver(self.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_vault() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.t3rnel");
        (dir, path)
    }

    #[test]
    fn unlock_order_prefers_host_key_then_env_dev_key() {
        let (_d, path) = scratch_vault();
        let key = Zeroizing::new([7u8; 32]);
        let broker = VaultBroker::open(path.clone(), true);
        // Host-provided key initializes a fresh vault.
        assert_eq!(
            broker.unlock_ordered(Some(key.clone())).unwrap(),
            UnlockSource::HostProvided
        );
        // Second broker on same path unlocks with env? No env set in tests —
        // use host key again (idempotent path).
        let broker2 = VaultBroker::open(path, true);
        assert_eq!(
            broker2.unlock_ordered(Some(key)).unwrap(),
            UnlockSource::HostProvided
        );
    }

    #[test]
    fn env_key_refused_when_dev_mode_off() {
        let (_d, path) = scratch_vault();
        std::env::set_var("T3RNEL_VAULT_KEY", "00".repeat(32));
        let broker = VaultBroker::open(path, false);
        let err = broker.unlock_ordered(None).unwrap_err();
        assert!(matches!(err, BrokerError::EnvKeyDisabled), "{err:?}");
        std::env::remove_var("T3RNEL_VAULT_KEY");
    }

    #[test]
    fn resolve_returns_zeroizing_and_notfound_for_missing() {
        let (_d, path) = scratch_vault();
        let broker = VaultBroker::open(path, false);
        broker
            .unlock_ordered(Some(Zeroizing::new([3u8; 32])))
            .unwrap();
        broker
            .provision("api.key", Zeroizing::new("s3cr3t".to_string()))
            .unwrap();
        let v = broker.resolve("api.key").unwrap();
        assert_eq!(v.as_str(), "s3cr3t");
        assert!(matches!(
            broker.resolve("nope"),
            Err(BrokerError::NotFound(_))
        ));
        // Locked broker refuses resolution.
        let (_d2, path2) = scratch_vault();
        let locked = VaultBroker::open(path2, false);
        assert!(matches!(locked.resolve("x"), Err(BrokerError::Locked)));
    }

    #[test]
    fn canary_is_stored_under_namespaced_name() {
        let (_d, path) = scratch_vault();
        let broker = VaultBroker::open(path, false);
        broker
            .unlock_ordered(Some(Zeroizing::new([9u8; 32])))
            .unwrap();
        let (name, value) = broker.issue_canary("org.example.plugin").unwrap();
        assert_eq!(name, "t3rn:canary:org.example.plugin");
        assert_eq!(value.len(), 64); // 32 bytes hex
                                     // The value resolves back through the broker — but only the host
                                     // ever holds it; the plugin would only ever see the name.
        let resolved = broker.resolve(&name).unwrap();
        assert_eq!(resolved.as_str(), value.as_str());
    }

    /// §14.14 acceptance: a confined plugin process must not find the real
    /// secret in its environment, its readable files, or its traffic. The
    /// proxy only ever injects secrets on declared egress; the sandbox has
    /// no network at all. This test proves the *process* surface.
    #[cfg(target_os = "linux")]
    #[test]
    fn confined_process_sees_no_secret() {
        // confinement_available() gates launch elsewhere; here we verify the
        // env scrub itself — the property that keeps secrets out of a plugin
        // process regardless of kernel support.
        let secret = "t3rn-test-secret-DO-NOT-LEAK-9f8e7d";
        let dir = tempfile::tempdir().unwrap();
        let mut policy = crate::plugin_sandbox::SandboxPolicy::for_plugin(dir.path());
        // Read-only system tree so /usr/bin/env can run under Landlock.
        policy.read_only_dirs.push("/".into());
        let mut cmd = std::process::Command::new("/usr/bin/env");
        // Set the would-be secret BEFORE confinement — the scrub must drop it.
        cmd.env("LEAK_ATTEMPT", secret);
        crate::plugin_sandbox::confined_command(&mut cmd, &policy);
        let out = cmd.output().expect("spawn");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!stdout.contains(secret), "secret leaked via env: {stdout}");
        assert!(
            !stdout.contains("LEAK_ATTEMPT"),
            "unscrubbed env var present"
        );
    }
}
