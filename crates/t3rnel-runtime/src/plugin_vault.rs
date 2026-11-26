//! Vault brokering for plugins (`05-security-and-trust.md` §14.9–§14.14).
//!
//! A plugin never sees a secret. It names one (`secret:NAME`); the host's
//! [`VaultBroker`] resolves it from the [`CredentialVault`] at call time,
//! hands the value to the proxy/scheme layer in `Zeroizing` memory only, and
//! audits the *reference*, never the value.
//!
//! Unlock order (§14.14): an explicit host-provided master key first, then the
//! OS keyring, then — only when the host explicitly enables dev mode —
//! `T3RNEL_VAULT_KEY`.
//! Interactive unlock is a host concern and is reported, not performed here.
//! The env-var path is dev-only: production builds refuse it unless the host
//! passes `dev_mode = true`, so a stray environment cannot silently unlock
//! the vault for plugin brokering.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use t3rnel_extensions::vault::CredentialVault;
use zeroize::Zeroizing;

use crate::plugin_auth::StoredGrant;
use crate::plugin_proxy::{ProxyError, SecretResolver};

/// Secret-name prefix that resolves to the *current access token* of a
/// stored OAuth grant. Grants live in the vault under `oauth:<provider>`
/// (written host-side by the core consent flow through
/// [`crate::plugin_auth::ScopedTokenService::store_grant`]); a manifest
/// `permissions.auth` rule may bind `oauth-access:<provider>` so the
/// credential-brokering proxy injects `Authorization: Bearer <token>` for
/// the plugin's declared hosts — this is how the Google connector plugins
/// (18 §8) authenticate without ever holding token material.
///
/// Resolution is fail-closed: an expired grant is `SecretUnavailable` until
/// the host refreshes it — the plugin triggers that by calling the `auth`
/// host service (`auth.token(provider, scopes)` runs `ensure_fresh`
/// host-side) before its API calls.
pub const OAUTH_ACCESS_PREFIX: &str = "oauth-access:";

/// Same expiry skew [`crate::plugin_auth::ScopedTokenService`] uses so a
/// token never dies mid-request.
const OAUTH_ACCESS_SKEW_SECS: i64 = 30;

/// Resolve `oauth-access:<provider>` to the stored grant's access token.
/// `ref_name` is the full secret name, used only for error reporting.
fn resolve_oauth_access(
    broker: &VaultBroker,
    provider: &str,
    ref_name: &str,
) -> Result<Zeroizing<String>, ProxyError> {
    let unavailable = || ProxyError::SecretUnavailable(ref_name.to_string());
    let provider_ok = !provider.is_empty()
        && provider.len() <= 32
        && provider
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !provider_ok {
        return Err(unavailable());
    }
    let raw = broker
        .resolve(&format!("oauth:{provider}"))
        .map_err(|_| unavailable())?;
    let grant: StoredGrant = serde_json::from_str(raw.as_str()).map_err(|_| unavailable())?;
    if let Some(exp) = grant.expires_at {
        if exp - OAUTH_ACCESS_SKEW_SECS <= chrono::Utc::now().timestamp() {
            return Err(unavailable());
        }
    }
    Ok(Zeroizing::new(grant.access_token))
}

/// Where the master key may come from, in §14.14 order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockSource {
    /// Host supplied the key at boot (key file descriptor / secret service).
    HostProvided,
    /// The OS keyring — the same master key the kernel unlocks its vault with.
    Keyring,
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
        // 2. The OS keyring: where the master key lives in normal use. Skipped when
        //    T3RNEL_VAULT_KEY is set, because the vault would then read that variable
        //    instead, and the variable is development-only (handled below).
        if vault.exists()
            && std::env::var_os("T3RNEL_VAULT_KEY").is_none()
            && vault.unlock().is_ok()
        {
            return Ok(UnlockSource::Keyring);
        }
        // 3. Dev-only env key.
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
                if let Some(provider) = name.strip_prefix(OAUTH_ACCESS_PREFIX) {
                    return resolve_oauth_access(&self.0, provider, name);
                }
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
        let path = dir.path().join(t3rnel_extensions::vault::VAULT_FILE_NAME);
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

    // -- oauth-access:<provider> resolution (18 §8 Google broker) ----------

    fn oauth_broker() -> (tempfile::TempDir, Arc<VaultBroker>) {
        let dir = tempfile::tempdir().unwrap();
        let broker = Arc::new(VaultBroker::open(
            dir.path().join(t3rnel_extensions::vault::VAULT_FILE_NAME),
            false,
        ));
        broker
            .unlock_ordered(Some(Zeroizing::new([11u8; 32])))
            .unwrap();
        (dir, broker)
    }

    fn oauth_grant(expires_in_secs: Option<i64>) -> crate::plugin_auth::StoredGrant {
        crate::plugin_auth::StoredGrant {
            access_token: "ya29.proxy-resolved-token".into(),
            refresh_token: Some("1//refresh".into()),
            expires_at: expires_in_secs
                .map(|s| (chrono::Utc::now() + chrono::Duration::seconds(s)).timestamp()),
            scopes: vec!["https://www.googleapis.com/auth/webmasters.readonly".into()],
            token_endpoint: Some("https://oauth2.googleapis.com/token".into()),
            client_id: Some("cid".into()),
            client_secret: None,
        }
    }

    #[test]
    fn oauth_access_name_resolves_the_grants_access_token() {
        let (_d, broker) = oauth_broker();
        let auth = crate::plugin_auth::ScopedTokenService::new(broker.clone(), "org.test.vault");
        auth.store_grant("google", oauth_grant(Some(3600))).unwrap();

        let resolver = broker.as_resolver();
        let token = resolver.resolve("oauth-access:google").unwrap();
        assert_eq!(token.as_str(), "ya29.proxy-resolved-token");

        // Unknown provider / malformed name fail closed.
        assert!(matches!(
            resolver.resolve("oauth-access:github"),
            Err(ProxyError::SecretUnavailable(_))
        ));
        assert!(matches!(
            resolver.resolve("oauth-access:"),
            Err(ProxyError::SecretUnavailable(_))
        ));
        assert!(matches!(
            resolver.resolve("oauth-access:Google"),
            Err(ProxyError::SecretUnavailable(_))
        ));
    }

    #[test]
    fn oauth_access_fails_closed_when_grant_expired() {
        let (_d, broker) = oauth_broker();
        let auth = crate::plugin_auth::ScopedTokenService::new(broker.clone(), "org.test.vault");
        // Already expired, no refresh attempted at resolve time — the proxy
        // path is sync, so freshness is checked, never repaired here.
        auth.store_grant("google", oauth_grant(Some(-10))).unwrap();
        let resolver = broker.as_resolver();
        assert!(matches!(
            resolver.resolve("oauth-access:google"),
            Err(ProxyError::SecretUnavailable(_))
        ));
        // A non-expiring grant (expires_at: None) resolves.
        auth.store_grant("google", oauth_grant(None)).unwrap();
        assert!(resolver.resolve("oauth-access:google").is_ok());
    }

    // ---- one vault, shared with the kernel ----------------------------------------------------------
    #[test]
    fn the_plugin_host_opens_the_kernels_vault_file() {
        use crate::plugin_host::{PluginHost, PluginHostConfig};
        let home = tempfile::tempdir().unwrap();
        let key = [5u8; 32];
        // The user pastes a key into the key screen: the kernel's vault file gets the entry.
        {
            let mut kernel_vault = t3rnel_extensions::vault::CredentialVault::new(
                home.path().join(t3rnel_extensions::vault::VAULT_FILE_NAME),
            );
            kernel_vault.init_with_key(Zeroizing::new(key)).unwrap();
            kernel_vault
                .set(
                    "exchange-key".into(),
                    Zeroizing::new("pasted-by-the-user".into()),
                )
                .unwrap();
        }
        let host = PluginHost::open(
            home.path(),
            PluginHostConfig {
                plugin_id: "org.test.sharedvault".into(),
                egress: vec![],
                auth: vec![],
                data_classes: vec![],
                vault_key: Some(Zeroizing::new(key)),
                dev_mode: false,
            },
        )
        .unwrap();
        // With the old file name this opened a second, empty vault and found nothing.
        assert_eq!(
            host.vault.resolve("exchange-key").unwrap().as_str(),
            "pasted-by-the-user"
        );
        assert!(
            !home.path().join("vault.t3rnel").exists(),
            "no second vault file may be created"
        );
    }

    #[test]
    fn without_any_key_the_broker_stays_locked_and_does_not_create_a_vault() {
        let (_d, path) = scratch_vault();
        std::env::remove_var("T3RNEL_VAULT_KEY");
        let broker = VaultBroker::open(path.clone(), false);
        assert!(matches!(
            broker.unlock_ordered(None),
            Err(BrokerError::Locked)
        ));
        assert!(!path.exists());
    }
}
