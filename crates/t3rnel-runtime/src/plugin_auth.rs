//! Scoped-token auth host service (`docs/sections/18 §8` — the generalized
//! `auth.google.token(scope=…)` pattern as `auth.token(provider, scope)`).
//!
//! Core owns the OAuth consent flow once (t3rnel-extensions `oauth.rs`);
//! providers' grants live in the credential vault. A plugin asks for a
//! **scoped, short-lived** token and receives only an opaque `authref:` —
//! never the access token value across the plugin boundary in the normal
//! path, and **never** a refresh token. The credential-brokering proxy (or
//! any host-side caller) resolves the reference back to token material via
//! [`ScopedTokenService::resolve`].
//!
//! Rules enforced here:
//! - a token reference is authenticated: it carries an HMAC (key held only by
//!   this service) over provider, scopes, expiry and the plugin it was issued
//!   to, so a plugin cannot forge a reference, widen its scopes, extend its
//!   expiry, or use one minted for another plugin;
//! - requested scopes must be a subset of the stored grant's scopes;
//! - TTL is caller-bounded (default 300s, hard max 3600s) and further capped
//!   at the grant's own expiry;
//! - an expired grant is refreshed through its stored token endpoint when a
//!   refresh token exists — the refresh token never leaves the vault;
//! - every issue/resolve is a host-side decision; plugins cannot mint,
//!   widen, or renew anything themselves.

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::plugin_vault::{BrokerError, VaultBroker};

/// Default scoped-token lifetime.
const DEFAULT_TTL_SECS: u64 = 300;
/// Hard cap on scoped-token lifetime.
const MAX_TTL_SECS: u64 = 3600;
/// Refresh this far before expiry so a token never dies mid-request.
const EXPIRY_SKEW_SECS: i64 = 30;

const VAULT_PREFIX: &str = "oauth:";
const REF_PREFIX: &str = "authref:v2:";
/// Deadline for a token-endpoint refresh.
const REFRESH_TIMEOUT_SECS: u64 = 20;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid provider name {0:?}")]
    BadProvider(String),
    #[error("invalid scope {0:?}")]
    BadScope(String),
    #[error("provider {0:?} has no stored grant — complete the OAuth flow first")]
    NotLinked(String),
    #[error("requested scopes exceed the stored grant for {0}")]
    ScopeExceeded(String),
    #[error("stored grant for {0} is expired and cannot be refreshed")]
    Expired(String),
    #[error("token reference is malformed or expired")]
    BadRef,
    #[error("token refresh failed for {0}: {1}")]
    Refresh(String, String),
    #[error("vault error: {0}")]
    Vault(String),
}

impl From<BrokerError> for AuthError {
    fn from(e: BrokerError) -> Self {
        AuthError::Vault(e.to_string())
    }
}

/// An OAuth grant as stored in the vault under `oauth:<provider>`.
/// Serialized as JSON inside the vault's encrypted blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredGrant {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Unix seconds when access_token expires; None = non-expiring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Scopes the grant covers.
    pub scopes: Vec<String>,
    /// Provider token endpoint used for refresh (when available).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_endpoint: Option<String>,
    /// OAuth client id used at consent time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// OAuth client secret, for providers (Google web and desktop clients)
    /// that require it to refresh. Lives only in the encrypted vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Service-account credential for jwt-bearer refresh — used when the
    /// grant was provisioned from a GCP service-account key rather than a
    /// browser OAuth consent (that flow yields no refresh token).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<ServiceAccountCredential>,
}

/// A Google-style service-account credential stored inside a [`StoredGrant`]
/// so the host can mint access tokens itself (jwt-bearer, RFC 7523) when no
/// OAuth refresh token exists. The private key lives only in the encrypted
/// vault — it is never returned across the plugin boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccountCredential {
    /// Service-account email (`client_email` in the key file).
    pub client_email: String,
    /// PEM-encoded PKCS#8 RSA private key (`private_key` in the key file).
    pub private_key: String,
    /// Token endpoint (`token_uri` in the key file; https only).
    #[serde(default = "default_service_account_token_uri")]
    pub token_uri: String,
}

fn default_service_account_token_uri() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

/// What a plugin receives: a reference + metadata, never token material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenGrant {
    /// Opaque `authref:v1:...` reference resolvable host-side only.
    pub token_ref: String,
    pub expires_at: DateTime<Utc>,
    pub scopes: Vec<String>,
    pub token_type: String,
}

/// Host-side resolution of a token reference — carries material in
/// `Zeroizing` memory only. Never crosses the plugin boundary.
#[derive(Debug)]
pub struct ResolvedToken {
    pub token_ref: String,
    pub access_token: Zeroizing<String>,
    pub expires_at: DateTime<Utc>,
    pub scopes: Vec<String>,
}

pub struct ScopedTokenService {
    vault: Arc<VaultBroker>,
    /// The plugin this service issues references to; baked into every reference.
    plugin_id: String,
    /// Authenticates references. Random per service, never leaves the host:
    /// references expire within an hour, so surviving a restart is not needed.
    ref_key: Zeroizing<[u8; 32]>,
    http: reqwest::Client,
    /// Serialises refreshes: a rotating refresh token is spent by its first use,
    /// so two concurrent refreshes would leave one of them holding a dead token.
    refresh_lock: tokio::sync::Mutex<()>,
}

impl ScopedTokenService {
    pub fn new(vault: Arc<VaultBroker>, plugin_id: impl Into<String>) -> Self {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
        ScopedTokenService {
            vault,
            plugin_id: plugin_id.into(),
            ref_key: Zeroizing::new(key),
            // No redirects (a refresh token must only go to the endpoint the
            // grant names), no ambient proxy, and a deadline.
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .timeout(std::time::Duration::from_secs(REFRESH_TIMEOUT_SECS))
                .build()
                .expect("a plain reqwest client always builds"),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// MAC over everything a reference asserts.
    fn mac(&self, provider: &str, scopes_b64: &str, exp: i64) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.ref_key.as_slice())
            .expect("hmac accepts any key length");
        mac.update(
            format!(
                "authref-v2|{provider}|{scopes_b64}|{exp}|{}",
                self.plugin_id
            )
            .as_bytes(),
        );
        mac
    }

    fn vault_key(provider: &str) -> String {
        format!("{VAULT_PREFIX}{provider}")
    }

    fn valid_provider(provider: &str) -> bool {
        !provider.is_empty()
            && provider.len() <= 32
            && provider
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    }

    fn valid_scope(scope: &str) -> bool {
        !scope.is_empty() && scope.len() <= 256 && !scope.chars().any(|c| c.is_control())
    }

    /// Host-side provisioning: store an OAuth grant completed by the core
    /// consent flow. `access_token`/`refresh_token` are taken by value into
    /// `Zeroizing` and stored only inside the encrypted vault.
    pub fn store_grant(&self, provider: &str, grant: StoredGrant) -> Result<(), AuthError> {
        if !Self::valid_provider(provider) {
            return Err(AuthError::BadProvider(provider.to_string()));
        }
        for s in &grant.scopes {
            if !Self::valid_scope(s) {
                return Err(AuthError::BadScope(s.clone()));
            }
        }
        let blob = Zeroizing::new(
            serde_json::to_string(&grant).map_err(|e| AuthError::Vault(e.to_string()))?,
        );
        self.vault
            .provision(&Self::vault_key(provider), blob)
            .map_err(Into::into)
    }

    /// Remove a stored grant (consent revoked). Implemented by deleting the
    /// vault entry through the broker once vault delete lands; until then
    /// callers should overwrite expiry via `store_grant`.
    pub fn revoke_grant(&self, provider: &str) -> Result<(), AuthError> {
        // Mark the grant expired so issue/resolve fail closed immediately.
        if let Ok(mut grant) = self.load_grant(provider) {
            grant.expires_at = Some(0);
            grant.access_token = String::new();
            grant.refresh_token = None;
            grant.client_secret = None;
            return self.save_grant(provider, &grant);
        }
        Ok(())
    }

    fn load_grant(&self, provider: &str) -> Result<StoredGrant, AuthError> {
        let raw = self
            .vault
            .resolve(&Self::vault_key(provider))
            .map_err(|e| match e {
                BrokerError::NotFound(_) => AuthError::NotLinked(provider.to_string()),
                other => AuthError::Vault(other.to_string()),
            })?;
        serde_json::from_str(raw.as_str()).map_err(|e| AuthError::Vault(e.to_string()))
    }

    fn save_grant(&self, provider: &str, grant: &StoredGrant) -> Result<(), AuthError> {
        let blob = Zeroizing::new(
            serde_json::to_string(grant).map_err(|e| AuthError::Vault(e.to_string()))?,
        );
        self.vault
            .provision(&Self::vault_key(provider), blob)
            .map_err(Into::into)
    }

    fn grant_expiry(grant: &StoredGrant) -> Option<DateTime<Utc>> {
        grant
            .expires_at
            .and_then(|ts| DateTime::from_timestamp(ts, 0))
    }

    fn is_fresh(grant: &StoredGrant) -> bool {
        Self::grant_expiry(grant)
            .map(|e| e.timestamp() - EXPIRY_SKEW_SECS > Utc::now().timestamp())
            .unwrap_or(true)
    }

    /// A refresh token may only be sent over TLS (or to a loopback test server).
    fn endpoint_allowed(endpoint: &str) -> bool {
        match reqwest::Url::parse(endpoint) {
            Ok(u) => match u.scheme() {
                "https" => u.host_str().is_some(),
                "http" => matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")),
                _ => false,
            },
            Err(_) => false,
        }
    }

    /// Ensure the stored grant's access token is fresh, refreshing through
    /// the provider token endpoint when needed. Returns the (possibly
    /// updated) grant.
    async fn ensure_fresh(
        &self,
        provider: &str,
        grant: StoredGrant,
    ) -> Result<StoredGrant, AuthError> {
        if Self::is_fresh(&grant) {
            return Ok(grant);
        }
        // One refresh at a time; whoever waited re-reads the vault, because the
        // caller ahead of them may already have refreshed.
        let _turn = self.refresh_lock.lock().await;
        let mut grant = self.load_grant(provider)?;
        if Self::is_fresh(&grant) {
            return Ok(grant);
        }
        // Service-account grants refresh via jwt-bearer — no refresh token
        // exists in that flow, so check it before the refresh-token path.
        if let Some(sa) = grant.service_account.clone() {
            return self
                .refresh_service_account(provider, grant, &sa)
                .await;
        }
        let (Some(refresh), Some(endpoint)) =
            (grant.refresh_token.clone(), grant.token_endpoint.clone())
        else {
            return Err(AuthError::Expired(provider.to_string()));
        };
        if !Self::endpoint_allowed(&endpoint) {
            return Err(AuthError::Refresh(
                provider.to_string(),
                "token endpoint must be an https URL".into(),
            ));
        }
        let client_id = grant.client_id.clone().unwrap_or_default();
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
            ("client_id", client_id.as_str()),
        ];
        if let Some(secret) = grant.client_secret.as_deref() {
            form.push(("client_secret", secret));
        }
        let resp = self
            .http
            .post(&endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| AuthError::Refresh(provider.to_string(), e.without_url().to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::Refresh(
                provider.to_string(),
                format!("token endpoint returned {}", resp.status()),
            ));
        }
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            #[serde(default)]
            refresh_token: Option<String>,
            #[serde(default)]
            expires_in: Option<u64>,
        }
        let tok: TokenResponse = resp
            .json()
            .await
            .map_err(|e| AuthError::Refresh(provider.to_string(), e.without_url().to_string()))?;
        grant.access_token = tok.access_token;
        if let Some(rt) = tok.refresh_token {
            grant.refresh_token = Some(rt);
        }
        grant.expires_at = tok
            .expires_in
            .map(|s| (Utc::now() + chrono::Duration::seconds(s as i64)).timestamp());
        self.save_grant(provider, &grant)?;
        Ok(grant)
    }

    /// Mint a fresh access token from a stored service-account credential
    /// (jwt-bearer grant — the service-account analogue of a refresh token).
    /// The signed assertion and the private key never leave this process.
    async fn refresh_service_account(
        &self,
        provider: &str,
        mut grant: StoredGrant,
        sa: &ServiceAccountCredential,
    ) -> Result<StoredGrant, AuthError> {
        if !Self::endpoint_allowed(&sa.token_uri) {
            return Err(AuthError::Refresh(
                provider.to_string(),
                "service-account token uri must be an https URL".into(),
            ));
        }
        let assertion =
            mint_service_account_assertion(provider, sa, &grant.scopes)?;
        let resp = self
            .http
            .post(&sa.token_uri)
            .form(&[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:jwt-bearer",
                ),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|e| {
                AuthError::Refresh(provider.to_string(), e.without_url().to_string())
            })?;
        if !resp.status().is_success() {
            return Err(AuthError::Refresh(
                provider.to_string(),
                format!("service-account token endpoint returned {}", resp.status()),
            ));
        }
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            #[serde(default)]
            expires_in: Option<u64>,
        }
        let tok: TokenResponse = resp
            .json()
            .await
            .map_err(|e| {
                AuthError::Refresh(provider.to_string(), e.without_url().to_string())
            })?;
        grant.access_token = tok.access_token;
        grant.expires_at = tok
            .expires_in
            .map(|s| (Utc::now() + chrono::Duration::seconds(s as i64)).timestamp());
        self.save_grant(provider, &grant)?;
        Ok(grant)
    }

    /// Whether `provider` has a usable stored grant: fresh, or refreshable
    /// via refresh token or service-account credential. Never returns token
    /// material — used by the admin OAuth status endpoint, where `issue()`
    /// cannot run because it requires a non-empty scope list.
    pub async fn grant_usable(&self, provider: &str) -> bool {
        if !Self::valid_provider(provider) {
            return false;
        }
        match self.load_grant(provider) {
            Ok(g) => {
                Self::is_fresh(&g)
                    || g.refresh_token.is_some()
                    || g.service_account.is_some()
            }
            Err(_) => false,
        }
    }

    fn check_scopes(
        provider: &str,
        grant: &StoredGrant,
        requested: &[String],
    ) -> Result<(), AuthError> {
        if requested.is_empty() {
            return Err(AuthError::BadScope("empty scope list".to_string()));
        }
        let granted: BTreeSet<&str> = grant.scopes.iter().map(|s| s.as_str()).collect();
        for s in requested {
            if !Self::valid_scope(s) {
                return Err(AuthError::BadScope(s.clone()));
            }
            if !granted.contains(s.as_str()) {
                return Err(AuthError::ScopeExceeded(provider.to_string()));
            }
        }
        Ok(())
    }

    /// Issue a scoped token reference for `provider` covering `scopes`.
    /// Plugin-facing: returns [`TokenGrant`] — no token material.
    pub async fn issue(
        &self,
        provider: &str,
        scopes: &[String],
        ttl_secs: Option<u64>,
    ) -> Result<TokenGrant, AuthError> {
        if !Self::valid_provider(provider) {
            return Err(AuthError::BadProvider(provider.to_string()));
        }
        let grant = self
            .ensure_fresh(provider, self.load_grant(provider)?)
            .await?;
        Self::check_scopes(provider, &grant, scopes)?;

        let ttl = ttl_secs.unwrap_or(DEFAULT_TTL_SECS).clamp(1, MAX_TTL_SECS);
        let now = Utc::now();
        // Cap at the grant's own expiry.
        let grant_exp = Self::grant_expiry(&grant);
        let mut exp = now + chrono::Duration::seconds(ttl as i64);
        if let Some(ge) = grant_exp {
            if ge < exp {
                exp = ge;
            }
        }
        if exp.timestamp() <= now.timestamp() {
            return Err(AuthError::Expired(provider.to_string()));
        }

        let scope_blob = scopes.join(",");
        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(scope_blob.as_bytes());
        let mac = hex::encode(
            self.mac(provider, &encoded, exp.timestamp())
                .finalize()
                .into_bytes(),
        );
        let token_ref = format!(
            "{REF_PREFIX}{provider}:{encoded}:{}:{}:{mac}",
            exp.timestamp(),
            self.plugin_id
        );
        Ok(TokenGrant {
            token_ref,
            expires_at: exp,
            scopes: scopes.to_vec(),
            token_type: "Bearer".to_string(),
        })
    }

    /// Resolve an `authref:` to token material — host-side only.
    pub async fn resolve(&self, token_ref: &str) -> Result<ResolvedToken, AuthError> {
        let rest = token_ref
            .strip_prefix(REF_PREFIX)
            .ok_or(AuthError::BadRef)?;
        // provider : scopes : expiry : plugin : mac
        let parts: Vec<&str> = rest.split(':').collect();
        let [provider, encoded, exp_str, plugin, mac_hex] = parts.as_slice() else {
            return Err(AuthError::BadRef);
        };
        let exp_ts: i64 = exp_str.parse().map_err(|_| AuthError::BadRef)?;
        // Nothing inside the reference is trusted until its MAC checks out and
        // it names this plugin: a forged or foreign reference stops here.
        let claimed = hex::decode(mac_hex).map_err(|_| AuthError::BadRef)?;
        self.mac(provider, encoded, exp_ts)
            .verify_slice(&claimed)
            .map_err(|_| AuthError::BadRef)?;
        if *plugin != self.plugin_id {
            return Err(AuthError::BadRef);
        }
        let scope_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| AuthError::BadRef)?;
        let scope_blob = String::from_utf8(scope_bytes).map_err(|_| AuthError::BadRef)?;
        let scopes: Vec<String> = scope_blob
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let exp = DateTime::from_timestamp(exp_ts, 0).ok_or(AuthError::BadRef)?;
        if exp <= Utc::now() {
            return Err(AuthError::BadRef);
        }
        // Re-validate against the live grant: scopes must still be covered
        // and the token must still be fresh (refreshing if needed).
        let grant = self
            .ensure_fresh(provider, self.load_grant(provider)?)
            .await?;
        Self::check_scopes(provider, &grant, &scopes)?;
        let grant_exp = Self::grant_expiry(&grant);
        let effective = grant_exp.map(|ge| ge.min(exp)).unwrap_or(exp);
        if effective <= Utc::now() {
            return Err(AuthError::Expired(provider.to_string()));
        }
        Ok(ResolvedToken {
            token_ref: token_ref.to_string(),
            access_token: Zeroizing::new(grant.access_token.clone()),
            expires_at: effective,
            scopes,
        })
    }
}

/// Build a signed jwt-bearer assertion for `sa` covering `scopes`
/// (RFC 7523 §2.1 + the Google service-account flow). RS256 via `ring` —
/// the private key is parsed from PEM and used in `Zeroizing` memory only.
fn mint_service_account_assertion(
    provider: &str,
    sa: &ServiceAccountCredential,
    scopes: &[String],
) -> Result<String, AuthError> {
    let refresh_err = |m: &str| AuthError::Refresh(provider.to_string(), m.to_string());
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
    let now = Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": sa.client_email,
        "scope": scopes.join(" "),
        "aud": sa.token_uri,
        "iat": now,
        "exp": now + 3600,
    });
    let input = format!(
        "{}.{}",
        b64.encode(serde_json::to_vec(&header).map_err(|e| refresh_err(&e.to_string()))?),
        b64.encode(serde_json::to_vec(&claims).map_err(|e| refresh_err(&e.to_string()))?)
    );
    let der = pem_to_der(&sa.private_key).map_err(|e| refresh_err(&e))?;
    let key = ring::signature::RsaKeyPair::from_pkcs8(&der)
        .map_err(|_| refresh_err("service-account key is not a valid PKCS#8 RSA key"))?;
    let rng = ring::rand::SystemRandom::new();
    let mut sig = vec![0u8; key.public().modulus_len()];
    key.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &rng,
        input.as_bytes(),
        &mut sig,
    )
    .map_err(|e| refresh_err(&format!("jwt signing failed: {e}")))?;
    Ok(format!("{input}.{}", b64.encode(sig)))
}

/// Strip PEM armor and base64-decode a `PRIVATE KEY` block to PKCS#8 DER.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    if body.is_empty() {
        return Err("service-account private_key is empty".into());
    }
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| format!("service-account private_key is not valid base64: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_vault::VaultBroker;

    fn service() -> (tempfile::TempDir, ScopedTokenService) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(VaultBroker::open(
            dir.path().join(t3rnel_extensions::vault::VAULT_FILE_NAME),
            false,
        ));
        vault
            .unlock_ordered(Some(Zeroizing::new([21u8; 32])))
            .unwrap();
        let svc = ScopedTokenService::new(vault, "org.test.auth");
        (dir, svc)
    }

    fn grant(scopes: &[&str], expires_in_secs: Option<i64>) -> StoredGrant {
        StoredGrant {
            access_token: "ya29.test-access".into(),
            refresh_token: Some("1//refresh".into()),
            expires_at: expires_in_secs
                .map(|s| (Utc::now() + chrono::Duration::seconds(s)).timestamp()),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            token_endpoint: None,
            client_id: Some("cid".into()),
            client_secret: None,
            service_account: None,
        }
    }

    #[tokio::test]
    async fn issue_returns_ref_never_token_and_scopes_enforced() {
        let (_d, svc) = service();
        svc.store_grant("google", grant(&["scope:a", "scope:b"], Some(3600)))
            .unwrap();
        let g = svc
            .issue("google", &["scope:a".to_string()], Some(120))
            .await
            .unwrap();
        assert!(g.token_ref.starts_with("authref:v2:google:"));
        assert_eq!(g.token_type, "Bearer");
        assert_eq!(g.scopes, vec!["scope:a"]);
        // No token material in the plugin-facing grant.
        let json = serde_json::to_string(&g).unwrap();
        assert!(!json.contains("ya29"));

        // Scope escalation refused.
        let err = svc
            .issue("google", &["scope:c".to_string()], None)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::ScopeExceeded(_)));

        // Unknown provider.
        let err = svc.issue("github", &["x".into()], None).await.unwrap_err();
        assert!(matches!(err, AuthError::NotLinked(_)));

        // resolve returns material host-side.
        let resolved = svc.resolve(&g.token_ref).await.unwrap();
        assert_eq!(resolved.access_token.as_str(), "ya29.test-access");
        assert!(resolved.expires_at > Utc::now());
    }

    #[tokio::test]
    async fn ttl_is_bounded_and_capped_by_grant_expiry() {
        let (_d, svc) = service();
        // Grant expires in 60s; request 1h → capped at grant expiry.
        svc.store_grant("google", grant(&["s"], Some(60))).unwrap();
        let g = svc
            .issue("google", &["s".into()], Some(3600))
            .await
            .unwrap();
        let ttl = g.expires_at - Utc::now();
        assert!(ttl <= chrono::Duration::seconds(61), "{ttl}");
        // TTL hard cap: huge request still bounded.
        let g2 = svc
            .issue("google", &["s".into()], Some(999_999))
            .await
            .unwrap();
        assert!(g2.expires_at - Utc::now() <= chrono::Duration::seconds(61));
    }

    #[tokio::test]
    async fn expired_grant_without_refresh_fails_closed() {
        let (_d, svc) = service();
        let mut g = grant(&["s"], Some(-10)); // already expired
        g.refresh_token = None;
        svc.store_grant("google", g).unwrap();
        let err = svc.issue("google", &["s".into()], None).await.unwrap_err();
        assert!(matches!(err, AuthError::Expired(_)));
    }

    #[tokio::test]
    async fn refresh_flows_through_token_endpoint() {
        // Real HTTP token endpoint on loopback.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 8192];
                let _ = sock.read(&mut buf).await;
                let body = r#"{"access_token":"fresh-token-123","expires_in":3600}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });

        let (_d, svc) = service();
        let mut g = grant(&["s"], Some(-10)); // expired → must refresh
        g.token_endpoint = Some(format!("http://127.0.0.1:{port}/token"));
        svc.store_grant("google", g).unwrap();
        let issued = svc.issue("google", &["s".into()], None).await.unwrap();
        let resolved = svc.resolve(&issued.token_ref).await.unwrap();
        assert_eq!(resolved.access_token.as_str(), "fresh-token-123");
        // The refresh token was never returned anywhere.
        assert!(!issued.token_ref.contains("refresh"));
    }

    #[tokio::test]
    async fn malformed_and_expired_refs_refused() {
        let (_d, svc) = service();
        svc.store_grant("google", grant(&["s"], Some(3600)))
            .unwrap();
        assert!(matches!(
            svc.resolve("authref:v2:bad").await,
            Err(AuthError::BadRef)
        ));
        assert!(matches!(
            svc.resolve("not-a-ref").await,
            Err(AuthError::BadRef)
        ));
        // Forge an expired ref.
        let expired = "authref:v2:google:eA:1:org.test.auth:00".to_string();
        assert!(matches!(
            svc.resolve(&expired).await,
            Err(AuthError::BadRef)
        ));
    }

    // ---- references cannot be forged, widened, extended or borrowed -------------------------------
    /// Swap one `:`-separated field of a reference.
    fn tamper(token_ref: &str, field: usize, value: &str) -> String {
        let mut parts: Vec<String> = token_ref.split(':').map(String::from).collect();
        parts[field + 2] = value.to_string(); // skip "authref", "v2"
        parts.join(":")
    }

    #[tokio::test]
    async fn a_reference_cannot_be_widened_or_extended_by_editing_it() {
        let (_d, svc) = service();
        svc.store_grant("google", grant(&["scope:a", "scope:b"], Some(86_400)))
            .unwrap();
        let g = svc
            .issue("google", &["scope:a".to_string()], Some(60))
            .await
            .unwrap();
        svc.resolve(&g.token_ref)
            .await
            .expect("the genuine reference resolves");
        // Fields: 0 provider, 1 scopes, 2 expiry, 3 plugin, 4 mac.
        let wider = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("scope:a,scope:b");
        let far = (Utc::now().timestamp() + 365 * 86_400).to_string();
        for (what, forged) in [
            ("wider scopes", tamper(&g.token_ref, 1, &wider)),
            ("later expiry", tamper(&g.token_ref, 2, &far)),
            ("another provider", tamper(&g.token_ref, 0, "github")),
            ("another plugin", tamper(&g.token_ref, 3, "org.evil.plugin")),
            ("no mac", tamper(&g.token_ref, 4, "")),
            ("wrong mac", tamper(&g.token_ref, 4, &"ab".repeat(32))),
        ] {
            assert!(
                matches!(svc.resolve(&forged).await, Err(AuthError::BadRef)),
                "{what} must be refused"
            );
        }
        // A reference built from scratch, in the exact format, without the key.
        let scratch = format!(
            "authref:v2:google:{wider}:{far}:org.test.auth:{}",
            "00".repeat(32)
        );
        assert!(matches!(
            svc.resolve(&scratch).await,
            Err(AuthError::BadRef)
        ));
    }

    #[tokio::test]
    async fn a_reference_issued_to_one_plugin_is_useless_to_another() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(VaultBroker::open(
            dir.path().join(t3rnel_extensions::vault::VAULT_FILE_NAME),
            false,
        ));
        vault
            .unlock_ordered(Some(Zeroizing::new([22u8; 32])))
            .unwrap();
        let alice = ScopedTokenService::new(vault.clone(), "org.test.alice");
        let mallory = ScopedTokenService::new(vault, "org.test.mallory");
        alice
            .store_grant("google", grant(&["s"], Some(3600)))
            .unwrap();
        let g = alice.issue("google", &["s".into()], None).await.unwrap();
        assert!(alice.resolve(&g.token_ref).await.is_ok());
        // Same vault, same grant, a reference taken from alice: refused.
        assert!(matches!(
            mallory.resolve(&g.token_ref).await,
            Err(AuthError::BadRef)
        ));
        // Even re-labelled as mallory's, the MAC (alice's key) does not verify.
        let relabelled = tamper(&g.token_ref, 3, "org.test.mallory");
        assert!(matches!(
            mallory.resolve(&relabelled).await,
            Err(AuthError::BadRef)
        ));
    }

    // ---- refresh -------------------------------------------------------------------------------------
    /// A token endpoint on loopback that records every request it receives.
    async fn recording_endpoint(reply: &'static str) -> (u16, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let log = seen.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                log.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..n]).to_string());
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                let _ = sock.write_all(reply.as_bytes()).await;
            }
        });
        (port, seen)
    }

    const OK_REPLY: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 52\r\nConnection: close\r\n\r\n{\"access_token\":\"fresh-token-123\",\"expires_in\":3600}";

    #[tokio::test]
    async fn refresh_sends_the_client_secret_when_the_grant_has_one() {
        let (port, seen) = recording_endpoint(OK_REPLY).await;
        let (_d, svc) = service();
        let mut g = grant(&["s"], Some(-10));
        g.token_endpoint = Some(format!("http://127.0.0.1:{port}/token"));
        g.client_secret = Some("shh-client-secret".into());
        svc.store_grant("google", g).unwrap();
        svc.issue("google", &["s".into()], None).await.unwrap();
        let body = seen.lock().unwrap().join("");
        assert!(body.contains("client_secret=shh-client-secret"), "{body}");
        assert!(body.contains("grant_type=refresh_token"));
    }

    #[tokio::test]
    async fn two_callers_on_an_expired_grant_refresh_exactly_once() {
        let (port, seen) = recording_endpoint(OK_REPLY).await;
        let (_d, svc) = service();
        let mut g = grant(&["s"], Some(-10));
        g.token_endpoint = Some(format!("http://127.0.0.1:{port}/token"));
        svc.store_grant("google", g).unwrap();
        let scopes = vec!["s".to_string()];
        let (a, b) = tokio::join!(
            svc.issue("google", &scopes, None),
            svc.issue("google", &scopes, None)
        );
        a.unwrap();
        b.unwrap();
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "a rotating refresh token is spent once"
        );
    }

    #[tokio::test]
    async fn the_refresh_token_is_never_sent_to_a_redirect_target() {
        let (capture_port, captured) = recording_endpoint(OK_REPLY).await;
        let redirect: &'static str = Box::leak(
            format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{capture_port}/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_boxed_str(),
        );
        let (port, _) = recording_endpoint(redirect).await;
        let (_d, svc) = service();
        let mut g = grant(&["s"], Some(-10));
        g.token_endpoint = Some(format!("http://127.0.0.1:{port}/token"));
        svc.store_grant("google", g).unwrap();
        let err = svc.issue("google", &["s".into()], None).await.unwrap_err();
        assert!(matches!(err, AuthError::Refresh(_, _)), "{err:?}");
        assert!(
            captured.lock().unwrap().is_empty(),
            "the redirect target received a request"
        );
    }

    #[tokio::test]
    async fn a_plain_http_token_endpoint_is_refused_before_any_request() {
        let (_d, svc) = service();
        for endpoint in [
            "http://accounts.example/token",
            "ftp://x/token",
            "not a url",
            "http://127.0.0.1.evil.example/token",
        ] {
            let mut g = grant(&["s"], Some(-10));
            g.token_endpoint = Some(endpoint.into());
            svc.store_grant("google", g).unwrap();
            let err = svc.issue("google", &["s".into()], None).await.unwrap_err();
            assert!(
                matches!(&err, AuthError::Refresh(_, m) if m.contains("https")),
                "{endpoint}: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn revoking_a_grant_removes_the_token_material() {
        let (_d, svc) = service();
        let mut g = grant(&["s"], Some(3600));
        g.client_secret = Some("secret".into());
        svc.store_grant("google", g).unwrap();
        let issued = svc.issue("google", &["s".into()], None).await.unwrap();
        svc.revoke_grant("google").unwrap();
        let left = svc.load_grant("google").unwrap();
        assert!(
            left.access_token.is_empty()
                && left.refresh_token.is_none()
                && left.client_secret.is_none(),
            "{left:?}"
        );
        assert!(
            svc.resolve(&issued.token_ref).await.is_err(),
            "a reference issued before revocation stops working"
        );
        assert!(svc.issue("google", &["s".into()], None).await.is_err());
    }

    // ---- service-account (jwt-bearer) refresh -------------------------------------------------------

    /// Throwaway 2048-bit RSA key generated for tests only
    /// (`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`).
    /// It signs assertions the mock token endpoint never validates.
    const TEST_SA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCpb3/o2e4Rmpd4\n\
+YzkgE2KN9a1v3SC0bNJ675wauYn3BXvDhFFJMBF4+atFISEskru3dHifE3GVx9i\n\
fw8F5i6ts5VHyftkVm1vRp5Dj67eS2JfwiJ5kF/M87ZZa710MSitzGsVTM+uW4BK\n\
n1CnzL9+cX39jP4RXEAsthjwX3eaOgJxOcdYE9oFYEk6sQ1FdsAe3I6vZ0R9IhMH\n\
Uz9hk+f8LCSQ4hiqMNux5C+S1SS+g8FAXcxRmBwGpbZGvNVkN9q3fCy6ziEVGFo2\n\
C0OJBfgKIdmyP5+2vhsGJut8N3yK42F83nqdbh836sMAnsXNiEZGn9poEFC6dzoi\n\
6lyZTRsNAgMBAAECggEASqA6ZRN/YK+HIZhALvA3trXrUnd12JyF6/vyD891eX7d\n\
BkJa5upN6Tp8giT0TQG+MUDvzWJUWxRKVXaC5mVAj+71w/25RLMwVf9ze2xQZ8Yq\n\
GOUHjCVDnKCG4xGqCwAP26SaUXJYUoIomjVbL9zlRsqz5DXyPTE1brvxdgWGRx2o\n\
IiBKU6gab8fh1jEEN6LlfiIMkv02kgvkH9GvlxzoGpq0ihiJfiuu4ncvPVrRCEQ7\n\
r8d49HvqHfDArhMp0NsPJmP/PNFhgIUdcKSgTEa9Z22u69peklONOZn/g666FFLA\n\
OOW3h0FJflP7cFYWlVdr8ezyJJsl1UGjNWJFbvVufQKBgQDW+Ihj8J3FfsSaSmEY\n\
VhKTDtWwDNmDEbYi8qEzEM7ZbkMTzx7LWB3qYYdytFTZfdFcfcFE9ZC99YDWEA+q\n\
bpliY2lbmTh10AcP7QinY99x5S9lt37wpQ4cp9Tk427Lnge5Wo0uWsFJELtwBs1L\n\
nVrmOQCZX2KlT6kCjHLojCLuVwKBgQDJxh1KtrNoWLe/c7AwdQtRUXuxa87dp+Kw\n\
xL6KbH1MAJGihMDUzdiuuaBUftdLTiF+j0Sj/RRtDDtaWS2AWUncZplqCoLff9zZ\n\
UM4rN/hLHJL3uMrTen+rzocEKSP0NDx5Mbks2yQ9inn+RDSomqOfED+Mp2Sl9ZKW\n\
bCPdpqsbOwKBgExVDeEm5G7nV5pNxPJmRcwwHVKZDXdMB7ebHgBK/JgaXfkft5iO\n\
3niGTxk8zVA5K+lCwijhZZb+INRh+Z4UDaTxFc0vt+ulhYxzJ3qArSv9LHpa0NlU\n\
UpF8Ss1HsOTeZXG8pJsMIMv4BAaAc89gvZE4Nm0/gICgq6u7AWZvtEubAoGBALAu\n\
3lrjxyog9Wkl0j2tpdE+rhwQv9QKCUZCtQHXk1yuznuzIVFv4HlIures/b7SnSqO\n\
XOg4TwKdAKJ2ZeXBkV3y9JiETxxq4GOdTDiuqY6kh6vo3qnkN+DD+F7osW1Fw1wr\n\
z75cJ3vZE4ay9awXQzHcFTFy5M6I7JOOH48mPhgLAoGBAKTxnGaMiZnujh5Nq4VW\n\
SIFQPITDmr38qS/g2OcdpnSU0tnk4xexuGCRfEWksHBkahhF8f/MPpBDkod5v06p\n\
g9u2+UON2Liz+RzPq4/2uOS/a/hNSR7BbOiRDnLksVvxZqXYm0uEZmIMeCwDob39\n\
mnl4ocx7s8WXkOWBQAZafC5V\n\
-----END PRIVATE KEY-----";

    fn sa_grant(token_uri: String) -> ServiceAccountCredential {
        ServiceAccountCredential {
            client_email: "reader@test-project.iam.gserviceaccount.com".into(),
            private_key: TEST_SA_PRIVATE_KEY.into(),
            token_uri,
        }
    }

    const SA_OK_REPLY: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 51\r\nConnection: close\r\n\r\n{\"access_token\":\"sa-fresh-token\",\"expires_in\":3600}";

    #[tokio::test]
    async fn grant_usable_covers_fresh_expired_refreshable_and_unknown() {
        let (_d, svc) = service();
        assert!(!svc.grant_usable("google").await, "unknown provider");
        assert!(!svc.grant_usable("NOT A PROVIDER").await);

        // Fresh grant.
        svc.store_grant("google", grant(&["s"], Some(3600))).unwrap();
        assert!(svc.grant_usable("google").await);

        // Expired but refreshable via refresh token.
        let mut g = grant(&["s"], Some(-10));
        svc.store_grant("google", g.clone()).unwrap();
        assert!(svc.grant_usable("google").await);

        // Expired, refresh token stripped, but a service account can renew it.
        g.refresh_token = None;
        g.service_account = Some(sa_grant(
            "https://oauth2.googleapis.com/token".into(),
        ));
        svc.store_grant("google", g).unwrap();
        assert!(svc.grant_usable("google").await);

        // Expired with nothing to refresh from.
        let mut dead = grant(&["s"], Some(-10));
        dead.refresh_token = None;
        svc.store_grant("google", dead).unwrap();
        assert!(!svc.grant_usable("google").await);
    }

    #[tokio::test]
    async fn service_account_grant_refreshes_via_jwt_bearer() {
        let (port, seen) = recording_endpoint(SA_OK_REPLY).await;
        let (_d, svc) = service();
        let mut g = grant(&["scope:a"], Some(-10)); // expired → must refresh
        g.refresh_token = None;
        g.service_account = Some(sa_grant(format!("http://127.0.0.1:{port}/token")));
        svc.store_grant("google", g).unwrap();

        let issued = svc.issue("google", &["scope:a".into()], None).await.unwrap();
        // The stored grant now carries the token the mock endpoint minted.
        let stored = svc.load_grant("google").unwrap();
        assert_eq!(stored.access_token, "sa-fresh-token");
        assert!(stored.refresh_token.is_none());

        // The request was a jwt-bearer exchange carrying a 3-part assertion.
        let raw = seen.lock().unwrap().join("\n---\n");
        assert_eq!(seen.lock().unwrap().len(), 1, "{raw}");
        assert!(
            raw.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"),
            "{raw}"
        );
        let assertion = raw
            .split("assertion=")
            .nth(1)
            .and_then(|s| s.split('&').next())
            .and_then(|s| s.split_whitespace().next())
            .expect("assertion form field");
        assert_eq!(
            assertion.matches('.').count(),
            2,
            "assertion must be a header.payload.signature JWT: {assertion}"
        );

        // A second issue is served from the now-fresh grant: no second call.
        svc.issue("google", &["scope:a".into()], None).await.unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1);
        let resolved = svc.resolve(&issued.token_ref).await.unwrap();
        assert_eq!(resolved.access_token.as_str(), "sa-fresh-token");
    }

    #[tokio::test]
    async fn service_account_token_uri_must_be_https() {
        let (_d, svc) = service();
        let mut g = grant(&["s"], Some(-10));
        g.refresh_token = None;
        g.service_account = Some(sa_grant("http://evil.example.com/token".into()));
        svc.store_grant("google", g).unwrap();
        let err = svc.issue("google", &["s".into()], None).await.unwrap_err();
        assert!(
            matches!(&err, AuthError::Refresh(_, m) if m.contains("https")),
            "{err:?}"
        );
        // Refused before any request — the vault still holds the dead grant.
        let stored = svc.load_grant("google").unwrap();
        assert_eq!(stored.access_token, "ya29.test-access");
    }
}
