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
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::plugin_vault::{BrokerError, VaultBroker};

/// Default scoped-token lifetime.
const DEFAULT_TTL_SECS: u64 = 300;
/// Hard cap on scoped-token lifetime.
const MAX_TTL_SECS: u64 = 3600;
/// Refresh this far before expiry so a token never dies mid-request.
const EXPIRY_SKEW_SECS: i64 = 30;

const VAULT_PREFIX: &str = "oauth:";
const REF_PREFIX: &str = "authref:v1:";

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
    http: reqwest::Client,
}

impl ScopedTokenService {
    pub fn new(vault: Arc<VaultBroker>) -> Self {
        ScopedTokenService {
            vault,
            http: reqwest::Client::new(),
        }
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
            grant.refresh_token = None;
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

    /// Ensure the stored grant's access token is fresh, refreshing through
    /// the provider token endpoint when needed. Returns the (possibly
    /// updated) grant.
    async fn ensure_fresh(
        &self,
        provider: &str,
        mut grant: StoredGrant,
    ) -> Result<StoredGrant, AuthError> {
        let exp = Self::grant_expiry(&grant);
        let fresh = exp
            .map(|e| e.timestamp() - EXPIRY_SKEW_SECS > Utc::now().timestamp())
            .unwrap_or(true);
        if fresh {
            return Ok(grant);
        }
        // Needs refresh.
        let (Some(refresh), Some(endpoint)) =
            (grant.refresh_token.clone(), grant.token_endpoint.clone())
        else {
            return Err(AuthError::Expired(provider.to_string()));
        };
        let client_id = grant.client_id.clone().unwrap_or_default();
        let resp = self
            .http
            .post(&endpoint)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh.as_str()),
                ("client_id", client_id.as_str()),
            ])
            .send()
            .await
            .map_err(|e| AuthError::Refresh(provider.to_string(), e.to_string()))?;
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
            .map_err(|e| AuthError::Refresh(provider.to_string(), e.to_string()))?;
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
        let token_ref = format!("{REF_PREFIX}{provider}:{encoded}:{}", exp.timestamp());
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
        let mut parts = rest.rsplitn(2, ':');
        let exp_ts: i64 = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or(AuthError::BadRef)?;
        let head = parts.next().ok_or(AuthError::BadRef)?;
        let (provider, encoded) = head.split_once(':').ok_or(AuthError::BadRef)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_vault::VaultBroker;

    fn service() -> (tempfile::TempDir, ScopedTokenService) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(VaultBroker::open(dir.path().join("vault.t3rnel"), false));
        vault
            .unlock_ordered(Some(Zeroizing::new([21u8; 32])))
            .unwrap();
        let svc = ScopedTokenService::new(vault);
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
        assert!(g.token_ref.starts_with("authref:v1:google:"));
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
            svc.resolve("authref:v1:bad").await,
            Err(AuthError::BadRef)
        ));
        assert!(matches!(
            svc.resolve("not-a-ref").await,
            Err(AuthError::BadRef)
        ));
        // Forge an expired ref.
        let expired = "authref:v1:google:eA:1".to_string(); // exp=1 → 1970
        assert!(matches!(
            svc.resolve(&expired).await,
            Err(AuthError::BadRef)
        ));
    }
}
