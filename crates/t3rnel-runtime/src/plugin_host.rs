//! Running plugin host (`17-implementation-guide.md` §9.4–§9.6 wiring).
//!
//! [`PluginHost`] is the per-plugin composition root: it owns the plugin's
//! [`PluginStorage`], its [`PluginProxy`] (with secrets resolved through
//! [`VaultBroker`]), and the audit trail. Host services call into it; the
//! plugin only ever sees proto responses — never connections, paths outside
//! its grant, or secret material.
//!
//! This is the seam the gRPC dispatch layer (proto contract) will call once
//! tonic wiring lands; keeping it transport-free makes it fully testable.

use std::path::Path;
use std::sync::Arc;

use crate::plugin_proxy::{
    AuthBinding, EgressRule, PluginProxy, ProxyError, ProxyRequest, ProxyResponse,
};
use crate::plugin_storage::PluginStorage;
use crate::plugin_vault::VaultBroker;

/// gRPC-style status categories for plugin-facing errors. Mirrors the code
/// space used by `t3rnel/plugin/v1` responses; kept structural until tonic
/// codegen exists (buf/protoc unavailable — see NEEDS-FROM-TOOLS.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStatus {
    Ok,
    InvalidArgument,
    PermissionDenied,
    NotFound,
    ResourceExhausted,
    Unavailable,
    Internal,
}

impl PluginStatus {
    pub fn code(self) -> i32 {
        match self {
            PluginStatus::Ok => 0,
            PluginStatus::InvalidArgument => 3,
            PluginStatus::PermissionDenied => 7,
            PluginStatus::NotFound => 5,
            PluginStatus::ResourceExhausted => 8,
            PluginStatus::Unavailable => 14,
            PluginStatus::Internal => 13,
        }
    }
}

/// Map a proxy/storage failure to the plugin-facing status. Security
/// refusals are `PermissionDenied` — the plugin learns *that* it was denied,
/// never which internal check tripped beyond the error text it already gets.
pub fn status_for_proxy_error(e: &ProxyError) -> PluginStatus {
    match e {
        ProxyError::BadUrl
        | ProxyError::BadPathEncoding
        | ProxyError::BadFraming
        | ProxyError::MethodNotDeclared(_, _)
        | ProxyError::PathNotDeclared(_, _) => PluginStatus::InvalidArgument,
        ProxyError::HostNotDeclared(_)
        | ProxyError::ForbiddenHeader(_)
        | ProxyError::PrivateUpstream(_)
        | ProxyError::SecretUnavailable(_)
        | ProxyError::RedirectBlocked(_) => PluginStatus::PermissionDenied,
        ProxyError::Upstream(_) => PluginStatus::Unavailable,
    }
}

/// The composed per-plugin host context.
pub struct PluginHost {
    pub plugin_id: String,
    pub storage: PluginStorage,
    pub proxy: PluginProxy,
    pub vault: Arc<VaultBroker>,
}

/// Everything needed to construct a [`PluginHost`] — supplied by the
/// installer/manifest layer once manifests are parsed at runtime.
pub struct PluginHostConfig {
    pub plugin_id: String,
    pub egress: Vec<EgressRule>,
    pub auth: Vec<AuthBinding>,
    /// Master key for vault unlock (host-provided; `None` → dev env path).
    pub vault_key: Option<zeroize::Zeroizing<[u8; 32]>>,
    /// Allow `T3RNEL_VAULT_KEY` unlock (dev/CI only).
    pub dev_mode: bool,
}

impl PluginHost {
    /// Open storage, unlock the vault in §14.14 order, and build the proxy
    /// with the vault-backed resolver. `home` must be a scratch/test dir in
    /// tests — never the live `~/.t3rnel`.
    pub fn open(
        home: &Path,
        cfg: PluginHostConfig,
    ) -> Result<Self, crate::plugin_vault::BrokerError> {
        let storage = PluginStorage::open(home, &cfg.plugin_id)
            .map_err(|e| crate::plugin_vault::BrokerError::Vault(e.to_string()))?;
        let vault_path = home.join("vault.t3rnel");
        let vault = Arc::new(VaultBroker::open(vault_path, cfg.dev_mode));
        vault.unlock_ordered(cfg.vault_key)?;
        let resolver = vault.as_resolver();
        let proxy = PluginProxy::new(cfg.plugin_id.clone(), cfg.egress, cfg.auth, resolver);
        Ok(PluginHost {
            plugin_id: cfg.plugin_id,
            storage,
            proxy,
            vault,
        })
    }

    /// `http` host service entry point: validate+forward through the proxy,
    /// audit the *reference-level* facts (host, method, status — never
    /// secrets or bodies), and return the response.
    pub async fn http(&self, req: &ProxyRequest) -> Result<ProxyResponse, ProxyError> {
        let result = self.proxy.request(req).await;
        let (action, detail) = match &result {
            Ok(resp) => (
                "http.ok",
                format!(
                    "status={} redirects_blocked={}",
                    resp.status,
                    resp.blocked_redirects.len()
                ),
            ),
            Err(e) => ("http.refused", format!("{e}")),
        };
        // Audit failures of the audit write itself must not mask the result.
        let _ = self.storage.audit_append(action, &detail);
        result
    }

    /// `audit` host service read: tail of this plugin's audit trail.
    pub fn audit_tail(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, String, String)>, crate::plugin_storage::StorageError> {
        self.storage.audit_tail(limit)
    }

    /// `auth` host service (18 §8): scoped, short-lived token brokering.
    /// The plugin-facing surface returns only opaque `authref:` references;
    /// [`crate::plugin_auth::ScopedTokenService::resolve`] stays host-side.
    /// Vault-scoped to this plugin host's broker — grants live under
    /// `oauth:<provider>` and are shared with the core consent flow.
    pub fn auth(&self) -> crate::plugin_auth::ScopedTokenService {
        crate::plugin_auth::ScopedTokenService::new(self.vault.clone())
    }

    /// `storage` host service KV surface.
    pub fn storage_get(
        &self,
        key: &str,
    ) -> Result<Option<String>, crate::plugin_storage::StorageError> {
        self.storage.kv_get(key)
    }
    pub fn storage_set(
        &self,
        key: &str,
        value: &str,
    ) -> Result<(), crate::plugin_storage::StorageError> {
        self.storage.kv_set(key, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_proxy::EgressRule;
    use std::collections::BTreeMap;

    fn cfg(plugin_id: &str, port: u16) -> PluginHostConfig {
        PluginHostConfig {
            plugin_id: plugin_id.into(),
            egress: vec![EgressRule {
                host: format!("127.0.0.1:{port}"),
                methods: vec!["GET".into()],
                paths: vec!["/v1/*".into()],
                allow_private: true,
            }],
            auth: vec![],
            vault_key: Some(zeroize::Zeroizing::new([5u8; 32])),
            dev_mode: false,
        }
    }

    #[tokio::test]
    async fn http_service_roundtrip_and_audit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await.unwrap();
            let body = "{}";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        });

        let home = tempfile::tempdir().unwrap();
        let host = PluginHost::open(home.path(), cfg("org.test.hostsvc", port)).unwrap();
        let resp = host
            .http(&ProxyRequest {
                url: format!("http://127.0.0.1:{port}/v1/data"),
                method: "GET".into(),
                headers: BTreeMap::new(),
                body: None,
                content_length: None,
                transfer_encoding_chunked: false,
            })
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        // Audit recorded the request at reference level.
        let tail = host.audit_tail(10).unwrap();
        assert!(tail.iter().any(|(_, a, _)| a == "http.ok"), "{tail:?}");

        // A refused request is audited too.
        let err = host
            .http(&ProxyRequest {
                url: format!("http://127.0.0.1:{port}/admin/secret"),
                method: "GET".into(),
                headers: BTreeMap::new(),
                body: None,
                content_length: None,
                transfer_encoding_chunked: false,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            status_for_proxy_error(&err),
            PluginStatus::InvalidArgument
        ));
        let tail = host.audit_tail(10).unwrap();
        assert!(tail.iter().any(|(_, a, _)| a == "http.refused"), "{tail:?}");
    }

    #[test]
    fn status_mapping_covers_all_error_kinds() {
        assert_eq!(
            status_for_proxy_error(&ProxyError::BadUrl),
            PluginStatus::InvalidArgument
        );
        assert_eq!(
            status_for_proxy_error(&ProxyError::HostNotDeclared("x".into())),
            PluginStatus::PermissionDenied
        );
        assert_eq!(
            status_for_proxy_error(&ProxyError::PrivateUpstream("10.0.0.1".into())),
            PluginStatus::PermissionDenied
        );
        assert_eq!(
            status_for_proxy_error(&ProxyError::SecretUnavailable("k".into())),
            PluginStatus::PermissionDenied
        );
        assert_eq!(
            status_for_proxy_error(&ProxyError::Upstream("boom".into())),
            PluginStatus::Unavailable
        );
        // gRPC code numbers match canonical values.
        assert_eq!(PluginStatus::PermissionDenied.code(), 7);
        assert_eq!(PluginStatus::Unavailable.code(), 14);
    }

    /// TLS enforcement: an `https://` request must attempt a real TLS
    /// handshake — a plaintext responder cannot satisfy it, proving there is
    /// no silent downgrade to cleartext.
    #[tokio::test]
    async fn https_upstream_requires_real_tls() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Accept and immediately send plaintext garbage — a TLS client
            // must fail the handshake, never fall back to cleartext.
            if let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = sock.write_all(b"HTTP/1.1 200 OK\r\n\r\nnot tls").await;
            }
        });
        let home = tempfile::tempdir().unwrap();
        let host = PluginHost::open(home.path(), cfg("org.test.tls", port)).unwrap();
        let err = host
            .http(&ProxyRequest {
                url: format!("https://127.0.0.1:{port}/v1/x"),
                method: "GET".into(),
                headers: BTreeMap::new(),
                body: None,
                content_length: None,
                transfer_encoding_chunked: false,
            })
            .await
            .unwrap_err();
        // Must be an upstream/TLS failure — never a successful plaintext read.
        assert!(matches!(err, ProxyError::Upstream(_)), "{err:?}");
    }
}
