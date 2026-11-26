//! OAuth2 PKCE flows — localhost callback for Google/GitHub/Microsoft/Slack.
//!
//! Launches a temporary localhost HTTP server, opens the browser to the auth URL,
//! receives the callback with the authorization code, and exchanges it for tokens.
//! All tokens are stored in the credential vault with `Zeroizing<String>`.

use crate::{ExtensionError, ExtensionResult, OAuthTemplate};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

/// Default OAuth client IDs for public PKCE flows.
/// These are safe to embed — PKCE doesn't require a client_secret.
pub fn default_client_ids() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    // Placeholder IDs — users should configure their own via config
    m.insert("google", "t3rnel-google-client-id");
    m.insert("github", "t3rnel-github-client-id");
    m.insert("microsoft", "t3rnel-microsoft-client-id");
    m.insert("slack", "t3rnel-slack-client-id");
    m
}

/// Resolve OAuth client IDs with config overrides applied on top of defaults.
pub fn resolve_client_ids(config: &t3rnel_types::config::OAuthConfig) -> HashMap<String, String> {
    let defaults = default_client_ids();
    let mut resolved: HashMap<String, String> = defaults
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    if let Some(ref id) = config.google_client_id {
        resolved.insert("google".into(), id.clone());
    }
    if let Some(ref id) = config.github_client_id {
        resolved.insert("github".into(), id.clone());
    }
    if let Some(ref id) = config.microsoft_client_id {
        resolved.insert("microsoft".into(), id.clone());
    }
    if let Some(ref id) = config.slack_client_id {
        resolved.insert("slack".into(), id.clone());
    }

    resolved
}

/// OAuth2 token response (raw from provider, for deserialization).
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthTokens {
    /// Access token for API calls.
    pub access_token: String,
    /// Refresh token for renewal (if provided).
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Token type (usually "Bearer").
    #[serde(default)]
    pub token_type: String,
    /// Seconds until access_token expires.
    #[serde(default)]
    pub expires_in: u64,
    /// Scopes granted.
    #[serde(default)]
    pub scope: String,
}

impl OAuthTokens {
    /// Get the access token as a Zeroizing string.
    pub fn access_token_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(self.access_token.clone())
    }

    /// Get the refresh token as a Zeroizing string.
    pub fn refresh_token_zeroizing(&self) -> Option<Zeroizing<String>> {
        self.refresh_token
            .as_ref()
            .map(|t| Zeroizing::new(t.clone()))
    }
}

/// PKCE code verifier and challenge pair.
struct PkcePair {
    verifier: Zeroizing<String>,
    challenge: String,
}

/// Generate a PKCE code_verifier and code_challenge (S256).
fn generate_pkce() -> PkcePair {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let verifier = Zeroizing::new(base64_url_encode(&bytes));
    let challenge = {
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let digest = hasher.finalize();
        base64_url_encode(&digest)
    };
    PkcePair {
        verifier,
        challenge,
    }
}

/// URL-safe base64 encoding (no padding).
fn base64_url_encode(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, data)
}

/// Generate a random state parameter for CSRF protection.
fn generate_state() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64_url_encode(&bytes)
}

/// A started PKCE flow: the authorization URL to hand to the user plus the
/// state needed to finish it (either via the loopback callback or an
/// explicit `finish_pkce_flow` call with the returned code).
pub struct StartedPkceFlow {
    /// URL to open in the user's browser.
    pub auth_url: String,
    /// Loopback redirect URI registered with the callback server.
    pub redirect_uri: String,
    /// CSRF state echoed back on the callback.
    pub state: String,
    /// Port the temporary callback server listens on.
    pub callback_port: u16,
    /// Resolves with the authorization code once the callback fires.
    pub code_rx: oneshot::Receiver<Result<String, ExtensionError>>,
    /// Keeps the callback server task alive; abort on drop of the flow.
    pub server_handle: tokio::task::JoinHandle<()>,
    /// PKCE verifier — secret material, never leaves the host process.
    /// `pub` so the API layer can finish a flow explicitly; treat as
    /// credential-adjacent.
    #[doc(hidden)]
    pub verifier: Zeroizing<String>,
    #[doc(hidden)]
    pub client_id: String,
    #[doc(hidden)]
    pub token_url: String,
}

/// Begin a PKCE flow: bind the loopback callback, build the auth URL and
/// spawn the callback server. Does NOT open a browser — callers that want
/// the desktop UX call [`open_authorize_url`].
pub async fn begin_pkce_flow(
    oauth: &OAuthTemplate,
    client_id: &str,
) -> ExtensionResult<StartedPkceFlow> {
    let pkce = generate_pkce();
    let state = generate_state();

    // Find an available port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| ExtensionError::OAuth(format!("Failed to bind localhost: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| ExtensionError::OAuth(format!("Failed to get port: {e}")))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    info!("OAuth callback server listening on port {port}");

    // Build authorization URL
    let scopes = oauth.scopes.join(" ");
    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        oauth.auth_url,
        urlencoding_encode(client_id),
        urlencoding_encode(&redirect_uri),
        urlencoding_encode(&scopes),
        urlencoding_encode(&state),
        urlencoding_encode(&pkce.challenge),
    );

    let (code_tx, code_rx) = oneshot::channel::<Result<String, ExtensionError>>();
    let code_tx = Arc::new(Mutex::new(Some(code_tx)));
    let expected_state = state.clone();

    // Spawn callback handler
    let server = axum::Router::new().route(
        "/callback",
        axum::routing::get({
            let code_tx = code_tx.clone();
            move |query: axum::extract::Query<CallbackParams>| {
                let code_tx = code_tx.clone();
                let expected_state = expected_state.clone();
                async move {
                    if query.state != expected_state {
                        let _ = code_tx.lock().await.take().map(|tx| {
                            let _ = tx.send(Err(ExtensionError::OAuth(
                                "invalid state parameter".to_string(),
                            )));
                        });
                        return axum::response::Html(
                            "<h1>Error</h1><p>Invalid state parameter. Possible CSRF attack.</p>"
                                .to_string(),
                        );
                    }
                    if let Some(ref error) = query.error {
                        let _ = code_tx.lock().await.take().map(|tx| {
                            let _ = tx.send(Err(ExtensionError::OAuth(format!(
                                "provider returned error: {error}"
                            ))));
                        });
                        return axum::response::Html(format!(
                            "<h1>Error</h1><p>OAuth error: {error}</p>"
                        ));
                    }
                    if let Some(ref code) = query.code {
                        if let Some(tx) = code_tx.lock().await.take() {
                            let _ = tx.send(Ok(code.clone()));
                        }
                        axum::response::Html(
                            "<h1>Success!</h1><p>Authorization complete. You can close this tab.</p><script>window.close()</script>"
                                .to_string(),
                        )
                    } else {
                        axum::response::Html(
                            "<h1>Error</h1><p>No authorization code received.</p>".to_string(),
                        )
                    }
                }
            }
        }),
    );

    let server_handle = tokio::spawn(async move {
        axum::serve(listener, server).await.ok();
    });

    Ok(StartedPkceFlow {
        auth_url,
        redirect_uri,
        state,
        callback_port: port,
        code_rx,
        server_handle,
        verifier: pkce.verifier,
        client_id: client_id.to_string(),
        token_url: oauth.token_url.clone(),
    })
}

/// Exchange an authorization code for tokens. Separated from the callback
/// wait so tests and non-browser flows (device hand-off, mock providers)
/// can complete a started flow explicitly.
pub async fn finish_pkce_flow(flow: &StartedPkceFlow, code: &str) -> ExtensionResult<OAuthTokens> {
    debug!("Exchanging authorization code for tokens...");
    exchange_code(
        &flow.token_url,
        &flow.redirect_uri,
        &flow.client_id,
        flow.verifier.as_str(),
        code,
    )
    .await
}

/// Low-level code→token exchange against `token_url`. Exposed so a consent
/// flow stored host-side (API `oauth/complete`) can finish without holding
/// the whole [`StartedPkceFlow`].
pub async fn exchange_code(
    token_url: &str,
    redirect_uri: &str,
    client_id: &str,
    code_verifier: &str,
    code: &str,
) -> ExtensionResult<OAuthTokens> {
    let client = reqwest::Client::new();
    let mut params = HashMap::new();
    params.insert("grant_type", "authorization_code");
    params.insert("code", code);
    params.insert("redirect_uri", redirect_uri);
    params.insert("client_id", client_id);
    params.insert("code_verifier", code_verifier);

    let resp = client
        .post(token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| ExtensionError::OAuth(format!("Token exchange request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(ExtensionError::OAuth(format!(
            "Token exchange failed ({}): {}",
            status, body
        )));
    }

    let tokens: OAuthTokens = resp
        .json()
        .await
        .map_err(|e| ExtensionError::OAuth(format!("Token response parse failed: {e}")))?;

    info!(
        "OAuth tokens obtained (expires_in: {}s, scopes: {})",
        tokens.expires_in, tokens.scope
    );
    Ok(tokens)
}

/// Open `url` in the user's default browser; failure is non-fatal (the URL
/// is also returned/logged for manual open).
pub fn open_authorize_url(url: &str) {
    if let Err(e) = open_browser(url) {
        warn!("Could not open browser: {e}");
        eprintln!("\nPlease open this URL in your browser:\n{url}\n");
    }
}

/// Run the complete OAuth2 PKCE flow for a given template.
///
/// 1. Start localhost callback server on a random port.
/// 2. Open browser to authorization URL.
/// 3. Wait for callback with authorization code.
/// 4. Exchange code for tokens.
/// 5. Return tokens.
pub async fn run_pkce_flow(oauth: &OAuthTemplate, client_id: &str) -> ExtensionResult<OAuthTokens> {
    let mut flow = begin_pkce_flow(oauth, client_id).await?;
    info!("Opening browser for OAuth authorization...");
    open_authorize_url(&flow.auth_url);

    let code = tokio::time::timeout(std::time::Duration::from_secs(300), &mut flow.code_rx)
        .await
        .map_err(|_| ExtensionError::OAuth("OAuth flow timed out after 5 minutes".to_string()))?
        .map_err(|_| ExtensionError::OAuth("Callback channel closed".to_string()))??;

    // Shut down callback server
    flow.server_handle.abort();

    finish_pkce_flow(&flow, &code).await
}

/// Callback query parameters.
#[derive(Deserialize)]
struct CallbackParams {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: String,
    #[serde(default)]
    error: Option<String>,
}

/// Simple percent-encoding for URL parameters.
fn urlencoding_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", byte));
            }
        }
    }
    result
}

/// Open a URL in the default browser.
fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_generation() {
        let pkce = generate_pkce();
        assert!(!pkce.verifier.is_empty());
        assert!(!pkce.challenge.is_empty());
        // Verifier and challenge should be different
        assert_ne!(pkce.verifier.as_str(), &pkce.challenge);
    }

    #[test]
    fn pkce_challenge_is_sha256() {
        let pkce = generate_pkce();
        // Verify: challenge = base64url(sha256(verifier))
        let mut hasher = Sha256::new();
        hasher.update(pkce.verifier.as_bytes());
        let digest = hasher.finalize();
        let expected = base64_url_encode(&digest);
        assert_eq!(pkce.challenge, expected);
    }

    #[test]
    fn state_randomness() {
        let s1 = generate_state();
        let s2 = generate_state();
        assert_ne!(s1, s2);
    }

    #[test]
    fn urlencoding_basic() {
        assert_eq!(urlencoding_encode("hello"), "hello");
        assert_eq!(urlencoding_encode("hello world"), "hello%20world");
        assert_eq!(urlencoding_encode("a=b&c=d"), "a%3Db%26c%3Dd");
    }

    #[test]
    fn default_client_ids_populated() {
        let ids = default_client_ids();
        assert!(ids.contains_key("google"));
        assert!(ids.contains_key("github"));
        assert!(ids.contains_key("microsoft"));
        assert!(ids.contains_key("slack"));
    }

    #[test]
    fn resolve_client_ids_uses_defaults() {
        let config = t3rnel_types::config::OAuthConfig::default();
        let ids = resolve_client_ids(&config);
        assert_eq!(ids["google"], "t3rnel-google-client-id");
        assert_eq!(ids["github"], "t3rnel-github-client-id");
    }

    #[test]
    fn resolve_client_ids_applies_overrides() {
        let config = t3rnel_types::config::OAuthConfig {
            google_client_id: Some("my-real-google-id".into()),
            github_client_id: None,
            microsoft_client_id: Some("my-msft-id".into()),
            slack_client_id: None,
        };
        let ids = resolve_client_ids(&config);
        assert_eq!(ids["google"], "my-real-google-id");
        assert_eq!(ids["github"], "t3rnel-github-client-id"); // default
        assert_eq!(ids["microsoft"], "my-msft-id");
        assert_eq!(ids["slack"], "t3rnel-slack-client-id"); // default
    }
}
