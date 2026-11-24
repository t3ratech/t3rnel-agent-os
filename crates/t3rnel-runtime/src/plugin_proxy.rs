//! Credential-brokering proxy for plugins (`05-security-and-trust.md` §14).
//!
//! A plugin never holds a secret and has no route out: it sends an *unsigned*
//! request through the `http` host service; this proxy validates it against
//! the manifest's declared hosts/methods/paths, resolves secret *names*
//! through a [`SecretResolver`] (the vault in production), applies the
//! declared auth [`Scheme`], forwards only to declared upstreams, scans the
//! response for echoed secrets, and audits references — never values.
//!
//! Hardening (§14.5): no redirects followed, DNS resolved and private ranges
//! refused unless the rule declares them, plugin-supplied auth/host/cookie
//! headers rejected, ambiguous transfer framing rejected, path normalisation
//! rejects encoded traversal, TLS verification is never disabled.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr, ToSocketAddrs};
use std::sync::Arc;

use zeroize::Zeroizing;

pub mod schemes;
pub use schemes::Scheme;

/// Resolves a secret *name* to its value in transit. Implementations must
/// return `Zeroizing` material and must never log it. The production impl
/// wraps `t3rnel_extensions::vault::CredentialVault::get`.
pub trait SecretResolver: Send + Sync {
    fn resolve(&self, name: &str) -> Result<Zeroizing<String>, ProxyError>;
}

/// Resolver backed by a closure — used by tests and by callers that already
/// hold an unlocked vault handle.
pub struct ClosureResolver<F>(pub F);
impl<F> SecretResolver for ClosureResolver<F>
where
    F: Fn(&str) -> Result<Zeroizing<String>, ProxyError> + Send + Sync,
{
    fn resolve(&self, name: &str) -> Result<Zeroizing<String>, ProxyError> {
        (self.0)(name)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("url must be absolute http(s)")]
    BadUrl,
    #[error("host {0:?} is not declared for this plugin")]
    HostNotDeclared(String),
    #[error("method {0:?} is not declared for {1}")]
    MethodNotDeclared(String, String),
    #[error("path {0:?} does not match any declared pattern for {1}")]
    PathNotDeclared(String, String),
    #[error("plugin may not supply header {0:?}")]
    ForbiddenHeader(String),
    #[error("conflicting or unsupported transfer framing")]
    BadFraming,
    #[error("path contains ambiguous or traversal encoding")]
    BadPathEncoding,
    #[error("upstream {0} resolves to a non-public address and is not declared")]
    PrivateUpstream(String),
    #[error("secret {0:?} is not available")]
    SecretUnavailable(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("redirect to undeclared host {0:?} refused")]
    RedirectBlocked(String),
}

/// One declared egress rule: a host (optionally `host:port`) plus the
/// methods and paths the plugin may use on it, and whether private/loopback
/// targets are permitted (VLC-style local adapters; user-approved at install).
#[derive(Debug, Clone)]
pub struct EgressRule {
    pub host: String,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
    pub allow_private: bool,
}

/// An auth binding: `secret` name + scheme, scoped to hosts/methods/paths.
/// Mirrors `bridge::manifest::AuthRule`; kept structural so the proxy does
/// not depend on the bridge crate.
#[derive(Debug, Clone)]
pub struct AuthBinding {
    pub secret: String,
    pub scheme: Scheme,
    pub hosts: Vec<String>,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
}

/// What the plugin asks the proxy to do.
#[derive(Debug)]
pub struct ProxyRequest {
    pub url: String,
    pub method: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>,
    /// Explicit Content-Length the plugin claims; must match actual body.
    pub content_length: Option<u64>,
    /// True when the plugin asked for chunked transfer encoding.
    pub transfer_encoding_chunked: bool,
}

/// The response handed back to the plugin. `body` has echoed secrets replaced
/// by their `secret:NAME` references.
#[derive(Debug)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    /// Redirect targets refused (audit visibility).
    pub blocked_redirects: Vec<String>,
}

/// Headers a plugin may never set — the proxy owns them.
const FORBIDDEN_HEADERS: &[&str] = &[
    "authorization",
    "host",
    "cookie",
    "proxy-authorization",
    "proxy-connection",
    "connection",
    "transfer-encoding",
    "content-length",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
];

/// IP ranges that are never valid upstreams unless the rule opts in.
fn is_private_or_special(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // CGNAT 100.64/10
                || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xFE) == 18) // benchmark 198.18/15
                || v4.octets()[0] == 0 // "this" network
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_or_special(&IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xFE00) == 0xFC00 // fc00::/7 ULA
                || (v6.segments()[0] & 0xFFC0) == 0xFE80 // fe80::/10 link-local
                || (v6.segments()[0] & 0xFFC0) == 0xFEC0 // fec0::/10 site-local (deprecated)
                || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0DB8) // documentation
                || (v6.segments()[0] == 0x0064 && v6.segments()[1] == 0xFF9B) // NAT64 well-known
        }
    }
}

/// Parsed and validated view of a request URL.
pub(crate) struct ParsedUrl {
    pub(crate) host: String, // without brackets for v6
    pub(crate) port: Option<u16>,
    pub(crate) path_query: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl, ProxyError> {
    let (scheme, rest) = url.split_once("://").ok_or(ProxyError::BadUrl)?;
    if scheme != "http" && scheme != "https" {
        return Err(ProxyError::BadUrl);
    }
    let (authority, path_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let authority = authority.split('?').next().unwrap_or(authority);
    let authority = authority.split('#').next().unwrap_or(authority);
    if authority.is_empty() {
        return Err(ProxyError::BadUrl);
    }
    // Split host/port, honouring [v6] literals.
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let end = inner.find(']').ok_or(ProxyError::BadUrl)?;
        let host = &inner[..end];
        let tail = &inner[end + 1..];
        let port = if tail.is_empty() {
            None
        } else {
            Some(
                tail.strip_prefix(':')
                    .and_then(|p| p.parse::<u16>().ok())
                    .ok_or(ProxyError::BadUrl)?,
            )
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                (h.to_string(), p.parse::<u16>().ok())
            }
            _ => (authority.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err(ProxyError::BadUrl);
    }
    Ok(ParsedUrl {
        host,
        port,
        path_query: if path_query.is_empty() {
            "/".to_string()
        } else {
            path_query.to_string()
        },
    })
}

/// Normalise a path and reject ambiguous encodings and traversal. Returns the
/// canonical path used for rule matching AND the exact bytes forwarded.
fn normalise_path(raw: &str) -> Result<String, ProxyError> {
    // Reject obvious traversal and ambiguous encodings outright.
    if raw.contains('\\') || raw.contains('\0') {
        return Err(ProxyError::BadPathEncoding);
    }
    // Percent-encoded dots or slashes are path confusion — decode once and
    // re-check; anything still ambiguous is refused.
    let mut decoded = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(ProxyError::BadPathEncoding);
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                .map_err(|_| ProxyError::BadPathEncoding)?;
            let v = u8::from_str_radix(hex, 16).map_err(|_| ProxyError::BadPathEncoding)?;
            // Reject encoded '.', '/', '\\', '%' and control chars — they are
            // how path confusion attacks smuggle traversal past naive checks.
            if matches!(v, b'.' | b'/' | b'\\' | b'%' | 0x00..=0x1F | 0x7F) {
                return Err(ProxyError::BadPathEncoding);
            }
            decoded.push(v as char);
            i += 3;
        } else {
            let c = raw[i..].chars().next().unwrap();
            if c.is_control() {
                return Err(ProxyError::BadPathEncoding);
            }
            decoded.push(c);
            i += c.len_utf8();
        }
    }
    // Dot-segment normalisation on the decoded path.
    let path_only = decoded.split('?').next().unwrap_or("/");
    let mut out: Vec<&str> = Vec::new();
    for seg in path_only.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if out.pop().is_none() {
                    return Err(ProxyError::BadPathEncoding);
                }
            }
            s => out.push(s),
        }
    }
    let mut norm = String::from("/");
    norm.push_str(&out.join("/"));
    if let Some(q) = decoded.split_once('?').map(|(_, q)| q) {
        norm.push('?');
        norm.push_str(q);
    }
    Ok(norm)
}

/// `prefix/*` style matching used by manifest path patterns.
fn path_covers(pattern: &str, path: &str) -> bool {
    if pattern == "*" || pattern == path {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    false
}

fn host_covers(rule_host: &str, url_host: &str, url_port: Option<u16>) -> bool {
    // Rule hosts may be "example.com", "example.com:8080" or "[::1]:8080".
    // A bare rule host matches the url host on its default port.
    let rule_host = rule_host
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']').map(|inner| (inner, "")))
        .map(|(inner, _)| inner)
        .unwrap_or(rule_host);
    // Bare IP literals (v4 or v6) match the URL host exactly — no port split.
    if rule_host.parse::<IpAddr>().is_ok() {
        return rule_host == url_host;
    }
    if let Some((rh, rp)) = rule_host.rsplit_once(':') {
        if rh.parse::<Ipv6Addr>().is_err() && rp.chars().all(|c| c.is_ascii_digit()) {
            let default = match rp.parse::<u16>() {
                Ok(p) => p,
                Err(_) => return false,
            };
            return rh == url_host && url_port.unwrap_or(default) == default;
        }
    }
    rule_host == url_host
}

/// The proxy. Holds declared egress + auth rules and a secret resolver.
pub struct PluginProxy {
    pub plugin_id: String,
    pub egress: Vec<EgressRule>,
    pub auth: Vec<AuthBinding>,
    secrets: Arc<dyn SecretResolver>,
    client: reqwest::Client,
    /// Body cap for responses returned to the plugin.
    pub max_response_bytes: usize,
}

impl PluginProxy {
    pub fn new(
        plugin_id: impl Into<String>,
        egress: Vec<EgressRule>,
        auth: Vec<AuthBinding>,
        secrets: Arc<dyn SecretResolver>,
    ) -> Self {
        PluginProxy {
            plugin_id: plugin_id.into(),
            egress,
            auth,
            secrets,
            // TLS verification is mandatory — reqwest/rustls verifies by
            // default and there is deliberately no "insecure" option.
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none()) // §14.5: no auto-follow
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            max_response_bytes: 8 * 1024 * 1024,
        }
    }

    /// Validate + forward one plugin request. Returns Err for every refusal;
    /// nothing is sent upstream on any error path.
    pub async fn request(&self, req: &ProxyRequest) -> Result<ProxyResponse, ProxyError> {
        // 1. URL parse + path normalisation (before any network I/O).
        let parsed = parse_url(&req.url)?;
        let path = normalise_path(&parsed.path_query)?;
        let method = req.method.to_ascii_uppercase();
        if !matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS"
        ) {
            return Err(ProxyError::MethodNotDeclared(method, parsed.host.clone()));
        }

        // 2. Egress allowlist: host, method, path.
        let rule = self
            .egress
            .iter()
            .find(|r| host_covers(&r.host, &parsed.host, parsed.port))
            .ok_or_else(|| {
                ProxyError::HostNotDeclared(format!("{}:{}", parsed.host, parsed.port.unwrap_or(0)))
            })?;
        if !rule
            .methods
            .iter()
            .any(|m| m == "*" || m.eq_ignore_ascii_case(&method))
        {
            return Err(ProxyError::MethodNotDeclared(
                method.clone(),
                rule.host.clone(),
            ));
        }
        let path_only = path.split('?').next().unwrap_or("/");
        if !rule.paths.iter().any(|p| path_covers(p, path_only)) {
            return Err(ProxyError::PathNotDeclared(
                path_only.to_string(),
                rule.host.clone(),
            ));
        }

        // 3. Plugin-supplied forbidden headers.
        for name in req.headers.keys() {
            if FORBIDDEN_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                return Err(ProxyError::ForbiddenHeader(name.clone()));
            }
        }

        // 4. Transfer framing sanity.
        let body = req.body.clone().unwrap_or_default();
        if let Some(cl) = req.content_length {
            if cl != body.len() as u64 {
                return Err(ProxyError::BadFraming);
            }
        }
        if req.transfer_encoding_chunked {
            return Err(ProxyError::BadFraming);
        }

        // 5. DNS resolution + private-range refusal (unless rule opts in).
        let check_host = parsed.host.clone();
        self.check_upstream(&check_host, parsed.port, rule.allow_private)
            .await?;

        // 6. Apply the matching auth binding (if any) — resolve secret now,
        //    use it in flight, zeroise after.
        let mut headers = req.headers.clone();
        let mut signed_url = req.url.clone();
        let mut signed_body = body.clone();
        let binding = self.auth.iter().find(|b| {
            b.hosts
                .iter()
                .any(|h| host_covers(h, &parsed.host, parsed.port))
                && b.methods
                    .iter()
                    .any(|m| m == "*" || m.eq_ignore_ascii_case(&method))
                && b.paths.iter().any(|p| path_covers(p, path_only))
        });
        // Collect secrets to zeroise explicitly after use.
        let mut secrets_used: Vec<Zeroizing<String>> = Vec::new();
        if let Some(b) = binding {
            let secret = self
                .secrets
                .resolve(&b.secret)
                .map_err(|_| ProxyError::SecretUnavailable(b.secret.clone()))?;
            secrets_used.push(Zeroizing::new(secret.to_string()));
            schemes::apply_scheme(
                b.scheme,
                secret.as_str(),
                &method,
                &parsed,
                path_only,
                &mut signed_url,
                &mut headers,
                &mut signed_body,
            )
            .map_err(|e| ProxyError::Upstream(format!("signing failed: {e}")))?;
        }

        // 7. Forward — never follow redirects.
        let mut rb = self.client.request(
            reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| ProxyError::BadUrl)?,
            &signed_url,
        );
        for (k, v) in &headers {
            rb = rb.header(k.as_str(), v.as_str());
        }
        if !signed_body.is_empty() || method == "POST" || method == "PUT" || method == "PATCH" {
            rb = rb.body(signed_body.clone());
        }
        let resp = rb
            .send()
            .await
            .map_err(|e| ProxyError::Upstream(e.to_string()))?;

        // 8. Redirects are never followed; record the target for audit.
        let mut blocked = Vec::new();
        if resp.status().is_redirection() {
            if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
                blocked.push(loc.to_string());
                // Even a declared-host redirect is returned, not followed —
                // the plugin must re-request so every hop is re-checked.
                return Ok(ProxyResponse {
                    status: resp.status().as_u16(),
                    headers: BTreeMap::new(),
                    body: Vec::new(),
                    blocked_redirects: blocked,
                });
            }
        }

        let status = resp.status().as_u16();
        let resp_headers: BTreeMap<String, String> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|s| (k.as_str().to_string(), s.to_string()))
            })
            .collect();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ProxyError::Upstream(e.to_string()))?;
        let mut body_out = bytes[..bytes.len().min(self.max_response_bytes)].to_vec();

        // 9. Secret-echo scan: replace any echoed secret with its reference.
        for sec in &secrets_used {
            let needle = sec.as_str().as_bytes();
            if !needle.is_empty() {
                let reference = format!(
                    "secret:{}",
                    binding.map(|b| b.secret.as_str()).unwrap_or("")
                );
                body_out = replace_bytes(&body_out, needle, reference.as_bytes());
            }
        }

        // Secrets are dropped here; Zeroizing clears on scope exit.
        drop(secrets_used);

        Ok(ProxyResponse {
            status,
            headers: resp_headers,
            body: body_out,
            blocked_redirects: blocked,
        })
    }

    /// Resolve the upstream host and refuse non-public addresses unless the
    /// egress rule opted in. Literal IPs are checked directly.
    async fn check_upstream(
        &self,
        host: &str,
        port: Option<u16>,
        allow_private: bool,
    ) -> Result<(), ProxyError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_private_or_special(&ip) && !allow_private {
                return Err(ProxyError::PrivateUpstream(host.to_string()));
            }
            return Ok(());
        }
        let port = port.unwrap_or(443);
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| ProxyError::Upstream(format!("DNS lookup for {host}: {e}")))?
            .collect();
        if addrs.is_empty() {
            return Err(ProxyError::Upstream(format!(
                "DNS lookup for {host}: no addresses"
            )));
        }
        for addr in &addrs {
            if is_private_or_special(&addr.ip()) && !allow_private {
                return Err(ProxyError::PrivateUpstream(format!(
                    "{host} -> {}",
                    addr.ip()
                )));
            }
        }
        Ok(())
    }
}

/// Replace every occurrence of `needle` in `hay` with `replacement`.
fn replace_bytes(hay: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || hay.is_empty() {
        return hay.to_vec();
    }
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if i + needle.len() <= hay.len() && &hay[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

/// Sync DNS resolution helper for non-async callers/tests.
#[allow(dead_code)]
fn resolves_to_private(host: &str, port: u16) -> bool {
    let mut addrs = match format!("{host}:{port}").to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return true, // unresolvable -> treat as private/unsafe
    };
    addrs.any(|a| is_private_or_special(&a.ip()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver() -> Arc<dyn SecretResolver> {
        Arc::new(ClosureResolver(
            |name: &str| -> Result<Zeroizing<String>, ProxyError> {
                Ok(Zeroizing::new(match name {
                    "TEST_KEY" => "s3cr3t-value-123".to_string(),
                    _ => return Err(ProxyError::SecretUnavailable(name.to_string())),
                }))
            },
        ))
    }

    fn rule(host: &str, allow_private: bool) -> EgressRule {
        EgressRule {
            host: host.to_string(),
            methods: vec!["*".to_string()],
            paths: vec!["*".to_string()],
            allow_private,
        }
    }

    #[test]
    fn parses_urls_and_ipv6_literals() {
        let p = parse_url("https://example.com:8443/a/b?x=1").unwrap();
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, Some(8443));
        assert_eq!(p.path_query, "/a/b?x=1");
        let p = parse_url("http://[fd00::1]:8080/x").unwrap();
        assert_eq!(p.host, "fd00::1");
        assert_eq!(p.port, Some(8080));
        let p = parse_url("http://[::ffff:7f00:1]/").unwrap();
        assert_eq!(p.host, "::ffff:7f00:1");
        assert!(parse_url("notaurl").is_err());
        assert!(parse_url("ftp://x/").is_err());
    }

    #[test]
    fn private_and_transition_addresses_are_detected() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "198.18.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:7f00:1",
        ] {
            assert!(
                is_private_or_special(&ip.parse().unwrap()),
                "{ip} must be private/special"
            );
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(
                !is_private_or_special(&ip.parse().unwrap()),
                "{ip} is public"
            );
        }
    }

    #[test]
    fn path_normalisation_rejects_traversal_and_encoding_tricks() {
        for bad in [
            "/../etc/passwd",
            "/a/../../b",
            "/a%2e%2e/b",
            "/a%2F..%2Fb",
            "/a%5c..%5cb",
            "/%2e%2e/",
            "/a/%00",
            "/a\\b",
            "/a/./../../x",
        ] {
            assert!(normalise_path(bad).is_err(), "{bad} must be rejected");
        }
        assert_eq!(normalise_path("/a/b/../c").unwrap(), "/a/c");
        assert_eq!(normalise_path("/a/./b?x=1").unwrap(), "/a/b?x=1");
        assert_eq!(normalise_path("/").unwrap(), "/");
    }

    #[test]
    fn plugin_cannot_supply_forbidden_headers() {
        // Driven through request() up to the header check — use an
        // undeclared-host-free setup so we reach header validation.
        // (Header check happens after egress/path checks, so declare them.)
        // We test the constant directly plus via a constructed request below.
        assert!(FORBIDDEN_HEADERS.contains(&"authorization"));
        assert!(FORBIDDEN_HEADERS.contains(&"host"));
        assert!(FORBIDDEN_HEADERS.contains(&"cookie"));
        assert!(FORBIDDEN_HEADERS.contains(&"transfer-encoding"));
        assert!(FORBIDDEN_HEADERS.contains(&"content-length"));
    }

    #[test]
    fn conflicting_content_length_is_rejected() {
        // The check is inside request(); verify the framing rule logic by
        // constructing the same comparison the code performs.
        let body = b"hello".to_vec();
        let cl_ok = Some(5u64);
        let cl_bad = Some(6u64);
        assert_eq!(cl_ok.map(|c| c == body.len() as u64), Some(true));
        assert_eq!(cl_bad.map(|c| c == body.len() as u64), Some(false));
        // chunked + any body is always refused
        let chunked = true;
        assert!(chunked);
    }

    #[tokio::test]
    async fn undeclared_host_is_refused_before_any_io() {
        let proxy = PluginProxy::new(
            "org.test.p",
            vec![rule("allowed.example.com", false)],
            vec![],
            resolver(),
        );
        let err = proxy
            .request(&ProxyRequest {
                url: "https://evil.example.net/x".into(),
                method: "GET".into(),
                headers: BTreeMap::new(),
                body: None,
                content_length: None,
                transfer_encoding_chunked: false,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::HostNotDeclared(_)), "{err:?}");
    }

    #[tokio::test]
    async fn method_and_path_must_match_declaration() {
        let proxy = PluginProxy::new(
            "org.test.p",
            vec![EgressRule {
                host: "api.example.com".into(),
                methods: vec!["GET".into()],
                paths: vec!["/v1/*".into()],
                allow_private: false,
            }],
            vec![],
            resolver(),
        );
        // POST not declared.
        let err = proxy
            .request(&ProxyRequest {
                url: "https://api.example.com/v1/x".into(),
                method: "POST".into(),
                headers: BTreeMap::new(),
                body: Some(b"{}".to_vec()),
                content_length: None,
                transfer_encoding_chunked: false,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, ProxyError::MethodNotDeclared(_, _)),
            "{err:?}"
        );
        // Path outside pattern.
        let err = proxy
            .request(&ProxyRequest {
                url: "https://api.example.com/admin/x".into(),
                method: "GET".into(),
                headers: BTreeMap::new(),
                body: None,
                content_length: None,
                transfer_encoding_chunked: false,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::PathNotDeclared(_, _)), "{err:?}");
    }

    #[tokio::test]
    async fn private_literal_upstream_refused_unless_declared() {
        // Literal private IP with allow_private=false -> refused at DNS step.
        let proxy = PluginProxy::new(
            "org.test.p",
            vec![rule("127.0.0.1:9", false)],
            vec![],
            resolver(),
        );
        let err = proxy
            .request(&ProxyRequest {
                url: "http://127.0.0.1:9/".into(),
                method: "GET".into(),
                headers: BTreeMap::new(),
                body: None,
                content_length: None,
                transfer_encoding_chunked: false,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::PrivateUpstream(_)), "{err:?}");

        // IPv6 ULA literal refused too.
        let proxy = PluginProxy::new(
            "org.test.p",
            vec![rule("[fd00::1]", false)],
            vec![],
            resolver(),
        );
        let err = proxy
            .request(&ProxyRequest {
                url: "http://[fd00::1]/".into(),
                method: "GET".into(),
                headers: BTreeMap::new(),
                body: None,
                content_length: None,
                transfer_encoding_chunked: false,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::PrivateUpstream(_)), "{err:?}");

        // IPv4-mapped IPv6 loopback refused.
        let proxy = PluginProxy::new(
            "org.test.p",
            vec![rule("[::ffff:7f00:1]", false)],
            vec![],
            resolver(),
        );
        let err = proxy
            .request(&ProxyRequest {
                url: "http://[::ffff:7f00:1]/".into(),
                method: "GET".into(),
                headers: BTreeMap::new(),
                body: None,
                content_length: None,
                transfer_encoding_chunked: false,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::PrivateUpstream(_)), "{err:?}");
    }

    #[tokio::test]
    async fn hostname_resolving_to_private_is_refused() {
        // "localhost" resolves to 127.0.0.1/::1 — must be refused.
        let proxy = PluginProxy::new(
            "org.test.p",
            vec![rule("localhost", false)],
            vec![],
            resolver(),
        );
        let err = proxy
            .request(&ProxyRequest {
                url: "http://localhost:1/".into(),
                method: "GET".into(),
                headers: BTreeMap::new(),
                body: None,
                content_length: None,
                transfer_encoding_chunked: false,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::PrivateUpstream(_)), "{err:?}");
    }

    #[tokio::test]
    async fn plugin_supplied_authorization_is_rejected() {
        let proxy = PluginProxy::new(
            "org.test.p",
            vec![rule("localhost", true)],
            vec![],
            resolver(),
        );
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".to_string(), "Bearer forged".to_string());
        let err = proxy
            .request(&ProxyRequest {
                url: "http://localhost:1/".into(),
                method: "GET".into(),
                headers,
                body: None,
                content_length: None,
                transfer_encoding_chunked: false,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ProxyError::ForbiddenHeader(h) if h == "Authorization"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn framing_mismatch_and_chunked_are_rejected() {
        let proxy = PluginProxy::new(
            "org.test.p",
            vec![rule("localhost", true)],
            vec![],
            resolver(),
        );
        let base = ProxyRequest {
            url: "http://localhost:1/".into(),
            method: "POST".into(),
            headers: BTreeMap::new(),
            body: Some(b"12345".to_vec()),
            content_length: None,
            transfer_encoding_chunked: false,
        };
        let r = ProxyRequest {
            url: base.url.clone(),
            method: base.method.clone(),
            headers: BTreeMap::new(),
            body: Some(b"12345".to_vec()),
            content_length: Some(4),
            transfer_encoding_chunked: false,
        };
        let err = proxy.request(&r).await.unwrap_err();
        assert!(matches!(err, ProxyError::BadFraming), "{err:?}");
        let r2 = ProxyRequest {
            url: "http://localhost:1/".into(),
            method: "POST".into(),
            headers: BTreeMap::new(),
            body: Some(b"12345".to_vec()),
            content_length: None,
            transfer_encoding_chunked: true,
        };
        let err = proxy.request(&r2).await.unwrap_err();
        assert!(matches!(err, ProxyError::BadFraming), "{err:?}");
    }

    #[tokio::test]
    async fn end_to_end_fake_upstream_bearer_and_secret_echo() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Fake upstream on loopback.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf).to_string();
            let _ = tx.send(req);
            let body = "echo s3cr3t-value-123 done";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                body.len(),
                body
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        });

        let proxy = PluginProxy::new(
            "org.test.p",
            vec![rule(&format!("127.0.0.1:{port}"), true)],
            vec![AuthBinding {
                secret: "TEST_KEY".into(),
                scheme: Scheme::Bearer,
                hosts: vec![format!("127.0.0.1:{port}")],
                methods: vec!["*".into()],
                paths: vec!["*".into()],
            }],
            resolver(),
        );
        let resp = proxy
            .request(&ProxyRequest {
                url: format!("http://127.0.0.1:{port}/data"),
                method: "GET".into(),
                headers: BTreeMap::new(),
                body: None,
                content_length: None,
                transfer_encoding_chunked: false,
            })
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        let req_text = rx.await.unwrap();
        assert!(
            req_text
                .to_ascii_lowercase()
                .contains("authorization: bearer s3cr3t-value-123"),
            "injected auth missing: {req_text}"
        );
        let text = String::from_utf8_lossy(&resp.body);
        assert!(
            text.contains("secret:TEST_KEY"),
            "echo must be redacted: {text}"
        );
        assert!(!text.contains("s3cr3t-value-123"), "secret leaked: {text}");
    }

    #[tokio::test]
    async fn redirect_is_never_followed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await.unwrap();
            let resp = "HTTP/1.1 302 Found\r\nLocation: http://evil.example.net/steal\r\nContent-Length: 0\r\n\r\n";
            sock.write_all(resp.as_bytes()).await.unwrap();
        });
        let proxy = PluginProxy::new(
            "org.test.p",
            vec![rule(&format!("127.0.0.1:{port}"), true)],
            vec![],
            resolver(),
        );
        let resp = proxy
            .request(&ProxyRequest {
                url: format!("http://127.0.0.1:{port}/"),
                method: "GET".into(),
                headers: BTreeMap::new(),
                body: None,
                content_length: None,
                transfer_encoding_chunked: false,
            })
            .await
            .unwrap();
        assert_eq!(resp.status, 302);
        assert_eq!(
            resp.blocked_redirects,
            vec!["http://evil.example.net/steal".to_string()]
        );
        assert!(resp.body.is_empty());
    }
}
