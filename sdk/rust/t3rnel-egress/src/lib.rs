//! `t3rnel-egress`: the credential-brokering proxy engine (`05-security-and-trust.md` §14).
//!
//! One implementation, used by the T3rnel core (as `t3rnel_runtime::plugin_proxy`) and by plugin
//! SDKs and development hosts, so the security-critical rules — URL parsing, egress matching, DNS
//! pinning, signing, redaction — can never drift between copies. Licensed Apache-2.0 so plugins can
//! link it.
//!
//! Credential-brokering proxy for plugins.
//!
//! A plugin never holds a secret and has no route out: it sends an *unsigned*
//! request through the `http` host service; this proxy validates it against
//! the manifest's declared hosts/methods/paths, resolves secret *names*
//! through a [`SecretResolver`] (the vault in production), applies the
//! declared auth [`Scheme`], forwards only to declared upstreams, scans the
//! response for echoed secrets, and audits references — never values.
//!
//! Hardening (§14.5):
//! - one URL parser (WHATWG, via `reqwest::Url`) decides host, port and path;
//!   the URL that is **forwarded** is rebuilt from exactly what was checked, so
//!   a URL that two parsers read differently cannot pass the allowlist and hit
//!   another path;
//! - userinfo (`user@host`) and fragments are refused;
//! - a rule's port is enforced (`host:8080` never matches port 443); a rule
//!   without a port matches only the scheme's default port;
//! - DNS is resolved **once**, every address is checked, and the connection is
//!   pinned to those addresses (no second lookup an attacker could change);
//! - ambient proxy variables are ignored, redirects are never followed,
//!   timeouts always apply, and request and response sizes are capped (a larger
//!   response is an error, never a silent truncation);
//! - echoed secrets are replaced by `secret:NAME` in the body, the headers and
//!   any redirect target, including their percent-encoded and base64 forms;
//! - plugin-supplied auth/host/cookie/framing headers are rejected, and TLS
//!   verification can never be disabled.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
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
    #[error("url must be absolute http(s) without credentials or a fragment")]
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
    #[error("request body exceeds the {0} byte limit")]
    RequestTooLarge(usize),
    #[error("response body exceeds the {0} byte limit")]
    ResponseTooLarge(usize),
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
    /// Permit percent-encoded slashes (`%2F`) inside a path segment. Off by default,
    /// because an encoded slash is how a path is smuggled past a prefix check. A few
    /// real APIs need it: Google Search Console takes a site or sitemap URL as one
    /// segment (`.../sitemaps/https%3A%2F%2Fexample.com%2Fsitemap.xml`). Even when
    /// allowed, encoded dots and backslashes stay refused, and a segment may not hide
    /// a dot segment behind an encoded slash (`..%2Fadmin`).
    pub allow_encoded_slash: bool,
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

/// The response handed back to the plugin. Echoed secrets are replaced by
/// their `secret:NAME` references in `body`, `headers` and `blocked_redirects`.
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

/// Headers an auth scheme may not set either: routing and framing belong to
/// the proxy. `authorization` and `cookie` stay allowed because they are the
/// legitimate carriers of a credential.
const SCHEME_FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "proxy-authorization",
    "proxy-connection",
];

/// Shortest secret the echo scan will redact. Shorter values would mangle
/// ordinary response text, and a real credential is never this short.
const MIN_REDACTABLE: usize = 4;

/// IP ranges that are never valid upstreams unless the rule opts in.
pub fn is_private_or_special(ip: &IpAddr) -> bool {
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
                || v4.octets()[0] >= 240 // reserved 240/4
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

/// Parsed and validated view of a request URL. Everything the proxy decides —
/// rule matching, DNS, signing, forwarding — comes from this one structure.
pub(crate) struct ParsedUrl {
    /// Lower-cased host; IPv6 without brackets.
    pub(crate) host: String,
    /// Explicit non-default port, if any (`:443` on https parses to `None`).
    pub(crate) port: Option<u16>,
    /// The port actually connected to.
    pub(crate) effective_port: u16,
    /// Normalised path plus query — the bytes that are matched, signed and sent.
    pub(crate) path_query: String,
    /// The full URL to forward, rebuilt from the checked parts.
    pub(crate) canonical: String,
}

/// True when any path segment of the raw URL is a dot segment, in any
/// percent-encoding. The URL parser would silently resolve these; the proxy
/// refuses them so traversal is an error, not a surprise.
fn raw_url_has_dot_segment_or_backslash(raw: &str) -> bool {
    let before_query = raw.split(['?', '#']).next().unwrap_or(raw);
    if before_query.contains('\\') {
        return true;
    }
    // Pieces are: scheme, empty, authority, then the path segments.
    before_query.split('/').enumerate().filter(|(i, _)| *i >= 3).any(|(_, seg)| {
        let decoded = seg.replace("%2e", ".").replace("%2E", ".");
        decoded == "." || decoded == ".."
    })
}

/// `parse_url_with` with the strict default (encoded slashes refused). Only the
/// test suite uses the strict shorthand; `request` picks the mode per rule.
#[cfg(test)]
fn parse_url(url: &str) -> Result<ParsedUrl, ProxyError> {
    parse_url_with(url, false)
}

/// [`parse_url_with`], optionally allowing `%2F` inside path segments (see [`EgressRule::allow_encoded_slash`]).
fn parse_url_with(url: &str, allow_encoded_slash: bool) -> Result<ParsedUrl, ProxyError> {
    // The URL parser silently deletes tabs and newlines and may mishandle NUL,
    // so what it checks would differ from what the caller wrote. Refuse them.
    if url.chars().any(|c| c.is_control()) {
        return Err(ProxyError::BadUrl);
    }
    let u = reqwest::Url::parse(url).map_err(|_| ProxyError::BadUrl)?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return Err(ProxyError::BadUrl);
    }
    if !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
        return Err(ProxyError::BadUrl);
    }
    if raw_url_has_dot_segment_or_backslash(url) {
        return Err(ProxyError::BadPathEncoding);
    }
    let host = u
        .host_str()
        .ok_or(ProxyError::BadUrl)?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    // The URL parser and Rust spell some IPv6 addresses differently
    // (::ffff:7f00:1 vs ::ffff:127.0.0.1); compare them by value.
    let host = normalise_ip_text(&host);
    if host.is_empty() {
        return Err(ProxyError::BadUrl);
    }
    let effective_port = u.port_or_known_default().ok_or(ProxyError::BadUrl)?;
    let raw_path_query = match u.query() {
        Some(q) => format!("{}?{}", u.path(), q),
        None => u.path().to_string(),
    };
    let path_query = normalise_path(&raw_path_query, allow_encoded_slash)?;
    let mut canon = u.clone();
    let (path_only, query) = match path_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_query.as_str(), None),
    };
    canon.set_path(path_only);
    canon.set_query(query);
    Ok(ParsedUrl {
        host,
        port: u.port(),
        effective_port,
        path_query,
        canonical: canon.to_string(),
    })
}

/// Normalise a path and reject ambiguous encodings and traversal. Returns the
/// canonical path used for rule matching AND the exact bytes forwarded.
///
/// Only the path is held to the strict rules: an encoded `.`, `/`, `\` or `%`
/// there is how path-confusion attacks smuggle traversal past a check, so it is
/// refused. A query string cannot change which path is requested, so it may
/// carry any percent-encoding (OAuth redirect URIs, search terms); only NUL and
/// control characters are refused there.
fn normalise_path(raw: &str, allow_encoded_slash: bool) -> Result<String, ProxyError> {
    let (path_raw, query) = match raw.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (raw, None),
    };
    if path_raw.contains('\\') || raw.contains('\0') {
        return Err(ProxyError::BadPathEncoding);
    }
    if let Some(q) = query {
        if q.chars().any(|c| c.is_control()) {
            return Err(ProxyError::BadPathEncoding);
        }
    }
    let mut checked = String::with_capacity(path_raw.len());
    let bytes = path_raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(ProxyError::BadPathEncoding);
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                .map_err(|_| ProxyError::BadPathEncoding)?;
            let v = u8::from_str_radix(hex, 16).map_err(|_| ProxyError::BadPathEncoding)?;
            let slash_ok = v == b'/' && allow_encoded_slash;
            if !slash_ok && matches!(v, b'.' | b'/' | b'\\' | b'%' | 0x00..=0x1F | 0x7F) {
                return Err(ProxyError::BadPathEncoding);
            }
            // Forwarded in its encoded form: a `%41` stays `%41` upstream.
            checked.push('%');
            checked.push_str(hex);
            i += 3;
        } else {
            let c = path_raw[i..].chars().next().unwrap();
            if c.is_control() {
                return Err(ProxyError::BadPathEncoding);
            }
            checked.push(c);
            i += c.len_utf8();
        }
    }
    let mut out: Vec<&str> = Vec::new();
    for seg in checked.split('/') {
        // A server may decode %2F before routing, turning "..%2Fadmin" into "../admin".
        // So each piece of a segment, split on an encoded slash, gets the dot-segment check too.
        if seg.contains("%2F") || seg.contains("%2f") {
            let lowered = seg.replace("%2F", "/").replace("%2f", "/");
            if lowered.split('/').any(|piece| piece == "." || piece == "..") {
                return Err(ProxyError::BadPathEncoding);
            }
        }
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
    if let Some(q) = query {
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

/// Split a rule host into (lower-cased host, optional port). Accepts
/// `example.com`, `example.com:8080`, `[::1]`, `[::1]:8080` and a bare `::1`.
fn split_rule_host(rule_host: &str) -> (String, Option<u16>) {
    let rule_host = rule_host.trim().to_ascii_lowercase();
    if let Some(inner) = rule_host.strip_prefix('[') {
        if let Some(end) = inner.find(']') {
            let host = inner[..end].to_string();
            let port = inner[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok());
            return (normalise_ip_text(&host), port);
        }
    }
    if rule_host.parse::<Ipv6Addr>().is_ok() {
        return (normalise_ip_text(&rule_host), None);
    }
    if let Some((h, p)) = rule_host.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(port) = p.parse::<u16>() {
                return (normalise_ip_text(h), Some(port));
            }
        }
    }
    (normalise_ip_text(&rule_host), None)
}

/// IP literals compare by value, not spelling.
fn normalise_ip_text(host: &str) -> String {
    host.parse::<IpAddr>()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| host.to_string())
}

/// Does a declared rule host cover this URL? A rule with a port covers exactly
/// that port; a rule without one covers only the scheme's default port.
fn host_covers(rule_host: &str, url: &ParsedUrl) -> bool {
    let (host, port) = split_rule_host(rule_host);
    if host != url.host {
        return false;
    }
    match port {
        Some(p) => p == url.effective_port,
        None => url.port.is_none(),
    }
}

/// Every form in which an upstream might echo a credential back.
fn redaction_needles(secret: &str, injected: &[String]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut forms: Vec<String> = vec![secret.to_string()];
    forms.push(schemes::urlencode(secret));
    forms.push(base64::engine::general_purpose::STANDARD.encode(secret));
    forms.push(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret));
    forms.extend(injected.iter().cloned());
    forms.sort();
    forms.dedup();
    forms
        .into_iter()
        .filter(|f| f.len() >= MIN_REDACTABLE)
        .map(|f| Zeroizing::new(f.into_bytes()))
        .collect()
}

/// Header values an auth scheme added or changed — the credential as it
/// travels (for example `Bearer xyz` or `Basic <base64>`), plus the part after
/// the scheme word.
fn injected_header_values(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (k, v) in after {
        if before.get(k) != Some(v) {
            out.push(v.clone());
            if let Some((_, rest)) = v.split_once(' ') {
                out.push(rest.to_string());
            }
        }
    }
    out
}

/// The proxy. Holds declared egress + auth rules and a secret resolver.
pub struct PluginProxy {
    pub plugin_id: String,
    pub egress: Vec<EgressRule>,
    pub auth: Vec<AuthBinding>,
    secrets: Arc<dyn SecretResolver>,
    /// Body cap for responses returned to the plugin. Larger is an error.
    pub max_response_bytes: usize,
    /// Body cap for requests sent upstream.
    pub max_request_bytes: usize,
    /// Whole-request deadline.
    pub timeout: Duration,
    /// Connection-establishment deadline.
    pub connect_timeout: Duration,
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
            max_response_bytes: 8 * 1024 * 1024,
            max_request_bytes: 8 * 1024 * 1024,
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// Build the one-shot HTTP client for a request: no redirects, no ambient
    /// proxy, TLS verification on (there is deliberately no switch), deadlines
    /// set, and the connection pinned to the addresses that were checked.
    fn client_for(
        &self,
        parsed: &ParsedUrl,
        pinned: &[SocketAddr],
    ) -> Result<reqwest::Client, ProxyError> {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(self.timeout)
            .connect_timeout(self.connect_timeout);
        if parsed.host.parse::<IpAddr>().is_err() {
            builder = builder.resolve_to_addrs(&parsed.host, pinned);
        }
        builder
            .build()
            .map_err(|e| ProxyError::Upstream(format!("http client: {e}")))
    }

    /// Validate + forward one plugin request. Returns Err for every refusal;
    /// nothing is sent upstream on any error path.
    pub async fn request(&self, req: &ProxyRequest) -> Result<ProxyResponse, ProxyError> {
        // 1. URL parse + path normalisation (before any network I/O).
        // Parse leniently first, only to learn the host and find the rule; then hold the URL
        // to the strict rules unless that rule explicitly allows encoded slashes.
        let mut parsed = parse_url_with(&req.url, true)?;
        let method = req.method.to_ascii_uppercase();
        if !matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS"
        ) {
            return Err(ProxyError::MethodNotDeclared(method, parsed.host.clone()));
        }

        // 2. Egress allowlist: host, port, method, path.
        let rule = self
            .egress
            .iter()
            .find(|r| host_covers(&r.host, &parsed))
            .ok_or_else(|| {
                ProxyError::HostNotDeclared(format!("{}:{}", parsed.host, parsed.effective_port))
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
        if !rule.allow_encoded_slash {
            parsed = parse_url_with(&req.url, false)?;
        }
        let path = parsed.path_query.clone();
        let path_only = path.split('?').next().unwrap_or("/").to_string();
        if !rule.paths.iter().any(|p| path_covers(p, &path_only)) {
            return Err(ProxyError::PathNotDeclared(path_only, rule.host.clone()));
        }

        // 3. Plugin-supplied forbidden headers.
        for name in req.headers.keys() {
            if FORBIDDEN_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                return Err(ProxyError::ForbiddenHeader(name.clone()));
            }
        }

        // 4. Transfer framing and size.
        let body = req.body.clone().unwrap_or_default();
        if body.len() > self.max_request_bytes {
            return Err(ProxyError::RequestTooLarge(self.max_request_bytes));
        }
        if let Some(cl) = req.content_length {
            if cl != body.len() as u64 {
                return Err(ProxyError::BadFraming);
            }
        }
        if req.transfer_encoding_chunked {
            return Err(ProxyError::BadFraming);
        }

        // 5. DNS once, refuse non-public addresses (unless the rule opts in),
        //    and keep the addresses for the connection.
        let pinned = self.resolve_pinned(&parsed, rule.allow_private).await?;

        // 6. Apply the matching auth binding (if any) — resolve secret now,
        //    use it in flight, zeroise after.
        let mut headers = req.headers.clone();
        let mut signed_url = parsed.canonical.clone();
        let mut signed_body = body;
        let binding = self.auth.iter().find(|b| {
            b.hosts.iter().any(|h| host_covers(h, &parsed))
                && b.methods
                    .iter()
                    .any(|m| m == "*" || m.eq_ignore_ascii_case(&method))
                && b.paths.iter().any(|p| path_covers(p, &path_only))
        });
        let mut needles: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        if let Some(b) = binding {
            let secret = self
                .secrets
                .resolve(&b.secret)
                .map_err(|_| ProxyError::SecretUnavailable(b.secret.clone()))?;
            let before = headers.clone();
            let url_before = signed_url.clone();
            schemes::apply_scheme(
                b.scheme,
                secret.as_str(),
                &method,
                &parsed,
                &mut signed_url,
                &mut headers,
                &mut signed_body,
            )
            .map_err(|e| ProxyError::Upstream(format!("signing failed: {e}")))?;
            let mut injected = injected_header_values(&before, &headers);
            if signed_url != url_before {
                // The part of the URL the scheme appended (a query credential).
                if let Some(added) = signed_url.strip_prefix(url_before.as_str()) {
                    injected.push(added.trim_start_matches(['?', '&']).to_string());
                }
                injected.push(signed_url.clone());
            }
            needles = redaction_needles(secret.as_str(), &injected);
        }

        // 7. Forward — never follow redirects, always pinned and time-boxed.
        let client = self.client_for(&parsed, &pinned)?;
        let mut rb = client.request(
            reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| ProxyError::BadUrl)?,
            &signed_url,
        );
        for (k, v) in &headers {
            rb = rb.header(k.as_str(), v.as_str());
        }
        if !signed_body.is_empty() || method == "POST" || method == "PUT" || method == "PATCH" {
            rb = rb.body(signed_body.clone());
        }
        let mut resp = rb
            .send()
            .await
            .map_err(|e| ProxyError::Upstream(redact_text(&e.to_string(), &needles, binding)))?;

        let status = resp.status().as_u16();
        let reference = binding.map(|b| format!("secret:{}", b.secret));

        // 8. Redirects are never followed; the target is reported (scrubbed)
        //    so the plugin must re-request and every hop is re-checked.
        if resp.status().is_redirection() {
            if let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) {
                return Ok(ProxyResponse {
                    status,
                    headers: BTreeMap::new(),
                    body: Vec::new(),
                    blocked_redirects: vec![redact_with(loc, &needles, reference.as_deref())],
                });
            }
        }

        let resp_headers: BTreeMap<String, String> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str().ok().map(|s| {
                    (
                        k.as_str().to_string(),
                        redact_with(s, &needles, reference.as_deref()),
                    )
                })
            })
            .collect();

        // Stream the body so the cap bounds memory, not just what is returned.
        let mut body_out: Vec<u8> = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| ProxyError::Upstream(redact_text(&e.to_string(), &needles, binding)))?
        {
            if body_out.len() + chunk.len() > self.max_response_bytes {
                return Err(ProxyError::ResponseTooLarge(self.max_response_bytes));
            }
            body_out.extend_from_slice(&chunk);
        }

        // 9. Secret-echo scan on the body.
        if let Some(reference) = &reference {
            for needle in &needles {
                body_out = replace_bytes(&body_out, needle, reference.as_bytes());
            }
        }

        Ok(ProxyResponse {
            status,
            headers: resp_headers,
            body: body_out,
            blocked_redirects: Vec::new(),
        })
    }

    /// Resolve the upstream host once, refuse non-public addresses unless the
    /// egress rule opted in, and return the addresses the connection must use.
    async fn resolve_pinned(
        &self,
        parsed: &ParsedUrl,
        allow_private: bool,
    ) -> Result<Vec<SocketAddr>, ProxyError> {
        let host = parsed.host.as_str();
        let port = parsed.effective_port;
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_private_or_special(&ip) && !allow_private {
                return Err(ProxyError::PrivateUpstream(host.to_string()));
            }
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
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
        Ok(addrs)
    }
}

/// Replace every needle in `text` with the secret's reference.
fn redact_with(text: &str, needles: &[Zeroizing<Vec<u8>>], reference: Option<&str>) -> String {
    let Some(reference) = reference else {
        return text.to_string();
    };
    let mut out = text.as_bytes().to_vec();
    for needle in needles {
        out = replace_bytes(&out, needle, reference.as_bytes());
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Same, for an error message that may quote the URL (a query credential).
fn redact_text(
    text: &str,
    needles: &[Zeroizing<Vec<u8>>],
    binding: Option<&AuthBinding>,
) -> String {
    let reference = binding.map(|b| format!("secret:{}", b.secret));
    redact_with(text, needles, reference.as_deref())
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
            allow_encoded_slash: false,
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
        assert_eq!(p.host, "::ffff:127.0.0.1");
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
            assert!(normalise_path(bad, false).is_err(), "{bad} must be rejected");
        }
        assert_eq!(normalise_path("/a/b/../c", false).unwrap(), "/a/c");
        assert_eq!(normalise_path("/a/./b?x=1", false).unwrap(), "/a/b?x=1");
        assert_eq!(normalise_path("/", false).unwrap(), "/");
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
                allow_encoded_slash: false,
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
            vec![rule("localhost:1", false)],
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
            vec![rule("localhost:1", true)],
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
            vec![rule("localhost:1", true)],
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

    // ---- helpers for the tests below ----------------------------------------------------------
    /// A one-shot upstream on loopback that answers the first connection with `reply`.
    async fn upstream(reply: Vec<u8>) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = vec![0u8; 8192];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(&reply).await;
            }
        });
        port
    }

    fn get(url: String) -> ProxyRequest {
        ProxyRequest {
            url,
            method: "GET".into(),
            headers: BTreeMap::new(),
            body: None,
            content_length: None,
            transfer_encoding_chunked: false,
        }
    }

    fn http_reply(headers: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{headers}\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn open_rule(port: u16, paths: &[&str]) -> EgressRule {
        EgressRule {
            host: format!("127.0.0.1:{port}"),
            methods: vec!["*".into()],
            paths: paths.iter().map(|s| s.to_string()).collect(),
            allow_private: true,
            allow_encoded_slash: false,
        }
    }

    fn proxy_with_secret(rules: Vec<EgressRule>, scheme: Scheme, port: u16) -> PluginProxy {
        PluginProxy::new(
            "org.test.p",
            rules,
            vec![AuthBinding {
                secret: "TEST_KEY".into(),
                scheme,
                hosts: vec![format!("127.0.0.1:{port}")],
                methods: vec!["*".into()],
                paths: vec!["*".into()],
            }],
            resolver(),
        )
    }

    // ---- URL parsing: one parser decides, and the forwarded URL is what was checked -------------
    #[test]
    fn a_url_two_parsers_read_differently_cannot_hide_a_path() {
        // The old hand-written parser took everything up to the first '/' as the
        // authority and read the path after it; the WHATWG parser ends the
        // authority at '?' or '#', so the real path was "/" and the checked path
        // was "/allowed/x". Both must now agree, or the URL is refused.
        let p = parse_url("https://declared.example?/allowed/x").unwrap();
        assert_eq!(p.path_query, "/?/allowed/x");
        assert!(parse_url("https://declared.example#/allowed/x").is_err(), "fragment");
        assert!(parse_url("https://user@declared.example/x").is_err(), "userinfo");
        assert!(parse_url("https://user:pw@declared.example/x").is_err(), "userinfo");
        assert!(parse_url("https://declared.example\\@evil.example/x").is_err());
    }

    #[test]
    fn the_forwarded_url_is_rebuilt_from_the_checked_parts() {
        let p = parse_url("HTTPS://Example.COM:443/a//b/c?q=%2F&r=1").unwrap();
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, None);
        assert_eq!(p.effective_port, 443);
        assert_eq!(p.path_query, "/a/b/c?q=%2F&r=1");
        assert_eq!(p.canonical, "https://example.com/a/b/c?q=%2F&r=1");
    }

    #[test]
    fn ip_literals_in_any_spelling_become_one_address() {
        for (url, host) in [
            ("http://0x7f.1/", "127.0.0.1"),
            ("http://2130706433/", "127.0.0.1"),
            ("http://127.1/", "127.0.0.1"),
            ("http://[::ffff:127.0.0.1]/", "::ffff:127.0.0.1"),
            ("http://[::ffff:7f00:1]/", "::ffff:127.0.0.1"),
        ] {
            assert_eq!(parse_url(url).unwrap().host, host, "{url}");
        }
    }

    #[test]
    fn dot_segments_and_backslashes_are_refused_in_every_encoding() {
        for bad in [
            "https://h.example/a/../b",
            "https://h.example/a/%2e%2e/b",
            "https://h.example/a/.%2E/b",
            "https://h.example/a/%2E/b",
            "https://h.example/a\\..\\b",
            "https://h.example/..",
        ] {
            assert!(parse_url(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn query_strings_may_carry_encoded_slashes_but_paths_may_not() {
        assert!(parse_url("https://h.example/cb?redirect_uri=https%3A%2F%2Fapp.example%2Fok").is_ok());
        assert!(parse_url("https://h.example/a%2Fb").is_err(), "encoded slash in a path");
        assert!(parse_url("https://h.example/a%2e/b").is_err(), "encoded dot in a path");
        assert!(parse_url("https://h.example/a?x=%00").is_ok(), "an encoded NUL is data in a query");
        // Raw control characters are refused outright, in any part of the URL.
        for bad in ["https://h.example/a?x=\u{0}", "https://h.example/a\u{0}", "https://h.example/a\tb", "https://h.exa\nmple/a", "https://h.example/a?x=1\r\nHost: evil"] {
            assert!(matches!(parse_url(bad), Err(ProxyError::BadUrl)), "{bad:?}");
        }
    }

    // ---- rule matching: the port is part of the rule ---------------------------------------------
    #[test]
    fn a_rule_port_is_enforced_and_a_bare_rule_means_the_default_port() {
        let on = |url: &str| parse_url(url).unwrap();
        // "host:8080" must not cover the same host on 443 (the old code did).
        assert!(!host_covers("api.example.com:8080", &on("https://api.example.com/x")));
        assert!(host_covers("api.example.com:8080", &on("https://api.example.com:8080/x")));
        assert!(!host_covers("api.example.com:8080", &on("https://api.example.com:9090/x")));
        // A bare rule is the default port only: 22 or 9200 on the same host is another service.
        assert!(host_covers("api.example.com", &on("https://api.example.com/x")));
        assert!(host_covers("api.example.com", &on("https://api.example.com:443/x")));
        assert!(!host_covers("api.example.com", &on("https://api.example.com:9200/x")));
        // An explicit default port in the rule matches the URL without a port.
        assert!(host_covers("api.example.com:443", &on("https://api.example.com/x")));
        // IPv6 and case.
        assert!(host_covers("[::1]:8080", &on("http://[::1]:8080/")));
        assert!(!host_covers("[::1]:8080", &on("http://[::1]/")));
        assert!(host_covers("API.Example.COM", &on("https://api.example.com/")));
    }

    #[tokio::test]
    async fn a_hidden_path_is_refused_before_any_io() {
        let proxy = PluginProxy::new(
            "org.test.p",
            vec![EgressRule {
                host: "declared.example".into(),
                methods: vec!["GET".into()],
                paths: vec!["/allowed/*".into()],
                allow_private: false,
                allow_encoded_slash: false,
            }],
            vec![],
            resolver(),
        );
        // Real path is "/", which the rule does not allow.
        let err = proxy.request(&get("https://declared.example?/allowed/x".into())).await.unwrap_err();
        assert!(matches!(err, ProxyError::PathNotDeclared(_, _)), "{err:?}");
        let err = proxy.request(&get("https://declared.example#/allowed/x".into())).await.unwrap_err();
        assert!(matches!(err, ProxyError::BadUrl), "{err:?}");
        let err = proxy.request(&get("https://declared.example:8443/allowed/x".into())).await.unwrap_err();
        assert!(matches!(err, ProxyError::HostNotDeclared(_)), "{err:?}");
    }

    // ---- forwarding ------------------------------------------------------------------------------
    #[tokio::test]
    async fn a_hostname_upstream_is_connected_by_its_pinned_address() {
        let port = upstream(http_reply("", "pinned")).await;
        let proxy = PluginProxy::new(
            "org.test.p",
            vec![EgressRule {
                host: format!("localhost:{port}"),
                methods: vec!["GET".into()],
                paths: vec!["/*".into()],
                allow_private: true,
                allow_encoded_slash: false,
            }],
            vec![],
            resolver(),
        );
        let resp = proxy.request(&get(format!("http://localhost:{port}/x"))).await.unwrap();
        assert_eq!(resp.body, b"pinned");
        assert!(
            proxy
                .resolve_pinned(&parse_url(&format!("http://localhost:{port}/")).unwrap(), true)
                .await
                .unwrap()
                .iter()
                .all(|a| a.port() == port && a.ip().is_loopback()),
            "every pinned address carries the effective port"
        );
    }

    #[tokio::test]
    async fn a_response_over_the_cap_is_an_error_not_a_silent_truncation() {
        let port = upstream(http_reply("", &"x".repeat(5000))).await;
        let mut proxy = PluginProxy::new("org.test.p", vec![open_rule(port, &["*"])], vec![], resolver());
        proxy.max_response_bytes = 1000;
        let err = proxy.request(&get(format!("http://127.0.0.1:{port}/"))).await.unwrap_err();
        assert!(matches!(err, ProxyError::ResponseTooLarge(1000)), "{err:?}");
    }

    #[tokio::test]
    async fn a_request_body_over_the_cap_is_refused_before_any_io() {
        let mut proxy = PluginProxy::new("org.test.p", vec![open_rule(9, &["*"])], vec![], resolver());
        proxy.max_request_bytes = 10;
        let mut req = get("http://127.0.0.1:9/".into());
        req.method = "POST".into();
        req.body = Some(vec![0u8; 11]);
        let err = proxy.request(&req).await.unwrap_err();
        assert!(matches!(err, ProxyError::RequestTooLarge(10)), "{err:?}");
    }

    #[tokio::test]
    async fn an_upstream_that_never_answers_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _held = listener.accept().await; // accept, then say nothing
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });
        let mut proxy = PluginProxy::new("org.test.p", vec![open_rule(port, &["*"])], vec![], resolver());
        proxy.timeout = std::time::Duration::from_millis(300);
        let started = std::time::Instant::now();
        let err = proxy.request(&get(format!("http://127.0.0.1:{port}/"))).await.unwrap_err();
        assert!(matches!(err, ProxyError::Upstream(_)), "{err:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "timeout did not apply");
    }

    // ---- secret hygiene --------------------------------------------------------------------------
    #[tokio::test]
    async fn an_echoed_secret_is_redacted_in_headers_and_in_encoded_forms() {
        use base64::Engine;
        let secret = "s3cr3t-value-123";
        let b64 = base64::engine::general_purpose::STANDARD.encode(secret);
        let body = format!("echo raw={secret} b64={b64} url={}", schemes::urlencode(secret));
        let hdr = format!("X-Debug: key={secret}\r\n");
        let port = upstream(http_reply(&hdr, &body)).await;
        let proxy = proxy_with_secret(vec![open_rule(port, &["*"])], Scheme::Bearer, port);
        let resp = proxy.request(&get(format!("http://127.0.0.1:{port}/"))).await.unwrap();
        let text = String::from_utf8_lossy(&resp.body).to_string();
        for form in [secret, b64.as_str()] {
            assert!(!text.contains(form), "body leaked {form}: {text}");
        }
        assert!(text.contains("secret:TEST_KEY"), "{text}");
        assert!(!resp.headers.values().any(|v| v.contains(secret)), "header leaked: {:?}", resp.headers);
        assert!(resp.headers["x-debug"].contains("secret:TEST_KEY"));
    }

    #[tokio::test]
    async fn a_redirect_target_carrying_the_secret_is_scrubbed() {
        let secret = "s3cr3t-value-123";
        let reply = format!("HTTP/1.1 302 Found\r\nLocation: http://other.example/cb?token={secret}\r\nContent-Length: 0\r\n\r\n");
        let port = upstream(reply.into_bytes()).await;
        let proxy = proxy_with_secret(vec![open_rule(port, &["*"])], Scheme::Bearer, port);
        let resp = proxy.request(&get(format!("http://127.0.0.1:{port}/"))).await.unwrap();
        assert_eq!(resp.status, 302);
        assert_eq!(resp.blocked_redirects, vec!["http://other.example/cb?token=secret:TEST_KEY".to_string()]);
    }

    #[tokio::test]
    async fn a_query_credential_never_appears_in_an_error_message() {
        // reqwest quotes the full URL in connection errors; with a query-key
        // credential that URL contains the secret.
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let secret = "s3cr3t-value-123";
        let proxy = PluginProxy::new(
            "org.test.p",
            vec![open_rule(closed, &["*"])],
            vec![AuthBinding {
                secret: "TEST_KEY".into(),
                scheme: Scheme::QueryKey,
                hosts: vec![format!("127.0.0.1:{closed}")],
                methods: vec!["*".into()],
                paths: vec!["*".into()],
            }],
            Arc::new(ClosureResolver(move |_: &str| Ok(Zeroizing::new(format!("key={secret}"))))),
        );
        let err = proxy.request(&get(format!("http://127.0.0.1:{closed}/"))).await.unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, ProxyError::Upstream(_)), "{err:?}");
        assert!(!text.contains(secret), "error leaked the secret: {text}");
    }

    #[tokio::test]
    async fn the_query_credential_is_sent_on_the_wire() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
            let _ = sock.write_all(&http_reply("", "ok")).await;
        });
        let proxy = PluginProxy::new(
            "org.test.p",
            vec![open_rule(port, &["*"])],
            vec![AuthBinding {
                secret: "TEST_KEY".into(),
                scheme: Scheme::QueryKey,
                hosts: vec![format!("127.0.0.1:{port}")],
                methods: vec!["*".into()],
                paths: vec!["*".into()],
            }],
            Arc::new(ClosureResolver(|_: &str| Ok(Zeroizing::new("apikey=abc def".to_string())))),
        );
        proxy.request(&get(format!("http://127.0.0.1:{port}/data?x=1"))).await.unwrap();
        let wire = rx.await.unwrap();
        assert!(wire.starts_with("GET /data?x=1&apikey=abc+def HTTP/1.1"), "{wire}");
    }

    // ---- encoded slashes: refused by default, allowed only by an explicit rule ----------------
    #[test]
    fn encoded_slashes_in_a_segment_need_the_rule_to_say_so() {
        let url = "https://www.googleapis.com/webmasters/v3/sites/sc-domain%3Aexample.com/sitemaps/https%3A%2F%2Fexample.com%2Fsitemap.xml";
        assert!(parse_url_with(url, false).is_err(), "refused by default");
        let p = parse_url_with(url, true).unwrap();
        // Forwarded exactly as written: %2F stays %2F, so the upstream sees the segment the plugin meant.
        assert!(p.canonical.ends_with("/sitemaps/https%3A%2F%2Fexample.com%2Fsitemap.xml"), "{}", p.canonical);
        assert!(p.path_query.starts_with("/webmasters/v3/sites/"), "{}", p.path_query);
    }

    #[test]
    fn allowing_encoded_slashes_does_not_allow_traversal_through_them() {
        for bad in [
            "https://h.example/a/..%2Fadmin",
            "https://h.example/a/%2E%2E%2Fadmin",
            "https://h.example/a/x%2F..%2F..%2Fadmin",
            "https://h.example/a/x%2f..",
            "https://h.example/a/.%2Fb",
            "https://h.example/a/%5Cb",
            "https://h.example/a/%2e%2e/b",
        ] {
            assert!(parse_url_with(bad, true).is_err(), "{bad} must stay refused even when encoded slashes are allowed");
        }
        // Ordinary content in such a segment is fine.
        assert!(parse_url_with("https://h.example/a/b%2Fc%2Fd", true).is_ok());
    }

    #[tokio::test]
    async fn a_rule_that_allows_encoded_slashes_forwards_them_and_other_rules_still_refuse() {
        let port = upstream(http_reply("", "ok")).await;
        let mut allowing = open_rule(port, &["/sites/*"]);
        allowing.allow_encoded_slash = true;
        let proxy = PluginProxy::new("org.test.p", vec![allowing], vec![], resolver());
        let resp = proxy.request(&get(format!("http://127.0.0.1:{port}/sites/https%3A%2F%2Fexample.com%2Fmap.xml"))).await.unwrap();
        assert_eq!(resp.body, b"ok");
        // The same URL against a rule that does not allow it never reaches the network.
        let strict = PluginProxy::new("org.test.p", vec![open_rule(1, &["/sites/*"])], vec![], resolver());
        let err = strict.request(&get("http://127.0.0.1:1/sites/a%2Fb".into())).await.unwrap_err();
        assert!(matches!(err, ProxyError::BadPathEncoding), "{err:?}");
    }
}
