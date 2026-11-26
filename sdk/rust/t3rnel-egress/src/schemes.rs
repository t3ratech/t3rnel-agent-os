//! Authentication/signing schemes the proxy applies in flight (05 §14.1,
//! §14.5). Each scheme is a small, separately tested unit; adding a scheme is
//! a core release, never a plugin feature. The plugin sends unsigned
//! requests; the proxy computes the credential material and injects it.
//!
//! A scheme only exists here if it does what it says against a real service.
//! A scheme for a service whose full signing rules are only partly written is
//! left out (a partial signer would send a wrong or revealing credential).
//!
//! Secret formats (the value stored in the vault under the manifest's secret
//! name):
//!
//! | Scheme | Vault value |
//! |---|---|
//! | `bearer` | the token |
//! | `header` | `Header-Name: value` |
//! | `basic` | `username:password` (RFC 7617; an empty username is `:password`) |
//! | `query-key` | `param_name=value` |
//! | `hmac-sha256` | the shared key (first-party T3rnel services, see below) |

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::SCHEME_FORBIDDEN_HEADERS;

type HmacSha256 = Hmac<Sha256>;

/// The fixed scheme list. Mirrors `bridge::manifest::AuthScheme`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Bearer,
    Header,
    Basic,
    QueryKey,
    /// Request signing for **T3rnel's own services**: HMAC-SHA256 over
    /// `METHOD \n path?query \n sha256(body) \n unix_timestamp`, sent as
    /// `X-T3rnel-Timestamp` and `X-T3rnel-Signature`. Third-party exchanges
    /// each define their own signing rules and need their own named scheme.
    HmacSha256,
}

/// Apply `scheme` using `secret` to the request being forwarded.
///
/// - `url` may be rewritten (query-key appends the credential).
/// - `headers` receives injected auth headers.
/// - `body` is the exact bytes that will be sent — signing and sending use
///   this one buffered copy (§14.5).
///
/// Returns an error for a secret that does not have the scheme's format;
/// callers treat it as fail-closed.
pub(crate) fn apply_scheme(
    scheme: Scheme,
    secret: &str,
    method: &str,
    parsed: &crate::ParsedUrl,
    url: &mut String,
    headers: &mut BTreeMap<String, String>,
    body: &mut Vec<u8>,
) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    apply_scheme_at(scheme, secret, method, parsed, url, headers, body, now)
}

/// [`apply_scheme`] with an explicit clock, so signatures are testable.
#[allow(clippy::too_many_arguments)] // signing fns take the full request view
pub(crate) fn apply_scheme_at(
    scheme: Scheme,
    secret: &str,
    method: &str,
    parsed: &crate::ParsedUrl,
    url: &mut String,
    headers: &mut BTreeMap<String, String>,
    body: &mut Vec<u8>,
    unix_seconds: u64,
) -> Result<(), String> {
    match scheme {
        Scheme::Bearer => {
            if secret.is_empty() || secret.contains(['\r', '\n']) {
                return Err("bearer secret is empty or contains a line break".into());
            }
            headers.insert("Authorization".into(), format!("Bearer {secret}"));
        }
        Scheme::Header => {
            let (name, value) = secret
                .split_once(':')
                .ok_or_else(|| "header scheme secret must be 'Name: value'".to_string())?;
            let name = name.trim();
            if name.is_empty() || !name.chars().all(is_token_char) {
                return Err("header scheme produced an invalid header name".into());
            }
            if SCHEME_FORBIDDEN_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                return Err(format!(
                    "header scheme may not set the routing/framing header {name:?}"
                ));
            }
            let value = value.trim();
            if value.is_empty() || value.contains(['\r', '\n']) {
                return Err("header scheme value is empty or contains a line break".into());
            }
            headers.insert(name.to_string(), value.to_string());
        }
        Scheme::Basic => {
            use base64::Engine;
            if !secret.contains(':') || secret.contains(['\r', '\n']) {
                return Err("basic scheme secret must be 'username:password'".into());
            }
            let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
            headers.insert("Authorization".into(), format!("Basic {encoded}"));
        }
        Scheme::QueryKey => {
            let (name, value) = secret
                .split_once('=')
                .ok_or_else(|| "query-key scheme secret must be 'param=value'".to_string())?;
            if name.is_empty() || !name.chars().all(is_token_char) || value.is_empty() {
                return Err("query-key scheme produced an invalid parameter".into());
            }
            let mut u = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
            u.query_pairs_mut().append_pair(name, value);
            *url = u.to_string();
        }
        Scheme::HmacSha256 => {
            let body_hash = hex::encode(Sha256::digest(&*body));
            let payload = format!("{}\n{}\n{}\n{}", method, parsed.path_query, body_hash, unix_seconds);
            let mut mac =
                HmacSha256::new_from_slice(secret.as_bytes()).map_err(|e| e.to_string())?;
            mac.update(payload.as_bytes());
            headers.insert("X-T3rnel-Timestamp".into(), unix_seconds.to_string());
            headers.insert(
                "X-T3rnel-Signature".into(),
                hex::encode(mac.finalize().into_bytes()),
            );
        }
    }
    Ok(())
}

/// Characters allowed in a header or parameter name (RFC 9110 token, minus the
/// rarely used punctuation — a name outside this set is refused, never escaped).
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Minimal percent-encoding for query parameter values.
pub(crate) fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ParsedUrl;

    fn parsed() -> ParsedUrl {
        ParsedUrl {
            host: "api.example.com".into(),
            port: None,
            effective_port: 443,
            path_query: "/v1/order?x=1".into(),
            canonical: "https://api.example.com/v1/order?x=1".into(),
        }
    }

    fn run(
        scheme: Scheme,
        secret: &str,
        url: &str,
        body: &[u8],
        at: u64,
    ) -> Result<(String, BTreeMap<String, String>), String> {
        let mut u = url.to_string();
        let mut h = BTreeMap::new();
        let mut b = body.to_vec();
        apply_scheme_at(scheme, secret, "POST", &parsed(), &mut u, &mut h, &mut b, at)?;
        assert_eq!(b, body, "a scheme must never change the body");
        Ok((u, h))
    }

    #[test]
    fn bearer_sets_authorization_and_refuses_a_line_break() {
        let (_, h) = run(Scheme::Bearer, "tok", "https://x/", b"", 0).unwrap();
        assert_eq!(h["Authorization"], "Bearer tok");
        assert!(run(Scheme::Bearer, "tok\r\nX-Evil: 1", "https://x/", b"", 0).is_err());
        assert!(run(Scheme::Bearer, "", "https://x/", b"", 0).is_err());
    }

    #[test]
    fn header_scheme_splits_name_and_value_and_refuses_bad_ones() {
        let (_, h) = run(Scheme::Header, "X-Api-Key: abc123", "https://x/", b"", 0).unwrap();
        assert_eq!(h["X-Api-Key"], "abc123");
        for bad in [
            "no-colon",
            "Bad Name: v",
            ": v",
            "X-A:",
            "X-A: v\r\nX-B: w",
            // The proxy owns routing and framing: a stored credential may not redirect or smuggle.
            "Host: evil.example",
            "Content-Length: 0",
            "Transfer-Encoding: chunked",
        ] {
            assert!(run(Scheme::Header, bad, "https://x/", b"", 0).is_err(), "{bad:?}");
        }
        // Authorization and Cookie are real credential carriers and stay allowed.
        assert!(run(Scheme::Header, "Authorization: Token t", "https://x/", b"", 0).is_ok());
        assert!(run(Scheme::Header, "Cookie: s=1", "https://x/", b"", 0).is_ok());
    }

    #[test]
    fn basic_encodes_username_and_password() {
        use base64::Engine;
        let enc = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let (_, h) = run(Scheme::Basic, "alice:s3cret", "https://x/", b"", 0).unwrap();
        assert_eq!(h["Authorization"], format!("Basic {}", enc("alice:s3cret")));
        // An empty username (VLC-style) is stored as ":password".
        let (_, h) = run(Scheme::Basic, ":pw", "https://x/", b"", 0).unwrap();
        assert_eq!(h["Authorization"], format!("Basic {}", enc(":pw")));
        // A password may itself contain a colon.
        let (_, h) = run(Scheme::Basic, "bob:p:w", "https://x/", b"", 0).unwrap();
        assert_eq!(h["Authorization"], format!("Basic {}", enc("bob:p:w")));
        // No username separator is a malformed secret, never a guess.
        assert!(run(Scheme::Basic, "justapassword", "https://x/", b"", 0).is_err());
    }

    #[test]
    fn query_key_uses_the_named_parameter_and_encodes_the_value() {
        let (u, _) = run(Scheme::QueryKey, "key=k y&z", "https://x.test/a?b=1", b"", 0).unwrap();
        let url = reqwest::Url::parse(&u).unwrap();
        let pairs: Vec<(String, String)> = url.query_pairs().map(|(a, b)| (a.into(), b.into())).collect();
        assert_eq!(pairs, vec![("b".into(), "1".into()), ("key".into(), "k y&z".into())]);
        // The value cannot add a second parameter or break out of the first.
        assert_eq!(url.query_pairs().count(), 2, "{u}");
        // Different services name the parameter differently.
        let (u, _) = run(Scheme::QueryKey, "access_token=abc", "https://x.test/", b"", 0).unwrap();
        assert!(u.contains("access_token=abc"), "{u}");
        for bad in ["novalue", "=v", "k=", "bad name=v", "k\r\n=v"] {
            assert!(run(Scheme::QueryKey, bad, "https://x.test/", b"", 0).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn hmac_signature_matches_an_independently_computed_value() {
        let body = b"{\"qty\":1}";
        let (_, h) = run(Scheme::HmacSha256, "key", "https://x/", body, 1_700_000_000).unwrap();
        // Computed here from the documented format, not by calling the scheme.
        let payload = format!(
            "POST\n/v1/order?x=1\n{}\n1700000000",
            hex::encode(Sha256::digest(body))
        );
        let mut mac = HmacSha256::new_from_slice(b"key").unwrap();
        mac.update(payload.as_bytes());
        assert_eq!(h["X-T3rnel-Signature"], hex::encode(mac.finalize().into_bytes()));
        assert_eq!(h["X-T3rnel-Timestamp"], "1700000000");
    }

    #[test]
    fn hmac_signature_changes_with_every_signed_part() {
        let sig = |secret: &str, body: &[u8], at: u64| {
            run(Scheme::HmacSha256, secret, "https://x/", body, at).unwrap().1["X-T3rnel-Signature"].clone()
        };
        let base = sig("key", b"a", 100);
        assert_eq!(base, sig("key", b"a", 100), "same input, same signature");
        assert_ne!(base, sig("other", b"a", 100), "key");
        assert_ne!(base, sig("key", b"b", 100), "body");
        assert_ne!(base, sig("key", b"a", 101), "timestamp");
        // The query string is signed: changing it must change the signature.
        let mut other = parsed();
        other.path_query = "/v1/order?x=2".into();
        let mut h = BTreeMap::new();
        apply_scheme_at(Scheme::HmacSha256, "key", "POST", &other, &mut "https://x/".to_string(), &mut h, &mut b"a".to_vec(), 100).unwrap();
        assert_ne!(base, h["X-T3rnel-Signature"], "query");
    }

    #[test]
    fn urlencode_escapes_everything_outside_the_unreserved_set() {
        assert_eq!(urlencode("aZ09-_.~"), "aZ09-_.~");
        assert_eq!(urlencode("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
    }
}
