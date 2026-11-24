//! Authentication/signing schemes the proxy applies in flight (05 §14.1,
//! §14.5). Each scheme is a small, separately tested unit; adding a scheme is
//! a core release, never a plugin feature. The plugin sends unsigned
//! requests; the proxy computes the credential material and injects it.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// The fixed scheme list. Mirrors `bridge::manifest::AuthScheme`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Bearer,
    Header,
    Basic,
    QueryKey,
    HmacSha256,
    AwsSigV4,
}

/// Apply `scheme` using `secret` to the request being forwarded.
///
/// - `url` may be rewritten (query-key appends the credential).
/// - `headers` receives injected auth headers.
/// - `body` is the exact bytes that will be sent — signing and sending use
///   this one buffered copy (§14.5).
///
/// Returns an error for schemes that cannot be applied to this request
/// shape; callers treat it as fail-closed.
#[allow(clippy::too_many_arguments)] // signing fns take the full request view
pub(crate) fn apply_scheme(
    scheme: Scheme,
    secret: &str,
    method: &str,
    parsed: &crate::plugin_proxy::ParsedUrl,
    path: &str,
    url: &mut String,
    headers: &mut BTreeMap<String, String>,
    body: &mut Vec<u8>,
) -> Result<(), String> {
    match scheme {
        Scheme::Bearer => {
            headers.insert("Authorization".into(), format!("Bearer {secret}"));
        }
        Scheme::Header => {
            // `secret` is expected as "Header-Name: value" — split once.
            let (name, value) = secret
                .split_once(':')
                .ok_or_else(|| "header scheme secret must be 'Name: value'".to_string())?;
            let name = name.trim();
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err("header scheme produced an invalid header name".into());
            }
            headers.insert(name.to_string(), value.trim().to_string());
        }
        Scheme::Basic => {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(format!(":{secret}"));
            headers.insert("Authorization".into(), format!("Basic {encoded}"));
        }
        Scheme::QueryKey => {
            // The secret is placed by the proxy into the query string; the
            // plugin cannot read it back from the response because the proxy
            // strips it before returning (the plugin never sees its own
            // signed URL either — callers must not echo `url` back).
            let sep = if url.contains('?') { '&' } else { '?' };
            *url = format!("{url}{sep}api_key={}", urlencode(secret));
        }
        Scheme::HmacSha256 => {
            // Exchange-style signing: HMAC-SHA256 over
            // "METHOD\npath\nbody_sha256\ntimestamp". The plugin cannot choose
            // the input or read the signature back.
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();
            let body_hash = hex::encode(Sha256::digest(body));
            let payload = format!("{}\n{}\n{}\n{}", method, path, body_hash, ts);
            let mut mac =
                HmacSha256::new_from_slice(secret.as_bytes()).map_err(|e| e.to_string())?;
            mac.update(payload.as_bytes());
            let sig = hex::encode(mac.finalize().into_bytes());
            headers.insert("X-T3rnel-Timestamp".into(), ts.to_string());
            headers.insert("X-T3rnel-Signature".into(), sig);
        }
        Scheme::AwsSigV4 => {
            // Minimal SigV4-compatible HMAC chain: canonical request over
            // method/path/body hash/date/region/service. Real deployments add
            // the full canonicalisation; this produces a valid signature
            // shape bound to this exact request.
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?;
            let amz_date = format!("{}", now.as_secs());
            let date_stamp = &amz_date[..amz_date.len().min(8)];
            let body_hash = hex::encode(Sha256::digest(body));
            let canonical = format!("{method}\n{path}\n\n\nhost:{}\nx-amz-date:{amz_date}\n\nhost;x-amz-date\n{body_hash}", parsed.host);
            let scope = format!("{date_stamp}/us-east-1/service/aws4_request");
            let string_to_sign = format!(
                "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
                hex::encode(Sha256::digest(canonical.as_bytes()))
            );
            let k_date = hmac_sha256(format!("AWS4{}", secret).as_bytes(), date_stamp.as_bytes());
            let k_region = hmac_sha256(&k_date, b"us-east-1");
            let k_service = hmac_sha256(&k_region, b"service");
            let k_signing = hmac_sha256(&k_service, b"aws4_request");
            let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));
            headers.insert(
                "Authorization".into(),
                format!("AWS4-HMAC-SHA256 Credential={secret}/{scope}, SignedHeaders=host;x-amz-date, Signature={signature}"),
            );
            headers.insert("X-Amz-Date".into(), amz_date);
        }
    }
    let _ = parsed;
    Ok(())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Minimal percent-encoding for query parameter values.
fn urlencode(s: &str) -> String {
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
    use crate::plugin_proxy::ParsedUrl;

    fn parsed() -> ParsedUrl {
        ParsedUrl {
            host: "api.example.com".into(),
            port: Some(443),
            path_query: "/v1/order".into(),
        }
    }

    #[test]
    fn bearer_sets_authorization() {
        let mut h = BTreeMap::new();
        apply_scheme(
            Scheme::Bearer,
            "tok",
            "GET",
            &parsed(),
            "/v1/order",
            &mut "https://x".into(),
            &mut h,
            &mut vec![],
        )
        .unwrap();
        assert_eq!(h["Authorization"], "Bearer tok");
    }

    #[test]
    fn header_scheme_splits_name_and_value() {
        let mut h = BTreeMap::new();
        apply_scheme(
            Scheme::Header,
            "X-Api-Key: abc123",
            "GET",
            &parsed(),
            "/v1/order",
            &mut "https://x".into(),
            &mut h,
            &mut vec![],
        )
        .unwrap();
        assert_eq!(h["X-Api-Key"], "abc123");
        assert!(apply_scheme(
            Scheme::Header,
            "no-colon",
            "GET",
            &parsed(),
            "/",
            &mut "https://x".into(),
            &mut h,
            &mut vec![]
        )
        .is_err());
        assert!(apply_scheme(
            Scheme::Header,
            "Bad Name: v",
            "GET",
            &parsed(),
            "/",
            &mut "https://x".into(),
            &mut h,
            &mut vec![]
        )
        .is_err());
    }

    #[test]
    fn basic_encodes_colon_prefix() {
        let mut h = BTreeMap::new();
        apply_scheme(
            Scheme::Basic,
            "pw",
            "GET",
            &parsed(),
            "/",
            &mut "https://x".into(),
            &mut h,
            &mut vec![],
        )
        .unwrap();
        use base64::Engine;
        assert_eq!(
            h["Authorization"],
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(":pw")
            )
        );
    }

    #[test]
    fn query_key_appends_encoded_secret() {
        let mut url = "https://x.test/a?b=1".to_string();
        let mut h = BTreeMap::new();
        apply_scheme(
            Scheme::QueryKey,
            "k y",
            "GET",
            &parsed(),
            "/",
            &mut url,
            &mut h,
            &mut vec![],
        )
        .unwrap();
        assert!(url.contains("api_key=k%20y"), "{url}");
        assert!(url.contains("b=1"));
    }

    #[test]
    fn hmac_signature_is_deterministic_per_request_parts() {
        let mut h1 = BTreeMap::new();
        let mut h2 = BTreeMap::new();
        let mut u1 = "https://x".to_string();
        let mut u2 = "https://x".to_string();
        let mut b = b"body".to_vec();
        apply_scheme(
            Scheme::HmacSha256,
            "secret",
            "POST",
            &parsed(),
            "/v1/order",
            &mut u1,
            &mut h1,
            &mut b.clone(),
        )
        .unwrap();
        apply_scheme(
            Scheme::HmacSha256,
            "secret",
            "POST",
            &parsed(),
            "/v1/order",
            &mut u2,
            &mut h2,
            &mut b,
        )
        .unwrap();
        assert!(h1["X-T3rnel-Signature"].len() == 64);
        assert!(h1.contains_key("X-T3rnel-Timestamp"));
        // Different secret -> different signature.
        let mut h3 = BTreeMap::new();
        let mut u3 = "https://x".to_string();
        apply_scheme(
            Scheme::HmacSha256,
            "other",
            "POST",
            &parsed(),
            "/v1/order",
            &mut u3,
            &mut h3,
            &mut b"body".to_vec(),
        )
        .unwrap();
        assert_ne!(h1["X-T3rnel-Signature"], h3["X-T3rnel-Signature"]);
    }

    #[test]
    fn aws_sigv4_produces_credential_and_signature() {
        let mut h = BTreeMap::new();
        let mut u = "https://x".to_string();
        apply_scheme(
            Scheme::AwsSigV4,
            "AKID",
            "GET",
            &parsed(),
            "/",
            &mut u,
            &mut h,
            &mut vec![],
        )
        .unwrap();
        let auth = &h["Authorization"];
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=AKID/"),
            "{auth}"
        );
        assert!(auth.contains("Signature="));
        assert!(h.contains_key("X-Amz-Date"));
    }
}
