//! WhatsApp channel adapters (`docs/sections/18 §3`, work-queue §7 step 4).
//!
//! Two implementations of the [`ChannelAdapter`] contract:
//!
//! - [`WhatsAppAdapter`] (`"whatsapp"`) — wraps the existing Baileys
//!   WhatsApp-Web gateway (`packages/whatsapp-gateway`, managed by
//!   `t3rnel_kernel::whatsapp_gateway`). Account linking stays user-driven
//!   through the existing QR flow (`POST /api/channels/whatsapp/qr/start`);
//!   the adapter reports [`WhatsAppLinkState::NeedsLinking`] until the
//!   gateway reports a linked number, and sends fail with an actionable
//!   error instead of silently dropping.
//! - [`WhatsAppBusinessAdapter`] (`"whatsapp-business"`) — WhatsApp
//!   Business Cloud API mode: outbound via `graph.facebook.com`, inbound
//!   via Meta webhook POSTs normalized into the shared
//!   [`BusinessWebhookState`] queue that `poll_inbound` drains.
//!
//! Credential model (18 §3/§6): the personal-mode *session* credential is
//! the gateway's own `auth_store` under `<home>/whatsapp-gateway/` — it is
//! never copied into the vault and never exposed to plugins. The adapter
//! receives [`BrokeredCreds`] at `connect` time exactly like every other
//! adapter; any secret names the linked account declares (e.g. a future
//! authenticated-gateway token, or the Business API token/verify-token/
//! phone-number-id) are resolved through the vault broker and retained
//! only as `Zeroizing` material inside the adapter.

use std::collections::VecDeque;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    AttachmentRef, BrokeredCreds, ChannelAdapter, ChannelCaps, ChannelError, OutboundMessage,
    Receipt,
};
use crate::conversations::{ConversationEvent, Provenance};

const CHANNEL_ID: &str = "whatsapp";
const BUSINESS_CHANNEL_ID: &str = "whatsapp-business";
/// Cloud API hard limit for a text body.
const CLOUD_MAX_TEXT: usize = 4096;
/// Upper bound on buffered webhook/poll events so a dead consumer cannot
/// grow memory without limit.
const MAX_QUEUED_EVENTS: usize = 1024;

/// Resolves the gateway base URL, starting the managed gateway if needed.
///
/// Wired by the API layer to `t3rnel_kernel::whatsapp_gateway::
/// ensure_gateway_running` (runtime cannot depend on kernel). The closure
/// returns the gateway base URL (e.g. `http://127.0.0.1:3009`).
pub type GatewayStarter = Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn Future<Output = Result<String, String>> + Send>>
        + Send
        + Sync,
>;

// ---------------------------------------------------------------------------
// Personal mode — Baileys gateway adapter
// ---------------------------------------------------------------------------

/// Link/connection state of the WhatsApp-Web session, as last observed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum WhatsAppLinkState {
    /// No gateway session established (never connected, or gateway down).
    #[default]
    Offline,
    /// Gateway is up but no number is linked — a QR scan is required.
    NeedsLinking,
    /// A number is linked (credentials on disk) but the socket is not
    /// currently connected — it may be reconnecting.
    Linked,
    /// Linked and the Baileys socket reports `connected`.
    Connected,
}

#[derive(Debug, Default)]
struct GatewayState {
    /// Resolved gateway base URL (no trailing slash).
    url: Option<String>,
    /// The `LinkedAccount.account` this session connected as.
    account: Option<String>,
    link: WhatsAppLinkState,
    /// Linked phone number digits as reported by `GET /linked`, if any.
    linked_number: Option<String>,
    /// Last consumed `/inbound/events` sequence number.
    cursor: u64,
}

/// Channel adapter for the personal WhatsApp account reached through the
/// Baileys gateway. One adapter instance serves the single gateway session;
/// the gateway itself is a singleton per T3rnel home.
pub struct WhatsAppAdapter {
    /// Explicit gateway URL (external gateway); takes precedence over the
    /// starter and `WHATSAPP_WEB_GATEWAY_URL`.
    fixed_url: Option<String>,
    starter: Option<GatewayStarter>,
    client: reqwest::Client,
    state: Mutex<GatewayState>,
    /// Resolved brokered secrets for the connected account (zeroized).
    /// The WhatsApp session itself lives in the gateway `auth_store`.
    secrets: Mutex<Vec<Zeroizing<String>>>,
}

impl WhatsAppAdapter {
    /// Managed mode: the gateway URL is resolved at `connect` via the
    /// [`GatewayStarter`] (kernel process manager) or
    /// `WHATSAPP_WEB_GATEWAY_URL`.
    pub fn new() -> Self {
        WhatsAppAdapter {
            fixed_url: None,
            starter: None,
            client: reqwest::Client::new(),
            state: Mutex::new(GatewayState {
                link: WhatsAppLinkState::Offline,
                ..GatewayState::default()
            }),
            secrets: Mutex::new(Vec::new()),
        }
    }

    /// External-gateway mode: talk to an already-running gateway at `url`.
    pub fn with_gateway_url(url: impl Into<String>) -> Self {
        let mut a = Self::new();
        a.fixed_url = Some(url.into().trim_end_matches('/').to_string());
        a
    }

    /// Attach the kernel-backed gateway starter (starts the managed
    /// gateway on demand when nothing is listening).
    pub fn with_starter(mut self, starter: GatewayStarter) -> Self {
        self.starter = Some(starter);
        self
    }

    /// Last observed link state (refreshed by `connect`/`poll_inbound`).
    pub fn link_state(&self) -> WhatsAppLinkState {
        self.state.lock().unwrap().link.clone()
    }

    /// Linked phone number digits, when known.
    pub fn linked_number(&self) -> Option<String> {
        self.state.lock().unwrap().linked_number.clone()
    }

    /// Resolve the gateway base URL: explicit > starter > env var.
    async fn resolve_url(&self) -> Result<String, ChannelError> {
        if let Some(u) = &self.fixed_url {
            return Ok(u.clone());
        }
        if let Some(starter) = &self.starter {
            return starter().await.map_err(ChannelError::Io);
        }
        if let Ok(u) = std::env::var("WHATSAPP_WEB_GATEWAY_URL") {
            let u = u.trim().trim_end_matches('/');
            if !u.is_empty() {
                return Ok(u.to_string());
            }
        }
        Err(ChannelError::Io(
            "no WhatsApp gateway available: configure [channels.whatsapp] so the \
             daemon manages the Baileys gateway, or set WHATSAPP_WEB_GATEWAY_URL \
             for an external gateway"
                .to_string(),
        ))
    }

    /// `GET /linked` → (linked, connected, number).
    async fn fetch_linked(&self, base: &str) -> Result<(bool, bool, String), ChannelError> {
        let resp = self
            .client
            .get(format!("{base}/linked"))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| ChannelError::Io(format!("whatsapp gateway /linked failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(ChannelError::Io(format!(
                "whatsapp gateway /linked returned {}",
                resp.status()
            )));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ChannelError::Io(format!("whatsapp gateway /linked bad json: {e}")))?;
        Ok((
            body.get("linked")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            body.get("connected")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            body.get("number")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        ))
    }

    /// Resolve an inbound [`AttachmentRef::reference`] (the gateway message
    /// id carried on `/inbound/events`) into the media bytes via
    /// `GET {gateway}/media/{id}`. Returns `(bytes, mime)` where `mime` comes
    /// from the response `Content-Type` (falling back to the event's
    /// `media_mime` hint supplied by the caller).
    ///
    /// The gateway only retains recent inbound media (bounded, per-session),
    /// so an expired/unknown id surfaces as `ChannelError::Poll`-style Io —
    /// callers should treat it as "attachment no longer available", not a
    /// transport failure worth retrying forever.
    pub async fn fetch_attachment(
        &self,
        reference: &str,
    ) -> Result<(Vec<u8>, Option<String>), ChannelError> {
        if reference.is_empty() {
            return Err(ChannelError::Io("empty media reference".to_string()));
        }
        // Prefer the already-resolved session URL; fall back to full
        // resolution (starter/env) so fetches work before the first poll.
        let cached = self.state.lock().unwrap().url.clone();
        let url = match cached {
            Some(u) => u,
            None => self.resolve_url().await?,
        };
        let resp = self
            .client
            .get(format!("{url}/media/{}", reference))
            .timeout(Duration::from_secs(60))
            .send()
            .await
            .map_err(|e| ChannelError::Io(format!("whatsapp gateway /media failed: {e}")))?;
        let status = resp.status();
        let mime = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(ChannelError::Io(format!(
                "media {reference} unknown or expired on the gateway"
            )));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ChannelError::Io(format!(
                "whatsapp gateway /media returned {status}: {}",
                body.chars().take(200).collect::<String>()
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ChannelError::Io(format!("whatsapp gateway /media read failed: {e}")))?
            .to_vec();
        Ok((bytes, mime))
    }

    fn link_state_for(linked: bool, connected: bool) -> WhatsAppLinkState {
        match (linked, connected) {
            (true, true) => WhatsAppLinkState::Connected,
            (true, false) => WhatsAppLinkState::Linked,
            (false, _) => WhatsAppLinkState::NeedsLinking,
        }
    }
}

impl Default for WhatsAppAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GatewayInboundEvent {
    seq: u64,
    #[serde(default)]
    id: Option<String>,
    /// Chat/thread key: group JID (`…@g.us`) or the sender's JID.
    #[serde(default)]
    chat: String,
    /// Channel-side sender JID (`…@s.whatsapp.net`, `…@lid`, or group participant).
    #[serde(default)]
    sender: String,
    /// Sender phone with leading `+`, when resolvable.
    #[serde(default)]
    phone: String,
    #[serde(default)]
    push_name: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    is_group: bool,
    /// MIME type of the message's media attachment, when it carried one
    /// (gateway `media_mime` field; absent on text-only events).
    #[serde(default)]
    media_mime: Option<String>,
    /// Epoch seconds.
    #[serde(default)]
    ts: i64,
}

#[derive(Debug, Deserialize)]
struct GatewayEventsResponse {
    #[serde(default)]
    events: Vec<GatewayInboundEvent>,
    #[serde(default)]
    latest: u64,
    #[serde(default)]
    linked: bool,
    #[serde(default)]
    connected: bool,
    #[serde(default)]
    number: String,
}

/// Map the gateway's placeholder media text onto an attachment kind.
fn media_placeholder_kind(text: &str) -> Option<&'static str> {
    let t = text.trim_start();
    if t.starts_with("[Image received") {
        Some("image")
    } else if t.starts_with("[Voice note received") {
        Some("voice")
    } else if t.starts_with("[Video received") || t.starts_with("[Document received") {
        Some("file")
    } else if t.starts_with("[Sticker received") {
        Some("image")
    } else {
        None
    }
}

impl WhatsAppAdapter {
    fn normalize_inbound(&self, ev: &GatewayInboundEvent, account: &str) -> ConversationEvent {
        // Sender: prefer the dialable phone; fall back to the raw JID for
        // lid-addressed contacts the gateway has not resolved yet.
        let sender = if ev.phone.is_empty() {
            ev.sender.clone()
        } else {
            ev.phone.clone()
        };
        // Thread key = chat id: the group JID for groups; for DMs the
        // phone number (send path normalizes it back to a JID), falling
        // back to the sender JID when no phone is known.
        let thread_key = if ev.is_group {
            if ev.chat.is_empty() {
                ev.sender.clone()
            } else {
                ev.chat.clone()
            }
        } else if !ev.phone.is_empty() {
            ev.phone.clone()
        } else {
            ev.sender.clone()
        };

        let mut attachments = Vec::new();
        if let Some(kind) = media_placeholder_kind(&ev.text) {
            // The message id doubles as the media handle: the gateway keeps
            // the Baileys message and serves its bytes at GET /media/{id}
            // (see `fetch_attachment`). `media_mime` types the ref when the
            // gateway reported it.
            attachments.push(AttachmentRef {
                kind: kind.to_string(),
                reference: ev.id.clone().unwrap_or_default(),
                mime: ev.media_mime.clone(),
                caption: None,
            });
        }

        ConversationEvent {
            channel: CHANNEL_ID.to_string(),
            account: account.to_string(),
            sender,
            thread_key,
            message_id: ev.id.clone(),
            text: ev.text.clone(),
            attachments,
            timestamp: DateTime::from_timestamp(ev.ts, 0).unwrap_or_else(Utc::now),
            provenance: Provenance {
                source: "channel:whatsapp".to_string(),
                untrusted: true,
                data_classes: ["personal".to_string()].into_iter().collect(),
            },
        }
    }
}

#[async_trait]
impl ChannelAdapter for WhatsAppAdapter {
    fn id(&self) -> &str {
        CHANNEL_ID
    }

    async fn connect(&self, creds: &BrokeredCreds) -> Result<(), ChannelError> {
        // Brokered credentials: resolve every secret name the linked account
        // declared. The WhatsApp *session* is the gateway auth_store (never a
        // vault secret, never plugin-visible); declared names cover future
        // authenticated gateways and are retained zeroized only.
        let mut secrets = Vec::new();
        for name in creds.secret_names() {
            secrets.push(creds.resolve(&name)?);
        }

        let url = self.resolve_url().await?;

        // Health gate: a gateway that does not answer /health cannot serve
        // sends or the inbound feed.
        let resp = self
            .client
            .get(format!("{url}/health"))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| ChannelError::Io(format!("whatsapp gateway unreachable at {url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(ChannelError::Io(format!(
                "whatsapp gateway at {url} unhealthy: {}",
                resp.status()
            )));
        }

        let (linked, connected, number) = self.fetch_linked(&url).await?;
        let non_empty_number = if number.is_empty() {
            None
        } else {
            Some(number)
        };

        {
            let mut st = self.state.lock().unwrap();
            st.url = Some(url);
            st.account = Some(creds.account().to_string());
            st.link = Self::link_state_for(linked, connected);
            st.linked_number = non_empty_number;
            st.cursor = 0;
        }
        *self.secrets.lock().unwrap() = secrets;
        Ok(())
    }

    async fn send(&self, msg: &OutboundMessage) -> Result<Receipt, ChannelError> {
        let (url, link, account) = {
            let st = self.state.lock().unwrap();
            (st.url.clone(), st.link.clone(), st.account.clone())
        };
        let Some(url) = url else {
            return Err(ChannelError::NotConnected(CHANNEL_ID.to_string()));
        };
        match link {
            WhatsAppLinkState::NeedsLinking => {
                return Err(ChannelError::Send(
                    CHANNEL_ID.to_string(),
                    "WhatsApp number is not linked — scan the QR code via the \
                     Channels → WhatsApp setup (POST /api/channels/whatsapp/qr/start) \
                     and link the number, then retry"
                        .to_string(),
                ));
            }
            WhatsAppLinkState::Offline => {
                return Err(ChannelError::Send(
                    CHANNEL_ID.to_string(),
                    "WhatsApp gateway session is not established; it may be \
                     restarting — retry shortly"
                        .to_string(),
                ));
            }
            WhatsAppLinkState::Linked | WhatsAppLinkState::Connected => {}
        }

        let to = msg.thread_key.trim();
        if to.is_empty() {
            return Err(ChannelError::Send(
                CHANNEL_ID.to_string(),
                "empty thread_key (chat id)".to_string(),
            ));
        }

        // Text first. The gateway normalizes phone numbers and passes JIDs
        // (user `@s.whatsapp.net`, group `@g.us`, `@lid`) through as-is.
        if !msg.text.trim().is_empty() {
            let resp = self
                .client
                .post(format!("{url}/message/send"))
                .json(&serde_json::json!({ "to": to, "text": msg.text }))
                .timeout(Duration::from_secs(30))
                .send()
                .await
                .map_err(|e| ChannelError::Send(CHANNEL_ID.to_string(), e.to_string()))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                let detail = if body.contains("not connected") {
                    "WhatsApp is not connected — the session may have dropped; \
                     check the QR/link status and retry"
                        .to_string()
                } else {
                    body.chars().take(200).collect()
                };
                return Err(ChannelError::Send(
                    CHANNEL_ID.to_string(),
                    format!("gateway {status}: {detail}"),
                ));
            }
        }

        // Attachments: the gateway exposes /file (documents) and /notify
        // (image + caption). Both enforce the ~/.t3rnel path guard
        // server-side; other kinds have no send path and are skipped.
        for att in &msg.attachments {
            match att.kind.as_str() {
                "file" => {
                    let resp = self
                        .client
                        .post(format!("{url}/file"))
                        .json(&serde_json::json!({
                            "to": to,
                            "path": att.reference,
                            "caption": att.caption,
                            "filename": PathBuf::from(&att.reference)
                                .file_name()
                                .map(|s| s.to_string_lossy().to_string()),
                        }))
                        .timeout(Duration::from_secs(60))
                        .send()
                        .await
                        .map_err(|e| ChannelError::Send(CHANNEL_ID.to_string(), e.to_string()))?;
                    if !resp.status().is_success() {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        return Err(ChannelError::Send(
                            CHANNEL_ID.to_string(),
                            format!(
                                "gateway file send {status}: {}",
                                body.chars().take(200).collect::<String>()
                            ),
                        ));
                    }
                }
                "image" => {
                    let resp = self
                        .client
                        .post(format!("{url}/notify"))
                        .json(&serde_json::json!({
                            "to": to,
                            "text": att.caption.clone().unwrap_or_else(|| "(image)".to_string()),
                            "image": att.reference,
                        }))
                        .timeout(Duration::from_secs(60))
                        .send()
                        .await
                        .map_err(|e| ChannelError::Send(CHANNEL_ID.to_string(), e.to_string()))?;
                    if !resp.status().is_success() {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        return Err(ChannelError::Send(
                            CHANNEL_ID.to_string(),
                            format!(
                                "gateway image send {status}: {}",
                                body.chars().take(200).collect::<String>()
                            ),
                        ));
                    }
                }
                _ => {}
            }
        }

        Ok(Receipt {
            channel: CHANNEL_ID.to_string(),
            account: account.unwrap_or_else(|| msg.account.clone()),
            // The gateway registers outbound ids internally but does not
            // return them; receipts therefore carry no message id.
            message_id: None,
            accepted_at: Utc::now(),
        })
    }

    async fn poll_inbound(&self) -> Result<Vec<ConversationEvent>, ChannelError> {
        let (url, cursor) = {
            let st = self.state.lock().unwrap();
            match &st.url {
                Some(u) => (u.clone(), st.cursor),
                // Never connected — nothing to poll, and no gateway to ask.
                None => return Ok(Vec::new()),
            }
        };

        let resp = self
            .client
            .get(format!("{url}/inbound/events"))
            .query(&[("since", cursor.to_string()), ("limit", "200".to_string())])
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| ChannelError::Poll(CHANNEL_ID.to_string(), e.to_string()))?;

        // Older gateways have no inbound feed — treat as empty rather than
        // erroring every poll tick.
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        if !resp.status().is_success() {
            return Err(ChannelError::Poll(
                CHANNEL_ID.to_string(),
                format!("gateway returned {}", resp.status()),
            ));
        }
        let feed: GatewayEventsResponse = resp.json().await.map_err(|e| {
            ChannelError::Poll(CHANNEL_ID.to_string(), format!("bad events json: {e}"))
        })?;

        // Refresh link state from the same response — the feed reports the
        // durable linked flag so a QR scan flips NeedsLinking → Linked
        // without waiting for the next connect.
        {
            let mut st = self.state.lock().unwrap();
            st.link = Self::link_state_for(feed.linked, feed.connected);
            if !feed.number.is_empty() {
                st.linked_number = Some(feed.number.clone());
            }
            // Advance the cursor past everything consumed. When the page was
            // full there may be more; otherwise jump to `latest` so events
            // evicted from the gateway's ring buffer are not re-fetched.
            st.cursor = if feed.events.len() >= 200 {
                feed.events.last().map(|e| e.seq).unwrap_or(feed.latest)
            } else {
                feed.latest.max(cursor)
            };
        }

        let account = self
            .state
            .lock()
            .unwrap()
            .account
            .clone()
            .unwrap_or_else(|| "default".to_string());
        Ok(feed
            .events
            .iter()
            .map(|ev| self.normalize_inbound(ev, &account))
            .collect())
    }

    fn capabilities(&self) -> ChannelCaps {
        ChannelCaps {
            text: true,
            // Inbound media arrives as placeholder text + an attachment
            // handle; outbound media is limited to gateway /file + /notify
            // image paths.
            media: true,
            buttons: false,
            // Group JIDs act as threads.
            threads: true,
            // The gateway does not return channel message ids on send.
            receipts: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Business mode — WhatsApp Cloud API adapter
// ---------------------------------------------------------------------------

/// Shared state between [`WhatsAppBusinessAdapter`] and the webhook route.
/// The API layer keeps an `Arc` to this and hands webhook payloads to
/// [`BusinessWebhookState::ingest`]; `poll_inbound` drains the same queue.
#[derive(Debug, Default)]
pub struct BusinessWebhookState {
    inner: Mutex<BusinessInner>,
}

#[derive(Debug, Default)]
struct BusinessInner {
    events: VecDeque<ConversationEvent>,
    access_token: Option<Zeroizing<String>>,
    verify_token: Option<Zeroizing<String>>,
    /// Meta app secret for `X-Hub-Signature-256` verification. When set,
    /// webhook POSTs without a valid signature are refused (fail closed).
    app_secret: Option<Zeroizing<String>>,
    phone_number_id: Option<String>,
    /// LinkedAccount.account this session connected as.
    account: Option<String>,
}

impl BusinessWebhookState {
    pub fn new() -> Arc<Self> {
        Arc::new(BusinessWebhookState {
            inner: Mutex::new(BusinessInner::default()),
        })
    }

    /// Constant-time-ish verify-token check for the Meta webhook handshake.
    /// No token configured → always false (fail closed).
    pub fn verify_token_matches(&self, presented: &str) -> bool {
        let inner = self.inner.lock().unwrap();
        match &inner.verify_token {
            Some(expected) => {
                let a = expected.as_bytes();
                let b = presented.as_bytes();
                a.len() == b.len()
                    && a.iter()
                        .zip(b.iter())
                        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
                        == 0
            }
            None => false,
        }
    }

    /// Verify an `X-Hub-Signature-256` header (`sha256=<hex hmac>`) over the
    /// raw request body using the configured app secret. Returns `None`
    /// when no app secret is configured (caller decides policy); `Some(ok)`
    /// otherwise — missing/malformed headers are `Some(false)`.
    pub fn signature_valid(&self, raw_body: &[u8], header: Option<&str>) -> Option<bool> {
        let inner = self.inner.lock().unwrap();
        let secret = inner.app_secret.as_ref()?;
        let presented = header?.strip_prefix("sha256=")?;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).ok()?;
        mac.update(raw_body);
        let expected = hex::encode(mac.finalize().into_bytes());
        // Constant-time compare on equal-length hex strings.
        let ok = expected.len() == presented.len()
            && expected
                .bytes()
                .zip(presented.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0;
        Some(ok)
    }

    /// True once `connect` has resolved the Cloud API credentials — the
    /// webhook route refuses payloads before then (fail closed: an
    /// unauthenticated POST must not inject conversation events).
    pub fn is_configured(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.access_token.is_some() && inner.phone_number_id.is_some()
    }

    /// Normalize one Cloud API webhook payload into queued events.
    /// Returns the number of messages ingested. Status callbacks and
    /// non-message changes are ignored.
    pub fn ingest(&self, payload: &serde_json::Value) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let mut ingested = 0usize;
        let account = inner
            .account
            .clone()
            .or_else(|| inner.phone_number_id.clone())
            .unwrap_or_else(|| "default".to_string());

        let Some(entries) = payload.get("entry").and_then(|e| e.as_array()) else {
            return 0;
        };
        for entry in entries {
            let Some(changes) = entry.get("changes").and_then(|c| c.as_array()) else {
                continue;
            };
            for change in changes {
                let Some(value) = change.get("value") else {
                    continue;
                };
                // Skip pure status/delivery receipts.
                let Some(messages) = value.get("messages").and_then(|m| m.as_array()) else {
                    continue;
                };
                for msg in messages {
                    let from = msg
                        .get("from")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if from.is_empty() {
                        continue;
                    }
                    let mtype = msg.get("type").and_then(|v| v.as_str()).unwrap_or("text");
                    let (text, kind) = match mtype {
                        "text" => (
                            msg.pointer("/text/body")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            None,
                        ),
                        other => {
                            let media_id = msg
                                .get(other)
                                .and_then(|m| m.get("id"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            let caption = msg
                                .get(other)
                                .and_then(|m| m.get("caption"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let label = match other {
                                "image" => "[Image received]",
                                "video" => "[Video received]",
                                "audio" => "[Voice note received]",
                                "document" => "[Document received]",
                                "location" => "[Location received]",
                                "contacts" => "[Contact card received]",
                                "sticker" => "[Sticker received]",
                                _ => "[Unsupported message type]",
                            };
                            (
                                if caption.is_empty() {
                                    label.to_string()
                                } else {
                                    format!("{label}: {caption}")
                                },
                                media_id.map(|id| (other.to_string(), id)),
                            )
                        }
                    };
                    if text.is_empty() && kind.is_none() {
                        continue;
                    }

                    let ts = msg
                        .get("timestamp")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<i64>().ok())
                        .unwrap_or_else(|| Utc::now().timestamp());

                    let mut attachments = Vec::new();
                    if let Some((k, id)) = &kind {
                        attachments.push(AttachmentRef {
                            kind: k.clone(),
                            // Opaque handle: the Cloud API media id,
                            // retrievable via GET /{media-id} with the token.
                            reference: id.clone(),
                            mime: None,
                            caption: None,
                        });
                    }

                    if inner.events.len() >= MAX_QUEUED_EVENTS {
                        inner.events.pop_front();
                    }
                    inner.events.push_back(ConversationEvent {
                        channel: BUSINESS_CHANNEL_ID.to_string(),
                        account: account.clone(),
                        sender: from.clone(),
                        // Cloud API conversations are per-recipient.
                        thread_key: from,
                        message_id: msg
                            .get("id")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        text,
                        attachments,
                        timestamp: DateTime::from_timestamp(ts, 0).unwrap_or_else(Utc::now),
                        provenance: Provenance {
                            source: "channel:whatsapp-business".to_string(),
                            untrusted: true,
                            data_classes: ["personal".to_string()].into_iter().collect(),
                        },
                    });
                    ingested += 1;
                }
            }
        }
        ingested
    }

    fn drain(&self) -> Vec<ConversationEvent> {
        let mut inner = self.inner.lock().unwrap();
        inner.events.drain(..).collect()
    }
}

/// WhatsApp Business Cloud API adapter. Credentials come from the vault via
/// [`BrokeredCreds`]: the linked account declares secret names ending in
/// `:access-token`, `:verify-token` and optionally `:phone-number-id`
/// (e.g. `channel:whatsapp-business:acct-1:access-token`). Inbound arrives
/// through the Meta webhook route, which feeds [`BusinessWebhookState`].
pub struct WhatsAppBusinessAdapter {
    /// API base override for tests; defaults to graph.facebook.com.
    api_base: String,
    /// Phone number id from config (`[channels.whatsapp] phone_number_id`);
    /// a `:phone-number-id` secret overrides it when present.
    configured_phone_number_id: Option<String>,
    state: Arc<BusinessWebhookState>,
    client: reqwest::Client,
}

impl WhatsAppBusinessAdapter {
    pub fn new(state: Arc<BusinessWebhookState>) -> Self {
        WhatsAppBusinessAdapter {
            api_base: "https://graph.facebook.com/v21.0".to_string(),
            configured_phone_number_id: None,
            state,
            client: reqwest::Client::new(),
        }
    }

    /// Share of the webhook state for the API route.
    pub fn webhook_state(&self) -> Arc<BusinessWebhookState> {
        self.state.clone()
    }

    /// Configured phone number id (Cloud API mode requires one).
    pub fn with_phone_number_id(mut self, id: impl Into<String>) -> Self {
        self.configured_phone_number_id = Some(id.into());
        self
    }

    /// API base override — tests point this at a mock server.
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into().trim_end_matches('/').to_string();
        self
    }

    fn secret_suffix<'a>(names: &'a [String], suffix: &str) -> Option<&'a str> {
        names
            .iter()
            .find(|n| n.ends_with(suffix))
            .map(|s| s.as_str())
    }
}

#[async_trait]
impl ChannelAdapter for WhatsAppBusinessAdapter {
    fn id(&self) -> &str {
        BUSINESS_CHANNEL_ID
    }

    async fn connect(&self, creds: &BrokeredCreds) -> Result<(), ChannelError> {
        let names = creds.secret_names();
        let token_name = Self::secret_suffix(&names, ":access-token").ok_or_else(|| {
            ChannelError::CredentialUnavailable(format!(
                "channel:{BUSINESS_CHANNEL_ID}:{}:access-token",
                creds.account()
            ))
        })?;
        let token = creds.resolve(token_name)?;

        let verify_name = Self::secret_suffix(&names, ":verify-token");
        let verify = match verify_name {
            Some(n) => Some(creds.resolve(n)?),
            None => None,
        };
        // Optional `:app-secret` vault secret enables X-Hub-Signature-256
        // verification on webhook POSTs. Absent → signature check skipped
        // (verify-token handshake + loopback bind remain the anchors).
        let app_secret =
            Self::secret_suffix(&names, ":app-secret").and_then(|n| creds.resolve(n).ok());
        let pnid_name = Self::secret_suffix(&names, ":phone-number-id");
        let pnid_secret = match pnid_name {
            Some(n) => Some(creds.resolve(n)?),
            None => None,
        };
        let phone_number_id = pnid_secret
            .as_ref()
            .map(|s| s.to_string())
            .or_else(|| self.configured_phone_number_id.clone())
            .ok_or_else(|| {
                ChannelError::CredentialUnavailable(format!(
                    "channel:{BUSINESS_CHANNEL_ID}:{}:phone-number-id",
                    creds.account()
                ))
            })?;

        {
            let mut inner = self.state.inner.lock().unwrap();
            inner.access_token = Some(token);
            inner.verify_token = verify;
            inner.app_secret = app_secret;
            inner.phone_number_id = Some(phone_number_id);
            inner.account = Some(creds.account().to_string());
        }
        Ok(())
    }

    async fn send(&self, msg: &OutboundMessage) -> Result<Receipt, ChannelError> {
        let (token, phone_number_id, account) = {
            let inner = self.state.inner.lock().unwrap();
            match (&inner.access_token, &inner.phone_number_id) {
                (Some(t), Some(p)) => (
                    t.to_string(),
                    p.clone(),
                    inner.account.clone().unwrap_or_else(|| msg.account.clone()),
                ),
                _ => return Err(ChannelError::NotConnected(BUSINESS_CHANNEL_ID.to_string())),
            }
        };

        let to = msg.thread_key.trim().trim_start_matches('+');
        if to.is_empty() || !to.chars().all(|c| c.is_ascii_digit()) {
            return Err(ChannelError::Send(
                BUSINESS_CHANNEL_ID.to_string(),
                format!("Cloud API recipient must be digits only, got {to:?}"),
            ));
        }

        // Cloud API text limit is 4096 chars — chunk on char boundaries.
        let mut chunks: Vec<String> = Vec::new();
        let mut rest = msg.text.as_str();
        while !rest.is_empty() {
            if rest.chars().count() <= CLOUD_MAX_TEXT {
                chunks.push(rest.to_string());
                break;
            }
            // Byte offset just past the 4096th char (nth is 0-based, so
            // nth(4096) is the start of char #4097).
            let split_at = rest
                .char_indices()
                .nth(CLOUD_MAX_TEXT)
                .map(|(i, _)| i)
                .unwrap_or(rest.len());
            chunks.push(rest[..split_at].to_string());
            rest = &rest[split_at..];
        }
        if chunks.is_empty() {
            chunks.push(String::new());
        }

        let mut last_id = None;
        for chunk in chunks {
            if chunk.trim().is_empty() {
                continue;
            }
            let body = serde_json::json!({
                "messaging_product": "whatsapp",
                "to": to,
                "type": "text",
                "text": { "body": chunk },
            });
            let resp = self
                .client
                .post(format!("{}/{}/messages", self.api_base, phone_number_id))
                .bearer_auth(token.as_str())
                .json(&body)
                .timeout(Duration::from_secs(30))
                .send()
                .await
                .map_err(|e| ChannelError::Send(BUSINESS_CHANNEL_ID.to_string(), e.to_string()))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                // Never echo the token; the body is Meta's error payload.
                return Err(ChannelError::Send(
                    BUSINESS_CHANNEL_ID.to_string(),
                    format!(
                        "cloud api {status}: {}",
                        text.chars().take(300).collect::<String>()
                    ),
                ));
            }
            let json: serde_json::Value = resp.json().await.unwrap_or_default();
            last_id = json
                .pointer("/messages/0/id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or(last_id);
        }

        // Link-addressed media (Cloud API accepts public https links).
        for att in &msg.attachments {
            let mtype = match att.kind.as_str() {
                "image" => "image",
                "file" | "voice" => "document",
                _ => continue,
            };
            if !att.reference.starts_with("https://") && !att.reference.starts_with("http://") {
                continue;
            }
            let body = serde_json::json!({
                "messaging_product": "whatsapp",
                "to": to,
                "type": mtype,
                mtype: {
                    "link": att.reference,
                    "caption": att.caption,
                },
            });
            let resp = self
                .client
                .post(format!("{}/{}/messages", self.api_base, phone_number_id))
                .bearer_auth(token.as_str())
                .json(&body)
                .timeout(Duration::from_secs(30))
                .send()
                .await
                .map_err(|e| ChannelError::Send(BUSINESS_CHANNEL_ID.to_string(), e.to_string()))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(ChannelError::Send(
                    BUSINESS_CHANNEL_ID.to_string(),
                    format!(
                        "cloud api media {status}: {}",
                        text.chars().take(300).collect::<String>()
                    ),
                ));
            }
        }

        Ok(Receipt {
            channel: BUSINESS_CHANNEL_ID.to_string(),
            account,
            message_id: last_id,
            accepted_at: Utc::now(),
        })
    }

    async fn poll_inbound(&self) -> Result<Vec<ConversationEvent>, ChannelError> {
        Ok(self.state.drain())
    }

    fn capabilities(&self) -> ChannelCaps {
        ChannelCaps {
            text: true,
            media: true,
            // Interactive buttons are possible via Cloud API but not wired;
            // approval replies are plain-text YES/NO by design (§2).
            buttons: false,
            threads: false,
            receipts: true,
        }
    }
}

#[cfg(test)]
mod tests;
