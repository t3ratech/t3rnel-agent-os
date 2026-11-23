//! Email channel adapters (IMAP/SMTP and AgentMail).
//!
//! Polls a configured provider for new emails and sends responses through the
//! same provider.
//! Uses the subject line for agent routing (e.g., "\[coder\] Fix this bug").

use crate::types::{ChannelAdapter, ChannelContent, ChannelMessage, ChannelType, ChannelUser};
use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use futures::Stream;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::AsyncSmtpTransport;
use lettre::AsyncTransport;
use lettre::Tokio1Executor;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use t3rnel_types::backoff::{BackoffDecision, BackoffProfile, BackoffSchedule};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

/// SASL PLAIN authenticator for IMAP servers that reject LOGIN
/// (e.g., Lark/Larksuite which only advertise AUTH=PLAIN).
struct PlainAuthenticator {
    username: String,
    password: String,
}

impl imap::Authenticator for PlainAuthenticator {
    type Response = String;
    fn process(&self, _data: &[u8]) -> Self::Response {
        // SASL PLAIN: \0<username>\0<password>
        format!("\x00{}\x00{}", self.username, self.password)
    }
}

/// Reply context for email threading (In-Reply-To / Subject continuity).
#[derive(Debug, Clone)]
struct ReplyCtx {
    subject: String,
    message_id: String,
}

/// Email channel adapter using IMAP for receiving and SMTP for sending.
pub struct EmailAdapter {
    /// IMAP server host.
    imap_host: String,
    /// IMAP port (993 for TLS).
    imap_port: u16,
    /// SMTP server host.
    smtp_host: String,
    /// SMTP port (587 for STARTTLS, 465 for implicit TLS).
    smtp_port: u16,
    /// Email address (used for both IMAP and SMTP).
    username: String,
    /// SECURITY: Password is zeroized on drop.
    password: Zeroizing<String>,
    /// How often to check for new emails.
    poll_interval: Duration,
    /// Which IMAP folders to monitor.
    folders: Vec<String>,
    /// Only process emails from these senders (empty = all).
    allowed_senders: Vec<String>,
    /// Shutdown signal.
    shutdown_tx: Arc<watch::Sender<bool>>,
    shutdown_rx: watch::Receiver<bool>,
    /// Tracks reply context per sender for email threading.
    reply_ctx: Arc<DashMap<String, ReplyCtx>>,
    /// Email retry backoff schedule.
    email_backoff: BackoffSchedule,
}

impl EmailAdapter {
    /// Create a new email adapter.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        imap_host: String,
        imap_port: u16,
        smtp_host: String,
        smtp_port: u16,
        username: String,
        password: String,
        poll_interval_secs: u64,
        folders: Vec<String>,
        allowed_senders: Vec<String>,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            imap_host,
            imap_port,
            smtp_host,
            smtp_port,
            username,
            password: Zeroizing::new(password),
            poll_interval: Duration::from_secs(poll_interval_secs),
            folders: if folders.is_empty() {
                vec!["INBOX".to_string()]
            } else {
                folders
            },
            allowed_senders,
            shutdown_tx: Arc::new(shutdown_tx),
            shutdown_rx,
            reply_ctx: Arc::new(DashMap::new()),
            email_backoff: BackoffSchedule::for_profile(BackoffProfile::Email),
        }
    }

    /// Check if a sender is in the allowlist (empty = allow all). Used in tests.
    #[allow(dead_code)]
    fn is_allowed_sender(&self, sender: &str) -> bool {
        self.allowed_senders.is_empty() || self.allowed_senders.iter().any(|s| sender.contains(s))
    }

    /// Extract agent name from subject line brackets, e.g., "[coder] Fix the bug" -> Some("coder")
    fn extract_agent_from_subject(subject: &str) -> Option<String> {
        let subject = subject.trim();
        if subject.starts_with('[') {
            if let Some(end) = subject.find(']') {
                let agent = &subject[1..end];
                if !agent.is_empty() {
                    return Some(agent.to_string());
                }
            }
        }
        None
    }

    /// Strip the agent tag from a subject line.
    fn strip_agent_tag(subject: &str) -> String {
        let subject = subject.trim();
        if subject.starts_with('[') {
            if let Some(end) = subject.find(']') {
                return subject[end + 1..].trim().to_string();
            }
        }
        subject.to_string()
    }

    /// Build an async SMTP transport for sending emails.
    async fn build_smtp_transport(
        &self,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>, Box<dyn std::error::Error>> {
        let creds = Credentials::new(self.username.clone(), self.password.as_str().to_string());

        let transport = if self.smtp_port == 465 {
            // Implicit TLS (port 465)
            AsyncSmtpTransport::<Tokio1Executor>::relay(&self.smtp_host)?
                .port(self.smtp_port)
                .credentials(creds)
                .build()
        } else {
            // STARTTLS (port 587 or other)
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.smtp_host)?
                .port(self.smtp_port)
                .credentials(creds)
                .build()
        };

        Ok(transport)
    }
}

/// Extract `user@domain` from a potentially formatted email string like `"Name <user@domain>"`.
fn extract_email_addr(raw: &str) -> String {
    let raw = raw.trim();
    if let Some(start) = raw.find('<') {
        if let Some(end) = raw.find('>') {
            if end > start {
                return raw[start + 1..end].trim().to_string();
            }
        }
    }
    raw.to_string()
}

/// Get a specific header value from a parsed email.
fn get_header(parsed: &mailparse::ParsedMail<'_>, name: &str) -> Option<String> {
    parsed
        .headers
        .iter()
        .find(|h| h.get_key().eq_ignore_ascii_case(name))
        .map(|h| h.get_value())
}

/// Extract the text/plain body from a parsed email (handles multipart).
fn extract_text_body(parsed: &mailparse::ParsedMail<'_>) -> String {
    if parsed.subparts.is_empty() {
        return parsed.get_body().unwrap_or_default();
    }
    // Walk subparts looking for text/plain
    for part in &parsed.subparts {
        let ct = part.ctype.mimetype.to_lowercase();
        if ct == "text/plain" {
            return part.get_body().unwrap_or_default();
        }
    }
    // Fallback: first subpart body
    parsed
        .subparts
        .first()
        .and_then(|p| p.get_body().ok())
        .unwrap_or_default()
}

fn notify_new_email_received() {
    std::thread::spawn(|| {
        let _ = std::process::Command::new("notify-send")
            .arg("T3rnel Email")
            .arg("New email arrived in the configured inbox.")
            .arg("--urgency=normal")
            .arg("--icon=mail-unread")
            .spawn();
    });
}

#[derive(Debug, Clone, Deserialize)]
struct AgentMailListResponse {
    #[serde(default)]
    messages: Vec<AgentMailMessage>,
}

#[derive(Debug, Clone, Deserialize)]
struct AgentMailMessage {
    message_id: String,
    #[serde(default)]
    thread_id: Option<String>,
    #[serde(default)]
    labels: Vec<String>,
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    preview: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    html: Option<String>,
    #[serde(default)]
    extracted_text: Option<String>,
    #[serde(default)]
    extracted_html: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AgentMailSendResponse {
    message_id: String,
    thread_id: String,
}

/// Email channel adapter using AgentMail's HTTP API.
pub struct AgentMailAdapter {
    inbox_id: String,
    api_key: Zeroizing<String>,
    base_url: String,
    poll_interval: Duration,
    allowed_senders: Vec<String>,
    shutdown_tx: Arc<watch::Sender<bool>>,
    shutdown_rx: watch::Receiver<bool>,
    reply_ctx: Arc<DashMap<String, ReplyCtx>>,
    email_backoff: BackoffSchedule,
    client: reqwest::Client,
}

impl AgentMailAdapter {
    /// Create a new AgentMail adapter.
    pub fn new(
        api_key: String,
        inbox_id: String,
        poll_interval_secs: u64,
        allowed_senders: Vec<String>,
        base_url: Option<String>,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            inbox_id,
            api_key: Zeroizing::new(api_key),
            base_url: base_url
                .unwrap_or_else(|| "https://api.agentmail.to/v0".to_string())
                .trim_end_matches('/')
                .to_string(),
            poll_interval: Duration::from_secs(poll_interval_secs),
            allowed_senders,
            shutdown_tx: Arc::new(shutdown_tx),
            shutdown_rx,
            reply_ctx: Arc::new(DashMap::new()),
            email_backoff: BackoffSchedule::for_profile(BackoffProfile::Email),
            client: reqwest::Client::new(),
        }
    }

    fn inbox_url(&self, suffix: &str) -> String {
        format!(
            "{}/inboxes/{}{}",
            self.base_url,
            encode_path_component(&self.inbox_id),
            suffix
        )
    }

    async fn request_json<T: DeserializeOwned>(
        api_key: &str,
        request: reqwest::RequestBuilder,
    ) -> Result<T, String> {
        let response = request
            .bearer_auth(api_key)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| format!("AgentMail request failed: {e}"))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| format!("AgentMail response read failed: {e}"))?;
        if !status.is_success() {
            return Err(format!(
                "AgentMail HTTP {}: {}",
                status.as_u16(),
                text.chars().take(500).collect::<String>()
            ));
        }
        serde_json::from_str(&text).map_err(|e| format!("AgentMail JSON parse failed: {e}"))
    }

    async fn fetch_unread_messages(
        client: &reqwest::Client,
        api_key: &str,
        base_url: &str,
        inbox_id: &str,
    ) -> Result<Vec<AgentMailMessage>, String> {
        let list_url = format!(
            "{}/inboxes/{}/messages?limit=50",
            base_url,
            encode_path_component(inbox_id)
        );
        let list: AgentMailListResponse = Self::request_json(api_key, client.get(list_url)).await?;
        let mut unread = Vec::new();
        for msg in list.messages {
            if !msg.labels.iter().any(|label| label == "unread")
                || !msg.labels.iter().any(|label| label == "received")
            {
                continue;
            }
            let full_url = format!(
                "{}/inboxes/{}/messages/{}",
                base_url,
                encode_path_component(inbox_id),
                encode_path_component(&msg.message_id)
            );
            match Self::request_json(api_key, client.get(full_url)).await {
                Ok(full) => unread.push(full),
                Err(err) => {
                    warn!(
                        message_id = %msg.message_id,
                        error = %err,
                        "AgentMail message fetch failed; using list entry"
                    );
                    unread.push(msg);
                }
            }
        }
        Ok(unread)
    }

    async fn update_message_labels(
        client: &reqwest::Client,
        api_key: &str,
        base_url: &str,
        inbox_id: &str,
        message_id: &str,
    ) -> Result<(), String> {
        let url = format!(
            "{}/inboxes/{}/messages/{}",
            base_url,
            encode_path_component(inbox_id),
            encode_path_component(message_id)
        );
        let payload = serde_json::json!({
            "add_labels": ["read", "processed"],
            "remove_labels": ["unread"]
        });
        let _: serde_json::Value =
            Self::request_json(api_key, client.patch(url).json(&payload)).await?;
        Ok(())
    }

    async fn send_agentmail_message(
        &self,
        to_addr: &str,
        subject: &str,
        body: &str,
    ) -> Result<AgentMailSendResponse, String> {
        let payload = serde_json::json!({
            "to": to_addr,
            "subject": subject,
            "text": body,
            "labels": ["t3rnel", "agent-reply"]
        });
        Self::request_json(
            self.api_key.as_str(),
            self.client
                .post(self.inbox_url("/messages/send"))
                .json(&payload),
        )
        .await
    }

    async fn reply_agentmail_message(
        &self,
        source_message_id: &str,
        body: &str,
    ) -> Result<AgentMailSendResponse, String> {
        let payload = serde_json::json!({
            "text": body,
            "labels": ["t3rnel", "agent-reply"]
        });
        let url = self.inbox_url(&format!(
            "/messages/{}/reply",
            encode_path_component(source_message_id)
        ));
        Self::request_json(self.api_key.as_str(), self.client.post(url).json(&payload)).await
    }

    fn message_body(msg: &AgentMailMessage) -> String {
        msg.extracted_text
            .as_deref()
            .or(msg.text.as_deref())
            .or(msg.preview.as_deref())
            .or(msg.extracted_html.as_deref())
            .or(msg.html.as_deref())
            .unwrap_or_default()
            .trim()
            .to_string()
    }
}

fn encode_path_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        let keep = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~');
        if keep {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

#[async_trait]
impl ChannelAdapter for AgentMailAdapter {
    fn name(&self) -> &str {
        "email-agentmail"
    }

    fn channel_type(&self) -> ChannelType {
        ChannelType::Email
    }

    async fn start(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = ChannelMessage> + Send>>, Box<dyn std::error::Error>>
    {
        let (tx, rx) = mpsc::channel::<ChannelMessage>(256);
        let poll_interval = self.poll_interval;
        let email_backoff = self.email_backoff.clone();
        let inbox_id = self.inbox_id.clone();
        let base_url = self.base_url.clone();
        let api_key = self.api_key.as_str().to_string();
        let allowed_senders = self.allowed_senders.clone();
        let client = self.client.clone();
        let reply_ctx = self.reply_ctx.clone();
        let mut shutdown_rx = self.shutdown_rx.clone();

        info!(
            inbox = %inbox_id,
            poll_interval_secs = poll_interval.as_secs(),
            "Starting AgentMail email adapter"
        );

        tokio::spawn(async move {
            let mut consecutive_errors = 0u32;
            loop {
                let sleep_duration = if consecutive_errors == 0 {
                    poll_interval
                } else {
                    match email_backoff.decision_for_attempt(consecutive_errors - 1) {
                        BackoffDecision::RetryAfter(delay) => delay,
                        BackoffDecision::Stop => {
                            error!(
                                attempt = consecutive_errors,
                                "AgentMail retry schedule exhausted; stopping email adapter"
                            );
                            break;
                        }
                    }
                };

                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        info!("AgentMail email adapter shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(sleep_duration) => {}
                }

                let messages = match AgentMailAdapter::fetch_unread_messages(
                    &client, &api_key, &base_url, &inbox_id,
                )
                .await
                {
                    Ok(messages) => {
                        consecutive_errors = 0;
                        messages
                    }
                    Err(err) => {
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        error!(
                            error = %err,
                            attempt = consecutive_errors,
                            next_decision = ?email_backoff.decision_for_attempt(consecutive_errors - 1),
                            "AgentMail poll error"
                        );
                        continue;
                    }
                };

                for message in messages {
                    let from_raw = message.from.clone().unwrap_or_default();
                    let from_addr = extract_email_addr(&from_raw);
                    if !allowed_senders.is_empty()
                        && !allowed_senders.iter().any(|s| from_addr.contains(s))
                    {
                        debug!(from = %from_addr, "AgentMail sender not allowed, skipping");
                        continue;
                    }

                    notify_new_email_received();

                    let subject = message.subject.clone().unwrap_or_default();
                    let body = AgentMailAdapter::message_body(&message);
                    reply_ctx.insert(
                        from_addr.clone(),
                        ReplyCtx {
                            subject: subject.clone(),
                            message_id: message.message_id.clone(),
                        },
                    );

                    let clean_subject = EmailAdapter::strip_agent_tag(&subject);
                    let text = if clean_subject.is_empty() {
                        body
                    } else {
                        format!("Subject: {clean_subject}\n\n{body}")
                    };
                    let mut metadata = std::collections::HashMap::new();
                    metadata.insert(
                        "agentmail_inbox_id".to_string(),
                        serde_json::Value::String(inbox_id.clone()),
                    );
                    if let Some(thread_id) = &message.thread_id {
                        metadata.insert(
                            "agentmail_thread_id".to_string(),
                            serde_json::Value::String(thread_id.clone()),
                        );
                    }

                    let msg = ChannelMessage {
                        channel: ChannelType::Email,
                        platform_message_id: message.message_id.clone(),
                        sender: ChannelUser {
                            platform_id: from_addr.clone(),
                            display_name: if from_raw.is_empty() {
                                from_addr.clone()
                            } else {
                                from_raw.clone()
                            },
                            t3rnel_user: None,
                        },
                        content: ChannelContent::Text(text),
                        target_agent: None,
                        timestamp: Utc::now(),
                        is_group: false,
                        thread_id: message.thread_id.clone(),
                        metadata,
                    };

                    if tx.send(msg).await.is_err() {
                        info!("Email channel receiver dropped, stopping AgentMail poll");
                        return;
                    }

                    if let Err(err) = AgentMailAdapter::update_message_labels(
                        &client,
                        &api_key,
                        &base_url,
                        &inbox_id,
                        &message.message_id,
                    )
                    .await
                    {
                        warn!(
                            message_id = %message.message_id,
                            error = %err,
                            "AgentMail message label update failed"
                        );
                    }
                }
            }
        });

        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn send(
        &self,
        user: &ChannelUser,
        content: ChannelContent,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ChannelContent::Text(text) = content else {
            warn!(
                "Unsupported email content type for {}, only text is supported",
                user.platform_id
            );
            return Ok(());
        };

        let to_addr = extract_email_addr(&user.platform_id);
        let (subject, body) = if text.starts_with("Subject: ") {
            if let Some(pos) = text.find("\n\n") {
                let subj = text[9..pos].trim().to_string();
                let body = text[pos + 2..].to_string();
                (subj, body)
            } else {
                ("T3rnel Reply".to_string(), text)
            }
        } else {
            let subj = self
                .reply_ctx
                .get(&to_addr)
                .map(|ctx| format!("Re: {}", ctx.subject))
                .unwrap_or_else(|| "T3rnel Reply".to_string());
            (subj, text)
        };

        let mut attempt = 0u32;
        loop {
            let reply_message_id = self
                .reply_ctx
                .get(&to_addr)
                .map(|ctx| ctx.message_id.clone());
            let result = if let Some(message_id) = reply_message_id {
                self.reply_agentmail_message(&message_id, &body).await
            } else {
                self.send_agentmail_message(&to_addr, &subject, &body).await
            };

            match result {
                Ok(response) => {
                    info!(
                        to = %to_addr,
                        subject = %subject,
                        message_id = %response.message_id,
                        thread_id = %response.thread_id,
                        "Email sent successfully via AgentMail"
                    );
                    return Ok(());
                }
                Err(err) => {
                    warn!(
                        to = %to_addr,
                        attempt = attempt + 1,
                        error = %err,
                        next_decision = ?self.email_backoff.decision_for_attempt(attempt),
                        "AgentMail send failed"
                    );
                    match self.email_backoff.decision_for_attempt(attempt) {
                        BackoffDecision::RetryAfter(delay) => {
                            tokio::time::sleep(delay).await;
                            attempt = attempt.saturating_add(1);
                        }
                        BackoffDecision::Stop => return Err(err.into()),
                    }
                }
            }
        }
    }

    async fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.shutdown_tx.send(true);
        Ok(())
    }
}

/// Fetch unseen emails from IMAP using blocking I/O.
/// Returns a Vec of (from_addr, subject, message_id, body).
fn fetch_unseen_emails(
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    folders: &[String],
) -> Result<Vec<(String, String, String, String)>, String> {
    let client = imap::ClientBuilder::new(host, port)
        .mode(if port == 993 {
            imap::ConnectionMode::Tls
        } else {
            imap::ConnectionMode::AutoTls
        })
        .connect()
        .map_err(|e| format!("IMAP connect failed: {e}"))?;

    // Try LOGIN first; fall back to AUTHENTICATE PLAIN for servers like Lark
    // that reject LOGIN and only support AUTH=PLAIN (SASL).
    let mut session = match client.login(username, password) {
        Ok(s) => s,
        Err((login_err, client)) => {
            let authenticator = PlainAuthenticator {
                username: username.to_string(),
                password: password.to_string(),
            };
            client
                .authenticate("PLAIN", &authenticator)
                .map_err(|(e, _)| {
                    format!("IMAP login failed: {login_err}; AUTH=PLAIN also failed: {e}")
                })?
        }
    };

    let mut results = Vec::new();

    for folder in folders {
        if let Err(e) = session.select(folder) {
            warn!(folder, error = %e, "IMAP SELECT failed, skipping folder");
            continue;
        }

        let uids = match session.uid_search("UNSEEN") {
            Ok(uids) => uids,
            Err(e) => {
                warn!(folder, error = %e, "IMAP SEARCH UNSEEN failed");
                continue;
            }
        };

        if uids.is_empty() {
            debug!(folder, "No unseen emails");
            continue;
        }

        // Fetch in batches of up to 50 to avoid huge responses
        let uid_list: Vec<u32> = uids.into_iter().take(50).collect();
        let uid_set: String = uid_list
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let fetches = match session.uid_fetch(&uid_set, "RFC822") {
            Ok(f) => f,
            Err(e) => {
                warn!(folder, error = %e, "IMAP FETCH failed");
                continue;
            }
        };

        for fetch in fetches.iter() {
            let body_bytes = match fetch.body() {
                Some(b) => b,
                None => continue,
            };

            let parsed = match mailparse::parse_mail(body_bytes) {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "Failed to parse email");
                    continue;
                }
            };

            let from = get_header(&parsed, "From").unwrap_or_default();
            let subject = get_header(&parsed, "Subject").unwrap_or_default();
            let message_id = get_header(&parsed, "Message-ID").unwrap_or_default();
            let text_body = extract_text_body(&parsed);

            let from_addr = extract_email_addr(&from);
            results.push((from_addr, subject, message_id, text_body));
        }

        // Mark fetched messages as Seen
        if let Err(e) = session.uid_store(&uid_set, "+FLAGS (\\Seen)") {
            warn!(error = %e, "Failed to mark emails as Seen");
        }
    }

    let _ = session.logout();
    Ok(results)
}

#[async_trait]
impl ChannelAdapter for EmailAdapter {
    fn name(&self) -> &str {
        "email"
    }

    fn channel_type(&self) -> ChannelType {
        ChannelType::Email
    }

    async fn start(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = ChannelMessage> + Send>>, Box<dyn std::error::Error>>
    {
        let (tx, rx) = mpsc::channel::<ChannelMessage>(256);
        let poll_interval = self.poll_interval;
        let email_backoff = self.email_backoff.clone();
        let imap_host = self.imap_host.clone();
        let imap_port = self.imap_port;
        let username = self.username.clone();
        let password = self.password.clone();
        let folders = self.folders.clone();
        let allowed_senders = self.allowed_senders.clone();
        let mut shutdown_rx = self.shutdown_rx.clone();
        let reply_ctx = self.reply_ctx.clone();

        info!(
            "Starting email adapter (IMAP: {}:{}, SMTP: {}:{}, polling every {:?})",
            imap_host, imap_port, self.smtp_host, self.smtp_port, poll_interval
        );

        tokio::spawn(async move {
            let mut consecutive_errors = 0u32;
            loop {
                let sleep_duration = if consecutive_errors == 0 {
                    poll_interval
                } else {
                    match email_backoff.decision_for_attempt(consecutive_errors - 1) {
                        BackoffDecision::RetryAfter(delay) => delay,
                        BackoffDecision::Stop => {
                            error!(
                                attempt = consecutive_errors,
                                "IMAP poll retry schedule is exhausted; stopping email adapter"
                            );
                            break;
                        }
                    }
                };

                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        info!("Email adapter shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(sleep_duration) => {}
                }

                // IMAP operations are blocking I/O — run in spawn_blocking
                let host = imap_host.clone();
                let port = imap_port;
                let user = username.clone();
                let pass = password.clone();
                let fldrs = folders.clone();

                let emails = tokio::task::spawn_blocking(move || {
                    fetch_unseen_emails(&host, port, &user, pass.as_str(), &fldrs)
                })
                .await;

                let emails = match emails {
                    Ok(Ok(emails)) => {
                        consecutive_errors = 0;
                        emails
                    }
                    Ok(Err(e)) => {
                        consecutive_errors += 1;
                        error!(
                            error = %e,
                            attempt = consecutive_errors,
                            next_decision = ?email_backoff.decision_for_attempt(consecutive_errors - 1),
                            "IMAP poll error; backing off"
                        );
                        continue;
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        error!(
                            error = %e,
                            attempt = consecutive_errors,
                            next_decision = ?email_backoff.decision_for_attempt(consecutive_errors - 1),
                            "IMAP spawn_blocking panic; backing off"
                        );
                        continue;
                    }
                };

                for (from_addr, subject, message_id, body) in emails {
                    // Check allowed senders
                    if !allowed_senders.is_empty()
                        && !allowed_senders.iter().any(|s| from_addr.contains(s))
                    {
                        debug!(from = %from_addr, "Email from non-allowed sender, skipping");
                        continue;
                    }

                    notify_new_email_received();

                    // Store reply context for threading
                    if !message_id.is_empty() {
                        reply_ctx.insert(
                            from_addr.clone(),
                            ReplyCtx {
                                subject: subject.clone(),
                                message_id: message_id.clone(),
                            },
                        );
                    }

                    // Extract target agent from subject brackets (stored in metadata for router)
                    let _target_agent = EmailAdapter::extract_agent_from_subject(&subject);
                    let clean_subject = EmailAdapter::strip_agent_tag(&subject);

                    // Build the message body: prepend subject context
                    let text = if clean_subject.is_empty() {
                        body.trim().to_string()
                    } else {
                        format!("Subject: {clean_subject}\n\n{}", body.trim())
                    };

                    let msg = ChannelMessage {
                        channel: ChannelType::Email,
                        platform_message_id: message_id.clone(),
                        sender: ChannelUser {
                            platform_id: from_addr.clone(),
                            display_name: from_addr.clone(),
                            t3rnel_user: None,
                        },
                        content: ChannelContent::Text(text),
                        target_agent: None, // Routing handled by bridge AgentRouter
                        timestamp: Utc::now(),
                        is_group: false,
                        thread_id: None,
                        metadata: std::collections::HashMap::new(),
                    };

                    if tx.send(msg).await.is_err() {
                        info!("Email channel receiver dropped, stopping poll");
                        return;
                    }
                }
            }
        });

        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn send(
        &self,
        user: &ChannelUser,
        content: ChannelContent,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match content {
            ChannelContent::Text(text) => {
                // Parse recipient address
                let to_addr = extract_email_addr(&user.platform_id);
                let to_mailbox: Mailbox = to_addr
                    .parse()
                    .map_err(|e| format!("Invalid recipient email '{}': {}", to_addr, e))?;

                let from_mailbox: Mailbox = self
                    .username
                    .parse()
                    .map_err(|e| format!("Invalid sender email '{}': {}", self.username, e))?;

                // Extract subject from text body convention: "Subject: ...\n\n..."
                let (subject, body) = if text.starts_with("Subject: ") {
                    if let Some(pos) = text.find("\n\n") {
                        let subj = text[9..pos].trim().to_string();
                        let body = text[pos + 2..].to_string();
                        (subj, body)
                    } else {
                        ("T3rnel Reply".to_string(), text)
                    }
                } else {
                    // Check reply context for subject continuity
                    let subj = self
                        .reply_ctx
                        .get(&to_addr)
                        .map(|ctx| format!("Re: {}", ctx.subject))
                        .unwrap_or_else(|| "T3rnel Reply".to_string());
                    (subj, text)
                };

                // Build email message
                let mut builder = lettre::Message::builder()
                    .from(from_mailbox)
                    .to(to_mailbox)
                    .subject(&subject);

                // Add In-Reply-To header for threading
                if let Some(ctx) = self.reply_ctx.get(&to_addr) {
                    if !ctx.message_id.is_empty() {
                        builder = builder.in_reply_to(ctx.message_id.clone());
                    }
                }

                let email = builder
                    .body(body)
                    .map_err(|e| format!("Failed to build email: {e}"))?;

                // Send via SMTP with email-specific retry backoff.
                let mut attempt = 0u32;
                loop {
                    let transport = self.build_smtp_transport().await?;
                    match transport.send(email.clone()).await {
                        Ok(_) => {
                            info!(
                                to = %to_addr,
                                subject = %subject,
                                "Email sent successfully via SMTP"
                            );
                            break;
                        }
                        Err(e) => {
                            let msg = format!("SMTP send failed: {e}");
                            warn!(
                                attempt = attempt + 1,
                                error = %msg,
                                next_decision = ?self.email_backoff.decision_for_attempt(attempt),
                                "SMTP send failed"
                            );
                            match self.email_backoff.decision_for_attempt(attempt) {
                                BackoffDecision::RetryAfter(delay) => {
                                    tokio::time::sleep(delay).await;
                                }
                                BackoffDecision::Stop => return Err(msg.into()),
                            }
                            attempt = attempt.saturating_add(1);
                        }
                    }
                }
            }
            _ => {
                warn!(
                    "Unsupported email content type for {}, only text is supported",
                    user.platform_id
                );
            }
        }
        Ok(())
    }

    async fn stop(&self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.shutdown_tx.send(true);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_adapter_creation() {
        let adapter = EmailAdapter::new(
            "imap.example.com".to_string(),
            993,
            "smtp.example.com".to_string(),
            587,
            "user@example.com".to_string(),
            "password".to_string(),
            30,
            vec![],
            vec![],
        );
        assert_eq!(adapter.name(), "email");
        assert_eq!(adapter.folders, vec!["INBOX".to_string()]);
    }

    #[test]
    fn test_allowed_senders() {
        let adapter = EmailAdapter::new(
            "imap.example.com".to_string(),
            993,
            "smtp.example.com".to_string(),
            587,
            "bot@example.com".to_string(),
            "pass".to_string(),
            30,
            vec![],
            vec!["boss@company.com".to_string()],
        );
        assert!(adapter.is_allowed_sender("boss@company.com"));
        assert!(!adapter.is_allowed_sender("random@other.com"));

        let open = EmailAdapter::new(
            "imap.example.com".to_string(),
            993,
            "smtp.example.com".to_string(),
            587,
            "bot@example.com".to_string(),
            "pass".to_string(),
            30,
            vec![],
            vec![],
        );
        assert!(open.is_allowed_sender("anyone@anywhere.com"));
    }

    #[test]
    fn test_extract_agent_from_subject() {
        assert_eq!(
            EmailAdapter::extract_agent_from_subject("[coder] Fix the bug"),
            Some("coder".to_string())
        );
        assert_eq!(
            EmailAdapter::extract_agent_from_subject("[researcher] Find papers on AI"),
            Some("researcher".to_string())
        );
        assert_eq!(
            EmailAdapter::extract_agent_from_subject("No brackets here"),
            None
        );
        assert_eq!(
            EmailAdapter::extract_agent_from_subject("[] Empty brackets"),
            None
        );
    }

    #[test]
    fn test_strip_agent_tag() {
        assert_eq!(
            EmailAdapter::strip_agent_tag("[coder] Fix the bug"),
            "Fix the bug"
        );
        assert_eq!(EmailAdapter::strip_agent_tag("No brackets"), "No brackets");
    }

    #[test]
    fn test_extract_email_addr() {
        assert_eq!(
            extract_email_addr("John Doe <john@example.com>"),
            "john@example.com"
        );
        assert_eq!(extract_email_addr("user@example.com"), "user@example.com");
        assert_eq!(extract_email_addr("<user@test.com>"), "user@test.com");
    }

    #[test]
    fn test_subject_extraction_from_body() {
        let text = "Subject: Test Subject\n\nThis is the body.";
        assert!(text.starts_with("Subject: "));
        let pos = text.find("\n\n").unwrap();
        let subject = &text[9..pos];
        let body = &text[pos + 2..];
        assert_eq!(subject, "Test Subject");
        assert_eq!(body, "This is the body.");
    }

    #[test]
    fn test_reply_ctx_threading() {
        let ctx_map: DashMap<String, ReplyCtx> = DashMap::new();
        ctx_map.insert(
            "user@test.com".to_string(),
            ReplyCtx {
                subject: "Original Subject".to_string(),
                message_id: "<msg-123@test.com>".to_string(),
            },
        );
        let ctx = ctx_map.get("user@test.com").unwrap();
        assert_eq!(ctx.subject, "Original Subject");
        assert_eq!(ctx.message_id, "<msg-123@test.com>");
    }
}
