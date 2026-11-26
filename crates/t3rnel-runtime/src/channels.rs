//! Channel adapter layer (`docs/sections/18-conversations-approvals-and-briefings.md` §3).
//!
//! Every messaging surface — WhatsApp, Telegram, Discord, email, the local
//! dashboard — is a [`ChannelAdapter`] behind one contract. Adding a channel
//! is a new adapter, never a fork of the core. Channel credentials are vault
//! secrets resolved through [`BrokeredCreds`] at connect time; adapters never
//! see raw secret material beyond that scope, and plugins never see channel
//! credentials at all (they hold opaque conversation refs only).
//!
//! [`ChannelRegistry`] is the dispatch point: it owns the connected adapters
//! and the per-user linked-account table persisted under
//! `<home>/channels/accounts.json`.

pub mod whatsapp;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::conversations::ConversationEvent;
use crate::plugin_vault::{BrokerError, VaultBroker};

// ---------------------------------------------------------------------------
// Contract types
// ---------------------------------------------------------------------------

/// What a channel can do — drives template selection and feature gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelCaps {
    pub text: bool,
    pub media: bool,
    pub buttons: bool,
    pub threads: bool,
    pub receipts: bool,
}

impl ChannelCaps {
    pub const TEXT_ONLY: ChannelCaps = ChannelCaps {
        text: true,
        media: false,
        buttons: false,
        threads: false,
        receipts: false,
    };
}

/// A media/file reference carried by an outbound or inbound message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentRef {
    /// "image" | "file" | "voice" | "location"
    pub kind: String,
    /// URL or opaque handle the channel understands.
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
}

/// One outbound message handed to an adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundMessage {
    /// Linked account this goes out through.
    pub account: String,
    /// Thread/conversation key on the channel side.
    pub thread_key: String,
    /// Human-readable text (already template-rendered by the caller).
    pub text: String,
    /// Optional attachments.
    #[serde(default)]
    pub attachments: Vec<AttachmentRef>,
    /// Channel-native extras (reply-to id, buttons payload, ...).
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

/// Proof a channel accepted a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub channel: String,
    pub account: String,
    /// Channel-native message id when the platform issues one.
    pub message_id: Option<String>,
    pub accepted_at: DateTime<Utc>,
}

/// Errors surfaced by adapters and the registry. They never contain secret
/// material — resolution failures are reported by secret *name* only.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("channel {0} is not connected")]
    NotConnected(String),
    #[error("channel {0} has no adapter registered")]
    NoAdapter(String),
    #[error("channel {0} send failed: {1}")]
    Send(String, String),
    #[error("channel {0} poll failed: {1}")]
    Poll(String, String),
    #[error("credential {0:?} unavailable for this account")]
    CredentialUnavailable(String),
    #[error("io error: {0}")]
    Io(String),
}

impl From<BrokerError> for ChannelError {
    fn from(e: BrokerError) -> Self {
        match e {
            BrokerError::NotFound(name) => ChannelError::CredentialUnavailable(name),
            other => ChannelError::Io(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Brokered credentials
// ---------------------------------------------------------------------------

/// Credentials handed to an adapter at `connect` time. The adapter may
/// resolve ONLY the secret names the linked account declared; everything
/// else is refused. Resolved values are `Zeroizing` and must not be logged,
/// persisted, or returned across the plugin boundary.
pub struct BrokeredCreds {
    vault: Arc<VaultBroker>,
    account: String,
    /// Secret names this account is allowed to resolve (e.g.
    /// `channel:whatsapp:acct-main:session`).
    allowed: BTreeSet<String>,
}

impl BrokeredCreds {
    pub fn new(vault: Arc<VaultBroker>, account: impl Into<String>, allowed: Vec<String>) -> Self {
        BrokeredCreds {
            vault,
            account: account.into(),
            allowed: allowed.into_iter().collect(),
        }
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    /// Resolve one declared secret. `Err(CredentialUnavailable)` for names
    /// outside the account's declared set or absent from the vault.
    pub fn resolve(&self, name: &str) -> Result<Zeroizing<String>, ChannelError> {
        if !self.allowed.contains(name) {
            return Err(ChannelError::CredentialUnavailable(name.to_string()));
        }
        self.vault.resolve(name).map_err(Into::into)
    }

    /// Declared secret names (references only — never values).
    pub fn secret_names(&self) -> Vec<String> {
        self.allowed.iter().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// The adapter contract (18 §3)
// ---------------------------------------------------------------------------

#[async_trait]
pub trait ChannelAdapter: Send + Sync {
    /// Stable channel id, e.g. "whatsapp", "telegram", "local".
    fn id(&self) -> &str;

    /// Establish the channel session. Called once per linked account with
    /// brokered credentials; adapters must not retain the `BrokeredCreds`
    /// itself, only what they need to operate.
    async fn connect(&self, creds: &BrokeredCreds) -> Result<(), ChannelError>;

    /// Send one message; returns the channel receipt.
    async fn send(&self, msg: &OutboundMessage) -> Result<Receipt, ChannelError>;

    /// Pull normalized inbound events. Push/webhook channels drain an
    /// internal queue here; poll channels fetch from the platform.
    async fn poll_inbound(&self) -> Result<Vec<ConversationEvent>, ChannelError>;

    fn capabilities(&self) -> ChannelCaps;
}

// ---------------------------------------------------------------------------
// Linked accounts
// ---------------------------------------------------------------------------

/// A user-linked channel account. `secret_names` are vault references —
/// the registry uses them to build each account's [`BrokeredCreds`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedAccount {
    pub channel: String,
    /// Channel-side account id (phone number, bot id, mailbox, ...).
    pub account: String,
    /// Optional human label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Vault secret names this account may resolve at connect.
    #[serde(default)]
    pub secret_names: Vec<String>,
    pub linked_at: DateTime<Utc>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AccountsFile {
    accounts: Vec<LinkedAccount>,
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Owns adapters and linked accounts. One registry per daemon; adapters are
/// shared `Arc`s so the conversation service and API routes see the same
/// connected sessions.
pub struct ChannelRegistry {
    adapters: Mutex<BTreeMap<String, Arc<dyn ChannelAdapter>>>,
    accounts: Mutex<Vec<LinkedAccount>>,
    accounts_path: PathBuf,
    /// Vault used to build per-account [`BrokeredCreds`] at connect time.
    vault: Option<Arc<VaultBroker>>,
}

impl ChannelRegistry {
    /// `home` is the T3rnel home dir (scratch dir in tests).
    pub fn new(home: &Path) -> Self {
        ChannelRegistry {
            adapters: Mutex::new(BTreeMap::new()),
            accounts: Mutex::new(Vec::new()),
            accounts_path: home.join("channels").join("accounts.json"),
            vault: None,
        }
    }

    /// Attach the vault broker used for connect-time credential brokering.
    pub fn set_vault(&mut self, vault: Arc<VaultBroker>) {
        self.vault = Some(vault);
    }

    /// Load persisted linked accounts. Missing file = empty registry.
    pub fn load(&self) -> std::io::Result<()> {
        let text = match std::fs::read_to_string(&self.accounts_path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let file: AccountsFile = serde_json::from_str(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        *self.accounts.lock().unwrap() = file.accounts;
        Ok(())
    }

    fn save_accounts(&self) -> std::io::Result<()> {
        if let Some(parent) = self.accounts_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = AccountsFile {
            accounts: self.accounts.lock().unwrap().clone(),
        };
        let tmp = self.accounts_path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&file)?)?;
        std::fs::rename(&tmp, &self.accounts_path)?;
        Ok(())
    }

    /// Register (or replace) an adapter for its channel id.
    pub fn register_adapter(&self, adapter: Arc<dyn ChannelAdapter>) {
        self.adapters
            .lock()
            .unwrap()
            .insert(adapter.id().to_string(), adapter);
    }

    pub fn adapter(&self, channel: &str) -> Option<Arc<dyn ChannelAdapter>> {
        self.adapters.lock().unwrap().get(channel).cloned()
    }

    pub fn adapter_ids(&self) -> Vec<String> {
        self.adapters.lock().unwrap().keys().cloned().collect()
    }

    /// Link a channel account for this user. Persisted immediately.
    pub fn link_account(&self, account: LinkedAccount) -> std::io::Result<()> {
        {
            let mut accounts = self.accounts.lock().unwrap();
            accounts.retain(|a| !(a.channel == account.channel && a.account == account.account));
            accounts.push(account);
        }
        self.save_accounts()
    }

    pub fn unlink_account(&self, channel: &str, account: &str) -> bool {
        let removed = {
            let mut accounts = self.accounts.lock().unwrap();
            let before = accounts.len();
            accounts.retain(|a| !(a.channel == channel && a.account == account));
            accounts.len() != before
        };
        if removed {
            let _ = self.save_accounts();
        }
        removed
    }

    pub fn linked_accounts(&self) -> Vec<LinkedAccount> {
        self.accounts.lock().unwrap().clone()
    }

    /// Connect every linked account that has a registered adapter, using
    /// brokered credentials scoped to that account's declared secret names.
    /// Accounts whose adapter is absent are skipped; connect failures are
    /// reported per account, never fatal to the rest.
    pub async fn connect_all(&self) -> Vec<(String, Result<(), ChannelError>)> {
        let mut out = Vec::new();
        for account in self.linked_accounts() {
            let label = format!("{}:{}", account.channel, account.account);
            let Some(adapter) = self.adapter(&account.channel) else {
                out.push((label, Err(ChannelError::NoAdapter(account.channel))));
                continue;
            };
            let result = match &self.vault {
                Some(vault) => {
                    let creds = BrokeredCreds::new(
                        vault.clone(),
                        account.account.clone(),
                        account.secret_names.clone(),
                    );
                    adapter.connect(&creds).await
                }
                None => Err(ChannelError::CredentialUnavailable(
                    "vault not attached".to_string(),
                )),
            };
            out.push((label, result));
        }
        out
    }

    /// Route one outbound message to the right adapter/account.
    pub async fn send(
        &self,
        channel: &str,
        msg: &OutboundMessage,
    ) -> Result<Receipt, ChannelError> {
        let adapter = self
            .adapter(channel)
            .ok_or_else(|| ChannelError::NoAdapter(channel.to_string()))?;
        adapter.send(msg).await
    }

    /// Poll every connected adapter for inbound events.
    pub async fn poll_all(&self) -> Vec<(String, Result<Vec<ConversationEvent>, ChannelError>)> {
        let adapters: Vec<(String, Arc<dyn ChannelAdapter>)> = self
            .adapters
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut out = Vec::new();
        for (id, adapter) in adapters {
            out.push((id.clone(), adapter.poll_inbound().await));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Local channel — the dashboard/webchat adapter
// ---------------------------------------------------------------------------

/// In-process sink the local adapter delivers outbound messages to. The API
/// layer drains it for the webchat UI; tests use it to observe deliveries.
#[derive(Debug)]
pub struct LocalChannel {
    id: String,
    outbound: Mutex<Vec<OutboundMessage>>,
    /// Events injected via [`LocalChannel::inject_inbound`] (webchat posts,
    /// test drivers) are returned by `poll_inbound`.
    inbound: Mutex<Vec<ConversationEvent>>,
    connected: Mutex<bool>,
}

impl LocalChannel {
    /// `account` is the local principal id (e.g. "dashboard", "webchat").
    pub fn new(account: impl Into<String>) -> Arc<Self> {
        Arc::new(LocalChannel {
            id: format!("local:{}", account.into()),
            outbound: Mutex::new(Vec::new()),
            inbound: Mutex::new(Vec::new()),
            connected: Mutex::new(false),
        })
    }

    /// Inject an inbound event as if the user typed it into the local UI.
    pub fn inject_inbound(&self, event: ConversationEvent) {
        self.inbound.lock().unwrap().push(event);
    }

    /// Drain delivered outbound messages (oldest first).
    pub fn drain_outbound(&self) -> Vec<OutboundMessage> {
        std::mem::take(&mut *self.outbound.lock().unwrap())
    }

    pub fn outbound_len(&self) -> usize {
        self.outbound.lock().unwrap().len()
    }
}

#[async_trait]
impl ChannelAdapter for LocalChannel {
    fn id(&self) -> &str {
        &self.id
    }

    async fn connect(&self, _creds: &BrokeredCreds) -> Result<(), ChannelError> {
        *self.connected.lock().unwrap() = true;
        Ok(())
    }

    async fn send(&self, msg: &OutboundMessage) -> Result<Receipt, ChannelError> {
        if !*self.connected.lock().unwrap() {
            return Err(ChannelError::NotConnected(self.id.clone()));
        }
        self.outbound.lock().unwrap().push(msg.clone());
        Ok(Receipt {
            channel: self.id.clone(),
            account: msg.account.clone(),
            message_id: Some(format!("local-{}", Utc::now().timestamp_micros())),
            accepted_at: Utc::now(),
        })
    }

    async fn poll_inbound(&self) -> Result<Vec<ConversationEvent>, ChannelError> {
        Ok(std::mem::take(&mut *self.inbound.lock().unwrap()))
    }

    fn capabilities(&self) -> ChannelCaps {
        // The local channel supports everything — it is the reference target
        // other adapters are measured against.
        ChannelCaps {
            text: true,
            media: true,
            buttons: true,
            threads: true,
            receipts: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_vault::VaultBroker;

    fn scratch_home() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn unlocked_vault(home: &Path) -> Arc<VaultBroker> {
        let vault = Arc::new(VaultBroker::open(
            home.join(t3rnel_extensions::vault::VAULT_FILE_NAME),
            false,
        ));
        vault
            .unlock_ordered(Some(Zeroizing::new([11u8; 32])))
            .unwrap();
        vault
    }

    fn event(text: &str) -> ConversationEvent {
        ConversationEvent {
            channel: "local:test".into(),
            account: "acct".into(),
            sender: "+15550001".into(),
            thread_key: "+15550001".into(),
            message_id: None,
            text: text.into(),
            attachments: vec![],
            timestamp: Utc::now(),
            provenance: crate::conversations::Provenance {
                source: "test".into(),
                untrusted: true,
                data_classes: ["personal".to_string()].into_iter().collect(),
            },
        }
    }

    #[tokio::test]
    async fn registry_links_accounts_and_routes_send() {
        let home = scratch_home();
        let mut registry = ChannelRegistry::new(home.path());
        registry.load().unwrap();
        let adapter = LocalChannel::new("dashboard");
        registry.register_adapter(adapter.clone());
        registry
            .link_account(LinkedAccount {
                channel: "local:dashboard".into(),
                account: "dashboard".into(),
                label: Some("web".into()),
                secret_names: vec![],
                linked_at: Utc::now(),
            })
            .unwrap();

        // Persisted + reloadable.
        let registry2 = ChannelRegistry::new(home.path());
        registry2.load().unwrap();
        assert_eq!(registry2.linked_accounts().len(), 1);

        // connect_all with vault: local adapter ignores creds but must get them.
        let vault = unlocked_vault(home.path());
        registry.set_vault(vault);
        let results = registry.connect_all().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].1.is_ok(), "{:?}", results[0].1);

        let receipt = registry
            .send(
                "local:dashboard",
                &OutboundMessage {
                    account: "dashboard".into(),
                    thread_key: "t1".into(),
                    text: "hello".into(),
                    attachments: vec![],
                    metadata: BTreeMap::new(),
                },
            )
            .await
            .unwrap();
        assert_eq!(receipt.channel, "local:dashboard");
        assert_eq!(adapter.outbound_len(), 1);

        // Inbound round-trip through poll_all.
        adapter.inject_inbound(event("hi"));
        let polls = registry.poll_all().await;
        assert_eq!(polls.len(), 1);
        let events = polls[0].1.as_ref().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].text, "hi");
    }

    #[tokio::test]
    async fn brokered_creds_enforces_declared_names() {
        let home = scratch_home();
        let vault = unlocked_vault(home.path());
        vault
            .provision(
                "channel:test:session",
                Zeroizing::new("tok-abc".to_string()),
            )
            .unwrap();
        let creds = BrokeredCreds::new(vault, "acct", vec!["channel:test:session".to_string()]);
        let v = creds.resolve("channel:test:session").unwrap();
        assert_eq!(v.as_str(), "tok-abc");
        // Undeclared name refused even though it exists check is by allowlist.
        assert!(matches!(
            creds.resolve("other:secret"),
            Err(ChannelError::CredentialUnavailable(_))
        ));
        assert_eq!(creds.secret_names(), vec!["channel:test:session"]);
    }

    #[tokio::test]
    async fn send_to_unregistered_channel_errors() {
        let home = scratch_home();
        let registry = ChannelRegistry::new(home.path());
        let err = registry
            .send(
                "telegram",
                &OutboundMessage {
                    account: "a".into(),
                    thread_key: "t".into(),
                    text: "x".into(),
                    attachments: vec![],
                    metadata: BTreeMap::new(),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ChannelError::NoAdapter(_)));
    }
}
