//! Tests for the WhatsApp channel adapters — mock gateway over loopback
//! HTTP (axum), scratch vault homes, no live daemon or `~/.t3rnel`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Query, State as AxumState},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::*;
use crate::channels::BrokeredCreds;
use crate::plugin_vault::VaultBroker;

// ---------------------------------------------------------------------------
// Mock gateway
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct MockGateway {
    /// Bodies received at POST /message/send.
    sent: Mutex<Vec<Value>>,
    /// Bodies received at POST /file.
    files: Mutex<Vec<Value>>,
    /// Inbound events the fake gateway will hand out via /inbound/events.
    inbound: Mutex<Vec<GatewayInboundEvent>>,
    latest_seq: Mutex<u64>,
    linked: Mutex<bool>,
    connected: Mutex<bool>,
}

async fn mock_health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn mock_linked(AxumState(gw): AxumState<Arc<MockGateway>>) -> Json<Value> {
    Json(json!({
        "linked": *gw.linked.lock().unwrap(),
        "connected": *gw.connected.lock().unwrap(),
        "number": "263700000001",
        "message": "mock",
    }))
}

async fn mock_events(
    AxumState(gw): AxumState<Arc<MockGateway>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let since: u64 = q.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
    let limit: usize = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(200);
    let events: Vec<GatewayInboundEvent> = gw
        .inbound
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.seq > since)
        .take(limit)
        .cloned()
        .collect();
    let latest = *gw.latest_seq.lock().unwrap();
    let linked = *gw.linked.lock().unwrap();
    let connected = *gw.connected.lock().unwrap();
    Json(json!({
        "events": events.iter().map(|e| serde_json::to_value(e).unwrap()).collect::<Vec<_>>(),
        "latest": latest,
        "linked": linked,
        "connected": connected,
        "number": "263700000001",
    }))
}

async fn mock_send(
    AxumState(gw): AxumState<Arc<MockGateway>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !*gw.connected.lock().unwrap() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "WhatsApp not connected" })),
        );
    }
    gw.sent.lock().unwrap().push(body);
    (
        StatusCode::OK,
        Json(json!({ "success": true, "message": "Sent" })),
    )
}

async fn mock_file(
    AxumState(gw): AxumState<Arc<MockGateway>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    gw.files.lock().unwrap().push(body);
    Json(json!({ "ok": true }))
}

async fn spawn_mock_gateway(gw: Arc<MockGateway>) -> String {
    let app = Router::new()
        .route("/health", get(mock_health))
        .route("/linked", get(mock_linked))
        .route("/inbound/events", get(mock_events))
        .route("/message/send", post(mock_send))
        .route("/file", post(mock_file))
        .with_state(gw);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn gw_event(seq: u64, text: &str) -> GatewayInboundEvent {
    GatewayInboundEvent {
        seq,
        id: Some(format!("wamid.mock.{seq}")),
        chat: "263711111111@s.whatsapp.net".to_string(),
        sender: "263711111111@s.whatsapp.net".to_string(),
        phone: "+263711111111".to_string(),
        push_name: "Tester".to_string(),
        text: text.to_string(),
        is_group: false,
        ts: 1_700_000_000,
    }
}

fn unlocked_vault(home: &std::path::Path) -> Arc<VaultBroker> {
    let vault = Arc::new(VaultBroker::open(
        home.join(t3rnel_extensions::vault::VAULT_FILE_NAME),
        false,
    ));
    vault
        .unlock_ordered(Some(Zeroizing::new([7u8; 32])))
        .unwrap();
    vault
}

fn creds_for(vault: Arc<VaultBroker>, account: &str, names: Vec<String>) -> BrokeredCreds {
    BrokeredCreds::new(vault, account, names)
}

fn outbound(thread_key: &str, text: &str) -> OutboundMessage {
    OutboundMessage {
        account: "default".to_string(),
        thread_key: thread_key.to_string(),
        text: text.to_string(),
        attachments: vec![],
        metadata: BTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// Personal (gateway) adapter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gateway_connect_send_poll_roundtrip() {
    let gw = Arc::new(MockGateway {
        linked: Mutex::new(true),
        connected: Mutex::new(true),
        ..MockGateway::default()
    });
    let url = spawn_mock_gateway(gw.clone()).await;

    let home = tempfile::tempdir().unwrap();
    let vault = unlocked_vault(home.path());
    let adapter = WhatsAppAdapter::with_gateway_url(&url);
    let creds = creds_for(vault, "default", vec![]);
    adapter.connect(&creds).await.unwrap();
    assert_eq!(adapter.link_state(), WhatsAppLinkState::Connected);
    assert_eq!(adapter.linked_number().as_deref(), Some("263700000001"));

    // Inbound: one DM + one group message.
    {
        let mut feed = gw.inbound.lock().unwrap();
        feed.push(gw_event(1, "hello agent"));
        let mut grp = gw_event(2, "group ping");
        grp.is_group = true;
        grp.chat = "120363000000@g.us".to_string();
        grp.sender = "263722222222@s.whatsapp.net".to_string();
        grp.phone = "+263722222222".to_string();
        feed.push(grp);
        feed.push(gw_event(3, "[Image received]: look"));
        *gw.latest_seq.lock().unwrap() = 3;
    }

    let events = adapter.poll_inbound().await.unwrap();
    assert_eq!(events.len(), 3);

    let dm = &events[0];
    assert_eq!(dm.channel, "whatsapp");
    assert_eq!(dm.account, "default");
    assert_eq!(dm.sender, "+263711111111");
    // DM thread key = phone number (send path re-normalizes to JID).
    assert_eq!(dm.thread_key, "+263711111111");
    assert_eq!(dm.message_id.as_deref(), Some("wamid.mock.1"));
    assert!(dm.provenance.untrusted);
    assert_eq!(dm.provenance.source, "channel:whatsapp");
    assert_eq!(
        dm.timestamp,
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    );

    let grp_ev = &events[1];
    // Group thread key = group chat JID.
    assert_eq!(grp_ev.thread_key, "120363000000@g.us");
    assert_eq!(grp_ev.sender, "+263722222222");

    // Media placeholder surfaces as an attachment handle.
    assert_eq!(events[2].attachments.len(), 1);
    assert_eq!(events[2].attachments[0].kind, "image");
    assert_eq!(events[2].attachments[0].reference, "wamid.mock.3");

    // Cursor advanced — second poll returns nothing.
    assert!(adapter.poll_inbound().await.unwrap().is_empty());

    // Send routes to /message/send with the thread key as `to`.
    let receipt = adapter
        .send(&outbound("+263711111111", "hi there"))
        .await
        .unwrap();
    assert_eq!(receipt.channel, "whatsapp");
    assert_eq!(receipt.account, "default");
    assert!(receipt.message_id.is_none());
    let sent = gw.sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["to"], "+263711111111");
    assert_eq!(sent[0]["text"], "hi there");
}

#[tokio::test]
async fn gateway_needs_linking_blocks_send_with_actionable_error() {
    let gw = Arc::new(MockGateway {
        linked: Mutex::new(false),
        connected: Mutex::new(false),
        ..MockGateway::default()
    });
    let url = spawn_mock_gateway(gw).await;

    let home = tempfile::tempdir().unwrap();
    let vault = unlocked_vault(home.path());
    let adapter = WhatsAppAdapter::with_gateway_url(&url);
    adapter
        .connect(&creds_for(vault, "default", vec![]))
        .await
        .unwrap();
    assert_eq!(adapter.link_state(), WhatsAppLinkState::NeedsLinking);

    let err = adapter.send(&outbound("+2637", "hello")).await.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("not linked"), "{msg}");
    assert!(msg.contains("qr/start"), "{msg}");
}

#[tokio::test]
async fn gateway_send_maps_not_connected_error() {
    let gw = Arc::new(MockGateway {
        linked: Mutex::new(true),
        connected: Mutex::new(false), // linked but socket down
        ..MockGateway::default()
    });
    let url = spawn_mock_gateway(gw).await;

    let home = tempfile::tempdir().unwrap();
    let vault = unlocked_vault(home.path());
    let adapter = WhatsAppAdapter::with_gateway_url(&url);
    adapter
        .connect(&creds_for(vault, "default", vec![]))
        .await
        .unwrap();
    assert_eq!(adapter.link_state(), WhatsAppLinkState::Linked);

    // Send is attempted (state allows it) but the gateway refuses.
    let err = adapter.send(&outbound("+2637", "hello")).await.unwrap_err();
    assert!(err.to_string().contains("not connected"), "{err}");
}

#[tokio::test]
async fn gateway_poll_before_connect_is_empty() {
    let adapter = WhatsAppAdapter::new();
    assert!(adapter.poll_inbound().await.unwrap().is_empty());
    assert_eq!(adapter.link_state(), WhatsAppLinkState::Offline);
}

#[tokio::test]
async fn gateway_link_state_flips_after_qr_scan() {
    let gw = Arc::new(MockGateway {
        linked: Mutex::new(false),
        connected: Mutex::new(false),
        ..MockGateway::default()
    });
    let url = spawn_mock_gateway(gw.clone()).await;

    let home = tempfile::tempdir().unwrap();
    let vault = unlocked_vault(home.path());
    let adapter = WhatsAppAdapter::with_gateway_url(&url);
    adapter
        .connect(&creds_for(vault, "default", vec![]))
        .await
        .unwrap();
    assert_eq!(adapter.link_state(), WhatsAppLinkState::NeedsLinking);

    // User scans the QR — the gateway now reports linked+connected.
    *gw.linked.lock().unwrap() = true;
    *gw.connected.lock().unwrap() = true;
    let _ = adapter.poll_inbound().await.unwrap();
    assert_eq!(adapter.link_state(), WhatsAppLinkState::Connected);
}

#[tokio::test]
async fn gateway_declared_secrets_are_brokered() {
    let gw = Arc::new(MockGateway {
        linked: Mutex::new(true),
        connected: Mutex::new(true),
        ..MockGateway::default()
    });
    let url = spawn_mock_gateway(gw).await;

    let home = tempfile::tempdir().unwrap();
    let vault = unlocked_vault(home.path());
    vault
        .provision(
            "channel:whatsapp:acct1:token",
            Zeroizing::new("sekrit".to_string()),
        )
        .unwrap();
    let adapter = WhatsAppAdapter::with_gateway_url(&url);
    // Undeclared name → CredentialUnavailable, connect fails closed.
    let err = adapter
        .connect(&creds_for(
            vault.clone(),
            "acct1",
            vec!["other:name".to_string()],
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(err, ChannelError::CredentialUnavailable(_)),
        "{err}"
    );

    // Declared + provisioned → connect succeeds.
    adapter
        .connect(&creds_for(
            vault,
            "acct1",
            vec!["channel:whatsapp:acct1:token".to_string()],
        ))
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Business (Cloud API) adapter
// ---------------------------------------------------------------------------

/// Mock Cloud API: records POST /v21.0/{pnid}/messages.
async fn spawn_mock_cloud(gw: Arc<MockGateway>) -> String {
    async fn cloud_send(
        AxumState(gw): AxumState<Arc<MockGateway>>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        gw.sent.lock().unwrap().push(body);
        Json(json!({
            "messaging_product": "whatsapp",
            "contacts": [{ "input": "2637", "wa_id": "2637" }],
            "messages": [{ "id": "wamid.cloud.1" }],
        }))
    }
    let app = Router::new()
        .route("/v21.0/{pnid}/messages", post(cloud_send))
        .with_state(gw);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn business_creds(vault: Arc<VaultBroker>, account: &str) -> BrokeredCreds {
    BrokeredCreds::new(
        vault,
        account,
        vec![
            "channel:whatsapp-business:biz1:access-token".to_string(),
            "channel:whatsapp-business:biz1:verify-token".to_string(),
        ],
    )
}

#[tokio::test]
async fn business_connect_send_and_webhook_ingest() {
    let cloud = Arc::new(MockGateway::default());
    let api_base = spawn_mock_cloud(cloud.clone()).await;

    let home = tempfile::tempdir().unwrap();
    let vault = unlocked_vault(home.path());
    vault
        .provision(
            "channel:whatsapp-business:biz1:access-token",
            Zeroizing::new("EAAG-token".to_string()),
        )
        .unwrap();
    vault
        .provision(
            "channel:whatsapp-business:biz1:verify-token",
            Zeroizing::new("verify-123".to_string()),
        )
        .unwrap();

    let state = BusinessWebhookState::new();
    let adapter = WhatsAppBusinessAdapter::new(state.clone())
        .with_api_base(format!("{api_base}/v21.0"))
        .with_phone_number_id("109876543210");
    adapter
        .connect(&business_creds(vault, "biz1"))
        .await
        .unwrap();

    // Send → Cloud API messages endpoint, digits-only recipient.
    let mut msg = outbound("263711111111", "hello business");
    msg.account = "biz1".to_string();
    let receipt = adapter.send(&msg).await.unwrap();
    assert_eq!(receipt.channel, "whatsapp-business");
    assert_eq!(receipt.message_id.as_deref(), Some("wamid.cloud.1"));
    {
        let sent = cloud.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0]["to"], "263711111111");
        assert_eq!(sent[0]["type"], "text");
    }

    // Webhook handshake token check.
    assert!(state.verify_token_matches("verify-123"));
    assert!(!state.verify_token_matches("wrong"));

    // Meta webhook payload → normalized inbound events.
    let payload = json!({
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "WABA-ID",
            "changes": [{
                "field": "messages",
                "value": {
                    "messaging_product": "whatsapp",
                    "metadata": { "phone_number_id": "109876543210" },
                    "contacts": [{ "profile": { "name": "Buyer" }, "wa_id": "263711111111" }],
                    "messages": [
                        {
                            "from": "263711111111",
                            "id": "wamid.in.1",
                            "timestamp": "1700000000",
                            "type": "text",
                            "text": { "body": "is this in stock?" }
                        },
                        {
                            "from": "263722222222",
                            "id": "wamid.in.2",
                            "timestamp": "1700000001",
                            "type": "image",
                            "image": { "id": "media-abc", "mime_type": "image/jpeg", "caption": "see this" }
                        }
                    ]
                }
            }]
        }]
    });
    assert_eq!(state.ingest(&payload), 2);

    let events = adapter.poll_inbound().await.unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].channel, "whatsapp-business");
    assert_eq!(events[0].account, "biz1");
    assert_eq!(events[0].sender, "263711111111");
    assert_eq!(events[0].thread_key, "263711111111");
    assert_eq!(events[0].text, "is this in stock?");
    assert_eq!(events[0].message_id.as_deref(), Some("wamid.in.1"));
    assert!(events[0].provenance.untrusted);
    assert_eq!(events[0].provenance.source, "channel:whatsapp-business");

    // Media message: placeholder text + opaque media-id attachment handle.
    assert_eq!(events[1].attachments.len(), 1);
    assert_eq!(events[1].attachments[0].kind, "image");
    assert_eq!(events[1].attachments[0].reference, "media-abc");
    assert!(events[1].text.contains("[Image received]"));

    // Drained — second poll empty.
    assert!(adapter.poll_inbound().await.unwrap().is_empty());
}

#[tokio::test]
async fn business_connect_requires_declared_token() {
    let state = BusinessWebhookState::new();
    let adapter = WhatsAppBusinessAdapter::new(state).with_phone_number_id("123");
    let home = tempfile::tempdir().unwrap();
    let vault = unlocked_vault(home.path());
    // No secrets declared → CredentialUnavailable naming the expected secret.
    let err = adapter
        .connect(&creds_for(vault, "biz1", vec![]))
        .await
        .unwrap_err();
    assert!(
        matches!(err, ChannelError::CredentialUnavailable(_)),
        "{err}"
    );
    assert!(err.to_string().contains("access-token"), "{err}");
}

#[tokio::test]
async fn business_send_before_connect_fails() {
    let state = BusinessWebhookState::new();
    let adapter = WhatsAppBusinessAdapter::new(state);
    let err = adapter.send(&outbound("2637", "hi")).await.unwrap_err();
    assert!(matches!(err, ChannelError::NotConnected(_)), "{err}");
}

#[test]
fn business_text_chunking_respects_cloud_limit() {
    // 5000 ASCII chars → two chunks, second non-empty.
    let text = "x".repeat(5000);
    let mut chunks = Vec::new();
    let mut rest = text.as_str();
    while !rest.is_empty() {
        if rest.chars().count() <= CLOUD_MAX_TEXT {
            chunks.push(rest.to_string());
            break;
        }
        let split_at = rest
            .char_indices()
            .nth(CLOUD_MAX_TEXT)
            .map(|(i, _)| i)
            .unwrap_or(rest.len());
        chunks.push(rest[..split_at].to_string());
        rest = &rest[split_at..];
    }
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].chars().count(), 4096);
    assert_eq!(chunks[1].chars().count(), 904);
}
