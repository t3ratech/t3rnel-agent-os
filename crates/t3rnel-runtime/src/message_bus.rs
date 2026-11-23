//! O(1) deque-based message bus with backpressure for A2A communication.
//!
//! Patterned on ruflo's MessageBus: bounded queues with drop-head backpressure,
//! priority routing, and per-agent flow control.

use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tracing::{debug, warn};

/// Maximum messages queued per agent before backpressure kicks in.
const DEFAULT_PER_AGENT_LIMIT: usize = 256;

/// Maximum messages in the broadcast queue.
const DEFAULT_BROADCAST_LIMIT: usize = 1024;

/// Priority levels for A2A messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {
    /// System-critical: halt, kill-switch, rail breach.
    Critical = 3,
    /// User-facing: chat responses, approvals.
    High = 2,
    /// Background tasks: telemetry, compaction.
    Normal = 1,
    /// Best-effort: metrics, logging.
    Low = 0,
}

/// An envelope carrying an A2A message through the bus.
#[derive(Debug, Clone)]
pub struct MessageEnvelope {
    /// Target agent ID (None for broadcast).
    pub target: Option<String>,
    /// Source agent or system component.
    pub source: String,
    /// Message payload.
    pub payload: serde_json::Value,
    /// Priority for queue ordering.
    pub priority: MessagePriority,
    /// Timestamp (RFC3339).
    pub timestamp: String,
    /// Unique envelope ID.
    pub id: String,
}

impl MessageEnvelope {
    /// Create a new envelope.
    pub fn new(
        target: Option<String>,
        source: impl Into<String>,
        payload: serde_json::Value,
        priority: MessagePriority,
    ) -> Self {
        Self {
            target,
            source: source.into(),
            payload,
            priority,
            timestamp: chrono::Utc::now().to_rfc3339(),
            id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

/// O(1) deque-based bounded queue with priority ordering and drop-head backpressure.
pub struct BoundedDeque {
    deque: VecDeque<MessageEnvelope>,
    limit: usize,
    notify: Arc<Notify>,
}

impl BoundedDeque {
    /// Create a new bounded deque with the given capacity.
    pub fn new(limit: usize) -> Self {
        Self {
            deque: VecDeque::with_capacity(limit.min(1024)),
            limit,
            notify: Arc::new(Notify::new()),
        }
    }

    /// Push a message with automatic backpressure: if over limit, drop oldest low-priority.
    pub fn push(&mut self, envelope: MessageEnvelope) {
        if self.deque.len() >= self.limit {
            // Backpressure: drop oldest Normal or Low priority message
            if let Some(drop_idx) = self
                .deque
                .iter()
                .position(|e| e.priority <= MessagePriority::Normal)
            {
                let dropped = self.deque.remove(drop_idx).unwrap();
                warn!(
                    envelope_id = %dropped.id,
                    source = %dropped.source,
                    "Backpressure: dropped oldest normal-priority message"
                );
            } else {
                // All messages are High/Critical — drop oldest regardless
                let dropped = self.deque.pop_front().unwrap();
                warn!(
                    envelope_id = %dropped.id,
                    source = %dropped.source,
                    priority = ?dropped.priority,
                    "Backpressure: dropped oldest message (all high priority)"
                );
            }
        }

        // Insert by priority: find first position where priority is < new priority
        let pos = self
            .deque
            .iter()
            .position(|e| e.priority < envelope.priority);
        match pos {
            Some(idx) => self.deque.insert(idx, envelope),
            None => self.deque.push_back(envelope),
        }

        self.notify.notify_one();
    }

    /// Pop the highest-priority message.
    pub fn pop(&mut self) -> Option<MessageEnvelope> {
        self.deque.pop_front()
    }

    /// Number of messages currently queued.
    pub fn len(&self) -> usize {
        self.deque.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.deque.is_empty()
    }

    /// Async wait until a message is available.
    pub async fn wait(&self) {
        if self.is_empty() {
            self.notify.notified().await;
        }
    }
}

/// Message bus with per-agent bounded deques and a broadcast channel.
pub struct MessageBus {
    /// Per-agent queues keyed by agent ID.
    agents: Arc<Mutex<std::collections::HashMap<String, BoundedDeque>>>,
    /// Broadcast queue for all subscribers.
    broadcast: Arc<Mutex<BoundedDeque>>,
    /// Maximum per-agent queue depth.
    per_agent_limit: usize,
    /// Shutdown signal.
    shutdown: Arc<Notify>,
}

impl MessageBus {
    /// Create a new message bus with default limits.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_PER_AGENT_LIMIT, DEFAULT_BROADCAST_LIMIT)
    }

    /// Create a new message bus with custom limits.
    pub fn with_limits(per_agent_limit: usize, broadcast_limit: usize) -> Self {
        Self {
            agents: Arc::new(Mutex::new(std::collections::HashMap::new())),
            broadcast: Arc::new(Mutex::new(BoundedDeque::new(broadcast_limit))),
            per_agent_limit,
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Send a message to a specific agent.
    pub async fn send_to(&self, agent_id: &str, envelope: MessageEnvelope) {
        let mut agents = self.agents.lock().await;
        let queue = agents
            .entry(agent_id.to_string())
            .or_insert_with(|| BoundedDeque::new(self.per_agent_limit));
        queue.push(envelope);
        debug!(agent = %agent_id, queue_len = queue.len(), "Message queued");
    }

    /// Broadcast a message to all subscribers.
    pub async fn broadcast(&self, envelope: MessageEnvelope) {
        let mut broadcast = self.broadcast.lock().await;
        broadcast.push(envelope);
    }

    /// Receive the next message for a specific agent (blocks until available).
    pub async fn recv_for(&self, agent_id: &str) -> Option<MessageEnvelope> {
        loop {
            let mut agents = self.agents.lock().await;
            if let Some(queue) = agents.get_mut(agent_id) {
                if let Some(envelope) = queue.pop() {
                    return Some(envelope);
                }
                let notify = queue.notify.clone();
                drop(agents);
                notify.notified().await;
            } else {
                // No queue yet — wait on broadcast
                drop(agents);
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
                    _ = self.shutdown.notified() => return None,
                }
            }
        }
    }

    /// Receive the next broadcast message.
    pub async fn recv_broadcast(&self) -> Option<MessageEnvelope> {
        loop {
            let mut broadcast = self.broadcast.lock().await;
            if let Some(envelope) = broadcast.pop() {
                return Some(envelope);
            }
            let notify = broadcast.notify.clone();
            drop(broadcast);
            tokio::select! {
                _ = notify.notified() => {}
                _ = self.shutdown.notified() => return None,
            }
        }
    }

    /// Drain all messages for an agent (used on shutdown or reconnection).
    pub async fn drain_agent(&self, agent_id: &str) -> Vec<MessageEnvelope> {
        let mut agents = self.agents.lock().await;
        if let Some(queue) = agents.get_mut(agent_id) {
            let drained: Vec<MessageEnvelope> = queue.deque.drain(..).collect();
            drained
        } else {
            Vec::new()
        }
    }

    /// Signal shutdown to all waiting receivers.
    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }

    /// Get queue depths for telemetry.
    pub async fn queue_depths(&self) -> std::collections::HashMap<String, usize> {
        let agents = self.agents.lock().await;
        agents.iter().map(|(k, v)| (k.clone(), v.len())).collect()
    }
}

impl Default for MessageBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounded_deque_priority_ordering() {
        let mut deque = BoundedDeque::new(10);
        let low = MessageEnvelope::new(
            Some("agent".to_string()),
            "source",
            serde_json::json!({}),
            MessagePriority::Low,
        );
        let high = MessageEnvelope::new(
            Some("agent".to_string()),
            "source",
            serde_json::json!({}),
            MessagePriority::High,
        );
        let critical = MessageEnvelope::new(
            Some("agent".to_string()),
            "source",
            serde_json::json!({}),
            MessagePriority::Critical,
        );

        deque.push(low.clone());
        deque.push(high.clone());
        deque.push(critical.clone());

        assert_eq!(deque.pop().unwrap().priority, MessagePriority::Critical);
        assert_eq!(deque.pop().unwrap().priority, MessagePriority::High);
        assert_eq!(deque.pop().unwrap().priority, MessagePriority::Low);
    }

    #[test]
    fn test_bounded_deque_backpressure_drops_oldest() {
        let mut deque = BoundedDeque::new(3);
        let m1 = MessageEnvelope::new(
            None,
            "s1",
            serde_json::json!({"i":1}),
            MessagePriority::Normal,
        );
        let m2 = MessageEnvelope::new(
            None,
            "s2",
            serde_json::json!({"i":2}),
            MessagePriority::Normal,
        );
        let m3 = MessageEnvelope::new(
            None,
            "s3",
            serde_json::json!({"i":3}),
            MessagePriority::Normal,
        );
        let m4 = MessageEnvelope::new(
            None,
            "s4",
            serde_json::json!({"i":4}),
            MessagePriority::Normal,
        );

        deque.push(m1.clone());
        deque.push(m2.clone());
        deque.push(m3.clone());
        deque.push(m4.clone()); // should drop m1

        assert_eq!(deque.len(), 3);
        assert_eq!(deque.pop().unwrap().payload, serde_json::json!({"i":2}));
        assert_eq!(deque.pop().unwrap().payload, serde_json::json!({"i":3}));
        assert_eq!(deque.pop().unwrap().payload, serde_json::json!({"i":4}));
    }

    #[tokio::test]
    async fn test_message_bus_send_and_recv() {
        let bus = MessageBus::new();
        let envelope = MessageEnvelope::new(
            Some("agent-1".to_string()),
            "orchestrator",
            serde_json::json!({"task": "deploy"}),
            MessagePriority::High,
        );

        bus.send_to("agent-1", envelope.clone()).await;
        let received = bus.recv_for("agent-1").await.unwrap();

        assert_eq!(received.source, "orchestrator");
        assert_eq!(received.payload, serde_json::json!({"task": "deploy"}));
    }

    #[tokio::test]
    async fn test_message_bus_broadcast() {
        let bus = MessageBus::new();
        let envelope = MessageEnvelope::new(
            None,
            "system",
            serde_json::json!({"event": "halt"}),
            MessagePriority::Critical,
        );

        bus.broadcast(envelope.clone()).await;
        let received = bus.recv_broadcast().await.unwrap();

        assert_eq!(received.priority, MessagePriority::Critical);
    }
}
