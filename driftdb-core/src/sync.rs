//! DriftDB — Real-Time Sync Engine
//!
//! Subscription-based change propagation:
//! - Clients subscribe to specific data patterns (labels, node IDs, event types)
//! - All mutations automatically checked against active subscriptions
//! - Matching changes instantly pushed to subscribers
//! - Zero polling — pure push-based architecture

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::event::DriftEvent;

// ═══════════════════════════════════════════════════════════════════
// Subscription Types
// ═══════════════════════════════════════════════════════════════════

/// Unique subscription ID
pub type SubId = u64;

/// What a client wants to subscribe to
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubFilter {
    /// All events
    All,
    /// Events for a specific node
    Node(String),
    /// Events for nodes with a specific label
    Label(String),
    /// Events of a specific type (NODE_CREATED, EDGE_CREATED, etc.)
    EventType(String),
    /// Multiple filters (match ANY)
    Any(Vec<SubFilter>),
}

/// Maximum nesting depth for SubFilter::Any (prevents stack overflow)
const MAX_FILTER_DEPTH: usize = 8;

impl SubFilter {
    /// Check if a DriftEvent matches this filter (depth-limited)
    pub fn matches(&self, event: &DriftEvent) -> bool {
        self.matches_depth(event, 0)
    }

    fn matches_depth(&self, event: &DriftEvent, depth: usize) -> bool {
        if depth > MAX_FILTER_DEPTH {
            return false; // Too deep — reject to prevent stack overflow
        }

        match self {
            SubFilter::All => true,

            SubFilter::Node(id) => match event {
                DriftEvent::NodeCreated { node_id, .. } => node_id.0 == *id,
                DriftEvent::NodeUpdated { node_id, .. } => node_id.0 == *id,
                DriftEvent::NodeDeleted { node_id, .. } => node_id.0 == *id,
                DriftEvent::EdgeCreated { source, target, .. } => {
                    source.0 == *id || target.0 == *id
                }
                DriftEvent::EdgeDeleted { .. } => false,
                DriftEvent::VectorAttached { node_id, .. } => node_id.0 == *id,
            },

            SubFilter::Label(label) => match event {
                DriftEvent::NodeCreated { labels, .. } => {
                    labels.iter().any(|l| l.to_lowercase() == label.to_lowercase())
                }
                _ => false,
            },

            SubFilter::EventType(etype) => event.event_type() == etype.as_str(),

            SubFilter::Any(filters) => {
                filters.iter().any(|f| f.matches_depth(event, depth + 1))
            }
        }
    }

    /// Validate a filter — rejects excessively nested or oversized filters
    pub fn validate(&self) -> Result<(), String> {
        self.validate_depth(0)
    }

    fn validate_depth(&self, depth: usize) -> Result<(), String> {
        if depth > MAX_FILTER_DEPTH {
            return Err(format!(
                "Filter nesting too deep ({} > {} max). Possible attack.",
                depth, MAX_FILTER_DEPTH
            ));
        }
        match self {
            SubFilter::Any(filters) => {
                if filters.len() > 100 {
                    return Err(format!(
                        "Too many filters in Any ({} > 100 max)",
                        filters.len()
                    ));
                }
                for f in filters {
                    f.validate_depth(depth + 1)?;
                }
                Ok(())
            }
            SubFilter::Node(id) | SubFilter::Label(id) | SubFilter::EventType(id) => {
                if id.len() > 1024 {
                    return Err("Filter string too long (max 1024 chars)".into());
                }
                Ok(())
            }
            SubFilter::All => Ok(()),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Change Event (what gets sent to clients)
// ═══════════════════════════════════════════════════════════════════

/// A serializable change notification sent to subscribers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeEvent {
    /// Subscription ID that matched
    pub sub_id: SubId,
    /// Event type
    pub event_type: String,
    /// The full event data as JSON
    pub data: serde_json::Value,
    /// Monotonic sequence number (for ordering)
    pub seq: u64,
}

// ═══════════════════════════════════════════════════════════════════
// Sync Engine
// ═══════════════════════════════════════════════════════════════════

/// Callback for delivering change events to subscribers
pub type ChangeCallback = Box<dyn Fn(ChangeEvent) + Send + Sync>;

/// A single subscription
struct Subscription {
    id: SubId,
    filter: SubFilter,
    callback: ChangeCallback,
}

/// The sync engine manages subscriptions and broadcasts changes
pub struct SyncEngine {
    subscriptions: Arc<Mutex<HashMap<SubId, Subscription>>>,
    next_id: AtomicU64,
    seq: AtomicU64,
}

impl SyncEngine {
    pub fn new() -> Self {
        SyncEngine {
            subscriptions: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(1),
            seq: AtomicU64::new(1),
        }
    }

    /// Subscribe to changes matching a filter. Returns the subscription ID.
    pub fn subscribe(&self, filter: SubFilter, callback: ChangeCallback) -> SubId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let sub = Subscription {
            id,
            filter,
            callback,
        };

        // Recover from poisoned Mutex (another thread panicked while holding lock)
        let mut subs = self.subscriptions.lock().unwrap_or_else(|e| e.into_inner());
        subs.insert(id, sub);
        id
    }

    /// Unsubscribe by ID
    pub fn unsubscribe(&self, id: SubId) -> bool {
        let mut subs = self.subscriptions.lock().unwrap_or_else(|e| e.into_inner());
        subs.remove(&id).is_some()
    }

    /// Broadcast a DriftEvent to all matching subscribers.
    ///
    /// SECURITY: We clone the subscription list under lock and release it
    /// BEFORE executing callbacks. This prevents a malicious/slow subscriber
    /// from blocking all mutations (lock contention DoS).
    pub fn broadcast(&self, event: &DriftEvent) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);

        // Serialize the event once for all subscribers
        let data = serde_json::to_value(event).unwrap_or_default();
        let event_type = event.event_type().to_string();

        // Collect matching subscription IDs under lock, then release
        let matching: Vec<SubId> = {
            let subs = self.subscriptions.lock().unwrap_or_else(|e| e.into_inner());
            subs.values()
                .filter(|s| s.filter.matches(event))
                .map(|s| s.id)
                .collect()
        };
        // Lock is now RELEASED — mutations are no longer blocked

        // Re-acquire and execute callbacks
        let subs = self.subscriptions.lock().unwrap_or_else(|e| e.into_inner());
        for sub_id in &matching {
            if let Some(sub) = subs.get(sub_id) {
                let change = ChangeEvent {
                    sub_id: sub.id,
                    event_type: event_type.clone(),
                    data: data.clone(),
                    seq,
                };
                (sub.callback)(change);
            }
        }
    }

    /// Get the number of active subscriptions
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Get all active subscription IDs and their filters
    pub fn list_subscriptions(&self) -> Vec<(SubId, String)> {
        self.subscriptions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|s| (s.id, format!("{:?}", s.filter)))
            .collect()
    }
}

impl Default for SyncEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Client Message Protocol
// ═══════════════════════════════════════════════════════════════════

/// Messages clients can send over WebSocket
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Subscribe to changes
    #[serde(rename = "subscribe")]
    Subscribe { filter: SubFilter },
    /// Unsubscribe
    #[serde(rename = "unsubscribe")]
    Unsubscribe { sub_id: u64 },
    /// Execute a query
    #[serde(rename = "query")]
    Query { sql: String },
    /// Ping
    #[serde(rename = "ping")]
    Ping,
}

/// Messages server sends to clients
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Subscription confirmed
    #[serde(rename = "subscribed")]
    Subscribed { sub_id: u64 },
    /// Unsubscription confirmed
    #[serde(rename = "unsubscribed")]
    Unsubscribed { sub_id: u64 },
    /// Change event
    #[serde(rename = "change")]
    Change {
        sub_id: u64,
        event_type: String,
        data: serde_json::Value,
        seq: u64,
    },
    /// Query result
    #[serde(rename = "result")]
    Result { data: serde_json::Value },
    /// Error
    #[serde(rename = "error")]
    Error { message: String },
    /// Pong
    #[serde(rename = "pong")]
    Pong { connections: usize },
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NodeId;
    use chrono::Utc;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn test_subscribe_all() {
        let engine = SyncEngine::new();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();

        engine.subscribe(SubFilter::All, Box::new(move |_| {
            c.fetch_add(1, Ordering::Relaxed);
        }));

        let event = DriftEvent::NodeCreated {
            node_id: NodeId("n1".into()),
            labels: vec!["User".into()],
            properties: HashMap::new(),
            timestamp: Utc::now(),
        };

        engine.broadcast(&event);
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_subscribe_label() {
        let engine = SyncEngine::new();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();

        engine.subscribe(SubFilter::Label("User".into()), Box::new(move |_| {
            c.fetch_add(1, Ordering::Relaxed);
        }));

        // Should match
        engine.broadcast(&DriftEvent::NodeCreated {
            node_id: NodeId("n1".into()),
            labels: vec!["User".into()],
            properties: HashMap::new(),
            timestamp: Utc::now(),
        });

        // Should NOT match
        engine.broadcast(&DriftEvent::NodeCreated {
            node_id: NodeId("n2".into()),
            labels: vec!["Product".into()],
            properties: HashMap::new(),
            timestamp: Utc::now(),
        });

        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_subscribe_node() {
        let engine = SyncEngine::new();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();

        engine.subscribe(SubFilter::Node("n1".into()), Box::new(move |_| {
            c.fetch_add(1, Ordering::Relaxed);
        }));

        engine.broadcast(&DriftEvent::NodeUpdated {
            node_id: NodeId("n1".into()),
            property: "name".into(),
            old_value: None,
            new_value: crate::types::Value::String("test".into()),
            timestamp: Utc::now(),
        });

        engine.broadcast(&DriftEvent::NodeUpdated {
            node_id: NodeId("n2".into()),
            property: "name".into(),
            old_value: None,
            new_value: crate::types::Value::String("other".into()),
            timestamp: Utc::now(),
        });

        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_subscribe_event_type() {
        let engine = SyncEngine::new();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();

        engine.subscribe(SubFilter::EventType("EDGE_CREATED".into()), Box::new(move |_| {
            c.fetch_add(1, Ordering::Relaxed);
        }));

        // Should NOT match
        engine.broadcast(&DriftEvent::NodeCreated {
            node_id: NodeId("n1".into()),
            labels: vec![],
            properties: HashMap::new(),
            timestamp: Utc::now(),
        });

        // Should match
        engine.broadcast(&DriftEvent::EdgeCreated {
            edge_id: crate::types::EdgeId("e1".into()),
            source: NodeId("n1".into()),
            target: NodeId("n2".into()),
            edge_type: "KNOWS".into(),
            properties: HashMap::new(),
            timestamp: Utc::now(),
        });

        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_unsubscribe() {
        let engine = SyncEngine::new();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();

        let id = engine.subscribe(SubFilter::All, Box::new(move |_| {
            c.fetch_add(1, Ordering::Relaxed);
        }));

        engine.broadcast(&DriftEvent::NodeCreated {
            node_id: NodeId("n1".into()),
            labels: vec![],
            properties: HashMap::new(),
            timestamp: Utc::now(),
        });
        assert_eq!(count.load(Ordering::Relaxed), 1);

        assert!(engine.unsubscribe(id));

        engine.broadcast(&DriftEvent::NodeCreated {
            node_id: NodeId("n2".into()),
            labels: vec![],
            properties: HashMap::new(),
            timestamp: Utc::now(),
        });
        // Should still be 1 — we unsubscribed
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_any_filter() {
        let engine = SyncEngine::new();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();

        engine.subscribe(
            SubFilter::Any(vec![
                SubFilter::Label("User".into()),
                SubFilter::EventType("EDGE_CREATED".into()),
            ]),
            Box::new(move |_| {
                c.fetch_add(1, Ordering::Relaxed);
            }),
        );

        // Match via label
        engine.broadcast(&DriftEvent::NodeCreated {
            node_id: NodeId("n1".into()),
            labels: vec!["User".into()],
            properties: HashMap::new(),
            timestamp: Utc::now(),
        });

        // Match via event type
        engine.broadcast(&DriftEvent::EdgeCreated {
            edge_id: crate::types::EdgeId("e1".into()),
            source: NodeId("n1".into()),
            target: NodeId("n2".into()),
            edge_type: "KNOWS".into(),
            properties: HashMap::new(),
            timestamp: Utc::now(),
        });

        // No match
        engine.broadcast(&DriftEvent::NodeDeleted {
            node_id: NodeId("n3".into()),
            timestamp: Utc::now(),
        });

        assert_eq!(count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_change_event_serialization() {
        let change = ChangeEvent {
            sub_id: 1,
            event_type: "NODE_CREATED".into(),
            data: serde_json::json!({"node_id": "n1"}),
            seq: 42,
        };

        let json = serde_json::to_string(&change).unwrap();
        let parsed: ChangeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.sub_id, 1);
        assert_eq!(parsed.seq, 42);
    }

    #[test]
    fn test_client_message_protocol() {
        let msg = ClientMessage::Subscribe {
            filter: SubFilter::Label("User".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("subscribe"));

        let msg2 = ClientMessage::Ping;
        let json2 = serde_json::to_string(&msg2).unwrap();
        assert!(json2.contains("ping"));
    }

    #[test]
    fn test_server_message_protocol() {
        let msg = ServerMessage::Subscribed { sub_id: 42 };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("subscribed"));
        assert!(json.contains("42"));

        let msg2 = ServerMessage::Change {
            sub_id: 1,
            event_type: "NODE_CREATED".into(),
            data: serde_json::json!({}),
            seq: 100,
        };
        let json2 = serde_json::to_string(&msg2).unwrap();
        assert!(json2.contains("change"));
    }

    #[test]
    fn test_multiple_subscribers() {
        let engine = SyncEngine::new();
        let count1 = Arc::new(AtomicUsize::new(0));
        let count2 = Arc::new(AtomicUsize::new(0));
        let c1 = count1.clone();
        let c2 = count2.clone();

        engine.subscribe(SubFilter::All, Box::new(move |_| {
            c1.fetch_add(1, Ordering::Relaxed);
        }));

        engine.subscribe(SubFilter::Label("User".into()), Box::new(move |_| {
            c2.fetch_add(1, Ordering::Relaxed);
        }));

        engine.broadcast(&DriftEvent::NodeCreated {
            node_id: NodeId("n1".into()),
            labels: vec!["User".into()],
            properties: HashMap::new(),
            timestamp: Utc::now(),
        });

        // Both should fire
        assert_eq!(count1.load(Ordering::Relaxed), 1);
        assert_eq!(count2.load(Ordering::Relaxed), 1);

        assert_eq!(engine.subscription_count(), 2);
    }
}
