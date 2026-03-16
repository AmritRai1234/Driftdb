//! DriftDB Core — Event system
//!
//! Every mutation in DriftDB emits a typed event.
//! Events are stored in a log and can be subscribed to.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::types::{EdgeId, NodeId, Value};

/// A typed event representing a mutation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DriftEvent {
    NodeCreated {
        node_id: NodeId,
        labels: Vec<String>,
        properties: HashMap<String, Value>,
        timestamp: DateTime<Utc>,
    },
    NodeUpdated {
        node_id: NodeId,
        property: String,
        old_value: Option<Value>,
        new_value: Value,
        timestamp: DateTime<Utc>,
    },
    NodeDeleted {
        node_id: NodeId,
        timestamp: DateTime<Utc>,
    },
    EdgeCreated {
        edge_id: EdgeId,
        source: NodeId,
        target: NodeId,
        edge_type: String,
        properties: HashMap<String, Value>,
        timestamp: DateTime<Utc>,
    },
    EdgeDeleted {
        edge_id: EdgeId,
        timestamp: DateTime<Utc>,
    },
    VectorAttached {
        node_id: NodeId,
        dimensions: usize,
        timestamp: DateTime<Utc>,
    },
}

impl DriftEvent {
    pub fn timestamp(&self) -> &DateTime<Utc> {
        match self {
            DriftEvent::NodeCreated { timestamp, .. } => timestamp,
            DriftEvent::NodeUpdated { timestamp, .. } => timestamp,
            DriftEvent::NodeDeleted { timestamp, .. } => timestamp,
            DriftEvent::EdgeCreated { timestamp, .. } => timestamp,
            DriftEvent::EdgeDeleted { timestamp, .. } => timestamp,
            DriftEvent::VectorAttached { timestamp, .. } => timestamp,
        }
    }

    pub fn event_type(&self) -> &str {
        match self {
            DriftEvent::NodeCreated { .. } => "NODE_CREATED",
            DriftEvent::NodeUpdated { .. } => "NODE_UPDATED",
            DriftEvent::NodeDeleted { .. } => "NODE_DELETED",
            DriftEvent::EdgeCreated { .. } => "EDGE_CREATED",
            DriftEvent::EdgeDeleted { .. } => "EDGE_DELETED",
            DriftEvent::VectorAttached { .. } => "VECTOR_ATTACHED",
        }
    }
}

/// Callback type for event listeners
pub type EventCallback = Box<dyn Fn(&DriftEvent) + Send + Sync>;

/// Event bus that manages event emission and subscriptions
pub struct EventBus {
    log: Arc<Mutex<Vec<DriftEvent>>>,
    listeners: Arc<Mutex<Vec<EventCallback>>>,
}

/// Maximum events stored in memory (prevents OOM from event spam)
const MAX_EVENT_LOG: usize = 100_000;

impl EventBus {
    pub fn new() -> Self {
        EventBus {
            log: Arc::new(Mutex::new(Vec::new())),
            listeners: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Emit an event — stores it in the log and notifies all listeners
    pub fn emit(&self, event: DriftEvent) {
        // Notify listeners
        if let Ok(listeners) = self.listeners.lock() {
            for listener in listeners.iter() {
                listener(&event);
            }
        }
        // Store in log (capped to prevent OOM)
        if let Ok(mut log) = self.log.lock() {
            if log.len() >= MAX_EVENT_LOG {
                // Evict oldest 10% to amortize the drain cost
                let drain_count = MAX_EVENT_LOG / 10;
                log.drain(..drain_count);
            }
            log.push(event);
        }
    }

    /// Subscribe to all events
    pub fn subscribe(&self, callback: EventCallback) {
        if let Ok(mut listeners) = self.listeners.lock() {
            listeners.push(callback);
        }
    }

    /// Get all events in the log
    pub fn get_log(&self) -> Vec<DriftEvent> {
        self.log.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Get events since a given timestamp
    pub fn events_since(&self, since: &DateTime<Utc>) -> Vec<DriftEvent> {
        self.get_log()
            .into_iter()
            .filter(|e| e.timestamp() >= since)
            .collect()
    }

    /// Get event count
    pub fn event_count(&self) -> usize {
        self.log.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
