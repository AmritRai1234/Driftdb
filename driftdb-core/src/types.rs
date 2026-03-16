//! DriftDB Core — Fundamental types
//!
//! Every piece of data in DriftDB is represented through these types.
//! Values are richly typed, nodes and edges have unique IDs, and
//! everything carries temporal metadata.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

// ─── Value Type ────────────────────────────────────────────────────────────

/// A dynamically-typed value that can be stored in DriftDB.
/// This is the fundamental unit of data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Vector(Vec<f64>),
    List(Vec<Value>),
    Map(HashMap<String, Value>),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => write!(f, "null"),
            Value::Bool(b) => write!(f, "{}", b),
            Value::Int(i) => write!(f, "{}", i),
            Value::Float(fl) => write!(f, "{:.4}", fl),
            Value::String(s) => write!(f, "\"{}\"", s),
            Value::Vector(v) => {
                let items: Vec<String> = v.iter().map(|x| format!("{:.3}", x)).collect();
                write!(f, "[{}]", items.join(", "))
            }
            Value::List(l) => {
                let items: Vec<String> = l.iter().map(|x| format!("{}", x)).collect();
                write!(f, "[{}]", items.join(", "))
            }
            Value::Map(m) => {
                let items: Vec<String> =
                    m.iter().map(|(k, v)| format!("{}: {}", k, v)).collect();
                write!(f, "{{{}}}", items.join(", "))
            }
        }
    }
}

impl Value {
    /// Returns the type name as a string
    pub fn type_name(&self) -> &str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::String(_) => "string",
            Value::Vector(_) => "vector",
            Value::List(_) => "list",
            Value::Map(_) => "map",
        }
    }

    /// Try to extract as a string reference
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Try to extract as an integer
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Try to extract as a float
    pub fn as_float(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            Value::Int(i) => Some(*i as f64),
            _ => None,
        }
    }

    /// Try to extract as a bool
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Try to extract as a vector
    pub fn as_vector(&self) -> Option<&Vec<f64>> {
        match self {
            Value::Vector(v) => Some(v),
            _ => None,
        }
    }
}

// ─── Identity Types ────────────────────────────────────────────────────────

/// Unique identifier for a node
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeId(pub String);

impl NodeId {
    #[inline]
    pub fn new() -> Self {
        // Use simple() format + truncate — avoids split + intermediate alloc
        let id = Uuid::new_v4().simple().to_string();
        NodeId(format!("n_{}", &id[..10]))
    }

    pub fn from_str(s: &str) -> Self {
        NodeId(s.to_string())
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for an edge
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct EdgeId(pub String);

impl EdgeId {
    #[inline]
    pub fn new() -> Self {
        let id = Uuid::new_v4().simple().to_string();
        EdgeId(format!("e_{}", &id[..10]))
    }

    pub fn from_str(s: &str) -> Self {
        EdgeId(s.to_string())
    }
}

impl Default for EdgeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EdgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─── Temporal Metadata ─────────────────────────────────────────────────────

/// Temporal range for a piece of data.
/// `created` is when it was written, `expired` is when it was superseded.
/// If `expired` is None, this is the current version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalMeta {
    pub created: DateTime<Utc>,
    pub expired: Option<DateTime<Utc>>,
    pub version: u64,
}

impl TemporalMeta {
    /// Create a new temporal metadata for a current (active) value
    pub fn now(version: u64) -> Self {
        TemporalMeta {
            created: Utc::now(),
            expired: None,
            version,
        }
    }

    /// Check if this version was active at the given timestamp
    pub fn active_at(&self, at: &DateTime<Utc>) -> bool {
        self.created <= *at && self.expired.map_or(true, |exp| *at < exp)
    }

    /// Check if this is the current (non-expired) version
    pub fn is_current(&self) -> bool {
        self.expired.is_none()
    }

    /// Expire this version now
    pub fn expire(&mut self) {
        self.expired = Some(Utc::now());
    }
}

// ─── Node & Edge Structures ────────────────────────────────────────────────

/// A node in the graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub labels: Vec<String>,
    pub properties: HashMap<String, Value>,
    pub temporal: TemporalMeta,
}

impl Node {
    /// Create a new node with given labels and properties
    pub fn new(labels: Vec<String>, properties: HashMap<String, Value>) -> Self {
        Node {
            id: NodeId::new(),
            labels,
            properties,
            temporal: TemporalMeta::now(1),
        }
    }

    /// Check if this node has a specific label
    pub fn has_label(&self, label: &str) -> bool {
        self.labels.iter().any(|l| l.eq_ignore_ascii_case(label))
    }

    /// Get a property value
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.properties.get(key)
    }
}

/// A directed edge between two nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub id: EdgeId,
    pub source: NodeId,
    pub target: NodeId,
    pub edge_type: String,
    pub properties: HashMap<String, Value>,
    pub temporal: TemporalMeta,
}

impl Edge {
    /// Create a new edge
    pub fn new(
        source: NodeId,
        target: NodeId,
        edge_type: String,
        properties: HashMap<String, Value>,
    ) -> Self {
        Edge {
            id: EdgeId::new(),
            source,
            target,
            edge_type,
            properties,
            temporal: TemporalMeta::now(1),
        }
    }
}

// ─── Properties helper ─────────────────────────────────────────────────────

/// Helper to build property maps fluently
pub struct Props;

impl Props {
    pub fn new() -> HashMap<String, Value> {
        HashMap::new()
    }
}

/// Extension trait for fluent property building
pub trait PropsBuilder {
    fn with(self, key: &str, value: Value) -> Self;
}

impl PropsBuilder for HashMap<String, Value> {
    fn with(mut self, key: &str, value: Value) -> Self {
        self.insert(key.to_string(), value);
        self
    }
}
