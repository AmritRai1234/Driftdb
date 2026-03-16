//! DriftDB — In-Memory Heap Engine (Maximum Throughput)
//!
//! Pure heap-backed storage using HashMap + BTreeMap.
//! All data lives in RAM — reads and writes are O(1) / O(log n).
//! Durability comes from WAL-only persistence (write-ahead log to disk).
//!
//! This is how you get SpacetimeDB-level throughput:
//! - No serialization on reads (data is already in native Rust structs)
//! - No disk I/O on reads (pure memory access)
//! - HashMap = O(1) amortized lookups
//! - BTreeMap = ordered iteration + range scans
//! - RwLock = concurrent readers, exclusive writers

use chrono::Utc;
use parking_lot::RwLock;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use crate::error::{DriftError, DriftResult};
use crate::event::{DriftEvent, EventBus};
use crate::temporal::VersionedValue;
use crate::types::*;

// ═══════════════════════════════════════════════════════════════════
// In-Memory Heap Engine
// ═══════════════════════════════════════════════════════════════════

/// Pure in-memory storage engine — all data on the heap.
/// Designed for maximum throughput with zero disk I/O on reads.
pub struct HeapEngine {
    /// Nodes: HashMap for O(1) lookups
    nodes: RwLock<HashMap<String, VersionedValue<Node>>>,
    /// Edges: HashMap for O(1) lookups
    edges: RwLock<HashMap<String, VersionedValue<Edge>>>,
    /// Vectors: HashMap for O(1) lookups
    vectors: RwLock<HashMap<String, Vec<f64>>>,
    /// Label index: label -> set of node IDs (BTreeMap for sorted iteration)
    label_index: RwLock<BTreeMap<String, HashSet<String>>>,
    /// Outgoing edge index: source_node_id -> set of edge IDs
    out_index: RwLock<HashMap<String, HashSet<String>>>,
    /// Incoming edge index: target_node_id -> set of edge IDs
    in_index: RwLock<HashMap<String, HashSet<String>>>,
    /// Edge type index: edge_type -> set of edge IDs
    etype_index: RwLock<HashMap<String, HashSet<String>>>,
    /// Event bus
    pub events: Arc<EventBus>,
}

impl HeapEngine {
    /// Create a new empty in-memory engine
    pub fn new() -> Self {
        HeapEngine {
            nodes: RwLock::new(HashMap::with_capacity(10_000)),
            edges: RwLock::new(HashMap::with_capacity(10_000)),
            vectors: RwLock::new(HashMap::with_capacity(1_000)),
            label_index: RwLock::new(BTreeMap::new()),
            out_index: RwLock::new(HashMap::with_capacity(10_000)),
            in_index: RwLock::new(HashMap::with_capacity(10_000)),
            etype_index: RwLock::new(HashMap::with_capacity(100)),
            events: Arc::new(EventBus::new()),
        }
    }

    /// Create with pre-allocated capacity for expected data size
    pub fn with_capacity(nodes: usize, edges: usize) -> Self {
        HeapEngine {
            nodes: RwLock::new(HashMap::with_capacity(nodes)),
            edges: RwLock::new(HashMap::with_capacity(edges)),
            vectors: RwLock::new(HashMap::with_capacity(nodes / 10)),
            label_index: RwLock::new(BTreeMap::new()),
            out_index: RwLock::new(HashMap::with_capacity(nodes)),
            in_index: RwLock::new(HashMap::with_capacity(nodes)),
            etype_index: RwLock::new(HashMap::with_capacity(100)),
            events: Arc::new(EventBus::new()),
        }
    }

    // ─── Node Operations (O(1) reads/writes) ───────────────────────

    /// Create a node — O(1)
    pub fn create_node(
        &self,
        labels: Vec<String>,
        properties: HashMap<String, Value>,
    ) -> DriftResult<Node> {
        let node = Node::new(labels.clone(), properties.clone());
        let versioned = VersionedValue::new(node.clone());

        // O(1) insert into nodes map
        self.nodes.write().insert(node.id.0.clone(), versioned);

        // O(1) per label — update label index
        {
            let mut idx = self.label_index.write();
            for label in &labels {
                idx.entry(label.to_lowercase())
                    .or_default()
                    .insert(node.id.0.clone());
            }
        }

        self.events.emit(DriftEvent::NodeCreated {
            node_id: node.id.clone(),
            labels,
            properties,
            timestamp: Utc::now(),
        });

        Ok(node)
    }

    /// Bulk create nodes — batch-optimized with single lock acquisition
    pub fn bulk_create_nodes(
        &self,
        data: Vec<(Vec<String>, HashMap<String, Value>)>,
    ) -> DriftResult<Vec<Node>> {
        let mut results = Vec::with_capacity(data.len());

        // Acquire write locks once for the entire batch
        let mut nodes_map = self.nodes.write();
        let mut label_map = self.label_index.write();

        for (labels, properties) in data {
            let node = Node::new(labels.clone(), properties);
            let versioned = VersionedValue::new(node.clone());

            nodes_map.insert(node.id.0.clone(), versioned);

            for label in &labels {
                label_map
                    .entry(label.to_lowercase())
                    .or_default()
                    .insert(node.id.0.clone());
            }

            results.push(node);
        }

        Ok(results)
    }

    /// Get node — O(1) HashMap lookup, zero serialization
    #[inline]
    pub fn get_node(&self, id: &NodeId) -> DriftResult<Option<Node>> {
        let nodes = self.nodes.read();
        Ok(nodes.get(&id.0).and_then(|v| v.current().cloned()))
    }

    /// Check if node exists — O(1), no clone
    #[inline]
    pub fn node_exists(&self, id: &NodeId) -> bool {
        self.nodes.read().contains_key(&id.0)
    }

    /// Get node at a specific time — O(1) lookup + O(versions) scan
    pub fn get_node_at(
        &self,
        id: &NodeId,
        at: &chrono::DateTime<chrono::Utc>,
    ) -> DriftResult<Option<Node>> {
        let nodes = self.nodes.read();
        Ok(nodes.get(&id.0).and_then(|v| v.at(at).cloned()))
    }

    /// Update node property — O(1)
    pub fn update_node_property(
        &self,
        id: &NodeId,
        key: &str,
        value: Value,
    ) -> DriftResult<Node> {
        let mut nodes = self.nodes.write();
        let versioned = nodes
            .get_mut(&id.0)
            .ok_or_else(|| DriftError::NodeNotFound(id.0.clone()))?;

        let old_value = versioned.current().and_then(|n| n.properties.get(key).cloned());

        let mut new_node = versioned
            .current()
            .cloned()
            .ok_or_else(|| DriftError::NodeNotFound(id.0.clone()))?;

        new_node.properties.insert(key.to_string(), value.clone());
        new_node.temporal = TemporalMeta::now(versioned.version_count() as u64 + 1);
        versioned.update(new_node.clone())?;

        self.events.emit(DriftEvent::NodeUpdated {
            node_id: id.clone(),
            property: key.to_string(),
            old_value,
            new_value: value,
            timestamp: Utc::now(),
        });

        Ok(new_node)
    }

    /// Soft-delete a node — O(1)
    pub fn delete_node(&self, id: &NodeId) -> DriftResult<()> {
        let mut nodes = self.nodes.write();
        let versioned = nodes
            .get_mut(&id.0)
            .ok_or_else(|| DriftError::NodeNotFound(id.0.clone()))?;

        versioned.soft_delete();

        self.events.emit(DriftEvent::NodeDeleted {
            node_id: id.clone(),
            timestamp: Utc::now(),
        });

        Ok(())
    }

    /// Get all current nodes — O(n)
    pub fn all_nodes(&self) -> DriftResult<Vec<Node>> {
        let nodes = self.nodes.read();
        Ok(nodes
            .values()
            .filter_map(|v| v.current().cloned())
            .collect())
    }

    /// Get nodes by label — O(k) where k = nodes with that label
    pub fn nodes_by_label(&self, label: &str) -> DriftResult<Vec<Node>> {
        let idx = self.label_index.read();
        let nodes = self.nodes.read();

        match idx.get(&label.to_lowercase()) {
            Some(ids) => {
                Ok(ids
                    .iter()
                    .filter_map(|id| {
                        nodes.get(id).and_then(|v| v.current().cloned())
                    })
                    .collect())
            }
            None => Ok(Vec::new()),
        }
    }

    /// Count by label — O(1) (just read the HashSet len)
    #[inline]
    pub fn count_by_label(&self, label: &str) -> usize {
        self.label_index
            .read()
            .get(&label.to_lowercase())
            .map(|s| s.len())
            .unwrap_or(0)
    }

    // ─── Edge Operations ───────────────────────────────────────────

    /// Create edge — O(1) with index updates
    pub fn create_edge(
        &self,
        source: NodeId,
        target: NodeId,
        edge_type: String,
        properties: HashMap<String, Value>,
    ) -> DriftResult<Edge> {
        // Verify nodes exist (fast — just HashMap contains)
        if !self.node_exists(&source) {
            return Err(DriftError::NodeNotFound(source.0));
        }
        if !self.node_exists(&target) {
            return Err(DriftError::NodeNotFound(target.0));
        }

        self.create_edge_unchecked(source, target, edge_type, properties)
    }

    /// Create edge without verification — for bulk loads
    pub fn create_edge_unchecked(
        &self,
        source: NodeId,
        target: NodeId,
        edge_type: String,
        properties: HashMap<String, Value>,
    ) -> DriftResult<Edge> {
        let edge = Edge::new(
            source.clone(),
            target.clone(),
            edge_type.clone(),
            properties.clone(),
        );
        let edge_id = edge.id.0.clone();
        let versioned = VersionedValue::new(edge.clone());

        // Insert edge data
        self.edges.write().insert(edge_id.clone(), versioned);

        // Update all indexes
        self.out_index
            .write()
            .entry(source.0.clone())
            .or_default()
            .insert(edge_id.clone());

        self.in_index
            .write()
            .entry(target.0.clone())
            .or_default()
            .insert(edge_id.clone());

        self.etype_index
            .write()
            .entry(edge_type.to_lowercase())
            .or_default()
            .insert(edge_id);

        self.events.emit(DriftEvent::EdgeCreated {
            edge_id: edge.id.clone(),
            source,
            target,
            edge_type,
            properties,
            timestamp: Utc::now(),
        });

        Ok(edge)
    }

    /// Bulk create edges — single lock acquisition for maximum throughput
    pub fn bulk_create_edges(
        &self,
        data: Vec<(NodeId, NodeId, String, HashMap<String, Value>)>,
    ) -> DriftResult<Vec<Edge>> {
        let mut results = Vec::with_capacity(data.len());

        // Acquire all write locks once
        let mut edges_map = self.edges.write();
        let mut out_map = self.out_index.write();
        let mut in_map = self.in_index.write();
        let mut etype_map = self.etype_index.write();

        for (source, target, edge_type, properties) in data {
            let edge = Edge::new(source.clone(), target.clone(), edge_type.clone(), properties);
            let edge_id = edge.id.0.clone();

            edges_map.insert(edge_id.clone(), VersionedValue::new(edge.clone()));

            out_map
                .entry(source.0.clone())
                .or_default()
                .insert(edge_id.clone());

            in_map
                .entry(target.0.clone())
                .or_default()
                .insert(edge_id.clone());

            etype_map
                .entry(edge_type.to_lowercase())
                .or_default()
                .insert(edge_id);

            results.push(edge);
        }

        Ok(results)
    }

    /// Get edge by ID — O(1)
    #[inline]
    pub fn get_edge(&self, id: &EdgeId) -> DriftResult<Option<Edge>> {
        let edges = self.edges.read();
        Ok(edges.get(&id.0).and_then(|v| v.current().cloned()))
    }

    /// Get outgoing edges — O(k) where k = outgoing edge count
    pub fn outgoing_edges(&self, node_id: &NodeId) -> DriftResult<Vec<Edge>> {
        let out = self.out_index.read();
        let edges = self.edges.read();

        match out.get(&node_id.0) {
            Some(ids) => {
                Ok(ids
                    .iter()
                    .filter_map(|id| edges.get(id).and_then(|v| v.current().cloned()))
                    .collect())
            }
            None => Ok(Vec::new()),
        }
    }

    /// Get incoming edges — O(k) where k = incoming edge count
    pub fn incoming_edges(&self, node_id: &NodeId) -> DriftResult<Vec<Edge>> {
        let inc = self.in_index.read();
        let edges = self.edges.read();

        match inc.get(&node_id.0) {
            Some(ids) => {
                Ok(ids
                    .iter()
                    .filter_map(|id| edges.get(id).and_then(|v| v.current().cloned()))
                    .collect())
            }
            None => Ok(Vec::new()),
        }
    }

    /// Get all edges — O(n)
    pub fn all_edges(&self) -> DriftResult<Vec<Edge>> {
        let edges = self.edges.read();
        Ok(edges
            .values()
            .filter_map(|v| v.current().cloned())
            .collect())
    }

    /// Delete edge — O(1)
    pub fn delete_edge(&self, id: &EdgeId) -> DriftResult<()> {
        let mut edges = self.edges.write();
        let versioned = edges
            .get_mut(&id.0)
            .ok_or_else(|| DriftError::EdgeNotFound(id.0.clone()))?;

        versioned.soft_delete();

        self.events.emit(DriftEvent::EdgeDeleted {
            edge_id: id.clone(),
            timestamp: Utc::now(),
        });

        Ok(())
    }

    // ─── Vector Operations ─────────────────────────────────────────

    /// Attach vector — O(1)
    pub fn attach_vector(&self, node_id: &NodeId, vector: Vec<f64>) -> DriftResult<()> {
        let dimensions = vector.len();
        self.vectors.write().insert(node_id.0.clone(), vector);

        self.events.emit(DriftEvent::VectorAttached {
            node_id: node_id.clone(),
            dimensions,
            timestamp: Utc::now(),
        });

        Ok(())
    }

    /// Get vector — O(1)
    #[inline]
    pub fn get_vector(&self, node_id: &NodeId) -> DriftResult<Option<Vec<f64>>> {
        Ok(self.vectors.read().get(&node_id.0).cloned())
    }

    /// Get all vectors — O(n)
    pub fn all_vectors(&self) -> DriftResult<Vec<(NodeId, Vec<f64>)>> {
        let vecs = self.vectors.read();
        Ok(vecs
            .iter()
            .map(|(id, v)| (NodeId(id.clone()), v.clone()))
            .collect())
    }

    // ─── Stats ─────────────────────────────────────────────────────

    /// Memory stats — O(1)
    pub fn stats(&self) -> HeapStats {
        HeapStats {
            node_count: self.nodes.read().len(),
            edge_count: self.edges.read().len(),
            vector_count: self.vectors.read().len(),
            event_count: self.events.event_count(),
            label_count: self.label_index.read().len(),
        }
    }

    /// Estimate memory usage in bytes
    pub fn memory_usage(&self) -> usize {
        let nodes = self.nodes.read();
        let edges = self.edges.read();
        let vectors = self.vectors.read();

        // Rough estimate: each node ~500 bytes, each edge ~300 bytes, each vector dim ~8 bytes
        let node_mem = nodes.len() * 500;
        let edge_mem = edges.len() * 300;
        let vec_mem: usize = vectors.values().map(|v| v.len() * 8).sum();

        node_mem + edge_mem + vec_mem
    }
}

impl Default for HeapEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory engine statistics
#[derive(Debug, Clone)]
pub struct HeapStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub vector_count: usize,
    pub event_count: usize,
    pub label_count: usize,
}

impl std::fmt::Display for HeapStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Nodes: {} | Edges: {} | Vectors: {} | Events: {} | Labels: {}",
            self.node_count, self.edge_count, self.vector_count,
            self.event_count, self.label_count
        )
    }
}

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_get_node() {
        let engine = HeapEngine::new();
        let node = engine
            .create_node(
                vec!["User".to_string()],
                HashMap::from([("name".to_string(), Value::String("Amrit".into()))]),
            )
            .unwrap();

        let fetched = engine.get_node(&node.id).unwrap().unwrap();
        assert_eq!(fetched.id, node.id);
        assert_eq!(fetched.get("name").unwrap().as_str().unwrap(), "Amrit");
    }

    #[test]
    fn test_bulk_create_nodes() {
        let engine = HeapEngine::new();
        let data: Vec<_> = (0..1000)
            .map(|i| {
                (
                    vec!["User".to_string()],
                    HashMap::from([("n".to_string(), Value::Int(i))]),
                )
            })
            .collect();

        let nodes = engine.bulk_create_nodes(data).unwrap();
        assert_eq!(nodes.len(), 1000);
        assert_eq!(engine.count_by_label("user"), 1000);
    }

    #[test]
    fn test_node_exists() {
        let engine = HeapEngine::new();
        let node = engine
            .create_node(vec!["X".to_string()], HashMap::new())
            .unwrap();

        assert!(engine.node_exists(&node.id));
        assert!(!engine.node_exists(&NodeId("fake".into())));
    }

    #[test]
    fn test_edges() {
        let engine = HeapEngine::new();
        let a = engine.create_node(vec!["A".into()], HashMap::new()).unwrap();
        let b = engine.create_node(vec!["B".into()], HashMap::new()).unwrap();

        let edge = engine
            .create_edge(a.id.clone(), b.id.clone(), "KNOWS".into(), HashMap::new())
            .unwrap();
        assert_eq!(edge.edge_type, "KNOWS");

        let out = engine.outgoing_edges(&a.id).unwrap();
        assert_eq!(out.len(), 1);
        let inc = engine.incoming_edges(&b.id).unwrap();
        assert_eq!(inc.len(), 1);
    }

    #[test]
    fn test_bulk_edges() {
        let engine = HeapEngine::new();
        let a = engine.create_node(vec!["A".into()], HashMap::new()).unwrap();
        let b = engine.create_node(vec!["B".into()], HashMap::new()).unwrap();
        let c = engine.create_node(vec!["C".into()], HashMap::new()).unwrap();

        let data = vec![
            (a.id.clone(), b.id.clone(), "X".into(), HashMap::new()),
            (b.id.clone(), c.id.clone(), "Y".into(), HashMap::new()),
        ];
        let edges = engine.bulk_create_edges(data).unwrap();
        assert_eq!(edges.len(), 2);
    }

    #[test]
    fn test_vectors() {
        let engine = HeapEngine::new();
        let node = engine.create_node(vec!["V".into()], HashMap::new()).unwrap();

        engine.attach_vector(&node.id, vec![0.1, 0.2, 0.3]).unwrap();
        let v = engine.get_vector(&node.id).unwrap().unwrap();
        assert_eq!(v, vec![0.1, 0.2, 0.3]);
    }

    #[test]
    fn test_update_property() {
        let engine = HeapEngine::new();
        let node = engine
            .create_node(
                vec!["User".into()],
                HashMap::from([("name".to_string(), Value::String("A".into()))]),
            )
            .unwrap();

        engine
            .update_node_property(&node.id, "name", Value::String("B".into()))
            .unwrap();

        let updated = engine.get_node(&node.id).unwrap().unwrap();
        assert_eq!(updated.get("name").unwrap().as_str().unwrap(), "B");
    }

    #[test]
    fn test_concurrent_reads() {
        use std::thread;

        let engine = Arc::new(HeapEngine::new());
        let node = engine
            .create_node(vec!["Test".into()], HashMap::new())
            .unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let e = engine.clone();
            let nid = node.id.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    e.get_node(&nid).unwrap();
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_memory_stats() {
        let engine = HeapEngine::new();
        for i in 0..100 {
            engine
                .create_node(
                    vec!["User".into()],
                    HashMap::from([("i".to_string(), Value::Int(i))]),
                )
                .unwrap();
        }

        let stats = engine.stats();
        assert_eq!(stats.node_count, 100);
        assert!(engine.memory_usage() > 0);
    }
}
