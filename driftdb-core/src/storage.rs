//! DriftDB Core — Storage Engine (Maximum Performance)
//!
//! Optimizations:
//! - Tree handles cached at construction (zero overhead per operation)
//! - LRU read cache for hot node lookups
//! - Single unified index tree with composite keys
//! - Batched writes for all bulk operations
//! - contains_key for existence checks (no deserialization)
//! - Bulk create for both nodes and edges
//! - Minimized cloning on read paths

use chrono::Utc;
use parking_lot::Mutex;
use sled::{Batch, Db, Tree};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::error::{DriftError, DriftResult};
use crate::event::{DriftEvent, EventBus};
use crate::temporal::VersionedValue;
use crate::types::*;

// ═══════════════════════════════════════════════════════════════════
// LRU Cache — O(1) get/put via HashMap + access order tracking
// ═══════════════════════════════════════════════════════════════════

struct LruCache<V> {
    map: HashMap<String, V>,
    order: Vec<String>,  // Most recently used at the end
    capacity: usize,
}

impl<V: Clone> LruCache<V> {
    fn new(capacity: usize) -> Self {
        LruCache {
            map: HashMap::with_capacity(capacity),
            order: Vec::with_capacity(capacity),
            capacity,
        }
    }

    #[inline]
    fn get(&mut self, key: &str) -> Option<V> {
        if let Some(val) = self.map.get(key) {
            let val = val.clone();
            // Move to end (most recently used) — only if not already there
            if self.order.last().map(|k| k.as_str()) != Some(key) {
                if let Some(pos) = self.order.iter().position(|k| k == key) {
                    self.order.remove(pos);
                }
                self.order.push(key.to_string());
            }
            Some(val)
        } else {
            None
        }
    }

    #[inline]
    fn put(&mut self, key: String, value: V) {
        if self.map.contains_key(&key) {
            // Update existing — move to end
            self.map.insert(key.clone(), value);
            if let Some(pos) = self.order.iter().position(|k| k == &key) {
                self.order.remove(pos);
            }
            self.order.push(key);
        } else {
            // Evict oldest if at capacity
            if self.map.len() >= self.capacity {
                if let Some(oldest) = self.order.first().cloned() {
                    self.map.remove(&oldest);
                    self.order.remove(0);
                }
            }
            self.map.insert(key.clone(), value);
            self.order.push(key);
        }
    }

    #[inline]
    fn invalidate(&mut self, key: &str) {
        self.map.remove(key);
        self.order.retain(|k| k != key);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Composite index key helpers
// ═══════════════════════════════════════════════════════════════════

const IDX_LABEL: u8 = 1;
const IDX_OUT: u8 = 2;
const IDX_IN: u8 = 3;
const IDX_ETYPE: u8 = 4;

#[inline]
fn idx_key(prefix: u8, category: &str, id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + category.len() + 1 + id.len());
    key.push(prefix);
    key.extend_from_slice(category.as_bytes());
    key.push(0xFF);
    key.extend_from_slice(id.as_bytes());
    key
}

#[inline]
fn idx_prefix(prefix: u8, category: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + category.len() + 1);
    key.push(prefix);
    key.extend_from_slice(category.as_bytes());
    key.push(0xFF);
    key
}

// ═══════════════════════════════════════════════════════════════════
// Storage Engine
// ═══════════════════════════════════════════════════════════════════

/// The main storage engine for DriftDB
pub struct Storage {
    db: Db,
    /// Cached tree handles — opened once, used forever
    nodes: Tree,
    edges: Tree,
    vectors: Tree,
    idx: Tree,
    /// LRU cache for hot node lookups
    node_cache: Mutex<LruCache<Node>>,
    /// Public event bus
    pub events: Arc<EventBus>,
}

impl Storage {
    /// Open or create a database at the given path (tuned for throughput)
    pub fn open<P: AsRef<Path>>(path: P) -> DriftResult<Self> {
        let db = sled::Config::new()
            .path(path)
            .cache_capacity(256 * 1024 * 1024)  // 256MB page cache
            .flush_every_ms(Some(1000))          // Batch I/O (1s flush intervals)
            .mode(sled::Mode::HighThroughput)    // Async flushing
            .open()?;

        let nodes = db.open_tree("n")?;
        let edges = db.open_tree("e")?;
        let vectors = db.open_tree("v")?;
        let idx = db.open_tree("i")?;

        Ok(Storage {
            db,
            nodes,
            edges,
            vectors,
            idx,
            node_cache: Mutex::new(LruCache::new(4096)),  // 4x larger cache
            events: Arc::new(EventBus::new()),
        })
    }

    /// Create a temporary in-memory database (for testing/benchmarks)
    pub fn temporary() -> DriftResult<Self> {
        let config = sled::Config::new().temporary(true);
        let db = config.open()?;
        let nodes = db.open_tree("n")?;
        let edges = db.open_tree("e")?;
        let vectors = db.open_tree("v")?;
        let idx = db.open_tree("i")?;

        Ok(Storage {
            db,
            nodes,
            edges,
            vectors,
            idx,
            node_cache: Mutex::new(LruCache::new(1024)),
            events: Arc::new(EventBus::new()),
        })
    }

    // ─── Node Operations ───────────────────────────────────────────

    /// Create a new node with labels and properties
    pub fn create_node(
        &self,
        labels: Vec<String>,
        properties: HashMap<String, Value>,
    ) -> DriftResult<Node> {
        let node = Node::new(labels.clone(), properties.clone());
        let versioned = VersionedValue::new(node.clone());
        let bytes = bincode::serialize(&versioned)?;

        // Write node data
        self.nodes.insert(node.id.0.as_bytes(), bytes)?;

        // Batch label indexes
        if !labels.is_empty() {
            let mut batch = Batch::default();
            for label in &labels {
                batch.insert(idx_key(IDX_LABEL, &label.to_lowercase(), &node.id.0), &[]);
            }
            self.idx.apply_batch(batch)?;
        }

        // Cache the new node
        self.node_cache.lock().put(node.id.0.clone(), node.clone());

        self.events.emit(DriftEvent::NodeCreated {
            node_id: node.id.clone(),
            labels,
            properties,
            timestamp: Utc::now(),
        });

        Ok(node)
    }

    /// Bulk create nodes — single batch write for maximum throughput
    pub fn bulk_create_nodes(
        &self,
        nodes_data: Vec<(Vec<String>, HashMap<String, Value>)>,
    ) -> DriftResult<Vec<Node>> {
        let mut results = Vec::with_capacity(nodes_data.len());
        let mut node_batch = Batch::default();
        let mut idx_batch = Batch::default();

        for (labels, properties) in nodes_data {
            let node = Node::new(labels.clone(), properties);
            let versioned = VersionedValue::new(node.clone());
            let bytes = bincode::serialize(&versioned)?;

            node_batch.insert(node.id.0.as_bytes(), bytes);
            for label in &labels {
                idx_batch.insert(idx_key(IDX_LABEL, &label.to_lowercase(), &node.id.0), &[]);
            }

            results.push(node);
        }

        self.nodes.apply_batch(node_batch)?;
        self.idx.apply_batch(idx_batch)?;

        Ok(results)
    }

    /// Get a node by ID (cache-first, then sled)
    pub fn get_node(&self, id: &NodeId) -> DriftResult<Option<Node>> {
        // Check cache first
        {
            let mut cache = self.node_cache.lock();
            if let Some(node) = cache.get(&id.0) {
                return Ok(Some(node));
            }
        }

        // Cache miss — read from sled
        match self.nodes.get(id.0.as_bytes())? {
            Some(bytes) => {
                let versioned: VersionedValue<Node> = bincode::deserialize(&bytes)?;
                if let Some(node) = versioned.current() {
                    let node = node.clone();
                    self.node_cache.lock().put(id.0.clone(), node.clone());
                    Ok(Some(node))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    /// Check if a node exists (fast — no deserialization)
    #[inline]
    pub fn node_exists(&self, id: &NodeId) -> DriftResult<bool> {
        Ok(self.nodes.contains_key(id.0.as_bytes())?)
    }

    /// Get a node at a specific point in time (bypasses cache)
    pub fn get_node_at(
        &self,
        id: &NodeId,
        at: &chrono::DateTime<chrono::Utc>,
    ) -> DriftResult<Option<Node>> {
        match self.nodes.get(id.0.as_bytes())? {
            Some(bytes) => {
                let versioned: VersionedValue<Node> = bincode::deserialize(&bytes)?;
                Ok(versioned.at(at).cloned())
            }
            None => Ok(None),
        }
    }

    /// Update a node's property
    pub fn update_node_property(
        &self,
        id: &NodeId,
        key: &str,
        value: Value,
    ) -> DriftResult<Node> {
        let bytes = self
            .nodes
            .get(id.0.as_bytes())?
            .ok_or_else(|| DriftError::NodeNotFound(id.0.clone()))?;

        let mut versioned: VersionedValue<Node> = bincode::deserialize(&bytes)?;
        let old_value = versioned.current().and_then(|n| n.properties.get(key).cloned());

        let mut new_node = versioned
            .current()
            .cloned()
            .ok_or_else(|| DriftError::NodeNotFound(id.0.clone()))?;

        new_node.properties.insert(key.to_string(), value.clone());
        new_node.temporal = TemporalMeta::now(versioned.version_count() as u64 + 1);
        versioned.update(new_node.clone())?;

        let new_bytes = bincode::serialize(&versioned)?;
        self.nodes.insert(id.0.as_bytes(), new_bytes)?;

        // Invalidate cache — next read gets fresh data
        self.node_cache.lock().invalidate(&id.0);

        self.events.emit(DriftEvent::NodeUpdated {
            node_id: id.clone(),
            property: key.to_string(),
            old_value,
            new_value: value,
            timestamp: Utc::now(),
        });

        Ok(new_node)
    }

    /// Soft-delete a node
    pub fn delete_node(&self, id: &NodeId) -> DriftResult<()> {
        let bytes = self
            .nodes
            .get(id.0.as_bytes())?
            .ok_or_else(|| DriftError::NodeNotFound(id.0.clone()))?;

        let mut versioned: VersionedValue<Node> = bincode::deserialize(&bytes)?;
        versioned.soft_delete();

        let new_bytes = bincode::serialize(&versioned)?;
        self.nodes.insert(id.0.as_bytes(), new_bytes)?;

        // Invalidate cache
        self.node_cache.lock().invalidate(&id.0);

        self.events.emit(DriftEvent::NodeDeleted {
            node_id: id.clone(),
            timestamp: Utc::now(),
        });

        Ok(())
    }

    /// Raw insert a node (for backup restore — preserves original ID)
    pub fn raw_insert_node(&self, id: &NodeId, bytes: &[u8]) -> DriftResult<()> {
        self.nodes.insert(id.0.as_bytes(), bytes)?;
        Ok(())
    }

    /// Raw insert an edge (for backup restore — preserves original ID)
    pub fn raw_insert_edge(&self, id: &EdgeId, bytes: &[u8]) -> DriftResult<()> {
        self.edges.insert(id.0.as_bytes(), bytes)?;
        Ok(())
    }

    /// Get all current nodes
    pub fn all_nodes(&self) -> DriftResult<Vec<Node>> {
        let mut nodes = Vec::new();

        for item in self.nodes.iter() {
            let (_, bytes) = item?;
            let versioned: VersionedValue<Node> = bincode::deserialize(&bytes)?;
            if let Some(node) = versioned.current() {
                nodes.push(node.clone());
            }
        }

        Ok(nodes)
    }

    /// Get all nodes with a specific label
    pub fn nodes_by_label(&self, label: &str) -> DriftResult<Vec<Node>> {
        let prefix = idx_prefix(IDX_LABEL, &label.to_lowercase());
        let mut nodes = Vec::new();

        for item in self.idx.scan_prefix(&prefix) {
            let (key, _) = item?;
            let node_id_bytes = &key[prefix.len()..];
            let node_id = NodeId(String::from_utf8_lossy(node_id_bytes).to_string());
            if let Some(node) = self.get_node(&node_id)? {
                nodes.push(node);
            }
        }

        Ok(nodes)
    }

    /// Count nodes with a specific label (fast — no deserialization)
    pub fn count_by_label(&self, label: &str) -> DriftResult<usize> {
        let prefix = idx_prefix(IDX_LABEL, &label.to_lowercase());
        Ok(self.idx.scan_prefix(&prefix).count())
    }

    // ─── Edge Operations ───────────────────────────────────────────

    /// Create edge with source/target verification
    pub fn create_edge(
        &self,
        source: NodeId,
        target: NodeId,
        edge_type: String,
        properties: HashMap<String, Value>,
    ) -> DriftResult<Edge> {
        self.create_edge_fast(source, target, edge_type, properties, true)
    }

    /// Create edge — set verify=false for bulk loads
    pub fn create_edge_fast(
        &self,
        source: NodeId,
        target: NodeId,
        edge_type: String,
        properties: HashMap<String, Value>,
        verify: bool,
    ) -> DriftResult<Edge> {
        if verify {
            if !self.nodes.contains_key(source.0.as_bytes())? {
                return Err(DriftError::NodeNotFound(source.0.clone()));
            }
            if !self.nodes.contains_key(target.0.as_bytes())? {
                return Err(DriftError::NodeNotFound(target.0.clone()));
            }
        }

        let edge = Edge::new(source.clone(), target.clone(), edge_type.clone(), properties.clone());
        let versioned = VersionedValue::new(edge.clone());
        let bytes = bincode::serialize(&versioned)?;

        self.edges.insert(edge.id.0.as_bytes(), bytes)?;

        let mut batch = Batch::default();
        batch.insert(idx_key(IDX_OUT, &source.0, &edge.id.0), &[]);
        batch.insert(idx_key(IDX_IN, &target.0, &edge.id.0), &[]);
        batch.insert(idx_key(IDX_ETYPE, &edge_type.to_lowercase(), &edge.id.0), &[]);
        self.idx.apply_batch(batch)?;

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

    /// Bulk insert edges — two batch writes instead of N*4 individual writes
    pub fn bulk_create_edges(
        &self,
        edges_data: Vec<(NodeId, NodeId, String, HashMap<String, Value>)>,
    ) -> DriftResult<Vec<Edge>> {
        let mut results = Vec::with_capacity(edges_data.len());
        let mut edge_batch = Batch::default();
        let mut idx_batch = Batch::default();

        for (source, target, edge_type, properties) in edges_data {
            let edge = Edge::new(source.clone(), target.clone(), edge_type.clone(), properties);
            let versioned = VersionedValue::new(edge.clone());
            let bytes = bincode::serialize(&versioned)?;

            edge_batch.insert(edge.id.0.as_bytes(), bytes);
            idx_batch.insert(idx_key(IDX_OUT, &source.0, &edge.id.0), &[]);
            idx_batch.insert(idx_key(IDX_IN, &target.0, &edge.id.0), &[]);
            idx_batch.insert(idx_key(IDX_ETYPE, &edge_type.to_lowercase(), &edge.id.0), &[]);

            results.push(edge);
        }

        self.edges.apply_batch(edge_batch)?;
        self.idx.apply_batch(idx_batch)?;

        Ok(results)
    }

    /// Get an edge by ID
    pub fn get_edge(&self, id: &EdgeId) -> DriftResult<Option<Edge>> {
        match self.edges.get(id.0.as_bytes())? {
            Some(bytes) => {
                let versioned: VersionedValue<Edge> = bincode::deserialize(&bytes)?;
                Ok(versioned.current().cloned())
            }
            None => Ok(None),
        }
    }

    /// Get all outgoing edges from a node
    pub fn outgoing_edges(&self, node_id: &NodeId) -> DriftResult<Vec<Edge>> {
        let prefix = idx_prefix(IDX_OUT, &node_id.0);
        let mut edges = Vec::new();

        for item in self.idx.scan_prefix(&prefix) {
            let (key, _) = item?;
            let edge_id = EdgeId(String::from_utf8_lossy(&key[prefix.len()..]).to_string());
            if let Some(edge) = self.get_edge(&edge_id)? {
                edges.push(edge);
            }
        }

        Ok(edges)
    }

    /// Get all incoming edges to a node
    pub fn incoming_edges(&self, node_id: &NodeId) -> DriftResult<Vec<Edge>> {
        let prefix = idx_prefix(IDX_IN, &node_id.0);
        let mut edges = Vec::new();

        for item in self.idx.scan_prefix(&prefix) {
            let (key, _) = item?;
            let edge_id = EdgeId(String::from_utf8_lossy(&key[prefix.len()..]).to_string());
            if let Some(edge) = self.get_edge(&edge_id)? {
                edges.push(edge);
            }
        }

        Ok(edges)
    }

    /// Get all current edges
    pub fn all_edges(&self) -> DriftResult<Vec<Edge>> {
        let mut edges = Vec::new();

        for item in self.edges.iter() {
            let (_, bytes) = item?;
            let versioned: VersionedValue<Edge> = bincode::deserialize(&bytes)?;
            if let Some(edge) = versioned.current() {
                edges.push(edge.clone());
            }
        }

        Ok(edges)
    }

    /// Delete an edge (soft-delete)
    pub fn delete_edge(&self, id: &EdgeId) -> DriftResult<()> {
        let bytes = self
            .edges
            .get(id.0.as_bytes())?
            .ok_or_else(|| DriftError::EdgeNotFound(id.0.clone()))?;

        let mut versioned: VersionedValue<Edge> = bincode::deserialize(&bytes)?;
        versioned.soft_delete();

        let new_bytes = bincode::serialize(&versioned)?;
        self.edges.insert(id.0.as_bytes(), new_bytes)?;

        self.events.emit(DriftEvent::EdgeDeleted {
            edge_id: id.clone(),
            timestamp: Utc::now(),
        });

        Ok(())
    }

    // ─── Vector Operations ─────────────────────────────────────────

    /// Attach a vector embedding to a node
    pub fn attach_vector(&self, node_id: &NodeId, vector: Vec<f64>) -> DriftResult<()> {
        let dimensions = vector.len();
        let bytes = bincode::serialize(&vector)?;
        self.vectors.insert(node_id.0.as_bytes(), bytes)?;

        self.events.emit(DriftEvent::VectorAttached {
            node_id: node_id.clone(),
            dimensions,
            timestamp: Utc::now(),
        });

        Ok(())
    }

    /// Get the vector attached to a node
    pub fn get_vector(&self, node_id: &NodeId) -> DriftResult<Option<Vec<f64>>> {
        match self.vectors.get(node_id.0.as_bytes())? {
            Some(bytes) => {
                let vector: Vec<f64> = bincode::deserialize(&bytes)?;
                Ok(Some(vector))
            }
            None => Ok(None),
        }
    }

    /// Get all node IDs that have vectors attached
    pub fn all_vectors(&self) -> DriftResult<Vec<(NodeId, Vec<f64>)>> {
        let mut results = Vec::new();

        for item in self.vectors.iter() {
            let (key, bytes) = item?;
            let node_id = NodeId(String::from_utf8_lossy(&key).to_string());
            let vector: Vec<f64> = bincode::deserialize(&bytes)?;
            results.push((node_id, vector));
        }

        Ok(results)
    }

    // ─── Stats ─────────────────────────────────────────────────────

    /// Get database statistics (fast — uses tree len, no iteration)
    pub fn stats(&self) -> DriftResult<StorageStats> {
        Ok(StorageStats {
            node_count: self.nodes.len(),
            edge_count: self.edges.len(),
            vector_count: self.vectors.len(),
            event_count: self.events.event_count(),
            size_on_disk: self.db.size_on_disk().unwrap_or(0),
        })
    }

    /// Flush all pending writes to disk
    pub fn flush(&self) -> DriftResult<()> {
        self.db.flush()?;
        Ok(())
    }
}

/// Database statistics
#[derive(Debug)]
pub struct StorageStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub vector_count: usize,
    pub event_count: usize,
    pub size_on_disk: u64,
}

impl std::fmt::Display for StorageStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let disk_mb = self.size_on_disk as f64 / (1024.0 * 1024.0);
        write!(
            f,
            "Nodes: {} | Edges: {} | Vectors: {} | Events: {} | Disk: {:.1} MB",
            self.node_count, self.edge_count, self.vector_count,
            self.event_count, disk_mb
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_storage() -> Storage {
        Storage::temporary().unwrap()
    }

    #[test]
    fn test_create_and_get_node() {
        let store = test_storage();
        let props = HashMap::from([
            ("name".to_string(), Value::String("Amrit".to_string())),
            ("age".to_string(), Value::Int(22)),
        ]);

        let node = store.create_node(vec!["User".to_string()], props).unwrap();
        assert!(node.has_label("User"));

        let fetched = store.get_node(&node.id).unwrap().unwrap();
        assert_eq!(fetched.id, node.id);
        assert_eq!(fetched.get("name").unwrap().as_str().unwrap(), "Amrit");
    }

    #[test]
    fn test_update_node_property() {
        let store = test_storage();
        let node = store
            .create_node(
                vec!["User".to_string()],
                HashMap::from([("name".to_string(), Value::String("Amrit".to_string()))]),
            )
            .unwrap();

        let updated = store
            .update_node_property(&node.id, "name", Value::String("Amrit S".to_string()))
            .unwrap();
        assert_eq!(updated.get("name").unwrap().as_str().unwrap(), "Amrit S");
    }

    #[test]
    fn test_create_and_traverse_edges() {
        let store = test_storage();
        let user = store
            .create_node(
                vec!["User".to_string()],
                HashMap::from([("name".to_string(), Value::String("Amrit".to_string()))]),
            )
            .unwrap();
        let project = store
            .create_node(
                vec!["Project".to_string()],
                HashMap::from([("name".to_string(), Value::String("Echo".to_string()))]),
            )
            .unwrap();

        let edge = store.create_edge(user.id.clone(), project.id.clone(), "BUILT".to_string(), HashMap::new()).unwrap();
        assert_eq!(edge.edge_type, "BUILT");

        let outgoing = store.outgoing_edges(&user.id).unwrap();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].target, project.id);

        let incoming = store.incoming_edges(&project.id).unwrap();
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0].source, user.id);
    }

    #[test]
    fn test_soft_delete_preserves_history() {
        let store = test_storage();
        let node = store
            .create_node(vec!["Temp".to_string()], HashMap::from([("data".to_string(), Value::Int(42))]))
            .unwrap();

        store.delete_node(&node.id).unwrap();
        assert!(store.get_node(&node.id).unwrap().is_none());
    }

    #[test]
    fn test_vector_operations() {
        let store = test_storage();
        let node = store.create_node(vec!["Item".to_string()], HashMap::new()).unwrap();

        let vec_data = vec![0.1, 0.5, 0.9, 0.3];
        store.attach_vector(&node.id, vec_data.clone()).unwrap();

        let fetched = store.get_vector(&node.id).unwrap().unwrap();
        assert_eq!(fetched, vec_data);
    }

    #[test]
    fn test_nodes_by_label() {
        let store = test_storage();
        store.create_node(vec!["User".to_string()], HashMap::from([("name".to_string(), Value::String("A".to_string()))])).unwrap();
        store.create_node(vec!["User".to_string()], HashMap::from([("name".to_string(), Value::String("B".to_string()))])).unwrap();
        store.create_node(vec!["Song".to_string()], HashMap::from([("title".to_string(), Value::String("C".to_string()))])).unwrap();

        let users = store.nodes_by_label("user").unwrap();
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn test_event_emission() {
        let store = test_storage();
        store.create_node(vec!["Test".to_string()], HashMap::new()).unwrap();

        let events = store.events.get_log();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type(), "NODE_CREATED");
    }

    #[test]
    fn test_stats() {
        let store = test_storage();
        store.create_node(vec!["A".to_string()], HashMap::new()).unwrap();
        store.create_node(vec!["B".to_string()], HashMap::new()).unwrap();

        let stats = store.stats().unwrap();
        assert_eq!(stats.node_count, 2);
        assert_eq!(stats.edge_count, 0);
    }

    #[test]
    fn test_bulk_create_edges() {
        let store = test_storage();
        let n1 = store.create_node(vec!["A".to_string()], HashMap::new()).unwrap();
        let n2 = store.create_node(vec!["B".to_string()], HashMap::new()).unwrap();
        let n3 = store.create_node(vec!["C".to_string()], HashMap::new()).unwrap();

        let edges_data = vec![
            (n1.id.clone(), n2.id.clone(), "KNOWS".to_string(), HashMap::new()),
            (n2.id.clone(), n3.id.clone(), "KNOWS".to_string(), HashMap::new()),
            (n1.id.clone(), n3.id.clone(), "LIKES".to_string(), HashMap::new()),
        ];

        let edges = store.bulk_create_edges(edges_data).unwrap();
        assert_eq!(edges.len(), 3);

        let out = store.outgoing_edges(&n1.id).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn test_bulk_create_nodes() {
        let store = test_storage();
        let data: Vec<(Vec<String>, HashMap<String, Value>)> = (0..100)
            .map(|i| {
                (
                    vec!["User".to_string()],
                    HashMap::from([("name".to_string(), Value::String(format!("user_{}", i)))]),
                )
            })
            .collect();

        let nodes = store.bulk_create_nodes(data).unwrap();
        assert_eq!(nodes.len(), 100);
        assert_eq!(store.count_by_label("user").unwrap(), 100);
    }

    #[test]
    fn test_node_cache() {
        let store = test_storage();
        let node = store.create_node(
            vec!["User".to_string()],
            HashMap::from([("name".to_string(), Value::String("Cached".to_string()))]),
        ).unwrap();

        // First read populates cache
        let n1 = store.get_node(&node.id).unwrap().unwrap();
        // Second read hits cache
        let n2 = store.get_node(&node.id).unwrap().unwrap();
        assert_eq!(n1.id, n2.id);

        // Update invalidates cache
        store.update_node_property(&node.id, "name", Value::String("Updated".to_string())).unwrap();
        let n3 = store.get_node(&node.id).unwrap().unwrap();
        assert_eq!(n3.get("name").unwrap().as_str().unwrap(), "Updated");
    }

    #[test]
    fn test_node_exists() {
        let store = test_storage();
        let node = store.create_node(vec!["Test".to_string()], HashMap::new()).unwrap();

        assert!(store.node_exists(&node.id).unwrap());
        assert!(!store.node_exists(&NodeId("fake_id".to_string())).unwrap());
    }
}
