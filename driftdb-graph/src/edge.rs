//! Edge operations for the graph engine

use driftdb_core::error::DriftResult;
use driftdb_core::types::{Edge, EdgeId, NodeId, Value};
use std::collections::HashMap;

use crate::GraphEngine;

impl GraphEngine {
    /// Create a typed edge between two nodes
    pub fn create_edge(
        &self,
        source: NodeId,
        target: NodeId,
        edge_type: String,
        properties: HashMap<String, Value>,
    ) -> DriftResult<Edge> {
        self.storage.create_edge(source, target, edge_type, properties)
    }

    /// Get an edge by ID
    pub fn get_edge(&self, id: &EdgeId) -> DriftResult<Option<Edge>> {
        self.storage.get_edge(id)
    }

    /// Get all outgoing edges from a node
    pub fn outgoing(&self, node_id: &NodeId) -> DriftResult<Vec<Edge>> {
        self.storage.outgoing_edges(node_id)
    }

    /// Get all incoming edges to a node
    pub fn incoming(&self, node_id: &NodeId) -> DriftResult<Vec<Edge>> {
        self.storage.incoming_edges(node_id)
    }

    /// Get outgoing edges of a specific type
    pub fn outgoing_of_type(&self, node_id: &NodeId, edge_type: &str) -> DriftResult<Vec<Edge>> {
        Ok(self
            .storage
            .outgoing_edges(node_id)?
            .into_iter()
            .filter(|e| e.edge_type.eq_ignore_ascii_case(edge_type))
            .collect())
    }

    /// Get incoming edges of a specific type
    pub fn incoming_of_type(&self, node_id: &NodeId, edge_type: &str) -> DriftResult<Vec<Edge>> {
        Ok(self
            .storage
            .incoming_edges(node_id)?
            .into_iter()
            .filter(|e| e.edge_type.eq_ignore_ascii_case(edge_type))
            .collect())
    }

    /// Get all edges
    pub fn all_edges(&self) -> DriftResult<Vec<Edge>> {
        self.storage.all_edges()
    }

    /// Get the target node of an edge
    pub fn edge_target(&self, edge: &Edge) -> DriftResult<Option<driftdb_core::types::Node>> {
        self.storage.get_node(&edge.target)
    }

    /// Get the source node of an edge
    pub fn edge_source(&self, edge: &Edge) -> DriftResult<Option<driftdb_core::types::Node>> {
        self.storage.get_node(&edge.source)
    }

    /// Delete an edge (soft-delete)
    pub fn delete_edge(&self, id: &EdgeId) -> DriftResult<()> {
        self.storage.delete_edge(id)
    }

    /// Get direct neighbors of a node (following outgoing edges)
    pub fn neighbors(&self, node_id: &NodeId) -> DriftResult<Vec<driftdb_core::types::Node>> {
        let edges = self.storage.outgoing_edges(node_id)?;
        let mut neighbors = Vec::new();
        for edge in edges {
            if let Some(node) = self.storage.get_node(&edge.target)? {
                neighbors.push(node);
            }
        }
        Ok(neighbors)
    }

    /// Get neighbors connected by a specific edge type
    pub fn neighbors_by_type(
        &self,
        node_id: &NodeId,
        edge_type: &str,
    ) -> DriftResult<Vec<driftdb_core::types::Node>> {
        let edges = self.outgoing_of_type(node_id, edge_type)?;
        let mut neighbors = Vec::new();
        for edge in edges {
            if let Some(node) = self.storage.get_node(&edge.target)? {
                neighbors.push(node);
            }
        }
        Ok(neighbors)
    }
}
