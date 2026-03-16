//! Node-level operations for the graph engine

use driftdb_core::error::DriftResult;
use driftdb_core::types::{Node, NodeId, Value};
use std::collections::HashMap;

use crate::GraphEngine;

impl GraphEngine {
    /// Create a node with labels and properties
    pub fn create_node(
        &self,
        labels: Vec<String>,
        properties: HashMap<String, Value>,
    ) -> DriftResult<Node> {
        self.storage.create_node(labels, properties)
    }

    /// Get a node by its ID
    pub fn get_node(&self, id: &NodeId) -> DriftResult<Option<Node>> {
        self.storage.get_node(id)
    }

    /// Get a node at a specific point in time
    pub fn get_node_at(
        &self,
        id: &NodeId,
        at: &chrono::DateTime<chrono::Utc>,
    ) -> DriftResult<Option<Node>> {
        self.storage.get_node_at(id, at)
    }

    /// Update a property on a node
    pub fn set_property(
        &self,
        id: &NodeId,
        key: &str,
        value: Value,
    ) -> DriftResult<Node> {
        self.storage.update_node_property(id, key, value)
    }

    /// Delete a node (soft-delete)
    pub fn delete_node(&self, id: &NodeId) -> DriftResult<()> {
        self.storage.delete_node(id)
    }

    /// Get all nodes
    pub fn all_nodes(&self) -> DriftResult<Vec<Node>> {
        self.storage.all_nodes()
    }

    /// Get nodes by label
    pub fn nodes_by_label(&self, label: &str) -> DriftResult<Vec<Node>> {
        self.storage.nodes_by_label(label)
    }

    /// Find nodes matching a property predicate
    pub fn find_nodes<F>(&self, predicate: F) -> DriftResult<Vec<Node>>
    where
        F: Fn(&Node) -> bool,
    {
        Ok(self.storage.all_nodes()?.into_iter().filter(predicate).collect())
    }

    /// Find nodes by label and property conditions
    pub fn find_by_label_and_props(
        &self,
        label: &str,
        conditions: &HashMap<String, Value>,
    ) -> DriftResult<Vec<Node>> {
        let nodes = self.storage.nodes_by_label(label)?;
        Ok(nodes
            .into_iter()
            .filter(|node| {
                conditions.iter().all(|(key, val)| {
                    node.properties.get(key).map_or(false, |v| v == val)
                })
            })
            .collect())
    }
}
