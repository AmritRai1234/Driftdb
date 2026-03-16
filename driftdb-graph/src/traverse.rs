//! Graph traversal algorithms — BFS, DFS, shortest path
//!
//! Security:
//! - All traversals have a MAX_VISITED cap (10K nodes) to prevent OOM
//! - BFS/DFS have a DEFAULT_MAX_DEPTH of 20 if no limit is specified
//! - DFS uses an explicit stack (not recursion) to prevent stack overflow

use driftdb_core::error::DriftResult;
use driftdb_core::types::{Node, NodeId};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::GraphEngine;

/// Result of a traversal operation
#[derive(Debug)]
pub struct TraversalResult {
    pub visited: Vec<Node>,
    pub paths: HashMap<String, Vec<NodeId>>,
}

/// Maximum nodes visited in any traversal (prevents OOM on huge graphs)
const MAX_VISITED: usize = 10_000;
/// Default max depth if none specified (prevents runaway traversal)
const DEFAULT_MAX_DEPTH: usize = 20;

impl GraphEngine {
    /// Breadth-first search from a starting node
    /// Returns all reachable nodes in BFS order (capped at MAX_VISITED)
    pub fn bfs(&self, start: &NodeId, max_depth: Option<usize>) -> DriftResult<Vec<Node>> {
        let max_depth = max_depth.unwrap_or(DEFAULT_MAX_DEPTH);
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        visited.insert(start.0.clone());
        queue.push_back((start.clone(), 0usize));

        while let Some((current_id, depth)) = queue.pop_front() {
            if depth > max_depth {
                continue;
            }

            // Safety cap: prevent OOM on massive graphs
            if visited.len() >= MAX_VISITED {
                break;
            }

            if let Some(node) = self.storage.get_node(&current_id)? {
                result.push(node);

                let edges = self.storage.outgoing_edges(&current_id)?;
                for edge in edges {
                    if !visited.contains(&edge.target.0) {
                        visited.insert(edge.target.0.clone());
                        queue.push_back((edge.target, depth + 1));
                    }
                }
            }
        }

        Ok(result)
    }

    /// Depth-first search from a starting node (iterative — no stack overflow)
    pub fn dfs(&self, start: &NodeId, max_depth: Option<usize>) -> DriftResult<Vec<Node>> {
        let max_depth = max_depth.unwrap_or(DEFAULT_MAX_DEPTH);
        let mut visited = HashSet::new();
        let mut result = Vec::new();
        // Use explicit stack instead of recursion to prevent stack overflow
        let mut stack: Vec<(NodeId, usize)> = vec![(start.clone(), 0)];

        while let Some((current, depth)) = stack.pop() {
            if visited.contains(&current.0) {
                continue;
            }
            if depth > max_depth {
                continue;
            }

            // Safety cap
            if visited.len() >= MAX_VISITED {
                break;
            }

            visited.insert(current.0.clone());

            if let Some(node) = self.storage.get_node(&current)? {
                result.push(node);

                let edges = self.storage.outgoing_edges(&current)?;
                for edge in edges {
                    if !visited.contains(&edge.target.0) {
                        stack.push((edge.target, depth + 1));
                    }
                }
            }
        }

        Ok(result)
    }

    /// Find the shortest path between two nodes (BFS-based)
    /// Returns the path as a list of NodeIds, or None if no path exists
    /// Capped at MAX_VISITED to prevent OOM on massive graphs
    pub fn shortest_path(
        &self,
        from: &NodeId,
        to: &NodeId,
    ) -> DriftResult<Option<Vec<NodeId>>> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut parent: HashMap<String, NodeId> = HashMap::new();

        visited.insert(from.0.clone());
        queue.push_back(from.clone());

        while let Some(current) = queue.pop_front() {
            // Safety cap
            if visited.len() >= MAX_VISITED {
                break;
            }

            if current.0 == to.0 {
                // Reconstruct path
                let mut path = vec![current.clone()];
                let mut node = current;
                while let Some(p) = parent.get(&node.0) {
                    path.push(p.clone());
                    node = p.clone();
                }
                path.reverse();
                return Ok(Some(path));
            }

            let edges = self.storage.outgoing_edges(&current)?;
            for edge in edges {
                if !visited.contains(&edge.target.0) {
                    visited.insert(edge.target.0.clone());
                    parent.insert(edge.target.0.clone(), current.clone());
                    queue.push_back(edge.target);
                }
            }
        }

        Ok(None) // No path found
    }

    /// Count the degree(outgoing + incoming edges) of a node
    pub fn degree(&self, node_id: &NodeId) -> DriftResult<(usize, usize)> {
        let out = self.storage.outgoing_edges(node_id)?.len();
        let inc = self.storage.incoming_edges(node_id)?.len();
        Ok((out, inc))
    }
}
