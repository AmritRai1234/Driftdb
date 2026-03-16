//! Pattern matching engine for graph queries
//!
//! Supports patterns like: (u:User)-[:LIKES]->(s:Song)
//! Returns all matching subgraphs

use driftdb_core::error::DriftResult;
use driftdb_core::types::{Edge, Node, Value};
use std::collections::HashMap;

use crate::GraphEngine;

/// A single step in a pattern match
#[derive(Debug, Clone)]
pub struct PatternStep {
    /// Variable name for this node (e.g., "u", "s")
    pub variable: String,
    /// Required label (e.g., "User")
    pub label: Option<String>,
    /// Required edge type to reach this node (None for the first node)
    pub edge_type: Option<String>,
    /// Property conditions
    pub conditions: HashMap<String, Value>,
}

/// A complete pattern to match
#[derive(Debug, Clone)]
pub struct Pattern {
    pub steps: Vec<PatternStep>,
}

/// A single match result — maps variable names to matched nodes
#[derive(Debug, Clone)]
pub struct MatchResult {
    pub bindings: HashMap<String, Node>,
    pub edges: Vec<Edge>,
}

impl GraphEngine {
    /// Execute a pattern match query against the graph
    pub fn match_pattern(&self, pattern: &Pattern) -> DriftResult<Vec<MatchResult>> {
        if pattern.steps.is_empty() {
            return Ok(Vec::new());
        }

        let first_step = &pattern.steps[0];
        let mut candidates: Vec<Node> = if let Some(ref label) = first_step.label {
            self.storage.nodes_by_label(label)?
        } else {
            self.storage.all_nodes()?
        };

        // Filter by conditions on the first step
        if !first_step.conditions.is_empty() {
            candidates.retain(|node| {
                first_step.conditions.iter().all(|(k, v)| {
                    node.properties.get(k).map_or(false, |prop| prop == v)
                })
            });
        }

        let mut results = Vec::new();

        for start_node in &candidates {
            let mut bindings = HashMap::new();
            bindings.insert(first_step.variable.clone(), start_node.clone());

            let mut matched_edges = Vec::new();
            let mut current_node = start_node.clone();
            let mut matched = true;

            for step in pattern.steps.iter().skip(1) {
                let edges = if let Some(ref etype) = step.edge_type {
                    self.outgoing_of_type(&current_node.id, etype)?
                } else {
                    self.storage.outgoing_edges(&current_node.id)?
                };

                let mut found = false;
                for edge in edges {
                    if let Some(target) = self.storage.get_node(&edge.target)? {
                        // Check label
                        if let Some(ref label) = step.label {
                            if !target.has_label(label) {
                                continue;
                            }
                        }

                        // Check conditions
                        let conds_match = step.conditions.iter().all(|(k, v)| {
                            target.properties.get(k).map_or(false, |prop| prop == v)
                        });

                        if conds_match {
                            bindings.insert(step.variable.clone(), target.clone());
                            matched_edges.push(edge);
                            current_node = target;
                            found = true;
                            break;
                        }
                    }
                }

                if !found {
                    matched = false;
                    break;
                }
            }

            if matched && bindings.len() == pattern.steps.len() {
                results.push(MatchResult {
                    bindings,
                    edges: matched_edges,
                });
            }
        }

        Ok(results)
    }
}
