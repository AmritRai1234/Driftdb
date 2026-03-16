//! DriftQL — Abstract Syntax Tree
//!
//! All query types are represented as AST nodes.

use driftdb_core::types::Value;
use std::collections::HashMap;

/// Top-level AST node — a single DriftQL statement
#[derive(Debug, Clone)]
pub enum Statement {
    /// CREATE (label {props})
    CreateNode {
        variable: Option<String>,
        labels: Vec<String>,
        properties: HashMap<String, Value>,
    },

    /// LINK (var1)-[:TYPE {props}]->(var2)
    CreateEdge {
        source: NodeRef,
        target: NodeRef,
        edge_type: String,
        properties: HashMap<String, Value>,
    },

    /// FIND pattern WHERE conditions RETURN fields
    Find {
        pattern: Vec<PatternElement>,
        where_clause: Option<WhereClause>,
        return_fields: Vec<ReturnField>,
        at_time: Option<String>,
    },

    /// FIND ... SIMILAR TO [...] WITHIN threshold
    FindSimilar {
        vector: Vec<f64>,
        threshold: f64,
        limit: Option<usize>,
        return_fields: Vec<ReturnField>,
    },

    /// SET var.property = value
    SetProperty {
        node_ref: NodeRef,
        property: String,
        value: Value,
    },

    /// DELETE var
    Delete {
        node_ref: NodeRef,
    },

    /// SHOW NODES | SHOW EDGES | SHOW STATS
    Show {
        target: ShowTarget,
    },

    /// HELP
    Help,
}

/// Reference to a node — either by variable or by looking up a previously
/// created node in the session
#[derive(Debug, Clone)]
pub struct NodeRef {
    pub variable: String,
    pub label: Option<String>,
    pub conditions: HashMap<String, Value>,
}

/// An element in a graph pattern
#[derive(Debug, Clone)]
pub struct PatternElement {
    pub variable: String,
    pub label: Option<String>,
    pub edge_type: Option<String>,
    pub conditions: HashMap<String, Value>,
}

/// WHERE clause conditions
#[derive(Debug, Clone)]
pub struct WhereClause {
    pub conditions: Vec<Condition>,
}

/// A single condition in a WHERE clause
#[derive(Debug, Clone)]
pub struct Condition {
    pub variable: String,
    pub property: String,
    pub operator: ComparisonOp,
    pub value: Value,
}

/// Comparison operators
#[derive(Debug, Clone)]
pub enum ComparisonOp {
    Eq,
    Neq,
    Lt,
    Gt,
    Lte,
    Gte,
}

/// RETURN field specification
#[derive(Debug, Clone)]
pub struct ReturnField {
    pub variable: String,
    pub property: Option<String>,
}

/// SHOW command targets
#[derive(Debug, Clone)]
pub enum ShowTarget {
    Nodes,
    Edges,
    Stats,
    Events,
}
