//! DriftQL Executor — Walks the AST and executes queries against the engines

use driftdb_core::error::{DriftError, DriftResult};
use driftdb_core::types::{Node, NodeId, Value};
use driftdb_graph::pattern::{Pattern, PatternStep};
use driftdb_graph::GraphEngine;
use driftdb_vector::VectorEngine;
use std::collections::HashMap;
use std::sync::Arc;

use crate::ast::*;

/// Query execution result
#[derive(Debug)]
pub enum QueryResult {
    /// A node was created
    NodeCreated { node: Node },
    /// An edge was created
    EdgeCreated { edge_id: String, edge_type: String },
    /// Tabular results from a FIND query
    Table {
        columns: Vec<String>,
        rows: Vec<Vec<String>>,
    },
    /// Vector similarity results
    SimilarResults {
        results: Vec<(String, f64)>,
    },
    /// A property was updated
    PropertySet { node_id: String, property: String },
    /// A node was deleted
    Deleted { id: String },
    /// Show output
    Info(String),
    /// Help text
    HelpText(String),
    /// Empty result
    Ok,
}

/// The query executor
pub struct Executor {
    graph: Arc<GraphEngine>,
    vector: Arc<VectorEngine>,
    /// Session variable bindings (var name -> node id)
    variables: HashMap<String, NodeId>,
}

impl Executor {
    pub fn new(graph: Arc<GraphEngine>, vector: Arc<VectorEngine>) -> Self {
        Executor {
            graph,
            vector,
            variables: HashMap::new(),
        }
    }

    /// Execute a parsed statement
    pub fn execute(&mut self, stmt: Statement) -> DriftResult<QueryResult> {
        match stmt {
            Statement::CreateNode {
                variable,
                labels,
                properties,
            } => self.exec_create_node(variable, labels, properties),

            Statement::CreateEdge {
                source,
                target,
                edge_type,
                properties,
            } => self.exec_create_edge(source, target, edge_type, properties),

            Statement::Find {
                pattern,
                where_clause,
                return_fields,
                at_time,
            } => self.exec_find(pattern, where_clause, return_fields, at_time),

            Statement::FindSimilar {
                vector,
                threshold,
                limit,
                return_fields,
            } => self.exec_find_similar(vector, threshold, limit, return_fields),

            Statement::SetProperty {
                node_ref,
                property,
                value,
            } => self.exec_set(node_ref, property, value),

            Statement::Delete { node_ref } => self.exec_delete(node_ref),

            Statement::Show { target } => self.exec_show(target),

            Statement::Help => Ok(QueryResult::HelpText(self.help_text())),
        }
    }

    fn exec_create_node(
        &mut self,
        variable: Option<String>,
        labels: Vec<String>,
        properties: HashMap<String, Value>,
    ) -> DriftResult<QueryResult> {
        let node = self.graph.create_node(labels, properties)?;

        if let Some(var) = variable {
            self.variables.insert(var, node.id.clone());
        }

        Ok(QueryResult::NodeCreated { node })
    }

    fn exec_create_edge(
        &mut self,
        source: NodeRef,
        target: NodeRef,
        edge_type: String,
        properties: HashMap<String, Value>,
    ) -> DriftResult<QueryResult> {
        let source_id = self.resolve_node_ref(&source)?;
        let target_id = self.resolve_node_ref(&target)?;

        let edge = self.graph.create_edge(source_id, target_id, edge_type.clone(), properties)?;

        Ok(QueryResult::EdgeCreated {
            edge_id: edge.id.0.clone(),
            edge_type,
        })
    }

    fn exec_find(
        &mut self,
        pattern_elements: Vec<PatternElement>,
        where_clause: Option<WhereClause>,
        return_fields: Vec<ReturnField>,
        _at_time: Option<String>,
    ) -> DriftResult<QueryResult> {
        // Convert AST pattern to graph engine pattern
        let steps: Vec<PatternStep> = pattern_elements
            .iter()
            .map(|pe| PatternStep {
                variable: pe.variable.clone(),
                label: pe.label.clone(),
                edge_type: pe.edge_type.clone(),
                conditions: pe.conditions.clone(),
            })
            .collect();

        let pattern = Pattern { steps };
        let matches = self.graph.match_pattern(&pattern)?;

        // Apply WHERE clause filtering
        let filtered = if let Some(ref wc) = where_clause {
            matches
                .into_iter()
                .filter(|m| {
                    wc.conditions.iter().all(|cond| {
                        m.bindings
                            .get(&cond.variable)
                            .and_then(|node| node.properties.get(&cond.property))
                            .map_or(false, |val| self.compare_values(val, &cond.operator, &cond.value))
                    })
                })
                .collect()
        } else {
            matches
        };

        // Build result table
        if return_fields.is_empty() {
            // Return all nodes in the pattern
            let mut columns = Vec::new();
            let mut rows = Vec::new();

            if let Some(first_match) = filtered.first() {
                columns = first_match.bindings.keys().cloned().collect();
                columns.sort();
            }

            for m in &filtered {
                let row: Vec<String> = columns
                    .iter()
                    .map(|col| {
                        m.bindings
                            .get(col)
                            .map(|n| format_node_brief(n))
                            .unwrap_or_default()
                    })
                    .collect();
                rows.push(row);
            }

            Ok(QueryResult::Table { columns, rows })
        } else {
            // Return specific fields
            let columns: Vec<String> = return_fields
                .iter()
                .map(|rf| {
                    if let Some(ref prop) = rf.property {
                        format!("{}.{}", rf.variable, prop)
                    } else {
                        rf.variable.clone()
                    }
                })
                .collect();

            let mut rows = Vec::new();
            for m in &filtered {
                let row: Vec<String> = return_fields
                    .iter()
                    .map(|rf| {
                        m.bindings
                            .get(&rf.variable)
                            .map(|node| {
                                if let Some(ref prop) = rf.property {
                                    node.properties
                                        .get(prop)
                                        .map(|v| format!("{}", v))
                                        .unwrap_or_else(|| "null".to_string())
                                } else {
                                    format_node_brief(node)
                                }
                            })
                            .unwrap_or_else(|| "null".to_string())
                    })
                    .collect();
                rows.push(row);
            }

            Ok(QueryResult::Table { columns, rows })
        }
    }

    fn exec_find_similar(
        &mut self,
        vector: Vec<f64>,
        threshold: f64,
        limit: Option<usize>,
        _return_fields: Vec<ReturnField>,
    ) -> DriftResult<QueryResult> {
        let results = self.vector.find_similar(&vector, threshold, limit.unwrap_or(10))?;

        let items: Vec<(String, f64)> = results
            .iter()
            .map(|r| (format_node_brief(&r.node), r.similarity))
            .collect();

        Ok(QueryResult::SimilarResults { results: items })
    }

    fn exec_set(
        &mut self,
        node_ref: NodeRef,
        property: String,
        value: Value,
    ) -> DriftResult<QueryResult> {
        let node_id = self.resolve_node_ref(&node_ref)?;
        self.graph.set_property(&node_id, &property, value)?;

        Ok(QueryResult::PropertySet {
            node_id: node_id.0,
            property,
        })
    }

    fn exec_delete(&mut self, node_ref: NodeRef) -> DriftResult<QueryResult> {
        let node_id = self.resolve_node_ref(&node_ref)?;
        self.graph.delete_node(&node_id)?;

        Ok(QueryResult::Deleted { id: node_id.0 })
    }

    fn exec_show(&self, target: ShowTarget) -> DriftResult<QueryResult> {
        match target {
            ShowTarget::Nodes => {
                let nodes = self.graph.all_nodes()?;
                let mut lines = Vec::new();
                for node in &nodes {
                    lines.push(format_node(node));
                }
                if lines.is_empty() {
                    Ok(QueryResult::Info("No nodes found.".to_string()))
                } else {
                    Ok(QueryResult::Info(lines.join("\n")))
                }
            }
            ShowTarget::Edges => {
                let edges = self.graph.all_edges()?;
                let mut lines = Vec::new();
                for edge in &edges {
                    lines.push(format!(
                        "({}) -[:{}]-> ({})  [{}]",
                        edge.source, edge.edge_type, edge.target, edge.id
                    ));
                }
                if lines.is_empty() {
                    Ok(QueryResult::Info("No edges found.".to_string()))
                } else {
                    Ok(QueryResult::Info(lines.join("\n")))
                }
            }
            ShowTarget::Stats => {
                let stats = self.graph.storage.stats()?;
                Ok(QueryResult::Info(format!("{}", stats)))
            }
            ShowTarget::Events => {
                let events = self.graph.storage.events.get_log();
                let mut lines = Vec::new();
                for event in events.iter().rev().take(20) {
                    lines.push(format!(
                        "[{}] {}",
                        event.timestamp().format("%H:%M:%S"),
                        event.event_type()
                    ));
                }
                if lines.is_empty() {
                    Ok(QueryResult::Info("No events recorded.".to_string()))
                } else {
                    Ok(QueryResult::Info(lines.join("\n")))
                }
            }
        }
    }

    /// Resolve a node reference to a NodeId
    fn resolve_node_ref(&self, node_ref: &NodeRef) -> DriftResult<NodeId> {
        // Try by variable binding first
        if let Some(id) = self.variables.get(&node_ref.variable) {
            return Ok(id.clone());
        }

        // Try by label + conditions
        if let Some(ref label) = node_ref.label {
            let nodes = self.graph.nodes_by_label(label)?;
            for node in &nodes {
                let matches = node_ref.conditions.iter().all(|(k, v)| {
                    node.properties.get(k).map_or(false, |prop| prop == v)
                });
                if matches {
                    return Ok(node.id.clone());
                }
            }
        }

        // Try as direct node ID
        let id = NodeId::from_str(&node_ref.variable);
        if self.graph.get_node(&id)?.is_some() {
            return Ok(id);
        }

        Err(DriftError::NodeNotFound(format!(
            "Cannot resolve node reference: '{}'",
            node_ref.variable
        )))
    }

    fn compare_values(&self, actual: &Value, op: &ComparisonOp, expected: &Value) -> bool {
        match op {
            ComparisonOp::Eq => actual == expected,
            ComparisonOp::Neq => actual != expected,
            ComparisonOp::Lt => compare_numeric(actual, expected, |a, b| a < b),
            ComparisonOp::Gt => compare_numeric(actual, expected, |a, b| a > b),
            ComparisonOp::Lte => compare_numeric(actual, expected, |a, b| a <= b),
            ComparisonOp::Gte => compare_numeric(actual, expected, |a, b| a >= b),
        }
    }

    fn help_text(&self) -> String {
        r#"
╔═══════════════════════════════════════════════════════════════╗
║                    DriftQL Quick Reference                    ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  CREATE (var:Label {key: "value", key2: 42})                  ║
║    Create a new node with labels and properties               ║
║                                                               ║
║  LINK (var1)-[:EDGE_TYPE {props}]->(var2)                     ║
║    Create an edge between two nodes                           ║
║                                                               ║
║  FIND (n:Label) RETURN n.property                             ║
║    Find nodes by label and return properties                  ║
║                                                               ║
║  FIND (a:Label)-[:EDGE]->(b:Label) RETURN a.name, b.name     ║
║    Pattern matching across relationships                      ║
║                                                               ║
║  FIND (n) WHERE n.age > 18 RETURN n.name                     ║
║    Find with conditions                                       ║
║                                                               ║
║  FIND SIMILAR TO [0.1, 0.5, 0.9] WITHIN 0.8                  ║
║    Vector similarity search                                   ║
║                                                               ║
║  SET var.property = "new_value"                               ║
║    Update a node property                                     ║
║                                                               ║
║  DELETE (var)                                                  ║
║    Soft-delete a node                                         ║
║                                                               ║
║  SHOW NODES | SHOW EDGES | SHOW STATS | SHOW EVENTS          ║
║    Display database contents                                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝"#
            .to_string()
    }
}

/// Helper: compare numeric values
fn compare_numeric<F: Fn(f64, f64) -> bool>(a: &Value, b: &Value, cmp: F) -> bool {
    match (a.as_float(), b.as_float()) {
        (Some(a), Some(b)) => cmp(a, b),
        _ => false,
    }
}

/// Format a node for display (brief)
fn format_node_brief(node: &Node) -> String {
    let labels = node.labels.join(":");
    let name = node
        .properties
        .get("name")
        .or_else(|| node.properties.get("title"))
        .map(|v| format!("{}", v))
        .unwrap_or_else(|| node.id.0.clone());
    format!("({}:{})", name, labels)
}

/// Format a node for display (full)
fn format_node(node: &Node) -> String {
    let labels = node.labels.join(":");
    let props: Vec<String> = node
        .properties
        .iter()
        .map(|(k, v)| format!("{}: {}", k, v))
        .collect();
    format!(
        "[{}] :{} {{ {} }}",
        node.id,
        labels,
        props.join(", ")
    )
}
