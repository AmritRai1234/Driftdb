//! DriftDB Graph Engine — Node operations, edge traversal, pattern matching

pub mod edge;
pub mod node;
pub mod pattern;
pub mod traverse;

use driftdb_core::Storage;
use std::sync::Arc;

/// Graph engine that wraps the core storage with graph-specific operations
pub struct GraphEngine {
    pub storage: Arc<Storage>,
}

impl GraphEngine {
    pub fn new(storage: Arc<Storage>) -> Self {
        GraphEngine { storage }
    }
}
