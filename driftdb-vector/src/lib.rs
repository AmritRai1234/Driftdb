//! DriftDB Vector Engine
//!
//! Provides vector storage, similarity search, and approximate
//! nearest neighbor indexing.

pub mod index;
pub mod similarity;
pub mod store;

use driftdb_core::Storage;
use std::sync::Arc;

/// Vector engine that wraps core storage with vector-specific operations
pub struct VectorEngine {
    pub storage: Arc<Storage>,
}

impl VectorEngine {
    pub fn new(storage: Arc<Storage>) -> Self {
        VectorEngine { storage }
    }
}
