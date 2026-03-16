//! Vector store operations

use driftdb_core::error::DriftResult;
use driftdb_core::types::{Node, NodeId};

use crate::similarity::cosine_similarity;
use crate::VectorEngine;

/// A similarity search result
#[derive(Debug, Clone)]
pub struct SimilarityResult {
    pub node: Node,
    pub similarity: f64,
}

impl VectorEngine {
    /// Attach a vector to a node
    pub fn attach(&self, node_id: &NodeId, vector: Vec<f64>) -> DriftResult<()> {
        self.storage.attach_vector(node_id, vector)
    }

    /// Get the vector for a node
    pub fn get_vector(&self, node_id: &NodeId) -> DriftResult<Option<Vec<f64>>> {
        self.storage.get_vector(node_id)
    }

    /// Find nodes with vectors similar to the query vector
    /// Returns results sorted by similarity (highest first)
    pub fn find_similar(
        &self,
        query: &[f64],
        min_similarity: f64,
        limit: usize,
    ) -> DriftResult<Vec<SimilarityResult>> {
        let all_vectors = self.storage.all_vectors()?;
        let mut results: Vec<SimilarityResult> = Vec::new();

        for (node_id, vector) in all_vectors {
            let sim = cosine_similarity(query, &vector);
            if sim >= min_similarity {
                if let Some(node) = self.storage.get_node(&node_id)? {
                    results.push(SimilarityResult {
                        node,
                        similarity: sim,
                    });
                }
            }
        }

        // Sort by similarity descending
        results.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap());
        results.truncate(limit);

        Ok(results)
    }

    /// Find the K nearest neighbors to a query vector
    pub fn knn(&self, query: &[f64], k: usize) -> DriftResult<Vec<SimilarityResult>> {
        self.find_similar(query, f64::NEG_INFINITY, k)
    }
}
