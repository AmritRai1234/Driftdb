//! VP-Tree based approximate nearest neighbor index
//!
//! Vantage-point trees for efficient similarity search
//! in high-dimensional spaces.

use crate::similarity::euclidean_distance;

/// A point in the VP-tree
#[derive(Debug, Clone)]
pub struct VPPoint {
    pub id: String,
    pub vector: Vec<f64>,
}

/// VP-Tree node
#[derive(Debug)]
enum VPNode {
    Leaf(VPPoint),
    Internal {
        vantage: VPPoint,
        radius: f64,
        inside: Option<Box<VPNode>>,
        outside: Option<Box<VPNode>>,
    },
}

/// Vantage-Point Tree for approximate nearest neighbor search
pub struct VPTree {
    root: Option<Box<VPNode>>,
}

impl VPTree {
    /// Build a VP-tree from a set of points
    pub fn build(mut points: Vec<VPPoint>) -> Self {
        let root = Self::build_recursive(&mut points);
        VPTree { root }
    }

    fn build_recursive(points: &mut Vec<VPPoint>) -> Option<Box<VPNode>> {
        if points.is_empty() {
            return None;
        }

        if points.len() == 1 {
            return Some(Box::new(VPNode::Leaf(points.remove(0))));
        }

        // Pick the first point as the vantage point
        let vantage = points.remove(0);

        // Compute distances from vantage point to all other points
        let mut distances: Vec<(f64, VPPoint)> = points
            .drain(..)
            .map(|p| {
                let dist = euclidean_distance(&vantage.vector, &p.vector);
                (dist, p)
            })
            .collect();

        // Sort by distance
        distances.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        // Median distance is our radius
        let median_idx = distances.len() / 2;
        let radius = distances[median_idx].0;

        // Split into inside and outside
        let mut inside_points: Vec<VPPoint> = distances[..median_idx]
            .iter()
            .map(|(_, p)| p.clone())
            .collect();
        let mut outside_points: Vec<VPPoint> = distances[median_idx..]
            .iter()
            .map(|(_, p)| p.clone())
            .collect();

        let inside = Self::build_recursive(&mut inside_points);
        let outside = Self::build_recursive(&mut outside_points);

        Some(Box::new(VPNode::Internal {
            vantage,
            radius,
            inside,
            outside,
        }))
    }

    /// Search for the k nearest neighbors to a query point
    pub fn search(&self, query: &[f64], k: usize) -> Vec<(String, f64)> {
        let mut results: Vec<(String, f64)> = Vec::new();
        let mut tau = f64::MAX; // Current furthest distance in results

        if let Some(ref root) = self.root {
            Self::search_recursive(root, query, k, &mut results, &mut tau);
        }

        results.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        results
    }

    fn search_recursive(
        node: &VPNode,
        query: &[f64],
        k: usize,
        results: &mut Vec<(String, f64)>,
        tau: &mut f64,
    ) {
        match node {
            VPNode::Leaf(point) => {
                let dist = euclidean_distance(query, &point.vector);
                if results.len() < k || dist < *tau {
                    results.push((point.id.clone(), dist));
                    results.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
                    if results.len() > k {
                        results.truncate(k);
                    }
                    if results.len() == k {
                        *tau = results.last().unwrap().1;
                    }
                }
            }
            VPNode::Internal {
                vantage,
                radius,
                inside,
                outside,
            } => {
                let dist = euclidean_distance(query, &vantage.vector);

                // Check if vantage point is a candidate
                if results.len() < k || dist < *tau {
                    results.push((vantage.id.clone(), dist));
                    results.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
                    if results.len() > k {
                        results.truncate(k);
                    }
                    if results.len() == k {
                        *tau = results.last().unwrap().1;
                    }
                }

                // Decide which subtrees to search
                if dist < *radius {
                    // Query is inside — search inside first
                    if let Some(ref inside_node) = inside {
                        if dist - *tau < *radius {
                            Self::search_recursive(inside_node, query, k, results, tau);
                        }
                    }
                    if let Some(ref outside_node) = outside {
                        if dist + *tau >= *radius {
                            Self::search_recursive(outside_node, query, k, results, tau);
                        }
                    }
                } else {
                    // Query is outside — search outside first
                    if let Some(ref outside_node) = outside {
                        if dist + *tau >= *radius {
                            Self::search_recursive(outside_node, query, k, results, tau);
                        }
                    }
                    if let Some(ref inside_node) = inside {
                        if dist - *tau < *radius {
                            Self::search_recursive(inside_node, query, k, results, tau);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vptree_basic() {
        let points = vec![
            VPPoint { id: "a".into(), vector: vec![0.0, 0.0] },
            VPPoint { id: "b".into(), vector: vec![1.0, 0.0] },
            VPPoint { id: "c".into(), vector: vec![0.0, 1.0] },
            VPPoint { id: "d".into(), vector: vec![10.0, 10.0] },
        ];

        let tree = VPTree::build(points);
        let results = tree.search(&[0.0, 0.0], 2);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "a"); // Closest to origin
    }

    #[test]
    fn test_vptree_single() {
        let points = vec![VPPoint { id: "x".into(), vector: vec![5.0, 5.0] }];
        let tree = VPTree::build(points);
        let results = tree.search(&[0.0, 0.0], 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "x");
    }
}
