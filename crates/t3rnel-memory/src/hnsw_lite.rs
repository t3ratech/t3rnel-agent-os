//! HnswLite — pure Rust in-memory HNSW semantic index.
//!
//! Ported from ruflo's 160-line HnswLite (TypeScript) to Rust.
//!
//! Features:
//! - O(log n) approximate nearest neighbor search
//! - Configurable M (max connections per layer) and ef_construction
//! - No external dependencies beyond random number generation
//!
//! # Example
//! ```
//! use t3rnel_memory::hnsw_lite::{HnswLite, Vector};
//!
//! let mut index = HnswLite::new(16, 200);
//! index.insert("doc1", Vector::from(vec![1.0, 0.0, 0.0]));
//! index.insert("doc2", Vector::from(vec![0.0, 1.0, 0.0]));
//! let results = index.search(&Vector::from(vec![0.9, 0.1, 0.0]), 2);
//! assert_eq!(results[0].id, "doc1");
//! ```

use rand::Rng;
use std::collections::{BinaryHeap, HashMap};

/// A vector with associated metadata.
#[derive(Debug, Clone)]
pub struct Vector {
    pub data: Vec<f32>,
}

impl Vector {
    /// Create a new vector from raw data.
    pub fn new(data: Vec<f32>) -> Self {
        Self { data }
    }

    /// Compute squared Euclidean distance to another vector.
    pub fn distance_sq(&self, other: &Vector) -> f32 {
        self.data
            .iter()
            .zip(other.data.iter())
            .map(|(a, b)| (a - b) * (a - b))
            .sum()
    }

    /// Normalize the vector to unit length (in-place).
    pub fn normalize(&mut self) {
        let norm: f32 = self.data.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 1e-8 {
            for x in &mut self.data {
                *x /= norm;
            }
        }
    }
}

impl From<Vec<f32>> for Vector {
    fn from(data: Vec<f32>) -> Self {
        Self { data }
    }
}

/// A node in the HNSW graph.
#[derive(Debug, Clone)]
struct Node {
    /// Unique document ID.
    id: String,
    /// The vector embedding.
    vector: Vector,
    /// Connections per layer. Layer 0 is the densest.
    layers: Vec<Vec<usize>>,
}

/// Search result from HNSW.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchResult {
    pub id: String,
    pub distance: f32,
}

impl Eq for SearchResult {}

impl Ord for SearchResult {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse ordering for min-heap via BinaryHeap (which is a max-heap)
        other.distance.partial_cmp(&self.distance).unwrap()
    }
}

impl PartialOrd for SearchResult {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Lightweight HNSW index for in-memory semantic search.
pub struct HnswLite {
    /// Maximum connections per element per layer (ruflo default: 16).
    m: usize,
    /// Size of dynamic candidate list during construction (ruflo default: 200).
    ef_construction: usize,
    /// All nodes in the index.
    nodes: Vec<Node>,
    /// Map from doc ID to node index.
    id_to_idx: HashMap<String, usize>,
    /// Entry point index (highest layer).
    entry_point: Option<usize>,
    /// Current max layer.
    max_layer: usize,
    /// Random number generator.
    rng: rand::rngs::StdRng,
}

impl HnswLite {
    /// Create a new HnswLite index with the given M and ef_construction.
    pub fn new(m: usize, ef_construction: usize) -> Self {
        Self {
            m,
            ef_construction,
            nodes: Vec::new(),
            id_to_idx: HashMap::new(),
            entry_point: None,
            max_layer: 0,
            rng: rand::SeedableRng::from_entropy(),
        }
    }

    /// Insert a document with its vector into the index.
    pub fn insert(&mut self, id: &str, vector: Vector) {
        if self.id_to_idx.contains_key(id) {
            let _ = self.delete(id);
        }
        let idx = self.nodes.len();
        let layer = self.random_layer();
        let mut layers: Vec<Vec<usize>> = Vec::with_capacity(layer + 1);
        for _ in 0..=layer {
            layers.push(Vec::new());
        }

        let node = Node {
            id: id.to_string(),
            vector,
            layers,
        };

        self.nodes.push(node);
        self.id_to_idx.insert(id.to_string(), idx);

        if self.entry_point.is_none() {
            self.entry_point = Some(idx);
            self.max_layer = layer;
            return;
        }

        // Search from top layer down to layer 0
        let mut ep = self.entry_point.unwrap();
        for lc in (layer + 1..=self.max_layer).rev() {
            if let Some(next) = self
                .search_layer(&self.nodes[idx].vector, ep, 1, lc)
                .first()
                .copied()
            {
                ep = next;
            }
        }

        // Connect from layer min(layer, max_layer) down to 0
        let top_layer = layer.min(self.max_layer);
        for lc in (0..=top_layer).rev() {
            let neighbors =
                self.search_layer(&self.nodes[idx].vector, ep, self.ef_construction, lc);
            let selected = self.select_neighbors(&neighbors, self.m);
            self.nodes[idx].layers[lc] = selected.clone();

            // Bidirectional connection
            for &nbr in &selected {
                self.nodes[nbr].layers[lc].push(idx);
                if self.nodes[nbr].layers[lc].len() > self.m * 2 {
                    // Trim excess connections
                    let distances: Vec<(usize, f32)> = self.nodes[nbr].layers[lc]
                        .iter()
                        .map(|&j| (j, self.nodes[nbr].vector.distance_sq(&self.nodes[j].vector)))
                        .collect();
                    let mut sorted = distances;
                    sorted.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
                    self.nodes[nbr].layers[lc] =
                        sorted.into_iter().take(self.m).map(|(j, _)| j).collect();
                }
            }

            if lc > 0 {
                if let Some(next) = selected.first().copied() {
                    ep = next;
                }
            }
        }

        if layer > self.max_layer {
            self.max_layer = layer;
            self.entry_point = Some(idx);
        }
    }

    /// Search for the k nearest neighbors to the query vector.
    pub fn search(&self, query: &Vector, k: usize) -> Vec<SearchResult> {
        if self.entry_point.is_none() || self.nodes.is_empty() {
            return Vec::new();
        }

        let mut ep = self.entry_point.unwrap();
        if !self.is_live_idx(ep) {
            return Vec::new();
        }
        // Descend from top layer
        for lc in (1..=self.max_layer).rev() {
            if let Some(next) = self.search_layer(query, ep, 1, lc).first().copied() {
                ep = next;
            }
        }

        let neighbors = self.search_layer(query, ep, k.max(self.ef_construction), 0);
        let selected = self.select_neighbors(&neighbors, k);
        selected
            .iter()
            .map(|&idx| SearchResult {
                id: self.nodes[idx].id.clone(),
                distance: self.nodes[idx].vector.distance_sq(query).sqrt(),
            })
            .collect()
    }

    /// Remove a document from the index.
    pub fn delete(&mut self, id: &str) -> bool {
        if let Some(&idx) = self.id_to_idx.get(id) {
            // Remove from all neighbor lists
            for node in &mut self.nodes {
                for layer in &mut node.layers {
                    layer.retain(|&j| j != idx);
                }
            }
            // We don't shrink the nodes vec to keep indices stable;
            // mark as deleted by clearing id
            self.nodes[idx].id.clear();
            self.id_to_idx.remove(id);
            if self.entry_point == Some(idx) {
                self.entry_point = self.id_to_idx.values().copied().next();
                self.max_layer = self
                    .id_to_idx
                    .values()
                    .filter_map(|&live_idx| self.nodes.get(live_idx))
                    .map(|node| node.layers.len().saturating_sub(1))
                    .max()
                    .unwrap_or(0);
            }
            true
        } else {
            false
        }
    }

    /// Number of documents in the index.
    pub fn len(&self) -> usize {
        self.id_to_idx.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.id_to_idx.is_empty()
    }

    /// Assign a random layer using an exponential distribution (ruflo style).
    fn random_layer(&mut self) -> usize {
        let m_l = 1.0 / (self.m as f64).ln();
        let mut layer = 0;
        let mut p: f64 = self.rng.gen();
        while p < m_l && layer < 16 {
            p = self.rng.gen();
            layer += 1;
        }
        layer
    }

    fn is_live_idx(&self, idx: usize) -> bool {
        self.nodes.get(idx).is_some_and(|node| {
            !node.id.is_empty()
                && self
                    .id_to_idx
                    .get(&node.id)
                    .is_some_and(|&mapped| mapped == idx)
        })
    }

    /// Greedy search within a single layer.
    fn search_layer(&self, query: &Vector, entry: usize, ef: usize, layer: usize) -> Vec<usize> {
        if !self.is_live_idx(entry) {
            return Vec::new();
        }
        let mut visited = std::collections::HashSet::new();
        let mut candidates = BinaryHeap::new();
        let mut results = BinaryHeap::new();

        let dist = self.nodes[entry].vector.distance_sq(query);
        candidates.push(SearchResult {
            id: self.nodes[entry].id.clone(),
            distance: dist,
        });
        results.push(SearchResult {
            id: self.nodes[entry].id.clone(),
            distance: dist,
        });
        visited.insert(entry);

        while let Some(current) = candidates.pop() {
            if results.len() >= ef && current.distance > results.peek().unwrap().distance {
                break;
            }

            let idx = self.id_to_idx.get(&current.id).copied().unwrap_or(entry);
            if layer < self.nodes[idx].layers.len() {
                for &neighbor in &self.nodes[idx].layers[layer] {
                    if !self.is_live_idx(neighbor) {
                        continue;
                    }
                    if visited.insert(neighbor) {
                        let ndist = self.nodes[neighbor].vector.distance_sq(query);
                        candidates.push(SearchResult {
                            id: self.nodes[neighbor].id.clone(),
                            distance: ndist,
                        });
                        results.push(SearchResult {
                            id: self.nodes[neighbor].id.clone(),
                            distance: ndist,
                        });
                    }
                }
            }
        }

        results
            .into_iter()
            .filter_map(|r| self.id_to_idx.get(&r.id).copied())
            .collect()
    }

    /// Select the closest M neighbors from candidates.
    fn select_neighbors(&self, candidates: &[usize], m: usize) -> Vec<usize> {
        let Some(&reference) = candidates.first() else {
            return Vec::new();
        };
        let mut scored: Vec<(usize, f32)> = candidates
            .iter()
            .filter(|&&idx| self.is_live_idx(idx))
            .map(|&idx| {
                let dist = self.nodes[idx]
                    .vector
                    .distance_sq(&self.nodes[reference].vector);
                (idx, dist)
            })
            .collect();
        scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        scored.into_iter().take(m).map(|(idx, _)| idx).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_search_basic() {
        let mut index = HnswLite::new(16, 200);
        index.insert("doc1", Vector::from(vec![1.0, 0.0, 0.0]));
        index.insert("doc2", Vector::from(vec![0.0, 1.0, 0.0]));
        index.insert("doc3", Vector::from(vec![0.0, 0.0, 1.0]));

        let results = index.search(&Vector::from(vec![0.9, 0.1, 0.0]), 1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "doc1");
    }

    #[test]
    fn test_search_k_nearest() {
        let mut index = HnswLite::new(16, 200);
        for i in 0..10 {
            let v = vec![i as f32, (i * 2) as f32, 0.0];
            index.insert(&format!("doc{i}"), Vector::from(v));
        }

        let results = index.search(&Vector::from(vec![3.0, 6.0, 0.0]), 3);
        assert_eq!(results.len(), 3);
        // Closest should be doc3
        assert_eq!(results[0].id, "doc3");
    }

    #[test]
    fn test_delete() {
        let mut index = HnswLite::new(16, 200);
        index.insert("a", Vector::from(vec![1.0, 0.0]));
        index.insert("b", Vector::from(vec![0.0, 1.0]));

        assert!(index.delete("a"));
        assert_eq!(index.len(), 1);

        let results = index.search(&Vector::from(vec![1.0, 0.0]), 1);
        assert_eq!(results[0].id, "b");
    }

    #[test]
    fn test_empty_search() {
        let index = HnswLite::new(16, 200);
        let results = index.search(&Vector::from(vec![1.0, 0.0]), 3);
        assert!(results.is_empty());
    }
}
