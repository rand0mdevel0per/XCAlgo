use petgraph::graph::{Graph as PetGraph, NodeIndex};
use petgraph::Undirected;
use petgraph::visit::EdgeRef;
use std::collections::HashSet;

/// Undirected graph wrapper for TDA cryptosystem
#[derive(Clone, Debug)]
pub struct Graph {
    inner: PetGraph<(), (), Undirected>,
    node_indices: Vec<NodeIndex>,
}

impl Graph {
    /// Create a new graph with n nodes
    pub fn new(n: usize) -> Self {
        let mut inner = PetGraph::new_undirected();
        let node_indices: Vec<NodeIndex> = (0..n).map(|_| inner.add_node(())).collect();

        Graph {
            inner,
            node_indices,
        }
    }

    /// Add an edge between nodes u and v
    pub fn add_edge(&mut self, u: usize, v: usize) {
        if u < self.node_indices.len() && v < self.node_indices.len() {
            let u_idx = self.node_indices[u];
            let v_idx = self.node_indices[v];
            self.inner.add_edge(u_idx, v_idx, ());
        }
    }

    /// Get neighbors of node u
    pub fn neighbors(&self, u: usize) -> Vec<usize> {
        if u >= self.node_indices.len() {
            return Vec::new();
        }

        let u_idx = self.node_indices[u];
        self.inner
            .neighbors(u_idx)
            .map(|idx| {
                self.node_indices
                    .iter()
                    .position(|&node_idx| node_idx == idx)
                    .unwrap()
            })
            .collect()
    }

    /// Check if edge exists between u and v
    pub fn has_edge(&self, u: usize, v: usize) -> bool {
        if u >= self.node_indices.len() || v >= self.node_indices.len() {
            return false;
        }

        let u_idx = self.node_indices[u];
        let v_idx = self.node_indices[v];

        self.inner.find_edge(u_idx, v_idx).is_some()
    }

    /// Get number of nodes
    pub fn node_count(&self) -> usize {
        self.node_indices.len()
    }

    /// Get number of edges
    pub fn edge_count(&self) -> usize {
        self.inner.edge_count()
    }

    /// Get all edges as (u, v) pairs
    pub fn edges(&self) -> Vec<(usize, usize)> {
        let mut result = Vec::new();
        let mut seen = HashSet::new();

        for edge in self.inner.edge_references() {
            let u_idx = edge.source();
            let v_idx = edge.target();

            let u = self.node_indices.iter().position(|&idx| idx == u_idx).unwrap();
            let v = self.node_indices.iter().position(|&idx| idx == v_idx).unwrap();

            // Ensure we don't add the same edge twice (undirected)
            let edge_pair = if u < v { (u, v) } else { (v, u) };
            if seen.insert(edge_pair) {
                result.push(edge_pair);
            }
        }

        result
    }

    /// Check if there's a path between u and v using BFS
    pub fn has_path(&self, u: usize, v: usize) -> bool {
        if u >= self.node_indices.len() || v >= self.node_indices.len() {
            return false;
        }

        if u == v {
            return true;
        }

        let mut visited = vec![false; self.node_count()];
        let mut queue = std::collections::VecDeque::new();

        queue.push_back(u);
        visited[u] = true;

        while let Some(current) = queue.pop_front() {
            for neighbor in self.neighbors(current) {
                if neighbor == v {
                    return true;
                }
                if !visited[neighbor] {
                    visited[neighbor] = true;
                    queue.push_back(neighbor);
                }
            }
        }

        false
    }
}
